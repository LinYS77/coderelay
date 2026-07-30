from __future__ import annotations

import asyncio
import imaplib
import re
import ssl
import time
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta, timezone
from email import policy
from email.message import Message
from email.parser import BytesParser
from typing import Any

import httpx

from coderelay.config import OutlookImapSourceSettings
from coderelay.domain.errors import (
    ConfigurationFailure,
    SourceCredentialsInvalid,
    SourceRateLimited,
    SourceReauthRequired,
    UpstreamFailure,
    UpstreamSchemaChanged,
    UpstreamTimeout,
)
from coderelay.domain.extractor import CodeExtractor
from coderelay.domain.models import CodeRequest, MailMessage, ProviderCode, SourceKind, SourceState, SourceStatus
from coderelay.infra.credential_store import (
    CredentialStoreError,
    EncryptedOutlookCredentialStore,
    OutlookCredential,
)
from coderelay.providers.base import CodeProvider
from coderelay.providers.http_utils import bounded_json, parse_retry_after
from coderelay.security import mask_email

_IMAP_SCOPE = "https://outlook.office.com/imap.accessasuser.all"
_UID_RE = re.compile(rb"\bUID\s+(\d+)\b")


class _ImapAuthenticationError(Exception):
    pass


class OutlookImapProvider(CodeProvider):
    provider_type = "outlook_imap"
    fetch_timeout_seconds = 30.0

    def __init__(
        self,
        settings: OutlookImapSourceSettings,
        client: httpx.AsyncClient,
        *,
        strict_secret_permissions: bool,
        imap_factory: Callable[..., Any] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings
        self.id = settings.id
        self.display_name = settings.display_name
        self.poll_interval_seconds = settings.poll_interval_seconds
        self._client = client
        self._extractor = CodeExtractor(settings.extractor)
        self._store = EncryptedOutlookCredentialStore(
            settings.credential_file,
            settings.credential_key_file,
            source_id=settings.id,
            strict_permissions=strict_secret_permissions,
        )
        try:
            self._credential = self._store.load()
        except CredentialStoreError as exc:
            raise ConfigurationFailure(str(exc)) from exc
        self._imap_factory = imap_factory or imaplib.IMAP4_SSL
        self._now = now or (lambda: datetime.now(UTC))
        self._token_lock = asyncio.Lock()
        self._access_token: str | None = None
        self._access_token_expires_at = 0.0

    async def fetch_code(self, request: CodeRequest) -> ProviderCode | None:
        access_token = await self._get_access_token()
        try:
            messages = await asyncio.to_thread(self._read_messages, access_token)
        except _ImapAuthenticationError:
            self._invalidate_access_token()
            access_token = await self._get_access_token(force_refresh=True)
            try:
                messages = await asyncio.to_thread(self._read_messages, access_token)
            except _ImapAuthenticationError as exc:
                self._invalidate_access_token()
                raise SourceCredentialsInvalid() from exc
        now = self._now()
        now = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
        extracted = self._extractor.extract(messages, not_before=request.not_before, now=now)
        if not extracted:
            return None
        return ProviderCode(
            source_id=self.id,
            kind=SourceKind.EMAIL,
            code=extracted.code,
            observed_at=now,
            received_at=extracted.message.received_at,
            freshness="fresh",
            evidence={
                "sender": extracted.message.sender[:320],
                "subject": extracted.redacted_subject,
                "message_fingerprint": extracted.message_fingerprint,
            },
        )

    def status(self) -> SourceStatus:
        return SourceStatus(
            id=self.id,
            display_name=self.display_name,
            provider_type=self.provider_type,
            kind=SourceKind.EMAIL,
            state=SourceState.READY,
            identity_hint=mask_email(self._credential.email),
        )

    def close(self) -> None:
        self._access_token = None
        self._access_token_expires_at = 0.0

    async def _get_access_token(self, *, force_refresh: bool = False) -> str:
        async with self._token_lock:
            if not force_refresh and self._access_token and time.monotonic() < self._access_token_expires_at:
                return self._access_token
            response = await self._request_access_token(self._credential)
            token = response.get("access_token")
            if not isinstance(token, str) or not token or len(token) > 131_072:
                raise UpstreamSchemaChanged()
            scope = response.get("scope")
            if isinstance(scope, str) and scope.strip():
                scopes = {item.casefold() for item in scope.split()}
                if _IMAP_SCOPE not in scopes:
                    raise SourceCredentialsInvalid()
            expires_in = response.get("expires_in", 3_600)
            try:
                lifetime = int(expires_in)
            except (TypeError, ValueError):
                lifetime = 3_600
            lifetime = min(86_400, max(60, lifetime))

            rotated = response.get("refresh_token")
            if isinstance(rotated, str) and rotated and rotated != self._credential.refresh_token:
                try:
                    updated = self._credential.with_refresh_token(rotated)
                    self._store.save(updated, overwrite=True)
                    self._credential = updated
                except CredentialStoreError as exc:
                    raise ConfigurationFailure("cannot persist rotated Outlook refresh token") from exc

            self._access_token = token
            self._access_token_expires_at = time.monotonic() + max(30, lifetime - 60)
            return token

    async def _request_access_token(self, credential: OutlookCredential) -> dict[str, object]:
        try:
            response = await self._client.post(
                self.settings.token_url,
                data={
                    "client_id": credential.client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": credential.refresh_token,
                },
                headers={"Accept": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise UpstreamTimeout() from exc
        except httpx.HTTPError as exc:
            raise UpstreamFailure() from exc
        if response.status_code == 429:
            raise SourceRateLimited(
                retry_after_seconds=parse_retry_after(response.headers.get("Retry-After"), default=5)
            )
        payload = bounded_json(response.content, max_bytes=1_048_576)
        if not isinstance(payload, dict):
            raise UpstreamSchemaChanged()
        if response.status_code == 400:
            error = payload.get("error")
            if error in {"invalid_grant", "interaction_required", "consent_required", "login_required"}:
                raise SourceReauthRequired()
            raise SourceCredentialsInvalid()
        if response.status_code in {401, 403}:
            raise SourceCredentialsInvalid()
        if response.status_code >= 500:
            raise UpstreamFailure()
        if response.status_code < 200 or response.status_code >= 300:
            raise UpstreamFailure()
        return payload

    def _read_messages(self, access_token: str) -> list[MailMessage]:
        imap = None
        try:
            imap = self._imap_factory(
                self.settings.imap_host,
                self.settings.imap_port,
                ssl_context=ssl.create_default_context(),
                timeout=self.settings.imap_timeout_seconds,
            )
            authentication = (f"user={self._credential.email}\x01auth=Bearer {access_token}\x01\x01").encode()
            try:
                imap.authenticate("XOAUTH2", lambda _: authentication)
            except imaplib.IMAP4.error as exc:
                raise _ImapAuthenticationError() from exc
            finally:
                authentication = b""
            status, data = imap.select("INBOX", readonly=True)
            if status != "OK" or not data or not data[0].isdigit():
                raise UpstreamFailure()
            message_count = int(data[0])
            messages: list[MailMessage] = []
            first_sequence = max(1, message_count - self.settings.max_messages + 1)
            for sequence in range(message_count, first_sequence - 1, -1):
                fetch_status, fetch_data = imap.fetch(
                    str(sequence),
                    f"(UID INTERNALDATE BODY.PEEK[]<0.{self.settings.max_message_bytes}>)",
                )
                if fetch_status != "OK" or not isinstance(fetch_data, list):
                    continue
                parsed = self._parse_fetch_data(fetch_data, sequence)
                if parsed is not None:
                    messages.append(parsed)
            return messages
        except _ImapAuthenticationError:
            raise
        except TimeoutError as exc:
            raise UpstreamTimeout() from exc
        except (OSError, ssl.SSLError, imaplib.IMAP4.error) as exc:
            raise UpstreamFailure() from exc
        finally:
            if imap is not None:
                with suppress(Exception):
                    imap.logout()

    def _parse_fetch_data(self, fetch_data: list[object], sequence: int) -> MailMessage | None:
        metadata = b""
        raw_message = b""
        for item in fetch_data:
            if isinstance(item, tuple) and len(item) >= 2:
                if isinstance(item[0], bytes):
                    metadata = item[0]
                if isinstance(item[1], bytes):
                    raw_message = item[1]
                if raw_message:
                    break
        if not metadata or not raw_message:
            return None
        raw_message = raw_message[: self.settings.max_message_bytes]
        received_at = _parse_internal_date(metadata)
        if received_at is None:
            return None
        try:
            parsed_message = BytesParser(policy=policy.default).parsebytes(raw_message)
        except Exception:
            return None
        subject = str(parsed_message.get("Subject", ""))[:10_000]
        sender = str(parsed_message.get("From", ""))[:4_096]
        uid_match = _UID_RE.search(metadata)
        uid = uid_match.group(1).decode("ascii") if uid_match else str(sequence)
        text, html = _extract_message_content(parsed_message, self.settings.extractor.max_text_chars)
        return MailMessage(
            provider_message_id=f"imap:{uid}",
            subject=subject,
            sender=sender,
            received_at=received_at,
            text=text,
            html=html,
        )

    def _invalidate_access_token(self) -> None:
        self._access_token = None
        self._access_token_expires_at = 0.0


def _parse_internal_date(metadata: bytes) -> datetime | None:
    match = imaplib.InternalDate.match(metadata)
    if not match:
        return None
    try:
        month = imaplib.Mon2num[match.group("mon")]
        offset_seconds = (int(match.group("zoneh")) * 60 + int(match.group("zonem"))) * 60
        if match.group("zonen") == b"-":
            offset_seconds = -offset_seconds
        source_zone = timezone(timedelta(seconds=offset_seconds))
        return datetime(
            int(match.group("year")),
            month,
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("min")),
            int(match.group("sec")),
            tzinfo=source_zone,
        ).astimezone(UTC)
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def _extract_message_content(message: Message, limit: int) -> tuple[str, str]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    plain_length = 0
    html_length = 0
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type().casefold()
        if content_type not in {"text/plain", "text/html"}:
            continue
        content = _decode_part(part)
        if not content:
            continue
        if content_type == "text/plain" and plain_length < limit:
            content = content[: limit - plain_length]
            plain_parts.append(content)
            plain_length += len(content)
        elif content_type == "text/html" and html_length < limit:
            content = content[: limit - html_length]
            html_parts.append(content)
            html_length += len(content)
    return "\n".join(plain_parts), "\n".join(html_parts)


def _decode_part(part: Message) -> str:
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except Exception:
        pass
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")
