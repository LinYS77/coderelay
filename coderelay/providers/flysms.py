from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import quote

import httpx

from coderelay.config import FlySmsSourceSettings
from coderelay.domain.errors import (
    SourceCredentialsInvalid,
    SourceExpiredOrDisabled,
    SourceRateLimited,
    SourceSyncing,
    UpstreamFailure,
    UpstreamSchemaChanged,
    UpstreamTimeout,
)
from coderelay.domain.extractor import CodeExtractor
from coderelay.domain.models import CodeRequest, MailMessage, ProviderCode, SourceKind, SourceState, SourceStatus
from coderelay.providers.base import CodeProvider
from coderelay.providers.http_utils import bounded_json, parse_iso_datetime, parse_retry_after, require_text
from coderelay.security import mask_email, read_secret

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_TOKEN_RE = re.compile(r"^tok_[A-Za-z0-9_-]+$")


class FlySmsProvider(CodeProvider):
    provider_type = "flysms"

    def __init__(
        self,
        settings: FlySmsSourceSettings,
        client: httpx.AsyncClient,
        *,
        strict_secret_permissions: bool,
    ) -> None:
        self.settings = settings
        self.id = settings.id
        self.display_name = settings.display_name
        self.poll_interval_seconds = settings.poll_interval_seconds
        self._client = client
        self._extractor = CodeExtractor(settings.extractor)
        self._email = read_secret(
            settings.email_file,
            strict_permissions=strict_secret_permissions,
            max_bytes=512,
        ).casefold()
        self._token = read_secret(
            settings.token_file,
            strict_permissions=strict_secret_permissions,
            max_bytes=1_024,
        )
        if not _EMAIL_RE.fullmatch(self._email):
            raise ValueError(f"FlySMS source {self.id!r} has an invalid mailbox email")
        if not _TOKEN_RE.fullmatch(self._token):
            raise ValueError(f"FlySMS source {self.id!r} has an invalid pickup token")

    async def fetch_code(self, request: CodeRequest) -> ProviderCode | None:
        now = datetime.now(UTC)
        latest_data = await self._request(f"{self.settings.base_url}/latest", allow_not_found=True)
        if latest_data is not None:
            latest = self._parse_detail(latest_data)
            extracted = self._extractor.extract([latest], not_before=request.not_before, now=now)
            if extracted:
                return self._result(
                    extracted.code, extracted.message, extracted.redacted_subject, extracted.message_fingerprint, now
                )

        summaries_data = await self._request(
            self.settings.base_url,
            params={"limit": str(self.settings.history_limit)},
            allow_not_found=True,
        )
        if summaries_data is None:
            return None
        summaries = self._parse_summaries(summaries_data)
        if summaries:
            extracted = self._extractor.extract(summaries, not_before=request.not_before, now=now)
            if extracted:
                return self._result(
                    extracted.code, extracted.message, extracted.redacted_subject, extracted.message_fingerprint, now
                )

        for summary in summaries[: self.settings.max_detail_messages]:
            mailbox, uid = self._split_provider_id(summary.provider_message_id)
            detail_data = await self._request(
                f"{self.settings.base_url}/{uid}",
                params={"mailbox": mailbox},
                allow_not_found=True,
            )
            if detail_data is None:
                continue
            detail = self._parse_detail(detail_data)
            extracted = self._extractor.extract([detail], not_before=request.not_before, now=now)
            if extracted:
                return self._result(
                    extracted.code, extracted.message, extracted.redacted_subject, extracted.message_fingerprint, now
                )
        return None

    def status(self) -> SourceStatus:
        return SourceStatus(
            id=self.id,
            display_name=self.display_name,
            provider_type=self.provider_type,
            kind=SourceKind.EMAIL,
            state=SourceState.EXPERIMENTAL,
            experimental=True,
            identity_hint=mask_email(self._email),
        )

    async def _request(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        allow_not_found: bool = False,
    ) -> object | None:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._token}",
            "X-Mailbox-Email": self._email,
        }
        try:
            response = await self._client.get(url, params=params, headers=headers)
        except httpx.TimeoutException as exc:
            raise UpstreamTimeout() from exc
        except httpx.HTTPError as exc:
            raise UpstreamFailure() from exc
        if response.status_code == 401:
            raise SourceCredentialsInvalid()
        if response.status_code == 403:
            raise SourceExpiredOrDisabled()
        if response.status_code == 404 and allow_not_found:
            return None
        if response.status_code == 429:
            retry_after = parse_retry_after(response.headers.get("Retry-After"), default=60)
            raise SourceRateLimited(retry_after_seconds=retry_after)
        if response.status_code == 503:
            retry_after = parse_retry_after(response.headers.get("Retry-After"), default=2)
            raise SourceSyncing(retry_after_seconds=retry_after)
        if response.status_code >= 500:
            raise UpstreamFailure()
        if response.status_code < 200 or response.status_code >= 300:
            raise UpstreamFailure()
        return bounded_json(response.content)

    def _parse_detail(self, value: object) -> MailMessage:
        if not isinstance(value, dict):
            raise UpstreamSchemaChanged()
        self._check_entitlement(value)
        response_email = require_text(value.get("email"), maximum=320).casefold()
        if response_email != self._email:
            raise UpstreamSchemaChanged()
        raw = value.get("message")
        if not isinstance(raw, dict):
            raise UpstreamSchemaChanged()
        mailbox = require_text(raw.get("mailbox"), maximum=512)
        uid = raw.get("uid")
        if not isinstance(uid, int) or isinstance(uid, bool) or uid < 1:
            raise UpstreamSchemaChanged()
        received_value = raw.get("mailboxReceivedAt") or raw.get("date") or raw.get("sentAt") or raw.get("ingestedAt")
        received_at = parse_iso_datetime(received_value)
        return MailMessage(
            provider_message_id=self._provider_id(mailbox, uid),
            subject=require_text(raw.get("subject"), maximum=10_000),
            sender=require_text(raw.get("from"), maximum=4_096),
            received_at=received_at,
            text=require_text(raw.get("text"), maximum=1_000_000),
            html=require_text(raw.get("html"), maximum=2_000_000, nullable=True),
        )

    def _parse_summaries(self, value: object) -> list[MailMessage]:
        if not isinstance(value, dict):
            raise UpstreamSchemaChanged()
        response_email = require_text(value.get("email"), maximum=320).casefold()
        if response_email != self._email:
            raise UpstreamSchemaChanged()
        raw_messages = value.get("messages")
        if not isinstance(raw_messages, list) or len(raw_messages) > 50:
            raise UpstreamSchemaChanged()
        messages: list[MailMessage] = []
        for raw in raw_messages:
            if not isinstance(raw, dict):
                raise UpstreamSchemaChanged()
            mailbox = require_text(raw.get("mailbox"), maximum=512)
            uid = raw.get("uid")
            if not isinstance(uid, int) or isinstance(uid, bool) or uid < 1:
                raise UpstreamSchemaChanged()
            messages.append(
                MailMessage(
                    provider_message_id=self._provider_id(mailbox, uid),
                    subject=require_text(raw.get("subject"), maximum=10_000),
                    sender=require_text(raw.get("from"), maximum=4_096),
                    received_at=parse_iso_datetime(raw.get("date")),
                    preview=require_text(raw.get("preview"), maximum=100_000),
                )
            )
        return messages

    @staticmethod
    def _check_entitlement(value: dict[object, object]) -> None:
        status = value.get("entitlementStatus")
        if status == "expired":
            raise SourceExpiredOrDisabled()
        if status == "pending":
            raise SourceSyncing(retry_after_seconds=2)
        if status is not None and status not in {"active", "unlimited"}:
            raise UpstreamSchemaChanged()

    def _result(
        self,
        code: str,
        message: MailMessage,
        redacted_subject: str,
        fingerprint: str,
        now: datetime,
    ) -> ProviderCode:
        return ProviderCode(
            source_id=self.id,
            kind=SourceKind.EMAIL,
            code=code,
            observed_at=now,
            received_at=message.received_at,
            freshness="fresh",
            evidence={
                "sender": message.sender[:320],
                "subject": redacted_subject,
                "message_fingerprint": fingerprint,
            },
        )

    @staticmethod
    def _provider_id(mailbox: str, uid: int) -> str:
        return f"flysms:{quote(mailbox, safe='')}:{uid}"

    @staticmethod
    def _split_provider_id(value: str) -> tuple[str, int]:
        prefix, encoded_mailbox, raw_uid = value.split(":", 2)
        if prefix != "flysms":
            raise UpstreamSchemaChanged()
        from urllib.parse import unquote

        return unquote(encoded_mailbox), int(raw_uid)
