from __future__ import annotations

import asyncio
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parseaddr
from urllib.parse import quote

import httpx
import msal
import requests

from coderelay.config import MicrosoftGraphSourceSettings
from coderelay.domain.errors import (
    ConfigurationFailure,
    SourceCredentialsInvalid,
    SourceRateLimited,
    SourceReauthRequired,
    SourceSyncing,
    UpstreamFailure,
    UpstreamSchemaChanged,
    UpstreamTimeout,
)
from coderelay.domain.extractor import CodeExtractor, normalize_datetime
from coderelay.domain.models import CodeRequest, MailMessage, ProviderCode, SourceKind, SourceState, SourceStatus
from coderelay.infra.msal_cache import EncryptedMsalCacheStore, TokenCacheError
from coderelay.providers.base import CodeProvider
from coderelay.providers.http_utils import bounded_json, parse_iso_datetime, parse_retry_after, require_text
from coderelay.security import mask_email, read_secret

_GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
_GRAPH_SCOPES = ["Mail.Read"]


class _MsalHttpClient:
    """Requests adapter with bounded timeouts and no ambient proxy inheritance."""

    def __init__(self, connect_timeout: float = 5.0, read_timeout: float = 10.0) -> None:
        self._timeout = (connect_timeout, read_timeout)
        self._session = requests.Session()
        self._session.trust_env = False
        self._session.headers["User-Agent"] = "CodeRelay-MSAL"

    def get(self, url: str, **kwargs: object) -> requests.Response:
        kwargs.setdefault("timeout", self._timeout)
        return self._session.get(url, **kwargs)  # type: ignore[arg-type]

    def post(self, url: str, **kwargs: object) -> requests.Response:
        kwargs.setdefault("timeout", self._timeout)
        return self._session.post(url, **kwargs)  # type: ignore[arg-type]

    def close(self) -> None:
        self._session.close()


class MicrosoftGraphProvider(CodeProvider):
    provider_type = "microsoft_graph"

    def __init__(
        self,
        settings: MicrosoftGraphSourceSettings,
        client: httpx.AsyncClient,
        *,
        strict_secret_permissions: bool,
    ) -> None:
        self.settings = settings
        self.id = settings.id
        self.display_name = settings.display_name
        self.poll_interval_seconds = settings.poll_interval_seconds
        self._client = client
        self._strict_permissions = strict_secret_permissions
        self._extractor = CodeExtractor(settings.extractor)
        self._client_id = _read_client_id(settings, strict_secret_permissions)
        try:
            self._cache_store = EncryptedMsalCacheStore(
                settings.token_cache_file,
                settings.token_cache_key_file,
                source_id=settings.id,
                strict_permissions=strict_secret_permissions,
            )
            self._cache = self._cache_store.create_cache()
        except (TokenCacheError, ValueError) as exc:
            raise ConfigurationFailure() from exc
        self._app: msal.PublicClientApplication | None = None
        self._msal_http = _MsalHttpClient()
        self._token_lock = threading.RLock()

    async def fetch_code(self, request: CodeRequest) -> ProviderCode | None:
        access_token = await asyncio.to_thread(self._get_access_token)
        now = datetime.now(UTC)
        params = {
            "$top": str(self.settings.page_size),
            "$orderby": "receivedDateTime desc",
            "$select": "id,subject,from,receivedDateTime,bodyPreview,internetMessageId",
        }
        value = await self._graph_get(
            f"{_GRAPH_ROOT}/me/mailFolders/inbox/messages",
            access_token,
            params=params,
        )
        messages = self._parse_collection(value)
        extracted = self._extractor.extract(messages, not_before=request.not_before, now=now)
        if extracted:
            return self._result(
                extracted.code, extracted.message, extracted.redacted_subject, extracted.message_fingerprint, now
            )

        detail_count = 0
        for summary in messages:
            if detail_count >= self.settings.max_detail_messages:
                break
            if request.not_before and normalize_datetime(summary.received_at) < normalize_datetime(request.not_before):
                continue
            detail_count += 1
            detail_value = await self._graph_get(
                f"{_GRAPH_ROOT}/me/messages/{quote(summary.provider_message_id, safe='')}",
                access_token,
                params={"$select": "id,subject,from,receivedDateTime,bodyPreview,body,internetMessageId"},
                allow_not_found=True,
            )
            if detail_value is None:
                continue
            detail = self._parse_message(detail_value, include_body=True)
            extracted = self._extractor.extract([detail], not_before=request.not_before, now=now)
            if extracted:
                return self._result(
                    extracted.code,
                    extracted.message,
                    extracted.redacted_subject,
                    extracted.message_fingerprint,
                    now,
                )
        return None

    def status(self) -> SourceStatus:
        with self._token_lock:
            accounts = list(self._cache.search(self._cache.CredentialType.ACCOUNT))
        state = SourceState.READY if accounts else SourceState.REQUIRES_SETUP
        username = self.settings.account_username
        if not username and len(accounts) == 1:
            raw_username = accounts[0].get("username")
            username = raw_username if isinstance(raw_username, str) else None
        return SourceStatus(
            id=self.id,
            display_name=self.display_name,
            provider_type=self.provider_type,
            kind=SourceKind.EMAIL,
            state=state,
            identity_hint=mask_email(username) if username else None,
        )

    def close(self) -> None:
        self._msal_http.close()

    def _get_access_token(self) -> str:
        with self._token_lock:
            try:
                if self._app is None:
                    self._app = msal.PublicClientApplication(
                        self._client_id,
                        authority=self.settings.authority,
                        token_cache=self._cache,
                        http_client=self._msal_http,
                    )
                accounts = self._app.get_accounts(username=self.settings.account_username)
                if not accounts:
                    raise SourceReauthRequired()
                if len(accounts) > 1 and not self.settings.account_username:
                    raise ConfigurationFailure(
                        "account_username is required when an MSAL cache contains multiple accounts"
                    )
                result = self._app.acquire_token_silent(_GRAPH_SCOPES, account=accounts[0])
                self._cache_store.save_if_changed(self._cache)
            except SourceReauthRequired:
                raise
            except ConfigurationFailure:
                raise
            except TokenCacheError as exc:
                raise ConfigurationFailure() from exc
            except Exception as exc:
                raise UpstreamFailure() from exc
            if not result or "access_token" not in result:
                error = result.get("error") if isinstance(result, dict) else None
                if error in {"invalid_grant", "interaction_required", "consent_required", "login_required"}:
                    raise SourceReauthRequired()
                raise SourceReauthRequired()
            token = result["access_token"]
            if not isinstance(token, str) or not token:
                raise UpstreamFailure()
            return token

    async def _graph_get(
        self,
        url: str,
        access_token: str,
        *,
        params: dict[str, str],
        allow_not_found: bool = False,
    ) -> object | None:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {access_token}",
            "Prefer": 'outlook.body-content-type="text"',
        }
        try:
            response = await self._client.get(url, params=params, headers=headers)
        except httpx.TimeoutException as exc:
            raise UpstreamTimeout() from exc
        except httpx.HTTPError as exc:
            raise UpstreamFailure() from exc
        if response.status_code == 401:
            raise SourceReauthRequired()
        if response.status_code == 403:
            raise SourceCredentialsInvalid()
        if response.status_code == 404 and allow_not_found:
            return None
        if response.status_code == 429:
            retry_after = parse_retry_after(response.headers.get("Retry-After"), default=5)
            raise SourceRateLimited(retry_after_seconds=retry_after)
        if response.status_code == 503:
            retry_after = parse_retry_after(response.headers.get("Retry-After"), default=2)
            raise SourceSyncing(retry_after_seconds=retry_after)
        if response.status_code >= 500:
            raise UpstreamFailure()
        if response.status_code < 200 or response.status_code >= 300:
            raise UpstreamFailure()
        return bounded_json(response.content)

    def _parse_collection(self, value: object) -> list[MailMessage]:
        if not isinstance(value, dict) or not isinstance(value.get("value"), list):
            raise UpstreamSchemaChanged()
        items = value["value"]
        if len(items) > self.settings.page_size:
            raise UpstreamSchemaChanged()
        return [self._parse_message(item, include_body=False) for item in items]

    def _parse_message(self, value: object, *, include_body: bool) -> MailMessage:
        if not isinstance(value, dict):
            raise UpstreamSchemaChanged()
        message_id = require_text(value.get("id"), maximum=8_192)
        sender_value = value.get("from")
        if not isinstance(sender_value, dict) or not isinstance(sender_value.get("emailAddress"), dict):
            raise UpstreamSchemaChanged()
        address_data = sender_value["emailAddress"]
        address = require_text(address_data.get("address"), maximum=320)
        name = require_text(address_data.get("name"), maximum=1_024, nullable=True)
        sender = f"{name} <{address}>" if name else address
        text = ""
        html = ""
        if include_body:
            body = value.get("body")
            if not isinstance(body, dict):
                raise UpstreamSchemaChanged()
            content = require_text(body.get("content"), maximum=1_000_000)
            content_type = require_text(body.get("contentType"), maximum=32).casefold()
            if content_type == "html":
                html = content
            elif content_type == "text":
                text = content
            else:
                raise UpstreamSchemaChanged()
        return MailMessage(
            provider_message_id=message_id,
            subject=require_text(value.get("subject"), maximum=10_000, nullable=True),
            sender=sender,
            received_at=parse_iso_datetime(value.get("receivedDateTime")),
            preview=require_text(value.get("bodyPreview"), maximum=100_000, nullable=True),
            text=text,
            html=html,
        )

    def _result(
        self,
        code: str,
        message: MailMessage,
        redacted_subject: str,
        fingerprint: str,
        now: datetime,
    ) -> ProviderCode:
        _, address = parseaddr(message.sender)
        return ProviderCode(
            source_id=self.id,
            kind=SourceKind.EMAIL,
            code=code,
            observed_at=now,
            received_at=message.received_at,
            freshness="fresh",
            evidence={
                "sender": (address or message.sender)[:320],
                "subject": redacted_subject,
                "message_fingerprint": fingerprint,
            },
        )


def _read_client_id(settings: MicrosoftGraphSourceSettings, strict_permissions: bool) -> str:
    value = read_secret(
        settings.client_id_file,
        strict_permissions=strict_permissions,
        max_bytes=256,
    )
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise ValueError(f"Microsoft source {settings.id!r} has an invalid client ID") from exc


def run_device_flow(
    settings: MicrosoftGraphSourceSettings,
    *,
    strict_secret_permissions: bool,
    show_message: Callable[[str], None],
) -> str | None:
    client_id = _read_client_id(settings, strict_secret_permissions)
    store = EncryptedMsalCacheStore(
        settings.token_cache_file,
        settings.token_cache_key_file,
        source_id=settings.id,
        strict_permissions=strict_secret_permissions,
    )
    cache = store.create_cache()
    http_client = _MsalHttpClient()
    try:
        app = msal.PublicClientApplication(
            client_id,
            authority=settings.authority,
            token_cache=cache,
            http_client=http_client,
        )
        flow = app.initiate_device_flow(scopes=_GRAPH_SCOPES)
        message = flow.get("message") if isinstance(flow, dict) else None
        if not isinstance(message, str) or "user_code" not in flow:
            error = flow.get("error") if isinstance(flow, dict) else "unknown_error"
            raise RuntimeError(f"Microsoft device flow could not start: {error}")
        show_message(message)
        result = app.acquire_token_by_device_flow(flow)
        store.save_if_changed(cache)
        if not isinstance(result, dict) or "access_token" not in result:
            error = result.get("error") if isinstance(result, dict) else "unknown_error"
            raise RuntimeError(f"Microsoft device flow failed: {error}")
        accounts = app.get_accounts(username=settings.account_username)
        if len(accounts) == 1 and isinstance(accounts[0].get("username"), str):
            return accounts[0]["username"]
        return settings.account_username
    finally:
        http_client.close()
