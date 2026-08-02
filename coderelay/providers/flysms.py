from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import quote

import httpx

from coderelay.config import FlySmsProviderSettings
from coderelay.domain.credentials import FlySmsCredential
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
from coderelay.domain.models import CodeRequest, MailMessage, ProviderCode
from coderelay.providers.base import CodeProvider
from coderelay.providers.http_utils import bounded_json, parse_iso_datetime, parse_retry_after, require_text


class FlySmsProvider(CodeProvider):
    provider_type = "flysms"
    # A cold FlySMS/iCloud synchronization can take several upstream requests.
    # Keep a bounded but larger budget than the default single-request timeout.
    fetch_timeout_seconds = 45.0

    def __init__(
        self,
        settings: FlySmsProviderSettings,
        client: httpx.AsyncClient,
        credential: FlySmsCredential,
    ) -> None:
        self.settings = settings
        self.poll_interval_seconds = settings.poll_interval_seconds
        self._client = client
        self._extractor = CodeExtractor(settings.extractor)
        self._email = credential.email
        self._token = credential.token

    async def fetch_code(self, request: CodeRequest) -> ProviderCode | None:
        now = datetime.now(UTC)
        latest_data = await self._request(f"{self.settings.base_url}/latest", allow_not_found=True)
        if latest_data is not None:
            latest = self._parse_detail(latest_data)
            extracted = self._extractor.extract([latest], not_before=request.not_before, now=now)
            if extracted:
                return self._result(extracted.code, extracted.message, now)

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
                return self._result(extracted.code, extracted.message, now)

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
                return self._result(extracted.code, extracted.message, now)
        return None

    def close(self) -> None:
        self._email = ""
        self._token = ""

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
            provider_sequence=uid,
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
                    provider_sequence=uid,
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
        now: datetime,
    ) -> ProviderCode:
        return ProviderCode(
            code=code,
            observed_at=now,
            received_at=message.received_at,
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
