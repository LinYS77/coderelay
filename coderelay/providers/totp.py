from __future__ import annotations

import asyncio
import hashlib
import math
from collections.abc import Callable
from datetime import UTC, datetime

import pyotp

from coderelay.config import TotpSourceSettings
from coderelay.domain.errors import InvalidCodeRequest
from coderelay.domain.models import CodeRequest, ProviderCode, SourceKind, SourceState, SourceStatus
from coderelay.providers.base import CodeProvider
from coderelay.security import read_secret

_DIGESTS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


class TotpProvider(CodeProvider):
    provider_type = "totp"
    poll_interval_seconds = 0.0
    fetch_timeout_seconds = 35.0

    def __init__(
        self,
        settings: TotpSourceSettings,
        *,
        strict_secret_permissions: bool,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings
        self.id = settings.id
        self.display_name = settings.display_name
        self._now = now or (lambda: datetime.now(UTC))
        raw = read_secret(
            settings.secret_file,
            strict_permissions=strict_secret_permissions,
            max_bytes=8_192,
        )
        if raw.casefold().startswith("otpauth://"):
            otp = pyotp.parse_uri(raw)
            if not isinstance(otp, pyotp.TOTP):
                raise ValueError(f"TOTP source {self.id!r} contains a non-TOTP otpauth URI")
            if otp.digits != 6:
                raise ValueError(f"TOTP source {self.id!r} must generate exactly six digits")
            self._totp = otp
        else:
            secret = "".join(raw.split())
            self._totp = pyotp.TOTP(
                secret,
                digits=6,
                digest=_DIGESTS[settings.algorithm],
                interval=settings.period_seconds,
            )
        # Decode and generate once so malformed Base32 fails during startup.
        self._totp.at(0)

    async def fetch_code(self, request: CodeRequest) -> ProviderCode:
        minimum_ttl = max(request.min_ttl_seconds, self.settings.default_min_ttl_seconds)
        if minimum_ttl >= self._totp.interval:
            raise InvalidCodeRequest()
        now = self._utc_now()
        remaining_precise = self._expires_timestamp(now.timestamp()) - now.timestamp()
        if minimum_ttl and remaining_precise < minimum_ttl:
            await asyncio.sleep(max(0.0, remaining_precise) + 0.05)
            now = self._utc_now()

        timestamp = now.timestamp()
        interval = self._totp.interval
        valid_from_timestamp = math.floor(timestamp / interval) * interval
        expires_timestamp = valid_from_timestamp + interval
        remaining = max(0, math.ceil(expires_timestamp - timestamp))
        code = self._totp.at(timestamp)
        return ProviderCode(
            source_id=self.id,
            kind=SourceKind.TOTP,
            code=code,
            observed_at=now,
            valid_from=datetime.fromtimestamp(valid_from_timestamp, UTC),
            expires_at=datetime.fromtimestamp(expires_timestamp, UTC),
            remaining_seconds=remaining,
            freshness="current",
            evidence={},
        )

    def status(self) -> SourceStatus:
        return SourceStatus(
            id=self.id,
            display_name=self.display_name,
            provider_type=self.provider_type,
            kind=SourceKind.TOTP,
            state=SourceState.READY,
        )

    def _utc_now(self) -> datetime:
        value = self._now()
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    def _expires_timestamp(self, timestamp: float) -> float:
        interval = self._totp.interval
        return (math.floor(timestamp / interval) + 1) * interval
