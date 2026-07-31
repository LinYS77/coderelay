from __future__ import annotations

import asyncio
import hashlib
import math
from collections.abc import Callable
from datetime import UTC, datetime

import pyotp

from coderelay.domain.errors import InvalidCodeRequest
from coderelay.domain.models import CodeRequest, ProviderCode
from coderelay.providers.base import CodeProvider


class TotpProvider(CodeProvider):
    poll_interval_seconds = 0.0
    fetch_timeout_seconds = 35.0

    def __init__(self, credential: str, *, now: Callable[[], datetime] | None = None) -> None:
        self._now = now or (lambda: datetime.now(UTC))
        raw = credential.strip()
        if not raw or len(raw) > 8_192:
            raise ValueError("TOTP credential has an invalid length")
        if raw.casefold().startswith("otpauth://"):
            otp = pyotp.parse_uri(raw)
            if not isinstance(otp, pyotp.TOTP):
                raise ValueError("TOTP credential contains a non-TOTP otpauth URI")
            if otp.digits != 6:
                raise ValueError("TOTP credential must generate exactly six digits")
            self._totp: pyotp.TOTP | None = otp
        else:
            secret = "".join(raw.split())
            self._totp = pyotp.TOTP(secret, digits=6, digest=hashlib.sha1, interval=30)
        # Decode and generate once so malformed Base32 fails before the API reports success.
        self._totp.at(0)
        raw = ""
        credential = ""

    async def fetch_code(self, request: CodeRequest) -> ProviderCode:
        totp = self._totp
        if totp is None:
            raise InvalidCodeRequest()
        minimum_ttl = request.min_ttl_seconds
        if minimum_ttl >= totp.interval:
            raise InvalidCodeRequest()
        now = self._utc_now()
        remaining_precise = self._expires_timestamp(now.timestamp(), totp.interval) - now.timestamp()
        if minimum_ttl and remaining_precise < minimum_ttl:
            await asyncio.sleep(max(0.0, remaining_precise) + 0.05)
            now = self._utc_now()

        timestamp = now.timestamp()
        valid_from_timestamp = math.floor(timestamp / totp.interval) * totp.interval
        expires_timestamp = valid_from_timestamp + totp.interval
        return ProviderCode(
            code=totp.at(timestamp),
            observed_at=now,
            valid_from=datetime.fromtimestamp(valid_from_timestamp, UTC),
            expires_at=datetime.fromtimestamp(expires_timestamp, UTC),
            remaining_seconds=max(0, math.ceil(expires_timestamp - timestamp)),
        )

    def close(self) -> None:
        self._totp = None

    def _utc_now(self) -> datetime:
        value = self._now()
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @staticmethod
    def _expires_timestamp(timestamp: float, interval: int) -> float:
        return (math.floor(timestamp / interval) + 1) * interval
