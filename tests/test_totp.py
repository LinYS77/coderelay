from __future__ import annotations

from datetime import UTC, datetime

import pytest

from coderelay.domain.errors import InvalidCodeRequest
from coderelay.domain.models import CodeRequest
from coderelay.providers.totp import TotpProvider

SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


@pytest.mark.asyncio
async def test_totp_matches_rfc_derived_six_digit_value() -> None:
    now = datetime.fromtimestamp(1_111_111_111, UTC)
    provider = TotpProvider(SECRET, now=lambda: now)
    result = await provider.fetch_code(CodeRequest(min_ttl_seconds=0))
    assert result.code == "050471"
    assert result.valid_from == datetime.fromtimestamp(1_111_111_110, UTC)
    assert result.expires_at == datetime.fromtimestamp(1_111_111_140, UTC)
    assert result.remaining_seconds == 29


def test_totp_rejects_hotp_uri() -> None:
    with pytest.raises(ValueError, match="non-TOTP"):
        TotpProvider("otpauth://hotp/Test?secret=GEZDGNBV&counter=0")


@pytest.mark.asyncio
async def test_totp_rejects_impossible_minimum_ttl() -> None:
    provider = TotpProvider(SECRET)
    with pytest.raises(InvalidCodeRequest):
        await provider.fetch_code(CodeRequest(min_ttl_seconds=30))


def test_totp_drops_provider_reference_on_close() -> None:
    provider = TotpProvider(SECRET)
    provider.close()
    assert provider._totp is None
