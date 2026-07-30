from __future__ import annotations

from datetime import UTC, datetime

import pytest

from coderelay.config import TotpSourceSettings
from coderelay.domain.errors import InvalidCodeRequest
from coderelay.domain.models import CodeRequest
from coderelay.providers.totp import TotpProvider


@pytest.mark.asyncio
async def test_totp_matches_rfc_derived_six_digit_value(secret_writer) -> None:
    secret = secret_writer("totp", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    now = datetime.fromtimestamp(1_111_111_111, UTC)
    settings = TotpSourceSettings(
        id="rfc_totp",
        type="totp",
        display_name="RFC",
        secret_file=secret,
        default_min_ttl_seconds=0,
    )
    provider = TotpProvider(settings, strict_secret_permissions=True, now=lambda: now)
    result = await provider.fetch_code(CodeRequest(source_id="rfc_totp", min_ttl_seconds=0))
    assert result.code == "050471"
    assert result.valid_from == datetime.fromtimestamp(1_111_111_110, UTC)
    assert result.expires_at == datetime.fromtimestamp(1_111_111_140, UTC)
    assert result.remaining_seconds == 29


def test_totp_rejects_hotp_uri(secret_writer) -> None:
    secret = secret_writer("hotp", "otpauth://hotp/Test?secret=GEZDGNBV&counter=0")
    settings = TotpSourceSettings(id="bad_hotp", type="totp", display_name="Bad", secret_file=secret)
    with pytest.raises(ValueError, match="non-TOTP"):
        TotpProvider(settings, strict_secret_permissions=True)


@pytest.mark.asyncio
async def test_totp_rejects_impossible_minimum_ttl(secret_writer) -> None:
    secret = secret_writer("totp-short", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    settings = TotpSourceSettings(
        id="short_totp",
        type="totp",
        display_name="Short",
        secret_file=secret,
        period_seconds=15,
        default_min_ttl_seconds=0,
    )
    provider = TotpProvider(settings, strict_secret_permissions=True)
    with pytest.raises(InvalidCodeRequest):
        await provider.fetch_code(CodeRequest(source_id="short_totp", min_ttl_seconds=15))
