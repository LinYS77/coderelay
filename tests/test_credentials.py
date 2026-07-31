from __future__ import annotations

from urllib.parse import quote

import pytest

from coderelay.domain.credentials import CredentialError, parse_flysms_credential, parse_outlook_credential

CLIENT_ID = "11111111-2222-4333-8444-555555555555"
REFRESH_TOKEN = "M." + "a" * 240
FLY_EMAIL = "box.name@icloud.com"
FLY_TOKEN = "tok_test-token_with-safe-characters_123456"


def fly_credential(*, email: str = FLY_EMAIL, token: str = FLY_TOKEN, host: str = "flysms.xyz") -> str:
    return f"{email}---{token}---https://{host}/icloud/pickup#email={quote(email, safe='')}&key={quote(token, safe='')}"


def test_parse_outlook_credential_discards_password() -> None:
    credential = parse_outlook_credential(
        f"User@Example.com----super-secret-password----{CLIENT_ID}----{REFRESH_TOKEN}"
    )
    assert credential.email == "user@example.com"
    assert credential.client_id == CLIENT_ID
    assert credential.refresh_token == REFRESH_TOKEN
    assert not hasattr(credential, "password")


def test_parse_outlook_credential_rejects_bad_shape() -> None:
    with pytest.raises(CredentialError, match="email----password"):
        parse_outlook_credential("not-four-parts")


def test_parse_flysms_credential_validates_duplicated_components() -> None:
    credential = parse_flysms_credential(fly_credential())
    assert credential.email == FLY_EMAIL
    assert credential.token == FLY_TOKEN


def test_parse_flysms_credential_rejects_component_mismatch() -> None:
    raw = fly_credential().replace(f"key={FLY_TOKEN}", "key=tok_different_token_123456")
    with pytest.raises(CredentialError, match="do not match"):
        parse_flysms_credential(raw)


@pytest.mark.parametrize(
    "raw",
    [
        fly_credential(host="example.com"),
        fly_credential().replace("https://", "http://", 1),
        fly_credential().replace("/icloud/pickup", "/icloud/other", 1),
        fly_credential() + "&extra=value",
    ],
)
def test_parse_flysms_credential_rejects_noncanonical_or_extra_url(raw: str) -> None:
    with pytest.raises(CredentialError):
        parse_flysms_credential(raw)
