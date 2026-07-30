from __future__ import annotations

import os
from pathlib import Path

import pytest

from coderelay.infra.credential_store import (
    CredentialStoreError,
    EncryptedOutlookCredentialStore,
    OutlookCredential,
    parse_four_part_credential,
)
from coderelay.security import generate_key_material

CLIENT_ID = "11111111-2222-4333-8444-555555555555"
REFRESH_TOKEN = "M." + "a" * 240


def test_parse_four_part_credential_discards_password() -> None:
    credential = parse_four_part_credential(
        f"User@Example.com----super-secret-password----{CLIENT_ID}----{REFRESH_TOKEN}"
    )
    assert credential.email == "user@example.com"
    assert credential.client_id == CLIENT_ID
    assert credential.refresh_token == REFRESH_TOKEN
    assert not hasattr(credential, "password")


def test_parse_four_part_credential_rejects_bad_shape() -> None:
    with pytest.raises(CredentialStoreError, match="email----password"):
        parse_four_part_credential("not-four-parts")


def test_encrypted_outlook_credential_round_trip(secret_writer, tmp_path: Path) -> None:
    key_file = secret_writer("outlook.key", generate_key_material())
    credential_file = tmp_path / "data" / "outlook.enc"
    store = EncryptedOutlookCredentialStore(
        credential_file,
        key_file,
        source_id="outlook_test",
        strict_permissions=True,
    )
    credential = OutlookCredential(
        email="user@example.com",
        client_id=CLIENT_ID,
        refresh_token=REFRESH_TOKEN,
    )
    store.save(credential)

    payload = credential_file.read_bytes()
    assert b"user@example.com" not in payload
    assert REFRESH_TOKEN.encode() not in payload
    assert b"super-secret-password" not in payload
    assert os.stat(credential_file).st_mode & 0o077 == 0
    assert store.load() == credential


def test_encrypted_outlook_credential_rotates_token(secret_writer, tmp_path: Path) -> None:
    key_file = secret_writer("outlook.key", generate_key_material())
    credential_file = tmp_path / "outlook.enc"
    store = EncryptedOutlookCredentialStore(
        credential_file,
        key_file,
        source_id="outlook_test",
        strict_permissions=True,
    )
    first = OutlookCredential("user@example.com", CLIENT_ID, REFRESH_TOKEN)
    store.save(first)
    rotated = first.with_refresh_token("M." + "b" * 240)
    store.save(rotated, overwrite=True)
    assert store.load() == rotated


def test_encrypted_outlook_credential_rejects_wrong_key(secret_writer, tmp_path: Path) -> None:
    key_one = secret_writer("one.key", generate_key_material())
    key_two = secret_writer("two.key", generate_key_material())
    credential_file = tmp_path / "outlook.enc"
    first = EncryptedOutlookCredentialStore(
        credential_file,
        key_one,
        source_id="mail",
        strict_permissions=True,
    )
    first.save(OutlookCredential("user@example.com", CLIENT_ID, REFRESH_TOKEN))
    second = EncryptedOutlookCredentialStore(
        credential_file,
        key_two,
        source_id="mail",
        strict_permissions=True,
    )
    with pytest.raises(CredentialStoreError, match="authentication failed"):
        second.load()
