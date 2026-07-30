from __future__ import annotations

import os
from pathlib import Path

import pytest

from coderelay.config import AppConfig, ConfigError, load_config
from coderelay.security import (
    SecretFileError,
    SessionSigner,
    decode_key_material,
    generate_api_token,
    generate_key_material,
    hash_api_token,
    hash_ui_password,
    read_secret,
    verify_api_token,
    verify_ui_password,
)


def test_example_config_parses_and_resolves_paths() -> None:
    config = load_config("config.example.toml")
    assert [source.type for source in config.sources] == ["totp", "outlook_imap", "flysms"]
    assert config.security.api_token_hash_files[0].is_absolute()
    assert config.sources[0].id == "primary_totp"


def test_config_rejects_duplicate_source_ids(app_config: AppConfig) -> None:
    payload = app_config.model_dump(exclude={"config_path"})
    payload["sources"].append(payload["sources"][0].copy())
    with pytest.raises(ValueError, match="unique"):
        AppConfig.model_validate(payload)


def test_config_rejects_wildcard_host(app_config: AppConfig) -> None:
    payload = app_config.model_dump(exclude={"config_path"})
    payload["server"]["allowed_hosts"] = ["*"]
    with pytest.raises(ValueError, match="cannot be blank"):
        AppConfig.model_validate(payload)


def test_load_config_reports_invalid_toml(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("[[bad", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(path)


def test_api_token_hash_and_verification() -> None:
    token = generate_api_token()
    stored = hash_api_token(token)
    assert token.startswith("cr_live_")
    assert verify_api_token(token, [stored])
    assert not verify_api_token(token + "x", [stored])
    assert not verify_api_token("", [stored])


def test_ui_password_is_argon2id() -> None:
    encoded = hash_ui_password("a sufficiently long password")
    assert encoded.startswith("$argon2id$")
    assert verify_ui_password("a sufficiently long password", encoded)
    assert not verify_ui_password("wrong password", encoded)


def test_password_minimum_length() -> None:
    with pytest.raises(ValueError, match="14"):
        hash_ui_password("too short")


def test_session_signer_expiry() -> None:
    key = decode_key_material(generate_key_material())
    signer = SessionSigner(key, lifetime_seconds=60)
    token = signer.issue(now=1_000)
    claims = signer.verify(token, now=1_030)
    assert claims is not None
    assert claims.expires_at == 1_060
    assert signer.verify(token, now=1_060) is None
    assert signer.verify(token + "tampered", now=1_030) is None


def test_secret_file_permission_check(tmp_path: Path) -> None:
    path = tmp_path / "secret"
    path.write_text("value\n", encoding="utf-8")
    os.chmod(path, 0o644)
    with pytest.raises(SecretFileError, match="group/others"):
        read_secret(path, strict_permissions=True)
    assert read_secret(path, strict_permissions=False) == "value"


def test_secret_reader_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("value\n", encoding="utf-8")
    os.chmod(target, 0o600)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(SecretFileError, match="cannot access"):
        read_secret(link, strict_permissions=True)
