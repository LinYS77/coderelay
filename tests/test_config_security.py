from __future__ import annotations

import os
from pathlib import Path

import pytest

from coderelay.config import AppConfig, ConfigError, ExtractorSettings, load_config
from coderelay.security import SecretFileError, generate_api_token, hash_api_token, read_secret, verify_api_token


def test_example_config_is_stateless_and_resolves_only_api_hashes() -> None:
    config = load_config("config.example.toml")
    assert config.security.api_token_hash_files[0].is_absolute()
    assert config.providers.outlook.imap_host == "outlook.office365.com"
    assert config.providers.flysms.base_url == "https://flysms.xyz/icloud/api/pickup/messages"
    assert not hasattr(config, "sources")
    assert not hasattr(config.security, "ui_password_hash_file")
    assert not hasattr(config.security, "session_secret_file")


def test_config_rejects_legacy_persisted_sources(app_config: AppConfig) -> None:
    payload = app_config.model_dump(exclude={"config_path"})
    payload["sources"] = [{"type": "totp", "secret_file": "secret"}]
    with pytest.raises(ValueError, match="Extra inputs"):
        AppConfig.model_validate(payload)


def test_config_rejects_wildcard_host(app_config: AppConfig) -> None:
    payload = app_config.model_dump(exclude={"config_path"})
    payload["server"]["allowed_hosts"] = ["*"]
    with pytest.raises(ValueError, match="cannot be blank"):
        AppConfig.model_validate(payload)


def test_config_rejects_runtime_upstream_override(app_config: AppConfig) -> None:
    payload = app_config.model_dump(exclude={"config_path"})
    payload["providers"]["flysms"]["base_url"] = "https://attacker.example/messages"
    with pytest.raises(ValueError):
        AppConfig.model_validate(payload)


def test_load_config_reports_invalid_toml(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("[[bad", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(path)


def test_extractor_settings_normalize_casefold_and_reject_non_re2() -> None:
    settings = ExtractorSettings(
        senders=[" Alerts@Example.com ", "alerts@example.com"],
        sender_domains=[" @Trusted.Example "],
        subject_keywords=[" Straße ", "STRASSE"],
    )
    assert settings.senders == ["alerts@example.com"]
    assert settings.sender_domains == ["trusted.example"]
    assert settings.subject_keywords == ["strasse"]

    for pattern in (
        r"(?P<code>[0-9]{6})(?=x)",
        r"(?P<code>[0-9]{6})\1",
        r"([0-9]{6})",
    ):
        with pytest.raises(ValueError):
            ExtractorSettings(patterns=[pattern])


def test_api_token_hash_and_verification() -> None:
    token = generate_api_token()
    stored = hash_api_token(token)
    assert token.startswith("cr_live_")
    assert verify_api_token(token, [stored])
    assert not verify_api_token(token + "x", [stored])
    assert not verify_api_token("", [stored])


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
