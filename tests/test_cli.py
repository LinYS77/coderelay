from __future__ import annotations

import io
import os
from pathlib import Path

from coderelay.cli import main
from coderelay.infra.credential_store import EncryptedOutlookCredentialStore
from coderelay.security import decode_key_material, generate_key_material, read_secret, verify_api_token


def test_cli_generates_api_token_hash(tmp_path: Path, capsys) -> None:
    output = tmp_path / "api.hash"
    assert main(["generate-api-token", "--hash-file", str(output)]) == 0
    captured = capsys.readouterr().out.strip().splitlines()
    token = captured[-1]
    stored = read_secret(output, strict_permissions=True)
    assert verify_api_token(token, [stored])
    assert os.stat(output).st_mode & 0o077 == 0


def test_cli_generates_key(tmp_path: Path) -> None:
    output = tmp_path / "session.key"
    assert main(["generate-key", "--output", str(output)]) == 0
    assert len(decode_key_material(read_secret(output, strict_permissions=True))) == 32
    assert main(["generate-key", "--output", str(output)]) == 2


def test_cli_hashes_password_from_stdin(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "password.hash"
    monkeypatch.setattr("sys.stdin", io.StringIO("a long command line safe password\n"))
    assert main(["hash-password", "--password-stdin", "--output", str(output)]) == 0
    assert read_secret(output, strict_permissions=True).startswith("$argon2id$")


def test_cli_imports_outlook_credential_without_password(tmp_path: Path, secret_writer, monkeypatch) -> None:
    key_file = secret_writer("outlook-import.key", generate_key_material())
    credential_file = tmp_path / "outlook.enc"
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        f'''[security]
api_token_hash_files = ["dummy-api-hash"]
ui_password_hash_file = "dummy-password"
session_secret_file = "dummy-session"
strict_secret_permissions = true

[[sources]]
id = "outlook_primary"
type = "outlook_imap"
display_name = "Outlook"
credential_file = "{credential_file}"
credential_key_file = "{key_file}"
''',
        encoding="utf-8",
    )
    refresh_token = "M." + "x" * 240
    raw = (
        "user@example.com----password-that-must-not-be-stored----"
        "11111111-2222-4333-8444-555555555555----"
        f"{refresh_token}\n"
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(raw))
    assert (
        main(
            [
                "outlook-import",
                "--config",
                str(config_file),
                "--credential-stdin",
                "outlook_primary",
            ]
        )
        == 0
    )
    encrypted = credential_file.read_bytes()
    assert b"password-that-must-not-be-stored" not in encrypted
    store = EncryptedOutlookCredentialStore(
        credential_file,
        key_file,
        source_id="outlook_primary",
        strict_permissions=True,
    )
    credential = store.load()
    assert credential.email == "user@example.com"
    assert credential.refresh_token == refresh_token
    assert not hasattr(credential, "password")
