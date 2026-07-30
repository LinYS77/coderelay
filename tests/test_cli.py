from __future__ import annotations

import io
import os
from pathlib import Path

from coderelay.cli import main
from coderelay.security import decode_key_material, read_secret, verify_api_token


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
