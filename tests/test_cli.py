from __future__ import annotations

import os
from pathlib import Path

import pytest

from coderelay.cli import main
from coderelay.security import read_secret, verify_api_token


def test_cli_generates_api_token_hash(tmp_path: Path, capsys) -> None:
    output = tmp_path / "api.hash"
    assert main(["generate-api-token", "--hash-file", str(output)]) == 0
    captured = capsys.readouterr().out.strip().splitlines()
    token = captured[-1]
    stored = read_secret(output, strict_permissions=True)
    assert verify_api_token(token, [stored])
    assert os.stat(output).st_mode & 0o077 == 0


def test_cli_validates_stateless_config(tmp_path: Path, capsys) -> None:
    token_file = tmp_path / "api.hash"
    assert main(["generate-api-token", "--hash-file", str(token_file)]) == 0
    capsys.readouterr()
    config = tmp_path / "config.toml"
    config.write_text(
        """[security]
api_token_hash_files = ["api.hash"]
strict_secret_permissions = true
""",
        encoding="utf-8",
    )
    assert main(["validate-config", "--config", str(config)]) == 0
    output = capsys.readouterr().out
    assert "mode: stateless" in output
    assert "totp, outlook, flysms" in output


@pytest.mark.parametrize("removed_command", ["outlook-import", "hash-password", "generate-key"])
def test_cli_removes_persistent_credential_commands(removed_command: str) -> None:
    with pytest.raises(SystemExit) as caught:
        main([removed_command])
    assert caught.value.code == 2
