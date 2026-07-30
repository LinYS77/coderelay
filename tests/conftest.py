from __future__ import annotations

import os
from pathlib import Path

import pytest

from coderelay.config import AppConfig
from coderelay.security import generate_api_token, generate_key_material, hash_api_token, hash_ui_password


@pytest.fixture
def secret_writer(tmp_path: Path):
    def write(name: str, value: str) -> Path:
        path = tmp_path / name
        path.write_text(value + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    return write


@pytest.fixture
def api_token() -> str:
    return generate_api_token()


@pytest.fixture
def app_config(secret_writer, tmp_path: Path, api_token: str) -> AppConfig:
    token_hash = secret_writer("api-token.sha256", hash_api_token(api_token))
    password_hash = secret_writer("ui-password.argon2", hash_ui_password("correct horse battery staple"))
    session_key = secret_writer("session.key", generate_key_material())
    totp_secret = secret_writer("totp.secret", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    return AppConfig.model_validate(
        {
            "server": {
                "host": "127.0.0.1",
                "port": 8787,
                "allowed_hosts": ["testserver", "localhost", "127.0.0.1"],
                "max_wait_seconds": 2,
            },
            "security": {
                "api_token_hash_files": [token_hash],
                "ui_password_hash_file": password_hash,
                "session_secret_file": session_key,
                "cookie_secure": False,
                "strict_secret_permissions": True,
                "api_rate_limit_per_minute": 100,
                "login_rate_limit_per_minute": 5,
            },
            "sources": [
                {
                    "id": "test_totp",
                    "type": "totp",
                    "display_name": "Test TOTP",
                    "secret_file": totp_secret,
                    "default_min_ttl_seconds": 0,
                }
            ],
        }
    )
