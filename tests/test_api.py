from __future__ import annotations

import re

from fastapi.testclient import TestClient

from coderelay.app import create_app
from coderelay.domain.errors import NoFreshCode
from coderelay.domain.models import CodeResult, CredentialUpdate

TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def auth(api_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_token}"}


def test_health_is_public_but_api_requires_bearer(app_config, api_token: str) -> None:
    with TestClient(create_app(app_config)) as client:
        live = client.get("/health/live")
        assert live.status_code == 200
        assert live.json()["version"] == "0.3.0"
        assert client.get("/health/ready").json() == {"status": "ready", "mode": "stateless"}

        payload = {"type": "totp", "credential": TOTP_SECRET, "min_ttl": 0}
        unauthorized = client.post("/api/v1/code", json=payload)
        assert unauthorized.status_code == 401
        assert unauthorized.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
        assert unauthorized.headers["www-authenticate"] == "Bearer"

        token_in_url = client.post(f"/api/v1/code?api_token={api_token}", json=payload)
        assert token_in_url.status_code == 401
        wrong = client.post("/api/v1/code", json=payload, headers={"Authorization": "Bearer invalid-token"})
        assert wrong.status_code == 401


def test_totp_post_returns_minimal_json(app_config, api_token: str) -> None:
    with TestClient(create_app(app_config)) as client:
        response = client.post(
            "/api/v1/code",
            json={"type": "totp", "credential": TOTP_SECRET, "min_ttl": 0},
            headers=auth(api_token),
        )
    assert response.status_code == 200, response.text
    assert set(response.json()) == {"code"}
    assert re.fullmatch(r"\d{6}", response.json()["code"])
    assert response.headers["cache-control"].startswith("no-store")
    assert response.headers["x-content-type-options"] == "nosniff"


def test_old_source_routes_are_removed(app_config, api_token: str) -> None:
    with TestClient(create_app(app_config)) as client:
        assert client.get("/api/v1/sources", headers=auth(api_token)).status_code == 404
        assert client.get("/api/v1/codes/anything", headers=auth(api_token)).status_code == 404
        assert client.get("/").status_code == 404
        assert client.get("/login").status_code == 404
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_request_credential_is_not_echoed_on_validation_parse_error_or_logs(
    app_config,
    api_token: str,
    capsys,
) -> None:
    secret = "sensitive-request-credential-value"
    with TestClient(create_app(app_config)) as client:
        validation = client.post(
            "/api/v1/code",
            json={"type": "unknown", "credential": secret},
            headers=auth(api_token),
        )
        malformed = client.post(
            "/api/v1/code",
            json={"type": "outlook", "credential": secret, "wait_seconds": 0},
            headers=auth(api_token),
        )
    assert validation.status_code == 422
    assert malformed.status_code == 422
    assert secret not in validation.text
    assert secret not in malformed.text
    assert malformed.json()["error"]["code"] == "INVALID_CODE_REQUEST"
    assert secret not in capsys.readouterr().err


def test_success_can_return_request_scoped_outlook_rotation(app_config, api_token: str) -> None:
    rotated = "M." + "r" * 240

    class StubService:
        async def resolve(self, command):
            command.credential = ""
            return CodeResult(code="123456", credential_update=CredentialUpdate(refresh_token=rotated))

        def close(self):
            return None

    with TestClient(create_app(app_config)) as client:
        client.app.state.container.code_service = StubService()
        response = client.post(
            "/api/v1/code",
            json={"type": "outlook", "credential": "request-only-secret", "wait_seconds": 0},
            headers=auth(api_token),
        )
    assert response.status_code == 200
    assert response.json() == {"code": "123456", "credential_update": {"refresh_token": rotated}}


def test_error_can_return_rotation_without_server_persistence(app_config, api_token: str) -> None:
    rotated = "M." + "e" * 240

    class StubService:
        async def resolve(self, command):
            command.credential = ""
            raise NoFreshCode(credential_update=CredentialUpdate(refresh_token=rotated))

        def close(self):
            return None

    with TestClient(create_app(app_config)) as client:
        client.app.state.container.code_service = StubService()
        response = client.post(
            "/api/v1/code",
            json={"type": "outlook", "credential": "request-only-secret", "wait_seconds": 0},
            headers=auth(api_token),
        )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NO_FRESH_CODE"
    assert response.json()["credential_update"] == {"refresh_token": rotated}


def test_unauthenticated_api_attempts_are_rate_limited(app_config) -> None:
    limited_config = app_config.model_copy(
        update={"security": app_config.security.model_copy(update={"api_rate_limit_per_minute": 2})}
    )
    payload = {"type": "totp", "credential": TOTP_SECRET}
    with TestClient(create_app(limited_config)) as client:
        assert client.post("/api/v1/code", json=payload).status_code == 401
        assert client.post("/api/v1/code", json=payload).status_code == 401
        limited = client.post("/api/v1/code", json=payload)
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMITED"
    assert int(limited.headers["retry-after"]) >= 1


def test_request_body_limit(app_config, api_token: str) -> None:
    with TestClient(create_app(app_config)) as client:
        response = client.post(
            "/api/v1/code",
            content=b"x" * 140_000,
            headers={**auth(api_token), "Content-Type": "application/json"},
        )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"
