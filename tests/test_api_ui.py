from __future__ import annotations

import re

from fastapi.testclient import TestClient

from coderelay.app import create_app


def test_health_and_ui_redirect(app_config) -> None:
    with TestClient(create_app(app_config)) as client:
        live = client.get("/health/live")
        assert live.status_code == 200
        assert live.json()["status"] == "ok"
        assert live.headers["cache-control"] == "no-store"
        assert client.get("/", follow_redirects=False).headers["location"] == "/login"
        login = client.get("/login")
        assert login.status_code == 200
        assert "登录 CodeRelay" in login.text
        assert "default-src 'self'" in login.headers["content-security-policy"]


def test_api_requires_auth_and_returns_no_store(app_config, api_token: str) -> None:
    with TestClient(create_app(app_config)) as client:
        unauthorized = client.get("/api/v1/sources")
        assert unauthorized.status_code == 401
        assert unauthorized.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
        assert unauthorized.headers["www-authenticate"] == "Bearer"

        code_without_auth = client.get("/api/v1/codes/test_totp?min_ttl=0")
        assert code_without_auth.status_code == 401
        code_with_token_in_url = client.get(f"/api/v1/codes/test_totp?min_ttl=0&api_token={api_token}")
        assert code_with_token_in_url.status_code == 401
        code_with_wrong_bearer = client.get(
            "/api/v1/codes/test_totp?min_ttl=0",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert code_with_wrong_bearer.status_code == 401

        response = client.get(
            "/api/v1/sources",
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert response.status_code == 200
        assert response.json()[0]["id"] == "test_totp"
        assert response.headers["cache-control"].startswith("no-store")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-request-id"]


def test_unauthenticated_api_attempts_are_rate_limited(app_config) -> None:
    limited_config = app_config.model_copy(
        update={
            "security": app_config.security.model_copy(update={"api_rate_limit_per_minute": 2}),
        }
    )
    with TestClient(create_app(limited_config)) as client:
        assert client.get("/api/v1/sources").status_code == 401
        assert client.get("/api/v1/sources").status_code == 401
        limited = client.get("/api/v1/sources")
        assert limited.status_code == 429
        assert limited.json()["error"]["code"] == "RATE_LIMITED"
        assert int(limited.headers["retry-after"]) >= 1


def test_totp_api_returns_six_digit_string(app_config, api_token: str) -> None:
    with TestClient(create_app(app_config)) as client:
        response = client.get(
            "/api/v1/codes/test_totp?min_ttl=0",
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert re.fullmatch(r"\d{6}", payload["code"])
        assert payload["kind"] == "totp"
        assert payload["expires_at"]
        assert payload["evidence"] == {"sender": None, "subject": None, "message_fingerprint": None}


def test_ui_login_session_and_logout(app_config) -> None:
    with TestClient(create_app(app_config)) as client:
        wrong = client.post("/auth/login", json={"password": "incorrect password"})
        assert wrong.status_code == 401

        logged_in = client.post("/auth/login", json={"password": "correct horse battery staple"})
        assert logged_in.status_code == 200
        assert "coderelay_session=" in logged_in.headers["set-cookie"]
        assert "HttpOnly" in logged_in.headers["set-cookie"]
        assert "SameSite=strict" in logged_in.headers["set-cookie"]

        dashboard = client.get("/app")
        assert dashboard.status_code == 200
        assert "已配置来源" in dashboard.text
        assert client.get("/api/v1/sources").status_code == 200

        logout = client.post("/auth/logout")
        assert logout.status_code == 200
        assert client.get("/app", follow_redirects=False).headers["location"] == "/login"


def test_request_body_limit(app_config) -> None:
    with TestClient(create_app(app_config)) as client:
        response = client.post(
            "/auth/login",
            content=b"x" * 70_000,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"


def test_production_docs_are_not_exposed(app_config) -> None:
    with TestClient(create_app(app_config)) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
