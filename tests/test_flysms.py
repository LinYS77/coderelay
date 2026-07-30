from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from coderelay.config import FlySmsSourceSettings
from coderelay.domain.errors import SourceRateLimited, UpstreamSchemaChanged
from coderelay.domain.models import CodeRequest
from coderelay.providers.flysms import FlySmsProvider


@pytest.fixture
def fly_settings(secret_writer) -> FlySmsSourceSettings:
    email = secret_writer("fly-email", "box@example.com")
    token = secret_writer("fly-token", "tok_test_token_123")
    return FlySmsSourceSettings(
        id="fly_test",
        type="flysms",
        display_name="Fly",
        email_file=email,
        token_file=token,
        base_url="https://flysms.example/icloud/api/pickup/messages",
    )


@pytest.mark.asyncio
async def test_flysms_latest_message(fly_settings: FlySmsSourceSettings) -> None:
    received = datetime.now(UTC) - timedelta(seconds=2)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/latest")
        assert request.headers["Authorization"] == "Bearer tok_test_token_123"
        assert request.headers["X-Mailbox-Email"] == "box@example.com"
        return httpx.Response(
            200,
            json={
                "email": "box@example.com",
                "entitlementStatus": "active",
                "message": {
                    "mailbox": "INBOX",
                    "uid": 7,
                    "subject": "Your verification code",
                    "from": "Service <no-reply@service.example>",
                    "to": "box@example.com",
                    "date": received.isoformat(),
                    "text": "Your verification code is 123456",
                    "html": "",
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = FlySmsProvider(fly_settings, client, strict_secret_permissions=True)
        result = await provider.fetch_code(
            CodeRequest(source_id="fly_test", not_before=received - timedelta(seconds=1))
        )
    assert result is not None
    assert result.code == "123456"
    assert result.evidence["message_fingerprint"].startswith("sha256:")
    assert result.evidence["subject"] == "Your verification code"


@pytest.mark.asyncio
async def test_flysms_history_fallback(fly_settings: FlySmsSourceSettings) -> None:
    received = datetime.now(UTC) - timedelta(seconds=2)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/latest"):
            return httpx.Response(404, json={"code": "NO_MESSAGE"})
        return httpx.Response(
            200,
            json={
                "email": "box@example.com",
                "scope": "abcdefghijklmnop",
                "revision": "abcdefghijklmnop",
                "messages": [
                    {
                        "mailbox": "INBOX",
                        "uid": 8,
                        "subject": "Security code 654321",
                        "from": "no-reply@service.example",
                        "to": "box@example.com",
                        "date": received.isoformat(),
                        "preview": "Security code 654321",
                        "hasAttachments": False,
                    }
                ],
                "nextCursor": None,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = FlySmsProvider(fly_settings, client, strict_secret_permissions=True)
        result = await provider.fetch_code(CodeRequest(source_id="fly_test"))
    assert result is not None and result.code == "654321"


@pytest.mark.asyncio
async def test_flysms_honors_retry_after(fly_settings: FlySmsSourceSettings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "17"}, json={"error": "limited"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = FlySmsProvider(fly_settings, client, strict_secret_permissions=True)
        with pytest.raises(SourceRateLimited) as caught:
            await provider.fetch_code(CodeRequest(source_id="fly_test"))
    assert caught.value.retry_after_seconds == 17


@pytest.mark.asyncio
async def test_flysms_rejects_mismatched_mailbox(fly_settings: FlySmsSourceSettings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "email": "other@example.com",
                "entitlementStatus": "active",
                "message": {},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = FlySmsProvider(fly_settings, client, strict_secret_permissions=True)
        with pytest.raises(UpstreamSchemaChanged):
            await provider.fetch_code(CodeRequest(source_id="fly_test"))
