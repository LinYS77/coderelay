from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from coderelay.config import MicrosoftGraphSourceSettings
from coderelay.domain.errors import SourceRateLimited
from coderelay.domain.models import CodeRequest, SourceState
from coderelay.providers.microsoft_graph import MicrosoftGraphProvider
from coderelay.security import generate_key_material


@pytest.fixture
def graph_settings(secret_writer, tmp_path) -> MicrosoftGraphSourceSettings:
    client_id = secret_writer("client-id", "11111111-2222-4333-8444-555555555555")
    cache_key = secret_writer("cache-key", generate_key_material())
    return MicrosoftGraphSourceSettings(
        id="graph_test",
        type="microsoft_graph",
        display_name="Graph",
        client_id_file=client_id,
        token_cache_file=tmp_path / "graph-cache.enc",
        token_cache_key_file=cache_key,
        page_size=10,
    )


@pytest.mark.asyncio
async def test_graph_reads_body_preview(graph_settings: MicrosoftGraphSourceSettings) -> None:
    received = datetime.now(UTC) - timedelta(seconds=2)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1.0/me/mailFolders/inbox/messages"
        assert request.headers["Authorization"] == "Bearer access-token"
        assert request.headers["Prefer"] == 'outlook.body-content-type="text"'
        assert request.url.params["$top"] == "10"
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "message-one",
                        "subject": "Your verification code",
                        "from": {"emailAddress": {"name": "Service", "address": "no-reply@example.com"}},
                        "receivedDateTime": received.isoformat().replace("+00:00", "Z"),
                        "bodyPreview": "Use verification code 123456 to continue.",
                        "internetMessageId": "<one@example.com>",
                    }
                ]
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = MicrosoftGraphProvider(graph_settings, client, strict_secret_permissions=True)
        provider._get_access_token = lambda: "access-token"  # type: ignore[method-assign]
        result = await provider.fetch_code(
            CodeRequest(source_id="graph_test", not_before=received - timedelta(seconds=1))
        )
    assert result is not None
    assert result.code == "123456"
    assert result.evidence["sender"] == "no-reply@example.com"


@pytest.mark.asyncio
async def test_graph_fetches_detail_when_preview_has_no_code(graph_settings: MicrosoftGraphSourceSettings) -> None:
    received = datetime.now(UTC) - timedelta(seconds=2)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/inbox/messages"):
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "message-two",
                            "subject": "Login request",
                            "from": {"emailAddress": {"name": "", "address": "login@example.com"}},
                            "receivedDateTime": received.isoformat(),
                            "bodyPreview": "Open this message to continue.",
                        }
                    ]
                },
            )
        assert request.url.path.endswith("/me/messages/message-two")
        return httpx.Response(
            200,
            json={
                "id": "message-two",
                "subject": "Login request",
                "from": {"emailAddress": {"name": "", "address": "login@example.com"}},
                "receivedDateTime": received.isoformat(),
                "bodyPreview": "Open this message to continue.",
                "body": {"contentType": "text", "content": "Your security code is 654321"},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = MicrosoftGraphProvider(graph_settings, client, strict_secret_permissions=True)
        provider._get_access_token = lambda: "access-token"  # type: ignore[method-assign]
        result = await provider.fetch_code(CodeRequest(source_id="graph_test"))
    assert result is not None and result.code == "654321"


@pytest.mark.asyncio
async def test_graph_maps_rate_limit(graph_settings: MicrosoftGraphSourceSettings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "9"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = MicrosoftGraphProvider(graph_settings, client, strict_secret_permissions=True)
        provider._get_access_token = lambda: "access-token"  # type: ignore[method-assign]
        with pytest.raises(SourceRateLimited) as caught:
            await provider.fetch_code(CodeRequest(source_id="graph_test"))
    assert caught.value.retry_after_seconds == 9


@pytest.mark.asyncio
async def test_empty_graph_cache_requires_setup(graph_settings: MicrosoftGraphSourceSettings) -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(500))) as client:
        provider = MicrosoftGraphProvider(graph_settings, client, strict_secret_permissions=True)
        assert provider.status().state == SourceState.REQUIRES_SETUP
