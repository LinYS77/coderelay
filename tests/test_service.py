from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from coderelay.domain.errors import InvalidCodeRequest, NoFreshCode, SourceSyncing, UpstreamTimeout
from coderelay.domain.models import (
    CodeRequest,
    CredentialUpdate,
    OutlookCodeCommand,
    ProviderCode,
    TotpCodeCommand,
)
from coderelay.providers.base import CodeProvider
from coderelay.services.code_service import CodeService


class FakeProvider(CodeProvider):
    poll_interval_seconds = 0.01

    def __init__(self, values, *, update: CredentialUpdate | None = None) -> None:
        self.values = iter(values)
        self.calls = 0
        self.closed = False
        self._update = update

    async def fetch_code(self, request: CodeRequest) -> ProviderCode | None:
        self.calls += 1
        value = next(self.values)
        if isinstance(value, Exception):
            raise value
        return value

    @property
    def credential_update(self) -> CredentialUpdate | None:
        return self._update

    def close(self) -> None:
        self.closed = True


class SlowNoCodeProvider(FakeProvider):
    fetch_timeout_seconds = 0.1

    def __init__(self) -> None:
        super().__init__([])
        self.completed = False

    async def fetch_code(self, request: CodeRequest) -> ProviderCode | None:
        self.calls += 1
        await asyncio.sleep(0.03)
        self.completed = True
        return None


class HangingProvider(SlowNoCodeProvider):
    fetch_timeout_seconds = 0.01

    async def fetch_code(self, request: CodeRequest) -> ProviderCode | None:
        self.calls += 1
        await asyncio.sleep(1)
        self.completed = True
        return None


def code_result(code: str = "123456") -> ProviderCode:
    return ProviderCode(code=code, observed_at=datetime.now(UTC), received_at=datetime.now(UTC))


def service_with(app_config, provider: CodeProvider) -> CodeService:
    return CodeService(app_config, provider_factory=lambda _command, _client: provider)


@pytest.mark.asyncio
async def test_service_polls_until_code_arrives_and_clears_command(app_config) -> None:
    provider = FakeProvider([None, code_result()])
    command = OutlookCodeCommand(credential="request-secret", wait_seconds=1)
    returned = await service_with(app_config, provider).resolve(command)
    assert returned.code == "123456"
    assert provider.calls == 2
    assert provider.closed is True
    assert command.credential == ""


@pytest.mark.asyncio
async def test_service_retries_temporary_sync_state(app_config) -> None:
    provider = FakeProvider([SourceSyncing(retry_after_seconds=0), code_result("654321")])
    command = OutlookCodeCommand(credential="request-secret", wait_seconds=1)
    returned = await service_with(app_config, provider).resolve(command)
    assert returned.code == "654321"
    assert provider.calls == 2


@pytest.mark.asyncio
async def test_service_returns_request_scoped_credential_update(app_config) -> None:
    update = CredentialUpdate(refresh_token="M." + "b" * 240)
    provider = FakeProvider([code_result()], update=update)
    command = TotpCodeCommand(credential="request-secret", min_ttl_seconds=0)
    returned = await service_with(app_config, provider).resolve(command)
    assert returned.credential_update == update
    assert provider.closed is True
    assert command.credential == ""


@pytest.mark.asyncio
async def test_no_fresh_error_carries_rotation_without_persisting(app_config) -> None:
    update = CredentialUpdate(refresh_token="M." + "c" * 240)
    provider = FakeProvider([None], update=update)
    command = OutlookCodeCommand(credential="request-secret", wait_seconds=0)
    with pytest.raises(NoFreshCode) as caught:
        await service_with(app_config, provider).resolve(command)
    assert caught.value.credential_update == update
    assert provider.closed is True
    assert command.credential == ""


@pytest.mark.asyncio
async def test_short_wait_does_not_cancel_first_upstream_fetch(app_config) -> None:
    provider = SlowNoCodeProvider()
    command = OutlookCodeCommand(credential="request-secret", wait_seconds=0.01)
    with pytest.raises(NoFreshCode):
        await service_with(app_config, provider).resolve(command)
    assert provider.completed is True
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_provider_timeout_still_bounds_a_hung_fetch(app_config) -> None:
    provider = HangingProvider()
    command = TotpCodeCommand(credential="request-secret")
    with pytest.raises(UpstreamTimeout):
        await service_with(app_config, provider).resolve(command)
    assert provider.completed is False
    assert provider.calls == 1
    assert command.credential == ""


@pytest.mark.asyncio
async def test_invalid_request_credential_is_cleared(app_config) -> None:
    command = TotpCodeCommand(credential="invalid base32 secret")
    service = CodeService(app_config)
    with pytest.raises(InvalidCodeRequest):
        await service.resolve(command)
    assert command.credential == ""


@pytest.mark.asyncio
async def test_http_client_is_new_and_closed_for_each_request(app_config) -> None:
    clients = []

    class FakeClient:
        async def __aenter__(self):
            clients.append(self)
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            self.closed = True

    provider = FakeProvider([code_result(), code_result()])
    service = CodeService(
        app_config,
        provider_factory=lambda _command, _client: provider,
        client_factory=FakeClient,
    )
    await service.resolve(TotpCodeCommand(credential="first"))
    await service.resolve(TotpCodeCommand(credential="second"))
    assert len(clients) == 2
    assert clients[0] is not clients[1]
    assert all(client.closed for client in clients)
