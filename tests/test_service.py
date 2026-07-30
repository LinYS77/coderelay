from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from coderelay.domain.errors import NoFreshCode, SourceNotFound, SourceSyncing
from coderelay.domain.models import CodeRequest, ProviderCode, SourceKind, SourceState, SourceStatus
from coderelay.providers.base import CodeProvider
from coderelay.services.code_service import CodeService


class FakeProvider(CodeProvider):
    id = "test_totp"
    display_name = "Fake"
    provider_type = "fake"
    poll_interval_seconds = 0.01

    def __init__(self, values):
        self.values = iter(values)
        self.calls = 0

    async def fetch_code(self, request: CodeRequest) -> ProviderCode | None:
        self.calls += 1
        value = next(self.values)
        if isinstance(value, Exception):
            raise value
        return value

    def status(self) -> SourceStatus:
        return SourceStatus(
            id=self.id,
            display_name=self.display_name,
            provider_type=self.provider_type,
            kind=SourceKind.EMAIL,
            state=SourceState.READY,
        )


def email_result(code: str = "123456") -> ProviderCode:
    now = datetime.now(UTC)
    return ProviderCode(
        source_id="test_totp",
        kind=SourceKind.EMAIL,
        code=code,
        observed_at=now,
        received_at=now,
    )


@pytest.mark.asyncio
async def test_service_polls_until_code_arrives(app_config) -> None:
    result = email_result()
    provider = FakeProvider([None, result])
    service = CodeService(app_config, {provider.id: provider})
    returned = await service.get_code(CodeRequest(source_id=provider.id, wait_seconds=1))
    assert returned == result
    assert provider.calls == 2


@pytest.mark.asyncio
async def test_service_retries_temporary_sync_state(app_config) -> None:
    result = email_result("654321")
    provider = FakeProvider([SourceSyncing(retry_after_seconds=0), result])
    service = CodeService(app_config, {provider.id: provider})
    returned = await service.get_code(CodeRequest(source_id=provider.id, wait_seconds=1))
    assert returned.code == "654321"
    assert provider.calls == 2


@pytest.mark.asyncio
async def test_service_short_cache_respects_not_before(app_config) -> None:
    result = email_result()
    provider = FakeProvider([result])
    service = CodeService(app_config, {provider.id: provider})
    first = await service.get_code(CodeRequest(source_id=provider.id))
    second = await service.get_code(
        CodeRequest(source_id=provider.id, not_before=result.received_at - timedelta(seconds=1))
    )
    assert first == second
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_service_no_code_without_wait(app_config) -> None:
    provider = FakeProvider([None])
    service = CodeService(app_config, {provider.id: provider})
    with pytest.raises(NoFreshCode):
        await service.get_code(CodeRequest(source_id=provider.id))


@pytest.mark.asyncio
async def test_service_unknown_source(app_config) -> None:
    service = CodeService(app_config, {})
    with pytest.raises(SourceNotFound):
        await service.get_code(CodeRequest(source_id="unknown"))
