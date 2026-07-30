from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass
from datetime import UTC

import httpx

from coderelay.config import (
    AppConfig,
    FlySmsSourceSettings,
    OutlookImapSourceSettings,
    TotpSourceSettings,
)
from coderelay.domain.errors import (
    NoFreshCode,
    SourceDisabled,
    SourceNotFound,
    SourceRateLimited,
    SourceSyncing,
    UpstreamFailure,
    UpstreamTimeout,
)
from coderelay.domain.models import CodeRequest, ProviderCode, SourceKind, SourceState, SourceStatus
from coderelay.providers import FlySmsProvider, OutlookImapProvider, TotpProvider
from coderelay.providers.base import CodeProvider


@dataclass(slots=True)
class _CachedResult:
    result: ProviderCode
    stored_at: float


class CodeService:
    def __init__(self, config: AppConfig, providers: dict[str, CodeProvider]) -> None:
        self._config = config
        self._providers = providers
        self._locks = {source.id: asyncio.Lock() for source in config.sources}
        self._cache: dict[str, _CachedResult] = {}

    async def get_code(self, request: CodeRequest) -> ProviderCode:
        source_settings = next((source for source in self._config.sources if source.id == request.source_id), None)
        if source_settings is None:
            raise SourceNotFound()
        if not source_settings.enabled:
            raise SourceDisabled()
        provider = self._providers.get(request.source_id)
        if provider is None:
            raise SourceNotFound()

        cached = self._usable_cached(request)
        if cached is not None:
            return cached

        async with self._locks[request.source_id]:
            cached = self._usable_cached(request)
            if cached is not None:
                return cached
            result = await self._poll(provider, request)
            if result.kind == SourceKind.EMAIL:
                self._cache[request.source_id] = _CachedResult(result=result, stored_at=time.monotonic())
            return result

    def list_sources(self) -> list[SourceStatus]:
        result: list[SourceStatus] = []
        for source in self._config.sources:
            if not source.enabled:
                result.append(
                    SourceStatus(
                        id=source.id,
                        display_name=source.display_name,
                        provider_type=source.type,
                        kind=SourceKind.TOTP if source.type == "totp" else SourceKind.EMAIL,
                        state=SourceState.DISABLED,
                        experimental=source.type == "flysms",
                    )
                )
                continue
            provider = self._providers[source.id]
            result.append(provider.status())
        return result

    def close(self) -> None:
        for provider in self._providers.values():
            provider.close()

    async def _poll(self, provider: CodeProvider, request: CodeRequest) -> ProviderCode:
        polling = request.wait_seconds > 0
        deadline = time.monotonic() + float(request.wait_seconds) if polling else 0.0
        attempted = False
        while True:
            if polling and attempted and time.monotonic() >= deadline:
                raise NoFreshCode(retry_after_seconds=max(1, math.ceil(provider.poll_interval_seconds)))
            attempted = True
            try:
                # A short long-poll window must not cancel a healthy first upstream read.
                # The deadline decides whether another attempt may start; every started
                # attempt receives the provider's own bounded I/O budget.
                async with asyncio.timeout(provider.fetch_timeout_seconds):
                    result = await provider.fetch_code(request)
                if result is not None:
                    return result
            except TimeoutError as timeout:
                error = UpstreamTimeout()
                if polling and await self._sleep_for_retry(None, deadline, provider.poll_interval_seconds):
                    continue
                raise error from timeout
            except SourceRateLimited as exc:
                if polling and await self._sleep_for_retry(exc.retry_after_seconds, deadline):
                    continue
                raise
            except (SourceSyncing, UpstreamFailure, UpstreamTimeout) as exc:
                if polling and await self._sleep_for_retry(
                    exc.retry_after_seconds,
                    deadline,
                    provider.poll_interval_seconds,
                ):
                    continue
                raise

            if not polling:
                raise NoFreshCode(retry_after_seconds=max(1, math.ceil(provider.poll_interval_seconds)))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NoFreshCode(retry_after_seconds=max(1, math.ceil(provider.poll_interval_seconds)))
            await asyncio.sleep(min(provider.poll_interval_seconds, remaining))

    async def _sleep_for_retry(
        self,
        retry_after: int | None,
        deadline: float,
        fallback: float = 1.0,
    ) -> bool:
        delay = float(retry_after if retry_after is not None else fallback)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or delay > remaining:
            return False
        await asyncio.sleep(max(0.05, delay))
        return True

    def _usable_cached(self, request: CodeRequest) -> ProviderCode | None:
        cached = self._cache.get(request.source_id)
        if cached is None or time.monotonic() - cached.stored_at > 2.0:
            return None
        result = cached.result
        if result.received_at is None:
            return None
        if request.not_before is not None:
            boundary = request.not_before
            if boundary.tzinfo is None:
                boundary = boundary.replace(tzinfo=UTC)
            if result.received_at < boundary.astimezone(UTC):
                return None
        return result


def build_code_service(config: AppConfig, client: httpx.AsyncClient) -> CodeService:
    providers: dict[str, CodeProvider] = {}
    strict = config.security.strict_secret_permissions
    for settings in config.sources:
        if not settings.enabled:
            continue
        if isinstance(settings, TotpSourceSettings):
            provider: CodeProvider = TotpProvider(settings, strict_secret_permissions=strict)
        elif isinstance(settings, OutlookImapSourceSettings):
            provider = OutlookImapProvider(settings, client, strict_secret_permissions=strict)
        elif isinstance(settings, FlySmsSourceSettings):
            provider = FlySmsProvider(settings, client, strict_secret_permissions=strict)
        else:  # pragma: no cover - guarded by the discriminated config model
            raise TypeError(f"unsupported source settings: {type(settings)!r}")
        providers[settings.id] = provider
    return CodeService(config, providers)
