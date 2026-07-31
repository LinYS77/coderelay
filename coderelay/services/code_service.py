from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Callable

import httpx

from coderelay import __version__
from coderelay.config import AppConfig
from coderelay.domain.credentials import CredentialError, parse_flysms_credential, parse_outlook_credential
from coderelay.domain.errors import (
    CodeRelayError,
    InvalidCodeRequest,
    NoFreshCode,
    SourceRateLimited,
    SourceSyncing,
    UpstreamFailure,
    UpstreamTimeout,
)
from coderelay.domain.models import (
    CodeCommand,
    CodeRequest,
    CodeResult,
    FlySmsCodeCommand,
    OutlookCodeCommand,
    ProviderCode,
    TotpCodeCommand,
)
from coderelay.providers import CodeProvider, FlySmsProvider, OutlookImapProvider, TotpProvider

ProviderFactory = Callable[[CodeCommand, httpx.AsyncClient], CodeProvider]
ClientFactory = Callable[[], httpx.AsyncClient]


class CodeService:
    """Resolve one request-scoped credential without retaining upstream state."""

    def __init__(
        self,
        config: AppConfig,
        *,
        provider_factory: ProviderFactory | None = None,
        client_factory: ClientFactory | None = None,
    ) -> None:
        self._config = config
        self._provider_factory = provider_factory or self._build_provider
        self._client_factory = client_factory or self._new_client
        self._concurrency = asyncio.Semaphore(config.server.max_concurrent_code_requests)

    async def resolve(self, command: CodeCommand) -> CodeResult:
        try:
            async with self._concurrency, self._client_factory() as client:
                return await self._resolve_bounded(command, client)
        finally:
            # This drops CodeRelay's command-level reference. Python cannot promise
            # physical memory zeroization, but no reference is retained cross-request.
            command.credential = ""

    async def _resolve_bounded(self, command: CodeCommand, client: httpx.AsyncClient) -> CodeResult:
        try:
            provider = self._provider_factory(command, client)
        except (CredentialError, TypeError, ValueError) as exc:
            raise InvalidCodeRequest() from exc

        try:
            request = self._provider_request(command)
            result = await self._poll(provider, request)
            return CodeResult(code=result.code, credential_update=provider.credential_update)
        except CodeRelayError as exc:
            if exc.credential_update is None:
                exc.credential_update = provider.credential_update
            raise
        finally:
            provider.close()

    def _new_client(self) -> httpx.AsyncClient:
        timeout = httpx.Timeout(
            connect=self._config.server.http_connect_timeout_seconds,
            read=self._config.server.http_read_timeout_seconds,
            write=self._config.server.http_read_timeout_seconds,
            pool=self._config.server.http_connect_timeout_seconds,
        )
        limits = httpx.Limits(
            max_connections=self._config.server.http_max_connections,
            max_keepalive_connections=min(10, self._config.server.http_max_connections),
        )
        return httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": f"CodeRelay/{__version__}"},
        )

    def _build_provider(self, command: CodeCommand, client: httpx.AsyncClient) -> CodeProvider:
        if isinstance(command, TotpCodeCommand):
            return TotpProvider(command.credential)
        if isinstance(command, OutlookCodeCommand):
            credential = parse_outlook_credential(command.credential)
            return OutlookImapProvider(self._config.providers.outlook, client, credential)
        if isinstance(command, FlySmsCodeCommand):
            credential = parse_flysms_credential(command.credential)
            return FlySmsProvider(self._config.providers.flysms, client, credential)
        raise TypeError("unsupported code command")

    @staticmethod
    def _provider_request(command: CodeCommand) -> CodeRequest:
        if isinstance(command, TotpCodeCommand):
            return CodeRequest(min_ttl_seconds=command.min_ttl_seconds)
        return CodeRequest(not_before=command.not_before, wait_seconds=command.wait_seconds)

    async def _poll(self, provider: CodeProvider, request: CodeRequest) -> ProviderCode:
        polling = request.wait_seconds > 0
        deadline = time.monotonic() + float(request.wait_seconds) if polling else 0.0
        attempted = False
        while True:
            if polling and attempted and time.monotonic() >= deadline:
                raise NoFreshCode(retry_after_seconds=max(1, math.ceil(provider.poll_interval_seconds)))
            attempted = True
            try:
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

    @staticmethod
    async def _sleep_for_retry(
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

    def close(self) -> None:
        """No providers or HTTP clients survive a request."""


def build_code_service(config: AppConfig) -> CodeService:
    return CodeService(config)
