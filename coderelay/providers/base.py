from __future__ import annotations

from abc import ABC, abstractmethod

from coderelay.domain.models import CodeRequest, ProviderCode, SourceStatus


class CodeProvider(ABC):
    id: str
    display_name: str
    provider_type: str
    poll_interval_seconds: float = 2.0
    fetch_timeout_seconds: float = 15.0

    @abstractmethod
    async def fetch_code(self, request: CodeRequest) -> ProviderCode | None:
        raise NotImplementedError

    @abstractmethod
    def status(self) -> SourceStatus:
        raise NotImplementedError

    def close(self) -> None:
        """Release provider-owned resources."""
        return None
