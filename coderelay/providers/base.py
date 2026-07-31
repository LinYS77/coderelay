from __future__ import annotations

from abc import ABC, abstractmethod

from coderelay.domain.models import CodeRequest, CredentialUpdate, ProviderCode


class CodeProvider(ABC):
    poll_interval_seconds: float = 2.0
    fetch_timeout_seconds: float = 15.0

    @abstractmethod
    async def fetch_code(self, request: CodeRequest) -> ProviderCode | None:
        raise NotImplementedError

    @property
    def credential_update(self) -> CredentialUpdate | None:
        return None

    def close(self) -> None:
        """Release request-scoped resources and drop credential references."""
        return None
