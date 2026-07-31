from __future__ import annotations

from dataclasses import dataclass

from coderelay.config import AppConfig
from coderelay.infra.rate_limit import SlidingWindowRateLimiter
from coderelay.security import SecurityContext
from coderelay.services import CodeService


@dataclass(slots=True)
class AppContainer:
    config: AppConfig
    security: SecurityContext
    code_service: CodeService
    rate_limiter: SlidingWindowRateLimiter
