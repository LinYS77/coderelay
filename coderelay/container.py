from __future__ import annotations

from dataclasses import dataclass

import httpx

from coderelay.config import AppConfig
from coderelay.infra.rate_limit import SlidingWindowRateLimiter
from coderelay.security import SecurityContext
from coderelay.services import CodeService


@dataclass(slots=True)
class AppContainer:
    config: AppConfig
    security: SecurityContext
    http_client: httpx.AsyncClient
    code_service: CodeService
    rate_limiter: SlidingWindowRateLimiter
