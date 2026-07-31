from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from coderelay.container import AppContainer
from coderelay.domain.errors import AuthenticationRequired, RequestRateLimited
from coderelay.security import principal_fingerprint, verify_api_token


@dataclass(frozen=True, slots=True)
class Principal:
    identifier: str


def get_container(request: Request) -> AppContainer:
    return request.app.state.container


def client_ip(request: Request) -> str:
    if request.client is None:
        return "unknown"
    return request.client.host[:128]


async def require_auth(request: Request) -> Principal:
    container = get_container(request)
    authorization = request.headers.get("Authorization", "")
    principal: Principal | None = None
    if authorization:
        scheme, separator, token = authorization.partition(" ")
        token = token.strip()
        if separator and scheme.casefold() == "bearer" and verify_api_token(token, container.security.api_token_hashes):
            principal = Principal(identifier=principal_fingerprint(token))
        token = ""

    limit = container.config.security.api_rate_limit_per_minute
    ip = client_ip(request)
    ip_retry = await container.rate_limiter.check(f"api:ip:{ip}", limit=limit)
    if ip_retry:
        raise RequestRateLimited(retry_after_seconds=ip_retry)
    if principal is None:
        raise AuthenticationRequired()

    principal_retry = await container.rate_limiter.check(f"api:principal:{principal.identifier}", limit=limit)
    if principal_retry:
        raise RequestRateLimited(retry_after_seconds=principal_retry)
    return principal
