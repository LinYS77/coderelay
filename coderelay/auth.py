from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from fastapi import Request

from coderelay.container import AppContainer
from coderelay.domain.errors import AuthenticationRequired, RequestRateLimited
from coderelay.security import SessionClaims, principal_fingerprint, verify_api_token


@dataclass(frozen=True, slots=True)
class Principal:
    kind: str
    identifier: str
    session: SessionClaims | None = None


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
        if (
            separator
            and scheme.casefold() == "bearer"
            and verify_api_token(token.strip(), container.security.api_token_hashes)
        ):
            principal = Principal(kind="api", identifier=principal_fingerprint(token.strip()))
    else:
        cookie = request.cookies.get(container.config.security.session_cookie_name, "")
        claims = container.security.session_signer.verify(cookie)
        if claims is not None:
            principal = Principal(kind="session", identifier=claims.nonce, session=claims)
    if principal is None:
        raise AuthenticationRequired()

    limit = container.config.security.api_rate_limit_per_minute
    ip = client_ip(request)
    principal_retry = await container.rate_limiter.check(f"api:principal:{principal.identifier}", limit=limit)
    ip_retry = await container.rate_limiter.check(f"api:ip:{ip}", limit=limit)
    retry_after = max(principal_retry or 0, ip_retry or 0)
    if retry_after:
        raise RequestRateLimited(retry_after_seconds=retry_after)
    return principal


async def require_session(request: Request) -> Principal:
    container = get_container(request)
    cookie = request.cookies.get(container.config.security.session_cookie_name, "")
    claims = container.security.session_signer.verify(cookie)
    if claims is None:
        raise AuthenticationRequired()
    return Principal(kind="session", identifier=claims.nonce, session=claims)


def origin_is_allowed(request: Request) -> bool:
    origin = request.headers.get("Origin")
    if not origin:
        return True
    try:
        parsed = urlparse(origin)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    request_origin = f"{request.url.scheme}://{request.url.netloc}".rstrip("/")
    return origin.rstrip("/") == request_origin
