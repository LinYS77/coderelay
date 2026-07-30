from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from coderelay.auth import client_ip, get_container, origin_is_allowed, require_session
from coderelay.domain.errors import AuthenticationRequired, RequestRateLimited
from coderelay.security import verify_ui_password


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1_024)


router = APIRouter(prefix="/auth")


@router.post("/login")
async def login(payload: LoginRequest, request: Request) -> JSONResponse:
    container = get_container(request)
    if not origin_is_allowed(request):
        raise AuthenticationRequired()
    ip_retry = await container.rate_limiter.check(
        f"login:{client_ip(request)}",
        limit=container.config.security.login_rate_limit_per_minute,
    )
    global_retry = await container.rate_limiter.check(
        "login:global",
        limit=container.config.security.login_global_rate_limit_per_minute,
    )
    retry_after = max(ip_retry or 0, global_retry or 0)
    if retry_after:
        raise RequestRateLimited(retry_after_seconds=retry_after)
    valid = await asyncio.to_thread(
        verify_ui_password,
        payload.password,
        container.security.ui_password_hash,
    )
    if not valid:
        raise AuthenticationRequired()
    token = container.security.session_signer.issue()
    response = JSONResponse({"ok": True})
    response.set_cookie(
        key=container.config.security.session_cookie_name,
        value=token,
        max_age=container.config.security.session_hours * 3_600,
        httponly=True,
        secure=container.config.security.cookie_secure,
        samesite="strict",
        path="/",
    )
    return response


@router.post("/logout", dependencies=[Depends(require_session)])
async def logout(request: Request) -> JSONResponse:
    if not origin_is_allowed(request):
        raise AuthenticationRequired()
    container = get_container(request)
    response = JSONResponse({"ok": True})
    response.delete_cookie(
        container.config.security.session_cookie_name,
        path="/",
        secure=container.config.security.cookie_secure,
        httponly=True,
        samesite="strict",
    )
    return response


@router.get("/session", dependencies=[Depends(require_session)])
async def session_status() -> dict[str, bool]:
    return {"authenticated": True}
