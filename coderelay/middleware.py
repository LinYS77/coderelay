from __future__ import annotations

import re
import secrets
from collections.abc import Awaitable, Callable
from typing import Any

from coderelay.infra.logging import request_id_var

_RequestIdPattern = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
ASGIApp = Callable[
    [dict[str, Any], Callable[..., Awaitable[dict[str, Any]]], Callable[..., Awaitable[None]]], Awaitable[None]
]


def _set_header(headers: list[tuple[bytes, bytes]], name: bytes, value: bytes) -> None:
    headers[:] = [(key, current) for key, current in headers if key.lower() != name]
    headers.append((name, value))


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int = 65_536) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                length = int(raw_length)
            except ValueError:
                length = self.max_bytes + 1
            if length < 0 or length > self.max_bytes:
                await self._reject(send)
                return

        if scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            total += len(body)
            if total > self.max_bytes:
                await self._reject(send)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(send: Callable[..., Any]) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"cache-control", b"no-store")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": (
                    b'{"error":{"code":"REQUEST_TOO_LARGE","message":"Request body is too large","retryable":false}}'
                ),
            }
        )


class RequestIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        supplied = headers.get(b"x-request-id", b"").decode("ascii", "ignore")
        request_id = supplied if _RequestIdPattern.fullmatch(supplied) else secrets.token_hex(12)
        token = request_id_var.set(request_id)

        async def send_with_id(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                response_headers = list(message.get("headers", []))
                _set_header(response_headers, b"x-request-id", request_id.encode("ascii"))
                message["headers"] = response_headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            request_id_var.reset(token)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        scheme = scope.get("scheme", "http")

        async def send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                security_headers = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=(), payment=()",
                    b"content-security-policy": (
                        b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                        b"connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
                        b"form-action 'self'; frame-ancestors 'none'"
                    ),
                }
                for name, value in security_headers.items():
                    _set_header(headers, name, value)
                if path.startswith(("/api/", "/auth/", "/app", "/login")):
                    _set_header(headers, b"cache-control", b"no-store, private")
                    _set_header(headers, b"pragma", b"no-cache")
                if scheme == "https":
                    _set_header(headers, b"strict-transport-security", b"max-age=31536000; includeSubDomains")
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)
