from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from coderelay import __version__
from coderelay.api import router as api_router
from coderelay.config import AppConfig
from coderelay.container import AppContainer
from coderelay.domain.errors import AuthenticationRequired, CodeRelayError
from coderelay.infra.logging import configure_logging, request_id_var
from coderelay.infra.rate_limit import SlidingWindowRateLimiter
from coderelay.middleware import RequestBodyLimitMiddleware, RequestIdMiddleware, SecurityHeadersMiddleware
from coderelay.security import SecurityContext
from coderelay.services import CodeService, build_code_service

logger = logging.getLogger(__name__)


def create_app(config: AppConfig) -> FastAPI:
    configure_logging(config.server.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        security = SecurityContext.from_settings(config.security)
        service: CodeService | None = None
        try:
            service = build_code_service(config)
            app.state.container = AppContainer(
                config=config,
                security=security,
                code_service=service,
                rate_limiter=SlidingWindowRateLimiter(),
            )
            logger.info("application_started mode=stateless")
            yield
        finally:
            if service is not None:
                service.close()
            logger.info("application_stopped")

    app = FastAPI(
        title="CodeRelay",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.server.allowed_hosts)
    if config.server.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.server.cors_origins,
            allow_credentials=False,
            allow_methods=["POST"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
            max_age=600,
        )
    app.add_middleware(RequestBodyLimitMiddleware, max_bytes=131_072)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIdMiddleware)
    app.include_router(api_router)

    @app.get("/health/live", include_in_schema=False)
    async def health_live() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__}, headers={"Cache-Control": "no-store"})

    @app.get("/health/ready", include_in_schema=False)
    async def health_ready(request: Request) -> JSONResponse:
        container: AppContainer | None = getattr(request.app.state, "container", None)
        if container is None:
            return JSONResponse({"status": "not_ready"}, status_code=503, headers={"Cache-Control": "no-store"})
        return JSONResponse(
            {"status": "ready", "mode": "stateless"},
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(CodeRelayError)
    async def handle_domain_error(request: Request, exc: CodeRelayError) -> JSONResponse:
        logger.warning("request_failed code=%s", exc.code)
        headers: dict[str, str] = {"Cache-Control": "no-store"}
        if exc.retry_after_seconds is not None:
            headers["Retry-After"] = str(exc.retry_after_seconds)
        if isinstance(exc, AuthenticationRequired):
            headers["WWW-Authenticate"] = "Bearer"
        content: dict[str, object] = {
            "error": {
                "code": exc.code,
                "message": exc.public_message,
                "retryable": exc.retryable,
                "retry_after_seconds": exc.retry_after_seconds,
                "request_id": request_id_var.get(),
            }
        }
        if exc.credential_update is not None:
            content["credential_update"] = {"refresh_token": exc.credential_update.refresh_token}
        return JSONResponse(status_code=exc.status_code, headers=headers, content=content)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _simple_error(422, "VALIDATION_ERROR", "The request body or parameters are invalid")

    @app.exception_handler(HTTPException)
    async def handle_http_error(request: Request, exc: HTTPException) -> JSONResponse:
        message = str(exc.detail) if isinstance(exc.detail, str) else "The request could not be processed"
        return _simple_error(exc.status_code, "HTTP_ERROR", message, headers=exc.headers)

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.error("unhandled_exception", exc_info=exc)
        return _simple_error(500, "INTERNAL_ERROR", "An internal error occurred")

    return app


def _simple_error(
    status_code: int,
    code: str,
    message: str,
    *,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        headers={"Cache-Control": "no-store", **(headers or {})},
        content={
            "error": {
                "code": code,
                "message": message,
                "retryable": False,
                "retry_after_seconds": None,
                "request_id": request_id_var.get(),
            }
        },
    )
