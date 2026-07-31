from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from coderelay.auth import get_container, require_auth
from coderelay.domain.models import FlySmsCodeCommand, OutlookCodeCommand, TotpCodeCommand


class TotpCodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["totp"]
    credential: SecretStr = Field(min_length=1, max_length=8_192)
    min_ttl: int = Field(default=5, ge=0, le=30)


class OutlookCodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["outlook"]
    credential: SecretStr = Field(min_length=1, max_length=70_000)
    not_before: datetime | None = None
    wait_seconds: int = Field(default=20, ge=0, le=60)


class FlySmsCodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["flysms"]
    credential: SecretStr = Field(min_length=1, max_length=4_096)
    not_before: datetime | None = None
    wait_seconds: int = Field(default=20, ge=0, le=60)


CodeRequestBody = Annotated[
    TotpCodeRequest | OutlookCodeRequest | FlySmsCodeRequest,
    Field(discriminator="type"),
]


class CredentialUpdateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=100, max_length=65_536)


class CodeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(pattern=r"^\d{6}$")
    credential_update: CredentialUpdateResponse | None = None


router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_auth)])


@router.post("/code", response_model=CodeResponse, response_model_exclude_none=True)
async def resolve_code(payload: CodeRequestBody, request: Request) -> CodeResponse:
    container = get_container(request)
    credential = payload.credential.get_secret_value()
    try:
        if isinstance(payload, TotpCodeRequest):
            command = TotpCodeCommand(credential=credential, min_ttl_seconds=payload.min_ttl)
        else:
            if payload.wait_seconds > container.config.server.max_wait_seconds:
                raise HTTPException(
                    status_code=422,
                    detail=f"wait_seconds cannot exceed {container.config.server.max_wait_seconds}",
                )
            not_before = _normalize_not_before(payload.not_before)
            if isinstance(payload, OutlookCodeRequest):
                command = OutlookCodeCommand(
                    credential=credential,
                    not_before=not_before,
                    wait_seconds=payload.wait_seconds,
                )
            else:
                command = FlySmsCodeCommand(
                    credential=credential,
                    not_before=not_before,
                    wait_seconds=payload.wait_seconds,
                )
        result = await container.code_service.resolve(command)
        update = (
            CredentialUpdateResponse(refresh_token=result.credential_update.refresh_token)
            if result.credential_update is not None
            else None
        )
        return CodeResponse(code=result.code, credential_update=update)
    finally:
        credential = ""
        payload.credential = SecretStr("")


def _normalize_not_before(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise HTTPException(status_code=422, detail="not_before must include a timezone")
    normalized = value.astimezone(UTC)
    if normalized > datetime.now(UTC) + timedelta(minutes=5):
        raise HTTPException(status_code=422, detail="not_before is too far in the future")
    return normalized
