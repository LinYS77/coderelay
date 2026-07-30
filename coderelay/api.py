from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from coderelay.auth import get_container, require_auth
from coderelay.domain.models import CodeRequest, ProviderCode, SourceStatus


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sender: str | None = None
    subject: str | None = None
    message_fingerprint: str | None = None


class CodeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str
    kind: str
    code: str = Field(pattern=r"^\d{6}$")
    freshness: str
    observed_at: datetime
    received_at: datetime | None
    valid_from: datetime | None
    expires_at: datetime | None
    remaining_seconds: int | None
    evidence: EvidenceResponse

    @classmethod
    def from_domain(cls, result: ProviderCode) -> CodeResponse:
        return cls(
            source_id=result.source_id,
            kind=result.kind.value,
            code=result.code,
            freshness=result.freshness,
            observed_at=result.observed_at,
            received_at=result.received_at,
            valid_from=result.valid_from,
            expires_at=result.expires_at,
            remaining_seconds=result.remaining_seconds,
            evidence=EvidenceResponse.model_validate(result.evidence),
        )


class SourceResponse(BaseModel):
    id: str
    display_name: str
    provider_type: str
    kind: str
    state: str
    experimental: bool
    identity_hint: str | None

    @classmethod
    def from_domain(cls, value: SourceStatus) -> SourceResponse:
        return cls(
            id=value.id,
            display_name=value.display_name,
            provider_type=value.provider_type,
            kind=value.kind.value,
            state=value.state.value,
            experimental=value.experimental,
            identity_hint=value.identity_hint,
        )


router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_auth)])


@router.get("/sources", response_model=list[SourceResponse])
async def list_sources(request: Request) -> list[SourceResponse]:
    statuses = get_container(request).code_service.list_sources()
    return [SourceResponse.from_domain(status) for status in statuses]


@router.get("/codes/{source_id}", response_model=CodeResponse)
async def get_code(
    source_id: str,
    request: Request,
    not_before: Annotated[datetime | None, Query()] = None,
    wait_seconds: Annotated[int, Query(ge=0, le=60)] = 0,
    min_ttl: Annotated[int, Query(ge=0, le=30)] = 5,
) -> CodeResponse:
    container = get_container(request)
    if wait_seconds > container.config.server.max_wait_seconds:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=422,
            detail=f"wait_seconds cannot exceed {container.config.server.max_wait_seconds}",
        )
    if not_before is not None:
        if not_before.tzinfo is None:
            from fastapi import HTTPException

            raise HTTPException(status_code=422, detail="not_before must include a timezone")
        not_before = not_before.astimezone(UTC)
        if not_before > datetime.now(UTC) + timedelta(minutes=5):
            from fastapi import HTTPException

            raise HTTPException(status_code=422, detail="not_before is too far in the future")
    result = await container.code_service.get_code(
        CodeRequest(
            source_id=source_id,
            not_before=not_before,
            wait_seconds=wait_seconds,
            min_ttl_seconds=min_ttl,
        )
    )
    return CodeResponse.from_domain(result)
