from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class SourceKind(StrEnum):
    TOTP = "totp"
    EMAIL = "email"


class SourceState(StrEnum):
    READY = "ready"
    REQUIRES_SETUP = "requires_setup"
    DISABLED = "disabled"
    EXPERIMENTAL = "experimental"


@dataclass(frozen=True, slots=True)
class CodeRequest:
    source_id: str
    not_before: datetime | None = None
    wait_seconds: int = 0
    min_ttl_seconds: int = 5


@dataclass(frozen=True, slots=True)
class MailMessage:
    provider_message_id: str
    subject: str
    sender: str
    received_at: datetime
    preview: str = ""
    text: str = ""
    html: str = ""


@dataclass(frozen=True, slots=True)
class ExtractedCode:
    code: str
    message: MailMessage
    redacted_subject: str
    message_fingerprint: str


@dataclass(frozen=True, slots=True)
class ProviderCode:
    source_id: str
    kind: SourceKind
    code: str
    observed_at: datetime
    received_at: datetime | None = None
    valid_from: datetime | None = None
    expires_at: datetime | None = None
    remaining_seconds: int | None = None
    freshness: str = "fresh"
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SourceStatus:
    id: str
    display_name: str
    provider_type: str
    kind: SourceKind
    state: SourceState
    experimental: bool = False
    identity_hint: str | None = None
