from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class TotpCodeCommand:
    credential: str
    min_ttl_seconds: int = 5


@dataclass(slots=True)
class OutlookCodeCommand:
    credential: str
    not_before: datetime | None = None
    wait_seconds: int = 20


@dataclass(slots=True)
class FlySmsCodeCommand:
    credential: str
    not_before: datetime | None = None
    wait_seconds: int = 20


CodeCommand = TotpCodeCommand | OutlookCodeCommand | FlySmsCodeCommand


@dataclass(frozen=True, slots=True)
class CodeRequest:
    not_before: datetime | None = None
    wait_seconds: int = 0
    min_ttl_seconds: int = 5


@dataclass(frozen=True, slots=True)
class CredentialUpdate:
    refresh_token: str


@dataclass(frozen=True, slots=True)
class CodeResult:
    code: str
    credential_update: CredentialUpdate | None = None


@dataclass(frozen=True, slots=True)
class MailMessage:
    provider_message_id: str
    subject: str
    sender: str
    received_at: datetime
    preview: str = ""
    text: str = ""
    html: str = ""
    provider_sequence: int = 0


@dataclass(frozen=True, slots=True)
class ExtractedCode:
    code: str
    message: MailMessage
    redacted_subject: str
    message_fingerprint: str


@dataclass(frozen=True, slots=True)
class ProviderCode:
    code: str
    observed_at: datetime
    received_at: datetime | None = None
    valid_from: datetime | None = None
    expires_at: datetime | None = None
    remaining_seconds: int | None = None
