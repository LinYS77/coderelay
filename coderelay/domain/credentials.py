from __future__ import annotations

import hmac
import re
import uuid
from dataclasses import dataclass, replace
from urllib.parse import parse_qsl, urlsplit

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_FLYSMS_TOKEN_RE = re.compile(r"^tok_[A-Za-z0-9_-]{16,512}$")
_FLYSMS_URL_PREFIX = "https://flysms.xyz/icloud/pickup#"
_FLYSMS_SEPARATOR = f"---{_FLYSMS_URL_PREFIX}"


class CredentialError(ValueError):
    """Raised when a request-scoped upstream credential is malformed."""


@dataclass(frozen=True, slots=True)
class OutlookCredential:
    email: str
    client_id: str
    refresh_token: str

    def with_refresh_token(self, refresh_token: str) -> OutlookCredential:
        return replace(self, refresh_token=_validate_refresh_token(refresh_token))


@dataclass(frozen=True, slots=True)
class FlySmsCredential:
    email: str
    token: str


def parse_outlook_credential(value: str) -> OutlookCredential:
    parts = value.rstrip("\r\n").split("----", 3)
    if len(parts) != 4:
        raise CredentialError("Outlook credential must use email----password----client_id----refresh_token format")
    email, password, client_id, refresh_token = (part.strip() for part in parts)
    if not password:
        raise CredentialError("Outlook credential password field is empty")
    credential = OutlookCredential(
        email=_validate_email(email),
        client_id=_validate_client_id(client_id),
        refresh_token=_validate_refresh_token(refresh_token),
    )
    # The compatibility-only password is deliberately absent from the returned model.
    password = ""
    parts.clear()
    return credential


def parse_flysms_credential(value: str) -> FlySmsCredential:
    raw = value.rstrip("\r\n")
    email, separator, remainder = raw.partition("---")
    if not separator:
        raise CredentialError("FlySMS credential must use email---token---pickup_url format")
    token, url_separator, url_suffix = remainder.partition(_FLYSMS_SEPARATOR)
    if not url_separator:
        raise CredentialError("FlySMS credential must include the canonical HTTPS pickup URL")

    normalized_email = _validate_email(email)
    normalized_token = token.strip()
    if not _FLYSMS_TOKEN_RE.fullmatch(normalized_token):
        raise CredentialError("FlySMS token has an invalid shape")

    pickup_url = _FLYSMS_URL_PREFIX + url_suffix
    try:
        parsed = urlsplit(pickup_url)
        port = parsed.port
    except ValueError as exc:
        raise CredentialError("FlySMS pickup URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "flysms.xyz"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/icloud/pickup"
        or parsed.query
    ):
        raise CredentialError("FlySMS pickup URL must target the canonical FlySMS pickup page")
    try:
        pairs = parse_qsl(parsed.fragment, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise CredentialError("FlySMS pickup URL fragment is invalid") from exc
    if len(pairs) != 2 or {key for key, _ in pairs} != {"email", "key"}:
        raise CredentialError("FlySMS pickup URL fragment must contain exactly email and key")
    fragment = dict(pairs)
    fragment_email = _validate_email(fragment.get("email", ""))
    fragment_token = fragment.get("key", "")
    if fragment_email != normalized_email or not hmac.compare_digest(fragment_token, normalized_token):
        raise CredentialError("FlySMS credential components do not match")
    return FlySmsCredential(email=normalized_email, token=normalized_token)


def _validate_email(value: object) -> str:
    if not isinstance(value, str):
        raise CredentialError("credential email must be a string")
    normalized = value.strip().casefold()
    if len(normalized) > 320 or not _EMAIL_RE.fullmatch(normalized):
        raise CredentialError("credential email is invalid")
    return normalized


def _validate_client_id(value: object) -> str:
    if not isinstance(value, str):
        raise CredentialError("Outlook client_id must be a string")
    try:
        return str(uuid.UUID(value.strip()))
    except ValueError as exc:
        raise CredentialError("Outlook client_id is invalid") from exc


def _validate_refresh_token(value: object) -> str:
    if not isinstance(value, str):
        raise CredentialError("Outlook refresh token must be a string")
    normalized = value.strip()
    if not 100 <= len(normalized) <= 65_536 or any(character.isspace() for character in normalized):
        raise CredentialError("Outlook refresh token has an invalid shape")
    return normalized
