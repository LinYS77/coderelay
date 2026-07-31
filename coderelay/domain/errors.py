from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from coderelay.domain.models import CredentialUpdate


class CodeRelayError(Exception):
    code = "INTERNAL_ERROR"
    status_code = 500
    retryable = False
    public_message = "An internal error occurred"

    def __init__(
        self,
        message: str | None = None,
        *,
        retry_after_seconds: int | None = None,
        credential_update: CredentialUpdate | None = None,
    ) -> None:
        super().__init__(message or self.public_message)
        self.retry_after_seconds = retry_after_seconds
        self.credential_update = credential_update


class AuthenticationRequired(CodeRelayError):
    code = "AUTHENTICATION_REQUIRED"
    status_code = 401
    public_message = "Authentication is required"


class RequestRateLimited(CodeRelayError):
    code = "RATE_LIMITED"
    status_code = 429
    retryable = True
    public_message = "Too many requests"


class InvalidCodeRequest(CodeRelayError):
    code = "INVALID_CODE_REQUEST"
    status_code = 422
    public_message = "The code request is invalid"


class NoFreshCode(CodeRelayError):
    code = "NO_FRESH_CODE"
    status_code = 404
    retryable = True
    public_message = "No matching fresh verification code was found"


class AmbiguousCode(CodeRelayError):
    code = "AMBIGUOUS_CODE"
    status_code = 409
    public_message = "More than one verification code matched equally well"


class SourceCredentialsInvalid(CodeRelayError):
    code = "SOURCE_CREDENTIALS_INVALID"
    status_code = 424
    public_message = "The supplied upstream credentials are invalid"


class SourceReauthRequired(CodeRelayError):
    code = "SOURCE_REAUTH_REQUIRED"
    status_code = 424
    public_message = "The supplied Outlook credential requires reauthorization"


class SourceExpiredOrDisabled(CodeRelayError):
    code = "SOURCE_EXPIRED_OR_DISABLED"
    status_code = 424
    public_message = "The upstream source is expired or disabled"


class SourceRateLimited(CodeRelayError):
    code = "SOURCE_RATE_LIMITED"
    status_code = 429
    retryable = True
    public_message = "The upstream source is rate limited"


class UpstreamSchemaChanged(CodeRelayError):
    code = "UPSTREAM_SCHEMA_CHANGED"
    status_code = 502
    public_message = "The upstream source returned an unsupported response"


class UpstreamFailure(CodeRelayError):
    code = "UPSTREAM_FAILURE"
    status_code = 502
    retryable = True
    public_message = "The upstream source failed"


class SourceSyncing(CodeRelayError):
    code = "SOURCE_SYNCING"
    status_code = 503
    retryable = True
    public_message = "The upstream source is still syncing"


class UpstreamTimeout(CodeRelayError):
    code = "UPSTREAM_TIMEOUT"
    status_code = 504
    retryable = True
    public_message = "The upstream source timed out"
