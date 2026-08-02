package api

import "fmt"

type publicError struct {
	Status     int
	Code       string
	Message    string
	Retryable  bool
	RetryAfter int
}

func (e *publicError) Error() string {
	return fmt.Sprintf("%s (%d)", e.Code, e.Status)
}

func authenticationRequired() *publicError {
	return &publicError{Status: 401, Code: "AUTHENTICATION_REQUIRED", Message: "A valid Bearer token is required"}
}

func rateLimited(retry int) *publicError {
	return &publicError{Status: 429, Code: "RATE_LIMITED", Message: "Too many requests", Retryable: true, RetryAfter: retry}
}

func serverBusy(retry int) *publicError {
	if retry < 1 {
		retry = 1
	}
	return &publicError{Status: 503, Code: "SERVER_BUSY", Message: "The server is at capacity", Retryable: true, RetryAfter: retry}
}

func validationError() *publicError {
	return &publicError{Status: 422, Code: "VALIDATION_ERROR", Message: "The request body or parameters are invalid"}
}

func invalidCodeRequest() *publicError {
	return &publicError{Status: 422, Code: "INVALID_CODE_REQUEST", Message: "The verification-code request is invalid"}
}

func requestTooLarge() *publicError {
	return &publicError{Status: 413, Code: "REQUEST_TOO_LARGE", Message: "Request body is too large"}
}

func unsupportedMediaType() *publicError {
	return &publicError{Status: 415, Code: "UNSUPPORTED_MEDIA_TYPE", Message: "Content-Type must be application/json"}
}

func methodNotAllowed() *publicError {
	return &publicError{Status: 405, Code: "HTTP_ERROR", Message: "The HTTP method is not allowed"}
}

func notFound() *publicError {
	return &publicError{Status: 404, Code: "HTTP_ERROR", Message: "The requested resource was not found"}
}

func invalidHost() *publicError {
	return &publicError{Status: 400, Code: "HTTP_ERROR", Message: "The request Host is not allowed"}
}

func noFreshCode(retry int) *publicError {
	return &publicError{Status: 404, Code: "NO_FRESH_CODE", Message: "No matching fresh verification code was found", Retryable: true, RetryAfter: retry}
}

func ambiguousCode() *publicError {
	return &publicError{Status: 409, Code: "AMBIGUOUS_CODE", Message: "More than one verification code matched equally well"}
}

func sourceCredentialsInvalid() *publicError {
	return &publicError{Status: 424, Code: "SOURCE_CREDENTIALS_INVALID", Message: "The supplied upstream credentials are invalid"}
}

func sourceReauthRequired() *publicError {
	return &publicError{Status: 424, Code: "SOURCE_REAUTH_REQUIRED", Message: "The supplied Outlook credential requires reauthorization"}
}

func sourceExpired() *publicError {
	return &publicError{Status: 424, Code: "SOURCE_EXPIRED_OR_DISABLED", Message: "The upstream source is expired or disabled"}
}

func sourceRateLimited(retry int) *publicError {
	return &publicError{Status: 429, Code: "SOURCE_RATE_LIMITED", Message: "The upstream source is rate limited", Retryable: true, RetryAfter: retry}
}

func upstreamSchemaChanged() *publicError {
	return &publicError{Status: 502, Code: "UPSTREAM_SCHEMA_CHANGED", Message: "The upstream source returned an unsupported response"}
}

func upstreamFailure() *publicError {
	return &publicError{Status: 502, Code: "UPSTREAM_FAILURE", Message: "The upstream source failed", Retryable: true}
}

func sourceSyncing(retry int) *publicError {
	return &publicError{Status: 503, Code: "SOURCE_SYNCING", Message: "The upstream source is still syncing", Retryable: true, RetryAfter: retry}
}

func upstreamTimeout() *publicError {
	return &publicError{Status: 504, Code: "UPSTREAM_TIMEOUT", Message: "The verification-code operation timed out", Retryable: true}
}

func internalError() *publicError {
	return &publicError{Status: 500, Code: "INTERNAL_ERROR", Message: "An internal error occurred"}
}
