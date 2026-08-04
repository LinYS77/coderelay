package domain

import (
	"bytes"
	"errors"
)

var (
	ErrNoFreshCode           = errors.New("no fresh verification code")
	ErrAmbiguousCode         = errors.New("ambiguous verification code")
	ErrSourceCredentials     = errors.New("upstream credentials are invalid")
	ErrSourceReauthRequired  = errors.New("upstream credential requires reauthorization")
	ErrSourceExpired         = errors.New("upstream source is expired or disabled")
	ErrSourceRateLimited     = errors.New("upstream source is rate limited")
	ErrSourceSyncing         = errors.New("upstream source is syncing")
	ErrUpstreamFailure       = errors.New("upstream source failed")
	ErrUpstreamSchemaChanged = errors.New("upstream response schema changed")
	ErrUpstreamTimeout       = errors.New("upstream operation timed out")
)

type SourceStageError struct {
	Cause error
	Stage string
}

func (e *SourceStageError) Error() string {
	if e == nil || e.Cause == nil {
		return "provider stage failed"
	}
	return e.Cause.Error()
}

func (e *SourceStageError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func WithSourceStage(cause error, stage string) error {
	if cause == nil || stage == "" {
		return cause
	}
	return &SourceStageError{Cause: cause, Stage: stage}
}

func SourceStageOf(err error) string {
	var staged *SourceStageError
	if errors.As(err, &staged) && staged != nil {
		return staged.Stage
	}
	return ""
}

type CredentialUpdate struct {
	RefreshToken []byte
}

func (u *CredentialUpdate) Destroy() {
	if u == nil {
		return
	}
	clear(u.RefreshToken)
	u.RefreshToken = nil
}

type CredentialUpdateError struct {
	Cause  error
	Update *CredentialUpdate
}

func (e *CredentialUpdateError) Error() string {
	if e == nil || e.Cause == nil {
		return "provider error with credential update"
	}
	return e.Cause.Error()
}

func (e *CredentialUpdateError) Destroy() {
	if e == nil || e.Update == nil {
		return
	}
	e.Update.Destroy()
	e.Update = nil
}

func (e *CredentialUpdateError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func WithCredentialUpdate(cause error, refreshToken []byte) error {
	if len(refreshToken) == 0 {
		return cause
	}
	return &CredentialUpdateError{Cause: cause, Update: &CredentialUpdate{RefreshToken: append([]byte(nil), refreshToken...)}}
}

func CredentialUpdateOf(err error) *CredentialUpdate {
	var wrapped *CredentialUpdateError
	if errors.As(err, &wrapped) && wrapped.Update != nil {
		return &CredentialUpdate{RefreshToken: bytes.Clone(wrapped.Update.RefreshToken)}
	}
	return nil
}

type RetryAfterError struct {
	Cause   error
	Seconds int
}

func (e *RetryAfterError) Error() string {
	if e == nil || e.Cause == nil {
		return "upstream retry requested"
	}
	return e.Cause.Error()
}

func (e *RetryAfterError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func WithRetryAfter(cause error, seconds int) error {
	if seconds < 1 {
		seconds = 1
	} else if seconds > 300 {
		seconds = 300
	}
	return &RetryAfterError{Cause: cause, Seconds: seconds}
}

func RetryAfter(err error) int {
	var retry *RetryAfterError
	if errors.As(err, &retry) {
		return retry.Seconds
	}
	return 0
}
