package domain

import "errors"

var (
	ErrNoFreshCode           = errors.New("no fresh verification code")
	ErrAmbiguousCode         = errors.New("ambiguous verification code")
	ErrSourceCredentials     = errors.New("upstream credentials are invalid")
	ErrSourceExpired         = errors.New("upstream source is expired or disabled")
	ErrSourceRateLimited     = errors.New("upstream source is rate limited")
	ErrSourceSyncing         = errors.New("upstream source is syncing")
	ErrUpstreamFailure       = errors.New("upstream source failed")
	ErrUpstreamSchemaChanged = errors.New("upstream response schema changed")
	ErrUpstreamTimeout       = errors.New("upstream operation timed out")
)

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
