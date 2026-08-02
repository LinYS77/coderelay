package probe

import (
	"errors"
	"fmt"
)

// StageError keeps the underlying error for errors.Is while exposing only a
// fixed stage and code to callers. Upstream response bodies and credentials
// must never be embedded in Error().
type StageError struct {
	Stage string
	Code  string
	cause error
}

func (e *StageError) Error() string {
	return fmt.Sprintf("phase0 stage %s failed (%s)", e.Stage, e.Code)
}

func (e *StageError) Unwrap() error {
	return e.cause
}

func stageError(stage, code string, cause error) error {
	if cause == nil {
		cause = errors.New("unspecified failure")
	}
	return &StageError{Stage: stage, Code: code, cause: cause}
}

func safeErrorFields(err error) (stage, code string) {
	var target *StageError
	if errors.As(err, &target) {
		return target.Stage, target.Code
	}
	return "internal", "UNCLASSIFIED"
}

// SafeErrorFields returns fixed, non-sensitive fields suitable for terminal
// output. It intentionally does not return the wrapped cause.
func SafeErrorFields(err error) (stage, code string) {
	return safeErrorFields(err)
}
