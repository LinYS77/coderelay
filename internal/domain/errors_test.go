package domain

import (
	"errors"
	"testing"
)

func TestRetryAfterErrorPreservesCauseWithoutInput(t *testing.T) {
	err := WithRetryAfter(ErrSourceRateLimited, 999)
	if !errors.Is(err, ErrSourceRateLimited) || RetryAfter(err) != 300 {
		t.Fatalf("error=%v retry=%d", err, RetryAfter(err))
	}
	if err.Error() != ErrSourceRateLimited.Error() {
		t.Fatalf("error text=%q", err.Error())
	}
}
