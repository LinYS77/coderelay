package domain

import (
	"bytes"
	"errors"
	"testing"
)

func TestCredentialUpdatePreservesCauseAndCopiesToken(t *testing.T) {
	token := []byte("rotated-token")
	err := WithCredentialUpdate(ErrNoFreshCode, token)
	if !errors.Is(err, ErrNoFreshCode) {
		t.Fatal("wrapped cause was not preserved")
	}
	update := CredentialUpdateOf(err)
	if update == nil || !bytes.Equal(update.RefreshToken, token) {
		t.Fatalf("update = %q", update.RefreshToken)
	}
	token[0] = 'x'
	if update.RefreshToken[0] != 'r' {
		t.Fatal("update aliases source token")
	}
	update.Destroy()
	var wrapped *CredentialUpdateError
	if !errors.As(err, &wrapped) {
		t.Fatal("wrapper type was lost")
	}
	wrapped.Destroy()
}

func TestSourceStageSurvivesCredentialUpdateWrapping(t *testing.T) {
	staged := WithSourceStage(ErrSourceCredentials, "outlook_imap_auth")
	wrapped := WithCredentialUpdate(staged, []byte("rotated-token-value"))
	if !errors.Is(wrapped, ErrSourceCredentials) {
		t.Fatal("staged error lost its public cause")
	}
	if stage := SourceStageOf(wrapped); stage != "outlook_imap_auth" {
		t.Fatalf("stage=%q", stage)
	}
	var update *CredentialUpdateError
	if errors.As(wrapped, &update) {
		update.Destroy()
	}
}

func TestRetryAfterErrorPreservesCauseWithoutInput(t *testing.T) {
	err := WithRetryAfter(ErrSourceRateLimited, 999)
	if !errors.Is(err, ErrSourceRateLimited) || RetryAfter(err) != 300 {
		t.Fatalf("error=%v retry=%d", err, RetryAfter(err))
	}
	if err.Error() != ErrSourceRateLimited.Error() {
		t.Fatalf("error text=%q", err.Error())
	}
}
