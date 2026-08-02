package api

import (
	"context"
	"strings"
	"testing"

	"github.com/LinYS77/coderelay/internal/domain"
)

type outlookUpdateResolver struct {
	updateOnError bool
}

func (r outlookUpdateResolver) Resolve(context.Context, *domain.Command) (domain.Result, error) {
	update := &domain.CredentialUpdate{RefreshToken: []byte(strings.Repeat("n", 120))}
	if r.updateOnError {
		return domain.Result{}, domain.WithCredentialUpdate(domain.ErrNoFreshCode, update.RefreshToken)
	}
	return domain.Result{Code: [6]byte{'1', '2', '3', '4', '5', '6'}, CredentialUpdate: update}, nil
}

func TestOutlookCredentialUpdateIsReturnedOnSuccessAndError(t *testing.T) {
	payload := []byte(`{"type":"outlook","credential":"user@example.com----pw----550e8400-e29b-41d4-a716-446655440000----` + strings.Repeat("r", 120) + `","wait_seconds":0}`)
	for _, test := range []struct {
		name     string
		resolver Resolver
		status   int
		wantCode string
	}{
		{"success", outlookUpdateResolver{}, 200, ""},
		{"error", outlookUpdateResolver{updateOnError: true}, 404, "NO_FRESH_CODE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, token, cancel := newTestHandler(t, test.resolver, nil)
			defer cancel()
			response := perform(handler, "POST", "/api/v1/code", payload, string(token))
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `"credential_update":{"refresh_token":"`+strings.Repeat("n", 120)+`"}`) {
				t.Fatalf("credential update missing: %s", response.Body.String())
			}
			if test.wantCode != "" && errorCode(t, response) != test.wantCode {
				t.Fatalf("error code=%s body=%s", errorCode(t, response), response.Body.String())
			}
		})
	}
}
