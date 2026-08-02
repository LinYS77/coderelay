package outlook

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
)

func TestProviderReturnsRotationWhenIMAPFails(t *testing.T) {
	rotated := testRefreshToken('z')
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`{"access_token":"access","expires_in":3600,"scope":"https://outlook.office.com/imap.accessasuser.all","refresh_token":"` + string(rotated) + `"}`))
	}))
	defer server.Close()
	oauth := newOAuthClientForTest(server.URL, server.Client(), time.Second)
	provider := newProviderForTest(config.OutlookConfig{PollIntervalSeconds: 1, MaxMessages: 1, MaxMessageBytes: 64 << 10}, oauth)
	provider.openOverride = func(context.Context, *Credential, []byte) (*imapSession, error) {
		return nil, domain.ErrUpstreamFailure
	}
	secret := credential.NewOwned([]byte("user@example.com----pw----550e8400-e29b-41d4-a716-446655440000----" + strings.Repeat("r", 120)))
	defer secret.Destroy()
	_, update, err := provider.Resolve(context.Background(), secret, nil, 0)
	if !errors.Is(err, domain.ErrUpstreamFailure) {
		t.Fatalf("Resolve error = %v", err)
	}
	if update == nil || string(update.RefreshToken) != string(rotated) {
		t.Fatalf("rotation update = %q", update.RefreshToken)
	}
	update.Destroy()
}
