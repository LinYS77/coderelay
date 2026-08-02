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
)

func TestProviderCloseCancelsActiveOAuthRequest(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(entered)
		select {
		case <-request.Context().Done():
		case <-release:
		}
	}))
	defer func() {
		close(release)
		server.Close()
	}()
	oauth := newOAuthClientForTest(server.URL, server.Client(), 10*time.Second)
	provider := newProviderForTest(config.OutlookConfig{PollIntervalSeconds: 1, MaxMessages: 1, MaxMessageBytes: 64 << 10}, oauth)
	secret := credential.NewOwned([]byte("user@example.com----pw----550e8400-e29b-41d4-a716-446655440000----" + strings.Repeat("r", 120)))
	defer secret.Destroy()
	result := make(chan error, 1)
	go func() {
		_, _, err := provider.Resolve(context.Background(), secret, nil, 0)
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("OAuth request did not start")
	}
	provider.Close()
	provider.Close()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Resolve error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Resolve did not stop after Provider.Close")
	}
}
