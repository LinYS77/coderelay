package outlook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
)

func TestProviderRefreshesOnceAfterIMAPAuthFailure(t *testing.T) {
	var oauthCalls atomic.Int32
	oauthServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call := oauthCalls.Add(1)
		access := "access1"
		if call == 2 {
			access = "access2"
		}
		_, _ = writer.Write([]byte(`{"access_token":"` + access + `","expires_in":3600,"scope":"https://outlook.office.com/imap.accessasuser.all"}`))
	}))
	defer oauthServer.Close()
	oauth := newOAuthClientForTest(oauthServer.URL, oauthServer.Client(), time.Second)
	provider := newProviderForTest(config.OutlookConfig{PollIntervalSeconds: 1, MaxMessages: 1, MaxMessageBytes: 64 << 10}, oauth)
	var opens atomic.Int32
	var done <-chan error
	provider.openOverride = func(ctx context.Context, parsed *Credential, access []byte) (*imapSession, error) {
		if opens.Add(1) == 1 {
			if string(access) != "access1" {
				t.Errorf("first access = %q", access)
			}
			return nil, imapAuthError{}
		}
		if string(access) != "access2" {
			t.Errorf("refreshed access = %q", access)
		}
		session, serverDone, err := newPreselectedSession(ctx, parsed.Email, access, [][]byte{[]byte("From: Service <service@example.com>\r\nSubject: Verification\r\nContent-Type: text/plain\r\n\r\nCode 765432\r\n")})
		done = serverDone
		return session, err
	}
	secret := credential.NewOwned([]byte("user@example.com----pw----550e8400-e29b-41d4-a716-446655440000----" + strings.Repeat("r", 120)))
	defer secret.Destroy()
	code, _, err := provider.Resolve(context.Background(), domain.OutlookRequest{Credential: secret, MailAccess: domain.OutlookMailAccessIMAP})
	if err != nil || string(code[:]) != "765432" {
		t.Fatalf("Resolve = %q, %v", code, err)
	}
	if oauthCalls.Load() != 2 || opens.Load() != 2 {
		t.Fatalf("oauth calls=%d opens=%d", oauthCalls.Load(), opens.Load())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
