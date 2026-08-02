package outlook

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/domain"
)

func TestOAuthErrorCanCarryRotatedRefreshToken(t *testing.T) {
	rotated := testRefreshToken('e')
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"error":"invalid_grant","refresh_token":"` + string(rotated) + `"}`))
	}))
	defer server.Close()
	client := newOAuthClientForTest(server.URL, server.Client(), time.Second)
	credential := oauthCredential(t, 'o')
	defer credential.Destroy()
	_, err := client.Refresh(t.Context(), &credential)
	if !errors.Is(err, domain.ErrSourceReauthRequired) {
		t.Fatalf("error = %v", err)
	}
	update := domain.CredentialUpdateOf(err)
	if update == nil || string(update.RefreshToken) != string(rotated) {
		t.Fatalf("update = %q", update.RefreshToken)
	}
	if strings.Contains(err.Error(), string(rotated)) {
		t.Fatal("rotation appeared in error text")
	}
	update.Destroy()
}
