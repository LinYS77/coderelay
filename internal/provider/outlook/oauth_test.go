package outlook

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/domain"
)

func oauthCredential(t *testing.T, token byte) Credential {
	t.Helper()
	value := testRefreshToken(token)
	credential, err := ParseCredential([]byte("user@example.com----password----550e8400-e29b-41d4-a716-446655440000----" + string(value)))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func TestOAuthRefreshUsesExpectedFormAndReturnsRotation(t *testing.T) {
	rotated := testRefreshToken('n')
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/token" {
			t.Errorf("request = %s %s", request.Method, request.URL)
		}
		if got := request.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("content type = %q", got)
		}
		body, _ := io.ReadAll(request.Body)
		text := string(body)
		if !strings.Contains(text, "client_id=550e8400-e29b-41d4-a716-446655440000") || !strings.Contains(text, "grant_type=refresh_token") || !strings.Contains(text, "refresh_token=") {
			t.Errorf("unexpected form %q", text)
		}
		if strings.Contains(text, "password") {
			t.Error("password appeared in OAuth form")
		}
		_, _ = writer.Write([]byte(`{"access_token":"access-value","token_type":"Bearer","expires_in":3600,"scope":"https://outlook.office.com/imap.accessasuser.all","refresh_token":"` + string(rotated) + `"}`))
	}))
	defer server.Close()
	client := newOAuthClientForTest(server.URL+"/token", server.Client(), time.Second)
	credential := oauthCredential(t, 'o')
	defer credential.Destroy()
	result, err := client.Refresh(t.Context(), &credential)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if !result.ScopeVerified {
		t.Fatal("IMAP scope was not verified")
	}
	if string(result.AccessToken) != "access-value" || string(result.RotatedRefreshToken) != string(rotated) {
		t.Fatalf("unexpected OAuth result: access=%q rotation=%q", result.AccessToken, result.RotatedRefreshToken)
	}
	result.Destroy()
}

func TestOAuthRefreshMapsErrorsWithoutEchoingBody(t *testing.T) {
	cases := []struct {
		name string
		code int
		body string
		want error
	}{
		{"reauth", http.StatusBadRequest, `{"error":"invalid_grant","error_description":"secret-body-must-not-escape"}`, domain.ErrSourceReauthRequired},
		{"credentials", http.StatusUnauthorized, `{"error":"bad"}`, domain.ErrSourceCredentials},
		{"rate", http.StatusTooManyRequests, `temporarily unavailable`, domain.ErrSourceRateLimited},
		{"upstream", http.StatusBadGateway, `<html>gateway failure</html>`, domain.ErrUpstreamFailure},
		{"schema", http.StatusOK, `{"access_token":1}`, domain.ErrUpstreamSchemaChanged},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(test.code)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			client := newOAuthClientForTest(server.URL, server.Client(), time.Second)
			credential := oauthCredential(t, 'q')
			defer credential.Destroy()
			_, err := client.Refresh(t.Context(), &credential)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), "secret-body") {
				t.Fatal("error echoed OAuth response body")
			}
		})
	}
}

func TestDecodeOAuthObjectRejectsDuplicateAndTrailing(t *testing.T) {
	for _, body := range []string{`{"access_token":"a","access_token":"b"}`, `{"access_token":"a"}{}`} {
		if _, err := decodeOAuthObject([]byte(body)); err == nil {
			t.Fatalf("decodeOAuthObject accepted %q", body)
		}
	}
}
