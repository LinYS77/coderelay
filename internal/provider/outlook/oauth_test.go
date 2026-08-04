package outlook

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("OAuth form parse: %v", err)
		}
		if values.Get("client_id") != "550e8400-e29b-41d4-a716-446655440000" || values.Get("grant_type") != "refresh_token" || values.Get("refresh_token") == "" {
			t.Errorf("unexpected OAuth form keys")
		}
		if values.Get("scope") != imapScope {
			t.Errorf("scope = %q, want %q", values.Get("scope"), imapScope)
		}
		if strings.Contains(string(body), "password") {
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

func TestOAuthRefreshRoundTripsOpaqueRefreshTokenCharacters(t *testing.T) {
	opaque := "M." + strings.Repeat("A!*$_-", 24)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if request.Form.Get("refresh_token") != opaque {
			t.Error("opaque refresh token changed during form encoding")
		}
		_, _ = writer.Write([]byte(`{"access_token":"access-value","expires_in":3600,"scope":"https://outlook.office.com/IMAP.AccessAsUser.All"}`))
	}))
	defer server.Close()
	client := newOAuthClientForTest(server.URL, server.Client(), time.Second)
	credential, err := ParseCredential([]byte("user@example.com----password----550e8400-e29b-41d4-a716-446655440000----" + opaque))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	result, err := client.Refresh(t.Context(), &credential)
	if err != nil {
		t.Fatal(err)
	}
	result.Destroy()
}

func TestOAuthRefreshMapsErrorsWithoutEchoingBody(t *testing.T) {
	cases := []struct {
		name  string
		code  int
		body  string
		want  error
		stage string
	}{
		{"reauth", http.StatusBadRequest, `{"error":"invalid_grant","error_description":"secret-body-must-not-escape"}`, domain.ErrSourceReauthRequired, stageOutlookOAuth},
		{"scope reauth", http.StatusBadRequest, `{"error":"invalid_scope"}`, domain.ErrSourceReauthRequired, stageOutlookOAuth},
		{"credentials", http.StatusUnauthorized, `{"error":"bad"}`, domain.ErrSourceCredentials, stageOutlookOAuth},
		{"rate", http.StatusTooManyRequests, `temporarily unavailable`, domain.ErrSourceRateLimited, stageOutlookOAuth},
		{"upstream", http.StatusBadGateway, `<html>gateway failure</html>`, domain.ErrUpstreamFailure, stageOutlookOAuth},
		{"schema", http.StatusOK, `{"access_token":1}`, domain.ErrUpstreamSchemaChanged, ""},
		{"scope schema", http.StatusOK, `{"access_token":"access","expires_in":3600,"scope":1}`, domain.ErrUpstreamSchemaChanged, ""},
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
			if stage := domain.SourceStageOf(err); stage != test.stage {
				t.Fatalf("stage=%q, want %q", stage, test.stage)
			}
			if strings.Contains(err.Error(), "secret-body") {
				t.Fatal("error echoed OAuth response body")
			}
		})
	}
}

func TestOAuthRefreshWrongReturnedScopeRequiresReauth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"access_token":"access-value","expires_in":3600,"scope":"https://graph.microsoft.com/Mail.Read"}`))
	}))
	defer server.Close()
	client := newOAuthClientForTest(server.URL, server.Client(), time.Second)
	credential := oauthCredential(t, 's')
	defer credential.Destroy()
	_, err := client.Refresh(t.Context(), &credential)
	if !errors.Is(err, domain.ErrSourceReauthRequired) {
		t.Fatalf("error=%v", err)
	}
	if stage := domain.SourceStageOf(err); stage != stageOutlookOAuthScope {
		t.Fatalf("stage=%q", stage)
	}
}

func TestDecodeOAuthObjectRejectsDuplicateAndTrailing(t *testing.T) {
	for _, body := range []string{`{"access_token":"a","access_token":"b"}`, `{"access_token":"a"}{}`} {
		if _, err := decodeOAuthObject([]byte(body)); err == nil {
			t.Fatalf("decodeOAuthObject accepted %q", body)
		}
	}
}
