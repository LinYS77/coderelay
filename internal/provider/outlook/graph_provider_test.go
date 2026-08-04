package outlook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
)

func TestGraphProviderRefreshesWithoutScopeAndExtractsPreview(t *testing.T) {
	now := time.Date(2026, 8, 4, 7, 0, 0, 0, time.UTC)
	rotated := testRefreshToken('z')
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		methods = append(methods, request.Method+" "+request.URL.Path)
		switch request.URL.Path {
		case "/token":
			body, _ := io.ReadAll(request.Body)
			values, err := url.ParseQuery(string(body))
			if err != nil {
				t.Error(err)
			}
			if _, exists := values["scope"]; exists {
				t.Errorf("Graph refresh sent scope=%q", values.Get("scope"))
			}
			_, _ = writer.Write([]byte(`{"access_token":"graph-access","expires_in":3600,"scope":"User.Read Mail.Read","refresh_token":"` + string(rotated) + `"}`))
		case "/v1.0/me":
			assertGraphBearer(t, request)
			_, _ = writer.Write([]byte(`{"mail":"user@example.com","userPrincipalName":"user@example.com"}`))
		case "/v1.0/me/mailFolders/inbox/messages":
			assertGraphBearer(t, request)
			if request.URL.Query().Get("$top") != "10" || request.URL.Query().Get("$orderby") != "receivedDateTime desc" {
				t.Errorf("query=%q", request.URL.RawQuery)
			}
			response := map[string]any{"value": []any{map[string]any{
				"id":               "message-1",
				"receivedDateTime": now.Format(time.RFC3339Nano),
				"subject":          "Verification",
				"bodyPreview":      "Your verification code is 123456",
				"isRead":           false,
				"from": map[string]any{"emailAddress": map[string]any{
					"name": "Service", "address": "service@example.com",
				}},
			}}}
			_ = json.NewEncoder(writer).Encode(response)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	oauth := newOAuthClientForTest(server.URL+"/token", server.Client(), time.Second)
	provider := newProviderForTest(config.OutlookConfig{
		PollIntervalSeconds: 1,
		MaxMessages:         10,
		MaxMessageBytes:     64 << 10,
	}, oauth)
	provider.now = func() time.Time { return now }
	provider.graph = newGraphClientForTest(server.URL+"/v1.0", server.Client(), time.Second)
	defer provider.Close()

	secret := credential.NewOwned([]byte("user@example.com----pw----550e8400-e29b-41d4-a716-446655440000----" + strings.Repeat("r", 120)))
	defer secret.Destroy()
	code, update, err := provider.Resolve(context.Background(), domain.OutlookRequest{
		Credential: secret,
		MailAccess: domain.OutlookMailAccessGraph,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(code[:]) != "123456" || update == nil || string(update.RefreshToken) != string(rotated) {
		t.Fatalf("code=%q update=%v", code, update)
	}
	update.Destroy()
	for _, method := range methods {
		if !strings.HasPrefix(method, "POST /token") && !strings.HasPrefix(method, "GET ") {
			t.Fatalf("non-read-only Graph method: %s", method)
		}
	}
}

func TestGraphProviderRefreshesOnceAfterGraph401(t *testing.T) {
	now := time.Date(2026, 8, 4, 8, 15, 0, 0, time.UTC)
	firstRotation := testRefreshToken('a')
	secondRotation := testRefreshToken('b')
	var tokenCalls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			tokenCalls++
			access, rotation := "access-1", firstRotation
			if tokenCalls == 2 {
				access, rotation = "access-2", secondRotation
			}
			_, _ = writer.Write([]byte(`{"access_token":"` + access + `","expires_in":3600,"scope":"User.Read Mail.Read","refresh_token":"` + string(rotation) + `"}`))
		case "/v1.0/me":
			if request.Header.Get("Authorization") == "Bearer access-1" {
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = writer.Write([]byte(`{"error":{"message":"must stay secret"}}`))
				return
			}
			_, _ = writer.Write([]byte(`{"mail":"user@example.com","userPrincipalName":"user@example.com"}`))
		case "/v1.0/me/mailFolders/inbox/messages":
			_ = json.NewEncoder(writer).Encode(map[string]any{"value": []any{map[string]any{
				"id": "message-1", "receivedDateTime": now.Format(time.RFC3339Nano),
				"subject": "Verification code 112233", "bodyPreview": "", "isRead": false,
				"from": map[string]any{"emailAddress": map[string]any{"address": "service@example.com"}},
			}}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newGraphProviderForTest(t, server, now)
	defer provider.Close()
	secret := graphTestSecret()
	defer secret.Destroy()
	code, update, err := provider.Resolve(context.Background(), domain.OutlookRequest{Credential: secret, MailAccess: domain.OutlookMailAccessGraph})
	if err != nil || string(code[:]) != "112233" {
		t.Fatalf("code=%q error=%v", code, err)
	}
	if tokenCalls != 2 || update == nil || string(update.RefreshToken) != string(secondRotation) {
		t.Fatalf("token calls=%d update=%v", tokenCalls, update)
	}
	update.Destroy()
}

func TestGraphProviderRefreshesOnceAfterList401(t *testing.T) {
	now := time.Date(2026, 8, 4, 8, 20, 0, 0, time.UTC)
	var tokenCalls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			tokenCalls++
			_, _ = writer.Write([]byte(`{"access_token":"access-` + strconv.Itoa(tokenCalls) + `","expires_in":3600,"scope":"User.Read Mail.Read"}`))
		case "/v1.0/me":
			_, _ = writer.Write([]byte(`{"mail":"user@example.com","userPrincipalName":"user@example.com"}`))
		case "/v1.0/me/mailFolders/inbox/messages":
			if request.Header.Get("Authorization") == "Bearer access-1" {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"value": []any{map[string]any{
				"id": "message-1", "receivedDateTime": now.Format(time.RFC3339Nano),
				"subject": "Verification code 445566", "from": map[string]any{"emailAddress": map[string]any{"address": "service@example.com"}},
			}}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newGraphProviderForTest(t, server, now)
	defer provider.Close()
	secret := graphTestSecret()
	defer secret.Destroy()
	code, _, err := provider.Resolve(context.Background(), domain.OutlookRequest{Credential: secret, MailAccess: domain.OutlookMailAccessGraph})
	if err != nil || string(code[:]) != "445566" || tokenCalls != 2 {
		t.Fatalf("code=%q error=%v tokenCalls=%d", code, err, tokenCalls)
	}
}

func TestGraphProviderReturnsRotationWithNoFreshCode(t *testing.T) {
	now := time.Date(2026, 8, 4, 9, 45, 0, 0, time.UTC)
	rotated := testRefreshToken('z')
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			_, _ = writer.Write([]byte(`{"access_token":"graph-access","expires_in":3600,"scope":"User.Read Mail.Read","refresh_token":"` + string(rotated) + `"}`))
		case "/v1.0/me":
			_, _ = writer.Write([]byte(`{"mail":"user@example.com","userPrincipalName":"user@example.com"}`))
		case "/v1.0/me/mailFolders/inbox/messages":
			_, _ = writer.Write([]byte(`{"value":[]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newGraphProviderForTest(t, server, now)
	defer provider.Close()
	secret := graphTestSecret()
	defer secret.Destroy()
	_, update, err := provider.Resolve(context.Background(), domain.OutlookRequest{Credential: secret, MailAccess: domain.OutlookMailAccessGraph})
	if !errors.Is(err, domain.ErrNoFreshCode) || update == nil || string(update.RefreshToken) != string(rotated) {
		t.Fatalf("error=%v update=%v", err, update)
	}
	update.Destroy()
}

func TestGraphProviderUsesNewestMessageEvenIfResponseIsOutOfOrder(t *testing.T) {
	now := time.Date(2026, 8, 4, 9, 30, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			_, _ = writer.Write([]byte(`{"access_token":"graph-access","expires_in":3600,"scope":"User.Read Mail.Read"}`))
		case "/v1.0/me":
			_, _ = writer.Write([]byte(`{"mail":"user@example.com","userPrincipalName":"user@example.com"}`))
		case "/v1.0/me/mailFolders/inbox/messages":
			message := func(id, subject string, received time.Time) map[string]any {
				return map[string]any{"id": id, "receivedDateTime": received.Format(time.RFC3339Nano), "subject": subject,
					"from": map[string]any{"emailAddress": map[string]any{"address": "service@example.com"}}}
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"value": []any{
				message("old", "Verification code 111222", now.Add(-time.Minute)),
				message("new", "Verification code 333444", now),
			}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newGraphProviderForTest(t, server, now)
	defer provider.Close()
	secret := graphTestSecret()
	defer secret.Destroy()
	code, _, err := provider.Resolve(context.Background(), domain.OutlookRequest{Credential: secret, MailAccess: domain.OutlookMailAccessGraph})
	if err != nil || string(code[:]) != "333444" {
		t.Fatalf("code=%q error=%v", code, err)
	}
}

func TestGraphProviderTwentyConcurrentCredentialsStayIsolated(t *testing.T) {
	now := time.Date(2026, 8, 4, 9, 15, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			if err := request.ParseForm(); err != nil {
				t.Error(err)
				return
			}
			refresh := request.Form.Get("refresh_token")
			if len(refresh) != 120 {
				t.Errorf("refresh length=%d", len(refresh))
				return
			}
			_, _ = writer.Write([]byte(`{"access_token":"access-` + refresh[:1] + `","expires_in":3600,"scope":"User.Read Mail.Read"}`))
		case "/v1.0/me":
			label := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer access-")
			_, _ = writer.Write([]byte(`{"mail":"user` + label + `@example.com","userPrincipalName":"user` + label + `@example.com"}`))
		case "/v1.0/me/mailFolders/inbox/messages":
			label := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer access-")
			if len(label) != 1 || label[0] < 'A' || label[0] > 'T' {
				t.Errorf("authorization label=%q", label)
				return
			}
			code := fmt.Sprintf("%06d", 100000+int(label[0]-'A'))
			_ = json.NewEncoder(writer).Encode(map[string]any{"value": []any{map[string]any{
				"id": "message-" + label, "receivedDateTime": now.Format(time.RFC3339Nano),
				"subject": "Verification code " + code,
				"from":    map[string]any{"emailAddress": map[string]any{"address": "service@example.com"}},
			}}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newGraphProviderForTest(t, server, now)
	defer provider.Close()
	type result struct {
		index int
		code  string
		err   error
	}
	results := make(chan result, 20)
	for index := 0; index < 20; index++ {
		go func(index int) {
			label := byte('A' + index)
			secret := credential.NewOwned([]byte(fmt.Sprintf("user%c@example.com----pw----550e8400-e29b-41d4-a716-446655440000----%s", label, strings.Repeat(string(label), 120))))
			code, _, err := provider.Resolve(context.Background(), domain.OutlookRequest{Credential: secret, MailAccess: domain.OutlookMailAccessGraph})
			secret.Destroy()
			results <- result{index: index, code: string(code[:]), err: err}
		}(index)
	}
	for range 20 {
		current := <-results
		want := fmt.Sprintf("%06d", 100000+current.index)
		if current.err != nil || current.code != want {
			t.Fatalf("index=%d code=%q want=%q error=%v", current.index, current.code, want, current.err)
		}
	}
}

func TestGraphProviderRespectsRetryAfterDuringPolling(t *testing.T) {
	current := time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)
	var listCalls int
	var slept []time.Duration
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			_, _ = writer.Write([]byte(`{"access_token":"graph-access","expires_in":3600,"scope":"User.Read Mail.Read"}`))
		case "/v1.0/me":
			_, _ = writer.Write([]byte(`{"mail":"user@example.com","userPrincipalName":"user@example.com"}`))
		case "/v1.0/me/mailFolders/inbox/messages":
			listCalls++
			if listCalls == 1 {
				writer.Header().Set("Retry-After", "2")
				writer.WriteHeader(http.StatusTooManyRequests)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"value": []any{map[string]any{
				"id": "new", "receivedDateTime": current.Format(time.RFC3339Nano), "subject": "Code 123789",
				"from": map[string]any{"emailAddress": map[string]any{"address": "service@example.com"}},
			}}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newGraphProviderForTest(t, server, current)
	provider.now = func() time.Time { return current }
	provider.sleep = func(_ context.Context, value time.Duration) error {
		slept = append(slept, value)
		current = current.Add(value)
		return nil
	}
	defer provider.Close()
	secret := graphTestSecret()
	defer secret.Destroy()
	code, _, err := provider.Resolve(context.Background(), domain.OutlookRequest{Credential: secret, MailAccess: domain.OutlookMailAccessGraph, WaitSeconds: 3})
	if err != nil || string(code[:]) != "123789" {
		t.Fatalf("code=%q error=%v", code, err)
	}
	if len(slept) != 1 || slept[0] != 2*time.Second {
		t.Fatalf("slept=%v", slept)
	}
}

func TestGraphProviderRejectsDuplicateJSONKeys(t *testing.T) {
	now := time.Date(2026, 8, 4, 8, 45, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			_, _ = writer.Write([]byte(`{"access_token":"graph-access","expires_in":3600,"scope":"User.Read Mail.Read"}`))
		case "/v1.0/me":
			_, _ = writer.Write([]byte(`{"mail":"user@example.com","userPrincipalName":"user@example.com"}`))
		case "/v1.0/me/mailFolders/inbox/messages":
			_, _ = writer.Write([]byte(`{"value":[],"value":[{"id":"m1","receivedDateTime":"` + now.Format(time.RFC3339Nano) + `","subject":"Verification code 991122","from":{"emailAddress":{"address":"service@example.com"}}}]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newGraphProviderForTest(t, server, now)
	defer provider.Close()
	secret := graphTestSecret()
	defer secret.Destroy()
	_, _, err := provider.Resolve(context.Background(), domain.OutlookRequest{Credential: secret, MailAccess: domain.OutlookMailAccessGraph})
	if !errors.Is(err, domain.ErrUpstreamSchemaChanged) || domain.SourceStageOf(err) != stageOutlookGraphList {
		t.Fatalf("error=%v stage=%q", err, domain.SourceStageOf(err))
	}
}

func TestGraphProviderPollingFetchesEachMIMEOnceAndFindsNewMessage(t *testing.T) {
	current := time.Date(2026, 8, 4, 8, 30, 0, 0, time.UTC)
	var listCalls, mimeCalls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/token":
			_, _ = writer.Write([]byte(`{"access_token":"graph-access","expires_in":3600,"scope":"User.Read Mail.Read"}`))
		case request.URL.Path == "/v1.0/me":
			_, _ = writer.Write([]byte(`{"mail":"user@example.com","userPrincipalName":"user@example.com"}`))
		case request.URL.Path == "/v1.0/me/mailFolders/inbox/messages":
			listCalls++
			items := []any{map[string]any{
				"id": "old", "receivedDateTime": current.Add(-time.Second).Format(time.RFC3339Nano),
				"subject": "Notice", "bodyPreview": "Open message", "from": map[string]any{"emailAddress": map[string]any{"address": "service@example.com"}},
			}}
			if listCalls >= 3 {
				items = append([]any{map[string]any{
					"id": "new", "receivedDateTime": current.Format(time.RFC3339Nano),
					"subject": "Verification code 778899", "bodyPreview": "", "from": map[string]any{"emailAddress": map[string]any{"address": "service@example.com"}},
				}}, items...)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"value": items})
		case strings.HasSuffix(request.URL.Path, "/old/$value"):
			mimeCalls++
			_, _ = writer.Write([]byte("From: service@example.com\r\nSubject: Notice\r\n\r\nNo verification value here\r\n"))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newGraphProviderForTest(t, server, current)
	provider.now = func() time.Time { return current }
	provider.sleep = func(_ context.Context, value time.Duration) error {
		current = current.Add(value)
		return nil
	}
	defer provider.Close()
	secret := graphTestSecret()
	defer secret.Destroy()
	code, _, err := provider.Resolve(context.Background(), domain.OutlookRequest{Credential: secret, MailAccess: domain.OutlookMailAccessGraph, WaitSeconds: 3})
	if err != nil || string(code[:]) != "778899" {
		t.Fatalf("code=%q error=%v", code, err)
	}
	if listCalls != 3 || mimeCalls != 1 {
		t.Fatalf("list calls=%d MIME calls=%d", listCalls, mimeCalls)
	}
}

func TestGraphProviderRejectsCredentialEmailMismatchAndReturnsRotation(t *testing.T) {
	now := time.Date(2026, 8, 4, 8, 0, 0, 0, time.UTC)
	rotated := testRefreshToken('z')
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			_, _ = writer.Write([]byte(`{"access_token":"graph-access","expires_in":3600,"scope":"User.Read Mail.Read","refresh_token":"` + string(rotated) + `"}`))
		case "/v1.0/me":
			_, _ = writer.Write([]byte(`{"mail":"other@example.com","userPrincipalName":"other@example.com"}`))
		default:
			t.Errorf("unexpected request after identity mismatch: %s", request.URL)
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newGraphProviderForTest(t, server, now)
	defer provider.Close()
	secret := graphTestSecret()
	defer secret.Destroy()
	_, update, err := provider.Resolve(context.Background(), domain.OutlookRequest{Credential: secret, MailAccess: domain.OutlookMailAccessGraph})
	if !errors.Is(err, domain.ErrSourceCredentials) || domain.SourceStageOf(err) != stageOutlookGraphIdentity {
		t.Fatalf("error=%v stage=%q", err, domain.SourceStageOf(err))
	}
	if update == nil || string(update.RefreshToken) != string(rotated) {
		t.Fatalf("update=%v", update)
	}
	update.Destroy()
}

func TestGraphProviderFallsBackToBoundedMIME(t *testing.T) {
	now := time.Date(2026, 8, 4, 7, 30, 0, 0, time.UTC)
	messageID := "opaque/id+1"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/token":
			_, _ = writer.Write([]byte(`{"access_token":"graph-access","expires_in":3600,"scope":"User.Read Mail.Read"}`))
		case request.URL.Path == "/v1.0/me":
			_, _ = writer.Write([]byte(`{"mail":"user@example.com","userPrincipalName":"user@example.com"}`))
		case request.URL.Path == "/v1.0/me/mailFolders/inbox/messages":
			_ = json.NewEncoder(writer).Encode(map[string]any{"value": []any{map[string]any{
				"id": messageID, "receivedDateTime": now.Format(time.RFC3339Nano),
				"subject": "Account notice", "bodyPreview": "Open this message to continue", "isRead": false,
				"from": map[string]any{"emailAddress": map[string]any{"address": "service@example.com"}},
			}}})
		case strings.HasSuffix(request.URL.Path, "/$value"):
			if request.URL.EscapedPath() != "/v1.0/me/mailFolders/inbox/messages/opaque%2Fid+1/$value" {
				t.Errorf("escaped MIME path=%q", request.URL.EscapedPath())
			}
			_, _ = writer.Write([]byte("From: Service <service@example.com>\r\nSubject: Verification\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour verification code is 654321\r\n"))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newGraphProviderForTest(t, server, now)
	defer provider.Close()
	secret := graphTestSecret()
	defer secret.Destroy()
	code, _, err := provider.Resolve(context.Background(), domain.OutlookRequest{Credential: secret, MailAccess: domain.OutlookMailAccessGraph})
	if err != nil || string(code[:]) != "654321" {
		t.Fatalf("code=%q error=%v", code, err)
	}
}

func newGraphProviderForTest(t *testing.T, server *httptest.Server, now time.Time) *Provider {
	t.Helper()
	oauth := newOAuthClientForTest(server.URL+"/token", server.Client(), time.Second)
	provider := newProviderForTest(config.OutlookConfig{PollIntervalSeconds: 1, MaxMessages: 10, MaxMessageBytes: 64 << 10}, oauth)
	provider.now = func() time.Time { return now }
	provider.graph = newGraphClientForTest(server.URL+"/v1.0", server.Client(), time.Second)
	return provider
}

func graphTestSecret() *credential.Secret {
	return credential.NewOwned([]byte("user@example.com----pw----550e8400-e29b-41d4-a716-446655440000----" + strings.Repeat("r", 120)))
}

func assertGraphBearer(t *testing.T, request *http.Request) {
	t.Helper()
	if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer graph-access" {
		t.Errorf("request=%s %s authorization=%q", request.Method, request.URL, request.Header.Get("Authorization"))
	}
}
