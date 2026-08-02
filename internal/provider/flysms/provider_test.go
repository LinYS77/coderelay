package flysms

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/extractor"
)

func TestLatestContract(t *testing.T) {
	now := time.Date(2026, 8, 2, 4, 0, 0, 0, time.UTC)
	provider, closeServer := newTestProvider(t, now, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/icloud/api/pickup/messages/latest" || request.URL.RawQuery != "" {
			t.Errorf("unexpected URL %s", request.URL.String())
		}
		assertUpstreamIdentity(t, request, testEmail, testToken)
		writeJSONResponse(t, writer, http.StatusOK, detailEnvelope(testEmail, "INBOX", 7, now.Add(-time.Second), "Your verification code is 123456"))
	})
	defer closeServer()
	code, err := resolveTestCredential(provider, validCredential(testEmail, testToken), nil, 0)
	if err != nil || string(code[:]) != "123456" {
		t.Fatalf("code=%q error=%v", code, err)
	}
}

func TestHistoryContract(t *testing.T) {
	now := time.Date(2026, 8, 2, 4, 0, 0, 0, time.UTC)
	var calls atomic.Int64
	provider, closeServer := newTestProvider(t, now, func(writer http.ResponseWriter, request *http.Request) {
		assertUpstreamIdentity(t, request, testEmail, testToken)
		calls.Add(1)
		if strings.HasSuffix(request.URL.Path, "/latest") {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if request.URL.Path != "/icloud/api/pickup/messages" || request.URL.Query().Get("limit") != "30" {
			t.Errorf("unexpected history URL %s", request.URL.String())
		}
		writeJSONResponse(t, writer, http.StatusOK, map[string]any{
			"email": testEmail,
			"messages": []any{map[string]any{
				"mailbox": "INBOX", "uid": 8, "subject": "Security code 654321",
				"from": "no-reply@service.example", "date": now.Add(-time.Second).Format(time.RFC3339Nano), "preview": "Security code 654321",
			}},
		})
	})
	defer closeServer()
	code, err := resolveTestCredential(provider, validCredential(testEmail, testToken), nil, 0)
	if err != nil || string(code[:]) != "654321" || calls.Load() != 2 {
		t.Fatalf("code=%q calls=%d error=%v", code, calls.Load(), err)
	}
}

func TestDetailContract(t *testing.T) {
	now := time.Date(2026, 8, 2, 4, 0, 0, 0, time.UTC)
	var detailCalls atomic.Int64
	provider, closeServer := newTestProvider(t, now, func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/latest"):
			writer.WriteHeader(http.StatusNotFound)
		case request.URL.Path == "/icloud/api/pickup/messages":
			writeJSONResponse(t, writer, http.StatusOK, map[string]any{
				"email": testEmail,
				"messages": []any{map[string]any{
					"mailbox": "Archive & Inbox", "uid": 9, "subject": "Notice",
					"from": "sender@example.com", "date": now.Add(-time.Second).Format(time.RFC3339Nano), "preview": "Message preview",
				}},
			})
		default:
			detailCalls.Add(1)
			if request.URL.Path != "/icloud/api/pickup/messages/9" || request.URL.Query().Get("mailbox") != "Archive & Inbox" {
				t.Errorf("unexpected detail URL %s", request.URL.String())
			}
			writeJSONResponse(t, writer, http.StatusOK, detailEnvelope(testEmail, "Archive & Inbox", 9, now.Add(-time.Second), "Authentication code: 112233"))
		}
	})
	defer closeServer()
	code, err := resolveTestCredential(provider, validCredential(testEmail, testToken), nil, 0)
	if err != nil || string(code[:]) != "112233" || detailCalls.Load() != 1 {
		t.Fatalf("code=%q detail_calls=%d error=%v", code, detailCalls.Load(), err)
	}
}

func TestNoFreshCodeAndNotBefore(t *testing.T) {
	now := time.Date(2026, 8, 2, 4, 0, 0, 0, time.UTC)
	provider, closeServer := newTestProvider(t, now, func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/latest") {
			writeJSONResponse(t, writer, http.StatusOK, detailEnvelope(testEmail, "INBOX", 3, now.Add(-time.Minute), "Verification code 123456"))
			return
		}
		writeJSONResponse(t, writer, http.StatusOK, map[string]any{"email": testEmail, "messages": []any{}})
	})
	defer closeServer()
	notBefore := now.Add(-time.Second)
	_, err := resolveTestCredential(provider, validCredential(testEmail, testToken), &notBefore, 0)
	if !errors.Is(err, domain.ErrNoFreshCode) || domain.RetryAfter(err) != 2 {
		t.Fatalf("error=%v retry=%d", err, domain.RetryAfter(err))
	}
}

func TestEntitlementAndHTTPStatusMapping(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name       string
		status     int
		body       any
		header     string
		expected   error
		retryAfter int
	}{
		{name: "401", status: 401, expected: domain.ErrSourceCredentials},
		{name: "403", status: 403, expected: domain.ErrSourceExpired},
		{name: "429", status: 429, header: "17", expected: domain.ErrSourceRateLimited, retryAfter: 17},
		{name: "503", status: 503, expected: domain.ErrSourceSyncing, retryAfter: 2},
		{name: "500", status: 500, expected: domain.ErrUpstreamFailure},
		{name: "expired", status: 200, body: map[string]any{"email": testEmail, "entitlementStatus": "expired"}, expected: domain.ErrSourceExpired},
		{name: "pending", status: 200, body: map[string]any{"email": testEmail, "entitlementStatus": "pending"}, expected: domain.ErrSourceSyncing, retryAfter: 2},
		{name: "unknown", status: 200, body: map[string]any{"email": testEmail, "entitlementStatus": "mystery"}, expected: domain.ErrUpstreamSchemaChanged},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			provider, closeServer := newTestProvider(t, now, func(writer http.ResponseWriter, request *http.Request) {
				if test.header != "" {
					writer.Header().Set("Retry-After", test.header)
				}
				if test.body == nil {
					writer.WriteHeader(test.status)
					return
				}
				writeJSONResponse(t, writer, test.status, test.body)
			})
			defer closeServer()
			_, err := resolveTestCredential(provider, validCredential(testEmail, testToken), nil, 0)
			if !errors.Is(err, test.expected) || domain.RetryAfter(err) != test.retryAfter {
				t.Fatalf("error=%v retry=%d", err, domain.RetryAfter(err))
			}
		})
	}
}

func TestSchemaFaultsAndResponseBounds(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "mailbox mismatch", handler: func(writer http.ResponseWriter, request *http.Request) {
			writeJSONResponse(t, writer, 200, detailEnvelope("other@example.com", "INBOX", 1, now, "Verification code 123456"))
		}},
		{name: "duplicate root", handler: func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"email":"`+testEmail+`","email":"`+testEmail+`","message":{}}`)
		}},
		{name: "malformed JSON", handler: func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(writer, `{"email":`)
		}},
		{name: "oversized", handler: func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Length", strconv.Itoa(latestResponseLimit+1))
			writer.WriteHeader(http.StatusOK)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			provider, closeServer := newTestProvider(t, now, test.handler)
			defer closeServer()
			_, err := resolveTestCredential(provider, validCredential(testEmail, testToken), nil, 0)
			if !errors.Is(err, domain.ErrUpstreamSchemaChanged) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestPollingRetriesBeforeDeadline(t *testing.T) {
	clock := time.Now().UTC()
	var latestCalls atomic.Int64
	provider, closeServer := newTestProvider(t, clock, func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/latest") {
			if latestCalls.Add(1) == 1 {
				writeJSONResponse(t, writer, http.StatusOK, detailEnvelope(testEmail, "INBOX", 1, clock, "no matching message"))
				return
			}
			writeJSONResponse(t, writer, http.StatusOK, detailEnvelope(testEmail, "INBOX", 2, clock, "Verification code 246810"))
			return
		}
		writeJSONResponse(t, writer, http.StatusOK, map[string]any{"email": testEmail, "messages": []any{}})
	})
	defer closeServer()
	var sleeps atomic.Int64
	provider.settings.PollIntervalSeconds = 1
	provider.sleep = func(ctx context.Context, delay time.Duration) error {
		sleeps.Add(1)
		return nil
	}
	provider.jitter = func(delay time.Duration) time.Duration { return delay }
	code, err := resolveTestCredential(provider, validCredential(testEmail, testToken), nil, 3)
	if err != nil || string(code[:]) != "246810" || latestCalls.Load() != 2 || sleeps.Load() != 1 {
		t.Fatalf("code=%q calls=%d sleeps=%d error=%v", code, latestCalls.Load(), sleeps.Load(), err)
	}
}

func TestDetailFanoutIsBoundedAtFive(t *testing.T) {
	now := time.Now().UTC()
	var detailCalls atomic.Int64
	provider, closeServer := newTestProvider(t, now, func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/latest"):
			writer.WriteHeader(http.StatusNotFound)
		case request.URL.Path == "/icloud/api/pickup/messages":
			messages := make([]any, 6)
			for i := range messages {
				messages[i] = map[string]any{"mailbox": "INBOX", "uid": i + 1, "subject": "Notice", "from": "sender@example.com", "date": now.Format(time.RFC3339Nano), "preview": "no code"}
			}
			writeJSONResponse(t, writer, http.StatusOK, map[string]any{"email": testEmail, "messages": messages})
		default:
			detailCalls.Add(1)
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	defer closeServer()
	_, err := resolveTestCredential(provider, validCredential(testEmail, testToken), nil, 0)
	if !errors.Is(err, domain.ErrNoFreshCode) || detailCalls.Load() != 5 {
		t.Fatalf("error=%v detail_calls=%d", err, detailCalls.Load())
	}
}

func TestRetryAfterLongerThanWindowPreservesSourceError(t *testing.T) {
	provider, closeServer := newTestProvider(t, time.Now().UTC(), func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Retry-After", "5")
		writer.WriteHeader(http.StatusTooManyRequests)
	})
	defer closeServer()
	_, err := resolveTestCredential(provider, validCredential(testEmail, testToken), nil, 2)
	if !errors.Is(err, domain.ErrSourceRateLimited) || domain.RetryAfter(err) != 5 {
		t.Fatalf("error=%v retry=%d", err, domain.RetryAfter(err))
	}
}

func TestTimeoutCancellationAndReadFault(t *testing.T) {
	now := time.Now().UTC()
	t.Run("timeout", func(t *testing.T) {
		provider, closeServer := newTestProvider(t, now, func(writer http.ResponseWriter, request *http.Request) {
			<-request.Context().Done()
		})
		defer closeServer()
		provider.networkTimeout = 20 * time.Millisecond
		provider.fetchTimeout = 100 * time.Millisecond
		_, err := resolveTestCredential(provider, validCredential(testEmail, testToken), nil, 0)
		if !errors.Is(err, domain.ErrUpstreamTimeout) {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		provider, closeServer := newTestProvider(t, now, func(writer http.ResponseWriter, request *http.Request) {
			<-request.Context().Done()
		})
		defer closeServer()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		secret := credential.NewOwned([]byte(validCredential(testEmail, testToken)))
		defer secret.Destroy()
		_, err := provider.Resolve(ctx, secret, nil, 0)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("read fault", func(t *testing.T) {
		provider := testProvider(now, &faultDoer{})
		_, err := resolveTestCredential(provider, validCredential(testEmail, testToken), nil, 0)
		if !errors.Is(err, domain.ErrUpstreamFailure) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestTwentyConcurrentCredentialsDoNotCross(t *testing.T) {
	now := time.Now().UTC()
	expected := make(map[string]struct {
		token string
		code  string
	}, 20)
	for i := 0; i < 20; i++ {
		email := fmt.Sprintf("box%02d@example.com", i)
		expected[email] = struct {
			token string
			code  string
		}{token: fmt.Sprintf("tok_parallel-safe-token-%02d-abcdef", i), code: fmt.Sprintf("%06d", 100_000+i)}
	}
	provider, closeServer := newTestProvider(t, now, func(writer http.ResponseWriter, request *http.Request) {
		email := request.Header.Get("X-Mailbox-Email")
		identity, ok := expected[email]
		if !ok || request.Header.Get("Authorization") != "Bearer "+identity.token {
			t.Errorf("upstream identity mismatch")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSONResponse(t, writer, 200, detailEnvelope(email, "INBOX", 1, now, "Verification code "+identity.code))
	})
	defer closeServer()

	var wait sync.WaitGroup
	errorsFound := make(chan error, 20)
	for email, identity := range expected {
		email, identity := email, identity
		wait.Add(1)
		go func() {
			defer wait.Done()
			code, err := resolveTestCredential(provider, validCredential(email, identity.token), nil, 0)
			if err != nil || string(code[:]) != identity.code {
				errorsFound <- fmt.Errorf("identity mismatch")
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
}

func newTestProvider(t *testing.T, now time.Time, handler http.HandlerFunc) (*Provider, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	baseURL, err := url.Parse(server.URL + "/icloud/api/pickup/messages")
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	cfg := config.Default()
	client, transport := newHTTPClient(cfg.Server)
	provider := testProvider(now, client)
	provider.baseURL = baseURL
	provider.transport = transport
	return provider, func() {
		provider.Close()
		server.Close()
	}
}

func testProvider(now time.Time, client httpDoer) *Provider {
	settings := config.Default().Providers.FlySMS
	return &Provider{
		settings:       settings,
		baseURL:        &url.URL{Scheme: "http", Host: "example.invalid", Path: "/icloud/api/pickup/messages"},
		client:         client,
		networkTimeout: time.Second,
		fetchTimeout:   2 * time.Second,
		maxWait:        30,
		extractor:      extractor.New(extractor.DefaultSettings()),
		now:            func() time.Time { return now },
		sleep:          sleepContext,
		jitter:         func(value time.Duration) time.Duration { return value },
	}
}

func resolveTestCredential(provider *Provider, value string, notBefore *time.Time, waitSeconds int) ([6]byte, error) {
	secret := credential.NewOwned([]byte(value))
	defer secret.Destroy()
	return provider.Resolve(context.Background(), secret, notBefore, waitSeconds)
}

func detailEnvelope(email, mailbox string, uid int64, received time.Time, text string) map[string]any {
	return map[string]any{
		"email": email, "entitlementStatus": "active",
		"message": map[string]any{
			"mailbox": mailbox, "uid": uid, "subject": "Verification code", "from": "sender@example.com",
			"date": received.Format(time.RFC3339Nano), "text": text, "html": "",
		},
	}
}

func assertUpstreamIdentity(t *testing.T, request *http.Request, email, token string) {
	t.Helper()
	if request.Header.Get("Authorization") != "Bearer "+token || request.Header.Get("X-Mailbox-Email") != email {
		t.Fatal("upstream credential headers are incorrect")
	}
	if request.Header.Get("Cookie") != "" {
		t.Fatal("cookie was sent to FlySMS")
	}
}

func writeJSONResponse(t *testing.T, writer http.ResponseWriter, status int, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

type faultDoer struct{}

func (*faultDoer) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: -1,
		Header:        make(http.Header),
		Body:          io.NopCloser(faultReader{}),
	}, nil
}

type faultReader struct{}

func (faultReader) Read([]byte) (int, error) { return 0, errors.New("injected read failure") }
