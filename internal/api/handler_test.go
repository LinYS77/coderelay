package api

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/auth"
	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/secretfile"
	"github.com/LinYS77/coderelay/internal/totp"
)

const testTOTPSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestHealthAndReadinessArePublic(t *testing.T) {
	handler, _, cancel := newTestHandler(t, totp.New(), nil)
	defer cancel()

	live := perform(handler, http.MethodGet, "/health/live", nil, "")
	if live.Code != http.StatusOK || !strings.Contains(live.Body.String(), `"version":"1.0.0-phase2"`) {
		t.Fatalf("live: status=%d body=%s", live.Code, live.Body.String())
	}
	ready := perform(handler, http.MethodGet, "/health/ready", nil, "")
	if ready.Code != http.StatusOK || ready.Body.String() != "{\"status\":\"ready\",\"mode\":\"stateless\"}" {
		t.Fatalf("ready: status=%d body=%s", ready.Code, ready.Body.String())
	}
	if live.Header().Get("Cache-Control") != "no-store" || live.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("health security headers are missing")
	}

	handler.BeginShutdown()
	notReady := perform(handler, http.MethodGet, "/health/ready", nil, "")
	if notReady.Code != http.StatusServiceUnavailable || notReady.Body.String() != "{\"status\":\"not_ready\"}" {
		t.Fatalf("not ready: status=%d body=%s", notReady.Code, notReady.Body.String())
	}
}

func TestRequestIDValidation(t *testing.T) {
	handler, _, cancel := newTestHandler(t, totp.New(), nil)
	defer cancel()
	valid := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	valid.Host = "example.com"
	valid.Header.Set("X-Request-ID", "request_1234")
	validResponse := httptest.NewRecorder()
	handler.ServeHTTP(validResponse, valid)
	if validResponse.Header().Get("X-Request-ID") != "request_1234" {
		t.Fatal("valid request ID was not preserved")
	}
	invalid := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	invalid.Host = "example.com"
	invalid.Header.Set("X-Request-ID", "bad")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	if got := invalidResponse.Header().Get("X-Request-ID"); got == "bad" || len(got) != 24 {
		t.Fatalf("invalid request ID replacement = %q", got)
	}
}

func TestBearerRequiredBeforeBodyRead(t *testing.T) {
	handler, token, cancel := newTestHandler(t, totp.New(), nil)
	defer cancel()
	payload := []byte(`{"type":"totp","credential":"` + testTOTPSecret + `"}`)

	for _, authorization := range []string{"", "Bearer wrong-token"} {
		body := newCountingBody(payload)
		request := newAPIRequest(body, authorization)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || errorCode(t, response) != "AUTHENTICATION_REQUIRED" {
			t.Fatalf("authorization=%q status=%d body=%s", authorization, response.Code, response.Body.String())
		}
		if body.reads.Load() != 0 {
			t.Fatal("unauthorized request body was read")
		}
		if response.Header().Get("WWW-Authenticate") != "Bearer" || response.Header().Get("Connection") != "close" {
			t.Fatal("unauthorized response headers are incomplete")
		}
	}

	body := newCountingBody(payload)
	request := newAPIRequest(body, "")
	request.URL.RawQuery = "api_token=" + string(token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || body.reads.Load() != 0 {
		t.Fatal("URL token bypassed Bearer authentication")
	}

	body = newCountingBody(payload)
	request = newAPIRequest(body, "Bearer "+string(token))
	request.URL.RawQuery = "credential=must-not-be-in-url"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity || body.reads.Load() != 0 {
		t.Fatal("query parameters were accepted on the code endpoint")
	}
}

func TestHostAndDuplicateAuthorizationRejectBeforeBody(t *testing.T) {
	handler, token, cancel := newTestHandler(t, totp.New(), nil)
	defer cancel()
	payload := []byte(`{"type":"totp","credential":"` + testTOTPSecret + `"}`)

	badHostBody := newCountingBody(payload)
	badHost := newAPIRequest(badHostBody, "Bearer "+string(token))
	badHost.Host = "attacker.example"
	badHostResponse := httptest.NewRecorder()
	handler.ServeHTTP(badHostResponse, badHost)
	if badHostResponse.Code != http.StatusBadRequest || badHostBody.reads.Load() != 0 {
		t.Fatalf("bad host status=%d reads=%d", badHostResponse.Code, badHostBody.reads.Load())
	}

	duplicateBody := newCountingBody(payload)
	duplicate := newAPIRequest(duplicateBody, "")
	duplicate.Header.Add("Authorization", "Bearer "+string(token))
	duplicate.Header.Add("Authorization", "Bearer another-token")
	duplicateResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateResponse, duplicate)
	if duplicateResponse.Code != http.StatusUnauthorized || duplicateBody.reads.Load() != 0 {
		t.Fatalf("duplicate auth status=%d reads=%d", duplicateResponse.Code, duplicateBody.reads.Load())
	}
}

func TestTOTPReturnsMinimalJSONAndSecurityHeaders(t *testing.T) {
	fixed := time.Unix(1_111_111_111, 0).UTC()
	handler, token, cancel := newTestHandler(t, totp.NewWithClock(func() time.Time { return fixed }), nil)
	defer cancel()
	response := perform(handler, http.MethodPost, "/api/v1/code", []byte(`{"type":"totp","credential":"`+testTOTPSecret+`","min_ttl":0}`), string(token))
	if response.Code != http.StatusOK || response.Body.String() != `{"code":"050471"}` {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	expectedHeaders := map[string]string{
		"Cache-Control":          "no-store, private",
		"Pragma":                 "no-cache",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for key, expected := range expectedHeaders {
		if response.Header().Get(key) != expected {
			t.Errorf("%s = %q, want %q", key, response.Header().Get(key), expected)
		}
	}
	if len(response.Header().Get("X-Request-ID")) != 24 {
		t.Fatal("generated request ID has wrong length")
	}
}

func TestStrictJSONAndBodyLimitsNeverEchoCredential(t *testing.T) {
	handler, token, cancel := newTestHandler(t, totp.New(), nil)
	defer cancel()
	secret := "sensitive-phase1-request-secret"
	cases := []struct {
		name   string
		body   []byte
		status int
		code   string
	}{
		{name: "duplicate", body: []byte(`{"type":"totp","credential":"` + secret + `","credential":"other"}`), status: 422, code: "VALIDATION_ERROR"},
		{name: "unknown field", body: []byte(`{"type":"totp","credential":"` + secret + `","wait_seconds":1}`), status: 422, code: "VALIDATION_ERROR"},
		{name: "trailing", body: []byte(`{"type":"totp","credential":"` + secret + `"}{}`), status: 422, code: "VALIDATION_ERROR"},
		{name: "array", body: []byte(`[]`), status: 422, code: "VALIDATION_ERROR"},
		{name: "unknown type", body: []byte(`{"type":"unknown","credential":"` + secret + `"}`), status: 422, code: "VALIDATION_ERROR"},
		{name: "future provider", body: []byte(`{"type":"outlook","credential":"` + secret + `"}`), status: 422, code: "INVALID_CODE_REQUEST"},
		{name: "invalid utf8", body: []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, status: 422, code: "VALIDATION_ERROR"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response := perform(handler, http.MethodPost, "/api/v1/code", test.body, string(token))
			if response.Code != test.status || errorCode(t, response) != test.code {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), secret) {
				t.Fatal("credential was echoed")
			}
		})
	}

	oversized := bytes.Repeat([]byte{'x'}, int(handler.config.Server.MaxBodyBytes)+10_000)
	response := perform(handler, http.MethodPost, "/api/v1/code", oversized, string(token))
	if response.Code != http.StatusRequestEntityTooLarge || errorCode(t, response) != "REQUEST_TOO_LARGE" {
		t.Fatalf("oversized status=%d body=%s", response.Code, response.Body.String())
	}
	chunkedBody := newCountingBody(oversized)
	chunked := newAPIRequest(chunkedBody, "Bearer "+string(token))
	chunked.ContentLength = -1
	chunked.TransferEncoding = []string{"chunked"}
	chunkedResponse := httptest.NewRecorder()
	handler.ServeHTTP(chunkedResponse, chunked)
	if chunkedResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversized status=%d", chunkedResponse.Code)
	}
	if got := chunkedBody.bytesRead.Load(); got > handler.config.Server.MaxBodyBytes+1 {
		t.Fatalf("oversized reader consumed %d bytes, limit=%d", got, handler.config.Server.MaxBodyBytes)
	}
}

func TestFlySMSRequestDecodesAndMapsSuccess(t *testing.T) {
	resolver := &captureFlyResolver{code: [6]byte{'1', '2', '3', '4', '5', '6'}}
	handler, token, cancel := newTestHandler(t, resolver, nil)
	defer cancel()
	notBefore := time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	payload := []byte(`{"type":"flysms","credential":"box@example.com---tok_test-token_12345678---https://flysms.xyz/icloud/pickup#email=box%40example.com&key=tok_test-token_12345678","not_before":"` + notBefore + `","wait_seconds":7}`)
	response := perform(handler, http.MethodPost, "/api/v1/code", payload, string(token))
	if response.Code != http.StatusOK || response.Body.String() != `{"code":"123456"}` {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if resolver.provider != domain.ProviderFlySMS || resolver.wait != 7 || !resolver.hasTime {
		t.Fatal("FlySMS request fields were not decoded")
	}
}

func TestFlySMSRequestValidationRejectsFutureAndUnknownFields(t *testing.T) {
	handler, token, cancel := newTestHandler(t, &captureFlyResolver{}, nil)
	defer cancel()
	cases := []string{
		`{"type":"flysms","credential":"x","unknown":1}`,
		`{"type":"flysms","credential":"x","not_before":"2099-01-01T00:00:00Z"}`,
		`{"type":"flysms","credential":"x","wait_seconds":31}`,
	}
	for _, value := range cases {
		response := perform(handler, http.MethodPost, "/api/v1/code", []byte(value), string(token))
		if response.Code != http.StatusUnprocessableEntity || errorCode(t, response) != "VALIDATION_ERROR" {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestFlySMSErrorMapping(t *testing.T) {
	cases := []struct {
		err    error
		code   string
		status int
	}{
		{err: domain.ErrNoFreshCode, code: "NO_FRESH_CODE", status: 404},
		{err: domain.ErrAmbiguousCode, code: "AMBIGUOUS_CODE", status: 409},
		{err: domain.ErrSourceRateLimited, code: "SOURCE_RATE_LIMITED", status: 429},
		{err: domain.ErrSourceSyncing, code: "SOURCE_SYNCING", status: 503},
		{err: domain.ErrUpstreamSchemaChanged, code: "UPSTREAM_SCHEMA_CHANGED", status: 502},
	}
	for _, test := range cases {
		handler, token, cancel := newTestHandler(t, errorResolver{cause: test.err}, nil)
		response := perform(handler, http.MethodPost, "/api/v1/code", []byte(`{"type":"flysms","credential":"x"}`), string(token))
		cancel()
		if response.Code != test.status || errorCode(t, response) != test.code {
			t.Fatalf("error=%v status=%d body=%s", test.err, response.Code, response.Body.String())
		}
	}
}

func TestInvalidTOTPCredentialAndMinTTLUseDomainError(t *testing.T) {
	handler, token, cancel := newTestHandler(t, totp.New(), nil)
	defer cancel()
	cases := [][]byte{
		[]byte(`{"type":"totp","credential":"sensitive-invalid-base32!","min_ttl":0}`),
		[]byte(`{"type":"totp","credential":"` + testTOTPSecret + `","min_ttl":30}`),
	}
	for _, payload := range cases {
		response := perform(handler, http.MethodPost, "/api/v1/code", payload, string(token))
		if response.Code != http.StatusUnprocessableEntity || errorCode(t, response) != "INVALID_CODE_REQUEST" {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "sensitive-invalid") || strings.Contains(response.Body.String(), testTOTPSecret) {
			t.Fatal("invalid TOTP credential was echoed")
		}
	}
}

func TestInvalidContentTypeDoesNotReadBody(t *testing.T) {
	handler, token, cancel := newTestHandler(t, totp.New(), nil)
	defer cancel()
	body := newCountingBody([]byte("sensitive-body"))
	request := newAPIRequest(body, "Bearer "+string(token))
	request.Header.Set("Content-Type", "text/plain")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType || body.reads.Load() != 0 {
		t.Fatalf("status=%d reads=%d", response.Code, body.reads.Load())
	}
}

func TestUnauthenticatedRequestsAreIPRateLimitedWithoutBodyRead(t *testing.T) {
	mutate := func(cfg *config.Config) {
		cfg.Server.MaxConcurrentCodeRequests = 1
		cfg.Server.MaxQueuedCodeRequests = 1
		cfg.Security.APIRateLimitBurst = 2
		cfg.Security.APIRateLimitPerMinute = 60
	}
	handler, _, cancel := newTestHandler(t, totp.New(), mutate)
	defer cancel()
	for i := 0; i < 3; i++ {
		body := newCountingBody([]byte(`{"type":"totp","credential":"secret"}`))
		request := newAPIRequest(body, "")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if i < 2 && response.Code != http.StatusUnauthorized {
			t.Fatalf("request %d status=%d", i, response.Code)
		}
		if i == 2 && (response.Code != http.StatusTooManyRequests || errorCode(t, response) != "RATE_LIMITED") {
			t.Fatalf("limited status=%d body=%s", response.Code, response.Body.String())
		}
		if body.reads.Load() != 0 {
			t.Fatal("unauthenticated rate-limit path read body")
		}
	}
}

func TestAuthenticatedRequestsArePrincipalRateLimitedAcrossIPs(t *testing.T) {
	mutate := func(cfg *config.Config) {
		cfg.Server.MaxConcurrentCodeRequests = 1
		cfg.Server.MaxQueuedCodeRequests = 1
		cfg.Security.APIRateLimitBurst = 2
		cfg.Security.APIRateLimitPerMinute = 60
	}
	fixed := time.Unix(1_111_111_111, 0)
	handler, token, cancel := newTestHandler(t, totp.NewWithClock(func() time.Time { return fixed }), mutate)
	defer cancel()
	for i := 0; i < 3; i++ {
		body := newCountingBody([]byte(`{"type":"totp","credential":"` + testTOTPSecret + `","min_ttl":0}`))
		request := newAPIRequest(body, "Bearer "+string(token))
		request.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", i+1)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if i < 2 && response.Code != http.StatusOK {
			t.Fatalf("request %d status=%d body=%s", i, response.Code, response.Body.String())
		}
		if i == 2 && (response.Code != http.StatusTooManyRequests || errorCode(t, response) != "RATE_LIMITED") {
			t.Fatalf("principal limit status=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestAdmissionRejectsTwentyFifthWithoutReadingBody(t *testing.T) {
	resolver := newBlockingResolver()
	handler, token, cancel := newTestHandler(t, resolver, nil)
	defer cancel()
	var wait sync.WaitGroup
	bodies := make([]*countingBody, 24)
	for i := 0; i < 24; i++ {
		payload := []byte(fmt.Sprintf(`{"type":"totp","credential":"%s","min_ttl":0}`, testTOTPSecret))
		bodies[i] = newCountingBody(payload)
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			request := newAPIRequest(bodies[index], "Bearer "+string(token))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Errorf("request %d status=%d body=%s", index, response.Code, response.Body.String())
			}
		}(i)
	}
	resolver.waitEntered(t, 20)
	waitForHandlerCount(t, handler.QueuedRequests, 4)
	readBodies := 0
	for _, body := range bodies {
		if body.reads.Load() > 0 {
			readBodies++
		}
	}
	if readBodies != 20 {
		t.Fatalf("body readers used before admission = %d, want 20", readBodies)
	}

	body := newCountingBody([]byte(`{"type":"totp","credential":"` + testTOTPSecret + `","min_ttl":0}`))
	request := newAPIRequest(body, "Bearer "+string(token))
	response := httptest.NewRecorder()
	started := time.Now()
	handler.ServeHTTP(response, request)
	elapsed := time.Since(started)
	if response.Code != http.StatusServiceUnavailable || errorCode(t, response) != "SERVER_BUSY" {
		t.Fatalf("25th status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Retry-After") != "2" {
		t.Fatalf("Retry-After = %q", response.Header().Get("Retry-After"))
	}
	if body.reads.Load() != 0 {
		t.Fatal("25th body was read")
	}
	if elapsed >= 100*time.Millisecond {
		t.Fatalf("25th rejection took %s", elapsed)
	}
	resolver.releaseAll()
	wait.Wait()
	if handler.ActiveRequests() != 0 || handler.QueuedRequests() != 0 {
		t.Fatalf("active=%d queued=%d", handler.ActiveRequests(), handler.QueuedRequests())
	}
}

func TestTwentyConcurrentTOTPRequestsAreIsolatedAndFast(t *testing.T) {
	fixed := time.Unix(1_111_111_111, 0).UTC()
	generator := totp.NewWithClock(func() time.Time { return fixed })
	handler, token, cancel := newTestHandler(t, generator, nil)
	defer cancel()

	type result struct {
		index   int
		status  int
		code    string
		latency time.Duration
	}
	results := make(chan result, 20)
	expected := make([]string, 20)
	secrets := make([]string, 20)
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		raw := bytes.Repeat([]byte{byte(i + 1)}, 20)
		secrets[i] = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		secret := credential.NewOwned([]byte(secrets[i]))
		code, err := generator.Resolve(context.Background(), secret, 0)
		secret.Destroy()
		clear(raw)
		if err != nil {
			t.Fatal(err)
		}
		expected[i] = string(code[:])
		clear(code[:])
		go func(index int) {
			<-start
			payload := []byte(fmt.Sprintf(`{"type":"totp","credential":"%s","min_ttl":0}`, secrets[index]))
			began := time.Now()
			response := perform(handler, http.MethodPost, "/api/v1/code", payload, string(token))
			elapsed := time.Since(began)
			var decoded struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(response.Body.Bytes(), &decoded)
			results <- result{index: index, status: response.Code, code: decoded.Code, latency: elapsed}
		}(i)
	}
	close(start)
	latencies := make([]time.Duration, 0, 20)
	for i := 0; i < 20; i++ {
		current := <-results
		if current.status != http.StatusOK {
			t.Fatalf("request %d status=%d", current.index, current.status)
		}
		if current.code != expected[current.index] {
			t.Fatalf("request %d code=%s want=%s", current.index, current.code, expected[current.index])
		}
		latencies = append(latencies, current.latency)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p99 := latencies[len(latencies)-1]
	t.Logf("20-concurrent TOTP p99/max handler overhead: %s", p99)
	if p99 >= 50*time.Millisecond {
		t.Fatalf("TOTP p99=%s, want <50ms", p99)
	}
}

func TestInvalidResolverCodeReturnsInternalError(t *testing.T) {
	handler, token, cancel := newTestHandler(t, invalidResultResolver{}, nil)
	defer cancel()
	response := perform(handler, http.MethodPost, "/api/v1/code", []byte(`{"type":"totp","credential":"`+testTOTPSecret+`","min_ttl":0}`), string(token))
	if response.Code != http.StatusInternalServerError || errorCode(t, response) != "INTERNAL_ERROR" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestResolverDeadlineUsesPublicTimeout(t *testing.T) {
	handler, token, cancel := newTestHandler(t, errorResolver{cause: context.DeadlineExceeded}, nil)
	defer cancel()
	response := perform(handler, http.MethodPost, "/api/v1/code", []byte(`{"type":"totp","credential":"`+testTOTPSecret+`","min_ttl":0}`), string(token))
	if response.Code != http.StatusGatewayTimeout || errorCode(t, response) != "UPSTREAM_TIMEOUT" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestResolverErrorsDoNotLeakCredentialOrCause(t *testing.T) {
	causeSecret := "sensitive-upstream-cause"
	handler, token, cancel := newTestHandler(t, errorResolver{cause: errors.New(causeSecret)}, nil)
	defer cancel()
	var logs strings.Builder
	handler.logger = slog.New(slog.NewTextHandler(&logs, nil))
	response := perform(handler, http.MethodPost, "/api/v1/code", []byte(`{"type":"totp","credential":"`+testTOTPSecret+`","min_ttl":0}`), string(token))
	if response.Code != http.StatusInternalServerError || errorCode(t, response) != "INTERNAL_ERROR" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	combined := response.Body.String() + logs.String()
	if strings.Contains(combined, testTOTPSecret) || strings.Contains(combined, causeSecret) {
		t.Fatal("credential or raw resolver cause entered response/logs")
	}
}

func TestPanicRecoveryRedactsValueAndReleasesAdmission(t *testing.T) {
	panicSecret := "sensitive-panic-value"
	handler, token, cancel := newTestHandler(t, panicResolver{value: panicSecret}, nil)
	defer cancel()
	var logs strings.Builder
	handler.logger = slog.New(slog.NewTextHandler(&logs, nil))
	response := perform(handler, http.MethodPost, "/api/v1/code", []byte(`{"type":"totp","credential":"`+testTOTPSecret+`","min_ttl":0}`), string(token))
	if response.Code != http.StatusInternalServerError || errorCode(t, response) != "INTERNAL_ERROR" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String()+logs.String(), panicSecret) {
		t.Fatal("panic value entered response or logs")
	}
	if handler.ActiveRequests() != 0 {
		t.Fatal("admission slot leaked after panic")
	}
}

func TestOldAndUIRoutesRemainJSON404(t *testing.T) {
	handler, token, cancel := newTestHandler(t, totp.New(), nil)
	defer cancel()
	for _, path := range []string{"/", "/login", "/docs", "/openapi.json", "/api/v1/sources", "/api/v1/codes/old"} {
		response := perform(handler, http.MethodGet, path, nil, string(token))
		if response.Code != http.StatusNotFound || response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatalf("path=%s status=%d type=%s", path, response.Code, response.Header().Get("Content-Type"))
		}
	}
}

func TestTrustedProxyClientIP(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.10, 127.0.0.1")
	trusted := map[netip.Addr]struct{}{netip.MustParseAddr("127.0.0.1"): {}}
	if got := clientIP(request, trusted); got != "198.51.100.10" {
		t.Fatalf("client IP = %s", got)
	}
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.1")
	if got := clientIP(request, trusted); got != "192.0.2.1" {
		t.Fatalf("untrusted proxy header was accepted: %s", got)
	}
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Forwarded-For", strings.Repeat("198.51.100.1,", 33))
	if got := clientIP(request, trusted); got != "unknown" {
		t.Fatalf("oversized forwarded chain = %s", got)
	}
}

type testTOTPResolver struct{ provider *totp.Generator }

func (r testTOTPResolver) Resolve(ctx context.Context, command *domain.Command) (domain.Result, error) {
	code, err := r.provider.Resolve(ctx, command.Credential, command.MinTTL)
	if err != nil {
		clear(code[:])
		if errors.Is(err, totp.ErrInvalidCredential) || errors.Is(err, totp.ErrInvalidMinTTL) {
			return domain.Result{}, domain.ErrInvalidCodeRequest
		}
		return domain.Result{}, err
	}
	return domain.Result{Code: code}, nil
}

type invalidResultResolver struct{}

func (invalidResultResolver) Resolve(context.Context, *domain.Command) (domain.Result, error) {
	return domain.Result{Code: [6]byte{'1', '2', 'x', '4', '5', '6'}}, nil
}

type captureFlyResolver struct {
	provider domain.Provider
	wait     int
	hasTime  bool
	code     [6]byte
}

func (r *captureFlyResolver) Resolve(_ context.Context, command *domain.Command) (domain.Result, error) {
	r.provider = command.Provider
	r.wait = command.WaitSeconds
	r.hasTime = command.NotBefore != nil
	return domain.Result{Code: r.code}, nil
}

type panicResolver struct{ value string }

func (r panicResolver) Resolve(context.Context, *domain.Command) (domain.Result, error) {
	panic(r.value)
}

type errorResolver struct{ cause error }

func (r errorResolver) Resolve(context.Context, *domain.Command) (domain.Result, error) {
	return domain.Result{}, r.cause
}

type countingBody struct {
	reader    *bytes.Reader
	reads     atomic.Int64
	bytesRead atomic.Int64
}

func newCountingBody(value []byte) *countingBody {
	return &countingBody{reader: bytes.NewReader(value)}
}

func (b *countingBody) Read(value []byte) (int, error) {
	b.reads.Add(1)
	n, err := b.reader.Read(value)
	b.bytesRead.Add(int64(n))
	return n, err
}

func (*countingBody) Close() error { return nil }

type blockingResolver struct {
	entered atomic.Int64
	release chan struct{}
	once    sync.Once
}

func newBlockingResolver() *blockingResolver {
	return &blockingResolver{release: make(chan struct{})}
}

func (r *blockingResolver) Resolve(ctx context.Context, _ *domain.Command) (domain.Result, error) {
	r.entered.Add(1)
	select {
	case <-r.release:
		return domain.Result{Code: [6]byte{'1', '2', '3', '4', '5', '6'}}, nil
	case <-ctx.Done():
		return domain.Result{}, ctx.Err()
	}
}

func (r *blockingResolver) waitEntered(t *testing.T, expected int64) {
	t.Helper()
	waitForHandlerCount(t, r.entered.Load, expected)
}

func (r *blockingResolver) releaseAll() {
	r.once.Do(func() { close(r.release) })
}

func newTestHandler(t *testing.T, resolverInput any, mutate func(*config.Config)) (*Handler, []byte, context.CancelFunc) {
	t.Helper()
	var resolver Resolver
	switch value := resolverInput.(type) {
	case Resolver:
		resolver = value
	case *totp.Generator:
		resolver = testTOTPResolver{provider: value}
	default:
		t.Fatalf("unsupported test resolver %T", resolverInput)
	}
	cfg := config.Default()
	cfg.Server.AllowedHosts = []string{"example.com", "127.0.0.1"}
	if mutate != nil {
		mutate(&cfg)
	}
	token, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "api.sha256")
	if err := secretfile.WriteExclusive(path, hash); err != nil {
		t.Fatal(err)
	}
	clear(hash)
	cfg.Security.APITokenHashFiles = []string{path}
	verifier, err := auth.LoadVerifier(cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewHandler(cfg, verifier, resolver, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	handler.Start(ctx)
	return handler, token, func() {
		cancel()
		clear(token)
	}
}

func perform(handler http.Handler, method, path string, body []byte, token string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	request.Host = "example.com"
	request.RemoteAddr = "192.0.2.10:1234"
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func newAPIRequest(body *countingBody, authorization string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/code", nil)
	request.Host = "example.com"
	request.RemoteAddr = "192.0.2.10:1234"
	request.Body = body
	request.ContentLength = int64(body.reader.Len())
	request.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	return request
}

func errorCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var decoded struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode error response: %v; body=%s", err, response.Body.String())
	}
	return decoded.Error.Code
}

func waitForHandlerCount(t *testing.T, value func() int64, expected int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if value() == expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("count=%d, want=%d", value(), expected)
}

var _ io.ReadCloser = (*countingBody)(nil)
var _ Resolver = (*blockingResolver)(nil)
var _ Resolver = testTOTPResolver{}
var _ Resolver = (*captureFlyResolver)(nil)
var _ Resolver = invalidResultResolver{}
var _ Resolver = errorResolver{}
var _ Resolver = panicResolver{}
