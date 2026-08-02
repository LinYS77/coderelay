package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	testClientID     = "11111111-2222-4333-8444-555555555555"
	testRefreshToken = "M." + "a" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testRotatedToken = "M." + "b" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestPhase0MockOAuthAndIMAPFlow(t *testing.T) {
	mockIMAP := startMockIMAPServer(t, false)
	credential := &Credential{
		Email:        []byte("user@example.com"),
		ClientID:     []byte(testClientID),
		RefreshToken: []byte(testRefreshToken),
	}
	defer credential.Destroy()

	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		if got := request.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %q", got)
		}
		if err := request.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		assertFormValue(t, request.Form, "client_id", testClientID)
		assertFormValue(t, request.Form, "grant_type", "refresh_token")
		assertFormValue(t, request.Form, "refresh_token", testRefreshToken)
		if _, ok := request.Form["scope"]; ok {
			t.Error("OAuth request unexpectedly contains scope")
		}
		if _, ok := request.Form["password"]; ok {
			t.Error("OAuth request unexpectedly contains password")
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"access_token":  string(mockIMAP.tracker.token),
			"refresh_token": testRotatedToken,
			"expires_in":    3600,
			"scope":         "https://outlook.office.com/IMAP.AccessAsUser.All",
		})
	}))
	defer tokenServer.Close()
	oauthHTTPClient := tokenServer.Client()
	oauthHTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	oauth := newOAuthClientForTest(tokenServer.URL, oauthHTTPClient)
	defer oauth.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	token, err := oauth.Refresh(ctx, credential)
	if err != nil {
		t.Fatalf("OAuth refresh failed: %v", err)
	}
	defer token.Destroy()
	if !token.ScopeVerified {
		t.Fatal("scope was not verified")
	}
	if string(token.RotatedRefreshToken) != testRotatedToken {
		t.Fatal("rotated token was not retained")
	}

	report, err := ProbeIMAP(ctx, mockIMAP.config, credential.Email, token.AccessToken, 2)
	if err != nil {
		t.Fatalf("IMAP probe failed: %v", err)
	}
	mockIMAP.waitForNoSessions(t)

	if report.TLSVersion != "TLS1.3" {
		t.Errorf("TLS version = %q, want TLS1.3", report.TLSVersion)
	}
	if !report.XOAUTH2 || !report.ReadOnlySelectRequested {
		t.Fatalf("authentication/read-only report = %+v", report)
	}
	if report.NumMessages != 2 {
		t.Errorf("NumMessages = %d, want 2", report.NumMessages)
	}
	if report.SessionCount != 1 || report.NoopCount != 1 {
		t.Errorf("session/noop = %d/%d, want 1/1", report.SessionCount, report.NoopCount)
	}
	if report.BodyFetchCommands != 2 || !report.SingleBatchPerCycle {
		t.Errorf("body fetch report = %d/%v", report.BodyFetchCommands, report.SingleBatchPerCycle)
	}
	if !report.SeenPreserved || report.SeenChecked != 2 {
		t.Errorf("seen report = preserved:%v checked:%d", report.SeenPreserved, report.SeenChecked)
	}
	if len(report.Cycles) != 2 {
		t.Fatalf("cycles = %d, want 2", len(report.Cycles))
	}
	for _, cycle := range report.Cycles {
		if cycle.SequenceRange != "1:2" || len(cycle.Messages) != 2 {
			t.Fatalf("unexpected cycle: %+v", cycle)
		}
		for _, message := range cycle.Messages {
			if message.UID == "" || message.InternalDate == "" || message.LiteralBytes == 0 || !message.MIME.Parsed {
				t.Fatalf("incomplete message report: %+v", message)
			}
		}
	}
	firstMIME := report.Cycles[0].Messages[0].MIME
	if firstMIME.PlainBytes == 0 || firstMIME.HTMLBytes == 0 || firstMIME.AttachmentCount != 1 {
		t.Fatalf("multipart MIME was not parsed as expected: %+v", firstMIME)
	}
	if mockIMAP.tracker.totalSessions.Load() != 1 {
		t.Errorf("total sessions = %d, want 1", mockIMAP.tracker.totalSessions.Load())
	}
	if mockIMAP.tracker.bodyFetchCalls.Load() != 2 {
		t.Errorf("body FETCH calls = %d, want 2", mockIMAP.tracker.bodyFetchCalls.Load())
	}
	if mockIMAP.tracker.readonlySelects.Load() != 1 || mockIMAP.tracker.violations.Load() != 0 {
		t.Errorf("readonly/violations = %d/%d", mockIMAP.tracker.readonlySelects.Load(), mockIMAP.tracker.violations.Load())
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal safe report: %v", err)
	}
	for _, forbidden := range [][]byte{
		credential.Email,
		credential.RefreshToken,
		token.AccessToken,
		token.RotatedRefreshToken,
		[]byte("654321"),
		[]byte("Attachment must be ignored"),
	} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatal("safe report contains sensitive test data")
		}
	}
	if options := imapOptions(); options.DebugWriter != nil {
		t.Fatal("imapclient DebugWriter must remain nil")
	}
}

func TestContextCancellationClosesBlockedFetch(t *testing.T) {
	mockIMAP := startMockIMAPServer(t, true)
	defer mockIMAP.tracker.releaseBlockedFetch()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := make(chan error, 1)
	go func() {
		_, err := ProbeIMAP(ctx, mockIMAP.config, mockIMAP.tracker.email, mockIMAP.tracker.token, 2)
		result <- err
	}()

	select {
	case <-mockIMAP.tracker.fetchStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked FETCH did not start")
	}
	started := time.Now()
	cancel()
	select {
	case err := <-result:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("cancellation took %s, want <=1s", elapsed)
		} else {
			t.Logf("blocked FETCH cancellation latency: %s", elapsed)
		}
		mockIMAP.tracker.releaseBlockedFetch()
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt blocked FETCH")
	}
	mockIMAP.waitForNoSessions(t)
}

func TestOversizedLiteralAbortsSession(t *testing.T) {
	mockIMAP := startMockIMAPServer(t, false)
	mockIMAP.tracker.oversizeBody = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := ProbeIMAP(ctx, mockIMAP.config, mockIMAP.tracker.email, mockIMAP.tracker.token, 2)
	if err == nil {
		t.Fatal("oversized literal unexpectedly succeeded")
	}
	stage, code := SafeErrorFields(err)
	if stage != "imap_fetch" || code != "COMMAND_FAILED" {
		t.Fatalf("oversized literal error = %s/%s", stage, code)
	}
	mockIMAP.waitForNoSessions(t)
}

func TestOneHundredConnectionsDoNotLeakGoroutinesOrFDs(t *testing.T) {
	if testing.Short() {
		t.Skip("resource gate skipped in short mode")
	}
	mockIMAP := startMockIMAPServer(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Warm up certificate parsing and the IMAP server/client goroutines before
	// taking the resource baseline.
	if err := SmokeIMAP(ctx, mockIMAP.config, mockIMAP.tracker.email, mockIMAP.tracker.token); err != nil {
		t.Fatalf("warm-up session failed: %v", err)
	}
	mockIMAP.waitForNoSessions(t)

	report, err := RunLeakCheck(ctx, 100, 0, func(iterationCtx context.Context) error {
		return SmokeIMAP(iterationCtx, mockIMAP.config, mockIMAP.tracker.email, mockIMAP.tracker.token)
	})
	if err != nil {
		t.Fatalf("resource loop failed: %v", err)
	}
	mockIMAP.waitForNoSessions(t)
	if !report.Supported {
		t.Skip("/proc/self/fd is unavailable")
	}
	if !report.Passed || report.Completed != 100 {
		t.Fatalf("resource gate failed: %+v", report)
	}
	t.Logf(
		"resource gate: iterations=%d goroutines=%d->%d (delta=%d) fds=%d->%d (delta=%d)",
		report.Iterations,
		report.Before.Goroutines,
		report.After.Goroutines,
		report.GoroutineDelta,
		report.Before.OpenFDs,
		report.After.OpenFDs,
		report.FDDelta,
	)
	if mockIMAP.tracker.violations.Load() != 0 {
		t.Fatalf("protocol violations = %d", mockIMAP.tracker.violations.Load())
	}
}

func TestLeakReportRetainsFailureIteration(t *testing.T) {
	calls := 0
	report, err := RunLeakCheck(context.Background(), 10, 0, func(context.Context) error {
		if calls == 4 {
			return errors.New("synthetic safe failure")
		}
		calls++
		return nil
	})
	if err == nil {
		t.Fatal("synthetic operation unexpectedly succeeded")
	}
	if report.Completed != 4 || report.Passed {
		t.Fatalf("failure progress was not retained: %+v", report)
	}
}

func TestOAuthResponseLimitAndFormEncoding(t *testing.T) {
	credential := &Credential{
		Email:        []byte("user@example.com"),
		ClientID:     []byte(testClientID),
		RefreshToken: []byte(testRefreshToken),
	}
	defer credential.Destroy()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(bytes.Repeat([]byte{'x'}, maxOAuthResponseBytes+1))
	}))
	defer server.Close()
	oauth := newOAuthClientForTest(server.URL, server.Client())
	defer oauth.Close()
	_, err := oauth.Refresh(context.Background(), credential)
	if err == nil {
		t.Fatal("oversized OAuth response unexpectedly succeeded")
	}
	stage, code := SafeErrorFields(err)
	if stage != "oauth" || code != "RESPONSE_TOO_LARGE" {
		t.Fatalf("oversized OAuth error = %s/%s", stage, code)
	}

	special := []byte("M.a b+c/d?e&f=g!h~i")
	encoded := appendFormField(nil, "refresh_token", special, false)
	parsed, err := url.ParseQuery(string(encoded))
	if err != nil {
		t.Fatalf("parse encoded form: %v", err)
	}
	if parsed.Get("refresh_token") != string(special) {
		t.Fatal("form encoder changed refresh token bytes")
	}
	clear(encoded)
	clear(special)
}

func TestCredentialParserDropsPasswordAndAtomicRotationFile(t *testing.T) {
	raw := []byte("User@Example.com----  compatibility-password  ----" + testClientID + "----" + testRefreshToken + "\n")
	credential, err := ParseCredential(raw)
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	if bytes.Contains(raw, []byte("compatibility-password")) {
		t.Fatal("compatibility password was not cleared from the caller buffer")
	}
	defer credential.Destroy()
	if string(credential.Email) != "user@example.com" || string(credential.ClientID) != testClientID {
		t.Fatalf("normalized non-secret fields are wrong")
	}
	if strings.Contains(string(credential.RefreshToken), "compatibility-password") {
		t.Fatal("password leaked into credential model")
	}

	path := t.TempDir() + "/rotation.secret"
	if err := ValidateSecretOutputPath(path); err != nil {
		t.Fatalf("preflight rotation output: %v", err)
	}
	if err := WriteSecretAtomic(path, []byte(testRotatedToken)); err != nil {
		t.Fatalf("write rotation: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat rotation: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("rotation mode = %o, want 600", info.Mode().Perm())
	}
}

func assertFormValue(t *testing.T, form url.Values, key, expected string) {
	t.Helper()
	values := form[key]
	if len(values) != 1 || values[0] != expected {
		t.Errorf("form field %s did not match expected value", key)
	}
}
