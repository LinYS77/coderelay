package service

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/api"
	"github.com/LinYS77/coderelay/internal/auth"
	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/secretfile"
)

func TestGracefulShutdownWaitsForActiveRequestAndDropsReadiness(t *testing.T) {
	cfg := config.Default()
	cfg.Server.AllowedHosts = []string{"127.0.0.1", "localhost"}
	token, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(token)
	defer clear(hash)
	hashPath := filepath.Join(t.TempDir(), "api.sha256")
	if err := secretfile.WriteExclusive(hashPath, hash); err != nil {
		t.Fatal(err)
	}
	cfg.Security.APITokenHashFiles = []string{hashPath}
	verifier, err := auth.LoadVerifier(cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &shutdownResolver{entered: make(chan struct{}), release: make(chan struct{})}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := api.NewHandler(cfg, verifier, resolver, logger)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer resolver.releaseAll()
	serveDone := make(chan error, 1)
	go func() { serveDone <- serveListener(ctx, cfg, handler, logger, listener) }()
	baseURL := "http://" + listener.Addr().String()
	waitForLive(t, baseURL)

	payload := []byte(`{"type":"totp","credential":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","min_ttl":0}`)
	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/code", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(token))
	responseDone := make(chan int, 1)
	go func() {
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			responseDone <- 0
			return
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		responseDone <- response.StatusCode
	}()
	select {
	case <-resolver.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("active request did not enter resolver")
	}

	cancel()
	waitForNotReady(t, handler)
	select {
	case err := <-serveDone:
		t.Fatalf("server stopped before active request completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	resolver.releaseAll()
	if status := <-responseDone; status != http.StatusOK {
		t.Fatalf("active response status=%d", status)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("graceful shutdown did not complete")
	}
}

type shutdownResolver struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *shutdownResolver) Resolve(ctx context.Context, _ *domain.Command) (domain.Result, error) {
	r.once.Do(func() { close(r.entered) })
	select {
	case <-r.release:
		return domain.Result{Code: [6]byte{'1', '2', '3', '4', '5', '6'}}, nil
	case <-ctx.Done():
		return domain.Result{}, ctx.Err()
	}
}

func (r *shutdownResolver) releaseAll() {
	select {
	case <-r.release:
	default:
		close(r.release)
	}
}

func waitForLive(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(baseURL + "/health/live")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not become live")
}

func waitForNotReady(t *testing.T, handler http.Handler) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
		request.Host = "localhost"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code == http.StatusServiceUnavailable {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("readiness did not drop")
}

var _ api.Resolver = (*shutdownResolver)(nil)
