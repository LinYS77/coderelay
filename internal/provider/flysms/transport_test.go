package flysms

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/domain"
)

func TestTransportIsHTTP1OnlyCookieFreeAndReusable(t *testing.T) {
	var connections atomic.Int64
	var requests atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.ProtoMajor != 1 {
			t.Errorf("negotiated protocol = %s", request.Proto)
		}
		if request.Header.Get("Cookie") != "" {
			t.Error("cookie leaked into a later FlySMS request")
		}
		writer.Header().Set("Set-Cookie", "identity=must-not-persist; Secure")
		_, _ = writer.Write([]byte(`{"email":"box@example.com"}`))
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	cfg := config.Default()
	client, transport := newHTTPClient(cfg.Server)
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // #nosec G402 -- test server certificate
	defer transport.CloseIdleConnections()
	baseURL, err := url.Parse(server.URL + "/icloud/api/pickup/messages")
	if err != nil {
		t.Fatal(err)
	}
	provider := testProvider(time.Now().UTC(), client)
	provider.baseURL = baseURL
	provider.transport = transport
	credential := Credential{Email: "box@example.com", Token: []byte("tok_1234567890123456")}
	defer credential.Destroy()
	for i := 0; i < 2; i++ {
		payload, exists, err := provider.requestJSON(context.Background(), &credential, endpointLatest, nil)
		clearPayload(payload)
		if err != nil || !exists {
			t.Fatalf("request %d exists=%v error=%v", i, exists, err)
		}
	}
	if requests.Load() != 2 || connections.Load() != 1 {
		t.Fatalf("requests=%d connections=%d", requests.Load(), connections.Load())
	}
	if client.Jar != nil || transport.Proxy != nil || transport.Protocols == nil || !transport.Protocols.HTTP1() || transport.Protocols.HTTP2() {
		t.Fatal("FlySMS transport isolation or protocol policy is invalid")
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var destinationHits atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		destinationHits.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL+"/credential-target", http.StatusFound)
	}))
	defer source.Close()
	cfg := config.Default()
	client, transport := newHTTPClient(cfg.Server)
	defer transport.CloseIdleConnections()
	baseURL, err := url.Parse(source.URL + "/icloud/api/pickup/messages")
	if err != nil {
		t.Fatal(err)
	}
	provider := testProvider(time.Now().UTC(), client)
	provider.baseURL = baseURL
	credential := Credential{Email: "box@example.com", Token: []byte("tok_1234567890123456")}
	defer credential.Destroy()
	payload, _, err := provider.requestJSON(context.Background(), &credential, endpointLatest, nil)
	clearPayload(payload)
	if !errors.Is(err, domain.ErrUpstreamFailure) || destinationHits.Load() != 0 {
		t.Fatalf("error=%v destination_hits=%d", err, destinationHits.Load())
	}
}

func TestEachProviderOwnsAnIndependentTransport(t *testing.T) {
	cfg := config.Default()
	firstClient, first := newHTTPClient(cfg.Server)
	secondClient, second := newHTTPClient(cfg.Server)
	defer first.CloseIdleConnections()
	defer second.CloseIdleConnections()
	if first == second || firstClient.Transport == secondClient.Transport || firstClient.Jar != nil || secondClient.Jar != nil {
		t.Fatal("FlySMS transports are not independent and cookie-free")
	}
}
