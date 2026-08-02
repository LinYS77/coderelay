package flysms

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/LinYS77/coderelay/internal/config"
)

var errRedirectForbidden = errors.New("FlySMS redirects are forbidden")

func newHTTPClient(server config.ServerConfig) (*http.Client, *http.Transport) {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: duration(server.HTTPConnectTimeoutSeconds), KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      false,
		MaxIdleConns:           server.HTTPMaxConnections,
		MaxIdleConnsPerHost:    server.HTTPMaxConnections,
		MaxConnsPerHost:        server.HTTPMaxConnections,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  duration(server.HTTPReadTimeoutSeconds),
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		Protocols:              protocols,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   0,
		Jar:       nil,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirectForbidden
		},
	}
	return client, transport
}

func duration(seconds float64) time.Duration {
	return time.Duration(seconds * float64(time.Second))
}
