package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MicrosoftTokenEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	outlookIMAPScope       = "https://outlook.office.com/imap.accessasuser.all"
	maxOAuthResponseBytes  = 1 << 20
	maxAccessTokenBytes    = 128 << 10
)

type OAuthResult struct {
	AccessToken         []byte
	RotatedRefreshToken []byte
	ExpiresInSeconds    int
	ScopeVerified       bool
}

func (r *OAuthResult) Destroy() {
	if r == nil {
		return
	}
	clear(r.AccessToken)
	clear(r.RotatedRefreshToken)
	r.AccessToken = nil
	r.RotatedRefreshToken = nil
}

type OAuthClient struct {
	endpoint  string
	client    *http.Client
	transport *http.Transport
}

func NewMicrosoftOAuthClient() *OAuthClient {
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           2,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &OAuthClient{endpoint: MicrosoftTokenEndpoint, client: client, transport: transport}
}

func newOAuthClientForTest(endpoint string, client *http.Client) *OAuthClient {
	return &OAuthClient{endpoint: endpoint, client: client}
}

func (c *OAuthClient) Close() {
	if c == nil {
		return
	}
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	} else if c.client != nil {
		c.client.CloseIdleConnections()
	}
}

func (c *OAuthClient) Refresh(ctx context.Context, credential *Credential) (*OAuthResult, error) {
	if c == nil || c.client == nil || credential == nil {
		return nil, stageError("oauth", "INVALID_STATE", errors.New("OAuth client is not initialized"))
	}
	form := make([]byte, 0, len(credential.ClientID)+len(credential.RefreshToken)+64)
	form = appendFormField(form, "client_id", credential.ClientID, false)
	form = appendFormField(form, "grant_type", []byte("refresh_token"), true)
	form = appendFormField(form, "refresh_token", credential.RefreshToken, true)
	defer clear(form)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(form))
	if err != nil {
		return nil, stageError("oauth", "REQUEST_BUILD_FAILED", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "CodeRelay-Outlook-Phase0/0.1")

	resp, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, stageError("oauth", "CANCELED_OR_TIMEOUT", ctx.Err())
		}
		return nil, stageError("oauth", "REQUEST_FAILED", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseBytes+1))
	if err != nil {
		return nil, stageError("oauth", "RESPONSE_READ_FAILED", err)
	}
	defer clear(body)
	if len(body) > maxOAuthResponseBytes {
		return nil, stageError("oauth", "RESPONSE_TOO_LARGE", errors.New("OAuth response exceeds limit"))
	}

	var payload struct {
		AccessToken  string          `json:"access_token"`
		RefreshToken string          `json:"refresh_token"`
		ExpiresIn    json.RawMessage `json:"expires_in"`
		Scope        string          `json:"scope"`
		Error        string          `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, stageError("oauth", "INVALID_JSON", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code := "HTTP_FAILURE"
		switch payload.Error {
		case "invalid_grant", "interaction_required", "consent_required", "login_required":
			code = "REAUTH_REQUIRED"
		}
		return nil, stageError("oauth", code, errors.New("Microsoft token endpoint rejected the request"))
	}
	if !validAccessToken(payload.AccessToken) {
		return nil, stageError("oauth", "INVALID_ACCESS_TOKEN", errors.New("OAuth response access token is invalid"))
	}
	if payload.Scope != "" && !hasScope(payload.Scope, outlookIMAPScope) {
		return nil, stageError("oauth", "IMAP_SCOPE_MISSING", errors.New("OAuth response does not include Outlook IMAP scope"))
	}

	expires := 3600
	if len(payload.ExpiresIn) > 0 && string(payload.ExpiresIn) != "null" {
		var number json.Number
		if err := json.Unmarshal(payload.ExpiresIn, &number); err == nil {
			if parsed, err := strconv.Atoi(number.String()); err == nil {
				expires = parsed
			}
		}
	}
	if expires < 60 {
		expires = 60
	} else if expires > 86_400 {
		expires = 86_400
	}

	result := &OAuthResult{
		AccessToken:      []byte(payload.AccessToken),
		ExpiresInSeconds: expires,
		ScopeVerified:    payload.Scope == "" || hasScope(payload.Scope, outlookIMAPScope),
	}
	payload.AccessToken = ""
	if payload.RefreshToken != "" && !bytes.Equal([]byte(payload.RefreshToken), credential.RefreshToken) {
		rotated := []byte(payload.RefreshToken)
		if err := validateRefreshToken(rotated); err != nil {
			clear(rotated)
			result.Destroy()
			return nil, stageError("oauth", "INVALID_ROTATED_TOKEN", err)
		}
		result.RotatedRefreshToken = rotated
	}
	payload.RefreshToken = ""
	return result, nil
}

func validAccessToken(token string) bool {
	if token == "" || len(token) > maxAccessTokenBytes || !utf8.ValidString(token) {
		return false
	}
	for _, r := range token {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func hasScope(scopeList, expected string) bool {
	for _, scope := range strings.Fields(scopeList) {
		if strings.EqualFold(scope, expected) {
			return true
		}
	}
	return false
}

func appendFormField(dst []byte, key string, value []byte, separator bool) []byte {
	if separator {
		dst = append(dst, '&')
	}
	dst = append(dst, key...)
	dst = append(dst, '=')
	for _, b := range value {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '-', b == '_', b == '.', b == '~':
			dst = append(dst, b)
		case b == ' ':
			dst = append(dst, '+')
		default:
			const hex = "0123456789ABCDEF"
			dst = append(dst, '%', hex[b>>4], hex[b&15])
		}
	}
	return dst
}
