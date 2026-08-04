package outlook

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/domain"
)

const (
	imapScope              = "https://outlook.office.com/IMAP.AccessAsUser.All"
	maxOAuthBodyBytes      = 1 << 20
	maxAccessTokenSize     = 128 << 10
	stageOutlookOAuth      = "outlook_oauth_token"
	stageOutlookOAuthScope = "outlook_oauth_scope"
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
	endpoint       string
	client         *http.Client
	transport      *http.Transport
	networkTimeout time.Duration
}

func NewOAuthClient(server config.ServerConfig, settings config.OutlookConfig) (*OAuthClient, error) {
	if settings.TokenURL != config.OutlookTokenURL {
		return nil, errors.New("outlook token endpoint is not fixed")
	}
	connectTimeout := duration(server.HTTPConnectTimeoutSeconds)
	if connectTimeout <= 0 {
		connectTimeout = 5 * time.Second
	}
	readTimeout := duration(server.HTTPReadTimeoutSeconds)
	if readTimeout <= 0 {
		readTimeout = 20 * time.Second
	}
	maxConnections := server.HTTPMaxConnections
	if maxConnections <= 0 {
		maxConnections = 20
	}
	if maxConnections > 100 {
		return nil, errors.New("outlook HTTP connection limit is invalid")
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           maxConnections,
		MaxIdleConnsPerHost:    maxConnections,
		MaxConnsPerHost:        maxConnections,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  readTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		Protocols:              protocols,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   0,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("outlook redirects are forbidden")
		},
	}
	return &OAuthClient{endpoint: settings.TokenURL, client: client, transport: transport, networkTimeout: readTimeout}, nil
}

func newOAuthClientForTest(endpoint string, client *http.Client, timeouts ...time.Duration) *OAuthClient {
	timeout := 30 * time.Second
	if len(timeouts) > 0 {
		timeout = timeouts[0]
	}
	if client != nil && client.CheckRedirect == nil {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return errors.New("outlook redirects are forbidden")
		}
	}
	return &OAuthClient{endpoint: endpoint, client: client, networkTimeout: timeout}
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
	if c == nil || c.client == nil || credential == nil || ctx == nil {
		return nil, domain.ErrUpstreamFailure
	}
	form := make([]byte, 0, len(credential.ClientID)+len(credential.RefreshToken)+len(imapScope)+80)
	form = appendFormField(form, "client_id", credential.ClientID, false)
	// Refresh tokens can cover multiple resources. Select the fixed Outlook
	// IMAP resource explicitly instead of relying on the token's default scope.
	form = appendFormField(form, "scope", []byte(imapScope), true)
	form = appendFormField(form, "grant_type", []byte("refresh_token"), true)
	form = appendFormField(form, "refresh_token", credential.RefreshToken, true)
	defer clear(form)
	timeout := c.networkTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	requestBody := io.NopCloser(bytes.NewReader(form))
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.endpoint, requestBody)
	if err != nil {
		return nil, domain.ErrUpstreamFailure
	}
	request.ContentLength = int64(len(form))
	request.GetBody = nil
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", "CodeRelay-Outlook/1.0.0-phase5.2")
	response, err := c.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if requestCtx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
			return nil, domain.ErrUpstreamTimeout
		}
		return nil, domain.ErrUpstreamFailure
	}
	defer response.Body.Close()
	if response.ContentLength > maxOAuthBodyBytes {
		return nil, domain.ErrUpstreamSchemaChanged
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxOAuthBodyBytes+1))
	if err != nil {
		clear(body)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if requestCtx.Err() != nil {
			return nil, domain.ErrUpstreamTimeout
		}
		return nil, domain.ErrUpstreamFailure
	}
	defer clear(body)
	if len(body) > maxOAuthBodyBytes || !utf8.Valid(body) {
		return nil, domain.ErrUpstreamSchemaChanged
	}
	payload, decodeErr := decodeOAuthObject(body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if decodeErr == nil {
			defer clearOAuthFields(payload)
		}
		return nil, mapOAuthHTTPError(response.StatusCode, payload, response.Header.Get("Retry-After"), credential.RefreshToken)
	}
	if decodeErr != nil {
		return nil, domain.ErrUpstreamSchemaChanged
	}
	defer clearOAuthFields(payload)
	accessToken, ok := requiredString(payload, "access_token", maxAccessTokenSize)
	if !ok || !validAccessToken(accessToken) {
		return nil, domain.ErrUpstreamSchemaChanged
	}
	scopeVerified := true
	if scope, exists := payload["scope"]; exists {
		value, ok := rawString(scope)
		if !ok {
			return nil, domain.ErrUpstreamSchemaChanged
		}
		if value != "" && !hasScope(value, imapScope) {
			return nil, domain.WithSourceStage(domain.ErrSourceReauthRequired, stageOutlookOAuthScope)
		}
		scopeVerified = true
	}
	expires, expiresOK := parseExpires(payload["expires_in"])
	if !expiresOK {
		return nil, domain.ErrUpstreamSchemaChanged
	}
	result := &OAuthResult{AccessToken: []byte(accessToken), ExpiresInSeconds: expires, ScopeVerified: scopeVerified}
	if rotated, exists := payload["refresh_token"]; exists {
		value, ok := rawString(rotated)
		if !ok {
			result.Destroy()
			return nil, domain.ErrUpstreamSchemaChanged
		}
		if value != "" {
			candidate := []byte(value)
			if err := validateRefreshToken(candidate); err != nil {
				clear(candidate)
				result.Destroy()
				return nil, domain.ErrUpstreamSchemaChanged
			}
			if replacement, changed := differentRefreshToken(candidate, credential.RefreshToken); changed {
				result.RotatedRefreshToken = replacement
				candidate = nil
			}
			clear(candidate)
		}
	}
	return result, nil
}

func decodeOAuthObject(body []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("OAuth response is not an object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			clearOAuthFields(fields)
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			clearOAuthFields(fields)
			return nil, errors.New("OAuth response key is invalid")
		}
		if _, exists := fields[key]; exists {
			clearOAuthFields(fields)
			return nil, errors.New("OAuth response contains duplicate key")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			clear(value)
			clearOAuthFields(fields)
			return nil, err
		}
		fields[key] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		clearOAuthFields(fields)
		return nil, errors.New("OAuth response is not closed")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		clearOAuthFields(fields)
		return nil, errors.New("OAuth response has trailing data")
	}
	return fields, nil
}

func clearOAuthFields(fields map[string]json.RawMessage) {
	for key, value := range fields {
		clear(value)
		delete(fields, key)
	}
}

func rawString(raw json.RawMessage) (string, bool) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

func mapOAuthHTTPError(status int, fields map[string]json.RawMessage, retryAfter string, oldToken []byte) error {
	var mapped error
	switch {
	case status == http.StatusTooManyRequests:
		mapped = domain.WithRetryAfter(domain.ErrSourceRateLimited, parseRetryAfterOutlook(retryAfter, 5, time.Now().UTC()))
	case status == http.StatusBadRequest:
		switch optionalString(fields, "error") {
		case "invalid_grant", "interaction_required", "consent_required", "login_required", "invalid_scope":
			mapped = domain.ErrSourceReauthRequired
		default:
			mapped = domain.ErrSourceCredentials
		}
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		mapped = domain.ErrSourceCredentials
	default:
		mapped = domain.ErrUpstreamFailure
	}
	mapped = domain.WithSourceStage(mapped, stageOutlookOAuth)
	if fields == nil {
		return mapped
	}
	return oauthErrorWithRotation(mapped, fields, oldToken)
}

func optionalString(fields map[string]json.RawMessage, key string) string {
	if raw, ok := fields[key]; ok {
		value, _ := rawString(raw)
		return value
	}
	return ""
}

func oauthErrorWithRotation(err error, fields map[string]json.RawMessage, oldToken []byte) error {
	candidate, changed := refreshTokenCandidate(fields, oldToken)
	if !changed {
		return err
	}
	wrapped := domain.WithCredentialUpdate(err, candidate)
	clear(candidate)
	return wrapped
}

func refreshTokenCandidate(fields map[string]json.RawMessage, oldToken []byte) ([]byte, bool) {
	raw, ok := fields["refresh_token"]
	if !ok {
		return nil, false
	}
	value, ok := rawString(raw)
	if !ok || value == "" {
		return nil, false
	}
	candidate := []byte(value)
	if validateRefreshToken(candidate) != nil {
		clear(candidate)
		return nil, false
	}
	return differentRefreshToken(candidate, oldToken)
}

func differentRefreshToken(candidate, oldToken []byte) ([]byte, bool) {
	oldHash := sha256.Sum256(oldToken)
	newHash := sha256.Sum256(candidate)
	same := subtle.ConstantTimeCompare(oldHash[:], newHash[:])
	clear(oldHash[:])
	clear(newHash[:])
	if same == 1 {
		clear(candidate)
		return nil, false
	}
	return candidate, true
}

func requiredString(fields map[string]json.RawMessage, key string, maximum int) (string, bool) {
	raw, ok := fields[key]
	if !ok {
		return "", false
	}
	value, ok := rawString(raw)
	return value, ok && utf8.RuneCountInString(value) <= maximum
}

func validAccessToken(value string) bool {
	if value == "" || len(value) > maxAccessTokenSize || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func hasScope(value, expected string) bool {
	for _, item := range strings.Fields(value) {
		if strings.EqualFold(item, expected) {
			return true
		}
	}
	return false
}

func parseExpires(raw json.RawMessage) (int, bool) {
	result := 3_600
	if len(raw) == 0 {
		return result, true
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '-' && (trimmed[0] < '0' || trimmed[0] > '9') {
		return 0, false
	}
	parsed, err := strconv.ParseInt(string(trimmed), 10, 64)
	if err != nil {
		return 0, false
	}
	if parsed < 60 {
		return 60, true
	}
	if parsed > 86_400 {
		return 86_400, true
	}
	return int(parsed), true
}

func appendFormField(dst []byte, key string, value []byte, separator bool) []byte {
	if separator {
		dst = append(dst, '&')
	}
	dst = append(dst, key...)
	dst = append(dst, '=')
	const hex = "0123456789ABCDEF"
	for _, b := range value {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.' || b == '~' {
			dst = append(dst, b)
		} else if b == ' ' {
			dst = append(dst, '+')
		} else {
			dst = append(dst, '%', hex[b>>4], hex[b&15])
		}
	}
	return dst
}

func duration(seconds float64) time.Duration { return time.Duration(seconds * float64(time.Second)) }

func parseRetryAfterOutlook(value string, fallback int, now time.Time) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return clampRetry(fallback)
	}
	if parsed, err := strconv.Atoi(value); err == nil {
		return clampRetry(parsed)
	}
	if target, err := http.ParseTime(value); err == nil {
		return clampRetry(int(math.Ceil(target.Sub(now).Seconds())))
	}
	return clampRetry(fallback)
}

func clampRetry(value int) int {
	if value < 1 {
		return 1
	}
	if value > 300 {
		return 300
	}
	return value
}
