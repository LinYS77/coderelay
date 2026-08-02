package flysms

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/version"
)

const (
	latestResponseLimit  = 3 << 20
	detailResponseLimit  = 3 << 20
	historyResponseLimit = 1 << 20
)

type endpointKind uint8

const (
	endpointLatest endpointKind = iota
	endpointHistory
	endpointDetail
)

func (p *Provider) requestJSON(ctx context.Context, credential *Credential, kind endpointKind, message *messageReference) ([]byte, bool, error) {
	requestURL := *p.baseURL
	query := make(url.Values)
	maximum := int64(latestResponseLimit)
	switch kind {
	case endpointLatest:
		requestURL.Path += "/latest"
	case endpointHistory:
		maximum = historyResponseLimit
		query.Set("limit", strconv.Itoa(p.settings.HistoryLimit))
	case endpointDetail:
		if message == nil || message.UID < 1 {
			return nil, false, domain.ErrUpstreamSchemaChanged
		}
		maximum = detailResponseLimit
		requestURL.Path += "/" + strconv.FormatInt(message.UID, 10)
		query.Set("mailbox", message.Mailbox)
	default:
		return nil, false, domain.ErrUpstreamFailure
	}
	requestURL.RawQuery = query.Encode()
	requestCtx, cancel := context.WithTimeout(ctx, p.networkTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, false, domain.ErrUpstreamFailure
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "CodeRelay/"+version.Value)
	request.Header.Set("X-Mailbox-Email", credential.Email)
	authorization := make([]byte, 0, len("Bearer ")+len(credential.Token))
	authorization = append(authorization, "Bearer "...)
	authorization = append(authorization, credential.Token...)
	request.Header.Set("Authorization", string(authorization))
	clear(authorization)

	response, err := p.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		if requestCtx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
			return nil, false, domain.ErrUpstreamTimeout
		}
		return nil, false, domain.ErrUpstreamFailure
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusUnauthorized:
		return nil, false, domain.ErrSourceCredentials
	case http.StatusForbidden:
		return nil, false, domain.ErrSourceExpired
	case http.StatusNotFound:
		return nil, false, nil
	case http.StatusTooManyRequests:
		return nil, false, domain.WithRetryAfter(domain.ErrSourceRateLimited, parseRetryAfter(response.Header.Get("Retry-After"), 60, p.now()))
	case http.StatusServiceUnavailable:
		return nil, false, domain.WithRetryAfter(domain.ErrSourceSyncing, parseRetryAfter(response.Header.Get("Retry-After"), 2, p.now()))
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, false, domain.ErrUpstreamFailure
	}
	if response.ContentLength > maximum {
		return nil, false, domain.ErrUpstreamSchemaChanged
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		clear(payload)
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		if requestCtx.Err() != nil {
			return nil, false, domain.ErrUpstreamTimeout
		}
		return nil, false, domain.ErrUpstreamFailure
	}
	if int64(len(payload)) > maximum {
		clear(payload)
		return nil, false, domain.ErrUpstreamSchemaChanged
	}
	return payload, true, nil
}

func parseRetryAfter(value string, fallback int, now time.Time) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return clampRetry(fallback)
	}
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil {
		return clampRetry(int(seconds))
	}
	if target, err := http.ParseTime(value); err == nil {
		seconds := int(math.Ceil(target.Sub(now).Seconds()))
		return clampRetry(seconds)
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

func clearPayload(payload []byte) {
	clear(payload)
}
