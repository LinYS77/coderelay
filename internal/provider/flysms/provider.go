// Package flysms implements the fixed-host FlySMS mail provider.
package flysms

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/extractor"
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type messageReference struct {
	Mailbox string
	UID     int64
}

type Provider struct {
	settings       config.FlySMSConfig
	baseURL        *url.URL
	client         httpDoer
	transport      *http.Transport
	networkTimeout time.Duration
	fetchTimeout   time.Duration
	maxWait        int
	extractor      *extractor.Extractor
	now            func() time.Time
	sleep          func(context.Context, time.Duration) error
	jitter         func(time.Duration) time.Duration
}

func New(cfg config.Config) (*Provider, error) {
	if cfg.Providers.FlySMS.BaseURL != config.FlySMSBaseURL {
		return nil, errors.New("FlySMS endpoint is not fixed")
	}
	baseURL, err := url.Parse(cfg.Providers.FlySMS.BaseURL)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host != "flysms.xyz" || baseURL.Path != "/icloud/api/pickup/messages" {
		return nil, errors.New("FlySMS endpoint is invalid")
	}
	client, transport := newHTTPClient(cfg.Server)
	return &Provider{
		settings:       cfg.Providers.FlySMS,
		baseURL:        baseURL,
		client:         client,
		transport:      transport,
		networkTimeout: duration(cfg.Server.HTTPReadTimeoutSeconds),
		fetchTimeout:   duration(cfg.Providers.FlySMS.FetchTimeoutSeconds),
		maxWait:        cfg.Server.MaxWaitSeconds,
		extractor:      extractor.New(extractor.DefaultSettings()),
		now:            time.Now,
		sleep:          sleepContext,
		jitter:         boundedJitter,
	}, nil
}

func (p *Provider) Resolve(ctx context.Context, source *credential.Secret, notBefore *time.Time, waitSeconds int) ([6]byte, error) {
	var empty [6]byte
	if p == nil || p.client == nil || p.baseURL == nil || p.extractor == nil || source == nil || ctx == nil || waitSeconds < 0 || waitSeconds > p.maxWait {
		return empty, domain.ErrInvalidCodeRequest
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	parsed, err := ParseCredential(source.Bytes())
	if err != nil {
		return empty, domain.ErrInvalidCodeRequest
	}
	defer parsed.Destroy()

	start := p.now().UTC()
	pollDeadline := start.Add(time.Duration(waitSeconds) * time.Second)
	operationTimeout := p.fetchTimeout + time.Duration(waitSeconds)*time.Second
	operationCtx, cancelOperation := context.WithTimeout(ctx, operationTimeout)
	defer cancelOperation()
	for {
		attemptCtx, cancelAttempt := context.WithTimeout(operationCtx, p.fetchTimeout)
		code, found, attemptErr := p.fetch(attemptCtx, &parsed, notBefore)
		cancelAttempt()
		if found && attemptErr == nil {
			copy(empty[:], code)
			code = ""
			return empty, nil
		}
		code = ""
		if ctx.Err() != nil {
			return empty, ctx.Err()
		}
		if operationCtx.Err() != nil {
			return empty, domain.ErrUpstreamTimeout
		}
		if errors.Is(attemptErr, context.Canceled) {
			return empty, context.Canceled
		}
		if errors.Is(attemptErr, context.DeadlineExceeded) {
			attemptErr = domain.ErrUpstreamTimeout
		}
		if attemptErr != nil && !retryable(attemptErr) {
			return empty, attemptErr
		}

		now := p.now().UTC()
		remaining := pollDeadline.Sub(now)
		if waitSeconds == 0 || remaining <= 0 {
			if attemptErr != nil {
				return empty, attemptErr
			}
			return empty, domain.WithRetryAfter(domain.ErrNoFreshCode, retrySeconds(p.settings.PollIntervalSeconds))
		}
		delay := duration(p.settings.PollIntervalSeconds)
		if retry := domain.RetryAfter(attemptErr); retry > 0 {
			delay = time.Duration(retry) * time.Second
		}
		delay = p.jitter(delay)
		if delay >= remaining {
			if attemptErr != nil {
				return empty, attemptErr
			}
			if err := p.sleep(operationCtx, remaining); err != nil {
				if ctx.Err() != nil {
					return empty, ctx.Err()
				}
				return empty, domain.ErrUpstreamTimeout
			}
			return empty, domain.WithRetryAfter(domain.ErrNoFreshCode, retrySeconds(p.settings.PollIntervalSeconds))
		}
		if err := p.sleep(operationCtx, delay); err != nil {
			if ctx.Err() != nil {
				return empty, ctx.Err()
			}
			return empty, domain.ErrUpstreamTimeout
		}
	}
}

func (p *Provider) fetch(ctx context.Context, credential *Credential, notBefore *time.Time) (string, bool, error) {
	payload, exists, err := p.requestJSON(ctx, credential, endpointLatest, nil)
	if err != nil {
		return "", false, err
	}
	if exists {
		message, err := decodeDetail(payload, credential.Email, nil)
		clearPayload(payload)
		if err != nil {
			p.closeMalformed(err)
			return "", false, err
		}
		code, extractErr := p.extractor.Extract([]extractor.Message{message}, notBefore, p.now().UTC())
		message.Destroy()
		if extractErr != nil {
			return "", false, extractErr
		}
		if code != "" {
			return code, true, nil
		}
	}

	payload, exists, err = p.requestJSON(ctx, credential, endpointHistory, nil)
	if err != nil || !exists {
		clearPayload(payload)
		return "", false, err
	}
	summaries, err := decodeHistory(payload, credential.Email)
	clearPayload(payload)
	if err != nil {
		p.closeMalformed(err)
		return "", false, err
	}
	defer destroyMessages(summaries)
	code, err := p.extractor.Extract(summaries, notBefore, p.now().UTC())
	if err != nil {
		return "", false, err
	}
	if code != "" {
		return code, true, nil
	}

	maximum := p.settings.MaxDetailMessages
	if maximum > len(summaries) {
		maximum = len(summaries)
	}
	for i := 0; i < maximum; i++ {
		reference := messageReference{Mailbox: summaries[i].Mailbox, UID: summaries[i].UID}
		payload, exists, err = p.requestJSON(ctx, credential, endpointDetail, &reference)
		if err != nil {
			clearPayload(payload)
			return "", false, err
		}
		if !exists {
			continue
		}
		detail, err := decodeDetail(payload, credential.Email, &summaries[i])
		clearPayload(payload)
		if err != nil {
			p.closeMalformed(err)
			return "", false, err
		}
		code, extractErr := p.extractor.Extract([]extractor.Message{detail}, notBefore, p.now().UTC())
		detail.Destroy()
		if extractErr != nil {
			return "", false, extractErr
		}
		if code != "" {
			return code, true, nil
		}
	}
	return "", false, nil
}

func (p *Provider) Close() {
	if p != nil && p.transport != nil {
		p.transport.CloseIdleConnections()
	}
}

func (p *Provider) closeMalformed(err error) {
	if errors.Is(err, domain.ErrUpstreamSchemaChanged) && p.transport != nil {
		p.transport.CloseIdleConnections()
	}
}

func retryable(err error) bool {
	return errors.Is(err, domain.ErrSourceRateLimited) ||
		errors.Is(err, domain.ErrSourceSyncing) ||
		errors.Is(err, domain.ErrUpstreamFailure) ||
		errors.Is(err, domain.ErrUpstreamTimeout)
}

func retrySeconds(value float64) int {
	seconds := int(value)
	if float64(seconds) < value {
		seconds++
	}
	return clampRetry(seconds)
}

func boundedJitter(value time.Duration) time.Duration {
	if value <= 0 {
		return value
	}
	var raw [2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return value
	}
	fraction := float64(binary.BigEndian.Uint16(raw[:])) / 65_535
	factor := 0.9 + 0.2*fraction
	return time.Duration(float64(value) * factor)
}

func sleepContext(ctx context.Context, value time.Duration) error {
	timer := time.NewTimer(value)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
