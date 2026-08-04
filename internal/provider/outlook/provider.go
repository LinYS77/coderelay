package outlook

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/extractor"
)

const (
	outlookAttemptTimeout = 30 * time.Second
	stageOutlookIMAPAuth  = "outlook_imap_auth"
)

type Provider struct {
	settings     config.OutlookConfig
	oauth        *OAuthClient
	graph        *graphClient
	extractor    *extractor.Extractor
	maxWait      int
	now          func() time.Time
	sleep        func(context.Context, time.Duration) error
	jitter       func(time.Duration) time.Duration
	mu           sync.Mutex
	sessions     map[*imapSession]struct{}
	closed       bool
	openOverride func(context.Context, *Credential, []byte) (*imapSession, error)
	lifecycle    context.Context
	cancelLife   context.CancelFunc
	closeOnce    sync.Once
}

func New(cfg config.Config) (*Provider, error) {
	if cfg.Providers.Outlook.IMAPHost != config.OutlookIMAPHost || cfg.Providers.Outlook.IMAPPort != config.OutlookIMAPPort {
		return nil, errors.New("outlook IMAP endpoint is not fixed")
	}
	settings := cfg.Providers.Outlook
	if settings.IMAPTimeoutSeconds < 3 || settings.IMAPTimeoutSeconds > 60 || settings.PollIntervalSeconds < 1 || settings.PollIntervalSeconds > 10 || settings.MaxMessages < 1 || settings.MaxMessages > 50 || settings.MaxMessageBytes < 32<<10 || settings.MaxMessageBytes > 1<<20 {
		return nil, errors.New("outlook provider limits are invalid")
	}
	codeExtractor, err := extractor.New(extractorSettings(settings.Extractor))
	if err != nil {
		return nil, err
	}
	oauth, err := NewOAuthClient(cfg.Server, settings)
	if err != nil {
		return nil, err
	}
	lifecycle, cancelLife := context.WithCancel(context.Background())
	return &Provider{
		settings:   settings,
		oauth:      oauth,
		graph:      newGraphClient(graphBaseURL, oauth.client, oauth.networkTimeout),
		extractor:  codeExtractor,
		maxWait:    cfg.Server.MaxWaitSeconds,
		now:        time.Now,
		sleep:      sleepContext,
		jitter:     boundedJitter,
		sessions:   make(map[*imapSession]struct{}),
		lifecycle:  lifecycle,
		cancelLife: cancelLife,
	}, nil
}

func newProviderForTest(settings config.OutlookConfig, oauth *OAuthClient) *Provider {
	lifecycle, cancelLife := context.WithCancel(context.Background())
	return &Provider{
		settings:   settings,
		oauth:      oauth,
		extractor:  mustDefaultExtractor(),
		maxWait:    30,
		now:        time.Now,
		sleep:      sleepContext,
		jitter:     func(value time.Duration) time.Duration { return value },
		sessions:   make(map[*imapSession]struct{}),
		lifecycle:  lifecycle,
		cancelLife: cancelLife,
	}
}

func extractorSettings(value config.ExtractorConfig) extractor.Settings {
	return extractor.Settings{
		Senders:                value.Senders,
		SenderDomains:          value.SenderDomains,
		SubjectKeywords:        value.SubjectKeywords,
		Patterns:               value.Patterns,
		MaxAge:                 time.Duration(value.MaxAgeSeconds) * time.Second,
		MaxTextChars:           value.MaxTextChars,
		AllowGenericFallback:   value.AllowGenericFallback,
		GenericRequiresKeyword: value.GenericRequiresKeyword,
	}
}

func mustDefaultExtractor() *extractor.Extractor {
	result, err := extractor.New(extractor.DefaultSettings())
	if err != nil {
		panic("invalid default extractor settings")
	}
	return result
}

func (p *Provider) Resolve(ctx context.Context, request domain.OutlookRequest) ([6]byte, *domain.CredentialUpdate, error) {
	mailAccess := request.MailAccess
	if mailAccess == "" {
		mailAccess = domain.OutlookMailAccessIMAP
	}
	if mailAccess == domain.OutlookMailAccessGraph {
		return p.resolveGraph(ctx, request.Credential, request.NotBefore, request.WaitSeconds)
	}
	if mailAccess != domain.OutlookMailAccessIMAP {
		return [6]byte{}, nil, domain.ErrInvalidCodeRequest
	}
	return p.resolveIMAP(ctx, request.Credential, request.NotBefore, request.WaitSeconds)
}

func (p *Provider) resolveIMAP(ctx context.Context, source *credential.Secret, notBefore *time.Time, waitSeconds int) ([6]byte, *domain.CredentialUpdate, error) {
	var empty [6]byte
	if p == nil || p.oauth == nil || p.extractor == nil || p.now == nil || p.sleep == nil || p.jitter == nil || p.lifecycle == nil || source == nil || ctx == nil || waitSeconds < 0 || waitSeconds > p.maxWait {
		return empty, nil, domain.ErrInvalidCodeRequest
	}
	if err := ctx.Err(); err != nil {
		return empty, nil, err
	}
	select {
	case <-p.lifecycle.Done():
		return empty, nil, domain.ErrUpstreamFailure
	default:
	}
	resolveStart := p.now().UTC()
	pollDeadline := resolveStart.Add(time.Duration(waitSeconds) * time.Second)
	requestCtx, cancelRequest := context.WithCancel(ctx)
	stopLifecycle := context.AfterFunc(p.lifecycle, cancelRequest)
	defer func() {
		stopLifecycle()
		cancelRequest()
	}()
	operationCtx, cancelOperation := context.WithTimeout(requestCtx, outlookAttemptTimeout+time.Duration(waitSeconds)*time.Second)
	defer cancelOperation()
	parsed, err := ParseCredential(source.Bytes())
	if err != nil {
		return empty, nil, domain.ErrInvalidCodeRequest
	}
	defer parsed.Destroy()

	var rotation []byte
	defer func() { clear(rotation) }()
	accessToken, accessExpiresAt, err := p.refreshAccess(operationCtx, &parsed, &rotation)
	if err != nil {
		return empty, makeUpdate(rotation), err
	}
	defer func() { clear(accessToken) }()

	forceRefreshUsed := false
	session, err := p.openForResolve(operationCtx, &parsed, accessToken)
	if isIMAPAuthError(err) {
		forceRefreshUsed = true
		if session != nil {
			session.Abort()
		}
		clear(accessToken)
		accessToken, accessExpiresAt, err = p.refreshAccess(operationCtx, &parsed, &rotation)
		if err == nil {
			session, err = p.openForResolve(operationCtx, &parsed, accessToken)
		}
	}
	if err != nil {
		return empty, makeUpdate(rotation), mapIMAPError(err)
	}
	if !p.registerSession(session) {
		session.Abort()
		return empty, makeUpdate(rotation), domain.ErrUpstreamFailure
	}
	defer func() {
		p.unregisterSession(session)
		session.Close()
	}()

	reconnects := 0
	for attempt := 0; ; attempt++ {
		attemptCtx, cancelAttempt := context.WithTimeout(operationCtx, outlookAttemptTimeout)
		if attempt > 0 && !forceRefreshUsed && !accessExpiresAt.IsZero() && !p.now().UTC().Add(outlookAttemptTimeout+5*time.Second).Before(accessExpiresAt) {
			forceRefreshUsed = true
			p.unregisterSession(session)
			session.Abort()
			clear(accessToken)
			accessToken, accessExpiresAt, err = p.refreshAccess(attemptCtx, &parsed, &rotation)
			if err == nil {
				session, err = p.openForResolve(attemptCtx, &parsed, accessToken)
			}
			if err == nil && !p.registerSession(session) {
				session.Abort()
				err = domain.ErrUpstreamFailure
			}
			if err != nil {
				cancelAttempt()
				return empty, makeUpdate(rotation), mapIMAPError(err)
			}
		}
		if attempt > 0 {
			if noopErr := session.noop(attemptCtx); noopErr != nil {
				if reconnects >= 2 {
					cancelAttempt()
					return empty, makeUpdate(rotation), mapIMAPError(noopErr)
				}
				reconnects++
				p.unregisterSession(session)
				session.Abort()
				session, err = p.openForResolve(attemptCtx, &parsed, accessToken)
				if isIMAPAuthError(err) && !forceRefreshUsed {
					forceRefreshUsed = true
					clear(accessToken)
					accessToken, accessExpiresAt, err = p.refreshAccess(attemptCtx, &parsed, &rotation)
					if err == nil {
						session, err = p.openForResolve(attemptCtx, &parsed, accessToken)
					}
				}
				if err == nil && !p.registerSession(session) {
					session.Abort()
					err = domain.ErrUpstreamFailure
				}
			}
			if err != nil {
				cancelAttempt()
				return empty, makeUpdate(rotation), mapIMAPError(err)
			}
		}

		messages, fetchErr := session.fetchBatch(attemptCtx, p.settings.MaxMessages, p.settings.MaxMessageBytes)
		if fetchErr != nil && !errors.Is(fetchErr, domain.ErrUpstreamSchemaChanged) && attemptCtx.Err() == nil && reconnects < 2 {
			destroyMessages(messages)
			reconnects++
			p.unregisterSession(session)
			session.Abort()
			session, err = p.openForResolve(attemptCtx, &parsed, accessToken)
			if isIMAPAuthError(err) && !forceRefreshUsed {
				forceRefreshUsed = true
				clear(accessToken)
				accessToken, accessExpiresAt, err = p.refreshAccess(attemptCtx, &parsed, &rotation)
				if err == nil {
					session, err = p.openForResolve(attemptCtx, &parsed, accessToken)
				}
			}
			if err == nil && !p.registerSession(session) {
				session.Abort()
				err = domain.ErrUpstreamFailure
			}
			if err == nil {
				messages, fetchErr = session.fetchBatch(attemptCtx, p.settings.MaxMessages, p.settings.MaxMessageBytes)
			} else {
				fetchErr = mapIMAPError(err)
			}
		}
		cancelAttempt()
		if fetchErr != nil {
			destroyMessages(messages)
			if ctx.Err() != nil {
				return empty, makeUpdate(rotation), ctx.Err()
			}
			if errors.Is(fetchErr, domain.ErrUpstreamSchemaChanged) {
				return empty, makeUpdate(rotation), fetchErr
			}
			if errors.Is(fetchErr, context.DeadlineExceeded) || errors.Is(fetchErr, domain.ErrUpstreamTimeout) {
				fetchErr = domain.ErrUpstreamTimeout
			}
			if waitSeconds == 0 || !p.now().UTC().Before(pollDeadline) {
				return empty, makeUpdate(rotation), mapIMAPError(fetchErr)
			}
			remaining := pollDeadline.Sub(p.now().UTC())
			if remaining <= 0 {
				return empty, makeUpdate(rotation), mapIMAPError(fetchErr)
			}
			delay := p.jitter(duration(p.settings.PollIntervalSeconds))
			if delay > remaining {
				delay = remaining
			}
			if sleepErr := p.sleep(operationCtx, delay); sleepErr != nil {
				return empty, makeUpdate(rotation), mapContextError(sleepErr, ctx.Err())
			}
			continue
		}

		code, extractErr := p.extractor.Extract(messages, notBefore, p.now().UTC())
		destroyMessages(messages)
		if extractErr != nil {
			return empty, makeUpdate(rotation), extractErr
		}
		if code != "" {
			copy(empty[:], code)
			code = ""
			return empty, makeUpdate(rotation), nil
		}
		if waitSeconds == 0 {
			return empty, makeUpdate(rotation), domain.WithRetryAfter(domain.ErrNoFreshCode, retrySeconds(p.settings.PollIntervalSeconds))
		}
		remaining := pollDeadline.Sub(p.now().UTC())
		if remaining <= 0 {
			return empty, makeUpdate(rotation), domain.WithRetryAfter(domain.ErrNoFreshCode, retrySeconds(p.settings.PollIntervalSeconds))
		}
		delay := p.jitter(duration(p.settings.PollIntervalSeconds))
		if delay >= remaining {
			if sleepErr := p.sleep(operationCtx, remaining); sleepErr != nil {
				return empty, makeUpdate(rotation), mapContextError(sleepErr, ctx.Err())
			}
			return empty, makeUpdate(rotation), domain.WithRetryAfter(domain.ErrNoFreshCode, retrySeconds(p.settings.PollIntervalSeconds))
		}
		if sleepErr := p.sleep(operationCtx, delay); sleepErr != nil {
			return empty, makeUpdate(rotation), mapContextError(sleepErr, ctx.Err())
		}
	}
}

func (p *Provider) refreshAccess(ctx context.Context, credential *Credential, rotation *[]byte) ([]byte, time.Time, error) {
	return p.refreshAccessFor(ctx, credential, rotation, oauthTargetIMAP)
}

func (p *Provider) refreshAccessFor(ctx context.Context, credential *Credential, rotation *[]byte, target oauthTarget) ([]byte, time.Time, error) {
	result, err := p.oauth.RefreshFor(ctx, credential, target)
	if err != nil {
		if token, cause, ok := consumeOAuthRotationError(err); ok {
			if adoptErr := adoptRotation(credential, token, rotation); adoptErr == nil {
				clear(token)
				return nil, time.Time{}, cause
			}
			clear(token)
		}
		return nil, time.Time{}, err
	}
	access := bytes.Clone(result.AccessToken)
	expiresAt := p.now().Add(time.Duration(result.ExpiresInSeconds) * time.Second)
	if len(result.RotatedRefreshToken) > 0 {
		if err := adoptRotation(credential, result.RotatedRefreshToken, rotation); err != nil {
			result.Destroy()
			clear(access)
			return nil, time.Time{}, err
		}
	}
	result.Destroy()
	return access, expiresAt, nil
}

func consumeOAuthRotationError(err error) ([]byte, error, bool) {
	var wrapped *domain.CredentialUpdateError
	if !errors.As(err, &wrapped) || wrapped == nil || wrapped.Update == nil || len(wrapped.Update.RefreshToken) == 0 {
		return nil, err, false
	}
	cause := wrapped.Cause
	if cause == nil {
		cause = domain.ErrUpstreamFailure
	}
	token := bytes.Clone(wrapped.Update.RefreshToken)
	wrapped.Destroy()
	return token, cause, true
}

func (p *Provider) openForResolve(ctx context.Context, credential *Credential, accessToken []byte) (*imapSession, error) {
	if p.openOverride != nil {
		return p.openOverride(ctx, credential, accessToken)
	}
	return p.openSession(ctx, credential, accessToken)
}

func (p *Provider) openSession(ctx context.Context, credential *Credential, accessToken []byte) (*imapSession, error) {
	session, err := dialIMAP(ctx, p.settings)
	if err != nil {
		return nil, err
	}
	if err := session.authenticate(ctx, credential.Email, accessToken); err != nil {
		session.Abort()
		return nil, err
	}
	if _, err := session.selectReadOnly(ctx); err != nil {
		session.Abort()
		return nil, err
	}
	return session, nil
}

func (p *Provider) registerSession(session *imapSession) bool {
	if session == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.sessions[session] = struct{}{}
	return true
}

func (p *Provider) unregisterSession(session *imapSession) {
	p.mu.Lock()
	delete(p.sessions, session)
	p.mu.Unlock()
}

func (p *Provider) Close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		if p.cancelLife != nil {
			p.cancelLife()
		}
		p.mu.Lock()
		p.closed = true
		sessions := make([]*imapSession, 0, len(p.sessions))
		for session := range p.sessions {
			sessions = append(sessions, session)
		}
		p.mu.Unlock()
		for _, session := range sessions {
			session.Abort()
		}
		if p.oauth != nil {
			p.oauth.Close()
		}
	})
}

func adoptRotation(credential *Credential, rotated []byte, current *[]byte) error {
	updated, err := credential.WithRefreshToken(rotated)
	if err != nil {
		return domain.ErrUpstreamSchemaChanged
	}
	credential.Destroy()
	*credential = updated
	clear(*current)
	*current = bytes.Clone(rotated)
	return nil
}

func makeUpdate(rotation []byte) *domain.CredentialUpdate {
	if len(rotation) == 0 {
		return nil
	}
	return &domain.CredentialUpdate{RefreshToken: bytes.Clone(rotation)}
}

func isIMAPAuthError(err error) bool {
	var authErr imapAuthError
	return errors.As(err, &authErr)
}

func mapIMAPError(err error) error {
	if err == nil {
		return domain.ErrUpstreamFailure
	}
	if isIMAPAuthError(err) {
		return domain.WithSourceStage(domain.ErrSourceCredentials, stageOutlookIMAPAuth)
	}
	return err
}

func mapContextError(err, parent error) error {
	if parent != nil && errors.Is(parent, context.Canceled) {
		return parent
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return domain.ErrUpstreamTimeout
}

func boundedJitter(value time.Duration) time.Duration {
	if value <= 0 {
		return value
	}
	var raw [2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return value
	}
	factor := 0.9 + 0.2*float64(binary.BigEndian.Uint16(raw[:]))/65_535
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

func retrySeconds(value float64) int {
	seconds := int(value)
	if float64(seconds) < value {
		seconds++
	}
	if seconds < 1 {
		return 1
	}
	if seconds > 300 {
		return 300
	}
	return seconds
}
