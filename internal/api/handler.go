package api

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/LinYS77/coderelay/internal/admission"
	"github.com/LinYS77/coderelay/internal/auth"
	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/domain"
	"github.com/LinYS77/coderelay/internal/ratelimit"
	"github.com/LinYS77/coderelay/internal/version"
)

type Resolver interface {
	Resolve(context.Context, *domain.Command) (domain.Result, error)
}

type Handler struct {
	config           config.Config
	allowedHosts     map[string]struct{}
	trustedProxies   map[netip.Addr]struct{}
	verifier         *auth.Verifier
	ipLimiter        *ratelimit.Limiter
	principalLimiter *ratelimit.Limiter
	admission        *admission.Controller
	resolver         Resolver
	logger           *slog.Logger
	ready            atomic.Bool
}

func NewHandler(cfg config.Config, verifier *auth.Verifier, resolver Resolver, logger *slog.Logger) (*Handler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	trusted, err := cfg.TrustedProxyAddrs()
	if err != nil {
		return nil, err
	}
	if verifier == nil || resolver == nil {
		return nil, errors.New("API dependencies are not initialized")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}
	return &Handler{
		config:           cfg,
		allowedHosts:     cfg.AllowedHostSet(),
		trustedProxies:   trusted,
		verifier:         verifier,
		ipLimiter:        ratelimit.New(cfg.Security.APIRateLimitPerMinute, cfg.Security.APIRateLimitBurst, cfg.Security.MaxIPRateLimitEntries),
		principalLimiter: ratelimit.New(cfg.Security.APIRateLimitPerMinute, cfg.Security.APIRateLimitBurst, cfg.Security.MaxPrincipalRateLimitEntries),
		admission:        admission.New(cfg.Server.MaxConcurrentCodeRequests, cfg.Server.MaxQueuedCodeRequests, cfg.Server.AdmissionWait()),
		resolver:         resolver,
		logger:           logger,
	}, nil
}

func (h *Handler) Start(ctx context.Context) {
	h.ipLimiter.StartCleanup(ctx, time.Minute, 2*time.Minute)
	h.principalLimiter.StartCleanup(ctx, time.Minute, 2*time.Minute)
	h.ready.Store(true)
}

func (h *Handler) BeginShutdown() {
	h.ready.Store(false)
	h.admission.Close()
}

func (h *Handler) ActiveRequests() int64 { return h.admission.Active() }
func (h *Handler) QueuedRequests() int64 { return h.admission.Queued() }

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	id := requestID(request)
	setSecurityHeaders(writer.Header(), request.URL.Path, id)
	tracked := &responseTracker{ResponseWriter: writer}
	defer h.recoverPanic(tracked, request, id)

	if !allowedRequestHost(request.Host, h.allowedHosts) {
		h.rejectBeforeBody(tracked, request, id, invalidHost())
		return
	}
	switch request.URL.Path {
	case "/health/live":
		h.serveLive(tracked, request, id)
	case "/health/ready":
		h.serveReady(tracked, request, id)
	case "/api/v1/code":
		h.serveCode(tracked, request, id)
	default:
		h.rejectBeforeBody(tracked, request, id, notFound())
	}
}

func (h *Handler) serveLive(writer http.ResponseWriter, request *http.Request, id string) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		h.rejectBeforeBody(writer, request, id, methodNotAllowed())
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}{Status: "ok", Version: version.Value})
}

func (h *Handler) serveReady(writer http.ResponseWriter, request *http.Request, id string) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		h.rejectBeforeBody(writer, request, id, methodNotAllowed())
		return
	}
	if !h.ready.Load() {
		writeJSON(writer, http.StatusServiceUnavailable, struct {
			Status string `json:"status"`
		}{Status: "not_ready"})
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Status string `json:"status"`
		Mode   string `json:"mode"`
	}{Status: "ready", Mode: "stateless"})
}

func (h *Handler) serveCode(writer http.ResponseWriter, request *http.Request, id string) {
	ipDecision := h.ipLimiter.Allow("ip:" + clientIP(request, h.trustedProxies))
	if !ipDecision.Allowed {
		h.rejectBeforeBody(writer, request, id, rateLimited(ipDecision.RetryAfterSeconds))
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		h.rejectBeforeBody(writer, request, id, methodNotAllowed())
		return
	}
	if !validJSONContentType(request.Header.Values("Content-Type")) {
		h.rejectBeforeBody(writer, request, id, unsupportedMediaType())
		return
	}

	token := bearerCandidate(request)
	principal, authenticated := h.verifier.Verify(token)
	clear(token)
	if !authenticated {
		principal = ""
		h.rejectBeforeBody(writer, request, id, authenticationRequired())
		return
	}
	principalDecision := h.principalLimiter.Allow("principal:" + principal)
	principal = ""
	if !principalDecision.Allowed {
		h.rejectBeforeBody(writer, request, id, rateLimited(principalDecision.RetryAfterSeconds))
		return
	}
	if request.URL.RawQuery != "" {
		h.rejectBeforeBody(writer, request, id, validationError())
		return
	}

	release, admissionResult := h.admission.Acquire(request.Context())
	switch admissionResult {
	case admission.Acquired:
		defer release()
	case admission.Canceled:
		return
	default:
		retry := int(math.Ceil(h.config.Server.AdmissionWait().Seconds()))
		h.rejectBeforeBody(writer, request, id, serverBusy(retry))
		return
	}

	command, err := readCodeCommand(unwrapResponseWriter(writer), request, h.config.Server.MaxBodyBytes)
	if err != nil {
		if request.Context().Err() != nil {
			return
		}
		var problem *publicError
		if errors.As(err, &problem) {
			if problem.Status == http.StatusRequestEntityTooLarge {
				request.Close = true
				writer.Header().Set("Connection", "close")
			}
			writePublicError(writer, id, problem)
		} else {
			writePublicError(writer, id, validationError())
		}
		return
	}
	defer command.Destroy()

	result, err := h.resolver.Resolve(request.Context(), command)
	if err != nil {
		result.Destroy()
		if request.Context().Err() != nil || errors.Is(err, context.Canceled) {
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			writePublicError(writer, id, upstreamTimeout())
			return
		}
		if errors.Is(err, domain.ErrInvalidCodeRequest) {
			writePublicError(writer, id, invalidCodeRequest())
			return
		}
		h.logger.Error("request_failed", "request_id", id, "provider", "totp", "stage", "resolve", "error_code", "INTERNAL_ERROR", "status", 500)
		writePublicError(writer, id, internalError())
		return
	}
	defer result.Destroy()
	if !validSixDigitCode(result.Code) {
		h.logger.Error("request_failed", "request_id", id, "provider", "totp", "stage", "resolve", "error_code", "INVALID_PROVIDER_RESULT", "status", 500)
		writePublicError(writer, id, internalError())
		return
	}
	if err := writeSuccess(writer, result.Code); err != nil {
		h.logger.Warn("response_write_failed", "request_id", id, "provider", "totp", "stage", "response", "error_code", "WRITE_FAILED")
	}
}

func (h *Handler) rejectBeforeBody(writer http.ResponseWriter, request *http.Request, id string, problem *publicError) {
	if requestHasBody(request) {
		request.Close = true
		writer.Header().Set("Connection", "close")
	}
	writePublicError(writer, id, problem)
}

func (h *Handler) recoverPanic(writer *responseTracker, request *http.Request, id string) {
	if recover() == nil {
		return
	}
	_, file, line, _ := runtime.Caller(3)
	h.logger.Error("panic_recovered", "request_id", id, "stage", "handler", "error_code", "PANIC", "file", file, "line", line)
	if !writer.wroteHeader {
		if requestHasBody(request) {
			request.Close = true
			writer.Header().Set("Connection", "close")
		}
		writePublicError(writer, id, internalError())
	}
}

func validSixDigitCode(code [6]byte) bool {
	for _, value := range code {
		if value < '0' || value > '9' {
			return false
		}
	}
	return true
}

func validJSONContentType(values []string) bool {
	if len(values) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return false
	}
	if len(parameters) == 0 {
		return true
	}
	charset, ok := parameters["charset"]
	return ok && len(parameters) == 1 && strings.EqualFold(charset, "utf-8")
}

func requestHasBody(request *http.Request) bool {
	return request.Body != nil && (request.ContentLength != 0 || len(request.TransferEncoding) != 0)
}

func setSecurityHeaders(header http.Header, path, id string) {
	header.Set("X-Request-ID", id)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	header.Set("Cache-Control", "no-store")
	if strings.HasPrefix(path, "/api/") {
		header.Set("Cache-Control", "no-store, private")
		header.Set("Pragma", "no-cache")
	}
}

type responseTracker struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *responseTracker) WriteHeader(status int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *responseTracker) Write(value []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(value)
}

func (w *responseTracker) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func unwrapResponseWriter(writer http.ResponseWriter) http.ResponseWriter {
	if current, ok := writer.(interface{ Unwrap() http.ResponseWriter }); ok {
		return current.Unwrap()
	}
	return writer
}

type discardWriter struct{}

func (discardWriter) Write(value []byte) (int, error) { return len(value), nil }
