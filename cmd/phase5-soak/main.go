// Command phase5-soak runs the credential-safe, single-core CodeRelay soak gate.
// It launches the static production binary with a temporary synthetic TOTP
// configuration, drives one shared API key below 240 requests/minute, samples
// Linux process resources, checks result isolation, scans logs for synthetic
// secrets/codes, and verifies graceful shutdown.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LinYS77/coderelay/internal/auth"
	"github.com/LinYS77/coderelay/internal/credential"
	"github.com/LinYS77/coderelay/internal/secretfile"
	"github.com/LinYS77/coderelay/internal/totp"
)

const (
	policyPerMinute = 240
	policyBurst     = 40
	mib             = 1024 * 1024
)

type options struct {
	binary        string
	duration      time.Duration
	concurrency   int
	cycleInterval time.Duration
	sampleEvery   time.Duration
	output        string
}

type report struct {
	RequestedSeconds   float64 `json:"requested_seconds"`
	DurationSeconds    float64 `json:"duration_seconds"`
	Completed          bool    `json:"completed"`
	Concurrency        int     `json:"concurrency"`
	CycleIntervalMS    float64 `json:"cycle_interval_ms"`
	Cycles             int64   `json:"cycles"`
	MinimumRequests    int64   `json:"minimum_requests"`
	Requests           int64   `json:"requests"`
	HTTP200            int64   `json:"http_200"`
	HTTP500            int64   `json:"http_500"`
	OtherFailures      int64   `json:"other_failures"`
	CredentialMismatch int64   `json:"credential_result_mismatch"`
	P99LatencyMS       float64 `json:"p99_latency_ms"`
	MaxLatencyMS       float64 `json:"max_latency_ms"`
	GoroutinesBefore   int64   `json:"goroutines_before"`
	GoroutinesAfter    int64   `json:"goroutines_after"`
	GoroutinePeak      int64   `json:"goroutine_peak"`
	GoroutineLeak      int64   `json:"goroutine_leak"`
	FDBefore           int     `json:"fd_before"`
	FDAfter            int     `json:"fd_after"`
	FDLeak             int     `json:"fd_leak"`
	FDPeak             int     `json:"fd_peak"`
	SocketPeak         int     `json:"socket_peak"`
	ThreadPeak         int     `json:"thread_peak"`
	RSSBeforeBytes     int64   `json:"rss_before_bytes"`
	RSSAfterBytes      int64   `json:"rss_after_bytes"`
	SteadyRSSPeakBytes int64   `json:"steady_rss_peak_bytes"`
	StressRSSPeakBytes int64   `json:"stress_rss_peak_bytes"`
	LogSecretMatches   int     `json:"log_secret_matches"`
	ShutdownMS         float64 `json:"shutdown_ms"`
	ExitClean          bool    `json:"exit_clean"`
}

type processSample struct {
	rssBytes int64
	fds      int
	sockets  int
	threads  int
}

type requestResult struct {
	status   int
	code     string
	latency  time.Duration
	mismatch bool
	failed   bool
}

type synchronizedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *synchronizedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(value)
}

func (b *synchronizedBuffer) BytesCopy() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.Buffer.Bytes()...)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "phase5-soak:", err)
		os.Exit(1)
	}
}

func run() error {
	var cfg options
	flag.StringVar(&cfg.binary, "binary", "dist/coderelay", "path to the static CodeRelay binary")
	flag.DurationVar(&cfg.duration, "duration", time.Minute, "soak duration (acceptance: 60m)")
	flag.IntVar(&cfg.concurrency, "concurrency", 20, "requests per paced burst")
	flag.DurationVar(&cfg.cycleInterval, "cycle-interval", 5250*time.Millisecond, "delay between bursts")
	flag.DurationVar(&cfg.sampleEvery, "sample-every", 100*time.Millisecond, "Linux /proc sampling interval")
	flag.StringVar(&cfg.output, "output", "", "optional JSON report path")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("positional arguments are not allowed")
	}
	if cfg.binary == "" || cfg.duration < time.Second || cfg.concurrency < 1 || cfg.concurrency > policyBurst || cfg.cycleInterval <= 0 || cfg.sampleEvery < 10*time.Millisecond {
		return errors.New("invalid soak options")
	}
	if float64(cfg.concurrency)*float64(time.Minute)/float64(cfg.cycleInterval) > policyPerMinute {
		return errors.New("load would exceed the shared-key 240/minute policy")
	}
	binary, err := filepath.Abs(cfg.binary)
	if err != nil {
		return err
	}
	if info, statErr := os.Stat(binary); statErr != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return errors.New("binary is missing or not executable")
	}
	if _, err := os.ReadDir("/proc/self/fd"); err != nil {
		return errors.New("the soak gate requires Linux /proc")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	temporary, err := os.MkdirTemp("", "coderelay-phase5-soak-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}

	token, hash, err := auth.GenerateToken()
	if err != nil {
		return err
	}
	defer clear(token)
	defer clear(hash)
	hashPath := filepath.Join(temporary, "api.sha256")
	if err := secretfile.WriteExclusive(hashPath, hash); err != nil {
		return err
	}
	port, err := unusedPort()
	if err != nil {
		return err
	}
	configPath := filepath.Join(temporary, "config.toml")
	configBody := fmt.Sprintf("[server]\nport = %d\nallowed_hosts = [\"127.0.0.1\", \"localhost\"]\n\n[security]\napi_token_hash_files = [%s]\n", port, strconv.Quote(hashPath))
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		return err
	}

	var logs synchronizedBuffer
	command := exec.Command(binary, "serve", "--config", configPath)
	command.Stdout = &logs
	command.Stderr = &logs
	command.Env = []string{
		"GOMAXPROCS=1",
		"GOMEMLIMIT=384MiB",
		"HOME=" + temporary,
		"TMPDIR=" + temporary,
	}
	if err := command.Start(); err != nil {
		return err
	}
	waitResult := make(chan error, 1)
	go func() { waitResult <- command.Wait() }()
	stopped := false
	defer func() {
		if !stopped && command.Process != nil {
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case <-waitResult:
			case <-time.After(3 * time.Second):
				_ = command.Process.Kill()
				<-waitResult
			}
		}
	}()

	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
		MaxConnsPerHost:     cfg.concurrency,
		MaxIdleConns:        cfg.concurrency,
		MaxIdleConnsPerHost: cfg.concurrency,
		IdleConnTimeout:     10 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	if err := waitReady(ctx, client, baseURL); err != nil {
		return fmt.Errorf("startup failed: %w; logs=%s", err, redactLogSummary(logs.BytesCopy()))
	}
	transport.CloseIdleConnections()
	time.Sleep(300 * time.Millisecond)
	baseline, err := sampleProcess(command.Process.Pid)
	if err != nil {
		return err
	}
	beforeGoroutines, err := requestRuntimeSnapshot(command.Process, &logs)
	if err != nil {
		return err
	}

	secrets := syntheticSecrets(cfg.concurrency)
	payloads := make([][]byte, len(secrets))
	sensitive := make([][]byte, 0, len(secrets)+policyBurst+2)
	sensitive = append(sensitive, append([]byte(nil), token...), append([]byte(nil), hash...))
	for index, secret := range secrets {
		payloads[index] = []byte(fmt.Sprintf(`{"type":"totp","credential":"%s","min_ttl":5}`, secret))
		sensitive = append(sensitive, []byte(secret))
	}
	defer func() {
		for _, value := range payloads {
			clear(value)
		}
		for _, value := range sensitive {
			clear(value)
		}
	}()

	samplerCtx, stopSampler := context.WithCancel(context.Background())
	samples := make(chan processSample, maxInt(16, int(cfg.cycleInterval/cfg.sampleEvery)+16))
	sampleErrors := make(chan error, 1)
	go sampleLoop(samplerCtx, command.Process.Pid, cfg.sampleEvery, samples, sampleErrors)
	started := time.Now()
	deadline := started.Add(cfg.duration)
	warmupUntil := started.Add(minDuration(30*time.Second, cfg.duration/10))
	latencies := make([]time.Duration, 0, int(cfg.duration/cfg.cycleInterval+1)*cfg.concurrency)
	var result report
	result.RequestedSeconds = cfg.duration.Seconds()
	result.Concurrency = cfg.concurrency
	result.CycleIntervalMS = float64(cfg.cycleInterval) / float64(time.Millisecond)
	minimumCycles := int64(cfg.duration / cfg.cycleInterval)
	if minimumCycles < 1 {
		minimumCycles = 1
	}
	result.MinimumRequests = minimumCycles * int64(cfg.concurrency)
	result.FDBefore = baseline.fds
	result.RSSBeforeBytes = baseline.rssBytes
	result.GoroutinesBefore = beforeGoroutines
	result.FDPeak = baseline.fds
	result.SocketPeak = baseline.sockets
	result.ThreadPeak = baseline.threads
	result.StressRSSPeakBytes = baseline.rssBytes

	nextCycle := started
	interrupted := false
loadLoop:
	for !nextCycle.After(deadline) {
		if err := waitUntil(ctx, nextCycle); err != nil {
			interrupted = true
			break
		}
		batch := runBatch(ctx, client, baseURL, token, secrets, payloads)
		result.Cycles++
		for _, current := range batch {
			result.Requests++
			latencies = append(latencies, current.latency)
			if current.failed {
				result.OtherFailures++
			} else {
				switch current.status {
				case http.StatusOK:
					result.HTTP200++
				case http.StatusInternalServerError:
					result.HTTP500++
				default:
					result.OtherFailures++
				}
			}
			if current.mismatch {
				result.CredentialMismatch++
			}
			if current.code != "" {
				sensitive = append(sensitive, []byte(current.code))
			}
		}
		for {
			select {
			case current := <-samples:
				mergeSample(&result, current, time.Now().After(warmupUntil))
			case err := <-sampleErrors:
				stopSampler()
				return err
			default:
				nextCycle = nextCycle.Add(cfg.cycleInterval)
				continue loadLoop
			}
		}
	}
	if !interrupted {
		if err := waitUntil(ctx, deadline); err != nil {
			interrupted = true
		}
	}
	result.DurationSeconds = time.Since(started).Seconds()
	result.Completed = !interrupted && !time.Now().Before(deadline)
	stopSampler()
	for current := range samples {
		mergeSample(&result, current, time.Now().After(warmupUntil))
	}
	select {
	case err := <-sampleErrors:
		return err
	default:
	}

	transport.CloseIdleConnections()
	time.Sleep(time.Second)
	finalSample, err := sampleProcess(command.Process.Pid)
	if err != nil {
		return err
	}
	mergeSample(&result, finalSample, true)
	result.FDAfter = finalSample.fds
	result.RSSAfterBytes = finalSample.rssBytes
	afterGoroutines, err := requestRuntimeSnapshot(command.Process, &logs)
	if err != nil {
		return err
	}
	result.GoroutinesAfter = afterGoroutines
	for _, count := range runtimeSnapshots(logs.BytesCopy()) {
		result.GoroutinePeak = maxInt64(result.GoroutinePeak, count)
	}
	result.GoroutineLeak = maxInt64(0, afterGoroutines-beforeGoroutines)
	result.FDLeak = maxInt(0, finalSample.fds-baseline.fds)
	setLatencyMetrics(&result, latencies)

	shutdownStarted := time.Now()
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case waitErr := <-waitResult:
		stopped = true
		result.ShutdownMS = float64(time.Since(shutdownStarted)) / float64(time.Millisecond)
		result.ExitClean = waitErr == nil
		if waitErr != nil {
			return fmt.Errorf("service exit: %w", waitErr)
		}
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		<-waitResult
		stopped = true
		return errors.New("graceful shutdown exceeded 10s")
	}
	result.LogSecretMatches = countSensitiveMatches(logs.BytesCopy(), sensitive)
	if result.SteadyRSSPeakBytes == 0 {
		result.SteadyRSSPeakBytes = result.StressRSSPeakBytes
	}

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if _, err := os.Stdout.Write(encoded); err != nil {
		return err
	}
	if cfg.output != "" {
		if err := os.WriteFile(cfg.output, encoded, 0o644); err != nil {
			return err
		}
	}
	return validateReport(result)
}

func runBatch(ctx context.Context, client *http.Client, baseURL string, token []byte, secrets []string, payloads [][]byte) []requestResult {
	start := make(chan struct{})
	results := make(chan requestResult, len(secrets))
	generator := totp.New()
	for index := range secrets {
		go func() {
			<-start
			began := time.Now()
			before, beforeErr := expectedCode(generator, secrets[index])
			requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			request, requestErr := http.NewRequestWithContext(requestCtx, http.MethodPost, baseURL+"/api/v1/code", bytes.NewReader(payloads[index]))
			if requestErr == nil {
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Authorization", "Bearer "+string(token))
			}
			var current requestResult
			if requestErr != nil {
				current.failed = true
			} else {
				response, responseErr := client.Do(request)
				if responseErr != nil {
					current.failed = true
				} else {
					body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
					_ = response.Body.Close()
					current.status = response.StatusCode
					if readErr != nil || len(body) > 4096 {
						current.failed = true
					} else {
						var envelope struct {
							Code string `json:"code"`
						}
						if json.Unmarshal(body, &envelope) != nil {
							current.failed = true
						}
						current.code = envelope.Code
					}
					clear(body)
				}
			}
			cancel()
			after, afterErr := expectedCode(generator, secrets[index])
			current.latency = time.Since(began)
			if current.status == http.StatusOK && (beforeErr != nil || afterErr != nil || current.code != before && current.code != after) {
				current.mismatch = true
			}
			results <- current
		}()
	}
	close(start)
	batch := make([]requestResult, 0, len(secrets))
	for range secrets {
		batch = append(batch, <-results)
	}
	return batch
}

func expectedCode(generator *totp.Generator, value string) (string, error) {
	secret := credential.NewOwned([]byte(value))
	defer secret.Destroy()
	code, err := generator.Resolve(context.Background(), secret, 0)
	if err != nil {
		return "", err
	}
	result := string(code[:])
	clear(code[:])
	return result, nil
}

func waitReady(ctx context.Context, client *http.Client, baseURL string) error {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("readiness timeout")
		case <-ticker.C:
			response, err := client.Get(baseURL + "/health/ready")
			if err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
	}
}

func requestRuntimeSnapshot(process *os.Process, logs *synchronizedBuffer) (int64, error) {
	before := len(runtimeSnapshots(logs.BytesCopy()))
	if err := process.Signal(syscall.SIGUSR1); err != nil {
		return 0, err
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		values := runtimeSnapshots(logs.BytesCopy())
		if len(values) > before {
			return values[len(values)-1], nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0, errors.New("runtime snapshot was not logged")
}

func runtimeSnapshots(value []byte) []int64 {
	lines := bytes.Split(value, []byte{'\n'})
	result := make([]int64, 0, 2)
	for _, line := range lines {
		var event struct {
			Message    string `json:"msg"`
			Goroutines int64  `json:"goroutines"`
		}
		if json.Unmarshal(line, &event) == nil && event.Message == "runtime_snapshot" {
			result = append(result, event.Goroutines)
		}
	}
	return result
}

func sampleLoop(ctx context.Context, pid int, interval time.Duration, output chan processSample, failures chan<- error) {
	defer close(output)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	nextRuntimeSnapshot := time.Now().Add(time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if !now.Before(nextRuntimeSnapshot) {
				if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil {
					select {
					case failures <- err:
					default:
					}
					return
				}
				nextRuntimeSnapshot = now.Add(time.Second)
			}
			current, err := sampleProcess(pid)
			if err != nil {
				select {
				case failures <- err:
				default:
				}
				return
			}
			select {
			case output <- current:
			case <-ctx.Done():
				return
			}
		}
	}
}

func sampleProcess(pid int) (processSample, error) {
	var result processSample
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return result, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "VmRSS:":
			value, parseErr := strconv.ParseInt(fields[1], 10, 64)
			if parseErr != nil {
				return result, parseErr
			}
			result.rssBytes = value * 1024
		case "Threads:":
			value, parseErr := strconv.Atoi(fields[1])
			if parseErr != nil {
				return result, parseErr
			}
			result.threads = value
		}
	}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return result, err
	}
	result.fds = len(fds)
	if result.rssBytes <= 0 || result.threads <= 0 || result.fds <= 0 {
		return processSample{}, errors.New("incomplete Linux process metrics")
	}
	for _, fd := range fds {
		target, readErr := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		if readErr == nil && strings.HasPrefix(target, "socket:[") {
			result.sockets++
		}
	}
	return result, nil
}

func mergeSample(result *report, current processSample, steady bool) {
	result.FDPeak = maxInt(result.FDPeak, current.fds)
	result.SocketPeak = maxInt(result.SocketPeak, current.sockets)
	result.ThreadPeak = maxInt(result.ThreadPeak, current.threads)
	result.StressRSSPeakBytes = maxInt64(result.StressRSSPeakBytes, current.rssBytes)
	if steady {
		result.SteadyRSSPeakBytes = maxInt64(result.SteadyRSSPeakBytes, current.rssBytes)
	}
}

func setLatencyMetrics(result *report, values []time.Duration) {
	if len(values) == 0 {
		return
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	index := (len(values)*99 + 99) / 100
	if index > 0 {
		index--
	}
	result.P99LatencyMS = float64(values[index]) / float64(time.Millisecond)
	result.MaxLatencyMS = float64(values[len(values)-1]) / float64(time.Millisecond)
}

func validateReport(result report) error {
	failures := make([]string, 0, 10)
	if !result.Completed || result.DurationSeconds < result.RequestedSeconds {
		failures = append(failures, "soak did not run for the requested duration")
	}
	if result.Requests < result.MinimumRequests {
		failures = append(failures, "soak request count is below the paced minimum")
	}
	if result.Requests == 0 || result.HTTP200 != result.Requests {
		failures = append(failures, "not every request returned HTTP 200")
	}
	if result.HTTP500 != 0 {
		failures = append(failures, "internal 500 is nonzero")
	}
	if result.OtherFailures != 0 {
		failures = append(failures, "request failures are nonzero")
	}
	if result.CredentialMismatch != 0 {
		failures = append(failures, "credential/result mismatch is nonzero")
	}
	if result.GoroutinesBefore < 1 || result.GoroutinesAfter < 1 || result.FDBefore < 1 || result.FDAfter < 1 || result.RSSBeforeBytes < 1 || result.RSSAfterBytes < 1 {
		failures = append(failures, "resource baseline or final sample is missing")
	}
	if result.GoroutinePeak < result.GoroutinesBefore || result.GoroutinePeak < result.GoroutinesAfter {
		failures = append(failures, "goroutine peak sample is invalid")
	}
	if result.GoroutineLeak != 0 || result.GoroutinesAfter != result.GoroutinesBefore {
		failures = append(failures, "goroutine leak is nonzero")
	}
	if result.FDLeak != 0 || result.FDAfter != result.FDBefore {
		failures = append(failures, "FD leak is nonzero")
	}
	if result.SteadyRSSPeakBytes >= 256*mib {
		failures = append(failures, "steady RSS reached 256 MiB")
	}
	if result.StressRSSPeakBytes >= 512*mib {
		failures = append(failures, "stress RSS reached 512 MiB")
	}
	if result.LogSecretMatches != 0 {
		failures = append(failures, "synthetic credential/code entered logs")
	}
	if !result.ExitClean {
		failures = append(failures, "service did not exit cleanly")
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func syntheticSecrets(count int) []string {
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	result := make([]string, count)
	for index := range result {
		digest := sha256.Sum256([]byte(fmt.Sprintf("CodeRelay Phase 5 synthetic worker %d", index)))
		result[index] = encoding.EncodeToString(digest[:20])
		clear(digest[:])
	}
	return result
}

func countSensitiveMatches(logs []byte, values [][]byte) int {
	needles := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if len(value) == 0 {
			continue
		}
		key := string(value)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		needles = append(needles, key)
	}
	matches := 0
	for _, line := range bytes.Split(logs, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if json.Unmarshal(line, &event) != nil {
			for _, needle := range needles {
				if bytes.Contains(line, []byte(needle)) {
					matches++
				}
			}
			continue
		}
		for key, value := range event {
			// Structured logger timestamps and numeric resource metrics can
			// coincidentally contain a six-digit sequence; credentials and
			// codes are strings and must never appear in any other field.
			if key == "time" {
				continue
			}
			text, ok := value.(string)
			if !ok {
				continue
			}
			for _, needle := range needles {
				if strings.Contains(text, needle) {
					matches++
				}
			}
		}
	}
	return matches
}

func unusedPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func waitUntil(ctx context.Context, target time.Time) error {
	delay := time.Until(target)
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func redactLogSummary(value []byte) string {
	lines := bytes.Count(value, []byte{'\n'})
	return fmt.Sprintf("%d bytes/%d lines", len(value), lines)
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
