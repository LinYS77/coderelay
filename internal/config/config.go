// Package config loads and validates the Phase 1 Go service configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
)

const maxConfigBytes = 1 << 20

var ErrInvalid = errors.New("invalid CodeRelay configuration")

type Config struct {
	Server     ServerConfig   `toml:"server"`
	Security   SecurityConfig `toml:"security"`
	ConfigPath string         `toml:"-"`
}

type ServerConfig struct {
	Host                      string   `toml:"host"`
	Port                      int      `toml:"port"`
	AllowedHosts              []string `toml:"allowed_hosts"`
	CORSOrigins               []string `toml:"cors_origins"`
	ForwardedAllowIPs         string   `toml:"forwarded_allow_ips"`
	AccessLog                 bool     `toml:"access_log"`
	LogLevel                  string   `toml:"log_level"`
	MaxInboundConnections     int      `toml:"max_inbound_connections"`
	MaxConcurrentCodeRequests int      `toml:"max_concurrent_code_requests"`
	MaxQueuedCodeRequests     int      `toml:"max_queued_code_requests"`
	AdmissionWaitSeconds      float64  `toml:"admission_wait_seconds"`
	ReadHeaderTimeoutSeconds  float64  `toml:"read_header_timeout_seconds"`
	ReadTimeoutSeconds        float64  `toml:"read_timeout_seconds"`
	WriteTimeoutSeconds       float64  `toml:"write_timeout_seconds"`
	IdleTimeoutSeconds        float64  `toml:"idle_timeout_seconds"`
	ShutdownTimeoutSeconds    float64  `toml:"shutdown_timeout_seconds"`
	MaxHeaderBytes            int      `toml:"max_header_bytes"`
	MaxBodyBytes              int64    `toml:"max_body_bytes"`
}

type SecurityConfig struct {
	APITokenHashFiles            []string `toml:"api_token_hash_files"`
	StrictSecretPermissions      bool     `toml:"strict_secret_permissions"`
	APIRateLimitPerMinute        int      `toml:"api_rate_limit_per_minute"`
	APIRateLimitBurst            int      `toml:"api_rate_limit_burst"`
	MaxIPRateLimitEntries        int      `toml:"max_ip_rate_limit_entries"`
	MaxPrincipalRateLimitEntries int      `toml:"max_principal_rate_limit_entries"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			Host:                      "127.0.0.1",
			Port:                      8787,
			AllowedHosts:              []string{"2fa.077.li", "localhost", "127.0.0.1"},
			CORSOrigins:               []string{},
			ForwardedAllowIPs:         "127.0.0.1,::1",
			AccessLog:                 false,
			LogLevel:                  "info",
			MaxInboundConnections:     128,
			MaxConcurrentCodeRequests: 20,
			MaxQueuedCodeRequests:     4,
			AdmissionWaitSeconds:      2,
			ReadHeaderTimeoutSeconds:  3,
			ReadTimeoutSeconds:        10,
			WriteTimeoutSeconds:       100,
			IdleTimeoutSeconds:        60,
			ShutdownTimeoutSeconds:    90,
			MaxHeaderBytes:            16 << 10,
			MaxBodyBytes:              128 << 10,
		},
		Security: SecurityConfig{
			StrictSecretPermissions:      true,
			APIRateLimitPerMinute:        240,
			APIRateLimitBurst:            40,
			MaxIPRateLimitEntries:        10_000,
			MaxPrincipalRateLimitEntries: 1_000,
		},
	}
}

func Load(path string) (Config, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("%w: cannot resolve config path", ErrInvalid)
	}
	fd, err := syscall.Open(absolute, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Config{}, fmt.Errorf("%w: cannot read config file", ErrInvalid)
	}
	file := os.NewFile(uintptr(fd), absolute)
	if file == nil {
		_ = syscall.Close(fd)
		return Config{}, fmt.Errorf("%w: cannot read config file", ErrInvalid)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxConfigBytes {
		return Config{}, fmt.Errorf("%w: config file size is invalid", ErrInvalid)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		clear(raw)
		return Config{}, fmt.Errorf("%w: cannot read config file", ErrInvalid)
	}
	defer clear(raw)
	if len(raw) == 0 || len(raw) > maxConfigBytes || !utf8.Valid(raw) {
		return Config{}, fmt.Errorf("%w: config file size or encoding is invalid", ErrInvalid)
	}

	cfg := Default()
	decoder := toml.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("%w: TOML could not be decoded", ErrInvalid)
	}
	cfg.ConfigPath = absolute
	if len(cfg.Security.APITokenHashFiles) == 0 || len(cfg.Security.APITokenHashFiles) > 64 {
		return Config{}, invalid("security.api_token_hash_files must contain 1..64 paths")
	}
	base := filepath.Dir(absolute)
	for i, secretPath := range cfg.Security.APITokenHashFiles {
		secretPath = strings.TrimSpace(secretPath)
		if secretPath == "" {
			return Config{}, invalid("security.api_token_hash_files contains a blank path")
		}
		secretPath = filepath.Clean(secretPath)
		if !filepath.IsAbs(secretPath) {
			secretPath = filepath.Join(base, secretPath)
		}
		resolved, err := filepath.Abs(secretPath)
		if err != nil {
			return Config{}, fmt.Errorf("%w: API token hash path is invalid", ErrInvalid)
		}
		cfg.Security.APITokenHashFiles[i] = resolved
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if addr, err := netip.ParseAddr(c.Server.Host); err != nil || !addr.IsLoopback() {
		return invalid("server.host must be a literal loopback address")
	}
	if c.Server.Port < 1 || c.Server.Port > 65_535 {
		return invalid("server.port is outside 1..65535")
	}
	if len(c.Server.AllowedHosts) == 0 || len(c.Server.AllowedHosts) > 64 {
		return invalid("server.allowed_hosts must contain 1..64 entries")
	}
	seenHosts := make(map[string]struct{}, len(c.Server.AllowedHosts))
	for i, host := range c.Server.AllowedHosts {
		normalized, ok := normalizeAllowedHost(host)
		if !ok || normalized == "*" {
			return invalid("server.allowed_hosts contains an invalid host")
		}
		if _, exists := seenHosts[normalized]; exists {
			return invalid("server.allowed_hosts contains a duplicate")
		}
		seenHosts[normalized] = struct{}{}
		c.Server.AllowedHosts[i] = normalized
	}
	if len(c.Server.CORSOrigins) != 0 {
		return invalid("CORS must remain disabled in Phase 1")
	}
	if c.Server.AccessLog {
		return invalid("access_log must remain false")
	}
	if !slices.Contains([]string{"debug", "info", "warning", "error"}, strings.ToLower(c.Server.LogLevel)) {
		return invalid("server.log_level is invalid")
	}
	if _, err := c.TrustedProxyAddrs(); err != nil {
		return err
	}
	if c.Server.MaxInboundConnections < c.Server.MaxConcurrentCodeRequests+c.Server.MaxQueuedCodeRequests || c.Server.MaxInboundConnections > 512 {
		return invalid("max_inbound_connections must cover admission and remain at most 512")
	}
	if c.Server.MaxConcurrentCodeRequests < 1 || c.Server.MaxConcurrentCodeRequests > 100 {
		return invalid("max_concurrent_code_requests is outside 1..100")
	}
	if c.Server.MaxQueuedCodeRequests < 0 || c.Server.MaxQueuedCodeRequests > c.Server.MaxConcurrentCodeRequests {
		return invalid("max_queued_code_requests is outside 0..max_concurrent")
	}
	if !between(c.Server.AdmissionWaitSeconds, 0.01, 10) {
		return invalid("admission_wait_seconds is outside 0.01..10")
	}
	if !between(c.Server.ReadHeaderTimeoutSeconds, 0.1, 30) ||
		!between(c.Server.ReadTimeoutSeconds, 1, 60) ||
		!between(c.Server.WriteTimeoutSeconds, 1, 300) ||
		!between(c.Server.IdleTimeoutSeconds, 1, 300) ||
		!between(c.Server.ShutdownTimeoutSeconds, 1, 300) {
		return invalid("one or more server timeouts are outside their supported range")
	}
	minimumWrite := c.Server.AdmissionWaitSeconds + 35 + 10
	if c.Server.WriteTimeoutSeconds < minimumWrite {
		return invalid("write_timeout_seconds is too short for TOTP operation budget")
	}
	if c.Server.ShutdownTimeoutSeconds < 40 {
		return invalid("shutdown_timeout_seconds is too short for TOTP operation budget")
	}
	if c.Server.MaxHeaderBytes < 4<<10 || c.Server.MaxHeaderBytes > 64<<10 {
		return invalid("max_header_bytes is outside 4096..65536")
	}
	if c.Server.MaxBodyBytes < 1<<10 || c.Server.MaxBodyBytes > 128<<10 {
		return invalid("max_body_bytes is outside 1024..131072")
	}

	if !c.Security.StrictSecretPermissions {
		return invalid("security.strict_secret_permissions must remain true")
	}
	if len(c.Security.APITokenHashFiles) == 0 || len(c.Security.APITokenHashFiles) > 64 {
		return invalid("security.api_token_hash_files must contain 1..64 paths")
	}
	seenHashPaths := make(map[string]struct{}, len(c.Security.APITokenHashFiles))
	for _, path := range c.Security.APITokenHashFiles {
		if strings.TrimSpace(path) == "" {
			return invalid("security.api_token_hash_files contains a blank path")
		}
		if _, duplicate := seenHashPaths[path]; duplicate {
			return invalid("security.api_token_hash_files contains a duplicate")
		}
		seenHashPaths[path] = struct{}{}
	}
	if c.Security.APIRateLimitPerMinute < 1 || c.Security.APIRateLimitPerMinute > 10_000 {
		return invalid("api_rate_limit_per_minute is outside 1..10000")
	}
	if c.Security.APIRateLimitBurst < c.Server.MaxConcurrentCodeRequests || c.Security.APIRateLimitBurst > 10_000 {
		return invalid("api_rate_limit_burst must cover max_concurrent_code_requests")
	}
	if c.Security.MaxIPRateLimitEntries < 1 || c.Security.MaxIPRateLimitEntries > 100_000 ||
		c.Security.MaxPrincipalRateLimitEntries < 1 || c.Security.MaxPrincipalRateLimitEntries > 10_000 {
		return invalid("rate-limit map capacity is invalid")
	}
	return nil
}

func (c Config) Address() string {
	return net.JoinHostPort(c.Server.Host, fmt.Sprintf("%d", c.Server.Port))
}

func (c Config) AllowedHostSet() map[string]struct{} {
	result := make(map[string]struct{}, len(c.Server.AllowedHosts))
	for _, host := range c.Server.AllowedHosts {
		if normalized, ok := normalizeAllowedHost(host); ok {
			result[normalized] = struct{}{}
		}
	}
	return result
}

func (c Config) TrustedProxyAddrs() (map[netip.Addr]struct{}, error) {
	if len(c.Server.ForwardedAllowIPs) > 1_024 {
		return nil, invalid("forwarded_allow_ips is too long")
	}
	items := strings.Split(c.Server.ForwardedAllowIPs, ",")
	if len(items) > 32 {
		return nil, invalid("forwarded_allow_ips contains too many addresses")
	}
	result := make(map[netip.Addr]struct{})
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil || !addr.IsLoopback() {
			return nil, invalid("forwarded_allow_ips must contain only loopback addresses")
		}
		addr = addr.Unmap()
		if _, duplicate := result[addr]; duplicate {
			return nil, invalid("forwarded_allow_ips contains a duplicate")
		}
		result[addr] = struct{}{}
	}
	if len(result) == 0 {
		return nil, invalid("forwarded_allow_ips must contain at least one address")
	}
	return result, nil
}

func (s ServerConfig) AdmissionWait() time.Duration     { return seconds(s.AdmissionWaitSeconds) }
func (s ServerConfig) ReadHeaderTimeout() time.Duration { return seconds(s.ReadHeaderTimeoutSeconds) }
func (s ServerConfig) ReadTimeout() time.Duration       { return seconds(s.ReadTimeoutSeconds) }
func (s ServerConfig) WriteTimeout() time.Duration      { return seconds(s.WriteTimeoutSeconds) }
func (s ServerConfig) IdleTimeout() time.Duration       { return seconds(s.IdleTimeoutSeconds) }
func (s ServerConfig) ShutdownTimeout() time.Duration   { return seconds(s.ShutdownTimeoutSeconds) }

func normalizeAllowedHost(value string) (string, bool) {
	host := strings.ToLower(strings.TrimSpace(value))
	if host == "" || strings.ContainsAny(host, "/\\@") {
		return "", false
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String(), true
	}
	if strings.Contains(host, ":") || len(host) > 253 {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return "", false
			}
		}
	}
	return host, true
}

func between(value, minimum, maximum float64) bool {
	return value >= minimum && value <= maximum
}

func seconds(value float64) time.Duration {
	return time.Duration(value * float64(time.Second))
}

func invalid(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalid, message)
}
