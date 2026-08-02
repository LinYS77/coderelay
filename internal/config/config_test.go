package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExampleConfigLoadsAndIsBounded(t *testing.T) {
	cfg, err := Load("../../config.example.toml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Address() != "127.0.0.1:8787" {
		t.Fatalf("address = %s", cfg.Address())
	}
	if cfg.Server.MaxInboundConnections != 128 || cfg.Server.MaxConcurrentCodeRequests != 20 || cfg.Server.MaxQueuedCodeRequests != 4 || cfg.Server.AdmissionWaitSeconds != 2 {
		t.Fatal("connection or admission defaults are wrong")
	}
	if cfg.Server.MaxWaitSeconds != 30 || cfg.Server.HTTPMaxConnections != 20 || cfg.Providers.FlySMS.BaseURL != FlySMSBaseURL {
		t.Fatal("FlySMS HTTP defaults are wrong")
	}
	if cfg.Security.APIRateLimitBurst != 40 || cfg.Security.APIRateLimitPerMinute != 240 || cfg.Security.MaxIPRateLimitEntries != 10_000 || cfg.Security.MaxPrincipalRateLimitEntries != 1_000 {
		t.Fatal("rate defaults are wrong")
	}
	if len(cfg.Providers.Outlook.Extractor.Patterns) != 1 || cfg.Providers.Outlook.Extractor.GenericRequiresKeyword || len(cfg.Providers.FlySMS.Extractor.Patterns) != 1 {
		t.Fatal("extractor configuration was not loaded")
	}
	if !filepath.IsAbs(cfg.Security.APITokenHashFiles[0]) {
		t.Fatal("token hash path was not resolved")
	}
}

func TestDefaultsSurvivePartialTOML(t *testing.T) {
	path := writeConfig(t, "[security]\napi_token_hash_files = [\"api.sha256\"]\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Security.StrictSecretPermissions || cfg.Server.MaxBodyBytes != 128<<10 {
		t.Fatal("defaults were not retained")
	}
}

func TestConfigRejectsUnknownLegacyAndUnsafeFields(t *testing.T) {
	cases := []string{
		"[security]\napi_token_hash_files=[\"x\"]\n[[sources]]\ntype=\"totp\"\n",
		"[server]\nhost=\"0.0.0.0\"\n[security]\napi_token_hash_files=[\"x\"]\n",
		"[server]\nallowed_hosts=[\"*\"]\n[security]\napi_token_hash_files=[\"x\"]\n",
		"[server]\nmax_concurrent_code_requests=20\n[security]\napi_token_hash_files=[\"x\"]\napi_rate_limit_burst=19\n",
		"[server]\nmax_inbound_connections=23\n[security]\napi_token_hash_files=[\"x\"]\n",
		"[server]\nwrite_timeout_seconds=40\n[security]\napi_token_hash_files=[\"x\"]\n",
		"[server]\ncors_origins=[\"https://example.com\"]\n[security]\napi_token_hash_files=[\"x\"]\n",
		"[server]\nforwarded_allow_ips=\"203.0.113.1\"\n[security]\napi_token_hash_files=[\"x\"]\n",
		"[security]\napi_token_hash_files=[\"x\"]\nmax_ip_rate_limit_entries=100001\n",
		"[security]\napi_token_hash_files=[\"x\"]\nstrict_secret_permissions=false\n",
		"[security]\napi_token_hash_files=[\"   \"]\n",
		"[server]\nhttp_max_connections=19\n[security]\napi_token_hash_files=[\"x\"]\n",
		"[providers.flysms]\nbase_url=\"https://example.com/icloud/api/pickup/messages\"\n[security]\napi_token_hash_files=[\"x\"]\n",
		"[providers.flysms]\nmax_detail_messages=11\n[security]\napi_token_hash_files=[\"x\"]\n",
	}
	for _, value := range cases {
		path := writeConfig(t, value)
		if _, err := Load(path); !errors.Is(err, ErrInvalid) {
			t.Errorf("unsafe config unexpectedly accepted; error=%v", err)
		}
	}
}

func TestExtractorConfigNormalizesAndRejectsNonRE2(t *testing.T) {
	valid := `[providers.outlook.extractor]
senders=[" ALERTS@Example.com ", "alerts@example.com"]
sender_domains=[" @Trusted.Example "]
subject_keywords=[" Straße ", "STRASSE"]
patterns=['(?i)code\s*(?P<code>\d{6})']
max_age_seconds=30
allow_generic_fallback=false
generic_requires_keyword=false
max_text_chars=1000
[security]
api_token_hash_files=["x"]
`
	cfg, err := Load(writeConfig(t, valid))
	if err != nil {
		t.Fatal(err)
	}
	settings := cfg.Providers.Outlook.Extractor
	if len(settings.Senders) != 1 || settings.Senders[0] != "alerts@example.com" || len(settings.SenderDomains) != 1 || settings.SenderDomains[0] != "trusted.example" {
		t.Fatalf("normalized sender settings = %+v", settings)
	}
	if len(settings.SubjectKeywords) != 1 || settings.SubjectKeywords[0] != "strasse" || settings.AllowGenericFallback || settings.GenericRequiresKeyword {
		t.Fatalf("normalized keyword settings = %+v", settings)
	}

	invalidPatterns := []string{
		`(?P<code>[0-9]{6})(?=x)`,
		`(?P<code>[0-9]{6})\1`,
		`([0-9]{6})`,
	}
	for _, pattern := range invalidPatterns {
		value := "[providers.outlook.extractor]\npatterns=['" + pattern + "']\n[security]\napi_token_hash_files=['x']\n"
		if _, err := Load(writeConfig(t, value)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("non-RE2 or unnamed pattern %q accepted: %v", pattern, err)
		}
	}
	for _, value := range []string{
		"[providers.outlook.extractor]\nsender_domains=['invalid']\n[security]\napi_token_hash_files=['x']\n",
		"[providers.outlook.extractor]\nmax_age_seconds=29\n[security]\napi_token_hash_files=['x']\n",
		"[providers.outlook.extractor]\nmax_text_chars=999\n[security]\napi_token_hash_files=['x']\n",
	} {
		if _, err := Load(writeConfig(t, value)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid extractor bounds accepted: %v", err)
		}
	}
}

func TestConfigRejectsMalformedAndOversizedTOML(t *testing.T) {
	if _, err := Load(writeConfig(t, "[[bad")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed TOML error = %v", err)
	}
	duplicate := "[server]\nport=8787\nport=8788\n[security]\napi_token_hash_files=[\"x\"]\n"
	if _, err := Load(writeConfig(t, duplicate)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate TOML key error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "large.toml")
	if err := os.WriteFile(path, make([]byte, maxConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized config error = %v", err)
	}
	valid := writeConfig(t, "[security]\napi_token_hash_files=[\"x\"]\n")
	link := filepath.Join(t.TempDir(), "config-link.toml")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink config error = %v", err)
	}
}

func writeConfig(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
