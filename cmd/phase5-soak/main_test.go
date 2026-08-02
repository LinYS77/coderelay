package main

import (
	"encoding/json"
	"testing"
)

func TestSyntheticSecretsAreUniqueAndNeverReported(t *testing.T) {
	values := syntheticSecrets(40)
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if len(value) != 32 {
			t.Fatalf("secret length=%d", len(value))
		}
		if _, duplicate := seen[value]; duplicate {
			t.Fatal("duplicate synthetic secret")
		}
		seen[value] = struct{}{}
	}
}

func TestCredentialLogScanUsesStructuredStringFields(t *testing.T) {
	secret := []byte("synthetic-secret-value")
	code := []byte("123456")
	safe := []byte(`{"time":"2026-08-02T12:34:56.123456Z","level":"INFO","msg":"runtime_snapshot","heap_bytes":123456}` + "\n")
	if matches := countSensitiveMatches(safe, [][]byte{secret, code}); matches != 0 {
		t.Fatalf("safe numeric/timestamp matches=%d", matches)
	}
	leaked := []byte(`{"time":"2026-08-02T00:00:00Z","level":"ERROR","msg":"request failed for synthetic-secret-value and 123456"}` + "\n")
	if matches := countSensitiveMatches(leaked, [][]byte{secret, code}); matches != 2 {
		t.Fatalf("leaked matches=%d", matches)
	}
}

func TestRuntimeSnapshotParser(t *testing.T) {
	var first, second map[string]any
	first = map[string]any{"msg": "application_started"}
	second = map[string]any{"msg": "runtime_snapshot", "goroutines": 17}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	values := runtimeSnapshots(append(append(firstJSON, '\n'), secondJSON...))
	if len(values) != 1 || values[0] != 17 {
		t.Fatalf("snapshots=%v", values)
	}
}

func TestReportThresholds(t *testing.T) {
	passing := report{
		RequestedSeconds:   1,
		DurationSeconds:    1,
		Completed:          true,
		MinimumRequests:    100,
		Requests:           100,
		HTTP200:            100,
		GoroutinesBefore:   10,
		GoroutinesAfter:    10,
		GoroutinePeak:      10,
		FDBefore:           8,
		FDAfter:            8,
		RSSBeforeBytes:     8 * mib,
		RSSAfterBytes:      9 * mib,
		SteadyRSSPeakBytes: 255*mib - 1,
		StressRSSPeakBytes: 511*mib - 1,
		ExitClean:          true,
	}
	if err := validateReport(passing); err != nil {
		t.Fatal(err)
	}
	failing := passing
	failing.CredentialMismatch = 1
	if err := validateReport(failing); err == nil {
		t.Fatal("credential mismatch passed")
	}
	failing = passing
	failing.Completed = false
	if err := validateReport(failing); err == nil {
		t.Fatal("incomplete soak passed")
	}
	failing = passing
	failing.MinimumRequests = 101
	if err := validateReport(failing); err == nil {
		t.Fatal("insufficient request count passed")
	}
	failing = passing
	failing.SteadyRSSPeakBytes = 256 * mib
	if err := validateReport(failing); err == nil {
		t.Fatal("steady RSS threshold passed at the boundary")
	}
}
