package totp

import (
	"context"
	"encoding/base32"
	"errors"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/credential"
)

const rfcSHA1Base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestRFC6238SixDigitVectors(t *testing.T) {
	t.Parallel()
	timestamps := []int64{59, 1_111_111_109, 1_111_111_111, 1_234_567_890, 2_000_000_000, 20_000_000_000}
	vectors := []struct {
		name      string
		secret    string
		algorithm string
		expected  []string
	}{
		{name: "sha1", secret: "12345678901234567890", algorithm: "SHA1", expected: []string{"287082", "081804", "050471", "005924", "279037", "353130"}},
		{name: "sha256", secret: "12345678901234567890123456789012", algorithm: "SHA256", expected: []string{"119246", "084774", "062674", "819424", "698825", "737706"}},
		{name: "sha512", secret: "1234567890123456789012345678901234567890123456789012345678901234", algorithm: "SHA512", expected: []string{"693936", "091201", "943326", "441116", "618901", "863826"}},
	}
	for _, vector := range vectors {
		vector := vector
		t.Run(vector.name, func(t *testing.T) {
			t.Parallel()
			encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(vector.secret))
			uri := "otpauth://totp/Example:alice?secret=" + encoded + "&issuer=Example&algorithm=" + vector.algorithm + "&digits=6&period=30"
			for i, timestamp := range timestamps {
				code, err := resolveAt(t, uri, 0, time.Unix(timestamp, 0).UTC())
				if err != nil {
					t.Fatalf("time %d Resolve: %v", timestamp, err)
				}
				if string(code[:]) != vector.expected[i] {
					t.Fatalf("time %d code = %q, want %q", timestamp, code, vector.expected[i])
				}
			}
		})
	}
}

func TestWindowBoundaryAtOneNanosecond(t *testing.T) {
	before, err := resolveAt(t, rfcSHA1Base32, 0, time.Unix(59, 999_999_999))
	if err != nil {
		t.Fatal(err)
	}
	after, err := resolveAt(t, rfcSHA1Base32, 0, time.Unix(60, 0))
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("code did not change at the exact TOTP boundary")
	}
	if got := remainingInPeriod(time.Unix(60, 0), 30); got != 30*time.Second {
		t.Fatalf("remaining at boundary = %s", got)
	}
}

func TestRawBase32CompatibilityValue(t *testing.T) {
	code, err := resolveAt(t, "  GEZD GNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n", 0, time.Unix(1_111_111_111, 0).UTC())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(code[:]) != "050471" {
		t.Fatalf("code = %q, want 050471", code)
	}
}

func TestURIValidation(t *testing.T) {
	t.Parallel()
	cases := []string{
		"otpauth://hotp/Test?secret=" + rfcSHA1Base32 + "&counter=0",
		"otpauth://totp/Test?secret=" + rfcSHA1Base32 + "&digits=8",
		"otpauth://totp/Test?secret=" + rfcSHA1Base32 + "&digits=",
		"otpauth://totp/Test?secret=" + rfcSHA1Base32 + "&algorithm=",
		"otpauth://totp/Test?secret=" + rfcSHA1Base32 + "&period=",
		"otpauth://totp/Test?secret=" + rfcSHA1Base32 + "&period=0",
		"otpauth://totp/Test?secret=" + rfcSHA1Base32 + "&encoder=",
		"otpauth://totp/Test?secret=" + rfcSHA1Base32 + "&secret=" + rfcSHA1Base32,
		"otpauth://totp/Issuer:alice?secret=" + rfcSHA1Base32 + "&issuer=Other",
		"otpauth://totp/?secret=" + rfcSHA1Base32,
		"otpauth://totp/Test?secret=not-base32!",
	}
	for _, value := range cases {
		secret := credential.NewOwned([]byte(value))
		_, err := New().Resolve(context.Background(), secret, 0)
		secret.Destroy()
		if !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("credential unexpectedly accepted; error=%v", err)
		}
	}
}

func TestEncodedColonInLabelIsNotIssuerSeparator(t *testing.T) {
	uri := "otpauth://totp/alice%3Awork?secret=" + rfcSHA1Base32
	if _, err := resolveAt(t, uri, 0, time.Unix(59, 0)); err != nil {
		t.Fatalf("encoded label colon was rejected: %v", err)
	}
}

func TestMinTTLWaitsForNextWindow(t *testing.T) {
	now := time.Unix(59, 500_000_000).UTC()
	generator := &Generator{now: func() time.Time { return now }}
	var waited time.Duration
	generator.wait = func(_ context.Context, duration time.Duration) error {
		waited = duration
		now = now.Add(duration)
		return nil
	}
	secret := credential.NewOwned([]byte(rfcSHA1Base32))
	defer secret.Destroy()
	code, err := generator.Resolve(context.Background(), secret, 5)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if waited < 500*time.Millisecond || waited > 510*time.Millisecond {
		t.Fatalf("waited %s, want about 501ms", waited)
	}
	if string(code[:]) == "287082" {
		t.Fatal("code did not advance to the next window")
	}
}

func TestMinTTLRejectsPeriodAndCancellation(t *testing.T) {
	secret := credential.NewOwned([]byte(rfcSHA1Base32))
	defer secret.Destroy()
	if _, err := New().Resolve(context.Background(), secret, 30); !errors.Is(err, ErrInvalidMinTTL) {
		t.Fatalf("min TTL error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	generator := &Generator{
		now: func() time.Time { return time.Unix(59, 500_000_000) },
		wait: func(ctx context.Context, _ time.Duration) error {
			return ctx.Err()
		},
	}
	if _, err := generator.Resolve(ctx, secret, 5); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func BenchmarkResolveTOTP(b *testing.B) {
	generator := &Generator{now: func() time.Time { return time.Unix(1_111_111_111, 0) }, wait: waitContext}
	for i := 0; i < b.N; i++ {
		secret := credential.NewOwned([]byte(rfcSHA1Base32))
		if _, err := generator.Resolve(context.Background(), secret, 0); err != nil {
			b.Fatal(err)
		}
		secret.Destroy()
	}
}

func resolveAt(t *testing.T, value string, minTTL int, now time.Time) ([6]byte, error) {
	t.Helper()
	generator := &Generator{now: func() time.Time { return now }, wait: waitContext}
	secret := credential.NewOwned([]byte(value))
	defer secret.Destroy()
	return generator.Resolve(context.Background(), secret, minTTL)
}
