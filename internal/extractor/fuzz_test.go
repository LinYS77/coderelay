package extractor

import (
	"errors"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/domain"
)

func FuzzExtractor(f *testing.F) {
	f.Add("Verification code 123456", "", "", "sender@example.com")
	f.Add("", "Security code 654321", `<script>Code 111111</script>`, "Service <sender@example.com>")
	f.Add("验证码 １２３４５６", "Straße 246810", `<p>OTP&nbsp;135790</p>`, "")
	extractor, err := New(DefaultSettings())
	if err != nil {
		f.Fatal(err)
	}
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, subject, text, html, sender string) {
		code, err := extractor.Extract([]Message{{
			ID:         "fuzz",
			UID:        1,
			Subject:    subject,
			Sender:     sender,
			ReceivedAt: now,
			Text:       text,
			HTML:       html,
		}}, nil, now)
		if err != nil && !errors.Is(err, domain.ErrAmbiguousCode) {
			t.Fatalf("unexpected error: %v", err)
		}
		if code != "" && !sixASCIIDigits(code) {
			t.Fatalf("non-ASCII code %q", code)
		}
	})
}
