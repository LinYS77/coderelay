package extractor

import (
	"errors"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/domain"
)

func TestExtractFreshCodeFromTextSubjectAndHTML(t *testing.T) {
	now := time.Date(2026, 8, 2, 4, 0, 0, 0, time.UTC)
	extractor := New(DefaultSettings())
	cases := []Message{
		{UID: 1, ReceivedAt: now.Add(-time.Second), Subject: "Notice", Text: "Your verification code is 123456"},
		{UID: 2, ReceivedAt: now.Add(-time.Second), Subject: "Security code 654321"},
		{UID: 3, ReceivedAt: now.Add(-time.Second), Subject: "Notice", HTML: `<script>code 999999</script><p>One-time code: <b>112233</b></p>`},
	}
	expected := []string{"123456", "654321", "112233"}
	for i, message := range cases {
		code, err := extractor.Extract([]Message{message}, nil, now)
		if err != nil || code != expected[i] {
			t.Fatalf("case %d code=%q error=%v", i, code, err)
		}
	}
}

func TestExtractHonorsFreshnessKeywordsURLsAndASCII(t *testing.T) {
	now := time.Date(2026, 8, 2, 4, 0, 0, 0, time.UTC)
	extractor := New(DefaultSettings())
	notBefore := now.Add(-time.Minute)
	messages := []Message{
		{UID: 4, ReceivedAt: now.Add(-2 * time.Minute), Subject: "Verification code 111111"},
		{UID: 3, ReceivedAt: now.Add(-time.Second), Text: "number 222222 without keyword"},
		{UID: 2, ReceivedAt: now.Add(-time.Second), Text: "verification code https://example.test/333333"},
		{UID: 1, ReceivedAt: now.Add(-time.Second), Text: "verification code １２３４５６"},
	}
	code, err := extractor.Extract(messages, &notBefore, now)
	if err != nil || code != "" {
		t.Fatalf("code=%q error=%v", code, err)
	}
}

func TestExtractRejectsEqualScoreAmbiguity(t *testing.T) {
	now := time.Now().UTC()
	extractor := New(DefaultSettings())
	_, err := extractor.Extract([]Message{{ReceivedAt: now, Subject: "verification code 123456 or 654321"}}, nil, now)
	if !errors.Is(err, domain.ErrAmbiguousCode) {
		t.Fatalf("error=%v", err)
	}
}

func TestNewestMessageAndUIDWin(t *testing.T) {
	now := time.Now().UTC()
	extractor := New(DefaultSettings())
	code, err := extractor.Extract([]Message{
		{UID: 1, ReceivedAt: now.Add(-time.Second), Subject: "verification code 111111"},
		{UID: 2, ReceivedAt: now.Add(-time.Second), Subject: "verification code 222222"},
	}, nil, now)
	if err != nil || code != "222222" {
		t.Fatalf("code=%q error=%v", code, err)
	}
}
