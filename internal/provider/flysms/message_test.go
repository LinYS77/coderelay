package flysms

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/LinYS77/coderelay/internal/domain"
)

func TestDateContractFormats(t *testing.T) {
	values := []string{
		"2026-08-02T04:00:00.123456Z",
		"2026-08-02T04:00:00",
		"Sun, 02 Aug 2026 04:00:00 +0000",
	}
	for _, value := range values {
		parsed, err := parseDate(value)
		if err != nil || parsed.Location() != time.UTC || parsed.Year() != 2026 {
			t.Fatalf("value=%q parsed=%v error=%v", value, parsed, err)
		}
	}
}

func TestHistoryContractRejectsTooManyMessagesAndInvalidUID(t *testing.T) {
	messages := make([]any, 51)
	for i := range messages {
		messages[i] = map[string]any{"mailbox": "INBOX", "uid": i + 1, "subject": "", "from": "", "date": "2026-08-02T04:00:00Z", "preview": ""}
	}
	payload, err := json.Marshal(map[string]any{"email": testEmail, "messages": messages})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	if _, err := decodeHistory(payload, testEmail); !errors.Is(err, domain.ErrUpstreamSchemaChanged) {
		t.Fatalf("too-many error=%v", err)
	}
	invalidUID := []byte(`{"mailbox":"INBOX","uid":true,"subject":"","from":"","date":"2026-08-02T04:00:00Z","preview":""}`)
	if _, err := decodeMessage(invalidUID, true); !errors.Is(err, domain.ErrUpstreamSchemaChanged) {
		t.Fatalf("UID error=%v", err)
	}
}
