package flysms

import (
	"testing"
	"time"
)

func FuzzResponseContracts(f *testing.F) {
	f.Add([]byte(`{"email":"box@example.com","entitlementStatus":"active","message":{"mailbox":"INBOX","uid":1,"subject":"Code","from":"sender@example.com","date":"2026-08-02T04:00:00Z","text":"verification code 123456","html":""}}`), true)
	f.Add([]byte(`{"email":"box@example.com","messages":[]}`), false)
	f.Add([]byte(`null`), true)
	f.Fuzz(func(t *testing.T, value []byte, detail bool) {
		if len(value) > detailResponseLimit {
			return
		}
		if detail {
			message, _ := decodeDetail(value, "box@example.com", nil)
			message.Destroy()
			return
		}
		messages, _ := decodeHistory(value, "box@example.com")
		destroyMessages(messages)
	})
}

func FuzzRetryAfter(f *testing.F) {
	f.Add("17")
	f.Add("Wed, 21 Oct 2015 07:28:00 GMT")
	f.Add("invalid")
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4_096 {
			return
		}
		result := parseRetryAfter(value, 2, time.Unix(0, 0).UTC())
		if result < 1 || result > 300 {
			t.Fatalf("retry-after result=%d", result)
		}
	})
}
