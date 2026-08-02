package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

func FuzzBoundedTokenBucket(f *testing.F) {
	f.Add([]byte{4, 40, 1, 2, 3, 4, 5, 6})
	f.Add([]byte{1, 1, 0xff, 0, 0xff})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) < 2 {
			return
		}
		maximum := int(input[0]%32) + 1
		burst := int(input[1]%40) + 1
		now := time.Unix(1_000, 0)
		limiter := New(240, burst, maximum)
		limiter.now = func() time.Time { return now }
		for index, operation := range input[2:] {
			switch operation % 4 {
			case 0:
				now = now.Add(time.Duration(operation+1) * time.Millisecond)
			case 1:
				limiter.cleanup(now, time.Duration(operation+1)*time.Millisecond)
			default:
				decision := limiter.Allow(fmt.Sprintf("key-%d", int(operation)%64))
				if !decision.Allowed && (decision.RetryAfterSeconds < 1 || decision.RetryAfterSeconds > 300) {
					t.Fatalf("operation %d retry=%d", index, decision.RetryAfterSeconds)
				}
			}
			if entries := limiter.EntryCount(); entries < 0 || entries > int64(maximum) {
				t.Fatalf("operation %d entries=%d maximum=%d", index, entries, maximum)
			}
		}
	})
}
