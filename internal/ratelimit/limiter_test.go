package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenBucketRefillAndRetry(t *testing.T) {
	now := time.Unix(1_000, 0)
	limiter := New(2, 2, 10)
	limiter.now = func() time.Time { return now }
	first := limiter.Allow("key")
	second := limiter.Allow("key")
	if !first.Allowed || !second.Allowed {
		t.Fatal("initial burst was rejected")
	}
	decision := limiter.Allow("key")
	if decision.Allowed || decision.RetryAfterSeconds != 30 {
		t.Fatalf("decision = %+v", decision)
	}
	now = now.Add(30 * time.Second)
	if !limiter.Allow("key").Allowed {
		t.Fatal("refilled token was rejected")
	}
}

func TestBoundedMapFailsClosedAndCleansIdle(t *testing.T) {
	now := time.Unix(1_000, 0)
	limiter := New(60, 10, 2)
	limiter.now = func() time.Time { return now }
	if !limiter.Allow("one").Allowed || !limiter.Allow("two").Allowed {
		t.Fatal("initial keys were rejected")
	}
	decision := limiter.Allow("three")
	if decision.Allowed || !decision.CapacityExhausted || limiter.EntryCount() != 2 {
		t.Fatalf("capacity decision = %+v entries=%d", decision, limiter.EntryCount())
	}
	now = now.Add(3 * time.Minute)
	limiter.cleanup(now, 2*time.Minute)
	if limiter.EntryCount() != 0 || !limiter.Allow("three").Allowed {
		t.Fatal("idle entries were not cleaned")
	}
}

func TestConcurrentSameKeyConsumesOnlyBurst(t *testing.T) {
	limiter := New(240, 40, 100)
	fixed := time.Unix(1_000, 0)
	limiter.now = func() time.Time { return fixed }
	var allowed atomic.Int64
	var wait sync.WaitGroup
	for i := 0; i < 100; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if limiter.Allow("shared").Allowed {
				allowed.Add(1)
			}
		}()
	}
	wait.Wait()
	if allowed.Load() != 40 {
		t.Fatalf("allowed = %d, want 40", allowed.Load())
	}
	if limiter.EntryCount() != 1 {
		t.Fatalf("entries = %d, want 1", limiter.EntryCount())
	}
}
