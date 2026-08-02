// Package ratelimit implements a bounded sharded token-bucket limiter.
package ratelimit

import (
	"context"
	"hash/fnv"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const shardCount = 64

type Decision struct {
	Allowed           bool
	RetryAfterSeconds int
	CapacityExhausted bool
}

type bucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type Limiter struct {
	shards     [shardCount]shard
	rate       float64
	burst      float64
	maxEntries int64
	entries    atomic.Int64
	now        func() time.Time
	startOnce  sync.Once
}

func New(perMinute, burst, maxEntries int) *Limiter {
	limiter := &Limiter{
		rate:       float64(perMinute) / 60,
		burst:      float64(burst),
		maxEntries: int64(maxEntries),
		now:        time.Now,
	}
	for i := range limiter.shards {
		limiter.shards[i].buckets = make(map[string]*bucket)
	}
	return limiter
}

func (l *Limiter) Allow(key string) Decision {
	if l == nil || key == "" || l.rate <= 0 || l.burst < 1 || l.maxEntries < 1 {
		return Decision{Allowed: false, RetryAfterSeconds: 1, CapacityExhausted: true}
	}
	now := l.now()
	current := &l.shards[shardIndex(key)]
	current.mu.Lock()
	defer current.mu.Unlock()

	entry := current.buckets[key]
	if entry == nil {
		if !l.reserveEntry() {
			return Decision{Allowed: false, RetryAfterSeconds: 1, CapacityExhausted: true}
		}
		entry = &bucket{tokens: l.burst, updated: now, lastSeen: now}
		current.buckets[key] = entry
	}

	elapsed := now.Sub(entry.updated).Seconds()
	if elapsed > 0 {
		entry.tokens = math.Min(l.burst, entry.tokens+elapsed*l.rate)
		entry.updated = now
	}
	entry.lastSeen = now
	if entry.tokens >= 1 {
		entry.tokens--
		return Decision{Allowed: true}
	}
	retry := int(math.Ceil((1 - entry.tokens) / l.rate))
	if retry < 1 {
		retry = 1
	} else if retry > 300 {
		retry = 300
	}
	return Decision{Allowed: false, RetryAfterSeconds: retry}
}

func (l *Limiter) StartCleanup(ctx context.Context, interval, idle time.Duration) {
	if l == nil || interval <= 0 || idle <= 0 {
		return
	}
	l.startOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case now := <-ticker.C:
					l.cleanup(now, idle)
				case <-ctx.Done():
					return
				}
			}
		}()
	})
}

func (l *Limiter) EntryCount() int64 {
	if l == nil {
		return 0
	}
	return l.entries.Load()
}

func (l *Limiter) cleanup(now time.Time, idle time.Duration) {
	for i := range l.shards {
		current := &l.shards[i]
		current.mu.Lock()
		for key, entry := range current.buckets {
			if now.Sub(entry.lastSeen) > idle {
				delete(current.buckets, key)
				l.entries.Add(-1)
			}
		}
		current.mu.Unlock()
	}
}

func (l *Limiter) reserveEntry() bool {
	for {
		current := l.entries.Load()
		if current >= l.maxEntries {
			return false
		}
		if l.entries.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func shardIndex(key string) uint64 {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(key))
	return hash.Sum64() % shardCount
}
