// Package admission provides bounded active-request and FIFO short-queue control.
package admission

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type Result uint8

const (
	Acquired Result = iota
	Busy
	Closed
	Canceled
)

type waiter struct {
	ready  chan struct{}
	done   bool
	result Result
}

type Controller struct {
	mu        sync.Mutex
	maxActive int
	maxQueued int
	wait      time.Duration
	active    int
	queue     []*waiter
	closed    bool
	activeNow atomic.Int64
	queuedNow atomic.Int64
}

func New(maxActive, maxQueued int, wait time.Duration) *Controller {
	controller := &Controller{
		maxActive: maxActive,
		maxQueued: maxQueued,
		wait:      wait,
		queue:     make([]*waiter, 0, max(0, maxQueued)),
	}
	if maxActive < 1 || maxQueued < 0 || wait <= 0 {
		controller.closed = true
	}
	return controller
}

// Acquire admits work immediately only when capacity is available and no older
// waiter exists. Once a queue forms, releases promote waiters in FIFO order so
// new requests cannot bypass or starve them.
func (c *Controller) Acquire(ctx context.Context) (release func(), result Result) {
	if c == nil || ctx == nil {
		return nil, Closed
	}
	if ctx.Err() != nil {
		return nil, Canceled
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, Closed
	}
	if c.maxActive > 0 && c.active < c.maxActive && len(c.queue) == 0 {
		c.active++
		c.activeNow.Add(1)
		c.mu.Unlock()
		return c.releaseFunc(), Acquired
	}
	if c.maxQueued <= 0 || len(c.queue) >= c.maxQueued {
		c.mu.Unlock()
		return nil, Busy
	}
	current := &waiter{ready: make(chan struct{})}
	c.queue = append(c.queue, current)
	c.queuedNow.Add(1)
	c.mu.Unlock()

	timer := time.NewTimer(c.wait)
	defer stopTimer(timer)
	fallback := Busy
	select {
	case <-current.ready:
		return c.waiterResult(current)
	case <-timer.C:
		fallback = Busy
	case <-ctx.Done():
		fallback = Canceled
	}
	return c.cancelOrObserve(current, fallback)
}

func (c *Controller) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	queued := c.queue
	c.queue = nil
	if len(queued) > 0 {
		c.queuedNow.Add(-int64(len(queued)))
	}
	for _, current := range queued {
		current.done = true
		current.result = Closed
		close(current.ready)
	}
	c.mu.Unlock()
}

func (c *Controller) Active() int64 {
	if c == nil {
		return 0
	}
	return c.activeNow.Load()
}

func (c *Controller) Queued() int64 {
	if c == nil {
		return 0
	}
	return c.queuedNow.Load()
}

func (c *Controller) waiterResult(current *waiter) (func(), Result) {
	c.mu.Lock()
	result := current.result
	done := current.done
	c.mu.Unlock()
	if !done || result != Acquired {
		return nil, result
	}
	return c.releaseFunc(), Acquired
}

func (c *Controller) cancelOrObserve(current *waiter, fallback Result) (func(), Result) {
	c.mu.Lock()
	if current.done {
		result := current.result
		c.mu.Unlock()
		if result == Acquired {
			return c.releaseFunc(), Acquired
		}
		return nil, result
	}
	for index, queued := range c.queue {
		if queued != current {
			continue
		}
		copy(c.queue[index:], c.queue[index+1:])
		c.queue[len(c.queue)-1] = nil
		c.queue = c.queue[:len(c.queue)-1]
		c.queuedNow.Add(-1)
		break
	}
	current.done = true
	current.result = fallback
	c.mu.Unlock()
	return nil, fallback
}

func (c *Controller) releaseFunc() func() {
	var once sync.Once
	return func() {
		once.Do(c.release)
	}
}

func (c *Controller) release() {
	c.mu.Lock()
	if c.active > 0 {
		c.active--
		c.activeNow.Add(-1)
	}
	if !c.closed && len(c.queue) > 0 && c.active < c.maxActive {
		current := c.queue[0]
		copy(c.queue, c.queue[1:])
		c.queue[len(c.queue)-1] = nil
		c.queue = c.queue[:len(c.queue)-1]
		c.queuedNow.Add(-1)
		c.active++
		c.activeNow.Add(1)
		current.done = true
		current.result = Acquired
		close(current.ready)
	}
	c.mu.Unlock()
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
