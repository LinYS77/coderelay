// Package admission provides bounded active-request and short-queue control.
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

type Controller struct {
	active    chan struct{}
	queue     chan struct{}
	wait      time.Duration
	shutdown  chan struct{}
	closeOnce sync.Once
	activeNow atomic.Int64
	queuedNow atomic.Int64
}

func New(maxActive, maxQueued int, wait time.Duration) *Controller {
	return &Controller{
		active:   make(chan struct{}, maxActive),
		queue:    make(chan struct{}, maxQueued),
		wait:     wait,
		shutdown: make(chan struct{}),
	}
}

func (c *Controller) Acquire(ctx context.Context) (release func(), result Result) {
	if c == nil {
		return nil, Closed
	}
	select {
	case <-c.shutdown:
		return nil, Closed
	default:
	}

	select {
	case c.active <- struct{}{}:
		if c.isClosed() {
			<-c.active
			return nil, Closed
		}
		c.activeNow.Add(1)
		return c.releaseFunc(), Acquired
	default:
	}

	select {
	case c.queue <- struct{}{}:
		c.queuedNow.Add(1)
	case <-c.shutdown:
		return nil, Closed
	default:
		return nil, Busy
	}
	defer func() {
		<-c.queue
		c.queuedNow.Add(-1)
	}()

	timer := time.NewTimer(c.wait)
	defer stopTimer(timer)
	select {
	case c.active <- struct{}{}:
		if c.isClosed() {
			<-c.active
			return nil, Closed
		}
		c.activeNow.Add(1)
		return c.releaseFunc(), Acquired
	case <-timer.C:
		return nil, Busy
	case <-ctx.Done():
		return nil, Canceled
	case <-c.shutdown:
		return nil, Closed
	}
}

func (c *Controller) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() { close(c.shutdown) })
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

func (c *Controller) isClosed() bool {
	select {
	case <-c.shutdown:
		return true
	default:
		return false
	}
}

func (c *Controller) releaseFunc() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			<-c.active
			c.activeNow.Add(-1)
		})
	}
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
