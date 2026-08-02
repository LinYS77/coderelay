package probe

import (
	"net"
	"sync"
	"time"
)

// cappedDeadlineConn prevents the IMAP library's internal five-minute literal
// deadline from extending beyond the request/stage deadline. Context
// cancellation still closes the connection independently.
type cappedDeadlineConn struct {
	net.Conn
	mu  sync.RWMutex
	cap time.Time
}

func newCappedDeadlineConn(conn net.Conn, cap time.Time) *cappedDeadlineConn {
	return &cappedDeadlineConn{Conn: conn, cap: cap}
}

func (c *cappedDeadlineConn) SetCap(deadline time.Time) {
	c.mu.Lock()
	c.cap = deadline
	c.mu.Unlock()
	_ = c.Conn.SetDeadline(deadline)
}

func (c *cappedDeadlineConn) capped(deadline time.Time) time.Time {
	c.mu.RLock()
	capDeadline := c.cap
	c.mu.RUnlock()
	if capDeadline.IsZero() {
		return deadline
	}
	if deadline.IsZero() || capDeadline.Before(deadline) {
		return capDeadline
	}
	return deadline
}

func (c *cappedDeadlineConn) SetDeadline(deadline time.Time) error {
	return c.Conn.SetDeadline(c.capped(deadline))
}

func (c *cappedDeadlineConn) SetReadDeadline(deadline time.Time) error {
	return c.Conn.SetReadDeadline(c.capped(deadline))
}

func (c *cappedDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	return c.Conn.SetWriteDeadline(c.capped(deadline))
}
