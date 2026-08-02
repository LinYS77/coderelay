package service

import (
	"net"
	"sync"
)

// boundedListener caps accepted inbound connections, which also bounds the
// request goroutines and file descriptors owned by net/http. Excess clients
// remain in the kernel's bounded listen backlog until a slot is available.
type boundedListener struct {
	net.Listener
	slots     chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newBoundedListener(listener net.Listener, maximum int) net.Listener {
	return &boundedListener{
		Listener: listener,
		slots:    make(chan struct{}, maximum),
		closed:   make(chan struct{}),
	}
}

func (l *boundedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &boundedConnection{Conn: connection, release: func() { <-l.slots }}, nil
}

func (l *boundedListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		l.closeErr = l.Listener.Close()
	})
	return l.closeErr
}

type boundedConnection struct {
	net.Conn
	release   func()
	closeOnce sync.Once
	closeErr  error
}

func (c *boundedConnection) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		c.release()
	})
	return c.closeErr
}
