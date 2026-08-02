package service

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestBoundedListenerWaitsForConnectionSlotAndCloses(t *testing.T) {
	base := newTestListener()
	listener := newBoundedListener(base, 1)
	serverOne, clientOne := net.Pipe()
	defer clientOne.Close()
	base.pending <- serverOne
	first, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	<-base.acceptCalled

	serverTwo, clientTwo := net.Pipe()
	defer clientTwo.Close()
	base.pending <- serverTwo
	secondResult := make(chan net.Conn, 1)
	secondError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		secondResult <- connection
		secondError <- err
	}()
	select {
	case <-base.acceptCalled:
		t.Fatal("underlying listener accepted beyond the configured limit")
	case <-time.After(20 * time.Millisecond):
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-base.acceptCalled:
	case <-time.After(time.Second):
		t.Fatal("slot release did not resume Accept")
	}
	second := <-secondResult
	if err := <-secondError; err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close error = %v", err)
	}
}

type testListener struct {
	pending      chan net.Conn
	acceptCalled chan struct{}
	closed       chan struct{}
	closeOnce    sync.Once
}

func newTestListener() *testListener {
	return &testListener{
		pending:      make(chan net.Conn, 2),
		acceptCalled: make(chan struct{}, 2),
		closed:       make(chan struct{}),
	}
}

func (l *testListener) Accept() (net.Conn, error) {
	l.acceptCalled <- struct{}{}
	select {
	case connection := <-l.pending:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *testListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (*testListener) Addr() net.Addr { return testAddress("test") }

type testAddress string

func (a testAddress) Network() string { return string(a) }
func (a testAddress) String() string  { return string(a) }
