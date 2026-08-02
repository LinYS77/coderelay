package admission

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestTwentyActiveFourQueuedAndTwentyFifthBusy(t *testing.T) {
	controller := New(20, 4, 2*time.Second)
	releases := make([]func(), 0, 20)
	for i := 0; i < 20; i++ {
		release, result := controller.Acquire(context.Background())
		if result != Acquired {
			t.Fatalf("active request %d result=%v", i, result)
		}
		releases = append(releases, release)
	}

	results := make(chan Result, 4)
	queuedReleases := make(chan func(), 4)
	var wait sync.WaitGroup
	for i := 0; i < 4; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			release, result := controller.Acquire(context.Background())
			if release != nil {
				queuedReleases <- release
			}
			results <- result
		}()
	}
	waitForCount(t, controller.Queued, 4)

	started := time.Now()
	if _, result := controller.Acquire(context.Background()); result != Busy {
		t.Fatalf("25th result=%v, want Busy", result)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("25th rejection took %s", elapsed)
	}

	for i := 0; i < 4; i++ {
		releases[i]()
	}
	for i := 0; i < 4; i++ {
		if result := <-results; result != Acquired {
			t.Fatalf("queued result=%v", result)
		}
		(<-queuedReleases)()
	}
	for _, release := range releases[4:] {
		release()
	}
	wait.Wait()
	if controller.Active() != 0 || controller.Queued() != 0 {
		t.Fatalf("active=%d queued=%d", controller.Active(), controller.Queued())
	}
}

func TestCloseReleasesQueueWithoutCancelingActive(t *testing.T) {
	controller := New(1, 1, time.Minute)
	release, result := controller.Acquire(context.Background())
	if result != Acquired {
		t.Fatal(result)
	}
	queued := make(chan Result, 1)
	go func() {
		_, result := controller.Acquire(context.Background())
		queued <- result
	}()
	waitForCount(t, controller.Queued, 1)
	controller.Close()
	select {
	case result := <-queued:
		if result != Closed {
			t.Fatalf("queued result=%v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("queued request did not exit")
	}
	if controller.Active() != 1 {
		t.Fatal("active request was canceled by admission close")
	}
	release()
	if _, result := controller.Acquire(context.Background()); result != Closed {
		t.Fatalf("post-close result=%v", result)
	}
}

func TestQueuedContextCancellation(t *testing.T) {
	controller := New(1, 1, time.Minute)
	release, _ := controller.Acquire(context.Background())
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan Result, 1)
	go func() {
		_, current := controller.Acquire(ctx)
		result <- current
	}()
	waitForCount(t, controller.Queued, 1)
	cancel()
	if current := <-result; current != Canceled {
		t.Fatalf("result=%v", current)
	}
}

func waitForCount(t *testing.T, value func() int64, expected int64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if value() == expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("count=%d, want %d", value(), expected)
}
