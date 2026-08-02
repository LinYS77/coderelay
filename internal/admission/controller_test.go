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

func TestQueuedRequestWaitsForConfiguredTwoSeconds(t *testing.T) {
	controller := New(1, 1, 2*time.Second)
	release, result := controller.Acquire(context.Background())
	if result != Acquired {
		t.Fatal(result)
	}
	defer release()

	started := time.Now()
	if _, result := controller.Acquire(context.Background()); result != Busy {
		t.Fatalf("queued result=%v, want Busy", result)
	}
	elapsed := time.Since(started)
	if elapsed < 1900*time.Millisecond || elapsed > 2500*time.Millisecond {
		t.Fatalf("queue wait=%s, want approximately 2s", elapsed)
	}
	if controller.Queued() != 0 {
		t.Fatalf("queued=%d after timeout", controller.Queued())
	}
}

func TestQueuedRequestsArePromotedFIFOWithoutNewArrivalBypass(t *testing.T) {
	controller := New(1, 2, time.Second)
	initialRelease, result := controller.Acquire(context.Background())
	if result != Acquired {
		t.Fatal(result)
	}

	type acquisition struct {
		id      int
		release func()
		result  Result
	}
	acquired := make(chan acquisition, 3)
	for id := 1; id <= 2; id++ {
		go func() {
			release, result := controller.Acquire(context.Background())
			acquired <- acquisition{id: id, release: release, result: result}
		}()
		waitForCount(t, controller.Queued, int64(id))
	}

	initialRelease()
	first := <-acquired
	if first.id != 1 || first.result != Acquired {
		t.Fatalf("first promotion=%+v, want queued request 1", first)
	}

	newArrival := make(chan acquisition, 1)
	go func() {
		release, result := controller.Acquire(context.Background())
		newArrival <- acquisition{id: 3, release: release, result: result}
	}()
	waitForCount(t, controller.Queued, 2)
	first.release()
	second := <-acquired
	if second.id != 2 || second.result != Acquired {
		t.Fatalf("second promotion=%+v, want queued request 2", second)
	}
	second.release()
	third := <-newArrival
	if third.id != 3 || third.result != Acquired {
		t.Fatalf("third promotion=%+v", third)
	}
	third.release()
	if controller.Active() != 0 || controller.Queued() != 0 {
		t.Fatalf("active=%d queued=%d", controller.Active(), controller.Queued())
	}
}

func TestAlreadyCanceledContextIsNotAdmitted(t *testing.T) {
	controller := New(1, 1, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if release, result := controller.Acquire(ctx); release != nil || result != Canceled {
		t.Fatalf("release=%v result=%v", release != nil, result)
	}
	if controller.Active() != 0 || controller.Queued() != 0 {
		t.Fatal("canceled request changed admission counts")
	}
}

func TestConcurrentCancellationReleaseAndCloseDrainsCounts(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		controller := New(4, 4, 10*time.Millisecond)
		start := make(chan struct{})
		var wait sync.WaitGroup
		for request := 0; request < 16; request++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(request%3+1)*time.Millisecond)
				defer cancel()
				<-start
				release, result := controller.Acquire(ctx)
				if result == Acquired {
					time.Sleep(time.Duration(request%2) * time.Millisecond)
					release()
					release()
				}
			}()
		}
		close(start)
		time.Sleep(time.Millisecond)
		controller.Close()
		wait.Wait()
		if controller.Active() != 0 || controller.Queued() != 0 {
			t.Fatalf("iteration=%d active=%d queued=%d", iteration, controller.Active(), controller.Queued())
		}
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
