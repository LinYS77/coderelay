package probe

import (
	"context"
	"os"
	"runtime"
	"time"
)

type ResourceSnapshot struct {
	Goroutines int `json:"goroutines"`
	OpenFDs    int `json:"open_fds"`
}

type LeakReport struct {
	Iterations     int              `json:"iterations"`
	Completed      int              `json:"completed"`
	DelayMillis    int64            `json:"delay_millis"`
	Supported      bool             `json:"supported"`
	Before         ResourceSnapshot `json:"before"`
	After          ResourceSnapshot `json:"after"`
	GoroutineDelta int              `json:"goroutine_delta"`
	FDDelta        int              `json:"fd_delta"`
	Passed         bool             `json:"passed"`
}

func RunLeakCheck(ctx context.Context, iterations int, delay time.Duration, operation func(context.Context) error) (LeakReport, error) {
	report := LeakReport{Iterations: iterations, DelayMillis: delay.Milliseconds()}
	if iterations <= 0 {
		return report, nil
	}

	settleRuntime()
	before, supported := resourceSnapshot()
	report.Before = before
	report.Supported = supported
	for i := 0; i < iterations; i++ {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				finishLeakReport(&report)
				return report, ctx.Err()
			case <-timer.C:
			}
		}
		if err := operation(ctx); err != nil {
			finishLeakReport(&report)
			return report, err
		}
		report.Completed++
	}
	finishLeakReport(&report)
	return report, nil
}

func finishLeakReport(report *LeakReport) {
	settleRuntime()
	after, afterSupported := resourceSnapshot()
	report.After = after
	report.Supported = report.Supported && afterSupported
	report.GoroutineDelta = after.Goroutines - report.Before.Goroutines
	report.FDDelta = after.OpenFDs - report.Before.OpenFDs
	report.Passed = report.Supported && report.Completed == report.Iterations && report.GoroutineDelta <= 0 && report.FDDelta <= 0
}

func resourceSnapshot() (ResourceSnapshot, bool) {
	snapshot := ResourceSnapshot{Goroutines: runtime.NumGoroutine(), OpenFDs: -1}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return snapshot, false
	}
	snapshot.OpenFDs = len(entries)
	return snapshot, true
}

func settleRuntime() {
	runtime.GC()
	runtime.GC()
	time.Sleep(250 * time.Millisecond)
}
