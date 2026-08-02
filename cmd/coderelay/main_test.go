package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestSIGUSR1WritesOnlyBoundedRuntimeMetrics(t *testing.T) {
	lines := make(chan []byte, 1)
	logger := slog.New(slog.NewJSONHandler(channelWriter{lines: lines}, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := startRuntimeSnapshots(ctx, logger)
	defer stop()

	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-lines:
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("runtime log is not JSON: %v", err)
		}
		if event["msg"] != "runtime_snapshot" {
			t.Fatalf("message=%v", event["msg"])
		}
		for _, key := range []string{"goroutines", "heap_bytes", "heap_sys_bytes"} {
			value, ok := event[key].(float64)
			if !ok || value < 1 {
				t.Fatalf("%s=%v", key, event[key])
			}
		}
		for key := range event {
			switch key {
			case "time", "level", "msg", "goroutines", "heap_bytes", "heap_sys_bytes":
			default:
				t.Fatalf("unexpected runtime log field %q", key)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SIGUSR1 runtime snapshot was not logged")
	}
}

type channelWriter struct{ lines chan<- []byte }

func (w channelWriter) Write(value []byte) (int, error) {
	copyOfValue := append([]byte(nil), value...)
	w.lines <- copyOfValue
	return len(value), nil
}
