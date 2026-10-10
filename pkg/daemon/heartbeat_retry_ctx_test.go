package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// TestSleepCtxReturnsTrueOnFullSleep confirms sleepCtx reports a completed
// sleep when ctx stays live.
func TestSleepCtxReturnsTrueOnFullSleep(t *testing.T) {
	if !sleepCtx(context.Background(), 10*time.Millisecond) {
		t.Fatal("sleepCtx returned false for a full, uncancelled sleep")
	}
}

// TestSleepCtxReturnsFalseOnCancel confirms sleepCtx short-circuits and reports
// cancellation when ctx is cancelled during the sleep.
func TestSleepCtxReturnsFalseOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if sleepCtx(ctx, 30*time.Second) {
		t.Fatal("sleepCtx returned true despite ctx cancellation")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("sleepCtx did not wake on cancel promptly: took %v", elapsed)
	}
}

// TestStartHeartbeatWithRetryExitsBeforeStartOnCancel pins the #4033 fix: the
// bind-retry goroutine must observe ctx and bail BEFORE calling StartHeartbeat
// when comms have already been torn down. With a pre-cancelled ctx the loop
// returns without ever installing a heartbeat.
func TestStartHeartbeatWithRetryExitsBeforeStartOnCancel(t *testing.T) {
	d := &Daemon{cluster: cluster.NewManager(0, 1)}
	defer d.cluster.StopHeartbeat()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // comms already torn down

	done := make(chan struct{})
	go func() {
		// A real control interface would resolve here, but the ctx guard runs
		// first, so the interface name is irrelevant.
		d.startHeartbeatWithRetry(ctx, "127.0.0.1", "127.0.0.1")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startHeartbeatWithRetry did not exit on a cancelled ctx (ignored commsCtx)")
	}

	// No heartbeat may have been installed.
	if d.cluster.HeartbeatRunning() {
		t.Fatal("startHeartbeatWithRetry installed a heartbeat despite a cancelled ctx")
	}
}

// TestStartHeartbeatWithRetryExitsMidRetryOnCancel pins the ctx-aware retry
// sleep: with an unresolvable control interface the loop parks in sleepCtx;
// cancelling ctx must wake it and return well within the 30 * 2s = 60s
// worst-case retry budget. On revert (time.Sleep, ctx ignored) this blocks for
// the full budget and the test times out RED.
func TestStartHeartbeatWithRetryExitsMidRetryOnCancel(t *testing.T) {
	d := &Daemon{cluster: cluster.NewManager(0, 1)}
	defer d.cluster.StopHeartbeat()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	start := time.Now()
	go func() {
		// "xpf-nonexistent-4033" does not exist, so resolveClusterInterfaceAddr
		// returns "" and the loop parks in the ctx-aware retry sleep.
		d.startHeartbeatWithRetry(ctx, "xpf-nonexistent-4033", "127.0.0.1")
		close(done)
	}()

	time.Sleep(50 * time.Millisecond) // ensure the loop is parked in sleepCtx
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("startHeartbeatWithRetry did not exit on mid-retry ctx cancel (retry loop ignored commsCtx)")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("startHeartbeatWithRetry took %v to honour ctx cancel", elapsed)
	}
	if d.cluster.HeartbeatRunning() {
		t.Fatal("no heartbeat should be installed for an unresolvable interface")
	}
}
