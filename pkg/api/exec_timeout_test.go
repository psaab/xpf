package api

import (
	"context"
	"testing"
	"time"
)

// runTimeout derives its deadline from the parent ctx via
// context.WithTimeout(parent, 15s) — the effective deadline is the
// earlier of the two. The timeout test passes a short parent deadline
// so the kill path is exercised without waiting out the real 15s
// constant (same precedent as the pkg/grpcapi helper tests; the
// pkg/daemon contract reference ships untested).

// The ping/traceroute budget tables moved to pkg/diagcmd
// (TestPingExecTimeoutTable17203, TestPingClientTimeoutCoversServerBudget15235)
// when the servers migrated to diagcmd.PingExecTimeout (#17203).

func TestRunTimeoutSuccess(t *testing.T) {
	if err := runTimeout(context.Background(), "true"); err != nil {
		t.Fatalf("runTimeout(true): %v", err)
	}
}

func TestRunTimeoutKillsHungCommand(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := runTimeout(parent, "sleep", "30")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("runTimeout: want error for killed command, got nil")
	}
	// Bound: 200ms deadline + 5s WaitDelay worst case, with slack.
	if elapsed > 10*time.Second {
		t.Fatalf("runTimeout took %v, command was not killed by the deadline", elapsed)
	}
}
