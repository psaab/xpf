package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #12884: a wall-clock step between the previous scheduler's last tick and
// a scheduler-modifying commit must fail closed on the replacement. The
// replacement is primed before CarryRecoveryStateFrom, so its initial
// evaluate saw a zero lastEval and could not detect the jump.
func TestCarryRecoveryStateFromDetectsCommitTimeClockStep12884(t *testing.T) {
	cfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", AllDay: true},
	}
	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	noop := func(context.Context, map[string]bool) error { return nil }
	previous, initial := NewPrimed(cfg, noop, now)
	if !initial["workhours"] {
		t.Fatal("previous scheduler should start active")
	}
	// The wall clock steps backward an hour after the previous tick.
	previous.mu.Lock()
	previous.lastWallUnixNano = now.Add(time.Hour).UnixNano()
	previous.mu.Unlock()

	commitAt := now.Add(time.Minute)
	replacement, primed := NewPrimed(cfg, noop, commitAt)
	if !primed["workhours"] {
		t.Fatal("replacement primes active (this is the pre-carry state)")
	}
	replacement.CarryRecoveryStateFrom(previous, commitAt)
	if replacement.ActiveState()["workhours"] {
		t.Fatal("replacement stayed active across a wall-clock step at commit time")
	}
	if replacement.unsafeUntil.IsZero() {
		t.Fatal("replacement must carry a recovery hold after the step")
	}

	// Control: no step — the replacement stays active.
	steady, _ := NewPrimed(cfg, noop, now)
	replacement2, _ := NewPrimed(cfg, noop, commitAt)
	replacement2.CarryRecoveryStateFrom(steady, commitAt)
	if !replacement2.ActiveState()["workhours"] {
		t.Fatal("steady-clock replacement must stay active")
	}
}
