package scheduler

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestScheduler_RepublishFailClosedAfterBoundedAge pins the #5669 bounded-age
// latch and the #10906 honesty correction. Persistent republish failure forces
// scheduled policies inactive in the authoritative control-plane state and
// emits one alarm. A current helper's #11285 heartbeat lease independently
// expires scheduler-bound rules; older helpers can retain the last-known
// schedule. The name of the scheduler latch remains for compatibility, while
// its alarm and gauge communicate FAIL-OPEN-STALE.
//
// The test also verifies the latch holds the inactive scheduler state until
// republish succeeds, then permits a legitimately open window to recover.
func TestScheduler_RepublishFailClosedAfterBoundedAge(t *testing.T) {
	// Capture WARN+ so the one-time fail-closed alarm is observable; the
	// per-name "state changed" logs are INFO and stay suppressed.
	var logBuf bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(oldLogger)

	schedCfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", StartTime: "09:00:00", StopTime: "17:00:00"},
	}

	var (
		calls     int
		lastState map[string]bool
		failing   = true
	)
	updateFn := func(_ context.Context, state map[string]bool) error {
		calls++
		lastState = state
		if failing {
			return errors.New("republish failed: wedged control socket")
		}
		return nil
	}

	// Prime inside the window (active). NewPrimed must not fire updateFn.
	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	s, initial := NewPrimed(schedCfg, updateFn, now)
	if !initial["workhours"] {
		t.Fatalf("workhours should start active inside window, got %v", initial)
	}
	if s.RepublishFailClosed() {
		t.Fatal("a fresh scheduler must not be fail-closed")
	}

	// Window closes at 17:00 → desired flips to inactive. The first evaluate
	// fires updateFn, which FAILS and latches the #3780 pending retry. Not yet
	// fail-closed: a single failure is within the bounded age.
	closeT := time.Date(2026, 2, 12, 17, 30, 0, 0, time.UTC)
	s.evaluate(context.Background(), closeT, true)
	if !s.RepublishPending() {
		t.Fatal("a failed republish must latch pending for retry")
	}
	if s.RepublishFailClosed() {
		t.Fatal("a single failure inside the bounded age must NOT be fail-closed (would false-alarm on a transient stall)")
	}

	// Retry every 60 s with the republish still failing. Before the bounded age
	// elapses the scheduler must stay in silent-retry (not fail-closed).
	tick := closeT
	for tick.Sub(closeT) < RepublishFailClosedAge {
		tick = tick.Add(60 * time.Second)
		beforeBound := tick.Sub(closeT) < RepublishFailClosedAge
		s.evaluate(context.Background(), tick, true)
		if beforeBound && s.RepublishFailClosed() {
			t.Fatalf("must not fail-closed before the bounded age (streak=%s, bound=%s)",
				tick.Sub(closeT), RepublishFailClosedAge)
		}
	}

	// The streak has now reached the bounded age: the scheduler MUST have
	// latched fail-open-stale and emitted exactly one alarm.
	if !s.RepublishFailClosed() {
		t.Fatalf("republish failing for %s (>= bound %s) must latch fail-open-stale",
			tick.Sub(closeT), RepublishFailClosedAge)
	}
	if got := strings.Count(logBuf.String(), "FAIL-OPEN-STALE"); got != 1 {
		t.Fatalf("fail-open-stale must emit exactly one alarm, got %d\nlog:\n%s", got, logBuf.String())
	}

	// The permit's window LEGITIMATELY reopens the next day (09:00-17:00),
	// desired active=true — but enforcement is still wedged, so the scheduler
	// must build an INACTIVE snapshot and report the permit inactive in its
	// authoritative state until a republish succeeds again.
	//
	// This test asserts the CONTROL-PLANE disposition only. The independent
	// #11285 heartbeat-lease enforcement on current helpers is covered by the
	// dataplane tests; a legacy helper may still enforce its last-known
	// snapshot while the shared control channel remains wedged.
	reopen := time.Date(2026, 2, 13, 10, 0, 0, 0, time.UTC)
	s.evaluate(context.Background(), reopen, true)
	if lastState["workhours"] {
		t.Fatal("fail-closed must build the permit INACTIVE in the published snapshot even when its window reopens")
	}
	if s.IsActive("workhours") {
		t.Fatal("fail-closed authoritative state must report the permit inactive")
	}

	// Republish recovers. The next successful publish clears fail-closed; the
	// scheduler then republishes the TRUE window state so the legitimately-open
	// permit reopens (no permanent false-deny).
	failing = false
	s.evaluate(context.Background(), reopen.Add(60*time.Second), true)
	if s.RepublishFailClosed() {
		t.Fatal("a successful republish must clear fail-closed")
	}
	if s.RepublishPending() {
		t.Fatal("a successful republish must clear the pending retry")
	}
	s.evaluate(context.Background(), reopen.Add(120*time.Second), true)
	if !lastState["workhours"] {
		t.Fatal("after recovery the reopened window must republish the permit ACTIVE (no permanent false-deny)")
	}
	if !s.IsActive("workhours") {
		t.Fatal("after recovery the reopened window must report active")
	}
}

func TestScheduler_RepublishesNormalDispositionOnceAfterFailClosedRecovery(t *testing.T) {
	schedCfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", StartTime: "09:00:00", StopTime: "17:00:00"},
	}
	var (
		s                  *Scheduler
		failing            = true
		published          []map[string]bool
		latchAtPublication []bool
	)
	updateFn := func(_ context.Context, state map[string]bool) error {
		published = append(published, state)
		latchAtPublication = append(latchAtPublication, s.RepublishFailClosed())
		if failing {
			return errors.New("republish unavailable")
		}
		return nil
	}
	start := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	s, _ = NewPrimed(schedCfg, updateFn, start)

	closeAt := time.Date(2026, 2, 12, 17, 30, 0, 0, time.UTC)
	s.evaluate(context.Background(), closeAt, true)
	tick := closeAt
	for tick.Sub(closeAt) < RepublishFailClosedAge {
		tick = tick.Add(time.Minute)
		s.evaluate(context.Background(), tick, true)
	}
	if !s.RepublishFailClosed() {
		t.Fatal("republish failure streak did not latch fail-closed")
	}

	failing = false
	latchPublishAt := tick.Add(time.Minute)
	s.evaluate(context.Background(), latchPublishAt, true)
	if s.RepublishFailClosed() || s.RepublishPending() {
		t.Fatal("successful latch snapshot must clear the fail-closed and retry latches")
	}
	if got := len(published); got == 0 || !latchAtPublication[got-1] {
		t.Fatal("recovery snapshot was not published with the fail-closed latch set")
	}
	if published[len(published)-1]["workhours"] {
		t.Fatal("latched snapshot state = active, want inactive scheduler map")
	}

	normalPublishAt := latchPublishAt.Add(time.Minute)
	publishedBeforeNormal := len(published)
	s.evaluate(context.Background(), normalPublishAt, true)
	if got := len(published); got != publishedBeforeNormal+1 {
		t.Fatalf("normal disposition publications = %d, want exactly one after latch recovery", got-publishedBeforeNormal)
	}
	if latchAtPublication[len(latchAtPublication)-1] {
		t.Fatal("follow-up snapshot still carried the fail-closed latch")
	}
	if published[len(published)-1]["workhours"] {
		t.Fatal("follow-up normal snapshot state = active, want inactive schedule")
	}

	s.evaluate(context.Background(), normalPublishAt.Add(time.Minute), true)
	if got := len(published); got != publishedBeforeNormal+1 {
		t.Fatalf("normal disposition republished %d times, want exactly once", got-publishedBeforeNormal)
	}
}

// Note on gauge coverage (#6137 finding 3, #10906): the honest
// xpf_scheduler_republish_fail_open_stale gauge and its deprecated
// xpf_scheduler_republish_fail_closed alias read the scheduler's own
// RepublishFailClosed() latch (the SSOT the daemon accessor delegates to).
// Its 0→1 transition at the bound and 1→0 clear on recovery are pinned above.
// The daemon accessor's latch-source contract is covered by
// pkg/daemon's TestSchedulerRepublishFailClosedGaugeReadsSSOTLatch_5669; the
// API metric names, values, alias equality, and help text are covered by
// pkg/api's TestSchedulerFailOpenStaleMetricNamesTheDataplaneRisk10906.

// TestScheduler_WithinBoundTransientNeverFailsClosed is the control: a normal
// successful window transition and a transient failure that recovers INSIDE the
// bounded age must never trip fail-closed — no false-deny of a legitimate
// window, no false alarm. This test does NOT depend on the #5669 latch, so it
// stays green whether or not the fix is present (keeps the fail-on-revert
// target-count at 1).
func TestScheduler_WithinBoundTransientNeverFailsClosed(t *testing.T) {
	schedCfg := map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours", StartTime: "09:00:00", StopTime: "17:00:00"},
	}
	var (
		calls     int
		lastState map[string]bool
		failing   = false
	)
	updateFn := func(_ context.Context, state map[string]bool) error {
		calls++
		lastState = state
		if failing {
			return errors.New("transient republish failure")
		}
		return nil
	}

	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	s, _ := NewPrimed(schedCfg, updateFn, now)

	// A clean window close: one successful republish, never fail-closed.
	closeT := time.Date(2026, 2, 12, 17, 30, 0, 0, time.UTC)
	s.evaluate(context.Background(), closeT, true)
	if s.RepublishFailClosed() {
		t.Fatal("a successful window transition must never be fail-closed")
	}
	if lastState["workhours"] {
		t.Fatal("a closed window must publish the permit inactive")
	}

	// A transient failure that recovers well inside the bounded age must not
	// fail-closed. Reopen the window (desired active) so a spurious fail-closed
	// would be observable as a false-deny.
	reopen := time.Date(2026, 2, 13, 9, 30, 0, 0, time.UTC)
	failing = true
	s.evaluate(context.Background(), reopen, true) // republish fails once, latches pending
	if !s.RepublishPending() {
		t.Fatal("a failed republish should latch pending")
	}
	// A couple more failures, still comfortably within the bound.
	failing = true
	s.evaluate(context.Background(), reopen.Add(60*time.Second), true)
	if s.RepublishFailClosed() {
		t.Fatalf("a transient failure inside the bounded age (%s) must not fail-closed", RepublishFailClosedAge)
	}
	// Recover before the bound.
	failing = false
	s.evaluate(context.Background(), reopen.Add(120*time.Second), true)
	if s.RepublishFailClosed() || s.RepublishPending() {
		t.Fatal("recovery inside the bound must leave neither pending nor fail-closed")
	}
	if !lastState["workhours"] {
		t.Fatal("the legitimately-open window must publish ACTIVE after a within-bound transient recovers (no false-deny)")
	}
	if !s.IsActive("workhours") {
		t.Fatal("the legitimately-open window must be active after recovery")
	}
}
