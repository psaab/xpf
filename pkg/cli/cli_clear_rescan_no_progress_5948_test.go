package cli

// #5948: the fresh-RESCAN fallback of the bounded filtered clear
// (clearFilteredV*Rescan, used ONLY by a cursor-LESS dataplane) re-collects
// matching keys from the top each round and relies on the just-processed keys
// being GONE so the next scan returns a smaller set. If a cursor-less dp's
// DeleteSession PERSISTENTLY errored (genuine, non-not-found) for >= batch
// matching keys, the identical set would be re-collected forever — an infinite
// loop. (The production cursor path cannot reach this: its cursor advances every
// round regardless of delete success, and both production dp types implement the
// cursor iterators, so the rescan is test/edge only.)
//
// The fix adds a no-progress guard: a non-empty chunk that REMOVED nothing
// (deleteAll's removed==0 — every forward delete genuinely failed, so all keys
// remain) breaks the loop with the aggregated errors already recorded. A
// not-found key counts as removed (it will not reappear), so a concurrently-
// drained chunk still makes progress and is not mistaken for a stall.
//
// FAIL-ON-REVERT: remove the `if removed == 0 { return deleted }` guard and
// TestClearRescanNoProgressTerminates_5948 loops past the fake's round cap
// (dp.exceeded → RED) instead of terminating after one round. The round cap
// makes a regression fail deterministically rather than wedge the suite.

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// cursorlessClearDP implements cliRuntime WITHOUT the cursor iterators
// (IterateSessionsFrom/V6From), so the bounded filtered clear takes the
// fresh-RESCAN fallback (clearFilteredV*Rescan), not the production cursor path.
// It does NOT embed *dataplane.Manager precisely so those cursor methods are
// absent (embedding would promote them and satisfy cliSessionCursor). A round
// cap turns a regression's infinite loop into a deterministic failure: once
// rounds exceeds maxRounds, IterateSessions yields nothing so the loop
// terminates and the test asserts on dp.exceeded rather than hanging.
type cursorlessClearDP struct {
	keys      []dataplane.SessionKey // matching v4 forward keys
	deleted   map[dataplane.SessionKey]bool
	delErr    error // non-nil: DeleteSession genuinely fails and does NOT remove the key
	notFound  bool  // DeleteSession reports not-found BUT the key is gone (concurrent drain)
	rounds    int
	maxRounds int
	exceeded  bool
	delCalls  int
}

func (d *cursorlessClearDP) IsLoaded() bool { return true }

func (d *cursorlessClearDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.rounds++
	if d.rounds > d.maxRounds {
		// Regression backstop: a missing no-progress guard would call this
		// forever. Yield nothing so the loop terminates via len==0; the test
		// asserts !exceeded.
		d.exceeded = true
		return nil
	}
	for _, k := range d.keys {
		if d.deleted[k] {
			continue
		}
		if !fn(k, dataplane.SessionValue{}) {
			break
		}
	}
	return nil
}

func (d *cursorlessClearDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (d *cursorlessClearDP) DeleteSession(key dataplane.SessionKey) error {
	d.delCalls++
	switch {
	case d.notFound:
		d.deleted[key] = true // it IS gone (another actor removed it) — progress...
		return ebpf.ErrKeyNotExist
	case d.delErr != nil:
		return d.delErr // genuine failure: key remains in the map
	default:
		d.deleted[key] = true
		return nil
	}
}

func (d *cursorlessClearDP) DeleteSessionV6(dataplane.SessionKeyV6) error { return nil }

// --- remaining cliRuntime surface: unused by the filtered-clear path, stubbed. ---
func (d *cursorlessClearDP) Compile(*config.Config) (*dataplane.CompileResult, error) {
	return nil, nil
}
func (d *cursorlessClearDP) ReadGlobalCounter(uint32) (uint64, error) { return 0, nil }
func (d *cursorlessClearDP) ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error) {
	return dataplane.InterfaceCounterValue{}, nil
}
func (d *cursorlessClearDP) ReadZoneCounters(uint32, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}
func (d *cursorlessClearDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}
func (d *cursorlessClearDP) ReadFilterConfig(uint32) (dataplane.FilterConfig, error) {
	return dataplane.FilterConfig{}, nil
}
func (d *cursorlessClearDP) ReadFilterCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}
func (d *cursorlessClearDP) ReadFloodCounters(uint32) (dataplane.FloodState, error) {
	return dataplane.FloodState{}, nil
}
func (d *cursorlessClearDP) ReadNATPortCounter(uint32) (uint64, error) { return 0, nil }
func (d *cursorlessClearDP) ReadNATRuleCounter(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}
func (d *cursorlessClearDP) SessionCount() (int, int)            { return len(d.keys), 0 }
func (d *cursorlessClearDP) ClearAllCounters() error             { return nil }
func (d *cursorlessClearDP) ClearAllSessions() (int, int, error) { return 0, 0, nil }
func (d *cursorlessClearDP) ClearFilterCounters() error          { return nil }
func (d *cursorlessClearDP) ClearNATRuleCounters() error         { return nil }
func (d *cursorlessClearDP) ClearPolicyCounters() error          { return nil }
func (d *cursorlessClearDP) GetMapStats() []dataplane.MapStats   { return nil }
func (d *cursorlessClearDP) GetPersistentNAT() *dataplane.PersistentNATTable {
	return nil
}

// compile-time: the fake really is a cliRuntime.
var _ cliRuntime = (*cursorlessClearDP)(nil)

func makeTCPKeys(n int) []dataplane.SessionKey {
	keys := make([]dataplane.SessionKey, n)
	for i := range keys {
		keys[i] = dataplane.SessionKey{Protocol: 6, SrcPort: uint16(1000 + i)}
	}
	return keys
}

func withBatch(t *testing.T, n int) {
	t.Helper()
	orig := cliClearFilteredBatch
	t.Cleanup(func() { cliClearFilteredBatch = orig })
	cliClearFilteredBatch = n
}

// assertRescanPath fails if dp would take the cursor path instead of the rescan
// fallback — the test is meaningless unless the rescan runs.
func assertRescanPath(t *testing.T, dp cliRuntime) {
	t.Helper()
	if _, ok := dp.(cliSessionCursor); ok {
		t.Fatal("fake satisfies cliSessionCursor; the clear would take the cursor path, not the rescan under test")
	}
}

// TestClearRescanNoProgressTerminates_5948 is the core assertion: a cursor-less
// dp whose DeleteSession PERSISTENTLY fails must make the filtered clear
// TERMINATE (no infinite re-collect), surfacing the delete failures.
func TestClearRescanNoProgressTerminates_5948(t *testing.T) {
	withBatch(t, 4)
	dp := &cursorlessClearDP{
		keys:      makeTCPKeys(8), // > batch → the pre-fix loop would re-collect forever
		deleted:   map[dataplane.SessionKey]bool{},
		delErr:    errors.New("injected persistent EIO"),
		maxRounds: 100, // regression backstop; the guard stops after round 1
	}
	assertRescanPath(t, dp)

	c := newClearCLI(t, dp)
	var out string
	done := make(chan struct{})
	go func() {
		out = captureStdout(t, func() {
			if err := c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"}); err != nil {
				t.Errorf("handleClearSecurity: %v", err)
			}
		})
		close(done)
	}()
	<-done // the round cap guarantees this returns even on a regression

	if dp.exceeded {
		t.Fatalf("rescan looped past the round cap (%d rounds) without progress — the no-progress guard is missing; in production (a cursor-less dp) this is an infinite loop", dp.maxRounds)
	}
	// The guard stops after the first non-empty, zero-removed round.
	if dp.rounds != 1 {
		t.Errorf("expected exactly 1 rescan round before the no-progress break, got %d", dp.rounds)
	}
	// The persistent delete failures are surfaced, not swallowed.
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "forward delete") {
		t.Errorf("persistent delete failure not surfaced:\n%s", out)
	}
}

// TestClearRescanSucceedingClearsAll_5948 is the positive control: a cursor-less
// dp whose deletes SUCCEED still clears the entire matched set over multiple
// bounded rounds (normal progress unchanged by the guard).
func TestClearRescanSucceedingClearsAll_5948(t *testing.T) {
	withBatch(t, 4)
	const n = 10
	dp := &cursorlessClearDP{
		keys:      makeTCPKeys(n),
		deleted:   map[dataplane.SessionKey]bool{},
		maxRounds: 100,
	}
	assertRescanPath(t, dp)

	c := newClearCLI(t, dp)
	out := captureStdout(t, func() {
		if err := c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"}); err != nil {
			t.Errorf("handleClearSecurity: %v", err)
		}
	})

	if dp.exceeded {
		t.Fatalf("succeeding-delete rescan looped past the round cap — should converge in ~n/batch rounds")
	}
	if got := len(dp.deleted); got != n {
		t.Fatalf("cleared %d of %d matching sessions, want all %d (bounded rescan must clear the full set)", got, n, n)
	}
	if strings.Contains(out, "WARNING") {
		t.Errorf("a clean rescan emitted a spurious WARNING:\n%s", out)
	}
}

// TestClearRescanNotFoundIsProgress_5948 proves the guard uses REMOVED (deleted
// OR not-found), not just successful deletes: a chunk whose keys were
// concurrently drained (DeleteSession reports not-found but the keys are gone)
// MUST be treated as progress, so the loop continues and clears the rest instead
// of breaking early. A `deleted==0` guard would wrongly stop after round 1 and
// leave the remaining matching keys uncleared.
func TestClearRescanNotFoundIsProgress_5948(t *testing.T) {
	withBatch(t, 4)
	const n = 10
	dp := &cursorlessClearDP{
		keys:      makeTCPKeys(n),
		deleted:   map[dataplane.SessionKey]bool{},
		notFound:  true, // every delete is a benign not-found, but the key IS gone
		maxRounds: 100,
	}
	assertRescanPath(t, dp)

	c := newClearCLI(t, dp)
	out := captureStdout(t, func() {
		if err := c.handleClearSecurity([]string{"flow", "session", "protocol", "tcp"}); err != nil {
			t.Errorf("handleClearSecurity: %v", err)
		}
	})

	if dp.exceeded {
		t.Fatal("not-found rescan looped past the round cap")
	}
	// Every matching key must have been visited/drained across the whole set —
	// the guard must NOT break early on a not-found (== gone) chunk.
	if got := len(dp.deleted); got != n {
		t.Fatalf("only %d of %d matching keys drained; the no-progress guard broke early on a not-found chunk (treated not-found as no-progress)", got, n)
	}
	// not-found is benign: no failure WARNING.
	if strings.Contains(out, "WARNING") {
		t.Errorf("not-found (benign) rescan emitted a spurious WARNING:\n%s", out)
	}
}
