package eventengine

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #17709 (Kimi arm of the PR #17462 retro-review): the #16650 pending
// purge in apply still drops e.mu before taking pendingMu
// (engine.go purge window). During that window the successor generation
// is fully published, so a successor event can commit, arm its cooldown,
// and park its in-cooldown edge — but the predecessor's stale parked
// entry still occupies the (policy,event) key, and
// insertDeferredCooldownParks' first-park-wins rule silently drops the
// successor park. The purge then deletes the predecessor entry, leaving
// no parked entry for drainDeferred to replay: the successor's only
// in-cooldown edge is lost.
//
// This test pauses apply at the purge boundary using a test seam, drives the
// full successor commit + cooldown park while the predecessor entry still
// exists, then resumes the purge and asserts the successor edge survives and
// replays exactly once at cooldown expiry.
func TestApplyPurgeWindowKeepsSuccessorPark17709(t *testing.T) {
	polR1 := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name r1"}}
	e, cur := setup16650(t, polR1)

	cur.set(0)
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "R1 commit", func() bool { return e.Stats().Committed >= 1 })
	waitCooldown16650(t, e)

	cur.set(5)
	e.HandleEvent(eventFor("ping_test_failed")) // R1 edge parks
	if got := e.Stats().PendingDeferred; got != 1 {
		t.Fatalf("R1 edge not parked: PendingDeferred=%d, want 1", got)
	}

	e.pendingMu.Lock()
	r1Park, ok := e.pending.cooldown["p\x00ping_test_failed"]
	e.pendingMu.Unlock()
	if !ok {
		t.Fatal("R1 cooldown entry disappeared before redefinition")
	}

	// Pause Apply after it publishes R2 and releases e.mu, but before
	// acquiring pendingMu to purge the predecessor entry.
	polR2 := &config.EventPolicy{Name: "p", Events: []string{"ping_test_failed"}, ThenCommands: []string{"set system host-name r2"}}
	cur.set(10)
	purgeWindow := make(chan struct{})
	resumePurge := make(chan struct{})
	releasePurge := func() {
		select {
		case <-resumePurge:
		default:
			close(resumePurge)
		}
	}
	e.beforePendingPurgeFn = func() {
		close(purgeWindow)
		<-resumePurge
	}
	applyDone := make(chan struct{})
	go func() {
		defer close(applyDone)
		applyPolicies9984(e, []*config.EventPolicy{polR2})
	}()
	defer func() {
		releasePurge()
		select {
		case <-applyDone:
		case <-time.After(10 * time.Second):
			t.Error("Apply did not finish during test cleanup")
		}
	}()

	select {
	case <-purgeWindow:
	case <-time.After(10 * time.Second):
		releasePurge()
		t.Fatal("Apply did not reach the parked-entry purge window")
	}

	// Successor fires (fresh runtime, no cooldown anchor) and commits,
	// arming its cooldown — all while apply is parked in the window.
	cur.set(12)
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "R2 commit in purge window", func() bool { return e.Stats().Committed >= 2 })
	waitCooldown16650(t, e)

	// The deferred worker may drain a stale R1 entry after Apply publishes
	// R2's fresh runtime (whose cooldown anchor is still zero). Keep the
	// collision deterministic by restoring that captured R1 entry if needed;
	// R2's committed cooldown below prevents it from draining during this arm.
	key := "p\x00ping_test_failed"
	e.pendingMu.Lock()
	if _, exists := e.pending.cooldown[key]; !exists {
		e.pending.cooldown[key] = r1Park
		e.counters.pendingDeferred.Add(1)
	}
	stale, exists := e.pending.cooldown[key]
	e.pendingMu.Unlock()
	if !exists || stale.action.semRev == rev16650(e, "p") {
		t.Fatalf("expected a stale R1 park before successor edge, exists=%t semRev=%q live=%q", exists, stale.action.semRev, rev16650(e, "p"))
	}

	// Successor's in-cooldown edge must replace the guaranteed stale R1 key.
	// Synchronous HandleEvent ensures insertion completes before Apply resumes.
	cur.set(15)
	e.HandleEvent(eventFor("ping_test_failed"))
	e.pendingMu.Lock()
	de, ok := e.pending.cooldown[key]
	e.pendingMu.Unlock()
	if !ok || de.action.semRev != rev16650(e, "p") {
		t.Fatalf("successor park not installed before purge: exists=%t semRev=%q live=%q", ok, de.action.semRev, rev16650(e, "p"))
	}

	// Resume the purge; it must preserve the already-installed successor park.
	releasePurge()
	select {
	case <-applyDone:
	case <-time.After(10 * time.Second):
		t.Fatal("redefining Apply did not finish after purge release")
	}

	if got := e.Stats().PendingDeferred; got != 1 {
		t.Fatalf("successor edge swallowed in purge window: PendingDeferred=%d, want 1 (successor park survives purge); stats=%+v", got, e.Stats())
	}
	e.pendingMu.Lock()
	de, ok = e.pending.cooldown[key]
	e.pendingMu.Unlock()
	if !ok {
		t.Fatalf("no parked cooldown entry for successor after purge")
	}
	if de.action.semRev != rev16650(e, "p") {
		t.Fatalf("parked entry semRev is stale (predecessor), want successor rev")
	}


	// Drain after cooldown: successor edge replays exactly once.
	cur.set(50)
	e.drainDeferred()
	waitFor(t, "R2 deferred replay", func() bool { return e.Stats().Committed >= 3 })
	time.Sleep(150 * time.Millisecond)
	if got := e.Stats().Committed; got != 3 {
		t.Fatalf("commits=%d, want exactly 3 (R1, R2, R2 replay)", got)
	}
	if got := e.Stats().PendingDeferred; got != 0 {
		t.Fatalf("PendingDeferred=%d after drain, want 0", got)
	}
}
