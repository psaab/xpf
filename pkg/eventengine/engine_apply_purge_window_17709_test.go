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
	defer releasePurge()
	e.beforePendingPurgeFn = func() {
		close(purgeWindow)
		<-resumePurge
	}
	applyDone := make(chan struct{})
	go func() {
		defer close(applyDone)
		applyPolicies9984(e, []*config.EventPolicy{polR2})
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

	// Successor's in-cooldown edge must park. Pre-fix the predecessor's
	// stale entry still occupies the key, so this park is dropped.
	cur.set(15)
	suppressed := e.Stats().CooldownSuppressed
	edgeDone := make(chan struct{})
	go func() {
		defer close(edgeDone)
		e.HandleEvent(eventFor("ping_test_failed"))
	}()
	waitFor(t, "successor cooldown edge evaluated", func() bool {
		return e.Stats().CooldownSuppressed > suppressed
	})

	// Resume the purge; it removes the predecessor entry after the
	// successor insertion had an opportunity to replace it.
	releasePurge()
	select {
	case <-applyDone:
	case <-time.After(10 * time.Second):
		t.Fatal("redefining Apply did not finish after purge release")
	}
	select {
	case <-edgeDone:
	case <-time.After(10 * time.Second):
		t.Fatal("successor cooldown park did not finish")
	}

	if got := e.Stats().PendingDeferred; got != 1 {
		t.Fatalf("successor edge swallowed in purge window: PendingDeferred=%d, want 1 (successor park survives purge); stats=%+v", got, e.Stats())
	}
	e.pendingMu.Lock()
	de, ok := e.pending.cooldown["p\x00ping_test_failed"]
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
