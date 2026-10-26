package userspace

import (
	"testing"
)

// #8597 K82: the status-loop catch-up branch in syncSnapshotLocked trusted a
// generation number ACROSS Manager incarnations.
//
// `m.generation` is per-incarnation and lives only in memory (manager.go), so a
// generation reported by a helper that outlived a daemon restart is not
// comparable to this incarnation's counter at all. process.go returns WITHOUT
// restarting the helper when the config is equal and the ping succeeds, so a
// retained helper keeps reporting the previous incarnation's
// LastSnapshotGeneration — which is >= this Manager's first snapshot for any
// prior value.
//
// The branch then mirrored the full successful-apply bookkeeping (marking the
// snapshot published AND applied, stamping the content hash) for a snapshot it
// never sent, and the `publishedSnapshot >= lastSnapshot.Generation` gate at the
// top then suppressed the publish until a later commit moved the generation past
// the stale one. The helper is running the OLD configuration throughout while the
// daemon's bookkeeping says the new one was applied.
//
// The evidence the branch was missing is `publishedSnapshot != 0`: until THIS
// Manager has published something, no generation the helper reports says
// anything about what it holds.
//
// SCOPE — read before extending. This drives the branch directly with the state
// a restart-with-retained-helper produces. It does NOT drive the restart
// interleaving end to end (the status loop racing the compile path's publish),
// which is why #8597 records K82 as mechanism-real with the full interleaving
// not live-driven. What is pinned here is the branch's contract: given a
// generation from an incarnation that never published, do not claim it was
// applied.

// seedRetainedHelperGeneration8597 models a FRESH Manager (nothing published
// this incarnation) whose retained helper still reports a high generation from
// the previous one.
func seedRetainedHelperGeneration8597(t *testing.T, h *partialUpdateHarness6986) {
	t.Helper()
	fresh := &ConfigSnapshot{
		Version:    ProtocolVersion,
		Generation: 1, // this incarnation's FIRST snapshot
		Config:     h.cfg,
		Zones:      []ZoneSnapshot{{Name: "fresh-incarnation-8597", ID: 91}},
		Summary:    SnapshotSummary{ZoneCount: 1},
	}
	h.m.mu.Lock()
	h.m.lastSnapshot = fresh
	h.m.generation = 1
	h.m.publishedSnapshot = 0 // NOTHING published by this incarnation
	// The retained helper's answer, carried over a daemon restart.
	h.m.lastStatus.LastSnapshotGeneration = 7
	h.m.xskLivenessProven = true
	h.m.mu.Unlock()

	if h.m.lastStatus.LastSnapshotGeneration < h.m.lastSnapshot.Generation {
		t.Fatal("fixture: the retained helper must report a generation >= this " +
			"incarnation's, or the catch-up branch is not even reachable and the " +
			"cell proves nothing")
	}
}

func TestCatchUpDoesNotTrustARetainedHelpersGeneration8597K82(t *testing.T) {
	h := newPartialUpdateHarness6986(t)
	seedRetainedHelperGeneration8597(t, h)

	h.m.mu.Lock()
	_ = h.m.syncSnapshotLocked()
	h.m.mu.Unlock()

	// The observable that separates the two behaviours is whether an
	// apply_snapshot actually went to the helper. The catch-up path sends
	// nothing and returns nil; the publish path puts a request on the wire.
	// (The post-publish bookkeeping errors in a unit build with no BPF maps —
	// asserting on the RECORDED REQUEST rather than the error is the same
	// reasoning the #6986 harness documents.)
	sent := h.sent(t, "apply_snapshot")
	if len(sent) == 0 {
		t.Fatal("#8597 K82: a fresh Manager published NOTHING and treated the " +
			"retained helper's stale generation as proof the snapshot was applied. " +
			"The helper keeps running the previous incarnation's configuration " +
			"while the daemon's bookkeeping says the new one landed, and the " +
			"publish stays suppressed until a later commit outruns the stale " +
			"generation")
	}
}

// The other half, and the reason this is a gate rather than a deletion: once
// this incarnation HAS published, the catch-up is legitimate and must still
// fire. Removing the branch outright — the obvious over-correction — would make
// every status tick re-publish an unchanged snapshot and break the
// same-plan-during-XSK-startup exception the branch exists to preserve.
func TestCatchUpStillFiresOnceThisIncarnationHasPublished8597K82(t *testing.T) {
	h := newPartialUpdateHarness6986(t)
	seedRetainedHelperGeneration8597(t, h)

	// The one difference from the cell above: this Manager HAS published.
	h.m.mu.Lock()
	h.m.publishedSnapshot = 1
	h.m.lastSnapshot.Generation = 2
	h.m.generation = 2
	h.m.lastStatus.LastSnapshotGeneration = 7 // helper is genuinely ahead
	h.m.mu.Unlock()

	h.m.mu.Lock()
	err := h.m.syncSnapshotLocked()
	h.m.mu.Unlock()
	if err != nil {
		t.Fatalf("the catch-up path must return cleanly, got %v", err)
	}
	if sent := h.sent(t, "apply_snapshot"); len(sent) != 0 {
		t.Fatalf("the catch-up path published %d snapshot(s); it must mirror the "+
			"bookkeeping WITHOUT re-sending a snapshot the helper already has",
			len(sent))
	}
	h.m.mu.Lock()
	published := h.m.publishedSnapshot
	h.m.mu.Unlock()
	if published != 2 {
		t.Fatalf("publishedSnapshot = %d, want 2 — the legitimate catch-up must "+
			"still advance the bookkeeping", published)
	}
}
