package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// seedDeferredDebt10041 puts a live Manager behind an outstanding publish. The
// helper model is seeded independently so its installed (generation, digest,
// fabrics) can be ahead of Go's retained authority, which is the state the
// deferred tick must repair rather than re-send forever.
func seedDeferredDebt10041(
	t *testing.T,
	f *fixture9824,
	managerGen, helperGen uint64,
	retainedFabrics, helperFabrics []FabricSnapshot,
	partialDebt bool,
) {
	t.Helper()
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	retained := f.snap9824(managerGen,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
		[]NeighborSnapshot{n0}, retainedFabrics)
	helper := f.snap9824(helperGen,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}},
		[]NeighborSnapshot{n0}, helperFabrics)
	f.m.mu.Lock()
	f.m.lastSnapshot = retained
	f.m.generation = managerGen
	f.m.publishedSnapshot = managerGen - 1
	f.m.publishedPlanKey = snapshotBindingPlanKey(retained)
	hash, ok := snapshotContentHash(retained)
	if !ok {
		t.Fatal("retained snapshot did not hash")
	}
	f.m.lastSnapshotHash = hash
	f.m.lastStatus.LastSnapshotGeneration = managerGen - 1
	f.m.applySnapshotOutcomeUnknown = true
	if partialDebt {
		f.m.partialOutcomeUnknown = partialFabrics
	}
	f.m.mu.Unlock()
	f.model.seed(helperGen, 0, digest9824(t, helper), helperFabrics)
	f.endXSKWindow()
}

func assert10041TransportFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("tick returned nil, want the scripted lost response")
	}
	if errors.Is(err, errHelperRejected) {
		t.Fatalf("tick returned an in-band refusal, want the scripted transport error: %v", err)
	}
}

func assert10041Converged(t *testing.T, f *fixture9824, wantGeneration uint64) {
	t.Helper()
	f.m.mu.Lock()
	mgen, retained, published := f.m.generation, f.m.lastSnapshot.Generation, f.m.publishedSnapshot
	retainedSnapshot := *f.m.lastSnapshot
	unknown, partial := f.m.applySnapshotOutcomeUnknown, f.m.partialOutcomeUnknown
	f.m.mu.Unlock()
	installed, installedDigest := f.model.installedState()
	if mgen != wantGeneration || retained != wantGeneration || published != wantGeneration || installed != wantGeneration {
		t.Fatalf("not converged: manager=%d retained=%d published=%d helper=%d, want all %d", mgen, retained, published, installed, wantGeneration)
	}
	wantDigest := digest9824(t, &retainedSnapshot)
	if installedDigest != wantDigest {
		t.Fatalf("helper digest = %q, want retained snapshot digest %q", installedDigest, wantDigest)
	}
	if unknown || partial != 0 {
		t.Fatalf("debt remains at convergence: unknown=%v partial=%v", unknown, partial)
	}
	if f.ctrl.stored.Enabled != 1 {
		t.Fatalf("ctrl.Enabled = %d at convergence, want 1", f.ctrl.stored.Enabled)
	}
}

// TestDeferredTickEqualityLandingConverges10041 covers r2's equality landing:
// Compile reserves generation 8, an unallocated worker-arm republish lands at
// generation 9 but loses its response, and the deferred compiled snapshot is
// still stored at the manager's generation. The apply-time rebase must move it
// to 10, strictly above the helper, so the service tick admits it first try.
func TestDeferredTickEqualityLandingConverges10041(t *testing.T) {
	f := newFixture9824(t)
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	alpha := []FabricSnapshot{fabricAlpha9824()}
	seed := f.seedPublished(t, 7, baseZones9824(), []NeighborSnapshot{n0}, alpha)
	f.m.mu.Lock()
	seed.DeferWorkers = true
	if hash, ok := snapshotContentHash(seed); ok {
		f.m.lastSnapshotHash = hash
	}
	f.m.pendingWorkerArm = true
	f.m.mu.Unlock()
	f.model.seed(7, 0, digest9824(t, seed), alpha)
	f.forcePendingXSK()

	epoch := f.m.partialUpdateEpoch.Load()
	reserved := f.m.bumpGeneration()
	compiled := f.snap9824(reserved,
		[]ZoneSnapshot{{Name: "zone-a", ID: 1}, {Name: markerZone9824, ID: 77}},
		[]NeighborSnapshot{n0}, alpha)
	compiled.partialUpdateEpoch = epoch

	// The republish uses unallocated m.generation+1 and lands without an ACK.
	f.model.scriptDrops(1)
	f.m.mu.Lock()
	err := f.m.retryDeferredWorkerArmLocked()
	f.m.mu.Unlock()
	assert10041TransportFailure(t, err)
	installed, _ := f.model.installedState()
	f.m.mu.Lock()
	mgen, retained, published := f.m.generation, f.m.lastSnapshot.Generation, f.m.publishedSnapshot
	f.m.mu.Unlock()
	if installed != reserved+1 || mgen != reserved || retained != 7 || published != 7 {
		t.Fatalf("equality premise = helper %d manager %d retained %d published %d, want %d/%d/7/7",
			installed, mgen, retained, published, reserved+1, reserved)
	}

	appliesBefore := f.model.countVerb("apply_snapshot")
	if _, err := f.apply(t, compiled); err != nil {
		t.Fatalf("deferred compiled apply returned %v, want nil", err)
	}
	if got := f.model.countVerb("apply_snapshot"); got != appliesBefore {
		t.Fatalf("deferred compiled apply sent %d requests, want 0", got-appliesBefore)
	}
	f.m.mu.Lock()
	stored := f.m.lastSnapshot.Generation
	f.m.mu.Unlock()
	if stored != installed+1 {
		t.Fatalf("deferred compiled generation = %d, want helper+1 = %d", stored, installed+1)
	}

	f.endXSKWindow()
	if err := f.tick(t); err != nil {
		t.Fatalf("service tick returned %v, want first-try admission", err)
	}
	if gens := f.model.applyGenerations()[appliesBefore:]; !equalUint64s(gens, []uint64{stored}) {
		t.Fatalf("service tick offers = %v, want single [%d]", gens, stored)
	}
	sent := f.lastApplyOfType(t, "apply_snapshot")
	if sent.Snapshot == nil || !snapshotHasZone(sent.Snapshot, markerZone9824) {
		t.Fatal("service tick apply_snapshot lacks the compiled marker zone")
	}
	assert10041Converged(t, f, stored)
	f.assertNoViolations(t)
}

// TestDeferredTickResampleNoOpWritebackConverges10041 covers r3-main:
// a resampled beta copy lands with a lost response, a no-op alpha writeback
// clears the partial debt and the helper digest, then the conflict retry lands
// with a lost response. The retry generation must remain retained.
func TestDeferredTickResampleNoOpWritebackConverges10041(t *testing.T) {
	f := newFixture9824(t)
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	alpha := []FabricSnapshot{fabricAlpha9824()}
	beta := []FabricSnapshot{fabricBeta9824()}
	f.seedPublished(t, 7, baseZones9824(), []NeighborSnapshot{n0}, alpha)
	seedDeferredDebt10041(t, f, 8, 7, alpha, alpha, true)
	samples := [][]FabricSnapshot{beta, alpha}
	f.fabricFunc = func(*config.Config) []FabricSnapshot {
		if len(samples) == 0 {
			t.Fatal("fabric sampler called after the r3-main script ended")
		}
		out := samples[0]
		samples = samples[1:]
		return append([]FabricSnapshot(nil), out...)
	}

	f.model.scriptDrops(1)
	base := f.model.countVerb("apply_snapshot")
	assert10041TransportFailure(t, f.tick(t))
	if gens := f.model.applyGenerations()[base:]; !equalUint64s(gens, []uint64{8}) {
		t.Fatalf("r3-main first offers = %v, want [8]", gens)
	}
	installed, _ := f.model.installedState()
	if installed != 8 {
		t.Fatalf("r3-main first helper generation = %d, want 8", installed)
	}
	f.m.mu.Lock()
	retainedFabrics := append([]FabricSnapshot(nil), f.m.lastSnapshot.Fabrics...)
	partial := f.m.partialOutcomeUnknown
	f.m.mu.Unlock()
	if !fabricSnapshotsEqual(retainedFabrics, alpha) || partial != partialFabrics {
		t.Fatalf("first lost tick mutated retained/debt: fabrics=%+v partial=%v", retainedFabrics, partial)
	}
	if f.ctrl.stored.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d after first lost tick, want 0", f.ctrl.stored.Enabled)
	}

	// The no-op writeback is observable at the helper: beta is replaced by
	// alpha, which clears the helper's digest without advancing Go's generation.
	m := f.m
	m.SyncFabricState()
	f.m.mu.Lock()
	mgen, partial := f.m.generation, f.m.partialOutcomeUnknown
	f.m.mu.Unlock()
	_, digest := f.model.installedState()
	if mgen != 8 || partial != 0 || digest != "" {
		t.Fatalf("no-op writeback state = generation %d partial %v digest %q, want 8/0/empty", mgen, partial, digest)
	}

	f.model.scriptDrops(1)
	base = f.model.countVerb("apply_snapshot")
	assert10041TransportFailure(t, f.tick(t))
	if gens := f.model.applyGenerations()[base:]; !equalUint64s(gens, []uint64{8, 9}) {
		t.Fatalf("r3-main conflict retry offers = %v, want [8 9]", gens)
	}
	installed, _ = f.model.installedState()
	f.m.mu.Lock()
	mgen, retained := f.m.generation, f.m.lastSnapshot.Generation
	f.m.mu.Unlock()
	if installed != 9 || mgen != 9 || retained != 9 {
		t.Fatalf("r3-main failed retry was not adopted: helper=%d manager=%d retained=%d", installed, mgen, retained)
	}

	if err := f.tick(t); err != nil {
		t.Fatalf("r3-main convergence tick returned %v", err)
	}
	assert10041Converged(t, f, 9)
	f.assertNoViolations(t)
}

// TestDeferredTickTickDriftConverges10041 covers r3-short: beta is sampled
// into the first lost tick, alpha is sampled into the conflict retry, and the
// retry response is lost. Partial debt remains until the identical re-offer
// succeeds on the next tick; no no-op writeback is allowed to mask this path.
func TestDeferredTickTickDriftConverges10041(t *testing.T) {
	f := newFixture9824(t)
	n0 := neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")
	alpha := []FabricSnapshot{fabricAlpha9824()}
	beta := []FabricSnapshot{fabricBeta9824()}
	f.seedPublished(t, 7, baseZones9824(), []NeighborSnapshot{n0}, alpha)
	seedDeferredDebt10041(t, f, 8, 7, alpha, alpha, true)
	samples := [][]FabricSnapshot{beta, alpha, alpha}
	f.fabricFunc = func(*config.Config) []FabricSnapshot {
		if len(samples) == 0 {
			t.Fatal("fabric sampler called after the r3-short script ended")
		}
		out := samples[0]
		samples = samples[1:]
		return append([]FabricSnapshot(nil), out...)
	}

	f.model.scriptDrops(1)
	base := f.model.countVerb("apply_snapshot")
	assert10041TransportFailure(t, f.tick(t))
	if gens := f.model.applyGenerations()[base:]; !equalUint64s(gens, []uint64{8}) {
		t.Fatalf("r3-short first offers = %v, want [8]", gens)
	}
	installed, _ := f.model.installedState()
	if installed != 8 {
		t.Fatalf("r3-short first helper generation = %d, want 8", installed)
	}

	f.model.scriptDrops(1)
	base = f.model.countVerb("apply_snapshot")
	assert10041TransportFailure(t, f.tick(t))
	if gens := f.model.applyGenerations()[base:]; !equalUint64s(gens, []uint64{8, 9}) {
		t.Fatalf("r3-short conflict retry offers = %v, want [8 9]", gens)
	}
	installed, _ = f.model.installedState()
	f.m.mu.Lock()
	mgen, retained, partial := f.m.generation, f.m.lastSnapshot.Generation, f.m.partialOutcomeUnknown
	f.m.mu.Unlock()
	if installed != 9 || mgen != 9 || retained != 9 || partial != partialFabrics {
		t.Fatalf("r3-short lost retry state = helper %d manager %d retained %d partial %v, want 9/9/9/%v", installed, mgen, retained, partial, partialFabrics)
	}
	if f.ctrl.stored.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d after lost retry, want fail-closed 0", f.ctrl.stored.Enabled)
	}

	base = f.model.countVerb("apply_snapshot")
	if err := f.tick(t); err != nil {
		t.Fatalf("r3-short convergence tick returned %v", err)
	}
	if gens := f.model.applyGenerations()[base:]; !equalUint64s(gens, []uint64{9}) {
		t.Fatalf("r3-short convergence offers = %v, want [9]", gens)
	}
	assert10041Converged(t, f, 9)
	f.assertNoViolations(t)
}
