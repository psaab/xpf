package userspace

// #10066: tick retry adoption must not write stale m.cfg in diverged spawn state.
//
// ensureProcessLocked spawns NEW and writes m.cfg (NEW), but a later
// protocol-gate / disarm / publish-refusal failure returns with lastSnapshot
// still OLD, so m.cfg (NEW) != lastSnapshot.Userspace (OLD). #10064's
// same-generation skip fixes the no-retry case; a tick conflict-retry that
// lands-but-loses-its-response still differs (retry Gen != retained Gen) and
// fully adopts OLD incl. m.cfg, clobbering NEW.
//
// These cells pin the diverged-spawn + land-lost-retry trace plus controls:
// clean spawn (no divergence), same-gen retry (#10064, still skips), and
// Compile-differ (genuine new identity, still adopts m.cfg).

import (
	"reflect"
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// oldNewUcfg10066 returns a diverged spawn pair: OLD (retained) vs NEW
// (spawned). Workers differ so configEqual is false; ControlSocket/Binary/
// StateFile also differ so a stale writeback is observable via DeepEqual and
// via the watchdog session socket path.
func oldNewUcfg10066() (oldUcfg, newUcfg config.UserspaceConfig) {
	oldUcfg = config.UserspaceConfig{
		Binary:        "/run/xpf-10066-old-helper",
		ControlSocket: "/tmp/xpf-10066-old.sock",
		StateFile:     "/tmp/xpf-10066-old.state",
		Workers:       1,
		RingEntries:   256,
		PollMode:      "busy-poll",
	}
	newUcfg = config.UserspaceConfig{
		Binary:        "/run/xpf-10066-new-helper",
		ControlSocket: "/tmp/xpf-10066-new.sock",
		StateFile:     "/tmp/xpf-10066-new.state",
		Workers:       2,
		RingEntries:   512,
		PollMode:      "interrupt",
	}
	return oldUcfg, newUcfg
}

// seedDivergedTick10066 installs a diverged spawn state on a deferred-publish
// fixture: lastSnapshot OLD Gen-8 unpublished (published 1, gate open), m.cfg
// NEW (spawned), m.generation 8. The tick's republish therefore carries OLD
// content with a NEW spawn record outstanding.
func seedDivergedTick10066(t *testing.T, f *deferredPublishFixture9337, retainedUcfg, mcfg config.UserspaceConfig) {
	t.Helper()
	retained, err := buildSnapshot(&config.Config{}, retainedUcfg, 8, 0)
	if err != nil {
		t.Fatalf("buildSnapshot retained: %v", err)
	}
	f.m.lastSnapshot = retained
	f.snap = retained
	// The fixture computed publishedPlanKey from its empty-Userspace snap;
	// Workers feeds the plan key, so recompute or the tick takes the
	// restart branch (stopLocked + respawn) instead of the republish path.
	f.m.publishedPlanKey = snapshotBindingPlanKey(retained)
	f.m.cfg = mcfg
	f.m.generation = 8
}

// TestTickRetryDivergedSpawnPreservesMcfg10066 is the bug cell: diverged spawn
// (m.cfg NEW, retained OLD) + tick conflict + lost retry response. The retry
// generation must still be consumed (retained Gen-9, m.generation 9,
// published held back), but m.cfg must stay NEW — adopting OLD clobbers the
// spawn record, poisoning crash respawn and forcing a kill+respawn on the
// next NEW commit.
//
// RED-on-revert: remove the #10066 m.cfg guard and m.cfg == OLD (stale
// writeback), so the DeepEqual(NEW) assertion fails.
func TestTickRetryDivergedSpawnPreservesMcfg10066(t *testing.T) {
	t.Parallel()
	f := newDeferredPublishFixture9337(t, nil)
	oldUcfg, newUcfg := oldNewUcfg10066()
	seedDivergedTick10066(t, f, oldUcfg, newUcfg)
	if configEqual(f.m.cfg, f.m.lastSnapshot.Userspace) {
		t.Fatal("premise: diverged state requires m.cfg NEW != retained OLD")
	}
	rec := &applyRecorder9520{replies: []error{contentConflict9520(8), errLostResponse9520}}
	f.m.controlRequestHook = rec.hook

	if err := f.runSync(t); err == nil {
		t.Fatal("syncSnapshotLocked returned nil after the conflict retry lost its response")
	}
	if got := rec.generations(); !slices.Equal(got, []uint64{8, 9}) {
		t.Fatalf("apply_snapshot generations = %v, want [8 9] (conflict + lost retry)", got)
	}
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	// The possibly-landed retry generation is still consumed (#10041 R1 via
	// deliberate retry adoption); only the identity writeback is blocked.
	if f.m.lastSnapshot == nil || f.m.lastSnapshot.Generation != 9 {
		t.Fatalf("lastSnapshot.Generation = %v, want 9 (retry generation consumed)",
			func() uint64 {
				if f.m.lastSnapshot == nil {
					return 0
				}
				return f.m.lastSnapshot.Generation
			}())
	}
	if f.m.generation != 9 {
		t.Fatalf("m.generation = %d, want 9 (landed retry consumed)", f.m.generation)
	}
	if f.m.publishedSnapshot != 1 {
		t.Fatalf("publishedSnapshot = %d, want 1 held back (gate still open)", f.m.publishedSnapshot)
	}
	if !configEqual(f.m.lastSnapshot.Userspace, oldUcfg) {
		t.Fatalf("retained Userspace = %+v, want OLD %+v (tick carries retained content)",
			f.m.lastSnapshot.Userspace, oldUcfg)
	}
	if !reflect.DeepEqual(f.m.cfg, newUcfg) {
		t.Fatalf("m.cfg = %+v, want NEW %+v (stale OLD writeback over diverged spawn)",
			f.m.cfg, newUcfg)
	}
	if f.ctrl.stored.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled = %d after a failed republish, want 0 (fail closed)", f.ctrl.stored.Enabled)
	}
}

// TestTickRetryCleanSpawnKeepsMcfg10066: no divergence (m.cfg NEW == retained
// NEW); the same conflict + lost-retry trace keeps NEW. Passes pre- and
// post-fix; guards against a fix that breaks the clean path.
func TestTickRetryCleanSpawnKeepsMcfg10066(t *testing.T) {
	t.Parallel()
	f := newDeferredPublishFixture9337(t, nil)
	_, newUcfg := oldNewUcfg10066()
	seedDivergedTick10066(t, f, newUcfg, newUcfg)
	if !configEqual(f.m.cfg, f.m.lastSnapshot.Userspace) {
		t.Fatal("premise: clean state requires m.cfg == retained")
	}
	rec := &applyRecorder9520{replies: []error{contentConflict9520(8), errLostResponse9520}}
	f.m.controlRequestHook = rec.hook

	if err := f.runSync(t); err == nil {
		t.Fatal("syncSnapshotLocked returned nil after the conflict retry lost its response")
	}
	if got := rec.generations(); !slices.Equal(got, []uint64{8, 9}) {
		t.Fatalf("apply_snapshot generations = %v, want [8 9]", got)
	}
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.m.lastSnapshot == nil || f.m.lastSnapshot.Generation != 9 {
		t.Fatal("clean retry did not consume the retry generation (want retained Gen-9)")
	}
	if !reflect.DeepEqual(f.m.cfg, newUcfg) {
		t.Fatalf("m.cfg = %+v, want NEW %+v (clean spawn must keep its identity)", f.m.cfg, newUcfg)
	}
}

// TestTickSameGenDivergedPreservesMcfg10066: diverged spawn but NO conflict —
// a single transport failure at the retained generation. #10064 already skips
// retention here (same-gen, no new generation); m.cfg stays NEW and retained
// stays Gen-8. Passes pre- and post-fix; guards the #10064 pin.
func TestTickSameGenDivergedPreservesMcfg10066(t *testing.T) {
	t.Parallel()
	f := newDeferredPublishFixture9337(t, nil)
	oldUcfg, newUcfg := oldNewUcfg10066()
	seedDivergedTick10066(t, f, oldUcfg, newUcfg)
	rec := &applyRecorder9520{replies: []error{errLostResponse9520}}
	f.m.controlRequestHook = rec.hook

	if err := f.runSync(t); err == nil {
		t.Fatal("syncSnapshotLocked returned nil on a transport failure")
	}
	if got := rec.generations(); !slices.Equal(got, []uint64{8}) {
		t.Fatalf("apply_snapshot generations = %v, want [8] (no conflict, no retry)", got)
	}
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.m.lastSnapshot == nil || f.m.lastSnapshot.Generation != 8 {
		t.Fatal("same-gen failure moved retained; #10064 skips retention when nothing is new")
	}
	if f.m.generation != 8 {
		t.Fatalf("m.generation = %d, want 8 unchanged (same-gen consumes nothing)", f.m.generation)
	}
	if !reflect.DeepEqual(f.m.cfg, newUcfg) {
		t.Fatalf("m.cfg = %+v, want NEW %+v (same-gen must not touch the spawn record)", f.m.cfg, newUcfg)
	}
}

// TestCompileDifferStillAdoptsMcfg10066: a genuine Compile-differ (attempted
// NEW identity vs retained OLD) with a transport failure still adopts m.cfg.
// Guards against over-blocking: the #10066 guard must only skip the
// tick-differ (adopted == retained), never a new identity.
func TestCompileDifferStillAdoptsMcfg10066(t *testing.T) {
	t.Parallel()
	h := newDebtHarness9642(t)
	defer h.stopLoop(t)
	retained, attempted := buildDebtPair9642(t, true /* changedPlan: Workers 1 vs 2 */)
	h.seedPublished(t, retained)
	// Pre-spawn m.cfg (OLD) so the test is sensitive to advancement: skipping
	// the m.cfg write would leave OLD, failing the NEW assertion.
	h.m.mu.Lock()
	h.m.cfg = retained.Userspace
	h.m.mu.Unlock()
	if configEqual(attempted.Userspace, retained.Userspace) {
		t.Fatal("premise: Compile-differ requires attempted NEW != retained OLD")
	}
	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()

	h.m.mu.Lock()
	var status ProcessStatus
	err := h.m.publishSnapshotFailClosedLocked(attempted, &status, false /*mapsMutatedInPlace*/)
	h.m.mu.Unlock()
	if err == nil {
		t.Fatal("publishSnapshotFailClosedLocked returned nil on a transport failure")
	}
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if h.m.lastSnapshot == nil || h.m.lastSnapshot.Generation != 9 {
		t.Fatal("Compile-differ transport failure did not adopt the attempted generation (want Gen-9)")
	}
	if !reflect.DeepEqual(h.m.cfg, attempted.Userspace) {
		t.Fatalf("m.cfg = %+v, want attempted NEW %+v (Compile-differ must advance the spawn record)",
			h.m.cfg, attempted.Userspace)
	}
	if h.m.publishedSnapshot != 8 {
		t.Fatalf("publishedSnapshot = %d, want 8 held back", h.m.publishedSnapshot)
	}
}
