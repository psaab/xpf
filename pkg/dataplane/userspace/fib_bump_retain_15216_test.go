package userspace

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15216 (A29-03): a successful route-only BumpFIBGeneration advances
// m.lastSnapshot.Generation (and m.generation) but, before the fix, never
// touched m.publishedSnapshot. Until the next status tick re-aligned the
// pair (the hash catch-up in syncSnapshotLocked), a same-plan commit whose
// apply_snapshot was refused in-band inside that window reached
// retainPreviousClassifierPlanLocked with
// publishedSnapshot != lastSnapshot.Generation, so classifierPlanRetainable
// failed and the commit took the #4959 ctrl-disable path — a transient
// kernel-only transit drop — instead of the #7468 atomic retain, even
// though the helper was still enforcing exactly the retained snapshot
// (a FIB bump moves only the FIB view, never last_snapshot_generation).
//
// The fix advances publishedSnapshot on bump success when it equalled the
// pre-bump generation (mirroring advanceGenerationAfterPartialUpdateLocked's
// #6986 guard), and reverts it with the other speculative fields on a
// refusal/known-unsent restore. The #9337 deferral case — publishedSnapshot
// behind an unpublished lastSnapshot — stays non-retainable.
//
// RED on revert: dropping the `if prevPublished == prevSnapGen ...`
// advance in BumpFIBGeneration leaves publishedSnapshot at the pre-bump
// generation, so TestSamePlanRefusalAfterFIBBumpRetains15216 sees no
// rollback and ctrl disabled.

// fibBumpRetainManager15216 builds a manager whose helper has accepted
// generation 4 (publishedSnapshot == lastSnapshot.Generation == 4) and
// answers bump_fib_generation successfully, reporting the status the real
// helper returns after a confirmed bump. apply_snapshot requests are routed
// to applyErr when non-nil.
func fibBumpRetainManager15216(t *testing.T, applyErr error) (*Manager, *fakeCtrlMap) {
	t.Helper()
	m, ctrl := seamedManager(t)
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m.proc = &exec.Cmd{Process: proc}
	m.lastSnapshot = &ConfigSnapshot{
		Version:       ProtocolVersion,
		Generation:    4,
		FIBGeneration: 17,
		Config:        &config.Config{},
	}
	m.generation = 4
	m.publishedSnapshot = 4
	m.publishedPlanKey = snapshotBindingPlanKey(m.lastSnapshot)
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	}
	// Seed ctrl enabled so a fail-closed disable is observable.
	ctrl.haveStored = true
	ctrl.stored = userspaceCtrlValue{Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 4, QueueCount: 4}
	m.failClosedCtrlMapHook = ctrl
	m.bumpFIBGenerationHook = func() (uint32, error) { return 42, nil }
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		switch req.Type {
		case "bump_fib_generation":
			if status != nil {
				*status = *readyHelperStatus()
			}
			return nil
		case "apply_snapshot":
			return applyErr
		default:
			return nil
		}
	}
	return m, ctrl
}

// TestSamePlanRefusalAfterFIBBumpRetains15216 is the A29-03 cell: after a
// confirmed route-only bump, a same-plan commit refused in-band must take
// the #7468 retain (classifier maps rolled back to the retained snapshot,
// ctrl left enabled), not the ctrl-disable path.
func TestSamePlanRefusalAfterFIBBumpRetains15216(t *testing.T) {
	refusal := newHelperRejection("snapshot integrity preflight rejected")
	m, ctrl := fibBumpRetainManager15216(t, refusal)

	var syncedTo []*ConfigSnapshot
	m.syncClassifierMapsHook = func(s *ConfigSnapshot) error {
		syncedTo = append(syncedTo, s)
		return nil
	}
	if _, err := m.BumpFIBGeneration(); err != nil {
		t.Fatalf("BumpFIBGeneration: %v", err)
	}

	m.mu.Lock()
	genAfterBump, publishedAfterBump := m.lastSnapshot.Generation, m.publishedSnapshot
	retained := m.lastSnapshot
	m.mu.Unlock()
	if genAfterBump != 5 {
		t.Fatalf("lastSnapshot.Generation = %d after bump, want 5", genAfterBump)
	}
	if publishedAfterBump != genAfterBump {
		t.Fatalf("publishedSnapshot = %d after a confirmed route-only bump, want %d: "+
			"the helper still enforces the retained snapshot, so the pair must stay "+
			"aligned or the #7468 retain predicate cannot recognise it (#15216)",
			publishedAfterBump, genAfterBump)
	}

	// Same-plan commit (classifier maps mutated in place) refused in-band.
	// The bump's own helper-status sync also rolls through the hook; only
	// syncs from the refused publish below count.
	syncedTo = nil
	refused := &ConfigSnapshot{Generation: 6, Config: &config.Config{}}
	var status ProcessStatus
	m.mu.Lock()
	err := m.publishPreparedSnapshotFailClosedLocked(refused, &status, true)
	m.mu.Unlock()
	if !errors.Is(err, refusal) {
		t.Fatalf("publish error = %v, want it to carry the helper refusal", err)
	}
	if len(syncedTo) != 1 || syncedTo[0] != retained {
		t.Fatalf("classifier maps synced %d time(s) after a post-bump refusal, want exactly "+
			"one rollback to the retained generation %d. The route-only bump left "+
			"publishedSnapshot behind lastSnapshot.Generation, so the retain "+
			"predicate failed and the commit disabled ctrl instead of retaining "+
			"the plan the helper still enforces (#15216).",
			len(syncedTo), genAfterBump)
	}
	if ctrl.stored.Enabled != 1 {
		t.Fatalf("userspace_ctrl.Enabled = %d after a refused same-plan commit "+
			"following a route-only bump, want 1 (retained plan keeps transit)",
			ctrl.stored.Enabled)
	}
}

// TestFIBBumpDoesNotLeapfrogDeferredPublish15216 is the #9337 control: when
// a deferred publish is outstanding (publishedSnapshot behind
// lastSnapshot.Generation), the bump must NOT advance publishedSnapshot —
// the tick gate must still see unpublished work — and a refusal of that
// deferred snapshot stays non-retainable.
func TestFIBBumpDoesNotLeapfrogDeferredPublish15216(t *testing.T) {
	m, _ := fibBumpRetainManager15216(t, nil)

	// Model the pendingXSKStartup deferral: generation 8 retained,
	// generation 4 still the helper-enforced published one.
	m.mu.Lock()
	m.lastSnapshot.Generation = 8
	m.generation = 8
	m.mu.Unlock()

	if _, err := m.BumpFIBGeneration(); err != nil {
		t.Fatalf("BumpFIBGeneration: %v", err)
	}
	m.mu.Lock()
	gen, published := m.lastSnapshot.Generation, m.publishedSnapshot
	m.mu.Unlock()
	if gen != 9 {
		t.Fatalf("lastSnapshot.Generation = %d after bump, want 9", gen)
	}
	if published != 4 {
		t.Fatalf("publishedSnapshot = %d after a bump over a deferred publish, want 4 unchanged: "+
			"advancing it would close the status tick's publish gate on a snapshot the "+
			"helper never received (#6986/#9337)", published)
	}
	if classifierPlanRetainable(true, m.lastSnapshot, published,
		newHelperRejection("snapshot integrity preflight rejected")) {
		t.Fatal("the #9337 deferral case became retainable after a FIB bump; " +
			"the refused deferred snapshot must stay non-retainable")
	}
}

// TestFIBBumpRefusalRestoresPublishedSnapshot15216 pins the speculative
// advance's other half: when the helper refuses the bump in-band (or the
// request is known unsent), the #10724 restore must revert
// publishedSnapshot together with the generation/FIB fields, so local
// bookkeeping never describes an unpublished bump as published.
func TestFIBBumpRefusalRestoresPublishedSnapshot15216(t *testing.T) {
	rejected := newHelperRejection("fib generation rollback rejected")
	m, _ := fibBumpRetainManager15216(t, nil)
	m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.Type == "bump_fib_generation" {
			return rejected
		}
		return nil
	}

	if _, err := m.BumpFIBGeneration(); !errors.Is(err, errHelperRejected) {
		t.Fatalf("BumpFIBGeneration error = %v, want helper rejection", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot.Generation != 4 || m.generation != 4 {
		t.Fatalf("refusal left generations at snapshot=%d allocator=%d, want restored 4/4",
			m.lastSnapshot.Generation, m.generation)
	}
	if m.publishedSnapshot != 4 {
		t.Fatalf("publishedSnapshot = %d after a refused bump, want restored 4: "+
			"the speculative advance must be reverted with the other bump fields (#10724)",
			m.publishedSnapshot)
	}
	if m.lastSnapshot.FIBGeneration != 17 {
		t.Fatalf("lastSnapshot.FIBGeneration = %d after refusal, want restored 17",
			m.lastSnapshot.FIBGeneration)
	}
}
