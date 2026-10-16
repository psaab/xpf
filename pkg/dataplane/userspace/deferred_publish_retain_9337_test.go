package userspace

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9337: the #7468 atomic retain was UNSOUND on the deferred-publish path.
//
// retainPreviousClassifierPlanLocked treats m.lastSnapshot as "the snapshot the
// helper is still enforcing". That is true at every publish site except one:
// applyCompiledSnapshot's pendingXSKStartup branch assigns m.lastSnapshot = snap
// and RETURNS, deferring the publish to syncSnapshotLocked. syncSnapshotLocked
// then publishes m.lastSnapshot ITSELF, so on an in-band {"ok":false} the
// "rollback" re-syncs the classifier maps to the very plan the helper just
// refused, reports success, and leaves ctrl at Enabled=1 — the shim keeps
// steering transit against a plan the helper never accepted while the helper
// enforces the previous-good one. That is the #4959 fail-open, reintroduced by
// its own remedy.
//
// The privileged guard for the deferred path
// (TestDeferredPublishRejectedFailsClosed4959) could not see it, and the reason
// is worth recording because it is the general shape: it reached ctrl.Enabled=0
// through the WRONG BRANCH. Its harness loads no classifier maps, so the
// rollback failed with "userspace_ingress_ifaces map not loaded" and fell into
// the ctrl-disable fallback. The cell asserted the right outcome for a reason
// that does not exist in production, where the maps ARE loaded and the rollback
// succeeds. These cells install the syncClassifierMapsHook seam so the rollback
// SUCCEEDS, which is the only configuration in which the defect is observable.
//
// They are unprivileged by construction: the observable is the snapshot
// IDENTITY handed to the classifier sync, not a BPF map.

// deferredPublishFixture9337 models the manager exactly as the pendingXSKStartup
// deferral leaves it: m.lastSnapshot is the snapshot awaiting publication and
// m.publishedSnapshot still names the older generation the helper is enforcing.
type deferredPublishFixture9337 struct {
	m    *Manager
	snap *ConfigSnapshot
	// ctrl is the userspace_ctrl row the fail-closed path writes through,
	// seeded Enabled=1 (a running, enabled firewall) so a disable is
	// observable rather than indistinguishable from a no-op.
	ctrl *fakeCtrlMap

	mu       sync.Mutex
	syncedTo []*ConfigSnapshot
}

func newDeferredPublishFixture9337(t *testing.T, publishErr error) *deferredPublishFixture9337 {
	t.Helper()
	f := &deferredPublishFixture9337{}

	snap, err := buildSnapshot(&config.Config{}, config.UserspaceConfig{}, 8, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.lastSnapshot = snap
	// The helper accepted generation 1 and has been sent nothing since; the
	// pendingXSKStartup branch left generation 8 in m.lastSnapshot unpublished.
	m.publishedSnapshot = 1
	m.publishedPlanKey = snapshotBindingPlanKey(snap)
	m.xskLivenessProven = false
	m.xskLivenessFailed = false
	// A helper version has been observed and matches, so
	// ensureEgressZoneProtocolLocked short-circuits instead of spending a
	// control round-trip. (The privileged 4959 fixture did NOT seed this, and
	// the resulting extra `status` request ate its control server's only queued
	// response — see the fixture note there.)
	m.lastStatus = ProcessStatus{
		ConfigSnapshotProtocolVersion: ProtocolVersion,
		LastSnapshotGeneration:        1,
	}
	m.helperStatusObserved = true

	f.ctrl = &fakeCtrlMap{
		stored:     userspaceCtrlValue{Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 4, QueueCount: 4},
		haveStored: true,
	}
	m.failClosedCtrlMapHook = f.ctrl
	// applyHelperStatusLocked runs on the success path and operates on two more
	// shim maps; seam them so a landed publish returns nil instead of a
	// "map not loaded" error that the success cell would have to tolerate.
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}

	m.syncClassifierMapsHook = func(s *ConfigSnapshot) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.syncedTo = append(f.syncedTo, s)
		return nil
	}
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type != "apply_snapshot" {
			return nil
		}
		return publishErr
	}

	f.m = m
	f.snap = snap
	return f
}

func (f *deferredPublishFixture9337) rollbacks() []*ConfigSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*ConfigSnapshot, len(f.syncedTo))
	copy(out, f.syncedTo)
	return out
}

// runSync drives the real deferred-publish path and stops the reconcile worker
// the rejection starts, so the recorder cannot be written concurrently with the
// assertions.
func (f *deferredPublishFixture9337) runSync(t *testing.T) error {
	t.Helper()
	f.m.mu.Lock()
	err := f.m.syncSnapshotLocked()
	cancel := f.m.syncCancel
	f.m.syncCancel = nil
	f.m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return err
}

// TestDeferredPublishRefusalCannotRollBackToTheRefusedPlan9337 is the cell the
// defect fails.
//
// The classifier maps must NOT be "rolled back" to m.lastSnapshot here: it is
// the snapshot the helper just refused, so the sync is a no-op that reports
// success and licenses leaving ctrl enabled against a plan the helper never
// accepted.
func TestDeferredPublishRefusalCannotRollBackToTheRefusedPlan9337(t *testing.T) {
	refusal := newHelperRejection("snapshot integrity preflight rejected")
	f := newDeferredPublishFixture9337(t, refusal)

	err := f.runSync(t)
	if err == nil {
		t.Fatal("syncSnapshotLocked returned nil for a refused deferred publish")
	}
	if !errors.Is(err, refusal) {
		t.Fatalf("returned error = %v, want it to carry the helper's refusal", err)
	}

	if got := f.rollbacks(); len(got) != 0 {
		t.Fatalf("the refused deferred publish rolled the classifier maps to generation %d, "+
			"which is the generation that was just REFUSED (published generation is %d). "+
			"That sync is a no-op dressed as a rollback: it succeeds, so "+
			"retainPreviousClassifierPlanLocked skips the ctrl-disable and the shim keeps "+
			"steering transit against a plan the helper never accepted while the helper "+
			"enforces generation %d — the #4959 fail-open (#9337).",
			got[0].Generation, f.m.publishedSnapshot, f.m.publishedSnapshot)
	}

	f.m.mu.Lock()
	published := f.m.publishedSnapshot
	f.m.mu.Unlock()
	if published != 1 {
		t.Fatalf("publishedSnapshot = %d after a REFUSED deferred publish, want 1 unchanged; "+
			"the refused snapshot must not be recorded as the enforced one", published)
	}

	// The security property itself, observed on the row production writes.
	if f.ctrl.stored.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled = %d after a refused deferred publish, want 0. "+
			"The classifier maps hold generation %d and the helper is enforcing generation "+
			"%d, so an enabled shim redirects transit to XSK against a plan the helper "+
			"never accepted (#4959 fail-open, #9337 residual on the deferred path).",
			f.ctrl.stored.Enabled, f.snap.Generation, published)
	}
}

// TestDeferredPublishTransportFailureStillDoesNotRollBack9337 pins the
// pre-existing #7468 discriminator on this path too. It is not a duplicate of
// the cell above: it fails for a DIFFERENT conjunct (the error class), so a fix
// that dropped the error-class test and kept the generation test would still be
// caught.
func TestDeferredPublishTransportFailureStillDoesNotRollBack9337(t *testing.T) {
	transport := errors.New("write: broken pipe")
	f := newDeferredPublishFixture9337(t, transport)

	if err := f.runSync(t); err == nil {
		t.Fatal("syncSnapshotLocked returned nil for a failed deferred publish")
	}
	if got := f.rollbacks(); len(got) != 0 {
		t.Fatalf("classifier maps were rolled back to generation %d after a TRANSPORT "+
			"failure; the helper may already be enforcing the published snapshot and a "+
			"rollback leaves the maps a generation BEHIND it", got[0].Generation)
	}
}

// TestDeferredPublishSuccessLandsAndKeepsCtrlEnabled9337 is the transparency
// control. Without it the two cells above are satisfied by a predicate that
// refuses everything — including a healthy commit — and "ctrl was disabled"
// would be indistinguishable from "ctrl is disabled on every path".
func TestDeferredPublishSuccessLandsAndKeepsCtrlEnabled9337(t *testing.T) {
	f := newDeferredPublishFixture9337(t, nil)

	err := f.runSync(t)
	if err != nil {
		t.Fatalf("syncSnapshotLocked on the success path returned %v, want nil", err)
	}
	// No assertion on the classifier-sync recorder here: on the SUCCESS path
	// applyHelperStatusLocked legitimately re-syncs the classifier maps from
	// m.lastSnapshot (#6994), so a sync recorded here is the normal reconcile,
	// not a rollback. The properties that separate "the publish landed" from
	// "the wrap short-circuited it" are the two below.
	f.m.mu.Lock()
	published := f.m.publishedSnapshot
	f.m.mu.Unlock()
	if published != f.snap.Generation {
		t.Fatalf("publishedSnapshot = %d after a successful deferred publish, want %d — "+
			"the publish must land", published, f.snap.Generation)
	}
	if f.ctrl.stored.Enabled != 1 {
		t.Fatalf("userspace_ctrl.Enabled = %d after a SUCCESSFUL deferred publish, want 1 "+
			"unchanged; the fail-closed wrap must not turn a healthy address commit into "+
			"a transit drop", f.ctrl.stored.Enabled)
	}
}

// TestOrdinaryRefusalStillRetainsThePreviousPlan9337 is the OTHER direction,
// and it is the one that makes the fix a narrowing rather than a revert of
// #7468. On the ordinary Compile path m.publishedSnapshot names m.lastSnapshot,
// the helper really is still enforcing it, and the atomic retain must survive —
// #6707 criterion 1 is that transit does not drop for a second on every refused
// policy update.
//
// It drives the same retainPreviousClassifierPlanLocked the cells above reach,
// so a predicate that simply refused every retain would red here.
func TestOrdinaryRefusalStillRetainsThePreviousPlan9337(t *testing.T) {
	retained := &ConfigSnapshot{Generation: 41}
	refused := &ConfigSnapshot{Generation: 42}

	m := New()
	m.lastSnapshot = retained
	m.publishedSnapshot = retained.Generation
	var syncedTo []*ConfigSnapshot
	m.syncClassifierMapsHook = func(s *ConfigSnapshot) error {
		syncedTo = append(syncedTo, s)
		return nil
	}
	m.controlRequestHook = func(ControlRequest, *ProcessStatus) error {
		return newHelperRejection("integrity preflight rejected")
	}

	var status ProcessStatus
	m.prepareSnapshotForApply(refused)
	err := m.publishPreparedSnapshotFailClosedLocked(refused, &status, true)
	if m.syncCancel != nil {
		m.syncCancel()
	}
	if err == nil {
		t.Fatal("prepared fail-closed publish returned nil on a refused publish")
	}
	if len(syncedTo) != 1 || syncedTo[0] != retained {
		t.Fatalf("classifier maps synced %d time(s) on the ordinary Compile path, want exactly "+
			"one rollback to the retained generation %d. The #9337 narrowing must not turn a "+
			"refused policy update back into a one-second transit drop (#6707 criterion 1).",
			len(syncedTo), retained.Generation)
	}
}
