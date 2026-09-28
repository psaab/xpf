package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/vrrp"
)

// #9175 — the #4957 applied marker was never invalidated, so a promote/fail/
// re-promote flap reported a config that never converged as converged.
//
// `MarkActiveApplied` and `MarkAppliedDigest` were the digest's ONLY writers, so
// it recorded a success and nothing ever unrecorded one. The store's field
// comment justified that with "the marker is keyed on the config text, so a
// stale value can only make the shortcut MORE conservative … never falsely
// converged". That holds for a FORWARD sequence, where every promotion moves the
// active text away from the stamped digest. It does not hold for RE-PROMOTION of
// a text that already applied once in this process — the leftover digest matches
// the active text again.
//
// `handleConfigSync` then takes its converged shortcut, returns nil, and the HA
// config high-water advances past a generation the dataplane never took. The
// standby reports the generation applied while holding an older one, and the
// failure is only observable at a failover.
//
// THESE CELLS DRIVE `applyConfigLocked`, not the store. The invalidation lives
// at that one choke point precisely so no caller has to remember it, and a cell
// that called the store method directly would be green on a build where nothing
// calls it — presence, not reachability.

const (
	confA9175 = "system {\n    host-name node-a;\n}\n"
	confB9175 = "system {\n    host-name node-b;\n}\n"
)

// applyMarkerDaemon9175 builds a Daemon wired to drive the REAL
// applyConfigLocked body against a real store. Same shape as the #2926
// cancellation fixture: d.routing/d.frr/d.networkd are nil, so the netlink
// phases are skipped and a non-cancelled apply runs clean.
func applyMarkerDaemon9175(t *testing.T) *Daemon {
	t.Helper()
	installFakeNetworkctl(t)
	installSSHDSeam(t, &sshdSeamRecorder{})
	d := &Daemon{
		vrrpMgr: vrrp.NewManager(),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:    Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	return d
}

// promote9175 puts `text` in as the active config through the HA config-sync
// ingress — the same entry point the defect is reached from — and hands back the
// compiled tree so it can be handed to applyConfigLocked.
func promote9175(t *testing.T, d *Daemon, text string) {
	t.Helper()
	if _, err := d.store.SyncApply(text, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
}

// failApply9175 drives a REAL applyConfigLocked that FAILS. The failure is a
// cancelled context, which is a genuine production failure mode (#2926, a daemon
// stop landing mid-apply) rather than an injected sentinel, and it bails before
// any side effect — so the config is promoted and never converged, which is
// exactly the state the marker must not vouch for.
func failApply9175(t *testing.T, d *Daemon) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.applyConfigLocked(ctx, d.store.ActiveConfig()); err == nil {
		t.Fatal("CONTROL FAILED: applyConfigLocked returned nil for a cancelled " +
			"context, so this cell never drove a FAILED apply and can prove nothing")
	}
}

// THE DEFECT, in the issue's own three-step shape. Every step is asserted,
// including the middle one — a two-step test cannot see this, because the marker
// only matches again on RE-promotion.
func TestPromotionFlapDoesNotFalselyConverge9175(t *testing.T) {
	d := applyMarkerDaemon9175(t)

	// step 1: A is promoted and its apply SUCCEEDS.
	promote9175(t, d, confA9175)
	if err := d.applyConfigLocked(context.Background(), d.store.ActiveConfig()); err != nil {
		t.Fatalf("CONTROL FAILED: the step-1 apply of A must succeed, got %v", err)
	}
	d.store.MarkActiveApplied()
	if !d.store.ActiveApplied() {
		t.Fatal("CONTROL FAILED: A must read applied after a successful apply; " +
			"with the marker never armed, step 3 below is vacuously correct")
	}

	// step 2: B is promoted and its apply FAILS. Conservative and already
	// correct today — this is the row that shows the shortcut is normally right,
	// and it must not regress.
	promote9175(t, d, confB9175)
	failApply9175(t, d)
	if d.store.ActiveApplied() {
		t.Fatal("step 2: a promoted-but-unapplied config must NOT read as applied " +
			"(#4957). This is the pre-existing invariant, not the #9175 defect")
	}

	// step 3: A is RE-promoted and its apply ALSO fails. The digest left over
	// from step 1 matches the active text again.
	promote9175(t, d, confA9175)
	failApply9175(t, d)
	if d.store.ActiveApplied() {
		t.Error("#9175: after A -> B(fail) -> A(fail) the store reports the config " +
			"CONVERGED for a dataplane that never took it.\n" +
			"  MarkActiveApplied and MarkAppliedDigest were the digest's only " +
			"writers, so nothing ever unrecorded a success, and step 1's digest " +
			"matches the active text again after the re-promotion.\n" +
			"  handleConfigSync then takes its converged shortcut, returns nil, and " +
			"the HA config high-water advances past a generation the standby never " +
			"applied — the #4957 fail-open, re-entered through the remedy #4957 " +
			"itself prescribed. Only observable at failover.")
	}
}

// The same defect in its shortest form, and the one that binds the WIRING: a
// failed apply of the config that is ALREADY marked applied must un-mark it. No
// intervening promotion, so nothing but the failure can be doing the work.
func TestFailedApplyClearsTheAppliedMarker9175(t *testing.T) {
	d := applyMarkerDaemon9175(t)
	promote9175(t, d, confA9175)
	d.store.MarkActiveApplied()
	if !d.store.ActiveApplied() {
		t.Fatal("CONTROL FAILED: the marker was never armed")
	}

	failApply9175(t, d)

	if d.store.ActiveApplied() {
		t.Error("#9175: an apply of the active config FAILED and the applied marker " +
			"still vouches for it. applyConfigLocked is the one choke point every " +
			"apply in the daemon goes through, so its error path is where the " +
			"marker has to be dropped")
	}
}

// LOAD-BEARING CONTROL. A SUCCESSFUL apply must leave the marker standing.
// "Invalidate on every apply" satisfies both cells above and reds here, and it
// would silently disable the #4957 convergence shortcut — turning every peer
// re-push into a redundant full apply on a standby.
func TestSuccessfulApplyKeepsTheAppliedMarker9175(t *testing.T) {
	d := applyMarkerDaemon9175(t)
	promote9175(t, d, confA9175)
	d.store.MarkActiveApplied()

	if err := d.applyConfigLocked(context.Background(), d.store.ActiveConfig()); err != nil {
		t.Fatalf("the apply must succeed for this control to mean anything: %v", err)
	}

	if !d.store.ActiveApplied() {
		t.Error("a SUCCESSFUL apply cleared the applied marker. The #4957 shortcut " +
			"then never fires, and every peer config-sync re-push re-applies a " +
			"config that is already live — which is the cost #4957 exists to avoid")
	}
}

// The other direction of the same control, through the config-sync stamp pair
// (#6296): a capture/replay stamp taken after a SUCCESSFUL apply must survive.
func TestCapturedDigestStampSurvivesASuccessfulApply9175(t *testing.T) {
	d := applyMarkerDaemon9175(t)
	promote9175(t, d, confA9175)
	captured := d.store.ActiveDigest()
	if captured == "" {
		t.Fatal("CONTROL FAILED: ActiveDigest is empty, so nothing was captured")
	}
	if err := d.applyConfigLocked(context.Background(), d.store.ActiveConfig()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	d.store.MarkAppliedDigest(captured)
	if !d.store.ActiveApplied() {
		t.Error("the #6296 capture/replay stamp must still arm the marker after a " +
			"successful apply")
	}
}

// A daemon with no store must not panic on the failure path. The guard is
// cheap and every other apply-path store access in this file carries one.
func TestFailedApplyWithNoStoreDoesNotPanic9175(t *testing.T) {
	installFakeNetworkctl(t)
	d := &Daemon{vrrpMgr: vrrp.NewManager(), opts: Options{NoDataplane: true}}
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.applyConfigLocked(ctx, nil); err != nil {
		// A nil cfg returns nil before the cancellation boundary on some paths;
		// either outcome is fine here. The cell is about not panicking.
		_ = err
	}
}
