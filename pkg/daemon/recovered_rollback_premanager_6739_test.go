package daemon

// recovered_rollback_premanager_6739_test.go — #6739, work item G's provable half.
//
// A recovered commit-confirmed rollback can reach the apply tail BEFORE daemon
// startup has constructed the managers that tail dereferences.
//
// THE ORDERING, all of it on master:
//
//	daemon_run.go     SetRollbackExecutor(d.executeConfirmedRollback)  <- before the phase list
//	phase 1           loadAndBootstrapConfig -> Store.Load -> re-arms time.AfterFunc(remaining)
//	phase 2           interface-naming
//	phase 3           initManagers -> d.vrrpMgr = vrrp.NewManager()
//
// Nothing holds applySem across the phases, so the timer goroutine and the
// startup phases run concurrently. When `remaining` elapses before phase 3, the
// rollback dereferences a nil vrrpMgr and the daemon PANICS AT BOOT.
//
// `remaining` is strictly positive — an already-expired window is rolled back
// synchronously in an earlier branch of recoverPendingConfirmLocked and never
// reaches the re-arm — but it is bounded below only by how close the boot is to
// the deadline. `commit confirmed 1` plus a ~55s reboot arms seconds.
//
// The fix guards the dereference and fails CLOSED. It deliberately does NOT
// move the dispatch point: #6739 records that work item G's startup-readiness
// gate (release at end-of-phase-5) is unsafe without work item H, because it
// converts this short pre-manager window into a post-manager
// bootstrap-with-live-cluster hybrid. G/H/H2 remain unimplemented and
// unconverged.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
)

// daemonAtRecoveryWindow6739 models the daemon EXACTLY as it is when a
// recovered timer can fire: phase 1 done, so the store exists — it is the very
// object that armed the timer — and every manager initManagers builds is nil.
//
// A bare &Daemon{} would be the wrong fixture: it also has a nil store, which
// panics later in the same function for a reason production never reaches, and
// would make this cell pass for the wrong defect.
func daemonAtRecoveryWindow6739(t *testing.T) *Daemon {
	t.Helper()
	return &Daemon{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
	}
}

// TestRecoveredRollbackDoesNotPanicBeforeManagers6739 is the issue.
//
// FAIL-ON-REVERT: remove the `d.vrrpMgr == nil` arm in applyTailReconciles and
// this cell panics with a nil pointer dereference, which is what the daemon
// does at boot.
func TestRecoveredRollbackDoesNotPanicBeforeManagers6739(t *testing.T) {
	d := daemonAtRecoveryWindow6739(t)

	// Precondition: this is the state under test, not a bare struct.
	if d.vrrpMgr != nil {
		t.Fatal("precondition: vrrpMgr must be nil — phase 3 has not run")
	}
	if d.store == nil {
		t.Fatal("precondition: the store must exist — phase 1 armed the timer from it")
	}

	err := d.applyTailReconciles(&config.Config{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	// FAIL CLOSED, not "skip and report success". This site is already
	// fail-closed one branch below, because reporting a successful apply while
	// the manager does not hold the requested instance set claims HA coverage
	// that is not running. A nil manager holds no instance set at all.
	if err == nil {
		t.Fatal("a rollback that reached the VRRP reconcile with no VRRP manager reported " +
			"SUCCESS — the apply claimed HA coverage from a manager that does not exist " +
			"yet (#6739)")
	}
	if !strings.Contains(err.Error(), "VRRP manager not initialized") {
		t.Fatalf("apply failed for a different reason than the missing manager: %v", err)
	}
}

// TestVRRPGuardDoesNotFireWhenTheManagerExists6739 is the PAIRED control.
//
// Without it, "return an error when vrrpMgr is nil" is satisfied by a guard
// that fires unconditionally — which would fail every normal apply on the box
// while still passing the cell above.
func TestVRRPGuardDoesNotFireWhenTheManagerExists6739(t *testing.T) {
	d := daemonAtRecoveryWindow6739(t)
	d.vrrpMgr = vrrp.NewManager()

	err := d.applyTailReconciles(&config.Config{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil && strings.Contains(err.Error(), "VRRP manager not initialized") {
		t.Fatalf("the #6739 guard fired with a live VRRP manager present — it would fail "+
			"every ordinary apply: %v", err)
	}
}

// TestRecoveredWindowStillArmsATimerBeforeManagersExist6739 binds the ORDERING
// premise the guard above exists for, rather than trusting the reading.
//
// If a future change made Store.Load resolve every recovered window
// synchronously, or moved manager construction ahead of the config load, the
// guard would become dead code and this cell is what would say so.
func TestRecoveredWindowStillArmsATimerBeforeManagersExist6739(t *testing.T) {
	// The executor is registered before the startup phase list, and
	// loadAndBootstrapConfig (phase 1) runs before initManagers (phase 3).
	// Assert the two source facts the hazard rests on, so a reordering reds.
	runSrc := readSource6739(t, "daemon_run.go")
	iLoad := strings.Index(runSrc, "d.loadAndBootstrapConfig()")
	iInit := strings.Index(runSrc, "d.initManagers(")
	iExec := strings.Index(runSrc, "d.store.SetRollbackExecutor(")
	if iLoad < 0 || iInit < 0 || iExec < 0 {
		t.Fatalf("anchors not found (load=%d init=%d exec=%d) — the startup shape changed; "+
			"re-derive whether the #6739 window still exists", iLoad, iInit, iExec)
	}
	if !(iExec < iLoad && iLoad < iInit) {
		t.Fatalf("startup order changed: SetRollbackExecutor@%d, loadAndBootstrapConfig@%d, "+
			"initManagers@%d. The #6739 pre-manager window depends on executor-then-load-then-"+
			"managers; re-check the guard is still needed", iExec, iLoad, iInit)
	}
}

func readSource6739(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
