package upgrade

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

type rollbackRejoinTrace17957 struct {
	*fakeCluster
	events []string
}

func (c *rollbackRejoinTrace17957) SyncEstablished() (bool, error) {
	c.events = append(c.events, "sync")
	return c.fakeCluster.SyncEstablished()
}

func (c *rollbackRejoinTrace17957) ResetFailover() error {
	c.events = append(c.events, "reset")
	return c.fakeCluster.ResetFailover()
}

func (c *rollbackRejoinTrace17957) LocalRejoinComplete() (bool, error) {
	c.events = append(c.events, "rejoin")
	return c.fakeCluster.LocalRejoinComplete()
}

// #17957: twin of #17840 on the rolling ROLLBACK path. A SIGINT/SIGHUP
// landing in the STOP window of RollbackTo is deferred by the inner
// rollback (#16796): executeRollback finishes restore -> flip -> START
// + health, clears the journal, and only then returns the
// rolled-back-then-deferred error. Pre-fix that error was a plain
// fmt.Errorf, and runRollingRollbackWith classified only
// errRollbackRefusedBeforeStop as benign — every other RollbackTo error
// (including the committed deferred one) took the "single-node rollback
// failed (inspect the drained node)" arm and SKIPPED the sync wait +
// RejoinAndConfirm below it. The rollback had committed and the daemon
// was running the rollback target, but the node stayed
// ForceSecondary-drained (the #17840 wedge on the rollback path).
//
// RED pre-fix: the committed case below observes resetCalled=false and
// rejoinChecks=0 while runRollingRollbackWith reports
// "single-node rollback failed".
// FAIL-ON-REVERT: drop the committed arm in runRollingRollbackWith (or
// return to the plain fmt.Errorf at the rollback completion boundary)
// and the committed case goes RED again; the controls pin the
// neighbouring arms so the committed arm cannot be widened.

// Defect cell: signal delivered at StopUnit entry during a rolling
// rollback. The rollback must commit, then sync + rejoin must still run
// before the deferred error surfaces.
func TestRollingRollbackCommittedDeferredStillRejoins17957(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	cl := &rollbackRejoinTrace17957{fakeCluster: &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}}

	g, stop := InstallSignalGuard(nil)
	defer stop()
	fx.fs.stopHook = func() { g.DeliverForTest(syscall.SIGINT) }
	fx.fs.healthHook = func() { cl.events = append(cl.events, "rollback-health") }

	rc := fastRC()
	rc.SignalGuard = g
	err := runRollingRollbackWith(fx.r, cl, rc, "")
	if err == nil || !strings.Contains(err.Error(), "rolled back") || !strings.Contains(err.Error(), "deferred") {
		t.Fatalf("rolling rollback with mid-STOP SIGINT: err = %v, want the rolled-back-then-deferred error to surface after rejoin", err)
	}
	var committedDeferred *rollbackCommittedDeferredError
	if !errors.As(err, &committedDeferred) {
		t.Fatalf("rolling rollback with mid-STOP SIGINT: err = %v (%T), want *rollbackCommittedDeferredError", err, err)
	}
	// The rollback itself committed and the daemon is running the target.
	if got := currentTarget(t, fx.cfg); got != "1.0.0" {
		t.Fatalf("current = %q, want 1.0.0 (rollback committed despite SIGINT)", got)
	}
	if !fx.fs.unitRunning {
		t.Fatal("unit not running after committed deferred rollback")
	}
	// Sync + rejoin ran: the drain was actually undone, not merely left.
	if !cl.forced {
		t.Error("ForceSecondary not called (drain never started)")
	}
	if cl.syncPolls <= 1 {
		t.Errorf("SyncEstablished polled %d times, want >1 (sync wait ran after the rollback)", cl.syncPolls)
	}
	if !cl.resetCalled {
		t.Error("ResetFailover not called — node left ForceSecondary after a committed rollback (#17957 defect)")
	}
	if cl.rejoinChecks == 0 {
		t.Error("LocalRejoinComplete never consulted — rejoin not confirmed after a committed rollback (#17957 defect)")
	}
	wantEvents := []string{"sync", "rollback-health", "sync", "sync", "reset", "sync", "rejoin"}
	if got := strings.Join(cl.events, ","); got != strings.Join(wantEvents, ",") {
		t.Errorf("rollback/rejoin call order = %v, want %v", cl.events, wantEvents)
	}
}

// Control: rejoin never confirms after a committed deferred rollback.
// The rejoin error must surface (not the deferred error) and the rejoin
// must have been attempted. Mirrors the forward fold cell in #17840.
func TestRollingRollbackCommittedDeferredRejoinFailure17957(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}
	cl.rejoinIncomplete = true // configured RG never leaves the drain

	g, stop := InstallSignalGuard(nil)
	defer stop()
	fx.fs.stopHook = func() { g.DeliverForTest(syscall.SIGINT) }

	rc := rejoinRC()
	rc.SignalGuard = g
	err := runRollingRollbackWith(fx.r, cl, rc, "")
	if err == nil || !strings.Contains(err.Error(), "did not rejoin") {
		t.Fatalf("rolling rollback with committed-deferred + incomplete rejoin: err = %v, want the rejoin error to surface", err)
	}
	if strings.Contains(err.Error(), "deferred") {
		t.Fatalf("rejoin failure masked by the deferred error: %v", err)
	}
	if got := currentTarget(t, fx.cfg); got != "1.0.0" {
		t.Fatalf("current = %q, want 1.0.0 (rollback committed despite rejoin failure)", got)
	}
	if !cl.resetCalled {
		t.Error("ResetFailover not called — rejoin was not attempted")
	}
	if cl.rejoinChecks == 0 {
		t.Error("LocalRejoinComplete never consulted — rejoin confirmation not attempted")
	}
}

// Control: a genuine post-STOP rollback failure (target starts but
// never health-confirms) must keep the destructive arm — node left
// secondary for inspection, sync/rejoin skipped, and the error must NOT
// classify as committed-deferred. The committed arm must not widen.
func TestRollingRollbackFailedRollbackStillLeavesNodeSecondary17957(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	fx.fs.healthFailVersions["1.0.0"] = true
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}

	err := runRollingRollbackWith(fx.r, cl, fastRC(), "")
	if err == nil || !strings.Contains(err.Error(), "single-node rollback failed") {
		t.Fatalf("rolling rollback with unhealthy target: err = %v, want single-node rollback failed", err)
	}
	var committedDeferred *rollbackCommittedDeferredError
	if errors.As(err, &committedDeferred) {
		t.Fatalf("destructive rollback failure misclassified as committed-deferred: %v", err)
	}
	if !cl.forced {
		t.Error("ForceSecondary not called (drain never started)")
	}
	if cl.resetCalled {
		t.Error("ResetFailover called after a destructive rollback failure — node must stay secondary for operator inspection")
	}
	if cl.rejoinChecks != 0 {
		t.Errorf("LocalRejoinComplete consulted %d times, want 0 (no rejoin after a destructive rollback failure)", cl.rejoinChecks)
	}
	if cl.syncPolls != 1 {
		t.Errorf("SyncEstablished polled %d times, want 1 (precondition only; sync wait must not run after a failed rollback)", cl.syncPolls)
	}
}
