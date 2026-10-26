package upgrade

import (
	"strings"
	"syscall"
	"testing"
)

// #17840: a SIGINT/SIGHUP landing in the STOP window of a rolling
// upgrade is deferred by the inner cut (#16796): Run finishes
// START+COMMIT and only then returns the committed-then-deferred
// error. Pre-fix that error was a plain fmt.Errorf, and
// runRollingWith classified only *cutBeforeStopError as benign —
// every other cut error took the destructive arm, returning
// "single-node cut failed" and SKIPPING steps 6-7 (SyncEstablished
// wait + RejoinAndConfirm). The cut had committed and the daemon was
// running the new version, but the node stayed ForceSecondary-drained
// (the #6557 "silently ineligible" wedge) with the operator told the
// cut failed.
//
// RED pre-fix: the committed case below observes resetCalled=false
// and rejoinChecks=0 while runRollingWith reports a failed cut.
// FAIL-ON-REVERT: drop the committed arm in runRollingWith (or return
// to the plain fmt.Errorf at the COMMIT boundary) and the committed
// case goes RED again; the two controls pin the neighbouring arms so
// the committed arm cannot be widened to swallow them.

// Defect cell: signal delivered at StopUnit entry during a rolling
// cut. The cut must commit, then steps 6-7 must still run before the
// deferred error surfaces.
func TestRollingCommittedDeferredCutStillRejoins17840(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	cl := healthyRollingCluster()

	g, stop := InstallSignalGuard(nil)
	defer stop()
	fs.stopHook = func() { g.DeliverForTest(syscall.SIGINT) }

	rc := rejoinRC()
	rc.SignalGuard = g
	err := runRollingWith(r, cl, rc)
	if err == nil || !strings.Contains(err.Error(), "committed") || !strings.Contains(err.Error(), "deferred") {
		t.Fatalf("rolling with mid-STOP SIGINT: err = %v, want the committed-then-deferred error to surface after rejoin", err)
	}
	// The cut itself committed and the daemon is running the target.
	if got := currentTarget(t, cfg); got != "2.0.0" {
		t.Fatalf("current = %q, want 2.0.0 (cut committed despite SIGINT)", got)
	}
	if !fs.unitRunning {
		t.Fatal("unit not running after committed deferred cut")
	}
	if proof := r.LastCommittedCut(); !proof.healthConfirmed {
		t.Fatal("LastCommittedCut not recorded for the committed cut")
	}
	// Steps 6-7 ran: the drain was actually undone, not merely requested.
	if !cl.forced {
		t.Error("ForceSecondary not called (drain never started)")
	}
	if cl.syncPolls <= 1 {
		t.Errorf("SyncEstablished polled %d times, want >1 (step 6 wait ran after the cut)", cl.syncPolls)
	}
	if !cl.resetCalled {
		t.Error("ResetFailover not called — node left ForceSecondary after a committed cut (#17840 defect)")
	}
	if cl.rejoinChecks == 0 {
		t.Error("LocalRejoinComplete never consulted — rejoin not confirmed after a committed cut (#17840 defect)")
	}
}

// Control: a pre-STOP signal still takes the designed failback arm —
// no cut, failback confirmed, error surfaces. The committed arm must
// not absorb this class.
func TestRollingPreStopSignalStillFailsBack17840(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	cl := healthyRollingCluster()

	g, stop := InstallSignalGuard(nil)
	defer stop()
	g.DeliverForTest(syscall.SIGHUP)

	rc := rejoinRC()
	rc.SignalGuard = g
	err := runRollingWith(r, cl, rc)
	if err == nil || !strings.Contains(err.Error(), "refused before STOP") {
		t.Fatalf("rolling with pre-STOP SIGHUP: err = %v, want refused-before-STOP failback", err)
	}
	for _, c := range fs.calls {
		if c == "stop" {
			t.Fatalf("StopUnit called despite pre-STOP abort; calls=%v", fs.calls)
		}
	}
	if got := currentTarget(t, cfg); got != "1.0.0" {
		t.Fatalf("current = %q, want 1.0.0 (no cut on pre-STOP abort)", got)
	}
	if !cl.resetCalled {
		t.Error("pre-STOP failback did not call ResetFailover")
	}
	if cl.syncPolls != 1 {
		t.Errorf("SyncEstablished polled %d times, want 1 (precondition only; step 6 must not run without a cut)", cl.syncPolls)
	}
}

// Control: a genuine post-STOP cut failure (target starts but never
// health-confirms, HA rollback operator-driven) must keep the
// destructive arm — node left secondary for inspection, steps 6-7
// skipped. The committed arm must not widen into this class.
func TestRollingFailedCutStillLeavesNodeSecondary17840(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	fs.healthFailVersions["2.0.0"] = true
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	cl := healthyRollingCluster()

	rc := rejoinRC()
	err := runRollingWith(r, cl, rc)
	if err == nil || !strings.Contains(err.Error(), "single-node cut failed") {
		t.Fatalf("rolling with unhealthy target: err = %v, want single-node cut failed", err)
	}
	if !cl.forced {
		t.Error("ForceSecondary not called (drain never started)")
	}
	if cl.resetCalled {
		t.Error("ResetFailover called after a destructive cut failure — node must stay secondary for operator inspection")
	}
	if cl.rejoinChecks != 0 {
		t.Errorf("LocalRejoinComplete consulted %d times, want 0 (no rejoin after a destructive cut failure)", cl.rejoinChecks)
	}
	if cl.syncPolls != 1 {
		t.Errorf("SyncEstablished polled %d times, want 1 (precondition only; step 6 must not run after a failed cut)", cl.syncPolls)
	}
}

// Fold regression cell (PR #17954 review): committed-deferred cut whose
// step-7 rejoin never confirms. The cc051e48bb gate retains
// LastCommittedCut only after RejoinAndConfirm succeeds; when rejoin
// fails, the rejoin error must surface (not the deferred error), the
// rejoin must have been attempted, and the proof must be CLEARED.
// RED pre-fold: gate on committedDeferred==nil retains the proof.
func TestRollingCommittedDeferredRejoinFailureClearsProof17840(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	cl := healthyRollingCluster()
	cl.rejoinIncomplete = true // configured RG never leaves the drain

	g, stop := InstallSignalGuard(nil)
	defer stop()
	fs.stopHook = func() { g.DeliverForTest(syscall.SIGINT) }

	rc := rejoinRC()
	rc.SignalGuard = g
	err := runRollingWith(r, cl, rc)
	if err == nil || !strings.Contains(err.Error(), "did not rejoin") {
		t.Fatalf("rolling with committed-deferred cut + incomplete rejoin: err = %v, want the rejoin error to surface", err)
	}
	if strings.Contains(err.Error(), "deferred") {
		t.Fatalf("rejoin failure masked by the deferred error: %v", err)
	}
	if got := currentTarget(t, cfg); got != "2.0.0" {
		t.Fatalf("current = %q, want 2.0.0 (cut committed despite rejoin failure)", got)
	}
	if proof := r.LastCommittedCut(); proof.healthConfirmed {
		t.Fatalf("LastCommittedCut retained after failed rejoin: %+v, want cleared proof", proof)
	}
	if !cl.resetCalled {
		t.Error("ResetFailover not called — rejoin was not attempted")
	}
	if cl.rejoinChecks == 0 {
		t.Error("LocalRejoinComplete never consulted — rejoin confirmation not attempted")
	}
}
