package upgrade

// Fold-2 permanent pins for #12175 (ported from the confirmation probes):
// twin/forward ROLLINGBACK-refusal parity, the twin fail-open direction,
// the four failback-branch cells (M8-M12), and the STOPPED-resume boundary
// (M3). All socket-free fakeCluster cells — no :4784 fixture.

import (
	"errors"
	"strings"
	"testing"
)

type hookCluster12175 struct {
	*fakeCluster
	onDrain func()
}

func (h *hookCluster12175) DrainComplete() (bool, error) {
	if h.onDrain != nil {
		h.onDrain()
		h.onDrain = nil
	}
	return h.fakeCluster.DrainComplete()
}

func healthyFake12175() *fakeCluster {
	return &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}
}

// seedFailedStopRollback leaves a ROLLINGBACK journal from an operator
// rollback whose StopUnit FAILED (daemon still up, stop state unknown).
func seedFailedStopRollback12175(t *testing.T) *rollbackFixture {
	t.Helper()
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	stopErr := errors.New("seed: injected StopUnit failure")
	fx.r.cfg.Sys = stopFailureSystem12175{System: fx.fs, err: stopErr}
	if err := fx.r.RollbackTo("", RollbackOptions{}); !errors.Is(err, stopErr) {
		t.Fatalf("seed: want StopUnit failure, got %v", err)
	}
	fx.r.cfg.Sys = fx.fs
	j, err := fx.r.loadJournal()
	if err != nil || j.State != StateRollingBack {
		t.Fatalf("seed: want ROLLINGBACK journal, got %+v err=%v", j, err)
	}
	fx.fs.calls = nil
	return fx
}

// P2: twin re-run over a failed-STOP ROLLINGBACK journal, transient post-drain refusal.
func TestRolling_TwinRollingBackRefusalKeepsHold_12175(t *testing.T) {
	fx := seedFailedStopRollback12175(t)
	cl := &hookCluster12175{fakeCluster: healthyFake12175(), onDrain: func() {
		fx.fs.readerErr = errors.New("transient capability-check exec failure")
	}}
	err := runRollingRollbackWith(fx.r, cl, fastRC(), "")
	t.Logf("TWIN err=%v", err)
	t.Logf("TWIN forced=%v resetCalled=%v rejoinChecks=%d calls=%v", cl.forced, cl.resetCalled, cl.rejoinChecks, fx.fs.calls)
	if cl.resetCalled {
		t.Error("twin failed back a ROLLINGBACK-journal refusal (forward driver keeps the hold on the identical journal)")
	}
	if err != nil && strings.Contains(err.Error(), "refused before STOP") {
		t.Error("twin claims pre-STOP for a ROLLINGBACK-journal refusal")
	}
}

// P2b: forward driver over the SAME journal shape + the same transient refusal.
func TestRolling_ForwardRollingBackRefusalKeepsHold_12175(t *testing.T) {
	fx := seedFailedStopRollback12175(t)
	fx.fs.readerErr = errors.New("transient capability-check exec failure")
	cl := healthyFake12175()
	err := runRollingWith(fx.r, cl, fastRC())
	t.Logf("FWD err=%v", err)
	t.Logf("FWD forced=%v resetCalled=%v rejoinChecks=%d calls=%v", cl.forced, cl.resetCalled, cl.rejoinChecks, fx.fs.calls)
	if err == nil || !strings.Contains(err.Error(), "transient capability-check exec failure") {
		t.Fatalf("premise: want the transient refusal in the error, got %v", err)
	}
	if cl.resetCalled {
		t.Error("forward driver failed back a ROLLINGBACK-resume refusal (an earlier STOP may already have happened)")
	}
	if strings.Contains(err.Error(), "refused before STOP") {
		t.Error("forward driver claims pre-STOP for a ROLLINGBACK-resume refusal")
	}
}

// P2c: twin re-run over a ROLLINGBACK journal whose prior attempt STOPPED,
// flipped, STARTED the target and FAILED its health gate (target still
// unhealthy); transient post-drain refusal.
func TestRolling_TwinUnhealthyRollingBackRefusalKeepsHold_12175(t *testing.T) {
	fx := seedRollingBackJournal12175(t)
	cl := &hookCluster12175{fakeCluster: healthyFake12175(), onDrain: func() {
		fx.fs.readerErr = errors.New("transient capability-check exec failure")
	}}
	err := runRollingRollbackWith(fx.r, cl, fastRC(), "")
	t.Logf("TWIN-UNHEALTHY err=%v", err)
	t.Logf("TWIN-UNHEALTHY resetCalled=%v unitRunning=%v calls=%v", cl.resetCalled, fx.fs.unitRunning, fx.fs.calls)
	if cl.resetCalled {
		t.Error("twin failed back an unhealthy-target ROLLINGBACK refusal (forward keeps the hold)")
	}
}

// P2d: forward driver over the SAME unhealthy-target journal + same refusal.
func TestRolling_ForwardUnhealthyRollingBackRefusalKeepsHold_12175(t *testing.T) {
	fx := seedRollingBackJournal12175(t)
	fx.fs.readerErr = errors.New("transient capability-check exec failure")
	cl := healthyFake12175()
	err := runRollingWith(fx.r, cl, fastRC())
	t.Logf("FWD-UNHEALTHY err=%v", err)
	t.Logf("FWD-UNHEALTHY resetCalled=%v unitRunning=%v calls=%v", cl.resetCalled, fx.fs.unitRunning, fx.fs.calls)
	if err == nil || !strings.Contains(err.Error(), "transient capability-check exec failure") {
		t.Fatalf("premise: want the transient refusal in the error, got %v", err)
	}
	if cl.resetCalled {
		t.Error("forward driver failed back an unhealthy-target ROLLINGBACK refusal")
	}
	if strings.Contains(err.Error(), "refused before STOP") {
		t.Error("forward driver claims pre-STOP for an unhealthy-target ROLLINGBACK refusal")
	}
}

// P3: negative direction of MINOR-3 — a twin failure AFTER this run's STOP
// attempt must keep the hold.
func TestRolling_TwinPostStopFailureKeepsHold_12175(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	stopErr := errors.New("injected StopUnit failure")
	fx.r.cfg.Sys = stopFailureSystem12175{System: fx.fs, err: stopErr}
	cl := healthyFake12175()
	err := runRollingRollbackWith(fx.r, cl, fastRC(), "")
	t.Logf("err=%v", err)
	if !errors.Is(err, stopErr) {
		t.Fatalf("premise: want StopUnit failure, got %v", err)
	}
	if cl.resetCalled {
		t.Error("twin failed back after a STOP attempt")
	}
	if strings.Contains(err.Error(), "refused before STOP") {
		t.Error("twin operator text claims pre-STOP for a STOP failure")
	}
}

func verifierRejectRunner12175(t *testing.T) (*Runner, *fakeSystem) {
	t.Helper()
	fs := newFakeSystem(t, "2.0.0")
	fs.verifyPass = false
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	return r, fs
}

// P4a: failback ResetFailover error must surface, joined with the cause.
func TestRolling_FailbackResetErrorSurfaces_12175(t *testing.T) {
	r, _ := verifierRejectRunner12175(t)
	cl := healthyFake12175()
	resetErr := errors.New("injected ResetFailover failure")
	cl.resetErr = resetErr
	err := runRollingWith(r, cl, fastRC())
	t.Logf("err=%v", err)
	if !errors.Is(err, resetErr) {
		t.Error("ResetFailover failure not in chain")
	}
	if !strings.Contains(err.Error(), "failback (ResetFailover) FAILED") {
		t.Error("reset failure not reported as failed failback")
	}
	var bs *cutBeforeStopError
	if !errors.As(err, &bs) {
		t.Error("refusal cause dropped from reset-failure chain")
	}
}

// P4b: unconfirmed rejoin readback must not claim confirmation.
func TestRolling_FailbackRejoinUnconfirmedReported_12175(t *testing.T) {
	r, _ := verifierRejectRunner12175(t)
	cl := healthyFake12175()
	cl.rejoinIncomplete = true
	err := runRollingWith(r, cl, fastRC())
	t.Logf("err=%v", err)
	if strings.Contains(err.Error(), "confirmed by per-RG readback") {
		t.Error("unconfirmed rejoin reported as confirmed")
	}
	if !strings.Contains(err.Error(), "local rejoin is not confirmed") {
		t.Error("unconfirmed rejoin not reported")
	}
}

// P4c: readback error must surface, joined with the cause.
func TestRolling_FailbackRejoinReadbackErrorSurfaces_12175(t *testing.T) {
	r, _ := verifierRejectRunner12175(t)
	cl := healthyFake12175()
	rbErr := errors.New("injected readback failure")
	cl.rejoinErr = rbErr
	err := runRollingWith(r, cl, fastRC())
	t.Logf("err=%v", err)
	if !errors.Is(err, rbErr) {
		t.Error("readback error not in chain")
	}
	var bs *cutBeforeStopError
	if !errors.As(err, &bs) {
		t.Error("refusal cause dropped from readback-error chain")
	}
}

// P4d: confirmed failback reports confirmation (positive control for M9).
func TestRolling_FailbackConfirmedReported_12175(t *testing.T) {
	r, _ := verifierRejectRunner12175(t)
	cl := healthyFake12175()
	err := runRollingWith(r, cl, fastRC())
	t.Logf("err=%v", err)
	if !strings.Contains(err.Error(), "confirmed by per-RG readback") {
		t.Error("confirmed failback not reported as confirmed")
	}
}

// P5: STOPPED-journal resume (prior run stopped the unit, crashed before FLIP);
// a flip failure on resume is post-STOP and must keep the hold (M3 boundary).
func TestRolling_StoppedResumeFlipFailureKeepsHold_12175(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	fs.daemonReloadFailOnce = true
	if serr := r.Run(Options{SkipStartHealthRollback: true}); serr == nil {
		t.Fatal("seed: expected HA flip failure")
	}
	j, err := r.loadJournal()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("seed journal state=%s unitRunning=%v", j.State, fs.unitRunning)
	if j.State != StateStopped {
		t.Fatalf("seed must land at STOPPED (state=%s) — this cell is the only M3 killer", j.State)
	}
	fs.daemonReloadFailOnce = true
	cl := healthyFake12175()
	rerr := runRollingWith(r, cl, fastRC())
	t.Logf("err=%v resetCalled=%v", rerr, cl.resetCalled)
	if cl.resetCalled {
		t.Error("STOPPED-resume flip failure failed back")
	}
}
