package upgrade

// Fold cells for #12175 (ported from the round-1 reviewer repros): a ROLLINGBACK
// resume counts as stop-attempted (MAJOR-1), the UnitAlreadyStopped seed is
// preserved (MINOR-1), and the rolling rollback twin fails post-drain refusals
// back (MINOR-3). The FLIPPED-resume guard kills mutant M2 (MINOR-2).

import (
	"errors"
	"strings"
	"testing"
)

func seedRollingBackJournal12175(t *testing.T) *rollbackFixture {
	t.Helper()
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	fx.fs.healthFailVersions["1.0.0"] = true
	if err := fx.r.RollbackTo("", RollbackOptions{}); err == nil {
		t.Fatal("seed: RollbackTo to an unhealthy target unexpectedly succeeded")
	}
	if j, err := fx.r.loadJournal(); err != nil || j.State != StateRollingBack {
		t.Fatalf("seed: want ROLLINGBACK journal, got %+v err=%v", j, err)
	}
	fx.fs.calls = nil
	return fx
}

func logRGs12175(t *testing.T, br *managerBridge12175) {
	t.Helper()
	for _, st := range br.m.GroupStates() {
		t.Logf("post: RG %d state=%v manual=%v weight=%d", st.GroupID, st.State, st.ManualFailover, st.Weight)
	}
}

// MAJOR: the PR's own STOP-attempt invariant, applied to the rollback resume
// that the forward driver's inner Run performs first (the rollback-resume branch at the top of Run).
func TestRolling_RollingBackResumeStopFailureKeepsDrain_12175(t *testing.T) {
	local, _ := twoNodeManagers12175(t)
	fx := seedRollingBackJournal12175(t)
	stopErr := errors.New("injected StopUnit failure")
	fx.r.cfg.Sys = stopFailureSystem12175{System: fx.fs, err: stopErr}
	br := &managerBridge12175{m: local, synced: true, peerReady: true, drainAfter: 1}
	rerr := runRollingWith(fx.r, br, fastRC())
	t.Logf("rolling err: %v (resetCalls=%d)", rerr, br.resetCalls)
	logRGs12175(t, br)
	if !errors.Is(rerr, stopErr) {
		t.Fatalf("premise: error does not carry the StopUnit failure: %v", rerr)
	}
	if br.resetCalls != 0 {
		t.Errorf("ResetFailover ran %d time(s) after the rollback resume ATTEMPTED STOP", br.resetCalls)
	}
	if strings.Contains(rerr.Error(), "refused before STOP") {
		t.Error("operator text claims a pre-STOP refusal for a failed STOP attempt")
	}
}

// MAJOR variant: STOP+flip+START ran, helper health failed.
func TestRolling_RollingBackResumeHealthFailureKeepsDrain_12175(t *testing.T) {
	local, _ := twoNodeManagers12175(t)
	fx := seedRollingBackJournal12175(t)
	br := &managerBridge12175{m: local, synced: true, peerReady: true, drainAfter: 1}
	rerr := runRollingWith(fx.r, br, fastRC())
	t.Logf("rolling err: %v", rerr)
	t.Logf("calls: %v resetCalls=%d", fx.fs.calls, br.resetCalls)
	logRGs12175(t, br)
	if br.resetCalls != 0 {
		t.Errorf("ResetFailover ran after the rollback resume STOPPED/started the unit and failed health")
	}
	if rerr != nil && strings.Contains(rerr.Error(), "refused before STOP") {
		t.Error("operator text claims a pre-STOP refusal")
	}
}

// MAJOR variant: legacy auto-rollback journal, StartUnit fails -> daemon DOWN.
func TestRolling_AutoRollbackResumeStartFailureKeepsDrain_12175(t *testing.T) {
	local, _ := twoNodeManagers12175(t)
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	if err := fx.r.saveJournal(&Journal{State: StateRollingBack, TargetVersion: "2.0.0", PreviousVersion: "1.0.0"}); err != nil {
		t.Fatal(err)
	}
	fx.fs.startFailOnce = true
	fx.fs.calls = nil
	br := &managerBridge12175{m: local, synced: true, peerReady: true, drainAfter: 1}
	rerr := runRollingWith(fx.r, br, fastRC())
	t.Logf("rolling err: %v", rerr)
	t.Logf("calls: %v unitRunning=%v resetCalls=%d", fx.fs.calls, fx.fs.unitRunning, br.resetCalls)
	if br.resetCalls != 0 || strings.Contains(rerr.Error(), "refused before STOP") {
		t.Errorf("post-STOP auto-rollback resume failure (daemon down) treated as pre-STOP refusal")
	}
}

// MINOR (latent): opts.UnitAlreadyStopped was overwritten by the classifier assignment.
func TestRun_UnitAlreadyStoppedPreservedAcrossClassifier_12175(t *testing.T) {
	for _, tc := range []struct {
		name string
		arm  func(fs *fakeSystem)
	}{
		{"flip-failure", func(fs *fakeSystem) { fs.daemonReloadFailOnce = true }},
		{"start-failure", func(fs *fakeSystem) { fs.startFailOnce = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeSystem(t, "2.0.0")
			r, cfg := testEnv(t, fs)
			seedInitialCurrent(t, r, cfg, "1.0.0")
			fs.unitRunning = false
			tc.arm(fs)
			err := r.Run(Options{UnitAlreadyStopped: true, SkipStartHealthRollback: true})
			var bs *cutBeforeStopError
			t.Logf("err=%v calls=%v", err, fs.calls)
			if err == nil {
				t.Fatal("expected a post-STOP failure")
			}
			if errors.As(err, &bs) {
				t.Errorf("post-STOP %s with UnitAlreadyStopped marked cutBeforeStopError", tc.name)
			}
		})
	}
}

// Sibling audit: the rolling ROLLBACK twin re-runs its refusal gate after the
// drain (RollbackTo -> rollbackInvocationPlan); a pre-STOP refusal there keeps
// the hold (#12175 defect class).
type drainHookBridge12175 struct {
	*managerBridge12175
	onDrain func()
}

func (b *drainHookBridge12175) DrainComplete() (bool, error) {
	if b.onDrain != nil {
		b.onDrain()
		b.onDrain = nil
	}
	return b.managerBridge12175.DrainComplete()
}

func TestRolling_RollbackTwinPostDrainRefusalFailsBack_12175(t *testing.T) {
	local, _ := twoNodeManagers12175(t)
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	inner := &managerBridge12175{m: local, synced: true, peerReady: true, drainAfter: 1}
	br := &drainHookBridge12175{managerBridge12175: inner, onDrain: func() {
		fx.fs.readerErr = errors.New("transient capability-check exec failure")
	}}
	err := runRollingRollbackWith(fx.r, br, fastRC(), "")
	t.Logf("rollback err: %v", err)
	t.Logf("calls: %v resetCalls=%d unitRunning=%v", fx.fs.calls, inner.resetCalls, fx.fs.unitRunning)
	logRGs12175(t, inner)
	for _, c := range fx.fs.calls {
		if c == "stop" {
			t.Fatalf("premise invalid: STOP ran (calls=%v)", fx.fs.calls)
		}
	}
	assertNoResidualHold12175(t, local)
	if err == nil || !strings.Contains(err.Error(), "single-node rollback refused before STOP") {
		t.Errorf("twin failback wording wrong, got %v", err)
	}
}

// Guard: a FLIPPED-resume START-health failure keeps the hold. Kills the
// classifier-deletion mutant (M2).
func TestRolling_FlippedResumeHealthFailureKeepsHold_12175(t *testing.T) {
	local, _ := twoNodeManagers12175(t)
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	fs.healthFailVersions["2.0.0"] = true
	if err := r.Run(Options{SkipStartHealthRollback: true}); err == nil {
		t.Fatal("seed: expected HA start-health failure")
	}
	if j, err := r.loadJournal(); err != nil || j.State != StateFlipped {
		t.Fatalf("seed: want FLIPPED journal, got %+v err=%v", j, err)
	}
	br := &managerBridge12175{m: local, synced: true, peerReady: true, drainAfter: 1}
	rerr := runRollingWith(r, br, fastRC())
	t.Logf("rolling err: %v resetCalls=%d", rerr, br.resetCalls)
	if br.resetCalls != 0 {
		t.Errorf("post-STOP FLIPPED-resume health failure failed back (resetCalls=%d)", br.resetCalls)
	}
}
