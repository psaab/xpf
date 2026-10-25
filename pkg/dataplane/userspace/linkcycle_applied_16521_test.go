package userspace

import (
	"os"
	"os/exec"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16521: notifyLinkCycle must only mark m.lastSnapshot applied when the
// helper already holds it. A same-plan commit retained by Compile's
// pendingXSKStartup deferral reaches the RETH rebind with the helper still
// on the published generation; marking it applied advanced
// PolicyReadConfig/capture authority and fired the policy-invalidation
// discharge early, skipping the deferred-publish re-capture.
//
// These cells drive the real notifyLinkCycle through the control-request
// hook seam (fakeCtrlMap/fakeBindingsMap cover applyHelperStatusLocked, as
// in the #9337 deferred-publish fixture). RED on revert: dropping the
// helperHoldsLastSnapshotLocked gate in notifyLinkCycle makes the defect
// arm record gen 6 and fire both committers.

func linkCycleAppliedManager16521(t *testing.T, helperEcho uint64) (*Manager, *[]uint64, *[]uint64) {
	t.Helper()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.failClosedCtrlMapHook = &fakeCtrlMap{stored: userspaceCtrlValue{Enabled: 1}, haveStored: true}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "rebind" && status != nil {
			*status = ProcessStatus{
				PID:                    4242,
				Workers:                1,
				LastSnapshotGeneration: helperEcho,
				Capabilities:           UserspaceCapabilities{ForwardingSupported: true},
			}
		}
		return nil
	}
	var policyCommitted, captureCommitted []uint64
	m.SetPolicySnapshotCommitter(func(generation uint64) {
		policyCommitted = append(policyCommitted, generation)
	})
	m.SetCaptureAuthorityCommitter(func(generation uint64, _ *ConfigSnapshot) {
		captureCommitted = append(captureCommitted, generation)
	})
	skipLinkCycleRebindSleep(t)
	return m, &policyCommitted, &captureCommitted
}

// seedApplied16521 leaves the manager as a reconciled gen-5 apply left it,
// then installs retained gen 6 as m.lastSnapshot. The gen-5 seed mark fires
// the committers, so callers reset their records after seeding.
func seedApplied16521(m *Manager, cfgOld, cfgNew *config.Config) {
	m.lastSnapshot = &ConfigSnapshot{Config: cfgOld, Generation: 5}
	m.markAppliedSnapshotLocked() // applied gen = 5
	m.lastSnapshot = &ConfigSnapshot{Config: cfgNew, Generation: 6}
}

func TestNotifyLinkCycleDoesNotMarkUnpublishedSnapshotApplied16521(t *testing.T) {
	cfgOld, cfgNew := &config.Config{}, &config.Config{}
	m, policyCommitted, captureCommitted := linkCycleAppliedManager16521(t, 5)
	seedApplied16521(m, cfgOld, cfgNew)
	*policyCommitted, *captureCommitted = nil, nil
	// Compile's pendingXSKStartup deferral: gen 6 retained, helper on 5.
	m.publishedSnapshot = 5
	m.pendingFullSnapshotMetadata = true
	m.lastStatus = ProcessStatus{LastSnapshotGeneration: 5}
	m.deferWorkers = false // daemon clears it before NotifyLinkCycle

	if err := m.NotifyLinkCycle(); err != nil {
		t.Fatalf("NotifyLinkCycle: %v", err)
	}
	if got := m.appliedSnapshot.Generation; got != 5 {
		t.Fatalf("appliedSnapshot = %d, want 5: the link cycle marked an unpublished snapshot applied", got)
	}
	if m.appliedSnapshot.Config != cfgOld {
		t.Fatal("appliedSnapshot.Config advanced to the deferred config before publish")
	}
	if len(*policyCommitted) != 0 || len(*captureCommitted) != 0 {
		t.Fatalf("committers fired for unpublished gen: policy=%v capture=%v, want none",
			*policyCommitted, *captureCommitted)
	}
	if !m.pendingFullSnapshotMetadata || m.publishedSnapshot != 5 {
		t.Fatalf("deferred publish state disturbed: pending=%v published=%d, want true/5",
			m.pendingFullSnapshotMetadata, m.publishedSnapshot)
	}
}

// TestNotifyLinkCycleMarksPublishedSnapshotApplied16521 is the #2079 r11
// DeferWorkers twin: gen 6 was published and the helper echoes it, so the
// post-rebind capture must still record it.
func TestNotifyLinkCycleMarksPublishedSnapshotApplied16521(t *testing.T) {
	cfgOld, cfgNew := &config.Config{}, &config.Config{}
	m, policyCommitted, captureCommitted := linkCycleAppliedManager16521(t, 6)
	seedApplied16521(m, cfgOld, cfgNew)
	*policyCommitted, *captureCommitted = nil, nil
	m.publishedSnapshot = 6
	m.pendingFullSnapshotMetadata = false
	m.lastStatus = ProcessStatus{LastSnapshotGeneration: 6}

	if err := m.NotifyLinkCycle(); err != nil {
		t.Fatalf("NotifyLinkCycle: %v", err)
	}
	if got := m.appliedSnapshot.Generation; got != 6 {
		t.Fatalf("appliedSnapshot = %d, want 6: the #2079 r11 post-rebind capture regressed", got)
	}
	if m.appliedSnapshot.Config != cfgNew {
		t.Fatal("appliedSnapshot.Config is not the published gen-6 config")
	}
	if len(*policyCommitted) != 1 || (*policyCommitted)[0] != 6 {
		t.Fatalf("policy committer = %v, want [6]", *policyCommitted)
	}
	if len(*captureCommitted) != 1 || (*captureCommitted)[0] != 6 {
		t.Fatalf("capture committer = %v, want [6]", *captureCommitted)
	}
}

// TestNotifyLinkCycleSkipsMarkWhenOutcomeUnknown16521: even with matching
// generations, an unknown-outcome apply means the helper's holdings are
// unproven, so the rebind must not mark.
func TestNotifyLinkCycleSkipsMarkWhenOutcomeUnknown16521(t *testing.T) {
	cfgOld, cfgNew := &config.Config{}, &config.Config{}
	m, policyCommitted, captureCommitted := linkCycleAppliedManager16521(t, 6)
	seedApplied16521(m, cfgOld, cfgNew)
	*policyCommitted, *captureCommitted = nil, nil
	m.publishedSnapshot = 6
	m.lastStatus = ProcessStatus{LastSnapshotGeneration: 6}
	m.applySnapshotOutcomeUnknown = true

	if err := m.NotifyLinkCycle(); err != nil {
		t.Fatalf("NotifyLinkCycle: %v", err)
	}
	if got := m.appliedSnapshot.Generation; got != 5 {
		t.Fatalf("appliedSnapshot = %d, want 5 with an unknown apply outcome", got)
	}
	if len(*policyCommitted) != 0 || len(*captureCommitted) != 0 {
		t.Fatalf("committers fired with unknown outcome: policy=%v capture=%v",
			*policyCommitted, *captureCommitted)
	}
}

// TestLinkCycleDeferredCommitDischargesOnlyAfterTickPublish16521 chains the
// manager defect arm into the deferred publish: after the guarded link
// cycle the snapshot is still pending, so the status tick runs the
// pre-publisher (the daemon's deferred-window re-capture) BEFORE the
// publish lands and only then fires the committer (the discharge trigger).
func TestLinkCycleDeferredCommitDischargesOnlyAfterTickPublish16521(t *testing.T) {
	cfgOld, cfgNew := &config.Config{}, &config.Config{}
	m, policyCommitted, _ := linkCycleAppliedManager16521(t, 5)
	seedApplied16521(m, cfgOld, cfgNew)
	*policyCommitted = nil
	m.publishedSnapshot = 5
	m.pendingFullSnapshotMetadata = true
	m.publishedPlanKey = snapshotBindingPlanKey(m.lastSnapshot)
	m.lastStatus = ProcessStatus{LastSnapshotGeneration: 5}

	var order []string
	m.SetPolicySnapshotPrePublisher(func(generation uint64) error {
		if generation != 6 {
			t.Errorf("pre-publisher generation = %d, want 6", generation)
		}
		order = append(order, "recapture")
		return nil
	})
	// Extend the hook installed by the fixture: the tick publish lands.
	prevHook := m.controlRequestHook
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			order = append(order, "publish")
			if status != nil {
				*status = ProcessStatus{LastSnapshotGeneration: 6}
			}
			return nil
		}
		return prevHook(req, status)
	}

	if err := m.NotifyLinkCycle(); err != nil {
		t.Fatalf("NotifyLinkCycle: %v", err)
	}
	if len(*policyCommitted) != 0 {
		t.Fatalf("discharge committer fired at link cycle, before publish: %v", *policyCommitted)
	}

	m.mu.Lock()
	if !m.prepareDeferredPolicySnapshotLocked() {
		m.mu.Unlock()
		t.Fatal("deferred tick pre-publisher refused the pending snapshot")
	}
	err := m.syncSnapshotLocked()
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("syncSnapshotLocked (deferred tick publish): %v", err)
	}
	if len(order) != 2 || order[0] != "recapture" || order[1] != "publish" {
		t.Fatalf("deferred tick order = %v, want [recapture publish]: the re-capture must precede the publish", order)
	}
	if got := m.appliedSnapshot.Generation; got != 6 {
		t.Fatalf("appliedSnapshot = %d after tick publish, want 6", got)
	}
	if len(*policyCommitted) != 1 || (*policyCommitted)[0] != 6 {
		t.Fatalf("policy committer after tick publish = %v, want [6] (discharge only now)", *policyCommitted)
	}
}
