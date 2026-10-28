package cluster

import "testing"

// #17125 (R4-Q35-04): FinalizePeerTransferOut[Batch] deleted only
// peerTransferOutOverride and left peerTransferOutPrevious behind, while
// ResetFailover's #14979 comment cited both Finalize paths as keeping the
// override pair in lockstep. Every reader of the stale snapshot was gated
// on the override, so it was inert — but a half-cleared pair is exactly
// the state the lockstep comment claimed cannot happen, and a future
// reader keyed on the snapshot alone (the #15211 restore already
// snapshotted it independently) would inherit a stale peer view.
//
// The fix collapses the pair into transferOverrides, one map of
// transferOverride{reqID, previous}, so a half-clear cannot be
// represented. These cells assert the whole entry is gone after Finalize
// (single and batch) and that a different RG's entry survives as control.
// Pre-fix both FAIL with the snapshot half left behind.
//
// FAIL-ON-REVERT: restoring a bare delete of only one half (or the old
// two-map split) makes both tests fail / not compile against this field.

func armTransferOverride17125(m *Manager, rgID int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applyPeerTransferOutOverrideLocked(rgID, 77)
}

func TestFinalizePeerTransferOutClearsTransferOverride17125(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 100}),
		makeRG(1, true, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)
	<-m.Events()
	<-m.Events()

	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover() error = %v", err)
	}
	<-m.Events()
	armTransferOverride17125(m, 0)
	armTransferOverride17125(m, 1)

	if err := m.FinalizePeerTransferOut(0); err != nil {
		t.Fatalf("FinalizePeerTransferOut() error = %v", err)
	}

	m.mu.RLock()
	_, left := m.transferOverrides[0]
	control, controlOK := m.transferOverrides[1]
	m.mu.RUnlock()
	if left {
		t.Error("FinalizePeerTransferOut left a transferOverrides entry (reqID + peer snapshot) behind")
	}
	if !controlOK || control.reqID != 77 {
		t.Errorf("control RG1 entry must survive FinalizePeerTransferOut(0): ok=%t reqID=%d, want true/77", controlOK, control.reqID)
	}
}

func TestFinalizePeerTransferOutBatchClearsTransferOverride17125(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(1, true, map[int]int{0: 100}),
		makeRG(2, true, map[int]int{0: 100}),
		makeRG(3, true, map[int]int{0: 100}),
	)
	m.UpdateConfig(cfg)
	<-m.Events()
	<-m.Events()
	<-m.Events()

	if _, err := m.ManualFailoverBatch([]int{1, 2}); err != nil {
		t.Fatalf("ManualFailoverBatch() error = %v", err)
	}
	<-m.Events()
	<-m.Events()
	armTransferOverride17125(m, 1)
	armTransferOverride17125(m, 2)
	armTransferOverride17125(m, 3)

	if err := m.FinalizePeerTransferOutBatch([]int{2, 1}); err != nil {
		t.Fatalf("FinalizePeerTransferOutBatch() error = %v", err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, rgID := range []int{1, 2} {
		if _, ok := m.transferOverrides[rgID]; ok {
			t.Errorf("rg %d: transferOverrides entry left after batch finalize", rgID)
		}
	}
	if control, ok := m.transferOverrides[3]; !ok || control.reqID != 77 {
		t.Errorf("control RG3 entry must survive batch finalize: ok=%t reqID=%d, want true/77", ok, control.reqID)
	}
}
