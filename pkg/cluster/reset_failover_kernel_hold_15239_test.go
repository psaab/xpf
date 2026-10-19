package cluster

import "testing"

// #15239 (A56-01): a failover reset of ANY ONE redundancy group cleared the
// node-global kernel-upgrade election hold. The hold is node-scoped — an
// unverified candidate kernel must stay SECONDARY on every RG until the
// promotion marker confirms it — but ResetFailover(rgID) dropped it inline,
// so `request chassis cluster failover reset redundancy-group 1` (or the
// equivalent gRPC cluster-failover-reset:1) on a candidate-trialling node
// made the whole node election-eligible and let it claim primary before
// xpf-kernel-promote verified the dataplane.
//
// The only legitimate synchronous release producers are the orchestrator
// rejoin (ResetAllFailover — every configured RG, reached via
// `xpfd upgrade kernel rejoin` / RejoinAndConfirm and via kernel
// self-recovery) and the promotion-marker reconcile
// (ClearKernelUpgradeHold). A single-RG operator reset is neither.
//
// Revert the guard in ResetFailover (restore the unconditional inline
// clear) and these tests go RED: the hold is gone after ResetFailover(1)
// and the held node reclaims primary.
// TestResetFailoverSingleRGPreservesKernelUpgradeHold15239 is the exact
// A56-01 mechanism: candidate armed (hold set, marker != running — the
// promotion gate has not verified), then a single-RG reset. The hold must
// survive and no RG may become primary; the reset's own per-RG work
// (ManualFailover clear, weight restore) must still happen.
func TestResetFailoverSingleRGPreservesKernelUpgradeHold15239(t *testing.T) {
	m := NewManager(0, 1)
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)
	if m.IsLocalPrimary(0) || m.IsLocalPrimary(1) {
		t.Fatal("precondition: held candidate must be secondary on every RG")
	}
	drainEvents(m, 8)

	if err := m.ResetFailover(1); err != nil {
		t.Fatalf("ResetFailover(1): %v", err)
	}
	if !m.KernelUpgradeHeld() {
		t.Fatal("single-RG ResetFailover(1) cleared the node-global kernel-upgrade hold; " +
			"an unverified candidate is now election-eligible (A56-01)")
	}
	if m.IsLocalPrimary(0) || m.IsLocalPrimary(1) {
		t.Fatalf("held candidate claimed primary after ResetFailover(1): RG0=%v RG1=%v",
			m.IsLocalPrimary(0), m.IsLocalPrimary(1))
	}
	// The reset's per-RG work still happened: RG1 is no longer manually
	// failed over and its weight is restored — only the hold release is
	// withheld.
	states := m.GroupStates()
	if states[1].ManualFailover {
		t.Error("ResetFailover(1) must still clear RG1 ManualFailover")
	}
	if states[1].Weight == 0 {
		t.Error("ResetFailover(1) must still restore RG1 weight")
	}
	// Reason must still render (hold genuinely still set).
	if got := m.KernelUpgradeHoldReason(); got != KernelUpgradeHoldCandidate {
		t.Errorf("KernelUpgradeHoldReason = %q, want candidate reason while held", got)
	}
}

// TestResetAllFailoverStillClearsKernelUpgradeHold15239 is the surviving
// legitimate producer: the orchestrator rejoin (ResetAllFailover) clears
// the hold synchronously and the node reclaims primary — the
// never-both-down property the inline clear was originally added for,
// preserved at the all-RG scope where it belongs.
func TestResetAllFailoverStillClearsKernelUpgradeHold15239(t *testing.T) {
	m := NewManager(0, 1)
	m.SetKernelUpgradeHold(KernelUpgradeHoldCandidate)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 200}),
	)
	m.UpdateConfig(cfg)
	if m.IsLocalPrimary(0) || m.IsLocalPrimary(1) {
		t.Fatal("precondition: held candidate must be secondary")
	}
	drainEvents(m, 8)

	if err := m.ResetAllFailover(); err != nil {
		t.Fatalf("ResetAllFailover: %v", err)
	}
	if m.KernelUpgradeHeld() {
		t.Fatal("ResetAllFailover (orchestrator rejoin) must clear the kernel-upgrade hold synchronously")
	}
	if !m.IsLocalPrimary(0) || !m.IsLocalPrimary(1) {
		t.Fatal("after rejoin the isolated node must reclaim primary on every RG (hold cleared)")
	}
}

// TestResetFailoverNoHoldUnchanged15239 is the control: with no hold set,
// a single-RG reset behaves exactly as before (clears the manual failover
// and re-elects primary).
func TestResetFailoverNoHoldUnchanged15239(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	<-m.Events()
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("ManualFailover: %v", err)
	}
	<-m.Events()
	if err := m.ResetFailover(0); err != nil {
		t.Fatalf("ResetFailover: %v", err)
	}
	if m.GroupStates()[0].ManualFailover {
		t.Error("ManualFailover should be cleared")
	}
	if !m.IsLocalPrimary(0) {
		t.Error("state should be primary after reset with no hold")
	}
}
