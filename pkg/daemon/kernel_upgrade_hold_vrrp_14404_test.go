package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #14404: rgStateMachine must not activate (rg_active desired) while the
// kernel-upgrade hold is armed, even if VRRP reports MASTER; after the hold
// clears the same MASTER state activates.
func TestRGStateMachine_KernelUpgradeHoldBlocksActivation14404(t *testing.T) {
	s := newRGStateMachine()
	s.SetKernelUpgradeHold(true)
	tr := s.SetVRRP("reth0", true)
	if tr.Active || s.IsActive() {
		t.Fatalf("held RG must stay inactive on VRRP MASTER: tr=%+v active=%v", tr, s.IsActive())
	}
	tr = s.SetCluster(true)
	if tr.Active || s.IsActive() {
		t.Fatalf("held RG must stay inactive on cluster primary: tr=%+v", tr)
	}
	s.SetKernelUpgradeHold(false)
	tr = s.SetVRRP("reth0", true)
	if !tr.Active || !s.IsActive() {
		t.Fatalf("cleared RG must activate on VRRP MASTER: tr=%+v active=%v", tr, s.IsActive())
	}
	_ = cluster.KernelUpgradeHoldCandidate
}

// Posture: while held, a secondary+MASTER mismatch must not be reported as
// NeedsResign (the hold, not posture, is authority; resign+reconcile flap
// would re-promote).
func TestRGStateMachine_KernelUpgradeHoldPosture14404(t *testing.T) {
	s := newRGStateMachine()
	s.startedAt = time.Now().Add(-time.Minute)
	s.SetKernelUpgradeHold(true)
	s.SetCluster(false)
	s.SetVRRP("reth0", true)
	if s.IsActive() {
		t.Fatal("setup: held RG must be inactive")
	}
	now := time.Now()
	if got := s.CheckVRRPPosture(now, 1); got != vrrpPostureOK {
		t.Fatalf("held posture first check = %v, want OK", got)
	}
	if got := s.CheckVRRPPosture(now.Add(10*time.Second), 1); got != vrrpPostureOK {
		t.Fatalf("held posture sustained = %v, want OK (no resign flap while held)", got)
	}
	c := newRGStateMachine()
	c.startedAt = time.Now().Add(-time.Minute)
	c.SetCluster(false)
	c.SetVRRP("reth0", true)
	c.CheckVRRPPosture(now, 1)
	if got := c.CheckVRRPPosture(now.Add(10*time.Second), 1); got != vrrpPostureNeedsResign {
		t.Fatalf("control posture = %v, want NeedsResign", got)
	}
}
