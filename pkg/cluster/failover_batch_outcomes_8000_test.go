// #8000: a manual failover must report what it actually DID, not merely that it
// did not error.
//
// A `ResetFailover` landing in the unlocked pre-hook window bumps the RG's
// failover generation and the reset WINS — the SecondaryHold write is abandoned
// and nil is returned (#5246, pinned by failover_races_5245_5246_test.go). That
// is correct and these cells do not touch it. What was missing is that the
// caller could not tell the two apart, so a partially-applied batch reported a
// full handoff.
//
// The cells assert the OUTCOME, not the error, because the error is nil in both
// the applied and the superseded case — asserting on it is exactly the blind
// spot being fixed.
package cluster

import (
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// supersededDuringPreHook runs fn (a failover call) with a ResetFailover landing
// inside its unlocked pre-hook window, reproducing the #5246 race deterministically
// rather than by timing.
func supersededDuringPreHook(t *testing.T, m *Manager, rgID int, fn func()) {
	t.Helper()
	// The BATCH calls the pre-hook once per member, so the signal must fire
	// exactly once — closing per call panics with "close of closed channel".
	// The reset therefore lands during the FIRST member's hook, which is what
	// makes that member superseded while the rest commit normally.
	hookStarted := make(chan struct{})
	hookRelease := make(chan struct{})
	var once sync.Once
	m.SetPreManualFailoverHook(func(int) error {
		once.Do(func() { close(hookStarted) })
		<-hookRelease
		return nil
	})
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	<-hookStarted
	if err := m.ResetFailover(rgID); err != nil {
		t.Fatalf("ResetFailover: %v", err)
	}
	close(hookRelease)
	<-done
}

func newPrimaryManager8000(t *testing.T, rgIDs ...int) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	rgs := make([]*config.RedundancyGroup, 0, len(rgIDs))
	for _, id := range rgIDs {
		rgs = append(rgs, makeRG(id, false, map[int]int{0: 200}))
	}
	m.UpdateConfig(makeConfig(rgs...))
	for range rgIDs {
		recvEvent19161(t, m.Events(), "drain each initial secondary→primary election")
	}
	for _, id := range rgIDs {
		if !m.IsLocalPrimary(id) {
			t.Fatalf("precondition: node should be primary for RG%d", id)
		}
	}
	return m
}

// The singular path must report the supersede. The batch delegates to it for a
// one-member request, so the batch's own contract depends on this.
//
// FAIL-ON-REVERT: return a bare `nil` from ManualFailover's supersede arm and
// the outcome reads FailoverApplied — indistinguishable from a real failover.
func TestManualFailoverReportsSupersede8000(t *testing.T) {
	m := newPrimaryManager8000(t, 0)

	var outcome FailoverOutcome
	var err error
	supersededDuringPreHook(t, m, 0, func() { outcome, err = m.ManualFailover(0) })

	if err != nil {
		t.Fatalf("ManualFailover returned an error for a supersede: %v — the #5246 "+
			"contract is that a reset winning is NOT an error, and this cell must "+
			"not be the thing that changes it", err)
	}
	if outcome != FailoverSuperseded {
		t.Errorf("ManualFailover outcome = %v, want FailoverSuperseded. The reset won, "+
			"so no failover happened — reporting this as applied is what left an "+
			"operator unable to tell a real transfer from one a concurrent reset "+
			"claimed (#8000)", outcome)
	}

	// Control: an UNCONTESTED failover must report applied, or the cell above
	// passes on an implementation that reports everything as superseded.
	m2 := newPrimaryManager8000(t, 0)
	got, err := m2.ManualFailover(0)
	if err != nil {
		t.Fatalf("uncontested ManualFailover: %v", err)
	}
	if got != FailoverApplied {
		t.Errorf("uncontested ManualFailover outcome = %v, want FailoverApplied — the "+
			"outcome must distinguish the two cases, not report one of them always", got)
	}
}

// The batch must name which members moved and which a reset claimed.
//
// FAIL-ON-REVERT: drop the `res.Superseded = append(...)` in the commit loop and
// the batch reports a full handoff for a partially-applied request — the exact
// defect #8000 names.
func TestManualFailoverBatchReportsPartialApplication8000(t *testing.T) {
	m := newPrimaryManager8000(t, 0, 1)

	var res BatchFailoverResult
	var err error
	// The pre-hook fires once per batch, so resetting RG0 inside it supersedes
	// RG0 while RG1 commits normally — a genuinely PARTIAL batch.
	supersededDuringPreHook(t, m, 0, func() { res, err = m.ManualFailoverBatch([]int{0, 1}) })

	if err != nil {
		t.Fatalf("ManualFailoverBatch returned an error for a partial batch: %v — a "+
			"supersede is a correct outcome, not a failure, and turning it into an "+
			"error would reverse the #5246 contract", err)
	}
	if !res.Partial() {
		t.Fatalf("BatchFailoverResult.Partial() = false for a batch whose member was "+
			"superseded; applied=%v superseded=%v. The caller cannot tell a full "+
			"handoff from a partial one, which is #8000", res.Applied, res.Superseded)
	}
	if len(res.Superseded) != 1 || res.Superseded[0] != 0 {
		t.Errorf("Superseded = %v, want [0] — the RG the reset actually claimed", res.Superseded)
	}
	if len(res.Applied) != 1 || res.Applied[0] != 1 {
		t.Errorf("Applied = %v, want [1] — the member that did move must still be "+
			"reported as applied, or a partial batch is indistinguishable from a "+
			"total failure", res.Applied)
	}

	// Control: an uncontested batch reports every member applied and Partial()
	// false. Without it the cell passes on an implementation that marks
	// everything superseded.
	m2 := newPrimaryManager8000(t, 0, 1)
	full, err := m2.ManualFailoverBatch([]int{0, 1})
	if err != nil {
		t.Fatalf("uncontested ManualFailoverBatch: %v", err)
	}
	if full.Partial() || len(full.Applied) != 2 {
		t.Errorf("uncontested batch: Partial()=%v applied=%v superseded=%v; want a full "+
			"handoff — the result must distinguish partial from complete, not report "+
			"one of them always", full.Partial(), full.Applied, full.Superseded)
	}
}

// A ONE-member batch does not run the commit loop at all — it delegates to
// ManualFailover and maps that outcome. The two-member cell above never reaches
// this mapping, so a mutation here (append to Applied unconditionally) escapes
// it. Both production shapes have to be pinned.
//
// FAIL-ON-REVERT: in ManualFailoverBatch's `len(ids) == 1` arm, append to
// res.Applied regardless of outcome and this cell reds while the two-member cell
// stays green.
func TestManualFailoverBatchSingleMemberReportsSupersede8000(t *testing.T) {
	m := newPrimaryManager8000(t, 0)

	var res BatchFailoverResult
	var err error
	supersededDuringPreHook(t, m, 0, func() { res, err = m.ManualFailoverBatch([]int{0}) })

	if err != nil {
		t.Fatalf("single-member ManualFailoverBatch: %v", err)
	}
	if len(res.Superseded) != 1 || res.Superseded[0] != 0 {
		t.Errorf("Superseded = %v, want [0]: the one-member batch delegates to "+
			"ManualFailover, and dropping its outcome makes the delegation report a "+
			"handoff that did not happen (#8000)", res.Superseded)
	}
	if len(res.Applied) != 0 {
		t.Errorf("Applied = %v, want empty — the reset claimed the only member", res.Applied)
	}
	if !res.Partial() {
		t.Error("Partial() = false for a one-member batch whose only member was superseded")
	}

	// Control: an uncontested one-member batch must report it applied.
	m2 := newPrimaryManager8000(t, 0)
	full, err := m2.ManualFailoverBatch([]int{0})
	if err != nil {
		t.Fatalf("uncontested single-member batch: %v", err)
	}
	if full.Partial() || len(full.Applied) != 1 || full.Applied[0] != 0 {
		t.Errorf("uncontested single-member batch: applied=%v superseded=%v; want applied=[0]",
			full.Applied, full.Superseded)
	}
}
