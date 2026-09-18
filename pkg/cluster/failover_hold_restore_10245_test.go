package cluster

import (
	"fmt"
	"testing"
)

// #10245: ForceSecondary pins Weight=0 while setting ManualFailover, then a
// later ManualFailover changes the state to SecondaryHold without changing the
// pin. A failed peer transfer clears the hold and recalcWeight installs the
// monitor-derived weight; the abort must restore the ForceSecondary-origin
// pin as well as the hold flag, timestamp, and state.
//
// FAIL-ON-REVERT: changing restoreWeight back to the old state-shape predicate
// (`StateSecondary && Weight == 0`) makes this exact stacked shape skip weight
// restoration because the captured state is SecondaryHold. The failed request
// then leaves the debt-derived weight instead of the pinned zero.
func TestRequestPeerFailoverStackedForceSecondaryManualFailoverRestoresWeight10245(t *testing.T) {
	m := holdFixture10004(t, 0)
	if err := m.ForceSecondary(); err != nil {
		t.Fatalf("fixture: ForceSecondary(): %v", err)
	}
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("fixture: ManualFailover() after ForceSecondary: %v", err)
	}
	m.mu.RLock()
	wantAt := m.groups[0].ManualFailoverAt
	stacked := m.groups[0].ManualFailover && m.groups[0].State == StateSecondaryHold && m.groups[0].Weight == 0
	m.mu.RUnlock()
	if !stacked {
		t.Fatal("fixture: ForceSecondary -> ManualFailover must produce flagged SecondaryHold with pinned weight 0")
	}

	m.SetTransferReadinessFunc(func(int) (bool, []string) { return true, nil })
	m.SetPeerFailoverFunc(func(int) (uint64, error) { return 3201, nil })
	m.SetLocalTransferCommitReadyHook(func([]int) error {
		return fmt.Errorf("dataplane not settled")
	})
	m.SetPeerFailoverCommitFunc(func(int, uint64) error {
		t.Error("peer transfer-commit must not run after local-commit-ready failed")
		return nil
	})

	if err := m.RequestPeerFailover(0); err == nil {
		t.Fatal("expected local-commit-ready failure")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rg := m.groups[0]
	if !rg.ManualFailover {
		t.Error("stacked hold flag was not restored after failed transfer")
	}
	if !rg.ManualFailoverAt.Equal(wantAt) {
		t.Errorf("stacked hold timestamp = %v, want original %v", rg.ManualFailoverAt, wantAt)
	}
	if rg.State != StateSecondaryHold {
		t.Errorf("stacked hold state = %s, want secondary-hold", rg.State)
	}
	if rg.Weight != 0 {
		t.Errorf("stacked ForceSecondary weight = %d after failed transfer, want pinned 0", rg.Weight)
	}
}
