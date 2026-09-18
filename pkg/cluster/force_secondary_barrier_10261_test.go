package cluster

import (
	"errors"
	"sort"
	"sync"
	"testing"
	"time"
)

// #10261: the ISSU drain (ForceSecondary) must run the same pre-demotion
// barrier as ManualFailover/ManualFailoverBatch before resigning any RG.
//
// The daemon wires prepareUserspaceManualFailover as the pre-manual-failover
// hook (daemon_ha_comms_wiring.go): it waits for the session-sync peer
// barrier, proving the peer processed every queued session delta before this
// node demotes. ManualFailover and ManualFailoverBatch both run that hook
// with retry; ForceSecondary demoted every RG without running it at all, so
// the peer could take ownership while in-flight deltas were still queued —
// established flows the peer never learned strand at the TCP congestion
// floor while sibling flows (whose deltas landed) keep forwarding. That is
// the Sep-13 secondary-cut shape: 3 of 4 iperf streams at 0 bps with cwnd
// pinned at 1.41 KiB and ~1 failed RTO probe/s, no reset, no death.

func forceSecondaryBarrierFixture10261(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(1, false, map[int]int{0: 150}),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 2)

	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			{GroupID: 1, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	}
	m.handlePeerHeartbeat(pkt)
	if !m.IsLocalPrimary(0) || !m.IsLocalPrimary(1) {
		t.Fatal("fixture: both RGs should be primary before ForceSecondary")
	}
	return m
}

func TestForceSecondaryRunsDemotionBarrier10261(t *testing.T) {
	m := forceSecondaryBarrierFixture10261(t)

	var mu sync.Mutex
	var calls []int
	m.SetPreManualFailoverHook(func(rgID int) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, rgID)
		return nil
	})

	if err := m.ForceSecondary(); err != nil {
		t.Fatalf("ForceSecondary: %v", err)
	}

	mu.Lock()
	got := append([]int(nil), calls...)
	mu.Unlock()
	sort.Ints(got)
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("pre-demotion hook calls = %v, want [0 1] (one barrier per demoted RG)", got)
	}

	states := m.GroupStates()
	for _, rg := range states {
		if rg.State != StateSecondary {
			t.Errorf("RG %d: state = %s, want secondary after ForceSecondary", rg.GroupID, rg.State)
		}
		if rg.Weight != 0 {
			t.Errorf("RG %d: weight = %d, want 0 after ForceSecondary", rg.GroupID, rg.Weight)
		}
		if !rg.ManualFailover {
			t.Errorf("RG %d: ManualFailover should be true after ForceSecondary", rg.GroupID)
		}
	}
	drainEvents(m, 2)
}

func TestForceSecondaryBarrierFailureBlocksDemotion10261(t *testing.T) {
	m := forceSecondaryBarrierFixture10261(t)

	barrierErr := errors.New("demotion peer barrier failed: peer has not acked queued deltas")
	m.SetPreManualFailoverHook(func(rgID int) error { return barrierErr })

	if err := m.ForceSecondary(); err == nil {
		t.Fatal("ForceSecondary with a failing demotion barrier should fail, not demote anyway (#10261)")
	}

	// Nothing demoted: the node must still be primary for both RGs so the
	// rolling driver aborts WITHOUT cutting instead of handing the peer an
	// incomplete session table.
	if !m.IsLocalPrimary(0) || !m.IsLocalPrimary(1) {
		t.Fatal("a refused ForceSecondary must leave both RGs primary")
	}
	states := m.GroupStates()
	for _, rg := range states {
		if rg.Weight == 0 {
			t.Errorf("RG %d: weight = 0 after refused ForceSecondary, want monitor-derived (>0)", rg.GroupID)
		}
		if rg.ManualFailover {
			t.Errorf("RG %d: ManualFailover set after refused ForceSecondary, want false", rg.GroupID)
		}
	}
}

func TestForceSecondarySkipsBarrierForDisabledRG10261(t *testing.T) {
	m := forceSecondaryBarrierFixture10261(t)

	m.mu.Lock()
	m.groups[1].State = StateDisabled
	m.mu.Unlock()

	var mu sync.Mutex
	var calls []int
	m.SetPreManualFailoverHook(func(rgID int) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, rgID)
		return nil
	})

	if err := m.ForceSecondary(); err != nil {
		t.Fatalf("ForceSecondary: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 || calls[0] != 0 {
		t.Fatalf("pre-demotion hook calls = %v, want [0] (disabled RG demotes nothing)", calls)
	}
}
func TestForceSecondaryAbortsWhenResetWinsDuringBarrier10261(t *testing.T) {
	m := forceSecondaryBarrierFixture10261(t)

	entered := make(chan struct{})
	release := make(chan struct{})
	m.SetPreManualFailoverHook(func(rgID int) error {
		if rgID == 0 {
			close(entered)
			<-release
		}
		return nil
	})

	done := make(chan error, 1)
	go func() { done <- m.ForceSecondary() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("ForceSecondary did not invoke the pre-failover barrier hook")
	}

	// ResetFailover is allowed to supersede an unlocked pre-hook. The trailing
	// ForceSecondary commit must observe the generation change and leave the
	// reset's primary state intact instead of reapplying weight=0.
	if err := m.ResetFailover(0); err != nil {
		t.Fatalf("ResetFailover during barrier: %v", err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("ForceSecondary should abort when ResetFailover supersedes its barrier")
	}
	if !m.IsLocalPrimary(0) || !m.IsLocalPrimary(1) {
		t.Fatal("a superseded ForceSecondary must leave both RGs primary")
	}
}
