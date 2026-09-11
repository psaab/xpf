package cluster

import (
	"fmt"
	"testing"
	"time"
)

// #9640: under `disable-rg-confirmed` (#7147) the fence must be issued while this node
// still does not own the redundancy groups. A manual failover in effect when the peer
// times out broke that. handlePeerTimeout cleared the manual failover through
// recalcWeight, which ends in electSingleNode because peerAlive is already false, so the
// node promoted itself BEFORE awaitPeerFenceLocked asked the peer to relinquish.
// TestConfirmedFenceRunsBeforeElection7147 never sets a manual failover, so no cell
// covered that path. These cells drive the real ManualFailover API.

// fenceManager9640 is confirmFenceManager with a chosen fencing policy and rgs
// redundancy groups: peer seen and alive, every group forced SECONDARY, so a
// promotion is observable.
func fenceManager9640(t *testing.T, policy string, rgs int) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig()
	for i := 0; i < rgs; i++ {
		cfg.RedundancyGroups = append(cfg.RedundancyGroups, makeRG(i, false, map[int]int{0: 200, 1: 100}))
	}
	cfg.RethCount = rgs
	cfg.PeerFencing = policy
	m.UpdateConfig(cfg)
	m.mu.Lock()
	m.peerAlive = true
	m.peerEverSeen = true
	for _, rg := range m.groups {
		rg.State = StateSecondary
	}
	m.mu.Unlock()
	return m
}

func drainEvents9640(m *Manager) string {
	var out []string
	for {
		select {
		case ev := <-m.Events():
			out = append(out, fmt.Sprintf("rg%d:%v->%v", ev.GroupID, ev.OldState, ev.NewState))
		default:
			return fmt.Sprint(out)
		}
	}
}

func TestManualFailoverAtPeerTimeoutElectsOnlyAfterTheConfirmedFence9640(t *testing.T) {
	m := confirmFenceManager(t)
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("FIXTURE: manual failover: %v", err)
	}
	m.mu.RLock()
	manual := m.groups[0].ManualFailover
	m.mu.RUnlock()
	if state := rgState(t, m, 0); !manual || state == StatePrimary {
		t.Fatalf("FIXTURE: RG0 must be in a manual failover and not primary when the peer "+
			"times out (manual=%v, state=%v), or the ordering cannot be observed", manual, state)
	}

	var stateAtFence NodeState
	var called bool
	m.SetPeerFenceConfirmFunc(func(timeout time.Duration) (FenceAck, error) {
		called = true
		stateAtFence = rgState(t, m, 0)
		return FenceAck{Status: FenceAckOK, RGsFenced: 1, RGsTotal: 1}, nil
	})

	m.handlePeerTimeout()

	if !called {
		t.Fatal("the confirm function was never called under disable-rg-confirmed, so " +
			"nothing gated the takeover")
	}
	if stateAtFence == StatePrimary {
		t.Error("clearing the manual failover on peer loss elected this node primary " +
			"BEFORE the fence was issued; under disable-rg-confirmed the first election " +
			"must be the one after the peer confirms")
	}
	if got := rgState(t, m, 0); got != StatePrimary {
		t.Errorf("after a CONFIRMED fence the node is %v, want primary: the takeover must "+
			"still happen", got)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.groups[0].ManualFailover {
		t.Error("peer loss must still clear the manual failover, or the survivor stays parked")
	}
}

// The early election was not confined to the group in the manual failover: electSingleNode
// elects EVERY group, so a manual failover on RG0 promoted RG1 before the fence too.
func TestManualFailoverOnOneGroupElectsNoGroupBeforeTheConfirmedFence9640(t *testing.T) {
	m := fenceManager9640(t, PeerFencingDisableRGConfirmed, 2)
	if _, err := m.ManualFailover(0); err != nil {
		t.Fatalf("FIXTURE: manual failover: %v", err)
	}
	if rgState(t, m, 1) == StatePrimary {
		t.Fatal("FIXTURE: RG1 must start secondary, or its promotion cannot be observed")
	}
	var atFence [2]NodeState
	m.SetPeerFenceConfirmFunc(func(timeout time.Duration) (FenceAck, error) {
		atFence[0], atFence[1] = rgState(t, m, 0), rgState(t, m, 1)
		return FenceAck{Status: FenceAckOK, RGsFenced: 2, RGsTotal: 2}, nil
	})

	m.handlePeerTimeout()

	for rg, state := range atFence {
		if state == StatePrimary {
			t.Errorf("RG%d was already primary when the fence was issued; a manual failover on "+
				"RG0 must not elect any group before the peer confirms", rg)
		}
	}
	for rg := 0; rg < 2; rg++ {
		if got := rgState(t, m, rg); got != StatePrimary {
			t.Errorf("after a CONFIRMED fence RG%d is %v, want primary", rg, got)
		}
	}
}

// The other policies keep TODAY's outcome. The expected strings are the MEASURED
// behaviour of master a21c23ac7 (docs/log/9640.md): for every policy a manual failover
// emits secondary->secondary-hold, and peer loss then emits exactly one
// secondary-hold->primary, ending primary with the manual failover cleared.
func TestPeerLossWithManualFailoverKeepsTodaysOutcome9640(t *testing.T) {
	for _, policy := range []string{"", PeerFencingDisableRG, PeerFencingDisableRGConfirmed} {
		m := fenceManager9640(t, policy, 1)
		_ = drainEvents9640(m)
		if _, err := m.ManualFailover(0); err != nil {
			t.Fatalf("policy %q: FIXTURE: manual failover: %v", policy, err)
		}
		if got := drainEvents9640(m); got != "[rg0:secondary->secondary-hold]" {
			t.Fatalf("policy %q: FIXTURE: manual failover emitted %s", policy, got)
		}

		m.handlePeerTimeout()

		if got := drainEvents9640(m); got != "[rg0:secondary-hold->primary]" {
			t.Errorf("policy %q: peer loss emitted %s, want master's [rg0:secondary-hold->primary]", policy, got)
		}
		if got := rgState(t, m, 0); got != StatePrimary {
			t.Errorf("policy %q: end state %v, want primary", policy, got)
		}
		m.mu.RLock()
		manual := m.groups[0].ManualFailover
		m.mu.RUnlock()
		if manual {
			t.Errorf("policy %q: peer loss left the manual failover set", policy)
		}
	}
}
