package cluster

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestHAStateMatchesTextRender17095 pins the typed HA state to the
// operator text renders over the SAME manager fixture: every gate
// input the rolling/kernel-drain predicates consume must agree
// between cluster.HAState and FormatStatus / FormatInformation, so
// the typed channel and the text view cannot drift (#17095).
func TestHAStateMatchesTextRender17095(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ClusterID: 1,
		NodeID:    0,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, Preempt: true, NodePriorities: map[int]int{0: 200, 1: 100}},
			{ID: 1, Preempt: true, NodePriorities: map[int]int{0: 100, 1: 200}},
		},
	})
	m.SetSyncBulkPrimed(true)

	st := m.HAState()
	info := m.FormatInformation()
	stat := m.FormatStatus()

	if st.PeerAlive != strings.Contains(info, "Remote node: healthy") {
		t.Errorf("PeerAlive=%v disagrees with information render", st.PeerAlive)
	}
	if st.BulkPrimed != strings.Contains(info, "Bulk sync primed: yes") {
		t.Errorf("BulkPrimed=%v disagrees with information render", st.BulkPrimed)
	}
	if st.SyncEstablished {
		t.Error("sync unconfigured must not be sync-established in typed state")
	}
	if st.LocalHAProtocol != CurrentHAProtocolVersion {
		t.Errorf("LocalHAProtocol=%d, want %d", st.LocalHAProtocol, CurrentHAProtocolVersion)
	}
	if st.PeerHAProtocol != nil {
		t.Error("peer not alive: PeerHAProtocol must be absent (nil), not zero")
	}
	if st.PeerSessionSyncWirePresent {
		t.Error("peer not alive: peer wire field must be absent")
	}
	if len(st.Groups) != 2 {
		t.Fatalf("Groups=%d, want 2", len(st.Groups))
	}
	for _, g := range st.Groups {
		if !strings.Contains(stat, "Redundancy group: ") {
			t.Fatalf("status render lacks RG headers:\n%s", stat)
		}
		if g.PeerStateKnown {
			t.Errorf("rg %d: peer state known with no peer alive", g.ID)
		}
		if g.Weight <= 0 {
			t.Errorf("rg %d: weight=%d, want >0 on a fresh manager", g.ID, g.Weight)
		}
	}
	// Peer advertised: presence fields must flip together.
	m.mu.Lock()
	m.peerAlive = true
	m.peerNodeID = 1
	m.peerGroups = map[int]PeerGroupState{0: {GroupID: 0, State: StatePrimary, Priority: 200}}
	m.mu.Unlock()
	st = m.HAState()
	if !st.PeerAlive || st.PeerHAProtocol == nil || !st.PeerSessionSyncWirePresent {
		t.Errorf("peer alive: presence not carried: %+v", st)
	}
	if st.Groups[0].PeerState != StatePrimary || !st.Groups[0].PeerStateKnown {
		t.Errorf("rg0 peer state = %v known=%v, want primary/true", st.Groups[0].PeerState, st.Groups[0].PeerStateKnown)
	}
	if st.Groups[1].PeerStateKnown {
		t.Error("rg1: unadvertised peer group must be unknown, not fabricated")
	}
}
