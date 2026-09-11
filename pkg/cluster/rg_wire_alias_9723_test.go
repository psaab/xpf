package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9723: `localRGIDForWireByte` resolved a received wire byte by ranging over a
// Go map, so with RG0 and RG -1 both configured the peer's RG0 entry went to
// either group. The reviewer measured 46 of 400 lookups resolving to -1.

// rawClusterConfig9723 builds a ClusterConfig directly, bypassing the config
// compiler (which now drops negative ids), so the manager itself is exercised
// with aliasing ids.
func rawClusterConfig9723(ids ...int) *config.ClusterConfig {
	cc := &config.ClusterConfig{}
	for _, id := range ids {
		cc.RedundancyGroups = append(cc.RedundancyGroups, &config.RedundancyGroup{
			ID:             id,
			NodePriorities: map[int]int{0: 200, 1: 100},
		})
	}
	return cc
}

func TestLocalRGIDForWireByteIsDeterministic_9723(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []int
		b    uint8
		want int
	}{
		{"RG0 beside a negative id", []int{0, -1}, 0, 0},
		{"a negative id alone still resolves", []int{-1}, 0, -1},
		{"exact 255 beside saturating ids", []int{300, 255, 256}, 255, 255},
		{"smallest of two saturating ids", []int{300, 256}, 255, 256},
		{"in-range control", []int{1, 2}, 2, 2},
	} {
		m := NewManager(0, 1)
		m.UpdateConfig(rawClusterConfig9723(tc.ids...))
		drainEvents(m, 16)
		for trial := 0; trial < 400; trial++ {
			if got := m.localRGIDForWireByte(tc.b); got != tc.want {
				t.Fatalf("%s: trial %d resolved byte %d to %d, want %d", tc.name, trial, tc.b, got, tc.want)
			}
		}
	}
}

// TestPeerRG0EntryIsAlwaysPresentBesideANegativeGroup_9723 is the issue's
// consequence, driven through real heartbeats built by the peer: over many
// rounds the local node must always hold the peer's RG0 entry under id 0.
func TestPeerRG0EntryIsAlwaysPresentBesideANegativeGroup_9723(t *testing.T) {
	cc := rawClusterConfig9723(0, -1)
	peer := NewManager(1, 1)
	peer.UpdateConfig(cc)
	drainEvents(peer, 16)
	local := NewManager(0, 1)
	local.UpdateConfig(cc)
	drainEvents(local, 16)
	for round := 0; round < 200; round++ {
		local.handlePeerHeartbeat(peer.buildHeartbeat())
		states := local.PeerGroupStates()
		st, ok := states[0]
		if !ok {
			t.Fatalf("round %d: the peer's RG0 entry is missing (keys %v); election.go turns that into "+
				"`Peer has no RG info` and elects locally", round, keysOf8337(states))
		}
		if st.GroupID != 0 {
			t.Fatalf("round %d: peerGroups[0].GroupID = %d, want 0", round, st.GroupID)
		}
	}
}
