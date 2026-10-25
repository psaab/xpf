package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16749 render belt: a hold-time FRR refuses (1, 2, >65535) must not
// render a `timers` line — one refused line fails the whole frr-reload
// and poisons every later reload (#14585). Valid values render as before.
func TestBGPNeighborHoldTimeRenderBelt16749(t *testing.T) {
	for _, ht := range []int{1, 2, 65536, 100000} {
		m := New()
		bgp := &config.BGPConfig{
			LocalAS: 65001,
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.255.0.2", PeerAS: 65002, HoldTime: ht},
			},
		}
		got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
		if strings.Contains(got, "timers") {
			t.Errorf("hold-time %d rendered a timers line bgpd refuses:\n%s", ht, got)
		}
		if !strings.Contains(got, "neighbor 10.255.0.2 remote-as 65002") {
			t.Errorf("hold-time %d belt suppressed the neighbor itself:\n%s", ht, got)
		}
	}
	// Controls unchanged.
	for ht, want := range map[int]string{3: " neighbor 10.255.0.2 timers 1 3\n", 9: " neighbor 10.255.0.2 timers 3 9\n", 30: " neighbor 10.255.0.2 timers 10 30\n", 65535: " neighbor 10.255.0.2 timers 21845 65535\n"} {
		m := New()
		bgp := &config.BGPConfig{
			LocalAS: 65001,
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.255.0.2", PeerAS: 65002, HoldTime: ht},
			},
		}
		got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
		if !strings.Contains(got, want) {
			t.Errorf("hold-time %d: want %q in:\n%s", ht, want, got)
		}
	}
	// 0 = unset: no timers line, as before.
	m := New()
	bgp := &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{{Address: "10.255.0.2", PeerAS: 65002}}}
	if got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil); strings.Contains(got, "timers") {
		t.Errorf("hold-time 0 must render no timers line:\n%s", got)
	}
}
