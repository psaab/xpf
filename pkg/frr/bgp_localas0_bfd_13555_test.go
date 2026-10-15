package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13555: the `router bgp` block is gated on bgp.LocalAS > 0, but the BFD
// peer accumulator was gated only on bgp != nil. On a tolerant load with a
// BGP config whose LocalAS stayed 0, FRR received a `bfd { peer ... }`
// stanza for a BGP instance that was never rendered.
//
// The fix gates the BFD peer accumulation on the same predicate as
// `router bgp`.
func TestBGPBFDNotRenderedWhenLocalASZero13555(t *testing.T) {
	m := New()

	bfdZeroAS := &config.BGPConfig{
		LocalAS: 0,
		Neighbors: []*config.BGPNeighbor{
			{Address: "192.0.2.1", PeerAS: 65001, FamilyInet: true, BFD: true},
		},
	}
	got := m.generateProtocols(nil, nil, bfdZeroAS, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "router bgp") {
		t.Errorf("LocalAS==0 must not render router bgp; output:\n%s", got)
	}
	if strings.Contains(got, "bfd\n") || strings.Contains(got, " peer 192.0.2.1") {
		t.Errorf("LocalAS==0 must not render a BFD stanza/peer for a nonexistent BGP instance; output:\n%s", got)
	}

	// Positive control: same neighbor with a valid LocalAS renders both.
	bfdValidAS := &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			{Address: "192.0.2.1", PeerAS: 65001, FamilyInet: true, BFD: true},
		},
	}
	gotValid := m.generateProtocols(nil, nil, bfdValidAS, nil, nil, "", 0, nil, nil)
	if !strings.Contains(gotValid, "router bgp 65000\n") {
		t.Errorf("valid LocalAS must render router bgp; output:\n%s", gotValid)
	}
	if !strings.Contains(gotValid, " peer 192.0.2.1\n") {
		t.Errorf("valid LocalAS must render the BFD peer; output:\n%s", gotValid)
	}
}
