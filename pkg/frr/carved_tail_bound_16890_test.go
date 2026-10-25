package frr

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16890: a carved export with 6552 counted term sequences would place its
// final deny at 65540 unless the render-side #5701 belt reserves the tail.
func TestBGPCarvedNoNextPolicyTailSequenceBoundary16890(t *testing.T) {
	mkFC := func(n int) *FullConfig {
		terms := make([]*config.PolicyTerm, 0, n)
		lists := map[string]*config.PrefixList{
			"adv": {Name: "adv", Prefixes: []string{"192.0.2.0/24"}},
		}
		for i := range n {
			name := fmt.Sprintf("pl%d", i)
			lists[name] = &config.PrefixList{Name: name, Prefixes: []string{"10.0.0.0/8"}}
			terms = append(terms, &config.PolicyTerm{
				Name:       fmt.Sprintf("t%d", i),
				PrefixList: []string{name},
				Action:     "accept",
			})
		}
		po := &config.PolicyOptionsConfig{
			PrefixLists: lists,
			PolicyStatements: map[string]*config.PolicyStatement{
				"BIG": {Name: "BIG", Terms: terms},
				"LOCAL": {Name: "LOCAL", Terms: []*config.PolicyTerm{{
					Name: "t1", FromProtocols: []string{"static"}, PrefixList: []string{"adv"}, Action: "accept",
				}}},
			},
		}
		return &FullConfig{
			PolicyOptions: po,
			BGP: &config.BGPConfig{
				LocalAS: 65001, RouterID: "1.1.1.1",
				Neighbors: []*config.BGPNeighbor{
					{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"BIG"}},
					{Address: "192.0.2.2", PeerAS: 65004, FamilyInet: true, Export: []string{"LOCAL"}},
				},
			},
		}
	}

	// At one below the count ceiling, the two-sequence carved pair ends at
	// 65530, the highest legal sequence rounded down to the route-map step.
	fc := mkFC(int(config.MaxRouteMapSequences) - 1)
	if got := config.RouteMapSequenceCount(fc.PolicyOptions, fc.PolicyOptions.PolicyStatements["BIG"]); got != uint64(config.MaxRouteMapSequences)-1 {
		t.Fatalf("control count = %d, want %d", got, config.MaxRouteMapSequences-1)
	}
	rendered := New().buildManagedSection(fc)
	block := routeMapBlock15157(rendered, "BIG")
	headers, maxSeq := maxRenderedSeq16869(t, block, "BIG")
	if headers != 6553 || maxSeq != 65530 {
		t.Fatalf("in-range carved map headers=%d maxSeq=%d, want 6553/65530:\n%s", headers, maxSeq, block[len(block)-min(len(block), 500):])
	}
	for _, want := range []string{
		"route-map BIG permit 65520\n match source-protocol bgp\n",
		"route-map BIG deny 65530\n",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("in-range carved map missing %q", want)
		}
	}

	// At the issue's exact 6552-term shape, the carved deny would be 65540.
	// Quarantine the entire expansion rather than poisoning frr-reload.
	fc = mkFC(int(config.MaxRouteMapSequences))
	if got := config.RouteMapSequenceCount(fc.PolicyOptions, fc.PolicyOptions.PolicyStatements["BIG"]); got != config.MaxRouteMapSequences {
		t.Fatalf("escaping count = %d, want %d", got, config.MaxRouteMapSequences)
	}
	rendered = New().buildManagedSection(fc)
	headersOnly := routeMapHeaders6807(rendered, "BIG")
	if len(headersOnly) != 1 || headersOnly[0] != fmt.Sprintf("route-map BIG deny %d", quarantineDenySeq) {
		t.Fatalf("out-of-range carved tail must render only the quarantine deny, got %v", headersOnly)
	}
	if strings.Contains(rendered, "route-map BIG deny 65540\n") {
		t.Fatal("out-of-range carved tail deny 65540 escaped the #5701 belt")
	}
}
