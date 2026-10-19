package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14585 render belt: a leniently-loaded config carrying combinations FRR
// refuses must render nothing FRR rejects.

func TestRenderCrossField14585OmitsRefusedLines(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:           65001,
		Dampening:         true,
		DampeningReuse:    750,
		DampeningSuppress: 500,
		Neighbors: []*config.BGPNeighbor{
			{Address: "192.0.2.2", PeerAS: 65002, LocalAS: 65001, RouteReflectorClient: true, FamilyInet: true},
			{Address: "192.0.2.3", PeerAS: 65001, RemovePrivateAS: true, FamilyInet: true},
			{Address: "192.0.2.4", PeerAS: 65001, RouteReflectorClient: true, FamilyInet: true},
			{Address: "192.0.2.5", PeerAS: 65002, LocalAS: 65009, RemovePrivateAS: true, FamilyInet: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	for _, bad := range []string{
		"neighbor 192.0.2.2 local-as 65001",
		"neighbor 192.0.2.2 route-reflector-client",
		"neighbor 192.0.2.3 remove-private-AS",
		"bgp dampening",
	} {
		if strings.Contains(got, bad) {
			t.Errorf("renderer emitted FRR-refused %q:\n%s", bad, got)
		}
	}
	for _, good := range []string{
		"neighbor 192.0.2.4 route-reflector-client",
		"neighbor 192.0.2.5 local-as 65009",
		"neighbor 192.0.2.5 remove-private-AS all",
	} {
		if !strings.Contains(got, good) {
			t.Errorf("renderer dropped valid %q:\n%s", good, got)
		}
	}
}

func TestRenderCrossField14585OSPBackboneStubOmitted(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", AreaType: "stub"},
			{ID: "0.0.0.1", AreaType: "stub"},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "area 0.0.0.0 stub") {
		t.Errorf("renderer emitted backbone stub:\n%s", got)
	}
	if !strings.Contains(got, "area 0.0.0.1 stub") {
		t.Errorf("renderer dropped non-backbone stub:\n%s", got)
	}
	ospf3 := &config.OSPFv3Config{
		Areas: []*config.OSPFv3Area{{ID: "0", AreaType: "nssa"}},
	}
	got3 := m.generateProtocols(nil, ospf3, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got3, "area 0 nssa") {
		t.Errorf("renderer emitted backbone nssa:\n%s", got3)
	}
}

func TestRenderCrossField14585DampeningValidStillRenders(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:           65001,
		Dampening:         true,
		DampeningReuse:    750,
		DampeningSuppress: 2000,
		Neighbors:         []*config.BGPNeighbor{{Address: "192.0.2.2", PeerAS: 65002}},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "bgp dampening 15 750 2000 60") {
		t.Errorf("valid dampening dropped:\n%s", got)
	}
}

// #15663: the render belt must classify iBGP by the effective local AS
// (neighbor LocalAS, which already carries any group local-as, else the
// router AS), not the router AS alone.
func TestRenderCrossField15663LocalASEffective(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			// Effective iBGP via local-as: RRC renders, remove-private omitted.
			{Address: "192.0.2.2", PeerAS: 65001, LocalAS: 65001, RouteReflectorClient: true, FamilyInet: true},
			{Address: "192.0.2.3", PeerAS: 65001, LocalAS: 65001, RemovePrivateAS: true, FamilyInet: true},
			// True eBGP under local-as: RRC omitted, remove-private renders.
			{Address: "192.0.2.4", PeerAS: 65002, LocalAS: 65001, RouteReflectorClient: true, FamilyInet: true},
			{Address: "192.0.2.5", PeerAS: 65002, LocalAS: 65001, RemovePrivateAS: true, FamilyInet: true},
			// Peer matches router AS but local-as override makes it eBGP.
			{Address: "192.0.2.6", PeerAS: 65000, LocalAS: 65001, RouteReflectorClient: true, FamilyInet: true},
			{Address: "192.0.2.7", PeerAS: 65000, LocalAS: 65001, RemovePrivateAS: true, FamilyInet: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	for _, good := range []string{
		"neighbor 192.0.2.2 route-reflector-client",
		"neighbor 192.0.2.5 remove-private-AS all",
		"neighbor 192.0.2.7 remove-private-AS all",
	} {
		if !strings.Contains(got, good) {
			t.Errorf("renderer dropped valid %q:\n%s", good, got)
		}
	}
	for _, bad := range []string{
		"neighbor 192.0.2.3 remove-private-AS",
		"neighbor 192.0.2.4 route-reflector-client",
		"neighbor 192.0.2.6 route-reflector-client",
	} {
		if strings.Contains(got, bad) {
			t.Errorf("renderer emitted FRR-refused %q:\n%s", bad, got)
		}
	}
}
