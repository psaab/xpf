package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16800: FRR bgpd evaluates an outbound route-map for a REFLECTED
// (IBGP->IBGP) advertisement on a dummy attribute copy unless
// `bgp route-reflector allow-outbound-policy` is set in the router
// stanza, so every export-policy set clause (the #5115
// `then next-hop self` lowering, local-preference, community, ...)
// was silently discarded on reflected routes and RR clients received
// the original next-hop/attributes (the #2977 blackhole). These tests
// pin the render: every stanza (default AND each VRF) that renders a
// route-reflector-client gains the line exactly once at router level;
// stanzas with no rendered client are byte-identical.
//
// FAIL-ON-REVERT: dropping the render in renderBGP16125 (or gating it
// on a modifying policy being attached) turns the positive, per-VRF,
// multi-client and modifying-chain assertions RED.

const allowOutboundPolicy16800 = " bgp route-reflector allow-outbound-policy\n"

// modifyingPolicy16800 returns a policy whose terms carry the three
// set-clause families the source report names: `then next-hop self`,
// local-preference, and community.
func modifyingPolicy16800() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"TE": {
				Name: "TE",
				Terms: []*config.PolicyTerm{
					{Name: "t", NextHop: "self", HasLocalPreference: true, LocalPreference: 777, Action: "accept"},
				},
			},
			"TAG": {
				Name: "TAG",
				Terms: []*config.PolicyTerm{
					{Name: "t", CommunityOp: "add", CommunityAdd: "65001:100", Action: "accept"},
				},
			},
		},
	}
}

// TestRRAllowOutboundPolicyRendered16800 is the primary render pin: a
// route-reflector-client with a modifying export chain renders the
// stanza knob exactly once, at router level, adjacent to cluster-id.
func TestRRAllowOutboundPolicyRendered16800(t *testing.T) {
	m := New()
	po := modifyingPolicy16800()
	bgp := &config.BGPConfig{
		LocalAS:   65001,
		RouterID:  "1.1.1.1",
		ClusterID: "10.0.0.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65001, RouteReflectorClient: true, Export: []string{"TE"}},
			{Address: "10.0.0.3", PeerAS: 65001, Export: []string{"TE"}},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)
	if !strings.Contains(got, "neighbor 10.0.0.2 route-reflector-client\n") {
		t.Fatalf("anti-vacuity: RR client not rendered:\n%s", got)
	}
	if !strings.Contains(got, "neighbor 10.0.0.2 route-map TE out\n") {
		t.Fatalf("anti-vacuity: modifying export not attached:\n%s", got)
	}
	if !strings.Contains(got, " bgp cluster-id 10.0.0.1\n"+allowOutboundPolicy16800) {
		t.Errorf("allow-outbound-policy must follow cluster-id at router level:\n%s", got)
	}
	if n := strings.Count(got, allowOutboundPolicy16800); n != 1 {
		t.Errorf("want exactly 1 allow-outbound-policy line, got %d:\n%s", n, got)
	}
	// The route-map set clauses the knob makes effective on reflected
	// routes must themselves be present (otherwise the line is vacuous).
	rmap := m.generatePolicyOptions(po)
	for _, want := range []string{" set ip next-hop peer-address\n", " set local-preference 777\n", " set community 65001:100 additive\n"} {
		if !strings.Contains(rmap, want) {
			t.Errorf("modifying clause %q missing from route-map:\n%s", want, rmap)
		}
	}
}

// TestRRAllowOutboundPolicyNonRRByteIdentical16800 proves the counter-
// case: no route-reflector-client -> no line, in either a plain iBGP
// or eBGP stanza (acceptance: non-RR stanzas render byte-identically).
func TestRRAllowOutboundPolicyNonRRByteIdentical16800(t *testing.T) {
	m := New()
	po := modifyingPolicy16800()
	for _, tc := range []struct {
		name string
		bgp  *config.BGPConfig
	}{
		{"ibgp", &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1", Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65001, Export: []string{"TE"}}}}},
		{"ebgp", &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1", Neighbors: []*config.BGPNeighbor{
			{Address: "192.0.2.2", PeerAS: 65002, Export: []string{"TE"}}}}},
		{"no-neighbors", &config.BGPConfig{LocalAS: 65001, RouterID: "1.1.1.1"}},
	} {
		got := m.generateProtocols(nil, nil, tc.bgp, nil, nil, "", 0, po, nil)
		if strings.Contains(got, "allow-outbound-policy") {
			t.Errorf("%s: non-RR stanza must not render allow-outbound-policy:\n%s", tc.name, got)
		}
	}
}

// TestRRAllowOutboundPolicyRenderedWithoutModifyingPolicy16800 pins
// the unconditional-per-client gate: the knob does not depend on the
// attached export chain carrying a set clause, so accept/reject-only,
// import-only, global-chain and policy-less RR stanzas all gain it.
func TestRRAllowOutboundPolicyRenderedWithoutModifyingPolicy16800(t *testing.T) {
	m := New()
	plain := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		"PLAIN": {Name: "PLAIN", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
	}}
	client := func(mut func(*config.BGPNeighbor)) *config.BGPNeighbor {
		n := &config.BGPNeighbor{Address: "10.0.0.2", PeerAS: 65001, RouteReflectorClient: true}
		if mut != nil {
			mut(n)
		}
		return n
	}
	for _, tc := range []struct {
		name string
		bgp  *config.BGPConfig
		po   *config.PolicyOptionsConfig
	}{
		{"accept-only export", &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{
			client(func(n *config.BGPNeighbor) { n.Export = []string{"PLAIN"} })}}, plain},
		{"import only", &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{
			client(func(n *config.BGPNeighbor) { n.Import = []string{"PLAIN"} })}}, plain},
		{"no policy", &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{client(nil)}}, nil},
		{"global export chain", &config.BGPConfig{LocalAS: 65001, Export: []string{"PLAIN"},
			Neighbors: []*config.BGPNeighbor{client(nil)}}, plain},
	} {
		got := m.generateProtocols(nil, nil, tc.bgp, nil, nil, "", 0, tc.po, nil)
		if !strings.Contains(got, "neighbor 10.0.0.2 route-reflector-client\n") {
			t.Fatalf("%s: anti-vacuity: RR client not rendered:\n%s", tc.name, got)
		}
		if n := strings.Count(got, allowOutboundPolicy16800); n != 1 {
			t.Errorf("%s: want exactly 1 allow-outbound-policy line, got %d:\n%s", tc.name, n, got)
		}
	}
}

// TestRRAllowOutboundPolicyModifyingChainShapes16800 proves every
// effective export-chain shape that can carry a modifying term still
// resolves (anti-vacuity) and keeps the knob: own chain, global chain,
// and a >=2 composed chain.
func TestRRAllowOutboundPolicyModifyingChainShapes16800(t *testing.T) {
	m := New()
	po := modifyingPolicy16800()
	client := &config.BGPNeighbor{Address: "10.0.0.2", PeerAS: 65001, RouteReflectorClient: true}
	for _, tc := range []struct {
		name string
		bgp  *config.BGPConfig
		want string
	}{
		{"own chain", &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65001, RouteReflectorClient: true, Export: []string{"TE"}}}}, "neighbor 10.0.0.2 route-map TE out\n"},
		{"global chain", &config.BGPConfig{LocalAS: 65001, Export: []string{"TE"}, Neighbors: []*config.BGPNeighbor{client}}, "neighbor 10.0.0.2 route-map TE out\n"},
		{"composed chain", &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65001, RouteReflectorClient: true, Export: []string{"TE", "TAG"}}}}, "neighbor 10.0.0.2 route-map TE-TAG" + ReservedChainSuffix + " out\n"},
	} {
		got := m.generateProtocols(nil, nil, tc.bgp, nil, nil, "", 0, po, nil)
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: anti-vacuity: export attachment %q missing:\n%s", tc.name, tc.want, got)
		}
		if n := strings.Count(got, allowOutboundPolicy16800); n != 1 {
			t.Errorf("%s: want exactly 1 allow-outbound-policy line, got %d:\n%s", tc.name, n, got)
		}
	}
}

// TestRRAllowOutboundPolicyMultipleClientsOneLine16800: the knob is
// router-global, so two clients (one per family) still yield one line.
func TestRRAllowOutboundPolicyMultipleClientsOneLine16800(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65001, RouteReflectorClient: true, FamilyInet: true},
			{Address: "2001:db8::2", PeerAS: 65001, RouteReflectorClient: true, FamilyInet6: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	for _, want := range []string{"neighbor 10.0.0.2 route-reflector-client\n", "neighbor 2001:db8::2 route-reflector-client\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("anti-vacuity: %q missing:\n%s", want, got)
		}
	}
	if n := strings.Count(got, allowOutboundPolicy16800); n != 1 {
		t.Errorf("want exactly 1 allow-outbound-policy line for two clients, got %d:\n%s", n, got)
	}
}

// TestRRAllowOutboundPolicyEBGPOnlyClientOmitted16800: a would-be
// client the #14585 belt omits as eBGP renders no route-reflector-
// client and therefore no knob.
func TestRRAllowOutboundPolicyEBGPOnlyClientOmitted16800(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "192.0.2.2", PeerAS: 65002, RouteReflectorClient: true, FamilyInet: true},
			// Effective eBGP via local-as override (#15663 classification).
			{Address: "192.0.2.3", PeerAS: 65001, LocalAS: 65009, RouteReflectorClient: true, FamilyInet: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "route-reflector-client") {
		t.Fatalf("anti-vacuity: eBGP route-reflector-client must be omitted (#14585):\n%s", got)
	}
	if strings.Contains(got, "allow-outbound-policy") {
		t.Errorf("stanza with no rendered client must not render allow-outbound-policy:\n%s", got)
	}
}

// TestRRAllowOutboundPolicyDisabledOrInvalidClient16800: clients
// excluded from validNeighbors (disabled, remote-as 0) render no
// client and no knob.
func TestRRAllowOutboundPolicyDisabledOrInvalidClient16800(t *testing.T) {
	m := New()
	for _, tc := range []struct {
		name string
		n    *config.BGPNeighbor
	}{
		{"disabled", &config.BGPNeighbor{Address: "10.0.0.2", PeerAS: 65001, RouteReflectorClient: true, Disable: true}},
		{"remote-as 0", &config.BGPNeighbor{Address: "10.0.0.2", PeerAS: 0, RouteReflectorClient: true}},
	} {
		bgp := &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{tc.n}}
		got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
		if strings.Contains(got, "allow-outbound-policy") {
			t.Errorf("%s: excluded client must not trigger allow-outbound-policy:\n%s", tc.name, got)
		}
	}
	// Whole-protocol disable renders no stanza at all.
	off := &config.BGPConfig{LocalAS: 65001, Disable: true, Neighbors: []*config.BGPNeighbor{
		{Address: "10.0.0.2", PeerAS: 65001, RouteReflectorClient: true}}}
	if got := m.generateProtocols(nil, nil, off, nil, nil, "", 0, nil, nil); strings.Contains(got, "router bgp") {
		t.Errorf("disabled BGP must render no stanza:\n%s", got)
	}
}

// TestRRAllowOutboundPolicyPerVRF16800: each routing-instance stanza
// is gated independently — the RR VRF gains the line, the non-RR VRF
// and a non-RR default instance do not (and vice versa).
func TestRRAllowOutboundPolicyPerVRF16800(t *testing.T) {
	fc := &FullConfig{
		BGP: &config.BGPConfig{
			LocalAS:   65001,
			Neighbors: []*config.BGPNeighbor{{Address: "10.0.0.9", PeerAS: 65001, FamilyInet: true}},
		},
		Instances: []InstanceConfig{
			{
				Name:    "cust-a",
				VRFName: "vrf-cust-a",
				BGP: &config.BGPConfig{
					LocalAS:   65001,
					ClusterID: "10.1.0.1",
					Neighbors: []*config.BGPNeighbor{{Address: "10.1.0.2", PeerAS: 65001, RouteReflectorClient: true, FamilyInet: true}},
				},
			},
			{
				Name:    "cust-b",
				VRFName: "vrf-cust-b",
				BGP: &config.BGPConfig{
					LocalAS:   65002,
					Neighbors: []*config.BGPNeighbor{{Address: "10.2.0.2", PeerAS: 65002, FamilyInet: true}},
				},
			},
		},
	}
	got := New().buildManagedSection(fc)
	if !strings.Contains(got, "router bgp 65001 vrf vrf-cust-a\n") ||
		!strings.Contains(got, "router bgp 65002 vrf vrf-cust-b\n") ||
		!strings.Contains(got, "router bgp 65001\n") {
		t.Fatalf("anti-vacuity: expected default + 2 VRF stanzas:\n%s", got)
	}
	if n := strings.Count(got, allowOutboundPolicy16800); n != 1 {
		t.Errorf("want exactly 1 allow-outbound-policy line (RR VRF only), got %d:\n%s", n, got)
	}
	// The single line must sit inside the RR VRF stanza, after its
	// cluster-id and before its address-family block.
	start := strings.Index(got, "router bgp 65001 vrf vrf-cust-a\n")
	end := strings.Index(got[start:], "\n!\n")
	if end < 0 {
		t.Fatalf("RR VRF stanza not terminated:\n%s", got)
	}
	stanza := got[start : start+end]
	if !strings.Contains(stanza, " bgp cluster-id 10.1.0.1\n"+allowOutboundPolicy16800) {
		t.Errorf("allow-outbound-policy must be in the RR VRF stanza after cluster-id:\n%s", stanza)
	}
}
