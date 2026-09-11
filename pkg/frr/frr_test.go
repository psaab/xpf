package frr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestGenerateStaticRoute_SingleNextHop(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops:    []config.NextHopEntry{{Address: "192.168.1.1"}},
	}
	got := m.generateStaticRoute(sr, "", nil, nil)
	want := "ip route 10.0.0.0/8 192.168.1.1\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_ECMP(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops: []config.NextHopEntry{
			{Address: "192.168.1.1"},
			{Address: "192.168.2.1"},
		},
	}
	got := m.generateStaticRoute(sr, "", nil, nil)
	if !strings.Contains(got, "ip route 10.0.0.0/8 192.168.1.1\n") {
		t.Errorf("missing first next-hop: %q", got)
	}
	if !strings.Contains(got, "ip route 10.0.0.0/8 192.168.2.1\n") {
		t.Errorf("missing second next-hop: %q", got)
	}
}

func TestGenerateStaticRoute_Discard(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.0.99.0/24",
		Discard:     true,
	}
	got := m.generateStaticRoute(sr, "", nil, nil)
	want := "ip route 10.0.99.0/24 Null0\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_Preference(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops:    []config.NextHopEntry{{Address: "192.168.1.1"}},
		Preference:  100,
	}
	got := m.generateStaticRoute(sr, "", nil, nil)
	want := "ip route 10.0.0.0/8 192.168.1.1 100\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestGenerateStaticRoute_LinkLocalInferredScope proves the #2452 fix end to
// end at the renderer: an unqualified link-local next-hop whose interface was
// resolved by inference (passed via ipv6NextHopInterfaces) renders WITH the
// interface scope, which FRR requires for link-local statics. Fail-on-revert:
// if inference returns "" (no synthetic fe80::/64 candidate), the map lookup
// yields no interface and FRR gets a scopeless `ipv6 route ::/0 fe80::1`.
func TestGenerateStaticRoute_LinkLocalInferredScope(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "::/0",
		NextHops:    []config.NextHopEntry{{Address: "fe80::1"}},
	}
	nhIfaces := map[string]map[string]string{"": {"fe80::1": "ge-0-0-3.50"}}
	got := m.generateStaticRoute(sr, "", nil, nhIfaces)
	want := "ipv6 route ::/0 fe80::1 ge-0-0-3.50\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestGenerateStaticRoute_LinkLocalExplicitQualifier confirms an explicit
// interface qualifier on the next-hop renders directly (operator
// disambiguated) regardless of the inference map.
func TestGenerateStaticRoute_LinkLocalExplicitQualifier(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "::/0",
		NextHops:    []config.NextHopEntry{{Address: "fe80::1", Interface: "ge-0-0-4.0"}},
	}
	// Even with a (wrong) inference entry, the explicit qualifier wins.
	nhIfaces := map[string]map[string]string{"": {"fe80::1": "ge-0-0-3.50"}}
	got := m.generateStaticRoute(sr, "", nil, nhIfaces)
	want := "ipv6 route ::/0 fe80::1 ge-0-0-4\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_VRF(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "172.16.0.0/12",
		NextHops:    []config.NextHopEntry{{Address: "10.0.1.1"}},
	}
	got := m.generateStaticRoute(sr, "customer-a", nil, nil)
	want := "ip route 172.16.0.0/12 10.0.1.1 vrf customer-a\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_IPv6(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "2001:db8::/32",
		NextHops:    []config.NextHopEntry{{Address: "fe80::1", Interface: "trust0"}},
	}
	got := m.generateStaticRoute(sr, "", nil, nil)
	want := "ipv6 route 2001:db8::/32 fe80::1 trust0\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_InterfaceOnly(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops:    []config.NextHopEntry{{Interface: "tunnel0"}},
	}
	got := m.generateStaticRoute(sr, "", nil, nil)
	want := "ip route 10.0.0.0/8 tunnel0\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_NextTable(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "0.0.0.0/0",
		NextTable:   "Comcast-GigabitPro",
	}
	got := m.generateStaticRoute(sr, "", nil, nil)
	if got != "" {
		t.Errorf("next-table route should produce empty FRR output, got %q", got)
	}
}

func TestGenerateProtocols_OSPF(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", Passive: false},
					{Name: "dmz0", Passive: true},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "router ospf\n") {
		t.Error("missing 'router ospf'")
	}
	if !strings.Contains(got, "ospf router-id 1.1.1.1\n") {
		t.Error("missing router-id")
	}
	// #1712: OSPFv2 area membership must be rendered per-interface via
	// "ip ospf area <id>" under "interface <name>", NEVER as a global
	// "network <prefix> area" catch-all (which matches every IPv4
	// interface in the VRF). Reject any "network ... area ..." line.
	if strings.Contains(got, "network 0.0.0.0/0") {
		t.Errorf("must not emit catch-all 'network 0.0.0.0/0', got:\n%s", got)
	}
	if strings.Contains(got, " area ") && strings.Contains(got, " network ") {
		// Defensive: no "network <x> area <y>" line of any prefix.
		for _, line := range strings.Split(got, "\n") {
			ln := strings.TrimSpace(line)
			if strings.HasPrefix(ln, "network ") && strings.Contains(ln, " area ") {
				t.Errorf("must not emit 'network ... area ...' activation, got line: %q", ln)
			}
		}
	}
	if !strings.Contains(got, "interface trust0\n ip ospf area 0.0.0.0\nexit\n") {
		t.Errorf("missing per-interface 'ip ospf area' activation for trust0, got:\n%s", got)
	}
	if !strings.Contains(got, "interface dmz0\n ip ospf area 0.0.0.0\nexit\n") {
		t.Errorf("missing per-interface 'ip ospf area' activation for dmz0, got:\n%s", got)
	}
	if !strings.Contains(got, "passive-interface dmz0\n") {
		t.Error("missing passive-interface")
	}
	if strings.Contains(got, "passive-interface trust0") {
		t.Error("trust0 should not be passive")
	}
}

// TestGenerateProtocols_OSPFTwoAreasUnrelatedIface proves the #1712 fix:
// with two areas each holding a distinct interface, every interface is
// activated in its OWN area via a per-interface "ip ospf area" line, no
// global "network ... area" catch-all is emitted, and an L3 interface
// that is NOT in any OSPF area (here "untrust0", simply absent from
// ospf.Areas) is never activated. Under the old "network 0.0.0.0/0 area"
// rendering, the catch-all would have activated untrust0 too and let
// render order decide which area trust0/dmz0 landed in.
func TestGenerateProtocols_OSPFTwoAreasUnrelatedIface(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}},
			{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "dmz0"}}},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)

	// No catch-all of any prefix.
	if strings.Contains(got, "network 0.0.0.0/0") {
		t.Errorf("must not emit catch-all 'network 0.0.0.0/0', got:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		ln := strings.TrimSpace(line)
		if strings.HasPrefix(ln, "network ") && strings.Contains(ln, " area ") {
			t.Errorf("must not emit 'network ... area ...' activation, got line: %q", ln)
		}
	}

	// Each configured interface activated in its OWN area.
	if !strings.Contains(got, "interface trust0\n ip ospf area 0.0.0.0\nexit\n") {
		t.Errorf("trust0 not activated in area 0.0.0.0, got:\n%s", got)
	}
	if !strings.Contains(got, "interface dmz0\n ip ospf area 0.0.0.1\nexit\n") {
		t.Errorf("dmz0 not activated in area 0.0.0.1, got:\n%s", got)
	}

	// An interface not in any OSPF area must never be activated. Exactly
	// two "ip ospf area" activation lines should appear (trust0, dmz0).
	if n := strings.Count(got, "ip ospf area "); n != 2 {
		t.Errorf("expected exactly 2 'ip ospf area' activations, got %d:\n%s", n, got)
	}
	if strings.Contains(got, "untrust0") {
		t.Errorf("unrelated interface untrust0 must never appear in OSPF config, got:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFExportAndCost(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Export:   []string{"connected", "static"},
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", Cost: 100},
					{Name: "dmz0", Cost: 0},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "redistribute connected\n") {
		t.Error("missing redistribute connected")
	}
	if !strings.Contains(got, "redistribute static\n") {
		t.Error("missing redistribute static")
	}
	if !strings.Contains(got, "ip ospf cost 100\n") {
		t.Errorf("missing ospf cost for trust0, got:\n%s", got)
	}
	if strings.Contains(got, "ip ospf cost 0") {
		t.Error("should not emit cost 0")
	}
}

func TestGenerateProtocols_BGP(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, Description: "upstream"},
			{Address: "10.0.3.1", PeerAS: 65003, MultihopTTL: 5},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "router bgp 65001\n") {
		t.Error("missing 'router bgp 65001'")
	}
	if !strings.Contains(got, "bgp router-id 1.1.1.1\n") {
		t.Error("missing router-id")
	}
	if !strings.Contains(got, "neighbor 10.0.2.1 remote-as 65002\n") {
		t.Error("missing neighbor 10.0.2.1")
	}
	if !strings.Contains(got, "neighbor 10.0.2.1 description upstream\n") {
		t.Error("missing neighbor description")
	}
	if !strings.Contains(got, "neighbor 10.0.3.1 ebgp-multihop 5\n") {
		t.Error("missing multihop")
	}
}

func TestGenerateProtocols_RIP(t *testing.T) {
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"trust0", "dmz0"},
		Passive:      []string{"dmz0"},
		Redistribute: []string{"connected", "static"},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	if !strings.Contains(got, "router rip\n") {
		t.Error("missing 'router rip'")
	}
	if !strings.Contains(got, "network trust0\n") {
		t.Error("missing network trust0")
	}
	if !strings.Contains(got, "passive-interface dmz0\n") {
		t.Error("missing passive-interface dmz0")
	}
	if !strings.Contains(got, "redistribute connected\n") {
		t.Error("missing redistribute connected")
	}
}

func TestGenerateProtocols_ISIS(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:   "49.0001.1921.6800.1001.00",
		Level: "level-1-2",
		Interfaces: []*config.ISISInterface{
			{Name: "trust0", Passive: false, Metric: 10},
			{Name: "dmz0", Passive: true},
		},
	}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
	if !strings.Contains(got, "router isis xpf\n") {
		t.Error("missing 'router isis xpf'")
	}
	if !strings.Contains(got, "net 49.0001.1921.6800.1001.00\n") {
		t.Error("missing NET")
	}
	if !strings.Contains(got, "is-type level-1-2\n") {
		t.Error("missing is-type")
	}
	if !strings.Contains(got, "isis metric 10\n") {
		t.Error("missing metric")
	}
	if !strings.Contains(got, "isis passive\n") {
		t.Error("missing passive")
	}
}

// TestGenerateProtocols_BGPExportBareToken is the #2473 bare-token guard.
// A global `protocols bgp export <token>` where the token is a BARE
// protocol keyword (connected/static/... — NOT a defined policy-statement)
// is this firewall's redistribution shorthand and MUST render as
// `redistribute <proto>`. It has NO route-map to reference: rendering it as
// `neighbor X route-map connected out` would point at a non-existent
// route-map. (#6807 CORRECTION: this said FRR resolves that to PERMIT-ALL and
// advertises the entire table. It does not — bgp_output_modifier returns
// RMAP_DENY for a name it cannot resolve, so the dangling ref WITHDRAWS the
// peer's routes. The classification this cell guards is still correct: a bare
// protocol token is a redistribute verb and has no policy to reference. Only
// the stated consequence was wrong.) Fail-on-revert: routing ALL bgp.Export through
// route-map-out makes `route-map connected out` appear with no defining
// route-map → the assert-no-dangling-route-map check below fails.
func TestGenerateProtocols_BGPExportBareToken(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Export:   []string{"connected", "static"},
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002},
		},
	}
	// nil policyOptions: no policy-statements defined, so both tokens are
	// bare protocol keywords.
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "redistribute connected\n") {
		t.Errorf("missing redistribute connected, got:\n%s", got)
	}
	if !strings.Contains(got, "redistribute static\n") {
		t.Errorf("missing redistribute static, got:\n%s", got)
	}
	// A bare token must NEVER render a dangling route-map out (permit-all
	// leak).
	if strings.Contains(got, "route-map connected out") || strings.Contains(got, "route-map static out") {
		t.Errorf("LEAK: bare protocol token must not render a dangling route-map out, got:\n%s", got)
	}
}

// TestGenerateProtocols_BGPExportNoLeak is the #2473 route-leak guard. A
// Junos global `protocols bgp export <policy>` whose policy carries `from
// protocol ospf` (or connected/static) MUST render as a peer-level
// `neighbor <X> route-map <name> out` — NOT as `redistribute ospf
// route-map ...` under `router bgp`. The old code routed bgp.Export
// through resolveRedistribute, which emitted `redistribute ospf` and
// actively ANNOUNCED the OSPF/connected RIB into BGP (internal subnets
// leaked to external peers). Fail-on-revert: reverting to
// resolveRedistribute makes `redistribute ospf` reappear → this test
// fails.
func TestGenerateProtocols_BGPExportNoLeak(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"leak-ospf": {
				Name: "leak-ospf",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocols: []string{"ospf"}, Action: "accept"},
				},
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Export:   []string{"leak-ospf"},
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)
	// The global export is applied as a peer-level default route-map out.
	if !strings.Contains(got, "neighbor 10.0.2.1 route-map leak-ospf out\n") {
		t.Errorf("missing peer-level route-map out for global export, got:\n%s", got)
	}
	// The leak: a from-protocol global export must NOT emit redistribute.
	if strings.Contains(got, "redistribute ospf") {
		t.Errorf("ROUTE LEAK: global BGP export must not emit redistribute, got:\n%s", got)
	}
}

// TestGenerateProtocols_BGPImport is the #2490 inbound-filter render. A
// neighbor `import <policy-statement>` MUST render `neighbor X route-map
// <policy> in`, and the route-map it references must actually be emitted by
// generatePolicyOptions (the policy-statement is defined). Fail-on-revert:
// removing the `route-map in` render makes the in-line disappear → this test
// fails.
func TestGenerateProtocols_BGPImport(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"IMPORT-FILTER": {
				Name: "IMPORT-FILTER",
				Terms: []*config.PolicyTerm{
					{Name: "t1", Action: "accept"},
				},
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, Import: []string{"IMPORT-FILTER"}},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)
	if !strings.Contains(got, "neighbor 10.0.2.1 route-map IMPORT-FILTER in\n") {
		t.Errorf("missing peer-level route-map in for import, got:\n%s", got)
	}
	// The referenced route-map must actually be emitted (defining block).
	full := m.generatePolicyOptions(po)
	if !strings.Contains(full, "route-map IMPORT-FILTER permit") {
		t.Errorf("import policy-statement not rendered as a route-map, got:\n%s", full)
	}
}

// TestGenerateProtocols_BGPImportAndExport proves import and export on the
// same neighbor render independently — both `route-map ... in` AND
// `route-map ... out` are emitted. Fail-on-revert (import side): dropping the
// import render leaves only the out line → this test fails.
func TestGenerateProtocols_BGPImportAndExport(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"IN":  {Name: "IN", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
			"OUT": {Name: "OUT", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, Import: []string{"IN"}, Export: []string{"OUT"}},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)
	if !strings.Contains(got, "neighbor 10.0.2.1 route-map IN in\n") {
		t.Errorf("missing route-map IN in, got:\n%s", got)
	}
	if !strings.Contains(got, "neighbor 10.0.2.1 route-map OUT out\n") {
		t.Errorf("missing route-map OUT out, got:\n%s", got)
	}
}

// TestGenerateProtocols_BGPExportNextHopSelf proves a `then next-hop self`
// export policy attached to an iBGP neighbor is lowered as a TERM-SCOPED
// route-map `set ip/ipv6 next-hop peer-address` clause (self in the
// outbound direction), NOT the neighbor-wide `next-hop-self` knob (#5115).
//
// FRR has no literal `set ... next-hop self` clause, but in an OUTBOUND
// route-map `set ip next-hop peer-address` resolves to the local end of
// the BGP session (= self) and is evaluated per-route. The pre-#5115 code
// emitted `neighbor <peer> next-hop-self force`, which ran after route
// selection and rewrote EVERY route advertised to the peer — widening a
// term-scoped action to the whole neighbor. The route-map lowering still
// overrides iBGP / route-reflector-reflected next-hops (the #2977 fix),
// now scoped to the term's routes.
//
// Fail-on-revert: restore the `neighbor %s next-hop-self force` emission
// and the neighbor block regains the widening knob (first assertion RED);
// drop the route-map `set ip/ipv6 next-hop peer-address` emission and the
// route-map assertions go RED.
func TestGenerateProtocols_BGPExportNextHopSelf(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"NHS": {
				Name: "NHS",
				Terms: []*config.PolicyTerm{
					{Name: "t", NextHop: "self", Action: "accept"},
				},
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS:  65001, // iBGP: peer in the same AS
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65001, Export: []string{"NHS"}},
		},
	}
	proto := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)

	// The neighbor block MUST NOT carry the widening next-hop-self knob.
	if strings.Contains(proto, "next-hop-self") {
		t.Errorf("#5115: neighbor-wide `next-hop-self` knob must NOT be emitted (widens the term-scoped action), got:\n%s", proto)
	}

	// The export route-map MUST carry the term-scoped self lowering.
	rmap := m.generatePolicyOptions(po)
	if !strings.Contains(rmap, "set ip next-hop peer-address\n") {
		t.Errorf("#5115: missing term-scoped `set ip next-hop peer-address` for `then next-hop self`, got:\n%s", rmap)
	}
	if !strings.Contains(rmap, "set ipv6 next-hop peer-address\n") {
		t.Errorf("#5115: missing term-scoped `set ipv6 next-hop peer-address` for `then next-hop self`, got:\n%s", rmap)
	}
	// And NEVER an invalid `set ... next-hop self` clause (FRR rejects it,
	// taking the whole route-map down).
	if strings.Contains(rmap, "set ip next-hop self") || strings.Contains(rmap, "set ipv6 next-hop self") {
		t.Errorf("must NOT emit an invalid `set ... next-hop self` route-map clause, got:\n%s", rmap)
	}
}

// TestGenerateProtocols_BGPExportNextHopSelfRRClient proves the route-
// reflector reflected-route sub-case (#2977): a route-reflector-CLIENT
// neighbor with a `then next-hop self` export still rewrites the next-hop
// on the iBGP-learned routes reflected to the client. An OUTBOUND route-map
// `set ip next-hop peer-address` unconditionally overrides the next-hop for
// every route the clause matches (the same effect the old `force` gave), so
// the #2977 blackhole stays fixed WITHOUT the widening neighbor knob (#5115).
func TestGenerateProtocols_BGPExportNextHopSelfRRClient(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"NHS": {
				Name: "NHS",
				Terms: []*config.PolicyTerm{
					{Name: "t", NextHop: "self", Action: "accept"},
				},
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS:  65001, // iBGP
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			// RR client: routes reflected to it are iBGP-learned; the outbound
			// route-map set-clause overrides their next-hop unconditionally.
			{Address: "10.0.0.3", PeerAS: 65001, Export: []string{"NHS"}, RouteReflectorClient: true},
		},
	}
	proto := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)

	if !strings.Contains(proto, "neighbor 10.0.0.3 route-reflector-client\n") {
		t.Fatalf("#2977: RR client not configured as expected, got:\n%s", proto)
	}
	if strings.Contains(proto, "next-hop-self") {
		t.Errorf("#5115: RR-client export must NOT emit the widening `next-hop-self` knob, got:\n%s", proto)
	}
	if rmap := m.generatePolicyOptions(po); !strings.Contains(rmap, "set ip next-hop peer-address\n") {
		t.Errorf("#2977/#5115: RR-client `then next-hop self` must render the term-scoped `set ip next-hop peer-address`, got:\n%s", rmap)
	}
}

// TestGenerateProtocols_BGPExportNoSpuriousNextHopSelf proves an export
// policy WITHOUT `then next-hop self` never emits the next-hop-self knob nor
// a spurious peer-address set-clause — no regression for the common case.
func TestGenerateProtocols_BGPExportNoSpuriousNextHopSelf(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"OUT": {Name: "OUT", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65001, Export: []string{"OUT"}},
		},
	}
	if got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil); strings.Contains(got, "next-hop-self") {
		t.Errorf("spurious next-hop-self emitted for a policy without `then next-hop self`, got:\n%s", got)
	}
	if got := m.generatePolicyOptions(po); strings.Contains(got, "next-hop peer-address") {
		t.Errorf("spurious `set next-hop peer-address` emitted for a policy without `then next-hop self`, got:\n%s", got)
	}
}

// TestGenerateProtocols_BGPExportNextHopSelfTermScoped is the #5115
// widening regression: a two-term export policy where ONE term accepts
// prefix A without touching the next-hop and a SEPARATE term accepts prefix
// B with `then next-hop self`. The pre-#5115 code saw "some term wants
// self" and emitted the neighbor-wide `next-hop-self force` knob, which runs
// after route selection and rewrites the next-hop of BOTH prefixes — even
// prefix A, whose term never asked for self. The fix lowers the self action
// into ONLY term B's route-map sequence, so exactly one `set ip next-hop
// peer-address` clause is emitted and prefix A's sequence is untouched.
//
// Fail-on-revert: restoring the neighbor knob makes the `next-hop-self`
// assertion RED; a knob-based lowering would also fail the "exactly one
// set-clause / scoped to term B" assertions.
func TestGenerateProtocols_BGPExportNextHopSelfTermScoped(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"NHS2": {
				Name: "NHS2",
				Terms: []*config.PolicyTerm{
					// Term A: accept prefix A, DO NOT set next-hop self.
					{
						Name:         "keep-nh",
						RouteFilters: []*config.RouteFilter{{Prefix: "10.10.0.0/24", MatchType: "exact"}},
						Action:       "accept",
					},
					// Term B: accept prefix B WITH next-hop self.
					{
						Name:         "self-nh",
						RouteFilters: []*config.RouteFilter{{Prefix: "10.20.0.0/24", MatchType: "exact"}},
						NextHop:      "self",
						Action:       "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS:  65001, // iBGP
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65001, Export: []string{"NHS2"}},
		},
	}

	// No neighbor-wide knob — that is the widening the issue reports.
	proto := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)
	if strings.Contains(proto, "next-hop-self") {
		t.Errorf("#5115: term-scoped `then next-hop self` must NOT widen into a neighbor-wide `next-hop-self` knob, got:\n%s", proto)
	}

	rmap := m.generatePolicyOptions(po)
	// Exactly one term requested self, so exactly one set-clause is emitted
	// (per AF). More than one would mean it leaked onto the other term.
	if n := strings.Count(rmap, "set ip next-hop peer-address"); n != 1 {
		t.Errorf("#5115: expected exactly one `set ip next-hop peer-address` (term B only), got %d in:\n%s", n, rmap)
	}
	// The self set-clause must be scoped to term B's sequence: it appears
	// AFTER term B's prefix (10.20.0.0/24) and there is a route-map sequence
	// boundary between term A's prefix (10.10.0.0/24) and the set-clause, so
	// term A's sequence does not carry it.
	iA := strings.Index(rmap, "10.10.0.0/24")
	iB := strings.Index(rmap, "10.20.0.0/24")
	iSet := strings.Index(rmap, "set ip next-hop peer-address")
	if iA < 0 || iB < 0 || iSet < 0 {
		t.Fatalf("#5115: missing expected prefixes/set-clause in route-map, got:\n%s", rmap)
	}
	if !(iA < iB && iB < iSet) {
		t.Errorf("#5115: self set-clause not scoped to term B (want prefixA<prefixB<set, got %d/%d/%d):\n%s", iA, iB, iSet, rmap)
	}
	if !strings.Contains(rmap[iA:iSet], "route-map NHS2") {
		t.Errorf("#5115: no route-map sequence boundary between term A and the self set-clause — set-clause may leak into term A's sequence:\n%s", rmap)
	}
}

// TestGeneratePolicyOptions_MultiTermOnMatchNext proves a multi-term policy
// whose early term is NON-TERMINATING (set clauses, no `then accept`/`reject`)
// renders `on-match next` so FRR keeps evaluating the later terms (#2451).
//
// Junos evaluates terms sequentially and falls through a term that carries
// only modifications; FRR otherwise stops at the first matching permit
// sequence after running its set clauses, silently truncating the policy.
//
// Fail-on-revert: if the `on-match next` emission is removed, term 1 (community
// set) becomes terminating in FRR and term 2 (local-preference + accept) never
// runs — the "both terms apply" assertion below fails.
func TestGeneratePolicyOptions_MultiTermOnMatchNext(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"MULTI": {
				Name: "MULTI",
				Terms: []*config.PolicyTerm{
					// Term 1: set community, NO accept → non-terminating,
					// must emit on-match next.
					{Name: "t1", Community: "65000:100"},
					// Term 2: set local-preference + accept → terminating
					// permit, NO on-match next.
					{Name: "t2", LocalPreference: 200, HasLocalPreference: true, Action: "accept"},
				},
				DefaultAction: "reject",
			},
		},
	}
	got := m.generatePolicyOptions(po)

	// Both set clauses must render.
	if !strings.Contains(got, " set community 65000:100\n") {
		t.Errorf("term 1 community set missing, got:\n%s", got)
	}
	if !strings.Contains(got, " set local-preference 200\n") {
		t.Errorf("term 2 local-preference set missing, got:\n%s", got)
	}

	// Term 1 (non-terminating) MUST carry on-match next so FRR falls through
	// to term 2 — without it both set clauses do not both apply.
	idxComm := strings.Index(got, " set community 65000:100\n")
	idxLP := strings.Index(got, " set local-preference 200\n")
	idxOMN := strings.Index(got, " on-match next\n")
	if idxOMN < 0 {
		t.Fatalf("term 1 must emit on-match next so both terms apply, got:\n%s", got)
	}
	// on-match next belongs to term 1: it appears after term 1's set and
	// before term 2's set (the sequences render in term order).
	if !(idxComm < idxOMN && idxOMN < idxLP) {
		t.Errorf("on-match next must sit between term 1 (community) and term 2 (local-preference) so the non-terminating term 1 falls through; comm=%d omn=%d lp=%d, got:\n%s",
			idxComm, idxOMN, idxLP, got)
	}

	// Regression guard: the terminating accept term (term 2) must NOT get its
	// own on-match next — exactly one on-match next in this policy.
	if n := strings.Count(got, " on-match next\n"); n != 1 {
		t.Errorf("expected exactly one on-match next (term 1 only), got %d:\n%s", n, got)
	}
}

// TestGeneratePolicyOptions_TerminatingTermNoOnMatchNext proves a terminating
// term (then accept) does NOT get on-match next — FRR stops, matching Junos
// accept semantics (#2451 regression guard). A single-term accept policy is
// unchanged from pre-#2451 output.
func TestGeneratePolicyOptions_TerminatingTermNoOnMatchNext(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"ACCEPT-ONE": {
				Name: "ACCEPT-ONE",
				Terms: []*config.PolicyTerm{
					{Name: "t1", LocalPreference: 150, HasLocalPreference: true, Action: "accept"},
				},
				DefaultAction: "reject",
			},
		},
	}
	got := m.generatePolicyOptions(po)
	if !strings.Contains(got, " set local-preference 150\n") {
		t.Errorf("accept term set clause missing, got:\n%s", got)
	}
	if strings.Contains(got, "on-match next") {
		t.Errorf("terminating accept term must NOT emit on-match next, got:\n%s", got)
	}
}

// TestGenerateProtocols_BGPImportMostSpecificWins proves the RENDER side of
// Junos most-specific-wins after #5277: the group-vs-neighbor LEVEL override is
// now resolved by the COMPILER (a neighbor's own import REPLACES the inherited
// group import — see TestBGPNeighborImportReplacesGroup in pkg/config), so the
// renderer receives the neighbor's already-resolved OWN import list. A
// single-policy list still references the standalone route-map (byte-identical),
// and FRR gets exactly ONE `route-map in`. The overridden group policy is not in
// the neighbor's list at all, so it never renders.
func TestGenerateProtocols_BGPImportMostSpecificWins(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"GROUP-IMPORT": {Name: "GROUP-IMPORT", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
			"NEIGH-IMPORT": {Name: "NEIGH-IMPORT", Terms: []*config.PolicyTerm{{Name: "t", Action: "accept"}}},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			// Compiler-resolved: the neighbor's own import replaced the group's.
			{Address: "10.0.2.1", PeerAS: 65002, Import: []string{"NEIGH-IMPORT"}},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)
	if !strings.Contains(got, "neighbor 10.0.2.1 route-map NEIGH-IMPORT in\n") {
		t.Errorf("resolved neighbor import (NEIGH-IMPORT) not applied, got:\n%s", got)
	}
	if strings.Contains(got, "route-map GROUP-IMPORT in") {
		t.Errorf("overridden group import must not render, got:\n%s", got)
	}
	if strings.Count(got, "route-map NEIGH-IMPORT in") != 1 {
		t.Errorf("expected exactly one route-map in, got:\n%s", got)
	}
}

// TestGenerateProtocols_BGPImportUndefinedNoDangling is the #2490 application
// of the #2473 lesson on the INBOUND direction. An import ref that is NOT a
// defined policy-statement (a bare token, or a name that slipped the strict
// validator on a lenient load/HA-sync path) must NEVER render a dangling
// `route-map <token> in`.
//
// #6807 CORRECTION: the original rationale — "FRR resolves an undefined
// route-map to PERMIT-ALL, silently accepting every inbound advertisement" — is
// backwards. bgp_input_modifier returns RMAP_DENY for an unresolvable name
// (stable/10.6), so the dangling in-line would DENY all inbound, and it is the
// absent attachment this guard produces that accepts everything. The guard's
// BEHAVIOUR is deliberately unchanged (that decision is #7625); only the
// claim is corrected. Do not "fix" the direction from the old sentence.
// Fail-on-revert: dropping the isDefinedPolicyStatement guard makes the
// dangling in-line appear.
func TestGenerateProtocols_BGPImportUndefinedNoDangling(t *testing.T) {
	m := New()
	// nil policyOptions: no policy-statements defined, so the import ref is
	// undefined (simulates a lenient load that bypassed strict validation).
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"undefined-policy"}},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "route-map undefined-policy in") {
		t.Errorf("LEAK: undefined import ref must not render a dangling route-map in (permit-all inbound), got:\n%s", got)
	}
}

// TestGenerateProtocols_BGPExportUndefinedNoDangling is the #2539 sibling of
// the #2490 inbound guard: the OUTBOUND render path must also skip an
// undefined per-neighbor export ref rather than emit a dangling
// `route-map <token> out`. A per-neighbor export is parseable as of #2490; on
// the lenient load/HA-sync path the strict reject is downgraded to a warning,
// so an undefined ref can reach the renderer. (#6807 CORRECTION: a dangling
// `route-map out` resolves to RMAP_DENY in FRR, not permit-all — the peer's
// routes are withdrawn, not leaked. Behaviour here is unchanged; only the
// claim is corrected.)
// Fail-on-revert: dropping the isDefinedPolicyStatement guard on the export
// emit sites makes the dangling out-line appear. Bare protocol tokens still
// take the redistribute path (the #2473 classification), so this guard only
// affects undefined policy-statement refs.
func TestGenerateProtocols_BGPExportUndefinedNoDangling(t *testing.T) {
	m := New()
	// nil policyOptions: no policy-statements defined, so the per-neighbor
	// export ref is undefined (simulates a lenient load that bypassed strict
	// validation).
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"undefined-policy"}},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "route-map undefined-policy out") {
		t.Errorf("LEAK: undefined export ref must not render a dangling route-map out (permit-all outbound), got:\n%s", got)
	}
}

// TestGenerateProtocols_OSPFExportPolicyStatement covers the #2144
// render path: an OSPF `export` that names a defined policy-statement (not
// a bare protocol token) is expanded by resolveRedistribute into one
// `redistribute <proto> route-map <name>` line per `from protocol` the
// policy matches. This is the well-formed reference whose dangling sibling
// the new commit-time validator rejects.
func TestGenerateProtocols_OSPFExportPolicyStatement(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "ge-0-0-0"}}},
		},
		Export: []string{"EXPORT-DIRECT-STATIC"},
	}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXPORT-DIRECT-STATIC": {
				Name: "EXPORT-DIRECT-STATIC",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocols: []string{"direct", "static"}, Action: "accept"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, po, nil)
	// "direct" maps to FRR "connected"; both protocols carry the route-map.
	if !strings.Contains(got, "redistribute connected route-map EXPORT-DIRECT-STATIC\n") {
		t.Errorf("missing redistribute connected route-map line, got:\n%s", got)
	}
	if !strings.Contains(got, "redistribute static route-map EXPORT-DIRECT-STATIC\n") {
		t.Errorf("missing redistribute static route-map line, got:\n%s", got)
	}
}

// TestGenerateProtocols_ExportDirectNormalized covers the #2144 render fix:
// a bare `export direct` (Junos spelling for directly-connected routes)
// must render the FRR keyword `redistribute connected`, NOT the invalid
// `redistribute direct` (which fails the frr-reload). The commit-time
// validator accepts "direct" as a known token, so render and validation
// must agree.
func TestGenerateProtocols_ExportDirectNormalized(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "ge-0-0-0"}}},
		},
		Export: []string{"direct"},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "redistribute connected\n") {
		t.Errorf("bare `export direct` must render `redistribute connected`, got:\n%s", got)
	}
	if strings.Contains(got, "redistribute direct") {
		t.Errorf("rendered the FRR-invalid `redistribute direct`, got:\n%s", got)
	}
}

func TestGenerateProtocols_ISISExport(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:    "49.0001.1921.6800.1001.00",
		Level:  "level-2",
		Export: []string{"connected"},
		Interfaces: []*config.ISISInterface{
			{Name: "trust0"},
		},
	}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
	// #9666: isisd accepts only `redistribute <ipv4|ipv6> <proto> <level>`.
	// This cell asserted the OSPF-shaped `redistribute connected`, which isisd
	// rejects and which failed the whole managed reload.
	for _, want := range []string{" redistribute ipv4 connected level-2\n", " redistribute ipv6 connected level-2\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, " redistribute connected\n") {
		t.Errorf("rendered the isisd-invalid `redistribute connected`, got:\n%s", got)
	}
}

func TestGenerateProtocols_VRF(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "2.2.2.2",
		Areas:    []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}}},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "cust-a", 0, nil, nil)
	if !strings.Contains(got, "router ospf vrf cust-a\n") {
		t.Error("missing VRF suffix in OSPF")
	}
}

func TestWriteManagedSection_Fresh(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")

	m := &Manager{frrConf: confPath}

	// Write initial frr.conf with some existing content
	os.WriteFile(confPath, []byte("log syslog informational\n"), 0644)

	if err := m.writeManagedSection("ip route 10.0.0.0/8 192.168.1.1\n"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)

	if !strings.Contains(got, markerBegin) {
		t.Error("missing begin marker")
	}
	if !strings.Contains(got, markerEnd) {
		t.Error("missing end marker")
	}
	if !strings.Contains(got, "ip route 10.0.0.0/8 192.168.1.1\n") {
		t.Error("missing route")
	}
	if !strings.Contains(got, "log syslog informational\n") {
		t.Error("existing config lost")
	}
}

func TestWriteManagedSection_Replace(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")

	m := &Manager{frrConf: confPath}

	// Write initial config with managed section
	initial := "log syslog informational\n" +
		markerBegin + "\n" +
		"ip route 10.0.0.0/8 192.168.1.1\n" +
		markerEnd + "\n"
	os.WriteFile(confPath, []byte(initial), 0644)

	if err := m.writeManagedSection("ip route 10.0.0.0/8 192.168.2.1\n"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)

	if strings.Contains(got, "192.168.1.1") {
		t.Error("old route still present")
	}
	if !strings.Contains(got, "192.168.2.1") {
		t.Error("new route missing")
	}
}

func TestWriteManagedSection_Clear(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")

	m := &Manager{frrConf: confPath}

	initial := "log syslog informational\n" +
		markerBegin + "\n" +
		"ip route 10.0.0.0/8 192.168.1.1\n" +
		markerEnd + "\n"
	os.WriteFile(confPath, []byte(initial), 0644)

	if err := m.writeManagedSection(""); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)

	if strings.Contains(got, markerBegin) {
		t.Error("managed section not removed")
	}
	if !strings.Contains(got, "log syslog") {
		t.Error("existing config lost")
	}
}

func TestWriteManagedSection_NoExistingFile(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")

	m := &Manager{frrConf: confPath}

	if err := m.writeManagedSection("ip route 10.0.0.0/8 Null0\n"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)
	if !strings.Contains(got, "log syslog informational") {
		t.Error("default log line missing when frr.conf didn't exist")
	}
	if !strings.Contains(got, "ip route 10.0.0.0/8 Null0\n") {
		t.Error("route missing")
	}
}

// TestWriteManagedSection_OrphanedBeginMarker is the #1646 regression test.
// A prior torn write (os.WriteFile is not atomic) can leave an orphaned
// markerBegin with no markerEnd. The pre-fix code skipped the strip entirely
// when markerEnd was absent, appending a SECOND managed block — and the write
// after that would over-cut from the orphan begin to the new block's end,
// deleting everything in between, including unrelated operator/tool config.
//
// The fix discards an orphaned-begin tail to EOF. After one writeManagedSection
// the file must contain exactly one managed block and must NOT carry the torn
// partial content forward into a state that a subsequent write would over-cut.
func TestWriteManagedSection_OrphanedBeginMarker(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")

	m := &Manager{frrConf: confPath}

	// Simulate a torn write: legitimate config, then an orphaned begin marker
	// with a partial managed body and NO end marker (the write was truncated).
	torn := "log syslog informational\n" +
		"ip route 192.0.2.0/24 198.51.100.1\n" + // unrelated, operator-added
		markerBegin + "\n" +
		"ip route 10.0.0.0/8 192.168.9.9\n" // partial body, no markerEnd
	if err := os.WriteFile(confPath, []byte(torn), 0644); err != nil {
		t.Fatal(err)
	}

	// First write after the torn state.
	if err := m.writeManagedSection("ip route 10.0.0.0/8 192.168.2.1\n"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)

	// Exactly one begin marker — the orphan must have been discarded, not kept.
	if n := strings.Count(got, markerBegin); n != 1 {
		t.Errorf("expected exactly 1 begin marker, got %d:\n%s", n, got)
	}
	if n := strings.Count(got, markerEnd); n != 1 {
		t.Errorf("expected exactly 1 end marker, got %d:\n%s", n, got)
	}
	// Unrelated operator config above the torn block must survive.
	if !strings.Contains(got, "ip route 192.0.2.0/24 198.51.100.1") {
		t.Errorf("unrelated operator config was lost:\n%s", got)
	}
	if !strings.Contains(got, "log syslog informational") {
		t.Errorf("base config lost:\n%s", got)
	}
	// The partial torn body must be gone.
	if strings.Contains(got, "192.168.9.9") {
		t.Errorf("orphaned partial managed body was not discarded:\n%s", got)
	}
	// The new managed route is present.
	if !strings.Contains(got, "ip route 10.0.0.0/8 192.168.2.1") {
		t.Errorf("new managed route missing:\n%s", got)
	}

	// A SECOND write must remain stable and must not over-cut the unrelated
	// config — this is the step where the pre-fix double-begin state corrupted
	// the file.
	if err := m.writeManagedSection("ip route 10.0.0.0/8 192.168.3.3\n"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(confPath)
	got = string(data)
	if !strings.Contains(got, "ip route 192.0.2.0/24 198.51.100.1") {
		t.Errorf("unrelated operator config lost on second write:\n%s", got)
	}
	if n := strings.Count(got, markerBegin); n != 1 {
		t.Errorf("second write: expected 1 begin marker, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "192.168.3.3") {
		t.Errorf("second write's route missing:\n%s", got)
	}
}

// TestWriteManagedSection_StaleEndMarkerBeforeBegin is the #2908 regression
// test (agy-review-053 053-03). A stale end-marker positioned *before* the
// live begin marker (operator hand-edit, an interleaved partial copy, or
// external tooling) used to make the unanchored strings.Index(content,
// markerEnd) return end < start. The strip content[:start] + content[end:]
// then DUPLICATED the text between end and start while leaving the live begin
// marker in place, producing two begin markers and a corrupt managed block
// that FRR reload rejects.
//
// This is distinct from #1646 (orphaned begin / missing end). The fix anchors
// the end-marker search strictly after the begin marker so end >= start always
// holds and the slice can never duplicate.
//
// FAIL-ON-REVERT: if the end-marker lookup is reverted to the from-0
// strings.Index(content, markerEnd), the stale-end case yields end < start and
// this test fails on the duplicated begin marker and corrupted body.
func TestWriteManagedSection_StaleEndMarkerBeforeBegin(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")

	m := &Manager{frrConf: confPath}

	// Construct a file where a STALE end marker appears BEFORE the live begin
	// marker, with operator config interleaved around them.
	stale := "log syslog informational\n" +
		"ip route 192.0.2.0/24 198.51.100.1\n" + // operator config, before stale end
		markerEnd + "\n" + // STALE/orphaned end marker (no preceding begin)
		"ip route 203.0.113.0/24 198.51.100.2\n" + // operator config, between markers
		markerBegin + "\n" +
		"ip route 10.0.0.0/8 192.168.9.9\n" + // current managed body
		markerEnd + "\n"
	if err := os.WriteFile(confPath, []byte(stale), 0644); err != nil {
		t.Fatal(err)
	}

	if err := m.writeManagedSection("ip route 10.0.0.0/8 192.168.2.1\n"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)

	// Exactly one begin marker. With the from-0 lookup, end < start kept the
	// live begin marker AND re-appended the duplicated tail → two begin
	// markers.
	if n := strings.Count(got, markerBegin); n != 1 {
		t.Errorf("expected exactly 1 begin marker, got %d:\n%s", n, got)
	}
	// Exactly one end marker — the stale one must be carried as inert operator
	// text (it is just a comment line outside the managed block) but the
	// managed block itself must contribute exactly one. The total end-marker
	// count is the stale one + the managed one = 2; what matters is that the
	// managed block is well formed (one begin, and an end after it).
	beginIdx := strings.Index(got, markerBegin)
	if beginIdx < 0 {
		t.Fatalf("managed begin marker missing:\n%s", got)
	}
	if !strings.Contains(got[beginIdx:], markerEnd) {
		t.Errorf("managed block has no end marker after its begin:\n%s", got)
	}
	// The new managed route is present; the old managed body is gone.
	if !strings.Contains(got, "ip route 10.0.0.0/8 192.168.2.1") {
		t.Errorf("new managed route missing:\n%s", got)
	}
	if strings.Contains(got, "192.168.9.9") {
		t.Errorf("old managed body was not replaced:\n%s", got)
	}
	// Operator config on both sides of the stale end marker must survive.
	if !strings.Contains(got, "ip route 192.0.2.0/24 198.51.100.1") {
		t.Errorf("operator config before stale end marker lost:\n%s", got)
	}
	if !strings.Contains(got, "ip route 203.0.113.0/24 198.51.100.2") {
		t.Errorf("operator config between markers lost:\n%s", got)
	}

	// A SECOND write must stay stable — exactly one begin marker, operator
	// config preserved, route updated. This is where a duplicated-begin state
	// from the first write would corrupt the file on the next over-cut.
	if err := m.writeManagedSection("ip route 10.0.0.0/8 192.168.3.3\n"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(confPath)
	got = string(data)
	if n := strings.Count(got, markerBegin); n != 1 {
		t.Errorf("second write: expected 1 begin marker, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "ip route 192.0.2.0/24 198.51.100.1") {
		t.Errorf("second write: operator config before stale end lost:\n%s", got)
	}
	if !strings.Contains(got, "192.168.3.3") {
		t.Errorf("second write's route missing:\n%s", got)
	}
}

// TestWriteManagedSection_PreservesExistingMode guards the Copilot finding on
// #1646: the atomic temp-file + rename write replaces the inode, so it must
// reuse the existing file's mode rather than unconditionally applying 0644.
// frr.conf is commonly deployed 0640; making it world-readable on the next
// apply would be a permission regression vs the old os.WriteFile path (which
// preserved the mode of an existing file).
func TestWriteManagedSection_PreservesExistingMode(t *testing.T) {
	// Force the "frr group absent" path so the fresh-file write below does not
	// attempt a (non-root) fchown to the frr gid (#4484 L-6); the 0640 mode is
	// enforced regardless of the owner override.
	restore := resolveFRRGroup
	resolveFRRGroup = func() (int, bool) { return 0, false }
	t.Cleanup(func() { resolveFRRGroup = restore })

	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")

	m := &Manager{frrConf: confPath}

	initial := "log syslog informational\n"
	if err := os.WriteFile(confPath, []byte(initial), 0640); err != nil {
		t.Fatal(err)
	}
	// Chmod explicitly in case the umask masked bits at create time.
	if err := os.Chmod(confPath, 0640); err != nil {
		t.Fatal(err)
	}

	if err := m.writeManagedSection("ip route 10.0.0.0/8 192.168.1.1\n"); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0640 {
		t.Errorf("mode not preserved across atomic write: got %o, want 0640", got)
	}

	// A brand-new file (no existing target) is created 0640, NOT the old
	// world-readable 0644: the managed section carries routing-auth secrets
	// (BGP TCP-MD5, OSPF/IS-IS/RIP keys), so a fresh frr.conf must not be
	// world-readable (#4484 L-6). On a real appliance the fresh file is also
	// owned root:frr (WithOwner) so the frr daemons can still read it; here the
	// group is forced absent, leaving it 0640 root:root.
	freshPath := filepath.Join(dir, "fresh.conf")
	mf := &Manager{frrConf: freshPath}
	if err := mf.writeManagedSection("ip route 10.0.0.0/8 Null0\n"); err != nil {
		t.Fatal(err)
	}
	fi, err = os.Stat(freshPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0640 {
		t.Errorf("new file mode: got %o, want 0640 (0644 is world-readable, #4484 L-6)", got)
	}
}

// TestWriteManagedSection_PreservesSymlink guards the AGY adversarial-review
// finding on #1646: the old os.WriteFile path followed a symlink and wrote
// through to its target, whereas a naive rename onto the link path would
// destroy the link and leave a regular file. xpfd is sometimes pointed at
// /etc/frr/frr.conf via a symlink; the atomic write must resolve and preserve
// it.
func TestWriteManagedSection_PreservesSymlink(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real-frr.conf")
	linkPath := filepath.Join(dir, "frr.conf")

	if err := os.WriteFile(realPath, []byte("log syslog informational\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}

	m := &Manager{frrConf: linkPath}
	if err := m.writeManagedSection("ip route 10.0.0.0/8 192.168.1.1\n"); err != nil {
		t.Fatal(err)
	}

	// frr.conf must still be a symlink pointing at the real file.
	fi, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink was replaced by a regular file")
	}
	// The managed section must have landed in the real target, through the link.
	data, err := os.ReadFile(realPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "192.168.1.1") {
		t.Errorf("write did not reach the symlink target:\n%s", string(data))
	}
	if !strings.Contains(string(data), "log syslog informational") {
		t.Errorf("existing content in symlink target lost:\n%s", string(data))
	}
	// Mode of the real target preserved.
	rfi, err := os.Stat(realPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := rfi.Mode().Perm(); got != 0640 {
		t.Errorf("symlink target mode not preserved: got %o, want 0640", got)
	}
}

// TestWriteManagedSection_DanglingSymlink covers the Copilot round-2 finding:
// when frr.conf is a symlink whose target does not exist yet, EvalSymlinks
// fails; os.WriteFile would still follow the link and create the target, so
// the atomic write must Readlink and write through the link rather than
// replacing it with a regular file.
func TestWriteManagedSection_DanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "real-frr.conf") // does NOT exist yet
	linkPath := filepath.Join(dir, "frr.conf")

	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatal(err)
	}

	m := &Manager{frrConf: linkPath}
	if err := m.writeManagedSection("ip route 10.0.0.0/8 192.168.1.1\n"); err != nil {
		t.Fatal(err)
	}

	// The link must survive and now resolve to a created target.
	fi, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("dangling symlink was replaced by a regular file")
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("symlink target was not created: %v", err)
	}
	if !strings.Contains(string(data), "192.168.1.1") {
		t.Errorf("write did not reach the dangling-symlink target:\n%s", string(data))
	}
}

func TestGeneratePolicyOptions(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"mgmt": {
				Name:     "mgmt",
				Prefixes: []string{"10.0.0.0/8", "172.16.0.0/12"},
			},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"export-connected": {
				Name: "export-connected",
				Terms: []*config.PolicyTerm{
					{
						Name:          "t1",
						FromProtocols: []string{"direct"},
						RouteFilters: []*config.RouteFilter{
							{Prefix: "10.0.0.0/8", MatchType: "exact"},
						},
						Action: "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	checks := []string{
		"ip prefix-list mgmt seq 5 permit 10.0.0.0/8",
		"ip prefix-list mgmt seq 10 permit 172.16.0.0/12",
		"route-map export-connected permit 10",
		"match source-protocol connected",
		"route-map export-connected deny 20",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// TestGeneratePolicyOptionsMultiProtocol verifies that a term matching
// multiple protocols ("from protocol [ bgp ospf static ]") renders a
// "match source-protocol" line for EVERY protocol. Regression for #2008
// H18 — the old single-FromProtocol render emitted only one match line, so
// a multi-protocol policy silently matched only the first protocol.
func TestGeneratePolicyOptionsMultiProtocol(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXPORT-ALL": {
				Name: "EXPORT-ALL",
				Terms: []*config.PolicyTerm{
					{
						Name:          "t1",
						FromProtocols: []string{"bgp", "ospf", "direct"},
						Action:        "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	// "direct" maps to FRR "connected"; all three must render.
	checks := []string{
		"route-map EXPORT-ALL permit 10",
		"match source-protocol bgp",
		"match source-protocol ospf",
		"match source-protocol connected",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// Sanity: exactly three match lines (no extra, none dropped).
	if n := strings.Count(got, "match source-protocol "); n != 3 {
		t.Errorf("got %d match source-protocol lines, want 3:\n%s", n, got)
	}
}

func TestGeneratePolicyOptionsRouteMapAttributes(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"SET-ATTRS": {
				Name: "SET-ATTRS",
				Terms: []*config.PolicyTerm{
					{
						Name:               "t1",
						FromProtocols:      []string{"bgp"},
						Action:             "accept",
						LocalPreference:    200,
						HasLocalPreference: true,
						Metric:             100,
						HasMetric:          true,
						Community:          "65000:100",
						Origin:             "igp",
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	checks := []string{
		"route-map SET-ATTRS permit 10",
		"match source-protocol bgp",
		"set local-preference 200",
		"set metric 100",
		"set community 65000:100",
		"set origin igp",
		"route-map SET-ATTRS deny 20",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestBGPAddressFamily(t *testing.T) {
	m := New()

	// to_BV-FIREHOUSE must be a DEFINED policy-statement so the export
	// route-map out is emitted: an undefined ref is now skipped to avoid a
	// dangling permit-all route-map (#2539, sibling of the #2490 import guard).
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"to_BV-FIREHOUSE": {
				Name:  "to_BV-FIREHOUSE",
				Terms: []*config.PolicyTerm{{Name: "t1", Action: "accept"}},
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS: 64701,
		Neighbors: []*config.BGPNeighbor{
			{
				Address:     "192.168.255.1",
				PeerAS:      65909,
				FamilyInet:  true,
				FamilyInet6: true,
				Export:      []string{"to_BV-FIREHOUSE"},
			},
			{
				Address:    "10.0.0.2",
				PeerAS:     65002,
				FamilyInet: true,
			},
		},
	}

	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)

	checks := []string{
		"router bgp 64701",
		"neighbor 192.168.255.1 remote-as 65909",
		"neighbor 10.0.0.2 remote-as 65002",
		"address-family ipv4 unicast",
		"neighbor 192.168.255.1 activate",
		"neighbor 192.168.255.1 route-map to_BV-FIREHOUSE out",
		"neighbor 10.0.0.2 activate",
		"exit-address-family",
		"address-family ipv6 unicast",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}

	// Neighbor 10.0.0.2 should NOT be in ipv6 address-family
	lines := strings.Split(got, "\n")
	inIPv6 := false
	for _, line := range lines {
		if strings.Contains(line, "address-family ipv6") {
			inIPv6 = true
		}
		if strings.Contains(line, "exit-address-family") {
			inIPv6 = false
		}
		if inIPv6 && strings.Contains(line, "10.0.0.2") {
			t.Error("10.0.0.2 should not be in ipv6 address-family")
		}
	}
}

// TestBGPDualStackGroupActivatesByAddressVersion is the end-to-end fail-on-
// revert guard for #2454: a dual-stack BGP group (family inet AND inet6) with
// one IPv4 and one IPv6 neighbor, compiled from config then rendered to FRR,
// must activate the IPv4 neighbor ONLY under address-family ipv4 unicast and
// the IPv6 neighbor ONLY under ipv6 unicast. Before the compiler address-
// version gate, the IPv4 neighbor was activated under ipv6 unicast too —
// invalid without RFC 5549 extended-nexthop, which breaks AF activation.
func TestBGPDualStackGroupActivatesByAddressVersion(t *testing.T) {
	tree := &config.ConfigTree{}
	setCommands := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group dual peer-as 65002",
		"set protocols bgp group dual family inet unicast",
		"set protocols bgp group dual family inet6 unicast",
		"set protocols bgp group dual neighbor 10.0.0.2",
		"set protocols bgp group dual neighbor 2001:db8::2",
	}
	for _, cmd := range setCommands {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	m := New()
	got := m.generateProtocols(nil, nil, cfg.Protocols.BGP, nil, nil, "", 0, nil, nil)

	// Walk the rendered output tracking which address-family block each
	// `activate` line falls in.
	var af string
	sawV4inV4, sawV6inV6, v4inV6, v6inV4 := false, false, false, false
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "address-family ipv4"):
			af = "v4"
		case strings.HasPrefix(trimmed, "address-family ipv6"):
			af = "v6"
		case trimmed == "exit-address-family":
			af = ""
		}
		if !strings.HasSuffix(trimmed, " activate") {
			continue
		}
		switch {
		case strings.Contains(trimmed, "10.0.0.2"):
			if af == "v4" {
				sawV4inV4 = true
			}
			if af == "v6" {
				v4inV6 = true
			}
		case strings.Contains(trimmed, "2001:db8::2"):
			if af == "v6" {
				sawV6inV6 = true
			}
			if af == "v4" {
				v6inV4 = true
			}
		}
	}

	if !sawV4inV4 {
		t.Error("IPv4 neighbor 10.0.0.2 must be activated under address-family ipv4 unicast")
	}
	if !sawV6inV6 {
		t.Error("IPv6 neighbor 2001:db8::2 must be activated under address-family ipv6 unicast")
	}
	if v4inV6 {
		t.Errorf("#2454: IPv4 neighbor 10.0.0.2 must NOT be activated under address-family ipv6 unicast\n%s", got)
	}
	if v6inV4 {
		t.Errorf("IPv6 neighbor 2001:db8::2 must NOT be activated under address-family ipv4 unicast\n%s", got)
	}
}

// TestPolicyCommunityOperations is the end-to-end fail-on-revert guard for
// #2848: a policy term with `then community add <v>` must render
// `set community <v> additive`, `then community delete <name>` must render
// `set comm-list <name> delete`, `then community set <v>` (and the legacy bare
// `then community <v>`) must render the whole-attribute replace
// `set community <v>`, and `then community none` must render
// `set community none`. Before the operation support, every form collapsed onto
// the replace clause (`set community <v>`), which wiped upstream-set communities
// — a vSRX parity gap. RED if the operation handling is reverted (the compiler
// would drop the op fields, or the renderer would emit `set community` for all
// forms).
//
// Driven through the full ParseSetCommand + SetPath + CompileConfig +
// generatePolicyOptions path so the schema (multi-value `then community` leaf),
// the compiler (applyCommunityAction), and the FRR renderer are all exercised.
func TestPolicyCommunityOperations(t *testing.T) {
	tree := &config.ConfigTree{}
	setCommands := []string{
		// The `then community delete <name>` form references a defined
		// community-list (#2881 cross-reference gate); define it.
		"set policy-options community MYLIST members 65000:999",
		// add → additive append
		"set policy-options policy-statement P term t_add from protocol bgp",
		"set policy-options policy-statement P term t_add then community add 65000:111",
		// delete → comm-list delete (by community-list name)
		"set policy-options policy-statement P term t_del from protocol bgp",
		"set policy-options policy-statement P term t_del then community delete MYLIST",
		// set → whole-attribute replace
		"set policy-options policy-statement P term t_set from protocol bgp",
		"set policy-options policy-statement P term t_set then community set 65000:222",
		// bare → legacy replace form
		"set policy-options policy-statement P term t_bare from protocol bgp",
		"set policy-options policy-statement P term t_bare then community 65000:333",
		// none → strip all
		"set policy-options policy-statement P term t_none from protocol bgp",
		"set policy-options policy-statement P term t_none then community none",
		// terminating term so the policy is not all fall-through
		"set policy-options policy-statement P term t_end then accept",
	}
	for _, cmd := range setCommands {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	m := New()
	got := m.generatePolicyOptions(&cfg.PolicyOptions)

	checks := []struct {
		desc string
		want string
	}{
		{"add → additive append", " set community 65000:111 additive\n"},
		{"delete → comm-list delete", " set comm-list MYLIST delete\n"},
		{"set → whole-attribute replace", " set community 65000:222\n"},
		{"bare → legacy replace form", " set community 65000:333\n"},
		{"none → strip all", " set community none\n"},
	}
	for _, c := range checks {
		if !strings.Contains(got, c.want) {
			t.Errorf("#2848 %s: missing %q in:\n%s", c.desc, c.want, got)
		}
	}

	// The `add` clause must NOT degrade to a plain replace (the revert
	// behavior): `set community 65000:111` WITHOUT the `additive` suffix would
	// overwrite upstream communities.
	if strings.Contains(got, " set community 65000:111\n") {
		t.Errorf("#2848 add operation rendered as a plain replace (missing `additive`):\n%s", got)
	}
	// The `delete` clause must NOT render as a `set community` replace.
	if strings.Contains(got, " set community MYLIST") {
		t.Errorf("#2848 delete operation rendered as `set community` instead of `set comm-list ... delete`:\n%s", got)
	}
}

// TestPolicyCommunityDeleteMultiList is the fail-on-revert guard for #2902: a
// `then community delete [ listA listB ]` clause references MULTIPLE
// community-lists, and FRR's `set comm-list <name> delete` strips ONE list per
// line — so EVERY referenced list must render its own clause. The pre-#2902
// compiler stored only vals[1] (`CommunityDelete = vals[1]`), so listB and any
// further lists were silently dropped and the communities the operator meant to
// strip leaked into advertised prefixes. RED if the compiler reads only the
// first list value (only listA emitted) or the renderer emits a single clause.
//
// Driven through the full ParseSetCommand + SetPath + CompileConfig +
// generatePolicyOptions path so the schema (multi-value `then community` leaf),
// the compiler (applyCommunityAction accumulating vals[1:]), and the FRR
// renderer (one clause per list) are all exercised.
func TestPolicyCommunityDeleteMultiList(t *testing.T) {
	tree := &config.ConfigTree{}
	setCommands := []string{
		// The referenced community-lists must be defined (#2881 gate).
		"set policy-options community listA members 65000:1",
		"set policy-options community listB members 65000:2",
		"set policy-options community listC members 65000:3",
		"set policy-options policy-statement P term t_del from protocol bgp",
		// Bracketed multi-list: the lexer strips the brackets, so this
		// flattens to delete + [listA listB listC] (the #2419 multi-value
		// shape). All three must render.
		"set policy-options policy-statement P term t_del then community delete [ listA listB listC ]",
		"set policy-options policy-statement P term t_end then accept",
	}
	for _, cmd := range setCommands {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	m := New()
	got := m.generatePolicyOptions(&cfg.PolicyOptions)

	for _, name := range []string{"listA", "listB", "listC"} {
		want := " set comm-list " + name + " delete\n"
		if !strings.Contains(got, want) {
			t.Errorf("#2902 multi-list delete: missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_ECMPMaxPaths(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true},
		},
	}
	// Global ECMP (forwarding-table export) must NOT enable BGP multipath:
	// without an explicit `protocols bgp multipath`, the BGP address-
	// families render no `maximum-paths` even when ecmpMaxPaths > 1 (#2791).
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 64, nil, nil)
	if strings.Contains(got, "maximum-paths") {
		t.Errorf("global ECMP must not emit BGP maximum-paths, got:\n%s", got)
	}

	// Also test OSPF ECMP
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}},
		},
	}
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "", 64, nil, nil)
	if !strings.Contains(got, "maximum-paths 64") {
		t.Errorf("missing maximum-paths in OSPF, got:\n%s", got)
	}

	// Without ECMP
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "maximum-paths") {
		t.Errorf("should not have maximum-paths when ecmp=0, got:\n%s", got)
	}
}

// TestGenerateProtocols_OSPFv3ECMPMaxPaths is a fail-on-revert guard for
// #2997: the "router ospf6" block must emit "maximum-paths <N>" when global
// forwarding-table ECMP is enabled (ecmpMaxPaths > 1), mirroring the OSPFv4
// "router ospf" block. Before the fix the ospf6 block omitted the line, so
// IPv6 OSPF ECMP was never installed even when configured. Reverting the
// render line in policy_render.go turns this test RED.
func TestGenerateProtocols_OSPFv3ECMPMaxPaths(t *testing.T) {
	m := New()
	ospfv3 := &config.OSPFv3Config{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFv3Area{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFv3Interface{{Name: "trust0"}}},
		},
	}

	// Global ECMP set: the router ospf6 block must render maximum-paths.
	got := m.generateProtocols(nil, ospfv3, nil, nil, nil, "", 64, nil, nil)
	if !strings.Contains(got, "router ospf6") {
		t.Fatalf("expected router ospf6 block, got:\n%s", got)
	}
	if !strings.Contains(got, "maximum-paths 64") {
		t.Errorf("#2997: missing maximum-paths in router ospf6 block, got:\n%s", got)
	}

	// No ECMP (ecmpMaxPaths=0): no maximum-paths line.
	got = m.generateProtocols(nil, ospfv3, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "maximum-paths") {
		t.Errorf("#2997: should not emit maximum-paths in ospf6 when ecmp=0, got:\n%s", got)
	}

	// ecmpMaxPaths=1 is single-path: no maximum-paths line.
	got = m.generateProtocols(nil, ospfv3, nil, nil, nil, "", 1, nil, nil)
	if strings.Contains(got, "maximum-paths") {
		t.Errorf("#2997: should not emit maximum-paths in ospf6 when ecmp=1, got:\n%s", got)
	}
}

func TestApplyFull_BackupRouter(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")
	os.WriteFile(confPath, []byte("log syslog informational\n"), 0644)

	m := &Manager{frrConf: confPath}
	fc := &FullConfig{
		BackupRouter:    "192.168.50.1",
		BackupRouterDst: "0.0.0.0/0",
	}

	// ApplyFull calls reload which fails in test, so just test writeManagedSection.
	// Build the same string that ApplyFull would.
	var b strings.Builder
	b.WriteString("! xpf managed config - do not edit\n!\n")
	dst := fc.BackupRouterDst
	if dst == "" {
		dst = "0.0.0.0/0"
	}
	b.WriteString("ip route " + dst + " " + fc.BackupRouter + " 250\n!\n")

	if err := m.writeManagedSection(b.String()); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)
	want := "ip route 0.0.0.0/0 192.168.50.1 250"
	if !strings.Contains(got, want) {
		t.Errorf("backup router missing, got:\n%s\nwant substring: %s", got, want)
	}
}

func TestFRRMultiVRF(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")
	os.WriteFile(confPath, []byte("log syslog informational\n"), 0644)

	m := &Manager{frrConf: confPath}

	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{
			{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
		},
		Instances: []InstanceConfig{
			{
				VRFName: "vrf-tunnel-vr",
				StaticRoutes: []*config.StaticRoute{
					{Destination: "10.0.50.0/24", NextHops: []config.NextHopEntry{{Address: "10.0.40.1"}}},
				},
			},
			{
				VRFName: "vrf-dmz-vr",
				StaticRoutes: []*config.StaticRoute{
					{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "10.0.30.1"}}},
				},
				OSPF: &config.OSPFConfig{
					RouterID: "3.3.3.3",
					Areas: []*config.OSPFArea{
						{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "dmz0"}}},
					},
				},
			},
		},
	}

	// Build the section that ApplyFull would generate (without calling reload)
	var b strings.Builder
	b.WriteString("! xpf managed config - do not edit\n!\n")
	for _, sr := range fc.StaticRoutes {
		b.WriteString(m.generateStaticRoute(sr, "", nil, nil))
	}
	b.WriteString("!\n")
	for _, inst := range fc.Instances {
		if len(inst.StaticRoutes) > 0 {
			for _, sr := range inst.StaticRoutes {
				b.WriteString(m.generateStaticRoute(sr, inst.VRFName, nil, nil))
			}
			b.WriteString("!\n")
		}
	}
	for _, inst := range fc.Instances {
		if inst.OSPF != nil || inst.BGP != nil || inst.RIP != nil || inst.ISIS != nil {
			b.WriteString(m.generateProtocols(inst.OSPF, inst.OSPFv3, inst.BGP, inst.RIP, inst.ISIS, inst.VRFName, 0, nil, nil))
		}
	}

	if err := m.writeManagedSection(b.String()); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(confPath)
	got := string(data)

	// Verify global static route
	if !strings.Contains(got, "ip route 0.0.0.0/0 172.16.50.1\n") {
		t.Error("missing global default route")
	}

	// Verify per-VRF static routes
	if !strings.Contains(got, "ip route 10.0.50.0/24 10.0.40.1 vrf vrf-tunnel-vr\n") {
		t.Errorf("missing tunnel-vr static route, got:\n%s", got)
	}
	if !strings.Contains(got, "ip route 0.0.0.0/0 10.0.30.1 vrf vrf-dmz-vr\n") {
		t.Errorf("missing dmz-vr static route, got:\n%s", got)
	}

	// Verify per-VRF OSPF
	if !strings.Contains(got, "router ospf vrf vrf-dmz-vr\n") {
		t.Errorf("missing VRF OSPF block, got:\n%s", got)
	}
	if !strings.Contains(got, "ospf router-id 3.3.3.3\n") {
		t.Errorf("missing OSPF router-id, got:\n%s", got)
	}
}

func TestFRRForwardingInstance(t *testing.T) {
	m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf")}
	os.WriteFile(m.frrConf, []byte("log syslog informational\n"), 0644)

	fc := &FullConfig{
		Instances: []InstanceConfig{
			{
				VRFName: "", // forwarding instance — no VRF, default table
				StaticRoutes: []*config.StaticRoute{
					{Destination: "10.99.0.0/16", NextHops: []config.NextHopEntry{{Address: "10.0.40.1"}}},
				},
			},
			{
				VRFName: "vrf-normal-vr",
				StaticRoutes: []*config.StaticRoute{
					{Destination: "192.168.0.0/16", NextHops: []config.NextHopEntry{{Address: "10.0.1.1"}}},
				},
			},
		},
	}

	var b strings.Builder
	for _, inst := range fc.Instances {
		for _, sr := range inst.StaticRoutes {
			b.WriteString(m.generateStaticRoute(sr, inst.VRFName, nil, nil))
		}
	}
	got := b.String()

	// Forwarding instance route should NOT have vrf suffix
	if !strings.Contains(got, "ip route 10.99.0.0/16 10.0.40.1\n") {
		t.Errorf("forwarding instance route should be in default table, got:\n%s", got)
	}
	// Normal VRF route should have vrf suffix
	if !strings.Contains(got, "ip route 192.168.0.0/16 10.0.1.1 vrf vrf-normal-vr\n") {
		t.Errorf("VRF route should have vrf suffix, got:\n%s", got)
	}
}

func TestApplyFull_BackupRouterWithPrefix(t *testing.T) {
	fc := &FullConfig{
		BackupRouter:    "10.0.1.1",
		BackupRouterDst: "192.168.0.0/16",
	}

	var b strings.Builder
	if fc.BackupRouter != "" {
		dst := fc.BackupRouterDst
		if dst == "" {
			dst = "0.0.0.0/0"
		}
		prefix := "ip"
		if strings.Contains(dst, ":") {
			prefix = "ipv6"
		}
		b.WriteString(prefix + " route " + dst + " " + fc.BackupRouter + " 250\n")
	}

	got := b.String()
	want := "ip route 192.168.0.0/16 10.0.1.1 250\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestBackupRouterFamilyAwareDefault is the fail-on-revert guard for #2891.
//
// An IPv6 backup-router with no explicit destination must default its route
// prefix to ::/0 and emit `ipv6 route ::/0 <v6nh>` — NOT `ip route 0.0.0.0/0
// <v6nh>` (a v4 prefix with a v6 next-hop, which frr-reload rejects and which
// fails the entire static config load). A v4 backup-router with no explicit
// destination must still default to 0.0.0.0/0 and emit `ip route 0.0.0.0/0
// <v4nh>`.
//
// Driven through the full ParseSetCommand + SetPath + CompileConfig path so the
// compiler (compiler_system.go backup-router handling) and the FRR renderer
// (renderBackupRouter) are both exercised. Reverting the family-aware default
// in renderBackupRouter turns the v6 case red.
func TestBackupRouterFamilyAwareDefault(t *testing.T) {
	tests := []struct {
		name    string
		setCmd  string
		want    string
		notWant string
	}{
		{
			name:    "v6 backup-router empty dst defaults to ::/0",
			setCmd:  "set system backup-router 2001:db8::1",
			want:    "ipv6 route ::/0 2001:db8::1 250\n",
			notWant: "ip route 0.0.0.0/0 2001:db8::1 250\n",
		},
		{
			name:    "v4 backup-router empty dst defaults to 0.0.0.0/0",
			setCmd:  "set system backup-router 192.168.50.1",
			want:    "ip route 0.0.0.0/0 192.168.50.1 250\n",
			notWant: "ipv6 route ::/0 192.168.50.1 250\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree := &config.ConfigTree{}
			path, err := config.ParseSetCommand(tc.setCmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", tc.setCmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", tc.setCmd, err)
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}

			fc := &FullConfig{
				BackupRouter:    cfg.System.BackupRouter,
				BackupRouterDst: cfg.System.BackupRouterDst,
			}
			var b strings.Builder
			renderBackupRouter(&b, fc)
			got := b.String()

			if !strings.Contains(got, tc.want) {
				t.Errorf("#2891 %s: missing %q in:\n%s", tc.name, tc.want, got)
			}
			if strings.Contains(got, tc.notWant) {
				t.Errorf("#2891 %s: must NOT emit %q (mismatched prefix/next-hop family):\n%s", tc.name, tc.notWant, got)
			}
		})
	}
}

func TestGenerateStaticRoute_QualifiedNextHopLinkLocal(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "::/0",
		NextHops: []config.NextHopEntry{
			{Address: "fe80::2d0:f6ff:feda:c180", Interface: "wan0.0"},
		},
	}
	got := m.generateStaticRoute(sr, "ATT", nil, nil)
	want := "ipv6 route ::/0 fe80::2d0:f6ff:feda:c180 wan0 vrf ATT\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_UnitSuffixStripped(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops:    []config.NextHopEntry{{Interface: "tunnel0.0"}},
	}
	got := m.generateStaticRoute(sr, "", nil, nil)
	want := "ip route 10.0.0.0/8 tunnel0\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_NoUnitNoStrip(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "2001:db8::/32",
		NextHops:    []config.NextHopEntry{{Address: "fe80::1", Interface: "trust0"}},
	}
	got := m.generateStaticRoute(sr, "", nil, nil)
	want := "ipv6 route 2001:db8::/32 fe80::1 trust0\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_VLANSuffixNotStripped(t *testing.T) {
	m := New()
	sr := &config.StaticRoute{
		Destination: "::/0",
		NextHops:    []config.NextHopEntry{{Address: "fe80::50", Interface: "wan0.50"}},
	}
	got := m.generateStaticRoute(sr, "", nil, nil)
	// VLAN sub-interface "wan0.50" must NOT be stripped — it's a real kernel name
	want := "ipv6 route ::/0 fe80::50 wan0.50\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_RethResolution(t *testing.T) {
	m := New()
	// RethToPhysical() returns Junos names — LinuxIfName is applied inside
	rethMap := map[string]string{"reth0": "ge-0/0/1"}

	// RETH with VLAN sub-interface
	sr := &config.StaticRoute{
		Destination: "::/0",
		NextHops:    []config.NextHopEntry{{Address: "fe80::50", Interface: "reth0.50"}},
	}
	got := m.generateStaticRoute(sr, "", rethMap, nil)
	want := "ipv6 route ::/0 fe80::50 ge-0-0-1.50\n"
	if got != want {
		t.Errorf("reth VLAN: got %q, want %q", got, want)
	}

	// RETH without sub-interface
	sr2 := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops:    []config.NextHopEntry{{Interface: "reth0"}},
	}
	got2 := m.generateStaticRoute(sr2, "", rethMap, nil)
	want2 := "ip route 10.0.0.0/8 ge-0-0-1\n"
	if got2 != want2 {
		t.Errorf("reth bare: got %q, want %q", got2, want2)
	}

	// Non-RETH interface unchanged
	sr3 := &config.StaticRoute{
		Destination: "10.0.0.0/8",
		NextHops:    []config.NextHopEntry{{Interface: "trust0"}},
	}
	got3 := m.generateStaticRoute(sr3, "", rethMap, nil)
	want3 := "ip route 10.0.0.0/8 trust0\n"
	if got3 != want3 {
		t.Errorf("non-reth: got %q, want %q", got3, want3)
	}
}

func TestGenerateStaticRoute_InferredIPv6NextHopInterface(t *testing.T) {
	m := New()
	rethMap := map[string]string{"reth0": "ge-0/0/2"}
	sr := &config.StaticRoute{
		Destination: "::/0",
		NextHops: []config.NextHopEntry{
			{Address: "2001:559:8585:50::1"},
		},
	}
	got := m.generateStaticRoute(sr, "", rethMap, map[string]map[string]string{
		"": {"2001:559:8585:50::1": "reth0.50"},
	})
	want := "ipv6 route ::/0 2001:559:8585:50::1 ge-0-0-2.50\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerateStaticRoute_InferredIPv6NextHopInterfaceByVRF(t *testing.T) {
	m := New()
	rethMap := map[string]string{"reth0": "ge-0/0/2", "reth1": "ge-0/0/3"}
	sr := &config.StaticRoute{
		Destination: "2001:db8:ffff::/48",
		NextHops: []config.NextHopEntry{
			{Address: "2001:db8:1::100"},
		},
	}
	got := m.generateStaticRoute(sr, "vrf-BLUE", rethMap, map[string]map[string]string{
		"":         {"2001:db8:1::100": "reth0.10"},
		"vrf-BLUE": {"2001:db8:1::100": "reth1.20"},
	})
	want := "ipv6 route 2001:db8:ffff::/48 2001:db8:1::100 ge-0-0-3.20 vrf vrf-BLUE\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestApplyFull_ConsistentHash(t *testing.T) {
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	os.WriteFile(m.frrConf, []byte(""), 0644)

	fc := &FullConfig{
		ForwardingTableExport: "lb-policy",
		PolicyOptions: &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{
				"lb-policy": {
					Name: "lb-policy",
					Terms: []*config.PolicyTerm{
						{LoadBalance: "consistent-hash", Action: "accept"},
					},
				},
			},
		},
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
		},
	}
	// ApplyFull will fail (no FRR), but fc.ConsistentHash should be set.
	_ = m.ApplyFull(fc)
	if !fc.ConsistentHash {
		t.Error("ConsistentHash should be true with load-balance consistent-hash")
	}
}

func TestApplyFull_PerPacketNotConsistent(t *testing.T) {
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	os.WriteFile(m.frrConf, []byte(""), 0644)

	fc := &FullConfig{
		ForwardingTableExport: "lb-policy",
		PolicyOptions: &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{
				"lb-policy": {
					Name: "lb-policy",
					Terms: []*config.PolicyTerm{
						{LoadBalance: "per-packet", Action: "accept"},
					},
				},
			},
		},
	}
	_ = m.ApplyFull(fc)
	if fc.ConsistentHash {
		t.Error("ConsistentHash should be false with load-balance per-packet")
	}
}

func TestParseRouteJSON(t *testing.T) {
	input := `{
		"10.0.1.0/24": [{
			"prefix": "10.0.1.0/24",
			"protocol": "connected",
			"selected": true,
			"installed": true,
			"distance": 0,
			"metric": 0,
			"uptime": "2d05h30m",
			"table": 254,
			"nexthops": [{
				"directlyConnected": true,
				"interfaceName": "trust0",
				"active": true,
				"fib": true
			}]
		}],
		"0.0.0.0/0": [{
			"prefix": "0.0.0.0/0",
			"protocol": "static",
			"selected": true,
			"installed": true,
			"distance": 5,
			"metric": 0,
			"uptime": "01:02:20",
			"table": 254,
			"nexthops": [{
				"ip": "172.16.50.1",
				"interfaceName": "wan0.50",
				"active": true,
				"fib": true
			}]
		}]
	}`

	routes, err := parseRouteJSON(input)
	if err != nil {
		t.Fatal(err)
	}

	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}

	// Routes should be sorted by prefix (0.0.0.0/0 before 10.0.1.0/24)
	if routes[0].Prefix != "0.0.0.0/0" {
		t.Errorf("expected first route 0.0.0.0/0, got %s", routes[0].Prefix)
	}
	if routes[0].Protocol != "static" {
		t.Errorf("expected protocol static, got %s", routes[0].Protocol)
	}
	if routes[0].Distance != 5 {
		t.Errorf("expected distance 5, got %d", routes[0].Distance)
	}
	if len(routes[0].NextHops) != 1 || routes[0].NextHops[0].IP != "172.16.50.1" {
		t.Errorf("expected next-hop 172.16.50.1")
	}

	if routes[1].Prefix != "10.0.1.0/24" {
		t.Errorf("expected second route 10.0.1.0/24, got %s", routes[1].Prefix)
	}
	if !routes[1].NextHops[0].DirectlyConnected {
		t.Error("expected directly connected")
	}
}

func TestFormatRouteDetail(t *testing.T) {
	routes := []FRRRouteDetail{
		{
			Prefix:    "0.0.0.0/0",
			Protocol:  "static",
			Selected:  true,
			Installed: true,
			Distance:  5,
			Metric:    0,
			Uptime:    "01:02:20",
			NextHops: []FRRNextHop{
				{IP: "172.16.50.1", Interface: "wan0.50", Active: true, FIB: true},
			},
		},
		{
			Prefix:    "10.0.1.0/24",
			Protocol:  "connected",
			Selected:  true,
			Installed: true,
			Distance:  0,
			NextHops: []FRRNextHop{
				{DirectlyConnected: true, Interface: "trust0", Active: true, FIB: true},
			},
		},
	}

	got := FormatRouteDetail(routes)

	checks := []string{
		"* 0.0.0.0/0",
		"Protocol: static",
		"Preference: 5/0",
		"Age: 01:02:20",
		"Next-hop: 172.16.50.1 via wan0.50",
		"* 10.0.1.0/24",
		"Protocol: connected",
		"Next-hop: directly connected via trust0",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_OSPFMD5Auth(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", AuthType: "md5", AuthKey: "secret123", AuthKeyID: 5},
					{Name: "dmz0", AuthType: "simple", AuthKey: "plainpw"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)

	checks := []string{
		"interface trust0\n",
		"ip ospf authentication message-digest\n",
		"ip ospf message-digest-key 5 md5 secret123\n",
		"interface dmz0\n",
		"ip ospf authentication\n",
		"ip ospf authentication-key plainpw\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_OSPFMD5AuthDefaultKeyID(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", AuthType: "md5", AuthKey: "key1"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "message-digest-key 1 md5 key1") {
		t.Errorf("default key-id should be 1, got:\n%s", got)
	}
}

func TestGenerateProtocols_BGPPassword(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, AuthPassword: "bgpSecret"},
			{Address: "10.0.3.1", PeerAS: 65003},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "neighbor 10.0.2.1 password bgpSecret\n") {
		t.Errorf("missing BGP password, got:\n%s", got)
	}
	if strings.Contains(got, "neighbor 10.0.3.1 password") {
		t.Error("neighbor without auth should not have password line")
	}
}

func TestGenerateProtocols_OSPFBFD(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", BFD: true},
					{Name: "dmz0"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "ip ospf bfd\n") {
		t.Errorf("missing OSPF BFD, got:\n%s", got)
	}
}

func TestGenerateProtocols_BGPBFD(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, BFD: true, BFDInterval: 100},
			{Address: "10.0.3.1", PeerAS: 65003},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)

	checks := []string{
		"neighbor 10.0.2.1 bfd\n",
		"bfd\n",
		"peer 10.0.2.1\n",
		"detect-multiplier 3\n",
		"receive-interval 100\n",
		"transmit-interval 100\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "neighbor 10.0.3.1 bfd") {
		t.Error("neighbor without BFD should not have bfd line")
	}
}

func TestGenerateProtocols_OSPFStubArea(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID:       "0.0.0.1",
				AreaType: "stub",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "area 0.0.0.1 stub\n") {
		t.Errorf("missing stub area, got:\n%s", got)
	}
	if strings.Contains(got, "no-summary") {
		t.Error("should not have no-summary without NoSummary flag")
	}
}

func TestGenerateProtocols_OSPFStubNoSummary(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID:        "0.0.0.1",
				AreaType:  "stub",
				NoSummary: true,
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "area 0.0.0.1 stub no-summary\n") {
		t.Errorf("missing stub no-summary, got:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFNSSAArea(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID:       "0.0.0.2",
				AreaType: "nssa",
				Interfaces: []*config.OSPFInterface{
					{Name: "dmz0"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "area 0.0.0.2 nssa\n") {
		t.Errorf("missing nssa area, got:\n%s", got)
	}
}

func TestGenerateProtocols_BGPRouteReflector(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:   65001,
		ClusterID: "10.0.0.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65001, RouteReflectorClient: true},
			{Address: "10.0.0.3", PeerAS: 65001},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)

	checks := []string{
		"bgp cluster-id 10.0.0.1\n",
		"neighbor 10.0.0.2 route-reflector-client\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "neighbor 10.0.0.3 route-reflector-client") {
		t.Error("non-RR neighbor should not have route-reflector-client")
	}
}

func TestGenerateProtocols_ISISAuth(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:      "49.0001.0100.0000.0001.00",
		Level:    "level-2",
		AuthType: "md5",
		AuthKey:  "isisSecret",
		Interfaces: []*config.ISISInterface{
			{Name: "trust0"},
		},
	}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)

	checks := []string{
		"area-password md5 isisSecret\n",
		"domain-password md5 isisSecret\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_ISISAuthClear(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:      "49.0001.0100.0000.0001.00",
		Level:    "level-2",
		AuthType: "simple",
		AuthKey:  "plainpw",
		Interfaces: []*config.ISISInterface{
			{Name: "trust0"},
		},
	}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)

	checks := []string{
		"area-password clear plainpw\n",
		"domain-password clear plainpw\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_ISISWideMetrics(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:             "49.0001.0100.0000.0001.00",
		Level:           "level-2",
		WideMetricsOnly: true,
		Interfaces: []*config.ISISInterface{
			{Name: "trust0"},
		},
	}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
	if !strings.Contains(got, " metric-style wide\n") {
		t.Errorf("missing metric-style wide in:\n%s", got)
	}
}

func TestGenerateProtocols_ISISOverload(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:      "49.0001.0100.0000.0001.00",
		Level:    "level-2",
		Overload: true,
		Interfaces: []*config.ISISInterface{
			{Name: "trust0"},
		},
	}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
	if !strings.Contains(got, " set-overload-bit\n") {
		t.Errorf("missing set-overload-bit in:\n%s", got)
	}
}

func TestGenerateProtocols_ISISInterfaceAuth(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:   "49.0001.0100.0000.0001.00",
		Level: "level-2",
		Interfaces: []*config.ISISInterface{
			{Name: "trust0", AuthType: "md5", AuthKey: "ifaceSecret"},
			{Name: "dmz0", AuthType: "simple", AuthKey: "plainpw"},
		},
	}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
	checks := []string{
		"isis password md5 ifaceSecret\n",
		"isis password clear plainpw\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_RIPAuth(t *testing.T) {
	m := New()
	rip := &config.RIPConfig{
		Interfaces: []string{"trust0", "dmz0"},
		AuthType:   "md5",
		AuthKey:    "ripSecret",
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)

	checks := []string{
		"interface trust0\n",
		"interface dmz0\n",
		"ip rip authentication mode md5\n",
		"ip rip authentication string ripSecret\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_RIPAuthText(t *testing.T) {
	m := New()
	rip := &config.RIPConfig{
		Interfaces: []string{"trust0"},
		AuthType:   "simple",
		AuthKey:    "plainpw",
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)

	checks := []string{
		"ip rip authentication mode text\n",
		"ip rip authentication string plainpw\n",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// #9408: the field is MEGABITS PER SECOND — FRR's own unit for `auto-cost
// reference-bandwidth (1-4294967)` — and the renderer emits it verbatim. This
// pin said "int in, int out" and was silent about the unit, which is how the
// leaf's bits/s -> Mbps conversion could be missing for so long without any
// cell noticing. 10000 here is 10 Gbps.
func TestGenerateProtocols_OSPFReferenceBandwidth(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		ReferenceBandwidthMbps: 10000,
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 1, nil, nil)
	if !strings.Contains(got, "auto-cost reference-bandwidth 10000\n") {
		t.Errorf("missing reference-bandwidth in:\n%s", got)
	}
	// The rendered number must be within the grammar FRR actually accepts:
	// `auto-cost reference-bandwidth (1-4294967)`. A pin that only checks the
	// substring cannot tell a renderable value from one vtysh rejects.
	if ospf.ReferenceBandwidthMbps < 1 || ospf.ReferenceBandwidthMbps > 4294967 {
		t.Errorf("fixture premise: %d Mbps is outside FRR's 1..4294967 grammar", ospf.ReferenceBandwidthMbps)
	}
}

func TestGenerateProtocols_OSPFPassiveDefault(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID:       "1.1.1.1",
		PassiveDefault: true,
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", NoPassive: true},
					{Name: "dmz0"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "passive-interface default\n") {
		t.Errorf("missing passive-interface default in:\n%s", got)
	}
	if !strings.Contains(got, "no passive-interface trust0\n") {
		t.Errorf("missing 'no passive-interface trust0' in:\n%s", got)
	}
	// dmz0 should NOT have "no passive-interface" since it stays passive
	if strings.Contains(got, "no passive-interface dmz0") {
		t.Errorf("dmz0 should stay passive (no 'no passive-interface') in:\n%s", got)
	}
	// Should NOT have old-style "passive-interface dmz0" either
	if strings.Contains(got, "passive-interface dmz0") {
		t.Errorf("should not have per-interface passive when passive-default is set:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFNetworkType(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", NetworkType: "point-to-point"},
					{Name: "dmz0"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "ip ospf network point-to-point\n") {
		t.Errorf("missing 'ip ospf network point-to-point' in:\n%s", got)
	}
	// dmz0 should not have network type set
	if strings.Contains(got, "ip ospf network broadcast") {
		t.Errorf("dmz0 should not have network type set:\n%s", got)
	}
}

func TestGenerateProtocols_BGPGracefulRestart(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:         65001,
		GracefulRestart: true,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
	if !strings.Contains(got, "bgp graceful-restart\n") {
		t.Errorf("missing graceful-restart in:\n%s", got)
	}
}

func TestGenerateProtocols_BGPMultipath(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:             65001,
		Multipath:           64,
		MultipathMultipleAS: true,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
	if !strings.Contains(got, "bgp bestpath as-path multipath-relax\n") {
		t.Errorf("missing multipath-relax in:\n%s", got)
	}
	if !strings.Contains(got, "maximum-paths 64\n") {
		t.Errorf("missing maximum-paths in:\n%s", got)
	}
}

// TestGenerateProtocols_BGPMultipathIBGP pins the #2978 fix: FRR `maximum-paths
// N` only enables eBGP multipath, so iBGP-learned prefixes get a single best
// path and ECMP is silently disabled for iBGP routes. When the operator sets
// `protocols bgp multipath ibgp`, the renderer must ALSO emit `maximum-paths
// ibgp <n>` in BOTH unicast address-families. Deleting the new render lines
// turns this test RED.
func TestGenerateProtocols_BGPMultipathIBGP(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:       65001,
		RouterID:      "1.1.1.1",
		Multipath:     64,
		MultipathIBGP: true,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002, FamilyInet: true},
			{Address: "2001:db8::1", PeerAS: 65002, FamilyInet6: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
	// eBGP multipath line unchanged.
	if n := strings.Count(got, "maximum-paths 64\n"); n != 2 {
		t.Errorf("want 2 `maximum-paths 64` lines (ipv4+ipv6), got %d:\n%s", n, got)
	}
	// iBGP multipath line emitted in both address-families.
	if n := strings.Count(got, "maximum-paths ibgp 64\n"); n != 2 {
		t.Errorf("want 2 `maximum-paths ibgp 64` lines (ipv4+ipv6), got %d:\n%s", n, got)
	}
}

// TestGenerateProtocols_BGPMultipathNoIBGP asserts the eBGP-only default is
// unchanged: without `multipath ibgp`, NO `maximum-paths ibgp` line is emitted.
func TestGenerateProtocols_BGPMultipathNoIBGP(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:   65001,
		Multipath: 64,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002, FamilyInet: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
	if strings.Contains(got, "maximum-paths ibgp") {
		t.Errorf("eBGP-only multipath must NOT emit `maximum-paths ibgp`:\n%s", got)
	}
}

// TestGenerateProtocols_BGPMaxPathsDecoupledFromECMP pins the #2791 fix: the
// BGP address-family `maximum-paths` line is driven ONLY by the explicit
// `protocols bgp multipath` knob (bgp.Multipath), and is NEVER seeded from the
// global forwarding-table ECMP value (ecmpMaxPaths). The pre-fix code did
// `bgpMaxPaths := ecmpMaxPaths` so a global ECMP setting silently enabled BGP
// multipath. Reverting that decoupling re-introduces a `maximum-paths` line in
// the ECMP-only sub-case below, turning this test RED.
func TestGenerateProtocols_BGPMaxPathsDecoupledFromECMP(t *testing.T) {
	m := New()
	// Dual-stack neighbors so both the ipv4 and ipv6 unicast address-family
	// blocks are emitted and inspected.
	mkBGP := func(multipath int) *config.BGPConfig {
		return &config.BGPConfig{
			LocalAS:   65001,
			RouterID:  "1.1.1.1",
			Multipath: multipath,
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true},
				{Address: "2001:db8::1", PeerAS: 65002, FamilyInet6: true},
			},
		}
	}

	// Global ECMP set (ecmpMaxPaths=8), BGP multipath NOT configured: the BGP
	// address-families must NOT contain `maximum-paths`.
	got := m.generateProtocols(nil, nil, mkBGP(0), nil, nil, "", 8, nil, nil)
	if strings.Contains(got, "maximum-paths") {
		t.Errorf("global ECMP (no bgp multipath) must not emit BGP maximum-paths; "+
			"reverting the #2791 decoupling re-couples it. got:\n%s", got)
	}

	// BGP multipath explicitly configured: the BGP address-families MUST
	// contain `maximum-paths` even when global ECMP is off (ecmpMaxPaths=0) —
	// one line per address-family (ipv4 + ipv6).
	got = m.generateProtocols(nil, nil, mkBGP(4), nil, nil, "", 0, nil, nil)
	if n := strings.Count(got, "maximum-paths 4\n"); n != 2 {
		t.Errorf("explicit bgp multipath must emit `maximum-paths 4` in both "+
			"address-families (want 2, got %d):\n%s", n, got)
	}
}

func TestGenerateProtocols_BGPDefaultOriginate(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002, FamilyInet: true, DefaultOriginate: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
	if !strings.Contains(got, "neighbor 10.0.0.2 default-originate\n") {
		t.Errorf("missing default-originate in:\n%s", got)
	}
}

func TestGenerateProtocols_BGPLogNeighborChanges(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:            65001,
		LogNeighborChanges: true,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
	if !strings.Contains(got, "bgp log-neighbor-changes\n") {
		t.Errorf("missing log-neighbor-changes in:\n%s", got)
	}
}

func TestResolveRedistribute_BareProtocol(t *testing.T) {
	m := New()
	for _, proto := range []string{"connected", "static", "ospf", "bgp", "rip", "isis", "kernel"} {
		got := m.resolveRedistribute(proto, nil, "", nil)
		want := " redistribute " + proto + "\n"
		if got != want {
			t.Errorf("resolveRedistribute(%q, nil) = %q, want %q", proto, got, want)
		}
	}
}

func TestResolveRedistribute_PolicyStatement(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"internal": {Name: "internal", Prefixes: []string{"10.0.0.0/8", "172.16.0.0/12"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"export-connected": {
				Name: "export-connected",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocols: []string{"direct"}, Action: "accept", PrefixList: []string{"internal"}},
				},
			},
		},
	}
	got := m.resolveRedistribute("export-connected", po, "", nil)
	want := " redistribute connected route-map export-connected\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveRedistribute_MultiProtocol(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"export-all": {
				Name: "export-all",
				Terms: []*config.PolicyTerm{
					{Name: "connected", FromProtocols: []string{"direct"}, Action: "accept"},
					{Name: "static", FromProtocols: []string{"static"}, Action: "accept"},
				},
			},
		},
	}
	got := m.resolveRedistribute("export-all", po, "", nil)
	// Should have both protocols, sorted alphabetically
	if !strings.Contains(got, "redistribute connected route-map export-all\n") {
		t.Errorf("missing connected route-map in:\n%s", got)
	}
	if !strings.Contains(got, "redistribute static route-map export-all\n") {
		t.Errorf("missing static route-map in:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFExportRouteMap(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"trusted-nets": {Name: "trusted-nets", Prefixes: []string{"10.0.1.0/24", "10.0.2.0/24"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"export-direct": {
				Name: "export-direct",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocols: []string{"direct"}, PrefixList: []string{"trusted-nets"}, Action: "accept"},
				},
				DefaultAction: "reject",
			},
		},
	}
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Export:   []string{"export-direct"},
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, po, nil)
	if !strings.Contains(got, "redistribute connected route-map export-direct\n") {
		t.Errorf("missing route-map redistribute, got:\n%s", got)
	}
	// Should NOT have bare "redistribute export-direct"
	if strings.Contains(got, "redistribute export-direct\n") {
		t.Errorf("should not have bare redistribute with policy name, got:\n%s", got)
	}
}

// TestGenerateProtocols_BGPExportRouteMap covers the #2473 corrected
// contract: a global `protocols bgp export <policy>` is applied to each
// peer as `neighbor <X> route-map <policy> out`. The route-map itself is
// rendered by generatePolicyOptions (verified separately); here we assert
// the BGP render references it as a peer-level export, never as
// `redistribute`.
func TestGenerateProtocols_BGPExportRouteMap(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"bgp-export": {
				Name: "bgp-export",
				Terms: []*config.PolicyTerm{
					{Name: "connected", FromProtocols: []string{"direct"}, Action: "accept"},
					{Name: "static", FromProtocols: []string{"static"}, Action: "accept"},
				},
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Export:   []string{"bgp-export"},
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)
	if !strings.Contains(got, "neighbor 10.0.2.1 route-map bgp-export out\n") {
		t.Errorf("missing peer-level route-map out, got:\n%s", got)
	}
	if strings.Contains(got, "redistribute") {
		t.Errorf("global BGP export must not emit redistribute, got:\n%s", got)
	}
}

// TestGenerateProtocols_BGPExportPrefixOnly covers #2473 failure mode 2: a
// global export filtering on prefix/community with NO `from protocol` was
// SILENTLY DROPPED (resolveRedistribute returned ""), so the operator's
// advertise filter was never applied. It must now render as a working
// peer-level `route-map out`.
func TestGenerateProtocols_BGPExportPrefixOnly(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"adv-filter": {
				Name: "adv-filter",
				Terms: []*config.PolicyTerm{
					// No FromProtocols — matches by community only.
					{Name: "t1", FromCommunity: []string{"no-export"}, Action: "reject"},
				},
				DefaultAction: "accept",
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Export:  []string{"adv-filter"},
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)
	if !strings.Contains(got, "neighbor 10.0.2.1 route-map adv-filter out\n") {
		t.Errorf("prefix/community-only global export must apply as route-map out (was silently dropped), got:\n%s", got)
	}
	if strings.Contains(got, "redistribute") {
		t.Errorf("global BGP export must not emit redistribute, got:\n%s", got)
	}
}

// TestGenerateProtocols_BGPExportCoexistence covers the #2473 coexistence
// semantics (Junos most-specific-wins): a neighbor with its OWN export
// overrides the global default for that neighbor, while a neighbor without
// one inherits the global default. FRR accepts a single `route-map out`
// per neighbor/AF, so exactly one is emitted per peer — never two
// competing route-maps for one peer.
func TestGenerateProtocols_BGPExportCoexistence(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"global-default": {Name: "global-default", Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"static"}, Action: "accept"}}},
			"peer-specific":  {Name: "peer-specific", Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"static"}, Action: "accept"}}},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Export:  []string{"global-default"},
		Neighbors: []*config.BGPNeighbor{
			// Inherits the global default.
			{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true},
			// Overrides the global default with its own export.
			{Address: "10.0.2.2", PeerAS: 65003, FamilyInet: true, Export: []string{"peer-specific"}},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)
	if !strings.Contains(got, "neighbor 10.0.2.1 route-map global-default out\n") {
		t.Errorf("neighbor without own export must inherit global default, got:\n%s", got)
	}
	if !strings.Contains(got, "neighbor 10.0.2.2 route-map peer-specific out\n") {
		t.Errorf("neighbor with own export must override global default, got:\n%s", got)
	}
	// The overriding neighbor must NOT also get the global default
	// (one route-map out per neighbor/AF).
	if strings.Contains(got, "neighbor 10.0.2.2 route-map global-default out\n") {
		t.Errorf("neighbor with own export must not also receive global default, got:\n%s", got)
	}
}

// TestGenerateProtocols_BGPExportMixed covers the #2473 split: a global
// export list mixing a defined policy-statement name AND a bare protocol
// token must render BOTH semantics — the policy-statement as a peer-level
// `route-map out`, the bare token as a global `redistribute`. Neither must
// leak into the other path (no `redistribute <policy>`, no dangling
// `route-map <token> out`).
func TestGenerateProtocols_BGPExportMixed(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"adv-filter": {
				Name:          "adv-filter",
				Terms:         []*config.PolicyTerm{{Name: "t1", FromCommunity: []string{"no-export"}, Action: "reject"}},
				DefaultAction: "accept",
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		// "adv-filter" is a policy-statement → route-map out;
		// "static" is a bare token → redistribute.
		Export: []string{"adv-filter", "static"},
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, po, nil)
	// Policy-statement → peer-level route-map out.
	if !strings.Contains(got, "neighbor 10.0.2.1 route-map adv-filter out\n") {
		t.Errorf("policy-statement export must render route-map out, got:\n%s", got)
	}
	// Bare token → global redistribute.
	if !strings.Contains(got, "redistribute static\n") {
		t.Errorf("bare token export must render redistribute, got:\n%s", got)
	}
	// No crossover: the policy-statement must NOT redistribute, and the
	// bare token must NOT render a dangling route-map out.
	if strings.Contains(got, "redistribute adv-filter") {
		t.Errorf("policy-statement export must not redistribute, got:\n%s", got)
	}
	if strings.Contains(got, "route-map static out") {
		t.Errorf("bare token must not render dangling route-map out, got:\n%s", got)
	}
}

// TestResolveRedistribute_ProtocolLessPolicy is the #2223 fail-on-revert
// guard. A defined policy-statement whose terms carry NO `from protocol`
// (it matches only from community / prefix-list / as-path) has no
// resolvable redistribute source protocol. resolveRedistribute MUST skip
// it (emit nothing) rather than fall back to the FRR-invalid
// `redistribute <policy>` line — that line is rejected by frr-reload.py
// and, because it lands in the xpf-managed section, fails the WHOLE
// reload: no stale config is removed anywhere in the managed section while
// it is rendered, not just in this stanza.
//
// Pre-fix this returned " redistribute export-comm\n". Post-fix it
// returns "".
func TestResolveRedistribute_ProtocolLessPolicy(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"export-comm": {
				Name: "export-comm",
				Terms: []*config.PolicyTerm{
					// from community only — no `from protocol`.
					{Name: "t1", FromCommunity: []string{"my-comm"}, Action: "accept"},
				},
				DefaultAction: "accept",
			},
		},
	}
	got := m.resolveRedistribute("export-comm", po, "", nil)
	if got != "" {
		t.Errorf("protocol-less policy must yield no redistribute line, got %q", got)
	}
	// Specifically must NOT emit the FRR-invalid bare-policy line.
	if strings.Contains(got, "redistribute export-comm") {
		t.Errorf("emitted FRR-invalid `redistribute <policy>` line, got %q", got)
	}
}

// TestResolveRedistribute_UnknownToken covers an export name that is
// neither a known protocol token nor a defined policy-statement (a name
// that slipped past the strict validator on a tolerant load / peer-sync
// path). It must never render a bare `redistribute <name>` — there is no
// valid source protocol, and the line would degrade the managed reload
// exactly as the protocol-less-policy case does (#2223).
func TestResolveRedistribute_UnknownToken(t *testing.T) {
	m := New()
	// nil policy-options: the name resolves to nothing.
	if got := m.resolveRedistribute("no-such-policy", nil, "", nil); got != "" {
		t.Errorf("unknown token must yield no redistribute line, got %q", got)
	}
	// Non-nil policy-options that simply does not define the name.
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"other": {Name: "other"},
		},
	}
	if got := m.resolveRedistribute("typo-name", po, "", nil); got != "" {
		t.Errorf("undefined policy name must yield no redistribute line, got %q", got)
	}
}

// TestGenerateProtocols_ProtocolLessPolicyExport is the end-to-end #2223
// guard at the generateProtocols level: an OSPF instance exporting a
// protocol-less policy alongside a normal protocol-qualified policy must
// (a) omit any invalid `redistribute <policy>` line for the protocol-less
// export, and (b) still emit the correct `redistribute <proto> route-map
// <name>` for the well-formed one — one bad stanza never suppresses the
// good one.
func TestGenerateProtocols_ProtocolLessPolicyExport(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			// Protocol-less: from community only.
			"export-comm": {
				Name:          "export-comm",
				Terms:         []*config.PolicyTerm{{Name: "t1", FromCommunity: []string{"my-comm"}, Action: "accept"}},
				DefaultAction: "accept",
			},
			// Well-formed: from protocol static.
			"export-static": {
				Name:  "export-static",
				Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"static"}, Action: "accept"}},
			},
		},
	}
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Export:   []string{"export-comm", "export-static"},
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, po, nil)

	// The protocol-less export must NOT produce any invalid line.
	if strings.Contains(got, "redistribute export-comm") {
		t.Errorf("rendered FRR-invalid `redistribute export-comm`, got:\n%s", got)
	}
	// The well-formed export must still render correctly.
	if !strings.Contains(got, "redistribute static route-map export-static\n") {
		t.Errorf("missing valid `redistribute static route-map export-static`, got:\n%s", got)
	}

	// Belt: no redistribute line in the managed output may name a policy
	// (i.e. a non-protocol token) as its source protocol. Every
	// `redistribute <tok>` must have <tok> in the known protocol set.
	assertNoInvalidRedistribute(t, got)
}

// assertNoInvalidRedistribute is an frr.conf-syntax-validity belt: it
// fails if any generated `redistribute <tok> ...` line names a token that
// is not a valid FRR redistribute source protocol. This is the structural
// invariant #2223 protects — a bad source protocol degrades the whole
// managed-section reload.
func assertNoInvalidRedistribute(t *testing.T, conf string) {
	t.Helper()
	valid := map[string]bool{
		"connected": true, "static": true, "ospf": true, "ospf6": true,
		"bgp": true, "rip": true, "ripng": true, "isis": true,
		"kernel": true, "babel": true, "table": true, "sharp": true,
	}
	for _, line := range strings.Split(conf, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "redistribute" {
			if !valid[f[1]] {
				t.Errorf("invalid FRR redistribute source protocol %q in line %q", f[1], strings.TrimSpace(line))
			}
		}
	}
}

func TestGenerateProtocols_BGPAllowASIn(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002, AllowASIn: 2},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
	if !strings.Contains(got, "neighbor 10.0.0.2 allowas-in 2\n") {
		t.Errorf("missing allowas-in in:\n%s", got)
	}
}

func TestGenerateProtocols_BGPRemovePrivateAS(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002, RemovePrivateAS: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
	if !strings.Contains(got, "neighbor 10.0.0.2 remove-private-AS\n") {
		t.Errorf("missing remove-private-AS in:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFv3(t *testing.T) {
	m := New()
	ospfv3 := &config.OSPFv3Config{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFv3Area{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFv3Interface{
					{Name: "trust0", Passive: true, Cost: 10},
					{Name: "dmz0"},
				},
			},
		},
		Export: []string{"connected"},
	}
	got := m.generateProtocols(nil, ospfv3, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "router ospf6\n") {
		t.Errorf("missing router ospf6 in:\n%s", got)
	}
	if !strings.Contains(got, "ospf6 router-id 10.0.0.1\n") {
		t.Errorf("missing router-id in:\n%s", got)
	}
	if !strings.Contains(got, "interface trust0 area 0.0.0.0\n") {
		t.Errorf("missing interface trust0 area in:\n%s", got)
	}
	if !strings.Contains(got, "interface dmz0 area 0.0.0.0\n") {
		t.Errorf("missing interface dmz0 area in:\n%s", got)
	}
	if !strings.Contains(got, "ipv6 ospf6 passive\n") {
		t.Errorf("missing passive in:\n%s", got)
	}
	if !strings.Contains(got, "ipv6 ospf6 cost 10\n") {
		t.Errorf("missing cost in:\n%s", got)
	}
	if !strings.Contains(got, "redistribute connected\n") {
		t.Errorf("missing redistribute in:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFv3VRF(t *testing.T) {
	m := New()
	ospfv3 := &config.OSPFv3Config{
		RouterID: "10.0.0.2",
		Areas: []*config.OSPFv3Area{
			{
				ID: "0.0.0.1",
				Interfaces: []*config.OSPFv3Interface{
					{Name: "vrf-eth0"},
				},
			},
		},
	}
	got := m.generateProtocols(nil, ospfv3, nil, nil, nil, "cust-a", 0, nil, nil)
	if !strings.Contains(got, "router ospf6 vrf cust-a\n") {
		t.Errorf("missing VRF-scoped ospf6 in:\n%s", got)
	}
	if !strings.Contains(got, "ospf6 router-id 10.0.0.2\n") {
		t.Errorf("missing router-id in:\n%s", got)
	}
}

// TestGenerateProtocols_OSPFv3BFD verifies an OSPFv3 interface with BFD renders
// the FRR 10.6 ospf6d interface command `ipv6 ospf6 bfd` (bare, no profile) and
// does NOT emit the OSPFv2 `ip ospf bfd` form (#2474).
func TestGenerateProtocols_OSPFv3BFD(t *testing.T) {
	m := New()
	ospfv3 := &config.OSPFv3Config{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFv3Area{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFv3Interface{
					{Name: "trust0", BFD: true},
				},
			},
		},
	}
	got := m.generateProtocols(nil, ospfv3, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "interface trust0\n") {
		t.Errorf("missing interface block in:\n%s", got)
	}
	if !strings.Contains(got, " ipv6 ospf6 bfd\n") {
		t.Errorf("missing 'ipv6 ospf6 bfd' in:\n%s", got)
	}
	if strings.Contains(got, "ip ospf bfd") {
		t.Errorf("must NOT emit OSPFv2 'ip ospf bfd' for an OSPFv3 interface in:\n%s", got)
	}
}

// TestGenerateProtocols_OSPFv3BFDProfile verifies that an OSPFv3 interface with
// a custom interval/multiplier renders a BFD profile reference plus the profile
// definition, mirroring the OSPFv2 structure but with the ospf6 keyword (#2474).
func TestGenerateProtocols_OSPFv3BFDProfile(t *testing.T) {
	m := New()
	ospfv3 := &config.OSPFv3Config{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFv3Area{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFv3Interface{
					{Name: "trust0", BFD: true, BFDInterval: 300, BFDMultiplier: 3},
				},
			},
		},
	}
	got := m.generateProtocols(nil, ospfv3, nil, nil, nil, "", 0, nil, nil)
	profile := bfdProfileName(300, 3)
	if !strings.Contains(got, " ipv6 ospf6 bfd profile "+profile+"\n") {
		t.Errorf("missing 'ipv6 ospf6 bfd profile %s' in:\n%s", profile, got)
	}
	if !strings.Contains(got, "profile "+profile+"\n") {
		t.Errorf("missing BFD profile definition %q in:\n%s", profile, got)
	}
	if strings.Contains(got, "ip ospf bfd") {
		t.Errorf("must NOT emit OSPFv2 'ip ospf bfd' for an OSPFv3 interface in:\n%s", got)
	}
}

// TestBuildManagedSection_SingleGlobalBFDBlock is the #2550 fail-on-revert
// guard: BFD profiles configured in the DEFAULT instance AND in a VRF
// instance must consolidate into EXACTLY ONE top-level `bfd` block, with
// each profile defined exactly once (even when two instances reference the
// same profile). Before the fix, generateProtocols emitted its own per-call
// `bfd` block, so a default + VRF config produced TWO top-level `bfd`
// blocks (count == 2); after the fix the manager emits one global block
// (count == 1). The whole managed section is rendered via the real
// assemble path (buildManagedSection), not generateProtocols in isolation.
func TestBuildManagedSection_SingleGlobalBFDBlock(t *testing.T) {
	m := New()

	// Default instance: OSPFv2 interface with a 300/3 BFD profile.
	ospf := &config.OSPFConfig{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", BFD: true, BFDInterval: 300, BFDMultiplier: 3},
				},
			},
		},
	}

	// VRF instance: ISIS interface with a DISTINCT 250/4 BFD profile PLUS a
	// second interface that re-references the SAME 300/3 profile as the
	// default instance — exercises cross-instance dedup.
	isis := &config.ISISConfig{
		NET:   "49.0001.1921.6800.1001.00",
		Level: "level-1-2",
		Interfaces: []*config.ISISInterface{
			{Name: "blue0", BFD: true, BFDInterval: 250, BFDMultiplier: 4},
			{Name: "blue1", BFD: true, BFDInterval: 300, BFDMultiplier: 3},
		},
	}

	fc := &FullConfig{
		OSPF: ospf,
		Instances: []InstanceConfig{
			{Name: "blue", VRFName: "vrf-blue", ISIS: isis},
		},
	}

	got := m.buildManagedSection(fc)

	// A top-level `bfd` block opens with a bare "bfd\n" line (no leading
	// space). Interface-level BFD lines (" ip ospf bfd ...", " isis bfd
	// ...") are space-indented, so "\nbfd\n" matches ONLY block openers.
	blocks := strings.Count(got, "\nbfd\n")
	if blocks != 1 {
		t.Fatalf("expected exactly 1 top-level bfd block, got %d in:\n%s", blocks, got)
	}

	// Each distinct profile must be DEFINED exactly once. A definition line
	// is "\n profile <name>\n" (newline immediately before " profile");
	// reference lines read "... bfd profile <name>" so they do NOT match.
	prof300 := bfdProfileName(300, 3)
	prof250 := bfdProfileName(250, 4)
	if n := strings.Count(got, "\n profile "+prof300+"\n"); n != 1 {
		t.Errorf("profile %s must be defined exactly once, got %d in:\n%s", prof300, n, got)
	}
	if n := strings.Count(got, "\n profile "+prof250+"\n"); n != 1 {
		t.Errorf("profile %s must be defined exactly once, got %d in:\n%s", prof250, n, got)
	}

	// Both protocol interfaces must still reference their profile.
	if !strings.Contains(got, " ip ospf bfd profile "+prof300+"\n") {
		t.Errorf("missing OSPFv2 bfd profile reference %s in:\n%s", prof300, got)
	}
	if !strings.Contains(got, " isis bfd profile "+prof250+"\n") {
		t.Errorf("missing ISIS bfd profile reference %s in:\n%s", prof250, got)
	}

	// The single global bfd block must be top-level (not nested inside a
	// router/instance scope): the bfd opener must NOT be immediately
	// preceded by a router stanza line without an intervening "!" divider.
	bfdIdx := strings.Index(got, "\nbfd\n")
	if bfdIdx < 0 {
		t.Fatalf("no top-level bfd block found in:\n%s", got)
	}
	if !strings.HasPrefix(got[bfdIdx:], "\nbfd\n profile ") {
		t.Errorf("global bfd block must lead with a profile stanza, got:\n%s", got[bfdIdx:])
	}
}

// TestBuildManagedSection_BGPBFDPeersSingleBlock proves BGP BFD peers in
// the default instance AND a VRF consolidate into the SAME single global
// bfd block, each carrying the correct (or absent) vrf suffix (#2550 +
// #2489 preserved).
func TestBuildManagedSection_BGPBFDPeersSingleBlock(t *testing.T) {
	m := New()

	defBGP := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.9", PeerAS: 65002, BFD: true},
		},
	}
	vrfBGP := &config.BGPConfig{
		LocalAS: 65010,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.1.1.2", PeerAS: 65011, BFD: true},
		},
	}

	fc := &FullConfig{
		BGP: defBGP,
		Instances: []InstanceConfig{
			{Name: "blue", VRFName: "vrf-blue", BGP: vrfBGP},
		},
	}

	got := m.buildManagedSection(fc)

	if blocks := strings.Count(got, "\nbfd\n"); blocks != 1 {
		t.Fatalf("expected exactly 1 top-level bfd block for BGP BFD peers, got %d in:\n%s", blocks, got)
	}
	if !strings.Contains(got, " peer 10.0.0.9\n") {
		t.Errorf("default-instance BFD peer must be a bare `peer` line, got:\n%s", got)
	}
	if !strings.Contains(got, " peer 10.1.1.2 vrf vrf-blue\n") {
		t.Errorf("VRF BFD peer must carry `vrf vrf-blue` suffix (#2489), got:\n%s", got)
	}
}

func TestGeneratePolicyOptionsCommunityListAndMetricType(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"MY-COMM": {
				Name:    "MY-COMM",
				Members: []string{"65000:100", "65000:200"},
			},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"OSPF-EXPORT": {
				Name: "OSPF-EXPORT",
				Terms: []*config.PolicyTerm{
					{
						Name:          "t1",
						FromProtocols: []string{"direct"},
						FromCommunity: []string{"MY-COMM"},
						Action:        "accept",
						MetricType:    1,
						Metric:        100,
						HasMetric:     true,
					},
					{
						Name:       "t2",
						Action:     "accept",
						MetricType: 2,
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	checks := []string{
		"bgp community-list standard MY-COMM permit 65000:100",
		"bgp community-list standard MY-COMM permit 65000:200",
		"route-map OSPF-EXPORT permit 10",
		"match source-protocol connected",
		"match community MY-COMM",
		"set metric 100",
		"set metric-type type-1",
		"route-map OSPF-EXPORT permit 20",
		"set metric-type type-2",
		"route-map OSPF-EXPORT deny 30",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// TestGeneratePolicyOptionsCommunityExpandedVsStandard pins the #2643
// fix: a community definition with a regex/wildcard member must render as
// an FRR `expanded` community-list (which accepts POSIX regex), NOT
// `standard` (which rejects regex at config load and fails the whole
// frr-reload). A literal-only definition stays `standard`, and a MIXED
// definition (any regex member) renders the WHOLE list as `expanded`
// because FRR forbids the same name being both standard and expanded.
func TestGeneratePolicyOptionsCommunityExpandedVsStandard(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			// Literal-only -> standard.
			"LIT-ONLY": {
				Name:    "LIT-ONLY",
				Members: []string{"65000:100", "no-export"},
			},
			// Wildcard member -> expanded (whole list).
			"WILD": {
				Name:    "WILD",
				Members: []string{"65000:*"},
			},
			// Mixed literal + regex -> whole list expanded.
			"MIXED": {
				Name:    "MIXED",
				Members: []string{"65000:100", "65001:.*"},
			},
			// POSIX-ERE interval/bound braces are regex too — the member
			// carries none of `* . + ? ^ $ [ ]`, so it relies on `{` `}`
			// being in communityRegexChars to route to an expanded list
			// (#2643 follow-up false-negative).
			"BOUND": {
				Name:    "BOUND",
				Members: []string{"65000:1{2,3}"},
			},
		},
	}

	got := m.generatePolicyOptions(po)

	wantLines := []string{
		// Literal-only definition keeps standard.
		"bgp community-list standard LIT-ONLY permit 65000:100",
		"bgp community-list standard LIT-ONLY permit no-export",
		// Wildcard member renders the member as-is into an expanded list.
		"bgp community-list expanded WILD permit 65000:*",
		// Mixed definition: BOTH members go into the expanded list — the
		// literal member must NOT regress to a standard line, since the
		// same list name cannot be both kinds in FRR.
		"bgp community-list expanded MIXED permit 65000:100",
		"bgp community-list expanded MIXED permit 65001:.*",
		// Brace-bound member must render expanded, not standard.
		"bgp community-list expanded BOUND permit 65000:1{2,3}",
	}
	for _, want := range wantLines {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}

	// fail-on-revert: forcing a wildcard/regex member onto a standard
	// list is exactly the FRR-invalid config that fails the reload. No
	// standard community-list line may carry a regex metacharacter, and
	// no name may appear as both standard and expanded.
	for _, line := range strings.Split(got, "\n") {
		if !strings.HasPrefix(line, "bgp community-list standard ") {
			continue
		}
		// fields: bgp community-list standard <name> permit <member>
		fields := strings.Fields(line)
		if len(fields) != 6 {
			t.Fatalf("unexpected standard community-list line shape: %q", line)
		}
		member := fields[5]
		if strings.ContainsAny(member, communityRegexChars) {
			t.Errorf("FRR-invalid: regex member %q on a standard community-list line: %q", member, line)
		}
	}
	if strings.Contains(got, "bgp community-list standard MIXED ") {
		t.Errorf("MIXED list must NOT appear as standard (would collide with its expanded form):\n%s", got)
	}
	if strings.Contains(got, "bgp community-list standard WILD ") {
		t.Errorf("WILD list must NOT appear as standard:\n%s", got)
	}
	if strings.Contains(got, "bgp community-list standard BOUND ") {
		t.Errorf("BOUND (brace-bound regex) list must NOT appear as standard:\n%s", got)
	}
}

func TestGenerateProtocols_BGPDampening(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:   65001,
		RouterID:  "1.1.1.1",
		Dampening: true,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "bgp dampening 15 750 2000 60\n") {
		t.Errorf("missing default dampening, got:\n%s", got)
	}
}

func TestGenerateProtocols_BGPDampeningCustom(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS:              65001,
		RouterID:             "1.1.1.1",
		Dampening:            true,
		DampeningHalfLife:    10,
		DampeningReuse:       500,
		DampeningSuppress:    3000,
		DampeningMaxSuppress: 45,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "bgp dampening 10 500 3000 45\n") {
		t.Errorf("missing custom dampening, got:\n%s", got)
	}
}

func TestGeneratePolicyOptionsASPath(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		ASPaths: map[string]*config.ASPathDef{
			"AS65000": {Name: "AS65000", Regex: "65000"},
			"TRANSIT": {Name: "TRANSIT", Regex: "65[0-9]+"},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"FILTER-AS": {
				Name: "FILTER-AS",
				Terms: []*config.PolicyTerm{
					{
						Name:       "match-as",
						FromASPath: []string{"AS65000"},
						Action:     "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	checks := []string{
		"bgp as-path access-list AS65000 permit 65000",
		"bgp as-path access-list TRANSIT permit 65[0-9]+",
		"route-map FILTER-AS permit 10",
		"match as-path AS65000",
		"route-map FILTER-AS deny 20",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateProtocols_BGPPrefixLimit(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{
				Address:         "10.0.0.2",
				PeerAS:          65002,
				FamilyInet:      true,
				PrefixLimitInet: 1000,
			},
			{
				Address:          "fd00::2",
				PeerAS:           65003,
				FamilyInet6:      true,
				PrefixLimitInet6: 500,
			},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
	if !strings.Contains(got, "neighbor 10.0.0.2 maximum-prefix 1000\n") {
		t.Errorf("missing IPv4 maximum-prefix in:\n%s", got)
	}
	if !strings.Contains(got, "neighbor fd00::2 maximum-prefix 500\n") {
		t.Errorf("missing IPv6 maximum-prefix in:\n%s", got)
	}
}

func TestGenerateProtocols_BGPPrefixLimitZeroOmitted(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65001,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.2", PeerAS: 65002, FamilyInet: true},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
	if strings.Contains(got, "maximum-prefix") {
		t.Errorf("should not have maximum-prefix when limit is 0:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFVirtualLink(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.1",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0"},
				},
				VirtualLinks: []*config.OSPFVirtualLink{
					{NeighborID: "10.0.0.2", TransitArea: "0.0.0.1"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "area 0.0.0.1 virtual-link 10.0.0.2\n") {
		t.Errorf("missing virtual-link in:\n%s", got)
	}
}

func TestGenerateProtocols_OSPFVirtualLinkCustomTransitArea(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.1",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0"},
				},
				VirtualLinks: []*config.OSPFVirtualLink{
					{NeighborID: "10.0.0.3", TransitArea: "0.0.0.2"},
				},
			},
		},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "area 0.0.0.2 virtual-link 10.0.0.3\n") {
		t.Errorf("missing virtual-link with custom transit area in:\n%s", got)
	}
}

func TestNextHopPeerAddress(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists: make(map[string]*config.PrefixList),
		Communities: make(map[string]*config.CommunityDef),
		ASPaths:     make(map[string]*config.ASPathDef),
		PolicyStatements: map[string]*config.PolicyStatement{
			"to-vpn-mesh": {
				Name: "to-vpn-mesh",
				Terms: []*config.PolicyTerm{
					{
						Name:          "v6",
						FromProtocols: []string{"direct"},
						RouteFilters: []*config.RouteFilter{
							{Prefix: "2001:559:8585::/48", MatchType: "exact"},
						},
						NextHop: "peer-address",
						Action:  "accept",
					},
					{
						Name:          "v4",
						FromProtocols: []string{"direct"},
						RouteFilters: []*config.RouteFilter{
							{Prefix: "172.16.0.0/20", MatchType: "exact"},
						},
						Action: "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}
	got := m.generatePolicyOptions(po)

	// "next-hop peer-address" in Junos should map to BOTH the v4 and v6
	// peer-address forms in FRR. The session AF is unknown at render time,
	// so both lines are emitted and FRR applies each to the matching family.
	if !strings.Contains(got, "set ip next-hop peer-address") {
		t.Errorf("missing 'set ip next-hop peer-address' in:\n%s", got)
	}
	if !strings.Contains(got, "set ipv6 next-hop peer-address") {
		t.Errorf("missing 'set ipv6 next-hop peer-address' in:\n%s", got)
	}

	// Verify route-filter exact generates proper prefix-list
	if !strings.Contains(got, "permit 2001:559:8585::/48\n") {
		t.Errorf("missing exact prefix-list entry for 2001:559:8585::/48 in:\n%s", got)
	}

	// Verify "next-hop self" lowers to the OUTBOUND route-map self idiom
	// `set ip/ipv6 next-hop peer-address` (self in the outbound direction),
	// NOT a neighbor-wide knob and NOT an invalid `set ... next-hop self`
	// (#5115). A bare term (no `from`) matches every advertised route, so a
	// genuinely neighbor-wide self keeps neighbor-wide effect via the
	// match-all route-map sequence.
	po2 := &config.PolicyOptionsConfig{
		PrefixLists: make(map[string]*config.PrefixList),
		Communities: make(map[string]*config.CommunityDef),
		ASPaths:     make(map[string]*config.ASPathDef),
		PolicyStatements: map[string]*config.PolicyStatement{
			"self-policy": {
				Name: "self-policy",
				Terms: []*config.PolicyTerm{
					{
						Name:    "t1",
						NextHop: "self",
						Action:  "accept",
					},
				},
			},
		},
	}
	got2 := m.generatePolicyOptions(po2)
	if !strings.Contains(got2, "set ip next-hop peer-address") {
		t.Errorf("next-hop self should lower to `set ip next-hop peer-address`, got:\n%s", got2)
	}
	if !strings.Contains(got2, "set ipv6 next-hop peer-address") {
		t.Errorf("next-hop self should lower to `set ipv6 next-hop peer-address`, got:\n%s", got2)
	}
	if strings.Contains(got2, "next-hop self") {
		t.Errorf("next-hop self must NOT emit a literal `set ... next-hop self`, got:\n%s", got2)
	}
}

// TestNextHopAddressFamily verifies that a literal next-hop is rendered with
// the FRR set-clause matching its address family. An IPv6 literal MUST use
// "set ipv6 next-hop global" — FRR rejects "set ip next-hop <v6>" with a
// syntax error that fails the entire route-map parse (#2403). An IPv4 literal
// keeps the existing "set ip next-hop" form.
func TestNextHopAddressFamily(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists: make(map[string]*config.PrefixList),
		Communities: make(map[string]*config.CommunityDef),
		ASPaths:     make(map[string]*config.ASPathDef),
		PolicyStatements: map[string]*config.PolicyStatement{
			"v6-nh": {
				Name: "v6-nh",
				Terms: []*config.PolicyTerm{
					{
						Name:    "t1",
						NextHop: "2001:db8::1",
						Action:  "accept",
					},
				},
			},
		},
	}
	got := m.generatePolicyOptions(po)

	// IPv6 literal must use the dedicated v6 form.
	if !strings.Contains(got, "set ipv6 next-hop global 2001:db8::1") {
		t.Errorf("missing 'set ipv6 next-hop global 2001:db8::1' in:\n%s", got)
	}
	// And must NOT emit the v4 clause for a v6 address — FRR would reject it.
	if strings.Contains(got, "set ip next-hop 2001:db8::1") {
		t.Errorf("v6 next-hop wrongly rendered as 'set ip next-hop', got:\n%s", got)
	}

	// IPv4 literal keeps the v4 form (and must not gain a v6 clause).
	po2 := &config.PolicyOptionsConfig{
		PrefixLists: make(map[string]*config.PrefixList),
		Communities: make(map[string]*config.CommunityDef),
		ASPaths:     make(map[string]*config.ASPathDef),
		PolicyStatements: map[string]*config.PolicyStatement{
			"v4-nh": {
				Name: "v4-nh",
				Terms: []*config.PolicyTerm{
					{
						Name:    "t1",
						NextHop: "10.0.0.1",
						Action:  "accept",
					},
				},
			},
		},
	}
	got2 := m.generatePolicyOptions(po2)
	if !strings.Contains(got2, "set ip next-hop 10.0.0.1") {
		t.Errorf("missing 'set ip next-hop 10.0.0.1' in:\n%s", got2)
	}
	if strings.Contains(got2, "set ipv6 next-hop") {
		t.Errorf("v4 next-hop wrongly emitted a v6 clause, got:\n%s", got2)
	}
}

func TestRouteFilterExactFRR(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists: make(map[string]*config.PrefixList),
		Communities: make(map[string]*config.CommunityDef),
		ASPaths:     make(map[string]*config.ASPathDef),
		PolicyStatements: map[string]*config.PolicyStatement{
			"to-firewall": {
				Name: "to-firewall",
				Terms: []*config.PolicyTerm{
					{
						Name:          "default_v4",
						FromProtocols: []string{"direct"},
						RouteFilters: []*config.RouteFilter{
							{Prefix: "192.168.50.0/24", MatchType: "exact"},
							{Prefix: "192.168.99.0/24", MatchType: "exact"},
							{Prefix: "172.16.100.0/22", MatchType: "exact"},
						},
						Action: "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}
	got := m.generatePolicyOptions(po)

	// Each exact route-filter should generate a prefix-list entry without ge/le
	checks := []string{
		"ip prefix-list to-firewall-default_v4 seq 5 permit 192.168.50.0/24\n",
		"ip prefix-list to-firewall-default_v4 seq 10 permit 192.168.99.0/24\n",
		"ip prefix-list to-firewall-default_v4 seq 15 permit 172.16.100.0/22\n",
		"match ip address prefix-list to-firewall-default_v4",
		"route-map to-firewall permit 10",
		"route-map to-firewall deny 20",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// uptoPolicyOptions builds a one-statement / one-term policy carrying a
// single "upto" route-filter, for the #2072 render tests.
func uptoPolicyOptions(prefix string, uptoLen int) *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"p": {
				Name: "p",
				Terms: []*config.PolicyTerm{
					{
						Name:         "t1",
						RouteFilters: []*config.RouteFilter{{Prefix: prefix, MatchType: "upto", UptoLen: uptoLen}},
						Action:       "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}
}

// TestRouteFilterUptoFRR is the #2072 render regression: "upto /N" must
// emit a bare "le N" (no ge — FRR rejects ge<=prefix-len), NOT the
// default "le 32"/"le 128" that the pre-fix code produced by falling
// through the match-type switch.
func TestRouteFilterUptoFRR(t *testing.T) {
	t.Run("v4_upto24", func(t *testing.T) {
		got := New().generatePolicyOptions(uptoPolicyOptions("10.0.0.0/8", 24))
		if !strings.Contains(got, "ip prefix-list p-t1 seq 5 permit 10.0.0.0/8 le 24\n") {
			t.Errorf("want bare 'le 24' line, got:\n%s", got)
		}
		if strings.Contains(got, "le 32") {
			t.Errorf("must NOT emit default 'le 32' for upto /24, got:\n%s", got)
		}
		if strings.Contains(got, "ge ") {
			t.Errorf("must NOT emit 'ge' (FRR rejects ge<=prefix-len), got:\n%s", got)
		}
	})

	t.Run("v6_upto48", func(t *testing.T) {
		got := New().generatePolicyOptions(uptoPolicyOptions("2001:db8::/32", 48))
		if !strings.Contains(got, "ipv6 prefix-list p-t1 seq 5 permit 2001:db8::/32 le 48\n") {
			t.Errorf("want bare 'le 48' line, got:\n%s", got)
		}
		if strings.Contains(got, "le 128") {
			t.Errorf("must NOT emit default 'le 128' for upto /48, got:\n%s", got)
		}
		if strings.Contains(got, "ge ") {
			t.Errorf("must NOT emit 'ge', got:\n%s", got)
		}
	})

	// upto /N where N == prefix length means only the prefix itself
	// (exact). "le 8" would be rejected by FRR (le == prefix-len), so we
	// render a bare prefix with no le/ge.
	t.Run("v4_upto_eq_plen_is_exact", func(t *testing.T) {
		got := New().generatePolicyOptions(uptoPolicyOptions("10.0.0.0/8", 8))
		if !strings.Contains(got, "ip prefix-list p-t1 seq 5 permit 10.0.0.0/8\n") {
			t.Errorf("want bare 'permit 10.0.0.0/8' (exact) line, got:\n%s", got)
		}
		if strings.Contains(got, "le ") || strings.Contains(got, "ge ") {
			t.Errorf("upto /8 on a /8 must be exact (no le/ge), got:\n%s", got)
		}
	})

	// Degrade-safe: an upto with no usable length (UptoLen 0) must fall
	// back to the orlonger-equivalent default and never emit an invalid
	// FRR line.
	t.Run("v4_upto_zero_degrades_to_default", func(t *testing.T) {
		got := New().generatePolicyOptions(uptoPolicyOptions("10.0.0.0/8", 0))
		if !strings.Contains(got, "ip prefix-list p-t1 seq 5 permit 10.0.0.0/8 le 32\n") {
			t.Errorf("UptoLen 0 must degrade to default 'le 32', got:\n%s", got)
		}
		if strings.Contains(got, "ge ") {
			t.Errorf("degrade path must not emit 'ge', got:\n%s", got)
		}
	})

	// upto /N where N < prefix-len (e.g. upto /4 on a /8) is nonsensical in
	// Junos (an EMPTY length range). It must fail-CLOSED — emit NO prefix-list
	// line (match-nothing) — NOT the open-ended "le 32" the earlier #2102 code
	// degraded to, which silently widened the match to base+all-more-specifics
	// (fail-open on a route-filter that gates route accept/redistribute).
	// Aligns with the #2525 fail-closed posture the sibling invalid
	// match-types already use (#4484 L-12). Skip emits no FRR-invalid line, so
	// the #2102 frr-reload-brick concern does not apply.
	t.Run("v4_upto_below_plen_fail_closed", func(t *testing.T) {
		got := New().generatePolicyOptions(uptoPolicyOptions("10.0.0.0/8", 4))
		if strings.Contains(got, "permit 10.0.0.0/8") {
			t.Errorf("UptoLen 4 (< plen 8) must emit NO permit line (fail-closed), got:\n%s", got)
		}
		if strings.Contains(got, "le 32") {
			t.Errorf("must NOT fail-open to 'le 32', got:\n%s", got)
		}
		if strings.Contains(got, "le 4") {
			t.Errorf("must NOT emit FRR-invalid 'le 4' (le < prefix-len), got:\n%s", got)
		}
	})

	// upto /N where N > family max (e.g. /40 on a v4 /8) is also nonsensical;
	// it must fail-CLOSED (no line) rather than degrade to the open-ended
	// "le 32" (#4484 L-12).
	t.Run("v4_upto_above_maxlen_fail_closed", func(t *testing.T) {
		got := New().generatePolicyOptions(uptoPolicyOptions("10.0.0.0/8", 40))
		if strings.Contains(got, "permit 10.0.0.0/8") {
			t.Errorf("UptoLen 40 (> v4 max 32) must emit NO permit line (fail-closed), got:\n%s", got)
		}
		if strings.Contains(got, "le 32") {
			t.Errorf("must NOT fail-open to 'le 32', got:\n%s", got)
		}
		if strings.Contains(got, "le 40") {
			t.Errorf("must NOT emit out-of-range 'le 40', got:\n%s", got)
		}
	})

	// v6 upto /N == prefix-len -> exact (bare prefix), the v6 twin of the
	// v4 ==plen case (Codex #2102 coverage gap).
	t.Run("v6_upto_eq_plen_is_exact", func(t *testing.T) {
		got := New().generatePolicyOptions(uptoPolicyOptions("2001:db8::/32", 32))
		if !strings.Contains(got, "ipv6 prefix-list p-t1 seq 5 permit 2001:db8::/32\n") {
			t.Errorf("v6 upto /32 on a /32 must be exact, got:\n%s", got)
		}
		if strings.Contains(got, "le ") || strings.Contains(got, "ge ") {
			t.Errorf("v6 ==plen must emit no le/ge, got:\n%s", got)
		}
	})

	// A /0 prefix with UptoLen 0 is the zero-value collision between
	// "unset length" and "plen 0". It must degrade to the orlonger
	// default (le 32), NOT silently render exact (Codex #2102 MAJOR #2).
	t.Run("v4_default_route_unset_upto_degrades_not_exact", func(t *testing.T) {
		got := New().generatePolicyOptions(uptoPolicyOptions("0.0.0.0/0", 0))
		if !strings.Contains(got, "ip prefix-list p-t1 seq 5 permit 0.0.0.0/0 le 32\n") {
			t.Errorf("/0 with unset upto must degrade to 'le 32', not exact, got:\n%s", got)
		}
	})

	// A /0 prefix with a real upto /24 still renders le 24 (the unset
	// guard must not block a legitimately-parsed length).
	t.Run("v4_default_route_upto24", func(t *testing.T) {
		got := New().generatePolicyOptions(uptoPolicyOptions("0.0.0.0/0", 24))
		if !strings.Contains(got, "ip prefix-list p-t1 seq 5 permit 0.0.0.0/0 le 24\n") {
			t.Errorf("/0 upto /24 must render 'le 24', got:\n%s", got)
		}
	})

	// Max-length host prefix: a /32 has no more-specifics, so "upto /N"
	// (any N) is just the prefix itself. The default "le 32" the switch
	// inherits would be FRR-INVALID (le == prefix-len) — this is the
	// Codex #2102 MAJOR #1 case. Must render bare exact, never "le 32".
	t.Run("v4_max_length_upto_below_plen_is_exact", func(t *testing.T) {
		got := New().generatePolicyOptions(uptoPolicyOptions("192.0.2.1/32", 31))
		if !strings.Contains(got, "ip prefix-list p-t1 seq 5 permit 192.0.2.1/32\n") {
			t.Errorf("/32 upto /31 must render bare exact, got:\n%s", got)
		}
		if strings.Contains(got, "le 32") {
			t.Errorf("/32 must NOT emit FRR-invalid 'le 32' (le == prefix-len), got:\n%s", got)
		}
	})

	t.Run("v6_max_length_upto_below_plen_is_exact", func(t *testing.T) {
		got := New().generatePolicyOptions(uptoPolicyOptions("2001:db8::1/128", 127))
		if !strings.Contains(got, "ipv6 prefix-list p-t1 seq 5 permit 2001:db8::1/128\n") {
			t.Errorf("/128 upto /127 must render bare exact, got:\n%s", got)
		}
		if strings.Contains(got, "le 128") {
			t.Errorf("/128 must NOT emit FRR-invalid 'le 128', got:\n%s", got)
		}
	})

	// upto /N just below the family max on a non-max prefix is still a
	// valid "le N" (plen < N < maxLen).
	t.Run("v4_upto_near_max", func(t *testing.T) {
		got := New().generatePolicyOptions(uptoPolicyOptions("10.0.0.0/8", 31))
		if !strings.Contains(got, "ip prefix-list p-t1 seq 5 permit 10.0.0.0/8 le 31\n") {
			t.Errorf("/8 upto /31 must render 'le 31', got:\n%s", got)
		}
	})
}

// TestRouteFilterUpto_MixedFamilyTerm renders a term that mixes a v4
// "upto" route-filter with a v6 route-filter (SMR #2102 cross-#2071
// coverage gap). As of #2607 a mixed-family route-filter term SPLITS
// into two route-map sequences — one per family — so BOTH families match
// (the pre-#2607 single term-level matcher silently dropped one family).
// The v4 entry lands in the `_v4` per-family list (FRR-valid "ip ... le
// 24") with its own `match ip address` line; the v6 entry lands in the
// `_v6` list (bare "ipv6 ...") with its own `match ipv6 address` line.
// Per-entry seq slots keep each route-filter's ORIGINAL index (v4 at idx
// 0 → seq 5, v6 at idx 1 → seq 10).
func TestRouteFilterUpto_MixedFamilyTerm(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{}, Communities: map[string]*config.CommunityDef{}, ASPaths: map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"p": {Name: "p", Terms: []*config.PolicyTerm{
				{
					Name: "t1",
					RouteFilters: []*config.RouteFilter{
						{Prefix: "10.0.0.0/8", MatchType: "upto", UptoLen: 24},
						{Prefix: "2001:db8::/32", MatchType: "exact"},
					},
					Action: "accept",
				},
			}, DefaultAction: "reject"},
		},
	}
	got := New().generatePolicyOptions(po)
	// v4 upto renders an FRR-valid bare "le 24" entry in the _v4 list.
	if !strings.Contains(got, "ip prefix-list p-t1_v4 seq 5 permit 10.0.0.0/8 le 24\n") {
		t.Errorf("v4 upto entry missing/wrong in mixed term:\n%s", got)
	}
	// v6 exact renders a bare ipv6 entry (no le/ge) in the _v6 list.
	if !strings.Contains(got, "ipv6 prefix-list p-t1_v6 seq 10 permit 2001:db8::/32\n") {
		t.Errorf("v6 exact entry missing/wrong in mixed term:\n%s", got)
	}
	// BOTH families are bound — one match line per family, each on its own
	// route-map sequence (the #2607 fix).
	if !strings.Contains(got, "match ip address prefix-list p-t1_v4\n") {
		t.Errorf("v4 match line missing in split mixed term:\n%s", got)
	}
	if !strings.Contains(got, "match ipv6 address prefix-list p-t1_v6\n") {
		t.Errorf("v6 match line missing in split mixed term:\n%s", got)
	}
	// No FRR-invalid line: neither a "ge" nor the over-matching "le 32".
	if strings.Contains(got, "ge ") {
		t.Errorf("mixed term must not emit 'ge', got:\n%s", got)
	}
	if strings.Contains(got, "10.0.0.0/8 le 32") {
		t.Errorf("v4 upto must be capped at /24, not the le 32 default, got:\n%s", got)
	}
}

// TestPolicyMixedFamilyRouteFilterSplit is the #2607 golden test. A single
// policy term carrying BOTH IPv4 and IPv6 route-filters (a legitimate
// dual-stack export/import term) must render so BOTH families match. The
// pre-#2607 renderer compressed the family into one term-level matchV6 and
// emitted a SINGLE `match ip|ipv6 address` line; the other family's
// prefix-list entries were written but never matched (FRR `match ip
// address` only matches IPv4, `match ipv6 address` only IPv6) → that family
// silently failed the term. Emitting BOTH match lines in ONE sequence is
// also wrong: FRR ANDs different match types within a route-map index, so a
// v4 route NOMATCHes the ipv6 clause and a v6 route NOMATCHes the ip clause
// → NEITHER matches. The correct structure is TWO route-map SEQUENCES (one
// per family), each with its own seq, single-family match line over a
// per-family prefix-list, and the full term body (set/action).
func TestPolicyMixedFamilyRouteFilterSplit(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{}, Communities: map[string]*config.CommunityDef{}, ASPaths: map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"DUAL": {Name: "DUAL", Terms: []*config.PolicyTerm{
				{
					Name: "t1",
					RouteFilters: []*config.RouteFilter{
						{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
						{Prefix: "2001:db8::/32", MatchType: "orlonger"},
					},
					LocalPreference:    200,
					HasLocalPreference: true,
					Action:             "accept",
				},
			}, DefaultAction: "reject"},
		},
	}
	got := New().generatePolicyOptions(po)

	// Two route-map permit sequences for the single term (the split), plus
	// the default-action deny. The single-matcher / both-in-one-sequence
	// regressions BOTH produce exactly one permit sequence → this count
	// FAILS on revert.
	if n := strings.Count(got, "route-map DUAL permit "); n != 2 {
		t.Fatalf("mixed-family term must emit 2 permit sequences (one per family), got %d:\n%s", n, got)
	}

	// v4 prefixes live in an `ip prefix-list` (the _v4 per-family list),
	// bound by `match ip address` in the v4 sequence.
	wantV4 := []string{
		"ip prefix-list DUAL-t1_v4 seq 5 permit 10.0.0.0/8 le 32\n",
		"match ip address prefix-list DUAL-t1_v4\n",
	}
	// v6 prefixes live in an `ipv6 prefix-list` (the _v6 list), bound by
	// `match ipv6 address` in the v6 sequence.
	wantV6 := []string{
		"ipv6 prefix-list DUAL-t1_v6 seq 10 permit 2001:db8::/32 le 128\n",
		"match ipv6 address prefix-list DUAL-t1_v6\n",
	}
	for _, w := range append(append([]string{}, wantV4...), wantV6...) {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in mixed-family render:\n%s", w, got)
		}
	}

	// The term body (set clause) must be present in BOTH sequences (a route
	// hits exactly one family sequence, so the action must be on each).
	if n := strings.Count(got, "set local-preference 200\n"); n != 2 {
		t.Errorf("set clause must appear in BOTH family sequences, got %d:\n%s", n, got)
	}

	// FAIL-ON-REVERT: the old single-matchV6 emission put both families'
	// entries in ONE list named `DUAL-t1` and emitted exactly one match
	// line (v4, the first family). Neither the combined list name nor a
	// cross-family match against it may appear.
	if strings.Contains(got, "prefix-list DUAL-t1 ") || strings.Contains(got, "prefix-list DUAL-t1\n") {
		t.Errorf("must NOT use the combined single-family list name DUAL-t1 (pre-#2607 bug):\n%s", got)
	}
	// The v6 entries must never be referenced by an `ip` (v4) match line,
	// nor v4 by an `ipv6` match line — the silent-fail the issue reports.
	if strings.Contains(got, "match ip address prefix-list DUAL-t1_v6") {
		t.Errorf("v6 list must not be bound by an IPv4 match line:\n%s", got)
	}
	if strings.Contains(got, "match ipv6 address prefix-list DUAL-t1_v4") {
		t.Errorf("v4 list must not be bound by an IPv6 match line:\n%s", got)
	}

	// Default-action deny follows the two split sequences at seq 30.
	if !strings.Contains(got, "route-map DUAL deny 30\n") {
		t.Errorf("default-action deny must follow the split term at seq 30:\n%s", got)
	}
}

// TestPolicySingleFamilyRouteFilterUnchanged is the #2607 no-churn control:
// a homogeneous (single-family) route-filter term must render EXACTLY as
// before the split — ONE sequence, the historical un-suffixed `<name>-<term>`
// prefix-list name, ONE match line. This guards the common case against any
// accidental always-split regression.
func TestPolicySingleFamilyRouteFilterUnchanged(t *testing.T) {
	// v4-only term.
	gotV4 := New().generatePolicyOptions(rfPolicyOptions(
		&config.RouteFilter{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
		&config.RouteFilter{Prefix: "172.16.0.0/12", MatchType: "exact"}))
	if !strings.Contains(gotV4, "ip prefix-list p-t1 seq 5 permit 10.0.0.0/8 le 32\n") {
		t.Errorf("v4-only term must keep the un-suffixed p-t1 list:\n%s", gotV4)
	}
	if !strings.Contains(gotV4, "match ip address prefix-list p-t1\n") {
		t.Errorf("v4-only term must emit one un-suffixed match line:\n%s", gotV4)
	}
	if strings.Contains(gotV4, "p-t1_v4") || strings.Contains(gotV4, "p-t1_v6") {
		t.Errorf("v4-only term must NOT split into per-family lists:\n%s", gotV4)
	}
	if n := strings.Count(gotV4, "route-map p permit "); n != 1 {
		t.Errorf("v4-only term must render ONE permit sequence, got %d:\n%s", n, gotV4)
	}

	// v6-only term.
	gotV6 := New().generatePolicyOptions(rfPolicyOptions(
		&config.RouteFilter{Prefix: "2001:db8::/32", MatchType: "orlonger"}))
	if !strings.Contains(gotV6, "ipv6 prefix-list p-t1 seq 5 permit 2001:db8::/32 le 128\n") {
		t.Errorf("v6-only term must keep the un-suffixed p-t1 list:\n%s", gotV6)
	}
	if !strings.Contains(gotV6, "match ipv6 address prefix-list p-t1\n") {
		t.Errorf("v6-only term must emit one un-suffixed match line:\n%s", gotV6)
	}
	if strings.Contains(gotV6, "p-t1_v4") || strings.Contains(gotV6, "p-t1_v6") {
		t.Errorf("v6-only term must NOT split into per-family lists:\n%s", gotV6)
	}
}

// TestPolicyMixedFamilyEndToEnd proves the family split propagates the
// whole compiler→render path. It uses the hierarchical (brace) config
// syntax via NewParser rather than the flat-set ParseSetCommand loop: a
// term legitimately carries MULTIPLE `from route-filter` clauses, but the
// flat-set AST merges repeated `route-filter` keys (the second `set ...
// route-filter <p2>` line overwrites the first in tree.SetPath) — a
// pre-existing AST limitation unrelated to #2607's render-layer fix. The
// brace parser keeps both route-filters as distinct child nodes, which is
// the real shape a committed dual-stack policy produces. (The flat-set
// mandate in CLAUDE.md targets flat-set *token grouping*; here both
// syntaxes feed the same typed config, and the multi-route-filter-per-term
// shape only survives the brace path.)
func TestPolicyMixedFamilyEndToEnd(t *testing.T) {
	src := `policy-options {
  policy-statement EXPORT-DUAL {
    term t1 {
      from {
        route-filter 10.0.0.0/8 orlonger;
        route-filter 2001:db8::/32 orlonger;
      }
      then accept;
    }
  }
}`
	tree, perr := config.NewParser(src).Parse()
	if len(perr) > 0 {
		t.Fatalf("parse errors: %v", perr)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	// Sanity: the compiler kept BOTH route-filters (else the render test
	// below would be vacuously single-family).
	if ps := cfg.PolicyOptions.PolicyStatements["EXPORT-DUAL"]; ps == nil || len(ps.Terms) != 1 || len(ps.Terms[0].RouteFilters) != 2 {
		t.Fatalf("expected one term with two route-filters, got %#v", cfg.PolicyOptions.PolicyStatements["EXPORT-DUAL"])
	}
	got := New().generatePolicyOptions(&cfg.PolicyOptions)
	if n := strings.Count(got, "route-map EXPORT-DUAL permit "); n != 2 {
		t.Fatalf("compiled dual-stack term must render 2 permit sequences, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "match ip address prefix-list EXPORT-DUAL-t1_v4\n") {
		t.Errorf("v4 family must be bound after compile+render:\n%s", got)
	}
	if !strings.Contains(got, "match ipv6 address prefix-list EXPORT-DUAL-t1_v6\n") {
		t.Errorf("v6 family must be bound after compile+render:\n%s", got)
	}
}

// rfPolicyOptions builds a one-term policy "p"/"t1" carrying the given
// route-filters (verbatim — no implicit upto length), for the #2103/#2105
// render tests. The prefix-list name the renderer derives is "p-t1".
func rfPolicyOptions(rfs ...*config.RouteFilter) *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"p": {
				Name: "p",
				Terms: []*config.PolicyTerm{
					{Name: "t1", RouteFilters: rfs, Action: "accept"},
				},
				DefaultAction: "reject",
			},
		},
	}
}

// TestRouteFilterLongerFRR covers #2103: the "longer" match-type must
// skip a max-length prefix (no more-specifics exist → empty set) rather
// than emit an FRR-invalid "ge plen+1 le maxLen" line, while still
// rendering the valid "ge plen+1 le maxLen" for every shorter prefix.
func TestRouteFilterLongerFRR(t *testing.T) {
	// #2103 core: /32 longer must emit NO "ip prefix-list ... permit"
	// entry (the empty set), but the term MUST still emit the "match ...
	// prefix-list" line referencing the (then-undefined) list name. In
	// FRR a match against an undefined prefix-list → NULL → RMAP_NOMATCH
	// (DENY), so the term matches nothing and stays fail-closed.
	// Suppressing the match line would leave a bare "permit <seq>" with no
	// match clauses, which FRR treats as match-ALL (Copilot #2110). The
	// list name itself must NEVER be materialised with zero entries — a
	// count==0 prefix-list is FRR PREFIX_PERMIT (match-ALL).
	t.Run("v4_max_length_longer_skips_entry_keeps_match", func(t *testing.T) {
		got := New().generatePolicyOptions(rfPolicyOptions(
			&config.RouteFilter{Prefix: "10.0.0.0/32", MatchType: "longer"}))
		if strings.Contains(got, "ge 33") {
			t.Errorf("/32 longer must NOT emit FRR-invalid 'ge 33', got:\n%s", got)
		}
		if strings.Contains(got, "permit 10.0.0.0/32") {
			t.Errorf("/32 longer must emit NO prefix-list entry, got:\n%s", got)
		}
		// The match line MUST be present (fail-closed via undefined list).
		if !strings.Contains(got, "match ip address prefix-list p-t1\n") {
			t.Errorf("all-skipped term MUST emit the match line (fail-closed), got:\n%s", got)
		}
		// But NO "ip prefix-list p-t1 ... permit" entry materialises the list.
		if strings.Contains(got, "ip prefix-list p-t1 seq") {
			t.Errorf("all-skipped term must NOT materialise a prefix-list entry, got:\n%s", got)
		}
	})

	t.Run("v6_max_length_longer_skips_entry_keeps_match", func(t *testing.T) {
		got := New().generatePolicyOptions(rfPolicyOptions(
			&config.RouteFilter{Prefix: "2001:db8::1/128", MatchType: "longer"}))
		if strings.Contains(got, "ge 129") {
			t.Errorf("/128 longer must NOT emit FRR-invalid 'ge 129', got:\n%s", got)
		}
		if strings.Contains(got, "permit 2001:db8::1/128") {
			t.Errorf("/128 longer must emit NO prefix-list entry, got:\n%s", got)
		}
		// Family is derived from the parseable (skipped) v6 entry → the
		// match line must be the v6 matcher, fail-closed.
		if !strings.Contains(got, "match ipv6 address prefix-list p-t1\n") {
			t.Errorf("all-skipped v6 term MUST emit the v6 match line, got:\n%s", got)
		}
		if strings.Contains(got, "ipv6 prefix-list p-t1 seq") {
			t.Errorf("all-skipped v6 term must NOT materialise a prefix-list entry, got:\n%s", got)
		}
	})

	// Boundary: /31 has exactly one more-specific (/32), so "longer"
	// renders the FRR-VALID "ge 32 le 32". The fix must NOT over-skip /31.
	t.Run("v4_slash31_longer_emits_ge32_le32", func(t *testing.T) {
		got := New().generatePolicyOptions(rfPolicyOptions(
			&config.RouteFilter{Prefix: "10.0.0.0/31", MatchType: "longer"}))
		if !strings.Contains(got, "ip prefix-list p-t1 seq 5 permit 10.0.0.0/31 ge 32 le 32\n") {
			t.Errorf("/31 longer must emit valid 'ge 32 le 32', got:\n%s", got)
		}
	})

	t.Run("v6_slash127_longer_emits_ge128_le128", func(t *testing.T) {
		got := New().generatePolicyOptions(rfPolicyOptions(
			&config.RouteFilter{Prefix: "2001:db8::/127", MatchType: "longer"}))
		if !strings.Contains(got, "ipv6 prefix-list p-t1 seq 5 permit 2001:db8::/127 ge 128 le 128\n") {
			t.Errorf("/127 longer must emit valid 'ge 128 le 128', got:\n%s", got)
		}
	})

	// Controls: ordinary prefixes are UNCHANGED by the fix.
	t.Run("v4_slash24_longer_unchanged", func(t *testing.T) {
		got := New().generatePolicyOptions(rfPolicyOptions(
			&config.RouteFilter{Prefix: "10.0.0.0/24", MatchType: "longer"}))
		if !strings.Contains(got, "ip prefix-list p-t1 seq 5 permit 10.0.0.0/24 ge 25 le 32\n") {
			t.Errorf("/24 longer must still emit 'ge 25 le 32', got:\n%s", got)
		}
	})

	t.Run("v6_slash64_longer_unchanged", func(t *testing.T) {
		got := New().generatePolicyOptions(rfPolicyOptions(
			&config.RouteFilter{Prefix: "2001:db8::/64", MatchType: "longer"}))
		if !strings.Contains(got, "ipv6 prefix-list p-t1 seq 5 permit 2001:db8::/64 ge 65 le 128\n") {
			t.Errorf("/64 longer must still emit 'ge 65 le 128', got:\n%s", got)
		}
	})

	// Mixed term (#2103/#2105 F1/F6): a skipped /32 longer at index 0
	// followed by a valid /24 longer at index 1. The /24 keeps its
	// seq 10 (gaps are FRR-legal; remaining entries are NOT renumbered),
	// and the term still emits a match line.
	t.Run("mixed_skipped_then_valid_keeps_seq_and_match", func(t *testing.T) {
		got := New().generatePolicyOptions(rfPolicyOptions(
			&config.RouteFilter{Prefix: "10.0.0.0/32", MatchType: "longer"},
			&config.RouteFilter{Prefix: "10.0.0.0/24", MatchType: "longer"}))
		if strings.Contains(got, "permit 10.0.0.0/32") {
			t.Errorf("index-0 /32 longer must be skipped, got:\n%s", got)
		}
		if !strings.Contains(got, "ip prefix-list p-t1 seq 10 permit 10.0.0.0/24 ge 25 le 32\n") {
			t.Errorf("index-1 /24 longer must keep seq 10, got:\n%s", got)
		}
		if !strings.Contains(got, "match ip address prefix-list p-t1\n") {
			t.Errorf("mixed term with a surviving entry must emit the match line, got:\n%s", got)
		}
	})

	// Mixed family (#2103/#2105 F6 → #2607): a skipped v4 /32 longer at
	// index 0 followed by a valid v6 entry. This is a genuinely
	// mixed-family term, so as of #2607 it SPLITS into a v4 sequence and a
	// v6 sequence. The v4 sequence carries only the (skipped) /32 longer →
	// no entry materialises in p-t1_v4, but the fail-closed match line
	// `match ip address prefix-list p-t1_v4` is still emitted (undefined
	// list → NOMATCH → DENY for v4 routes). The v6 sequence carries the
	// /64 orlonger → an `ipv6 prefix-list p-t1_v6` entry plus `match ipv6
	// address prefix-list p-t1_v6`. The two match lines reference DISJOINT
	// per-family lists, so neither can pick up an off-family entry.
	t.Run("mixed_family_splits_into_two_sequences", func(t *testing.T) {
		got := New().generatePolicyOptions(rfPolicyOptions(
			&config.RouteFilter{Prefix: "10.0.0.0/32", MatchType: "longer"},
			&config.RouteFilter{Prefix: "2001:db8::/64", MatchType: "orlonger"}))
		if !strings.Contains(got, "ipv6 prefix-list p-t1_v6 seq 10 permit 2001:db8::/64 le 128\n") {
			t.Errorf("v6 orlonger entry missing in _v6 list, got:\n%s", got)
		}
		if !strings.Contains(got, "match ipv6 address prefix-list p-t1_v6\n") {
			t.Errorf("v6 sequence match line missing, got:\n%s", got)
		}
		// The v4 sequence: all-skipped, but the fail-closed match line is
		// still emitted against the (undefined, hence NOMATCH) _v4 list.
		if !strings.Contains(got, "match ip address prefix-list p-t1_v4\n") {
			t.Errorf("v4 sequence fail-closed match line missing, got:\n%s", got)
		}
		// No v4 entry materialises (the /32 longer is the empty set).
		if strings.Contains(got, "ip prefix-list p-t1_v4 seq") {
			t.Errorf("skipped /32 longer must NOT materialise a v4 entry, got:\n%s", got)
		}
		// Two route-map sequences for the single term (seq 10 and 20),
		// plus the default-action deny at 30.
		if n := strings.Count(got, "route-map p permit "); n != 2 {
			t.Errorf("split mixed term must emit exactly 2 permit sequences, got %d:\n%s", n, got)
		}
	})
}

// TestRouteFilterOrlongerMaxLengthValid is the #2102/#2105 F2 control:
// "orlonger /32" renders a bare "le 32" (le == prefix-len), which is
// FRR-VALID (only strictly-less le/ge is rejected). It proves the #2103
// longer fix did NOT touch orlonger and documents the valid equality.
func TestRouteFilterOrlongerMaxLengthValid(t *testing.T) {
	got := New().generatePolicyOptions(rfPolicyOptions(
		&config.RouteFilter{Prefix: "10.0.0.0/32", MatchType: "orlonger"}))
	if !strings.Contains(got, "ip prefix-list p-t1 seq 5 permit 10.0.0.0/32 le 32\n") {
		t.Errorf("orlonger /32 must still emit valid 'le 32', got:\n%s", got)
	}
	if !strings.Contains(got, "match ip address prefix-list p-t1\n") {
		t.Errorf("orlonger /32 term must emit a match line, got:\n%s", got)
	}
}

// TestRouteFilterMalformedPrefixBelt covers the #2105 render-side
// belt-and-suspenders: a malformed prefix (which the commit validator
// rejects, but the lenient load/HA-sync path can still feed to the
// renderer) must NEVER produce an FRR prefix-list ENTRY. A lone
// malformed prefix still emits the match line (fail-closed via an
// undefined list → NOMATCH → DENY); a valid prefix alongside it
// survives.
func TestRouteFilterMalformedPrefixBelt(t *testing.T) {
	t.Run("lone_no_mask_emits_no_entry", func(t *testing.T) {
		got := New().generatePolicyOptions(rfPolicyOptions(
			&config.RouteFilter{Prefix: "10.0.0.0", MatchType: "exact"}))
		if strings.Contains(got, "permit 10.0.0.0") {
			t.Errorf("malformed prefix (no mask) must emit no permit line, got:\n%s", got)
		}
		if strings.Contains(got, "prefix-list p-t1 seq") {
			t.Errorf("lone malformed prefix must NOT materialise a prefix-list entry, got:\n%s", got)
		}
		if !strings.Contains(got, "address prefix-list p-t1\n") {
			t.Errorf("lone malformed prefix must still emit the fail-closed match line, got:\n%s", got)
		}
	})

	t.Run("lone_bad_mask_emits_no_entry", func(t *testing.T) {
		got := New().generatePolicyOptions(rfPolicyOptions(
			&config.RouteFilter{Prefix: "10.0.0.0/99", MatchType: "orlonger"}))
		if strings.Contains(got, "permit 10.0.0.0/99") {
			t.Errorf("out-of-range mask must emit no permit line, got:\n%s", got)
		}
		if strings.Contains(got, "prefix-list p-t1 seq") {
			t.Errorf("out-of-range mask must NOT materialise a prefix-list entry, got:\n%s", got)
		}
	})

	// Bad ADDRESS with an in-range MASK must also be skipped. A mask-only
	// check (Atoi on the mask) would pass these and emit an FRR-invalid
	// line; the belt uses net.ParseCIDR (same as the commit validator) so
	// the whole CIDR is validated, not just the mask.
	t.Run("bad_octet_in_range_mask_emits_nothing", func(t *testing.T) {
		for _, bad := range []string{
			"999.999.999.999/24", // out-of-range v4 octets, valid mask
			"10.0.0.0.0/8",       // five octets
			"abcd/16",            // not an address at all
		} {
			got := New().generatePolicyOptions(rfPolicyOptions(
				&config.RouteFilter{Prefix: bad, MatchType: "orlonger"}))
			if strings.Contains(got, "permit "+bad) {
				t.Errorf("bad-address prefix %q must emit no permit line, got:\n%s", bad, got)
			}
			// No prefix-list ENTRY materialises (a count==0 list is FRR
			// match-ALL); but the term still emits the match line so it is
			// fail-closed (undefined list → NOMATCH → DENY).
			if strings.Contains(got, "prefix-list p-t1 seq") {
				t.Errorf("lone bad-address prefix %q must NOT materialise a prefix-list entry, got:\n%s", bad, got)
			}
			if !strings.Contains(got, "match ") || !strings.Contains(got, "address prefix-list p-t1\n") {
				t.Errorf("lone bad-address prefix %q must still emit the fail-closed match line, got:\n%s", bad, got)
			}
		}
	})

	// A colon-bearing garbage token (the isV6 heuristic would treat it as
	// v6) with an in-range mask must NOT slip through as an "ipv6
	// prefix-list ... permit foo:bar/24" line. net.ParseCIDR rejects it.
	t.Run("colon_garbage_emits_nothing", func(t *testing.T) {
		for _, bad := range []string{"foo:bar/24", "1:2:3/30"} {
			got := New().generatePolicyOptions(rfPolicyOptions(
				&config.RouteFilter{Prefix: bad, MatchType: "orlonger"}))
			if strings.Contains(got, "permit "+bad) {
				t.Errorf("colon-garbage prefix %q must emit no permit line, got:\n%s", bad, got)
			}
		}
	})

	// A valid v6 prefix alongside a malformed "v4-ish" index-0 prefix
	// ("garbage" has no colon → the family heuristic buckets it v4). As of
	// #2607 the term is mixed-family (one v4-bucketed, one v6) and SPLITS:
	// the v4 sequence carries only the skipped "garbage" → no entry, but a
	// fail-closed `match ip address prefix-list p-t1_v4` line; the v6
	// sequence carries the valid /64 → an entry in p-t1_v6 plus a
	// `match ipv6 address prefix-list p-t1_v6` line.
	t.Run("malformed_index0_then_valid_v6_splits", func(t *testing.T) {
		got := New().generatePolicyOptions(rfPolicyOptions(
			&config.RouteFilter{Prefix: "garbage", MatchType: "exact"},
			&config.RouteFilter{Prefix: "2001:db8::/64", MatchType: "exact"}))
		if !strings.Contains(got, "ipv6 prefix-list p-t1_v6 seq 10 permit 2001:db8::/64\n") {
			t.Errorf("valid v6 entry must survive in _v6 list, got:\n%s", got)
		}
		if !strings.Contains(got, "match ipv6 address prefix-list p-t1_v6\n") {
			t.Errorf("v6 sequence match line missing, got:\n%s", got)
		}
		if !strings.Contains(got, "match ip address prefix-list p-t1_v4\n") {
			t.Errorf("v4 sequence fail-closed match line missing, got:\n%s", got)
		}
		if strings.Contains(got, "permit garbage") {
			t.Errorf("malformed index-0 prefix must be skipped, got:\n%s", got)
		}
	})

	// A valid v6 /64 (orlonger) must NOT be belt-skipped — proves the
	// belt does not false-skip well-formed prefixes.
	t.Run("valid_prefix_not_false_skipped", func(t *testing.T) {
		got := New().generatePolicyOptions(rfPolicyOptions(
			&config.RouteFilter{Prefix: "2001:db8::/64", MatchType: "orlonger"}))
		if !strings.Contains(got, "ipv6 prefix-list p-t1 seq 5 permit 2001:db8::/64 le 128\n") {
			t.Errorf("valid v6 /64 orlonger must be emitted, got:\n%s", got)
		}
	})
}

func TestGenerateRoutesBlackhole(t *testing.T) {
	m := New()
	tmpDir := t.TempDir()
	m.frrConf = filepath.Join(tmpDir, "frr.conf")
	os.WriteFile(m.frrConf, []byte(""), 0644)

	fc := &FullConfig{
		GenerateRoutes: []*config.GenerateRoute{
			{Prefix: "192.168.0.0/16", Discard: true},
			{Prefix: "2001:db8::/32"},
		},
	}
	_ = m.ApplyFull(fc) // reload may fail without vtysh
	data, _ := os.ReadFile(m.frrConf)
	got := string(data)
	if !strings.Contains(got, "ip route 192.168.0.0/16 blackhole") {
		t.Errorf("missing IPv4 blackhole route in:\n%s", got)
	}
	if !strings.Contains(got, "ipv6 route 2001:db8::/32 blackhole") {
		t.Errorf("missing IPv6 blackhole route in:\n%s", got)
	}
}

func TestInterfaceBandwidthFRR(t *testing.T) {
	m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf")}
	os.WriteFile(m.frrConf, []byte("log syslog informational\n"), 0644)

	fc := &FullConfig{
		InterfaceBandwidths: map[string]uint64{
			"wan0":   1000000000, // 1Gbps
			"trust0": 100000000,  // 100Mbps
		},
	}

	got := m.generateInterfaceSettings(fc)
	// Should contain bandwidth in kbps
	if !strings.Contains(got, "interface trust0\n bandwidth 100000\n") {
		t.Errorf("missing trust0 bandwidth, got:\n%s", got)
	}
	if !strings.Contains(got, "interface wan0\n bandwidth 1000000\n") {
		t.Errorf("missing wan0 bandwidth, got:\n%s", got)
	}
}

func TestPointToPointFRR(t *testing.T) {
	m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf")}
	os.WriteFile(m.frrConf, []byte("log syslog informational\n"), 0644)

	fc := &FullConfig{
		InterfacePointToPoint: map[string]bool{
			"gr-0/0/0": true,
		},
	}

	got := m.generateInterfaceSettings(fc)
	if !strings.Contains(got, "interface gr-0/0/0\n ip ospf network point-to-point\n") {
		t.Errorf("missing point-to-point, got:\n%s", got)
	}
}

func TestPointToPointSkipWithExplicitOSPFType(t *testing.T) {
	m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf")}
	os.WriteFile(m.frrConf, []byte("log syslog informational\n"), 0644)

	// If OSPF has an explicit network-type for the interface, skip p2p from interface settings
	fc := &FullConfig{
		OSPF: &config.OSPFConfig{
			Areas: []*config.OSPFArea{
				{
					ID: "0.0.0.0",
					Interfaces: []*config.OSPFInterface{
						{Name: "gr-0/0/0", NetworkType: "broadcast"},
					},
				},
			},
		},
		InterfacePointToPoint: map[string]bool{
			"gr-0/0/0": true,
		},
	}

	got := m.generateInterfaceSettings(fc)
	// Should NOT contain point-to-point since OSPF has explicit broadcast type
	if strings.Contains(got, "ip ospf network point-to-point") {
		t.Errorf("should not emit p2p when OSPF has explicit network-type, got:\n%s", got)
	}
}

func TestBandwidthAndPointToPointCombined(t *testing.T) {
	m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf")}
	os.WriteFile(m.frrConf, []byte("log syslog informational\n"), 0644)

	fc := &FullConfig{
		InterfaceBandwidths: map[string]uint64{
			"gr-0/0/0": 10000000, // 10Mbps
		},
		InterfacePointToPoint: map[string]bool{
			"gr-0/0/0": true,
		},
	}

	got := m.generateInterfaceSettings(fc)
	if !strings.Contains(got, "interface gr-0/0/0\n") {
		t.Errorf("missing interface block, got:\n%s", got)
	}
	if !strings.Contains(got, " bandwidth 10000\n") {
		t.Errorf("missing bandwidth 10000, got:\n%s", got)
	}
	if !strings.Contains(got, " ip ospf network point-to-point\n") {
		t.Errorf("missing point-to-point, got:\n%s", got)
	}
}

func TestDHCPRoutesSuppressedByStaticDefault(t *testing.T) {
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	os.WriteFile(m.frrConf, []byte(""), 0644)

	// With a static default route, DHCP IPv4 default should be suppressed
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{
			{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
		},
		DHCPRoutes: []DHCPRoute{
			{Gateway: "10.0.100.1"},
		},
	}
	_ = m.ApplyFull(fc)
	data, _ := os.ReadFile(m.frrConf)
	got := string(data)

	if !strings.Contains(got, "ip route 0.0.0.0/0 172.16.50.1") {
		t.Errorf("missing static default route in:\n%s", got)
	}
	if strings.Contains(got, "10.0.100.1") {
		t.Errorf("DHCP default route should be suppressed when static default exists, got:\n%s", got)
	}
}

func TestDHCPRoutesNotSuppressedWithoutStaticDefault(t *testing.T) {
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	os.WriteFile(m.frrConf, []byte(""), 0644)

	// Without a static default route, DHCP default should be emitted
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{
			{Destination: "10.0.0.0/8", NextHops: []config.NextHopEntry{{Address: "192.168.1.1"}}},
		},
		DHCPRoutes: []DHCPRoute{
			{Gateway: "10.0.100.1"},
		},
	}
	_ = m.ApplyFull(fc)
	data, _ := os.ReadFile(m.frrConf)
	got := string(data)

	if !strings.Contains(got, "ip route 0.0.0.0/0 10.0.100.1 200") {
		t.Errorf("DHCP default should be present without static default, got:\n%s", got)
	}
}

func TestDHCPRoutesIPv6SuppressedByStaticDefault(t *testing.T) {
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	os.WriteFile(m.frrConf, []byte(""), 0644)

	// IPv6 static default suppresses IPv6 DHCP, but IPv4 DHCP remains
	fc := &FullConfig{
		Inet6StaticRoutes: []*config.StaticRoute{
			{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "fe80::1", Interface: "wan0"}}},
		},
		DHCPRoutes: []DHCPRoute{
			{Gateway: "10.0.100.1"},                                // IPv4 — should remain
			{Gateway: "fe80::gw", Interface: "eth0", IsIPv6: true}, // IPv6 — should be suppressed
		},
	}
	_ = m.ApplyFull(fc)
	data, _ := os.ReadFile(m.frrConf)
	got := string(data)

	if !strings.Contains(got, "ip route 0.0.0.0/0 10.0.100.1 200") {
		t.Errorf("IPv4 DHCP route should remain when only IPv6 default exists, got:\n%s", got)
	}
	if strings.Contains(got, "fe80::gw") {
		t.Errorf("IPv6 DHCP route should be suppressed when IPv6 static default exists, got:\n%s", got)
	}
}

// TestDHCPRoutesIPv4BindInterface verifies that a DHCP-learned IPv4 default
// route binds to the originating interface when the lease records one,
// mirroring the IPv6 branch. In multi-WAN / shared-gateway-IP deployments an
// unbound `ip route 0.0.0.0/0 <gw> 200` leaves the kernel unable to pick the
// correct egress (#2547). This assertion FAILS against master, which emitted
// the gateway-only form.
func TestDHCPRoutesIPv4BindInterface(t *testing.T) {
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	os.WriteFile(m.frrConf, []byte(""), 0644)

	fc := &FullConfig{
		DHCPRoutes: []DHCPRoute{
			{Gateway: "10.0.100.1", Interface: "ge-0-0-3"},
		},
	}
	_ = m.ApplyFull(fc)
	data, _ := os.ReadFile(m.frrConf)
	got := string(data)

	if !strings.Contains(got, "ip route 0.0.0.0/0 10.0.100.1 ge-0-0-3 200\n") {
		t.Errorf("DHCP IPv4 default route should bind the originating interface, got:\n%s", got)
	}
}

// TestDHCPRoutesIPv4NoInterfaceUnbound verifies backward compatibility: a DHCP
// IPv4 lease without a recorded interface still renders the gateway-only form.
func TestDHCPRoutesIPv4NoInterfaceUnbound(t *testing.T) {
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	os.WriteFile(m.frrConf, []byte(""), 0644)

	fc := &FullConfig{
		DHCPRoutes: []DHCPRoute{
			{Gateway: "10.0.100.1"},
		},
	}
	_ = m.ApplyFull(fc)
	data, _ := os.ReadFile(m.frrConf)
	got := string(data)

	if !strings.Contains(got, "ip route 0.0.0.0/0 10.0.100.1 200\n") {
		t.Errorf("DHCP IPv4 default without interface should render gateway-only form, got:\n%s", got)
	}
}

// TestDHCPClasslessRoutesNotSuppressedByStaticDefault locks in the #4118 fix:
// an RFC 3442 classless static route (option 121, carried on a DHCPRoute with a
// non-empty Destination) is MORE-SPECIFIC and must be emitted even when a
// configured static default exists — only the DHCP default route is suppressed
// by a static default. RED-on-revert: without the Destination field the
// classless route would be rendered as (or suppressed like) the default route.
func TestDHCPClasslessRoutesNotSuppressedByStaticDefault(t *testing.T) {
	m := New()
	m.frrConf = filepath.Join(t.TempDir(), "frr.conf")
	os.WriteFile(m.frrConf, []byte(""), 0644)

	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{
			{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
		},
		DHCPRoutes: []DHCPRoute{
			// DHCP default — suppressed by the static default.
			{Gateway: "192.0.2.1", Interface: "ge-0-0-3"},
			// Classless static route — must survive.
			{Destination: "10.20.0.0/16", Gateway: "192.0.2.9", Interface: "ge-0-0-3"},
		},
	}
	_ = m.ApplyFull(fc)
	data, _ := os.ReadFile(m.frrConf)
	got := string(data)

	if !strings.Contains(got, "ip route 10.20.0.0/16 192.0.2.9 ge-0-0-3 200\n") {
		t.Errorf("classless static route missing (must not be suppressed by static default), got:\n%s", got)
	}
	if strings.Contains(got, "ip route 0.0.0.0/0 192.0.2.1") {
		t.Errorf("DHCP default should be suppressed by the static default, got:\n%s", got)
	}
	if !strings.Contains(got, "ip route 0.0.0.0/0 172.16.50.1") {
		t.Errorf("static default route missing, got:\n%s", got)
	}
}

func TestPerInstanceInet6StaticRoutes(t *testing.T) {
	m := New()
	m.frrConf = t.TempDir() + "/frr.conf"
	fc := &FullConfig{
		Instances: []InstanceConfig{
			{
				VRFName: "vrf-ATT",
				Inet6StaticRoutes: []*config.StaticRoute{
					{
						Destination: "::/0",
						NextHops:    []config.NextHopEntry{{Address: "fe80::2d0:f6ff:feda:c180", Interface: "wan0"}},
					},
				},
			},
		},
	}
	_ = m.ApplyFull(fc)
	data, _ := os.ReadFile(m.frrConf)
	got := string(data)
	if !strings.Contains(got, "ipv6 route ::/0 fe80::2d0:f6ff:feda:c180 wan0 vrf vrf-ATT") {
		t.Errorf("expected per-VRF IPv6 static route, got:\n%s", got)
	}
}

// #1798 belt test: BGP free-text values (neighbor description,
// password) and IGP auth keys must not inject extra frr.conf lines
// even if commit-time validation were bypassed.
func TestGenerateProtocols_NewlineFreeTextDoesNotInject(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			{
				Address:      "10.0.0.1",
				PeerAS:       65001,
				Description:  "peer\nno router bgp 65000",
				AuthPassword: "pw\nagentx",
			},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "no router bgp 65000" || trimmed == "agentx" {
			t.Fatalf("injected frr.conf line leaked:\n%s", got)
		}
	}
	if !strings.Contains(got, " neighbor 10.0.0.1 description peer no router bgp 65000\n") {
		t.Errorf("sanitized description missing:\n%s", got)
	}
	// #9050 REVISED THIS ASSERTION, and the revision is the point.
	//
	// It used to require that the sanitized password WAS emitted as
	// `password pw agentx`. That satisfied #1798 -- no injected line -- while
	// leaving a value that vtysh reads as TWO tokens. The belt collapsed a
	// newline into a space and thereby manufactured, for an auth secret, the
	// very splittable line #9050 is about. For a DESCRIPTION or an as-path
	// regex a space is legitimate and the assertion above still holds; for an
	// auth secret it is not, and the render now omits the line rather than
	// emitting a token FRR would either truncate to `pw` (a silently weakened
	// secret) or refuse -- and a refused line fails the whole frr-reload, which
	// takes down every protocol on the box rather than one adjacency.
	if strings.Contains(got, " neighbor 10.0.0.1 password ") {
		t.Errorf("a password that is not a single vtysh token was emitted:\n%s", got)
	}
}

// --- #2071 / #2607: from prefix-list match clause must honor the
// prefix-list's address family. generatePolicyOptions previously emitted
// "match ip address prefix-list" unconditionally, so an IPv6 prefix-list
// referenced by `from prefix-list` was a silent no-op in an IPv6
// routing-policy context (OSPFv3 export, BGP inet6). #2071 made a
// single-family list emit its one family-correct matcher; #2607 extends
// this so a MIXED v4+v6 list binds BOTH families (one match line per family
// in its own route-map sequence) instead of collapsing to ipv6 and silently
// dropping every v4 route.

func policyOptionsWithPrefixListTerm(plName string, prefixes []string, withRouteFilter bool) *config.PolicyOptionsConfig {
	term := &config.PolicyTerm{
		Name:       "t1",
		PrefixList: []string{plName},
		Action:     "accept",
	}
	if withRouteFilter {
		// v4 route-filter co-resident with the prefix-list in the SAME
		// term — exercises the no-term-body-duplication invariant.
		term.RouteFilters = []*config.RouteFilter{
			{Prefix: "192.168.50.0/24", MatchType: "exact"},
		}
	}
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"p": {
				Name:  "p",
				Terms: []*config.PolicyTerm{term},
			},
		},
	}
	if prefixes != nil {
		po.PrefixLists[plName] = &config.PrefixList{Name: plName, Prefixes: prefixes}
	}
	return po
}

func TestPrefixListMatch_IPv4(t *testing.T) {
	m := New()
	po := policyOptionsWithPrefixListTerm("v4list", []string{"10.0.0.0/8", "172.16.0.0/12"}, false)
	got := m.generatePolicyOptions(po)
	// Byte-identical to pre-fix render: the exact IPv4 match line.
	if !strings.Contains(got, " match ip address prefix-list v4list\n") {
		t.Errorf("v4 prefix-list: missing exact `match ip address prefix-list v4list` in:\n%s", got)
	}
	if strings.Contains(got, "match ipv6 address prefix-list v4list") {
		t.Errorf("v4 prefix-list: must NOT emit the IPv6 matcher in:\n%s", got)
	}
}

func TestPrefixListMatch_IPv6(t *testing.T) {
	m := New()
	po := policyOptionsWithPrefixListTerm("v6list", []string{"2001:db8::/32", "2001:559:8585::/48"}, false)
	got := m.generatePolicyOptions(po)
	// This assertion FAILS against pre-fix code (which emitted `match ip
	// address`): non-tautological.
	if !strings.Contains(got, " match ipv6 address prefix-list v6list\n") {
		t.Errorf("v6 prefix-list: missing `match ipv6 address prefix-list v6list` in:\n%s", got)
	}
	if strings.Contains(got, "match ip address prefix-list v6list") {
		t.Errorf("v6 prefix-list: must NOT emit the IPv4 matcher in:\n%s", got)
	}
}

func TestPrefixListMatch_Mixed_BindsBothFamilies_2607(t *testing.T) {
	m := New()
	// #2607: a mixed v4+v6 referenced list must bind BOTH families. FRR ANDs
	// match clauses within one route-map index (a v4 route NOMATCHes the ipv6
	// clause and vice versa → AND-deny for both), so the mixed list expands into
	// a `match ip` sequence and a `match ipv6` sequence — mirroring the #2642
	// one-sequence-per-OR-value split (a mixed list is exactly "(in v4 half) OR
	// (in v6 half)"). Pre-#2607 it collapsed to a lone ipv6 matcher, silently
	// dropping every IPv4 route.
	po := policyOptionsWithPrefixListTerm("mixed", []string{"10.0.0.0/8", "2001:db8::/32"}, false)
	got := m.generatePolicyOptions(po)
	if !strings.Contains(got, " match ip address prefix-list mixed\n") {
		t.Errorf("mixed prefix-list: missing the IPv4 matcher (v4 routes would silently fail the term) in:\n%s", got)
	}
	if !strings.Contains(got, " match ipv6 address prefix-list mixed\n") {
		t.Errorf("mixed prefix-list: missing the IPv6 matcher in:\n%s", got)
	}
	// The two matchers live in SEPARATE sequences (FRR ANDs within one index).
	if !strings.Contains(got, "route-map p permit 10\n") || !strings.Contains(got, "route-map p permit 20\n") {
		t.Errorf("mixed prefix-list: want two term sequences (permit 10 + permit 20), one per family, in:\n%s", got)
	}
}

func TestPrefixListMatch_CoResidentRouteFilter_2607(t *testing.T) {
	m := New()
	// Term with BOTH a v4 route-filter and a mixed prefix-list. Post-#2607 the
	// mixed list expands per-family, so the term emits two sequences: the v4
	// half co-resides with the v4 route-filter (same FRR type → the from-
	// prefix-list v4 entries render as an ACCESS-LIST so FRR ANDs them, #5730),
	// and the v6 half ANDs `match ipv6 address prefix-list mixed` with the v4
	// route-filter — a distinct type, off-family unsatisfiable, emitted not
	// dropped (#5702). The route-filter inline definition is re-emitted per
	// sequence (idempotent in FRR), like the existing #2642 OR-split.
	po := policyOptionsWithPrefixListTerm("mixed", []string{"10.0.0.0/8", "2001:db8::/32"}, true)
	got := m.generatePolicyOptions(po)
	if !strings.Contains(got, " match ip address prefix-list p-t1\n") {
		t.Errorf("co-resident: route-filter v4 matcher missing in:\n%s", got)
	}
	// v4 half of the mixed list rendered as an access-list (#5730), not a
	// colliding `match ip address prefix-list mixed`.
	ipACL := routeFilterACLName("mixed", "ip")
	if !strings.Contains(got, "access-list "+ipACL+" seq 5 permit 10.0.0.0/8 exact-match\n") {
		t.Errorf("co-resident: mixed list v4 half must render as an access-list (#5730) in:\n%s", got)
	}
	if !strings.Contains(got, " match ip address "+ipACL+"\n") {
		t.Errorf("co-resident: missing the access-list match for the mixed v4 half in:\n%s", got)
	}
	// v6 half still emitted (off-family AND, #5702).
	if !strings.Contains(got, " match ipv6 address prefix-list mixed\n") {
		t.Errorf("co-resident: mixed list v6 half must still be emitted in:\n%s", got)
	}
	// Two term sequences (one per mixed-list family).
	if !strings.Contains(got, "route-map p permit 10\n") || !strings.Contains(got, "route-map p permit 20\n") {
		t.Errorf("co-resident: want two term sequences (one per family) in:\n%s", got)
	}
}

func TestPrefixListMatch_UnknownName_DefaultsIPv4(t *testing.T) {
	m := New()
	// Term references a prefix-list that is not defined (nil prefixes).
	// Falls back to the IPv4 matcher — byte-identical to pre-fix render,
	// no panic.
	po := policyOptionsWithPrefixListTerm("ghost", nil, false)
	got := m.generatePolicyOptions(po)
	if !strings.Contains(got, " match ip address prefix-list ghost\n") {
		t.Errorf("unknown prefix-list: must default to `match ip address prefix-list ghost` in:\n%s", got)
	}
	if strings.Contains(got, "match ipv6 address prefix-list ghost") {
		t.Errorf("unknown prefix-list: must NOT emit the IPv6 matcher in:\n%s", got)
	}
}

// TestPrefixListMatch_EndToEnd_FlatSet drives the full flat-set ->
// compile -> render path, honoring the CLAUDE.md rule to use
// ParseSetCommand + tree.SetPath (NOT NewParser). It lives in package frr
// (generatePolicyOptions is unexported) and inlines its own compile loop
// (config.buildTree is a package-config test helper, unreachable here).
func TestPrefixListMatch_EndToEnd_FlatSet(t *testing.T) {
	cmds := []string{
		"set policy-options prefix-list v6nets 2001:db8::/32",
		"set policy-options policy-statement p term t1 from prefix-list v6nets",
		"set policy-options policy-statement p term t1 then accept",
	}
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	m := New()
	// PolicyOptions is a value field — pass its address.
	got := m.generatePolicyOptions(&cfg.PolicyOptions)
	if !strings.Contains(got, " match ipv6 address prefix-list v6nets\n") {
		t.Errorf("end-to-end: v6 prefix-list compiled+rendered must emit the IPv6 matcher, got:\n%s", got)
	}
	if strings.Contains(got, "match ip address prefix-list v6nets") {
		t.Errorf("end-to-end: must NOT emit the IPv4 matcher for a v6 list, got:\n%s", got)
	}
}

// TestGeneratePolicyOptionsPrefixLengthRange verifies the #2525 fix: a
// route-filter "prefix-length-range /low-/high" renders the FRR bounded
// length range "ge low le high", NOT the pre-fix silent open-ended fall-through
// ("le 32" / "le 128") that leaked/dropped the operator's constraint.
//
// Fail-on-revert: revert the renderer's prefix-length-range arm so the entry
// falls through to the pre-switch default "le 32" — the "ge 16 le 24" assertion
// fails AND the "must NOT contain le 32 open-ended" assertion fires.
func TestGeneratePolicyOptionsPrefixLengthRange(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"IMPORT-RANGE": {
				Name: "IMPORT-RANGE",
				Terms: []*config.PolicyTerm{
					{
						Name:   "v4",
						Action: "accept",
						RouteFilters: []*config.RouteFilter{
							{Prefix: "10.0.0.0/8", MatchType: "prefix-length-range", RangeLow: 16, RangeHigh: 24},
						},
					},
					{
						Name:   "v6",
						Action: "accept",
						RouteFilters: []*config.RouteFilter{
							{Prefix: "2001:db8::/32", MatchType: "prefix-length-range", RangeLow: 48, RangeHigh: 64},
						},
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	wantV4 := "ip prefix-list IMPORT-RANGE-v4 seq 5 permit 10.0.0.0/8 ge 16 le 24"
	if !strings.Contains(got, wantV4) {
		t.Errorf("v4 prefix-length-range: missing %q in:\n%s", wantV4, got)
	}
	wantV6 := "ipv6 prefix-list IMPORT-RANGE-v6 seq 5 permit 2001:db8::/32 ge 48 le 64"
	if !strings.Contains(got, wantV6) {
		t.Errorf("v6 prefix-length-range: missing %q in:\n%s", wantV6, got)
	}
	// The bug was a silent open-ended "le 32"/"le 128" fall-through. With the
	// fix the bounded range never renders an open-ended le on the base prefix.
	if strings.Contains(got, "10.0.0.0/8 le 32") {
		t.Errorf("v4 range leaked the open-ended le 32 fall-through (#2525):\n%s", got)
	}
	if strings.Contains(got, "2001:db8::/32 le 128") {
		t.Errorf("v6 range leaked the open-ended le 128 fall-through (#2525):\n%s", got)
	}
	// The match line must still be emitted so the route-map references the list.
	if !strings.Contains(got, "match ip address prefix-list IMPORT-RANGE-v4") {
		t.Errorf("v4 match line missing:\n%s", got)
	}
	if !strings.Contains(got, "match ipv6 address prefix-list IMPORT-RANGE-v6") {
		t.Errorf("v6 match line missing:\n%s", got)
	}
}

// TestGeneratePolicyOptionsPrefixLengthRangeAtOrBelowBaseSkipped verifies the
// #2525 lenient-path guard: a prefix-length-range whose low bound is AT or
// BELOW the base prefix length (e.g. /8-/24 on a /8, or /4-/24) is rejected at
// commit by the strict gate — but on the tolerant load/peer-sync path that
// reject is downgraded to a warning (#1960) and the stored bad range reaches
// the renderer. The renderer MUST skip the entry (match-nothing) rather than
// emit `ge 8 le 24` / `ge 4 le 24`, which FRR rejects ("len < ge-value") and
// which would fail the whole frr-reload batch (#1880-class). Fail-on-revert:
// remove the `RangeLow > baseLen` renderer floor and the entry emits
// `ge 8 le 24` — this test fails.
func TestGeneratePolicyOptionsPrefixLengthRangeAtOrBelowBaseSkipped(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{
						Name:   "atbase",
						Action: "accept",
						RouteFilters: []*config.RouteFilter{
							{Prefix: "10.0.0.0/8", MatchType: "prefix-length-range", RangeLow: 8, RangeHigh: 24},
						},
					},
					{
						Name:   "belowbase",
						Action: "accept",
						RouteFilters: []*config.RouteFilter{
							{Prefix: "10.0.0.0/8", MatchType: "prefix-length-range", RangeLow: 4, RangeHigh: 24},
						},
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	// No `ge <= base` line may be emitted for either term.
	for _, bad := range []string{"ge 8 le 24", "ge 4 le 24"} {
		if strings.Contains(got, bad) {
			t.Errorf("emitted FRR-invalid %q (ge <= base prefix) — would brick frr-reload (#2525/#1880):\n%s", bad, got)
		}
	}
	// The entries are skipped, so no prefix-list line exists; the match line is
	// still emitted (fail-closed RMAP_NOMATCH).
	if strings.Contains(got, "prefix-list P-atbase seq") || strings.Contains(got, "prefix-list P-belowbase seq") {
		t.Errorf("at/below-base range must emit NO prefix-list line:\n%s", got)
	}
	if !strings.Contains(got, "match ip address prefix-list P-atbase") {
		t.Errorf("at-base term must still emit a match line (fail-closed):\n%s", got)
	}
}

// TestGeneratePolicyOptionsThroughSkipped verifies that the FRR-unsupported
// "through" match-type (which only reaches the renderer on the tolerant
// load/peer-sync path — the strict commit gate rejects it) renders NO
// prefix-list line and NEVER the open-ended "le 32" fall-through (#2525). The
// match line is still emitted, so the term resolves to RMAP_NOMATCH (DENY) —
// fail-closed, not a silent permit.
func TestGeneratePolicyOptionsThroughSkipped(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{
						Name:   "t1",
						Action: "accept",
						RouteFilters: []*config.RouteFilter{
							{Prefix: "10.0.0.0/8", MatchType: "through", ThroughPrefix: "10.1.0.0/16"},
						},
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	if strings.Contains(got, "prefix-list P-t1 seq") {
		t.Errorf("through entry must emit NO prefix-list line:\n%s", got)
	}
	if strings.Contains(got, "10.0.0.0/8 le 32") {
		t.Errorf("through entry leaked the open-ended le 32 fall-through (#2525):\n%s", got)
	}
	// Fail-closed: the match line referencing the (now-empty) list is still
	// emitted, so FRR resolves it to RMAP_NOMATCH (DENY).
	if !strings.Contains(got, "match ip address prefix-list P-t1") {
		t.Errorf("through term must still emit a match line (fail-closed DENY):\n%s", got)
	}
}

// TestGeneratePolicyOptionsMatchTypesRegression locks the existing match-type
// renderings (exact / longer / orlonger / upto) so the #2525 switch rework did
// not break them.
func TestGeneratePolicyOptionsMatchTypesRegression(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "exact", Action: "accept", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}},
					{Name: "longer", Action: "accept", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "longer"}}},
					{Name: "orlong", Action: "accept", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}},
					{Name: "upto", Action: "accept", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "upto", UptoLen: 24}}},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	checks := []string{
		"ip prefix-list P-exact seq 5 permit 10.0.0.0/8\n", // exact: bare prefix, no ge/le
		"ip prefix-list P-longer seq 5 permit 10.0.0.0/8 ge 9 le 32",
		"ip prefix-list P-orlong seq 5 permit 10.0.0.0/8 le 32",
		"ip prefix-list P-upto seq 5 permit 10.0.0.0/8 le 24",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("regression: missing %q in:\n%s", want, got)
		}
	}
}

// --- #2489: a VRF-scoped BGP neighbor with BFD must render its top-level
// `bfd { peer <addr> }` line WITH the matching `vrf <name>` suffix.
// FRR's bfdd is a single daemon; a `peer <addr>` line with no vrf is
// created in the DEFAULT VRF and never associates with the VRF-bound BGP
// session, so the BFD session stays DOWN and sub-second failover never
// works for VRF BGP peers. The `bfd` block is rendered once per BGP
// instance (manager.go calls generateProtocols per-instance), so the
// in-scope vrfName is correct for every peer in the block.

func bgpWithBFDPeer(addr string) *config.BGPConfig {
	return &config.BGPConfig{
		LocalAS:  65001,
		RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: addr, PeerAS: 65002, BFD: true},
		},
	}
}

// TestGenerateProtocols_BFDPeerVRFSuffix is the fail-on-revert guard:
// removing the vrf suffix from the bfd peer line (the bug) makes
// `peer 10.1.1.2 vrf vrf-1` collapse to `peer 10.1.1.2` → this test
// fails.
func TestGenerateProtocols_BFDPeerVRFSuffix(t *testing.T) {
	m := New()
	bgp := bgpWithBFDPeer("10.1.1.2")
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "vrf-1", 0, nil, nil)

	if !strings.Contains(got, " peer 10.1.1.2 vrf vrf-1\n") {
		t.Errorf("VRF-scoped BFD peer must carry `vrf vrf-1` suffix, got:\n%s", got)
	}
	// The unqualified default-VRF line must NOT appear for a VRF peer —
	// that is exactly the bug (peer lands in the default VRF).
	if strings.Contains(got, " peer 10.1.1.2\n") {
		t.Errorf("VRF-scoped BFD peer must NOT render an unqualified `peer` line (lands in default VRF), got:\n%s", got)
	}
	// The router stanza and in-router neighbor bfd must stay VRF-correct.
	if !strings.Contains(got, "router bgp 65001 vrf vrf-1\n") {
		t.Errorf("router bgp must carry vrf suffix, got:\n%s", got)
	}
	if !strings.Contains(got, " neighbor 10.1.1.2 bfd\n") {
		t.Errorf("in-router neighbor bfd line missing, got:\n%s", got)
	}
}

// TestGenerateProtocols_BFDPeerDefaultNoVRFSuffix proves the default
// instance (vrfName == "") still renders a bare `peer <addr>` line with
// NO spurious vrf suffix — the fix must not regress default-VRF BFD.
func TestGenerateProtocols_BFDPeerDefaultNoVRFSuffix(t *testing.T) {
	m := New()
	bgp := bgpWithBFDPeer("10.0.0.9")
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)

	if !strings.Contains(got, " peer 10.0.0.9\n") {
		t.Errorf("default-instance BFD peer must render bare `peer` line, got:\n%s", got)
	}
	if strings.Contains(got, "peer 10.0.0.9 vrf") {
		t.Errorf("default-instance BFD peer must NOT carry a vrf suffix, got:\n%s", got)
	}
}

// TestGenerateProtocols_BFDPeerMixedInstances renders a default-instance
// BGP and a VRF-instance BGP through the same per-instance path manager.go
// uses, and verifies each instance's bfd peer line carries the VRF of the
// instance it belongs to (none for default, `vrf vrf-blue` for the VRF
// instance) — the per-instance bfd-block invariant that makes a single
// in-scope vrfName correct.
func TestGenerateProtocols_BFDPeerMixedInstances(t *testing.T) {
	m := New()
	var b strings.Builder
	// Default instance peer.
	b.WriteString(m.generateProtocols(nil, nil, bgpWithBFDPeer("10.0.0.1"), nil, nil, "", 0, nil, nil))
	// VRF instance peer.
	b.WriteString(m.generateProtocols(nil, nil, bgpWithBFDPeer("10.2.2.2"), nil, nil, "vrf-blue", 0, nil, nil))
	got := b.String()

	if !strings.Contains(got, " peer 10.0.0.1\n") {
		t.Errorf("default-instance peer must be unqualified, got:\n%s", got)
	}
	if strings.Contains(got, "peer 10.0.0.1 vrf") {
		t.Errorf("default-instance peer must NOT carry a vrf suffix, got:\n%s", got)
	}
	if !strings.Contains(got, " peer 10.2.2.2 vrf vrf-blue\n") {
		t.Errorf("VRF-instance peer must carry `vrf vrf-blue`, got:\n%s", got)
	}
	if strings.Contains(got, " peer 10.2.2.2\n") {
		t.Errorf("VRF-instance peer must NOT render an unqualified line, got:\n%s", got)
	}
}

// --- #2642: a policy term with MULTIPLE same-type `from` matches ------------
// Junos allows repeated `from { community c1; community c2; }` (and the same
// for prefix-list / as-path) which match with OR ("any") semantics. FRR holds
// only one rule of each match TYPE per route-map index (route_map_add_match
// replaces same-type), so OR is rendered as one route-map SEQUENCE per value,
// each carrying the full term body and the same permit/deny action — a route
// matching ANY value reaches a sequence it satisfies.

func TestPolicyTermMultiCommunity_OR(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"C1": {Name: "C1", Members: []string{"65000:1"}},
			"C2": {Name: "C2", Members: []string{"65000:2"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromCommunity: []string{"C1", "C2"}, Action: "accept"},
				},
				DefaultAction: "reject",
			},
		},
	}
	got := m.generatePolicyOptions(po)

	// Both communities must render (the bug kept only the last). OR =
	// two permit sequences, NOT two match lines in one index (which FRR
	// would collapse to the last).
	for _, want := range []string{
		"match community C1",
		"match community C2",
		"route-map P permit 10",
		"route-map P permit 20",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// fail-on-revert: each community sits in its OWN sequence (OR), so the
	// two match lines must not co-reside in one route-map index. Count permit
	// sequences for P: exactly two term sequences + (deny default) => the two
	// match-community lines are in distinct indices.
	if got1, got2 := strings.Count(got, "match community C1"), strings.Count(got, "match community C2"); got1 != 1 || got2 != 1 {
		t.Errorf("expected exactly one match line per community, got C1=%d C2=%d:\n%s", got1, got2, got)
	}
	if n := strings.Count(got, "route-map P permit "); n != 2 {
		t.Errorf("expected 2 permit term sequences (one per community, OR), got %d:\n%s", n, got)
	}
}

func TestPolicyTermMultiASPath_OR(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		ASPaths: map[string]*config.ASPathDef{
			"A1": {Name: "A1", Regex: "65001"},
			"A2": {Name: "A2", Regex: "65002"},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromASPath: []string{"A1", "A2"}, Action: "accept"},
				},
				DefaultAction: "reject",
			},
		},
	}
	got := m.generatePolicyOptions(po)
	for _, want := range []string{"match as-path A1", "match as-path A2", "route-map P permit 10", "route-map P permit 20"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "route-map P permit "); n != 2 {
		t.Errorf("expected 2 permit term sequences (one per as-path, OR), got %d:\n%s", n, got)
	}
}

func TestPolicyTermMultiPrefixList_OR(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"PL1": {Name: "PL1", Prefixes: []string{"10.0.0.0/8"}},
			"PL2": {Name: "PL2", Prefixes: []string{"172.16.0.0/12"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "t1", PrefixList: []string{"PL1", "PL2"}, Action: "accept"},
				},
				DefaultAction: "reject",
			},
		},
	}
	got := m.generatePolicyOptions(po)
	for _, want := range []string{
		"match ip address prefix-list PL1",
		"match ip address prefix-list PL2",
		"route-map P permit 10",
		"route-map P permit 20",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "route-map P permit "); n != 2 {
		t.Errorf("expected 2 permit term sequences (one per prefix-list, OR), got %d:\n%s", n, got)
	}
}

// Different match TYPES AND, same type ORs: `from { community c1; community c2;
// as-path a1; }` = (c1 OR c2) AND a1. The cross-product renders as two
// sequences {c1,a1} and {c2,a1}; each carries the as-path match (AND).
func TestPolicyTermMultiCommunity_ANDAsPath_CrossProduct(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"C1": {Name: "C1", Members: []string{"65000:1"}},
			"C2": {Name: "C2", Members: []string{"65000:2"}},
		},
		ASPaths: map[string]*config.ASPathDef{"A1": {Name: "A1", Regex: "65001"}},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromCommunity: []string{"C1", "C2"}, FromASPath: []string{"A1"}, Action: "accept"},
				},
				DefaultAction: "reject",
			},
		},
	}
	got := m.generatePolicyOptions(po)
	// Two sequences, each ANDing the single as-path with one community.
	if n := strings.Count(got, "route-map P permit "); n != 2 {
		t.Errorf("expected 2 permit sequences (|C|*|A| = 2), got %d:\n%s", n, got)
	}
	if n := strings.Count(got, "match as-path A1"); n != 2 {
		t.Errorf("as-path must AND into BOTH community sequences, got %d match lines:\n%s", n, got)
	}
	if !strings.Contains(got, "match community C1") || !strings.Contains(got, "match community C2") {
		t.Errorf("both communities must render:\n%s", got)
	}
}

// A single-match term must still render exactly ONE sequence (no churn /
// regression of the common case).
func TestPolicyTermSingleMatch_NoExtraSequences(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{"C1": {Name: "C1", Members: []string{"65000:1"}}},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name:          "P",
				Terms:         []*config.PolicyTerm{{Name: "t1", FromCommunity: []string{"C1"}, Action: "accept"}},
				DefaultAction: "reject",
			},
		},
	}
	got := m.generatePolicyOptions(po)
	if n := strings.Count(got, "route-map P permit "); n != 1 {
		t.Errorf("single-match term must render exactly 1 permit sequence, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "route-map P permit 10\n") || !strings.Contains(got, "route-map P deny 20\n") {
		t.Errorf("single-match term must keep historical seq numbers (10, 20):\n%s", got)
	}
}

// TestGeneratePolicyOptionsMetricZero is the #2847 fail-on-revert guard.
//
// A route-map `set metric N` / BGP MED of 0 is a valid traffic-engineering
// value (advertise a highly preferred route). Before #2847 the renderer
// gated the clause on `term.Metric > 0`, so an explicitly configured
// `then metric 0` silently emitted nothing and the operator's MED never
// reached FRR. The fix records presence (PolicyTerm.HasMetric, set by the
// compiler whenever the `metric` leaf is parsed) and the renderer emits the
// clause on presence, not on value > 0.
//
// This test drives the full config path (ParseSetCommand -> SetPath ->
// CompileConfig -> generatePolicyOptions) for three cases:
//   - metric 0   -> "set metric 0" MUST be rendered (RED if reverted to >0)
//   - metric unset -> NO "set metric" clause
//   - metric 50  -> "set metric 50" still rendered
func TestGeneratePolicyOptionsMetricZero(t *testing.T) {
	compileAndRender := func(t *testing.T, cmds []string) string {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, cmd := range cmds {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		m := &Manager{frrConf: "/dev/null"}
		return m.generatePolicyOptions(&cfg.PolicyOptions)
	}

	t.Run("metric_zero_emitted", func(t *testing.T) {
		got := compileAndRender(t, []string{
			"set policy-options policy-statement MED0 term t from protocol bgp",
			"set policy-options policy-statement MED0 term t then metric 0",
			"set policy-options policy-statement MED0 term t then accept",
		})
		if !strings.Contains(got, "set metric 0\n") {
			t.Errorf("metric 0 must render a `set metric 0` clause (#2847); got:\n%s", got)
		}
	})

	t.Run("metric_unset_not_emitted", func(t *testing.T) {
		got := compileAndRender(t, []string{
			"set policy-options policy-statement NOMED term t from protocol bgp",
			"set policy-options policy-statement NOMED term t then accept",
		})
		if strings.Contains(got, "set metric") {
			t.Errorf("an unconfigured metric must render no `set metric` clause; got:\n%s", got)
		}
	})

	t.Run("metric_nonzero_emitted", func(t *testing.T) {
		got := compileAndRender(t, []string{
			"set policy-options policy-statement MED50 term t from protocol bgp",
			"set policy-options policy-statement MED50 term t then metric 50",
			"set policy-options policy-statement MED50 term t then accept",
		})
		if !strings.Contains(got, "set metric 50\n") {
			t.Errorf("metric 50 must still render `set metric 50`; got:\n%s", got)
		}
	})
}

// TestGeneratePolicyOptionsLocalPreferenceZero is the #2857 fail-on-revert
// guard, the direct sibling of TestGeneratePolicyOptionsMetricZero (#2847).
//
// A route-map `set local-preference 0` is a valid BGP value: it maximally
// deprioritizes a route within the AS. Before #2857 the renderer gated the
// clause on `term.LocalPreference > 0`, so an explicitly configured
// `then local-preference 0` silently emitted nothing and the operator's
// intent never reached FRR (FRR's route-map YANG accepts local-preference 0).
// The fix records presence (PolicyTerm.HasLocalPreference, set by the
// compiler whenever the `local-preference` leaf is parsed) and the renderer
// emits the clause on presence, not on value > 0.
//
// This test drives the full config path (ParseSetCommand -> SetPath ->
// CompileConfig -> generatePolicyOptions) for three cases:
//   - local-preference 0   -> "set local-preference 0" MUST be rendered
//     (RED if reverted to >0)
//   - local-preference unset -> NO "set local-preference" clause
//   - local-preference 200 -> "set local-preference 200" still rendered
func TestGeneratePolicyOptionsLocalPreferenceZero(t *testing.T) {
	compileAndRender := func(t *testing.T, cmds []string) string {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, cmd := range cmds {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		m := &Manager{frrConf: "/dev/null"}
		return m.generatePolicyOptions(&cfg.PolicyOptions)
	}

	t.Run("local_preference_zero_emitted", func(t *testing.T) {
		got := compileAndRender(t, []string{
			"set policy-options policy-statement LP0 term t from protocol bgp",
			"set policy-options policy-statement LP0 term t then local-preference 0",
			"set policy-options policy-statement LP0 term t then accept",
		})
		if !strings.Contains(got, "set local-preference 0\n") {
			t.Errorf("local-preference 0 must render a `set local-preference 0` clause (#2857); got:\n%s", got)
		}
	})

	t.Run("local_preference_unset_not_emitted", func(t *testing.T) {
		got := compileAndRender(t, []string{
			"set policy-options policy-statement NOLP term t from protocol bgp",
			"set policy-options policy-statement NOLP term t then accept",
		})
		if strings.Contains(got, "set local-preference") {
			t.Errorf("an unconfigured local-preference must render no `set local-preference` clause; got:\n%s", got)
		}
	})

	t.Run("local_preference_nonzero_emitted", func(t *testing.T) {
		got := compileAndRender(t, []string{
			"set policy-options policy-statement LP200 term t from protocol bgp",
			"set policy-options policy-statement LP200 term t then local-preference 200",
			"set policy-options policy-statement LP200 term t then accept",
		})
		if !strings.Contains(got, "set local-preference 200\n") {
			t.Errorf("local-preference 200 must still render `set local-preference 200`; got:\n%s", got)
		}
	})
}

// TestResolveRedistribute_SelfExclusion is the #2943 fail-on-revert guard
// for self-redistribution: a protocol must never redistribute its own
// routes (FRR rejects `redistribute ospf` under `router ospf`, failing the
// whole managed reload). Both the bare-token path and the policy-statement
// `from protocol <self>` path must drop the self protocol.
func TestResolveRedistribute_SelfExclusion(t *testing.T) {
	m := New()
	// Bare-token self redistribute is dropped.
	if got := m.resolveRedistribute("ospf", nil, "ospf", nil); got != "" {
		t.Errorf("self-redistribute (bare token) must be dropped; got %q", got)
	}
	// A different protocol still renders.
	if got := m.resolveRedistribute("static", nil, "ospf", nil); got != " redistribute static\n" {
		t.Errorf("non-self protocol must still redistribute; got %q", got)
	}
	// Policy-statement path: a term `from protocol ospf` under router ospf
	// is self-redistribution and must be excluded, while a sibling
	// `from protocol static` term still renders.
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"leak": {
				Name: "leak",
				Terms: []*config.PolicyTerm{
					{Name: "self", FromProtocols: []string{"ospf"}, Action: "accept"},
					{Name: "other", FromProtocols: []string{"static"}, Action: "accept"},
				},
			},
		},
	}
	got := m.resolveRedistribute("leak", po, "ospf", nil)
	if strings.Contains(got, "redistribute ospf route-map leak") {
		t.Errorf("self-redistribute via policy term must be excluded (#2943); got %q", got)
	}
	if !strings.Contains(got, "redistribute static route-map leak") {
		t.Errorf("non-self policy term must still render; got %q", got)
	}
}

// TestResolveRedistribute_OSPF6RIPng is the #2943 fail-on-revert guard for
// the missing ospf6 / ripng keywords: a bare `export ospf6` / `export
// ripng` must render the valid FRR redistribute line, not fall through to
// the skip-and-warn path that silently drops IPv6 IGP redistribution.
func TestResolveRedistribute_OSPF6RIPng(t *testing.T) {
	m := New()
	if got := m.resolveRedistribute("ospf6", nil, "", nil); got != " redistribute ospf6\n" {
		t.Errorf("ospf6 must render `redistribute ospf6`; got %q", got)
	}
	if got := m.resolveRedistribute("ripng", nil, "", nil); got != " redistribute ripng\n" {
		t.Errorf("ripng must render `redistribute ripng`; got %q", got)
	}
}

// TestGenerateProtocols_IPv6NeighborPolicyActivatesUnderV6 is the #2941
// fail-on-revert guard: an IPv6 BGP peer address (2001:db8::1) with a
// global export policy but NO explicit `family inet6` must be activated
// under `address-family ipv6 unicast`, never under ipv4 unicast. Before the
// fix the `!n.FamilyInet6` fall-through routed the policied family-less peer
// into the ipv4 set, so FRR tried to resolve an IPv4 next-hop over the IPv6
// session and dropped prefixes. The export name must be a DEFINED
// policy-statement so the global default takes the route-map path (not the
// redistribute path).
func TestGenerateProtocols_IPv6NeighborPolicyActivatesUnderV6(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"adv-v6": {
				Name:          "adv-v6",
				Terms:         []*config.PolicyTerm{{Name: "t1", Action: "accept"}},
				DefaultAction: "reject",
			},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS: 65000,
		Export:  []string{"adv-v6"}, // global default export, a defined policy
		Neighbors: []*config.BGPNeighbor{
			// IPv6 peer, no family stanza, but reached by the global export.
			{Address: "2001:db8::1", PeerAS: 65001},
		},
	}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 1, po, nil)

	v6Idx := strings.Index(got, "address-family ipv6 unicast")
	v4Idx := strings.Index(got, "address-family ipv4 unicast")
	if v6Idx < 0 {
		t.Fatalf("expected an ipv6 unicast address-family block; got:\n%s", got)
	}
	activate := "neighbor 2001:db8::1 activate"
	aIdx := strings.Index(got, activate)
	if aIdx < 0 {
		t.Fatalf("IPv6 neighbor never activated; got:\n%s", got)
	}
	// The activate line must fall INSIDE the ipv6 block, not the ipv4 block.
	if v4Idx >= 0 && v4Idx < aIdx && (v6Idx < 0 || v6Idx > aIdx) {
		t.Errorf("IPv6 neighbor activated under ipv4 unicast (#2941 regression); got:\n%s", got)
	}
	if !(v6Idx < aIdx) {
		t.Errorf("IPv6 neighbor activate must follow the ipv6 unicast header; got:\n%s", got)
	}
	// The route-map out must also land in the ipv6 block.
	if !strings.Contains(got, "neighbor 2001:db8::1 route-map adv-v6 out") {
		t.Errorf("expected `neighbor 2001:db8::1 route-map adv-v6 out`; got:\n%s", got)
	}
}

// TestGenerateProtocols_ISISBFDInsideInterfaceBlock is the #2942
// fail-on-revert guard: `isis bfd` (interface-scoped) must be emitted
// INSIDE the `interface <name>` block, BEFORE its `exit`. Emitting it after
// `exit` lands it in global scope, which vtysh rejects and one rejected
// line fails the whole managed-section reload (#1880/#2223).
func TestGenerateProtocols_ISISBFDInsideInterfaceBlock(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:   "49.0001.0100.0000.0001.00",
		Level: "level-2",
		Interfaces: []*config.ISISInterface{
			{Name: "ge-0-0-1", BFD: true},
		},
	}
	got := m.generateProtocols(nil, nil, nil, nil, isis, "", 1, nil, nil)

	ifaceIdx := strings.Index(got, "interface ge-0-0-1")
	if ifaceIdx < 0 {
		t.Fatalf("expected an `interface ge-0-0-1` block; got:\n%s", got)
	}
	bfdIdx := strings.Index(got[ifaceIdx:], " isis bfd\n")
	if bfdIdx < 0 {
		t.Fatalf("expected an `isis bfd` line for the interface; got:\n%s", got)
	}
	bfdIdx += ifaceIdx
	// The interface block's `exit` must come AFTER the isis bfd line.
	exitIdx := strings.Index(got[ifaceIdx:], "exit\n")
	if exitIdx < 0 {
		t.Fatalf("expected an `exit` closing the interface block; got:\n%s", got)
	}
	exitIdx += ifaceIdx
	if !(bfdIdx < exitIdx) {
		t.Errorf("`isis bfd` emitted AFTER the interface `exit` (#2942 regression) — lands in global scope; got:\n%s", got)
	}
}

// TestPolicyRouteFilterPrefixListSameFamilyNoCollision locks the #5730 fix: a
// policy term carrying BOTH an on-family route-filter AND a same-family
// `from prefix-list` must render the two as DISTINCT FRR match rule types so
// FRR ANDs them, not as two `match ipv6 address prefix-list` clauses (which
// collide — FRR's route_map_add_match REPLACES a same-type rule and keeps only
// the LAST, silently dropping the route-filter constraint and loosening
// "(route-filter) AND (prefix-list)" to prefix-list-only).
//
// The fix renders the from-prefix-list as an ACCESS-LIST match
// (`match ipv6 address <generated ACL name>`, a distinct FRR rule type from
// `match ipv6 address prefix-list`; the name is the #5872 bounded/namespaced/
// hashed identifier). A v6 route in the prefix-list but OUTSIDE
// the route-filter range therefore still fails the route-filter's prefix-list
// clause and does NOT match the term.
//
// Fail-on-revert: neutralize the collision branch so the from-prefix-list
// renders as a second `match ipv6 address prefix-list V6ONLY` — the
// access-list match / definition assertions fail AND the "must NOT collide"
// assertion fires.
func TestPolicyRouteFilterPrefixListSameFamilyNoCollision(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"V6ONLY": {Name: "V6ONLY", Prefixes: []string{"2001:db8:ffff::/48"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"MIX": {
				Name: "MIX",
				Terms: []*config.PolicyTerm{
					{
						Name:   "t1",
						Action: "accept",
						RouteFilters: []*config.RouteFilter{
							{Prefix: "2001:db8::/32", MatchType: "orlonger"},
						},
						PrefixList: []string{"V6ONLY"},
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	// The route-filter's prefix-list match line must still be present.
	if !strings.Contains(got, "match ipv6 address prefix-list MIX-t1") {
		t.Errorf("route-filter match line dropped; want %q in:\n%s",
			"match ipv6 address prefix-list MIX-t1", got)
	}
	// The from-prefix-list must render as an ACCESS-LIST match (distinct FRR
	// rule type) so FRR ANDs it with the route-filter's prefix-list match. The
	// access-list name is the #5872 bounded/namespaced/hashed identifier; the
	// definition and the reference MUST use the identical name (helper output).
	aclName := routeFilterACLName("V6ONLY", "ipv6")
	if !strings.Contains(got, "match ipv6 address "+aclName) {
		t.Errorf("from-prefix-list not rendered as an access-list match; want %q in:\n%s",
			"match ipv6 address "+aclName, got)
	}
	// Its access-list definition must be emitted (exact-match preserves the
	// Junos `from prefix-list` exact semantics).
	wantACL := "ipv6 access-list " + aclName + " seq 5 permit 2001:db8:ffff::/48 exact-match"
	if !strings.Contains(got, wantACL) {
		t.Errorf("missing access-list definition; want %q in:\n%s", wantACL, got)
	}
	// The COLLISION form must NOT appear: a second `match ipv6 address
	// prefix-list` for the from-prefix-list would let FRR replace the
	// route-filter clause (the #5730 bug).
	if strings.Contains(got, "match ipv6 address prefix-list V6ONLY") {
		t.Errorf("from-prefix-list collided as a second same-type prefix-list match (#5730 regression); got:\n%s", got)
	}
	// Exactly ONE `match ipv6 address prefix-list` line — the route-filter's.
	if n := strings.Count(got, "match ipv6 address prefix-list "); n != 1 {
		t.Errorf("expected exactly 1 `match ipv6 address prefix-list` line (the route-filter's), got %d:\n%s", n, got)
	}
}

// TestPolicyRouteFilterPrefixListOffFamilyUnchanged guards that the #5730 fix
// does NOT touch the #5702 off-family coexistence: a v4 route-filter co-resident
// with a v6 `from prefix-list` are ALREADY distinct FRR rule types
// (`match ip address prefix-list` vs `match ipv6 address prefix-list`), so the
// from-prefix-list stays a prefix-list match (fail-closed AND — no v4 route can
// satisfy a v6-only list), never an access-list.
func TestPolicyRouteFilterPrefixListOffFamilyUnchanged(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"V6ONLY": {Name: "V6ONLY", Prefixes: []string{"2001:db8:ffff::/48"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"OFF": {
				Name: "OFF",
				Terms: []*config.PolicyTerm{
					{
						Name:   "t1",
						Action: "accept",
						RouteFilters: []*config.RouteFilter{
							{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
						},
						PrefixList: []string{"V6ONLY"},
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	if !strings.Contains(got, "match ip address prefix-list OFF-t1") {
		t.Errorf("v4 route-filter match line missing; got:\n%s", got)
	}
	// Off-family from-prefix-list must remain a prefix-list match (#5702),
	// NOT be converted to an access-list.
	if !strings.Contains(got, "match ipv6 address prefix-list V6ONLY") {
		t.Errorf("off-family from-prefix-list must stay a prefix-list match (#5702); got:\n%s", got)
	}
	if strings.Contains(got, routeFilterACLNamespace) {
		t.Errorf("off-family from-prefix-list must NOT be converted to an access-list (#5872 generated-ACL namespace present); got:\n%s", got)
	}
}
