package frr

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14586: a DEFINED policy-statement referenced by an effective BGP export
// chain (global `protocols bgp export`, group, or per-neighbor export) that
// carries `from protocol static|direct` (or any non-self source) selected
// nothing at runtime: the renderer emitted only the per-peer
// `route-map <policy> out` filter, but nothing ever redistributed the
// static/connected routes INTO BGP, so zebra's connected/static routes
// never entered bgpd and the export advertised nothing (PfxSnt 0). The
// `<policy>-<proto>-xpf-redist` maps were rendered and referenced by
// nothing.
//
// Fix: for each defined policy in the UNION of effective export chains of
// a `router bgp` instance, also emit
// `redistribute <proto> route-map <policy>-<proto>-xpf-redist` per family
// (IPv4 sources at router level, IPv6 sources under
// `address-family ipv6 unicast`), keeping `route-map out` as the per-peer
// filter. This is NOT the #2473 leak: redistribution is gated by the
// filtered per-source map (#12065), never an unfiltered `redistribute …`.
//
// Acceptance (issue): the probe render contains
// `redistribute static route-map EXP-static-xpf-redist` and
// `redistribute connected route-map EXP-connected-xpf-redist` under
// `router bgp` (per family), no unfiltered `redistribute`, and the
// zebra+bgpd cell shows selected prefixes present / non-selected absent
// (the render-level proxy asserts the filtered maps carry the terms).

// bgpRedistLines14586 returns the redistribute lines of a rendered BGP
// section, split into router-level (one leading space) and IPv6-AF
// (two leading spaces) lines, each space-prefixed as rendered.
func bgpRedistLines14586(t *testing.T, got string) (top, af6 []string) {
	t.Helper()
	start := strings.Index(got, "router bgp ")
	if start < 0 {
		t.Fatalf("no router bgp section:\n%s", got)
	}
	section := got[start:]
	if end := strings.Index(section, "exit\n!\n"); end >= 0 {
		section = section[:end]
	}
	inAF6 := false
	for _, ln := range strings.Split(section, "\n") {
		if ln == " address-family ipv6 unicast" {
			inAF6 = true
			continue
		}
		if ln == " exit-address-family" {
			inAF6 = false
			continue
		}
		if !strings.HasPrefix(ln, " redistribute ") && !strings.HasPrefix(ln, "  redistribute ") {
			continue
		}
		if inAF6 {
			af6 = append(af6, ln)
		} else {
			top = append(top, ln)
		}
	}
	return top, af6
}

func sortedLines14586(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func assertRedistSet14586(t *testing.T, label string, gotLines, want []string) {
	t.Helper()
	g, w := sortedLines14586(gotLines), sortedLines14586(want)
	if strings.Join(g, "\n") != strings.Join(w, "\n") {
		t.Errorf("%s redistribute lines =\n%s\nwant\n%s", label, strings.Join(g, "\n"), strings.Join(w, "\n"))
	}
}

// The decisive issue fixture: EXP exported globally, with a static term
// and a direct term, each gated by a prefix-list so selectivity is
// observable at render level.
func expPolicyPO14586() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "static-term", FromProtocols: []string{"static"}, PrefixList: []string{"adv-static"}, Action: "accept"},
					{Name: "direct-term", FromProtocols: []string{"direct"}, PrefixList: []string{"adv-direct"}, Action: "accept"},
				},
			},
		},
		PrefixLists: map[string]*config.PrefixList{
			"adv-static": {Name: "adv-static", Prefixes: []string{"192.0.2.0/24", "2001:db8:1::/48"}},
			"adv-direct": {Name: "adv-direct", Prefixes: []string{"10.0.0.0/24", "2001:db8:2::/48"}},
		},
	}
}

func expBGPFc14586(po *config.PolicyOptionsConfig) *FullConfig {
	return &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Export:   []string{"EXP"},
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true},
				{Address: "2001:db8::2", PeerAS: 65002, FamilyInet6: true},
			},
		},
	}
}

// TestBGPDefinedExportPolicyOriginatesStaticDirect14586 is the acceptance
// cell: a defined policy with `from protocol static|direct` in the global
// export chain must originate the selected routes into BGP via filtered
// redistribution, per family, while keeping the per-peer route-map.
func TestBGPDefinedExportPolicyOriginatesStaticDirect14586(t *testing.T) {
	m := New()
	got := m.buildManagedSection(expBGPFc14586(expPolicyPO14586()))

	top, af6 := bgpRedistLines14586(t, got)
	assertRedistSet14586(t, "router bgp", top, []string{
		" redistribute static route-map EXP-static-xpf-redist",
		" redistribute connected route-map EXP-connected-xpf-redist",
	})
	assertRedistSet14586(t, "address-family ipv6 unicast", af6, []string{
		"  redistribute static route-map EXP-static-xpf-redist",
		"  redistribute connected route-map EXP-connected-xpf-redist",
	})

	// No unfiltered redistribution anywhere in the BGP instance.
	for _, bad := range []string{" redistribute static\n", " redistribute connected\n", "  redistribute static\n", "  redistribute connected\n"} {
		if strings.Contains(got, bad) {
			t.Errorf("unfiltered %q must not render:\n%s", strings.TrimSpace(bad), got)
		}
	}

	// The per-peer filter survives (route-map out is the second gate).
	for _, want := range []string{
		"neighbor 192.0.2.2 route-map EXP out\n",
		"neighbor 2001:db8::2 route-map EXP out\n",
		"route-map EXP-static-xpf-redist permit",
		"route-map EXP-connected-xpf-redist permit",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}

	// Selectivity: each per-source map carries ONLY its own source's
	// term filter, so a non-selected connected/static prefix is absent
	// (denied by the map's terminating deny) rather than leaked.
	staticMap := routeMapBlock11447(got, "EXP-static-xpf-redist")
	if staticMap == "" || !strings.Contains(staticMap, "adv-static") || strings.Contains(staticMap, "adv-direct") {
		t.Errorf("EXP-static-xpf-redist must carry only the static term's filter:\n%s", staticMap)
	}
	if !strings.Contains(staticMap, "route-map EXP-static-xpf-redist deny") {
		t.Errorf("EXP-static-xpf-redist must end fail-closed:\n%s", staticMap)
	}
	connectedMap := routeMapBlock11447(got, "EXP-connected-xpf-redist")
	if connectedMap == "" || !strings.Contains(connectedMap, "adv-direct") || strings.Contains(connectedMap, "adv-static") {
		t.Errorf("EXP-connected-xpf-redist must carry only the direct term's filter:\n%s", connectedMap)
	}
	if !strings.Contains(connectedMap, "route-map EXP-connected-xpf-redist deny") {
		t.Errorf("EXP-connected-xpf-redist must end fail-closed:\n%s", connectedMap)
	}
}

// TestBGPDefinedExportPolicyNoFrom14586: a no-`from protocol` policy in a
// BGP export chain applies to every source (#14380 semantics carried to
// BGP): the renderer must originate the whole node-fitting, non-self
// domain through the filtered per-source maps — never a bare
// `redistribute <proto>`.
func TestBGPDefinedExportPolicyNoFrom14586(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}, Action: "accept"},
				},
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS:   65001,
			RouterID:  "1.1.1.1",
			Export:    []string{"EXP"},
			Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true}},
		},
	}
	got := m.buildManagedSection(fc)
	top, af6 := bgpRedistLines14586(t, got)
	// Router-level (IPv4 grammar): every IPv4-fitting non-self source.
	assertRedistSet14586(t, "router bgp", top, []string{
		" redistribute connected route-map EXP-connected-xpf-redist",
		" redistribute isis route-map EXP-isis-xpf-redist",
		" redistribute kernel route-map EXP-kernel-xpf-redist",
		" redistribute ospf route-map EXP-ospf-xpf-redist",
		" redistribute rip route-map EXP-rip-xpf-redist",
		" redistribute static route-map EXP-static-xpf-redist",
	})
	// IPv6 AF: every IPv6-fitting non-self source.
	assertRedistSet14586(t, "address-family ipv6 unicast", af6, []string{
		"  redistribute connected route-map EXP-connected-xpf-redist",
		"  redistribute isis route-map EXP-isis-xpf-redist",
		"  redistribute kernel route-map EXP-kernel-xpf-redist",
		"  redistribute ospf6 route-map EXP-ospf6-xpf-redist",
		"  redistribute ripng route-map EXP-ripng-xpf-redist",
		"  redistribute static route-map EXP-static-xpf-redist",
	})
	if strings.Contains(got, "redistribute bgp") {
		t.Errorf("BGP must never redistribute itself:\n%s", got)
	}
	// Every referenced map is defined.
	for _, proto := range []string{"connected", "isis", "kernel", "ospf", "ospf6", "rip", "ripng", "static"} {
		if !strings.Contains(got, "route-map EXP-"+proto+"-xpf-redist permit") {
			t.Errorf("route-map EXP-%s-xpf-redist not defined:\n%s", proto, got)
		}
	}
}

// TestBGPDefinedExportOspfFilteredNotUnfiltered14586 pins the #2473
// leak-avoidance boundary after the fix: a defined policy with
// `from protocol ospf` DOES originate OSPF routes into BGP, but only
// through the filtered per-source map — the unfiltered
// `redistribute ospf` of the pre-#2473 code must never return.
func TestBGPDefinedExportOspfFilteredNotUnfiltered14586(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"leak-ospf": {
				Name:  "leak-ospf",
				Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"ospf"}, PrefixList: []string{"cust"}, Action: "accept"}},
			},
		},
		PrefixLists: map[string]*config.PrefixList{
			"cust": {Name: "cust", Prefixes: []string{"203.0.113.0/24"}},
		},
	}
	bgp := &config.BGPConfig{
		LocalAS:   65001,
		RouterID:  "1.1.1.1",
		Export:    []string{"leak-ospf"},
		Neighbors: []*config.BGPNeighbor{{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true}},
	}
	fc := &FullConfig{PolicyOptions: po, BGP: bgp}
	got := m.buildManagedSection(fc)

	if !strings.Contains(got, "neighbor 10.0.2.1 route-map leak-ospf out\n") {
		t.Errorf("missing peer-level route-map out for global export:\n%s", got)
	}
	top, af6 := bgpRedistLines14586(t, got)
	assertRedistSet14586(t, "router bgp", top, []string{
		" redistribute ospf route-map leak-ospf-ospf-xpf-redist",
	})
	// ospf is IPv4-only: nothing in the IPv6 family.
	assertRedistSet14586(t, "address-family ipv6 unicast", af6, nil)
	if strings.Contains(got, " redistribute ospf\n") || strings.Contains(got, "  redistribute ospf\n") {
		t.Errorf("ROUTE LEAK: unfiltered redistribute ospf must not render:\n%s", got)
	}
	ospfMap := routeMapBlock11447(got, "leak-ospf-ospf-xpf-redist")
	if ospfMap == "" || !strings.Contains(ospfMap, "cust") || !strings.Contains(ospfMap, "route-map leak-ospf-ospf-xpf-redist deny") {
		t.Errorf("leak-ospf-ospf-xpf-redist must carry the term filter and end fail-closed:\n%s", ospfMap)
	}
}

// TestBGPPerNeighborDefinedExportOriginates14586: Junos most-specific-wins
// resolves per-neighbor (and group) export chains, so origination follows
// the UNION of effective chains — a policy only one neighbor exports must
// still originate its routes (they enter the BGP RIB once; the per-peer
// route-map out remains the per-peer gate). A policy a neighbor overrides
// away from still originates via the neighbors that keep it.
func TestBGPPerNeighborDefinedExportOriginates14586(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name:  "EXP",
				Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"static"}, Action: "accept"}},
			},
			"ONLY-B": {
				Name:  "ONLY-B",
				Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"direct"}, Action: "accept"}},
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Export:   []string{"EXP"},
			Neighbors: []*config.BGPNeighbor{
				{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true},
				{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, Export: []string{"ONLY-B"}},
			},
		},
	}
	got := m.buildManagedSection(fc)
	top, af6 := bgpRedistLines14586(t, got)
	assertRedistSet14586(t, "router bgp", top, []string{
		" redistribute static route-map EXP-static-xpf-redist",
		" redistribute connected route-map ONLY-B-connected-xpf-redist",
	})
	assertRedistSet14586(t, "address-family ipv6 unicast", af6, []string{
		"  redistribute static route-map EXP-static-xpf-redist",
		"  redistribute connected route-map ONLY-B-connected-xpf-redist",
	})
	// Per-peer filters stay most-specific: .1 gets EXP, .2 gets ONLY-B.
	if !strings.Contains(got, "neighbor 192.0.2.1 route-map EXP out\n") {
		t.Errorf("neighbor .1 must keep the global EXP route-map out:\n%s", got)
	}
	if !strings.Contains(got, "neighbor 192.0.2.2 route-map ONLY-B out\n") {
		t.Errorf("neighbor .2 must keep its own ONLY-B route-map out:\n%s", got)
	}
}

// TestBGPDefinedExportBGPOnlySourceEmitsNothing14586: a policy whose only
// source is BGP itself must not redistribute BGP into BGP (self-drop), and
// must not emit any other line either.
func TestBGPDefinedExportBGPOnlySourceEmitsNothing14586(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"SELFBGP": {
				Name:  "SELFBGP",
				Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"bgp"}, Action: "accept"}},
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS:   65001,
			RouterID:  "1.1.1.1",
			Export:    []string{"SELFBGP"},
			Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true}},
		},
	}
	got := m.buildManagedSection(fc)
	top, af6 := bgpRedistLines14586(t, got)
	assertRedistSet14586(t, "router bgp", top, nil)
	assertRedistSet14586(t, "address-family ipv6 unicast", af6, nil)
	// No attachment may name the self map. (The map's DEFINITION is
	// rendered by generatePolicyOptions' explicit-only set, as for every
	// policy; it is unreferenced and inert — the attachment is what
	// would redistribute BGP into itself.)
	if strings.Contains(got, "redistribute bgp") {
		t.Errorf("self-redistribute line must not render for BGP export:\n%s", got)
	}
}

// TestBGPBareTokenAndDefinedExportCoexist14586: a bare token and a defined
// policy in the same global export list keep their separate paths — the
// bare token stays an unfiltered-global redistribute verb, the defined
// policy originates only through its filtered maps, and the two never
// produce a duplicate line for the same source.
func TestBGPBareTokenAndDefinedExportCoexist14586(t *testing.T) {
	m := New()
	po := expPolicyPO14586()
	fc := expBGPFc14586(po)
	fc.BGP.Export = []string{"kernel", "EXP"}
	got := m.buildManagedSection(fc)
	top, af6 := bgpRedistLines14586(t, got)
	assertRedistSet14586(t, "router bgp", top, []string{
		" redistribute kernel",
		" redistribute static route-map EXP-static-xpf-redist",
		" redistribute connected route-map EXP-connected-xpf-redist",
	})
	assertRedistSet14586(t, "address-family ipv6 unicast", af6, []string{
		"  redistribute kernel",
		"  redistribute static route-map EXP-static-xpf-redist",
		"  redistribute connected route-map EXP-connected-xpf-redist",
	})
	// Router-level kernel appears once (the IPv6-AF line is separately
	// indented and counted in af6 above).
	if n := strings.Count(got, "\n redistribute kernel\n"); n != 1 {
		t.Errorf("bare kernel token must render exactly once at router level, got %d:\n%s", n, got)
	}
	if n := strings.Count(got, "\n  redistribute kernel\n"); n != 1 {
		t.Errorf("bare kernel token must render exactly once in the IPv6 AF, got %d:\n%s", n, got)
	}
}

// TestBGPDefinedExportRedistMapCollisionRefused14586: the newly-referenced
// per-source maps join the generated-map collision belt — an operator
// policy-statement named EXP-static-xpf-redist must refuse the apply
// (FRR merges same-named route-maps) when EXP is exported via BGP.
func TestBGPDefinedExportRedistMapCollisionRefused14586(t *testing.T) {
	po := expPolicyPO14586()
	po.PolicyStatements["EXP-static-xpf-redist"] = &config.PolicyStatement{
		Name:  "EXP-static-xpf-redist",
		Terms: []*config.PolicyTerm{{Name: "term", FromProtocols: []string{"connected"}, Action: "accept"}},
	}
	fc := expBGPFc14586(po)
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
	err := m.ApplyFull(fc)
	if err == nil || !strings.Contains(err.Error(), "EXP-static-xpf-redist") {
		t.Fatalf("expected collision refusal naming EXP-static-xpf-redist, got %v", err)
	}
	// Control: without the colliding operator policy the belt does not fire.
	if err := redistProtocolMapCollisionForNodes(expPolicyPO14586(), "bgp", "bgp"); err != nil {
		t.Fatalf("clean BGP-referenced policy flagged: %v", err)
	}
	if err := redistProtocolMapCollisionForNodes(expPolicyPO14586(), "bgp", "bgp-ipv6"); err != nil {
		t.Fatalf("clean BGP IPv6-referenced policy flagged: %v", err)
	}
}
