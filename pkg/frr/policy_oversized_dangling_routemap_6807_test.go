package frr

// policy_oversized_dangling_routemap_6807_test.go — #6807.
//
// The render belts for an over-ceiling policy (#5701) and an over-ceiling
// composed BGP chain (#5732) skipped the DEFINITION so a `route-map ... 70000`
// line could not poison the whole vtysh-batched frr-reload. But BGP rendering
// emits the ATTACHMENT (`neighbor <ip> route-map <name> in|out`) independently,
// off the policy's presence in PolicyStatements — so the attachment outlived
// its definition.
//
// The repository asserted, in eight comments and three tests, that FRR resolves
// such a dangling name to PERMIT-ALL. That is false. FRR stable/10.6
// bgpd/bgp_route.c:
//
//	bgp_input_modifier:   rmap = route_map_lookup_by_name(rmap_name);
//	                      if (!rmap) return RMAP_DENY;
//	bgp_output_modifier:  if (!rmap_name) return RMAP_PERMIT;
//	                      rmap = route_map_lookup_by_name(rmap_name);
//	                      if (rmap == NULL) return RMAP_DENY;
//
// A NAMED-but-undefined map denies; only an ABSENT attachment permits. So the
// pre-fix behaviour silently withdrew every route on the attached neighbors —
// a routing outage — with an operator-visible signal of one slog.Warn line.
//
// The invariant these cells hold is the one the defect violates: a route-map
// NAME referenced anywhere in the managed section must be DEFINED in the same
// managed section. That is stated as a property over the whole rendered
// section, not as a point assertion about the oversized case, so it also
// catches a future dangling reference arriving from some other cause.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

var (
	// Attachment sites that NAME a route-map: BGP neighbor in/out and the
	// redistribute verb. Both resolve through route_map_lookup_by_name.
	reNeighborRouteMap6807 = regexp.MustCompile(`(?m)^\s*neighbor \S+ route-map (\S+) (?:in|out)\s*$`)
	reRedistRouteMap6807   = regexp.MustCompile(`(?m)^\s*redistribute \S+ route-map (\S+)\s*$`)
	// Definition headers.
	reRouteMapDef6807 = regexp.MustCompile(`(?m)^route-map (\S+) (?:permit|deny) \d+\s*$`)
)

// danglingRouteMapRefs6807 returns the sorted set of route-map names that the
// managed section REFERENCES but never DEFINES.
func danglingRouteMapRefs6807(section string) []string {
	defined := map[string]bool{}
	for _, m := range reRouteMapDef6807.FindAllStringSubmatch(section, -1) {
		defined[m[1]] = true
	}
	dangling := map[string]bool{}
	for _, re := range []*regexp.Regexp{reNeighborRouteMap6807, reRedistRouteMap6807} {
		for _, m := range re.FindAllStringSubmatch(section, -1) {
			if !defined[m[1]] {
				dangling[m[1]] = true
			}
		}
	}
	out := make([]string, 0, len(dangling))
	for n := range dangling {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// countRouteMapRefs6807 counts attachment sites naming route-map name. A cell
// asserting "no dangling reference" is worthless if the fixture emitted no
// reference at all, so every cell below asserts this is non-zero first.
func countRouteMapRefs6807(section, name string) int {
	n := 0
	for _, re := range []*regexp.Regexp{reNeighborRouteMap6807, reRedistRouteMap6807} {
		for _, m := range re.FindAllStringSubmatch(section, -1) {
			if m[1] == name {
				n++
			}
		}
	}
	return n
}

// oversizedPolicy6807 builds a policy-statement whose single term expands to
// one route-map sequence per prefix-list value, one past the ceiling.
func oversizedPolicy6807(name string) *config.PolicyStatement {
	pl := make([]string, config.MaxRouteMapSequences+1)
	for i := range pl {
		pl[i] = fmt.Sprintf("pl%d", i)
	}
	return &config.PolicyStatement{Name: name, Terms: []*config.PolicyTerm{{Name: "t1", PrefixList: pl}}}
}

// TestDanglingRefDetectorFindsAPlantedDangle6807 is the NEGATIVE CONTROL for
// every cell below. `danglingRouteMapRefs6807` reporting "none" must mean the
// section is clean, not that the regexes matched nothing — so feed it a section
// that definitely dangles and require it to say so.
func TestDanglingRefDetectorFindsAPlantedDangle6807(t *testing.T) {
	planted := "router bgp 65001\n" +
		"  neighbor 10.0.2.1 route-map GHOST out\n" +
		"  neighbor 10.0.2.1 route-map REAL in\n" +
		"!\n" +
		"route-map REAL permit 10\n" +
		"exit\n"
	got := danglingRouteMapRefs6807(planted)
	if len(got) != 1 || got[0] != "GHOST" {
		t.Fatalf("the dangling-reference detector did not find the planted "+
			"undefined GHOST reference, so every clean verdict it returns is "+
			"meaningless; got %v", got)
	}
	if n := countRouteMapRefs6807(planted, "REAL"); n != 1 {
		t.Fatalf("the reference counter must see the defined REAL attachment too, got %d", n)
	}
}

// TestOversizedPolicyLeavesNoDanglingAttachment6807 is the issue, end to end: a
// neighbor exports an over-ceiling policy through the REAL managed-section
// renderer.
func TestOversizedPolicyLeavesNoDanglingAttachment6807(t *testing.T) {
	fc := &FullConfig{
		PolicyOptions: &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{"BIG": oversizedPolicy6807("BIG")},
			PrefixLists:      map[string]*config.PrefixList{},
			Communities:      map[string]*config.CommunityDef{},
			ASPaths:          map[string]*config.ASPathDef{},
		},
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"BIG"}},
			},
		},
	}
	got := New().buildManagedSection(fc)

	// Precondition: the attachment really is emitted. Without this the cell
	// would pass on a render that dropped the attachment entirely — a DIFFERENT
	// (fail-open) outcome that must not be mistaken for the fix.
	if n := countRouteMapRefs6807(got, "BIG"); n == 0 {
		t.Fatalf("fixture emitted no `route-map BIG` attachment, so this cell "+
			"cannot observe whether it dangles:\n%s", got)
	}
	if d := danglingRouteMapRefs6807(got); len(d) != 0 {
		t.Fatalf("the managed section REFERENCES route-map(s) %v that it never "+
			"DEFINES. FRR returns RMAP_DENY for a name it cannot resolve, so "+
			"every route on the attached neighbors is withdrawn (#6807):\n%s",
			d, got)
	}
	// The definition that resolves it is the bounded explicit deny, not a
	// fragment of the over-ceiling expansion.
	headers := routeMapHeaders6807(got, "BIG")
	if len(headers) != 1 {
		t.Fatalf("BIG must be defined by exactly one bounded header, got %d: %v", len(headers), headers)
	}
	if want := fmt.Sprintf("route-map BIG deny %d", quarantineDenySeq); headers[0] != want {
		t.Fatalf("BIG must resolve to the bounded explicit DENY %q, got %q — an "+
			"attachment that resolves to PERMIT would advertise every route the "+
			"operator's policy existed to filter", want, headers[0])
	}
}

// TestOversizedComposedChainLeavesNoDanglingAttachment6807 is the #5732 sibling:
// two members that each pass the per-policy ceiling but SUM past it, so the
// composed `-xpf-chain` route-map is the one that cannot render.
func TestOversizedComposedChainLeavesNoDanglingAttachment6807(t *testing.T) {
	half := config.MaxRouteMapSequences/2 + 100
	mk := func(name string, n int) *config.PolicyStatement {
		pl := make([]string, n)
		for i := range pl {
			pl[i] = fmt.Sprintf("pl%d", i)
		}
		return &config.PolicyStatement{Name: name, Terms: []*config.PolicyTerm{{Name: "t", PrefixList: pl}}}
	}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{"A": mk("A", half), "B": mk("B", half)},
		PrefixLists:      map[string]*config.PrefixList{},
		Communities:      map[string]*config.CommunityDef{},
		ASPaths:          map[string]*config.ASPathDef{},
	}
	// Sanity: each member is in-bounds, the chain is not — otherwise this cell
	// exercises the single-policy belt instead of the composed one.
	if config.RouteMapSequenceCount(po, po.PolicyStatements["A"]) > config.MaxRouteMapSequences {
		t.Fatal("member A must be within the per-policy ceiling")
	}
	if config.ComposedChainSequenceCount(po, po.PolicyStatements, []string{"A", "B"}) <= config.MaxRouteMapSequences {
		t.Fatal("composed A+B must exceed the ceiling")
	}

	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"A", "B"}},
			},
		},
	}
	got := New().buildManagedSection(fc)

	composed := "A-B" + config.ReservedChainSuffix
	if n := countRouteMapRefs6807(got, composed); n == 0 {
		t.Fatalf("fixture emitted no `route-map %s` attachment:\n%s", composed, got)
	}
	if d := danglingRouteMapRefs6807(got); len(d) != 0 {
		t.Fatalf("the managed section references undefined route-map(s) %v — FRR "+
			"denies every route on the attached neighbors (#6807):\n%s", d, got)
	}
	headers := routeMapHeaders6807(got, composed)
	if len(headers) != 1 {
		t.Fatalf("%s must be defined by exactly one bounded header, got %d: %v", composed, len(headers), headers)
	}
	if want := fmt.Sprintf("route-map %s deny %d", composed, quarantineDenySeq); headers[0] != want {
		t.Fatalf("%s must resolve to the bounded explicit DENY %q, got %q", composed, want, headers[0])
	}
}

// TestOversizedRedistributeProtocolMapLeavesNoDangling6807 covers the per-
// protocol redistribute attachment and its bounded deny map. The fixture is
// dual-use so the base BGP policy and its static-specific redistribute map are
// both attached and must resolve to explicit deny definitions when oversized.
func TestOversizedRedistributeProtocolMapLeavesNoDangling6807(t *testing.T) {
	big := oversizedPolicy6807("BIG")
	big.Terms[0].FromProtocols = []string{"static"}
	big.DefaultAction = ""

	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{"BIG": big},
		PrefixLists:      map[string]*config.PrefixList{},
		Communities:      map[string]*config.CommunityDef{},
		ASPaths:          map[string]*config.ASPathDef{},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"BIG"}},
			},
		},
		OSPF: &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0"}}, Export: []string{"BIG"}},
	}

	got := New().buildManagedSection(fc)
	protocolMap := redistProtocolRouteMapName("BIG", "static")
	if n := countRouteMapRefs6807(got, protocolMap); n == 0 {
		t.Fatalf("fixture emitted no redistribute attachment for %s:\\n%s", protocolMap, got)
	}
	if d := danglingRouteMapRefs6807(got); len(d) != 0 {
		t.Fatalf("the managed section references undefined route-map(s) %v — FRR denies every route on the attached policy:\\n%s", d, got)
	}
	for _, name := range []string{"BIG", protocolMap} {
		headers := routeMapHeaders6807(got, name)
		if len(headers) != 1 {
			t.Fatalf("route-map %q must be defined by exactly one bounded header, got %d: %v", name, len(headers), headers)
		}
		if want := fmt.Sprintf("route-map %s deny %d", name, quarantineDenySeq); headers[0] != want {
			t.Fatalf("route-map %q must resolve to the bounded explicit deny %q, got %q", name, want, headers[0])
		}
	}
}

// TestNormalPolicyStillRendersItsFullExpansion6807 is the PAIRED control for
// all of the above: an in-bounds policy must render its real terms, not a
// quarantine deny. Without it, "no dangling reference and the header is a
// bounded deny" is satisfied by a renderer that quarantines EVERY policy — the
// same routing outage, applied universally.
func TestNormalPolicyStillRendersItsFullExpansion6807(t *testing.T) {
	fc := &FullConfig{
		PolicyOptions: &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{
				"OK": {Name: "OK", Terms: []*config.PolicyTerm{
					{Name: "t1", PrefixList: []string{"rfc1918"}, Action: "reject"},
					{Name: "t2", Action: "accept"},
				}},
			},
			PrefixLists: map[string]*config.PrefixList{"rfc1918": {Name: "rfc1918", Prefixes: []string{"10.0.0.0/8"}}},
			Communities: map[string]*config.CommunityDef{},
			ASPaths:     map[string]*config.ASPathDef{},
		},
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"OK"}},
			},
		},
	}
	got := New().buildManagedSection(fc)

	if d := danglingRouteMapRefs6807(got); len(d) != 0 {
		t.Fatalf("a healthy config must not dangle either, got %v:\n%s", d, got)
	}
	headers := routeMapHeaders6807(got, "OK")
	if len(headers) < 2 {
		t.Fatalf("an in-bounds policy must render its real term sequences, not a "+
			"single quarantine header — got %d: %v\n%s", len(headers), headers, got)
	}
	if want := fmt.Sprintf("route-map OK deny %d", quarantineDenySeq); headers[0] == want && len(headers) == 1 {
		t.Fatalf("in-bounds policy OK was quarantined like an oversized one")
	}
	// Its real content is present: the RFC1918 reject term.
	if !strings.Contains(got, "match ip address prefix-list rfc1918") {
		t.Fatalf("the in-bounds policy's term match did not render:\n%s", got)
	}
}

// TestQuarantinedRouteMapsIsReportedAndReset6807 binds the producer side of the
// gauge: rendering must RECORD what it quarantined, and a later healthy render
// must CLEAR it.
//
// The reset leg is the one that matters operationally. Without it the set only
// ever grows, so an operator who reduces the oversized policy and re-commits
// keeps being paged for a withdrawal that no longer exists — and the alert
// becomes noise that gets muted, which is how the next real one is missed.
func TestQuarantinedRouteMapsIsReportedAndReset6807(t *testing.T) {
	m := New()

	// A fresh manager has nothing to report — otherwise the "records it"
	// assertion below would pass on a manager that reports names unconditionally.
	if got := m.QuarantinedRouteMaps(); len(got) != 0 {
		t.Fatalf("a manager that has rendered nothing must report no quarantine, got %v", got)
	}

	big := oversizedPolicy6807("BIG")
	big.Terms[0].FromProtocols = []string{"static"}
	big.DefaultAction = ""
	oversized := &FullConfig{
		PolicyOptions: &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{"BIG": big},
			PrefixLists:      map[string]*config.PrefixList{},
			Communities:      map[string]*config.CommunityDef{},
			ASPaths:          map[string]*config.ASPathDef{},
		},
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"BIG"}},
			},
		},
		OSPF: &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0"}}, Export: []string{"BIG"}},
	}
	m.buildManagedSection(oversized)

	got := m.QuarantinedRouteMaps()
	// Both the BGP policy and its source-specific redistribute map are
	// quarantined, so the gauge reports each attached name.
	want := []string{"BIG", redistProtocolRouteMapName("BIG", "static")}
	if len(got) != len(want) {
		t.Fatalf("QuarantinedRouteMaps() = %v, want %v — the render did not record "+
			"what it quarantined, so the xpf_frr_route_maps_quarantined gauge "+
			"reports a healthy box while routes are being withdrawn", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("QuarantinedRouteMaps() = %v, want %v (sorted)", got, want)
		}
	}

	// A subsequent HEALTHY render clears it: the set describes the section
	// actually rendered, not everything ever seen.
	healthy := &FullConfig{
		PolicyOptions: &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{
				"OK": {Name: "OK", Terms: []*config.PolicyTerm{{Name: "t1", Action: "accept"}}},
			},
			PrefixLists: map[string]*config.PrefixList{},
			Communities: map[string]*config.CommunityDef{},
			ASPaths:     map[string]*config.ASPathDef{},
		},
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Export: []string{"OK"}},
			},
		},
	}
	m.buildManagedSection(healthy)
	if got := m.QuarantinedRouteMaps(); len(got) != 0 {
		t.Fatalf("QuarantinedRouteMaps() = %v after a healthy render, want empty — "+
			"the operator who reduced the policy and re-committed is still being "+
			"paged for a withdrawal that no longer exists", got)
	}
}
