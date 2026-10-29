package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16625 (R3-A12-03): per-group RIP export rendered per-interface.
//
// Probe: CUSTOMERS (ge-0/0/1.0, DEFAULT-ONLY = 0.0.0.0/0 exact)
// vs CORE (ge-0/0/2.0, ALL-STATIC = 192.168.50.0/24 exact).
// Acceptance: CUSTOMERS never receives 192.168.50.0/24 and CORE
// receives it, in both group orders. Rendered proof: the
// CUSTOMERS distribute-list permits only 0.0.0.0/0, the CORE
// list permits 192.168.50.0/24, and bindings attach each list
// to the right interface. The union redistribute pool contains
// both policies' route-maps (superset), confined per interface.

func ripGroupPO16625() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"DEFAULT-ONLY": {Name: "DEFAULT-ONLY", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "0.0.0.0/0", MatchType: "exact"}}, Action: "accept"},
			}},
			"ALL-STATIC": {Name: "ALL-STATIC", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "192.168.50.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
		},
	}
}

func ripGroupedConfig16625(customersFirst bool) *config.RIPConfig {
	cust := &config.RIPGroup{Name: "CUSTOMERS", Interfaces: []string{"ge-0-0-1"}, Export: []string{"DEFAULT-ONLY"}}
	core := &config.RIPGroup{Name: "CORE", Interfaces: []string{"ge-0-0-2"}, Export: []string{"ALL-STATIC"}}
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1", "ge-0-0-2"},
		Redistribute: []string{"DEFAULT-ONLY", "ALL-STATIC"},
	}
	if customersFirst {
		rip.Groups = []*config.RIPGroup{cust, core}
	} else {
		rip.Groups = []*config.RIPGroup{core, cust}
	}
	return rip
}

// listForIface extracts the prefix-list name bound `out <iface>`.
func listForIface16625(t *testing.T, got, iface string) string {
	t.Helper()
	for _, line := range strings.Split(got, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "distribute-list prefix ") && strings.HasSuffix(line, " out "+iface) {
			f := strings.Fields(line)
			if len(f) == 5 {
				return f[2]
			}
		}
	}
	t.Fatalf("no distribute-list binding for %s in:\n%s", iface, got)
	return ""
}

// listPermits returns permit entry bodies of `ip prefix-list <name>`.
func listPermits16625(got, name string) []string {
	var out []string
	prefix := "ip prefix-list " + name + " seq "
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, prefix) {
			rest := strings.TrimPrefix(line, prefix)
			// "<seq> permit|deny <body>"
			f := strings.SplitN(rest, " ", 3)
			if len(f) == 3 && f[1] == "permit" {
				out = append(out, f[2])
			}
		}
	}
	return out
}

func TestRIPPerGroupExportRendered16625(t *testing.T) {
	for _, customersFirst := range []bool{true, false} {
		m := New()
		got := m.generateProtocols(nil, nil, nil, ripGroupedConfig16625(customersFirst), nil, "", 0, ripGroupPO16625(), nil)
		custList := listForIface16625(t, got, "ge-0-0-1")
		coreList := listForIface16625(t, got, "ge-0-0-2")
		if custList == coreList {
			t.Fatalf("customersFirst=%v: both interfaces share list %s — per-group boundary erased:\n%s", customersFirst, custList, got)
		}
		custPermits := listPermits16625(got, custList)
		corePermits := listPermits16625(got, coreList)
		// CUSTOMERS: default only, NEVER 192.168.50.0/24.
		if len(custPermits) != 1 || custPermits[0] != "0.0.0.0/0" {
			t.Errorf("customersFirst=%v: CUSTOMERS permits=%v, want [0.0.0.0/0]", customersFirst, custPermits)
		}
		for _, p := range custPermits {
			if strings.Contains(p, "192.168.50.0") {
				t.Errorf("customersFirst=%v: LEAK — CUSTOMERS permits %s", customersFirst, p)
			}
		}
		// CORE: receives 192.168.50.0/24.
		if len(corePermits) != 1 || corePermits[0] != "192.168.50.0/24" {
			t.Errorf("customersFirst=%v: CORE permits=%v, want [192.168.50.0/24] (loss if empty)", customersFirst, corePermits)
		}
		// Union pool still redistributes both policies.
		if !strings.Contains(got, "redistribute ") {
			t.Errorf("customersFirst=%v: union redistribution missing:\n%s", customersFirst, got)
		}
		// Both interfaces enrolled.
		if !strings.Contains(got, "network ge-0-0-1\n") || !strings.Contains(got, "network ge-0-0-2\n") {
			t.Errorf("customersFirst=%v: enrollment missing:\n%s", customersFirst, got)
		}
	}
}

func TestRIPPerGroupBareTokenFailsClosed16625(t *testing.T) {
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"static"},
		Groups: []*config.RIPGroup{
			{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"static"}},
		},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, ripGroupPO16625(), nil)
	list := listForIface16625(t, got, "ge-0-0-1")
	permits := listPermits16625(got, list)
	if len(permits) != 0 {
		t.Errorf("bare-token group must deny-all, permits=%v:\n%s", permits, got)
	}
	if !strings.Contains(got, "ip prefix-list "+list+" seq 5 deny 0.0.0.0/0 le 32") {
		t.Errorf("explicit deny-all entry missing:\n%s", got)
	}
}

func TestRIPPerGroupContestedWithheld16625(t *testing.T) {
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1", "ge-0-0-2"},
		Redistribute: []string{"DEFAULT-ONLY", "ALL-STATIC"},
		Groups: []*config.RIPGroup{
			{Name: "A", Interfaces: []string{"ge-0-0-1"}, Export: []string{"DEFAULT-ONLY"}},
			{Name: "B", Interfaces: []string{"ge-0-0-1", "ge-0-0-2"}, Export: []string{"ALL-STATIC"}},
		},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, ripGroupPO16625(), nil)
	if strings.Contains(got, "network ge-0-0-1") {
		t.Errorf("contested interface must be withheld (fail closed):\n%s", got)
	}
	if !strings.Contains(got, "network ge-0-0-2") {
		t.Errorf("uncontested interface must stay enrolled:\n%s", got)
	}
}

func TestRIPNoGroupsLegacyByteShape16625(t *testing.T) {
	// #16866 supersedes the byte-identical-legacy clause of this
	// test: group-less RIP now also carries the per-interface
	// deny-all gate (bare tokens advertise nothing in Junos).
	// The legacy stanza lines themselves are unchanged.
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"trust0", "dmz0"},
		Passive:      []string{"dmz0"},
		Redistribute: []string{"connected", "static"},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	for _, want := range []string{"router rip\n", " network trust0\n", " redistribute connected\n", " redistribute static\n", " distribute-list prefix "} {
		if !strings.Contains(got, want) {
			t.Errorf("line %q missing:\n%s", want, got)
		}
	}
}

func TestRIPPerGroupRejectTermConfines16625(t *testing.T) {
	// Policy accepts 10.0.0.0/8 except 10.1.0.0/16 rejected first.
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "deny-sub", RouteFilters: []*config.RouteFilter{{Prefix: "10.1.0.0/16", MatchType: "exact"}}, Action: "reject"},
				{Name: "accept-rest", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}, Action: "accept"},
			}},
		},
	}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"P"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := listForIface16625(t, got, "ge-0-0-1")
	// Ordered list must deny 10.1.0.0/16 before permitting 10/8.
	denyIdx := strings.Index(got, "ip prefix-list "+list+" seq 5 deny 10.1.0.0/16")
	permitIdx := strings.Index(got, "ip prefix-list "+list+" seq 10 permit 10.0.0.0/8 le 32")
	if denyIdx < 0 || permitIdx < 0 || denyIdx > permitIdx {
		t.Errorf("reject term must render as earlier deny (deny@%d permit@%d):\n%s", denyIdx, permitIdx, got)
	}
}

func TestRIPPerGroupMaxLengthLongerBoundaryPreservesSibling16625(t *testing.T) {
	// #18361: a max-length `longer` filter (10.0.0.1/32 longer) is a
	// valid empty match set. It must not make the whole RIP per-group
	// export render deny-all; the sibling broader permit in the same
	// accepting term must survive. The host route itself must stay
	// denied (Junos longest-match: 10.0.0.1/32 matches the /32 longer
	// boundary and fails), so a bare exact-host deny precedes the permit.
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: []*config.RouteFilter{
					{Prefix: "10.0.0.1/32", MatchType: "longer"},
					{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
				}, Action: "accept"},
			}},
		},
	}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"P"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := listForIface16625(t, got, "ge-0-0-1")
	permits := listPermits16625(got, list)
	if len(permits) != 1 || permits[0] != "10.0.0.0/8 le 32" {
		t.Errorf("sibling broader permit must survive, permits=%v:\n%s", permits, got)
	}
	if strings.Contains(got, "ip prefix-list "+list+" seq 5 deny 0.0.0.0/0 le 32") {
		t.Errorf("empty max-length longer must NOT deny-all the group:\n%s", got)
	}
	hostDeny := "ip prefix-list " + list + " seq 5 deny 10.0.0.1/32\n"
	siblingPermit := "ip prefix-list " + list + " seq 10 permit 10.0.0.0/8 le 32\n"
	if denyIdx, permitIdx := strings.Index(got, hostDeny), strings.Index(got, siblingPermit); denyIdx < 0 || permitIdx < 0 || denyIdx > permitIdx {
		t.Errorf("bare exact-host deny must precede the sibling broader permit (deny@%d permit@%d):\n%s", denyIdx, permitIdx, got)
	}
}

func TestRIPPerGroupEmptyMaxLengthLongerTermFallsThrough16625(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "empty-host-longer", RouteFilters: []*config.RouteFilter{
					{Prefix: "10.0.0.1/32", MatchType: "longer"},
				}, Action: "accept"},
				{Name: "sibling-permit", RouteFilters: []*config.RouteFilter{
					{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
				}, Action: "accept"},
			}},
		},
	}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"P"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := listForIface16625(t, got, "ge-0-0-1")
	permits := listPermits16625(got, list)
	if len(permits) != 1 || permits[0] != "10.0.0.0/8 le 32" {
		t.Errorf("later sibling permit must survive an empty boundary term, permits=%v:\n%s", permits, got)
	}
	if strings.Contains(got, "ip prefix-list "+list+" seq 5 deny 0.0.0.0/0 le 32") {
		t.Errorf("empty boundary term must not deny-all the group:\n%s", got)
	}
	if strings.Contains(got, "deny 10.0.0.1/32") {
		t.Errorf("an empty term must fall through, not exclude the route from a later accept:\n%s", got)
	}
}

func TestRIPPerGroupBoundaryWithLaterAcceptFailsClosed16625(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "empty-boundary", RouteFilters: []*config.RouteFilter{
					{Prefix: "10.0.0.1/32", MatchType: "longer"},
					{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
				}, Action: "accept"},
				{Name: "later-host-accept", RouteFilters: []*config.RouteFilter{
					{Prefix: "10.0.0.1/32", MatchType: "exact"},
				}, Action: "accept"},
			}},
		},
	}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"P"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := listForIface16625(t, got, "ge-0-0-1")
	if permits := listPermits16625(got, list); len(permits) != 0 {
		t.Errorf("boundary must not override a later accept the prefix gate cannot represent, permits=%v:\n%s", permits, got)
	}
	if !strings.Contains(got, "ip prefix-list "+list+" seq 5 deny 0.0.0.0/0 le 32") {
		t.Errorf("unrepresentable fallthrough must remain fail-closed:\n%s", got)
	}
}

func TestRIPPerGroupBoundaryWithCoveringLaterAcceptFailsClosed16625(t *testing.T) {
	// A later orlonger accept whose base covers the boundary host can
	// change its outcome even though it is not an exact-host filter.
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "empty-boundary", RouteFilters: []*config.RouteFilter{
					{Prefix: "10.0.0.1/32", MatchType: "longer"},
					{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
				}, Action: "accept"},
			}},
			"Q": {Name: "Q", Terms: []*config.PolicyTerm{
				{Name: "covering-accept", RouteFilters: []*config.RouteFilter{
					{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
				}, Action: "accept"},
			}},
		},
	}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"P", "Q"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P", "Q"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := listForIface16625(t, got, "ge-0-0-1")
	if permits := listPermits16625(got, list); len(permits) != 0 {
		t.Errorf("covering later accept must remain fail-closed, permits=%v:\n%s", permits, got)
	}
	if !strings.Contains(got, "ip prefix-list "+list+" seq 5 deny 0.0.0.0/0 le 32") {
		t.Errorf("covering later accept must keep the group fail-closed:\n%s", got)
	}
}

func TestRIPPerGroupBoundaryBeforeRejectDefaultPreservesSibling16625(t *testing.T) {
	// An explicit reject default terminates P before Q can accept
	// the exact host. The empty /32 longer boundary must therefore
	// remain representable alongside P's broader permit.
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", DefaultAction: "reject", Terms: []*config.PolicyTerm{
				{Name: "empty-boundary", RouteFilters: []*config.RouteFilter{
					{Prefix: "10.0.0.1/32", MatchType: "longer"},
					{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
				}, Action: "accept"},
			}},
			"Q": {Name: "Q", Terms: []*config.PolicyTerm{
				{Name: "later-host-accept", RouteFilters: []*config.RouteFilter{
					{Prefix: "10.0.0.1/32", MatchType: "exact"},
				}, Action: "accept"},
			}},
		},
	}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"P", "Q"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P", "Q"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := listForIface16625(t, got, "ge-0-0-1")
	if permits := listPermits16625(got, list); len(permits) != 1 || permits[0] != "10.0.0.0/8 le 32" {
		t.Errorf("later unreachable accept must not erase P's broader permit, permits=%v:\n%s", permits, got)
	}
	hostDeny := "ip prefix-list " + list + " seq 5 deny 10.0.0.1/32\n"
	siblingPermit := "ip prefix-list " + list + " seq 10 permit 10.0.0.0/8 le 32\n"
	if denyIdx, permitIdx := strings.Index(got, hostDeny), strings.Index(got, siblingPermit); denyIdx < 0 || permitIdx < 0 || denyIdx > permitIdx {
		t.Errorf("boundary host deny must precede the sibling broader permit (deny@%d permit@%d):\n%s", denyIdx, permitIdx, got)
	}
	if strings.Contains(got, "ip prefix-list "+list+" seq 5 deny 0.0.0.0/0 le 32") {
		t.Errorf("unreachable later accept must not deny-all the group:\n%s", got)
	}
}

func TestRIPPerGroupBoundaryWithDisjointLaterAcceptPreservesSibling16625(t *testing.T) {
	// A later policy that can only accept prefixes disjoint from the
	// boundary host cannot change the host's outcome, so it must not
	// force the conservative deny-all path: P's host deny and broader
	// permit plus Q's own accept must all survive.
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "empty-boundary", RouteFilters: []*config.RouteFilter{
					{Prefix: "10.0.0.1/32", MatchType: "longer"},
					{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
				}, Action: "accept"},
			}},
			"Q": {Name: "Q", Terms: []*config.PolicyTerm{
				{Name: "disjoint-accept", RouteFilters: []*config.RouteFilter{
					{Prefix: "192.0.2.0/24", MatchType: "exact"},
				}, Action: "accept"},
			}},
		},
	}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"P", "Q"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P", "Q"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := listForIface16625(t, got, "ge-0-0-1")
	permits := listPermits16625(got, list)
	if len(permits) != 2 || permits[0] != "10.0.0.0/8 le 32" || permits[1] != "192.0.2.0/24" {
		t.Errorf("disjoint later accept must preserve P's broader permit and Q's route, permits=%v:\n%s", permits, got)
	}
	hostDeny := "ip prefix-list " + list + " seq 5 deny 10.0.0.1/32\n"
	siblingPermit := "ip prefix-list " + list + " seq 10 permit 10.0.0.0/8 le 32\n"
	if denyIdx, permitIdx := strings.Index(got, hostDeny), strings.Index(got, siblingPermit); denyIdx < 0 || permitIdx < 0 || denyIdx > permitIdx {
		t.Errorf("boundary host deny must precede P's broader permit (deny@%d permit@%d):\n%s", denyIdx, permitIdx, got)
	}
	if strings.Contains(got, "ip prefix-list "+list+" seq 5 deny 0.0.0.0/0 le 32") {
		t.Errorf("disjoint later accept must not deny-all the group:\n%s", got)
	}
}

// #17688 defect 1: group exports are independent chains unioned, not
// one flattened ordered chain. CUSTOMERS' export is
// prefix-restricted with a downstream accept in its own policy? No:
// CUSTOMERS = [GUARD (default-reject, accepts nothing for static),
// DEFAULT-ONLY]; CORE = [ALL-STATIC]. A flattened ordered chain
// terminates at GUARD's default reject and starves ALL-STATIC, so
// 192.168.50.0/24 never enters the pool and CORE loses it. Each
// group's chain must be evaluated independently: GUARD's reject
// terminates only CUSTOMERS' evaluation.
func TestRIPPerGroupIndependentChainsUnionBothOrders17688(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"GUARD": {Name: "GUARD", DefaultAction: "reject"},
			"DEFAULT-ONLY": {Name: "DEFAULT-ONLY", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "0.0.0.0/0", MatchType: "exact"}}, Action: "accept"},
			}},
			"ALL-STATIC": {Name: "ALL-STATIC", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "192.168.50.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
		},
	}
	mk := func(customersFirst bool) *config.RIPConfig {
		cust := &config.RIPGroup{Name: "CUSTOMERS", Interfaces: []string{"ge-0-0-1"}, Export: []string{"GUARD", "DEFAULT-ONLY"}}
		core := &config.RIPGroup{Name: "CORE", Interfaces: []string{"ge-0-0-2"}, Export: []string{"ALL-STATIC"}}
		rip := &config.RIPConfig{
			Interfaces:   []string{"ge-0-0-1", "ge-0-0-2"},
			Redistribute: []string{"GUARD", "DEFAULT-ONLY", "ALL-STATIC"},
		}
		if customersFirst {
			rip.Groups = []*config.RIPGroup{cust, core}
		} else {
			rip.Groups = []*config.RIPGroup{core, cust}
			rip.Redistribute = []string{"ALL-STATIC", "GUARD", "DEFAULT-ONLY"}
		}
		return rip
	}
	for _, customersFirst := range []bool{true, false} {
		m := New()
		got := m.generateProtocols(nil, nil, nil, mk(customersFirst), nil, "", 0, po, nil)
		custList := listForIface16625(t, got, "ge-0-0-1")
		coreList := listForIface16625(t, got, "ge-0-0-2")
		if permits := listPermits16625(got, coreList); len(permits) != 1 || permits[0] != "192.168.50.0/24" {
			t.Errorf("customersFirst=%v: CORE permits=%v, want [192.168.50.0/24] — earlier group's default-reject starved the pool:\n%s", customersFirst, permits, got)
		}
		// GUARD default-rejects before DEFAULT-ONLY runs inside
		// CUSTOMERS' own chain, so CUSTOMERS accepts nothing.
		if permits := listPermits16625(got, custList); len(permits) != 0 {
			t.Errorf("customersFirst=%v: CUSTOMERS permits=%v, want none (its own chain rejects) — never 192.168.50.0/24:\n%s", customersFirst, permits, got)
		}
	}
}

// #17688 defect 1 route-admission witness: through the real managed
// section (which defines the composed/OR route-maps), the static
// route-map admitted set must contain 192.168.50.0/24 in both orders.
// Textual prefix-list permits alone do not prove the route enters
// the pool, so evaluate the attached map's sequences semantically.
func TestRIPPerGroupUnionPoolAdmitsCORE17688(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"GUARD": {Name: "GUARD", DefaultAction: "reject"},
			"DEFAULT-ONLY": {Name: "DEFAULT-ONLY", Terms: []*config.PolicyTerm{
				{Name: "t1", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "0.0.0.0/0", MatchType: "exact"}}, Action: "accept"},
			}},
			"ALL-STATIC": {Name: "ALL-STATIC", Terms: []*config.PolicyTerm{
				{Name: "t1", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.168.50.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
		},
	}
	for _, customersFirst := range []bool{true, false} {
		cust := &config.RIPGroup{Name: "CUSTOMERS", Interfaces: []string{"ge-0-0-1"}, Export: []string{"GUARD", "DEFAULT-ONLY"}}
		core := &config.RIPGroup{Name: "CORE", Interfaces: []string{"ge-0-0-2"}, Export: []string{"ALL-STATIC"}}
		rip := &config.RIPConfig{
			Interfaces:   []string{"ge-0-0-1", "ge-0-0-2"},
			Redistribute: []string{"GUARD", "DEFAULT-ONLY", "ALL-STATIC"},
		}
		if customersFirst {
			rip.Groups = []*config.RIPGroup{cust, core}
		} else {
			rip.Groups = []*config.RIPGroup{core, cust}
			rip.Redistribute = []string{"ALL-STATIC", "GUARD", "DEFAULT-ONLY"}
		}
		fc := &FullConfig{PolicyOptions: po, RIP: rip}
		got := New().buildManagedSection(fc)
		mapName := ""
		for _, line := range strings.Split(got, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) == 4 && f[0] == "redistribute" && f[1] == "static" && f[2] == "route-map" {
				mapName = f[3]
			}
		}
		if mapName == "" {
			t.Fatalf("customersFirst=%v: no static redistribute route-map in managed section:\n%s", customersFirst, got)
		}
		seqs := parseOrSeqs16868(t, got, mapName)
		if v := evalRoute16868(t, seqs, "192.168.50.0/24", false); v != "permit" {
			t.Errorf("customersFirst=%v: pool route-map %s verdict for 192.168.50.0/24 = %q, want permit (CORE route starved):\n%s", customersFirst, mapName, v, got)
		}
	}
}

// #17688: protocol-qualified accepts remain fail-closed. FRR's RIP
// outbound distribute-list accepts prefix/access lists only; a
// prefix-only gate would also admit connected and RIP-learned native
// routes that bypass the redistribution route-map.
func TestRIPPerGroupProtocolQualifiedAcceptFailsClosed17688(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "t1", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.168.50.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
		},
	}
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"P"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
	}
	got := New().generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := listForIface16625(t, got, "ge-0-0-1")
	if permits := listPermits16625(got, list); len(permits) != 0 {
		t.Errorf("protocol-qualified accept must stay fail-closed, permits=%v:\n%s", permits, got)
	}
	if !strings.Contains(got, "ip prefix-list "+list+" seq 5 deny 0.0.0.0/0 le 32") {
		t.Errorf("protocol-qualified accept must render explicit deny-all:\n%s", got)
	}
}

func TestRIPPerGroupMatchAllAcceptPermits17688(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "t1", Action: "accept"},
			}},
		},
	}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"P"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := listForIface16625(t, got, "ge-0-0-1")
	if permits := listPermits16625(got, list); len(permits) != 1 || permits[0] != "0.0.0.0/0 le 32" {
		t.Errorf("match-all accept must permit any prefix (0.0.0.0/0 le 32), permits=%v:\n%s", permits, got)
	}
	if strings.Contains(got, "ip prefix-list "+list+" seq 5 deny 0.0.0.0/0 le 32") {
		t.Errorf("match-all accept must not render deny-all:\n%s", got)
	}
}

// #17688: independently grouped chains still use ripd's IPv4 policy
// variant when joined in the OR-composed redistribution pool.
func TestRIPPerGroupUnionPoolUsesRIPFamilyVariant17688(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"V4": {Name: "V4", Terms: []*config.PolicyTerm{
				{Name: "v4", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.168.50.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
			"V6": {Name: "V6", Terms: []*config.PolicyTerm{
				{Name: "v6", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "2001:db8:50::/48", MatchType: "exact"}}, Action: "accept"},
			}},
		},
	}
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1", "ge-0-0-2"},
		Redistribute: []string{"V4", "V6"},
		Groups: []*config.RIPGroup{
			{Name: "V4", Interfaces: []string{"ge-0-0-1"}, Export: []string{"V4"}},
			{Name: "V6", Interfaces: []string{"ge-0-0-2"}, Export: []string{"V6"}},
		},
	}
	got := New().buildManagedSection(&FullConfig{RIP: rip, PolicyOptions: po})
	mapName := ""
	for _, line := range strings.Split(got, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 4 && fields[0] == "redistribute" && fields[1] == "static" && fields[2] == "route-map" {
			mapName = fields[3]
		}
	}
	if mapName == "" {
		t.Fatalf("missing grouped static redistribution map:\n%s", got)
	}
	seqs := redistSeqs16864(t, got, mapName)
	joined := strings.Join(seqs, "\n")
	if strings.Contains(joined, "match ipv6") {
		t.Errorf("grouped OR map must use ripd's IPv4 variant, not include v6 terms:\n%s", joined)
	}
	if !strings.Contains(joined, "match ip address prefix-list") {
		t.Errorf("grouped OR map lost its IPv4 route-filter term:\n%s", joined)
	}
	mustNoEmptyPermit16864(t, got, mapName)
}
