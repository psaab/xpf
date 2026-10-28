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
