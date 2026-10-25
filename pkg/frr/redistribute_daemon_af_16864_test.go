package frr

import (
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16864 (R3-B07-01): per-source redistribute maps were rendered
// daemon-agnostically. vtysh dispatches each `match` line only to
// daemons that installed it, so a clause the consuming daemon did not
// install vanished and its sequence became match-all:
//   - ospfd/ospf6d/ripd/isisd drop `match community` / `match as-path`
//     (bgpd-only), so a community-scoped BGP->IGP export leaked every
//     BGP route;
//   - ospfd/ripd drop `match ipv6 ...`, ospf6d drops `match ip ...`,
//     so in a dual-stack policy the other family's accept terms leaked
//     every route of the source and its reject terms withdrew all
//     redistribution.
//
// Fix: redistribute maps render per (policy, source, consuming
// daemon/AF) — variant suffix `-ospf` / `-ospf6` / `-rip` / `-isis-v4`
// / `-isis-v6` / `-bgp` / `-bgp6` — keeping only clauses that daemon
// evaluates, omitting terms whose AF cannot match there, and failing
// closed (omit accept, keep deny, warn) on bgpd-only conditions.
// BGP-attached maps and unreferenced policies keep the unsuffixed
// per-source render byte-identically.

var redistSeqHeader16864 = regexp.MustCompile(`^route-map (\S+) (permit|deny) (\d+)$`)

// redistSeqs16864 parses one route-map's sequences in rendered order.
// It stops at the next top-level stanza (a line starting with
// "router " or "route-map ") so stanza lines never pollute a sequence.
func redistSeqs16864(t *testing.T, got, name string) []string {
	t.Helper()
	var seqs []string
	inMap := false
	for _, ln := range strings.Split(got, "\n") {
		if m := redistSeqHeader16864.FindStringSubmatch(ln); m != nil {
			inMap = m[1] == name
			if inMap {
				seqs = append(seqs, m[2]+" "+m[3])
			}
			continue
		}
		if strings.HasPrefix(ln, "router ") {
			inMap = false
			continue
		}
		if inMap && strings.HasPrefix(ln, " ") && len(seqs) > 0 {
			seqs[len(seqs)-1] += "|" + strings.TrimSpace(ln)
		}
	}
	if len(seqs) == 0 {
		t.Fatalf("route-map %s not defined:\n%s", name, got)
	}
	return seqs
}

// mustNoEmptyPermit16864 asserts the #16864 invariant: no PERMIT
// sequence without a match clause in this variant (a dropped clause
// would make it match-all). Bare DENY sequences are fail-closed —
// the authored catch-all reject and the trailing default — and are
// the correct render, so they are not flagged.
func mustNoEmptyPermit16864(t *testing.T, got, name string) {
	t.Helper()
	for _, s := range redistSeqs16864(t, got, name) {
		if strings.HasPrefix(s, "permit") && !strings.Contains(s, "match ") {
			t.Errorf("route-map %s has empty-match permit %q (daemon would match-all):\n%s", name, s, got)
		}
	}
}

// --- s4: dual-stack policy shared by ospf and ospf3 ---------------

func dualStackPO16864() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"V4NETS": {Name: "V4NETS", Prefixes: []string{"192.168.50.0/24"}},
			"V6NETS": {Name: "V6NETS", Prefixes: []string{"2001:db8:50::/48"}},
		},
		Communities: map[string]*config.CommunityDef{
			"CUST": {Name: "CUST", Members: []string{"65000:100"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"V4-ONLY": {
				Name: "V4-ONLY",
				Terms: []*config.PolicyTerm{
					{Name: "v4", FromProtocols: []string{"static"}, PrefixList: []string{"V4NETS"}, Action: "accept"},
					{Name: "v6", FromProtocols: []string{"static"}, PrefixList: []string{"V6NETS"}, Action: "accept"},
				},
			},
		},
	}
}

func TestRedistDualStackSharedPolicyPerDaemon16864(t *testing.T) {
	fc := &FullConfig{
		PolicyOptions: dualStackPO16864(),
		OSPF:          &config.OSPFConfig{RouterID: "1.1.1.1", Areas: []*config.OSPFArea{{ID: "0.0.0.0"}}, Export: []string{"V4-ONLY"}},
		OSPFv3:        &config.OSPFv3Config{RouterID: "1.1.1.1", Areas: []*config.OSPFv3Area{{ID: "0.0.0.0"}}, Export: []string{"V4-ONLY"}},
	}
	got := New().buildManagedSection(fc)

	// Each daemon attaches its own variant.
	if !strings.Contains(got, " redistribute static route-map V4-ONLY-static-xpf-redist-ospf\n") {
		t.Errorf("ospfd must attach the -ospf variant:\n%s", got)
	}
	if !strings.Contains(got, " redistribute static route-map V4-ONLY-static-xpf-redist-ospf6\n") {
		t.Errorf("ospf6d must attach the -ospf6 variant:\n%s", got)
	}
	// s4 acceptance: ospf exports only .50, ospf6 only :50::/48.
	ospfMap := strings.Join(redistSeqs16864(t, got, "V4-ONLY-static-xpf-redist-ospf"), "\n")
	if !strings.Contains(ospfMap, "match ip address prefix-list V4NETS") || strings.Contains(ospfMap, "V6NETS") || strings.Contains(ospfMap, "match ipv6") {
		t.Errorf("ospf variant must carry only the v4 term:\n%s", ospfMap)
	}
	ospf6Map := strings.Join(redistSeqs16864(t, got, "V4-ONLY-static-xpf-redist-ospf6"), "\n")
	if !strings.Contains(ospf6Map, "match ipv6 address prefix-list V6NETS") || strings.Contains(ospf6Map, "V4NETS") || strings.Contains(ospf6Map, "match ip address") {
		t.Errorf("ospf6 variant must carry only the v6 term:\n%s", ospf6Map)
	}
	mustNoEmptyPermit16864(t, got, "V4-ONLY-static-xpf-redist-ospf")
	mustNoEmptyPermit16864(t, got, "V4-ONLY-static-xpf-redist-ospf6")
}

// --- s1/s2: single-family policies at the wrong daemon -------------

func TestRedistSingleFamilyAtWrongDaemon16864(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"V4NETS": {Name: "V4NETS", Prefixes: []string{"192.168.50.0/24"}},
			"V6NETS": {Name: "V6NETS", Prefixes: []string{"2001:db8:50::/48"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			// s1: v6-only accept + catch-all reject under ospf.
			"S1": {
				Name: "S1",
				Terms: []*config.PolicyTerm{
					{Name: "v6only", FromProtocols: []string{"static"}, PrefixList: []string{"V6NETS"}, Action: "accept"},
					{Name: "rest", FromProtocols: []string{"static"}, Action: "reject"},
				},
			},
			// s2: mirror under ospf6.
			"S2": {
				Name: "S2",
				Terms: []*config.PolicyTerm{
					{Name: "v4only", FromProtocols: []string{"static"}, PrefixList: []string{"V4NETS"}, Action: "accept"},
					{Name: "rest", FromProtocols: []string{"static"}, Action: "reject"},
				},
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF:          &config.OSPFConfig{RouterID: "1.1.1.1", Areas: []*config.OSPFArea{{ID: "0.0.0.0"}}, Export: []string{"S1"}},
		OSPFv3:        &config.OSPFv3Config{RouterID: "1.1.1.1", Areas: []*config.OSPFv3Area{{ID: "0.0.0.0"}}, Export: []string{"S2"}},
	}
	got := New().buildManagedSection(fc)

	// s1 at ospfd: the v6 accept is omitted (never an empty-match
	// permit); the catch-all reject stays, so nothing redistributes —
	// Junos-correct, since no v6 route exists in ospfd.
	s1 := redistSeqs16864(t, got, "S1-static-xpf-redist-ospf")
	for _, s := range s1 {
		if strings.HasPrefix(s, "permit") {
			t.Errorf("s1/ospf must not permit (v6 accept leaked as match-all): %v\n%s", s1, got)
		}
	}
	// s2 at ospf6d: mirror.
	s2 := redistSeqs16864(t, got, "S2-static-xpf-redist-ospf6")
	for _, s := range s2 {
		if strings.HasPrefix(s, "permit") {
			t.Errorf("s2/ospf6 must not permit (v4 accept leaked as match-all): %v\n%s", s2, got)
		}
	}
	mustNoEmptyPermit16864(t, got, "S1-static-xpf-redist-ospf")
	mustNoEmptyPermit16864(t, got, "S2-static-xpf-redist-ospf6")
}

// --- s3 + community: bgpd-only conditions fail closed at IGPs ------

func TestRedistCommunityScopedBGPToOSPF16864(t *testing.T) {
	// s3/comm: `from protocol bgp + community CUST accept`, then
	// catch-all reject. Pre-fix ospfd dropped `match community`, so
	// seq 10 permitted every BGP route (s3 exported 10.88.0.0 too).
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"CUST": {Name: "CUST", Members: []string{"65000:100"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"COMM": {
				Name: "COMM",
				Terms: []*config.PolicyTerm{
					{Name: "cust", FromProtocols: []string{"bgp"}, FromCommunity: []string{"CUST"}, Action: "accept"},
					{Name: "rest", FromProtocols: []string{"bgp"}, Action: "reject"},
				},
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF:          &config.OSPFConfig{RouterID: "1.1.1.1", Areas: []*config.OSPFArea{{ID: "0.0.0.0"}}, Export: []string{"COMM"}},
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1", Export: []string{"COMM"},
			Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true}},
		},
	}
	got := New().buildManagedSection(fc)

	if !strings.Contains(got, " redistribute bgp route-map COMM-bgp-xpf-redist-ospf\n") {
		t.Errorf("ospfd must attach the -ospf variant:\n%s", got)
	}
	ospfMap := redistSeqs16864(t, got, "COMM-bgp-xpf-redist-ospf")
	for _, s := range ospfMap {
		if strings.HasPrefix(s, "permit") && !strings.Contains(s, "match ") {
			t.Errorf("ospf variant has empty-match permit (community dropped -> match-all leak): %v\n%s", ospfMap, got)
		}
		if strings.Contains(s, "match community") {
			t.Errorf("ospf variant must not emit bgpd-only match community: %v", ospfMap)
		}
	}
	// Fail-closed: no permit at all in the ospf variant (the only
	// accept needs a community ospfd cannot evaluate).
	for _, s := range ospfMap {
		if strings.HasPrefix(s, "permit") {
			t.Errorf("community-scoped accept must be omitted at ospfd (fail closed), got permit: %v\n%s", ospfMap, got)
		}
	}
	// Positive control: the BGP-attached (unsuffixed) map keeps the
	// community match — bgpd evaluates it.
	bgpMap := redistSeqs16864(t, got, "COMM-bgp-xpf-redist")
	joined := strings.Join(bgpMap, "\n")
	if !strings.Contains(joined, "match community CUST") || !strings.Contains(joined, "permit") {
		t.Errorf("BGP control map must keep match community + permit:\n%s", joined)
	}
	// The standalone BGP export map is untouched too.
	if !strings.Contains(got, "route-map COMM permit") || !strings.Contains(got, "match community CUST") {
		t.Errorf("standalone COMM map changed:\n%s", got)
	}
}

// --- IS-IS: per-AF variants -----------------------------------------

func TestRedistISISPerAFVariants16864(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"V4NETS": {Name: "V4NETS", Prefixes: []string{"192.168.50.0/24"}},
			"V6NETS": {Name: "V6NETS", Prefixes: []string{"2001:db8:50::/48"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"DUAL": {
				Name: "DUAL",
				Terms: []*config.PolicyTerm{
					{Name: "v4", FromProtocols: []string{"static"}, PrefixList: []string{"V4NETS"}, Action: "accept"},
					{Name: "v6", FromProtocols: []string{"static"}, PrefixList: []string{"V6NETS"}, Action: "accept"},
				},
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		ISIS:          &config.ISISConfig{NET: "49.0001.1921.6800.1001.00", Level: "level-2", Export: []string{"DUAL"}},
	}
	got := New().buildManagedSection(fc)
	if !strings.Contains(got, " redistribute ipv4 static level-2 route-map DUAL-static-xpf-redist-isis-v4\n") {
		t.Errorf("isis ipv4 line must name the -isis-v4 variant:\n%s", got)
	}
	if !strings.Contains(got, " redistribute ipv6 static level-2 route-map DUAL-static-xpf-redist-isis-v6\n") {
		t.Errorf("isis ipv6 line must name the -isis-v6 variant:\n%s", got)
	}
	v4 := strings.Join(redistSeqs16864(t, got, "DUAL-static-xpf-redist-isis-v4"), "\n")
	if !strings.Contains(v4, "match ip address prefix-list V4NETS") || strings.Contains(v4, "V6NETS") {
		t.Errorf("isis-v4 variant wrong:\n%s", v4)
	}
	v6 := strings.Join(redistSeqs16864(t, got, "DUAL-static-xpf-redist-isis-v6"), "\n")
	if !strings.Contains(v6, "match ipv6 address prefix-list V6NETS") || strings.Contains(v6, "V4NETS") {
		t.Errorf("isis-v6 variant wrong:\n%s", v6)
	}
}

// --- RIP: v6 accept must not leak; route-filters are AF-scoped -----

func TestRedistRIPAndRouteFilterFamily16864(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"RF": {
				Name: "RF",
				Terms: []*config.PolicyTerm{
					{Name: "v6rf", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "2001:db8:50::/48", MatchType: "exact"}}, Action: "accept"},
					{Name: "v4rf", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.168.50.0/24", MatchType: "exact"}}, Action: "accept"},
				},
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		RIP:           &config.RIPConfig{Interfaces: []string{"ge-0/0/0.0"}, Redistribute: []string{"RF"}},
		OSPFv3:        &config.OSPFv3Config{RouterID: "1.1.1.1", Areas: []*config.OSPFv3Area{{ID: "0.0.0.0"}}, Export: []string{"RF"}},
	}
	got := New().buildManagedSection(fc)
	ripMap := redistSeqs16864(t, got, "RF-static-xpf-redist-rip")
	joined := strings.Join(ripMap, "\n")
	if strings.Contains(joined, "match ipv6") {
		t.Errorf("rip variant must omit the v6 route-filter term:\n%s", joined)
	}
	if !strings.Contains(joined, "match ip address prefix-list") {
		t.Errorf("rip variant must keep the v4 route-filter term:\n%s", joined)
	}
	mustNoEmptyPermit16864(t, got, "RF-static-xpf-redist-rip")
	v6Map := strings.Join(redistSeqs16864(t, got, "RF-static-xpf-redist-ospf6"), "\n")
	if strings.Contains(v6Map, "match ip address") || !strings.Contains(v6Map, "match ipv6 address prefix-list") {
		t.Errorf("ospf6 variant must keep only the v6 route-filter term:\n%s", v6Map)
	}
}

// --- Non-terminating modify term with unevaluable condition --------

func TestRedistModifyTermUnevaluableFailsClosed16864(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"CUST": {Name: "CUST", Members: []string{"65000:100"}},
		},
		PrefixLists: map[string]*config.PrefixList{
			"V4NETS": {Name: "V4NETS", Prefixes: []string{"192.168.50.0/24"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"MOD": {
				Name: "MOD",
				Terms: []*config.PolicyTerm{
					// Non-terminating: set metric only for CUST routes.
					{Name: "tag", FromProtocols: []string{"static"}, FromCommunity: []string{"CUST"}, Metric: 5, HasMetric: true},
					{Name: "ok", FromProtocols: []string{"static"}, PrefixList: []string{"V4NETS"}, Action: "accept"},
				},
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF:          &config.OSPFConfig{RouterID: "1.1.1.1", Areas: []*config.OSPFArea{{ID: "0.0.0.0"}}, Export: []string{"MOD"}},
	}
	got := New().buildManagedSection(fc)
	ospfMap := redistSeqs16864(t, got, "MOD-static-xpf-redist-ospf")
	joined := strings.Join(ospfMap, "\n")
	if strings.Contains(joined, "set metric 5") {
		t.Errorf("unevaluable modify term must be omitted at ospfd, not applied to every route:\n%s", joined)
	}
	if !strings.Contains(joined, "match ip address prefix-list V4NETS") {
		t.Errorf("the conditioned accept term must survive:\n%s", joined)
	}
	mustNoEmptyPermit16864(t, got, "MOD-static-xpf-redist-ospf")
}

// --- Controls: BGP-only and unreferenced renders unchanged ---------

func TestRedistBGPOnlyPolicyNoIGPVariants16864(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"CUST": {Name: "CUST", Members: []string{"65000:100"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"BGPEX": {
				Name: "BGPEX",
				Terms: []*config.PolicyTerm{
					{Name: "cust", FromProtocols: []string{"static"}, FromCommunity: []string{"CUST"}, Action: "accept"},
				},
			},
			"UNREF": {
				Name: "UNREF",
				Terms: []*config.PolicyTerm{
					{Name: "cust", FromProtocols: []string{"static"}, FromCommunity: []string{"CUST"}, Action: "accept"},
				},
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1", Export: []string{"BGPEX"},
			Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true}},
		},
	}
	got := New().buildManagedSection(fc)
	// BGP origination keeps the unsuffixed map with its community match.
	m := redistSeqs16864(t, got, "BGPEX-static-xpf-redist")
	if !strings.Contains(strings.Join(m, "\n"), "match community CUST") {
		t.Errorf("BGP-attached map must keep match community:\n%s", strings.Join(m, "\n"))
	}
	for _, bad := range []string{"BGPEX-static-xpf-redist-ospf", "BGPEX-static-xpf-redist-rip", "BGPEX-static-xpf-redist-isis", "UNREF-static-xpf-redist-ospf"} {
		if strings.Contains(got, bad) {
			t.Errorf("unexpected IGP variant %q for a BGP-only/unreferenced policy:\n%s", bad, got)
		}
	}
	// Unreferenced policy still gets its explicit per-source map.
	if !strings.Contains(got, "route-map UNREF-static-xpf-redist ") {
		t.Errorf("unreferenced policy lost its per-source map:\n%s", got)
	}
}

// --- Variant-name collision guard -----------------------------------

func TestRedistVariantCollisionRefused16864(t *testing.T) {
	po := dualStackPO16864()
	// Operator policy whose name equals a generated variant name.
	po.PolicyStatements["V4-ONLY-static-xpf-redist-ospf"] = &config.PolicyStatement{
		Name:  "V4-ONLY-static-xpf-redist-ospf",
		Terms: []*config.PolicyTerm{{Name: "x", Action: "accept"}},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF:          &config.OSPFConfig{RouterID: "1.1.1.1", Areas: []*config.OSPFArea{{ID: "0.0.0.0"}}, Export: []string{"V4-ONLY"}},
	}
	if err := New().ApplyFull(fc); err == nil {
		t.Fatal("ApplyFull accepted an operator policy colliding with a generated -ospf variant")
	}
}
