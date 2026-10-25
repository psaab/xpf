package frr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16866 (R3-B07-03): Junos RIP advertises nothing by default.
// ripd's `network <if>` originates the connected subnet of every
// RIP-enabled interface and re-advertises RIP-learned routes
// outside any export filter; the legacy render attached the
// export only as `redistribute <src> route-map`, which ripd
// applies only to redistributed (non-interface, non-RIP) routes.
// The fix confines every enrolled interface with a per-instance
// deny-all / policy-derived `distribute-list prefix ... out <if>`
// gate (the #16625 mechanism, extended to group-less and
// empty-export shapes).
//
// Probe cells (mirroring the source report):
//   r1: group G { neighbor ge-0/0/1.0, ge-0/0/2.0; export ONLY-50 }
//       where ONLY-50 is source-qualified (from protocol static).
//       A destination-only gate cannot reproduce source
//       semantics for native candidates, so the chain fails
//       closed: the peer learns nothing, never the connected
//       10.0.1.0/24 / 10.0.2.0/24 subnets and never a RIP-learned
//       prefix. The prefix-only variant (ONLY-50-PREFIX) permits
//       exactly 192.168.50.0/24.
//   r2: no export at all. The peer must learn nothing.
// Positive controls: the static per-source route-map still
// renders for ONLY-50; the prefix-only policy permits exactly
// its accepted prefix and enrols one composed connected map.
// F1/F3 guards: no `redistribute rip` (FRR-invalid) ever
// renders, and connected is attached exactly once per stanza.

func rip16866PO() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"ONLY-50": {Name: "ONLY-50", Terms: []*config.PolicyTerm{
				{Name: "t1", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "192.168.50.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
		},
	}
}

// rip16866ListFor returns the prefix-list name bound out <iface>,
// failing the test when no binding exists (pre-fix RED).
func rip16866ListFor(t *testing.T, got, iface string) string {
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
	t.Fatalf("no distribute-list binding for %s (interface routes leak ungated) in:\n%s", iface, got)
	return ""
}

func rip16866Permits(got, name string) []string {
	var out []string
	prefix := "ip prefix-list " + name + " seq "
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, prefix) {
			f := strings.SplitN(strings.TrimPrefix(line, prefix), " ", 3)
			if len(f) == 3 && f[1] == "permit" {
				out = append(out, f[2])
			}
		}
	}
	return out
}

// rip16866ListLines returns the full rendered lines of list
// `name` in order, for candidate simulation.
func rip16866ListLines(got, name string) []string {
	var out []string
	prefix := "ip prefix-list " + name + " seq "
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, prefix) {
			out = append(out, line)
		}
	}
	return out
}

// rip16866Candidate runs candidate (CIDR) through the named
// list with FRR first-match semantics via the #16762 simulator.
// NOMATCH means the distribute-list denies (no permit matched).
func rip16866Candidate(got, name, candidate string) string {
	return simulatePrefixList16762(rip16866ListLines(got, name), candidate)
}

func TestRIPNoExportDeniesAll16866(t *testing.T) {
	// r2 cell: interfaces, no export anywhere. Junos advertises
	// nothing; every enrolled interface must be deny-all gated.
	m := New()
	rip := &config.RIPConfig{Interfaces: []string{"ge-0-0-1", "ge-0-0-2"}}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	for _, iface := range []string{"ge-0-0-1", "ge-0-0-2"} {
		list := rip16866ListFor(t, got, iface)
		if permits := rip16866Permits(got, list); len(permits) != 0 {
			t.Errorf("no-export RIP must advertise nothing on %s, permits=%v:\n%s", iface, permits, got)
		}
		if !strings.Contains(got, "ip prefix-list "+list+" seq 5 deny 0.0.0.0/0 le 32") {
			t.Errorf("explicit deny-all entry missing for %s:\n%s", iface, got)
		}
	}
	// Enrollment itself is unchanged (RIP still runs, learns routes).
	if !strings.Contains(got, "network ge-0-0-1\n") || !strings.Contains(got, "network ge-0-0-2\n") {
		t.Errorf("enrollment missing:\n%s", got)
	}
}

func TestRIPBareRedistributeDeniesInterfaceRoutes16866(t *testing.T) {
	// Group-less bare tokens: `redistribute connected/static` asks
	// ripd to originate those sources with NO policy. Junos has no
	// such spelling — without an export policy nothing (connected
	// or RIP-learned) may be advertised. The bare redistribute
	// verbs stay (positive control: the authored redistribution is
	// not silently dropped from the stanza), but the outbound
	// distribute-list must deny everything.
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"trust0", "dmz0"},
		Passive:      []string{"dmz0"},
		Redistribute: []string{"connected", "static"},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	for _, iface := range []string{"trust0", "dmz0"} {
		list := rip16866ListFor(t, got, iface)
		if permits := rip16866Permits(got, list); len(permits) != 0 {
			t.Errorf("bare-token RIP must advertise nothing on %s, permits=%v:\n%s", iface, permits, got)
		}
	}
	for _, want := range []string{"redistribute connected\n", "redistribute static\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("authored redistribute verb %q lost:\n%s", want, got)
		}
	}
}

func TestRIPGroupExportGatesConnectedAndLearned16866(t *testing.T) {
	// r1 cell with a SOURCE-QUALIFIED policy (from protocol
	// static): the accepted set cannot be reproduced by a
	// destination-only gate for native candidates, so the chain
	// fails closed — deny-all on both neighbors, no connected or
	// RIP-learned leak (#16866 F2). The static redistribution
	// itself still flows through its per-source route-map
	// (positive control below).
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1", "ge-0-0-2"},
		Redistribute: []string{"ONLY-50"},
		Groups: []*config.RIPGroup{
			{Name: "G", Interfaces: []string{"ge-0-0-1", "ge-0-0-2"}, Export: []string{"ONLY-50"}},
		},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, rip16866PO(), nil)
	for _, iface := range []string{"ge-0-0-1", "ge-0-0-2"} {
		list := rip16866ListFor(t, got, iface)
		if permits := rip16866Permits(got, list); len(permits) != 0 {
			t.Errorf("%s permits=%v, want deny-all (source-qualified policy is inexpressible at the prefix gate):\n%s", iface, permits, got)
		}
	}
	if !strings.Contains(got, "redistribute static route-map ONLY-50-") {
		t.Errorf("policy redistribution (positive control) missing:\n%s", got)
	}
	if strings.Contains(got, "redistribute rip") {
		t.Errorf("FRR-invalid self-redistribution rendered:\n%s", got)
	}
}

func TestRIPPrefixOnlyPolicyFlowsAcceptedPrefix16866(t *testing.T) {
	// Prefix-only r1 variant: ONLY-50-PREFIX accepts exactly
	// 192.168.50.0/24 with no source condition. The gate permits
	// exactly that prefix (a static, a connected subnet, or a
	// RIP-learned route to it all advertise in Junos); every
	// other connected/RIP-learned prefix is denied. Exactly one
	// composed connected attachment enrols non-interface
	// connected routes; no `redistribute rip` ever renders (F1).
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"ONLY-50-PREFIX": {Name: "ONLY-50-PREFIX", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "192.168.50.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
		},
	}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1", "ge-0-0-2"},
		Redistribute: []string{"ONLY-50-PREFIX"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1", "ge-0-0-2"}, Export: []string{"ONLY-50-PREFIX"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	for _, iface := range []string{"ge-0-0-1", "ge-0-0-2"} {
		list := rip16866ListFor(t, got, iface)
		permits := rip16866Permits(got, list)
		if len(permits) != 1 || permits[0] != "192.168.50.0/24" {
			t.Errorf("%s permits=%v, want exactly [192.168.50.0/24]:\n%s", iface, permits, got)
		}
	}
	if n := strings.Count(got, "redistribute connected route-map "); n != 1 {
		t.Errorf("want exactly 1 connected attachment, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "redistribute connected route-map ONLY-50-PREFIX-connected-xpf-redist-rip\n") {
		t.Errorf("single-policy connected attachment missing:\n%s", got)
	}
	if strings.Contains(got, "redistribute rip") {
		t.Errorf("FRR-invalid self-redistribution rendered:\n%s", got)
	}
}

func TestRIPGroupNoExportDeniesAll16866(t *testing.T) {
	// A group with NO export statement: Junos advertises nothing
	// to those neighbors. Pre-fix this skipped filtering entirely.
	m := New()
	rip := &config.RIPConfig{
		Interfaces: []string{"ge-0-0-1"},
		Groups:     []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, rip16866PO(), nil)
	list := rip16866ListFor(t, got, "ge-0-0-1")
	if permits := rip16866Permits(got, list); len(permits) != 0 {
		t.Errorf("empty-export group must advertise nothing, permits=%v:\n%s", permits, got)
	}
}

func TestRIPGlobalNeighborUnderGroupsDeniesAll16866(t *testing.T) {
	// An interface enrolled only globally (no group) under a
	// grouped config has no export policy of its own: Junos
	// advertises nothing to it. Pre-fix it received the union.
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1", "ge-0-0-9"},
		Redistribute: []string{"ONLY-50"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"ONLY-50"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, rip16866PO(), nil)
	list := rip16866ListFor(t, got, "ge-0-0-9")
	if permits := rip16866Permits(got, list); len(permits) != 0 {
		t.Errorf("global-only neighbor must advertise nothing, permits=%v:\n%s", permits, got)
	}
	// Grouped interface: ONLY-50 is source-qualified, so its
	// chain fails closed too (F2) — the grouped permit set is
	// empty, distinct from the global-only deny-all only in
	// provenance, identical in effect.
	glist := rip16866ListFor(t, got, "ge-0-0-1")
	if permits := rip16866Permits(got, glist); len(permits) != 0 {
		t.Errorf("grouped interface permits=%v, want deny-all (source-qualified chain):\n%s", permits, got)
	}
}

func TestRIPPolicyChainProfilesConnectedAndRip16866(t *testing.T) {
	// A prefix-only policy can accept connected and RIP-learned
	// routes in Junos. Exactly its accepted prefix may leave.
	// Connected enrols as ONE composed attachment; RIP is never
	// self-redistributed (FRR-invalid, F1) — learned routes are
	// confined by the prefix gate, which is exact here because
	// the policy decides by prefix alone.
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"DIRECT-AND-RIP": {Name: "DIRECT-AND-RIP", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.2.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
		},
	}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"DIRECT-AND-RIP"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"DIRECT-AND-RIP"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := rip16866ListFor(t, got, "ge-0-0-1")
	permits := rip16866Permits(got, list)
	if len(permits) != 1 || permits[0] != "10.0.2.0/24" {
		t.Errorf("permits=%v, want [10.0.2.0/24]:\n%s", permits, got)
	}
	if !strings.Contains(got, "redistribute connected route-map DIRECT-AND-RIP-connected-xpf-redist-rip\n") {
		t.Errorf("single composed connected attachment missing:\n%s", got)
	}
	if strings.Contains(got, "redistribute rip") {
		t.Errorf("FRR-invalid self-redistribution rendered (F1):\n%s", got)
	}
}

func TestRIPTwoPolicyConnectedChainSingleAttachment16866(t *testing.T) {
	// F3: P1 (direct 10.50.0.0/24) + P2 (direct 10.60.0.0/24) in
	// one group-less chain. FRR keeps ONE route-map per source,
	// so the render must carry exactly one connected attachment
	// naming the composed chain map — never per-policy appends
	// that would leave only P2 effective. Both accepted prefixes
	// permit at the gate, in both chain orders.
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P1": {Name: "P1", Terms: []*config.PolicyTerm{
				{Name: "t1", FromProtocols: []string{"direct"}, RouteFilters: []*config.RouteFilter{{Prefix: "10.50.0.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
			"P2": {Name: "P2", Terms: []*config.PolicyTerm{
				{Name: "t1", FromProtocols: []string{"direct"}, RouteFilters: []*config.RouteFilter{{Prefix: "10.60.0.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
		},
	}
	for _, chain := range [][]string{{"P1", "P2"}, {"P2", "P1"}} {
		m := New()
		rip := &config.RIPConfig{Interfaces: []string{"ge-0-0-1"}, Redistribute: chain}
		got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
		if n := strings.Count(got, "redistribute connected"); n != 1 {
			t.Errorf("chain %v: want exactly 1 connected attachment, got %d:\n%s", chain, n, got)
		}
		if !strings.Contains(got, "redistribute connected route-map P1-P2-xpf-chain-connected-xpf-redist-rip\n") &&
			!strings.Contains(got, "redistribute connected route-map P2-P1-xpf-chain-connected-xpf-redist-rip\n") {
			t.Errorf("chain %v: composed connected attachment missing:\n%s", chain, got)
		}
		if strings.Contains(got, "redistribute rip") {
			t.Errorf("chain %v: FRR-invalid self-redistribution rendered:\n%s", chain, got)
		}
	}
}

func TestRIPStaticOnlyPolicyNoNativeLeak16866(t *testing.T) {
	// F2 counterexample: ONLY-STATIC accepts 10.0.0.0/8 orlonger
	// from static only. A connected 10.0.2.0/24 or a RIP-learned
	// 10.0.3.0/24 in the same range must NOT be permitted by the
	// prefix gate — the chain fails closed (deny-all), whether or
	// not any static exists. The static per-source map still
	// renders (its own filtering is source-correct).
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"ONLY-STATIC": {Name: "ONLY-STATIC", Terms: []*config.PolicyTerm{
				{Name: "t1", FromProtocols: []string{"static"}, RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}, Action: "accept"},
			}},
		},
	}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1", "ge-0-0-2"},
		Redistribute: []string{"ONLY-STATIC"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1", "ge-0-0-2"}, Export: []string{"ONLY-STATIC"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	for _, iface := range []string{"ge-0-0-1", "ge-0-0-2"} {
		list := rip16866ListFor(t, got, iface)
		if permits := rip16866Permits(got, list); len(permits) != 0 {
			t.Errorf("%s permits=%v — native connected/RIP routes in 10/8 would leak under a static-only policy:\n%s", iface, permits, got)
		}
	}
}

func TestRIPGroupLessPolicyExportGatesAllInterfaces16866(t *testing.T) {
	// Legacy Junos spelling without groups: `redistribute
	// <policy>` is the instance export. ONLY-50 is
	// source-qualified, so every enrolled interface fails
	// closed (deny-all) rather than leaking native routes (F2).
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1", "ge-0-0-2"},
		Redistribute: []string{"ONLY-50"},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, rip16866PO(), nil)
	for _, iface := range []string{"ge-0-0-1", "ge-0-0-2"} {
		list := rip16866ListFor(t, got, iface)
		if permits := rip16866Permits(got, list); len(permits) != 0 {
			t.Errorf("%s permits=%v, want deny-all:\n%s", iface, permits, got)
		}
	}
	if strings.Contains(got, "redistribute rip") {
		t.Errorf("FRR-invalid self-redistribution rendered:\n%s", got)
	}
}

func TestRIPFullSectionTwoNativeChains16866(t *testing.T) {
	// Full-section (production assembly) oracle for F1/F2/F3:
	// two groups with distinct prefix-only direct-accepting
	// policies PA (10.1.0.0/24) and PB (10.2.0.0/24), compiler
	// union Redistribute=[PA,PB]. Asserts:
	//   - exactly ONE `redistribute connected` attachment in the
	//     whole section (no duplicate/last-wins, F1/F3);
	//   - no `redistribute rip` anywhere (FRR-invalid, F1);
	//   - every route-map named by a redistribute line is DEFINED
	//     in the section (no dangling <P>-rip-...-rip, F2);
	//   - each group's prefix gate permits exactly its own
	//     accepted prefix (both originate, no cross-leak).
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"PA": {Name: "PA", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "10.1.0.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
			"PB": {Name: "PB", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "10.2.0.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		RIP: &config.RIPConfig{
			Interfaces:   []string{"ge-0-0-1", "ge-0-0-2"},
			Redistribute: []string{"PA", "PB"},
			Groups: []*config.RIPGroup{
				{Name: "GA", Interfaces: []string{"ge-0-0-1"}, Export: []string{"PA"}},
				{Name: "GB", Interfaces: []string{"ge-0-0-2"}, Export: []string{"PB"}},
			},
		},
	}
	got := New().buildManagedSection(fc)
	if strings.Contains(got, "redistribute rip") {
		t.Errorf("FRR-invalid self-redistribution in full section:\n%s", got)
	}
	if n := strings.Count(got, "redistribute connected"); n != 1 {
		t.Errorf("want exactly 1 redistribute connected in full section, got %d:\n%s", n, got)
	}
	defined := make(map[string]bool)
	for _, line := range strings.Split(got, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "route-map" {
			defined[f[1]] = true
		}
	}
	for _, line := range strings.Split(got, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redistribute ") && strings.Contains(line, " route-map ") {
			name := strings.Fields(line)[len(strings.Fields(line))-1]
			if !defined[name] {
				t.Errorf("dangling route-map %q attached but never defined:\n%s", name, got)
			}
		}
	}
	gaList := rip16866ListFor(t, got, "ge-0-0-1")
	gbList := rip16866ListFor(t, got, "ge-0-0-2")
	if p := rip16866Permits(got, gaList); len(p) != 1 || p[0] != "10.1.0.0/24" {
		t.Errorf("GA permits=%v, want [10.1.0.0/24]:\n%s", p, got)
	}
	if p := rip16866Permits(got, gbList); len(p) != 1 || p[0] != "10.2.0.0/24" {
		t.Errorf("GB permits=%v, want [10.2.0.0/24]:\n%s", p, got)
	}
	var connMap string
	for _, line := range strings.Split(got, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redistribute connected route-map ") {
			connMap = strings.Fields(line)[3]
		}
	}
	if connMap == "" || !defined[connMap] {
		t.Fatalf("connected attachment map %q not defined:\n%s", connMap, got)
	}
}

func TestRIPExplicitRejectDefaultTerminatesChain16866(t *testing.T) {
	// Re-review F1: P1 (accept 10.50.0.0/24, statement default
	// reject) terminates the chain; P2's 10.60.0.0/24 must NOT be
	// permitted in [P1 P2] order. Control [P2 P1]: P2 runs first
	// and its permit stands. Both asserted via candidate
	// simulation, not permit strings.
	mkPO := func() *config.PolicyOptionsConfig {
		return &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
			"P1": {Name: "P1", DefaultAction: "reject", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "10.50.0.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
			"P2": {Name: "P2", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "10.60.0.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
		}}
	}
	render := func(chain []string) (string, string) {
		m := New()
		rip := &config.RIPConfig{
			Interfaces:   []string{"ge-0-0-1"},
			Redistribute: chain,
			Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: chain}},
		}
		got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, mkPO(), nil)
		return got, rip16866ListFor(t, got, "ge-0-0-1")
	}
	got, list := render([]string{"P1", "P2"})
	if a := rip16866Candidate(got, list, "10.60.0.0/24"); a == "permit" {
		t.Errorf("[P1 P2]: 10.60.0.0/24 permitted despite P1 terminating reject (F1):\n%s", got)
	}
	if a := rip16866Candidate(got, list, "10.50.0.0/24"); a != "permit" {
		t.Errorf("[P1 P2]: 10.50.0.0/24 = %s, want permit:\n%s", a, got)
	}
	got2, list2 := render([]string{"P2", "P1"})
	if a := rip16866Candidate(got2, list2, "10.60.0.0/24"); a != "permit" {
		t.Errorf("[P2 P1] control: 10.60.0.0/24 = %s, want permit:\n%s", a, got2)
	}
}

func TestRIPNextPolicyFailsClosed16866(t *testing.T) {
	// Re-review F2: `then next policy` on 10.60.0.0/24 skips the
	// later accept term. The gate cannot lower a conditional
	// jump, so the statement fails closed (deny-all gate) rather
	// than permitting via the skipped term.
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		"P": {Name: "P", Terms: []*config.PolicyTerm{
			{Name: "jump", NextPolicy: true, RouteFilters: []*config.RouteFilter{{Prefix: "10.60.0.0/24", MatchType: "exact"}}},
			{Name: "later", RouteFilters: []*config.RouteFilter{{Prefix: "10.60.0.0/24", MatchType: "exact"}}, Action: "accept"},
		}},
	}}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"P"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := rip16866ListFor(t, got, "ge-0-0-1")
	if a := rip16866Candidate(got, list, "10.60.0.0/24"); a == "permit" {
		t.Errorf("next-policy candidate permitted via skipped accept term (F2):\n%s", got)
	}
	if permits := rip16866Permits(got, list); len(permits) != 0 {
		t.Errorf("next-policy statement must fail closed, permits=%v:\n%s", permits, got)
	}
}

func TestRIPLongestMatchRouteFilters16866(t *testing.T) {
	// Re-review F3 + gate2 R2: one accepting term with
	// overlapping filters `10.0.0.0/8 orlonger` + `10.1.0.0/16
	// exact` carries a longest-match stop. A single ordered
	// list cannot express "this term does not match, keep
	// evaluating" (later terms might accept), so the chain
	// fails closed deny-all instead of promoting the stop to
	// a chain deny (over-deny) or dropping it (over-permit).
	// No candidate permits, in either authored order.
	for _, order := range []int{0, 1} {
		filters := []*config.RouteFilter{
			{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
			{Prefix: "10.1.0.0/16", MatchType: "exact"},
		}
		if order == 1 {
			filters[0], filters[1] = filters[1], filters[0]
		}
		po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{{Name: "t1", RouteFilters: filters, Action: "accept"}}},
		}}
		m := New()
		rip := &config.RIPConfig{
			Interfaces:   []string{"ge-0-0-1"},
			Redistribute: []string{"P"},
			Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
		}
		got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
		list := rip16866ListFor(t, got, "ge-0-0-1")
		for _, cand := range []string{"10.1.1.0/24", "10.1.0.0/16", "10.2.0.0/24"} {
			if a := rip16866Candidate(got, list, cand); a == "permit" {
				t.Errorf("order=%d candidate %s permitted; stop-carrying accept term must fail closed (R2):\n%s", order, cand, got)
			}
		}
		if p := rip16866Permits(got, list); len(p) != 0 {
			t.Errorf("order=%d: permits=%v, want deny-all:\n%s", order, p, got)
		}
	}
}

func TestRIPNextPolicyZeroEntryJumpsFailClosed16866(t *testing.T) {
	// Gate2 B1: jumps yielding ZERO prefix entries still fire
	// in Junos — unconditional (match-all), source-only (fires
	// for that source class), and empty-prefix-list (unproven
	// match-nothing) shapes must ALL fail closed, not skip to
	// the later accept. Each renders deny-all (no permits).
	cases := map[string][]*config.PolicyTerm{
		"unconditional": {
			{Name: "jump", NextPolicy: true},
			{Name: "later", RouteFilters: []*config.RouteFilter{{Prefix: "10.60.0.0/24", MatchType: "exact"}}, Action: "accept"},
		},
		"source-only": {
			{Name: "jump", NextPolicy: true, FromProtocols: []string{"direct"}},
			{Name: "later", RouteFilters: []*config.RouteFilter{{Prefix: "10.60.0.0/24", MatchType: "exact"}}, Action: "accept"},
		},
		"empty-prefix-list": {
			{Name: "jump", NextPolicy: true, PrefixList: []string{"EMPTY"}},
			{Name: "later", RouteFilters: []*config.RouteFilter{{Prefix: "10.60.0.0/24", MatchType: "exact"}}, Action: "accept"},
		},
	}
	for label, terms := range cases {
		po := &config.PolicyOptionsConfig{
			PrefixLists:      map[string]*config.PrefixList{"EMPTY": {Name: "EMPTY"}},
			PolicyStatements: map[string]*config.PolicyStatement{"P": {Name: "P", Terms: terms}},
		}
		m := New()
		rip := &config.RIPConfig{
			Interfaces:   []string{"ge-0-0-1"},
			Redistribute: []string{"P"},
			Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
		}
		got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
		list := rip16866ListFor(t, got, "ge-0-0-1")
		if a := rip16866Candidate(got, list, "10.60.0.0/24"); a == "permit" {
			t.Errorf("%s jump: 10.60.0.0/24 permitted via skipped accept (B1):\n%s", label, got)
		}
		if p := rip16866Permits(got, list); len(p) != 0 {
			t.Errorf("%s jump: must fail closed, permits=%v:\n%s", label, p, got)
		}
	}
}

func TestRIPJumpPlusRejectDefaultTerminates16866(t *testing.T) {
	// Gate2 B2: [P1 P2] where P1 carries a jump term AND an
	// explicit reject default. Any NextPolicy presence fails
	// the whole chain closed now, so P2's accept can never
	// permit — in either chain order.
	mkPO := func() *config.PolicyOptionsConfig {
		return &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
			"P1": {Name: "P1", DefaultAction: "reject", Terms: []*config.PolicyTerm{
				{Name: "jump", NextPolicy: true, FromProtocols: []string{"static"}},
				{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "10.50.0.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
			"P2": {Name: "P2", Terms: []*config.PolicyTerm{
				{Name: "t1", RouteFilters: []*config.RouteFilter{{Prefix: "10.60.0.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
		}}
	}
	for _, chain := range [][]string{{"P1", "P2"}, {"P2", "P1"}} {
		m := New()
		rip := &config.RIPConfig{
			Interfaces:   []string{"ge-0-0-1"},
			Redistribute: chain,
			Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: chain}},
		}
		got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, mkPO(), nil)
		list := rip16866ListFor(t, got, "ge-0-0-1")
		if a := rip16866Candidate(got, list, "10.60.0.0/24"); a == "permit" {
			t.Errorf("chain %v: 10.60.0.0/24 permitted despite jump+reject P1 (B2):\n%s", chain, got)
		}
	}
}

func TestRIPCrossTermLongestMatchStopFailsClosed16866(t *testing.T) {
	// Gate2 R2: t1 (accept, overlapping filters with a
	// longest-match stop) + t2 (accept 10.1.1.0/24). Junos:
	// 10.1.1.0/24 fails t1's longest match, then t2 accepts.
	// One ordered list cannot express term-no-match-continue,
	// so the chain fails closed (deny-all) rather than
	// over-denying via a promoted chain deny or over-permitting
	// by dropping the stop. Silent exactness is not claimed.
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		"P": {Name: "P", Terms: []*config.PolicyTerm{
			{Name: "t1", Action: "accept", RouteFilters: []*config.RouteFilter{
				{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
				{Prefix: "10.1.0.0/16", MatchType: "exact"},
			}},
			{Name: "t2", Action: "accept", RouteFilters: []*config.RouteFilter{
				{Prefix: "10.1.1.0/24", MatchType: "exact"},
			}},
		}},
	}}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"P"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := rip16866ListFor(t, got, "ge-0-0-1")
	if p := rip16866Permits(got, list); len(p) != 0 {
		t.Errorf("cross-term stop shape must fail closed, permits=%v:\n%s", p, got)
	}
}

func TestRIPMixedPrefixListRouteFilterFailsClosed16866(t *testing.T) {
	// Gate3 B1: Junos ANDs distinct from-types in one term.
	// Term {PL=[10.50.0.0/24], RF 10.0.0.0/8 orlonger} accepts
	// only the intersection (10.50.0.0/24). A union lowering
	// would permit 10.60.0.0/24 and 10.99.0.0/24 natively.
	// The mixed term is inexpressible: deny-all gate.
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{"PL": {Name: "PL", Prefixes: []string{"10.50.0.0/24"}}},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "t1", Action: "accept", PrefixList: []string{"PL"}, RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}},
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
	list := rip16866ListFor(t, got, "ge-0-0-1")
	for _, cand := range []string{"10.60.0.0/24", "10.99.0.0/24", "10.50.0.0/24"} {
		if a := rip16866Candidate(got, list, cand); a == "permit" {
			t.Errorf("mixed PL+RF candidate %s permitted (union leak, B1):\n%s", cand, got)
		}
	}
}

func TestRIPPrefixListEntriesNormalized16866(t *testing.T) {
	// Gate3 B2: prefix-list entries reach the gate only via
	// NormalizePrefixListEntry. Malformed and newline-bearing
	// entries fail the chain closed (deny-all, no injected
	// lines); a bare host renders masked as /32.
	render := func(prefixes []string) string {
		po := &config.PolicyOptionsConfig{
			PrefixLists: map[string]*config.PrefixList{"PL": {Name: "PL", Prefixes: prefixes}},
			PolicyStatements: map[string]*config.PolicyStatement{
				"P": {Name: "P", Terms: []*config.PolicyTerm{{Name: "t1", Action: "accept", PrefixList: []string{"PL"}}}},
			},
		}
		m := New()
		rip := &config.RIPConfig{
			Interfaces:   []string{"ge-0-0-1"},
			Redistribute: []string{"P"},
			Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
		}
		return m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	}
	for label, prefixes := range map[string][]string{
		"malformed": {"bogus"},
		"newline":   {"10.50.0.0/24\nip prefix-list EVIL seq 5 permit 0.0.0.0/0 le 32"},
	} {
		got := render(prefixes)
		if strings.Contains(got, "EVIL") || strings.Contains(got, "permit bogus") {
			t.Errorf("%s entry reached render verbatim:\n%s", label, got)
		}
		list := rip16866ListFor(t, got, "ge-0-0-1")
		if p := rip16866Permits(got, list); len(p) != 0 {
			t.Errorf("%s entry: permits=%v, want deny-all:\n%s", label, p, got)
		}
	}
	got := render([]string{"10.50.0.5"})
	if !strings.Contains(got, "permit 10.50.0.5/32") {
		t.Errorf("bare host must render normalized /32:\n%s", got)
	}
	got = render([]string{"10.50.0.1/24"})
	if !strings.Contains(got, "permit 10.50.0.0/24") || strings.Contains(got, "permit 10.50.0.1/24") {
		t.Errorf("host-bits entry must render masked:\n%s", got)
	}
}

func TestRIPRejectTermStopFailsClosed16866(t *testing.T) {
	// Gate3 Astra R2: t1 reject {10/8 orlonger + 10.1/16 exact}
	// does NOT match 10.1.1.0/24 (longest-match fails), so t2
	// accept must decide. The stop cannot be copied into the
	// chain deny; the shape fails closed instead.
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		"P": {Name: "P", Terms: []*config.PolicyTerm{
			{Name: "t1", Action: "reject", RouteFilters: []*config.RouteFilter{
				{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
				{Prefix: "10.1.0.0/16", MatchType: "exact"},
			}},
			{Name: "t2", Action: "accept", RouteFilters: []*config.RouteFilter{
				{Prefix: "10.1.1.0/24", MatchType: "exact"},
			}},
		}},
	}}
	m := New()
	rip := &config.RIPConfig{
		Interfaces:   []string{"ge-0-0-1"},
		Redistribute: []string{"P"},
		Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
	list := rip16866ListFor(t, got, "ge-0-0-1")
	if p := rip16866Permits(got, list); len(p) != 0 {
		t.Errorf("reject-stop shape must fail closed, permits=%v:\n%s", p, got)
	}
}

func TestRIPSameAddressDifferentLengthStop16866(t *testing.T) {
	// #17843 witness through the RIP gate: 10.0.0.0/8 orlonger +
	// 10.0.0.0/16 exact (same masked address, different length)
	// in an accept term with statement reject. 10.0.1.0/24 fails
	// the /16 exact longest match and must NOT permit via /8.
	// The stop-carrying accept fails closed; both orders.
	for _, swap := range []bool{false, true} {
		filters := []*config.RouteFilter{
			{Prefix: "10.0.0.0/8", MatchType: "orlonger"},
			{Prefix: "10.0.0.0/16", MatchType: "exact"},
		}
		if swap {
			filters[0], filters[1] = filters[1], filters[0]
		}
		po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", DefaultAction: "reject", Terms: []*config.PolicyTerm{
				{Name: "t1", Action: "accept", RouteFilters: filters},
			}},
		}}
		m := New()
		rip := &config.RIPConfig{
			Interfaces:   []string{"ge-0-0-1"},
			Redistribute: []string{"P"},
			Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
		}
		got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
		list := rip16866ListFor(t, got, "ge-0-0-1")
		if a := rip16866Candidate(got, list, "10.0.1.0/24"); a == "permit" {
			t.Errorf("swap=%v: 10.0.1.0/24 permitted past failed /16 longest match (#17843):\n%s", swap, got)
		}
	}
}

func TestRIPPlainRejectTermsCandidateSim16866(t *testing.T) {
	// Gate4 regression guard: PLAIN reject terms (no
	// longest-match stop) must keep their deny emission — the
	// gate4 defect failed the whole chain closed for every
	// reject entry. Candidate-simulated:
	//   RF: reject 10.1.0.0/16 exact, then accept 10.0.0.0/8
	//       orlonger → 10.1.0.0/16 deny, 10.2.0.0/24 permit.
	//   PL: reject prefix-list [10.1.0.0/16], then accept
	//       10.0.0.0/8 orlonger → same decisions.
	rfPO := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
		"P": {Name: "P", Terms: []*config.PolicyTerm{
			{Name: "deny-sub", Action: "reject", RouteFilters: []*config.RouteFilter{{Prefix: "10.1.0.0/16", MatchType: "exact"}}},
			{Name: "accept-rest", Action: "accept", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}},
		}},
	}}
	plPO := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{"DENYPL": {Name: "DENYPL", Prefixes: []string{"10.1.0.0/16"}}},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "deny-sub", Action: "reject", PrefixList: []string{"DENYPL"}},
				{Name: "accept-rest", Action: "accept", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}},
			}},
		},
	}
	for label, po := range map[string]*config.PolicyOptionsConfig{"route-filter": rfPO, "prefix-list": plPO} {
		m := New()
		rip := &config.RIPConfig{
			Interfaces:   []string{"ge-0-0-1"},
			Redistribute: []string{"P"},
			Groups:       []*config.RIPGroup{{Name: "G", Interfaces: []string{"ge-0-0-1"}, Export: []string{"P"}}},
		}
		got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, po, nil)
		list := rip16866ListFor(t, got, "ge-0-0-1")
		if a := rip16866Candidate(got, list, "10.1.0.0/16"); a != "deny" {
			t.Errorf("%s: rejected candidate 10.1.0.0/16 gate=%s, want deny:\n%s", label, a, got)
		}
		if a := rip16866Candidate(got, list, "10.2.0.0/24"); a != "permit" {
			t.Errorf("%s: accepted candidate 10.2.0.0/24 gate=%s, want permit (plain reject must not collapse chain):\n%s", label, a, got)
		}
	}
}

func TestRIPGateNameCollisionFullSection16866(t *testing.T) {
	// Gate5 R1: an operator prefix-list named into the generated
	// gate namespace (`xpf-rip-0-grp-0`, the first gate a
	// group-less render allocates) would merge with the gate in
	// one FRR object. Both arms must refuse at ApplyFull:
	//   ordinary-reject gate: a surviving foreign seq-15 permit
	//     (203.0.113.0/24) must never leak past the gate;
	//   deny-all (no export): the gate's seq-5 deny must never
	//     overwrite the unrelated operator policy's list.
	// The full section renders both definitions into the shared
	// name (proving reachability), and ApplyFull refuses.
	operatorPO := func() *config.PolicyOptionsConfig {
		return &config.PolicyOptionsConfig{
			PrefixLists: map[string]*config.PrefixList{
				"xpf-rip-0-grp-0": {Name: "xpf-rip-0-grp-0", Prefixes: []string{"10.99.0.0/24", "10.98.0.0/24", "203.0.113.0/24"}},
			},
			PolicyStatements: map[string]*config.PolicyStatement{
				"P": {Name: "P", Terms: []*config.PolicyTerm{
					{Name: "deny-sub", Action: "reject", RouteFilters: []*config.RouteFilter{{Prefix: "10.1.0.0/16", MatchType: "exact"}}},
					{Name: "accept-rest", Action: "accept", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}},
				}},
			},
		}
	}
	arms := map[string]*config.RIPConfig{
		"ordinary-reject": {Interfaces: []string{"ge-0-0-1"}, Redistribute: []string{"P"}},
		"deny-all":        {Interfaces: []string{"ge-0-0-1"}},
	}
	for label, ripCfg := range arms {
		fc := &FullConfig{PolicyOptions: operatorPO(), RIP: ripCfg}
		section := New().buildManagedSection(fc)
		if !strings.Contains(section, "ip prefix-list xpf-rip-0-grp-0 seq 15 permit 203.0.113.0/24") {
			t.Fatalf("%s: operator entry not rendered (witness unreachable):\n%s", label, section)
		}
		confPath := filepath.Join(t.TempDir(), "frr.conf")
		if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
		err := m.ApplyFull(fc)
		if err == nil || !strings.Contains(err.Error(), "xpf-rip-0-grp-0") {
			t.Errorf("%s: ApplyFull must refuse the gate-name collision naming the list, got %v", label, err)
		}
	}
	// Positive control: a non-reserved operator name applies.
	fc := &FullConfig{PolicyOptions: &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{"OPERATOR-LIST": {Name: "OPERATOR-LIST", Prefixes: []string{"203.0.113.0/24"}}},
	}, RIP: &config.RIPConfig{Interfaces: []string{"ge-0-0-1"}}}
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
	if err := m.ApplyFull(fc); err != nil {
		t.Errorf("non-reserved operator list must apply cleanly, got %v", err)
	}
}
