package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14698: a reject-only `from protocol` term is a Junos filter condition,
// never a redistribution request. Before the fix, every FromProtocols
// token enrolled its source protocol (and a no-from term expanded to the
// whole node-fitting domain) regardless of term.Action, so a defensive
// guard like
//
//	term guard { from protocol bgp; then reject; }
//	term adv   { from community C; then accept; }
//
// exported under OSPF rendered `redistribute bgp route-map
// EXP-bgp-xpf-redist` whose filtered map contains the guard deny plus
// every protocol-agnostic accept term (and, absent an explicit policy
// default, the fail-closed deny trailing — but with a community/prefix
// accept or default-accept the BGP RIB leaks). Junos never originates
// BGP routes from such a policy.
//
// The fix enrolls a source protocol only when at least one term that can
// actually accept routes for that source exists: an explicit accept /
// non-terminating term naming the protocol, or a no-from accept /
// non-terminating term (which still expands, #14380). A protocol named
// only by reject terms — or only by a no-from reject term for every
// source — enrols nothing.

func rejectOnlyPO14698() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"C": {Name: "C", Members: []string{"65000:1"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "guard", FromProtocols: []string{"bgp"}, Action: "reject"},
					{Name: "adv", FromCommunity: []string{"C"}, Action: "reject"},
					{Name: "conn", FromProtocols: []string{"direct"}, Action: "accept"},
				},
			},
		},
	}
}

// Decisive regression from the issue: reject-only bgp must not activate
// redistribution, while the positive connected term is preserved. The
// community term here is also reject-only for every source except the
// explicit connected accept, so bgp's filtered map can never permit.
func TestRedistributeRejectOnlyProtocolDoesNotActivateRedist14698(t *testing.T) {
	m := New()
	po := rejectOnlyPO14698()
	got := m.resolveRedistribute("EXP", po, "ospf", nil)
	if strings.Contains(got, "redistribute bgp") {
		t.Errorf("reject-only from protocol bgp activated redistribution:\n%s", got)
	}
	if !strings.Contains(got, "redistribute connected route-map EXP-connected-xpf-redist") {
		t.Errorf("positive connected term lost, want filtered connected entry:\n%s", got)
	}
	// Every other source is likewise permit-dominated here (only deny
	// terms apply to them), so none may be attached.
	for _, proto := range []string{"isis", "kernel", "rip", "static"} {
		if strings.Contains(got, "redistribute "+proto+" ") {
			t.Errorf("permit-dominated source %s attached:\n%s", proto, got)
		}
	}
	if strings.Contains(got, "redistribute ospf") {
		t.Errorf("self protocol redistributed:\n%s", got)
	}
}

// The issue's leak shape with a protocol-AGNOSTIC accept: bgp routes
// carrying community C are genuinely permitted by the policy (the
// guard denies only non-C bgp routes), so Junos would originate them
// and bgp must stay enrolled — with the guard deny FIRST in its map.
// This pins that the fix does not over-prune to "any reject term
// mentioning a protocol kills the source".
func TestRedistributeRejectGuardWithAgnosticAcceptKeepsSource14698(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"C": {Name: "C", Members: []string{"65000:1"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "guard", FromProtocols: []string{"bgp"}, PrefixList: []string{"BAD"}, Action: "reject"},
					{Name: "adv", FromCommunity: []string{"C"}, Action: "accept"},
				},
			},
			"BADP": {
				Name:  "BADP",
				Terms: []*config.PolicyTerm{{Name: "t", FromProtocols: []string{"static"}, Action: "accept"}},
			},
		},
		PrefixLists: map[string]*config.PrefixList{
			"BAD": {Name: "BAD", Prefixes: []string{"10.0.0.0/8"}},
		},
	}
	po.PolicyStatements["EXP"].Terms[0].PrefixList = []string{"BAD"}
	got := m.resolveRedistribute("EXP", po, "ospf", nil)
	if !strings.Contains(got, "redistribute bgp route-map EXP-bgp-xpf-redist") {
		t.Errorf("agnostic accept must keep bgp enrolled (permit-capable):\n%s", got)
	}
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF: &config.OSPFConfig{
			RouterID: "1.1.1.1",
			Export:   []string{"EXP"},
			Areas:    []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}}},
		},
	}
	rendered := m.buildManagedSection(fc)
	bgpMap := routeMapBlock12065(rendered, "EXP-bgp-xpf-redist")
	denyIdx := strings.Index(bgpMap, "deny")
	permitIdx := strings.Index(bgpMap, "permit")
	if denyIdx < 0 || permitIdx < 0 || denyIdx > permitIdx {
		t.Errorf("bgp redist map must deny (guard) before permit (agnostic accept):\n%s", bgpMap)
	}
}

// End-to-end: the managed section must neither attach nor define a
// bgp redist map for the reject-only source, and the positive maps keep
// their permit sequences.
func TestRedistributeRejectOnlyProtocolManagedSection14698(t *testing.T) {
	m := New()
	po := rejectOnlyPO14698()
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF: &config.OSPFConfig{
			RouterID: "1.1.1.1",
			Export:   []string{"EXP"},
			Areas:    []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}}},
		},
	}
	got := m.buildManagedSection(fc)
	if strings.Contains(got, "redistribute bgp") {
		t.Errorf("managed section attaches reject-only bgp source:\n%s", got)
	}
	if strings.Contains(got, "EXP-bgp-xpf-redist") {
		t.Errorf("managed section defines a route-map for reject-only bgp source:\n%s", got)
	}
	if !strings.Contains(got, "redistribute connected route-map EXP-connected-xpf-redist") {
		t.Errorf("managed section lost positive connected redistribute:\n%s", got)
	}
	connMap := routeMapBlock12065(got, "EXP-connected-xpf-redist")
	if connMap == "" || !strings.Contains(connMap, "permit") {
		t.Errorf("connected redist map missing its accept permit sequence:\n%s", connMap)
	}
}

// A protocol named by both a reject guard and a later accept term is a
// positive source: the guard still filters within its map, but the
// source must be enrolled (Junos ordered-term semantics preserved).
func TestRedistributeRejectPlusAcceptSameProtocolEnrolls14698(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"BAD":  {Name: "BAD", Prefixes: []string{"10.0.0.0/8"}},
			"GOOD": {Name: "GOOD", Prefixes: []string{"192.0.2.0/24"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "guard", FromProtocols: []string{"bgp"}, PrefixList: []string{"BAD"}, Action: "reject"},
					{Name: "adv", FromProtocols: []string{"bgp"}, PrefixList: []string{"GOOD"}, Action: "accept"},
				},
				DefaultAction: "reject",
			},
		},
	}
	got := m.resolveRedistribute("EXP", po, "ospf", nil)
	if !strings.Contains(got, "redistribute bgp route-map EXP-bgp-xpf-redist") {
		t.Errorf("protocol with an accept term was not enrolled:\n%s", got)
	}
}

// A no-from reject term alone enrols nothing: it can only deny, so no
// source may be activated by it.
func TestRedistributeNoFromRejectOnlyEnrollsNothing14698(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "deny-all", Action: "reject"},
				},
			},
		},
	}
	if got := m.resolveRedistribute("EXP", po, "ospf", nil); got != "" {
		t.Errorf("no-from reject-only policy activated redistribution:\n%s", got)
	}
	// And its (non-)enrollment must not define per-source maps either.
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF: &config.OSPFConfig{
			RouterID: "1.1.1.1",
			Export:   []string{"EXP"},
			Areas:    []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}}},
		},
	}
	if got := m.buildManagedSection(fc); strings.Contains(got, "-xpf-redist") {
		t.Errorf("no-from reject-only policy defined redist maps:\n%s", got)
	}
}

// A no-from reject term followed by an explicit accept still enrols the
// accept's source only — the reject term must not expand the domain.
func TestRedistributeNoFromRejectPlusExplicitAccept14698(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "deny-agnostic", Action: "reject"},
					{Name: "adv-static", FromProtocols: []string{"static"}, Action: "accept"},
				},
			},
		},
	}
	got := m.resolveRedistribute("EXP", po, "ospf", nil)
	if !strings.Contains(got, "redistribute static route-map EXP-static-xpf-redist") {
		t.Errorf("explicit static accept lost:\n%s", got)
	}
	for _, proto := range []string{"bgp", "connected", "isis", "kernel", "rip"} {
		if strings.Contains(got, "redistribute "+proto+" ") {
			t.Errorf("no-from reject term expanded to %s:\n%s", proto, got)
		}
	}
}

// Unknown lenient-path tokens must not enrol either: only known FRR
// routing-protocol keywords may become a `redistribute <proto>` source.
func TestRedistributeUnknownProtocolTokenDoesNotEnroll14698(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "bogus", FromProtocols: []string{"ospv"}, Action: "accept"},
					{Name: "conn", FromProtocols: []string{"direct"}, Action: "accept"},
				},
			},
		},
	}
	got := m.resolveRedistribute("EXP", po, "ospf", nil)
	if strings.Contains(got, "ospv") {
		t.Errorf("unknown protocol token enrolled as a redistribute source:\n%s", got)
	}
	if !strings.Contains(got, "redistribute connected route-map EXP-connected-xpf-redist") {
		t.Errorf("positive connected term lost alongside unknown token:\n%s", got)
	}
}

// Enrollment predicate unit cells: reject-only / unknown tokens enrol
// nothing; accept, non-terminating, and mixed terms enrol their source.
func TestRedistProtocolsRejectAndUnknownGate14698(t *testing.T) {
	cases := []struct {
		name  string
		terms []*config.PolicyTerm
		want  []string
	}{
		{
			name:  "reject only",
			terms: []*config.PolicyTerm{{Name: "g", FromProtocols: []string{"bgp"}, Action: "reject"}},
			want:  nil,
		},
		{
			name:  "unknown only",
			terms: []*config.PolicyTerm{{Name: "g", FromProtocols: []string{"ospv"}, Action: "accept"}},
			want:  nil,
		},
		{
			name:  "accept",
			terms: []*config.PolicyTerm{{Name: "g", FromProtocols: []string{"bgp"}, Action: "accept"}},
			want:  []string{"bgp"},
		},
		{
			name:  "non-terminating can fall through to default accept",
			terms: []*config.PolicyTerm{{Name: "g", FromProtocols: []string{"bgp"}}},
			want:  []string{"bgp"},
		},
		{
			name: "reject plus accept same proto",
			terms: []*config.PolicyTerm{
				{Name: "g", FromProtocols: []string{"bgp"}, Action: "reject"},
				{Name: "a", FromProtocols: []string{"bgp"}, Action: "accept"},
			},
			want: []string{"bgp"},
		},
		{
			name:  "direct alias canonicalizes",
			terms: []*config.PolicyTerm{{Name: "g", FromProtocols: []string{"direct"}, Action: "accept"}},
			want:  []string{"connected"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := &config.PolicyStatement{Name: "P", Terms: tc.terms}
			got := redistProtocols(ps)
			if len(got) != len(tc.want) {
				t.Fatalf("redistProtocols = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("redistProtocols = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// BGP export path (#14586): a reject-only bgp guard in a BGP export
// policy must not originate other protocols? No — under router bgp the
// guard's protocol is self; use static as the reject-only source here:
// the BGP export chain must not emit `redistribute static` for a
// static source named only by a reject term, while a positive direct
// term still originates.
func TestBGPRedistRejectOnlySourceDoesNotOriginate14698(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "guard", FromProtocols: []string{"static"}, Action: "reject"},
					{Name: "adv", FromProtocols: []string{"direct"}, Action: "accept"},
				},
				DefaultAction: "reject",
			},
		},
	}
	entries := m.bgpPolicyRedistEntries14586([]string{"EXP"}, po)
	for _, e := range entries {
		if e.proto == "static" {
			t.Errorf("reject-only static source originated via BGP export: %+v", entries)
		}
	}
	found := false
	for _, e := range entries {
		if e.proto == "connected" {
			found = true
		}
	}
	if !found {
		t.Errorf("positive direct source lost via BGP export: %+v", entries)
	}
}
