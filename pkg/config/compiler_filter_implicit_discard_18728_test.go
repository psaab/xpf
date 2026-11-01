package config

import (
	"strings"
	"testing"
)

// #18728: FirewallFilterHasCatchAll decides BOTH the commit warning and the
// runtime implicit final discard (the dataplane snapshot's synthetic term and
// the lo0 kernel drop), so it must count every term that ends evaluation for
// every packet reaching it. The pre-#18728 predicate counted only
// accept/discard/reject; that under-count was harmless for a warning but
// would now ADD a discard after a filter that already terminates everything.

func TestFirewallFilterHasCatchAllRefined18728(t *testing.T) {
	for _, tc := range []struct {
		name  string
		terms []*FirewallFilterTerm
		want  bool
	}{
		{"no terms", nil, false},
		{"all nil terms", []*FirewallFilterTerm{nil, nil}, false},
		{"unconstrained accept", []*FirewallFilterTerm{{Name: "a", Action: FilterActionAccept}}, true},
		{"unconstrained discard", []*FirewallFilterTerm{{Name: "d", Action: FilterActionDiscard}}, true},
		{"unconstrained reject", []*FirewallFilterTerm{{Name: "r", Action: FilterActionReject}}, true},
		// Modifier-only terminates as implicit accept (#14632).
		{"unconstrained count only", []*FirewallFilterTerm{{Name: "c", Count: "all"}}, true},
		{"unconstrained log only", []*FirewallFilterTerm{{Name: "l", Log: true}}, true},
		{"unconstrained forwarding-class only", []*FirewallFilterTerm{{Name: "fc", ForwardingClass: "ef"}}, true},
		// A routing-instance term terminates on the routing decision.
		{"unconstrained routing-instance", []*FirewallFilterTerm{{Name: "ri", RoutingInstance: "blue"}}, true},
		// A terminal action wins over a contradictory next-term bit (#5142).
		{"accept with next term", []*FirewallFilterTerm{{Name: "a", Action: FilterActionAccept, NextTerm: true}}, true},
		// The routing-instance term terminates even with next term (#9140).
		{"routing-instance with next term", []*FirewallFilterTerm{{Name: "ri", RoutingInstance: "blue", NextTerm: true}}, true},
		// Only an authored `then { ...; next term; }` with no action falls through.
		{"count then next term", []*FirewallFilterTerm{{Name: "c", Count: "c", NextTerm: true}}, false},
		{"constrained accept", []*FirewallFilterTerm{{Name: "a", Protocols: []string{"tcp"}, Action: FilterActionAccept}}, false},
		{"constrained count only", []*FirewallFilterTerm{{Name: "c", DestinationPorts: []string{"179"}, Count: "bgp"}}, false},
		{"catch-all after allowlist", []*FirewallFilterTerm{
			{Name: "ssh", Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Action: FilterActionAccept},
			{Name: "default", Action: FilterActionAccept},
		}, true},
		{"fall-through then catch-all", []*FirewallFilterTerm{
			{Name: "mark", Count: "m", NextTerm: true},
			{Name: "default", Action: FilterActionDiscard},
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := FirewallFilterHasCatchAll(&FirewallFilter{Name: "f", Terms: tc.terms})
			if got != tc.want {
				t.Fatalf("FirewallFilterHasCatchAll = %v, want %v", got, tc.want)
			}
		})
	}
	if FirewallFilterHasCatchAll(nil) {
		t.Fatal("a nil filter has no catch-all")
	}
}

// The commit warning follows the refined predicate: silent for a
// modifier-only or routing-instance catch-all, and it says what now happens.
func TestFilterNoCatchAllWarningRefinedAndWorded18728(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter allow term ssh from protocol tcp",
		"set firewall family inet filter allow term ssh from destination-port 22",
		"set firewall family inet filter allow term ssh then accept",
		"set firewall family inet filter count-all term c then count all",
		"set firewall family inet filter mark-next term m then count m",
		"set firewall family inet filter mark-next term m then next term",
		"set interfaces ge-0-0-0 unit 0 family inet filter input allow",
		"set interfaces ge-0-0-1 unit 0 family inet filter input count-all",
		"set interfaces ge-0-0-2 unit 0 family inet filter input mark-next",
	})
	warnings := ValidateConfig(cfg)
	got := hasNoCatchAllWarn(warnings, "allow")
	if got == "" {
		t.Fatalf("expected the #18728 warning for allowlist %q, got %v", "allow", warnings)
	}
	for _, want := range []string{"unmatched traffic is discarded", "implicit-discard", "then accept", "#18728"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "xpf accepts traffic matching no term") {
		t.Errorf("warning still describes the pre-#18728 implicit accept: %q", got)
	}
	if w := hasNoCatchAllWarn(warnings, "count-all"); w != "" {
		t.Errorf("modifier-only unconstrained term is a catch-all (#14632 implicit accept); unexpected warning %q", w)
	}
	if hasNoCatchAllWarn(warnings, "mark-next") == "" {
		t.Errorf("`then { count; next term; }` falls through and is not a catch-all; expected a warning, got %v", warnings)
	}
}

// The lo0 implicit-discard exemption: "lo" always; the cluster control link
// and fabric only when a chassis cluster names them; never fxp0. Bare em0/fab0
// on a standalone node are not proof of a cluster role (#11068).
func TestLo0ImplicitDiscardExemptNetdevs18728(t *testing.T) {
	ifaces := map[string]*InterfaceConfig{
		"em0":  {Name: "em0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"fab0": {Name: "fab0", FabricMembers: []string{"ge-0/0/0"}},
		"fxp0": {Name: "fxp0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}
	standalone := &Config{}
	standalone.Interfaces.Interfaces = ifaces
	if got := Lo0ImplicitDiscardExemptNetdevs(standalone); len(got) != 1 || got[0] != "lo" {
		t.Fatalf("standalone exempt = %v, want [lo]", got)
	}
	if got := Lo0ImplicitDiscardExemptNetdevs(nil); len(got) != 1 || got[0] != "lo" {
		t.Fatalf("nil config exempt = %v, want [lo]", got)
	}
	cluster := &Config{}
	cluster.Interfaces.Interfaces = ifaces
	cluster.Chassis.Cluster = &ClusterConfig{ControlInterface: "em0"}
	got := Lo0ImplicitDiscardExemptNetdevs(cluster)
	want := []string{"lo", "em0", "fab0", "ge-0-0-0"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("cluster exempt = %v, want %v", got, want)
	}
	for _, n := range got {
		if strings.HasPrefix(n, "fxp0") {
			t.Fatalf("fxp0 must not be exempt from the lo0 implicit discard: %v", got)
		}
	}
}

// The synthetic term's name is reserved: an authored `implicit-discard` term
// is warned about (on any filter, attached or not), once per filter, and an
// ordinary name is not.
func TestImplicitDiscardTermNameReserved18728(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter clash term implicit-discard from destination-port 23",
		"set firewall family inet filter clash term implicit-discard then accept",
		"set firewall family inet filter clash term default then accept",
		"set firewall family inet6 filter clash6 term implicit-discard then discard",
		"set firewall family inet filter fine term web from destination-port 443",
		"set firewall family inet filter fine term web then accept",
	})
	var got []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "reserved for the synthetic Junos implicit final discard") {
			got = append(got, w)
		}
	}
	if len(got) != 2 {
		t.Fatalf("want one reserved-name warning per clashing filter (2), got %d: %q", len(got), got)
	}
	for _, want := range []string{`filter "clash" term "implicit-discard"`, `inet6 filter "clash6"`} {
		found := false
		for _, w := range got {
			if strings.Contains(w, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no warning containing %q in %q", want, got)
		}
	}
	if ImplicitDiscardTermName != "implicit-discard" {
		t.Fatalf("ImplicitDiscardTermName = %q", ImplicitDiscardTermName)
	}
}

// #18728 incident: the required set is resolved from the cluster ROLES, and
// the validator fails closed on an empty name or a missing role netdev. The
// lab-shaped node1 config (control-interface em0, fab1 over ge-7/0/0, plus
// fab0 over ge-0/0/0 for the peer) yields an exemption that satisfies it.
func TestLo0ImplicitDiscardRequiredAndValidate18728(t *testing.T) {
	cfg := &Config{}
	cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: "em0"}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"em0":  {Name: "em0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"fab0": {Name: "fab0", FabricMembers: []string{"ge-0/0/0"}},
		"fab1": {Name: "fab1", FabricMembers: []string{"ge-7/0/0"}},
		"fxp0": {Name: "fxp0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}
	req := Lo0ImplicitDiscardRequiredNetdevs(cfg)
	want := "lo,em0,fab0,fab1,ge-0-0-0,ge-7-0-0"
	if strings.Join(req, ",") != want {
		t.Fatalf("required = %v, want %s", req, want)
	}
	if err := ValidateLo0ImplicitDiscardExempt(Lo0ImplicitDiscardExemptNetdevs(cfg), req); err != nil {
		t.Fatalf("the rendered exemption must satisfy the role requirement: %v", err)
	}
	for _, bad := range [][]string{
		{"lo", "em0", "fab0", "fab1", "ge-0-0-0"},                 // fabric member of node1 missing
		{"lo", "fab0", "fab1", "ge-0-0-0", "ge-7-0-0"},            // control link missing
		{"lo", "em0", "", "fab0", "fab1", "ge-0-0-0", "ge-7-0-0"}, // empty name
	} {
		if err := ValidateLo0ImplicitDiscardExempt(bad, req); err == nil {
			t.Errorf("exemption %q must be refused", bad)
		}
	}
	if got := Lo0ImplicitDiscardRequiredNetdevs(&Config{}); strings.Join(got, ",") != "lo" {
		t.Fatalf("standalone required = %v, want [lo]", got)
	}
}
