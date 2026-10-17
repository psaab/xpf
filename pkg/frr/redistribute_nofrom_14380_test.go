package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14380: a policy-statement whose terms carry no `from protocol`
// matches routes regardless of source protocol, so an IGP export of
// it must render one redistribute line per applicable non-self source
// (and each per-source route-map must be DEFINED), instead of the
// pre-fix zero lines. Mixed policies render the union; self/off-family
// filtering is unchanged.

// noFromRouteFilterPO14380 is the issue fixture: policy P with only a
// no-from `from route-filter 10.0.0.0/8 exact, then accept` term.
func noFromRouteFilterPO14380() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{{
					Name:         "t1",
					RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}},
					Action:       "accept",
				}},
			},
		},
	}
}

func TestRedistributeNoFromRouteFilterUnderOSPF14380(t *testing.T) {
	m := New()
	po := noFromRouteFilterPO14380()
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF: &config.OSPFConfig{
			RouterID: "1.1.1.1",
			Export:   []string{"P"},
			Areas:    []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}}},
		},
	}
	got := m.buildManagedSection(fc)
	for _, proto := range []string{"bgp", "connected", "isis", "kernel", "rip", "static"} {
		want := " redistribute " + proto + " route-map P-" + proto + "-xpf-redist\n"
		if !strings.Contains(got, want) {
			t.Errorf("missing %q, got:\n%s", want, got)
		}
		// Every referenced per-source route-map must be DEFINED,
		// carrying the route-filter match.
		if !strings.Contains(got, "route-map P-"+proto+"-xpf-redist permit") {
			t.Errorf("route-map P-%s-xpf-redist not defined, got:\n%s", proto, got)
		}
	}
	// Self (ospf) and off-family (ospf6, ripng) must stay filtered.
	for _, bad := range []string{" redistribute ospf ", " redistribute ospf6 ", " redistribute ripng "} {
		if strings.Contains(got, bad) {
			t.Errorf("self/off-family source %q must not render, got:\n%s", bad, got)
		}
	}
	if strings.Contains(got, "redistribute P") {
		t.Errorf("emitted FRR-invalid bare-policy line, got:\n%s", got)
	}
	if !strings.Contains(got, "match ip address prefix-list") {
		t.Errorf("no-from route-filter match missing from redist maps, got:\n%s", got)
	}
}

func TestRedistributeMixedNoFromUnderOSPF14380(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocols: []string{"static"}, Action: "accept"},
					{Name: "t2", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}, Action: "accept"},
				},
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF: &config.OSPFConfig{
			RouterID: "1.1.1.1",
			Export:   []string{"P"},
			Areas:    []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}}},
		},
	}
	got := m.buildManagedSection(fc)
	// Union, not just the explicit static source.
	for _, proto := range []string{"bgp", "connected", "isis", "kernel", "rip", "static"} {
		want := " redistribute " + proto + " route-map P-" + proto + "-xpf-redist\n"
		if !strings.Contains(got, want) {
			t.Errorf("missing %q, got:\n%s", want, got)
		}
	}
	// The no-from term must ride in a non-static per-source map (here
	// connected), not only in the map for its sibling's explicit source.
	seq := routeMapSequenceContaining(got, "P-connected-xpf-redist", "match ip address prefix-list")
	if seq == "" {
		t.Errorf("no-from term missing from P-connected-xpf-redist map, got:\n%s", got)
	}
}

func TestRedistributeSelfOnlyPolicyStillEmpty14380(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name:  "P",
				Terms: []*config.PolicyTerm{{Name: "t1", FromProtocols: []string{"ospf"}, Action: "accept"}},
			},
		},
	}
	if got := m.resolveRedistribute("P", po, "ospf", nil); got != "" {
		t.Errorf("self-only policy must still yield no redistribute line, got %q", got)
	}
}

// The expanded no-from set must join the generated-map collision belt
// at the use site: an operator policy-statement named
// P-<proto>-xpf-redist for a source the pre-fix enumeration never
// reached must refuse the apply when the policy is actually
// referenced there (FRR merges same-named route-maps). With no such
// export reference the explicit-only render is unchanged.
func TestRedistProtocolMapCollisionNoFromExpanded14380(t *testing.T) {
	po := noFromRouteFilterPO14380()
	po.PolicyStatements["P-static-xpf-redist"] = &config.PolicyStatement{
		Name:  "P-static-xpf-redist",
		Terms: []*config.PolicyTerm{{Name: "term", FromProtocols: []string{"connected"}, Action: "accept"}},
	}
	// No export reference: the pre-#14380 explicit-only collision set
	// is unchanged, so this alone is not a collision.
	if err := redistProtocolMapCollision(po); err != nil {
		t.Fatalf("redistProtocolMapCollision changed for an unreferenced policy: %v", err)
	}
	// Referenced under OSPF: the referencing node set must refuse.
	if err := redistProtocolMapCollisionForNodes(po, "ospf", "ospf"); err == nil {
		t.Fatal("referenced no-from policy colliding with an operator policy was accepted")
	}
	// Control: without the colliding operator policy there is no error.
	if err := redistProtocolMapCollisionForNodes(noFromRouteFilterPO14380(), "ospf", "ospf"); err != nil {
		t.Fatalf("redistProtocolMapCollisionForNodes flagged a clean no-from policy: %v", err)
	}
}
