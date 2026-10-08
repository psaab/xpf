package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildManagedSection_CrossContextRouteMapNoLeak_4481 is the fail-on-revert
// guard for #4481. A single policy-statement (SHARED) is applied BOTH as a BGP
// route-map in (its trailing default must be PERMIT — Junos BGP default-accept,
// #2998) AND as an OSPF export (redistribute, whose Junos default is REJECT).
//
// FRR route-maps are keyed by NAME — one object shared across use sites. The
// fix renders an OSPF map scoped to each source protocol, selecting only terms
// applicable to that source and using the redistribute fail-closed default;
// the BGP neighbor keeps referencing the permit-default base map.
//
// Revert (redistribute referencing the bare NAME) turns the attachment into
// `redistribute static route-map SHARED`, leaking the BGP permit-default map.
func TestBuildManagedSection_CrossContextRouteMapNoLeak_4481(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"SHARED": {
				Name: "SHARED",
				// Match only a subset of static routes; everything else must
				// fall to the policy default. In BGP context that default is
				// accept (#2998); in the redistribute context it must be the
				// fail-closed deny, NOT the leaked permit.
				Terms: []*config.PolicyTerm{
					{
						Name:          "t1",
						FromProtocols: []string{"static"},
						PrefixList:    []string{"allowed"},
						Action:        "accept",
					},
				},
				DefaultAction: "",
			},
		},
		PrefixLists: map[string]*config.PrefixList{
			"allowed": {Name: "allowed", Prefixes: []string{"10.0.0.0/8"}},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		// BGP neighbor applies SHARED as an inbound filter → SHARED is
		// collected into bgpAcceptDefault → its base route-map gets the
		// #2998 trailing permit.
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, Import: []string{"SHARED"}},
			},
		},
		// OSPF exports the SAME policy → rendered as a redistribute route-map.
		OSPF: &config.OSPFConfig{
			Areas:  []*config.OSPFArea{{ID: "0.0.0.0"}},
			Export: []string{"SHARED"},
		},
	}

	got := m.buildManagedSection(fc)

	// #2998 preserved: the BGP neighbor applies the base map, which keeps its
	// trailing permit (BGP default-accept).
	if !strings.Contains(got, "neighbor 10.0.2.1 route-map SHARED in\n") {
		t.Fatalf("BGP neighbor must still apply the base route-map SHARED, got:\n%s", got)
	}
	if !strings.Contains(got, "route-map SHARED permit ") {
		t.Errorf("base BGP route-map SHARED must keep its #2998 trailing permit, got:\n%s", got)
	}

	// #12065 fix: the OSPF redistribute references the static-specific map,
	// whose term set excludes other source protocols and whose default denies.
	redistMap := "SHARED-static-xpf-redist"
	if !strings.Contains(got, "redistribute static route-map "+redistMap+"\n") {
		t.Errorf("OSPF redistribute must reference the static-specific map %s, got:\n%s", redistMap, got)
	}
	if !strings.Contains(got, "route-map "+redistMap+" deny ") {
		t.Errorf("the redistribute map must end fail-closed (trailing deny), got:\n%s", got)
	}

	// The leak itself: the redistribute must NOT point at the bare permit-default
	// map SHARED.
	if strings.Contains(got, "redistribute static route-map SHARED\n") {
		t.Errorf("cross-context leak: OSPF redistribute references the BGP permit-default map SHARED, got:\n%s", got)
	}
}
