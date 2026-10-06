package frr

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func assertInlineDefinitionsBeforePolicyRouteMap12046(t *testing.T, section, policy string, definitions ...string) {
	t.Helper()

	header := "route-map " + policy + " "
	mapAt := strings.Index(section, header)
	if mapAt < 0 {
		t.Fatalf("route-map %q not found in managed section:\n%s", policy, section)
	}
	for _, definition := range definitions {
		definitionAt := strings.Index(section, definition)
		if definitionAt < 0 {
			t.Errorf("inline definition %q not found in managed section:\n%s", definition, section)
			continue
		}
		if definitionAt >= mapAt {
			t.Errorf("inline definition %q at byte %d must precede first route-map line for %q at byte %d:\n%s", definition, definitionAt, policy, mapAt, section)
		}
	}
}

func assertNoTopLevelLineInsideRouteMap12046(t *testing.T, section string) {
	t.Helper()

	inRouteMap := false
	for lineNo, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "route-map ") {
			if inRouteMap {
				t.Errorf("route-map header at line %d appeared before the preceding route-map exited", lineNo+1)
			}
			inRouteMap = true
			continue
		}
		if !inRouteMap {
			continue
		}
		if line == "exit" {
			inRouteMap = false
			continue
		}
		if line != "" && !strings.HasPrefix(line, " ") {
			t.Errorf("top-level line %q appeared inside a route-map block at line %d", line, lineNo+1)
		}
	}
	if inRouteMap {
		t.Error("managed section ended before route-map block exited")
	}
}

func TestInlineRouteFilterDefinitionsPrecedeRouteMaps12046(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"FROM": {Name: "FROM", Prefixes: []string{"10.1.0.0/16"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"V4": {Name: "V4", Terms: []*config.PolicyTerm{{
				Name: "t", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}, Action: "accept",
			}}},
			"V6": {Name: "V6", Terms: []*config.PolicyTerm{{
				Name: "t", RouteFilters: []*config.RouteFilter{{Prefix: "2001:db8::/32", MatchType: "orlonger"}}, Action: "accept",
			}}},
			"ACL": {Name: "ACL", Terms: []*config.PolicyTerm{{
				Name: "t", RouteFilters: []*config.RouteFilter{{Prefix: "10.2.0.0/16", MatchType: "exact"}}, PrefixList: []string{"FROM"}, Action: "accept",
			}}},
		},
	}
	section := New().buildManagedSection(&FullConfig{PolicyOptions: po})

	assertInlineDefinitionsBeforePolicyRouteMap12046(t, section, "V4", "ip prefix-list V4-t seq 5 permit 10.0.0.0/8 le 32\n")
	assertInlineDefinitionsBeforePolicyRouteMap12046(t, section, "V6", "ipv6 prefix-list V6-t seq 5 permit 2001:db8::/32 le 128\n")
	aclName := routeFilterACLName("FROM", "ip")
	assertInlineDefinitionsBeforePolicyRouteMap12046(t, section, "ACL", fmt.Sprintf("access-list %s seq 5 permit 10.1.0.0/16 exact-match\n", aclName))

	for _, want := range []string{
		" match ip address prefix-list V4-t\n",
		" match ipv6 address prefix-list V6-t\n",
		" match ip address prefix-list ACL-t\n",
		" match ip address " + aclName + "\n",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("managed section lost route-map match %q:\n%s", want, section)
		}
	}
	assertNoTopLevelLineInsideRouteMap12046(t, section)
}

func TestComposedRouteFilterDefinitionsPrecedeRouteMap12046(t *testing.T) {
	const composed = "A-B-xpf-chain"
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"A": {Name: "A", Terms: []*config.PolicyTerm{{
				Name: "t", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}, Action: "reject",
			}}},
			"B": {Name: "B", Terms: []*config.PolicyTerm{{
				Name: "t", RouteFilters: []*config.RouteFilter{{Prefix: "2001:db8::/32", MatchType: "orlonger"}}, Action: "accept",
			}}},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{{Address: "10.0.0.1", PeerAS: 65002, FamilyInet: true, Export: []string{"A", "B"}}},
		},
	}
	section := New().buildManagedSection(fc)

	assertInlineDefinitionsBeforePolicyRouteMap12046(t, section, composed,
		"ip prefix-list "+composed+"-A-t seq 5 permit 10.0.0.0/8 le 32\n",
		"ipv6 prefix-list "+composed+"-B-t seq 5 permit 2001:db8::/32 le 128\n",
	)
	assertNoTopLevelLineInsideRouteMap12046(t, section)
}

func TestQNHRouteFilterDefinitionsPrecedeRouteMap12046(t *testing.T) {
	policy := &config.PolicyStatement{Name: "P", Terms: []*config.PolicyTerm{{
		Name: "t", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "orlonger"}}, Action: "accept",
	}}}
	po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{"P": policy}}
	scope := &qnhMetricScope11447{routes: []qnhMetricRoute11447{{
		destination: "192.0.2.0/24", destinationList: "QNH-DEST", metric: 20,
	}}}

	rendered := New().renderQNHMetricPolicyMap11447(po, "QNH-P", policy, scope)
	assertInlineDefinitionsBeforePolicyRouteMap12046(t, rendered, "QNH-P",
		"ip prefix-list QNH-P-t seq 5 permit 10.0.0.0/8 le 32\n")
	assertNoTopLevelLineInsideRouteMap12046(t, rendered)
}
