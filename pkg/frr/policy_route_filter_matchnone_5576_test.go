package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// rf5576PolicyOptions builds a one-statement / one-term export policy
// carrying a single route-filter whose Prefix and MatchType are supplied
// verbatim, so a test can feed the #5576 keyword-in-CIDR-slot shape
// (Prefix:"longer") the compiler produces from `route-filter longer
// exact`, as well as a legitimate form.
func rf5576PolicyOptions(prefix, matchType string) *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXPORT": {
				Name: "EXPORT",
				Terms: []*config.PolicyTerm{
					{
						Name:         "t1",
						RouteFilters: []*config.RouteFilter{{Prefix: prefix, MatchType: matchType}},
						Action:       "accept",
					},
				},
				DefaultAction: "reject",
			},
		},
	}
}

// TestRouteFilterMatchNoneFalseDeny_5576 documents WHY the #5576 commit-time
// rejection matters. If a match-type keyword reaches the renderer in the
// prefix slot (`route-filter longer exact` → Prefix="longer",
// MatchType="exact"), net.ParseCIDR("longer") fails, so the malformed-prefix
// belt emits NO prefix-list entry — yet the route-map still carries `match
// ip address prefix-list <derived inline name>` against the now-EMPTY list.
// That is an operational match-none: the term's authored `accept` matches
// nothing (a silent false-deny). The positional commit validator
// (ValidateRouteFilterArgPositional) rejects this at commit; this render
// test locks the fail-closed belt that still guards the tolerant load /
// peer-sync path, and confirms the legitimate form renders its entry.
func TestRouteFilterMatchNoneFalseDeny_5576(t *testing.T) {
	inlineName := inlinePrefixListName("EXPORT", "EXPORT", "t1", "")
	// (a) keyword-in-CIDR-slot renders match-none: no prefix-list entry.
	bad := New().generatePolicyOptions(rf5576PolicyOptions("longer", "exact"))
	if strings.Contains(bad, "permit longer") {
		t.Errorf("#5576: malformed prefix `longer` must NOT render a prefix-list line, got:\n%s", bad)
	}
	if strings.Contains(bad, "prefix-list "+inlineName+" seq") {
		t.Errorf("#5576: no seq entry may exist for the match-none list, got:\n%s", bad)
	}

	// (b) the legitimate form renders the correct prefix-list entry AND
	// keeps the route-map match reference.
	good := New().generatePolicyOptions(rf5576PolicyOptions("10.0.0.0/24", "exact"))
	if !strings.Contains(good, "ip prefix-list "+inlineName+" seq 5 permit 10.0.0.0/24\n") {
		t.Errorf("#5576: legitimate `10.0.0.0/24 exact` must render its prefix-list entry, got:\n%s", good)
	}
	if !strings.Contains(good, "match ip address prefix-list "+inlineName) {
		t.Errorf("#5576: legitimate form must keep the route-map match, got:\n%s", good)
	}
}
