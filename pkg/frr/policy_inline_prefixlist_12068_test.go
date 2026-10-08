package frr

import (
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

var inlinePrefixListMatch12068 = regexp.MustCompile(`(?m)^ match (ip|ipv6) address prefix-list ([^\s]+)$`)

func inlinePrefixListMatches12068(rendered, family string) []string {
	var names []string
	for _, match := range inlinePrefixListMatch12068.FindAllStringSubmatch(rendered, -1) {
		if match[1] == family {
			names = append(names, match[2])
		}
	}
	return names
}

func TestInlinePrefixListNamesCollisionFree_12068(t *testing.T) {
	t.Run("operator prefix-list", func(t *testing.T) {
		po := &config.PolicyOptionsConfig{
			PrefixLists: map[string]*config.PrefixList{
				"IMP-CUST": {Name: "IMP-CUST", Prefixes: []string{"192.0.2.0/24"}},
			},
			PolicyStatements: map[string]*config.PolicyStatement{
				"IMP": {Name: "IMP", Terms: []*config.PolicyTerm{{
					Name: "CUST", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}, Action: "accept",
				}}},
			},
		}
		rendered := (&Manager{}).generatePolicyOptions(po)
		if !strings.Contains(rendered, "ip prefix-list IMP-CUST seq 5 permit 192.0.2.0/24") {
			t.Fatalf("operator prefix-list definition was lost:\n%s", rendered)
		}
		matches := inlinePrefixListMatches12068(rendered, "ip")
		if len(matches) != 1 {
			t.Fatalf("got %d inline route-filter matches, want 1:\n%s", len(matches), rendered)
		}
		if matches[0] == "IMP-CUST" {
			t.Fatalf("inline route-filter list collides with operator prefix-list %q:\n%s", matches[0], rendered)
		}
	})

	t.Run("non-injective policy-term join", func(t *testing.T) {
		po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
			"A":   {Name: "A", Terms: []*config.PolicyTerm{{Name: "B-C", RouteFilters: []*config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}, Action: "accept"}}},
			"A-B": {Name: "A-B", Terms: []*config.PolicyTerm{{Name: "C", RouteFilters: []*config.RouteFilter{{Prefix: "192.0.2.0/24", MatchType: "exact"}}, Action: "accept"}}},
		}}
		rendered := (&Manager{}).generatePolicyOptions(po)
		matches := inlinePrefixListMatches12068(rendered, "ip")
		if len(matches) != 2 {
			t.Fatalf("got %d inline route-filter matches, want 2:\n%s", len(matches), rendered)
		}
		if matches[0] == matches[1] {
			t.Fatalf("distinct (policy, term) identities share inline prefix-list name %q:\n%s", matches[0], rendered)
		}
	})

	t.Run("mixed-family suffix", func(t *testing.T) {
		po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "T", RouteFilters: []*config.RouteFilter{
					{Prefix: "10.0.0.0/8", MatchType: "exact"},
					{Prefix: "2001:db8::/32", MatchType: "exact"},
				}, Action: "accept"},
				{Name: "T_v4", RouteFilters: []*config.RouteFilter{{Prefix: "192.0.2.0/24", MatchType: "exact"}}, Action: "accept"},
			}},
		}}
		rendered := (&Manager{}).generatePolicyOptions(po)
		matches := inlinePrefixListMatches12068(rendered, "ip")
		if len(matches) != 2 {
			t.Fatalf("got %d IPv4 inline route-filter matches, want 2:\n%s", len(matches), rendered)
		}
		if matches[0] == matches[1] {
			t.Fatalf("mixed-family suffix collides with term identity: both use %q:\n%s", matches[0], rendered)
		}
	})

	t.Run("long identity stays bounded and deterministic", func(t *testing.T) {
		part := strings.Repeat("policy-", 64)
		name := inlinePrefixListName(part, part, part, "_v6")
		if len(name) > frrInlinePrefixListMaxLen {
			t.Fatalf("generated name length = %d, exceeds %d: %q", len(name), frrInlinePrefixListMaxLen, name)
		}
		if !strings.HasSuffix(name, inlinePrefixListNamespace+name[len(name)-inlinePrefixListHashHexLen:]) {
			t.Fatalf("generated name lacks reserved marker and hash suffix: %q", name)
		}
		if again := inlinePrefixListName(part, part, part, "_v6"); again != name {
			t.Fatalf("name is not deterministic: first %q, second %q", name, again)
		}
		otherContext := inlinePrefixListName(part+"-other", part, part, "_v6")
		if otherContext == name {
			t.Fatalf("different route-map context lost behind readable truncation: %q", name)
		}
		otherTerm := inlinePrefixListName(part, part, part+"-other", "_v6")
		if otherTerm == name {
			t.Fatalf("different term identity lost behind readable truncation: %q", name)
		}
	})

	t.Run("reserved operator namespace fails closed", func(t *testing.T) {
		po := &config.PolicyOptionsConfig{
			PrefixLists: map[string]*config.PrefixList{
				"operator-xpf-inline-name": {Name: "operator-xpf-inline-name", Prefixes: []string{"192.0.2.0/24"}},
			},
		}
		err := routeFilterACLNameCollision(po)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("routeFilterACLNameCollision = %v, want reserved inline-prefix-list namespace error", err)
		}
	})
}
