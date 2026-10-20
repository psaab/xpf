package cmdtree

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15721 (V46-03): selector/value subtrees missing from OperationalTree made
// Canonicalize return CanonicalUnknown for lawful commands, so every
// regex-restricted login class was refused them and completion died.
func TestCanonicalizeSelectorSubtrees15721(t *testing.T) {
	okLines := []string{
		"show security match-policies",
		"show security match-policies from-zone trust to-zone untrust source-ip 10.0.1.1 destination-ip 10.0.2.1 protocol tcp destination-port 443",
		"show security match-policies protocol icmp icmp-type 8 icmp-code 0 non-first-fragment ingress-interface ge-0/0/0.0 source-port 1234",
		"test policy",
		"test policy from-zone trust to-zone untrust source-ip 10.0.1.1 destination-ip 10.0.2.1 destination-port 80 protocol tcp",
		"test policy to-zone untrust from-zone trust protocol udp",
		"show security policies policy-name allow-web",
		"show security policies hit-count",
		"show security policies hit-count from-zone trust to-zone untrust",
		"show security policies hit-count to-zone untrust",
		"show security policies hit-count from-zone trust hit-count",
		"show security nat source pool",
		"show security nat source pool snat-pool-1",
		"show security nat destination pool",
		"show security nat destination pool dnat-pool-1",
		"show bgp neighbor",
		"show bgp neighbor 10.0.0.1",
		"show bgp neighbor 10.0.0.1 received-routes",
		"show bgp neighbor 2001:db8::1 advertised-routes",
		"show protocols bgp neighbor",
		"show protocols bgp neighbor 10.0.0.1",
		"show protocols bgp neighbor 10.0.0.1 advertised-routes",
		// Neighbours that must not regress.
		"show security policies",
		"show security policies from-zone trust to-zone untrust",
		"show security policies from-zone trust to-zone untrust hit-count",
		"show security nat source rule rs-rule",
		"show security nat source rule-set rs1",
		"show bgp summary",
		"show protocols bgp summary",
	}
	for _, line := range okLines {
		got, res := Canonicalize(OperationalTree, strings.Fields(line))
		if res != CanonicalOK || strings.Join(got, " ") != line {
			t.Errorf("Canonicalize(%q) = %q (%v), want %q CanonicalOK", line, strings.Join(got, " "), res, line)
		}
	}

	// Fail-closed controls: dangling selectors, garbage after a value, and
	// sibling-keyword smuggling must stay CanonicalUnknown (#8289/#9505).
	badLines := []string{
		"show security match-policies from-zone",
		"show security match-policies bogus-selector trust",
		"show security match-policies from-zone trust bogus",
		"test policy from-zone",
		"show security policies policy-name",
		"show security policies hit-count from-zone",
		"show security policies hit-count bogus trust",
		"show security nat source pool snat-pool-1 bogus",
		"show security nat destination pool dnat-pool-1 bogus",
		"show protocols bgp neighbor received-routes bogus",
		"show protocols bgp neighbor 10.0.0.1 received-routes bogus",
	}
	for _, line := range badLines {
		if _, res := Canonicalize(OperationalTree, strings.Fields(line)); res == CanonicalOK {
			t.Errorf("Canonicalize(%q) = CanonicalOK, want refusal", line)
		}
	}

	// Completion: dynamic value slots must offer configured values.
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{"trust": {}, "untrust": {}},
			NAT: config.NATConfig{
				SourcePools: map[string]*config.NATPool{"snat-pool-1": {}},
				Destination: &config.DestinationNATConfig{
					Pools: map[string]*config.NATPool{"dnat-pool-1": {}},
				},
			},
		},
	}
	completions := []struct {
		words string
		want  string
	}{
		{"show security match-policies from-zone", "trust"},
		{"test policy from-zone", "trust"},
		{"show security policies hit-count from-zone", "trust"},
		{"show security nat source pool", "snat-pool-1"},
		{"show security nat destination pool", "dnat-pool-1"},
	}
	for _, tc := range completions {
		cands := CompleteFromTree(OperationalTree, strings.Fields(tc.words), "", cfg)
		if !contains(cands, tc.want) {
			t.Errorf("CompleteFromTree(%q) = %v, want %q offered", tc.words, cands, tc.want)
		}
	}
	// The BGP neighbor IP slot and the match-policies selector keywords
	// themselves must be offered.
	if cands := CompleteFromTree(OperationalTree, []string{"show", "bgp", "neighbor"}, "", cfg); !contains(cands, "<ip>") {
		t.Errorf("CompleteFromTree(show bgp neighbor) = %v, want <ip> offered", cands)
	}
	if cands := CompleteFromTree(OperationalTree, []string{"show", "security", "match-policies"}, "from", cfg); !contains(cands, "from-zone") {
		t.Errorf("CompleteFromTree(show security match-policies, from) = %v, want from-zone offered", cands)
	}
}
