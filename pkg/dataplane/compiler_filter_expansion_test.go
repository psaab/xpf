package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestFilterTermExpansionCountMatchesExpand is the #3459 drift guard: the
// public config.FilterTermExpansionCount (the SSOT every counter reader uses
// to size and stride a term's counter slots) MUST equal len(expandFilterTerm)
// — the actual rule layout the compiler installs. If a future change to
// expandFilterTerm's cross-product is not mirrored there, the per-term hit
// attribution drifts onto a neighbouring term's slots (the #3459 bug).
//
// The except-prefix-list case is the load-bearing one: expandFilterTerm emits
// a (negated) rule for an except prefix, so the count must include it.
func TestFilterTermExpansionCountMatchesExpand(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"src2": {Name: "src2", Prefixes: []string{"10.1.0.0/24", "10.2.0.0/24"}},
		"dst3": {Name: "dst3", Prefixes: []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}},
		"ex1":  {Name: "ex1", Prefixes: []string{"172.16.0.0/12"}},
	}

	cases := []struct {
		name string
		term *config.FirewallFilterTerm
	}{
		{
			name: "bare term (any/any) -> 1 rule",
			term: &config.FirewallFilterTerm{Name: "t", Action: config.FilterActionAccept},
		},
		{
			name: "multi dest-port only",
			term: &config.FirewallFilterTerm{
				Name: "t", Action: config.FilterActionAccept,
				DestinationPorts: []string{"80", "443"},
			},
		},
		{
			name: "source-prefix-list (2) x dest-ports (2)",
			term: &config.FirewallFilterTerm{
				Name: "t", Action: config.FilterActionAccept,
				SourcePrefixLists: []config.PrefixListRef{{Name: "src2"}},
				DestinationPorts:  []string{"80", "443"},
			},
		},
		{
			name: "literal src (1) + src-prefix-list (2) x dst-prefix-list (3)",
			term: &config.FirewallFilterTerm{
				Name: "t", Action: config.FilterActionAccept,
				SourceAddresses:   []string{"10.0.0.1/32"},
				SourcePrefixLists: []config.PrefixListRef{{Name: "src2"}},
				DestPrefixLists:   []config.PrefixListRef{{Name: "dst3"}},
			},
		},
		{
			name: "except prefix-list still contributes a (negated) rule",
			term: &config.FirewallFilterTerm{
				Name: "t", Action: config.FilterActionAccept,
				SourcePrefixLists: []config.PrefixListRef{{Name: "src2"}, {Name: "ex1", Except: true}},
				DestinationPorts:  []string{"53"},
				SourcePorts:       []string{"1024", "2048"},
			},
		},
		{
			name: "missing prefix-list reference contributes nothing",
			term: &config.FirewallFilterTerm{
				Name: "t", Action: config.FilterActionAccept,
				SourcePrefixLists: []config.PrefixListRef{{Name: "does-not-exist"}},
			},
		},
	}

	for _, fam := range []uint8{AFInet, AFInet6} {
		for _, tc := range cases {
			want := uint32(len(expandFilterTerm(tc.term, fam, nil, prefixLists, nil)))
			got := config.FilterTermExpansionCount(tc.term, prefixLists)
			if got != want {
				t.Errorf("family=%d %s: FilterTermExpansionCount()=%d, len(expandFilterTerm)=%d",
					fam, tc.name, got, want)
			}
		}
	}
}
