package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// bigPrefixList5456 builds a PrefixList of n valid CIDR entries directly (no
// parsing). The content is irrelevant to the rule COUNT — expandFilterTerm
// emits one rule per cross-product entry regardless of whether a given CIDR
// parses — so a repeated valid literal keeps the slice cheap to build.
func bigPrefixList5456(name string, n int) *config.PrefixList {
	pfx := make([]string, n)
	for i := range pfx {
		pfx[i] = "10.0.0.0/32"
	}
	return &config.PrefixList{Name: name, Prefixes: pfx}
}

// TestFilterTermExpansionCountLargeValidMatchesAndBoundsUint32 extends the
// #3459 drift guard for #5456: for a LARGE-but-valid term (cross-product well
// under the cap) the config-package stride SSOT
// config.FilterTermExpansionCount must (a) still equal len(expandFilterTerm)
// AND (b) stay strictly below 2^32 — the property the old
// `return uint32(product)` cast could silently violate by wrapping.
func TestFilterTermExpansionCountLargeValidMatchesAndBoundsUint32(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"src": bigPrefixList5456("src", 100),
		"dst": bigPrefixList5456("dst", 100),
	}
	term := &config.FirewallFilterTerm{
		Name:              "big",
		Action:            config.FilterActionDiscard,
		SourcePrefixLists: []config.PrefixListRef{{Name: "src"}},
		DestPrefixLists:   []config.PrefixListRef{{Name: "dst"}},
		DestinationPorts:  []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"},
	}
	// 100 × 100 × 10 = 100_000 — large, but far under both the cap and 2^32.
	for _, fam := range []uint8{AFInet, AFInet6} {
		want := len(expandFilterTerm(term, fam, nil, prefixLists, nil))
		got := config.FilterTermExpansionCount(term, prefixLists)
		if uint32(want) != got {
			t.Errorf("family=%d: FilterTermExpansionCount()=%d != len(expandFilterTerm)=%d",
				fam, got, want)
		}
		if uint64(got) >= 1<<32 {
			t.Errorf("family=%d: stride %d is not below 2^32 (would wrap the uint32 slot index)", fam, got)
		}
	}
}

// TestFilterTermExpansionCountOverCapBoundedConsistently pins that BOTH the
// stride SSOT and the materializer stop at the same cap: an over-cap term's
// count clamps to config.MaxFilterTermExpansion and expandFilterTerm emits
// EXACTLY that many rules — it never attempts the full (here 4_000_000-entry)
// cross-product. Keeping count == len for an over-bound term preserves the
// #3459 drift-guard invariant on the tolerant load / peer-sync path.
func TestFilterTermExpansionCountOverCapBoundedConsistently(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{
		"src": bigPrefixList5456("src", 2000),
		"dst": bigPrefixList5456("dst", 2000), // 2000 × 2000 = 4_000_000 > cap (1_048_576)
	}
	term := &config.FirewallFilterTerm{
		Name:              "overcap",
		Action:            config.FilterActionDiscard,
		SourcePrefixLists: []config.PrefixListRef{{Name: "src"}},
		DestPrefixLists:   []config.PrefixListRef{{Name: "dst"}},
	}
	count := config.FilterTermExpansionCount(term, prefixLists)
	if count != config.MaxFilterTermExpansion {
		t.Fatalf("over-cap stride = %d, want clamp to MaxFilterTermExpansion (%d)",
			count, config.MaxFilterTermExpansion)
	}
	got := len(expandFilterTerm(term, AFInet, nil, prefixLists, nil))
	if got != config.MaxFilterTermExpansion {
		t.Fatalf("expandFilterTerm materialized %d rules, want the cap %d "+
			"(it must not attempt the full 4_000_000-entry cross-product)",
			got, config.MaxFilterTermExpansion)
	}
}
