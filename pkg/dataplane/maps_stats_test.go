package dataplane

import "testing"

// expectedMapStatCountable is the authoritative name -> countable mapping for
// every BPF map GetMapStats reports on. It mirrors the BPF map types declared
// in bpf/headers/xpf_maps.h: a descriptor is countable iff its map type is
// sparse (HASH / LPM_TRIE); pre-allocated ARRAY / PERCPU_ARRAY maps are not
// countable because iterating them yields every index up to MaxEntries.
//
// This guards the #1694 fixes (correct names for nat_pool_configs /
// screen_configs, and filter_rules marked non-countable) against regression.
var expectedMapStatCountable = map[string]bool{
	"sessions":           true,  // HASH
	"sessions_v6":        true,  // HASH
	"zone_configs":       false, // ARRAY
	"policy_rules":       false, // ARRAY
	"address_book_v4":    true,  // LPM_TRIE
	"address_book_v6":    true,  // LPM_TRIE
	"address_membership": true,  // HASH
	"applications":       true,  // HASH
	"snat_rules":         false, // ARRAY
	"nat_pool_configs":   false, // ARRAY (was stale "nat_pool_config")
	"screen_configs":     false, // ARRAY (was stale "screen_profiles")
	"global_counters":    false, // PERCPU_ARRAY
	"policy_counters":    false, // PERCPU_ARRAY
	"filter_rules":       false, // ARRAY (was wrongly countable:true)
}

// staleMapStatNames are the incorrect names #1694 removed. They never matched
// an m.maps key, so descriptors using them silently reported nothing.
var staleMapStatNames = []string{"nat_pool_config", "screen_profiles"}

func TestMapStatsReportDescriptorsMatchExpected(t *testing.T) {
	if len(mapStatsReportDescriptors) != len(expectedMapStatCountable) {
		t.Fatalf("descriptor count = %d, want %d",
			len(mapStatsReportDescriptors), len(expectedMapStatCountable))
	}

	seen := make(map[string]bool, len(mapStatsReportDescriptors))
	for _, d := range mapStatsReportDescriptors {
		if seen[d.name] {
			t.Errorf("duplicate descriptor name %q", d.name)
		}
		seen[d.name] = true

		want, ok := expectedMapStatCountable[d.name]
		if !ok {
			t.Errorf("unexpected descriptor name %q in mapStatsReportDescriptors", d.name)
			continue
		}
		if d.countable != want {
			t.Errorf("descriptor %q countable = %v, want %v", d.name, d.countable, want)
		}
	}

	for name := range expectedMapStatCountable {
		if !seen[name] {
			t.Errorf("expected descriptor %q missing from mapStatsReportDescriptors", name)
		}
	}
}

// TestMapStatsReportDescriptorsCorrectNames asserts the #1694 name fixes: the
// corrected names are present and the stale ones are gone.
func TestMapStatsReportDescriptorsCorrectNames(t *testing.T) {
	names := make(map[string]bool, len(mapStatsReportDescriptors))
	for _, d := range mapStatsReportDescriptors {
		names[d.name] = true
	}

	for _, want := range []string{"nat_pool_configs", "screen_configs"} {
		if !names[want] {
			t.Errorf("corrected map name %q not present in mapStatsReportDescriptors", want)
		}
	}
	for _, stale := range staleMapStatNames {
		if names[stale] {
			t.Errorf("stale map name %q still present in mapStatsReportDescriptors", stale)
		}
	}
}

// TestMapStatsFilterRulesNotCountable pins the #1694 ARRAY mis-count fix:
// filter_rules is a BPF_MAP_TYPE_ARRAY and must not be counted by iteration.
func TestMapStatsFilterRulesNotCountable(t *testing.T) {
	for _, d := range mapStatsReportDescriptors {
		if d.name == "filter_rules" {
			if d.countable {
				t.Fatal("filter_rules is a BPF ARRAY and must be countable:false")
			}
			return
		}
	}
	t.Fatal("filter_rules descriptor not found")
}
