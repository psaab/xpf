package dataplane

// BPF map utilization stats.
// Same-package split of maps.go (#1686): MapStats + GetMapStats.

// MapStats holds utilization info for a BPF map.
type MapStats struct {
	Name       string
	Type       string
	MaxEntries uint32
	UsedCount  uint32
	KeySize    uint32
	ValueSize  uint32
}

// mapStatDescriptor names a BPF map GetMapStats reports on and whether its
// entries can be meaningfully counted by iteration.
//
// countable is true ONLY for sparse maps (HASH / LPM_TRIE), where iteration
// yields exactly the live entries. It MUST be false for pre-allocated maps
// (ARRAY / PERCPU_ARRAY): every index key in such a map already exists, so
// iterating returns MaxEntries unconditionally, which makes UsedCount a
// meaningless "100% utilized" value.
type mapStatDescriptor struct {
	name      string
	countable bool
}

// mapStatsReportDescriptors is the static set of BPF maps GetMapStats reports
// on. It is read (never mutated) by GetMapStats and by the unit test that
// asserts the name + countability invariant; it stays unexported.
//
// Name correctness (#1694): nat_pool_configs and screen_configs are the real
// BPF map names — see the C definitions in bpf/headers/xpf_maps.h and the
// setters in maps_nat.go / maps_screen.go (m.maps is keyed by the literal
// collection map name; see loader_userspace_shim.go). The earlier
// nat_pool_config / screen_profiles spellings never matched an m.maps key, so
// those descriptors silently reported nothing.
//
// Countability correctness (#1694): filter_rules is BPF_MAP_TYPE_ARRAY
// (bpf/headers/xpf_maps.h), so it is non-countable; the earlier
// countable:true made UsedCount always equal MaxEntries. struct filter_rule
// has no per-slot "valid" flag — rule validity is carried by
// filter_config.num_rules/rule_start, not by slot contents — so a real
// used-count is not a cheap value-aware iteration and is left out of scope.
//
// Invariant: a descriptor is countable iff its BPF map type is HASH or
// LPM_TRIE (sparse); ARRAY / PERCPU_ARRAY maps are non-countable.
var mapStatsReportDescriptors = []mapStatDescriptor{
	{"sessions", true},
	{"sessions_v6", true},
	{"zone_configs", false},
	{"policy_rules", false},
	{"address_book_v4", true},
	{"address_book_v6", true},
	{"address_membership", true},
	{"applications", true},
	{"snat_rules", false},
	{"nat_pool_configs", false},
	{"screen_configs", false},
	{"global_counters", false},
	{"policy_counters", false},
	{"filter_rules", false},
}

// GetMapStats returns utilization statistics for key BPF maps.
func (m *Manager) GetMapStats() []MapStats {
	var stats []MapStats
	for _, rm := range mapStatsReportDescriptors {
		bm, present, _ := m.lookupMapLocked(rm.name)
		if !present || bm == nil {
			continue
		}
		info, err := bm.Info()
		if err != nil {
			continue
		}
		ms := MapStats{
			Name:       rm.name,
			Type:       info.Type.String(),
			MaxEntries: info.MaxEntries,
			KeySize:    info.KeySize,
			ValueSize:  info.ValueSize,
		}

		if rm.countable {
			// Count entries by iterating the map
			var count uint32
			iter := bm.Iterate()
			var key, val []byte
			for iter.Next(&key, &val) {
				count++
			}
			ms.UsedCount = count
		}

		stats = append(stats, ms)
	}
	return stats
}
