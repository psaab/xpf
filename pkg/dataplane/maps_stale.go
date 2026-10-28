package dataplane

import (
	"log/slog"

	"github.com/cilium/ebpf"
)

// Hitless-restart stale-cleanup map accessors.
// Same-package split of maps.go (#1686). One responsibility: after new config
// entries are written, remove map entries no longer present in the new config,
// avoiding the clear-then-repopulate window where BPF programs see empty maps.
// Each routine's sister domain file (where the corresponding setter lives) is
// noted per group below.

// DeleteStaleIfaceZone removes iface_zone_map entries not in the written set.
func (m *Manager) DeleteStaleIfaceZone(written map[IfaceZoneKey]bool) {
	zm, present, _ := m.lookupMapLocked("iface_zone_map")
	if !present {
		return
	}
	var key IfaceZoneKey
	var val IfaceZoneValue
	iter := zm.Iterate()
	var stale []IfaceZoneKey
	for iter.Next(&key, &val) {
		if !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale iface_zone entries", "count", len(stale))
	}
}

// DeleteStaleVlanIface removes vlan_iface_map entries not in the written set.
func (m *Manager) DeleteStaleVlanIface(written map[uint32]bool) {
	zm, present, _ := m.lookupMapLocked("vlan_iface_map")
	if !present {
		return
	}
	var key uint32
	var val VlanIfaceInfo
	iter := zm.Iterate()
	var stale []uint32
	for iter.Next(&key, &val) {
		if !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale vlan_iface entries", "count", len(stale))
	}
}

// DeleteStaleZonePairPolicies zeros zone_pair_policies entries not in the written set.
// The map is an ARRAY so entries cannot be deleted — zero means "no policy".
func (m *Manager) DeleteStaleZonePairPolicies(written map[ZonePairKey]bool) {
	zm, present, _ := m.lookupMapLocked("zone_pair_policies")
	if !present {
		return
	}
	zeroPS := PolicySet{}
	var key uint32
	var val PolicySet
	iter := zm.Iterate()
	count := 0
	for iter.Next(&key, &val) {
		if val.NumRules == 0 {
			continue // already empty
		}
		fromZone := key / MaxZones
		toZone := key % MaxZones
		zpk := ZonePairKey{FromZone: fromZone, ToZone: toZone}
		if !written[zpk] {
			zm.Update(key, zeroPS, ebpf.UpdateAny)
			count++
		}
	}
	if count > 0 {
		slog.Info("zeroed stale zone_pair_policies entries", "count", count)
	}
}

// DeleteStaleApplications removes application entries not in the written set.
func (m *Manager) DeleteStaleApplications(written map[AppKey]bool) {
	zm, present, _ := m.lookupMapLocked("applications")
	if !present {
		return
	}
	var key AppKey
	var val []byte
	iter := zm.Iterate()
	var stale []AppKey
	for iter.Next(&key, &val) {
		if !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale application entries", "count", len(stale))
	}
}

// DeleteStaleStaticNAT removes static_nat entries not in the written sets.
func (m *Manager) DeleteStaleStaticNAT(writtenV4 map[StaticNATKeyV4]bool, writtenV6 map[StaticNATKeyV6]bool) {
	if zm, present, _ := m.lookupMapLocked("static_nat_v4"); present {
		var key StaticNATKeyV4
		var val []byte
		iter := zm.Iterate()
		var stale []StaticNATKeyV4
		for iter.Next(&key, &val) {
			if !writtenV4[key] {
				stale = append(stale, key)
			}
		}
		for _, k := range stale {
			zm.Delete(k)
		}
		if len(stale) > 0 {
			slog.Info("deleted stale static_nat_v4 entries", "count", len(stale))
		}
	}
	if zm, present, _ := m.lookupMapLocked("static_nat_v6"); present {
		var key StaticNATKeyV6
		var val []byte
		iter := zm.Iterate()
		var stale []StaticNATKeyV6
		for iter.Next(&key, &val) {
			if !writtenV6[key] {
				stale = append(stale, key)
			}
		}
		for _, k := range stale {
			zm.Delete(k)
		}
		if len(stale) > 0 {
			slog.Info("deleted stale static_nat_v6 entries", "count", len(stale))
		}
	}
}

// ZeroStaleScreenConfigs zeroes screen_configs entries above maxID.
func (m *Manager) ZeroStaleScreenConfigs(maxID uint32) {
	zm, present, _ := m.lookupMapLocked("screen_configs")
	if !present {
		return
	}
	empty := ScreenConfig{}
	for i := maxID + 1; i < 64; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
}

// DeleteStaleIfaceFilter removes iface_filter_map entries not in the written set.
func (m *Manager) DeleteStaleIfaceFilter(written map[IfaceFilterKey]bool) {
	zm, present, _ := m.lookupMapLocked("iface_filter_map")
	if !present {
		return
	}
	var key IfaceFilterKey
	var val []byte
	iter := zm.Iterate()
	var stale []IfaceFilterKey
	for iter.Next(&key, &val) {
		if !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale iface_filter entries", "count", len(stale))
	}
}

// ZeroStaleFilterConfigs zeroes filter_configs entries from startID onwards.
func (m *Manager) ZeroStaleFilterConfigs(startID uint32) {
	zm, present, _ := m.lookupMapLocked("filter_configs")
	if !present {
		return
	}
	var empty FilterConfig
	for i := startID; i < MaxFilterConfigs; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
}
