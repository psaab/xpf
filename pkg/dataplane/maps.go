package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
)

// SetZoneConfig writes a zone configuration entry.
func (m *Manager) SetZoneConfig(zoneID uint16, cfg ZoneConfig) error {
	zm, ok := m.maps["zone_configs"]
	if !ok {
		return fmt.Errorf("zone_configs map not found")
	}
	return zm.Update(uint32(zoneID), cfg, ebpf.UpdateAny)
}

// SetZonePairPolicy writes a zone-pair policy set entry.
// The zone_pair_policies map is an ARRAY keyed by flat index:
// from_zone * MaxZones + to_zone.
func (m *Manager) SetZonePairPolicy(fromZone, toZone uint16, ps PolicySet) error {
	zm, ok := m.maps["zone_pair_policies"]
	if !ok {
		return fmt.Errorf("zone_pair_policies map not found")
	}
	key := uint32(fromZone)*MaxZones + uint32(toZone)
	return zm.Update(key, ps, ebpf.UpdateAny)
}

// SetPolicyRule writes a policy rule at the computed flat index.
func (m *Manager) SetPolicyRule(policySetID uint32, ruleIndex uint32, rule PolicyRule) error {
	zm, ok := m.maps["policy_rules"]
	if !ok {
		return fmt.Errorf("policy_rules map not found")
	}
	idx := policySetID*MaxRulesPerPolicy + ruleIndex
	return zm.Update(idx, rule, ebpf.UpdateAny)
}

// SetAddressBookEntry writes an LPM trie entry for an address.
// Auto-detects IPv4 vs IPv6 from the CIDR and routes to the correct map.
func (m *Manager) SetAddressBookEntry(cidr string, addressID uint32) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}

	ones, _ := ipNet.Mask.Size()

	if ip4 := ipNet.IP.To4(); ip4 != nil {
		zm, ok := m.maps["address_book_v4"]
		if !ok {
			return fmt.Errorf("address_book_v4 map not found")
		}
		key := LPMKeyV4{
			PrefixLen: uint32(ones),
			Addr:      binary.BigEndian.Uint32(ip4),
		}
		val := AddrValue{AddressID: addressID}
		return zm.Update(key, val, ebpf.UpdateAny)
	}

	// IPv6
	zm, ok := m.maps["address_book_v6"]
	if !ok {
		return fmt.Errorf("address_book_v6 map not found")
	}
	key := LPMKeyV6{
		PrefixLen: uint32(ones),
	}
	copy(key.Addr[:], ipNet.IP.To16())
	val := AddrValue{AddressID: addressID}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// SetAddressMembership writes an address-set membership entry.
// This maps (resolvedID, setID) -> 1, indicating that resolvedID
// is a member of the address-set identified by setID.
func (m *Manager) SetAddressMembership(resolvedID, setID uint32) error {
	zm, ok := m.maps["address_membership"]
	if !ok {
		return fmt.Errorf("address_membership map not found")
	}
	key := AddrMembershipKey{IP: resolvedID, AddressID: setID}
	val := uint8(1)
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearAddressBookV4 removes all entries from the address_book_v4 LPM trie.
func (m *Manager) ClearAddressBookV4() error {
	zm, ok := m.maps["address_book_v4"]
	if !ok {
		return fmt.Errorf("address_book_v4 map not found")
	}
	var key LPMKeyV4
	iter := zm.Iterate()
	var keys []LPMKeyV4
	var val []byte
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// ClearAddressBookV6 removes all entries from the address_book_v6 LPM trie.
func (m *Manager) ClearAddressBookV6() error {
	zm, ok := m.maps["address_book_v6"]
	if !ok {
		return fmt.Errorf("address_book_v6 map not found")
	}
	var key LPMKeyV6
	iter := zm.Iterate()
	var keys []LPMKeyV6
	var val []byte
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// ClearAddressMembership removes all entries from the address_membership map.
func (m *Manager) ClearAddressMembership() error {
	zm, ok := m.maps["address_membership"]
	if !ok {
		return fmt.Errorf("address_membership map not found")
	}
	var key AddrMembershipKey
	iter := zm.Iterate()
	var keys []AddrMembershipKey
	var val []byte
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// SetApplication writes an application map entry.
func (m *Manager) SetApplication(protocol uint8, dstPort uint16, appID uint32, timeout uint32, algType uint8, srcPortLow, srcPortHigh uint16) error {
	zm, ok := m.maps["applications"]
	if !ok {
		return fmt.Errorf("applications map not found")
	}
	key := AppKey{
		Protocol: protocol,
		DstPort:  htons(dstPort),
	}
	val := AppValue{
		AppID:       appID,
		ALGType:     algType,
		Timeout:     timeout,
		SrcPortLow:  srcPortLow,
		SrcPortHigh: srcPortHigh,
	}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// SetAppRange writes a range-based application entry at the given index.
func (m *Manager) SetAppRange(index uint32, entry AppRangeEntry) error {
	zm, ok := m.maps["app_ranges"]
	if !ok {
		return fmt.Errorf("app_ranges map not found")
	}
	return zm.Update(index, entry, ebpf.UpdateAny)
}

// ClearAppRanges zeros all app_ranges entries.
func (m *Manager) ClearAppRanges() error {
	zm, ok := m.maps["app_ranges"]
	if !ok {
		return fmt.Errorf("app_ranges map not found")
	}
	zero := AppRangeEntry{}
	for i := uint32(0); i < MaxAppRanges; i++ {
		zm.Update(i, zero, ebpf.UpdateAny)
	}
	return nil
}

// IterateSessions iterates all session entries, calling fn for each.
// fn receives the key and value; return false to stop iteration.
//
// When the userspace dataplane is active, this map contains mirrored
// sessions written by the Rust helper's publish_bpf_conntrack_entry.
// The helper periodically refreshes LastSeen (~10s) so callers see
// reasonably accurate idle times.  Session lifetime is owned by the
// helper, not Go GC (GC.SkipSweep is set).  See #333.
func (m *Manager) IterateSessions(fn func(SessionKey, SessionValue) bool) error {
	sm, ok := m.maps["sessions"]
	if !ok {
		return fmt.Errorf("sessions map not found")
	}

	var key SessionKey
	var val SessionValue
	iter := sm.Iterate()
	for iter.Next(&key, &val) {
		if !fn(key, val) {
			break
		}
	}
	return iter.Err()
}

// DeleteSession deletes a session entry by key.
func (m *Manager) DeleteSession(key SessionKey) error {
	sm, ok := m.maps["sessions"]
	if !ok {
		return fmt.Errorf("sessions map not found")
	}
	return sm.Delete(key)
}

// SetSessionV4 writes a v4 session entry (used by cluster sync to install sessions from peer).
func (m *Manager) SetSessionV4(key SessionKey, val SessionValue) error {
	sm, ok := m.maps["sessions"]
	if !ok {
		return fmt.Errorf("sessions map not found")
	}
	return sm.Update(key, val, ebpf.UpdateAny)
}

// GetSessionV4 looks up a single v4 session entry by key.
func (m *Manager) GetSessionV4(key SessionKey) (SessionValue, error) {
	sm, ok := m.maps["sessions"]
	if !ok {
		return SessionValue{}, fmt.Errorf("sessions map not found")
	}
	var val SessionValue
	if err := sm.Lookup(key, &val); err != nil {
		return SessionValue{}, err
	}
	return val, nil
}

// GetSessionV6 looks up a single v6 session entry by key.
func (m *Manager) GetSessionV6(key SessionKeyV6) (SessionValueV6, error) {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return SessionValueV6{}, fmt.Errorf("sessions_v6 map not found")
	}
	var val SessionValueV6
	if err := sm.Lookup(key, &val); err != nil {
		return SessionValueV6{}, err
	}
	return val, nil
}

// ClearZonePairPolicies zeros all zone-pair policy entries.
// The map is an ARRAY so entries cannot be deleted — zero means "no policy".
func (m *Manager) ClearZonePairPolicies() error {
	zm, ok := m.maps["zone_pair_policies"]
	if !ok {
		return fmt.Errorf("zone_pair_policies map not found")
	}
	zeroPS := PolicySet{}
	var key uint32
	var val PolicySet
	iter := zm.Iterate()
	for iter.Next(&key, &val) {
		if val.NumRules > 0 {
			zm.Update(key, zeroPS, ebpf.UpdateAny)
		}
	}
	return nil
}

// ClearApplications deletes all application map entries.
func (m *Manager) ClearApplications() error {
	zm, ok := m.maps["applications"]
	if !ok {
		return fmt.Errorf("applications map not found")
	}
	var key AppKey
	iter := zm.Iterate()
	var keys []AppKey
	var val []byte
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// SetDNATEntry writes a dnat_table entry.
func (m *Manager) SetDNATEntry(key DNATKey, val DNATValue) error {
	zm, ok := m.maps["dnat_table"]
	if !ok {
		return fmt.Errorf("dnat_table map not found")
	}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// DeleteDNATEntry deletes a dnat_table entry.
func (m *Manager) DeleteDNATEntry(key DNATKey) error {
	zm, ok := m.maps["dnat_table"]
	if !ok {
		return fmt.Errorf("dnat_table map not found")
	}
	return zm.Delete(key)
}

// ClearDNATStatic deletes all static (flags=1) dnat_table entries.
func (m *Manager) ClearDNATStatic() error {
	zm, ok := m.maps["dnat_table"]
	if !ok {
		return fmt.Errorf("dnat_table map not found")
	}
	var key DNATKey
	var val DNATValue
	iter := zm.Iterate()
	var toDelete []DNATKey
	for iter.Next(&key, &val) {
		if val.Flags == DNATFlagStatic {
			toDelete = append(toDelete, key)
		}
	}
	for _, k := range toDelete {
		zm.Delete(k)
	}
	return nil
}

// SetSNATRule writes a snat_rules entry at the computed flat index.
// The snat_rules map is an ARRAY keyed by flat index:
// from_zone * MaxZones * MaxSNATRulesPerPair + to_zone * MaxSNATRulesPerPair + rule_idx.
func (m *Manager) SetSNATRule(fromZone, toZone, ruleIdx uint16, val SNATValue) error {
	zm, ok := m.maps["snat_rules"]
	if !ok {
		return fmt.Errorf("snat_rules map not found")
	}
	key := uint32(fromZone)*MaxZones*MaxSNATRulesPerPair + uint32(toZone)*MaxSNATRulesPerPair + uint32(ruleIdx)
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearSNATRules zeroes all snat_rules entries (ARRAY map semantics).
func (m *Manager) ClearSNATRules() error {
	zm, ok := m.maps["snat_rules"]
	if !ok {
		return fmt.Errorf("snat_rules map not found")
	}
	empty := SNATValue{}
	for i := uint32(0); i < MaxZones*MaxZones*MaxSNATRulesPerPair; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// IterateSessionsV6 iterates all IPv6 session entries, calling fn for each.
func (m *Manager) IterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return fmt.Errorf("sessions_v6 map not found")
	}

	var key SessionKeyV6
	var val SessionValueV6
	iter := sm.Iterate()
	for iter.Next(&key, &val) {
		if !fn(key, val) {
			break
		}
	}
	return iter.Err()
}

// IterateSessionsFrom iterates v4 session entries starting after cursorKey.
// If cursorKey is nil, iteration starts from the beginning.
// fn returns false to stop iteration.
func (m *Manager) IterateSessionsFrom(cursorKey *SessionKey, fn func(SessionKey, SessionValue) bool) error {
	sm, ok := m.maps["sessions"]
	if !ok {
		return fmt.Errorf("sessions map not found")
	}

	var nextKey SessionKey
	var startKey interface{} = cursorKey
	if cursorKey == nil {
		startKey = nil
	}

	// Get the first key to iterate from.
	if err := sm.NextKey(startKey, &nextKey); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil // no entries or cursor at end
		}
		return fmt.Errorf("sessions NextKey: %w", err)
	}

	for {
		var val SessionValue
		if err := sm.Lookup(nextKey, &val); err != nil {
			// Entry may have been deleted between NextKey and Lookup; skip.
			var next SessionKey
			if err := sm.NextKey(nextKey, &next); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					return nil
				}
				return fmt.Errorf("sessions NextKey: %w", err)
			}
			nextKey = next
			continue
		}
		if !fn(nextKey, val) {
			return nil
		}
		var next SessionKey
		if err := sm.NextKey(nextKey, &next); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil // end of map
			}
			return fmt.Errorf("sessions NextKey: %w", err)
		}
		nextKey = next
	}
}

// IterateSessionsV6From iterates v6 session entries starting after cursorKey.
// If cursorKey is nil, iteration starts from the beginning.
// fn returns false to stop iteration.
func (m *Manager) IterateSessionsV6From(cursorKey *SessionKeyV6, fn func(SessionKeyV6, SessionValueV6) bool) error {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return fmt.Errorf("sessions_v6 map not found")
	}

	var nextKey SessionKeyV6
	var startKey interface{} = cursorKey
	if cursorKey == nil {
		startKey = nil
	}

	if err := sm.NextKey(startKey, &nextKey); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("sessions_v6 NextKey: %w", err)
	}

	for {
		var val SessionValueV6
		if err := sm.Lookup(nextKey, &val); err != nil {
			var next SessionKeyV6
			if err := sm.NextKey(nextKey, &next); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					return nil
				}
				return fmt.Errorf("sessions_v6 NextKey: %w", err)
			}
			nextKey = next
			continue
		}
		if !fn(nextKey, val) {
			return nil
		}
		var next SessionKeyV6
		if err := sm.NextKey(nextKey, &next); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil
			}
			return fmt.Errorf("sessions_v6 NextKey: %w", err)
		}
		nextKey = next
	}
}

// BatchIterateSessions iterates sessions using batch lookup for reduced
// kernel lock contention.  Yields between batches so BPF datapath isn't
// starved of hash-table bucket locks.
func (m *Manager) BatchIterateSessions(fn func(SessionKey, SessionValue) bool) error {
	sm, ok := m.maps["sessions"]
	if !ok {
		return fmt.Errorf("sessions map not found")
	}

	const batchSize = 256
	keys := make([]SessionKey, batchSize)
	vals := make([]SessionValue, batchSize)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := sm.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			if !fn(keys[i], vals[i]) {
				return nil
			}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil // done
		}
		if err != nil {
			return fmt.Errorf("batch lookup sessions: %w", err)
		}
		runtime.Gosched() // yield to reduce lock contention with BPF datapath
	}
}

// BatchIterateSessionsV6 is the IPv6 variant of BatchIterateSessions.
func (m *Manager) BatchIterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return fmt.Errorf("sessions_v6 map not found")
	}

	const batchSize = 256
	keys := make([]SessionKeyV6, batchSize)
	vals := make([]SessionValueV6, batchSize)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := sm.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			if !fn(keys[i], vals[i]) {
				return nil
			}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("batch lookup sessions_v6: %w", err)
		}
		runtime.Gosched()
	}
}

// BatchDeleteSessions deletes multiple session entries in a single syscall.
func (m *Manager) BatchDeleteSessions(keys []SessionKey) (int, error) {
	sm, ok := m.maps["sessions"]
	if !ok {
		return 0, fmt.Errorf("sessions map not found")
	}
	if len(keys) == 0 {
		return 0, nil
	}
	return sm.BatchDelete(keys, nil)
}

// BatchDeleteSessionsV6 deletes multiple IPv6 session entries in a single syscall.
func (m *Manager) BatchDeleteSessionsV6(keys []SessionKeyV6) (int, error) {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return 0, fmt.Errorf("sessions_v6 map not found")
	}
	if len(keys) == 0 {
		return 0, nil
	}
	return sm.BatchDelete(keys, nil)
}

// DeleteSessionV6 deletes an IPv6 session entry by key.
func (m *Manager) DeleteSessionV6(key SessionKeyV6) error {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return fmt.Errorf("sessions_v6 map not found")
	}
	return sm.Delete(key)
}

// SetSessionV6 writes a v6 session entry (used by cluster sync to install sessions from peer).
func (m *Manager) SetSessionV6(key SessionKeyV6, val SessionValueV6) error {
	sm, ok := m.maps["sessions_v6"]
	if !ok {
		return fmt.Errorf("sessions_v6 map not found")
	}
	return sm.Update(key, val, ebpf.UpdateAny)
}

// SessionCount returns the number of active IPv4 and IPv6 sessions.
// Only forward entries are counted (IsReverse == 0).
func (m *Manager) SessionCount() (v4, v6 int) {
	if sm, ok := m.maps["sessions"]; ok {
		var key SessionKey
		var val SessionValue
		iter := sm.Iterate()
		for iter.Next(&key, &val) {
			if val.IsReverse == 0 {
				v4++
			}
		}
	}
	if sm, ok := m.maps["sessions_v6"]; ok {
		var key SessionKeyV6
		var val SessionValueV6
		iter := sm.Iterate()
		for iter.Next(&key, &val) {
			if val.IsReverse == 0 {
				v6++
			}
		}
	}
	return
}

// SetDNATEntryV6 writes a dnat_table_v6 entry.
func (m *Manager) SetDNATEntryV6(key DNATKeyV6, val DNATValueV6) error {
	zm, ok := m.maps["dnat_table_v6"]
	if !ok {
		return fmt.Errorf("dnat_table_v6 map not found")
	}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// DeleteDNATEntryV6 deletes a dnat_table_v6 entry.
func (m *Manager) DeleteDNATEntryV6(key DNATKeyV6) error {
	zm, ok := m.maps["dnat_table_v6"]
	if !ok {
		return fmt.Errorf("dnat_table_v6 map not found")
	}
	return zm.Delete(key)
}

// ClearDNATStaticV6 deletes all static (flags=1) dnat_table_v6 entries.
func (m *Manager) ClearDNATStaticV6() error {
	zm, ok := m.maps["dnat_table_v6"]
	if !ok {
		return fmt.Errorf("dnat_table_v6 map not found")
	}
	var key DNATKeyV6
	var val DNATValueV6
	iter := zm.Iterate()
	var toDelete []DNATKeyV6
	for iter.Next(&key, &val) {
		if val.Flags == DNATFlagStatic {
			toDelete = append(toDelete, key)
		}
	}
	for _, k := range toDelete {
		zm.Delete(k)
	}
	return nil
}

// SetSNATRuleV6 writes a snat_rules_v6 entry at the computed flat index.
// The snat_rules_v6 map is an ARRAY keyed by flat index:
// from_zone * MaxZones * MaxSNATRulesPerPair + to_zone * MaxSNATRulesPerPair + rule_idx.
func (m *Manager) SetSNATRuleV6(fromZone, toZone, ruleIdx uint16, val SNATValueV6) error {
	zm, ok := m.maps["snat_rules_v6"]
	if !ok {
		return fmt.Errorf("snat_rules_v6 map not found")
	}
	key := uint32(fromZone)*MaxZones*MaxSNATRulesPerPair + uint32(toZone)*MaxSNATRulesPerPair + uint32(ruleIdx)
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearSNATRulesV6 zeroes all snat_rules_v6 entries (ARRAY map semantics).
func (m *Manager) ClearSNATRulesV6() error {
	zm, ok := m.maps["snat_rules_v6"]
	if !ok {
		return fmt.Errorf("snat_rules_v6 map not found")
	}
	empty := SNATValueV6{}
	for i := uint32(0); i < MaxZones*MaxZones*MaxSNATRulesPerPair; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// SetNATPoolConfig writes a NAT pool configuration entry.
func (m *Manager) SetNATPoolConfig(poolID uint32, cfg NATPoolConfig) error {
	zm, ok := m.maps["nat_pool_configs"]
	if !ok {
		return fmt.Errorf("nat_pool_configs map not found")
	}
	return zm.Update(poolID, cfg, ebpf.UpdateAny)
}

// SetNATPoolIPV4 writes an IPv4 address to a NAT pool IP slot.
func (m *Manager) SetNATPoolIPV4(poolID, index uint32, ip uint32) error {
	zm, ok := m.maps["nat_pool_ips_v4"]
	if !ok {
		return fmt.Errorf("nat_pool_ips_v4 map not found")
	}
	mapIdx := poolID*MaxNATPoolIPsPerPool + index
	return zm.Update(mapIdx, ip, ebpf.UpdateAny)
}

// SetNATPoolIPV6 writes an IPv6 address to a NAT pool IP slot.
func (m *Manager) SetNATPoolIPV6(poolID, index uint32, ip [16]byte) error {
	zm, ok := m.maps["nat_pool_ips_v6"]
	if !ok {
		return fmt.Errorf("nat_pool_ips_v6 map not found")
	}
	mapIdx := poolID*MaxNATPoolIPsPerPool + index
	val := NATPoolIPV6{IP: ip}
	return zm.Update(mapIdx, val, ebpf.UpdateAny)
}

// ClearNATPoolConfigs zeroes all nat_pool_configs entries.
func (m *Manager) ClearNATPoolConfigs() error {
	zm, ok := m.maps["nat_pool_configs"]
	if !ok {
		return fmt.Errorf("nat_pool_configs map not found")
	}
	empty := NATPoolConfig{}
	for i := uint32(0); i < 32; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// ClearNATPoolIPs zeroes all nat_pool_ips_v4 and nat_pool_ips_v6 entries.
func (m *Manager) ClearNATPoolIPs() error {
	v4Map, ok := m.maps["nat_pool_ips_v4"]
	if !ok {
		return fmt.Errorf("nat_pool_ips_v4 map not found")
	}
	v6Map, ok := m.maps["nat_pool_ips_v6"]
	if !ok {
		return fmt.Errorf("nat_pool_ips_v6 map not found")
	}
	maxEntries := uint32(32 * MaxNATPoolIPsPerPool)
	var zeroV4 uint32
	zeroV6 := NATPoolIPV6{}
	for i := uint32(0); i < maxEntries; i++ {
		v4Map.Update(i, zeroV4, ebpf.UpdateAny)
		v6Map.Update(i, zeroV6, ebpf.UpdateAny)
	}
	return nil
}

// SetSNATEgressIP writes a per-interface SNAT address for interface-mode SNAT.
func (m *Manager) SetSNATEgressIP(key SNATEgressKey, val SNATEgressValue) error {
	zm, ok := m.maps["snat_egress_ips"]
	if !ok {
		return fmt.Errorf("snat_egress_ips map not found")
	}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearSNATEgressIPs deletes all snat_egress_ips entries.
func (m *Manager) ClearSNATEgressIPs() error {
	zm, ok := m.maps["snat_egress_ips"]
	if !ok {
		return fmt.Errorf("snat_egress_ips map not found")
	}
	var key SNATEgressKey
	iter := zm.Iterate()
	var keys []SNATEgressKey
	var val []byte
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// SetScreenConfig writes a screen profile configuration entry.
func (m *Manager) SetScreenConfig(profileID uint32, cfg ScreenConfig) error {
	zm, ok := m.maps["screen_configs"]
	if !ok {
		return fmt.Errorf("screen_configs map not found")
	}
	return zm.Update(profileID, cfg, ebpf.UpdateAny)
}

// ClearScreenConfigs zeroes all screen_configs entries.
func (m *Manager) ClearScreenConfigs() error {
	zm, ok := m.maps["screen_configs"]
	if !ok {
		return fmt.Errorf("screen_configs map not found")
	}
	empty := ScreenConfig{}
	for i := uint32(0); i < 64; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// UpdateSessionCountSrc writes a per-source-IP session count entry.
func (m *Manager) UpdateSessionCountSrc(key SessionCountKey, count uint32) error {
	zm, ok := m.maps["session_count_src"]
	if !ok {
		return fmt.Errorf("session_count_src map not found")
	}
	val := SessionCountValue{Count: count}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// UpdateSessionCountDst writes a per-destination-IP session count entry.
func (m *Manager) UpdateSessionCountDst(key SessionCountKey, count uint32) error {
	zm, ok := m.maps["session_count_dst"]
	if !ok {
		return fmt.Errorf("session_count_dst map not found")
	}
	val := SessionCountValue{Count: count}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearSessionCounts deletes all entries from the session count maps.
func (m *Manager) ClearSessionCounts() error {
	for _, name := range []string{"session_count_src", "session_count_dst"} {
		zm, ok := m.maps[name]
		if !ok {
			continue
		}
		var key SessionCountKey
		var val []byte
		iter := zm.Iterate()
		var keys []SessionCountKey
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			zm.Delete(k)
		}
	}
	return nil
}

// SetMirrorConfig writes a port-mirroring entry for the given ingress ifindex.
func (m *Manager) SetMirrorConfig(ifindex int, mirrorIfindex int, rate uint32) error {
	zm, ok := m.maps["mirror_config"]
	if !ok {
		return fmt.Errorf("mirror_config map not found")
	}
	val := MirrorConfig{
		MirrorIfindex: uint32(mirrorIfindex),
		Rate:          rate,
	}
	return zm.Update(uint32(ifindex), val, ebpf.UpdateAny)
}

// ClearMirrorConfigs removes all mirror_config entries.
// mirror_config is a HASH (#756): iterate-and-delete existing keys.
func (m *Manager) ClearMirrorConfigs() error {
	zm, ok := m.maps["mirror_config"]
	if !ok {
		return fmt.Errorf("mirror_config map not found")
	}
	var key uint32
	var val MirrorConfig
	iter := zm.Iterate()
	var keys []uint32
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate mirror_config: %w", err)
	}
	for _, k := range keys {
		if err := zm.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete mirror_config %d: %w", k, err)
		}
	}
	return nil
}

// ReadGlobalCounter reads a per-CPU global counter and returns the sum across all CPUs.
func (m *Manager) ReadGlobalCounter(index uint32) (uint64, error) {
	zm, ok := m.maps["global_counters"]
	if !ok {
		return 0, fmt.Errorf("global_counters map not found")
	}
	var perCPU []uint64
	if err := zm.Lookup(index, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	// Add userspace counter offsets (stored separately to avoid per-CPU race).
	m.mu.Lock()
	total += m.userspaceCounterOffsets[index]
	m.mu.Unlock()
	return total, nil
}

// IncrementGlobalCounter adds delta to a per-CPU global counter (on CPU 0).
// This is used by the userspace dataplane to account for packets forwarded
// outside the BPF pipeline.
func (m *Manager) IncrementGlobalCounter(index uint32, delta uint64) error {
	if delta == 0 {
		return nil
	}
	// Store delta in the userspace counter offset map instead of writing
	// directly to the per-CPU BPF array. ReadGlobalCounter merges both.
	// This avoids the read-modify-write race with concurrent eBPF increments.
	m.mu.Lock()
	if m.userspaceCounterOffsets == nil {
		m.userspaceCounterOffsets = make(map[uint32]uint64)
	}
	m.userspaceCounterOffsets[index] += delta
	m.mu.Unlock()
	return nil
}

// ReadFloodCounters reads the per-CPU flood state for a zone and sums them.
func (m *Manager) ReadFloodCounters(zoneID uint16) (FloodState, error) {
	zm, ok := m.maps["flood_counters"]
	if !ok {
		return FloodState{}, fmt.Errorf("flood_counters map not found")
	}
	var perCPU []FloodState
	if err := zm.Lookup(uint32(zoneID), &perCPU); err != nil {
		return FloodState{}, err
	}
	var total FloodState
	for _, fs := range perCPU {
		total.SynCount += fs.SynCount
		total.ICMPCount += fs.ICMPCount
		total.UDPCount += fs.UDPCount
	}
	return total, nil
}

// ReadInterfaceCounters reads the per-CPU interface counter values and sums them.
// interface_counters is a PERCPU_HASH (#756): a missing key simply means
// no traffic has traversed the interface yet, which reads as zero.
func (m *Manager) ReadInterfaceCounters(ifindex int) (InterfaceCounterValue, error) {
	zm, ok := m.maps["interface_counters"]
	if !ok {
		return InterfaceCounterValue{}, fmt.Errorf("interface_counters map not found")
	}
	var perCPU []InterfaceCounterValue
	if err := zm.Lookup(uint32(ifindex), &perCPU); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return InterfaceCounterValue{}, nil
		}
		return InterfaceCounterValue{}, err
	}
	var total InterfaceCounterValue
	for _, v := range perCPU {
		total.RxPackets += v.RxPackets
		total.RxBytes += v.RxBytes
		total.TxPackets += v.TxPackets
		total.TxBytes += v.TxBytes
	}
	return total, nil
}

// ReadZoneCounters reads the per-CPU zone counter values and sums them.
// direction: 0 = ingress, 1 = egress.
func (m *Manager) ReadZoneCounters(zoneID uint16, direction int) (CounterValue, error) {
	zm, ok := m.maps["zone_counters"]
	if !ok {
		return CounterValue{}, fmt.Errorf("zone_counters map not found")
	}
	idx := uint32(zoneID)*2 + uint32(direction)
	var perCPU []CounterValue
	if err := zm.Lookup(idx, &perCPU); err != nil {
		return CounterValue{}, err
	}
	var total CounterValue
	for _, v := range perCPU {
		total.Packets += v.Packets
		total.Bytes += v.Bytes
	}
	return total, nil
}

// ReadPolicyCounters reads the per-CPU policy counter values and sums them.
func (m *Manager) ReadPolicyCounters(policyID uint32) (CounterValue, error) {
	zm, ok := m.maps["policy_counters"]
	if !ok {
		return CounterValue{}, fmt.Errorf("policy_counters map not found")
	}
	var perCPU []CounterValue
	if err := zm.Lookup(policyID, &perCPU); err != nil {
		return CounterValue{}, err
	}
	var total CounterValue
	for _, v := range perCPU {
		total.Packets += v.Packets
		total.Bytes += v.Bytes
	}
	return total, nil
}

// ReadFilterCounters reads the per-CPU firewall filter counter values and sums them.
func (m *Manager) ReadFilterCounters(ruleIdx uint32) (CounterValue, error) {
	zm, ok := m.maps["filter_counters"]
	if !ok {
		return CounterValue{}, fmt.Errorf("filter_counters map not found")
	}
	var perCPU []CounterValue
	if err := zm.Lookup(ruleIdx, &perCPU); err != nil {
		return CounterValue{}, err
	}
	var total CounterValue
	for _, v := range perCPU {
		total.Packets += v.Packets
		total.Bytes += v.Bytes
	}
	return total, nil
}

// SetDefaultPolicy writes the global default policy action (0=deny, 1=permit).
func (m *Manager) SetDefaultPolicy(action uint8) error {
	zm, ok := m.maps["default_policy"]
	if !ok {
		return fmt.Errorf("default_policy map not found")
	}
	return zm.Update(uint32(0), action, ebpf.UpdateAny)
}

// SetFlowTimeout writes a flow timeout value (in seconds) at the given index.
func (m *Manager) SetFlowTimeout(idx, seconds uint32) error {
	zm, ok := m.maps["flow_timeouts"]
	if !ok {
		return fmt.Errorf("flow_timeouts map not found")
	}
	return zm.Update(idx, seconds, ebpf.UpdateAny)
}

// FlowConfigValue mirrors struct flow_config in xpf_common.h.
type FlowConfigValue struct {
	TCPMSSIPsec       uint16
	TCPMSSGreIn       uint16
	TCPMSSGreOut      uint16
	AllowDNSReply     uint8
	AllowEmbeddedICMP uint8
	GREAccel          uint8
	ALGFlags          uint8  // bit 0: DNS disable, bit 1: FTP disable, bit 2: SIP disable, bit 3: TFTP disable
	Lo0FilterV4       uint16 // filter ID for lo0 inet input (0xFFFF=none)
	Lo0FilterV6       uint16 // filter ID for lo0 inet6 input (0xFFFF=none)
	TCPFlags          uint8  // bit 0: no-syn-check, bit 1: rst-invalidate-session
	AppFlags          uint8  // bit 0: AppID enabled, bit 1: pre-ID session-init log, bit 2: pre-ID session-close log
}

// Lo0FilterNone is the sentinel value meaning no lo0 filter configured.
const Lo0FilterNone = uint16(0xFFFF)

// SetFlowConfig writes the global flow configuration (TCP MSS clamp, etc.).
func (m *Manager) SetFlowConfig(cfg FlowConfigValue) error {
	zm, ok := m.maps["flow_config_map"]
	if !ok {
		return fmt.Errorf("flow_config_map map not found")
	}
	return zm.Update(uint32(0), cfg, ebpf.UpdateAny)
}

// UpdateFabricFwd writes the fabric cross-chassis forwarding config.
// Pass a zero FabricFwdInfo (Ifindex=0) to disable fabric redirect.
func (m *Manager) UpdateFabricFwd(info FabricFwdInfo) error {
	zm, ok := m.maps["fabric_fwd"]
	if !ok {
		return fmt.Errorf("fabric_fwd map not found")
	}
	return zm.Update(uint32(0), info, ebpf.UpdateAny)
}

// UpdateFabricFwd1 writes the secondary fabric cross-chassis forwarding config (key=1).
// Pass a zero FabricFwdInfo (Ifindex=0) to disable fabric1 redirect.
func (m *Manager) UpdateFabricFwd1(info FabricFwdInfo) error {
	zm, ok := m.maps["fabric_fwd"]
	if !ok {
		return fmt.Errorf("fabric_fwd map not found")
	}
	return zm.Update(uint32(1), info, ebpf.UpdateAny)
}

// UpdateRGActive sets the active state of a redundancy group in BPF.
// active=true means this node is primary for the RG; false means secondary.
func (m *Manager) UpdateRGActive(rgID int, active bool) error {
	zm, ok := m.maps["rg_active"]
	if !ok {
		return fmt.Errorf("rg_active map not found")
	}
	var val uint8
	if active {
		val = 1
	}
	return zm.Update(uint32(rgID), val, ebpf.UpdateAny)
}

// UpdateHAWatchdog writes the current monotonic timestamp (seconds) for a
// redundancy group. BPF checks this to detect userspace liveness — if the
// timestamp is stale (>2s), the RG is treated as inactive (fail-closed).
func (m *Manager) UpdateHAWatchdog(rgID int, timestamp uint64) error {
	zm, ok := m.maps["ha_watchdog"]
	if !ok {
		return fmt.Errorf("ha_watchdog map not found")
	}
	return zm.Update(uint32(rgID), timestamp, ebpf.UpdateAny)
}

// SetStaticNATEntryV4 writes a static NAT v4 entry.
func (m *Manager) SetStaticNATEntryV4(ip uint32, direction uint8, translated uint32) error {
	zm, ok := m.maps["static_nat_v4"]
	if !ok {
		return fmt.Errorf("static_nat_v4 map not found")
	}
	key := StaticNATKeyV4{IP: ip, Direction: direction}
	return zm.Update(key, translated, ebpf.UpdateAny)
}

// SetStaticNATEntryV6 writes a static NAT v6 entry.
func (m *Manager) SetStaticNATEntryV6(ip [16]byte, direction uint8, translated [16]byte) error {
	zm, ok := m.maps["static_nat_v6"]
	if !ok {
		return fmt.Errorf("static_nat_v6 map not found")
	}
	key := StaticNATKeyV6{IP: ip, Direction: direction}
	val := StaticNATValueV6{IP: translated}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearStaticNATEntries deletes all static_nat_v4 and static_nat_v6 entries.
func (m *Manager) ClearStaticNATEntries() error {
	// Clear v4
	if zm, ok := m.maps["static_nat_v4"]; ok {
		var key StaticNATKeyV4
		iter := zm.Iterate()
		var keys []StaticNATKeyV4
		var val []byte
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			zm.Delete(k)
		}
	}
	// Clear v6
	if zm, ok := m.maps["static_nat_v6"]; ok {
		var key StaticNATKeyV6
		iter := zm.Iterate()
		var keys []StaticNATKeyV6
		var val []byte
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			zm.Delete(k)
		}
	}
	return nil
}

// ClearAllSessions deletes all IPv4 and IPv6 sessions, plus associated
// dynamic DNAT table entries for SNAT sessions. Returns (v4_deleted, v6_deleted, err).
func (m *Manager) ClearAllSessions() (int, int, error) {
	v4Deleted := 0
	v6Deleted := 0

	// IPv4: collect all keys and SNAT entries for DNAT cleanup
	var v4Keys []SessionKey
	var snatDNATKeys []DNATKey
	if err := m.IterateSessions(func(key SessionKey, val SessionValue) bool {
		v4Keys = append(v4Keys, key)
		// Track dynamic SNAT sessions for dnat_table cleanup
		if val.IsReverse == 0 &&
			val.Flags&SessFlagSNAT != 0 &&
			val.Flags&SessFlagStaticNAT == 0 {
			snatDNATKeys = append(snatDNATKeys, DNATKey{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
				FromZone: 0,
			})
		}
		return true
	}); err != nil {
		return 0, 0, fmt.Errorf("iterate sessions: %w", err)
	}
	for _, key := range v4Keys {
		if err := m.DeleteSession(key); err == nil {
			v4Deleted++
		}
	}
	for _, dk := range snatDNATKeys {
		m.DeleteDNATEntry(dk)
	}

	// IPv6: collect all keys and SNAT entries for DNAT cleanup
	var v6Keys []SessionKeyV6
	var snatDNATKeysV6 []DNATKeyV6
	if err := m.IterateSessionsV6(func(key SessionKeyV6, val SessionValueV6) bool {
		v6Keys = append(v6Keys, key)
		if val.IsReverse == 0 &&
			val.Flags&SessFlagSNAT != 0 &&
			val.Flags&SessFlagStaticNAT == 0 {
			snatDNATKeysV6 = append(snatDNATKeysV6, DNATKeyV6{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
				FromZone: 0,
			})
		}
		return true
	}); err != nil {
		return v4Deleted, 0, fmt.Errorf("iterate sessions_v6: %w", err)
	}
	for _, key := range v6Keys {
		if err := m.DeleteSessionV6(key); err == nil {
			v6Deleted++
		}
	}
	for _, dk := range snatDNATKeysV6 {
		m.DeleteDNATEntryV6(dk)
	}

	return v4Deleted, v6Deleted, nil
}

// ClearGlobalCounters zeroes all global counter entries.
func (m *Manager) ClearGlobalCounters() error {
	zm, ok := m.maps["global_counters"]
	if !ok {
		return fmt.Errorf("global_counters map not found")
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]uint64, numCPUs)
	for i := uint32(0); i < GlobalCtrMax; i++ {
		if err := zm.Update(i, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear global counter %d: %w", i, err)
		}
	}
	return nil
}

// ClearInterfaceCounters zeroes all interface counter entries.
// interface_counters is a PERCPU_HASH (#756): iterate-and-zero existing
// keys; missing keys stay absent and read as zero.
func (m *Manager) ClearInterfaceCounters() error {
	zm, ok := m.maps["interface_counters"]
	if !ok {
		return fmt.Errorf("interface_counters map not found")
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]InterfaceCounterValue, numCPUs)
	var key uint32
	var val []InterfaceCounterValue
	iter := zm.Iterate()
	var keys []uint32
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate interface_counters: %w", err)
	}
	for _, k := range keys {
		if err := zm.Update(k, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear interface_counters %d: %w", k, err)
		}
	}
	return nil
}

// ClearZoneCounters zeroes all zone counter entries.
func (m *Manager) ClearZoneCounters() error {
	zm, ok := m.maps["zone_counters"]
	if !ok {
		return fmt.Errorf("zone_counters map not found")
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]CounterValue, numCPUs)
	for i := uint32(0); i < 128; i++ {
		zm.Update(i, zero, ebpf.UpdateAny)
	}
	return nil
}

// ClearPolicyCounters zeroes all policy counter entries.
func (m *Manager) ClearPolicyCounters() error {
	zm, ok := m.maps["policy_counters"]
	if !ok {
		return fmt.Errorf("policy_counters map not found")
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]CounterValue, numCPUs)
	for i := uint32(0); i < 4096; i++ {
		zm.Update(i, zero, ebpf.UpdateAny)
	}
	return nil
}

// ClearFilterCounters zeroes all filter counter entries.
func (m *Manager) ClearFilterCounters() error {
	zm, ok := m.maps["filter_counters"]
	if !ok {
		return fmt.Errorf("filter_counters map not found")
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]CounterValue, numCPUs)
	for i := uint32(0); i < MaxFilterRules; i++ {
		zm.Update(i, zero, ebpf.UpdateAny)
	}
	return nil
}

// ClearAllCounters zeroes all counter maps (global, interface, zone, policy, filter).
func (m *Manager) ClearAllCounters() error {
	if err := m.ClearGlobalCounters(); err != nil {
		return err
	}
	if err := m.ClearInterfaceCounters(); err != nil {
		return err
	}
	if err := m.ClearZoneCounters(); err != nil {
		return err
	}
	if err := m.ClearPolicyCounters(); err != nil {
		return err
	}
	return m.ClearFilterCounters()
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// ipToUint32BE converts a net.IP to a uint32 matching the in-memory layout
// that BPF programs use when copying __be32 fields (e.g. iph->daddr).
// The IP address bytes are stored as-is; on little-endian hosts this means
// the uint32 numeric value differs from the big-endian interpretation, but
// the byte pattern in the BPF map key matches what BPF writes.
func ipToUint32BE(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.NativeEndian.Uint32(ip4)
}

// SetNAT64Config writes a NAT64 prefix config at the given index and hash map.
func (m *Manager) SetNAT64Config(index uint32, cfg NAT64Config) error {
	zm, ok := m.maps["nat64_configs"]
	if !ok {
		return fmt.Errorf("nat64_configs not found")
	}
	if err := zm.Update(index, cfg, ebpf.UpdateAny); err != nil {
		return err
	}
	// Also write to the hash map for O(1) lookup in BPF
	hm, ok := m.maps["nat64_prefix_map"]
	if ok {
		key := NAT64PrefixKey{Prefix: cfg.Prefix}
		hm.Update(key, cfg, ebpf.UpdateAny)
	}
	return nil
}

// SetNAT64Count writes the number of active NAT64 prefixes.
func (m *Manager) SetNAT64Count(count uint32) error {
	zm, ok := m.maps["nat64_count"]
	if !ok {
		return fmt.Errorf("nat64_count not found")
	}
	var zero uint32
	return zm.Update(zero, count, ebpf.UpdateAny)
}

// ClearNAT64Configs zeroes all NAT64 config entries and sets count to 0.
func (m *Manager) ClearNAT64Configs() error {
	zm, ok := m.maps["nat64_configs"]
	if !ok {
		return fmt.Errorf("nat64_configs not found")
	}
	var empty NAT64Config
	for i := uint32(0); i < 4; i++ { // MAX_NAT64_PREFIXES
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	// Clear the hash map
	if hm, ok := m.maps["nat64_prefix_map"]; ok {
		var key NAT64PrefixKey
		var val []byte
		iter := hm.Iterate()
		var keys []NAT64PrefixKey
		for iter.Next(&key, &val) {
			keys = append(keys, key)
		}
		for _, k := range keys {
			hm.Delete(k)
		}
	}
	return m.SetNAT64Count(0)
}

// ipTo16Bytes converts a net.IP to a [16]byte array.
func ipTo16Bytes(ip net.IP) [16]byte {
	var b [16]byte
	copy(b[:], ip.To16())
	return b
}

// SetIfaceFilter assigns a filter ID to an interface + family combination.
func (m *Manager) SetIfaceFilter(key IfaceFilterKey, filterID uint32) error {
	zm, ok := m.maps["iface_filter_map"]
	if !ok {
		return fmt.Errorf("iface_filter_map not found")
	}
	return zm.Update(key, filterID, ebpf.UpdateAny)
}

// ClearIfaceFilterMap removes all entries from the iface_filter_map.
func (m *Manager) ClearIfaceFilterMap() error {
	zm, ok := m.maps["iface_filter_map"]
	if !ok {
		return fmt.Errorf("iface_filter_map not found")
	}
	var key IfaceFilterKey
	var val []byte
	iter := zm.Iterate()
	var keys []IfaceFilterKey
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		zm.Delete(k)
	}
	return nil
}

// SetFilterConfig writes a filter config entry.
func (m *Manager) SetFilterConfig(filterID uint32, cfg FilterConfig) error {
	zm, ok := m.maps["filter_configs"]
	if !ok {
		return fmt.Errorf("filter_configs not found")
	}
	return zm.Update(filterID, cfg, ebpf.UpdateAny)
}

// ReadFilterConfig reads a filter config entry.
func (m *Manager) ReadFilterConfig(filterID uint32) (FilterConfig, error) {
	zm, ok := m.maps["filter_configs"]
	if !ok {
		return FilterConfig{}, fmt.Errorf("filter_configs not found")
	}
	var cfg FilterConfig
	if err := zm.Lookup(filterID, &cfg); err != nil {
		return FilterConfig{}, err
	}
	return cfg, nil
}

// SetFilterRule writes a filter rule entry.
func (m *Manager) SetFilterRule(index uint32, rule FilterRule) error {
	zm, ok := m.maps["filter_rules"]
	if !ok {
		return fmt.Errorf("filter_rules not found")
	}
	return zm.Update(index, rule, ebpf.UpdateAny)
}

// SetPolicerConfig writes a policer configuration entry.
func (m *Manager) SetPolicerConfig(id uint32, cfg PolicerConfig) error {
	zm, ok := m.maps["policer_configs"]
	if !ok {
		return fmt.Errorf("policer_configs map not found")
	}
	return zm.Update(id, cfg, ebpf.UpdateAny)
}

// ClearPolicerConfigs zeroes all policer_configs entries.
func (m *Manager) ClearPolicerConfigs() error {
	zm, ok := m.maps["policer_configs"]
	if !ok {
		return fmt.Errorf("policer_configs map not found")
	}
	empty := PolicerConfig{}
	for i := uint32(0); i < MaxPolicers; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// ClearFilterConfigs clears all filter config and rule entries.
func (m *Manager) ClearFilterConfigs() error {
	zm, ok := m.maps["filter_configs"]
	if !ok {
		return fmt.Errorf("filter_configs not found")
	}
	var empty FilterConfig
	for i := uint32(0); i < MaxFilterConfigs; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
	return nil
}

// UpdatePolicyScheduleState iterates policy rules and toggles the Active flag
// based on scheduler state. Only rules whose scheduler state changed are updated.
func (m *Manager) UpdatePolicyScheduleState(_ *config.Config, activeState map[string]bool) {
	zm, ok := m.maps["policy_rules"]
	if !ok {
		return
	}
	result := m.LastCompileResult()
	if result == nil {
		return
	}

	for _, slot := range result.PolicyScheduleRuleSlots {
		active, exists := activeState[slot.SchedulerName]
		if !exists {
			active = true // default active if scheduler not found
		}

		idx := slot.PolicySetID*MaxRulesPerPolicy + slot.RuleIndex
		var rule PolicyRule
		if err := zm.Lookup(idx, &rule); err != nil {
			continue
		}

		var newActive uint8
		if active {
			newActive = 1
		}
		if rule.Active != newActive {
			rule.Active = newActive
			zm.Update(idx, rule, ebpf.UpdateAny)
			slog.Info("policy schedule state updated",
				"policy", slot.PolicyName,
				"scheduler", slot.SchedulerName,
				"active", active)
		}
	}
}

// ReadNATRuleCounter reads the per-CPU NAT rule hit counter and returns
// the summed packets and bytes across all CPUs.
func (m *Manager) ReadNATRuleCounter(counterID uint32) (CounterValue, error) {
	zm, ok := m.maps["nat_rule_counters"]
	if !ok {
		return CounterValue{}, fmt.Errorf("nat_rule_counters map not found")
	}
	var perCPU []CounterValue
	if err := zm.Lookup(counterID, &perCPU); err != nil {
		return CounterValue{}, err
	}
	var total CounterValue
	for _, v := range perCPU {
		total.Packets += v.Packets
		total.Bytes += v.Bytes
	}
	return total, nil
}

// ClearNATRuleCounters zeroes all NAT rule counter entries.
func (m *Manager) ClearNATRuleCounters() error {
	zm, ok := m.maps["nat_rule_counters"]
	if !ok {
		return fmt.Errorf("nat_rule_counters map not found")
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]CounterValue, numCPUs)
	for i := uint32(0); i < MaxNATRuleCounters; i++ {
		zm.Update(i, zero, ebpf.UpdateAny)
	}
	return nil
}

// ReadNATPortCounter reads the per-CPU NAT port allocation counter for a pool
// and returns the sum across all CPUs.
func (m *Manager) ReadNATPortCounter(poolID uint32) (uint64, error) {
	zm, ok := m.maps["nat_port_counters"]
	if !ok {
		return 0, fmt.Errorf("nat_port_counters map not found")
	}
	var perCPU []NATPortCounter
	if err := zm.Lookup(poolID, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v.Counter
	}
	return total, nil
}

// SeedNATPortCounters initializes all NAT port allocation counters with a
// random offset. This prevents SNAT port reuse after daemon restart — without
// the seed, the allocator starts from port_low and reuses ports that remote
// servers may still have in ESTABLISHED state from pre-restart sessions.
func (m *Manager) SeedNATPortCounters() {
	zm, ok := m.maps["nat_port_counters"]
	if !ok {
		return
	}
	numCPUs, err := ebpf.PossibleCPU()
	if err != nil || numCPUs <= 0 {
		return
	}
	for poolID := uint32(0); poolID < 32; poolID++ {
		vals := make([]NATPortCounter, numCPUs)
		// Only seed CPU 0; the CPU-interleaved formula ensures each CPU
		// gets a distinct sequence regardless of starting offset.
		vals[0] = NATPortCounter{Counter: rand.Uint64()}
		zm.Update(poolID, vals, ebpf.UpdateAny)
	}
	slog.Info("seeded NAT port counters with random offset")
}

// SeedSessionIDCounter seeds the session_id_gen PERCPU map with a
// node-specific base to avoid collisions between cluster nodes.
// Each CPU gets base = (nodeID << 48) | (cpuIndex << 32).
func (m *Manager) SeedSessionIDCounter(nodeID int) {
	zm, ok := m.maps["session_id_gen"]
	if !ok {
		return
	}
	numCPUs, err := ebpf.PossibleCPU()
	if err != nil || numCPUs <= 0 {
		return
	}
	vals := make([]uint64, numCPUs)
	for i := range vals {
		vals[i] = (uint64(nodeID) << 48) | (uint64(i) << 32)
	}
	if err := zm.Update(uint32(0), vals, ebpf.UpdateAny); err != nil {
		slog.Warn("failed to seed session ID counter", "err", err)
		return
	}
	slog.Info("seeded session ID counter", "nodeID", nodeID, "cpus", numCPUs)
}

// --- Hitless restart: delete-stale methods ---
// These methods remove map entries that are no longer present in the new config,
// AFTER new entries have been written. This avoids the clear-then-repopulate
// window where BPF programs see empty maps.

// DeleteStaleIfaceZone removes iface_zone_map entries not in the written set.
func (m *Manager) DeleteStaleIfaceZone(written map[IfaceZoneKey]bool) {
	zm, ok := m.maps["iface_zone_map"]
	if !ok {
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
	zm, ok := m.maps["vlan_iface_map"]
	if !ok {
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
	zm, ok := m.maps["zone_pair_policies"]
	if !ok {
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
		fromZone := uint16(key / MaxZones)
		toZone := uint16(key % MaxZones)
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
	zm, ok := m.maps["applications"]
	if !ok {
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

// DeleteStaleSNATRules zeroes snat_rules ARRAY entries not in the written set.
// The map is an ARRAY so entries cannot be deleted — zero means "no rule".
func (m *Manager) DeleteStaleSNATRules(written map[SNATKey]bool) {
	zm, ok := m.maps["snat_rules"]
	if !ok {
		return
	}
	empty := SNATValue{}
	var key uint32
	var val SNATValue
	iter := zm.Iterate()
	count := 0
	for iter.Next(&key, &val) {
		if val.Mode == 0 && val.SrcAddrID == 0 && val.DstAddrID == 0 {
			continue // already empty
		}
		fromZone := uint16(key / (MaxZones * MaxSNATRulesPerPair))
		rem := key % (MaxZones * MaxSNATRulesPerPair)
		toZone := uint16(rem / MaxSNATRulesPerPair)
		ruleIdx := uint16(rem % MaxSNATRulesPerPair)
		sk := SNATKey{FromZone: fromZone, ToZone: toZone, RuleIdx: ruleIdx}
		if !written[sk] {
			zm.Update(key, empty, ebpf.UpdateAny)
			count++
		}
	}
	if count > 0 {
		slog.Info("zeroed stale snat_rules entries", "count", count)
	}
}

// DeleteStaleSNATRulesV6 zeroes snat_rules_v6 ARRAY entries not in the written set.
// The map is an ARRAY so entries cannot be deleted — zero means "no rule".
func (m *Manager) DeleteStaleSNATRulesV6(written map[SNATKey]bool) {
	zm, ok := m.maps["snat_rules_v6"]
	if !ok {
		return
	}
	empty := SNATValueV6{}
	var key uint32
	var val SNATValueV6
	iter := zm.Iterate()
	count := 0
	for iter.Next(&key, &val) {
		if val.Mode == 0 && val.SrcAddrID == 0 && val.DstAddrID == 0 {
			continue // already empty
		}
		fromZone := uint16(key / (MaxZones * MaxSNATRulesPerPair))
		rem := key % (MaxZones * MaxSNATRulesPerPair)
		toZone := uint16(rem / MaxSNATRulesPerPair)
		ruleIdx := uint16(rem % MaxSNATRulesPerPair)
		sk := SNATKey{FromZone: fromZone, ToZone: toZone, RuleIdx: ruleIdx}
		if !written[sk] {
			zm.Update(key, empty, ebpf.UpdateAny)
			count++
		}
	}
	if count > 0 {
		slog.Info("zeroed stale snat_rules_v6 entries", "count", count)
	}
}

// DeleteStaleDNATStatic removes static dnat_table entries not in the written set.
func (m *Manager) DeleteStaleDNATStatic(written map[DNATKey]bool) {
	zm, ok := m.maps["dnat_table"]
	if !ok {
		return
	}
	var key DNATKey
	var val DNATValue
	iter := zm.Iterate()
	var stale []DNATKey
	for iter.Next(&key, &val) {
		if val.Flags == DNATFlagStatic && !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale dnat_table entries", "count", len(stale))
	}
}

// DeleteStaleDNATStaticV6 removes static dnat_table_v6 entries not in the written set.
func (m *Manager) DeleteStaleDNATStaticV6(written map[DNATKeyV6]bool) {
	zm, ok := m.maps["dnat_table_v6"]
	if !ok {
		return
	}
	var key DNATKeyV6
	var val DNATValueV6
	iter := zm.Iterate()
	var stale []DNATKeyV6
	for iter.Next(&key, &val) {
		if val.Flags == DNATFlagStatic && !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale dnat_table_v6 entries", "count", len(stale))
	}
}

// DeleteStaleStaticNAT removes static_nat entries not in the written sets.
func (m *Manager) DeleteStaleStaticNAT(writtenV4 map[StaticNATKeyV4]bool, writtenV6 map[StaticNATKeyV6]bool) {
	if zm, ok := m.maps["static_nat_v4"]; ok {
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
	if zm, ok := m.maps["static_nat_v6"]; ok {
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

// SetNPTv6Rule writes an NPTv6 prefix translation rule.
func (m *Manager) SetNPTv6Rule(key NPTv6Key, val NPTv6Value) error {
	zm, ok := m.maps["nptv6_rules"]
	if !ok {
		return fmt.Errorf("nptv6_rules map not found")
	}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// DeleteStaleNPTv6 removes nptv6_rules entries not in the written set.
func (m *Manager) DeleteStaleNPTv6(written map[NPTv6Key]bool) {
	zm, ok := m.maps["nptv6_rules"]
	if !ok {
		return
	}
	var key NPTv6Key
	var val []byte
	iter := zm.Iterate()
	var stale []NPTv6Key
	for iter.Next(&key, &val) {
		if !written[key] {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		zm.Delete(k)
	}
	if len(stale) > 0 {
		slog.Info("deleted stale nptv6_rules entries", "count", len(stale))
	}
}

// DeleteStaleNAT64 zeroes stale nat64_configs entries and removes stale prefix map entries.
func (m *Manager) DeleteStaleNAT64(count uint32, writtenPrefixes map[NAT64PrefixKey]bool) {
	if zm, ok := m.maps["nat64_configs"]; ok {
		var empty NAT64Config
		for i := count; i < 4; i++ {
			zm.Update(i, empty, ebpf.UpdateAny)
		}
	}
	if hm, ok := m.maps["nat64_prefix_map"]; ok {
		var key NAT64PrefixKey
		var val []byte
		iter := hm.Iterate()
		var stale []NAT64PrefixKey
		for iter.Next(&key, &val) {
			if !writtenPrefixes[key] {
				stale = append(stale, key)
			}
		}
		for _, k := range stale {
			hm.Delete(k)
		}
	}
}

// ZeroStaleScreenConfigs zeroes screen_configs entries above maxID.
func (m *Manager) ZeroStaleScreenConfigs(maxID uint32) {
	zm, ok := m.maps["screen_configs"]
	if !ok {
		return
	}
	empty := ScreenConfig{}
	for i := maxID + 1; i < 64; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
}

// ZeroStaleNATPoolConfigs zeroes nat_pool_configs and nat_pool_ips entries
// for pool IDs from startID onwards.
func (m *Manager) ZeroStaleNATPoolConfigs(startID uint32) {
	if zm, ok := m.maps["nat_pool_configs"]; ok {
		empty := NATPoolConfig{}
		for i := startID; i < 32; i++ {
			zm.Update(i, empty, ebpf.UpdateAny)
		}
	}
	if v4Map, ok := m.maps["nat_pool_ips_v4"]; ok {
		var zeroV4 uint32
		start := startID * MaxNATPoolIPsPerPool
		end := uint32(32) * MaxNATPoolIPsPerPool
		for i := start; i < end; i++ {
			v4Map.Update(i, zeroV4, ebpf.UpdateAny)
		}
	}
	if v6Map, ok := m.maps["nat_pool_ips_v6"]; ok {
		zeroV6 := NATPoolIPV6{}
		start := startID * MaxNATPoolIPsPerPool
		end := uint32(32) * MaxNATPoolIPsPerPool
		for i := start; i < end; i++ {
			v6Map.Update(i, zeroV6, ebpf.UpdateAny)
		}
	}
}

// DeleteStaleIfaceFilter removes iface_filter_map entries not in the written set.
func (m *Manager) DeleteStaleIfaceFilter(written map[IfaceFilterKey]bool) {
	zm, ok := m.maps["iface_filter_map"]
	if !ok {
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
	zm, ok := m.maps["filter_configs"]
	if !ok {
		return
	}
	var empty FilterConfig
	for i := startID; i < MaxFilterConfigs; i++ {
		zm.Update(i, empty, ebpf.UpdateAny)
	}
}

// BumpFIBGeneration increments the global FIB generation counter, causing
// all cached FIB entries in sessions to miss on the next packet. BPF programs
// compare session.fib_gen against fib_gen_map[0] and re-run bpf_fib_lookup
// when they differ.
//
// This replaces the old InvalidateFIBCache() approach which iterated sessions
// and wrote them back via sm.Update(). That caused RCU replacement of hash map
// entries — BPF programs holding pointers from bpf_map_lookup_elem would write
// to the OLD (about-to-be-freed) entry, losing counter/last_seen updates and
// causing sessions to expire prematurely.
// StartFIBSync is a no-op for eBPF — bpf_fib_lookup handles FIB queries in-kernel.
func (m *Manager) StartFIBSync(_ context.Context) {}

func (m *Manager) NotifyLinkCycle() {} // no-op: eBPF programs survive link cycles
func (m *Manager) SyncFabricState() {} // no-op: eBPF uses fabric_fwd BPF map directly

func (m *Manager) BumpFIBGeneration() uint32 {
	zm, ok := m.maps["fib_gen_map"]
	if !ok {
		slog.Warn("fib_gen_map not found, cannot bump FIB generation")
		return 0
	}
	var key uint32
	var gen uint32
	if err := zm.Lookup(key, &gen); err != nil {
		gen = 0
	}
	gen++
	if err := zm.Update(key, gen, ebpf.UpdateAny); err != nil {
		slog.Warn("failed to bump FIB generation", "err", err)
		return gen - 1
	}
	slog.Info("bumped FIB generation counter", "generation", gen)
	return gen
}

// MapStats holds utilization info for a BPF map.
type MapStats struct {
	Name       string
	Type       string
	MaxEntries uint32
	UsedCount  uint32
	KeySize    uint32
	ValueSize  uint32
}

// GetMapStats returns utilization statistics for key BPF maps.
func (m *Manager) GetMapStats() []MapStats {
	// Maps to report on and whether to count entries (only for hash maps)
	reportMaps := []struct {
		name      string
		countable bool // hash maps can be iterated; arrays cannot meaningfully count
	}{
		{"sessions", true},
		{"sessions_v6", true},
		{"zone_configs", false},
		{"policy_rules", false},
		{"address_book_v4", true},
		{"address_book_v6", true},
		{"address_membership", true},
		{"applications", true},
		{"snat_rules", false},
		{"dnat_table", true},
		{"dnat_table_v6", true},
		{"nat_pool_config", false},
		{"screen_profiles", false},
		{"global_counters", false},
		{"policy_counters", false},
		{"filter_rules", true},
	}

	var stats []MapStats
	for _, rm := range reportMaps {
		bm, ok := m.maps[rm.name]
		if !ok || bm == nil {
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
