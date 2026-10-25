package dataplane

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
)

// Policy / zone / address-book / application map accessors.
// Same-package split of maps.go (#1686): zone configs, zone-pair policy sets,
// policy rules, address books + membership, applications, default policy, the
// scheduler-driven Active-flag toggle, and the policy hit counters.

// SetZoneConfig writes a zone configuration entry.
func (m *Manager) SetZoneConfig(zoneID uint32, cfg ZoneConfig) error {
	zm, present, st := m.lookupMapLocked("zone_configs")
	if st == registryFresh {
		return fmt.Errorf("%w: zone_configs", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("zone_configs map not found")
	}
	return zm.Update(uint32(zoneID), cfg, ebpf.UpdateAny)
}

// SetZonePairPolicy writes a zone-pair policy set entry.
// The zone_pair_policies map is an ARRAY keyed by flat index:
// from_zone * MaxZones + to_zone.
func (m *Manager) SetZonePairPolicy(fromZone, toZone uint32, ps PolicySet) error {
	zm, present, st := m.lookupMapLocked("zone_pair_policies")
	if st == registryFresh {
		return fmt.Errorf("%w: zone_pair_policies", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("zone_pair_policies map not found")
	}
	key := fromZone*MaxZones + toZone
	return zm.Update(key, ps, ebpf.UpdateAny)
}

// SetPolicyRule writes a policy rule at the computed flat index.
// #16560: the flat index is the contiguous runtime RuleID itself (the
// policy_rules map holds MAX_POLICIES*MAX_RULES_PER_POLICY entries and
// total expanded rules are capped at MaxTotalPolicyRuleExpansion, so the
// ID is always in range), not policySetID*MaxRulesPerPolicy+ruleIndex.
func (m *Manager) SetPolicyRule(policySetID uint32, ruleIndex uint32, rule PolicyRule) error {
	zm, present, st := m.lookupMapLocked("policy_rules")
	if st == registryFresh {
		return fmt.Errorf("%w: policy_rules", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("policy_rules map not found")
	}
	return zm.Update(rule.RuleID, rule, ebpf.UpdateAny)
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
		zm, present, st := m.lookupMapLocked("address_book_v4")
		if st == registryFresh {
			return fmt.Errorf("%w: address_book_v4", ErrDataplaneNotArmed)
		}
		if !present {
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
	zm, present, st := m.lookupMapLocked("address_book_v6")
	if st == registryFresh {
		return fmt.Errorf("%w: address_book_v6", ErrDataplaneNotArmed)
	}
	if !present {
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
	zm, present, st := m.lookupMapLocked("address_membership")
	if st == registryFresh {
		return fmt.Errorf("%w: address_membership", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("address_membership map not found")
	}
	key := AddrMembershipKey{IP: resolvedID, AddressID: setID}
	val := uint8(1)
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearAddressBookV4 removes all entries from the address_book_v4 LPM trie.
func (m *Manager) ClearAddressBookV4() error {
	zm, present, st := m.lookupMapLocked("address_book_v4")
	if st == registryFresh {
		return fmt.Errorf("%w: address_book_v4", ErrDataplaneNotArmed)
	}
	if !present {
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
	zm, present, st := m.lookupMapLocked("address_book_v6")
	if st == registryFresh {
		return fmt.Errorf("%w: address_book_v6", ErrDataplaneNotArmed)
	}
	if !present {
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
	zm, present, st := m.lookupMapLocked("address_membership")
	if st == registryFresh {
		return fmt.Errorf("%w: address_membership", ErrDataplaneNotArmed)
	}
	if !present {
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
	zm, present, st := m.lookupMapLocked("applications")
	if st == registryFresh {
		return fmt.Errorf("%w: applications", ErrDataplaneNotArmed)
	}
	if !present {
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
	zm, present, st := m.lookupMapLocked("app_ranges")
	if st == registryFresh {
		return fmt.Errorf("%w: app_ranges", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("app_ranges map not found")
	}
	return zm.Update(index, entry, ebpf.UpdateAny)
}

// ClearAppRanges zeros all app_ranges entries.
func (m *Manager) ClearAppRanges() error {
	zm, present, st := m.lookupMapLocked("app_ranges")
	if st == registryFresh {
		return fmt.Errorf("%w: app_ranges", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("app_ranges map not found")
	}
	// #6959: PROPAGATE. MaxAppRanges is app_ranges' max_entries.
	return clearArrayEntriesIn(zm, "app_ranges", MaxAppRanges, AppRangeEntry{})
}

// ClearZonePairPolicies zeros all zone-pair policy entries.
// The map is an ARRAY so entries cannot be deleted — zero means "no policy".
func (m *Manager) ClearZonePairPolicies() error {
	zm, present, st := m.lookupMapLocked("zone_pair_policies")
	if st == registryFresh {
		return fmt.Errorf("%w: zone_pair_policies", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("zone_pair_policies map not found")
	}
	zeroPS := PolicySet{}
	var key uint32
	var val PolicySet
	iter := zm.Iterate()
	for iter.Next(&key, &val) {
		if val.NumRules > 0 {
			// #6959: PROPAGATE. The keys come from the map's own
			// iterator, so every one is in range by construction and
			// no working clear becomes an error.
			if err := zm.Update(key, zeroPS, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("clear zone_pair_policies entry %d: %w", key, err)
			}
		}
	}
	return nil
}

// ClearApplications deletes all application map entries.
func (m *Manager) ClearApplications() error {
	zm, present, st := m.lookupMapLocked("applications")
	if st == registryFresh {
		return fmt.Errorf("%w: applications", ErrDataplaneNotArmed)
	}
	if !present {
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

// SetDefaultPolicy writes the global default policy action (0=deny, 1=permit).
func (m *Manager) SetDefaultPolicy(action uint8) error {
	zm, present, st := m.lookupMapLocked("default_policy")
	if st == registryFresh {
		return fmt.Errorf("%w: default_policy", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("default_policy map not found")
	}
	return zm.Update(uint32(0), action, ebpf.UpdateAny)
}

// UpdatePolicyScheduleState iterates policy rules and toggles the Active flag
// based on scheduler state. Only rules whose scheduler state changed are updated.
//
// #3780: this is the retired eBPF map path (the userspace backend shadows
// it in pkg/dataplane/userspace/manager.go). It stays best-effort: the map
// is direct-write, there is nothing to retry, and the eBPF backend never
// runs at runtime. It always reports success (nil) so the daemon's
// scheduler self-heal never spins on a dead path.
func (m *Manager) UpdatePolicyScheduleState(_ *config.Config, activeState map[string]bool) error {
	// #2114 A3 class 2: the #3780 deliberate nil is the fresh AND absent
	// outcome — the scheduler self-heal never spins on this path.
	zm, present, _ := m.lookupMapLocked("policy_rules")
	if !present {
		return nil
	}
	result := m.LastCompileResult()
	if result == nil {
		return nil
	}

	for _, slot := range result.PolicyScheduleRuleSlots {
		active, exists := activeState[slot.SchedulerName]
		if !exists {
			active = true // default active if scheduler not found
		}

		idx := slot.RuleID
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
			// #6959 DELIBERATE DISCARD (allowlisted in
			// discarded_map_update_6959_test.go). The #3780 contract in
			// this function's doc comment is that it ALWAYS reports
			// success so the daemon's scheduler self-heal never spins on
			// a dead path; this is the retired eBPF map, shadowed at
			// runtime by pkg/dataplane/userspace. Propagating here would
			// break that contract, not fix a defect.
			zm.Update(idx, rule, ebpf.UpdateAny)
			slog.Info("policy schedule state updated",
				"policy", slot.PolicyName,
				"scheduler", slot.SchedulerName,
				"active", active)
		}
	}
	return nil
}

// ReadPolicyCounters reads the per-CPU policy counter values and sums them.
func (m *Manager) ReadPolicyCounters(policyID uint32) (CounterValue, error) {
	zm, present, st := m.lookupMapLocked("policy_counters")
	if st == registryFresh {
		return CounterValue{}, fmt.Errorf("%w: policy_counters", ErrDataplaneNotArmed)
	}
	if !present {
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

// ClearPolicyCounters zeroes all policy counter entries.
func (m *Manager) ClearPolicyCounters() error {
	zm, present, st := m.lookupMapLocked("policy_counters")
	if st == registryFresh {
		return fmt.Errorf("%w: policy_counters", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("policy_counters map not found")
	}
	return clearPolicyCountersIn(zm)
}

// clearPolicyCountersRaw is the UNGATED ClearAllCounters composition leg
// (#2114 A3 nested-call rule — see clearInterfaceCountersRaw).
func (m *Manager) clearPolicyCountersRaw() error {
	zm, present, _ := m.lookupMapLocked("policy_counters")
	if !present {
		return fmt.Errorf("policy_counters map not found")
	}
	return clearPolicyCountersIn(zm)
}

// counterMapUpdater is the *ebpf.Map subset the blind-write counter-clear
// loops use. It exists as a seam (#2114, Codex PR #6743 r4-F2): creating
// a real BPF map needs privileges the unit lane does not have, so the
// error-propagation contract below is otherwise untestable and would ship
// on a comment alone. *ebpf.Map satisfies it as declared.
type counterMapUpdater interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
}

// clearArrayEntriesIn zeroes entries [0, entries) of a BPF ARRAY map and
// PROPAGATES the first Update error, naming the map and the index.
//
// #6959: this is the shared body of the blind-write clear loops that #6743
// left behind. Each of them ran `zm.Update(i, zero, ebpf.UpdateAny)` as a
// bare statement, so an operator's `clear ...` reported success no matter
// how many slots the map actually rejected — a detached map, a permissions
// failure, or a size mismatch was indistinguishable from a completed clear.
// It takes the same counterMapUpdater seam #6743 introduced because
// creating a real BPF map returns EPERM in the unprivileged unit lane, so
// the propagation contract is otherwise untestable.
//
// The bound is always the map's declared max_entries (see each call site),
// so no index can be out of range on an armed map and no WORKING clear
// becomes an error.
func clearArrayEntriesIn(zm counterMapUpdater, mapName string, entries uint32, zero any) error {
	for i := uint32(0); i < entries; i++ {
		if err := zm.Update(i, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear %s entry %d: %w", mapName, i, err)
		}
	}
	return nil
}

// clearPolicyCountersIn zeroes every policy_counters slot.
//
// #2114 (Codex PR #6743 r4-F2): the Update error is PROPAGATED. It used
// to be discarded, so `clear security policies statistics` reported
// success even when not one slot was actually zeroed — the operator's
// only feedback that the clear landed was a message that could not
// fail. The bound is exact: policy_counters is a PERCPU_ARRAY of
// MAX_POLICIES == 4096 entries (bpf/headers/xpf_maps.h,
// bpf/headers/xpf_common.h:151), so every index below is in range on an
// armed map and this cannot turn a working clear into an error. Matches
// clearInterfaceCountersIn, which already returned its Update error.
//
// RESIDUAL — error propagation does NOT close the detached-backend false
// success (Codex PR #6743 r5/r6-F5). Teardown() does not close the map
// FDs: loader.go's teardown closes only the link handles and Cleanup
// merely unpins, so a RETAINED, torn-down Manager still holds a live
// FD-backed map object. cilium's Map.Update through that FD SUCCEEDS, and
// a successful write is indistinguishable from a correct one at this
// layer — so a `clear` issued against a disowned generation still reports
// success while the live generation keeps its counters. Detecting it
// needs a generation tag or lease on the handle itself, which is #6741's
// scope, NOT this wrapper's; do not read the paragraph above as closing
// that case.
func clearPolicyCountersIn(zm counterMapUpdater) error {
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]CounterValue, numCPUs)
	for i := uint32(0); i < 4096; i++ {
		if err := zm.Update(i, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear policy_counters %d: %w", i, err)
		}
	}
	return nil
}
