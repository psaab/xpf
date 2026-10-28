package dataplane

import (
	"fmt"
	"log/slog"
	"math/rand/v2"

	"github.com/cilium/ebpf"
)

// NAT map accessors.
// Same-package split of maps.go (#1686): DNAT/SNAT rules, NAT pools, SNAT
// egress IPs, static 1:1 NAT, NAT64, NPTv6, plus the NAT-specific rule/port
// counters and the port-counter seed. NAT counters live here (not
// maps_counters.go) by the #1686 rule that domain-specific counters stay with
// their domain.

// ReadNATRuleCounter returns the per-rule NAT translation hit total for a
// counter ID (#2218). The value is the userspace-reported offset: the Rust
// userspace dataplane never writes the legacy nat_rule_counters BPF array map
// (the #1476 eBPF retirement dropped the XDP increment), it reports per-rule
// hits over the status channel, which the userspace Manager mirrors here via
// SetNATRuleCounterOffset.
//
// #2255: counter IDs are now a stable key-derived hash (sparse u32), not a
// dense [0,256) array index, so this read path keys the sparse offset map
// directly and never indexes the legacy 256-entry nat_rule_counters array
// (a hash id ≥ MaxNATRuleCounters would fail that bounded Lookup). The legacy
// array only ever held zeros at runtime, so dropping the Lookup changes no
// observable value.
func (m *Manager) ReadNATRuleCounter(counterID uint32) (CounterValue, error) {
	m.mu.Lock()
	offset := m.natRuleCounterOffsets[counterID]
	m.mu.Unlock()
	return offset, nil
}

// SetNATRuleCounterOffset records the absolute cumulative per-rule NAT
// translation hit total reported by the Rust userspace dataplane for the
// given counter ID (#2218). ReadNATRuleCounter merges this offset on top of
// the BPF map value. The total is absolute (overwrites), since the helper
// reports cumulative-since-start totals on every status poll.
func (m *Manager) SetNATRuleCounterOffset(counterID uint32, val CounterValue) {
	m.mu.Lock()
	if m.natRuleCounterOffsets == nil {
		m.natRuleCounterOffsets = make(map[uint32]CounterValue)
	}
	m.natRuleCounterOffsets[counterID] = val
	m.mu.Unlock()
}

// ClearNATRuleCounterOffsets zeroes all userspace-reported NAT rule counter
// offsets (#2218). Called by ClearNATRuleCounters so an operator clear also
// drops the mirrored helper totals.
func (m *Manager) ClearNATRuleCounterOffsets() {
	m.mu.Lock()
	m.natRuleCounterOffsets = nil
	m.mu.Unlock()
}

// ClearNATRuleCounters zeroes all NAT rule counter entries.
func (m *Manager) ClearNATRuleCounters() error {
	// Drop userspace-reported offsets first so a clear takes effect even
	// without a BPF map (userspace-only runtime) (#2218).
	m.ClearNATRuleCounterOffsets()
	// #2114 A3 class 3: state-independent pinned behavior — the offset
	// reset above is the meaningful clear; the absent map is not an error
	// in ANY state. Scoped lookup only; the zeroing below runs off-lock.
	zm, present, _ := m.lookupMapLocked("nat_rule_counters")
	if !present {
		return nil
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]CounterValue, numCPUs)
	// #6959: PROPAGATE. MaxNATRuleCounters is nat_rule_counters'
	// max_entries.
	return clearArrayEntriesIn(zm, "nat_rule_counters", MaxNATRuleCounters, zero)
}

// ReadNATPortCounter reads the per-CPU NAT port allocation counter for a pool
// and returns the sum across all CPUs.
func (m *Manager) ReadNATPortCounter(poolID uint32) (uint64, error) {
	zm, present, st := m.lookupMapLocked("nat_port_counters")
	if st == registryFresh {
		return 0, fmt.Errorf("%w: nat_port_counters", ErrDataplaneNotArmed)
	}
	if !present {
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
	zm, present, _ := m.lookupMapLocked("nat_port_counters")
	if !present {
		return
	}
	numCPUs, err := ebpf.PossibleCPU()
	if err != nil || numCPUs <= 0 {
		return
	}
	// #8597 K75: the bound is the MAP's size, single-sourced. It used to be a
	// literal 32 sitting next to a map declared with userspaceShimMaxNATPools —
	// the same number twice, with nothing to notice if one moved. That constant
	// mirrors MAX_NAT_POOLS in bpf/headers/xpf_common.h (the shared C/Go ABI, so
	// widening it is a header change, not a Go one), and
	// TestSeedNATPortCountersCoversTheWholeMap_8597 pins the agreement.
	for poolID := uint32(0); poolID < userspaceShimMaxNATPools; poolID++ {
		vals := make([]NATPortCounter, numCPUs)
		// Only seed CPU 0; the CPU-interleaved formula ensures each CPU
		// gets a distinct sequence regardless of starting offset.
		vals[0] = NATPortCounter{Counter: rand.Uint64()}
		zm.Update(poolID, vals, ebpf.UpdateAny)
	}
	slog.Info("seeded NAT port counters with random offset")
}
