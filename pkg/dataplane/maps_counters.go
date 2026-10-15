package dataplane

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// Cross-cutting counter map accessors.
// Same-package split of maps.go (#1686): the generic global/interface/zone
// counters plus the ClearAllCounters orchestrator. Domain-specific counters
// (policy, filter, NAT, flood) live in their own domain files; ClearAllCounters
// calls those domain clears via same-package method dispatch.

// ErrCounterNotPopulated reports that a READ returned no value for this key --
// the family is safely readable, but nothing published a row here (#3643). It
// deliberately does NOT say the family is unsourced: per-zone traffic IS
// sourced since #3651, and only flood remains unsourced. It is DISTINCT from a
// genuine read failure (a missing map or a degraded IPC bridge, which must
// still bump the #3345 xpf_counter_read_errors_total signal) and DISTINCT from
// a real zero. Read surfaces treat it as "not available" -- never a 500, never
// a false read-error alert, never a bare misleading 0.
//
// The two per-zone families that return this reach it for DIFFERENT reasons,
// and conflating them is what made the pre-#6843 wording wrong:
//
//   - Per-zone TRAFFIC counters ARE populated (#3651 shipped the userspace
//     POPULATE path). This sentinel means the helper published no row for THIS
//     zone -- a pre-#3651 helper, a zone past the helper's hot-path slot
//     capacity, or an idle zone whose all-zero row the sparse snapshot drops.
//     Those are the ONLY three. "No loaded dataplane" and "no apply result
//     yet" are NOT meanings of this sentinel: on both, the collector
//     increments before it ever calls ReadZoneCounters, so no read happens and
//     no sentinel is produced. They are causes of the UNPOPULATED GAUGE, which
//     is a wider set -- see the xpf_zone_counters_unpopulated_zones HELP, and
//     do not read that list as a list of sentinel meanings.
//   - Per-zone FLOOD counters are still deferred: no PRODUCTION writer exists,
//     so in a running firewall they report this on every read (#3643 plan §5A,
//     leaning on the #3343 aggregate). Not an API-wide absolute --
//     SetFloodCounterOffset is exported and tests do populate it.
var ErrCounterNotPopulated = errors.New("counter not populated in userspace dataplane")

// ReadGlobalCounter reads a per-CPU global counter and returns the sum across all CPUs.
func (m *Manager) ReadGlobalCounter(index uint32) (uint64, error) {
	zm, present, st := m.lookupMapLocked("global_counters")
	if st == registryFresh {
		return 0, fmt.Errorf("%w: global_counters", ErrDataplaneNotArmed)
	}
	if !present {
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

// ReadUserspaceCounterOffset returns just the in-memory userspace counter
// delta accumulated for index via IncrementGlobalCounter, independent of the
// BPF global_counters map. ReadGlobalCounter merges this offset with the
// per-CPU map sum; this accessor exposes the userspace half on its own so the
// userspace-dp counter bridge accounting (e.g. the #3343 per-screen-reason
// publish path) can be inspected without a loaded BPF map.
func (m *Manager) ReadUserspaceCounterOffset(index uint32) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.userspaceCounterOffsets[index]
}

// ReadInterfaceCounters reads the per-CPU interface counter values and sums them.
// interface_counters is a PERCPU_HASH (#756): a missing key simply means
// no traffic has traversed the interface yet, which reads as zero.
func (m *Manager) ReadInterfaceCounters(ifindex int) (InterfaceCounterValue, error) {
	zm, present, st := m.lookupMapLocked("interface_counters")
	if st == registryFresh {
		return InterfaceCounterValue{}, fmt.Errorf("%w: interface_counters", ErrDataplaneNotArmed)
	}
	if !present {
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

// ReadZoneCounters returns the userspace-reported per-zone traffic counter for
// zoneID in the given direction (0 = ingress, 1 = egress).
//
// #3643: zone ids are stable name-hashes in [1,65533] (#3075), but the legacy
// zone_counters BPF array is a dense MaxZones*2-entry per-CPU array. Indexing it
// by a stable-hash id >= MaxZones OOBs the bounded Lookup (ErrKeyNotExist),
// which the read surfaces mis-reported as a hard failure (REST 500, false
// Prometheus read-error alert, CLI/gRPC error rows). This now keys a Go-side
// sparse offset map -- the exact treatment #2255 gave nat_rule_counters -- and
// NEVER indexes the dense array, so an id >= MaxZones can no longer OOB.
//
// #3651: the helper DOES now populate per-zone traffic counters (Rust forward-
// path accounting -> ProcessStatus.ZoneTrafficCounters -> syncBPFCountersLocked
// -> ReplaceZoneCounterOffsets), so this returns live volume for a zone the helper
// has published. ErrCounterNotPopulated remains reachable and is NOT an error
// condition: the helper's status snapshot is sparse and omits all-zero rows, so
// the sentinel covers a pre-#3651 helper, a zone past the helper's hot-path
// slot capacity, and a merely idle zone alike. Surfaces must render "not
// available" (or omit the sample) rather than a misleading 0, and must not
// treat it as a read failure -- see pkg/api/README.md.
func (m *Manager) ReadZoneCounters(zoneID uint16, direction int) (CounterValue, error) {
	if direction != 0 && direction != 1 {
		return CounterValue{}, fmt.Errorf("invalid zone counter direction %d", direction)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	vals, ok := m.zoneCounterOffsets[zoneID]
	if !ok {
		return CounterValue{}, ErrCounterNotPopulated
	}
	return vals[direction], nil
}

// SetZoneCounterOffset records the absolute cumulative per-zone ingress/egress
// traffic counters reported by the userspace dataplane for zoneID (#3643
// POPULATE hook, mirroring SetNATRuleCounterOffset). Values are absolute
// (overwrite), matching the helper's cumulative-since-launch totals. Once set,
// ReadZoneCounters returns them (nil error) instead of ErrCounterNotPopulated.
//
// #6843: this has NO production callers. syncBPFCountersLocked now replaces the
// whole offset map per status poll (ReplaceZoneCounterOffsets) rather than
// setting row by row, because a per-row setter can only add or overwrite and so
// strands the last value of any zone the helper stops publishing. This single-
// row setter is retained for tests that seed one zone directly; production code
// MUST use ReplaceZoneCounterOffsets, or a zone that disappears from the helper
// snapshot keeps serving a frozen total.
func (m *Manager) SetZoneCounterOffset(zoneID uint16, ingress, egress CounterValue) {
	m.mu.Lock()
	if m.zoneCounterOffsets == nil {
		m.zoneCounterOffsets = make(map[uint16][2]CounterValue)
	}
	m.zoneCounterOffsets[zoneID] = [2]CounterValue{ingress, egress}
	m.mu.Unlock()
}

// ReplaceZoneCounterOffsets atomically replaces the ENTIRE per-zone offset map
// with the rows the helper published in this status poll (#3651).
//
// Replace, not merge, and the distinction is load-bearing. The helper's
// `zone_traffic_counters` block is a COMPLETE sparse set rebuilt from its store
// on every poll, not a delta — so a zone absent from it is a zone the helper is
// no longer reporting, and the correct Go-side state is "not populated".
// SetZoneCounterOffset alone can only ever ADD or overwrite, so a row that
// stops being published leaves its last value stranded in the map and every
// read surface keeps serving a FROZEN total indefinitely.
//
// Three ways a row legitimately disappears, all of which this handles:
//
//   - The zone lost its hot-path slot. Config apply carries the store forward
//     and retains still-configured zones, but a zone pushed past the helper's
//     assignable slot capacity gets slot 0 and stops being counted; the helper
//     drops it from the published set (coordinator zone_traffic_counters). Its
//     retained totals are stale from that moment on.
//   - The zone was deleted from the config (helper-side reconcile drops it).
//   - The helper restarted, or was downgraded to a build with no per-zone
//     block. Its store is empty, so it publishes nothing, and nothing is what
//     the Go side should report.
//
// An empty rows map therefore clears the offset map, which is correct in every case
// above: "the helper published no per-zone volume" is exactly
// ErrCounterNotPopulated. The sole call site (syncBPFCountersLocked) runs only
// on a successfully decoded ProcessStatus, so an empty set here is a real
// observation and never a failed fetch.
func (m *Manager) ReplaceZoneCounterOffsets(rows map[uint16][2]CounterValue) {
	m.mu.Lock()
	if len(rows) == 0 {
		m.zoneCounterOffsets = nil
		m.mu.Unlock()
		return
	}
	next := make(map[uint16][2]CounterValue, len(rows))
	for id, vals := range rows {
		next[id] = vals
	}
	m.zoneCounterOffsets = next
	m.mu.Unlock()
}

// ClearZoneCounterOffsets drops all userspace-reported per-zone traffic offsets
// (#3643), mirroring ClearNATRuleCounterOffsets. Wired into ClearZoneCounters.
func (m *Manager) ClearZoneCounterOffsets() {
	m.mu.Lock()
	m.zoneCounterOffsets = nil
	m.mu.Unlock()
}

// ClearGlobalCounters zeroes all global counter entries.
//
// A counter clear is an EPOCH operation: every source ReadGlobalCounter merges
// must move to zero together. ReadGlobalCounter returns the per-CPU BPF array
// sum PLUS the in-memory userspaceCounterOffsets entry (IncrementGlobalCounter
// accumulates the helper-forwarded deltas there so userspace-forwarded packets
// that bypass the BPF pipeline are still reflected). Zeroing only the BPF array
// therefore let a cleared global RX/TX/drop/session total snap straight back to
// its pre-clear value on the next read (#5098) — the offset half survived.
//
// Drop the offset map FIRST, under the same m.mu that guards every
// IncrementGlobalCounter/ReadGlobalCounter access, so (a) the clear takes
// effect on the read path even without a loaded BPF map (userspace-only
// runtime), mirroring ClearZoneCounters/ClearNATRuleCounters, and (b) in the
// userspace runtime the per-CPU BPF array is always 0 — the helper forwards
// packets outside the BPF pipeline and records them ONLY in the offset map,
// never the array — so once the offset is dropped a concurrent
// ReadGlobalCounter merges 0 (offset) + 0 (array) = 0. Note the offset reset
// and the BPF-array zero below are NOT co-locked: the reset happens under m.mu,
// the array zeroing after it is released. That is safe here ONLY because the
// array stays 0 in this runtime; were the array ever non-zero, a read racing
// between the two steps could briefly merge a zeroed offset with a stale array.
// This method clears every index [0,GlobalCtrMax) — exactly the set the offset
// map can hold — so the whole map is reset.
func (m *Manager) ClearGlobalCounters() error {
	m.mu.Lock()
	m.userspaceCounterOffsets = nil
	m.mu.Unlock()

	// #2114 A3 class 3: state-independent pinned behavior — scoped lookup
	// only; the zeroing below runs off-lock on the copied handle.
	zm, present, _ := m.lookupMapLocked("global_counters")
	if !present {
		// Userspace-only runtime with no BPF map loaded: the offset reset above
		// is the meaningful clear, so a missing array is not an error (parity
		// with ClearZoneCounters/ClearNATRuleCounters).
		return nil
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
	zm, present, st := m.lookupMapLocked("interface_counters")
	if st == registryFresh {
		return fmt.Errorf("%w: interface_counters", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("interface_counters map not found")
	}
	return clearInterfaceCountersIn(zm)
}

// clearInterfaceCountersRaw is the UNGATED composition leg for
// ClearAllCounters (#2114 A3 nested-call rule — class-3 hybrids compose
// through internal raw helpers, never the public gated methods, so the
// pinned legacy "interface_counters map not found" text survives in every
// state instead of being replaced by ErrDataplaneNotArmed; the userspace
// manager counter tests tolerate exactly that text on a mapless manager).
func (m *Manager) clearInterfaceCountersRaw() error {
	zm, present, _ := m.lookupMapLocked("interface_counters")
	if !present {
		return fmt.Errorf("interface_counters map not found")
	}
	return clearInterfaceCountersIn(zm)
}

func clearInterfaceCountersIn(zm *ebpf.Map) error {
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
	// #3643: drop the userspace-reported offsets first so an operator clear
	// takes effect on the read path (the only source of per-zone values today)
	// even when the legacy dense BPF map is absent, mirroring
	// ClearNATRuleCounters.
	m.ClearZoneCounterOffsets()
	// #2114 A3 class 3 (see ClearGlobalCounters).
	zm, present, _ := m.lookupMapLocked("zone_counters")
	if !present {
		return nil
	}
	numCPUs := ebpf.MustPossibleCPU()
	zero := make([]CounterValue, numCPUs)
	// #6959: PROPAGATE. 128 is zone_counters' max_entries.
	return clearArrayEntriesIn(zm, "zone_counters", 128, zero)
}

// ClearAllCounters zeroes all counter maps and userspace counter offsets.
//
// #2114 A3 class 3 nested-call rule: the composition runs through the
// UNGATED raw internals (clearInterfaceCountersRaw / clearPolicyCountersRaw /
// clearFilterCountersRaw) and the class-3 public clears (global/zone/NAT —
// ungated by design), never the gated class-1 public forms, so the pinned
// pre-arm legacy error texts survive byte-for-byte in every registry state.
func (m *Manager) ClearAllCounters() error {
	// Clear sparse userspace offsets before any map operation can fail. This is
	// required for mapless/userspace-only managers: the legacy interface map
	// lookup below still returns its pinned error, but must not strand counters.
	m.ClearZoneCounterOffsets()
	m.ClearFloodCounterOffsets()
	m.ClearNATRuleCounterOffsets()
	if err := m.ClearGlobalCounters(); err != nil {
		return err
	}
	if err := m.clearInterfaceCountersRaw(); err != nil {
		return err
	}
	if err := m.ClearZoneCounters(); err != nil {
		return err
	}
	if err := m.ClearNATRuleCounters(); err != nil {
		return err
	}
	if err := m.clearPolicyCountersRaw(); err != nil {
		return err
	}
	return m.clearFilterCountersRaw()
}
