package dataplane

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Screen / IDS map accessors.
// Same-package split of maps.go (#1686): screen profile configs, the
// per-source/per-destination session-count limit maps, and the per-zone flood
// counters. The session-count maps are a separate map family co-located here
// by IDS relevance, not because they share storage with screen_configs.

// SetScreenConfig writes a screen profile configuration entry.
func (m *Manager) SetScreenConfig(profileID uint32, cfg ScreenConfig) error {
	zm, present, st := m.lookupMapLocked("screen_configs")
	if st == registryFresh {
		return fmt.Errorf("%w: screen_configs", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("screen_configs map not found")
	}
	return zm.Update(profileID, cfg, ebpf.UpdateAny)
}

// ClearScreenConfigs zeroes all screen_configs entries.
func (m *Manager) ClearScreenConfigs() error {
	zm, present, st := m.lookupMapLocked("screen_configs")
	if st == registryFresh {
		return fmt.Errorf("%w: screen_configs", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("screen_configs map not found")
	}
	// #6959: PROPAGATE. 64 is screen_configs' max_entries.
	return clearArrayEntriesIn(zm, "screen_configs", 64, ScreenConfig{})
}

// UpdateSessionCountSrc writes a per-source-IP session count entry.
func (m *Manager) UpdateSessionCountSrc(key SessionCountKey, count uint32) error {
	zm, present, st := m.lookupMapLocked("session_count_src")
	if st == registryFresh {
		return fmt.Errorf("%w: session_count_src", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("session_count_src map not found")
	}
	val := SessionCountValue{Count: count}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// UpdateSessionCountDst writes a per-destination-IP session count entry.
func (m *Manager) UpdateSessionCountDst(key SessionCountKey, count uint32) error {
	zm, present, st := m.lookupMapLocked("session_count_dst")
	if st == registryFresh {
		return fmt.Errorf("%w: session_count_dst", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("session_count_dst map not found")
	}
	val := SessionCountValue{Count: count}
	return zm.Update(key, val, ebpf.UpdateAny)
}

// ClearSessionCounts deletes all entries from the session count maps.
func (m *Manager) ClearSessionCounts() error {
	for _, name := range []string{"session_count_src", "session_count_dst"} {
		zm, present, _ := m.lookupMapLocked(name)
		if !present {
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

// ReadFloodCounters returns the userspace-reported per-zone flood-event state
// for zoneID.
//
// #3643: like ReadZoneCounters, this keys a Go-side sparse offset map instead
// of indexing the dense flood_counters BPF array (MaxZones entries), so a
// stable-hash zone id >= MaxZones can no longer OOB the bounded Lookup and
// surface as a hard read failure.
//
// #3651: the helper DOES now populate per-zone flood counters (Rust screen-drop
// path accounting -> ProcessStatus.ZoneFloodCounters -> syncBPFCountersLocked ->
// ReplaceFloodCounterOffsets), so this returns live SYN/ICMP/UDP flood-event
// counts for a zone the helper has published. Only SynCount/ICMPCount/UDPCount
// are sourced; the legacy WindowStart/SynproxyActive fields belonged to the
// deleted eBPF rate-limiter state and stay zero (no surface reads them).
// ErrCounterNotPopulated remains reachable and is NOT an error condition: the
// helper's snapshot is sparse and omits all-zero rows, so the sentinel covers a
// helper with no per-zone flood accounting, a zone past the helper's slot
// capacity, and a zone that has simply never tripped a flood check alike.
// Surfaces must render "not available" rather than a misleading 0.
func (m *Manager) ReadFloodCounters(zoneID uint32) (FloodState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fs, ok := m.floodCounterOffsets[zoneID]
	if !ok {
		return FloodState{}, ErrCounterNotPopulated
	}
	return fs, nil
}

// SetFloodCounterOffset records the absolute cumulative per-zone flood-event
// counts reported by the userspace dataplane for zoneID (#3643 POPULATE hook,
// mirroring SetZoneCounterOffset). Once set, ReadFloodCounters returns it (nil
// error) instead of ErrCounterNotPopulated.
//
// #3651: this has NO production callers. syncBPFCountersLocked replaces the
// whole offset map per status poll (ReplaceFloodCounterOffsets) rather than
// setting row by row, because a per-row setter can only add or overwrite and so
// strands the last value of any zone the helper stops publishing. This single-
// row setter is retained for tests that seed one zone directly; production code
// MUST use ReplaceFloodCounterOffsets, or a zone that disappears from the helper
// snapshot keeps serving a frozen total.
func (m *Manager) SetFloodCounterOffset(zoneID uint32, fs FloodState) {
	m.mu.Lock()
	if m.floodCounterOffsets == nil {
		m.floodCounterOffsets = make(map[uint32]FloodState)
	}
	m.floodCounterOffsets[zoneID] = fs
	m.mu.Unlock()
}

// ReplaceFloodCounterOffsets atomically replaces the ENTIRE per-zone flood
// offset map with the rows the helper published in this status poll (#3651).
//
// Replace, not merge, and the distinction is load-bearing — the exact same
// argument as ReplaceZoneCounterOffsets. The helper's `zone_flood_counters`
// block is a COMPLETE sparse set rebuilt from its store on every poll, not a
// delta, so a zone absent from it is a zone the helper is no longer reporting
// and the correct Go-side state is "not populated". SetFloodCounterOffset alone
// can only ever ADD or overwrite, so a row that stops being published leaves its
// last value stranded in the map and every read surface keeps serving a FROZEN
// flood count indefinitely — a number that looks alive while under-reporting
// every subsequent attack, which is strictly worse than an honest
// "not available".
//
// Three ways a row legitimately disappears, all of which this handles:
//
//   - The zone lost its hot-path slot. Config apply carries the helper's store
//     forward and retains still-configured zones, but a zone pushed past the
//     helper's assignable slot capacity gets slot 0 and stops being counted; the
//     helper drops it from the published set (coordinator zone_flood_counters).
//     Its retained counts are stale from that moment on.
//   - The zone was deleted from the config (helper-side reconcile drops it).
//   - The helper restarted, was cleared (clear_flood_counters), or was
//     downgraded to a build with no per-zone flood block. Its store is empty, so
//     it publishes nothing, and nothing is what the Go side should report.
//
// An empty rows map therefore clears the offset map, which is correct in every
// case above: "the helper published no per-zone flood counts" is exactly
// ErrCounterNotPopulated. The sole call site (syncBPFCountersLocked) runs only
// on a successfully decoded ProcessStatus, so an empty set here is a real
// observation and never a failed fetch.
func (m *Manager) ReplaceFloodCounterOffsets(rows map[uint32]FloodState) {
	m.mu.Lock()
	if len(rows) == 0 {
		m.floodCounterOffsets = nil
		m.mu.Unlock()
		return
	}
	next := make(map[uint32]FloodState, len(rows))
	for id, fs := range rows {
		next[id] = fs
	}
	m.floodCounterOffsets = next
	m.mu.Unlock()
}

// ClearFloodCounterOffsets drops all userspace-reported per-zone flood offsets
// (#3643). Wired into ClearAllCounters.
func (m *Manager) ClearFloodCounterOffsets() {
	m.mu.Lock()
	m.floodCounterOffsets = nil
	m.mu.Unlock()
}
