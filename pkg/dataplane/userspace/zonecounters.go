package userspace

import (
	"errors"
)

// ClearZoneCounters resets the per-zone ingress/egress traffic counters
// (#3651). This is the userspace.Manager override of the embedded bpfShim
// method, and it is the path the operator zone-counter clear resolves to via
// the LegacyDataPlaneAdapter delegation.
//
// Clearing requires TWO actions, exactly mirroring ClearNATRuleCounters:
//
//  1. bpfShim.ClearZoneCounters() drops the Go-side zone-counter offset map
//     (and the legacy dense BPF array, when present) that ReadZoneCounters
//     keys -- the only source of per-zone values today.
//  2. clearHelperZoneCountersLocked() sends the clear_zone_counters IPC so the
//     Rust helper's cumulative ZoneCounterStore is reset.
//
// Step 2 is the load-bearing half. The helper reports cumulative totals on
// every 1/s status poll, and syncBPFCountersLocked REPLACES the offset map from
// that snapshot (ReplaceZoneCounterOffsets, #6843). Without resetting the helper
// store, the next poll would restore the cumulative total and the cleared value
// would snap back within <=1s.
//
// After the IPC clear the zone reads as NOT POPULATED, not as zero. The helper's
// snapshot is sparse and omits all-zero rows (ZoneCounterStore::snapshot), so a
// just-cleared zone produces no row at all, and the Go replacement drops its
// offset — ReadZoneCounters then returns ErrCounterNotPopulated and the surfaces
// render "not available". That is a real behavioural difference from "reports
// 0": traffic after the clear repopulates the row and the counters resume from
// zero, but until then there is nothing to report rather than a zero to report.
func (m *Manager) ClearZoneCounters() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	if m.bpfShim != nil {
		if err := m.bpfShim.ClearZoneCounters(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := m.clearHelperZoneCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// clearHelperZoneCountersLocked sends the clear_zone_counters IPC to the Rust
// helper so its ZoneCounterStore resets to zero, then records the refreshed
// (zeroed) status. Mirrors clearHelperNATCountersLocked. Caller holds m.mu.
//
// With no live helper process the cached helper-reported zone counters in
// m.lastStatus are dropped directly so a clear takes effect even in the
// userspace-only / pre-start state (parity with the bpfShim offset clear).
func (m *Manager) clearHelperZoneCountersLocked() error {
	if m.proc == nil || m.proc.Process == nil {
		m.lastStatus.ZoneTrafficCounters = nil
		m.republishLastStatusLocked()
		return nil
	}

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "clear_zone_counters"}, &status); err != nil {
		return err
	}
	m.recordHelperStatusLocked(&status)
	return nil
}
