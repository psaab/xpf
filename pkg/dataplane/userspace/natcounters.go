package userspace

import (
	"errors"
)

// ClearNATRuleCounters resets the per-rule SNAT/DNAT/static-NAT translation
// hit counters (#2218). This is the userspace.Manager override of the embedded
// bpfShim method, and it is the path the operator `clear security nat
// source/destination rule` (and `clear security nat` family) resolves to via
// the LegacyDataPlaneAdapter delegation.
//
// Clearing requires TWO actions, exactly mirroring ClearPolicyCounters:
//
//  1. bpfShim.ClearNATRuleCounters() zeroes the Go-side offset map (and the
//     BPF map, when present) that ReadNATRuleCounter merges on top of the BPF
//     value.
//  2. clearHelperNATCountersLocked() sends the `clear_nat_counters` IPC so the
//     Rust helper's own NatCounterStore (cumulative-since-start) is reset.
//
// Step 2 is the load-bearing half. The helper reports cumulative totals on
// every 1/s status poll, and syncBPFCountersLocked writes them into the offset
// map ABSOLUTELY (SetNATRuleCounterOffset overwrites). Without resetting the
// helper store, the next poll would restore the cumulative total and the
// cleared value would snap back within <=1s. After the IPC clear the helper
// reports 0, so the offset stays 0.
func (m *Manager) ClearNATRuleCounters() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	if m.bpfShim != nil {
		if err := m.bpfShim.ClearNATRuleCounters(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := m.clearHelperNATCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// clearHelperNATCountersLocked sends the `clear_nat_counters` IPC to the Rust
// helper so its NatCounterStore resets to zero, then records the refreshed
// (zeroed) status. Mirrors clearHelperPolicyCountersLocked. Caller holds m.mu.
//
// With no live helper process the cached helper-reported NAT counters in
// m.lastStatus are zeroed directly so a clear takes effect even in the
// userspace-only / pre-start state (parity with the bpfShim offset clear).
func (m *Manager) clearHelperNATCountersLocked() error {
	if m.proc == nil || m.proc.Process == nil {
		// Preserve previously published status snapshots: callers retain
		// shallow copies of these slices.
		counters := append([]NATRuleCounterStatus(nil), m.lastStatus.NATRuleCounters...)
		for i := range counters {
			counters[i].Packets = 0
			counters[i].Bytes = 0
		}
		m.lastStatus.NATRuleCounters = counters
		m.republishLastStatusLocked()
		return nil
	}

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "clear_nat_counters"}, &status); err != nil {
		return err
	}
	m.recordHelperStatusLocked(&status)
	return nil
}
