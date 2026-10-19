package userspace

import (
	"errors"
)

// ClearFilterCounters resets the per-term firewall filter hit counters
// (#15107, A64-03). This is the userspace.Manager override of the embedded
// bpfShim method, and it is the path the operator `clear firewall all`
// resolves to via the LegacyDataPlaneAdapter delegation.
//
// Clearing requires TWO actions, exactly mirroring ClearPolicyCounters
// (#6566) and ClearNATRuleCounters (#2218):
//
//  1. bpfShim.ClearFilterCounters() zeroes the retired-eBPF `filter_counters`
//     per-CPU array (kept for legacy parity; nothing increments it in
//     userspace mode).
//  2. clearHelperFilterCountersLocked() sends the `clear_filter_counters`
//     IPC so the Rust helper's own FilterTermCounters (and the per-colour
//     policer counters `show firewall` renders beside them) reset.
//
// Step 2 is the load-bearing half. The helper reports cumulative totals on
// every 1/s status poll and the Go surfaces read them from the mirrored
// ProcessStatus, so without resetting the helper the cleared value snaps
// back within <=1s — while the CLI has already printed "Firewall filter
// counters cleared". After the IPC clear the helper reports 0.
func (m *Manager) ClearFilterCounters() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	if m.bpfShim != nil {
		if err := m.bpfShim.ClearFilterCounters(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := m.clearHelperFilterCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// clearHelperFilterCountersLocked sends the `clear_filter_counters` IPC to
// the Rust helper so its filter term counters reset to zero, then records
// the refreshed (zeroed) status. Mirrors clearHelperPolicyCountersLocked.
// Caller holds m.mu.
//
// With no live helper process the cached helper-reported filter and policer
// counters in m.lastStatus are zeroed directly so a clear takes effect even
// in the userspace-only / pre-start state (parity with the bpfShim clear).
// Rows are retained with zeroed counts rather than dropped: unlike the
// sparse zone/flood blocks, filter term rows are published for every
// configured term, so a just-cleared term reads as an explicit 0.
func (m *Manager) clearHelperFilterCountersLocked() error {
	if m.proc == nil || m.proc.Process == nil {
		// Preserve previously published status snapshots: callers retain
		// shallow copies of these slices.
		terms := append([]FirewallFilterTermCounterStatus(nil), m.lastStatus.FilterTermCounters...)
		for i := range terms {
			terms[i].Packets = 0
			terms[i].Bytes = 0
		}
		m.lastStatus.FilterTermCounters = terms
		policers := append([]ThreeColorPolicerStatus(nil), m.lastStatus.ThreeColorPolicerCounters...)
		for i := range policers {
			policers[i].GreenPackets = 0
			policers[i].GreenBytes = 0
			policers[i].YellowPackets = 0
			policers[i].YellowBytes = 0
			policers[i].RedPackets = 0
			policers[i].RedBytes = 0
			policers[i].DropPackets = 0
			policers[i].DropBytes = 0
		}
		m.lastStatus.ThreeColorPolicerCounters = policers
		m.republishLastStatusLocked()
		return nil
	}

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "clear_filter_counters"}, &status); err != nil {
		return err
	}
	m.recordHelperStatusLocked(&status)
	return nil
}
