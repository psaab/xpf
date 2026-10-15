package dataplane

import "sort"

// DetachDebt returns the current fail-closed census without clearing it.
func (m *Manager) DetachDebt() []int {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	out := make([]int, 0, len(m.detachDebt))
	for ifindex := range m.detachDebt {
		out = append(out, ifindex)
	}
	m.mu.Unlock()
	sort.Ints(out)
	return out
}

// HostDivergence returns the currently retained host-mutation classes.
func (m *Manager) HostDivergence() []string {
	if m == nil {
		return nil
	}
	m.hostDivergence.mu.Lock()
	out := make([]string, 0, len(m.hostDivergence.actions))
	for action := range m.hostDivergence.actions {
		out = append(out, action)
	}
	m.hostDivergence.mu.Unlock()
	sort.Strings(out)
	return out
}

// SurfaceCoverage returns the last arm-proof surface snapshot without mutation.
func (m *Manager) SurfaceCoverage() ([]SurfaceCoverage, bool, bool) {
	report, seen := m.lastArmCoverage()
	return append([]SurfaceCoverage(nil), report.Surfaces...), report.Ran, seen
}
