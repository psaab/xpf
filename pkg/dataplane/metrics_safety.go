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

// ArmCoverageSnapshot returns one consistent, read-only copy of the last
// published proof and whether any proof has been published.
func (m *Manager) ArmCoverageSnapshot() (ArmCoverageReport, bool) {
	if m == nil {
		return ArmCoverageReport{}, false
	}
	m.armCoverage.mu.RLock()
	report := m.armCoverage.report
	report.Surfaces = append([]SurfaceCoverage(nil), report.Surfaces...)
	seen := m.armCoverage.seen
	m.armCoverage.mu.RUnlock()
	return report, seen
}
