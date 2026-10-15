package userspace

import "github.com/psaab/xpf/pkg/dataplane"

func (a *LegacyDataPlaneAdapter) ObsoleteRegistryAccesses() uint64 {
	if a == nil || a.manager == nil || a.manager.bpfShim == nil {
		return 0
	}
	return a.manager.bpfShim.ObsoleteRegistryAccesses()
}
func (a *LegacyDataPlaneAdapter) DetachDebt() []int {
	if a == nil || a.manager == nil || a.manager.bpfShim == nil {
		return nil
	}
	return a.manager.bpfShim.DetachDebt()
}
func (a *LegacyDataPlaneAdapter) HostDivergence() []string {
	if a == nil || a.manager == nil || a.manager.bpfShim == nil {
		return nil
	}
	return a.manager.bpfShim.HostDivergence()
}
func (a *LegacyDataPlaneAdapter) SurfaceCoverage() ([]dataplane.SurfaceCoverage, bool, bool) {
	if a == nil || a.manager == nil || a.manager.bpfShim == nil {
		return nil, false, false
	}
	return a.manager.bpfShim.SurfaceCoverage()
}
