package userspace

import "errors"

// DumpFIB reads the installed userspace helper FIB (#11370).
//
// This is an operator-triggered read, not a polling API: it uses the shared
// control socket once and returns the helper's current generation with the
// rows captured under the same server-state lock.
func (m *Manager) DumpFIB() (uint32, []FibRouteWire, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return 0, nil, errors.New("userspace dataplane helper not running")
	}
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type:           "fib_dump",
		SuppressStatus: true,
	})
	if err != nil {
		return 0, nil, err
	}
	return resp.FIBGeneration, resp.FIBRoutes, nil
}

// DumpFIB forwards the helper-side read through the adapter published to the
// CLI and other daemon surfaces.
func (a *LegacyDataPlaneAdapter) DumpFIB() (uint32, []FibRouteWire, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return 0, nil, err
	}
	return m.DumpFIB()
}
