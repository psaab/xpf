package ra

import "log/slog"

// withdrawInterfacesForTest is the interface-scoped graceful withdraw the
// production Manager.WithdrawInterfaces used to provide (#17160: deleted —
// it had no non-test caller; daemon HA paths use Withdraw,
// ClearInterfacesWithoutGoodbye, and WithdrawOnce). It is kept here because
// the #4961 per-interface-epoch and #8597 supersession-contrast cells pin
// its exact semantics (bump only the named interfaces' epochs, claim
// graceful intent, release owned drains) against releaseDrain.
func (m *Manager) withdrawInterfacesForTest(names []string) {
	m.mu.Lock()
	// #4961: bump ONLY the per-interface epochs for the named interfaces.
	for _, name := range names {
		m.bumpIfaceEpoch(name)
		m.clearWantedLocked(name)
	}
	owned := m.claimGracefulLocked(names)
	epoch := m.epoch
	m.mu.Unlock()
	for _, o := range owned {
		if err := m.releaseDrain(o.name, o.s, epoch, nil); err != nil {
			slog.Warn("ra: interface-scoped withdraw failed",
				"interface", o.name, "err", err)
		}
	}
}
