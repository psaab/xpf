package vrrp

import "time"

// Test-only seams for #17165: these wrappers were production-unreachable
// (deadcode) and existed only for tests. Production calls the Held /
// Locked / admitAndRecord / ForOwner variants directly.

// updateConfig is the unheld convenience wrapper tests use; production
// calls updateConfigHeld (manager.go passes heldRETH for #14404).
func (vi *vrrpInstance) updateConfig(cfg Instance) {
	vi.updateConfigHeld(cfg, false)
}

// advertInterval is the RLock-taking interval accessor tests use;
// production arms timers via armAdvertTimer/advertiseIntervalMS.
func (vi *vrrpInstance) advertInterval() time.Duration {
	vi.mu.RLock()
	ms := vi.cfg.AdvertiseInterval
	vi.mu.RUnlock()
	return advertIntervalFromMS(ms)
}

// garpSendAllowed is the two-argument GARP gate tests use; production
// sendGARP passes its captured owner generation to garpSendAllowedForOwner.
func (vi *vrrpInstance) garpSendAllowed(force bool, nowNanos int64) bool {
	return vi.garpSendAllowedForOwner(force, nowNanos, vi.ownerGen.Load())
}

// recordMasterAdvert is the record-only seam tests use; production
// handlers call admitAndRecord so counter, gate and record cannot drift.
func (vi *vrrpInstance) recordMasterAdvert(pkt *VRRPPacket) {
	vi.admitAndRecord(pkt)
}

// resignIsPending reports whether a forced resignation is queued but
// not yet actuated; test-only (production reads resignPending under
// resignMu at its discard/commit sites).
func (vi *vrrpInstance) resignIsPending() bool {
	vi.resignMu.Lock()
	defer vi.resignMu.Unlock()
	return vi.resignPending
}

// count returns how many unreported-arrival adverts have been observed;
// test-only (production only calls observe via acceptArrivalIfindex).
func (d *arrivalIfindexDetector) count() uint64 { return d.occurrences.Load() }
