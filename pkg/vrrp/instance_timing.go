package vrrp

import (
	"time"
)

// vrrpInstance timing: advertisement interval derivation (local vs learned),
// master-down interval, and the shared timer stop/drain helper.
// Split out of instance.go for the #8090 modularity floor. Pure move.

// initialMasterDownInterval is the master-down interval run() arms at startup.
//
// EXTRACTED so the deafness policy is checkable rather than a literal inside a
// run-loop local (#7579). It is the STARTUP half of the pair; the release half
// is masterDownAfterSyncHoldRelease below, and the two sharing
// deafMasterDownInterval is what stops one drifting from the other.
func (vi *vrrpInstance) initialMasterDownInterval() time.Duration {
	if !vi.getPreempt() {
		return deafMasterDownInterval
	}
	return vi.masterDownInterval()
}

// masterDownAfterSyncHoldRelease reports the master-down interval to arm when a
// sync-hold release did NOT promote, and whether to re-arm at all (#7579).
//
// Returns (_, false) for a node that IS preempting — including the priority-255
// address owner, for which getPreempt() is true irrespective of the no-preempt
// flag. Such a node wants the short interval and a prompt promotion, and
// re-arming it would be a failover regression.
//
// Returns (deafMasterDownInterval, true) otherwise: the release declined to
// promote, so this node stays BACKUP, and it is entering the second deafness
// window described on deafMasterDownInterval. Self-limiting — handleBackupRx
// resets to the short interval on the first advert heard.
func (vi *vrrpInstance) masterDownAfterSyncHoldRelease() (time.Duration, bool) {
	if vi.getPreempt() {
		return 0, false
	}
	return deafMasterDownInterval, true
}

// advertInterval returns the advertisement interval as a Duration.
// AdvertiseInterval is in milliseconds. The cfg field is snapshotted under
// vi.mu.RLock() — mirroring the other config accessors (masterDownInterval,
// preemptHoldDuration) — so a concurrent locked config update cannot race the
// read that go test -race would otherwise flag (#6230). The lock is released
// before the Duration math, matching the masterDownInterval idiom.
//
// Callers that ALREADY hold vi.mu (masterAdverFloor, reached from
// recordMasterAdvert under vi.mu.Lock) MUST use advertIntervalLocked instead:
// re-taking the RLock while the write lock is held would deadlock.
func (vi *vrrpInstance) advertInterval() time.Duration {
	vi.mu.RLock()
	ms := vi.cfg.AdvertiseInterval
	vi.mu.RUnlock()
	return advertIntervalFromMS(ms)
}

// advertIntervalLocked returns the advertisement interval as a Duration for
// callers that already hold vi.mu (read or write). It performs the same read as
// advertInterval WITHOUT taking the lock, for paths that run under vi.mu.Lock
// (recordMasterAdvert → masterAdverFloor); calling advertInterval there would
// deadlock on the RLock (#6230).
func (vi *vrrpInstance) advertIntervalLocked() time.Duration {
	return advertIntervalFromMS(vi.cfg.AdvertiseInterval)
}

// advertIntervalFromMS converts a configured advertise interval in
// milliseconds to the Duration that the run loop actually uses.
//
// VRRP's Max Advert Int field carries centiseconds, so the timer must use the
// same 10ms quantum as the wire. This is also the owning boundary for tolerant
// load / peer-sync values: non-positive input uses the documented 1000ms
// default, sub-quantum positive input floors safely to one quantum, and values
// above the field's 12-bit ceiling saturate instead of wrapping.
func advertIntervalFromMS(ms int) time.Duration {
	return time.Duration(normalizeAdvertIntervalMS9914(ms)) * time.Millisecond
}

func normalizeAdvertIntervalMS9914(ms int) int {
	if ms <= 0 {
		return 1000
	}
	if ms < 10 {
		return 10
	}
	maxMS := maxAdvertIntCentiseconds9039 * 10
	if ms > maxMS {
		return maxMS
	}
	return (ms / 10) * 10
}

// effectiveAdvertInterval picks the advertisement interval that drives the
// Master_Down_Interval / Skew_Time computation. Per RFC 5798 §6.1/§6.4.2 a
// BACKUP times the master out on the interval the MASTER advertises
// (Master_Adver_Interval, learned from the received advert's Max Adver Int),
// falling back to the locally-configured interval only before any advert has
// been heard (cold-start). localMS is cfg.AdvertiseInterval in milliseconds;
// learned is the last value recorded by recordMasterAdvert (0 = none yet).
func effectiveAdvertInterval(localMS int, learned time.Duration) time.Duration {
	if learned > 0 {
		return learned
	}
	// Use the same normalization as the cold-start timer and send sink, so a
	// tolerant out-of-domain local value cannot make the fallback horizon
	// disagree with the Max Advert Int value we emit.
	return advertIntervalFromMS(localMS)
}

// masterDownInterval returns the master-down timer value.
// Per RFC 5798: Master_Down_Interval = (3 * Master_Adver_Interval) + Skew_Time
// Skew_Time = ((256 - priority) * Master_Adver_Interval) / 256
//
// Master_Adver_Interval is the interval ADVERTISED BY THE CURRENT MASTER
// (learned from the received advert's Max Adver Int, §6.4.2), NOT this node's
// own configured AdvertiseInterval. Before any advert has been heard
// (masterAdverInterval == 0) the local interval is the fallback. The local
// priority is used for Skew_Time (RFC 5798 §6.1).
func (vi *vrrpInstance) masterDownInterval() time.Duration {
	vi.mu.RLock()
	localMS := vi.cfg.AdvertiseInterval
	learned := vi.masterAdverInterval
	vi.mu.RUnlock()
	advert := effectiveAdvertInterval(localMS, learned)
	skew := time.Duration(256-vi.getPriority()) * advert / 256
	return 3*advert + skew
}

// stopAndDrainTimer stops t and drains a pending fire from its channel so a
// subsequent Reset arms a clean interval. Safe on an already-stopped or
// already-drained timer.
func stopAndDrainTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// garpCount returns the configured gratuitous-ARP burst count under vi.mu.
//
// #8597 (muse-004 K20): sendGARP read vi.cfg.GARPCount with no lock while
// updateConfig writes it under vi.mu on the manager goroutine — the #5087 day-2
// path. Every other reader of a mu-guarded cfg field in this package snapshots
// under the lock (instance_preempt.go, track.go, manager.go, advertInterval
// here); the send paths were the exception.
func (vi *vrrpInstance) garpCount() int {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.cfg.GARPCount
}

// startupLogFields snapshots the two mu-guarded fields run()'s starting log
// emits, in ONE RLock.
//
// #8597: the log itself is not a forwarding decision, so the consequence of the
// unlocked read is a possibly-stale line rather than a wrong election — but
// `go test -race` does not grade races by consequence, and a snapshot that took
// the lock twice would still be able to straddle a writer and print two fields
// from different configs.
func (vi *vrrpInstance) startupLogFields() (priority int, preempt bool) {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.cfg.Priority, vi.cfg.Preempt
}

// advertiseIntervalMS returns the raw configured advertise interval in
// MILLISECONDS under vi.mu, for the one caller that needs the wire encoding
// rather than a Duration (sendAdvert's RFC 5798 centisecond field).
//
// Deliberately not advertInterval(): that applies advertIntervalFromMS, which
// substitutes the 1000 ms default for a non-positive value. The wire field must
// carry what the peer will use to derive ITS master-down interval, and folding
// the default in here would make a misconfigured instance advertise a cadence
// it is not actually sending at.
func (vi *vrrpInstance) advertiseIntervalMS() int {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.cfg.AdvertiseInterval
}
