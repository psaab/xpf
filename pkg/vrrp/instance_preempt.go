package vrrp

import (
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// vrrpInstance preempt policy: the desired/suppressed preempt flags, the
// observed-master preemption decision, and the preempt-hold timer arm/disarm.
// Split out of instance.go for the #8090 modularity floor. Pure move.

// suppressPreempt forces effective preempt to false while preserving the
// configured desiredPreempt value for later restore.
func (vi *vrrpInstance) suppressPreempt() {
	vi.mu.Lock()
	vi.cfg.Preempt = false
	vi.mu.Unlock()
}

// setDesiredPreempt updates the configured preempt value that should be
// restored when sync hold is released.
func (vi *vrrpInstance) setDesiredPreempt(preempt bool) {
	vi.mu.Lock()
	vi.desiredPreempt = preempt
	vi.mu.Unlock()
}

// restorePreempt sets cfg.Preempt to the configured (desired) value.
// Called when sync hold is released to re-enable preemption.
func (vi *vrrpInstance) restorePreempt() {
	vi.mu.Lock()
	vi.cfg.Preempt = vi.desiredPreempt
	vi.mu.Unlock()
}

// triggerPreemptNow signals the run loop to attempt immediate preemption.
// Non-blocking: if a signal is already pending it is silently dropped.
func (vi *vrrpInstance) triggerPreemptNow() {
	select {
	case vi.preemptNowCh <- struct{}{}:
	default:
	}
}

// getPreempt reports the EFFECTIVE preempt mode. It is the configured
// cfg.Preempt OR-ed with the address-owner override: an instance whose
// configured priority is 255 (the IP address owner) always preempts,
// irrespective of the no-preempt flag or a sync-hold suppression of
// cfg.Preempt (RFC 5798 §6.1: "a Backup MUST preempt when it is the IP address
// owner ... irrespective of the setting of this flag"). Without this override
// an owner configured with `no-preempt` that returns after a peer took over
// would reset its master-down timer on every lower-priority advert
// (handleBackupRx) and stay BACKUP forever, though it OWNS the VIP (#4116).
//
// The override keys on cfg.Priority (the configured value), not the effective
// tracked priority: an owner is track-exempt (getPriority never demotes 255),
// so the configured 255 is authoritative here. It is a no-op for every
// non-owner instance, so cluster RETH failover (weight-based priorities < 255)
// is unaffected.
func (vi *vrrpInstance) getPreempt() bool {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	return vi.cfg.Preempt || vi.cfg.Priority == addressOwnerPriority
}

// shouldPreemptObservedMaster decides whether the non-force sync-hold preempt
// shortcut (the preemptNowCh case in run) may transition this BACKUP instance
// to MASTER (#2082). It encodes RFC 5798 §6.4.2 preemption: a BACKUP preempts
// only on a STRICTLY higher priority than the currently-observed master. It
// returns true iff:
//
//   - preempt is effective — either configured, OR this instance is the IP
//     address owner (priority 255), which always preempts irrespective of the
//     no-preempt flag (RFC 5798 §6.1, #4116). A non-owner non-preempting node
//     never preempts on the shortcut, AND
//   - either no live master has been observed recently (lastMasterSeen is zero
//     or older than masterDownInterval — the cold-start / peer-down /
//     silent-master-death rescue, where becoming MASTER is correct), OR a
//     recent master was observed AND our effective priority is strictly greater
//     than its last advertised priority.
//
// Equal priority returns false (RFC 5798 §6.4.2 — an equal-priority BACKUP does
// not preempt; the address tie-break in handleMasterRx resolves a MASTER-MASTER
// collision, a different state than preemption). The ForceRGMaster path
// (force=true) is gated OUTSIDE this helper (the run-loop short-circuits it),
// so cluster-authoritative promotion is unaffected.
//
// Lock discipline (BINDING — Go's sync.RWMutex is non-reentrant): this helper
// snapshots everything it needs under ONE vi.mu.RLock(), releases, then
// computes the effective priority and the staleness horizon from the locals.
// It MUST NOT call getPriority()/getPreempt()/masterDownInterval() (each of
// which RLocks vi.mu) while holding the lock. RLock (not Lock) is used so it
// never blocks concurrent external readers such as Status().
func (vi *vrrpInstance) shouldPreemptObservedMaster() bool {
	vi.mu.RLock()
	preempt := vi.cfg.Preempt
	priority := vi.cfg.Priority
	trackDown := vi.trackDown
	trackIface := vi.cfg.TrackInterface
	trackCost := vi.cfg.TrackPriorityCost
	advertMS := vi.cfg.AdvertiseInterval
	masterAdver := vi.masterAdverInterval
	lastMasterPriority := vi.lastMasterPriority
	lastMasterSeen := vi.lastMasterSeen
	vi.mu.RUnlock()

	// The IP address owner (priority 255) always preempts, irrespective of the
	// no-preempt flag or a sync-hold suppression of cfg.Preempt (RFC 5798 §6.1,
	// #4116) — mirrors getPreempt(). This is a no-op for every non-owner
	// instance, so the cluster RETH sync-hold gate (#2082) is unchanged.
	if !preempt && priority != addressOwnerPriority {
		return false
	}

	// Effective advertised priority — replicates getPriority() (track.go)
	// from the snapshot: priority 0/255 pass through unchanged; otherwise
	// while the tracked link is down, TrackPriorityCost is subtracted and
	// clamped to [1, 254].
	effective := priority
	if priority != 0 && priority != 255 && trackDown && trackIface != "" {
		effective -= trackCost
		if effective < 1 {
			effective = 1
		} else if effective > 254 {
			effective = 254
		}
	}

	// masterDownInterval staleness horizon — replicates masterDownInterval()
	// (3*advert + skew) from the snapshot using the effective priority AND the
	// master's LEARNED advertised interval (RFC 5798 §6.1/§6.4.2), so the
	// "is the observed master still live" horizon matches the master's cadence,
	// not the local config, exactly as masterDownInterval() now does.
	advert := effectiveAdvertInterval(advertMS, masterAdver)
	skew := time.Duration(256-effective) * advert / 256
	masterDown := 3*advert + skew

	// No live master observed (cold-start) or the last advert is older than
	// the master-down horizon (silent death / peer-down) → no master to
	// respect, becoming MASTER is correct.
	if lastMasterSeen.IsZero() || time.Since(lastMasterSeen) > masterDown {
		return true
	}

	// A live master was observed — preempt only on STRICTLY higher priority.
	return effective > lastMasterPriority
}

// preemptHoldDuration returns the configured preempt hold-time as a Duration,
// or 0 when no hold-time is configured (immediate preemption — today's
// behavior). cfg.PreemptHoldTime is in seconds (Junos `preempt hold-time`).
func (vi *vrrpInstance) preemptHoldDuration() time.Duration {
	vi.mu.RLock()
	defer vi.mu.RUnlock()
	// #8642: a wrapped hold collapses to ~512ns — immediate preemption of a
	// live master, which is the behaviour #2082's priority gate exists to
	// prevent. Fallback 0 preserves the existing "no hold" meaning.
	return config.SecondsToDuration(vi.cfg.PreemptHoldTime, 0)
}

// backupConfigUpdateNeedsMasterDownReset reports whether a BACKUP
// configUpdatedCh consumption with NO armed hold must re-arm
// masterDownTimer (#15689). Two cases:
//
//   - No learned master interval (hasLearned false) and the recorded
//     change shrank the local AdvertiseInterval: masterDownInterval()
//     falls back to the local interval, so the timer armed at
//     3× the old interval is stale by up to ~12 minutes (Scenario B).
//     With a learned interval the master's cadence owns the horizon
//     and handleBackupRx resets per advert — leave the timer alone.
//   - Preemption newly warranted (shouldPreemptObservedMaster now
//     true — preempt toggled on, or priority raised above the live
//     master): re-arming evaluates the takeover on the fresh horizon
//     instead of the timer armed under the old posture. A dead master
//     also reads warranted here; re-arming to masterDownInterval() is
//     the same horizon a fresh BACKUP would use, so no regression.
func (vi *vrrpInstance) backupConfigUpdateNeedsMasterDownReset(change configChange15689, hasLearned bool) bool {
	if !hasLearned && change.valid && change.newAdvertiseMS < change.oldAdvertiseMS {
		return true
	}
	return vi.shouldPreemptObservedMaster()
}

// preemptingLiveLowerMaster reports whether the masterDownTimer expiry that is
// firing right now represents PREEMPTION of a still-live lower-priority master
// (as opposed to takeover of a dead/silent master). It returns true iff a
// non-zero-priority master advert was observed within the master-down horizon
// AND its last advertised priority is strictly below our effective priority.
//
// This is the ONLY case the preempt hold-time delays (#2850): RFC 5798 / Junos
// `preempt hold-time` defers a higher-priority node reclaiming mastership from
// a working lower-priority master until routing converges. A genuinely dead
// master (no recent advert) is NOT delayed — there is nothing forwarding to
// blackhole, so takeover stays immediate.
//
// Reuses the same lastMaster* snapshot + effective-priority + master-down
// staleness math as shouldPreemptObservedMaster (#2082); kept as a sibling so
// the two preempt paths agree on what "a live lower master" means.
func (vi *vrrpInstance) preemptingLiveLowerMaster() bool {
	vi.mu.RLock()
	priority := vi.cfg.Priority
	trackDown := vi.trackDown
	trackIface := vi.cfg.TrackInterface
	trackCost := vi.cfg.TrackPriorityCost
	advertMS := vi.cfg.AdvertiseInterval
	masterAdver := vi.masterAdverInterval
	lastMasterPriority := vi.lastMasterPriority
	lastMasterSeen := vi.lastMasterSeen
	vi.mu.RUnlock()

	effective := priority
	if priority != 0 && priority != 255 && trackDown && trackIface != "" {
		effective -= trackCost
		if effective < 1 {
			effective = 1
		} else if effective > 254 {
			effective = 254
		}
	}

	// Master-down staleness horizon from the master's LEARNED interval (RFC
	// 5798 §6.1/§6.4.2), matching masterDownInterval(); falls back to the local
	// interval before any advert is heard.
	advert := effectiveAdvertInterval(advertMS, masterAdver)
	skew := time.Duration(256-effective) * advert / 256
	masterDown := 3*advert + skew

	// No recent live master → this is a dead-master takeover, not preemption.
	if lastMasterSeen.IsZero() || time.Since(lastMasterSeen) > masterDown {
		return false
	}
	// A live master was observed — only its STRICTLY lower priority is a
	// preemption we should hold.
	return effective > lastMasterPriority
}

// heldMasterIsStale reports whether the lower-priority master that an armed
// preempt hold-time (#2850) is currently deferring to has gone SILENT — its
// last advert is older than the master-down horizon (or none was ever seen).
// It is the #4584 liveness-watchdog predicate: while the hold is armed the
// masterDownTimer is repurposed as a watchdog (armPreemptHold), and on its fire
// a stale held master means the VIP-owning master DIED mid-hold and must be
// taken over immediately (dead master → immediate takeover), whereas a
// still-live master (recent advert, lastMasterSeen fresh) keeps deferring to
// the natural hold expiry.
//
// Unlike preemptingLiveLowerMaster/shouldPreemptObservedMaster this checks ONLY
// staleness, deliberately NOT the effective>lastMasterPriority comparison: a
// track-interface demotion that drops us below a STILL-LIVE master must NOT
// trigger a watchdog takeover (that live master is still forwarding). The
// natural hold-expiry re-validation (shouldPreemptObservedMaster, #2900) owns
// the demotion case. Uses the same master-down staleness horizon (3*advert +
// skew on the master's learned interval) as the sibling preempt helpers so all
// agree on what "silent" means.
//
// Lock discipline mirrors shouldPreemptObservedMaster: snapshot under ONE
// RLock, then compute from the locals (never call an RLocking accessor while
// holding the lock).
func (vi *vrrpInstance) heldMasterIsStale() bool {
	vi.mu.RLock()
	priority := vi.cfg.Priority
	trackDown := vi.trackDown
	trackIface := vi.cfg.TrackInterface
	trackCost := vi.cfg.TrackPriorityCost
	advertMS := vi.cfg.AdvertiseInterval
	masterAdver := vi.masterAdverInterval
	lastMasterSeen := vi.lastMasterSeen
	vi.mu.RUnlock()

	effective := priority
	if priority != 0 && priority != 255 && trackDown && trackIface != "" {
		effective -= trackCost
		if effective < 1 {
			effective = 1
		} else if effective > 254 {
			effective = 254
		}
	}

	advert := effectiveAdvertInterval(advertMS, masterAdver)
	skew := time.Duration(256-effective) * advert / 256
	masterDown := 3*advert + skew

	return lastMasterSeen.IsZero() || time.Since(lastMasterSeen) > masterDown
}

// armPreemptHold (re)arms the preempt hold-time countdown (#2850) for `hold`
// and records that it is running (#2900). Called only from the run-loop
// goroutine; the preemptHoldArmed flag is mu-guarded for external readers.
//
// It ALSO (re)arms masterDownTimer for masterDownInterval as a liveness
// watchdog (#4584). Without this the masterDownTimer would sit IDLE for the
// entire hold: it already fired to reach this arming point, and handleBackupRx
// never resets it for a persisting lower-priority advert. A held (VIP-owning)
// lower-priority master that DIES mid-hold would then go undetected until the
// (possibly very long) hold-time elapsed — up to ~holdTime of VIP blackhole for
// a dead master, violating the "dead master → immediate takeover" invariant.
// stepBackup's masterDownTimer.C case treats a fire while preemptHoldArmed as
// this watchdog: a stale held master triggers immediate takeover, a still-live
// one re-arms the watchdog and defers to the natural hold expiry.
func (vi *vrrpInstance) armPreemptHold(masterDownTimer, preemptHoldTimer *time.Timer, hold time.Duration) {
	stopAndDrainTimer(preemptHoldTimer)
	preemptHoldTimer.Reset(hold)
	stopAndDrainTimer(masterDownTimer)
	masterDownTimer.Reset(vi.masterDownInterval())
	vi.mu.Lock()
	vi.preemptHoldArmed = true
	vi.preemptHoldArmedAt = time.Now()
	vi.mu.Unlock()
}

// disarmPreemptHold stops a (possibly) armed preempt hold-time countdown and
// clears the armed flag (#2900). Safe on an already-stopped timer. Called only
// from the run-loop goroutine.
func (vi *vrrpInstance) disarmPreemptHold(preemptHoldTimer *time.Timer) {
	stopAndDrainTimer(preemptHoldTimer)
	vi.mu.Lock()
	vi.preemptHoldArmed = false
	vi.preemptHoldArmedAt = time.Time{}
	vi.mu.Unlock()
}
