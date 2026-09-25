package vrrp

import (
	"bytes"
	"log/slog"
	"net"
	"time"
)

// vrrpInstance advertisement receive path: recording an observed master, the
// backup and master RX handlers, and equal-priority resolution.
// Split out of instance.go for the #8090 modularity floor. Pure move.

// recordMasterAdvert records a peer's last advertised priority for the
// sync-hold preempt gate (#2082). Priority-0 (resignation) adverts are NOT
// recorded — leaving a stale lastMasterPriority is safe because post-resign
// takeover flows through the ungated masterDownTimer path, not the gated
// preemptNowCh shortcut. A nonzero source address is retained per family for
// the #10719 unknown-source detector. An unexpected priority-255 source does
// not replace an already-learned identity; a priority-255 first advert can
// seed a cold-start identity only after the detector has reported it. Called
// from handleBackupRx/handleMasterRx, which run in the run-loop goroutine; mu
// also makes its state race-clean for external readers.
func (vi *vrrpInstance) recordMasterAdvert(pkt *VRRPPacket) {
	if pkt.Priority == 0 {
		return
	}
	vi.mu.Lock()
	vi.lastMasterPriority = int(pkt.Priority)
	vi.lastMasterSeen = time.Now()
	if src4 := pkt.SrcIP.To4(); src4 != nil {
		// Priority 255 changes mastership unconditionally. Do not let an
		// unexpected owner advert replace the source against which the next
		// owner/resignation advert is checked.
		if pkt.Priority != addressOwnerPriority || !vi.lastMasterIPv4Known ||
			net.IP(vi.lastMasterIPv4[:]).Equal(src4) {
			copy(vi.lastMasterIPv4[:], src4)
			vi.lastMasterIPv4Known = true
		}
	} else if src16 := pkt.SrcIP.To16(); src16 != nil {
		if pkt.Priority != addressOwnerPriority || !vi.lastMasterIPv6Known ||
			net.IP(vi.lastMasterIPv6[:]).Equal(src16) {
			copy(vi.lastMasterIPv6[:], src16)
			vi.lastMasterIPv6Known = true
		}
	}
	// Adopt the master's advertised interval (RFC 5798 §6.1/§6.4.2
	// Master_Adver_Interval). Max Adver Int is centiseconds on the wire (10 ms
	// units); convert to a Duration. A zero/absent field is ignored so
	// masterDownInterval falls back to the local interval rather than computing
	// a zero (flapping) master-down timer from a malformed advert.
	if pkt.MaxAdvertInt > 0 {
		learned := time.Duration(pkt.MaxAdvertInt) * 10 * time.Millisecond
		// Clamp a pathologically-low learned interval up to a safe floor
		// (#4548). A BACKUP must never time its master out FASTER than its own
		// configured advertise cadence: a buggy or misconfigured peer that
		// advertises Max Adver Int=1 (10 ms) would otherwise collapse
		// masterDownInterval (and the preempt-gate staleness horizons) to
		// ~30 ms (3*10ms + skew) on a 30 ms RETH node and flap mastership on
		// ordinary jitter. The floor is the node's own configured advertise
		// interval; a SLOWER master (learned >= floor, the #4061
		// anti-premature-failover case) is adopted unchanged — only the low
		// side is clamped, so the 30 ms RETH fast-failover default is preserved
		// exactly (floor == 30 ms == learned → no change).
		if floor := vi.masterAdverFloor(); learned < floor {
			learned = floor
		}
		vi.masterAdverInterval = learned
	}
	vi.mu.Unlock()
}

// warnUnknownMasterAdvert counts and rate-limits a warning for a priority-0
// resignation or priority-255 owner advert whose source is not the last
// nonzero-priority source learned for that address family (#10719). This is
// detection only: the caller still applies RFC priority/state-machine
// behavior, and a cold-start instance has no peer identity to compare against.
func (vi *vrrpInstance) warnUnknownMasterAdvert(pkt *VRRPPacket) {
	if pkt.Priority != 0 && pkt.Priority != addressOwnerPriority {
		return
	}

	var knownMasterIP net.IP
	var known bool
	vi.mu.RLock()
	if src4 := pkt.SrcIP.To4(); src4 != nil {
		known = vi.lastMasterIPv4Known
		if known {
			var snapshot [4]byte
			copy(snapshot[:], vi.lastMasterIPv4[:])
			knownMasterIP = snapshot[:]
		}
	} else if pkt.SrcIP.To16() != nil {
		known = vi.lastMasterIPv6Known
		if known {
			var snapshot [16]byte
			copy(snapshot[:], vi.lastMasterIPv6[:])
			knownMasterIP = snapshot[:]
		}
	} else {
		vi.mu.RUnlock()
		return
	}
	vi.mu.RUnlock()

	if known && knownMasterIP.Equal(pkt.SrcIP) {
		return
	}

	total := vi.unrecognizedMasterAdverts.Add(1)
	now := time.Now().UnixNano()
	last := vi.lastUnknownMasterWarn.Load()
	if elapsed := now - last; elapsed >= 0 && elapsed < int64(10*time.Second) {
		return
	}
	if !vi.lastUnknownMasterWarn.CompareAndSwap(last, now) {
		return
	}
	slog.Warn("vrrp: priority-0/255 advert from source other than the learned master",
		"key", vi.key(), "priority", pkt.Priority, "source_ip", pkt.SrcIP,
		"known_master_ip", knownMasterIP, "total_unrecognized_master_adverts", total)
}

// masterAdverFloor is the minimum interval a learned Master_Adver_Interval may
// take (#4548). It is the node's own configured advertise interval
// (cfg.AdvertiseInterval, defaulting to 1000 ms when unset — see advertInterval)
// with an absolute minLearnedMasterAdverInterval backstop. Its sole caller,
// recordMasterAdvert, already holds vi.mu.Lock, so it reads the interval via
// advertIntervalLocked — calling the RLock-taking advertInterval here would
// self-deadlock against the held write lock (#6230).
func (vi *vrrpInstance) masterAdverFloor() time.Duration {
	floor := vi.advertIntervalLocked()
	if floor < minLearnedMasterAdverInterval {
		floor = minLearnedMasterAdverInterval
	}
	return floor
}

// handleBackupRx processes a received advertisement while in Backup state.
//
// preemptHoldTimer is the optional `preempt hold-time` countdown (#2850). A
// resigning (priority-0) master or a returning >= -priority master cancels any
// in-flight hold: the first because takeover becomes immediate, the second
// because there is no longer a lower-priority master to preempt. A persisting
// lower-priority master leaves an armed hold running (this path intentionally
// does not reset masterDownTimer on a lower advert). recordMasterAdvert still
// refreshes lastMasterSeen from every non-zero advert, which is what keeps the
// #4584 masterDownTimer liveness watchdog (armed by armPreemptHold) reading the
// held master as alive; if the adverts stop, the watchdog observes the staleness
// and takes over.
func (vi *vrrpInstance) handleBackupRx(pkt *VRRPPacket, masterDownTimer, preemptHoldTimer *time.Timer) {
	vi.warnUnknownMasterAdvert(pkt)
	vi.recordMasterAdvert(pkt)
	pri := vi.getPriority()
	if pkt.Priority == 0 {
		// Master is explicitly resigning — become Master immediately.
		// RFC 5798 says use skew timer, but with only 2 HA nodes there's
		// no contention risk, and immediate transition gives zero-delay
		// planned failover (systemctl stop on primary). A pending preempt
		// hold-time is irrelevant once the master has resigned: there is
		// no live master left to blackhole. Cancel any in-flight hold and
		// arm a one-shot bypass so the imminent 1ms masterDownTimer expiry
		// promotes immediately instead of re-arming the hold (#2850). The
		// last-seen master record is intentionally left untouched — the
		// #2082 recordMasterAdvert contract owns it.
		slog.Info("vrrp: peer resigned (priority 0), immediate takeover",
			"key", vi.key())
		vi.disarmPreemptHold(preemptHoldTimer)
		vi.mu.Lock()
		vi.skipNextPreemptHold = true
		vi.mu.Unlock()
		masterDownTimer.Reset(time.Millisecond)
		return
	}

	// If we don't preempt, or the incoming priority is >= ours, accept it:
	// reset the master-down timer and abort any pending preempt hold-time —
	// a worthy master is present, so there is nothing to preempt (#2850).
	// getPreempt() returns true for the IP address owner (priority 255)
	// irrespective of the no-preempt flag, so an owner hearing a LOWER-priority
	// advert does NOT reset the timer here — the timer expires and the owner
	// reclaims MASTER (RFC 5798 §6.1, #4116).
	// Also clear the one-shot resign bypass: it was armed by a prior
	// priority-0 resign to make the imminent 1ms masterDownTimer expiry
	// promote immediately, but a worthy master returning before that fire
	// supersedes the resign. Tying the bypass's lifetime to the same
	// condition that drains the hold prevents it leaking to a LATER
	// legitimate masterDownTimer expiry where it would wrongly skip the
	// hold once.
	if !vi.getPreempt() || int(pkt.Priority) >= pri {
		masterDownTimer.Reset(vi.masterDownInterval())
		vi.disarmPreemptHold(preemptHoldTimer)
		vi.mu.Lock()
		vi.skipNextPreemptHold = false
		vi.mu.Unlock()
	}
	// If preempt is true and incoming priority < ours, ignore — let the
	// master-down timer expire (and, if a hold is armed, let it run).
}

// handleMasterRx processes a received advertisement while in Master state.
// Per RFC 5798 §6.4.3: if priority is higher, step down. If equal,
// the node with the higher source IP stays Master (tie-breaking).
func (vi *vrrpInstance) handleMasterRx(pkt *VRRPPacket, masterDownTimer, advertTimer *time.Timer) {
	vi.warnUnknownMasterAdvert(pkt)
	vi.recordMasterAdvert(pkt)
	pri := vi.getPriority()
	if pkt.Priority == 0 {
		// Peer resigning — send immediate advert and stay Master.
		vi.sendAdvert(pri)
		advertTimer.Reset(vi.advertInterval())
		return
	}

	pktPri := int(pkt.Priority)
	if pktPri > pri {
		// Higher priority — step down unconditionally.
		vi.becomeBackup(masterDownTimer, advertTimer)
	} else if pktPri == pri && pkt.SrcIP != nil {
		// Equal priority — RFC 5798 §6.4.3 tie-break: higher source IP wins.
		// The comparison is anchored to ONE address family so both nodes
		// decide off the SAME ordering (#4376) — see resolveEqualPriorityMaster.
		vi.resolveEqualPriorityMaster(pkt, masterDownTimer, advertTimer)
	}
	// Lower priority, or equal with our IP higher: stay Master.
}

// resolveEqualPriorityMaster runs the RFC 5798 §6.4.3 MASTER-MASTER tie-break
// for an equal-priority peer advert while we are MASTER.
//
// A single instance is genuinely dual-stack: CollectRethInstances puts all of a
// unit's v4+v6 addresses on ONE instance, and sendAdvert emits BOTH a v4 advert
// (from getLocalIP, the lowest primary v4) and a v6 advert (from getLocalIPv6,
// the link-local) from two UNRELATED sources. If the tie-break keyed off
// whichever family happened to arrive, two equal-priority nodes with DISAGREEING
// v4-vs-v6 orderings (A: higher-v4/lower-LL, B: lower-v4/higher-LL) would each
// step down on the other family's advert — both go BACKUP, both masterDown
// timers expire, both re-elect: permanent no-master oscillation (#4376).
//
// Fix: anchor the tie-break to ONE family so both nodes compare the SAME pair of
// addresses. A v4-bearing instance (dual-stack or v4-only, i.e. it advertises a
// v4 VIP) decides ONLY off v4 adverts and ignores the peer's v6-family advert;
// a v6-only instance decides off the link-local v6 advert. The classifier keys
// off the configured VIP families (immutable per instance), NOT the resolved
// local address, so a transient address flush cannot flip a dual-stack instance
// to the v6 ordering and reintroduce the split.
func (vi *vrrpInstance) resolveEqualPriorityMaster(pkt *VRRPPacket, masterDownTimer, advertTimer *time.Timer) {
	peerV4 := pkt.SrcIP.To4() != nil

	var localCmp, peerCmp net.IP
	if vi.hasIPv4VIP() {
		// v4-bearing: anchor on v4. Ignore the peer's v6-family advert — the
		// peer's v4 advert drives the symmetric decision on both nodes.
		if !peerV4 {
			return
		}
		localCmp, peerCmp = vi.getLocalIP().To4(), pkt.SrcIP.To4()
	} else {
		// v6-only: anchor on the link-local v6 address.
		if peerV4 {
			return
		}
		if lip6 := vi.getLocalIPv6(); lip6 != nil {
			localCmp = lip6.To16()
		}
		peerCmp = pkt.SrcIP.To16()
	}

	if localCmp == nil {
		// Unresolved local advert source: we cannot run the tie-break and must
		// NOT treat that as "we win" (#4376 secondary defect — the old code let
		// peerHigher stay false and stay MASTER by default). Yield to the
		// actively advertising equal-priority peer. This does NOT oscillate: a
		// node that cannot determine its own source address cannot put a valid
		// advert of this family on the wire (sendPacket errors), so the peer
		// never receives a same-family advert from it and only one side steps
		// down. The address re-resolves on the advert-send path and a healthy
		// node re-elects cleanly.
		slog.Info("vrrp: equal priority tie-break, local source unresolved — stepping down",
			"key", vi.key(), "peer_ip", pkt.SrcIP, "priority", vi.getPriority())
		vi.becomeBackup(masterDownTimer, advertTimer)
		return
	}

	if bytes.Compare(peerCmp, localCmp) > 0 {
		slog.Info("vrrp: equal priority tie-break, peer IP is higher — stepping down",
			"key", vi.key(), "our_ip", localCmp, "peer_ip", pkt.SrcIP,
			"priority", vi.getPriority())
		vi.becomeBackup(masterDownTimer, advertTimer)
	}
	// Peer lower/equal: stay Master.
}
