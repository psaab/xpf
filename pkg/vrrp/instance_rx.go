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

// maxLearnedMasterAdverInterval caps a learned Master_Adver_Interval
// (#14706). MaxAdvertInt is masked to 12 bits on the wire (4095 cs =
// 40.95 s); without a ceiling a rejected advert could inflate the
// master-down / preempt staleness horizon to ~122 s. The ceiling is the
// largest interval advertiseIntervalMS can emit: the advertise-interval
// normalizer saturates at the 12-bit wire ceiling, i.e. 40950 ms.
const maxLearnedMasterAdverInterval = 40950 * time.Millisecond

// advertSourceFamily reports whether pkt carries a usable source of the
// given family and returns that source. A 4-byte source is IPv4 even
// though To16 would also succeed, mirroring warnUnknownMasterAdvert.
func advertSourceFamily(pkt *VRRPPacket, ipv4 bool) (net.IP, bool) {
	if ipv4 {
		if src4 := pkt.SrcIP.To4(); src4 != nil {
			return src4, true
		}
		return nil, false
	}
	if pkt.SrcIP.To4() != nil {
		return nil, false
	}
	if src16 := pkt.SrcIP.To16(); src16 != nil {
		return src16, true
	}
	return nil, false
}

// sameAdvertSource reports whether pkt's source equals the learned
// master source for its own family. A packet with no usable source is
// never the same source.
func (vi *vrrpInstance) sameAdvertSource(pkt *VRRPPacket) bool {
	// Caller holds vi.mu.
	if src4, ok := advertSourceFamily(pkt, true); ok {
		return vi.lastMasterIPv4Known && net.IP(vi.lastMasterIPv4[:]).Equal(src4)
	}
	if src16, ok := advertSourceFamily(pkt, false); ok {
		return vi.lastMasterIPv6Known && net.IP(vi.lastMasterIPv6[:]).Equal(src16)
	}
	return false
}

// learnMasterSourceLocked records pkt's source for its family, preserving
// the #10719 priority-255 carve-out: an unexpected owner advert does not
// replace an already-learned identity while that identity is fresh. When
// the retained record is stale, however, admitAndRecord has accepted the
// advert as the new master (#16018 stale-owner handover): refresh the
// learned source too, or lastMasterSeen becomes fresh while still naming
// the dead owner and the gate drops the new owner's own 0/255 adverts.
// staleBefore is the single staleness verdict from the same lock hold.
// Caller holds vi.mu and has just stamped lastMasterSeen = now.
func (vi *vrrpInstance) learnMasterSourceLocked(pkt *VRRPPacket, staleBefore bool) {
	// Caller holds vi.mu.
	if src4, ok := advertSourceFamily(pkt, true); ok {
		if pkt.Priority != addressOwnerPriority || staleBefore || !vi.lastMasterIPv4Known ||
			net.IP(vi.lastMasterIPv4[:]).Equal(src4) {
			copy(vi.lastMasterIPv4[:], src4)
			vi.lastMasterIPv4Known = true
		}
		return
	}
	if src16, ok := advertSourceFamily(pkt, false); ok {
		if pkt.Priority != addressOwnerPriority || staleBefore || !vi.lastMasterIPv6Known ||
			net.IP(vi.lastMasterIPv6[:]).Equal(src16) {
			copy(vi.lastMasterIPv6[:], src16)
			vi.lastMasterIPv6Known = true
		}
	}
}

// observedMasterStaleLocked reports whether the retained master record
// is stale under the interval learned from that same master. Caller
// holds vi.mu; the effective priority is recomputed from cfg/tracking
// fields (never via an RLock-taking accessor) mirroring
// shouldPreemptObservedMaster.
func (vi *vrrpInstance) observedMasterStaleLocked(now time.Time) bool {
	if vi.lastMasterSeen.IsZero() {
		return true
	}
	effective := vi.cfg.Priority
	if effective != 0 && effective != addressOwnerPriority && vi.trackDown && vi.cfg.TrackInterface != "" {
		effective -= vi.cfg.TrackPriorityCost
		if effective < 1 {
			effective = 1
		} else if effective > 254 {
			effective = 254
		}
	}
	advert := effectiveAdvertInterval(vi.cfg.AdvertiseInterval, vi.masterAdverInterval)
	skew := time.Duration(256-effective) * advert / 256
	return now.Sub(vi.lastMasterSeen) > 3*advert+skew
}

// admitAndRecord decides, under a single vi.mu hold, both halves of the
// #16018 / #14706 contract for one received advert and applies the record
// half before releasing the lock:
//
//   - drop (#16018): a priority-0/255 advert from a source other than the
//     learned master for its family while that record is still fresh.
//     The caller returns without any timer/state effect. Unknown-source
//     adverts are counted/reported (#10719) whether dropped or applied;
//     cold-start and stale records apply and are counted exactly as the
//     detector always did.
//   - record (#14706): only an accepted nonzero-priority advert may
//     overwrite the retained record — no retained master, a same-source
//     advert (including that master's own demotion), a priority >= the
//     retained master's, a priority-255 advert (subject to the #10719
//     source carve-out below), or any advert once the retained record is
//     stale. A rejected lower-priority advert therefore cannot lower the
//     preempt bar, refresh a bogus master's liveness, prime the detector,
//     or inflate the learned interval. Priority-0 adverts are never
//     recorded: post-resign takeover flows through the ungated
//     masterDownTimer path, not the gated preemptNowCh shortcut (#2082).
//
// The staleness verdict is computed ONCE from the record as it stands at
// admission and carried through the record update. Splitting the two
// (gate under one lock, record under a later one) let an interleaved
// in-place update — e.g. a same-source advert refreshing
// lastMasterPriority/lastMasterSeen, or an accepted advert inflating
// masterAdverInterval — flip the horizon between the drop decision and
// the acceptance check, so the two halves could disagree about whether
// the record was stale. When a stale record accepts a new owner's
// advert, the learned source hands over with it (#16018 fold): refreshing
// freshness alone would leave the gate comparing the new owner against
// the dead one. Caller must NOT hold vi.mu.
func (vi *vrrpInstance) admitAndRecord(pkt *VRRPPacket) (drop bool) {
	isZero255 := pkt.Priority == 0 || pkt.Priority == addressOwnerPriority
	// Source classification needs no lock (packet is immutable here).
	var src net.IP
	var isV4 bool
	if isZero255 {
		var ok bool
		if src, ok = advertSourceFamily(pkt, true); ok {
			isV4 = true
		} else if src, ok = advertSourceFamily(pkt, false); !ok {
			// No usable source: never counted, never dropped, never recorded.
			return false
		}
	}

	vi.mu.Lock()
	now := time.Now()
	stale := vi.observedMasterStaleLocked(now)

	var known, mismatch bool
	var knownMasterIP net.IP
	if isZero255 {
		if isV4 {
			known = vi.lastMasterIPv4Known
			if known {
				var snapshot [4]byte
				copy(snapshot[:], vi.lastMasterIPv4[:])
				knownMasterIP = snapshot[:]
				mismatch = !knownMasterIP.Equal(src)
			}
		} else {
			known = vi.lastMasterIPv6Known
			if known {
				var snapshot [16]byte
				copy(snapshot[:], vi.lastMasterIPv6[:])
				knownMasterIP = snapshot[:]
				mismatch = !knownMasterIP.Equal(src)
			}
		}
		drop = known && mismatch && !stale
	}

	if !drop && pkt.Priority != 0 {
		accepted := vi.lastMasterSeen.IsZero() ||
			int(pkt.Priority) >= vi.lastMasterPriority ||
			pkt.Priority == addressOwnerPriority ||
			vi.sameAdvertSource(pkt) ||
			stale
		if accepted {
			vi.lastMasterPriority = int(pkt.Priority)
			vi.lastMasterSeen = now
			vi.learnMasterSourceLocked(pkt, stale)
			// Adopt the accepted master's advertised interval (RFC 5798
			// §6.1/§6.4.2 Master_Adver_Interval). Max Adver Int is
			// centiseconds on the wire (10 ms units); convert to a
			// Duration. A zero/absent field is ignored so
			// masterDownInterval falls back to the local interval rather
			// than computing a zero (flapping) master-down timer.
			if pkt.MaxAdvertInt > 0 {
				learned := time.Duration(pkt.MaxAdvertInt&0x0FFF) * 10 * time.Millisecond
				// Clamp a pathologically-low learned interval up to a safe
				// floor (#4548) and cap it at the largest emittable interval
				// (#14706): a BACKUP must never time its master out FASTER
				// than its own configured advertise cadence (a peer
				// advertising Max Adver Int=1 would otherwise collapse the
				// horizon to ~30 ms and flap on jitter). The floor is the
				// node's own configured advertise interval; a SLOWER master
				// is adopted unchanged — only the low side is clamped, so
				// the 30 ms RETH fast-failover default is preserved exactly
				// (floor == 30 ms == learned → no change).
				if floor := vi.masterAdverFloor(); learned < floor {
					learned = floor
				}
				if learned > maxLearnedMasterAdverInterval {
					learned = maxLearnedMasterAdverInterval
				}
				vi.masterAdverInterval = learned
			}
		}
	}
	vi.mu.Unlock()

	if isZero255 && (!known || mismatch) {
		// #10719 detector: counted whether the #16018 gate dropped the
		// advert or it applied (cold start / stale).
		total := vi.unrecognizedMasterAdverts.Add(1)
		warnNow := time.Now().UnixNano()
		last := vi.lastUnknownMasterWarn.Load()
		if elapsed := warnNow - last; elapsed < 0 || elapsed >= int64(10*time.Second) {
			if vi.lastUnknownMasterWarn.CompareAndSwap(last, warnNow) {
				slog.Warn("vrrp: priority-0/255 advert from source other than the learned master",
					"key", vi.key(), "priority", pkt.Priority, "source_ip", pkt.SrcIP,
					"known_master_ip", knownMasterIP, "total_unrecognized_master_adverts", total,
					"dropped", drop)
			}
		}
	}
	return drop
}

// recordMasterAdvert is the record-only seam for tests and direct callers
// that have no drop decision to make (nonzero-priority adverts, or an
// advert the handler has already admitted). It applies the same atomic
// admission+record as admitAndRecord; priority-0 adverts are not recorded.
func (vi *vrrpInstance) recordMasterAdvert(pkt *VRRPPacket) {
	vi.admitAndRecord(pkt)
}

// warnUnknownMasterAdvert retains the #10719 detection entry point for
// tests that only need counting/warning; production handlers use
// admitAndRecord so the counter, the gate, and the record cannot drift.
func (vi *vrrpInstance) warnUnknownMasterAdvert(pkt *VRRPPacket) {
	vi.admitAndRecord(pkt)
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
// does not reset masterDownTimer on a lower advert). recordMasterAdvert
// refreshes lastMasterSeen only from an accepted advert (#14706), which is
// what keeps the #4584 masterDownTimer liveness watchdog (armed by
// armPreemptHold) reading the held master as alive; if the accepted
// adverts stop, the watchdog observes the staleness and takes over.
func (vi *vrrpInstance) handleBackupRx(pkt *VRRPPacket, masterDownTimer, preemptHoldTimer *time.Timer) {
	if vi.admitAndRecord(pkt) {
		// #16018: forged resignation/owner claim from a non-master source
		// while the learned master is fresh — dropped atomically with the
		// admission decision; no timer/state effect.
		return
	}
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
		// 1ms one-shot arm, not cfg-derived; note the interval from
		// THIS lock hold (cfg as of the arm) rather than a
		// post-Reset re-read. Priority is not noted (#15927): this
		// arm puts nothing on the wire.
		masterDownTimer.Reset(time.Millisecond)
		vi.armIntervalAppliedLocked()
		vi.mu.Unlock()
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
		vi.armMasterDownTimer(masterDownTimer)
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
	if vi.admitAndRecord(pkt) {
		// #16018: forged priority-0/255 from a non-master source while
		// the learned master is fresh — do not demote, re-advertise, or
		// reaffirm on its behalf.
		return
	}
	pri := vi.getPriority()
	if pkt.Priority == 0 {
		// Peer resigning — send immediate advert and stay Master.
		seq := vi.sendSeqNow()
		vi.sendAdvert(pri)
		vi.noteAdvertPrioritySeq(seq, pri)
		vi.armAdvertTimer(advertTimer)
		return
	}

	pktPri := int(pkt.Priority)
	if pktPri > pri {
		// Higher priority — step down unconditionally.
		vi.becomeBackup(masterDownTimer, advertTimer)
		return
	}
	if pktPri < pri {
		// This peer briefly claimed MASTER but loses to our higher priority.
		// Refresh ARP/NDP now that it has advertised its own node MAC.
		vi.reaffirmMaster()
		return
	}
	if pkt.SrcIP != nil {
		// Equal priority — RFC 5798 §6.4.3 tie-break: higher source IP wins.
		// The comparison is anchored to ONE address family so both nodes
		// decide off the SAME ordering (#4376) — see resolveEqualPriorityMaster.
		vi.resolveEqualPriorityMaster(pkt, masterDownTimer, advertTimer)
	}
	// An equal-priority packet from an unrelated address family or with no
	// source IP cannot establish that this node won the tie-break.
}

// reaffirmMaster refreshes neighbor mappings after a losing peer briefly
// claimed MASTER and announced its per-node MAC. VRRP advertisements refresh
// bridge forwarding state, not host ARP/NDP caches, so the stable winner must
// announce its VIPs without a state transition.
func (vi *vrrpInstance) reaffirmMaster() {
	if vi.suppressGARP.Load() {
		return
	}
	now := time.Now().UnixNano()
	for {
		last := vi.lastMasterReaffirmTime.Load()
		if garpDampened(last, now) {
			return
		}
		if vi.lastMasterReaffirmTime.CompareAndSwap(last, now) {
			break
		}
	}

	vi.vipMu.Lock()
	epoch := vi.garpEpoch.Add(1)
	vi.vipMu.Unlock()
	go func() {
		// A later winner refresh supersedes this one, and a demotion must
		// not emit an asynchronous burst after ownership has moved away.
		if vi.getState() != StateMaster || vi.garpEpoch.Load() != epoch {
			return
		}
		vi.sendGARP(true)
	}()
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
		return
	}
	// We win the tie-break; repair any neighbor cache changed by the claimant.
	vi.reaffirmMaster()
}
