package cluster

import (
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (s *SessionSync) noteHelperMirrorResult(af string, warned *atomic.Bool, err error) {
	if err == nil {
		warned.Store(false)
		return
	}
	s.stats.Errors.Add(1)
	if warned.CompareAndSwap(false, true) {
		slog.Warn("cluster sync: failed to mirror synced session into dataplane helper", "af", af, "err", err)
		return
	}
	slog.Debug("cluster sync: repeated synced-session helper mirror failure", "af", af, "err", err)
}

// genGuardMapCap bounds the sender-side echo maps and the receiver-side
// stored-generation maps so a churning workload cannot grow them without
// limit. Both are evicted on delete; the cap is a safety valve for keys whose
// delete never arrives (e.g. dropped close delta). It matches the delete
// journal cap order-of-magnitude.
//
// Overflow handling (#2198 F1): when a map is at cap, a NEW key is NOT
// recorded (skip-record-on-full) and an EXISTING key is updated in place. The
// map is NEVER cleared. Clearing the whole map would drop the stored
// generation of every live key, disabling the guard cluster-wide for a churn
// window — exactly the #2170 hazard the guard exists to close: a stale delete
// could then kill a live re-established session. A skipped new key degrades to
// gen-0 (unconditional delete / unconditional install), which is always SAFE
// — gen-0 never causes a wrongful delete of a *different* live incarnation,
// it only loses the stale-delete protection for that one new key.
//
// #9719: two arms of that safety valve were permanent rather than momentary.
//   - Receiver: a tombstone never frees its entry, so churn filled the map with
//     tombstones and then skip-recorded every new key until the next bulk. A new
//     key at the cap now evicts the oldest tombstone first (genTombstoneOrder).
//   - Sender: above the cap a new key was not stamped, so its delete went out
//     with generation 0. After an overflow, a missing stamp now draws a fresh
//     generation (takeDeleteGenV4).
const genGuardMapCap = 200000

// putGenBounded records gen for key in m without ever clearing the map or
// dropping the stored generation of an existing key. An existing key is always
// updated in place; a new key is recorded only while the map is below
// genGuardMapCap. Returns true if the entry was stored. The caller holds the
// map's mutex. Generic over the two wire-key types.
func putGenBounded[K comparable](m map[K]uint64, key K, gen uint64) bool {
	if _, exists := m[key]; exists {
		m[key] = gen
		return true
	}
	if len(m) >= genGuardMapCap {
		// Map is full and this is a new key: skip-record. The key degrades to
		// gen-0 behavior, which is safe (see genGuardMapCap doc).
		return false
	}
	m[key] = gen
	return true
}

// nextInstallGen returns the next strictly-monotonic install generation.
func (s *SessionSync) nextInstallGen() uint64 {
	return s.genCounter.Add(1)
}

// fullSetSeqGuard is the receiver-side high-water mark for one FULL-SET sync
// stream (IPsec SA, or DHCP leases per family) under #5706. It records the
// last-applied (incarnation, seq) and admits only a strictly-newer pair, so a
// stale full-set delivered out of order across the redundant fabric
// receiveLoops (conn0/conn1) is dropped instead of regressing the held set.
//
// Ordering is lexicographic on (incarnation, seq): a strictly-higher
// incarnation always supersedes (a peer restart draws a fresh epoch), and
// within an incarnation the per-type seq orders the pushes. A LOWER
// incarnation is stale and refused — EXCEPT that the guard is reset() to zero
// on a peer bulk re-prime (resetRecvGen), so an OS-rebooted peer whose
// monotonic epoch restarts LOWER is re-accepted from its fresh set rather than
// stranded on the pre-reboot set (the #2198 F2 stale-RETAIN inverse, applied
// to full-set sync). The zero value is the initial/legacy state.
//
// Access is serialized by SessionSync.recvSeqMu because the two fabric
// receiveLoops can invoke admit concurrently.
type fullSetSeqGuard struct {
	incarnation uint64
	seq         uint64
}

// admit reports whether a full-set stamped (incarnation, seq) is strictly
// newer than the last-applied pair and, when it is, advances the high-water
// mark. incarnation==0 || seq==0 marks a LEGACY (pre-#5706) sender that sends
// no ordering trailer: admit-always and do NOT advance the mark, mirroring the
// config-gen gen==0 accept-always compat. The caller holds recvSeqMu.
func (g *fullSetSeqGuard) admit(incarnation, seq uint64) bool {
	if incarnation == 0 || seq == 0 {
		return true // legacy sender — no sequence, accept-always
	}
	if g.incarnation == 0 ||
		incarnation > g.incarnation ||
		(incarnation == g.incarnation && seq > g.seq) {
		g.incarnation = incarnation
		g.seq = seq
		return true
	}
	return false
}

// reset returns the guard to its zero (accept-next) state. Called from
// resetRecvGen on a peer bulk re-prime so a rebooted peer with a lower epoch is
// re-accepted. The caller holds recvSeqMu.
func (g *fullSetSeqGuard) reset() {
	g.incarnation = 0
	g.seq = 0
}

// stampInstallGenV4 assigns a fresh install generation to a v4 session being
// sent and records it (keyed by wire key) so the matching delete can echo the
// exact generation of the install it cancels (#2170 SMR fix #1). It mutates
// val.Generation in place. A re-send (sweep/bulk) of a live key intentionally
// bumps the generation: the per-key stored generation only ever climbs, so a
// journaled delete from before the re-send is strictly older and refused.
func (s *SessionSync) stampInstallGenV4(key dataplane.SessionKey, val *dataplane.SessionValue) {
	g := s.nextInstallGen()
	val.Generation = g
	// #7095: stamp the cluster-stable ingress fold on the same pass that
	// stamps the generation — one place per family, covering both the
	// incremental and the bulk send paths, which both call this immediately
	// before encoding.
	val.IngressIfaceFold = s.stampIngressIfaceFold(val.IngressIfindex, val.IngressVlanID)
	// #5274: stamp the admitting config epoch = the config-sync generation
	// (#3931) this node currently holds. A session still present in the local
	// table when it is queued has survived this node's own config-apply
	// clearSessionsForDeletedPolicies sweep, so it is admitted under the
	// current config; the receiver refuses it only once IT applies a strictly
	// newer config (lastAppliedConfigGen advances past this epoch).
	//
	// The namespace claim holds in ONE direction only. configGenCounter and the
	// receiver's lastAppliedConfigGen are the same sender→receiver namespace
	// when the SENDER is the RG0 config-sync authority — the authority mints the
	// generation and the peer records the one it applied. In the reverse
	// (non-authority → authority) direction, reachable only active/active, the
	// stamp is a value this node's configGenCounter has not advanced since it
	// last held the authority (its construction seed if it never has), while the
	// authority's high-water never advances at all, so the guard is inert:
	// fail-OPEN, no false reject. That residual is deliberate (#5274 scope-out)
	// and regression-pinned by sync_config_epoch_active_active_6284_test.go.
	//
	// #6419 closed the reverse direction as not-cheaply-fixable. Note what the
	// blocker is and is NOT. Each counter IS live in the role the obvious
	// shortcut ("non-authority stamps lastAppliedConfigGen, authority thresholds
	// on configGenCounter") wants to read it: configGenCounter advances on the
	// authority, lastAppliedConfigGen advances off it. What that asymmetry
	// establishes is only that the shortcut cannot be written role-free — each
	// counter is frozen in the OTHER role, so both the stamp site and the
	// threshold site must branch on IsLocalPrimary(0). The actual kill is that a
	// role-branched stamp is unreadable across an RG0 handover: role is not
	// learned atomically by both nodes, and telling the two namespaces apart
	// needs an authority tag that ConfigEpoch, a bare uint64 on the wire, does
	// not carry today. See docs/session-sync-architecture.md for the full
	// argument and for the tagged-epoch variant that remains open.
	val.ConfigEpoch = s.configGenCounter.Load()
	s.genSentMu.Lock()
	if s.genSentV4 == nil {
		s.genSentV4 = make(map[dataplane.SessionKey]uint64)
	}
	if !putGenBounded(s.genSentV4, key, g) {
		s.stats.GenMapOverflow.Add(1)
		// #9719: from now on a missing stamp no longer means "never sent in this
		// boot"; see takeDeleteGenV4.
		s.genSentOverflowV4 = true
	}
	// #9412: keep this frame from regressing the close class already sent for
	// the same incarnation (a mirror-sourced resend carries 0). Same lock.
	if s.closeClassSentV4 == nil {
		s.closeClassSentV4 = make(map[dataplane.SessionKey]sentCloseClass)
	}
	stampCloseClassLocked(s.closeClassSentV4, key, val.SessionID, &val.TCPCloseClass)
	s.genSentMu.Unlock()
}

func (s *SessionSync) stampInstallGenV6(key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) {
	g := s.nextInstallGen()
	val.Generation = g
	// #7095: stamp the cluster-stable ingress fold on the same pass that
	// stamps the generation — one place per family, covering both the
	// incremental and the bulk send paths, which both call this immediately
	// before encoding.
	val.IngressIfaceFold = s.stampIngressIfaceFold(val.IngressIfindex, val.IngressVlanID)
	// #5274: stamp the admitting config epoch (see stampInstallGenV4).
	val.ConfigEpoch = s.configGenCounter.Load()
	s.genSentMu.Lock()
	if s.genSentV6 == nil {
		s.genSentV6 = make(map[dataplane.SessionKeyV6]uint64)
	}
	if !putGenBounded(s.genSentV6, key, g) {
		s.stats.GenMapOverflow.Add(1)
		s.genSentOverflowV6 = true // #9719: see stampInstallGenV4.
	}
	// #9412: keep this frame from regressing the close class already sent for
	// the same incarnation (a mirror-sourced resend carries 0). Same lock.
	if s.closeClassSentV6 == nil {
		s.closeClassSentV6 = make(map[dataplane.SessionKeyV6]sentCloseClass)
	}
	stampCloseClassLocked(s.closeClassSentV6, key, val.SessionID, &val.TCPCloseClass)
	s.genSentMu.Unlock()
}

// takeDeleteGenV4 returns the generation a delete for this wire key should
// carry and evicts the sender-side stamp.
//
// #2221: the delete draws a FRESH, strictly-greater generation
// (nextInstallGen) rather than echoing the install's stamp. The stamp and the
// sendCh enqueue are not atomic and two producer goroutines (the sweep
// stamping a live re-send, the delta-drain taking the close) mutate the same
// key, so a delete can be enqueued onto sendCh BEFORE the install it cancels.
// On the wire the receiver then applies delete then install with IDENTICAL
// generations; the receiver guards only refuse a STRICTLY-older operation, so
// the late install resurrects the closed session (the #2170 residual:
// stale-RETAIN rather than stale-delete). Drawing a fresh generation that is
// strictly greater than every prior install of this key makes a delete always
// out-rank the install it cancels: the receiver's install guard refuses a
// reordered older install (incoming < the delete tombstone), while a genuinely
// newer incarnation (re-established + re-stamped by a later sweep) carries an
// even higher generation and still applies. This composes with #2170: the
// per-key generation only ever climbs, so a journaled stale delete from before
// a re-sync is still strictly older than the live entry and refused.
//
// A key never installed in this boot (no stamp recorded) returns 0 (legacy
// fallback → unconditional delete in the apply guard), which is the safe
// behavior and preserves rolling-upgrade compatibility.
//
// #9719: once the stamp map has overflowed, a missing stamp no longer implies
// that. The key may be a live session whose stamp was skipped at the cap, and 0
// would make its delete unconditional on the receiver. So after an overflow a
// missing stamp draws a fresh generation too. The receiver refuses such a
// delete only while it holds a NEWER generation for the key, which is the
// correct answer.
func (s *SessionSync) takeDeleteGenV4(key dataplane.SessionKey) uint64 {
	s.genSentMu.Lock()
	defer s.genSentMu.Unlock()
	// #9412: the incarnation is being deleted; forget its close class. Before the
	// early return, so a key with no generation stamp is still evicted.
	delete(s.closeClassSentV4, key)
	if _, ok := s.genSentV4[key]; !ok {
		if s.genSentOverflowV4 {
			// #9719: the stamp map has overflowed in this process, so this key may
			// be a LIVE session whose stamp was skipped at the cap. Sending 0 would
			// make the receiver apply the delete unconditionally. A fresh generation
			// keeps the ordering guard, and still out-ranks every install of the key.
			return s.nextInstallGen()
		}
		return 0
	}
	delete(s.genSentV4, key)
	return s.nextInstallGen()
}

func (s *SessionSync) takeDeleteGenV6(key dataplane.SessionKeyV6) uint64 {
	s.genSentMu.Lock()
	defer s.genSentMu.Unlock()
	// #9412: the incarnation is being deleted; forget its close class. Before the
	// early return, so a key with no generation stamp is still evicted.
	delete(s.closeClassSentV6, key)
	if _, ok := s.genSentV6[key]; !ok {
		if s.genSentOverflowV6 {
			return s.nextInstallGen() // #9719: see takeDeleteGenV4.
		}
		return 0
	}
	delete(s.genSentV6, key)
	return s.nextInstallGen()
}

// installGenGuardV4 implements the receiver-side install-side guard (#2170 SMR
// fix #2): refuse to overwrite a stored entry with a strictly-older-generation
// install so the per-key stored generation never regresses. Returns the
// generation to record on a successful apply (the incoming generation, or the
// preserved stored generation when the incoming one is 0). The bool reports
// whether the install should proceed.
// WHAT THESE GUARDS ARE, AND THE ONE THING THEY ARE REPEATEDLY READ AS (#9048).
//
// installGenGuardV4/V6 and deleteGenGuardV4/V6 are per-key REORDERING guards
// for ONE sender's stream (#2170). They answer "is this delta older than the
// last one I applied for this key?" and nothing else.
//
// `stored == 0` therefore means "I HAVE NO ORDERING INFORMATION FOR THIS KEY",
// not "this delta is safe". recvGenV4 is populated solely by
// recordInstalledGenV4 — prior PEER installs — so a session THIS node created
// itself has no stored generation and both guards admit anything for it. That
// reads like a fall-through defect and it is not one: with no prior peer
// install there is no ordering to violate, and refusing on gen-0 would break
// every legitimate first install and every legacy (pre-#2170) sender, which is
// exactly what the `incoming == 0` / `deleteGen == 0` arms are for.
//
// THEY ARE NOT OWNERSHIP GUARDS, and nothing here should become one. "May this
// peer touch a session this node owns and is forwarding for?" is a different
// question with different inputs (local origin + local HA state), and it is
// answered one layer down in the dataplane helper, where both facts actually
// live:
//
//   - INSTALL: SessionTable::upsert_synced_with_origin refuses to clobber a
//     local-origin entry unless synced_entry_allows_local_replace says the
//     incoming entry's owner RG is not locally forwarding-active.
//   - DELETE: handle_delete_synced refuses to tear down a local-origin entry
//     whose owner RG IS locally forwarding-active, counting
//     PEER_DELETE_REFUSED_LOCAL_OWNED (#9048). Until then only the install
//     verb had a guard, and the asymmetry was invisible because the two verbs
//     are guarded in different files at different layers.
//
// Both are inert in normal operation: the delta EMITTER is gated on
// IsPrimaryForRGFn, so exactly one node emits and the receiver's entries at
// those keys carry a peer-synced origin. They fire only when both nodes are
// primary for the same RG, which is what makes that helper counter a
// split-brain indicator rather than a tuning knob.
func (s *SessionSync) installGenGuardV4(key dataplane.SessionKey, incoming uint64) (record uint64, apply bool) {
	s.recvGenMu.Lock()
	defer s.recvGenMu.Unlock()
	stored, ok := s.recvGenV4[key]
	if ok && stored != 0 && incoming != 0 && incoming < stored {
		return 0, false
	}
	if incoming == 0 {
		// Legacy / unknown install: apply but keep the stored generation
		// (do not roll it back to 0).
		return stored, true
	}
	return incoming, true
}

func (s *SessionSync) installGenGuardV6(key dataplane.SessionKeyV6, incoming uint64) (record uint64, apply bool) {
	s.recvGenMu.Lock()
	defer s.recvGenMu.Unlock()
	stored, ok := s.recvGenV6[key]
	if ok && stored != 0 && incoming != 0 && incoming < stored {
		return 0, false
	}
	if incoming == 0 {
		return stored, true
	}
	return incoming, true
}

// recordInstalledGenV4 stores the per-key generation after a successful
// install-apply, bounded by genGuardMapCap.
func (s *SessionSync) recordInstalledGenV4(key dataplane.SessionKey, gen uint64) {
	if gen == 0 {
		return
	}
	s.recvGenMu.Lock()
	if s.recvGenV4 == nil {
		s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
	}
	// #9719: a new key at the cap first evicts the oldest tombstone, so churn
	// cannot starve live keys of their ordering guard.
	stored, evicted := putGenEvictingTombstones(s.recvGenV4, &s.recvTombV4, key, gen)
	if evicted {
		s.stats.GenTombstonesEvicted.Add(1)
	}
	if stored {
		// The key is live again; a tombstone it held is superseded by this
		// generation, which the install guard already required to be >= it.
		s.recvTombV4.forget(key)
	} else {
		s.stats.GenMapOverflow.Add(1)
	}
	s.recvGenMu.Unlock()
}

func (s *SessionSync) recordInstalledGenV6(key dataplane.SessionKeyV6, gen uint64) {
	if gen == 0 {
		return
	}
	s.recvGenMu.Lock()
	if s.recvGenV6 == nil {
		s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
	}
	// #9719: see the v4 twin.
	stored, evicted := putGenEvictingTombstones(s.recvGenV6, &s.recvTombV6, key, gen)
	if evicted {
		s.stats.GenTombstonesEvicted.Add(1)
	}
	if stored {
		s.recvTombV6.forget(key)
	} else {
		s.stats.GenMapOverflow.Add(1)
	}
	s.recvGenMu.Unlock()
}

// deleteGenGuardV4 implements the receiver-side delete guard (#2170): a delete
// is refused only when both the stored and delete generations are non-zero and
// the delete generation is STRICTLY older than the stored entry's. Equality
// applies (it is the delete of the very session installed); gen==0 on either
// side falls back to today's unconditional delete (rolling-upgrade safe). The
// bool reports whether the delete should proceed.
//
// #2221: on an applied delete the stored generation is NOT evicted — it is
// upgraded to the (strictly-greater, see takeDeleteGenV4) delete generation as
// a TOMBSTONE. A subsequent reordered install that carries the OLDER generation
// of the very session this delete cancelled is then refused by installGenGuard*
// (incoming < the tombstone), so the standby converges to the master's state
// (session GONE) regardless of install/delete arrival order. A genuinely newer
// incarnation re-established and re-stamped by a later sweep carries a higher
// generation and still applies (incoming > tombstone). A gen-0 (legacy) delete
// evicts (no tombstone to record) — the legacy unconditional path is unchanged.
// Tombstones are bounded by genGuardMapCap and cleared by the bulk barrier
// (resetRecvGen), so a churning workload cannot grow the map without limit and
// a cross-boot generation regression is handled at BulkStart.
//
// #9719: a tombstone never frees its entry, so between bulks the map used to
// fill with tombstones of closed sessions and then skip-record every NEW key.
// The oldest tombstone is now evicted to make room (genTombstoneOrder); a live
// entry never is.
func (s *SessionSync) deleteGenGuardV4(key dataplane.SessionKey, deleteGen uint64) bool {
	s.recvGenMu.Lock()
	defer s.recvGenMu.Unlock()
	stored := s.recvGenV4[key]
	if stored != 0 && deleteGen != 0 && deleteGen < stored {
		return false
	}
	if deleteGen != 0 {
		// Record the delete generation as a tombstone so a reordered older
		// install of the cancelled session is refused. Bounded; never clears.
		if s.recvGenV4 == nil {
			s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
		}
		stored, evicted := putGenEvictingTombstones(s.recvGenV4, &s.recvTombV4, key, deleteGen)
		if evicted {
			s.stats.GenTombstonesEvicted.Add(1)
		}
		if stored {
			// #9719: the newest tombstone, and so the last to be evicted.
			s.recvTombV4.mark(key)
		} else {
			s.stats.GenMapOverflow.Add(1)
		}
	} else {
		delete(s.recvGenV4, key)
		s.recvTombV4.forget(key)
	}
	return true
}

func (s *SessionSync) deleteGenGuardV6(key dataplane.SessionKeyV6, deleteGen uint64) bool {
	s.recvGenMu.Lock()
	defer s.recvGenMu.Unlock()
	stored := s.recvGenV6[key]
	if stored != 0 && deleteGen != 0 && deleteGen < stored {
		return false
	}
	if deleteGen != 0 {
		if s.recvGenV6 == nil {
			s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
		}
		stored, evicted := putGenEvictingTombstones(s.recvGenV6, &s.recvTombV6, key, deleteGen)
		if evicted {
			s.stats.GenTombstonesEvicted.Add(1)
		}
		if stored {
			s.recvTombV6.mark(key) // #9719: see the v4 twin.
		} else {
			s.stats.GenMapOverflow.Add(1)
		}
	} else {
		delete(s.recvGenV6, key)
		s.recvTombV6.forget(key)
	}
	return true
}

// resetRecvGen clears the receiver-side stored-generation maps. It is called
// when the peer begins a fresh bulk transfer (#2198 F2): a reconnecting peer
// may have REBOOTED, which legitimately restarts its sender genCounter (it is
// seeded from CLOCK_MONOTONIC nanos, which resets at OS boot). Its bulk
// re-prime then carries generations that may be LOWER than the generations we
// stored from the peer's previous boot. Without this reset the install guard
// would refuse the bulk re-prime as "stale" (stored > incoming) — the inverse
// of the #2170 bug (stale-RETAIN) — and the cold-start re-prime would silently
// fail to land.
//
// This is safe against opening a stale-delete window: deletes are only acted
// on after the bulk completes (reconcileStaleSessions runs at BulkEnd), and
// the bulk re-prime re-establishes the live set (re-recording each key's fresh
// generation) before any such delete is processed. A delete that arrives
// mid-bulk for a key the bulk has not yet re-recorded falls back to gen-0
// (stored==0 after reset) → unconditional, which is the legacy-safe behavior.
func (s *SessionSync) resetRecvGen() {
	// #9715: under applyMu, so an install on the other receive loop that passed
	// its guard before this reset cannot record its pre-reboot generation after
	// it. That stale high-water would refuse the rebooted peer's lower re-prime
	// generations: the stale-RETAIN this reset exists to prevent.
	s.applyMu.Lock()
	s.recvGenMu.Lock()
	s.recvGenV4 = make(map[dataplane.SessionKey]uint64)
	s.recvGenV6 = make(map[dataplane.SessionKeyV6]uint64)
	s.recvTombV4.reset() // #9719: the tombstone order describes the maps just cleared.
	s.recvTombV6.reset()
	s.recvGenMu.Unlock()
	s.applyMu.Unlock()
	// #3931: also reset the last-applied config generation. A reconnecting
	// peer may have REBOOTED, restarting its monotonic configGenCounter at a
	// value LOWER than the generation we stored from its previous boot.
	// Without this reset the config guard (admitConfigGen) would refuse the
	// reconnect config re-push as stale (last > incoming) — the same
	// stale-RETAIN inverse the session reset closes (#2198 F2). Resetting to
	// 0 makes the next config apply unconditionally; it is always the peer's
	// CURRENT config (pushConfigToPeer sends ShowActive), so the newest
	// content still wins.
	//
	// #5084: the three clears below are ONE transaction under configGenMu, and
	// every advance of these marks takes the same lock. Without it a clear could
	// land between a concurrent advance's load and its store and be LOST, so a
	// pre-reboot generation survived the reset and refused every one of the
	// reconnected peer's lower current generations — permanently, since the
	// marks are monotone-max. The clears run on a receive-loop goroutine and the
	// applied-mark advance runs on configApplyLoop, so they genuinely race.
	s.configGenMu.Lock()
	s.lastAppliedConfigGen.Store(0)
	// #6284: drop the apply-in-progress fence alongside the high-water so a
	// concurrent bulk re-prime restores the accept-everything posture the reset
	// intends. A re-prime admits the rebooted peer's lower-generation set; a
	// stale fence from an apply that raced the reset would otherwise keep
	// refusing it. configApplyLoop may re-raise the fence on its NEXT apply,
	// which is benign — the re-primed installs are re-sent by the next sweep.
	// (The pre-#5084 wording called that "the same benign race the high-water
	// reset already has with a concurrent advance". The fence half is benign;
	// the high-water half is not, which is what configGenMu now closes.)
	s.applyingConfigGen.Store(0)
	// #5563: reset the received-config high-water alongside the applied mark so
	// the manual-failover readiness gate's applied<=received invariant holds
	// across the reset window. The reconnect re-push then re-establishes both
	// (received on receive, applied on successful apply).
	s.lastRecvConfigGen.Store(0)
	s.configGenMu.Unlock()
	// #5706: reset the full-set (IPsec/DHCP) ordering high-water marks for the
	// same reason. A reconnecting peer that OS-rebooted restarts its monotonic
	// incarnation LOWER; without this reset the guard would refuse its fresh
	// full-set re-push (nudged on reconnect) as stale and strand the standby on
	// the pre-reboot set. Resetting to the zero state admits the next push
	// unconditionally — it is always the peer's CURRENT set.
	s.recvSeqMu.Lock()
	s.ipsecRecvSeq.reset()
	s.dhcpV4RecvSeq.reset()
	s.dhcpV6RecvSeq.reset()
	s.recvSeqMu.Unlock()
}

// Apply atomicity (#2198 F3, corrected by #9715).
//
// The helpers (installGenGuard*, recordInstalledGen*, deleteGenGuard*) each take
// recvGenMu separately. The apply as a whole runs as ONE critical section under
// applyMu: an install from its guard, through the dataplane write, to its record
// or rollback; a delete from its guard through the dataplane delete.
//
// F3 used to argue no such lock was needed, because the receive apply path is
// single-threaded: the peer sends over one active stream. That holds within one
// receiveLoop, but every installed fabric connection runs its own loop. When the
// stream moves (a fabric flap, or the #9508 preferred-fabric switch), the old
// loop can still be applying frames it already read while the new loop applies
// newer frames for the same key. The #9715 cells drive both interleavings the
// old sequence allowed:
//   - an older install parked in its dataplane write recorded its generation
//     over a newer install's;
//   - an admitted delete removed a newer install that landed during its write.
//
// applyMu does hold across dataplane I/O, which F3 declined to do with
// recvGenMu. The cost F3 named, serializing unrelated keys, is paid only while
// two loops apply at once: in steady state one loop applies and the lock is
// uncontended.
// configEpochStale reports whether a synced session admitted under config
// epoch `epoch` must be REFUSED because this node has since applied a STRICTLY
// newer config (#5274). The peer stamps the session with the #3931 config-sync
// generation it held when it queued the session (stampInstallGen*);
// lastAppliedConfigGen is the highest config generation THIS node has applied
// from that same peer, so the two are directly comparable in one
// sender→receiver namespace. A newer config the peer committed AND this node
// applied may DENY the session, and this node's clearSessionsForDeletedPolicies
// sweep for that config already ran — so installing the delayed session would
// revive a stale PERMIT the config invalidated. epoch==0 (a legacy/pre-#5274
// peer, or a local-origin entry) disables the check, unconditionally admitting
// as before (rolling-upgrade safe). The check is authoritative here in the Go
// cluster layer: the #3931 namespace lives entirely in SessionSync, and the
// receiver refuses BEFORE forwarding the install to the userspace helper.
//
// #6284 item 2: the refusal threshold is max(applyingConfigGen, lastApplied-
// ConfigGen), not the high-water alone. configApplyLoop raises the fence
// (applyingConfigGen) to the generation it is applying BEFORE running the
// clearSessionsForDeletedPolicies sweep and lowers it only AFTER the high-water
// advances (success) or the apply fails, so during that whole window an install
// stamped with an older epoch is refused against the applying generation
// instead of admitted against the not-yet-advanced high-water. The fence is
// read FIRST and folded with a max: on the success-release ordering (high-water
// stored, THEN fence cleared) this guarantees a reader that observes fence==0
// has already observed the advanced high-water, so the effective threshold
// never dips — closing the sub-µs sweep-vs-advance stale-permit race.
func (s *SessionSync) configEpochStale(epoch uint64) bool {
	if epoch == 0 {
		return false
	}
	barrier := s.applyingConfigGen.Load()
	if applied := s.lastAppliedConfigGen.Load(); applied > barrier {
		barrier = applied
	}
	return epoch < barrier
}

// rollBackStaleConfigInstallV4 removes a synced session whose config epoch went
// STALE between the pre-install check and the dataplane write (#6368).
//
// configEpochStale and PutClusterSynced* are not one critical section: the
// check reads max(applyingConfigGen, lastAppliedConfigGen) and the Put lands
// several statements later, on the receiveLoop goroutine, while configApplyLoop
// runs on its own. If the receiveLoop is descheduled across that gap — a GC
// pause or a loaded box is enough, and the window is the whole of
// OnConfigReceived, which compiles and promotes a config and runs
// clearSessionsForDeletedPolicies inside it, not "a few instructions" — the
// install can pass the check against the OLD threshold and land its Put AFTER
// the sweep that was supposed to invalidate it. The result is a stale PERMIT
// that no later sweep re-examines: it survives until the next config apply,
// which on a quiet box may be never, and a session installed on the standby is
// exactly what that node forwards on after a failover.
//
// The fix is act-then-verify rather than a lock. Serializing the check with the
// Put against configApplyLoop would mean holding one lock across dataplane I/O
// and across a whole config apply. applyMu (#9715) does not do that: it orders
// the receive loops against each other, not against configApplyLoop. Re-reading the threshold after
// the Put costs one atomic load per install and detects precisely the case the
// pre-check could not see; the rollback then applies the SAME verdict the guard
// would have reached, just later. That introduces no new semantic:
// configEpochStale never consults policy, it refuses on epoch alone, so a late
// refusal is the guard's own decision rather than a fresh judgement about this
// session.
//
// The generation is deliberately NOT recorded for a rolled-back install: the
// per-key recv-gen high-water must stay where it was so the peer's next
// re-sync of this key is admitted rather than refused as stale.
func (s *SessionSync) rollBackStaleConfigInstallV4(key dataplane.SessionKey, epoch uint64) {
	s.stats.SessionsStaleConfigIgnored.Add(1)
	if err := s.sessions.DeleteWithCompanionsV4(key, dataplane.DeleteReasonClusterStale); err != nil {
		slog.Warn("cluster sync: could not roll back a v4 install whose config epoch went stale during the dataplane write — a stale permit may survive until the next config apply",
			"session_config_epoch", epoch, "applied_config_gen", s.lastAppliedConfigGen.Load(), "err", err)
		return
	}
	slog.Debug("cluster sync: rolled back a v4 install whose config epoch went stale during the dataplane write (#6368)",
		"session_config_epoch", epoch, "applied_config_gen", s.lastAppliedConfigGen.Load())
}

// rollBackStaleConfigInstallV6 is the v6 twin of
// rollBackStaleConfigInstallV4; see there for why the check is re-run after
// the write instead of being serialized with it.
func (s *SessionSync) rollBackStaleConfigInstallV6(key dataplane.SessionKeyV6, epoch uint64) {
	s.stats.SessionsStaleConfigIgnored.Add(1)
	if err := s.sessions.DeleteWithCompanionsV6(key, dataplane.DeleteReasonClusterStale); err != nil {
		slog.Warn("cluster sync: could not roll back a v6 install whose config epoch went stale during the dataplane write — a stale permit may survive until the next config apply",
			"session_config_epoch", epoch, "applied_config_gen", s.lastAppliedConfigGen.Load(), "err", err)
		return
	}
	slog.Debug("cluster sync: rolled back a v6 install whose config epoch went stale during the dataplane write (#6368)",
		"session_config_epoch", epoch, "applied_config_gen", s.lastAppliedConfigGen.Load())
}

func (s *SessionSync) installClusterSyncedV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	if s.sessions == nil {
		return
	}
	// #9715: guard, write and record are one apply across receive loops; see applyMu.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	record, apply := s.installGenGuardV4(key, val.Generation)
	if !apply {
		s.stats.InstallsStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation v4 install",
			"incoming_gen", val.Generation)
		return
	}
	if s.configEpochStale(val.ConfigEpoch) {
		s.stats.SessionsStaleConfigIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-config-epoch v4 install (peer moved to a newer config that may deny this session)",
			"session_config_epoch", val.ConfigEpoch, "applied_config_gen", s.lastAppliedConfigGen.Load())
		return
	}
	if err := s.sessions.PutClusterSyncedV4(key, val); err == nil {
		// #6368: the check above and this write are not atomic. Re-read the
		// threshold now — a config apply that raised the fence and ran its
		// sweep while this install was in flight must not leave the session
		// behind it.
		if s.configEpochStale(val.ConfigEpoch) {
			s.rollBackStaleConfigInstallV4(key, val.ConfigEpoch)
			return
		}
		s.recordInstalledGenV4(key, record)
		s.stats.SessionsInstalled.Add(1)
		s.noteHelperMirrorResult("v4", &s.sessionMirrorWarnedV4, nil)
		if val.IsReverse == 0 && s.OnForwardSessionInstalled != nil {
			s.OnForwardSessionInstalled()
		}
	} else if errors.Is(err, dataplane.ErrSyncedImportRefused) {
		// #6785: the helper REFUSED this import on semantic grounds and Go has
		// already rolled its BPF mirror row back, so there is no split truth and
		// no sick socket — do not bump Errors or fire the mirror-failure warning,
		// which would make an oversubscribed-but-healthy standby read as a flaky
		// mirror. Count it as its own debt instead: the peer still believes it
		// synced a session this node does not hold.
		s.stats.ImportsRefusedByHelper.Add(1)
		slog.Debug("cluster sync: helper refused a synced-session import; the "+
			"local mirror was rolled back and the peer holds a session this node does not",
			"af", "v4", "err", err)
	} else {
		s.noteHelperMirrorResult("v4", &s.sessionMirrorWarnedV4, err)
	}
}

func (s *SessionSync) installClusterSyncedV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	if s.sessions == nil {
		return
	}
	// #9715: see the v4 twin and applyMu.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	record, apply := s.installGenGuardV6(key, val.Generation)
	if !apply {
		s.stats.InstallsStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation v6 install",
			"incoming_gen", val.Generation)
		return
	}
	if s.configEpochStale(val.ConfigEpoch) {
		s.stats.SessionsStaleConfigIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-config-epoch v6 install (peer moved to a newer config that may deny this session)",
			"session_config_epoch", val.ConfigEpoch, "applied_config_gen", s.lastAppliedConfigGen.Load())
		return
	}
	if err := s.sessions.PutClusterSyncedV6(key, val); err == nil {
		// #6368: see the v4 twin — re-read the threshold after the write so a
		// config apply that completed its sweep during this install cannot
		// leave the session behind it.
		if s.configEpochStale(val.ConfigEpoch) {
			s.rollBackStaleConfigInstallV6(key, val.ConfigEpoch)
			return
		}
		s.recordInstalledGenV6(key, record)
		s.stats.SessionsInstalled.Add(1)
		s.noteHelperMirrorResult("v6", &s.sessionMirrorWarnedV6, nil)
		if val.IsReverse == 0 && s.OnForwardSessionInstalled != nil {
			s.OnForwardSessionInstalled()
		}
	} else if errors.Is(err, dataplane.ErrSyncedImportRefused) {
		// #6785: the helper REFUSED this import on semantic grounds and Go has
		// already rolled its BPF mirror row back, so there is no split truth and
		// no sick socket — do not bump Errors or fire the mirror-failure warning,
		// which would make an oversubscribed-but-healthy standby read as a flaky
		// mirror. Count it as its own debt instead: the peer still believes it
		// synced a session this node does not hold.
		s.stats.ImportsRefusedByHelper.Add(1)
		slog.Debug("cluster sync: helper refused a synced-session import; the "+
			"local mirror was rolled back and the peer holds a session this node does not",
			"af", "v6", "err", err)
	} else {
		s.noteHelperMirrorResult("v6", &s.sessionMirrorWarnedV6, err)
	}
}

func (s *SessionSync) deleteClusterSyncedV4(key dataplane.SessionKey, deleteGen uint64) {
	if s.sessions == nil {
		return
	}
	// #9715: the guard and the dataplane delete are one apply across receive
	// loops, so a newer install cannot land between them; see applyMu.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if !s.deleteGenGuardV4(key, deleteGen) {
		s.stats.DeletesStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation v4 delete (replacement session survives)",
			"delete_gen", deleteGen)
		return
	}
	if err := s.sessions.DeleteWithCompanionsV4(key, dataplane.DeleteReasonClusterStale); err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: failed to delete v4 session", "err", err)
	}
}

func (s *SessionSync) deleteClusterSyncedV6(key dataplane.SessionKeyV6, deleteGen uint64) {
	if s.sessions == nil {
		return
	}
	// #9715: see the v4 twin and applyMu.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if !s.deleteGenGuardV6(key, deleteGen) {
		s.stats.DeletesStaleIgnored.Add(1)
		slog.Debug("cluster sync: ignored stale-generation v6 delete (replacement session survives)",
			"delete_gen", deleteGen)
		return
	}
	if err := s.sessions.DeleteWithCompanionsV6(key, dataplane.DeleteReasonClusterStale); err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: failed to delete v6 session", "err", err)
	}
}
