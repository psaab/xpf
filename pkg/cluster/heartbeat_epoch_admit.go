package cluster

// Epoch ADMISSION: the #6169 boot-epoch gate and the per-value session budget
// that bounds it.
//
// Split out of heartbeat.go in #6669 r18. heartbeat.go carries the wire format
// and the sender/receiver lifecycle; this file carries the decision an
// authenticated frame's epoch is put through, which is a distinct concern with
// its own (long) rationale. The split was forced by the 2000-line modularity
// gate when the finding-2 disclosure widened, and it is the right cut
// regardless: nothing here touches sockets.

// admitAuthed is the #6169 anti-replay decision for one MAC-VERIFIED frame:
// the boot-epoch floor and the bounded session ring applied as ONE transaction
// under the state lock. Callers must invoke it only after the MAC has verified.
//
// hasEpoch reports whether the frame carried a boot-epoch section
// (heartbeatFrameEpoch).
//
// ORDER IS LOAD-BEARING. The epoch floor is tested BEFORE the session ring is
// consulted, and a frame rejected by the floor never reaches ring.admit. Test
// it after, and the gate is bypassable: ring.admit RECORDS a never-seen session
// as a side effect, so a replayed retired frame would still evict a live
// watermark and churn the ring even while being rejected. That inverted
// ordering is what failed review on the earlier attempt (#6370).
//
// The three cases:
//
//   - epoch < highEpoch — an incarnation OLDER than the highest one accepted.
//     Reject. This is the #6169 close: a captured frame below the floor never
//     reaches the ring at all, so it cannot churn it.
//     "Older" is not the same as "retired", and the difference is #6711: once a
//     sender's epoch has REGRESSED, the live incarnation is the one sorted
//     below, so this branch refuses it while an archived frame from a genuinely
//     retired one is admitted above.
//   - epoch == highEpoch — an incarnation at the floor. Fall through to the
//     ring, which is what handles within-incarnation replay (unchanged #6167
//     behaviour) — but only for a BOUNDED set of sessions at that value
//     (heartbeatEpochSessionsPerEpoch slots, reset by a raise).
//     Equality MUST fall through for a bound session: the live peer signs
//     every frame of its incarnation with one epoch, so rejecting equality
//     outright would declare a healthy peer dead. It must NOT fall through
//     without a bound: distinct sessions sharing one epoch churn the ring
//     exactly as epochless frames do (measured 1625/1625). And the bound
//     cannot be ONE — a successor incarnation republishes its predecessor's
//     epoch whenever the store cannot advance the file, so a singleton refused
//     a healthy node on every heartbeat (measured 0/40). See
//     highEpochSessions for both measurements and the residual.
//     A regressed sender therefore has two doors out of a poisoned floor:
//     landing exactly ON it while a slot is free, or RAISING past it. Strictly
//     past is the wider (a nanosecond of wall clock, versus hitting one value
//     exactly) and the only one that cannot be exhausted; an earlier revision
//     of this comment named equality alone, and round 10 shut it entirely.
//     TestPoisonedFloorStillRecoversByRaise_6669 measures both.
//   - epoch > highEpoch — an incarnation newer than anything accepted so far
//     (genuinely newer while the sender's clock advances; #6711 is when it is
//     merely a higher reading from an older one). Let the ring vet the
//     nonce, then raise the floor. The floor only ever rises to a value the
//     genuine peer actually signed — but that does NOT mean it cannot rise
//     above the live peer, and an earlier revision of this comment said it did.
//     It rises above the LIVE peer whenever the peer's own epoch has REGRESSED
//     since the archived frame was signed (#6711: a backward clock step larger
//     than bootEpochMaxSkew makes refineBootEpoch decline the intact persisted
//     value; since #6711 it no longer overwrites it, so correcting the clock
//     recovers, but the regression itself is unchanged). One archived frame
//     then locks the live peer out, and because the archived frame re-raises a
//     CLEARED floor exactly as it re-arms a cleared latch, a receiver restart
//     does not recover while it is being replayed. Measured in
//     TestArchivedEpochPoisonsAFreshFloor_6711.
//
// MIGRATION + THE DOWNGRADE LATCH (dual-accept, the #4126 VRRP-checksum /
// heartbeatAuthDecision pattern).
//
// An epochless frame is accepted and passed to the ring exactly as before —
// UNTIL the peer has proved it emits epochs. From then on an epochless frame
// from that peer is refused. Both halves are required:
//
//   - Accepting epochless frames before the peer has proved otherwise is what
//     keeps a rolling upgrade from splitting the cluster, and it is why the
//     latch is armed by OBSERVATION rather than by local build version.
//   - Refusing them afterwards is what actually closes #6169. An attacker's
//     captures are by construction mostly PRE-upgrade and therefore epochless;
//     without the latch they bypass the floor entirely and the fix would only
//     defend against an attacker who started capturing after the upgrade.
//     Measured on the first cut of this change: floor latched at a live peer's
//     epoch, and still 975/975 epochless replays admitted.
//
// The latch is armed by an ACCEPTED frame that carried an epoch section. It
// lives on Manager.hbAuth, so the routine restarts (heartbeat restart,
// DHCP-triggered VRF rebind, HA comms restart) preserve it, and since #16022
// it is persisted across a full daemon restart in a key-set-scoped record
// written off this path (heartbeat_epoch_persist.go). See the epochSeen field
// comment for how the earlier durable-latch pricing is engaged.
//
// WHAT MAKES THE LATCH SAFE is the sender-side invariant in heartbeat_epoch.go:
// a keyed heartbeat carries no epoch IF AND ONLY IF the peer runs a pre-#6169
// build.
//
// That invariant holds against BOTH storage failure modes, and the distinction
// is load-bearing because only one of them was ever covered. A FAILING store
// (unwritable dir, ENOSPC, corrupt file) always fell through to the wall-clock
// seed. A HANGING store did not: the epoch was computed before any I/O and then
// thrown away by not publishing until after a blocking LOCK_EX, so a held lock
// left bootEpoch at 0 and the sender silently degraded to a legacy frame — which
// a latched peer then rejects, declaring a healthy node dead within ~500ms
// (measured). Emission is now published from the wall clock BEFORE any file is
// touched (Manager.heartbeatBootEpoch), so a hung disk, a blocking flock and a
// wedged fsync are all survivable; persistence only ever raises the value later.
//
// The one remaining trigger is a genuine ROLLBACK of the peer to a pre-#6169
// build, a deliberate operator-initiated act: that peer's frames are refused
// until the latch is cleared. Clearing it is the PSK rotation (the record is
// key-set-scoped, so the rotation drops it on the next apply) — there is no
// state file to hand-edit. This is the same trade #4107's sticky peerAuthSeen
// already makes for the auth trailer.
//
// A bare `systemctl restart xpfd` on THIS node no longer clears the latch at
// all, and against any cleared state an attacker holding one archived
// epoch-bearing frame re-arms it. Rotate the control-link PSK on both nodes.
// See the arming site in admitAuthed for why the re-arm is not closed in code.
//
// The three epoch cases, once the peer is known to emit them:
//
//   - epoch < highEpoch — an incarnation OLDER than the highest one accepted.
//     Reject. This is the #6169 close: a captured frame below the floor never
//     reaches the ring at all, so it cannot churn it.
//     "Older" is not the same as "retired", and the difference is #6711: once a
//     sender's epoch has REGRESSED, the live incarnation is the one sorted
//     below, so this branch refuses it while an archived frame from a genuinely
//     retired one is admitted above.
//   - epoch == highEpoch — an incarnation at the floor. Fall through to the
//     ring, which is what handles within-incarnation replay (unchanged #6167
//     behaviour) — but only for a BOUNDED set of sessions at that value
//     (heartbeatEpochSessionsPerEpoch slots, reset by a raise).
//     Equality MUST fall through for a bound session: the live peer signs
//     every frame of its incarnation with one epoch, so rejecting equality
//     outright would declare a healthy peer dead. It must NOT fall through
//     without a bound: distinct sessions sharing one epoch churn the ring
//     exactly as epochless frames do (measured 1625/1625). And the bound
//     cannot be ONE — a successor incarnation republishes its predecessor's
//     epoch whenever the store cannot advance the file, so a singleton refused
//     a healthy node on every heartbeat (measured 0/40). See
//     highEpochSessions for both measurements and the residual.
//     A regressed sender therefore has two doors out of a poisoned floor:
//     landing exactly ON it while a slot is free, or RAISING past it. Strictly
//     past is the wider (a nanosecond of wall clock, versus hitting one value
//     exactly) and the only one that cannot be exhausted; an earlier revision
//     of this comment named equality alone, and round 10 shut it entirely.
//     TestPoisonedFloorStillRecoversByRaise_6669 measures both.
//   - epoch > highEpoch — an incarnation newer than anything accepted so far
//     (genuinely newer while the sender's clock advances; #6711 is when it is
//     merely a higher reading from an older one). Let the ring vet the
//     nonce, then raise the floor. The floor only ever rises to a value the
//     genuine peer actually signed — but that does NOT mean it cannot rise
//     above the live peer, and an earlier revision of this comment said it did.
//     It rises above the LIVE peer whenever the peer's own epoch has REGRESSED
//     since the archived frame was signed (#6711: a backward clock step larger
//     than bootEpochMaxSkew makes refineBootEpoch decline the intact persisted
//     value; since #6711 it no longer overwrites it, so correcting the clock
//     recovers, but the regression itself is unchanged). One archived frame
//     then locks the live peer out, and because the archived frame re-raises a
//     CLEARED floor exactly as it re-arms a cleared latch, a receiver restart
//     does not recover while it is being replayed. Measured in
//     TestArchivedEpochPoisonsAFreshFloor_6711.
//
// An epoch outside the ABSOLUTE plausibility band (epochUsableAsFloor: zero, or
// beyond year 2200) is REFUSED. That check is clock-independent, so it is safe
// on every frame and runs before anything else in the hasEpoch path: such a
// frame never reaches the floor comparison, never touches the ring, and never
// arms the latch — s.epochSeen stays false. A corrupt far-future value
// therefore cannot slam the one-way door.
//
// The FORWARD bound (epochWithinForwardBound: more than bootEpochMaxSkew — one
// HOUR — ahead of our own wall clock) is deliberately NOT tested here. It gates
// only the RAISE path, epoch > highEpoch, where latching a far-future floor is
// the actual hazard.
//
// DO NOT HOIST THE FORWARD BOUND BACK TO THE TOP. Re-testing an epoch that has
// ALREADY been accepted is a different thing from vetting a new one, and doing
// it was a defect: a backward wall-clock step beyond the skew made every
// subsequent frame from a healthy, already-latched incarnation fail the bound
// and be rejected BEFORE the monotonic lastSeen update, so the peer was
// declared dead in ~500ms and the cluster went dual-master. At epoch ==
// highEpoch the frame therefore falls through to the ring (for a session within
// the per-value bound — see highEpochSessions), which is correct: equality
// cannot move the floor, so the one-way door is untouched either way.
//
// The second-order consequence is the safe direction and is deliberate: a peer
// whose clock runs more than an hour ahead cannot RAISE the floor, and because
// the latch never armed on it, its EPOCHLESS frames would still be accepted if
// it were later rolled back. Refusing to latch an out-of-bound epoch never
// strands a peer that comes back into range.
// It returns the admission decision and, on refusal, a REASON naming the arm
// that refused. The reason exists because heartbeatAuthDecision cannot tell
// them apart: it sees only `nonceFresh == false` and reports every one of them
// as "stale nonce (replay)". Two of the epoch arms are not replays at all — an
// out-of-band epoch is a corrupt or non-conforming peer, and an epoch past the
// forward bound is a healthy peer with a fast clock — and labelling either as a
// replay sends the operator hunting an attacker instead of checking the peer's
// build or its NTP. An empty reason means "no epoch-specific arm refused this",
// and the caller keeps heartbeatAuthDecision's generic wording.
//
// It takes s.mu itself. It was previously a bare pass-through to a second
// method named admitAuthed, which by the usual Go convention would mean
// "caller already holds the lock" — the opposite of what it did. One function,
// no suffix.
func (s *heartbeatAuthState) admitAuthed(hasEpoch bool, epoch, session, counter uint64) (ok bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !hasEpoch {
		if s.epochSeen {
			// Downgrade: this peer has proved it emits epochs.
			s.epochDowngradeRejected.Add(1)
			return false, "boot epoch withdrawn by a peer that had signed one (rollback or pre-upgrade replay)"
		}
		// The migration window — and the ONLY residual an operator can still be
		// exposed to on merge day, since a capture taken before the upgrade is
		// epochless and this node has not yet seen proof the peer emits epochs.
		// Counted so that exposure is visible rather than inferred: a peer still
		// sending epochless frames after both nodes are upgraded is either
		// mid-rollout or an attack, and both are things an operator must see.
		// Surfaced through HeartbeatStats.EpochlessAdmitted.
		ok := s.replay.admit(session, counter)
		if ok {
			s.epochlessAdmitted.Add(1)
		}
		// No epoch-specific reason: an epochless refusal here IS an ordinary ring
		// replay, which is exactly what heartbeatAuthDecision already says.
		return ok, ""
	}
	// An epoch the floor cannot ORDER is refused, not admitted-and-ignored.
	// Admitting it would recreate the epochless bypass in miniature: a frame
	// outside the comparable range is governed by the bounded ring alone, so
	// captures from an incarnation that once emitted an out-of-range epoch would
	// replay indefinitely. See epochOrderable.
	// The ABSOLUTE sanity check is clock-independent, so it is safe on every
	// frame: a 0 or beyond-year-2200 value is never a real incarnation.
	if !epochUsableAsFloor(epoch) {
		s.epochOutOfBandRejected.Add(1)
		return false, "boot epoch outside the plausible range (corrupt state file, or a peer " +
			"that is not a conforming #6169 build)"
	}
	// A frame BELOW the floor is a replay of a retired incarnation, so the
	// generic "stale nonce (replay)" wording is already accurate here and no
	// distinct reason is added. It is the one epoch arm where the collapsed
	// label was never wrong; the counter for it is EpochDowngradeRejected's
	// sibling case and is deliberately not introduced (see the fold notes).
	if epoch < s.highEpoch {
		return false, ""
	}
	// A BOUNDED NUMBER OF INCARNATIONS PER EPOCH VALUE. Equality falls through
	// to the ring — it must, because the live peer signs every one of its frames
	// with the same epoch — but only for a session already bound at this floor,
	// or for a new one while a slot is free. Without any bound, distinct
	// sessions sharing one valid epoch are all admitted at the floor and churn
	// the ring exactly as epochless frames do (measured 1625/1625); with a
	// singleton bound, a legitimate successor incarnation that republished its
	// predecessor's epoch is refused on every heartbeat (measured 0/40). This
	// runs BEFORE s.replay.admit for the same reason the floor itself does:
	// admit() RECORDS a never-seen session as a side effect, so a check placed
	// after it would evict a live watermark while rejecting. The binding itself
	// is recorded only once the frame is actually admitted, below, so a frame
	// the ring refuses cannot spend a slot. See highEpochSessions for the bound,
	// its residual cost, and the two alternatives that were declined.
	if epoch == s.highEpoch && !s.epochSessionAdmissible(session) {
		s.epochSessionCollision.Add(1)
		return false, "too many peer sessions at one boot epoch (peer cannot advance its " +
			"epoch store, or a replayed capture set sharing one epoch)"
	}
	// The FORWARD bound is clock-dependent, so it gates ONLY the irreversible
	// operation — raising the floor. Applying it to a frame from the
	// already-latched incarnation (epoch == highEpoch) made a backward
	// wall-clock step beyond bootEpochMaxSkew reject a HEALTHY peer before the
	// monotonic lastSeen update, declaring it dead in ~500ms and going
	// dual-master. See epochWithinForwardBound.
	//
	// Sampled through epochNowNanos rather than time.Now directly, so the
	// regime this bound does NOT cover is drivable: below epochClockSaneFloor
	// (a dead RTC, or a boot before NTP) epochWithinForwardBound abstains
	// entirely and epochUsableAsFloor above is the only surviving filter. With
	// a real clock that regime is unreachable from a test, which left the
	// absolute band looking redundant with this one. See
	// TestUncredibleClockLeavesOnlyTheAbsoluteBand_6669.
	//
	// #6969 F5: when the bound fires, DECLINE THE RAISE — do not reject the
	// frame. Rejecting cost liveness: the frame never reaches the monotonic
	// lastSeen update, so a peer that restarts while this receiver's clock is
	// more than bootEpochMaxSkew slow is declared dead in ~500ms and the
	// cluster goes dual-master, over what is a clock fault on ONE node. The
	// comment above already said the bound gates "ONLY the irreversible
	// operation"; the implementation was wider than its own stated intent.
	//
	// The frame is then treated exactly as if it had arrived AT the floor, so
	// it must pass the SAME per-value session budget an equality frame does.
	// That is not incidental: without it, a frame that cannot be latched would
	// be an unbounded admission path — precisely the epochless bypass the floor
	// exists to close. Checked here, BEFORE s.replay.admit, for the same reason
	// the equality check is: admit() records a never-seen session as a side
	// effect, so a check after it would evict a live watermark while rejecting.
	//
	// NARROWED TO AN ESTABLISHED PEER (s.highEpoch != 0), which is the whole
	// reason this can be a small change. The harm being fixed is "a peer this
	// receiver has already accepted is declared dead", and that needs a floor to
	// exist. A receiver with NO floor has no established peer and therefore no
	// liveness to protect, so refusing there costs nothing — and it keeps every
	// fresh-state guard at full strength: an unorderable epoch presented to a
	// fresh receiver is still refused outright, never arms the latch, and leaves
	// the floor at 0. Without this clause the change would re-decide six
	// deliberate assertions across four files instead of one.
	declineRaise := false
	if epoch > s.highEpoch && !epochWithinForwardBound(epoch, epochNowNanos()) {
		s.epochRaiseDeclinedAheadOfClock.Add(1)
		if s.highEpoch == 0 {
			// NO ESTABLISHED PEER, so there is no liveness to protect and the
			// old refusal is kept exactly. This arm is why the change re-decides
			// one deliberate assertion instead of six: every fresh-state guard —
			// an unorderable epoch is refused, never arms the latch, leaves the
			// floor at 0 — is untouched.
			return false, "boot epoch more than bootEpochMaxSkew ahead of our clock " +
				"(check NTP on BOTH nodes — this is a clock fault, not a replay)"
		}
		declineRaise = true
		if !s.epochSessionAdmissible(session) {
			s.epochSessionCollision.Add(1)
			return false, "too many peer sessions at one boot epoch (peer cannot advance its " +
				"epoch store, or a replayed capture set sharing one epoch)"
		}
	}
	if !s.replay.admit(session, counter) {
		return false, ""
	}
	// ARMING THE LATCH. A REPLAY CAN DO THIS, and the consequence is a real
	// residual an operator has to be told about, not a theoretical one.
	//
	// Arming requires only an authenticated, orderable, ring-fresh epoch frame.
	// Against a FRESH state — highEpoch 0, latch clear, ring empty, which is
	// what a node with no durable record for the current key set starts in —
	// a single ARCHIVED frame captured while the peer still ran an
	// epoch-capable build satisfies all three: nothing is below the floor,
	// and an empty ring calls its session never-seen. It re-arms the latch,
	// and the legitimately rolled-back peer's genuine epochless frames are
	// refused again at the top of this function. One replay per clearing
	// sustains that indefinitely.
	//
	// SO RESTARTING xpfd IS NOT, BY ITSELF, RECOVERY FROM A ROLLBACK while an
	// on-link attacker holds such a capture — which is precisely the attacker
	// #6169 exists to defend against — and since #16022 it does not even clear
	// the latch. The complete recovery is to ROTATE THE CONTROL-LINK PSK on
	// both nodes: rotation makes every archived frame fail
	// verifyHeartbeatMAC, so it never reaches this function to re-arm
	// anything, and it re-scopes the durable record so the latch it armed is
	// dropped on the next apply. The key is re-read per frame on both paths,
	// so rotation needs no restart of its own.
	//
	// The RE-ARM is not closed in code, and the alternatives were priced
	// separately, because they are separate designs. Binding arming to
	// freshness needs a challenge-response or a timestamp the heartbeat wire
	// format does not carry, and cannot be approximated from the epoch
	// itself: a legitimately long-lived peer's epoch is arbitrarily old, so
	// no recency test separates it from an archived one. The durable half —
	// refusing the epoch-LESS captures that sustain forged liveness
	// indefinitely (measured 1625/1625 admitted after a restart pre-#16022,
	// against 0/1625 for a spent epoch-bearing set) — IS now closed by the
	// key-set-scoped record in heartbeat_epoch_persist.go, priced in full at
	// the epochSeen field comment.
	//
	// SCOPE, honestly: a peer that has NEVER emitted an epoch cannot be falsely
	// armed this way — there is nothing to capture. It bites on rollback,
	// replacement under the same identity and key, or a partial upgrade.
	//
	// AND THE COST IS NOT ONLY THE LATCH (#6669 r18, Codex finding 2). The
	// same archived frame is ADMITTED, so admitFrame goes on to refresh
	// lastSeen and call handlePeerHeartbeat: a peer that is DEAD looks alive
	// for as long as the replay continues, and that liveness feeds election.
	// One frame per dead-peer interval sustains it. This is NOT introduced
	// here — master has no epoch gate at all, so the bare ring admits the
	// same frame after the same restart, and TestHeartbeatRestartStillAccepts
	// GenuinePeer_5086 requires it (a real peer reboot must be accepted).
	// The epoch floor strictly improves on that ONCE ARMED and does not close
	// the post-restart window. Read the paragraph above as covering the latch
	// only; the forged-liveness half is the same replay, and the same PSK
	// rotation retires it.
	// Pinned by TestArchivedEpochReplayReArmsLatchAfterRestart_6169.
	// #6969 F5: declineRaise means the epoch is ABOVE the floor but could not be
	// verified against this node's clock. TWO consequences of admission are
	// withheld from it, and the second was found by the tests rather than
	// reasoned out in advance:
	//
	//  1. the FLOOR does not move. A floor raised to a value this node cannot
	//     verify locks out the live peer (#6711 poisoning) — the worst outcome
	//     in this area, and the reason the bound exists at all.
	//  2. the DOWNGRADE LATCH is not armed. epochSeen means "this peer has been
	//     observed signing boot epochs", after which its epochless frames are
	//     refused. A frame whose epoch this node cannot judge is not evidence
	//     for that: arming on it would let one captured far-future frame lock
	//     out a genuinely rolled-back peer, which is exactly what
	//     TestHeartbeatUnorderableEpochNeverArmsLatch_6169 guards.
	//
	// What the frame DOES get is the thing it was rejected for: it reaches the
	// monotonic lastSeen update, so a peer that restarted while this node's
	// clock is slow stays alive instead of being declared dead in ~500ms.
	seenBefore := s.epochSeen
	bindingsBefore := s.highEpochSessionCount
	boundBefore := s.highEpochSessions
	if !declineRaise {
		s.epochSeen = true
	}
	if epoch > s.highEpoch && !declineRaise {
		s.highEpoch = epoch
		// Rebind the floor to THIS incarnation, DISCARDING the sessions bound at
		// the old value. The two must move together: a floor whose bound
		// sessions are stale would refuse the very peer that just raised it, and
		// carrying them forward would let one epoch value's budget be spent at
		// the next. The discarded sessions are below the floor from here on and
		// are refused by the `epoch < s.highEpoch` test above.
		s.bindEpochSession(session, true)
	} else {
		// epoch == s.highEpoch: admissibility was decided above, so this either
		// re-affirms a session already bound or consumes a free slot.
		// A clock-skew decline also reaches this branch: it does not arm or
		// raise, but it DOES spend the durable per-value session budget, so
		// that spend must advance the generation and mark persistence owed.
		// Otherwise a restart restores the pre-decline bindings and hands
		// the declined session a fresh equality slot the live process had
		// already denied it.
		s.bindEpochSession(session, false)
	}
	// #16022: any actual latch/floor/bindings advance — decline-raise
	// binding consumption included, mere re-affirmation excluded — bumps the
	// monotonic generation and marks the async record owed. No I/O here.
	// A raise always rebinds (bindingsChanged); the seenBefore term covers
	// a first arming whose binding was already present in a test fixture.
	bindingsChanged := s.highEpochSessionCount != bindingsBefore || s.highEpochSessions != boundBefore
	if bindingsChanged || (s.epochSeen && !seenBefore) {
		s.peerEpochPersistGeneration++
		if s.peerEpochPersistGeneration == 0 {
			s.peerEpochPersistGeneration = 1
		}
		s.peerEpochPersistOwed = true
	}
	return true, ""
}

// epochSessionAdmissible reports whether a frame claiming exactly highEpoch may
// proceed from this session. It is a pure predicate: the caller records the
// binding with bindEpochSession only after the frame is actually admitted.
//
// s.mu must be held.
func (s *heartbeatAuthState) epochSessionAdmissible(session uint64) bool {
	for i := 0; i < s.highEpochSessionCount; i++ {
		if s.highEpochSessions[i] == session {
			return true
		}
	}
	return s.highEpochSessionCount < len(s.highEpochSessions)
}

// bindEpochSession records session as one of the incarnations admitted at the
// current floor. reset drops every previous binding, which is what a raise
// does; otherwise the session is added if it is not already present and a slot
// is free.
//
// TWO PROPERTIES, TWO ENFORCERS, and two earlier revisions of this comment each
// credited the wrong one.
//
//   - The CAPACITY REFUSAL — the (k+1)-th distinct session at one epoch value is
//     rejected — is enforced by epochSessionAdmissible, at admitAuthed and
//     BEFORE the ring. Not by the full-set branch below, which the pre-check
//     makes unreachable from that caller: under the same s.mu hold
//     epochSessionAdmissible already returns false for any session not in the
//     set once the count reaches len(highEpochSessions), and nothing between
//     that check and this call mutates the set. Mutating the branch to evict
//     slot 0 leaves the whole suite green, so a reader told the decision lives
//     there is reading a line that cannot execute.
//   - The NO-REFILL property — a slot, once spent, is never freed except by a
//     raise — is enforced HERE, and cannot be anywhere else.
//     epochSessionAdmissible is a pure predicate; it cannot free a slot. This
//     function is the ONLY mutator of highEpochSessions/highEpochSessionCount,
//     and no-refill is exactly the shape of what it does not do: it never
//     evicts, never decrements, and resets only when the caller signals a raise.
//     That is why the full-set branch is a no-op rather than an eviction —
//     eviction would make the budget refillable and hand an attacker back the
//     unbounded churn the bound exists to stop — and it is kept as
//     defence-in-depth against a future caller that does not pre-check.
//
// Nothing here expires or rebinds on silence either, which is the same property
// seen from the other side: see the declined alternative at highEpochSessions.
//
// s.mu must be held.
func (s *heartbeatAuthState) bindEpochSession(session uint64, reset bool) {
	if reset {
		s.highEpochSessions[0] = session
		s.highEpochSessionCount = 1
		return
	}
	for i := 0; i < s.highEpochSessionCount; i++ {
		if s.highEpochSessions[i] == session {
			return
		}
	}
	if s.highEpochSessionCount < len(s.highEpochSessions) {
		s.highEpochSessions[s.highEpochSessionCount] = session
		s.highEpochSessionCount++
	}
}
