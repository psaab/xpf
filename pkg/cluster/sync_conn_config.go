package cluster

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
)

// DefaultConfigApplyFailGrace is how long a received config-sync generation may
// stay un-applied — apply hard-failing, standby config stale, high-water pinned
// per M-2/#4151 — before the node raises the CF config-sync monitor-failure /
// degraded-health annotation (#6387, §12.6). The trigger is TIME-BASED rather
// than attempt-count: configApplyLoop only runs on a RECEIVED config, and the
// sender pushes a generation at most ONCE per connection/generation (the
// daemon's level-triggered reconcileConfigSyncToPeer is idempotent after the
// first push), so an "N consecutive failures" gate — or any gate keyed on a
// second delivery edge — could strand the standby forever below the threshold.
// The raise is therefore driven by an independent grace-expiry TIMER armed on
// the first failure of a streak (armConfigApplyGraceTimerLocked): it fires and
// raises CF once the grace elapses with no further delivery required. The grace
// is a wall-clock window an order of magnitude longer than a transient
// RG0-primary config rejection — which clears within a few seconds as the local
// node settles ownership — so a genuine persistent apply failure surfaces to
// the operator promptly while a momentary rejection never flaps the flag (the
// timer is cancelled by the intervening successful apply). It clears on the
// first successful apply. Sized off the peer-loss / transfer-lease timescale
// (DefaultRemoteTransferOutLease is 30s); tests override via
// SessionSync.configApplyFailGrace and SessionSync.afterFuncFn.
const DefaultConfigApplyFailGrace = 30 * time.Second

// nowMono returns CLOCK_MONOTONIC nanos, honoring the test injection seam
// (#6387). Production uses MonotonicNanos.
func (s *SessionSync) nowMono() int64 {
	if s.nowMonoFn != nil {
		return s.nowMonoFn()
	}
	return MonotonicNanos()
}

// configApplyGrace returns the stale-duration grace before a persistently
// un-applied config raises the CF health signal, honoring the test override
// (#6387).
func (s *SessionSync) configApplyGrace() time.Duration {
	if s.configApplyFailGrace > 0 {
		return s.configApplyFailGrace
	}
	return DefaultConfigApplyFailGrace
}

// afterFunc schedules f to run after d, honoring the test injection seam
// (#6387). Production uses time.AfterFunc; a test can capture the callback and
// drive the grace-expiry timer deterministically.
func (s *SessionSync) afterFunc(d time.Duration, f func()) *time.Timer {
	if s.afterFuncFn != nil {
		return s.afterFuncFn(d, f)
	}
	return time.AfterFunc(d, f)
}

// noteConfigApplyFailure drives the time-based config-sync health signal on an
// apply-failure edge (#6387). On the FIRST failure of an un-applied streak it
// ARMS an independent grace-expiry timer (armConfigApplyGraceTimerLocked): the
// config sender re-pushes a generation at most once per connection/generation
// (daemon reconcileConfigSyncToPeer is level-triggered but idempotent), so a
// STABLE connection with a single persistent apply failure receives NO second
// delivery — the periodic reconcile is a no-op after the first push. Without
// the timer the standby would stay silently stranded forever below the
// threshold; the timer guarantees CF surfaces once the grace elapses even with
// no further delivery.
//
// If a later re-delivery of the same generation DOES arrive (the high-water
// never advanced on failure, so it is re-admitted) after the streak has
// persisted STRICTLY longer than the grace, the on-edge fast path raises
// immediately. Both the timer and the on-edge path funnel through
// raiseConfigApplyHealthLocked, which is idempotent and epoch-guarded, so CF
// raises at most once per streak. A transient failure that clears within the
// grace never raises (noteConfigApplySuccess cancels the timer and resets the
// streak) — no flap. Called from the single-consumer configApplyLoop and, since
// #6778, from handleConfigPayload's queue-full drop on the receive loop: a
// generation received and never applied is the condition this timer exists to
// surface, whether the apply failed or never ran. The shared state is guarded
// by configApplyMu, which is what makes the second (concurrent) caller safe —
// the timer callback already runs on its own goroutine.
func (s *SessionSync) noteConfigApplyFailure(applyErr error) {
	now := s.nowMono()
	reason := ""
	if applyErr != nil {
		reason = applyErr.Error()
	}

	s.configApplyMu.Lock()
	defer s.configApplyMu.Unlock()
	if s.firstUnappliedFailNano == 0 {
		s.firstUnappliedFailNano = now
		s.armConfigApplyGraceTimerLocked()
	}
	s.configApplyFailReason = reason
	// On-edge fast path: raise immediately if a re-delivery arrives after the
	// streak has already persisted STRICTLY longer than the grace. Strictly-
	// greater per the #6387 contract — an elapsed exactly equal to the grace
	// has not yet crossed the window (the grace-expiry timer, armed above,
	// covers the boundary/no-redelivery case).
	//
	// #6398 fix: the OnConfigApplyHealth delivery happens WHILE STILL HOLDING
	// configApplyMu. Serializing every raise and clear publish under the one
	// mutex is what prevents a late raise from landing after a concurrent
	// success has cleared CF (the callback-reorder race). The callback runs
	// SetConfigSyncHealth, a cheap two-field setter under m.mu, so the fixed
	// lock order configApplyMu → m.mu has no inverse and cannot deadlock.
	if s.raiseWanted(now) {
		s.raiseConfigApplyHealthLocked()
		if s.OnConfigApplyHealth != nil {
			s.OnConfigApplyHealth(true, reason)
		}
	}
}

// raiseWanted reports whether the un-applied streak has persisted strictly
// longer than the grace and CF has not already been raised. Caller holds
// configApplyMu.
func (s *SessionSync) raiseWanted(now int64) bool {
	if s.configApplyHealthRaised || s.firstUnappliedFailNano == 0 {
		return false
	}
	return time.Duration(now-s.firstUnappliedFailNano) > s.configApplyGrace()
}

// raiseConfigApplyHealthLocked marks CF raised for the current streak. Caller
// holds configApplyMu and fires OnConfigApplyHealth(true, reason) WHILE STILL
// HOLDING that lock (#6398), so a raise cannot be reordered behind a concurrent
// clear. Idempotent (callers gate on !configApplyHealthRaised).
func (s *SessionSync) raiseConfigApplyHealthLocked() {
	s.configApplyHealthRaised = true
}

// armConfigApplyGraceTimerLocked arms (or re-arms) the independent grace-expiry
// timer for the current un-applied streak (#6387). Caller holds configApplyMu.
// It stops any prior timer and bumps configApplyFailEpoch so an in-flight
// callback from a superseded streak/connection cannot raise CF, guaranteeing no
// timer/goroutine leak across re-arms.
func (s *SessionSync) armConfigApplyGraceTimerLocked() {
	s.stopConfigApplyGraceTimerLocked()
	s.configApplyFailEpoch++
	epoch := s.configApplyFailEpoch
	s.configApplyFailTimer = s.afterFunc(s.configApplyGrace(), func() {
		s.fireConfigApplyGraceExpiry(epoch)
	})
}

// stopConfigApplyGraceTimerLocked stops and drops the grace-expiry timer.
// Caller holds configApplyMu.
func (s *SessionSync) stopConfigApplyGraceTimerLocked() {
	if s.configApplyFailTimer != nil {
		s.configApplyFailTimer.Stop()
		s.configApplyFailTimer = nil
	}
}

// stopConfigApplyGraceTimer stops the grace-expiry timer and invalidates any
// in-flight callback (epoch bump), used on SessionSync teardown (Stop) so no
// timer survives a comms restart. Safe to call with no timer armed.
func (s *SessionSync) stopConfigApplyGraceTimer() {
	s.configApplyMu.Lock()
	s.stopConfigApplyGraceTimerLocked()
	s.configApplyFailEpoch++
	s.configApplyMu.Unlock()
}

// fireConfigApplyGraceExpiry is the grace-expiry timer callback (own
// goroutine, #6387). It raises CF for the streak that armed it — no fresh
// delivery required — unless a success or a re-arm has since advanced the epoch
// (the cancelled-but-already-firing race) or CF is already raised. Idempotent.
func (s *SessionSync) fireConfigApplyGraceExpiry(epoch uint64) {
	s.configApplyMu.Lock()
	defer s.configApplyMu.Unlock()
	if epoch != s.configApplyFailEpoch || s.configApplyHealthRaised || s.firstUnappliedFailNano == 0 {
		return
	}
	s.raiseConfigApplyHealthLocked()
	// #6398 fix: deliver the raise WHILE STILL HOLDING configApplyMu so it
	// cannot be reordered behind a concurrent noteConfigApplySuccess clear. If
	// a success wins the lock first it bumps the epoch and this callback never
	// runs (the guard above); if this callback wins, its raise is fully
	// published before the success's clear can acquire the lock. Either
	// interleaving leaves CF in the correct final state. See
	// noteConfigApplyFailure for the lock-order (configApplyMu → m.mu) rationale.
	if s.OnConfigApplyHealth != nil {
		s.OnConfigApplyHealth(true, s.configApplyFailReason)
	}
}

// noteConfigApplySuccess clears the config-sync health streak on a successful
// apply (#6387). It cancels the grace-expiry timer, resets the streak, and
// bumps the epoch so an in-flight timer callback becomes a no-op. It then
// clears the node-global CF annotation without consulting THIS instance's
// configApplyHealthRaised flag. A comms transport change tears down this
// SessionSync but KEEPS the cluster Manager (daemon stopClusterComms), so a CF
// raised by a PRIOR SessionSync instance would otherwise stay stuck forever:
// the replacement instance records the applied generation but, gated on its own
// never-set flag, would never clear the manager. An idempotent clear is cheap,
// so a caught-up successful apply on ANY instance re-converges the annotation.
// Called from the single-consumer configApplyLoop; guarded by configApplyMu.
//
// #6778: the clear is gated on the applied generation having CAUGHT UP with the
// received high-water — the same predicate TransferReadinessSnapshot.ConfigStale
// uses. Before this gate any successful apply cleared the streak, so a config
// dropped at the receive edge (queue full) armed the debt and then had it
// cancelled milliseconds later by the apply of an OLDER generation still sitting
// in the queue — the standby stayed behind the primary with the health signal
// disarmed. appliedGen is the generation whose apply just succeeded; the caller
// has not yet advanced lastAppliedConfigGen when it calls this (the advance must
// follow, for the #6284 fence-release ordering), so the comparison is made
// against the incoming generation rather than the mark.
//
// The gate cannot strand CF raised: a generation the receiver refuses before
// recordRecvConfigGen never raises the received mark, resetRecvGen clears BOTH
// marks to 0 on reconnect, and a legacy peer leaves both at 0 — so appliedGen >=
// lastRecvConfigGen holds in every case where the node is genuinely caught up,
// including the cross-instance clear the paragraph above describes.
func (s *SessionSync) noteConfigApplySuccess(appliedGen uint64) {
	if appliedGen < s.lastRecvConfigGen.Load() {
		// Still behind the newest generation the peer has sent — an older
		// queued config applied while a newer one was lost or is still in
		// flight. Leave the streak and its grace timer armed so a drop that
		// never re-converges still raises CF.
		return
	}
	s.configApplyMu.Lock()
	defer s.configApplyMu.Unlock()
	s.firstUnappliedFailNano = 0
	s.configApplyFailReason = ""
	s.stopConfigApplyGraceTimerLocked()
	s.configApplyFailEpoch++
	s.configApplyHealthRaised = false

	// #6398 fix: deliver the clear WHILE STILL HOLDING configApplyMu. The epoch
	// bump above invalidates any in-flight grace-expiry timer, and publishing
	// the clear under the same mutex that serializes the raise sites guarantees
	// a late raise callback cannot overtake this clear: a timer callback still
	// parked on configApplyMu resumes only after this clear returns, sees the
	// bumped epoch, and no-ops. Delivering the clear OUTSIDE the lock (the prior
	// behavior) let a late raise land after it and leave the Manager stuck
	// configSyncFailing=true after a successful apply.
	if s.OnConfigApplyHealth != nil {
		s.OnConfigApplyHealth(false, "")
	}
}

// ReserveConfigGen reserves an outgoing config generation without writing.
// Daemon callers hold their active-snapshot publication lock while reserving,
// then pass this token to QueueConfigWithAncestryAtGeneration. That ordering
// prevents a stale snapshot from acquiring a newer generation after a commit.
func (s *SessionSync) ReserveConfigGen() uint64 {
	return s.nextConfigGen()
}

// nextConfigGen draws the next strictly-monotonic config generation stamped
// on an outgoing config-sync message (#3931). The counter is seeded from
// CLOCK_MONOTONIC nanos at construction so it never regresses below a value
// the peer may already hold across this node's restarts within a boot.
func (s *SessionSync) nextConfigGen() uint64 {
	return s.configGenCounter.Add(1)
}

// QueueConfig sends the full config text to the peer using the legacy payload
// shape. Callers with explicit rename provenance should use
// QueueConfigWithAncestry.
func (s *SessionSync) QueueConfig(configText string) {
	s.queueConfig(configText, nil, 0)
}

// QueueConfigWithAncestry sends config text and its validated rename
// descriptors as one ordered payload. A peer that has not negotiated the
// additive sidecar receives the legacy text/generation payload and therefore
// takes the existing safe teardown behavior.
func (s *SessionSync) QueueConfigWithAncestry(
	configText string,
	ancestry []configstore.RenameDescriptor,
) bool {
	return s.queueConfig(configText, ancestry, 0)
}

// QueueConfigWithAncestryAtGeneration sends a previously reserved config
// generation. The daemon reserves under its active-publication lock, then
// releases that lock before this method performs I/O.
func (s *SessionSync) QueueConfigWithAncestryAtGeneration(
	configText string,
	ancestry []configstore.RenameDescriptor,
	gen uint64,
) bool {
	if gen == 0 {
		return false
	}
	return s.queueConfig(configText, ancestry, gen)
}

func (s *SessionSync) queueConfig(
	configText string,
	ancestry []configstore.RenameDescriptor,
	reservedGen uint64,
) bool {
	conn := s.getActiveConn()
	if conn == nil {
		return false
	}
	gen := reservedGen
	if gen == 0 {
		gen = s.nextConfigGen()
	}
	payload := encodeConfigPayload(configText, gen)
	if len(ancestry) > 0 && s.ConfigAncestryCapable() {
		payload = encodeConfigPayloadWithAncestry(configText, gen, ancestry)
	}
	// #6629: the config text is the ACTIVE TREE, rendered unredacted — it
	// carries every Secret leaf, including `chassis cluster
	// authentication-key`, the PSK this very link authenticates with. Seal it
	// under the connection's ephemeral key so a passive observer on the
	// control segment cannot read it. The plaintext is the payload built
	// above, byte for byte, so the receiver's decode path is identical.
	msgType := uint8(syncMsgConfig)
	encrypted := false
	if key := s.awaitConfigKey(conn); key != nil {
		sealed, serr := sealConfigPayload(key, payload)
		if serr != nil {
			// Never fail the push on a seal error: config sync is how the
			// standby converges, and an unconverged standby is a worse
			// outcome than a readable payload. Fall through to cleartext with
			// the same warning the mixed-version path emits.
			slog.Error("cluster sync: could not encrypt config payload; sending CLEARTEXT (#6629)",
				"err", serr)
		} else {
			payload, msgType, encrypted = sealed, uint8(syncMsgConfigEncrypted), true
		}
	}
	if !encrypted {
		// The mixed-version case, and the one moment the operator can act on
		// this: a peer that predates #6629 never sends a key exchange, so the
		// config crosses in the clear exactly as it does today. That is the
		// correct fallback — refusing would break the rolling upgrade — but it
		// must not be silent, because an operator running a mixed-version pair
		// WHILE FIRST KEYING THE CLUSTER is standing in the exposed window.
		// The key's presence is reported, never the key (config.Secret exists
		// so it never reaches a log).
		slog.Warn("cluster sync: sending the config to the peer IN CLEARTEXT — the peer did "+
			"not negotiate config-payload encryption (older build). Every secret in the "+
			"active configuration, including the control-link PSK when one is set, is "+
			"readable by anything that can observe the control segment; upgrade the peer, "+
			"and rotate the PSK afterwards because any capture taken now still verifies "+
			"(#6629)",
			"control_link_key_configured", len(s.authKey()) > 0,
			"remote", connRemoteAddrString(conn), "gen", gen, "size", len(configText))
	}
	s.writeMu.Lock()
	err := writeMsg(conn, msgType, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: config send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return false
	}
	// #7328: record the generation actually put on the wire so a peer's
	// config-apply nack can be matched to THIS push. Stored only after a
	// successful write — a send that errored above disconnected, and the
	// reconnect bumps the connection epoch and re-pushes on its own.
	s.lastSentConfigGen.Store(gen)
	s.stats.ConfigsSent.Add(1)
	slog.Info("cluster sync: config sent to peer", "size", len(configText), "gen", gen,
		"encrypted", encrypted)
	return true
}

// errConfigApplyQueueFull is the health-debt reason recorded when a config
// payload is dropped at the receive edge because the #3931 ordered apply queue
// was full (#6778). It is not returned by an apply — no apply ran — but it
// feeds the same #6387 grace timer, because "received a generation, never
// applied it" is the condition that timer exists to surface, and the operator
// needs the DISTINCT reason: an apply failure points at the config or the
// store, a queue-full drop points at a saturated receive path.
var errConfigApplyQueueFull = errors.New("config apply queue full: the newest config generation was dropped before apply")

// sendConfigApplyNack tells the SENDER that this node did not apply the config
// generation it pushed (#7328). Called from configApplyLoop's failure branch —
// the single ordered consumer — and from handleConfigPayload's queue-full drop
// (#6778), so nacks are rate-bounded by how often the peer pushes.
//
// Best-effort by construction: with no active connection there is nothing to
// tell, and a write error disconnects, which bumps the peer's connection epoch
// and makes its reconciler re-push anyway. The transport is TCP, so a nack that
// is not delivered means the connection is gone — there is no silent-loss case
// that would strand the marker.
func (s *SessionSync) sendConfigApplyNack(gen uint64) {
	if gen == 0 {
		// A legacy/unknown generation never advanced a high-water and is
		// applied unconditionally, so there is no marker to re-arm.
		return
	}
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], gen)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgConfigApplyNack, payload[:])
	s.writeMu.Unlock()
	if err != nil {
		slog.Debug("cluster sync: config-apply nack send error", "gen", gen, "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return
	}
	slog.Info("cluster sync: told peer its config generation did not apply here", "gen", gen)
}

// shouldApplyConfigGen is the admission half of the #3931 receiver-side config
// ordering guard. It returns true if a config with generation gen should be
// ATTEMPTED — gen==0 (a legacy sender / unknown, applied unconditionally) or
// strictly newer than the last SUCCESSFULLY-applied generation — and false if
// it is an out-of-order older / duplicate config that must be dropped.
//
// It deliberately does NOT advance the high-water mark; the caller advances via
// recordAppliedConfigGen ONLY after the apply succeeds (M-2/#4151). Advancing
// on admission (the pre-#4151 behavior) meant an apply failure left the
// high-water ahead of the actually-applied config, so the primary's re-push of
// the same generation was dropped as stale and the standby stayed silently
// stranded on the prior config. It is called ONLY from the single-consumer
// configApplyLoop, so the load needs no CAS.
func (s *SessionSync) shouldApplyConfigGen(gen uint64) bool {
	if gen == 0 {
		return true
	}
	last := s.lastAppliedConfigGen.Load()
	return last == 0 || gen > last
}

// recordAppliedConfigGen advances the config high-water mark after a config of
// generation gen has been SUCCESSFULLY applied. gen==0 (legacy / unconditional)
// never advances the mark, mirroring the pre-#3931 behavior.
//
// #5084: the load/compare/store is taken under configGenMu. The prior comment
// here claimed it is "called ONLY from the single-consumer configApplyLoop, so
// the load/store pair needs no CAS" — that is the wrong contract. The apply
// loop is indeed the only ADVANCER, but resetRecvGen CLEARS this mark to 0 from
// a receive-loop goroutine, so the pair had a concurrent writer. A clear landing
// between the load and the store is LOST, re-raising a pre-reboot generation the
// reconnect reset had just cleared and refusing every one of the reconnected
// peer's lower current generations from then on. See the configGenMu doc.
//
// The three writers of lastAppliedConfigGen are:
//
//	recordAppliedConfigGen  the advance, here — configApplyLoop, under configGenMu
//	resetRecvGen            the reconnect clear-to-0 — receive loop, under configGenMu
//	initGenState            NewSessionSync / NewDualSessionSync, before Start
//	                        spawns any goroutine, so it needs no lock
func (s *SessionSync) recordAppliedConfigGen(gen uint64) {
	if gen == 0 {
		return
	}
	s.configGenMu.Lock()
	defer s.configGenMu.Unlock()
	if gen > s.lastAppliedConfigGen.Load() {
		if s.configGenAdvanceBarrierFn != nil {
			s.configGenAdvanceBarrierFn()
		}
		s.lastAppliedConfigGen.Store(gen)
	}
}

// recordRecvConfigGen advances the RECEIVED config high-water (#5563) under
// configGenMu, for the same reason recordAppliedConfigGen does (#5084): the
// raise is a load/compare/store and resetRecvGen clears the mark from another
// goroutine. The prior inline comment justified the bare pair with "the
// receiveLoop is single-threaded per connection" — true per connection, but
// there are TWO receive loops (conn0/conn1), so a raise driven by one fabric
// races a reset driven by the other. A lost clear here leaves PeerConfigGen
// pinned at a pre-reboot generation, which inverts the manual-failover
// readiness gate (PeerConfigGen > AppliedConfigGen) into reporting READY while
// the standby runs the pre-reboot policy.
func (s *SessionSync) recordRecvConfigGen(gen uint64) {
	if gen == 0 {
		return
	}
	s.configGenMu.Lock()
	defer s.configGenMu.Unlock()
	if gen > s.lastRecvConfigGen.Load() {
		if s.configGenAdvanceBarrierFn != nil {
			s.configGenAdvanceBarrierFn()
		}
		s.lastRecvConfigGen.Store(gen)
	}
}

// beginConfigApply raises the apply-in-progress fence to gen for the duration
// of an apply (#6284, item 2). It is set BEFORE OnConfigReceived runs — so it
// covers the whole apply, including the receiver's clearSessionsForDeletedPolicies
// sweep — and configEpochStale folds max(fence, high-water) into its refusal
// threshold. A gen==0 (legacy/unconditional) apply carries no comparable epoch,
// so the fence stays 0 and no install is refused on its account. Called ONLY
// from the single-consumer configApplyLoop. The store takes configGenMu (#5084)
// so it cannot straddle resetRecvGen's clear of the same field; a stale fence is
// less harmful than a stale high-water (the next sweep re-sends the transiently
// refused installs), but the reset clears all three marks as one transaction and
// leaving one writer outside the lock invites a reader to conclude none is
// needed.
func (s *SessionSync) beginConfigApply(gen uint64) {
	s.configGenMu.Lock()
	defer s.configGenMu.Unlock()
	s.applyingConfigGen.Store(gen)
}

// endConfigApply lowers the apply-in-progress fence (#6284, item 2). On a
// SUCCESSFUL apply the caller advances the high-water (recordAppliedConfigGen)
// FIRST and only then calls this, so the effective refusal threshold
// max(fence, high-water) never dips between the sweep and the high-water
// advance — closing the residual window. On an apply FAILURE the high-water
// deliberately stays put (M-2/#4151) and the fence is simply dropped, restoring
// the pre-apply admission posture (the transiently-refused installs are re-sent
// by the peer's next sweep). Called ONLY from configApplyLoop, under configGenMu
// for the reason given on beginConfigApply (#5084).
func (s *SessionSync) endConfigApply() {
	s.configGenMu.Lock()
	defer s.configGenMu.Unlock()
	s.applyingConfigGen.Store(0)
}

// configApplyLoop is the single ordered consumer of config-sync messages
// (#3931). It drains configApplyCh in receive order and attempts a config only
// when shouldApplyConfigGen accepts its generation, so a reordered older config
// from a rapid commit pair (C1 after C2) is dropped and the standby always
// converges to the newest config. Replaces the pre-#3931 racing
// `go OnConfigReceived` per message.
//
// The config high-water mark (lastAppliedConfigGen) advances ONLY after the
// apply succeeds (recordAppliedConfigGen, gated on OnConfigReceived returning
// nil). An apply failure counts ConfigsApplyFailed and leaves the high-water at
// the last-applied generation, so the primary's re-push of the same generation
// is re-admitted and the standby re-converges instead of being silently
// stranded on the prior config (M-2/#4151).
func (s *SessionSync) configApplyLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-s.configApplyCh:
			// #5084 rule 3, and it must run BEFORE the generation gate. The
			// payload's generation is drawn from a DEAD peer incarnation, so it
			// is incomparable with the current one — feeding it to a
			// monotone-max high-water is precisely the defect: an old-boot item
			// applying after resetRecvGen records a high mark, and the rebooted
			// peer's lower-generation current config is then refused as stale,
			// permanently.
			//
			// Dropping here strands nothing, and that is true only because
			// membership is an EQUIVALENCE. #6900 failed partly because
			// skipping a payload also skipped the generation gate and could
			// leave the high-water holding information from a connection it had
			// just fenced out; here the dropped payload's generation carries no
			// information the current namespace needs, because it was never
			// comparable to begin with.
			if s.configItemIncarnationStale(item) {
				s.stats.ConfigsDeadIncarnationDropped.Add(1)
				slog.Warn("cluster sync: dropping config from a replaced peer boot incarnation — "+
					"the peer rebooted and re-primed, so this payload's generation is incomparable "+
					"with the current one (#5084)",
					"item_incarnation", item.incarnation.String(),
					"current_incarnation", s.PeerBootIncarnation().String(),
					"gen", item.gen, "size", len(item.text))
				continue
			}
			if !s.shouldApplyConfigGen(item.gen) {
				s.stats.ConfigsStaleIgnored.Add(1)
				slog.Warn("cluster sync: dropping out-of-order config sync (stale generation) — standby retains newer config",
					"incoming_gen", item.gen, "last_applied_gen", s.lastAppliedConfigGen.Load(), "size", len(item.text))
				continue
			}
			if s.OnConfigReceivedWithAncestry == nil && s.OnConfigReceived == nil {
				// No apply handler wired — the config cannot be applied, so the
				// high-water must NOT advance (M-2/#4151). A later wired handler
				// re-applies on the primary's next push of this generation.
				continue
			}
			// #6284 item 2: fence installs against the generation being applied
			// for the ENTIRE apply. The clearSessionsForDeletedPolicies sweep
			// runs inside OnConfigReceived, so a synced session install that races
			// the sub-µs gap between the sweep and the high-water advance must be
			// refused now.
			s.beginConfigApply(item.gen)
			var applyErr error
			if s.OnConfigReceivedWithAncestry != nil {
				applyErr = s.OnConfigReceivedWithAncestry(item.text, item.ancestry)
			} else {
				applyErr = s.OnConfigReceived(item.text)
			}
			if applyErr != nil {
				// transient RG0-primary rejection). Do NOT advance the
				// high-water: leaving it at the last-applied generation keeps
				// the standby eligible for the primary's re-push so it
				// re-converges instead of being silently stranded (M-2/#4151).
				s.stats.ConfigsApplyFailed.Add(1)
				// Debug, not Warn: handleConfigSync (the callback) already logs
				// the authoritative one-time reason WHY the apply failed
				// (RG0-primary rejection at Warn, compile/promote failure at
				// Error). This line is the per-retry diagnostic detail of the
				// M-2/#4151 high-water retention, and the same generation may be
				// re-pushed on every reconnect while the condition persists — a
				// Warn here would spam (CLAUDE.md logging rule). The
				// rate-independent observable is the ConfigsApplyFailed counter
				// above (surfaced in cluster status), not this log.
				slog.Debug("cluster sync: config apply failed — retaining prior high-water so the peer re-push re-converges",
					"incoming_gen", item.gen, "last_applied_gen", s.lastAppliedConfigGen.Load(), "size", len(item.text), "err", applyErr)
				// #6387: drive the time-based CF health signal on this failure
				// edge. On the FIRST failure of a streak it ARMS an independent
				// grace-expiry timer that raises OnConfigApplyHealth(true) once
				// the grace elapses even if no further config is delivered — the
				// sender pushes a generation at most once per connection, so a
				// stable connection with a persistent apply failure would
				// otherwise never re-enter this edge. A standby stranded by a
				// persistent apply failure thus surfaces as a CF monitor-failure /
				// degraded health instead of only the terse `Transfer ready: no`
				// string.
				s.noteConfigApplyFailure(applyErr)
				// #7328: tell the SENDER this generation did not take effect.
				// #4151 leaves this node eligible for a re-push of the SAME
				// generation, but the sender's #5863 (epoch x generation) marker
				// was claimed BEFORE the push and nothing clears it, so no
				// trigger on the live connection would ever push it again --
				// the eligibility #4151 preserves is unreachable without this.
				// The sender re-arms its marker and re-pushes on its ordinary
				// reconcile cadence.
				s.sendConfigApplyNack(item.gen)
				// #6284: drop the fence — the high-water intentionally stays put
				// (M-2/#4151), so restore the pre-apply admission posture.
				s.endConfigApply()
				continue
			}
			// #6387: a confirmed apply clears any raised CF health signal (the
			// standby has re-converged). #6778 narrows "re-converged" to mean
			// CAUGHT UP: the clear now takes the applied generation and no-ops
			// while it is still behind the received high-water, so an older
			// queued config applying after a newer one was dropped at the
			// receive edge cannot cancel the debt for the generation that was
			// lost. A gen==0 legacy apply still clears (a legacy peer never
			// raises the received mark, so both sides read 0).
			s.noteConfigApplySuccess(item.gen)
			// Apply confirmed — advance the high-water so a duplicate re-push of
			// the same generation is correctly skipped as stale, THEN drop the
			// fence. Advancing first keeps the effective refusal threshold
			// max(fence, high-water) from dipping in the release window (#6284).
			s.recordAppliedConfigGen(item.gen)
			s.endConfigApply()
		}
	}
}
