//! WireGuard handshake orchestration on `WgEngine` (#1709 S1).
//!
//! This file holds the slow-path, control-thread-only handshake driver: the
//! `HandshakeError` enum, the `PendingHandshake` reservation record, the
//! two-phase index reservation, and the four engine entry points that
//! compose `snow` + the `handshake` framing module + the `Tai64nClock` into
//! the full on-wire WireGuard handshake in both roles.
//!
//! It is split out of `engine.rs` (which holds the `WgEngine` struct, the
//! peer table, and the hot encap/decap paths) purely for modularity — these
//! methods are `impl WgEngine` blocks in the same `wg` module and reach the
//! engine's private fields directly. Keeping them here keeps `engine.rs`
//! under the 2000-LOC refactor threshold and the security-critical handshake
//! orchestration auditable in one place.
//!
//! None of this runs on the AF_XDP poll worker: the hot encap/decap paths in
//! `engine.rs` never build a `HandshakeState`. Handshake construction +
//! MAC1 keyed-BLAKE2s + X25519 happen on the control/coordinator thread.

use super::engine::{InstallSessionError, WgEngine};
use super::handshake::{self, FramingError, MSG_INIT_NOISE_LEN, MSG_RESPONSE_NOISE_LEN};
use super::session::{SessionRole, WgSession};
use super::tai64n::TAI64N_LEN;
use super::{WG_KEY_LEN, WG_MSG_INIT_LEN, WG_MSG_RESPONSE_LEN};
use snow::HandshakeState;
use std::sync::Arc;

/// Errors that can fail the slow-path WG handshake build / consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HandshakeError {
    /// The caller-supplied peer pubkey is not in the engine table.
    UnknownPeer,
    /// The on-wire framing was malformed or its MAC1 did not verify.
    Framing(FramingError),
    /// snow rejected the Noise message (bad AEAD tag, wrong key, etc.).
    Crypto,
    /// The responder's msg2 `receiver_index` did not match the
    /// `sender_index` we reserved for this handshake — a spoofed or
    /// misrouted response; drop it.
    ReceiverIndexMismatch,
    /// No pending handshake reservation matched the response's
    /// `receiver_index`. Either the response is stale (the handshake
    /// timed out and its reservation was released) or spoofed.
    NoPendingHandshake,
    /// snow `read_message` recovered the peer's static public key, but
    /// it is not a configured peer in the engine table. (Responder path.)
    UnknownInitiator,
    /// Could not allocate a fresh, collision-free local index after
    /// several attempts (astronomically unlikely with a 32-bit space).
    IndexExhausted,
    /// The output buffer was too small for the framed handshake message.
    OutputTooSmall,
    /// Internal snow / engine error building the handshake state.
    Internal,
    /// The initiation's recovered TAI64N is `<=` the greatest already
    /// accepted from this peer — a replayed or reordered type-1 message.
    /// Dropped per the WireGuard handshake anti-replay rule (#4092) after
    /// the Noise read identifies the peer, but before msg2 crypto/session
    /// install. #9908 bounds how many valid-MAC2 replays can reach that
    /// read per source; admitted replays still pay the bounded read cost.
    ReplayedInitiation,
}

impl From<FramingError> for HandshakeError {
    fn from(e: FramingError) -> Self {
        HandshakeError::Framing(e)
    }
}

/// #6227 item 5: WireGuard handshake-session mutex (`reconcile_lock` /
/// `cookie_gen`) poison recoveries, summed across every site in this file.
/// Mirrors the crate-wide poison-recovery policy established by
/// `worker_queue::lock_recover` (#1807) and `shared_ops::lock_shared_recover`
/// (#2402): a panic that poisoned the lock already happened and was
/// contained by the control-thread supervisor, so the correct recovery is
/// `clear_poison` + keep using the guarded state, not `.unwrap()` panicking
/// this thread too.
pub(in crate::afxdp::wg) static WG_HANDSHAKE_LOCK_POISON_RECOVERIES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Lock a WireGuard handshake-session mutex, RECOVERING from poison instead
/// of panicking (#6227 item 5). Every caller in this file is control-thread
/// only (never the AF_XDP poll worker, see the module doc), so a blocking
/// `lock()` — rather than `worker_queue`'s `try_lock` — is the right shape
/// here; only the poison policy is shared.
#[inline]
fn lock_recover<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            m.clear_poison();
            WG_HANDSHAKE_LOCK_POISON_RECOVERIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            eprintln!(
                "xpf-wg: handshake-session mutex poisoned by a prior panic; recovering and clearing poison"
            );
            poisoned.into_inner()
        }
    }
}

/// A handshake in progress: the snow `HandshakeState` plus the metadata
/// needed to promote it to a live session once the exchange completes.
///
/// Held in the engine keyed by OUR locally-chosen `sender_index` (the
/// reserved index). Keeping `HandshakeState` engine-internal (rather than
/// handed back to the caller and re-supplied) keeps the public API trading
/// only byte slices / `[u8;32]` and pre-stages the S3 integration where the
/// coordinator thread owns pending handshakes (SMR-6).
///
/// `pub(in crate::afxdp::wg)` so `engine.rs`'s `WgEngine` struct can name the
/// type in its `pending: RwLock<FxHashMap<u32, PendingHandshake>>` field; the
/// fields stay module-private (only this file's methods read them).
pub(in crate::afxdp::wg) struct PendingHandshake {
    /// snow state, pumped to completion on the second message. `Some` for
    /// an initiator handshake that must resume across the
    /// `create_initiation` → `consume_response` call boundary; `None` for
    /// a responder reservation, which completes synchronously inside
    /// `consume_initiation_create_response` (the snow state never needs to
    /// outlive that call, so the pending entry is a bare reservation
    /// marker).
    state: Option<HandshakeState>,
    /// The peer this handshake is with (its static public key).
    peer_pubkey: [u8; WG_KEY_LEN],
    /// Our locally-chosen index (the reservation key). The peer echoes
    /// it as the `receiver_index` of the message it sends back.
    local_index: u32,
    /// Initiator or responder — determines the session-confirmation gate
    /// (see `WgSession`). The peer's index is NOT stored here: both
    /// completion paths derive the session's `peer_index` directly from the
    /// message they just parsed (msg2.sender_index for the initiator,
    /// msg1.sender_index for the responder), so the pending record only
    /// needs the reservation key + role + identity.
    role: SessionRole,
}

impl WgEngine {
    // ===================================================================
    // WireGuard handshake — framed, both roles (#1709 S1)
    //
    // These compose snow + handshake.rs framing + the TAI64N clock into the
    // full on-wire WG handshake. They run on the CONTROL/coordinator thread
    // only — never the AF_XDP poll worker (the hot encap/decap paths never
    // build a HandshakeState). Index allocation follows a two-phase
    // reservation discipline: a local index is recorded in `pending` (which
    // the index allocator treats as reserved alongside the live demux map)
    // BEFORE the message carrying it is emitted, so a concurrent handshake
    // cannot steal it and blackhole the resulting session. Promotion installs
    // the live demux entry BEFORE clearing the reservation, so the index is
    // never absent from both maps during the hand-off. All reservation
    // mutations are serialized by `reconcile_lock`.
    // ===================================================================

    /// Reserve a fresh, collision-free local index and register a pending
    /// handshake under it. Holds the `reconcile_lock` (serialized with
    /// `install_session` / `reconcile_peers`) so the reservation is atomic
    /// w.r.t. session install and peer removal.
    ///
    /// Enforces the at-most-one-pending-per-peer cap: if the peer already
    /// has a pending reservation, it is aborted (removed from `pending` and
    /// its `pending_by_peer` marker) before the new one is recorded. A
    /// pending reservation never lives in the live-session demux map
    /// (`sessions_by_local_index`), so nothing is removed there. Returns the
    /// reserved local index.
    fn reserve_pending(
        &self,
        peer_pubkey: [u8; WG_KEY_LEN],
        state: Option<HandshakeState>,
        role: SessionRole,
    ) -> Result<u32, HandshakeError> {
        let _guard = lock_recover(&self.reconcile_lock);
        self.reserve_pending_locked(peer_pubkey, state, role)
    }

    /// Lock-free core of `reserve_pending`: caller MUST hold `reconcile_lock`.
    /// Used by the responder path, which holds the lock across
    /// reserve → build msg2 → install so a concurrent same-peer initiation
    /// cannot abort the reservation mid-completion (Codex round-2 race).
    fn reserve_pending_locked(
        &self,
        peer_pubkey: [u8; WG_KEY_LEN],
        state: Option<HandshakeState>,
        role: SessionRole,
    ) -> Result<u32, HandshakeError> {
        // Re-check the peer is configured UNDER the lock (Codex round-3
        // TOCTOU finding). `create_initiation` checks `peer_arc` before
        // acquiring reconcile_lock; if `reconcile_peers(&[])` removes the
        // peer in that gap, reserving here would create a pending entry for a
        // peer absent from the published table. `reconcile_peers`'s
        // pending-drain iterates the OLD table's pubkeys, so it would never
        // drain this entry — it would leak until response / re-add / restart.
        // Re-checking under the lock makes reservation linearizable with peer
        // removal: a peer removed before we acquire the lock yields
        // UnknownPeer and no reservation is created.
        if self.peer_arc(&peer_pubkey).is_none() {
            return Err(HandshakeError::UnknownPeer);
        }
        let by_index = self.sessions_by_local_index.read().unwrap_or_else(|e| e.into_inner());
        let mut pending = self.pending.write().unwrap_or_else(|e| e.into_inner());
        let mut by_peer = self.pending_by_peer.write().unwrap_or_else(|e| e.into_inner());

        // Abort any prior PENDING (not-yet-completed) handshake for this
        // peer (DoS bound: at most one pending reservation per peer). The
        // `pending_by_peer` marker is cleared by `clear_reservation_locked`
        // on completion, so a still-present marker can only point at an
        // incomplete reservation living in `pending` — NOT at a live
        // session in `by_index`. We therefore drop only the `pending`
        // entry and the marker; we must NOT touch `by_index`, or we would
        // blackhole an already-established session for this peer that a
        // prior completed handshake legitimately installed there.
        // #9918 F-141: this sound flood bound over-fires on crossed VALID
        // initiations (both sides hold an Initiator pending, each aborts its
        // own on the peer's valid init, both reach pending 0 with no current
        // and both Responses drop as NoPendingHandshake). Accepted: keeping
        // the Initiator would install counterpartless sessions with no idle
        // recovery, and a tie-breaker would not bind a kernel/go peer.
        // Recovery is on-demand via a fresh trigger (NoSession edge ~1 s,
        // REKEY_TIMEOUT <= 5 s); see
        // `crossed_valid_initiations_stall_then_recover_9918`.
        if let Some(old_idx) = by_peer.remove(&peer_pubkey) {
            pending.remove(&old_idx);
        }

        // Pick a fresh index not present as a live session OR a pending
        // reservation. 32-bit space; a handful of tries is plenty.
        let mut local_index = 0u32;
        let mut found = false;
        for _ in 0..8 {
            let cand = rand_u32_nonzero();
            if !by_index.contains_key(&cand) && !pending.contains_key(&cand) {
                local_index = cand;
                found = true;
                break;
            }
        }
        if !found {
            return Err(HandshakeError::IndexExhausted);
        }

        // Reserve the index by recording the pending handshake. The
        // reservation lives in `pending` (NOT in the live-session demux
        // map): the index allocator above rejects any candidate already
        // present in `pending` OR `by_index`, and the whole reserve →
        // complete sequence is serialized by `reconcile_lock`, so a
        // concurrent handshake or `install_session` cannot claim this index
        // until the completion path inserts the live session (via
        // `install_session_locked`) or releases the reservation. decap never
        // sees a half-built session because the live entry is only inserted
        // by `install_session_locked` on completion.
        pending.insert(
            local_index,
            PendingHandshake {
                state,
                peer_pubkey,
                local_index,
                role,
            },
        );
        by_peer.insert(peer_pubkey, local_index);
        Ok(local_index)
    }

    /// Test-only: deterministically exercise the under-lock peer recheck in
    /// `reserve_pending_locked` — the exact code path that closes the
    /// create_initiation TOCTOU (Codex round-4). The production gap (peer
    /// removed between `create_initiation`'s pre-lock `peer_arc` and the
    /// locked reserve) is a narrow race that a concurrency test cannot hit
    /// reliably; this drives the fixed branch directly by acquiring
    /// `reconcile_lock` and calling `reserve_pending_locked` exactly as the
    /// completion paths do, after the peer has been removed.
    #[cfg(test)]
    pub(crate) fn try_reserve_pending_for_test(
        &self,
        peer_pubkey: [u8; WG_KEY_LEN],
        role: SessionRole,
    ) -> Result<u32, HandshakeError> {
        let _guard = lock_recover(&self.reconcile_lock);
        self.reserve_pending_locked(peer_pubkey, None, role)
    }

    /// Release a pending reservation (handshake failed before completion).
    /// Removes it from `pending` and clears the `pending_by_peer` marker if
    /// it still points at this index. A pending reservation lives only in
    /// `pending` (never in the live-session demux map), so there is nothing
    /// to undo in `sessions_by_local_index`. Idempotent.
    fn release_pending(&self, local_index: u32) {
        let _guard = lock_recover(&self.reconcile_lock);
        let mut pending = self.pending.write().unwrap_or_else(|e| e.into_inner());
        if let Some(ph) = pending.remove(&local_index) {
            let mut by_peer = self.pending_by_peer.write().unwrap_or_else(|e| e.into_inner());
            // Only clear the peer→index map if it still points at us.
            if by_peer.get(&ph.peer_pubkey) == Some(&local_index) {
                by_peer.remove(&ph.peer_pubkey);
            }
        }
    }

    /// Number of in-flight (reserved-but-not-completed) handshakes. Test /
    /// diagnostic accessor.
    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> usize {
        self.pending.read().unwrap().len()
    }

    /// Build a framed WG type-1 initiation toward `peer_pubkey`.
    ///
    /// Reserves a local sender_index FIRST, builds the snow msg1 body with
    /// a fresh monotonic TAI64N as the Noise payload, and frames it (type,
    /// reserved, sender_index, body, mac1 over the responder pubkey, mac2
    /// zeros). On any failure after reservation the reservation is released.
    /// Writes the 148-byte message at `out[0..148]` and returns the chosen
    /// sender_index.
    fn create_initiation_inner(
        &self,
        peer_pubkey: &[u8; WG_KEY_LEN],
        out: &mut [u8],
    ) -> Result<u32, HandshakeError> {
        if out.len() < WG_MSG_INIT_LEN {
            return Err(HandshakeError::OutputTooSmall);
        }
        // Confirm the peer is configured before doing any work.
        if self.peer_arc(peer_pubkey).is_none() {
            return Err(HandshakeError::UnknownPeer);
        }
        let mut state = self
            .build_initiator_handshake(peer_pubkey)
            .map_err(|_| HandshakeError::Internal)?;

        // Reserve the local index + register the pending handshake BEFORE
        // emitting the message (two-phase reservation). The snow state is
        // stashed (as `Some`) after we write msg1 (which mutates it) so it
        // can resume in `consume_response`; the peer's index is learned from
        // msg2 at that point.
        let local_index =
            self.reserve_pending(*peer_pubkey, None, SessionRole::Initiator)?;

        // Build the snow msg1 body with the TAI64N as the Noise payload.
        let tai64n = self.tai64n_clock.now();
        debug_assert_eq!(tai64n.len(), TAI64N_LEN);
        let mut noise_body = [0u8; MSG_INIT_NOISE_LEN];
        let n = match state.write_message(&tai64n, &mut noise_body) {
            Ok(n) => n,
            Err(_) => {
                self.release_pending(local_index);
                return Err(HandshakeError::Crypto);
            }
        };
        if n != MSG_INIT_NOISE_LEN {
            self.release_pending(local_index);
            return Err(HandshakeError::Crypto);
        }
        // Frame it.
        if let Err(e) = handshake::build_initiation(out, local_index, &noise_body, peer_pubkey) {
            self.release_pending(local_index);
            return Err(e.into());
        }
        // #4094 PR-B: record this initiation's MAC1 (the AEAD AAD for a
        // future cookie-reply) and, if we already hold a fresh cookie for
        // this peer, stamp a valid MAC2 — so a retried initiation after a
        // cookie challenge is admitted by a responder under load. build_
        // initiation left MAC2 zero; this is the sole site that stamps it.
        self.add_initiator_macs(peer_pubkey, out, self.now_ns());
        // Stash the real (post-write) snow state into the pending entry so
        // `consume_response` can resume it.
        {
            let mut pending = self.pending.write().unwrap_or_else(|e| e.into_inner());
            if let Some(ph) = pending.get_mut(&local_index) {
                ph.state = Some(state);
            } else {
                // Reservation vanished (aborted by a concurrent init for the
                // same peer). Treat as a failed build.
                return Err(HandshakeError::NoPendingHandshake);
            }
        }
        Ok(local_index)
    }

    /// #4094 PR-B: record the just-built outbound initiation's MAC1 and
    /// stamp MAC2 if we hold a fresh cookie for `peer_pubkey`. Delegates to
    /// the per-peer [`super::cookie::InitiatorCookie`]. Called from
    /// `create_initiation_inner` after `build_initiation` has written MAC1
    /// and zeroed MAC2. Slow path (control thread only).
    fn add_initiator_macs(&self, peer_pubkey: &[u8; WG_KEY_LEN], out: &mut [u8], now_ns: u64) {
        let mut cg = lock_recover(&self.cookie_gen);
        let entry = cg
            .entry(*peer_pubkey)
            .or_insert_with(super::cookie::InitiatorCookie::new);
        entry.add_macs(out, now_ns);
    }

    /// #4094 PR-B: consume an inbound WG type-3 cookie-reply. A responder
    /// under load answers our valid-MAC1 initiation with a cookie-reply
    /// instead of a handshake response; this decrypts it and stores the
    /// cookie so our NEXT initiation to that peer carries a valid MAC2.
    ///
    /// The reply's `receiver_index` (bytes 4..8, LE) echoes the
    /// `sender_index` of the initiation that triggered it — the key of a
    /// pending initiator handshake — so we look it up to attribute the reply
    /// to a peer, then decrypt with that peer's static public key (the
    /// responder key that derives the cookie AEAD key) and OUR stored
    /// last-sent MAC1 as the AEAD AAD. Returns `true` iff a cookie was
    /// decrypted and stored. Fails closed (`false`) for a wrong-length
    /// reply, a `receiver_index` with no matching in-flight initiation, or a
    /// decryption/authentication failure.
    ///
    /// Counts internally (mirroring `classify_initiation`'s self-contained
    /// counter discipline): `hs_rx_cookie_consumed` on success,
    /// `hs_rx_cookie_unsupported` on any drop. Slow path (control thread
    /// only).
    pub(crate) fn consume_cookie_reply(&self, reply: &[u8], now_ns: u64) -> bool {
        let ok = self.consume_cookie_reply_inner(reply, now_ns);
        if ok {
            super::counters::WgCounters::bump(&self.counters.hs_rx_cookie_consumed);
        } else {
            super::counters::WgCounters::bump(&self.counters.hs_rx_cookie_unsupported);
        }
        ok
    }

    fn consume_cookie_reply_inner(&self, reply: &[u8], now_ns: u64) -> bool {
        if reply.len() != super::cookie::WG_MSG_COOKIE_LEN {
            return false;
        }
        let recv_index = u32::from_le_bytes([reply[4], reply[5], reply[6], reply[7]]);
        let Some(peer_pubkey) = self.peer_for_pending_index(recv_index) else {
            return false;
        };
        let mut cg = lock_recover(&self.cookie_gen);
        let entry = cg
            .entry(peer_pubkey)
            .or_insert_with(super::cookie::InitiatorCookie::new);
        entry.consume_reply(reply, &peer_pubkey, now_ns)
    }

    /// The peer a pending initiator handshake with local index `index` is
    /// with, if any. Used by `consume_cookie_reply` to attribute an inbound
    /// cookie-reply (whose `receiver_index` echoes our `sender_index`) to a
    /// peer. Defined here because `PendingHandshake`'s fields are private to
    /// this module.
    fn peer_for_pending_index(&self, index: u32) -> Option<[u8; WG_KEY_LEN]> {
        self.pending
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&index)
            .map(|ph| ph.peer_pubkey)
    }

    /// Consume a peer's framed WG type-2 response, complete the initiator
    /// handshake, and install the derived transport session.
    ///
    /// Verifies the framing (mac1 over OUR public key) and that the
    /// response's `receiver_index` matches a pending INITIATOR reservation we
    /// hold. On success the pending handshake is promoted to a live
    /// `WgSession` (initiator role, confirmed at install) and registered for
    /// inbound demux. Returns the local index of the installed session.
    ///
    /// Invariants this method preserves (Codex code-review rounds 1 & 2):
    ///   - The ENTIRE completion (validate → take snow state → Noise read →
    ///     install → clear reservation) runs while holding `reconcile_lock`.
    ///     `reserve_pending` / `release_pending` / `reconcile_peers` also take
    ///     `reconcile_lock`, so no concurrent re-initiation to the same peer
    ///     can abort this in-flight reservation, and no concurrent
    ///     reservation/install can observe a window where the index is absent
    ///     from both `pending` and `sessions_by_local_index`. The Noise read
    ///     is slow-path crypto run under the slow-path lock — handshakes are
    ///     never on the AF_XDP hot path, so the lock hold is acceptable.
    ///     (Round-2 finding: the earlier lock-drop-during-read version still
    ///     allowed the per-peer abort to remove the entry mid-read.)
    ///   - A msg2 that fails Noise authentication does NOT destroy the
    ///     reservation. MAC1 keys on the (public) initiator pubkey, so an
    ///     on-path observer can forge a msg2 with a valid MAC1 but a bogus
    ///     Noise body; if such a forgery consumed the pending state, it would
    ///     DoS the real handshake. snow's `read_message` restores its
    ///     symmetric state on a failed read, so we put the borrowed
    ///     `HandshakeState` back and keep waiting for a valid (or
    ///     retransmitted) response.
    fn consume_response_inner(
        &self,
        msg: &[u8],
    ) -> Result<([u8; WG_KEY_LEN], u32), HandshakeError> {
        let parsed = handshake::parse_response_with_key(msg, &self.mac1_key)?;
        let local_index = parsed.receiver_index;

        // Hold reconcile_lock across the whole completion so the reservation
        // cannot be aborted out from under us and the index never disappears
        // from both maps.
        let _guard = lock_recover(&self.reconcile_lock);

        // Validate + take the snow state. The entry stays in `pending`
        // (state = None) so the index remains reserved.
        let (peer_pubkey, mut state) = {
            let mut pending = self.pending.write().unwrap_or_else(|e| e.into_inner());
            let ph = pending
                .get_mut(&local_index)
                .ok_or(HandshakeError::NoPendingHandshake)?;
            if ph.role != SessionRole::Initiator {
                return Err(HandshakeError::ReceiverIndexMismatch);
            }
            let peer_pubkey = ph.peer_pubkey;
            let state = ph.state.take().ok_or(HandshakeError::NoPendingHandshake)?;
            (peer_pubkey, state)
        };

        // Drive snow to completion. On a failed read, snow restored its
        // symmetric state, so put the HandshakeState back into the (still
        // locked, still present) reservation — a forged/garbled msg2 must not
        // kill the pending handshake.
        let mut sink = [0u8; MSG_RESPONSE_NOISE_LEN];
        if state.read_message(parsed.noise_body, &mut sink).is_err() {
            if let Some(ph) = self
                .pending
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&local_index)
            {
                ph.state = Some(state);
            }
            return Err(HandshakeError::Crypto);
        }
        let transport = match state.into_stateless_transport_mode() {
            Ok(t) => t,
            Err(_) => {
                // Unreachable after a successful msg2 read; clear the
                // reservation rather than leak it.
                self.clear_reservation_locked(local_index, &peer_pubkey);
                return Err(HandshakeError::Crypto);
            }
        };
        let session = Arc::new(WgSession::new_with_role(
            transport,
            local_index,
            parsed.sender_index,
            peer_pubkey,
            SessionRole::Initiator,
            self.now_ns(),
        ));
        // #1888 S5: a valid msg2 is an authenticated RECEIVE — stamp
        // last_recv_any (clears the T7 no-reply arm) per the §3
        // any-authenticated-receive rule. Done here at the completion
        // site so it orders before any same-iteration TUN egress.
        if let Some(peer) = self.peer_arc(&peer_pubkey) {
            peer.note_authenticated_recv(self.now_ns());
        }
        // Install the live session, then clear the reservation — both under
        // the reconcile_lock we already hold (install_session_locked must NOT
        // re-take it).
        let result = match self.install_session_locked(&peer_pubkey, session) {
            Ok(()) => Ok((peer_pubkey, local_index)),
            Err(InstallSessionError::UnknownPeer) => Err(HandshakeError::UnknownPeer),
            Err(InstallSessionError::LocalIndexCollision) => Err(HandshakeError::Internal),
        };
        self.clear_reservation_locked(local_index, &peer_pubkey);
        result
    }

    /// Clear a reservation's `pending` entry and its `pending_by_peer` marker
    /// (if it still points at this index). Caller MUST hold `reconcile_lock`.
    fn clear_reservation_locked(&self, local_index: u32, peer_pubkey: &[u8; WG_KEY_LEN]) {
        let mut pending = self.pending.write().unwrap_or_else(|e| e.into_inner());
        pending.remove(&local_index);
        let mut by_peer = self.pending_by_peer.write().unwrap_or_else(|e| e.into_inner());
        if by_peer.get(peer_pubkey) == Some(&local_index) {
            by_peer.remove(peer_pubkey);
        }
    }

    /// Responder path: parse a peer's framed WG type-1 initiation, run snow
    /// to recover the peer's static key + TAI64N, identify the configured
    /// peer, build a framed WG type-2 response, reserve our responder
    /// sender_index, and install the derived (unconfirmed) transport
    /// session. Writes the 92-byte response at `out[0..92]` and returns
    /// `(peer_pubkey, our_sender_index)` — pubkey first, matching the return
    /// expression below.
    fn consume_initiation_create_response_inner(
        &self,
        msg: &[u8],
        out: &mut [u8],
    ) -> Result<([u8; WG_KEY_LEN], u32), HandshakeError> {
        if out.len() < WG_MSG_RESPONSE_LEN {
            return Err(HandshakeError::OutputTooSmall);
        }
        // Verify framing (mac1 over OUR public key) and recover the body.
        let parsed = handshake::parse_initiation_with_key(msg, &self.mac1_key)?;
        let peer_sender_index = parsed.sender_index;

        // Run the responder Noise read to recover the peer static key.
        let mut state = self
            .build_responder_handshake()
            .map_err(|_| HandshakeError::Internal)?;
        let mut ts_sink = [0u8; TAI64N_LEN];
        // snow writes the recovered Noise payload (the peer's TAI64N) into
        // ts_sink. A compliant responder uses it for handshake anti-replay:
        // after identifying the peer below (#4092) we reject an initiation
        // whose TAI64N is `<=` the greatest already accepted from that peer.
        // We must READ it here regardless so snow advances the transcript.
        if state.read_message(parsed.noise_body, &mut ts_sink).is_err() {
            return Err(HandshakeError::Crypto);
        }
        // Identify the initiator from the recovered static key.
        let peer_pubkey = {
            let rs = state.get_remote_static().ok_or(HandshakeError::Crypto)?;
            if rs.len() != WG_KEY_LEN {
                return Err(HandshakeError::Crypto);
            }
            let mut pk = [0u8; WG_KEY_LEN];
            pk.copy_from_slice(rs);
            pk
        };
        let Some(peer_config) = self.peer_config(&peer_pubkey) else {
            return Err(HandshakeError::UnknownInitiator);
        };

        // #4092 responder handshake anti-replay. The peer is now
        // identified (from the static key snow recovered above); reject a
        // replayed or reordered initiation — one whose TAI64N is `<=` the
        // greatest we have already accepted from this peer — BEFORE the
        // expensive msg2 build / session install / liveness stamp, matching
        // the WireGuard whitepaper §5.1 rule and the kernel's
        // `memcmp(timestamp, last_timestamp) > 0` gate. The check-and-update
        // is atomic on the peer's own high-water lock, so two concurrent
        // initiations from the same peer cannot both pass. A peer that
        // vanished between the two table loads is treated as unknown.
        let peer = self
            .peer_arc(&peer_pubkey)
            .ok_or(HandshakeError::UnknownInitiator)?;
        if !peer.check_and_update_tai64n(&ts_sink) {
            return Err(HandshakeError::ReplayedInitiation);
        }

        // #1434 B2: the responder learns the peer only AFTER reading
        // msg1, but the PSK is mixed during the msg2 WRITE (the Psk(2)
        // token sits at the end of the IKpsk2 second message). So set
        // the identified peer's PSK now, before write_message(msg2),
        // overriding the zero PSK the builder pre-set. A peer with no
        // configured PSK keeps the zero key (pre-#1434 behavior). snow
        // 0.10.0 exposes HandshakeState::set_psk for exactly this
        // "identify peer, then pick PSK" responder ordering. #2836: the
        // PSK comes from the immutable per-snapshot config bundle.
        let psk = peer_config.preshared_key();
        if state.set_psk(2, &psk).is_err() {
            return Err(HandshakeError::Crypto);
        }

        // Hold reconcile_lock across reserve → build msg2 → install so a
        // concurrent same-peer initiation cannot abort our reservation between
        // reserve and install (Codex round-2 race). The responder completes
        // synchronously in this single call, so the pending entry is a bare
        // reservation marker (state = None).
        let _guard = lock_recover(&self.reconcile_lock);
        let local_index =
            self.reserve_pending_locked(peer_pubkey, None, SessionRole::Responder)?;

        // Build the snow msg2 body (empty Noise payload).
        let mut noise_body = [0u8; MSG_RESPONSE_NOISE_LEN];
        let n = match state.write_message(&[], &mut noise_body) {
            Ok(n) => n,
            Err(_) => {
                self.clear_reservation_locked(local_index, &peer_pubkey);
                return Err(HandshakeError::Crypto);
            }
        };
        if n != MSG_RESPONSE_NOISE_LEN {
            self.clear_reservation_locked(local_index, &peer_pubkey);
            return Err(HandshakeError::Crypto);
        }
        // Frame the response: receiver_index echoes the initiator's
        // sender_index; mac1 keys on the INITIATOR's public key (recipient).
        if let Err(e) = handshake::build_response(
            out,
            local_index,
            peer_sender_index,
            &noise_body,
            &peer_pubkey,
        ) {
            self.clear_reservation_locked(local_index, &peer_pubkey);
            return Err(e.into());
        }

        // The handshake is complete on our side after writing msg2.
        let transport = match state.into_stateless_transport_mode() {
            Ok(t) => t,
            Err(_) => {
                self.clear_reservation_locked(local_index, &peer_pubkey);
                return Err(HandshakeError::Crypto);
            }
        };
        let session = Arc::new(WgSession::new_with_role(
            transport,
            local_index,
            peer_sender_index,
            peer_pubkey,
            SessionRole::Responder,
            self.now_ns(),
        ));
        // #1888 S5: a valid msg1 is an authenticated RECEIVE — stamp
        // last_recv_any (clears the T7 no-reply arm), §3 rule. Reuse the
        // `peer` Arc resolved for the #4092 anti-replay check above (same
        // pubkey → same long-lived `Arc<Peer>`).
        peer.note_authenticated_recv(self.now_ns());
        // Install the live session (UNCONFIRMED — egress gated until the first
        // authenticated inbound transport record), then clear the reservation.
        // Both under the reconcile_lock we already hold.
        let install = match self.install_session_locked(&peer_pubkey, session) {
            Ok(()) => Ok(()),
            Err(InstallSessionError::UnknownPeer) => Err(HandshakeError::UnknownPeer),
            Err(InstallSessionError::LocalIndexCollision) => Err(HandshakeError::Internal),
        };
        self.clear_reservation_locked(local_index, &peer_pubkey);
        install?;
        Ok((peer_pubkey, local_index))
    }

}

// ===================================================================
// #1865: telemetry-counting wrappers around the three slow-path
// handshake entry points. The *_inner bodies above are unchanged; the
// wrappers own the Result -> counter mapping so a call site can never
// bypass accounting. Completion stamps use the wg-local
// CLOCK_MONOTONIC reader (counters::monotonic_now_ns — same domain as
// the coordinator's monotonic_nanos, which the status snapshot uses
// for the wall-clock conversion).
// ===================================================================
impl WgEngine {
    /// Build a framed WG type-1 initiation toward `peer_pubkey`.
    /// Counted: Ok → `hs_initiations_created` ("created", NOT "sent" —
    /// the UDP send happens at the call site and can fail; see
    /// `hs_send_errors`); Err → `hs_initiation_build_failures` (all
    /// variants folded; previously discarded entirely by the
    /// `if let Ok` at the drive_initiation call site).
    pub(crate) fn create_initiation(
        &self,
        peer_pubkey: &[u8; WG_KEY_LEN],
        out: &mut [u8],
    ) -> Result<u32, HandshakeError> {
        let res = self.create_initiation_inner(peer_pubkey, out);
        match &res {
            Ok(_) => super::counters::WgCounters::bump(&self.counters.hs_initiations_created),
            Err(_) => super::counters::WgCounters::bump(
                &self.counters.hs_initiation_build_failures,
            ),
        }
        res
    }

    /// Initiator path: consume a framed WG type-2 response. Counted:
    /// Ok → `hs_completions_initiator` + completion stamp; Err →
    /// per-reason `hs_rx_drops_*`.
    pub(crate) fn consume_response(
        &self,
        msg: &[u8],
    ) -> Result<([u8; WG_KEY_LEN], u32), HandshakeError> {
        match self.consume_response_inner(msg) {
            Ok(result) => {
                super::counters::WgCounters::bump(&self.counters.hs_completions_initiator);
                self.counters
                    .record_handshake_complete(super::counters::monotonic_now_ns());
                Ok(result)
            }
            Err(e) => Err(self.counters.count_handshake_rx_err(e)),
        }
    }

    /// Responder path: consume a framed WG type-1 initiation and build
    /// the type-2 response. Counted: Ok → `hs_responses_created` +
    /// completion stamp (this single increment site is ALSO the
    /// responder-completion event — the Prometheus completions metric
    /// emits it under role="responder"; the UDP response send and its
    /// failure are the call site's `hs_send_errors`); Err →
    /// per-reason `hs_rx_drops_*`.
    pub(crate) fn consume_initiation_create_response(
        &self,
        msg: &[u8],
        out: &mut [u8],
    ) -> Result<([u8; WG_KEY_LEN], u32), HandshakeError> {
        match self.consume_initiation_create_response_inner(msg, out) {
            Ok(ok) => {
                super::counters::WgCounters::bump(&self.counters.hs_responses_created);
                self.counters
                    .record_handshake_complete(super::counters::monotonic_now_ns());
                Ok(ok)
            }
            Err(e) => Err(self.counters.count_handshake_rx_err(e)),
        }
    }
}

/// Allocate a non-zero pseudo-random u32 for a handshake index. WG indices
/// are opaque demux tags; uniqueness (not unpredictability) is what matters
/// for correctness, but a random draw keeps collisions astronomically rare.
/// Uses the OS RNG via `getrandom` (pulled in transitively); falls back to a
/// time-seeded value only if that fails (never expected on Linux).
fn rand_u32_nonzero() -> u32 {
    let mut buf = [0u8; 4];
    let v = if getrandom::getrandom(&mut buf).is_ok() {
        u32::from_ne_bytes(buf)
    } else {
        // Extremely unlikely fallback; still non-zero below.
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0x9e37_79b9)
    };
    if v == 0 { 0x9e37_79b9 } else { v }
}
