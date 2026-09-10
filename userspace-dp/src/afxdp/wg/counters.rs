//! #1865: operator-visible WireGuard telemetry counters.
//!
//! One `WgCounters` per `WgEngine` (== per tunnel in S2a). All fields
//! are relaxed `AtomicU64`s: increment sites are either the per-tunnel
//! control thread (slow path) or the rarely-hit transit encap path in
//! `frame/wg.rs` (which already heap-allocates per packet), and the
//! single reader is the 1/s status poll. Multi-counter snapshots are
//! NOT transactional — the poll reads each atomic independently while
//! the control thread increments, so e.g. `decap_packets` may be one
//! ahead of `decap_bytes` within one snapshot. Fine for observability.
//!
//! Counter lifetime follows the engine `Arc`:
//!   - survives control-thread tombstone/respawn cycles (#1872) and
//!     unrelated commits (engine reuse via `wg_identity_unchanged`);
//!   - resets to zero when a commit CHANGES the crypto identity and
//!     `populate_wg_engines` rebuilds the engine. Deliberate: under
//!     #1873's positional id renumbering, inheriting the same-id
//!     previous engine's counters would attribute a DIFFERENT
//!     tunnel's history to this one. Prometheus `rate()` tolerates
//!     monotonic resets, and the reset is itself a faithful signal
//!     that every session was rebuilt.
//!
//! Reason mapping is consolidated here (`count_decap_err`,
//! `count_encap_err`, `count_handshake_rx_err`) so the engine return
//! sites stay one-liners and a future error-variant addition fails
//! compilation here rather than silently going uncounted.
//!
//! Per-peer TAI64N anti-replay rejects ARE counted
//! (`hs_rx_drops_replayed_init`, #4092 — the responder rejects an
//! initiation whose TAI64N is `<=` the greatest already accepted from
//! that peer). The responder cookie-reply / MAC2 under-load path is now
//! counted too (#4094 PR-A): `hs_cookie_replies_sent`,
//! `hs_rx_under_load_no_mac2`, `hs_rx_under_load_mac2_ok`, and
//! `hs_cookie_reply_budget_drops`. The initiator-side cookie-reply CONSUME
//! (#4094 PR-B) is now counted: `hs_rx_cookie_consumed` (a cookie-reply we
//! decrypted and stored, arming a valid MAC2 on our next initiation) and
//! `hs_rx_cookie_unsupported` (now a real site: a cookie-reply we could not
//! attribute to an in-flight initiation or could not decrypt).

use super::engine::{DecapError, EncapError};
use super::handshake::FramingError;
use super::handshake_session::HandshakeError;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub(crate) struct WgCounters {
    // --- handshake ---
    /// `create_initiation` Ok — msg1 BUILT (not necessarily sent; a
    /// failed send shows in `hs_send_errors`, so the #1736 EINVAL
    /// fingerprint is `created↑ + send_errors↑ + completions flat`).
    pub(crate) hs_initiations_created: AtomicU64,
    /// `create_initiation` Err, all variants folded (previously
    /// discarded by the `if let Ok` at the drive_initiation call site).
    pub(crate) hs_initiation_build_failures: AtomicU64,
    /// `consume_initiation_create_response` Ok — responder accepted
    /// msg1, built msg2, installed the (unconfirmed) session. This is
    /// ALSO the responder-completion event (single increment site; the
    /// Prometheus completions metric emits it under role="responder").
    pub(crate) hs_responses_created: AtomicU64,
    /// `consume_response` Ok — initiator-side handshake completion.
    pub(crate) hs_completions_initiator: AtomicU64,
    /// Inbound handshake-message drops by reason (msg1 + msg2 paths).
    pub(crate) hs_rx_drops_mac1_mismatch: AtomicU64,
    pub(crate) hs_rx_drops_malformed: AtomicU64,
    pub(crate) hs_rx_drops_crypto: AtomicU64,
    pub(crate) hs_rx_drops_unknown_peer: AtomicU64,
    pub(crate) hs_rx_drops_stale_response: AtomicU64,
    pub(crate) hs_rx_drops_index_exhausted: AtomicU64,
    /// #4092 responder handshake anti-replay rejects: a type-1
    /// initiation whose recovered TAI64N was `<=` the greatest already
    /// accepted from that peer (a replay or a reorder). Distinct from
    /// the transport-record `decap_drops_replay` window; this is the
    /// HANDSHAKE anti-replay gate.
    pub(crate) hs_rx_drops_replayed_init: AtomicU64,
    /// Inbound type-3 (cookie-reply) datagrams DROPPED by the initiator
    /// (#4094 PR-B): a reply we could not attribute to an in-flight
    /// initiation (`receiver_index` matched no pending handshake) or could
    /// not decrypt (wrong key / bad AAD / tampered). Successful consumes are
    /// counted separately as `hs_rx_cookie_consumed`. Same wire name as the
    /// former S7 placeholder for Go-side compatibility; the meaning is now a
    /// real drop-by-reason rather than "unsupported".
    pub(crate) hs_rx_cookie_unsupported: AtomicU64,
    /// #4094 PR-B: inbound type-3 cookie-replies successfully CONSUMED by the
    /// initiator — decrypted with the responder's public-key-derived key and
    /// our last-sent MAC1 as AAD, and stored so the NEXT initiation to that
    /// peer carries a valid MAC2. The initiator half of the under-load DoS
    /// mitigation working end-to-end (pairs with the responder's
    /// `hs_cookie_replies_sent` / `hs_rx_under_load_mac2_ok`).
    pub(crate) hs_rx_cookie_consumed: AtomicU64,
    /// #4094 PR-A: WG type-3 CookieReply messages the RESPONDER emitted —
    /// one per under-load, valid-MAC1, missing/bad-MAC2 initiation that was
    /// challenged instead of handshaked.
    pub(crate) hs_cookie_replies_sent: AtomicU64,
    /// #4094 PR-A: under-load initiations DROPPED for a missing/bad MAC2
    /// (a cookie challenge was issued in reply). The DoS-mitigation hit
    /// count — these are the forged/unprimed initiations the responder
    /// refused to spend a Noise handshake on.
    pub(crate) hs_rx_under_load_no_mac2: AtomicU64,
    /// #4094 PR-A: under-load initiations that carried a VALID MAC2 and
    /// were allowed through to the handshake (the cookie mechanism working
    /// end-to-end — a primed peer completing under load).
    pub(crate) hs_rx_under_load_mac2_ok: AtomicU64,
    /// #4094 PR-A: under-load initiations dropped WITHOUT a cookie reply.
    /// Primarily the per-window cookie-reply emission budget being exhausted
    /// (item 6 storm bound) — non-zero means the generated-reply budget is
    /// clamping a heavy valid-MAC1 flood. #4332 folds in the per-SOURCE
    /// token-bucket throttle drops (a single flooding source, or a
    /// full-source-table fail-closed) — a bounded hardening layered before the
    /// global budget; both drops mean "under load, challenged but no reply
    /// emitted". Also covers the fail-closed drop when the OS CSPRNG is
    /// unavailable for the secret/nonce (BUG-2; impossible on Linux, so
    /// effectively budget/source-throttle-only in practice).
    pub(crate) hs_cookie_reply_budget_drops: AtomicU64,
    /// Type byte ∉ {1,2,3,4}. Zero-length UDP datagrams never reach
    /// type dispatch (consumed by the `Ok(_) => break` recv arm in
    /// wg_control), so runts are deliberately NOT counted here.
    pub(crate) rx_unknown_type: AtomicU64,
    /// `wg_send_to` failures for handshake messages — BOTH the
    /// initiation send and the (previously `let _ =`-discarded)
    /// response send.
    pub(crate) hs_send_errors: AtomicU64,
    /// `request_handshake` accepted a NoSession edge (rate-limited
    /// worker→control "please initiate"). Ties an encap-drop burst to
    /// the re-initiation it triggered.
    pub(crate) hs_requests_armed: AtomicU64,

    // --- transport decap (inbound) ---
    pub(crate) decap_packets: AtomicU64,
    /// Inner-IP bytes (un-padded), symmetric with `encap_bytes`. These
    /// are logical tunnel payload bytes — they will NOT match a kernel
    /// peer's `wg show` transfer numbers (which include WG overhead).
    pub(crate) decap_bytes: AtomicU64,
    /// Authenticated ZERO-length transport records (WG persistent
    /// keepalives: pad_to_16(0) == 0 ⇒ snow yields n == 0). Counted
    /// after the replay gate, before the inner parse — withOUT this
    /// class peel a keepalive peer would emit steady
    /// `decap_drops_malformed_inner` false alarms. NOT a drop counter.
    pub(crate) decap_keepalives: AtomicU64,
    pub(crate) decap_drops_malformed_header: AtomicU64,
    pub(crate) decap_drops_unknown_session: AtomicU64,
    pub(crate) decap_drops_counter_ceiling: AtomicU64,
    pub(crate) decap_drops_crypto: AtomicU64,
    pub(crate) decap_drops_replay: AtomicU64,
    pub(crate) decap_drops_allowed_ips: AtomicU64,
    /// MalformedInner with n > 0 only — the n == 0 keepalive class is
    /// peeled off into `decap_keepalives` above.
    pub(crate) decap_drops_malformed_inner: AtomicU64,
    pub(crate) decap_drops_buffer: AtomicU64,
    /// #9521: authenticated TRANSPORT records that reached an UNSTEERED listen
    /// port's control-thread socket and were dropped instead of being written
    /// to the wgN TUN, where the kernel would have forwarded their plaintext
    /// with no zone policy. Counted after authentication, so an unauthenticated
    /// sender cannot move it.
    pub(crate) rx_unsteered_transport_drops: AtomicU64,
    /// #9594: authenticated transport records for the STEERED listen port that
    /// reached its control thread through the kernel on an ingress the XDP shim
    /// adjudicates — which happens only while the dataplane is degraded — whose
    /// inner packet was TRANSIT. Dropped instead of written to the wgN TUN, where
    /// the kernel would have forwarded it with no zone policy. Inner packets
    /// addressed to the firewall itself are still delivered.
    pub(crate) rx_degraded_transit_drops: AtomicU64,

    // --- transport encap (egress) ---
    pub(crate) encap_packets: AtomicU64,
    pub(crate) encap_bytes: AtomicU64,
    /// `EncapError::NoSession` from the no-current-session arm ONLY.
    pub(crate) encap_drops_no_session: AtomicU64,
    /// `EncapError::NoSession` from the `is_confirmed()` gate arm —
    /// egress was asked to encrypt on an UNCONFIRMED `current` session.
    /// Distinguishable so an operator does not tcpdump a transient rekey
    /// blip (#1736 AGY r2). Counter-only split: the returned error stays
    /// `NoSession` and every caller contract is untouched. After the
    /// #3882 3-slot keypair fix an unconfirmed responder keypair lives
    /// in `next`, never `current`, so the natural responder-rekey path
    /// no longer reaches this gate (it reports `encap_drops_no_session`
    /// while the confirmed `current` keeps serving egress); the gate
    /// remains as a defense-in-depth invariant that egress never uses an
    /// unconfirmed session.
    pub(crate) encap_drops_unconfirmed: AtomicU64,
    pub(crate) encap_drops_rekey_required: AtomicU64,
    /// UnknownPeer | CryptoFailed | BufferTooSmall — all
    /// "structurally impossible unless bug" classes, folded. Split if
    /// ever nonzero in the field.
    pub(crate) encap_drops_other: AtomicU64,
    /// Exact pad-aware MTU-guard drops, BOTH egress sites (control
    /// thread TUN-read + frame/wg.rs transit). The #1736 v4-mapped
    /// blackhole counter.
    pub(crate) encap_mtu_drops: AtomicU64,
    /// `wg_send_to` failures for encap'd transport datagrams.
    pub(crate) transport_send_errors: AtomicU64,
    /// `tun.write_all` failures delivering decap'd inner packets.
    pub(crate) tun_write_errors: AtomicU64,
    /// Inner packets drained (and dropped) off the TUN while a
    /// responder-only peer has no learned endpoint to send to.
    pub(crate) tun_rx_drops_no_endpoint: AtomicU64,

    // --- #1888 S5 timers ---
    /// Encap refused: current session past REJECT_AFTER_TIME (the
    /// per-use T3 gate; arms the rekey edge).
    pub(crate) encap_drops_expired: AtomicU64,
    /// Decap refused: demuxed session past REJECT_AFTER_TIME
    /// (drop-only; never arms the rekey edge — Codex r1 M4).
    pub(crate) decap_drops_expired: AtomicU64,
    /// Sessions torn down by the control thread's `expire_sessions`
    /// pass (current + previous + next slots, #3882).
    pub(crate) sessions_expired: AtomicU64,
    /// Timer-driven handshake initiations by reason: `age` = the rekey
    /// edge (T1 send-age / T2 receive-horizon / send-side T3),
    /// `dead_peer` = T7 no-reply reinit, `keepalive_no_session` = T8
    /// persistent-keepalive due with no usable session.
    pub(crate) rekeys_initiated_age: AtomicU64,
    pub(crate) rekeys_initiated_dead_peer: AtomicU64,
    pub(crate) rekeys_initiated_keepalive_no_session: AtomicU64,
    /// Keepalives SENT: T6 passive (incl. the post-msg2
    /// key-confirmation keepalive) vs T8 persistent. RX side is the
    /// pre-existing `decap_keepalives`.
    pub(crate) keepalives_tx_passive: AtomicU64,
    pub(crate) keepalives_tx_persistent: AtomicU64,
    /// Pending-handshake reservations released by the T5
    /// attempt-window give-up (`abort_pending_for_peer`).
    pub(crate) pending_aborted_attempt_window: AtomicU64,

    // --- state (not a counter) ---
    /// Monotonic (CLOCK_MONOTONIC ns) stamp of the most recent
    /// handshake completion, either role. 0 = never. Converted to
    /// wall-clock epoch seconds at status-snapshot time; the stored
    /// stamp stays monotonic so an NTP step fences nothing (#1792).
    pub(crate) last_handshake_complete_ns: AtomicU64,
}

impl WgCounters {
    #[inline]
    pub(crate) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a decap failure by reason and hand the error back, so the
    /// engine's return sites stay `Err(self.counters.count_decap_err(e))`
    /// one-liners. The keepalive class never routes through here (it is
    /// counted at its dedicated site inside `try_decap`).
    pub(crate) fn count_decap_err(&self, e: DecapError) -> DecapError {
        let c = match e {
            DecapError::MalformedHeader | DecapError::ShortRecord => {
                &self.decap_drops_malformed_header
            }
            DecapError::UnknownSession => &self.decap_drops_unknown_session,
            DecapError::CounterRejectAfterMessages => &self.decap_drops_counter_ceiling,
            DecapError::CryptoFailed => &self.decap_drops_crypto,
            DecapError::ReplayDuplicate | DecapError::ReplayOutOfWindow => {
                &self.decap_drops_replay
            }
            DecapError::AllowedIpsViolation => &self.decap_drops_allowed_ips,
            DecapError::MalformedInner(_) => &self.decap_drops_malformed_inner,
            DecapError::BufferTooSmall => &self.decap_drops_buffer,
            DecapError::Expired => &self.decap_drops_expired,
            // #7230: a keepalive is not a DROP — it is an authenticated
            // record with nothing to deliver — so it keeps its own
            // counter rather than joining decap_drops_malformed_inner.
            // This arm exists because the match is exhaustive with no
            // `_`: adding a DecapError variant cannot silently become
            // uncounted.
            DecapError::Keepalive(_) => &self.decap_keepalives,
        };
        Self::bump(c);
        e
    }

    /// Count an encap failure by reason and hand the error back. The
    /// two `NoSession` arms inside `try_encap` do NOT route through
    /// here — they bump `encap_drops_no_session` /
    /// `encap_drops_unconfirmed` directly at their distinct sites (the
    /// returned variant is the same `NoSession`, so this mapper cannot
    /// tell them apart).
    pub(crate) fn count_encap_err(&self, e: EncapError) -> EncapError {
        let c = match e {
            EncapError::RekeyRequired => &self.encap_drops_rekey_required,
            // Defensive: NoSession should never reach this mapper (see
            // doc above); attribute to no_session rather than lose it.
            EncapError::NoSession => &self.encap_drops_no_session,
            EncapError::UnknownPeer
            | EncapError::CryptoFailed
            | EncapError::BufferTooSmall => &self.encap_drops_other,
        };
        Self::bump(c);
        e
    }

    /// Count an inbound handshake-message drop by reason (msg1 + msg2
    /// consume paths) and hand the error back.
    pub(crate) fn count_handshake_rx_err(&self, e: HandshakeError) -> HandshakeError {
        let c = match &e {
            HandshakeError::Framing(FramingError::Mac1Mismatch) => {
                &self.hs_rx_drops_mac1_mismatch
            }
            HandshakeError::Framing(_) | HandshakeError::OutputTooSmall => {
                &self.hs_rx_drops_malformed
            }
            HandshakeError::Crypto | HandshakeError::Internal => &self.hs_rx_drops_crypto,
            HandshakeError::UnknownInitiator | HandshakeError::UnknownPeer => {
                &self.hs_rx_drops_unknown_peer
            }
            HandshakeError::NoPendingHandshake | HandshakeError::ReceiverIndexMismatch => {
                &self.hs_rx_drops_stale_response
            }
            HandshakeError::IndexExhausted => &self.hs_rx_drops_index_exhausted,
            HandshakeError::ReplayedInitiation => &self.hs_rx_drops_replayed_init,
        };
        Self::bump(c);
        e
    }

    /// Stamp a handshake completion (either role) at `now_ns`
    /// (CLOCK_MONOTONIC). `max(1)` keeps a (test-clock) completion at
    /// t=0 distinguishable from "never".
    pub(crate) fn record_handshake_complete(&self, now_ns: u64) {
        self.last_handshake_complete_ns
            .store(now_ns.max(1), Ordering::Relaxed);
    }
}

/// CLOCK_MONOTONIC nanoseconds. Same clock domain (and same
/// implementation) as `crate::afxdp::neighbor::monotonic_nanos` — the
/// status snapshot converts stamps recorded here using that helper's
/// `now_mono`, so the domains MUST match. Duplicated (6 lines) rather
/// than imported to preserve the wg module's documented isolation from
/// the wider afxdp web (wg/mod.rs "Why this module exists in
/// isolation").
pub(crate) fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

#[cfg(test)]
mod counters_tests {
    use super::*;

    #[test]
    fn decap_err_mapping_covers_every_variant() {
        let c = WgCounters::default();
        for e in [
            DecapError::MalformedHeader,
            DecapError::ShortRecord,
            DecapError::UnknownSession,
            DecapError::CounterRejectAfterMessages,
            DecapError::CryptoFailed,
            DecapError::ReplayDuplicate,
            DecapError::ReplayOutOfWindow,
            DecapError::AllowedIpsViolation,
            // #7686/#7230: the two identity-carrying variants. The key is a
            // fixture value — this cell is about the MAPPING, not attribution
            // (that is bound in wg/tests.rs) — but they must be present or the
            // test does not meet its own name.
            DecapError::MalformedInner([7u8; 32]),
            DecapError::Keepalive([9u8; 32]),
            DecapError::BufferTooSmall,
            DecapError::Expired,
        ] {
            let back = c.count_decap_err(e.clone());
            assert_eq!(back, e, "mapper must hand the error back unchanged");
        }
        assert_eq!(c.decap_drops_malformed_header.load(Ordering::Relaxed), 2);
        assert_eq!(c.decap_drops_replay.load(Ordering::Relaxed), 2);
        assert_eq!(c.decap_drops_unknown_session.load(Ordering::Relaxed), 1);
        assert_eq!(c.decap_drops_counter_ceiling.load(Ordering::Relaxed), 1);
        assert_eq!(c.decap_drops_crypto.load(Ordering::Relaxed), 1);
        assert_eq!(c.decap_drops_allowed_ips.load(Ordering::Relaxed), 1);
        assert_eq!(c.decap_drops_malformed_inner.load(Ordering::Relaxed), 1);
        // #7230: a keepalive is NOT a drop, so it must land on its own
        // counter. Absent this the test's name ("covers every variant") was a
        // claim it did not meet: Keepalive was missing from the list above
        // from the moment #7230 added it.
        assert_eq!(c.decap_keepalives.load(Ordering::Relaxed), 1);
        assert_eq!(c.decap_drops_buffer.load(Ordering::Relaxed), 1);
        assert_eq!(c.decap_drops_expired.load(Ordering::Relaxed), 1);
        // #7686: the assertion that stood here was `decap_keepalives == 0`,
        // justified by "the keepalive class never routes through the mapper".
        // That is FALSE — `try_decap` returns
        // `Err(count_decap_err(DecapError::Keepalive(..)))` (engine.rs:1614) —
        // and it passed only because `Keepalive` was missing from the variant
        // list above, so the zero was vacuous rather than verified. A counter
        // asserted to be 0 by a test that never feeds it is indistinguishable
        // from a working one. The live assertion is above.
    }

    #[test]
    fn handshake_rx_err_mapping_distinguishes_mac1() {
        let c = WgCounters::default();
        c.count_handshake_rx_err(HandshakeError::Framing(FramingError::Mac1Mismatch));
        c.count_handshake_rx_err(HandshakeError::Framing(FramingError::WrongLength));
        c.count_handshake_rx_err(HandshakeError::OutputTooSmall);
        c.count_handshake_rx_err(HandshakeError::NoPendingHandshake);
        assert_eq!(c.hs_rx_drops_mac1_mismatch.load(Ordering::Relaxed), 1);
        assert_eq!(c.hs_rx_drops_malformed.load(Ordering::Relaxed), 2);
        assert_eq!(c.hs_rx_drops_stale_response.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handshake_complete_stamp_never_zero() {
        let c = WgCounters::default();
        assert_eq!(c.last_handshake_complete_ns.load(Ordering::Relaxed), 0);
        c.record_handshake_complete(0);
        assert_eq!(
            c.last_handshake_complete_ns.load(Ordering::Relaxed),
            1,
            "a t=0 completion must remain distinguishable from never"
        );
    }
}
