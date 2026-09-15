//! WG transport session: snow `StatelessTransportState` plus a
//! sliding-window replay tracker.
//!
//! The transport state is derived from a completed Noise IK
//! handshake. snow's `StatelessTransportState` is `Sync` because
//! it holds no mutable per-message state — the counter and the
//! replay window are entirely the caller's responsibility, which is
//! exactly what we want for AF_XDP worker integration.
//!
//! Replay window: the reference WireGuard RFC 6479 ring bitmap
//! (kernel `noise.c` `counter_validate` / wireguard-go `replay.go`
//! `ValidateCounter`) — a `[u64; 128]` ring of 8192 bits giving an
//! 8128-counter reorder window (#5168). The single 64-wide `u64`
//! window it replaced (#5168) rejected authentic packets ~2 orders
//! of magnitude earlier than a reference peer under multi-queue /
//! path-diversity reorder. A single `Mutex` covers `(counter,
//! backtrack)` — contention is bounded because we only ever decap
//! from the worker that owns the binding the session was demuxed
//! onto. Encap uses a separate `AtomicU64` counter because we are
//! the sole producer.

use snow::StatelessTransportState;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// #5168: reference WireGuard replay-ring geometry, byte-for-byte the
/// kernel/wireguard-go constants:
///   COUNTER_BITS_TOTAL     = RING_BLOCKS * BLOCK_BITS = 128 * 64 = 8192
///   COUNTER_REDUNDANT_BITS = BLOCK_BITS               = 64
///   COUNTER_WINDOW_SIZE    = 8192 - 64                = 8128  (== REPLAY_WINDOW)
/// The one redundant block (64 counters) is the headroom that lets the
/// advance-clear never wipe a bit still inside the window.
const BLOCK_BITS: u64 = 64;
const BLOCK_BIT_LOG: u64 = 6; // log2(BLOCK_BITS)
const RING_BLOCKS: usize = 128; // ring word count (power of two)
const BLOCK_MASK: usize = RING_BLOCKS - 1; // 127
const BIT_MASK: u64 = BLOCK_BITS - 1; // 63

/// Maximum reorder age (in counters) the replay window tolerates — the
/// reference WireGuard `COUNTER_WINDOW_SIZE` (kernel/wireguard-go). A counter
/// whose age exceeds this is rejected as too old; a counter at age exactly
/// `REPLAY_WINDOW` is still IN the window (the reference reject test is
/// `highest - c > REPLAY_WINDOW`, a STRICT `>`), matching the reference
/// byte-for-byte. Was `64` before #5168 (a single-u64 window that dropped
/// authentic reordered traffic ~2 orders of magnitude early).
pub(crate) const REPLAY_WINDOW: u64 = (RING_BLOCKS as u64 - 1) * BLOCK_BITS; // 8128
/// WireGuard reject-after-messages limit.
///
/// Per the protocol, a session must stop encrypting after this many
/// transport messages and rekey.
pub(crate) const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1u64 << 13);

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// WG whitepaper §6.1 timer constants (#1888 S5), all CLOCK_MONOTONIC
/// nanoseconds. Enforcement loci are documented in
/// `docs/research/1888-wg-timers/plan.md` §3 (the section of record).
///
/// REKEY_AFTER_TIME: on SENDING transport data, if the current session
/// is older than this AND we initiated it, initiate a new handshake.
pub(crate) const REKEY_AFTER_TIME_NS: u64 = 120 * NANOS_PER_SEC;
/// REJECT_AFTER_TIME: session keys older than this MUST NOT be used to
/// send or receive. Enforced per-use in try_encap/try_decap; the
/// control thread's `expire_sessions` tears the session down.
pub(crate) const REJECT_AFTER_TIME_NS: u64 = 180 * NANOS_PER_SEC;
/// REKEY_TIMEOUT: handshake-initiation retransmit pacing. (Spec jitter
/// of <=333ms is deliberately omitted — sub-granularity at the 1s
/// control-thread tick, single-digit tunnel counts.)
pub(crate) const REKEY_TIMEOUT_NS: u64 = 5 * NANOS_PER_SEC;
/// REKEY_ATTEMPT_TIME: give up retransmitting after this long; resume
/// only on a fresh trigger (new egress data / persistent keepalive).
pub(crate) const REKEY_ATTEMPT_TIME_NS: u64 = 90 * NANOS_PER_SEC;
/// KEEPALIVE_TIMEOUT: passive keepalive — after receiving data, if
/// nothing (data or keepalive) was sent within this window, send an
/// authenticated empty transport record.
pub(crate) const KEEPALIVE_TIMEOUT_NS: u64 = 10 * NANOS_PER_SEC;
/// "Suspect dead session": after sending data, if NO authenticated
/// packet was received within KEEPALIVE_TIMEOUT + REKEY_TIMEOUT,
/// initiate a new handshake. (Jitter omitted, same rationale as
/// REKEY_TIMEOUT.)
pub(crate) const NO_REPLY_REINIT_NS: u64 = KEEPALIVE_TIMEOUT_NS + REKEY_TIMEOUT_NS;
/// Receive-horizon rekey: on RECEIVING a transport record, if the
/// current session is older than REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT
/// - REKEY_TIMEOUT (165s) AND we initiated it, initiate — covers a
/// receive-only initiator before the responder's 180s discard.
pub(crate) const RECV_REKEY_HORIZON_NS: u64 =
    REJECT_AFTER_TIME_NS - KEEPALIVE_TIMEOUT_NS - REKEY_TIMEOUT_NS;

#[inline]
fn reserve_next_counter(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            if current >= REJECT_AFTER_MESSAGES {
                None
            } else {
                Some(current + 1)
            }
        })
        .ok()
}

/// Which side of the handshake produced this session. Determines the
/// initial value of `confirmed` (initiator-side sessions are confirmed
/// at install because the initiator is the side that sends first;
/// responder-side sessions start unconfirmed and must observe a valid
/// inbound data record before egress is allowed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionRole {
    Initiator,
    Responder,
}

/// A live, post-handshake WG transport session.
///
/// Debug-impl is hand-rolled because snow's `StatelessTransportState`
/// doesn't expose useful Debug (it would leak keys anyway).
pub(crate) struct WgSession {
    /// snow transport state. Stateless w.r.t. nonce — we drive the
    /// counter ourselves on both directions.
    pub(crate) transport: StatelessTransportState,
    /// Receiver index that the *peer* will put in the WG data
    /// header when sending to us. Locally chosen at handshake time.
    /// Used for inbound demux: the engine's
    /// `sessions_by_local_index: RwLock<FxHashMap<u32, Arc<WgSession>>>`
    /// is keyed by `local_index` alone, not by `(listen_port,
    /// local_index)`. Listen-port selection happens one layer up in
    /// the integration PR's UDP-socket dispatch, before the record
    /// reaches the engine.
    pub(crate) local_index: u32,
    /// Receiver index that *we* put in the WG data header when
    /// sending to the peer. Peer-chosen at handshake time.
    pub(crate) peer_index: u32,
    /// Monotonic outbound counter.
    pub(crate) tx_counter: AtomicU64,
    /// Replay tracker for inbound packets.
    pub(crate) replay: Mutex<ReplayState>,
    /// Identifier of the peer this session belongs to (peer pubkey).
    /// Stored so the engine can route demuxed packets back through
    /// the peer's AllowedIPs gate.
    pub(crate) peer_pubkey: [u8; 32],
    /// WireGuard key-confirmation flag. WG spec: the responder MUST
    /// NOT send encrypted transport data on a fresh session until it
    /// has authenticated the initiator's first transport packet. This
    /// is the anti-reflection / key-confirmation invariant that
    /// prevents the responder from acting as a one-shot amplifier
    /// against a forged handshake response. Initiator-role sessions
    /// are installed with `confirmed = true` (the initiator is the
    /// side that sends first by definition). Responder-role sessions
    /// are installed with `confirmed = false`; egress through such a
    /// session is treated as no-usable-session until a successful
    /// inbound `read_message` flips the flag.
    pub(crate) confirmed: AtomicBool,
    /// CLOCK_MONOTONIC ns at install (#1888 S5). Basis for the
    /// REKEY_AFTER_TIME / RECV_REKEY_HORIZON / REJECT_AFTER_TIME age
    /// checks. Stamped by the handshake-completion paths from
    /// `WgEngine::now_ns()` so every age comparison shares one clock
    /// domain (including under the test mock clock).
    pub(crate) created_ns: u64,
    /// Which side initiated this session (#1888 S5). REKEY_AFTER_TIME
    /// and the receive-horizon rekey fire only on Initiator-role
    /// sessions — the spec's initiator-only rule that prevents both
    /// sides rekeying simultaneously.
    pub(crate) role: SessionRole,
}

impl std::fmt::Debug for WgSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgSession")
            .field("local_index", &self.local_index)
            .field("peer_index", &self.peer_index)
            .field("tx_counter", &self.tx_counter)
            .field("peer_pubkey_first4", &&self.peer_pubkey[..4])
            .finish_non_exhaustive()
    }
}
/// #9918 F-142: wipe the transport keys when the session drops. snow
/// 0.10.0 has no `zeroize` and no `Drop` impl (verified against the locked
/// registry: no `zeroize` dep, no `impl Drop`, no wipe in `src/`), so without
/// this the 64 bytes of session keys (initiator + responder directions)
/// persist in freed heap until reuse. `rekey_manually` overwrites both
/// cipher keys in place (`CipherChaChaPoly::set` is a plain copy), and zeros
/// need no RNG — there is no failure mode in `Drop`. The handshake
/// `HandshakeState` (chaining keys, ephemerals, seconds-lived pendings)
/// has no wipe API and remains an accepted residual (see engine.rs).
impl Drop for WgSession {
    fn drop(&mut self) {
        const ZEROS: [u8; 32] = [0u8; 32];
        self.transport.rekey_manually(Some(&ZEROS), Some(&ZEROS));
    }
}
impl WgSession {
    /// Create a session in initiator role — confirmed at install
    /// (the initiator is the side that sends first per the WG spec).
    /// Existing callers used `WgSession::new`; that constructor maps
    /// to this initiator behavior to preserve backward compatibility
    /// for the in-tree tests that drive both sides through the
    /// engine's slow path. Callers that handle a responder session
    /// (after reading the initiator's first handshake message) MUST
    /// use `new_with_role(SessionRole::Responder, ...)`.
    pub(crate) fn new(
        transport: StatelessTransportState,
        local_index: u32,
        peer_index: u32,
        peer_pubkey: [u8; 32],
    ) -> Self {
        Self::new_with_role(
            transport,
            local_index,
            peer_index,
            peer_pubkey,
            SessionRole::Initiator,
            super::counters::monotonic_now_ns(),
        )
    }

    /// Create a session and record its role for key-confirmation
    /// gating plus its install stamp for the #1888 age timers. See the
    /// `confirmed` field doc on `WgSession` for the
    /// initiator-vs-responder contract. `created_ns` is the caller's
    /// clock read (`WgEngine::now_ns()` on the completion paths) so the
    /// age comparisons stay in one clock domain.
    pub(crate) fn new_with_role(
        transport: StatelessTransportState,
        local_index: u32,
        peer_index: u32,
        peer_pubkey: [u8; 32],
        role: SessionRole,
        created_ns: u64,
    ) -> Self {
        let confirmed = matches!(role, SessionRole::Initiator);
        Self {
            transport,
            local_index,
            peer_index,
            tx_counter: AtomicU64::new(0),
            replay: Mutex::new(ReplayState::default()),
            peer_pubkey,
            confirmed: AtomicBool::new(confirmed),
            created_ns,
            role,
        }
    }

    /// Atomically reserve the next outbound counter value.
    #[inline]
    pub(crate) fn next_tx_counter(&self) -> Option<u64> {
        reserve_next_counter(&self.tx_counter)
    }

    /// Returns true once the session has authenticated at least one
    /// inbound transport packet. Initiator-role sessions return true
    /// from install onward.
    #[inline]
    pub(crate) fn is_confirmed(&self) -> bool {
        self.confirmed.load(Ordering::Acquire)
    }

    /// Mark the session as confirmed. Called from `try_decap` after a
    /// successful AEAD authentication of an inbound transport record.
    /// `Release` pairs with the `Acquire` load in `is_confirmed` so
    /// any subsequent egress reader sees a `true` flag.
    #[inline]
    pub(crate) fn mark_confirmed(&self) {
        self.confirmed.store(true, Ordering::Release);
    }
}

/// Reference WireGuard RFC 6479 ring-bitmap replay tracker (#5168) —
/// the kernel `counter_validate` / wireguard-go `ValidateCounter`
/// algorithm. `counter` is the highest counter accepted so far;
/// `backtrack` is a ring of [`RING_BLOCKS`] u64 words indexed by
/// `(c >> BLOCK_BIT_LOG) & BLOCK_MASK`, bit `c & BIT_MASK` recording
/// that counter `c` was seen. A counter `c` is fresh iff
///   - `c > counter` (new high water mark — the passed-over ring
///     blocks are cleared forward), OR
///   - `counter - c <= REPLAY_WINDOW` AND its bit is currently unset.
///
/// No `started` flag is needed (unlike the pre-#5168 single-u64
/// window): the pristine all-zero filter accepts counter 0 on first
/// sight (its bit is unset) and rejects the replay (its bit is now
/// set) purely from the bitmap, exactly as the reference does.
#[derive(Debug, Clone)]
pub(crate) struct ReplayState {
    /// Highest counter accepted so far (wireguard-go `f.counter`).
    pub(crate) counter: u64,
    /// Ring of `RING_BLOCKS` 64-bit words; `backtrack[(c >> 6) &
    /// BLOCK_MASK]` bit `c & 63` == 1 means counter `c` was seen.
    pub(crate) backtrack: [u64; RING_BLOCKS],
}

impl Default for ReplayState {
    #[inline]
    fn default() -> Self {
        // `[u64; 128]` has no std `Default`; the pristine filter is
        // all-zero (counter 0, empty ring) — the reference zero value.
        ReplayState {
            counter: 0,
            backtrack: [0u64; RING_BLOCKS],
        }
    }
}

impl ReplayState {
    /// Cheap pre-crypto reject for trivially stale counters.
    ///
    /// This never rejects a candidate the authoritative
    /// [`Self::check_and_update`] would accept for the current snapshot,
    /// so it is safe to run before AEAD without creating false drops:
    /// it uses the SAME `counter - c > REPLAY_WINDOW` boundary as the
    /// commit, and `counter` only ever advances, so a candidate that is
    /// definitely-out here stays out at commit. Best-effort CPU guard
    /// under concurrent decap, not a hard guarantee.
    #[inline]
    pub(crate) fn definitely_out_of_window(&self, c: u64) -> bool {
        self.counter.saturating_sub(c) > REPLAY_WINDOW
    }

    /// Check-and-update for inbound counter `c`. Returns
    /// `ReplayDecision::Accept` if the counter is fresh (and the ring is
    /// updated atomically with the accept), `Repeat` if its bit is
    /// already set, or `OutOfWindow` if it is older than the window.
    ///
    /// Algorithm: the reference WireGuard RFC 6479 ring window
    /// (kernel/wireguard-go). The test suite covers the in-order /
    /// repeat / out-of-window / gap-fill / far-jump arms and the
    /// reference age boundary (64/127/8127/8128 accepted, 8129 rejected)
    /// explicitly — read the reference if you change this.
    pub(crate) fn check_and_update(&mut self, c: u64) -> ReplayDecision {
        let index_block = (c >> BLOCK_BIT_LOG) as usize;
        if c > self.counter {
            // New high water mark: clear the ring blocks now passed over
            // (wrapping mod RING_BLOCKS), capped at the whole ring for a
            // jump wider than the ring, then adopt the new counter.
            let current = (self.counter >> BLOCK_BIT_LOG) as usize;
            let diff = (index_block - current).min(RING_BLOCKS);
            for i in (current + 1)..=(current + diff) {
                self.backtrack[i & BLOCK_MASK] = 0;
            }
            self.counter = c;
        } else if self.counter - c > REPLAY_WINDOW {
            // Older than the window (strict `>`, matching the reference).
            return ReplayDecision::OutOfWindow;
        }
        let block = index_block & BLOCK_MASK;
        let mask = 1u64 << (c & BIT_MASK);
        if self.backtrack[block] & mask != 0 {
            ReplayDecision::Repeat
        } else {
            self.backtrack[block] |= mask;
            ReplayDecision::Accept
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayDecision {
    Accept,
    Repeat,
    OutOfWindow,
}

#[cfg(test)]
mod session_tests {
    use super::*;

    #[test]
    fn in_order_accepts() {
        let mut r = ReplayState::default();
        for c in 0u64..200 {
            assert_eq!(r.check_and_update(c), ReplayDecision::Accept, "c={}", c);
        }
    }

    #[test]
    fn exact_repeat_rejects() {
        let mut r = ReplayState::default();
        assert_eq!(r.check_and_update(10), ReplayDecision::Accept);
        // Replay of the same counter must be rejected as Repeat,
        // not silently accepted as a no-op.
        assert_eq!(r.check_and_update(10), ReplayDecision::Repeat);
    }

    #[test]
    fn out_of_window_rejects() {
        let mut r = ReplayState::default();
        assert_eq!(r.check_and_update(10_000), ReplayDecision::Accept);
        // Age 8129 (10000 - 8129 = 1871) is the first counter BEYOND the
        // 8128-wide reference window — too old.
        assert_eq!(r.check_and_update(1_871), ReplayDecision::OutOfWindow);
        assert_eq!(r.check_and_update(0), ReplayDecision::OutOfWindow);
    }

    #[test]
    fn gap_fill_in_window_accepts() {
        let mut r = ReplayState::default();
        // Receive 0, 2, 4 — accept all. Then receive the gap-filled
        // 1 and 3. WG explicitly allows in-window gap fill; this
        // is the whole point of the sliding bitmap (NAT/reorder).
        assert_eq!(r.check_and_update(0), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(2), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(4), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(1), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(3), ReplayDecision::Accept);
        // But the gap fills themselves now repeat.
        assert_eq!(r.check_and_update(1), ReplayDecision::Repeat);
        assert_eq!(r.check_and_update(3), ReplayDecision::Repeat);
    }

    #[test]
    fn jump_ahead_resets_bitmap() {
        // A counter jumping forward by more than the ring capacity
        // (RING_BLOCKS*BLOCK_BITS = 8192) clears the whole ring; the old
        // counter is then far out of window.
        let mut r = ReplayState::default();
        assert_eq!(r.check_and_update(10), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(20_000), ReplayDecision::Accept);
        // The old counter 10 is now age 19990 — far out of the 8128 window.
        assert_eq!(r.check_and_update(10), ReplayDecision::OutOfWindow);
        // The new counter 20000 is at the head and must repeat-fail.
        assert_eq!(r.check_and_update(20_000), ReplayDecision::Repeat);
    }

    #[test]
    fn window_edge_repeat() {
        // The bit at the trailing edge of the window must reject a
        // repeat. This is the most common off-by-one in replay
        // window code.
        let mut r = ReplayState::default();
        assert_eq!(r.check_and_update(0), ReplayDecision::Accept);
        // Move the window so 0 sits at the INCLUSIVE trailing edge:
        // highest = REPLAY_WINDOW (8128), age = 8128 == REPLAY_WINDOW is
        // still in-window (reference strict `>`), so the seen 0 repeats.
        assert_eq!(r.check_and_update(REPLAY_WINDOW), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(0), ReplayDecision::Repeat);
        // One more step pushes 0 out: highest = 8129, age = 8129 > window.
        assert_eq!(r.check_and_update(REPLAY_WINDOW + 1), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(0), ReplayDecision::OutOfWindow);
    }

    #[test]
    fn precheck_out_of_window_matches_window_width() {
        let mut r = ReplayState::default();
        assert_eq!(r.check_and_update(10_000), ReplayDecision::Accept);
        // Age 8128 (10000-8128=1872) is the inclusive edge — still in window,
        // so the precheck must NOT declare it out.
        assert!(!r.definitely_out_of_window(1_872));
        // Age 8129 (10000-8129=1871) is out — the precheck matches the commit
        // boundary exactly.
        assert!(r.definitely_out_of_window(1_871));
    }

    // #5168 FAIL-ON-REVERT: the reference WireGuard window tolerates ~8128
    // counters of reorder. UNSEEN counters at ages 64, 127, 8127, and the
    // inclusive edge 8128 must ALL be ACCEPTED — the pre-#5168 single-u64
    // 64-wide window falsely rejected everything from age 64 onward, collapsing
    // authentic reordered traffic ~2 orders of magnitude early. A counter one
    // past the window (age 8129) is still rejected as too old. Reverting
    // REPLAY_WINDOW to 64 (or the old single-u64 algorithm) turns the
    // age-64/127/8127/8128 accepts RED.
    #[test]
    fn unseen_counters_within_reference_window_accepted() {
        let mut r = ReplayState::default();
        // High-water mark well above the window so each age maps to a
        // distinct, non-negative counter.
        const HIGH: u64 = 100_000;
        assert_eq!(r.check_and_update(HIGH), ReplayDecision::Accept);
        for age in [64u64, 127, 8127, REPLAY_WINDOW] {
            assert_eq!(
                r.check_and_update(HIGH - age),
                ReplayDecision::Accept,
                "unseen counter at age {age} must be accepted \
                 (reference window {REPLAY_WINDOW})"
            );
        }
        // One counter past the inclusive edge is too old.
        assert_eq!(
            r.check_and_update(HIGH - (REPLAY_WINDOW + 1)),
            ReplayDecision::OutOfWindow,
            "age {} (one past the window) must be rejected as too old",
            REPLAY_WINDOW + 1
        );
    }

    // #5168: widening the window must NOT weaken the core anti-replay
    // property — a genuine replay (an already-accepted counter) is still
    // rejected at every in-window age.
    #[test]
    fn replayed_counter_rejected_at_every_age() {
        let mut r = ReplayState::default();
        const HIGH: u64 = 100_000;
        assert_eq!(r.check_and_update(HIGH), ReplayDecision::Accept);
        for age in [0u64, 1, 64, 127, 8127, REPLAY_WINDOW] {
            let c = HIGH - age;
            if age != 0 {
                // age 0 is HIGH itself, already accepted above.
                assert_eq!(
                    r.check_and_update(c),
                    ReplayDecision::Accept,
                    "seed unseen counter at age {age}"
                );
            }
            assert_eq!(
                r.check_and_update(c),
                ReplayDecision::Repeat,
                "replay of counter at age {age} must be rejected"
            );
        }
    }

    // #5168: the ring must preserve an in-window bit across many block
    // boundaries — accept a counter, advance ~62 blocks forward, and confirm
    // the still-in-window older counter repeats (its bit survived the
    // forward-clear).
    #[test]
    fn ring_preserves_in_window_bit_across_blocks() {
        let mut r = ReplayState::default();
        assert_eq!(r.check_and_update(5_000), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(9_000), ReplayDecision::Accept);
        // 5000 is now age 4000 — well inside the 8128 window; its bit must
        // still be set (a false Accept here would mean a replay slipped
        // through the ring clearing).
        assert_eq!(
            r.check_and_update(5_000),
            ReplayDecision::Repeat,
            "in-window bit must survive across block boundaries"
        );
    }

    // #6118 (#5168 hardening): the anti-false-Repeat WRAP accept — the
    // availability twin of `ring_preserves_in_window_bit_across_blocks`.
    //
    // One ring slot+bit is shared by every counter congruent modulo the ring
    // capacity (RING_BLOCKS * BLOCK_BITS = 8192), so `X` and `X + 8192` are
    // indistinguishable to the bitmap read. A FRESH `X + 8192` may therefore be
    // decided off `X`'s bit, and the only thing that makes it decide correctly
    // is the forward-clear sweep having zeroed `X`'s block while the high-water
    // advanced over it. If that sweep is skipped — or stops one block short of
    // the wrap tail — the fresh counter falsely Repeats and authentic traffic is
    // dropped after a large counter advance.
    //
    // RED-ON-REVERT: neutering the sweep, or narrowing its inclusive bound by
    // one block (`current + diff` -> `(current + diff).saturating_sub(1)`, which
    // leaves exactly the seed's block dirty when `diff` saturates at
    // RING_BLOCKS), turns the wrap accept below into a Repeat. Both mutations
    // leave the other 13 replay tests GREEN — this case is their sole detector.
    #[test]
    fn wrap_accept_after_forward_clear() {
        // The counters, chosen so the aliasing and the window arm are exact.
        const RING_SPAN: u64 = RING_BLOCKS as u64 * BLOCK_BITS; // 8192
        let seed = 100u64;
        let wrapped = seed + RING_SPAN; // same word, same bit as `seed`
        // One block PAST `wrapped`: far enough that the advance's `diff`
        // saturates at RING_BLOCKS (so the sweep wraps all the way back over
        // the seed's block), yet near enough that `wrapped` is still in window
        // and so takes the bitmap arm rather than the high-water arm.
        let advance = wrapped + BLOCK_BITS;

        // The slot aliasing is this test's precondition, not an assumption —
        // assert it, so a geometry change cannot silently make the case vacuous.
        let slot = |c: u64| ((c >> BLOCK_BIT_LOG) as usize & BLOCK_MASK, c & BIT_MASK);
        assert_eq!(
            slot(seed),
            slot(wrapped),
            "precondition: {seed} and {wrapped} must alias ONE ring slot+bit"
        );
        assert_ne!(
            slot(advance),
            slot(seed),
            "precondition: the advance must not itself sit on the shared slot"
        );

        let mut r = ReplayState::default();
        assert_eq!(r.check_and_update(seed), ReplayDecision::Accept);
        assert_eq!(r.check_and_update(advance), ReplayDecision::Accept);
        assert!(
            !r.definitely_out_of_window(wrapped),
            "precondition: {wrapped} must be IN window at high-water {advance}, \
             so the decision is the bitmap read and not the age reject"
        );

        assert_eq!(
            r.check_and_update(wrapped),
            ReplayDecision::Accept,
            "a fresh counter aliasing a forward-cleared slot must ACCEPT, not \
             falsely Repeat off the stale bit left by {seed}"
        );
        // ...and the accept must have SET the bit, not merely passed the read:
        // its own replay repeats.
        assert_eq!(
            r.check_and_update(wrapped),
            ReplayDecision::Repeat,
            "the wrap accept must record {wrapped} as seen"
        );
    }

    #[test]
    fn reject_after_messages_constant_matches_wireguard_spec() {
        assert_eq!(REJECT_AFTER_MESSAGES, 0xffff_ffff_ffff_dfff);
    }

    /// WG whitepaper §6.1 timer constants (#1888 S5).
    #[test]
    fn timer_constants_match_wireguard_spec() {
        assert_eq!(REKEY_AFTER_TIME_NS, 120_000_000_000);
        assert_eq!(REJECT_AFTER_TIME_NS, 180_000_000_000);
        assert_eq!(REKEY_TIMEOUT_NS, 5_000_000_000);
        assert_eq!(REKEY_ATTEMPT_TIME_NS, 90_000_000_000);
        assert_eq!(KEEPALIVE_TIMEOUT_NS, 10_000_000_000);
        assert_eq!(NO_REPLY_REINIT_NS, 15_000_000_000);
        assert_eq!(RECV_REKEY_HORIZON_NS, 165_000_000_000);
    }

    #[test]
    fn tx_counter_stops_at_reject_after_messages_without_advancing() {
        let counter = AtomicU64::new(REJECT_AFTER_MESSAGES - 1);
        assert_eq!(
            reserve_next_counter(&counter),
            Some(REJECT_AFTER_MESSAGES - 1)
        );
        assert_eq!(counter.load(Ordering::Relaxed), REJECT_AFTER_MESSAGES);
        assert_eq!(reserve_next_counter(&counter), None);
        assert_eq!(counter.load(Ordering::Relaxed), REJECT_AFTER_MESSAGES);
    }
}
