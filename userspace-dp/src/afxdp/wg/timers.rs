//! #1888 S5: time-based WireGuard state on `WgEngine` — the engine
//! clock, the rekey-request edge, session expiry (REJECT_AFTER_TIME
//! teardown), the attempt-window abort, and the pure timer decision
//! pass the per-tunnel control thread runs at 1s granularity.
//!
//! Design of record: `docs/research/1888-wg-timers/plan.md` (plan v9,
//! 3/3 PLAN-READY). The §3 timer-semantics table is authoritative for
//! WHICH packets arm/clear WHICH timers; this file implements the
//! engine-resident half, `coordinator/wg_control/` implements the
//! control-loop half (poll(2) timeout, handshake attempt machine,
//! keepalive emission).
//!
//! Clock discipline: `WgEngine::now_ns()` is a per-use CLOCK_MONOTONIC
//! read (vDSO). In S2a no AF_XDP steady-state path calls it — decap is
//! control-thread-only and the worker transit encap (frame/wg.rs)
//! already heap-allocates per packet. S3 flag: if decap ever moves
//! onto AF_XDP workers, this must convert to a published coarse clock
//! WITH a hard publisher-cadence bound (an unbounded publisher lets a
//! stalled control thread ship packets past REJECT_AFTER_TIME — the
//! reason a cached-clock design was rejected at plan review).

use super::counters::WgCounters;
use super::engine::WgEngine;
use super::session::{KEEPALIVE_TIMEOUT_NS, NO_REPLY_REINIT_NS};
use std::sync::atomic::Ordering;

/// Sentinel for "no deadline" in `TimerActions::next_deadline_ns`
/// (Codex r2 C3 — a 0/past sentinel would saturate the poll timeout
/// to 0 and busy-spin).
pub(crate) const WG_NO_DEADLINE_NS: u64 = u64::MAX;

/// Which keepalive class a `timer_pass` send action belongs to —
/// picks the telemetry counter at the emission site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeepaliveKind {
    /// T6: passive keepalive (received data, sent nothing for 10s).
    Passive,
    /// T8: operator-configured persistent keepalive.
    Persistent,
}

/// Why `timer_pass` wants a handshake initiated. (Age-driven rekeys —
/// T1/T2/send-side-T3 — arrive via the rekey-request edge instead;
/// they are armed at the encap/decap use sites.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitiateReason {
    /// T7: we sent data and heard nothing for 15s — suspect dead
    /// session.
    DeadPeer,
    /// T8 due with no usable session — a keepalive cannot be sent
    /// until a handshake completes (NAT pinhole maintenance).
    KeepaliveNoSession,
}

/// Output of one timer decision pass. Pure data — `timer_pass`
/// performs no IO and mutates nothing; the control loop owns sends
/// and reports outcomes back (skip-pacing, AGY r3 G1).
#[derive(Debug, Clone, Copy)]
pub(crate) struct TimerActions {
    pub(crate) initiate: Option<InitiateReason>,
    pub(crate) send_keepalive: Option<KeepaliveKind>,
    /// Earliest FUTURE deadline among the armed/enabled timers;
    /// `WG_NO_DEADLINE_NS` when none. Never a past value: a due timer
    /// is returned as an action instead.
    pub(crate) next_deadline_ns: u64,
}

impl TimerActions {
    fn idle() -> Self {
        Self {
            initiate: None,
            send_keepalive: None,
            next_deadline_ns: WG_NO_DEADLINE_NS,
        }
    }
}

impl WgEngine {
    /// CLOCK_MONOTONIC ns, with a `#[cfg(test)]`-only mock override so
    /// the timer semantics are deterministically testable. Release
    /// builds compile to a bare vDSO read.
    #[inline]
    pub(crate) fn now_ns(&self) -> u64 {
        #[cfg(test)]
        {
            let m = self.mock_now_ns.load(Ordering::Relaxed);
            if m != 0 {
                return m;
            }
        }
        super::counters::monotonic_now_ns()
    }

    /// Test hook: pin the engine clock (0 restores the real clock).
    #[cfg(test)]
    pub(crate) fn set_mock_now_ns(&self, now_ns: u64) {
        self.mock_now_ns.store(now_ns, Ordering::Relaxed);
    }

    /// Arm the "session is stale, rekey" edge (T1 age threshold,
    /// T2 receive horizon, send-side T3 expiry) for `peer_pubkey`. Relaxed
    /// atomic on that peer's own slot — same pattern as the NoSession
    /// handshake-request edge. The control loop consumes it and initiates
    /// WITHOUT the confirmed-session gate (a confirmed-but-stale session is
    /// exactly what is being replaced). #5164: scoped PER PEER (was
    /// per-engine in S2a) so a rekey edge armed by peer B's stale session
    /// drives B's attempt, not a lower-sorted peer A's. No-op if the peer is
    /// not in the current table.
    #[inline]
    pub(crate) fn request_rekey(&self, peer_pubkey: &[u8; 32]) {
        if let Some(peer) = self.peer_arc(peer_pubkey) {
            peer.rekey_request_pending.store(true, Ordering::Relaxed);
        }
    }

    /// Control side of the rekey edge, scoped PER PEER (#5164): returns true
    /// if `peer_pubkey`'s edge is armed, and clears only that peer's edge.
    /// `false` if the peer is unknown or has no pending rekey edge.
    pub(crate) fn take_rekey_request(&self, peer_pubkey: &[u8; 32]) -> bool {
        self.peer_arc(peer_pubkey)
            .map(|peer| peer.rekey_request_pending.swap(false, Ordering::Relaxed))
            .unwrap_or(false)
    }

    /// The current session's `local_index` for the named peer, if any.
    /// The handshake attempt machine records this at attempt start and
    /// declares success when it CHANGES (identity check — clock
    /// comparisons across the install seam were proven fragile at
    /// plan review, Codex r2 C1). Slow path.
    pub(crate) fn current_session_local_index(&self, pubkey: &[u8; 32]) -> Option<u32> {
        let peer = self.peer_arc(pubkey)?;
        let cur = peer.current.read().unwrap_or_else(|e| e.into_inner());
        cur.as_ref().map(|s| s.local_index)
    }

    /// Whether the named peer has a USABLE session for keepalive
    /// emission: current, key-confirmed, and not past
    /// REJECT_AFTER_TIME (AGY r2 A2 — an unconfirmed responder-role
    /// session is NOT usable; its keepalive would silently fail the
    /// confirmed gate, so T8 must initiate instead). Slow path.
    pub(crate) fn peer_has_usable_session(&self, pubkey: &[u8; 32], now_ns: u64) -> bool {
        let Some(peer) = self.peer_arc(pubkey) else {
            return false;
        };
        let cur = peer.current.read().unwrap_or_else(|e| e.into_inner());
        matches!(
            cur.as_ref(),
            Some(s) if s.usable_at(now_ns)
        )
    }

    /// Clear the T7 no-reply arm for the named peer. Called by the
    /// control loop when a handshake attempt STARTS (the T7 obligation
    /// transfers to the attempt machine) and when it GIVES UP (egress
    /// during the attempt re-arms T7; carried across the give-up
    /// boundary it would reopen a fresh 90s window every 15s — AGY r2
    /// A1 + r4 H1). Slow path.
    pub(crate) fn clear_t7_arm(&self, pubkey: &[u8; 32]) {
        if let Some(peer) = self.peer_arc(pubkey) {
            peer.t7_armed_send_ns.store(0, Ordering::Relaxed);
        }
    }

    /// Skip-pacing for a passive (T6) keepalive that could not be sent
    /// (no endpoint / no usable session / socket error): re-arm the T6
    /// timer at `now` so its deadline is strictly future and the poll
    /// loop cannot spin on a past-due timer (AGY r3 G1).
    pub(crate) fn pace_passive_keepalive_skip(&self, pubkey: &[u8; 32], now_ns: u64) {
        if let Some(peer) = self.peer_arc(pubkey) {
            peer.t6_armed_recv_ns.store(now_ns.max(1), Ordering::Relaxed);
        }
    }

    /// Advance the T8 pacing anchor — called whenever the control loop
    /// ACTS on a T8 due-tick (keepalive send attempt, handshake
    /// initiation, or skip), success or failure (AGY r3 G1). Also called
    /// by the handshake attempt machine's GIVE-UP branch (#2961) with the
    /// give-up time, so a permanently-down persistent-keepalive peer
    /// observes a full keepalive-interval cooldown before the next
    /// `KeepaliveNoSession` attempt instead of re-firing a fresh 90s
    /// window every tick.
    pub(crate) fn note_t8_attempt(&self, pubkey: &[u8; 32], now_ns: u64) {
        if let Some(peer) = self.peer_arc(pubkey) {
            peer.t8_last_attempt_ns.store(now_ns.max(1), Ordering::Relaxed);
        }
    }

    /// Stamp an authenticated handshake message SENT toward the peer
    /// (initiation or response, after `wg_send_to` success). Feeds the
    /// §3 `last_send_any_ns` semantics: clears the T6 arm and paces T8.
    pub(crate) fn note_handshake_sent(&self, pubkey: &[u8; 32], now_ns: u64) {
        if let Some(peer) = self.peer_arc(pubkey) {
            peer.note_authenticated_send(now_ns);
        }
    }

    /// Tear down current/previous/next sessions older than
    /// REJECT_AFTER_TIME. Holds `reconcile_lock` (serialized with
    /// install/reconcile/promote — a concurrent `consume_response` or
    /// `maybe_promote_next` cannot interleave) and removes the demux
    /// entries exactly like the reconcile peer-removal drain, so no
    /// demux entry can orphan. The `next` slot is included so an
    /// unconfirmed responder keypair the peer never confirms (never
    /// sends data on) is also torn down at REJECT_AFTER_TIME instead of
    /// pinning a demux entry (#3882). Returns the number of sessions
    /// dropped; each bumps `sessions_expired`.
    pub(crate) fn expire_sessions(&self, now_ns: u64) -> usize {
        let _guard = self.reconcile_lock.lock().unwrap_or_else(|e| e.into_inner());
        let table = self.load_table();
        let mut dropped_indices: Vec<u32> = Vec::new();
        for entry in table.peers.iter() {
            let peer = &entry.peer;
            for slot in [&peer.current, &peer.previous, &peer.next] {
                let mut guard = slot.write().unwrap_or_else(|e| e.into_inner());
                if let Some(session) = guard.as_ref() {
                    if session.expired_at(now_ns) {
                        dropped_indices.push(session.local_index);
                        *guard = None;
                    }
                }
            }
        }
        if dropped_indices.is_empty() {
            return 0;
        }
        {
            let mut by_index = self
                .sessions_by_local_index
                .write()
                .unwrap_or_else(|e| e.into_inner());
            for li in &dropped_indices {
                by_index.remove(li);
            }
        }
        for _ in &dropped_indices {
            WgCounters::bump(&self.counters().sessions_expired);
        }
        dropped_indices.len()
    }

    /// Abort the named peer's pending (reserved-but-incomplete)
    /// handshake, releasing the reservation so a stale msg2 delivered
    /// after the T5 attempt give-up cannot complete it (Codex r1 M5).
    /// Under `reconcile_lock`, consistent with reserve/release. Bumps
    /// `pending_aborted_attempt_window` when a reservation existed.
    pub(crate) fn abort_pending_for_peer(&self, pubkey: &[u8; 32]) {
        let _guard = self.reconcile_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut by_peer = self.pending_by_peer.write().unwrap_or_else(|e| e.into_inner());
        if let Some(reserved_idx) = by_peer.remove(pubkey) {
            self.pending.write().unwrap_or_else(|e| e.into_inner()).remove(&reserved_idx);
            WgCounters::bump(&self.counters().pending_aborted_attempt_window);
        }
    }

    /// One pure timer decision pass for the (S2a: single) configured
    /// peer. 1s-granularity caller cadence; computes T6/T7/T8 actions
    /// plus the earliest FUTURE deadline. `endpoint_known` is supplied
    /// by the control loop because the LEARNED endpoint
    /// (`effective_endpoint`) is control-thread-local state the engine
    /// cannot see — with `endpoint_known == false` no action that
    /// requires sending is emitted and no deadline is armed for it
    /// (AGY r3 G1(b)).
    pub(crate) fn timer_pass(&self, now_ns: u64, endpoint_known: bool) -> TimerActions {
        let Some(pubkey) = self.first_peer_pubkey() else {
            return TimerActions::idle();
        };
        self.timer_pass_for_peer(&pubkey, now_ns, endpoint_known)
    }

    /// One pure timer decision pass for a SPECIFIC peer (#1434
    /// multi-peer). The control loop calls this once per peer per tick,
    /// supplying that peer's `endpoint_known` (the learned/configured
    /// endpoint is per-peer control-thread-local state the engine cannot
    /// see). `timer_pass` is the single-peer wrapper retained for the
    /// pre-#1434 callers/tests.
    pub(crate) fn timer_pass_for_peer(
        &self,
        pubkey: &[u8; 32],
        now_ns: u64,
        endpoint_known: bool,
    ) -> TimerActions {
        let mut actions = TimerActions::idle();
        // #2836: take the peer's timer state and its config from ONE
        // table snapshot so the keepalive interval read below pairs with
        // this peer instance, not a config that a concurrent reconcile
        // swapped in between two loads.
        let Some((peer, config)) = self.peer_entry(pubkey) else {
            return actions;
        };
        if !endpoint_known {
            return actions;
        }
        let mut earliest = WG_NO_DEADLINE_NS;

        // T7 — no-reply reinit ("suspect dead session").
        let t7_armed = peer.t7_armed_send_ns.load(Ordering::Relaxed);
        if t7_armed != 0 {
            let due = t7_armed.saturating_add(NO_REPLY_REINIT_NS);
            if now_ns >= due {
                actions.initiate = Some(InitiateReason::DeadPeer);
            } else {
                earliest = earliest.min(due);
            }
        }

        // T6 — passive keepalive.
        let t6_armed = peer.t6_armed_recv_ns.load(Ordering::Relaxed);
        if t6_armed != 0 {
            let due = t6_armed.saturating_add(KEEPALIVE_TIMEOUT_NS);
            if now_ns >= due {
                actions.send_keepalive = Some(KeepaliveKind::Passive);
            } else {
                earliest = earliest.min(due);
            }
        }

        // T8 — persistent keepalive. Pacing anchor is the most recent
        // authenticated traversal in EITHER direction (wireguard-go
        // `timersAnyAuthenticatedPacketTraversal`) or the last T8
        // attempt (skip-pacing), whichever is later.
        let keepalive_secs = config.persistent_keepalive;
        if keepalive_secs != 0 {
            let interval_ns = u64::from(keepalive_secs).saturating_mul(1_000_000_000);
            let anchor = peer
                .last_send_any_ns
                .load(Ordering::Relaxed)
                .max(peer.last_recv_any_ns.load(Ordering::Relaxed))
                .max(peer.t8_last_attempt_ns.load(Ordering::Relaxed));
            let due = anchor.saturating_add(interval_ns);
            if now_ns >= due {
                if self.peer_has_usable_session(pubkey, now_ns) {
                    // Persistent wins over a simultaneous passive
                    // action — one keepalive satisfies both.
                    actions.send_keepalive = Some(KeepaliveKind::Persistent);
                } else if actions.initiate.is_none() {
                    actions.initiate = Some(InitiateReason::KeepaliveNoSession);
                }
            } else {
                earliest = earliest.min(due);
            }
        }

        actions.next_deadline_ns = earliest;
        actions
    }
}
