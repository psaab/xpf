//! #1888 S5 handshake attempt machine for the WG control thread:
//! per-peer retransmit pacing (REKEY_TIMEOUT), the 90s give-up window
//! (REKEY_ATTEMPT_TIME), identity-based success, initiation sends, and
//! the keepalive emit/pace helpers the timer arm drives.

use super::super::*;
use super::sock::wg_send_to;
use crate::afxdp::wg::counters::WgCounters;
use std::net::{SocketAddr, UdpSocket};

/// #1888 S5 handshake attempt window (thread-local state machine).
/// While active, initiations retry every REKEY_TIMEOUT (5s) BYPASSING
/// the confirmed-session gate (the attempt encodes the decision to
/// replace the current session — losing one datagram must not starve a
/// rekey until the 180s hard expiry); the window ends on SUCCESS (the
/// peer's current-session identity changed — clock comparisons across
/// the install seam are fragile, so identity it is) or GIVE-UP at
/// REKEY_ATTEMPT_TIME (90s), which releases the pending reservation so
/// a stale msg2 cannot complete later.
pub(super) struct HandshakeAttempt {
    pub(super) started_ns: u64,
    pub(super) last_tx_ns: u64,
    pub(super) baseline_session: Option<u32>,
}

/// Why an attempt is being started — picks the telemetry counter.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AttemptTrigger {
    /// Configured-initiator bring-up (thread start).
    BringUp,
    /// Worker NoSession edge (gated on !confirmed, today's rule).
    NoSessionEdge,
    /// T1/T2/send-side-T3 rekey edge (ungated — replaces a live
    /// confirmed-but-stale session).
    RekeyEdge,
    /// T7 no-reply reinit.
    DeadPeer,
    /// T8 persistent-keepalive due with no usable session.
    KeepaliveNoSession,
}

/// Start a handshake attempt: consume the T7 obligation (it transfers
/// to the attempt machine), advance the T8 anchor when T8 triggered,
/// count the timer-driven rekey classes, send the first initiation,
/// and record the baseline session identity the success check compares
/// against.
#[allow(clippy::too_many_arguments)]
pub(super) fn start_attempt(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    peer_pubkey: &[u8; 32],
    endpoint: SocketAddr,
    trigger: AttemptTrigger,
    now_ns: u64,
    encap_buf: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
) -> Option<HandshakeAttempt> {
    engine.clear_t7_arm(peer_pubkey);
    let counters = engine.counters();
    match trigger {
        AttemptTrigger::RekeyEdge => WgCounters::bump(&counters.rekeys_initiated_age),
        AttemptTrigger::DeadPeer => WgCounters::bump(&counters.rekeys_initiated_dead_peer),
        AttemptTrigger::KeepaliveNoSession => {
            WgCounters::bump(&counters.rekeys_initiated_keepalive_no_session);
            engine.note_t8_attempt(peer_pubkey, now_ns);
        }
        AttemptTrigger::BringUp | AttemptTrigger::NoSessionEdge => {}
    }
    let baseline_session = engine.current_session_local_index(peer_pubkey);
    drive_initiation(
        engine,
        socket,
        socket_is_v6,
        peer_pubkey,
        endpoint,
        encap_buf,
        tunnel_name,
        recent_exceptions,
    );
    Some(HandshakeAttempt {
        started_ns: now_ns,
        last_tx_ns: now_ns,
        baseline_session,
    })
}

/// One step of the handshake attempt machine (runs inside the timer
/// arm). Returns the machine's next deadline (retry or give-up) for
/// the poll-timeout computation; WG_NO_DEADLINE_NS when idle.
#[allow(clippy::too_many_arguments)]
pub(super) fn drive_attempt_machine(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    peer_pubkey: &[u8; 32],
    effective_endpoint: Option<SocketAddr>,
    actions: &crate::afxdp::wg::timers::TimerActions,
    now_ns: u64,
    attempt: &mut Option<HandshakeAttempt>,
    encap_buf: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
) -> u64 {
    use crate::afxdp::wg::session::{REKEY_ATTEMPT_TIME_NS, REKEY_TIMEOUT_NS};
    use crate::afxdp::wg::timers::{InitiateReason, WG_NO_DEADLINE_NS};

    // End checks. SUCCESS is an identity test: the current session's
    // local_index changed from the attempt-start baseline (and is
    // present — a mid-attempt expiry clearing current to None must NOT
    // read as success). The success path mutates NOTHING beyond the
    // attempt slot: all success-side cleanup ran inline at the
    // authenticated completion site, before any same-iteration egress
    // (plan v9).
    if let Some(att) = attempt.as_ref() {
        let current = engine.current_session_local_index(peer_pubkey);
        if current.is_some() && current != att.baseline_session {
            *attempt = None;
        } else if now_ns.saturating_sub(att.started_ns) >= REKEY_ATTEMPT_TIME_NS {
            // GIVE-UP: release the pending reservation (a stale msg2
            // must not complete later), clear the T7 arm (egress
            // during the attempt re-armed it; carried across the
            // boundary it would reopen a fresh window next tick), and
            // drain the request edges armed by during-attempt sends.
            // Only traffic AFTER this boundary may re-trigger.
            engine.abort_pending_for_peer(peer_pubkey);
            engine.clear_t7_arm(peer_pubkey);
            let _ = engine.take_rekey_request(peer_pubkey);
            let _ = engine.take_handshake_request(peer_pubkey);
            *attempt = None;
            // #2961: advance the T8 pacing anchor to the GIVE-UP time so
            // a permanently-down persistent-keepalive peer waits a full
            // keepalive_interval before the next KeepaliveNoSession
            // attempt, rather than re-firing on the next ~1s tick. The
            // T8 anchor is max(last_send_any, last_recv_any,
            // t8_last_attempt); for an unreachable peer last_send_any may
            // not advance (sends error with no route) and last_recv_any
            // never advances, so without this the anchor stays at the
            // attempt START — `now >= start + interval` is already true
            // at give-up (start + 90s > start + interval for the common
            // <90s intervals), making "keepalive due" perpetually true
            // and producing a zero-cooldown 90s handshake storm. Stamping
            // give-up time T+90 makes the next attempt due at
            // T+90+interval — the intended cooldown (interval between the
            // END of one failed window and the START of the next). The
            // success path (identity-change branch above) does not reach
            // here, so a live peer keeps pacing off real traffic.
            engine.note_t8_attempt(peer_pubkey, now_ns);
            // Codex code-r1 BLOCKER: `actions` was computed BEFORE this
            // cleanup — a T7 DeadPeer (or stale-edge) trigger captured
            // in it would resurrect a fresh 90s window in the SAME
            // pass, bypassing the boundary we just enforced. Return
            // without evaluating triggers; the next pass (<=1s tick)
            // recomputes actions from the post-cleanup state, where a
            // genuinely-due T8 still starts its fresh window (AGY F4).
            return WG_NO_DEADLINE_NS;
        }
    }

    // Retry while active, paced by REKEY_TIMEOUT, BYPASSING the
    // confirmed-session gate (the attempt encodes the decision).
    if let Some(att) = attempt.as_mut() {
        if now_ns.saturating_sub(att.last_tx_ns) >= REKEY_TIMEOUT_NS {
            if let Some(ep) = effective_endpoint {
                drive_initiation(
                    engine,
                    socket,
                    socket_is_v6,
                    peer_pubkey,
                    ep,
                    encap_buf,
                    tunnel_name,
                    recent_exceptions,
                );
            }
            // A failed/skipped send still advances the pacing anchor
            // (skip-pacing — the deadline must be strictly future).
            att.last_tx_ns = now_ns;
        }
        return (att.last_tx_ns.saturating_add(REKEY_TIMEOUT_NS))
            .min(att.started_ns.saturating_add(REKEY_ATTEMPT_TIME_NS));
    }

    // No attempt active: evaluate the start triggers per the plan's §3
    // initiation-predicate table. Edges are consume-once; a consumed
    // edge with no known endpoint is dropped (any subsequent send on a
    // stale session re-arms it, so it cannot be permanently lost).
    // #5164: consume ONLY this peer's edges — the per-peer loop iterates
    // pubkey-sorted peers, so a global edge here let the first-sorted peer
    // drain an edge peer B raised, blackholing B.
    let rekey_edge = engine.take_rekey_request(peer_pubkey);
    let nosession_edge = engine.take_handshake_request(peer_pubkey);
    let trigger = if rekey_edge {
        Some(AttemptTrigger::RekeyEdge)
    } else if nosession_edge && !engine.peer_has_confirmed_session(peer_pubkey) {
        Some(AttemptTrigger::NoSessionEdge)
    } else {
        match actions.initiate {
            Some(InitiateReason::DeadPeer) => Some(AttemptTrigger::DeadPeer),
            Some(InitiateReason::KeepaliveNoSession) => Some(AttemptTrigger::KeepaliveNoSession),
            None => None,
        }
    };
    if let (Some(trigger), Some(ep)) = (trigger, effective_endpoint) {
        *attempt = start_attempt(
            engine,
            socket,
            socket_is_v6,
            peer_pubkey,
            ep,
            trigger,
            now_ns,
            encap_buf,
            tunnel_name,
            recent_exceptions,
        );
        return now_ns.saturating_add(REKEY_TIMEOUT_NS);
    }
    WG_NO_DEADLINE_NS
}

/// Emit one keepalive (T6 passive / T8 persistent / post-msg2
/// confirmation) toward the peer endpoint. Failure paths advance the
/// corresponding pacing anchor so a due-but-unsendable keepalive can
/// never leave a past deadline spinning the poll loop (skip-pacing).
#[allow(clippy::too_many_arguments)]
pub(super) fn send_keepalive(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    peer_pubkey: &[u8; 32],
    endpoint: SocketAddr,
    kind: crate::afxdp::wg::timers::KeepaliveKind,
    now_ns: u64,
    encap_buf: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
) {
    use crate::afxdp::wg::timers::KeepaliveKind;
    match engine.create_keepalive(peer_pubkey, encap_buf) {
        Ok(outcome) => {
            match wg_send_to(
                socket,
                socket_is_v6,
                &encap_buf[..outcome.len],
                endpoint,
                None,
            ) {
                Ok(_) => {
                    engine.note_encap_sent(peer_pubkey, outcome);
                    let counters = engine.counters();
                    match kind {
                        KeepaliveKind::Passive => WgCounters::bump(&counters.keepalives_tx_passive),
                        KeepaliveKind::Persistent => {
                            WgCounters::bump(&counters.keepalives_tx_persistent);
                            engine.note_t8_attempt(peer_pubkey, now_ns);
                        }
                    }
                }
                Err(e) => {
                    WgCounters::bump(&engine.counters().transport_send_errors);
                    record_local_tunnel_exception(
                        recent_exceptions,
                        tunnel_name,
                        format!("wg_keepalive_send:{e}"),
                    );
                    pace_keepalive_skip(engine, peer_pubkey, kind, now_ns);
                }
            }
        }
        // No usable session (engine gate) — T8 handles this via its
        // KeepaliveNoSession initiation; pace so we don't re-fire
        // every iteration.
        Err(_) => pace_keepalive_skip(engine, peer_pubkey, kind, now_ns),
    }
}

/// Skip-pacing by keepalive class (AGY r3 G1).
pub(super) fn pace_keepalive_skip(
    engine: &crate::afxdp::wg::WgEngine,
    peer_pubkey: &[u8; 32],
    kind: crate::afxdp::wg::timers::KeepaliveKind,
    now_ns: u64,
) {
    match kind {
        crate::afxdp::wg::timers::KeepaliveKind::Passive => {
            engine.pace_passive_keepalive_skip(peer_pubkey, now_ns)
        }
        crate::afxdp::wg::timers::KeepaliveKind::Persistent => {
            engine.note_t8_attempt(peer_pubkey, now_ns)
        }
    }
}

/// Build + send a fresh initiation toward the peer endpoint. A send
/// error is surfaced as an exception (the next tick retries); a missing
/// session keeps the timer armed.
#[allow(clippy::too_many_arguments)]
pub(super) fn drive_initiation(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    peer_pubkey: &[u8; 32],
    endpoint: SocketAddr,
    out: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
) {
    // #1865: create_initiation Ok/Err accounting is engine-internal
    // (hs_initiations_created / hs_initiation_build_failures); the
    // send failure is OURS to count — created↑ + send_errors↑ +
    // completions flat is the #1736 EINVAL fingerprint.
    if let Ok(_local_index) = engine.create_initiation(peer_pubkey, out) {
        let len = crate::afxdp::wg::WG_MSG_INIT_LEN;
        match wg_send_to(socket, socket_is_v6, &out[..len], endpoint, None) {
            Ok(_) => {
                // #1888 S5: a handshake initiation on the wire is an
                // authenticated SEND — clears the T6 arm, paces T8.
                engine.note_handshake_sent(peer_pubkey, monotonic_nanos());
            }
            Err(e) => {
                WgCounters::bump(&engine.counters().hs_send_errors);
                record_local_tunnel_exception(
                    recent_exceptions,
                    tunnel_name,
                    format!("wg_initiation_send:{endpoint}:{e}"),
                );
            }
        }
    }
}
