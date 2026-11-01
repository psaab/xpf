//! #18722, production evidence chain. The session-level cells
//! (`session/idle_served_keepalive_18722_tests.rs`) model the HA context
//! with a closure. This cell wires the closure production builds
//! (`housekeeping.rs`: `shared_node_served_evidence` over the shared
//! synced map) and drives the shared row's counts through the batch
//! restamp the serving worker's ct-slice runs once per refresh cycle
//! (`run_shared_evidence_leg` -> `restamp_shared_packet_counts_batch`).
//!
//! It pins that the recency proof the expiry pass reads is the one
//! production actually moves: while the serving pair forwards, the
//! restamps advance `served_packets` and the opening replica survives;
//! once they stop, the replica reaps within two of its windows. A
//! `shared_node_served_evidence` that dropped the counts (the pre-#18722
//! shape) leaves `served_packets` at 0, so the replica reaps on its first
//! crossed window even while served: the survival half reds.

use super::*;
use crate::afxdp::testfx::{test_key, test_metadata, test_resolution};
use crate::session::{
    ExpireHaContext, STALE_SYNCED_CEILING_ABS_NS, STALE_SYNCED_CEILING_MULT, SessionDecision,
    TcpHandshakeState,
};
use crate::tcp_flags::TCP_SYN;

const SEC: u64 = 1_000_000_000;
/// `slice_pacing::CT_REFRESH_WINDOW_NS`: the shared-evidence leg's cadence.
const RESTAMP_EVERY: u64 = 10 * SEC;

fn decision() -> SessionDecision {
    SessionDecision {
        resolution: test_resolution(),
        nat: crate::nat::NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

/// The serving pair's canonical shared row: Established, counts as the
/// ct-slice last restamped them (0 until the first restamp).
fn serving_row(key: &SessionKey) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: key.clone(),
        decision: decision(),
        metadata: test_metadata(),
        source_nat_static: None,
        leak_incarnation: 0,
        origin: crate::session::SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id: 0x18722,
        tcp_close_class: 0,
        tcp_handshake_state: TcpHandshakeState::Established.to_wire(),
        rev_packets: 0,
        fwd_packets: 0,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
    }
}

#[test]
fn shared_restamps_keep_an_opening_replica_only_while_they_advance_18722() {
    let forward = test_key();
    let reverse = crate::session::reverse_session_key(&forward, crate::nat::NatDecision::default());
    let t0 = 1_000 * SEC;
    // This worker's replica pair: pure Opening, never answered here.
    let mut table = SessionTable::new();
    assert!(table.install_with_protocol(
        forward.clone(),
        decision(),
        test_metadata(),
        t0,
        PROTO_TCP,
        TCP_SYN
    ));
    let mut reverse_metadata = test_metadata();
    reverse_metadata.is_reverse = true;
    assert!(table.install_with_protocol(
        reverse.clone(),
        decision(),
        reverse_metadata,
        t0,
        PROTO_TCP,
        TCP_SYN
    ));
    let window = 20 * SEC;
    assert_eq!(
        table.timeout_secs_for(&forward),
        20,
        "premise: opening window"
    );

    let shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    shared_sessions
        .lock()
        .expect("shared")
        .insert(forward.clone(), serving_row(&forward));
    // The production closure (`housekeeping.rs`).
    let node_served = |key: &SessionKey| {
        crate::afxdp::shared_ops::shared_node_served_evidence(&shared_sessions, key)
    };
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ExpireHaContext {
        node_active: true,
        forwards_rg: &forwards,
        epoch_of: &epoch,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
        node_served: &node_served,
    };

    // The serving worker forwards 100 packets each way per second; its
    // ct-slice restamps the live counts every refresh cycle.
    let restamp = |now: u64| {
        let elapsed = (now - t0) / SEC;
        crate::afxdp::shared_ops::restamp_shared_packet_counts_batch(
            &shared_sessions,
            &shared_forward_wire_sessions,
            &[(
                forward.clone(),
                crate::nat::NatDecision::default(),
                100 * elapsed,
                100 * elapsed,
            )],
        );
    };
    let quiet_at = t0 + 4 * window;
    let mut now = t0;
    while now < quiet_at {
        now += SEC;
        if (now - t0) % RESTAMP_EVERY == 0 {
            restamp(now);
        }
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
    }
    assert!(
        crate::afxdp::shared_ops::shared_node_served_evidence(&shared_sessions, &forward)
            .served_packets
            > 0,
        "premise: the production evidence carries the restamped counts"
    );
    assert!(
        table.entry_with_origin(&forward).is_some() && table.entry_with_origin(&reverse).is_some(),
        "#16223/#18722: the replica survives four windows while the serving pair's \
         restamped counts advance"
    );
    // The client dies without a FIN: no more packets, no more advance. The
    // last restamp was at +80 s; crossed checks fall at +84 s and +105 s.
    // Exact contract: the window-1 check (+84 s) still sees that restamp and
    // KEEPS the replica, the window-2 check (+105 s) REAPS it.
    let mut events: Vec<(&'static str, u64)> = Vec::new();
    while now < quiet_at + 10 * window {
        now += SEC;
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        if table.last_pop_stats().kept_alive_by_companion > 0 {
            events.push(("kept", now));
        }
        if table.entry_with_origin(&forward).is_none()
            && table.entry_with_origin(&reverse).is_none()
        {
            events.push(("reaped", now));
            break;
        }
    }
    let rel: Vec<_> = events
        .iter()
        .map(|(e, t)| (*e, (t - quiet_at) / SEC))
        .collect();
    assert_eq!(
        events.len(),
        2,
        "#18722: expected [kept at the window-1 check, reaped at the window-2 check] after the \
         last restamp, got {rel:?} (seconds after it)"
    );
    assert_eq!(
        events[0].0, "kept",
        "#18722: the window-1 check must KEEP, got {rel:?}"
    );
    assert_eq!(
        events[1].0, "reaped",
        "#18722: the window-2 check must REAP, got {rel:?}"
    );
    assert!(
        events[0].1 <= quiet_at + window + 2 * SEC,
        "#18722: the keep must be the first crossed check after the last restamp, got {rel:?}"
    );
    assert!(
        events[1].1 > events[0].1 + window && events[1].1 <= events[0].1 + window + 2 * SEC,
        "#18722: the reap must be the next crossed check, one window after the keep, got {rel:?}"
    );
}
