//! #18722: the expiry pass's node-level retention arm
//! (`opening_companion_keeps_alive`, #16223) kept rows on CUMULATIVE
//! evidence. `promoted_and_served()` is true for every TCP flow that was
//! ever answered (an Established wire somewhere plus reverse counters
//! that only grow), and the arm re-stamped `last_seen_ns = now_ns` on
//! each pass. So an idle ESTABLISHED flow (a crashed client, a sleeping
//! NAT'd device: no FIN, no RST) re-stamped itself for ever: no Close
//! delta, no RT_FLOW close, and the session plus its NAT binding were
//! held until the table or the pool filled.
//!
//! The contract these cells pin:
//! 1. A completed row is its own serving pair, so node-level evidence
//!    cannot retain it. It reaps one window after its last packet in
//!    either direction (`companion_keeps_alive`) and emits its Close.
//! 2. An OPENING row (the #16223 split-posture replica) is kept only
//!    while the node-wide served packet total ADVANCES between checks.
//! 3. Once that total stops, the opening row reaps within two of its
//!    windows: the first crossed check may still see the last advance.
//!
//! Time is simulated (explicit `now_ns`), never the wall clock (#8218).

use super::tests::{install_forward_reverse_pair, key_v4};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_PSH, TCP_SYN};
use std::cell::Cell;

const SEC: u64 = 1_000_000_000;
const MS: u64 = 1_000_000;

fn ha_with<'a>(
    node_served: &'a dyn Fn(&SessionKey) -> NodeServedEvidence,
    forwards: &'a dyn Fn(i32) -> bool,
    epoch: &'a dyn Fn(i32) -> u32,
) -> ExpireHaContext<'a> {
    ExpireHaContext {
        node_active: true,
        forwards_rg: forwards,
        epoch_of: epoch,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
        node_served,
    }
}

/// What `shared_node_served_evidence` returns for a tuple whose shared
/// row is Established with `served` restamped packets.
fn shared_established(served: u64) -> NodeServedEvidence {
    NodeServedEvidence {
        handshake_wire: TcpHandshakeState::Established.to_wire(),
        shared_established: true,
        served_packets: served,
        ..NodeServedEvidence::default()
    }
}

/// THE #18722 SHAPE: a locally authored TCP flow, handshake complete and
/// answered (forward SYN, reverse SYN-ACK, forward ACK, then data both
/// ways, all accounted), then silent. The HA context reports what
/// production reports for it: its own shared row, Established, with the
/// counts the ct-slice last restamped (frozen, because nothing moves).
/// Idle past the established window, BOTH halves must reap and the
/// forward half must emit its Close (the RT_FLOW close and the HA Close
/// both ride that delta).
///
/// RED pre-fix: both halves are re-stamped to `now_ns` by the node-level
/// arm and nothing expires. Also red with only the advance check (no
/// opening gate): the first crossed check reads the frozen total as an
/// advance over the zero baseline and keeps the pair one more window.
#[test]
fn idle_established_served_flow_reaps_with_its_close_18722() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let t0 = 1_000 * SEC;
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_SYN);
    assert!(
        table
            .lookup_with_origin(&reverse, t0 + MS, TCP_SYN | TCP_ACK)
            .is_some()
    );
    table.account_packet(&reverse, 60, TCP_SYN | TCP_ACK, 0);
    assert!(
        table
            .lookup_with_origin(&forward, t0 + 2 * MS, TCP_ACK)
            .is_some()
    );
    table.account_packet(&forward, 52, TCP_ACK, 0);
    let last = t0 + 3 * MS;
    assert!(
        table
            .lookup_with_origin(&forward, last, TCP_ACK | TCP_PSH)
            .is_some()
    );
    table.account_packet(&forward, 1_000, TCP_ACK | TCP_PSH, 0);
    assert!(
        table
            .lookup_with_origin(&reverse, last, TCP_ACK | TCP_PSH)
            .is_some()
    );
    table.account_packet(&reverse, 1_400, TCP_ACK | TCP_PSH, 0);
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("premise: installed half");
        assert!(
            entry.established && !entry.handshake_pending && !entry.closing,
            "{label}: premise, the handshake completed"
        );
    }
    let local = table.node_served_evidence(&forward);
    assert!(
        local.promoted_and_served(),
        "premise: the flow's own rows are promoted-and-served evidence (the input that kept it alive)"
    );
    let window = table
        .entry_by_key(&forward)
        .expect("forward")
        .expires_after_ns;
    assert_eq!(
        window, table.timeouts.tcp_established_ns,
        "premise: established window"
    );
    let _ = table.drain_deltas(64);

    let frozen = shared_established(4);
    let node_served = move |_: &SessionKey| frozen;
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    // Still inside the window: nothing reaps (anti-vacuity for the reap below).
    let _ = table.expire_stale_entries_ha(last + window - SEC, Some(&ha));
    assert!(
        table.entry_by_key(&forward).is_some(),
        "inside the window the flow stays"
    );
    let past = last + window + 2 * SEC;
    let expired = table.expire_stale_entries_ha(past, Some(&ha));
    let stats = table.last_pop_stats();
    assert_eq!(
        stats.kept_alive_by_companion, 0,
        "#18722: no keep-alive arm may retain an idle completed flow on node-level evidence"
    );
    assert!(
        table.entry_by_key(&forward).is_none() && table.entry_by_key(&reverse).is_none(),
        "#18722: an idle established flow must reap one window after its last packet"
    );
    assert!(
        expired.iter().any(|e| e.key == forward) && expired.iter().any(|e| e.key == reverse),
        "#18722: both halves must be returned for teardown (NAT release, BPF delete)"
    );
    let closes: Vec<_> = table
        .drain_deltas(64)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Close && d.key == forward)
        .collect();
    let overflow = expired
        .iter()
        .filter(|e| e.key == forward && e.overflow_close.is_some())
        .count();
    assert_eq!(
        closes.len() + overflow,
        1,
        "#18722: the reaped flow must emit exactly one Close (RT_FLOW close + HA Close)"
    );
}

/// Install a pure-Opening pair (the #16223 fw0 replica shape: never
/// answered locally, so neither local arm can keep it) on the 20 s
/// opening window.
fn opening_replica(t0: u64) -> (SessionTable, SessionKey, SessionKey, u64) {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_SYN);
    let window = table
        .entry_by_key(&forward)
        .expect("forward")
        .expires_after_ns;
    assert_eq!(
        window, table.timeouts.tcp_opening_ns,
        "premise: opening window"
    );
    for key in [&forward, &reverse] {
        let entry = table.entry_by_key(key).expect("half");
        assert!(
            !entry.established && !entry.handshake_pending,
            "premise: pure Opening replica"
        );
    }
    (table, forward, reverse, window)
}

/// The serving pair lives elsewhere on the node and keeps forwarding:
/// its ct-slice restamps the shared row's counts every 10 s
/// (`CT_REFRESH_WINDOW_NS`). The opening replica must survive five of
/// its windows, kept by the advancing total alone.
#[test]
fn opening_replica_is_kept_while_its_serving_pair_advances_18722() {
    let t0 = 1_000 * SEC;
    let (mut table, forward, reverse, window) = opening_replica(t0);
    let served = Cell::new(10u64);
    let node_served = |_: &SessionKey| shared_established(served.get());
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    let mut kept = 0usize;
    let end = t0 + 5 * window;
    let mut now = t0;
    while now < end {
        now += SEC;
        if (now - t0) % (10 * SEC) == 0 {
            served.set(served.get() + 25);
        }
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        kept += table.last_pop_stats().kept_alive_by_companion;
    }
    assert!(
        table.entry_by_key(&forward).is_some() && table.entry_by_key(&reverse).is_some(),
        "#16223/#18722: a replica whose serving pair keeps forwarding must survive"
    );
    assert!(
        kept >= 2,
        "anti-vacuity: retention must have come from the node-level arm (kept {kept} times)"
    );
}

/// The same replica after its serving pair goes quiet (the client died
/// without FIN): the restamped total freezes at `quiet_at`. Crossed checks
/// fall at +21 s, +42 s, +63 s (each re-stamps to its own instant), so
/// the last advance (+60 s) lands between the +42 s and +63 s checks. The
/// exact contract: the +63 s check (window 1 after quiet) still sees that
/// advance and KEEPS the replica; the +84 s check (window 2) REAPS it.
/// RED with the cumulative check restored: every check keeps it.
#[test]
fn opening_replica_reaps_once_its_serving_pair_goes_quiet_18722() {
    let t0 = 1_000 * SEC;
    let (mut table, forward, reverse, window) = opening_replica(t0);
    let served = Cell::new(10u64);
    let node_served = |_: &SessionKey| shared_established(served.get());
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    let quiet_at = t0 + 3 * window;
    let mut now = t0;
    while now < quiet_at {
        now += SEC;
        if (now - t0) % (10 * SEC) == 0 {
            served.set(served.get() + 25);
        }
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
    }
    assert!(
        table.entry_by_key(&forward).is_some() && table.entry_by_key(&reverse).is_some(),
        "anti-vacuity: the replica was alive while its serving pair advanced"
    );
    let events = run_gc_events(
        &mut table,
        &ha,
        &forward,
        &reverse,
        quiet_at,
        quiet_at + 10 * window,
    );
    assert_keep_then_reap(&events, quiet_at, window, "local opening pair");
}

/// Import a forward/reverse REPLICA pair as the HA import path does
/// (`upsert_synced_with_origin`), with `wire` as the owner's handshake state.
fn import_replica_pair(
    table: &mut SessionTable,
    origin: SessionOrigin,
    wire: u8,
    now_ns: u64,
) -> (SessionKey, SessionKey) {
    let forward = key_v4();
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());
    for (key, is_reverse, session_id) in [
        (&forward, false, 0x1_8722u64),
        (&reverse, true, 0x2_8722u64),
    ] {
        let mut metadata = super::tests::metadata();
        metadata.is_reverse = is_reverse;
        assert!(
            table.upsert_synced_with_origin(
                SessionInstall {
                    key: key.clone(),
                    decision: super::tests::decision(),
                    metadata,
                    source_nat_static: None,
                    origin,
                    now_ns,
                    protocol: crate::ip_proto::PROTO_TCP,
                    tcp_flags: 0,
                    session_id,
                    tcp_close_class: 0,
                    tcp_handshake_state: wire,
                    persistent_lease_hold: None,
                    fwd_packets: 40,
                    rev_packets: 40,
                },
                false,
            ),
            "premise: the replica import must install"
        );
    }
    (forward, reverse)
}

/// LIVE SHAPE 1 (udp, node1): an ESTABLISHED replica on a node that
/// forwards its RG (the HA `Age` path), its tuple's shared row Established
/// with frozen counts. Both replica origins the node-level arm treats as
/// local service are covered. It must reap within ONE established window
/// of its last refresh. RED on master: the cumulative node-level arm
/// re-stamps it on every pass and it never ages out.
#[test]
fn idle_established_replica_reaps_within_one_window_18722() {
    for origin in [SessionOrigin::SyncImport, SessionOrigin::WorkerLocalImport] {
        let t0 = 1_000 * SEC;
        let mut table = SessionTable::new();
        let (forward, reverse) = import_replica_pair(
            &mut table,
            origin,
            TcpHandshakeState::Established.to_wire(),
            t0,
        );
        let window = table
            .entry_by_key(&forward)
            .expect("forward")
            .expires_after_ns;
        assert_eq!(
            window, table.timeouts.tcp_established_ns,
            "{origin:?}: premise, established window"
        );
        for key in [&forward, &reverse] {
            let entry = table.entry_by_key(key).expect("half");
            assert!(
                entry.established && !entry.handshake_pending,
                "{origin:?}: premise, an established replica"
            );
        }
        let frozen = shared_established(80);
        let node_served = move |_: &SessionKey| frozen;
        let forwards = |_: i32| true;
        let epoch = |_: i32| 0u32;
        let ha = ha_with(&node_served, &forwards, &epoch);
        let _ = table.expire_stale_entries_ha(t0 + window - SEC, Some(&ha));
        assert!(
            table.entry_by_key(&forward).is_some(),
            "{origin:?}: anti-vacuity, the replica lives inside its window"
        );
        let _ = table.expire_stale_entries_ha(t0 + window + 2 * SEC, Some(&ha));
        assert!(
            table.entry_by_key(&forward).is_none() && table.entry_by_key(&reverse).is_none(),
            "#18722 {origin:?}: an idle established replica must age out one window after its \
             last refresh, not be re-stamped for ever by its own cumulative evidence"
        );
    }
}

/// LIVE SHAPE 2 (udp, node0): an OPENING replica (20 s window) of the same
/// dead flow, its shared row Established with frozen counts. THE BOUND IS
/// EXACT: the window-1 crossed check still sees the counts as an advance
/// over the zero baseline (the last activity before the flow went quiet), so
/// it KEEPS both halves; the window-2 check sees no advance and reaps them.
/// RED on master: every check keeps them, for ever.
#[test]
fn idle_opening_replica_reaps_within_two_windows_18722() {
    for origin in [SessionOrigin::SyncImport, SessionOrigin::WorkerLocalImport] {
        let t0 = 1_000 * SEC;
        let mut table = SessionTable::new();
        let (forward, reverse) =
            import_replica_pair(&mut table, origin, TcpHandshakeState::Opening.to_wire(), t0);
        let window = table
            .entry_by_key(&forward)
            .expect("forward")
            .expires_after_ns;
        assert_eq!(
            window, table.timeouts.tcp_opening_ns,
            "{origin:?}: premise, opening window"
        );
        let frozen = shared_established(80);
        let node_served = move |_: &SessionKey| frozen;
        let forwards = |_: i32| true;
        let epoch = |_: i32| 0u32;
        let ha = ha_with(&node_served, &forwards, &epoch);
        let events = run_gc_events(&mut table, &ha, &forward, &reverse, t0, t0 + 10 * window);
        assert_keep_then_reap(&events, t0, window, &format!("{origin:?}"));
    }
}

/// One GC pass per second over `(from, to]`. Records each pass that KEPT a
/// half (`kept_alive_by_companion`) and the pass that reaped both halves.
fn run_gc_events(
    table: &mut SessionTable,
    ha: &ExpireHaContext<'_>,
    forward: &SessionKey,
    reverse: &SessionKey,
    from: u64,
    to: u64,
) -> Vec<(&'static str, u64)> {
    let mut events = Vec::new();
    let mut now = from;
    while now < to {
        now += SEC;
        let _ = table.expire_stale_entries_ha(now, Some(ha));
        if table.last_pop_stats().kept_alive_by_companion > 0 {
            events.push(("kept", now));
        }
        if table.entry_by_key(forward).is_none() && table.entry_by_key(reverse).is_none() {
            events.push(("reaped", now));
            break;
        }
    }
    events
}

/// The exact two-window contract after `quiet` (the last advance the
/// serving pair made): the first crossed check after it KEEPS the row (it
/// still sees that advance), the next crossed check, one window later,
/// REAPS it, and nothing else happens in between.
fn assert_keep_then_reap(events: &[(&'static str, u64)], quiet: u64, window: u64, label: &str) {
    let rel: Vec<_> = events
        .iter()
        .map(|(e, t)| (*e, (t - quiet) / SEC))
        .collect();
    assert_eq!(
        events.len(),
        2,
        "#18722 {label}: expected exactly [kept at the window-1 check, reaped at the window-2 \
         check] after the last advance, got {rel:?} (seconds after it)"
    );
    let (kept_ev, kept_at) = events[0];
    let (reap_ev, reaped_at) = events[1];
    assert_eq!(
        kept_ev, "kept",
        "#18722 {label}: the window-1 check must KEEP the row, got {rel:?}"
    );
    assert_eq!(
        reap_ev, "reaped",
        "#18722 {label}: the window-2 check must REAP the row, got {rel:?}"
    );
    assert!(
        kept_at > quiet && kept_at <= quiet + window + 2 * SEC,
        "#18722 {label}: the keep must be the first crossed check after the last advance, got {rel:?}"
    );
    assert!(
        reaped_at > kept_at + window && reaped_at <= kept_at + window + 2 * SEC,
        "#18722 {label}: the reap must be the next crossed check, one window after the keep, got {rel:?}"
    );
}
