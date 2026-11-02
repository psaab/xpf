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
        shared_served: Some(served),
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
/// with FROZEN counts (the flow is dead). Both replica origins are
/// covered. A replica is not the serving pair, so it takes the node-level
/// arm: the window-1 check still reads the frozen counts as a change from
/// the zero baseline and KEEPS it, the window-2 check REAPS it. RED on
/// master: the cumulative node-level arm keeps it for ever.
#[test]
fn idle_established_replica_reaps_within_two_windows_18722() {
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
        let events = run_gc_events(&mut table, &ha, &forward, &reverse, t0, t0 + 10 * window);
        assert_keep_then_reap(&events, t0, window, &format!("established {origin:?}"));
    }
}

/// #18742 F1 (seat L): the LIVE twin. The same established replica on a
/// worker that serves neither direction (its halves are never refreshed
/// here) while the serving worker elsewhere on the node keeps forwarding:
/// its ct-slice restamps the shared counts every 10 s. The replica must
/// survive five windows; reaping it would run the replica teardown
/// (conntrack mirror delete, flow-cache eviction) under the live flow.
/// RED at 1981f3299e, whose opening-only gate sent every completed row to
/// `companion_keeps_alive` alone and reaped this one at window 1.
#[test]
fn live_established_replica_is_kept_while_its_serving_pair_advances_18722() {
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
        let served = Cell::new(80u64);
        let node_served = |_: &SessionKey| shared_established(served.get());
        let forwards = |_: i32| true;
        let epoch = |_: i32| 0u32;
        let ha = ha_with(&node_served, &forwards, &epoch);
        let mut kept = 0usize;
        let mut now = t0;
        while now < t0 + 5 * window {
            now += SEC;
            if (now - t0) % (10 * SEC) == 0 {
                served.set(served.get() + 25);
            }
            let _ = table.expire_stale_entries_ha(now, Some(&ha));
            kept += table.last_pop_stats().kept_alive_by_companion;
        }
        assert!(
            table.entry_by_key(&forward).is_some() && table.entry_by_key(&reverse).is_some(),
            "#18742 F1 {origin:?}: a live flow's established replica must survive on a \
             non-serving worker while the serving pair's counts move"
        );
        assert!(
            kept >= 2,
            "{origin:?}: anti-vacuity, the node-level arm kept it ({kept})"
        );
    }
}

/// #18742 (seat L, MINOR): the served total can DROP while the flow lives
/// (a local serving pair removed, the shared row republished lower). A drop
/// is a change, not silence, so the replica is kept; only an unchanged total
/// reaps it. Events: kept at +21 s (0 -> 100), kept at +42 s (100 -> 60, the
/// drop), reaped at +63 s (60 unchanged). RED with an increase-only (`>`)
/// check: the drop reads as no advance and the live replica reaps at +42 s.
#[test]
fn a_served_total_drop_counts_as_a_change_18722() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let (forward, reverse) = import_replica_pair(
        &mut table,
        SessionOrigin::SyncImport,
        TcpHandshakeState::Opening.to_wire(),
        t0,
    );
    let window = table
        .entry_by_key(&forward)
        .expect("forward")
        .expires_after_ns;
    assert_eq!(window, 20 * SEC, "premise: opening window");
    let served = Cell::new(100u64);
    let node_served = |_: &SessionKey| shared_established(served.get());
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    let mut events = Vec::new();
    let mut now = t0;
    while now < t0 + 10 * window {
        now += SEC;
        if now == t0 + 30 * SEC {
            served.set(60);
        }
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        if table.last_pop_stats().kept_alive_by_companion > 0 {
            events.push(("kept", (now - t0) / SEC));
        }
        if table.entry_by_key(&forward).is_none() && table.entry_by_key(&reverse).is_none() {
            events.push(("reaped", (now - t0) / SEC));
            break;
        }
    }
    assert_eq!(
        events,
        vec![("kept", 21), ("kept", 42), ("reaped", 63)],
        "#18742: a drop in the served total must keep the replica; only an unchanged total reaps it"
    );
}

/// #18742 (seat U, NIT): the bounds are for a node that FORWARDS the RG. On a
/// node that does not, the #2120 standby gate HOLDS peer-synced replicas
/// regardless of activity (that is what keeps a flow alive across a
/// failover, #131) until the owner's delete or the stale ceiling. Both idle
/// shapes, frozen evidence: still present two windows in, counted as held.
#[test]
fn standby_holds_idle_replicas_regardless_of_activity_18722() {
    for wire in [
        TcpHandshakeState::Established.to_wire(),
        TcpHandshakeState::Opening.to_wire(),
    ] {
        let t0 = 1_000 * SEC;
        let mut table = SessionTable::new();
        let (forward, reverse) =
            import_replica_pair(&mut table, SessionOrigin::SyncImport, wire, t0);
        let window = table
            .entry_by_key(&forward)
            .expect("forward")
            .expires_after_ns;
        let frozen = shared_established(80);
        let node_served = move |_: &SessionKey| frozen;
        let forwards = |_: i32| false;
        let epoch = |_: i32| 0u32;
        let ha = ha_with(&node_served, &forwards, &epoch);
        let mut held = 0usize;
        let mut now = t0;
        // Two windows plus slack: past where the `Age` path reaps (window 2).
        let probe_at = t0 + 2 * window + 3 * SEC;
        if window > 100 * SEC {
            // Established: one jump per window boundary keeps the loop short.
            for at in [t0 + window + 2 * SEC, probe_at] {
                let _ = table.expire_stale_entries_ha(at, Some(&ha));
                held += table.last_pop_stats().held_standby;
            }
        } else {
            while now < probe_at {
                now += SEC;
                let _ = table.expire_stale_entries_ha(now, Some(&ha));
                held += table.last_pop_stats().held_standby;
            }
        }
        assert!(
            table.entry_by_key(&forward).is_some() && table.entry_by_key(&reverse).is_some(),
            "#18722 wire {wire}: on a node that does not forward the RG the replica is HELD, \
             not aged by the node-level arm"
        );
        assert!(
            held > 0,
            "wire {wire}: anti-vacuity, the standby HOLD arm ran ({held})"
        );
    }
}

/// #18742 (seat U, NIT): promotion. A replica imported while this node is
/// standby is held; then the RG moves here (forwarding flips with an epoch
/// bump). SelfHeal re-stamps it at the promotion, so it gets a FULL window
/// from the promotion before any check, then the replica contract (frozen
/// counts: kept at window 1, reaped at window 2) applies from there.
#[test]
fn promotion_selfheals_then_ages_on_the_replica_contract_18722() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let (forward, reverse) = import_replica_pair(
        &mut table,
        SessionOrigin::SyncImport,
        TcpHandshakeState::Opening.to_wire(),
        t0,
    );
    let window = table
        .entry_by_key(&forward)
        .expect("forward")
        .expires_after_ns;
    let frozen = shared_established(80);
    let node_served = move |_: &SessionKey| frozen;
    let forwarding = Cell::new(false);
    let rg_epoch = Cell::new(0u32);
    let forwards = |_: i32| forwarding.get();
    let epoch = |_: i32| rg_epoch.get();
    let ha = ha_with(&node_served, &forwards, &epoch);
    let mut now = t0;
    while now < t0 + 30 * SEC {
        now += SEC;
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
    }
    assert!(
        table.entry_by_key(&forward).is_some(),
        "premise: held while standby"
    );
    forwarding.set(true);
    rg_epoch.set(1);
    // The GC visits a held row at its held re-check tick, so SelfHeal fires
    // there, not at the flip itself; the contract is relative to the heal.
    let mut heal_at = None;
    let mut events = Vec::new();
    while now < t0 + 30 * SEC + 20 * window {
        now += SEC;
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        let stats = table.last_pop_stats();
        if heal_at.is_none() && stats.healed_on_promote > 0 {
            heal_at = Some(now);
            continue;
        }
        let Some(healed) = heal_at else { continue };
        if stats.kept_alive_by_companion > 0 {
            events.push(("kept", now));
        }
        if table.entry_by_key(&forward).is_none() && table.entry_by_key(&reverse).is_none() {
            events.push(("reaped", now));
            break;
        }
        if now < healed + window {
            assert!(
                events.is_empty(),
                "#18722: no keep-alive decision may run inside the window after the SelfHeal"
            );
        }
    }
    let healed = heal_at.expect("anti-vacuity: the promotion edge must self-heal the replica");
    assert_keep_then_reap(&events, healed, window, "promoted replica");
}

/// #18671 interaction (merged in this branch): a moved session's packets
/// arrive keyed by its forward-wire tuple, and since #18656 the probe
/// serves them on the canonical row (accounting included). Those hits must
/// advance the row's served total, so the node-level arm's recency proof
/// sees a live moved flow.
#[test]
fn wire_keyed_hits_on_a_moved_session_advance_the_served_total_18722() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            172, 16, 80, 8,
        ))),
        rewrite_src_port: Some(40000),
        ..crate::nat::NatDecision::default()
    };
    let mut d = super::tests::decision();
    d.nat = nat;
    let now = 10 * SEC;
    assert!(table.upsert_synced(
        forward.clone(),
        d,
        super::tests::metadata(),
        now,
        crate::ip_proto::PROTO_TCP,
        TCP_ACK,
        false
    ));
    let reverse = reverse_session_key(&forward, nat);
    let mut rmeta = super::tests::metadata();
    rmeta.is_reverse = true;
    assert!(table.upsert_synced(
        reverse,
        d,
        rmeta,
        now,
        crate::ip_proto::PROTO_TCP,
        TCP_ACK,
        false
    ));
    let wire = forward_wire_key(&forward, nat);
    assert_ne!(wire, forward, "premise: SNAT moves the forward wire tuple");
    let before = table
        .node_served_evidence(&forward)
        .local_served
        .expect("premise: forward row present");
    let mut wire_canonical = None;
    let verdict = table.probe_hit_deferring_state_update_with_ack_rollback_verdict(
        &wire,
        now + 600 * SEC,
        1514,
        TCP_ACK | TCP_PSH,
        1448,
        0,
        None,
        false,
        &mut wire_canonical,
    );
    assert_eq!(
        verdict,
        ProbeHitVerdict::Live,
        "premise: the wire-keyed hit is served (#18656)"
    );
    let after = table
        .node_served_evidence(&forward)
        .local_served
        .expect("forward row present");
    assert!(
        after > before,
        "#18722 x #18671: a wire-keyed hit on a moved session must advance the served total \
         ({before} -> {after})"
    );
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

/// #18742 case 2 (coordinator): a DEAD flow whose companion is removed
/// FIRST. Both halves are kept once at the window-1 check (+21 s; the arm
/// keeps the pair together). Then the forward half is removed before the
/// next check (+30 s), the way its own owner's Close or reap removes it.
/// Its counters were the reverse half's local contributor, so that
/// contributor VANISHES. Absent is not a change, so the reverse half still
/// reaps at its window-2 check (+42 s), not one window later. RED under a
/// summed total compared with `!=` (the vanished counters read as a drop,
/// a "change"), and RED with an absent contributor read as 0.
#[test]
fn a_removed_companion_is_not_activity_18722() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let (forward, reverse) = import_replica_pair(
        &mut table,
        SessionOrigin::SyncImport,
        TcpHandshakeState::Opening.to_wire(),
        t0,
    );
    let frozen = shared_established(80);
    let node_served = move |_: &SessionKey| frozen;
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    let mut kept_at = Vec::new();
    let mut reverse_gone = None;
    let mut now = t0;
    while now < t0 + 200 * SEC && reverse_gone.is_none() {
        now += SEC;
        if now == t0 + 30 * SEC {
            assert!(
                table.entry_by_key(&forward).is_some(),
                "premise: the forward half was kept at +21 s"
            );
            table.delete(&forward);
        }
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        if table.last_pop_stats().kept_alive_by_companion > 0 {
            kept_at.push((now - t0) / SEC);
        }
        if table.entry_by_key(&reverse).is_none() {
            reverse_gone = Some((now - t0) / SEC);
        }
    }
    assert_eq!(
        kept_at,
        vec![21],
        "premise: one keep, at the window-1 check"
    );
    assert_eq!(
        reverse_gone,
        Some(42),
        "#18742: the reverse half must reap at its window-2 check; its removed companion's \
         vanished counters are not activity"
    );
}

/// #18742 case 1 (seat L): a LIVE flow whose evidence source is REPLACED.
/// The reverse replica's local contributor is its forward row, which this
/// table serves (counters advancing). At +30 s that forward row is removed
/// (the pair moved), and the shared row is republished by a new serving
/// incarnation with LOWER counts that then advance again. The live replica
/// must survive three more windows. RED under a summed total compared with
/// `>` (the sum drops: false silence, false reap), and RED with per-
/// contributor `>` (the republished-lower shared count is below its old
/// baseline at the next check).
#[test]
fn a_live_flows_replaced_source_is_activity_not_silence_18722() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let (forward, reverse) = import_replica_pair(
        &mut table,
        SessionOrigin::SyncImport,
        TcpHandshakeState::Opening.to_wire(),
        t0,
    );
    let window = table
        .entry_by_key(&reverse)
        .expect("reverse")
        .expires_after_ns;
    let shared = Cell::new(300u64);
    let node_served = |_: &SessionKey| shared_established(shared.get());
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    let replaced_at = t0 + 30 * SEC;
    let mut now = t0;
    while now < replaced_at + 3 * window {
        now += SEC;
        if now < replaced_at {
            // This table serves the forward row: its counters advance.
            table.account_packet(&forward, 100, TCP_ACK, 0);
        }
        if now == replaced_at {
            table.delete(&forward);
            shared.set(20);
        }
        if now > replaced_at && (now - t0) % (10 * SEC) == 0 {
            shared.set(shared.get() + 25);
        }
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        assert!(
            table.entry_by_key(&reverse).is_some(),
            "#18742: the live flow's replica was reaped at +{} s after its source was replaced",
            (now - t0) / SEC
        );
    }
}

/// Install one replica row (either half) as the HA import path does.
#[expect(
    clippy::too_many_arguments,
    reason = "#18722 test helper: one import per field"
)]
fn import_row(
    table: &mut SessionTable,
    key: &SessionKey,
    is_reverse: bool,
    origin: SessionOrigin,
    wire: u8,
    close_class: u8,
    now_ns: u64,
    allow_replace_local: bool,
) {
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
                protocol: key.protocol,
                tcp_flags: 0,
                session_id: if is_reverse { 0x9_8722 } else { 0x8_8722 },
                tcp_close_class: close_class,
                tcp_handshake_state: wire,
                persistent_lease_hold: None,
                fwd_packets: 40,
                rev_packets: 40,
            },
            allow_replace_local,
        ),
        "premise: the replica row must install"
    );
}

/// PAIR-MODEL EXCEPTION 1: a CLOSING companion is never aligned. The
/// forward replica is kept by the node-level arm at +21 s; the reverse
/// half is CLOSING in TIME_WAIT (close class 2, both FIN bits, so the
/// classic `companion_keeps_alive` cannot keep the forward half from it and
/// the node-level arm is what keeps it) and was imported at +15 s, so it
/// has not crossed. The keep must not re-stamp it or move its baselines: it
/// keeps its own close fuse (#10885/#14630).
#[test]
fn pair_exception_closing_companion_is_not_aligned_18722() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let forward = key_v4();
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());
    let established = TcpHandshakeState::Established.to_wire();
    import_row(
        &mut table,
        &forward,
        false,
        SessionOrigin::SyncImport,
        TcpHandshakeState::Opening.to_wire(),
        0,
        t0,
        false,
    );
    import_row(
        &mut table,
        &reverse,
        true,
        SessionOrigin::SyncImport,
        established,
        2,
        t0 + 15 * SEC,
        false,
    );
    assert!(
        table.entry_by_key(&reverse).expect("reverse").closing,
        "premise: the companion is closing"
    );
    let frozen = shared_established(80);
    let node_served = move |_: &SessionKey| frozen;
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    let mut now = t0;
    while now < t0 + 21 * SEC {
        now += SEC;
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
    }
    assert!(
        table.last_pop_stats().kept_alive_by_companion > 0,
        "premise: the forward half was kept at +21 s"
    );
    let rev = table
        .entry_by_key(&reverse)
        .expect("the closing companion is still present");
    assert_eq!(
        rev.last_seen_ns,
        t0 + 15 * SEC,
        "#18722: a closing companion is not re-stamped by the pair keep"
    );
    assert_eq!(
        (rev.node_served_seen_local, rev.node_served_seen_shared),
        (0, 0),
        "#18722: a closing companion does not take the pair baselines"
    );
}

/// PAIR-MODEL EXCEPTION 2: NON-TCP pairs never take the node-level arm.
/// A UDP replica pair with served, advancing node evidence still ages on
/// the classic rules: both halves reap at their own window.
#[test]
fn pair_exception_non_tcp_never_takes_the_arm_18722() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let mut forward = key_v4();
    forward.protocol = crate::ip_proto::PROTO_UDP;
    forward.dst_port = 53;
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());
    import_row(
        &mut table,
        &forward,
        false,
        SessionOrigin::SyncImport,
        0,
        0,
        t0,
        false,
    );
    import_row(
        &mut table,
        &reverse,
        true,
        SessionOrigin::SyncImport,
        0,
        0,
        t0,
        false,
    );
    let window = table
        .entry_by_key(&forward)
        .expect("forward")
        .expires_after_ns;
    let served = Cell::new(80u64);
    let node_served = |_: &SessionKey| shared_established(served.get());
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    let mut kept = 0usize;
    let mut now = t0;
    while now < t0 + window + 2 * SEC {
        now += SEC;
        served.set(served.get() + 10);
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        kept += table.last_pop_stats().kept_alive_by_companion;
    }
    assert_eq!(
        kept, 0,
        "#18722: no keep-alive arm may keep an idle UDP replica on node evidence"
    );
    assert!(
        table.entry_by_key(&forward).is_none() && table.entry_by_key(&reverse).is_none(),
        "#18722: a UDP pair reaps on its own window whatever the node evidence says"
    );
}

/// PAIR-MODEL EXCEPTION 3: a completed local row rejects shared evidence
/// without its matching canonical session identity. Even if shared packet
/// counts are live and advancing, unknown identity cannot protect this
/// session. Its retention remains `companion_keeps_alive`'s alone, so with
/// no packets on either of its own halves it reaps one window after its last
/// packet.
#[test]
fn pair_exception_completed_local_row_rejects_unrelated_shared_identity_18722() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let forward = key_v4();
    let reverse = install_forward_reverse_pair(&mut table, &forward, t0, TCP_SYN);
    assert!(
        table
            .lookup_with_origin(&reverse, t0 + MS, TCP_SYN | TCP_ACK)
            .is_some()
    );
    table.account_packet(&reverse, 60, TCP_SYN | TCP_ACK, 0);
    let last = t0 + 2 * MS;
    assert!(table.lookup_with_origin(&forward, last, TCP_ACK).is_some());
    table.account_packet(&forward, 52, TCP_ACK, 0);
    let window = table
        .entry_by_key(&forward)
        .expect("forward")
        .expires_after_ns;
    let served = Cell::new(80u64);
    let other_session_id = table.session_id_for(&forward).wrapping_add(1);
    let node_served = |_: &SessionKey| {
        let mut evidence = shared_established(served.get());
        evidence.shared_incarnation = Some((other_session_id, 0));
        evidence
    };
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    served.set(served.get() + 1_000);
    let _ = table.expire_stale_entries_ha(last + window - SEC, Some(&ha));
    assert!(
        table.entry_by_key(&forward).is_some(),
        "anti-vacuity: alive inside its window"
    );
    served.set(served.get() + 1_000);
    let _ = table.expire_stale_entries_ha(last + window + 2 * SEC, Some(&ha));
    assert_eq!(
        table.last_pop_stats().kept_alive_by_companion,
        0,
        "#18722: unidentified advancing evidence must not keep a completed local row"
    );
    assert!(
        table.entry_by_key(&forward).is_none() && table.entry_by_key(&reverse).is_none(),
        "#18722: a completed local pair reaps one window after its own last packet"
    );
}

/// PAIR-MODEL EXCEPTION 4: the #16223 B1 split replica. A lone reverse
/// half (no forward row in this table, no shared row) whose only local
/// evidence is a node-served stamp is decided alone, on that stamp: kept
/// at the window-1 check (the stamp reads as a change from 0), reaped at
/// the window-2 check (unchanged).
#[test]
fn pair_exception_stamp_only_split_replica_is_decided_alone_18722() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let forward = key_v4();
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());
    import_row(
        &mut table,
        &reverse,
        true,
        SessionOrigin::SyncImport,
        TcpHandshakeState::Opening.to_wire(),
        0,
        t0,
        false,
    );
    table.note_node_served_handshake(&forward, TcpHandshakeState::Established.to_wire(), 7);
    let ev = table.node_served_evidence(&reverse);
    assert!(
        table.entry_by_key(&forward).is_none(),
        "premise: no forward row here"
    );
    assert_eq!(
        ev.local_served,
        Some(7),
        "premise: the stamp is the local contributor"
    );
    let node_served = |_: &SessionKey| NodeServedEvidence::default();
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    let window = table
        .entry_by_key(&reverse)
        .expect("reverse")
        .expires_after_ns;
    let mut events = Vec::new();
    let mut now = t0;
    while now < t0 + 10 * window {
        now += SEC;
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        if table.last_pop_stats().kept_alive_by_companion > 0 {
            events.push(("kept", now));
        }
        if table.entry_by_key(&reverse).is_none() {
            events.push(("reaped", now));
            break;
        }
    }
    assert_keep_then_reap(&events, t0, window, "stamp-only split replica");
}

/// #18742 (seat L, NIT): the two per-contributor baselines
/// (`node_served_seen_local` / `_shared`) grow `SessionEntry` by 16 B.
/// Pin the size so the next growth is a decision, not an accident. Re-pin
/// with a cited reason when a field is added on purpose. The hot fields the
/// expiry scan reads are printed with their cache lines for the PR record
/// (they are compared against master there, not pinned here, because a
/// `repr(Rust)` layout reorders on any field change).
#[test]
fn session_entry_size_is_pinned_18722() {
    use std::mem::{offset_of, size_of};
    let hot = [
        ("last_seen_ns", offset_of!(SessionEntry, last_seen_ns)),
        (
            "expires_after_ns",
            offset_of!(SessionEntry, expires_after_ns),
        ),
        ("wheel_tick", offset_of!(SessionEntry, wheel_tick)),
        ("held_wheel_tick", offset_of!(SessionEntry, held_wheel_tick)),
        ("origin", offset_of!(SessionEntry, origin)),
        ("metadata", offset_of!(SessionEntry, metadata)),
        ("decision", offset_of!(SessionEntry, decision)),
        ("first_held_ns", offset_of!(SessionEntry, first_held_ns)),
        ("seen_rg_epoch", offset_of!(SessionEntry, seen_rg_epoch)),
        ("closing", offset_of!(SessionEntry, closing)),
        ("reset", offset_of!(SessionEntry, reset)),
        ("fin_own", offset_of!(SessionEntry, fin_own)),
        ("fin_peer", offset_of!(SessionEntry, fin_peer)),
        ("established", offset_of!(SessionEntry, established)),
        (
            "handshake_pending",
            offset_of!(SessionEntry, handshake_pending),
        ),
        ("syn_ack_first", offset_of!(SessionEntry, syn_ack_first)),
        ("counters", offset_of!(SessionEntry, counters)),
        (
            "closing_counters_seen",
            offset_of!(SessionEntry, closing_counters_seen),
        ),
        (
            "node_served_seen_local",
            offset_of!(SessionEntry, node_served_seen_local),
        ),
        (
            "node_served_seen_shared",
            offset_of!(SessionEntry, node_served_seen_shared),
        ),
    ];
    let lines: Vec<_> = hot
        .iter()
        .map(|(n, o)| format!("{n}@{o}/L{}", o / 64))
        .collect();
    eprintln!(
        "SESSION_ENTRY_LAYOUT size={} align={} {}",
        size_of::<SessionEntry>(),
        std::mem::align_of::<SessionEntry>(),
        lines.join(" ")
    );
    assert_eq!(
        size_of::<SessionEntry>(),
        SESSION_ENTRY_SIZE_18722,
        "SessionEntry changed size: re-pin with a cited reason (640 B at #18722/#18742)"
    );
}

/// Master `SessionEntry` (600 B at 218c320230) plus the two #18722 count
/// baselines and #18742 shared-incarnation identity / last-change clock.
const SESSION_ENTRY_SIZE_18722: usize = 640;
/// #18742 small-window cell helper: force a pure-Opening replica pair onto a
/// `window` idle window. `session_timeout_ns` never applies an app override to
/// an Opening row, so stamp the window directly on both halves and re-bucket;
/// `push_to_wheel` re-derives the wheel target from `last_seen + expires_after`.
fn opening_replica_with_window(
    window: u64,
) -> (SessionTable, SessionKey, SessionKey) {
    let t0 = 1_000 * SEC;
    let (mut table, forward, reverse, _) = opening_replica(t0);
    for key in [&forward, &reverse] {
        table
            .entry_by_key_mut(key)
            .expect("half")
            .expires_after_ns = window;
        table.push_to_wheel(key, t0);
    }
    (table, forward, reverse)
}

/// #18742 (Sol+Kimi MAJOR, convergent): the configured window can be smaller
/// than the shared restamp cadence. The per-app idle schema allows 1 s
/// (`app_inactivity_timeout_ns`, seconds > 0) and a per-zone syn-flood override
/// can push an Opening replica to 5 s, while the serving worker's ct-slice
/// restamps the shared counts only once per 10-13 s cycle
/// (`CT_REFRESH_WINDOW_NS`, const-asserted inside the 20 s OPENING window but
/// not inside a 1-5 s configured window). The pre-fold arm required a count
/// CHANGE at every crossed check: with a 5 s window the crossed checks fall at
/// +6 s and +12 s with no restamp between them, so a LIVE flow's replica reaps
/// at the second check solely because the evidence cadence exceeds its window.
///
/// Contract pinned here: with continuous serving (counts advancing at the
/// production cadence) the replica SURVIVES; once serving stops it still reaps
/// (proven by the frozen-counts guard below). RED pre-fix: the +12 s check sees
/// an unchanged total and reaps the live replica.
#[test]
fn small_window_replica_survives_on_production_cadence_restamps_18722() {
    let t0 = 1_000 * SEC;
    let window = 5 * SEC;
    let (mut table, forward, reverse) = opening_replica_with_window(window);
    let served = Cell::new(10u64);
    let node_served = |_: &SessionKey| shared_established(served.get());
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    let mut kept = 0usize;
    let mut now = t0;
    // Continuous serving: +25 packets at the 10 s production cadence.
    while now < t0 + 45 * SEC {
        now += SEC;
        if (now - t0) % (10 * SEC) == 0 {
            served.set(served.get() + 25);
        }
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        kept += table.last_pop_stats().kept_alive_by_companion;
        assert!(
            table.entry_by_key(&forward).is_some() && table.entry_by_key(&reverse).is_some(),
            "#18742: a live flow's {window:?}ns-window replica was reaped at +{} s solely \
             because the 10-13 s restamp cadence exceeds its window",
            (now - t0) / SEC
        );
    }
    assert!(
        kept >= 2,
        "anti-vacuity: retention must have come from the node-level arm (kept {kept} times)"
    );
    // Idle twin: serving stopped at t0 (counts frozen). It must still reap:
    // the initial count is observed at the first crossed check, then the
    // bounded cadence grace expires. The guard below allows that grace plus
    // the next configured-window crossing.
    let (mut idle, idle_f, idle_r) = opening_replica_with_window(window);
    let frozen = shared_established(10);
    let idle_served = move |_: &SessionKey| frozen;
    let idle_ha = ha_with(&idle_served, &forwards, &epoch);
    let mut gone_at = None;
    let mut now = t0;
    while now < t0 + 30 * SEC {
        now += SEC;
        let _ = idle.expire_stale_entries_ha(now, Some(&idle_ha));
        if idle.entry_by_key(&idle_f).is_none() && idle.entry_by_key(&idle_r).is_none() {
            gone_at = Some((now - t0) / SEC);
            break;
        }
    }
    let idle_bound_secs =
        NODE_SERVED_EVIDENCE_DEFAULT_CADENCE_NS / SEC + 2 * (window / SEC) + 2;
    assert!(
        gone_at.is_some_and(|s| s <= idle_bound_secs),
        "#18742: an idle {window:?}ns-window replica must reap within the cadence + window bound ({idle_bound_secs} s), gone_at={gone_at:?}"
    );
}

/// #18742 follow-up: HA imports can exceed the default 2x session cap, so
/// production evidence cadence is computed from the live slab. Model a 30 s
/// over-cap cycle, hold a live 5 s replica through the intermediate crossed
/// checks, then publish the next count restamp before the cycle expires.
#[test]
fn overcap_ct_cycle_keeps_short_window_replica_until_restamp_18722() {
    let t0 = 1_000 * SEC;
    let window = 5 * SEC;
    let cadence = 30 * SEC;
    let (mut table, forward, reverse) = opening_replica_with_window(window);
    let served = Cell::new(300u64);
    let node_served = |_: &SessionKey| NodeServedEvidence {
        handshake_wire: TcpHandshakeState::Established.to_wire(),
        shared_established: true,
        shared_incarnation: Some((0xA_8730, 0)),
        shared_evidence_max_cadence_ns: Some(cadence),
        shared_served: Some(served.get()),
        ..NodeServedEvidence::default()
    };
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    let mut now = t0;
    while now < t0 + window + SEC {
        now += SEC;
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
    }
    assert!(
        table.entry_by_key(&forward).is_some(),
        "premise: the initial source count was observed"
    );

    while now < t0 + 65 * SEC {
        now += SEC;
        if (now - t0) % cadence == 0 {
            served.set(served.get() + 25);
        }
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        assert!(
            table.entry_by_key(&forward).is_some() && table.entry_by_key(&reverse).is_some(),
            "#18742: the live replica was reaped at +{} s before its {cadence:?} restamp",
            (now - t0) / SEC
        );
    }
}

/// #18742 ABA cell helper: import a replica pair under an explicit
/// `session_id` so the test can distinguish the source incarnation from the
/// replica's own stable identity.
fn import_replica_pair_with_id(
    table: &mut SessionTable,
    session_id: u64,
    wire: u8,
    now_ns: u64,
) -> (SessionKey, SessionKey) {
    let forward = key_v4();
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());
    for (key, is_reverse) in [(&forward, false), (&reverse, true)] {
        let mut metadata = super::tests::metadata();
        metadata.is_reverse = is_reverse;
        assert!(
            table.upsert_synced_with_origin(
                SessionInstall {
                    key: key.clone(),
                    decision: super::tests::decision(),
                    metadata,
                    source_nat_static: None,
                    origin: SessionOrigin::SyncImport,
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

/// #18742 (Kimi ABA): an equal-count source replacement is invisible to a
/// values-only comparison. The shared evidence source serves 300 packets, is
/// REMOVED, then a NEW incarnation republishes exactly 300. The first crossed
/// check after replacement must recognize the new identity as activity even
/// though the count is unchanged; the next production-cadence count increase
/// then proves the replacement continues to serve.
///
/// RED pre-fix: the cadence grace alone keeps the row at the first crossed
/// check, but `node_served_last_change_ns` remains at the old source's check
/// time because the equal-count replacement was not recognized.
#[test]
fn equal_count_source_replacement_is_activity_18722() {
    let t0 = 1_000 * SEC;
    let window = 5 * SEC;
    let mut table = SessionTable::new();
    let (forward, reverse) = import_replica_pair_with_id(
        &mut table,
        0xA_8722,
        TcpHandshakeState::Established.to_wire(),
        t0,
    );
    for key in [&forward, &reverse] {
        table.entry_by_key_mut(key).expect("half").expires_after_ns = window;
        table.push_to_wheel(key, t0);
    }
    let shared = Cell::new(Some((100u64, 300u64)));
    let node_served = |_: &SessionKey| match shared.get() {
        Some((session_id, served)) => NodeServedEvidence {
            handshake_wire: TcpHandshakeState::Established.to_wire(),
            shared_established: true,
            shared_incarnation: Some((session_id, 0)),
            shared_served: Some(served),
            ..NodeServedEvidence::default()
        },
        None => NodeServedEvidence::default(),
    };
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    let mut now = t0;
    while now < t0 + window + SEC {
        now += SEC;
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
    }
    let old_change_at = table
        .entry_by_key(&forward)
        .expect("forward survived source's first check")
        .node_served_last_change_ns;
    assert_eq!(old_change_at, now, "premise: the original 300 count was observed");

    // The source disappears briefly, then a new source republishes the same
    // count under a distinct stable session identity.
    shared.set(None);
    now += SEC;
    let _ = table.expire_stale_entries_ha(now, Some(&ha));
    shared.set(Some((101, 300)));
    let replacement_at = now + window;
    while now < replacement_at {
        now += SEC;
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
    }
    assert!(
        table.entry_by_key(&forward).is_some() && table.entry_by_key(&reverse).is_some(),
        "the cadence grace must retain the pair at the replacement's first crossed check"
    );
    assert_eq!(
        table
            .entry_by_key(&forward)
            .expect("forward")
            .node_served_last_change_ns,
        now,
        "#18742 ABA: same count (300) with a new incarnation must refresh the activity \
         timestamp at the replacement's first crossed check; old timestamp was {}",
        old_change_at
    );

    // Count changes resume on the production 10 s restamp cadence. The live
    // replacement must continue to survive later crossings.
    while now < t0 + 45 * SEC {
        now += SEC;
        if (now - t0) % (10 * SEC) == 0 && now >= t0 + 20 * SEC {
            shared.set(shared.get().map(|(session_id, served)| (session_id, served + 25)));
        }
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        assert!(
            table.entry_by_key(&forward).is_some() && table.entry_by_key(&reverse).is_some(),
            "#18742 ABA: the live replacement was reaped at +{} s",
            (now - t0) / SEC
        );
    }
}

/// #18742 Sol: the pair decision is aligned when a KEEP occurs, but
/// per-zone OPENING windows remain independent. With 5 s / 9 s windows,
/// the shorter half can expire on an earlier wheel pass than its companion.
/// This cell protects the README scope: the "both halves reap in one pass"
/// statement applies only when their idle windows match (the normal completed
/// application-timeout case), not when zones deliberately configure different
/// half-open windows.
#[test]
fn mixed_zone_windows_may_reap_pair_halves_in_different_passes_18722() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let (forward, reverse) = import_replica_pair(
        &mut table,
        SessionOrigin::SyncImport,
        TcpHandshakeState::Opening.to_wire(),
        t0,
    );
    let forward_window = 5 * SEC;
    let reverse_window = 9 * SEC;
    for (key, window) in [(&forward, forward_window), (&reverse, reverse_window)] {
        table.entry_by_key_mut(key).expect("half").expires_after_ns = window;
        table.push_to_wheel(key, t0);
    }
    let frozen = shared_established(80);
    let node_served = move |_: &SessionKey| frozen;
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_with(&node_served, &forwards, &epoch);
    let mut forward_reaped_at = None;
    let mut reverse_reaped_at = None;
    let mut now = t0;
    while now < t0 + 60 * SEC && (forward_reaped_at.is_none() || reverse_reaped_at.is_none()) {
        now += SEC;
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        if table.entry_by_key(&forward).is_none() && forward_reaped_at.is_none() {
            forward_reaped_at = Some(now);
        }
        if table.entry_by_key(&reverse).is_none() && reverse_reaped_at.is_none() {
            reverse_reaped_at = Some(now);
        }
    }
    let forward_reaped_at = forward_reaped_at.expect("forward half reaped");
    let reverse_reaped_at = reverse_reaped_at.expect("reverse half reaped");
    assert!(
        forward_reaped_at < reverse_reaped_at,
        "#18742: different configured idle windows mean halves may reap on different passes; \
         forward={:?} s, reverse={:?} s after install",
        (forward_reaped_at - t0) / SEC,
        (reverse_reaped_at - t0) / SEC
    );
}
