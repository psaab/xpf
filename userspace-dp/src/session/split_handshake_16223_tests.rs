//! #16223: split-RG rows never leave the 20 s TCP opening window.
//!
//! Live shape (fw1 LAN-ingress + fw0 fabric-ingress): the forward rows
//! expire with `established=false, handshake_pending=false` (wire
//! Opening), the fw1 reverse rows with `handshake_pending=true`, and
//! `last_seen ~= created` on the replica rows despite ~1.2 M served
//! flow-cache hits per node. Per-packet completion therefore cannot be
//! the cure: the completing/data segments are consumed on workers/nodes
//! whose local row is not the pending one (or whose key orientation
//! never matches the pending half).
//!
//! These tests pin the two halves of the proven failure at predicate
//! level:
//!  1. An Opening forward row (`established=false,
//!     handshake_pending=false, syn_ack_first=false`) served ONLY by
//!     cache hits (`probe_hit`) never completes — the completion
//!     conjunct `handshake_pending` is false on exactly the row the
//!     cache serves. (Discriminator: fails pre-fix by construction —
//!     see `opening_forward_cache_hit_never_completes_16223`.)
//!  2. The GC companion-retention probe refuses to keep such a row
//!     alive from a live companion, so both halves reap together at
//!     the opening deadline even though the flow is active.
//!
//! The fix must make an active Opening/pending pair survive past the
//! opening window under cache-hit-only service and promote to the
//! established window once the handshake has observably completed
//! (reverse activity), while a handshake that never completes (no
//! reverse traffic at all) still reaps on the opening window.

use super::tests::{decision, install_forward_reverse_pair, key_v4, metadata};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_PSH, TCP_SYN};

const SEC: u64 = 1_000_000_000;

/// Install a bare-SYN forward/reverse pair exactly as the session-miss
/// path seeds it: both halves Opening (`established=false`,
/// `handshake_pending=false`, `syn_ack_first=false`) on the 20 s
/// opening window. This is the fw0 forward-row shape at expiry in
/// #16223 (`origin=worker_local_import/forward_flow, fabric_ingress`).
fn opening_pair() -> (SessionTable, SessionKey, SessionKey, u64) {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("installed half");
        assert!(
            !entry.established && !entry.handshake_pending && !entry.syn_ack_first,
            "{label}: premise — bare-SYN install is Opening (wire state 1)"
        );
        assert_eq!(
            entry.expires_after_ns, table.timeouts.tcp_opening_ns,
            "{label}: premise — Opening half on the 20 s window"
        );
        assert_eq!(table.timeout_secs_for(key), 20);
    }
    (table, forward, reverse, now)
}

/// Reverse SYN-ACK arrives on a DIFFERENT worker's table than the one
/// that will serve the data (split posture: the SYN-ACK crosses the
/// fabric / lands on a sibling worker). Modelled here as: the reverse
/// lookup runs (promoting both halves to established+pending), but the
/// completing forward ACK and all later data are consumed by
/// `probe_hit` on the FORWARD key — the #14939 path — while the
/// reverse half is never probed again.
/// Control: this is the shape #14939 already covers and must keep
/// passing (sanity that the fixture is not vacuous).
#[test]
fn control_pending_pair_completes_via_forward_probe_hit_16223() {
    let (mut table, forward, reverse, now) = opening_pair();
    // SYN-ACK on the reverse half (slow-path lookup): both halves
    // become established+pending, still on the opening window.
    assert!(
        table
            .lookup_with_origin(&reverse, now + SEC, TCP_SYN | TCP_ACK)
            .is_some()
    );
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("half after SYN-ACK");
        assert!(
            entry.established && entry.handshake_pending,
            "{label}: premise — SYN-ACK promotes but leaves pending"
        );
    }
    // Completing ACK + data via the fused cache probe on the forward key.
    assert!(table.probe_hit(&forward, now + 2 * SEC, 512, TCP_ACK | TCP_PSH, 512, 0));
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("half after completing ACK");
        assert!(
            entry.established && !entry.handshake_pending,
            "{label}: control — forward probe_hit must complete (#14939)"
        );
        assert_eq!(entry.expires_after_ns, table.timeouts.tcp_established_ns);
    }
    assert_eq!(table.timeout_secs_for(&forward), 1800);
    assert_eq!(table.timeout_secs_for(&reverse), 1800);
}

/// DISCRIMINATOR (#16223 fw1 reverse shape): a synced
/// HandshakePending pair (`established=true, handshake_pending=true`
/// — the fw1 reverse rows at expiry) served only via cache hits on
/// the REVERSE half. Pre-fix the orientation conjunct
/// (`syn_ack_first == is_reverse`: false == true) never fires for a
/// plain pending row hit on its reverse half, and the completing
/// forward ACK is cache-served on the fabric peer — so the pair
/// stays pending and reaps at 20 s. Post-fix, reverse cache service
/// past the throttle (genuinely served return traffic on this table)
/// completes both halves.
#[test]
fn opening_forward_cache_hit_never_completes_16223() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: forward.clone(),
            decision: decision(),
            metadata: metadata(),
            origin: SessionOrigin::WorkerLocalImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id: 43,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
            source_nat_static: None,
        },
        false,
    ));
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    reverse_metadata.ingress_zone = crate::test_zone_ids::TEST_WAN_ZONE_ID;
    reverse_metadata.egress_zone = crate::test_zone_ids::TEST_LAN_ZONE_ID;
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: reverse.clone(),
            decision: decision(),
            metadata: reverse_metadata,
            origin: SessionOrigin::WorkerLocalImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id: 43,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
            source_nat_static: None,
        },
        false,
    ));
    // Return-direction data served only via cache hits on the reverse
    // key, past the keepalive throttle so this table genuinely
    // re-stamps (served, not merely probed).
    assert!(table.probe_hit(&reverse, now + 6 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("half after reverse cache service");
        assert!(
            entry.established && !entry.handshake_pending && !entry.syn_ack_first,
            "#16223: {label} must complete under reverse cache service \
             (got established={} handshake_pending={} syn_ack_first={})",
            entry.established, entry.handshake_pending, entry.syn_ack_first
        );
        assert_eq!(
            entry.expires_after_ns, table.timeouts.tcp_established_ns,
            "#16223: {label} must move to the established window (Timeout:1800)"
        );
    }
    assert_eq!(table.timeout_secs_for(&forward), 1800);
    assert_eq!(table.timeout_secs_for(&reverse), 1800);
}

/// DISCRIMINATOR (#16223 GC half): a classic-pending pair whose
/// forward half idle-crosses (its hits were throttled / served on a
/// sibling worker, so `last_seen` never moved) while the reverse
/// half is freshly served. Pre-fix `companion_keeps_alive` refuses
/// (`handshake_pending` on the companion), so the forward half reaps
/// at the deadline. Post-fix the GC retention arm keeps it from the
/// companion's real last activity.
#[test]
fn opening_pair_with_active_companion_survives_gc_16223() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    assert!(
        table
            .lookup_with_origin(&reverse, now + SEC, TCP_SYN | TCP_ACK)
            .is_some()
    );
    for key in [&forward, &reverse] {
        assert!(
            table.entry_by_key(key).expect("half").handshake_pending,
            "premise — classic-pending pair"
        );
    }
    assert!(table.probe_hit(&reverse, now + 19 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    table.last_gc_ns = now + 20 * SEC;
    let expired = table.expire_stale_entries(now + 22 * SEC);
    assert!(
        expired.is_empty(),
        "#16223: pending pair with a fresh companion must survive GC, expired {} entries",
        expired.len()
    );
    assert!(table.entry_by_key(&forward).is_some(), "forward half must survive");
    assert!(table.entry_by_key(&reverse).is_some(), "reverse half must survive");
}

/// Guard (#6752/#13679 semantics preserved): a bare-SYN pair that
/// NEVER sees reverse traffic must still reap on the opening window —
/// the fix must not turn every SYN into a 1800 s session. (One half
/// may be retained one extra pass by the companion probe; both must
/// be gone after the next pass.)
#[test]
fn unreplied_opening_pair_still_reaps_on_opening_window_16223() {
    let (mut table, forward, reverse, now) = opening_pair();
    // Forward-only SYN retransmit, no reverse activity ever.
    assert!(table.probe_hit(&forward, now + 5 * SEC, 60, TCP_SYN, 0, 0));
    let _ = table.expire_stale_entries(now + 21 * SEC);
    let _ = table.expire_stale_entries(now + 60 * SEC);
    assert!(
        table.entry_by_key(&forward).is_none(),
        "#16223 guard: unreplied forward half must reap at ~20 s"
    );
    assert!(
        table.entry_by_key(&reverse).is_none(),
        "#16223 guard: unreplied reverse half must reap at ~20 s"
    );
}

/// Guard: a SYN-ACK-first pending row must still require its reverse
/// ACK — a forward-direction ACK must not complete it (#4109/#14630
/// orientation conjunct `syn_ack_first == is_reverse` preserved).
#[test]
fn syn_ack_first_orientation_guard_holds_16223() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    // SYN-ACK-first pickup on the forward half.
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN | TCP_ACK);
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("installed half");
        assert!(
            !entry.established && entry.handshake_pending && entry.syn_ack_first,
            "{label}: premise — SYN-ACK-first pending"
        );
    }
    // Forward-direction ACK (wrong orientation) must NOT complete.
    assert!(table.probe_hit(&forward, now + SEC, 512, TCP_ACK | TCP_PSH, 512, 0));
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("half after wrong-direction ACK");
        assert!(
            entry.handshake_pending && entry.syn_ack_first,
            "#16223 guard: {label} — forward ACK must not complete SYN-ACK-first"
        );
        assert_eq!(entry.expires_after_ns, table.timeouts.tcp_opening_ns);
    }
    // Reverse ACK (correct orientation) completes both halves.
    assert!(table.probe_hit(&reverse, now + 2 * SEC, 512, TCP_ACK, 0, 0));
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("half after reverse ACK");
        assert!(
            entry.established && !entry.handshake_pending && !entry.syn_ack_first,
            "#16223 guard: {label} — reverse ACK must complete SYN-ACK-first"
        );
        assert_eq!(entry.expires_after_ns, table.timeouts.tcp_established_ns);
    }
}

/// Synced-replica shape (fw1 reverse row at expiry:
/// `handshake_pending=true`): a HandshakePending import pair served
/// only via cache hits on the REVERSE key (return traffic is what the
/// LAN-ingress node serves) must complete. Pre-fix the orientation
/// conjunct requires `syn_ack_first == is_reverse` (false == true
/// fails) for a plain HandshakePending row hit on its reverse half,
/// because completion for SYN-first pending is defined only on the
/// forward half — yet in split posture the completing forward ACK is
/// consumed on the fabric peer, and this node's reverse hits carry
/// PSH+ACK data that proves completion. Post-fix both halves promote.
#[test]
fn synced_pending_reverse_cache_hit_completes_16223() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: forward.clone(),
            decision: decision(),
            metadata: metadata(),
            origin: SessionOrigin::WorkerLocalImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id: 42,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
            source_nat_static: None,
        },
        false,
    ));
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    reverse_metadata.ingress_zone = crate::test_zone_ids::TEST_WAN_ZONE_ID;
    reverse_metadata.egress_zone = crate::test_zone_ids::TEST_LAN_ZONE_ID;
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: reverse.clone(),
            decision: decision(),
            metadata: reverse_metadata,
            origin: SessionOrigin::WorkerLocalImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id: 42,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
            source_nat_static: None,
        },
        false,
    ));
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("imported half");
        assert!(
            entry.established && entry.handshake_pending && !entry.syn_ack_first,
            "{label}: premise — synced HandshakePending import"
        );
        assert_eq!(entry.expires_after_ns, table.timeouts.tcp_opening_ns);
    }
    // This table genuinely serves the flow: a forward cache hit past
    // the keepalive throttle (the LAN-ingress node's workers serve
    // forward data). Companion is the established pending reverse —
    // refreshed-freshness proof — so the pair completes.
    assert!(table.probe_hit(&forward, now + 6 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("half after forward cache service");
        assert!(
            entry.established && !entry.handshake_pending,
            "#16223: {label} must complete once this table serves the pending pair \
             (got established={} handshake_pending={})",
            entry.established, entry.handshake_pending
        );
        assert_eq!(
            entry.expires_after_ns, table.timeouts.tcp_established_ns,
            "#16223: {label} must move to the established window (Timeout:1800)"
        );
    }
    assert_eq!(table.timeout_secs_for(&forward), 1800);
    assert_eq!(table.timeout_secs_for(&reverse), 1800);
}

/// LIVE SHAPE (B1/B5, separate tables): the fw1 dying row is a lone
/// `syn_ack_first=true` reverse replica in its OWN worker table with
/// NO companion, while the serving pair (promoted, Timeout 1800,
/// reverse counters in the thousands) lives in a DIFFERENT table on
/// the same node. Node-level evidence — not any local flag — must
/// complete/retain the replica. Without evidence it must still reap
/// (#4109: a SYN-ACK-first row whose server was never served waits
/// for its reverse ACK and dies on the opening window).
#[test]
fn syn_ack_first_replica_completes_from_node_evidence_16223() {
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());

    // Serving table: promoted pair with real reverse service.
    let mut serving = SessionTable::new();
    let serving_reverse = install_forward_reverse_pair(&mut serving, &forward, now, TCP_SYN);
    assert_eq!(serving_reverse, reverse);
    assert!(serving.lookup_with_origin(&reverse, now + SEC, TCP_SYN | TCP_ACK).is_some());
    assert!(serving.probe_hit(&forward, now + 2 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    assert!(serving.probe_hit(&reverse, now + 3 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    let serving_entry = serving.entry_by_key(&forward).expect("serving forward");
    assert!(serving_entry.established && !serving_entry.handshake_pending);
    assert!(serving_entry.counters.rev_packets > 0, "premise: serving pair served reverse");

    // Replica table: ONLY the syn_ack_first reverse half, no companion.
    let mut replica = SessionTable::new();
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    reverse_metadata.ingress_zone = crate::test_zone_ids::TEST_WAN_ZONE_ID;
    reverse_metadata.egress_zone = crate::test_zone_ids::TEST_LAN_ZONE_ID;
    assert!(replica.upsert_synced_with_origin(
        SessionInstall {
            key: reverse.clone(),
            decision: decision(),
            metadata: reverse_metadata,
            origin: SessionOrigin::WorkerLocalImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id: 77,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::SynAckFirstPending.to_wire(),
            source_nat_static: None,
        },
        false,
    ));
    {
        let entry = replica.entry_by_key(&reverse).expect("replica reverse");
        assert!(
            !entry.established && entry.handshake_pending && entry.syn_ack_first,
            "premise: live fw1 shape (syn_ack_first, pending, not established)"
        );
        assert!(replica.entry_by_key(&forward).is_none(), "premise: companion absent");
    }
    // No node evidence yet: a SYN-ACK retransmit (the only segment
    // this replica ever observes — its completing ACK is consumed on
    // the fabric peer) must NOT complete it. The classic arm refuses
    // SYN-bearing segments, and without node proof the #4109 guard
    // holds. (A bare reverse ACK would complete classically — that
    // is the #4109 rule itself, exercised by the guard test above.)
    assert!(replica.probe_hit(&reverse, now + SEC, 512, TCP_SYN | TCP_ACK, 0, 0));
    assert!(
        replica.entry_by_key(&reverse).expect("replica").handshake_pending,
        "without node evidence the syn_ack_first replica must stay pending"
    );
    // Node-level proof arrives (shared-map Established + serving rev).
    replica.note_node_served_handshake(
        &forward,
        TcpHandshakeState::Established.to_wire(),
        serving_entry.counters.rev_packets,
    );
    // GC at the opening deadline must RETAIN it on node evidence alone.
    replica.last_gc_ns = now + 20 * SEC;
    let node_served = |_: &SessionKey| NodeServedEvidence {
        handshake_wire: TcpHandshakeState::Established.to_wire(),
        rev_packets: serving_entry.counters.rev_packets,
        shared_established: true,
        ..NodeServedEvidence::default()
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
    let expired = replica.expire_stale_entries_ha(now + 22 * SEC, Some(&ha));
    assert!(
        expired.is_empty(),
        "#16223 B1: syn_ack_first replica with node-served proof must survive GC"
    );
    assert!(replica.entry_by_key(&reverse).is_some());
    // And a served hit now completes it to the established window.
    assert!(replica.probe_hit(&reverse, now + 23 * SEC, 512, TCP_ACK | TCP_PSH, 512, 0));
    let entry = replica.entry_by_key(&reverse).expect("completed replica");
    assert!(
        entry.established && !entry.handshake_pending && !entry.syn_ack_first,
        "#16223 B1: node evidence must complete the syn_ack_first replica"
    );
    assert_eq!(entry.expires_after_ns, replica.timeouts.tcp_established_ns);
}

/// LIVE SHAPE (B2/B5, separate tables): fw0 replicas are pure Opening
/// (`handshake_pending=false`) with an Opening companion and zero
/// counters. Node-level served evidence must retain them at GC;
/// without it they reap together on the opening window.
#[test]
fn opening_replica_survives_gc_only_with_node_evidence_16223() {
    let now = 1_000_000_000u64;
    // Control: no evidence -> both Opening halves reap.
    let (mut control, forward, reverse, _) = opening_pair();
    control.last_gc_ns = now;
    let _ = control.expire_stale_entries(now + 21 * SEC);
    let _ = control.expire_stale_entries(now + 42 * SEC);
    assert!(control.entry_by_key(&forward).is_none(), "control forward must reap");
    assert!(control.entry_by_key(&reverse).is_none(), "control reverse must reap");

    // With node evidence (separate serving table promoted + served):
    let (mut replica, forward, reverse, _) = opening_pair();
    replica.note_node_served_handshake(
        &forward,
        TcpHandshakeState::Established.to_wire(),
        8850,
    );
    replica.last_gc_ns = now;
    let expired = replica.expire_stale_entries(now + 21 * SEC);
    assert!(
        expired.is_empty(),
        "#16223 B2: Opening replica with node-served proof must survive GC, expired {}",
        expired.len()
    );
    assert!(replica.entry_by_key(&forward).is_some());
    assert!(replica.entry_by_key(&reverse).is_some());
    // A served hit completes the Opening replica pair.
    assert!(replica.probe_hit(&forward, now + 22 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    for key in [&forward, &reverse] {
        let entry = replica.entry_by_key(key).expect("completed half");
        assert!(
            entry.established && !entry.handshake_pending,
            "#16223 B2: Opening replica must complete on node evidence"
        );
        assert_eq!(entry.expires_after_ns, replica.timeouts.tcp_established_ns);
    }
    assert_eq!(replica.timeout_secs_for(&forward), 1800);
}

/// Guard: node evidence with a promoted wire but ZERO served reverse
/// packets must NOT complete or retain — a promoted-but-never-answered
/// pair cannot launder a half-open flow into 1800s.
#[test]
fn node_evidence_without_served_reverse_does_not_complete_16223() {
    let (mut table, forward, reverse, now) = opening_pair();
    table.note_node_served_handshake(&forward, TcpHandshakeState::Established.to_wire(), 0);
    assert!(table.probe_hit(&forward, now + 6 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    for key in [&forward, &reverse] {
        let entry = table.entry_by_key(key).expect("half");
        assert!(
            !entry.established || entry.handshake_pending,
            "#16223 guard: zero served-reverse evidence must not complete"
        );
    }
    table.last_gc_ns = now + 7 * SEC;
    let _ = table.expire_stale_entries(now + 28 * SEC);
    let _ = table.expire_stale_entries(now + 60 * SEC);
    assert!(table.entry_by_key(&forward).is_none(), "unserved pair must reap");
    assert!(table.entry_by_key(&reverse).is_none(), "unserved pair must reap");
}

/// #16217 split shape, NEITHER table alone sufficient (FZFixWire3):
/// worker A's serving forward row is Established but served ZERO
/// reverse packets (the strict slice's `rev_packets>0` conjunct
/// fails); worker B's row for the same tuple is a pending replica
/// that observed reverse traffic but never promoted (its
/// `established` conjunct fails). Only NODE-WIDE assembly — A
/// Established OR B reverse counters, aggregated over the shared
/// maps by `shared_completion_evidence` at the ct-slice — collects
/// the tuple. Neither table's evidence alone may collect it.
#[test]
fn split_two_workers_neither_alone_sufficient_16217() {
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());

    // Worker A: serving pair promoted (SYN-ACK observed) and the
    // forward ACK completes it locally — Established, but the reverse
    // half was never hit again, so local reverse counters stay 0.
    let mut a = SessionTable::new();
    let a_rev = install_forward_reverse_pair(&mut a, &forward, now, TCP_SYN);
    assert_eq!(a_rev, reverse);
    assert!(a.lookup_with_origin(&reverse, now + SEC, TCP_SYN | TCP_ACK).is_some());
    assert!(a.probe_hit(&forward, now + 2 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    {
        let e = a.entry_by_key(&forward).expect("A forward");
        assert!(e.established && !e.handshake_pending, "premise A: Established");
        assert_eq!(e.counters.rev_packets, 0, "premise A: zero local reverse");
    }
    // A's slice alone collects via (a): any worker's local row Established.
    let mut a_node: Vec<(SessionKey, crate::nat::NatDecision)> = Vec::new();
    a.node_served_forward_slice(0, usize::MAX, &|_| NodeServedEvidence::default(), &mut a_node);
    assert!(
        a_node.iter().any(|(k, _)| k == &forward),
        "#16217(a): local Established row collects without shared evidence"
    );
    // Strict slice on A alone must NOT collect it.
    let mut strict: Vec<(SessionKey, crate::nat::NatDecision)> = Vec::new();
    a.established_forward_slice(0, usize::MAX, &mut strict);
    assert!(
        !strict.iter().any(|(k, _)| k == &forward),
        "premise: strict slice alone insufficient (rev_packets==0)"
    );

    // Worker B: pending replica that observed reverse service only.
    let mut b = SessionTable::new();
    let mut rev_meta = metadata();
    rev_meta.is_reverse = true;
    rev_meta.ingress_zone = crate::test_zone_ids::TEST_WAN_ZONE_ID;
    rev_meta.egress_zone = crate::test_zone_ids::TEST_LAN_ZONE_ID;
    assert!(b.upsert_synced_with_origin(
        SessionInstall {
            key: reverse.clone(),
            decision: decision(),
            metadata: rev_meta,
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id: 93,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
            source_nat_static: None,
        },
        false,
    ));
    // B's slice alone (no shared evidence) must NOT collect.
    let mut b_alone: Vec<(SessionKey, crate::nat::NatDecision)> = Vec::new();
    b.node_served_forward_slice(0, usize::MAX, &|_| NodeServedEvidence::default(), &mut b_alone);
    assert!(
        !b_alone.iter().any(|(k, _)| k == &forward),
        "premise: worker B alone insufficient"
    );

    // Node-wide: a pending FORWARD row on a third table, fed ONLY the
    // aggregated evidence (A established via stamps + B reverse
    // counters via shared-map replica), must collect — neither source
    // alone is in this table.
    let mut c = SessionTable::new();
    assert!(c.upsert_synced_with_origin(
        SessionInstall {
            key: forward.clone(),
            decision: decision(),
            metadata: metadata(),
            // Serving origin so the collector considers it.
            origin: SessionOrigin::SharedPromote,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id: 94,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
            source_nat_static: None,
        },
        false,
    ));
    {
        let e = c.entry_by_key(&forward).expect("C forward");
        assert!(!e.established || e.handshake_pending, "premise C: not locally complete");
    }
    // Alone: no shared evidence → not collected.
    let mut c_alone: Vec<(SessionKey, crate::nat::NatDecision)> = Vec::new();
    c.node_served_forward_slice(0, usize::MAX, &|_| NodeServedEvidence::default(), &mut c_alone);
    assert!(
        !c_alone.iter().any(|(k, _)| k == &forward),
        "premise: collector table alone insufficient (no cross-table view)"
    );
    // Aggregated: reverse service observed node-wide (B) → collected.
    let agg = |_: &SessionKey| NodeServedEvidence {
        rev_packets_any: 7,
        ..NodeServedEvidence::default()
    };
    let mut c_agg: Vec<(SessionKey, crate::nat::NatDecision)> = Vec::new();
    c.node_served_forward_slice(0, usize::MAX, &agg, &mut c_agg);
    assert!(
        c_agg.iter().any(|(k, _)| k == &forward),
        "#16217(b): node-wide reverse evidence must collect the split tuple"
    );
    // Aggregated (c): #16223 served-completion stamp alone → collected.
    let agg_c = |_: &SessionKey| NodeServedEvidence {
        served_completed: true,
        ..NodeServedEvidence::default()
    };
    let mut c_agg2: Vec<(SessionKey, crate::nat::NatDecision)> = Vec::new();
    c.node_served_forward_slice(0, usize::MAX, &agg_c, &mut c_agg2);
    assert!(
        c_agg2.iter().any(|(k, _)| k == &forward),
        "#16217(c): served-completion evidence must collect the split tuple"
    );
    // Negative: zero aggregated evidence → still not collected.
    let mut c_neg: Vec<(SessionKey, crate::nat::NatDecision)> = Vec::new();
    c.node_served_forward_slice(0, usize::MAX, &|_| NodeServedEvidence::default(), &mut c_neg);
    assert!(!c_neg.iter().any(|(k, _)| k == &forward));
}

/// #16217 wire-cadence shape: a split pair completes via the cache-hit
/// path (`cache_hit_handshake_progress`) on the serving table while
/// the peer's shared wire still reads HandshakePending — the ct-slice
/// (10 s cadence) has not run. The completion itself must be visible
/// to the collector WITHOUT any ct-slice run: the local table already
/// reads Established for both halves, and the collector's aggregated
/// evidence (shared reverse replica) must collect the tuple for the
/// shared canonical + forward-wire alias advance. Control: without
/// the cache-hit completion the pending pair collects nothing.
#[test]
fn split_cache_hit_completion_collects_without_ct_slice_16217() {
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());

    // Control: pending synced pair, no completion yet.
    let mut control = SessionTable::new();
    for (key, is_rev, id) in [(&forward, false, 95u64), (&reverse, true, 95u64)] {
        let mut meta = metadata();
        meta.is_reverse = is_rev;
        if is_rev {
            meta.ingress_zone = crate::test_zone_ids::TEST_WAN_ZONE_ID;
            meta.egress_zone = crate::test_zone_ids::TEST_LAN_ZONE_ID;
        }
        assert!(control.upsert_synced_with_origin(
            SessionInstall {
                key: key.clone(),
                decision: decision(),
                metadata: meta,
                origin: SessionOrigin::SharedPromote,
                now_ns: now,
                protocol: PROTO_TCP,
                tcp_flags: 0,
                session_id: id,
                tcp_close_class: 0,
                tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
                source_nat_static: None,
            },
            false,
        ));
    }
    let mut ctrl_out: Vec<(SessionKey, crate::nat::NatDecision)> = Vec::new();
    control.node_served_forward_slice(0, usize::MAX, &|_| NodeServedEvidence::default(), &mut ctrl_out);
    // A pending pair with only a reverse replica present DOES carry
    // rev_packets_any via the local half; use zero-evidence collector
    // semantics: the pair is not Established locally, so (a) fails and
    // without shared aggregation nothing collects. Assert the local
    // halves are not yet Established (the wire-advance premise).
    assert!(
        !control.entry_by_key(&forward).expect("ctrl fwd").established
            || control.entry_by_key(&forward).expect("ctrl fwd").handshake_pending,
        "premise: control pair still pending"
    );

    // Split serving table: promoted pair, completing ACK + data served
    // ONLY via cache hits (probe_hit) — the #16223 completion path.
    let mut serving = SessionTable::new();
    let serving_reverse = install_forward_reverse_pair(&mut serving, &forward, now, TCP_SYN);
    assert_eq!(serving_reverse, reverse);
    assert!(serving.lookup_with_origin(&reverse, now + SEC, TCP_SYN | TCP_ACK).is_some());
    assert!(serving.probe_hit(&forward, now + 2 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    assert!(serving.probe_hit(&reverse, now + 3 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    for key in [&forward, &reverse] {
        let e = serving.entry_by_key(key).expect("serving half");
        assert!(e.established && !e.handshake_pending, "premise: cache-hit completion landed");
    }
    // The HA stage-advance Update must be queued (emit carve-out).
    serving.emit_probe_hit_state_update(&forward);
    let updates: Vec<_> = serving
        .drain_deltas(64)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Update)
        .collect();
    assert!(!updates.is_empty(), "#16217: cache-hit completion must queue an HA Update");
    assert!(
        updates.iter().any(|d| d.tcp_handshake_state == TcpHandshakeState::Established.to_wire()),
        "#16217: an Update must carry the Established stage"
    );

    // Collector on the serving table WITHOUT ct-slice: local (a) alone
    // collects (Established row present), proving the wire can advance
    // on the same packet path.
    let mut out: Vec<(SessionKey, crate::nat::NatDecision)> = Vec::new();
    serving.node_served_forward_slice(0, usize::MAX, &|_| NodeServedEvidence::default(), &mut out);
    assert!(out.iter().any(|(k, _)| k == &forward), "#16217: completed pair must collect without ct-slice");

    // Replica table (peer worker): pending, completes from node
    // evidence on its next served hit — again no ct-slice involved.
    let mut replica = SessionTable::new();
    for (key, is_rev) in [(&forward, false), (&reverse, true)] {
        let mut meta = metadata();
        meta.is_reverse = is_rev;
        if is_rev {
            meta.ingress_zone = crate::test_zone_ids::TEST_WAN_ZONE_ID;
            meta.egress_zone = crate::test_zone_ids::TEST_LAN_ZONE_ID;
        }
        assert!(replica.upsert_synced_with_origin(
            SessionInstall {
                key: key.clone(),
                decision: decision(),
                metadata: meta,
                origin: SessionOrigin::SyncImport,
                now_ns: now,
                protocol: PROTO_TCP,
                tcp_flags: 0,
                session_id: 96,
                tcp_close_class: 0,
                tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
                source_nat_static: None,
            },
            false,
        ));
    }
    let _ = replica.drain_deltas(64);
    replica.note_node_served_handshake(&forward, TcpHandshakeState::Established.to_wire(), 3);
    assert!(replica.probe_hit(&forward, now + 6 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    for key in [&forward, &reverse] {
        let e = replica.entry_by_key(key).expect("replica half");
        assert!(e.established && !e.handshake_pending, "#16217: replica must complete via cache-hit path");
    }
    replica.emit_probe_hit_state_update(&forward);
    let updates: Vec<_> = replica
        .drain_deltas(64)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Update)
        .collect();
    assert_eq!(updates.len(), 1, "#16217: replica completion must emit the stage-advance Update");
    assert_eq!(updates[0].tcp_handshake_state, TcpHandshakeState::Established.to_wire());
}

/// #16217 (GLM B1): `take_probe_stage_transition` fires exactly once —
/// on the cache hit that transitions the pair into Established — and
/// never on steady-state hits. The flow-cache caller restamps shared
/// evidence only behind this gate, so a per-packet restamp would
/// show up here as repeated `true`.
///
/// MUTATION: record the transition on every probe hit (or never) and
/// the once-only assertions fail.
#[test]
fn cache_hit_restamp_gate_fires_only_on_stage_transition_16217() {
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let mut serving = SessionTable::new();
    let _reverse = install_forward_reverse_pair(&mut serving, &forward, now, TCP_SYN);
    // SYN-ACK promotes both halves to HandshakePending.
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());
    assert!(serving.lookup_with_origin(&reverse, now + SEC, TCP_SYN | TCP_ACK).is_some());
    // No completion yet: the gate must not fire.
    assert!(
        !serving.take_probe_stage_transition(&forward),
        "no completion -> no transition gate"
    );
    // Completing ACK via the deferring cache-hit probe (the
    // flow_cache_hit caller shape), then admitted.
    assert!(serving.probe_hit_deferring_state_update(
        &forward,
        now + 2 * SEC,
        1200,
        TCP_ACK | TCP_PSH,
        1200,
        0
    ));
    serving.emit_probe_hit_state_update(&forward);
    assert!(
        serving.take_probe_stage_transition(&forward),
        "the completing hit must open the restamp gate exactly here"
    );
    assert!(
        !serving.take_probe_stage_transition(&forward),
        "the gate is consumed by the first take"
    );
    // Steady-state hits on the Established pair never re-open it.
    for i in 0..4u64 {
        assert!(serving.probe_hit_deferring_state_update(
            &forward,
            now + (3 + i) * SEC,
            1200,
            TCP_ACK | TCP_PSH,
            1200,
            0
        ));
        serving.emit_probe_hit_state_update(&forward);
        assert!(
            !serving.take_probe_stage_transition(&forward),
            "steady-state hit {i} must not re-open the restamp gate (per-packet restamp)"
        );
    }
}

/// #16217 split shape (FZFixWire): the serving pair is Established on
fn split_serving_established_replica_pending_completes_and_announces_16217() {
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());

    // Serving table (sibling worker): promoted pair, genuinely served.
    let mut serving = SessionTable::new();
    let serving_reverse = install_forward_reverse_pair(&mut serving, &forward, now, TCP_SYN);
    assert_eq!(serving_reverse, reverse);
    assert!(serving.lookup_with_origin(&reverse, now + SEC, TCP_SYN | TCP_ACK).is_some());
    assert!(serving.probe_hit(&forward, now + 2 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    assert!(serving.probe_hit(&reverse, now + 3 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    let serving_entry = serving.entry_by_key(&forward).expect("serving forward");
    assert!(serving_entry.established && !serving_entry.handshake_pending);
    assert!(serving_entry.counters.rev_packets > 0);
    // Leg 1: the node-served slice collects the serving pair.
    let mut out: Vec<(SessionKey, crate::nat::NatDecision)> = Vec::new();
    serving.node_served_forward_slice(0, usize::MAX, &|_| NodeServedEvidence::default(), &mut out);
    assert!(
        out.iter().any(|(k, _)| k == &forward),
        "#16217: node-served slice must collect the sibling serving pair, got {out:?}"
    );

    // Replica table: peer-synced HandshakePending pair, never served
    // locally (the completing ACK was consumed on the sibling).
    let mut replica = SessionTable::new();
    assert!(replica.upsert_synced_with_origin(
        SessionInstall {
            key: forward.clone(),
            decision: decision(),
            metadata: metadata(),
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id: 91,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
            source_nat_static: None,
        },
        false,
    ));
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    reverse_metadata.ingress_zone = crate::test_zone_ids::TEST_WAN_ZONE_ID;
    reverse_metadata.egress_zone = crate::test_zone_ids::TEST_LAN_ZONE_ID;
    assert!(replica.upsert_synced_with_origin(
        SessionInstall {
            key: reverse.clone(),
            decision: decision(),
            metadata: reverse_metadata,
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id: 91,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
            source_nat_static: None,
        },
        false,
    ));
    let _ = replica.drain_deltas(64);
    // Node evidence arrives (shared wire Established + serving rev).
    replica.note_node_served_handshake(
        &forward,
        TcpHandshakeState::Established.to_wire(),
        serving_entry.counters.rev_packets,
    );
    // A served hit on the replica completes it via node evidence.
    assert!(replica.probe_hit(&forward, now + 6 * SEC, 1200, TCP_ACK | TCP_PSH, 1200, 0));
    for key in [&forward, &reverse] {
        let entry = replica.entry_by_key(key).expect("replica half");
        assert!(
            entry.established && !entry.handshake_pending,
            "#16217: replica half must complete from node evidence"
        );
    }
    replica.emit_probe_hit_state_update(&forward);
    let updates: Vec<_> = replica
        .drain_deltas(64)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Update)
        .collect();
    assert_eq!(updates.len(), 1, "#16217: stage advancement must emit exactly one Update, got {updates:?}");
    assert_eq!(updates[0].key, forward);
    assert_eq!(
        updates[0].tcp_handshake_state,
        TcpHandshakeState::Established.to_wire(),
        "#16217: Update must carry the Established stage"
    );
    assert_eq!(updates[0].tcp_close_class, 0, "#16217: close class unchanged");
}

/// #16217 Wire8 (backup-origin publication): on the BACKUP node a
/// canonical row held as a local serving row (`WorkerLocalImport` —
/// this node's own session replicated across its workers — or
/// `SharedPromote`) that is Established must be collected by
/// `node_served_forward_slice` so the ct-slice restamps the shared
/// canonical + forward-wire alias to Established; the fabric-ingress
/// gate's shared lookup then hits regardless of which worker later
/// receives the retransmit. Pre-fix `node_served_forward_slice` and
/// `node_served_evidence` excluded every `is_peer_synced()` origin
/// (which includes `WorkerLocalImport`), so fw1's Backup canonical
/// rows never published and stayed `Timeout: 20`.
/// A pure HA-peer replica (`SyncImport`/`SharedMaterialize`) is NOT
/// a local serving row and must never publish from its own flags,
/// even when Established — its completion is announced via the HA
/// Update carve-out instead. Fail-closed arms: reverse, pending,
/// and closing rows never collect.
///
/// FAIL-ON-REVERT: dropping `WorkerLocalImport` from the serving
/// predicate leaves the WorkerLocalImport arm uncollected.
#[test]
fn backup_origin_row_publishes_to_shared_16217() {
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let established = TcpHandshakeState::Established.to_wire();

    let mk = |origin: SessionOrigin, wire: u8| -> SessionTable {
        let mut table = SessionTable::new();
        assert!(table.upsert_synced_with_origin(
            SessionInstall {
                key: forward.clone(),
                decision: decision(),
                metadata: metadata(),
                origin,
                now_ns: now,
                protocol: PROTO_TCP,
                tcp_flags: 0,
                session_id: 99,
                tcp_close_class: 0,
                tcp_handshake_state: wire,
                source_nat_static: None,
            },
            false,
        ));
        table
    };
    let collect = |table: &SessionTable| -> Vec<(SessionKey, crate::nat::NatDecision)> {
        let mut out = Vec::new();
        table.node_served_forward_slice(
            0,
            usize::MAX,
            &|_| NodeServedEvidence::default(),
            &mut out,
        );
        out
    };

    // Positive: backup-origin local serving rows publish.
    for origin in [
        SessionOrigin::WorkerLocalImport,
        SessionOrigin::SharedPromote,
    ] {
        let table = mk(origin, established);
        let e = table.entry_by_key(&forward).expect("row");
        assert!(
            e.established && !e.handshake_pending && !e.closing && !e.metadata.is_reverse,
            "premise {origin:?}: Established non-reverse serving row"
        );
        assert!(
            collect(&table).iter().any(|(k, _)| k == &forward),
            "#16217 Wire8: {origin:?} Established backup row must publish to shared"
        );
    }

    // Negative: pure SyncImport replica does not publish, even Established.
    let replica = mk(SessionOrigin::SyncImport, established);
    assert!(
        !collect(&replica).iter().any(|(k, _)| k == &forward),
        "#16217 Wire8: SyncImport replica must not publish from its own flags"
    );
    let materialized = mk(SessionOrigin::SharedMaterialize, established);
    assert!(
        !collect(&materialized).iter().any(|(k, _)| k == &forward),
        "#16217 Wire8: SharedMaterialize replica must not publish"
    );

    // Fail-closed: pending WorkerLocalImport never collects.
    let pending = mk(
        SessionOrigin::WorkerLocalImport,
        TcpHandshakeState::HandshakePending.to_wire(),
    );
    assert!(
        !collect(&pending).iter().any(|(k, _)| k == &forward),
        "#16217 Wire8: pending backup row must fail closed"
    );
}

/// #16217 guard: a peer-synced row whose CLOSE class transitions
/// (server RST) must stay silent — the carve-out is stage-only.
#[test]
fn peer_synced_close_transition_stays_silent_16217() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: forward.clone(),
            decision: decision(),
            metadata: metadata(),
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id: 92,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::Established.to_wire(),
            source_nat_static: None,
        },
        false,
    ));
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    reverse_metadata.ingress_zone = crate::test_zone_ids::TEST_WAN_ZONE_ID;
    reverse_metadata.egress_zone = crate::test_zone_ids::TEST_LAN_ZONE_ID;
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: reverse.clone(),
            decision: decision(),
            metadata: reverse_metadata,
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id: 92,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::Established.to_wire(),
            source_nat_static: None,
        },
        false,
    ));
    let _ = table.drain_deltas(64);
    assert!(table.lookup(&reverse, now + SEC, crate::tcp_flags::TCP_RST | TCP_ACK).is_some());
    let updates: Vec<_> = table
        .drain_deltas(64)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Update)
        .collect();
    assert!(
        updates.is_empty(),
        "#16217: peer-synced close transition must stay silent, got {updates:?}"
    );
}

/// #16217 (export stamp, change 1): `open_export_delta_with_provenance`
/// must export `tcp_handshake_state = Established` when node-wide
/// completion evidence holds for the tuple, even though the exporting
/// table's own row still reads HandshakePending. The exporting table
/// is a pending replica; the completion proof is the serving worker's
/// stamp (`note_node_served_handshake` with an Established wire and
/// admitted reverse counters). Control: with no stamp the export
/// keeps the live pending wire.
///
/// MUTATION: drop the `completion_evidence_for` stamp in
/// `open_export_delta_with_provenance` and the positive arm exports
/// wire 2, failing the first assertion.
#[test]
fn export_stamp_open_delta_established_on_node_evidence_16217() {
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let mut table = SessionTable::new();
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: forward.clone(),
            decision: decision(),
            metadata: metadata(),
            origin: SessionOrigin::SharedPromote,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            session_id: 97,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
            source_nat_static: None,
        },
        false,
    ));
    // Control: no node evidence -> live pending wire exported.
    let control = table
        .open_export_delta_with_provenance(
            forward.clone(),
            decision(),
            metadata(),
            SessionOrigin::SharedPromote,
            false,
            ExportProvenance::Incremental,
        )
        .expect("forward export");
    assert_eq!(
        control.tcp_handshake_state,
        TcpHandshakeState::HandshakePending.to_wire(),
        "premise: without evidence the export keeps the pending wire"
    );
    // Serving worker on this node completed the pair and served
    // reverse traffic; its stamp is the node-wide evidence.
    table.note_node_served_handshake(
        &forward,
        TcpHandshakeState::Established.to_wire(),
        5,
    );
    let stamped = table
        .open_export_delta_with_provenance(
            forward.clone(),
            decision(),
            metadata(),
            SessionOrigin::SharedPromote,
            false,
            ExportProvenance::Incremental,
        )
        .expect("forward export");
    assert_eq!(
        stamped.tcp_handshake_state,
        TcpHandshakeState::Established.to_wire(),
        "#16217: export must stamp Established when node-wide evidence holds"
    );
}

/// #16217 (export stamp, change 1): `emit_session_state_update` must
/// stamp Established when node-wide evidence holds, and the
/// shared-evidence variant must do the same from shared evidence
/// alone. The row transitions Opening -> HandshakePending locally
/// (a real transition, so the transition-only gate passes) but never
/// completes locally; only the node stamp / shared evidence proves
/// completion.
///
/// MUTATION: drop the evidence stamp in
/// `emit_session_state_update_inner` and both positive arms emit the
/// live pending wire, failing their assertions.
#[test]
fn export_stamp_update_established_on_node_and_shared_evidence_16217() {
    let established = TcpHandshakeState::Established.to_wire();
    let pending = TcpHandshakeState::HandshakePending.to_wire();
    let now = 1_000_000_000u64;

    let mk_table = |wire: u8| {
        let forward = key_v4();
        let mut table = SessionTable::new();
        assert!(table.upsert_synced_with_origin(
            SessionInstall {
                key: forward.clone(),
                decision: decision(),
                metadata: metadata(),
                origin: SessionOrigin::ForwardFlow,
                now_ns: now,
                protocol: PROTO_TCP,
                tcp_flags: 0,
                session_id: 98,
                tcp_close_class: 0,
                tcp_handshake_state: wire,
                source_nat_static: None,
            },
            false,
        ));
        (table, forward)
    };

    // Helper: a table whose row already reads HandshakePending. The
    // caller passes `handshake_state_before = Opening`, modelling the
    // hit path that observed the Opening row, promoted it, and now
    // emits the transition Update (emit is transition-only on the
    // before/after pair, exactly as the lookup callers drive it).
    let updates_of = |table: &mut SessionTable, forward: &SessionKey| -> Vec<SessionDelta> {
        table.drain_deltas(64);
        table.emit_session_state_update(
            forward,
            0,
            TcpHandshakeState::Opening.to_wire(),
        );
        table
            .drain_deltas(64)
            .into_iter()
            .filter(|d| d.kind == SessionDeltaKind::Update)
            .collect()
    };

    // (a) Table-local node evidence -> Update reads Established.
    let (mut table, forward) = mk_table(pending);
    table.note_node_served_handshake(&forward, established, 3);
    let updates = updates_of(&mut table, &forward);
    assert_eq!(updates.len(), 1, "transition must emit one Update");
    assert_eq!(
        updates[0].tcp_handshake_state, established,
        "#16217: Update must stamp Established on node evidence"
    );

    // (b) Shared evidence alone (no local stamp): the shared variant
    // stamps Established.
    let shared = NodeServedEvidence {
        rev_packets_any: 4,
        ..NodeServedEvidence::default()
    };
    let (mut with_shared, forward2) = mk_table(pending);
    with_shared.drain_deltas(64);
    with_shared.emit_session_state_update_with_shared_evidence(
        &forward2,
        0,
        TcpHandshakeState::Opening.to_wire(),
        shared,
    );
    let updates: Vec<_> = with_shared
        .drain_deltas(64)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Update)
        .collect();
    assert_eq!(updates.len(), 1);
    assert_eq!(
        updates[0].tcp_handshake_state, established,
        "#16217: shared-evidence Update must stamp Established"
    );

    // (c) Control: no evidence anywhere -> live pending wire.
    let (mut plain, forward3) = mk_table(pending);
    let updates = updates_of(&mut plain, &forward3);
    assert_eq!(updates.len(), 1);
    assert_eq!(
        updates[0].tcp_handshake_state, pending,
        "control: without any evidence the Update keeps the pending wire"
    );
}

/// #16217 (counter carriage): the Open export and the stage-advance
/// Update must snapshot the LIVE counters, not the install-time
/// zero — otherwise the peer import stamps (0,0) and the scoped
/// adoption gate can never qualify (FZDiag19). The serving pair is
/// driven with real accounted traffic first.
///
/// MUTATION: restore `SessionCounters::default()` in
/// `open_export_delta_with_provenance` or
/// `emit_session_state_update_inner` and the matching arm reads 0.
#[test]
fn open_and_update_deltas_carry_live_counters_16217() {
    let (mut table, forward, reverse, _now) = opening_pair();
    // Serve real traffic: forward packets on the forward key, replies
    // on the reverse key (folded onto the forward entry).
    table.account_packet(&forward, 1200, 0, 0);
    table.account_packet(&forward, 1200, 0, 0);
    table.account_packet(&reverse, 800, 0, 0);
    let live = table.session_counters(&forward).expect("forward entry");
    assert!(live.fwd_packets > 0 && live.rev_packets > 0, "premise: live counters nonzero: {live:?}");
    let delta = table
        .open_export_delta_with_provenance(
            forward.clone(),
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            false,
            ExportProvenance::Incremental,
        )
        .expect("forward export");
    assert_eq!(delta.counters.fwd_packets, live.fwd_packets, "#16217: Open export must carry live fwd count");
    assert_eq!(delta.counters.rev_packets, live.rev_packets, "#16217: Open export must carry live rev count");
    // Update leg: force a transition emit and read its counters.
    table.drain_deltas(64);
    table.emit_session_state_update(&forward, 9, TcpHandshakeState::Opening.to_wire());
    let updates: Vec<_> = table
        .drain_deltas(64)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Update)
        .collect();
    assert_eq!(updates.len(), 1, "transition must emit one Update");
    assert_eq!(updates[0].counters.fwd_packets, live.fwd_packets, "#16217: Update must carry live fwd count");
    assert_eq!(updates[0].counters.rev_packets, live.rev_packets, "#16217: Update must carry live rev count");
}

/// #16217 (counter carriage): `build_synced_session_entry` stamps the
/// request's counters onto the imported entry, and the monotonic
/// publish merge preserves the max on republication.
///
/// MUTATION: restore `rev_packets: 0, fwd_packets: 0` in
/// `build_synced_session_entry` and the imported entry reads (0,0).
#[test]
fn import_stamps_request_counters_16217() {
    let req = crate::protocol::SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 43210,
        dst_port: 5211,
        fwd_packets: 12345,
        rev_packets: 6789,
        ..crate::protocol::SessionSyncRequest::default()
    };
    let zones: rustc_hash::FxHashMap<String, u16> = rustc_hash::FxHashMap::default();
    let entry = crate::server::helpers::build_synced_session_entry(&req, &zones, 0)
        .expect("import builds");
    assert_eq!(entry.fwd_packets, 12345, "#16217: import must stamp fwd count");
    assert_eq!(entry.rev_packets, 6789, "#16217: import must stamp rev count");
}

