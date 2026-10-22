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
