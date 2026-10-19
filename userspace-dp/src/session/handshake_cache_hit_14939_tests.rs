//! #14939: a handshake-completing segment consumed by a hit path that
//! never reaches the full `lookup` promotion arm must still complete
//! the handshake — on whichever path consumes it.
//!
//! Live discriminator (loss, master 8cece4238a): during iperf -P12 ALL
//! sessions showed `Timeout: 20` (the OPENING window) mid-flow instead
//! of 300 (established). `handshake_pending` never cleared for these
//! installs, so sessions lived on the 20 s opening window and —
//! combined with 30 s-scale reap — died mid-transfer; SYN-less packets
//! then failed strict-syn-check for a permanent stall.
//!
//! #6752's README reasoning ("its completing segment reaches the slow
//! path because `packet_eligible` admits TCP only when `is_ack_only`")
//! covers the bare completing ACK. It does NOT cover the realistic
//! completing segment: an ACK carrying the first data (Linux/Nagle
//! data ACK, PSH+ACK — `is_ack_only` ignores PSH/URG, so such a
//! segment `should_cache` on its SYN-ACK-seeded entry and is then
//! served by `touch_if_stale_with_payload`, which pre-fix refreshed
//! only `last_seen_ns` and never consulted `handshake_pending`). Once
//! one ACK-only packet seeded the cache, every later completing/data
//! segment was cache-served forever and no path ever completed the
//! handshake.
//!
//! The deferred-Owner replay (`apply_deferred_owner_hit_with_payload`)
//! already replays through the real `lookup` arm and completes; these
//! tests pin that as the control, plus the SYN-ACK-first replica /
//! materialized shape (a synced HandshakePending import must be
//! completable by `touch_if_stale_with_payload` on this node too).

use super::tests::{decision, install_forward_reverse_pair, key_v4, metadata};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_PSH, TCP_SYN};

const SEC: u64 = 1_000_000_000;

fn pending_pair() -> (SessionTable, SessionKey, SessionKey, u64) {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    // Reverse SYN-ACK through the real lookup arm: promotes both halves
    // but leaves the handshake pending on the opening window.
    assert!(
        table
            .lookup_with_origin(&reverse, now + SEC, TCP_SYN | TCP_ACK)
            .is_some()
    );
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("installed half");
        assert!(
            entry.established && entry.handshake_pending,
            "{label}: premise — SYN-ACK promotes but leaves handshake pending"
        );
        assert_eq!(
            entry.expires_after_ns, table.timeouts.tcp_opening_ns,
            "{label}: premise — pending half on the opening window"
        );
    }
    (table, forward, reverse, now + SEC)
}

/// The flow-cache keepalive is the path that consumes the completing
/// segment once the flow is cached. A data-bearing completing ACK
/// (PSH+ACK with payload) arriving while pending must promote BOTH
/// halves onto the established window, not merely re-stamp
/// `last_seen_ns` on the opening window.
#[test]
fn flow_cache_completing_ack_promotes_pending_pair_14939() {
    let (mut table, forward, reverse, synack_ns) = pending_pair();
    let ack_ns = synack_ns + SEC;
    assert!(
        table.touch_if_stale_with_payload(&forward, ack_ns, TCP_ACK | TCP_PSH, 512),
        "cache hit must be served (live backing session)"
    );
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("half after completing ACK");
        assert!(
            entry.established && !entry.handshake_pending && !entry.syn_ack_first,
            "#14939: {label} handshake must complete on the flow-cache hit path"
        );
        assert_eq!(
            entry.expires_after_ns, table.timeouts.tcp_established_ns,
            "#14939: {label} must move to the established window (Timeout:1800, #15127)"
        );
        assert_eq!(
            entry.last_seen_ns, ack_ns,
            "#14939: {label} re-stamped by the completing ACK"
        );
    }
    assert_eq!(table.timeout_secs_for(&forward), 1800); // #15127
    assert_eq!(table.timeout_secs_for(&reverse), 1800); // #15127
}

/// Bare completing ACK (no payload) through the same keepalive: also
/// completes. This is the segment class #6752 assumed always reaches
/// the slow path; once cached it does not, so the keepalive must own
/// completion for it too.
#[test]
fn flow_cache_bare_completing_ack_promotes_14939() {
    let (mut table, forward, reverse, synack_ns) = pending_pair();
    let ack_ns = synack_ns + SEC;
    assert!(table.touch_if_stale_with_payload(&forward, ack_ns, TCP_ACK, 0));
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("half after bare ACK");
        assert!(
            !entry.handshake_pending,
            "#14939: bare completing ACK via keepalive must clear pending ({label})"
        );
        assert_eq!(entry.expires_after_ns, table.timeouts.tcp_established_ns);
    }
}

/// Control / deferred-Owner replay: the replay goes through the real
/// lookup arm, so it already completes. Pinning it keeps the two hit
/// paths from diverging again.
#[test]
fn deferred_owner_replay_completes_pending_pair_14939() {
    let (mut table, forward, reverse, synack_ns) = pending_pair();
    let ack_ns = synack_ns + SEC;
    // Deferred (read-only) probe first, exactly as the poll path does.
    let _ = table.lookup_with_origin_deferring_authority_with_payload(
        &forward,
        ack_ns,
        TCP_ACK | TCP_PSH,
        512,
    );
    for key in [&forward, &reverse] {
        assert!(
            table.entry_by_key(key).expect("half").handshake_pending,
            "deferred probe must not mutate before the Owner verdict"
        );
    }
    table.apply_deferred_owner_hit_with_payload(&forward, ack_ns, TCP_ACK | TCP_PSH, 512);
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("half after Owner replay");
        assert!(
            entry.established && !entry.handshake_pending,
            "#14939: Owner replay must complete the handshake ({label})"
        );
        assert_eq!(entry.expires_after_ns, table.timeouts.tcp_established_ns);
    }
}

/// SYN-ACK-first / synced-replica shape: a HandshakePending import
/// (established=true, handshake_pending=true, syn_ack_first=false —
/// the `upsert_synced` mapping) completed by a forward ACK that this
/// node's worker consumes via the flow-cache keepalive.
#[test]
fn synced_pending_replica_completes_via_flow_cache_hit_14939() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    // Forward half imported as HandshakePending (wire state 2).
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: forward.clone(),
            decision: decision(),
            metadata: metadata(),
            origin: SessionOrigin::SyncImport,
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
            origin: SessionOrigin::SyncImport,
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
            "{label}: premise — synced HandshakePending import shape"
        );
        assert_eq!(entry.expires_after_ns, table.timeouts.tcp_opening_ns);
    }
    let ack_ns = now + SEC;
    assert!(table.touch_if_stale_with_payload(&forward, ack_ns, TCP_ACK | TCP_PSH, 256));
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("half after completing ACK");
        assert!(
            !entry.handshake_pending,
            "#14939: synced pending replica must complete via the consuming hit path ({label})"
        );
        assert_eq!(
            entry.expires_after_ns, table.timeouts.tcp_established_ns,
            "#14939: {label} must show the established window after completion"
        );
    }
}

/// #14630 guard must hold on the new path: a closing (RST-stamped)
/// pending entry never completes, even when the completing-shaped ACK
/// is consumed by the flow-cache keepalive.
#[test]
fn flow_cache_ack_after_rst_does_not_complete_14939() {
    let (mut table, forward, reverse, synack_ns) = pending_pair();
    // RST on the forward half through the real lookup arm.
    assert!(
        table
            .lookup_with_origin(&forward, synack_ns + SEC, crate::tcp_flags::TCP_RST)
            .is_some()
    );
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("closing half");
        assert!(
            entry.closing && entry.handshake_pending,
            "{label}: premise closing+pending"
        );
    }
    let ack_ns = synack_ns + 2 * SEC;
    let _ = table.touch_if_stale_with_payload(&forward, ack_ns, TCP_ACK, 0);
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = table.entry_by_key(key).expect("half after post-RST ACK");
        assert!(
            entry.handshake_pending,
            "#14939/#14630: post-RST ACK via keepalive must not complete ({label})"
        );
        assert_ne!(
            entry.expires_after_ns, table.timeouts.tcp_established_ns,
            "#14939/#14630: closing half must not be re-armed onto the established window ({label})"
        );
    }
}

/// Survival: after completion via the cache hit, data traffic keeps
/// both halves alive past opening+closing windows (the live stall was
/// reap at ~20-30 s despite continuous traffic).
#[test]
fn completed_pair_survives_past_opening_window_under_cache_hits_14939() {
    let (mut table, forward, reverse, synack_ns) = pending_pair();
    assert!(table.touch_if_stale_with_payload(&forward, synack_ns + SEC, TCP_ACK | TCP_PSH, 1024));
    // Continuous data for 40 s (past the 20 s opening window) served
    // entirely by cache hits.
    for step in 1..=8u64 {
        let t = synack_ns + SEC + step * 5 * SEC;
        assert!(
            table.touch_if_stale_with_payload(&forward, t, TCP_ACK | TCP_PSH, 1024),
            "forward half must stay live under data at +{}s",
            step * 5
        );
        assert!(
            table.session_is_live_at(&reverse, t),
            "reverse half must stay live under companion data at +{}s",
            step * 5
        );
    }
    assert_eq!(table.timeout_secs_for(&forward), 1800); // #15127
}
