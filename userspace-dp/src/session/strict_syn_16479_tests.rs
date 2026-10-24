//! #16479: the read-only pre-handshake state probe behind the
//! strict-syn-check session-HIT gate. The poll path and the flow-cache
//! fence both read this probe; a dropped pre-handshake data segment
//! must observe the pending state WITHOUT the probe itself refreshing,
//! promoting, or completing it.

use super::tests::{decision, install_forward_reverse_pair, key_v4, metadata};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_SYN};

const SEC: u64 = 1_000_000_000;

#[test]
fn strict_probe_reports_pending_then_established_16479() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    // Bare SYN install: OPENING (not established, not yet pending).
    assert_eq!(
        table.strict_pre_handshake_state(&forward, now),
        Some((false, false, false, false)),
        "#16479: bare-SYN forward half must probe OPENING"
    );
    // Reverse SYN-ACK promotes but leaves the handshake pending.
    assert!(table
        .lookup_with_origin(&reverse, now + SEC, TCP_SYN | TCP_ACK)
        .is_some());
    let fwd_before = table.entry_by_key(&forward).expect("forward half").last_seen_ns;
    assert_eq!(
        table.strict_pre_handshake_state(&forward, now + SEC),
        Some((true, true, false, false)),
        "#16479: post-SYN-ACK forward half must probe pending"
    );
    assert_eq!(
        table.strict_pre_handshake_state(&reverse, now + SEC),
        Some((true, true, false, false)),
        "#16479: post-SYN-ACK reverse half must probe pending"
    );
    // The probe is read-only: it must not refresh or complete.
    let fwd_after = table.entry_by_key(&forward).expect("forward half");
    assert_eq!(fwd_after.last_seen_ns, fwd_before, "#16479: probe must not refresh");
    assert!(fwd_after.handshake_pending, "#16479: probe must not complete the handshake");
    // Completing ACK (payload-free) clears pending on both halves.
    assert!(table
        .lookup_with_origin(&forward, now + 2 * SEC, TCP_ACK)
        .is_some());
    assert_eq!(
        table.strict_pre_handshake_state(&forward, now + 2 * SEC),
        Some((true, false, false, false)),
        "#16479: completed forward half must probe established"
    );
    assert_eq!(
        table.strict_pre_handshake_state(&reverse, now + 2 * SEC),
        Some((true, false, false, false)),
        "#16479: completed reverse half must probe established"
    );
    // Positive control for the data-after-handshake case is the state
    // above: established && !pending is exactly what the leaf predicate
    // admits (see session_admission tests). An idle-crossed entry probes
    // as a miss, not a hit.
    assert_eq!(
        table.strict_pre_handshake_state(&forward, now + 10_000 * SEC),
        None,
        "#16479: idle-crossed entry must probe None (miss)"
    );
}

#[test]
fn strict_probe_syn_ack_first_pending_16479() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN | TCP_ACK);
    let _ = reverse;
    assert_eq!(
        table.strict_pre_handshake_state(&forward, now),
        Some((false, true, true, false)),
        "#16479: SYN-ACK-first forward half must probe syn_ack_first pending"
    );
}

#[test]
fn strict_probe_midstream_pickup_is_established_16479() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    // Mid-stream pickup (no-syn-check shape): installs established.
    assert!(table.install_with_protocol_with_origin(
        forward.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        now,
        PROTO_TCP,
        TCP_ACK,
    ));
    assert_eq!(
        table.strict_pre_handshake_state(&forward, now),
        Some((true, false, false, false)),
        "#16479: mid-stream pickup must probe established (never gated)"
    );
}
