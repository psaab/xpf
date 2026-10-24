//! #16042: handshake promotion/completion must validate the segment's
//! ack number (ack == companion ISN + 1, wrapping) at EVERY completion
//! gate — lookup SYN-ACK, lookup completing-ACK, cached-hit
//! (`probe_hit` / keepalive), and the `update_session` / promote twin.
//!
//! A wrong-ack segment must never promote a pair off the opening
//! window; the correct ack must. Unknown evidence (HA import with no
//! observed SYN, unparsed ack) fails OPEN — flags-only, bounded by the
//! opening window — never fail-closed, so a failover import's first
//! completing segment still completes.
//!
//! NAT: the companion is resolved through `reverse_session_key`, so a
//! translated pair validates against the alias companion's ISN.
//! Wraparound: ISN `u32::MAX` expects ack 0.
//! SYN-ACK-first: the completing segment is a reverse non-SYN ACK
//! acking the SYN-ACK's ISN.
//!
//! FAIL-ON-REVERT: removing the `ack_valid` conjunct from any gate
//! turns the corresponding bad-ack test RED.

use super::tests::{decision, install_forward_reverse_pair, key_v4, metadata};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_PSH, TCP_SYN};

const SEC: u64 = 1_000_000_000;
const CLIENT_ISN: u32 = 1000;
const SERVER_ISN: u32 = 5000;

/// Install a SYN-first pair and note the client SYN (ISN 1000), so the
/// reverse half carries the client ISN a SYN-ACK must ack (1001).
fn syn_pair() -> (SessionTable, SessionKey, SessionKey, u64) {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    table.note_tcp_seq(&forward, CLIENT_ISN, 0, 4096, 0, TCP_SYN, 0);
    (table, forward, reverse, now)
}

/// Drive a reverse SYN-ACK (server ISN 5000) with the given ack through
/// the ack-carrying lookup; returns both halves' (established, pending).
fn syn_ack_via_lookup(table: &mut SessionTable, reverse: &SessionKey, now: u64, ack: u32) {
    table.note_tcp_seq(reverse, SERVER_ISN, ack, 4096, 0, TCP_SYN | TCP_ACK, 0);
    assert!(
        table
            .lookup_with_origin_with_ack(reverse, now, TCP_SYN | TCP_ACK, 0, Some(ack))
            .is_some(),
        "SYN-ACK hit must resolve"
    );
}

fn assert_opening(table: &SessionTable, key: &SessionKey, label: &str) {
    let e = table.entry_by_key(key).expect("half");
    assert!(
        !e.established || e.handshake_pending,
        "#16042: {label} must stay on the opening window (established={}, pending={})",
        e.established, e.handshake_pending
    );
    assert_eq!(
        e.expires_after_ns, table.timeouts.tcp_opening_ns,
        "#16042: {label} must keep the opening expiry"
    );
}

fn assert_established(table: &SessionTable, key: &SessionKey, label: &str) {
    let e = table.entry_by_key(key).expect("half");
    assert!(
        e.established && !e.handshake_pending && !e.syn_ack_first,
        "#16042: {label} must be established and not pending"
    );
    assert_eq!(
        e.expires_after_ns, table.timeouts.tcp_established_ns,
        "#16042: {label} must be on the established window"
    );
}

// ---------------------------------------------------------------- lookup SYN-ACK

#[test]
fn bad_ack_syn_ack_does_not_promote_lookup_16042() {
    let (mut table, forward, reverse, now) = syn_pair();
    syn_ack_via_lookup(&mut table, &reverse, now + SEC, CLIENT_ISN + 999);
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        assert_opening(&table, key, label);
        let e = table.entry_by_key(key).unwrap();
        assert!(!e.established, "#16042: bad-ack SYN-ACK promoted {label}");
    }
}

#[test]
fn correct_ack_syn_ack_promotes_but_stays_pending_lookup_16042() {
    let (mut table, forward, reverse, now) = syn_pair();
    syn_ack_via_lookup(&mut table, &reverse, now + SEC, CLIENT_ISN + 1);
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("half");
        assert!(
            e.established && e.handshake_pending,
            "#16042: correct SYN-ACK must promote but stay pending ({label})"
        );
        assert_eq!(e.expires_after_ns, table.timeouts.tcp_opening_ns);
    }
}

// ------------------------------------------------------- lookup completing-ACK

#[test]
fn bad_ack_completing_ack_does_not_complete_lookup_16042() {
    let (mut table, forward, reverse, now) = syn_pair();
    syn_ack_via_lookup(&mut table, &reverse, now + SEC, CLIENT_ISN + 1);
    // Completing ACK must ack SERVER_ISN+1 = 5001; send a wrong ack.
    assert!(table
        .lookup_with_origin_with_ack(&forward, now + 2 * SEC, TCP_ACK | TCP_PSH, 100, Some(SERVER_ISN + 77))
        .is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        assert_opening(&table, key, label);
    }
    // The correct ack then completes.
    assert!(table
        .lookup_with_origin_with_ack(&forward, now + 3 * SEC, TCP_ACK | TCP_PSH, 100, Some(SERVER_ISN + 1))
        .is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        assert_established(&table, key, label);
    }
}

#[test]
fn wraparound_isn_completing_ack_16042() {
    // Server ISN = u32::MAX → expected ack wraps to 0.
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    table.note_tcp_seq(&forward, CLIENT_ISN, 0, 4096, 0, TCP_SYN, 0);
    table.note_tcp_seq(&reverse, u32::MAX, CLIENT_ISN + 1, 4096, 0, TCP_SYN | TCP_ACK, 0);
    assert!(table
        .lookup_with_origin_with_ack(&reverse, now + SEC, TCP_SYN | TCP_ACK, 0, Some(CLIENT_ISN + 1))
        .is_some());
    // Wrong ack (1, the non-wrapping successor) must not complete.
    assert!(table
        .lookup_with_origin_with_ack(&forward, now + 2 * SEC, TCP_ACK, 0, Some(1))
        .is_some());
    assert_opening(&table, &forward, "forward");
    // Ack 0 is the wrapping-correct completing ack.
    assert!(table
        .lookup_with_origin_with_ack(&forward, now + 3 * SEC, TCP_ACK, 0, Some(0))
        .is_some());
    assert_established(&table, &forward, "forward");
    assert_established(&table, &reverse, "reverse");
}

// ------------------------------------------------------------ SYN-ACK-first

#[test]
fn syn_ack_first_bad_ack_does_not_complete_16042() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    // Installed from the SYN-ACK itself (installing direction = forward
    // key here mirrors install_forward_reverse_pair with SYN|ACK flags).
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN | TCP_ACK);
    // Seed both halves with the SYN-ACK ISN, as the poll install does.
    table.seed_tcp_isn(&forward, SERVER_ISN, TCP_SYN | TCP_ACK);
    for key in [&forward, &reverse] {
        let e = table.entry_by_key(key).unwrap();
        assert!(!e.established && e.handshake_pending && e.syn_ack_first, "premise SYN-ACK-first pending");
    }
    // Completing segment: reverse non-SYN ACK acking SERVER_ISN+1.
    assert!(table
        .lookup_with_origin_with_ack(&reverse, now + SEC, TCP_ACK, 0, Some(SERVER_ISN + 55))
        .is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).unwrap();
        assert!(e.handshake_pending && e.syn_ack_first, "#16042: bad ack completed SYN-ACK-first ({label})");
        assert_eq!(e.expires_after_ns, table.timeouts.tcp_opening_ns);
    }
    assert!(table
        .lookup_with_origin_with_ack(&reverse, now + 2 * SEC, TCP_ACK, 0, Some(SERVER_ISN + 1))
        .is_some());
    assert_established(&table, &forward, "forward");
    assert_established(&table, &reverse, "reverse");
}

// ---------------------------------------------------------------- cached-hit

#[test]
fn bad_ack_does_not_complete_cached_hit_16042() {
    let (mut table, forward, reverse, now) = syn_pair();
    syn_ack_via_lookup(&mut table, &reverse, now + SEC, CLIENT_ISN + 1);
    // Cached-hit path (probe_hit) with a wrong ack.
    assert!(table.probe_hit_with_ack(&forward, now + 2 * SEC, 100, TCP_ACK | TCP_PSH, 100, 0, Some(SERVER_ISN + 9)));
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        assert_opening(&table, key, label);
    }
    // Deferring variant with a wrong ack also must not complete.
    assert!(table.probe_hit_deferring_state_update_with_ack(
        &forward,
        now + 3 * SEC,
        100,
        TCP_ACK | TCP_PSH,
        100,
        0,
        Some(1),
    ));
    assert_opening(&table, &forward, "forward");
    // Correct ack via the fused probe completes both halves.
    assert!(table.probe_hit_with_ack(&forward, now + 4 * SEC, 100, TCP_ACK | TCP_PSH, 100, 0, Some(SERVER_ISN + 1)));
    assert_established(&table, &forward, "forward");
    assert_established(&table, &reverse, "reverse");
}

#[test]
fn bad_ack_does_not_complete_keepalive_16042() {
    let (mut table, forward, reverse, now) = syn_pair();
    syn_ack_via_lookup(&mut table, &reverse, now + SEC, CLIENT_ISN + 1);
    assert!(table.touch_if_stale_with_ack(&forward, now + 2 * SEC, TCP_ACK | TCP_PSH, 100, Some(42)));
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        assert_opening(&table, key, label);
    }
    assert!(table.touch_if_stale_with_ack(&forward, now + 3 * SEC, TCP_ACK | TCP_PSH, 100, Some(SERVER_ISN + 1)));
    assert_established(&table, &forward, "forward");
    assert_established(&table, &reverse, "reverse");
}

// ------------------------------------------------------------- update paths

fn update_req<'a>(key: &'a SessionKey, meta: SessionMetadata, flags: u8, ack: Option<u32>, now: u64) -> SessionUpdate<'a> {
    SessionUpdate {
        key,
        decision: decision(),
        metadata: meta,
        origin: SessionOrigin::ForwardFlow,
        now_ns: now,
        protocol: PROTO_TCP,
        tcp_flags: flags,
        ack,
    }
}

#[test]
fn bad_ack_syn_ack_does_not_promote_update_16042() {
    let (mut table, forward, reverse, now) = syn_pair();
    let mut rev_meta = metadata();
    rev_meta.is_reverse = true;
    // update_session SYN-ACK twin with a wrong ack.
    assert!(table.update_session(update_req(&reverse, rev_meta.clone(), TCP_SYN | TCP_ACK, Some(CLIENT_ISN + 31), now + SEC), false));
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).unwrap();
        assert!(!e.established, "#16042: bad-ack SYN-ACK promoted via update ({label})");
        assert_eq!(e.expires_after_ns, table.timeouts.tcp_opening_ns);
    }
    // Correct ack promotes (pending) via the same twin.
    table.note_tcp_seq(&reverse, SERVER_ISN, CLIENT_ISN + 1, 4096, 0, TCP_SYN | TCP_ACK, 0);
    assert!(table.update_session(update_req(&reverse, rev_meta, TCP_SYN | TCP_ACK, Some(CLIENT_ISN + 1), now + 2 * SEC), false));
    let e = table.entry_by_key(&reverse).unwrap();
    assert!(e.established && e.handshake_pending, "#16042: correct SYN-ACK must promote via update");
    // Completing ACK with wrong ack must not complete; correct must.
    assert!(table.update_session(update_req(&forward, metadata(), TCP_ACK, Some(9), now + 3 * SEC), false));
    assert_opening(&table, &forward, "forward");
    assert!(table.update_session(update_req(&forward, metadata(), TCP_ACK, Some(SERVER_ISN + 1), now + 4 * SEC), false));
    assert_established(&table, &forward, "forward");
    assert_established(&table, &reverse, "reverse");
}

#[test]
fn bad_ack_does_not_complete_promote_synced_16042() {
    let (mut table, forward, reverse, now) = syn_pair();
    syn_ack_via_lookup(&mut table, &reverse, now + SEC, CLIENT_ISN + 1);
    // promote_synced_with_origin is update_session(req, false): wrong ack.
    assert!(table.promote_synced_with_origin(update_req(&forward, metadata(), TCP_ACK, Some(1234), now + 2 * SEC)));
    assert_opening(&table, &forward, "forward");
    assert!(table.promote_synced_with_origin(update_req(&forward, metadata(), TCP_ACK, Some(SERVER_ISN + 1), now + 3 * SEC)));
    assert_established(&table, &forward, "forward");
    assert_established(&table, &reverse, "reverse");
}

// ------------------------------------------------------- NAT alias companion

#[test]
fn nat_alias_companion_ack_validated_16042() {
    // SNAT: forward decision rewrites src to 203.0.113.7:40001, so the
    // reverse companion key is the translated alias, not the plain swap.
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let mut nat = crate::nat::NatDecision::default();
    nat.rewrite_src = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)));
    nat.rewrite_src_port = Some(40001);
    let mut fwd_decision = decision();
    fwd_decision.nat = nat;
    assert!(table.install_with_protocol(forward.clone(), fwd_decision, metadata(), now, PROTO_TCP, TCP_SYN));
    let reverse = reverse_session_key(&forward, nat);
    // SNAT companion: dst is the translated source the reply targets.
    assert_eq!(reverse.dst_ip, std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)), "premise: alias dst is the SNAT address");
    assert_eq!(reverse.dst_port, 40001, "premise: alias dst port is the SNAT port");
    let mut rev_meta = metadata();
    rev_meta.is_reverse = true;
    let mut rev_decision = decision();
    rev_decision.nat = nat.reverse(forward.src_ip, forward.dst_ip, forward.src_port, forward.dst_port);
    assert!(table.install_with_protocol(reverse.clone(), rev_decision, rev_meta, now, PROTO_TCP, TCP_SYN));
    let _ = table.drain_deltas(16);
    // Seed + note through the alias keys exactly as the poll path does.
    table.seed_tcp_isn(&forward, CLIENT_ISN, TCP_SYN);
    table.note_tcp_seq(&forward, CLIENT_ISN, 0, 4096, 0, TCP_SYN, 0);
    assert_eq!(
        table.handshake_expected_ack(&reverse),
        Some(CLIENT_ISN + 1),
        "#16042: NAT alias reverse hit must expect client ISN+1"
    );
    // Bad-ack SYN-ACK on the alias reverse key must not promote.
    assert!(table
        .lookup_with_origin_with_ack(&reverse, now + SEC, TCP_SYN | TCP_ACK, 0, Some(777))
        .is_some());
    assert!(!table.entry_by_key(&reverse).unwrap().established, "#16042: bad-ack promoted NAT pair");
    // Note the real SYN-ACK seq, then the correct ack promotes.
    table.note_tcp_seq(&reverse, SERVER_ISN, CLIENT_ISN + 1, 4096, 0, TCP_SYN | TCP_ACK, 0);
    assert!(table
        .lookup_with_origin_with_ack(&reverse, now + 2 * SEC, TCP_SYN | TCP_ACK, 0, Some(CLIENT_ISN + 1))
        .is_some());
    assert!(table.entry_by_key(&reverse).unwrap().established);
    // Completing ACK on the forward key validates against server ISN.
    assert_eq!(table.handshake_expected_ack(&forward), Some(SERVER_ISN + 1));
    assert!(table
        .lookup_with_origin_with_ack(&forward, now + 3 * SEC, TCP_ACK, 0, Some(5))
        .is_some());
    assert_opening(&table, &forward, "forward");
    assert!(table
        .lookup_with_origin_with_ack(&forward, now + 4 * SEC, TCP_ACK, 0, Some(SERVER_ISN + 1))
        .is_some());
    assert_established(&table, &forward, "forward");
}

// ------------------------------------------- HA import unknown-evidence

#[test]
fn ha_import_unknown_evidence_fails_open_16042() {
    // An HA import carries no ISN (tcp_peer_isn = None on both halves).
    // Its first completing segment — here with ANY ack, because no
    // expectation exists — must still complete (fail-open), never get
    // stuck pending because evidence is unknown.
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    for (key, is_rev) in [(&forward, false), (&reverse_of(&forward), true)] {
        let key = key.clone();
        let mut meta = metadata();
        meta.is_reverse = is_rev;
        assert!(table.upsert_synced_with_origin(
            SessionInstall {
                key,
                decision: decision(),
                metadata: meta,
                source_nat_static: None,
                origin: SessionOrigin::SyncImport,
                now_ns: now,
                protocol: PROTO_TCP,
                tcp_flags: 0,
                session_id: 42,
                tcp_close_class: 0,
                tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
            },
            false,
        ));
    }
    let reverse = reverse_of(&forward);
    assert_eq!(table.handshake_expected_ack(&forward), None, "premise: import has unknown evidence");
    // A completing ACK with an arbitrary ack completes (fail-open).
    assert!(table
        .lookup_with_origin_with_ack(&forward, now + SEC, TCP_ACK | TCP_PSH, 10, Some(0xDEAD_BEEF))
        .is_some());
    assert_established(&table, &forward, "forward");
    assert_established(&table, &reverse, "reverse");
    // And the unparsed-ack (None) form completes too.
    let (mut table2, forward2, reverse2, now2) = syn_pair();
    syn_ack_via_lookup(&mut table2, &reverse2, now2 + SEC, CLIENT_ISN + 1);
    assert!(table2.lookup_with_origin(&forward2, now2 + 2 * SEC, TCP_ACK).is_some());
    assert_established(&table2, &forward2, "forward2");
}

fn reverse_of(forward: &SessionKey) -> SessionKey {
    reverse_session_key(forward, crate::nat::NatDecision::default())
}

// ------------------------------------------------------------- deferred Owner

#[test]
fn bad_ack_deferred_owner_replay_does_not_complete_16042() {
    let (mut table, forward, reverse, now) = syn_pair();
    syn_ack_via_lookup(&mut table, &reverse, now + SEC, CLIENT_ISN + 1);
    // Read-only deferred probe, then Owner replay with a wrong ack.
    let _ = table.lookup_with_origin_deferring_authority_with_ack(&forward, now + 2 * SEC, TCP_ACK, 0, Some(31337));
    table.apply_deferred_owner_hit_with_ack(&forward, now + 2 * SEC, TCP_ACK, 0, Some(31337));
    assert_opening(&table, &forward, "forward");
    table.apply_deferred_owner_hit_with_ack(&forward, now + 3 * SEC, TCP_ACK, 0, Some(SERVER_ISN + 1));
    assert_established(&table, &forward, "forward");
    assert_established(&table, &reverse, "reverse");
}
