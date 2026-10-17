// #14630 (Y25-01): a bare ACK after a RST must not complete the handshake
// gate and re-arm the reset reverse half onto the 300 s established window.
//
// Sequence: SYN, reverse SYN-ACK (handshake_pending on both halves), RST
// (both halves closing+reset on TCP_RST_TIMEOUT_NS, handshake_pending left
// set), then a bare forward ACK. Pre-fix, `handshake_completed` consulted
// only packet flags + `handshake_pending` — not `entry.closing`/`reset` —
// so the ACK cleared pending on the forward half (which stayed on the 2 s
// window via its closing branch) and `propagate_tcp_state_to_companion`
// unconditionally re-stamped the reverse companion onto
// `session_timeout_ns(..., true, ...)` (300 s / app override). The forward
// half then reaped at RST+2 s while the reverse half survived as an
// uncounted orphan (per-source counting charges only the forward half):
// `show security flow session` listed a reverse-only row that still
// admitted server->client hits for up to 5 minutes.
//
// The Reset contract (TcpCloseClass::Reset, #3046/#10885): once a RST is
// seen both halves reap on the 2 s abort window and the reset is sticky —
// a later graceful segment cannot promote the entry back to a longer
// window. Handshake completion on a closing entry is exactly such a
// promotion, so all three completion sites (lookup, update_session, and
// the companion mirror) must refuse it.
//
// Loaded as a sibling submodule via `#[path]` from session/mod.rs.

use super::tests::{install_forward_reverse_pair, key_v4, metadata};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_RST, TCP_SYN};

const SEC: u64 = 1_000_000_000;

/// Drive SYN -> SYN-ACK -> RST on a fresh pair and assert the shared
/// premise: both halves closing+reset on the RST window, still pending.
fn pair_after_rst(table: &mut SessionTable) -> (SessionKey, SessionKey, u64) {
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(table, &forward, now, TCP_SYN);
    assert!(
        table
            .lookup(&reverse, now + 1_000_000, TCP_SYN | TCP_ACK)
            .is_some(),
        "premise: reverse SYN-ACK hits"
    );
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("half after SYN-ACK");
        assert!(
            e.established && e.handshake_pending,
            "{label}: premise SYN-ACK promotes but leaves handshake pending"
        );
    }
    let rst_ns = now + 2_000_000;
    assert!(
        table.lookup(&forward, rst_ns, TCP_RST).is_some(),
        "premise: forward RST hits"
    );
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("half after RST");
        assert!(e.closing && e.reset, "{label}: RST stamps closing+reset");
        assert_eq!(
            e.expires_after_ns, TCP_RST_TIMEOUT_NS,
            "{label}: RST puts the half on the 2s abort window"
        );
        assert!(
            e.handshake_pending,
            "{label}: premise — stamp_tcp_close does not clear handshake_pending"
        );
    }
    (forward, reverse, rst_ns)
}

#[test]
fn rst_then_bare_ack_does_not_complete_handshake_14630() {
    let mut table = SessionTable::new();
    let (forward, reverse, rst_ns) = pair_after_rst(&mut table);
    assert_eq!(
        table.session_limit_src_count(metadata().ingress_zone, forward.src_ip),
        1,
        "premise: the pair counts as one logical (forward) session"
    );

    // The bare ACK that crosses the RST.
    let ack_ns = rst_ns + 1_000_000;
    assert!(
        table.lookup(&forward, ack_ns, TCP_ACK).is_some(),
        "the post-RST ACK still hits in-window (forwarding is not gated)"
    );
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("half after post-RST ACK");
        assert!(e.closing && e.reset, "{label}: reset stays sticky");
        assert!(
            e.handshake_pending,
            "#14630: a bare ACK after RST must not complete the handshake on the {label} half"
        );
        assert_eq!(
            e.expires_after_ns, TCP_RST_TIMEOUT_NS,
            "#14630: {label} half must stay on the 2s RST window, not the 300s established window"
        );
        assert_eq!(
            e.last_seen_ns, rst_ns,
            "#14630: {label} half must not be re-stamped by the post-RST ACK (#10885)"
        );
    }

    // Both halves reap together at RST+3s; no orphan reverse row remains.
    let reap_ns = rst_ns + 3 * SEC;
    table.last_gc_ns = reap_ns - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(reap_ns);
    assert_eq!(
        expired.len(),
        2,
        "#14630: both reset halves must reap at RST+3s (expired==2), got {expired:?}"
    );
    assert_eq!(table.len(), 0, "#14630: no orphan reverse row survives");
    assert!(
        table.lookup(&reverse, reap_ns, TCP_ACK).is_none(),
        "#14630: the orphan reverse row must not admit late server->client hits"
    );
    assert_eq!(
        table.session_limit_src_count(metadata().ingress_zone, forward.src_ip),
        0,
        "source count returns to zero once both halves reap"
    );
}

/// SYN-ACK-first variant: the completing segment is a bare ACK on the
/// reverse half (`promote_from_asymmetric_ack`). A RST first must close
/// that gate too.
#[test]
fn rst_then_reverse_ack_does_not_complete_syn_ack_first_14630() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN | TCP_ACK);
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("SYN-ACK-first half");
        assert!(
            !e.established && e.handshake_pending && e.syn_ack_first,
            "{label}: premise SYN-ACK-first pending"
        );
    }
    let rst_ns = now + 1_000_000;
    assert!(table.lookup(&forward, rst_ns, TCP_RST).is_some());
    let ack_ns = rst_ns + 1_000_000;
    assert!(table.lookup(&reverse, ack_ns, TCP_ACK).is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("half after post-RST reverse ACK");
        assert!(e.closing && e.reset, "{label}: reset stays sticky");
        assert!(
            e.handshake_pending && e.syn_ack_first,
            "#14630: post-RST reverse ACK must not complete a SYN-ACK-first handshake ({label})"
        );
        assert_eq!(
            e.expires_after_ns, TCP_RST_TIMEOUT_NS,
            "#14630: {label} half stays on the RST window"
        );
    }
    let reap_ns = rst_ns + 3 * SEC;
    table.last_gc_ns = reap_ns - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(reap_ns);
    assert_eq!(expired.len(), 2, "#14630: both halves reap at RST+3s");
    assert_eq!(table.len(), 0);
}

/// HA twin: `update_session` carries real TCP flags on the shared-promote
/// path, so the same RST-then-ACK sequence must not complete there either.
/// Pre-fix the updated half itself stayed on the close window (its
/// `closing` branch), but the companion mirror re-armed the sibling half
/// onto the established window — the same orphan, one node removed.
#[test]
fn update_session_rst_then_ack_does_not_complete_handshake_14630() {
    let mut table = SessionTable::new();
    let (forward, reverse, rst_ns) = pair_after_rst(&mut table);

    let ack_ns = rst_ns + 1_000_000;
    assert!(table.update_session(
        SessionUpdate {
            key: &forward,
            decision: super::tests::decision(),
            metadata: metadata(),
            origin: SessionOrigin::ForwardFlow,
            now_ns: ack_ns,
            protocol: PROTO_TCP,
            tcp_flags: TCP_ACK,
        },
        false
    ));
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("half after update_session ACK");
        assert!(e.closing && e.reset, "{label}: reset stays sticky");
        assert!(
            e.handshake_pending,
            "#14630: update_session ACK after RST must not complete the handshake ({label})"
        );
        assert_eq!(
            e.expires_after_ns, TCP_RST_TIMEOUT_NS,
            "#14630: update_session must keep the {label} half on the RST window"
        );
    }
    let reap_ns = rst_ns + 3 * SEC;
    table.last_gc_ns = reap_ns - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(reap_ns);
    assert_eq!(expired.len(), 2, "#14630: both halves reap at RST+3s");
    assert_eq!(table.len(), 0);
}

/// FIN variant of the same gate: a FIN stamps `closing` without `reset`,
/// and the completing ACK must not promote either half off the close
/// window. (The forward half was already saved by its own closing branch
/// pre-fix; the companion was re-armed to 300 s.)
#[test]
fn fin_then_bare_ack_does_not_complete_handshake_14630() {
    use crate::tcp_flags::TCP_FIN;
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    assert!(
        table
            .lookup(&reverse, now + 1_000_000, TCP_SYN | TCP_ACK)
            .is_some()
    );
    let fin_ns = now + 2_000_000;
    assert!(table.lookup(&forward, fin_ns, TCP_FIN).is_some());
    let ack_ns = fin_ns + 1_000_000;
    assert!(table.lookup(&forward, ack_ns, TCP_ACK).is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("half after FIN+ACK");
        assert!(e.closing && !e.reset, "{label}: FIN close, not reset");
        assert!(
            e.handshake_pending,
            "#14630: an ACK after FIN must not complete the handshake ({label})"
        );
        assert_eq!(
            e.expires_after_ns, table.timeouts.tcp_closing_ns,
            "#14630: {label} half stays on the FIN close window"
        );
    }
}

/// Control: without any close, the identical SYN / SYN-ACK / bare-ACK
/// sequence still completes and earns the established window on both
/// halves (the fix must not break the normal handshake).
#[test]
fn bare_ack_without_close_still_completes_handshake_14630() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    assert!(
        table
            .lookup(&reverse, now + 1_000_000, TCP_SYN | TCP_ACK)
            .is_some()
    );
    assert!(table.lookup(&forward, now + 2_000_000, TCP_ACK).is_some());
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let e = table.entry_by_key(key).expect("completed half");
        assert!(
            e.established && !e.handshake_pending && !e.closing,
            "{label}: control handshake completes"
        );
        assert_eq!(
            e.expires_after_ns, table.timeouts.tcp_established_ns,
            "{label}: control earns the established window"
        );
    }
}
