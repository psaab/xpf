//! #14945: `probe_hit` must be a semantic fusion of the three probes it
//! replaces on the flow-cache hit path — `session_is_live_at` (liveness),
//! `touch_if_stale_with_payload` (throttled keepalive, #14939 handshake
//! completion, #14935/#10885 closing gates) and `account_packet`
//! (#2501/#2749 counters + observed fields) — performed under ONE
//! `record_by_key_mut` borrow.
//!
//! Each cell drives the fused probe and the unfused sequence over two
//! identically-seeded tables and asserts the observable session state is
//! identical: return value, per-direction counters, observed ToS / TCP
//! flags, `last_seen_ns`, handshake/closing state, and the established
//! window. A fusion that dropped the closing gate, the completion arm,
//! the throttle, or the reverse fold would diverge on at least one cell.
//!
//! Loaded as a sibling submodule via `#[path]` from session/mod.rs.

use super::tests::{decision, install_forward_reverse_pair, key_v4, metadata};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};

const SEC: u64 = 1_000_000_000;

/// Snapshot of everything the fused probe is allowed to move, read back
/// through the same accessors the hit-path tests use.
#[derive(Debug, PartialEq)]
struct ProbeSnapshot {
    counters: Option<SessionCounters>,
    observed: Option<(u8, u8)>,
    last_seen_ns: Option<u64>,
    established: Option<bool>,
    handshake_pending: Option<bool>,
    syn_ack_first: Option<bool>,
    closing: Option<bool>,
    expires_after_ns: Option<u64>,
}

fn snapshot(table: &SessionTable, key: &SessionKey) -> ProbeSnapshot {
    let entry = table.entry_by_key(key);
    ProbeSnapshot {
        counters: table.session_counters(key),
        observed: table.observed_close_fields(key),
        last_seen_ns: table.last_seen_ns(key),
        established: entry.map(|e| e.established),
        handshake_pending: entry.map(|e| e.handshake_pending),
        syn_ack_first: entry.map(|e| e.syn_ack_first),
        closing: entry.map(|e| e.closing),
        expires_after_ns: entry.map(|e| e.expires_after_ns),
    }
}

/// The unfused sequence, in the exact order the pre-#14945 hit path ran
/// it (liveness, then keepalive, then accounting) — the oracle.
fn unfused_hit(
    table: &mut SessionTable,
    key: &SessionKey,
    now_ns: u64,
    len: u64,
    tcp_flags: u8,
    payload_len: u32,
    dscp: u8,
) -> bool {
    if !table.session_is_live_at(key, now_ns) {
        return false;
    }
    if !table.touch_if_stale_with_payload(key, now_ns, tcp_flags, payload_len) {
        return false;
    }
    table.account_packet(key, len, tcp_flags, dscp);
    true
}

fn assert_equivalent(
    label: &str,
    fused: &mut SessionTable,
    oracle: &mut SessionTable,
    keys: &[&SessionKey],
    now_ns: u64,
    len: u64,
    tcp_flags: u8,
    payload_len: u32,
    dscp: u8,
    probe_key: &SessionKey,
) {
    let fused_ok = fused.probe_hit(probe_key, now_ns, len, tcp_flags, payload_len, dscp);
    let oracle_ok = unfused_hit(oracle, probe_key, now_ns, len, tcp_flags, payload_len, dscp);
    assert_eq!(fused_ok, oracle_ok, "{label}: probe_hit return diverged");
    for key in keys {
        assert_eq!(
            snapshot(fused, key),
            snapshot(oracle, key),
            "{label}: session state diverged for {key:?}"
        );
    }
}

fn pair_table() -> (SessionTable, SessionKey, SessionKey, u64) {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);
    (table, forward, reverse, now)
}

/// Forward established flow: fresh (inside the throttle window), stale
/// (past the quarter-timeout), and reverse-direction packets all fuse
/// identically — counters, observed fields, and refresh timing.
#[test]
fn probe_hit_matches_unfused_sequence_forward_and_reverse_14945() {
    let (mut fused, forward, reverse, now) = pair_table();
    let (mut oracle, _, _, _) = pair_table();

    // Fresh: inside the keepalive throttle — no re-stamp, still charged.
    assert_equivalent(
        "fresh-forward",
        &mut fused,
        &mut oracle,
        &[&forward, &reverse],
        now + SEC,
        1500,
        TCP_ACK | TCP_PSH,
        512,
        46,
        &forward,
    );
    // Stale: past expires/4 — the keepalive re-stamps under the probe.
    let stale_ns = now + 200 * SEC;
    assert_equivalent(
        "stale-forward",
        &mut fused,
        &mut oracle,
        &[&forward, &reverse],
        stale_ns,
        900,
        TCP_ACK,
        0,
        10,
        &forward,
    );
    // Reverse packet: folds onto the forward entry's rev counters, keeps
    // the forward ToS, ORs its TCP flags.
    assert_equivalent(
        "reverse",
        &mut fused,
        &mut oracle,
        &[&forward, &reverse],
        stale_ns + SEC,
        700,
        TCP_ACK | TCP_PSH,
        128,
        63,
        &reverse,
    );
    let counters = fused
        .session_counters(&forward)
        .expect("forward entry survives");
    assert_eq!(counters.fwd_packets, 2, "both forward packets charged once");
    assert_eq!(counters.fwd_bytes, 2400);
    assert_eq!(
        counters.rev_packets, 1,
        "reverse packet folded onto forward"
    );
    assert_eq!(counters.rev_bytes, 700);
}

/// Absent and idle-crossed keys refuse identically and move nothing.
#[test]
fn probe_hit_refuses_absent_and_expired_like_unfused_14945() {
    let (mut fused, forward, reverse, now) = pair_table();
    let (mut oracle, _, _, _) = pair_table();

    let missing = SessionKey {
        src_port: 9999,
        ..forward.clone()
    };
    assert_equivalent(
        "absent",
        &mut fused,
        &mut oracle,
        &[&forward, &reverse],
        now + SEC,
        100,
        TCP_ACK,
        0,
        0,
        &missing,
    );

    // Idle-crossed: install + 1900 s with no traffic crosses the 1800 s (#15127)
    // established window.
    assert_equivalent(
        "expired",
        &mut fused,
        &mut oracle,
        &[&forward, &reverse],
        now + 1900 * SEC,
        100,
        TCP_ACK,
        0,
        0,
        &forward,
    );
    assert_eq!(
        fused.session_counters(&forward).map(|c| c.fwd_packets),
        Some(0),
        "an idle-crossed probe must not charge the session"
    );
}

/// #14939: a completing ACK consumed by the fused probe promotes BOTH
/// halves exactly as the unfused keepalive does.
#[test]
fn probe_hit_completes_pending_handshake_like_unfused_14945() {
    let build = || {
        let mut table = SessionTable::new();
        let forward = key_v4();
        let now = 1_000_000_000u64;
        let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
        assert!(
            table
                .lookup_with_origin(&reverse, now + SEC, TCP_SYN | TCP_ACK)
                .is_some()
        );
        (table, forward, reverse, now + SEC)
    };
    let (mut fused, forward, reverse, synack_ns) = build();
    let (mut oracle, _, _, _) = build();

    assert_equivalent(
        "completing-ack",
        &mut fused,
        &mut oracle,
        &[&forward, &reverse],
        synack_ns + SEC,
        512,
        TCP_ACK | TCP_PSH,
        512,
        46,
        &forward,
    );
    for (label, key) in [("forward", &forward), ("reverse", &reverse)] {
        let entry = fused.entry_by_key(key).expect("half after completion");
        assert!(
            entry.established && !entry.handshake_pending && !entry.syn_ack_first,
            "{label}: fused probe must complete the handshake (#14939)"
        );
        assert_eq!(entry.expires_after_ns, fused.timeouts.tcp_established_ns);
    }
}

/// #14935/#10885: closing gates survive the fusion — an RST-aborted entry
/// is served (live) but never re-stamped; a FIN-owning direction with
/// payload progress re-stamps, matching the unfused keepalive.
#[test]
fn probe_hit_preserves_closing_gates_like_unfused_14945() {
    // RST-aborted pair.
    let build_rst = || {
        let (mut table, forward, reverse, now) = pair_table();
        assert!(table.lookup(&forward, now + SEC, TCP_RST).is_some());
        (table, forward, reverse, now + SEC)
    };
    let (mut fused, forward, reverse, rst_ns) = build_rst();
    let (mut oracle, _, _, _) = build_rst();
    assert_equivalent(
        "rst-hit",
        &mut fused,
        &mut oracle,
        &[&forward, &reverse],
        rst_ns + SEC,
        100,
        TCP_ACK,
        0,
        0,
        &forward,
    );
    assert_eq!(
        fused.last_seen_ns(&forward),
        Some(rst_ns),
        "an RST-aborted entry must not slide under the fused probe"
    );

    // Single-FIN half-close: payload from the FIN-owning direction is
    // progress (#14935); a bare ACK from the same direction is not.
    let build_fin = || {
        let (mut table, forward, reverse, now) = pair_table();
        assert!(
            table
                .lookup(&forward, now + SEC, TCP_FIN | TCP_ACK)
                .is_some()
        );
        (table, forward, reverse, now + SEC)
    };
    let (mut fused, forward, reverse, fin_ns) = build_fin();
    let (mut oracle, _, _, _) = build_fin();
    assert_equivalent(
        "fin-bare-ack",
        &mut fused,
        &mut oracle,
        &[&forward, &reverse],
        fin_ns + 2 * SEC,
        100,
        TCP_ACK,
        0,
        0,
        &forward,
    );
    assert_equivalent(
        "fin-payload",
        &mut fused,
        &mut oracle,
        &[&forward, &reverse],
        fin_ns + 3 * SEC,
        600,
        TCP_ACK | TCP_PSH,
        400,
        0,
        &forward,
    );
}

/// Translated reverse alias: a packet keyed by the reverse entry's
/// translated wire tuple resolves through the alias index under the same
/// single borrow and folds onto the forward entry.
#[test]
fn probe_hit_reverse_alias_folds_like_unfused_14945() {
    let build = || {
        let mut table = SessionTable::new();
        let now = 1_000_000_000u64;
        let fwd = key_v4();
        let nat = crate::nat::NatDecision {
            rewrite_src: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                203, 0, 113, 1,
            ))),
            rewrite_src_port: Some(40001),
            ..crate::nat::NatDecision::default()
        };
        let fwd_decision = SessionDecision {
            resolution: decision().resolution,
            nat,
            install_table_domain: 0,
            install_table_check: 0,
        };
        assert!(table.install_with_protocol(
            fwd.clone(),
            fwd_decision,
            metadata(),
            now,
            PROTO_TCP,
            TCP_ACK
        ));
        let rev = reverse_session_key(&fwd, nat);
        let rev_nat = nat.reverse(fwd.src_ip, fwd.dst_ip, fwd.src_port, fwd.dst_port);
        let rev_decision = SessionDecision {
            resolution: decision().resolution,
            nat: rev_nat,
            install_table_domain: 0,
            install_table_check: 0,
        };
        let mut rev_metadata = metadata();
        rev_metadata.is_reverse = true;
        assert!(table.install_with_protocol(
            rev.clone(),
            rev_decision,
            rev_metadata,
            now,
            PROTO_TCP,
            TCP_ACK
        ));
        (table, fwd, rev, now)
    };
    let (mut fused, forward, reverse, now) = build();
    let (mut oracle, _, _, _) = build();
    assert_equivalent(
        "translated-reverse",
        &mut fused,
        &mut oracle,
        &[&forward, &reverse],
        now + SEC,
        800,
        TCP_ACK | TCP_PSH,
        200,
        20,
        &reverse,
    );
    assert_eq!(
        fused
            .session_counters(&forward)
            .map(|c| (c.rev_packets, c.rev_bytes)),
        Some((1, 800)),
        "translated reverse packet must fold onto the forward entry"
    );
}
