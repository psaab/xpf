//! #19173 fold (r24 P3-1): an identical re-import keeps the replaced row's
//! install epoch; a re-import that changes ANY forwarding input, or names
//! another incarnation, mints a new one.
//!
//! The flow-cache seed binds `install_epoch` and the fused probe refuses any
//! other value, so these cells pin `replacement_keeps_incarnation` from both
//! sides at table level: the identical cells keep the epoch (a mutant that
//! never carries reds them), and the table below changes ONE compared input
//! per row and requires a new epoch (a mutant that always carries reds every
//! row; one that drops a field from the compare reds that field's row).
use super::tests::{decision, key_v4, metadata};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_PSH};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

pub(super) const SEC: u64 = 1_000_000_000;
/// The wire session id of the base row (a peer-minted id, nonzero).
pub(super) const WIRE_ID: u64 = (1 << 48) | 19173;

/// The base re-import: an Established TCP peer import with a wire id.
pub(super) fn base(now: u64) -> SessionInstall {
    SessionInstall {
        key: key_v4(),
        decision: decision(),
        metadata: metadata(),
        source_nat_static: None,
        origin: SessionOrigin::SyncImport,
        now_ns: now,
        protocol: PROTO_TCP,
        tcp_flags: TCP_ACK,
        session_id: WIRE_ID,
        tcp_close_class: 0,
        tcp_handshake_state: TcpHandshakeState::Established.to_wire(),
        persistent_lease_hold: None,
        fwd_packets: 10,
        rev_packets: 10,
    }
}

/// What one replacement did to the row's incarnation token.
#[derive(Debug, PartialEq, Eq)]
enum Token {
    Kept,
    Minted,
}

/// Install `prev` (with leak stamp `prev_leak`), let `mark` change the row in
/// place, then re-import `next` (with `next_leak`) and report whether the
/// install epoch survived. Premises: both installs land, and a minted epoch
/// is larger than the one it replaced.
fn replace(
    prev: SessionInstall,
    prev_leak: u64,
    mark: impl FnOnce(&mut SessionTable),
    next: SessionInstall,
    next_leak: u64,
) -> Token {
    let mut table = SessionTable::new();
    let key = prev.key.clone();
    assert!(table.upsert_synced_with_origin_and_leak(prev, true, prev_leak), "prev installs");
    mark(&mut table);
    let before = table.entry_by_key_quiet(&key).expect("prev row").install_epoch;
    assert!(table.upsert_synced_with_origin_and_leak(next, true, next_leak), "next installs");
    let after = table.entry_by_key_quiet(&key).expect("next row").install_epoch;
    assert_ne!(after, PROBE_ANY_INCARNATION);
    assert_eq!(table.leak_incarnation(&key).unwrap_or(0), next_leak, "the install stamps the leak");
    if after == before {
        Token::Kept
    } else {
        assert!(after > before, "a minted epoch is new and larger");
        Token::Minted
    }
}

fn no_mark(_: &mut SessionTable) {}

/// The identical re-import keeps the epoch, reuses the replaced row's slab
/// slot (the #9856 export cursor relies on it: a carried row is the
/// never-replaced row to the export walk) and leaves the table's epoch
/// counter where it was (the export's kick epoch).
#[test]
fn identical_reimport_keeps_the_epoch_and_the_slot_19173() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 10 * SEC;
    assert!(table.upsert_synced_with_origin(base(now), false));
    let epoch = table.entry_by_key_quiet(&key).expect("row").install_epoch;
    let handle = *table.key_to_handle.get(&key).expect("handle");
    let counter = table.current_epoch();
    for n in 1..=5u64 {
        // A liveness frame converts to SyncImport; the counters and the
        // clock move, the flags vary within the same TCP state.
        let mut next = base(now + n * SEC);
        next.origin = SessionOrigin::SyncLiveness;
        next.tcp_flags = if n % 2 == 0 { TCP_ACK } else { TCP_ACK | TCP_PSH };
        next.fwd_packets = 10 + n;
        next.rev_packets = 10 + 2 * n;
        assert!(table.upsert_synced_with_origin(next, false), "re-import {n} installs");
        let row = table.entry_by_key_quiet(&key).expect("row");
        assert_eq!(row.install_epoch, epoch, "re-import {n} keeps the epoch");
        assert_eq!(row.session_id, WIRE_ID);
        assert_eq!(*table.key_to_handle.get(&key).expect("handle"), handle, "re-import {n} slot");
        assert_eq!(table.current_epoch(), counter, "re-import {n} minted nothing");
    }
}

/// A zero wire id (a local-tunnel `UpsertLocal` refresh, a legacy peer)
/// names no incarnation, so an otherwise identical re-import keeps the epoch,
/// even though the row is installed under a fresh node-local session id.
#[test]
fn zero_wire_id_identical_reimport_keeps_the_epoch_19173() {
    let mut prev = base(10 * SEC);
    prev.session_id = 0;
    let mut next = base(11 * SEC);
    next.session_id = 0;
    assert_eq!(replace(prev, 0, no_mark, next, 0), Token::Kept);
}

/// Inputs the compare deliberately ignores keep the epoch too (the
/// classification's "not compared" side): packet counters, the clock,
/// non-closing TCP flags, a known wire id over a stored id it equals, an
/// equal leak stamp, the same bound policy counter.
#[test]
fn non_forwarding_differences_keep_the_epoch_19173() {
    let counter = Arc::new(crate::policy::PolicyRuleCounter::with_rule_id("r19173"));
    let with_counter = |now| {
        let mut install = base(now);
        install.metadata.policy_counter = Some(Arc::clone(&counter));
        install
    };
    let mut next = with_counter(20 * SEC);
    next.tcp_flags = TCP_ACK | TCP_PSH;
    next.fwd_packets = 999;
    next.rev_packets = 777;
    assert_eq!(replace(with_counter(10 * SEC), 7, no_mark, next, 7), Token::Kept);
}

/// One forwarding-relevant change to a re-import.
pub(super) type Change = fn(&mut SessionInstall);

/// THE table's single-field changes: one compared input of the base re-import
/// per row, named by the compared term it exercises. Shared with #19191's
/// `ha_resolution_carry_19191_tests.rs`, which replays every row that is not
/// a resolution field under the HA resolution carry.
pub(super) fn forwarding_input_changes() -> Vec<(&'static str, Change)> {
    vec![
        ("decision.resolution.disposition", |i: &mut SessionInstall| {
            i.decision.resolution.disposition = crate::afxdp::ForwardingDisposition::FabricRedirect
        }),
        ("decision.resolution.egress_ifindex", |i: &mut SessionInstall| i.decision.resolution.egress_ifindex = 13),
        ("decision.resolution.tx_ifindex", |i: &mut SessionInstall| i.decision.resolution.tx_ifindex = 13),
        ("decision.resolution.next_hop", |i: &mut SessionInstall| {
            i.decision.resolution.next_hop = Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 2)))
        }),
        ("decision.resolution.neighbor_mac", |i: &mut SessionInstall| {
            i.decision.resolution.neighbor_mac = Some([0, 1, 2, 3, 4, 6])
        }),
        ("decision.resolution.src_mac", |i: &mut SessionInstall| i.decision.resolution.src_mac = Some([2, 0, 0, 0, 0, 1])),
        ("decision.resolution.tx_vlan_id", |i: &mut SessionInstall| i.decision.resolution.tx_vlan_id = 80),
        ("decision.resolution.tunnel_endpoint_id", |i: &mut SessionInstall| i.decision.resolution.tunnel_endpoint_id = 3),
        ("decision.resolution.route_mtu", |i: &mut SessionInstall| i.decision.resolution.route_mtu = 1400),
        ("decision.nat", |i: &mut SessionInstall| {
            i.decision.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
            i.decision.nat.rewrite_src_port = Some(40000);
        }),
        ("decision.install_table", |i: &mut SessionInstall| {
            let (domain, check) = crate::session::install_table_identity("t19173");
            i.decision.install_table_domain = domain;
            i.decision.install_table_check = check;
        }),
        ("metadata.ingress_zone", |i: &mut SessionInstall| i.metadata.ingress_zone += 100),
        ("metadata.egress_zone", |i: &mut SessionInstall| i.metadata.egress_zone += 100),
        ("metadata.ingress_zone_check", |i: &mut SessionInstall| i.metadata.ingress_zone_check = 0x1917),
        ("metadata.egress_zone_check", |i: &mut SessionInstall| i.metadata.egress_zone_check = 0x1917),
        ("metadata.ingress_ifindex", |i: &mut SessionInstall| i.metadata.ingress_ifindex = 24),
        ("metadata.ingress_vlan_id", |i: &mut SessionInstall| i.metadata.ingress_vlan_id = 50),
        ("metadata.forward_ingress_vlan_id", |i: &mut SessionInstall| i.metadata.forward_ingress_vlan_id = Some(50)),
        ("metadata.nat_scope_ifindex", |i: &mut SessionInstall| i.metadata.nat_scope_ifindex = Some(24)),
        ("metadata.owner_rg_id", |i: &mut SessionInstall| i.metadata.owner_rg_id = 2),
        ("metadata.fabric_ingress", |i: &mut SessionInstall| i.metadata.fabric_ingress = true),
        ("metadata.is_reverse", |i: &mut SessionInstall| i.metadata.is_reverse = true),
        ("metadata.forward_wire_alias_origin", |i: &mut SessionInstall| i.metadata.forward_wire_alias_origin = true),
        ("metadata.log_session_init", |i: &mut SessionInstall| i.metadata.log_session_init = true),
        ("metadata.log_session_close", |i: &mut SessionInstall| i.metadata.log_session_close = true),
        ("metadata.policy_id", |i: &mut SessionInstall| i.metadata.policy_id = 7),
        ("metadata.inactivity_timeout_ns", |i: &mut SessionInstall| i.metadata.inactivity_timeout_ns = Some(30 * SEC)),
        ("metadata.policy_counter_idx", |i: &mut SessionInstall| i.metadata.policy_counter_idx = 3),
        ("metadata.policy_counter", |i: &mut SessionInstall| {
            i.metadata.policy_counter =
                Some(Arc::new(crate::policy::PolicyRuleCounter::with_rule_id("r19173")))
        }),
        ("source_nat_static", |i: &mut SessionInstall| i.source_nat_static = Some(true)),
        ("origin", |i: &mut SessionInstall| i.origin = SessionOrigin::WorkerLocalImport),
        ("identity: another nonzero wire session id", |i: &mut SessionInstall| i.session_id = WIRE_ID + 1),
        ("tcp close class (a FIN in the import's flags)", |i: &mut SessionInstall| i.tcp_flags = TCP_ACK | TCP_FIN),
        ("tcp close class (a stated wire close class)", |i: &mut SessionInstall| {
            i.tcp_close_class = TcpCloseClass::TimeWait.to_wire()
        }),
    ]
}

/// THE table: change one forwarding-relevant input per row; every row must
/// mint a new epoch. Each row names the compared term it exercises, so a
/// mutant that drops that term from `replacement_keeps_incarnation` reds the
/// row with its name.
#[test]
fn any_forwarding_input_change_mints_a_new_epoch_19173() {
    let now = 10 * SEC;
    let v6 = |s: &str| s.parse::<Ipv6Addr>().expect("v6");
    let rows = forwarding_input_changes();
    let mut kept = Vec::new();
    let mut checked = 0usize;
    for (name, change) in &rows {
        let mut next = base(now + SEC);
        change(&mut next);
        checked += 1;
        if replace(base(now), 0, no_mark, next, 0) != Token::Minted {
            kept.push(*name);
        }
    }
    // metadata.nat64_reverse: a closure cannot build the v6 pair above.
    let mut next = base(now + SEC);
    next.metadata.nat64_reverse = Some(crate::nat64::Nat64ReverseInfo {
        orig_src_v6: v6("2001:db8::1"),
        orig_dst_v6: v6("64:ff9b::808:808"),
    });
    checked += 1;
    if replace(base(now), 0, no_mark, next, 0) != Token::Minted {
        kept.push("metadata.nat64_reverse");
    }
    // The bound policy counter is compared by identity: an equal-content
    // counter that is another Arc is another binding.
    let mut prev = base(now);
    prev.metadata.policy_counter =
        Some(Arc::new(crate::policy::PolicyRuleCounter::with_rule_id("r19173")));
    let mut next = base(now + SEC);
    next.metadata.policy_counter =
        Some(Arc::new(crate::policy::PolicyRuleCounter::with_rule_id("r19173")));
    checked += 1;
    if replace(prev, 0, no_mark, next, 0) != Token::Minted {
        kept.push("metadata.policy_counter (another Arc)");
    }
    // The #9951 leak incarnation the row carries: changed, gained, lost.
    for (name, prev_leak, next_leak) in [
        ("leak incarnation changed", 5u64, 6u64),
        ("leak incarnation gained", 0, 6),
        ("leak incarnation lost", 5, 0),
    ] {
        checked += 1;
        if replace(base(now), prev_leak, no_mark, base(now + SEC), next_leak) != Token::Minted {
            kept.push(name);
        }
    }
    // The #16217 adoption mark: a replacement never carries it.
    let adopted = |table: &mut SessionTable| {
        table.entry_by_key_mut(&key_v4()).expect("row").fabric_established = true;
    };
    checked += 1;
    if replace(base(now), 0, adopted, base(now + SEC), 0) != Token::Minted {
        kept.push("fabric_established");
    }
    // The TCP handshake stage: a pending row the peer now states Established.
    let mut prev = base(now);
    prev.tcp_handshake_state = TcpHandshakeState::HandshakePending.to_wire();
    checked += 1;
    if replace(prev, 0, no_mark, base(now + SEC), 0) != Token::Minted {
        kept.push("tcp handshake stage");
    }
    assert!(
        kept.is_empty(),
        "#19173: these forwarding-input changes kept the replaced row's install \
         epoch, so a cache entry seeded from the old row would keep hitting: {kept:?}"
    );
    // Anti-vacuity: every case above ran (34 table rows, nat64_reverse, the
    // second counter Arc, three leak cases, the adoption mark, the stage).
    assert_eq!((rows.len(), checked), (34, 41));
}

/// The local install path never carries: a local re-install over a synced
/// row, identical decision and metadata, is a new incarnation.
#[test]
fn local_reinstall_always_mints_19173() {
    let mut table = SessionTable::new();
    let key = key_v4();
    assert!(table.upsert_synced_with_origin(base(10 * SEC), false));
    let before = table.entry_by_key_quiet(&key).expect("row").install_epoch;
    assert!(table.install_with_protocol(key.clone(), decision(), metadata(), 11 * SEC, PROTO_TCP, TCP_ACK));
    let after = table.entry_by_key_quiet(&key).expect("row").install_epoch;
    assert!(after > before, "a local install mints: {before} -> {after}");
}
