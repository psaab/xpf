//! #17058: `SyncedSessionEntry` construction from a live table row is
//! single-sourced in `SessionTable::synced_entry_for`. The probe and
//! promote paths that used to hand-build the literal (zero-filling
//! `source_nat_static`, close/handshake state, counters, PPTP pair and
//! lease hold) now route through it, so a field added to the entry
//! cannot be silently dropped by a call-site literal.

use crate::session::tests::{decision, key_v4, metadata};
use crate::session::{SessionOrigin, SessionTable};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn synced_entry_for_carries_live_wire_fields_17058() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let mut dec = decision();
    dec.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
    dec.nat.rewrite_src_port = Some(45_000);
    assert!(table.install_with_protocol_with_origin_and_source_nat(
        key.clone(),
        dec,
        metadata(),
        SessionOrigin::ForwardFlow,
        1_000_000_000,
        crate::ip_proto::PROTO_TCP,
        0x10,
        Some(true),
    ));
    table.account_packet(&key, 100, 0x10, 0);
    table.account_packet(&key, 100, 0x10, 0);

    let entry = table
        .synced_entry_for(&key)
        .expect("live row yields a synced entry");
    assert_eq!(entry.key, key);
    assert_eq!(entry.source_nat_static, Some(true));
    assert_eq!(entry.origin, SessionOrigin::ForwardFlow);
    assert_eq!(entry.protocol, key.protocol);
    assert_eq!(entry.tcp_flags, 0);
    assert_eq!(entry.generation, 0);
    assert_ne!(entry.session_id, 0, "live session id carried, not zeroed");
    assert_eq!(entry.session_id, table.session_id_for(&key));
    assert_eq!(entry.fwd_packets, 2, "live forward counter carried");
    assert_eq!(entry.rev_packets, 0);
    assert_eq!(entry.tcp_close_class, table.close_class_wire_for(&key));
    assert_eq!(
        entry.tcp_handshake_state,
        table.handshake_state_wire_for(&key)
    );
    assert_eq!(entry.pptp_call_ids, table.pptp_call_ids_wire_for(&key));
    assert_eq!(
        entry.persistent_lease_hold,
        table.persistent_lease_hold_for(&key)
    );
    assert_eq!(
        entry.leak_incarnation,
        table.leak_incarnation(&key).unwrap_or(0)
    );
}

#[test]
fn synced_entry_for_absent_key_is_none_17058() {
    let table = SessionTable::new();
    assert!(table.synced_entry_for(&key_v4()).is_none());
}

#[test]
fn synced_entry_for_dynamic_snat_is_some_false_17058() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let mut dec = decision();
    dec.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)));
    assert!(table.install_with_protocol_with_origin_and_source_nat(
        key.clone(),
        dec,
        metadata(),
        SessionOrigin::ForwardFlow,
        1_000_000_000,
        crate::ip_proto::PROTO_TCP,
        0x10,
        Some(false),
    ));
    let entry = table.synced_entry_for(&key).expect("live row");
    assert_eq!(
        entry.source_nat_static,
        Some(false),
        "dynamic SNAT provenance is Some(false), distinguishable from unknown None"
    );
}
