//! #17058: the policy-delete probe (`handle_probe_policy_tuples`) and the
//! conntrack provenance flags. The probe used to hand-build its survivor
//! with `source_nat_static: None`; `repair_policy_bares` republishes the
//! mirror from that entry, so a static-SNAT survivor lost
//! `SESS_FLAG_STATIC_NAT | SESS_FLAG_SNAT_PROVENANCE_KNOWN`. These cells
//! pin the shared construction and the flag mapping it feeds.

use super::*;
use super::commands::handle_probe_policy_tuples;
use crate::afxdp::testfx::{test_key, test_metadata, test_resolution};
use std::net::{IpAddr, Ipv4Addr};

fn static_snat_table() -> (SessionTable, SessionKey) {
    let key = test_key();
    let mut dec = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    dec.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
    dec.nat.rewrite_src_port = Some(45_000);
    let mut table = SessionTable::new();
    assert!(table.install_with_protocol_with_origin_and_source_nat(
        key.clone(),
        dec,
        test_metadata(),
        SessionOrigin::ForwardFlow,
        1_000_000_000,
        crate::ip_proto::PROTO_TCP,
        0x10,
        Some(true),
    ));
    (table, key)
}

#[test]
fn probe_policy_tuples_carries_static_snat_provenance_17058() {
    let (table, key) = static_snat_table();
    let bare = key.clone();
    let found = std::sync::Mutex::new(vec![None]);
    handle_probe_policy_tuples(&table, &[bare], &found);
    let slots = found.lock().unwrap();
    let entry = slots[0]
        .as_ref()
        .expect("probe must find the live survivor under its bare tuple");
    assert_eq!(
        entry.source_nat_static,
        Some(true),
        "probe survivor must carry the live static-SNAT provenance, not None"
    );
    assert_eq!(entry.key, key);
    assert_ne!(entry.session_id, 0);
}

#[test]
fn probe_policy_tuples_dynamic_snat_is_some_false_17058() {
    let key = test_key();
    let mut dec = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    dec.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)));
    let mut table = SessionTable::new();
    assert!(table.install_with_protocol_with_origin_and_source_nat(
        key.clone(),
        dec,
        test_metadata(),
        SessionOrigin::ForwardFlow,
        1_000_000_000,
        crate::ip_proto::PROTO_TCP,
        0x10,
        Some(false),
    ));
    let found = std::sync::Mutex::new(vec![None]);
    handle_probe_policy_tuples(&table, &[key.clone()], &found);
    let slots = found.lock().unwrap();
    assert_eq!(
        slots[0].as_ref().map(|e| e.source_nat_static),
        Some(Some(false))
    );
}

#[test]
fn probe_policy_tuples_structure_no_handbuilt_literal_17058() {
    let src = include_str!("commands/delete_synced.rs");
    assert!(
        !src.contains("source_nat_static: None"),
        "probe must not hand-build a SyncedSessionEntry with zeroed provenance"
    );
    assert!(
        !src.contains("SyncedSessionEntry {"),
        "probe must route through SessionTable::synced_entry_for, not a literal"
    );
    assert!(
        src.contains("synced_entry_for"),
        "probe must call the shared construction"
    );
    let promote = include_str!("promote.rs");
    assert!(
        !promote.contains("SyncedSessionEntry {"),
        "promote must route through SessionTable::synced_entry_for, not a literal"
    );
    assert!(promote.contains("synced_entry_for"));
    let resolve = include_str!("resolve.rs");
    assert!(
        resolve.contains("into_session_install"),
        "materialize must build its install via into_session_install"
    );
}
