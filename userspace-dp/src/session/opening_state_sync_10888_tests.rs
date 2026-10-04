//! #10888: OPENING and handshake-pending are session state, not a local-only
//! timeout hint. They must cross sync independently of `tcp_flags` (which is
//! deliberately zero on the production import path), and a lost Close must not
//! extend an opening import beyond its original opening deadline.

use super::*;
use crate::SessionSyncRequest;
use crate::server::helpers::build_synced_session_entry;
use crate::test_zone_ids::*;

const SEC: u64 = 1_000_000_000;
const OPENING_SECS: u64 = 20;
const APP_TIMEOUT_SECS: u32 = 86_400;
const OWNER_RG: i32 = 1;

fn synced_record(tcp_handshake_state: u8, tcp_close_class: u8) -> SessionSyncRequest {
    let base = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "8.8.8.8".to_string(),
        src_port: 12345,
        dst_port: 443,
        ingress_zone_id: TEST_TRUST_ZONE_ID,
        egress_zone_id: TEST_UNTRUST_ZONE_ID,
        owner_rg_id: OWNER_RG,
        inactivity_timeout: APP_TIMEOUT_SECS,
        tcp_close_class,
        ..SessionSyncRequest::default()
    };
    let mut value = serde_json::to_value(base).expect("FIXTURE: serialize request");
    value["tcp_handshake_state"] = serde_json::json!(tcp_handshake_state);
    serde_json::from_value(value).expect("FIXTURE: deserialize request")
}

fn import(table: &mut SessionTable, request: &SessionSyncRequest, now_ns: u64) -> SessionKey {
    let zones = rustc_hash::FxHashMap::default();
    let entry = build_synced_session_entry(request, &zones, 0).expect("FIXTURE: import request");
    let key = entry.key.clone();
    assert!(
        table.upsert_synced_with_origin(entry.into_session_install(now_ns), false),
        "FIXTURE: synced upsert"
    );
    key
}

fn expire_as_standby(table: &mut SessionTable, now_ns: u64) -> Vec<ExpiredSession> {
    let forwards = |_rg: i32| false;
    let epoch = |_rg: i32| 0;
    let ha = ExpireHaContext {
        node_active: true,
        forwards_rg: &forwards,
        epoch_of: &epoch,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
    };
    table.last_gc_ns = 0;
    table.expire_stale_entries_ha(now_ns, Some(&ha))
}

#[test]
fn synced_opening_uses_opening_window_and_reaps_lost_close_at_deadline_10888() {
    let mut table = SessionTable::new();
    let installed_at = 10 * SEC;
    let key = import(&mut table, &synced_record(1, 0), installed_at);
    let entry = table.entry_by_key(&key).expect("imported session");

    assert_eq!(
        entry.expires_after_ns,
        OPENING_SECS * SEC,
        "#10888: a synced OPENING TCP entry must ignore its 86400s app timeout"
    );
    assert!(
        !entry.established && !entry.handshake_pending,
        "#10888: the imported OPENING state was erased"
    );

    // Let the expiry wheel reach its first scan tick after the deadline. A
    // suppressed primary Close cannot turn the opening timeout into a second
    // lifetime based on the app timeout or standby stale ceiling.
    let opening_deadline = installed_at + OPENING_SECS * SEC;
    let first_due_sweep = opening_deadline + WHEEL_TICK_NS_FOR_TEST + 1;
    let expired = expire_as_standby(&mut table, first_due_sweep);
    assert!(
        expired.iter().any(|entry| entry.key == key),
        "#10888: a lost-Close opening must reap at its first due wheel scan"
    );
}

#[test]
fn syn_ack_first_pending_import_preserves_reverse_ack_gate_10888() {
    let mut table = SessionTable::new();
    let key = import(&mut table, &synced_record(3, 0), 10 * SEC);
    let entry = table.entry_by_key(&key).expect("imported SYN-ACK-first session");
    assert!(!entry.established);
    assert!(entry.handshake_pending);
    assert!(entry.syn_ack_first);
    assert_eq!(entry.expires_after_ns, OPENING_SECS * SEC);
    assert_eq!(table.handshake_state_wire_for(&key), 3);
}

#[test]
fn delivered_close_still_uses_its_tcp_close_window_10888() {
    let mut table = SessionTable::new();
    let installed_at = 10 * SEC;
    let key = import(&mut table, &synced_record(1, 1), installed_at);
    let entry = table.entry_by_key(&key).expect("imported closing session");
    assert!(
        entry.closing,
        "FIXTURE: delivered Close class did not install"
    );
    assert_eq!(
        entry.expires_after_ns, table.timeouts.tcp_closing_ns,
        "#10888: OPENING state must not override a delivered Close class"
    );
}

#[test]
fn legacy_sync_without_handshake_state_keeps_established_behavior_10888() {
    let mut value = serde_json::to_value(synced_record(0, 0)).expect("FIXTURE: serialize request");
    value.as_object_mut().unwrap().remove("tcp_handshake_state");
    let request = serde_json::from_value(value).expect("FIXTURE: deserialize legacy request");
    let mut table = SessionTable::new();
    let key = import(&mut table, &request, 10 * SEC);
    let entry = table.entry_by_key(&key).expect("imported session");
    assert!(entry.established && !entry.handshake_pending);
    assert_eq!(
        entry.expires_after_ns,
        APP_TIMEOUT_SECS as u64 * SEC,
        "a legacy state-less peer must retain today's established/app timeout behavior"
    );
}
