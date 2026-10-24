//! #16218: a peer-synced row that is still opening/handshake-pending when
//! its RG activates on this node must survive the promotion GC pass
//! (SelfHeal re-stamp), and a demoted opening row on the old owner must be
//! HELD (bounded by the opening-window ceiling), not instantly reaped.
//! Before the fix, `standby_gate_decision` returned `ReapStaleSynced` for
//! any idle-crossed opening peer-synced row before either the SelfHeal or
//! Hold arm could run, so the first GC pass after the RG move deleted the
//! flow on both nodes.

use super::*;
use crate::SessionSyncRequest;
use crate::server::helpers::build_synced_session_entry;
use crate::test_zone_ids::*;

const SEC: u64 = 1_000_000_000;
const OPENING_SECS: u64 = 20;
const OWNER_RG: i32 = 1;

fn synced_opening() -> SessionSyncRequest {
    let base = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 60948,
        dst_port: 5211,
        ingress_zone_id: TEST_TRUST_ZONE_ID,
        egress_zone_id: TEST_UNTRUST_ZONE_ID,
        owner_rg_id: OWNER_RG,
        inactivity_timeout: 1800,
        tcp_close_class: 0,
        session_id: 4242,
        ..SessionSyncRequest::default()
    };
    let mut value = serde_json::to_value(base).expect("FIXTURE: serialize request");
    // TcpHandshakeState::Opening on the wire.
    value["tcp_handshake_state"] = serde_json::json!(1);
    serde_json::from_value(value).expect("FIXTURE: deserialize request")
}

fn import_opening(table: &mut SessionTable, now_ns: u64) -> SessionKey {
    let zones = rustc_hash::FxHashMap::default();
    let entry = build_synced_session_entry(&synced_opening(), &zones, 0)
        .expect("FIXTURE: import request");
    let key = entry.key.clone();
    assert!(
        table.upsert_synced_with_origin(entry.into_session_install(now_ns), false),
        "FIXTURE: synced upsert"
    );
    key
}

fn expire_with(
    table: &mut SessionTable,
    now_ns: u64,
    forwards: bool,
    epoch: u32,
) -> Vec<ExpiredSession> {
    let forwards_rg = move |_rg: i32| forwards;
    let epoch_of = move |_rg: i32| epoch;
    let ha = ExpireHaContext {
        node_active: true,
        forwards_rg: &forwards_rg,
        epoch_of: &epoch_of,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
    node_served: &|_| NodeServedEvidence::default(),
    };
    table.last_gc_ns = 0;
    table.expire_stale_entries_ha(now_ns, Some(&ha))
}

#[test]
fn promoted_opening_row_self_heals_instead_of_reaping_16218() {
    let mut table = SessionTable::new();
    let installed_at = 10 * SEC;
    let key = import_opening(&mut table, installed_at);
    let entry = table.entry_by_key(&key).expect("imported opening row");
    assert!(!entry.established, "FIXTURE: row must import as opening");
    assert_eq!(entry.expires_after_ns, OPENING_SECS * SEC);

    // RG1 activates on this node (epoch bumped to 1) after the opening
    // deadline has passed with no local traffic refresh. The promotion
    // GC pass must SelfHeal (re-stamp + record epoch), never reap.
    let promote_sweep = installed_at + OPENING_SECS * SEC + WHEEL_TICK_NS_FOR_TEST + 1;
    let expired = expire_with(&mut table, promote_sweep, true, 1);
    assert!(
        expired.is_empty(),
        "#16218: a promoted opening row must not be reaped at failover"
    );
    assert_eq!(table.last_pop_stats().healed_on_promote, 1);
    assert_eq!(table.last_pop_stats().reaped_stale_synced, 0);
    let entry = table.entry_by_key(&key).expect("row survives promotion");
    assert_eq!(entry.last_seen_ns, promote_sweep, "SelfHeal must re-stamp");
}

#[test]
fn demoted_opening_row_is_held_not_instantly_reaped_16218() {
    let mut table = SessionTable::new();
    let installed_at = 10 * SEC;
    let key = import_opening(&mut table, installed_at);

    // Old owner after demotion: this node no longer forwards RG1. The
    // first idle-crossed pass must HOLD the row (the peer may still need
    // it / may fail back), bounded by 3x the opening window.
    let demote_sweep = installed_at + OPENING_SECS * SEC + WHEEL_TICK_NS_FOR_TEST + 1;
    let expired = expire_with(&mut table, demote_sweep, false, 1);
    assert!(
        expired.is_empty(),
        "#16218: a demoted opening row must be held, not instantly reaped"
    );
    assert_eq!(table.last_pop_stats().held_standby, 1);
    assert_eq!(table.last_pop_stats().reaped_stale_synced, 0);
    assert!(table.entry_by_key(&key).is_some(), "held row must survive");

    // Past first_held + 3x opening window it reaps (lost-Close bound).
    let ceiling_sweep = demote_sweep + 3 * OPENING_SECS * SEC + WHEEL_TICK_NS_FOR_TEST + 1;
    let expired = expire_with(&mut table, ceiling_sweep, false, 1);
    assert!(
        expired.iter().any(|entry| entry.key == key),
        "#16218: held opening row must reap past its opening ceiling"
    );
    assert_eq!(table.last_pop_stats().reaped_stale_synced, 1);
}
