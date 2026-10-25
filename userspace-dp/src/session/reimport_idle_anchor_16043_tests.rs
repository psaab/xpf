//! #16043: a same-id HA re-import is a snapshot resend, not activity.
//! It must not refresh the idle anchor (`last_seen_ns`) for non-TCP
//! sessions or for legacy TCP imports that carry no handshake state.
//! Before the fix, `upsert_synced_with_origin` preserved the anchor only
//! for TCP imports with a nonzero wire id, so every same-id re-import of
//! a UDP/ICMP/other session — and every legacy TCP re-import — re-stamped
//! `last_seen_ns` to the import instant and a periodic re-import cadence
//! could defer idle expiry indefinitely.

use super::*;
use crate::SessionSyncRequest;
use crate::server::helpers::build_synced_session_entry;
use crate::test_zone_ids::*;

const SEC: u64 = 1_000_000_000;
const OWNER_RG: i32 = 1;

fn request(protocol: u8, session_id: u64) -> SessionSyncRequest {
    SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "8.8.8.8".to_string(),
        src_port: 12345,
        dst_port: 443,
        ingress_zone_id: TEST_TRUST_ZONE_ID,
        egress_zone_id: TEST_UNTRUST_ZONE_ID,
        owner_rg_id: OWNER_RG,
        session_id,
        ..SessionSyncRequest::default()
    }
}

fn import(table: &mut SessionTable, req: &SessionSyncRequest, now_ns: u64) -> SessionKey {
    let zones = rustc_hash::FxHashMap::default();
    let entry = build_synced_session_entry(req, &zones, 0).expect("FIXTURE: import request");
    let key = entry.key.clone();
    assert!(
        table.upsert_synced_with_origin(entry.into_session_install(now_ns), false),
        "FIXTURE: synced upsert"
    );
    key
}

fn anchor(table: &SessionTable, key: &SessionKey) -> u64 {
    table
        .entry_by_key(key)
        .expect("imported session must exist")
        .last_seen_ns
}

fn expire_as_standby(table: &mut SessionTable, now_ns: u64) -> Vec<ExpiredSession> {
    let forwards = |_rg: i32| false;
    let epoch = |_rg: i32| 0;
    let no_served = |_key: &SessionKey| NodeServedEvidence::default();
    let ha = ExpireHaContext {
        node_active: true,
        forwards_rg: &forwards,
        epoch_of: &epoch,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
        node_served: &no_served,
    };
    table.last_gc_ns = 0;
    table.expire_stale_entries_ha(now_ns, Some(&ha))
}

/// Decisive check from #16043: same-id re-import leaves the idle anchor
/// unchanged and the session expires on the ORIGINAL anchor; a new-id
/// import anchors fresh (control).
#[test]
fn same_id_udp_reimport_preserves_idle_anchor_and_expires_on_it_16043() {
    let mut table = SessionTable::new();
    let installed_at = 10 * SEC;
    let udp = crate::ip_proto::PROTO_UDP;
    let key = import(&mut table, &request(udp, 77), installed_at);
    assert_eq!(anchor(&table, &key), installed_at, "FIXTURE: fresh import anchors at import time");

    // Periodic same-id re-imports are snapshot resends, not activity.
    for step in 1..=3u64 {
        import(&mut table, &request(udp, 77), installed_at + step * 15 * SEC);
        assert_eq!(
            anchor(&table, &key),
            installed_at,
            "#16043: same-id UDP re-import #{step} must not refresh the idle anchor"
        );
    }

    // The session therefore ages from the original anchor (default UDP
    // window), not the last re-import instant. On a non-forwarding standby
    // a peer-synced entry is first HELD, then reaped once the hold itself
    // exceeds the stale-synced ceiling (measured from the first hold
    // observation); sweep past both deadlines.
    let udp_window = table.timeouts.udp_ns;
    let first_due_sweep = installed_at + udp_window + WHEEL_TICK_NS_FOR_TEST + 1;
    let held = expire_as_standby(&mut table, first_due_sweep);
    assert!(
        !held.iter().any(|entry| entry.key == key),
        "#16043: standby HOLD must retain the entry at its first due sweep"
    );
    assert_eq!(
        anchor(&table, &key),
        installed_at,
        "#16043: HOLD must not re-stamp the idle anchor"
    );
    let ceiling_sweep = first_due_sweep
        + STALE_SYNCED_CEILING_MULT * udp_window
        + STALE_SYNCED_CEILING_ABS_NS
        + WHEEL_TICK_NS_FOR_TEST
        + 1;
    let expired = expire_as_standby(&mut table, ceiling_sweep);
    assert!(
        expired.iter().any(|entry| entry.key == key),
        "#16043: same-id-reimported UDP session must expire once its hold ceiling passes"
    );

    // Control: a new incarnation (different wire id) anchors fresh.
    let new_incarnation_at = ceiling_sweep + SEC;
    let key2 = import(&mut table, &request(udp, 78), new_incarnation_at);
    assert_eq!(key2, key, "FIXTURE: same tuple re-imported under a new id");
    assert_eq!(
        anchor(&table, &key),
        new_incarnation_at,
        "#16043: new-id import control must anchor fresh"
    );
}

/// The HOLD arm of #16043: same-id re-imports that CONTINUE after the
/// standby HOLD clock has armed must not restart the stale-synced
/// ceiling. Before the fold, the replacement entry cleared
/// `first_held_ns`, so each re-import during HOLD re-armed the ceiling
/// and a lost-delete entry could be pinned indefinitely even with its
/// idle anchor preserved.
#[test]
fn continuing_same_id_reimports_during_hold_do_not_restart_ceiling_16043() {
    let mut table = SessionTable::new();
    let installed_at = 10 * SEC;
    let udp = crate::ip_proto::PROTO_UDP;
    let key = import(&mut table, &request(udp, 77), installed_at);
    let udp_window = table.timeouts.udp_ns;

    // First due sweep on the non-forwarding standby: HELD, clock armed.
    let hold_at = installed_at + udp_window + WHEEL_TICK_NS_FOR_TEST + 1;
    let held = expire_as_standby(&mut table, hold_at);
    assert!(!held.iter().any(|entry| entry.key == key), "FIXTURE: first sweep must HOLD");
    assert_eq!(
        table.first_held_ns_for(&key),
        Some(hold_at),
        "FIXTURE: HOLD arms first_held_ns at the first due sweep"
    );

    // Continuing same-id re-imports during HOLD preserve BOTH clocks.
    let ceiling = STALE_SYNCED_CEILING_MULT * udp_window;
    let mut t = hold_at;
    for step in 1..=3u64 {
        t = hold_at + step * (ceiling / 2);
        import(&mut table, &request(udp, 77), t);
        assert_eq!(anchor(&table, &key), installed_at, "#16043: re-import during HOLD must preserve the idle anchor");
        assert_eq!(
            table.first_held_ns_for(&key),
            Some(hold_at),
            "#16043: re-import during HOLD must not restart the stale ceiling (step {step})"
        );
    }

    // Past the ceiling measured from the ORIGINAL hold instant — despite
    // re-imports landing after it — the entry is reaped.
    let reap_at = t + WHEEL_TICK_NS_FOR_TEST + 1;
    assert!(reap_at > hold_at + ceiling, "FIXTURE: reap sweep must be past the original ceiling");
    let expired = expire_as_standby(&mut table, reap_at);
    assert!(
        expired.iter().any(|entry| entry.key == key),
        "#16043: continuing same-id re-imports during HOLD must not defer the stale-ceiling reap"
    );
}

/// Compatibility coverage (not newly-fixed behavior): for TCP the
/// preserved-anchor predicate is algebraically unchanged from #10888 —
/// a legacy (handshake-state-0) import and its stored entry both decode
/// through the legacy-established view — so a same-id legacy re-import
/// already preserved the anchor at base. This cell pins that the
/// generalized #16043 fence did not regress it; a changed id anchors
/// fresh.
#[test]
fn same_id_legacy_tcp_reimport_preserves_idle_anchor_16043() {
    let mut table = SessionTable::new();
    let installed_at = 10 * SEC;
    let tcp = crate::ip_proto::PROTO_TCP;
    // request() leaves tcp_handshake_state at its default (0 = legacy).
    let key = import(&mut table, &request(tcp, 77), installed_at);
    let reimported_at = installed_at + 15 * SEC;
    import(&mut table, &request(tcp, 77), reimported_at);
    assert_eq!(
        anchor(&table, &key),
        installed_at,
        "#16043: same-id legacy TCP re-import must not refresh the idle anchor"
    );

    let new_id_at = reimported_at + SEC;
    import(&mut table, &request(tcp, 78), new_id_at);
    assert_eq!(
        anchor(&table, &key),
        new_id_at,
        "#16043: new-id TCP import must anchor fresh"
    );
}

/// A zero wire id carries no identity to match (legacy peer that predates
/// the session-id field, or a locally-generated replica): it keeps the
/// pre-#16043 fresh-anchor behavior rather than pinning the first anchor
/// forever.
#[test]
fn zero_id_reimport_keeps_fresh_anchor_16043() {
    let mut table = SessionTable::new();
    let installed_at = 10 * SEC;
    let udp = crate::ip_proto::PROTO_UDP;
    let key = import(&mut table, &request(udp, 0), installed_at);
    let reimported_at = installed_at + 15 * SEC;
    import(&mut table, &request(udp, 0), reimported_at);
    assert_eq!(
        anchor(&table, &key),
        reimported_at,
        "#16043: zero-id re-import has no identity to fence and anchors fresh"
    );
}

/// A primary-liveness frame is distinct from a snapshot resend: it refreshes
/// the standby HOLD anchor while the primary keeps the session live, but a
/// lost Close is still reaped after those frames stop.
#[test]
fn primary_liveness_refreshes_hold_clock_until_signal_stops_16880() {
    let mut table = SessionTable::new();
    let installed_at = 10 * SEC;
    let udp = crate::ip_proto::PROTO_UDP;
    let key = import(&mut table, &request(udp, 77), installed_at);
    let timeout = table.timeouts.udp_ns;

    let hold_at = installed_at + timeout + WHEEL_TICK_NS_FOR_TEST + 1;
    let held = expire_as_standby(&mut table, hold_at);
    assert!(
        !held.iter().any(|entry| entry.key == key),
        "FIXTURE: first sweep must HOLD"
    );
    assert_eq!(table.first_held_ns_for(&key), Some(hold_at));

    let mut live_request = request(udp, 77);
    live_request.primary_liveness = true;
    let mut last_liveness_at = hold_at;
    for step in 1..=10u64 {
        last_liveness_at = hold_at + step * timeout;
        import(&mut table, &live_request, last_liveness_at);
        assert_eq!(
            table.first_held_ns_for(&key),
            Some(last_liveness_at),
            "#16880: a primary-liveness frame must re-anchor HOLD at step {step}"
        );
        let held = expire_as_standby(&mut table, last_liveness_at + WHEEL_TICK_NS_FOR_TEST + 1);
        assert!(
            !held.iter().any(|entry| entry.key == key),
            "#16880: a primary-live session must remain held at step {step}"
        );
    }

    // Local activity may refresh the idle anchor, but it cannot extend the
    // absolute HOLD deadline established by the last primary-liveness frame.
    let ceiling = STALE_SYNCED_CEILING_MULT * timeout;
    let activity_at = last_liveness_at + ceiling - timeout / 2;
    table.touch(&key, activity_at);
    assert_eq!(
        table.first_held_ns_for(&key),
        Some(last_liveness_at),
        "#16880: local traffic must not move the primary-liveness HOLD anchor"
    );

    let reap_at = activity_at + timeout + WHEEL_TICK_NS_FOR_TEST + 1;
    assert!(
        reap_at > last_liveness_at + ceiling,
        "FIXTURE: post-traffic reap must be beyond the primary-liveness ceiling"
    );
    let expired = expire_as_standby(&mut table, reap_at);
    assert!(
        expired.iter().any(|entry| entry.key == key),
        "#16880: traffic after the last primary-liveness frame must not extend HOLD"
    );
}
