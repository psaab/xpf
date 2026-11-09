//! #19026 Part 2: the close fence for restored `SharedPromote` copies.
//!
//! At RG activation the prewarm restores a locally promoted session as
//! `SharedPromote` on EVERY worker (#15950). Only the worker its packets land
//! on refreshes its copy; the others age one window after the activation
//! re-stamp, and each idle copy's expiry Close was the carrier of the shared
//! removal, the sibling `DeleteSynced` fan-out and the HA delete — all keyed
//! by tuple, so it tore down the serving worker's live row (udp: live pings
//! closed "idle Timeout" at T0+62, up to 4 Close frames per session).
//!
//! The approved rule (issue comment, design (b)) for an expiring forward
//! `SharedPromote` row on a node that forwards its RG:
//! - R1  shared primary row absent, or a different session id -> silent;
//! - R2  same session, this copy never served since install
//!   (`last_packet_seen_ns < created_ns`):
//!   (a) shared fwd+rev advanced past this copy's install-seeded counters
//!       -> silent (someone served after the restore);
//!   (b) not advanced -> only the designated closer closes;
//! - R3  this copy served -> ordinary AGE with its Close.
//!
//! Every Close delta is exactly one HA delete once flushed
//! (`flush_session_deltas`: event-stream close + `DeleteSynced` fan-out), so
//! the cells count Close deltas across all copies as "Close + HA delete".

use super::*;
use crate::SessionSyncRequest;
use crate::server::helpers::build_synced_session_entry;
use crate::test_zone_ids::*;

const SEC: u64 = 1_000_000_000;
const RG: i32 = 1;
const WORKERS: usize = 6;
const SESSION_ID: u64 = 0x0001_0000_0000_1906;
const SEEDED_FWD: u64 = 30;
const SEEDED_REV: u64 = 30;
const INSTALL_NS: u64 = 1_000 * SEC;

fn promoted_icmp_entry() -> crate::afxdp::SyncedSessionEntry {
    let req = SessionSyncRequest {
        forward_wire_alias_origin: false,
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_ICMP,
        src_ip: "10.0.63.106".to_string(),
        dst_ip: "172.16.80.211".to_string(),
        src_port: 3306,
        dst_port: 0,
        ingress_zone_id: TEST_TRUST_ZONE_ID,
        egress_zone_id: TEST_UNTRUST_ZONE_ID,
        owner_rg_id: RG,
        inactivity_timeout: 60,
        session_id: SESSION_ID,
        fwd_packets: SEEDED_FWD,
        rev_packets: SEEDED_REV,
        ..SessionSyncRequest::default()
    };
    let mut entry = build_synced_session_entry(&req, &rustc_hash::FxHashMap::default(), 0)
        .expect("FIXTURE: synced entry");
    // What the activation prewarm pushes for a locally promoted row (#15950).
    entry.origin = SessionOrigin::SharedPromote;
    entry
}

/// One table per worker, each holding the restored `SharedPromote` copy as
/// the prewarm installs it (`handle_upsert_synced` ->
/// `upsert_synced_with_origin(.., allow_replace_local=false)` on the node
/// that forwards the RG). `closer` is the designated restore closer.
fn restored_copies(closer: Option<usize>) -> (Vec<SessionTable>, SessionKey) {
    let entry = promoted_icmp_entry();
    let key = entry.key.clone();
    let mut tables: Vec<SessionTable> = (0..WORKERS).map(|_| SessionTable::new()).collect();
    for (worker, table) in tables.iter_mut().enumerate() {
        assert!(
            table.upsert_synced_with_origin(entry.clone().into_session_install(INSTALL_NS), false),
            "FIXTURE: worker {worker} restore"
        );
        assert_eq!(
            table.entry_with_origin(&key).map(|(_, _, origin)| origin),
            Some(SessionOrigin::SharedPromote),
            "FIXTURE: worker {worker} holds the SharedPromote copy"
        );
    }
    if let Some(closer) = closer {
        assert!(
            tables[closer].mark_restore_closer(&key, SESSION_ID),
            "FIXTURE: the designated copy is marked"
        );
    }
    (tables, key)
}

/// A packet hit on this worker's copy (the production read path plus its
/// accounting charge), stamping `last_packet_seen_ns` past `created_ns`.
fn serve(table: &mut SessionTable, key: &SessionKey, now_ns: u64) {
    assert!(table.lookup_with_origin(key, now_ns, 0).is_some(), "FIXTURE: serve hit");
    table.account_packet(key, 84, 0, 0);
}

fn expire(
    table: &mut SessionTable,
    now_ns: u64,
    forwards: bool,
    shared: Option<SharedRowIdentity>,
) -> Vec<ExpiredSession> {
    let forwards_rg = move |_rg: i32| forwards;
    let epoch_of = |_rg: i32| 0u32;
    let shared_row = move |_key: &SessionKey| shared;
    let ha = ExpireHaContext {
        node_active: true,
        forwards_rg: &forwards_rg,
        epoch_of: &epoch_of,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
        node_served: &|_| NodeServedEvidence::default(),
        shared_row: &shared_row,
    };
    table.last_gc_ns = 0;
    table.expire_stale_entries_ha(now_ns, Some(&ha))
}

fn closes_for(table: &mut SessionTable, key: &SessionKey) -> usize {
    table
        .drain_deltas(4096)
        .into_iter()
        .filter(|delta| delta.kind == SessionDeltaKind::Close && delta.key == *key)
        .count()
}

fn tombstones_for(table: &mut SessionTable, key: &SessionKey) -> usize {
    let mut n = 0;
    table.take_tombstones_for_export(u64::MAX, &[RG], |tombstone| {
        if tombstone.key == *key {
            n += 1;
        }
        true
    });
    n
}

/// Past every copy's idle window (60 s from the install re-stamp).
fn after_window() -> u64 {
    INSTALL_NS + 62 * SEC
}

fn shared(packets: u64) -> Option<SharedRowIdentity> {
    Some(SharedRowIdentity {
        session_id: SESSION_ID,
        packets,
    })
}

/// Cell 1: while another worker serves the flow (its packets advanced the
/// shared row's max-merged counters), every non-serving restored copy is
/// removed SILENTLY: no Close delta (so no shared removal, no sibling
/// `DeleteSynced`, no HA delete, no RT_FLOW close), no export tombstone, and
/// a fenced teardown marker for the reap.
#[test]
fn non_serving_restored_copy_is_silent_while_another_serves_19026() {
    let (mut tables, key) = restored_copies(Some(0));
    let serving = 2;
    // The serving worker keeps the flow alive at 10 Hz-ish cadence.
    for second in 1..=62u64 {
        serve(&mut tables[serving], &key, INSTALL_NS + second * SEC);
    }
    let advanced = shared(SEEDED_FWD + SEEDED_REV + 124);
    let mut silent = 0;
    for (worker, table) in tables.iter_mut().enumerate() {
        let expired = expire(table, after_window(), true, advanced);
        if worker == serving {
            assert!(expired.is_empty(), "the serving copy is live");
            assert!(table.entry_by_key(&key).is_some());
            continue;
        }
        assert_eq!(expired.len(), 1, "worker {worker}: the idle copy is removed");
        assert!(
            expired[0].close_fenced,
            "worker {worker}: its reap must take the fenced teardown"
        );
        assert!(expired[0].overflow_close.is_none());
        assert_eq!(
            closes_for(table, &key),
            0,
            "#19026: worker {worker}'s non-serving copy (closer or not) emits no Close"
        );
        assert_eq!(tombstones_for(table, &key), 0, "no export tombstone either");
        silent += 1;
    }
    assert_eq!(silent, WORKERS - 1);
}

/// Cell 2: a flow that really goes idle closes EXACTLY ONCE across all
/// copies — through the copy that served (R3) — with no duplicate from the
/// fenced copies, and the closer mark does not add a second Close.
#[test]
fn idle_flow_closes_exactly_once_across_copies_19026() {
    let (mut tables, key) = restored_copies(Some(0));
    let serving = 3;
    for second in 1..=10u64 {
        serve(&mut tables[serving], &key, INSTALL_NS + second * SEC);
    }
    // Everyone is past the window after the flow stops at +10 s.
    let now = INSTALL_NS + 75 * SEC;
    let advanced = shared(SEEDED_FWD + SEEDED_REV + 20);
    let mut closes = 0;
    for table in tables.iter_mut() {
        let _ = expire(table, now, true, advanced);
        closes += closes_for(table, &key);
        assert!(table.entry_by_key(&key).is_none(), "every copy is gone");
    }
    assert_eq!(closes, 1, "#19026: Close + HA delete == 1 for the session");
}

/// Cell 4 (twin a): a stale shared row — present, same session, nobody ever
/// served after the restore, counters not advanced — closes exactly once,
/// through the designated restore closer.
#[test]
fn stale_restored_session_closes_once_via_designated_closer_19026() {
    let closer = 4;
    let (mut tables, key) = restored_copies(Some(closer));
    let stale = shared(SEEDED_FWD + SEEDED_REV);
    let mut closes_by_worker = Vec::new();
    for table in tables.iter_mut() {
        let expired = expire(table, after_window(), true, stale);
        assert_eq!(expired.len(), 1);
        closes_by_worker.push(closes_for(table, &key));
    }
    assert_eq!(
        closes_by_worker.iter().sum::<usize>(),
        1,
        "#19026: the stale twin closes exactly once ({closes_by_worker:?})"
    );
    assert_eq!(closes_by_worker[closer], 1, "and it is the designated closer");
}

/// Cell 4 (twin b, R1): the same never-served restored copies with the
/// shared row GONE (already closed elsewhere) stay silent — the closer too.
#[test]
fn restored_copies_stay_silent_when_shared_row_is_gone_19026() {
    let (mut tables, key) = restored_copies(Some(1));
    for (worker, table) in tables.iter_mut().enumerate() {
        let expired = expire(table, after_window(), true, None);
        assert_eq!(expired.len(), 1);
        assert!(expired[0].close_fenced, "worker {worker}");
        assert_eq!(closes_for(table, &key), 0, "#19026 R1: worker {worker} is silent");
    }
}

/// R1, replaced: a different session id under the key is a replacement;
/// the old copies must not close it.
#[test]
fn restored_copies_stay_silent_when_shared_row_was_replaced_19026() {
    let (mut tables, key) = restored_copies(Some(1));
    let replaced = Some(SharedRowIdentity {
        session_id: SESSION_ID + 1,
        packets: SEEDED_FWD + SEEDED_REV,
    });
    for table in tables.iter_mut() {
        let _ = expire(table, after_window(), true, replaced);
        assert_eq!(closes_for(table, &key), 0, "#19026 R1 (replaced): silent");
    }
}

/// Cell 5: the fence has not muted real expiry. A genuinely idle locally
/// owned row still closes: a plain `ForwardFlow` row, a `SharedPromote` copy
/// that served (R3) even when no shared row is consulted, and a
/// `SharedPromote` row on a node that does NOT forward its RG or runs with
/// no HA context at all.
#[test]
fn genuinely_idle_local_rows_still_close_19026() {
    // R3: the copy served, then the flow went idle; shared not advanced past
    // what this copy itself contributed.
    let (mut tables, key) = restored_copies(None);
    serve(&mut tables[0], &key, INSTALL_NS + SEC);
    let own = tables[0].fwd_packets_for(&key) + tables[0].rev_packets_for(&key);
    let _ = expire(&mut tables[0], INSTALL_NS + 63 * SEC, true, shared(own));
    assert_eq!(closes_for(&mut tables[0], &key), 1, "R3: a served copy closes");

    // Not forwarding the RG here: the fence does not apply; the standby gate
    // HOLDs the row exactly as before #19026.
    let (mut tables, key) = restored_copies(None);
    let expired = expire(&mut tables[1], after_window(), false, None);
    assert!(expired.is_empty(), "standby: held, not reaped");
    assert!(tables[1].entry_by_key(&key).is_some());

    // No HA context: standalone semantics, ordinary Close.
    let (mut tables, key2) = restored_copies(None);
    tables[2].last_gc_ns = 0;
    let expired = tables[2].expire_stale_entries_ha(after_window(), None);
    assert_eq!(expired.len(), 1);
    assert!(!expired[0].close_fenced);
    assert_eq!(closes_for(&mut tables[2], &key2), 1, "no HA: ordinary Close");
    let _ = key;

    // A plain local ForwardFlow row, idle on a forwarding node.
    let mut table = SessionTable::new();
    let mut entry = promoted_icmp_entry();
    entry.origin = SessionOrigin::SyncImport;
    let mut install = entry.into_session_install(INSTALL_NS);
    install.origin = SessionOrigin::ForwardFlow;
    install.session_id = 0;
    let local_key = install.key.clone();
    assert!(table.upsert_synced_with_origin(install, true), "FIXTURE: local row");
    let expired = expire(&mut table, after_window(), true, None);
    assert_eq!(expired.len(), 1);
    assert!(!expired[0].close_fenced);
    assert_eq!(closes_for(&mut table, &local_key), 1, "a local ForwardFlow row closes");
}

/// The restore-closer mark is per incarnation: it survives a same-id
/// re-import (a resend that is allowed to replace the local row) and is
/// dropped by a new incarnation. (On the forwarding node a resend is refused
/// by the local-replace guard and the marked row simply stays.)
#[test]
fn restore_closer_mark_follows_the_incarnation_19026() {
    let (mut tables, key) = restored_copies(Some(0));
    let entry = promoted_icmp_entry();
    assert!(
        !tables[0].upsert_synced_with_origin(entry.clone().into_session_install(INSTALL_NS), false),
        "premise: on the forwarding node the local-replace guard refuses the resend"
    );
    assert!(tables[0].upsert_synced_with_origin(
        entry.clone().into_session_install(INSTALL_NS + SEC),
        true
    ));
    let stale = shared(SEEDED_FWD + SEEDED_REV);
    let _ = expire(&mut tables[0], INSTALL_NS + 63 * SEC, true, stale);
    assert_eq!(closes_for(&mut tables[0], &key), 1, "same-id resend keeps the mark");

    let (mut tables, key) = restored_copies(Some(0));
    let mut next = promoted_icmp_entry();
    next.session_id = SESSION_ID + 7;
    assert!(tables[0].upsert_synced_with_origin(next.into_session_install(INSTALL_NS), true));
    assert!(
        !tables[0].mark_restore_closer(&key, SESSION_ID),
        "a mark for the old incarnation does not apply to the new one"
    );
    let replaced = Some(SharedRowIdentity {
        session_id: SESSION_ID + 7,
        packets: SEEDED_FWD + SEEDED_REV,
    });
    let _ = expire(&mut tables[0], after_window(), true, replaced);
    assert_eq!(closes_for(&mut tables[0], &key), 0, "the new incarnation was never marked");
}
