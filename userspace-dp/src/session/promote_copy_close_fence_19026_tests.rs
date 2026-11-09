//! #19026 Part 2 (fold cycle 1): the restore close fence, rule by rule.
//!
//! At RG activation the prewarm restores a locally promoted row as
//! `SharedPromote` on EVERY worker (#15950). Before #19026 each idle copy's
//! expiry Close carried the shared removal, the sibling `DeleteSynced` fan-out
//! and the HA delete — all keyed by tuple — and so tore down the serving
//! worker's live row (udp: live pings closed "idle Timeout" at T0+62).
//!
//! `SessionTable::promote_fence_step` (expire.rs) now runs the same rule on
//! every restored copy, with no designated closer:
//! R1 shared row gone / other id -> silent; this copy (either direction) or
//! any worker (`last_served_ns`) served inside the window -> KEEP, re-stamped
//! to that packet time; node idle -> hold one evidence cadence + GC; evidence
//! moved without fresh service -> hold again; else CLAIM -> exactly one copy
//! closes. The claim creates the node's close-retirement directory entry for
//! the old session id (compare-and-insert, carrying the Close); any copy that
//! finds an entry is silent, and the directory itself owns the obligation
//! (takeover, full ring, replacement: `close_retirement_19026_tests.rs`).
//!
//! These cells drive `expire_stale_entries_ha` with a modelled shared row
//! (`SharedModel`): `shared_row` reads it and `claim_close` runs the
//! directory create iff it still reads the expected identity, as
//! `shared_ops::claim_shared_close` does under the shared-map lock. The end-to-end paths (prewarm, restamp,
//! real flush, sibling deletes) are pinned in
//! `afxdp/worker/loop_body/promote_fence_concurrency_19026_tests.rs`.

use super::*;
use crate::SessionSyncRequest;
use crate::server::helpers::build_synced_session_entry;
use crate::test_zone_ids::*;
use std::cell::Cell;

const SEC: u64 = 1_000_000_000;
const RG: i32 = 1;
const SESSION_ID: u64 = 0x0001_0000_0000_1906;
const INSTALL_NS: u64 = 1_000 * SEC;
const WINDOW_NS: u64 = 60 * SEC;
/// The fence's hold with `fence_evidence_cadence_ns = CADENCE_NS`. The wheel
/// visits the deferred row on the first GC pass after the hold's tick, so
/// post-hold checks run 2 s later.
const CADENCE_NS: u64 = 13 * SEC;
const HOLD_NS: u64 = CADENCE_NS + SESSION_GC_INTERVAL_NS;

/// The node's shared primary row as the fence sees it.
struct SharedModel {
    row: Cell<Option<SharedRowIdentity>>,
    claims: Cell<u32>,
}

impl SharedModel {
    fn new(packets: u64, last_served_ns: u64) -> Self {
        Self {
            row: Cell::new(Some(SharedRowIdentity {
                session_id: SESSION_ID,
                packets,
                last_served_ns,
            })),
            claims: Cell::new(0),
        }
    }

    fn served(&self, at_ns: u64) {
        let mut row = self.row.get().expect("shared row");
        row.packets += 1;
        row.last_served_ns = row.last_served_ns.max(at_ns);
        self.row.set(Some(row));
    }
}

fn promoted_icmp_entry() -> crate::afxdp::SyncedSessionEntry {
    promoted_entry(crate::ip_proto::PROTO_ICMP, 3306, 0)
}

fn promoted_entry(protocol: u8, src_port: u16, dst_port: u16) -> crate::afxdp::SyncedSessionEntry {
    let req = SessionSyncRequest {
        forward_wire_alias_origin: false,
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol,
        src_ip: "10.0.63.106".to_string(),
        dst_ip: "172.16.80.211".to_string(),
        src_port,
        dst_port,
        ingress_zone_id: TEST_TRUST_ZONE_ID,
        egress_zone_id: TEST_UNTRUST_ZONE_ID,
        owner_rg_id: RG,
        inactivity_timeout: 60,
        session_id: SESSION_ID,
        fwd_packets: 30,
        rev_packets: 30,
        ..SessionSyncRequest::default()
    };
    let mut entry = build_synced_session_entry(&req, &rustc_hash::FxHashMap::default(), 0)
        .expect("FIXTURE: synced entry");
    entry.origin = SessionOrigin::SharedPromote;
    entry
}

/// One worker's restored copy, as the prewarm installs it on the node that
/// forwards the RG.
fn restored_copy() -> (SessionTable, SessionKey) {
    let entry = promoted_icmp_entry();
    let key = entry.key.clone();
    let mut table = SessionTable::new();
    assert!(table.upsert_synced_with_origin(entry.into_session_install(INSTALL_NS), false));
    assert_eq!(table.timeout_secs_for(&key), 60, "FIXTURE: 60 s window");
    (table, key)
}

fn serve(table: &mut SessionTable, key: &SessionKey, now_ns: u64) {
    assert!(table.lookup_with_origin(key, now_ns, 0).is_some(), "FIXTURE: serve hit");
    table.account_packet(key, 84, 0, 0);
}

fn expire(
    table: &mut SessionTable,
    now_ns: u64,
    forwards: bool,
    shared: &SharedModel,
) -> Vec<ExpiredSession> {
    let forwards_rg = move |_rg: i32| forwards;
    let epoch_of = |_rg: i32| 0u32;
    let shared_row = |_key: &SessionKey| shared.row.get();
    // As `shared_ops::claim_shared_close`: compare, then run the directory's
    // compare-and-insert (the row itself is not touched).
    let claim_close =
        |_key: &SessionKey, expected: SharedRowIdentity, create: &mut dyn FnMut() -> bool| {
            if shared.row.get() == Some(expected) && create() {
                shared.claims.set(shared.claims.get() + 1);
                true
            } else {
                false
            }
        };
    let ha = ExpireHaContext {
        node_active: true,
        forwards_rg: &forwards_rg,
        epoch_of: &epoch_of,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
        node_served: &|_| NodeServedEvidence::default(),
        shared_row: &shared_row,
        claim_close: &claim_close,
        fence_evidence_cadence_ns: CADENCE_NS,
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

/// Past the copy's own window (60 s from the install re-stamp).
fn crossed() -> u64 {
    INSTALL_NS + WINDOW_NS + 2 * SEC
}

/// Cell 1: while ANOTHER worker serves (the shared row's `last_served_ns`
/// is inside the window — the minting worker's restamp stamps it too), an
/// idle restored copy is KEPT, re-stamped to that packet time: no removal,
/// no Close (so no shared removal, sibling `DeleteSynced`, HA delete or
/// RT_FLOW close), no hold, the shared row untouched. Kept rather than
/// dropped so a copy that can close the session exists on whichever worker
/// the flow moves to. Once the node goes idle the copy holds and claims.
#[test]
fn idle_copy_is_kept_while_another_worker_serves_19026() {
    let (mut table, key) = restored_copy();
    let now = crossed();
    let served = now - 5 * SEC;
    let shared = SharedModel::new(60, served);
    assert!(expire(&mut table, now, true, &shared).is_empty(), "the idle copy is kept");
    assert_eq!(
        table.entry_by_key(&key).expect("kept").last_seen_ns,
        served,
        "re-stamped to the node's last service"
    );
    assert_eq!(closes_for(&mut table, &key), 0, "#19026: no Close");
    assert_eq!(tombstones_for(&mut table, &key), 0, "no export tombstone");
    assert_eq!(table.promote_fence_hold_count(), 0, "not held");
    assert!(shared.row.get().is_some() && shared.claims.get() == 0, "shared row untouched");
    // The node goes idle: one window after its last service the copy holds,
    // then claims and closes exactly once.
    let idle = served + WINDOW_NS + 2 * SEC;
    assert!(expire(&mut table, idle, true, &shared).is_empty(), "held");
    let expired = expire(&mut table, idle + HOLD_NS + 2 * SEC, true, &shared);
    assert_eq!(expired.len(), 1);
    assert!(!expired[0].close_fenced);
    assert_eq!(closes_for(&mut table, &key), 1, "exactly one Close once idle");
    assert_eq!(shared.claims.get(), 1);
}

/// Codex P1 #1: a copy that SERVED (served-since-install was R3 = Close on
/// bb9608f1a6) is kept without a Close when another worker served more
/// recently.
#[test]
fn copy_that_served_earlier_is_kept_while_another_serves_19026() {
    let (mut table, key) = restored_copy();
    serve(&mut table, &key, INSTALL_NS + 5 * SEC);
    let now = INSTALL_NS + 5 * SEC + WINDOW_NS + 2 * SEC;
    let shared = SharedModel::new(70, now - 3 * SEC);
    assert!(expire(&mut table, now, true, &shared).is_empty(), "kept");
    assert!(table.entry_by_key(&key).is_some());
    assert_eq!(closes_for(&mut table, &key), 0, "#19026 Codex P1 #1: no Close");
}

/// R14 F2: service in the REVERSE direction only (a reverse hit stamps the
/// reverse half; only its counters fold onto the forward copy) is this
/// copy's own service: the forward copy is kept to the reverse packet time,
/// then, once idle, holds and closes exactly once (no leak).
#[test]
fn reverse_only_service_keeps_the_copy_then_closes_once_19026() {
    let entry = promoted_entry(crate::ip_proto::PROTO_UDP, 40000, 5000);
    let key = entry.key.clone();
    let mut reverse = entry.clone();
    reverse.key = reverse_session_key(&key, entry.decision.nat);
    reverse.metadata.is_reverse = true;
    reverse.origin = SessionOrigin::WorkerLocalImport;
    let reverse_key = reverse.key.clone();
    let mut table = SessionTable::new();
    assert!(table.upsert_synced_with_origin(entry.into_session_install(INSTALL_NS), false));
    assert!(table.upsert_synced_with_origin(reverse.into_session_install(INSTALL_NS), false));
    let served = INSTALL_NS + 20 * SEC;
    assert!(table.lookup_with_origin(&reverse_key, served, 0).is_some(), "FIXTURE: reverse hit");
    table.account_packet(&reverse_key, 84, 0, 0);
    assert_eq!(
        table.entry_by_key(&key).expect("forward").last_packet_seen_ns,
        0,
        "FIXTURE premise: reverse service does not stamp the forward copy"
    );
    // Nobody else served; the shared row has not been restamped yet.
    let shared = SharedModel::new(60, 0);
    assert!(expire(&mut table, crossed(), true, &shared).is_empty(), "kept");
    assert_eq!(table.entry_by_key(&key).expect("kept").last_seen_ns, served);
    assert_eq!(closes_for(&mut table, &key), 0);
    let idle = served + WINDOW_NS + 2 * SEC;
    let _ = expire(&mut table, idle, true, &shared);
    let _ = expire(&mut table, idle + HOLD_NS + 2 * SEC, true, &shared);
    assert!(table.entry_by_key(&key).is_none(), "the forward copy left");
    assert_eq!(closes_for(&mut table, &key), 1, "#19026 R14 F2: exactly one Close");
}

/// The node looks idle: the copy is HELD for one evidence cadence + GC
/// interval (no removal, no Close), then claims, and closes exactly once.
#[test]
fn node_idle_copy_holds_then_claims_and_closes_once_19026() {
    let (mut table, key) = restored_copy();
    let now = crossed();
    let shared = SharedModel::new(60, 0);
    assert!(expire(&mut table, now, true, &shared).is_empty(), "held, not removed");
    assert_eq!(table.promote_fence_hold_count(), 1);
    assert_eq!(closes_for(&mut table, &key), 0, "no Close during the hold");
    // Early visit inside the hold: still held.
    assert!(expire(&mut table, now + HOLD_NS / 2, true, &shared).is_empty());
    let expired = expire(&mut table, now + HOLD_NS + 2 * SEC, true, &shared);
    assert_eq!(expired.len(), 1);
    assert!(!expired[0].close_fenced, "the claim winner takes the ordinary reap");
    assert_eq!(closes_for(&mut table, &key), 1, "exactly one Close");
    assert_eq!(shared.claims.get(), 1);
    assert!(
        matches!(
            table.close_retirement_directory().entry_for_test(SESSION_ID),
            Some(Retirement::Pending { .. })
        ),
        "#19026: the claim created the pending close-retirement entry"
    );
    assert!(shared.row.get().is_some(), "the claim does not touch the shared row");
    assert_eq!(table.promote_fence_hold_count(), 0);
}

/// Codex P1 #2: serving evidence that surfaces DURING the hold (a restamp
/// that lagged the copy's crossing) cancels the close: the copy is kept.
#[test]
fn evidence_surfacing_during_the_hold_cancels_the_close_19026() {
    let (mut table, key) = restored_copy();
    let now = crossed();
    let shared = SharedModel::new(60, 0);
    assert!(expire(&mut table, now, true, &shared).is_empty(), "held");
    shared.served(now - SEC); // another worker's restamp lands late
    assert!(expire(&mut table, now + HOLD_NS + 2 * SEC, true, &shared).is_empty(), "kept");
    assert_eq!(table.entry_by_key(&key).expect("kept").last_seen_ns, now - SEC);
    assert_eq!(closes_for(&mut table, &key), 0, "#19026 Codex P1 #2: no Close");
    assert_eq!(shared.claims.get(), 0);
    assert_eq!(table.promote_fence_hold_count(), 0, "the hold is cancelled");
}

/// Evidence that changes during the hold WITHOUT fresh service (a stale
/// counter max-merge) neither closes on the stale snapshot nor silences the
/// copy: the hold re-arms on the new evidence, then claims once.
#[test]
fn stale_evidence_change_rearms_the_hold_19026() {
    let (mut table, key) = restored_copy();
    let now = crossed();
    let shared = SharedModel::new(60, 0);
    assert!(expire(&mut table, now, true, &shared).is_empty(), "held");
    let mut row = shared.row.get().expect("row");
    row.packets += 5; // counts moved; no packet inside the window
    shared.row.set(Some(row));
    let first_end = now + HOLD_NS + 2 * SEC;
    assert!(expire(&mut table, first_end, true, &shared).is_empty(), "re-held, not closed");
    assert_eq!(shared.claims.get(), 0);
    assert_eq!(table.promote_fence_hold_count(), 1);
    let expired = expire(&mut table, first_end + HOLD_NS + 2 * SEC, true, &shared);
    assert_eq!(expired.len(), 1);
    assert_eq!(closes_for(&mut table, &key), 1, "the re-armed hold claims once");
}

/// Exactly once across copies: two copies (sharing the node's directory)
/// reach their claim; the first creates the entry and closes; the second
/// finds the entry and is silent at once.
#[test]
fn two_copies_claiming_close_exactly_once_19026() {
    let (mut a, key) = restored_copy();
    let (mut b, _) = restored_copy();
    b.set_close_retirement_directory(a.close_retirement_directory().clone());
    let now = crossed();
    let shared = SharedModel::new(60, 0);
    assert!(expire(&mut a, now, true, &shared).is_empty());
    assert!(expire(&mut b, now, true, &shared).is_empty());
    let at_claim = now + HOLD_NS + 2 * SEC;
    let ea = expire(&mut a, at_claim, true, &shared);
    let eb = expire(&mut b, at_claim, true, &shared);
    assert_eq!(ea.len(), 1, "the winner leaves with its Close");
    assert!(!ea[0].close_fenced);
    assert_eq!(eb.len(), 1, "the second copy finds the entry and leaves");
    assert!(eb[0].close_fenced, "silent: the directory owns the Close");
    assert_eq!(
        closes_for(&mut a, &key) + closes_for(&mut b, &key),
        1,
        "#19026: Close + HA delete == 1"
    );
    assert_eq!(shared.claims.get(), 1);
}

/// A copy that crosses AFTER another copy claimed finds the directory entry
/// and leaves at once (silent), without first arming a hold of its own.
#[test]
fn a_copy_crossing_after_the_claim_leaves_at_once_19026() {
    let (mut a, key) = restored_copy();
    let shared = SharedModel::new(60, 0);
    let now = crossed();
    assert!(expire(&mut a, now, true, &shared).is_empty());
    let at_claim = now + HOLD_NS + 2 * SEC;
    assert_eq!(expire(&mut a, at_claim, true, &shared).len(), 1, "a claims");
    let (mut b, _) = restored_copy();
    b.set_close_retirement_directory(a.close_retirement_directory().clone());
    let eb = expire(&mut b, at_claim + SEC, true, &shared);
    assert_eq!(eb.len(), 1, "b leaves at its first crossing");
    assert!(eb[0].close_fenced);
    assert_eq!(b.promote_fence_hold_count(), 0, "no hold armed");
    assert_eq!(closes_for(&mut b, &key), 0);
}

/// R1 twins: the shared row gone, or replaced by another incarnation — every
/// copy is silent, with no hold.
#[test]
fn shared_row_gone_or_replaced_is_silent_19026() {
    for replaced in [false, true] {
        let (mut table, key) = restored_copy();
        let shared = SharedModel::new(60, 0);
        if replaced {
            shared.row.set(Some(SharedRowIdentity {
                session_id: SESSION_ID + 1,
                packets: 60,
                last_served_ns: 0,
            }));
        } else {
            shared.row.set(None);
        }
        let expired = expire(&mut table, crossed(), true, &shared);
        assert_eq!(expired.len(), 1, "replaced={replaced}");
        assert!(expired[0].close_fenced);
        assert_eq!(closes_for(&mut table, &key), 0, "replaced={replaced}: R1 silent");
        assert_eq!(tombstones_for(&mut table, &key), 0, "a Transfer: no export tombstone");
        assert_eq!(table.promote_fence_hold_count(), 0);
    }
}

/// A copy whose own packets are inside its window (its idle anchor lagged)
/// is serving: kept and re-stamped to its packet time, never silenced or
/// held.
#[test]
fn copy_with_its_own_recent_packets_is_kept_19026() {
    let (mut table, key) = restored_copy();
    serve(&mut table, &key, INSTALL_NS + 30 * SEC);
    // Model a lagging idle anchor: last_seen older than the last packet.
    table.entry_by_key_mut(&key).expect("row").last_seen_ns = INSTALL_NS;
    table.push_to_wheel(&key, INSTALL_NS);
    let shared = SharedModel::new(61, 0);
    assert!(expire(&mut table, crossed(), true, &shared).is_empty(), "kept");
    assert_eq!(table.entry_by_key(&key).expect("kept").last_seen_ns, INSTALL_NS + 30 * SEC);
    assert_eq!(table.promote_fence_hold_count(), 0, "not held");
}

/// A hold armed under one idle anchor does not carry over once the row was
/// re-stamped (here: an RG-transition refresh): the next crossing re-arms a
/// fresh hold instead of claiming on the stale one.
#[test]
fn hold_rearms_after_the_row_is_restamped_19026() {
    let (mut table, key) = restored_copy();
    let now = crossed();
    let shared = SharedModel::new(60, 0);
    assert!(expire(&mut table, now, true, &shared).is_empty(), "held");
    let (decision, metadata, _) = table.entry_with_origin(&key).expect("held row");
    assert!(table.refresh_for_ha_transition(&key, decision, metadata, now + SEC));
    let later = now + SEC + WINDOW_NS + 2 * SEC;
    assert!(
        expire(&mut table, now + HOLD_NS + 2 * SEC, true, &shared).is_empty(),
        "the stale hold does not claim a re-stamped row"
    );
    assert_eq!(shared.claims.get(), 0);
    assert!(expire(&mut table, later, true, &shared).is_empty(), "a fresh hold");
    let expired = expire(&mut table, later + HOLD_NS + 2 * SEC, true, &shared);
    assert_eq!(expired.len(), 1);
    assert_eq!(closes_for(&mut table, &key), 1, "the re-armed hold claims once");
}

/// Cell 5: the fence has not muted real expiry elsewhere: a standby node
/// still HOLDs, no HA context is standalone (ordinary Close), and a plain
/// local `ForwardFlow` row closes as before.
#[test]
fn fence_leaves_other_expiry_paths_unchanged_19026() {
    let shared = SharedModel::new(60, 0);
    let (mut standby, key) = restored_copy();
    assert!(expire(&mut standby, crossed(), false, &shared).is_empty(), "standby HOLD");
    assert!(standby.entry_by_key(&key).is_some());

    let (mut standalone, key) = restored_copy();
    standalone.last_gc_ns = 0;
    let expired = standalone.expire_stale_entries_ha(crossed(), None);
    assert_eq!(expired.len(), 1);
    assert!(!expired[0].close_fenced);
    assert_eq!(closes_for(&mut standalone, &key), 1, "no HA: ordinary Close");

    let mut table = SessionTable::new();
    let mut install = promoted_icmp_entry().into_session_install(INSTALL_NS);
    install.origin = SessionOrigin::ForwardFlow;
    install.session_id = 0;
    let local_key = install.key.clone();
    assert!(table.upsert_synced_with_origin(install, true));
    let expired = expire(&mut table, crossed(), true, &shared);
    assert_eq!(expired.len(), 1);
    assert!(!expired[0].close_fenced);
    assert_eq!(closes_for(&mut table, &local_key), 1, "a local ForwardFlow row closes");
    assert_eq!(shared.claims.get(), 0, "no claim outside the fence");
}

/// R14 G1 (cycle 3): a new local session that replaces an IDLE-CROSSED
/// restored copy (held by the fence or not yet visited) emits the old
/// session's Close through the close-retirement directory. Replacing a copy
/// still inside its window (including one re-stamped after a stale hold)
/// emits none: the ordinary silent Replace, as on master.
#[test]
fn local_install_over_a_held_restored_copy_closes_it_once_19026() {
    // (label, crossed, held by the fence, re-stamped after the hold, Closes)
    for (label, crossed_copy, held, restamped, closes) in [
        ("live", false, false, false, 0usize),
        // The fence has not visited it yet: still the old session's end.
        ("crossed, not yet held", true, false, false, 1),
        ("held", true, true, false, 1),
        // A hold armed before an RG-transition re-stamp is stale: the copy is
        // live again, so replacing it stays the ordinary silent Replace.
        ("held, then re-stamped live", true, true, true, 0),
    ] {
        let (mut table, key) = restored_copy();
        let (decision, metadata, origin) = table.entry_with_origin(&key).expect("copy");
        assert_eq!(origin, SessionOrigin::SharedPromote, "FIXTURE: a restored copy");
        let mut at = if crossed_copy { crossed() } else { INSTALL_NS + 10 * SEC };
        if held {
            let shared = SharedModel::new(60, 0);
            assert!(expire(&mut table, at, true, &shared).is_empty(), "FIXTURE: held");
            assert_eq!(table.promote_fence_hold_count(), 1, "FIXTURE: held");
            at += SEC;
        }
        if restamped {
            let (d, m, _) = table.entry_with_origin(&key).expect("held copy");
            assert!(table.refresh_for_ha_transition(&key, d, m, at), "FIXTURE: re-stamped");
            at += SEC;
        }
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision,
            metadata,
            SessionOrigin::ForwardFlow,
            at,
            crate::ip_proto::PROTO_ICMP,
            0,
        ));
        assert_ne!(
            table.entry_with_origin(&key).map(|(_, _, o)| o),
            Some(SessionOrigin::SharedPromote),
            "FIXTURE: the new local session replaced the copy"
        );
        assert_eq!(
            closes_for(&mut table, &key),
            closes,
            "#19026 R14 G1 ({label}): Close count for the replaced copy"
        );
    }
}
