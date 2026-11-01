//! #18550: a late peer re-import must revive an idle-lapsed worker replica
//! on the node that now forwards its RG.
//!
//! A worker row past its idle deadline is fail-closed at lookup:
//! `IdleCrossed` returns no hit and does NOT fall back to the shared row
//! (`shared_ops/lookup.rs`, `SessionExpiryProbe::IdleCrossed`). This is
//! deliberate (`session/entry.rs`, "its shared replica must not resurrect
//! it"). A same-id, same-TCP-state re-import keeps the row's inactivity
//! anchor (#16043), so before #18550 a late import landing on such a row
//! installed it, published its steering rows, and still left every lookup
//! missing until the wheel's SELF-HEAL visited the row. For a row in HOLD,
//! that visit is up to `HELD_RECHECK_HORIZON_NS` (255 s) away.
//!
//! The fix is confined to the node that forwards the owner RG
//! (`!allow_replace_local` in `handle_upsert_synced`) and to peer-synced rows
//! that are ALREADY crossed. Those rows are re-stamped exactly as the wheel's
//! SELF-HEAL arm would re-stamp them. The same import onto a reaped (absent)
//! row installs a fresh anchor anyway, so the fix removes a dependence on
//! wheel timing rather than granting new life. These are unchanged:
//! - the standby (HOLD semantics, #16880);
//! - a re-import landing on a still-live row (the #16043 anchor);
//! - an expired LOCAL row, which the install guard refuses.

use super::*;
use crate::session::SessionTable;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const RG: i32 = 1;
const SECS: u64 = 1_000_000_000;
const T0_SECS: u64 = 10_000;
const ESTABLISHED_WIRE: u8 = 4;
/// Past the 1800 s default established window.
const LAPSE_SECS: u64 = 1_801;
const SESSION_ID: u64 = 0x1855_0000_0001;
/// The activation epoch of RG 1 on this node (bumped at activation).
const RG_EPOCH: u32 = 3;
/// The node-level epoch (`rg_epochs[0]`). It deliberately DIFFERS from
/// `RG_EPOCH`, so a re-stamp that read the wrong RG's epoch records a value
/// the wheel's gate does not match, and the second SELF-HEAL shows.
const NODE_EPOCH: u32 = 9;

/// Per-RG epochs with the wheel's mapping: RG 1 has its own epoch, and every
/// other RG (0 / out of range) falls back to the node-level edge.
fn rg_epoch(rg: i32) -> u32 {
    if rg == RG { RG_EPOCH } else { NODE_EPOCH }
}

/// The worker's RG activation-epoch reader, as `worker_loop_setup` wires it.
fn epoch_table() -> SessionTable {
    let mut sessions = SessionTable::new();
    sessions.set_rg_epoch_reader(Arc::new(rg_epoch));
    sessions
}

fn active(now_secs: u64) -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([(
        RG,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: now_secs,
            lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
        },
    )])
}

fn standby() -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([(
        RG,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: 0,
            lease: HAForwardingLease::Inactive,
        },
    )])
}

fn forwarding() -> ForwardingState {
    let mut forwarding = crate::afxdp::testfx::test_forwarding_state();
    if let Some(wan) = forwarding.egress.get_mut(&12) {
        wan.primary_v6 = Some(wan_v6());
    }
    if let Some(lan) = forwarding.egress.get_mut(&6) {
        lan.primary_v6 = Some("2001:559:8585:ef00::1".parse().expect("lan v6"));
    }
    forwarding
}

fn wan_v6() -> Ipv6Addr {
    "2001:559:8585:80::8".parse().expect("wan v6")
}

/// Client -> iperf3 server, interface-SNAT'd to the WAN address, Established,
/// carrying a peer session id so the #16043 same-incarnation rule applies.
fn peer_forward(v6: bool, origin: SessionOrigin) -> SyncedSessionEntry {
    let (family, src, dst, snat) = if v6 {
        (
            libc::AF_INET6 as u8,
            IpAddr::V6("2001:559:8585:ef00::102".parse().expect("client v6")),
            IpAddr::V6("2001:559:8585:80::200".parse().expect("server v6")),
            IpAddr::V6(wan_v6()),
        )
    } else {
        (
            libc::AF_INET as u8,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        )
    };
    let mut metadata = crate::afxdp::testfx::test_metadata();
    metadata.owner_rg_id = RG;
    SyncedSessionEntry {
        key: SessionKey {
            addr_family: family,
            protocol: PROTO_TCP,
            src_ip: src,
            dst_ip: dst,
            src_port: 55_068,
            dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
        },
        decision: SessionDecision {
            resolution: crate::afxdp::testfx::test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(snat),
                rewrite_src_port: Some(40_001),
                ..NatDecision::default()
            },
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata,
        leak_incarnation: 0,
        origin,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: SESSION_ID,
        tcp_close_class: 0,
        tcp_handshake_state: ESTABLISHED_WIRE,
        rev_packets: 0,
        fwd_packets: 0,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
        source_nat_static: None,
    }
}

struct Fixture {
    forwarding: ForwardingState,
    sessions: SessionTable,
    shared: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    indexes: SharedSessionOwnerRgIndexes,
    forward_key: SessionKey,
    reply_key: SessionKey,
}

fn upsert(
    fx: &mut Fixture,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    entry: SyncedSessionEntry,
    now_secs: u64,
) {
    super::commands::handle_upsert_synced(
        &mut fx.sessions,
        SteeringMap::unshared_for_test(-1),
        &fx.forwarding,
        ha,
        &Arc::new(ShardedNeighborMap::new()),
        entry,
        now_secs * SECS,
        now_secs,
        0,
    );
}

/// The import pair as the coordinator fans it out: the forward entry and its
/// synthesized reverse companion, published to the shared maps and installed
/// on the worker at `T0`, while this node forwards the RG.
fn fixture(v6: bool) -> Fixture {
    let forwarding = forwarding();
    let forward = peer_forward(v6, SessionOrigin::SyncImport);
    let ha0 = active(T0_SECS);
    let reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
        &forwarding,
        &ha0,
        &Arc::new(ShardedNeighborMap::new()),
        &forward,
        T0_SECS,
    )
    .expect("fixture: reverse companion must synthesize");
    let mut fx = Fixture {
        forwarding,
        sessions: epoch_table(),
        shared: Arc::new(Mutex::new(FastMap::default())),
        shared_nat: Arc::new(Mutex::new(FastMap::default())),
        shared_forward_wire: Arc::new(Mutex::new(FastMap::default())),
        indexes: SharedSessionOwnerRgIndexes::default(),
        forward_key: forward.key.clone(),
        reply_key: reverse.key.clone(),
    };
    for entry in [&forward, &reverse] {
        crate::afxdp::shared_ops::publish_shared_session(
            &fx.shared,
            &fx.shared_nat,
            &fx.shared_forward_wire,
            &fx.indexes,
            entry,
        );
    }
    upsert(&mut fx, &ha0, forward, T0_SECS);
    upsert(&mut fx, &ha0, reverse, T0_SECS);
    assert!(
        fx.sessions.entry_with_origin(&fx.forward_key).is_some()
            && fx.sessions.entry_with_origin(&fx.reply_key).is_some(),
        "fixture: worker must hold both halves"
    );
    fx
}

/// The late import pair from the peer at `now_secs`. Same incarnation, same
/// TCP state. `liveness` marks the frame as primary liveness (#16880).
fn reimport(fx: &mut Fixture, v6: bool, ha: &BTreeMap<i32, HAGroupRuntime>, now_secs: u64) {
    let forward = peer_forward(v6, SessionOrigin::SyncLiveness);
    let reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
        &fx.forwarding,
        ha,
        &Arc::new(ShardedNeighborMap::new()),
        &forward,
        now_secs,
    )
    .expect("reverse companion");
    assert_eq!(reverse.key, fx.reply_key);
    upsert(fx, ha, forward, now_secs);
    upsert(fx, ha, reverse, now_secs);
}

/// The packet-path lookup (worker table, then shared fallback) for `key`.
fn hit(fx: &mut Fixture, key: &SessionKey, now_secs: u64) -> bool {
    crate::afxdp::shared_ops::lookup_session_across_scopes_with_shared_and_payload(
        &mut fx.sessions,
        &fx.shared,
        &fx.shared_nat,
        &fx.shared_forward_wire,
        &fx.indexes,
        key,
        now_secs * SECS,
        0x10,
        0,
    )
    .is_some()
}

fn assert_precondition_lapsed(fx: &mut Fixture, v6: bool, at: u64) {
    let (forward_key, reply_key) = (fx.forward_key.clone(), fx.reply_key.clone());
    assert!(
        fx.shared.lock().expect("shared").contains_key(&reply_key),
        "precondition: the shared row stays live"
    );
    assert!(
        !hit(fx, &forward_key, at) && !hit(fx, &reply_key, at),
        "precondition (v6={v6}): a lapsed worker row must miss even with a live shared row \
         (IdleCrossed is fail-closed); otherwise this fixture is not the shape under test"
    );
}

fn assert_late_reimport_revives(v6: bool) {
    let mut fx = fixture(v6);
    let t1 = T0_SECS + LAPSE_SECS;
    assert_precondition_lapsed(&mut fx, v6, t1);
    reimport(&mut fx, v6, &active(t1), t1);
    let (forward_key, reply_key) = (fx.forward_key.clone(), fx.reply_key.clone());
    assert!(
        hit(&mut fx, &reply_key, t1),
        "late peer re-import (v6={v6}) on the node that forwards the RG left the lapsed reply \
         row fail-closed: the server's segments miss and fall to the local-delivery path"
    );
    assert!(
        hit(&mut fx, &forward_key, t1),
        "late peer re-import (v6={v6}) left the lapsed forward row fail-closed"
    );
}

#[test]
fn late_reimport_revives_lapsed_replica_on_owner_v4_18550() {
    assert_late_reimport_revives(false);
}

#[test]
fn late_reimport_revives_lapsed_replica_on_owner_v6_18550() {
    assert_late_reimport_revives(true);
}

/// The wheel's HA view on the RG owner: RG 1 forwarded here at `RG_EPOCH`.
fn run_wheel(fx: &mut Fixture, now_secs: u64) -> (Vec<SessionKey>, crate::session::WheelPopStats) {
    let forwards_rg = |rg: i32| rg == RG || rg <= 0;
    let epoch_of = rg_epoch;
    let node_served = |_: &SessionKey| crate::session::NodeServedEvidence::default();
    let ctx = crate::session::ExpireHaContext {
        node_active: true,
        forwards_rg: &forwards_rg,
        epoch_of: &epoch_of,
        ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
        node_served: &node_served,
    };
    let expired = fx
        .sessions
        .expire_stale_entries_ha(now_secs * SECS, Some(&ctx))
        .into_iter()
        .map(|expired| expired.key)
        .collect();
    (expired, fx.sessions.last_pop_stats())
}

/// A revived row the flow has abandoned ages after ONE idle window. The
/// re-stamp spends the activation edge, as SELF-HEAL does. Without the epoch
/// the import's install reset `seen_rg_epoch` to 0, the wheel self-healed the
/// revived row a second time, and a dead flow lived about two windows.
///
/// The middle pass also proves the re-stamp re-bucketed the row. Its old
/// install-time wheel hint is now stale and dropped. If it were still live,
/// that pass would re-bucket the row itself.
fn assert_revived_dead_row_ages_once(v6: bool) {
    let mut fx = fixture(v6);
    // First GC initialises the wheel cursor at T0, before anything is due.
    let (expired, _) = run_wheel(&mut fx, T0_SECS);
    assert!(expired.is_empty());
    let t1 = T0_SECS + LAPSE_SECS;
    reimport(&mut fx, v6, &active(t1), t1);
    let (forward_key, reply_key) = (fx.forward_key.clone(), fx.reply_key.clone());
    let (_, forward_metadata, _) = fx
        .sessions
        .entry_with_origin(&forward_key)
        .expect("forward row");
    assert_eq!(
        forward_metadata.owner_rg_id, RG,
        "precondition: the forward row must be owned by RG {RG}, whose epoch differs from the \
         node epoch, or a re-stamp reading the wrong RG's epoch is unobservable"
    );

    let (expired, stats) = run_wheel(&mut fx, t1 + 10);
    assert!(
        expired.is_empty(),
        "revived row (v6={v6}) reaped before its new deadline"
    );
    assert_eq!(
        (stats.re_bucketed, stats.healed_on_promote),
        (0, 0),
        "after the re-stamp (v6={v6}) the wheel still found a live install-time hint for the          revived rows: the re-stamp did not re-bucket them"
    );

    let t2 = t1 + LAPSE_SECS + 1;
    let (expired, stats) = run_wheel(&mut fx, t2);
    assert_eq!(
        stats.healed_on_promote, 0,
        "revived dead row (v6={v6}) was self-healed a second time: the re-stamp did not          record the activation epoch"
    );
    assert!(
        expired.contains(&forward_key) && expired.contains(&reply_key),
        "revived dead row (v6={v6}) was not reaped one idle window after the re-stamp          (expired {expired:?})"
    );
    assert_eq!(
        expired.iter().filter(|key| **key == forward_key).count(),
        1,
        "forward half reaped more than once (v6={v6})"
    );
    assert!(fx.sessions.entry_with_origin(&forward_key).is_none());
    assert!(fx.sessions.entry_with_origin(&reply_key).is_none());
}

#[test]
fn revived_dead_row_ages_after_one_window_v4_18550() {
    assert_revived_dead_row_ages_once(false);
}

#[test]
fn revived_dead_row_ages_after_one_window_v6_18550() {
    assert_revived_dead_row_ages_once(true);
}

/// Control: on the standby a lapsed replica stays in HOLD. Liveness renews
/// only the HOLD anchor (#16880), and activation re-stamps the row.
fn assert_standby_keeps_lapsed(v6: bool) {
    let mut fx = fixture(v6);
    let t1 = T0_SECS + LAPSE_SECS;
    reimport(&mut fx, v6, &standby(), t1);
    let reply_key = fx.reply_key.clone();
    assert!(
        !hit(&mut fx, &reply_key, t1),
        "standby (v6={v6}) re-import re-anchored a held replica: #18550 must be confined to \
         the node that forwards the RG"
    );
}

#[test]
fn standby_reimport_keeps_lapsed_replica_held_v4_18550() {
    assert_standby_keeps_lapsed(false);
}

#[test]
fn standby_reimport_keeps_lapsed_replica_held_v6_18550() {
    assert_standby_keeps_lapsed(true);
}

/// Control (#16043): a re-import landing on a row that is still within its
/// window must not extend it. The anchor stays at T0, so the row lapses at
/// T0 + window even though the re-import came later.
fn assert_live_row_keeps_anchor(v6: bool) {
    let mut fx = fixture(v6);
    let t_mid = T0_SECS + 100;
    reimport(&mut fx, v6, &active(t_mid), t_mid);
    // Anchor T0 -> crossed at T0 + 1801. A re-anchor at t_mid would still be
    // live here (t_mid + 1800 > T0 + 1850).
    let probe = T0_SECS + 1_850;
    let reply_key = fx.reply_key.clone();
    assert!(
        !hit(&mut fx, &reply_key, probe),
        "re-import (v6={v6}) on a still-live row moved its inactivity anchor (#16043)"
    );
}

#[test]
fn reimport_on_live_row_keeps_inactivity_anchor_v4_18550() {
    assert_live_row_keeps_anchor(false);
}

#[test]
fn reimport_on_live_row_keeps_inactivity_anchor_v6_18550() {
    assert_live_row_keeps_anchor(true);
}

/// Control (`session/entry.rs` intent): an expired LOCAL session is not
/// resurrected by a peer import. The install guard refuses the replace while
/// this node forwards the RG, and the re-stamp never touches a local row.
fn assert_local_row_not_revived(v6: bool) {
    let local = peer_forward(v6, SessionOrigin::ForwardFlow);
    let mut fx = Fixture {
        forwarding: forwarding(),
        sessions: SessionTable::new(),
        shared: Arc::new(Mutex::new(FastMap::default())),
        shared_nat: Arc::new(Mutex::new(FastMap::default())),
        shared_forward_wire: Arc::new(Mutex::new(FastMap::default())),
        indexes: SharedSessionOwnerRgIndexes::default(),
        forward_key: local.key.clone(),
        reply_key: local.key.clone(),
    };
    assert!(fx.sessions.install_with_protocol_with_origin(
        local.key.clone(),
        local.decision,
        local.metadata.clone(),
        SessionOrigin::ForwardFlow,
        T0_SECS * SECS,
        PROTO_TCP,
        0x10,
    ));
    let t1 = T0_SECS + LAPSE_SECS;
    assert!(
        !fx.sessions
            .restamp_lapsed_peer_synced(&local.key, t1 * SECS),
        "the re-stamp must refuse a LOCAL row (v6={v6})"
    );
    let forward = peer_forward(v6, SessionOrigin::SyncLiveness);
    upsert(&mut fx, &active(t1), forward, t1);
    let (_, _, origin) = fx
        .sessions
        .entry_with_origin(&local.key)
        .expect("local row");
    assert_eq!(origin, SessionOrigin::ForwardFlow);
    let key = local.key.clone();
    assert!(
        !hit(&mut fx, &key, t1),
        "a lapsed LOCAL session (v6={v6}) was resurrected by a peer import"
    );
}

#[test]
fn lapsed_local_row_is_not_revived_by_peer_import_v4_18550() {
    assert_local_row_not_revived(false);
}

#[test]
fn lapsed_local_row_is_not_revived_by_peer_import_v6_18550() {
    assert_local_row_not_revived(true);
}
