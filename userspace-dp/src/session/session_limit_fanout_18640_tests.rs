// #18640: the per-source session cap is per worker, but HA session sync fans
// every peer session out to EVERY worker as a SyncImport copy
// (`afxdp/ha/session_import.rs`, the `UpsertSynced` fan-out loop). These cells
// model one node as N worker tables, the way the coordinator drives them.

use super::tests::{decision, metadata};
use super::*;
use std::net::Ipv4Addr;

const NOW: u64 = 1_000_000_000;
const WORKERS: u32 = 4;

fn src() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 62, 102))
}

fn fwd_key(port: u16) -> SessionKey {
    SessionKey {
        addr_family: 2,
        protocol: PROTO_UDP,
        src_ip: src(),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 210)),
        src_port: port,
        dst_port: 9,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn install(key: &SessionKey, origin: SessionOrigin, is_reverse: bool) -> SessionInstall {
    let mut meta = metadata();
    meta.owner_rg_id = 1;
    meta.is_reverse = is_reverse;
    SessionInstall {
        key: key.clone(),
        decision: decision(),
        metadata: meta,
        origin,
        now_ns: NOW,
        protocol: PROTO_UDP,
        tcp_flags: 0,
        session_id: 0,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        persistent_lease_hold: None,
        fwd_packets: 0,
        rev_packets: 0,
        source_nat_static: None,
    }
}

fn node_tables() -> Vec<SessionTable> {
    (0..WORKERS)
        .map(|i| {
            let mut t = SessionTable::new();
            t.set_session_limit_shard(i, WORKERS);
            t
        })
        .collect()
}

fn per_worker(tables: &[SessionTable]) -> Vec<u32> {
    tables
        .iter()
        .map(|t| t.session_limit_src_count(crate::test_zone_ids::TEST_LAN_ZONE_ID, src()))
        .collect()
}

/// Every table's count must equal the rows the production predicate charges
/// on that table (the census invariant, per worker).
fn assert_balanced(tables: &[SessionTable], label: &str) {
    assert_balanced_in(tables, crate::test_zone_ids::TEST_LAN_ZONE_ID, label);
}

/// `assert_balanced` for one ingress zone, plus no unmatched decrement anywhere.
fn assert_balanced_in(tables: &[SessionTable], zone: u32, label: &str) {
    for (i, t) in tables.iter().enumerate() {
        assert_eq!(t.session_limit_dec_underflows(), 0, "{label}: worker {i} decremented a count it never charged");
    }
    for (i, t) in tables.iter().enumerate() {
        let mut charged = 0u32;
        t.iter_with_origin(|key, _d, md, origin| {
            if md.ingress_zone == zone && key.src_ip == src() && t.session_limit_counted(key, origin, md.is_reverse) {
                charged += 1;
            }
        });
        assert_eq!(
            t.session_limit_src_count(zone, src()),
            charged,
            "{label}: worker {i} count in zone {zone} must equal the rows it is charged for"
        );
    }
}


fn node_sum(tables: &[SessionTable]) -> u32 {
    tables
        .iter()
        .map(|t| t.session_limit_src_count(crate::test_zone_ids::TEST_LAN_ZONE_ID, src()))
        .sum()
}

/// The standby: HA session sync installs each peer session (forward and
/// reverse) on EVERY worker. The node must charge each logical session ONCE,
/// spread across workers, not once per worker (pre-fix: 4 x S, every worker
/// at S, so a source the primary admitted under its per-worker cap was over
/// the cap on every worker after failover).
#[test]
fn fanned_out_peer_copies_charge_once_per_node_18640() {
    let mut tables = node_tables();
    let s = 64u16;
    for p in 0..s {
        let k = fwd_key(40000 + p);
        let rev = reverse_session_key(&k, NatDecision::default());
        for t in tables.iter_mut() {
            assert!(
                t.upsert_synced_with_origin(install(&k, SessionOrigin::SyncImport, false), false)
            );
            assert!(
                t.upsert_synced_with_origin(install(&rev, SessionOrigin::SyncImport, true), false)
            );
        }
    }
    assert_eq!(
        node_sum(&tables),
        u32::from(s),
        "each peer session charges the node once: {:?}",
        per_worker(&tables)
    );
    assert!(
        per_worker(&tables).iter().all(|c| *c < u32::from(s)),
        "no single worker carries the whole source: {:?}",
        per_worker(&tables)
    );
    assert_balanced(&tables, "after fan-out");
    // A re-import (snapshot resend) of every session nets to the same charge.
    for p in 0..s {
        let k = fwd_key(40000 + p);
        for t in tables.iter_mut() {
            assert!(
                t.upsert_synced_with_origin(install(&k, SessionOrigin::SyncImport, false), false)
            );
        }
    }
    assert_eq!(node_sum(&tables), u32::from(s));
    // The peer's deletes and this node's expiry both release the charge.
    for p in 0..s / 2 {
        let k = fwd_key(40000 + p);
        for t in tables.iter_mut() {
            t.delete(&k);
        }
    }
    assert_eq!(node_sum(&tables), u32::from(s / 2));
    assert_balanced(&tables, "after peer deletes");
    for t in tables.iter_mut() {
        let _ = t.expire_stale_entries(NOW + 3_600_000_000_000);
    }
    assert_eq!(
        node_sum(&tables),
        0,
        "expiry must release every charge: {:?}",
        per_worker(&tables)
    );
}

/// The old primary on failback: its owner rows and the sibling
/// WorkerLocalImport replicas are all re-tagged SyncImport by
/// `demote_owner_rg`. Pre-fix every worker then charged every session.
#[test]
fn demoted_replicas_charge_once_per_node_18640() {
    let mut tables = node_tables();
    let s = 64u16;
    for p in 0..s {
        let k = fwd_key(41000 + p);
        let owner = (p as usize) % tables.len();
        let mut meta = metadata();
        meta.owner_rg_id = 1;
        assert!(tables[owner].install_with_protocol_with_origin(
            k.clone(),
            decision(),
            meta,
            SessionOrigin::ForwardFlow,
            NOW,
            PROTO_UDP,
            0
        ));
        for (i, t) in tables.iter_mut().enumerate() {
            if i != owner {
                assert!(t.upsert_synced_with_origin(
                    install(&k, SessionOrigin::WorkerLocalImport, false),
                    false
                ));
            }
        }
    }
    assert_eq!(
        node_sum(&tables),
        u32::from(s),
        "primary: one charge per local session"
    );
    for t in tables.iter_mut() {
        let _ = t.demote_owner_rg(1);
    }
    assert_eq!(
        node_sum(&tables),
        u32::from(s),
        "after demotion still one charge per session: {:?}",
        per_worker(&tables)
    );
    assert_balanced(&tables, "after demotion");
    for t in tables.iter_mut() {
        let _ = t.expire_stale_entries(NOW + 3_600_000_000_000);
    }
    assert_eq!(node_sum(&tables), 0);
}

/// Failover: the worker the flow lands on promotes its copy; the copy on the
/// designated worker is then replaced by a WorkerLocalImport replica. The node
/// ends with exactly one charge, on the serving worker.
#[test]
fn promoted_copy_moves_the_charge_to_the_serving_worker_18640() {
    let mut tables = node_tables();
    let k = fwd_key(42000);
    for t in tables.iter_mut() {
        assert!(t.upsert_synced_with_origin(install(&k, SessionOrigin::SyncImport, false), false));
    }
    let designated = (0..tables.len())
        .find(|i| tables[*i].session_limit_counted(&k, SessionOrigin::SyncImport, false))
        .expect("one worker is designated");
    assert_eq!(
        (0..tables.len())
            .filter(|i| tables[*i].session_limit_counted(&k, SessionOrigin::SyncImport, false))
            .count(),
        1,
        "exactly one worker of the fan-out is designated"
    );
    let serving = (designated + 1) % tables.len();
    let mut meta = metadata();
    meta.owner_rg_id = 1;
    assert!(tables[serving].promote_synced_with_origin(SessionUpdate {
        key: &k,
        decision: decision(),
        metadata: meta,
        origin: SessionOrigin::SharedPromote,
        now_ns: NOW + 1_000,
        protocol: PROTO_UDP,
        tcp_flags: 0,
        ack: None,
    }));
    assert_eq!(
        per_worker(&tables)[serving],
        1,
        "the serving worker now charges the session"
    );
    assert_balanced(&tables, "after promote");
    for (i, t) in tables.iter_mut().enumerate() {
        if i != serving {
            assert!(t.upsert_synced_with_origin(
                install(&k, SessionOrigin::WorkerLocalImport, false),
                true
            ));
        }
    }
    assert_eq!(
        node_sum(&tables),
        1,
        "one charge, on the serving worker: {:?}",
        per_worker(&tables)
    );
    assert_balanced(&tables, "after sibling replicas");
}

/// Setting the slot after rows exist re-derives the counts, so a later
/// removal decrements exactly what the increment charged.
#[test]
fn shard_change_rebuilds_counts_18640() {
    let mut tables: Vec<SessionTable> = (0..WORKERS).map(|_| SessionTable::new()).collect();
    let s = 32u16;
    for p in 0..s {
        let k = fwd_key(43000 + p);
        for t in tables.iter_mut() {
            assert!(
                t.upsert_synced_with_origin(install(&k, SessionOrigin::SyncImport, false), false)
            );
        }
    }
    assert_eq!(
        node_sum(&tables),
        u32::from(s) * WORKERS,
        "unsharded tables charge every copy"
    );
    for (i, t) in tables.iter_mut().enumerate() {
        t.set_session_limit_shard(i as u32, WORKERS);
    }
    assert_eq!(node_sum(&tables), u32::from(s));
    assert_balanced(&tables, "after shard set");
    for p in 0..s {
        let k = fwd_key(43000 + p);
        for t in tables.iter_mut() {
            t.delete(&k);
        }
    }
    assert_eq!(node_sum(&tables), 0);
    assert!(
        tables.iter().all(|t| t.session_limit_src_map_len() == 0),
        "no phantom zero entries (#2128)"
    );
}

/// #3122 still holds across the fan-out: a source whose synced sessions
/// exceed the per-worker limit on every worker's share stays capped on every
/// worker after failover. The charges are spread, not dropped.
#[test]
fn synced_copies_still_enforce_the_cap_after_failover_18640() {
    let mut tables = node_tables();
    let limit = 2u32;
    let s = 64u16; // 16 per worker on average, far above the limit
    for p in 0..s {
        let k = fwd_key(44000 + p);
        for t in tables.iter_mut() {
            assert!(
                t.upsert_synced_with_origin(install(&k, SessionOrigin::SyncImport, false), false)
            );
        }
    }
    for (i, c) in per_worker(&tables).iter().enumerate() {
        assert!(
            *c >= limit,
            "worker {i} charges {c} synced sessions; the over-limit predicate must still fire on every worker: {:?}",
            per_worker(&tables)
        );
    }
}


/// Review W: the HA-transition refresh (the activation scan) must keep one charge
/// per node. Reverting its tail to the origin-only predicate charged every worker
/// (`[64, 64, 64, 64]`), the #18640 defect itself.
#[test]
fn ha_transition_refresh_keeps_one_charge_per_node_18640() {
    let mut tables = node_tables();
    let s = 64u16;
    for p in 0..s {
        let k = fwd_key(45000 + p);
        let rev = reverse_session_key(&k, NatDecision::default());
        for t in tables.iter_mut() {
            assert!(t.upsert_synced_with_origin(install(&k, SessionOrigin::SyncImport, false), false));
            assert!(t.upsert_synced_with_origin(install(&rev, SessionOrigin::SyncImport, true), false));
        }
    }
    assert_eq!(node_sum(&tables), u32::from(s));
    let mut meta = metadata();
    meta.owner_rg_id = 1;
    for p in 0..s {
        let k = fwd_key(45000 + p);
        for t in tables.iter_mut() {
            assert!(t.refresh_for_ha_transition(&k, decision(), meta.clone(), NOW + 1_000_000));
        }
    }
    assert_eq!(node_sum(&tables), u32::from(s), "after the HA refresh: {:?}", per_worker(&tables));
    assert!(per_worker(&tables).iter().all(|c| *c < u32::from(s)), "{:?}", per_worker(&tables));
    assert_balanced(&tables, "after the HA refresh");
}

/// Review W: an in-place zone move must move each charge once. Reverting the
/// zone moves to the origin-only predicate put 4 x S in the new zone.
#[test]
fn zone_move_moves_one_charge_per_node_18640() {
    let mut tables = node_tables();
    let s = 64u16;
    let lan = crate::test_zone_ids::TEST_LAN_ZONE_ID;
    let moved = crate::test_zone_ids::TEST_WAN_ZONE_ID;
    for p in 0..s {
        let k = fwd_key(46000 + p);
        // The pair rebinds need the reverse companion.
        let rev = reverse_session_key(&k, NatDecision::default());
        for t in tables.iter_mut() {
            assert!(t.upsert_synced_with_origin(install(&k, SessionOrigin::SyncImport, false), false));
            assert!(t.upsert_synced_with_origin(install(&rev, SessionOrigin::SyncImport, true), false));
        }
    }
    for p in 0..s {
        let k = fwd_key(46000 + p);
        for t in tables.iter_mut() {
            assert!(t.rebind_zones_pair(&k, moved, 0, lan, 0));
        }
    }
    let in_zone = |zone: u32| -> Vec<u32> { tables.iter().map(|t| t.session_limit_src_count(zone, src())).collect() };
    assert_eq!(in_zone(lan).iter().sum::<u32>(), 0, "nothing left in the old zone: {:?}", in_zone(lan));
    assert_eq!(in_zone(moved).iter().sum::<u32>(), u32::from(s), "one charge per session in the new zone: {:?}", in_zone(moved));
    assert_balanced_in(&tables, moved, "after the zone move");
    assert_balanced_in(&tables, lan, "old zone after the zone move");
}

/// Review W, the policy-pair twin: `rebind_policy_pair` also moves a counted
/// session's zone pair in place, and must move each charge once.
#[test]
fn policy_rebind_moves_one_charge_per_node_18640() {
    let mut tables = node_tables();
    let s = 64u16;
    let lan = crate::test_zone_ids::TEST_LAN_ZONE_ID;
    let moved = crate::test_zone_ids::TEST_WAN_ZONE_ID;
    for p in 0..s {
        let k = fwd_key(47000 + p);
        // The pair rebinds need the reverse companion.
        let rev = reverse_session_key(&k, NatDecision::default());
        for t in tables.iter_mut() {
            assert!(t.upsert_synced_with_origin(install(&k, SessionOrigin::SyncImport, false), false));
            assert!(t.upsert_synced_with_origin(install(&rev, SessionOrigin::SyncImport, true), false));
        }
    }
    let counter = std::sync::Arc::new(crate::policy::PolicyRuleCounter::default());
    for p in 0..s {
        let k = fwd_key(47000 + p);
        for t in tables.iter_mut() {
            assert!(t.rebind_policy_pair(&k, 7, 7, counter.clone(), moved, 0, lan, 0));
        }
    }
    let in_zone = |zone: u32| -> Vec<u32> { tables.iter().map(|t| t.session_limit_src_count(zone, src())).collect() };
    assert_eq!(in_zone(lan).iter().sum::<u32>(), 0, "{:?}", in_zone(lan));
    assert_eq!(in_zone(moved).iter().sum::<u32>(), u32::from(s), "{:?}", in_zone(moved));
    assert_balanced_in(&tables, moved, "after the policy rebind");
}
