use super::*;
use crate::afxdp::testfx::{test_metadata, test_resolution};
use crate::ip_proto::PROTO_TCP;
use crate::nat::{
    NatHolder, NatScopeCtx, PersistentNatPermit, PersistentSourceKey, PersistentLeaseHold,
    SourceNatFlowKey, TranslatedTuple, match_source_nat_result_for_tuple,
    parse_source_nat_rules, release_recorded_persistent_inbound_hold,
    release_source_nat_allocation, release_source_nat_allocation_for_worker_with_hold,
};
use crate::session::{SessionDecision, SessionKey, SessionOrigin, SessionTable};
use crate::afxdp::ForwardingState;
use crate::SourceNATRuleSnapshot;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

const NOW_NS: u64 = 10_000_000_000;
const INTERNAL_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, 100));
const REMOTE_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
const INTERNAL_PORT: u16 = 12_345;
const REMOTE_PORT: u16 = 443;

struct LeaseFixture {
    forwarding: ForwardingState,
    source_key: PersistentSourceKey,
    outbound_key: SessionKey,
    outbound_nat: crate::nat::NatDecision,
    translated: TranslatedTuple,
    shared_entry: crate::afxdp::SyncedSessionEntry,
}

fn lease_fixture(now_ns: u64) -> LeaseFixture {
    let mut forwarding = crate::afxdp::testfx::test_forwarding_state();
    forwarding.source_nat_rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "persistent-pool-17683".into(),
        from_zone: "lan".into(),
        to_zone: "wan".into(),
        source_addresses: vec!["0.0.0.0/0".into()],
        pool_name: "persistent-pool-17683".into(),
        pool_addresses: vec!["203.0.113.10/32".into()],
        port_low: 40_000,
        port_high: 40_000,
        persistent_nat: true,
        persistent_nat_permit_any_remote_host: true,
        persistent_nat_inactivity_timeout: 1,
        ..SourceNATRuleSnapshot::default()
    }]);

    let mut counter = None;
    let outbound_nat = match match_source_nat_result_for_tuple(
        &forwarding.iface_nat_allocators,
        &forwarding.source_nat_rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        INTERNAL_IP,
        REMOTE_IP,
        Some(PROTO_TCP),
        INTERNAL_PORT,
        REMOTE_PORT,
        None,
        None,
        now_ns,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    ) {
        crate::nat::SourceNatLookup::Matched(nat) => nat,
        other => panic!("persistent source NAT allocation failed: {other:?}"),
    };
    let translated = TranslatedTuple {
        ip: outbound_nat.rewrite_src.expect("translated source address"),
        port: outbound_nat.rewrite_src_port.expect("translated source port"),
    };
    let source_key = PersistentSourceKey {
        protocol: PROTO_TCP,
        src_ip: INTERNAL_IP,
        src_port: INTERNAL_PORT,
        routing_scope: 0,
        remote: None,
    };
    let outbound_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: INTERNAL_IP,
        dst_ip: REMOTE_IP,
        src_port: INTERNAL_PORT,
        dst_port: REMOTE_PORT,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    release_source_nat_allocation(
        &forwarding.iface_nat_allocators,
        &forwarding.source_nat_rules,
        &outbound_key,
        outbound_nat,
        false,
        now_ns + 1,
    );

    let inbound_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: REMOTE_IP,
        dst_ip: translated.ip,
        src_port: REMOTE_PORT,
        dst_port: translated.port,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let mut metadata = test_metadata();
    metadata.is_reverse = false;
    metadata.owner_rg_id = 1;
    let shared_entry = crate::afxdp::SyncedSessionEntry {
        key: inbound_key,
        decision: SessionDecision {
            resolution: test_resolution(),
            nat: crate::nat::NatDecision {
                rewrite_dst: Some(INTERNAL_IP),
                rewrite_dst_port: Some(INTERNAL_PORT),
                ..crate::nat::NatDecision::default()
            },
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata,
        source_nat_static: None,
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: crate::tcp_flags::TCP_ACK,
        generation: 0,
        session_id: 17_683,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        rev_packets: 0,
        fwd_packets: 0,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
    };

    LeaseFixture {
        forwarding,
        source_key,
        outbound_key,
        outbound_nat,
        translated,
        shared_entry,
    }
}

fn acquire_owner_hold(fixture: &LeaseFixture, now_ns: u64) -> PersistentLeaseHold {
    fixture.forwarding.source_nat_rules[0]
        .pool_allocator
        .acquire_persistent_inbound_with_hold(fixture.source_key, now_ns)
        .expect("owner hold on minted lease")
}

fn shared_entry_with_owner_hold(
    fixture: &LeaseFixture,
    hold: PersistentLeaseHold,
) -> crate::afxdp::SyncedSessionEntry {
    let mut entry = fixture.shared_entry.clone();
    entry.persistent_lease_hold = Some(hold);
    entry
}

fn inbound_count(fixture: &LeaseFixture) -> u32 {
    fixture.forwarding.source_nat_rules[0]
        .pool_allocator
        .debug_persistent_lease_for_flow(
            &SourceNatFlowKey {
                protocol: PROTO_TCP,
                src_ip: INTERNAL_IP,
                dst_ip: REMOTE_IP,
                src_port: INTERNAL_PORT,
                dst_port: REMOTE_PORT,
                routing_scope: 0,
            },
            PersistentNatPermit::AnyRemoteHost,
        )
        .expect("persistent lease remains installed")
        .inbound_flows
}

fn materialize(
    sessions: &mut SessionTable,
    entry: crate::afxdp::SyncedSessionEntry,
    forwarding: &ForwardingState,
    now_ns: u64,
) -> bool {
    let mut resolved = crate::afxdp::session_glue::ResolvedSessionLookup::shared(entry);
    let (_, install_failed) =
        super::resolve::materialize_shared_session_hit_adopted(
            sessions,
            &mut resolved,
            forwarding,
            now_ns,
            crate::tcp_flags::TCP_ACK,
            false,
        );
    install_failed
}

#[test]
fn shared_hit_then_ha_upsert_keeps_independent_replica_holds_17683() {
    let fixture = lease_fixture(NOW_NS);
    let owner_hold = acquire_owner_hold(&fixture, NOW_NS + 2);
    let shared = shared_entry_with_owner_hold(&fixture, owner_hold);
    let mut replica_a = SessionTable::new();
    let mut replica_b = SessionTable::new();

    assert!(!materialize(
        &mut replica_a,
        shared.clone(),
        &fixture.forwarding,
        NOW_NS + 3,
    ));
    assert!(!materialize(
        &mut replica_b,
        shared.clone(),
        &fixture.forwarding,
        NOW_NS + 4,
    ));
    assert_eq!(inbound_count(&fixture), 3, "owner plus both materialized replicas");
    assert_eq!(replica_a.persistent_lease_hold_for(&shared.key), Some(owner_hold));
    assert_eq!(replica_b.persistent_lease_hold_for(&shared.key), Some(owner_hold));

    let mut ha_state = BTreeMap::new();
    super::commands::handle_upsert_synced(
        &mut replica_a,
        SteeringMap::unshared_for_test(-1),
        &fixture.forwarding,
        &mut ha_state,
        &Arc::new(crate::afxdp::ShardedNeighborMap::new()),
        shared.clone(),
        NOW_NS + 5,
        1,
        1,
    );

    assert_eq!(inbound_count(&fixture), 3, "HA upsert must not duplicate A's local reference");
    assert_eq!(replica_a.persistent_lease_hold_for(&shared.key), Some(owner_hold));
    assert_eq!(replica_b.persistent_lease_hold_for(&shared.key), Some(owner_hold));
    // Model replacement after the local reference was released and the new
    // forwarding snapshot no longer contains its allocator.
    assert!(release_recorded_persistent_inbound_hold(
        &fixture.forwarding.source_nat_rules,
        owner_hold,
        NOW_NS + 6,
    ));
    assert_eq!(inbound_count(&fixture), 2);
    let mut forwarding_without_pool = fixture.forwarding.clone();
    forwarding_without_pool.source_nat_rules.clear();
    let mut replacement = shared.clone();
    replacement.decision.nat = crate::nat::NatDecision::default();
    replacement.persistent_lease_hold = None;
    super::commands::handle_upsert_synced(
        &mut replica_a,
        SteeringMap::unshared_for_test(-1),
        &forwarding_without_pool,
        &ha_state,
        &Arc::new(crate::afxdp::ShardedNeighborMap::new()),
        replacement,
        NOW_NS + 7,
        1,
        1,
    );
    assert_eq!(
        replica_a.persistent_lease_hold_for(&shared.key),
        None,
        "replacement without an acquired hold must clear the stale stored token",
    );
    assert_eq!(replica_b.persistent_lease_hold_for(&shared.key), Some(owner_hold));
}

#[test]
fn materialized_shared_wire_alias_releases_replaced_incumbent_hold_17683() {
    let fixture = lease_fixture(NOW_NS);
    let owner_hold = acquire_owner_hold(&fixture, NOW_NS + 2);
    let mut shared = shared_entry_with_owner_hold(&fixture, owner_hold);
    shared.decision.nat.rewrite_src =
        Some(IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 2)));
    shared.decision.nat.rewrite_src_port = Some(50_001);
    let wire_key = crate::session::forward_wire_key(&shared.key, shared.decision.nat);
    assert_ne!(wire_key, shared.key, "fixture must exercise a forward wire alias");

    let shared_sessions = Arc::new(std::sync::Mutex::new(crate::afxdp::FastMap::default()));
    let shared_nat_sessions = Arc::new(std::sync::Mutex::new(crate::afxdp::FastMap::default()));
    let shared_forward_wire_sessions =
        Arc::new(std::sync::Mutex::new(crate::afxdp::FastMap::default()));
    let owner_indexes = crate::afxdp::SharedSessionOwnerRgIndexes::default();
    crate::afxdp::shared_ops::publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &owner_indexes,
        &shared,
    );
    let alias_hit = crate::afxdp::shared_ops::lookup_shared_forward_wire_match(
        &shared_forward_wire_sessions,
        &owner_indexes,
        &wire_key,
    )
    .expect("wire alias resolves to the canonical shared entry");
    assert_eq!(alias_hit.key, shared.key);

    let mut sessions = SessionTable::new();
    assert!(
        fixture.forwarding.source_nat_rules[0]
            .pool_allocator
            .acquire_persistent_inbound_for_hold(owner_hold, fixture.translated, NOW_NS + 3),
        "seed an independently-held local incumbent"
    );
    let mut incumbent = alias_hit.clone();
    incumbent.origin = SessionOrigin::ForwardFlow;
    assert!(sessions.upsert_synced_with_origin(
        incumbent.into_session_install(NOW_NS + 3),
        true,
    ));
    assert_eq!(inbound_count(&fixture), 2, "publisher and local incumbent own holds");

    let mut resolved = crate::afxdp::session_glue::ResolvedSessionLookup::shared(alias_hit);
    let (_, install_failed) =
        super::resolve::materialize_shared_session_hit_adopted(
            &mut sessions,
            &mut resolved,
            &fixture.forwarding,
            NOW_NS + 4,
            crate::tcp_flags::TCP_ACK,
            true,
        );
    assert!(!install_failed, "shared materialization replaces the adopted incumbent");
    assert_eq!(
        inbound_count(&fixture),
        2,
        "replacement must release its incumbent after acquiring the new local hold"
    );

    let replica_hold = sessions
        .persistent_lease_hold_for(&shared.key)
        .expect("materialized entry owns one local reference");
    sessions.delete(&shared.key);
    assert!(release_recorded_persistent_inbound_hold(
        &fixture.forwarding.source_nat_rules,
        replica_hold,
        NOW_NS + 5,
    ));
    assert!(release_recorded_persistent_inbound_hold(
        &fixture.forwarding.source_nat_rules,
        owner_hold,
        NOW_NS + 6,
    ));
    assert_eq!(
        inbound_count(&fixture),
        0,
        "teardown of the replica and publisher leaves no orphaned reference"
    );
}

#[test]
fn expiring_replica_b_releases_only_b_persistent_hold_17683() {
    let fixture = lease_fixture(NOW_NS);
    let owner_hold = acquire_owner_hold(&fixture, NOW_NS + 2);
    let shared = shared_entry_with_owner_hold(&fixture, owner_hold);
    let mut replica_a = SessionTable::new();
    let mut replica_b = SessionTable::new();
    replica_b.set_timeouts(crate::session::SessionTimeouts::from_seconds(1, 0, 0));

    assert!(!materialize(
        &mut replica_a,
        shared.clone(),
        &fixture.forwarding,
        NOW_NS + 3,
    ));
    assert!(!materialize(
        &mut replica_b,
        shared,
        &fixture.forwarding,
        NOW_NS + 4,
    ));
    assert_eq!(inbound_count(&fixture), 3);

    let expiry_ns = NOW_NS + 10_000_000_000;
    let expired = replica_b.expire_stale_entries(expiry_ns);
    assert_eq!(expired.len(), 1, "replica B's local session expires");
    let expired = expired.into_iter().next().expect("expired B session");
    assert_eq!(expired.persistent_lease_hold, Some(owner_hold));
    release_source_nat_allocation_for_worker_with_hold(
        &fixture.forwarding.iface_nat_allocators,
        &fixture.forwarding.source_nat_rules,
        &expired.key,
        expired.decision.nat,
        expired.metadata.is_reverse,
        expiry_ns,
        1,
        expired.persistent_lease_hold,
    );

    assert_eq!(inbound_count(&fixture), 2, "owner and replica A remain referenced");
    assert_eq!(replica_a.persistent_lease_hold_for(&expired.key), Some(owner_hold));
    assert_eq!(replica_b.len(), 0);
}

#[test]
fn stale_shared_hold_cannot_materialize_a_local_entry_17683() {
    let fixture = lease_fixture(NOW_NS);
    let owner_hold = acquire_owner_hold(&fixture, NOW_NS + 2);
    let mut stale_shared = shared_entry_with_owner_hold(&fixture, owner_hold);
    stale_shared.key.dst_port = stale_shared.key.dst_port.wrapping_add(1);
    let mut local = SessionTable::new();

    assert!(materialize(
        &mut local,
        stale_shared,
        &fixture.forwarding,
        NOW_NS + 3,
    ));
    assert_eq!(local.len(), 0, "a stale recorded tuple is not installed");
    assert_eq!(inbound_count(&fixture), 1, "failed acquire does not add a local ref");
}

#[test]
fn stale_hold_cannot_release_same_key_reminted_lease_17683() {
    let fixture = lease_fixture(NOW_NS);
    let allocator = &fixture.forwarding.source_nat_rules[0].pool_allocator;
    let owner_hold = acquire_owner_hold(&fixture, NOW_NS + 2);
    let shared = shared_entry_with_owner_hold(&fixture, owner_hold);
    let mut old_replica = SessionTable::new();
    old_replica.set_timeouts(crate::session::SessionTimeouts::from_seconds(1, 0, 0));
    assert!(!materialize(
        &mut old_replica,
        shared,
        &fixture.forwarding,
        NOW_NS + 3,
    ));
    let expired_at = NOW_NS + 10_000_000_000;
    let expired = old_replica
        .expire_stale_entries(expired_at)
        .into_iter()
        .next()
        .expect("old replica session expires");
    let stale_hold = expired.persistent_lease_hold.expect("old replica hold");
    release_source_nat_allocation_for_worker_with_hold(
        &fixture.forwarding.iface_nat_allocators,
        &fixture.forwarding.source_nat_rules,
        &expired.key,
        expired.decision.nat,
        expired.metadata.is_reverse,
        expired_at,
        1,
        Some(stale_hold),
    );
    assert_eq!(inbound_count(&fixture), 1);
    release_source_nat_allocation_for_worker_with_hold(
        &fixture.forwarding.iface_nat_allocators,
        &fixture.forwarding.source_nat_rules,
        &fixture.shared_entry.key,
        fixture.shared_entry.decision.nat,
        false,
        expired_at + 1,
        2,
        Some(owner_hold),
    );
    assert_eq!(inbound_count(&fixture), 0);

    // The single-port pool and same flow force the re-mint to reuse the exact
    // PersistentSourceKey and translated tuple after the idle lease expires.
    // #16035: small pools quarantine reclaimed ports for 60s; cross that window
    // before re-minting to exercise a same-key, same-tuple lease incarnation.
    const SMALL_POOL_REUSE_DELAY_NS: u64 = 60_000_000_000;
    let reclaim_ns = expired_at + 2_000_000_000;
    assert_eq!(
        allocator.debug_gc_expired_chunked(reclaim_ns, 1),
        1,
        "expired idle lease must be reclaimed before same-key re-mint",
    );
    let remint_ns = reclaim_ns + SMALL_POOL_REUSE_DELAY_NS + 1;
    let mut counter = None;
    let reminted_nat = match match_source_nat_result_for_tuple(
        &fixture.forwarding.iface_nat_allocators,
        &fixture.forwarding.source_nat_rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        INTERNAL_IP,
        REMOTE_IP,
        Some(PROTO_TCP),
        INTERNAL_PORT,
        REMOTE_PORT,
        None,
        None,
        remint_ns,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    ) {
        crate::nat::SourceNatLookup::Matched(nat) => nat,
        other => panic!("same-flow lease re-mint failed: {other:?}"),
    };
    let new_hold = allocator
        .acquire_persistent_inbound_with_hold(fixture.source_key, remint_ns + 1)
        .expect("new lease hold");
    assert_eq!(new_hold.key, stale_hold.key);
    assert_eq!(new_hold.allocator_id, stale_hold.allocator_id);
    assert_ne!(new_hold.incarnation, stale_hold.incarnation);
    assert_eq!(
        TranslatedTuple {
            ip: reminted_nat.rewrite_src.expect("reminted address"),
            port: reminted_nat.rewrite_src_port.expect("reminted port"),
        },
        fixture.translated,
        "the test exercises a same-key, same-tuple re-mint",
    );

    release_source_nat_allocation_for_worker_with_hold(
        &fixture.forwarding.iface_nat_allocators,
        &fixture.forwarding.source_nat_rules,
        &expired.key,
        expired.decision.nat,
        expired.metadata.is_reverse,
        remint_ns + 2,
        1,
        Some(stale_hold),
    );
    assert_eq!(inbound_count(&fixture), 1, "stale handle cannot decrement the re-mint");
    release_source_nat_allocation_for_worker_with_hold(
        &fixture.forwarding.iface_nat_allocators,
        &fixture.forwarding.source_nat_rules,
        &fixture.shared_entry.key,
        fixture.shared_entry.decision.nat,
        false,
        remint_ns + 3,
        1,
        Some(new_hold),
    );
    release_source_nat_allocation(
        &fixture.forwarding.iface_nat_allocators,
        &fixture.forwarding.source_nat_rules,
        &fixture.outbound_key,
        reminted_nat,
        false,
        remint_ns + 4,
    );
}
