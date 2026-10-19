//! #14669: handle_upsert_synced must derive HA ownership locally.
//!
//! The peer's stamped owner_rg_id and cached resolution are node-local
//! facts on the sender, not this node. Pre-fix handle_upsert_synced
//! computed allow_replace_local/is_active from the peer stamp before
//! re-resolving, served the peer's LocalDelivery verbatim, and leaked
//! the replaced reservation when the NAT target moved pools.

use super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const NOW_NS: u64 = 1_000_000_000;
const NOW_SECS: u64 = 1;
const RG1_IFINDEX: i32 = 12;
const RG2_IFINDEX: i32 = 13;
const FOREIGN_LOCAL_IFINDEX: i32 = 99;

fn active_rg(now: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now,
        lease: HAGroupRuntime::active_lease_until(now, now),
    }
}
fn inactive_rg() -> HAGroupRuntime {
    HAGroupRuntime {
        active: false,
        watchdog_timestamp: 0,
        lease: HAForwardingLease::Inactive,
    }
}

/// Two egresses: RG1 on 12 (route to 8.8.8.8), RG2 on 13 (route to 9.9.9.9),
/// plus a local address 10.0.0.1 on ifindex 12.
fn split_rg_forwarding() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        RG1_IFINDEX,
        EgressInterface {
            bind_ifindex: RG1_IFINDEX,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0, 0, 0, 0, 12],
            zone_id: 2,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 50, 1)),
            primary_v6: None,
        },
    );
    forwarding.egress.insert(
        RG2_IFINDEX,
        EgressInterface {
            bind_ifindex: RG2_IFINDEX,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0, 0, 0, 0, 13],
            zone_id: 2,
            redundancy_group: 2,
            primary_v4: Some(Ipv4Addr::new(172, 16, 60, 1)),
            primary_v6: None,
        },
    );
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(ipnet::Ipv4Net::new(Ipv4Addr::new(172, 16, 50, 0), 24).unwrap()),
        host: Ipv4Addr::new(172, 16, 50, 0),
        ifindex: RG1_IFINDEX,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(ipnet::Ipv4Net::new(Ipv4Addr::new(172, 16, 60, 0), 24).unwrap()),
        host: Ipv4Addr::new(172, 16, 60, 0),
        ifindex: RG2_IFINDEX,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding
        .routes_v4
        .entry("inet.0".to_string())
        .or_default()
        .push(RouteEntryV4::single(
            PrefixV4::from_net(ipnet::Ipv4Net::new(Ipv4Addr::new(8, 8, 8, 8), 32).unwrap()),
            RG1_IFINDEX,
            0,
            Some(Ipv4Addr::new(172, 16, 50, 254)),
            false,
            String::new(),
            1,
        ));
    forwarding
        .routes_v4
        .entry("inet.0".to_string())
        .or_default()
        .push(RouteEntryV4::single(
            PrefixV4::from_net(ipnet::Ipv4Net::new(Ipv4Addr::new(9, 9, 9, 9), 32).unwrap()),
            RG2_IFINDEX,
            0,
            Some(Ipv4Addr::new(172, 16, 60, 254)),
            false,
            String::new(),
            1,
        ));
    forwarding.neighbors.insert(
        (RG1_IFINDEX, IpAddr::V4(Ipv4Addr::new(172, 16, 50, 254))),
        NeighborEntry {
            mac: [0, 0, 0, 0, 0, 1],
        },
    );
    forwarding.neighbors.insert(
        (RG2_IFINDEX, IpAddr::V4(Ipv4Addr::new(172, 16, 60, 254))),
        NeighborEntry {
            mac: [0, 0, 0, 0, 0, 2],
        },
    );
    let local = Ipv4Addr::new(10, 0, 0, 1);
    forwarding.local_v4.insert(local);
    forwarding
        .local_tables_v4
        .entry(local)
        .or_default()
        .insert("inet.0".to_string());
    forwarding
}

fn split_ha() -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([(1, inactive_rg()), (2, active_rg(NOW_SECS))])
}

fn key_for(dst: Ipv4Addr) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(dst),
        src_port: 55068,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn metadata(owner: i32) -> SessionMetadata {
    SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: owner,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        nat_scope_ifindex: None,
    }
}

fn peer_resolution() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::NoRoute,
        local_ifindex: FOREIGN_LOCAL_IFINDEX,
        egress_ifindex: FOREIGN_LOCAL_IFINDEX,
        tx_ifindex: FOREIGN_LOCAL_IFINDEX,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: Some([0xaa; 6]),
        src_mac: Some([0xbb; 6]),
        tx_vlan_id: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    }
}

fn synced_entry(
    key: SessionKey,
    owner: i32,
    resolution: ForwardingResolution,
    nat: NatDecision,
) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key,
        decision: SessionDecision {
            resolution,
            nat,
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata: metadata(owner),
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        pptp_call_ids: 0,
        source_nat_static: None,
    }
}

fn apply_upsert(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    entry: SyncedSessionEntry,
) {
    super::commands::handle_upsert_synced(
        sessions,
        SteeringMap::unshared_for_test(-1),
        forwarding,
        ha,
        &Arc::new(ShardedNeighborMap::new()),
        entry,
        NOW_NS,
        NOW_SECS,
        0,
    );
}

/// Case A: peer stamps owner 0, local route is via standby RG1, but RG2 is
/// locally active. Pre-fix: synced_entry_allows_local_replace(0)=false
/// (any RG active) so is_active=true, enforce turns the RG1 resolution
/// HAInactive and the entry keeps the peer's foreign resolution + owner 0.
/// Post-fix: local owner 1 is derived first, allow_replace=true,
/// is_active=false, so the locally resolved ForwardCandidate is stored.
#[test]
fn upsert_synced_owner_zero_standby_rg_stores_local_candidate_14669() {
    let forwarding = split_rg_forwarding();
    let ha = split_ha();
    let mut sessions = SessionTable::new();
    let key = key_for(Ipv4Addr::new(8, 8, 8, 8));
    apply_upsert(
        &mut sessions,
        &forwarding,
        &ha,
        synced_entry(key.clone(), 0, peer_resolution(), NatDecision::default()),
    );
    let (decision, meta, _) = sessions
        .entry_with_origin(&key)
        .expect("synced session must be installed");
    assert_eq!(meta.owner_rg_id, 1, "local re-resolution must stamp RG1");
    assert_eq!(
        decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate,
        "standby RG1 session must store the local candidate, not HAInactive/peer state"
    );
    assert_eq!(decision.resolution.egress_ifindex, RG1_IFINDEX);
}

/// Case B: peer stamps standby RG1, but local route is via active RG2 and a
/// live local session occupies the key. Pre-fix allow_replace_local=true
/// (stale) clobbers it. Post-fix the recomputed guard (RG2 active) refuses.
#[test]
fn upsert_synced_stale_standby_stamp_does_not_clobber_active_local_14669() {
    let forwarding = split_rg_forwarding();
    let ha = split_ha();
    let mut sessions = SessionTable::new();
    let key = key_for(Ipv4Addr::new(9, 9, 9, 9));
    // Live locally-owned session on active RG2.
    let local_nat = NatDecision::default();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: RG2_IFINDEX,
                tx_ifindex: RG2_IFINDEX,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 60, 254))),
                neighbor_mac: Some([0, 0, 0, 0, 0, 2]),
                src_mac: Some([0x02, 0, 0, 0, 0, 13]),
                tx_vlan_id: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: local_nat,
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata(2),
        SessionOrigin::ForwardFlow,
        NOW_NS,
        PROTO_TCP,
        0x10,
    ));
    apply_upsert(
        &mut sessions,
        &forwarding,
        &ha,
        synced_entry(key.clone(), 1, peer_resolution(), NatDecision::default()),
    );
    let (_, meta, origin) = sessions
        .entry_with_origin(&key)
        .expect("local session must survive");
    assert!(
        !origin.is_peer_synced(),
        "peer upsert with stale standby stamp must not replace the active local session"
    );
    assert_eq!(meta.owner_rg_id, 2);
}

/// Flaw 2: peer-cached LocalDelivery with a foreign local_ifindex for a
/// transit destination (not local here) must not be served verbatim.
/// Locally 8.8.8.8 routes via RG1, so the stored resolution must be the
/// local ForwardCandidate on RG1, never LocalDelivery on ifindex 99.
#[test]
fn upsert_synced_peer_local_delivery_not_trusted_14669() {
    let forwarding = split_rg_forwarding();
    let ha = split_ha();
    let mut sessions = SessionTable::new();
    let key = key_for(Ipv4Addr::new(8, 8, 8, 8));
    let mut cached = peer_resolution();
    cached.disposition = ForwardingDisposition::LocalDelivery;
    apply_upsert(
        &mut sessions,
        &forwarding,
        &ha,
        synced_entry(key.clone(), 1, cached, NatDecision::default()),
    );
    let (decision, _, _) = sessions
        .entry_with_origin(&key)
        .expect("synced session must be installed");
    assert_ne!(
        decision.resolution.local_ifindex, FOREIGN_LOCAL_IFINDEX,
        "peer local_ifindex must never be retained"
    );
    assert_eq!(
        decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(decision.resolution.egress_ifindex, RG1_IFINDEX);
}

/// Flaw 3: Pool A -> Pool B replacement must release Pool A's reservation.
/// Both pools share the translated address (distinct allocators); the new
/// entry's zone pair selects Pool B. Pre-fix new_entry_reserves=true skips
/// the release and reserve_flow only touches B, stranding A's port.
#[test]
fn upsert_synced_cross_pool_replacement_releases_old_pool_14669() {
    let mut forwarding = split_rg_forwarding();
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding.zone_name_to_id.insert("lan".to_string(), 1);
    forwarding.zone_name_to_id.insert("wan".to_string(), 2);
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
        crate::SourceNATRuleSnapshot {
            name: "snat-a".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-a".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20000,
            ..crate::SourceNATRuleSnapshot::default()
        },
        crate::SourceNATRuleSnapshot {
            name: "snat-b".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-b".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20000,
            ..crate::SourceNATRuleSnapshot::default()
        },
    ]);
    forwarding.zone_id_to_name.insert(3, "dmz".to_string());
    forwarding.zone_name_to_id.insert("dmz".to_string(), 3);

    let ha = split_ha();
    let mut sessions = SessionTable::new();
    let key = key_for(Ipv4Addr::new(8, 8, 8, 8));
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        rewrite_src_port: Some(20000),
        ..NatDecision::default()
    };
    // First import: lan->wan selects Pool A.
    let mut first = synced_entry(key.clone(), 1, peer_resolution(), nat);
    first.metadata.ingress_zone = 1;
    first.metadata.egress_zone = 2;
    apply_upsert(&mut sessions, &forwarding, &ha, first);
    let used_a = crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[0].used_ports;
    let used_b = crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[1].used_ports;
    assert_eq!(used_a, 1, "precondition: first import reserves Pool A");
    assert_eq!(used_b, 0, "precondition: Pool B untouched");

    // Replacement: same translated tuple, dmz->wan selects Pool B.
    let mut second = synced_entry(key.clone(), 1, peer_resolution(), nat);
    second.metadata.ingress_zone = 3;
    second.metadata.egress_zone = 2;
    apply_upsert(&mut sessions, &forwarding, &ha, second);
    let used_a = crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[0].used_ports;
    let used_b = crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[1].used_ports;
    assert_eq!(
        used_a, 0,
        "cross-pool replacement must release Pool A (#14669)"
    );
    assert_eq!(used_b, 1, "replacement must reserve Pool B");
}

/// Control: same-tuple refresh (same zones/NAT) must keep the reservation —
/// the release must not fire when the target is unchanged.
#[test]
fn upsert_synced_same_tuple_refresh_keeps_reservation_14669() {
    let mut forwarding = split_rg_forwarding();
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding.zone_name_to_id.insert("lan".to_string(), 1);
    forwarding.zone_name_to_id.insert("wan".to_string(), 2);
    forwarding.source_nat_rules =
        crate::nat::parse_source_nat_rules(&[crate::SourceNATRuleSnapshot {
            name: "snat-a".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-a".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20000,
            ..crate::SourceNATRuleSnapshot::default()
        }]);
    let ha = split_ha();
    let mut sessions = SessionTable::new();
    let key = key_for(Ipv4Addr::new(8, 8, 8, 8));
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        rewrite_src_port: Some(20000),
        ..NatDecision::default()
    };
    let mut first = synced_entry(key.clone(), 1, peer_resolution(), nat);
    first.metadata.ingress_zone = 1;
    first.metadata.egress_zone = 2;
    apply_upsert(&mut sessions, &forwarding, &ha, first.clone());
    apply_upsert(&mut sessions, &forwarding, &ha, first);
    assert_eq!(
        crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[0].used_ports,
        1,
        "same-tuple refresh must keep exactly one reservation"
    );
}
