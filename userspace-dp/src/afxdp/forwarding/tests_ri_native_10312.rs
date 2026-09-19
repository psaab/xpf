//! #10312: a routing-instance member interface resolves in its instance table,
//! not MAIN, even when no PBR term steers the packet.
//!
//! Pre-fix `ingress_route_table_override` returned `RouteOverride::None` for
//! every non-PBR packet, so the miss path resolved the destination in the
//! global `inet.0`/`inet6.0` — a WAN leak for RI members. Post-fix the two
//! `None` sites fall back to the native instance table synthesized from the
//! flow's routing domain (stage-9b-stamped, fabric-aware) or, when the domain
//! is unstamped (flowless L3-only contexts) or the instance has no dataplane
//! presence yet, from the ingress interface's instance name.
//!
//! Fixture: `tenant-a` owns ge-0/0/1.80 (101, 10.0.0.1/24, RG 1) with a
//! production-faithful shipped domain id; MAIN owns ge-wan (13,
//! 203.0.113.1/30, RG 1) plus a 0/0 default route, and ge-lan (24,
//! 192.168.1.1/24) for the default-instance control. Membership is shipped
//! BOTH ways Go ships it (name + domain); the gate control (F6) pins that
//! name-only membership does NOT activate native synthesis.

use super::super::forwarding_build::*;
use super::*;
use crate::ip_proto::PROTO_TCP;
use crate::session::install_table_identity;
use crate::test_zone_ids::*;
use crate::{
    ConfigSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceAddressSnapshot,
    InterfaceSnapshot, NeighborSnapshot, RouteSnapshot, ZoneSnapshot,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

const TENANT_IFINDEX: i32 = 101;
const WAN_IFINDEX: i32 = 13;
const LAN_IFINDEX: i32 = 24;
const RG1: i32 = 1;

fn tenant_domain() -> u32 {
    install_table_identity("tenant-a").0
}

fn base_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "za".to_string(),
                id: TEST_TRUST_ZONE_ID,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "wan".to_string(),
                id: TEST_UNTRUST_ZONE_ID,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "lan".to_string(),
                id: TEST_LAN_ZONE_ID,
                ..Default::default()
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1.80".to_string(),
                zone: "za".to_string(),
                routing_instance: "tenant-a".to_string(),
                routing_domain: tenant_domain(),
                linux_name: "ge-0-0-1.80".to_string(),
                ifindex: TENANT_IFINDEX,
                hardware_addr: "02:00:00:00:00:a1".to_string(),
                addresses: vec![
                    InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "10.0.0.1/24".to_string(),
                        scope: 0,
                    },
                    InterfaceAddressSnapshot {
                        family: "inet6".to_string(),
                        address: "2001:db8:a::1/64".to_string(),
                        scope: 0,
                    },
                ],
                redundancy_group: RG1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-wan".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-wan".to_string(),
                ifindex: WAN_IFINDEX,
                hardware_addr: "02:00:00:00:00:0d".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "203.0.113.1/30".to_string(),
                    scope: 0,
                }],
                redundancy_group: RG1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-lan".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-lan".to_string(),
                ifindex: LAN_IFINDEX,
                hardware_addr: "02:00:00:00:00:18".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.168.1.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        routes: vec![RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "0.0.0.0/0".to_string(),
            next_hops: vec!["203.0.113.2".to_string()],
            ..Default::default()
        }],
        neighbors: vec![NeighborSnapshot {
            interface: "ge-wan".to_string(),
            ifindex: WAN_IFINDEX,
            family: "inet".to_string(),
            ip: "203.0.113.2".to_string(),
            mac: "00:aa:bb:cc:dd:0d".to_string(),
            state: "reachable".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// F1 fixture helper: attach a v4 PBR filter to the tenant member whose single
/// steering term matches `steer_dst` into `target_instance`.
fn pbr_snapshot_for(steer_dst: &str, target_instance: &str) -> ConfigSnapshot {
    let mut snapshot = base_snapshot();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "pbr4".to_string(),
        family: "inet".to_string(),
        terms: vec![
            FirewallTermSnapshot {
                name: "steer".to_string(),
                destination_addresses: vec![steer_dst.to_string()],
                routing_instance: target_instance.to_string(),
                action: "accept".to_string(),
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "default".to_string(),
                action: "accept".to_string(),
                ..Default::default()
            },
        ],
    }];
    snapshot
        .interfaces
        .iter_mut()
        .find(|iface| iface.ifindex == TENANT_IFINDEX)
        .expect("tenant member must exist")
        .filter_input_v4 = "pbr4".to_string();
    snapshot
}

fn v4_flow(src: Ipv4Addr, dst: Ipv4Addr, domain: u32) -> SessionFlow {
    SessionFlow {
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(dst),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(src),
            dst_ip: IpAddr::V4(dst),
            src_port: 55068,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: domain,
        },
    }
}

fn v4_meta(ingress_ifindex: i32) -> UserspaceDpMeta {
    UserspaceDpMeta {
        ingress_ifindex: ingress_ifindex as u32,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..Default::default()
    }
}

fn v6_flow(src: Ipv6Addr, dst: Ipv6Addr, domain: u32) -> SessionFlow {
    SessionFlow {
        src_ip: IpAddr::V6(src),
        dst_ip: IpAddr::V6(dst),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(src),
            dst_ip: IpAddr::V6(dst),
            src_port: 55068,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: domain,
        },
    }
}

fn v6_meta(ingress_ifindex: i32) -> UserspaceDpMeta {
    UserspaceDpMeta {
        ingress_ifindex: ingress_ifindex as u32,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        ..Default::default()
    }
}

/// F1: an RI-member ingress with NO input filter resolves in its instance
/// table, not MAIN. RED pre-fix (`None` → MAIN/WAN); GREEN post-fix.
#[test]
fn ri_member_without_pbr_steers_into_instance_table_10312() {
    let state = build_forwarding_state(&base_snapshot());
    assert!(
        state.has_routing_domains,
        "FIXTURE: the membership gate must be armed or this cell is vacuous"
    );
    let flow = v4_flow(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(8, 8, 8, 8),
        tenant_domain(),
    );
    let meta = v4_meta(TENANT_IFINDEX);
    let RouteOverride::Table {
        table,
        domain,
        check,
    } = ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None)
    else {
        panic!("an RI-member packet with no PBR filter must steer into tenant-a.inet.0, not MAIN");
    };
    assert_eq!(table, "tenant-a.inet.0");
    assert_eq!((domain, check), install_table_identity("tenant-a"));
}

/// F2 (v6 twin): the formed table carries the packet family's suffix.
#[test]
fn ri_member_without_pbr_forms_v6_instance_table_10312() {
    let state = build_forwarding_state(&base_snapshot());
    let flow = v6_flow(
        "2001:db8:a::42".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        tenant_domain(),
    );
    let meta = v6_meta(TENANT_IFINDEX);
    let RouteOverride::Table {
        table,
        domain,
        check,
    } = ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None)
    else {
        panic!("an RI-member v6 packet with no PBR filter must steer into tenant-a.inet6.0");
    };
    assert_eq!(table, "tenant-a.inet6.0");
    assert_eq!((domain, check), install_table_identity("tenant-a"));
}

/// F3: a filter that does NOT match still falls back to the native table
/// (the second `None` site). RED pre-fix; GREEN post-fix.
#[test]
fn ri_member_with_nonmatching_filter_falls_back_to_instance_10312() {
    let state = build_forwarding_state(&pbr_snapshot_for("8.8.8.8/32", "blue"));
    let flow = v4_flow(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(1, 1, 1, 1),
        tenant_domain(),
    );
    let meta = v4_meta(TENANT_IFINDEX);
    let RouteOverride::Table { table, .. } =
        ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None)
    else {
        panic!("a non-matching PBR filter must fall back to tenant-a.inet.0, not MAIN");
    };
    assert_eq!(table, "tenant-a.inet.0");
}

/// F4 (control): a MATCHING PBR term still wins over the native table.
/// GREEN pre- and post-fix — precedence is unchanged.
#[test]
fn matching_pbr_term_still_wins_over_native_table_10312() {
    let state = build_forwarding_state(&pbr_snapshot_for("8.8.8.8/32", "blue"));
    let flow = v4_flow(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(8, 8, 8, 8),
        tenant_domain(),
    );
    let meta = v4_meta(TENANT_IFINDEX);
    let RouteOverride::Table {
        table,
        domain,
        check,
    } = ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None)
    else {
        panic!("CONTROL: a matching PBR term must steer");
    };
    assert_eq!(table, "blue.inet.0");
    assert_eq!((domain, check), install_table_identity("blue"));
}

/// F5 (control): a default-instance ingress still resolves MAIN.
/// GREEN pre- and post-fix.
#[test]
fn default_ingress_still_resolves_main_10312() {
    let state = build_forwarding_state(&base_snapshot());
    let flow = v4_flow(Ipv4Addr::new(192, 168, 1, 50), Ipv4Addr::new(8, 8, 8, 8), 0);
    let meta = v4_meta(LAN_IFINDEX);
    assert!(
        matches!(
            ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None),
            RouteOverride::None
        ),
        "CONTROL: a default-instance packet must keep resolving MAIN"
    );
}

/// F6 (control): name-only membership (domain unshipped, gate off) does NOT
/// activate native synthesis — the #7160 single-bool gate still guards it.
/// GREEN pre- and post-fix.
#[test]
fn name_only_membership_does_not_activate_native_table_10312() {
    let mut snapshot = base_snapshot();
    snapshot
        .interfaces
        .iter_mut()
        .find(|iface| iface.ifindex == TENANT_IFINDEX)
        .expect("tenant member must exist")
        .routing_domain = 0;
    let state = build_forwarding_state(&snapshot);
    assert!(
        !state.has_routing_domains,
        "FIXTURE: stripping the shipped domain must disarm the gate"
    );
    let flow = v4_flow(Ipv4Addr::new(10, 0, 0, 42), Ipv4Addr::new(8, 8, 8, 8), 0);
    let meta = v4_meta(TENANT_IFINDEX);
    assert!(
        matches!(
            ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None),
            RouteOverride::None
        ),
        "CONTROL: with the membership gate off the override must stay None"
    );
}

/// F7: end-to-end at the forwarding boundary — the steered table resolves a
/// tenant-connected destination to the member interface, not the WAN.
/// RED pre-fix (egress 13 via MAIN 0/0); GREEN post-fix (egress 101).
#[test]
fn native_table_lookup_egresses_member_not_wan_10312() {
    let state = build_forwarding_state(&base_snapshot());
    let flow = v4_flow(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(10, 0, 0, 99),
        tenant_domain(),
    );
    let meta = v4_meta(TENANT_IFINDEX);
    // Mirror the miss path: the override (if any) selects the lookup table.
    let table = match ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None) {
        RouteOverride::Table { table, .. } => Some(table),
        RouteOverride::None => None,
        RouteOverride::Drop => panic!("no filter is configured; Drop is unreachable"),
    };
    let resolved = lookup_forwarding_resolution_in_table_with_dynamic(
        &state,
        &Arc::new(ShardedNeighborMap::new()),
        flow.dst_ip,
        table.as_deref(),
    );
    assert_eq!(
        resolved.egress_ifindex, TENANT_IFINDEX,
        "a tenant-connected destination must egress the member interface, not the WAN"
    );
}

/// F8: flowless-shaped input (unstamped domain, L3-only context) still
/// synthesizes the native table from the ingress name. RED pre-fix.
#[test]
fn unstamped_flowless_context_falls_back_to_ingress_name_10312() {
    let state = build_forwarding_state(&base_snapshot());
    // A flowless L3-only context carries no staged domain (domain 0).
    let flow = v4_flow(Ipv4Addr::new(10, 0, 0, 42), Ipv4Addr::new(10, 0, 0, 99), 0);
    let meta = v4_meta(TENANT_IFINDEX);
    let RouteOverride::Table { table, .. } =
        ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None)
    else {
        panic!("an unstamped RI-member context must still synthesize tenant-a.inet.0");
    };
    assert_eq!(table, "tenant-a.inet.0");
}

/// F10: a nonzero domain with no current family/owner row is terminal, never
/// an implicit MAIN lookup. RED-on-revert: mapping this state to
/// `RouteOverride::None` sends the packet to the WAN default route.
#[test]
fn unresolvable_native_domain_does_not_fall_back_to_main_10312() {
    let mut state = build_forwarding_state(&base_snapshot());
    state
        .install_tables
        .get_mut(&tenant_domain())
        .expect("tenant registry row")
        .v4 = None;
    let flow = v4_flow(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(8, 8, 8, 8),
        tenant_domain(),
    );
    let meta = v4_meta(TENANT_IFINDEX);
    assert!(
        matches!(
            ingress_route_table_override(&state, &[], meta, &flow, None, None, 0, None),
            RouteOverride::Drop
        ),
        "a nonzero domain with no v4 owner must terminate, not resolve in MAIN/WAN"
    );
}
