//! #15118 (A77-03): a DNAT/static-NAT external address must not be treated as
//! firewall-local for packets no translate rule could match.
//!
//! Registration (`destination_ips_scoped` / `external_ips_scoped` via the
//! forwarding build) historically kept only the rule's routing-instance and
//! discarded its from-zone, from-interface, source-address, protocol and port
//! scope. The FIB then LocalDelivered *every* packet to that address before
//! the route lookup — including untranslated traffic (another protocol, port,
//! source, or ingress zone) whose real destination is a routed host. That is
//! the scoped-DNS-redirect blackhole: `udp/53 -> resolver` also swallowed
//! `tcp/443` and ICMP to the same address.
//!
//! These cells drive the real snapshot -> `build_forwarding_state` ->
//! `lookup_forwarding_resolution_for_nat_flow` path. The scoped-flow helper is
//! the session-miss resolution the poll loop uses after pre-routing NAT finds
//! no translation, so a non-matching flow must follow the FIB while a matching
//! flow (or a DNAT-to-self translation) still delivers locally.

use super::super::forwarding_build::*;
use super::super::test_fixtures::*;
use super::*;
use crate::test_zone_ids::*;
use crate::{DestinationNATRuleSnapshot, InterfaceSnapshot, RouteSnapshot, StaticNATRuleSnapshot};

const VIP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 53);
const VIP6: &str = "2001:db8:53::53";
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 10);
const WAN_HOST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);

fn scoped_snapshot() -> crate::ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    // Give the LAN a connected route to the VIP so "fall through to the FIB"
    // is observable as ForwardCandidate/MissingNeighbor rather than NoRoute,
    // and keep the default WAN route from nat_snapshot for the WAN cells.
    snapshot.routes.push(RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "203.0.113.0/24".to_string(),
        next_hops: vec!["10.0.61.254@reth1.0".to_string()],
        ..Default::default()
    });
    snapshot.neighbors.push(crate::NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 24,
        family: "inet".to_string(),
        ip: "10.0.61.254".to_string(),
        mac: "00:11:22:33:44:66".to_string(),
        state: "reachable".to_string(),
        ..Default::default()
    });
    snapshot
}

fn flow(src: IpAddr, dst: IpAddr, protocol: u8, src_port: u16, dst_port: u16) -> SessionFlow {
    SessionFlow {
        src_ip: src,
        dst_ip: dst,
        forward_key: crate::session::SessionKey {
            addr_family: if dst.is_ipv4() { 2 } else { 10 },
            protocol,
            src_ip: src,
            dst_ip: dst,
            src_port,
            dst_port,
            discriminator: crate::session::TunnelDiscriminator::None,
            routing_domain: 0,
        },
    }
}

fn resolve(state: &ForwardingState, f: &SessionFlow, zone: &str) -> ForwardingResolution {
    lookup_forwarding_resolution_for_nat_flow(state, None, f, zone, "", "")
}

#[test]
fn scoped_dnat_nonmatching_protocol_and_port_fall_through_to_fib_15118() {
    let mut snapshot = scoped_snapshot();
    // DNS redirect: only udp/53 from lan is translated, to a transit resolver.
    snapshot.destination_nat_rules = vec![DestinationNATRuleSnapshot {
        name: "dns-redirect".to_string(),
        from_zone: "lan".to_string(),
        destination_address: VIP.to_string(),
        destination_port: 53,
        protocol: "udp".to_string(),
        pool_address: "10.0.61.53".to_string(),
        pool_port: 53,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);

    // Proxy/ownership registration is retained: the address is still a global
    // local member (ARP/ND + inject ownership), even though local delivery is
    // now scoped. Removing it from local_v4 entirely would fail this control.
    assert!(
        state.local_v4.contains(&VIP),
        "scoped DNAT VIP must remain registered for proxy/ownership"
    );

    // The matching flow's *translated* target is transit, so resolution of the
    // wire destination with a matching tuple still reaches the local shortcut
    // only as the pre-translation interception point; the decisive cells are
    // the non-matching tuples below, which pre-fix also LocalDelivered.
    let tcp443 = flow(IpAddr::V4(LAN_HOST), IpAddr::V4(VIP), 6, 40000, 443);
    let resolved = resolve(&state, &tcp443, "lan");
    assert_ne!(
        resolved.disposition,
        ForwardingDisposition::LocalDelivery,
        "tcp/443 to a udp/53-only DNAT VIP must be routed, not LocalDelivered (#15118)"
    );

    let icmp = flow(IpAddr::V4(LAN_HOST), IpAddr::V4(VIP), 1, 0, 0);
    let resolved = resolve(&state, &icmp, "lan");
    assert_ne!(
        resolved.disposition,
        ForwardingDisposition::LocalDelivery,
        "ICMP to a udp/53-only DNAT VIP must be routed, not LocalDelivered (#15118)"
    );

    let wrong_port = flow(IpAddr::V4(LAN_HOST), IpAddr::V4(VIP), 17, 40000, 5353);
    let resolved = resolve(&state, &wrong_port, "lan");
    assert_ne!(
        resolved.disposition,
        ForwardingDisposition::LocalDelivery,
        "udp/5353 to a udp/53-only DNAT VIP must be routed, not LocalDelivered (#15118)"
    );

    // Control: the exact scoped tuple is still claimed locally (the poll loop
    // translates it before resolving the translated target; here this proves
    // the scope predicate itself admits the configured tuple).
    let dns = flow(IpAddr::V4(LAN_HOST), IpAddr::V4(VIP), 17, 40000, 53);
    let resolved = resolve(&state, &dns, "lan");
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::LocalDelivery,
        "udp/53 from lan must still be claimed for its DNAT rule (#15118 control)"
    );
}

#[test]
fn scoped_dnat_wrong_zone_and_source_fall_through_to_fib_15118() {
    let mut snapshot = scoped_snapshot();
    snapshot.destination_nat_rules = vec![DestinationNATRuleSnapshot {
        name: "dns-redirect".to_string(),
        from_zone: "lan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string()],
        destination_address: VIP.to_string(),
        destination_port: 53,
        protocol: "udp".to_string(),
        pool_address: "10.0.61.53".to_string(),
        pool_port: 53,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);

    // Same tuple, wrong ingress zone.
    let from_wan = flow(IpAddr::V4(WAN_HOST), IpAddr::V4(VIP), 17, 40000, 53);
    let resolved = resolve(&state, &from_wan, "wan");
    assert_ne!(
        resolved.disposition,
        ForwardingDisposition::LocalDelivery,
        "udp/53 from wan to a lan-scoped DNAT VIP must be routed (#15118)"
    );

    // Right zone, source outside the rule's source-address scope.
    let bad_src = flow(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
        IpAddr::V4(VIP),
        17,
        40000,
        53,
    );
    let resolved = resolve(&state, &bad_src, "lan");
    assert_ne!(
        resolved.disposition,
        ForwardingDisposition::LocalDelivery,
        "udp/53 from an out-of-scope source must be routed (#15118)"
    );

    // Control: in-scope source from the configured zone still claimed.
    let ok = flow(IpAddr::V4(LAN_HOST), IpAddr::V4(VIP), 17, 40000, 53);
    let resolved = resolve(&state, &ok, "lan");
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
}

#[test]
fn scoped_static_nat_wrong_zone_falls_through_and_unscoped_stays_local_15118() {
    let mut snapshot = scoped_snapshot();
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        name: "web-static".to_string(),
        from_zone: "wan".to_string(),
        external_ip: VIP.to_string(),
        internal_ip: "10.0.61.80".to_string(),
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    assert!(state.local_v4.contains(&VIP));

    // Static NAT is protocol/port-agnostic, but its from-zone still scopes it:
    // a LAN packet to the external must follow the LAN FIB, not LocalDeliver.
    let from_lan = flow(IpAddr::V4(LAN_HOST), IpAddr::V4(VIP), 6, 40000, 443);
    let resolved = resolve(&state, &from_lan, "lan");
    assert_ne!(
        resolved.disposition,
        ForwardingDisposition::LocalDelivery,
        "tcp/443 from lan to a wan-scoped static-NAT external must be routed (#15118)"
    );

    // Control: from the configured zone the external is still claimed.
    let from_wan = flow(IpAddr::V4(WAN_HOST), IpAddr::V4(VIP), 6, 40000, 443);
    let resolved = resolve(&state, &from_wan, "wan");
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::LocalDelivery,
        "wan-scoped static-NAT external must still claim wan traffic (#15118 control)"
    );

    // An unscoped static NAT (whole-address, no from scope) is unchanged:
    // it claims in any zone.
    let mut snapshot = scoped_snapshot();
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        name: "web-static-unscoped".to_string(),
        external_ip: VIP.to_string(),
        internal_ip: "10.0.61.80".to_string(),
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let any_zone = flow(IpAddr::V4(LAN_HOST), IpAddr::V4(VIP), 6, 40000, 443);
    let resolved = resolve(&state, &any_zone, "lan");
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::LocalDelivery,
        "unscoped static NAT must retain any-zone local claim (#15118 control)"
    );
}

#[test]
fn dnat_to_self_still_delivers_for_matching_and_translated_flows_15118() {
    // #9529/#6025 control: DNAT to a configured interface address. The
    // translated target (10.0.61.1, reth1.0) is itself interface-local, so the
    // session resolution on the translated target delivers locally; the wire
    // VIP with the matching tuple is claimed; a non-matching tuple is not.
    let mut snapshot = scoped_snapshot();
    snapshot.destination_nat_rules = vec![DestinationNATRuleSnapshot {
        name: "vip-to-self".to_string(),
        from_zone: "wan".to_string(),
        destination_address: VIP.to_string(),
        destination_port: 443,
        protocol: "tcp".to_string(),
        pool_address: "10.0.61.1".to_string(),
        pool_port: 8443,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);

    let matching = flow(IpAddr::V4(WAN_HOST), IpAddr::V4(VIP), 6, 40000, 443);
    assert_eq!(
        resolve(&state, &matching, "wan").disposition,
        ForwardingDisposition::LocalDelivery,
        "matching DNAT-to-self tuple must still be claimed (#15118/#9529 control)"
    );

    let nonmatching = flow(IpAddr::V4(WAN_HOST), IpAddr::V4(VIP), 6, 40000, 22);
    assert_ne!(
        resolve(&state, &nonmatching, "wan").disposition,
        ForwardingDisposition::LocalDelivery,
        "tcp/22 to a tcp/443 DNAT-to-self VIP must not be claimed on the wire tuple (#15118)"
    );
    // The plain table lookup on the translated interface address is unchanged.
    let plain = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)));
    assert_eq!(
        plain.resolution.disposition,
        ForwardingDisposition::LocalDelivery
    );
}

#[test]
fn scoped_dnat_v6_nonmatching_falls_through_15118() {
    let mut snapshot = scoped_snapshot();
    snapshot.destination_nat_rules = vec![DestinationNATRuleSnapshot {
        name: "dns6-redirect".to_string(),
        from_zone: "lan".to_string(),
        destination_address: VIP6.to_string(),
        destination_port: 53,
        protocol: "udp".to_string(),
        pool_address: "2001:559:8585:ef00::53".to_string(),
        pool_port: 53,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let vip6: IpAddr = VIP6.parse().unwrap();
    let vip6_addr: std::net::Ipv6Addr = VIP6.parse().unwrap();
    assert!(state.local_v6.contains(&vip6_addr));

    let tcp = SessionFlow {
        src_ip: "2001:559:8585:ef00::10".parse().unwrap(),
        dst_ip: vip6,
        forward_key: crate::session::SessionKey {
            addr_family: 10,
            protocol: 6,
            src_ip: "2001:559:8585:ef00::10".parse().unwrap(),
            dst_ip: vip6,
            src_port: 40000,
            dst_port: 443,
            discriminator: crate::session::TunnelDiscriminator::None,
            routing_domain: 0,
        },
    };
    let resolved = lookup_forwarding_resolution_for_nat_flow(&state, None, &tcp, "lan", "", "");
    assert_ne!(
        resolved.disposition,
        ForwardingDisposition::LocalDelivery,
        "tcp/443 to a udp/53-only v6 DNAT VIP must be routed (#15118)"
    );
    let _ = TEST_LAN_ZONE_ID;
    let _ = InterfaceSnapshot::default();
}
