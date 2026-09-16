//! #9956 F-052: the SNAT interface/routing-instance scope must resolve on the
//! LOGICAL ingress unit, not the physical bind ifindex.
//!
//! `nat_scope_ctx_for_flow` (forwarding/nat.rs) reads `ifindex_to_config_name`
//! / `ifindex_to_routing_instance` — both keyed by LOGICAL unit ifindex
//! (forwarding_build/interfaces.rs) — at the RAW physical `ingress_ifindex`
//! and never reads `meta.ingress_vlan_id` (its own #9062 comment says so).
//! Every zone / filter / pre-routing admission site resolves the logical unit
//! first via `resolve_ingress_logical_ifindex` (39 non-test callers); this
//! resolver is the outlier. The in-file contrast is
//! `poll_descriptor/frag_assoc.rs`: the fragment authority resolves the logical
//! unit, then passes the raw physical ifindex into the SNAT-scope probe.
//!
//! The escape needs the parent bind ifindex to carry some unit's identity —
//! here the untagged unit reth0.0, collapsed onto its parent netdev (unit and
//! base share ifindex 11, the #6722 shape), in tenant-a — while the tagged
//! sibling reth0.50 (logical 13) sits in tenant-b. A rule scoped
//! `from interface reth0.0` / `from routing-instance tenant-a` must match only
//! unit-A traffic; scoping unit-B traffic on the physical parent 11 matches
//! unit-A's rule (wrong-APPLY escape). Otherwise (parent maps to "") a scoped
//! rule fails closed — still wrong, but safe.
//!
//! RED on base: the physical-keyed scope for VID-50 traffic reports unit-A's
//! identity and unit-B flow matches unit-A's SNAT rule.

use super::super::forwarding_build::*;
use super::nat::{match_source_nat_for_flow, nat_scope_ctx_for_flow};
use super::*;
use crate::test_zone_ids::*;
use crate::{
    ConfigSnapshot, InterfaceAddressSnapshot, InterfaceSnapshot, SourceNATRuleSnapshot,
    ZoneSnapshot,
};
use std::net::{IpAddr, Ipv4Addr};

// Production values are Go's `StableRoutingInstanceTableID(name)` (FNV-1a into
// [100000, 999999]); the Rust side treats the domain as an opaque label with 0
// = default, so distinct nonzero sentinels exercise the same isolation.
const DOMAIN_A: u32 = 100001;
const DOMAIN_B: u32 = 100002;

fn addr_v4(s: &str) -> InterfaceAddressSnapshot {
    InterfaceAddressSnapshot {
        family: "inet".to_string(),
        address: s.to_string(),
        scope: 0,
    }
}

fn trunk_snapshot() -> ConfigSnapshot {
    super::super::test_fixtures::v5(ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "lan".to_string(),
                id: TEST_LAN_ZONE_ID,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["any-service".to_string()],
                ..Default::default()
            },
            ZoneSnapshot {
                name: "wan".to_string(),
                id: TEST_WAN_ZONE_ID,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["any-service".to_string()],
                ..Default::default()
            },
        ],
        interfaces: vec![
            // The trunk base row: unzoned, unbound (no RI), the parent netdev.
            InterfaceSnapshot {
                name: "reth0".to_string(),
                linux_name: "ge-0-0-0".to_string(),
                ifindex: 11,
                hardware_addr: "02:bf:72:00:00:0b".to_string(),
                ..Default::default()
            },
            // Unit A (untagged): collapsed onto the parent netdev, so the
            // parent bind ifindex 11 carries THIS unit's config name and
            // routing instance (the #6722 shared-ifindex shape). Zone lan,
            // tenant-a.
            InterfaceSnapshot {
                name: "reth0.0".to_string(),
                zone: "lan".to_string(),
                routing_instance: "tenant-a".to_string(),
                routing_domain: DOMAIN_A,
                linux_name: "ge-0-0-0".to_string(),
                ifindex: 11,
                parent_ifindex: 11,
                hardware_addr: "02:bf:72:00:00:0b".to_string(),
                addresses: vec![addr_v4("10.0.61.1/24")],
                ..Default::default()
            },
            // Unit B (tagged VID 50): logical 13 on parent 11. Zone lan,
            // tenant-b — same zone as A (so zone scope cannot distinguish),
            // different interface and routing instance.
            InterfaceSnapshot {
                name: "reth0.50".to_string(),
                zone: "lan".to_string(),
                routing_instance: "tenant-b".to_string(),
                routing_domain: DOMAIN_B,
                linux_name: "ge-0-0-0.50".to_string(),
                ifindex: 13,
                parent_ifindex: 11,
                vlan_id: 50,
                hardware_addr: "02:bf:72:00:50:08".to_string(),
                addresses: vec![addr_v4("10.0.50.1/24")],
                ..Default::default()
            },
            // The wan egress carrying the interface-SNAT address.
            InterfaceSnapshot {
                name: "reth1.0".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 24,
                hardware_addr: "02:bf:72:01:00:01".to_string(),
                addresses: vec![addr_v4("172.16.80.8/24")],
                ..Default::default()
            },
        ],
        source_nat_rules: vec![SourceNATRuleSnapshot {
            name: "snat-a".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            from_interface: "reth0.0".to_string(),
            from_routing_instance: "tenant-a".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..Default::default()
        }],
        ..Default::default()
    })
}

fn unit_flow(src: Ipv4Addr, domain: u32) -> crate::afxdp::SessionFlow {
    let src_ip = IpAddr::V4(src);
    let dst_ip: IpAddr = "172.16.80.200".parse().expect("dst");
    crate::afxdp::SessionFlow {
        src_ip,
        dst_ip,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::afxdp::PROTO_TCP,
            src_ip,
            dst_ip,
            src_port: 40000,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: domain,
        },
    }
}

#[test]
fn snat_scope_resolves_the_logical_vlan_unit_9956() {
    let forwarding = build_forwarding_state(&trunk_snapshot());

    // Fixture sanity: VID 50 on parent 11 resolves to logical 13 (unit B);
    // the physical parent itself carries unit-A's identity (the collapsed
    // unit0 row claims ifindex 11 for both scope maps).
    assert_eq!(
        resolve_ingress_logical_ifindex(&forwarding, 11, 50),
        Some(13),
        "VID-50 traffic on parent 11 must resolve to logical unit 13"
    );
    assert_eq!(
        forwarding.ifindex_to_config_name.get(&13).map(String::as_str),
        Some("reth0.50"),
        "logical 13 must carry unit-B's config name"
    );
    assert_eq!(
        forwarding
            .ifindex_to_routing_instance
            .get(&13)
            .map(String::as_str),
        Some("tenant-b"),
        "logical 13 must carry unit-B's routing instance"
    );
    assert_eq!(
        forwarding.ifindex_to_config_name.get(&11).map(String::as_str),
        Some("reth0.0"),
        "precondition: the parent bind ifindex carries unit-A's identity, \
         which is the arm the escape needs"
    );

    // Unit-B traffic as the CURRENT callers scope it: the raw physical
    // ingress ifindex (poll_descriptor/mod.rs mainline sites and the
    // frag_assoc.rs fragment probe all pass `meta.ingress_ifindex`).
    let scope_physical = nat_scope_ctx_for_flow(&forwarding, 11, 24, DOMAIN_B);
    assert_eq!(
        scope_physical.ingress_ifname, "reth0.50",
        "#9956 F-052: VID-50 traffic scoped on the physical parent reports \
         unit-A's interface (RED on base)"
    );
    assert_eq!(
        scope_physical.ingress_routing_instance, "tenant-b",
        "#9956 F-052: VID-50 traffic scoped on the physical parent reports \
         unit-A's routing instance (RED on base)"
    );

    // End to end: unit-B traffic must NOT match unit-A's scoped SNAT rule.
    let flow_b = unit_flow(Ipv4Addr::new(10, 0, 50, 100), DOMAIN_B);
    assert!(
        match_source_nat_for_flow(&forwarding, 11, "lan", "wan", 24, &flow_b).is_none(),
        "#9956 F-052: traffic from unit B must not match unit-A's \
         `from interface reth0.0 / from routing-instance tenant-a` SNAT rule \
         (RED on base: physical-keyed scope wrong-APPLYs it)"
    );

    // Positive control: unit-A's OWN traffic matches its rule under the same
    // physical-keyed call shape (untagged unit0 resolves logical == physical).
    let flow_a = unit_flow(Ipv4Addr::new(10, 0, 61, 100), DOMAIN_A);
    assert!(
        match_source_nat_for_flow(&forwarding, 11, "lan", "wan", 24, &flow_a).is_some(),
        "#9956 F-052 control: unit-A traffic must still match its own scoped rule"
    );
}
