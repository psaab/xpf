// ===================================================================
// #5802 — the pre-routing DNAT / static-NAT / NPTv6 scope must key on
// the LOGICAL VLAN unit that received the frame, resolved through
// `prerouting_ingress_scope` (which uses `resolve_ingress_logical_-
// ifindex`), NOT the raw physical `meta.ingress_ifindex`. The three
// scope maps (`ifindex_to_zone_id` / `ifindex_to_config_name` /
// `ifindex_to_routing_instance`) are keyed by the logical unit ifindex;
// a VLAN sub-interface's physical parent maps only to its FIRST unit.
// Scoping the pre-routing NAT on the physical parent let a packet on
// one VLAN unit match another unit's scoped NAT rule (or miss its own)
// on a trunk whose units sit in distinct zones / interfaces — a NAT
// scope-escape ahead of the correct logical zone policy.
// ===================================================================
use super::*;

#[cfg(test)]
mod prerouting_scope_tests {
    use super::*;
    use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
    use std::net::{IpAddr, Ipv4Addr};
    use super::super::tests_support::*;

    /// nat_snapshot() already carries reth0.80 (logical 12, parent 11,
    /// VID 80, zone `wan`, the parent's FIRST sub-interface). Add reth0.50
    /// (logical 13, parent 11, VID 50, zone `lan`) so the physical parent
    /// 11 carries TWO VLAN units in DISTINCT zones. Add two scoped inbound
    /// destination-translation rules so both escape directions are covered:
    ///   - a port-based DNAT scoped `from zone wan` (unit-A's zone), and
    ///   - a static (1:1) DNAT scoped `from interface reth0.50` (unit-B's
    ///     OWN interface).
    fn two_vlan_scoped_nat_snapshot() -> crate::ConfigSnapshot {
        let mut snap = crate::afxdp::test_fixtures::nat_snapshot();
        snap.interfaces.push(crate::InterfaceSnapshot {
            name: "reth0.50".to_string(),
            zone: "lan".to_string(),
            linux_name: "ge-0-0-0.50".to_string(),
            ifindex: 13,
            parent_ifindex: 11,
            redundancy_group: 1,
            vlan_id: 50,
            hardware_addr: "02:bf:72:00:50:08".to_string(),
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "172.16.50.8/24".to_string(),
                scope: 0,
            }],
            ..Default::default()
        });
        // Port DNAT scoped to unit-A's zone (wan): 172.16.80.200:443/tcp.
        snap.destination_nat_rules
            .push(crate::DestinationNATRuleSnapshot {
                name: "dnat-from-wan".to_string(),
                from_zone: "wan".to_string(),
                destination_address: "172.16.80.200".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "10.0.61.200".to_string(),
                pool_port: 8443,
                ..Default::default()
            });
        // Static (1:1) DNAT scoped to unit-B's OWN interface (reth0.50).
        snap.static_nat_rules.push(crate::StaticNATRuleSnapshot {
            name: "static-from-reth0-50".to_string(),
            from_interface: "reth0.50".to_string(),
            external_ip: "172.16.50.200".to_string(),
            internal_ip: "10.0.61.201".to_string(),
            ..Default::default()
        });
        snap
    }

    /// #5802 fail-on-revert (wrong-APPLY escape). A DNAT scoped `from zone
    /// wan` must translate only traffic whose LOGICAL ingress unit is in
    /// `wan`. A frame arriving on the VID-50 unit (zone `lan`) must be
    /// scoped OUT. Reverting the fix to scope on the physical parent 11 —
    /// which inherits unit-A's first-unit `wan` zone — makes the VID-50
    /// frame WRONGLY match unit-A's DNAT (NAT applied outside its
    /// configured `from zone`), so the unit-B assertion goes RED.
    #[test]
    fn prerouting_dnat_scope_uses_logical_vlan_unit_zone_5802() {
        let forwarding = build_forwarding_state(&two_vlan_scoped_nat_snapshot());

        // Fixture sanity: parent 11 / VID 80 -> logical 12 (zone wan);
        // parent 11 / VID 50 -> logical 13 (zone lan). The physical parent
        // 11 inherits ONLY unit-A's (first sub-interface) zone -> wan.
        assert_eq!(resolve_ingress_logical_ifindex(&forwarding, 11, 80), Some(12));
        assert_eq!(resolve_ingress_logical_ifindex(&forwarding, 11, 50), Some(13));
        assert_eq!(
            forwarding.ifindex_to_zone_id.get(&12).copied(),
            Some(TEST_WAN_ZONE_ID)
        );
        assert_eq!(
            forwarding.ifindex_to_zone_id.get(&13).copied(),
            Some(TEST_LAN_ZONE_ID)
        );
        // #7509 RETARGET, re-expressed and STRICTLY STRONGER. This asserted the
        // parent inherited unit-A's first-unit `wan` zone -- the arbitrary
        // walk-order pick that makes a VID-50 frame wrongly match unit-A's
        // `from zone wan` DNAT, which is the hazard this cell guards.
        //
        // A contested parent now carries no zone, so the hazard is expressed as
        // "the parent names no zone" instead of "the parent names the WRONG
        // zone". Both make a physical-keyed scope decision wrong for the VID-50
        // unit; the new form also distinguishes it from "scoped to some other
        // real zone", which the old form could not.
        //
        // The two assertions above are the control: units 12 and 13 must still
        // resolve to `wan` and `lan`, so this 0 is specific to the contested
        // parent rather than a state with no zones at all.
        assert_eq!(
            forwarding.ifindex_to_zone_id.get(&11).copied().unwrap_or(0),
            0,
            "the physical parent carries units in DIFFERENT zones (wan on \
             unit-A, lan on unit-B), so it resolves to NO zone (#7509)"
        );

        let src: IpAddr = "203.0.113.9".parse().unwrap();
        let dst: IpAddr = "172.16.80.200".parse().unwrap();

        // Unit-A frame (VID 80): scope resolves to wan -> the wan-scoped
        // DNAT MATCHES its OWN zone's traffic.
        let scope_a = prerouting_ingress_scope(&forwarding, 11, 80, None);
        assert_eq!(scope_a.zone_name, "wan");
        assert_eq!(scope_a.logical_ifindex, 12);
        let dnat_a = forwarding.dnat_table.lookup_with_counter_scoped(
            crate::ip_proto::PROTO_TCP,
            src,
            dst,
            51000,
            443,
            scope_a.zone_name,
            scope_a.ifname,
            scope_a.routing_instance,
            None,
        );
        assert!(
            dnat_a.is_some(),
            "unit-A (logical zone wan) must match its own wan-scoped DNAT"
        );

        // Unit-B frame (VID 50): scope resolves to lan -> the wan-scoped
        // DNAT is SCOPED OUT. Reverting to the physical parent makes this
        // resolve to wan and the DNAT WRONGLY matches -> RED (#5802).
        let scope_b = prerouting_ingress_scope(&forwarding, 11, 50, None);
        assert_eq!(
            scope_b.zone_name, "lan",
            "the VID-50 unit must scope on its OWN logical zone (lan), \
             not the parent's inherited wan"
        );
        assert_eq!(scope_b.logical_ifindex, 13);
        let dnat_b = forwarding.dnat_table.lookup_with_counter_scoped(
            crate::ip_proto::PROTO_TCP,
            src,
            dst,
            51000,
            443,
            scope_b.zone_name,
            scope_b.ifname,
            scope_b.routing_instance,
            None,
        );
        assert!(
            dnat_b.is_none(),
            "unit-B (logical zone lan) must NOT match unit-A's wan-scoped \
             DNAT — a cross-VLAN-unit NAT scope-escape (#5802)"
        );
    }

    /// #5802 fail-on-revert (wrong-SKIP escape). A static DNAT scoped
    /// `from interface reth0.50` must translate the VID-50 unit's OWN
    /// traffic. The fix derives the logical ifname `reth0.50`, so the
    /// rule matches. Reverting to the physical parent 11 (which has NO
    /// config-name -> ifname "") makes the interface-scoped rule WRONGLY
    /// MISS, so unit-B's own traffic skips its configured translation ->
    /// the unit-B assertion goes RED.
    #[test]
    fn prerouting_static_dnat_scope_uses_logical_vlan_unit_interface_5802() {
        let forwarding = build_forwarding_state(&two_vlan_scoped_nat_snapshot());
        let src: IpAddr = "203.0.113.9".parse().unwrap();
        let ext: IpAddr = "172.16.50.200".parse().unwrap();

        // Unit-B frame (VID 50): ifname resolves to reth0.50 -> its OWN
        // reth0.50-scoped static DNAT MATCHES.
        let scope_b = prerouting_ingress_scope(&forwarding, 11, 50, None);
        assert_eq!(scope_b.ifname, "reth0.50");
        let static_b = forwarding.static_nat.match_dnat_with_counter_scoped(
            ext,
            0,
            Some(src),
            scope_b.zone_name,
            scope_b.ifname,
            scope_b.routing_instance,
        );
        assert!(
            static_b.is_some(),
            "unit-B must match its OWN reth0.50-scoped static DNAT (the fix \
             derives the logical ifname); reverting to the physical parent \
             yields ifname \"\" and WRONGLY skips the translation (#5802)"
        );

        // Unit-A frame (VID 80): ifname resolves to reth0.80 -> the
        // reth0.50-scoped rule is correctly scoped OUT.
        let scope_a = prerouting_ingress_scope(&forwarding, 11, 80, None);
        assert_eq!(scope_a.ifname, "reth0.80");
        let static_a = forwarding.static_nat.match_dnat_with_counter_scoped(
            ext,
            0,
            Some(src),
            scope_a.zone_name,
            scope_a.ifname,
            scope_a.routing_instance,
        );
        assert!(
            static_a.is_none(),
            "unit-A must NOT match unit-B's reth0.50-scoped static DNAT"
        );
    }

    /// #5802 non-VLAN regression: an untagged port (reth1.0, ifindex 24)
    /// has no `(parent, vlan)` mapping, so `resolve_ingress_logical_-
    /// ifindex` returns None and `prerouting_ingress_scope` falls back to
    /// the physical ifindex — the scope identity is byte-identical to
    /// pre-#5802 (logical == physical).
    #[test]
    fn prerouting_scope_non_vlan_unchanged_5802() {
        let forwarding = build_forwarding_state(&two_vlan_scoped_nat_snapshot());
        assert_eq!(
            resolve_ingress_logical_ifindex(&forwarding, 24, 0),
            Some(24),
            "an untagged port resolves logical == physical"
        );
        let scope = prerouting_ingress_scope(&forwarding, 24, 0, None);
        assert_eq!(
            scope.logical_ifindex, 24,
            "an untagged port scopes on itself (logical == physical)"
        );
        assert_eq!(scope.zone_name, "lan");
        assert_eq!(scope.ifname, "reth1.0");
        // The derived scope equals the direct physical-keyed lookups (the
        // pre-#5802 behavior) — non-trunk ingress is unchanged.
        assert_eq!(
            forwarding
                .ifindex_to_config_name
                .get(&24)
                .map(|s| s.as_str()),
            Some(scope.ifname),
        );
        assert_eq!(
            forwarding
                .ifindex_to_zone_id
                .get(&24)
                .and_then(|id| forwarding.zone_id_to_name.get(id))
                .map(|s| s.as_str()),
            Some(scope.zone_name),
        );
    }
/// #10313 RED-on-master: an unknown tagged VID on an agreed-zone trunk must
/// not inherit the parent's sibling zone. The same physical parent identity
/// remains available for `from interface` / `from routing-instance` scope:
/// only the zone/policy identity is unzoned.
///
/// The physical parent row is absent, so master has no
/// `ifindex_to_config_name[11]` entry. The tagged unit `reth0.50` is the
/// structurally-known owner from which the fix derives the parent name.
/// VID 99 has no `(11, 99)` map entry. Before the fix,
/// `prerouting_ingress_scope` falls back to physical ifindex 11 and reads the
/// propagated `lan` zone while leaving `ifname` empty.

#[test]
fn unknown_vid_on_agreed_zone_trunk_is_unzoned_but_keeps_parent_ifname_10313() {
    let forwarding =
        build_forwarding_state(&crate::afxdp::test_fixtures::agreed_zone_trunk_snapshot_10313());

    // Known VID control: the configured unit keeps its own logical identity
    // and its `lan` zone.
    let known = prerouting_ingress_scope(&forwarding, 11, 50, None);
    assert_eq!(known.zone_name, "lan");
    assert_eq!(known.ifname, "reth0.50");
    assert_eq!(known.routing_instance, "tenant-b");
    let (known_from, _) =
        crate::afxdp::forwarding::zone_pair_ids_for_flow(&forwarding, known.logical_ifindex, 24);
    assert_eq!(
        known_from,
        TEST_LAN_ZONE_ID,
        "known VID traffic must remain in its configured sibling zone"
    );
    // XDP may be attached to the VLAN child itself. Its ingress ifindex is
    // already logical, so only the child's configured VID is known.
    let child_match = prerouting_ingress_scope(&forwarding, 13, 50, None);
    assert_eq!(child_match.logical_ifindex, 13);
    assert_eq!(child_match.zone_name, "lan");
    assert_eq!(child_match.ifname, "reth0.50");
    assert!(
        !crate::afxdp::forwarding::unknown_ingress_vlan(&forwarding, 13, 50),
        "a VLAN child must admit its configured VID"
    );
    let child_wrong_vid = prerouting_ingress_scope(&forwarding, 13, 99, None);
    assert_eq!(
        child_wrong_vid.zone_name, "",
        "a different VID on the child must not inherit its configured zone"
    );
    assert!(
        crate::afxdp::forwarding::unknown_ingress_vlan(&forwarding, 13, 99),
        "a VLAN child must still reject a VID other than its configured VID"
    );

    // Unknown VID regression: the scope keeps the physical parent identity
    // for interface matching, but no configured unit owns VID 99, so the
    // ingress zone must be the unzoned sentinel and the packet is rejected
    // at the common ingress boundary.
    let unknown = prerouting_ingress_scope(&forwarding, 11, 99, None);
    assert_eq!(
        unknown.zone_name, "",
        "unknown VID must not inherit the agreed sibling zone"
    );
    let fabric_override = prerouting_ingress_scope(
        &forwarding,
        11,
        99,
        Some(TEST_WAN_ZONE_ID),
    );
    assert_eq!(
        fabric_override.zone_name, "wan",
        "a valid fabric ingress override remains authoritative for an unknown local VID"
    );
    assert_eq!(
        unknown.ifname, "reth0",
        "unknown VID must derive the parent config identity for from-interface scope"
    );
    assert!(
        crate::afxdp::forwarding::unknown_ingress_vlan(&forwarding, 11, 99),
        "unknown VID must be recognized at the common ingress boundary"
    );
    assert!(
        !crate::afxdp::forwarding::unknown_ingress_vlan(&forwarding, 11, 50),
        "known VID must remain admitted to the normal logical-unit path"
    );
}


fn broadcast_arp_reply_10313(sender_ip: Ipv4Addr, sender_mac: [u8; 6]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&sender_mac);
    frame.extend_from_slice(&[0x08, 0x06]);
    // Ethernet/IPv4 ARP reply: htype, ptype, hlen, plen, opcode.
    frame.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]);
    frame.extend_from_slice(&sender_mac);
    frame.extend_from_slice(&sender_ip.octets());
    frame.extend_from_slice(&[0x00; 6]);
    frame.extend_from_slice(&[10, 0, 0, 1]);
    frame
}

/// #10313 packet-path guard: the unknown tagged VID must be recycled before
/// ARP learning, while the exact known VID still learns under its logical
/// ifindex and the untagged parent retains its normal physical fallback.
#[test]
fn unknown_vid_is_recycled_before_arp_learning_10313() {
    let forwarding =
        build_forwarding_state(&crate::afxdp::test_fixtures::agreed_zone_trunk_snapshot_10313());
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
    let neighbors = std::sync::Arc::new(crate::afxdp::sharded_neighbor::ShardedNeighborMap::default());

    let unknown_ip = Ipv4Addr::new(192, 0, 2, 99);
    let unknown_meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 11,
        ingress_vlan_id: 99,
        ingress_vlan_present: 1,
        l3_offset: 14,
        pkt_len: 42,
        addr_family: libc::AF_INET as u8,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    txn_run_descriptor_with_neighbors(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &broadcast_arp_reply_10313(unknown_ip, [0x02, 0x99, 0, 0, 0, 1]),
        unknown_meta,
        &neighbors,
    );
    assert!(
        neighbors.get(&(11, IpAddr::V4(unknown_ip))).is_none(),
        "unknown VID must recycle before the physical-parent ARP learn"
    );
    assert!(
        neighbors.get(&(13, IpAddr::V4(unknown_ip))).is_none(),
        "unknown VID must not reach the logical-unit ARP learn either"
    );

    let known_ip = Ipv4Addr::new(192, 0, 2, 50);
    let known_meta = UserspaceDpMeta {
        ingress_vlan_id: 50,
        ingress_vlan_present: 1,
        ..unknown_meta
    };
    txn_run_descriptor_with_neighbors(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &broadcast_arp_reply_10313(known_ip, [0x02, 0x50, 0, 0, 0, 1]),
        known_meta,
        &neighbors,
    );
    assert!(
        neighbors.get(&(13, IpAddr::V4(known_ip))).is_some(),
        "known VID must reach ARP learning under logical ifindex 13"
    );

    let untagged_ip = Ipv4Addr::new(192, 0, 2, 1);
    let untagged_meta = UserspaceDpMeta {
        ingress_vlan_id: 0,
        ingress_vlan_present: 0,
        ..unknown_meta
    };
    txn_run_descriptor_with_neighbors(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &broadcast_arp_reply_10313(untagged_ip, [0x02, 0x01, 0, 0, 0, 1]),
        untagged_meta,
        &neighbors,
    );
    assert!(
        neighbors.get(&(11, IpAddr::V4(untagged_ip))).is_some(),
        "untagged parent traffic must retain its physical fallback"
    );
}
/// The parent-name half of #10313 is independent of zone adjudication: when
/// only a tagged unit row survives, the fallback scope must still expose the
/// parent interface name for `from interface` matching.
#[test]
fn unknown_vid_scope_populates_parent_ifname_10313() {
    let forwarding =
        build_forwarding_state(&crate::afxdp::test_fixtures::agreed_zone_trunk_snapshot_10313());
    let scope = prerouting_ingress_scope(&forwarding, 11, 99, None);
    assert_eq!(
        scope.ifname, "reth0",
        "unknown VID must not leave the parent interface scope empty"
    );
}
/// #10656 (residual of #10313): an unknown tagged VID on a unit-less zoned
/// port must not inherit the port's own zone. `reth2` (31, `lan`) carries
/// no unit rows, so `(31, 99)` is an identity the snapshot does not own:
/// the scope keeps the port config name for `from interface` matching, but
/// the zone/policy identity is the unzoned sentinel. Untagged traffic on
/// the port keeps its `lan` zone via the normal physical fallback.
#[test]
fn unknown_vid_on_unitless_zoned_port_is_unzoned_but_keeps_port_ifname_10656() {
    let forwarding =
        build_forwarding_state(&crate::afxdp::test_fixtures::unitless_zoned_port_snapshot_10656());

    // Untagged control: the plain port keeps its own identity and `lan` zone.
    let untagged = prerouting_ingress_scope(&forwarding, 31, 0, None);
    assert_eq!(untagged.zone_name, "lan");
    assert_eq!(untagged.ifname, "reth2");
    let (untagged_from, _) = crate::afxdp::forwarding::zone_pair_ids_for_flow(
        &forwarding,
        untagged.logical_ifindex,
        24,
    );
    assert_eq!(
        untagged_from, TEST_LAN_ZONE_ID,
        "untagged port traffic must remain in its configured zone"
    );

    // Unknown VID regression: no unit owns VID 99 on this bind, so the
    // ingress zone must be the unzoned sentinel even though the port itself
    // is zoned `lan`.
    let unknown = prerouting_ingress_scope(&forwarding, 31, 99, None);
    assert_eq!(
        unknown.zone_name, "",
        "unknown VID must not inherit the unit-less port's own zone"
    );
    let fabric_override =
        prerouting_ingress_scope(&forwarding, 31, 99, Some(TEST_WAN_ZONE_ID));
    assert_eq!(
        fabric_override.zone_name, "wan",
        "a valid fabric ingress override remains authoritative for an unknown local VID"
    );
    assert_eq!(
        unknown.ifname, "reth2",
        "unknown VID must keep the port config identity for from-interface scope"
    );
    assert!(
        crate::afxdp::forwarding::unknown_ingress_vlan(&forwarding, 31, 99),
        "unknown VID must be recognized at the common ingress boundary"
    );
    assert!(
        !crate::afxdp::forwarding::unknown_ingress_vlan(&forwarding, 31, 0),
        "untagged traffic must remain on the normal physical fallback"
    );
}

/// #10656 packet-path guard: the unknown tagged VID on a unit-less port
/// must be recycled before ARP learning, while untagged traffic on the
/// same port still learns under its physical ifindex.
#[test]
fn unknown_vid_on_unitless_port_is_recycled_before_arp_learning_10656() {
    let forwarding =
        build_forwarding_state(&crate::afxdp::test_fixtures::unitless_zoned_port_snapshot_10656());
    let ha_state = txn_ha_state();
    let mut sessions = SessionTable::new();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 31, 0);
    let neighbors =
        std::sync::Arc::new(crate::afxdp::sharded_neighbor::ShardedNeighborMap::default());

    let unknown_ip = Ipv4Addr::new(192, 0, 2, 99);
    let unknown_meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 31,
        ingress_vlan_id: 99,
        ingress_vlan_present: 1,
        l3_offset: 14,
        pkt_len: 42,
        addr_family: libc::AF_INET as u8,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    txn_run_descriptor_with_neighbors(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &broadcast_arp_reply_10313(unknown_ip, [0x02, 0x99, 0, 0, 0, 1]),
        unknown_meta,
        &neighbors,
    );
    assert!(
        neighbors.get(&(31, IpAddr::V4(unknown_ip))).is_none(),
        "unknown VID must recycle before the physical-port ARP learn"
    );

    let untagged_ip = Ipv4Addr::new(192, 0, 2, 1);
    let untagged_meta = UserspaceDpMeta {
        ingress_vlan_id: 0,
        ingress_vlan_present: 0,
        ..unknown_meta
    };
    txn_run_descriptor_with_neighbors(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &broadcast_arp_reply_10313(untagged_ip, [0x02, 0x01, 0, 0, 0, 1]),
        untagged_meta,
        &neighbors,
    );
    assert!(
        neighbors.get(&(31, IpAddr::V4(untagged_ip))).is_some(),
        "untagged port traffic must retain its physical fallback"
    );
}
}
