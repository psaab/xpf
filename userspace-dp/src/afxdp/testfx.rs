// Shared session/forwarding fixture builders for afxdp tests (#16137).
//
// This is the single home for the four builder families that were
// copy-pasted between `session_glue/tests.rs` and `ha_tests.rs`:
// `test_resolution`, `test_metadata`, `test_key`, and the
// `test_forwarding_state*` chain. Before this module the two copies had
// already drifted in two places where the drift was observable:
//
//   * `test_metadata` differed in `fabric_ingress` (`false` in
//     session_glue, `true` in ha_tests — ha_tests fixtures riding the
//     shared alias document the `true` default they depend on), and
//   * `test_forwarding_state_with_fabric` assigned zone ids 1/2/3 to
//     lan/sfmix/wan in ha_tests while session_glue used the canonical
//     `TEST_LAN_ZONE_ID`/`TEST_SFMIX_ZONE_ID`/`TEST_WAN_ZONE_ID` (1/5/2) —
//     ha_tests' `sfmix`->2 collided with its own `wan` id.
//
// The canonical builders below preserve the session_glue values verbatim
// (every field, including `fabric_ingress: false` and the canonical zone
// ids). HA-specific values live in the explicit `*_for_ha` variants so a
// reader sees at the call site which variant a test rides; nothing in this
// module papers over a difference with a default.
//
// Deliberately NOT shared here: the `test_key` copies in
// `poll_descriptor/flow_cache_hit_tests.rs` (10.0.1.100 -> 172.16.50.200,
// ports 45678/443) and `poll_descriptor_structure_13081_tests.rs` (UDP,
// Ipsec discriminator, routing_domain 7) are different flows modelling
// different topologies, not duplicates of the session key below, and the
// `test_metadata` in `event_stream/codec/codec_tests.rs` uses the
// trust/untrust zone pair for wire-codec fixtures. Folding those in would
// change what those tests model.

use super::*;
use crate::test_zone_ids::*;
use std::net::Ipv4Addr;

/// The shared forward-candidate resolution: egress/tx ifindex 12 via
/// 172.16.50.1. Byte-identical in both former copies.
pub(crate) fn test_resolution() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: Some([6, 7, 8, 9, 10, 11]),
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    }
}

/// The shared session key: TCP 10.0.61.102:55068 -> 172.16.80.200:5201.
/// Byte-identical in both former copies.
pub(crate) fn test_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 55068,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// Session metadata for the shared key: LAN -> WAN, owner RG 1, NOT
/// fabric-ingress. This is the session_glue copy verbatim (its zone ids
/// 1/2 are `TEST_LAN_ZONE_ID`/`TEST_WAN_ZONE_ID`).
pub(crate) fn test_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 1,
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

/// HA variant of [`test_metadata`]: identical except `fabric_ingress:
/// true`, which the ha_tests synced-session fixtures ride (callers that
/// need a plain row clear the flag explicitly).
pub(crate) fn test_metadata_for_ha() -> SessionMetadata {
    SessionMetadata {
        fabric_ingress: true,
        ..test_metadata()
    }
}

/// Base forwarding state: connected 10.0.61.0/24 on ifindex 6, a neighbor
/// for the shared key's source, and LAN (ifindex 6) / WAN (ifindex 12,
/// VLAN 80) egress rows, both owner RG 1.
pub(crate) fn test_forwarding_state() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(10, 0, 61, 0), 24).unwrap()),
        host: Ipv4Addr::new(10, 0, 61, 0),
        ifindex: 6,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (6, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        },
    );
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );
    forwarding
}

/// [`test_forwarding_state`] plus the lan/sfmix/wan name->id map (canonical
/// zone ids) and one up fabric link on parent ifindex 21.
pub(crate) fn test_forwarding_state_with_fabric() -> ForwardingState {
    let mut forwarding = test_forwarding_state();
    forwarding
        .zone_name_to_id
        .insert("lan".to_string(), TEST_LAN_ZONE_ID);
    forwarding
        .zone_name_to_id
        .insert("sfmix".to_string(), TEST_SFMIX_ZONE_ID);
    forwarding
        .zone_name_to_id
        .insert("wan".to_string(), TEST_WAN_ZONE_ID);
    forwarding.fabrics.push(FabricLink {
        parent_ifindex: 21,
        overlay_ifindex: 101,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        up: true,
    });
    forwarding
}

/// [`test_forwarding_state_with_fabric`] with the ifindex-6 LAN egress row
/// moved to owner RG 2 (the split-RG topology).
pub(crate) fn test_forwarding_state_split_rgs() -> ForwardingState {
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 2,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    forwarding
}

/// [`test_forwarding_state`] with `ip` marked as a local destination in
/// the default `inet.0` table.
pub(crate) fn test_forwarding_state_with_local_destination(ip: Ipv4Addr) -> ForwardingState {
    let mut forwarding = test_forwarding_state();
    forwarding.local_v4.insert(ip);
    forwarding
        .local_tables_v4
        .entry(ip)
        .or_default()
        .insert("inet.0".to_string());
    forwarding
}

/// [`test_forwarding_state_split_rgs`] plus a tunnel endpoint (id 1) on
/// ifindex 586.
pub(crate) fn test_forwarding_state_split_rgs_with_tunnel() -> ForwardingState {
    let mut forwarding = test_forwarding_state_split_rgs();
    forwarding.tunnel_endpoint_by_ifindex.insert(586, 1);
    forwarding
}

#[cfg(test)]
mod equivalence_16137_tests {
    //! #16137 decisive acceptance: permanent equivalence for every shared
    //! builder. These assertions pin the exact values the two former
    //! copies agreed on (and, where they drifted, the canonical values
    //! documented at the top of this module). Mutating any builder field
    //! — a zone id, the fabric flag, a port, a MAC — must red one of
    //! these cells; they assert fields directly, not builder-vs-builder
    //! equality, so the pin survives future refactors of the chain.

    use super::*;

    #[test]
    fn testfx_resolution_values_16137() {
        let r = test_resolution();
        assert_eq!(r.disposition, ForwardingDisposition::ForwardCandidate);
        assert_eq!(r.local_ifindex, 0);
        assert_eq!(r.egress_ifindex, 12);
        assert_eq!(r.tx_ifindex, 12);
        assert_eq!(r.tunnel_endpoint_id, 0);
        assert_eq!(r.next_hop, Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))));
        assert_eq!(r.neighbor_mac, Some([0, 1, 2, 3, 4, 5]));
        assert_eq!(r.src_mac, Some([6, 7, 8, 9, 10, 11]));
        assert_eq!(r.tx_vlan_id, 0);
        assert_eq!(r.source_ifindex, 0);
        assert_eq!(r.route_mtu, 0);
        assert_eq!(r.transport_route_mtu, 0);
    }

    #[test]
    fn testfx_key_values_16137() {
        let k = test_key();
        assert_eq!(k.addr_family, libc::AF_INET as u8);
        assert_eq!(k.protocol, PROTO_TCP);
        assert_eq!(k.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));
        assert_eq!(k.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
        assert_eq!(k.src_port, 55068);
        assert_eq!(k.dst_port, 5201);
        assert_eq!(k.discriminator, Default::default());
        assert_eq!(k.routing_domain, 0);
        // The key must keep matching the forwarding fixture topology:
        // its source is the neighbor row, its dst is off the WAN egress.
        let f = test_forwarding_state();
        assert!(f.neighbors.contains_key(&(6, k.src_ip)));
    }

    #[test]
    fn testfx_metadata_variants_16137() {
        let m = test_metadata();
        assert_eq!(m.ingress_zone, TEST_LAN_ZONE_ID);
        assert_eq!(m.egress_zone, TEST_WAN_ZONE_ID);
        assert_eq!(m.ingress_zone_check, 0);
        assert_eq!(m.egress_zone_check, 0);
        assert_eq!(m.ingress_ifindex, 0);
        assert_eq!(m.ingress_vlan_id, 0);
        assert_eq!(m.forward_ingress_vlan_id, None);
        assert_eq!(m.owner_rg_id, 1);
        assert!(!m.fabric_ingress, "canonical metadata is not fabric-ingress");
        assert!(!m.is_reverse);
        assert!(m.nat64_reverse.is_none());
        assert!(!m.log_session_init);
        assert!(!m.log_session_close);
        assert_eq!(m.policy_id, 0);
        assert!(m.inactivity_timeout_ns.is_none());
        assert_eq!(m.policy_counter_idx, 0);
        assert!(m.policy_counter.is_none());
        assert!(m.nat_scope_ifindex.is_none());

        // The HA variant differs in exactly the fabric flag.
        let ha = test_metadata_for_ha();
        assert!(ha.fabric_ingress);
        assert_eq!(ha.ingress_zone, m.ingress_zone);
        assert_eq!(ha.egress_zone, m.egress_zone);
        assert_eq!(ha.owner_rg_id, m.owner_rg_id);
        assert_eq!(ha.ingress_ifindex, m.ingress_ifindex);
        assert_eq!(ha.policy_id, m.policy_id);
    }

    #[test]
    fn testfx_forwarding_state_chain_16137() {
        let base = test_forwarding_state();
        assert_eq!(base.connected_v4.len(), 1);
        assert_eq!(base.connected_v4[0].ifindex, 6);
        assert_eq!(base.connected_v4[0].host, Ipv4Addr::new(10, 0, 61, 0));
        assert_eq!(
            base.connected_v4[0].prefix.addr(),
            Ipv4Addr::new(10, 0, 61, 0)
        );
        assert_eq!(base.connected_v4[0].prefix.prefix_len(), 24);
        assert_eq!(base.connected_v4[0].tunnel_endpoint_id, 0);
        assert_eq!(
            base.neighbors
                .get(&(6, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))))
                .map(|n| n.mac),
            Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
        );
        assert_eq!(base.connected_v4[0].table, "inet.0");
        let lan = base.egress.get(&6).expect("LAN egress row");
        assert_eq!(lan.bind_ifindex, 6);
        assert_eq!(lan.vlan_id, 0);
        assert_eq!(lan.zone_id, TEST_LAN_ZONE_ID);
        assert_eq!(lan.mtu, 1500);
        assert_eq!(lan.src_mac, [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]);
        assert_eq!(lan.redundancy_group, 1);
        assert_eq!(lan.primary_v4, Some(Ipv4Addr::new(10, 0, 61, 1)));
        assert_eq!(lan.primary_v6, None);
        let wan = base.egress.get(&12).expect("WAN egress row");
        assert_eq!(wan.bind_ifindex, 11);
        assert_eq!(wan.vlan_id, 80);
        assert_eq!(wan.zone_id, TEST_WAN_ZONE_ID);
        assert_eq!(wan.mtu, 1500);
        assert_eq!(wan.src_mac, [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]);
        assert_eq!(wan.redundancy_group, 1);
        assert_eq!(wan.primary_v4, Some(Ipv4Addr::new(172, 16, 80, 8)));
        assert_eq!(wan.primary_v6, None);
        assert!(base.zone_name_to_id.is_empty());
        assert!(base.fabrics.is_empty());

        let fabric = test_forwarding_state_with_fabric();
        assert_eq!(
            fabric.zone_name_to_id.get("lan"),
            Some(&TEST_LAN_ZONE_ID)
        );
        assert_eq!(
            fabric.zone_name_to_id.get("sfmix"),
            Some(&TEST_SFMIX_ZONE_ID),
            "sfmix must keep the canonical id, distinct from wan"
        );
        assert_eq!(
            fabric.zone_name_to_id.get("wan"),
            Some(&TEST_WAN_ZONE_ID)
        );
        assert_eq!(fabric.fabrics.len(), 1);
        assert_eq!(fabric.fabrics[0].parent_ifindex, 21);
        assert_eq!(fabric.fabrics[0].overlay_ifindex, 101);
        assert_eq!(
            fabric.fabrics[0].peer_addr,
            IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))
        );
        assert_eq!(
            fabric.fabrics[0].peer_mac,
            [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]
        );
        assert_eq!(
            fabric.fabrics[0].local_mac,
            [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]
        );
        assert!(fabric.fabrics[0].up);
        // The fabric variant extends the base, it does not rebuild it.
        assert_eq!(fabric.egress.get(&6).map(|e| e.redundancy_group), Some(1));
        assert_eq!(fabric.connected_v4.len(), 1);

        let split = test_forwarding_state_split_rgs();
        assert_eq!(split.egress.get(&6).map(|e| e.redundancy_group), Some(2));
        assert_eq!(split.egress.get(&12).map(|e| e.redundancy_group), Some(1));
        assert_eq!(split.fabrics.len(), 1);

        let tunneled = test_forwarding_state_split_rgs_with_tunnel();
        assert_eq!(tunneled.tunnel_endpoint_by_ifindex.get(&586), Some(&1));
        assert_eq!(tunneled.egress.get(&6).map(|e| e.redundancy_group), Some(2));

        let local_ip = Ipv4Addr::new(10, 0, 61, 1);
        let local = test_forwarding_state_with_local_destination(local_ip);
        assert!(local.local_v4.contains(&local_ip));
        assert!(local
            .local_tables_v4
            .get(&local_ip)
            .is_some_and(|tables| tables.contains("inet.0")));
        assert!(local.zone_name_to_id.is_empty());
    }
}
