// #15534: a poisoned DNAT entry (#14947 `lenient_match_dropped`) must
// drop a flowless packet instead of letting it fall through
// untranslated (or NPTv6-translated). Regression through the real
// flowless path: ForwardingState built from snapshots ->
// `flowless_pre_routing_destination_nat` / `flowless_base_resolution`.
//
// RED on master: `flowless_poisoned_claim` / the `Poisoned` variant do
// not exist, and the address-only Option lookup maps Poisoned to None,
// so a GRE (portless) packet to the poisoned destination returns
// `None` from pre-routing and resolves/forwards untranslated.
use super::frag_assoc::FlowlessPreRoutingNat;
use super::*;
use std::net::Ipv4Addr;

const EXT4: &str = "203.0.113.10";
const SRC4: &str = "198.51.100.1";

fn v4_meta(protocol: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        protocol,
        addr_family: libc::AF_INET as u8,
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 6,
        pkt_len: 60,
        ..UserspaceDpMeta::default()
    }
}

fn v4_flow(dst: &str, protocol: u8) -> SessionFlow {
    let src: IpAddr = SRC4.parse().unwrap();
    let dst_ip: IpAddr = dst.parse().unwrap();
    SessionFlow {
        src_ip: src,
        dst_ip,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol,
            src_ip: src,
            dst_ip,
            src_port: 0,
            dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

fn dnat_forwarding(snaps: Vec<crate::DestinationNATRuleSnapshot>) -> ForwardingState {
    let mut fw = ForwardingState::default();
    fw.dnat_table =
        crate::nat::DnatTable::from_snapshots(&snaps, &crate::nat::NatCounterStore::default());
    fw
}

fn poisoned_snap(
    name: &str,
    destination_port: u16,
    protocol: &str,
    off: bool,
) -> crate::DestinationNATRuleSnapshot {
    crate::DestinationNATRuleSnapshot {
        name: name.to_string(),
        destination_address: EXT4.to_string(),
        destination_port,
        protocol: protocol.to_string(),
        pool_address: if off {
            String::new()
        } else {
            "192.168.1.10".to_string()
        },
        pool_port: 0,
        off,
        lenient_match_dropped: true,
        ..Default::default()
    }
}

fn gre_frame() -> Vec<u8> {
    // eth + IPv4 (proto GRE) header; only used for wire-info derivation.
    let mut f = vec![0u8; 14 + 20];
    f[12] = 0x08;
    f[13] = 0x00;
    f[14] = 0x45;
    f[23] = crate::ip_proto::PROTO_GRE;
    f[26..30].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 1).octets());
    f[30..34].copy_from_slice(&Ipv4Addr::new(203, 0, 113, 10).octets());
    f
}

#[test]
fn flowless_poisoned_address_only_dnat_drops_15534() {
    // Address-only poisoned DNAT (no port, no protocol): a GRE packet
    // has no L4 ports, so the old address-only lookup mapped the
    // Poisoned outcome to None and the packet fell through.
    let fw = dnat_forwarding(vec![poisoned_snap("addr-only", 0, "", false)]);
    assert!(
        fw.dnat_table
            .flowless_poisoned_claim(
                crate::ip_proto::PROTO_GRE,
                SRC4.parse().unwrap(),
                EXT4.parse().unwrap(),
                "",
                "",
                "",
                None,
            )
            .0,
        "table-level flowless_poisoned_claim must fire for address-only poison"
    );
    let meta = v4_meta(crate::ip_proto::PROTO_GRE);
    let frame = gre_frame();
    let pre = flowless_pre_routing_destination_nat(
        &fw,
        &v4_flow(EXT4, crate::ip_proto::PROTO_GRE),
        meta,
        flowless_nat_wire_info(&frame, meta),
        None,
        None,
        None,
    );
    assert!(
        matches!(pre, FlowlessPreRoutingNat::Poisoned { .. }),
        "address-only poisoned DNAT must drop, got {}",
        match &pre {
            FlowlessPreRoutingNat::None => "None",
            FlowlessPreRoutingNat::Translated { .. } => "Translated",
            FlowlessPreRoutingNat::Untranslatable => "Untranslatable",
            FlowlessPreRoutingNat::Poisoned { .. } => "Poisoned",
        }
    );
    // Through flowless_base_resolution the drop is terminal (None).
    let resolved = flowless_base_resolution(
        &fw,
        &std::sync::Arc::new(ShardedNeighborMap::new()),
        &std::collections::BTreeMap::new(),
        0,
        &v4_flow(EXT4, crate::ip_proto::PROTO_GRE),
        meta,
        None,
        flowless_nat_wire_info(&frame, meta),
        None,
        None,
        None,
    );
    assert!(
        resolved.is_none(),
        "poisoned flowless packet must not resolve for forwarding"
    );
}

#[test]
fn flowless_poisoned_port_scoped_dnat_drops_15534() {
    // Port-scoped poisoned DNAT (tcp/80): the flowless packet carries
    // ports 0/0, so the entry is mis-keyed for the address-only lookup;
    // the possible-claim scan must still drop it.
    let fw = dnat_forwarding(vec![poisoned_snap("port-scoped", 80, "tcp", false)]);
    let meta = v4_meta(crate::ip_proto::PROTO_GRE);
    let frame = gre_frame();
    let pre = flowless_pre_routing_destination_nat(
        &fw,
        &v4_flow(EXT4, crate::ip_proto::PROTO_GRE),
        meta,
        flowless_nat_wire_info(&frame, meta),
        None,
        None,
        None,
    );
    assert!(
        matches!(pre, FlowlessPreRoutingNat::Poisoned { .. }),
        "port-scoped poisoned DNAT must drop, got {}",
        match &pre {
            FlowlessPreRoutingNat::None => "None",
            FlowlessPreRoutingNat::Translated { .. } => "Translated",
            FlowlessPreRoutingNat::Untranslatable => "Untranslatable",
            FlowlessPreRoutingNat::Poisoned { .. } => "Poisoned",
        }
    );
    let resolved = flowless_base_resolution(
        &fw,
        &std::sync::Arc::new(ShardedNeighborMap::new()),
        &std::collections::BTreeMap::new(),
        0,
        &v4_flow(EXT4, crate::ip_proto::PROTO_GRE),
        meta,
        None,
        flowless_nat_wire_info(&frame, meta),
        None,
        None,
        None,
    );
    assert!(resolved.is_none(), "port-scoped poison must be terminal");
}

#[test]
fn flowless_poisoned_fragment_unknown_proto_drops_15534() {
    // Non-first fragment: protocol is the 255 unknown sentinel.
    let fw = dnat_forwarding(vec![poisoned_snap("frag", 80, "tcp", false)]);
    let meta = v4_meta(crate::session::SHIM_PROTO_FRAGMENT_NO_L4);
    let frame = gre_frame();
    let pre = flowless_pre_routing_destination_nat(
        &fw,
        &v4_flow(EXT4, crate::session::SHIM_PROTO_FRAGMENT_NO_L4),
        meta,
        flowless_nat_wire_info(&frame, meta),
        None,
        None,
        None,
    );
    assert!(
        matches!(pre, FlowlessPreRoutingNat::Poisoned { .. }),
        "fragment-unknown poisoned DNAT must drop, got non-Poisoned"
    );
}

#[test]
fn flowless_healthy_dnat_controls_15534() {
    // Healthy address-only translate still translates a GRE packet.
    let mut healthy = poisoned_snap("healthy", 0, "", false);
    healthy.lenient_match_dropped = false;
    let fw = dnat_forwarding(vec![healthy]);
    let meta = v4_meta(crate::ip_proto::PROTO_GRE);
    let frame = gre_frame();
    let pre = flowless_pre_routing_destination_nat(
        &fw,
        &v4_flow(EXT4, crate::ip_proto::PROTO_GRE),
        meta,
        flowless_nat_wire_info(&frame, meta),
        None,
        None,
        None,
    );
    assert!(
        matches!(pre, FlowlessPreRoutingNat::Translated { .. }),
        "healthy address-only DNAT must still translate flowless, got {}",
        match &pre {
            FlowlessPreRoutingNat::None => "None",
            FlowlessPreRoutingNat::Translated { .. } => "Translated",
            FlowlessPreRoutingNat::Untranslatable => "Untranslatable",
            FlowlessPreRoutingNat::Poisoned { .. } => "Poisoned",
        }
    );

    // Healthy off exempts (no drop, no translation).
    let mut off = poisoned_snap("off", 0, "", true);
    off.lenient_match_dropped = false;
    let fw = dnat_forwarding(vec![off]);
    let pre = flowless_pre_routing_destination_nat(
        &fw,
        &v4_flow(EXT4, crate::ip_proto::PROTO_GRE),
        meta,
        flowless_nat_wire_info(&frame, meta),
        None,
        None,
        None,
    );
    assert!(
        matches!(pre, FlowlessPreRoutingNat::None),
        "healthy off must exempt the flowless packet, got non-None"
    );

    // No DNAT rule for the destination: no drop.
    let fw = dnat_forwarding(vec![]);
    let pre = flowless_pre_routing_destination_nat(
        &fw,
        &v4_flow(EXT4, crate::ip_proto::PROTO_GRE),
        meta,
        flowless_nat_wire_info(&frame, meta),
        None,
        None,
        None,
    );
    assert!(
        matches!(pre, FlowlessPreRoutingNat::None),
        "no DNAT rule must not drop, got non-None"
    );
}
