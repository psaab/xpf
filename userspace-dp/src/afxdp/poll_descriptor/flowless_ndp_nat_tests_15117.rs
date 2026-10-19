// #15117 (A77-02): a unicast NS/NA (NUD probe) addressed to a v6
// static-NAT (or IP-only DNAT) external was translated by the flowless
// pre-routing stage and never reached the kernel's proxy-NDP.
//
// These drive the extracted flowless decision helpers directly (the poll
// loop is un-callable): `flowless_nat_wire_info` +
// `flowless_base_resolution`, plus the frame predicate the session-miss
// arm uses (`is_ndp_hop255_frame`) and the shim predicate pulled in by
// source (same shape as `tests_shim_degraded_ndp_10863`).
use crate::afxdp::frame::is_ndp_hop255_frame;
use super::flowless_verdict::FlowlessBaseResolution;
use super::*;

#[path = "../../../../userspace-xdp/src/degraded_ndp.rs"]
mod shim_ndp_15117;

const EXTERNAL: &str = "2001:db8:0:1::10";
const INTERNAL: &str = "2001:db8:0:2::10";
const SRC: &str = "2001:db8:0:1::99";

fn v6_meta(protocol: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        protocol,
        addr_family: libc::AF_INET6 as u8,
        l3_offset: 14,
        l4_offset: 54,
        ingress_ifindex: 6,
        ..UserspaceDpMeta::default()
    }
}

fn v6_flow(dst: &str, protocol: u8) -> SessionFlow {
    let src: IpAddr = SRC.parse().unwrap();
    let dst_ip: IpAddr = dst.parse().unwrap();
    SessionFlow {
        src_ip: src,
        dst_ip,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET6 as u8,
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

/// eth + IPv6 (hop `hop`) + ICMPv6 type `ty` (8-byte header).
fn icmpv6_frame(hop: u8, ty: u8) -> Vec<u8> {
    let src: Ipv6Addr = SRC.parse().unwrap();
    let dst: Ipv6Addr = EXTERNAL.parse().unwrap();
    let mut f = vec![0u8; 14 + 40 + 8];
    f[12] = 0x86;
    f[13] = 0xDD;
    f[14] = 0x60;
    f[18..20].copy_from_slice(&8u16.to_be_bytes());
    f[20] = 58; // next header ICMPv6
    f[21] = hop;
    f[22..38].copy_from_slice(&src.octets());
    f[38..54].copy_from_slice(&dst.octets());
    f[54] = ty;
    f
}

fn static_nat_forwarding() -> ForwardingState {
    // Build through the real snapshot path so the FIB, egress and
    // interface-NAT ownership match production: the external lives on
    // the WAN interface, the internal host is routed via LAN.
    let mut snap = crate::afxdp::test_fixtures::nat_snapshot();
    snap.static_nat_rules.push(crate::StaticNATRuleSnapshot {
        name: "ndp-static".into(),
        external_ip: EXTERNAL.into(),
        internal_ip: INTERNAL.into(),
        ..Default::default()
    });
    snap.routes.push(crate::RouteSnapshot {
        family: "inet6".into(),
        destination: "2001:db8:0:2::/64".into(),
        next_hops: vec!["2001:db8:0:2::1@reth1.0".into()],
        ..Default::default()
    });
    build_forwarding_state(&snap)
}

fn resolve(
    fw: &ForwardingState,
    frame: &[u8],
    dst: &str,
    ty: u8,
) -> FlowlessBaseResolution {
    let meta = v6_meta(crate::ip_proto::PROTO_ICMPV6);
    let wire = flowless_nat_wire_info(frame, meta);
    flowless_base_resolution(
        fw,
        &std::sync::Arc::new(ShardedNeighborMap::new()),
        &std::collections::BTreeMap::new(),
        0,
        &v6_flow(dst, crate::ip_proto::PROTO_ICMPV6),
        meta,
        Some((ty, 0)),
        wire,
        None,
        None,
        None,
    )
    .expect("flowless destination resolves")
}

#[test]
fn ndp_to_static_nat_external_is_not_translated_15117() {
    let fw = static_nat_forwarding();
    for ty in [133u8, 134, 135, 136, 137] {
        let frame = icmpv6_frame(255, ty);
        assert!(
            is_ndp_hop255_frame(&frame, v6_meta(crate::ip_proto::PROTO_ICMPV6)),
            "frame predicate must classify type {ty} hop 255 as NDP"
        );
        // The pre-routing stage itself must not translate (pre-fix:
        // Translated; with only the rewrite gate: Untranslatable).
        let pre = flowless_pre_routing_destination_nat(
            &fw,
            &v6_flow(EXTERNAL, crate::ip_proto::PROTO_ICMPV6),
            v6_meta(crate::ip_proto::PROTO_ICMPV6),
            flowless_nat_wire_info(&frame, v6_meta(crate::ip_proto::PROTO_ICMPV6)),
            None,
            None,
            Some((ty, 0)),
        );
        assert!(
            !matches!(pre, FlowlessPreRoutingNat::Translated { .. }),
            "NDP type {ty} must never be pre-routing Translated (got the internal rewrite pre-fix)"
        );
        let resolved = resolve(&fw, &frame, EXTERNAL, ty);
        assert_eq!(
            resolved.nat.rewrite_dst, None,
            "NDP type {ty} to the static external must not be rewritten"
        );
        assert_eq!(
            resolved.resolution.disposition,
            ForwardingDisposition::LocalDelivery,
            "NDP type {ty} to the static external must LocalDeliver to the kernel proxy-NDP"
        );
    }
}

#[test]
fn ndp_controls_still_translate_15117() {
    let fw = static_nat_forwarding();
    // Echo request (128) to the same external still translates.
    let echo = icmpv6_frame(255, 128);
    assert!(!is_ndp_hop255_frame(
        &echo,
        v6_meta(crate::ip_proto::PROTO_ICMPV6)
    ));
    let resolved = resolve(&fw, &echo, EXTERNAL, 128);
    assert_eq!(
        resolved.nat.rewrite_dst,
        Some(INTERNAL.parse::<IpAddr>().unwrap()),
        "echo to the static external must still translate"
    );
    // Off-link NS (hop 64) is not on-link NDP: still translates.
    let off_link = icmpv6_frame(64, 135);
    assert!(!is_ndp_hop255_frame(
        &off_link,
        v6_meta(crate::ip_proto::PROTO_ICMPV6)
    ));
    let resolved = resolve(&fw, &off_link, EXTERNAL, 135);
    assert_eq!(
        resolved.nat.rewrite_dst,
        Some(INTERNAL.parse::<IpAddr>().unwrap()),
        "hop-64 NS must still translate (not on-link)"
    );
}

#[test]
fn shim_nat_external_ndp_predicate_15117() {
    for ty in 133..=137u8 {
        assert!(shim_ndp_15117::is_nat_external_ndp_control(ty, 255, true));
        assert!(!shim_ndp_15117::is_nat_external_ndp_control(ty, 64, true));
        assert!(!shim_ndp_15117::is_nat_external_ndp_control(ty, 255, false));
    }
    for ty in [128u8, 129, 1, 4] {
        assert!(!shim_ndp_15117::is_nat_external_ndp_control(ty, 255, true));
    }
}
