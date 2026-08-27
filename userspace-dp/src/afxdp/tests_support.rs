// Shared test-support helpers for the afxdp forwarding tests.
//
// Split out of afxdp/tests.rs (#4840) as a sibling `#[path]` test module
// loaded from afxdp/mod.rs. Pure code motion: every non-#[test] helper
// fn is moved verbatim (visibility widened to `pub(super)` so the
// per-subsystem test modules can call them via `use super::tests_support::*`).
#![allow(unused_imports)]
#![allow(dead_code)]

use super::test_fixtures::*;
use super::worker::WorkerTxPipeline;
use super::*;
use crate::test_zone_ids::*;
use crate::xsk_ffi::IfInfo;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    DestinationNATRuleSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot,
    InterfaceAddressSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot,
    SourceNATRuleSnapshot, StaticNATRuleSnapshot, ThreeColorPolicerSnapshot, ZoneSnapshot,
};

pub(super) fn build_icmp_echo_frame_v4(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, ttl, PROTO_ICMP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    let icmp_start = frame.len();
    frame.extend_from_slice(&[8, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]);
    let icmp_csum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    frame
}


pub(super) fn build_icmp_echo_frame_v6(src: Ipv6Addr, dst: Ipv6Addr, hop_limit: u8) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, PROTO_ICMPV6, hop_limit]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let icmp_start = frame.len();
    frame.extend_from_slice(&[128, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]);
    let icmp_csum = checksum16_ipv6(src, dst, PROTO_ICMPV6, &frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    frame
}


/// Build a `ForwardingState.filter_state` with a single egress (output) v4
/// firewall filter on ifindex 5 carrying one term (#2238 test helper).
pub(super) fn build_output_filter_state(
    filter_name: &str,
    term: FirewallTermSnapshot,
) -> crate::filter::FilterState {
    crate::filter::parse_filter_state(
        &[FirewallFilterSnapshot {
            name: filter_name.into(),
            family: "inet".into(),
            terms: vec![term],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "ge-0/0/1.0".into(),
            ifindex: 5,
            filter_output_v4: filter_name.into(),
            ..Default::default()
        }],
        "",
        "",
    ).expect("filter state compiles")
}


/// Shared egress fixture for the suppression tests: ifindex 5 with a
/// primary v4 and v6 so the emission cases can actually build a reply.
pub(super) fn icmp_suppress_forwarding() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: Some("2001:559:8585:ef00::1".parse().unwrap()),
        },
    );
    forwarding
}


pub(super) fn ttl_meta_v4() -> UserspaceDpMeta {
    UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    }
}


pub(super) fn icmp_suppress_ident() -> BindingIdentity {
    BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    }
}


pub(super) fn icmp_suppress_flow_v4(src: Ipv4Addr, dst: Ipv4Addr) -> SessionFlow {
    SessionFlow {
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(dst),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            src_ip: IpAddr::V4(src),
            dst_ip: IpAddr::V4(dst),
            src_port: 0xc000,
            dst_port: 53,
        },
    }
}


/// Drive `build_local_time_exceeded_request` end-to-end and return
/// whether it produced a request. Used by the suppression tests so each
/// case pins the CALL-SITE wiring, not just the gate predicate: removing
/// the gate from `build_local_time_exceeded_request` makes these return
/// `true` and the assertions fail.
pub(super) fn te_request_built(frame: &[u8], meta: UserspaceDpMeta) -> bool {
    let fwd = icmp_suppress_forwarding();
    let (src, dst) = match meta.addr_family as i32 {
        libc::AF_INET6 => (
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[meta.l3_offset as usize + 8..meta.l3_offset as usize + 24])
                    .unwrap(),
            )),
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[meta.l3_offset as usize + 24..meta.l3_offset as usize + 40])
                    .unwrap(),
            )),
        ),
        _ => {
            let l3 = meta.l3_offset as usize;
            (
                IpAddr::V4(Ipv4Addr::new(
                    frame[l3 + 12],
                    frame[l3 + 13],
                    frame[l3 + 14],
                    frame[l3 + 15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    frame[l3 + 16],
                    frame[l3 + 17],
                    frame[l3 + 18],
                    frame[l3 + 19],
                )),
            )
        }
    };
    let flow = SessionFlow {
        src_ip: src,
        dst_ip: dst,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            src_ip: src,
            dst_ip: dst,
            src_port: 0xc000,
            dst_port: 53,
        },
    };
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    build_local_time_exceeded_request(
        frame,
        desc,
        meta,
        &icmp_suppress_ident(),
        &flow,
        &fwd,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut BatchCounters::default(),
    )
    .is_some()
}


/// Build an IPv4 UDP frame with a configurable TTL and dst MAC so the
/// suppression tests can drive the multicast/broadcast-L2 case.
pub(super) fn build_udp_frame_v4_full(
    dst_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ttl: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    frame.extend_from_slice(&[0x08, 0x00]);
    let l3 = frame.len();
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, ttl, PROTO_UDP, 0, 0,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let ip_csum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&[0xc0, 0x00, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]); // UDP
    frame
}


pub(super) fn reject_egress_forwarding(v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: v4,
            primary_v6: v6,
        },
    );
    forwarding
}


/// Build an IPv4 UDP frame: [Eth][IP src=client dst=server proto=UDP][UDP].
pub(super) fn build_udp_frame_v4(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[
        0x00, 0x25, 0x90, 0x12, 0x34, 0x56, // dst mac (firewall)
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac (client)
        0x08, 0x00,
    ]);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 64, PROTO_UDP, 0, 0,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&[0xc0, 0x00, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]); // UDP hdr
    frame
}


/// Build an IPv4 ICMP Time Exceeded frame with an embedded TCP packet.
/// outer: [Eth][IP: src=router_ip, dst=snat_ip][ICMP type=11 code=0]
///        [Embedded: IP src=snat_ip, dst=server_ip, proto=TCP][TCP src=snat_port, dst=server_port]
pub(super) fn build_icmp_te_frame_v4(
    router_ip: Ipv4Addr,
    snat_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    snat_port: u16,
    server_port: u16,
    embedded_proto: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    // Ethernet header
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], // dst MAC
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56], // src MAC
        0,
        0x0800,
    );
    let ip_start = frame.len(); // 14

    // Build embedded IP+L4 first to know sizes
    let mut embedded = Vec::new();
    // Embedded IPv4 header (20 bytes, IHL=5)
    embedded.extend_from_slice(&[
        0x45,
        0x00,
        0x00,
        0x00, // version/IHL, DSCP, total length (fill later)
        0x00,
        0x01,
        0x00,
        0x00, // ID, flags, fragment offset
        64,
        embedded_proto,
        0x00,
        0x00, // TTL, protocol, checksum (fill later)
    ]);
    embedded.extend_from_slice(&snat_ip.octets()); // src
    embedded.extend_from_slice(&server_ip.octets()); // dst
    // Embedded L4: first 8 bytes
    if matches!(embedded_proto, PROTO_TCP | PROTO_UDP) {
        embedded.extend_from_slice(&snat_port.to_be_bytes());
        embedded.extend_from_slice(&server_port.to_be_bytes());
        embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq/other
    } else if embedded_proto == PROTO_ICMP {
        embedded.extend_from_slice(&[8, 0, 0x00, 0x00]); // echo request, checksum
        embedded.extend_from_slice(&snat_port.to_be_bytes()); // echo ID
        embedded.extend_from_slice(&[0x00, 0x01]); // seq
    }
    // Fill embedded IP total length
    let emb_total = embedded.len() as u16;
    embedded[2..4].copy_from_slice(&emb_total.to_be_bytes());
    // Compute embedded IP checksum
    embedded[10..12].copy_from_slice(&[0, 0]);
    let emb_ip_csum = checksum16(&embedded[..20]);
    embedded[10..12].copy_from_slice(&emb_ip_csum.to_be_bytes());

    // Outer ICMP header: type=11 (Time Exceeded), code=0, checksum, unused
    let mut icmp = Vec::new();
    icmp.extend_from_slice(&[11, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // type, code, csum, unused
    icmp.extend_from_slice(&embedded);
    // Compute ICMP checksum
    icmp[2..4].copy_from_slice(&[0, 0]);
    let icmp_csum = checksum16(&icmp);
    icmp[2..4].copy_from_slice(&icmp_csum.to_be_bytes());

    // Outer IPv4 header
    let outer_total_len = (20 + icmp.len()) as u16;
    frame.extend_from_slice(&[
        0x45, 0x00, // version/IHL, DSCP
    ]);
    frame.extend_from_slice(&outer_total_len.to_be_bytes()); // total length
    frame.extend_from_slice(&[
        0x00, 0x02, 0x00, 0x00, // ID, flags
        64, PROTO_ICMP, 0x00, 0x00, // TTL, protocol, checksum
    ]);
    frame.extend_from_slice(&router_ip.octets()); // src
    frame.extend_from_slice(&snat_ip.octets()); // dst

    // Compute outer IP checksum
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&[0, 0]);
    let ip_csum = checksum16(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());

    // Append ICMP payload
    frame.extend_from_slice(&icmp);

    frame
}


/// Shared meta for the IPv4 embedded-ICMP builder tests.
pub(super) fn icmp_err_meta_v4() -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    }
}


/// Resolution + metadata block shared by the v4 #3112 fixtures.
pub(super) fn icmp_err_resolution_v4(next_hop: Ipv4Addr) -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 5,
        tx_ifindex: 5,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(next_hop)),
        neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
        tx_vlan_id: 0,
    }
}


pub(super) fn icmp_err_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_UNTRUST_ZONE_ID,
        egress_zone: TEST_TRUST_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}


/// Build an IPv6 ICMPv6 Time Exceeded frame with an embedded TCP packet.
pub(super) fn build_icmpv6_te_frame(
    router_ip: Ipv6Addr,
    snat_ip: Ipv6Addr,
    server_ip: Ipv6Addr,
    snat_port: u16,
    server_port: u16,
    embedded_proto: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );

    // Build embedded IPv6+L4
    let mut embedded = Vec::new();
    // IPv6 header (40 bytes)
    embedded.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version, traffic class, flow label
    let emb_payload_len = 8u16; // 8 bytes of L4
    embedded.extend_from_slice(&emb_payload_len.to_be_bytes());
    embedded.push(embedded_proto); // next header
    embedded.push(64); // hop limit
    embedded.extend_from_slice(&snat_ip.octets()); // src
    embedded.extend_from_slice(&server_ip.octets()); // dst
    // Embedded L4: first 8 bytes
    if matches!(embedded_proto, PROTO_TCP | PROTO_UDP) {
        embedded.extend_from_slice(&snat_port.to_be_bytes());
        embedded.extend_from_slice(&server_port.to_be_bytes());
        embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    } else if embedded_proto == PROTO_ICMPV6 {
        embedded.extend_from_slice(&[128, 0, 0x00, 0x00]); // echo request, checksum
        embedded.extend_from_slice(&snat_port.to_be_bytes()); // echo ID
        embedded.extend_from_slice(&[0x00, 0x01]); // seq
    }

    // ICMPv6 header: type=3 (Time Exceeded), code=0, checksum, unused
    let mut icmp6 = Vec::new();
    icmp6.extend_from_slice(&[3, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    icmp6.extend_from_slice(&embedded);

    // Outer IPv6 header
    let payload_len = icmp6.len() as u16;
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.push(PROTO_ICMPV6); // next header
    frame.push(64); // hop limit
    frame.extend_from_slice(&router_ip.octets()); // src
    frame.extend_from_slice(&snat_ip.octets()); // dst

    // Compute ICMPv6 checksum (covers pseudo-header)
    icmp6[2..4].copy_from_slice(&[0, 0]);
    let csum = checksum16_ipv6(router_ip, snat_ip, PROTO_ICMPV6, &icmp6);
    icmp6[2..4].copy_from_slice(&csum.to_be_bytes());

    frame.extend_from_slice(&icmp6);
    frame
}


/// Flexible ICMPv6 Time Exceeded fixture for the #1838 §5.7 builder
/// tests: optional outer hop-by-hop ext header (8 bytes between the
/// outer IPv6 header and the ICMPv6 header), optional fragment header
/// in the EMBEDDED quoted packet (with caller-controlled raw
/// offset/flags bytes), and optional trailing bytes inside the ICMPv6
/// checksum coverage (used to force a computed-zero checksum).
#[allow(clippy::too_many_arguments)]
pub(super) fn build_icmpv6_te_frame_ext(
    router_ip: Ipv6Addr,
    snat_ip: Ipv6Addr,
    server_ip: Ipv6Addr,
    snat_port: u16,
    server_port: u16,
    outer_hbh: bool,
    embedded_frag_off_flags: Option<u16>,
    trailing: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );

    // Embedded IPv6 (+ optional fragment header) + 8 bytes of TCP.
    let mut embedded = Vec::new();
    embedded.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    let frag_len = if embedded_frag_off_flags.is_some() {
        8
    } else {
        0
    };
    let emb_payload_len = (frag_len + 8) as u16;
    embedded.extend_from_slice(&emb_payload_len.to_be_bytes());
    embedded.push(if embedded_frag_off_flags.is_some() {
        44 // fragment header
    } else {
        PROTO_TCP
    });
    embedded.push(64);
    embedded.extend_from_slice(&snat_ip.octets());
    embedded.extend_from_slice(&server_ip.octets());
    if let Some(off_flags) = embedded_frag_off_flags {
        embedded.push(PROTO_TCP); // next header after the fragment hdr
        embedded.push(0); // reserved
        embedded.extend_from_slice(&off_flags.to_be_bytes());
        embedded.extend_from_slice(&[0, 0, 0, 1]); // identification
    }
    embedded.extend_from_slice(&snat_port.to_be_bytes());
    embedded.extend_from_slice(&server_port.to_be_bytes());
    embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // ICMPv6 Time Exceeded + embedded + trailing.
    let mut icmp6 = Vec::new();
    icmp6.extend_from_slice(&[3, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    icmp6.extend_from_slice(&embedded);
    icmp6.extend_from_slice(trailing);

    // Outer IPv6 header (+ optional hop-by-hop).
    let hbh_len = if outer_hbh { 8usize } else { 0 };
    let payload_len = (hbh_len + icmp6.len()) as u16;
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.push(if outer_hbh { 0 } else { PROTO_ICMPV6 });
    frame.push(64);
    frame.extend_from_slice(&router_ip.octets());
    frame.extend_from_slice(&snat_ip.octets());
    if outer_hbh {
        // Hop-by-hop: next = ICMPv6, hdr-ext-len 0 → 8 bytes total.
        frame.extend_from_slice(&[PROTO_ICMPV6, 0, 1, 4, 0, 0, 0, 0]);
    }

    icmp6[2..4].copy_from_slice(&[0, 0]);
    let csum = checksum16_ipv6(router_ip, snat_ip, PROTO_ICMPV6, &icmp6);
    let csum = if csum == 0 { 0xffff } else { csum };
    icmp6[2..4].copy_from_slice(&csum.to_be_bytes());

    frame.extend_from_slice(&icmp6);
    frame
}


pub(super) fn icmpv6_te_match_fixture(
    snat_ip: Ipv6Addr,
    client_ip: Ipv6Addr,
    snat_port: u16,
    client_port: u16,
) -> EmbeddedIcmpMatch {
    EmbeddedIcmpMatch {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(snat_ip)),
            rewrite_src_port: Some(snat_port),
            ..NatDecision::default()
        },
        original_src: IpAddr::V6(client_ip),
        original_src_port: client_port,
        original_dst: IpAddr::V6(client_ip),
        original_dst_port: client_port,
        embedded_proto: PROTO_TCP,
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(client_ip)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
            tx_vlan_id: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_UNTRUST_ZONE_ID,
            egress_zone: TEST_TRUST_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        outbound_snat: false,
    }
}


pub(super) fn icmpv6_te_meta(l4_offset: u16) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    }
}


/// Rewrite the outer ICMPv4 type byte (frame[l4_offset]) to `new_type`
/// and recompute the outer ICMP checksum, leaving the 8-byte ICMP header
/// length unchanged. ICMPv4 Redirect (5) and Source Quench (4) share the
/// 3/11/12 header layout — the type-specific word (Redirect's gateway
/// address) occupies bytes 4..8 where Time Exceeded carries its unused
/// word — so an existing type-11 frame becomes a valid type-5/4 frame by
/// flipping the type byte and refreshing the checksum.
pub(super) fn rewrite_outer_icmpv4_type(frame: &mut [u8], l4_offset: usize, new_type: u8) {
    frame[l4_offset] = new_type;
    frame[l4_offset + 2] = 0;
    frame[l4_offset + 3] = 0;
    let csum = checksum16(&frame[l4_offset..]);
    frame[l4_offset + 2..l4_offset + 4].copy_from_slice(&csum.to_be_bytes());
}


pub(super) fn build_policy_deny_tcp_syn_frame() -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61, 102,
        172, 16, 80, 200,
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    frame.extend_from_slice(&12345u16.to_be_bytes());
    frame.extend_from_slice(&5201u16.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, TCP_FLAG_SYN, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00]);
    frame
}


pub(super) fn set_ipv4_dst(frame: &mut [u8], dst: Ipv4Addr) {
    frame[24] = 0;
    frame[25] = 0;
    frame[30..34].copy_from_slice(&dst.octets());
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
}


/// #2617 harness: drive a single LAN→WAN TCP-SYN session-miss packet through
/// `poll_binding_process_descriptor` with an interface input filter whose term
/// is `then { log; accept; }` matching dport 5201. Returns the worker event
/// handle (for `filter_log.sent` stats) plus the decoded receiver so callers
/// can assert the emitted RT_FLOW event.
///
/// `max_sessions` caps the worker session table BEFORE the poll: `Some(0)`
/// forces the ForwardCandidate install to be REFUSED (admission cap), which
/// exercises the cache-declined / short-lived permitted-flow path the #2617
/// fix repairs — the accepted `then log` must still emit on the miss packet
/// even though no session is installed.
pub(super) fn run_input_filter_accept_log_poll(
    max_sessions: Option<usize>,
) -> (
    crate::event_stream::EventStreamWorkerHandle,
    std::sync::mpsc::Receiver<crate::event_stream::codec::EventFrame>,
) {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        },
    ];
    snapshot.interfaces[0].filter_input_v4 = "log-input".to_string();
    snapshot.neighbors = vec![NeighborSnapshot {
        interface: "reth0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: "172.16.80.200".to_string(),
        mac: "00:aa:bb:cc:dd:ee".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    }];
    snapshot.routes = vec![RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "0.0.0.0/0".to_string(),
        next_hops: vec!["172.16.80.200@reth0.80".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
    }];
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "log-input".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "log-web".to_string(),
            action: "accept".to_string(),
            destination_ports: vec!["5201".to_string()],
            log: true,
            ..Default::default()
        }],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let frame = build_policy_deny_tcp_syn_frame();
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    if let Some(cap) = max_sessions {
        sessions.set_max_sessions_for_test(cap);
    }
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    (event_handle, event_rx)
}


/// Assert the common shape of the emitted accepted input-filter `then log`
/// RT_FLOW event (shared by the install-success and install-refused #2617
/// tests).
pub(super) fn assert_input_filter_accept_log_event(
    event_handle: &crate::event_stream::EventStreamWorkerHandle,
    event_rx: &std::sync::mpsc::Receiver<crate::event_stream::codec::EventFrame>,
) {
    let event = event_rx
        .try_recv()
        .expect("input filter-log event from poll descriptor")
        .decode_dataplane_event()
        .expect("filter-log payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(event.reason, FilterLogSource::Input.wire_reason());
    assert_eq!(event.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));
    assert_eq!(event.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(event.dst_port, 5201);
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(event.egress_zone_id, 0);
    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
}


// #4743: a NoRoute drop whose destination is a martian address bumps BOTH
// route_miss_packets AND the martian_dropped sub-breakout. RED-on-revert:
// removing the `counters.bump_martian()` call in the NoRoute arm makes this fail
// (martian_dropped stays 0). A non-martian NoRoute leaves martian_dropped 0.
pub(super) fn record_noroute_with_dst(
    counters: &mut BatchCounters,
    dst: std::net::IpAddr,
) {
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let binding = BindingIdentity {
        slot: 1,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-0"),
        ifindex: 3,
    };
    let dbg = crate::afxdp::ResolutionDebug {
        ingress_ifindex: 3,
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5))),
        dst_ip: Some(dst),
        src_port: 1000,
        dst_port: 2000,
        from_zone: None,
        to_zone: None,
    };
    record_forwarding_disposition(
        &binding,
        DispositionCounters::Hot(counters),
        ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        64,
        None,
        Some(&dbg),
        &recent_exceptions,
        &Arc::new(Mutex::new(None)),
        &ForwardingState::default(),
    );
}


pub(super) fn txn_ha_state() -> BTreeMap<i32, HAGroupRuntime> {
    let mut ha = BTreeMap::new();
    for rg in [1, 2] {
        ha.insert(
            rg,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 123,
                lease: HAGroupRuntime::active_lease_until(123, 123),
            },
        );
    }
    ha
}


pub(super) fn build_txn_tcp_syn_frame_v4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x01, 0x00, 0x01],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        0,
        0x0800,
    );
    let s = src.octets();
    let d = dst.octets();
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, s[0], s[1],
        s[2], s[3], d[0], d[1], d[2], d[3],
    ]);
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, tcp_flags, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00]);
    frame
}


pub(super) fn txn_meta_v4(ingress_ifindex: u32, tcp_flags: u8, pkt_len: u16) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}


/// Push one frame through `poll_binding_process_descriptor` against the
/// given table/forwarding state. Owns the per-call shared-map and
/// telemetry scaffolding; the caller keeps `binding` + `sessions` across
/// calls so multi-phase pins can observe accumulated state.
pub(super) fn txn_run_descriptor(
    binding: &mut BindingWorker,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> (BatchCounters, DebugPollCounters) {
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    txn_run_descriptor_with_deliveries(
        binding,
        sessions,
        forwarding,
        ha_state,
        frame,
        meta,
        &local_tunnel_deliveries,
    )
}


/// `txn_run_descriptor` with a CALLER-PROVIDED `dynamic_neighbors` map, so a
/// test can seed the shard MAC-change epochs BEFORE the poll takes its
/// pre-resolve snapshot (`snapshot_shard_epochs`). Used by the #6075 poll
/// epoch-snapshot pin: the flow-cache `neighbor_mac_epoch` a tunnel forward
/// stamps must be read from the OUTER transport neighbor's shard, so the test
/// pre-bumps that specific shard and asserts the stamp reflects it. The stock
/// `txn_run_descriptor*` helpers own an internal fresh (all-zero) map, which
/// cannot exercise a non-zero snapshot. Returns the batch + debug counters.
pub(super) fn txn_run_descriptor_with_neighbors(
    binding: &mut BindingWorker,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    frame: &[u8],
    meta: UserspaceDpMeta,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> (BatchCounters, DebugPollCounters) {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(binding));
    let mirror_targets = MirrorTargetMap::default();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding,
        ha_state,
        dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: None,
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;
    poll_binding_process_descriptor(
        binding,
        0,
        area_ptr,
        1,
        sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );
    (batch, dbg)
}


/// `txn_run_descriptor` with a caller-provided `local_tunnel_deliveries`
/// map, so the GRE local-origin INBOUND delivery pins (#1885) can
/// observe exactly the bytes that would be written to the gr- TUN.
pub(super) fn txn_run_descriptor_with_deliveries(
    binding: &mut BindingWorker,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    frame: &[u8],
    meta: UserspaceDpMeta,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
) -> (BatchCounters, DebugPollCounters) {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(binding));
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding,
        ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: None,
        local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;
    poll_binding_process_descriptor(
        binding,
        0,
        area_ptr,
        1,
        sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );
    (batch, dbg)
}


/// `txn_run_descriptor` with an event stream wired so a cold-path emit (deny /
/// filter-log / host-inbound deny) can be observed on the returned receiver.
/// Returns the batch + debug counters AND the event handle/receiver.
pub(super) fn txn_run_descriptor_capturing_events(
    binding: &mut BindingWorker,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> (
    BatchCounters,
    DebugPollCounters,
    crate::event_stream::EventStreamWorkerHandle,
    std::sync::mpsc::Receiver<crate::event_stream::codec::EventFrame>,
) {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(binding));
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding,
        ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;
    poll_binding_process_descriptor(
        binding,
        0,
        area_ptr,
        1,
        sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        crate::afxdp::neighbor::monotonic_nanos(),
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );
    (batch, dbg, event_handle, event_rx)
}


pub(super) fn txn_flow_cache_entries(binding: &BindingWorker) -> usize {
    binding.flow.flow_cache.entries.iter().flatten().count()
}


pub(super) fn build_txn_tcp_syn_frame_v6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x01, 0x00, 0x01],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        0,
        0x86dd,
    );
    // IPv6 header: version 6, payload len 20 (TCP), next header TCP, hop 64.
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x14, PROTO_TCP, 64]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let tcp_start = frame.len();
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&[0x50, TCP_FLAG_SYN, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00]);
    let csum = checksum16_ipv6(src, dst, PROTO_TCP, &frame[tcp_start..]);
    frame[tcp_start + 16] = (csum >> 8) as u8;
    frame[tcp_start + 17] = csum as u8;
    frame
}


pub(super) fn tunnel_gate_test_fixture() -> (
    BindingIdentity,
    BindingLiveState,
    Arc<Mutex<ExceptionEventRing>>,
    UserspaceDpMeta,
    Vec<u8>,
) {
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    (binding, live, recent_exceptions, meta, frame)
}


pub(super) fn tunnel_marked_decision(disposition: ForwardingDisposition) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 0,
            tunnel_endpoint_id: 824,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}


/// #1885 fixture: WAN underlay (reth0.80, VLAN 80) + a gre endpoint
/// whose local outer address is 172.16.80.8 and whose gr- interface
/// (ifindex 77) carries the inner address 10.255.0.1/30, so an inner
/// packet to 10.255.0.1 resolves LocalDelivery with
/// `local_ifindex == 77` — the `local_tunnel_deliveries` key.
/// Default-permit so host-inbound resolution, not policy, decides.
pub(super) fn gre_to_self_snapshot() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.source_nat_rules.clear();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "gr-0/0/0.0".to_string(),
        zone: "wan".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 77,
        tunnel: true,
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.255.0.1/30".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.tunnel_endpoints = vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
        id: 824,
        interface: "gr-0/0/0.0".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 77,
        zone: "wan".to_string(),
        mode: "gre".to_string(),
        outer_family: "inet".to_string(),
        source: "172.16.80.8".to_string(),
        destination: "203.0.113.9".to_string(),
        transport_table: "inet.0".to_string(),
        ttl: 64,
        ..Default::default()
    }];
    snapshot
}


/// Inner ICMP echo request 10.255.0.2 -> 10.255.0.1 (the gr-local
/// inner address): 20-byte IPv4 header + 8-byte ICMP + 8 payload.
pub(super) fn build_gre_inner_icmp_packet_v4() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00, 64, PROTO_ICMP, 0x00, 0x00, 10, 255, 0, 2,
        10, 255, 0, 1,
    ]);
    let ip_sum = checksum16(&packet[0..20]);
    packet[10] = (ip_sum >> 8) as u8;
    packet[11] = ip_sum as u8;
    let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
    icmp.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]);
    let icmp_sum = checksum16(&icmp);
    icmp[2] = (icmp_sum >> 8) as u8;
    icmp[3] = icmp_sum as u8;
    packet.extend_from_slice(&icmp);
    packet
}


/// GRE-to-self OUTER frame: peer 203.0.113.9 -> local 172.16.80.8,
/// proto 47, flagless GRE (proto 0x0800) wrapping `inner`. `vlan_id`
/// 0 = untagged underlay (L3 at 14); nonzero = 802.1Q-tagged underlay
/// (L3 at 18) — the live reth0.80 shape from #1885.
pub(super) fn build_gre_to_self_outer_frame_v4(vlan_id: u16, inner: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        vlan_id,
        0x0800,
    );
    let l3 = frame.len();
    let total = (20 + 4 + inner.len()) as u16;
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&[
        0x00, 0x01, 0x00, 0x00, 64, PROTO_GRE, 0x00, 0x00, 203, 0, 113, 9, 172, 16, 80, 8,
    ]);
    let ip_sum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10] = (ip_sum >> 8) as u8;
    frame[l3 + 11] = ip_sum as u8;
    frame.extend_from_slice(&[0x00, 0x00, 0x08, 0x00]); // flagless GRE, proto IPv4
    frame.extend_from_slice(inner);
    frame
}


/// Shim-contract meta for the GRE OUTER frame (`parse_l2` in
/// userspace-xdp is VLAN-aware: tagged L3 at 18, untagged at 14).
pub(super) fn gre_to_self_outer_meta(vlan_id: u16, frame_len: usize) -> UserspaceDpMeta {
    let l3: u16 = if vlan_id > 0 { 18 } else { 14 };
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 11,
        ingress_vlan_id: vlan_id,
        ingress_vlan_present: u8::from(vlan_id > 0),
        l3_offset: l3,
        l4_offset: l3 + 20,
        payload_offset: l3 + 24,
        pkt_len: frame_len as u16 - l3,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_GRE,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}


/// #1885 driver: run one GRE-to-self outer frame end-to-end through
/// `poll_binding_process_descriptor` with a registered gr- delivery
/// channel and assert the TUN-bound payload is the decapped INNER
/// packet, byte-identical, delivered EXACTLY once.
pub(super) fn assert_gre_to_self_delivers_inner_exactly_once(vlan_id: u16) {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let mut sessions = SessionTable::new();

    let inner = build_gre_inner_icmp_packet_v4();
    let frame = build_gre_to_self_outer_frame_v4(vlan_id, &inner);
    let meta = gre_to_self_outer_meta(vlan_id, frame.len());

    let (tx, rx) = mpsc::sync_channel(8);
    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
    let mut deliveries = BTreeMap::new();
    deliveries.insert(77, LocalTunnelDelivery { tx, wake });
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));

    txn_run_descriptor_with_deliveries(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &local_tunnel_deliveries,
    );

    let delivered = rx
        .try_recv()
        .expect("GRE-to-self inner packet must reach the gr- delivery channel");
    assert_eq!(
        delivered[0] >> 4,
        4,
        "TUN-bound payload must start with the IP version nibble \
         (IFF_NO_PI contract — the #1885 EINVAL observable), got {:02x?}",
        &delivered[..delivered.len().min(8)]
    );
    assert_eq!(
        delivered, inner,
        "delivery must be the decapped INNER packet byte-identical — \
         not an outer-frame slice (mis-paired frame/meta, #1885)"
    );
    assert!(
        rx.try_recv().is_err(),
        "exactly ONE delivery per packet — the LocalDelivery arm must \
         not enqueue in addition to the leg's trailing chokepoint"
    );
}


/// #3019: gre_to_self_snapshot (default-permit, lan ingress, 10.255.0.1 local)
/// optionally extended with a `from-zone lan to-zone junos-host` policy.
pub(super) fn junos_host_local_delivery_snapshot(action: Option<&str>) -> ConfigSnapshot {
    let mut snapshot = gre_to_self_snapshot();
    if let Some(act) = action {
        snapshot.policies.push(PolicyRuleSnapshot {
            name: "host-policy".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "junos-host".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: act.to_string(),
            ..Default::default()
        });
    }
    snapshot
}


/// #3019: gre_to_self_snapshot extended with a `from-zone lan to-zone
/// junos-host then permit` policy carrying an explicit `then log` selection and
/// a non-zero admitting `policy_id` — the #3706 fixture. `log_init`/`log_close`
/// drive the policy's Junos `then log session-init`/`session-close` selection.
pub(super) fn junos_host_local_delivery_permit_snapshot(
    log_init: bool,
    log_close: bool,
    policy_id: u32,
) -> ConfigSnapshot {
    let mut snapshot = gre_to_self_snapshot();
    snapshot.policies.push(PolicyRuleSnapshot {
        name: "host-permit-log".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "junos-host".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        log_session_init: log_init,
        log_session_close: log_close,
        policy_id,
        ..Default::default()
    });
    snapshot
}


/// #3706 helper: run the session-MISS LocalDelivery descriptor for a host-bound
/// TCP/179 SYN under `snapshot` and return the metadata of the single installed
/// host-local session (log flags, admitting policy id, hit-counter handle),
/// asserting exactly one session was cached and it was not policy-denied.
pub(super) fn run_junos_host_permit_local_delivery(snapshot: &ConfigSnapshot) -> (bool, bool, u32, u32) {
    let forwarding = build_forwarding_state(snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 255, 0, 1),
        12345,
        179,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);

    let (tx, rx) = mpsc::sync_channel(8);
    let wake = Arc::new(TunnelWake::new().expect("eventfd"));
    let mut deliveries = BTreeMap::new();
    deliveries.insert(77, LocalTunnelDelivery { tx, wake });
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(deliveries));

    let (_batch, dbg) = txn_run_descriptor_with_deliveries(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &local_tunnel_deliveries,
    );
    let _ = rx;

    assert_eq!(dbg.local, 1, "packet must take the LocalDelivery arm");
    assert_eq!(
        dbg.policy_deny, 0,
        "a to-zone junos-host permit must NOT policy-deny the host-bound flow"
    );
    assert_eq!(
        sessions.len(),
        1,
        "a permitted host-bound flow must cache exactly one host-local session"
    );
    let mut seen = None;
    sessions.iter_with_origin(|_key, _decision, md, _origin| {
        seen = Some((
            md.log_session_init,
            md.log_session_close,
            md.policy_id,
            md.policy_counter_idx,
        ));
    });
    seen.expect("a host-local session must be installed for a permitted flow")
}


/// #2782: GRE-to-self OUTER frame whose GRE header carries the optional
/// fields selected by `flags` (any of `GRE_FLAG_CHECKSUM` / `GRE_FLAG_KEY`
/// / `GRE_FLAG_SEQUENCE`), wrapping `inner`. When the Checksum-Present (C)
/// bit is set the 4-byte Checksum+Reserved1 field is emitted FIRST (RFC
/// 2890 fixed order: Checksum, Key, Sequence) and the 16-bit checksum is
/// computed over the whole GRE header + payload (IP one's-complement,
/// checksum field zeroed during the sum) so a conformant peer's frame is
/// reproduced. `corrupt_checksum` flips one payload byte AFTER the
/// checksum is written, so the C-bit frame fails verification — used to
/// drive the invalid-checksum drop counter. The outer IPv4 Total Length
/// is set to exactly cover the GRE header + inner (no trailing pad), so
/// the decap-side checksum region is bounded correctly.
pub(super) fn build_gre_checksum_present_outer_frame_v4(
    vlan_id: u16,
    flags: u16,
    key: u32,
    seq: u32,
    inner: &[u8],
    corrupt_checksum: bool,
) -> Vec<u8> {
    let checksum_present = (flags & 0x8000) != 0;
    let key_present = (flags & 0x2000) != 0;
    let sequence_present = (flags & 0x1000) != 0;

    // Build the GRE header + payload separately so we can compute the
    // checksum over exactly that region.
    let mut gre = Vec::new();
    gre.extend_from_slice(&flags.to_be_bytes());
    gre.extend_from_slice(&0x0800u16.to_be_bytes()); // inner proto IPv4
    let checksum_field_at = if checksum_present {
        let at = gre.len();
        gre.extend_from_slice(&[0x00, 0x00]); // Checksum (filled below)
        gre.extend_from_slice(&[0x00, 0x00]); // Reserved1
        Some(at)
    } else {
        None
    };
    if key_present {
        gre.extend_from_slice(&key.to_be_bytes());
    }
    if sequence_present {
        gre.extend_from_slice(&seq.to_be_bytes());
    }
    gre.extend_from_slice(inner);
    if let Some(at) = checksum_field_at {
        let sum = checksum16(&gre);
        gre[at] = (sum >> 8) as u8;
        gre[at + 1] = sum as u8;
    }
    if corrupt_checksum {
        // Flip a payload byte after the checksum is sealed so the C-bit
        // verification fails (but a flagless decap would still parse it).
        let last = gre.len() - 1;
        gre[last] ^= 0xff;
    }

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        vlan_id,
        0x0800,
    );
    let l3 = frame.len();
    let total = (20 + gre.len()) as u16;
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&[
        0x00, 0x01, 0x00, 0x00, 64, PROTO_GRE, 0x00, 0x00, 203, 0, 113, 9, 172, 16, 80, 8,
    ]);
    let ip_sum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10] = (ip_sum >> 8) as u8;
    frame[l3 + 11] = ip_sum as u8;
    frame.extend_from_slice(&gre);
    frame
}


/// Build a flagless-GRE OUTER frame (peer 203.0.113.9 -> local
/// 172.16.80.8, the `gre_to_self_snapshot` tunnel tuple) carrying an
/// arbitrary `inner` packet under the GRE inner proto `gre_inner_proto`
/// (0x0800 = IPv4 inner, 0x86dd = IPv6 inner). The outer IP total length
/// is taken from the actual byte counts so a deliberately short inner
/// still produces a well-formed OUTER — the truncation is purely in the
/// inner, which is what the #2376 guard inspects. Untagged underlay
/// (L3 at 14).
pub(super) fn build_gre_to_self_outer_frame_with_inner(gre_inner_proto: u16, inner: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        0,
        0x0800,
    );
    let l3 = frame.len();
    let total = (20 + 4 + inner.len()) as u16;
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&[
        0x00, 0x01, 0x00, 0x00, 64, PROTO_GRE, 0x00, 0x00, 203, 0, 113, 9, 172, 16, 80, 8,
    ]);
    let ip_sum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10] = (ip_sum >> 8) as u8;
    frame[l3 + 11] = ip_sum as u8;
    // Flagless GRE header: flags/version = 0, protocol = gre_inner_proto.
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&gre_inner_proto.to_be_bytes());
    frame.extend_from_slice(inner);
    frame
}


/// IPv4 inner with `protocol` and `total_len` set to `ihl + l4_bytes`
/// (ihl = 20). `l4_bytes` is how many bytes of L4 follow the IP header in
/// the IP-declared length; the physical packet is padded to the declared
/// length so `packet_trimmed_len` returns `total_len` (the truncation
/// being tested is "declared length too short for the L4 header", not a
/// short physical buffer).
pub(super) fn build_gre_inner_v4(protocol: u8, l4_bytes: usize) -> Vec<u8> {
    let total = 20 + l4_bytes;
    let mut packet = vec![
        0x45,
        0x00,
        (total >> 8) as u8,
        total as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        64,
        protocol,
        0x00,
        0x00,
        10,
        255,
        0,
        2,
        10,
        255,
        0,
        1,
    ];
    let ip_sum = checksum16(&packet[0..20]);
    packet[10] = (ip_sum >> 8) as u8;
    packet[11] = ip_sum as u8;
    packet.extend(std::iter::repeat(0u8).take(l4_bytes));
    packet
}


/// IPv6 inner with the given next-header `protocol`, `payload_len`
/// L4 bytes after the 40-byte fixed header. Physical buffer padded to the
/// declared length so the truncation is in the IP-declared length, not
/// the buffer.
pub(super) fn build_gre_inner_v6(protocol: u8, payload_len: usize) -> Vec<u8> {
    let mut packet = vec![0x60, 0x00, 0x00, 0x00];
    packet.extend_from_slice(&(payload_len as u16).to_be_bytes());
    packet.push(protocol);
    packet.push(64); // hop limit
    // src 2001:db8::2, dst 2001:db8::1
    packet.extend_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ]);
    packet.extend_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
    packet.extend(std::iter::repeat(0u8).take(payload_len));
    packet
}


/// #1902 fixture: inner TCP SYN L3 packet (no Ethernet header — it is
/// the flagless-GRE proto-0x0800 payload) 10.255.0.2 -> `dst`. With
/// `dst` on the reth1.0 connected subnet the decap-INBOUND forward
/// decision egresses a PLAIN interface (`tunnel_endpoint_id == 0`) —
/// not LocalDelivery, not a tunnel-marked encap — so a cold neighbor
/// reaches the MissingNeighbor pending_neigh admission site.
pub(super) fn build_gre_inner_tcp_syn_packet_v4(dst: Ipv4Addr) -> Vec<u8> {
    let mut packet = Vec::new();
    let d = dst.octets();
    packet.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 255, 0, 2,
        d[0], d[1], d[2], d[3],
    ]);
    let ip_sum = checksum16(&packet[0..20]);
    packet[10] = (ip_sum >> 8) as u8;
    packet[11] = ip_sum as u8;
    packet.extend_from_slice(&12345u16.to_be_bytes());
    packet.extend_from_slice(&443u16.to_be_bytes());
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.extend_from_slice(&0u32.to_be_bytes());
    packet.extend_from_slice(&[0x50, TCP_FLAG_SYN, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00]);
    packet
}


/// #1902 driver: one GRE-to-self outer frame whose INNER packet
/// forwards out reth1.0 toward a COLD neighbor, end-to-end through
/// `poll_binding_process_descriptor`, then neighbor resolution +
/// `retry_pending_neigh`. Pre-#1902 the MissingNeighbor arm buffered
/// `desc` (the un-decapped OUTER UMEM frame, VLAN-tagged on the
/// reth0.80 underlay) paired with the post-decap INNER meta/decision,
/// and the retry swept that entry into a prepared TX — the
/// still-encapsulated outer GRE packet rewritten at inner-meta
/// offsets, transmitted toward the inner next-hop. Fixed: the packet
/// is never admitted (counted, recycled) and the retry TXes nothing;
/// first-packet delivery rides the trailing decap-aware slow-path
/// chokepoint (#1901), which pairs the INNER frame correctly.
pub(super) fn assert_decapped_missing_neighbor_never_buffered_or_retried(vlan_id: u16) {
    let mut forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let ha_state = txn_ha_state();
    // bindings[0] = WAN parent ingress (ifindex 11); bindings[1] = the
    // inner-egress LAN binding (ifindex 24) so a defective retry TX has
    // a real target binding and would land in its pending_tx_prepared.
    let mut bindings = vec![
        BindingWorker::new_for_mirror_test(0, 0, 11, 0),
        BindingWorker::new_for_mirror_test(1, 0, 24, 0),
    ];
    bindings[0].interface = Arc::<str>::from("ge-0-0-0");
    bindings[1].interface = Arc::<str>::from("ge-0-0-1");
    let mut sessions = SessionTable::new();

    let inner_dst = Ipv4Addr::new(10, 0, 61, 50);
    let inner = build_gre_inner_tcp_syn_packet_v4(inner_dst);
    let frame = build_gre_to_self_outer_frame_v4(vlan_id, &inner);
    let meta = gre_to_self_outer_meta(vlan_id, frame.len());

    let (_batch, dbg) = txn_run_descriptor(
        &mut bindings[0],
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(
        dbg.missing_neigh, 1,
        "inner dst neighbor is cold -> the packet must take the MissingNeighbor arm"
    );
    assert!(
        bindings[0].pending_neigh.is_empty(),
        "#1902: a GRE-decapped packet must NEVER be admitted to pending_neigh — \
         desc references the un-decapped OUTER frame while meta/decision \
         describe the synthetic INNER frame"
    );
    assert_eq!(
        bindings[0]
            .live
            .pending_neigh_decap_drops
            .load(Ordering::Relaxed),
        1,
        "the decap-refusal gate must count the refused candidate"
    );
    assert!(
        bindings[0].scratch.scratch_recycle.contains(&128),
        "the refused frame must be recycled now, not pinned in pending_neigh"
    );

    // Resolve the inner next-hop and run the retry sweep: nothing may be
    // TXed from the (empty) buffer. Pre-#1902 this swept the mis-paired
    // entry into bindings[1].tx_pipeline.pending_tx_prepared.
    forwarding.neighbors.insert(
        (24, IpAddr::V4(inner_dst)),
        NeighborEntry {
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        },
    );
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut shared_recycles = Vec::new();
    let area = bindings[0].umem.area() as *const MmapArea;
    let (left, rest) = bindings.split_at_mut(0);
    let (binding, right) = rest.split_first_mut().expect("ingress binding");
    retry_pending_neigh(
        binding,
        left,
        0,
        right,
        &lookup,
        &mirror_targets,
        &forwarding,
        &dynamic_neighbors,
        None,
        123_000_000_100,
        // SAFETY: `area` was cast from `&MmapArea` borrowed out of
        // bindings[0].umem just above; the allocation lives past this
        // call, the split borrows cover disjoint binding state (not the
        // umem area), and the test is single-threaded.
        unsafe { &*area },
        &mut shared_recycles,
    );
    for (i, b) in bindings.iter().enumerate() {
        assert!(
            b.tx_pipeline.pending_tx_prepared.is_empty(),
            "binding {i}: no retried TX may exist for a decapped packet — \
             pre-#1902 the untagged variant held the OUTER GRE frame \
             (proto 47, outer dst = the firewall itself) truncated to the \
             inner length and MAC-rewritten toward the inner next-hop"
        );
    }
}


pub(super) fn dnat_snat_decision() -> NatDecision {
    NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(54321),
        ..NatDecision::default()
    }
}


pub(super) fn dnat_v4_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 443,
    }
}


pub(super) fn dnat_v6_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6("2001:559:8585:61::100".parse::<Ipv6Addr>().unwrap()),
        dst_ip: IpAddr::V6("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()),
        src_port: 12345,
        dst_port: 443,
    }
}


pub(super) fn dnat_snat_decision_v6() -> NatDecision {
    NatDecision {
        rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap())),
        rewrite_src_port: Some(54321),
        ..NatDecision::default()
    }
}


/// v6 ingress meta for the txn harness (TCP, ingress on `ifindex`).
pub(super) fn txn_meta_v6(ingress_ifindex: u32, frame_len: usize) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 74,
        pkt_len: (frame_len - 14) as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}


/// Build a wan->lan inbound DNAT snapshot: public VIP 172.16.80.8:443 is
/// port-DNAT'd to the internal LAN host 10.0.61.102:8443. The internal
/// host is directly connected on reth1.0 (10.0.61.0/24) and given a
/// neighbor so the translated destination resolves to a ForwardCandidate.
/// The caller supplies the single from=wan/to=lan policy.
pub(super) fn inbound_dnat_snapshot(policy: PolicyRuleSnapshot) -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.destination_nat_rules = vec![DestinationNATRuleSnapshot {
        counter_id: 0,
        name: "web-dnat".to_string(),
        from_zone: "wan".to_string(),
        from_interface: String::new(),
        from_routing_instance: String::new(),
        source_addresses: vec![],
        destination_address: "172.16.80.8".to_string(),
        destination_prefix: String::new(),
        destination_port: 443,
        protocol: "tcp".to_string(),
        pool_address: "10.0.61.102".to_string(),
        pool_port: 8443,
        match_source_ports: vec![],
        match_destination_ports: vec![],
        match_icmp_type: None,
        match_icmp_code: None,
        off: false,
    }];
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "reth1.0".to_string(),
        ifindex: 24,
        family: "inet".to_string(),
        ip: "10.0.61.102".to_string(),
        mac: "02:aa:bb:cc:dd:01".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    // Replace the default lan->wan permit with the caller's wan->lan rule
    // so the only policy that can match the inbound flow is the one under
    // test (default-policy stays deny).
    snapshot.policies = vec![policy];
    snapshot
}


pub(super) fn wan_to_lan_permit(dst: &str, name: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: "wan".to_string(),
        to_zone: "lan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec![dst.to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }
}


/// Build a wan-ingress inbound NPTv6 snapshot. The external prefix
/// 2602:fd41:70::/48 is translated to the internal prefix
/// fd35:1940:27::/48; a route + neighbor for the internal prefix make the
/// translated destination a ForwardCandidate out reth1.0 (lan). The
/// caller supplies the single wan->lan policy under test.
pub(super) fn inbound_nptv6_snapshot(policy: PolicyRuleSnapshot) -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.nptv6_rules = vec![crate::protocol::Nptv6RuleSnapshot {
        name: "nptv6".to_string(),
        from_zone: "wan".to_string(),
        internal_prefix: "fd35:1940:27::/48".to_string(),
        external_prefix: "2602:fd41:70::/48".to_string(),
    }];
    // Route the internal /48 toward the LAN host (reth1.0) so the
    // translated destination resolves on the inside.
    snapshot.routes.push(RouteSnapshot {
        table: "inet6.0".to_string(),
        family: "inet6".to_string(),
        destination: "fd35:1940:27::/48".to_string(),
        next_hops: vec!["fd35:1940:27:100::102@reth1.0".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
    });
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "reth1.0".to_string(),
        ifindex: 24,
        family: "inet6".to_string(),
        ip: "fd35:1940:27:100::102".to_string(),
        mac: "02:aa:bb:cc:dd:02".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    snapshot.policies = vec![policy];
    snapshot
}


/// Build a NAT64 snapshot: the synthetic IPv6 destination 64:ff9b::808:808
/// extracts the IPv4 server 8.8.8.8 (routed out wan via the default route).
/// Ingress is on reth1.0 (lan, ifindex 24); egress zone is wan. The caller
/// supplies the lan->wan policy under test.
pub(super) fn nat64_snapshot(policy: PolicyRuleSnapshot) -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.nat64_rules = vec![crate::protocol::NAT64RuleSnapshot {
        name: "nat64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["172.16.80.50".to_string()],
        no_v6_frag_header: false,
            ..Default::default()
    }];
    snapshot.policies = vec![policy];
    snapshot
}


pub(super) fn lan_to_wan_permit(dst: &str, name: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec![dst.to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }
}


/// Drop a neighbor entry (by IP) from a snapshot so its next hop stays
/// unresolved → MissingNeighbor.
pub(super) fn drop_neighbor(snapshot: &mut ConfigSnapshot, ip: &str) {
    snapshot.neighbors.retain(|n| n.ip != ip);
}


/// Ethernet (14B) + IPv4 header with the given `frag_off` (raw flags+offset
/// field) + `payload`. A non-first fragment carries payload where an L4
/// header would be; we plant TCP-port-shaped bytes there to prove they are
/// NOT parsed as ports.
pub(super) fn eth_ipv4_frag_frame(frag_off: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![
        // dst mac, src mac
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5,
        // ethertype IPv4
        0x08, 0x00,
    ];
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    let total = (20 + payload.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    ip[6..8].copy_from_slice(&frag_off.to_be_bytes());
    ip[8] = 64; // ttl
    ip[9] = PROTO_TCP;
    ip[12..16].copy_from_slice(&[10, 0, 61, 100]); // src
    ip[16..20].copy_from_slice(&[172, 16, 80, 200]); // dst
    f.extend_from_slice(&ip);
    f.extend_from_slice(payload);
    f
}


/// The egress output-filter that DISCARDs TCP traffic to dst port 443.
/// Re-used from `build_live_forward_request_from_frame_drops_logged_output_filter_discard`.
pub(super) fn wan_drop_443_forwarding() -> ForwardingState {
    build_forwarding_state(&ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-drop".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-drop".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "discard".into(),
                log: true,
                ..Default::default()
            }],
        }],
        ..Default::default()
    })
}


pub(super) fn frag_test_ingress_ident() -> BindingIdentity {
    BindingIdentity {
        slot: 7,
        queue_id: 3,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    }
}


pub(super) fn frag_test_decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    }
}


/// Meta describing a flowless TCP packet whose stamped flow_* fields claim
/// dst port 443 (what the shim would write from the bytes at the post-IP
/// offset of a non-first fragment). flow_*_addr are non-zero so
/// `parse_session_flow_from_meta` returns Some (the meta fallback the gate
/// must suppress for a fragment).
pub(super) fn frag_test_meta(l3_offset: u16) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 60,
        l3_offset,
        flow_src_port: 33333,
        flow_dst_port: 443,
        flow_src_addr: [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..UserspaceDpMeta::default()
    }
}


/// Full (non-fragment) IPv4 ICMP frame: eth(14) + IPv4(20, proto=ICMP) + an
/// 8-byte ICMP header of the given type. `total_len` covers the ICMP header so
/// the type byte and the [l4+4..l4+6] word both lie inside the declared
/// datagram. Bytes [l4+4..l4+6] are 0xBEEF — what the shim stamps as the
/// ungated pseudo source port.
pub(super) fn eth_ipv4_icmp_frame(icmp_type: u8) -> Vec<u8> {
    let mut f = vec![
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x08, 0x00,
    ];
    let icmp = [icmp_type, 0x00, 0x00, 0x00, 0xbe, 0xef, 0x00, 0x01];
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    let total = (20 + icmp.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[8] = 64; // ttl
    ip[9] = PROTO_ICMP;
    ip[12..16].copy_from_slice(&[10, 0, 61, 100]); // src
    ip[16..20].copy_from_slice(&[172, 16, 80, 200]); // dst
    f.extend_from_slice(&ip);
    f.extend_from_slice(&icmp);
    f
}


/// Meta for a non-first IPv4 TCP fragment ingressing on `reth1.0` (lan,
/// ifindex 24) toward 172.16.80.200 (wan). `flow_*_addr` carry the L3 identity
/// the shim stamps even for a fragment; the stamped ports are deliberately the
/// hostile payload bytes — the gate forces ports = 0 / l4_present = false and
/// MUST NOT trust them.
pub(super) fn frag_v4_transit_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 28,
        l3_offset: 14,
        flow_src_port: 33333,
        flow_dst_port: 443,
        flow_src_addr: [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}


/// A reachable wan neighbor for 172.16.80.200 so the fragment resolves
/// ForwardCandidate (not MissingNeighbor) and reaches the transit gate.
pub(super) fn frag_transit_wan_neighbor() -> NeighborSnapshot {
    NeighborSnapshot {
        interface: "ge-0-0-0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: "172.16.80.200".to_string(),
        mac: "00:aa:bb:cc:dd:ee".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    }
}


/// A non-first IPv4 fragment frame (offset != 0 => flowless per #2344).
pub(super) fn frag_v4_transit_frame() -> Vec<u8> {
    eth_ipv4_frag_frame(0x0001, &[0x82, 0x35, 0x01, 0xbb, 0, 0, 0, 0])
}


/// Build N attacker-constructible flowless v4 metas differing only in the
/// (src_port, dst_port) pair — the input the fabric hash mixes when there
/// is no session flow yet.
pub(super) fn fabric_adversarial_metas(n: u16) -> Vec<(UserspaceDpMeta, (u16, u16))> {
    (0..n)
        .map(|i| {
            let mut meta = frag_test_meta(14);
            let src = 40000u16.wrapping_add(i);
            let dst = 443u16;
            meta.flow_src_port = src;
            meta.flow_dst_port = dst;
            (meta, (src, dst))
        })
        .collect()
}


/// Ethernet (14B) + IPv6 header + fragment header (44) + `payload`. A
/// non-first fragment has fragment-offset bits set.
pub(super) fn eth_ipv6_frag_frame(frag_off: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x86, 0xdd,
    ];
    let mut ip = vec![0u8; 40];
    ip[0] = 0x60;
    ip[6] = 44; // next header = fragment
    ip[7] = 64; // hop limit
    // src 2001:559:8585:80::100, dst 2001:559:8585:80::200
    ip[8..24].copy_from_slice(&[
        0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0x00,
    ]);
    ip[24..40].copy_from_slice(&[
        0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00,
    ]);
    let mut frag = [0u8; 8];
    frag[0] = PROTO_TCP; // next header after fragment
    frag[2..4].copy_from_slice(&frag_off.to_be_bytes());
    frag[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes());
    let plen = (8 + payload.len()) as u16;
    ip[4..6].copy_from_slice(&plen.to_be_bytes());
    f.extend_from_slice(&ip);
    f.extend_from_slice(&frag);
    f.extend_from_slice(payload);
    f
}

