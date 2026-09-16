// Shared test-support helpers for the afxdp/frame tests.
//
// Split out of afxdp/frame/tests.rs (#4840) as a sibling `#[path]` test
// module loaded from afxdp/frame/mod.rs. Pure code motion: every non-#[test]
// helper (fn + const) is moved verbatim (visibility widened to `pub(super)`
// so the per-subsystem test modules reach them via
// `use super::tests_support::*`).
#![allow(unused_imports)]
#![allow(dead_code)]

use super::super::test_fixtures::*;
use super::*;
use crate::event_stream::DataplaneEventRateLimitConfig;
use crate::event_stream::codec::DataplaneEventKind;
use crate::test_zone_ids::*;
use crate::{FirewallFilterSnapshot, FirewallTermSnapshot, ThreeColorPolicerSnapshot};

pub(super) fn active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}


pub(super) fn inactive_ha_runtime(watchdog_timestamp: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: false,
        watchdog_timestamp,
        lease: HAForwardingLease::Inactive,
    }
}


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


pub(super) fn build_icmp_echo_frame_v4_vlan(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, vlan_id: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        vlan_id,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, ttl, PROTO_ICMP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let ip_csum = checksum16(&frame[18..38]);
    frame[28..30].copy_from_slice(&ip_csum.to_be_bytes());
    let icmp_start = frame.len();
    frame.extend_from_slice(&[8, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]);
    let icmp_csum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    frame
}


pub(super) fn build_ipv6_gre_frame(
    inner_packet: &[u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    key: Option<u32>,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x02],
        0,
        0x86dd,
    );
    let gre_len = if key.is_some() { 8usize } else { 4usize };
    let payload_len = u16::try_from(gre_len + inner_packet.len()).unwrap();
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.push(PROTO_GRE);
    frame.push(64);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let flags = if key.is_some() { 0x2000u16 } else { 0u16 };
    frame.extend_from_slice(&flags.to_be_bytes());
    frame.extend_from_slice(
        &(if inner_packet.first().map(|b| b >> 4) == Some(4) {
            0x0800u16
        } else {
            0x86ddu16
        })
        .to_be_bytes(),
    );
    if let Some(key) = key {
        frame.extend_from_slice(&key.to_be_bytes());
    }
    frame.extend_from_slice(inner_packet);
    frame
}


pub(super) fn native_gre_outer_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 6,
        rx_queue_index: 0,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 58,
        pkt_len: 92,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_GRE,
        ..UserspaceDpMeta::default()
    }
}


pub(super) fn pbr_v4_flow() -> SessionFlow {
    SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            src_port: 0,
            dst_port: 0,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    }
}


pub(super) fn pbr_v4_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..Default::default()
    }
}


pub(super) fn pbr_v6_flow() -> SessionFlow {
    let src: std::net::Ipv6Addr = "2001:559:8585:61::100".parse().expect("v6 src");
    let dst: std::net::Ipv6Addr = "2001:559:8585:80::200".parse().expect("v6 dst");
    SessionFlow {
        src_ip: IpAddr::V6(src),
        dst_ip: IpAddr::V6(dst),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: crate::ip_proto::PROTO_ICMPV6,
            src_ip: IpAddr::V6(src),
            dst_ip: IpAddr::V6(dst),
            src_port: 0,
            dst_port: 0,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    }
}


pub(super) fn pbr_v6_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        ingress_ifindex: 5,
        addr_family: libc::AF_INET6 as u8,
        protocol: crate::ip_proto::PROTO_ICMPV6,
        ..Default::default()
    }
}


/// #4392: build a `WorkerTxPipeline` with a fixed TX-frame budget so the reject
/// reply either enqueues (budget available) or fails closed onto the
/// `filter_reject_reply_budget_drops` counter (budget == 0). Mirrors the
/// reject_reply.rs test helper; all fields are `pub(crate)`.
pub(super) fn pbr_reject_tx_pipeline(max_pending_tx: usize) -> crate::afxdp::worker::WorkerTxPipeline {
    crate::afxdp::worker::WorkerTxPipeline {
        free_tx_frames: std::collections::VecDeque::new(),
        pending_tx_prepared: std::collections::VecDeque::new(),
        pending_tx_local: std::collections::VecDeque::new(),
        backup_retry_scratch: std::collections::VecDeque::new(),
        max_pending_tx,
        outstanding_tx: 0,
        pending_fill_frames: std::collections::VecDeque::new(),
        in_flight_prepared_recycles: FastMap::default(),
        in_flight_untracked_tx: FastSet::default(),
        tx_submit_ns: Vec::new().into_boxed_slice(),
    }
}


/// Ingress `reth1.0` (ifindex 5) carries a v6 PBR filter steering the IPv6
/// SOURCE `2001:db8:61::/64` into routing-instance `vrf1`. A NAT64 prefix
/// `64:ff9b::/96` (v4 pool present) translates a matching IPv6 destination to
/// its embedded IPv4 host. The `vrf1` egress (ifindex 20) owns BOTH the
/// translated v4 subnet `192.0.2.0/24` (connected -> `vrf1.inet.0`) and a v6
/// subnet `2001:db8:dd::/64` (connected -> `vrf1.inet6.0`, for the no-NAT64
/// control). No other interface owns `192.0.2.0/24`, so the base `inet.0` table
/// has NO route for the translated dst — a leak would visibly fail to resolve.
pub(super) fn pbr_nat64_snapshot() -> crate::ConfigSnapshot {
    crate::ConfigSnapshot {
        zones: vec![
            crate::ZoneSnapshot {
                name: "lan".to_string(),
                id: TEST_LAN_ZONE_ID,
                ..Default::default()
            },
            crate::ZoneSnapshot {
                name: "vrf1".to_string(),
                id: TEST_SFMIX_ZONE_ID,
                ..Default::default()
            },
        ],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "reth1.0".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 5,
                filter_input_v6: "pbr6".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet6".to_string(),
                    address: "2001:db8:61::1/64".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/3.0".to_string(),
                zone: "vrf1".to_string(),
                routing_instance: "vrf1".to_string(),
                linux_name: "ge-0-0-3".to_string(),
                ifindex: 20,
                hardware_addr: "02:00:00:00:00:20".to_string(),
                addresses: vec![
                    crate::InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "192.0.2.1/24".to_string(),
                        scope: 0,
                    },
                    crate::InterfaceAddressSnapshot {
                        family: "inet6".to_string(),
                        address: "2001:db8:dd::1/64".to_string(),
                        scope: 0,
                    },
                ],
                ..Default::default()
            },
        ],
        filters: vec![crate::FirewallFilterSnapshot {
            name: "pbr6".to_string(),
            family: "inet6".to_string(),
            terms: vec![
                crate::FirewallTermSnapshot {
                    name: "steer".to_string(),
                    source_addresses: vec!["2001:db8:61::/64".to_string()],
                    routing_instance: "vrf1".to_string(),
                    action: "accept".to_string(),
                    ..Default::default()
                },
                crate::FirewallTermSnapshot {
                    name: "default".to_string(),
                    action: "accept".to_string(),
                    ..Default::default()
                },
            ],
        }],
        nat64_rules: vec![crate::NAT64RuleSnapshot {
            name: "nat64".to_string(),
            prefix: "64:ff9b::/96".to_string(),
            pool_addresses: vec!["198.51.100.1".to_string()],
            no_v6_frag_header: false,
                    ..Default::default()
        }],
        ..Default::default()
    }
}


/// Ingress `reth1.0` (ifindex 5) steers dst `192.0.2.0/24` into routing-instance
/// `vrf1`. The `vrf1` egress (ifindex 20) owns that subnet and carries an output
/// filter denying tcp/80; a base-instance egress (ifindex 30) owns the SAME
/// subnet in `inet.0` and carries a permissive output filter — the interface the
/// flow would egress WITHOUT the PBR steer.
pub(super) fn pbr_output_filter_snapshot() -> crate::ConfigSnapshot {
    crate::ConfigSnapshot {
        zones: vec![
            crate::ZoneSnapshot {
                name: "lan".to_string(),
                id: TEST_LAN_ZONE_ID,
                ..Default::default()
            },
            crate::ZoneSnapshot {
                name: "vrf1".to_string(),
                id: TEST_SFMIX_ZONE_ID,
                ..Default::default()
            },
            crate::ZoneSnapshot {
                name: "base".to_string(),
                id: TEST_WAN_ZONE_ID,
                ..Default::default()
            },
        ],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "reth1.0".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 5,
                filter_input_v4: "pbr4".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.61.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/3.0".to_string(),
                zone: "vrf1".to_string(),
                routing_instance: "vrf1".to_string(),
                linux_name: "ge-0-0-3".to_string(),
                ifindex: 20,
                hardware_addr: "02:00:00:00:00:20".to_string(),
                filter_output_v4: "deny-80".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.2.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0/0/4.0".to_string(),
                zone: "base".to_string(),
                linux_name: "ge-0-0-4".to_string(),
                ifindex: 30,
                hardware_addr: "02:00:00:00:00:30".to_string(),
                filter_output_v4: "allow-all".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.0.2.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        filters: vec![
            crate::FirewallFilterSnapshot {
                name: "pbr4".to_string(),
                family: "inet".to_string(),
                terms: vec![
                    crate::FirewallTermSnapshot {
                        name: "steer".to_string(),
                        destination_addresses: vec!["192.0.2.0/24".to_string()],
                        routing_instance: "vrf1".to_string(),
                        action: "accept".to_string(),
                        ..Default::default()
                    },
                    crate::FirewallTermSnapshot {
                        name: "default".to_string(),
                        action: "accept".to_string(),
                        ..Default::default()
                    },
                ],
            },
            crate::FirewallFilterSnapshot {
                name: "deny-80".to_string(),
                family: "inet".to_string(),
                terms: vec![
                    crate::FirewallTermSnapshot {
                        name: "block-http".to_string(),
                        protocols: vec!["tcp".to_string()],
                        destination_ports: vec!["80".to_string()],
                        action: "discard".to_string(),
                        ..Default::default()
                    },
                    crate::FirewallTermSnapshot {
                        name: "default".to_string(),
                        action: "accept".to_string(),
                        ..Default::default()
                    },
                ],
            },
            crate::FirewallFilterSnapshot {
                name: "allow-all".to_string(),
                family: "inet".to_string(),
                terms: vec![crate::FirewallTermSnapshot {
                    name: "default".to_string(),
                    action: "accept".to_string(),
                    ..Default::default()
                }],
            },
        ],
        ..Default::default()
    }
}


/// #2315: build an inner IPv4 ICMP frame, set its TOS byte, and
/// recompute the inner IPv4 header checksum so it stays valid. The IPv4
/// header is at inner[14..34]; the TOS byte is inner[15]; the checksum
/// is inner[24..26].
pub(super) fn inner_v4_frame_with_tos(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, tos: u8) -> Vec<u8> {
    let mut inner = build_icmp_echo_frame_v4(src, dst, ttl);
    inner[15] = tos;
    inner[24] = 0;
    inner[25] = 0;
    let cs = checksum16(&inner[14..34]);
    inner[24..26].copy_from_slice(&cs.to_be_bytes());
    inner
}


/// #2315: overwrite the outer IPv6 ECN field (low 2 bits of the Traffic
/// Class) on a built GRE frame. The IPv6 header starts at frame[14];
/// TC = (octet0<<4)|(octet1>>4); ECN is bits 4-5 of octet 1.
pub(super) fn set_outer_ipv6_ecn(frame: &mut [u8], ecn: u8) {
    frame[15] = (frame[15] & 0xCF) | ((ecn & 0x03) << 4);
}


pub(super) fn tcp_checksum_ok_ipv4(packet: &[u8]) -> bool {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    checksum16_ipv4(src, dst, PROTO_TCP, &packet[ihl..total_len]) == 0
}


pub(super) fn tcp_ports_ipv4(packet: &[u8]) -> (u16, u16) {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    (
        u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
        u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
    )
}


pub(super) fn build_ipv4_tcp_frame(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&ack.to_be_bytes());
    frame.extend_from_slice(&[0x50, flags, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
    frame
}


pub(super) fn icmpv6_checksum_ok(packet: &[u8]) -> bool {
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("src"));
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("dst"));
    checksum16_ipv6(src, dst, PROTO_ICMPV6, &packet[40..]) == 0
}


pub(super) fn l2_rewrite_test_decision(vlan_id: u16) -> SessionDecision {
    SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 11,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: vlan_id,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 }
}


pub(super) fn build_icmp_frame_v4(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, icmp_type: u8, id: u16) -> Vec<u8> {
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
    frame.extend_from_slice(&[
        icmp_type,
        0,
        0x00,
        0x00,
        (id >> 8) as u8,
        id as u8,
        0x00,
        0x01,
    ]);
    let icmp_csum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    frame
}


pub(super) fn build_icmpv6_echo_frame(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    hop: u8,
    icmp_type: u8,
    id: u16,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, PROTO_ICMPV6, hop]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&[
        icmp_type,
        0,
        0x00,
        0x00,
        (id >> 8) as u8,
        id as u8,
        0x00,
        0x01,
    ]);
    let sum = checksum16_ipv6(src, dst, PROTO_ICMPV6, &frame[54..]);
    frame[56] = (sum >> 8) as u8;
    frame[57] = sum as u8;
    frame
}


pub(super) fn icmp_test_decision(nat: NatDecision) -> SessionDecision {
    SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 11,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: 0,
    }, nat, install_table_domain: 0, install_table_check: 0 }
}


// #4381 FAIL-ON-REVERT (RFC 6146 BIB): the NAT64 frame builder rewrites the L4
// SOURCE port to the unique translated value on the forward (v6->v4) path, and
// restores the ORIGINAL client port on the reverse (v4->v6) reply. Reverting
// `apply_nat64_port_translation` (or the `forward_decision` /
// `NatDecision::reverse` port carriage) leaves the forward src port at the
// original value and the reverse dst port at the translated value — the
// port-translation assertions go RED and the reverse tuple collides.
pub(super) fn nat64_forward_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    }
}


pub(super) fn nat64_reverse_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    }
}


pub(super) fn tcp_ports_ipv6(packet: &[u8]) -> (u16, u16) {
    (
        u16::from_be_bytes([packet[40], packet[41]]),
        u16::from_be_bytes([packet[42], packet[43]]),
    )
}


pub(super) fn tcp_checksum_ok_ipv6(packet: &[u8]) -> bool {
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("v6 src"));
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("v6 dst"));
    checksum16_ipv6(src, dst, PROTO_TCP, &packet[40..]) == 0
}


/// Build an oversized (multi-MTU) TCP frame for one address family
/// with a caller-chosen TTL / hop-limit, ready for the segmentation
/// builders. No NAT rewrite is configured so the test isolates the
/// TTL gate. `egress mtu` is 1500 and the TCP payload is large enough
/// to force more than one segment.
pub(super) fn build_oversized_tcp_frame_for_ttl_gate(
    addr_family: i32,
    ttl: u8,
) -> (Vec<u8>, UserspaceDpMeta, SessionDecision, ForwardingState) {
    let src_port = 47308u16;
    let dst_port = 5201u16;
    let tcp_payload_len = 8192usize; // >> MTU, forces segmentation
    let tcp_header_len = 20usize;

    let mut frame = Vec::new();
    let (ether_type, next_hop, primary_v4, primary_v6) = match addr_family {
        libc::AF_INET => (
            0x0800u16,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            Some(Ipv4Addr::new(172, 16, 80, 8)),
            None,
        ),
        libc::AF_INET6 => (
            0x86ddu16,
            IpAddr::V6("2001:559:8585:80::200".parse().unwrap()),
            None,
            Some("2001:559:8585:80::8".parse().unwrap()),
        ),
        _ => panic!("unsupported addr_family"),
    };
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
        0,
        ether_type,
    );

    let (l4_offset, l3_header_len) = match addr_family {
        libc::AF_INET => {
            let total_len = (20 + tcp_header_len + tcp_payload_len) as u16;
            frame.extend_from_slice(&[
                0x45,
                0x00,
                (total_len >> 8) as u8,
                total_len as u8,
                0xd1,
                0x43,
                0x40,
                0x00,
                ttl, // TTL field at IP-header offset 8
                PROTO_TCP,
                0x00,
                0x00,
            ]);
            frame.extend_from_slice(&Ipv4Addr::new(10, 0, 61, 102).octets());
            frame.extend_from_slice(&Ipv4Addr::new(172, 16, 80, 200).octets());
            (34usize, 20usize)
        }
        libc::AF_INET6 => {
            let plen = (tcp_header_len + tcp_payload_len) as u16;
            frame.extend_from_slice(&[
                0x60,
                0x00,
                0x00,
                0x00,
                (plen >> 8) as u8,
                plen as u8,
                PROTO_TCP,
                ttl, // hop-limit field at IP-header offset 7
            ]);
            frame.extend_from_slice(
                &"2001:559:8585:ef00::102"
                    .parse::<Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
            frame.extend_from_slice(
                &"2001:559:8585:80::200"
                    .parse::<Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
            (54usize, 40usize)
        }
        _ => unreachable!(),
    };
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x52, 0x04, 0xc1, 0xa3, // seq
        0x73, 0x7f, 0x63, 0x1c, // ack
        0x50, 0x10, 0x00, 0x3f, // data offset (5)/ACK flag/window
        0x00, 0x00, 0x00, 0x00, // checksum/urgent
    ]);
    frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
    if addr_family == libc::AF_INET {
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("v4 tcp sum");
    } else {
        recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("v6 tcp sum");
    }

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: l4_offset as u16,
        addr_family: addr_family as u8,
        protocol: PROTO_TCP,
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(next_hop),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x01, 0x00]),
            tx_vlan_id: 0,
        },
        // No NAT — the test isolates the TTL/hop-limit gate.
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x16, 0x01, 0x00],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4,
            primary_v6,
        },
    );
    let _ = l3_header_len;
    (frame, meta, decision, forwarding)
}


/// Helper: build a RewriteDescriptor from a SessionDecision + flow.
pub(super) fn test_descriptor(
    flow: &SessionFlow,
    decision: &SessionDecision,
    vlan_id: u16,
    ether_type: u16,
) -> RewriteDescriptor {
    RewriteDescriptor {
        dst_mac: decision.resolution.neighbor_mac.unwrap_or([0; 6]),
        src_mac: decision.resolution.src_mac.unwrap_or([0; 6]),
        fabric_redirect: decision.resolution.disposition == ForwardingDisposition::FabricRedirect,
        tx_vlan_id: vlan_id,
        ether_type,
        rewrite_src_ip: decision.nat.rewrite_src,
        rewrite_dst_ip: decision.nat.rewrite_dst,
        rewrite_src_port: decision.nat.rewrite_src_port,
        rewrite_dst_port: decision.nat.rewrite_dst_port,
        ip_csum_delta: compute_ip_csum_delta(flow, &decision.nat),
        l4_csum_delta: compute_l4_csum_delta(flow, &decision.nat),
        egress_ifindex: decision.resolution.egress_ifindex,
        tx_ifindex: decision.resolution.tx_ifindex,
        target_binding_index: None,
        input_filter_log: None,
        input_filter_counters: crate::filter::CachedFilterCounters::default(),
        tx_selection: CachedTxSelectionDescriptor::default(),
        nat64: false,
        nptv6: false,
        apply_nat_on_fabric: false,
    }
}


/// Build a minimal L3-relative IPv4 packet (no Ethernet). `frag_off` is
/// the raw 16-bit IPv4 fragment-offset field (flags + offset). `payload`
/// is appended after the 20-byte header (it stands in for the bytes a
/// non-first fragment carries where an L4 header would be).
pub(super) fn frag_v4_packet(protocol: u8, frag_off: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    let total = (20 + payload.len()) as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    p[6..8].copy_from_slice(&frag_off.to_be_bytes());
    p[8] = 64; // ttl
    p[9] = protocol;
    p[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
    p[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
    p.extend_from_slice(payload);
    p
}


/// Build a minimal L3-relative IPv6 packet with an optional fragment
/// header (44) before the L4/payload. `frag_off` is the raw 16-bit
/// fragment-header offset/flags field; pass None for no fragment header.
pub(super) fn frag_v6_packet(protocol: u8, frag_off: Option<u16>, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[7] = 64; // hop limit
    p[8..24].copy_from_slice(&[0x20; 16]); // src
    p[24..40].copy_from_slice(&[0x30; 16]); // dst
    match frag_off {
        Some(off) => {
            p[6] = 44; // next header = fragment
            let mut frag = [0u8; 8];
            frag[0] = protocol; // next header after fragment
            frag[2..4].copy_from_slice(&off.to_be_bytes());
            frag[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes()); // id
            p.extend_from_slice(&frag);
        }
        None => p[6] = protocol,
    }
    let plen = (p.len() - 40 + payload.len()) as u16;
    p[4..6].copy_from_slice(&plen.to_be_bytes());
    p.extend_from_slice(payload);
    p
}


// #5150 (security — match-on-padding / filter-evasion): the flexible-match-range
// byte slices (flex_l3 / flex_l4) MUST be bounded by the IP-DECLARED datagram
// end (IP total-length), NOT the physical Ethernet frame end. Otherwise a
// byte-offset filter term can match ATTACKER-CONTROLLED bytes in Ethernet slack
// (padding beyond the declared IP length — e.g. the 60-octet minimum-frame pad
// appended by NICs after a short datagram). These tests build a frame with slack
// past the IP total-length and assert the slack is EXCLUDED from both flex
// slices. They FAIL if the clamp is reverted to `..frame.len()` (the slice then
// runs to the frame end and includes the slack marker).
pub(super) const FLEX_SLACK_MARKER: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];


pub(super) fn inject_test_egress(vlan_id: u16) -> EgressInterface {
    EgressInterface {
        bind_ifindex: 5,
        vlan_id,
        mtu: 1500,
        src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        zone_id: 0,
        redundancy_group: 0,
        primary_v4: None,
        primary_v6: None,
    }
}


pub(super) fn inject_req(packet_length: u32) -> InjectPacketRequest {
    InjectPacketRequest {
        packet_length,
        ..Default::default()
    }
}


/// Build a plain (non-tunnel) IPv4 TCP SYN frame carrying an MSS option.
/// `mss` is the advertised MSS in the SYN's TCP options.
pub(super) fn build_ipv4_tcp_syn_with_mss(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    mss: u16,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        0,
        0x0800,
    );
    // IPv4 header: 20 bytes IP + 24 bytes TCP (20 + 4-byte MSS option).
    let total_len = 20u16 + 24u16;
    frame.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0x12,
        0x34,
        0x40,
        0x00,
        64,
        PROTO_TCP,
        0x00,
        0x00,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x60, TCP_FLAG_SYN, 0xfa, 0xf0, // data offset (6 words = 24B)/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum + urg
    ]);
    frame.extend_from_slice(&[0x02, 0x04]); // MSS option kind=2 len=4
    frame.extend_from_slice(&mss.to_be_bytes());
    let ip_sum = checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("v4 tcp sum");
    frame
}


/// Build a plain (non-tunnel) IPv6 TCP SYN frame carrying an MSS option.
pub(super) fn build_ipv6_tcp_syn_with_mss(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    mss: u16,
) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        0,
        0x86dd,
    );
    let plen = 24u16; // 20 TCP + 4 MSS option
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        PROTO_TCP,
        64,
    ]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x60, TCP_FLAG_SYN, 0xfa, 0xf0, // data offset (6 words)/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum + urg
    ]);
    frame.extend_from_slice(&[0x02, 0x04]);
    frame.extend_from_slice(&mss.to_be_bytes());
    recompute_l4_checksum_ipv6(&mut frame[14..], 40, PROTO_TCP).expect("v6 tcp sum");
    frame
}


/// A plain ForwardCandidate decision (no tunnel) for a forwarded packet.
pub(super) fn plain_forward_decision_v4(dst: Ipv4Addr) -> SessionDecision {
    SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 11,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(dst)),
        neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 }
}


pub(super) fn plain_meta_v4(src_port: u16, dst_port: u16, meta_flags: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        meta_flags,
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    }
}


/// Read the MSS option value back out of a built IPv4 frame (eth+20 IP).
pub(super) fn built_ipv4_mss(frame: &[u8]) -> u16 {
    // eth(14) + IPv4(20) -> TCP; MSS option at TCP offset 20 (+2 for value).
    let mss_off = 14 + 20 + 22;
    u16::from_be_bytes([frame[mss_off], frame[mss_off + 1]])
}


pub(super) fn built_ipv6_mss(frame: &[u8]) -> u16 {
    let mss_off = 14 + 40 + 22;
    u16::from_be_bytes([frame[mss_off], frame[mss_off + 1]])
}


/// #4517: build an L3-relative IPv6 packet — 40-byte base header + a chain
/// of minimal 8-byte extension headers + an L4 header. Each ext header is
/// `(next_header_type, frag_off)`; `frag_off` is `Some` only for a
/// Fragment header (44). A generic EH with `HdrExtLen = 0` is 8 bytes
/// `(0+1)*8`, AH with `len = 0` is 8 bytes `(0+2)*4`, and Fragment is a
/// fixed 8 bytes — so every descriptor here is exactly one 8-byte header.
pub(super) fn v6_eh_chain(ehs: &[(u8, Option<u16>)], l4_proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60; // version 6
    p[7] = 64; // hop limit
    p[8..24].copy_from_slice(&[0x20; 16]); // src
    p[24..40].copy_from_slice(&[0x30; 16]); // dst
    p[6] = ehs.first().map(|(t, _)| *t).unwrap_or(l4_proto);
    for (i, (_ty, frag_off)) in ehs.iter().enumerate() {
        let next = ehs.get(i + 1).map(|(t, _)| *t).unwrap_or(l4_proto);
        let mut hdr = [0u8; 8];
        hdr[0] = next; // this EH's next-header field
        hdr[1] = 0; // HdrExtLen = 0
        if let Some(off) = frag_off {
            hdr[2..4].copy_from_slice(&off.to_be_bytes());
            hdr[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes()); // frag id
        }
        p.extend_from_slice(&hdr);
    }
    let plen = (p.len() - 40 + l4.len()) as u16;
    p[4..6].copy_from_slice(&plen.to_be_bytes());
    p.extend_from_slice(l4);
    p
}

