//! #17131: cross-language golden frames for every event-stream encoder body.
//!
//! Each specimen below is built by the REAL Rust encoder. Every slot the
//! encoder writes carries a non-default specimen value, EXCEPT the slots
//! enumerated below, which are intentionally zero/unwritten; the Go side
//! (`TestEventFrameGoldensDecode17131`) byte-pins or field-asserts every
//! remaining written slot, so a moved encoder offset reds Go even where
//! `EventRecord` has no field for the slot. Intentional zero/unwritten
//! slots:
//!
//! * dataplane_event (POLICY_DENY): NAT slots are `None`/0 (no
//!   translation on a deny); [56:64] carries the config generation in
//!   place of rule/term, so rule_id/term_id are unwritten for this kind.
//! * session frames: NAT64/snat_v4 trailing slot is zero (specimen is
//!   not NAT64; FLAG_NAT64 gates the value).
//! * session_update: written slots the Go decoder intentionally does not
//!   surface (disposition, next-hop) are byte-pinned in Go instead.
//! * rt_flow_create: [56:64] volume/reason slots unwritten by the create
//!   encoder (a create has no volume or close reason yet).
//!
//! Specimens are serialized to hex under
//! `pkg/dataplane/userspace/testdata/event_frames/<name>.hex`, and decoded
//! on the Go side through the production decoders
//! (`decodeSessionEvent` / `decodeSessionCloseEvent` /
//! `decodeDataplaneEventPayload` -> `logging.DecodeRawEventRecord`) by
//! `TestEventFrameGoldensDecode17131`. This generalizes the #9412
//! single-golden mechanism (previously only `encode_session_record` via
//! SessionUpdate) to SessionClose, RT_FLOW close/create, and the
//! dataplane-event payload.
//!
//! Regenerate ONLY for an intentional wire-layout change, together with the
//! Go decoder in the same commit:
//! `XPF_WRITE_GOLDEN=1 cargo test -- --exact <this test name>`

use super::*;
use crate::afxdp::{ForwardingDisposition, ForwardingResolution};
use crate::nat::NatDecision;
use crate::session::{SessionDecision, SessionKey, SessionMetadata, TunnelDiscriminator};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

fn golden_decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 12,
            egress_ifindex: 70003,
            tx_ifindex: 70004,
            tunnel_endpoint_id: 513,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 9, 8, 1))),
            neighbor_mac: Some([0xaa, 0x17, 0x13, 0x31, 0x00, 0x01]),
            src_mac: Some([0x11, 0x17, 0x13, 0x31, 0x00, 0x02]),
            tx_vlan_id: 4094,
            source_ifindex: 13,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 10))),
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 20))),
            rewrite_src_port: Some(40000),
            rewrite_dst_port: Some(40001),
            nat64: false,
            nptv6: false,
            source_nat_icmp: Some((13, 7)),
        },
        install_table_domain: 525_590,
        install_table_check: 3_318_534_811,
    }
}

fn golden_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: 301,
        egress_zone: 1001,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 424_242,
        ingress_vlan_id: 2345,
        forward_ingress_vlan_id: None,
        owner_rg_id: 40_002,
        fabric_ingress: true,
        is_reverse: true,
        nat64_reverse: None,
        log_session_init: true,
        log_session_close: true,
        policy_id: 777_001,
        inactivity_timeout_ns: Some(90_000_000_000),
        policy_counter_idx: 888_002,
        policy_counter: Some(Arc::new(crate::policy::PolicyRuleCounter::with_rule_id(
            "golden-rule-17131",
        ))),
        nat_scope_ifindex: Some(-12_345),
    }
}

fn golden_key_v4() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 200)),
        src_port: 12345,
        dst_port: 80,
        discriminator: TunnelDiscriminator::Keyed(0x0BAD_F00D),
        routing_domain: 77,
    }
}

fn specimen_session_update() -> EventFrame {
    let zones: FxHashMap<String, u32> = FxHashMap::default();
    EventFrame::encode_session_update_with_handshake_state(
        171_310_1,
        &golden_key_v4(),
        &golden_decision(),
        &golden_metadata(),
        &zones,
        true,
        0x5EED_1713,
        2,
        3,
        Some(true),
        0x1122_3344_5566_7788,
        111_111,
        222_222,
    )
}

fn specimen_session_close_v4() -> EventFrame {
    let key = SessionKey {
        src_port: 23456,
        dst_port: 443,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 7, 7, 7)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 31, 7, 7)),
        discriminator: TunnelDiscriminator::Keyed(0x00C0_FFEE),
        routing_domain: 88,
        ..golden_key_v4()
    };
    EventFrame::encode_session_close_with_ingress(
        171_310_2,
        &key,
        40_001,
        FLAG_FABRIC_REDIRECT | FLAG_FABRIC_INGRESS,
        301,
        1001,
        true,
        424_243,
        2346,
    )
}

fn specimen_session_close_v6() -> EventFrame {
    let key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: 17,
        src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1713, 0, 0, 0, 0, 1)),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1713, 0, 0, 0, 0, 2)),
        src_port: 5353,
        dst_port: 53,
        discriminator: TunnelDiscriminator::Unkeyed,
        routing_domain: 89,
    };
    EventFrame::encode_session_close_with_ingress(
        171_310_3,
        &key,
        -7,
        FLAG_FABRIC_INGRESS,
        302,
        1002,
        false,
        70_001,
        4094,
    )
}

fn specimen_rt_flow_close() -> EventFrame {
    EventFrame::encode_session_close_rt_flow(
        171_310_4,
        libc::AF_INET as u8,
        6,
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 102)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        12345,
        443,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99))),
        40000,
        8443,
        301,
        1001,
        88_088,
        41_041,
        9,
        true,
        1_700_000_000,
        123_456_789,
        1_700_000_123_000_000_000,
        7007,
        42_042,
        1_111_111,
        222_333_444,
        44_444,
        55_666_777,
        0xB8,
        0x13,
        9009,
        0xA1B2_C3D4_E5F6_0708,
        RT_FLOW_CLOSE_REASON_TCP_RST,
    )
}

fn specimen_rt_flow_create() -> EventFrame {
    EventFrame::encode_session_create_rt_flow(
        171_310_5,
        libc::AF_INET as u8,
        6,
        IpAddr::V4(Ipv4Addr::new(10, 0, 3, 102)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 81, 200)),
        23456,
        443,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 81, 8))),
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100))),
        40001,
        9443,
        303,
        1003,
        42_042,
        43_043,
        77_077,
        9009,
        88_088,
        0x1122_3344_5566_7788,
        1_700_000_123_456_789_012,
        true,
    )
}

fn specimen_dataplane_event() -> EventFrame {
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::PolicyDeny,
        addr_family: libc::AF_INET6 as u8,
        protocol: 17,
        action: RT_FLOW_ACTION_DENY,
        src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 6, 5, 4, 3, 2, 1)),
        src_port: 5353,
        dst_port: 53,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id: 301,
        egress_zone_id: 1001,
        ingress_ifindex: 77_077,
        policy_id: 101_101,
        rule_id: 202_202,
        term_id: 505_505,
        reason: 5,
        owner_rg_id: -3,
        application_id: 30_303,
        filter_id: 404_404,
        screen_id: 606_606,
        config_generation: 41_041,
        timestamp_ns: 1_700_000_999_000_000_000,
    };
    EventFrame::encode_dataplane_event(171_310_6, &event)
}

/// One specimen per encoder body. The Go table test decodes each file
/// through the production decoder named in the issue (#17131).
fn golden_specimens() -> [(&'static str, fn() -> EventFrame); 6] {
    [
        ("session_update", specimen_session_update as fn() -> EventFrame),
        ("session_close_v4", specimen_session_close_v4),
        ("session_close_v6", specimen_session_close_v6),
        ("rt_flow_close", specimen_rt_flow_close),
        ("rt_flow_create", specimen_rt_flow_create),
        ("dataplane_event", specimen_dataplane_event),
    ]
}

#[test]
fn test_event_frame_goldens_match_go_testdata_17131() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../pkg/dataplane/userspace/testdata/event_frames"
    );
    for (name, build) in golden_specimens() {
        let frame = build();
        let bytes = frame.as_bytes();
        assert_eq!(frame.seq, u64::from_le_bytes(bytes[8..16].try_into().unwrap()), "{name}: header seq");
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize,
            bytes.len() - FRAME_HEADER_SIZE,
            "{name}: header payload length"
        );
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let path = format!("{dir}/{name}.hex");
        if std::env::var_os("XPF_WRITE_GOLDEN").is_some() {
            std::fs::create_dir_all(dir).expect("create golden dir");
            std::fs::write(&path, format!("{hex}\n")).expect("write golden");
        }
        let golden = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read golden {path}: {e} (regenerate with XPF_WRITE_GOLDEN=1)"));
        assert_eq!(
            hex,
            golden.trim(),
            "#17131: {name} frame no longer matches the golden the Go decoder is pinned to; \
             if this layout change is intentional, regenerate with XPF_WRITE_GOLDEN=1 and update the Go decoder in the same commit"
        );
    }
}
