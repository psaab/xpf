use super::*;
use crate::ip_proto::PROTO_ICMP;
use crate::{NatAppTermWire, SourceNATRuleSnapshot};
use std::net::{IpAddr, Ipv4Addr};

fn forwarding() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "echo-only".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["0.0.0.0/0".into()],
            pool_addresses: vec!["192.0.2.1".into()],
            match_applications: vec![NatAppTermWire {
                protocol: PROTO_ICMP as u16,
                icmp_type: Some(8),
                ..NatAppTermWire::default()
            }],
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    forwarding.egress.insert(
        2,
        crate::afxdp::EgressInterface {
            bind_ifindex: 2,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: 2,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(192, 0, 2, 2)),
            primary_v6: None,
        },
    );
    forwarding.zone_id_to_name.insert(1, "lan".into());
    forwarding.zone_id_to_name.insert(2, "wan".into());
    forwarding
}

fn flow(protocol: u8) -> SessionFlow {
    let src_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    SessionFlow {
        src_ip,
        dst_ip,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol,
            src_ip,
            dst_ip,
            src_port: 0,
            dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

fn meta(protocol: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        protocol,
        addr_family: libc::AF_INET as u8,
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 1,
        ..UserspaceDpMeta::default()
    }
}

fn icmpv4_frame(icmp_type: u8, code: u8) -> Vec<u8> {
    let mut frame = vec![0; 14 + 20 + 8];
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&28u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = PROTO_ICMP;
    frame[26..30].copy_from_slice(&[198, 51, 100, 1]);
    frame[30..34].copy_from_slice(&[203, 0, 113, 10]);
    frame[34] = icmp_type;
    frame[35] = code;
    frame
}

#[test]
fn retry_flowless_fragment_nat_uses_readable_icmp_type_11509() {
    let forwarding = forwarding();
    let error_meta = meta(PROTO_ICMP);
    let error_frame = icmpv4_frame(3, 1);
    let error_icmp = super::super::policy_packet_icmp(&error_frame, error_meta);
    assert_eq!(error_icmp, Some((3, 1)));
    assert!(matches!(
        retry_flowless_fragment_nat(
            &forwarding,
            &flow(PROTO_ICMP),
            error_meta,
            error_icmp,
            None,
            1,
            2,
            2,
            0,
            0,
        ),
        RetryFlowlessFragmentNat::Unchanged
    ));

    let echo_meta = meta(PROTO_ICMP);
    let echo_frame = icmpv4_frame(8, 0);
    let echo_icmp = super::super::policy_packet_icmp(&echo_frame, echo_meta);
    assert_eq!(echo_icmp, Some((8, 0)));
    assert!(matches!(
        retry_flowless_fragment_nat(
            &forwarding,
            &flow(PROTO_ICMP),
            echo_meta,
            echo_icmp,
            None,
            1,
            2,
            2,
            0,
            0,
        ),
        RetryFlowlessFragmentNat::Drop
    ));

    let unknown_meta = meta(u8::MAX);
    assert!(matches!(
        retry_flowless_fragment_nat(
            &forwarding,
            &flow(u8::MAX),
            unknown_meta,
            None,
            None,
            1,
            2,
            2,
            0,
            0,
        ),
        RetryFlowlessFragmentNat::Drop
    ));
}
