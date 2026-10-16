//! #13662: reject unsupported GRE legacy bits without rejecting RFC 2784
//! bits that receivers are required to ignore.

use super::tests_support::*;
use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::gre::try_native_gre_decap_from_frame;

const TUNNEL_PEER: [u8; 4] = [203, 0, 113, 9];
const UNKEYED_GRE_PROTOCOL: u16 = 0x0800;

fn gre_frame(flags: u16, tail: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        0,
        0x0800,
    );
    let l3 = frame.len();
    let total = (20 + 4 + tail.len()) as u16;
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, PROTO_GRE, 0x00, 0x00]);
    frame.extend_from_slice(&TUNNEL_PEER);
    frame.extend_from_slice(&[172, 16, 80, 8]);
    let ip_sum = checksum16(&frame[l3..l3 + 20]);
    frame[l3 + 10] = (ip_sum >> 8) as u8;
    frame[l3 + 11] = ip_sum as u8;
    frame.extend_from_slice(&flags.to_be_bytes());
    frame.extend_from_slice(&UNKEYED_GRE_PROTOCOL.to_be_bytes());
    frame.extend_from_slice(tail);
    frame
}

#[test]
fn unsupported_legacy_gre_bits_are_refused_13662() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    for bit in [0x0800u16, 0x0400u16] {
        let frame = gre_frame(bit, &inner);
        let meta = gre_to_self_outer_meta(0, frame.len());
        assert!(
            try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
            "unsupported legacy GRE bit {bit:#06x} must not be decapsulated"
        );
    }
}

#[test]
fn rfc2784_must_ignore_bits_are_accepted_13662() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot());
    let inner = build_gre_inner_icmp_packet_v4();
    // RFC 2784 §2.3 bits 6-12 are ignored on receipt. In particular this
    // includes all bits in 0x03F8; none changes RFC 2890 optional-field offsets.
    for ignored in [0x0008u16, 0x0038, 0x00C0, 0x0100, 0x0200, 0x03F8] {
        let frame = gre_frame(ignored, &inner);
        let meta = gre_to_self_outer_meta(0, frame.len());
        let decap = try_native_gre_decap_from_frame(&frame, meta, &forwarding)
            .unwrap_or_else(|| panic!("must-ignore GRE bits {ignored:#06x} must be accepted"));
        assert_eq!(
            &decap.frame[decap.meta.l3_offset as usize..],
            &inner[..],
            "ignored GRE bits must not change the decapsulated payload"
        );
    }
}
