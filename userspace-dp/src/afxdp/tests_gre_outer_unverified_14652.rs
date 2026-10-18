//! #14652 residual: native GRE decap must refuse an IPv6 outer chain
//! that sights an Authentication Header (51) before GRE.
//!
//! The XDP walker advances past AH to GRE (emitting protocol 47), so
//! `meta.protocol == PROTO_GRE` alone admits such a frame to stage-6
//! decap before screen (stage 10) / stage-11 PROTO_AH drop ever see
//! the outer packet, while non-GRE AH transit is dropped (#10729).
//! Returning `None` from decap is a refusal, not a drop: the outer
//! frame continues on the ordinary path where those stages adjudicate
//! it. The fragment half of #14652 is already handled by #14645
//! (gre_reassembly before decap at stage 6) and is not re-tested here.

use super::tests_support::*;
use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::gre::try_native_gre_decap_from_frame;
use crate::afxdp::gre_reassembly::GreReassembler;
use crate::afxdp::poll_stages::{GreDecapStage, stage_native_gre_decap};

/// IPv6-outer GRE frame with an AH header (12 bytes, payload len 1)
/// inserted between the fixed header and the GRE header:
/// fixed(40, next=51) -> AH(next=47) -> GRE -> inner.
fn build_v6_ah_gre_frame(inner: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    // AH: next=GRE(47), payload len 1 => (1+2)*4 = 12 bytes total.
    payload.extend_from_slice(&[PROTO_GRE, 1, 0, 0]);
    payload.extend_from_slice(&0u32.to_be_bytes()); // SPI
    payload.extend_from_slice(&0u32.to_be_bytes()); // sequence
    payload.extend_from_slice(&[0x00, 0x00, 0x08, 0x00]); // flagless GRE, proto IPv4
    payload.extend_from_slice(inner);
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        0,
        0x86dd,
    );
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.push(PROTO_AH); // Next Header = AH (51)
    frame.push(64);
    frame.extend_from_slice(&GRE_V6_PEER);
    frame.extend_from_slice(&GRE_V6_LOCAL);
    frame.extend_from_slice(&payload);
    frame
}

#[test]
fn gre_decap_refuses_ipv6_outer_ah_sighted_gre_14652() {
    let forwarding = build_forwarding_state(&gre_to_self_snapshot_v6());
    let inner = build_gre_inner_icmp_packet_v4();
    // Control: plain v6 GRE decaps.
    let plain = build_gre_to_self_outer_frame_v6(0, &inner);
    let meta = gre_to_self_outer_meta_v6(0, plain.len());
    assert!(
        try_native_gre_decap_from_frame(&plain, meta, &forwarding).is_some(),
        "control: plain IPv6 GRE must decap"
    );
    // AH-wrapped GRE. Shim meta still stamps protocol GRE and l4 at the
    // GRE header (after AH), mirroring the XDP walker advancing past AH.
    let frame = build_v6_ah_gre_frame(&inner);
    let mut meta = gre_to_self_outer_meta_v6(0, frame.len());
    meta.l4_offset = 14 + 40 + 12;
    meta.payload_offset = meta.l4_offset + 4;
    // Fixture premise: the canonical AH sighting fires on this frame.
    assert!(
        crate::afxdp::frame::ipv6_ah_sighted(&frame, meta.addr_family, 14),
        "fixture: AH must be sighted in the outer chain"
    );
    assert!(
        try_native_gre_decap_from_frame(&frame, meta, &forwarding).is_none(),
        "#14652: IPv6 AH-sighted GRE must not be decapsulated (unverified AH stripped before stage-11 PROTO_AH drop)"
    );
    // Stage level: stage_native_gre_decap must fall through as NotGre,
    // not Decapped, so the outer frame reaches screen/stage-11.
    let mut pool = GreReassembler::new();
    let mut allows = |_: &[u8], _: UserspaceDpMeta| true;
    match stage_native_gre_decap(&frame, meta, &forwarding, &mut pool, 1_000_000_000, &mut allows) {
        GreDecapStage::NotGre(returned) => {
            assert_eq!(returned.l3_offset, meta.l3_offset);
        }
        GreDecapStage::Decapped(..) => {
            panic!("#14652: stage_native_gre_decap must not decap AH-sighted GRE")
        }
        GreDecapStage::Buffered => panic!("#14652: AH frame is not a fragment; must not buffer"),
        GreDecapStage::FilterDropped => panic!("#14652: AH frame must fall through, not filter-drop"),
    }
    // Stage control: plain v6 GRE still decaps at stage level.
    let plain_meta = gre_to_self_outer_meta_v6(0, plain.len());
    match stage_native_gre_decap(&plain, plain_meta, &forwarding, &mut pool, 1_000_000_001, &mut allows) {
        GreDecapStage::Decapped(_, decapped) => {
            assert!(!decapped.is_empty(), "control: decapped frame must be non-empty");
        }
        _ => panic!("control: plain IPv6 GRE must decap at stage level"),
    }
}
