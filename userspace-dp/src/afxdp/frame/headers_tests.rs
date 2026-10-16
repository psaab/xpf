// Golden-vector tests for the consolidated outer-header serializers.
//
// All byte arrays here were derived by hand and independently
// re-derived by three plan reviewers (Codex, Gemini, AGY) during
// the #1440 plan-review cycle. The IPv4 header checksum worked
// example in plan.md §6.1 (DF=1 form: sum = 0xD9AA ⇒ cs = 0x2655)
// pins the GRE-IPv4 vector below.
//
// Test fixtures use Vec only inside the test body; the production
// builders write into a caller-supplied `&mut [u8]`.

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---- IPv4 outer / GRE pattern (the §6.1 worked-example vector) ----

#[test]
fn ipv4_header_gre_golden() {
    // Independently re-derived by Codex r1, Gemini r1 (after revert),
    // AGY r2, Claude SMR. Sum of header words = 0xD9AA; ~sum = 0x2655.
    let mut buf = [0u8; 20];
    let n = write_ipv4_header(
        &mut buf,
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        47,  // GRE
        0,   // tos
        64,  // ttl
        120, // total_len
    )
    .expect("write_ipv4_header");
    assert_eq!(n, 20);
    let expected: [u8; 20] = [
        0x45, 0x00, // version/IHL + ToS
        0x00, 0x78, // total_len = 120
        0x00, 0x00, // ID = 0
        0x40, 0x00, // Flags=DF, FragOffset=0
        0x40, 0x2F, // TTL=64, Protocol=47 (GRE)
        0x26, 0x55, // Checksum (see §6.1)
        0x0A, 0x00, 0x00, 0x01, // src 10.0.0.1
        0x0A, 0x00, 0x00, 0x02, // dst 10.0.0.2
    ];
    assert_eq!(buf, expected, "GRE IPv4 outer header golden mismatch");
}

#[test]
fn ipv4_header_checksum_self_check() {
    // RFC 1071 self-check: a fresh checksum16 over the full 20-byte
    // header (with the checksum present) must be zero. Sanity-checks
    // that the builder writes a valid checksum regardless of inputs.
    let mut buf = [0xffu8; 20];
    write_ipv4_header(
        &mut buf,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(198, 51, 100, 1),
        17, // UDP
        0xb8,
        32,
        128,
    )
    .expect("write_ipv4_header");
    let cs = checksum16(&buf);
    assert_eq!(cs, 0, "IPv4 header self-check failed (cs={:#06x})", cs);
}

#[test]
fn ipv4_header_ttl_zero_defaults_to_64() {
    let mut buf = [0u8; 20];
    write_ipv4_header(
        &mut buf,
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(0, 0, 0, 0),
        47,
        0,
        0, // ttl=0 ⇒ should default to 64
        20,
    )
    .expect("write_ipv4_header");
    assert_eq!(buf[8], 64, "ttl=0 must default to 64");
}

#[test]
fn ipv4_header_df_bit_set() {
    // Wire-byte invariant: DF=1 (RFC 791 §3.1 / RFC 6864 §3
    // compliance). If a future commit deletes the DF=1 write in
    // `write_ipv4_header`, this assertion fails. 0xff sentinel
    // pre-fill ensures we're checking the function WROTE the bytes
    // rather than a zero-initialized buffer.
    let mut buf = [0xffu8; 20];
    write_ipv4_header(
        &mut buf,
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        47,
        0,
        64,
        120,
    )
    .expect("write_ipv4_header");
    assert_eq!(
        &buf[6..8],
        &[0x40, 0x00],
        "IPv4 Flags+FragOffset must be 0x4000 (DF=1, RFC 791/6864)"
    );
    assert_eq!(&buf[4..6], &[0x00, 0x00], "IPv4 Identification must be 0");
}

#[test]
fn ipv4_header_tos_threaded_through() {
    let mut buf = [0u8; 20];
    write_ipv4_header(
        &mut buf,
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(0, 0, 0, 0),
        47,
        0xb8, // EF DSCP=46 << 2
        64,
        20,
    )
    .expect("write_ipv4_header");
    assert_eq!(buf[1], 0xb8);
}

#[test]
fn ipv4_header_short_buffer_returns_none() {
    let mut buf = [0u8; 19];
    let r = write_ipv4_header(
        &mut buf,
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(0, 0, 0, 0),
        47,
        0,
        64,
        20,
    );
    assert!(r.is_none(), "short buffer must return None, not panic");
}

#[test]
fn ipv4_tunnel_header_honors_selected_df_policy() {
    for (df, expected) in [(false, [0x00, 0x00]), (true, [0x40, 0x00])] {
        let mut buf = [0xffu8; 20];
        write_ipv4_tunnel_header(
            &mut buf,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            47,
            0,
            64,
            120,
            df,
        )
        .expect("write_ipv4_tunnel_header");
        assert_eq!(&buf[6..8], &expected, "wrong DF policy for df={df}");
        assert_eq!(checksum16(&buf), 0, "header checksum must remain valid");
    }
}

// ---- IPv6 outer / GRE pattern ----

#[test]
fn ipv6_header_gre_golden() {
    let mut buf = [0u8; 40];
    let n = write_ipv6_header(
        &mut buf,
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        47,  // GRE
        0,   // traffic class
        0,   // flow label
        64,  // hop limit
        104, // payload len
    )
    .expect("write_ipv6_header");
    assert_eq!(n, 40);
    // Version=6, TC=0, FL=0 ⇒ first 4 bytes 0x60 0x00 0x00 0x00.
    assert_eq!(&buf[0..4], &[0x60, 0x00, 0x00, 0x00]);
    // Payload length = 104 = 0x0068.
    assert_eq!(&buf[4..6], &[0x00, 0x68]);
    // Next header = 47 (GRE).
    assert_eq!(buf[6], 47);
    // Hop limit = 64.
    assert_eq!(buf[7], 64);
    // Src 2001:db8::1.
    assert_eq!(
        &buf[8..24],
        &[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]
    );
    // Dst 2001:db8::2.
    assert_eq!(
        &buf[24..40],
        &[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ]
    );
}

#[test]
fn ipv6_header_traffic_class_and_flow_label() {
    let mut buf = [0u8; 40];
    // TC = 0xB8 (EF). Flow label = 0xABCDE.
    write_ipv6_header(
        &mut buf,
        Ipv6Addr::UNSPECIFIED,
        Ipv6Addr::UNSPECIFIED,
        17,
        0xb8,
        0xabcde,
        64,
        0,
    )
    .expect("write_ipv6_header");
    // Byte 0: version (6) << 4 | TC high nibble (0xb).
    assert_eq!(buf[0], 0x6b);
    // Byte 1: TC low nibble (0x8) << 4 | flow_label high nibble (0xa).
    assert_eq!(buf[1], 0x8a);
    // Bytes 2..4: flow label middle + low (0xbcde).
    assert_eq!(buf[2], 0xbc);
    assert_eq!(buf[3], 0xde);
}

#[test]
fn ipv6_header_hop_limit_zero_defaults_to_64() {
    let mut buf = [0u8; 40];
    write_ipv6_header(
        &mut buf,
        Ipv6Addr::UNSPECIFIED,
        Ipv6Addr::UNSPECIFIED,
        47,
        0,
        0,
        0, // hop_limit=0 ⇒ should default to 64
        0,
    )
    .expect("write_ipv6_header");
    assert_eq!(buf[7], 64);
}

#[test]
fn ipv6_header_short_buffer_returns_none() {
    let mut buf = [0u8; 39];
    let r = write_ipv6_header(
        &mut buf,
        Ipv6Addr::UNSPECIFIED,
        Ipv6Addr::UNSPECIFIED,
        47,
        0,
        0,
        64,
        0,
    );
    assert!(r.is_none());
}

// ---- UDP outer ----

#[test]
fn udp_header_with_cs_zero_default() {
    // RFC 768 "no checksum" default — used by the future WG outer
    // IPv4 encap. Wire-byte invariant: bytes 6..8 == [0, 0].
    let mut buf = [0xffu8; 8];
    let n =
        write_udp_header(&mut buf, 51820, 51820, 108, /* cs */ 0).expect("write_udp_header");
    assert_eq!(n, 8);
    assert_eq!(&buf[0..2], &51820u16.to_be_bytes());
    assert_eq!(&buf[2..4], &51820u16.to_be_bytes());
    assert_eq!(&buf[4..6], &108u16.to_be_bytes());
    assert_eq!(&buf[6..8], &[0, 0], "UDP cs=0 must be written as [0, 0]");
}

#[test]
fn udp_header_with_nonzero_cs() {
    let mut buf = [0u8; 8];
    write_udp_header(&mut buf, 1234, 5678, 16, /* cs */ 0xabcd).expect("write_udp_header");
    assert_eq!(&buf[6..8], &[0xab, 0xcd]);
}

#[test]
fn udp_header_short_buffer_returns_none() {
    let mut buf = [0u8; 7];
    let r = write_udp_header(&mut buf, 0, 0, 8, 0);
    assert!(r.is_none());
}

// ---- Eth header ----

#[test]
fn eth_header_slice_no_vlan() {
    let mut buf = [0u8; 32];
    write_eth_header_slice(&mut buf, [1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12], 0, 0x0800)
        .expect("write_eth_header_slice");
    assert_eq!(&buf[0..6], &[1, 2, 3, 4, 5, 6]);
    assert_eq!(&buf[6..12], &[7, 8, 9, 10, 11, 12]);
    assert_eq!(&buf[12..14], &[0x08, 0x00]);
    assert_eq!(&buf[14], &0u8, "no VLAN ⇒ no bytes past byte 14");
}

#[test]
fn eth_header_slice_with_vlan() {
    let mut buf = [0u8; 32];
    write_eth_header_slice(&mut buf, [0; 6], [0; 6], 0x123, 0x0800)
        .expect("write_eth_header_slice");
    assert_eq!(&buf[12..14], &[0x81, 0x00]);
    assert_eq!(&buf[14..16], &[0x01, 0x23]);
    assert_eq!(&buf[16..18], &[0x08, 0x00]);
}

#[test]
fn eth_header_slice_vlan_vid_masked_to_12_bits() {
    // VID > 0xFFF must be masked to 12 bits per 802.1Q.
    let mut buf = [0u8; 32];
    write_eth_header_slice(&mut buf, [0; 6], [0; 6], 0xF123, 0x86dd)
        .expect("write_eth_header_slice");
    assert_eq!(&buf[14..16], &[0x01, 0x23], "VID must be masked to 12 bits");
}

#[test]
fn eth_header_slice_short_buffer_returns_none() {
    let mut buf = [0u8; 13]; // < 14
    let r = write_eth_header_slice(&mut buf, [0; 6], [0; 6], 0, 0x0800);
    assert!(r.is_none());
    let mut buf2 = [0u8; 17]; // < 18 with VLAN
    let r2 = write_eth_header_slice(&mut buf2, [0; 6], [0; 6], 100, 0x0800);
    assert!(r2.is_none());
}

#[test]
fn eth_header_len_basic() {
    assert_eq!(eth_header_len(0), 14);
    assert_eq!(eth_header_len(100), 18);
    assert_eq!(eth_header_len(0xfff), 18);
}

#[test]
fn eth_header_vec_push() {
    let mut buf = Vec::new();
    write_eth_header(&mut buf, [1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12], 0, 0x0800);
    assert_eq!(buf.len(), 14);
    assert_eq!(&buf[0..6], &[1, 2, 3, 4, 5, 6]);
    assert_eq!(&buf[12..14], &[0x08, 0x00]);
}

#[test]
fn eth_header_vec_push_with_vlan() {
    let mut buf = Vec::new();
    write_eth_header(&mut buf, [0; 6], [0; 6], 0x100, 0x86dd);
    assert_eq!(buf.len(), 18);
    assert_eq!(&buf[12..14], &[0x81, 0x00]);
    assert_eq!(&buf[14..16], &[0x01, 0x00]);
    assert_eq!(&buf[16..18], &[0x86, 0xdd]);
}

// ---- #2149: TxVlanTag priority-tagged VLAN-0 / PCP preservation ----

#[test]
fn txvlantag_from_vid_matches_legacy_semantics() {
    // `From<u16>` must reproduce the pre-#2149 bare-VID behavior
    // exactly: present iff VID > 0, TPID 0x8100, PCP/DEI 0, VID masked
    // to 12 bits.
    assert_eq!(
        TxVlanTag::from(0),
        TxVlanTag {
            tpid: 0x8100,
            tci: 0,
            present: false
        }
    );
    assert!(!TxVlanTag::from(0).emits(), "VID 0 must not emit a tag");
    assert_eq!(TxVlanTag::from(0).header_len(), 14);

    let t = TxVlanTag::from(0x123);
    assert!(t.emits());
    assert_eq!(t.tpid, 0x8100);
    assert_eq!(t.tci, 0x123, "bare VID has PCP/DEI 0");
    assert_eq!(t.header_len(), 18);

    // VID > 0xFFF masked to 12 bits.
    assert_eq!(TxVlanTag::from(0xF123).tci, 0x123);
}

#[test]
fn txvlantag_priority_tagged_vlan0_emits() {
    // The 802.1p priority-tagged VLAN-0 case: VID 0, PCP 5. A bare VID
    // would NOT emit (the pre-fix bug); the tag MUST emit because PCP
    // is non-zero.
    let t = TxVlanTag::from_parts(0x8100, 5, false, 0);
    assert!(t.present);
    assert!(t.emits(), "PCP != 0 with VID 0 must still emit a tag");
    assert_eq!(t.header_len(), 18);
    // TCI = PCP(5) << 13 | DEI(0) << 12 | VID(0) = 0xA000.
    assert_eq!(t.tci, 0xA000);
}

#[test]
fn txvlantag_present_but_empty_tci_degrades_to_untagged() {
    // A present tag with an all-zero TCI carries no information (no
    // VID, no priority) and must be treated as untagged — matching the
    // legacy `vid == 0` behavior so an inbound plain VID-0 tag does not
    // produce a meaningless tag on the reflected error.
    let t = TxVlanTag {
        tpid: 0x8100,
        tci: 0,
        present: true,
    };
    assert!(!t.emits());
    assert_eq!(t.header_len(), 14);
}

#[test]
fn eth_header_tagged_priority_tagged_vlan0_preserves_full_tci() {
    // The core #2149 builder proof: a priority-tagged VLAN-0 tag
    // (TPID 0x8100, PCP 5, DEI 0, VID 0) is serialized WITH the tag and
    // the full TCI preserved. Pre-fix (`vlan_id > 0` gating) this frame
    // was emitted untagged (14 bytes) with PCP lost.
    let tag = TxVlanTag::from_parts(0x8100, 5, false, 0);

    // Vec-push variant.
    let mut vbuf = Vec::new();
    write_eth_header_tagged(&mut vbuf, [1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12], tag, 0x0800);
    assert_eq!(vbuf.len(), 18, "priority-tagged VLAN-0 must be 18 bytes");
    assert_eq!(&vbuf[12..14], &[0x81, 0x00], "TPID 0x8100");
    // TCI 0xA000: PCP 5 in the top 3 bits, DEI 0, VID 0.
    assert_eq!(&vbuf[14..16], &[0xA0, 0x00], "TCI must preserve PCP=5, VID=0");
    assert_eq!(&vbuf[16..18], &[0x08, 0x00], "ether_type follows the tag");

    // Slice variant must produce identical bytes.
    let mut sbuf = [0xffu8; 18];
    write_eth_header_slice_tagged(
        &mut sbuf,
        [1, 2, 3, 4, 5, 6],
        [7, 8, 9, 10, 11, 12],
        tag,
        0x0800,
    )
    .expect("slice writer");
    assert_eq!(&sbuf[..], &vbuf[..], "slice and vec writers must agree");
}

#[test]
fn eth_header_tagged_preserves_8021ad_tpid_and_dei() {
    // A reflected 802.1ad (0x88a8) tag must keep its TPID, and DEI must
    // survive. TCI = PCP(3) | DEI(1) | VID(100).
    let tag = TxVlanTag::from_parts(0x88a8, 3, true, 100);
    let mut buf = [0u8; 18];
    write_eth_header_slice_tagged(&mut buf, [0; 6], [0; 6], tag, 0x86dd).expect("writer");
    assert_eq!(&buf[12..14], &[0x88, 0xa8], "802.1ad TPID preserved");
    // TCI = (3 << 13) | (1 << 12) | 100 = 0x6000 | 0x1000 | 0x64 = 0x7064.
    assert_eq!(&buf[14..16], &[0x70, 0x64], "PCP=3, DEI=1, VID=100");
    assert_eq!(&buf[16..18], &[0x86, 0xdd]);
}

#[test]
fn eth_header_tagged_untagged_stays_untagged() {
    // No tag ⇒ 14-byte header, ether_type at byte 12, nothing past 14.
    let mut buf = [0xffu8; 18];
    write_eth_header_slice_tagged(&mut buf, [1; 6], [2; 6], TxVlanTag::NONE, 0x0800)
        .expect("writer");
    assert_eq!(&buf[12..14], &[0x08, 0x00], "ether_type at byte 12 when untagged");
    // Bytes 14.. are untouched by the writer (still the 0xff sentinel),
    // proving no tag was written.
    assert_eq!(&buf[14..18], &[0xff, 0xff, 0xff, 0xff], "no tag bytes written");
}

#[test]
fn eth_header_legacy_vid_path_still_emits_8021q_tag() {
    // The bare-VID `write_eth_header` path (egress config VID) must be
    // unchanged: a normal VID > 0 still emits a plain 802.1Q tag.
    let mut buf = Vec::new();
    write_eth_header(&mut buf, [0; 6], [0; 6], 0x064, 0x0800);
    assert_eq!(buf.len(), 18);
    assert_eq!(&buf[12..14], &[0x81, 0x00]);
    assert_eq!(&buf[14..16], &[0x00, 0x64], "PCP 0, VID 100");
    assert_eq!(&buf[16..18], &[0x08, 0x00]);
}
