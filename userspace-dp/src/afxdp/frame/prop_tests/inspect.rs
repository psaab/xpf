//! S1 — frame/inspect parse properties (#1824 plan §5.3-S1).
//!
//! P-I1 no-panic, P-I2 bounds, P-I3 offset consistency, P-I4 valid
//! round-trip, P-I5 meta independence, plus deterministic pins for the
//! walk-bound and meta-arbitration behaviors the properties must not
//! silently calcify.

use super::strategies::{
    arb_garbage_frame, arb_mangled_ext_frame, arb_meta, arb_parse_packet, AF4, AF6,
};
use super::*;

/// Exercise every read-only parser against one (frame, meta) pair.
/// proptest treats any panic as a property failure, so the body is
/// just the call list (P-I1).
fn call_all_parsers(frame: &[u8], meta: UserspaceDpMeta, l4_probe: usize) {
    let _ = frame_l3_offset(frame);
    let _ = frame_l4_offset(frame, meta.addr_family);
    let _ = packet_rel_l4_offset(frame, meta.addr_family);
    let _ = packet_rel_l4_offset_and_protocol(frame, meta.addr_family);
    let _ = parse_flow_ports(frame, l4_probe, meta.protocol, frame.len());
    let _ = parse_session_flow_from_bytes(frame, meta);
    let _ = parse_session_flow_from_frame(frame, meta);
    let _ = parse_ipv4_session_flow_from_frame(frame, meta);
    let _ = parse_packet_destination_from_frame(frame, meta);
    let _ = decode_frame_summary(frame);
}

proptest! {
    #![proptest_config(super::cfg(512))]

    /// P-I1: no input of length 0..2048 with arbitrary metadata can
    /// panic any parser.
    #[test]
    fn parse_no_panic_on_garbage(
        frame in arb_garbage_frame(),
        meta in arb_meta(),
        l4_probe in 0usize..2048,
    ) {
        call_all_parsers(&frame, meta, l4_probe);
    }

    /// P-I1 (structured arm): mangled well-formed v6 ext-header chains
    /// (oversized hdr-ext-len, mutated next-header bytes, mid-chain
    /// truncation, >6-header chains) cannot panic either. This is the
    /// generator that actually reaches the AH(51)/fragment(44)/
    /// no-next(59) walk arms.
    #[test]
    fn parse_no_panic_on_mangled_ext_chains(
        frame in arb_mangled_ext_frame(),
        meta in arb_meta(),
        l4_probe in 0usize..2048,
    ) {
        call_all_parsers(&frame, meta, l4_probe);
    }

    /// P-I2: every returned offset stays inside the frame and respects
    /// the layering floor (l4 >= l3 >= 14; rel offsets >= fixed header
    /// size).
    #[test]
    fn parse_offsets_in_bounds(
        frame in arb_garbage_frame(),
        af in super::strategies::arb_af(),
    ) {
        if let Some(l3) = frame_l3_offset(&frame) {
            prop_assert!(l3 == 14 || l3 == 18);
            prop_assert!(l3 <= frame.len());
            if let Some(l4) = frame_l4_offset(&frame, af) {
                prop_assert!(l4 <= frame.len());
                prop_assert!(l4 >= l3 + 20);
            }
        } else {
            prop_assert!(frame.len() < 18);
        }
        if let Some(rel) = packet_rel_l4_offset(&frame, af) {
            prop_assert!(rel <= frame.len());
            let floor = if af as i32 == libc::AF_INET6 { 40 } else { 20 };
            prop_assert!(rel >= floor);
        }
    }

    /// P-I3: the frame-level walk equals l3 + the packet-relative walk
    /// for ALL inputs (garbage included), and the `_and_protocol`
    /// variant agrees on the offset.
    #[test]
    fn parse_offset_consistency_garbage(
        frame in arb_garbage_frame(),
        af in super::strategies::arb_af(),
    ) {
        let composed = frame_l3_offset(&frame)
            .and_then(|l3| packet_rel_l4_offset(&frame[l3..], af).map(|rel| l3 + rel));
        prop_assert_eq!(frame_l4_offset(&frame, af), composed);
        let with_proto = frame_l3_offset(&frame)
            .and_then(|l3| packet_rel_l4_offset_and_protocol(&frame[l3..], af))
            .map(|(rel, _)| rel);
        let rel_only = frame_l3_offset(&frame)
            .and_then(|l3| packet_rel_l4_offset(&frame[l3..], af));
        prop_assert_eq!(with_proto, rel_only);
    }

    #[test]
    fn parse_offset_consistency_mangled_ext(
        frame in arb_mangled_ext_frame(),
        af in super::strategies::arb_af(),
    ) {
        let composed = frame_l3_offset(&frame)
            .and_then(|l3| packet_rel_l4_offset(&frame[l3..], af).map(|rel| l3 + rel));
        prop_assert_eq!(frame_l4_offset(&frame, af), composed);
    }
}

proptest! {
    #![proptest_config(super::cfg(512))]

    /// P-I4: a synthesized valid packet parses back to exactly the
    /// tuple it was built from — with consistent metadata AND with the
    /// metadata tuple/offsets zeroed (frame-led fallback agreement).
    /// v6 ext chains up to 6 headers, well within the inspect walk's
    /// `MAX_IPV6_EXT_HEADERS` (8) loop bound; the fail-closed
    /// over-bound behavior is pinned separately below (#2292).
    #[test]
    fn parse_valid_round_trip(pkt in arb_parse_packet(6)) {
        let expected = pkt.session_flow();

        // Ground-truth offsets first: the walk must land exactly on
        // the L4 header the builder placed.
        prop_assert_eq!(frame_l3_offset(&pkt.frame), Some(pkt.l3));
        prop_assert_eq!(
            frame_l4_offset(&pkt.frame, pkt.addr_family),
            Some(pkt.l4())
        );
        let (rel, walked_proto) = packet_rel_l4_offset_and_protocol(
            &pkt.frame[pkt.l3..],
            pkt.addr_family,
        ).expect("rel l4");
        prop_assert_eq!(rel, pkt.rel_l4);
        prop_assert_eq!(walked_proto, pkt.protocol);

        // Meta-consistent parse.
        let flow = parse_session_flow_from_bytes(&pkt.frame, pkt.meta);
        prop_assert_eq!(flow.as_ref(), Some(&expected));

        // Frame-led parse: tuple + offsets zeroed, family/protocol
        // retained (the shim always stamps those).
        let mut blank = pkt.meta;
        blank.l3_offset = 0;
        blank.l4_offset = 0;
        blank.payload_offset = 0;
        blank.flow_src_port = 0;
        blank.flow_dst_port = 0;
        blank.flow_src_addr = [0u8; 16];
        blank.flow_dst_addr = [0u8; 16];
        let frame_led = parse_session_flow_from_bytes(&pkt.frame, blank);
        prop_assert_eq!(frame_led.as_ref(), Some(&expected));

        // Destination reader agrees with the tuple.
        prop_assert_eq!(
            parse_packet_destination_from_frame(&pkt.frame, pkt.meta),
            Some(pkt.dst_ip)
        );
    }

    /// P-I5: with generator-enforced `meta.protocol == final protocol`,
    /// the meta-led and frame-led arbitration paths agree. The
    /// inconsistent-protocol divergence is pinned by the deterministic
    /// example below, not hidden by the generator.
    #[test]
    fn parse_meta_independence(pkt in arb_parse_packet(6)) {
        let with_meta = parse_session_flow_from_bytes(&pkt.frame, pkt.meta);
        let mut blank = pkt.meta;
        blank.l3_offset = 0;
        blank.l4_offset = 0;
        blank.flow_src_port = 0;
        blank.flow_dst_port = 0;
        blank.flow_src_addr = [0u8; 16];
        blank.flow_dst_addr = [0u8; 16];
        let frame_led = parse_session_flow_from_bytes(&pkt.frame, blank);
        prop_assert_eq!(with_meta, frame_led);
    }
}

// ---------------------------------------------------------------------------
// Deterministic pins (current-behavior documentation, NOT generator-
// hidden). These are SHAPED to run under Miri -- no proptest loop -- but
// no gate runs them there (#9499): `make test-miri` covers only the
// modules in userspace-dp/MIRI.registry, and `afxdp::frame::` is declared
// in userspace-dp/MIRI.unregistered instead. This comment previously read
// "These also run under miri", which a reader takes as a run that happens.
// ---------------------------------------------------------------------------

/// Builds a v6 TCP frame with `n` hop-by-hop extension headers (8
/// bytes each) for the walk-bound pins.
fn v6_frame_with_n_hbh(n: usize) -> Vec<u8> {
    use super::strategies::{build_valid_frame, ExtHdr, PacketSpec};
    let spec = PacketSpec {
        v6: true,
        src4: 0,
        dst4: 0,
        src6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        dst6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        protocol: PROTO_TCP,
        src_port: 1000,
        dst_port: 2000,
        vlan_id: 0,
        vlan_present: false,
        pcp: 0,
        ttl: 64,
        ihl: 20,
        ext: vec![ExtHdr::HopByHop(0); n],
        payload_len: 4,
        payload_seed: 7,
        udp_zero_csum: false,
        tcp_flags: 0x10,
        tcp_opt_len: 0,
        seq: 1,
    };
    build_valid_frame(&spec).frame
}

/// #2292 walk-bound pin (fail-CLOSED): the forwarding walkers resolve a
/// chain of up to `MAX_IPV6_EXT_HEADERS - 1` (7) extension headers (the
/// `MAX_IPV6_EXT_HEADERS`-th loop iteration consumes the terminal L4),
/// and FAIL CLOSED on `MAX_IPV6_EXT_HEADERS` (8) or more — both
/// `packet_rel_l4_offset` and `packet_rel_l4_offset_and_protocol`
/// return `None` instead of surrendering the offset of an unconsumed
/// extension header with a fake `proto == 0`.
///
/// This matches the screen path (`screen/extract.rs`, `for _ in 0..8`,
/// which `Err`s when the 8th iteration is still on an ext header), so
/// screen and forwarding agree on the same over-bound chain. The
/// pre-#2292 forwarding walkers used 6 iterations and a post-loop
/// `Some(offset)` that surrendered the unconsumed ext-header offset.
///
/// Fail-on-revert: against the old 6-iteration surrender-open shape the
/// 7-header case returns `None` (bound too low) AND the 8-header case
/// returns `Some(..)` / `proto == 0` — both assertions flip.
#[test]
fn pin_ext_walk_bound_fail_closed() {
    let resolvable = MAX_IPV6_EXT_HEADERS - 1;
    let max = v6_frame_with_n_hbh(resolvable);
    assert_eq!(
        packet_rel_l4_offset(&max[14..], AF6),
        Some(40 + resolvable * 8),
        "a {resolvable}-header chain must resolve to the real L4 offset"
    );
    let (rel, proto) =
        packet_rel_l4_offset_and_protocol(&max[14..], AF6).expect("walk result at bound");
    assert_eq!(rel, 40 + resolvable * 8);
    assert_eq!(proto, PROTO_TCP, "terminal protocol at the bound is the real L4");

    // At/over the bound the walk is still on an extension header when it
    // runs out of iterations → fail CLOSED (None), never a surrendered
    // offset with a fake proto=0.
    for n in [MAX_IPV6_EXT_HEADERS, MAX_IPV6_EXT_HEADERS + 1] {
        let over = v6_frame_with_n_hbh(n);
        assert_eq!(
            packet_rel_l4_offset(&over[14..], AF6),
            None,
            "an {n}-header chain must fail CLOSED (None), not surrender the offset"
        );
        assert_eq!(
            packet_rel_l4_offset_and_protocol(&over[14..], AF6),
            None,
            "_and_protocol must also fail CLOSED on {n} headers — no fake proto=0 surrender"
        );
        assert_eq!(
            frame_l4_offset(&over, AF6),
            None,
            "frame_l4_offset must fail CLOSED on the {n}-header chain"
        );
    }
}

/// Deterministic arm-execution guarantee for the v6 ext-header walk:
/// a mixed chain exercising routing(43) + AH(51, the `(len+2)*4`
/// arithmetic) + fragment(44, fixed 8-byte advance) + dest-opts(60)
/// resolves to the exact L4 offset on every run — the structured
/// random chains cover these arms statistically; this pins them
/// unconditionally (plan §9.4b acceptance evidence companion).
#[test]
fn pin_ext_walk_mixed_chain_exact_offset() {
    use super::strategies::{build_valid_frame, ExtHdr, PacketSpec};
    let ext = vec![
        ExtHdr::Routing(1),  // (1+1)*8 = 16
        ExtHdr::Ah(2),       // (2+2)*4 = 16
        ExtHdr::Fragment,    // 8
        ExtHdr::DestOpts(0), // 8
    ];
    let expected_rel = 40 + 16 + 16 + 8 + 8;
    let spec = PacketSpec {
        v6: true,
        src4: 0,
        dst4: 0,
        src6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        dst6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        protocol: PROTO_UDP,
        src_port: 53,
        dst_port: 5353,
        vlan_id: 80,
        vlan_present: true,
        pcp: 0,
        ttl: 64,
        ihl: 20,
        ext,
        payload_len: 16,
        payload_seed: 3,
        udp_zero_csum: false,
        tcp_flags: 0,
        tcp_opt_len: 0,
        seq: 0,
    };
    let pkt = build_valid_frame(&spec);
    assert_eq!(pkt.rel_l4, expected_rel);
    assert_eq!(pkt.l3, 18, "VLAN-tagged frame");
    assert_eq!(
        packet_rel_l4_offset(&pkt.frame[pkt.l3..], AF6),
        Some(expected_rel)
    );
    let (rel, proto) =
        packet_rel_l4_offset_and_protocol(&pkt.frame[pkt.l3..], AF6).expect("walk");
    assert_eq!((rel, proto), (expected_rel, PROTO_UDP));
    assert_eq!(frame_l4_offset(&pkt.frame, AF6), Some(pkt.l3 + expected_rel));
    // And the flow parses through the chain.
    let flow = parse_session_flow_from_bytes(&pkt.frame, pkt.meta).expect("flow");
    assert_eq!(flow, pkt.session_flow());
}

/// No-next-header (59) pin: the walk refuses to produce an L4 offset.
#[test]
fn pin_ext_walk_no_next_header_is_none() {
    let mut frame = v6_frame_with_n_hbh(1);
    // First ext header's next-header byte → 59 (no next header).
    frame[14 + 40] = 59;
    assert_eq!(packet_rel_l4_offset(&frame[14..], AF6), None);
    assert_eq!(frame_l4_offset(&frame, AF6), None);
}

/// #2145 pin: an 802.1p priority-tagged VLAN-0 frame
/// (`vlan_present = true, vlan_id = 0, pcp > 0`) carries a real 802.1Q
/// tag, so L3 starts at offset 18 and `ingress_vlan_present` is 1
/// while `ingress_vlan_id` is 0. The strategy builder must be able to
/// produce this shape (the old `present = vlan_id != 0` derivation
/// could not), and the production `frame_l3_offset` parser must resolve
/// it to 18 from the TPID, not 14.
#[test]
fn pin_priority_tagged_vlan0_frame_parses_l3_at_offset_18() {
    use super::strategies::{build_valid_frame, PacketSpec};
    let spec = PacketSpec {
        v6: false,
        src4: 0x0a00_3d66,
        dst4: 0xac10_50c8,
        src6: [0; 16],
        dst6: [0; 16],
        protocol: PROTO_TCP,
        src_port: 49152,
        dst_port: 443,
        vlan_id: 0,
        vlan_present: true,
        pcp: 5,
        ttl: 64,
        ihl: 20,
        ext: Vec::new(),
        payload_len: 0,
        payload_seed: 1,
        udp_zero_csum: false,
        tcp_flags: 0x02,
        tcp_opt_len: 0,
        seq: 1,
    };
    let pkt = build_valid_frame(&spec);
    assert_eq!(pkt.l3, 18, "priority-tagged VLAN-0 frame keeps the tag → L3 at 18");
    assert_eq!(
        pkt.meta.ingress_vlan_present, 1,
        "tag is present even though VID is 0"
    );
    assert_eq!(pkt.meta.ingress_vlan_id, 0, "priority tag carries VID 0");
    assert_eq!(pkt.meta.ingress_pcp, 5);
    // The on-wire TPID is 802.1Q so the production parser resolves 18.
    assert_eq!(u16::from_be_bytes([pkt.frame[12], pkt.frame[13]]), 0x8100);
    assert_eq!(frame_l3_offset(&pkt.frame), Some(18));
    // The flow still parses correctly through the tagged header.
    let flow = parse_session_flow_from_bytes(&pkt.frame, pkt.meta).expect("flow");
    assert_eq!(flow, pkt.session_flow());
}

/// P-I5 divergence pin (inspect.rs:329-356 arbitration): when
/// `meta.protocol` disagrees with the frame's protocol byte, the
/// meta-led fast path wins for TCP/UDP-complete metadata and the
/// session key carries the META protocol, while the frame-led path
/// carries the FRAME protocol. This documents current arbitration —
/// the P-I5 property constrains its generator instead of asserting
/// either choice is "right".
#[test]
fn pin_meta_frame_protocol_arbitration_divergence() {
    use super::strategies::{build_valid_frame, PacketSpec};
    let spec = PacketSpec {
        v6: false,
        src4: 0x0a000001,
        dst4: 0x0a000002,
        src6: [0; 16],
        dst6: [0; 16],
        protocol: PROTO_TCP,
        src_port: 1234,
        dst_port: 80,
        vlan_id: 0,
        vlan_present: false,
        pcp: 0,
        ttl: 64,
        ihl: 20,
        ext: Vec::new(),
        payload_len: 0,
        payload_seed: 1,
        udp_zero_csum: false,
        tcp_flags: 0x10,
        tcp_opt_len: 0,
        seq: 1,
    };
    let pkt = build_valid_frame(&spec);

    // Lie about the protocol in otherwise-complete metadata.
    let mut lying = pkt.meta;
    lying.protocol = PROTO_UDP;
    let meta_led = parse_session_flow_from_bytes(&pkt.frame, lying).expect("meta-led flow");
    assert_eq!(
        meta_led.forward_key.protocol, PROTO_UDP,
        "complete-tuple fast path trusts meta.protocol (inspect.rs:329-334)"
    );

    // Frame-led (zeroed tuple): v4 key protocol comes from the frame
    // byte (inspect.rs:614).
    let mut blank = lying;
    blank.flow_src_addr = [0; 16];
    blank.flow_dst_addr = [0; 16];
    blank.flow_src_port = 0;
    blank.flow_dst_port = 0;
    blank.l3_offset = 0;
    blank.l4_offset = 0;
    let frame_led = parse_session_flow_from_bytes(&pkt.frame, blank).expect("frame-led flow");
    assert_eq!(
        frame_led.forward_key.protocol, PROTO_TCP,
        "frame-led v4 path keys on frame[l3+9]"
    );
    assert_ne!(meta_led.forward_key.protocol, frame_led.forward_key.protocol);
}

/// Sanity: the AF constants used throughout the harness are the libc
/// values the production meta carries.
#[test]
fn pin_af_constants() {
    assert_eq!(AF4 as i32, libc::AF_INET);
    assert_eq!(AF6 as i32, libc::AF_INET6);
}

// === #2344: non-first-fragment SessionFlow gate ===
//
// A non-first IP fragment carries NO L4 header — its post-IP-header
// bytes are payload, not TCP/UDP ports. The SessionFlow parsers MUST
// NOT fabricate a ported flow from such a packet; they return `None`
// so the fragment is flowless and follows the route-based, session-less
// forward path (composing with #1852's NAT-leaf gate and the #2293-era
// screen fragment classification). These pins fail if the gate is
// reverted, because the parser would then synthesize a flow carrying
// payload bytes as ports.

use super::strategies::{ExtHdr, PacketSpec, build_valid_frame};

/// A baseline TCP/IPv4 spec with a distinct port pair. The fragment
/// tests mutate the built frame's fragment-offset field and assert the
/// parsers refuse to produce a flow.
fn ipv4_tcp_spec() -> PacketSpec {
    PacketSpec {
        v6: false,
        src4: 0x0a00_0001,
        dst4: 0x0a00_0002,
        src6: [0; 16],
        dst6: [0; 16],
        protocol: PROTO_TCP,
        src_port: 0x1234,
        dst_port: 0x5678,
        vlan_id: 0,
        vlan_present: false,
        pcp: 0,
        ttl: 64,
        ihl: 20,
        ext: Vec::new(),
        payload_len: 16,
        payload_seed: 0xABCD,
        udp_zero_csum: false,
        tcp_flags: 0x10,
        tcp_opt_len: 0,
        seq: 1,
    }
}

/// Zero the tuple/offset fields so `parse_session_flow_from_bytes` is
/// forced down the frame-led path (the meta fast path requires a
/// complete TCP/UDP tuple). This isolates the per-parser gate.
fn frame_led_meta(meta: UserspaceDpMeta) -> UserspaceDpMeta {
    let mut m = meta;
    m.flow_src_addr = [0; 16];
    m.flow_dst_addr = [0; 16];
    m.flow_src_port = 0;
    m.flow_dst_port = 0;
    m.l3_offset = 0;
    m.l4_offset = 0;
    m
}

/// IPv4 non-first fragment (frag-offset != 0) must NOT parse into a
/// ported SessionFlow on the frame-led path.
#[test]
fn pin_ipv4_non_first_fragment_no_session_flow_frame_led() {
    let pkt = build_valid_frame(&ipv4_tcp_spec());
    // Control: the unmodified frame parses to the expected ported flow.
    let blank = frame_led_meta(pkt.meta);
    let control = parse_session_flow_from_bytes(&pkt.frame, blank).expect("control flow");
    assert_eq!(control, pkt.session_flow());

    // Set IPv4 fragment offset = 1 (8-byte units) in bytes l3+6..l3+8.
    // IPv4 frag_off layout: HIGH 3 bits are flags (Reserved/DF/MF), LOW
    // 13 bits are the fragment offset (`& 0x1FFF`, per
    // ipv4_is_non_first_fragment). 0x0001 -> offset 1, no flags.
    let mut frag = pkt.frame.clone();
    let off = u16::from_be_bytes([frag[pkt.l3 + 6], frag[pkt.l3 + 7]]) | 0x0001;
    frag[pkt.l3 + 6..pkt.l3 + 8].copy_from_slice(&off.to_be_bytes());
    assert!(
        ipv4_is_non_first_fragment(&frag[pkt.l3..]),
        "fragment offset must be non-zero for this pin"
    );

    assert_eq!(
        parse_session_flow_from_bytes(&frag, frame_led_meta(pkt.meta)),
        None,
        "non-first IPv4 fragment must not fabricate a ported flow"
    );
    // Direct frame parser (GRE decap calls this) is gated too.
    assert_eq!(
        parse_ipv4_session_flow_from_frame(&frag, frame_led_meta(pkt.meta)),
        None,
        "parse_ipv4_session_flow_from_frame must gate the non-first fragment"
    );
    assert_eq!(
        parse_session_flow_from_frame(&frag, frame_led_meta(pkt.meta)),
        None,
        "parse_session_flow_from_frame must gate the non-first fragment"
    );
}

/// The meta fast path must NOT bypass the gate. The XDP shim does not
/// gate non-first fragments, so meta can arrive with payload bytes in
/// `flow_*_port`. The chokepoint in `parse_session_flow_from_bytes`
/// must reject the fragment before consulting that meta tuple.
#[test]
fn pin_ipv4_non_first_fragment_no_session_flow_meta_fast_path() {
    let pkt = build_valid_frame(&ipv4_tcp_spec());
    // pkt.meta carries a complete TCP tuple -> meta fast path would fire.
    let mut frag = pkt.frame.clone();
    let off = u16::from_be_bytes([frag[pkt.l3 + 6], frag[pkt.l3 + 7]]) | 0x0001;
    frag[pkt.l3 + 6..pkt.l3 + 8].copy_from_slice(&off.to_be_bytes());

    assert_eq!(
        parse_session_flow_from_bytes(&frag, pkt.meta),
        None,
        "meta fast path must not admit a non-first IPv4 fragment"
    );
}

/// First / atomic fragment (offset 0, MF possibly set) still carries
/// the real L4 header -> parses normally. Guards against an over-broad
/// gate that drops legitimate first fragments.
#[test]
fn pin_ipv4_first_fragment_offset_zero_still_parses() {
    let pkt = build_valid_frame(&ipv4_tcp_spec());
    let mut frag = pkt.frame.clone();
    // Set MF (one of the HIGH 3 flag bits, 0x2000) but keep the LOW 13
    // offset bits 0 -> this is a FIRST fragment.
    let off = u16::from_be_bytes([frag[pkt.l3 + 6], frag[pkt.l3 + 7]]) | 0x2000;
    frag[pkt.l3 + 6..pkt.l3 + 8].copy_from_slice(&off.to_be_bytes());
    assert!(
        !ipv4_is_non_first_fragment(&frag[pkt.l3..]),
        "MF-set, offset-0 is a FIRST fragment"
    );
    let flow = parse_session_flow_from_bytes(&frag, frame_led_meta(pkt.meta))
        .expect("first fragment still parses");
    assert_eq!(flow, pkt.session_flow());
}

/// IPv6 non-first fragment (Fragment Header type 44, offset != 0) must
/// NOT parse into a ported SessionFlow.
#[test]
fn pin_ipv6_non_first_fragment_no_session_flow() {
    let mut spec = ipv4_tcp_spec();
    spec.v6 = true;
    spec.src6 = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    spec.dst6 = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    spec.ext = vec![ExtHdr::Fragment];
    let pkt = build_valid_frame(&spec);

    // Control: with offset 0 the fragment header is a first fragment and
    // the flow parses normally.
    let blank = frame_led_meta(pkt.meta);
    let control = parse_session_flow_from_bytes(&pkt.frame, blank).expect("v6 control flow");
    assert_eq!(control, pkt.session_flow());

    // Fragment header sits at l3+40; its offset field is bytes 2..4 of
    // the header. Mask 0xFFF8 (upper 13 bits) is the offset; set offset
    // = 1 (8-octet units) -> byte 3 = 0x08.
    let mut frag = pkt.frame.clone();
    let fh = pkt.l3 + 40;
    let foff = u16::from_be_bytes([frag[fh + 2], frag[fh + 3]]) | 0x0008;
    frag[fh + 2..fh + 4].copy_from_slice(&foff.to_be_bytes());
    assert!(
        ipv6_is_non_first_fragment(&frag[pkt.l3..]),
        "v6 fragment offset must be non-zero for this pin"
    );

    assert_eq!(
        parse_session_flow_from_bytes(&frag, frame_led_meta(pkt.meta)),
        None,
        "non-first IPv6 fragment must not fabricate a ported flow"
    );
    assert_eq!(
        parse_session_flow_from_frame(&frag, frame_led_meta(pkt.meta)),
        None,
        "parse_session_flow_from_frame must gate the non-first IPv6 fragment"
    );
}

/// IPv6 first fragment (Fragment Header present, offset 0) still parses
/// — the L4 header is in this fragment.
#[test]
fn pin_ipv6_first_fragment_offset_zero_still_parses() {
    let mut spec = ipv4_tcp_spec();
    spec.v6 = true;
    spec.src6 = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    spec.dst6 = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    spec.ext = vec![ExtHdr::Fragment];
    let pkt = build_valid_frame(&spec);
    // Set MF (low bit 0x0001) but keep offset bits 0 -> FIRST fragment.
    let mut frag = pkt.frame.clone();
    let fh = pkt.l3 + 40;
    let foff = u16::from_be_bytes([frag[fh + 2], frag[fh + 3]]) | 0x0001;
    frag[fh + 2..fh + 4].copy_from_slice(&foff.to_be_bytes());
    assert!(
        !ipv6_is_non_first_fragment(&frag[pkt.l3..]),
        "MF-set, offset-0 IPv6 fragment is a FIRST fragment"
    );
    let flow = parse_session_flow_from_bytes(&frag, frame_led_meta(pkt.meta))
        .expect("v6 first fragment still parses");
    assert_eq!(flow, pkt.session_flow());
}
