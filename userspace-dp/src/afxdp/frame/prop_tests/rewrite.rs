//! S2 — NAT rewrite properties (#1824 plan §5.3-S2).
//!
//! P-N1 round-trip identity on non-checksum bytes, P-N2 validity
//! oracle at every hop, P-N3 descriptor-vs-generic differential
//! (success cases, `expected_ports = None`, FULL byte equality —
//! unmasked since the #1838/#1839/#1840 trio fix), P-N3b
//! decline/divergence pins as deterministic examples, P-N4 payload
//! immutability.
//!
//! Domain notes (post-trio):
//!   - #1838 fixed: NAT-applying generators emit v6 ext-header chains
//!     (the offset is threaded through both paths).
//!   - #1839 fixed: P-N3 asserts full byte equality with an EMPTY
//!     mask. P-N1 (apply + undo round trip) still masks checksum
//!     bytes — apply/undo restores the VALUE class, but the
//!     one's-complement zero has two encodings and the round trip is
//!     not representation-stable by design.
//!   - #1840 fixed: valid-packet generators still never emit v6 UDP
//!     zero checksums (malformed per RFC 8200 §8.1 — outside the
//!     valid domain); the malformed encoding is covered by the
//!     deterministic pins below.

use super::oracle::{checksum_byte_ranges, first_diff_outside, oracle_packet_valid};
use super::strategies::{
    arb_packet_with_nat, arb_vlan, build_valid_frame, ExtHdr, PacketSpec, ValidPacket, AF4, AF6,
};
use super::*;
use crate::afxdp::checksum::{compute_ip_csum_delta, compute_l4_csum_delta};

/// Harness-defined same-packet inverse of a NAT decision (plan P-N1).
/// Explicitly NOT `NatDecision::reverse` (nat/mod.rs:63-79) — that
/// builds the reverse-FLOW decision (src↔dst swapped) for reply
/// packets and would corrupt a same-direction packet.
fn undo_of(nat: NatDecision, pkt: &ValidPacket) -> NatDecision {
    NatDecision {
        rewrite_src: nat.rewrite_src.map(|_| pkt.src_ip),
        rewrite_dst: nat.rewrite_dst.map(|_| pkt.dst_ip),
        rewrite_src_port: nat.rewrite_src_port.map(|_| pkt.src_port),
        rewrite_dst_port: nat.rewrite_dst_port.map(|_| pkt.dst_port),
        nat64: false,
        nptv6: false,
    }
}

/// One NAT hop, composed exactly as the production caller does it
/// (`rewrite_apply_v4`, frame/mod.rs:514-525): `apply_nat_ipv4` owns
/// the L4 checksum only — the IPv4 HEADER checksum is the caller's
/// job via `adjust_ipv4_header_checksum`, normally folded together
/// with the TTL decrement. The harness applies no TTL change, so
/// passing the current TTL as `old_ttl` makes that term identity.
fn apply_nat_family(packet: &mut [u8], pkt: &ValidPacket, nat: NatDecision) -> Option<()> {
    // #1852: mirror the production orchestrators — compute the
    // non-first-fragment predicate from the L3 packet and thread it into
    // the NAT leaf. For the existing non-fragment generators this is
    // always `false` (offset-0/atomic fragment headers only).
    let non_first_fragment = is_non_first_fragment(packet, pkt.addr_family);
    if pkt.addr_family == AF4 {
        let old_src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let old_dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let ttl = packet[8];
        apply_nat_ipv4(packet, pkt.protocol, nat, non_first_fragment)?;
        adjust_ipv4_header_checksum(&mut packet[..pkt.rel_l4], old_src, old_dst, ttl)
    } else {
        apply_nat_ipv6(packet, pkt.rel_l4, pkt.protocol, nat, non_first_fragment)
    }
}

proptest! {
    #![proptest_config(super::cfg(256))]

    /// P-N2 vacuity guard: the oracle accepts every generator output
    /// (including ext-header chains and v4 UDP zero-checksum frames).
    /// If this fails, the oracle or the builders are wrong — every
    /// other property in this file depends on both.
    #[test]
    fn oracle_accepts_generator_output(pkt in super::strategies::arb_parse_packet(6)) {
        let packet = pkt.l3_packet();
        let verdict = oracle_packet_valid(
            &packet,
            pkt.addr_family,
            pkt.protocol,
            pkt.rel_l4,
            pkt.udp_zero_csum,
        );
        prop_assert!(verdict.is_ok(), "oracle rejected builder output: {:?}", verdict);
    }

    /// P-N1 + P-N2: apply(D) then apply(undo(D)) restores every
    /// non-checksum byte, and the checksums are VALID (not necessarily
    /// bit-equal — one's-complement zero has two encodings) at all
    /// three points. v4 UDP "no checksum" stays zero across both hops.
    #[test]
    fn nat_round_trip_identity((pkt, nat) in arb_packet_with_nat()) {
        let original = pkt.l3_packet();
        prop_assert!(oracle_packet_valid(
            &original, pkt.addr_family, pkt.protocol, pkt.rel_l4, pkt.udp_zero_csum,
        ).is_ok());

        let mut packet = original.clone();
        prop_assert!(apply_nat_family(&mut packet, &pkt, nat).is_some());
        let fwd_verdict = oracle_packet_valid(
            &packet, pkt.addr_family, pkt.protocol, pkt.rel_l4, pkt.udp_zero_csum,
        );
        prop_assert!(fwd_verdict.is_ok(), "after forward NAT: {:?}", fwd_verdict);

        let undo = undo_of(nat, &pkt);
        prop_assert!(apply_nat_family(&mut packet, &pkt, undo).is_some());
        let undo_verdict = oracle_packet_valid(
            &packet, pkt.addr_family, pkt.protocol, pkt.rel_l4, pkt.udp_zero_csum,
        );
        prop_assert!(undo_verdict.is_ok(), "after undo NAT: {:?}", undo_verdict);

        let excluded = checksum_byte_ranges(pkt.addr_family, pkt.protocol, pkt.rel_l4);
        let diff = first_diff_outside(&original, &packet, &excluded);
        prop_assert!(
            diff.is_none(),
            "round trip diverged outside checksum bytes at offset {:?} (rel_l4 {})",
            diff,
            pkt.rel_l4,
        );

        // RFC 768 pin: a v4 UDP datagram sent without a checksum keeps
        // the 0x0000 encoding through both rewrites.
        if pkt.udp_zero_csum {
            let off = pkt.rel_l4 + 6;
            prop_assert_eq!(&packet[off..off + 2], &[0u8, 0u8]);
        }
    }

    /// P-N4: bytes after the L4 header (the payload) are untouched by
    /// a single forward NAT application.
    #[test]
    fn nat_payload_immutable((pkt, nat) in arb_packet_with_nat()) {
        let original = pkt.l3_packet();
        let mut packet = original.clone();
        prop_assert!(apply_nat_family(&mut packet, &pkt, nat).is_some());
        let payload_start = pkt.rel_l4 + pkt.l4_header_len;
        prop_assert_eq!(
            &packet[payload_start..],
            &original[payload_start..],
        );
    }
}

// ---------------------------------------------------------------------------
// P-N3 — descriptor-vs-generic differential
// ---------------------------------------------------------------------------

fn make_decision(pkt: &ValidPacket, nat: NatDecision, tx_vlan: u16) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(pkt.dst_ip),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: tx_vlan,
        },
        nat,
    }
}

/// Build the rewrite descriptor exactly as the flow cache does
/// (flow_cache.rs:323-355): same MACs, same NAT fields, deltas from
/// `compute_ip_csum_delta` / `compute_l4_csum_delta`.
fn make_descriptor(pkt: &ValidPacket, nat: NatDecision, tx_vlan: u16) -> RewriteDescriptor {
    let flow = pkt.session_flow();
    RewriteDescriptor {
        dst_mac: [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        fabric_redirect: false,
        tx_vlan_id: tx_vlan,
        ether_type: if pkt.addr_family == AF6 { 0x86dd } else { 0x0800 },
        rewrite_src_ip: nat.rewrite_src,
        rewrite_dst_ip: nat.rewrite_dst,
        rewrite_src_port: nat.rewrite_src_port,
        rewrite_dst_port: nat.rewrite_dst_port,
        ip_csum_delta: compute_ip_csum_delta(&flow, &nat),
        l4_csum_delta: compute_l4_csum_delta(&flow, &nat),
        egress_ifindex: 12,
        tx_ifindex: 11,
        target_binding_index: None,
        input_filter_log: None,
        input_filter_counters: crate::filter::CachedFilterCounters::default(),
        tx_selection: CachedTxSelectionDescriptor::default(),
        nat64: false,
        nptv6: false,
        apply_nat_on_fabric: false,
    }
}

const DIFF_ADDR: usize = 256;

fn area_with_frame(frame: &[u8]) -> MmapArea {
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(DIFF_ADDR, frame.len())
        .expect("frame fits area")
        .copy_from_slice(frame);
    area
}

// #3111 FAIL-ON-REVERT: the descriptor fast path is the LIVE corruption
// vector — `apply_rewrite_descriptor_ipv4` writes `rewrite_src_port` at the
// L4 offset. For a port-less protocol (GRE) the TCP|UDP gate must suppress
// that write so the GRE flags/version bytes survive; only the source IP is
// translated. A descriptor carrying a (buggy) port must NOT be able to
// clobber the tunnel header. Reverting the guard writes the port over the
// GRE flags -> RED.
#[test]
fn descriptor_fast_path_gre_preserves_l4_header() {
    use crate::afxdp::UserspaceDpMeta;

    // eth(14) + IPv4(20, proto GRE, total_len 28) + GRE(8).
    let frame: Vec<u8> = vec![
        // eth dst, eth src, ethertype 0x0800
        0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0x08, 0x00,
        // IPv4 header (proto 47 = GRE, total length 28)
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 47, 0x00, 0x00, 10, 0, 1, 100, 8, 8, 8,
        8,
        // GRE header: flags/version, protocol-type, key
        0x30, 0x01, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef,
    ];
    let area = area_with_frame(&frame);
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: frame.len() as u32,
        options: 0,
    };
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        addr_family: AF4,
        protocol: 47, // GRE
        ..UserspaceDpMeta::default()
    };
    let rd = RewriteDescriptor {
        dst_mac: [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
        src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
        fabric_redirect: false,
        tx_vlan_id: 0,
        ether_type: 0x0800,
        rewrite_src_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1))),
        rewrite_dst_ip: None,
        // A buggy allocator would hand the fast path a pseudo-port; the
        // gate must refuse to write it for a port-less protocol.
        rewrite_src_port: Some(0xBEEF),
        rewrite_dst_port: None,
        ip_csum_delta: 0,
        l4_csum_delta: 0,
        egress_ifindex: 12,
        tx_ifindex: 11,
        target_binding_index: None,
        input_filter_log: None,
        input_filter_counters: crate::filter::CachedFilterCounters::default(),
        tx_selection: CachedTxSelectionDescriptor::default(),
        nat64: false,
        nptv6: false,
        apply_nat_on_fabric: false,
    };

    let res = apply_rewrite_descriptor(&area, desc, meta, &rd, None)
        .expect("descriptor rewrite must succeed for GRE");
    let out = area
        .slice(res.offset as usize, res.len as usize)
        .expect("descriptor output slice");

    // Source IP translated (eth 14 + IP src offset 12 = 26).
    assert_eq!(&out[26..30], &[203, 0, 113, 1]);
    // GRE flags/version (eth 14 + IP 20 = 34) PRESERVED.
    assert_eq!(
        &out[34..36],
        &[0x30, 0x01],
        "GRE header must survive the descriptor fast path"
    );
}

proptest! {
    #![proptest_config(super::cfg(128))]

    /// P-N3: the generic in-place rewrite and the descriptor fast path
    /// produce FULLY byte-identical output frames (mask EMPTY since the
    /// #1838/#1839/#1840 trio — plan §9.3 / Q7), for the success
    /// domain: TCP/UDP, TTL ≥ 2 (v6 ext chains included), v6 UDP
    /// checksum nonzero, `expected_ports = None` (both paths check the
    /// arrival tuple pre-NAT since #9782 — descriptor declines on
    /// mismatch, generic repairs — so port-mismatch inputs remain
    /// differential-comparable only in outcome class, and `None` keeps
    /// the byte-equality domain mismatch-free). Both outputs must also
    /// be VALID by the oracle.
    #[test]
    fn descriptor_generic_differential(
        (pkt, nat) in arb_packet_with_nat(),
        tx_vlan in arb_vlan(),
    ) {
        let frame = &pkt.frame;
        let area_a = area_with_frame(frame);
        let area_b = area_with_frame(frame);
        let desc = XdpDesc {
            addr: DIFF_ADDR as u64,
            len: frame.len() as u32,
            options: 0,
        };

        let decision = make_decision(&pkt, nat, tx_vlan);
        let generic = rewrite_forwarded_frame_in_place(
            &area_a, desc, pkt.meta, &decision, false, None,
        );
        let rd = make_descriptor(&pkt, nat, tx_vlan);
        let fast = apply_rewrite_descriptor(&area_b, desc, pkt.meta, &rd, None);

        let generic = generic.expect("generic rewrite must succeed on valid input");
        let fast = fast.expect("descriptor rewrite must succeed on valid input");
        prop_assert_eq!(generic, fast, "InPlaceRewriteResult (offset/len/l2) must agree");

        let out_a = area_a
            .slice(generic.offset as usize, generic.len as usize)
            .expect("generic output slice");
        let out_b = area_b
            .slice(fast.offset as usize, fast.len as usize)
            .expect("descriptor output slice");

        let out_l3 = if tx_vlan > 0 { 18usize } else { 14usize };
        // EMPTY exclusion mask: any byte difference — checksum fields
        // included — is a path divergence (#1839/#1840 fixed).
        let diff = first_diff_outside(out_a, out_b, &[]);
        prop_assert!(
            diff.is_none(),
            "paths diverged at output offset {:?}",
            diff,
        );

        // Both outputs must be independently valid (P-N2 oracle).
        for (label, out) in [("generic", out_a), ("descriptor", out_b)] {
            let verdict = oracle_packet_valid(
                &out[out_l3..],
                pkt.addr_family,
                pkt.protocol,
                pkt.rel_l4,
                pkt.udp_zero_csum,
            );
            prop_assert!(verdict.is_ok(), "{} output invalid: {:?}", label, verdict);
        }

        // P-N4 (in-place flavor): payload bytes after the L4 header
        // are exactly the input's.
        let payload_in = &frame[pkt.l3 + pkt.rel_l4 + pkt.l4_header_len..];
        let payload_out = &out_a[out_l3 + pkt.rel_l4 + pkt.l4_header_len..];
        prop_assert_eq!(payload_out, payload_in);

        // TTL/hop-limit decremented exactly once (both paths agree by
        // the masked compare; check the generic output against input).
        let ttl_off = if pkt.addr_family == AF4 { 8 } else { 7 };
        prop_assert_eq!(
            out_a[out_l3 + ttl_off],
            frame[pkt.l3 + ttl_off] - 1,
        );
    }
}

// ---------------------------------------------------------------------------
// P-N3b — decline conditions + divergence pins (deterministic examples)
// ---------------------------------------------------------------------------

fn pin_packet(v6: bool, protocol: u8, ttl: u8, ext: Vec<ExtHdr>) -> ValidPacket {
    build_valid_frame(&PacketSpec {
        v6,
        src4: 0x0a00_3d66,           // 10.0.61.102
        dst4: 0xac10_50c8,           // 172.16.80.200
        src6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66],
        dst6: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc8],
        protocol,
        src_port: 0x1111,
        dst_port: 0x2222,
        vlan_id: 0,
        vlan_present: false,
        pcp: 0,
        ttl,
        ihl: 20,
        ext,
        payload_len: 8,
        payload_seed: 42,
        udp_zero_csum: false,
        tcp_flags: 0x18,
        tcp_opt_len: 0,
        seq: 100,
    })
}

/// (a) TTL/hop-limit ≤ 1 → both paths decline, BOTH transactionally.
///
/// BOTH in-place rewrites are now TRANSACTIONAL: their bail gates run
/// against the pristine frame BEFORE `rewrite_commit_eth_from_plan`
/// mutates anything, so a `None` return leaves the ENTIRE frame (L2
/// included) byte-identical — required because the callers re-read the
/// SAME UMEM after a decline (the flow cache chains
/// `apply_rewrite_descriptor(...).or_else(generic)` then reprocesses via
/// `build_live_forward_request_from_frame`; `tx/dispatch` reprocesses via
/// `build_forwarded_frame_from_frame(source_frame)`), and a scribbled L2 /
/// shifted payload would corrupt that reprocessing.
///   - DESCRIPTOR path (`apply_rewrite_descriptor`): #5466.
///   - GENERIC path (`rewrite_forwarded_frame_in_place`): #4965 — the
///     `validate_generic_rewrite_v4/v6` preflight now runs the TTL gate
///     before the eth commit, so its L2 is NO LONGER scribbled on decline.
/// Both assertions therefore check the FULL frame (FAIL-ON-REVERT for
/// #5466 descriptor + #4965 generic).
#[test]
fn pin_ttl_expired_declines_l3_untouched() {
    for v6 in [false, true] {
        let pkt = pin_packet(v6, PROTO_TCP, 1, Vec::new());
        let nat = NatDecision {
            rewrite_src_port: Some(0x3333),
            ..NatDecision::default()
        };
        let desc = XdpDesc {
            addr: DIFF_ADDR as u64,
            len: pkt.frame.len() as u32,
            options: 0,
        };

        let area = area_with_frame(&pkt.frame);
        let decision = make_decision(&pkt, nat, 0);
        assert!(
            rewrite_forwarded_frame_in_place(&area, desc, pkt.meta, &decision, false, None)
                .is_none(),
            "generic path must decline TTL≤1 (v6={v6})"
        );
        let after = area.slice(DIFF_ADDR, pkt.frame.len()).unwrap();
        assert_eq!(
            after,
            &pkt.frame[..],
            "#4965: generic TTL decline must be transactional — full frame \
             byte-identical, incl. L2 (v6={v6})"
        );

        let area = area_with_frame(&pkt.frame);
        let rd = make_descriptor(&pkt, nat, 0);
        assert!(
            apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None).is_none(),
            "descriptor path must decline TTL≤1 (v6={v6})"
        );
        let after = area.slice(DIFF_ADDR, pkt.frame.len()).unwrap();
        assert_eq!(
            after,
            &pkt.frame[..],
            "descriptor TTL decline must be transactional (#5466): \
             full frame byte-identical, incl. L2 (v6={v6})"
        );
    }
}

/// #4965 FAIL-ON-REVERT: the generic in-place rewrite
/// (`rewrite_forwarded_frame_in_place`) is transactional — for EVERY decline
/// reason the full UMEM frame AND a sentinel region around it stay
/// byte-identical. Before #4965 `rewrite_prepare_eth` committed the eth header
/// (and, on the no-headroom VLAN push, the payload `copy_within` memmove) and
/// `apply_nat_ipv4/v6` wrote IP/port bytes BEFORE their fallible checks, so a
/// decline left a scribbled L2 / shifted payload / partial NAT+checksum — which
/// the flow-cache `.or_else(generic)` fallback and the tx-dispatch
/// `build_forwarded_frame_from_frame(source_frame)` reinject then re-read as a
/// corrupt packet. Reverting the preflight (commit-before-check) makes an
/// assertion FAIL: the mutated bytes differ from the input.
///
/// Covers: TTL/hop-limit expiry (v4/v6), malformed IHL, truncated L4 checksum
/// with an ADDRESS NAT (old code writes the IP address then declines at the L4
/// checksum adjust — the "partially-adjusted NAT+checksum" corruption, v4/v6),
/// the VLAN-push-no-headroom memmove path (the worst manifestation — a pre-check
/// memmove shifts the payload), and the descriptor-declines-then-`.or_else`
/// chain. (Unknown-address-family declines in `rewrite_eth_params` before any
/// byte is touched, so it was already atomic and is not a revert-sensitive
/// case.)
#[test]
fn declined_rewrite_leaves_umem_byte_identical_4965() {
    const SENTINEL: u8 = 0xA5;
    const AREA: usize = 4096;

    // A SENTINEL-filled area with the frame at DIFF_ADDR; returns the area and
    // a whole-area snapshot so a decline can be checked against the ENTIRE area
    // (frame region unchanged + the surrounding sentinel intact — catches any
    // OOB write leaked past the frame).
    fn sentinel_area(frame: &[u8]) -> (MmapArea, Vec<u8>) {
        let mut area = MmapArea::new(AREA).expect("mmap");
        for b in area.slice_mut(0, AREA).unwrap().iter_mut() {
            *b = SENTINEL;
        }
        area.slice_mut(DIFF_ADDR, frame.len())
            .unwrap()
            .copy_from_slice(frame);
        let snapshot = area.slice(0, AREA).unwrap().to_vec();
        (area, snapshot)
    }

    fn assert_generic_declines_untouched(pkt: &ValidPacket, nat: NatDecision, label: &str) {
        let (area, snapshot) = sentinel_area(&pkt.frame);
        let desc = XdpDesc {
            addr: DIFF_ADDR as u64,
            len: pkt.frame.len() as u32,
            options: 0,
        };
        let decision = make_decision(pkt, nat, 0);
        assert!(
            rewrite_forwarded_frame_in_place(&area, desc, pkt.meta, &decision, false, None)
                .is_none(),
            "generic must decline: {label}"
        );
        assert_eq!(
            area.slice(0, AREA).unwrap(),
            &snapshot[..],
            "#4965: declined generic rewrite must leave UMEM byte-identical (frame + sentinel): {label}"
        );
    }

    // (1) TTL / hop-limit ≤ 1 — v4 + v6, with a port NAT decision present.
    for v6 in [false, true] {
        let pkt = pin_packet(v6, PROTO_TCP, 1, Vec::new());
        let nat = NatDecision {
            rewrite_src_port: Some(0x3333),
            ..NatDecision::default()
        };
        assert_generic_declines_untouched(&pkt, nat, if v6 { "ttl v6" } else { "ttl v4" });
    }

    // (2) Malformed IHL (v4): drop the IHL nibble below 5 (< 20 bytes).
    {
        let mut pkt = pin_packet(false, PROTO_TCP, 64, Vec::new());
        pkt.frame[pkt.l3] = 0x44; // version 4, IHL 4 → 16 bytes < 20
        assert_generic_declines_untouched(&pkt, NatDecision::default(), "malformed ihl");
    }

    // (3) Truncated L4 checksum field with an ADDRESS NAT. Under the reverted
    //     (commit-before-check) code the eth header is committed and
    //     `apply_nat_ipv4/v6` WRITES the new IP source, THEN declines at the L4
    //     checksum adjust (`packet.get(csum_off..csum_off+2)` OOB) — leaving a
    //     scribbled L2 + partially-rewritten IP. The preflight declines first.
    {
        // v4: keep the full IPv4 header (20) but only 16 L4 bytes → the TCP
        // checksum at ihl+16 (=36) needs 38 bytes of L3 payload; we give 36.
        let mut pkt = pin_packet(false, PROTO_TCP, 64, Vec::new());
        pkt.frame.truncate(pkt.l3 + 36);
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7))),
            ..NatDecision::default()
        };
        assert_generic_declines_untouched(&pkt, nat, "v4 truncated l4 csum + addr nat");
    }
    {
        // v6: keep the fixed 40-byte header but only 16 L4 bytes → the TCP
        // checksum at rel_l4+16 (=56) needs 58 bytes of L3 payload; give 56.
        let mut pkt = pin_packet(true, PROTO_TCP, 64, Vec::new());
        pkt.frame.truncate(pkt.l3 + 56);
        let nat = NatDecision {
            rewrite_src: Some(IpAddr::V6("2001:db8::7".parse().unwrap())),
            ..NatDecision::default()
        };
        assert_generic_declines_untouched(&pkt, nat, "v6 truncated l4 csum + addr nat");
    }

    // (4) VLAN-push-no-headroom memmove path + a TTL decline — the worst
    //     manifestation. Under the reverted code the commit `copy_within`
    //     SHIFTS the L3 payload by 4 (and writes the new eth header) BEFORE the
    //     TTL gate declines, so the fallback reprocesses a doubly-shifted frame.
    {
        const FRAME_BASE: usize = 4096; // == UMEM_FRAME_SIZE
        const BIG: usize = 8192;
        let pkt = pin_packet(false, PROTO_TCP, 1, Vec::new()); // no VLAN → l3 = 14, TTL=1
        let mut area = MmapArea::new(BIG).expect("mmap");
        for b in area.slice_mut(0, BIG).unwrap().iter_mut() {
            *b = SENTINEL;
        }
        area.slice_mut(FRAME_BASE, pkt.frame.len())
            .unwrap()
            .copy_from_slice(&pkt.frame);
        let snapshot = area.slice(0, BIG).unwrap().to_vec();
        let desc = XdpDesc {
            addr: FRAME_BASE as u64,
            len: pkt.frame.len() as u32,
            options: 0,
        };
        // tx_vlan_id = 100 → target eth_len 18 → VLAN push; rx-4 leaves the
        // UMEM chunk → VlanPushMemmoveNoHeadroom (the memmove path).
        let decision = make_decision(&pkt, NatDecision::default(), 100);
        assert!(
            rewrite_forwarded_frame_in_place(&area, desc, pkt.meta, &decision, false, None)
                .is_none(),
            "generic must decline TTL≤1 on the vlan-push memmove path"
        );
        assert_eq!(
            area.slice(0, BIG).unwrap(),
            &snapshot[..],
            "#4965: memmove-path decline must NOT shift the payload or scribble L2"
        );
    }

    // (5) The descriptor-declines-then-`.or_else(generic)` chain (exactly the
    //     flow-cache composition). A non-first fragment makes the descriptor
    //     path decline (transactional per #5466); TTL≤1 makes the generic
    //     fallback decline. Both must be atomic so the chained `None` leaves
    //     the frame pristine for the caller's subsequent reprocessing.
    {
        let mut pkt = pin_packet(false, PROTO_TCP, 1, Vec::new()); // TTL = 1
        let l3 = pkt.l3;
        pkt.frame[l3 + 6] = 0x00;
        pkt.frame[l3 + 7] = 0x10; // fragment-offset nonzero → non-first fragment
        let (area, snapshot) = sentinel_area(&pkt.frame);
        let desc = XdpDesc {
            addr: DIFF_ADDR as u64,
            len: pkt.frame.len() as u32,
            options: 0,
        };
        let nat = NatDecision {
            rewrite_src_port: Some(0x3333),
            ..NatDecision::default()
        };
        let rd = make_descriptor(&pkt, nat, 0);
        let decision = make_decision(&pkt, nat, 0);
        let result = apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None).or_else(|| {
            rewrite_forwarded_frame_in_place(&area, desc, pkt.meta, &decision, false, None)
        });
        assert!(
            result.is_none(),
            "descriptor (fragment) then generic (TTL) must both decline"
        );
        assert_eq!(
            area.slice(0, AREA).unwrap(),
            &snapshot[..],
            "#4965: descriptor-decline → or_else(generic)-decline must leave UMEM byte-identical"
        );
    }
}

/// (b) Descriptor port-mismatch (DMA-race guard,
/// `validate_rewrite_descriptor_ipv4`) → `None` with the WHOLE frame
/// byte-identical (#5466 transactional guarantee: the DMA-race gate runs
/// before any UMEM mutation, so the eth header is NOT scribbled either).
/// The generic path treats expected ports differently (post-NAT enforce)
/// — that is exactly why P-N3 runs with `expected_ports = None`.
#[test]
fn pin_descriptor_port_mismatch_declines() {
    let pkt = pin_packet(false, PROTO_TCP, 64, Vec::new());
    let nat = NatDecision::default();
    let area = area_with_frame(&pkt.frame);
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };
    let rd = make_descriptor(&pkt, nat, 0);
    assert!(
        apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, Some((0x1112, 0x2222))).is_none(),
        "descriptor must decline on expected-port mismatch"
    );
    let after = area.slice(DIFF_ADDR, pkt.frame.len()).unwrap();
    assert_eq!(
        after,
        &pkt.frame[..],
        "descriptor port-mismatch decline must be transactional (#5466): \
         full frame byte-identical, incl. L2"
    );
}

/// #5466 FAIL-ON-REVERT (fragment): a descriptor rewrite that bails at
/// the non-first-fragment gate must leave the ENTIRE frame byte-identical.
/// Before the transactional split, `rewrite_prepare_eth` wrote the new
/// Ethernet header BEFORE the fragment gate, so the caller's
/// `.or_else(generic)` fallback reprocessed a scribbled frame. Reverting
/// the fix (mutate before the gate) makes the full-frame assertion FAIL:
/// the frame's L2 (DST_MAC/SRC_MAC) would be overwritten by the
/// descriptor's distinct MACs.
#[test]
fn pin_5466_descriptor_fragment_decline_frame_untouched() {
    let pkt = pin_packet(false, PROTO_TCP, 64, Vec::new()); // v4, l3 = 14
    let l3 = pkt.l3;
    let mut bytes = pkt.frame.clone();
    // Turn the datagram into a NON-first IPv4 fragment: set the
    // fragment-offset field (IP header bytes 6-7) to a nonzero offset.
    // `ipv4_is_non_first_fragment` gates on `(frag_off & 0x1FFF) != 0`.
    bytes[l3 + 6] = 0x00;
    bytes[l3 + 7] = 0x10; // offset 0x10 → non-first fragment (MF/DF clear)
    let before = bytes.clone();

    let area = area_with_frame(&bytes);
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: bytes.len() as u32,
        options: 0,
    };
    // Descriptor MACs differ from the frame's DST_MAC/SRC_MAC, so a
    // pre-gate eth write is detectable by the full-frame compare.
    let rd = make_descriptor(&pkt, NatDecision::default(), 0);
    assert!(
        apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None).is_none(),
        "descriptor must decline a non-first fragment"
    );
    let after = area.slice(DIFF_ADDR, bytes.len()).unwrap();
    assert_eq!(
        after,
        &before[..],
        "#5466: fragment decline must leave the full frame byte-identical (no eth scribble)"
    );
}

/// #5466 FAIL-ON-REVERT (memmove — the worst manifestation): a VLAN push
/// with no UMEM headroom takes the `copy_within` payload memmove path in
/// `rewrite_commit_eth_from_plan`. If a bail gate ran AFTER that commit,
/// the memmove would have SHIFTED the L3 payload and the generic fallback
/// would reprocess doubly-shifted bytes — unrecoverable corruption. Here
/// the descriptor bails at the fragment gate; the whole frame must stay
/// byte-identical (no shift, no L2 scribble). Reverting the fix mutates
/// (memmove + eth write) before the gate → RED.
#[test]
fn pin_5466_descriptor_vlan_push_memmove_decline_frame_untouched() {
    let pkt = pin_packet(false, PROTO_TCP, 64, Vec::new()); // no VLAN → l3 = 14
    let l3 = pkt.l3;
    let mut bytes = pkt.frame.clone();
    // Non-first fragment so the descriptor bails at the fragment gate.
    bytes[l3 + 6] = 0x00;
    bytes[l3 + 7] = 0x10;
    let before = bytes.clone();

    // Place the frame at a UMEM-frame boundary so a VLAN push (tx = rx - 4)
    // leaves the current chunk → `VlanPushMemmoveNoHeadroom` → the commit
    // would `copy_within`. FRAME_BASE == UMEM_FRAME_SIZE.
    const FRAME_BASE: usize = 4096;
    let mut area = MmapArea::new(8192).expect("mmap");
    area.slice_mut(FRAME_BASE, bytes.len())
        .expect("frame fits area")
        .copy_from_slice(&bytes);
    let desc = XdpDesc {
        addr: FRAME_BASE as u64,
        len: bytes.len() as u32,
        options: 0,
    };
    // tx_vlan_id > 0 → target eth_len 18 → VLAN push (memmove, no headroom).
    let rd = make_descriptor(&pkt, NatDecision::default(), 100);
    assert!(
        apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None).is_none(),
        "descriptor must decline a non-first fragment on the vlan-push memmove path"
    );
    let after = area.slice(FRAME_BASE, bytes.len()).unwrap();
    assert_eq!(
        after,
        &before[..],
        "#5466: memmove-path decline must NOT shift the payload or scribble L2"
    );
}

/// #5466 success control: a valid descriptor rewrite still succeeds and
/// produces output byte-identical to the generic path — the transactional
/// split must not change any success-path byte. Deterministic companion to
/// the P-N3 `descriptor_generic_differential` proptest, covering v4, v6,
/// and the VLAN-push (descriptor-view) success path.
#[test]
fn pin_5466_descriptor_success_matches_generic() {
    for (v6, tx_vlan) in [(false, 0u16), (true, 0u16), (false, 100u16)] {
        let pkt = pin_packet(v6, PROTO_TCP, 64, Vec::new());
        let nat = NatDecision {
            rewrite_src_port: Some(0x5a5a),
            ..NatDecision::default()
        };
        let desc = XdpDesc {
            addr: DIFF_ADDR as u64,
            len: pkt.frame.len() as u32,
            options: 0,
        };

        let area_g = area_with_frame(&pkt.frame);
        let generic = rewrite_forwarded_frame_in_place(
            &area_g,
            desc,
            pkt.meta,
            &make_decision(&pkt, nat, tx_vlan),
            false,
            None,
        )
        .expect("generic rewrite must succeed");

        let area_d = area_with_frame(&pkt.frame);
        let fast = apply_rewrite_descriptor(
            &area_d,
            desc,
            pkt.meta,
            &make_descriptor(&pkt, nat, tx_vlan),
            None,
        )
        .expect("descriptor rewrite must succeed (#5466 success path intact)");

        assert_eq!(
            generic, fast,
            "InPlaceRewriteResult must agree (v6={v6}, vlan={tx_vlan})"
        );
        let out_g = area_g
            .slice(generic.offset as usize, generic.len as usize)
            .unwrap();
        let out_d = area_d.slice(fast.offset as usize, fast.len as usize).unwrap();
        assert_eq!(
            out_g, out_d,
            "descriptor success output must be byte-identical to generic (v6={v6}, vlan={tx_vlan})"
        );
    }
}

/// (c) NAT64 descriptors decline BEFORE the eth prep (rewrite/mod.rs)
/// — frame fully untouched, including L2. The flow cache never builds a
/// NAT64 descriptor (`should_cache` gates `!decision.nat.nat64`); this
/// pins the defense-in-depth check.
///
/// #2652: NPTv6 is no longer in this decline set — it is now applied by
/// the descriptor fast path (proved byte-identical to the generic path
/// in `pin_nptv6_descriptor_matches_generic_byte_for_byte`). A
/// descriptor flagged `nptv6` with a non-v6 ether_type still declines
/// (the defense-in-depth v4 guard), which is also pinned below.
#[test]
fn pin_descriptor_nat64_decline_frame_untouched() {
    let pkt = pin_packet(false, PROTO_TCP, 64, Vec::new());
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };
    // NAT64: always declines, frame untouched.
    {
        let area = area_with_frame(&pkt.frame);
        let mut rd = make_descriptor(&pkt, NatDecision::default(), 0);
        rd.nat64 = true;
        assert!(apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None).is_none());
        let after = area.slice(DIFF_ADDR, pkt.frame.len()).unwrap();
        assert_eq!(
            after,
            &pkt.frame[..],
            "nat64 decline happens before any byte is written"
        );
    }
    // NPTv6 on a v4-typed descriptor: defense-in-depth decline, frame
    // untouched (NPTv6 is IPv6-only; the v4 ether_type is inconsistent).
    {
        let area = area_with_frame(&pkt.frame);
        let mut rd = make_descriptor(&pkt, NatDecision::default(), 0);
        rd.nptv6 = true; // ether_type stays 0x0800 (this is a v4 pin packet)
        assert!(apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None).is_none());
        let after = area.slice(DIFF_ADDR, pkt.frame.len()).unwrap();
        assert_eq!(
            after,
            &pkt.frame[..],
            "nptv6 on a non-v6 descriptor declines before any byte is written"
        );
    }
}

/// #2652 — NPTv6 descriptor fast path is BYTE-IDENTICAL to the generic
/// slow path. NPTv6 (RFC 6296) is a same-family IPv6 dst-prefix rewrite
/// that is checksum-neutral by design: the generic `apply_nat_ipv6`
/// writes the new address and SKIPS the L4 checksum adjust
/// (`skip_l4_csum = nat.nptv6`); the descriptor carries `l4_csum_delta
/// == 0` (`compute_l4_csum_delta` short-circuits on `nat.nptv6`) so the
/// fast path's IPv6 arm also leaves the L4 checksum untouched.
///
/// This is the fail-on-revert proof: with the descriptor `nptv6` flag
/// honored (orchestrator no longer early-returns for `rd.nptv6`), the
/// two outputs match byte-for-byte. Reinstating the `rd.nptv6` decline
/// makes `fast` `None` and the `.expect(...)` panics.
#[test]
fn pin_nptv6_descriptor_matches_generic_byte_for_byte() {
    // Valid IPv6 TCP packet (no VLAN), pure-ACK eligible.
    let pkt = pin_packet(true, PROTO_TCP, 64, Vec::new());
    // NPTv6: dst prefix translation only (the upstream compiler folds the
    // RFC 6296 adjustment word into the rewritten address, so the
    // dataplane simply writes it and leaves the L4 checksum alone).
    let mut new_dst = match pkt.dst_ip {
        IpAddr::V6(a) => a.octets(),
        _ => unreachable!("v6 pin packet"),
    };
    // Replace the /48 prefix; checksum-neutrality is a property of the
    // address bytes the compiler chose, but the DATAPLANE behavior under
    // test (write address, skip L4 csum) is identical for any new dst —
    // both paths skip the L4 csum, so they agree regardless.
    new_dst[0] = 0xfd;
    new_dst[1] = 0x00;
    new_dst[2] = 0x00;
    let nptv6_nat = NatDecision {
        rewrite_dst: Some(IpAddr::V6(std::net::Ipv6Addr::from(new_dst))),
        nptv6: true,
        ..NatDecision::default()
    };

    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };

    // Capture the input L4 checksum (TCP csum at rel_l4 + 16).
    let l4_csum_off = pkt.l3 + pkt.rel_l4 + 16;
    let in_l4_csum =
        u16::from_be_bytes([pkt.frame[l4_csum_off], pkt.frame[l4_csum_off + 1]]);

    // Generic slow path.
    let area_g = area_with_frame(&pkt.frame);
    let decision = make_decision(&pkt, nptv6_nat, 0);
    let generic = rewrite_forwarded_frame_in_place(&area_g, desc, pkt.meta, &decision, false, None)
        .expect("generic NPTv6 rewrite must succeed");

    // Descriptor fast path — descriptor built exactly as the flow cache does,
    // including the nptv6 flag (#2652) and the zero L4 csum delta.
    let area_d = area_with_frame(&pkt.frame);
    let mut rd = make_descriptor(&pkt, nptv6_nat, 0);
    rd.nptv6 = true;
    assert_eq!(
        rd.l4_csum_delta, 0,
        "NPTv6 descriptor must carry a zero L4 csum delta (checksum-neutral)"
    );
    let fast = apply_rewrite_descriptor(&area_d, desc, pkt.meta, &rd, None)
        .expect("descriptor NPTv6 rewrite must succeed (#2652) — fail-on-revert");

    assert_eq!(generic, fast, "InPlaceRewriteResult (offset/len/l2) must agree");

    let out_g = area_g.slice(generic.offset as usize, generic.len as usize).unwrap();
    let out_d = area_d.slice(fast.offset as usize, fast.len as usize).unwrap();
    assert_eq!(out_g, out_d, "NPTv6 fast path must be byte-identical to generic");

    // Confirm the actual NPTv6 semantics on the shared output: dst address
    // rewritten, L4 checksum UNCHANGED (checksum-neutral).
    let out_l3 = 14usize; // no VLAN
    let out_dst = &out_g[out_l3 + 24..out_l3 + 40];
    assert_eq!(out_dst, &new_dst, "NPTv6 must rewrite the IPv6 dst address");
    let out_l4_csum_off = out_l3 + pkt.rel_l4 + 16;
    let out_l4_csum =
        u16::from_be_bytes([out_g[out_l4_csum_off], out_g[out_l4_csum_off + 1]]);
    assert_eq!(
        out_l4_csum, in_l4_csum,
        "NPTv6 is checksum-neutral — the L4 checksum must be untouched"
    );
}

/// #3121 — NPTv6 source translation COMPOSES with DNAT destination
/// translation. When an outbound IPv6 flow matches BOTH an NPTv6
/// source-prefix rule and a destination NAT rule, the decision carries
/// BOTH `rewrite_src` (NPTv6) and `rewrite_dst` (DNAT) with `nptv6 =
/// true`. The NPTv6 source rewrite is checksum-neutral by RFC 6296 (its
/// L4 delta nets zero), but the DNAT destination rewrite is NOT neutral
/// and MUST be folded into the L4 checksum -- so the checksum path may
/// no longer blanket-skip on `nat.nptv6` when a destination rewrite is
/// also present.
///
/// FAIL-ON-REVERT: with the pre-#3121 short-circuit restored
/// (`compute_l4_csum_delta` returns 0 whenever `nat.nptv6`, and
/// `apply_nat_ipv6`'s compose arm skips on `nat.nptv6`), the DNAT
/// destination change is left out of the L4 checksum -> the output
/// frame's stored checksum no longer matches the rewritten addresses ->
/// `oracle_packet_valid` rejects both paths -> RED.
#[test]
fn pin_nptv6_composes_with_dnat_checksum_valid() {
    // Valid IPv6 TCP packet (no VLAN). src6 = 2001::66, dst6 = 2001::c8.
    let pkt = pin_packet(true, PROTO_TCP, 64, Vec::new());

    // NPTv6 outbound source translation, modelled checksum-neutral
    // (RFC 6296): swap the /48 prefix to fd00:: and fold the
    // ones-complement compensation into the adjustment word so the full
    // address's 16-bit sum is preserved (orig word-sum 0x2001+0x0066 =
    // 0x2067; new = 0xfd00 + 0x2300 + 0x0066 folds to 0x2067).
    let new_src: [u8; 16] = [
        0xfd, 0x00, 0, 0, 0, 0, 0x23, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x66,
    ];
    // DNAT destination rewrite to an internal address (NOT checksum-
    // neutral -- this is the delta that must survive the compose).
    let new_dst: [u8; 16] = [
        0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V6(std::net::Ipv6Addr::from(new_src))),
        rewrite_dst: Some(IpAddr::V6(std::net::Ipv6Addr::from(new_dst))),
        nptv6: true,
        ..NatDecision::default()
    };

    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };

    // Capture the input L4 checksum (TCP csum at rel_l4 + 16).
    let l4_csum_off = pkt.l3 + pkt.rel_l4 + 16;
    let in_l4_csum = u16::from_be_bytes([pkt.frame[l4_csum_off], pkt.frame[l4_csum_off + 1]]);

    // Generic slow path.
    let area_g = area_with_frame(&pkt.frame);
    let decision = make_decision(&pkt, nat, 0);
    let generic = rewrite_forwarded_frame_in_place(&area_g, desc, pkt.meta, &decision, false, None)
        .expect("generic NPTv6+DNAT rewrite must succeed");

    // Descriptor fast path -- built exactly as the flow cache does,
    // including the nptv6 flag. Unlike pure NPTv6 (#2652), the compose
    // descriptor carries a NON-zero L4 delta (the DNAT term).
    let area_d = area_with_frame(&pkt.frame);
    let mut rd = make_descriptor(&pkt, nat, 0);
    rd.nptv6 = true;
    assert_ne!(
        rd.l4_csum_delta, 0,
        "NPTv6+DNAT compose descriptor must carry the DNAT L4 csum delta (#3121)"
    );
    let fast = apply_rewrite_descriptor(&area_d, desc, pkt.meta, &rd, None)
        .expect("descriptor NPTv6+DNAT rewrite must succeed");

    assert_eq!(generic, fast, "InPlaceRewriteResult (offset/len/l2) must agree");

    let out_g = area_g.slice(generic.offset as usize, generic.len as usize).unwrap();
    let out_d = area_d.slice(fast.offset as usize, fast.len as usize).unwrap();
    assert_eq!(
        out_g, out_d,
        "NPTv6+DNAT fast path must be byte-identical to the generic path"
    );

    let out_l3 = 14usize; // no VLAN

    // BOTH translations applied: source prefix-translated (NPTv6),
    // destination rewritten (DNAT).
    let out_src = &out_g[out_l3 + 8..out_l3 + 24];
    let out_dst = &out_g[out_l3 + 24..out_l3 + 40];
    assert_eq!(out_src, &new_src, "NPTv6 must rewrite the IPv6 source address");
    assert_eq!(out_dst, &new_dst, "DNAT must rewrite the IPv6 destination address");

    // The DNAT destination change is not checksum-neutral, so the stored
    // L4 checksum MUST have moved off the input value.
    let out_l4_csum_off = out_l3 + pkt.rel_l4 + 16;
    let out_l4_csum =
        u16::from_be_bytes([out_g[out_l4_csum_off], out_g[out_l4_csum_off + 1]]);
    assert_ne!(
        out_l4_csum, in_l4_csum,
        "DNAT must fold its destination delta into the L4 checksum (#3121)"
    );

    // The stored L4 checksum must be VALID for the rewritten addresses.
    // This is the fail-on-revert assertion: a pre-#3121 nptv6 blanket
    // skip leaves the checksum correct for the OLD destination -> invalid.
    let verdict = oracle_packet_valid(
        &out_g[out_l3..],
        pkt.addr_family,
        pkt.protocol,
        pkt.rel_l4,
        false,
    );
    assert!(
        verdict.is_ok(),
        "NPTv6+DNAT output L4 checksum must be valid for the rewritten src+dst: {:?}",
        verdict
    );
}

/// (d) #1838 (D3) FIXED pin: the generic v6 NAT path threads the
/// caller's ext-aware L4 offset (shared `v6_rel_l4_offset` helper, the
/// same precedence rule the descriptor path uses). On a valid IPv6
/// packet with a hop-by-hop extension header and a dst-port rewrite
/// the REAL TCP port is rewritten at the parsed offset, the extension
/// header bytes stay byte-identical, the checksum adjust lands at
/// `rel_l4 + 16`, and the generic in-place output is byte-identical
/// to the descriptor output. (This flipped the original #1824 defect
/// pin that asserted the fixed-40 corruption.)
#[test]
fn pin_1838_generic_v6_nat_ext_header_rewrites_real_l4() {
    let pkt = pin_packet(true, PROTO_TCP, 64, vec![ExtHdr::HopByHop(0)]);
    assert_eq!(pkt.rel_l4, 48, "one hop-by-hop header → L4 at 48");
    let nat = NatDecision {
        rewrite_dst_port: Some(0x3333),
        ..NatDecision::default()
    };

    // Generic path (apply_nat_ipv6 is what the in-place rewrite, the
    // copy builder, the segmentation arm, and the slow path call).
    let original = pkt.l3_packet();
    let mut packet = original.clone();
    assert!(apply_nat_ipv6(&mut packet, pkt.rel_l4, PROTO_TCP, nat, false).is_some());
    assert_eq!(
        u16::from_be_bytes([packet[48 + 2], packet[48 + 3]]),
        0x3333,
        "#1838 fixed: real TCP dst port rewritten at the parsed offset"
    );
    assert_eq!(
        &packet[40..48],
        &original[40..48],
        "#1838 fixed: hop-by-hop extension header bytes untouched"
    );
    assert_ne!(
        &packet[48 + 16..48 + 18],
        &original[48 + 16..48 + 18],
        "#1838 fixed: checksum adjust lands at rel_l4 + 16"
    );
    let verdict = oracle_packet_valid(&packet, AF6, PROTO_TCP, pkt.rel_l4, false);
    assert!(verdict.is_ok(), "post-NAT packet valid: {:?}", verdict);

    // Generic in-place vs descriptor on the same input: byte-identical
    // output frames (the offset-source parity is structural now).
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };
    let area_g = area_with_frame(&pkt.frame);
    let decision = make_decision(&pkt, nat, 0);
    let g = rewrite_forwarded_frame_in_place(&area_g, desc, pkt.meta, &decision, false, None)
        .expect("generic in-place rewrite succeeds");
    let area_d = area_with_frame(&pkt.frame);
    let rd = make_descriptor(&pkt, nat, 0);
    let d = apply_rewrite_descriptor(&area_d, desc, pkt.meta, &rd, None)
        .expect("descriptor path succeeds");
    assert_eq!(g, d, "InPlaceRewriteResult must agree");
    let out_g = area_g.slice(g.offset as usize, g.len as usize).unwrap();
    let out_d = area_d.slice(d.offset as usize, d.len as usize).unwrap();
    assert_eq!(
        out_g, out_d,
        "#1838 fixed: generic and descriptor outputs byte-identical on ext-headered input"
    );
    assert_eq!(
        u16::from_be_bytes([out_d[14 + 48 + 2], out_d[14 + 48 + 3]]),
        0x3333,
        "descriptor path rewrites the REAL dst port"
    );
    assert_eq!(
        &out_d[14 + 40..14 + 48],
        &pkt.frame[14 + 40..14 + 48],
        "descriptor path leaves the hop-by-hop header intact"
    );
}

/// Craft a valid v6 packet whose TRUE L4 checksum is zero, stored with
/// the 0x0000 encoding (legitimate for TCP — only UDP forbids it on
/// the wire). The last two payload bytes are the balancing word.
fn pin_packet_v6_with_zero_csum(protocol: u8) -> ValidPacket {
    let mut pkt = pin_packet(true, protocol, 64, Vec::new());
    let l4 = pkt.l4();
    let csum_off = l4 + if protocol == PROTO_TCP { 16 } else { 6 };
    // Zero the stored checksum and the balancing word, then set the
    // balancer so the segment sums to one's-complement zero.
    pkt.frame[csum_off..csum_off + 2].copy_from_slice(&[0, 0]);
    let end = pkt.frame.len();
    pkt.frame[end - 2..].copy_from_slice(&[0, 0]);
    let balance = checksum16_ipv6(
        Ipv6Addr::from(<[u8; 16]>::try_from(&pkt.frame[14 + 8..14 + 24]).unwrap()),
        Ipv6Addr::from(<[u8; 16]>::try_from(&pkt.frame[14 + 24..14 + 40]).unwrap()),
        protocol,
        &pkt.frame[l4..],
    );
    pkt.frame[end - 2..].copy_from_slice(&balance.to_be_bytes());
    pkt
}

/// (e) #1839 (D1) FIXED pin: the descriptor path's computed-zero
/// canonicalization is scoped to the shared predicate
/// (`adjust_zero_checksum_illegal` — UDP/ICMPv6 for v6), matching the
/// generic adjusters. A v6 TCP checksum that computes to 0x0000 keeps
/// the 0x0000 encoding on BOTH paths (valid on the wire — RFC 8200
/// §8.1 mandates the substitution for UDP only), and the two outputs
/// are byte-identical end to end. (Flipped from the #1824 defect pin
/// asserting the all-protocol descriptor canonicalization.)
#[test]
fn pin_1839_v6_tcp_zero_encoding_parity() {
    let pkt = pin_packet_v6_with_zero_csum(PROTO_TCP);
    let csum_rel = pkt.rel_l4 + 16;
    // Sanity: the crafted packet is genuinely valid with stored 0x0000.
    assert!(oracle_packet_valid(
        &pkt.frame[pkt.l3..], AF6, PROTO_TCP, pkt.rel_l4, false,
    )
    .is_ok());

    // Same-port "rewrite": generic short-circuits (old == new port)
    // and leaves 0x0000; the descriptor applies its ≡0 delta (0xFFFF),
    // computes 0, and now KEEPS the 0x0000 encoding for TCP.
    let nat = NatDecision {
        rewrite_src_port: Some(pkt.src_port),
        ..NatDecision::default()
    };
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };

    let area = area_with_frame(&pkt.frame);
    let decision = make_decision(&pkt, nat, 0);
    let g = rewrite_forwarded_frame_in_place(&area, desc, pkt.meta, &decision, false, None)
        .expect("generic succeeds");
    let out_g = area.slice(g.offset as usize, g.len as usize).unwrap();
    assert_eq!(
        u16::from_be_bytes([out_g[14 + csum_rel], out_g[14 + csum_rel + 1]]),
        0x0000,
        "generic path keeps the 0x0000 encoding for v6 TCP"
    );

    let area = area_with_frame(&pkt.frame);
    let rd = make_descriptor(&pkt, nat, 0);
    assert_eq!(rd.l4_csum_delta, 0xffff, "same-port delta is ≡0 (0xFFFF)");
    let d = apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None)
        .expect("descriptor succeeds");
    let out_d = area.slice(d.offset as usize, d.len as usize).unwrap();
    assert_eq!(
        u16::from_be_bytes([out_d[14 + csum_rel], out_d[14 + csum_rel + 1]]),
        0x0000,
        "#1839 fixed: descriptor keeps the 0x0000 encoding for v6 TCP"
    );

    // Full-frame byte equality — the divergence is gone.
    assert_eq!(out_g, out_d, "#1839 fixed: outputs byte-identical");
    for out in [out_g, out_d] {
        assert!(
            oracle_packet_valid(&out[14..], AF6, PROTO_TCP, pkt.rel_l4, false).is_ok()
        );
    }
}

/// #1839 descriptor-scope matrix (deterministic): a v6 UDP checksum
/// that computes to 0x0000 via the descriptor's ≡0 delta IS
/// canonicalized to 0xFFFF (RFC 8200 §8.1) — the predicate scoping
/// removed TCP from the canonicalization, not UDP.
#[test]
fn descriptor_v6_udp_computed_zero_canonicalizes() {
    let pkt = pin_packet_v6_with_zero_csum(PROTO_UDP);
    // NOTE: stored 0x0000 with a genuinely-zero sum. For UDP this
    // stored encoding is the malformed RFC 8200 case; the descriptor's
    // delta application turns it into the canonical 0xFFFF.
    let csum_rel = pkt.rel_l4 + 6;
    let nat = NatDecision {
        rewrite_src_port: Some(pkt.src_port),
        ..NatDecision::default()
    };
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };
    let area = area_with_frame(&pkt.frame);
    let rd = make_descriptor(&pkt, nat, 0);
    let d = apply_rewrite_descriptor(&area, desc, pkt.meta, &rd, None)
        .expect("descriptor succeeds");
    let out_d = area.slice(d.offset as usize, d.len as usize).unwrap();
    assert_eq!(
        u16::from_be_bytes([out_d[14 + csum_rel], out_d[14 + csum_rel + 1]]),
        0xffff,
        "v6 UDP computed-zero must canonicalize to 0xFFFF on the descriptor path"
    );
}

/// Run the full generic in-place rewrite and the descriptor fast path
/// over the same frame + NAT decision; return the two output frames
/// (asserting both succeed and the result structs agree).
fn run_both_paths(pkt: &ValidPacket, nat: NatDecision) -> (Vec<u8>, Vec<u8>) {
    let desc = XdpDesc {
        addr: DIFF_ADDR as u64,
        len: pkt.frame.len() as u32,
        options: 0,
    };
    let area_g = area_with_frame(&pkt.frame);
    let decision = make_decision(pkt, nat, 0);
    let g = rewrite_forwarded_frame_in_place(&area_g, desc, pkt.meta, &decision, false, None)
        .expect("generic in-place rewrite succeeds");
    let area_d = area_with_frame(&pkt.frame);
    let rd = make_descriptor(pkt, nat, 0);
    let d = apply_rewrite_descriptor(&area_d, desc, pkt.meta, &rd, None)
        .expect("descriptor rewrite succeeds");
    assert_eq!(g, d, "InPlaceRewriteResult must agree");
    (
        area_g
            .slice(g.offset as usize, g.len as usize)
            .unwrap()
            .to_vec(),
        area_d
            .slice(d.offset as usize, d.len as usize)
            .unwrap()
            .to_vec(),
    )
}

/// (f) #1840 (D2) FIXED pin: the RFC 768 zero-checksum skip in
/// `adjust_l4_checksum_port` is family-gated (`l4_udp_checksum_optional`
/// — IPv4 UDP only). A (malformed per RFC 8200 §8.1) v6 UDP datagram
/// with stored 0x0000 gets its checksum adjusted through a generic
/// port rewrite, byte-identical to the descriptor path's delta
/// application. (Flipped from the #1824 defect pin asserting the
/// ungated skip.)
#[test]
fn pin_1840_v6_udp_zero_skip_family_gated() {
    let mut pkt = pin_packet(true, PROTO_UDP, 64, Vec::new());
    let csum_off = pkt.l4() + 6;
    // Force the malformed v6-UDP-zero encoding.
    pkt.frame[csum_off..csum_off + 2].copy_from_slice(&[0, 0]);
    let nat = NatDecision {
        rewrite_src_port: Some(pkt.src_port.wrapping_add(1)),
        ..NatDecision::default()
    };

    // Generic path: port rewritten AND checksum adjusted from 0.
    let mut packet = pkt.l3_packet();
    assert!(apply_nat_ipv6(&mut packet, pkt.rel_l4, PROTO_UDP, nat, false).is_some());
    assert_eq!(
        u16::from_be_bytes([packet[40], packet[41]]),
        pkt.src_port.wrapping_add(1),
        "generic path rewrites the port"
    );
    assert_ne!(
        u16::from_be_bytes([packet[40 + 6], packet[40 + 7]]),
        0x0000,
        "#1840 fixed: malformed v6 UDP stored-0 is adjusted, not skipped"
    );

    // Full-path parity: generic output byte-identical to descriptor.
    let (out_g, out_d) = run_both_paths(&pkt, nat);
    assert_eq!(
        out_g, out_d,
        "#1840 fixed: both paths agree byte-for-byte on the malformed v6 UDP input"
    );
}

/// #1840 family-gate regression guard (v4 counterpart): the RFC 768
/// "no checksum" encoding on IPv4 UDP keeps the skip — stored 0x0000
/// stays 0x0000 through a port rewrite on BOTH paths, byte-identical.
#[test]
fn pin_1840_v4_udp_zero_skip_preserved() {
    let pkt = pin_packet(false, PROTO_UDP, 64, Vec::new());
    let mut pkt = pkt;
    let csum_off = pkt.l4() + 6;
    pkt.frame[csum_off..csum_off + 2].copy_from_slice(&[0, 0]);
    pkt.udp_zero_csum = true;
    let nat = NatDecision {
        rewrite_src_port: Some(pkt.src_port.wrapping_add(1)),
        ..NatDecision::default()
    };

    let mut packet = pkt.l3_packet();
    assert!(apply_nat_ipv4(&mut packet, PROTO_UDP, nat, false).is_some());
    assert_eq!(
        u16::from_be_bytes([packet[pkt.rel_l4], packet[pkt.rel_l4 + 1]]),
        pkt.src_port.wrapping_add(1),
        "v4 port still rewritten"
    );
    assert_eq!(
        u16::from_be_bytes([packet[pkt.rel_l4 + 6], packet[pkt.rel_l4 + 7]]),
        0x0000,
        "v4 UDP 'no checksum' encoding preserved through the rewrite"
    );

    let (out_g, out_d) = run_both_paths(&pkt, nat);
    let out_csum = 14 + pkt.rel_l4 + 6;
    assert_eq!(
        u16::from_be_bytes([out_d[out_csum], out_d[out_csum + 1]]),
        0x0000,
        "descriptor keeps the v4 RFC 768 skip too"
    );
    assert_eq!(out_g, out_d, "v4 zero-skip parity is byte-exact");
}

/// #1840 §5.5 same-port residual pin: malformed v6 UDP stored-0 ×
/// IDENTITY port rewrite. The generic short-circuit (old == new) never
/// calls the adjuster, but the no-op-port parity rule writes the
/// canonical 0xFFFF — matching the descriptor's ≡0-delta application.
/// The v4 counterpart stays 0x0000 on both paths (RFC 768 skip).
#[test]
fn pin_same_port_v6_udp_zero_parity_rule() {
    // v6: both paths emit 0xFFFF.
    let mut pkt = pin_packet(true, PROTO_UDP, 64, Vec::new());
    let csum_off = pkt.l4() + 6;
    pkt.frame[csum_off..csum_off + 2].copy_from_slice(&[0, 0]);
    let nat = NatDecision {
        rewrite_src_port: Some(pkt.src_port), // identity
        ..NatDecision::default()
    };
    let mut packet = pkt.l3_packet();
    assert!(apply_nat_ipv6(&mut packet, pkt.rel_l4, PROTO_UDP, nat, false).is_some());
    assert_eq!(
        u16::from_be_bytes([packet[40 + 6], packet[40 + 7]]),
        0xffff,
        "§5.5 rule: identity port-NAT on stored-0 v6 UDP canonicalizes to 0xFFFF"
    );
    let (out_g, out_d) = run_both_paths(&pkt, nat);
    let out_csum = 14 + pkt.rel_l4 + 6;
    assert_eq!(
        u16::from_be_bytes([out_g[out_csum], out_g[out_csum + 1]]),
        0xffff
    );
    assert_eq!(
        u16::from_be_bytes([out_d[out_csum], out_d[out_csum + 1]]),
        0xffff
    );
    assert_eq!(out_g, out_d, "identity-port v6 UDP stored-0 parity");

    // v4 counterpart: stays 0x0000 on both paths.
    let mut pkt = pin_packet(false, PROTO_UDP, 64, Vec::new());
    let csum_off = pkt.l4() + 6;
    pkt.frame[csum_off..csum_off + 2].copy_from_slice(&[0, 0]);
    pkt.udp_zero_csum = true;
    let nat = NatDecision {
        rewrite_src_port: Some(pkt.src_port), // identity
        ..NatDecision::default()
    };
    let mut packet = pkt.l3_packet();
    assert!(apply_nat_ipv4(&mut packet, PROTO_UDP, nat, false).is_some());
    assert_eq!(
        u16::from_be_bytes([packet[pkt.rel_l4 + 6], packet[pkt.rel_l4 + 7]]),
        0x0000,
        "v4 identity port-NAT keeps the RFC 768 'no checksum' encoding"
    );
    let (out_g, out_d) = run_both_paths(&pkt, nat);
    let out_csum = 14 + pkt.rel_l4 + 6;
    assert_eq!(
        u16::from_be_bytes([out_g[out_csum], out_g[out_csum + 1]]),
        0x0000
    );
    assert_eq!(out_g, out_d, "identity-port v4 UDP stored-0 parity");
}

/// #1838 per-ext-kind placement (deterministic): for every extension
/// header kind the inspect walk understands, a port rewrite + src
/// address rewrite through `apply_nat_ipv6` lands the port at the
/// parsed offset, leaves the ext-chain bytes byte-identical, and
/// yields an oracle-valid packet (checksum adjusted at the real
/// offset).
#[test]
fn ext_kind_nat_rewrite_placement() {
    let new_src: Ipv6Addr = "2001:db8:aaaa::5".parse().unwrap();
    for ext in [
        ExtHdr::HopByHop(1),
        ExtHdr::Routing(0),
        ExtHdr::DestOpts(2),
        ExtHdr::Ah(1),
        ExtHdr::Fragment, // atomic (offset 0) by construction
    ] {
        for proto in [PROTO_TCP, PROTO_UDP] {
            let pkt = pin_packet(true, proto, 64, vec![ext]);
            let rel_l4 = pkt.rel_l4;
            assert_eq!(rel_l4, 40 + ext.encoded_len(), "ground truth offset");
            let nat = NatDecision {
                rewrite_src: Some(IpAddr::V6(new_src)),
                rewrite_dst_port: Some(0x4444),
                ..NatDecision::default()
            };
            let original = pkt.l3_packet();
            let mut packet = original.clone();
            assert!(
                apply_nat_ipv6(&mut packet, rel_l4, proto, nat, false).is_some(),
                "apply_nat_ipv6 succeeds ({ext:?}/{proto})"
            );
            assert_eq!(
                u16::from_be_bytes([packet[rel_l4 + 2], packet[rel_l4 + 3]]),
                0x4444,
                "dst port at parsed offset ({ext:?}/{proto})"
            );
            assert_eq!(
                &packet[40..rel_l4],
                &original[40..rel_l4],
                "ext chain untouched ({ext:?}/{proto})"
            );
            let verdict = oracle_packet_valid(&packet, AF6, proto, rel_l4, false);
            assert!(
                verdict.is_ok(),
                "post-NAT oracle valid ({ext:?}/{proto}): {verdict:?}"
            );
        }
    }
}

/// #1838: `recompute_l4_checksum_ipv6` with an ext chain produces an
/// oracle-valid packet — the L4 segment, the checksum field, and the
/// pseudo-header upper-layer length (`len - rel_l4`, RFC 8200 §8.1)
/// all derive from the threaded offset.
#[test]
fn recompute_v6_with_ext_chain_oracle_valid() {
    for proto in [PROTO_TCP, PROTO_UDP] {
        let pkt = pin_packet(
            true,
            proto,
            64,
            vec![ExtHdr::HopByHop(0), ExtHdr::DestOpts(1)],
        );
        let rel_l4 = pkt.rel_l4;
        let mut packet = pkt.l3_packet();
        // Corrupt the stored checksum, then recompute at the real offset.
        let csum_off = rel_l4 + if proto == PROTO_TCP { 16 } else { 6 };
        packet[csum_off..csum_off + 2].copy_from_slice(&0xDEADu16.to_be_bytes());
        assert!(recompute_l4_checksum_ipv6(&mut packet, rel_l4, proto).is_some());
        let verdict = oracle_packet_valid(&packet, AF6, proto, rel_l4, false);
        assert!(verdict.is_ok(), "recompute oracle valid ({proto}): {verdict:?}");
    }
}
