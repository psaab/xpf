// #8670: the Pref64-destination gate must attribute its drop by REASON.
//
// The gate (`poll_descriptor/mod.rs`, #6835) refuses a packet that reached the
// forward path still addressed to a Pref64 destination. It served two
// populations and counted both as `nat64_frag_dropped`:
//
//   - a real non-first fragment whose association missed — correctly named;
//   - every IP protocol outside {TCP, UDP, ICMP, ICMPv6}, which has no L4
//     identity the shim can resolve (#6837 `metadata_tuple_complete`) and so
//     arrives flowless. These are NOT fragments.
//
// The second population is the defect, and the harm is a FALSE ACCUSATION
// rather than a missing number: `nat64_frag_dropped` surfaces as the `NAT64
// fragment drops` operator counter, so a broken ESP or GRE tunnel across a
// NAT64 prefix reported a FRAGMENTATION fault and sent the operator to PMTU.
// "Dropped because it is a fragment" and "dropped because stateful NAT64 does
// not translate this protocol at all" need opposite next actions.
//
// These cells drive the REAL poll path (`txn_run_descriptor`), not the
// attribution helper, so they bind the WIRING: moving the gate's counter back
// reds them.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::test_zone_ids::*;
use std::net::Ipv6Addr;

const GRE: u8 = 47;
const ESP: u8 = 50;
const AH: u8 = 51;

/// A plain (unfragmented) IPv6 frame carrying `proto` directly after the fixed
/// header — no extension chain, so the only thing that can make it flowless is
/// the protocol itself.
fn v6_plain_frame_8670(src: Ipv6Addr, dst: Ipv6Addr, proto: u8) -> Vec<u8> {
    let mut f = vec![
        0x02, 0xbf, 0x72, 0x01, 0x00, 0x01, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x86, 0xdd,
    ];
    let mut ip = vec![0u8; 40];
    ip[0] = 0x60; // version 6
    ip[4..6].copy_from_slice(&20u16.to_be_bytes()); // payload len
    ip[6] = proto;
    ip[7] = 64; // hop limit > 1: no ICMP-TE
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    f.extend_from_slice(&ip);
    f.extend_from_slice(&[0u8; 20]);
    f
}

fn v6_plain_meta_8670(
    frame_len: usize,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    proto: u8,
) -> UserspaceDpMeta {
    UserspaceDpMeta {
        flow_src_addr: src.octets(),
        flow_dst_addr: dst.octets(),
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 54,
        pkt_len: (frame_len - 14) as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: proto,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

fn snapshot_8670() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.nat64_rules = vec![crate::protocol::NAT64RuleSnapshot {
        name: "nat64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["172.16.80.50".to_string()],
        no_v6_frag_header: false,
        ..Default::default()
    }];
    snapshot
}

/// Drive one plain v6 datagram of `proto` to `dst` through the real poll path.
/// Returns `(tx, frag_dropped, ineligible_protocol, exthdr_ineligible)`.
fn drive_8670(proto: u8, dst: Ipv6Addr) -> (u64, u64, u64, u64) {
    let forwarding = build_forwarding_state(&snapshot_8670());
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);
    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let frame = v6_plain_frame_8670(src, dst, proto);
    let meta = v6_plain_meta_8670(frame.len(), src, dst, proto);
    let (batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    (
        dbg.tx as u64,
        batch.nat64_frag_dropped,
        batch.nat64_ineligible_protocol,
        batch.nat64_exthdr_ineligible,
    )
}

fn pref64_dst() -> Ipv6Addr {
    "64:ff9b::808:808".parse().expect("pref64 dst")
}

/// A routable, NON-Pref64 IPv6 destination reached via the fixture's `::/0`.
fn ordinary_dst() -> Ipv6Addr {
    "2001:4860:4860::8888".parse().expect("ordinary v6 dst")
}

// THE DEFECT. A whole GRE / ESP datagram addressed to a Pref64 destination is
// refused (correctly — RFC 6146 specifies stateful NAT64 for TCP, UDP and ICMP
// only, and a Pref64 is a translation namespace no router can deliver) and must
// be attributed to the PROTOCOL counter, never to the fragment counter.
#[test]
fn pref64_untranslatable_protocol_is_not_counted_as_a_fragment_8670() {
    for (proto, name) in [(GRE, "GRE"), (ESP, "ESP")] {
        let (tx, frag, proto_inelig, exthdr) = drive_8670(proto, pref64_dst());
        assert_eq!(tx, 0, "{name} to a Pref64 destination must not be emitted");
        assert_eq!(
            frag, 0,
            "#8670: a whole {name} datagram is NOT a fragment, so it must not bump \
             `nat64_frag_dropped` — that counter surfaces as `NAT64 fragment drops` and \
             reported a broken {name} tunnel as a FRAGMENTATION fault, sending the operator \
             to PMTU for a problem that is architectural"
        );
        assert_eq!(
            proto_inelig, 1,
            "#8670: the {name} drop must be attributed to `nat64_ineligible_protocol`"
        );
        assert_eq!(exthdr, 0, "{name} carries no extension header");
    }
}

// THE CONTROL that makes the cell above mean something. Without it, "GRE to
// Pref64 is dropped" is equally consistent with GRE being undeliverable in this
// fixture for some unrelated reason — an unroutable destination, a policy deny,
// a protocol the dataplane refuses outright. Driving the SAME protocol to an
// ordinary destination shows it forwards, so the Pref64 destination is the
// discriminator and the gate under test is the thing that refused it.
//
// This is the experiment that corrected the issue as filed: #8670 originally
// claimed the drop was a property of FLOWLESS traffic. It is not. Flowless GRE
// and ESP forward perfectly well; the un-varied axis in the original report was
// the Pref64 destination, and varying it is what located the real gate.
#[test]
fn untranslatable_protocol_forwards_to_an_ordinary_destination_8670() {
    for (proto, name) in [(GRE, "GRE"), (ESP, "ESP")] {
        let (tx, frag, proto_inelig, exthdr) = drive_8670(proto, ordinary_dst());
        assert_eq!(
            tx, 1,
            "CONTROL: {name} to an ORDINARY v6 destination must FORWARD. If this is 0 the \
             sibling cell proves nothing — the drop there would not be attributable to the \
             Pref64 gate"
        );
        assert_eq!(
            (frag, proto_inelig, exthdr),
            (0, 0, 0),
            "CONTROL: a forwarded {name} datagram must bump no NAT64 refusal counter"
        );
    }
}

// AH (51) is untranslatable too, but it already had a correctly-named counter
// (`nat64_exthdr_ineligible`, #5625 — RFC 7915 §5.1) and was not reaching it
// from this gate. Attributing in the TX dispatcher's order — ext-header, then
// fragment, then protocol — means one packet gets ONE answer whichever site
// refuses it. Pins that AH does not land in the new protocol bucket.
#[test]
fn pref64_ah_is_attributed_to_the_exthdr_counter_not_the_protocol_one_8670() {
    let (tx, frag, proto_inelig, exthdr) = drive_8670(AH, pref64_dst());
    assert_eq!(tx, 0, "AH to a Pref64 destination must not be emitted");
    assert_eq!(
        exthdr, 1,
        "#8670: AH must reach the ext-header counter it already had"
    );
    assert_eq!(
        proto_inelig, 0,
        "#8670: AH must NOT fall into the protocol bucket — the gate attributes ext-header \
         first, matching the TX dispatcher, so the two sites cannot disagree about one packet"
    );
    assert_eq!(frag, 0, "AH is not a fragment");
}

// ANTI-REGRESSION. The gate's OTHER population is a genuine non-first fragment,
// for which `nat64_frag_dropped` is the right counter and must not move. A fix
// that redirected the whole gate to the new counter would pass every cell above
// and silently destroy the #2562 fragment accounting; this is what catches it.
//
// `source_nat_rules` is cleared for the reason
// `nat64_frag_assoc_miss_must_drop_with_default_route_6927` documents: the
// #6122 same-family gate claims any fragment it would translate, upstream of
// this one, so leaving the fixture's `::/0` SNAT rule in place means the packet
// never reaches the gate under test.
#[test]
fn pref64_nonfirst_fragment_is_still_attributed_to_the_fragment_counter_8670() {
    let mut snapshot = snapshot_8670();
    snapshot.source_nat_rules.clear();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src v6");
    let dst = pref64_dst();

    // Non-first fragment (offset > 0), TCP inside, with no association
    // installed — a miss, which is what reaches the Pref64 gate.
    let mut f = vec![
        0x02, 0xbf, 0x72, 0x01, 0x00, 0x01, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x86, 0xdd,
    ];
    let mut ip = vec![0u8; 40];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&28u16.to_be_bytes());
    ip[6] = 44; // Fragment extension header
    ip[7] = 64;
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    f.extend_from_slice(&ip);
    let mut frag = [0u8; 8];
    frag[0] = crate::ip_proto::PROTO_TCP;
    frag[2..4].copy_from_slice(&0x0008u16.to_be_bytes()); // offset > 0
    frag[4..8].copy_from_slice(&0x8670_0001u32.to_be_bytes());
    f.extend_from_slice(&frag);
    f.extend_from_slice(&[0u8; 20]);

    let mut meta = v6_plain_meta_8670(f.len(), src, dst, crate::ip_proto::PROTO_TCP);
    meta.l4_offset = 62;
    meta.payload_offset = 82;

    let (batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &f,
        meta,
        true,
    );
    assert_eq!(dbg.tx, 0, "a NAT64 fragment-association miss must drop");
    assert_eq!(
        batch.nat64_frag_dropped, 1,
        "#8670: a REAL non-first fragment must KEEP its #2562 attribution — redirecting the \
         whole gate to the protocol counter would pass every other cell here while silently \
         destroying the fragment accounting"
    );
    assert_eq!(
        batch.nat64_ineligible_protocol, 0,
        "#8670: a fragment is not a protocol-ineligibility drop"
    );
}
