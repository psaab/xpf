// #6304: bind the LIVE established-flow mirror call site.
//
// `stage_flow_cache_hit` had NO test reference anywhere in the tree
// (`git grep stage_flow_cache_hit -- '*tests*'` returned zero). The two #6114
// fail-on-revert tests drive the sample-before-CAS ordering through the DEAD
// `enqueue_sampled_mirror_clone_to_live` wrapper, which shares
// `sample_then_admit_mirror_clone` with this live path. Both are therefore
// bound to the SHARED HELPER, not to the live call site: reverting ONLY the
// call site here — leaving `sample_then_admit_mirror_clone` correct — passed
// the entire suite.
//
// This module closes that gap by driving `stage_flow_cache_hit` itself.
//
// TOPOLOGY (the fold round): every ifindex here is DISTINCT, and the ingress
// is a real 802.1Q-tagged unit, so the two resolutions the live call site
// performs are observable rather than collapsed onto one constant:
//
//   wire VLAN 80 on physical ifindex 6  --(ingress_logical_ifindex)-->  20080
//     `resolve_mirror_config` is keyed by the LOGICAL unit, so dropping
//     `meta.ingress_vlan_id` resolves NO mirror configuration at all.
//
//   mirror output unit 200  --(forwarding.egress[200].bind_ifindex)-->  22
//     `MirrorTargetMap` is keyed by the PHYSICAL XSK bind port, so passing
//     `config.output_ifindex` through unresolved searches for 200 and reports
//     `NoBinding`.
//
// An earlier revision of this module set ingress == egress == 7 and mirror
// out == 22 with no VLAN or interface maps, which left both of those live
// call-site regressions green.

use super::*;
use crate::afxdp::flow_cache::{FlowCacheEntry, FlowCacheStamp};
use crate::afxdp::umem::MmapArea;
use crate::ip_proto::{PROTO_TCP, PROTO_UDP};
use crate::test_zone_ids::*;
use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// PHYSICAL AF_XDP bind port this worker owns.
const PHYS_INGRESS_IFINDEX: i32 = 6;
/// 802.1Q VID carried on the wire (a real tag: `l3_offset` is 18, not 14).
const INGRESS_VLAN_ID: u16 = 80;
/// LOGICAL (VLAN-selecting) ingress unit that `(6, 80)` resolves to.
const LOGICAL_INGRESS_IFINDEX: i32 = 20080;
/// Forward egress for the cached decision.
const EGRESS_IFINDEX: i32 = 7;
/// `then port-mirror` output — a LOGICAL unit, as the compiler emits it.
const MIRROR_OUT_LOGICAL_IFINDEX: i32 = 200;
/// ...backed by THIS physical XSK bind port, which is what `MirrorTargetMap`
/// is keyed by.
const MIRROR_OUT_BIND_IFINDEX: i32 = 22;
const BINDING_INDEX: usize = 0;
/// #6304: the post-SNAT source address `nat_translated_entry` rewrites to.
/// Distinct from the DNAT address below so a rewrite that applied one of them
/// to both slots is visible.
const SNAT_SRC_IP: Ipv4Addr = Ipv4Addr::new(172, 16, 50, 8);
/// #6304: the post-DNAT destination address `nat_translated_entry` rewrites to.
const DNAT_DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 55);

fn test_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 50, 200)),
        src_port: 45678,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

/// A VLAN-80-tagged IPv4/TCP ACK with a healthy TTL (64), so the #3779
/// TTL-expiry arm above the mirror block does not divert it into a Time
/// Exceeded reply.
///
/// `option_words` is the number of 32-bit IPv4 option words, so the IHL nibble
/// is `5 + option_words` and the header is genuinely that long: `total_len`,
/// the frame length and the metadata offsets all follow from it. Every test
/// here uses a self-consistent frame; the rollback test corrupts ONE byte of
/// this frame AFTER construction, which is the only way that decline is
/// reachable (see `dma_raced_short_ihl_frame`).
///
/// The 802.1Q tag is PHYSICALLY present because the shim only ever reports a
/// non-zero `ingress_vlan_id` together with `ingress_vlan_present`, and the
/// whole dataplane then reads L3 at 18 (`parse_l2` in `userspace-xdp`,
/// `poll_stages.rs:551`, `rewrite_plan_eth_from_parts`). A fixture with
/// `ingress_vlan_id = 80` and an untagged frame is a meta/frame pair the wire
/// format cannot produce.
///
/// Both checksum fields (IPv4 header at [28..30], TCP at [54..56] of the
/// no-option frame — the TCP header starts at 38, and its checksum is at +16)
/// are left ZERO, which no correct sender emits. Nothing on
/// this path verifies either one — XDP receives whatever the NIC DMA'd, and
/// both rewriters only apply INCREMENTAL deltas
/// (`adjust_ipv4_header_checksum`, `recompute_l4_checksum_ipv4`) rather than
/// validating the inbound value — so the zero does not change any decision
/// under test. It does mean the frame is not a wire-valid packet end to end,
/// only in every field these tests read.
fn vlan_tagged_tcp_v4_frame(option_words: usize) -> Vec<u8> {
    let key = test_key();
    let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (key.src_ip, key.dst_ip) else {
        unreachable!("test key is v4")
    };
    let ihl_words = 5 + option_words;
    assert!(ihl_words <= 15, "IPv4 IHL nibble is 4 bits");
    let total_len = (ihl_words * 4 + 20) as u16;
    let mut frame = Vec::new();
    // Ethernet dst + src, then the 802.1Q TPID.
    frame.extend_from_slice(&[
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0xbf, 0x72, 0x00, 0x01, 0x01, 0x81, 0x00,
    ]);
    // 802.1Q TCI (PCP 0, DEI 0, VID 80), then the inner ether_type.
    frame.extend_from_slice(&INGRESS_VLAN_ID.to_be_bytes());
    frame.extend_from_slice(&[0x08, 0x00]);
    // IPv4: version 4 + the declared IHL, TTL 64, proto TCP.
    frame.push(0x40 | ihl_words as u8);
    frame.push(0x00);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    // IPv4 options: one NOP (type 1) per byte. Padding a header out with NOPs
    // is legal per RFC 791 §3.1 and is what a router emits when it has to
    // preserve header length without carrying an option.
    frame.extend(std::iter::repeat_n(0x01u8, option_words * 4));
    // TCP: ports, seq, ack, offset 5 / ACK, window, csum, urg.
    frame.extend_from_slice(&key.src_port.to_be_bytes());
    frame.extend_from_slice(&key.dst_port.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x50, 0x10, 0xfa, 0xf0]);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    assert_eq!(
        frame.len(),
        18 + total_len as usize,
        "the frame must carry exactly the datagram it declares"
    );
    frame
}

/// #7678: the UDP twin of `test_key`. The protocol is the ONLY field that
/// differs, so a cell using it exercises the same cache set, the same
/// addresses and the same ports as every TCP cell here — the one axis under
/// test is the one that moves.
fn udp_test_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        protocol: PROTO_UDP,
        ..test_key()
    }
}

/// #7678: a VLAN-80-tagged IPv4/UDP datagram carrying `udp_test_key`'s tuple.
///
/// It must not be TCP. `reject_reply.rs` branches on `meta.protocol ==
/// PROTO_TCP` and synthesizes a TCP RST on that arm, never consulting
/// `reject_message` — so a reject cell built on the TCP frame builders cannot
/// reach the ICMP code path at all, however the cached descriptor is set up.
fn vlan_tagged_udp_v4_frame() -> Vec<u8> {
    let key = udp_test_key();
    let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (key.src_ip, key.dst_ip) else {
        unreachable!("test key is v4")
    };
    // IHL 5 (20 bytes) + the 8-byte UDP header + 4 bytes of payload.
    let udp_len: u16 = 8 + 4;
    let total_len: u16 = 20 + udp_len;
    let mut frame = Vec::new();
    frame.extend_from_slice(&[
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0xbf, 0x72, 0x00, 0x01, 0x01, 0x81, 0x00,
    ]);
    frame.extend_from_slice(&INGRESS_VLAN_ID.to_be_bytes());
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, 64, PROTO_UDP, 0x00, 0x00]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&key.src_port.to_be_bytes());
    frame.extend_from_slice(&key.dst_port.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(
        frame.len(),
        18 + total_len as usize,
        "the frame must carry exactly the datagram it declares"
    );
    frame
}

/// #7678: `test_meta` for the UDP frame. Derived the same way, with the
/// protocol and ports taken from `udp_test_key` so the metadata, the frame and
/// the looked-up key all describe one datagram.
fn udp_test_meta(frame: &[u8]) -> UserspaceDpMeta {
    let key = udp_test_key();
    UserspaceDpMeta {
        protocol: PROTO_UDP,
        // A UDP datagram has no TCP flags; leaving the TCP ACK bit set would
        // be a self-inconsistent packet.
        tcp_flags: 0,
        l4_offset: 18 + ((frame[18] & 0x0f) as u16) * 4,
        payload_offset: frame.len() as u16,
        pkt_len: frame.len() as u16,
        flow_src_port: key.src_port,
        flow_dst_port: key.dst_port,
        ..test_meta(frame)
    }
}

fn tcp_v4_ack_frame() -> Vec<u8> {
    vlan_tagged_tcp_v4_frame(0)
}

/// The rollback fixture: a frame whose IPv4 IHL nibble was overwritten to 15
/// (60 bytes) AFTER the shim parsed and described it, leaving an L3 payload
/// (40 bytes) shorter than the header the packet now declares.
///
/// DOMAIN PARITY, stated exactly. This is NOT a frame the parser could have
/// produced together with `test_meta`'s offsets: `parse_ipv4`
/// (`userspace-xdp/src/lib.rs`) does `read_bytes(data, data_end, l3_offset,
/// ihl)?` before deriving `l4_offset`, so a shim-delivered IPv4 packet ALWAYS
/// satisfies `frame.len() - l3 >= ihl`, and `ipv4_declared_l3_end` then clamps
/// the trimmed payload UP to at least `ihl`. Those two facts COMPOSE rather
/// than corroborate, and the shim leg is the load-bearing one: on exactly the
/// input it excludes (`frame.len() < l3 + ihl`) `ipv4_declared_l3_end` returns
/// `None` rather than clamping, and `trim_l3_payload` falls through to a
/// `meta.pkt_len`-derived length with no `ihl` relation at all. So the clamp
/// bites only where the shim leg already holds — do not lean on it alone.
/// Together they mean no self-consistent, shim-produced IPv4 frame can make
/// either in-place rewriter take its `l3_payload.len() < ihl` bail — verified
/// firsthand by
/// `live_flow_cache_callsite_ip_options_frame_takes_the_in_place_path_6304`,
/// which feeds the SELF-CONSISTENT IHL-15 packet (40 bytes of options, an
/// honest 80-byte datagram) and watches the rewrite succeed.
///
/// What IS reachable, and what this fixture models, is the frame changing
/// under the descriptor after the shim wrote the metadata — NIC DMA into a
/// recycled UMEM frame. That hazard is exactly why `expected_ports` exists as
/// a "DMA race guard" and why #5466/#4965 made both rewriters run every bail
/// gate against the PRISTINE frame before the first UMEM write. Under it the
/// metadata legitimately describes the packet the shim SAW, not the bytes now
/// in the buffer, so `test_meta`'s `l4_offset = 38` is correct provenance
/// rather than an impossible claim. The rollback branch it drives is therefore
/// defense-in-depth, not a hot-path case — which is precisely why nothing else
/// in the suite covered it.
fn dma_raced_short_ihl_frame() -> Vec<u8> {
    let mut frame = tcp_v4_ack_frame();
    // version 4, IHL 15 (= 60 bytes) over the 40-byte L3 payload actually
    // present. Only the version/IHL byte is disturbed: the ports at [38..42]
    // still match the flow tuple, so the descriptor path's DMA-race port gate
    // is NOT what declines here — the header-length gate is.
    frame[18] = 0x4f;
    frame
}

fn test_meta(frame: &[u8]) -> UserspaceDpMeta {
    let key = test_key();
    let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (key.src_ip, key.dst_ip) else {
        unreachable!("test key is v4")
    };
    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&src_ip.octets());
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&dst_ip.octets());
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: PHYS_INGRESS_IFINDEX as u32,
        ingress_vlan_id: INGRESS_VLAN_ID,
        ingress_vlan_present: 1,
        l3_offset: 18,
        // Derived from the frame the way `parse_ipv4` derives them — L4 starts
        // after the IHL the header declares, and the payload after the TCP data
        // offset. Hardcoding 38/58 silently detached the metadata from any
        // fixture carrying IPv4 options.
        l4_offset: 18 + ((frame[18] & 0x0f) as u16) * 4,
        payload_offset: frame.len() as u16,
        // The shim reports the FULL wire length (`packet_len = data_end - data`,
        // `userspace-xdp/src/lib.rs:566`), and the reinject path agrees
        // (`coordinator/inject.rs:73` uses `frame_len`). `pkt_len` feeds the
        // filter/policy/zone byte counters and the session byte accounting, so
        // an L2-stripped value under-reports every one of them.
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        flow_src_addr: src_addr,
        flow_dst_addr: dst_addr,
        flow_src_port: key.src_port,
        flow_dst_port: key.dst_port,
        ..UserspaceDpMeta::default()
    }
}

fn cached_entry() -> FlowCacheEntry {
    FlowCacheEntry {
        key: test_key(),
        // #5139: the cache identity is (PHYSICAL parent, LOGICAL unit). The
        // lookup rebuilds both from the packet via `FlowCacheLookup::for_packet`,
        // so these must match what `(6, VLAN 80)` resolves to or the hit never
        // happens and every test below silently exercises the miss path.
        ingress_ifindex: PHYS_INGRESS_IFINDEX,
        logical_ingress_ifindex: LOGICAL_INGRESS_IFINDEX,
        descriptor: RewriteDescriptor {
            dst_mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
            fabric_redirect: false,
            // Egress keeps the tag, so `eth_len == l3 == 18` and the in-place
            // rewrite is a pure header overwrite with no payload memmove.
            tx_vlan_id: INGRESS_VLAN_ID,
            ether_type: 0x0800,
            rewrite_src_ip: None,
            rewrite_dst_ip: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            ip_csum_delta: 0,
            l4_csum_delta: 0,
            egress_ifindex: EGRESS_IFINDEX,
            tx_ifindex: EGRESS_IFINDEX,
            // Hairpin: the forward target IS this binding, which is the arm
            // that carries the in-place rewrite + the live mirror block.
            target_binding_index: Some(BINDING_INDEX),
            input_filter_log: None,
            input_filter_counters: crate::filter::CachedFilterCounters::default(),
            tx_selection: CachedTxSelectionDescriptor::default(),
            nat64: false,
            nptv6: false,
            apply_nat_on_fabric: false,
        },
        decision: SessionDecision { resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: EGRESS_IFINDEX,
            tx_ifindex: EGRESS_IFINDEX,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]),
            tx_vlan_id: INGRESS_VLAN_ID,
        }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 },
        metadata: SessionMetadata {
            ingress_zone: TEST_TRUST_ZONE_ID,
            egress_zone: TEST_UNTRUST_ZONE_ID,
            // #4983: the cached session was installed from a frame that
            // arrived on {PHYS_INGRESS_IFINDEX, INGRESS_VLAN_ID}, so mirror
            // the same pair the fixture's UserspaceDpMeta carries above --
            // a flow-cache-hit fixture that zeroed it would model a session
            // production cannot install on this path.
            ingress_ifindex: PHYS_INGRESS_IFINDEX as u32,
            ingress_vlan_id: INGRESS_VLAN_ID,
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
        stamp: FlowCacheStamp {
            config_generation: 0,
            fib_generation: 0,
            owner_rg_id: 0,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        },
        observed_bytes: 0,
        last_used_epoch: 0,
        neighbor_mac_epoch: 0,
        neighbor_shard: crate::afxdp::flow_cache::NEIGHBOR_SHARD_NONE,
    }
}

/// `cached_entry` with an UNTAGGED egress: same VLAN-80-tagged ingress frame,
/// but the cached descriptor asks for no tag on the way out.
///
/// This is the only lever in this module that changes which `InPlaceL2Rewrite`
/// variant the rewrite reports. With `tx_vlan_id == INGRESS_VLAN_ID` the
/// target Ethernet length equals the ingress `l3_offset` (18 == 18) and
/// `classify_in_place_l2_rewrite` returns `SameLength`, whose arm in
/// `WorkerTxCounters::record_in_place_l2_rewrite` is empty — so every other
/// fixture here accounts NOTHING through that call and cannot tell whether it
/// runs. With `tx_vlan_id == 0` the target is 14, the 802.1Q tag is dropped by
/// sliding the descriptor 4 bytes forward inside the same UMEM frame, and the
/// call is `VlanPopDescriptor`.
///
/// `decision.resolution.tx_vlan_id` moves with it: the generic rewriter reads
/// the resolution where the descriptor path reads the descriptor, and this
/// module has already been bitten once by a fixture whose two halves
/// disagreed.
fn untagged_egress_entry() -> FlowCacheEntry {
    let mut entry = cached_entry();
    entry.descriptor.tx_vlan_id = 0;
    entry.decision.resolution.tx_vlan_id = 0;
    entry
}

/// #6304: `cached_entry` carrying a BOUND policy hit counter.
///
/// The stock fixture leaves `policy_counter: None` and `policy_counter_idx: 0`,
/// and the `ForwardingState::default()` policy snapshot has no rule at index 0,
/// so `resolve_session_hit_counter(None, 0)` is `None` and the whole
/// `if let Some(counter)` block at the call site never executes. Binding the
/// handle is what makes the block reachable — see
/// `live_flow_cache_callsite_recounts_the_established_policy_hit_6304`.
///
/// The handle is bound rather than the index because #3322 made the BOUND
/// handle the preferred resolution: it survives a live policy reorder, where
/// the positional index re-attributes the flow's packets to a different rule.
fn policy_counted_entry(counter: &Arc<crate::policy::PolicyRuleCounter>) -> FlowCacheEntry {
    let mut entry = cached_entry();
    entry.metadata.policy_counter = Some(counter.clone());
    entry
}

/// #6304: `cached_entry` carrying BOUND filter `then count` handles on both
/// replay paths — the #2573 TX/output side and the #3777 interface-INPUT side.
///
/// The stock fixture leaves `tx_selection: CachedTxSelectionDescriptor::default()`
/// and `input_filter_counters: CachedFilterCounters::default()`, i.e. two EMPTY
/// counter lists. Both replays are `for_each` walks over those lists, so neither
/// body executes on any fixture in THIS module — which is why
/// `live_flow_cache_callsite_replays_every_filter_count_term_6304` exists.
///
/// The two sides were NOT equally unbound crate-wide, and an earlier revision of
/// this comment said they were. Severing the TX/output walk leaves the whole
/// crate green; severing the INPUT walk reds
/// `txn_flow_cache_hit_replays_input_filter_then_count_3777`
/// (`afxdp/tests_txn_flow_cache.rs`), which drives two packets of one flow
/// through the full descriptor path and asserts the input counter reaches 2.
/// Both measured, one mutation at a time. The input assertion here is therefore
/// a SECOND, call-site-local binding rather than the only one — worth keeping,
/// since #3777 exists precisely because the two sides regressed independently
/// once already, but not worth overclaiming.
///
/// `tx` is a SLICE, not one handle, because #2573's guarantee is specifically
/// that ALL matched `then count` terms are replayed rather than only the last: a
/// #2544 fall-through flow matches several count terms, and a replay that walked
/// only the final one would satisfy a single-counter assertion.
fn filter_counted_entry(
    tx: &[Arc<crate::filter::FilterTermCounter>],
    input: &Arc<crate::filter::FilterTermCounter>,
) -> FlowCacheEntry {
    let mut entry = cached_entry();
    for counter in tx {
        entry
            .descriptor
            .tx_selection
            .filter_counters
            .push(counter.clone());
    }
    entry.descriptor.input_filter_counters.push(input.clone());
    entry
}

/// #6304: `cached_entry` carrying a real SNAT **and** a real DNAT.
///
/// The stock fixture's decision is `NatDecision::default()` — both
/// `rewrite_src` and `rewrite_dst` `None` — so the two `if
/// cached_decision.nat.rewrite_*.is_some()` guards at the call site are FALSE
/// on every packet this module has ever staged and neither
/// `telemetry.counters.snat_packets` nor `.dnat_packets` can be reached. A cell
/// that merely retained the counters would still not exercise those two lines.
///
/// BOTH halves move together. `RewriteDescriptor::from_forward_decision` copies
/// `decision.nat.rewrite_src`/`rewrite_dst` into `descriptor.rewrite_src_ip`/
/// `rewrite_dst_ip` and derives the two checksum deltas from the same pair, so
/// a fixture that set the decision alone would be one production never
/// produces: the descriptor fast path reads the DESCRIPTOR, so it would forward
/// the frame un-translated while the counters claimed a translation. The deltas
/// come from the same `compute_*_csum_delta` helpers the seed path uses rather
/// than being hand-computed, so the fixture cannot drift from the constructor.
///
/// Ports are deliberately NOT rewritten: `authoritative_forward_ports` derives
/// the DMA-race gate's expected pair from `flow.forward_key`, which is the
/// PRE-NAT tuple, and the frame carries exactly that pair — so an address-only
/// translation keeps the in-place descriptor rewrite on its success path and
/// the positive control below is a real one.
fn nat_translated_entry() -> FlowCacheEntry {
    let mut entry = cached_entry();
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(SNAT_SRC_IP)),
        rewrite_dst: Some(IpAddr::V4(DNAT_DST_IP)),
        ..NatDecision::default()
    };
    let key = test_key();
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key,
    };
    entry.decision.nat = nat;
    entry.descriptor.rewrite_src_ip = nat.rewrite_src;
    entry.descriptor.rewrite_dst_ip = nat.rewrite_dst;
    entry.descriptor.ip_csum_delta = crate::afxdp::checksum::compute_ip_csum_delta(&flow, &nat);
    entry.descriptor.l4_csum_delta = crate::afxdp::checksum::compute_l4_csum_delta(&flow, &nat);
    entry
}

fn tx_pipeline() -> WorkerTxPipeline {
    WorkerTxPipeline {
        free_tx_frames: (0..8u64).collect(),
        pending_tx_prepared: VecDeque::new(),
        pending_tx_local: VecDeque::new(),
        backup_retry_scratch: std::collections::VecDeque::new(),
        max_pending_tx: 64,
        outstanding_tx: 0,
        pending_fill_frames: VecDeque::new(),
        in_flight_prepared_recycles: FastMap::default(),
        in_flight_untracked_tx: FastSet::default(),
        tx_submit_ns: Vec::new().into_boxed_slice(),
    }
}

fn tx_counters() -> WorkerTxCounters {
    WorkerTxCounters {
        pending_direct_tx_packets: 0,
        pending_copy_tx_packets: 0,
        neighbor_retry_cross_umem_copies: 0,
        pending_in_place_tx_packets: 0,
        pending_in_place_vlan_push_desc_packets: 0,
        pending_in_place_vlan_pop_desc_packets: 0,
        pending_in_place_vlan_push_no_headroom_packets: 0,
        pending_in_place_l2_memmove_fallback_packets: 0,
        pending_direct_tx_no_frame_fallback_packets: 0,
        pending_direct_tx_build_fallback_packets: 0,
        pending_direct_tx_disallowed_fallback_packets: 0,
    }
}

fn scratch() -> WorkerScratch {
    WorkerScratch {
        scratch_recycle: Vec::new(),
        scratch_forwards: Vec::new(),
        scratch_fill: Vec::new(),
        scratch_prepared_tx: Vec::new(),
        scratch_local_tx: Vec::new(),
        scratch_committed_orig_idx: Vec::new(),
        scratch_exact_prepared_tx: Vec::new(),
        scratch_exact_local_tx: Vec::new(),
        scratch_completed_offsets: Vec::new(),
        scratch_post_recycles: Vec::new(),
        scratch_cross_binding_tx: Vec::new(),
        scratch_rst_teardowns: Vec::new(),
        scratch_filter_revoked_keys: Vec::new(),
    }
}

/// How much room the cross-worker mirror clone queue has when the packet
/// reaches admission.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MirrorTargetQueue {
    /// Admission succeeds. This is the correct fixture for a NON-sampled
    /// packet: at cap, `try_acquire_pending_tx_admission` returns `Err` from
    /// its relaxed `admitted >= admission_cap` load BEFORE reaching the
    /// `compare_exchange_weak(AcqRel)`, so "no shared-CAS side effect" holds
    /// for the trivial reason that no CAS was reachable, whatever the call
    /// site did.
    WithRoom,
    /// Driven to its cap, so admission reports `QueueFullCrossWorker`.
    AtCap,
    /// EMPTY, but with a soft cap of exactly one slot — so the target's
    /// `pending_tx_admitted` accounting becomes externally observable: any
    /// admission this call site holds or strands excludes an interleaving
    /// producer's `try_enqueue_tx_owned`, exactly as
    /// `mirror/mod_tests.rs::live_mirror_admission_reserves_slot_against_interleaving_producer`
    /// demonstrates.
    CapOneEmpty,
}

/// Owns every referent a `WorkerContext` borrows so EVERY call-site test below
/// shares ONE wiring definition. Before the fold each test carried its own
/// ~200-line copy, and the mirror maps drifted apart from the ifindexes the
/// call site actually resolves.
///
/// Deliberately not "the N tests below": the module has grown three times since
/// this comment was written and a literal count went stale on each of them. The
/// exception worth naming instead is
/// `live_flow_cache_callsite_delegates_to_the_shared_sampler_6304`, which reads
/// source text rather than running the stage and so borrows nothing from here.
struct LiveCallSiteFixture {
    ingress_live: Arc<BindingLiveState>,
    target_live: Arc<BindingLiveState>,
    ident: BindingIdentity,
    binding_lookup: WorkerBindingLookup,
    mirror_targets: MirrorTargetMap,
    forwarding: ForwardingState,
    ha_state: BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: SharedSessionOwnerRgIndexes,
    ike_exchanges: crate::afxdp::forwarding::SharedIkeExchangeTable,
    local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    recent_exceptions: Arc<Mutex<ExceptionEventRing>>,
    last_resolution: Arc<Mutex<Option<ResolutionEvent>>>,
    peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    /// #7699: the PPTP control inbox `worker_ctx()` hands the stages. Owned by
    /// the fixture because `worker_ctx` RETURNS the context — a local would be
    /// borrowed out of the method.
    pptp_control: Arc<crate::session::pptp_control::PptpControlInbox>,
    dnat_fds: DnatTableFds,
    rg_epochs: [AtomicU32; MAX_RG_EPOCHS],
    /// #6999: an event stream for the cached filter-LOG emissions to reach.
    /// `None` on every pre-#6999 fixture, which is exactly why those two calls
    /// were severable with the whole crate green: `worker_ctx()` handed
    /// production a `None` sink, so both emissions ran to completion and
    /// produced nothing any test could look at.
    event_stream: Option<crate::event_stream::EventStreamWorkerHandle>,
    /// The receiving half of the stream above. `try_recv` takes `&self`, so it
    /// lives on the fixture rather than being threaded back out of the call.
    event_rx: Option<std::sync::mpsc::Receiver<crate::event_stream::EventFrame>>,
}

impl LiveCallSiteFixture {
    fn new(queue: MirrorTargetQueue) -> Self {
        let target_live = Arc::new(BindingLiveState::new());
        if queue == MirrorTargetQueue::CapOneEmpty {
            target_live.set_max_pending_tx(1);
        }
        if queue == MirrorTargetQueue::AtCap {
            target_live.set_max_pending_tx(1);
            assert!(
                target_live
                    .try_enqueue_tx_owned(TxRequest {
                        bytes: Vec::new(),
                        expected_ports: None,
                        expected_addr_family: 0,
                        expected_protocol: 0,
                        flow_key: None,
                        egress_ifindex: MIRROR_OUT_BIND_IFINDEX,
                        cos_queue_id: None,
                        dscp_rewrite: None,
                        mirror_clone: false,
                        overlap_admissions: None,
                        enqueue_ns: 0,
                    })
                    .is_ok(),
                "precondition: the mirror target's clone queue is driven to its cap"
            );
        }

        // The mirror target is a DIFFERENT binding, keyed — as production keys
        // it — by the PHYSICAL bind ifindex + the ingress queue id.
        let mut mirror_targets = MirrorTargetMap::default();
        mirror_targets.insert(
            &BindingIdentity {
                slot: 9,
                queue_id: 0,
                worker_id: 1,
                interface: Arc::<str>::from("mirror-out"),
                ifindex: MIRROR_OUT_BIND_IFINDEX,
            },
            target_live.clone(),
        );

        let mut forwarding = ForwardingState::default();
        // (physical 6, VLAN 80) -> logical unit 20080.
        forwarding
            .ingress_logical_ifindex
            .insert((PHYS_INGRESS_IFINDEX, INGRESS_VLAN_ID), LOGICAL_INGRESS_IFINDEX);
        // The mirror config hangs off the LOGICAL unit. Deliberately NOT also
        // registered under the physical ifindex: `resolve_mirror_config` falls
        // back to `mirror_configs[ingress_ifindex]`, and a duplicate entry
        // there would rescue a call site that ignored the VLAN id.
        forwarding.mirror_configs.insert(
            LOGICAL_INGRESS_IFINDEX,
            MirrorRuntimeConfig {
                output_ifindex: MIRROR_OUT_LOGICAL_IFINDEX,
                rate: 2,
            },
        );
        // The mirror output unit 200 binds to physical XSK port 22.
        forwarding.egress.insert(
            MIRROR_OUT_LOGICAL_IFINDEX,
            EgressInterface {
                bind_ifindex: MIRROR_OUT_BIND_IFINDEX,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x16, 0x00],
                zone_id: TEST_UNTRUST_ZONE_ID,
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );

        Self {
            event_stream: None,
            event_rx: None,
            ingress_live: Arc::new(BindingLiveState::new()),
            target_live,
            ident: BindingIdentity {
                slot: 0,
                queue_id: 0,
                worker_id: 0,
                interface: Arc::<str>::from("ge-0-0-2"),
                ifindex: PHYS_INGRESS_IFINDEX,
            },
            binding_lookup: WorkerBindingLookup::default(),
            mirror_targets,
            forwarding,
            ha_state: BTreeMap::new(),
            dynamic_neighbors: Arc::new(ShardedNeighborMap::default()),
            shared_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_owner_rg_indexes: SharedSessionOwnerRgIndexes::default(),
            ike_exchanges: Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new()),
            local_tunnel_deliveries: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            recent_exceptions: Arc::new(Mutex::new(ExceptionEventRing::new())),
            last_resolution: Arc::new(Mutex::new(None)),
            peer_worker_commands: Vec::new(),
            pptp_control: Arc::new(
                crate::session::pptp_control::PptpControlInbox::default(),
            ),
            dnat_fds: DnatTableFds::default(),
            rg_epochs: std::array::from_fn(|_| AtomicU32::new(0)),
        }
    }

    /// #6304: add the per-zone traffic-counter wiring `record_zone_traffic`
    /// needs to do anything at all.
    ///
    /// A BUILDER rather than a change to `new`, because it touches state every
    /// other cell in this module reads: registering `EGRESS_IFINDEX` in
    /// `forwarding.egress` gives the forward egress a zone and an MTU it did not
    /// have, and the ten existing cells are calibrated against the fixture
    /// without it. Only the zone-counter cell opts in.
    ///
    /// Without this, `record_zone_traffic` early-returns before touching
    /// anything: the default `ZoneCounterSlotMap` is empty so `slot_of` is 0 for
    /// the ingress zone, and `EGRESS_IFINDEX` is in no map `egress_zone_id`
    /// reads so the egress slot is 0 too — `if ingress_slot == 0 && egress_slot
    /// == 0 { return; }`. That is why deleting the call was green across the
    /// whole crate.
    ///
    /// #6722: the egress half is seeded in `ifindex_unambiguous_zone_id`, NOT
    /// in `forwarding.egress`. `ForwardingState::egress_zone_id` used to read
    /// `egress[i].zone_id`; it is now a single read of that ledger, so a
    /// fixture that populates only `egress` resolves the egress zone to the 0
    /// sentinel and the untrust row never appears. Both are written here with
    /// the SAME zone because production writes them that way —
    /// `forwarding_build::interfaces::populate_egress` sources each
    /// `EgressInterface::zone_id` from this same ledger — so the fixture stays
    /// a faithful model rather than a state the builder cannot produce.
    /// #7678: give the INGRESS interface a primary IPv4 address.
    ///
    /// `build_reject_icmp_unreachable` sources a generated ICMP reply from the
    /// ingress interface's primary address, and every stock egress entry in
    /// this fixture carries `primary_v4: None` — so without this the builder
    /// returns `None` and NOTHING is enqueued, whatever the cached descriptor
    /// says. That is a silent nothing, not an error, which is why the cell
    /// using this asserts the reply was enqueued before reading a byte of it.
    ///
    /// KEYED ON THE LOGICAL IFINDEX, NOT THE PHYSICAL ONE. `enqueue_reject_reply`
    /// resolves `resolve_ingress_logical_ifindex(forwarding, ingress_ifindex,
    /// meta.ingress_vlan_id)` BEFORE the egress lookup, and this fixture maps
    /// `(6, VLAN 80) -> 20080`. An entry keyed on `PHYS_INGRESS_IFINDEX` is
    /// therefore never consulted on a VLAN-tagged frame — measured: it leaves
    /// `pending_tx_local` empty and looks exactly like the reject branch not
    /// running at all.
    fn with_ingress_primary_v4(mut self) -> Self {
        self.forwarding.egress.insert(
            LOGICAL_INGRESS_IFINDEX,
            EgressInterface {
                bind_ifindex: PHYS_INGRESS_IFINDEX,
                vlan_id: INGRESS_VLAN_ID,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
                zone_id: TEST_TRUST_ZONE_ID,
                redundancy_group: 0,
                primary_v4: Some(Ipv4Addr::new(10, 0, 1, 1)),
                primary_v6: None,
            },
        );
        self
    }

    fn with_zone_accounting(mut self) -> Self {
        self.forwarding.egress.insert(
            EGRESS_IFINDEX,
            EgressInterface {
                bind_ifindex: PHYS_INGRESS_IFINDEX,
                vlan_id: INGRESS_VLAN_ID,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
                zone_id: TEST_UNTRUST_ZONE_ID,
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );
        // #6722: the map `egress_zone_id` actually reads. See the doc above.
        self.forwarding
            .ifindex_unambiguous_zone_id
            .insert(EGRESS_IFINDEX, TEST_UNTRUST_ZONE_ID);
        self.forwarding.zone_counter_slot_map =
            Arc::new(crate::afxdp::zone_counters::ZoneCounterSlotMap::build(
                &[TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID],
                &self.forwarding.zone_counter_store,
            ));
        self
    }

    fn worker_ctx(&self) -> WorkerContext<'_> {
        WorkerContext {
            pptp_control: &self.pptp_control,
            ident: &self.ident,
            binding_lookup: &self.binding_lookup,
            mirror_targets: &self.mirror_targets,
            forwarding: &self.forwarding,
            ha_state: &self.ha_state,
            dynamic_neighbors: &self.dynamic_neighbors,
            neighbor_resolver: None,
            shared_sessions: &self.shared_sessions,
            shared_nat_sessions: &self.shared_nat_sessions,
            shared_forward_wire_sessions: &self.shared_forward_wire_sessions,
            shared_owner_rg_indexes: &self.shared_owner_rg_indexes,
            ike_exchanges: &self.ike_exchanges,
            slow_path: None,
            event_stream: self.event_stream.as_ref(),
            local_tunnel_deliveries: &self.local_tunnel_deliveries,
            recent_exceptions: &self.recent_exceptions,
            last_resolution: &self.last_resolution,
            peer_worker_commands: &self.peer_worker_commands,
            worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
            dnat_fds: &self.dnat_fds,
            rg_epochs: &self.rg_epochs,
            cold_path_sample_mask: 0xff,
        }
    }
}

/// What one `stage_flow_cache_hit` call did, with everything the tests assert
/// on lifted out of the UMEM's lifetime.
struct StageRun {
    outcome: FlowCacheOutcome,
    /// #8262: `SessionTable::lookup_miss_counts()` after the call —
    /// `(no_handle, stale_handle, key_mismatch)`. The harness computed none of
    /// this before, so the one counter that distinguishes "the key the stage
    /// probed with is not the key the session was installed under" from every
    /// other kind of miss was unreadable from a test.
    session_lookup_miss_counts: (u64, u64, u64),
    /// #5190: the flow cache's own (hits, misses, evictions) tallies read
    /// IMMEDIATELY after the call — before the `cached_observed_bytes`
    /// probe below, whose `lookup` would itself move them.
    flow_cache_tallies: (u64, u64, u64),
    tx_pipeline: WorkerTxPipeline,
    tx_counters: WorkerTxCounters,
    scratch: WorkerScratch,
    mirror_sample_counter: u64,
    /// `telemetry.dbg` after the call. `run_stage` used to build this and drop
    /// it unread, which left `telemetry.dbg.forward += 1` / `.tx += 1` on BOTH
    /// staging arms deletable with the whole module green — an undercounted
    /// forward/tx debug counter on every successful in-place cache hit.
    dbg_forward: u64,
    dbg_tx: u64,
    /// #6304: how many times THIS call reached
    /// `try_acquire_pending_tx_admission` — the shared cross-worker CAS whose
    /// per-packet cost #6114 removed by sampling first. Zero for a packet the
    /// worker-local sampler declined; see
    /// `live_flow_cache_callsite_nonsampled_makes_no_shared_admission_attempt_6304`.
    admission_attempts: u64,
    /// #6304: the per-RX-batch accounting counters after the call. `run_stage`
    /// used to build these and drop them unread, so
    /// `forward_candidate_packets`, `snat_packets` and `dnat_packets` — all
    /// three flushed onto the operator-visible `BindingLiveState` atomics by
    /// `BatchCounters::flush` (`afxdp/mod.rs`) — were deletable with the
    /// whole module green. Bound by
    /// `live_flow_cache_callsite_accounts_forward_and_nat_packets_6304`.
    counters: BatchCounters,
    /// #6304: the bytes the in-place arm actually staged for TX, read out of
    /// the UMEM at the queued `PreparedTxRequest`'s `(offset, len)` before the
    /// mapping is dropped. `None` when nothing was staged in place.
    ///
    /// Needed because a cached descriptor and a cached DECISION can disagree —
    /// this module has been bitten by that once already — so a fixture claiming
    /// a translation has to show the translated bytes rather than assert them.
    tx_frame: Option<Vec<u8>>,
    /// #6304: the cached entry's `observed_bytes` after the call, or `None` if
    /// the entry is no longer in the cache.
    ///
    /// This is the only view of what the call site PASSED to
    /// `lookup_counted` as its byte argument. Every other caller of
    /// `lookup_counted` in the tree invokes it directly with a literal, so they
    /// bind the CALLEE's accumulation and nothing binds this call site's choice
    /// of `meta.pkt_len` — changing it to `0` leaves lookup behaviour intact and
    /// silently zeroes per-hit observed bytes. `Option` rather than a
    /// `unwrap_or(0)`: a MISSING entry must not be reported as a zero byte
    /// count, which is the mutation. See
    /// `live_flow_cache_callsite_counts_observed_bytes_on_the_hit_6304`.
    cached_observed_bytes: Option<u64>,
    /// #6997: the session table AFTER the call. `run_stage_with_entry` used to
    /// build this locally and drop it unread, which is why
    /// `sessions.account_packet(..)` and `sessions.touch_if_stale(..)` were
    /// both severable with the whole crate green — the same "built and dropped
    /// unread" shape `dbg` and `counters` were in before #6304 bound them.
    sessions: SessionTable,
}

/// Drive the LIVE call site once.
///
/// #6304 fidelity: production slices `raw_frame` straight out of the UMEM
/// (`poll_descriptor/mod.rs`: `unsafe { &*area }.slice(desc.addr, desc.len)`),
/// so `packet_frame` ALIASES the bytes `apply_rewrite_descriptor` then mutates
/// in place (TTL decrement + checksum delta). Handing a heap copy in here
/// instead would decouple the mirror clone from the rewrite and make "the
/// clone carries the PRE-rewrite frame" true for free — the
/// capture-before-rewrite ordering at `flow_cache_hit.rs` would be unbound.
/// The caller's `frame` stays pristine as the comparison value.
fn run_stage(
    fixture: &LiveCallSiteFixture,
    frame: &[u8],
    initial_sample_counter: u64,
) -> StageRun {
    let meta = test_meta(frame);
    run_stage_with_meta(fixture, frame, meta, initial_sample_counter)
}

/// `run_stage` with the shim metadata supplied explicitly, for the rollback
/// fixture — whose UMEM bytes changed AFTER the shim described them, so the
/// metadata must be the one derived from the PRISTINE frame.
fn run_stage_with_meta(
    fixture: &LiveCallSiteFixture,
    frame: &[u8],
    meta: UserspaceDpMeta,
    initial_sample_counter: u64,
) -> StageRun {
    run_stage_with_entry(fixture, frame, meta, cached_entry(), initial_sample_counter)
}

/// `run_stage_with_meta` with the cached flow-cache entry supplied explicitly,
/// so a test can vary the CACHED REWRITE DESCRIPTOR rather than the packet.
/// `live_flow_cache_callsite_accounts_vlan_pop_l2_rewrite_6304` uses it to
/// hand the same VLAN-tagged frame an UNTAGGED egress, which is the only way
/// to reach an `InPlaceL2Rewrite` variant other than `SameLength` from here.
impl LiveCallSiteFixture {
    /// #6999: attach a real event stream, with rate limiting DISABLED
    /// (`events_per_second: 0, burst: 0`) so a missing event is a missing
    /// emission and never a throttled one.
    fn with_event_stream(mut self) -> Self {
        let (handle, rx) = crate::event_stream::test_worker_handle(
            8,
            crate::event_stream::DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        );
        self.event_stream = Some(handle);
        self.event_rx = Some(rx);
        self
    }
}

/// #6997/#6999: the two knobs the call-site binders need and no pre-existing
/// test wanted, defaulted so every existing caller exercises a live backing
/// session.
///
/// `session` is the load-bearing one. Production cache hits require a backing
/// session, so the default harness seeds `test_key()`; callers that explicitly
/// need an empty table can pass `None`. Both `account_packet` and
/// `touch_if_stale` return immediately when the key resolves to nothing — so a
/// binder built on an empty fixture would stay green with those calls deleted.
struct StageSeed {
    /// Install a session for `test_key()` before the call, as
    /// `(install_ns, protocol, tcp_flags)`.
    session: Option<(u64, u8, u8)>,
    /// #7678: TX-pipeline headroom for the reject-reply budget gate.
    ///
    /// `enqueue_reject_reply` passes through `syn_cookie_reply_budget_available`,
    /// which needs BOTH `free_tx_frames.len() > SYN_COOKIE_REPLY_PENDING_RESERVE`
    /// AND `admitted < max_pending_tx - reserve`. That reserve is `TX_BATCH_SIZE`
    /// = 64, and the stock fixture carries 8 free frames with
    /// `max_pending_tx: 64` — so the gate can NEVER admit on it (8 <= 64, and
    /// `0 < 64 - 64` is false). The reply is built and then dropped at the
    /// budget gate, which is indistinguishable from the reject branch never
    /// running unless you instrument it.
    ///
    /// `None` keeps every pre-#7678 caller on the stock (8, 64) pipeline.
    tx_headroom: Option<(usize, usize)>,
    /// #7678: the `SessionFlow` handed to `stage_flow_cache_hit`, i.e. the key
    /// the stage LOOKS UP with. `None` keeps every pre-#7678 caller on
    /// `test_key()`.
    ///
    /// This seam is the whole reason a non-TCP cell was previously impossible.
    /// The stage does not derive its key from the packet — it takes
    /// `flow.forward_key` as a parameter — and this harness hardcoded that to
    /// `test_key()` (`PROTO_TCP`). So re-keying only the CACHED ENTRY to a UDP
    /// key made `entry.key != *key` in `FlowCache::lookup_with_observed_bytes`
    /// and the lookup MISSED, no matter how the frame was built. Both sides
    /// have to move together.
    flow: Option<SessionFlow>,
    /// #8262: the key the SESSION is installed under, when it must differ from
    /// the cached entry's key.
    ///
    /// Without this seam the harness cannot express a key mismatch at all: the
    /// install takes `entry_for_session.key` and the probe takes
    /// `flow.forward_key`, and both default to `test_key()` — so the fixture
    /// supplies BOTH OPERANDS OF THE COMPARISON FROM ONE VALUE and they agree
    /// by construction. That harness can vary every other axis (TX headroom,
    /// admission, mirror sampling, validation state) and never touch the one
    /// axis a key-mismatch bug lives on.
    ///
    /// `None` installs from the cached entry's key, which is every pre-#8262
    /// caller's behaviour.
    install_key: Option<crate::session::SessionKey>,
    /// The `now_ns` handed to `stage_flow_cache_hit`. Separate from
    /// `install_ns` so a cell can choose whether the session is STALE at call
    /// time, which is the only axis `touch_if_stale` branches on.
    now_ns: u64,
}

impl Default for StageSeed {
    fn default() -> Self {
        // 1_000_000 is the `now_ns` every pre-#6997 caller passed inline.
        Self {
            // Cache-hit admission now requires this backing session. Keep
            // explicit `None` available for miss-path fixtures.
            session: Some((1_000_000, PROTO_TCP, 0x10)),
            now_ns: 1_000_000,
            flow: None,
            tx_headroom: None,
            install_key: None,
        }
    }
}

fn run_stage_with_entry(
    fixture: &LiveCallSiteFixture,
    frame: &[u8],
    meta: UserspaceDpMeta,
    entry: FlowCacheEntry,
    initial_sample_counter: u64,
) -> StageRun {
    run_stage_seeded(
        fixture,
        frame,
        meta,
        entry,
        initial_sample_counter,
        StageSeed::default(),
    )
}

fn run_stage_seeded(
    fixture: &LiveCallSiteFixture,
    frame: &[u8],
    meta: UserspaceDpMeta,
    entry: FlowCacheEntry,
    initial_sample_counter: u64,
    seed: StageSeed,
) -> StageRun {
    let mut area = MmapArea::new(2 * 1024 * 1024).expect("umem mmap");
    let frame_offset: u64 = 4096;
    area.slice_mut(frame_offset as usize, frame.len())
        .expect("umem slice for the test frame")
        .copy_from_slice(frame);
    let desc = XdpDesc {
        addr: frame_offset,
        len: frame.len() as u32,
        options: 0,
    };
    let raw_frame = area
        .slice(frame_offset as usize, frame.len())
        .expect("raw frame must ALIAS the UMEM, as it does in production");

    let entry_for_session = entry.clone();
    let mut flow_state = WorkerFlowCacheState {
        flow_cache: FlowCache::new(),
    };
    flow_state.flow_cache.insert(entry);

    let mut tx_pipeline_state = tx_pipeline();
    if let Some((free_frames, max_pending)) = seed.tx_headroom {
        tx_pipeline_state.free_tx_frames = (0..free_frames as u64).collect();
        tx_pipeline_state.max_pending_tx = max_pending;
    }
    let mut tx_counters_state = tx_counters();
    let mut scratch_state = scratch();
    let mut sessions = SessionTable::new();
    if let Some((install_ns, protocol, tcp_flags)) = seed.session {
        // Install from the CACHED entry's own decision + metadata, so the
        // session the accounting lands on is the one this cached flow
        // describes rather than an unrelated fixture.
        assert!(
            sessions.install_with_protocol(
                seed
                    .install_key
                    .clone()
                    .unwrap_or_else(|| entry_for_session.key.clone()),
                entry_for_session.decision.clone(),
                entry_for_session.metadata.clone(),
                install_ns,
                protocol,
                tcp_flags,
            ),
            "fixture invalid: the seeded session did not install, so every \
             assertion about per-session accounting below would be vacuous"
        );
    }
    let mut dbg = DebugPollCounters::default();
    let mut counters = BatchCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut counters,
    };

    let flow = seed.flow.clone().unwrap_or_else(|| SessionFlow {
        src_ip: test_key().src_ip,
        dst_ip: test_key().dst_ip,
        forward_key: test_key(),
    });
    let mut owned_packet_frame: Option<Vec<u8>> = None;
    let mut mirror_sample_counter = initial_sample_counter;

    // #6304: measure only THIS call. The fixture's own setup pushes (the AtCap
    // precondition, the interleaving-producer probes) go through the same
    // admission primitive, so the reset has to sit immediately before the call
    // and the read immediately after it.
    crate::afxdp::binding_state::pending_tx_admission_attempts_reset();
    let outcome = stage_flow_cache_hit(
        &mut flow_state,
        &mut tx_pipeline_state,
        &mut tx_counters_state,
        &mut scratch_state,
        &mut mirror_sample_counter,
        &fixture.ingress_live,
        0,
        BINDING_INDEX,
        desc,
        &area as *const MmapArea,
        raw_frame,
        &mut owned_packet_frame,
        meta,
        &flow,
        false,
        ValidationState::default(),
        &mut sessions,
        seed.now_ns,
        1,
        &fixture.worker_ctx(),
        &mut telemetry,
    );
    let admission_attempts = crate::afxdp::binding_state::pending_tx_admission_attempts();
    // #5190: snapshot the cache tallies BEFORE the observed-bytes probe
    // below — that probe calls `lookup`, which bumps hits/misses itself.
    let flow_cache_tallies = (
        flow_state.flow_cache.hits,
        flow_state.flow_cache.misses,
        flow_state.flow_cache.evictions,
    );
    // #6304: lift the staged TX bytes out of the UMEM before the mapping dies
    // with this function's frame.
    let tx_frame = tx_pipeline_state
        .pending_tx_prepared
        .front()
        .and_then(|prepared| area.slice(prepared.offset as usize, prepared.len as usize))
        .map(<[u8]>::to_vec);
    // #6304: read the hit entry's accumulated byte count back out. The
    // `#[cfg(test)]` `lookup` is the ZERO-adding variant of the same
    // `lookup_with_observed_bytes` body, so this read cannot itself move the
    // number it is reporting.
    let cached_observed_bytes = flow_state
        .flow_cache
        .lookup(
            &flow.forward_key,
            FlowCacheLookup::for_packet(meta, ValidationState::default(), &fixture.forwarding),
            1,
            &fixture.rg_epochs,
        )
        .map(|entry| entry.observed_bytes);

    StageRun {
        outcome,
        session_lookup_miss_counts: sessions.lookup_miss_counts(),
        flow_cache_tallies,
        tx_pipeline: tx_pipeline_state,
        tx_counters: tx_counters_state,
        scratch: scratch_state,
        mirror_sample_counter,
        dbg_forward: dbg.forward,
        dbg_tx: dbg.tx,
        admission_attempts,
        counters,
        tx_frame,
        cached_observed_bytes,
        sessions,
    }
}

/// #6304 FAIL-ON-REVERT (live call site): a NON-sampled packet on the
/// established-flow HOT path must not produce, reserve for, or account a
/// mirror clone.
///
/// The target here has ROOM. That is deliberate and load-bearing: with the
/// target AT CAP (the pre-fold fixture) `try_acquire_pending_tx_admission`
/// bails at its relaxed `admitted >= admission_cap` load before the
/// `compare_exchange_weak(AcqRel)` ever executes, so a zero drop counter was
/// satisfied by the queue being full rather than by the packet being declined
/// — the assertion could not tell the two apart. With room, a call site that
/// DROPS the sampler and clones unconditionally lands a real frame on the
/// target and the queue assertion below fails.
///
/// Scope, precisely: that is the mutation this cell distinguishes. A call site
/// that still consults the sampler but consults it AFTER reserving — taking an
/// admission and handing it back on `NotSampled` — enqueues nothing and passes
/// every assertion here. See
/// `live_flow_cache_callsite_delegates_to_the_shared_sampler_6304` for what
/// covers that mutation and what it does not.
///
/// The mirror result is recorded ONLY inside the successful in-place-rewrite
/// branch, so the positive controls are load-bearing too: without them a
/// fixture whose rewrite silently failed would report 0 under both the correct
/// and the reverted call site — a test that looks bound and is not.
#[test]
fn live_flow_cache_callsite_nonsampled_produces_no_clone_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    // rate = 2 with counter = 1 -> `mirror_sample_allows` is FALSE.
    let run = run_stage(&fixture, &frame, 1);

    // --- POSITIVE CONTROLS: the fixture actually reached the recording point.
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must be consumed by the fast path"
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED — this is the \
         branch the mirror result is recorded in"
    );
    assert_eq!(
        run.tx_pipeline.pending_tx_prepared.len(),
        1,
        "control: the rewritten frame must be queued for TX"
    );

    // --- THE #6304 DISCRIMINATOR: nothing mirror-shaped happened at all.
    let mut queued = VecDeque::new();
    fixture.target_live.take_pending_tx_into(&mut queued);
    assert!(
        queued.is_empty(),
        "#6304: a NON-sampled packet must not enqueue a clone on the mirror \
         target — the target had ROOM, so a call site that DROPPED the sampler \
         and cloned unconditionally lands a real frame here. (Reserve-before- \
         sample does NOT land one: it still consults the sampler and hands the \
         reservation back, which is why that mutation needs the attempt count.)"
    );
    assert_eq!(
        fixture.ingress_live.mirrored_packets.load(Ordering::Relaxed),
        0,
        "#6304: and it must not be accounted as mirrored"
    );
    assert_eq!(
        fixture
            .ingress_live
            .mirror_drops_queue_full
            .load(Ordering::Relaxed),
        0,
        "#6304: a non-sampled packet must not report clone-queue pressure"
    );
    assert_eq!(
        fixture
            .ingress_live
            .mirror_drops_no_binding
            .load(Ordering::Relaxed),
        0,
        "#6304: nor a resolution failure it never attempted"
    );
    // The worker-local sampler still advances for the declined packet
    // (committed because the rewrite succeeded).
    assert_eq!(
        run.mirror_sample_counter, 2,
        "the worker-local sampler advances for the declined packet"
    );
}

/// #6304 companion (SELECTED arm, full queue): the test above pins
/// `mirror_sample_counter = 1` at `rate = 2`, so `mirror_sample_allows` is
/// FALSE and `MirrorSampleAdmission::NotSampled` short-circuits — everything
/// downstream of `Sampled(..)` at the live call site is left unbound by it.
/// Two mutations confirmed that firsthand, both leaving `mirror/resolver.rs`
/// byte-identical and the whole suite green:
///   - commit `mirror_next_counter` on `NotSampled`/`Sampled(Ok)` but NOT on
///     `Sampled(Err)` — the exact behavior #6114 adjudicated a bug. Under
///     sustained clone-queue pressure the hot path pins itself at the sampler's
///     first slot and hammers the shared `pending_tx_admitted` CAS at O(PPS)
///     instead of O(PPS/R).
///   - `Sampled(Ok(_)) => None` — every selected packet silently drops its
///     clone; port mirroring stops delivering on this path entirely.
///
/// This test binds the first: a SELECTED packet on a FULL cross-worker target
/// advances the sampler and THEN reports the pressure (#6114's sample-first
/// intent resolution), at the LIVE call site rather than through the dead
/// wrapper.
///
/// It also makes the mirror WIRING a standing assertion rather than a one-time
/// observation. Asserting a NON-zero `mirror_drops_queue_full_cross_worker`
/// fails loudly if the fixture ever stops reaching a resolved, cross-worker,
/// genuinely full target.
#[test]
fn live_flow_cache_callsite_selected_full_queue_advances_sampler_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::AtCap);
    let frame = tcp_v4_ack_frame();
    // rate = 2 with counter = 0 -> selected, so it reaches admission.
    let run = run_stage(&fixture, &frame, 0);

    // --- POSITIVE CONTROLS (same rationale as the non-sampled test).
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must be consumed by the fast path"
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED — this is the \
         branch the mirror result is recorded in"
    );
    assert_eq!(
        run.tx_pipeline.pending_tx_prepared.len(),
        1,
        "control: the rewritten frame must be queued for TX"
    );

    // --- WIRING, asserted rather than merely observed. A `NoBinding`
    // short-circuit — which is what dropping the `output_ifindex` resolution
    // produces — would read 0 here.
    assert_eq!(
        fixture
            .ingress_live
            .mirror_drops_queue_full
            .load(Ordering::Relaxed),
        1,
        "#6304: a SELECTED packet on a full cross-worker clone queue reports the \
         pressure; reading 0 means the fixture never reached a genuinely full \
         cross-worker target"
    );
    assert_eq!(
        fixture
            .ingress_live
            .mirror_drops_queue_full_cross_worker
            .load(Ordering::Relaxed),
        1,
        "#6304: and the pressure is attributed to the CROSS-WORKER counter"
    );

    // --- THE DISCRIMINATOR: sample-first means the sampler advanced BEFORE the
    // admission failed. Re-introducing the #6114-adjudicated bug at this call
    // site (commit the local counter on NotSampled/Sampled(Ok) but not on
    // Sampled(Err)) leaves it at 0.
    assert_eq!(
        run.mirror_sample_counter, 1,
        "#6304: the SELECTED packet advances the sampler before the full-queue \
         admit fails; deferring the commit on Sampled(Err) pins the hot path at \
         the sampler's first slot and restores the O(PPS) shared-CAS hit"
    );
    assert_eq!(
        fixture.ingress_live.mirrored_packets.load(Ordering::Relaxed),
        0,
        "a clone that was never admitted must not be counted as mirrored"
    );
}

/// #6304 companion (SELECTED arm, admittable target): binds the
/// `MirrorSampleAdmission::Sampled(Ok(..))` arm of the LIVE call site, which
/// the full-queue test never reaches. Mutating `Sampled(Ok(_)) => None` (every
/// selected packet silently drops its clone; port mirroring stops delivering
/// on this path) is green without it.
///
/// This is also the test that binds BOTH live-call-site resolutions, because
/// each collapses the clone to nothing:
///   - dropping `meta.ingress_vlan_id` from the `resolve_mirror_config` call
///     resolves logical unit 20080 -> nothing, so no mirror config is found
///     and no clone is emitted;
///   - passing `config.output_ifindex` (logical 200) to admission instead of
///     resolving it to the physical bind port 22 makes `MirrorTargetMap`
///     report `NoBinding`.
#[test]
fn live_flow_cache_callsite_selected_admitted_clone_reaches_target_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let run = run_stage(&fixture, &frame, 0);

    // --- POSITIVE CONTROLS.
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must be consumed by the fast path"
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED — this is the \
         branch the mirror clone is enqueued in"
    );

    // --- THE DISCRIMINATOR: the admitted clone must actually be delivered.
    assert_eq!(
        fixture.ingress_live.mirrored_packets.load(Ordering::Relaxed),
        1,
        "#6304: a SELECTED packet whose cross-worker target has room must have \
         its clone enqueued; dropping the Sampled(Ok) arm silently stops port \
         mirroring, and so does resolving either the ingress VLAN unit or the \
         mirror output ifindex incorrectly"
    );
    assert_eq!(
        fixture.ingress_live.mirrored_bytes.load(Ordering::Relaxed),
        frame.len() as u64,
        "#6304: the full-L2 frame length is accounted to the mirror byte counter"
    );
    assert_eq!(
        fixture
            .ingress_live
            .mirror_drops_no_binding
            .load(Ordering::Relaxed),
        0,
        "#6304: the mirror output unit resolves to a bound XSK port; a NoBinding \
         here means `config.output_ifindex` reached admission unresolved"
    );
    assert_eq!(
        fixture
            .ingress_live
            .mirror_drops_queue_full
            .load(Ordering::Relaxed),
        0,
        "an admittable target must not report clone-queue pressure"
    );
    assert_eq!(
        run.mirror_sample_counter, 1,
        "the sampler advances for the selected packet"
    );

    // The clone is a real full-L2 copy on the TARGET binding's queue, flagged
    // as a mirror clone and addressed to the mirror output interface.
    let mut queued = VecDeque::new();
    fixture.target_live.take_pending_tx_into(&mut queued);
    let clone = queued.pop_front().expect("the mirror clone must be queued");
    assert!(
        clone.mirror_clone,
        "the queued request must be flagged as a mirror clone"
    );
    assert_eq!(
        clone.egress_ifindex, MIRROR_OUT_LOGICAL_IFINDEX,
        "the clone egresses the mirror output interface"
    );
    assert_eq!(
        clone.bytes, frame,
        "the clone carries the full L2 frame verbatim, tag included, captured \
         BEFORE the in-place rewrite mutated the UMEM"
    );
    assert!(
        queued.is_empty(),
        "exactly one clone — the rewritten original goes out the ingress binding"
    );
}

/// #6304 (rewrite-failure rollback): sampling and admission run BEFORE the
/// in-place rewrite, but the sampler commit and the clone delivery are
/// deliberately deferred until the rewrite succeeds. Hoisting
///
///     if let Some(next_counter) = mirror_next_counter { *mirror_sample_counter = next_counter; }
///
/// above the `if let Some(rewrite_result)` check is green everywhere else in
/// the module: the DECLINED rewrite is the only state that can tell a committed
/// sampler from a rolled-back one, and this cell and the fallback arms of
/// `..._leaves_no_admission_stranded_on_target_6304` /
/// `..._accounts_debug_forward_and_tx_6304` are the only three places a rewrite
/// declines at all — and of those three, only this one reads the sampler.
/// (An earlier revision said "every other test requires a SUCCESSFUL rewrite …
/// green under all three", which was a count of the module as it stood then and
/// was wrong on both halves once the fallback arms were added.)
///
/// Here BOTH in-place rewriters decline and the packet takes the
/// `PendingForwardRequest` fallback, where `tx/dispatch` re-runs mirror
/// selection from scratch. Committing the sampler on this path would consume a
/// sampling slot for a packet this call site never mirrored, so the flow's
/// effective mirror rate silently halves whenever the fast path is missing.
///
/// The decline is driven by an IPv4 header whose IHL (15 -> 60 bytes) overruns
/// the 40-byte L3 payload. Both rewriters gate on exactly that, and both do so
/// BEFORE their first UMEM write (`validate_rewrite_descriptor_ipv4` for the
/// descriptor path, `validate_generic_rewrite_v4` for the generic one), so the
/// frame is still pristine when the fallback re-reads it — the #4965/#5466
/// preflight-then-commit contract. A port mismatch does NOT work here: the
/// generic path REPAIRS ports via `restore_l4_tuple_from_meta` /
/// `enforce_expected_ports` rather than declining, so only the descriptor path
/// would bail.
///
/// That decline is reachable ONLY for a frame whose bytes changed after the
/// shim described them, which is what `dma_raced_short_ihl_frame` builds and
/// documents — the metadata passed here is therefore the PRISTINE frame's, the
/// one the shim actually emitted.
#[test]
fn live_flow_cache_callsite_rewrite_failure_rolls_back_sampler_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let pristine = tcp_v4_ack_frame();
    let frame = dma_raced_short_ihl_frame();
    // rate = 2 with counter = 0 -> SELECTED, so the sampler has something to
    // roll back and admission is genuinely taken and released.
    let run = run_stage_with_meta(&fixture, &frame, test_meta(&pristine), 0);

    // --- POSITIVE CONTROLS: the packet really did take the fallback, and it
    // took it because the rewrite declined rather than because the flow-cache
    // lookup missed.
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must still be consumed by the fast path"
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 0,
        "control: BOTH in-place rewriters must have declined — if either had \
         succeeded this test would be re-asserting the committed path"
    );
    assert_eq!(
        run.scratch.scratch_forwards.len(),
        1,
        "control: the packet falls through to the PendingForwardRequest path, \
         where tx/dispatch re-runs mirror selection"
    );
    assert!(
        run.scratch.scratch_recycle.is_empty(),
        "control: the fallback owns the frame, so it is not recycled here"
    );

    // --- THE DISCRIMINATOR: nothing about the abandoned mirror decision
    // survives. Hoisting the sampler commit above the rewrite check leaves
    // this at 1.
    assert_eq!(
        run.mirror_sample_counter, 0,
        "#6304: a mirror decision taken before a rewrite that then declined must \
         NOT advance the worker-local sampler — the fallback path re-runs mirror \
         selection, so committing here consumes a sampling slot for a clone this \
         call site never emitted"
    );

    // ...and no clone was delivered or accounted on the way out.
    let mut queued = VecDeque::new();
    fixture.target_live.take_pending_tx_into(&mut queued);
    assert!(
        queued.is_empty(),
        "#6304: the reserved admission is released, not spent — no clone reaches \
         the target from the declined fast path"
    );
    assert_eq!(
        fixture.ingress_live.mirrored_packets.load(Ordering::Relaxed),
        0,
        "#6304: and nothing is accounted as mirrored"
    );
}

/// #6304 (call-site delegation canary). Inlining `admit_mirror_clone_to_live`
/// above the sampler at this call site and discarding the reservation when the
/// sampler declines is INDISTINGUISHABLE to a single-threaded observer of one
/// completed invocation: the reservation is taken with an AcqRel CAS and given
/// straight back by `PendingTxAdmission::drop` before the call returns, so
/// every counter, queue and frame this module can read afterwards is
/// unchanged. Verified firsthand — the mutation compiles and every behavioural
/// test in this module stays green.
///
/// That is a statement about what a COMPLETED call leaves behind, and nothing
/// more. The ordering is genuinely observable to a CONCURRENT producer: while
/// the transient reservation is held, the target's `pending_tx_admitted` is one
/// higher, so another worker pushing to the same mirror target sees the queue
/// full and its request is dropped —
/// `mirror/mod_tests.rs::live_mirror_admission_reserves_slot_against_interleaving_producer`
/// demonstrates exactly that exclusion. Reserve-first can therefore lose a
/// second producer's clone that sample-first would have admitted. The earlier
/// claim that no behavioural test COULD catch this mutation was a scope error:
/// state created and destroyed inside one call is invisible to that call by
/// construction, and visible to anyone racing it.
///
/// THE WINDOW itself is still not observed here, and cannot be observed
/// deterministically: it is a pair of atomic RMWs entirely inside
/// `stage_flow_cache_hit`, with no production hook a test could synchronise
/// against, so a racing-producer test would have to catch it open and would
/// fail only probabilistically — a flake, not a binding.
///
/// DETECTING THE MUTATION is strictly weaker than observing the window, and it
/// IS deterministic — `live_flow_cache_callsite_nonsampled_makes_no_shared_admission_attempt_6304`
/// now does it, so the ordering no longer rests on this source-text canary. It
/// counts calls into `try_acquire_pending_tx_admission`
/// (`afxdp/binding_state/tx_inbox.rs`) via a `#[cfg(test)]` THREAD-LOCAL —
/// deliberately not a `#[cfg(test)]` field on `BindingLiveState`, which would
/// change the layout of the very struct whose cross-core cacheline behaviour
/// #6114 exists to fix. A thread-local lives in its own storage, and FOUR
/// pinned values of that struct — size, align and two field offsets — are
/// measured unmoved with and without it, in both build configurations
/// (`binding_state/mod.rs`). That is a tripwire on the one hazard, NOT a claim
/// that the struct is byte-identical: its other ~90 fields are unpinned. Unlike
/// a process-global atomic, a thread-local also stays deterministic under the
/// default parallel `cargo test`.
///
/// Bound alongside it are the two properties either side of the window:
///   - the reservation the call site takes is externally visible and must be
///     handed back, not stranded —
///     `live_flow_cache_callsite_leaves_no_admission_stranded_on_target_6304`;
///   - the call site does not open-code the reservation at all, which is what
///     this canary pins. `sample_then_admit_mirror_clone` is the single home
///     for the #6114 ordering invariant, so going through it inherits the
///     ordering rather than restating it.
///
/// Limits of the canary itself, enumerated so the list is not mistaken for
/// completeness it does not have. It is source text, not a runtime
/// observation, and it would need updating if the helper is legitimately
/// renamed. It does NOT catch a reserve-before-sample rewrite INSIDE the shared
/// helper — one that reserved first and suppressed on a sampler decline keeps
/// the required spelling and avoids the forbidden one. Nor does it catch the
/// RENAME escape at the import — `use ...::admit_mirror_clone_to_live as
/// admit;` then `admit(...)` calls the reservation directly while the forbidden
/// spelling never appears in this file. Both of those are caught by the
/// attempt-count test named above, which observes the runtime call rather than
/// the source text; this canary is retained because it localises the failure to
/// "the call site stopped delegating" instead of leaving only a counter
/// mismatch to diagnose.
#[test]
fn live_flow_cache_callsite_delegates_to_the_shared_sampler_6304() {
    let src = include_str!("flow_cache_hit.rs");
    assert!(
        src.contains("sample_then_admit_mirror_clone("),
        "#6304: stage_flow_cache_hit must reach the mirror clone queue through \
         `sample_then_admit_mirror_clone`, the single home of the #6114 \
         sample-before-reserve ordering"
    );
    assert!(
        !src.contains("admit_mirror_clone_to_live("),
        "#6304: stage_flow_cache_hit must NOT call `admit_mirror_clone_to_live` \
         directly — open-coding the reservation at this call site reintroduces \
         the O(PPS) cross-core true-sharing #6114 removed, and — for a single \
         completed invocation — without changing any observable counter"
    );
}

/// #6304 FAIL-ON-REVERT for the #6114 ORDERING itself, at the live call site.
///
/// This is the cell the delegation canary above could not be: a runtime
/// observation rather than a source-text one, so it catches reserve-first in
/// EVERY spelling — open-coded at the call site, reached through a renamed
/// import, or rewritten inside `sample_then_admit_mirror_clone`, which is the
/// form nothing in the tree caught before.
///
/// What makes the mutation hard to see, restated so the instrument's shape is
/// justified rather than assumed. Reserve-first and sample-first leave a
/// COMPLETED call indistinguishable: the reservation is taken with an AcqRel
/// CAS and given straight back by `PendingTxAdmission::drop` before the call
/// returns, and the refusal path passes `record_overflow = false`
/// (`try_reserve_mirror_tx_owned`) so even a reservation that FAILS bumps no
/// counter. Net zero on `pending_tx_admitted`, no telemetry, same queue, same
/// sampler. The real difference is the transient — the O(PPS) cross-core
/// true-sharing #6114 removed — and that is visible only to a racing producer,
/// i.e. only probabilistically.
///
/// Counting the ATTEMPT is the deterministic weakening: the mutant must call
/// the admission primitive for a declined packet whatever it then does with the
/// result. See `pending_tx_admission_attempts` in
/// `afxdp/binding_state/tx_inbox.rs` for why the counter is a thread-local and
/// not a `#[cfg(test)]` field on `BindingLiveState` (four pinned layout values
/// on the exact struct #6114 is about, measured unmoved — not whole-struct
/// neutrality) and not a process-global atomic (determinism
/// under the default parallel `cargo test`).
///
/// The target has ROOM in the declined arm, and that is load-bearing: at cap
/// the mutant's reservation would be refused, so a test asserting on the
/// OUTCOME could not tell a refused reservation from one never attempted. The
/// instrument bumps BEFORE the cap load for the same reason — it must measure
/// call ordering, not queue depth, which the third cell pins.
#[test]
fn live_flow_cache_callsite_nonsampled_makes_no_shared_admission_attempt_6304() {
    // --- THE DISCRIMINATOR: rate = 2 with counter = 1 -> the sampler declines,
    // and nothing may reach the mirror target's shared admission counter.
    let declined = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let run = run_stage(&declined, &tcp_v4_ack_frame(), 1);
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED — the mirror \
         arm this measures runs only inside that branch"
    );
    assert_eq!(
        run.admission_attempts, 0,
        "#6304/#6114: a packet the worker-local sampler DECLINED must not touch \
         the mirror target's shared `pending_tx_admitted` at all. Reserving \
         first and handing the reservation back on decline restores exactly the \
         O(PPS) cross-core true-sharing #6114 removed, while leaving every \
         counter, queue and admission count this module can read unchanged"
    );

    // --- POSITIVE CONTROL: a SELECTED packet makes exactly ONE attempt. Without
    // it a zero above would also be satisfied by an unwired instrument, or by a
    // fixture that never resolves a mirror target at all; and the exact count
    // pins that the call site reserves ONCE, not once per resolution step.
    let selected = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let run = run_stage(&selected, &tcp_v4_ack_frame(), 0);
    assert_eq!(
        selected
            .ingress_live
            .mirrored_packets
            .load(Ordering::Relaxed),
        1,
        "control: the selected packet's clone is admitted and enqueued"
    );
    assert_eq!(
        run.admission_attempts, 1,
        "#6304: a SELECTED packet reserves on the mirror target exactly once"
    );

    // --- AT CAP: still exactly one attempt. This is what makes the declined
    // arm's zero mean "never asked" rather than "asked and was refused" — the
    // instrument counts the call, not its outcome.
    let full = LiveCallSiteFixture::new(MirrorTargetQueue::AtCap);
    let run = run_stage(&full, &tcp_v4_ack_frame(), 0);
    assert_eq!(
        full.ingress_live
            .mirror_drops_queue_full_cross_worker
            .load(Ordering::Relaxed),
        1,
        "control: the reservation was genuinely attempted and refused by a full \
         cross-worker target"
    );
    assert_eq!(
        run.admission_attempts, 1,
        "#6304: a refused reservation is still an ATTEMPT — the instrument \
         measures call ordering, not queue depth"
    );
}

/// #6304 (shared-capacity accounting). The mirror target's
/// `pending_tx_admitted` is not private bookkeeping: every OTHER producer of
/// that binding is gated on it, so an admission this call site holds is an
/// admission nobody else can use. `mirror/mod_tests.rs::
/// live_mirror_admission_reserves_slot_against_interleaving_producer` pins the
/// mechanism; this pins the consequence at the LIVE call site — after
/// `stage_flow_cache_hit` returns, the only capacity still consumed is
/// capacity a real clone occupies.
///
/// Driven at a soft cap of exactly ONE slot, so a single stranded admission is
/// the difference between an interleaving producer being served and being
/// dropped. The `admitted` cell is the positive control: it proves the cap is
/// genuinely binding, so the two `is_ok()` cells below are informative rather
/// than vacuously true of an unbounded queue.
///
/// This does NOT cover the transient reserve-then-release window (see
/// `live_flow_cache_callsite_delegates_to_the_shared_sampler_6304`); a call
/// site that reserved before sampling and correctly dropped the reservation
/// passes every cell here. What it does cover is the whole class where the
/// reservation is taken and never handed back — the sampler declines but the
/// admission outlives the call, or the rewrite declines but the rollback leaks
/// it — each of which silently shrinks the mirror target's usable clone queue
/// for every worker feeding it.
///
/// Not in that class, though an earlier revision of this comment listed it: a
/// `Sampled(Err(..))` admission. That arm carries a `MirrorCloneResult`, not a
/// token — the reservation FAILED, so there is nothing to release — and an
/// enqueue error on an admission that WAS granted keeps the token owned, so
/// `PendingTxAdmission::drop` releases it. Neither shape can strand a slot.
#[test]
fn live_flow_cache_callsite_leaves_no_admission_stranded_on_target_6304() {
    // --- NON-SAMPLED: rate = 2, counter = 1 -> declined by the sampler.
    let declined = LiveCallSiteFixture::new(MirrorTargetQueue::CapOneEmpty);
    let run = run_stage(&declined, &tcp_v4_ack_frame(), 1);
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED"
    );
    assert!(
        declined
            .target_live
            .try_enqueue_tx_owned(probe_tx_request())
            .is_ok(),
        "#6304: a non-sampled packet must leave the mirror target's single \
         admission slot free for another producer"
    );

    // --- SELECTED but the rewrite declines: the admission is taken for real
    // and must be released on the rollback path.
    let rolled_back = LiveCallSiteFixture::new(MirrorTargetQueue::CapOneEmpty);
    let pristine = tcp_v4_ack_frame();
    let run = run_stage_with_meta(
        &rolled_back,
        &dma_raced_short_ihl_frame(),
        test_meta(&pristine),
        0,
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 0,
        "control: both in-place rewriters must have declined"
    );
    assert!(
        rolled_back
            .target_live
            .try_enqueue_tx_owned(probe_tx_request())
            .is_ok(),
        "#6304: the admission reserved before a rewrite that then declined must \
         be RELEASED — stranding it permanently shrinks the mirror target's \
         clone queue by one slot per declined packet"
    );

    // --- POSITIVE CONTROL: the cap really is one slot. A SELECTED packet whose
    // clone IS admitted occupies it, and the same probe now fails; draining the
    // owner side gives the slot back.
    let admitted = LiveCallSiteFixture::new(MirrorTargetQueue::CapOneEmpty);
    let run = run_stage(&admitted, &tcp_v4_ack_frame(), 0);
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED"
    );
    assert_eq!(
        admitted.ingress_live.mirrored_packets.load(Ordering::Relaxed),
        1,
        "control: the clone must have been admitted and enqueued"
    );
    assert!(
        admitted
            .target_live
            .try_enqueue_tx_owned(probe_tx_request())
            .is_err(),
        "control: a soft cap of one slot is genuinely binding — an ADMITTED \
         clone excludes the interleaving producer, which is what makes the two \
         `is_ok()` assertions above meaningful"
    );
    let mut queued = VecDeque::new();
    admitted.target_live.take_pending_tx_into(&mut queued);
    assert_eq!(queued.len(), 1, "control: the drained request is the clone");
    assert!(
        admitted
            .target_live
            .try_enqueue_tx_owned(probe_tx_request())
            .is_ok(),
        "control: draining the owner side releases the admission again"
    );
}

/// A stand-in for another worker pushing to the same mirror target.
fn probe_tx_request() -> TxRequest {
    TxRequest {
        bytes: vec![0x5a; 64],
        expected_ports: None,
        expected_addr_family: 0,
        expected_protocol: 0,
        flow_key: None,
        egress_ifindex: MIRROR_OUT_BIND_IFINDEX,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    }
}

/// #6304 (over-reach guard / domain parity). The SELF-CONSISTENT counterpart of
/// the rollback fixture: an IPv4 header that honestly declares IHL 15, carries
/// 40 bytes of NOP options, and whose `total_len`, frame length and metadata
/// offsets all agree — i.e. exactly what `parse_ipv4` in the shim would deliver.
///
/// It must take the in-place path and COMMIT the sampler. That is the load
/// bearing half: it proves the rollback fixture's decline comes from the frame
/// having CHANGED after parse, not from "IHL 15" being intrinsically
/// unrewritable, and so proves the claim
/// `dma_raced_short_ihl_frame` makes about reachability rather than asserting
/// it. It also guards the option-carrying geometry itself — a rewrite that
/// assumed a fixed 20-byte IPv4 header would read the L4 ports out of the
/// option block and bail the DMA-race gate here.
///
/// Stays GREEN under every #6304 sampler revert — reserve-before-sample,
/// deferring the commit on `Sampled(Err)`, dropping the `Sampled(Ok)` arm,
/// hoisting the commit above the rewrite check, and leaking the reservation —
/// measured, not assumed. It is not inert, though: the sampler-commit
/// assertion below needs the mirror config to resolve, so it joins the
/// ingress-VLAN wiring binding and reds if that resolution is dropped.
#[test]
fn live_flow_cache_callsite_ip_options_frame_takes_the_in_place_path_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    // IHL 15: 10 option words on top of the 20-byte base header.
    let frame = vlan_tagged_tcp_v4_frame(10);
    assert_eq!(frame.len(), 98, "18 L2 + 60 IPv4 (options) + 20 TCP");
    assert_eq!(frame[18] & 0x0f, 15, "the IHL nibble the rollback frame fakes");
    let run = run_stage(&fixture, &frame, 0);

    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "the cached flow must be consumed by the fast path"
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "#6304 domain parity: a SELF-CONSISTENT IHL-15 frame rewrites in place. \
         The rollback fixture declines because its bytes changed after the shim \
         described them — not because a long IPv4 header cannot be rewritten"
    );
    assert!(
        run.scratch.scratch_forwards.is_empty(),
        "and it does not take the PendingForwardRequest fallback"
    );
    assert_eq!(
        run.mirror_sample_counter, 1,
        "the sampler commits on the successful-rewrite path"
    );
}

/// #6304 (staging telemetry). Both staging arms bump the debug forward/tx
/// counters — the in-place arm at the end of the successful-rewrite branch, the
/// fallback arm after `build_live_forward_request_from_frame` succeeds. Neither
/// was read by any test, so both increments were deletable with the module
/// green: an undercounted forward-debug metric on whichever arm was cut.
///
/// Scope, stated exactly rather than as "every cache hit": both increments sit
/// INSIDE the forwarding disposition arm and after successful staging, so a hit
/// that never reaches them — a cached terminal drop or a red policer (which
/// return above), a TTL-expired packet (diverted to Time Exceeded), a
/// LocalDelivery/Discard disposition, or a fallback whose builder returned
/// `None` — is not undercounted by the deletion because it never counted.
/// What regresses is every established-flow hit that FORWARDS, which on a
/// long-lived permitted flow is nearly all of them.
#[test]
fn live_flow_cache_callsite_accounts_debug_forward_and_tx_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let in_place = run_stage(&fixture, &tcp_v4_ack_frame(), 0);
    assert_eq!(
        in_place.tx_counters.pending_in_place_tx_packets, 1,
        "control: this is the in-place arm"
    );
    assert_eq!(
        in_place.dbg_forward, 1,
        "#6304: the in-place staging arm accounts one forwarded packet"
    );
    assert_eq!(
        in_place.dbg_tx, 1,
        "#6304: ...and one TX, on the same arm"
    );

    let fallback = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let pristine = tcp_v4_ack_frame();
    let run = run_stage_with_meta(
        &fallback,
        &dma_raced_short_ihl_frame(),
        test_meta(&pristine),
        0,
    );
    assert_eq!(
        run.scratch.scratch_forwards.len(),
        1,
        "control: this is the PendingForwardRequest fallback arm"
    );
    assert_eq!(
        run.dbg_forward, 1,
        "#6304: the fallback staging arm accounts one forwarded packet too"
    );
    assert_eq!(run.dbg_tx, 1, "#6304: ...and one TX");
}

/// #6304 (staging telemetry, second line). The
/// `record_in_place_l2_rewrite(rewrite_result.l2_rewrite)` call sits two lines
/// above the debug counters bound just above, on a rationale that applies to
/// it verbatim — and it was deletable with the WHOLE CRATE green (4283 passed
/// / 0 failed / 2 ignored plus every integration target, measured), not merely
/// with the #6304 guards green.
///
/// The reason is a fixture property rather than an oversight in the assertions:
/// every other frame here egresses on the same VLAN it arrived on, so
/// `eth_len == current_l3 == 18`, the classification is
/// `InPlaceL2Rewrite::SameLength`, and THAT arm of
/// `record_in_place_l2_rewrite` is an empty block. The call ran on every
/// fixture and could not be observed by any of them. Nothing else in the tree
/// asserted `pending_in_place_vlan_push_desc_packets` or
/// `_pop_desc_packets` either, so deleting the call cost nothing anywhere.
///
/// Handing the same tagged frame an UNTAGGED egress makes the call
/// load-bearing: the tag is popped by sliding the TX descriptor 4 bytes forward
/// inside the same UMEM frame, `classify_in_place_l2_rewrite` returns
/// `VlanPopDescriptor`, and the operator-visible
/// `pending_in_place_vlan_pop_desc_packets` — drained to `BindingLiveState` on
/// the per-second debug tick — must move.
///
/// The three sibling counters are asserted ZERO as well, so the cell binds the
/// CLASSIFICATION and not merely "some counter advanced". Measured: rewiring
/// the `VlanPopDescriptor` arm of `record_in_place_l2_rewrite` to bump the PUSH
/// counter instead reds this cell and no other #6304 guard — re-measured at the
/// round-3 head rather than carried forward, since the module has grown twice
/// since the first measurement and the original note pinned a literal count
/// ("the other nine") that went stale immediately. Hardcoding the ARGUMENT to
/// `SameLength` at the call site collapses onto the deletion mutation — that arm
/// is an empty block, so the pop counter stays at 0 either way.
#[test]
fn live_flow_cache_callsite_accounts_vlan_pop_l2_rewrite_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    // rate = 2 with counter = 1 -> NOT sampled: this cell is about the L2
    // rewrite accounting, so the mirror block stays out of the way.
    let run = run_stage_with_entry(
        &fixture,
        &frame,
        test_meta(&frame),
        untagged_egress_entry(),
        1,
    );

    // --- POSITIVE CONTROLS: the in-place arm ran, and it genuinely popped the
    // tag rather than taking the same-length path with a different label.
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must be consumed by the fast path"
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED — this is \
         the branch that records the L2 rewrite classification"
    );
    let prepared = run
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("control: the rewritten frame must be queued for TX");
    assert_eq!(
        prepared.len as usize,
        frame.len() - 4,
        "control: the TRANSMITTED extent is 4 bytes shorter than the ingress \
         frame — the 802.1Q tag really was popped, so `VlanPopDescriptor` is \
         the honest classification rather than a relabelled no-op"
    );

    // --- THE DISCRIMINATOR: the classification reaches the counters.
    let tx = &run.tx_counters;
    assert_eq!(
        tx.pending_in_place_vlan_pop_desc_packets, 1,
        "#6304: the in-place staging arm must account the descriptor VLAN pop \
         — this counter is the operator's only view of how the fast path is \
         rewriting L2, and without this cell the whole \
         `record_in_place_l2_rewrite` call deletes with the crate green"
    );
    assert_eq!(
        tx.pending_in_place_vlan_push_desc_packets, 0,
        "#6304: ...as a POP, not a push"
    );
    assert_eq!(
        tx.pending_in_place_vlan_push_no_headroom_packets, 0,
        "#6304: ...and not the no-headroom memmove variant"
    );
    assert_eq!(
        tx.pending_in_place_l2_memmove_fallback_packets, 0,
        "#6304: ...and not the unsupported-memmove fallback"
    );
}

/// #6304 (#3073 policy hit-count replay). `record_policy_hit_counter` at
/// `flow_cache_hit.rs` DELETES with the whole crate green — measured, 4285
/// passed / 0 failed — because no fixture ever reaches it. This closes that.
///
/// The mechanism is the same one that hid `record_in_place_l2_rewrite` in the
/// previous round, in its second shape. There the call ran on every fixture and
/// landed in an arm that is an empty block; here the call never runs at all: the
/// stock entry leaves `policy_counter: None` with `policy_counter_idx: 0`, and
/// `ForwardingState::default()` has no rule at index 0, so
/// `resolve_session_hit_counter` returns `None` and the guarded block is skipped
/// on every packet this module has ever staged. Both look like covered call
/// sites in a coverage report; neither binds anything.
///
/// What this costs when it regresses: the flow cache serves MOST packets of a
/// long-lived permitted flow, so `show security policies hit-count` would report
/// only each flow's seed packet — the exact under-count #3073 exists to fix.
///
/// The BYTE assertion is load-bearing separately from the packet one: the call
/// site passes `meta.pkt_len`, and a call site that passed a stripped L3 length
/// (or zero) would still advance the packet count. `test_meta` sets `pkt_len` to
/// the FULL wire length, as the shim reports it.
#[test]
fn live_flow_cache_callsite_recounts_the_established_policy_hit_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let counter = Arc::new(crate::policy::PolicyRuleCounter::default());
    let run = run_stage_with_entry(
        &fixture,
        &frame,
        test_meta(&frame),
        policy_counted_entry(&counter),
        0,
    );

    // --- POSITIVE CONTROL: the staged packet really was forwarded, so a zero
    // below would mean the counter was not charged rather than that the fixture
    // fell out of the fast path early.
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED"
    );

    // --- THE DISCRIMINATOR.
    assert_eq!(
        counter.test_packet_count(),
        1,
        "#6304/#3073: an established-session packet served from the flow cache \
         must be re-counted against the admitting policy's hit counter; without \
         it `show security policies hit-count` reports only each flow's first \
         frame"
    );
    assert_eq!(
        counter.test_byte_count(),
        frame.len() as u64,
        "#6304/#3073: ...charged the FULL wire length the shim reported, not a \
         stripped or zero byte count"
    );
}

/// #6304 (#3651 per-zone traffic volume). `record_zone_traffic` at
/// `flow_cache_hit.rs` also DELETES with the whole crate green — measured, same
/// run. Third instance of the same class in this module, and the reason the
/// sweep was run over every `record_*` call rather than the one that was
/// reported.
///
/// Here the call RAN on every fixture and did nothing: with an empty
/// `ZoneCounterSlotMap` and `EGRESS_IFINDEX` absent from `forwarding.egress`,
/// both slot lookups are 0 and the function returns at its first branch.
/// `with_zone_accounting` supplies exactly the wiring production always has —
/// a slot map built over the configured zones, and an egress interface carrying
/// a zone id — so the call has somewhere to land.
///
/// BOTH directions are asserted because the call passes two independently
/// resolved zone ids: the ingress one comes from the shim metadata, the egress
/// one from `egress_zone_id(cached_decision.resolution.egress_ifindex)`.
/// Asserting only one leaves the other resolvable to anything.
///
/// `ZONE_PENDING` is a per-thread coalescer, so the flush is what makes the
/// packet observable in the store at all. It is also thread state this test does
/// not exclusively own: whether libtest runs each test on its own thread is a
/// harness detail, not a contract, and `--test-threads=1` is part of this
/// project's standard validation. The preamble below drains whatever is pending
/// into a THROWAWAY store first, so a sibling's deltas can never fold into the
/// assertions here — the isolation is by construction rather than by assumption
/// about the runner.
#[test]
fn live_flow_cache_callsite_accounts_per_zone_traffic_6304() {
    let discard = crate::afxdp::zone_counters::ZoneCounterStore::default();
    crate::afxdp::zone_counters::flush_recorded_zone_counters(
        &discard,
        &crate::afxdp::zone_counters::ZoneCounterSlotMap::build(
            &[TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID],
            &discard,
        ),
    );

    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    let frame = tcp_v4_ack_frame();
    let mut meta = test_meta(&frame);
    meta.ingress_zone = TEST_TRUST_ZONE_ID;
    let run = run_stage_with_meta(&fixture, &frame, meta, 0);

    // --- POSITIVE CONTROL.
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED"
    );

    crate::afxdp::zone_counters::flush_recorded_zone_counters(
        &fixture.forwarding.zone_counter_store,
        &fixture.forwarding.zone_counter_slot_map,
    );
    let rows = fixture.forwarding.zone_counter_store.snapshot();

    // --- THE DISCRIMINATOR: the forwarded packet is charged to BOTH zones.
    let ingress = rows
        .iter()
        .find(|r| r.zone_id == TEST_TRUST_ZONE_ID)
        .expect(
            "#6304/#3651: the forwarded packet must be charged to its INGRESS \
             zone; no row at all means `record_zone_traffic` never reached the \
             coalescer",
        );
    assert_eq!(
        (ingress.ingress_packets, ingress.ingress_bytes),
        (1, frame.len() as u64),
        "#6304/#3651: one packet at the full wire length on the ingress zone"
    );
    assert_eq!(
        (ingress.egress_packets, ingress.egress_bytes),
        (0, 0),
        "#6304/#3651: ...and nothing on that zone's EGRESS side — the two \
         directions must not be conflated"
    );

    let egress = rows
        .iter()
        .find(|r| r.zone_id == TEST_UNTRUST_ZONE_ID)
        .expect(
            "#6304/#3651: ...and to its EGRESS zone, resolved from the cached \
             decision's egress ifindex",
        );
    assert_eq!(
        (egress.egress_packets, egress.egress_bytes),
        (1, frame.len() as u64),
        "#6304/#3651: one packet at the full wire length on the egress zone"
    );
    assert_eq!(
        (egress.ingress_packets, egress.ingress_bytes),
        (0, 0),
        "#6304/#3651: ...and nothing on that zone's INGRESS side"
    );
}

/// #6304 (#2573 + #3777 filter `then count` replay). Neither `record_filter_counter`
/// call site at `flow_cache_hit.rs` was reachable from ANY fixture in this module —
/// no fixture had ever put a counter in either list to walk — so this closes both
/// at the call site. Their crate-wide severance results DIFFER, and stating that
/// precisely matters more than the symmetry:
///
///   - TX/output walk reduced to `.for_each(|_| {})`: whole crate GREEN
///     (measured, 4263 passed / 0 failed at the head that first measured it).
///   - INPUT walk reduced the same way: RED —
///     `txn_flow_cache_hit_replays_input_filter_then_count_3777`
///     (`afxdp/tests_txn_flow_cache.rs`) already drove two packets of one flow
///     through the full descriptor path and asserted the input counter reaches 2.
///
/// So the input assertion below is a second binding, not the first one. An
/// earlier revision of this comment claimed both severed green — the same
/// miscount this PR exists to fix, reintroduced in its own prose.
///
/// Fourth and fifth instances of the unreachable-telemetry class in this
/// function, and a THIRD shape of it. `record_policy_hit_counter` was
/// unreachable behind a `None` guard; `record_zone_traffic` ran and landed in a
/// no-op arm; these two run and iterate an EMPTY collection, so the closure that
/// holds the call never executes at all. A coverage report marks the `for_each`
/// line as covered in every case.
///
/// What it costs when it regresses: `show firewall counter` reports only each
/// flow's seed packet. The flow cache serves most packets of a long-lived flow,
/// which is exactly what #2573 (output/TX side) and #3777 (interface input side)
/// were filed to fix — and #3777 was itself filed because the TX side had been
/// fixed and the input side had not, so the two sides are demonstrably able to
/// regress independently. That is why both are asserted here rather than one
/// standing in for the other.
///
/// TWO tx-side counters, not one: #2573's guarantee is that ALL matched count
/// terms replay, not just the last, so a single-counter assertion would be
/// satisfied by a walk that stopped after one. The BYTE cell is load-bearing
/// separately from the packet cell — the call site passes `meta.pkt_len`, and a
/// stripped or zero length would still advance the packet count.
#[test]
fn live_flow_cache_callsite_replays_every_filter_count_term_6304() {
    let tx_first = Arc::new(crate::filter::FilterTermCounter::default());
    let tx_second = Arc::new(crate::filter::FilterTermCounter::default());
    let input = Arc::new(crate::filter::FilterTermCounter::default());

    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let run = run_stage_with_entry(
        &fixture,
        &frame,
        test_meta(&frame),
        filter_counted_entry(&[tx_first.clone(), tx_second.clone()], &input),
        0,
    );

    // --- POSITIVE CONTROL: the packet really was forwarded, so a zero below
    // means the counter was not charged rather than that the fixture fell out of
    // the fast path before reaching the replay.
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED"
    );

    // --- THE DISCRIMINATORS.
    for (label, counter) in [("first", &tx_first), ("second", &tx_second)] {
        assert_eq!(
            (
                counter.packets.load(Ordering::Relaxed),
                counter.bytes.load(Ordering::Relaxed)
            ),
            (1, frame.len() as u64),
            "#6304/#2573: the {label} matched output-filter `then count` term must \
             be replayed on a flow-cache hit, at the full wire length. Replaying \
             only the last term is the #2544 fall-through under-count #2573 fixed"
        );
    }
    assert_eq!(
        (
            input.packets.load(Ordering::Relaxed),
            input.bytes.load(Ordering::Relaxed)
        ),
        (1, frame.len() as u64),
        "#6304/#3777: ...and the interface INPUT filter's `then count` handle too. \
         The input side regressed independently of the output side once already, \
         which is why #3777 exists as a separate issue"
    );
}

/// #6304 (per-batch forward + NAT accounting). Three counters on
/// `BatchCounters` — `forward_candidate_packets`, `snat_packets`,
/// `dnat_packets` — were bumped by this call site and read by nothing. Each is
/// flushed onto the operator-visible `BindingLiveState` atomic of the same name
/// by `BatchCounters::flush` (`afxdp/mod.rs`), published through
/// `binding_state/snapshot.rs`, and carried on the wire by
/// `protocol/binding.rs`, so deleting any one of them silently under-reports a
/// live per-binding counter for every established-flow cache hit that forwards.
///
/// A SIXTH shape of the class this module keeps finding, and the plainest: the
/// increments were reachable and did run — `run_stage` simply constructed
/// `BatchCounters::default()` and dropped it, so `StageRun` had nowhere to
/// report them from. Retaining the struct is what makes them assertable at all.
///
/// The NAT pair needs more than retention. Their guards read
/// `cached_decision.nat.rewrite_src`/`rewrite_dst`, and every fixture in this
/// module carried `NatDecision::default()` — both `None` — so the two lines were
/// unreachable as well as unread. `nat_translated_entry` supplies a decision AND
/// a descriptor carrying a real SNAT and a real DNAT; the frame assertions below
/// are what keep that fixture honest rather than merely asserted, since a
/// descriptor/decision disagreement would let the counters claim a translation
/// the wire never carried.
///
/// The UNTRANSLATED run is not a duplicate of the other cells: it binds the two
/// `is_some()` GUARDS rather than the increments. Dropping either guard and
/// bumping unconditionally leaves the translated run's rows satisfied and reds
/// only there, which is the mutation that would report every forwarded packet
/// as NAT'd.
///
/// WHY THE DISCRIMINATORS ARE AGGREGATED RATHER THAN ASSERTED IN SEQUENCE. The
/// property this test exists to demonstrate is that the three increments are
/// bound INDEPENDENTLY. A sequence of `assert_eq!`s cannot demonstrate that,
/// and an earlier revision of this test did not: the first divergence panics,
/// so in the "delete the forward increment" cell the SNAT and DNAT assertions
/// never executed at all. Distinct failure LINES across three cells prove only
/// that the rows read distinct FIELDS; they say nothing about what the
/// unexecuted rows would have done in that same run, which is the whole claim.
/// Every row below is therefore evaluated into `observed` and reported by a
/// single assertion at the end, so a mutation cell names which rows diverged
/// out of six that all ran.
///
/// THE PROPERTY CLAIMED, stated precisely because it is NOT "exactly one row
/// reds". Deleting production increment X reds every row ABOUT X and no row
/// about either other increment. TWO rows are about the forward increment on
/// purpose: `nat/forward` binds the increment itself, and `plain/forward` binds
/// its POSITION outside both `is_some()` NAT guards — an increment moved inside
/// them still satisfies the translated run, so without the second row that
/// motion is invisible. The forward cell therefore reds two rows, and both name
/// forward. Per-assertion uniqueness would be a property about this test's own
/// redundancy; per-increment independence is the property about the production
/// code, and it is the one asserted here.
///
/// The `[_; 6]` annotation on `observed` is load-bearing, not decoration:
/// deleting a row is a COMPILE error (E0308, measured), so the aggregation
/// cannot quietly lose a discriminator the way a deleted `assert_eq!` would.
/// That is a type-level constraint rather than a match on a name or on source
/// text, so a differently-spelled equivalent cannot satisfy it — add a row and
/// the count must be updated deliberately.
///
/// The POSITIVE CONTROLS above the rows are PRECONDITIONS, not discriminators,
/// and they deliberately still panic on the spot: a run that did not forward,
/// or did not really translate the frame, can say nothing about the counters,
/// and the honest outcome is to abort rather than report six meaningless rows.
/// When reading a mutation matrix, a control panic is a broken FIXTURE; only
/// the aggregate assertion at the end is a result about the production code.
#[test]
fn live_flow_cache_callsite_accounts_forward_and_nat_packets_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    // rate = 2 with counter = 1 -> NOT sampled: this cell is about the batch
    // accounting, so the mirror block stays out of the way.
    let nat = run_stage_with_entry(
        &fixture,
        &frame,
        test_meta(&frame),
        nat_translated_entry(),
        1,
    );

    // The UNTRANSLATED comparison run. Staged here, beside the translated run,
    // so that BOTH runs have executed before the first row is evaluated — a
    // divergence in either is then reported by the same aggregate assertion.
    let plain_fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let plain = run_stage(&plain_fixture, &frame, 1);

    // --- PRECONDITIONS (panicking, by design — see the doc comment): the
    // packet reached the accounting block, the translation the two NAT counters
    // are about is genuinely on the wire, and the untranslated run forwarded
    // too. A failure here is a broken FIXTURE, not a result about the counters.
    assert!(
        matches!(nat.outcome, FlowCacheOutcome::Consumed),
        "precondition: the cached flow must be consumed by the fast path"
    );
    assert_eq!(
        nat.tx_counters.pending_in_place_tx_packets, 1,
        "precondition: the in-place hairpin rewrite must have SUCCEEDED"
    );
    let staged = nat
        .tx_frame
        .as_ref()
        .expect("precondition: the rewritten frame must be staged for TX");
    assert_eq!(
        &staged[30..34],
        &SNAT_SRC_IP.octets(),
        "precondition: the SOURCE address was really translated — without this \
         the `snat_packets` row below would be counting a NAT the descriptor \
         never applied"
    );
    assert_eq!(
        &staged[34..38],
        &DNAT_DST_IP.octets(),
        "precondition: ...and the DESTINATION address too, to a DIFFERENT \
         value, so a rewrite that wrote one address into both slots is visible"
    );
    assert_eq!(
        plain.tx_counters.pending_in_place_tx_packets, 1,
        "precondition: the untranslated flow forwards in place too"
    );

    // --- THE DISCRIMINATORS. Every row is EVALUATED here and none is asserted
    // on its own, so that a mutation cell reports the complete set of rows that
    // moved rather than only the first. `(row, actual, expected, why)`.
    let observed: [(&str, u64, u64, &str); 6] = [
        (
            "nat/forward_candidate_packets",
            nat.counters.forward_candidate_packets,
            1,
            "a forwarded cache hit must charge `forward_candidate_packets` — the \
             per-binding forward counter every operator view of this path reads",
        ),
        (
            "nat/snat_packets",
            nat.counters.snat_packets,
            1,
            "a hit whose cached decision carries a source rewrite must charge \
             `snat_packets`",
        ),
        (
            "nat/dnat_packets",
            nat.counters.dnat_packets,
            1,
            "...and one carrying a destination rewrite must charge `dnat_packets`",
        ),
        (
            "plain/forward_candidate_packets",
            plain.counters.forward_candidate_packets,
            1,
            "NAT or not, a forwarded cache hit is a forward candidate. This row \
             binds the forward increment's POSITION outside both `is_some()` NAT \
             guards — an increment moved inside them still satisfies the \
             translated run, so nothing else here would see that motion",
        ),
        (
            "plain/snat_packets",
            plain.counters.snat_packets,
            0,
            "a flow with no source rewrite must NOT be reported as SNAT'd — \
             dropping the `rewrite_src.is_some()` guard and bumping \
             unconditionally reds this row and no other",
        ),
        (
            "plain/dnat_packets",
            plain.counters.dnat_packets,
            0,
            "...nor as DNAT'd, which is the same statement for \
             `rewrite_dst.is_some()`",
        ),
    ];

    let diverged: Vec<String> = observed
        .iter()
        .filter(|(_, actual, expected, _)| actual != expected)
        .map(|(row, actual, expected, why)| {
            format!("  {row}: got {actual}, want {expected} — #6304: {why}")
        })
        .collect();
    assert!(
        diverged.is_empty(),
        "#6304: {} of {} accounting rows diverged. ALL {} were evaluated before \
         this assertion, so the list below is COMPLETE and every row absent \
         from it held in the SAME run — which is what makes the three \
         increments independently bound rather than merely separately \
         readable:\n{}",
        diverged.len(),
        observed.len(),
        observed.len(),
        diverged.join("\n")
    );
}

/// #6304 (per-hit observed bytes, at the SEAM). `stage_flow_cache_hit` opens by
/// calling `flow_cache.lookup_counted(.., meta.pkt_len)`; the callee folds that
/// argument into the hit entry's `observed_bytes`, which is what
/// `show flow-cache` reports per cached flow and what the #4800 connection-rate
/// analysis reads.
///
/// The ARGUMENT is what was unbound, not the accumulation. `stage_flow_cache_hit`
/// is the ONLY production caller of `lookup_counted`; the other five in the tree
/// (`afxdp/flow_cache_tests.rs` x4 and `binding_state/tests/debug_state.rs` x1,
/// enumerated firsthand) are tests invoking it DIRECTLY with a literal 1500 or
/// 900, so they all bind the callee and none binds what this call site chooses to
/// pass. Replacing `meta.pkt_len` with `0` keeps
/// every lookup decision identical (the byte argument feeds nothing but the
/// accumulator) and silently zeroes per-hit observed bytes on the fast path that
/// serves most packets of a long-lived flow. That is the "tests reach past the
/// adapter and leave the seam unbound" shape: it is only visible to a cell that
/// drives the STAGE and reads the entry afterwards.
///
/// Two runs, because a single zero-seeded entry cannot separate `+=` from `=`.
/// The pre-loaded run starts the entry at a non-zero count, so a call site
/// passing 0 reads back the seed unchanged while a callee that ASSIGNED would
/// read back the packet length alone.
///
/// The read itself uses the `#[cfg(test)]` `lookup`, the zero-adding variant of
/// the same `lookup_with_observed_bytes` body, so observing the number cannot
/// move it. `Option` rather than a defaulted 0: an entry evicted out of the cache
/// must not be reported as a zero byte count, which is exactly the mutation.
#[test]
fn live_flow_cache_callsite_counts_observed_bytes_on_the_hit_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    // rate = 2 with counter = 1 -> NOT sampled; the mirror block is irrelevant
    // here and stays out of the way.
    let fresh = run_stage(&fixture, &frame, 1);

    // --- POSITIVE CONTROL: the packet took the cache-hit path at all. Without
    // it, a fixture that started missing would report `None` and look like a
    // different failure than the one this cell is about.
    assert_eq!(
        fresh.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED, so the \
         lookup above it was a HIT"
    );

    // --- THE DISCRIMINATOR.
    assert_eq!(
        fresh.cached_observed_bytes,
        Some(frame.len() as u64),
        "#6304: the cache-hit lookup must charge the entry the FULL wire length \
         the shim reported. Passing 0 (or an L3-stripped length) at the call \
         site leaves every lookup decision unchanged and silently zeroes the \
         per-flow observed-byte count"
    );

    // --- ...and it ACCUMULATES onto what the entry already carried, rather
    // than replacing it.
    let carried = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let mut preloaded = cached_entry();
    preloaded.observed_bytes = 4096;
    let second = run_stage_with_entry(&carried, &frame, test_meta(&frame), preloaded, 1);
    assert_eq!(
        second.tx_counters.pending_in_place_tx_packets, 1,
        "control: the pre-loaded entry is hit on the same fast path"
    );
    assert_eq!(
        second.cached_observed_bytes,
        Some(4096 + frame.len() as u64),
        "#6304: a hit ADDS this packet to the flow's running total — reading \
         back the seed alone means the call site passed 0, and reading back the \
         packet length alone means the count was assigned rather than folded"
    );
}

/// #5190 (A1-b1-F6) FAIL-ON-REVERT at the LIVE call site: a cached candidate
/// that the caller's DYNAMIC validation rejects must NOT be published as a
/// served flow-cache hit.
///
/// `lookup_counted` commits `hits += 1` the moment key/generation/epoch/lease
/// pass, because it has to hand out a borrow of the entry and cannot hold a
/// mutable borrow across the caller's own checks. The caller then re-tests the
/// per-shard neighbor MAC epoch (#3048/#5147) and the HA/fabric decision, and
/// on failure evicts the slot and falls through to the slow path — so the
/// packet was never served from the cache. Before #5190 it was still counted
/// as a hit, inflating the published hit rate during exactly the events
/// (gateway VRRP failover, NIC swap, RG transition) an operator reads it to
/// diagnose.
///
/// The fixture forces the neighbor-MAC-stale rejection by stamping the cached
/// entry against a REAL shard at a MAC epoch the live map has never reached.
/// Deleting `reclassify_hit_as_miss` turns the hits/misses assertions RED; the
/// `FallThrough` assertion stays green either way, which is what proves the
/// two are independent.
#[test]
fn live_flow_cache_callsite_rejected_candidate_is_not_a_hit_5190() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let meta = test_meta(&frame);
    let mut entry = cached_entry();
    // Stamp a real shard at an epoch the live neighbor map never reached ->
    // `neighbor_mac_epoch_stale` is true -> the caller rejects the candidate.
    entry.neighbor_shard = 0;
    entry.neighbor_mac_epoch = 0xDEAD_BEEF;
    let run = run_stage_with_entry(&fixture, &frame, meta, entry, 0);

    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "a MAC-stale cached descriptor must fall through to full slow-path \
         resolution (#3048/#5147) — the fixture is not reaching the reject \
         branch, so the tallies below would prove nothing"
    );
    let (hits, misses, evictions) = run.flow_cache_tallies;
    assert_eq!(
        hits, 0,
        "#5190: a candidate the caller REJECTED was never served from the \
         cache and must not be published as a flow-cache hit"
    );
    assert_eq!(
        misses, 1,
        "#5190: the rejected candidate must be accounted as a miss — the \
         packet went to the slow path"
    );
    assert_eq!(
        evictions, 1,
        "#5190: the rejected candidate's slot was evicted; the eviction \
         tally must show it"
    );
}

/// #5190 control: an ACCEPTED cached candidate still counts as exactly one
/// hit and zero misses. Without this, `reclassify_hit_as_miss` could be
/// mis-wired onto the accept path (or `hits += 1` deleted outright) and the
/// rejection test above would still pass.
#[test]
fn live_flow_cache_callsite_served_hit_still_counts_as_a_hit_5190() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let run = run_stage(&fixture, &frame, 0);
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "the unmodified fixture must take the served-hit path"
    );
    let (hits, misses, evictions) = run.flow_cache_tallies;
    assert_eq!(hits, 1, "a served cache hit must count as exactly one hit");
    assert_eq!(misses, 0, "a served cache hit must not count as a miss");
    assert_eq!(
        evictions, 0,
        "a served cache hit must not count as an eviction"
    );
}


// ─────────────────────────────────────────────────────────────────────────────
// #6997 / #6999: the four remaining unbound production calls at this call site.
//
// All four were measured by SINGLE-LINE severance on unfiltered whole-crate
// runs at this branch's base, each leaving 4850 tests collected / 0 failed:
//
//   sessions.touch_if_stale(..)          sessions.account_packet(..)
//   emit_cached_input_filter_log(..)     emit_cached_output_filter_log(..)
//
// WHY THE OLD FIXTURE COULD NOT HAVE CAUGHT THEM, which is the part worth
// carrying forward. It is not that the assertions were missing — it is that the
// fixture made all four production lines into no-ops:
//
//   * `sessions` was an EMPTY `SessionTable`, and both `account_packet` and
//     `touch_if_stale` return immediately when the key resolves to nothing. A
//     binder written on that fixture would have gone green with the calls
//     deleted, because the calls did nothing either way.
//   * `worker_ctx()` handed production `event_stream: None`, and the cached
//     entry carried `input_filter_log: None` with a default `tx_selection`
//     (so `filter_log: None`). Both emissions early-return on those.
//
// A guard whose fixture omits the interaction is mutation-INSENSITIVE, so the
// fixture work below IS the test: seed a session, seed a filter-log match, and
// attach a stream.

/// A `now_ns` between the keepalive threshold and the TCP opening timeout,
/// so the seeded half-open session is still eligible for a live cache hit.
const STALE_NOW_NS: u64 = INSTALL_NS + 10_000_000_000; // install + 10 s

/// A `now_ns` beyond the TCP opening timeout. The cache entry remains
/// physically installed, but must fall through instead of resurrecting it.
const EXPIRED_NOW_NS: u64 = INSTALL_NS + 21_000_000_000; // install + 21 s

/// The seeded install instant. Non-zero so "the timestamp moved" cannot be
/// satisfied by a field that was simply left at its default.
const INSTALL_NS: u64 = 1_000_000;

/// The packet's own DSCP and TCP flags, chosen to be DISTINCT from every
/// default in the fixture: `UserspaceDpMeta::default()` leaves `dscp` at 0 and
/// `test_meta` sets `tcp_flags` to 0x10, so an accounting call that dropped
/// either argument, or passed a neighbouring field, lands on a different number
/// than these.
const PKT_DSCP: u8 = 46; // EF -> ToS byte 0xB8
const PKT_TCP_FLAGS: u8 = 0x18; // PSH|ACK, not the fixture's bare ACK

/// `test_meta` with this module's distinct DSCP / TCP flags.
fn accounted_meta(frame: &[u8]) -> UserspaceDpMeta {
    let mut meta = test_meta(frame);
    meta.dscp = PKT_DSCP;
    meta.tcp_flags = PKT_TCP_FLAGS;
    meta
}

/// #6997: the forwarded packet must be accounted onto ITS session, with the
/// amount it actually carried and the observation fields the SESSION_CLOSE
/// RT_FLOW record is built from.
///
/// RED on revert: delete `sessions.account_packet(..)` from
/// `stage_flow_cache_hit` and every assertion below fails — counters stay 0 and
/// both observation fields stay at their install values.
///
/// The byte assertion is an EXACT equality against `meta.pkt_len`, not a
/// non-zero check: a call site that passed a neighbouring length (an
/// L2-stripped payload length, say) would satisfy "non-zero" while silently
/// under-reporting every byte total an operator reads after the fact. That is
/// the failure mode this issue names — not missing data in the security log,
/// but WRONG data in it.
#[test]
fn live_flow_cache_callsite_accounts_the_packet_onto_the_session_6997() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let meta = accounted_meta(&frame);
    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        cached_entry(),
        1,
        StageSeed {
            // Install with NO tcp flags, so every bit asserted below arrived
            // through the accounting call rather than through the install.
            session: Some((INSTALL_NS, PROTO_TCP, 0x00)),
            now_ns: INSTALL_NS,
            ..StageSeed::default()
        },
    );

    // Control: the fixture reached the accounting point at all.
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must be consumed by the fast path, otherwise \
         the accounting call below was never reached and every assertion here \
         would pass or fail for an unrelated reason"
    );

    let counters = run
        .sessions
        .session_counters(&test_key())
        .expect("control: the seeded session must still exist after the call");
    assert_eq!(
        counters.fwd_packets, 1,
        "the flow-cache hit must account exactly ONE forward packet onto the \
         session; 0 means `sessions.account_packet(..)` is not reached and the \
         SESSION_CLOSE record's packet total under-reports every cached packet \
         of every long-lived flow (#6997)"
    );
    assert_eq!(
        counters.fwd_bytes,
        u64::from(meta.pkt_len),
        "the accounted byte count must be the packet's OWN wire length \
         ({} here), not merely non-zero — a neighbouring length would satisfy a \
         non-zero check and silently under-report the byte total an operator \
         reads out of the security log (#6997)",
        meta.pkt_len
    );
    assert_eq!(
        counters.rev_packets, 0,
        "a forward packet must not be folded onto the reverse counters"
    );

    let (flags, tos) = run
        .sessions
        .observed_close_fields(&test_key())
        .expect("control: the seeded session must still exist after the call");
    assert_eq!(
        flags, PKT_TCP_FLAGS,
        "the packet's TCP control bits must be OR-accumulated onto the session \
         (#2749): the session was installed with 0x00, so 0x00 here means the \
         `meta.tcp_flags` argument never arrived and the SESSION_CLOSE frame's \
         tcpControlBits is a fabricated zero (#6997)"
    );
    assert_eq!(
        tos, PKT_DSCP << 2,
        "the forward-direction ToS byte must be the packet's DSCP shifted left \
         two (#2749). 0 means the `meta.dscp` argument never arrived; any other \
         value means a neighbouring field was passed in its place (#6997)"
    );
}

/// #6997/#918: a session idle long enough must have its liveness timestamp
/// refreshed by the cache-hit path, and a FRESH one must not.
///
/// The negative half is what makes the positive half mean something. Without
/// it, "the timestamp equals `now_ns`" is satisfied by ANY unconditional write
/// — including a `touch` that ignores staleness entirely and pays a wheel
/// re-bucket on every cached packet, which is the cost `touch_if_stale` exists
/// to avoid.
///
/// RED on revert: delete `sessions.touch_if_stale(..)` and the stale cell fails
/// (the timestamp stays at the install instant) while the fresh cell keeps
/// passing — so the pair localises the severance to the call, not to the
/// callee's threshold.
#[test]
fn live_flow_cache_callsite_refreshes_only_a_stale_session_6997() {
    let frame = tcp_v4_ack_frame();

    // STALE: idle for 10 s at call time, beyond the keepalive threshold but
    // within the TCP opening timeout.
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let stale = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        cached_entry(),
        1,
        StageSeed {
            session: Some((INSTALL_NS, PROTO_TCP, 0x02)),
            now_ns: STALE_NOW_NS,
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(stale.outcome, FlowCacheOutcome::Consumed),
        "control: the stale-session run must still take the cache-hit path"
    );
    assert_eq!(
        stale
            .sessions
            .last_seen_ns(&test_key())
            .expect("control: the seeded session must still exist"),
        STALE_NOW_NS,
        "a session idle far past its keepalive threshold must be refreshed to \
         the packet's own `now_ns` by the cache-hit path. Leaving it at the \
         install instant is the #2220 reaping bug: a low-rate flow served \
         entirely from the cache is reaped while still forwarding (#6997)"
    );

    // FRESH: the same fixture, called one microsecond after the install.
    let fixture2 = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let fresh = run_stage_seeded(
        &fixture2,
        &frame,
        accounted_meta(&frame),
        cached_entry(),
        1,
        StageSeed {
            session: Some((INSTALL_NS, PROTO_TCP, 0x00)),
            now_ns: INSTALL_NS + 1_000,
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(fresh.outcome, FlowCacheOutcome::Consumed),
        "control: the fresh-session run must also take the cache-hit path"
    );
    assert_eq!(
        fresh
            .sessions
            .last_seen_ns(&test_key())
            .expect("control: the seeded session must still exist"),
        INSTALL_NS,
        "a session refreshed one microsecond ago must NOT be touched again. A \
         timestamp that moves here means the throttle is gone and every cached \
         packet pays a timer-wheel re-bucket — and it would also make the stale \
         cell above pass against an unconditional write, which is what this \
         cell exists to exclude (#6997)"
    );
}

/// An idle-crossed session must evict the cached candidate and fall through
/// before any cache-hit side effect can run. The entry remains installed for
/// the timer wheel to reap, but this packet gets no refresh, accounting, TX, or
/// scratch ownership transfer.
#[test]
fn expired_flow_cache_hit_falls_through_without_side_effects_9991() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        cached_entry(),
        1,
        StageSeed {
            session: Some((INSTALL_NS, PROTO_TCP, 0x02)),
            now_ns: EXPIRED_NOW_NS,
            ..StageSeed::default()
        },
    );

    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "an idle-crossed cached session must be reclassified as a miss"
    );
    assert_eq!(
        run.sessions.last_seen_ns(&test_key()),
        Some(INSTALL_NS),
        "the expired cache candidate must not refresh its backing session"
    );
    let counters = run
        .sessions
        .session_counters(&test_key())
        .expect("the timer wheel still owns the installed session");
    assert_eq!(
        (
            counters.fwd_packets,
            counters.fwd_bytes,
            counters.rev_packets,
            counters.rev_bytes,
        ),
        (0, 0, 0, 0),
        "fallthrough must happen before packet accounting"
    );
    assert!(run.scratch.scratch_recycle.is_empty());
    assert!(run.scratch.scratch_forwards.is_empty());
    assert!(run.tx_frame.is_none());
}

/// A cached descriptor carrying BOTH a `then log` input-filter match and a
/// `then log` output-filter match, with DISTINCT filter/term ids so an
/// assertion cannot confuse the two records.
fn logging_cached_entry(input: bool, output: bool) -> FlowCacheEntry {
    let mut entry = cached_entry();
    if input {
        entry.descriptor.input_filter_log = Some(crate::afxdp::flow_cache::CachedInputFilterLog {
            log_match: crate::filter::FilterLogMatch {
                filter_id: 0x1111,
                term_id: 0x2222,
                action: crate::filter::FilterAction::Accept,
            },
            ingress_zone_id: TEST_TRUST_ZONE_ID,
        });
    }
    if output {
        entry.descriptor.tx_selection.filter_log = Some(crate::filter::FilterLogMatch {
            filter_id: 0x3333,
            term_id: 0x4444,
            action: crate::filter::FilterAction::Accept,
        });
    }
    entry
}

/// Drain every event the run produced, decoded.
fn drained_events(
    fixture: &LiveCallSiteFixture,
) -> Vec<crate::event_stream::codec::DataplaneEventPayload> {
    let rx = fixture
        .event_rx
        .as_ref()
        .expect("fixture was not built with_event_stream");
    let mut out = Vec::new();
    while let Ok(frame) = rx.try_recv() {
        if let Some(payload) = frame.decode_dataplane_event() {
            out.push(payload);
        }
    }
    out
}

/// #6999: the cached INPUT filter-log emission.
///
/// RED on revert: delete `emit_cached_input_filter_log(..)` from
/// `stage_flow_cache_hit` and no event is produced — firewall-filter `then log`
/// goes silent for every packet of every cached flow, i.e. most packets of
/// every long-lived permitted flow, while the dataplane keeps forwarding
/// correctly. The operator's log simply stops.
///
/// Asserts the record's FIELDS, not that "a log call happened": the neighbouring
/// counter site in this same function was once found bound by a test asserting
/// the wrong property, so presence alone is not evidence the right record went
/// out.
#[test]
fn live_flow_cache_callsite_emits_the_cached_input_filter_log_6999() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_event_stream();
    let frame = tcp_v4_ack_frame();
    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        logging_cached_entry(true, false),
        1,
        StageSeed::default(),
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must be consumed by the fast path"
    );

    let events = drained_events(&fixture);
    let event = events
        .iter()
        .find(|e| e.reason == FilterLogSource::Input.wire_reason())
        .unwrap_or_else(|| {
            panic!(
                "no cached INPUT filter-log record reached the event stream: {events:?}. \
                 `then log` on an input filter stops producing RT_FLOW records for \
                 every cached packet of every permitted flow, silently (#6999)"
            )
        });
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(
        event.src_ip,
        test_key().src_ip,
        "the record must carry the PACKET's source, not a fixture default"
    );
    assert_eq!(event.dst_ip, test_key().dst_ip);
    assert_eq!(event.src_port, test_key().src_port);
    assert_eq!(event.dst_port, test_key().dst_port);
    assert_eq!(
        event.ingress_zone_id, TEST_TRUST_ZONE_ID,
        "the record must carry the ingress zone the CACHED input-filter match \
         was resolved in"
    );

    // OVER-REACH CONTROL, in this cell's own body: the entry carried NO output
    // filter-log, so no cached-output record may appear. Without this, an
    // emission that fired both records unconditionally would satisfy the
    // assertion above while making the output side's own cell vacuous.
    assert!(
        !events
            .iter()
            .any(|e| e.reason == FilterLogSource::CachedOutput.wire_reason()),
        "a cached-OUTPUT record was emitted for an entry whose tx_selection \
         carries no filter_log: {events:?}"
    );
}

/// #6999: the cached OUTPUT filter-log emission, and the #3615 truthful action
/// it carries.
///
/// RED on revert: delete `emit_cached_output_filter_log(..)` and no
/// cached-output record is produced. That emission additionally carries
/// `output_reject_reply_enqueued`, the #3615 DENY-vs-REJECT discriminator, so a
/// regression here also makes the logged action disagree with what the
/// dataplane actually did.
#[test]
fn live_flow_cache_callsite_emits_the_cached_output_filter_log_6999() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_event_stream();
    let frame = tcp_v4_ack_frame();
    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        logging_cached_entry(false, true),
        1,
        StageSeed::default(),
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must be consumed by the fast path"
    );

    let events = drained_events(&fixture);
    let event = events
        .iter()
        .find(|e| e.reason == FilterLogSource::CachedOutput.wire_reason())
        .unwrap_or_else(|| {
            panic!(
                "no cached OUTPUT filter-log record reached the event stream: {events:?}. \
                 `then log` on an output filter stops producing RT_FLOW records for \
                 every cached packet, and with it the #3615 truthful reject action \
                 (#6999)"
            )
        });
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(event.src_ip, test_key().src_ip);
    assert_eq!(event.dst_ip, test_key().dst_ip);
    assert_eq!(event.dst_port, test_key().dst_port);

    // Same over-reach control, mirrored: this entry carries no INPUT log.
    assert!(
        !events
            .iter()
            .any(|e| e.reason == FilterLogSource::Input.wire_reason()),
        "an INPUT record was emitted for an entry whose descriptor carries no \
         input_filter_log: {events:?}"
    );
}

/// #7678: the flow-cache REPLAY consumer of `then reject <message-type>`.
///
/// Four hops carry a filter term's reject message-type from the filter result
/// to the ICMP builder. #6854 bound three; this is the fourth, and it was the
/// one with nowhere to stand — hardcoding
/// `cached_descriptor.tx_selection.reject_message` to the default left the
/// ENTIRE suite green, so an operator's `then reject host-unreachable` would
/// silently revert to administratively-prohibited on flow-cache-replayed
/// traffic with nothing to notice.
///
/// THREE THINGS HAD TO BE TRUE AT ONCE, and each fails SILENTLY on its own —
/// which is why the assertions below run in this order rather than jumping to
/// the byte under test. Each earlier failure otherwise masquerades as the
/// later one:
///
/// 1. **The lookup must HIT.** `stage_flow_cache_hit` does not derive its key
///    from the packet — it takes `flow.forward_key` as a parameter — and this
///    harness hardcoded that to `test_key()` (TCP). Re-keying only the cached
///    entry made `entry.key != *key` and the lookup MISSED, measured as
///    `tallies=(0,1,0)`. Both sides move together via `StageSeed.flow`.
/// 2. **The frame must NOT be TCP.** `reject_reply.rs` branches on
///    `meta.protocol == PROTO_TCP` and synthesizes a TCP RST on that arm,
///    never consulting `reject_message`. A TCP frame cannot reach the ICMP
///    code path however the descriptor is configured.
/// 3. **The ingress interface needs a primary IPv4.** The reply is sourced
///    from it; without one nothing is built at all.
///
/// FAIL-ON-REVERT: hardcode `flow_cache_hit.rs`'s `reject_message` read to
/// `RejectMessage::ADMIN_PROHIBITED` and the final assertion reds with code 13.
#[test]
fn live_flow_cache_replay_carries_the_configured_reject_message_type_7678() {
    let _bucket_guard = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        1_000_000,
    );

    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_ingress_primary_v4();
    let frame = vlan_tagged_udp_v4_frame();
    let meta = udp_test_meta(&frame);

    let mut entry = cached_entry();
    entry.key = udp_test_key();
    // `reject` is only ever true when `drop` is (flow_cache.rs), so setting it
    // alone would be a state the producer cannot emit.
    entry.descriptor.tx_selection.drop = true;
    entry.descriptor.tx_selection.reject = true;
    // `host-unreachable` — ICMPv4 type 3 code 1. Deliberately NOT the default
    // (code 13): a cell using ADMIN_PROHIBITED here would pass against a
    // hardcoded read and prove nothing.
    entry.descriptor.tx_selection.reject_message = crate::filter::RejectMessage {
        v4_code: 1,
        v6_code: 1,
    };

    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry,
        0,
        StageSeed {
            flow: Some(SessionFlow {
                src_ip: udp_test_key().src_ip,
                dst_ip: udp_test_key().dst_ip,
                forward_key: udp_test_key(),
            }),
            // Enough headroom for the budget gate to admit; see StageSeed.
            tx_headroom: Some((128, 256)),
            ..StageSeed::default()
        },
    );

    // (1) CHEAPEST AND EARLIEST. A miss means the stage never reached the
    // replay path, so everything below would be measuring the miss path while
    // reporting on the reject path.
    assert_eq!(
        run.flow_cache_tallies.0, 1,
        "#7678 PREMISE: the cached entry must be HIT. tallies=(hits, misses, evictions)={:?} \
         — a miss means the lookup key and the entry key disagree, and every assertion \
         below would then be describing a path the stage did not take",
        run.flow_cache_tallies
    );

    // (2) The reply must actually have been built. An absent frame read as a
    // pass is the exact outcome this issue exists to prevent.
    assert_eq!(
        run.tx_pipeline.pending_tx_local.len(),
        1,
        "#7678 PREMISE: a cached `then reject` replay must enqueue exactly one ICMP reply \
         on the ingress TX pipeline. If this is 0 the assertion below reads a frame that \
         was never built and proves nothing — the exact wired-but-unasserted outcome this \
         issue exists to close"
    );
    let reply = run
        .tx_pipeline
        .pending_tx_local
        .front()
        .expect("#7678: the ICMP reject reply must be queued on the ingress TX pipeline");

    // (3) The byte under test.
    let (ty, code) = icmp_type_code_v4_7678(&reply.bytes);
    assert_eq!(
        (ty, code),
        (3, 1),
        "#7678: the flow-cache REPLAY path must carry the cached term's message-type onto \
         the wire — `host-unreachable` is ICMPv4 type 3 code 1. Code 13 means the hop from \
         CachedTxSelectionDescriptor.reject_message to the builder carries the default, \
         which is the hop #6854 left unbound and the whole suite otherwise cannot see"
    );
}

/// Type/code of an ICMPv4 reply, skipping an optional 802.1Q tag. Local twin of
/// the #6854 helper in `tests_bind_forward.rs`, which is a different module.
fn icmp_type_code_v4_7678(frame: &[u8]) -> (u8, u8) {
    let mut off = 14usize;
    if frame.len() > 13 && u16::from_be_bytes([frame[12], frame[13]]) == 0x8100 {
        off += 4;
    }
    assert!(frame.len() > off, "frame too short for an IPv4 header");
    let ihl = usize::from(frame[off] & 0x0f) * 4;
    let icmp = off + ihl;
    assert!(
        frame.len() > icmp + 1,
        "frame too short for an ICMP type/code at offset {icmp}"
    );
    (frame[icmp], frame[icmp + 1])
}

/// #7678 OVER-REACH CONTROL, and the second user the issue asks for.
///
/// The cell above asserts code 1. On its own that passes for an assertion that
/// happens to read a constant 1 from anywhere — including a builder that
/// ignores `reject_message` entirely and a fixture that coincidentally agrees.
/// This drives the SAME fixture with the DEFAULT message-type and requires code
/// 13, so the two together show the byte on the wire TRACKS the cached field
/// rather than being fixed at either value.
///
/// It also demonstrates the harness generalises past one value: only
/// `reject_message` differs between the two cells.
#[test]
fn live_flow_cache_replay_default_reject_message_still_sends_admin_prohibited_7678() {
    let _bucket_guard = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        1_000_000,
    );

    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_ingress_primary_v4();
    let frame = vlan_tagged_udp_v4_frame();
    let meta = udp_test_meta(&frame);

    let mut entry = cached_entry();
    entry.key = udp_test_key();
    entry.descriptor.tx_selection.drop = true;
    entry.descriptor.tx_selection.reject = true;
    entry.descriptor.tx_selection.reject_message = crate::filter::RejectMessage::ADMIN_PROHIBITED;

    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry,
        0,
        StageSeed {
            flow: Some(SessionFlow {
                src_ip: udp_test_key().src_ip,
                dst_ip: udp_test_key().dst_ip,
                forward_key: udp_test_key(),
            }),
            tx_headroom: Some((128, 256)),
            ..StageSeed::default()
        },
    );

    assert_eq!(
        run.flow_cache_tallies.0, 1,
        "#7678 PREMISE: the cached entry must be HIT; tallies={:?}",
        run.flow_cache_tallies
    );
    assert_eq!(
        run.tx_pipeline.pending_tx_local.len(),
        1,
        "#7678 PREMISE: the replay must enqueue exactly one ICMP reply"
    );
    let reply = run
        .tx_pipeline
        .pending_tx_local
        .front()
        .expect("#7678: the ICMP reject reply must be queued");
    assert_eq!(
        icmp_type_code_v4_7678(&reply.bytes),
        (3, 13),
        "#7678: a cached reject with NO message-type must still send \
         administratively-prohibited (ICMPv4 type 3 code 13). If this reads 1, the \
         sibling cell's code-1 assertion is not tracking the cached field"
    );
}

// ---------------------------------------------------------------------------
// #8262: the session key and the flow-cache probe, built by their TWO
// PRODUCTION ROUTES rather than from one literal.
//
// THE GAP THIS CLOSES. Every other cell in this file installs the session from
// `entry_for_session.key` and probes with `flow.forward_key`, and both default
// to `test_key()`. The fixture supplies BOTH OPERANDS OF THE COMPARISON FROM
// ONE VALUE, so they agree by construction. Such a harness can vary every other
// axis — TX headroom, admission, mirror sampling, validation state — and never
// touch the axis a key-mismatch bug lives on. It is invisible to review because
// the tests around it are real, thorough and passing.
//
// The cells below take the key from the FRAME, through
// `parse_session_flow_from_bytes` and then the poll loop's own post-parse
// mutation (`poll_descriptor/mod.rs` assigns `forward_key.routing_domain` from
// `ingress_routing_domain`). Nothing is copied from `test_key()` into the
// probe: the frame is the source, exactly as in production.
//
// WHY A CONTROL AND A RED CELL, not one: a harness that can only show agreement
// proves nothing about its own power. The second cell exhibits a mismatch the
// old fixture COULD NOT EXPRESS AT ALL, and it is the reason to believe the
// first one would have noticed.
//
// THE LIMIT OF THIS HARNESS, measured at merge rather than assumed.
// `production_route_flow` REPLICATES the poll loop's post-parse mutation; it
// does not invoke the poll loop. So it is a faithful COPY of the production
// route, not the route itself, and the copy is hand-maintained. Deleting the
// `forward_key.routing_domain` assignment from `poll_descriptor/mod.rs` leaves
// BOTH cells here green — that was checked, and it is not a defect in them:
// the production line is guarded by
// `tests_routing_domain_7160::a_segment_on_a_routing_instance_member_matches_that_instances_session_7160`,
// which does go red. Coverage of that line was never this file's job.
//
// What the limit DOES mean: if a THIRD post-parse key mutation is added to the
// poll loop and not mirrored into `production_route_flow`, this file's
// "agreement" control goes quietly vacuous — the two routes would agree because
// both are missing the same step, which is a subtler version of the very defect
// #8262 was filed about. Whoever adds a post-parse mutation to
// `poll_binding_process_descriptor` owes this helper a line.

/// Build a `SessionFlow` the way production does: parse it out of the frame,
/// then apply the poll loop's post-parse key mutation.
///
/// This is deliberately NOT handed a key. If it were, it would be the old
/// fixture with more steps.
fn production_route_flow(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> SessionFlow {
    let mut flow = crate::afxdp::frame::parse_session_flow_from_bytes(frame, meta)
        .expect("the fixture frame must parse into a flow, or nothing below is exercised");
    // The mutation the poll loop applies between the parse and every later use
    // of the key (`poll_descriptor/mod.rs`, the `has_routing_domains` arm).
    flow.forward_key.routing_domain = crate::afxdp::forwarding::ingress_routing_domain(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
        None,
    );
    flow
}

/// Give the fixture a routing-instance membership so `ingress_routing_domain`
/// resolves a NON-ZERO domain. Without this the mutation is a no-op and the
/// two routes cannot diverge on it — the cell would pass while testing nothing,
/// which is the failure mode this whole file is being fixed for.
fn with_routing_domain(fixture: &mut LiveCallSiteFixture, domain: u32) {
    fixture.forwarding.has_routing_domains = true;
    fixture
        .forwarding
        .ifindex_to_routing_domain
        .insert(PHYS_INGRESS_IFINDEX, domain);
    fixture
        .forwarding
        .ifindex_to_routing_domain
        .insert(LOGICAL_INGRESS_IFINDEX, domain);
}

// CONTROL. Both routes run for real and AGREE, so the session installed under
// the frame-derived key is found by the frame-derived probe. Establishes that
// the harness drives a working path — without it, the red cell below could go
// red for any reason at all.
#[test]
fn the_two_production_routes_agree_for_one_frame_8262() {
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    with_routing_domain(&mut fixture, 7);
    let frame = vlan_tagged_tcp_v4_frame(0);
    let meta = test_meta(&frame);

    let flow = production_route_flow(&frame, meta, &fixture.forwarding);
    assert_eq!(
        flow.forward_key.routing_domain, 7,
        "precondition: the poll loop's mutation must actually move the key, or \
         this cell and the next one differ in nothing"
    );

    let mut entry = cached_entry();
    entry.key = flow.forward_key.clone();

    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry,
        0,
        StageSeed {
            session: Some((900_000, PROTO_TCP, 0x10)),
            flow: Some(flow.clone()),
            install_key: Some(flow.forward_key.clone()),
            ..StageSeed::default()
        },
    );

    assert_eq!(
        run.session_lookup_miss_counts,
        (0, 0, 0),
        "the two routes agree for this frame, so the stage's session lookups \
         must all HIT — no misses of any kind. This is the baseline the red \
         cell below is read against, so it is asserted as the whole tuple \
         rather than one counter"
    );
}

// THE RED CELL — a mismatch the pre-#8262 fixture could not express.
//
// The probe key carries the poll loop's resolved routing domain; the session
// was installed by a path that did NOT apply it. That is the shape of a real
// defect: one of the two routes forgets a mutation the other applies, and the
// 5-tuple is identical, so nothing about the packet looks wrong.
//
// The old fixture could not produce this at all — its install key and probe key
// were one `test_key()` with `routing_domain: 0`, so the field could not differ
// between them whatever else the cell varied.
#[test]
fn a_route_that_skips_the_poll_loop_mutation_is_a_key_mismatch_8262() {
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    with_routing_domain(&mut fixture, 7);
    let frame = vlan_tagged_tcp_v4_frame(0);
    let meta = test_meta(&frame);

    let flow = production_route_flow(&frame, meta, &fixture.forwarding);
    // The divergent route: parsed from the SAME frame, but without the
    // post-parse mutation.
    let unmutated = crate::afxdp::frame::parse_session_flow_from_bytes(&frame, meta)
        .expect("same frame, same parse")
        .forward_key;
    assert_eq!(
        unmutated.routing_domain, 0,
        "precondition: the un-mutated route leaves the domain at 0"
    );
    assert_ne!(
        unmutated, flow.forward_key,
        "precondition: the two routes must actually DIFFER, or this cell is the \
         control with a longer name"
    );

    let mut entry = cached_entry();
    entry.key = flow.forward_key.clone();

    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry,
        0,
        StageSeed {
            session: Some((900_000, PROTO_TCP, 0x10)),
            flow: Some(flow.clone()),
            install_key: Some(unmutated),
            ..StageSeed::default()
        },
    );

    let (no_handle, stale, key_mismatch) = run.session_lookup_miss_counts;
    assert!(
        no_handle > 0,
        "the session was installed under the key ONE production route produced \
         and probed with the key the OTHER produced, so the stage's lookups must \
         MISS. Reading no misses here means the harness cannot see the axis it \
         exists for. counts = {:?}",
        run.session_lookup_miss_counts
    );
    assert_ne!(
        run.session_lookup_miss_counts,
        (0, 0, 0),
        "and the tuple must differ from the agreeing case, which is the whole \
         claim: a key that diverged between the two routes is OBSERVABLE here"
    );

    // MEASURED, and worth recording because it contradicts the obvious guess:
    // a plain divergent key does NOT bump `lookup_miss_key_mismatch`. It misses
    // with NO HANDLE, because the two keys hash to different slots and the
    // probe never resolves a handle to compare a key against. `key_mismatch` is
    // for a RESOLVED handle whose stored key disagrees — slab-handle reuse —
    // which is a different defect entirely.
    //
    // This matters beyond the cell: #7919's cluster reading found
    // `session_lookup_miss_key_mismatch_total` at 0 on every worker, and it
    // would have been easy to read that as "no key divergence anywhere". It is
    // not evidence of that, and this is where the reason is written down.
    assert_eq!(
        (stale, key_mismatch),
        (0, 0),
        "a diverged key misses with NO HANDLE; if it ever starts bumping the \
         stale-handle or key-mismatch counters instead, the note above is stale \
         and the reasoning that rests on it needs re-checking"
    );
}
