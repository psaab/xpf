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
use crate::afxdp::flow_cache::{CachedPolicyDeny, FlowCacheEntry, FlowCacheStamp};
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
            last_queue_id: None,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: EGRESS_IFINDEX,
                tx_ifindex: EGRESS_IFINDEX,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]),
                tx_vlan_id: INGRESS_VLAN_ID,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_TRUST_ZONE_ID,
            egress_zone: TEST_UNTRUST_ZONE_ID,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            // #4983: the cached session was installed from a frame that
            // arrived on {PHYS_INGRESS_IFINDEX, INGRESS_VLAN_ID}, so mirror
            // the same pair the fixture's UserspaceDpMeta carries above --
            // a flow-cache-hit fixture that zeroed it would model a session
            // production cannot install on this path.
            ingress_ifindex: PHYS_INGRESS_IFINDEX as u32,
            ingress_vlan_id: INGRESS_VLAN_ID,
            forward_ingress_vlan_id: None,
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
            nat_scope_ifindex: None,
        },
        stamp: FlowCacheStamp {
            config_generation: 0,
            fib_generation: 0,
            owner_rg_id: 0,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        },
        policy_deny: None,
        deny_expires_at_secs: 0,
        cluster_terminal_source_ifindex: 0,
        cluster_terminal_stamp_owner_rg: 0,
        observed_bytes: 0,
        last_used_epoch: 0,
        neighbor_mac_epoch: 0,
        neighbor_shard: crate::afxdp::flow_cache::NEIGHBOR_SHARD_NONE,
        fabric_established: false,
        dest_owner_memo: Default::default(),
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
    entry.descriptor.ip_csum_delta = crate::afxdp::frame::compute_ip_csum_delta(&flow, &nat);
    entry.descriptor.l4_csum_delta = crate::afxdp::frame::compute_l4_csum_delta(&flow, &nat);
    entry
}

/// #14945 (3): `cached_entry` retargeted at binding 1 (LAN->WAN transit):
/// the cached descriptor AND decision name the distinct egress, so the
/// stage resolves `target_bi = 1` instead of the hairpin binding 0.
fn transit_entry() -> FlowCacheEntry {
    let mut entry = cached_entry();
    entry.descriptor.target_binding_index = Some(1);
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
                tx_pending_kick_descriptors: 0,
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
        scratch_prepared_committed_orig_idx: Vec::new(),
        scratch_prepared_tx_orig_idx: [0; 64],
        scratch_prepared_first_drop_reason: None,
        scratch_prepared_dropped_orig_idx: Vec::new(),
        scratch_dropped_mirror_orig_idx: Vec::new(),
        scratch_exact_prepared_tx: Vec::new(),
        scratch_exact_local_tx: Vec::new(),
        scratch_completed_offsets: Vec::new(),
        scratch_post_recycles: Vec::new(),
        scratch_cross_binding_tx: Vec::new(),
        scratch_rst_teardowns: Vec::new(),
        scratch_rst_trigger_keeps: Vec::new(),
        scratch_filter_revoked_keys: Vec::new(),
        pmech_injected_replay_addrs: Vec::new(),
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
    rg_epochs: [AtomicU32; MAX_RG_EPOCHS],
    /// #16217 (fold B6): fresh RG set handed to `worker_ctx`; tests
    /// override it to prove the cache/session marks judge the fresh
    /// set, not the lagging `ha_state` snapshot.
    fresh_active_rgs: std::collections::BTreeSet<i32>,
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
                        bytes: Vec::new().into(),
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
        forwarding.ingress_logical_ifindex.insert(
            (PHYS_INGRESS_IFINDEX, INGRESS_VLAN_ID),
            LOGICAL_INGRESS_IFINDEX,
        );
        forwarding.connected_v4_by_ifindex.insert(
            LOGICAL_INGRESS_IFINDEX,
            vec![crate::prefix::PrefixV4::from_net(
                "10.0.1.0/24".parse().expect("ingress prefix"),
            )],
        );
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
            pptp_control: Arc::new(crate::session::pptp_control::PptpControlInbox::default()),
            rg_epochs: std::array::from_fn(|_| AtomicU32::new(0)),
            fresh_active_rgs: std::collections::BTreeSet::new(),
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
    /// anything: the default slot map is empty so `slot_of` is 0 for
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
    /// #15941: install a bindless selector fence matching the stock
    /// test tuple (10.0.1.0/24 <-> 172.16.50.0/24) so the cached-hit
    /// fence arm can fire.
    fn with_selector_fence(mut self) -> Self {
        let snapshot = crate::protocol::ConfigSnapshot {
            bindless_selector_fence_enabled: true,
            bindless_selector_rows: vec![crate::protocol::IpsecBindlessSelectorSnapshot {
                local_ts: "10.0.1.0/24".to_string(),
                remote_ts: "172.16.50.0/24".to_string(),
            }],
            ..Default::default()
        };
        self.forwarding.bindless_ipsec_selector_fence =
            crate::afxdp::ipsec_selector_fence::BindlessIpsecSelectorFence::from_snapshot(
                &snapshot,
            )
                .expect("valid selector snapshot");
        self
    }

    /// #16479: enable strict-syn-check on the fixture's forwarding state.
    fn with_strict_syn_check(mut self) -> Self {
        self.forwarding.tcp_strict_syn_check = true;
        self
    }

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
        let (zone_map, zone_caches) = crate::afxdp::zone_slot_counters::ZoneSlotMap::build(
            &[TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID],
            &self.forwarding.zone_counter_store,
            &self.forwarding.flood_counter_store,
        );
        self.forwarding.zone_counter_slot_map = Arc::new(zone_map);
        self.forwarding.zone_counter_caches = Arc::new(zone_caches.clone());
        self.forwarding.flood_counter_caches = Arc::new(zone_caches);
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
            forwarding_active_rgs: &self.fresh_active_rgs,
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
    /// #16220: per-arm eviction tallies, read at the same instant.
    flow_cache_evictions_by_arm: [u64; crate::afxdp::flow_cache::FLOW_CACHE_EVICTION_ARM_COUNT],
    tx_pipeline: WorkerTxPipeline,
    tx_counters: WorkerTxCounters,
    /// #14945 (3): the TARGET binding's pipeline/counters on a
    /// cross-binding transit run; empty/default on hairpin runs.
    target_tx_pipeline: WorkerTxPipeline,
    target_tx_counters: WorkerTxCounters,
    scratch: WorkerScratch,
    mirror_sample_counter: u64,
    /// `telemetry.dbg` after the call. `run_stage` used to build this and drop
    /// it unread, which left `telemetry.dbg.forward += 1` / `.tx += 1` on BOTH
    /// staging arms deletable with the whole module green — an undercounted
    /// forward/tx debug counter on every successful in-place cache hit.
    dbg_forward: u64,
    dbg_tx: u64,
    dbg_policy_deny: u64,
    dbg_disposition_other: u64,
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
    /// #18533: `SessionKey` hashes the stage call performed (flow-cache set
    /// index + session-table index lookups), measured around that call only.
    session_key_hashes: u64,
}

/// Drive the LIVE call site once.
///
/// #6304 fidelity: production slices `raw_frame` straight out of the UMEM
/// (`poll_descriptor/mod.rs`: `area.area().slice(desc.addr, desc.len)`),
/// so `packet_frame` ALIASES the bytes `apply_rewrite_descriptor` then mutates
/// in place (TTL decrement + checksum delta). Handing a heap copy in here
/// instead would decouple the mirror clone from the rewrite and make "the
/// clone carries the PRE-rewrite frame" true for free — the
/// capture-before-rewrite ordering at `flow_cache_hit.rs` would be unbound.
/// The caller's `frame` stays pristine as the comparison value.
fn run_stage(fixture: &LiveCallSiteFixture, frame: &[u8], initial_sample_counter: u64) -> StageRun {
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
                session_close_events_per_second: 0,
                session_close_burst: 0,
                session_create_events_per_second: 0,
                session_create_burst: 0,
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
    /// #16222: validated fabric-stamp ingress (`packet_fabric_ingress`),
    /// distinct from the physical link identity below. Defaults false.
    packet_fabric_ingress: bool,
    /// Physical parent-or-overlay arrival identity for the anti-loop cache
    /// guard. Defaults false for ordinary non-fabric cache fixtures.
    fabric_link_ingress: bool,
    /// #14945 (3): run the stage with a cross-binding target
    /// (`target_bi = 1`), optionally sharing the ingress UMEM.
    cross_umem_shared: Option<bool>,
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
            flow: None,
            tx_headroom: None,
            install_key: None,
            packet_fabric_ingress: false,
            fabric_link_ingress: false,
            cross_umem_shared: None,
            now_ns: 1_000_000,
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
    // #16184: mint the owned handle up front; `raw_frame` borrows
    // from it (the same aliasing the production handle guarantees),
    // so no raw pointer is needed to stage the fixture.
    let area = UmemAreaHandle::from_mmap_area_for_test(area);
    let raw_frame = area
        .area()
        .slice(frame_offset as usize, frame.len())
        .expect("raw frame must ALIAS the UMEM, as it does in production");

    let entry_for_session = entry.clone();
    let mut flow_state = WorkerFlowCacheState {
        flow_cache: FlowCache::new(),
    };
    flow_state.flow_cache.insert(entry);

    // #14945 (3): the ingress UMEM identity the inline gate compares
    // against; a bare mmap area suffices for the hairpin arm, while a
    // cross-binding run clones this handle into the target binding.
    let ingress_umem = WorkerUmem::new_for_test(256).expect("ingress test umem");
    let mut tx_pipeline_state = tx_pipeline();
    if let Some((free_frames, max_pending)) = seed.tx_headroom {
        tx_pipeline_state.free_tx_frames = (0..free_frames as u64).collect();
        tx_pipeline_state.max_pending_tx = max_pending;
    }
    let mut tx_counters_state = tx_counters();
    let mut target_binding = BindingWorker::new_for_mirror_test(1, 0, EGRESS_IFINDEX, 0);
    if seed.cross_umem_shared == Some(true) {
        target_binding.umem = ingress_umem.clone();
    }
    // The target binding keeps its own (fresh) pipeline/counters, so the
    // stage's cross-binding arm writes to the queues asserted on below.
    let mut scratch_state = scratch();
    let mut sessions = SessionTable::new();
    if let Some((install_ns, protocol, tcp_flags)) = seed.session {
        // Install from the CACHED entry's own decision + metadata, so the
        // session the accounting lands on is the one this cached flow
        // describes rather than an unrelated fixture.
        assert!(
            sessions.install_with_protocol(
                seed.install_key
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

    let mut last_learned_neighbor = LearnedNeighborDedup::default();
    // #6304: measure only THIS call. The fixture's own setup pushes (the AtCap
    // precondition, the interleaving-producer probes) go through the same
    // admission primitive, so the reset has to sit immediately before the call
    // and the read immediately after it.
    crate::afxdp::binding_state::pending_tx_admission_attempts_reset();
    let hashes_before = crate::session::SESSION_KEY_HASHES_FOR_TEST.with(|count| count.get());
    let mut inline_tx = InlineTxBindings {
        ingress: InlineTxTarget {
            tx_pipeline: &mut tx_pipeline_state,
            tx_counters: &mut tx_counters_state,
        },
        // Cross-binding runs hand the stage the target as `right[0]`
        // (binding_index 0 -> target_bi 1); hairpin runs keep it out.
        left: &mut [],
        right: if seed.cross_umem_shared.is_some() {
            std::slice::from_mut(&mut target_binding)
        } else {
            &mut []
        },
    };
    let outcome = stage_flow_cache_hit(
        &mut flow_state,
        &mut inline_tx,
        &mut scratch_state,
        &mut mirror_sample_counter,
        &fixture.ingress_live,
        0,
        BINDING_INDEX,
        &ingress_umem,
        desc,
        &area,
        raw_frame,
        &mut owned_packet_frame,
        meta,
        &flow,
        seed.packet_fabric_ingress,
        None,
        seed.fabric_link_ingress,
        false,
        ValidationState::default(),
        &mut sessions,
        seed.now_ns,
        1,
        &fixture.worker_ctx(),
        &mut last_learned_neighbor,
        &mut telemetry,
    );
    let session_key_hashes =
        crate::session::SESSION_KEY_HASHES_FOR_TEST.with(|count| count.get()) - hashes_before;
    let admission_attempts = crate::afxdp::binding_state::pending_tx_admission_attempts();
    // #5190: snapshot the cache tallies BEFORE the observed-bytes probe
    // below — that probe calls `lookup`, which bumps hits/misses itself.
    let flow_cache_tallies = (
        flow_state.flow_cache.hits,
        flow_state.flow_cache.misses,
        flow_state.flow_cache.evictions,
    );
    let flow_cache_evictions_by_arm = flow_state.flow_cache.evictions_by_arm;
    // #6304: lift the staged TX bytes out of the UMEM before the mapping dies
    // with this function's frame.
    let target_tx_frame = target_binding
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .and_then(|prepared| {
            area.area()
                .slice(prepared.offset as usize, prepared.len as usize)
        })
        .map(<[u8]>::to_vec);
    let tx_frame = if seed.cross_umem_shared.is_some() {
        target_tx_frame
    } else {
        tx_pipeline_state
            .pending_tx_prepared
            .front()
            .and_then(|prepared| {
                area.area()
                    .slice(prepared.offset as usize, prepared.len as usize)
            })
            .map(<[u8]>::to_vec)
    };
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
        flow_cache_evictions_by_arm,
        tx_pipeline: tx_pipeline_state,
        tx_counters: tx_counters_state,
        target_tx_pipeline: target_binding.tx_pipeline,
        target_tx_counters: target_binding.tx_counters,
        scratch: scratch_state,
        mirror_sample_counter,
        dbg_forward: dbg.forward,
        dbg_tx: dbg.tx,
        dbg_policy_deny: dbg.policy_deny,
        dbg_disposition_other: dbg.disposition_other,
        admission_attempts,
        counters,
        tx_frame,
        cached_observed_bytes,
        sessions,
        session_key_hashes,
    }
}

/// The resolve-level refused-repair bit is the flow-cache seed gate. Keep the
/// call real enough to construct a cache candidate, then prove `true` leaves
/// no entry behind.
#[test]
fn refused_resolve_install_blocks_flow_cache_seed_10582_r4() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = vlan_tagged_tcp_v4_frame(0);
    let meta = test_meta(&frame);
    let key = test_key();
    let flow = Some(SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    });
    let mut flow_cache = FlowCache::new();
    let next_hop = cached_entry()
        .decision
        .resolution
        .next_hop
        .expect("cached decision carries a next-hop");
    let live_mac = cached_entry()
        .decision
        .resolution
        .neighbor_mac
        .expect("cached decision carries a neighbor MAC");
    fixture.dynamic_neighbors.insert(
        (EGRESS_IFINDEX, next_hop),
        NeighborEntry { mac: live_mac },
    );
    let worker_ctx = fixture.worker_ctx();

    let neighbor_epoch_snapshot = fixture.dynamic_neighbors.snapshot_shard_epochs();
    let policy_counter: Option<Arc<crate::policy::PolicyRuleCounter>> = None;

    stage_flow_cache_seed(
        &mut flow_cache,
        &flow,
        meta,
        ValidationState::default(),
        cached_entry().decision,
        None,
        0,
        Some(TEST_TRUST_ZONE_ID),
        true,
        false,
        0,
        &policy_counter,
        crate::filter::TermMatchExtra::default(),
        None,
        None,
        0,
        0,
        false,
        false,
        &neighbor_epoch_snapshot,
        &worker_ctx,
    );

    assert!(
        flow_cache
            .lookup(
                &key,
                FlowCacheLookup::for_packet(meta, ValidationState::default(), &fixture.forwarding),
                1,
                &fixture.rg_epochs,
            )
            .is_none(),
        "install_failed=true must block flow-cache seeding"
    );

    // Positive control: the same candidate seeds when the resolve did not
    // report a refused install.
    let mut allowed_flow_cache = FlowCache::new();
    stage_flow_cache_seed(
        &mut allowed_flow_cache,
        &flow,
        meta,
        ValidationState::default(),
        cached_entry().decision,
        None,
        0,
        Some(TEST_TRUST_ZONE_ID),
        false,
        false,
        0,
        &policy_counter,
        crate::filter::TermMatchExtra::default(),
        None,
        None,
        0,
        0,
        false,
        false,
        &neighbor_epoch_snapshot,
        &worker_ctx,
    );
    assert!(
        allowed_flow_cache
            .lookup(
                &key,
                FlowCacheLookup::for_packet(meta, ValidationState::default(), &fixture.forwarding),
                1,
                &fixture.rg_epochs,
            )
            .is_some(),
        "install_failed=false must allow the ordinary flow-cache seed"
    );
}
/// #17031 (Rev18320 M1): `stage_flow_cache_seed` must actually stamp a
/// promoted ambiguous claim, and must NOT stamp it when the owner RG is
/// not locally active. Before the fold every seed caller passed
/// `ambiguous_zone: None`, so dropping the new parameter (or passing the
/// scope ifindex's zone instead) stayed green.
///
/// Scope: this is FUNCTION-LEVEL coverage only. This cell drives
/// `stage_flow_cache_seed` directly and supplies `Some(CLAIMED_ZONE)`
/// itself, so it cannot observe what the descriptor passes at its
/// stage-9 call site. That production wiring is pinned separately by
/// `stage9_descriptor_forwards_ambiguous_zone_to_flow_cache_seed_17031`
/// below — a structural source assertion that stage-9 forwards the
/// in-scope `ambiguous_zone` variable (not `None`) in the seed's
/// `ambiguous_zone` parameter position.
///
/// FAIL-ON-REVERT: reverting `stage_flow_cache_seed` to raw-only
/// (ignoring `ambiguous_zone`) reds the active half (entry stays
/// unstamped / fabric-zone 0); stamping the claim ungated reds the
/// inactive half (claimed zone appears despite no local owner proof).
#[test]
fn flow_cache_seed_promotes_ambiguous_zone_only_when_owner_active_17031() {
    // Distinct claimed zone so a stamp cannot be confused with the
    // fixture's trust/untrust zones or with a raw override.
    const CLAIMED_ZONE: u32 = TEST_DMZ_ZONE_ID;
    let now_secs: u64 = 1;

    for (rg_active, expect_stamped) in [(true, true), (false, false)] {
        let mut fixture =
            LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
        // Owner RG of the cached decision's egress (EGRESS_IFINDEX) is RG1.
        fixture
            .forwarding
            .egress
            .get_mut(&EGRESS_IFINDEX)
            .expect("zone-accounting fixture seeds the egress")
            .redundancy_group = 1;
        // The logical ingress (20080) carries no zone, so without a
        // stamped override the seed's from-zone resolves to 0 and
        // nothing is stamped — the NOT-stamped assertion is therefore
        // discriminating, not vacuous.
        assert_eq!(
            fixture
                .forwarding
                .ifindex_to_zone_id
                .get(&LOGICAL_INGRESS_IFINDEX),
            None,
            "precondition: logical ingress must be unzoned"
        );
        if rg_active {
            fixture.ha_state.insert(
                1,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: now_secs,
                    lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
                },
            );
        }
        let frame = vlan_tagged_tcp_v4_frame(0);
        let meta = test_meta(&frame);
        let key = test_key();
        let flow = Some(SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key.clone(),
        });
        let next_hop = cached_entry()
            .decision
            .resolution
            .next_hop
            .expect("cached decision carries a next-hop");
        let live_mac = cached_entry()
            .decision
            .resolution
            .neighbor_mac
            .expect("cached decision carries a neighbor MAC");
        fixture
            .dynamic_neighbors
            .insert((EGRESS_IFINDEX, next_hop), NeighborEntry { mac: live_mac });
        let worker_ctx = fixture.worker_ctx();
        let neighbor_epoch_snapshot = fixture.dynamic_neighbors.snapshot_shard_epochs();
        let policy_counter: Option<Arc<crate::policy::PolicyRuleCounter>> = None;
        let mut flow_cache = FlowCache::new();
        stage_flow_cache_seed(
            &mut flow_cache,
            &flow,
            meta,
            ValidationState::default(),
            cached_entry().decision,
            None,
            0,
            // session_ingress_zone=None so from_forward_decision leaves
            // metadata.ingress_zone == 0 and the seed stamp block runs.
            None,
            false,
            false,
            0,
            &policy_counter,
            crate::filter::TermMatchExtra::default(),
            // raw proved override: none — the claim arrives ambiguous only.
            None,
            Some(CLAIMED_ZONE),
            now_secs,
            0,
            false,
            false,
            &neighbor_epoch_snapshot,
            &worker_ctx,
        );
        let entry = flow_cache
            .lookup(
                &key,
                FlowCacheLookup::for_packet(meta, ValidationState::default(), &fixture.forwarding),
                1,
                &fixture.rg_epochs,
            )
            .expect("seed must install a flow-cache entry in both halves");
        if expect_stamped {
            assert_eq!(
                entry.metadata.ingress_zone, CLAIMED_ZONE,
                "#17031: active owner RG must promote the ambiguous claim \
                 into the seed's stamped ingress_zone"
            );
        } else {
            assert_eq!(
                entry.metadata.ingress_zone, 0,
                "#17031: inactive owner RG must NOT stamp the ambiguous \
                 claim (fabric/unzoned ingress governs, zone 0)"
            );
            assert_ne!(
                entry.metadata.ingress_zone, CLAIMED_ZONE,
                "#17031: unpromoted claim must never appear as the stamp"
            );
        }
    }
}

/// #17031 (Rev18320 round 2/3): structural pin for the descriptor stage-9
/// wiring that the function-level seed cell above cannot observe. The
/// seed cell supplies `Some(CLAIMED_ZONE)` itself, so production could
/// regress to passing `None` at `mod.rs` stage-9 -> `stage_flow_cache_seed`
/// and that cell would stay green; this source assertion reds that exact
/// regression.
///
/// STRUCTURAL, not raw-text (round 3): comments and string/char literal
/// bodies are blanked with the shared #17152 helper first, then the one
/// whole-identifier `stage_flow_cache_seed` call is extracted by
/// balanced-paren matching and its argument list is split only on
/// depth-0 commas. The round-2 guard split the raw text on the callee
/// name and on `,`/`);`, so a 21-argument decoy written inside a string
/// satisfied it while the real call passed `None` — a false green,
/// proven in review. A decoy in prose or a literal is blanked before
/// matching and can no longer satisfy (or duplicate) this guard; only
/// the actual call expression is inspected. The crate has no direct
/// `syn` dev-dependency, so this token-level matcher follows the
/// established `blank_comments_and_strings` + depth-0 segment pattern
/// (`protocol::cos_literal_guard_7689`, `afxdp::session_glue` scans).
///
/// FAIL-ON-REVERT: changing the stage-9 argument in the
/// `ambiguous_zone` position (index 14, between `ingress_zone_override`
/// and `now_secs`) from `ambiguous_zone` to `None` reds this cell, as
/// does planting a decoy call in a string/comment while doing so.
#[test]
fn stage9_descriptor_forwards_ambiguous_zone_to_flow_cache_seed_17031() {
    use crate::test_support::source_scan::blank_comments_and_strings;

    let src = include_str!("mod.rs");
    let code = blank_comments_and_strings(src);
    let bytes = code.as_bytes();
    let needle = "stage_flow_cache_seed";
    let mut call_args: Vec<Vec<String>> = Vec::new();
    let mut from = 0usize;
    while let Some(hit) = code[from..].find(needle) {
        let start = from + hit;
        let after_name = start + needle.len();
        from = after_name;
        let ident_byte = |b: &u8| b.is_ascii_alphanumeric() || *b == b'_';
        let before_ok = start == 0 || !ident_byte(&bytes[start - 1]);
        let after_ok = !bytes.get(after_name).is_some_and(ident_byte);
        if !before_ok || !after_ok {
            continue;
        }
        let mut open = after_name;
        while open < bytes.len() && bytes[open].is_ascii_whitespace() {
            open += 1;
        }
        if bytes.get(open) != Some(&b'(') {
            continue;
        }
        // Do not mistake a function declaration's parameter list for a call.
        let before = code[..start].trim_end();
        if before
            .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
            .next()
            == Some("fn")
        {
            continue;
        }
        // Balanced-paren extraction of THIS call's argument list: nested
        // calls/groups cannot terminate it early at an inner `)`/`;`.
        let mut depth = (0i32, 0i32, 0i32);
        let mut close = None;
        for i in open..bytes.len() {
            match bytes[i] {
                b'(' => depth.0 += 1,
                b')' => {
                    depth.0 -= 1;
                    if depth == (0, 0, 0) {
                        close = Some(i);
                        break;
                    }
                }
                b'[' => depth.1 += 1,
                b']' => depth.1 -= 1,
                b'{' => depth.2 += 1,
                b'}' => depth.2 -= 1,
                _ => {}
            }
        }
        let close = close.expect(
            "#17031: stage_flow_cache_seed call in poll_descriptor/mod.rs \
             has unbalanced parentheses; cannot pin its wiring",
        );
        // Split only on depth-0 commas, so commas inside a nested
        // argument expression never shift the pinned positions.
        let mut args: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut depth = (0i32, 0i32, 0i32);
        for ch in code[open + 1..close].chars() {
            match ch {
                '(' => depth.0 += 1,
                ')' => depth.0 -= 1,
                '[' => depth.1 += 1,
                ']' => depth.1 -= 1,
                '{' => depth.2 += 1,
                '}' => depth.2 -= 1,
                _ => {}
            }
            if ch == ',' && depth == (0, 0, 0) {
                args.push(std::mem::take(&mut cur));
            } else {
                cur.push(ch);
            }
        }
        args.push(cur);
        let args: Vec<String> = args
            .iter()
            .map(|arg| arg.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|arg| !arg.is_empty())
            .collect();
        call_args.push(args);
    }
    assert_eq!(
        call_args.len(),
        1,
        "#17031: expected exactly ONE production stage_flow_cache_seed call \
         in poll_descriptor/mod.rs (comments/strings blanked); found {}; a \
         second call site needs its own ambiguous_zone wiring argument \
         before this guard can speak for it",
        call_args.len()
    );
    let args = &call_args[0];
    assert_eq!(
        args.len(),
        21,
        "#17031: stage_flow_cache_seed call arity drifted; re-pin the \
         ambiguous_zone position before trusting the index assertions: {args:?}"
    );
    assert_eq!(
        args[13], "ingress_zone_override",
        "#17031: argument before the ambiguous position must be the raw \
         proved override (position drift?): {args:?}"
    );
    assert_eq!(
        args[14], "ambiguous_zone",
        "#17031: descriptor stage-9 must forward the in-scope \
         ambiguous_zone variable into stage_flow_cache_seed (not None); \
         found {:?}",
        args[14]
    );
    assert_eq!(
        args[15], "now_secs",
        "#17031: argument after the ambiguous position must be now_secs \
         (position drift?): {args:?}"
    );
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
    unsafe { fixture.target_live.take_pending_tx_into(&mut queued) };
    assert!(
        queued.is_empty(),
        "#6304: a NON-sampled packet must not enqueue a clone on the mirror \
         target — the target had ROOM, so a call site that DROPPED the sampler \
         and cloned unconditionally lands a real frame here. (Reserve-before- \
         sample does NOT land one: it still consults the sampler and hands the \
         reservation back, which is why that mutation needs the attempt count.)"
    );
    assert_eq!(
        fixture
            .ingress_live
            .mirrored_packets
            .load(Ordering::Relaxed),
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
        fixture
            .ingress_live
            .mirrored_packets
            .load(Ordering::Relaxed),
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
        fixture
            .ingress_live
            .mirrored_packets
            .load(Ordering::Relaxed),
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
    unsafe { fixture.target_live.take_pending_tx_into(&mut queued) };
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
    unsafe { fixture.target_live.take_pending_tx_into(&mut queued) };
    assert!(
        queued.is_empty(),
        "#6304: the reserved admission is released, not spent — no clone reaches \
         the target from the declined fast path"
    );
    assert_eq!(
        fixture
            .ingress_live
            .mirrored_packets
            .load(Ordering::Relaxed),
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
        admitted
            .ingress_live
            .mirrored_packets
            .load(Ordering::Relaxed),
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
    unsafe { admitted.target_live.take_pending_tx_into(&mut queued) };
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
        bytes: vec![0x5a; 64].into(),
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
    assert_eq!(
        frame[18] & 0x0f,
        15,
        "the IHL nibble the rollback frame fakes"
    );
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
/// #18533: an admitted steady-state ESTABLISHED cache hit at the live call
/// site hashes the flow key exactly twice: the flow-cache set index and the
/// session table's record lookup. Gone from every packet: the #16217
/// pre-lookup `peek_entry` (a second set hash and way scan) and the
/// session lookups the #15947 eager undo, #16042 expected ack and #16223
/// stamp snapshots added to the deferring probe and its admission emit.
#[test]
fn live_established_cache_hit_hashes_the_flow_key_twice_18533() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let run = run_stage(&fixture, &tcp_v4_ack_frame(), 0);
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "premise: the packet is served from the cache"
    );
    assert_eq!(run.flow_cache_tallies.0, 1, "premise: one served hit");
    assert_eq!(
        run.sessions.handshake_state_wire_for(&test_key()),
        crate::session::TcpHandshakeState::Established.to_wire(),
        "premise: the backing session is steady-state established"
    );
    assert_eq!(
        run.session_key_hashes, 2,
        "flow-cache set index + session record lookup, and nothing else"
    );
}

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
    assert_eq!(in_place.dbg_tx, 1, "#6304: ...and one TX, on the same arm");

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

    crate::filter::flush_recorded_filter_counters();
    crate::policy::flush_recorded_policy_hit_counters();
    // --- THE DISCRIMINATOR.
    assert_eq!(
        counter.test_packet_count(),
        1,
        "#6304/#3073: an established-session packet served from the flow cache \
         must be re-counted against the admitting policy's hit counter; without \
         it `show security policies hit-count` reports only each flow's first \
         frame"
    );
    crate::filter::flush_recorded_filter_counters();
    crate::policy::flush_recorded_policy_hit_counters();
    assert_eq!(
        counter.test_byte_count(),
        frame.len() as u64,
        "#6304/#3073: ...charged the FULL wire length the shim reported, not a \
         stripped or zero byte count"
    );
    // #14656: counters are coalesced per-thread in every build; flush before asserting.
    // #14656: counters are coalesced per-thread in every build; flush before asserting.
}

/// #6304 (#3651 per-zone traffic volume). `record_zone_traffic` at
/// `flow_cache_hit.rs` also DELETES with the whole crate green — measured, same
/// run. Third instance of the same class in this module, and the reason the
/// sweep was run over every `record_*` call rather than the one that was
/// reported.
///
/// Here the call RAN on every fixture and did nothing: with an empty
/// slot map and `EGRESS_IFINDEX` absent from `forwarding.egress`,
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
    let (discard_map, discard_caches) = crate::afxdp::zone_slot_counters::ZoneSlotMap::build(
        &[TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID],
        &discard,
        &crate::afxdp::flood_counters::FloodCounterStore::default(),
    );
    crate::afxdp::zone_counters::flush_recorded_zone_counters(
        &discard,
        &discard_map,
        &discard_caches,
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
        &fixture.forwarding.zone_counter_caches,
    );
    let rows = crate::afxdp::zone_counters::zone_counter_snapshot(&fixture.forwarding.zone_counter_store);

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
/// #12865 (D6-06): the zone counters must credit the zones the packet was
/// adjudicated under (`cached_metadata`), not the raw shim stamp. A zero shim
/// zone is reachable on an unzoned fabric parent or contested VLAN parent.
/// Pre-fix this call passes `meta.ingress_zone` (0, skipped), losing the
/// ingress contribution despite the cached session's admitted trust zone.
#[test]
fn live_flow_cache_callsite_accounts_metadata_ingress_zone_12865() {
    let discard = crate::afxdp::zone_counters::ZoneCounterStore::default();
    let (discard_map, discard_caches) = crate::afxdp::zone_slot_counters::ZoneSlotMap::build(
        &[TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID],
        &discard,
        &crate::afxdp::flood_counters::FloodCounterStore::default(),
    );
    crate::afxdp::zone_counters::flush_recorded_zone_counters(
        &discard,
        &discard_map,
        &discard_caches,
    );
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    let frame = tcp_v4_ack_frame();
    let mut meta = test_meta(&frame);
    meta.ingress_zone = 0;
    let run = run_stage_with_meta(&fixture, &frame, meta, 0);
    assert_eq!(run.tx_counters.pending_in_place_tx_packets, 1);
    crate::afxdp::zone_counters::flush_recorded_zone_counters(
        &fixture.forwarding.zone_counter_store,
        &fixture.forwarding.zone_counter_slot_map,
        &fixture.forwarding.zone_counter_caches,
    );
    let rows = crate::afxdp::zone_counters::zone_counter_snapshot(&fixture.forwarding.zone_counter_store);
    let ingress = rows.iter().find(|r| r.zone_id == TEST_TRUST_ZONE_ID).expect(
        "#12865: ingress must be credited to cached_metadata.ingress_zone (trust), not raw meta.ingress_zone=0",
    );
    assert_eq!(
        (ingress.ingress_packets, ingress.ingress_bytes),
        (1, frame.len() as u64)
    );
    let egress = rows
        .iter()
        .find(|r| r.zone_id == TEST_UNTRUST_ZONE_ID)
        .expect("#12865: normal egress zone remains credited");
    assert_eq!(
        (egress.egress_packets, egress.egress_bytes),
        (1, frame.len() as u64)
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
        crate::filter::flush_recorded_filter_counters();
        crate::policy::flush_recorded_policy_hit_counters();
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
    crate::filter::flush_recorded_filter_counters();
    crate::policy::flush_recorded_policy_hit_counters();
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
    // #14656: counters are coalesced per-thread in every build; flush before asserting.
    // #14656: counters are coalesced per-thread in every build; flush before asserting.
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
        tos,
        PKT_DSCP << 2,
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
            l4_present: true,
            source: FilterLogSource::Input,
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

fn cached_deny_entry(
    disposition: ForwardingDisposition,
    policy_deny: Option<CachedPolicyDeny>,
) -> FlowCacheEntry {
    let mut entry = logging_cached_entry(true, false);
    entry.decision.resolution.disposition = disposition;
    entry.decision.resolution.next_hop = None;
    entry.decision.resolution.neighbor_mac = None;
    entry.decision.resolution.src_mac = None;
    if let Some(deny) = policy_deny {
        entry.metadata.policy_id = deny.policy_id;
    }
    entry.policy_deny = policy_deny;
    entry.deny_expires_at_secs = 3;
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
        event.ingress_zone_id, TEST_TRUST_ZONE_ID as u16,
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

/// #10314: a cached FabricRedirect is not admissible for a physical
/// parent/overlay arrival, even when the packet has no validated stamp.
#[test]
fn fabric_arrival_invalidates_cached_fabric_redirect_10314() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = vlan_tagged_tcp_v4_frame(0);
    let meta = test_meta(&frame);
    let mut entry = cached_entry();
    entry.descriptor.fabric_redirect = true;
    entry.decision.resolution.disposition = ForwardingDisposition::FabricRedirect;

    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry,
        0,
        StageSeed {
            fabric_link_ingress: true,
            ..StageSeed::default()
        },
    );

    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "parent/overlay arrival must not serve a cached FabricRedirect"
    );
    assert!(
        run.scratch.scratch_forwards.is_empty(),
        "cache invalidation must not enqueue the cached fabric redirect"
    );
}
/// #16222: a fabric-stamp-ingress hit on a cached FabricRedirect whose
/// stamp owner is the LAN RG (2) must be SERVED, not evicted as
/// different-owner FabricLocalWins. Decision-level ECMP/different-owner
/// semantics are pinned in forwarding::tests::*_16222; this binds the
/// stage wiring (per-flow entry point + fabric flag threading).
#[test]
fn fabric_stamp_ingress_serves_cached_redirect_16222() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = vlan_tagged_tcp_v4_frame(0);
    let meta = test_meta(&frame);
    let mut entry = cached_entry();
    entry.descriptor.fabric_redirect = true;
    entry.decision.resolution.disposition = ForwardingDisposition::FabricRedirect;
    entry.decision.resolution.egress_ifindex = EGRESS_IFINDEX;
    entry.stamp.owner_rg_id = 2;
    entry.metadata.owner_rg_id = 2;
    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry,
        0,
        StageSeed {
            packet_fabric_ingress: true,
            ..StageSeed::default()
        },
    );
    let arm = crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitFabricLocalWins as usize;
    assert_eq!(
        run.flow_cache_evictions_by_arm[arm], 0,
        "fabric-stamp ingress must not evict as different-owner FabricLocalWins"
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "second packet on fabric ingress must be served from cache"
    );
}

/// #16222 round 2: the fw0-seeded shape at stage level — DIRECT member
/// ingress (both fabric flags false), cached FabricRedirect, stamp owner
/// RG2 != WAN RG1. Round 1 retained only on fabric ingress, so this hit
/// evicted as PostHitFabricLocalWins per packet on fw0. Option B must
/// serve the second packet with the FabricLocalWins arm at 0.
#[test]
fn direct_member_ingress_serves_cached_redirect_owner_mismatch_16222() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = vlan_tagged_tcp_v4_frame(0);
    let meta = test_meta(&frame);
    let mut entry = cached_entry();
    entry.descriptor.fabric_redirect = true;
    entry.decision.resolution.disposition = ForwardingDisposition::FabricRedirect;
    entry.decision.resolution.egress_ifindex = EGRESS_IFINDEX;
    entry.stamp.owner_rg_id = 2;
    entry.metadata.owner_rg_id = 2;
    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry,
        0,
        StageSeed {
            packet_fabric_ingress: false,
            fabric_link_ingress: false,
            ..StageSeed::default()
        },
    );
    let arm = crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitFabricLocalWins as usize;
    assert_eq!(
        run.flow_cache_evictions_by_arm[arm], 0,
        "direct-member ingress must not evict as different-owner FabricLocalWins (fw0 shape)"
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "second packet on direct member ingress must be served from cache"
    );
}

/// #18566 stage wiring: a direct-ingress hit on a cached FabricRedirect whose
/// destination's connected owner (RG2) is now active here falls through to
/// the slow path, attributed to its own eviction arm, instead of being served
/// back over the fabric to a peer that no longer owns RG2. The stamp owner is
/// RG1 (also active here, so the re-homed entry would be kept), and no lookup
/// fence touches the entry. RED on revert of the FabricRedirect branch in the
/// validator (outcome Consumed, arm 0) and on folding the arm back into the
/// owner-active-redirect counter.
#[test]
fn direct_ingress_redirect_to_now_local_destination_falls_through_18566() {
    const LAN_UNIT_IFINDEX: i32 = 41;
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    fixture.forwarding.connected_v4_by_ifindex.insert(
        LAN_UNIT_IFINDEX,
        vec![crate::prefix::PrefixV4::from_net(
            "172.16.50.0/24".parse().expect("destination prefix"),
        )],
    );
    // The FIB's connected row too, so the slow path's fresh answer is the
    // LAN unit (MissingNeighbor before the neighbor resolves) and the arm's
    // agreement check sees a re-home.
    fixture.forwarding.connected_v4.push(crate::afxdp::ConnectedRouteV4 {
        prefix: crate::prefix::PrefixV4::from_net("172.16.50.0/24".parse().expect("destination prefix")),
        host: std::net::Ipv4Addr::new(172, 16, 50, 1),
        ifindex: LAN_UNIT_IFINDEX,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    fixture.forwarding.egress.insert(
        LAN_UNIT_IFINDEX,
        EgressInterface {
            bind_ifindex: LAN_UNIT_IFINDEX,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x02, 0x00, 0x01],
            zone_id: TEST_UNTRUST_ZONE_ID,
            redundancy_group: 2,
            primary_v4: None,
            primary_v6: None,
        },
    );
    let now_secs = monotonic_nanos() / 1_000_000_000;
    for rg in [1, 2] {
        fixture.ha_state.insert(
            rg,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: now_secs,
                lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
            },
        );
    }
    assert_eq!(
        crate::afxdp::session_glue::connected_owner_rg_for_target_in_table(
            &fixture.forwarding,
            test_key().dst_ip,
            None,
        ),
        2,
        "premise: the cached flow's destination is connected on the RG2 unit"
    );
    let frame = vlan_tagged_tcp_v4_frame(0);
    let meta = test_meta(&frame);
    let mut entry = cached_entry();
    entry.descriptor.fabric_redirect = true;
    entry.decision.resolution.disposition = ForwardingDisposition::FabricRedirect;
    entry.decision.resolution.egress_ifindex = EGRESS_IFINDEX;
    entry.stamp.owner_rg_id = 1;
    entry.metadata.owner_rg_id = 1;
    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry,
        0,
        StageSeed {
            packet_fabric_ingress: false,
            fabric_link_ingress: false,
            ..StageSeed::default()
        },
    );
    let arm =
        crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitFabricRedirectDestinationNowLocal as usize;
    assert_eq!(
        run.flow_cache_evictions_by_arm[arm], 1,
        "the stale redirect must be evicted under its own #18566 arm"
    );
    let owner_active =
        crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitOwnerActiveRedirect as usize;
    assert_eq!(
        run.flow_cache_evictions_by_arm[owner_active], 0,
        "and not hidden under the owner-active-redirect arm"
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "the stale redirect must not be served"
    );
    assert!(
        run.scratch.scratch_forwards.is_empty(),
        "nothing may be queued toward the fabric"
    );
}

#[test]
fn cached_martian_source_is_dropped_before_forward_side_effects_10689() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let source = Ipv4Addr::LOCALHOST;
    let mut frame = tcp_v4_ack_frame();
    frame[30..34].copy_from_slice(&source.octets());
    let mut meta = test_meta(&frame);
    meta.flow_src_addr[..4].copy_from_slice(&source.octets());

    let mut key = test_key();
    key.src_ip = IpAddr::V4(source);
    let mut entry = cached_entry();
    entry.key = key.clone();
    let flow = SessionFlow {
        src_ip: IpAddr::V4(source),
        dst_ip: key.dst_ip,
        forward_key: key,
    };
    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry,
        0,
        StageSeed {
            flow: Some(flow),
            ..StageSeed::default()
        },
    );

    assert_eq!(
        run.flow_cache_tallies,
        (1, 0, 0),
        "must be a real cache hit"
    );
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed));
    assert_eq!(run.scratch.scratch_recycle.len(), 1);
    assert!(run.scratch.scratch_forwards.is_empty());
    assert!(run.tx_pipeline.pending_tx_prepared.is_empty());
    assert_eq!(run.dbg_forward, 0);
    assert_eq!(run.dbg_tx, 0);
    assert_eq!(
        run.counters.transit_source_martian_drops, 1,
        "#15941 source-martian named counter"
    );
    assert_eq!(
        run.sessions.len(),
        1,
        "the gate must preserve the live session"
    );
}

#[test]
fn cached_martian_destination_is_dropped_before_forward_side_effects_11413() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let destination = Ipv4Addr::new(224, 0, 0, 1);
    let mut frame = tcp_v4_ack_frame();
    frame[34..38].copy_from_slice(&destination.octets());
    let mut meta = test_meta(&frame);
    meta.flow_dst_addr[..4].copy_from_slice(&destination.octets());

    let mut key = test_key();
    key.dst_ip = IpAddr::V4(destination);
    let mut entry = cached_entry();
    entry.key = key.clone();
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key,
    };
    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry,
        0,
        StageSeed {
            flow: Some(flow),
            ..StageSeed::default()
        },
    );

    assert_eq!(
        run.flow_cache_tallies,
        (1, 0, 0),
        "must be a real cache hit"
    );
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed));
    assert_eq!(run.scratch.scratch_recycle.len(), 1);
    assert!(run.scratch.scratch_forwards.is_empty());
    assert!(run.tx_pipeline.pending_tx_prepared.is_empty());
    assert_eq!(run.dbg_forward, 0);
    assert_eq!(run.dbg_tx, 0);
    assert_eq!(run.counters.martian_dropped, 1);
    assert_eq!(
        run.sessions.len(),
        1,
        "the gate must preserve the live session"
    );
}

/// #10854: the admitted cache-hit learn must retain the original RX source MAC
/// even though the same-binding fast path rewrites the Ethernet source to the
/// router's egress MAC in place.
#[test]
fn admitted_cache_hit_learns_original_rx_source_mac_after_in_place_rewrite() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let packet_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mut frame = tcp_v4_ack_frame();
    frame[6..12].copy_from_slice(&packet_mac);
    let egress_mac = cached_entry().descriptor.src_mac;
    let run = run_stage(&fixture, &frame, 0);

    assert_eq!(
        run.flow_cache_tallies,
        (1, 0, 0),
        "must be a real cache hit"
    );
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed));
    let tx_frame = run
        .tx_frame
        .expect("same-binding hit must stage an in-place TX frame");
    assert_eq!(
        &tx_frame[6..12],
        &egress_mac,
        "the egress rewrite must change the live UMEM source MAC",
    );
    let key = test_key().src_ip;
    assert_eq!(
        fixture
            .dynamic_neighbors
            .get(&(PHYS_INGRESS_IFINDEX, key))
            .map(|entry| entry.mac),
        Some(packet_mac),
        "the neighbor map must learn the original source MAC, not the rewritten router MAC",
    );
    assert_eq!(
        fixture
            .dynamic_neighbors
            .get(&(LOGICAL_INGRESS_IFINDEX, key))
            .map(|entry| entry.mac),
        Some(packet_mac),
        "the logical VLAN neighbor key must learn the original source MAC too",
    );
}

/// #11315: a missing live neighbor must not let a stale session decision
/// seed a flow-cache entry with the fresh epoch. FAILED/INCOMPLETE removes the
/// binding, then the first learn after removal does not bump the shard epoch.
/// A stale decision must remain uncacheable before and after that first learn.
#[test]
fn flow_cache_seed_refuses_stale_neighbor_mac_11315() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = vlan_tagged_tcp_v4_frame(0);
    let meta = test_meta(&frame);
    let key = test_key();
    let flow = Some(SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    });
    let stale_decision = cached_entry().decision;
    let next_hop = stale_decision
        .resolution
        .next_hop
        .expect("cached decision carries a next-hop");
    let mac_a = stale_decision
        .resolution
        .neighbor_mac
        .expect("cached decision carries neighbor MAC A");
    let mac_b = [0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b];
    fixture
        .dynamic_neighbors
        .insert((EGRESS_IFINDEX, next_hop), NeighborEntry { mac: mac_a });
    assert!(
        fixture
            .dynamic_neighbors
            .remove_if_present(&(EGRESS_IFINDEX, next_hop)),
        "fixture precondition: FAILED/INCOMPLETE removes a present binding"
    );
    let missing_neighbor_snapshot = fixture.dynamic_neighbors.snapshot_shard_epochs();
    let epoch_before_first_learn = missing_neighbor_snapshot.epoch_for(&(EGRESS_IFINDEX, next_hop));
    let worker_ctx = fixture.worker_ctx();
    let policy_counter: Option<Arc<crate::policy::PolicyRuleCounter>> = None;
    let seed =
        |cache: &mut FlowCache,
         decision: SessionDecision,
         neighbor_epoch_snapshot: &crate::afxdp::sharded_neighbor::ShardEpochSnapshot| {
            stage_flow_cache_seed(
                cache,
                &flow,
                meta,
                ValidationState::default(),
                decision,
                None,
                0,
                Some(TEST_TRUST_ZONE_ID),
                false,
                false,
                0,
                &policy_counter,
                crate::filter::TermMatchExtra::default(),
                None,
                None,
                0,
                0,
                false,
                false,
                neighbor_epoch_snapshot,
                &worker_ctx,
            );
        };
    let lookup_present = |cache: &mut FlowCache| {
        cache
            .lookup(
                &key,
                FlowCacheLookup::for_packet(meta, ValidationState::default(), &fixture.forwarding),
                1,
                &fixture.rg_epochs,
            )
            .is_some()
    };

    let mut absent_cache = FlowCache::new();
    seed(
        &mut absent_cache,
        stale_decision.clone(),
        &missing_neighbor_snapshot,
    );
    assert!(
        !lookup_present(&mut absent_cache),
        "a stale-MAC decision must not seed while its neighbor is absent"
    );

    // The first learn after removal does not advance the shard epoch.
    fixture
        .dynamic_neighbors
        .insert_if_changed((EGRESS_IFINDEX, next_hop), NeighborEntry { mac: mac_b });
    let live_neighbor_snapshot = fixture.dynamic_neighbors.snapshot_shard_epochs();
    assert_eq!(
        live_neighbor_snapshot.epoch_for(&(EGRESS_IFINDEX, next_hop)),
        epoch_before_first_learn,
        "a first learn must not bump the shard epoch"
    );

    let mut stale_cache = FlowCache::new();
    seed(&mut stale_cache, stale_decision, &live_neighbor_snapshot);
    assert!(
        !lookup_present(&mut stale_cache),
        "a stale-MAC decision must not seed after the first learn either"
    );

    let mut fresh_decision = cached_entry().decision;
    fresh_decision.resolution.neighbor_mac = Some(mac_b);
    let mut fresh_cache = FlowCache::new();
    seed(&mut fresh_cache, fresh_decision, &live_neighbor_snapshot);
    assert!(
        lookup_present(&mut fresh_cache),
        "a live-MAC decision must still seed the flow cache"
    );
}
/// #11315 v6 twin: after FAILED/INCOMPLETE removal, a stale IPv6 decision
/// must not be re-stamped before or after the first neighbor learn.
#[test]
fn flow_cache_seed_refuses_stale_neighbor_mac_v6_11315() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let src: IpAddr = "2001:db8:1::100".parse().unwrap();
    let dst: IpAddr = "2001:db8:1::200".parse().unwrap();
    let next_hop: IpAddr = "2001:db8:1::1".parse().unwrap();
    let key = crate::session::SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: src,
        dst_ip: dst,
        src_port: 45678,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let flow = Some(SessionFlow {
        src_ip: src,
        dst_ip: dst,
        forward_key: key.clone(),
    });
    let mut src_addr = [0u8; 16];
    src_addr.copy_from_slice(&match src {
        IpAddr::V6(ip) => ip.octets(),
        _ => unreachable!(),
    });
    let mut dst_addr = [0u8; 16];
    dst_addr.copy_from_slice(&match dst {
        IpAddr::V6(ip) => ip.octets(),
        _ => unreachable!(),
    });
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: PHYS_INGRESS_IFINDEX as u32,
        ingress_vlan_id: INGRESS_VLAN_ID,
        ingress_vlan_present: 1,
        l3_offset: 18,
        l4_offset: 58,
        payload_offset: 78,
        pkt_len: 78,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        flow_src_addr: src_addr,
        flow_dst_addr: dst_addr,
        flow_src_port: key.src_port,
        flow_dst_port: key.dst_port,
        ..UserspaceDpMeta::default()
    };
    let mac_a = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mac_b = [0x00, 0x11, 0x22, 0x33, 0x44, 0x66];
    fixture
        .dynamic_neighbors
        .insert((EGRESS_IFINDEX, next_hop), NeighborEntry { mac: mac_a });
    assert!(
        fixture
            .dynamic_neighbors
            .remove_if_present(&(EGRESS_IFINDEX, next_hop)),
        "fixture precondition: FAILED/INCOMPLETE removes a present v6 binding"
    );
    let missing_neighbor_snapshot = fixture.dynamic_neighbors.snapshot_shard_epochs();
    let epoch_before_first_learn = missing_neighbor_snapshot.epoch_for(&(EGRESS_IFINDEX, next_hop));
    let decision = |mac| SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: EGRESS_IFINDEX,
            tx_ifindex: EGRESS_IFINDEX,
            tunnel_endpoint_id: 0,
            next_hop: Some(next_hop),
            neighbor_mac: Some(mac),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]),
            tx_vlan_id: INGRESS_VLAN_ID,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let worker_ctx = fixture.worker_ctx();
    let policy_counter: Option<Arc<crate::policy::PolicyRuleCounter>> = None;
    let seed =
        |cache: &mut FlowCache,
         d: SessionDecision,
         neighbor_epoch_snapshot: &crate::afxdp::sharded_neighbor::ShardEpochSnapshot| {
            stage_flow_cache_seed(
                cache,
                &flow,
                meta,
                ValidationState::default(),
                d,
                None,
                0,
                Some(TEST_TRUST_ZONE_ID),
                false,
                false,
                0,
                &policy_counter,
                crate::filter::TermMatchExtra::default(),
                None,
                None,
                0,
                0,
                false,
                false,
                neighbor_epoch_snapshot,
                &worker_ctx,
            );
        };
    let lookup_present = |cache: &mut FlowCache| {
        cache
            .lookup(
                &key,
                FlowCacheLookup::for_packet(meta, ValidationState::default(), &fixture.forwarding),
                1,
                &fixture.rg_epochs,
            )
            .is_some()
    };

    let mut absent_cache = FlowCache::new();
    seed(
        &mut absent_cache,
        decision(mac_a),
        &missing_neighbor_snapshot,
    );
    assert!(
        !lookup_present(&mut absent_cache),
        "a stale IPv6 MAC must not seed while its neighbor is absent"
    );

    fixture
        .dynamic_neighbors
        .insert_if_changed((EGRESS_IFINDEX, next_hop), NeighborEntry { mac: mac_b });
    let live_neighbor_snapshot = fixture.dynamic_neighbors.snapshot_shard_epochs();
    assert_eq!(
        live_neighbor_snapshot.epoch_for(&(EGRESS_IFINDEX, next_hop)),
        epoch_before_first_learn,
        "a first v6 learn must not bump the shard epoch"
    );

    let mut stale_cache = FlowCache::new();
    seed(&mut stale_cache, decision(mac_a), &live_neighbor_snapshot);
    assert!(
        !lookup_present(&mut stale_cache),
        "a stale IPv6 decision must not seed after the first learn either"
    );

    let mut fresh_cache = FlowCache::new();
    seed(&mut fresh_cache, decision(mac_b), &live_neighbor_snapshot);
    assert!(
        lookup_present(&mut fresh_cache),
        "a current IPv6 MAC must still seed the flow cache"
    );
}

fn flow_cache_mtu_fixture_11376() -> LiveCallSiteFixture {
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    fixture.forwarding.egress.insert(
        EGRESS_IFINDEX,
        EgressInterface {
            bind_ifindex: EGRESS_IFINDEX,
            vlan_id: 0,
            mtu: 1200,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x02],
            zone_id: TEST_UNTRUST_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );
    fixture
}

fn oversized_udp_v4_frame_11376(total_len: usize) -> Vec<u8> {
    assert!(total_len >= 32 && total_len <= u16::MAX as usize);
    let mut frame = vlan_tagged_udp_v4_frame();
    frame.extend(std::iter::repeat_n(0u8, total_len - 32));
    frame[20..22].copy_from_slice(&(total_len as u16).to_be_bytes());
    frame[42..44].copy_from_slice(&((total_len - 20) as u16).to_be_bytes());
    frame
}

fn oversized_tcp_v4_frame_11376(total_len: usize, df: bool) -> Vec<u8> {
    assert!(total_len >= 40 && total_len <= u16::MAX as usize);
    let mut frame = tcp_v4_ack_frame();
    frame.extend(std::iter::repeat_n(0u8, total_len - 40));
    frame[20..22].copy_from_slice(&(total_len as u16).to_be_bytes());
    if !df {
        frame[24] &= !0x40;
    }
    frame
}

fn run_udp_cache_hit_11376(fixture: &LiveCallSiteFixture, frame: &[u8]) -> StageRun {
    let key = udp_test_key();
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    };
    let mut entry = cached_entry();
    entry.key = key;
    run_stage_seeded(
        fixture,
        frame,
        udp_test_meta(frame),
        entry,
        0,
        StageSeed {
            session: Some((1_000_000, PROTO_UDP, 0)),
            flow: Some(flow),
            ..StageSeed::default()
        },
    )
}

fn assert_oversized_cache_hit_uses_pending_egress_11376(run: &StageRun) {
    assert_eq!(
        run.flow_cache_tallies.0, 1,
        "the packet must exercise a flow-cache hit"
    );
    assert!(
        run.tx_pipeline.pending_tx_prepared.is_empty(),
        "oversized cache-hit packet must not be rewritten inline"
    );
    assert_eq!(
        run.scratch.scratch_forwards.len(),
        1,
        "oversized packet must enter the pending-forward egress path"
    );
}

#[test]
fn flow_cache_hit_defers_oversized_udp_to_ptb_path_11376() {
    let fixture = flow_cache_mtu_fixture_11376();
    let frame = oversized_udp_v4_frame_11376(1500);
    let run = run_udp_cache_hit_11376(&fixture, &frame);
    assert_oversized_cache_hit_uses_pending_egress_11376(&run);
}

#[test]
fn flow_cache_hit_defers_oversized_tcp_to_segmentation_path_11376() {
    let fixture = flow_cache_mtu_fixture_11376();
    let frame = oversized_tcp_v4_frame_11376(1500, false);
    let run = run_stage(&fixture, &frame, 0);
    assert_oversized_cache_hit_uses_pending_egress_11376(&run);
}

#[test]
fn policy_deny_cache_hit_replays_counts_logs_and_exception_without_session_11073() {
    use crate::event_stream::codec::DataplaneEventKind;

    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_event_stream();
    let frame = tcp_v4_ack_frame();
    let input_counter = Arc::new(crate::filter::FilterTermCounter::default());
    let policy_counter = Arc::new(crate::policy::PolicyRuleCounter::default());
    let mut entry = cached_deny_entry(
        ForwardingDisposition::PolicyDenied,
        Some(CachedPolicyDeny {
            action: crate::policy::PolicyAction::Deny,
            policy_id: 77,
            application_id: 19,
            reply_allowed: true,
        }),
    );
    entry.metadata.policy_counter_idx = 1;
    entry.metadata.policy_counter = Some(policy_counter.clone());
    entry
        .descriptor
        .input_filter_counters
        .push(input_counter.clone());

    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        entry,
        0,
        StageSeed {
            session: None,
            ..StageSeed::default()
        },
    );
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed));
    assert_eq!(run.flow_cache_tallies.0, 1, "the deny entry must be hit");
    assert_eq!(
        run.session_lookup_miss_counts,
        (0, 0, 0),
        "denial replay must not require or consult a forwarding session"
    );
    assert_eq!(run.counters.policy_denied_packets, 1);
    assert_eq!(run.dbg_policy_deny, 1);
    assert_eq!(run.dbg_disposition_other, 0);
    crate::filter::flush_recorded_filter_counters();
    crate::policy::flush_recorded_policy_hit_counters();
    assert_eq!(input_counter.packets.load(Ordering::Relaxed), 1);
    crate::filter::flush_recorded_filter_counters();
    crate::policy::flush_recorded_policy_hit_counters();
    assert_eq!(
        input_counter.bytes.load(Ordering::Relaxed),
        frame.len() as u64
    );
    crate::filter::flush_recorded_filter_counters();
    crate::policy::flush_recorded_policy_hit_counters();
    assert_eq!(policy_counter.test_packet_count(), 1);
    crate::filter::flush_recorded_filter_counters();
    crate::policy::flush_recorded_policy_hit_counters();
    assert_eq!(policy_counter.test_byte_count(), frame.len() as u64);

    let events = drained_events(&fixture);
    let deny_events: Vec<_> = events
        .iter()
        .filter(|event| event.kind == DataplaneEventKind::PolicyDeny)
        .collect();
    assert_eq!(
        deny_events.len(),
        1,
        "each hit must replay RT_FLOW policy deny"
    );
    assert_eq!(deny_events[0].action, 0, "plain deny remains a silent DENY");
    assert_eq!(deny_events[0].policy_id, 77);
    assert_eq!(deny_events[0].application_id, 19);
    assert_eq!(deny_events[0].ingress_zone_id, TEST_TRUST_ZONE_ID as u16);
    assert_eq!(deny_events[0].egress_zone_id, TEST_UNTRUST_ZONE_ID as u16);
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                event.reason == FilterLogSource::Input.wire_reason()
                    && event.kind == DataplaneEventKind::FilterLog
            })
            .count(),
        1,
        "accepted INPUT then-log must be replayed before the policy denial"
    );
    assert_eq!(
        fixture
            .recent_exceptions
            .lock()
            .expect("exception ring lock")
            .back()
            .map(|event| event.reason),
        Some("policy_denied")
    );
    assert_eq!(
        fixture
            .last_resolution
            .lock()
            .expect("last resolution lock")
            .as_ref()
            .map(|event| event.resolution.disposition),
        Some(ForwardingDisposition::PolicyDenied)
    );
    // #14656: counters are coalesced per-thread in every build; flush before asserting.
}

#[test]
fn discard_route_cache_hit_replays_drop_accounting_without_policy_event_11073() {
    use crate::event_stream::codec::DataplaneEventKind;

    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_event_stream();
    let frame = tcp_v4_ack_frame();
    let entry = cached_deny_entry(ForwardingDisposition::DiscardRoute, None);
    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        entry,
        0,
        StageSeed {
            session: None,
            ..StageSeed::default()
        },
    );
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed));
    assert_eq!(run.flow_cache_tallies.0, 1);
    assert_eq!(run.session_lookup_miss_counts, (0, 0, 0));
    assert_eq!(run.counters.discard_route_packets, 1);
    assert_eq!(run.counters.policy_denied_packets, 0);
    assert_eq!(run.dbg_policy_deny, 0);
    assert_eq!(run.dbg_disposition_other, 1);
    assert!(
        drained_events(&fixture)
            .iter()
            .all(|event| event.kind != DataplaneEventKind::PolicyDeny),
        "DiscardRoute must remain a silent route drop, not a policy event"
    );
    assert_eq!(
        fixture
            .recent_exceptions
            .lock()
            .expect("exception ring lock")
            .back()
            .map(|event| event.reason),
        Some("discard_route")
    );
}

#[test]
fn cached_policy_reject_synthesizes_reply_before_truthful_reject_event_11073() {
    use crate::event_stream::codec::DataplaneEventKind;

    let _bucket_guard = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        1_000_000,
    );
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom)
        .with_ingress_primary_v4()
        .with_event_stream();
    let frame = vlan_tagged_udp_v4_frame();
    let key = udp_test_key();
    let mut entry = cached_deny_entry(
        ForwardingDisposition::PolicyDenied,
        Some(CachedPolicyDeny {
            action: crate::policy::PolicyAction::Reject,
            policy_id: 81,
            application_id: 53,
            reply_allowed: true,
        }),
    );
    entry.key = key.clone();
    entry.descriptor.input_filter_log = None;
    let run = run_stage_seeded(
        &fixture,
        &frame,
        udp_test_meta(&frame),
        entry,
        0,
        StageSeed {
            session: None,
            flow: Some(SessionFlow {
                src_ip: key.src_ip,
                dst_ip: key.dst_ip,
                forward_key: key,
            }),
            tx_headroom: Some((128, 256)),
            ..StageSeed::default()
        },
    );
    assert_eq!(run.flow_cache_tallies.0, 1);
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "reject reply handling must still consume the denied ingress packet"
    );
    assert_eq!(
        run.tx_pipeline.pending_tx_local.len(),
        1,
        "a cached Reject must synthesize the same active UDP reject reply"
    );
    let events = drained_events(&fixture);
    let event = events
        .iter()
        .find(|event| event.kind == DataplaneEventKind::PolicyDeny)
        .expect("cached reject must emit an RT_FLOW policy event");
    assert_eq!(
        event.action,
        crate::afxdp::event_emit::RT_FLOW_ACTION_REJECT,
        "the event follows the successfully enqueued reply"
    );
    assert_eq!(event.policy_id, 81);
}

#[test]
fn cached_no_route_reject_is_silent_and_logs_deny_not_reject_11073() {
    use crate::event_stream::codec::DataplaneEventKind;

    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom)
        .with_ingress_primary_v4()
        .with_event_stream();
    let frame = vlan_tagged_udp_v4_frame();
    let key = udp_test_key();
    let mut entry = cached_deny_entry(
        ForwardingDisposition::PolicyDenied,
        Some(CachedPolicyDeny {
            action: crate::policy::PolicyAction::Reject,
            policy_id: 82,
            application_id: 53,
            reply_allowed: false,
        }),
    );
    entry.key = key.clone();
    entry.descriptor.input_filter_log = None;
    let run = run_stage_seeded(
        &fixture,
        &frame,
        udp_test_meta(&frame),
        entry,
        0,
        StageSeed {
            session: None,
            flow: Some(SessionFlow {
                src_ip: key.src_ip,
                dst_ip: key.dst_ip,
                forward_key: key,
            }),
            tx_headroom: Some((128, 256)),
            ..StageSeed::default()
        },
    );
    assert_eq!(run.flow_cache_tallies.0, 1);
    assert!(run.tx_pipeline.pending_tx_local.is_empty());
    let events = drained_events(&fixture);
    let event = events
        .iter()
        .find(|event| event.kind == DataplaneEventKind::PolicyDeny)
        .expect("NoRoute policy denial must replay its RT_FLOW event");
    assert_eq!(
        event.action, 0,
        "NoRoute cannot synthesize a reply and must report DENY, not REJECT"
    );
}

fn cos_cache_fixture(built: &crate::afxdp::types::ForwardingState) -> LiveCallSiteFixture {
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture.forwarding.cos = built.cos.clone();
    fixture.forwarding.filter_state = built.filter_state.clone();
    fixture.forwarding.tx_selection_enabled_v4 = built.tx_selection_enabled_v4;
    fixture.forwarding.tx_selection_enabled_v6 = built.tx_selection_enabled_v6;
    fixture.forwarding.ingress_logical_ifindex = built.ingress_logical_ifindex.clone();
    fixture
}

/// #11679: output-filter forwarding-class pins queue 1, but ingress DSCP
/// chooses loss priority on every TCP/443 cache hit. The flow-cache key omits
/// DSCP, so both transitions must refresh only the CoS rewrite while retaining
/// the queue. This exercises `stage_flow_cache_hit` with an injected cached
/// descriptor and asserts `PreparedTxRequest` fields plus staged-frame presence,
/// not the emitted wire bytes.
#[test]
fn cached_filter_pinned_queue_refreshes_ingress_lp_rewrite_11679() {
    let scheduler = |name: &str, priority: &str| crate::CoSSchedulerSnapshot {
        name: name.into(),
        priority: priority.into(),
        transmit_rate_bytes: 4_000_000,
        buffer_size_bytes: 128_000,
        ..Default::default()
    };
    let classifier_entry = |forwarding_class: &str, loss_priority: &str, dscp_value| {
        crate::CoSDSCPClassifierEntrySnapshot {
            forwarding_class: forwarding_class.into(),
            loss_priority: loss_priority.into(),
            dscp_values: vec![dscp_value],
        }
    };
    let classifier = |name: &str, entries| crate::CoSDSCPClassifierSnapshot {
        name: name.into(),
        entries,
    };
    let snapshot = crate::ConfigSnapshot {
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "reth0.0".into(),
                ifindex: EGRESS_IFINDEX,
                filter_output_v4: "pin-bulk".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_scheduler_map: "wan-map".into(),
                cos_dscp_classifier: "bulk".into(),
                cos_dscp_rewrite_rule: "wan-rw".into(),
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0-0-2".into(),
                ifindex: PHYS_INGRESS_IFINDEX,
                is_unit: Some(false),
                hardware_addr: "02:bf:72:00:01:01".into(),
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0-0-2.80".into(),
                ifindex: LOGICAL_INGRESS_IFINDEX,
                parent_ifindex: PHYS_INGRESS_IFINDEX,
                vlan_id: i32::from(INGRESS_VLAN_ID),
                is_unit: Some(true),
                cos_dscp_classifier: "voice".into(),
                ..Default::default()
            },
            crate::InterfaceSnapshot {
                name: "ge-0-0-2.81".into(),
                ifindex: LOGICAL_INGRESS_IFINDEX + 1,
                parent_ifindex: PHYS_INGRESS_IFINDEX,
                vlan_id: 81,
                is_unit: Some(true),
                cos_dscp_classifier: "vlan81".into(),
                ..Default::default()
            },
        ],
        filters: vec![crate::FirewallFilterSnapshot {
            name: "pin-bulk".into(),
            family: "inet".into(),
            terms: vec![crate::FirewallTermSnapshot {
                name: "bulk-class".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "accept".into(),
                forwarding_class: "bulk-data".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(crate::ClassOfServiceSnapshot {
            forwarding_classes: vec![
                crate::CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                crate::CoSForwardingClassSnapshot {
                    name: "bulk-data".into(),
                    queue: 1,
                },
                crate::CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 5,
                },
            ],
            dscp_classifiers: vec![
                classifier(
                    "bulk",
                    vec![
                        classifier_entry("bulk-data", "low", 46),
                        classifier_entry("bulk-data", "high", 10),
                    ],
                ),
                classifier(
                    "voice",
                    vec![
                        classifier_entry("voice", "high", 46),
                        classifier_entry("bulk-data", "low", 10),
                    ],
                ),
                classifier("vlan81", vec![classifier_entry("bulk-data", "high", 10)]),
            ],
            dscp_rewrite_rules: vec![crate::CoSDSCPRewriteRuleSnapshot {
                name: "wan-rw".into(),
                entries: vec![
                    crate::CoSDSCPRewriteRuleEntrySnapshot {
                        forwarding_class: "bulk-data".into(),
                        loss_priority: "low".into(),
                        dscp_value: 17,
                    },
                    crate::CoSDSCPRewriteRuleEntrySnapshot {
                        forwarding_class: "bulk-data".into(),
                        loss_priority: "high".into(),
                        dscp_value: 42,
                    },
                    crate::CoSDSCPRewriteRuleEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "high".into(),
                        dscp_value: 42,
                    },
                ],
            }],
            schedulers: vec![
                scheduler("be-sched", "low"),
                scheduler("bulk-sched", "low"),
                scheduler("voice-sched", "high"),
            ],
            scheduler_maps: vec![crate::CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    crate::CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                    crate::CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "bulk-data".into(),
                        scheduler: "bulk-sched".into(),
                    },
                    crate::CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "voice".into(),
                        scheduler: "voice-sched".into(),
                    },
                ],
            }],
            ..Default::default()
        }),
        ..Default::default()
    };

    let built = crate::afxdp::forwarding_build::build_forwarding_state(&snapshot);
    for (seed_dscp, hit_dscp, expected_dscp) in [(46u8, 10u8, 17u8), (10, 46, 42)] {
        let fixture = cos_cache_fixture(&built);

        let mut seed_frame = vlan_tagged_tcp_v4_frame(0);
        seed_frame[19] = seed_dscp << 2;
        let mut seed_meta = test_meta(&seed_frame);
        seed_meta.dscp = seed_dscp;
        let seed_selection = crate::afxdp::tx::resolve_cached_cos_tx_selection(
            &fixture.forwarding,
            EGRESS_IFINDEX,
            seed_meta,
            &test_key(),
        );
        assert_eq!(seed_selection.queue_id, Some(1), "filter pins bulk queue 1");
        assert!(
            !seed_selection.ba_reclassify,
            "the filter-pinned queue stays fixed"
        );
        assert!(seed_selection.cos_lp_reclassify);
        assert_eq!(
            seed_selection.dscp_rewrite,
            if seed_dscp == 46 { Some(42) } else { Some(17) },
            "the seed CoS rewrite must reflect its own ingress loss priority"
        );

        let mut entry = cached_entry();
        entry.descriptor.tx_selection = seed_selection;
        let mut hit_frame = vlan_tagged_tcp_v4_frame(0);
        hit_frame[19] = hit_dscp << 2;
        let mut hit_meta = test_meta(&hit_frame);
        hit_meta.dscp = hit_dscp;
        let run = run_stage_with_entry(&fixture, &hit_frame, hit_meta, entry, 0);

        assert_eq!(
            run.flow_cache_tallies,
            (1, 0, 0),
            "must drive a real cache hit"
        );
        assert!(matches!(run.outcome, FlowCacheOutcome::Consumed));
        let prepared = run
            .tx_pipeline
            .pending_tx_prepared
            .front()
            .expect("the cache hit must stage the packet for TX");
        assert_eq!(
            prepared.cos_queue_id,
            Some(1),
            "the output filter keeps queue 1 pinned"
        );
        assert_eq!(prepared.dscp_rewrite, Some(expected_dscp));
        assert!(
            run.tx_frame.is_some(),
            "the in-place production path stages bytes"
        );
    }
    // A second VLAN on the same physical ingress resolves a different unit and
    // therefore a different classifier, even though the packet tuple is equal.
    let fixture = cos_cache_fixture(&built);
    let mut vlan_seed_frame = vlan_tagged_tcp_v4_frame(0);
    vlan_seed_frame[14..16].copy_from_slice(&81_u16.to_be_bytes());
    vlan_seed_frame[19] = 46 << 2;
    let mut vlan_seed_meta = test_meta(&vlan_seed_frame);
    vlan_seed_meta.dscp = 46;
    vlan_seed_meta.ingress_vlan_id = 81;
    let vlan_seed_selection = crate::afxdp::tx::resolve_cached_cos_tx_selection(
        &fixture.forwarding,
        EGRESS_IFINDEX,
        vlan_seed_meta,
        &test_key(),
    );
    assert_eq!(vlan_seed_selection.queue_id, Some(1));
    assert!(vlan_seed_selection.cos_lp_reclassify);

    let mut vlan_entry = cached_entry();
    vlan_entry.logical_ingress_ifindex = LOGICAL_INGRESS_IFINDEX + 1;
    vlan_entry.metadata.ingress_vlan_id = 81;
    vlan_entry.descriptor.tx_selection = vlan_seed_selection;
    let mut vlan_hit_frame = vlan_tagged_tcp_v4_frame(0);
    vlan_hit_frame[14..16].copy_from_slice(&81_u16.to_be_bytes());
    vlan_hit_frame[19] = 10 << 2;
    let mut vlan_hit_meta = test_meta(&vlan_hit_frame);
    vlan_hit_meta.ingress_vlan_id = 81;
    vlan_hit_meta.dscp = 10;
    let vlan_run = run_stage_with_entry(&fixture, &vlan_hit_frame, vlan_hit_meta, vlan_entry, 0);
    assert_eq!(vlan_run.flow_cache_tallies, (1, 0, 0));
    let prepared = vlan_run
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("VLAN-specific cache hit stages TX");
    assert_eq!(prepared.cos_queue_id, Some(1));
    assert_eq!(prepared.dscp_rewrite, Some(42));
    assert!(
        vlan_run.tx_frame.is_some(),
        "VLAN-specific hit stages bytes"
    );

    // A filter class that has no materialized scheduler queue is pinned to the
    // interface default. That fallback remains fixed while the selected
    // default queue's LP rewrite is refreshed from each ingress code point.
    let mut fallback_snapshot = snapshot.clone();
    fallback_snapshot.filters[0].terms[0].forwarding_class = "unmaterialized".into();
    let fallback_cos = fallback_snapshot
        .class_of_service
        .as_mut()
        .expect("CoS snapshot exists");
    fallback_cos
        .forwarding_classes
        .push(crate::CoSForwardingClassSnapshot {
            name: "unmaterialized".into(),
            queue: 7,
        });
    fallback_cos.dscp_rewrite_rules[0].entries.extend([
        crate::CoSDSCPRewriteRuleEntrySnapshot {
            forwarding_class: "best-effort".into(),
            loss_priority: "low".into(),
            dscp_value: 17,
        },
        crate::CoSDSCPRewriteRuleEntrySnapshot {
            forwarding_class: "best-effort".into(),
            loss_priority: "high".into(),
            dscp_value: 42,
        },
    ]);
    let fallback_built = crate::afxdp::forwarding_build::build_forwarding_state(&fallback_snapshot);
    let fallback_fixture = cos_cache_fixture(&fallback_built);
    for (seed_dscp, hit_dscp, expected_dscp) in [(46_u8, 10_u8, 17_u8), (10, 46, 42)] {
        let mut seed_frame = vlan_tagged_tcp_v4_frame(0);
        seed_frame[19] = seed_dscp << 2;
        let mut seed_meta = test_meta(&seed_frame);
        seed_meta.dscp = seed_dscp;
        let selection = crate::afxdp::tx::resolve_cached_cos_tx_selection(
            &fallback_fixture.forwarding,
            EGRESS_IFINDEX,
            seed_meta,
            &test_key(),
        );
        assert_eq!(
            selection.queue_id,
            Some(0),
            "fallback pins the default queue"
        );
        assert!(selection.filter_forwarding_class_fallback_pinned);
        assert!(selection.cos_lp_reclassify);
        let mut entry = cached_entry();
        entry.descriptor.tx_selection = selection;
        let mut hit_frame = vlan_tagged_tcp_v4_frame(0);
        hit_frame[19] = hit_dscp << 2;
        let mut hit_meta = test_meta(&hit_frame);
        hit_meta.dscp = hit_dscp;
        let run = run_stage_with_entry(&fallback_fixture, &hit_frame, hit_meta, entry, 0);
        assert_eq!(run.flow_cache_tallies, (1, 0, 0));
        assert_eq!(
            run.tx_pipeline
                .pending_tx_prepared
                .front()
                .expect("fallback cache hit stages TX")
                .cos_queue_id,
            Some(0)
        );
        let prepared = run
            .tx_pipeline
            .pending_tx_prepared
            .front()
            .expect("fallback cache hit stages TX");
        assert_eq!(prepared.dscp_rewrite, Some(expected_dscp));
        assert!(run.tx_frame.is_some());
    }

    // The classifier's queue can be valid but absent from this egress's final
    // queue set. Clamp it to default queue 0, then still apply that queue's
    // current ingress LP rewrite on the cache hit.
    let mut clamp_snapshot = snapshot.clone();
    clamp_snapshot.filters[0].terms[0].forwarding_class.clear();
    let clamp_cos = clamp_snapshot
        .class_of_service
        .as_mut()
        .expect("CoS snapshot exists");
    clamp_cos.scheduler_maps[0]
        .entries
        .retain(|entry| entry.forwarding_class == "best-effort");
    clamp_cos.dscp_rewrite_rules[0].entries.extend([
        crate::CoSDSCPRewriteRuleEntrySnapshot {
            forwarding_class: "best-effort".into(),
            loss_priority: "low".into(),
            dscp_value: 17,
        },
        crate::CoSDSCPRewriteRuleEntrySnapshot {
            forwarding_class: "best-effort".into(),
            loss_priority: "high".into(),
            dscp_value: 42,
        },
    ]);
    let clamp_built = crate::afxdp::forwarding_build::build_forwarding_state(&clamp_snapshot);
    let clamp_fixture = cos_cache_fixture(&clamp_built);
    for (seed_dscp, hit_dscp, expected_dscp) in [(46_u8, 10_u8, 17_u8), (10, 46, 42)] {
        let mut seed_frame = vlan_tagged_tcp_v4_frame(0);
        seed_frame[19] = seed_dscp << 2;
        let mut seed_meta = test_meta(&seed_frame);
        seed_meta.dscp = seed_dscp;
        let selection = crate::afxdp::tx::resolve_cached_cos_tx_selection(
            &clamp_fixture.forwarding,
            EGRESS_IFINDEX,
            seed_meta,
            &test_key(),
        );
        assert_eq!(selection.queue_id, Some(0), "classifier queue clamps to q0");
        assert!(selection.ba_reclassify);
        let mut entry = cached_entry();
        entry.descriptor.tx_selection = selection;
        let mut hit_frame = vlan_tagged_tcp_v4_frame(0);
        hit_frame[19] = hit_dscp << 2;
        let mut hit_meta = test_meta(&hit_frame);
        hit_meta.dscp = hit_dscp;
        let run = run_stage_with_entry(&clamp_fixture, &hit_frame, hit_meta, entry, 0);
        assert_eq!(run.flow_cache_tallies, (1, 0, 0));
        assert_eq!(
            run.tx_pipeline
                .pending_tx_prepared
                .front()
                .expect("clamped cache hit stages TX")
                .cos_queue_id,
            Some(0)
        );
        let prepared = run
            .tx_pipeline
            .pending_tx_prepared
            .front()
            .expect("clamped cache hit stages TX");
        assert_eq!(prepared.dscp_rewrite, Some(expected_dscp));
        assert!(run.tx_frame.is_some());
    }
}
// F3 repro: a cached flow admitted by an unscheduled PERMIT below an inactive
// scheduled DENY currently survives lease expiry because cache lookup evicts
// only entries whose admitting counter belongs to a scheduled rule. The cold
// policy walk sees the newly eligible DENY, but the live cache-hit stage skips
// that revalidation and consumes the stale forwarding descriptor.
#[test]
fn expired_scheduler_lease_revalidates_cached_unscheduled_permit12273() {
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let mut zones = rustc_hash::FxHashMap::default();
    zones.insert("trust".to_string(), TEST_TRUST_ZONE_ID);
    zones.insert("untrust".to_string(), TEST_UNTRUST_ZONE_ID);
    fixture.forwarding.policy = crate::policy::parse_policy_state(
        "deny",
        &[
            crate::PolicyRuleSnapshot {
                name: "scheduled-deny".to_string(),
                from_zone: "trust".to_string(),
                to_zone: "untrust".to_string(),
                scheduler_name: "workhours".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                action: "deny".to_string(),
                inactive: true,
                policy_id: 12052,
                ..Default::default()
            },
            crate::PolicyRuleSnapshot {
                name: "unscheduled-permit".to_string(),
                from_zone: "trust".to_string(),
                to_zone: "untrust".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                action: "permit".to_string(),
                policy_id: 12053,
                ..Default::default()
            },
        ],
        &zones,
    );
    const RECEIVED_AT_NS: u64 = 100;
    assert!(
        fixture
            .forwarding
            .policy
            .scheduler_lease
            .apply(1, RECEIVED_AT_NS),
        "fixture must install the scheduler lease"
    );
    let expired_at = RECEIVED_AT_NS + crate::policy::SCHEDULER_HEARTBEAT_LEASE_NS + 1;
    assert!(
        fixture
            .forwarding
            .policy
            .scheduler_rules_expired_at(expired_at),
        "fixture must exercise the expired lease phase"
    );
    let cold = crate::policy::evaluate_policy_result_l3_aware_at(
        &fixture.forwarding.policy,
        TEST_TRUST_ZONE_ID,
        TEST_UNTRUST_ZONE_ID,
        test_key().src_ip,
        test_key().dst_ip,
        PROTO_TCP,
        test_key().src_port,
        test_key().dst_port,
        None,
        64,
        true,
        expired_at,
    );
    assert_eq!(cold.action, crate::policy::PolicyAction::Deny);
    assert_eq!(cold.policy_id, 12052);

    // The cache entry records the lower, unscheduled PERMIT as its admitting
    // rule (one-based counter index 2), so the old expiry eviction filter skips
    // it even though the newly eligible deny now wins the current cold walk.
    let mut entry = cached_entry();
    entry.metadata.policy_id = 12053;
    entry.metadata.policy_counter_idx = 2;
    let frame = tcp_v4_ack_frame();
    let mut seed = StageSeed {
        now_ns: expired_at,
        ..StageSeed::default()
    };
    seed.session = Some((1_000_000, PROTO_TCP, 0x10));
    let run = run_stage_seeded(&fixture, &frame, test_meta(&frame), entry, 1, seed);
    let cache_consumed = matches!(&run.outcome, FlowCacheOutcome::Consumed);
    assert!(
        !cache_consumed,
        "F3 BYPASS: flow-cache hit consumed a forwarding descriptor despite the \
         expired-lease cold policy walk selecting scheduled DENY; cache_consumed={}, \
         flow-cache (hits, misses, evictions)={:?}",
        cache_consumed, run.flow_cache_tallies
    );
}

/// #13635 (D3-01): a cached PolicyDenied entry seeded by a pre-session
/// unsolicited B->A packet must not execute once a live session backs
/// B->A. Pre-fix the deny arm returned Consumed (dropping the packet and,
/// for Reject, emitting a forged RST) before the liveness check.
/// The fix checks liveness inside the deny arm, evicts the stale deny
/// slot, reclassifies the hit as a miss, and falls through.
#[test]
fn policy_deny_cache_hit_falls_through_when_live_session_backs_flow_13635() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_event_stream();
    let frame = tcp_v4_ack_frame();
    let entry = cached_deny_entry(
        ForwardingDisposition::PolicyDenied,
        Some(CachedPolicyDeny {
            action: crate::policy::PolicyAction::Reject,
            policy_id: 13635,
            application_id: 19,
            reply_allowed: true,
        }),
    );
    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        entry,
        0,
        StageSeed::default(),
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "#13635: cached deny must fall through when a live session backs the flow, \
         not consume/drop it or emit a reject RST"
    );
    assert_eq!(
        run.flow_cache_tallies,
        (0, 1, 1),
        "#13635: the stale deny hit must be reclassified as miss+eviction"
    );
    assert_eq!(run.dbg_policy_deny, 0);
    assert_eq!(run.counters.policy_denied_packets, 0);
    assert!(run.cached_observed_bytes.is_none());
    assert!(run.scratch.scratch_recycle.is_empty());
    assert!(run.tx_pipeline.pending_tx_local.is_empty());
}

/// #13635: same guard for DiscardRoute deny entries.
#[test]
fn discard_route_cache_hit_falls_through_when_live_session_backs_flow_13635() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_event_stream();
    let frame = tcp_v4_ack_frame();
    let entry = cached_deny_entry(ForwardingDisposition::DiscardRoute, None);
    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        entry,
        0,
        StageSeed::default(),
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "#13635: cached DiscardRoute must fall through when a live session backs the flow"
    );
    assert_eq!(run.flow_cache_tallies, (0, 1, 1));
    assert_eq!(run.dbg_disposition_other, 0);
    assert!(run.cached_observed_bytes.is_none());
    assert!(run.scratch.scratch_recycle.is_empty());
}

/// #16217 (FZDiag28, part a): next-hop version of the #13635 guard. A
/// cached deny seeded while the FIB answered MissingNeighbor for
/// `(egress, next_hop)` must fall through once the NODE neighbor map
/// holds that hop (warm-pass shape: present only in the shared
/// dynamic map, absent from the static snapshot), so the session-hit
/// path can recompute the adopted ForwardCandidate.
///
/// FAIL-ON-REVERT: drop the neighbor-landed guard in the deny arm
/// and the deny is served (Consumed); a contradicting MAC or an
/// absent hop must keep the deny (fail-closed controls below).
#[test]
fn cached_deny_superseded_when_node_neighbor_lands_16217() {
    let hop = IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1));
    let mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
    let frame = tcp_v4_ack_frame();
    // Deny entry carrying the unresolved hop (next_hop set, no MAC).
    let mut entry = cached_deny_entry(
        ForwardingDisposition::PolicyDenied,
        Some(CachedPolicyDeny {
            action: crate::policy::PolicyAction::Deny,
            policy_id: 16217,
            application_id: 0,
            reply_allowed: false,
        }),
    );
    entry.decision.resolution.next_hop = Some(hop);
    entry.decision.resolution.neighbor_mac = None;
    entry.decision.resolution.egress_ifindex = EGRESS_IFINDEX;

    // Hop landed ONLY in the node map.
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_event_stream();
    fixture
        .dynamic_neighbors
        .insert((EGRESS_IFINDEX, hop), NeighborEntry { mac });
    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        entry.clone(),
        0,
        StageSeed {
            session: None,
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "#16217: cached deny must fall through once the node neighbor lands"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitDenySuperseded as usize],
        1,
        "the supersession must be attributed to PostHitDenySuperseded"
    );
    assert!(
        run.cached_observed_bytes.is_none(),
        "deny slot must be evicted"
    );

    // Control: hop absent — deny stays served (fail-closed).
    let fixture_absent = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_event_stream();
    let run = run_stage_seeded(
        &fixture_absent,
        &frame,
        accounted_meta(&frame),
        entry.clone(),
        0,
        StageSeed {
            session: None,
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "#16217: cached deny must stay served while the hop is unresolved"
    );

    // Control: contradicting MAC — deny stays served (fail-closed).
    let fixture_bad = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_event_stream();
    fixture_bad.dynamic_neighbors.insert(
        (EGRESS_IFINDEX, hop),
        NeighborEntry {
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        },
    );
    let mut entry_mac = entry.clone();
    entry_mac.decision.resolution.neighbor_mac = Some(mac);
    let run = run_stage_seeded(
        &fixture_bad,
        &frame,
        accounted_meta(&frame),
        entry_mac,
        0,
        StageSeed {
            session: None,
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "#16217: contradicting node MAC must keep the deny (fail-closed)"
    );
}

/// #13635: reverse-NAT cached denies use the translated wire tuple, while
/// the worker's backing reverse session remains stored under its canonical
/// key. The liveness guard must resolve that alias before replaying Reject.
#[test]
fn policy_deny_cache_hit_falls_through_for_live_reverse_nat_alias_13635() {
    use crate::afxdp::NatDecision;

    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_event_stream();
    let frame = tcp_v4_ack_frame();
    let canonical = test_key();
    let mut nat = NatDecision::default();
    nat.rewrite_dst = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 55)));
    let alias = crate::session::translated_session_key(&canonical, nat);
    assert_ne!(alias, canonical, "fixture must use a translated alias");

    let mut entry = cached_deny_entry(
        ForwardingDisposition::PolicyDenied,
        Some(CachedPolicyDeny {
            action: crate::policy::PolicyAction::Reject,
            policy_id: 13635,
            application_id: 19,
            reply_allowed: true,
        }),
    );
    entry.key = alias.clone();
    entry.decision.nat = nat;
    entry.metadata.is_reverse = true;
    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        entry,
        0,
        StageSeed {
            install_key: Some(canonical),
            flow: Some(SessionFlow {
                src_ip: alias.src_ip,
                dst_ip: alias.dst_ip,
                forward_key: alias,
            }),
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "#13635: a live reverse-NAT companion found by wire alias must defeat \
         the stale cached reject"
    );
    assert_eq!(run.flow_cache_tallies, (0, 1, 1));
    assert_eq!(run.dbg_policy_deny, 0);
    assert_eq!(run.counters.policy_denied_packets, 0);
    assert!(run.tx_pipeline.pending_tx_local.is_empty());
    assert!(run.cached_observed_bytes.is_none());
}

/// #14945 (3): LAN->WAN transit on the same worker — the egress binding
/// differs from the ingress binding but shares its UMEM allocation, so
/// the cache hit takes the INLINE in-place path and hands the prepared
/// request to the TARGET binding, byte-identical to the hairpin arm.
///
/// Fail-on-revert: restoring the `is_self_target` gate makes this run
/// detour through `PendingForwardRequest` (`scratch_forwards` non-empty,
/// target queue empty).
#[test]
fn transit_cross_binding_shared_umem_takes_inline_path_14945() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    // Hairpin control on the same frame: the byte-identical reference.
    let hairpin = run_stage(&fixture, &frame, 1);
    let hairpin_bytes = hairpin
        .tx_frame
        .clone()
        .expect("control: hairpin stages the rewritten frame");

    let run = run_stage_seeded(
        &fixture,
        &frame,
        test_meta(&frame),
        transit_entry(),
        1,
        StageSeed {
            cross_umem_shared: Some(true),
            ..StageSeed::default()
        },
    );

    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "the transit cache hit must be consumed"
    );
    assert_eq!(
        run.target_tx_pipeline.pending_tx_prepared.len(),
        1,
        "#14945: the prepared request must land on the TARGET binding's queue"
    );
    assert!(
        run.tx_pipeline.pending_tx_prepared.is_empty(),
        "#14945: nothing may be queued on the ingress binding for a transit hit"
    );
    assert!(
        run.scratch.scratch_forwards.is_empty(),
        "#14945: a shared-UMEM transit hit must NOT detour through \
         PendingForwardRequest/enqueue_pending_forwards"
    );
    assert_eq!(
        run.target_tx_counters.pending_in_place_tx_packets, 1,
        "#14945: the target binding is charged for the in-place TX"
    );
    assert_eq!(run.tx_counters.pending_in_place_tx_packets, 0);
    let transit_bytes = run
        .tx_frame
        .as_ref()
        .expect("the target's staged frame must be readable from the shared UMEM");
    assert_eq!(
        transit_bytes, &hairpin_bytes,
        "#14945: transit inline forwarding must be byte-identical to the hairpin arm"
    );
    // The prepared request still recycles to the INGRESS fill slot.
    let prepared = run
        .target_tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("target prepared request");
    assert_eq!(prepared.recycle.fill_slot(), Some(0));
    assert_eq!(prepared.egress_ifindex, EGRESS_IFINDEX);
}

/// #14945 (3) guard: a cross-binding target on a FOREIGN UMEM must not
/// receive a prepared offset into the ingress allocation — it keeps
/// the existing `PendingForwardRequest` detour (which rewrites in
/// place after resolving the shared allocation, or copies).
#[test]
fn transit_cross_binding_foreign_umem_keeps_pending_forward_14945() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let run = run_stage_seeded(
        &fixture,
        &frame,
        test_meta(&frame),
        transit_entry(),
        1,
        StageSeed {
            cross_umem_shared: Some(false),
            ..StageSeed::default()
        },
    );

    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed));
    assert!(
        run.target_tx_pipeline.pending_tx_prepared.is_empty(),
        "#14945/#8916: a foreign-UMEM target must never receive a prepared \
         offset into the ingress UMEM"
    );
    assert_eq!(
        run.scratch.scratch_forwards.len(),
        1,
        "#14945: a foreign-UMEM transit hit keeps the PendingForwardRequest path"
    );
    assert_eq!(run.target_tx_counters.pending_in_place_tx_packets, 0);
}

/// #15941 revert-guard: the cached-descriptor output-filter drop
/// (`flow_cache_hit.rs` cached drop arm) must increment
/// `transit_output_filter_drops`. A pure `then discard` (reject=false)
/// keeps it off the reject-reply path so the counter is the only trace.
#[test]
fn cached_output_filter_discard_counts_transit_drop_15941() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = vlan_tagged_udp_v4_frame();
    let meta = udp_test_meta(&frame);
    let mut entry = cached_entry();
    entry.key = udp_test_key();
    entry.descriptor.tx_selection.drop = true;
    entry.descriptor.tx_selection.reject = false;
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
            ..StageSeed::default()
        },
    );
    assert_eq!(run.flow_cache_tallies.0, 1, "must be a real cache hit");
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed));
    assert_eq!(
        run.counters.transit_output_filter_drops, 1,
        "#15941 cached drop site must increment the named counter"
    );
    assert!(run.scratch.scratch_forwards.is_empty());
    assert!(run.tx_pipeline.pending_tx_prepared.is_empty());
}

/// #15941 revert-guard: the cached-hit IPsec selector fence
/// (`flow_cache_hit.rs` fence arm) must increment
/// `transit_ipsec_fence_drops`.
#[test]
fn cached_selector_fence_counts_transit_fence_drop_15941() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_selector_fence();
    let frame = tcp_v4_ack_frame();
    let _meta = test_meta(&frame);
    let run = run_stage(&fixture, &frame, 0);
    assert_eq!(run.flow_cache_tallies.0, 1, "must be a real cache hit");
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed));
    assert_eq!(
        run.counters.transit_ipsec_fence_drops, 1,
        "#15941 cached-hit fence site must increment the named counter"
    );
    assert_eq!(run.dbg_tx, 0, "fenced hit must not transmit");
    assert!(run.scratch.scratch_forwards.is_empty());
}
/// #15958 (F1) revert-guard: a cached `drop: true` verdict on the
/// EARLY cached-drop arm (`cached_descriptor.tx_selection.drop` before
/// any inline/fallback TX) must record `forward_build_failures` AND a
/// `transit_output_filter_drop` ring entry, mirroring the slow-path
/// twin — previously this exit recycled silently after only the
/// `transit_output_filter_drops` count. This exercises the arm the fix
/// actually lives on: the cache-fallback builder's `None` exit is
/// unreachable for a dropping selection (the cached drop returns
/// first), so no counter is claimed for it.
#[test]
fn cached_drop_counts_forward_build_failure_15958() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let meta = test_meta(&frame);
    let mut entry = cached_entry();
    entry.descriptor.tx_selection.drop = true;
    entry.descriptor.tx_selection.reject = false;
    let run = run_stage_seeded(&fixture, &frame, meta, entry, 0, StageSeed::default());
    assert_eq!(run.flow_cache_tallies.0, 1, "must be a real cache hit");
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed));
    assert_eq!(
        run.counters.transit_output_filter_drops, 1,
        "early cached drop must keep its named transit counter"
    );
    assert_eq!(
        run.counters.forward_build_failures, 1,
        "F1: early cached drop must count as a forward build failure"
    );
    let reasons: Vec<String> = fixture
        .recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason().to_string())
        .collect();
    assert_eq!(
        reasons,
        vec!["transit_output_filter_drop"],
        "F1: early cached drop must ring transit_output_filter_drop"
    );
    assert!(run.scratch.scratch_forwards.is_empty());
    assert!(run.tx_pipeline.pending_tx_prepared.is_empty());
}
/// #16220: a peer-synced (SyncImport) session seeded into the flow cache
/// must serve its SECOND packet as a cache hit. This is the unit shape of
/// the PR #16217 no-failover regression (0 hits / 6.9M evictions): build
/// the session via the changed peer-synced import path, insert its entry
/// (as the slow-path seed does after a successful hit), then drive the
/// live hit stage — the packet must be Consumed as a hit with no eviction
/// arm moving.
#[test]
fn peer_synced_import_second_packet_hits_16220() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let meta = test_meta(&frame);
    let mut entry = cached_entry();
    // Peer-synced import provenance: owner RG 1 (the fixture's active RG).
    entry.metadata.owner_rg_id = 1;
    entry.stamp.owner_rg_id = 1;
    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry,
        0,
        StageSeed {
            session: Some((1_000_000, PROTO_TCP, 0x10)),
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "second packet of a peer-synced flow must be served from the flow cache"
    );
    assert_eq!(run.flow_cache_tallies.0, 1, "must count exactly one hit");
    assert_eq!(run.flow_cache_tallies.1, 0, "must not count a miss");
    assert_eq!(run.flow_cache_tallies.2, 0, "must not evict");
    assert_eq!(
        run.flow_cache_evictions_by_arm,
        [0; crate::afxdp::flow_cache::FLOW_CACHE_EVICTION_ARM_COUNT],
        "no eviction arm may move on a healthy peer-synced hit"
    );
}

/// #16220: the neighbor-MAC-stale rejection must attribute to the
/// PostHitNeighborMac arm (and not the HA/decision arm), so the live
/// per-arm counters can name the culprit without perf.
#[test]
fn neighbor_mac_stale_attributes_to_neighbor_arm_16220() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let meta = test_meta(&frame);
    let mut entry = cached_entry();
    entry.neighbor_shard = 0;
    entry.neighbor_mac_epoch = 0xDEAD_BEEF;
    let run = run_stage_with_entry(&fixture, &frame, meta, entry, 0);
    assert!(matches!(run.outcome, FlowCacheOutcome::FallThrough));
    assert_eq!(run.flow_cache_tallies.2, 1, "exactly one eviction");
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitNeighborMac as usize],
        1,
        "neighbor-MAC staleness must attribute to its own arm"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitDecisionInvalid as usize],
        0,
        "neighbor-MAC staleness must not attribute to the decision arm"
    );
}

/// #16269: a fabric-ingress cached DiscardRoute whose cluster-terminal
/// origin is CERTAIN (provenance stamp preserved, nat=(None,None),
/// stamp_owner_rg=0 — the exact live fw1 shape) and whose would-be
/// egress RG is now locally forwarding-active must NOT terminal-drop
/// on the new owner: it evicts to the slow path for re-resolve.
/// RED-on-revert: without the FabricIngressDiscardNowLocal arm the
/// hit is Consumed as a terminal drop (the aged-failover blackhole).
#[test]
fn fabric_ingress_discard_now_local_falls_through_16269() {
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    // EGRESS_IFINDEX (7) is the would-be WAN egress; stamp it RG1 and
    // make RG1 locally forwarding-active (the takeover state).
    fixture
        .forwarding
        .egress
        .get_mut(&EGRESS_IFINDEX)
        .expect("zone-accounting fixture seeds the egress")
        .redundancy_group = 1;
    fixture.ha_state.insert(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: 1,
            lease: HAGroupRuntime::active_lease_until(1, 1),
        },
    );
    let frame = tcp_v4_ack_frame();
    let mut entry = cached_deny_entry(ForwardingDisposition::DiscardRoute, None);
    entry.decision.resolution.source_ifindex = EGRESS_IFINDEX;
    assert_eq!(entry.decision.nat, NatDecision::default());
    assert_eq!(entry.stamp.owner_rg_id, 0);
    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        entry,
        0,
        StageSeed {
            packet_fabric_ingress: true,
            fabric_link_ingress: true,
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "#16269: fabric-ingress DiscardRoute now locally owned must re-resolve, not drop"
    );
    assert_eq!(run.flow_cache_tallies, (0, 1, 1));
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitFabricIngressDiscardNowLocal
                as usize],
        1,
        "the takeover eviction must attribute to its own arm"
    );
    assert_eq!(run.dbg_disposition_other, 0);
    assert!(run.scratch.scratch_recycle.is_empty());
}

/// #16269 control: same fabric-ingress DiscardRoute shape but WITHOUT
/// provenance (source_ifindex == 0 — operator discard / unattributable
/// row). Origin uncertain: it must stay a terminal drop even though
/// RG1 is locally active. Fail-closed; never a rescue guess.
#[test]
fn fabric_ingress_discard_without_provenance_stays_drop_16269() {
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture
        .forwarding
        .egress
        .get_mut(&EGRESS_IFINDEX)
        .expect("zone-accounting fixture seeds the egress")
        .redundancy_group = 1;
    fixture.ha_state.insert(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: 1,
            lease: HAGroupRuntime::active_lease_until(1, 1),
        },
    );
    let frame = tcp_v4_ack_frame();
    let entry = cached_deny_entry(ForwardingDisposition::DiscardRoute, None);
    assert_eq!(entry.decision.resolution.source_ifindex, 0);
    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        entry,
        0,
        StageSeed {
            session: None,
            packet_fabric_ingress: true,
            fabric_link_ingress: true,
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "uncertain-origin DiscardRoute must remain a terminal drop"
    );
    assert_eq!(run.dbg_disposition_other, 1);
}

/// #16269 control: certain origin but the would-be egress RG is still
/// peer-owned (not locally active) — the entry is not stale here; the
/// fabric-ingress packet must not re-resolve locally (and never
/// re-redirect). It stays a terminal drop on this node.
#[test]
fn fabric_ingress_discard_still_peer_owned_stays_drop_16269() {
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture
        .forwarding
        .egress
        .get_mut(&EGRESS_IFINDEX)
        .expect("zone-accounting fixture seeds the egress")
        .redundancy_group = 1;
    fixture.ha_state.insert(
        1,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: 1,
            lease: HAForwardingLease::Inactive,
        },
    );
    let frame = tcp_v4_ack_frame();
    let mut entry = cached_deny_entry(ForwardingDisposition::DiscardRoute, None);
    entry.decision.resolution.source_ifindex = EGRESS_IFINDEX;
    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        entry,
        0,
        StageSeed {
            session: None,
            packet_fabric_ingress: true,
            fabric_link_ingress: true,
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "still-peer-owned DiscardRoute must not re-resolve locally"
    );
    assert_eq!(run.dbg_disposition_other, 1);
}

/// #16269 (option c, LIVE shape): the fw1 fabric-ingress entry as the
/// scratch DISC cell proved it — DiscardRoute, nat=(None,None),
/// stamp_owner_rg=0, egress=0 — but seeded THROUGH
/// `FlowCacheEntry::from_deny_decision` with the FIB provenance stamp,
/// so the seed-time preservation (never-expire + provenance fields)
/// is what the hit judges. RG1 is locally forwarding-active
/// (takeover). The hit must evict to the slow path
/// (FabricIngressDiscardNowLocal arm), not terminal-drop.
/// RED-on-revert: drop the seed-time provenance/TTL preservation and
/// the entry either expires before the hit or carries no stamp.
#[test]
fn fabric_ingress_discard_seeded_live_shape_falls_through_16269() {
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture
        .forwarding
        .egress
        .get_mut(&EGRESS_IFINDEX)
        .expect("zone-accounting fixture seeds the egress")
        .redundancy_group = 1;
    fixture.ha_state.insert(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: 1,
            lease: HAGroupRuntime::active_lease_until(1, 1),
        },
    );
    let frame = tcp_v4_ack_frame();
    let flow = SessionFlow {
        src_ip: test_key().src_ip,
        dst_ip: test_key().dst_ip,
        forward_key: test_key(),
    };
    // Seed through the production deny constructor, exactly as
    // stage_flow_cache_deny_seed does: TTL now+1s, provenance stamped.
    let mut resolution = cached_entry().decision.resolution;
    resolution.disposition = ForwardingDisposition::DiscardRoute;
    resolution.egress_ifindex = 0;
    resolution.tx_ifindex = 0;
    resolution.next_hop = None;
    resolution.neighbor_mac = None;
    resolution.src_mac = None;
    resolution.source_ifindex = EGRESS_IFINDEX;
    let decision = SessionDecision {
        resolution,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let ha_state = BTreeMap::from([(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: 1,
            lease: HAGroupRuntime::active_lease_until(1, 1),
        },
    )]);
    let rg_epochs: [AtomicU32; crate::afxdp::flow_cache::MAX_RG_EPOCHS] =
        std::array::from_fn(|_| AtomicU32::new(0));
    let seeded = FlowCacheEntry::from_deny_decision(
        &flow,
        accounted_meta(&frame),
        ValidationState::default(),
        decision,
        0,
        TEST_TRUST_ZONE_ID,
        TEST_UNTRUST_ZONE_ID,
        0,
        None,
        None,
        None,
        crate::filter::CachedFilterCounters::default(),
        1 + crate::afxdp::flow_cache::DENY_CACHE_TTL_SECS,
        &fixture.forwarding,
        &ha_state,
        &rg_epochs,
    )
    .expect("live-shape DiscardRoute must seed through from_deny_decision");
    // Live shape: stamp_owner_rg=0 (owner resolution DiscardRoute->0),
    // nat=(None,None); seed preservation carries provenance + no TTL.
    assert_eq!(seeded.stamp.owner_rg_id, 0);
    assert_eq!(seeded.decision.nat, NatDecision::default());
    assert_eq!(seeded.cluster_terminal_source_ifindex, EGRESS_IFINDEX);
    assert_eq!(
        seeded.deny_expires_at_secs,
        crate::afxdp::flow_cache::CLUSTER_TERMINAL_DENY_EXPIRES_AT_SECS
    );
    let run = run_stage_seeded(
        &fixture,
        &frame,
        accounted_meta(&frame),
        seeded,
        0,
        StageSeed {
            packet_fabric_ingress: true,
            fabric_link_ingress: true,
            ..StageSeed::default()
        },
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "#16269 live shape: seeded cluster-terminal DiscardRoute now locally owned must re-resolve, not drop"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitFabricIngressDiscardNowLocal
                as usize],
        1,
        "the takeover eviction must attribute to its own arm"
    );
    assert_eq!(run.dbg_disposition_other, 0);
}

/// #16270 (cache supersession): the aged-failover shape at the live
/// hit stage — a cached ForwardCandidate (the stock `cached_entry`,
/// egress EGRESS_IFINDEX) whose egress is stamped RG1, with RG1 no
/// longer forwarding-active locally (failed over to the peer). The
/// hit must evict (PostHitForwardCandidateEgressDeparted) and fall
/// through to the slow path for re-resolve, NOT serve locally.
/// Control: RG1 locally active -> served (Consumed), no arm moves.
/// RED-on-revert: without the ForwardCandidateEgressDeparted arm the
/// departed hit is Consumed (served from the non-owner egress).
#[test]
fn forward_candidate_egress_departed_falls_through_16270() {
    let frame = tcp_v4_ack_frame();
    let meta = test_meta(&frame);
    // Departed: egress RG1 present but inactive (peer-owned now).
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture
        .forwarding
        .egress
        .get_mut(&EGRESS_IFINDEX)
        .expect("zone-accounting fixture seeds the egress")
        .redundancy_group = 1;
    fixture.ha_state.insert(
        1,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: 1,
            lease: HAForwardingLease::Inactive,
        },
    );
    let mut entry = cached_entry();
    entry.metadata.owner_rg_id = 1;
    entry.stamp.owner_rg_id = 1;
    let run = run_stage_seeded(&fixture, &frame, meta, entry, 0, StageSeed::default());
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "#16270: cached ForwardCandidate whose egress RG departed must re-resolve, not serve locally"
    );
    assert_eq!(run.flow_cache_tallies, (0, 1, 1));
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted
                as usize],
        1,
        "the supersession must attribute to the departed arm (validator checks departure BEFORE enforce)"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitEnforceChanged as usize],
        0,
        "EnforceChanged must not mask the departed arm"
    );
    // Control: same entry with RG1 locally forwarding-active is served.
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture
        .forwarding
        .egress
        .get_mut(&EGRESS_IFINDEX)
        .expect("zone-accounting fixture seeds the egress")
        .redundancy_group = 1;
    fixture.ha_state.insert(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: 1,
            lease: HAGroupRuntime::active_lease_until(1, 1),
        },
    );
    let mut entry = cached_entry();
    entry.metadata.owner_rg_id = 1;
    entry.stamp.owner_rg_id = 1;
    // Lease-carrying stamp would gate the lookup itself; keep the stamp
    // leaseless so the hit reaches decision revalidation (the arm under test).
    entry.stamp.owner_rg_lease_until = 0;
    let run = run_stage_seeded(&fixture, &frame, meta, entry, 0, StageSeed::default());
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "locally-active egress RG must keep serving the cached ForwardCandidate"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted
                as usize],
        0,
        "locally-active control must not move the supersession arm"
    );
}
/// #16217 (FZDiag34 reverse shape; FZDiag35 stamp=2 shape): a
/// REVERSE-direction cached entry is keyed by the reply tuple
/// (server -> translated client). Live fw0 (trace cellF, head
/// c4d4c5cd48): the reverse entry reads `ForwardCandidate egress=5
/// tx=5 local_rg=2` — egress 5 is ge-0-0-1, fw0's RG1 LAN member —
/// and its owner stamps SPLIT: rows whose seed recorded the
/// forward flow's LAN-member RG read stamp=1, rows whose seed
/// recorded the reply-egress (RETH) row's RG read stamp=2
/// (aggregate 6,374 vs 5,777 at d28). RG2 stays active on fw0
/// (RG0/RG2 never fail over), so for every stamp=2 row NEITHER the
/// logical departed arm (`forward_candidate_egress_departed`, keyed
/// on `egress_ifindex`) NOR the c4d4 owner arm (keyed on the stamp)
/// can fire: after RG1 fails over to fw1 those WAN replies are TX'd
/// out the departed member and the client's ACKs stop (55 SUM
/// zeros, twice on loss). The departed supersession must fire for
/// the stamp=2 shape exactly as for stamp=1 — the stamp now
/// records the forward flow's owner at seed
/// (`build_reverse_session_from_forward_match` +
/// `from_forward_decision` caller preference), so this fixture
/// hard-stamps 2 on BOTH stamp fields (the pre-fix live value) and
/// asserts the same FallThrough + arm ownership; the stamp=1 shape
/// remains covered by the sibling forward test above.
/// Fixture: egress row (logical) = RG2 active; tx member row = RG1
/// departed (its egress-row RG also names the departed owner — the
/// physical member IS RG1's). Departed arm: RG1 inactive. Control:
/// RG1 locally active -> served.
/// RED-on-revert: drop the owner arm and the reverse hit is
/// Consumed from the departed member.
#[test]
fn reverse_forward_candidate_egress_departed_falls_through_16217() {
    const TX_MEMBER_IFINDEX: i32 = 21;
    // Reverse key: server 172.16.50.200:443 -> SNAT client
    // 172.16.50.8:45678 (the translated tuple the WAN reply carries).
    fn reverse_entry() -> FlowCacheEntry {
        let mut entry = cached_entry();
        entry.key = crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 50, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 50, 8)),
            src_port: 443,
            dst_port: 45678,
            discriminator: Default::default(),
            routing_domain: 0,
        };
        // Live stamp=2 shape (FZDiag35): the seed recorded the
        // reply-egress (RETH) row's RG2 on BOTH stamp fields; the
        // physical TX member is still the departed RG1 interface.
        // Post-fix seeds stamp the forward owner (1) here — see the
        // doc comment above — but a row already carrying 2 (the
        // upgrade-era live shape) must still be superseded once its
        // LAN owner departs, which is what this fixture pins.
        entry.decision.resolution.tx_ifindex = TX_MEMBER_IFINDEX;
        entry.descriptor.egress_ifindex = EGRESS_IFINDEX;
        entry.descriptor.tx_ifindex = TX_MEMBER_IFINDEX;
        entry.metadata.is_reverse = true;
        entry.metadata.owner_rg_id = 2;
        entry.stamp.owner_rg_id = 2;
        entry.stamp.owner_rg_lease_until = 0;
        entry
    }
    fn reverse_frame() -> Vec<u8> {
        // Same VLAN-tagged TCP ACK builder, with the tuple swapped to
        // the reverse direction so frame/meta/key describe one packet.
        let mut frame = tcp_v4_ack_frame();
        // L3 at 18: src [30..34], dst [34..38]; L4 ports at [38..42].
        frame[30..34].copy_from_slice(&Ipv4Addr::new(172, 16, 50, 200).octets());
        frame[34..38].copy_from_slice(&Ipv4Addr::new(172, 16, 50, 8).octets());
        frame[38..40].copy_from_slice(&443u16.to_be_bytes());
        frame[40..42].copy_from_slice(&45678u16.to_be_bytes());
        frame
    }
    fn reverse_meta(frame: &[u8]) -> UserspaceDpMeta {
        let mut meta = test_meta(frame);
        let mut src_addr = [0u8; 16];
        src_addr[..4].copy_from_slice(&Ipv4Addr::new(172, 16, 50, 200).octets());
        let mut dst_addr = [0u8; 16];
        dst_addr[..4].copy_from_slice(&Ipv4Addr::new(172, 16, 50, 8).octets());
        meta.flow_src_addr = src_addr;
        meta.flow_dst_addr = dst_addr;
        meta.flow_src_port = 443;
        meta.flow_dst_port = 45678;
        meta
    }
    fn reverse_seed(entry: &FlowCacheEntry) -> StageSeed {
        StageSeed {
            flow: Some(SessionFlow {
                src_ip: entry.key.src_ip,
                dst_ip: entry.key.dst_ip,
                forward_key: entry.key.clone(),
            }),
            ..StageSeed::default()
        }
    }
    fn reverse_fixture(tx_active: bool) -> LiveCallSiteFixture {
        let mut fixture =
            LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
        // Logical egress row: RG2 (survives on this node).
        fixture
            .forwarding
            .egress
            .get_mut(&EGRESS_IFINDEX)
            .expect("zone-accounting fixture seeds the egress")
            .redundancy_group = 2;
        // Reply destination's connected owner (FZDiag35): the
        // reverse key's dst is the SNAT address 172.16.50.8; file
        // its /24 under the TX member (RG1) so
        // `connected_owner_rg_for_target` names the departed LAN
        // owner for the hit's target — the field the new
        // destination-owner arm judges for stamp=2 rows.
        fixture
            .forwarding
            .connected_v4
            .push(crate::afxdp::ConnectedRouteV4 {
                prefix: crate::prefix::PrefixV4::from_net(
                    "172.16.50.0/24".parse().expect("reply prefix"),
                ),
                host: std::net::Ipv4Addr::new(172, 16, 50, 0),
                ifindex: TX_MEMBER_IFINDEX,
                tunnel_endpoint_id: 0,
                table: "inet.0".to_string(),
            });
        // Physical TX member row: RG1 (departed after failover).
        fixture.forwarding.egress.insert(
            TX_MEMBER_IFINDEX,
            EgressInterface {
                bind_ifindex: TX_MEMBER_IFINDEX,
                vlan_id: INGRESS_VLAN_ID,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
                zone_id: TEST_TRUST_ZONE_ID,
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: None,
            },
        );
        fixture.ha_state.insert(
            2,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 1,
                lease: HAGroupRuntime::active_lease_until(1, 1),
            },
        );
        fixture.ha_state.insert(
            1,
            if tx_active {
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 1,
                    lease: HAGroupRuntime::active_lease_until(1, 1),
                }
            } else {
                HAGroupRuntime {
                    active: false,
                    watchdog_timestamp: 1,
                    lease: HAForwardingLease::Inactive,
                }
            },
        );
        fixture
    }
    let frame = reverse_frame();
    let meta = reverse_meta(&frame);
    // Departed: physical TX member RG1 inactive (fw1 owns it); the
    // logical RG2 attribution stays active, so only the TX arm fires.
    let fixture = reverse_fixture(false);
    let entry = reverse_entry();
    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry.clone(),
        0,
        reverse_seed(&entry),
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "#16217 reverse: cached reverse ForwardCandidate whose physical TX member RG departed must re-resolve (toward FabricRedirect), not TX out the departed member"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted
                as usize],
        1,
        "#16217 reverse: the departed supersession arm must own the reverse eviction"
    );
    // Control: TX member RG1 locally active -> reverse entry serves.
    let fixture = reverse_fixture(true);
    let entry = reverse_entry();
    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        entry.clone(),
        0,
        reverse_seed(&entry),
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "#16217 reverse control: locally-active TX member RG must keep serving the cached reverse ForwardCandidate"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted
                as usize],
        0,
        "#16217 reverse control: locally-active TX member must not move the supersession arm"
    );
}

/// #16217 (FZFixWire15): the subsequent-packet path for an adopted flow.
/// Packet 1 is the adoption resolve itself (driven through the production
/// resolver with `fabric_adopted = true`, exactly as the poll adoption
/// callsite runs it): it must yield the local ForwardCandidate, mark the
/// session fabric-established, and seed a fabric-established cache entry.
/// Packet 2 is an ordinary cache hit whose revalidation would demote the
/// cached ForwardCandidate to HAInactive (`EnforceChanged`) under the
/// receiving worker's stale HA snapshot: the adopted entry must be SERVED
/// (Consumed), not evicted. Packet 3 is the session-hit re-resolve after a
/// (hypothetical) eviction: the adopted context computed from the session
/// mark must again yield ForwardCandidate. Control: the identical flow
/// without adoption evicts on `EnforceChanged` and resolves HAInactive.
/// FAIL-ON-REVERT: drop the hit-path exemption, the seed mark, or the
/// session-hit adopted context and packet 2 evicts / packet 3 terminates.
#[test]
fn adopted_flow_survives_subsequent_packet_revalidation_16217() {
    // ── Packet 1: adoption resolve (production resolver, adopted) ──
    let mut sessions = crate::session::SessionTable::new();
    let key = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 55068,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(key.src_port),
        ..NatDecision::default()
    };
    let wire_key = crate::session::forward_wire_key(&key, nat);
    let mut forwarding = ForwardingState::default();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: crate::prefix::PrefixV4::from_net(
            Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap(),
        ),
        host: Ipv4Addr::new(172, 16, 80, 0),
        ifindex: EGRESS_IFINDEX,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.egress.insert(
        EGRESS_IFINDEX,
        EgressInterface {
            bind_ifindex: EGRESS_IFINDEX,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
            zone_id: TEST_UNTRUST_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );
    forwarding.neighbors.insert(
        (EGRESS_IFINDEX, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    // Receiving-worker HA snapshot: RG1 reads INACTIVE (the stale shape).
    let mut ha_state = BTreeMap::new();
    ha_state.insert(
        1,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: 1,
            lease: HAForwardingLease::Inactive,
        },
    );
    // Established synced session for the wire tuple (the adoption premise).
    let synced_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::FabricRedirect,
            local_ifindex: 0,
            egress_ifindex: 21,
            tx_ifindex: 21,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat,
        install_table_domain: 0,
        install_table_check: 0,
    };
    let entry = SyncedSessionEntry {
        key: wire_key.clone(),
        decision: synced_decision,
        metadata: SessionMetadata {
            ingress_zone: TEST_TRUST_ZONE_ID,
            egress_zone: TEST_UNTRUST_ZONE_ID,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
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
            nat_scope_ifindex: None,
        },
        leak_incarnation: 0,
        origin: crate::session::SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x18,
        generation: 0,
        session_id: 4243,
        tcp_close_class: 0,
        tcp_handshake_state: crate::session::TcpHandshakeState::Established.to_wire(),
        rev_packets: 1,
        fwd_packets: 1,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
        source_nat_static: None,
    };
    let shared_sessions = Arc::new(std::sync::Mutex::new(crate::afxdp::FastMap::default()));
    let shared_nat_sessions = Arc::new(std::sync::Mutex::new(crate::afxdp::FastMap::default()));
    let shared_forward_wire_sessions =
        Arc::new(std::sync::Mutex::new(crate::afxdp::FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    crate::afxdp::shared_ops::publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    assert!(
        crate::afxdp::shared_ops::fabric_adoption_established_for_wire(
            &sessions,
            &shared_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &wire_key,
            1_000_000,
        ),
        "premise: adoption gate must qualify the Established wire tuple"
    );
    let flow = SessionFlow {
        src_ip: wire_key.src_ip,
        dst_ip: wire_key.dst_ip,
        forward_key: wire_key.clone(),
    };
    let dynamic_neighbors = Arc::new(crate::afxdp::sharded_neighbor::ShardedNeighborMap::new());
    let peer_worker_commands: Vec<
        Arc<std::sync::Mutex<std::collections::VecDeque<WorkerCommand>>>,
    > = Vec::new();
    let resolve = |sessions: &mut crate::session::SessionTable, adopted: bool| {
        crate::afxdp::session_glue::resolve_flow_session_decision_with_conntrack_and_payload_and_ack(
            sessions,
            SteeringMap::unshared_for_test(-1),
            crate::afxdp::session_glue::SharedSessionRefs {
                sessions: &shared_sessions,
                nat_sessions: &shared_nat_sessions,
                forward_wire_sessions: &shared_forward_wire_sessions,
                owner_rg_indexes: &shared_owner_rg_indexes,
                peer_worker_commands: &peer_worker_commands,
                worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
                conntrack: crate::afxdp::session_glue::ConntrackFds { v4: -1, v6: -1 },
                tick: crate::afxdp::session_glue::Tick::from_parts(1_000_000, 1),
            },
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            &flow,
            PROTO_TCP,
            0x18,
            0,
            21,
            0,
            true,
            true,
            0,
            0,
            None,
            None,
            adopted,
            adopted.then(|| crate::afxdp::session_glue::AdoptedRecovery {
                decision: synced_decision,
                flow_key: wire_key.clone(),
                proved_rg: 1,
            }),
        )
        .expect("wire session should resolve")
    };
    // Control (fail-closed): without adoption the same resolve terminates.
    let mut control_sessions = crate::session::SessionTable::new();
    assert_eq!(
        resolve(&mut control_sessions, false)
            .decision
            .resolution
            .disposition,
        ForwardingDisposition::HAInactive,
        "non-adopted control must stay fail-closed on the HA terminal"
    );
    // Adopted resolve yields the local candidate; mark at adoption (the
    // poll adoption site's two marks: gate row + resolved row).
    let adopted = resolve(&mut sessions, true);
    assert_eq!(
        adopted.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate,
        "adopted resolve must yield the local ForwardCandidate"
    );
    sessions.mark_fabric_established_for_wire(&wire_key, 1_000_000);
    sessions.mark_fabric_established_for_wire(&adopted.key, 1_000_000);
    // The transient resolve may leave no local row to mark (production lands
    // it via the poll Owner-verdict purge/promote); install the resolved
    // serving row directly when absent, as that landing does, then mark it.
    if sessions.entry_with_origin(&adopted.key).is_none() {
        assert!(sessions.install_with_protocol_with_origin(
            adopted.key.clone(),
            adopted.decision.clone(),
            adopted.metadata.clone(),
            crate::session::SessionOrigin::WorkerLocalImport,
            1_000_000,
            PROTO_TCP,
            0x18,
        ));
        sessions.mark_fabric_established_for_wire(&adopted.key, 1_000_000);
        sessions.mark_fabric_established_for_wire(&wire_key, 1_000_000);
    }
    assert!(
        sessions.fabric_established_for_wire_at(&wire_key, 1_000_000),
        "adoption must mark the session fabric-established for subsequent packets"
    );
    // ── Packet 2: cache hit -> EnforceChanged revalidation ──
    // Seed the cache exactly as the adoption forward would (forward seed
    // with the adopted mark), then drive the live hit stage under the same
    // stale HA snapshot. The cached decision's egress (EGRESS_IFINDEX) is
    // RG1 in the hit fixture, so enforce demotes it: EnforceChanged.
    let frame = tcp_v4_ack_frame();
    let meta = test_meta(&frame);
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture
        .forwarding
        .egress
        .get_mut(&EGRESS_IFINDEX)
        .expect("egress")
        .redundancy_group = 1;
    // Wire18 (B2): this packet is the ADOPTION ITSELF (the packet right
    // after `mark_fabric_established`): the worker's HA snapshot still
    // reads RG1 INACTIVE (the stale shape adoption bypasses), so enforce
    // demotes the cached candidate — EnforceChanged. The adoption proof
    // is RE-VALIDATED here against the SESSION-side proof (the poll
    // session-hit context: local established row / shared wire / live
    // gate), which is exactly what stage 2's `session_hit_fabric_adopted`
    // computes in production: Wire15 packet 2 drives this same hit stage
    // standalone with `now_secs` at the adoption instant, BEFORE the
    // worker snapshot has caught up to the gate's ownership proof, so
    // the revalidation clock is the GATE proof age — the gate qualified
    // at `now_ns` with this node as owner, and the hit re-checks the
    // mark against the gate-era snapshot the resolve itself used. The
    // FAILBACK case (snapshot fully caught up AND RG gone again) is the
    // separate `adopted_mark_revalidates_ownership_each_hit_16217` cell.
    fixture.ha_state.insert(
        1,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: 1,
            lease: HAForwardingLease::Inactive,
        },
    );
    let mut adopted_entry = cached_entry();
    adopted_entry.fabric_established = true;
    // The transient resolve may leave no local row to mark (production lands
    // it via the poll Owner-verdict purge/promote); install the resolved
    // serving row directly when absent, as that landing does, then mark it.
    if sessions.entry_with_origin(&adopted.key).is_none() {
        assert!(sessions.install_with_protocol_with_origin(
            adopted.key.clone(),
            adopted.decision.clone(),
            adopted.metadata.clone(),
            crate::session::SessionOrigin::WorkerLocalImport,
            1_000_000,
            PROTO_TCP,
            0x18,
        ));
        sessions.mark_fabric_established_for_wire(&adopted.key, 1_000_000);
        sessions.mark_fabric_established_for_wire(&wire_key, 1_000_000);
    }
    assert!(
        sessions.fabric_established_for_wire_at(&wire_key, 1_000_000),
        "adoption must mark the session fabric-established for subsequent packets"
    );
    let run = run_stage_seeded(
        &fixture,
        &frame,
        meta,
        adopted_entry,
        0,
        StageSeed::default(),
    );
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "#16217: with departure checked BEFORE enforce, this fixture (egress row present, RG1 inactive) spells ForwardCandidateEgressDeparted, which the mark NEVER suppresses -- the adopted entry falls through and the session-hit re-resolve (packet 3, adopted context) serves it"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted
                as usize],
        1,
        "the departed arm must own this supersession"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitEnforceChanged as usize],
        0,
        "EnforceChanged must not mask the departed arm"
    );
    // Control: the identical entry WITHOUT the adoption mark evicts.
    let mut plain_entry = cached_entry();
    plain_entry.metadata.owner_rg_id = 1;
    plain_entry.stamp.owner_rg_id = 1;
    let run = run_stage_seeded(&fixture, &frame, meta, plain_entry, 0, StageSeed::default());
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "non-adopted control entry must still evict and fall through (fail-closed)"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm[crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitEnforceChanged as usize]
            + run.flow_cache_evictions_by_arm[crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted as usize],
        1,
        "non-adopted control must attribute exactly one supersession eviction"
    );
    // ── Packet 3: session-hit re-resolve with the adopted context ──
    // The poll session-hit site computes `session_hit_fabric_adopted` from
    // the session mark (plus the gate); here the mark alone must carry it.
    let adopted_ctx = sessions.fabric_established_for_wire_at(&wire_key, 1_000_000);
    assert!(
        adopted_ctx,
        "session-hit adopted context must derive from the adoption mark"
    );
    let hit = resolve(&mut sessions, adopted_ctx);
    assert_eq!(
        hit.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate,
        "session-hit re-resolve of an adopted flow must not die on ha_inactive"
    );
}

/// #16217 (Wire18): the lookup-fence path — the live fw0 shape proven by
/// FZFixWire17. Pre-failover the entry is seeded with a lease-carrying
/// stamp; AT the failover the RG epoch bumps AND the runtime lease drops,
/// so on master `FlowCache::lookup_*` evicts the entry at the
/// `LookupRgEpoch`/`LookupLease` fence BEFORE `stage_flow_cache_hit` ever
/// runs decision revalidation (`forwarding/ha.rs:551` can never fire —
/// the hit path is never reached). The slow path then re-serves/re-seeds
/// the same ForwardCandidate locally: permanent blackhole, with
/// `enforce_changed=0` and zero redirect arms in the post-FO stats.
///
/// This cell drives the PRODUCTION lookup (via `stage_flow_cache_hit`,
/// not a direct hand-off of the cached decision to the validator): the
/// fence must ADMIT the departed-egress candidate to the hit stage, where
/// decision revalidation supersedes it
/// (`PostHitForwardCandidateEgressDeparted` / `PostHitEnforceChanged`) and
/// the packet falls through to the slow-path re-resolve. The slow-path
/// leg is then driven through the production resolver (NOT adopted): the
/// fresh ForwardCandidate HA-demotes and the fabric converter produces
/// `FabricRedirect` — the conversion stays intact end to end.
///
/// Controls: (a) RG1 locally active — the identical fence-failing entry
/// is still fenced (the admission is departure-scoped, not a fence
/// removal); (b) the departed entry WITHOUT the egress-RG stamp
/// (owner rg 0) is still fenced. FAIL-ON-REVERT: drop the fence admission
/// and the departed hit never reaches the stage — `lookup_rg_epoch` /
/// `lookup_lease` move instead of the PostHit supersession arm, and the
/// stage outcome is indistinguishable from a plain miss.
#[test]
fn lookup_fence_departed_candidate_reaches_hit_stage_16217() {
    let frame = tcp_v4_ack_frame();
    let meta = test_meta(&frame);
    // Departed: egress RG1 present but inactive (peer-owned now). The
    // entry carries the pre-failover lease stamp (lease_until 100) while
    // the runtime map now reads RG1 inactive (current lease 0) AND the
    // epoch has bumped 3 -> 4: BOTH lookup fences fail on master.
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture
        .forwarding
        .egress
        .get_mut(&EGRESS_IFINDEX)
        .expect("zone-accounting fixture seeds the egress")
        .redundancy_group = 1;
    fixture.ha_state.insert(
        1,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: 1,
            lease: HAForwardingLease::Inactive,
        },
    );
    fixture.rg_epochs[1].store(4, Ordering::Relaxed);
    let mut entry = cached_entry();
    entry.metadata.owner_rg_id = 1;
    entry.stamp.owner_rg_id = 1;
    entry.stamp.owner_rg_epoch = 3;
    entry.stamp.owner_rg_lease_until = 100;
    let run = run_stage_seeded(&fixture, &frame, meta, entry, 0, StageSeed::default());
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "#16217 Wire18: fence-admitted departed candidate must fall through to the slow-path re-resolve, not serve locally"
    );
    // The supersession is attributed at the HIT stage, not at the lookup
    // fences: neither fence arm moved, exactly one PostHit supersession
    // arm did. On master the lookup evicts first (LookupRgEpoch) and the
    // PostHit arms stay 0 — this is the discriminating assertion.
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::LookupRgEpoch as usize],
        0,
        "the rg-epoch fence must NOT preempt a departed-egress candidate"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::LookupLease as usize],
        0,
        "the lease fence must NOT preempt a departed-egress candidate"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted
                as usize],
        1,
        "hit-stage decision revalidation must supersede the admitted candidate via the DEPARTED arm (validator checks departure BEFORE enforce)"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitEnforceChanged as usize],
        0,
        "the departed arm, not EnforceChanged, owns this eviction"
    );
    // Slow-path leg: the fall-through re-resolve (unadopted, as on fw0)
    // HA-demotes the fresh candidate and the fabric converter produces
    // FabricRedirect — the conversion the fence used to starve.
    let mut forwarding = ForwardingState::default();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: crate::prefix::PrefixV4::from_net(
            Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap(),
        ),
        host: Ipv4Addr::new(172, 16, 80, 0),
        ifindex: EGRESS_IFINDEX,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.egress.insert(
        EGRESS_IFINDEX,
        EgressInterface {
            bind_ifindex: EGRESS_IFINDEX,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
            zone_id: TEST_UNTRUST_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );
    // Fabric parent (egress 21) the redirect egresses on — registered as a
    // FabricLink, the form `resolve_fabric_redirect` reads.
    forwarding.fabrics.push(FabricLink {
        parent_ifindex: 21,
        overlay_ifindex: 101,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        up: true,
        link_authenticated: false,
    });
    let mut ha_state = BTreeMap::new();
    ha_state.insert(
        1,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: 1,
            lease: HAForwardingLease::Inactive,
        },
    );
    let candidate = ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: EGRESS_IFINDEX,
        tx_ifindex: EGRESS_IFINDEX,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x80, 0x00]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]),
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    };
    let enforced = crate::afxdp::session_glue::enforce_session_ha_resolution(
        &forwarding,
        &ha_state,
        1,
        candidate,
        PHYS_INGRESS_IFINDEX,
        0,
    );
    assert_eq!(
        enforced.disposition,
        ForwardingDisposition::HAInactive,
        "premise: the unadopted slow-path re-resolve HA-demotes the departed candidate"
    );
    let converted = crate::afxdp::session_glue::redirect_session_via_fabric_if_needed_at(
        &forwarding,
        &ha_state,
        1,
        enforced,
        false,
        TEST_TRUST_ZONE_ID,
    );
    assert_eq!(
        converted.disposition,
        ForwardingDisposition::FabricRedirect,
        "the slow-path fabric conversion must stay intact: departed candidate re-resolves to FabricRedirect, got {:?}",
        converted.disposition
    );
    // Control (a): RG1 locally ACTIVE — the identical fence-failing entry
    // (epoch bumped, lease dropped) is still fenced at lookup: the
    // admission is scoped to departure, not a fence removal.
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture
        .forwarding
        .egress
        .get_mut(&EGRESS_IFINDEX)
        .expect("zone-accounting fixture seeds the egress")
        .redundancy_group = 1;
    fixture.ha_state.insert(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: 1,
            lease: HAGroupRuntime::active_lease_until(1, 1),
        },
    );
    fixture.rg_epochs[1].store(4, Ordering::Relaxed);
    let mut entry = cached_entry();
    entry.metadata.owner_rg_id = 1;
    entry.stamp.owner_rg_id = 1;
    entry.stamp.owner_rg_epoch = 3;
    entry.stamp.owner_rg_lease_until = 100;
    let run = run_stage_seeded(&fixture, &frame, meta, entry, 0, StageSeed::default());
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "control: a fence-failing entry whose RG is locally active still falls through (fenced), it is not served stale"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::LookupRgEpoch as usize]
            + run.flow_cache_evictions_by_arm
                [crate::afxdp::flow_cache::FlowCacheEvictionArm::LookupLease as usize],
        1,
        "control: locally-active RG keeps the pre-existing fence behaviour (exactly one fence arm moves)"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted
                as usize],
        0,
        "control: locally-active RG never reaches the departed supersession arm"
    );
    // Control (b): departed HA state but the entry names NO egress RG
    // (stamp owner rg 0 AND the fixture's default egress row is RG0, so
    // `owner_rg_for_resolution` reads 0) -- the egress-RG admission must
    // not fire; the epoch fence (owner slot 0 bumped) still preempts.
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture.ha_state.insert(
        1,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: 1,
            lease: HAForwardingLease::Inactive,
        },
    );
    fixture.rg_epochs[0].store(9, Ordering::Relaxed);
    let mut entry = cached_entry();
    entry.metadata.owner_rg_id = 0;
    entry.stamp.owner_rg_id = 0;
    entry.stamp.owner_rg_epoch = 3;
    entry.stamp.owner_rg_lease_until = 0;
    let run = run_stage_seeded(&fixture, &frame, meta, entry, 0, StageSeed::default());
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "control: an ownerless fence-failing entry still falls through (fenced)"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::LookupRgEpoch as usize],
        1,
        "control: ownerless entries keep the pre-existing epoch fence (admission is departure-scoped)"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted
                as usize]
            + run.flow_cache_evictions_by_arm
                [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitEnforceChanged as usize],
        0,
        "control: ownerless entries never reach hit-stage supersession via the fence admission"
    );
}

/// #16217 (Wire18, B2): the fabric-established mark must re-validate RG
/// ownership on every hit. The proof behind the mark is "this node owns
/// the egress RG" — once that RG leaves this node again (FAILBACK) the
/// proof is stale and the adopted exemption must lapse: the flow converts
/// again instead of being served/exempted on the stale mark forever.
///
/// Two enforcement points, both driven here against CURRENT ownership:
/// (1) cache arm split — a marked entry whose validator returns the
/// `ForwardCandidateEgressDeparted` arm (enforce-equal shapes, where the
/// departure arm is what fires) is NEVER suppressed by the mark; it
/// supersedes and falls through. On master the mark suppressed BOTH arms,
/// so this shape was Consumed. (2) session context — the helper the poll
/// session-hit site shares (`revalidate_fabric_established` over the
/// marked row's stored decision) holds while the egress RG is locally
/// active and lapses the moment it departs, so the next re-resolve runs
/// unadopted (HA-demote + fabric conversion).
/// FAIL-ON-REVERT: restore the two-arm suppression and leg (1) is
/// Consumed; drop the session-site revalidation and leg (2) stays true.
#[test]
fn adopted_mark_revalidates_ownership_each_hit_16217() {
    let frame = tcp_v4_ack_frame();
    let _meta = test_meta(&frame);
    // Failback: the ADOPTED entry's egress RG1 is no longer
    // forwarding-active here. The validator spells this shape's rejection
    // `EnforceChanged` (enforce runs before the departure arm whenever the
    // egress row still exists), so the cache arm alone cannot distinguish
    // failback from the adoption-window lag — the lapse is enforced where
    // current ownership is judged per hit, the session context. This test
    // pins both production legs on the failback state: (1) the helper the
    // poll session-hit site shares judges the marked entry's ownership as
    // LAPSED (its next re-resolve runs unadopted: HA-demote + fabric
    // conversion), and (2) driven through the live hit stage, the entry
    // does NOT gain any new exemption from the stale mark — its outcome
    // is decided by ordinary revalidation state, asserted via the
    // departure predicate on the same fixture.
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture
        .forwarding
        .egress
        .get_mut(&EGRESS_IFINDEX)
        .expect("zone-accounting fixture seeds the egress")
        .redundancy_group = 1;
    fixture.ha_state.insert(
        1,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: 1,
            lease: HAForwardingLease::Inactive,
        },
    );
    let mut entry = cached_entry();
    entry.fabric_established = true;
    entry.metadata.owner_rg_id = 1;
    entry.stamp.owner_rg_id = 1;
    entry.stamp.owner_rg_lease_until = 0;
    // (1) Session-context leg: the marked row's stored decision no longer
    // re-validates — the poll session-hit site computes exactly this over
    // `fabric_established_decision_for_wire_at`.
    assert!(
        !crate::afxdp::forwarding::revalidate_fabric_established(
            &fixture.forwarding,
            &fixture.ha_state,
            1,
            entry.fabric_established,
            entry.decision.resolution,
        ),
        "#16217 Wire18 B2: after failback the marked entry's ownership proof must lapse (session-hit context unadopted)"
    );
    assert!(
        crate::afxdp::forwarding::forward_candidate_egress_departed(
            &fixture.forwarding,
            &fixture.ha_state,
            1,
            entry.decision.resolution,
        ),
        "premise: the failback fixture's egress RG reads departed"
    );
    // (2) Hit-stage leg: with the session context lapsed, the slow path
    // the fall-through reaches re-resolves UNADOPTED — driven here through
    // the production enforce + fabric converter on the same state (the
    // conversion the Wire18 fence test pins end-to-end for the fw0 leg).
    let enforced = crate::afxdp::session_glue::enforce_session_ha_resolution(
        &fixture.forwarding,
        &fixture.ha_state,
        1,
        entry.decision.resolution,
        PHYS_INGRESS_IFINDEX,
        0,
    );
    assert_eq!(
        enforced.disposition,
        ForwardingDisposition::HAInactive,
        "premise: the unadopted failback re-resolve HA-demotes"
    );
    // Conversion leg: the unadopted failback re-resolve fabric-converts.
    fixture.forwarding.fabrics.push(FabricLink {
        parent_ifindex: 21,
        overlay_ifindex: 101,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        up: true,
        link_authenticated: false,
    });
    let converted = crate::afxdp::session_glue::redirect_session_via_fabric_if_needed_at(
        &fixture.forwarding,
        &fixture.ha_state,
        1,
        enforced,
        false,
        TEST_TRUST_ZONE_ID,
    );
    assert_eq!(
        converted.disposition,
        ForwardingDisposition::FabricRedirect,
        "failback converts again: the lapsed flow re-resolves to FabricRedirect, got {:?}",
        converted.disposition
    );
    // Predicate-level pin (the same helper the hit stage and the poll
    // session-hit site share): ownership holding keeps the proof,
    // departure lapses it, unmarked never holds it. (Fold B6: the
    // packet-path sites now judge the FRESH-set twin
    // `revalidate_fabric_established_fresh`, pinned directly below;
    // the snapshot helper remains the fixture-level form.)
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        EGRESS_IFINDEX,
        EgressInterface {
            bind_ifindex: EGRESS_IFINDEX,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
            zone_id: TEST_UNTRUST_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: None,
        },
    );
    let resolution = ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: EGRESS_IFINDEX,
        tx_ifindex: EGRESS_IFINDEX,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    };
    let mut active_ha = BTreeMap::new();
    active_ha.insert(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: 1,
            lease: HAGroupRuntime::active_lease_until(1, 1),
        },
    );
    assert!(
        crate::afxdp::forwarding::revalidate_fabric_established(
            &forwarding,
            &active_ha,
            1,
            true,
            resolution
        ),
        "marked + egress RG locally active: the adoption proof still holds"
    );
    let mut departed_ha = BTreeMap::new();
    departed_ha.insert(
        1,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: 1,
            lease: HAForwardingLease::Inactive,
        },
    );
    assert!(
        !crate::afxdp::forwarding::revalidate_fabric_established(
            &forwarding,
            &departed_ha,
            1,
            true,
            resolution
        ),
        "marked + egress RG departed: the adoption proof lapses (failback converts again)"
    );
    assert!(
        !crate::afxdp::forwarding::revalidate_fabric_established(
            &forwarding,
            &active_ha,
            1,
            false,
            resolution
        ),
        "unmarked entries never hold the proof"
    );
}

/// #16217 (fold B6): the FRESH-set revalidator the packet-path sites
/// judge (`revalidate_fabric_established_fresh`, against
/// `worker_ctx.forwarding_active_rgs`) — marked + egress RG in the
/// fresh set holds the proof even when the per-tick `ha_state`
/// snapshot still reads it inactive (adoption-window lag: the exact
/// shape the fresh set exists for); marked + egress RG ABSENT from
/// the fresh set lapses even when a stale snapshot reads it active
/// (failback caught by the fresh set first); unknown RG (0) and
/// unmarked never qualify; a marked FabricRedirect keeps the
/// redirect-arm exemption.
///
/// MUTATION: judge against `ha_state` instead of the fresh set and
/// both lag/failback cells invert.
#[test]
fn adopted_mark_fresh_set_revalidation_16217() {
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        EGRESS_IFINDEX,
        EgressInterface {
            bind_ifindex: EGRESS_IFINDEX,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
            zone_id: TEST_UNTRUST_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: None,
        },
    );
    let candidate = ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: EGRESS_IFINDEX,
        tx_ifindex: EGRESS_IFINDEX,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    };
    let fresh_owner: std::collections::BTreeSet<i32> = [1].into_iter().collect();
    let fresh_departed: std::collections::BTreeSet<i32> = std::collections::BTreeSet::new();
    assert!(
        crate::afxdp::forwarding::revalidate_fabric_established_fresh(
            &forwarding,
            &fresh_owner,
            true,
            candidate
        ),
        "marked + egress RG in fresh set: proof holds (adoption window)"
    );
    assert!(
        !crate::afxdp::forwarding::revalidate_fabric_established_fresh(
            &forwarding,
            &fresh_departed,
            true,
            candidate
        ),
        "marked + egress RG absent from fresh set: proof lapses (failback)"
    );
    assert!(
        !crate::afxdp::forwarding::revalidate_fabric_established_fresh(
            &forwarding,
            &fresh_owner,
            false,
            candidate
        ),
        "unmarked entries never hold the proof"
    );
    // Unknown egress RG (0): never qualifies even on the owner set.
    let mut unknown = candidate;
    unknown.egress_ifindex = 0;
    assert!(
        !crate::afxdp::forwarding::revalidate_fabric_established_fresh(
            &forwarding,
            &fresh_owner,
            true,
            unknown
        ),
        "unknown egress RG never keeps the proof"
    );
    // Marked FabricRedirect: no local egress to depart — exemption.
    let mut redirect = candidate;
    redirect.disposition = ForwardingDisposition::FabricRedirect;
    assert!(
        crate::afxdp::forwarding::revalidate_fabric_established_fresh(
            &forwarding,
            &fresh_departed,
            true,
            redirect
        ),
        "marked FabricRedirect keeps the redirect-arm exemption"
    );
}

/// #16217 (fold B6, stage level): a marked entry whose fresh-set
/// revalidation LAPSES must not suppress the `EnforceChanged`
/// supersession even though the raw mark is set. Fixture: egress RG1,
/// `ha_state` reads RG1 INACTIVE (so the validator's enforce arm
/// demotes the candidate — the `EnforceChanged` shape the mark used
/// to suppress), fresh set EMPTY (the authoritative set agrees the
/// mark has lapsed). With the fold, fresh revalidation is false, so
/// nothing suppresses the demotion and the entry falls through to
/// re-resolve unadopted. Pre-fold the stage computed the
/// revalidation, discarded it, and the raw mark suppressed it.
///
/// MUTATION: restore `let _ = adopted_mark_revalidated;` (raw-mark
/// suppression) and this entry is Consumed instead of FallThrough.
#[test]
fn stage_hit_marked_entry_fresh_lapse_does_not_suppress_16217() {
    let frame = tcp_v4_ack_frame();
    let meta = test_meta(&frame);
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture
        .forwarding
        .egress
        .get_mut(&EGRESS_IFINDEX)
        .expect("zone-accounting fixture seeds the egress")
        .redundancy_group = 1;
    // Snapshot reads RG1 inactive (validator demotes via EnforceChanged);
    // the fresh set excludes it too, so the mark has lapsed under BOTH.
    fixture.ha_state.insert(
        1,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: 1,
            lease: HAForwardingLease::Inactive,
        },
    );
    fixture.fresh_active_rgs.clear();
    let mut entry = cached_entry();
    entry.fabric_established = true;
    entry.metadata.owner_rg_id = 1;
    entry.stamp.owner_rg_id = 1;
    entry.stamp.owner_rg_lease_until = 0;
    let run = run_stage_seeded(&fixture, &frame, meta, entry, 0, StageSeed::default());
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "#16217 B6: a marked entry whose fresh-set proof lapsed must fall through (no raw-mark suppression), got Consumed"
    );
}
/// #16217 (egress-RG fence + revalidated suppression + gate): three
/// production-path pins driven through `stage_flow_cache_hit` /
/// `fabric_adoption_gate_for_wire`, NOT through helper-level hand-offs.
/// (1) The lookup fence admits on the EGRESS RG: an entry whose stamp
/// owner is rg 0 (the live fw0 shape -- `stamp_owner_rg=0` while the
/// egress interface is RG1) is still admitted past BOTH fences when
/// egress RG1 has departed, and supersedes via the DEPARTED arm.
/// (2) A marked (adopted) entry whose egress RG has departed is never
/// served from cache even though its mark is set -- it falls through.
/// (3) The adoption gate declines on a NON-OWNER node: Established
/// evidence alone does not adopt when the FIB egress RG is not
/// forwarding-active locally; it adopts only on the owner.
/// FAIL-ON-REVERT: restore the stamp-owner fence and (1) fences;
/// restore raw-mark suppression and (2) is Consumed; drop the
/// ownership half of the gate and (3) adopts on the non-owner.
#[test]
fn stage_hit_egress_rg_fence_and_nonowner_gate_16217() {
    let frame = tcp_v4_ack_frame();
    let meta = test_meta(&frame);
    // (1) stamp owner 0, egress RG1 departed, both fences failing.
    {
        let mut fixture =
            LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
        fixture
            .forwarding
            .egress
            .get_mut(&EGRESS_IFINDEX)
            .expect("zone-accounting fixture seeds the egress")
            .redundancy_group = 1;
        fixture.ha_state.insert(
            1,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: 1,
                lease: HAForwardingLease::Inactive,
            },
        );
        fixture.rg_epochs[0].store(9, Ordering::Relaxed);
        let mut entry = cached_entry();
        entry.metadata.owner_rg_id = 0;
        entry.stamp.owner_rg_id = 0;
        entry.stamp.owner_rg_epoch = 3;
        entry.stamp.owner_rg_lease_until = 100;
        let run = run_stage_seeded(&fixture, &frame, meta, entry, 0, StageSeed::default());
        assert!(
            matches!(run.outcome, FlowCacheOutcome::FallThrough),
            "#16217: stamp-owner-0 entry with departed egress RG1 must fall through via hit-stage supersession, not serve or fence"
        );
        assert_eq!(
            run.flow_cache_evictions_by_arm
                [crate::afxdp::flow_cache::FlowCacheEvictionArm::LookupRgEpoch as usize]
                + run.flow_cache_evictions_by_arm
                    [crate::afxdp::flow_cache::FlowCacheEvictionArm::LookupLease as usize],
            0,
            "neither lookup fence may preempt an egress-departed candidate"
        );
        assert_eq!(
            run.flow_cache_evictions_by_arm[crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted as usize],
            1,
            "the egress-RG departed arm must own the supersession"
        );
    }
    // (2) marked entry, egress RG1 departed: never served.
    {
        let mut fixture =
            LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
        fixture
            .forwarding
            .egress
            .get_mut(&EGRESS_IFINDEX)
            .expect("zone-accounting fixture seeds the egress")
            .redundancy_group = 1;
        fixture.ha_state.insert(
            1,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: 1,
                lease: HAForwardingLease::Inactive,
            },
        );
        let mut entry = cached_entry();
        entry.fabric_established = true;
        entry.metadata.owner_rg_id = 1;
        entry.stamp.owner_rg_id = 1;
        entry.stamp.owner_rg_lease_until = 0;
        let run = run_stage_seeded(&fixture, &frame, meta, entry, 0, StageSeed::default());
        assert!(
            matches!(run.outcome, FlowCacheOutcome::FallThrough),
            "#16217: a marked entry whose egress RG departed must fall through, never serve on the stale mark"
        );
    }
    // (3) non-owner gate declines; owner gate adopts.
    {
        let mut sessions = crate::session::SessionTable::new();
        let key = test_key();
        let mut forwarding = ForwardingState::default();
        forwarding.connected_v4.push(ConnectedRouteV4 {
            prefix: crate::prefix::PrefixV4::from_net(
                Ipv4Net::new(Ipv4Addr::new(172, 16, 50, 0), 24).unwrap(),
            ),
            host: Ipv4Addr::new(172, 16, 50, 0),
            ifindex: EGRESS_IFINDEX,
            tunnel_endpoint_id: 0,
            table: "inet.0".to_string(),
        });
        forwarding.egress.insert(
            EGRESS_IFINDEX,
            EgressInterface {
                bind_ifindex: EGRESS_IFINDEX,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
                zone_id: TEST_UNTRUST_ZONE_ID,
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: None,
            },
        );
        let entry = cached_entry();
        assert!(sessions.install_with_protocol_with_origin(
            key.clone(),
            entry.decision.clone(),
            entry.metadata.clone(),
            crate::session::SessionOrigin::WorkerLocalImport,
            1_000_000,
            PROTO_TCP,
            0x18,
        ));
        let shared_sessions = Arc::new(std::sync::Mutex::new(crate::afxdp::FastMap::default()));
        let shared_forward_wire_sessions =
            Arc::new(std::sync::Mutex::new(crate::afxdp::FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        assert!(
            crate::afxdp::shared_ops::fabric_adoption_established_for_wire(
                &sessions,
                &shared_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &key,
                1_000_000,
            ),
            "premise: Established evidence alone qualifies (the pre-GLM-N1 gate)"
        );
        let mut non_owner_ha = BTreeMap::new();
        non_owner_ha.insert(
            1,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: 1,
                lease: HAForwardingLease::Inactive,
            },
        );
        let dyn_neigh = Arc::new(crate::afxdp::sharded_neighbor::ShardedNeighborMap::new());
        assert!(
            !crate::afxdp::shared_ops::fabric_adoption_gate_for_wire(
                &forwarding,
                &non_owner_ha,
                &std::collections::BTreeSet::new(),
                1,
                &sessions,
                &shared_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &key,
                1_000_000,
                &dyn_neigh,
            ),
            "#16217 GLM N1: a non-owner (egress RG1 not forwarding-active) must NOT adopt despite Established evidence"
        );
        let mut owner_ha = BTreeMap::new();
        owner_ha.insert(
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 1,
                lease: HAGroupRuntime::active_lease_until(1, 1),
            },
        );
        assert!(
            crate::afxdp::shared_ops::fabric_adoption_gate_for_wire(
                &forwarding,
                &owner_ha,
                &std::collections::BTreeSet::from([1]),
                1,
                &sessions,
                &shared_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &key,
                1_000_000,
                &dyn_neigh,
            ),
            "#16217 GLM N1: the forwarding-active owner of egress RG1 adopts"
        );
        // #16217 (ownership lag): the AUTHORITATIVE fresh set, not
        // the cached snapshot, decides. Cached snapshot says owner
        // (active) but the fresh coordinator set does NOT contain
        // RG1 -> decline; cached says non-owner but fresh set
        // contains RG1 -> adopt. FAIL-ON-REVERT: revert the gate to
        // the cached `ha_state` and both arms flip.
        assert!(
            !crate::afxdp::shared_ops::fabric_adoption_gate_for_wire(
                &forwarding,
                &owner_ha,
                &std::collections::BTreeSet::new(),
                1,
                &sessions,
                &shared_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &key,
                1_000_000,
                &dyn_neigh,
            ),
            "#16217 ownership lag: fresh authoritative set without RG1 must decline even when cached snapshot says owner"
        );
        assert!(
            crate::afxdp::shared_ops::fabric_adoption_gate_for_wire(
                &forwarding,
                &non_owner_ha,
                &std::collections::BTreeSet::from([1]),
                1,
                &sessions,
                &shared_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &key,
                1_000_000,
                &dyn_neigh,
            ),
            "#16217 ownership lag: fresh authoritative set with RG1 must adopt even when cached snapshot lags inactive"
        );
    }
}

/// #16217 (Codex N1 final): the gate must resolve ownership in the
/// session's OWN installed table (tenant), not MAIN. Fixture: dst
/// 172.16.50.200 connected in MAIN via egress 7 (RG1) and in tenant
/// "blue" via egress 8 (RG2); the session carries blue's
/// install_table_domain/check. Fresh set {2} (tenant owner only)
/// must ADOPT; fresh set {1} (MAIN owner only) must DECLINE.
/// FAIL-ON-REVERT: MAIN lookup flips both arms.
#[test]
fn gate_resolves_in_session_install_table_not_main_16217() {
    let mut sessions = crate::session::SessionTable::new();
    let key = test_key();
    let (domain, check) = crate::session::install_table_identity("blue");
    let mut forwarding = ForwardingState::default();
    for (ifindex, rg, table) in [(EGRESS_IFINDEX, 1, "inet.0"), (8, 2, "blue.inet.0")] {
        forwarding.connected_v4.push(ConnectedRouteV4 {
            prefix: crate::prefix::PrefixV4::from_net(
                Ipv4Net::new(Ipv4Addr::new(172, 16, 50, 0), 24).unwrap(),
            ),
            host: Ipv4Addr::new(172, 16, 50, 0),
            ifindex,
            tunnel_endpoint_id: 0,
            table: table.to_string(),
        });
        forwarding.egress.insert(
            ifindex,
            EgressInterface {
                bind_ifindex: ifindex,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
                zone_id: TEST_UNTRUST_ZONE_ID,
                redundancy_group: rg,
                primary_v4: None,
                primary_v6: None,
            },
        );
    }
    forwarding.install_tables.insert(
        domain,
        InstallTables {
            v4: Some("blue.inet.0".to_string()),
            v6: None,
            h2: check,
        },
    );
    let mut entry = cached_entry();
    entry.decision.install_table_domain = domain;
    entry.decision.install_table_check = check;
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        entry.decision.clone(),
        entry.metadata.clone(),
        crate::session::SessionOrigin::WorkerLocalImport,
        1_000_000,
        PROTO_TCP,
        0x18,
    ));
    let shared_sessions = Arc::new(std::sync::Mutex::new(crate::afxdp::FastMap::default()));
    let shared_forward_wire_sessions =
        Arc::new(std::sync::Mutex::new(crate::afxdp::FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let dyn_neigh = Arc::new(crate::afxdp::sharded_neighbor::ShardedNeighborMap::new());
    let mut ha = BTreeMap::new();
    ha.insert(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: 1,
            lease: HAForwardingLease::Inactive,
        },
    );
    ha.insert(
        2,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: 1,
            lease: HAForwardingLease::Inactive,
        },
    );
    assert!(
        crate::afxdp::shared_ops::fabric_adoption_gate_for_wire(
            &forwarding,
            &ha,
            &std::collections::BTreeSet::from([2]),
            1,
            &sessions,
            &shared_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &key,
            1_000_000,
            &dyn_neigh,
        ),
        "#16217 N1: tenant-table (blue, RG2) owner must adopt even though MAIN egress is RG1"
    );
    assert!(
        !crate::afxdp::shared_ops::fabric_adoption_gate_for_wire(
            &forwarding,
            &ha,
            &std::collections::BTreeSet::from([1]),
            1,
            &sessions,
            &shared_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &key,
            1_000_000,
            &dyn_neigh,
        ),
        "#16217 N1: MAIN-only (RG1) ownership must NOT adopt a blue-table session"
    );
}

/// #16479 (b) flow-cache cell: a data-bearing segment on a
/// handshake-incomplete session must NOT be served from the flow cache
/// under strict-syn-check. The cache entry is seeded (as a SYN-ACK
/// would seed it), the backing session is installed from a bare SYN
/// (OPENING), and an ACK+data frame carrying payload must fall through
/// to the slow path (which drops it) instead of being Consumed.
/// Fail-on-revert: remove the strict fence in `stage_flow_cache_hit`
/// and the run below is Consumed with a staged TX frame.
#[test]
fn strict_pre_handshake_data_not_served_from_cache_16479() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_strict_syn_check();
    // Build an ACK frame carrying 4 payload bytes: extend the stock
    // frame's declared lengths so `tcp_payload_len` reports 4.
    let mut frame = tcp_v4_ack_frame();
    let payload = [0xde, 0xad, 0xbe, 0xef];
    // IPv4 total_len at frame[20..22] (l3 at 18, +2); frame len grows.
    let total = u16::from_be_bytes([frame[20], frame[21]]) + 4;
    frame[20..22].copy_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&payload);
    let mut meta = test_meta(&frame);
    // PSH+ACK data segment (cache-eligible flags), payload present.
    meta.tcp_flags = 0x18;
    meta.payload_offset = (frame.len() - 4) as u16;
    meta.pkt_len = frame.len() as u16;
    // Backing session from a bare SYN: OPENING, handshake incomplete.
    let seed = StageSeed {
        session: Some((1_000_000, PROTO_TCP, 0x02)),
        ..StageSeed::default()
    };
    let run = run_stage_seeded(&fixture, &frame, meta, cached_entry(), 0, seed);
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "#16479: pre-handshake data must fall through, not be cache-served"
    );
    assert!(
        run.tx_frame.is_none() && run.tx_pipeline.pending_tx_prepared.is_empty(),
        "#16479: pre-handshake data must not stage a TX frame from cache"
    );
    // Positive control 1: knob OFF — the same cache hit is served.
    let fixture_off = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let seed_off = StageSeed {
        session: Some((1_000_000, PROTO_TCP, 0x02)),
        ..StageSeed::default()
    };
    let run_off = run_stage_seeded(&fixture_off, &frame, meta, cached_entry(), 0, seed_off);
    assert!(
        matches!(run_off.outcome, FlowCacheOutcome::Consumed),
        "#16479 control: without strict the cached data hit is still served"
    );
    // Positive control 2: strict ON but the session was installed from
    // an established (ACK) first packet — not handshake-incomplete —
    // so the cached data hit is served.
    let seed_est = StageSeed {
        session: Some((1_000_000, PROTO_TCP, 0x10)),
        ..StageSeed::default()
    };
    let run_est = run_stage_seeded(&fixture, &frame, meta, cached_entry(), 0, seed_est);
    assert!(
        matches!(run_est.outcome, FlowCacheOutcome::Consumed),
        "#16479 control: established session data must still be cache-served under strict"
    );
}

/// #18534 fixture: a clustered node serving a cached ForwardCandidate whose
/// destination (`test_key` dst 172.16.50.200) sits in a connected /24 owned by
/// RG1 (`DEST_OWNER_IFINDEX_18534`). The logical egress row and the seed stamp
/// name RG2, which stays active, so only the destination-owner arm can see RG1
/// depart. `publish_epoch` is the forwarding snapshot identity the entry's
/// destination-owner memo keys on (0 = unpublished fixture, never memoised).
const DEST_OWNER_IFINDEX_18534: i32 = 21;

fn dest_owner_fixture_18534(owner_active: bool, publish_epoch: u64) -> LiveCallSiteFixture {
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom).with_zone_accounting();
    fixture.forwarding.publish_epoch = publish_epoch;
    fixture
        .forwarding
        .egress
        .get_mut(&EGRESS_IFINDEX)
        .expect("zone-accounting fixture seeds the egress")
        .redundancy_group = 2;
    fixture.forwarding.connected_v4.push(crate::afxdp::ConnectedRouteV4 {
        prefix: crate::prefix::PrefixV4::from_net("172.16.50.0/24".parse().expect("prefix")),
        host: Ipv4Addr::new(172, 16, 50, 0),
        ifindex: DEST_OWNER_IFINDEX_18534,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    fixture.forwarding.egress.insert(
        DEST_OWNER_IFINDEX_18534,
        EgressInterface {
            bind_ifindex: DEST_OWNER_IFINDEX_18534,
            vlan_id: INGRESS_VLAN_ID,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x02],
            zone_id: TEST_TRUST_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: None,
        },
    );
    let active = HAGroupRuntime {
        active: true,
        watchdog_timestamp: 1,
        lease: HAGroupRuntime::active_lease_until(1, 1),
    };
    fixture.ha_state.insert(2, active);
    fixture.ha_state.insert(
        1,
        if owner_active {
            active
        } else {
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: 1,
                lease: HAForwardingLease::Inactive,
            }
        },
    );
    fixture
}

fn dest_owner_entry_18534() -> FlowCacheEntry {
    let mut entry = cached_entry();
    entry.metadata.owner_rg_id = 2;
    entry.stamp.owner_rg_id = 2;
    entry.stamp.owner_rg_lease_until = 0;
    entry
}

fn connected_owner_resolves_18534() -> u64 {
    crate::afxdp::session_glue::CONNECTED_OWNER_RESOLVES_FOR_TEST.with(|count| count.get())
}

/// #18534: the memo is a pure-function cache of the direct resolution, and
/// an unpublished snapshot (epoch 0) is never memoised.
#[test]
fn destination_owner_rg_is_never_memoised_unpublished_18534() {
    let target = test_key().dst_ip;
    let unpublished = dest_owner_fixture_18534(true, 0);
    let entry = dest_owner_entry_18534();
    let direct = crate::afxdp::session_glue::connected_owner_rg_for_target_in_table(
        &unpublished.forwarding,
        target,
        None,
    );
    assert_eq!(direct, 1, "premise: the destination's connected owner is RG1");
    let before = connected_owner_resolves_18534();
    assert_eq!(entry.destination_owner_rg(&unpublished.forwarding, target, None), 1);
    assert_eq!(entry.destination_owner_rg(&unpublished.forwarding, target, None), 1);
    assert_eq!(connected_owner_resolves_18534() - before, 2, "epoch 0 is never memoised");
}

/// #18534: a published snapshot resolves once per (epoch, target).
#[test]
fn destination_owner_rg_resolves_once_per_snapshot_and_target_18534() {
    let target = test_key().dst_ip;
    let other_target = IpAddr::V4(Ipv4Addr::new(172, 16, 50, 7));
    let published = dest_owner_fixture_18534(true, 7);
    let entry = dest_owner_entry_18534();
    let before = connected_owner_resolves_18534();
    assert_eq!(entry.destination_owner_rg(&published.forwarding, target, None), 1);
    assert_eq!(entry.destination_owner_rg(&published.forwarding, target, None), 1);
    assert_eq!(connected_owner_resolves_18534() - before, 1, "one resolution per published snapshot");
    assert_eq!(entry.destination_owner_rg(&published.forwarding, other_target, None), 1);
    assert_eq!(connected_owner_resolves_18534() - before, 2, "a different target resolves again");
}

/// #18534: a new published snapshot (a worker rotation) resolves again.
#[test]
fn destination_owner_rg_resolves_again_on_a_new_snapshot_18534() {
    let target = test_key().dst_ip;
    let entry = dest_owner_entry_18534();
    assert_eq!(entry.destination_owner_rg(&dest_owner_fixture_18534(true, 7).forwarding, target, None), 1);
    let rotated = dest_owner_fixture_18534(true, 8);
    let before = connected_owner_resolves_18534();
    assert_eq!(entry.destination_owner_rg(&rotated.forwarding, target, None), 1);
    assert_eq!(connected_owner_resolves_18534() - before, 1, "a new snapshot resolves again");
}

/// #18534: the live hit stage reads a current memo: no resolution.
#[test]
fn cached_hit_reads_a_current_destination_owner_memo_18534() {
    let frame = tcp_v4_ack_frame();
    let meta = test_meta(&frame);
    let target = test_key().dst_ip;
    let fixture = dest_owner_fixture_18534(true, 7);
    let entry = dest_owner_entry_18534();
    assert_eq!(entry.destination_owner_rg(&fixture.forwarding, target, None), 1, "seed the memo");
    let before = connected_owner_resolves_18534();
    let run = run_stage_with_entry(&fixture, &frame, meta, entry, 0);
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "premise: an active destination owner is served from the cache"
    );
    assert_eq!(connected_owner_resolves_18534() - before, 0, "a current memo is not re-resolved");
}

/// #18534: a memo from an older snapshot is resolved once by the hit.
#[test]
fn cached_hit_resolves_a_stale_destination_owner_memo_once_18534() {
    let frame = tcp_v4_ack_frame();
    let meta = test_meta(&frame);
    let target = test_key().dst_ip;
    let entry = dest_owner_entry_18534();
    assert_eq!(entry.destination_owner_rg(&dest_owner_fixture_18534(true, 7).forwarding, target, None), 1);
    let rotated = dest_owner_fixture_18534(true, 8);
    let before = connected_owner_resolves_18534();
    let run = run_stage_with_entry(&rotated, &frame, meta, entry, 0);
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed));
    assert_eq!(connected_owner_resolves_18534() - before, 1, "a stale memo resolves once");
}

/// #18534 transition: the memo holds WHICH RG owns the destination, never
/// whether it is active. RG1 departing in the HA state with no forwarding
/// publish (the failover shape) still falls the next hit through on the
/// destination-owner arm, with no re-resolution.
#[test]
fn memoised_destination_owner_still_sees_its_departure_18534() {
    let frame = tcp_v4_ack_frame();
    let meta = test_meta(&frame);
    let target = test_key().dst_ip;
    let fixture = dest_owner_fixture_18534(false, 7);
    let entry = dest_owner_entry_18534();
    assert_eq!(entry.destination_owner_rg(&fixture.forwarding, target, None), 1, "seed the memo");
    let before = connected_owner_resolves_18534();
    let run = run_stage_with_entry(&fixture, &frame, meta, entry, 0);
    assert!(
        matches!(run.outcome, FlowCacheOutcome::FallThrough),
        "a departed destination owner must re-resolve on the slow path"
    );
    assert_eq!(
        run.flow_cache_evictions_by_arm
            [crate::afxdp::flow_cache::FlowCacheEvictionArm::PostHitForwardCandidateEgressDeparted
                as usize],
        1,
        "the destination-owner arm owns the eviction"
    );
    assert_eq!(connected_owner_resolves_18534() - before, 0, "judged from the memo");
}

/// #18533 round 2: an ordinary cached flow (no cached drop, no policer)
/// cannot be dropped after the probe, so the probe builds no rollback undo.
#[test]
fn undroppable_cached_hit_records_no_rollback_undo_18533() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let run = run_stage(&fixture, &frame, 0);
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed), "premise: served");
    assert_eq!(run.sessions.probe_undo_records_for_test(), 0, "nothing can drop it: no undo");
    let charged = run.sessions.session_counters(&test_key()).expect("counters");
    assert_eq!(charged.fwd_packets, 1, "premise: the served packet is charged");
}

/// #18533 round 2: a cached `then discard` can drop the packet after the
/// probe, so the undo is built and the dropped packet is un-charged on the
/// session exactly as before.
#[test]
fn droppable_cached_hit_rolls_back_its_charge_18533() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let mut entry = cached_entry();
    entry.descriptor.tx_selection.drop = true;
    let run = run_stage_with_entry(&fixture, &frame, test_meta(&frame), entry, 0);
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed), "premise: dropped in place");
    assert_eq!(run.sessions.probe_undo_records_for_test(), 1, "a cached drop builds the undo");
    let after = run.sessions.session_counters(&test_key()).expect("counters");
    assert_eq!(
        (after.fwd_packets, after.fwd_bytes),
        (0, 0),
        "the dropped packet must not charge the session"
    );
}

/// #18534 fold: the policer half of `rollback_possible`. A cached flow with
/// no `then discard` but a three-color policer whose red treatment drops
/// can still be dropped after the probe, so the probe builds the undo and
/// the red packet is un-charged on the session. A 1-byte committed/excess
/// burst colours the first frame red.
#[test]
fn red_policer_drop_rolls_back_the_probe_charge_18534() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let mut entry = cached_entry();
    let state = crate::filter::ThreeColorPolicerState::sr_tcm_with_treatments(
        1,
        1,
        1,
        true,
        crate::filter::ThreeColorTreatments {
            red: crate::filter::ColorTreatment::drop(),
            ..Default::default()
        },
    )
    .expect("valid srTCM policer");
    entry.descriptor.tx_selection.three_color_policers.push(Arc::new(
        crate::filter::ThreeColorPolicerRuntime::new(90_018, "red-18534".into(), state),
    ));
    assert!(!entry.descriptor.tx_selection.drop, "premise: no cached discard");
    let run = run_stage_with_entry(&fixture, &frame, test_meta(&frame), entry, 0);
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed), "premise: dropped in place");
    assert_eq!(run.sessions.probe_undo_records_for_test(), 1, "a policer builds the undo");
    let after = run.sessions.session_counters(&test_key()).expect("counters");
    assert_eq!(
        (after.fwd_packets, after.fwd_bytes),
        (0, 0),
        "the policed packet must not charge the session"
    );
}

/// #18533 round 2: both transit address-class gates resolve their routing
/// domain once per hit. With routing instances configured (the gate behind
/// `ingress_routing_domain`'s map probes is open) a domain-0 flow paid two
/// resolutions per packet, one per gate.
#[test]
fn cached_hit_resolves_the_transit_routing_domain_once_18533() {
    let mut fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    fixture.forwarding.has_routing_domains = true;
    let frame = tcp_v4_ack_frame();
    let resolves =
        || crate::afxdp::forwarding::INGRESS_ROUTING_DOMAIN_RESOLVES_FOR_TEST.with(|c| c.get());
    let before = resolves();
    let run = run_stage(&fixture, &frame, 0);
    assert!(matches!(run.outcome, FlowCacheOutcome::Consumed), "premise: served");
    assert_eq!(resolves() - before, 1, "one routing-domain resolution for both gates");
}
