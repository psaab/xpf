//! #7176 (C179-001): the DEFERRED neighbor-retry flush owes the same
//! output-filter side effects the immediate forward path emits.
//!
//! A packet whose next hop is unresolved is buffered in `pending_neigh` and its
//! egress output filter is evaluated exactly once — here, at flush time, and
//! nowhere else (the admission path in `poll_descriptor` performs no
//! `resolve_cos_tx_selection_*` call for a `MissingNeighbor` disposition). The
//! flush read only `CoSTxSelection::drop`, so a `then reject` term degraded to
//! a silent `then discard` and a `then log` term emitted nothing.
//!
//! These tests drive `retry_pending_neigh` itself rather than the extracted
//! `apply_cos_drop_side_effects` helper. That is deliberate: the defect was
//! never in the helper's body, it was that the deferred path did not CALL it.
//! A test that invoked the helper directly would stay green if the call site
//! were deleted again, which is the exact regression these guard.

use super::*;
use crate::afxdp::event_emit::RT_FLOW_ACTION_REJECT;
use crate::afxdp::test_fixtures::*;
use crate::{FirewallFilterSnapshot, FirewallTermSnapshot};
use crate::event_stream::codec::DataplaneEventKind;
use crate::session::SessionKey;
use crate::session::TunnelDiscriminator;

const EGRESS_IFINDEX: i32 = 80;
const NEXT_HOP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 9));

/// The buffered packet's decision: unresolved next hop, egress 80.
fn deferred_decision() -> SessionDecision {
    SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::MissingNeighbor,
        local_ifindex: 0,
        egress_ifindex: EGRESS_IFINDEX,
        tx_ifindex: 22,
        tunnel_endpoint_id: 0,
        next_hop: Some(NEXT_HOP),
        neighbor_mac: None,
        src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 }
}

/// A ForwardingState whose EGRESS interface (ifindex 80) carries an output
/// filter with one term matching the fixture packet. `action` selects
/// `then reject` vs `then discard`; `log` selects whether `then log` is set.
fn forwarding_with_output_filter(action: &str, log: bool) -> ForwardingState {
    let mut forwarding = build_forwarding_state(&ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: EGRESS_IFINDEX,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-out".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-out".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "t1".into(),
                protocols: vec!["tcp".into()],
                action: action.into(),
                log,
                ..Default::default()
            }],
        }],
        ..Default::default()
    });
    // Resolve the neighbor so the flush proceeds to the output-filter
    // evaluation instead of re-queueing or timing the packet out.
    forwarding.neighbors.insert(
        (EGRESS_IFINDEX, NEXT_HOP),
        NeighborEntry {
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        },
    );
    forwarding
}

/// Buffer one TCP packet pending neighbor resolution, flush it, and return
/// what the flush produced.
fn flush_one(
    forwarding: &ForwardingState,
    with_flow_key: bool,
) -> (
    usize,                                   // reject replies enqueued
    u64,                                     // counters.filter_reject_sent
    std::sync::mpsc::Receiver<crate::event_stream::EventFrame>,
) {
    let mut bindings = vec![BindingWorker::new_for_mirror_test(0, 0, 11, 0)];
    // A minimal but VALID Ethernet/IPv4/TCP SYN. The RST builder reflects real
    // bytes, so a header-less stub frame makes `enqueue_filter_reject_reply`
    // fail closed and the test would report "no reply" for a fixture reason
    // rather than a production one. L2 addresses must be unicast (a group/
    // broadcast source is suppressed by `build_reject_rst_frame`).
    let src_ip = Ipv4Addr::new(10, 0, 0, 1);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
    let (src_port, dst_port) = (12345u16, 443u16);
    let mut frame = Vec::new();
    frame.extend_from_slice(&[
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, // dst MAC (unicast)
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src MAC
        0x08, 0x00, // ethertype IPv4
    ]);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02, 0xfa, 0xf0, // data offset / SYN / window
        0x00, 0x00, 0x00, 0x00, // checksum + urgent
    ]);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 11,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    // The buffered pre-NAT key must describe the SAME flow as the frame: the
    // reply is reflected along it, and the filter-log event is attributed to it.
    let flow_key = if with_flow_key {
        Some(SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(src_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port,
            dst_port,
            discriminator: TunnelDiscriminator::default(),
            routing_domain: 0,
        })
    } else {
        None
    };
    let pkt = PendingNeighPacket {
        addr: 0,
        desc: XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        decision: deferred_decision(),
        flow_key,
        queued_ns: 0,
        probe_attempts: 0,
    };
    // The flush reads the packet from UMEM (`area.slice(desc.addr, desc.len)`),
    // NOT from `frame`. Without this copy the flush parses a zero-filled frame,
    // the reply builder fails closed, and the test reports "no reject reply"
    // for a FIXTURE reason that looks exactly like the production defect.
    {
        // SAFETY: single-threaded test; nothing else holds a borrow of this
        // area at this point, and the bytes are written before any read.
        let area_mut = bindings[0].umem.area() as *const MmapArea as *mut MmapArea;
        unsafe {
            (*area_mut)
                .slice_mut(0, frame.len())
                .expect("umem slice for test frame")
                .copy_from_slice(&frame);
        }
    }
    bindings[0]
        .pending_neigh
        .insert((EGRESS_IFINDEX, NEXT_HOP), pkt);

    let (handle, rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let mut counters = BatchCounters::default();
    let lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut shared_recycles = Vec::new();
    let area = bindings[0].umem.area() as *const MmapArea;
    let (left, rest) = bindings.split_at_mut(0);
    let (binding, right) = rest.split_first_mut().expect("ingress binding");

    retry_pending_neigh(
        binding,
        left,
        0,
        right,
        &lookup,
        &mirror_targets,
        forwarding,
        &dynamic_neighbors,
        None,
        1,
        // SAFETY: `area` was cast from the `&MmapArea` borrowed out of
        // bindings[0].umem just above; the allocation outlives this call, the
        // split borrows cover disjoint binding state, and this is
        // single-threaded.
        unsafe { &*area },
        &mut shared_recycles,
        Some(&handle),
        &mut counters,
    );

    let replies = binding.tx_pipeline.pending_tx_local.len();
    (replies, counters.filter_reject_sent, rx)
}

/// An output-filter `then reject` matched at flush time must synthesize the
/// active reply, exactly as the immediate forward path does.
///
/// Firing input: a TCP packet buffered pending ARP whose egress output filter
/// terminates in `then reject`. Before the fix this enqueued NOTHING and the
/// frame was recycled silently.
#[test]
fn deferred_flush_reject_sends_reply_7176() {
    let forwarding = forwarding_with_output_filter("reject", false);
    let (replies, reject_sent, _rx) = flush_one(&forwarding, true);
    assert_eq!(
        replies, 1,
        "a deferred `then reject` must enqueue its active reply; \
         0 means the flush recycled the frame silently (C179-001)"
    );
    assert_eq!(
        reject_sent, 1,
        "the synthesized reply must be metered as a FILTER reject"
    );
}

/// The reject must be isolated to `then reject`: a `then discard` term drops
/// the packet with no reply. This is the paired negative — without it, a fix
/// that replied to every dropping verdict would also pass the test above.
#[test]
fn deferred_flush_discard_stays_silent_7176() {
    let forwarding = forwarding_with_output_filter("discard", false);
    let (replies, reject_sent, _rx) = flush_one(&forwarding, true);
    assert_eq!(
        replies, 0,
        "a deferred `then discard` must stay silent — only `then reject` replies"
    );
    assert_eq!(reject_sent, 0, "a discard must not be metered as a reject");
}

/// An output-filter `then log` matched at flush time must emit its event.
///
/// Firing input: a buffered TCP packet whose egress filter carries `log: true`.
/// Before the fix `cos.filter_log` was never read on this path, so the event
/// was lost entirely.
#[test]
fn deferred_flush_emits_filter_log_event_7176() {
    let forwarding = forwarding_with_output_filter("reject", true);
    let (_replies, _reject_sent, rx) = flush_one(&forwarding, true);
    let event = rx
        .try_recv()
        .expect(
            "a deferred flush whose output filter carries `then log` must emit \
             a filter-log event; nothing on the channel means the flush never \
             read cos.filter_log (C179-001)",
        )
        .decode_dataplane_event()
        .expect("filter event payload");
    assert_eq!(event.kind, DataplaneEventKind::FilterLog);
    assert_eq!(
        event.action, RT_FLOW_ACTION_REJECT,
        "the logged action must be the TRUTHFUL one (#3615): the reply was enqueued"
    );
}

/// A packet buffered WITHOUT a session key (a non-first fragment, #2357) has no
/// flow to reflect a reply from, so it keeps the silent drop — matching the
/// immediate path's flowless behaviour (#3615). Guards against a fix that
/// synthesizes a reply from a fabricated tuple.
#[test]
fn deferred_flush_flowless_reject_stays_silent_7176() {
    let forwarding = forwarding_with_output_filter("reject", false);
    let (replies, reject_sent, _rx) = flush_one(&forwarding, false);
    assert_eq!(
        replies, 0,
        "a flowless deferred packet must not synthesize a reject reply"
    );
    assert_eq!(reject_sent, 0, "no reply means no reject metered");
}

