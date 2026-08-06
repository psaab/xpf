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

use super::*;
use crate::afxdp::flow_cache::{FlowCacheEntry, FlowCacheStamp};
use crate::afxdp::umem::MmapArea;
use crate::ip_proto::PROTO_TCP;
use crate::test_zone_ids::*;
use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

const INGRESS_IFINDEX: i32 = 7;
const EGRESS_IFINDEX: i32 = 7;
const MIRROR_OUT_IFINDEX: i32 = 22;
const BINDING_INDEX: usize = 0;

fn test_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 50, 200)),
        src_port: 45678,
        dst_port: 443,
    }
}

/// A plain forwarded IPv4/TCP ACK with a healthy TTL (64), so the #3779
/// TTL-expiry arm above the mirror block does not divert it into a Time
/// Exceeded reply.
fn tcp_v4_ack_frame() -> Vec<u8> {
    let key = test_key();
    let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (key.src_ip, key.dst_ip) else {
        unreachable!("test key is v4")
    };
    let mut frame = Vec::new();
    // Ethernet
    frame.extend_from_slice(&[
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0xbf, 0x72, 0x00, 0x01, 0x01, 0x08, 0x00,
    ]);
    // IPv4: ihl=5, total len 40, TTL 64, proto TCP
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    // TCP: ports, seq, ack, offset 5 / ACK, window, csum, urg
    frame.extend_from_slice(&key.src_port.to_be_bytes());
    frame.extend_from_slice(&key.dst_port.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x50, 0x10, 0xfa, 0xf0]);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
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
        ingress_ifindex: INGRESS_IFINDEX as u32,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: (frame.len() - 14) as u16,
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
        ingress_ifindex: INGRESS_IFINDEX,
        logical_ingress_ifindex: INGRESS_IFINDEX,
        descriptor: RewriteDescriptor {
            dst_mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
            fabric_redirect: false,
            tx_vlan_id: 0,
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
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_TRUST_ZONE_ID,
            egress_zone: TEST_UNTRUST_ZONE_ID,
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

fn tx_pipeline() -> WorkerTxPipeline {
    WorkerTxPipeline {
        free_tx_frames: (0..8u64).collect(),
        pending_tx_prepared: VecDeque::new(),
        pending_tx_local: VecDeque::new(),
        max_pending_tx: 64,
        outstanding_tx: 0,
        pending_fill_frames: VecDeque::new(),
        in_flight_prepared_recycles: FastMap::default(),
        tx_submit_ns: Vec::new().into_boxed_slice(),
    }
}

fn tx_counters() -> WorkerTxCounters {
    WorkerTxCounters {
        pending_direct_tx_packets: 0,
        pending_copy_tx_packets: 0,
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
    }
}

/// #6304 FAIL-ON-REVERT (live call site): a NON-sampled packet on the
/// established-flow HOT path must NOT reserve the (full) cross-worker mirror
/// clone queue.
///
/// This drives `stage_flow_cache_hit` DIRECTLY — the live call site — rather
/// than the dead `enqueue_sampled_mirror_clone_to_live` wrapper the #6114 tests
/// use. The mutation it is built to catch is precisely the one those tests
/// miss: revert ONLY `flow_cache_hit.rs` to reserve-before-sample and leave
/// `sample_then_admit_mirror_clone` correct. Under that mutation this packet
/// calls `admit_mirror_clone_to_live` on a FULL target, takes the
/// `Err(QueueFullCrossWorker)` arm, and `record_mirror_clone_result` bumps
/// `mirror_drops_queue_full` — a non-sampled packet reporting clone-queue
/// pressure it must never touch.
///
/// The mirror drop is recorded ONLY inside the successful in-place-rewrite
/// branch, so the two positive controls below are load-bearing, not decoration:
/// without them a fixture whose rewrite silently failed would report 0 drops
/// under BOTH the correct and the reverted call site — a test that looks bound
/// and is not.
#[test]
fn live_flow_cache_callsite_nonsampled_does_not_reserve_full_queue_6304() {
    let mut area = MmapArea::new(2 * 1024 * 1024).expect("umem mmap");
    let frame = tcp_v4_ack_frame();
    let frame_offset: u64 = 4096;
    // Place the frame in the UMEM at a fixed offset; the descriptor addresses it.
    area.slice_mut(frame_offset as usize, frame.len())
        .expect("umem slice for the test frame")
        .copy_from_slice(&frame);
    let desc = XdpDesc {
        addr: frame_offset,
        len: frame.len() as u32,
        options: 0,
    };

    let ingress_live = Arc::new(BindingLiveState::new());

    // A DIFFERENT binding is the mirror target, and its clone queue is FULL.
    let target_live = Arc::new(BindingLiveState::new());
    target_live.set_max_pending_tx(1);
    assert!(
        target_live
            .try_enqueue_tx_owned(TxRequest {
                bytes: Vec::new(),
                expected_ports: None,
                expected_addr_family: 0,
                expected_protocol: 0,
                flow_key: None,
                egress_ifindex: MIRROR_OUT_IFINDEX,
                cos_queue_id: None,
                dscp_rewrite: None,
                mirror_clone: false,
                enqueue_ns: 0,
            })
            .is_ok(),
        "precondition: the mirror target's clone queue is driven to its cap"
    );
    let mut mirror_targets = MirrorTargetMap::default();
    mirror_targets.insert(
        &BindingIdentity {
            slot: 9,
            queue_id: 0,
            worker_id: 1,
            interface: Arc::<str>::from("mirror-out"),
            ifindex: MIRROR_OUT_IFINDEX,
        },
        target_live.clone(),
    );

    let mut forwarding = ForwardingState::default();
    forwarding.mirror_configs.insert(
        INGRESS_IFINDEX,
        MirrorRuntimeConfig {
            output_ifindex: MIRROR_OUT_IFINDEX,
            rate: 2,
        },
    );

    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: INGRESS_IFINDEX,
    };
    let binding_lookup = WorkerBindingLookup::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs: [AtomicU32; MAX_RG_EPOCHS] = std::array::from_fn(|_| AtomicU32::new(0));
    let worker_ctx = WorkerContext {
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: None,
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };

    let mut flow_state = WorkerFlowCacheState {
        flow_cache: FlowCache::new(),
    };
    flow_state.flow_cache.insert(cached_entry());

    let mut tx_pipeline_state = tx_pipeline();
    let mut tx_counters_state = tx_counters();
    let mut scratch_state = scratch();
    let mut sessions = SessionTable::new();
    let mut dbg = DebugPollCounters::default();
    let mut counters = BatchCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut counters,
    };

    let meta = test_meta(&frame);
    let flow = SessionFlow {
        src_ip: test_key().src_ip,
        dst_ip: test_key().dst_ip,
        forward_key: test_key(),
    };
    let mut owned_packet_frame: Option<Vec<u8>> = None;

    // rate = 2 with counter = 1 -> `mirror_sample_allows` is FALSE: this packet
    // is NOT selected, so sample-first must touch nothing shared.
    let mut mirror_sample_counter: u64 = 1;

    let outcome = stage_flow_cache_hit(
        &mut flow_state,
        &mut tx_pipeline_state,
        &mut tx_counters_state,
        &mut scratch_state,
        &mut mirror_sample_counter,
        &ingress_live,
        0,
        BINDING_INDEX,
        desc,
        &area as *const MmapArea,
        &frame,
        &mut owned_packet_frame,
        meta,
        &flow,
        false,
        ValidationState::default(),
        &mut sessions,
        1_000_000,
        1,
        &worker_ctx,
        &mut telemetry,
    );

    // --- POSITIVE CONTROLS: the fixture actually reached the recording point.
    // The mirror result is recorded only inside the successful in-place-rewrite
    // branch; if the rewrite had failed, the discriminating assertion below
    // would read 0 under BOTH the correct and the reverted call site.
    assert!(
        matches!(outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must be consumed by the fast path"
    );
    assert_eq!(
        tx_counters_state.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED — this is the \
         branch the mirror result is recorded in"
    );
    assert_eq!(
        tx_pipeline_state.pending_tx_prepared.len(),
        1,
        "control: the rewritten frame must be queued for TX"
    );

    // --- THE #6304 DISCRIMINATOR.
    assert_eq!(
        ingress_live.mirror_drops_queue_full.load(Ordering::Relaxed),
        0,
        "#6304: a NON-sampled packet on the LIVE flow-cache path must not reserve \
         the full clone queue; reverting only the flow_cache_hit.rs call site to \
         reserve-before-sample records a QueueFullCrossWorker drop here"
    );
    assert_eq!(
        ingress_live
            .mirror_drops_queue_full_cross_worker
            .load(Ordering::Relaxed),
        0,
        "#6304: and it must not report cross-worker clone-queue pressure"
    );
    // The worker-local sampler still advances for the declined packet (committed
    // because the rewrite succeeded).
    assert_eq!(
        mirror_sample_counter, 2,
        "the worker-local sampler advances for the declined packet"
    );
}
