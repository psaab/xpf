//! Shared test fixtures for the TX module and its CoS-shaping
//! siblings. Visibility is `pub(in crate::afxdp)` so any
//! `#[cfg(test)] mod tests` under `crate::afxdp::*` can reach them
//! via `use crate::afxdp::tx::test_support::*;`.

#![cfg(test)]

use super::*;
use crate::afxdp::cos::builders::build_cos_interface_runtime;

pub(in crate::afxdp) fn test_queue_fast_path(
    shared_exact: bool,
    owner_worker_id: u32,
    owner_live: Option<Arc<BindingLiveState>>,
    shared_queue_lease: Option<Arc<SharedCoSQueueLease>>,
) -> WorkerCoSQueueFastPath {
    WorkerCoSQueueFastPath {
        shared_exact,
        owner_worker_id,
        owner_live,
        shared_queue_lease,
        vtime_floor: None,
    }
}

pub(in crate::afxdp) fn test_cos_fast_interfaces(
    egress_ifindex: i32,
    tx_ifindex: i32,
    default_queue: u8,
    queue_entries: Vec<(u8, WorkerCoSQueueFastPath)>,
    tx_owner_live: Option<Arc<BindingLiveState>>,
    shared_root_lease: Option<Arc<SharedCoSRootLease>>,
) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
    let mut queue_index_by_id = [COS_FAST_QUEUE_INDEX_MISS; 256];
    let mut queue_fast_path = Vec::with_capacity(queue_entries.len());
    for (idx, (queue_id, queue)) in queue_entries.into_iter().enumerate() {
        queue_index_by_id[usize::from(queue_id)] = idx as u16;
        queue_fast_path.push(queue);
    }
    let default_queue_index = match queue_index_by_id[usize::from(default_queue)] {
        COS_FAST_QUEUE_INDEX_MISS => panic!("missing default queue {default_queue}"),
        idx => idx as usize,
    };
    let mut interfaces = FastMap::default();
    interfaces.insert(
        egress_ifindex,
        WorkerCoSInterfaceFastPath {
            tx_ifindex,
            default_queue_index,
            queue_index_by_id,
            tx_owner_live,
            shared_root_lease,
            queue_fast_path,
        },
    );
    interfaces
}

pub(in crate::afxdp) fn test_cos_interface_runtime(now_ns: u64) -> CoSInterfaceRuntime {
    build_cos_interface_runtime(
        &CoSInterfaceConfig {
            shaping_rate_bytes: 1_000_000,
            burst_bytes: COS_MIN_BURST_BYTES,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "best-effort".into(),
                priority: 5,
                transmit_rate_bytes: 1_000_000,
                exact: false,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            }],
        },
        now_ns,
    )
}

pub(in crate::afxdp) fn test_cos_runtime_with_exact(exact: bool) -> CoSInterfaceRuntime {
    test_cos_runtime_with_queues(
        1_000_000,
        vec![CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "best-effort".into(),
            priority: 5,
            transmit_rate_bytes: 500_000,
            exact,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
        }],
    )
}

pub(in crate::afxdp) fn test_cos_runtime_with_queues(
    shaping_rate_bytes: u64,
    queues: Vec<CoSQueueConfig>,
) -> CoSInterfaceRuntime {
    build_cos_interface_runtime(
        &CoSInterfaceConfig {
            shaping_rate_bytes,
            burst_bytes: COS_MIN_BURST_BYTES,
            default_queue: 0,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues,
        },
        0,
    )
}

pub(in crate::afxdp) fn test_cos_item(len: usize) -> CoSPendingTxItem {
    CoSPendingTxItem::Local(TxRequest {
        bytes: vec![0; len],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 42,
        cos_queue_id: Some(0),
        dscp_rewrite: None,
    })
}

pub(in crate::afxdp) fn test_flow_cos_item(src_port: u16, len: usize) -> CoSPendingTxItem {
    CoSPendingTxItem::Local(TxRequest {
        bytes: vec![0; len],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: Some(test_session_key(src_port, 5201)),
        egress_ifindex: 42,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
    })
}

pub(in crate::afxdp) fn test_flow_prepared_cos_item(src_port: u16, len: u32, offset: u64) -> CoSPendingTxItem {
    CoSPendingTxItem::Prepared(PreparedTxRequest {
        offset,
        len,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: Some(test_session_key(src_port, 5201)),
        egress_ifindex: 42,
        cos_queue_id: Some(4),
        dscp_rewrite: None,
    })
}

pub(in crate::afxdp) fn test_session_key(src_port: u16, dst_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, (src_port & 0xff) as u8)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port,
        dst_port,
    }
}

pub(in crate::afxdp) fn test_mixed_class_root_with_primed_queues() -> CoSInterfaceRuntime {
    // Four queues on the same iface: two exact (queue_id 0, 2),
    // two non-exact (queue_id 1, 3). Per-queue rate is set low
    // enough that `cos_guarantee_quantum_bytes` clamps to the
    // minimum (1500 bytes). That means the non-exact batch-build
    // path (`select_nonexact_cos_guarantee_batch`) dequeues exactly
    // one 1500-byte item per call, while the exact fast-path
    // selector (`select_exact_cos_guarantee_queue_with_fast_path`)
    // only picks a queue and advances its cursor — it does not
    // dequeue. Eight primed items per queue keeps backlog available
    // across every rotation round below without any test having to
    // push additional items.
    //
    // Shared by the #689 split-cursor regression tests.
    let slow_rate = 1_000_000 / 8; // 1 Mbps → quantum clamps to MIN
    let mut root = test_cos_runtime_with_queues(
        10_000_000_000 / 8,
        vec![
            CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "exact-0".into(),
                priority: 5,
                transmit_rate_bytes: slow_rate,
                exact: true,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            },
            CoSQueueConfig {
                queue_id: 1,
                forwarding_class: "nonexact-1".into(),
                priority: 5,
                transmit_rate_bytes: slow_rate,
                exact: false,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            },
            CoSQueueConfig {
                queue_id: 2,
                forwarding_class: "exact-2".into(),
                priority: 5,
                transmit_rate_bytes: slow_rate,
                exact: true,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            },
            CoSQueueConfig {
                queue_id: 3,
                forwarding_class: "nonexact-3".into(),
                priority: 5,
                transmit_rate_bytes: slow_rate,
                exact: false,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: COS_MIN_BURST_BYTES,
                dscp_rewrite: None,
            },
        ],
    );
    root.tokens = 1024 * 1024;
    for queue in &mut root.queues {
        queue.tokens = 64 * 1024;
        queue.runnable = true;
        // Eight items per queue covers the longest rotation test below
        // without any queue draining to empty.
        for _ in 0..8 {
            queue.items.push_back(test_cos_item(1500));
        }
        queue.queued_bytes = 8 * 1500;
    }
    root.nonempty_queues = 4;
    root.runnable_queues = 4;
    root
}

pub(in crate::afxdp) fn snapshot_counters(queue: &CoSQueueRuntime) -> CoSQueueDropCounters {
    queue.drop_counters
}

/// Build a minimal IPv4 packet (Ethernet + IPv4 header, no
/// payload) with the given `tos` byte and a valid IP checksum.
/// 34-byte total so `l3_offset = 14` lands on the IPv4 version/IHL
/// byte. Returns the buffer for mutation.
pub(in crate::afxdp) fn build_ipv4_test_packet(tos: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 34];
    // Ethernet header: dst + src MAC (12 bytes of zeros is fine
    // for a checksum-only test), ethertype = IPv4 (0x0800).
    pkt[12] = 0x08;
    pkt[13] = 0x00;
    // IPv4 header, l3_offset = 14:
    //   byte 0: version (4) + IHL (5) = 0x45
    //   byte 1: TOS
    //   bytes 2..3: total length (20)
    //   bytes 4..5: id
    //   bytes 6..7: flags + frag offset
    //   byte 8: TTL (64)
    //   byte 9: protocol (TCP=6)
    //   bytes 10..11: header checksum (placeholder)
    //   bytes 12..15: src IP 10.0.0.1
    //   bytes 16..19: dst IP 10.0.0.2
    pkt[14] = 0x45;
    pkt[15] = tos;
    pkt[16] = 0;
    pkt[17] = 20;
    pkt[22] = 64;
    pkt[23] = 6;
    pkt[26] = 10;
    pkt[27] = 0;
    pkt[28] = 0;
    pkt[29] = 1;
    pkt[30] = 10;
    pkt[31] = 0;
    pkt[32] = 0;
    pkt[33] = 2;
    let csum = compute_ipv4_header_checksum(&pkt[14..34]);
    pkt[24] = (csum >> 8) as u8;
    pkt[25] = (csum & 0xff) as u8;
    pkt
}

/// Compute the IPv4 header checksum over the given header bytes.
/// Used by tests to independently verify that the incremental
/// update in `mark_ecn_ce_ipv4` produced the same value a
/// from-scratch computation would.
pub(in crate::afxdp) fn compute_ipv4_header_checksum(header: &[u8]) -> u16 {
    assert_eq!(header.len(), 20, "test fixture must be a 20-byte header");
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        if i == 10 {
            // Skip the checksum field itself.
            continue;
        }
        sum += ((header[i] as u32) << 8) | header[i + 1] as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    (!sum & 0xffff) as u16
}

pub(in crate::afxdp) fn ipv4_tos(pkt: &[u8]) -> u8 {
    pkt[15]
}

pub(in crate::afxdp) fn ipv4_checksum(pkt: &[u8]) -> u16 {
    ((pkt[24] as u16) << 8) | pkt[25] as u16
}

/// Build a minimal IPv6 packet (Ethernet + IPv6 header, no
/// payload) with the given full tclass byte. Returns the buffer
/// for mutation.
pub(in crate::afxdp) fn build_ipv6_test_packet(tclass: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 54];
    pkt[12] = 0x86;
    pkt[13] = 0xdd;
    // IPv6 header, l3_offset = 14:
    //   version/tclass high nibble in byte 0 (version=6 -> 0x60
    //   in the high nibble; tclass high nibble in the low nibble)
    //   tclass low nibble + flow label high nibble in byte 1
    pkt[14] = 0x60 | ((tclass >> 4) & 0x0f);
    pkt[15] = ((tclass & 0x0f) << 4) | 0x00;
    // Payload length = 0, next header = TCP, hop limit = 64.
    pkt[20] = 6;
    pkt[21] = 64;
    pkt
}

pub(in crate::afxdp) fn ipv6_tclass(pkt: &[u8]) -> u8 {
    ((pkt[14] & 0x0f) << 4) | ((pkt[15] >> 4) & 0x0f)
}

/// Helper: build a `CoSPendingTxItem::Local` with an IPv4 test
/// packet carrying the given TOS byte. Default flow key routes it
/// into queue 0 of `test_cos_runtime_with_exact`.
pub(in crate::afxdp) fn test_local_ipv4_item(tos: u8) -> CoSPendingTxItem {
    CoSPendingTxItem::Local(TxRequest {
        bytes: build_ipv4_test_packet(tos),
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 42,
        cos_queue_id: Some(0),
        dscp_rewrite: None,
    })
}

/// Small dummy UMEM area for admission tests that exercise the
/// Local variant. The mark helpers never consult `umem` on the
/// Local path (they mutate `req.bytes` directly), so any valid
/// `MmapArea` satisfies the signature. A 4 KB mapping is cheap
/// and enough to round up to hugepage alignment internally.
pub(in crate::afxdp) fn test_admission_umem() -> MmapArea {
    MmapArea::new(4096).expect("mmap")
}

/// Build a flow-fair exact queue shaped to match the live
/// 16-flow / 1 Gbps / 128 KB-buffer workload that motivated #722.
/// Picking these exact numbers means the derived thresholds
/// (buffer_limit, share_cap, aggregate_ecn_threshold,
/// flow_ecn_threshold) match what the scheduler sees in
/// production, so the fixture is not just internally consistent —
/// it is the failure mode.
pub(in crate::afxdp) fn test_flow_fair_exact_queue_16_flows() -> CoSInterfaceRuntime {
    let mut root = test_cos_runtime_with_queues(
        25_000_000_000 / 8,
        vec![CoSQueueConfig {
            queue_id: 4,
            forwarding_class: "iperf-a".into(),
            priority: 5,
            transmit_rate_bytes: 1_000_000_000 / 8,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 128 * 1024,
            dscp_rewrite: None,
        }],
    );
    let queue = &mut root.queues[0];
    queue.flow_fair = true;
    queue.flow_hash_seed = 0;
    root
}

/// Populate 16 flow buckets on a flow-fair queue so
/// `active_flow_buckets == 16`. Target bucket `target` is set to
/// `target_bytes`; every other populated bucket gets 1 byte (just
/// enough to count as active). Returns the resulting
/// `queued_bytes` sum so the caller can reconcile the aggregate
/// with the per-bucket picture.
pub(in crate::afxdp) fn seed_sixteen_flow_buckets(
    queue: &mut CoSQueueRuntime,
    target: usize,
    target_bytes: u64,
) -> u64 {
    queue.active_flow_buckets = 16;
    let mut populated = 0usize;
    let mut bucket = 0usize;
    let mut sum = 0u64;
    while populated < 16 && bucket < queue.flow_bucket_bytes.len() {
        if bucket == target {
            queue.flow_bucket_bytes[bucket] = target_bytes;
            sum = sum.saturating_add(target_bytes);
            populated += 1;
        } else {
            queue.flow_bucket_bytes[bucket] = 1;
            sum = sum.saturating_add(1);
            populated += 1;
        }
        bucket += 1;
    }
    sum
}

/// Build a `WorkerCoSQueueFastPath` shaped like
/// `build_worker_cos_fast_interfaces` would build it for a queue
/// with the given `shared_exact` bit. Only the fields the
/// promotion path consults are populated — the rest stay at the
/// stable defaults the live builder uses when no lease or owner
/// live state is present.
pub(in crate::afxdp) fn test_queue_fast_path_for_promotion(shared_exact: bool) -> WorkerCoSQueueFastPath {
    WorkerCoSQueueFastPath {
        shared_exact,
        owner_worker_id: 0,
        owner_live: None,
        shared_queue_lease: None,
        vtime_floor: None,
    }
}

/// Build a Prepared CoS item whose frame lives in `umem` at the
/// given offset. Copies `packet_bytes` into the UMEM in place,
/// then returns the `CoSPendingTxItem::Prepared` referencing
/// those bytes. The caller is responsible for keeping `umem`
/// alive for the duration of the item's lifetime (each test
/// keeps both on the stack).
pub(in crate::afxdp) fn test_prepared_item_in_umem(
    umem: &mut MmapArea,
    offset: u64,
    packet_bytes: &[u8],
    expected_addr_family: u8,
) -> CoSPendingTxItem {
    let dest = umem
        .slice_mut(offset as usize, packet_bytes.len())
        .expect("umem slice");
    dest.copy_from_slice(packet_bytes);
    CoSPendingTxItem::Prepared(PreparedTxRequest {
        offset,
        len: packet_bytes.len() as u32,
        recycle: PreparedTxRecycle::FreeTxFrame,
        expected_ports: None,
        expected_addr_family,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: 42,
        cos_queue_id: Some(0),
        dscp_rewrite: None,
    })
}

/// Insert a single 802.1Q VLAN tag into an Ethernet-wrapped packet
/// between the MAC addresses and the ethertype. Used by the
/// VLAN-aware regression tests for both Local and Prepared paths.
pub(in crate::afxdp) fn insert_single_vlan_tag(packet: Vec<u8>, vid: u16, priority: u8) -> Vec<u8> {
    use crate::afxdp::ethernet::{ETH_HDR_LEN, VLAN_TAG_LEN};
    assert!(packet.len() >= ETH_HDR_LEN, "packet must be eth-framed");
    let mut tagged = Vec::with_capacity(packet.len() + VLAN_TAG_LEN);
    tagged.extend_from_slice(&packet[..12]); // dst + src MAC
    tagged.extend_from_slice(&[0x81, 0x00]); // TPID
    let tci: u16 = ((priority as u16) << 13) | (vid & 0x0FFF);
    tagged.extend_from_slice(&tci.to_be_bytes());
    tagged.extend_from_slice(&packet[12..]); // original ethertype + payload
    tagged
}

/// Test scaffolding: attach a real `SharedCoSQueueVtimeFloor` to a
/// queue runtime and return the `Arc` so tests can read peer slots
/// back to assert on published values. Existing fixtures default to
/// `vtime_floor: None` and exercise the no-op publish path; this
/// helper opts in for tests that need V_min participation.
pub(in crate::afxdp) fn attach_test_vtime_floor(
    queue: &mut CoSQueueRuntime,
    num_workers: u32,
    my_worker_id: u32,
) -> Arc<SharedCoSQueueVtimeFloor> {
    let floor = Arc::new(SharedCoSQueueVtimeFloor::new(num_workers as usize));
    queue.vtime_floor = Some(Arc::clone(&floor));
    queue.worker_id = my_worker_id;
    // V_min sync only kicks in on shared_exact; mark accordingly so
    // `cos_queue_v_min_continue` doesn't early-return.
    queue.shared_exact = true;
    queue.flow_fair = true;
    floor
}
