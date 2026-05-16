use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

// #1035 P4: shared CoS lease + V_min coordination types split into a
// sibling submodule. Re-exported at pub(super) so the rest of afxdp/
// continues to find them as `super::types::SharedCoS*`.
mod shared_cos_lease;
pub(super) use shared_cos_lease::{
    NOT_PARTICIPATING, PaddedVtimeSlot, SharedCoSExactBacklog, SharedCoSQueueLease,
    SharedCoSQueueVtimeFloor, SharedCoSRootLease, V8RateMode,
};

// Issue 68.1: CoS shaper / queue / flow-fair / runtime types extracted
// into types/cos.rs. Re-exported here so call sites that reach
// `crate::afxdp::types::*` resolve unchanged.
mod cos;
pub(in crate::afxdp) use cos::*;

// Issue 68.2: routing/forwarding types extracted into types/forwarding.rs.
mod forwarding;
pub(in crate::afxdp) use forwarding::*;
// Three forwarding types had wider-than-pub(super) visibility in the original
// types/mod.rs and are re-exported at their original surface so afxdp.rs's
// `pub(crate) use self::types::{...};` and external pub callers continue to
// resolve them.
pub use forwarding::NeighborEntry;
pub(crate) use forwarding::{ForwardingDisposition, ForwardingResolution};

// Issue 68.3: TX-request types extracted into types/tx.rs.
mod tx;
pub(in crate::afxdp) use tx::*;

// Issue 68.4: worker / runtime types extracted into types/runtime.rs.
mod runtime;
pub(in crate::afxdp) use runtime::*;

pub(super) type FastMap<K, V> = FxHashMap<K, V>;
pub(super) type FastSet<T> = FxHashSet<T>;
pub(super) type OwnerRgSessionIndex = FastMap<i32, FastSet<SessionKey>>;

#[derive(Clone)]
pub(super) struct SharedSessionOwnerRgIndexes {
    pub(super) sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(super) nat_sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(super) forward_wire_sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(super) reverse_prewarm_sessions: Arc<Mutex<OwnerRgSessionIndex>>,
}

impl Default for SharedSessionOwnerRgIndexes {
    fn default() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(FastMap::default())),
            nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
            reverse_prewarm_sessions: Arc::new(Mutex::new(FastMap::default())),
        }
    }
}

impl SharedSessionOwnerRgIndexes {
    pub(super) fn clear(&self) {
        if let Ok(mut index) = self.sessions.lock() {
            index.clear();
        }
        if let Ok(mut index) = self.nat_sessions.lock() {
            index.clear();
        }
        if let Ok(mut index) = self.forward_wire_sessions.lock() {
            index.clear();
        }
        if let Ok(mut index) = self.reverse_prewarm_sessions.lock() {
            index.clear();
        }
    }
}

/// Packet buffered while waiting for ARP/NDP neighbor resolution.
pub(super) struct PendingNeighPacket {
    pub(super) addr: u64,
    pub(super) desc: XdpDesc,
    pub(super) meta: UserspaceDpMeta,
    pub(super) decision: SessionDecision,
    pub(super) queued_ns: u64,
    /// Cold-start probe schedule attempts (GEMINI-NEXT.md Section 3).
    /// 0 means no retries fired yet beyond the initial probe; each
    /// retry from `retry_pending_neigh` increments this. Capped by
    /// `PROBE_SCHEDULE_NS.len()`.
    pub(super) probe_attempts: u8,
}

// Compile-time size guard: the `probe_attempts: u8` added in #1082
// fit within the existing trailing alignment padding, so the struct
// is the same 224 B as before. If a future field bumps this past 224,
// re-evaluate the per-binding worst-case (224 B × MAX_PENDING_NEIGH
// = ~896 KiB; the comment in afxdp.rs above MAX_PENDING_NEIGH must
// be updated to match).
const _: () = assert!(
    core::mem::size_of::<PendingNeighPacket>() == 224,
    "PendingNeighPacket size changed — update afxdp.rs MAX_PENDING_NEIGH commentary",
);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct UserspaceDpMeta {
    pub(super) magic: u32,
    pub(super) version: u16,
    pub(super) length: u16,
    pub(super) ingress_ifindex: u32,
    pub(super) rx_queue_index: u32,
    pub(super) ingress_vlan_id: u16,
    pub(super) ingress_pcp: u8,
    pub(super) ingress_vlan_present: u8,
    pub(super) ingress_zone: u16,
    pub(super) routing_table: u32,
    pub(super) l3_offset: u16,
    pub(super) l4_offset: u16,
    pub(super) payload_offset: u16,
    pub(super) pkt_len: u16,
    pub(super) addr_family: u8,
    pub(super) protocol: u8,
    pub(super) tcp_flags: u8,
    pub(super) meta_flags: u8,
    pub(super) dscp: u8,
    pub(super) dscp_rewrite: u8,
    pub(super) reserved: u16,
    pub(super) flow_src_port: u16,
    pub(super) flow_dst_port: u16,
    pub(super) flow_src_addr: [u8; 16],
    pub(super) flow_dst_addr: [u8; 16],
    pub(super) config_generation: u64,
    pub(super) fib_generation: u32,
    pub(super) reserved2: u32,
}

const _: [(); 96] = [(); std::mem::size_of::<UserspaceDpMeta>()];
const _: [(); 18] = [(); std::mem::offset_of!(UserspaceDpMeta, ingress_pcp)];
const _: [(); 19] = [(); std::mem::offset_of!(UserspaceDpMeta, ingress_vlan_present)];
const _: [(); 20] = [(); std::mem::offset_of!(UserspaceDpMeta, ingress_zone)];
const _: [(); 24] = [(); std::mem::offset_of!(UserspaceDpMeta, routing_table)];
const _: [(); 36] = [(); std::mem::offset_of!(UserspaceDpMeta, addr_family)];
const _: [(); 40] = [(); std::mem::offset_of!(UserspaceDpMeta, dscp)];
const _: [(); 80] = [(); std::mem::offset_of!(UserspaceDpMeta, config_generation)];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ForwardPacketMeta {
    pub(super) ingress_ifindex: u32,
    pub(super) ingress_vlan_id: u16,
    pub(super) ingress_pcp: u8,
    pub(super) ingress_vlan_present: u8,
    pub(super) l3_offset: u16,
    pub(super) l4_offset: u16,
    pub(super) payload_offset: u16,
    pub(super) pkt_len: u16,
    pub(super) addr_family: u8,
    pub(super) protocol: u8,
    pub(super) tcp_flags: u8,
    pub(super) meta_flags: u8,
    pub(super) dscp: u8,
    pub(super) flow_src_port: u16,
    pub(super) flow_dst_port: u16,
}

impl From<UserspaceDpMeta> for ForwardPacketMeta {
    fn from(meta: UserspaceDpMeta) -> Self {
        Self {
            ingress_ifindex: meta.ingress_ifindex,
            ingress_vlan_id: meta.ingress_vlan_id,
            ingress_pcp: meta.ingress_pcp,
            ingress_vlan_present: meta.ingress_vlan_present,
            l3_offset: meta.l3_offset,
            l4_offset: meta.l4_offset,
            payload_offset: meta.payload_offset,
            pkt_len: meta.pkt_len,
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            tcp_flags: meta.tcp_flags,
            meta_flags: meta.meta_flags,
            dscp: meta.dscp,
            flow_src_port: meta.flow_src_port,
            flow_dst_port: meta.flow_dst_port,
        }
    }
}

impl From<ForwardPacketMeta> for UserspaceDpMeta {
    fn from(meta: ForwardPacketMeta) -> Self {
        Self {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: meta.ingress_ifindex,
            rx_queue_index: 0,
            ingress_vlan_id: meta.ingress_vlan_id,
            ingress_pcp: meta.ingress_pcp,
            ingress_vlan_present: meta.ingress_vlan_present,
            ingress_zone: 0,
            routing_table: 0,
            l3_offset: meta.l3_offset,
            l4_offset: meta.l4_offset,
            payload_offset: meta.payload_offset,
            pkt_len: meta.pkt_len,
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            tcp_flags: meta.tcp_flags,
            meta_flags: meta.meta_flags,
            dscp: meta.dscp,
            dscp_rewrite: 0,
            reserved: 0,
            flow_src_port: meta.flow_src_port,
            flow_dst_port: meta.flow_dst_port,
            flow_src_addr: [0; 16],
            flow_dst_addr: [0; 16],
            config_generation: 0,
            fib_generation: 0,
            reserved2: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PacketDisposition {
    Valid,
    NoSnapshot,
    ConfigGenerationMismatch,
    FibGenerationMismatch,
    UnsupportedPacket,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SessionFlow {
    pub(super) src_ip: IpAddr,
    pub(super) dst_ip: IpAddr,
    pub(super) forward_key: SessionKey,
}

impl SessionFlow {
    pub(super) fn with_destination(&self, dst_ip: IpAddr) -> Self {
        let mut forward_key = self.forward_key.clone();
        forward_key.dst_ip = dst_ip;
        Self {
            src_ip: self.src_ip,
            dst_ip,
            forward_key,
        }
    }

    pub(super) fn reverse_key_with_nat(&self, nat: NatDecision) -> SessionKey {
        reverse_session_key(&self.forward_key, nat)
    }
}

#[cfg(test)]
mod flow_rr_ring_tests {
    use super::*;

    // #694 / #711: `FlowRrRing` invariant pins. Colocated with the production
    // FlowRrRing struct + impl in types/mod.rs (split back from the
    // shared_cos_lease test mod per Codex P4 review).

    #[test]
    fn flow_rr_ring_push_pop_round_robin_order() {
        let mut ring = FlowRrRing::default();
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.front(), None);

        ring.push_back(7);
        ring.push_back(11);
        ring.push_back(13);
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.front(), Some(7));

        // FIFO dequeue preserves push order.
        assert_eq!(ring.pop_front(), Some(7));
        assert_eq!(ring.pop_front(), Some(11));
        assert_eq!(ring.pop_front(), Some(13));
        assert_eq!(ring.pop_front(), None);
        assert!(ring.is_empty());
    }

    #[test]
    fn flow_rr_ring_push_front_places_at_head() {
        let mut ring = FlowRrRing::default();
        ring.push_back(5);
        ring.push_back(9);
        ring.push_front(3); // restore at head
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.pop_front(), Some(3));
        assert_eq!(ring.pop_front(), Some(5));
        assert_eq!(ring.pop_front(), Some(9));
    }

    #[test]
    fn flow_rr_ring_wraps_around_buffer_end_correctly() {
        // Drive the head past the backing-array end and back around.
        // A naive implementation that uses `head + len` without mod
        // breaks exactly here.
        let mut ring = FlowRrRing::default();
        // Fill to 3/4 of capacity, drain half, then fill by another
        // half-capacity worth — the tail write crosses the backing-
        // array end and wraps. Total in-flight stays within capacity.
        let first = COS_FLOW_FAIR_BUCKETS * 3 / 4;
        let second = COS_FLOW_FAIR_BUCKETS / 2;
        for i in 0..first {
            ring.push_back(i as u16);
        }
        for _ in 0..(first / 2) {
            ring.pop_front();
        }
        for i in 0..second {
            ring.push_back((i + 10_000) as u16);
        }
        let mut drained = Vec::with_capacity(ring.len());
        while let Some(b) = ring.pop_front() {
            drained.push(b);
        }
        let mut expected: Vec<u16> = ((first / 2)..first).map(|i| i as u16).collect();
        expected.extend((0..second).map(|i| (i + 10_000) as u16));
        assert_eq!(drained, expected);
    }

    #[test]
    fn flow_rr_ring_iter_yields_same_order_as_pop() {
        let mut ring = FlowRrRing::default();
        for v in [17u16, 3, 11, 29, 7] {
            ring.push_back(v);
        }
        let iter_snapshot: Vec<u16> = ring.iter().collect();
        let mut pop_snapshot = Vec::new();
        while let Some(b) = ring.pop_front() {
            pop_snapshot.push(b);
        }
        assert_eq!(iter_snapshot, pop_snapshot);
    }

    #[test]
    fn flow_rr_ring_accepts_full_cap_minus_one_without_wraparound_bug() {
        // Exactly-at-capacity-minus-one fills: common off-by-one site
        // for ring buffers where the "full" condition is tested.
        let mut ring = FlowRrRing::default();
        let cap = COS_FLOW_FAIR_BUCKETS as u16;
        for i in 0..(cap - 1) {
            ring.push_back(i);
        }
        assert_eq!(ring.len(), usize::from(cap - 1));
        // Drain and re-fill to force internal head advancement past
        // 3/4 of the buffer.
        for _ in 0..((cap - 1) / 2) {
            ring.pop_front();
        }
        // Push enough to wrap past the buffer end.
        for i in 0..((cap - 1) / 2) {
            ring.push_back(i + 10_000);
        }
        // Drain and assert no duplicate IDs and no spurious values.
        let mut seen = std::collections::BTreeSet::new();
        while let Some(b) = ring.pop_front() {
            assert!(seen.insert(b), "ring produced duplicate bucket id: {b}");
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn flow_rr_ring_holds_full_bucket_count_without_panic() {
        // The ring's own capacity is `COS_FLOW_FAIR_BUCKETS`. The
        // caller guards against duplicate pushes, so in practice the
        // ring holds at most `COS_FLOW_FAIR_BUCKETS` entries. Verify
        // that exactly-at-capacity is well-defined (no push_back
        // panic in release, no wrong head index) and that the ring
        // empties correctly.
        let mut ring = FlowRrRing::default();
        for i in 0..COS_FLOW_FAIR_BUCKETS {
            ring.push_back(i as u16);
        }
        assert_eq!(ring.len(), COS_FLOW_FAIR_BUCKETS);
        // Front is 0, tail write would wrap — but we're not over-
        // filling, so this is the well-defined "exactly at capacity"
        // case.
        assert_eq!(ring.front(), Some(0));
        // Drain and verify every ID came back exactly once.
        let mut count = 0usize;
        while let Some(b) = ring.pop_front() {
            assert_eq!(b, count as u16);
            count += 1;
        }
        assert_eq!(count, COS_FLOW_FAIR_BUCKETS);
    }

    #[test]
    fn flow_rr_ring_memory_footprint_fits_expected_budget() {
        // Sanity pin: `FlowRrRing` should be ~`2 * COS_FLOW_FAIR_BUCKETS`
        // bytes (N u16 entries + two u16 indices + padding). A future
        // refactor that accidentally widens the entry type to u32 would
        // double this without a loud signal; this bound catches it.
        // Sized off the constant so it tracks with future bucket-count
        // bumps automatically.
        let size = std::mem::size_of::<FlowRrRing>();
        let budget = 2 * COS_FLOW_FAIR_BUCKETS + 64;
        assert!(
            size <= budget,
            "FlowRrRing unexpectedly large: {size} bytes (budget {budget})"
        );
    }
}
