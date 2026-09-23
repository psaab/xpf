//! #10597 Half-B: control→worker forward transport for uncovered WG decap.
//!
//! The WG control thread decapsulates transport records the XDP shim never
//! adjudicated (uncovered ingress) on its kernel UDP socket. Half-A refused
//! the transit half of that plaintext; the host-inbound half still reached
//! the `wgN` TUN through a direct control-thread write, meeting only the
//! kernel's `input` chains — no screen, no session, no zone policy, no NAT.
//!
//! This module is the NEW forward leg that carries those decapsulated inners
//! to a worker for full pipeline adjudication under the tunnel zone. The
//! return leg reuses the #10409 worker→WG delivery map unchanged.
//!
//! Shape mirrors `ipsec_inner_queue.rs` (per-worker bounded MPSC +
//! bounded drain) and `worker_queue.rs` (poison recovery, capacity shed):
//!
//! - One [`WgUncoveredIngressQueue`] per worker, published by the
//!   coordinator in a live `ArcSwap<BTreeMap<u32, _>>` table (the
//!   `local_tunnel_deliveries` topology). Queues are STABLE across
//!   reconciles: a respawned worker_id re-adopts its queue, so only a
//!   worker_id removed from the set orphans its backlog.
//! - The producer (WG control thread) NEVER blocks: `try_enqueue` fails
//!   on full/closed and the caller drops + counts. No retry, no rehash
//!   loop — a rehash would reorder the flow across workers.
//! - Steering is a deterministic inner-5-tuple hash modulo the sorted
//!   live worker set, so a flow sticks to one worker while the set is
//!   stable (per-flow order preserved; cross-flow interleave matches GRE).
//! - The worker drains at most [`WG_UNCOVERED_DRAIN_BUDGET`] descriptors
//!   per pass into a reused [`WgUncoveredInjectedBatch`], which the poll
//!   loop consumes exactly once (cursor-consumed, multi-binding safe).
//! - A removed worker's queue is closed before its backlog is drained:
//!   descriptors enqueued through a stale table view after the drain fail
//!   `try_enqueue` (closed) and are counted as shed, never stranded
//!   silently.
//!
//! What travels in a [`WgUncoveredDescriptor`] is the ADVISORY minimum the
//! worker needs to re-fence: the tunnel identity (endpoint id + logical
//! ifindex + name), the raw inner bytes, the outer ECN (the control thread
//! must NOT combine it — the worker combines exactly once in
//! `build_logical_ingress_packet`), and the config/fib generations captured
//! from the rotation-gate view at decrypt time. The worker revalidates all
//! of it against its own current view; anything stale is dropped + counted,
//! never adjudicated under a replacement's identity
//! (`logical_ingress.rs` fencing invariant).

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Per-worker forward-queue depth. Mirrors `IPSEC_INNER_QUEUE_DEPTH`: deep
/// enough to absorb a WG control-thread burst (`WG_RX_BURST` is 64) without
/// shedding, shallow enough that a wedged worker's backlog stays bounded.
pub(in crate::afxdp) const WG_UNCOVERED_QUEUE_DEPTH: usize = 128;

/// Max descriptors one worker drains per poll pass. Mirrors
/// `IPSEC_INNER_DRAIN_BUDGET` (a bounded fraction of the AF_XDP poll
/// budget, same discipline as `WORKER_COMMAND_DRAIN_BUDGET`).
pub(in crate::afxdp) const WG_UNCOVERED_DRAIN_BUDGET: usize = 64;

/// Sentinel `XdpDesc.addr` for injected items inside
/// `poll_binding_process_descriptor`. Real UMEM addrs are offsets into the
/// worker's UMEM region (far below this); the sentinel is filtered out of
/// `scratch_recycle` before the fill-ring drain, so it can never reach the
/// kernel rings. Lengths travel in the real `desc.len` field, so every
/// `desc.len` accounting site reads the true injected length untouched.
pub(in crate::afxdp) const WG_UNCOVERED_SENTINEL_ADDR: u64 = u64::MAX;

/// #10597 G6a: number of uncovered host-inbound records that had to use the
/// explicit zero-worker reachability fallback. This is NOT the normal path:
/// while a live worker set exists, queue pressure and stale attachment are
/// fail-closed drops. The fallback is retained only for the startup / total
/// worker-loss window so management reachability is not silently black-holed.
pub(in crate::afxdp) static WG_UNCOVERED_FALLBACK_WRITES_TOTAL: AtomicU64 = AtomicU64::new(0);

/// #10597: records successfully accepted into a worker queue.
pub(in crate::afxdp) static WG_UNCOVERED_ENQUEUED_TOTAL: AtomicU64 = AtomicU64::new(0);
/// #10597: descriptors dropped at the worker because the advisory
/// generation/attachment no longer matches the live view.
pub(in crate::afxdp) static WG_UNCOVERED_STALE_TOTAL: AtomicU64 = AtomicU64::new(0);

/// #10597: descriptors that were admitted by the shim-local view but resolved
/// non-local under the worker's authoritative FIB. They are dropped rather
/// than delegated to the kernel (no transit bypass).
pub(in crate::afxdp) static WG_UNCOVERED_NONLOCAL_TOTAL: AtomicU64 = AtomicU64::new(0);

/// #10597: descriptors dropped because the steered worker's forward queue
/// was already at [`WG_UNCOVERED_QUEUE_DEPTH`]. Fail-closed under pressure:
/// the control thread drops + counts rather than falling back to the direct
/// TUN write, which would make queue pressure a load-controlled adjudication
/// bypass.
pub(in crate::afxdp) static WG_UNCOVERED_QUEUE_FULL_TOTAL: AtomicU64 = AtomicU64::new(0);

/// #10597: descriptors refused because the steered queue was closed (its
/// worker_id left the live set between the table load and the enqueue).
pub(in crate::afxdp) static WG_UNCOVERED_QUEUE_SHED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// #10597: backlog orphaned when a worker_id left the live set (drained at
/// removal; each descriptor counted here exactly once).
pub(in crate::afxdp) static WG_UNCOVERED_QUEUE_ORPHAN_TOTAL: AtomicU64 = AtomicU64::new(0);

/// #10597: forward-queue poison recoveries. Same policy as
/// `worker_queue.rs` (#1807): a panic while holding the lock leaves the
/// committed prefix intact, the queue is recovered (not discarded), and the
/// recovery is counted here rather than folded into the loss counters.
pub(in crate::afxdp) static WG_UNCOVERED_QUEUE_POISON_RECOVERIES: AtomicU64 = AtomicU64::new(0);

/// One control-thread-decapped inner packet awaiting worker adjudication.
/// Immutable once enqueued.
#[derive(Debug)]
pub(in crate::afxdp) struct WgUncoveredDescriptor {
    /// Tunnel endpoint id the record decrypted under (engine/counter key).
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
    /// Tunnel logical ifindex the inner adjudicates under (zone derivation).
    pub(in crate::afxdp) logical_ifindex: i32,
    /// Tunnel name at decrypt time (attachment revalidation).
    pub(in crate::afxdp) tunnel_name: String,
    /// Raw inner L3 bytes (no Ethernet header).
    pub(in crate::afxdp) inner: Vec<u8>,
    /// Outer ECN captured via recvmsg cmsg, carried for the worker's
    /// exactly-once RFC 6040 combine. `None` skips the combine.
    pub(in crate::afxdp) outer_ecn: Option<u8>,
    /// Advisory generations captured from the rotation-gate view at decrypt
    /// time. Revalidated by the worker; never trusted blindly.
    pub(in crate::afxdp) config_generation: u64,
    pub(in crate::afxdp) fib_generation: u32,
    /// Kernel receive ifindex (pktinfo), for provenance in exceptions.
    pub(in crate::afxdp) ingress_ifindex: Option<u32>,
}

/// Per-worker bounded MPSC ingress queue carrying
/// [`WgUncoveredDescriptor`]s from WG control threads to one worker.
pub(in crate::afxdp) struct WgUncoveredIngressQueue {
    pending: Mutex<VecDeque<WgUncoveredDescriptor>>,
    closed: AtomicBool,
}

impl WgUncoveredIngressQueue {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            pending: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
        }
    }

    fn lock_recover(&self) -> std::sync::MutexGuard<'_, VecDeque<WgUncoveredDescriptor>> {
        match self.pending.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                WG_UNCOVERED_QUEUE_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed);
                poisoned.into_inner()
            }
        }
    }

    /// Enqueue without blocking. `Err(descriptor)` hands the descriptor back
    /// on full (caller drops + counts [`WG_UNCOVERED_QUEUE_FULL_TOTAL`]) or
    /// closed (caller counts [`WG_UNCOVERED_QUEUE_SHED_TOTAL`]).
    pub(in crate::afxdp) fn try_enqueue(
        &self,
        desc: WgUncoveredDescriptor,
    ) -> Result<(), WgUncoveredDescriptor> {
        if self.closed.load(Ordering::Acquire) {
            return Err(desc);
        }
        let mut pending = self.lock_recover();
        // Re-check under the lock: `close_and_drain` sets closed before
        // draining, so anything enqueued after this point would strand.
        if self.closed.load(Ordering::Acquire) {
            return Err(desc);
        }
        if pending.len() >= WG_UNCOVERED_QUEUE_DEPTH {
            return Err(desc);
        }
        pending.push_back(desc);
        Ok(())
    }

    /// Drain up to `budget` descriptors into `batch`. Returns the count
    /// moved. Called only by the owning worker.
    pub(in crate::afxdp) fn drain_into(
        &self,
        batch: &mut Vec<WgUncoveredDescriptor>,
        budget: usize,
    ) -> usize {
        let mut pending = self.lock_recover();
        let mut moved = 0;
        while moved < budget {
            let Some(desc) = pending.pop_front() else {
                break;
            };
            batch.push(desc);
            moved += 1;
        }
        moved
    }

    /// Close the queue and hand back its backlog for orphan accounting. The
    /// closed flag is set BEFORE draining (under the same lock the producer
    /// re-checks), so no enqueue can land after the drain.
    pub(in crate::afxdp) fn close_and_drain(&self) -> Vec<WgUncoveredDescriptor> {
        let mut pending = self.lock_recover();
        self.closed.store(true, Ordering::Release);
        pending.drain(..).collect()
    }

    pub(in crate::afxdp) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(in crate::afxdp) fn len(&self) -> usize {
        self.lock_recover().len()
    }
}

impl Default for WgUncoveredIngressQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic inner-5-tuple hash for steering (FNV-1a/64 over family +
/// src + dst + proto + ports). Forwarded inners are always parseable v4/v6
/// (Half-A delivers only shim-local, which requires a parsed destination);
/// the fallback hashes the raw prefix so an unexpected shape still steers
/// deterministically rather than randomly.
pub(in crate::afxdp) fn wg_uncovered_flow_hash(inner: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    let mut mix = |bytes: &[u8]| {
        for &b in bytes {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    };
    let tuple: Option<(&[u8], &[u8], u8, u16, u16)> = match inner.first().map(|b| b >> 4) {
        Some(4) if inner.len() >= 20 => {
            let ihl = usize::from(inner[0] & 0x0f).saturating_mul(4);
            if inner.len() < ihl {
                None
            } else {
                let proto = inner[9];
                let (src_port, dst_port) = match proto {
                    crate::ip_proto::PROTO_TCP | crate::ip_proto::PROTO_UDP
                        if inner.len() >= ihl + 4 =>
                    {
                        (
                            u16::from_be_bytes([inner[ihl], inner[ihl + 1]]),
                            u16::from_be_bytes([inner[ihl + 2], inner[ihl + 3]]),
                        )
                    }
                    _ => (0, 0),
                };
                Some((&inner[12..16], &inner[16..20], proto, src_port, dst_port))
            }
        }
        Some(6) if inner.len() >= 40 => {
            let proto = inner[6];
            let (src_port, dst_port) = match proto {
                crate::ip_proto::PROTO_TCP | crate::ip_proto::PROTO_UDP
                    if inner.len() >= 44 =>
                {
                    (
                        u16::from_be_bytes([inner[40], inner[41]]),
                        u16::from_be_bytes([inner[42], inner[43]]),
                    )
                }
                _ => (0, 0),
            };
            Some((&inner[8..24], &inner[24..40], proto, src_port, dst_port))
        }
        _ => None,
    };
    match tuple {
        Some((src, dst, proto, sport, dport)) => {
            mix(src);
            mix(dst);
            mix(&[proto]);
            mix(&sport.to_be_bytes());
            mix(&dport.to_be_bytes());
        }
        None => mix(inner.get(..64).unwrap_or(inner)),
    }
    hash
}

/// Build the synthetic Ethernet frame/meta consumed by the ordinary worker
/// pipeline, and apply the worker-side attachment/generation fence. This is
/// deliberately separate from queue draining so unit cells can prove stale
/// descriptors are rejected before any policy/session work.
pub(in crate::afxdp) fn build_injected_packet(
    descriptor: &WgUncoveredDescriptor,
    forwarding: &crate::afxdp::ForwardingState,
    validation: crate::afxdp::ValidationState,
    rx_queue_index: u32,
) -> Option<(Vec<u8>, crate::afxdp::UserspaceDpMeta)> {
    if descriptor.config_generation != validation.config_generation
        || descriptor.fib_generation != validation.fib_generation
    {
        WG_UNCOVERED_STALE_TOTAL.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let endpoint = forwarding.tunnel_endpoints.get(&descriptor.tunnel_endpoint_id)?;
    if endpoint.mode != "wireguard"
        || endpoint.logical_ifindex != descriptor.logical_ifindex
        || forwarding
            .ifindex_to_name
            .get(&descriptor.logical_ifindex)
            .is_none_or(|name| name != &descriptor.tunnel_name)
    {
        WG_UNCOVERED_STALE_TOTAL.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let (inner_family, inner_eth_proto) = match descriptor.inner.first().map(|b| b >> 4) {
        Some(4) => (libc::AF_INET as u8, 0x0800u16),
        Some(6) => (libc::AF_INET6 as u8, 0x86ddu16),
        _ => {
            WG_UNCOVERED_STALE_TOTAL.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    let inner_len =
        crate::afxdp::gre::packet_trimmed_len(&descriptor.inner, inner_family)?;
    let inner = descriptor.inner.get(..inner_len)?;
    let (protocol, rel_l4_offset, payload_offset) =
        crate::afxdp::gre::parse_inner_protocol_and_offsets(inner, inner_family)?;
    crate::afxdp::logical_ingress::build_logical_ingress_packet(
        forwarding,
        &crate::afxdp::logical_ingress::LogicalIngressParams {
            inner_packet: inner,
            inner_family,
            inner_eth_proto,
            protocol,
            rel_l4_offset,
            payload_offset,
            logical_ifindex: endpoint.logical_ifindex,
            outer_ecn: descriptor.outer_ecn,
            ecn_illegal_drops: &crate::afxdp::gre::WG_DECAP_ECN_ILLEGAL_DROPS,
            meta_flags: 0,
            rx_queue_index,
            config_generation: descriptor.config_generation,
            fib_generation: descriptor.fib_generation,
        },
    )
}

/// Steer a flow hash to one live worker's queue. `BTreeMap` iteration is
/// key-sorted, so the choice is deterministic for a stable set; an empty
/// table (no workers) yields `None` and the caller takes the zero-worker
/// fallback. Returns the owning worker_id alongside the queue for
/// provenance in counters/exceptions.
pub(in crate::afxdp) fn steer_uncovered_queue(
    table: &BTreeMap<u32, Arc<WgUncoveredIngressQueue>>,
    hash: u64,
) -> Option<(u32, Arc<WgUncoveredIngressQueue>)> {
    if table.is_empty() {
        return None;
    }
    let idx = (hash % table.len() as u64) as usize;
    table
        .iter()
        .nth(idx)
        .map(|(id, queue)| (*id, queue.clone()))
}

/// The worker-side injected batch: one drain's descriptors plus the consume
/// cursor. Cursor-consumed so a multi-binding worker processes the batch
/// exactly once no matter how many bindings poll per tick; cleared (not
/// reallocated) after each pass.
pub(in crate::afxdp) struct WgUncoveredInjectedBatch {
    items: Vec<WgUncoveredDescriptor>,
    cursor: usize,
}

impl WgUncoveredInjectedBatch {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            items: Vec::with_capacity(WG_UNCOVERED_DRAIN_BUDGET),
            cursor: 0,
        }
    }

    pub(in crate::afxdp) fn drain_from(&mut self, queue: &WgUncoveredIngressQueue) -> usize {
        self.clear();
        queue.drain_into(&mut self.items, WG_UNCOVERED_DRAIN_BUDGET)
    }

    pub(in crate::afxdp) fn push_drained(&mut self, desc: WgUncoveredDescriptor) {
        self.items.push(desc);
    }

    pub(in crate::afxdp) fn next(&mut self) -> Option<WgUncoveredDescriptor> {
        if self.cursor >= self.items.len() {
            return None;
        }
        // Descriptors move out of order-safe storage: swap-remove would
        // reorder; the cursor walk preserves drain (FIFO) order. The slot is
        // left as a moved-from hole only transiently — `clear` truncates.
        // (Items are `Vec`-owned; move out via index replace with a dummy is
        // avoided by draining from the front through the cursor window.)
        let desc = self.items.get_mut(self.cursor).map(|slot| {
            // SAFETY-free move-out: replace with an empty placeholder; the
            // prefix below the cursor is dead until `clear`.
            std::mem::replace(
                slot,
                WgUncoveredDescriptor {
                    tunnel_endpoint_id: 0,
                    logical_ifindex: 0,
                    tunnel_name: String::new(),
                    inner: Vec::new(),
                    outer_ecn: None,
                    config_generation: 0,
                    fib_generation: 0,
                    ingress_ifindex: None,
                },
            )
        });
        if desc.is_some() {
            self.cursor += 1;
        }
        desc
    }

    pub(in crate::afxdp) fn is_empty(&self) -> bool {
        self.cursor >= self.items.len()
    }

    pub(in crate::afxdp) fn remaining(&self) -> usize {
        self.items.len().saturating_sub(self.cursor)
    }

    pub(in crate::afxdp) fn clear(&mut self) {
        self.items.clear();
        self.cursor = 0;
    }
}

impl Default for WgUncoveredInjectedBatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_descriptor(id: u16) -> WgUncoveredDescriptor {
        WgUncoveredDescriptor {
            tunnel_endpoint_id: id,
            logical_ifindex: 400,
            tunnel_name: "wg0".to_string(),
            inner: vec![0x45, 0, 0, 20],
            outer_ecn: Some(0),
            config_generation: 7,
            fib_generation: 9,
            ingress_ifindex: Some(3),
        }
    }

    #[test]
    fn enqueue_until_full_then_refuse_10597() {
        let queue = WgUncoveredIngressQueue::new();
        for id in 0..WG_UNCOVERED_QUEUE_DEPTH as u16 {
            assert!(queue.try_enqueue(test_descriptor(id)).is_ok());
        }
        assert_eq!(queue.len(), WG_UNCOVERED_QUEUE_DEPTH);
        let refused = queue.try_enqueue(test_descriptor(999)).expect_err("full");
        assert_eq!(refused.tunnel_endpoint_id, 999, "refusal hands it back");
        assert_eq!(queue.len(), WG_UNCOVERED_QUEUE_DEPTH);
    }

    #[test]
    fn drain_bounded_fifo_10597() {
        let queue = WgUncoveredIngressQueue::new();
        for id in 0..10u16 {
            queue.try_enqueue(test_descriptor(id)).unwrap();
        }
        let mut batch = Vec::new();
        assert_eq!(queue.drain_into(&mut batch, 4), 4);
        assert_eq!(queue.len(), 6);
        let ids: Vec<u16> = batch.iter().map(|d| d.tunnel_endpoint_id).collect();
        assert_eq!(ids, vec![0, 1, 2, 3], "FIFO order");
        // Budget larger than the backlog drains all.
        let mut rest = Vec::new();
        assert_eq!(queue.drain_into(&mut rest, WG_UNCOVERED_DRAIN_BUDGET), 6);
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn close_and_drain_orphans_backlog_and_refuses_late_10597() {
        let queue = WgUncoveredIngressQueue::new();
        queue.try_enqueue(test_descriptor(1)).unwrap();
        queue.try_enqueue(test_descriptor(2)).unwrap();
        let orphans = queue.close_and_drain();
        assert_eq!(orphans.len(), 2);
        assert!(queue.is_closed());
        assert!(queue.try_enqueue(test_descriptor(3)).is_err());
        assert!(queue.close_and_drain().is_empty());
    }

    #[test]
    fn steering_stable_and_spread_10597() {
        let table: BTreeMap<u32, Arc<WgUncoveredIngressQueue>> =
            [(0, Arc::new(WgUncoveredIngressQueue::new())), (1, Arc::new(WgUncoveredIngressQueue::new())), (2, Arc::new(WgUncoveredIngressQueue::new()))].into_iter().collect();
        // Same inner => same worker, every time (per-flow order).
        let inner = [0x45u8, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0, 80, 1, 187];
        let hash = wg_uncovered_flow_hash(&inner);
        let first = steer_uncovered_queue(&table, hash).unwrap().0;
        for _ in 0..8 {
            assert_eq!(steer_uncovered_queue(&table, wg_uncovered_flow_hash(&inner)).unwrap().0, first);
        }
        // Distinct flows spread across more than one worker.
        let mut owners = std::collections::BTreeSet::new();
        for i in 0u8..24 {
            let mut flow = inner.to_vec();
            flow[15] = i;
            owners.insert(steer_uncovered_queue(&table, wg_uncovered_flow_hash(&flow)).unwrap().0);
        }
        assert!(owners.len() > 1, "hash must spread, got {owners:?}");
        // Empty table => None (zero-worker fallback), never a panic.
        assert!(steer_uncovered_queue(&BTreeMap::new(), hash).is_none());
    }

    #[test]
    fn injected_batch_consumes_exactly_once_10597() {
        let mut batch = WgUncoveredInjectedBatch::new();
        assert!(batch.is_empty());
        batch.push_drained(test_descriptor(1));
        batch.push_drained(test_descriptor(2));
        assert_eq!(batch.remaining(), 2);
        assert_eq!(batch.next().unwrap().tunnel_endpoint_id, 1);
        assert!(!batch.is_empty());
        assert_eq!(batch.next().unwrap().tunnel_endpoint_id, 2);
        assert!(batch.is_empty());
        assert!(batch.next().is_none());
        batch.clear();
        assert!(batch.is_empty());
        assert_eq!(batch.remaining(), 0);
    }
}
