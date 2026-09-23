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

/// #10597: records successfully accepted into a worker queue.
pub(in crate::afxdp) static WG_UNCOVERED_ENQUEUED_TOTAL: AtomicU64 = AtomicU64::new(0);
/// #10597: descriptors dropped at the worker because the advisory
/// generation/attachment no longer matches the live view.
pub(in crate::afxdp) static WG_UNCOVERED_STALE_TOTAL: AtomicU64 = AtomicU64::new(0);
/// #10597: descriptors whose inner bytes fail to parse (bad IP version
/// nibble, short/truncated header, unparseable L4 offsets). Counted apart
/// from `STALE`: a malformed inner is a corrupt/decrypt-mismatched record,
/// not a rotation-gate fence hit, and conflating the two would hide either
/// signal.
pub(in crate::afxdp) static WG_UNCOVERED_MALFORMED_TOTAL: AtomicU64 = AtomicU64::new(0);

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
pub(crate) struct WgUncoveredDescriptor {
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
}

/// Per-worker bounded MPSC ingress queue carrying
/// [`WgUncoveredDescriptor`]s from WG control threads to one worker.
pub(crate) struct WgUncoveredIngressQueue {
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
        let mut pending = match self.pending.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                WG_UNCOVERED_QUEUE_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed);
                poisoned.into_inner()
            }
            Err(std::sync::TryLockError::WouldBlock) => return Err(desc),
        };
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
                crate::ip_proto::PROTO_TCP | crate::ip_proto::PROTO_UDP if inner.len() >= 44 => (
                    u16::from_be_bytes([inner[40], inner[41]]),
                    u16::from_be_bytes([inner[42], inner[43]]),
                ),
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
    let endpoint = match forwarding
        .tunnel_endpoints
        .get(&descriptor.tunnel_endpoint_id)
    {
        Some(endpoint) => endpoint,
        None => {
            WG_UNCOVERED_STALE_TOTAL.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
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
            WG_UNCOVERED_MALFORMED_TOTAL.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    let Some(inner_len) = crate::afxdp::gre::packet_trimmed_len(&descriptor.inner, inner_family)
    else {
        WG_UNCOVERED_MALFORMED_TOTAL.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let Some(inner) = descriptor.inner.get(..inner_len) else {
        WG_UNCOVERED_MALFORMED_TOTAL.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let Some((protocol, rel_l4_offset, payload_offset)) =
        crate::afxdp::gre::parse_inner_protocol_and_offsets(inner, inner_family)
    else {
        WG_UNCOVERED_MALFORMED_TOTAL.fetch_add(1, Ordering::Relaxed);
        return None;
    };
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

    #[cfg(test)]
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

    #[cfg(test)]
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
        let table: BTreeMap<u32, Arc<WgUncoveredIngressQueue>> = [
            (0, Arc::new(WgUncoveredIngressQueue::new())),
            (1, Arc::new(WgUncoveredIngressQueue::new())),
            (2, Arc::new(WgUncoveredIngressQueue::new())),
        ]
        .into_iter()
        .collect();
        // Same inner => same worker, every time (per-flow order).
        let inner = [
            0x45u8, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0, 80, 1, 187,
        ];
        let hash = wg_uncovered_flow_hash(&inner);
        let first = steer_uncovered_queue(&table, hash).unwrap().0;
        for _ in 0..8 {
            assert_eq!(
                steer_uncovered_queue(&table, wg_uncovered_flow_hash(&inner))
                    .unwrap()
                    .0,
                first
            );
        }
        // Distinct flows spread across more than one worker.
        let mut owners = std::collections::BTreeSet::new();
        for i in 0u8..24 {
            let mut flow = inner.to_vec();
            flow[15] = i;
            owners.insert(
                steer_uncovered_queue(&table, wg_uncovered_flow_hash(&flow))
                    .unwrap()
                    .0,
            );
        }
        assert!(owners.len() > 1, "hash must spread, got {owners:?}");
        // Empty table => no consumer: the caller must fail closed.
        assert!(steer_uncovered_queue(&BTreeMap::new(), hash).is_none());
    }

    fn valid_inner_v4(ecn: u8) -> Vec<u8> {
        let mut inner = vec![0u8; 40];
        let total_len = inner.len() as u16;
        inner[0] = 0x45;
        inner[1] = ecn & 0x03;
        inner[2..4].copy_from_slice(&total_len.to_be_bytes());
        inner[8] = 64;
        inner[9] = 6;
        inner[12..16].copy_from_slice(&[10, 123, 0, 2]);
        inner[16..20].copy_from_slice(&[10, 123, 0, 1]);
        inner[20..22].copy_from_slice(&12345u16.to_be_bytes());
        inner[22..24].copy_from_slice(&80u16.to_be_bytes());
        inner[32] = 0x50;
        inner
    }

    fn attached_descriptor(outer_ecn: Option<u8>, inner: Vec<u8>) -> WgUncoveredDescriptor {
        WgUncoveredDescriptor {
            tunnel_endpoint_id: 1,
            logical_ifindex: 400,
            tunnel_name: "wg0".to_string(),
            inner,
            outer_ecn,
            config_generation: 7,
            fib_generation: 9,
        }
    }

    #[test]
    fn injected_entry_builds_post_decap_frame_and_meta_10597() {
        let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(
            &crate::afxdp::test_fixtures::wg_outer_mtu_snapshot(),
        );
        let validation = crate::afxdp::ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        };
        let (frame, meta) = build_injected_packet(
            &attached_descriptor(Some(0), valid_inner_v4(0b10)),
            &forwarding,
            validation,
            3,
        )
        .expect("attached WG plaintext must build a worker frame");
        assert_eq!(frame.len(), 54, "Ethernet header plus inner IPv4");
        assert_eq!(meta.l3_offset, 14);
        assert_eq!(meta.pkt_len as usize, frame.len());
        assert_eq!(frame[14], 0x45, "the worker entry receives inner L3");
    }

    #[test]
    fn injected_entry_applies_rfc6040_ecn_once_10597() {
        let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(
            &crate::afxdp::test_fixtures::wg_outer_mtu_snapshot(),
        );
        let validation = crate::afxdp::ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        };
        let (frame, _) = build_injected_packet(
            &attached_descriptor(Some(0b11), valid_inner_v4(0b10)),
            &forwarding,
            validation,
            3,
        )
        .expect("ECT inner plus outer CE is a legal RFC 6040 upgrade");
        assert_eq!(frame[15] & 0x03, 0b11, "outer CE upgrades inner to CE");
    }

    #[test]
    fn injected_entry_rejects_attachment_or_generation_rotation_10597() {
        let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(
            &crate::afxdp::test_fixtures::wg_outer_mtu_snapshot(),
        );
        let validation = crate::afxdp::ValidationState {
            snapshot_installed: true,
            config_generation: 8,
            fib_generation: 9,
        };
        assert!(
            build_injected_packet(
                &attached_descriptor(None, valid_inner_v4(0)),
                &forwarding,
                validation,
                3,
            )
            .is_none(),
            "rotation generation must fence a queued descriptor"
        );
        let mut detached = attached_descriptor(None, valid_inner_v4(0));
        detached.tunnel_name = "wg1".to_string();
        let current = crate::afxdp::ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        };
        assert!(
            build_injected_packet(&detached, &forwarding, current, 3).is_none(),
            "attachment-name drift must fence a queued descriptor"
        );
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
    // #10597 traversal helpers + cells: drive one control-thread WG
    // plaintext record through the REAL worker pipeline
    // (`build_injected_packet` + `txn_run_descriptor_with_injected`) and
    // observe the #10409 delivery channel — the same bytes the wgN TUN
    // write would carry.
    fn wg_uncovered_host_snapshot(default_policy: &str) -> crate::afxdp::ConfigSnapshot {
        let mut snapshot = crate::afxdp::test_fixtures::wg_outer_mtu_snapshot();
        snapshot.default_policy = default_policy.to_string();
        snapshot.policies.clear();
        // The WG fixture zones carry no host-inbound stanza, which is
        // default-deny (#3405). Admit ping on the ingress (sfmix) zone so
        // the traversal cells reach policy/delivery; the deny cell below
        // deliberately omits this.
        for zone in snapshot.zones.iter_mut().filter(|z| z.name == "sfmix") {
            zone.host_inbound_configured = true;
            zone.host_inbound_system_services = vec!["ping".to_string()];
        }
        snapshot
    }

    fn wg_inner_icmp_echo(src: [u8; 4], dst: [u8; 4], ecn: u8) -> Vec<u8> {
        let mut packet = vec![
            0x45,
            ecn & 0x03,
            0x00,
            0x24,
            0x00,
            0x01,
            0x00,
            0x00,
            64,
            crate::ip_proto::PROTO_ICMP,
            0x00,
            0x00,
            src[0],
            src[1],
            src[2],
            src[3],
            dst[0],
            dst[1],
            dst[2],
            dst[3],
        ];
        let ip_sum = crate::afxdp::frame::checksum16(&packet[0..20]);
        packet[10] = (ip_sum >> 8) as u8;
        packet[11] = ip_sum as u8;
        let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        icmp.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]);
        let icmp_sum = crate::afxdp::frame::checksum16(&icmp);
        icmp[2] = (icmp_sum >> 8) as u8;
        icmp[3] = icmp_sum as u8;
        packet.extend_from_slice(&icmp);
        packet
    }

    fn wg_uncovered_icmp_descriptor(
        inner: Vec<u8>,
        outer_ecn: Option<u8>,
    ) -> WgUncoveredDescriptor {
        WgUncoveredDescriptor {
            tunnel_endpoint_id: 1,
            logical_ifindex: 400,
            tunnel_name: "wg0".to_string(),
            inner,
            outer_ecn,
            config_generation: 7,
            fib_generation: 9,
        }
    }

    fn wg_deliveries(
        ifindex: i32,
    ) -> (
        Arc<arc_swap::ArcSwap<BTreeMap<i32, crate::afxdp::tunnel::LocalTunnelDelivery>>>,
        std::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        let wake = Arc::new(crate::afxdp::tunnel::TunnelWake::new().expect("eventfd"));
        let mut map = BTreeMap::new();
        map.insert(
            ifindex,
            crate::afxdp::tunnel::LocalTunnelDelivery { tx, wake },
        );
        (Arc::new(arc_swap::ArcSwap::from_pointee(map)), rx)
    }

    fn wg_injected_validation() -> crate::afxdp::ValidationState {
        crate::afxdp::ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        }
    }

    #[test]
    fn injected_permit_delivers_inner_via_delivery_map_10597() {
        let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(
            &wg_uncovered_host_snapshot("permit"),
        );
        let ha_state = crate::afxdp::tests_support::txn_ha_state();
        let mut binding = crate::afxdp::worker::BindingWorker::new_for_mirror_test(0, 0, 6, 0);
        let mut sessions = crate::session::SessionTable::new();
        // ECT inner + outer CE: the traversal must carry the exactly-once
        // RFC 6040 upgrade all the way to the TUN-bound bytes.
        let inner = wg_inner_icmp_echo([10, 123, 0, 2], [10, 123, 0, 1], 0b10);
        let injected = build_injected_packet(
            &wg_uncovered_icmp_descriptor(inner, Some(0b11)),
            &forwarding,
            wg_injected_validation(),
            0,
        )
        .expect("attached WG plaintext must build a worker frame");
        let (deliveries, rx) = wg_deliveries(400);
        let (_batch, dbg) = crate::afxdp::tests_support::txn_run_descriptor_with_injected(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            injected,
            &deliveries,
        );
        assert_eq!(dbg.local, 1, "host-bound record must take LocalDelivery");
        assert_eq!(dbg.policy_deny, 0, "permit snapshot must not deny");
        let delivered = rx
            .try_recv()
            .expect("inner must reach the wg0 delivery channel");
        assert_eq!(
            delivered[0] >> 4,
            4,
            "TUN-bound payload starts with the IP nibble (IFF_NO_PI)"
        );
        assert_eq!(
            delivered[12..20].to_vec(),
            vec![10, 123, 0, 2, 10, 123, 0, 1],
            "addrs survive the control->worker->map round trip"
        );
        assert_eq!(
            delivered[1] & 0x03,
            0b11,
            "outer CE upgrades the delivered inner to CE"
        );
        assert!(rx.try_recv().is_err(), "exactly one delivery per record");
    }

    #[test]
    fn injected_deny_drops_without_delivery_10597() {
        // No ping admit: the bare fixture zone is host-inbound default-deny.
        let mut denied = crate::afxdp::test_fixtures::wg_outer_mtu_snapshot();
        denied.default_policy = "deny".to_string();
        denied.policies.clear();
        let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(&denied);
        let ha_state = crate::afxdp::tests_support::txn_ha_state();
        let mut binding = crate::afxdp::worker::BindingWorker::new_for_mirror_test(0, 0, 6, 0);
        let mut sessions = crate::session::SessionTable::new();
        let nonlocal_before = WG_UNCOVERED_NONLOCAL_TOTAL.load(Ordering::Relaxed);
        let inner = wg_inner_icmp_echo([10, 123, 0, 2], [10, 123, 0, 1], 0);
        let injected = build_injected_packet(
            &wg_uncovered_icmp_descriptor(inner, None),
            &forwarding,
            wg_injected_validation(),
            0,
        )
        .expect("attached WG plaintext must build a worker frame");
        let (deliveries, rx) = wg_deliveries(400);
        let (_batch, dbg) = crate::afxdp::tests_support::txn_run_descriptor_with_injected(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            injected,
            &deliveries,
        );
        assert_eq!(
            dbg.local, 1,
            "host-bound record takes the LocalDelivery arm"
        );
        assert_eq!(
            dbg.host_inbound_deny, 1,
            "unconfigured-zone host-inbound must deny the echo"
        );
        assert_eq!(
            dbg.policy_deny, 0,
            "host-inbound denies before policy is judged"
        );
        assert!(
            rx.try_recv().is_err(),
            "denied record must never reach the delivery map"
        );
        assert_eq!(
            sessions.len(),
            0,
            "denied record must not install a session"
        );
        assert_eq!(
            WG_UNCOVERED_NONLOCAL_TOTAL.load(Ordering::Relaxed) - nonlocal_before,
            0,
            "resolved local: G5 must not pre-drop what host-inbound denies"
        );
    }

    #[test]
    fn injected_junos_host_deny_drops_without_delivery_10597() {
        // Host-inbound admits (ping), but a to-zone junos-host deny policy
        // adjudicates after it (Junos order, #3019): the record must drop
        // with policy_deny, proving the pipeline's policy stage judges
        // control-thread plaintext.
        let mut snapshot = wg_uncovered_host_snapshot("permit");
        snapshot.policies.push(crate::PolicyRuleSnapshot {
            name: "host-deny".to_string(),
            from_zone: "sfmix".to_string(),
            to_zone: "junos-host".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "deny".to_string(),
            ..Default::default()
        });
        let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(&snapshot);
        let ha_state = crate::afxdp::tests_support::txn_ha_state();
        let mut binding = crate::afxdp::worker::BindingWorker::new_for_mirror_test(0, 0, 6, 0);
        let mut sessions = crate::session::SessionTable::new();
        let inner = wg_inner_icmp_echo([10, 123, 0, 2], [10, 123, 0, 1], 0);
        let injected = build_injected_packet(
            &wg_uncovered_icmp_descriptor(inner, None),
            &forwarding,
            wg_injected_validation(),
            0,
        )
        .expect("attached WG plaintext must build a worker frame");
        let (deliveries, rx) = wg_deliveries(400);
        let (_batch, dbg) = crate::afxdp::tests_support::txn_run_descriptor_with_injected(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            injected,
            &deliveries,
        );
        assert_eq!(
            dbg.local, 1,
            "host-bound record takes the LocalDelivery arm"
        );
        assert_eq!(
            dbg.policy_deny, 1,
            "junos-host deny must adjudicate-deny the host-bound record"
        );
        assert!(
            rx.try_recv().is_err(),
            "policy-denied record must never reach the delivery map"
        );
        assert_eq!(
            sessions.len(),
            0,
            "policy-denied record must not install a session"
        );
    }

    #[test]
    fn injected_frame_recycles_tx_pool_exactly_once_10597() {
        let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(
            &wg_uncovered_host_snapshot("permit"),
        );
        let ha_state = crate::afxdp::tests_support::txn_ha_state();
        let mut binding = crate::afxdp::worker::BindingWorker::new_for_mirror_test(0, 0, 6, 0);
        let mut sessions = crate::session::SessionTable::new();
        let free_before = binding.tx_pipeline.free_tx_frames.len();
        let head = *binding
            .tx_pipeline
            .free_tx_frames
            .front()
            .expect("seeded TX pool");
        let inner = wg_inner_icmp_echo([10, 123, 0, 2], [10, 123, 0, 1], 0);
        let injected = build_injected_packet(
            &wg_uncovered_icmp_descriptor(inner, None),
            &forwarding,
            wg_injected_validation(),
            0,
        )
        .expect("attached WG plaintext must build a worker frame");
        let (deliveries, rx) = wg_deliveries(400);
        crate::afxdp::tests_support::txn_run_descriptor_with_injected(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            injected,
            &deliveries,
        );
        assert!(rx.try_recv().is_ok(), "UMEM cell still delivers");
        assert_eq!(
            binding.tx_pipeline.free_tx_frames.len(),
            free_before,
            "pop+recycle nets zero: no leak, no double-recycle"
        );
        assert!(
            binding.tx_pipeline.free_tx_frames.contains(&head),
            "the injected frame returns to the free pool, not the fill ring"
        );
    }

    #[test]
    fn injected_nonlocal_transit_drops_without_delivery_10597() {
        let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(
            &wg_uncovered_host_snapshot("permit"),
        );
        let ha_state = crate::afxdp::tests_support::txn_ha_state();
        let mut binding = crate::afxdp::worker::BindingWorker::new_for_mirror_test(0, 0, 6, 0);
        let mut sessions = crate::session::SessionTable::new();
        let nonlocal_before = WG_UNCOVERED_NONLOCAL_TOTAL.load(Ordering::Relaxed);
        // 203.0.113.7 routes via reth0.80: transit under the worker FIB.
        let inner = wg_inner_icmp_echo([10, 123, 0, 2], [203, 0, 113, 7], 0);
        let injected = build_injected_packet(
            &wg_uncovered_icmp_descriptor(inner, None),
            &forwarding,
            wg_injected_validation(),
            0,
        )
        .expect("attached WG plaintext must build a worker frame");
        let (deliveries, rx) = wg_deliveries(400);
        let (_batch, dbg) = crate::afxdp::tests_support::txn_run_descriptor_with_injected(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            injected,
            &deliveries,
        );
        assert_eq!(
            WG_UNCOVERED_NONLOCAL_TOTAL.load(Ordering::Relaxed) - nonlocal_before,
            1,
            "transit-resolving record must fence as nonlocal"
        );
        assert!(
            rx.try_recv().is_err(),
            "nonlocal record must never reach the delivery map"
        );
        assert_eq!(
            sessions.len(),
            0,
            "nonlocal record must not install a session"
        );
        assert_eq!(
            dbg.policy_deny, 0,
            "nonlocal drops before policy adjudication"
        );
    }

    #[test]
    fn injected_other_interface_local_passes_g5_10597() {
        let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(
            &wg_uncovered_host_snapshot("permit"),
        );
        let ha_state = crate::afxdp::tests_support::txn_ha_state();
        let mut binding = crate::afxdp::worker::BindingWorker::new_for_mirror_test(0, 0, 6, 0);
        let mut sessions = crate::session::SessionTable::new();
        let nonlocal_before = WG_UNCOVERED_NONLOCAL_TOTAL.load(Ordering::Relaxed);
        // 172.16.80.8 is reth0.80's primary: local on another interface.
        let inner = wg_inner_icmp_echo([10, 123, 0, 2], [172, 16, 80, 8], 0);
        let injected = build_injected_packet(
            &wg_uncovered_icmp_descriptor(inner, None),
            &forwarding,
            wg_injected_validation(),
            0,
        )
        .expect("attached WG plaintext must build a worker frame");
        let (deliveries, rx) = wg_deliveries(400);
        crate::afxdp::tests_support::txn_run_descriptor_with_injected(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            injected,
            &deliveries,
        );
        assert_eq!(
            WG_UNCOVERED_NONLOCAL_TOTAL.load(Ordering::Relaxed) - nonlocal_before,
            0,
            "another interface's local addr must pass the G5 fence"
        );
        assert!(
            rx.try_recv().is_err(),
            "no wg0-map entry for ifindex 12: must not deliver on the WG channel"
        );
    }
    #[test]
    fn injected_entry_rejects_attachment_triple_10597() {
        let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(
            &crate::afxdp::test_fixtures::wg_outer_mtu_snapshot(),
        );
        let stale_before = WG_UNCOVERED_STALE_TOTAL.load(Ordering::Relaxed);
        // Unknown endpoint id: no attachment to revalidate against.
        let mut unknown = attached_descriptor(None, valid_inner_v4(0));
        unknown.tunnel_endpoint_id = 999;
        assert!(
            build_injected_packet(&unknown, &forwarding, wg_injected_validation(), 3).is_none(),
            "missing endpoint must fence a queued descriptor"
        );
        // Mode drift: the endpoint row is no longer WireGuard.
        let mut gre_mode = forwarding.clone();
        gre_mode
            .tunnel_endpoints
            .get_mut(&1)
            .expect("wg endpoint")
            .mode = "gre".to_string();
        assert!(
            build_injected_packet(
                &attached_descriptor(None, valid_inner_v4(0)),
                &gre_mode,
                wg_injected_validation(),
                3
            )
            .is_none(),
            "mode drift must fence a queued descriptor"
        );
        // Logical-ifindex drift: the row no longer owns the named unit.
        let mut drifted = forwarding.clone();
        drifted
            .tunnel_endpoints
            .get_mut(&1)
            .expect("wg endpoint")
            .logical_ifindex = 401;
        assert!(
            build_injected_packet(
                &attached_descriptor(None, valid_inner_v4(0)),
                &drifted,
                wg_injected_validation(),
                3
            )
            .is_none(),
            "logical-ifindex drift must fence a queued descriptor"
        );
        assert_eq!(
            WG_UNCOVERED_STALE_TOTAL.load(Ordering::Relaxed) - stale_before,
            3,
            "each attachment fence arm counts STALE exactly once"
        );
    }

    #[test]
    fn injected_entry_counts_malformed_apart_from_stale_10597() {
        let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(
            &crate::afxdp::test_fixtures::wg_outer_mtu_snapshot(),
        );
        let stale_before = WG_UNCOVERED_STALE_TOTAL.load(Ordering::Relaxed);
        let malformed_before = WG_UNCOVERED_MALFORMED_TOTAL.load(Ordering::Relaxed);
        // Bad IP version nibble.
        let mut bad_nibble = valid_inner_v4(0);
        bad_nibble[0] = 0x50;
        assert!(
            build_injected_packet(
                &attached_descriptor(None, bad_nibble),
                &forwarding,
                wg_injected_validation(),
                3
            )
            .is_none(),
            "bad nibble must reject before any policy/session work"
        );
        // Truncated inner: passes the nibble, fails trim/parse.
        assert!(
            build_injected_packet(
                &attached_descriptor(None, vec![0x45, 0, 0, 20]),
                &forwarding,
                wg_injected_validation(),
                3
            )
            .is_none(),
            "short inner must reject before any policy/session work"
        );
        assert_eq!(
            WG_UNCOVERED_MALFORMED_TOTAL.load(Ordering::Relaxed) - malformed_before,
            2,
            "each malformed inner counts MALFORMED exactly once"
        );
        assert_eq!(
            WG_UNCOVERED_STALE_TOTAL.load(Ordering::Relaxed) - stale_before,
            0,
            "malformed inners must not pollute the fence counter"
        );
    }

    #[test]
    fn enqueue_refuses_under_lock_contention_10597() {
        let queue = WgUncoveredIngressQueue::new();
        let held = queue.pending.lock().expect("test lock");
        let refused = queue
            .try_enqueue(test_descriptor(1))
            .expect_err("contended try_lock must refuse, never block");
        assert_eq!(refused.tunnel_endpoint_id, 1, "refusal hands it back");
        drop(held);
        assert!(
            queue.try_enqueue(test_descriptor(1)).is_ok(),
            "released lock admits"
        );
        assert_eq!(queue.len(), 1);
    }
}
