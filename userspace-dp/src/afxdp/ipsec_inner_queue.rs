//! #9506 P-MECH D11: dedicated per-worker ingress transport for IPsec-inner frames.
//!
//! Rust-internal transport only: pool-slot descriptors move over per-worker
//! bounded MPSC queues from the socket server to the owning worker, and verdicts
//! return over a bounded verdict queue. Nothing here touches a socket, q0, or
//! NFQUEUE: V1 posts DENY+reason or WOULD_PERMIT verdicts only, and completions
//! carry them back to Go (outcome code 7 denied / 10 would_permit, never code 1
//! written in V1).
//!
//! Invariants (r5 §4.3 contract, D11):
//! - Slab pool, hard cap [`IPSEC_INNER_SLAB_CAP`]: socket recv writes directly
//!   into an acquired slab; no hot-path allocation once warm.
//! - Per-worker ingress queue, hard cap [`IPSEC_INNER_QUEUE_DEPTH`]: full then
//!   DROP-and-count E23; the producer never blocks.
//! - Per-flow in-flight descriptors bounded at
//!   [`IPSEC_INNER_MAX_INFLIGHT_PER_FLOW`]: refusals count E23, never grow an
//!   unbounded list.
//! - Bounded poll budget [`IPSEC_INNER_DRAIN_BUDGET`] per pass (same discipline
//!   as `WORKER_COMMAND_DRAIN_BUDGET`).
//! - Result tombstone + slab refcount: a late result is discarded by the
//!   tombstone CAS and cannot cause a second accounting event or early pool
//!   reuse (exactly-once terminal accounting).
//! - Dead workers are reaped explicitly: the generation is retired, the queue
//!   drained, and every orphan descriptor terminalized exactly once (E34).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

/// Initial S7 sizing: 512 pooled descriptors. Final value S7/T22-owned.
pub(crate) const IPSEC_INNER_SLAB_CAP: usize = 512;
/// Per-worker ingress queue depth. Final value S7/T22-owned.
pub(crate) const IPSEC_INNER_QUEUE_DEPTH: usize = 128;
/// Max descriptors one worker drains per poll pass (named bounded fraction of
/// the AF_XDP poll budget; priced by T22/S7).
pub(crate) const IPSEC_INNER_DRAIN_BUDGET: usize = 64;
/// Bounded verdict queue depth (worker -> ReinjectCore). Never silent: full
/// counts E24.
pub(crate) const IPSEC_INNER_VERDICT_QUEUE_DEPTH: usize = 256;
/// Per-flow in-flight descriptor bound. Exceeding it refuses the new frame.
pub(crate) const IPSEC_INNER_MAX_INFLIGHT_PER_FLOW: u32 = 128;
/// Slab payload capacity: must hold the largest admissible submit frame.
pub(crate) const IPSEC_INNER_SLAB_BYTES: usize = 65_535;
/// Maximum copied STN bytes retained in an immutable D11 descriptor.
pub(crate) const IPSEC_INNER_STN_MAX: usize = 64;

/// Canonical §4.1 closed u8 reason map (32-60 + legacy 5/6). Single source of
/// truth for every Rust emitter, the admit-refusal wire value, and the event
/// codec. Unknown bytes are never emitted and never decoded into a label.
pub(crate) mod reason {
    pub(crate) const LEGACY_POLICY_DENY: u8 = 5;
    pub(crate) const LEGACY_HOST_INBOUND_DENY: u8 = 6;
    pub(crate) const ZONE_UNZONED: u8 = 32;
    pub(crate) const ZONE_AMBIGUOUS: u8 = 33;
    pub(crate) const IFID_UNDERIVABLE: u8 = 34;
    pub(crate) const STALE_GENERATION: u8 = 35;
    pub(crate) const MISSING_GENERATION: u8 = 36;
    pub(crate) const ZONE_ADVISORY_MISMATCH: u8 = 37;
    pub(crate) const SCREEN_DENY: u8 = 38;
    pub(crate) const PARSE_ECN: u8 = 39;
    pub(crate) const SESSION_ALIAS: u8 = 40;
    pub(crate) const INSTALL_ROLLBACK: u8 = 41;
    pub(crate) const TCP_RST_SUPPRESSED: u8 = 42;
    pub(crate) const NAT_STAGE: u8 = 43;
    pub(crate) const HOOK_ROUTE_MISMATCH: u8 = 44;
    pub(crate) const DOMAIN_OVERLAP: u8 = 45;
    pub(crate) const OTHER_DOMAIN: u8 = 46;
    pub(crate) const WORKER_QUEUE_FULL: u8 = 47;
    pub(crate) const VERDICT_UNCERTAIN: u8 = 48;
    pub(crate) const SLAB_EXHAUSTED: u8 = 49;
    pub(crate) const LEASE_EPOCH: u8 = 50;
    pub(crate) const SUBMIT_UNAVAILABLE: u8 = 51;
    pub(crate) const EVALUATOR_UNAVAILABLE: u8 = 52;
    pub(crate) const EGRESS_RESOURCE: u8 = 53;
    pub(crate) const FRAGMENT_REFUSED: u8 = 54;
    pub(crate) const PROVENANCE: u8 = 55;
    pub(crate) const UNSUPPORTED_HOOK: u8 = 56;
    pub(crate) const VERSION_SKEW: u8 = 57;
    pub(crate) const WORKER_ORPHAN_HA: u8 = 58;
    pub(crate) const INPUT_BOUNDARY: u8 = 59;
    pub(crate) const NO_ROUTE: u8 = 60;

    /// Closed validity predicate: exactly {5, 6} ∪ {32..=60}. Anything else is
    /// a decode error (E33), never a label.
    #[inline]
    pub(crate) fn is_valid_reason_byte(b: u8) -> bool {
        b == LEGACY_POLICY_DENY || b == LEGACY_HOST_INBOUND_DENY || (32..=60).contains(&b)
    }

    /// E-row (1-37) to §4.1 reason byte. `None` for unmapped rows: every
    /// terminal emission must resolve here (K-P1 audit).
    pub(crate) fn reason_for_erow(erow: u8) -> Option<u8> {
        Some(match erow {
            1 => ZONE_UNZONED,
            2 => ZONE_AMBIGUOUS,
            3 => IFID_UNDERIVABLE,
            4 => STALE_GENERATION,
            5 => MISSING_GENERATION,
            6 => ZONE_ADVISORY_MISMATCH,
            7 => SCREEN_DENY,
            8 => PARSE_ECN,
            9 => SESSION_ALIAS,
            10 => INSTALL_ROLLBACK,
            11 | 12 | 14 => LEGACY_POLICY_DENY,
            13 => TCP_RST_SUPPRESSED,
            15 => LEGACY_HOST_INBOUND_DENY,
            16 | 17 | 18 | 36 => NAT_STAGE,
            19 => NO_ROUTE,
            20 => HOOK_ROUTE_MISMATCH,
            21 => DOMAIN_OVERLAP,
            22 => OTHER_DOMAIN,
            23 => WORKER_QUEUE_FULL,
            24 => VERDICT_UNCERTAIN,
            25 => SLAB_EXHAUSTED,
            26 => LEASE_EPOCH,
            27 => SUBMIT_UNAVAILABLE,
            28 => EVALUATOR_UNAVAILABLE,
            29 => EGRESS_RESOURCE,
            30 => FRAGMENT_REFUSED,
            31 => PROVENANCE,
            32 => UNSUPPORTED_HOOK,
            33 => VERSION_SKEW,
            34 => WORKER_ORPHAN_HA,
            35 | 37 => INPUT_BOUNDARY,
            _ => return None,
        })
    }
}

// §4.3 transport/lifecycle-owned counters (all u64). Worker-detected causes
// increment ONLY here, never in Go.
pub(crate) static IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(crate) static IPSEC_INNER_VERDICT_QUEUE_FULL_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(crate) static IPSEC_INNER_SLAB_EXHAUSTED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(crate) static IPSEC_INNER_WORKER_RETIRED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(crate) static IPSEC_INNER_WORKER_ORPHAN_REAPED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(crate) static IPSEC_INNER_ORPHAN_PROVISIONAL_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(crate) static IPSEC_INNER_HA_UNKNOWN_TOTAL: AtomicU64 = AtomicU64::new(0);

/// D11 pool-slot descriptor (Rust-internal, never on a socket). Immutable once
/// enqueued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IpsecInnerDescriptor {
    pub slab_id: u32,
    pub len: u32,
    pub tunnel_if_id: u32,
    pub stn_ifindex: u32,
    pub stn: [u8; IPSEC_INNER_STN_MAX],
    pub stn_len: u8,
    pub inner_family: u8,
    pub inner_eth_proto: u16,
    pub protocol: u8,
    pub rel_l4_offset: u16,
    pub payload_offset: u16,
    pub logical_ifindex: i32,
    pub rx_queue_index: u32,
    pub flow_tag: u64,
    pub advisory_zone_id: u16,
    pub advisory_if_id: u32,
    /// Expected route domain (`D_usp1` = kernel main table, non-VRF).
    pub expected_routing_domain: u32,
    pub expected_fib_table: u32,
    pub permit_epoch: u64,
    pub queue_number: u16,
    pub queue_epoch: u64,
    pub snapshot_generation: u64,
    pub config_generation: u64,
    pub fib_generation: u32,
    pub pmech_inventory_generation: u64,
    pub pmech_inventory_fib_generation: u32,
    pub pmech_policy_identity: [u8; 32],
    pub phase_epoch: u64,
    pub worker_set_generation: u64,
    pub request_id: u64,
    pub flags: u8,
    /// Go-stamped absolute CLOCK_MONOTONIC acknowledgement deadline.
    pub deadline_mono_ns: u64,
    /// Enqueue instant (monotonic ns) retained for non-P2 relative accounting.
    pub enqueue_ns: u64,
}

/// Worker verdict posted to the D11 verdict queue. V1 carries Deny or
/// WouldPermit only; WouldPermit is a VERDICT, not a counter (Go owns the
/// suppression counter).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IpsecInnerVerdict {
    Deny {
        request_id: u64,
        stage: &'static str,
        reason: u8,
        policy_id: u32,
    },
    WouldPermit {
        request_id: u64,
    },
}

impl IpsecInnerVerdict {
    pub(crate) fn request_id(&self) -> u64 {
        match self {
            Self::Deny { request_id, .. } | Self::WouldPermit { request_id } => *request_id,
        }
    }
}

/// Slab slot lifecycle states.
const SLOT_FREE: u8 = 0;
const SLOT_ENQUEUED: u8 = 1;
const SLOT_WORKER_OWNED: u8 = 2;
const SLOT_VERDICT_POSTED: u8 = 3;
/// A timeout/reaper may revoke accounting while the worker still holds a
/// hazard reference.  REAP_PENDING is deliberately not FREE: the bytes stay
/// pinned until the worker's late completion/ACK drops the last reference.
const SLOT_REAP_PENDING: u8 = 4;

struct SlabSlot {
    buf: Mutex<Vec<u8>>,
    state: AtomicU8,
    /// Hazard/refcount: bytes stay alive while a worker may still read them.
    refs: AtomicU32,
}

/// Rust-side slab pool with a hard cap. Sockets write directly into an
/// acquired slab; free slots are recycled without allocation.
pub(crate) struct IpsecInnerSlabPool {
    slots: Vec<SlabSlot>,
}

impl IpsecInnerSlabPool {
    pub(crate) fn new() -> Self {
        let mut slots = Vec::with_capacity(IPSEC_INNER_SLAB_CAP);
        for _ in 0..IPSEC_INNER_SLAB_CAP {
            slots.push(SlabSlot {
                buf: Mutex::new(Vec::with_capacity(IPSEC_INNER_SLAB_BYTES)),
                state: AtomicU8::new(SLOT_FREE),
                refs: AtomicU32::new(0),
            });
        }
        Self { slots }
    }

    /// Acquire a free slot into ENQUEUED (refs=1). `None` on exhaustion (E25).
    pub(crate) fn acquire(&self) -> Option<u32> {
        for (id, slot) in self.slots.iter().enumerate() {
            if slot
                .state
                .compare_exchange(SLOT_FREE, SLOT_ENQUEUED, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                slot.refs.store(1, Ordering::Release);
                return Some(id as u32);
            }
        }
        IPSEC_INNER_SLAB_EXHAUSTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Mutable access to an acquired slot's buffer (socket recv target).
    pub(crate) fn buffer(&self, slab_id: u32) -> Option<std::sync::MutexGuard<'_, Vec<u8>>> {
        self.slots.get(slab_id as usize).map(|s| {
            // Lock poison fails closed: a poisoned slab is unusable, so treat
            // as unavailable rather than crossing an inconsistent buffer.
            s.buf.lock().unwrap_or_else(|e| e.into_inner())
        })
    }

    /// Nonblocking mutable access for the socket/submit producer. Contention
    /// is treated as a slab refusal; no producer path waits on a worker-held
    /// buffer lock.
    pub(crate) fn try_buffer(
        &self,
        slab_id: u32,
    ) -> Option<std::sync::MutexGuard<'_, Vec<u8>>> {
        self.slots.get(slab_id as usize)?.buf.try_lock().ok()
    }

    /// Worker takes ownership at dequeue (ENQUEUED -> WORKER_OWNED).  The
    /// acquired reference is transferred to the worker; it is not dropped by
    /// the reaper while this state is live.
    pub(crate) fn mark_worker_owned(&self, slab_id: u32) -> bool {
        self.slots
            .get(slab_id as usize)
            .map(|s| {
                s.state
                    .compare_exchange(
                        SLOT_ENQUEUED,
                        SLOT_WORKER_OWNED,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            })
            .unwrap_or(false)
    }

    pub(crate) fn mark_verdict_posted(&self, slab_id: u32) -> bool {
        self.slots
            .get(slab_id as usize)
            .map(|s| {
                s.state
                    .compare_exchange(
                        SLOT_WORKER_OWNED,
                        SLOT_VERDICT_POSTED,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            })
            .unwrap_or(false)
    }

    /// Completion ACK: drop one ref; the slot returns to FREE only when refs
    /// reach zero. Late/duplicate ACKs are discarded (`false`), never
    /// double-freed (no early pool reuse). A REAP_PENDING slot follows the
    /// same path: the reaper has won terminal accounting, but the worker's
    /// hazard still owns the bytes.
    pub(crate) fn ack_release(&self, slab_id: u32) -> bool {
        let Some(slot) = self.slots.get(slab_id as usize) else {
            return false;
        };
        let state = slot.state.load(Ordering::Acquire);
        // Only an acquired/worker/terminal slot may release; a FREE slot ACK
        // is a late duplicate. REAP_PENDING is explicitly accepted so a late
        // worker ACK is what finally permits reuse.
        if state == SLOT_FREE {
            return false;
        }
        let prev = slot.refs.fetch_sub(1, Ordering::AcqRel);
        if prev == 0 {
            slot.refs.store(0, Ordering::Release);
            return false;
        }
        if prev == 1 {
            // Last hazard/reference: reclaim. A concurrent acquire cannot
            // observe FREE before this store, so reuse is strictly post-ACK.
            if let Ok(mut buf) = slot.buf.lock() {
                buf.clear();
            }
            slot.state.store(SLOT_FREE, Ordering::Release);
            return true;
        }
        false
    }

    /// Reaper path for a slot whose descriptor is terminalized before a
    /// worker takes ownership. ENQUEUED can be reclaimed immediately, but
    /// reclamation first enters REAP_PENDING and clears/reset refs while the
    /// slot is unavailable. Only then is FREE published; this closes the
    /// acquire-vs-clear race where a producer could otherwise reuse bytes
    /// between a FREE store and the reaper's reset.
    ///
    /// If a worker owns the slot, mark REAP_PENDING and retain its hazard ref;
    /// `ack_release` must run before the slot can become FREE.
    pub(crate) fn force_release(&self, slab_id: u32) -> bool {
        let Some(slot) = self.slots.get(slab_id as usize) else {
            return false;
        };
        let state = slot.state.load(Ordering::Acquire);
        if state == SLOT_ENQUEUED {
            if slot
                .state
                .compare_exchange(
                    SLOT_ENQUEUED,
                    SLOT_REAP_PENDING,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_err()
            {
                return false;
            }
            // The slot is not FREE while reset runs, so acquire() cannot
            // race this clear or observe a half-reset buffer.
            slot.refs.store(0, Ordering::Release);
            if let Ok(mut buf) = slot.buf.lock() {
                buf.clear();
            }
            slot.state.store(SLOT_FREE, Ordering::Release);
            return true;
        }
        if state == SLOT_WORKER_OWNED
            && slot
                .state
                .compare_exchange(
                    SLOT_WORKER_OWNED,
                    SLOT_REAP_PENDING,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            return false;
        }
        if state == SLOT_VERDICT_POSTED
            && slot
                .state
                .compare_exchange(
                    SLOT_VERDICT_POSTED,
                    SLOT_REAP_PENDING,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            return false;
        }
        false
    }
    /// Reclaim a slot after the owning worker has terminated and its join/
    /// quiescence witness proves no late ACK can touch the bytes. Unlike
    /// `force_release`, this may clear WORKER_OWNED/VERDICT_POSTED directly;
    /// callers MUST NOT invoke it while the worker can still run.
    pub(crate) fn reclaim_after_worker_death(&self, slab_id: u32) -> bool {
        let Some(slot) = self.slots.get(slab_id as usize) else {
            return false;
        };
        let state = slot.state.load(Ordering::Acquire);
        if state == SLOT_ENQUEUED {
            return self.force_release(slab_id);
        }
        if !matches!(state, SLOT_WORKER_OWNED | SLOT_VERDICT_POSTED | SLOT_REAP_PENDING) {
            return false;
        }
        if state != SLOT_REAP_PENDING
            && slot
                .state
                .compare_exchange(
                    state,
                    SLOT_REAP_PENDING,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return false;
        }
        slot.refs.store(0, Ordering::Release);
        if let Ok(mut buf) = slot.buf.lock() {
            buf.clear();
        }
        slot.state.store(SLOT_FREE, Ordering::Release);
        true
    }

    #[cfg(test)]
    pub(crate) fn free_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state.load(Ordering::Relaxed) == SLOT_FREE)
            .count()
    }
}

impl Default for IpsecInnerSlabPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-worker bounded MPSC ingress queue carrying pool-slot descriptors.
pub(crate) struct IpsecInnerIngressQueue {
    worker_id: u32,
    pending: Mutex<VecDeque<IpsecInnerDescriptor>>,
    /// Retirement fence. Set under the `pending` lock by `close_and_drain`;
    /// checked under the same lock by `try_enqueue`. Closed queues stay
    /// permanently closed: worker-ID reuse installs a fresh queue object so a
    /// pre-retirement `Arc` clone can never enqueue stale work into the new
    /// generation (ABA-safe).
    closed: AtomicBool,
}

impl IpsecInnerIngressQueue {
    pub(crate) fn new(worker_id: u32) -> Self {
        Self {
            worker_id,
            pending: Mutex::new(VecDeque::with_capacity(IPSEC_INNER_QUEUE_DEPTH)),
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) fn worker_id(&self) -> u32 {
        self.worker_id
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Try-or-drop enqueue. Full, contended, or retired (closed) -> E23
    /// DROP-and-count; the producer never waits on a worker-owned queue.
    pub(crate) fn try_enqueue(
        &self,
        desc: IpsecInnerDescriptor,
    ) -> Result<(), IpsecInnerDescriptor> {
        let Ok(mut pending) = self.pending.try_lock() else {
            IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Err(desc);
        };
        if self.closed.load(Ordering::Acquire) {
            IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Err(desc);
        }
        if pending.len() >= IPSEC_INNER_QUEUE_DEPTH {
            IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Err(desc);
        }
        pending.push_back(desc);
        Ok(())
    }

    /// Atomically close the queue and drain everything. Retirement/reaper path
    /// only; allocation is outside the worker poll hot path. Idempotent: a
    /// second call drains stragglers (normally none, since `try_enqueue`
    /// rejects after close) without reopening.
    pub(crate) fn close_and_drain(&self) -> Vec<IpsecInnerDescriptor> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        self.closed.store(true, Ordering::Release);
        pending.drain(..).collect()
    }

    /// Drain up to `budget` descriptors into a caller-owned, preallocated
    /// batch (prefix, FIFO preserved). The worker owns two such batches and
    /// alternates them; this path performs no per-poll allocation.
    pub(crate) fn drain_into(
        &self,
        scratch: &mut Vec<IpsecInnerDescriptor>,
        budget: usize,
    ) -> bool {
        debug_assert!(
            scratch.capacity() >= budget.min(IPSEC_INNER_DRAIN_BUDGET),
            "D11 worker scratch must be preallocated for its poll budget"
        );
        scratch.clear();
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let take = pending.len().min(budget);
        scratch.extend(pending.drain(..take));
        !pending.is_empty()
    }

    /// Compatibility helper for cold tests/reaper paths. Production workers
    /// MUST use [`Self::drain_into`] or [`IpsecInnerDoubleBatch`].
    #[cfg(test)]
    pub(crate) fn drain_budget(&self, budget: usize) -> Vec<IpsecInnerDescriptor> {
        let mut scratch = Vec::with_capacity(budget.min(IPSEC_INNER_DRAIN_BUDGET));
        self.drain_into(&mut scratch, budget);
        scratch
    }

    /// Drain everything (retirement/reaper path only; allocation is outside
    /// the worker poll hot path).
    pub(crate) fn drain_all(&self) -> Vec<IpsecInnerDescriptor> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.drain(..).collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Two-batch double buffer for the worker poll body. Batches are allocated
/// once at worker construction and alternated; a producer never borrows a
/// worker-owned batch, so queue drain and adjudication can be pipelined without
/// a copy or hot-loop allocation.
pub(crate) struct IpsecInnerDoubleBatch {
    batches: [Vec<IpsecInnerDescriptor>; 2],
    next: usize,
    last: usize,
}

impl IpsecInnerDoubleBatch {
    pub(crate) fn new() -> Self {
        Self {
            batches: [
                Vec::with_capacity(IPSEC_INNER_DRAIN_BUDGET),
                Vec::with_capacity(IPSEC_INNER_DRAIN_BUDGET),
            ],
            next: 0,
            last: 0,
        }
    }

    /// Fill and return the next batch. The returned slice remains valid until
    /// the next call (callers must finish adjudication before then).
    pub(crate) fn drain_next(
        &mut self,
        queue: &IpsecInnerIngressQueue,
    ) -> &[IpsecInnerDescriptor] {
        let idx = self.next;
        self.next ^= 1;
        self.last = idx;
        queue.drain_into(&mut self.batches[idx], IPSEC_INNER_DRAIN_BUDGET);
        &self.batches[idx]
    }

    pub(crate) fn current(&self) -> &[IpsecInnerDescriptor] {
        &self.batches[self.last]
    }
}

impl Default for IpsecInnerDoubleBatch {
    fn default() -> Self {
        Self::new()
    }
}
/// Bounded verdict queue (worker -> ReinjectCore). Full counts E24, never
/// silent; the affected frame terminalizes uncertain (no retry).
pub(crate) struct IpsecInnerVerdictQueue {
    pending: Mutex<VecDeque<IpsecInnerVerdict>>,
}

impl IpsecInnerVerdictQueue {
    pub(crate) fn new() -> Self {
        Self {
            pending: Mutex::new(VecDeque::with_capacity(IPSEC_INNER_VERDICT_QUEUE_DEPTH)),
        }
    }

    pub(crate) fn try_post(&self, verdict: IpsecInnerVerdict) -> Result<(), IpsecInnerVerdict> {
        let Ok(mut pending) = self.pending.try_lock() else {
            IPSEC_INNER_VERDICT_QUEUE_FULL_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Err(verdict);
        };
        if pending.len() >= IPSEC_INNER_VERDICT_QUEUE_DEPTH {
            IPSEC_INNER_VERDICT_QUEUE_FULL_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Err(verdict);
        }
        pending.push_back(verdict);
        Ok(())
    }

    pub(crate) fn drain_budget(&self, budget: usize) -> Vec<IpsecInnerVerdict> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let take = pending.len().min(budget);
        pending.drain(..take).collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
    pub(crate) fn drain_into(&self, scratch: &mut Vec<IpsecInnerVerdict>, budget: usize) -> bool {
        scratch.clear();
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let take = pending.len().min(budget);
        scratch.extend(pending.drain(..take));
        !pending.is_empty()
    }
}

impl Default for IpsecInnerVerdictQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Result tombstone states for exactly-once terminal accounting.
const TOMBSTONE_PENDING: u8 = 0;
const TOMBSTONE_COMPLETED: u8 = 1;
const TOMBSTONE_ACCOUNTED: u8 = 2;

/// Per-request terminal-accounting record. The COMPLETED->ACCOUNTED CAS wins
/// the outcome exactly once; late results observe ACCOUNTED and are discarded.
pub(crate) struct RequestTombstone {
    state: AtomicU8,
    pub request_id: u64,
    pub worker_set_generation: u64,
}

impl RequestTombstone {
    pub(crate) fn new(request_id: u64, worker_set_generation: u64) -> Self {
        Self {
            state: AtomicU8::new(TOMBSTONE_PENDING),
            request_id,
            worker_set_generation,
        }
    }

    /// Record the worker decision. `false` if already completed (stale drain
    /// won first).
    pub(crate) fn complete(&self) -> bool {
        self.state
            .compare_exchange(
                TOMBSTONE_PENDING,
                TOMBSTONE_COMPLETED,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Claim terminal accounting. `true` exactly once per request; late
    /// completions get `false` and must not emit a second event/counter.
    pub(crate) fn claim_accounting(&self) -> bool {
        self.state
            .compare_exchange(
                TOMBSTONE_COMPLETED,
                TOMBSTONE_ACCOUNTED,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Stale-drain path claims directly from PENDING (worker never decided).
    pub(crate) fn claim_stale(&self) -> bool {
        if self
            .state
            .compare_exchange(
                TOMBSTONE_PENDING,
                TOMBSTONE_COMPLETED,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return false;
        }
        self.claim_accounting()
    }

    #[cfg(test)]
    pub(crate) fn is_accounted(&self) -> bool {
        self.state.load(Ordering::Acquire) == TOMBSTONE_ACCOUNTED
    }
}

/// Provisional-handle phases (D11 journal). `Committing`/`RollingBack` are
/// nonterminal recovery tracks: the record carries a stored writer result plus
/// idempotent progress bits so a reaper resumes exactly the missing effects
/// after owner death. `UncertainDenied` is the fail-closed terminal for
/// unknown/possible emission; it is neither `Committed` nor `RolledBack`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProvisionalPhase {
    Prepared,
    WriteStarted,
    Committing,
    RollingBack,
    Committed,
    RolledBack,
    UncertainDenied,
}

impl ProvisionalPhase {
    pub(crate) fn is_terminal(self) -> bool {
        matches!(
            self,
            ProvisionalPhase::Committed
                | ProvisionalPhase::RolledBack
                | ProvisionalPhase::UncertainDenied
        )
    }
}

/// Typed writer result stored durably in the journal (F.1). `None` on the
/// record means no result was observed yet. Written is authoritative only when
/// `output_bytes` matches the stored proof's expected length
/// (`ProvisionalRecord::written_proof_valid`); anything else is fail-closed
/// uncertain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProvisionalWriteResult {
    /// All `output_bytes` reached the device; commit track only.
    Written { output_bytes: u32 },
    /// Definitive pre- or post-write no-emission; rollback track only.
    NothingWritten,
    /// Bytes are (or may be) on the device; never commit, never roll back.
    Transferred,
    /// Writer outcome unknown (partial/timeout/lost); never commit or roll back.
    Uncertain,
}

/// Token-adjacent commit proof: output slab handle, expected transformed
/// length, and the bound request. Types mirror the D11 descriptor
/// (`IpsecInnerDescriptor::{slab_id, len, request_id}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProvisionalOutputProof {
    pub slab_id: u32,
    pub expected_output_bytes: u32,
    pub request_id: u64,
}

/// Why a record entered the rollback track. Distinguishes the pre-write
/// cancel (fence refused before q0) from a definitive post-write no-emission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProvisionalRollbackCause {
    PreWriteCancel,
    DefinitiveNoWrite,
}

/// Idempotent commit/rollback progress bits (F.1). A bit is set only after
/// its effect is visible; every effect is idempotent by transaction
/// token/session id, so a reaper replays exactly the missing bits after death.
/// Commit bits live in the low half, rollback bits in the high half; the sets
/// are disjoint by construction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProvisionalProgress(u64);

impl ProvisionalProgress {
    /// Writer result persisted in the journal (shared by both tracks).
    pub(crate) const WRITE_RESULT_STORED: u64 = 1 << 0;
    /// Commit track: local pair rows committed.
    pub(crate) const LOCAL_PAIR_COMMITTED: u64 = 1 << 1;
    /// Commit track: NAT holder rows committed.
    pub(crate) const NAT_HOLDER_COMMITTED: u64 = 1 << 2;
    /// Commit track: shared forward-row committed.
    pub(crate) const SHARED_FORWARD_COMMITTED: u64 = 1 << 3;
    /// Commit track: shared reverse-row committed.
    pub(crate) const SHARED_REVERSE_COMMITTED: u64 = 1 << 4;
    /// Commit track: shared NAT-row committed.
    pub(crate) const SHARED_NAT_COMMITTED: u64 = 1 << 5;
    /// Commit track: shared forward-wire row committed.
    pub(crate) const SHARED_FORWARD_WIRE_COMMITTED: u64 = 1 << 6;
    /// Commit track: shared index row committed.
    pub(crate) const SHARED_INDEX_COMMITTED: u64 = 1 << 7;
    /// Commit track: directory published Live (last primary effect).
    pub(crate) const DIRECTORY_LIVE: u64 = 1 << 8;
    /// Commit track: reverse waiters woken.
    pub(crate) const REVERSE_WAKE_COMPLETE: u64 = 1 << 9;
    /// Commit track: Written completion queued (after primary effects).
    pub(crate) const GO_COMPLETION_QUEUED: u64 = 1 << 10;
    /// Commit track: D11 ACK observed and slab released.
    pub(crate) const D11_ACKED_AND_SLAB_RELEASED: u64 = 1 << 11;
    /// Rollback track: local capacity released.
    pub(crate) const LOCAL_CAPACITY_RELEASED: u64 = 1 << 32;
    /// Rollback track: local key released.
    pub(crate) const LOCAL_KEY_RELEASED: u64 = 1 << 33;
    /// Rollback track: local alias released.
    pub(crate) const LOCAL_ALIAS_RELEASED: u64 = 1 << 34;
    /// Rollback track: NAT reservation released.
    pub(crate) const NAT_RESERVATION_RELEASED: u64 = 1 << 35;
    /// Rollback track: NAT retained pin released.
    pub(crate) const NAT_PIN_RELEASED: u64 = 1 << 36;
    /// Rollback track: shared forward reservation released.
    pub(crate) const SHARED_FORWARD_RELEASED: u64 = 1 << 37;
    /// Rollback track: shared reverse reservation released.
    pub(crate) const SHARED_REVERSE_RELEASED: u64 = 1 << 38;
    /// Rollback track: shared NAT reservation released.
    pub(crate) const SHARED_NAT_RELEASED: u64 = 1 << 39;
    /// Rollback track: shared forward-wire reservation released.
    pub(crate) const SHARED_FORWARD_WIRE_RELEASED: u64 = 1 << 40;
    /// Rollback track: shared index reservation released.
    pub(crate) const SHARED_INDEX_RELEASED: u64 = 1 << 41;
    /// Rollback track: directory Pending claim removed.
    pub(crate) const DIRECTORY_PENDING_REMOVED: u64 = 1 << 42;
    /// Rollback track: waiters refused/recycled.
    pub(crate) const WAITERS_REFUSED: u64 = 1 << 43;
    /// Rollback track: denial/refusal completion queued (exactly once).
    pub(crate) const ROLLBACK_GO_COMPLETION_QUEUED: u64 = 1 << 44;
    /// Rollback track: D11 ACK observed and slab released.
    pub(crate) const ROLLBACK_D11_ACKED_AND_SLAB_RELEASED: u64 = 1 << 45;
    /// Uncertain track: possible-use claims marked denied.
    pub(crate) const UNCERTAIN_DIRECTORY_DENIED: u64 = 1 << 46;
    /// Uncertain track: reverse waiters refused/recycled.
    pub(crate) const UNCERTAIN_WAITERS_REFUSED: u64 = 1 << 47;
    /// Uncertain track: one uncertain completion queued.
    pub(crate) const UNCERTAIN_GO_COMPLETION_QUEUED: u64 = 1 << 48;
    /// Uncertain track: D11 ACK observed and slab released.
    pub(crate) const UNCERTAIN_D11_ACKED_AND_SLAB_RELEASED: u64 = 1 << 49;


    fn set(&mut self, bit: u64) {
        self.0 |= bit;
    }


    pub(crate) fn has(self, bit: u64) -> bool {
        self.0 & bit != 0
    }

    pub(crate) fn bits(self) -> u64 {
        self.0
    }
    fn commit_effects_complete(self) -> bool {
        [
            Self::WRITE_RESULT_STORED,
            Self::LOCAL_PAIR_COMMITTED,
            Self::NAT_HOLDER_COMMITTED,
            Self::SHARED_FORWARD_COMMITTED,
            Self::SHARED_REVERSE_COMMITTED,
            Self::SHARED_NAT_COMMITTED,
            Self::SHARED_FORWARD_WIRE_COMMITTED,
            Self::SHARED_INDEX_COMMITTED,
            Self::DIRECTORY_LIVE,
            Self::REVERSE_WAKE_COMPLETE,
            Self::GO_COMPLETION_QUEUED,
            Self::D11_ACKED_AND_SLAB_RELEASED,
        ]
        .into_iter()
        .all(|bit| self.has(bit))
    }

    fn rollback_effects_complete(self) -> bool {
        [
            Self::WRITE_RESULT_STORED,
            Self::LOCAL_CAPACITY_RELEASED,
            Self::LOCAL_KEY_RELEASED,
            Self::LOCAL_ALIAS_RELEASED,
            Self::NAT_RESERVATION_RELEASED,
            Self::NAT_PIN_RELEASED,
            Self::SHARED_FORWARD_RELEASED,
            Self::SHARED_REVERSE_RELEASED,
            Self::SHARED_NAT_RELEASED,
            Self::SHARED_FORWARD_WIRE_RELEASED,
            Self::SHARED_INDEX_RELEASED,
            Self::DIRECTORY_PENDING_REMOVED,
            Self::WAITERS_REFUSED,
            Self::ROLLBACK_GO_COMPLETION_QUEUED,
            Self::ROLLBACK_D11_ACKED_AND_SLAB_RELEASED,
        ]
        .into_iter()
        .all(|bit| self.has(bit))
    }

    fn uncertain_effects_complete(self) -> bool {
        [
            Self::UNCERTAIN_DIRECTORY_DENIED,
            Self::UNCERTAIN_WAITERS_REFUSED,
            Self::UNCERTAIN_GO_COMPLETION_QUEUED,
            Self::UNCERTAIN_D11_ACKED_AND_SLAB_RELEASED,
        ]
        .into_iter()
        .all(|bit| self.has(bit))
    }

    fn record_can_close(record: &ProvisionalRecord) -> bool {
        match record.phase {
            ProvisionalPhase::Committed => record.progress.commit_effects_complete(),
            ProvisionalPhase::RolledBack => record.progress.rollback_effects_complete(),
            ProvisionalPhase::UncertainDenied => record.progress.uncertain_effects_complete(),
            ProvisionalPhase::Prepared
            | ProvisionalPhase::WriteStarted
            | ProvisionalPhase::Committing
            | ProvisionalPhase::RollingBack => false,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProvisionalRecord {
    pub owner_worker: u32,
    pub owner_generation: u64,
    pub phase: ProvisionalPhase,
    pub request_ids: Vec<u64>,
    pub generation: u64,
    /// Commit proof (slab handle, expected length, bound request).
    pub proof: Option<ProvisionalOutputProof>,
    /// Durably stored writer result; `None` means unobserved.
    pub result: Option<ProvisionalWriteResult>,
    /// Why rollback started; `None` outside the rollback track.
    pub rollback_cause: Option<ProvisionalRollbackCause>,
    /// Idempotent commit/rollback progress; reaper replays missing bits.
    pub progress: ProvisionalProgress,
    /// Normal plan expiry (monotonic ns, protocol/session-timeout derived);
    /// retained claims/pins live until this point.
    pub plan_expiry_ns: Option<u64>,
}

impl ProvisionalRecord {
    /// Stored `Written` result whose byte count matches the stored proof.
    /// This is the ONLY evidence that authorizes the commit track; a missing
    /// proof, a byte mismatch, or any other result fails closed.
    fn proof_is_bound(&self) -> bool {
        self.proof.is_some_and(|proof| {
            proof.slab_id < IPSEC_INNER_SLAB_CAP as u32
                && proof.expected_output_bytes > 0
                && proof.expected_output_bytes <= IPSEC_INNER_SLAB_BYTES as u32
                && self.request_ids.contains(&proof.request_id)
        })
    }

    /// Stored `Written` result whose byte count matches the stored, request-
    /// bound D11 slab proof. This is the ONLY evidence that authorizes the
    /// commit track; a missing proof, invalid slab/request, byte mismatch, or
    /// any other result fails closed.
    pub(crate) fn written_proof_valid(&self) -> bool {
        self.proof_is_bound()
            && matches!(
                (self.result, self.proof),
                (
                    Some(ProvisionalWriteResult::Written { output_bytes }),
                    Some(proof)
                ) if output_bytes == proof.expected_output_bytes
            )
    }

    /// Definitive no-emission: a stored `NothingWritten` result, or no result
    /// at all in Prepared / RollingBack with a pre-write-cancel cause. A
    /// pre-write cause is not authority once WriteStarted was reached. Any
    /// observed Written/Transferred/Uncertain result defeats this.
    pub(crate) fn definitive_no_write(&self) -> bool {
        match self.result {
            Some(ProvisionalWriteResult::NothingWritten) => true,
            None => match self.phase {
                ProvisionalPhase::Prepared => {
                    self.rollback_cause != Some(ProvisionalRollbackCause::DefinitiveNoWrite)
                }
                ProvisionalPhase::RollingBack => {
                    self.rollback_cause == Some(ProvisionalRollbackCause::PreWriteCancel)
                }
                _ => false,
            },
            Some(_) => false,
        }
    }

    fn can_transition_to(&self, next: ProvisionalPhase) -> bool {
        if self.phase == next {
            return true;
        }
        if self.phase.is_terminal() {
            return false;
        }
        match (self.phase, next) {
            (ProvisionalPhase::Prepared, ProvisionalPhase::WriteStarted) => {
                self.proof_is_bound()
                    && self.plan_expiry_ns.is_some_and(|expiry| expiry > 0)
                    && self.result.is_none()
                    && self.rollback_cause.is_none()
            }
            (ProvisionalPhase::WriteStarted, ProvisionalPhase::Committing) => {
                self.written_proof_valid()
                    && self.progress.has(ProvisionalProgress::WRITE_RESULT_STORED)
            }
            (ProvisionalPhase::Prepared, ProvisionalPhase::RollingBack) => {
                self.definitive_no_write()
            }
            (ProvisionalPhase::WriteStarted, ProvisionalPhase::RollingBack) => {
                self.result == Some(ProvisionalWriteResult::NothingWritten)
                    && self.progress.has(ProvisionalProgress::WRITE_RESULT_STORED)
            }
            (ProvisionalPhase::Committing, ProvisionalPhase::Committed) => {
                self.progress.commit_effects_complete()
            }
            (ProvisionalPhase::RollingBack, ProvisionalPhase::RolledBack) => {
                self.progress.rollback_effects_complete()
            }
            (_, ProvisionalPhase::UncertainDenied) => true,
            _ => false,
        }
    }

    fn can_mark_progress(&self, bit: u64) -> bool {
        use ProvisionalProgress as P;
        let has = |required| self.progress.has(required);
        let prerequisite_present = match bit {
            P::WRITE_RESULT_STORED => self.result.is_some(),
            P::LOCAL_PAIR_COMMITTED => true,
            P::NAT_HOLDER_COMMITTED => has(P::LOCAL_PAIR_COMMITTED),
            P::SHARED_FORWARD_COMMITTED => has(P::NAT_HOLDER_COMMITTED),
            P::SHARED_REVERSE_COMMITTED => has(P::SHARED_FORWARD_COMMITTED),
            P::SHARED_NAT_COMMITTED => has(P::SHARED_REVERSE_COMMITTED),
            P::SHARED_FORWARD_WIRE_COMMITTED => has(P::SHARED_NAT_COMMITTED),
            P::SHARED_INDEX_COMMITTED => has(P::SHARED_FORWARD_WIRE_COMMITTED),
            P::DIRECTORY_LIVE => has(P::SHARED_INDEX_COMMITTED),
            P::REVERSE_WAKE_COMPLETE => has(P::DIRECTORY_LIVE),
            P::GO_COMPLETION_QUEUED => has(P::REVERSE_WAKE_COMPLETE),
            P::D11_ACKED_AND_SLAB_RELEASED => has(P::GO_COMPLETION_QUEUED),
            P::LOCAL_CAPACITY_RELEASED => true,
            P::LOCAL_KEY_RELEASED => has(P::LOCAL_CAPACITY_RELEASED),
            P::LOCAL_ALIAS_RELEASED => has(P::LOCAL_KEY_RELEASED),
            P::NAT_RESERVATION_RELEASED => has(P::LOCAL_ALIAS_RELEASED),
            P::NAT_PIN_RELEASED => has(P::NAT_RESERVATION_RELEASED),
            P::SHARED_FORWARD_RELEASED => has(P::NAT_PIN_RELEASED),
            P::SHARED_REVERSE_RELEASED => has(P::SHARED_FORWARD_RELEASED),
            P::SHARED_NAT_RELEASED => has(P::SHARED_REVERSE_RELEASED),
            P::SHARED_FORWARD_WIRE_RELEASED => has(P::SHARED_NAT_RELEASED),
            P::SHARED_INDEX_RELEASED => has(P::SHARED_FORWARD_WIRE_RELEASED),
            P::DIRECTORY_PENDING_REMOVED => has(P::SHARED_INDEX_RELEASED),
            P::WAITERS_REFUSED => has(P::DIRECTORY_PENDING_REMOVED),
            P::ROLLBACK_GO_COMPLETION_QUEUED => has(P::WAITERS_REFUSED),
            P::ROLLBACK_D11_ACKED_AND_SLAB_RELEASED => {
                has(P::ROLLBACK_GO_COMPLETION_QUEUED)
            }
            P::UNCERTAIN_DIRECTORY_DENIED => true,
            P::UNCERTAIN_WAITERS_REFUSED => has(P::UNCERTAIN_DIRECTORY_DENIED),
            P::UNCERTAIN_GO_COMPLETION_QUEUED => has(P::UNCERTAIN_WAITERS_REFUSED),
            P::UNCERTAIN_D11_ACKED_AND_SLAB_RELEASED => {
                has(P::UNCERTAIN_GO_COMPLETION_QUEUED)
            }
            _ => return false,
        };
        let phase_and_proof_valid = match bit {
            P::WRITE_RESULT_STORED => true,
            P::LOCAL_PAIR_COMMITTED
            | P::NAT_HOLDER_COMMITTED
            | P::SHARED_FORWARD_COMMITTED
            | P::SHARED_REVERSE_COMMITTED
            | P::SHARED_NAT_COMMITTED
            | P::SHARED_FORWARD_WIRE_COMMITTED
            | P::SHARED_INDEX_COMMITTED
            | P::DIRECTORY_LIVE
            | P::REVERSE_WAKE_COMPLETE
            | P::GO_COMPLETION_QUEUED
            | P::D11_ACKED_AND_SLAB_RELEASED => {
                self.phase == ProvisionalPhase::Committing && self.written_proof_valid()
            }
            P::LOCAL_CAPACITY_RELEASED
            | P::LOCAL_KEY_RELEASED
            | P::LOCAL_ALIAS_RELEASED
            | P::NAT_RESERVATION_RELEASED
            | P::NAT_PIN_RELEASED
            | P::SHARED_FORWARD_RELEASED
            | P::SHARED_REVERSE_RELEASED
            | P::SHARED_NAT_RELEASED
            | P::SHARED_FORWARD_WIRE_RELEASED
            | P::SHARED_INDEX_RELEASED
            | P::DIRECTORY_PENDING_REMOVED
            | P::WAITERS_REFUSED
            | P::ROLLBACK_GO_COMPLETION_QUEUED
            | P::ROLLBACK_D11_ACKED_AND_SLAB_RELEASED => {
                self.phase == ProvisionalPhase::RollingBack && self.definitive_no_write()
            }
            P::UNCERTAIN_DIRECTORY_DENIED
            | P::UNCERTAIN_WAITERS_REFUSED
            | P::UNCERTAIN_GO_COMPLETION_QUEUED
            | P::UNCERTAIN_D11_ACKED_AND_SLAB_RELEASED => {
                self.phase == ProvisionalPhase::UncertainDenied
            }
            _ => false,
        };
        prerequisite_present && phase_and_proof_valid
    }
}

/// Bounded shared journal for verdict-issued handles. Bounded by the
/// slab/descriptor cap; never a best-effort log. V1 carries no permits, so
/// production verdicts never register here; the journal exists for the reaper
/// contract and fault-injection cells (S9.5-removal: permit paths register on
/// the S9.5 join).
pub(crate) struct ProvisionalJournal {
    records: Mutex<HashMap<u64, ProvisionalRecord>>,
    next_token: AtomicU64,
}

impl ProvisionalJournal {
    pub(crate) fn new() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            next_token: AtomicU64::new(1),
        }
    }

    pub(crate) fn register(&self, record: ProvisionalRecord) -> Option<u64> {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if records.len() >= IPSEC_INNER_SLAB_CAP {
            return None;
        }
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        records.insert(token, record);
        Some(token)
    }

    /// Owner-only, proof-checked phase transition; `false` on wrong
    /// owner/generation, unknown token, illegal skip, or insufficient proof.
    /// Terminal state is immutable; repeating the current phase is idempotent.
    pub(crate) fn transition(
        &self,
        token: u64,
        owner_worker: u32,
        owner_generation: u64,
        phase: ProvisionalPhase,
    ) -> bool {
        self.update_owned(token, owner_worker, owner_generation, |rec| {
            if !rec.can_transition_to(phase) {
                return false;
            }
            if rec.phase == phase {
                return true;
            }
            if phase == ProvisionalPhase::RollingBack {
                let cause = rec.rollback_cause.unwrap_or_else(|| {
                    if rec.result == Some(ProvisionalWriteResult::NothingWritten) {
                        ProvisionalRollbackCause::DefinitiveNoWrite
                    } else {
                        ProvisionalRollbackCause::PreWriteCancel
                    }
                });
                if rec.rollback_cause.is_some_and(|existing| existing != cause) {
                    return false;
                }
                if rec.result.is_none() {
                    rec.result = Some(ProvisionalWriteResult::NothingWritten);
                    rec.progress.set(ProvisionalProgress::WRITE_RESULT_STORED);
                }
                rec.rollback_cause = Some(cause);
            }
            rec.phase = phase;
            true
        })
    }

    fn update_owned(
        &self,
        token: u64,
        owner_worker: u32,
        owner_generation: u64,
        update: impl FnOnce(&mut ProvisionalRecord) -> bool,
    ) -> bool {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        match records.get_mut(&token) {
            Some(rec)
                if rec.owner_worker == owner_worker && rec.owner_generation == owner_generation =>
            {
                update(rec)
            }
            _ => false,
        }
    }

    /// Store the exact D11 output slab proof once. Repeating the same proof is
    /// idempotent; a conflicting proof or wrong owner/generation is refused.
    pub(crate) fn store_proof(
        &self,
        token: u64,
        owner_worker: u32,
        owner_generation: u64,
        proof: ProvisionalOutputProof,
    ) -> bool {
        self.update_owned(token, owner_worker, owner_generation, |rec| {
            if rec.proof == Some(proof) {
                return true;
            }
            if rec.phase != ProvisionalPhase::Prepared || rec.proof.is_some() {
                return false;
            }
            rec.proof = Some(proof);
            if rec.proof_is_bound() {
                true
            } else {
                rec.proof = None;
                false
            }
        })
    }

    /// Store the writer disposition once; a conflicting second result is
    /// rejected. The progress bit follows the visible result write.
    pub(crate) fn store_write_result(
        &self,
        token: u64,
        owner_worker: u32,
        owner_generation: u64,
        result: ProvisionalWriteResult,
    ) -> bool {
        self.update_owned(token, owner_worker, owner_generation, |rec| {
            if rec.result == Some(result) {
                rec.progress.set(ProvisionalProgress::WRITE_RESULT_STORED);
                return true;
            }
            if rec.result.is_some()
                || rec.phase != ProvisionalPhase::WriteStarted
                || rec.phase.is_terminal()
            {
                return false;
            }
            rec.result = Some(result);
            rec.progress.set(ProvisionalProgress::WRITE_RESULT_STORED);
            true
        })
    }

    /// Record a pre-write cancellation or definitive writer no-write result.
    /// Pre-write cancellation persists a typed NothingWritten disposition so
    /// the rollback progress record is independently recoverable.
    pub(crate) fn store_rollback_cause(
        &self,
        token: u64,
        owner_worker: u32,
        owner_generation: u64,
        cause: ProvisionalRollbackCause,
    ) -> bool {
        self.update_owned(token, owner_worker, owner_generation, |rec| {
            if rec.rollback_cause == Some(cause) {
                return true;
            }
            if rec.rollback_cause.is_some() {
                return false;
            }
            match (rec.phase, cause, rec.result) {
                (
                    ProvisionalPhase::Prepared,
                    ProvisionalRollbackCause::PreWriteCancel,
                    None | Some(ProvisionalWriteResult::NothingWritten),
                ) => {
                    rec.result = Some(ProvisionalWriteResult::NothingWritten);
                    rec.progress.set(ProvisionalProgress::WRITE_RESULT_STORED);
                    rec.rollback_cause = Some(cause);
                    true
                }
                (
                    ProvisionalPhase::WriteStarted,
                    ProvisionalRollbackCause::DefinitiveNoWrite,
                    Some(ProvisionalWriteResult::NothingWritten),
                )
                | (
                    ProvisionalPhase::RollingBack,
                    ProvisionalRollbackCause::DefinitiveNoWrite,
                    Some(ProvisionalWriteResult::NothingWritten),
                ) => {
                    rec.rollback_cause = Some(cause);
                    true
                }
                _ => false,
            }
        })
    }

    /// Set one effect bit after that effect is externally visible. The phase,
    /// proof/result, and predecessor bit are checked; repeating an already-set
    /// bit is idempotent.
    pub(crate) fn mark_progress(
        &self,
        token: u64,
        owner_worker: u32,
        owner_generation: u64,
        bit: u64,
    ) -> bool {
        self.update_owned(token, owner_worker, owner_generation, |rec| {
            if rec.progress.has(bit) {
                return true;
            }
            if !rec.can_mark_progress(bit) {
                return false;
            }
            rec.progress.set(bit);
            true
        })
    }

    /// Save the normal plan-expiry instant before q0. Zero is rejected rather
    /// than being an ambiguous sentinel; only the same value may be replayed.
    pub(crate) fn set_plan_expiry(
        &self,
        token: u64,
        owner_worker: u32,
        owner_generation: u64,
        expiry_ns: u64,
    ) -> bool {
        self.update_owned(token, owner_worker, owner_generation, |rec| {
            if rec.plan_expiry_ns == Some(expiry_ns) {
                return true;
            }
            if rec.phase != ProvisionalPhase::Prepared
                || rec.plan_expiry_ns.is_some()
                || expiry_ns == 0
            {
                return false;
            }
            rec.plan_expiry_ns = Some(expiry_ns);
            true
        })
    }

    /// Close only after terminal effects and D11 slab ownership are accounted.
    /// Nonterminal recovery tracks remain available to their owner/reaper.
    pub(crate) fn close(&self, token: u64) -> Option<ProvisionalRecord> {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if !records
            .get(&token)
            .is_some_and(ProvisionalProgress::record_can_close)
        {
            return None;
        }
        records.remove(&token)
    }

    pub(crate) fn get(&self, token: u64, owner_worker: u32, owner_generation: u64) -> Option<ProvisionalRecord> {
        let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        records.get(&token).filter(|rec| {
            rec.owner_worker == owner_worker && rec.owner_generation == owner_generation
        }).cloned()
    }

    pub(crate) fn len(&self) -> usize {
        self.records.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for ProvisionalJournal {
    fn default() -> Self {
        Self::new()
    }
}

/// CONTROL-published worker-set authority (D9/D16 Rust side). A descriptor for
/// a retired set is stale (E4), never misrouted. Nil/unavailable authoritative
/// set is E28 (enforcing).
pub(crate) struct WorkerSetAuthority {
    generation: AtomicU64,
    live: Mutex<BTreeSet<u32>>,
    published: AtomicU8,
}

impl WorkerSetAuthority {
    pub(crate) fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            live: Mutex::new(BTreeSet::new()),
            published: AtomicU8::new(0),
        }
    }

    /// CONTROL-plane publication: new generation + live set. Only CONTROL
    /// variants publish (D12: no packet-bearing WorkerCommand).
    pub(crate) fn publish(&self, live: BTreeSet<u32>) {
        *self.live.lock().unwrap_or_else(|e| e.into_inner()) = live;
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.published.store(1, Ordering::Release);
    }

    /// CONTROL-plane startup publication for a worker joining the shared set.
    /// Idempotent for retries; packet producers only observe the resulting
    /// generation through `try_route`.
    pub(crate) fn add_worker(&self, worker: u32) {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        if live.insert(worker) {
            self.generation.fetch_add(1, Ordering::AcqRel);
        }
        self.published.store(1, Ordering::Release);
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) fn try_is_authoritative(&self) -> Result<bool, ()> {
        if self.published.load(Ordering::Acquire) == 0 {
            return Ok(false);
        }
        let live = self.live.try_lock().map_err(|_| ())?;
        Ok(!live.is_empty())
    }

    pub(crate) fn try_route(&self, flow_tag: u64) -> Result<Option<u32>, ()> {
        let live = self.live.try_lock().map_err(|_| ())?;
        if live.is_empty() {
            return Ok(None);
        }
        let idx = (flow_tag % live.len() as u64) as usize;
        Ok(live.iter().nth(idx).copied())
    }

    pub(crate) fn is_authoritative(&self) -> bool {
        self.published.load(Ordering::Acquire) != 0
            && !self.live.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
    }

    pub(crate) fn route(&self, flow_tag: u64) -> Option<u32> {
        let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        if live.is_empty() {
            return None;
        }
        let idx = (flow_tag % live.len() as u64) as usize;
        live.iter().nth(idx).copied()
    }
    pub(crate) fn is_live(&self, worker: u32, generation: u64) -> bool {
        generation == self.generation()
            && self.live.lock().unwrap_or_else(|e| e.into_inner()).contains(&worker)
    }

    /// Retire one worker: remove from the live set and bump the generation so
    /// in-flight descriptors for the old set read stale. Returns the retired
    /// generation the reaper must drain.
    pub(crate) fn retire_worker(&self, worker: u32) -> Option<u64> {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        if !live.remove(&worker) {
            return None;
        }
        IPSEC_INNER_WORKER_RETIRED_TOTAL.fetch_add(1, Ordering::Relaxed);
        let retired = self.generation.load(Ordering::Acquire);
        self.generation.fetch_add(1, Ordering::AcqRel);
        Some(retired)
    }

    #[cfg(test)]
    pub(crate) fn live_count(&self) -> usize {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for WorkerSetAuthority {
    fn default() -> Self {
        Self::new()
    }
}

/// Ingress router: per-flow in-flight bound + owner routing + stale-set fence.
pub(crate) struct IpsecInnerRouter {
    inflight_by_flow: Mutex<HashMap<u64, u32>>,
}

impl IpsecInnerRouter {
    pub(crate) fn new() -> Self {
        Self {
            inflight_by_flow: Mutex::new(HashMap::new()),
        }
    }

    /// Admit one frame for routing without waiting on authority or inflight
    /// locks. Contention is an E23/E28 refusal; callers must release the
    /// acquired slab when this returns `Err`.
    pub(crate) fn admit(
        &self,
        authority: &WorkerSetAuthority,
        flow_tag: u64,
    ) -> Result<u32, u8> {
        match authority.try_is_authoritative() {
            Ok(true) => {}
            Ok(false) | Err(()) => return Err(reason::EVALUATOR_UNAVAILABLE),
        }
        let worker = match authority.try_route(flow_tag) {
            Ok(Some(worker)) => worker,
            Ok(None) | Err(()) => return Err(reason::EVALUATOR_UNAVAILABLE),
        };
        let Ok(mut inflight) = self.inflight_by_flow.try_lock() else {
            IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Err(reason::WORKER_QUEUE_FULL);
        };
        let count = inflight.entry(flow_tag).or_insert(0);
        if *count >= IPSEC_INNER_MAX_INFLIGHT_PER_FLOW {
            IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Err(reason::WORKER_QUEUE_FULL);
        }
        *count += 1;
        Ok(worker)
    }

    pub(crate) fn release(&self, flow_tag: u64) {
        let mut inflight = self.inflight_by_flow.lock().unwrap_or_else(|e| e.into_inner());
        self.release_locked(&mut inflight, flow_tag);
    }


    fn release_locked(&self, inflight: &mut HashMap<u64, u32>, flow_tag: u64) {
        match inflight.get_mut(&flow_tag) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                inflight.remove(&flow_tag);
            }
            None => {}
        }
    }
    /// Generation fence: a descriptor stamped with any other worker-set
    /// generation than the live one is stale (E4 DROP), never evaluated.
    pub(crate) fn check_generation(
        authority: &WorkerSetAuthority,
        worker: u32,
        worker_set_generation: u64,
    ) -> Result<(), u8> {
        if authority.is_live(worker, worker_set_generation) {
            Ok(())
        } else {
            Err(reason::STALE_GENERATION)
        }
    }
}

impl Default for IpsecInnerRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Reaper terminalization of one orphaned descriptor: tombstone-claimed
/// exactly once. The worker-death join witness permits direct slot reclaim.
pub(crate) fn reap_orphan_descriptor(
    pool: &IpsecInnerSlabPool,
    tombstone: &RequestTombstone,
    desc: &IpsecInnerDescriptor,
) -> bool {
    if !tombstone.claim_stale() {
        return false;
    }

    IPSEC_INNER_WORKER_ORPHAN_REAPED_TOTAL.fetch_add(1, Ordering::Relaxed);
    pool.reclaim_after_worker_death(desc.slab_id);
    true
}

struct ActiveIpsecDescriptor {
    worker_id: u32,
    desc: IpsecInnerDescriptor,
    posted: bool,
}

/// Fixed-capacity tombstone table shared by the socket producer, worker
/// completion drain, and worker-death reaper. Its backing Vec is allocated at
/// construction; admission uses try_lock and never grows it on the hot path.
struct IpsecInnerTombstones {
    entries: Mutex<Vec<(u64, RequestTombstone)>>,
}

impl IpsecInnerTombstones {
    fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::with_capacity(IPSEC_INNER_SLAB_CAP)),
        }
    }

    fn try_insert(&self, request_id: u64, generation: u64) -> bool {
        let Ok(mut entries) = self.entries.try_lock() else {
            return false;
        };
        if request_id == 0
            || entries.iter().any(|(existing, _)| *existing == request_id)
            || entries.len() == IPSEC_INNER_SLAB_CAP
        {
            return false;
        }
        entries.push((request_id, RequestTombstone::new(request_id, generation)));
        true
    }

    fn remove(&self, request_id: u64) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(index) = entries.iter().position(|(id, _)| *id == request_id) {
            entries.swap_remove(index);
        }
    }

    fn claim_stale(&self, request_id: u64) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let Some(index) = entries.iter().position(|(id, _)| *id == request_id) else {
            return false;
        };
        if !entries[index].1.claim_stale() {
            return false;
        }
        entries.swap_remove(index);
        true
    }

    fn complete(&self, request_id: u64) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let Some(index) = entries.iter().position(|(id, _)| *id == request_id) else {
            return false;
        };
        let tombstone = &entries[index].1;
        if !tombstone.complete() || !tombstone.claim_accounting() {
            return false;
        }
        entries.swap_remove(index);
        true
    }
}

/// D11 worker/verdict join. This is the only owner of per-worker queue
/// selection and descriptor lifecycle after the socket has admitted a frame.
/// `retire_worker` drains descriptors that never reached a worker; the
/// separate `join_worker_after_termination` call is the quiescence witness
/// that permits reclaiming worker-owned slabs.
pub(crate) struct IpsecInnerWorkerTransport {
    pool: Arc<IpsecInnerSlabPool>,
    queues: Mutex<BTreeMap<u32, Arc<IpsecInnerIngressQueue>>>,
    verdicts: Arc<IpsecInnerVerdictQueue>,
    /// Fallback verdicts retain E24 results when the primary bounded queue is
    /// contended/full. Capacity matches the slab cap, so an active descriptor
    /// always has one bounded terminal handoff slot.
    uncertain: Mutex<VecDeque<IpsecInnerVerdict>>,
    authority: Arc<WorkerSetAuthority>,
    router: Arc<IpsecInnerRouter>,
    tombstones: IpsecInnerTombstones,
    active: Mutex<Vec<ActiveIpsecDescriptor>>,
    retired: Mutex<BTreeMap<u32, Option<Arc<IpsecInnerIngressQueue>>>>,
}

impl IpsecInnerWorkerTransport {
    pub(crate) fn new(worker_ids: impl IntoIterator<Item = u32>) -> Self {
        let mut queues = BTreeMap::new();
        let mut live = BTreeSet::new();
        for worker_id in worker_ids {
            if queues
                .insert(
                    worker_id,
                    Arc::new(IpsecInnerIngressQueue::new(worker_id)),
                )
                .is_none()
            {
                live.insert(worker_id);
            }
        }
        let authority = Arc::new(WorkerSetAuthority::new());
        authority.publish(live);
        Self {
            pool: Arc::new(IpsecInnerSlabPool::new()),
            queues: Mutex::new(queues),
            verdicts: Arc::new(IpsecInnerVerdictQueue::new()),
            uncertain: Mutex::new(VecDeque::with_capacity(IPSEC_INNER_SLAB_CAP)),
            authority,
            router: Arc::new(IpsecInnerRouter::new()),
            tombstones: IpsecInnerTombstones::new(),
            active: Mutex::new(Vec::with_capacity(IPSEC_INNER_SLAB_CAP)),
            retired: Mutex::new(BTreeMap::new()),
        }
    }

    /// Prepare a queue before its worker is spawned. Preparation never
    /// publishes the worker-set authority; the complete live set is published
    /// only after the bring-up readiness barrier succeeds.
    pub(crate) fn prepare_worker(&self, worker_id: u32) {
        let mut queues = self.queues.lock().unwrap_or_else(|e| e.into_inner());
        let replace = queues
            .get(&worker_id)
            .map(|queue| queue.is_closed())
            .unwrap_or(true);
        if replace {
            queues.insert(
                worker_id,
                Arc::new(IpsecInnerIngressQueue::new(worker_id)),
            );
        }
    }

    /// Publish the complete worker set after every worker reports readiness.
    /// This is the sole startup authority publication path.
    pub(crate) fn publish_workers(&self, worker_ids: impl IntoIterator<Item = u32>) {
        let live = worker_ids.into_iter().collect::<BTreeSet<_>>();
        {
            let mut queues = self.queues.lock().unwrap_or_else(|e| e.into_inner());
            for worker_id in &live {
                let replace = queues
                    .get(worker_id)
                    .map(|queue| queue.is_closed())
                    .unwrap_or(true);
                if replace {
                    queues.insert(
                        *worker_id,
                        Arc::new(IpsecInnerIngressQueue::new(*worker_id)),
                    );
                }
            }
        }
        self.authority.publish(live);
    }

    pub(crate) fn pool(&self) -> &Arc<IpsecInnerSlabPool> {
        &self.pool
    }

    pub(crate) fn authority(&self) -> &Arc<WorkerSetAuthority> {
        &self.authority
    }

    pub(crate) fn verdict_queue(&self) -> &Arc<IpsecInnerVerdictQueue> {
        &self.verdicts
    }

    /// Admit a descriptor after its socket bytes have been written to
    /// `slab_id`. All refusal paths return the slot to the pool and roll back
    /// the per-flow reservation.
    pub(crate) fn admit_descriptor(&self, desc: IpsecInnerDescriptor) -> Result<u32, u8> {
        let generation = self.authority.generation();
        if generation == 0 {
            self.pool.force_release(desc.slab_id);
            return Err(reason::EVALUATOR_UNAVAILABLE);
        }
        if desc.worker_set_generation != generation {
            self.pool.force_release(desc.slab_id);
            return Err(reason::STALE_GENERATION);
        }
        let worker = match self.router.admit(&self.authority, desc.flow_tag) {
            Ok(worker) => worker,
            Err(erow) => {
                self.pool.force_release(desc.slab_id);
                return Err(erow);
            }
        };
        if !self
            .tombstones
            .try_insert(desc.request_id, desc.worker_set_generation)
        {
            self.router.release(desc.flow_tag);
            self.pool.force_release(desc.slab_id);
            return Err(reason::LEASE_EPOCH);
        }
        let slab_id = desc.slab_id;
        let flow_tag = desc.flow_tag;
        let request_id = desc.request_id;
        let Some(queue) = self
            .queues
            .try_lock()
            .ok()
            .and_then(|queues| queues.get(&worker).cloned())
        else {
            self.tombstones.remove(request_id);
            self.router.release(flow_tag);
            self.pool.force_release(slab_id);
            return Err(reason::WORKER_QUEUE_FULL);
        };
        if desc.worker_set_generation != self.authority.generation() {
            self.tombstones.remove(request_id);
            self.router.release(flow_tag);
            self.pool.force_release(slab_id);
            return Err(reason::STALE_GENERATION);
        }
        if queue.try_enqueue(desc).is_err() {
            self.tombstones.remove(request_id);
            self.router.release(flow_tag);
            // The queue owns no reference after a failed enqueue.
            self.pool.force_release(slab_id);
            return Err(reason::WORKER_QUEUE_FULL);
        }
        Ok(worker)
    }
    /// Drain one worker's bounded ingress prefix into its reusable double
    /// batch and transfer each descriptor's hazard from ENQUEUED to
    /// WORKER_OWNED. This is the worker-side join point.
    pub(crate) fn drain_worker(
        &self,
        worker_id: u32,
        batch: &mut IpsecInnerDoubleBatch,
    ) -> usize {
        let queue = self
            .queues
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&worker_id)
            .cloned();
        let Some(queue) = queue else {
            return 0;
        };
        let _ = batch.drain_next(&queue);
        let batch_index = batch.last;
        let batch_len = batch.batches[batch_index].len();
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let mut taken = 0;
        for read_index in 0..batch_len {
            let desc = batch.batches[batch_index][read_index].clone();
            // The worker-set generation may rotate after admission but before
            // this poll. Such a descriptor is stale E4 and must never reach
            // D13/D14.
            if IpsecInnerRouter::check_generation(
                &self.authority,
                worker_id,
                desc.worker_set_generation,
            )
            .is_err()
                || !self.pool.mark_worker_owned(desc.slab_id)
            {
                self.tombstones.claim_stale(desc.request_id);
                self.pool.force_release(desc.slab_id);
                self.router.release(desc.flow_tag);
                continue;
            }
            if taken != read_index {
                batch.batches[batch_index][taken] = desc.clone();
            }
            active.push(ActiveIpsecDescriptor {
                worker_id,
                desc,
                posted: false,
            });
            taken += 1;
        }
        batch.batches[batch_index].truncate(taken);
        taken
    }
    pub(crate) fn post_worker_verdict(
        &self,
        worker_id: u32,
        verdict: IpsecInnerVerdict,
    ) -> Result<(), IpsecInnerVerdict> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = active
            .iter_mut()
            .find(|entry| entry.worker_id == worker_id && entry.desc.request_id == verdict.request_id())
        else {
            return Err(verdict);
        };
        let _ = self.pool.mark_verdict_posted(entry.desc.slab_id);
        if self.verdicts.try_post(verdict.clone()).is_err() {
            let fallback = IpsecInnerVerdict::Deny {
                request_id: verdict.request_id(),
                stage: "d11_verdict_queue_full",
                reason: reason::VERDICT_UNCERTAIN,
                policy_id: 0,
            };
            let mut uncertain = self.uncertain.lock().unwrap_or_else(|e| e.into_inner());
            debug_assert!(uncertain.len() < IPSEC_INNER_SLAB_CAP);
            uncertain.push_back(fallback);
        }
        entry.posted = true;
        Ok(())
    }

    /// Retry a worker-post failure through the guaranteed bounded E24
    /// handoff. The active descriptor is retained until the verdict drain
    /// terminalizes the matching request, so an admitted Go frame cannot
    /// remain pending after a primary-queue refusal.
    pub(crate) fn requeue_worker_verdict(
        &self,
        worker_id: u32,
        verdict: IpsecInnerVerdict,
    ) -> bool {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = active
            .iter_mut()
            .find(|entry| entry.worker_id == worker_id && entry.desc.request_id == verdict.request_id())
        else {
            return false;
        };
        let mut uncertain = self.uncertain.lock().unwrap_or_else(|e| e.into_inner());
        if uncertain.len() == IPSEC_INNER_SLAB_CAP {
            return false;
        }
        uncertain.push_back(IpsecInnerVerdict::Deny {
            request_id: verdict.request_id(),
            stage: "d11_verdict_queue_full",
            reason: reason::VERDICT_UNCERTAIN,
            policy_id: 0,
        });
        entry.posted = true;
        true
    }
    /// Drain bounded worker results into a caller-owned completion scratch.
    /// Stale verdicts from a joined worker are discarded by the tombstone and
    /// cannot release a reused slab.
    pub(crate) fn drain_verdicts_into(
        &self,
        queue_scratch: &mut Vec<IpsecInnerVerdict>,
        out: &mut Vec<IpsecInnerVerdict>,
        budget: usize,
    ) {
        self.verdicts.drain_into(queue_scratch, budget);
        if queue_scratch.len() < budget {
            if let Ok(mut uncertain) = self.uncertain.try_lock() {
                let room = budget - queue_scratch.len();
                for _ in 0..room {
                    let Some(verdict) = uncertain.pop_front() else {
                        break;
                    };
                    queue_scratch.push(verdict);
                }
            }
        }
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        for verdict in queue_scratch.drain(..) {
            let Some(index) = active
                .iter()
                .position(|entry| entry.desc.request_id == verdict.request_id())
            else {
                continue;
            };
            let entry = active.swap_remove(index);
            self.pool.ack_release(entry.desc.slab_id);
            self.router.release(entry.desc.flow_tag);
            if self.tombstones.complete(verdict.request_id()) {
                out.push(verdict);
            }
        }
    }

    fn reap_closed_queue(&self, queue: &IpsecInnerIngressQueue) -> usize {
        let mut reaped = 0;
        for desc in queue.close_and_drain() {
            if self.tombstones.claim_stale(desc.request_id) {
                self.pool.reclaim_after_worker_death(desc.slab_id);
                self.router.release(desc.flow_tag);
                reaped += 1;
            }
        }
        reaped
    }

    /// Retire a worker generation and terminalize every descriptor still
    /// ENQUEUED. Closing the exact queue Arc under its pending mutex
    /// linearizes retirement against `try_enqueue`; old producer clones are
    /// rejected forever, while worker-ID reuse installs a fresh queue Arc.
    /// WORKER_OWNED/VERDICT_POSTED descriptors remain pinned until
    /// `join_worker_after_termination` proves that no late worker ACK exists.
    pub(crate) fn retire_worker(&self, worker_id: u32) -> Option<usize> {
        self.authority.retire_worker(worker_id)?;
        let queue = self
            .queues
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&worker_id)
            .cloned();
        let reaped = queue
            .as_ref()
            .map(|queue| self.reap_closed_queue(queue))
            .unwrap_or(0);
        self.retired
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(worker_id, queue);
        Some(reaped)
    }

    /// Final worker-death join witness. Only after this call may slabs owned
    /// by the dead worker be cleared and returned to the pool. The retired
    /// queue is retained by Arc so a replacement queue for the same worker ID
    /// cannot be accidentally drained here.
    pub(crate) fn join_worker_after_termination(&self, worker_id: u32) -> usize {
        let retired_queue = self
            .retired
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&worker_id);
        let Some(retired_queue) = retired_queue else {
            return 0;
        };
        let mut reaped = 0;
        {
            let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
            let mut index = 0;
            while index < active.len() {
                if active[index].worker_id != worker_id {
                    index += 1;
                    continue;
                }
                let entry = active.swap_remove(index);
                self.tombstones.claim_stale(entry.desc.request_id);
                self.pool
                    .reclaim_after_worker_death(entry.desc.slab_id);
                self.router.release(entry.desc.flow_tag);
                reaped += 1;
            }
        }
        if let Some(queue) = retired_queue {
            reaped += self.reap_closed_queue(&queue);
        }
        reaped
    }
}

/// Reaper classification of one journal record left by a dead worker.
/// `WriteStarted` without a stored definitive result is possible emission and
/// MUST fail closed as `UncertainDenied`, never be guessed committed or safe
/// to roll back. Commit requires byte-matched `Written` proof; rollback
/// requires definitive no-write/pre-write-cancel evidence.
pub(crate) fn reap_provisional_record(record: &ProvisionalRecord) -> ProvisionalPhase {
    IPSEC_INNER_ORPHAN_PROVISIONAL_TOTAL.fetch_add(1, Ordering::Relaxed);
    if record.phase.is_terminal() {
        return record.phase;
    }
    match record.phase {
        ProvisionalPhase::Prepared => match record.result {
            None | Some(ProvisionalWriteResult::NothingWritten)
                if record.definitive_no_write() =>
            {
                ProvisionalPhase::RollingBack
            }
            _ => ProvisionalPhase::UncertainDenied,
        },
        ProvisionalPhase::WriteStarted => match record.result {
            Some(ProvisionalWriteResult::Written { .. }) if record.written_proof_valid() => {
                ProvisionalPhase::Committing
            }
            Some(ProvisionalWriteResult::NothingWritten) => ProvisionalPhase::RollingBack,
            Some(ProvisionalWriteResult::Written { .. })
            | Some(ProvisionalWriteResult::Transferred)
            | Some(ProvisionalWriteResult::Uncertain)
            | None => ProvisionalPhase::UncertainDenied,
        },
        ProvisionalPhase::Committing => {
            if record.written_proof_valid() {
                ProvisionalPhase::Committing
            } else {
                ProvisionalPhase::UncertainDenied
            }
        }
        ProvisionalPhase::RollingBack => {
            if record.definitive_no_write() {
                ProvisionalPhase::RollingBack
            } else {
                ProvisionalPhase::UncertainDenied
            }
        }
        ProvisionalPhase::Committed
        | ProvisionalPhase::RolledBack
        | ProvisionalPhase::UncertainDenied => record.phase,
    }
}

/// Drain non-P2 descriptors whose relative acknowledgement interval elapsed.
pub(crate) fn drain_timed_out(
    queue: &IpsecInnerIngressQueue,
    pool: &IpsecInnerSlabPool,
    tombstones: &BTreeMap<u64, RequestTombstone>,
    now_ns: u64,
    ack_deadline_ns: u64,
) -> Vec<u64> {
    drain_expired(queue, pool, tombstones, |desc| {
        now_ns.saturating_sub(desc.enqueue_ns) > ack_deadline_ns
    })
}

/// Drain P2 descriptors by their Go-stamped absolute CLOCK_MONOTONIC point.
/// Queue transit consumes the original budget; it is never restarted here.
pub(crate) fn drain_p2_timed_out(
    queue: &IpsecInnerIngressQueue,
    pool: &IpsecInnerSlabPool,
    tombstones: &BTreeMap<u64, RequestTombstone>,
    now_ns: u64,
) -> Vec<u64> {
    drain_expired(queue, pool, tombstones, |desc| {
        desc.deadline_mono_ns <= now_ns
    })
}

fn drain_expired<F>(
    queue: &IpsecInnerIngressQueue,
    pool: &IpsecInnerSlabPool,
    tombstones: &BTreeMap<u64, RequestTombstone>,
    is_expired: F,
) -> Vec<u64>
where
    F: Fn(&IpsecInnerDescriptor) -> bool,
{
    // Timeout/reaper runs off the poll hot path. Keep the production worker
    // drain allocation-free; this helper's bounded cold-path result is small.
    let mut batch = Vec::with_capacity(IPSEC_INNER_DRAIN_BUDGET);
    queue.drain_into(&mut batch, IPSEC_INNER_DRAIN_BUDGET);
    let mut timed_out = Vec::new();
    let mut keep = Vec::with_capacity(batch.len());
    for desc in batch {
        if !is_expired(&desc) {
            keep.push(desc);
            continue;
        }
        let claimed = tombstones
            .get(&desc.request_id)
            .map(|t| t.claim_stale())
            .unwrap_or(true);
        if claimed {
            pool.force_release(desc.slab_id);
            timed_out.push(desc.request_id);
        } else {
            keep.push(desc);
        }
    }
    // Re-queue survivors at the FRONT in order (bounded: they came from here).
    if !keep.is_empty() {
        let mut pending = queue.pending.lock().unwrap_or_else(|e| e.into_inner());
        for desc in keep.into_iter().rev() {
            pending.push_front(desc);
        }
    }
    timed_out
}

#[cfg(test)]
mod tests {
    use super::reason::*;
    use super::*;
    use std::sync::atomic::Ordering;

    fn test_desc(request_id: u64, slab_id: u32) -> IpsecInnerDescriptor {
        IpsecInnerDescriptor {
            slab_id,
            len: 64,
            tunnel_if_id: 1,
            stn_ifindex: 42,
            stn: [0; IPSEC_INNER_STN_MAX],
            stn_len: 0,
            inner_family: 2,
            inner_eth_proto: 0x0800,
            protocol: 6,
            rel_l4_offset: 20,
            payload_offset: 20,
            logical_ifindex: 42,
            rx_queue_index: 0,
            flow_tag: 99,
            advisory_zone_id: 2,
            advisory_if_id: 1,
            expected_routing_domain: 0,
            expected_fib_table: 254,
            permit_epoch: 9,
            queue_number: 1,
            queue_epoch: 11,
            snapshot_generation: 3,
            config_generation: 3,
            fib_generation: 3,
            pmech_inventory_generation: 4,
            pmech_inventory_fib_generation: 3,
            pmech_policy_identity: [0x6a; 32],
            phase_epoch: 1,
            worker_set_generation: 1,
            request_id,
            deadline_mono_ns: 0,
            enqueue_ns: 0,
            flags: 0,
        }
    }

    #[test]
    fn reason_map_is_closed_32_to_60_plus_legacy() {
        for b in 0u8..=255 {
            let valid = is_valid_reason_byte(b);
            let expect = b == 5 || b == 6 || (32..=60).contains(&b);
            assert_eq!(valid, expect, "byte {b}");
        }
        // Every E-row 1-37 resolves to exactly one reason byte (K-P1).
        for erow in 1u8..=37 {
            assert!(reason_for_erow(erow).is_some(), "E{erow} unmapped");
        }
        assert_eq!(reason_for_erow(0), None);
        assert_eq!(reason_for_erow(38), None);
        // Spot pins (S9.5-removal: E29 fires only via fault injection in V1).
        assert_eq!(reason_for_erow(21), Some(DOMAIN_OVERLAP));
        assert_eq!(reason_for_erow(22), Some(OTHER_DOMAIN));
        assert_eq!(reason_for_erow(28), Some(EVALUATOR_UNAVAILABLE));
        assert_eq!(reason_for_erow(35), Some(INPUT_BOUNDARY));
        assert_eq!(reason_for_erow(37), Some(INPUT_BOUNDARY));
        assert_eq!(reason_for_erow(19), Some(NO_ROUTE));
        // #9506 S9.4: ambiguity/alias refusal, install rollback, and validated
        // fragment refusal retain their closed E-row reason bytes.
        assert_eq!(reason_for_erow(9), Some(SESSION_ALIAS));
        assert_eq!(reason_for_erow(10), Some(INSTALL_ROLLBACK));
        assert_eq!(reason_for_erow(30), Some(FRAGMENT_REFUSED));
    }

    #[test]
    fn contended_try_enqueue_refuses_without_waiting() {
        let before = IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL.load(Ordering::Relaxed);
        let queue = IpsecInnerIngressQueue::new(0);
        let guard = queue.pending.lock().unwrap_or_else(|e| e.into_inner());
        assert!(queue.try_enqueue(test_desc(81, 0)).is_err());
        drop(guard);
        assert_eq!(
            IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL.load(Ordering::Relaxed) - before,
            1
        );
    }

    #[test]
    fn contended_try_post_refuses_without_waiting() {
        let before = IPSEC_INNER_VERDICT_QUEUE_FULL_TOTAL.load(Ordering::Relaxed);
        let queue = IpsecInnerVerdictQueue::new();
        let guard = queue.pending.lock().unwrap_or_else(|e| e.into_inner());
        assert!(queue
            .try_post(IpsecInnerVerdict::WouldPermit { request_id: 81 })
            .is_err());
        drop(guard);
        assert_eq!(
            IPSEC_INNER_VERDICT_QUEUE_FULL_TOTAL.load(Ordering::Relaxed) - before,
            1
        );
    }
    #[test]
    fn ingress_queue_full_refuses_and_counts_once() {
        let before = IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL.load(Ordering::Relaxed);
        let queue = IpsecInnerIngressQueue::new(0);
        for i in 0..IPSEC_INNER_QUEUE_DEPTH {
            queue.try_enqueue(test_desc(i as u64 + 1, 0)).expect("fits");
        }
        let refused = queue.try_enqueue(test_desc(9999, 0)).unwrap_err();
        assert_eq!(refused.request_id, 9999);
        assert_eq!(queue.len(), IPSEC_INNER_QUEUE_DEPTH);
        assert_eq!(
            IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL.load(Ordering::Relaxed) - before,
            1
        );
    }

    #[test]
    fn admission_queue_full_rolls_back_flow_and_tombstone() {
        let transport = IpsecInnerWorkerTransport::new([0]);
        let pool = transport.pool().clone();
        let generation = transport.authority().generation();
        for request_id in 1..=IPSEC_INNER_QUEUE_DEPTH as u64 {
            let slab_id = pool.acquire().expect("admission slab");
            let mut desc = test_desc(request_id, slab_id);
            desc.flow_tag = request_id;
            desc.worker_set_generation = generation;
            assert_eq!(transport.admit_descriptor(desc), Ok(0));
        }

        let refused_id = IPSEC_INNER_QUEUE_DEPTH as u64 + 1;
        let refused_flow = 900_000;
        let slab_id = pool.acquire().expect("refused admission slab");
        let mut refused = test_desc(refused_id, slab_id);
        refused.flow_tag = refused_flow;
        refused.worker_set_generation = generation;
        assert_eq!(
            transport.admit_descriptor(refused),
            Err(reason::WORKER_QUEUE_FULL)
        );
        assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP - IPSEC_INNER_QUEUE_DEPTH);
        assert!(
            !transport
                .tombstones
                .entries
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|(request_id, _)| *request_id == refused_id)
        );
        assert!(
            !transport
                .router
                .inflight_by_flow
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&refused_flow)
        );
    }

    #[test]
    fn verdict_queue_full_counts_e24_never_silent() {
        let before = IPSEC_INNER_VERDICT_QUEUE_FULL_TOTAL.load(Ordering::Relaxed);
        let queue = IpsecInnerVerdictQueue::new();
        for i in 0..IPSEC_INNER_VERDICT_QUEUE_DEPTH {
            queue
                .try_post(IpsecInnerVerdict::Deny {
                    request_id: i as u64 + 1,
                    stage: "test",
                    reason: ZONE_UNZONED,
                    policy_id: 0,
                })
                .expect("fits");
        }
        assert!(queue
            .try_post(IpsecInnerVerdict::WouldPermit { request_id: 9999 })
            .is_err());
        assert_eq!(
            IPSEC_INNER_VERDICT_QUEUE_FULL_TOTAL.load(Ordering::Relaxed) - before,
            1
        );
    }

    #[test]
    fn slab_exhaustion_counts_e25_and_recycles_without_alloc() {
        let before = IPSEC_INNER_SLAB_EXHAUSTED_TOTAL.load(Ordering::Relaxed);
        let pool = IpsecInnerSlabPool::new();
        let mut ids = Vec::new();
        for _ in 0..IPSEC_INNER_SLAB_CAP {
            ids.push(pool.acquire().expect("slab"));
        }
        assert_eq!(pool.free_count(), 0);
        assert!(pool.acquire().is_none());
        assert_eq!(
            IPSEC_INNER_SLAB_EXHAUSTED_TOTAL.load(Ordering::Relaxed) - before,
            1
        );
        // Full lifecycle: worker-owned -> verdict -> ack recycles the slot.
        let id = ids[0];
        assert!(pool.mark_worker_owned(id));
        assert!(pool.mark_verdict_posted(id));
        assert!(pool.ack_release(id));
        assert_eq!(pool.free_count(), 1);
        // Late/duplicate ACK is discarded, never double-freed.
        assert!(!pool.ack_release(id));
        assert_eq!(pool.free_count(), 1);
        // Re-acquire recycles without allocation.
        assert_eq!(pool.acquire(), Some(id));
    }

    #[test]
    fn tombstone_gives_exactly_once_accounting() {
        let t = RequestTombstone::new(1, 1);
        assert!(t.complete());
        assert!(!t.complete(), "second decision loses the CAS");
        assert!(t.claim_accounting());
        assert!(!t.claim_accounting(), "late result discarded, no double count");
        assert!(t.is_accounted());
        // Stale path claims directly from pending exactly once.
        let stale = RequestTombstone::new(2, 1);
        assert!(stale.claim_stale());
        assert!(!stale.claim_stale());
        assert!(!stale.complete());
    }

    #[test]
    fn late_completion_cannot_cause_early_pool_reuse() {
        let pool = IpsecInnerSlabPool::new();
        let id = pool.acquire().unwrap();
        let t = RequestTombstone::new(1, 1);
        assert!(pool.mark_worker_owned(id));
        // Stale drain wins while the worker still holds its hazard reference.
        assert!(t.claim_stale());
        assert!(!pool.force_release(id));
        assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP - 1);
        // Late worker completion loses accounting but releases the hazard;
        // only now may the pool publish FREE and permit reuse.
        assert!(!t.complete());
        assert!(!t.claim_accounting());
        assert!(pool.ack_release(id));
        assert!(!pool.ack_release(id));
        assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP);
        assert_eq!(pool.acquire(), Some(id));
    }

    #[test]
    fn worker_death_reaps_orphans_exactly_once() {
        let before = IPSEC_INNER_WORKER_ORPHAN_REAPED_TOTAL.load(Ordering::Relaxed);
        let pool = IpsecInnerSlabPool::new();
        let queue = IpsecInnerIngressQueue::new(3);
        let authority = WorkerSetAuthority::new();
        authority.publish(BTreeSet::from([3, 4]));
        let worker_set_generation = authority.generation();
        let id = pool.acquire().unwrap();
        let mut desc = test_desc(1, id);
        desc.worker_set_generation = worker_set_generation;
        queue.try_enqueue(desc.clone()).unwrap();
        // Worker dies: retire + drain orphans.
        let retired = authority.retire_worker(3).expect("retired");
        assert_eq!(retired, worker_set_generation);
        let orphans = queue.drain_all();
        assert_eq!(orphans.len(), 1);
        let t = RequestTombstone::new(1, worker_set_generation);
        assert!(reap_orphan_descriptor(&pool, &t, &desc));
        assert!(!reap_orphan_descriptor(&pool, &t, &desc), "exactly once");
        assert_eq!(
            IPSEC_INNER_WORKER_ORPHAN_REAPED_TOTAL.load(Ordering::Relaxed) - before,
            1
        );
        assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP);
        // No new descriptor routes to the retired worker.
        assert_eq!(authority.route(7), Some(4));
    }

    #[test]
    fn worker_death_reclaims_owned_slot_after_join_witness() {
        let pool = IpsecInnerSlabPool::new();
        let id = pool.acquire().expect("slot");
        assert!(pool.mark_worker_owned(id));
        let desc = test_desc(91, id);
        let tombstone = RequestTombstone::new(91, 1);
        assert!(reap_orphan_descriptor(&pool, &tombstone, &desc));
        assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP);
    }

    #[test]
    fn retired_set_descriptor_is_stale_never_misrouted() {
        let authority = WorkerSetAuthority::new();
        authority.publish(BTreeSet::from([0]));
        let worker_set_generation = authority.generation();
        assert!(
            IpsecInnerRouter::check_generation(&authority, 0, worker_set_generation).is_ok()
        );
        authority.retire_worker(0);
        assert_eq!(
            IpsecInnerRouter::check_generation(&authority, 0, worker_set_generation),
            Err(STALE_GENERATION)
        );
        // Unpublished / empty authority is E28, not E4.
        let empty = WorkerSetAuthority::new();
        assert!(!empty.is_authoritative());
        let router = IpsecInnerRouter::new();
        assert_eq!(
            router.admit(&empty, 7),
            Err(EVALUATOR_UNAVAILABLE)
        );
    }

    #[test]
    fn per_flow_inflight_bound_refuses_e23() {
        let before = IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL.load(Ordering::Relaxed);
        let authority = WorkerSetAuthority::new();
        authority.publish(BTreeSet::from([0]));
        let router = IpsecInnerRouter::new();
        for _ in 0..IPSEC_INNER_MAX_INFLIGHT_PER_FLOW {
            router.admit(&authority, 7).expect("fits");
        }
        assert_eq!(router.admit(&authority, 7), Err(WORKER_QUEUE_FULL));
        assert_eq!(
            IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL.load(Ordering::Relaxed) - before,
            1
        );
        router.release(7);
        router.admit(&authority, 7).expect("slot freed");
    }

    #[test]
    fn worker_transport_verdict_join_releases_slab_once() {
        let transport = IpsecInnerWorkerTransport::new([3]);
        let pool = transport.pool().clone();
        let id = pool.acquire().expect("slot");
        let generation = transport.authority().generation();
        let mut desc = test_desc(31, id);
        desc.worker_set_generation = generation;
        assert_eq!(transport.admit_descriptor(desc), Ok(3));

        let mut batch = IpsecInnerDoubleBatch::new();
        assert_eq!(transport.drain_worker(3, &mut batch), 1);
        assert!(transport
            .post_worker_verdict(3, IpsecInnerVerdict::WouldPermit { request_id: 31 })
            .is_ok());
        let mut queue_scratch = Vec::with_capacity(IPSEC_INNER_VERDICT_QUEUE_DEPTH);
        let mut out = Vec::with_capacity(IPSEC_INNER_VERDICT_QUEUE_DEPTH);
        transport.drain_verdicts_into(
            &mut queue_scratch,
            &mut out,
            IPSEC_INNER_DRAIN_BUDGET,
        );
        assert_eq!(out, vec![IpsecInnerVerdict::WouldPermit { request_id: 31 }]);
        assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP);
    }

    #[test]
    fn worker_transport_join_reclaims_only_after_retirement() {
        let transport = IpsecInnerWorkerTransport::new([4]);
        let pool = transport.pool().clone();
        let id = pool.acquire().expect("slot");
        let generation = transport.authority().generation();
        let mut desc = test_desc(32, id);
        desc.worker_set_generation = generation;
        assert_eq!(transport.admit_descriptor(desc), Ok(4));
        let mut batch = IpsecInnerDoubleBatch::new();
        assert_eq!(transport.drain_worker(4, &mut batch), 1);
        assert_eq!(transport.retire_worker(4), Some(0));
        assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP - 1);
        assert_eq!(transport.join_worker_after_termination(4), 1);
        assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP);
        assert_eq!(transport.join_worker_after_termination(4), 0);
    }

    #[test]
    fn worker_transport_retirement_closes_old_queue_before_reuse() {
        let transport = IpsecInnerWorkerTransport::new([7]);
        let pool = transport.pool().clone();
        let old_queue = transport
            .queues
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&7)
            .cloned()
            .expect("old queue");
        let old_generation = transport.authority().generation();
        let id = pool.acquire().expect("old slab");
        let mut desc = test_desc(70, id);
        desc.worker_set_generation = old_generation;
        assert_eq!(transport.admit_descriptor(desc), Ok(7));

        assert_eq!(transport.retire_worker(7), Some(1));
        assert!(old_queue.is_closed());
        assert_eq!(transport.join_worker_after_termination(7), 0);

        let late_id = pool.acquire().expect("late slab");
        let mut late = test_desc(71, late_id);
        late.worker_set_generation = old_generation;
        assert!(
            old_queue.try_enqueue(late).is_err(),
            "a producer holding the pre-retirement Arc must be rejected"
        );
        assert!(pool.force_release(late_id));

        transport.prepare_worker(7);
        transport.publish_workers([7]);
        let new_queue = transport
            .queues
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&7)
            .cloned()
            .expect("new queue");
        assert!(!new_queue.is_closed());
        assert!(!std::sync::Arc::ptr_eq(&old_queue, &new_queue));
        let stale_id = pool.acquire().expect("stale slab");
        let mut stale = test_desc(73, stale_id);
        stale.worker_set_generation = old_generation;
        assert_eq!(
            transport.admit_descriptor(stale),
            Err(reason::STALE_GENERATION)
        );
        assert_eq!(new_queue.len(), 0);
        assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP);
        let new_generation = transport.authority().generation();
        let new_id = pool.acquire().expect("new slab");
        let mut next = test_desc(72, new_id);
        next.worker_set_generation = new_generation;
        assert_eq!(transport.admit_descriptor(next), Ok(7));
        assert_eq!(new_queue.len(), 1);
    }

    #[test]
    fn worker_transport_retirement_reaps_queued_descriptors() {
        let transport = IpsecInnerWorkerTransport::new([5]);
        let pool = transport.pool().clone();
        let id = pool.acquire().expect("slot");
        let generation = transport.authority().generation();
        let mut desc = test_desc(33, id);
        desc.worker_set_generation = generation;
        assert_eq!(transport.admit_descriptor(desc), Ok(5));
        assert_eq!(transport.retire_worker(5), Some(1));
        assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP);
        assert_eq!(transport.join_worker_after_termination(5), 0);
    }

    #[test]
    fn timeout_drain_terminalizes_e24_exactly_once() {
        let pool = IpsecInnerSlabPool::new();
        let queue = IpsecInnerIngressQueue::new(0);
        let id = pool.acquire().unwrap();
        let mut desc = test_desc(1, id);
        desc.enqueue_ns = 0;
        queue.try_enqueue(desc).unwrap();
        let mut tombstones = BTreeMap::new();
        tombstones.insert(1, RequestTombstone::new(1, 1));
        let timed_out = drain_timed_out(&queue, &pool, &tombstones, 10_000, 5_000);
        assert_eq!(timed_out, vec![1]);
        assert!(queue.is_empty());
        assert!(tombstones[&1].is_accounted());
        assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP);
        // Fresh descriptor survives the relative timeout drain.
        let id2 = pool.acquire().unwrap();
        let mut fresh = test_desc(2, id2);
        fresh.enqueue_ns = 9_999;
        queue.try_enqueue(fresh).unwrap();
        let timed_out = drain_timed_out(&queue, &pool, &tombstones, 10_000, 5_000);
        assert!(timed_out.is_empty());
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn p2_timeout_uses_absolute_wire_deadline() {
        let pool = IpsecInnerSlabPool::new();
        let queue = IpsecInnerIngressQueue::new(0);
        let expired_id = pool.acquire().unwrap();
        let mut expired = test_desc(3, expired_id);
        expired.enqueue_ns = 0;
        expired.deadline_mono_ns = 9_999;
        queue.try_enqueue(expired).unwrap();
        let fresh_id = pool.acquire().unwrap();
        let mut fresh = test_desc(4, fresh_id);
        fresh.enqueue_ns = 0;
        fresh.deadline_mono_ns = 10_001;
        queue.try_enqueue(fresh).unwrap();
        let mut tombstones = BTreeMap::new();
        tombstones.insert(3, RequestTombstone::new(3, 1));
        tombstones.insert(4, RequestTombstone::new(4, 1));
        let timed_out = drain_p2_timed_out(&queue, &pool, &tombstones, 10_000);
        assert_eq!(timed_out, vec![3]);
        assert_eq!(queue.len(), 1);
        assert_eq!(pool.free_count(), IPSEC_INNER_SLAB_CAP - 1);
    }

    #[test]
    fn provisional_journal_reaper_contract() {
        let before = IPSEC_INNER_ORPHAN_PROVISIONAL_TOTAL.load(Ordering::Relaxed);
        let journal = ProvisionalJournal::new();
        let prepared = journal
            .register(ProvisionalRecord {
                owner_worker: 0,
                owner_generation: 1,
                phase: ProvisionalPhase::Prepared,
                request_ids: vec![1],
                generation: 1,
                proof: None,
                result: None,
                rollback_cause: None,
                progress: ProvisionalProgress::default(),
                plan_expiry_ns: None,
            })
            .expect("bounded");
        let started = journal
            .register(ProvisionalRecord {
                owner_worker: 0,
                owner_generation: 1,
                phase: ProvisionalPhase::WriteStarted,
                request_ids: vec![2],
                generation: 1,
                proof: None,
                result: None,
                rollback_cause: None,
                progress: ProvisionalProgress::default(),
                plan_expiry_ns: None,
            })
            .expect("bounded");
        // Wrong owner cannot transition.
        assert!(!journal.transition(prepared, 1, 1, ProvisionalPhase::Committed));
        assert!(journal.transition(prepared, 0, 1, ProvisionalPhase::Prepared));
        // Prepared enters rollback; WriteStarted without a result stays denied.
        let rec = journal.get(prepared, 0, 1).unwrap();
        assert_eq!(reap_provisional_record(&rec), ProvisionalPhase::RollingBack);
        assert!(journal.transition(prepared, 0, 1, ProvisionalPhase::RollingBack));
        assert!(
            journal.close(prepared).is_none(),
            "nonterminal rollback work must remain journaled"
        );
        let rec = journal.get(started, 0, 1).unwrap();
        assert_eq!(reap_provisional_record(&rec), ProvisionalPhase::UncertainDenied);
        assert!(journal.transition(started, 0, 1, ProvisionalPhase::UncertainDenied));
        for bit in [
            ProvisionalProgress::UNCERTAIN_DIRECTORY_DENIED,
            ProvisionalProgress::UNCERTAIN_WAITERS_REFUSED,
            ProvisionalProgress::UNCERTAIN_GO_COMPLETION_QUEUED,
            ProvisionalProgress::UNCERTAIN_D11_ACKED_AND_SLAB_RELEASED,
        ] {
            assert!(journal.mark_progress(started, 0, 1, bit));
        }
        assert!(journal.close(started).is_some());
        assert_eq!(
            IPSEC_INNER_ORPHAN_PROVISIONAL_TOTAL.load(Ordering::Relaxed) - before,
            2
        );
        assert_eq!(journal.len(), 1);
    }
    #[test]
    fn write_started_with_written_result_reaps_to_committing() {
        let mut progress = ProvisionalProgress::default();
        progress.set(ProvisionalProgress::WRITE_RESULT_STORED);
        let record = ProvisionalRecord {
            owner_worker: 0,
            owner_generation: 1,
            phase: ProvisionalPhase::WriteStarted,
            request_ids: vec![2],
            generation: 1,
            proof: Some(ProvisionalOutputProof {
                slab_id: 3,
                expected_output_bytes: 96,
                request_id: 2,
            }),
            result: Some(ProvisionalWriteResult::Written { output_bytes: 96 }),
            rollback_cause: None,
            progress,
            plan_expiry_ns: Some(100),
        };
        assert_eq!(
            reap_provisional_record(&record),
            ProvisionalPhase::Committing,
            "a reaper must resume commit effects, not declare them complete"
        );
    }


    #[test]
    fn owner_routing_is_stable_per_flow() {
        let authority = WorkerSetAuthority::new();
        authority.publish(BTreeSet::from([2, 5, 9]));
        let a = authority.route(12345).unwrap();
        for _ in 0..16 {
            assert_eq!(authority.route(12345), Some(a), "same flow same worker");
        }
    }
}
