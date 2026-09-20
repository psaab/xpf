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
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

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
/// Cross-discriminator alias bucket bound (see `session` alias index).
pub(crate) const IPSEC_INNER_ALIAS_BUCKET_BOUND: usize = 8;

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
    pub phase_epoch: u64,
    pub worker_set_generation: u64,
    pub request_id: u64,
    pub flags: u8,
    /// Enqueue instant (monotonic ns) for ack-deadline accounting.
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
}

impl IpsecInnerIngressQueue {
    pub(crate) fn new(worker_id: u32) -> Self {
        Self {
            worker_id,
            pending: Mutex::new(VecDeque::with_capacity(IPSEC_INNER_QUEUE_DEPTH)),
        }
    }

    pub(crate) fn worker_id(&self) -> u32 {
        self.worker_id
    }

    /// Try-or-drop enqueue. Full -> E23 DROP-and-count, producer never blocks.
    pub(crate) fn try_enqueue(
        &self,
        desc: IpsecInnerDescriptor,
    ) -> Result<(), IpsecInnerDescriptor> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.len() >= IPSEC_INNER_QUEUE_DEPTH {
            IPSEC_INNER_WORKER_QUEUE_FULL_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Err(desc);
        }
        pending.push_back(desc);
        Ok(())
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
}

impl IpsecInnerDoubleBatch {
    pub(crate) fn new() -> Self {
        Self {
            batches: [
                Vec::with_capacity(IPSEC_INNER_DRAIN_BUDGET),
                Vec::with_capacity(IPSEC_INNER_DRAIN_BUDGET),
            ],
            next: 0,
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
        queue.drain_into(&mut self.batches[idx], IPSEC_INNER_DRAIN_BUDGET);
        &self.batches[idx]
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
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
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

/// Provisional-handle phases (D11 journal).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProvisionalPhase {
    Prepared,
    WriteStarted,
    Committed,
    RolledBack,
}

#[derive(Clone, Debug)]
pub(crate) struct ProvisionalRecord {
    pub owner_worker: u32,
    pub owner_generation: u64,
    pub phase: ProvisionalPhase,
    pub request_ids: Vec<u64>,
    pub generation: u64,
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

    /// Owner-only transition; `false` on wrong owner/generation or unknown
    /// token.
    pub(crate) fn transition(
        &self,
        token: u64,
        owner_worker: u32,
        owner_generation: u64,
        phase: ProvisionalPhase,
    ) -> bool {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        match records.get_mut(&token) {
            Some(rec)
                if rec.owner_worker == owner_worker && rec.owner_generation == owner_generation =>
            {
                rec.phase = phase;
                true
            }
            _ => false,
        }
    }

    /// Close through the journal CAS (owner or reaper with matching identity).
    pub(crate) fn close(&self, token: u64) -> Option<ProvisionalRecord> {
        self.records.lock().unwrap_or_else(|e| e.into_inner()).remove(&token)
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

    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) fn is_authoritative(&self) -> bool {
        self.published.load(Ordering::Acquire) != 0
            && !self.live.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
    }

    pub(crate) fn is_live(&self, worker: u32, generation: u64) -> bool {
        generation == self.generation()
            && self.live.lock().unwrap_or_else(|e| e.into_inner()).contains(&worker)
    }

    /// Stable owner routing: same flow -> same live worker (per-worker FIFO
    /// preserves per-flow order). `None` when no live worker exists (E28).
    pub(crate) fn route(&self, flow_tag: u64) -> Option<u32> {
        let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        if live.is_empty() {
            return None;
        }
        let idx = (flow_tag % live.len() as u64) as usize;
        live.iter().nth(idx).copied()
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

    /// Admit one frame for routing. Full per-flow bound or no live worker
    /// refuses with the E-row reason (E23 / E28); a retired-set descriptor is
    /// the caller's stale check (E4) — never misrouted.
    pub(crate) fn admit(
        &self,
        authority: &WorkerSetAuthority,
        flow_tag: u64,
    ) -> Result<u32, u8> {
        if !authority.is_authoritative() {
            return Err(reason::EVALUATOR_UNAVAILABLE);
        }
        let Some(worker) = authority.route(flow_tag) else {
            return Err(reason::EVALUATOR_UNAVAILABLE);
        };
        let mut inflight = self.inflight_by_flow.lock().unwrap_or_else(|e| e.into_inner());
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
/// exactly once, slab force-released exactly once. Returns `true` iff this
/// call owned the terminal accounting.
pub(crate) fn reap_orphan_descriptor(
    pool: &IpsecInnerSlabPool,
    tombstone: &RequestTombstone,
    desc: &IpsecInnerDescriptor,
) -> bool {
    if !tombstone.claim_stale() {
        return false;
    }
    IPSEC_INNER_WORKER_ORPHAN_REAPED_TOTAL.fetch_add(1, Ordering::Relaxed);
    pool.force_release(desc.slab_id);
    true
}

/// Reaper handling of one journal record left by a dead worker: Prepared rolls
/// back exactly once; WriteStarted/Committed is conservatively finalized as
/// committed (q0 may have emitted) and NEVER blindly rolled back.
pub(crate) fn reap_provisional_record(record: &ProvisionalRecord) -> ProvisionalPhase {
    IPSEC_INNER_ORPHAN_PROVISIONAL_TOTAL.fetch_add(1, Ordering::Relaxed);
    match record.phase {
        ProvisionalPhase::Prepared => ProvisionalPhase::RolledBack,
        ProvisionalPhase::WriteStarted | ProvisionalPhase::Committed => {
            ProvisionalPhase::Committed
        }
        ProvisionalPhase::RolledBack => ProvisionalPhase::RolledBack,
    }
}

/// Drain descriptors whose ack deadline passed. Each terminalizes E24
/// (uncertain, no retry) exactly once via its tombstone.
/// Drain descriptors whose ack deadline passed. Each terminalizes E24
/// (uncertain, no retry) exactly once via its tombstone.
pub(crate) fn drain_timed_out(
    queue: &IpsecInnerIngressQueue,
    pool: &IpsecInnerSlabPool,
    tombstones: &BTreeMap<u64, RequestTombstone>,
    now_ns: u64,
    ack_deadline_ns: u64,
) -> Vec<u64> {
    // Timeout/reaper runs off the poll hot path. Keep the production worker
    // drain allocation-free; this helper's bounded cold-path result is small.
    let mut batch = Vec::with_capacity(IPSEC_INNER_DRAIN_BUDGET);
    queue.drain_into(&mut batch, IPSEC_INNER_DRAIN_BUDGET);
    let mut timed_out = Vec::new();
    let mut keep = Vec::with_capacity(batch.len());
    for desc in batch {
        let expired = now_ns.saturating_sub(desc.enqueue_ns) > ack_deadline_ns;
        if !expired {
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
            flow_tag: 7,
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
            phase_epoch: 1,
            worker_set_generation: 1,
            request_id,
            flags: 0,
            enqueue_ns: 0,
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
        // Fresh descriptor survives the timeout drain.
        let id2 = pool.acquire().unwrap();
        let mut fresh = test_desc(2, id2);
        fresh.enqueue_ns = 9_999;
        queue.try_enqueue(fresh).unwrap();
        let timed_out = drain_timed_out(&queue, &pool, &tombstones, 10_000, 5_000);
        assert!(timed_out.is_empty());
        assert_eq!(queue.len(), 1);
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
            })
            .expect("bounded");
        let started = journal
            .register(ProvisionalRecord {
                owner_worker: 0,
                owner_generation: 1,
                phase: ProvisionalPhase::WriteStarted,
                request_ids: vec![2],
                generation: 1,
            })
            .expect("bounded");
        // Wrong owner cannot transition.
        assert!(!journal.transition(prepared, 1, 1, ProvisionalPhase::Committed));
        assert!(journal.transition(prepared, 0, 1, ProvisionalPhase::Prepared));
        // Reaper: Prepared rolls back; WriteStarted conservatively commits.
        let rec = journal.close(prepared).unwrap();
        assert_eq!(reap_provisional_record(&rec), ProvisionalPhase::RolledBack);
        let rec = journal.close(started).unwrap();
        assert_eq!(reap_provisional_record(&rec), ProvisionalPhase::Committed);
        assert_eq!(
            IPSEC_INNER_ORPHAN_PROVISIONAL_TOTAL.load(Ordering::Relaxed) - before,
            2
        );
        assert_eq!(journal.len(), 0);
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
