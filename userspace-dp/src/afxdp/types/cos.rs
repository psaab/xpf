// Class-of-Service types extracted from afxdp/types/mod.rs (Issue 68.1).
// 28 items / ~700 LOC of CoS shaper / queue / flow-fair-RR / fast-path /
// runtime types and constants.
//
// Pure relocation. The original `pub(super)` visibility (super=afxdp) is
// translated to `pub(in crate::afxdp)` so the types remain reachable from
// any afxdp/* sibling. types/mod.rs re-exports them via `pub(in crate::afxdp)
// use cos::*;` so external call sites that use `crate::afxdp::types::CoSState`
// (etc.) continue to resolve through the same import path.

use super::*;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSState {
    pub(in crate::afxdp) interfaces: FastMap<i32, CoSInterfaceConfig>,
    pub(in crate::afxdp) dscp_classifiers: FastMap<String, CoSDSCPClassifierConfig>,
    pub(in crate::afxdp) ieee8021_classifiers: FastMap<String, CoSIEEE8021ClassifierConfig>,
    pub(in crate::afxdp) dscp_rewrite_rules: FastMap<String, CoSDSCPRewriteRuleConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSInterfaceConfig {
    pub(in crate::afxdp) shaping_rate_bytes: u64,
    pub(in crate::afxdp) burst_bytes: u64,
    pub(in crate::afxdp) default_queue: u8,
    pub(in crate::afxdp) dscp_classifier: String,
    pub(in crate::afxdp) ieee8021_classifier: String,
    pub(in crate::afxdp) dscp_queue_by_dscp: [u8; 64],
    pub(in crate::afxdp) ieee8021_queue_by_pcp: [u8; 8],
    pub(in crate::afxdp) queue_by_forwarding_class: FastMap<String, u8>,
    pub(in crate::afxdp) queues: Vec<CoSQueueConfig>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSDSCPClassifierConfig {
    pub(in crate::afxdp) queue_by_dscp: FastMap<u8, u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSIEEE8021ClassifierConfig {
    pub(in crate::afxdp) queue_by_pcp: FastMap<u8, u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSDSCPRewriteRuleConfig {
    pub(in crate::afxdp) dscp_by_forwarding_class: FastMap<String, u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSQueueConfig {
    pub(in crate::afxdp) queue_id: u8,
    pub(in crate::afxdp) forwarding_class: String,
    pub(in crate::afxdp) priority: u8,
    pub(in crate::afxdp) transmit_rate_bytes: u64,
    pub(in crate::afxdp) exact: bool,
    /// #915: opt-in for exact queues to draw from root surplus
    /// tokens once their own bucket is empty. See the
    /// `CoSQueueRuntime.surplus_sharing` doc-comment for runtime
    /// semantics. Only meaningful when `exact == true` (the Go
    /// control plane warn-and-strips otherwise so the runtime
    /// never sees it set on a non-exact queue).
    pub(in crate::afxdp) surplus_sharing: bool,
    pub(in crate::afxdp) surplus_weight: u32,
    pub(in crate::afxdp) buffer_bytes: u64,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
}

pub(in crate::afxdp) const COS_FAST_QUEUE_INDEX_MISS: u16 = u16::MAX;

/// Number of SFQ flow buckets per flow-fair CoS queue.
///
/// GEMINI-NEXT.md Section 2 fairness: bumped 1024 → 4096. The metric
/// below is *per-flow* collision probability — i.e. the chance that any
/// given flow ends up sharing a bucket with at least one of the other
/// active flows in the queue, computed as `1 - (1 - 1/N)^(flows - 1)`
/// where N is `COS_FLOW_FAIR_BUCKETS`. Per-flow probability is what
/// directly governs that flow's fairness: colliding flows compete for
/// one SFQ dequeue slot and one admission-cap slice (#705).
///
/// Under typical 100E100M (Elephant + Mouse) workloads with ~200
/// concurrent flows per queue, 1024 buckets gave each flow ~17.7%
/// chance of sharing — a fairness leak even when MQFQ ordering was
/// correct. At 4096 buckets the same flow count drops the per-flow
/// probability to ~4.7%; at 64 flows it falls to ~1.5%. See #711 for
/// the original sizing analysis.
///
/// (The probability of *at least one* collision anywhere in the queue
/// — the canonical birthday-paradox metric — is much higher and stays
/// near 100% at 200 flows even at 4096 buckets. That metric is
/// fairness-irrelevant: a single colliding pair somewhere doesn't hurt
/// the other 198 flows.)
///
/// Per-queue memory overhead at 4096 buckets:
///   `flow_bucket_bytes: [u64; N]`    = 32 KB
///   `flow_bucket_head_finish_bytes: [u64; N]` = 32 KB
///   `flow_bucket_tail_finish_bytes: [u64; N]` = 32 KB
///   `flow_bucket_items: [VecDeque; N]` = 128 KB inline headers
///   `flow_rr_buckets: FlowRrRing` (`[u16; N] + head + len`) = 8 KB
/// = ~232 KB per flow-fair queue (was ~58 KB at 1024). Non-flow-fair
/// queues pay the same inline footprint but never touch the storage;
/// it stays cold. At 8 workers × 8 queues × 2 ifaces ≈ 30 MB total,
/// within the per-worker memory budget for production deployments.
pub(in crate::afxdp) const COS_FLOW_FAIR_BUCKETS: usize = 4096;

/// Pre-computed mask for `COS_FLOW_FAIR_BUCKETS`-modulo on the hot
/// path. Using a mask (rather than `%`) gives deterministic codegen
/// independent of the optimizer proving the power-of-two property at
/// each call site.
pub(in crate::afxdp) const COS_FLOW_FAIR_BUCKET_MASK: usize = COS_FLOW_FAIR_BUCKETS - 1;

/// #694: Fixed-capacity ring buffer holding the set of currently-active
/// flow bucket IDs, driving SFQ round-robin dequeue.
///
/// Storage is exactly `COS_FLOW_FAIR_BUCKETS` u16 slots — no heap
/// allocation. Replaces a prior `VecDeque<u8>` which paid allocator
/// cost per queue and capped bucket IDs at 256 (incompatible with the
/// #711 bucket-count grow). The ring is accessed exclusively through
/// the associated methods, which are all O(1).
///
/// Invariant: the ring contains no duplicate bucket IDs. The callers
/// in `cos_queue_push_*` / `cos_queue_pop_front` already gate on
/// "bucket transitioned empty → non-empty" before pushing and on
/// "bucket still non-empty" before re-enqueueing the RR cursor, so the
/// ring itself does not revalidate on the hot path.
#[derive(Debug)]
pub(in crate::afxdp) struct FlowRrRing {
    buf: [u16; COS_FLOW_FAIR_BUCKETS],
    head: u16,
    len: u16,
}

impl Default for FlowRrRing {
    fn default() -> Self {
        Self {
            buf: [0; COS_FLOW_FAIR_BUCKETS],
            head: 0,
            len: 0,
        }
    }
}

impl FlowRrRing {
    #[inline]
    pub(in crate::afxdp) fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub(in crate::afxdp) fn len(&self) -> usize {
        usize::from(self.len)
    }

    #[inline]
    pub(in crate::afxdp) fn front(&self) -> Option<u16> {
        if self.len == 0 {
            None
        } else {
            Some(self.buf[usize::from(self.head)])
        }
    }

    /// Iterate active bucket IDs in service order (head first).
    pub(in crate::afxdp) fn iter(&self) -> FlowRrRingIter<'_> {
        FlowRrRingIter {
            ring: self,
            offset: 0,
        }
    }

    // Hot-path invariant: the caller in `cos_queue_push_*` gates every
    // push on "bucket transitioned empty → non-empty", so a bucket ID
    // is in the ring at most once. The ring therefore never holds more
    // than `COS_FLOW_FAIR_BUCKETS` entries, and `len < CAP` is a
    // structural invariant — not a runtime bound we need to defend
    // against. `debug_assert!` enforces it in tests; release uses a
    // plain `+= 1` rather than `saturating_add` because a silent
    // saturation on a violated invariant would hide a real bug (the
    // push would succeed at the wrapped-buffer index and the ring
    // would lose either the new entry or an older one, depending on
    // head placement — very hard to triage).
    #[inline]
    pub(in crate::afxdp) fn push_back(&mut self, bucket: u16) {
        debug_assert!(
            usize::from(self.len) < COS_FLOW_FAIR_BUCKETS,
            "FlowRrRing overflow: len={} cap={}",
            self.len,
            COS_FLOW_FAIR_BUCKETS
        );
        let tail = (usize::from(self.head) + usize::from(self.len)) & COS_FLOW_FAIR_BUCKET_MASK;
        self.buf[tail] = bucket;
        self.len += 1;
    }

    #[inline]
    pub(in crate::afxdp) fn push_front(&mut self, bucket: u16) {
        debug_assert!(
            usize::from(self.len) < COS_FLOW_FAIR_BUCKETS,
            "FlowRrRing overflow: len={} cap={}",
            self.len,
            COS_FLOW_FAIR_BUCKETS
        );
        // head := (head + CAP - 1) mod CAP, with CAP a power of two
        // so this is a mask-only op. Avoids the `if head == 0` branch
        // on the hot path.
        self.head = ((usize::from(self.head) + COS_FLOW_FAIR_BUCKETS - 1)
            & COS_FLOW_FAIR_BUCKET_MASK) as u16;
        self.buf[usize::from(self.head)] = bucket;
        self.len += 1;
    }

    #[inline]
    pub(in crate::afxdp) fn pop_front(&mut self) -> Option<u16> {
        if self.len == 0 {
            return None;
        }
        let bucket = self.buf[usize::from(self.head)];
        self.head = ((usize::from(self.head) + 1) & COS_FLOW_FAIR_BUCKET_MASK) as u16;
        self.len -= 1;
        Some(bucket)
    }

    /// #785 Phase 3 — remove a specific bucket ID from the active
    /// set wherever it sits in the ring. Used by the MQFQ dequeue
    /// path when the bucket with the minimum virtual-finish-time
    /// (which may not be at `head`) drains to empty and must
    /// de-register from the active set.
    ///
    /// O(len) — scans the ring. `len` is bounded by the number of
    /// concurrently active flow buckets, typically 2-16 on
    /// iperf3-style workloads, up to `COS_FLOW_FAIR_BUCKETS = 1024`
    /// worst case. Returns `true` if the bucket was found and
    /// removed.
    ///
    /// Implementation: find the position via linear scan, then
    /// shift subsequent entries left (preserving head-relative
    /// order). Head stays fixed; `len` decrements. Avoids the
    /// alternative of "swap with tail then decrement" which would
    /// reorder the active set — acceptable for membership-only
    /// semantics but noisy for any future debug invariants that
    /// assume insertion-order preservation.
    pub(in crate::afxdp) fn remove(&mut self, bucket: u16) -> bool {
        if self.len == 0 {
            return false;
        }
        let head = usize::from(self.head);
        let len = usize::from(self.len);
        for i in 0..len {
            let idx = (head + i) & COS_FLOW_FAIR_BUCKET_MASK;
            if self.buf[idx] == bucket {
                // Shift subsequent entries left by one.
                for j in i..len - 1 {
                    let src = (head + j + 1) & COS_FLOW_FAIR_BUCKET_MASK;
                    let dst = (head + j) & COS_FLOW_FAIR_BUCKET_MASK;
                    self.buf[dst] = self.buf[src];
                }
                self.len -= 1;
                return true;
            }
        }
        false
    }
}

pub(in crate::afxdp) struct FlowRrRingIter<'a> {
    ring: &'a FlowRrRing,
    offset: usize,
}

#[derive(Clone)]
pub(in crate::afxdp) struct WorkerCoSQueueFastPath {
    pub(in crate::afxdp) shared_exact: bool,
    pub(in crate::afxdp) owner_worker_id: u32,
    pub(in crate::afxdp) owner_live: Option<Arc<BindingLiveState>>,
    pub(in crate::afxdp) shared_queue_lease: Option<Arc<SharedCoSQueueLease>>,
    /// #917 — cross-worker MQFQ V_min coordination structure.
    /// Allocated lazily on `shared_exact` promotion (one per
    /// shared queue, not per worker). All workers servicing the
    /// same shared queue receive the same `Arc`. `None` on
    /// non-shared queues (V_min sync only applies to
    /// `shared_exact`).
    pub(in crate::afxdp) vtime_floor: Option<Arc<SharedCoSQueueVtimeFloor>>,
}

#[derive(Clone)]
pub(in crate::afxdp) struct WorkerCoSInterfaceFastPath {
    pub(in crate::afxdp) tx_ifindex: i32,
    pub(in crate::afxdp) default_queue_index: usize,
    pub(in crate::afxdp) queue_index_by_id: [u16; 256],
    pub(in crate::afxdp) tx_owner_live: Option<Arc<BindingLiveState>>,
    pub(in crate::afxdp) shared_root_lease: Option<Arc<SharedCoSRootLease>>,
    pub(in crate::afxdp) queue_fast_path: Vec<WorkerCoSQueueFastPath>,
}

impl WorkerCoSInterfaceFastPath {
    #[inline]
    pub(in crate::afxdp) fn effective_queue_index(&self, requested_queue_id: Option<u8>) -> Option<usize> {
        if let Some(queue_id) = requested_queue_id {
            let idx = self.queue_index_by_id[usize::from(queue_id)];
            if idx != COS_FAST_QUEUE_INDEX_MISS {
                return Some(idx as usize);
            }
            return None;
        }
        (!self.queue_fast_path.is_empty()).then_some(
            self.default_queue_index
                .min(self.queue_fast_path.len().saturating_sub(1)),
        )
    }

    #[inline]
    pub(in crate::afxdp) fn queue_fast_path(
        &self,
        requested_queue_id: Option<u8>,
    ) -> Option<&WorkerCoSQueueFastPath> {
        self.effective_queue_index(requested_queue_id)
            .and_then(|idx| self.queue_fast_path.get(idx))
    }
}

pub(in crate::afxdp) struct CoSInterfaceRuntime {
    pub(in crate::afxdp) shaping_rate_bytes: u64,
    pub(in crate::afxdp) burst_bytes: u64,
    pub(in crate::afxdp) tokens: u64,
    pub(in crate::afxdp) default_queue: u8,
    pub(in crate::afxdp) nonempty_queues: usize,
    pub(in crate::afxdp) runnable_queues: usize,
    // Round-robin cursors for the two guarantee service classes. Exact and
    // non-exact guarantee queues rotate independently — the scheduler gives
    // exact queues strict priority over non-exact guarantee service (the
    // exact path runs first in `drain_shaped_tx`; non-exact only runs when
    // the exact path returns None), and within each class RR ordering is
    // preserved across calls without coupling to the other class's service
    // events. Prior to #689 both passes shared a single `guarantee_rr`
    // cursor; that had neither pure unified-RR semantics (because the exact
    // path always wins at a shared rr position) nor clean class-independent
    // semantics (because service events in one class advanced the cursor
    // seen by the other), and in pathological backlog mixes could produce
    // non-obvious skips in the non-exact rotation.
    pub(in crate::afxdp) exact_guarantee_rr: usize,
    pub(in crate::afxdp) nonexact_guarantee_rr: usize,
    // Unified-walk cursor used only by the test-only legacy selector
    // `select_cos_guarantee_batch_with_fast_path`. Gated on `cfg(test)`
    // so non-test builds of the hot CoS fast-path runtime do not pay
    // field footprint or init churn for compatibility scaffolding.
    // Separate from the production cursors above so test harnesses that
    // exercise the legacy walk do not disturb production rotation state
    // and vice versa — see the
    // `legacy_guarantee_rr_does_not_advance_class_cursors` regression
    // that pins that isolation contract.
    #[cfg(test)]
    pub(in crate::afxdp) legacy_guarantee_rr: usize,
    pub(in crate::afxdp) queues: Vec<CoSQueueRuntime>,
    pub(in crate::afxdp) queue_indices_by_priority: [Vec<usize>; COS_PRIORITY_LEVELS],
    pub(in crate::afxdp) rr_index_by_priority: [usize; COS_PRIORITY_LEVELS],
    pub(in crate::afxdp) timer_wheel: CoSTimerWheelRuntime,
}

/// #785 Phase 3 — Codex round-3 HIGH: pop→push_front round-trip
/// snapshot. Captured by `cos_queue_pop_front` immediately before
/// advancing `queue_vtime`, consumed by `cos_queue_push_front` to
/// restore pre-pop head/tail when the popped item rolls back onto
/// the queue (TX-ring-full retry path).
///
/// Without this snapshot, a push_front onto a drained bucket
/// (Rust reviewer MEDIUM #1) re-anchors head/tail to
/// `max(0, queue_vtime) + bytes`. Even if `queue_vtime` is rewound
/// symmetrically, that formula overshoots the pre-pop head by one
/// packet when the item was freshly enqueued at the pre-pop vtime:
/// the pre-pop head was `V + X`, the post-pop+rewind anchor would
/// be `V + X` (correct only by coincidence), but in the general
/// case where the item was enqueued long before pop (so head
/// trailed vtime) the rewound-anchor overshoots. Restoring the
/// snapshot exactly is the only path to true round-trip neutrality.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSQueuePopSnapshot {
    /// The bucket that was popped from. Used by
    /// `cos_queue_push_front` to verify it is restoring the SAME
    /// bucket the snapshot was captured for.
    ///
    /// **#913 contract**: a bucket mismatch on push_front is a
    /// HARD INVARIANT VIOLATION and panics via `assert!(false)`
    /// (see `cos_queue_push_front`). Stale-snapshot prevention is
    /// the responsibility of the surrounding helpers, NOT a
    /// runtime fallback:
    ///   - Batch-start clears in
    ///     `drain_exact_local_items_to_scratch_flow_fair` and
    ///     `drain_exact_prepared_items_to_scratch_flow_fair`
    ///     (the hot-path scratch builders) and in
    ///     `cos_queue_push_back` (any new enqueue invalidates
    ///     all outstanding pop snapshots).
    ///   - Drain-start clear in `cos_queue_drain_all` (#913).
    ///   - Orphan-drop cleanup at the four scratch-builder Drop
    ///     sites via `cos_queue_clear_orphan_snapshot_after_drop`
    ///     (#913 §3.4).
    /// With those in place, mismatch is believed unreachable in
    /// current code; the assert is a defensive tripwire for any
    /// future caller that introduces a new pop+drop site without
    /// the cleanup.
    pub(in crate::afxdp) bucket: u16,
    /// Bucket's HEAD finish time BEFORE the pop-time advance.
    pub(in crate::afxdp) pre_pop_head_finish: u64,
    /// Bucket's TAIL finish time BEFORE the pop-time advance.
    pub(in crate::afxdp) pre_pop_tail_finish: u64,
    /// #913 — `queue.queue_vtime` BEFORE the pop-time advance.
    /// Captured so push_front can exactly restore vtime under the
    /// new MQFQ served-finish semantics, where the advance is
    /// `max(vtime, served_finish)` (no fixed delta — symmetric
    /// rewind by `item_len` is wrong).
    pub(in crate::afxdp) pre_pop_queue_vtime: u64,
}

pub(in crate::afxdp) struct CoSQueueRuntime {
    pub(in crate::afxdp) queue_id: u8,
    pub(in crate::afxdp) priority: u8,
    pub(in crate::afxdp) transmit_rate_bytes: u64,
    pub(in crate::afxdp) exact: bool,
    /// #915: only meaningful when `exact == true`. When set, the
    /// queue (1) is NOT parked on `queue.tokens < head_len` in
    /// the exact-guarantee selector
    /// (`select_exact_cos_guarantee_queue_with_fast_path`), and
    /// (2) participates in `select_cos_surplus_batch` as if it
    /// were non-exact. The combined effect is that the queue
    /// retains its strict-priority guarantee but can also draw
    /// from root surplus tokens once its own bucket is empty.
    /// `tx_completion::apply_cos_*_result` phase-gates the
    /// `shared_queue_lease` consumption to Guarantee phase only,
    /// so surplus draws don't debit the per-queue rate cap.
    pub(in crate::afxdp) surplus_sharing: bool,
    pub(in crate::afxdp) flow_fair: bool,
    /// #785: cached shadow of `WorkerCoSQueueFastPath.shared_exact`
    /// populated by `promote_cos_queue_flow_fair`. Under the current
    /// promotion policy (`flow_fair = queue.exact && !shared_exact`),
    /// shared_exact queues are NOT on the flow-fair path — they stay
    /// on the single-FIFO-per-worker drain with no SFQ DRR ordering.
    /// The shadow exists so future cross-worker fairness work
    /// (tracked in issue #786) can branch on it.
    ///
    /// Keeping the field on the queue runtime makes the policy bit
    /// available to hot-path helpers directly from
    /// `&CoSQueueRuntime`, so current and future branching does not
    /// have to thread extra interface state through admission-path
    /// call sites or add an iface_fast lookup there.
    pub(in crate::afxdp) shared_exact: bool,
    // Per-queue hash salt mixed into `exact_cos_flow_bucket()` so the SFQ
    // bucket mapping is not an externally-probeable pure function of the
    // 5-tuple. Drawn from getrandom(2) exactly when a queue is promoted
    // onto the flow-fair path (see `ensure_cos_interface_runtime`), never
    // rotated for the lifetime of this runtime — within one instance the
    // mapping stays deterministic (required for correct enqueue/dequeue
    // bucket accounting), but is unpredictable across restarts and nodes.
    // Non-flow-fair queues keep `flow_hash_seed: 0`; the field is not read
    // on that path and the zero value preserves byte-identical legacy
    // hashing for any caller that reuses the function.
    pub(in crate::afxdp) flow_hash_seed: u64,
    pub(in crate::afxdp) surplus_weight: u32,
    pub(in crate::afxdp) surplus_deficit: u64,
    pub(in crate::afxdp) buffer_bytes: u64,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
    pub(in crate::afxdp) tokens: u64,
    pub(in crate::afxdp) last_refill_ns: u64,
    pub(in crate::afxdp) queued_bytes: u64,
    pub(in crate::afxdp) active_flow_buckets: u16,
    /// #784 diagnostic: runtime-lifetime peak of
    /// `active_flow_buckets` on this queue. Monotonically
    /// non-decreasing; resets only on daemon restart (queue
    /// runtime re-creation). Lets operators detect SFQ hash-
    /// collision regressions empirically — at steady state an
    /// iperf3 -P N workload should show
    /// `active_flow_buckets_peak >= N` if the hash is spreading
    /// correctly. Owner-only writes; the snapshot reader reads
    /// without resetting (Codex review: do NOT reset on
    /// snapshot, the doc here is the contract).
    pub(in crate::afxdp) active_flow_buckets_peak: u16,
    pub(in crate::afxdp) flow_bucket_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
    /// #785 Phase 3 — MQFQ virtual-finish-time ordering: per-bucket
    /// HEAD-packet finish time.
    ///
    /// Selection keys off this (the packet that's next to drain
    /// on this bucket), not the tail-finish, so equal-depth
    /// backlogged flows interleave `A,B,A,B` rather than burst
    /// `A,A,B,B`. Codex adversarial review of the first Phase 3
    /// revision flagged the tail-keyed selection as a correctness
    /// bug that collapsed MQFQ back to packet-count-fair for
    /// equal-byte flows.
    ///
    /// Invariants maintained by the enqueue/dequeue accounting:
    ///
    ///   * On enqueue to a previously-IDLE bucket (pre-enqueue
    ///     `flow_bucket_bytes[b] == 0`): head[b] = tail[b] =
    ///     `max(tail[b], queue.vtime) + bytes`.
    ///   * On enqueue to an ACTIVE bucket: tail[b] += bytes;
    ///     head[b] unchanged (the head packet is still the same
    ///     packet).
    ///   * On pop from a bucket that still has packets: head[b]
    ///     advances by the NEW head packet's bytes (the packet
    ///     that's now at front after pop).
    ///   * On pop that drains the bucket: head[b] = tail[b] = 0
    ///     so the next re-enqueue re-anchors at `queue.vtime`.
    ///
    /// Overflow: at 100 Gbps sustained, u64 wraps at ~46 years of
    /// uptime. No normalisation needed.
    ///
    /// Meaningful only on `flow_fair` queues.
    ///
    /// Read by `cos_queue_min_finish_bucket` as the selection key
    /// for MQFQ dequeue ordering.
    pub(in crate::afxdp) flow_bucket_head_finish_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
    /// #785 Phase 3 — MQFQ per-bucket TAIL finish: the finish
    /// time of the LAST-enqueued packet on this bucket. Used by
    /// enqueue to compute the next packet's finish (tail + bytes)
    /// and by empty-bucket detection to decide whether to
    /// re-anchor at `queue.vtime`. Distinct from head-finish —
    /// see above. Invariants: `head[b] <= tail[b]` when bucket
    /// is active; both 0 when bucket is idle.
    pub(in crate::afxdp) flow_bucket_tail_finish_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
    /// #785 Phase 3 — MQFQ queue virtual time. Updated on every
    /// dequeue to `finish[bucket]` of the drained bucket. Serves
    /// as the "catch-up anchor" in the enqueue formula:
    /// `finish[b] = max(finish[b], queue_vtime) + bytes`. A newly
    /// arriving flow bucket that's been idle re-anchors to
    /// `queue_vtime` so it starts competing at the current frontier
    /// rather than from 0 (which would let it sweep past all
    /// established flows in bounded rounds).
    ///
    /// Read by `cos_queue_min_finish_bucket` (as the `max(tail, vtime)`
    /// anchor source on idle-bucket re-entry) and updated by
    /// `cos_queue_pop_front` (+= drained bytes) and
    /// `cos_queue_push_front` (-= pushed bytes, symmetric rewind —
    /// see PR #796 Codex round-3 HIGH).
    pub(in crate::afxdp) queue_vtime: u64,
    /// #785 Phase 3 — Codex round-3 HIGH + NEW-1: LIFO stack of
    /// bucket-state snapshots captured at each `cos_queue_pop_front`.
    /// `cos_queue_push_front` pops from the back of the stack on
    /// rollback so every item in a batched multi-pop restore can
    /// restore its own pre-pop head/tail exactly — not just the most
    /// recent pop.
    ///
    /// Stack ordering:
    ///   * `cos_queue_pop_front` pushes onto the back (most recent).
    ///   * `cos_queue_push_front` pops from the back (LIFO).
    ///   * `cos_queue_push_back` clears the stack (any new enqueue
    ///     can invalidate earlier snapshots — bucket state under
    ///     those snapshots has changed).
    ///   * Flow-fair drain helpers (`drain_exact_*_flow_fair`) clear
    ///     the stack at batch start (not end) so successful-commit
    ///     chains from prior batches do not leak into the current
    ///     batch — and so the bound below holds even when a
    ///     committed submission never called push_front.
    ///   * Teardown paths (`cos_queue_drain_all` and
    ///     `reset_binding_cos_runtime`) call
    ///     `cos_queue_pop_front_no_snapshot` so that drains of
    ///     >TX_BATCH_SIZE items never grow the stack.
    ///
    /// Size bound: at most `TX_BATCH_SIZE` entries alive at once —
    /// enforced by the batch-start clear above. The hot-path drain
    /// helpers cap scratch depth at `TX_BATCH_SIZE` and push onto
    /// the stack once per pop, so ≤ `TX_BATCH_SIZE` snapshots
    /// accumulate between a drain and its paired push_front /
    /// commit. `cos_queue_pop_front` contains a `debug_assert!` to
    /// catch regressions in dev/test. Preallocated to that capacity
    /// so no hot-path realloc occurs. Each entry is 24 bytes
    /// (`CoSQueuePopSnapshot`), so the worst-case footprint is
    /// `TX_BATCH_SIZE × 24` bytes per queue — on top of the
    /// 1024-bucket bookkeeping arrays already resident in
    /// `CoSQueueRuntime`. Lowered from 256 → 64 in #920 (worst-case
    /// stack ~1.5 KB).
    ///
    /// Why a stack and not a single `Option`: earlier drained
    /// buckets in a batched rollback (e.g. N pops across M buckets,
    /// all ring-full-retried) need their exact pre-pop head/tail,
    /// not the `max(tail, queue_vtime) + bytes` re-anchor, which
    /// can overshoot when `queue_vtime` has already advanced past
    /// the earlier bucket's original head. Per-pop snapshots make
    /// every rollback item round-trip neutral.
    pub(in crate::afxdp) pop_snapshot_stack: Vec<CoSQueuePopSnapshot>,
    /// #785 Phase 3 — active-set tracking for flow-fair MQFQ.
    /// Still populated on bucket 0→>0 / >0→0 transitions so that
    /// `cos_queue_front`/`cos_queue_pop_front` can scan just the
    /// small active set rather than all 1024 SFQ buckets to find
    /// the minimum finish time. Semantically a set (membership),
    /// not a DRR ring — the ordering is governed by
    /// `flow_bucket_finish_bytes`, not ring position.
    pub(in crate::afxdp) flow_rr_buckets: FlowRrRing,
    pub(in crate::afxdp) flow_bucket_items: [VecDeque<CoSPendingTxItem>; COS_FLOW_FAIR_BUCKETS],
    pub(in crate::afxdp) runnable: bool,
    pub(in crate::afxdp) parked: bool,
    pub(in crate::afxdp) next_wakeup_tick: u64,
    pub(in crate::afxdp) wheel_level: u8,
    pub(in crate::afxdp) wheel_slot: usize,
    pub(in crate::afxdp) items: VecDeque<CoSPendingTxItem>,
    /// #774 optimization: cached count of `Local` items currently
    /// resident in `items` + `flow_bucket_items`. Incremented /
    /// decremented at every `cos_queue_push_*` and
    /// `cos_queue_pop_front` site. Replaces an O(n) scan in
    /// `cos_queue_accepts_prepared` that profiled at 3.25% CPU on
    /// the hot path at line rate. Owner-only writes; no atomic
    /// needed (same discipline as `queued_bytes`).
    pub(in crate::afxdp) local_item_count: u32,
    /// #917 — V_min cross-worker coordination. Set by
    /// `promote_cos_queue_flow_fair` when the queue is shared_exact
    /// (matches the queue.shared_exact policy). Each worker
    /// servicing this shared queue holds its own `CoSQueueRuntime`
    /// instance; all instances point to the same
    /// `SharedCoSQueueVtimeFloor` Arc but read/write their own slot
    /// indexed by `worker_id`.
    ///
    /// `None` for owner-local-exact and best-effort queues — V_min
    /// sync only applies to shared_exact.
    pub(in crate::afxdp) vtime_floor: Option<Arc<SharedCoSQueueVtimeFloor>>,
    /// Worker id of the local thread holding this `CoSQueueRuntime`
    /// instance. Used to index into `vtime_floor.slots` for publish
    /// (this worker's own slot) and to skip self in V_min reads.
    pub(in crate::afxdp) worker_id: u32,
    // #710: per-queue drop-reason counters. Single-writer (the owner
    // worker is the only code path that mutates this queue's runtime),
    // so plain `u64` is sufficient — no atomics needed on the hot path.
    // Snapshot reads happen through the `build_worker_cos_statuses`
    // path which copies the whole runtime into a status struct published
    // via `ArcSwap`, so reads are consistent without ordering discipline
    // here.
    pub(in crate::afxdp) drop_counters: CoSQueueDropCounters,
    // #751: per-queue owner-side drain telemetry. Lives inline on the
    // queue runtime so each queue's drain_latency + drain_invocations
    // are genuinely per-queue rather than a binding-wide rollup
    // surfaced under every queue row (#732). Single-writer on the
    // owner worker thread; atomic because the snapshot path reads
    // from a different thread.
    //
    // Cross-core ping-pong: this lives on the owner worker's hot
    // data, so it shares cache lines with the surrounding queue
    // state (tokens, queued_bytes, etc.). Owner-only writes to all
    // of them, so false-sharing risk is internal to the worker and
    // already accepted by the design. The #709 cache-pad isolation
    // on BindingLiveState was specifically for owner/peer split;
    // here both are owner-side so no separate pad is needed.
    pub(in crate::afxdp) owner_profile: CoSQueueOwnerProfile,
    /// #941 Work item D: counts back-to-back V_min throttle decisions
    /// (cos_queue_v_min_continue returning false → caller breaks).
    /// Resets on a successful pop (V_min check returns true). When
    /// it reaches `V_MIN_CONSECUTIVE_SKIP_HARD_CAP`, hard-cap fires:
    /// `v_min_suspended_remaining` is set to
    /// `V_MIN_SUSPENSION_BATCHES`, suspending V_min checks for that
    /// many drain calls so the worker can drain at full rate.
    pub(in crate::afxdp) consecutive_v_min_skips: u32,
    /// #941 Work item D: countdown of drain calls during which the
    /// V_min check is suspended. Decremented once per drain call
    /// after the `free_tx_frames.is_empty()` preflight passes (so a
    /// no-progress drain doesn't burn a suspension slot). When 0,
    /// V_min checks resume normally.
    pub(in crate::afxdp) v_min_suspended_remaining: u32,
    /// #941 Work item D: per-queue scratch counter for hard-cap
    /// activations. Flushed to
    /// `BindingLiveState::v_min_throttle_hard_cap_overrides` in
    /// `update_binding_debug_state` (mirrors flow_cache_collision_evictions
    /// pattern at umem.rs:2603-2607).
    pub(in crate::afxdp) v_min_hard_cap_overrides_scratch: u32,
    /// #943: per-queue scratch counter for V_min throttle decisions
    /// (i.e. `cos_queue_v_min_continue` returned `false` and the
    /// caller broke out of the drain loop without hard-cap firing).
    /// Flushed to `BindingLiveState::v_min_throttles` in
    /// `update_binding_debug_state` alongside the hard-cap counter.
    /// Together with `v_min_throttle_hard_cap_overrides` this gives
    /// operators visibility into both the regular throttle
    /// (working-as-designed fairness brake) and the hard-cap
    /// override path (escape hatch when the brake is too tight).
    pub(in crate::afxdp) v_min_throttles_scratch: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSQueueDropCounters {
    /// Flow-share admission cap exceeded; packet tail-dropped at
    /// `enqueue_cos_item`. Indicates SFQ bucket collision or a single
    /// flow attempting to occupy more than its fair share of the
    /// buffer. See #705, #711.
    pub(in crate::afxdp) admission_flow_share_drops: u64,
    /// Physical queue buffer exceeded; packet tail-dropped at
    /// `enqueue_cos_item`. Indicates buffer undersizing relative to
    /// the offered-load × RTT product. See #707.
    pub(in crate::afxdp) admission_buffer_drops: u64,
    /// Packet ECN CE-marked at admission (not dropped). Incremented
    /// when queue depth crosses the ECN threshold derived from
    /// `buffer_limit` AND the packet was already ECT(0) or ECT(1).
    /// Non-ECT packets above the threshold fall through to the drop
    /// path and are counted under the respective drop-reason field.
    /// See #718.
    pub(in crate::afxdp) admission_ecn_marked: u64,
    /// Queue parked because the interface shaping-rate token bucket is
    /// empty. Not a drop — the queue will be woken on timer-wheel tick.
    /// High count relative to serviced-batches indicates the root
    /// shaper is the limiter.
    pub(in crate::afxdp) root_token_starvation_parks: u64,
    /// Queue parked because the per-queue (exact) token bucket is
    /// empty. Not a drop — the queue will be woken when its own tokens
    /// refill. High count indicates the per-queue rate cap is the
    /// limiter for this queue.
    pub(in crate::afxdp) queue_token_starvation_parks: u64,
    /// Counts `writer.insert` returning zero on the exact-drain path —
    /// i.e. the TX ring refused the batch. NOT a packet-loss event on
    /// the exact path: FIFO variants leave items in `queue.items` and
    /// flow-fair variants explicitly restore them via
    /// `restore_exact_*_scratch_to_queue_head_flow_fair`. Frames copied
    /// into UMEM are released back to `free_tx_frames` by the caller;
    /// the packets themselves are retried on the next drain cycle.
    /// Elevated values indicate TX ring / completion reap pressure, not
    /// packet loss. See #706 / #709 for the downstream causes operators
    /// typically chase when this fires.
    pub(in crate::afxdp) tx_ring_full_submit_stalls: u64,
}

pub(in crate::afxdp) struct CoSTimerWheelRuntime {
    pub(in crate::afxdp) current_tick: u64,
    pub(in crate::afxdp) level0: [Vec<usize>; COS_TIMER_WHEEL_L0_SLOTS],
    pub(in crate::afxdp) level1: [Vec<usize>; COS_TIMER_WHEEL_L1_SLOTS],
}

/// #751: per-queue owner-side drain telemetry. Written by the owner
/// worker when a drain cycle services this specific queue (see
/// `drain_shaped_tx`'s per-queue return signal in tx.rs); read via
/// the snapshot path published through ArcSwap to Prometheus and to
/// `show class-of-service interface`.
///
/// Buckets sum to `drain_invocations` modulo the reader's scrape
/// window, pinned in
/// `queue_owner_profile_buckets_sum_to_drain_invocations`.
///
/// Single-writer. Relaxed is sufficient:
///   - The snapshot reader tolerates monotonic counter tearing
///     across the bucket array (same tolerance the BindingLiveState
///     owner_profile_owner already assumed).
///   - Prometheus scrape semantics are "best effort at scrape time".
///   - No happens-before requirement between the buckets themselves
///     or between `drain_latency_hist` and `drain_invocations` —
///     readers compute percentiles independently and a brief skew
///     just rounds the p50/p99 into an adjacent bucket.
pub(in crate::afxdp) struct CoSQueueOwnerProfile {
    pub(in crate::afxdp) drain_latency_hist: [AtomicU64; super::umem::DRAIN_HIST_BUCKETS],
    pub(in crate::afxdp) drain_invocations: AtomicU64,
    /// #760 instrumentation. Bytes the shaped drain actually
    /// submitted on behalf of this queue. Divide by a scrape window
    /// to get an observed drain rate and compare against
    /// `queue.transmit_rate_bytes`. Writer = owner worker on the
    /// single site that also decrements `queue.tokens` after a send
    /// (apply_direct_exact_send_result for exact-owner-local,
    /// apply_cos_send_result for the non-exact / shared-exact paths).
    pub(in crate::afxdp) drain_sent_bytes: AtomicU64,
    /// #760 instrumentation. Count of drain iterations where the
    /// root token gate fired (root.tokens < head_len) and the queue
    /// got parked waiting for the interface shaper to refill.
    pub(in crate::afxdp) drain_park_root_tokens: AtomicU64,
    /// #760 instrumentation. Count of drain iterations where the
    /// per-queue token gate fired (queue.tokens < head_len) and the
    /// queue got parked waiting for its own refill. A queue that
    /// sustains throughput above its configured rate with this near
    /// zero is a direct signal the gate never fired.
    pub(in crate::afxdp) drain_park_queue_tokens: AtomicU64,
}

impl CoSQueueOwnerProfile {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            drain_latency_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            drain_invocations: AtomicU64::new(0),
            drain_sent_bytes: AtomicU64::new(0),
            drain_park_root_tokens: AtomicU64::new(0),
            drain_park_queue_tokens: AtomicU64::new(0),
        }
    }
}

impl Default for CoSQueueOwnerProfile {
    fn default() -> Self {
        Self::new()
    }
}

pub(in crate::afxdp) enum CoSPendingTxItem {
    Local(TxRequest),
    Prepared(PreparedTxRequest),
}

pub(in crate::afxdp) const COS_PRIORITY_LEVELS: usize = 6;

pub(in crate::afxdp) const COS_TIMER_WHEEL_L0_SLOTS: usize = 256;

pub(in crate::afxdp) const COS_TIMER_WHEEL_L1_SLOTS: usize = 256;

impl<'a> Iterator for FlowRrRingIter<'a> {
    type Item = u16;
    #[inline]
    fn next(&mut self) -> Option<u16> {
        if self.offset >= usize::from(self.ring.len) {
            return None;
        }
        let idx = (usize::from(self.ring.head) + self.offset) & COS_FLOW_FAIR_BUCKET_MASK;
        self.offset += 1;
        Some(self.ring.buf[idx])
    }
}

// Compile-time invariants for COS_FLOW_FAIR_BUCKETS — the #711 design
// depends on both and a future refactor that changes the constant
// without checking these must fail at build time, not at runtime:
//
// 1. Power of two — `cos_flow_bucket_index` masks with
//    `COS_FLOW_FAIR_BUCKETS - 1` instead of modulo, and `FlowRrRing`
//    uses mask-based wrap math on the hot push/pop path. Without
//    power-of-two sizing that math silently indexes off the end.
// 2. Fits in `u16` — `FlowRrRing` stores bucket IDs as `u16`. A
//    larger constant would silently truncate.
const _: () = assert!(COS_FLOW_FAIR_BUCKETS.is_power_of_two());
const _: () = assert!(COS_FLOW_FAIR_BUCKETS <= u16::MAX as usize);
