use super::*;

mod mmap;
mod profile;
pub(in crate::afxdp) use profile::{OwnerProfileOwnerWrites, OwnerProfilePeerWrites};
pub(in crate::afxdp) use mmap::MmapArea;

pub(super) struct WorkerUmemInner {
    area: MmapArea,
    umem: Umem,
    total_frames: u32,
}

impl WorkerUmemInner {
    fn umem_mut(&mut self) -> &mut Umem {
        &mut self.umem
    }
}

#[derive(Clone)]
pub(super) struct WorkerUmem {
    inner: Rc<WorkerUmemInner>,
}

impl WorkerUmem {
    pub(super) fn new(total_frames: u32) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let area = MmapArea::new((total_frames as usize) * (UMEM_FRAME_SIZE as usize))?;
        let ring_size = umem_ring_size(total_frames);
        let umem_cfg = UmemConfig {
            fill_size: ring_size,
            complete_size: ring_size,
            frame_size: UMEM_FRAME_SIZE,
            headroom: UMEM_HEADROOM,
            flags: 0,
        };
        let umem = unsafe { Umem::new(umem_cfg, area.as_nonnull_slice()) }
            .map_err(|e| format!("create umem: {e}"))?;
        Ok(Self {
            inner: Rc::new(WorkerUmemInner {
                area,
                umem,
                total_frames,
            }),
        })
    }

    pub(super) fn area(&self) -> &MmapArea {
        &self.inner.area
    }

    pub(super) fn umem(&self) -> &Umem {
        &self.inner.umem
    }

    pub(super) fn umem_mut(&mut self) -> &mut Umem {
        Rc::get_mut(&mut self.inner)
            .expect("single-owner umem")
            .umem_mut()
    }

    pub(super) fn total_frames(&self) -> u32 {
        self.inner.total_frames
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn shares_allocation_with(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }

    pub(super) fn allocation_ptr(&self) -> *const WorkerUmemInner {
        Rc::as_ptr(&self.inner)
    }
}

pub(super) struct WorkerUmemPool {
    pub(super) umem: WorkerUmem,
    pub(super) free_frames: VecDeque<u64>,
}

impl WorkerUmemPool {
    pub(super) fn new(total_frames: u32) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let umem = WorkerUmem::new(total_frames.max(1))?;
        let mut free_frames = VecDeque::with_capacity(total_frames.max(1) as usize);
        for idx in 0..total_frames.max(1) {
            if let Some(frame) = umem.umem().frame(BufIdx(idx)) {
                free_frames.push_back(frame.offset);
            }
        }
        Ok(Self { umem, free_frames })
    }
}

/// Hard capacity of the per-binding redirect inbox
/// (`BindingLiveState::pending_tx`). Sized to cover the highest expected
/// soft cap produced by `pending_tx_capacity()` in prod
/// (`ring_entries = 2048` → `2 * ring_entries = 4096`). The MPSC ring is
/// allocated once at `BindingLiveState::new()` with this capacity, then
/// the soft cap from `set_max_pending_tx()` gates admissions inside
/// `enqueue_tx` / `enqueue_tx_owned`. If a caller ever requests a soft
/// cap larger than the hard cap, the effective cap clamps here and
/// excess pushes drop with a `redirect_inbox_overflow_drops` counter bump.
pub(super) const PENDING_TX_INBOX_HARD_CAP: usize = 4096;

/// #709: owner-drain / redirect-acquire latency histogram bucket count.
///
/// Bucket layout (produced by `bucket_index_for_ns`):
/// - Bucket 0: `[0, 1024 ns)` — the sub-1 µs catch-all.
/// - Bucket 1: `[1024, 2048)` = `[2^10, 2^11)` ns.
/// - Bucket N (N >= 1): `[2^(N+9), 2^(N+10))` ns.
/// - Bucket 15: saturation — any ns ≥ 2^24 (~16 ms) lands here.
///
/// Indexed branchlessly (one `leading_zeros` + one saturating subtract
/// + one min). Sized `[AtomicU64; DRAIN_HIST_BUCKETS]` on
/// `BindingLiveState` so the entire histogram lives inline in the
/// owner's `Arc<BindingLiveState>` — no heap allocation, no bucket-
/// search loop on the hot path. The const-assert below exists because
/// the bucket layout is part of the wire contract (protocol.rs +
/// Prometheus labels): any future change must propagate through both
/// sides, so force a compile error on a silent edit.
pub(super) const DRAIN_HIST_BUCKETS: usize = 16;
const _: () = assert!(DRAIN_HIST_BUCKETS == 16);

/// #709: sample mask for the redirect-acquire timer. We sample the
/// timer 1-in-(MASK+1) = 1-in-256 pushes. The mask is required to be a
/// power-of-two minus one so `counter & MASK == 0` fires uniformly on
/// exactly one value per wrap. Producer-local counter is seeded from
/// `worker_id` so samples from different workers don't lockstep onto
/// the same slot.
pub(super) const REDIRECT_SAMPLE_MASK: u64 = 0xff;
const _: () = assert!(REDIRECT_SAMPLE_MASK.count_ones() == REDIRECT_SAMPLE_MASK.trailing_ones());

/// #812: per-queue TX submit→completion latency histogram bucket count.
///
/// Same layout and math as `DRAIN_HIST_BUCKETS` (reuses
/// `bucket_index_for_ns`). Named distinctly so a future re-layout of
/// either histogram cannot silently drift the other — a rename of one
/// does not touch the other's wire contract. The paired const-asserts
/// below tie the two to each other AND pin the bucket count at 16 so
/// a silent drift on either side becomes a build error pointing at
/// this specific wire-contract dependency (Codex LOW #13 / plan §3.2).
pub(super) const TX_SUBMIT_LAT_BUCKETS: usize = DRAIN_HIST_BUCKETS;
const _ASSERT_TX_SUBMIT_BUCKET_COUNT_MATCHES_DRAIN: () =
    assert!(TX_SUBMIT_LAT_BUCKETS == DRAIN_HIST_BUCKETS);
const _ASSERT_TX_SUBMIT_BUCKET_COUNT_IS_16: () = assert!(TX_SUBMIT_LAT_BUCKETS == 16);

/// #812: sentinel for unstamped sidecar slots. A completion seen
/// against this value means the submit stamp was never written (e.g.
/// a surviving offset across a restart, or a `monotonic_nanos() == 0`
/// clock-gettime failure where `stamp_submits` early-returned without
/// touching the slot — `tx/transmit.rs::stamp_submits`). The reap path MUST
/// skip the histogram increment for these so the tail of the
/// distribution is not silently biased toward bucket 0 (plan §5.4).
///
/// We pick `u64::MAX` because a legitimate monotonic timestamp cannot
/// reach it — at nanosecond granularity it is ~585 years of uptime,
/// well past any deployment lifetime. This removes any value
/// collision between "just happened, small stamp" and "unstamped".
///
/// Codex round-1 MED + Rust round-1 MED-2: the previous
/// `canonical_submit_stamp(ts == 0) → sentinel` mapping in `tx.rs`
/// was in-band signalling on a u64 and has been removed. Clock-
/// failure is now a no-op at stamp time; the slot's pre-existing
/// `UNSTAMPED` state (set by `record_tx_completions_with_stamp` on
/// the previous reap, or by worker construction) is what causes the
/// reap to skip the sample.
pub(super) const TX_SIDECAR_UNSTAMPED: u64 = u64::MAX;

/// #709: branchless power-of-two bucket select for nanosecond deltas.
///
/// Mapping (see `DRAIN_HIST_BUCKETS` for the layout):
/// - `ns ∈ [0, 1024)` → bucket 0 (sub-1 µs catch-all).
/// - `ns ∈ [2^(N+9), 2^(N+10))` → bucket N, for N ∈ [1, 15).
/// - `ns ≥ 2^24` → bucket 15 (saturation).
///
/// Formula:
/// - `(ns | 1)` ensures `leading_zeros` sees at least one set bit —
///   `leading_zeros(0) == 64` would otherwise land us one bucket off
///   at the bottom. With the OR, `ns=0` behaves like `ns=1` (bucket 0).
/// - `clz = (ns | 1).leading_zeros()`: for `ns=1024 (2^10)`,
///   `clz = 64 - 11 = 53`; for `ns=2^24` (top bucket lower bound),
///   `clz = 64 - 25 = 39`.
/// - `b = 54 - clz` gives bucket 1 for `ns=1024` and bucket 15 for
///   `ns=2^24`. Sub-1024 ns delta yields `clz >= 54` → `b <= 0`, which
///   the `.max(0)` saturating subtract clamps at 0. Above 2^24, `b`
///   grows past 15, which `.min(DRAIN_HIST_BUCKETS - 1)` clamps.
///
/// One `leading_zeros` + one saturating subtract + one min. No loop,
/// no branch. Hot-path OK per plan §5.
#[inline]
pub(super) fn bucket_index_for_ns(ns: u64) -> usize {
    let clz = (ns | 1).leading_zeros() as i32;
    let b = (54 - clz).max(0) as usize;
    b.min(DRAIN_HIST_BUCKETS - 1)
}

/// Raw ring state: (rxP, rxC, frP, frC, txP, txC, crP, crC)
pub(in crate::afxdp) struct BindingLiveState {
    pub(super) bound: AtomicBool,
    pub(super) xsk_registered: AtomicBool,
    pub(super) bind_mode: AtomicU8,
    pub(super) socket_fd: AtomicI32,
    pub(super) socket_ifindex: AtomicI32,
    pub(super) socket_queue_id: AtomicU32,
    pub(super) socket_bind_flags: AtomicU32,
    pub(super) rx_packets: AtomicU64,
    pub(super) rx_bytes: AtomicU64,
    pub(super) rx_batches: AtomicU64,
    pub(super) rx_wakeups: AtomicU64,
    pub(super) metadata_packets: AtomicU64,
    pub(super) metadata_errors: AtomicU64,
    pub(super) validated_packets: AtomicU64,
    pub(super) validated_bytes: AtomicU64,
    pub(super) local_delivery_packets: AtomicU64,
    pub(super) forward_candidate_packets: AtomicU64,
    pub(super) route_miss_packets: AtomicU64,
    pub(super) neighbor_miss_packets: AtomicU64,
    pub(super) discard_route_packets: AtomicU64,
    pub(super) next_table_packets: AtomicU64,
    pub(super) exception_packets: AtomicU64,
    pub(super) config_gen_mismatches: AtomicU64,
    pub(super) fib_gen_mismatches: AtomicU64,
    pub(super) unsupported_packets: AtomicU64,
    pub(super) flow_cache_hits: AtomicU64,
    pub(super) flow_cache_misses: AtomicU64,
    pub(super) flow_cache_evictions: AtomicU64,
    /// #918: subset of `flow_cache_evictions` driven by full-set LRU
    /// displacement (i.e. an insert kicked out a different-key entry
    /// from the LRU way). Surfaces hot-set thrash distinctly from
    /// stale-on-lookup evictions so the acceptance gate
    /// (`collision_evictions / hits < 1 %`) is observable at runtime.
    pub(super) flow_cache_collision_evictions: AtomicU64,
    /// #941 Work item D: count of hard-cap activations. When V_min
    /// throttle would have fired for V_MIN_CONSECUTIVE_SKIP_HARD_CAP
    /// consecutive batches, hard-cap force-continues AND arms
    /// suspension. Each such activation increments this counter.
    /// Acceptance gate: under normal load (e.g. iperf-c P=12 saturating),
    /// per-binding hard-cap-override-rate = this / drain_invocations
    /// stays below 5 %. Counter is flushed from each queue's per-queue
    /// scratch field (`v_min_hard_cap_overrides_scratch`) in
    /// `update_binding_debug_state` (mirrors flow_cache_collision_evictions
    /// flush pattern).
    pub(super) v_min_throttle_hard_cap_overrides: AtomicU64,
    /// #943: count of V_min throttle decisions
    /// (`cos_queue_v_min_continue` returned `false` and the caller
    /// took the early-break path, exiting the drain loop). Distinct
    /// from `v_min_throttle_hard_cap_overrides` which only counts
    /// the hard-cap escape-hatch firings introduced by #941.
    /// Acceptance gate: `v_min_throttles` non-zero under load when
    /// V_min sync is active confirms the fairness brake is engaged;
    /// `v_min_throttle_hard_cap_overrides / v_min_throttles` ratio
    /// is the diagnostic for whether LAG_THRESHOLD is too tight.
    /// Flushed from each queue's `v_min_throttles_scratch` in
    /// `update_binding_debug_state` (mirrors flow_cache_collision_evictions).
    pub(super) v_min_throttles: AtomicU64,
    pub(super) session_hits: AtomicU64,
    pub(super) session_misses: AtomicU64,
    pub(super) session_creates: AtomicU64,
    pub(super) session_expires: AtomicU64,
    pub(super) session_delta_generated: AtomicU64,
    pub(super) session_delta_dropped: AtomicU64,
    pub(super) session_delta_drained: AtomicU64,
    pub(super) policy_denied_packets: AtomicU64,
    pub(super) screen_drops: AtomicU64,
    pub(super) snat_packets: AtomicU64,
    pub(super) dnat_packets: AtomicU64,
    pub(super) slow_path_packets: AtomicU64,
    pub(super) slow_path_bytes: AtomicU64,
    pub(super) slow_path_local_delivery_packets: AtomicU64,
    pub(super) slow_path_missing_neighbor_packets: AtomicU64,
    pub(super) slow_path_no_route_packets: AtomicU64,
    pub(super) slow_path_next_table_packets: AtomicU64,
    pub(super) slow_path_forward_build_packets: AtomicU64,
    pub(super) slow_path_drops: AtomicU64,
    pub(super) slow_path_rate_limited: AtomicU64,
    pub(super) kernel_rx_dropped: AtomicU64,
    pub(super) kernel_rx_invalid_descs: AtomicU64,
    pub(super) tx_packets: AtomicU64,
    pub(super) tx_bytes: AtomicU64,
    pub(super) tx_completions: AtomicU64,
    pub(super) tx_errors: AtomicU64,
    /// #710: counts packets that hit the redirect-inbox overflow path
    /// in `enqueue_tx` / `enqueue_tx_owned`. Multi-writer (every
    /// redirecting worker writes; the owner reads). Atomic because
    /// cross-thread. A non-zero value indicates the owner worker is
    /// not draining redirects fast enough — see #706 (mutex
    /// contention) and #709 (owner-worker hotspot).
    pub(super) redirect_inbox_overflow_drops: AtomicU64,
    /// #710: counts packets dropped from `pending_tx_local` /
    /// `pending_tx_prepared` when those bounded FIFOs overflow their
    /// `max_pending_tx` cap. Single-writer per binding (the worker
    /// that owns this binding), but exposed via atomic for cross-
    /// thread readers (status snapshotter). Indicates the worker is
    /// receiving redirected-in traffic faster than it can ingest into
    /// its CoS queues — upstream contributing cause is usually
    /// #706 / #709 (owner worker not keeping up) or #707 / #708
    /// (CoS enqueue throttled by buffer/admission caps).
    pub(super) pending_tx_local_overflow_drops: AtomicU64,
    /// #710: packets dropped at the TX submit path with a
    /// frame-level error (capacity exceeded, slice out of range, or
    /// other `TxError::Drop` from `transmit_batch` / transmit_prepared
    /// paths). Distinct from admission and redirect-inbox drops; a
    /// non-zero value usually indicates a frame-building bug upstream
    /// or a legitimate oversize packet. Subset of `tx_errors`.
    pub(super) tx_submit_error_drops: AtomicU64,
    /// #710: packets dropped in `apply_worker_shaped_tx_requests`
    /// because the worker could not locate any binding for the
    /// request's egress_ifindex. Happens when a cross-worker CoS
    /// redirect lands on a worker whose bound interfaces do not
    /// include the target. Typically reveals a binding-registration
    /// race during config reload or helper restart. Subset of
    /// `tx_errors`.
    pub(super) no_owner_binding_drops: AtomicU64,
    /// #709 / #746: owner-written telemetry, cacheline-isolated.
    /// `drain_latency_hist` buckets sum to `drain_invocations` (pinned
    /// in unit tests); `drain_noop_invocations` is a subset counter
    /// (drains that returned `false`). `owner_pps` is the owner-local
    /// pps window.
    ///
    /// Written only by the owner worker (the sole caller of
    /// `drain_shaped_tx` on this binding); read by the snapshot path
    /// and by Prometheus scrape. Owner-only write + Relaxed load/store
    /// is sufficient: the snapshot reader tolerates monotonic counter
    /// tearing across a bucket array, and Prometheus semantics are
    /// "best effort at scrape time".
    pub(super) owner_profile_owner: OwnerProfileOwnerWrites,
    /// #709 / #746: peer-written telemetry, cacheline-isolated.
    /// `redirect_acquire_hist` is the redirect-acquire latency
    /// histogram, sampled 1-in-(`REDIRECT_SAMPLE_MASK`+1) on
    /// producers. `redirect_sample_counter` is the producer-local
    /// sample counter; seeded from `worker_id` at construction so
    /// different producer workers don't lockstep their samples onto
    /// the same call. `peer_pps` is the peer-redirect pps window.
    ///
    /// Multi-writer: every worker that redirects a TX request into
    /// this binding's inbox increments a bucket on a sampled push.
    /// The owner reads via `snapshot()`.
    pub(super) owner_profile_peer: OwnerProfilePeerWrites,
    pub(super) direct_tx_packets: AtomicU64,
    pub(super) copy_tx_packets: AtomicU64,
    pub(super) in_place_tx_packets: AtomicU64,
    pub(super) direct_tx_no_frame_fallback_packets: AtomicU64,
    pub(super) direct_tx_build_fallback_packets: AtomicU64,
    pub(super) direct_tx_disallowed_fallback_packets: AtomicU64,
    pub(super) debug_pending_fill_frames: AtomicU32,
    pub(super) debug_spare_fill_frames: AtomicU32,
    pub(super) debug_free_tx_frames: AtomicU32,
    pub(super) debug_pending_tx_prepared: AtomicU32,
    pub(super) debug_pending_tx_local: AtomicU32,
    pub(super) debug_outstanding_tx: AtomicU32,
    pub(super) debug_in_flight_recycles: AtomicU32,
    /// #878: total UMEM frames allocated to this binding. Set once
    /// at worker construction (after `binding_frame_count_for_driver`)
    /// and read by the snapshot path.
    pub(super) umem_total_frames: AtomicU32,
    /// #878: configured TX-ring depth for this binding. Set once at
    /// worker construction. `outstanding_tx / tx_ring_capacity` is
    /// the second pressure signal aggregated by the Buffer% display.
    pub(super) tx_ring_capacity: AtomicU32,
    /// #878: UMEM frames currently in flight (not idle in any pool).
    /// Computed in the worker's per-second debug tick as
    /// `total - free_tx_frames.len() - pending_fill_frames.len()
    ///        - device.pending()` — one publish, one read, so the
    /// `show chassis forwarding` Buffer% can divide by
    /// `umem_total_frames` without torn-load risk. Approximation by
    /// design: cross-field sampling on the publish side is acceptable
    /// because the per-second cadence bounds skew, and the CLI
    /// surface is rare-diagnostic, not a load-bearing invariant.
    /// Subtracting `device.pending()` (the kernel fill ring depth)
    /// is essential — without it an idle binding reads ~80% because
    /// AF_XDP keeps the fill ring pre-populated by design.
    pub(super) umem_inflight_frames: AtomicU32,
    /// #802: ring-pressure instrumentation. Cumulative monotonic counters
    /// mirrored from the worker-local `BindingWorker` fields of the same
    /// name. Worker increments `b.dbg_tx_ring_full += 1` (etc.) on the hot
    /// path; the published value here is updated via `fetch_add(delta)`
    /// at the existing ~1s debug-report tick, BEFORE the local counter is
    /// reset for the next window. The control-socket snapshot reads from
    /// these atomics. No hot-path code is touched — this is purely a new
    /// read-side publish sink.
    pub(super) dbg_tx_ring_full: AtomicU64,
    pub(super) dbg_sendto_enobufs: AtomicU64,
    /// #802/#804: per-binding `bound_pending` FIFO overflow counter —
    /// incremented when `bound_pending_tx_local`/`bound_pending_tx_prepared`
    /// evict an item because the FIFO is above `max_pending_tx`. This is
    /// strictly the bound-pending path; the class-of-service admission
    /// overflow has its own counter below. Pre-#804 builds published a
    /// single `dbg_pending_overflow` that conflated the two sites; that
    /// wire key was removed in #804 in favor of the split names.
    pub(super) dbg_bound_pending_overflow: AtomicU64,
    /// #804: class-of-service queue admission overflow counter —
    /// incremented in `enqueue_cos_item()` when the CoS admission gate
    /// rejects the item (flow-share cap + buffer cap exhausted) but the
    /// caller still needs to account the drop. Separate from
    /// `dbg_bound_pending_overflow` so operators can disambiguate
    /// bound-pending pressure from CoS shaping pressure at triage time.
    pub(super) dbg_cos_queue_overflow: AtomicU64,
    /// #802: kernel XDP statistics v2 `rx_fill_ring_empty_descs` — the
    /// kernel's native cumulative counter of RX fill-ring starvation
    /// events. Published via `store()` (not fetch_add) because the
    /// kernel-side value is already absolute. Sampled from
    /// `device.statistics_v2()` at the same ~1s debug-report tick as
    /// the local counters above.
    pub(super) rx_fill_ring_empty_descs: AtomicU64,
    pub(super) last_heartbeat: AtomicU64,
    pub(super) max_pending_tx: AtomicU32,
    pub(super) last_error: Mutex<String>,
    /// Cross-worker redirect inbox (#706). N producer workers push
    /// redirected `TxRequest`s; the single owner worker drains. Bounded
    /// lock-free ring — replaces the pre-#706 `Mutex<VecDeque>` that
    /// serialised every producer against every other producer and
    /// against the owner's drain.
    pub(super) pending_tx: MpscInbox<TxRequest>,
    pub(super) pending_session_deltas: Mutex<VecDeque<SessionDeltaInfo>>,
}

impl BindingLiveState {
    pub(super) fn new() -> Self {
        Self {
            bound: AtomicBool::new(false),
            xsk_registered: AtomicBool::new(false),
            bind_mode: AtomicU8::new(XskBindMode::Unknown.as_u8()),
            socket_fd: AtomicI32::new(0),
            socket_ifindex: AtomicI32::new(0),
            socket_queue_id: AtomicU32::new(0),
            socket_bind_flags: AtomicU32::new(0),
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            rx_batches: AtomicU64::new(0),
            rx_wakeups: AtomicU64::new(0),
            metadata_packets: AtomicU64::new(0),
            metadata_errors: AtomicU64::new(0),
            validated_packets: AtomicU64::new(0),
            validated_bytes: AtomicU64::new(0),
            local_delivery_packets: AtomicU64::new(0),
            forward_candidate_packets: AtomicU64::new(0),
            route_miss_packets: AtomicU64::new(0),
            neighbor_miss_packets: AtomicU64::new(0),
            discard_route_packets: AtomicU64::new(0),
            next_table_packets: AtomicU64::new(0),
            exception_packets: AtomicU64::new(0),
            config_gen_mismatches: AtomicU64::new(0),
            fib_gen_mismatches: AtomicU64::new(0),
            unsupported_packets: AtomicU64::new(0),
            flow_cache_hits: AtomicU64::new(0),
            flow_cache_misses: AtomicU64::new(0),
            flow_cache_evictions: AtomicU64::new(0),
            flow_cache_collision_evictions: AtomicU64::new(0),
            v_min_throttle_hard_cap_overrides: AtomicU64::new(0),
            v_min_throttles: AtomicU64::new(0),
            session_hits: AtomicU64::new(0),
            session_misses: AtomicU64::new(0),
            session_creates: AtomicU64::new(0),
            session_expires: AtomicU64::new(0),
            session_delta_generated: AtomicU64::new(0),
            session_delta_dropped: AtomicU64::new(0),
            session_delta_drained: AtomicU64::new(0),
            policy_denied_packets: AtomicU64::new(0),
            screen_drops: AtomicU64::new(0),
            snat_packets: AtomicU64::new(0),
            dnat_packets: AtomicU64::new(0),
            slow_path_packets: AtomicU64::new(0),
            slow_path_bytes: AtomicU64::new(0),
            slow_path_local_delivery_packets: AtomicU64::new(0),
            slow_path_missing_neighbor_packets: AtomicU64::new(0),
            slow_path_no_route_packets: AtomicU64::new(0),
            slow_path_next_table_packets: AtomicU64::new(0),
            slow_path_forward_build_packets: AtomicU64::new(0),
            slow_path_drops: AtomicU64::new(0),
            slow_path_rate_limited: AtomicU64::new(0),
            kernel_rx_dropped: AtomicU64::new(0),
            kernel_rx_invalid_descs: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            tx_completions: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            redirect_inbox_overflow_drops: AtomicU64::new(0),
            pending_tx_local_overflow_drops: AtomicU64::new(0),
            tx_submit_error_drops: AtomicU64::new(0),
            no_owner_binding_drops: AtomicU64::new(0),
            // #709 / #746: owner-profile telemetry, split by writer
            // into two cacheline-isolated groups. Histograms are zero-
            // init fixed-cap arrays; sum of buckets == drain_invocations
            // invariant holds at `new()` (both 0). The redirect-sample
            // counter seed is left at zero by `new()`; call sites that
            // have a worker_id in hand should use `new_seeded()` instead
            // so per-worker samples don't lockstep onto the same push.
            owner_profile_owner: OwnerProfileOwnerWrites::new(),
            owner_profile_peer: OwnerProfilePeerWrites::new(),
            direct_tx_packets: AtomicU64::new(0),
            copy_tx_packets: AtomicU64::new(0),
            in_place_tx_packets: AtomicU64::new(0),
            direct_tx_no_frame_fallback_packets: AtomicU64::new(0),
            direct_tx_build_fallback_packets: AtomicU64::new(0),
            direct_tx_disallowed_fallback_packets: AtomicU64::new(0),
            debug_pending_fill_frames: AtomicU32::new(0),
            debug_spare_fill_frames: AtomicU32::new(0),
            debug_free_tx_frames: AtomicU32::new(0),
            debug_pending_tx_prepared: AtomicU32::new(0),
            debug_pending_tx_local: AtomicU32::new(0),
            debug_outstanding_tx: AtomicU32::new(0),
            debug_in_flight_recycles: AtomicU32::new(0),
            // #878: capacities are stored once by the worker at
            // construction time (in worker.rs after
            // binding_frame_count_for_driver). umem_inflight_frames
            // is republished by the worker each per-second debug
            // tick. Zero here means "not yet published"; the
            // fwdstatus builder treats zero on umem_total_frames as
            // "unknown" and falls back to the legacy display.
            umem_total_frames: AtomicU32::new(0),
            tx_ring_capacity: AtomicU32::new(0),
            umem_inflight_frames: AtomicU32::new(0),
            // #802: ring-pressure instrumentation sinks. Zero-init;
            // published by the worker's per-second debug tick.
            dbg_tx_ring_full: AtomicU64::new(0),
            dbg_sendto_enobufs: AtomicU64::new(0),
            dbg_bound_pending_overflow: AtomicU64::new(0),
            dbg_cos_queue_overflow: AtomicU64::new(0),
            rx_fill_ring_empty_descs: AtomicU64::new(0),
            last_heartbeat: AtomicU64::new(0),
            max_pending_tx: AtomicU32::new(0),
            last_error: Mutex::new(String::new()),
            pending_tx: MpscInbox::new(PENDING_TX_INBOX_HARD_CAP),
            pending_session_deltas: Mutex::new(VecDeque::new()),
        }
    }

    /// #709: construct a binding live state with the redirect-sample
    /// counter pre-seeded from `worker_id`. Seeding is cosmetic — the
    /// sample mask fires exactly 1-in-(MASK+1) regardless of start
    /// value — but it prevents every worker from firing its first
    /// sample on its very first push, which avoids an early-startup
    /// lockstep burst that would bias bucket 0 heavily on the first
    /// scrape.
    pub(super) fn new_seeded(worker_id: u32) -> Self {
        let mut state = Self::new();
        // `worker_id as u64` preserves the distinct-per-worker property
        // we care about without needing a randomness source. The mask
        // treats the counter modulo (MASK+1), so any seed ∈ [0, MASK]
        // suffices; larger worker_ids just wrap cheaply.
        //
        // #746: the sample counter moved into `owner_profile_peer`
        // when the owner/peer split landed; seeding writes through the
        // new nested path but the effect is identical.
        state.owner_profile_peer.redirect_sample_counter = AtomicU64::new(worker_id as u64);
        state
    }

    pub(super) fn set_bound(&self, socket_fd: c_int) {
        self.bound.store(true, Ordering::Relaxed);
        self.socket_fd.store(socket_fd, Ordering::Relaxed);
    }

    pub(super) fn set_socket_binding(&self, ifindex: i32, queue_id: u32, flags: u32) {
        self.socket_ifindex.store(ifindex, Ordering::Relaxed);
        self.socket_queue_id.store(queue_id, Ordering::Relaxed);
        self.socket_bind_flags.store(flags, Ordering::Relaxed);
    }

    pub(super) fn set_xsk_registered(&self, value: bool) {
        self.xsk_registered.store(value, Ordering::Relaxed);
    }

    pub(super) fn set_bind_mode(&self, mode: XskBindMode) {
        self.bind_mode.store(mode.as_u8(), Ordering::Relaxed);
    }

    pub(super) fn set_last_heartbeat_at(&self, now_ns: u64) {
        self.last_heartbeat.store(now_ns, Ordering::Relaxed);
    }

    pub(super) fn set_max_pending_tx(&self, max_pending: usize) {
        self.max_pending_tx
            .store(max_pending.min(u32::MAX as usize) as u32, Ordering::Relaxed);
    }

    pub(super) fn clear_error(&self) {
        if let Ok(mut err) = self.last_error.lock() {
            err.clear();
        }
    }

    pub(super) fn set_error(&self, msg: String) {
        if let Ok(mut err) = self.last_error.lock() {
            *err = msg;
        }
    }

    pub(super) fn record_slow_path_accept(
        &self,
        disposition: ForwardingDisposition,
        reason: &str,
        packet_len: u64,
    ) {
        self.slow_path_packets.fetch_add(1, Ordering::Relaxed);
        self.slow_path_bytes
            .fetch_add(packet_len, Ordering::Relaxed);
        if reason == "forward_build_slow_path" {
            self.slow_path_forward_build_packets
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        match disposition {
            ForwardingDisposition::LocalDelivery => {
                self.slow_path_local_delivery_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            ForwardingDisposition::MissingNeighbor => {
                self.slow_path_missing_neighbor_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            ForwardingDisposition::NoRoute => {
                self.slow_path_no_route_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            ForwardingDisposition::NextTableUnsupported => {
                self.slow_path_next_table_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub(super) fn snapshot(&self) -> BindingLiveSnapshot {
        let now_wall = Utc::now();
        let now_mono = monotonic_nanos();
        let session_delta_pending = self
            .pending_session_deltas
            .lock()
            .map(|pending| pending.len() as u64)
            .unwrap_or(0);
        BindingLiveSnapshot {
            bound: self.bound.load(Ordering::Relaxed),
            xsk_registered: self.xsk_registered.load(Ordering::Relaxed),
            xsk_bind_mode: XskBindMode::from_u8(self.bind_mode.load(Ordering::Relaxed))
                .as_str()
                .to_string(),
            zero_copy: XskBindMode::from_u8(self.bind_mode.load(Ordering::Relaxed)).is_zerocopy(),
            socket_fd: self.socket_fd.load(Ordering::Relaxed),
            socket_ifindex: self.socket_ifindex.load(Ordering::Relaxed),
            socket_queue_id: self.socket_queue_id.load(Ordering::Relaxed),
            socket_bind_flags: self.socket_bind_flags.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            rx_batches: self.rx_batches.load(Ordering::Relaxed),
            rx_wakeups: self.rx_wakeups.load(Ordering::Relaxed),
            metadata_packets: self.metadata_packets.load(Ordering::Relaxed),
            metadata_errors: self.metadata_errors.load(Ordering::Relaxed),
            validated_packets: self.validated_packets.load(Ordering::Relaxed),
            validated_bytes: self.validated_bytes.load(Ordering::Relaxed),
            local_delivery_packets: self.local_delivery_packets.load(Ordering::Relaxed),
            forward_candidate_packets: self.forward_candidate_packets.load(Ordering::Relaxed),
            route_miss_packets: self.route_miss_packets.load(Ordering::Relaxed),
            neighbor_miss_packets: self.neighbor_miss_packets.load(Ordering::Relaxed),
            discard_route_packets: self.discard_route_packets.load(Ordering::Relaxed),
            next_table_packets: self.next_table_packets.load(Ordering::Relaxed),
            exception_packets: self.exception_packets.load(Ordering::Relaxed),
            config_gen_mismatches: self.config_gen_mismatches.load(Ordering::Relaxed),
            fib_gen_mismatches: self.fib_gen_mismatches.load(Ordering::Relaxed),
            unsupported_packets: self.unsupported_packets.load(Ordering::Relaxed),
            flow_cache_hits: self.flow_cache_hits.load(Ordering::Relaxed),
            flow_cache_misses: self.flow_cache_misses.load(Ordering::Relaxed),
            flow_cache_evictions: self.flow_cache_evictions.load(Ordering::Relaxed),
            flow_cache_collision_evictions: self
                .flow_cache_collision_evictions
                .load(Ordering::Relaxed),
            v_min_throttle_hard_cap_overrides: self
                .v_min_throttle_hard_cap_overrides
                .load(Ordering::Relaxed),
            v_min_throttles: self.v_min_throttles.load(Ordering::Relaxed),
            session_hits: self.session_hits.load(Ordering::Relaxed),
            session_misses: self.session_misses.load(Ordering::Relaxed),
            session_creates: self.session_creates.load(Ordering::Relaxed),
            session_expires: self.session_expires.load(Ordering::Relaxed),
            session_delta_pending,
            session_delta_generated: self.session_delta_generated.load(Ordering::Relaxed),
            session_delta_dropped: self.session_delta_dropped.load(Ordering::Relaxed),
            session_delta_drained: self.session_delta_drained.load(Ordering::Relaxed),
            policy_denied_packets: self.policy_denied_packets.load(Ordering::Relaxed),
            screen_drops: self.screen_drops.load(Ordering::Relaxed),
            snat_packets: self.snat_packets.load(Ordering::Relaxed),
            dnat_packets: self.dnat_packets.load(Ordering::Relaxed),
            slow_path_packets: self.slow_path_packets.load(Ordering::Relaxed),
            slow_path_bytes: self.slow_path_bytes.load(Ordering::Relaxed),
            slow_path_local_delivery_packets: self
                .slow_path_local_delivery_packets
                .load(Ordering::Relaxed),
            slow_path_missing_neighbor_packets: self
                .slow_path_missing_neighbor_packets
                .load(Ordering::Relaxed),
            slow_path_no_route_packets: self.slow_path_no_route_packets.load(Ordering::Relaxed),
            slow_path_next_table_packets: self.slow_path_next_table_packets.load(Ordering::Relaxed),
            slow_path_forward_build_packets: self
                .slow_path_forward_build_packets
                .load(Ordering::Relaxed),
            slow_path_drops: self.slow_path_drops.load(Ordering::Relaxed),
            slow_path_rate_limited: self.slow_path_rate_limited.load(Ordering::Relaxed),
            kernel_rx_dropped: self.kernel_rx_dropped.load(Ordering::Relaxed),
            kernel_rx_invalid_descs: self.kernel_rx_invalid_descs.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            tx_completions: self.tx_completions.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
            redirect_inbox_overflow_drops: self
                .redirect_inbox_overflow_drops
                .load(Ordering::Relaxed),
            pending_tx_local_overflow_drops: self
                .pending_tx_local_overflow_drops
                .load(Ordering::Relaxed),
            tx_submit_error_drops: self.tx_submit_error_drops.load(Ordering::Relaxed),
            post_drain_backup_bytes: self
                .owner_profile_owner
                .post_drain_backup_bytes
                .load(Ordering::Relaxed),
            drain_sent_bytes_shaped_unconditional: self
                .owner_profile_owner
                .drain_sent_bytes_shaped_unconditional
                .load(Ordering::Relaxed),
            post_drain_backup_cos_drops: self
                .owner_profile_owner
                .post_drain_backup_cos_drops
                .load(Ordering::Relaxed),
            post_drain_backup_cos_drop_bytes: self
                .owner_profile_owner
                .post_drain_backup_cos_drop_bytes
                .load(Ordering::Relaxed),
            // Compile-time check: these four counters live on the
            // owner-only cacheline-isolated block to avoid ping-
            // pong with multi-writer overflow counters.
            // `no_owner_binding_drops` is read directly from the atomic
            // by `Coordinator::cos_no_owner_binding_drops_total()` — not
            // snapshotted here because it is not exposed per-binding.
            direct_tx_packets: self.direct_tx_packets.load(Ordering::Relaxed),
            copy_tx_packets: self.copy_tx_packets.load(Ordering::Relaxed),
            in_place_tx_packets: self.in_place_tx_packets.load(Ordering::Relaxed),
            direct_tx_no_frame_fallback_packets: self
                .direct_tx_no_frame_fallback_packets
                .load(Ordering::Relaxed),
            direct_tx_build_fallback_packets: self
                .direct_tx_build_fallback_packets
                .load(Ordering::Relaxed),
            direct_tx_disallowed_fallback_packets: self
                .direct_tx_disallowed_fallback_packets
                .load(Ordering::Relaxed),
            debug_pending_fill_frames: self.debug_pending_fill_frames.load(Ordering::Relaxed),
            debug_spare_fill_frames: self.debug_spare_fill_frames.load(Ordering::Relaxed),
            debug_free_tx_frames: self.debug_free_tx_frames.load(Ordering::Relaxed),
            debug_pending_tx_prepared: self.debug_pending_tx_prepared.load(Ordering::Relaxed),
            debug_pending_tx_local: self.debug_pending_tx_local.load(Ordering::Relaxed),
            debug_outstanding_tx: self.debug_outstanding_tx.load(Ordering::Relaxed),
            debug_in_flight_recycles: self.debug_in_flight_recycles.load(Ordering::Relaxed),
            // #878: per-binding UMEM/TX-ring capacities (set once at
            // worker startup) and current in-flight frames
            // (republished each per-second debug tick from the
            // worker thread). Zero on umem_total_frames means "not
            // yet published".
            umem_total_frames: self.umem_total_frames.load(Ordering::Relaxed),
            tx_ring_capacity: self.tx_ring_capacity.load(Ordering::Relaxed),
            umem_inflight_frames: self.umem_inflight_frames.load(Ordering::Relaxed),
            // #802: ring-pressure counters published from the worker's
            // periodic debug tick. Relaxed load is sufficient — these
            // are monotonic diagnostic counters, not part of any
            // load-bearing synchronization.
            dbg_tx_ring_full: self.dbg_tx_ring_full.load(Ordering::Relaxed),
            dbg_sendto_enobufs: self.dbg_sendto_enobufs.load(Ordering::Relaxed),
            dbg_bound_pending_overflow: self.dbg_bound_pending_overflow.load(Ordering::Relaxed),
            dbg_cos_queue_overflow: self.dbg_cos_queue_overflow.load(Ordering::Relaxed),
            rx_fill_ring_empty_descs: self.rx_fill_ring_empty_descs.load(Ordering::Relaxed),
            last_heartbeat: monotonic_timestamp_to_datetime(
                self.last_heartbeat.load(Ordering::Relaxed),
                now_mono,
                now_wall,
            ),
            last_error: self
                .last_error
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
            // #709 / #746: owner-profile telemetry snapshot.
            // Histograms are copied bucket-by-bucket under `Relaxed`
            // through the cacheline-isolated owner/peer structs.
            // Read-side tearing is acceptable — these are diagnostic
            // counters, not a load-bearing arithmetic invariant; the
            // only "invariant" (sum of buckets ≈ drain_invocations)
            // holds within a single-thread read only in steady-state,
            // which is how operators consume the values anyway.
            drain_latency_hist: Self::snapshot_hist(
                &self.owner_profile_owner.drain_latency_hist,
            ),
            drain_invocations: self
                .owner_profile_owner
                .drain_invocations
                .load(Ordering::Relaxed),
            drain_noop_invocations: self
                .owner_profile_owner
                .drain_noop_invocations
                .load(Ordering::Relaxed),
            redirect_acquire_hist: Self::snapshot_hist(
                &self.owner_profile_peer.redirect_acquire_hist,
            ),
            owner_pps: self.owner_profile_owner.owner_pps.load(Ordering::Relaxed),
            peer_pps: self.owner_profile_peer.peer_pps.load(Ordering::Relaxed),
            // #812: owner-written TX submit-latency telemetry.
            // Copied bucket-by-bucket under Relaxed; read-side
            // tearing acceptable per the §3.6 R2 bounded-skew
            // semantics and the drain-histogram precedent at
            // umem.rs:1322-1329. The count/sum scalars are loaded
            // immediately after the bucket sweep so the snapshot
            // read window is tight (single owner cacheline).
            tx_submit_latency_hist: Self::snapshot_hist(
                &self.owner_profile_owner.tx_submit_latency_hist,
            ),
            tx_submit_latency_count: self
                .owner_profile_owner
                .tx_submit_latency_count
                .load(Ordering::Relaxed),
            tx_submit_latency_sum_ns: self
                .owner_profile_owner
                .tx_submit_latency_sum_ns
                .load(Ordering::Relaxed),
            // #825: owner-written TX kick-latency telemetry. Same
            // single-writer / Relaxed-load discipline as the #812
            // submit-latency block above; bounded-read-skew
            // semantics per plan §4. Load scalars immediately after
            // the bucket sweep so the snapshot window is tight.
            tx_kick_latency_hist: Self::snapshot_hist(
                &self.owner_profile_owner.tx_kick_latency_hist,
            ),
            tx_kick_latency_count: self
                .owner_profile_owner
                .tx_kick_latency_count
                .load(Ordering::Relaxed),
            tx_kick_latency_sum_ns: self
                .owner_profile_owner
                .tx_kick_latency_sum_ns
                .load(Ordering::Relaxed),
            tx_kick_retry_count: self
                .owner_profile_owner
                .tx_kick_retry_count
                .load(Ordering::Relaxed),
        }
    }

    /// #709: copy a histogram bucket array under `Relaxed`. Inline to
    /// keep the fixed-size array on the caller's stack — no `Vec`.
    #[inline]
    fn snapshot_hist(hist: &[AtomicU64; DRAIN_HIST_BUCKETS]) -> [u64; DRAIN_HIST_BUCKETS] {
        std::array::from_fn(|i| hist[i].load(Ordering::Relaxed))
    }

    pub(super) fn enqueue_tx(&self, req: TxRequest) -> Result<(), String> {
        self.push_redirect_inbox(req);
        Ok(())
    }

    pub(super) fn enqueue_tx_owned(&self, req: TxRequest) -> Result<(), TxRequest> {
        // #709: redirect-acquire latency, sampled 1-in-256.
        //
        // Hot-path cost on the non-sampled branch: one
        // `fetch_add(1, Relaxed)` + one `&` + one `==`. Under a few ns
        // on modern x86_64. On the sampled branch: two
        // `monotonic_nanos()` (VDSO `clock_gettime(MONOTONIC)`, ~15 ns
        // each) + one bucket write. 1-in-256 sampling amortises to
        // `~(2 * 15 + 2) / 256 ≈ 0.13 ns` per push — well below the
        // noise floor of the redirect path itself.
        //
        // The timer wraps only `push_redirect_inbox`. We do NOT add a
        // second atomic to the MPSC inbox itself; the sample counter
        // lives on `BindingLiveState` next to the other per-binding
        // atomics. MPSC invariants from #715 are preserved.
        let sample = (self
            .owner_profile_peer
            .redirect_sample_counter
            .fetch_add(1, Ordering::Relaxed)
            & REDIRECT_SAMPLE_MASK)
            == 0;
        let start = if sample {
            Some(monotonic_nanos())
        } else {
            None
        };
        self.push_redirect_inbox(req);
        if let Some(start) = start {
            let delta = monotonic_nanos().saturating_sub(start);
            let bucket = bucket_index_for_ns(delta);
            self.owner_profile_peer.redirect_acquire_hist[bucket]
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Shared push path for `enqueue_tx` and `enqueue_tx_owned`.
    /// Drop-newest on overflow: if the soft cap or ring hard cap is hit,
    /// drop the incoming request and bump the overflow counters. This is
    /// a deliberate change from the pre-#706 drop-oldest behaviour —
    /// older queued packets are closer to being serviced by the owner
    /// worker, so evicting them just extends tail latency. The counter
    /// contract (`tx_errors` as the generic error,
    /// `redirect_inbox_overflow_drops` as the dedicated view) is preserved.
    #[inline]
    fn push_redirect_inbox(&self, req: TxRequest) {
        let max_pending = self.max_pending_tx.load(Ordering::Relaxed) as usize;
        if max_pending > 0 && self.pending_tx.len() >= max_pending {
            self.record_redirect_inbox_overflow();
            return;
        }
        if self.pending_tx.push(req).is_err() {
            // Hard cap hit — ring is full. Rare: the hard cap sits at
            // `PENDING_TX_INBOX_HARD_CAP`, so a non-zero soft cap
            // normally fires first. This branch is reachable only under
            // concurrent producers racing past the soft-cap check, or
            // when the caller has set `max_pending_tx = 0` (treat as
            // unlimited → hard cap is the only brake).
            self.record_redirect_inbox_overflow();
        }
    }

    #[inline]
    fn record_redirect_inbox_overflow(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
        // #710 / #706: non-zero values here indicate the owner worker
        // cannot drain redirects fast enough relative to producer push
        // rate. After #706 the path is lock-free, so contention is no
        // longer the bottleneck — further growth typically points at
        // owner-worker hotspot (#709) or CoS admission (#707 / #708).
        self.redirect_inbox_overflow_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Drain the redirect inbox into a caller-provided `VecDeque`, so the
    /// owner worker's drain stays allocation-free on the hot path. The
    /// caller reuses its existing `pending_tx_local` buffer across polls
    /// — calling `VecDeque::new()` / growing a fresh buffer on every drain
    /// put allocator noise back on the exact thread #706 is trying to
    /// keep quiet.
    pub(super) fn take_pending_tx_into(&self, out: &mut VecDeque<TxRequest>) {
        if self.pending_tx.is_empty() {
            return;
        }
        // SAFETY: `MpscInbox::pop` requires the single-consumer
        // invariant. The per-binding redirect inbox has exactly one
        // consumer — the owner worker — which is also the sole caller
        // of `take_pending_tx_into`. Enforced by convention (see the doc
        // comment on `pending_tx` in `BindingLiveState`).
        while let Some(req) = unsafe { self.pending_tx.pop() } {
            out.push_back(req);
        }
    }

    pub(super) fn pending_tx_empty(&self) -> bool {
        self.pending_tx.is_empty()
    }

    pub(super) fn push_session_delta(&self, delta: SessionDeltaInfo) {
        self.session_delta_generated.fetch_add(1, Ordering::Relaxed);
        match self.pending_session_deltas.lock() {
            Ok(mut pending) => {
                if pending.len() >= MAX_PENDING_SESSION_DELTAS {
                    self.session_delta_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                pending.push_back(delta);
            }
            Err(_) => {
                self.session_delta_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn drain_session_deltas(&self, max: usize) -> Vec<SessionDeltaInfo> {
        let drain = max.max(1);
        match self.pending_session_deltas.lock() {
            Ok(mut pending) => {
                let count = drain.min(pending.len());
                let mut out = Vec::with_capacity(count);
                for _ in 0..count {
                    if let Some(delta) = pending.pop_front() {
                        out.push(delta);
                    }
                }
                self.session_delta_drained
                    .fetch_add(out.len() as u64, Ordering::Relaxed);
                out
            }
            Err(_) => Vec::new(),
        }
    }
}

pub(super) fn update_binding_debug_state(binding: &mut BindingWorker) {
    // Use a simple modular counter to avoid 7 atomic stores on every call.
    // At ~1M calls/sec, checking every 65536 calls ~= every 65ms.
    binding.timers.debug_state_counter = binding.timers.debug_state_counter.wrapping_add(1);
    if binding.timers.debug_state_counter & 0xFFFF != 0 {
        return;
    }
    if binding.tx_counters.pending_direct_tx_packets != 0 {
        binding
            .live
            .direct_tx_packets
            .fetch_add(binding.tx_counters.pending_direct_tx_packets, Ordering::Relaxed);
        binding.tx_counters.pending_direct_tx_packets = 0;
    }
    if binding.tx_counters.pending_copy_tx_packets != 0 {
        binding
            .live
            .copy_tx_packets
            .fetch_add(binding.tx_counters.pending_copy_tx_packets, Ordering::Relaxed);
        binding.tx_counters.pending_copy_tx_packets = 0;
    }
    if binding.tx_counters.pending_in_place_tx_packets != 0 {
        binding
            .live
            .in_place_tx_packets
            .fetch_add(binding.tx_counters.pending_in_place_tx_packets, Ordering::Relaxed);
        binding.tx_counters.pending_in_place_tx_packets = 0;
    }
    if binding.tx_counters.pending_direct_tx_no_frame_fallback_packets != 0 {
        binding.live.direct_tx_no_frame_fallback_packets.fetch_add(
            binding.tx_counters.pending_direct_tx_no_frame_fallback_packets,
            Ordering::Relaxed,
        );
        binding.tx_counters.pending_direct_tx_no_frame_fallback_packets = 0;
    }
    if binding.tx_counters.pending_direct_tx_build_fallback_packets != 0 {
        binding.live.direct_tx_build_fallback_packets.fetch_add(
            binding.tx_counters.pending_direct_tx_build_fallback_packets,
            Ordering::Relaxed,
        );
        binding.tx_counters.pending_direct_tx_build_fallback_packets = 0;
    }
    if binding.tx_counters.pending_direct_tx_disallowed_fallback_packets != 0 {
        binding
            .live
            .direct_tx_disallowed_fallback_packets
            .fetch_add(
                binding.tx_counters.pending_direct_tx_disallowed_fallback_packets,
                Ordering::Relaxed,
            );
        binding.tx_counters.pending_direct_tx_disallowed_fallback_packets = 0;
    }
    if binding.flow.flow_cache.hits != 0 {
        binding
            .live
            .flow_cache_hits
            .fetch_add(binding.flow.flow_cache.hits, Ordering::Relaxed);
        binding.flow.flow_cache.hits = 0;
    }
    if binding.flow.flow_cache.misses != 0 {
        binding
            .live
            .flow_cache_misses
            .fetch_add(binding.flow.flow_cache.misses, Ordering::Relaxed);
        binding.flow.flow_cache.misses = 0;
    }
    if binding.flow.flow_cache.evictions != 0 {
        binding
            .live
            .flow_cache_evictions
            .fetch_add(binding.flow.flow_cache.evictions, Ordering::Relaxed);
        binding.flow.flow_cache.evictions = 0;
    }
    // #918: surface collision-driven evictions distinctly from
    // stale-on-lookup evictions so the post-merge acceptance gate
    // (`collision_evictions / hits < 1 %` under 100E100M load) is
    // observable from the standard binding-counter snapshot.
    if binding.flow.flow_cache.collision_evictions != 0 {
        binding
            .live
            .flow_cache_collision_evictions
            .fetch_add(binding.flow.flow_cache.collision_evictions, Ordering::Relaxed);
        binding.flow.flow_cache.collision_evictions = 0;
    }
    // #941 Work item D + #943: flush each queue's per-queue scratch
    // counters (hard-cap overrides AND regular V_min throttles) into
    // the binding-wide AtomicU64s. Mirrors the
    // flow_cache_collision_evictions pattern. Single-writer (worker
    // thread) on both ends, so no atomicity issue. The body is in
    // `flush_v_min_scratches_into` so it's directly unit-testable
    // without needing to construct a full `BindingWorker`.
    flush_v_min_scratches_into(
        binding.cos.cos_interfaces.values_mut(),
        &binding.live.v_min_throttle_hard_cap_overrides,
        &binding.live.v_min_throttles,
    );
}

/// Flush each queue's per-queue V_min scratch counters
/// (`v_min_hard_cap_overrides_scratch` + `v_min_throttles_scratch`)
/// into the binding-wide `AtomicU64`s and zero the scratches. Single
/// pass over `roots`, single-writer discipline. Extracted from
/// `update_binding_debug_state` so the flush is testable without
/// constructing a `BindingWorker` (which has ~40 fields).
pub(super) fn flush_v_min_scratches_into<'a, I>(
    roots: I,
    hard_cap_target: &AtomicU64,
    throttles_target: &AtomicU64,
) where
    I: IntoIterator<Item = &'a mut crate::afxdp::types::CoSInterfaceRuntime>,
{
    let mut hard_cap_overrides_total = 0u64;
    let mut throttles_total = 0u64;
    for root in roots {
        for queue in &mut root.queues {
            if queue.v_min_hard_cap_overrides_scratch != 0 {
                hard_cap_overrides_total =
                    hard_cap_overrides_total.saturating_add(
                        u64::from(queue.v_min_hard_cap_overrides_scratch),
                    );
                queue.v_min_hard_cap_overrides_scratch = 0;
            }
            if queue.v_min_throttles_scratch != 0 {
                throttles_total = throttles_total
                    .saturating_add(u64::from(queue.v_min_throttles_scratch));
                queue.v_min_throttles_scratch = 0;
            }
        }
    }
    if hard_cap_overrides_total != 0 {
        hard_cap_target.fetch_add(hard_cap_overrides_total, Ordering::Relaxed);
    }
    if throttles_total != 0 {
        throttles_target.fetch_add(throttles_total, Ordering::Relaxed);
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
