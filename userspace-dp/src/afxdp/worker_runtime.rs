// #869: per-worker busy/idle runtime accounting.
//
// The AF_XDP worker loop publishes cumulative time spent in three states
// (Active, IdleSpin, IdleBlock) plus loop counts and sampled thread CPU
// time.  Operators use this to tell compute saturation apart from spin
// waste apart from genuine idle headroom apart from VM-scheduling loss.
//
// Hot-path design:
//
//   1. At each loop iteration's top the worker computes
//      `delta = now - last_loop_ns` and attributes the delta to the
//      PREVIOUS loop's classified state.  No per-packet work.
//
//   2. After `did_work` is known and the worker has decided whether it
//      will take the active / spin / block branch, the state for the
//      next iteration is set.
//
//   3. Worker-local counters are pure u64 math.  They are copied into a
//      cacheline-isolated atomic struct only on a ~1s cadence (same
//      cadence as existing worker_heartbeats).  `CLOCK_THREAD_CPUTIME_ID`
//      is sampled on the same cadence, NOT per iteration.
//
//   4. Most atomics use `Ordering::Relaxed` because they are diagnostic
//      monotonic counters where cross-field tearing is acceptable. The
//      rolling-window fields (`wall_ns_60s`, `active_ns_60s`,
//      `thread_cpu_ns_60s`, `window_ns`) are an exception: they are
//      published as a coherent tuple guarded by a `window_gen` seqlock.
//      Writers `fetch_add(AcqRel)` to enter the odd publishing state,
//      Relaxed-store the four window fields, then `fetch_add(Release)`
//      back to an even committed state. Readers `Acquire`-load
//      `window_gen` (s1), Relaxed-load the four data fields, issue a
//      `fence(Acquire)` to seal those loads, then Relaxed-load
//      `window_gen` again (s2). If `s2 == s1` and even, the four data
//      fields were observed within a single committed epoch; on retry
//      exhaustion the reader returns `default()` so `statusfmt`
//      renders `-`. See the struct doc on `WorkerRuntimeAtomics` for
//      the publication invariant.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Classification applied to the previous worker-loop iteration.
/// Determines which counter the elapsed delta is added to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerRuntimeState {
    /// `did_work` returned true — the loop processed at least one ring
    /// or packet.
    Active,
    /// No useful work this iteration; worker stayed in the short-spin
    /// path (idle_iters <= IDLE_SPIN_ITERS).
    IdleSpin,
    /// No useful work this iteration; worker entered interrupt-mode
    /// `poll()` or `sleep()`.
    IdleBlock,
}

/// #1782 Step-1 (§5.2 mechanism (ii)): per-cause v8 queue-lease
/// under-grant counters. A slot is bumped at the CoS guarantee
/// selector sites when, AFTER `maybe_top_up_cos_queue_lease`, the
/// queue still cannot send its head (`queue.hot.tokens < head_len`)
/// — attributed to the `AcquireV8ShortfallCause` the lease reported.
/// `None`-cause under-grants (legacy lease / no lease / transparent
/// queue / fully-granted acquire) are NOT counted here; they remain
/// visible in the pre-existing `drain_park_queue_tokens` counter,
/// of which these are a v8-attributed subset.
///
/// Plain u64s — accumulated worker-locally (zero atomics on the hot
/// path) and flushed to `WorkerRuntimeAtomics` at the existing ~1s
/// publish tick.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CoSQueueLeaseUndergrantCounters {
    pub seqlock_give_up: u64,
    pub cap_zero: u64,
    pub epoch_rotated: u64,
    pub share_exhausted: u64,
    pub class_cap: u64,
    pub outstanding_cap: u64,
}

impl CoSQueueLeaseUndergrantCounters {
    /// Element-wise wrapping accumulate (telemetry merge at the
    /// drain-pass flush and the per-binding publish-tick sum).
    #[inline]
    pub(crate) fn add_assign(&mut self, other: &Self) {
        self.seqlock_give_up = self.seqlock_give_up.wrapping_add(other.seqlock_give_up);
        self.cap_zero = self.cap_zero.wrapping_add(other.cap_zero);
        self.epoch_rotated = self.epoch_rotated.wrapping_add(other.epoch_rotated);
        self.share_exhausted = self.share_exhausted.wrapping_add(other.share_exhausted);
        self.class_cap = self.class_cap.wrapping_add(other.class_cap);
        self.outstanding_cap = self.outstanding_cap.wrapping_add(other.outstanding_cap);
    }
}

/// Per-worker cumulative counters, owned exclusively by the worker
/// thread.  No atomics here — the worker only contends with itself.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WorkerRuntimeCounters {
    pub wall_ns: u64,
    pub active_ns: u64,
    pub idle_spin_ns: u64,
    pub idle_block_ns: u64,
    pub thread_cpu_ns: u64,
    pub work_loops: u64,
    pub idle_loops: u64,
    /// #7919: the largest per-session volume (`fwd_packets + rev_packets`) this
    /// worker has ever seen on a FORWARD entry of its own session table, as a
    /// monotonic high-water mark. Sampled on the conntrack-mirror refresh walk,
    /// which already iterates the table on a budgeted slice — so this adds one
    /// compare per walked entry and NO new iteration, and nothing on the packet
    /// path.
    ///
    /// WHY IT EXISTS. Every worker holds a copy of every session (measured:
    /// `session_table_entries` reads 6 on all six workers for three flows), but
    /// only the worker whose packets land accounts for it — the replication
    /// types carry no counters field. So "which workers' tables ever hold
    /// volume" is the axis that separates the two live explanations for #7919's
    /// zeroed session counters: if only one worker ever sees volume, accounting
    /// is reaching only that worker; if every worker does, accounting is fine
    /// and the shared conntrack mirror is losing it.
    ///
    /// A high-water rather than a windowed max on purpose: the refresh walk is
    /// budgeted, so a single cycle may not visit every entry, and a per-cycle
    /// max would read 0 for a worker whose one busy session simply was not in
    /// that slice — a zero indistinguishable from "never accounted", which is
    /// the exact confusion this is built to resolve.
    pub session_volume_high_water: u64,
    pub cos_queue_lease_acquire_v8_calls: u64,
    pub cos_queue_lease_acquire_v8_granted_bytes: u64,
    /// #1782 Step-1 (§5.2 mechanism (i)): cumulative CoS timer-wheel
    /// ticks advanced by `advance_cos_timer_wheel` across this
    /// worker's bindings, and the largest single-call advance ever
    /// observed (a monotonic high-water mark, not a windowed max).
    /// One cold drain catching up a multi-minute idle lag shows up as
    /// a single multi-million-tick `max` sample, which pinned the
    /// §4(i) O(lag) catch-up mechanism conclusively (2,226,212 ticks
    /// in one call). #1782 Step-2: over-horizon advances are now
    /// snapped in O(slots) (`snap_cos_timer_wheel_over_horizon`), but
    /// both counters keep recording the TRUE lag (`now_tick -
    /// current_tick` at entry) on the snap path — a large `max` no
    /// longer implies an O(lag) wall cost.
    pub cos_wheel_ticks_advanced_total: u64,
    pub cos_wheel_ticks_advanced_max: u64,
    /// #1782 Step-1 (§5.2 mechanism (ii)): per-cause v8 queue-lease
    /// under-grant attribution. See `CoSQueueLeaseUndergrantCounters`.
    pub cos_queue_lease_undergrant: CoSQueueLeaseUndergrantCounters,
    /// Cumulative timer-wheel GC classifications for this worker's session table.
    pub session_gc_scanned: u64,
    pub session_gc_dropped_gone: u64,
    pub session_gc_dropped_stale: u64,
    pub session_gc_re_bucketed: u64,
    pub session_gc_held_standby: u64,
    pub session_gc_reaped_stale_synced: u64,
    pub session_gc_healed_on_promote: u64,
    pub session_gc_aged_owner_rg_zero_active_node: u64,
    pub session_gc_kept_alive_by_companion: u64,
    pub session_table_entries: u64,
    pub max_sessions: u64,
    /// #1760: cumulative NAT reverse-key displacement events from this
    /// worker's SessionTable (`SessionTable::nat_reverse_key_collisions`).
    pub nat_reverse_key_collisions: u64,
    /// #6751: the DIFFERENT-SOURCE subset of the counter above
    /// (`SessionTable::nat_reverse_key_collisions_distinct_src`). The
    /// aggregate cannot separate the cross-session leak this issue is about
    /// from one host reusing an ephemeral port; this one can.
    pub nat_reverse_key_collisions_distinct_src: u64,
    /// #1861: cumulative at-cap install refusals from this worker's
    /// SessionTable (`SessionTable::create_drops` — previously
    /// write-only/invisible).
    pub session_create_drops: u64,
    /// #7919: by-key session-lookup misses on this worker, split by cause —
    /// (no handle in the index, stale handle past the slab, handle resolving to
    /// a record whose key differs). Both `touch_if_stale` and `account_packet`
    /// bail SILENTLY on a miss, so a frozen `Pkts: 0` row was previously
    /// indistinguishable from a genuinely idle flow.
    pub session_lookup_miss_no_handle: u64,
    pub session_lookup_miss_stale_handle: u64,
    pub session_lookup_miss_key_mismatch: u64,
    /// #1861: cumulative pair-admission preflight refusals (one per
    /// refused flow) from `SessionTable::admission_refused`.
    pub session_install_admission_refused: u64,
    /// #1861: cumulative post-preflight partial-install residuals from
    /// `SessionTable::install_partial`. Expected 0 forever; nonzero
    /// means the preflight/install pairing has a bug.
    pub session_install_partial: u64,
    /// #4800: cumulative locally-learned transit forward-flow installs
    /// summed across this worker's bindings — the per-worker share of the
    /// SNAT-allocate / publish / replicate new-flow path. Skew across
    /// workers is how a connection-rate run distinguishes a single-core
    /// bound from a genuine cross-worker lock bound.
    pub new_flow_installs: u64,
}

/// 60 s rolling window. Sized to comfortably cover typical Prometheus
/// scrape intervals (15–30 s in this repo) with headroom and to give
/// operators a "current load" view distinct from the lifetime
/// cumulative counters above.
pub(crate) const WR_WINDOW_INTERVAL_NS: u64 = 60_000_000_000;

/// Last-completed rolling-window delta read by status callers. Empty
/// (window_ns == 0) until the worker has been alive long enough for the
/// first rotation to complete.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WorkerRuntimeWindow {
    pub wall_ns: u64,
    pub active_ns: u64,
    pub thread_cpu_ns: u64,
    pub window_ns: u64,
}

/// Cacheline-isolated atomic publish slot.  The worker copies its local
/// counters here on a ~1s cadence; the coordinator (or any status reader)
/// snapshots with `Ordering::Relaxed`.  One Atomic per field keeps
/// snapshots consistent within a field — cross-field tearing is
/// acceptable for the cumulative diagnostic counters.
///
/// The rolling-window fields (`wall_ns_60s`, `active_ns_60s`,
/// `thread_cpu_ns_60s`, `window_ns`) are published as a seqlock-style
/// atomic tuple guarded by `window_gen`. Writers `fetch_add(AcqRel)`
/// to enter the odd publishing state, Relaxed-store the four window
/// fields, then `fetch_add(Release)` back to an even committed state.
/// Readers `Acquire`-load `window_gen` (s1), Relaxed-load the four
/// data fields, issue a `fence(Acquire)` to seal those loads, then
/// Relaxed-load `window_gen` again (s2). If `s2 == s1` and even, the
/// four data fields were observed within a single committed epoch;
/// on retry exhaustion the reader returns `default()` so `statusfmt`
/// renders `-`. This is necessary because `store(Release)` does NOT
/// prevent subsequent Relaxed stores from being hoisted above it (PR
/// #1311 round-2 finding); a single Release-store fence is
/// insufficient to publish multiple Relaxed values as a coherent
/// tuple.
#[repr(align(64))]
pub(crate) struct WorkerRuntimeAtomics {
    pub wall_ns: AtomicU64,
    pub active_ns: AtomicU64,
    pub idle_spin_ns: AtomicU64,
    pub idle_block_ns: AtomicU64,
    pub thread_cpu_ns: AtomicU64,
    pub work_loops: AtomicU64,
    pub idle_loops: AtomicU64,
    /// #7919: monotonic high-water of per-session volume seen on the refresh
    /// walk. Relaxed cumulative slot like the CoS counters; NOT part of the
    /// seqlock rolling-window tuple.
    pub session_volume_high_water: AtomicU64,
    // ---------------------------------------------------------------------
    // #7919 per-session counter QUERY scratch. Not telemetry: these are the
    // reply slots for a diagnostic request/response, written by this worker
    // when it answers one and read by the control thread that asked.
    //
    // They live here rather than in a new per-worker Arc because this struct is
    // ALREADY Arc-shared per worker and already reachable from both sides —
    // adding a second channel for six u64s would be plumbing without a
    // property. They are declared DELIBERATELY_OFF_WIRE in the #6961 guard for
    // exactly the reason that guard exists: they are not a series, and mapping
    // them onto one would report a diagnostic reply as a metric.
    //
    // PUBLICATION ORDER IS THE CONTRACT. The answer fields are written FIRST,
    // then `counter_query_seq` with Release; the reader loads the seq with
    // Acquire and only then reads the answers. The sequence IS the ack — there
    // is no separate completion flag to disagree with it.
    /// Sequence of the query this worker has ANSWERED. 0 = never answered.
    pub counter_query_seq: AtomicU64,
    /// 1 when the queried key was present in this worker's table, else 0.
    /// Distinguishes "this worker holds the session and it has no traffic"
    /// from "this worker does not hold it" — the two are different facts and
    /// collapsing them would answer the question this query exists to ask.
    pub counter_query_found: AtomicU64,
    pub counter_query_fwd_packets: AtomicU64,
    pub counter_query_fwd_bytes: AtomicU64,
    pub counter_query_rev_packets: AtomicU64,
    pub counter_query_rev_bytes: AtomicU64,
    /// 1 when the found entry is a peer-synced/replica origin (`is_peer_synced`),
    /// else 0. A replica that reports volume would falsify the premise behind
    /// the whole investigation (replicas are created at zero and cannot
    /// advance), so the answer carries what it would take to notice.
    pub counter_query_replica: AtomicU64,
    pub cos_queue_lease_acquire_v8_calls: AtomicU64,
    pub cos_queue_lease_acquire_v8_granted_bytes: AtomicU64,
    /// #1782 Step-1 (i): timer-wheel tick-advance sum + single-call
    /// high-water max. Simple Relaxed cumulative slots (like
    /// `cos_queue_lease_acquire_v8_calls`); NOT part of the seqlock
    /// rolling-window tuple.
    pub cos_wheel_ticks_advanced_total: AtomicU64,
    pub cos_wheel_ticks_advanced_max: AtomicU64,
    /// #1782 Step-1 (ii): per-cause v8 queue-lease under-grant slots.
    pub cos_queue_lease_undergrant_seqlock_give_up: AtomicU64,
    pub cos_queue_lease_undergrant_cap_zero: AtomicU64,
    pub cos_queue_lease_undergrant_epoch_rotated: AtomicU64,
    pub cos_queue_lease_undergrant_share_exhausted: AtomicU64,
    pub cos_queue_lease_undergrant_class_cap: AtomicU64,
    pub cos_queue_lease_undergrant_outstanding_cap: AtomicU64,
    pub session_table_entries: AtomicU64,
    pub max_sessions: AtomicU64,
    pub session_gc_scanned: AtomicU64,
    pub session_gc_dropped_gone: AtomicU64,
    pub session_gc_dropped_stale: AtomicU64,
    pub session_gc_re_bucketed: AtomicU64,
    pub session_gc_held_standby: AtomicU64,
    pub session_gc_reaped_stale_synced: AtomicU64,
    pub session_gc_healed_on_promote: AtomicU64,
    pub session_gc_aged_owner_rg_zero_active_node: AtomicU64,
    pub session_gc_kept_alive_by_companion: AtomicU64,
    /// #1760: cumulative NAT reverse-key displacement events. Simple
    /// Relaxed cumulative counter (like `session_table_entries`), NOT part
    /// of the seqlock-published rolling-window tuple below.
    pub nat_reverse_key_collisions: AtomicU64,
    pub nat_reverse_key_collisions_distinct_src: AtomicU64,
    /// #1861: install-refusal trio (same Relaxed cumulative pattern).
    pub session_create_drops: AtomicU64,
    pub session_lookup_miss_no_handle: AtomicU64,
    pub session_lookup_miss_stale_handle: AtomicU64,
    pub session_lookup_miss_key_mismatch: AtomicU64,
    pub session_install_admission_refused: AtomicU64,
    pub session_install_partial: AtomicU64,
    /// #4800: per-worker transit new-flow installs (same Relaxed
    /// cumulative pattern as the trio above).
    pub new_flow_installs: AtomicU64,
    /// Snapshot of the corresponding cumulative counter at the start of
    /// the current rolling window, plus the monotonic timestamp the
    /// snapshot was taken at. `publish()` rotates these whenever the
    /// elapsed wall window since the last rotation reaches
    /// `WR_WINDOW_INTERVAL_NS`. The displayed "last ~60s" value is the
    /// difference between the live cumulative counter and the snapshot
    /// below. Under the normal ~1 Hz publish cadence the rotated
    /// window is ~60–61s wide (one publish-tick of overshoot past the
    /// 60s threshold); if publishing stalls the window can be wider,
    /// and `window_ns` always carries the exact measured width so
    /// downstream rate math is honest regardless of cadence.
    pub wall_ns_window_base: AtomicU64,
    pub active_ns_window_base: AtomicU64,
    pub thread_cpu_ns_window_base: AtomicU64,
    pub window_base_at_ns: AtomicU64,
    pub wall_ns_60s: AtomicU64,
    pub active_ns_60s: AtomicU64,
    pub thread_cpu_ns_60s: AtomicU64,
    pub window_ns: AtomicU64,
    /// Seqlock-style generation counter for the rolling-window publication.
    /// Writers increment from even to odd before publishing the four window
    /// fields, then from odd to even after. Readers spin until they observe
    /// an even generation that is stable across all four field loads, so
    /// they never pair a fresh `thread_cpu_ns_60s` with a stale `window_ns`.
    pub window_gen: AtomicU64,
    pub tid: AtomicU64,
    /// #925 Phase 1+2 (catch+report+observe): set to true exactly once
    /// when the supervisor catches a worker_loop panic. Set-only today —
    /// cleared only by daemon restart. Phase 2 added the
    /// `xpf_userspace_worker_dead` Prometheus gauge that reads this flag
    /// via the JSON status wire (xpfCollector → control-socket status).
    /// A hypothetical Phase 3 (respawn, deferred indefinitely) would
    /// clear this by replacing WorkerRuntimeAtomics on relaunch.
    /// Adding this flag pushes the struct from 64 B → 128 B due to
    /// `#[repr(align(64))]` rounding; cost is negligible (a few hundred
    /// bytes total across all workers).
    pub dead: AtomicBool,
    /// #6979: has this worker's NAT holder bits already been reclaimed?
    ///
    /// A one-shot latch, not a second liveness flag. `dead` says the worker will
    /// never run another release; this says the sweep that acts on that has
    /// already run. Without it the retirement would repeat on every 1 Hz status
    /// tick, walking `live_by_flow` under each allocator's mutex forever — the
    /// exact hazard `PortAllocator::retire_worker`'s doc named as the reason its
    /// call site was left unchosen.
    ///
    /// Set with `compare_exchange`, so concurrent tickers cannot both sweep.
    /// Never cleared: a respawn would replace the whole `WorkerRuntimeAtomics`,
    /// which is how `dead` is already specified to reset.
    pub holders_retired: AtomicBool,
    /// Cacheline padding after the atomics so that adjacent workers in
    /// a `Vec<WorkerRuntimeAtomics>` don't false-share.
    _pad: [u8; 0],
}

impl WorkerRuntimeAtomics {
    pub fn new() -> Self {
        Self {
            wall_ns: AtomicU64::new(0),
            active_ns: AtomicU64::new(0),
            idle_spin_ns: AtomicU64::new(0),
            idle_block_ns: AtomicU64::new(0),
            thread_cpu_ns: AtomicU64::new(0),
            work_loops: AtomicU64::new(0),
            idle_loops: AtomicU64::new(0),
            session_volume_high_water: AtomicU64::new(0),
            counter_query_seq: AtomicU64::new(0),
            counter_query_found: AtomicU64::new(0),
            counter_query_fwd_packets: AtomicU64::new(0),
            counter_query_fwd_bytes: AtomicU64::new(0),
            counter_query_rev_packets: AtomicU64::new(0),
            counter_query_rev_bytes: AtomicU64::new(0),
            counter_query_replica: AtomicU64::new(0),
            cos_queue_lease_acquire_v8_calls: AtomicU64::new(0),
            cos_queue_lease_acquire_v8_granted_bytes: AtomicU64::new(0),
            cos_wheel_ticks_advanced_total: AtomicU64::new(0),
            cos_wheel_ticks_advanced_max: AtomicU64::new(0),
            cos_queue_lease_undergrant_seqlock_give_up: AtomicU64::new(0),
            cos_queue_lease_undergrant_cap_zero: AtomicU64::new(0),
            cos_queue_lease_undergrant_epoch_rotated: AtomicU64::new(0),
            cos_queue_lease_undergrant_share_exhausted: AtomicU64::new(0),
            cos_queue_lease_undergrant_class_cap: AtomicU64::new(0),
            cos_queue_lease_undergrant_outstanding_cap: AtomicU64::new(0),
            session_table_entries: AtomicU64::new(0),
            max_sessions: AtomicU64::new(0),
            session_gc_scanned: AtomicU64::new(0),
            session_gc_dropped_gone: AtomicU64::new(0),
            session_gc_dropped_stale: AtomicU64::new(0),
            session_gc_re_bucketed: AtomicU64::new(0),
            session_gc_held_standby: AtomicU64::new(0),
            session_gc_reaped_stale_synced: AtomicU64::new(0),
            session_gc_healed_on_promote: AtomicU64::new(0),
            session_gc_aged_owner_rg_zero_active_node: AtomicU64::new(0),
            session_gc_kept_alive_by_companion: AtomicU64::new(0),
            nat_reverse_key_collisions: AtomicU64::new(0),
            nat_reverse_key_collisions_distinct_src: AtomicU64::new(0),
            session_create_drops: AtomicU64::new(0),
            session_lookup_miss_no_handle: AtomicU64::new(0),
            session_lookup_miss_stale_handle: AtomicU64::new(0),
            session_lookup_miss_key_mismatch: AtomicU64::new(0),
            session_install_admission_refused: AtomicU64::new(0),
            session_install_partial: AtomicU64::new(0),
            new_flow_installs: AtomicU64::new(0),
            wall_ns_window_base: AtomicU64::new(0),
            active_ns_window_base: AtomicU64::new(0),
            thread_cpu_ns_window_base: AtomicU64::new(0),
            window_base_at_ns: AtomicU64::new(0),
            wall_ns_60s: AtomicU64::new(0),
            active_ns_60s: AtomicU64::new(0),
            thread_cpu_ns_60s: AtomicU64::new(0),
            window_ns: AtomicU64::new(0),
            window_gen: AtomicU64::new(0),
            tid: AtomicU64::new(0),
            dead: AtomicBool::new(false),
            holders_retired: AtomicBool::new(false),
            _pad: [],
        }
    }

    /// Publish a full snapshot of the worker's local counters.  Called
    /// on the ~1s publish cadence; NOT called per iteration. `now_ns`
    /// is the monotonic clock at publish time, used to rotate the
    /// rolling 60s window.
    pub fn publish(&self, c: &WorkerRuntimeCounters, now_ns: u64) {
        self.wall_ns.store(c.wall_ns, Ordering::Relaxed);
        self.active_ns.store(c.active_ns, Ordering::Relaxed);
        self.idle_spin_ns.store(c.idle_spin_ns, Ordering::Relaxed);
        self.idle_block_ns.store(c.idle_block_ns, Ordering::Relaxed);
        self.thread_cpu_ns.store(c.thread_cpu_ns, Ordering::Relaxed);
        self.work_loops.store(c.work_loops, Ordering::Relaxed);
        self.idle_loops.store(c.idle_loops, Ordering::Relaxed);
        self.session_volume_high_water
            .store(c.session_volume_high_water, Ordering::Relaxed);
        self.cos_queue_lease_acquire_v8_calls
            .store(c.cos_queue_lease_acquire_v8_calls, Ordering::Relaxed);
        self.cos_queue_lease_acquire_v8_granted_bytes.store(
            c.cos_queue_lease_acquire_v8_granted_bytes,
            Ordering::Relaxed,
        );
        // #1782 Step-1 publish: simple Relaxed stores on the existing
        // ~1s cadence, same tolerance as the other cumulative slots.
        self.cos_wheel_ticks_advanced_total
            .store(c.cos_wheel_ticks_advanced_total, Ordering::Relaxed);
        self.cos_wheel_ticks_advanced_max
            .store(c.cos_wheel_ticks_advanced_max, Ordering::Relaxed);
        let ug = &c.cos_queue_lease_undergrant;
        self.cos_queue_lease_undergrant_seqlock_give_up
            .store(ug.seqlock_give_up, Ordering::Relaxed);
        self.cos_queue_lease_undergrant_cap_zero
            .store(ug.cap_zero, Ordering::Relaxed);
        self.cos_queue_lease_undergrant_epoch_rotated
            .store(ug.epoch_rotated, Ordering::Relaxed);
        self.cos_queue_lease_undergrant_share_exhausted
            .store(ug.share_exhausted, Ordering::Relaxed);
        self.cos_queue_lease_undergrant_class_cap
            .store(ug.class_cap, Ordering::Relaxed);
        self.cos_queue_lease_undergrant_outstanding_cap
            .store(ug.outstanding_cap, Ordering::Relaxed);
        // Publish denominator before numerator so a torn multi-worker read can
        // under-report briefly, but cannot show entries without capacity.
        self.max_sessions.store(c.max_sessions, Ordering::Relaxed);
        self.session_table_entries
            .store(c.session_table_entries, Ordering::Relaxed);
        self.session_gc_scanned
            .store(c.session_gc_scanned, Ordering::Relaxed);
        self.session_gc_dropped_gone
            .store(c.session_gc_dropped_gone, Ordering::Relaxed);
        self.session_gc_dropped_stale
            .store(c.session_gc_dropped_stale, Ordering::Relaxed);
        self.session_gc_re_bucketed
            .store(c.session_gc_re_bucketed, Ordering::Relaxed);
        self.session_gc_held_standby
            .store(c.session_gc_held_standby, Ordering::Relaxed);
        self.session_gc_reaped_stale_synced
            .store(c.session_gc_reaped_stale_synced, Ordering::Relaxed);
        self.session_gc_healed_on_promote
            .store(c.session_gc_healed_on_promote, Ordering::Relaxed);
        self.session_gc_aged_owner_rg_zero_active_node.store(
            c.session_gc_aged_owner_rg_zero_active_node,
            Ordering::Relaxed,
        );
        self.session_gc_kept_alive_by_companion
            .store(c.session_gc_kept_alive_by_companion, Ordering::Relaxed);
        self.nat_reverse_key_collisions
            .store(c.nat_reverse_key_collisions, Ordering::Relaxed);
        self.nat_reverse_key_collisions_distinct_src
            .store(c.nat_reverse_key_collisions_distinct_src, Ordering::Relaxed);
        // #1861: install-refusal trio, same Relaxed cumulative cadence.
        self.session_create_drops
            .store(c.session_create_drops, Ordering::Relaxed);
        self.session_lookup_miss_no_handle
            .store(c.session_lookup_miss_no_handle, Ordering::Relaxed);
        self.session_lookup_miss_stale_handle
            .store(c.session_lookup_miss_stale_handle, Ordering::Relaxed);
        self.session_lookup_miss_key_mismatch
            .store(c.session_lookup_miss_key_mismatch, Ordering::Relaxed);
        self.session_install_admission_refused
            .store(c.session_install_admission_refused, Ordering::Relaxed);
        self.session_install_partial
            .store(c.session_install_partial, Ordering::Relaxed);
        // #4800: per-worker transit new-flow installs.
        self.new_flow_installs
            .store(c.new_flow_installs, Ordering::Relaxed);

        let base_at = self.window_base_at_ns.load(Ordering::Relaxed);
        if base_at == 0 {
            self.wall_ns_window_base.store(c.wall_ns, Ordering::Relaxed);
            self.active_ns_window_base
                .store(c.active_ns, Ordering::Relaxed);
            self.thread_cpu_ns_window_base
                .store(c.thread_cpu_ns, Ordering::Relaxed);
            self.window_base_at_ns.store(now_ns, Ordering::Relaxed);
        } else if now_ns.saturating_sub(base_at) >= WR_WINDOW_INTERVAL_NS {
            let prev_wall = self.wall_ns_window_base.load(Ordering::Relaxed);
            let prev_active = self.active_ns_window_base.load(Ordering::Relaxed);
            let prev_cpu = self.thread_cpu_ns_window_base.load(Ordering::Relaxed);
            let new_window = now_ns.saturating_sub(base_at);
            let new_wall_delta = c.wall_ns.saturating_sub(prev_wall);
            let new_active_delta = c.active_ns.saturating_sub(prev_active);
            let new_cpu_delta = c.thread_cpu_ns.saturating_sub(prev_cpu);

            // Seqlock publication. `fetch_add(1, AcqRel)` bumps the
            // generation from even to odd as a single atomic RMW; the
            // Acquire side of AcqRel forbids subsequent Relaxed stores
            // from being hoisted above this point. Readers that load an
            // odd generation must retry. A plain `store(Release)` would
            // NOT be sufficient here: Release is a one-way barrier that
            // prevents PRIOR ops from sinking past, but it allows
            // SUBSEQUENT Relaxed stores to be hoisted above it on
            // weakly-ordered CPUs (ARM, POWER), which is exactly the
            // hole flagged by PR #1311 round-2 review.
            self.window_gen.fetch_add(1, Ordering::AcqRel);
            self.wall_ns_60s.store(new_wall_delta, Ordering::Relaxed);
            self.active_ns_60s
                .store(new_active_delta, Ordering::Relaxed);
            self.thread_cpu_ns_60s
                .store(new_cpu_delta, Ordering::Relaxed);
            self.window_ns.store(new_window, Ordering::Relaxed);
            // Bump back to even with Release. Any reader that
            // Acquire-loads the new even generation observes all four
            // field stores above.
            self.window_gen.fetch_add(1, Ordering::Release);

            self.wall_ns_window_base.store(c.wall_ns, Ordering::Relaxed);
            self.active_ns_window_base
                .store(c.active_ns, Ordering::Relaxed);
            self.thread_cpu_ns_window_base
                .store(c.thread_cpu_ns, Ordering::Relaxed);
            self.window_base_at_ns.store(now_ns, Ordering::Relaxed);
        }
    }

    /// Snapshot for status readers.  Not atomic across fields — each
    /// field is `Relaxed`-loaded individually.
    pub fn snapshot(&self) -> WorkerRuntimeCounters {
        WorkerRuntimeCounters {
            wall_ns: self.wall_ns.load(Ordering::Relaxed),
            active_ns: self.active_ns.load(Ordering::Relaxed),
            idle_spin_ns: self.idle_spin_ns.load(Ordering::Relaxed),
            idle_block_ns: self.idle_block_ns.load(Ordering::Relaxed),
            thread_cpu_ns: self.thread_cpu_ns.load(Ordering::Relaxed),
            work_loops: self.work_loops.load(Ordering::Relaxed),
            idle_loops: self.idle_loops.load(Ordering::Relaxed),
            session_volume_high_water: self.session_volume_high_water.load(Ordering::Relaxed),
            cos_queue_lease_acquire_v8_calls: self
                .cos_queue_lease_acquire_v8_calls
                .load(Ordering::Relaxed),
            cos_queue_lease_acquire_v8_granted_bytes: self
                .cos_queue_lease_acquire_v8_granted_bytes
                .load(Ordering::Relaxed),
            cos_wheel_ticks_advanced_total: self
                .cos_wheel_ticks_advanced_total
                .load(Ordering::Relaxed),
            cos_wheel_ticks_advanced_max: self.cos_wheel_ticks_advanced_max.load(Ordering::Relaxed),
            cos_queue_lease_undergrant: CoSQueueLeaseUndergrantCounters {
                seqlock_give_up: self
                    .cos_queue_lease_undergrant_seqlock_give_up
                    .load(Ordering::Relaxed),
                cap_zero: self
                    .cos_queue_lease_undergrant_cap_zero
                    .load(Ordering::Relaxed),
                epoch_rotated: self
                    .cos_queue_lease_undergrant_epoch_rotated
                    .load(Ordering::Relaxed),
                share_exhausted: self
                    .cos_queue_lease_undergrant_share_exhausted
                    .load(Ordering::Relaxed),
                class_cap: self
                    .cos_queue_lease_undergrant_class_cap
                    .load(Ordering::Relaxed),
                outstanding_cap: self
                    .cos_queue_lease_undergrant_outstanding_cap
                    .load(Ordering::Relaxed),
            },
            session_table_entries: self.session_table_entries.load(Ordering::Relaxed),
            max_sessions: self.max_sessions.load(Ordering::Relaxed),
            nat_reverse_key_collisions: self.nat_reverse_key_collisions.load(Ordering::Relaxed),
            nat_reverse_key_collisions_distinct_src: self
                .nat_reverse_key_collisions_distinct_src
                .load(Ordering::Relaxed),
            session_create_drops: self.session_create_drops.load(Ordering::Relaxed),
            session_lookup_miss_no_handle: self
                .session_lookup_miss_no_handle
                .load(Ordering::Relaxed),
            session_lookup_miss_stale_handle: self
                .session_lookup_miss_stale_handle
                .load(Ordering::Relaxed),
            session_lookup_miss_key_mismatch: self
                .session_lookup_miss_key_mismatch
                .load(Ordering::Relaxed),
            session_install_admission_refused: self
                .session_install_admission_refused
                .load(Ordering::Relaxed),
            session_install_partial: self.session_install_partial.load(Ordering::Relaxed),
            session_gc_scanned: self.session_gc_scanned.load(Ordering::Relaxed),
            session_gc_dropped_gone: self.session_gc_dropped_gone.load(Ordering::Relaxed),
            session_gc_dropped_stale: self.session_gc_dropped_stale.load(Ordering::Relaxed),
            session_gc_re_bucketed: self.session_gc_re_bucketed.load(Ordering::Relaxed),
            session_gc_held_standby: self.session_gc_held_standby.load(Ordering::Relaxed),
            session_gc_reaped_stale_synced: self
                .session_gc_reaped_stale_synced
                .load(Ordering::Relaxed),
            session_gc_healed_on_promote: self.session_gc_healed_on_promote.load(Ordering::Relaxed),
            session_gc_aged_owner_rg_zero_active_node: self
                .session_gc_aged_owner_rg_zero_active_node
                .load(Ordering::Relaxed),
            session_gc_kept_alive_by_companion: self
                .session_gc_kept_alive_by_companion
                .load(Ordering::Relaxed),
            new_flow_installs: self.new_flow_installs.load(Ordering::Relaxed),
        }
    }

    /// Snapshot the rolling 60s window for status readers. `window_ns`
    /// is zero until the first rotation completes (i.e. for the first
    /// ~60s of the worker's lifetime) AND transiently while `publish()`
    /// rotates the window; callers should render "-" in that case
    /// rather than computing a percentage from a zero denominator.
    pub fn snapshot_window(&self) -> WorkerRuntimeWindow {
        // Seqlock read: spin until we observe an even generation that's
        // stable across all four field loads. Bound the retry count so a
        // pathological writer can't starve the reader; on giveup, return
        // default() so statusfmt renders "-" instead of a torn tuple.
        //
        // Under the normal ~1Hz publishing cadence and ~ns-µs writer
        // publication time, the reader will almost always succeed on
        // the first iteration. The retry loop is correctness scaffolding
        // for hostile interleaving, not normal-case throughput.
        //
        // Memory-ordering note for the generation check:
        // ARM's Load-Acquire (ldar) is a one-way forward barrier: it
        // prevents *subsequent* operations from being reordered before
        // it, but does NOT prevent *prior* Relaxed loads from being
        // reordered *past* it. Without an explicit fence, the four
        // Relaxed data loads below could migrate past s2's load in the
        // CPU's out-of-order execution, allowing a torn snapshot to
        // escape the s1==s2 guard. The fence(Acquire) between the data
        // loads and s2 emits `dmb ishld` on ARM (a load-load barrier;
        // bidirectional for loads but does not order stores), ensuring
        // all four Relaxed loads complete before s2 is observed. Two
        // orthogonal guarantees work together: s1's
        // Acquire provides visibility of data written before the
        // writer's Release that produced s1's value; the fence prevents
        // those data loads from physically executing after s2 in the
        // CPU's out-of-order trace, closing the window where a new
        // writer epoch could sneak in between s2 and the data reads.
        for _ in 0..16 {
            let s1 = self.window_gen.load(Ordering::Acquire);
            if s1 & 1 != 0 {
                // Writer mid-publish; back off and retry.
                std::hint::spin_loop();
                continue;
            }
            let window_ns = self.window_ns.load(Ordering::Relaxed);
            let wall_ns = self.wall_ns_60s.load(Ordering::Relaxed);
            let active_ns = self.active_ns_60s.load(Ordering::Relaxed);
            let thread_cpu_ns = self.thread_cpu_ns_60s.load(Ordering::Relaxed);
            // Seal the four data loads before the generation re-check.
            // Without this fence, prior Relaxed loads can be reordered
            // past the s2 Relaxed load on weakly-ordered CPUs (ARM,
            // POWER), allowing a torn snapshot to pass the s1==s2 guard.
            // This fence is orthogonal to s1's Acquire: s1's Acquire
            // ensures data written before the writer's Release(s1) is
            // visible to all loads sequenced after s1 in program order;
            // the fence here prevents those loads from physically
            // executing after s2 in the CPU's out-of-order trace, which
            // would let a new writer epoch sneak in between s2 and the
            // data reads without updating s2.
            std::sync::atomic::fence(Ordering::Acquire);
            let s2 = self.window_gen.load(Ordering::Relaxed);
            if s2 == s1 {
                return WorkerRuntimeWindow {
                    wall_ns,
                    active_ns,
                    thread_cpu_ns,
                    window_ns,
                };
            }
            std::hint::spin_loop();
        }
        // Pathological retry exhaustion → return zeros so statusfmt
        // renders "-".
        WorkerRuntimeWindow::default()
    }

    pub fn set_tid(&self, tid: u64) {
        self.tid.store(tid, Ordering::Relaxed);
    }

    pub fn tid(&self) -> u64 {
        self.tid.load(Ordering::Relaxed)
    }
}

impl Default for WorkerRuntimeAtomics {
    fn default() -> Self {
        Self::new()
    }
}

/// Sample CLOCK_THREAD_CPUTIME_ID for the calling thread.  Returns 0 on
/// syscall failure — diagnostic counters treat that as "no sample this
/// cadence" rather than propagating the error.
pub(crate) fn sample_thread_cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime with a valid clock id + writable timespec
    // is defined behavior.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64).saturating_mul(1_000_000_000) + (ts.tv_nsec as u64)
}

/// Return the calling thread's kernel TID (`gettid`) as u64.  Used in
/// status output so operators can correlate telemetry with `top -H`.
/// Returns 0 on syscall failure so a wrapped -1 sentinel never escapes
/// to Prometheus or the CLI.
pub(crate) fn current_tid() -> u64 {
    // SAFETY: gettid is a pure syscall with no arguments.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    if tid < 0 {
        return 0;
    }
    tid as u64
}

#[cfg(test)]
#[path = "worker_runtime_tests.rs"]
mod tests;
