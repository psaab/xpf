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
    pub cos_queue_lease_acquire_v8_calls: u64,
    pub cos_queue_lease_acquire_v8_granted_bytes: u64,
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
    pub cos_queue_lease_acquire_v8_calls: AtomicU64,
    pub cos_queue_lease_acquire_v8_granted_bytes: AtomicU64,
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
            cos_queue_lease_acquire_v8_calls: AtomicU64::new(0),
            cos_queue_lease_acquire_v8_granted_bytes: AtomicU64::new(0),
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
        self.cos_queue_lease_acquire_v8_calls
            .store(c.cos_queue_lease_acquire_v8_calls, Ordering::Relaxed);
        self.cos_queue_lease_acquire_v8_granted_bytes.store(
            c.cos_queue_lease_acquire_v8_granted_bytes,
            Ordering::Relaxed,
        );

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
            self.active_ns_60s.store(new_active_delta, Ordering::Relaxed);
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
            cos_queue_lease_acquire_v8_calls: self
                .cos_queue_lease_acquire_v8_calls
                .load(Ordering::Relaxed),
            cos_queue_lease_acquire_v8_granted_bytes: self
                .cos_queue_lease_acquire_v8_granted_bytes
                .load(Ordering::Relaxed),
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
