use super::*;

/// One proactive neighbor-warm request (#1636 option C). Carries the
/// egress ifindex + next-hop to solicit, the interface name used by
/// `trigger_kernel_arp_probe`, the snapshot `generation` it was queued
/// under (for generation-collapse on dequeue), and the owning routing
/// group `rg_id` (per-RG HA gate: only warm when this node is forwarding
/// for that RG).
#[derive(Clone, Debug)]
pub(crate) struct WarmItem {
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) hop: IpAddr,
    pub(in crate::afxdp) iface_name: String,
    pub(in crate::afxdp) generation: u64,
    pub(in crate::afxdp) rg_id: i32,
}

/// Bounded depth of the warm queue. Exceeds typical FRR snapshot route
/// counts (a handful to dozens) by a wide margin; on overflow the new
/// item is dropped and `warm_drops` is incremented.
pub(in crate::afxdp) const WARM_QUEUE_DEPTH: usize = 4096;

/// Per-key rate-limit window: skip re-warming the same (ifindex, hop)
/// within this window. Bounds wire-side solicit storms and socket churn
/// for permanently-unreachable next-hops.
pub(in crate::afxdp) const WARM_PER_KEY_RATE_LIMIT_NS: u64 = 5_000_000_000;

/// Snapshot-level rate-limit: skip the whole warm sweep if the last
/// admitted (non-forced) sweep was within this window. Coalesces a
/// config storm down to at most one sweep per second.
pub(in crate::afxdp) const WARM_SWEEP_RATE_LIMIT_NS: u64 = 1_000_000_000;

/// `last_probed_at` GC cadence + max entry age. The warmer loop prunes
/// keys older than `WARM_GC_MAX_AGE_NS` every `WARM_GC_INTERVAL_NS`.
pub(in crate::afxdp) const WARM_GC_INTERVAL_NS: u64 = 60_000_000_000;
pub(in crate::afxdp) const WARM_GC_MAX_AGE_NS: u64 = 300_000_000_000;

pub(crate) struct NeighborManager {
    pub(crate) dynamic: Arc<ShardedNeighborMap>,
    pub(crate) generation: Arc<AtomicU64>,
    /// #6034: highest authoritative manager-neighbor REPLACE generation
    /// applied so far. The Go manager stamps a monotonically increasing
    /// `neighbor_generation` on every `update_neighbors` replace;
    /// `apply_manager_neighbors` REJECTS a replace whose generation is
    /// <= this value (stale / reordered delivery must not clobber a newer
    /// table) and advances it on accept. 0 = no versioned replace applied
    /// yet; a generation-0 (unversioned / pre-#6034) push bypasses the
    /// fence and never advances it.
    pub(crate) applied_manager_generation: Arc<AtomicU64>,
    pub(crate) manager_keys: Arc<Mutex<FastSet<(i32, IpAddr)>>>,
    pub(crate) monitor_stop: Option<Arc<AtomicBool>>,
    /// #5165: join handle for the neighbor-monitor thread. Retained (like the
    /// sibling `resolver_join`, no longer discarded via `.ok()`) so `stop_inner`
    /// can JOIN the monitor after signalling stop — joining is what enforces the
    /// no-mutation-after-stop invariant that the loop's stop re-check alone
    /// cannot: a retired old-generation monitor blocked in `recv()` could
    /// otherwise apply a queued kernel neighbor event to `dynamic` AFTER a
    /// reconcile cleared the map and a fresh baseline repopulated it. Join
    /// latency is bounded by the monitor's 500ms `SO_RCVTIMEO` (the same bound
    /// the resolver's 500ms recv timeout provides).
    pub(crate) monitor_join: Option<std::thread::JoinHandle<()>>,
    // #1636 option C: proactive neighbor warming.
    /// Per-(ifindex, hop) last-probe timestamp (monotonic ns) for the
    /// 5s per-key rate-limit. Shared with the warmer worker thread.
    pub(crate) last_probed_at: Arc<Mutex<FastMap<(i32, IpAddr), u64>>>,
    /// Producer handle into the warmer worker's bounded queue. `None`
    /// until the worker is spawned at coordinator bring-up.
    pub(crate) warm_queue: Option<SyncSender<WarmItem>>,
    /// Stop flag for the warmer worker thread.
    pub(crate) warm_stop: Option<Arc<AtomicBool>>,
    /// #6314: join handle for the neighbor-warmer thread. Retained (like the
    /// sibling `monitor_join` / `resolver_join`, no longer discarded via
    /// `.ok()`) so `stop_inner` can JOIN the warmer after signalling `warm_stop`
    /// and dropping the producer — joining is what enforces the
    /// no-mutation-after-stop invariant the bare stop store cannot: a detached
    /// warmer blocked in `recv_timeout` could otherwise fire one stray ARP/NDP
    /// solicit or mutate `last_probed_at` AFTER a reconcile tore the dataplane
    /// down. Join latency is bounded by the warmer loop's 500ms recv timeout
    /// (the same bound the monitor's `SO_RCVTIMEO` and the resolver's recv
    /// timeout provide).
    pub(crate) warm_join: Option<std::thread::JoinHandle<()>>,
    /// Bumped on each admitted warm sweep; items tagged with a stale
    /// generation are dropped on dequeue (generation collapse).
    pub(crate) warm_generation: Arc<AtomicU64>,
    /// Monotonic ns of the last admitted (non-forced) warm sweep, for
    /// the 1s snapshot-level rate-limit. AtomicU64 so `queue_warm_pass`
    /// can take `&self` and be called from both `refresh_runtime_snapshot`
    /// (`&mut self`) and the RG-promote path.
    pub(crate) last_warm_sweep_ns: Arc<AtomicU64>,
    /// Channel-full drop telemetry (Prometheus `warm_drops`).
    pub(crate) warm_drops: Arc<AtomicU64>,
    /// Worker-disconnected telemetry (Prometheus `warm_disconnected`).
    pub(crate) warm_disconnected: Arc<AtomicU64>,
    /// Once-only operator-visible log gate for the disconnect transition.
    pub(crate) warned_disconnect: Arc<AtomicBool>,
    // #1769: shared on-demand neighbor resolver.
    /// Resolver handle (producer + counters) cloned into each worker so
    /// the negative-cache fast-fail can enqueue an on-demand GET/probe.
    /// `None` until the resolver thread is spawned at coordinator
    /// bring-up.
    pub(crate) resolver: Option<Arc<super::super::neighbor_resolver::NeighborResolver>>,
    /// Shared resolver counters (queue depth gauge + GET/probe/epoch
    /// telemetry), surfaced to Prometheus.
    pub(crate) resolver_counters: Arc<super::super::neighbor_resolver::ResolverCounters>,
    // #1772: neighbor/ARP resolution LATENCY histograms (observability-
    // only). Shared aggregate (one set of atomics across all workers +
    // the resolver thread); see neighbor_latency.rs for the design.
    /// pending_neigh dwell-time histogram: `now_ns - pkt.queued_ns` when
    /// a buffered packet is finally resolved + dispatched in
    /// `retry_pending_neigh`. THE key #1772 metric.
    pub(crate) pending_dwell_hist: Arc<super::super::neighbor_latency::NeighborLatencyHist>,
    /// Resolver single-key RTM_GETNEIGH round-trip-time histogram
    /// (request sent → reply read), measured on the resolver thread.
    pub(crate) resolver_get_rtt_hist: Arc<super::super::neighbor_latency::NeighborLatencyHist>,
    /// pending_neigh packets dropped after exceeding PENDING_NEIGH_TIMEOUT
    /// (never resolved within the window). Monotonic counter.
    pub(crate) pending_timeout_drops: Arc<AtomicU64>,
    /// High-water mark of `binding.pending_neigh.len()` observed at any
    /// retry-sweep entry across all bindings (gauge).
    pub(crate) pending_max_depth: Arc<AtomicU64>,
    /// Stop flag for the resolver worker thread.
    pub(crate) resolver_stop: Option<Arc<AtomicBool>>,
    /// Join handle for the resolver worker thread. Retained (like the sibling
    /// `monitor_join` (#5165) and `warm_join` (#6314) — all three neighbor aux
    /// threads are now retained + joined) so `stop_inner` can JOIN it after
    /// signalling stop — this enforces the no-mutation-after-stop invariant the
    /// bare stop re-check cannot (a detached resolver could otherwise mutate
    /// `dynamic_neighbors` after a reconcile spawned a fresh one). Join latency
    /// is bounded by the 500ms recv timeout + the 200ms GET timeout.
    pub(crate) resolver_join: Option<std::thread::JoinHandle<()>>,
}

impl NeighborManager {
    pub(super) fn new() -> Self {
        Self {
            dynamic: Arc::new(ShardedNeighborMap::new()),
            generation: Arc::new(AtomicU64::new(0)),
            applied_manager_generation: Arc::new(AtomicU64::new(0)),
            manager_keys: Arc::new(Mutex::new(FastSet::default())),
            monitor_stop: None,
            monitor_join: None,
            last_probed_at: Arc::new(Mutex::new(FastMap::default())),
            warm_queue: None,
            warm_stop: None,
            warm_join: None,
            warm_generation: Arc::new(AtomicU64::new(0)),
            last_warm_sweep_ns: Arc::new(AtomicU64::new(0)),
            warm_drops: Arc::new(AtomicU64::new(0)),
            warm_disconnected: Arc::new(AtomicU64::new(0)),
            warned_disconnect: Arc::new(AtomicBool::new(false)),
            resolver: None,
            resolver_counters: Arc::new(
                super::super::neighbor_resolver::ResolverCounters::default(),
            ),
            pending_dwell_hist: Arc::new(
                super::super::neighbor_latency::NeighborLatencyHist::default(),
            ),
            resolver_get_rtt_hist: Arc::new(
                super::super::neighbor_latency::NeighborLatencyHist::default(),
            ),
            pending_timeout_drops: Arc::new(AtomicU64::new(0)),
            pending_max_depth: Arc::new(AtomicU64::new(0)),
            resolver_stop: None,
            resolver_join: None,
        }
    }

    /// #5165: signal the neighbor-monitor thread to stop and JOIN it, mirroring
    /// the resolver teardown in `stop_inner`. Signalling alone is a check-then-
    /// act race (the loop only re-checks `stop` around its `recv()`); JOINING is
    /// what guarantees the retired monitor has exited BEFORE the caller proceeds
    /// to clear/reset the shared neighbor map, so an old-generation event can
    /// never mutate a freshly-rebuilt baseline. Idempotent: a monitor that was
    /// never spawned (both fields `None`) is a no-op. Join latency is bounded by
    /// the monitor's 500ms `SO_RCVTIMEO`.
    pub(crate) fn stop_and_join_monitor(&mut self) {
        if let Some(stop) = self.monitor_stop.take() {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(join) = self.monitor_join.take() {
            let _ = join.join();
        }
    }

    /// #6314: signal the neighbor-warmer thread to stop, drop the producer
    /// handle so its recv side disconnects, and JOIN it — mirroring the sibling
    /// `stop_and_join_monitor` and the resolver teardown in `stop_inner`.
    /// Signalling + dropping the queue alone is a check-then-act race (the loop
    /// only re-checks `warm_stop` around its `recv_timeout`); JOINING is what
    /// guarantees the retired warmer has exited BEFORE the caller proceeds, so a
    /// detached warmer can never fire a stray ARP/NDP solicit or mutate
    /// `last_probed_at` after teardown. Idempotent: a warmer that was never
    /// spawned (all fields `None`, e.g. a spawn failure that installed none) is
    /// a no-op. Join latency is bounded by the warmer loop's 500ms recv timeout.
    pub(crate) fn stop_and_join_warmer(&mut self) {
        if let Some(warm_stop) = self.warm_stop.take() {
            warm_stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        // Drop the producer so the warmer's recv side disconnects and it exits.
        self.warm_queue = None;
        if let Some(join) = self.warm_join.take() {
            let _ = join.join();
        }
    }
}

/// #7413: serialises every test that spawns a `neigh-monitor` thread.
///
/// The observable the #6637 leak gates read is the PROCESS-WIDE count of
/// threads named `neigh-monitor` (`/proc/self/task`), so it is shared by every
/// test that brings a coordinator up — not only the two that assert on it.
/// Under the parallel `cargo test` runner two spawners overlap and each sees
/// the other's monitor: measured `before=0 during=2` against an expected
/// `before+1`, with BOTH gates failing together in 4 of 8 runs of just those
/// two tests at `--test-threads=2`.
///
/// TEN tests across TWO modules spawn one. That population was enumerated by
/// running every test in the binary alone and watching for the monitor's own
/// `listening` line, not by reading call sites.
///
/// #7810: that enumeration ALSO carried the claim "none of them LEAKS one
/// (every spawner stops it), so the contamination is concurrent overlap and
/// nothing else." **That is true only on the normal path.** A spawner whose
/// teardown is a trailing `coordinator.stop()` skips it when the cell PANICS
/// and leaks its monitor into these process-wide gates, which then red
/// alongside it — measured on the first #7010 mutation matrix, where one cell's
/// red carried two collateral #6637 failures that had nothing to do with the
/// mutation.
///
/// So the contamination has TWO sources, not one, and they need different
/// remedies: concurrent overlap is what this lock fixes; panic leakage is what
/// `StoppedCoordinator` (whose `Drop` calls `stop()`) fixes. A census at
/// `3961adbee` found 12 guard-taking cells, 11 panic-safe via
/// `StoppedCoordinator::{new,wrap}` and one residual —
/// `coordinator_bringup_does_not_leak_a_neigh_monitor_thread_6637` itself,
/// which handles its own explicit panic branch but not a panic in setup or in
/// `reconcile`. It is left as-is deliberately: it asserts process-wide thread
/// COUNTS at specific points, so wrapping it would add a second `stop()` after
/// the measurement it exists to take.
///
/// NOTHING here is a production leak. `stop_inner` signals AND JOINS the
/// monitor (#5165), and bringup installs `monitor_stop` + `monitor_join`
/// together only when the thread actually spawned. This is a test-hygiene
/// property only.
///
/// It lives in the production module beside the thing it guards, mirroring
/// `icmp_ratelimit::global_bucket_test_lock`, and is `pub(crate)` rather than
/// module-scoped because one of the ten spawners is in `main_tests.rs`.
///
/// Poison-tolerant (`into_inner`) so a panicking guarded test cannot deadlock
/// the rest of the suite. Hold it for the WHOLE test body: the window that must
/// be exclusive is spawn → assert → teardown, not the assert alone.
///
/// The two asserting gates ALSO check `before == 0` as a precondition, and that
/// is the anti-rot half of this fix. An eleventh spawner added without the
/// guard makes them fail loudly, naming the missing lock, instead of failing as
/// an off-by-one delta that reads like a real leak.
///
/// #9556: that precondition WAITS (bounded) for the count to reach zero rather
/// than sampling it once. A monitor the previous test correctly joined can still
/// be listed in `/proc/self/task` for milliseconds after `join()` returns, so an
/// instant sample reported `before=1` in a serial suite with no leak and no
/// unlocked spawner. A thread still listed when the wait ends is a real one.
#[cfg(test)]
pub(crate) fn neigh_monitor_test_serial() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod monitor_join_tests_5165 {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// #5165 FAIL-ON-REVERT (join): `stop_and_join_monitor` must JOIN the
    /// monitor thread (wait for it to finish), not merely signal stop. The join
    /// is what enforces no-mutation-after-stop — `stop_inner` clears the shared
    /// neighbor map only AFTER this returns, so the retired monitor must be
    /// provably gone. A stand-in thread performs a bounded unit of work AFTER
    /// observing stop; a real JOIN makes `stop_and_join_monitor` block until it
    /// finishes (`done == true`). Reverting to the pre-#5165 `.ok()` discard
    /// (drop the handle without `join()`) returns immediately with
    /// `done == false` -> RED.
    #[test]
    fn stop_and_join_monitor_waits_for_thread() {
        let mut mgr = NeighborManager::new();
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let (s, d) = (stop.clone(), done.clone());
        let handle = std::thread::spawn(move || {
            // Mirror a monitor blocked in recv when stop is signalled: wake,
            // then perform one final bounded unit of work before exiting.
            while !s.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(2));
            }
            std::thread::sleep(Duration::from_millis(40));
            d.store(true, Ordering::Relaxed);
        });
        mgr.monitor_stop = Some(stop);
        mgr.monitor_join = Some(handle);

        mgr.stop_and_join_monitor();

        assert!(
            done.load(Ordering::Relaxed),
            "stop_and_join_monitor must JOIN the retired monitor (wait for it), not just signal stop",
        );
        assert!(mgr.monitor_stop.is_none(), "monitor_stop must be taken");
        assert!(mgr.monitor_join.is_none(), "monitor_join must be taken");
    }

    /// A monitor that was never spawned (both handles `None`, e.g. a spawn
    /// failure that installed neither) is a safe no-op.
    #[test]
    fn stop_and_join_monitor_no_monitor_is_noop() {
        let mut mgr = NeighborManager::new();
        mgr.stop_and_join_monitor();
        assert!(mgr.monitor_stop.is_none() && mgr.monitor_join.is_none());
    }
}

#[cfg(test)]
mod warmer_join_tests_6314 {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// #6314 FAIL-ON-REVERT (join): the neighbor WARMER is the odd-one-out among
    /// the three neighbor aux threads — the monitor and resolver were hardened by
    /// #5165 to retain a `JoinHandle` and be deterministically JOINED at
    /// teardown, but the warmer was still spawned with the pre-#5165 pattern (its
    /// handle discarded via `.ok()`, teardown signalling `warm_stop` + dropping
    /// the producer but never joining). `stop_and_join_warmer` must JOIN the
    /// warmer thread (wait for it to finish), not merely signal stop + drop the
    /// queue: joining is what enforces no-mutation-after-stop — a detached warmer
    /// could otherwise fire a stray ARP/NDP solicit / mutate `last_probed_at`
    /// after teardown. A stand-in thread performs a bounded unit of work AFTER
    /// observing stop; a real JOIN makes `stop_and_join_warmer` block until it
    /// finishes (`done == true`). Reverting to the pre-#6314 drop-only teardown
    /// (no `warm_join`, no `join()`) returns immediately with `done == false` ->
    /// RED (assertion, not a build break — mirrors #5165's monitor test).
    #[test]
    fn neighbor_warmer_joined_at_teardown_6314() {
        let mut mgr = NeighborManager::new();
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let (s, d) = (stop.clone(), done.clone());
        let (tx, rx) = std::sync::mpsc::sync_channel::<WarmItem>(WARM_QUEUE_DEPTH);
        let handle = std::thread::spawn(move || {
            // Mirror a warmer blocked in recv_timeout when stop is signalled:
            // wake, then perform one final bounded unit of work before exiting.
            // Hold `rx` so the producer drop alone does not race the timing —
            // the exit is gated on the stop flag, exactly like the real loop's
            // top-of-iteration and post-dequeue `stop` re-checks.
            let _rx = rx;
            while !s.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(2));
            }
            std::thread::sleep(Duration::from_millis(40));
            d.store(true, Ordering::Relaxed);
        });
        mgr.warm_queue = Some(tx);
        mgr.warm_stop = Some(stop);
        mgr.warm_join = Some(handle);

        mgr.stop_and_join_warmer();

        assert!(
            done.load(Ordering::Relaxed),
            "stop_and_join_warmer must JOIN the retired warmer (wait for it), not just signal stop",
        );
        assert!(mgr.warm_stop.is_none(), "warm_stop must be taken");
        assert!(mgr.warm_join.is_none(), "warm_join must be taken");
        assert!(
            mgr.warm_queue.is_none(),
            "warm_queue producer must be dropped so the warmer's recv side disconnects",
        );
    }

    /// A warmer that was never spawned (all handles `None`, e.g. a spawn failure
    /// that installed none) is a safe no-op.
    #[test]
    fn stop_and_join_warmer_no_warmer_is_noop() {
        let mut mgr = NeighborManager::new();
        mgr.stop_and_join_warmer();
        assert!(
            mgr.warm_stop.is_none() && mgr.warm_join.is_none() && mgr.warm_queue.is_none()
        );
    }
}
