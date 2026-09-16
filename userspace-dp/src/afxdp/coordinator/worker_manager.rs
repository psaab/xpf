use super::*;

/// #6242: the complete per-worker runtime, keyed by `worker_id`.
///
/// Consolidates the four previously-scattered owners — `WorkerManager.handles`
/// plus the three `Coordinator` sibling maps (`worker_panics` /
/// `worker_exception_rings` / `worker_last_resolution`) — into ONE record so a
/// worker's runtime is registered and rolled back as a single unit
/// (`records.insert` / `records.clear`), not a hand-sequenced multi-map
/// triplet. Registration is POST-SPAWN-SUCCESS (see
/// `reconcile/bringup.rs`): a worker that fails to spawn never had a record, so
/// spawn-failure rollback has nothing to unwind (the #4952 differential), and
/// the pre-spawn insert / spawn-Err `.remove` / teardown double-clear the old
/// layout required are gone.
///
/// COLD-PATH ONLY. The packet path never looks this up — each worker holds
/// DIRECT `Arc` clones of its own `exception_ring` / `last_resolution` (threaded
/// via `WorkerPublishedTelemetry` -> `WorkerContext`). The record is read only
/// by the ~1 Hz status thread, teardown, and the HA control fan-out. It holds
/// the SAME `Arc`s the worker telemetry holds (shared allocation, not a fresh
/// alloc), so the consolidation adds zero hot-path indirection and no extra
/// allocation vs. the pre-#6242 four-owner layout.
///
/// `runtime_atomics` / `cold_path_atomics` stay INSIDE `WorkerHandle` — the
/// record wraps the handle, it does not flatten it.
pub(in crate::afxdp) struct WorkerRuntimeRecord {
    pub(in crate::afxdp) handle: WorkerHandle,
    /// #925: panic-payload slot, written once when the worker dies, read at
    /// most once per gRPC status poll (~1 Hz).
    pub(in crate::afxdp) panic: Arc<Mutex<Option<String>>>,
    /// #5289: per-worker exception ring; the worker pushes compact POD events,
    /// the status thread drains + formats them.
    pub(in crate::afxdp) exception_ring: Arc<Mutex<ExceptionEventRing>>,
    /// #5289: per-worker last-forwarding-resolution slot; the status thread
    /// picks the newest across all workers.
    pub(in crate::afxdp) last_resolution: Arc<Mutex<Option<ResolutionEvent>>>,
}

impl WorkerRuntimeRecord {
    /// #9900 F-093: whether the #925 supervisor recorded this worker's panic.
    /// Fan-out producers shed (skip + count) dead workers instead of feeding
    /// a queue no thread will ever drain again.
    #[inline]
    pub(in crate::afxdp) fn is_dead(&self) -> bool {
        self.handle
            .runtime_atomics
            .dead
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// #9900 F-093: shed check for record-keyed fan-out. When the worker is
    /// dead, counts `commands` (the pushes this iteration would have made —
    /// callers pass their static fan-out width so shed stays commensurable
    /// with `WORKER_COMMAND_QUEUE_DROPS`) and returns true so the caller
    /// skips the queue instead of feeding a thread that will never drain.
    #[inline]
    pub(in crate::afxdp) fn shed_if_dead(&self, commands: u64) -> bool {
        if self.is_dead() {
            crate::afxdp::worker_queue::WORKER_COMMAND_QUEUE_SHED_TOTAL
                .fetch_add(commands, std::sync::atomic::Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
impl WorkerRuntimeRecord {
    /// Wrap a bare `WorkerHandle` in a record with fresh empty observability
    /// slots — the common test shape (a handle installed to drive HA / status
    /// / lifecycle assertions that do not exercise the exception/resolution
    /// content). Content-specific tests build the record inline with the exact
    /// `exception_ring` / `last_resolution` `Arc`s they assert on.
    pub(in crate::afxdp) fn for_test(handle: WorkerHandle) -> Self {
        Self {
            handle,
            panic: Arc::new(Mutex::new(None)),
            exception_ring: Arc::new(Mutex::new(ExceptionEventRing::new())),
            last_resolution: Arc::new(Mutex::new(None)),
        }
    }
}

/// Per-worker lifecycle and planning state.
///
/// Two distinct key spaces live here:
/// - `live` and `identities` are keyed by binding `slot` (per-binding
///   per-worker, populated from `BindingPlan::slot` in `refresh_bindings`).
/// - `records` is keyed by `worker_id` (one [`WorkerRuntimeRecord`] per
///   spawned worker thread — the #6242 consolidation of the former `handles`
///   map plus the three sibling `Coordinator` observability maps).
///
/// `last_planned_workers` and `last_planned_bindings` are reconcile-pass
/// bookkeeping surfaced in the stage label and operator status surface.
///
/// `last_planned_worker_slots` is the companion SIZING value for
/// per-worker-id-indexed structures (#1830 follow-up, Codex review on
/// PR #1841): `max(planned worker_id) + 1`, i.e. the array length
/// needed so every planned worker id is in range. Worker ids can be
/// SPARSE — the runtime binding/queue unregister handlers
/// (server/handlers/{binding,queue}.rs) can remove the bindings that
/// carried the low worker ids while a high-id worker survives the next
/// reconcile (bring_up_workers skips unregistered/invalid bindings) —
/// so this is NOT interchangeable with the COUNT
/// (`last_planned_workers`). Consumers that want "how many workers"
/// (status surface, stage label) keep using the count; consumers that
/// INDEX by worker id (v8 queue-lease per-worker arrays + rotation
/// scratch, V_min vtime floors) must use the slots value.
pub(in crate::afxdp) struct WorkerManager {
    pub(in crate::afxdp) live: BTreeMap<u32, Arc<BindingLiveState>>,
    pub(in crate::afxdp) identities: BTreeMap<u32, BindingIdentity>,
    /// #7209: the worker runtime records, published so the peer-synced import
    /// path can read them WITHOUT the snapshot-wide `ServerState` mutex.
    ///
    /// **This is the authority, not a cache.** An earlier attempt (issue #7209
    /// comment 5475077474) kept an owned `BTreeMap` here as the authority and
    /// published a separate fan-out projection alongside it, refreshed by
    /// calling a helper at each mutation site — with nothing enforcing the
    /// call. 17 test sites inserted into the map directly and the projection
    /// silently went short. There is no second structure here: this `ArcSwap`
    /// IS the map, so a site that mutates without publishing cannot compile.
    ///
    /// `ArcSwap` rather than `RwLock` deliberately, and the reason has to be
    /// stated precisely or a reader will check it and find it false. The
    /// fan-out loop itself takes only the per-worker command mutex — NOT
    /// `sessions.synced`, which `publish_shared_session` acquires and releases
    /// earlier in the same call. The hazard is the other direction: an
    /// `RwLock` read guard covering the whole import would be HELD ACROSS
    /// `publish_shared_session`'s acquisition of `sessions.synced`, inventing
    /// a records-before-sessions ordering that nothing else in the tree
    /// observes. That is a lock-graph change, the category that produced the
    /// #7095 self-deadlock and the category a green suite cannot see, because
    /// every test calls in from outside the lock. `ArcSwap` adds no edge, no
    /// blocking, and no `...Locked` naming hazard, and it is the tree's
    /// existing idiom. Writes are read-clone-store and cost nothing: exactly
    /// two production mutation sites, both reconcile-rare.
    records: Arc<ArcSwap<BTreeMap<u32, Arc<WorkerRuntimeRecord>>>>,
    /// #7209: worker `JoinHandle`s, keyed by the same `worker_id` as `records`.
    ///
    /// Separated from `WorkerRuntimeRecord` because consuming a `JoinHandle`
    /// needs `&mut`, and that was the ONLY thing standing between the record
    /// and being publishable behind an `Arc`. Kept owned and private here: a
    /// join handle is teardown lifecycle state with one producer
    /// (`reconcile/bringup.rs`) and one consumer (`stop_and_clear`), and
    /// nothing off-lock has any business with it.
    joins: BTreeMap<u32, std::thread::JoinHandle<()>>,
    pub(super) last_planned_workers: usize,
    pub(super) last_planned_bindings: usize,
    pub(super) last_planned_worker_slots: usize,
    /// #5290: rotating cursor for the fair RPC-fallback session-delta drain
    /// (`Coordinator::drain_session_deltas`). Persists the binding index the
    /// last drain stopped at so the next drain resumes there, guaranteeing no
    /// binding is perpetually starved across successive polls. A positional
    /// index into the slot-ordered `live` map (`% live.len()` at use), not a
    /// slot key — membership changes are rare (reconcile only) and the rotation
    /// self-corrects, so a stale index costs at most one poll of imperfect
    /// fairness, never permanent starvation.
    pub(in crate::afxdp) session_delta_drain_cursor: std::sync::atomic::AtomicUsize,
}

impl WorkerManager {
    pub(super) fn new() -> Self {
        Self {
            live: BTreeMap::new(),
            identities: BTreeMap::new(),
            records: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            joins: BTreeMap::new(),
            last_planned_workers: 0,
            last_planned_bindings: 0,
            last_planned_worker_slots: 0,
            session_delta_drain_cursor: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    #[inline]
    pub(super) fn last_planned_workers(&self) -> usize {
        self.last_planned_workers
    }

    #[inline]
    pub(super) fn last_planned_worker_slots(&self) -> usize {
        self.last_planned_worker_slots
    }

    #[inline]
    pub(super) fn last_planned_bindings(&self) -> usize {
        self.last_planned_bindings
    }

    /// #1189 Phase 1: stop all workers, drain map slots, and clear
    /// per-worker state. Called from `Coordinator::stop_inner`.
    /// Caller passes the BPF map fds because they live on
    /// `Coordinator::bpf_maps`, not on `WorkerManager`.
    ///
    /// #6242: the two-pass signal-ALL-then-join-ALL order is load-bearing —
    /// join one worker while its peers are unsignalled and a peer that blocks
    /// on a shared resource deadlocks the join. The XSK/heartbeat slot deletion
    /// runs over `live` (slot-keyed) while the coordinator FDs are still open,
    /// BEFORE clearing. `clear_records()` then drops each record's handle +
    /// panic + exception_ring + last_resolution `Arc`s together, in one step —
    /// subsuming the three `Coordinator.*.clear()` the pre-#6242 layout ran and
    /// removing the dead #5289 content-clear loops that iterated the
    /// already-emptied maps.
    pub(super) fn stop_and_clear(
        &mut self,
        xsk_map_fd: Option<&crate::afxdp::bpf_map::OwnedFd>,
        heartbeat_map_fd: Option<&crate::afxdp::bpf_map::OwnedFd>,
    ) {
        // #7209: signal through the published set, join through the owned
        // `joins` map. The two-pass order above is unchanged — every worker is
        // signalled before any is joined — because `std::mem::take` below runs
        // strictly after this loop has signalled all of them.
        for rec in self.records.load().values() {
            rec.handle.stop.store(true, Ordering::Relaxed);
        }
        // #7209: consumes each handle exactly once, exactly as the per-record
        // `join.take()` it replaces did. A record with no join handle (the
        // test-constructed shape) simply has no entry here.
        for (_worker_id, join) in std::mem::take(&mut self.joins) {
            let _ = join.join();
        }
        if let Some(fd) = xsk_map_fd {
            for (&slot, _) in &self.live {
                let _ = delete_xsk_slot(fd.fd, slot);
            }
        }
        if let Some(fd) = heartbeat_map_fd {
            for (&slot, _) in &self.live {
                let _ = delete_heartbeat_slot(fd.fd, slot);
            }
        }
        self.clear_records();
        self.identities.clear();
        self.live.clear();
    }

    /// #7209: the published worker runtime records.
    ///
    /// Lock-free: this loads an `ArcSwap` and returns a guard over the current
    /// map `Arc`. It takes NO lock and requires none to be held, so it is safe
    /// to call from the off-lock peer-synced import path and from code already
    /// holding the `ServerState` mutex alike. The snapshot is stable for the
    /// life of the guard — a concurrent `register` / `clear_records` publishes a
    /// NEW map and leaves this one intact.
    #[inline]
    pub(in crate::afxdp) fn records(
        &self,
    ) -> arc_swap::Guard<Arc<BTreeMap<u32, Arc<WorkerRuntimeRecord>>>> {
        self.records.load()
    }

    /// #7209: an OWNED snapshot of the published records, for a reader that
    /// needs several facts about the worker set to agree with each other.
    ///
    /// `records()` returns a borrow guard and is right for one quick question.
    /// This returns the `Arc` itself, which is right when a caller asks the
    /// worker set MORE THAN ONE question and a disagreement between the answers
    /// would be a bug — `upsert_synced_session` asks three (the import cap, the
    /// no-worker reservation gate, and the fan-out set) and must not see a
    /// teardown land between them. `load_full` also avoids parking an
    /// `arc_swap` debt slot for the length of a long call.
    #[inline]
    pub(in crate::afxdp) fn records_snapshot(
        &self,
    ) -> Arc<BTreeMap<u32, Arc<WorkerRuntimeRecord>>> {
        self.records.load_full()
    }

    /// #7209: a READ-ONLY handle onto the SAME published map this manager
    /// mutates. Sharing the cell, not a snapshot of it, so a holder observes
    /// every subsequent `register` / teardown.
    ///
    /// NOT yet the seam the peer-synced import path reads through — that path
    /// still reaches the manager directly via `records_snapshot()`, because it
    /// still runs under the `ServerState` mutex. This exists so the sharing
    /// property is bound by a test NOW, before the dispatch change relies on
    /// it; its production consumer arrives with that change.
    ///
    /// Returns a [`WorkerRecordsReader`], NOT the `Arc<ArcSwap<..>>`. Handing
    /// out the `ArcSwap` would hand out `store` / `rcu` / `swap` through
    /// `Deref` — a consumer could publish a record set, and `register`'s
    /// load-clone-store is a non-atomic read-modify-write that would silently
    /// drop such a write. It would also falsify this type's own claim to be the
    /// single authority: the field cannot be mutated without publishing, but an
    /// aliased writer could publish without the field. `RuntimeViewChannel`
    /// (`types/runtime_view.rs`) took the same decision for the same reason
    /// after a review probe used exactly that aliasing to publish a torn pair.
    #[inline]
    pub(in crate::afxdp) fn records_reader(&self) -> WorkerRecordsReader {
        WorkerRecordsReader {
            inner: Arc::clone(&self.records),
        }
    }

    /// #7209: register a spawned worker's runtime record and its join handle.
    ///
    /// The ONE insertion point. Publishing is not a separate step a caller can
    /// forget — the map lives behind the `ArcSwap`, so there is no way to add a
    /// record without storing the new map.
    ///
    /// Takes `&mut self` even though the `ArcSwap` would allow `&self`: this is
    /// reconcile-only mutation and keeping it exclusive preserves the
    /// compile-time statement that worker registration does not race the rest
    /// of the transaction. Widening it later is a deliberate decision, not a
    /// side effect of the field's type.
    pub(in crate::afxdp) fn register(
        &mut self,
        worker_id: u32,
        record: WorkerRuntimeRecord,
        join: Option<std::thread::JoinHandle<()>>,
    ) {
        // #9720: clear the (possibly reused) worker id's transition-debt slot
        // BEFORE publishing the record — a transition racing this registration
        // can only record debt for W after the insert below, so clear-first
        // never eats fresh debt, only the previous generation's stale slot.
        crate::afxdp::worker_queue::clear_transition_debt(worker_id);
        let mut next = (**self.records.load()).clone();
        next.insert(worker_id, Arc::new(record));
        self.records.store(Arc::new(next));
        match join {
            Some(join) => {
                self.joins.insert(worker_id, join);
            }
            None => {
                // Keep the two maps consistent if a worker_id is re-registered
                // without a join handle (test shapes), so a stale handle can
                // never be joined against a record that no longer exists.
                self.joins.remove(&worker_id);
            }
        }
    }

    /// #7209 test seam: drop ONE registered record.
    ///
    /// Production never removes a single record — registration is
    /// post-spawn-success and teardown clears the whole map (see
    /// `worker_queue.rs`) — so this exists only for the status/observability
    /// tests that simulate a worker disappearing between drains. Kept
    /// `cfg(test)` so it cannot become a production path by accident.
    #[cfg(test)]
    pub(in crate::afxdp) fn remove_record_for_test(&mut self, worker_id: u32) {
        // Same invariant `clear_records` asserts, for the same reason: dropping
        // a record whose thread is neither signalled nor joined detaches a
        // worker that `stop_and_clear` can then never reach.
        assert!(
            !self.joins.contains_key(&worker_id),
            "remove_record_for_test on worker {worker_id}, which still owns an \
             un-joined thread handle"
        );
        let mut next = (**self.records.load()).clone();
        next.remove(&worker_id);
        self.records.store(Arc::new(next));
        self.joins.remove(&worker_id);
    }

    /// #7209: whether a registered worker still owns a joinable thread handle.
    ///
    /// The join handle moved out of `WorkerRuntimeRecord` into `joins`, so the
    /// #6242 assertion that a LAUNCHED worker keeps one joinable — the #4952
    /// differential between a launched worker and a spawn failure — has to ask
    /// here instead of at `rec.handle.join`. The property is unchanged; only
    /// its owner moved.
    #[cfg(test)]
    pub(in crate::afxdp) fn has_join_handle(&self, worker_id: u32) -> bool {
        self.joins.contains_key(&worker_id)
    }

    /// #7209: drop every registered record by publishing an empty map, and
    /// with it every join handle.
    ///
    /// Readers holding a previously-loaded snapshot keep it alive until they
    /// drop it — the refcount is what makes an off-lock reader safe across a
    /// teardown, the same shape #8179 used for `BpfMaps`.
    ///
    /// PRIVATE, and it clears `joins` as well, because `records` and `joins`
    /// are two maps that must agree on their key set. `stop_and_clear` signals
    /// over the published records and joins over `joins`, so a `joins` entry
    /// whose record has been dropped is a thread that gets JOINED WITHOUT EVER
    /// BEING SIGNALLED — a hang, not an error. When this was `pub(in
    /// crate::afxdp)`, `register(id, rec, Some(join)); clear_records();
    /// stop_and_clear(..)` reached exactly that. Narrowing the visibility makes
    /// `stop_and_clear` the only reachable path, and the assertion turns a
    /// same-module misuse into a loud failure instead of a hang.
    fn clear_records(&mut self) {
        // `assert!`, not `debug_assert!`: `make test-rust` builds the cargo
        // legs in RELEASE, where a `debug_assert` is compiled out — the guard
        // would then exist only in the profile nobody gates on. It runs once
        // per teardown, so it costs nothing measurable.
        assert!(
            self.joins.is_empty(),
            "clear_records reached with {} un-joined worker thread(s); \
             stop_and_clear drains `joins` before clearing, so a non-empty map \
             here means a caller is dropping records out from under threads it \
             never signalled",
            self.joins.len()
        );
        self.records.store(Arc::new(BTreeMap::new()));
    }

    /// #7209: the key sets of `records` and `joins` agree, modulo records
    /// registered without a thread (the test shape). Every join handle MUST
    /// have a record, because `stop_and_clear` signals through the records and
    /// joins through this map — a join with no record is an unsignalled thread
    /// that the join then waits on forever.
    #[cfg(test)]
    fn every_join_has_a_record(&self) -> bool {
        let records = self.records.load();
        self.joins.keys().all(|id| records.contains_key(id))
    }
}

/// #7209: a read-only view of a [`WorkerManager`]'s published runtime records.
///
/// Shares the `ArcSwap` cell with the manager — so it observes every
/// registration and teardown — while exposing no way to publish. See
/// [`WorkerManager::records_reader`] for why that asymmetry is the point.
#[derive(Clone)]
pub(in crate::afxdp) struct WorkerRecordsReader {
    inner: Arc<ArcSwap<BTreeMap<u32, Arc<WorkerRuntimeRecord>>>>,
}

impl WorkerRecordsReader {
    /// Borrow the currently published record set.
    #[inline]
    pub(in crate::afxdp) fn load(
        &self,
    ) -> arc_swap::Guard<Arc<BTreeMap<u32, Arc<WorkerRuntimeRecord>>>> {
        self.inner.load()
    }
}

#[cfg(test)]
mod records_authority_tests_7209 {
    use super::*;
    use crate::afxdp::WorkerCommand;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    fn handle(commands: Arc<Mutex<VecDeque<WorkerCommand>>>) -> WorkerHandle {
        WorkerHandle {
            stop: Arc::new(AtomicBool::new(false)),
            heartbeat: Arc::new(AtomicU64::new(0)),
            commands,
            session_export_ack: Arc::new(AtomicU64::new(0)),
            cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
            runtime_atomics: Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new()),
            cold_path_atomics: Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new()),
        }
    }

    fn record(commands: Arc<Mutex<VecDeque<WorkerCommand>>>) -> WorkerRuntimeRecord {
        WorkerRuntimeRecord::for_test(handle(commands))
    }

    /// #7209: a handle taken BEFORE a registration observes that registration.
    ///
    /// This is the property that distinguishes the published record map from
    /// the fan-out PROJECTION rejected in issue #7209 (comment 5475077474).
    /// There, `records` stayed the authority and a second structure was
    /// refreshed by discipline, so a holder could observe a set that had gone
    /// stale. Here the handle shares the `ArcSwap` cell itself, so it cannot.
    ///
    /// Asserted in BOTH directions — a register and a clear — because a handle
    /// that aliased only additions would pass a one-way check while going
    /// stale across a teardown, which is precisely the window the off-lock
    /// peer-synced import path runs in.
    #[test]
    fn a_records_handle_observes_registrations_taken_after_it_7209() {
        let mut workers = WorkerManager::new();
        // Taken while the manager is EMPTY: nothing about the current contents
        // can be baked into the handle.
        let handle = workers.records_reader();
        assert!(
            handle.load().is_empty(),
            "handle must start empty or the assertions below prove nothing"
        );

        let queue = Arc::new(Mutex::new(VecDeque::new()));
        workers.register(7, record(Arc::clone(&queue)), None);

        assert_eq!(
            handle.load().len(),
            1,
            "a handle taken before the register must see it — if this fails the \
             handle is a snapshot, not a view of the authority, and the \
             off-lock import path would fan out to a stale worker set"
        );
        assert!(
            handle.load().contains_key(&7),
            "the registered worker_id must be reachable through the handle"
        );
        // The queue reached through the handle must be the SAME allocation the
        // caller registered — an equal-but-separate queue would let a fan-out
        // push commands no worker ever drains.
        let via_handle = Arc::clone(&handle.load().get(&7).expect("record").handle.commands);
        assert!(
            Arc::ptr_eq(&via_handle, &queue),
            "the handle must expose the registered command queue itself, not a copy"
        );

        workers.clear_records();
        assert!(
            handle.load().is_empty(),
            "a handle must also observe a teardown — a one-way alias would keep \
             fanning out to workers that have been joined and dropped"
        );
    }

    /// Paired control for the test above: two managers must NOT share a cell.
    ///
    /// Without this, the sharing assertion would also pass if `records` were a
    /// process-global — which is exactly the regression #6819 removed for the
    /// session counters, and it would make every assertion about one manager
    /// depend on what every other test happened to do.
    #[test]
    fn b_two_managers_do_not_share_a_records_cell_7209() {
        let mut left = WorkerManager::new();
        let right = WorkerManager::new();
        let right_handle = right.records_reader();
        left.register(1, record(Arc::new(Mutex::new(VecDeque::new()))), None);
        assert_eq!(
            left.records().len(),
            1,
            "the mutated manager must actually have the record, or the control \
             below is vacuous"
        );
        assert!(
            right_handle.load().is_empty(),
            "registering on one manager must not appear on another — a shared \
             cell here would make `records` a de facto process global"
        );
    }

    /// #7209: `register` publishes; there is no separate refresh to forget.
    ///
    /// The rejected projection needed a `refresh_synced_fanout_queues()` call at
    /// every mutation site. This asserts the equivalent invariant holds with no
    /// such call: the map read back through the PUBLIC accessor — not the
    /// private field — carries every registration.
    #[test]
    fn c_every_registration_is_visible_through_the_public_accessor_7209() {
        let mut workers = WorkerManager::new();
        for worker_id in 0..4u32 {
            workers.register(
                worker_id,
                record(Arc::new(Mutex::new(VecDeque::new()))),
                None,
            );
        }
        assert_eq!(workers.records().len(), 4);
        assert_eq!(workers.records_snapshot().len(), 4);
        for worker_id in 0..4u32 {
            assert!(
                workers.records().contains_key(&worker_id),
                "worker {worker_id} registered but not published"
            );
        }
    }

    /// #7209: `stop_and_clear` signals EVERY worker before joining ANY.
    ///
    /// The two-pass order is load-bearing (#6242): join one worker while its
    /// peers are unsignalled and a peer blocked on a shared resource deadlocks
    /// the join. Relocating the join handles out of the records could have
    /// silently collapsed the two passes into one, and no existing test binds
    /// the ordering — a single-worker fixture cannot see it, so this uses
    /// three, each of which records the stop-flag state of ALL THREE at the
    /// moment it is joined.
    #[test]
    fn d_stop_and_clear_signals_every_worker_before_joining_any_7209() {
        /// Sentinel recorded by a worker that was never signalled. Chosen
        /// outside the legal range (0..=3) so it cannot be mistaken for a real
        /// observation.
        const NEVER_SIGNALLED: usize = usize::MAX;
        let mut workers = WorkerManager::new();
        let stops: Vec<Arc<AtomicBool>> =
            (0..3).map(|_| Arc::new(AtomicBool::new(false))).collect();
        let observed: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
        for (worker_id, stop) in stops.iter().enumerate() {
            let mut rec = record(Arc::new(Mutex::new(VecDeque::new())));
            rec.handle.stop = Arc::clone(stop);
            let peers: Vec<Arc<AtomicBool>> = stops.iter().map(Arc::clone).collect();
            let observed = Arc::clone(&observed);
            let join = std::thread::spawn(move || {
                // Wait for EVERY peer's stop flag, not just this worker's own.
                //
                // The obvious version — spin on `peers[worker_id]`, then count
                // how many of the three are set — is RACY, and its flake is
                // indistinguishable from the regression it exists to catch.
                // `stop_and_clear` sets the three flags with three sequential
                // relaxed stores; if the signalling thread is descheduled
                // mid-loop, worker 0 wakes and counts 1. That yields
                // `[1, 2, 3]` — precisely the signature a COLLAPSED one-pass
                // teardown produces, so a scheduling hiccup would read as a
                // real #6242 regression and vice versa. (Found by review;
                // demonstrated with forced preemption. It did not reproduce in
                // 80 runs here, which is not evidence against it — the window
                // is narrow, not absent.)
                //
                // Waiting on ALL peers removes the timing assumption instead of
                // widening a margin. Under the correct signal-all-then-join-all
                // order every worker's condition is already true when the joins
                // begin, so all three exit promptly whatever the scheduler
                // does. Under a collapsed signal-one-join-one order, worker 0
                // is joined while workers 1 and 2 are unsignalled, so its
                // condition can NEVER become true and it runs to the deadline —
                // which is also what makes the bound load-bearing rather than a
                // hang guard: it converts that deadlock into a recorded
                // sentinel the assertions reject. Same bound covers a
                // `register` that never published (nothing signals at all).
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                loop {
                    let signalled = peers.iter().filter(|s| s.load(Ordering::Relaxed)).count();
                    if signalled == peers.len() {
                        observed.lock().expect("observed").push(signalled);
                        return;
                    }
                    if std::time::Instant::now() >= deadline {
                        observed.lock().expect("observed").push(NEVER_SIGNALLED);
                        return;
                    }
                    std::hint::spin_loop();
                }
            });
            workers.register(worker_id as u32, rec, Some(join));
        }

        workers.stop_and_clear(None, None);

        let observed = observed.lock().expect("observed");
        assert_eq!(
            observed.len(),
            3,
            "every registered worker must have been joined exactly once — a \
             join handle that outlived its record, or one never taken, shows up \
             here as a wrong count (and a never-joined thread would hang \
             `stop_and_clear` instead)"
        );
        assert!(
            !observed.contains(&NEVER_SIGNALLED),
            "a worker timed out waiting for every peer to be signalled \
             ({observed:?}; {} is the sentinel). TWO regressions land here: a \
             COLLAPSED signal-one-join-one teardown, where worker 0 is joined \
             while its peers are unsignalled so its wait can never complete; \
             and a `register` that never published, so `stop_and_clear` — which \
             signals through the PUBLISHED map — signals nobody at all. The \
             bound is what turns either into this assertion instead of a hung \
             suite",
            NEVER_SIGNALLED
        );
        assert!(
            observed.iter().all(|&signalled| signalled == 3),
            "every worker must have observed ALL THREE stop flags before it \
             was joined: signal-all-then-join-all (#6242). Collapsing the two \
             passes into one leaves worker 0 joined while its peers are \
             unsignalled, so its wait never completes and it records the \
             timeout sentinel: {observed:?}"
        );
        assert!(
            workers.records().is_empty(),
            "stop_and_clear publishes an empty record map"
        );
        assert!(
            !workers.has_join_handle(0),
            "the join handles are consumed, so a second stop_and_clear cannot \
             join an already-joined thread"
        );
    }

    /// #7209: a registration with a REAL join handle leaves the two maps in
    /// agreement, and the teardown drains both.
    ///
    /// This is the cell the first draft of these tests did not have, and the
    /// gap was real rather than theoretical: cells a/b/c all register with
    /// `join = None`, so NONE of them can observe a `joins` entry orphaned
    /// from its record. `records` and `joins` are two maps whose key sets must
    /// agree — `stop_and_clear` signals over the records and joins over
    /// `joins`, so a join whose record has been dropped is a thread joined
    /// without ever being signalled, which HANGS rather than failing. A
    /// hostile review of this change found that `clear_records` was
    /// `pub(in crate::afxdp)` and cleared only one of the two, making
    /// `register(.., Some(join)); clear_records(); stop_and_clear(..)` reach
    /// exactly that.
    #[test]
    fn f_a_real_join_handle_never_outlives_its_record_7209() {
        let mut workers = WorkerManager::new();
        let stop = Arc::new(AtomicBool::new(false));
        let mut rec = record(Arc::new(Mutex::new(VecDeque::new())));
        rec.handle.stop = Arc::clone(&stop);
        let spun = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !spun.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
                std::hint::spin_loop();
            }
        });
        workers.register(4, rec, Some(join));

        assert!(
            workers.has_join_handle(4),
            "the join handle must be registered, or the agreement assertion \
             below holds vacuously"
        );
        assert!(
            workers.every_join_has_a_record(),
            "a join handle with no matching record is a thread `stop_and_clear` \
             would join without signalling"
        );

        workers.stop_and_clear(None, None);

        assert!(workers.records().is_empty(), "teardown drops the records");
        assert!(
            !workers.has_join_handle(4),
            "teardown drops the join handle too — a survivor would be joined \
             again on the next teardown, against a record that no longer exists"
        );
        assert!(
            workers.every_join_has_a_record(),
            "the two maps must still agree after a teardown"
        );
    }

    /// #7209: dropping the records out from under un-joined threads FAILS.
    ///
    /// The control for `clear_records`'s guard. Without it the guard is a
    /// claim: every other cell here reaches `clear_records` through
    /// `stop_and_clear`, which drains `joins` first, so none of them can tell
    /// an armed assertion from a deleted one. This drives the misuse directly.
    #[test]
    #[should_panic(expected = "un-joined worker thread")]
    fn g_clearing_records_while_a_thread_is_un_joined_fails_loudly_7209() {
        let mut workers = WorkerManager::new();
        let stop = Arc::new(AtomicBool::new(false));
        let mut rec = record(Arc::new(Mutex::new(VecDeque::new())));
        rec.handle.stop = Arc::clone(&stop);
        let spun = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            // Short: this cell panics by design, so the thread is orphaned.
            // A long spin would burn a core alongside the rest of the suite,
            // which under `make test-rust`'s single-threaded leg is the whole
            // machine.
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
            while !spun.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
                std::thread::yield_now();
            }
        });
        workers.register(5, rec, Some(join));
        // Pre-#7209-review this silently produced a `joins` entry with no
        // record, and the NEXT `stop_and_clear` signalled nobody and then
        // blocked forever on the join.
        workers.clear_records();
    }

    // #7209: there was a cell here asserting that a snapshot outlives a
    // concurrent `clear_records`. It was DELETED rather than kept, because it
    // could not fail: in safe Rust there is no implementation of
    // `records_snapshot()` whose return could break the keep-alive claim, and
    // even a detached deep copy of the map satisfies both its `get` and its
    // `Arc::ptr_eq` (a `BTreeMap` clone clones the inner `Arc`s). Its one live
    // assertion — that `clear_records` actually clears — is already made by
    // cell `a`. A cell whose assertion cannot fail is worse than no cell: it
    // reads as coverage of the refcount guarantee and provides none.
}
