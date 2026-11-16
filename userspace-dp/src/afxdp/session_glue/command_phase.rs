//! #18705: one worker pass's command phase, and the HA view each command
//! dispatch runs under.
//!
//! The coordinator stores an RG transition in `rg_runtime` BEFORE it pushes
//! the command that carries it (`ha/state.rs`), and records a refused push
//! as #9720 debt after the store too. The worker used to load its pass view
//! before it looked at its queue, so a `RefreshOwnerRGS` pushed between that
//! load and the drain ran under the pre-activation view: the rows it scans
//! re-resolved `HAInactive` and were not rewritten, and the command was
//! consumed (a debt replay was stale-skipped). The heal was lost. Here the
//! view is loaded after the drain, and after the debt take, from the
//! `ha_state` `ArcSwap` itself, with the PUBLISHED activation epoch read
//! just before it, which a `RefreshOwnerRGS` dispatched under that view
//! stamps on the table (`SessionTable::note_owner_rgs_refreshed`).
use super::*;

/// Apply this worker's queued commands and position-ready #9720 transition
/// debt under a caller-fixed HA view (unit fixtures). `view_epoch0` is the
/// published activation epoch that view shows; `None` leaves the table's
/// refresh stamp untouched. Production loads its view after the drain
/// instead: [`run_worker_command_phase`].
#[cfg(test)]
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(in crate::afxdp) fn apply_worker_commands_at_view_epoch(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    view_epoch0: Option<u32>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    worker_id: u32,
    scratch: &mut VecDeque<WorkerCommand>,
) -> WorkerCommandResults {
    let view = Arc::new(ha_state.clone());
    apply_worker_commands_with_view(
        commands,
        sessions,
        session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        forwarding,
        &|| CommandView {
            ha: Arc::clone(&view),
            published_epoch0: view_epoch0,
            refresh_forwarding: None,
        },
        dynamic_neighbors,
        worker_id,
        scratch,
    )
}

/// [`apply_worker_commands_at_view_epoch`] with no known view epoch: the
/// fixture shape of every pre-#18705 caller.
#[cfg(test)]
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(in crate::afxdp) fn apply_worker_commands(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    worker_id: u32,
    scratch: &mut VecDeque<WorkerCommand>,
) -> WorkerCommandResults {
    apply_worker_commands_at_view_epoch(
        commands,
        sessions,
        session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        forwarding,
        ha_state,
        None,
        dynamic_neighbors,
        worker_id,
        scratch,
    )
}

#[cfg(test)]
thread_local! {
    /// #18705 test seam: runs once, on the calling thread, right after
    /// [`run_worker_command_phase`] has sampled its queue and debt epochs
    /// and BEFORE the apply drains the queue. It stands in for a coordinator
    /// that stores and pushes a transition in that gap, which is where the
    /// worker used to hold a view loaded before the store.
    pub(in crate::afxdp) static AFTER_COMMAND_CHECK_HOOK_18705:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

/// #18705 test entry: `run_worker_command_phase` for the pipeline cells.
#[cfg(test)]
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(in crate::afxdp) fn run_worker_command_phase_for_test(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha_state: &ArcSwap<BTreeMap<i32, HAGroupRuntime>>,
    ha_published_epoch0: &AtomicU32,
    shared_runtime: &RuntimeViewReader,
    worker_id: u32,
    last_transition_debt_epoch: &mut u64,
    last_session_import_repair_epoch: &mut u64,
    transition_debt_pending: bool,
    session_import_repair_pending: bool,
) -> (
    arc_swap::Guard<Arc<BTreeMap<i32, HAGroupRuntime>>>,
    WorkerCommandResults,
) {
    run_worker_command_phase(
        commands,
        sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        forwarding,
        ha_state,
        ha_published_epoch0,
        shared_runtime,
        &Arc::new(ShardedNeighborMap::default()),
        worker_id,
        &mut VecDeque::new(),
        last_transition_debt_epoch,
        last_session_import_repair_epoch,
        transition_debt_pending,
        session_import_repair_pending,
    )
}

/// One worker pass's command phase: decide whether commands or debt are due,
/// apply them, and return the HA view the rest of the pass runs under.
///
/// #18705: the HA view is loaded AFTER the queue drain (and again after the
/// #9720 debt take), never before. The coordinator stores an RG transition
/// in `rg_runtime` before it pushes (or records as debt) the command that
/// carries it, and the queue (debt) mutex orders that push before this
/// drain, so a view loaded after the drain shows the transition. A view
/// loaded at pass start, before the drain, did not: a `RefreshOwnerRGS`
/// drained under it re-resolved the rows `HAInactive` (not rewritten) and
/// was consumed, and a debt refresh was stale-skipped, so the heal was lost.
/// The returned view is loaded after the apply, so the pass never polls
/// under a view older than the one its commands ran under.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(in crate::afxdp) fn run_worker_command_phase(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &ArcSwap<BTreeMap<i32, HAGroupRuntime>>,
    ha_published_epoch0: &AtomicU32,
    // #18705 K3: the runtime-view channel, for the forwarding a refresh
    // re-resolves against (loaded with the HA view, after the drain).
    shared_runtime: &RuntimeViewReader,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    worker_id: u32,
    scratch: &mut VecDeque<WorkerCommand>,
    last_transition_debt_epoch: &mut u64,
    last_session_import_repair_epoch: &mut u64,
    transition_debt_pending: bool,
    session_import_repair_pending: bool,
) -> (
    arc_swap::Guard<Arc<BTreeMap<i32, HAGroupRuntime>>>,
    WorkerCommandResults,
) {
    // Only apply commands when pending — avoids lock overhead on
    // every loop iteration in the common (empty-queue) case.
    // #1807: a poisoned mutex is recovered (and the poison cleared)
    // instead of reading as "no commands" — that turned one worker
    // panic into permanent deafness to coordinator commands.
    let has_commands = crate::afxdp::worker_queue::try_lock_recover(commands)
        .map(|q| !q.is_empty())
        .unwrap_or(false);
    // #9720/#11360: sample both positional-debt epochs EVERY pass. A
    // record that lands after a queue drain still schedules the out-of-band
    // repair even when no later command arrives.
    let transition_debt_epoch = crate::afxdp::worker_queue::transition_debt_epoch(worker_id);
    let debt_epoch_changed = transition_debt_epoch != *last_transition_debt_epoch;
    let session_import_repair_epoch =
        crate::afxdp::worker_queue::session_import_repair_epoch(worker_id);
    let import_repair_epoch_changed =
        session_import_repair_epoch != *last_session_import_repair_epoch;
    let should_apply = crate::afxdp::worker_queue::should_apply_worker_commands(
        has_commands,
        debt_epoch_changed,
        transition_debt_pending,
        import_repair_epoch_changed,
        session_import_repair_pending,
    );
    #[cfg(test)]
    if let Some(hook) = AFTER_COMMAND_CHECK_HOOK_18705.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
    if !should_apply {
        return (ha_state.load(), WorkerCommandResults::empty());
    }
    // Acquire pairs with `update_ha_state`'s Release publish (made after its
    // `rg_runtime` store): the HA view loaded next shows that epoch's state.
    // K3: the forwarding is loaded AFTER the HA view. The coordinator
    // publishes an activation's FIB (the #16270 connected-route republish,
    // Go's `republishConnectedRGSync`) before `update_ha_state` stores the
    // activation, both under the server lock, so this forwarding is at least
    // as new as the FIB the HA view was activated against. The pass's own
    // forwarding was loaded at tick start, before the drain, and is not.
    let load_view = || -> CommandView {
        let published = ha_published_epoch0.load(Ordering::Acquire);
        let ha = ha_state.load_full();
        let refresh_forwarding = shared_runtime.load().forwarding().clone();
        CommandView {
            ha,
            published_epoch0: Some(published),
            refresh_forwarding: Some(refresh_forwarding),
        }
    };
    let results = apply_worker_commands_with_view(
        commands,
        sessions,
        session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        forwarding,
        &load_view,
        dynamic_neighbors,
        worker_id,
        scratch,
    );
    *last_transition_debt_epoch = transition_debt_epoch;
    *last_session_import_repair_epoch = session_import_repair_epoch;
    (ha_state.load(), results)
}

