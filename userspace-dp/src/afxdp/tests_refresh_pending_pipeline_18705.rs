// #18705, through the coordinator and the worker's production command phase
// (`session_glue::run_worker_command_phase`): `update_ha_state` bumps the
// node-level activation epoch, stores and publishes the activated view, then
// pushes `RefreshOwnerRGS` (or records it as #9720 debt). These cells run the
// worker's pass against that real sequence; the fixture-level cells are in
// `tests_refresh_pending_18705.rs`.
use super::tests_lan_owner_idle_import_18691::*;
use super::tests_split_rg_failback_18531::*;
use super::*;

/// Worker ids for the cells that register a worker with a coordinator. The
/// #9720 debt and epoch slots are process-global and tests run in parallel,
/// so each cell takes an id no other test uses (surveyed: 0-9, 77, 101-127
/// are taken).
const PIPELINE_WORKER: u32 = 87;
const HOOK_WORKER: u32 = 88;
const DEBT_WORKER: u32 = 89;

/// HA status for this node: RG0 and RG2 (LAN) active, RG1 (WAN) as given.
fn groups(rg1_active: bool) -> Vec<HAGroupStatus> {
    [(0, true), (1, rg1_active), (2, true)]
        .into_iter()
        .map(|(rg_id, active)| HAGroupStatus {
            rg_id,
            active,
            ..HAGroupStatus::default()
        })
        .collect()
}

/// The LAN owner of the split as a coordinator plus one registered worker:
/// the coordinator holds the split HA view (RG1 inactive, its own activation
/// fan-out drained), and the worker's table holds the live flow imported
/// under the split FIB, wired to the coordinator's epochs and seeded with
/// the published epoch exactly as `worker_loop` seeds it.
fn split_node_worker(
    worker_id: u32,
) -> (
    crate::afxdp::Coordinator,
    Arc<Mutex<VecDeque<WorkerCommand>>>,
    SessionTable,
) {
    let mut coordinator = crate::afxdp::Coordinator::new();
    coordinator.set_forwarding_for_test(rg_taking_node_forwarding());
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        worker_id,
        crate::afxdp::WorkerRuntimeRecord::for_test(crate::afxdp::WorkerHandle {
            stop: Arc::new(AtomicBool::new(false)),
            heartbeat: Arc::new(AtomicU64::new(0)),
            commands: commands.clone(),
            session_export_ack: Arc::new(AtomicU64::new(0)),
            cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
            runtime_atomics: Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new()),
            cold_path_atomics: Arc::new(
                crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new(),
            ),
        }),
        None,
    );
    crate::afxdp::worker_queue::clear_transition_debt(worker_id);
    coordinator
        .update_ha_state(&groups(false))
        .expect("seed the split HA view");
    commands.lock().expect("commands").clear();
    let (mut sessions, _, _) = lan_owner_import(Family::V4, false);
    let epochs = Arc::clone(&coordinator.rg_epochs);
    sessions.set_rg_epoch_reader(Arc::new(move |rg| {
        epochs[crate::afxdp::flow_cache::rg_epoch_index(rg)].load(Ordering::Relaxed)
    }));
    sessions.seed_owner_rg_refresh_epoch(
        coordinator.ha.published_epoch0.load(Ordering::Acquire),
    );
    (coordinator, commands, sessions)
}

/// The worker's per-pass command-phase carry (the `worker_loop` locals).
struct PassCarry {
    last_transition_debt_epoch: u64,
    last_session_import_repair_epoch: u64,
    transition_debt_pending: bool,
    session_import_repair_pending: bool,
}

impl PassCarry {
    fn new(worker_id: u32) -> Self {
        Self {
            last_transition_debt_epoch: crate::afxdp::worker_queue::transition_debt_epoch(
                worker_id,
            ),
            last_session_import_repair_epoch:
                crate::afxdp::worker_queue::session_import_repair_epoch(worker_id),
            transition_debt_pending: false,
            session_import_repair_pending: false,
        }
    }
}

/// One production command phase of `worker_id`'s pass; returns the view the
/// rest of the pass polls under.
fn worker_pass(
    coordinator: &crate::afxdp::Coordinator,
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    worker_id: u32,
    carry: &mut PassCarry,
) -> Arc<BTreeMap<i32, HAGroupRuntime>> {
    let (view, results) = crate::afxdp::session_glue::run_worker_command_phase(
        commands,
        sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        forwarding,
        &coordinator.ha.rg_runtime,
        &coordinator.ha.published_epoch0,
        &Arc::new(ShardedNeighborMap::default()),
        worker_id,
        &mut VecDeque::new(),
        &mut carry.last_transition_debt_epoch,
        &mut carry.last_session_import_repair_epoch,
        carry.transition_debt_pending,
        carry.session_import_repair_pending,
    );
    carry.transition_debt_pending = results.transition_debt_pending;
    carry.session_import_repair_pending = results.session_import_repair_pending;
    arc_swap::Guard::into_inner(view)
}

fn rg1_active(view: &BTreeMap<i32, HAGroupRuntime>) -> bool {
    view.get(&1).is_some_and(|group| group.active)
}

/// The pipeline: `update_ha_state` activates RG1 (epoch bumped, view stored
/// and published, `RefreshOwnerRGS` pushed), and this worker's pass runs
/// before the push lands, so its queue is empty and its view is the
/// activated one. The WAN reply in that pass must be kept. When the push
/// lands, the next pass dispatches the refresh, which heals the line and
/// stamps the table with the published epoch; the next reply is judged on
/// reth0.80 and kept.
#[test]
fn reply_in_the_pass_before_the_refresh_lands_is_kept_18705() {
    let (coordinator, commands, mut sessions) = split_node_worker(PIPELINE_WORKER);
    let owner_forwarding = fw1_owner_forwarding();
    let key = exported_forward(&owner_forwarding, Family::V4).key;
    let mut carry = PassCarry::new(PIPELINE_WORKER);
    coordinator
        .update_ha_state(&groups(true))
        .expect("activate RG1");
    // The push has not landed on this worker yet.
    let pushed: Vec<WorkerCommand> = commands.lock().expect("commands").drain(..).collect();
    assert!(
        pushed
            .iter()
            .any(|command| matches!(command, WorkerCommand::RefreshOwnerRGS { owner_rgs } if owner_rgs == &vec![1])),
        "fixture: the activation pushed RefreshOwnerRGS for RG1"
    );
    let view = worker_pass(
        &coordinator,
        &commands,
        &mut sessions,
        &owner_forwarding,
        PIPELINE_WORKER,
        &mut carry,
    );
    assert!(rg1_active(&view), "premise: the pass polls under the activated view");
    let (frame, meta) = wan_reply_frame_for(Family::V4);
    let before = drive(&mut sessions, &owner_forwarding, &view, WAN, &frame, meta, 1);
    assert_eq!(before.session_hit, 1, "the reply must hit the reverse row");
    assert_eq!(
        (before.snat_revoked, before.closes, sessions.len()),
        (0, 0, 2),
        "the reply in the pass before the refresh lands is kept"
    );
    assert_eq!(before.tx, [0, 0, 1], "and delivered to the LAN host");

    commands.lock().expect("commands").extend(pushed);
    let view = worker_pass(
        &coordinator,
        &commands,
        &mut sessions,
        &owner_forwarding,
        PIPELINE_WORKER,
        &mut carry,
    );
    assert_eq!(
        stored_forward_line(&sessions, &key).egress_ifindex,
        WAN_UNIT_IFINDEX,
        "the refresh heals the line onto reth0.80"
    );
    assert_eq!(
        sessions.refreshed_rg_epoch0_for_test(),
        coordinator.rg_epochs[0].load(Ordering::Relaxed),
        "the refresh stamps the table with the published activation epoch"
    );
    let (frame, meta) = wan_reply_frame_for(Family::V4);
    let after = drive(&mut sessions, &owner_forwarding, &view, WAN, &frame, meta, 1);
    assert_eq!(
        (after.snat_revoked, after.closes, sessions.len()),
        (0, 0, 2),
        "the healed line is judged valid"
    );
}

/// (A) The heal-loss interleaving at master: the worker took its pass view,
/// then the coordinator stored the activation and pushed the refresh, then
/// the worker saw a non-empty queue and drained it. The refresh must run
/// under a view loaded AFTER the drain, which shows the activation: the line
/// is healed and the table stamped. Under a view loaded at pass start (before
/// the store) the rows re-resolve `HAInactive`, nothing is rewritten, and
/// the consumed refresh never comes back.
#[test]
fn refresh_pushed_after_the_queue_check_runs_under_the_stored_view_18705() {
    let (coordinator, commands, mut sessions) = split_node_worker(HOOK_WORKER);
    let coordinator = Arc::new(coordinator);
    let owner_forwarding = fw1_owner_forwarding();
    let key = exported_forward(&owner_forwarding, Family::V4).key;
    let epoch_before = coordinator.rg_epochs[0].load(Ordering::Relaxed);
    let mut carry = PassCarry::new(HOOK_WORKER);
    // Something else is queued, so the queue check says "apply" before the
    // activation lands (during a failover the bulk-sync imports are).
    commands
        .lock()
        .expect("commands")
        .push_back(WorkerCommand::ForgetPptpCall(0xDEAD_BEEF));
    let activating = Arc::clone(&coordinator);
    crate::afxdp::session_glue::AFTER_COMMAND_CHECK_HOOK_18705.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            activating
                .update_ha_state(&groups(true))
                .expect("activate RG1 between the queue check and the drain");
        }));
    });
    let view = worker_pass(
        &coordinator,
        &commands,
        &mut sessions,
        &owner_forwarding,
        HOOK_WORKER,
        &mut carry,
    );
    assert_ne!(
        coordinator.rg_epochs[0].load(Ordering::Relaxed),
        epoch_before,
        "fixture: the activation landed inside the pass"
    );
    assert!(
        commands.lock().expect("commands").is_empty(),
        "fixture: the pass drained the refresh pushed after its queue check"
    );
    assert_eq!(
        stored_forward_line(&sessions, &key).egress_ifindex,
        WAN_UNIT_IFINDEX,
        "the refresh ran under the stored activated view and healed the line"
    );
    assert_eq!(
        sessions.refreshed_rg_epoch0_for_test(),
        coordinator.rg_epochs[0].load(Ordering::Relaxed),
        "and stamped the table with the activation's epoch"
    );
    assert!(rg1_active(&view), "the rest of the pass polls under the activated view");
    let (frame, meta) = wan_reply_frame_for(Family::V4);
    let out = drive(&mut sessions, &owner_forwarding, &view, WAN, &frame, meta, 1);
    assert_eq!(
        (out.snat_revoked, out.closes, sessions.len()),
        (0, 0, 2),
        "the healed line is judged valid"
    );
}

/// (B) A refused push: the activation finds the worker queue full, the
/// refresh becomes #9720 transition debt, and the worker replays it once the
/// backlog drains. That replay is a stamp source too: after the drain the
/// line is healed and the table is stamped with the activation's epoch, so
/// the keep ends without waiting for its bound.
#[test]
fn debt_replayed_refresh_stamps_the_table_18705() {
    let (coordinator, commands, mut sessions) = split_node_worker(DEBT_WORKER);
    let owner_forwarding = fw1_owner_forwarding();
    let key = exported_forward(&owner_forwarding, Family::V4).key;
    {
        let mut pending = commands.lock().expect("commands");
        for _ in 0..crate::afxdp::worker_queue::MAX_PENDING_WORKER_COMMANDS {
            pending.push_back(WorkerCommand::ForgetPptpCall(0xDEAD_BEEF));
        }
    }
    let mut carry = PassCarry::new(DEBT_WORKER);
    coordinator
        .update_ha_state(&groups(true))
        .expect("activate RG1 at a full queue");
    assert!(
        crate::afxdp::worker_queue::transition_debt_for_test(DEBT_WORKER)
            .ops()
            .iter()
            .any(|op| op.kind() == crate::afxdp::worker_queue::TransitionDebtKind::Refresh),
        "fixture: the refused refresh is this worker's debt"
    );
    let mut view = None;
    for _ in 0..64 {
        view = Some(worker_pass(
            &coordinator,
            &commands,
            &mut sessions,
            &owner_forwarding,
            DEBT_WORKER,
            &mut carry,
        ));
        if commands.lock().expect("commands").is_empty()
            && crate::afxdp::worker_queue::transition_debt_for_test(DEBT_WORKER).is_empty()
        {
            break;
        }
    }
    assert!(
        crate::afxdp::worker_queue::transition_debt_for_test(DEBT_WORKER).is_empty(),
        "fixture: the debt was replayed"
    );
    assert_eq!(
        stored_forward_line(&sessions, &key).egress_ifindex,
        WAN_UNIT_IFINDEX,
        "the replayed refresh heals the line"
    );
    assert_eq!(
        sessions.refreshed_rg_epoch0_for_test(),
        coordinator.rg_epochs[0].load(Ordering::Relaxed),
        "the replayed refresh stamps the table"
    );
    let view = view.expect("at least one pass");
    let (frame, meta) = wan_reply_frame_for(Family::V4);
    let out = drive(&mut sessions, &owner_forwarding, &view, WAN, &frame, meta, 1);
    assert_eq!(
        (out.snat_revoked, out.closes, sessions.len()),
        (0, 0, 2),
        "the healed line is judged valid"
    );
}
