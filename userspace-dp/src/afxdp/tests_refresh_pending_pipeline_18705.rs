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
const RG0_ONLY_WORKER: u32 = 90;
const FIB_RACE_WORKER: u32 = 91;
const DEBT_GAP_WORKER: u32 = 92;

/// HA status for this node: RG0 and RG2 (LAN) active, RG1 (WAN) as given.
fn groups(rg1_active: bool) -> Vec<HAGroupStatus> {
    groups_rg0(true, rg1_active)
}

/// HA status for this node: RG2 (LAN) active, RG0 and RG1 as given.
fn groups_rg0(rg0_active: bool, rg1_active: bool) -> Vec<HAGroupStatus> {
    [(0, rg0_active), (1, rg1_active), (2, true)]
        .into_iter()
        .map(|(rg_id, active)| HAGroupStatus {
            rg_id,
            active,
            ..HAGroupStatus::default()
        })
        .collect()
}

/// The worker's runtime-view channel (what `worker_loop` reads through
/// `shared_runtime`), publishing `forwarding`.
fn runtime_channel(forwarding: ForwardingState) -> crate::afxdp::types::RuntimeViewChannel {
    let channel = crate::afxdp::types::RuntimeViewChannel::default();
    publish_fib(&channel, forwarding);
    channel
}

/// The coordinator publishing a FIB, as the #16270 connected-route
/// republish does before an activation.
fn publish_fib(channel: &crate::afxdp::types::RuntimeViewChannel, forwarding: ForwardingState) {
    channel.publish(Arc::new(crate::afxdp::types::RuntimeView::new(
        ValidationState::default(),
        Arc::new(forwarding),
    )));
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
    split_node_worker_seeded(worker_id, &groups(false))
}

/// As `split_node_worker`, from the seed HA status `seed`.
fn split_node_worker_seeded(
    worker_id: u32,
    seed: &[HAGroupStatus],
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
        .update_ha_state(seed)
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
/// rest of the pass polls under. `forwarding` is the pass's own snapshot,
/// loaded at tick start; `runtime` is the channel it came from, which the
/// phase reads again after the drain.
fn worker_pass(
    coordinator: &crate::afxdp::Coordinator,
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    runtime: &crate::afxdp::types::RuntimeViewChannel,
    worker_id: u32,
    carry: &mut PassCarry,
) -> Arc<BTreeMap<i32, HAGroupRuntime>> {
    let (view, results) = crate::afxdp::session_glue::run_worker_command_phase_for_test(
        commands,
        sessions,
        forwarding,
        &coordinator.ha.rg_runtime,
        &coordinator.ha.published_epoch0,
        &runtime.reader(),
        worker_id,
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
    // The activation's FIB, already published (#16270).
    let runtime = runtime_channel(fw1_owner_forwarding());
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
        &runtime,
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
        &runtime,
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
    // The activation's FIB, already published (#16270).
    let runtime = runtime_channel(fw1_owner_forwarding());
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
        &runtime,
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
    // The activation's FIB, already published (#16270).
    let runtime = runtime_channel(fw1_owner_forwarding());
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
            &runtime,
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

/// Pop the RG1 refresh `update_ha_state` just pushed: "published, not yet
/// pushed" for this worker.
fn take_rg1_refresh(commands: &Arc<Mutex<VecDeque<WorkerCommand>>>) -> WorkerCommand {
    let mut pending = commands.lock().expect("commands");
    let last = pending.pop_back().expect("fixture: a pushed command");
    assert!(
        matches!(&last, WorkerCommand::RefreshOwnerRGS { owner_rgs } if owner_rgs == &vec![1]),
        "fixture: the RG1 activation pushed its refresh last"
    );
    last
}

/// K2 (#18705 review: Codex P1-2, r23 P2-1, r24 P2-1). RG0 activates alone
/// (epoch k) and queues `RefreshOwnerRGS{[0]}`. RG1 then activates and
/// publishes k+1, but its refresh is not yet pushed. The worker drains the
/// RG0 command and loads the view AFTER the drain, so the view already shows
/// RG1 active at k+1. The RG0 refresh re-resolves nothing (no RG > 0), so it
/// must not stamp: the rows still carry the split-FIB line, and the reply
/// must stay kept until the RG1 refresh lands.
#[test]
fn rg0_only_refresh_does_not_stamp_a_later_rg1_activation_18705() {
    let (coordinator, commands, mut sessions) =
        split_node_worker_seeded(RG0_ONLY_WORKER, &groups_rg0(false, false));
    let runtime = runtime_channel(fw1_owner_forwarding());
    let owner_forwarding = fw1_owner_forwarding();
    let key = exported_forward(&owner_forwarding, Family::V4).key;
    let mut carry = PassCarry::new(RG0_ONLY_WORKER);
    coordinator
        .update_ha_state(&groups_rg0(true, false))
        .expect("activate RG0 alone");
    coordinator
        .update_ha_state(&groups_rg0(true, true))
        .expect("activate RG1");
    let rg1_refresh = take_rg1_refresh(&commands);
    assert!(
        commands
            .lock()
            .expect("commands")
            .iter()
            .all(|command| matches!(command, WorkerCommand::RefreshOwnerRGS { owner_rgs } if owner_rgs == &vec![0])),
        "fixture: only the RG0 refresh is queued"
    );
    let view = worker_pass(
        &coordinator,
        &commands,
        &mut sessions,
        &owner_forwarding,
        &runtime,
        RG0_ONLY_WORKER,
        &mut carry,
    );
    assert!(rg1_active(&view), "premise: the RG0 command ran under the RG1-active view");
    assert_eq!(
        stored_forward_line(&sessions, &key).egress_ifindex,
        WAN_GATEWAY_UNIT_IFINDEX,
        "premise: the RG0 refresh re-resolved nothing"
    );
    assert_ne!(
        sessions.refreshed_rg_epoch0_for_test(),
        coordinator.rg_epochs[0].load(Ordering::Relaxed),
        "an RG0-only refresh must not stamp the view's epoch"
    );
    let (frame, meta) = wan_reply_frame_for(Family::V4);
    let before = drive(&mut sessions, &owner_forwarding, &view, WAN, &frame, meta, 1);
    assert_eq!(
        (before.snat_revoked, before.closes, sessions.len()),
        (0, 0, 2),
        "the RG1 activation is still pending: the reply is kept"
    );

    commands.lock().expect("commands").push_back(rg1_refresh);
    let view = worker_pass(
        &coordinator,
        &commands,
        &mut sessions,
        &owner_forwarding,
        &runtime,
        RG0_ONLY_WORKER,
        &mut carry,
    );
    assert_eq!(
        sessions.refreshed_rg_epoch0_for_test(),
        coordinator.rg_epochs[0].load(Ordering::Relaxed),
        "the RG1 refresh scans and stamps"
    );
    let (frame, meta) = wan_reply_frame_for(Family::V4);
    let after = drive(&mut sessions, &owner_forwarding, &view, WAN, &frame, meta, 1);
    assert_eq!(
        (after.snat_revoked, after.closes, sessions.len()),
        (0, 0, 2),
        "the healed line is judged valid"
    );
}

/// K3 (#18705 review: Codex P1-3). The worker took its forwarding snapshot
/// at tick start, under the split FIB. Then, between that load and the
/// drain, the coordinator republished the connected routes (#16270) and
/// stored and pushed the RG1 activation. The refresh must re-resolve
/// against the FIB published WITH the activation, not the pass's
/// pre-activation snapshot: under the split FIB the line stays the reth0.50
/// gateway line, the refresh stamps it "healed", and the next reply is
/// revoked.
#[test]
fn refresh_runs_under_the_fib_published_with_the_activation_18705() {
    let (coordinator, commands, mut sessions) = split_node_worker(FIB_RACE_WORKER);
    let coordinator = Arc::new(coordinator);
    let split_forwarding = rg_taking_node_forwarding();
    let owner_forwarding = fw1_owner_forwarding();
    let runtime = Arc::new(runtime_channel(rg_taking_node_forwarding()));
    let key = exported_forward(&owner_forwarding, Family::V4).key;
    let mut carry = PassCarry::new(FIB_RACE_WORKER);
    commands
        .lock()
        .expect("commands")
        .push_back(WorkerCommand::ForgetPptpCall(0xDEAD_BEEF));
    let activating = Arc::clone(&coordinator);
    let publishing = Arc::clone(&runtime);
    crate::afxdp::session_glue::AFTER_COMMAND_CHECK_HOOK_18705.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            publish_fib(&publishing, fw1_owner_forwarding());
            activating
                .update_ha_state(&groups(true))
                .expect("activate RG1 after the pass took its forwarding");
        }));
    });
    let view = worker_pass(
        &coordinator,
        &commands,
        &mut sessions,
        &split_forwarding,
        &runtime,
        FIB_RACE_WORKER,
        &mut carry,
    );
    assert!(
        commands.lock().expect("commands").is_empty() && rg1_active(&view),
        "fixture: the pass drained the refresh the activation pushed"
    );
    assert_eq!(
        stored_forward_line(&sessions, &key).egress_ifindex,
        WAN_UNIT_IFINDEX,
        "the refresh re-resolved against the FIB published with the activation"
    );
    let (frame, meta) = wan_reply_frame_for(Family::V4);
    let out = drive(&mut sessions, &owner_forwarding, &view, WAN, &frame, meta, 1);
    assert_eq!(
        (out.snat_revoked, out.closes, sessions.len()),
        (0, 0, 2),
        "the healed line is judged valid"
    );
}

/// K4 (#18705 review: Codex's predicted survivor). An RG1 activation lands
/// AFTER the slice was dispatched and BEFORE the #9720 debt take. Its push
/// is refused (the queue refilled to capacity), so it becomes debt, and the
/// debt is ready in this same pass (the drain had emptied the queue). The
/// debt must be dispatched under a view loaded after the take, which shows
/// RG1 active. Reusing the slice's view (RG1 inactive) stale-skips the
/// refresh: nothing heals, nothing stamps, and the debt is consumed.
#[test]
fn debt_recorded_after_the_slice_runs_under_a_fresh_view_18705() {
    let (coordinator, commands, mut sessions) = split_node_worker(DEBT_GAP_WORKER);
    let coordinator = Arc::new(coordinator);
    let runtime = runtime_channel(fw1_owner_forwarding());
    let owner_forwarding = fw1_owner_forwarding();
    let key = exported_forward(&owner_forwarding, Family::V4).key;
    let mut carry = PassCarry::new(DEBT_GAP_WORKER);
    commands
        .lock()
        .expect("commands")
        .push_back(WorkerCommand::ForgetPptpCall(0xDEAD_BEEF));
    let activating = Arc::clone(&coordinator);
    let refill = Arc::clone(&commands);
    crate::afxdp::session_glue::AFTER_SLICE_DISPATCH_HOOK_18705.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            {
                let mut pending = refill.lock().expect("commands");
                for _ in 0..crate::afxdp::worker_queue::MAX_PENDING_WORKER_COMMANDS {
                    pending.push_back(WorkerCommand::ForgetPptpCall(0xDEAD_BEEF));
                }
            }
            activating
                .update_ha_state(&groups(true))
                .expect("activate RG1 between the slice and the debt take");
        }));
    });
    let view = worker_pass(
        &coordinator,
        &commands,
        &mut sessions,
        &owner_forwarding,
        &runtime,
        DEBT_GAP_WORKER,
        &mut carry,
    );
    assert!(
        crate::afxdp::worker_queue::transition_debt_for_test(DEBT_GAP_WORKER).is_empty(),
        "fixture: the refused refresh was recorded and replayed in this pass"
    );
    assert_eq!(
        stored_forward_line(&sessions, &key).egress_ifindex,
        WAN_UNIT_IFINDEX,
        "the debt refresh ran under a view that shows the activation"
    );
    assert_eq!(
        sessions.refreshed_rg_epoch0_for_test(),
        coordinator.rg_epochs[0].load(Ordering::Relaxed),
        "and stamped the table"
    );
    let (frame, meta) = wan_reply_frame_for(Family::V4);
    let out = drive(&mut sessions, &owner_forwarding, &view, WAN, &frame, meta, 1);
    assert_eq!(
        (out.snat_revoked, out.closes, sessions.len()),
        (0, 0, 2),
        "the healed line is judged valid"
    );
    // Leave no filler behind for the next test that reuses this queue id.
    commands.lock().expect("commands").clear();
}
