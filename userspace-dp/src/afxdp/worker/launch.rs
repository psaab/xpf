// #6241 — typed worker-launch bundles.
//
// `worker_loop` (loop_body/mod.rs) was launched through a 38-parameter
// POSITIONAL protocol whose sole production caller is the spawn closure
// in `coordinator/reconcile/bringup.rs`. Several parameters shared the
// EXACT same Rust type, so a positional reorder or a mis-inserted
// argument compiled silently and misrouted a value to the wrong
// destination — the compiler checks *type*, not *semantic role*. The
// firsthand-verified silent-swap-compatible sets were:
//
//   * the three session maps `synced` / `nat` / `forward_wire`, all
//     `Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>` — a swap
//     silently misroutes NAT sessions into the forward-wire map, an HA
//     session-sync correctness bug with no compiler signal; and
//   * `heartbeat` vs `session_export_ack`, both `Arc<AtomicU64>` — a
//     swap makes the coordinator read the export-ack counter as the
//     liveness heartbeat (false failover).
//
// This module groups the 38 values into 5 top-level named bundles (plus
// 2 nested sub-bundles isolating the session-map swap hazard). Each
// field is named at its single construction site, so the positional
// drift is gone. Same-typed *source* mistakes at construction (e.g.
// `synced: coord.sessions.nat.clone()`) are caught by the `Arc::ptr_eq`
// wiring tests below, which exercise the SAME `from_coord`/`new`
// builders the production caller uses (per-role newtypes are out of
// scope — the ptr_eq tests provide the source-safety instead).
//
// Behavior-preserving (Refactor class A): `worker_loop` destructures
// each bundle back into the EXACT same local variable names at entry,
// BEFORE `worker_loop_setup` runs, so the one-shot setup call and the
// steady 10K–100K-tick/s loop body are TEXTUALLY UNCHANGED. The bundles
// are *moved* in and destructured — ZERO added clone/alloc/indirection
// on the launch path, and nothing bundle-shaped survives into the hot
// loop (honoring the #1776 no-inline-boundary constraint).
//
// `use super::*;` chains through worker/mod.rs so every concrete type
// (all `pub(in crate::afxdp)`/`pub(in crate::afxdp)` internal types) is in scope
// without re-importing.

use super::*;

/// Per-worker launch plan: identity plus the plan / FD values MOVED or
/// COPIED into the worker thread (not shared coordinator state).
///
/// `dnat_fds` carries raw `c_int` values (`DnatTableFds` is `Copy`);
/// ownership of the underlying FDs stays on the coordinator
/// (`coord.bpf_maps`) — the bundle carries values, never an `OwnedFd`.
pub(crate) struct WorkerLaunchPlan {
    pub(in crate::afxdp) worker_id: u32,
    /// #6311: the chassis-cluster node id this helper runs on (0 or 1; 0 for a
    /// standalone node), carried on `ConfigSnapshot.node_id`. It becomes the
    /// high bit of the worker's session-id namespace, so an id adopted verbatim
    /// from the peer (#5212) can never collide with one this node mints.
    pub(in crate::afxdp) node_id: u8,
    pub(in crate::afxdp) binding_plans: Vec<BindingPlan>,
    pub(in crate::afxdp) poll_mode: crate::PollMode,
    pub(in crate::afxdp) dnat_fds: DnatTableFds,
}

impl WorkerLaunchPlan {
    /// Build the per-worker launch plan from its per-worker inputs.
    /// `worker_id` + `binding_plans` come from the reconcile work list;
    /// `node_id` comes from the applied `ConfigSnapshot` (#6311);
    /// `poll_mode` mirrors `coord.poll_mode`; `dnat_fds` is built once
    /// before the spawn loop.
    pub(in crate::afxdp) fn new(
        worker_id: u32,
        node_id: u8,
        binding_plans: Vec<BindingPlan>,
        poll_mode: crate::PollMode,
        dnat_fds: DnatTableFds,
    ) -> Self {
        Self {
            worker_id,
            node_id,
            binding_plans,
            poll_mode,
            dnat_fds,
        }
    }
}

/// The two neighbor Arcs the worker reads while resolving next-hops.
pub(crate) struct WorkerNeighbors {
    pub(in crate::afxdp) dynamic: Arc<ShardedNeighborMap>,
    pub(in crate::afxdp) resolver: Option<Arc<NeighborResolver>>,
}

/// The three swap-compatible session maps + the owner-RG index, named so
/// a mis-wire is caught at the single construction site by the
/// `Arc::ptr_eq` wiring test (fail-on-revert). `synced` / `nat` /
/// `forward_wire` are all `Arc<Mutex<FastMap<SessionKey,
/// SyncedSessionEntry>>>`; a positional swap of any two is an HA-sync
/// correctness bug with no compiler signal.
pub(crate) struct WorkerSharedSessions {
    pub(in crate::afxdp) synced: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) forward_wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) owner_rg_indexes: SharedSessionOwnerRgIndexes,
}

/// Coordinator-published shared dataplane state (the worker reads each
/// field via an `ArcSwap` load, or via the shared session-map mutexes).
/// Every field is a `coord.*.clone()`, so [`WorkerSharedDataplane::from_coord`]
/// is the single, testable wiring site.
pub(crate) struct WorkerSharedDataplane {
    /// #6592: validation AND forwarding as ONE `ArcSwap`. They were two
    /// independent fields (`validation` / `forwarding`) until #6592; a worker
    /// loading them separately could pair them across generations in either
    /// direction. One `Arc` means one load and no pair to tear — see
    /// `types/runtime_view.rs`.
    pub(in crate::afxdp) runtime: RuntimeViewReader,
    pub(in crate::afxdp) ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    pub(in crate::afxdp) local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    pub(in crate::afxdp) fabrics: Arc<ArcSwap<Vec<FabricLink>>>,
    pub(in crate::afxdp) mirror_targets: Arc<ArcSwap<MirrorTargetMap>>,
    pub(in crate::afxdp) rg_epochs: Arc<[AtomicU32; MAX_RG_EPOCHS]>,
    pub(in crate::afxdp) slow_path: Option<Arc<SlowPathReinjector>>,
    pub(in crate::afxdp) neighbors: WorkerNeighbors,
    pub(in crate::afxdp) sessions: WorkerSharedSessions,
    /// #6471: node-shared live-IKE-exchange table for the Stage-11
    /// established-vs-forged discriminator (not a session map — kept out of
    /// [`WorkerSharedSessions`] so the swap-compatible trio stays the only
    /// same-typed set the wiring test has to pin).
    pub(in crate::afxdp) ike_exchanges: crate::afxdp::forwarding::SharedIkeExchangeTable,
    /// #7699: the node-shared PPTP control-segment inbox. Not in
    /// [`WorkerSharedSessions`] — it is not a session map, and the swap-hazard
    /// trio that bundle exists to pin must stay the only same-typed set there.
    pub(in crate::afxdp) pptp_control:
        Arc<crate::session::pptp_control::PptpControlInbox>,
}

impl WorkerSharedDataplane {
    /// Clone the coordinator-published shared dataplane state for a
    /// worker. This is the PRODUCTION wiring site — the spawn closure in
    /// `bring_up_workers` calls it, and the `Arc::ptr_eq` wiring tests
    /// call the SAME builder, so a same-typed source swap (e.g.
    /// `synced: coord.sessions.nat.clone()`) turns those tests RED.
    ///
    /// The clone count is identical to the pre-#6241 positional launch:
    /// one `Arc::clone` per field, exactly the clones `bring_up_workers`
    /// performed inline before.
    pub(in crate::afxdp) fn from_coord(coord: &Coordinator) -> Self {
        Self {
            runtime: coord.ha.runtime_reader(),
            ha_state: coord.ha.rg_runtime.clone(),
            local_tunnel_deliveries: coord.local_tunnel_deliveries.clone(),
            fabrics: coord.ha.fabrics.clone(),
            mirror_targets: coord.mirror_targets.clone(),
            rg_epochs: coord.rg_epochs.clone(),
            slow_path: coord.slow_path.clone(),
            neighbors: WorkerNeighbors {
                dynamic: coord.neighbors.dynamic.clone(),
                resolver: coord.neighbors.resolver.clone(),
            },
            sessions: WorkerSharedSessions {
                synced: coord.sessions.synced.clone(),
                nat: coord.sessions.nat.clone(),
                forward_wire: coord.sessions.forward_wire.clone(),
                owner_rg_indexes: coord.sessions.owner_rg_indexes.clone(),
            },
            ike_exchanges: coord.ike_exchanges.clone(),
            pptp_control: coord.pptp_control.clone(),
        }
    }
}

/// Bidirectional control channels: the per-worker command queue, the
/// peer/by-id command projections, the stop/heartbeat/export-ack
/// atomics, the event-stream handle, and the one-shot startup-readiness
/// sender.
///
/// `heartbeat` and `session_export_ack` are both `Arc<AtomicU64>` — the
/// second silent-swap hazard. They are per-worker fresh allocations, so
/// this bundle is built via [`WorkerControlChannels::new`] (not
/// `from_coord`); the `Arc::ptr_eq` wiring test pins each to the
/// intended slot.
pub(crate) struct WorkerControlChannels {
    pub(in crate::afxdp) commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    pub(in crate::afxdp) peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    pub(in crate::afxdp) worker_commands_by_id: Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>>,
    pub(in crate::afxdp) stop: Arc<AtomicBool>,
    pub(in crate::afxdp) heartbeat: Arc<AtomicU64>,
    pub(in crate::afxdp) session_export_ack: Arc<AtomicU64>,
    pub(in crate::afxdp) export_buffer: Arc<crate::afxdp::binding_state::ExportBufferState>,
    pub(in crate::afxdp) event_stream: Option<crate::event_stream::EventStreamWorkerHandle>,
    pub(in crate::afxdp) startup_report_tx: std::sync::mpsc::Sender<WorkerStartupReport>,
}

impl WorkerControlChannels {
    /// Assemble the control-channel bundle from its per-worker inputs
    /// (the command-queue projections + the fresh stop/heartbeat/ack
    /// atomics + the export buffer + the event-stream handle + the
    /// readiness sender). This is the single wiring site the production
    /// caller and the `Arc::ptr_eq` heartbeat/export-ack wiring test share.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::afxdp) fn new(
        commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
        peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
        worker_commands_by_id: Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>>,
        stop: Arc<AtomicBool>,
        heartbeat: Arc<AtomicU64>,
        session_export_ack: Arc<AtomicU64>,
        export_buffer: Arc<crate::afxdp::binding_state::ExportBufferState>,
        event_stream: Option<crate::event_stream::EventStreamWorkerHandle>,
        startup_report_tx: std::sync::mpsc::Sender<WorkerStartupReport>,
    ) -> Self {
        Self {
            commands,
            peer_worker_commands,
            worker_commands_by_id,
            stop,
            heartbeat,
            session_export_ack,
            export_buffer,
            event_stream,
            startup_report_tx,
        }
    }
}

/// The six CoS scheduler ArcSwaps the worker reads as scheduler INPUTS
/// (per `loop_body/setup.rs` — they seed the initial `load_full`s).
/// Their inner value types are mutually distinct, so `ArcSwap<T>`
/// invariance already makes a cross-swap a COMPILE error; the grouping
/// is a semantic separation of the coherent CoS subsystem, not
/// swap-safety. Every field is a `coord.cos.*.clone()`, so
/// [`WorkerCoSState::from_coord`] is the single wiring site.
pub(crate) struct WorkerCoSState {
    pub(in crate::afxdp) cos_owner_worker_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), u32>>>,
    pub(in crate::afxdp) cos_owner_live_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<BindingLiveState>>>>,
    pub(in crate::afxdp) cos_root_leases: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSRootLease>>>>,
    pub(in crate::afxdp) cos_exact_backlogs: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>>,
    pub(in crate::afxdp) cos_queue_leases: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>>,
    pub(in crate::afxdp) cos_queue_vtime_floors:
        Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>>,
}

impl WorkerCoSState {
    /// Clone the six coordinator-published CoS scheduler ArcSwaps for a
    /// worker. Same clone count as the pre-#6241 positional launch.
    pub(in crate::afxdp) fn from_coord(coord: &Coordinator) -> Self {
        Self {
            cos_owner_worker_by_queue: coord.cos.owner_worker_by_queue.clone(),
            cos_owner_live_by_queue: coord.cos.owner_live_by_queue.clone(),
            cos_root_leases: coord.cos.root_leases.clone(),
            cos_exact_backlogs: coord.cos.exact_backlogs.clone(),
            cos_queue_leases: coord.cos.queue_leases.clone(),
            cos_queue_vtime_floors: coord.cos.queue_vtime_floors.clone(),
        }
    }
}

/// Worker-written status / telemetry publish slots. The worker writes
/// each on a ~1s cadence; the coordinator's status thread reads them.
pub(crate) struct WorkerPublishedTelemetry {
    // #6242 LIFECYCLE CONTRACT (INTEGRATED): `recent_exceptions` and
    // `last_resolution` are the SAME `Arc`s the worker's per-worker
    // `WorkerRuntimeRecord` (`worker_manager.rs`) owns. `bring_up_workers`
    // allocates each ONCE, RETAINS one clone for the record
    // (`record_exception_ring` / `record_last_resolution`) and MOVES the
    // original into this worker-facing bundle. End state: one allocation
    // shared by the record and the live worker (strong_count 2 while both own
    // it — it drops to 1 when the worker exits and to 0 when the record is
    // removed); no re-allocation. #6241 owns this worker-facing argument
    // bundle; #6242 owns the coordinator-side runtime record — they share the
    // `Arc`, not a type. The record is registered as ONE `records.insert`
    // AFTER the spawn succeeds, so a failed worker never publishes a record
    // (the #4952 differential is structural).
    pub(in crate::afxdp) recent_exceptions: Arc<Mutex<ExceptionEventRing>>,
    pub(in crate::afxdp) recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    // #6242 LIFECYCLE CONTRACT — see `recent_exceptions` above.
    pub(in crate::afxdp) last_resolution: Arc<Mutex<Option<ResolutionEvent>>>,
    pub(in crate::afxdp) cos_status: Arc<ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>>,
    pub(in crate::afxdp) runtime_atomics: Arc<crate::afxdp::worker_runtime::WorkerRuntimeAtomics>,
    pub(in crate::afxdp) cold_path_atomics: Arc<crate::afxdp::cold_path_hist::WorkerColdPathAtomics>,
}

impl WorkerPublishedTelemetry {
    /// Assemble the telemetry publish-slot bundle from its per-worker
    /// allocations. `recent_session_deltas` is `coord.recent_session_deltas`;
    /// the rest are fresh per-worker slots (`recent_exceptions` and
    /// `last_resolution` are also registered in the coordinator-side maps
    /// by the caller — see the #6242 lifecycle note on the fields).
    pub(in crate::afxdp) fn new(
        recent_exceptions: Arc<Mutex<ExceptionEventRing>>,
        recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
        last_resolution: Arc<Mutex<Option<ResolutionEvent>>>,
        cos_status: Arc<ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>>,
        runtime_atomics: Arc<crate::afxdp::worker_runtime::WorkerRuntimeAtomics>,
        cold_path_atomics: Arc<crate::afxdp::cold_path_hist::WorkerColdPathAtomics>,
    ) -> Self {
        Self {
            recent_exceptions,
            recent_session_deltas,
            last_resolution,
            cos_status,
            runtime_atomics,
            cold_path_atomics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fail-on-revert wiring tests (#6241). Each constructs a real
    // `Coordinator` (whose `Coordinator::new()` allocates DISTINCT Arcs
    // for every shared slot), calls the SAME production builder the
    // spawn closure uses, and asserts by `Arc::ptr_eq` that each bundle
    // field points at the intended coordinator slot. A same-typed source
    // swap in a `from_coord` builder (the silent-misroute the issue
    // targets) turns the matching assertion RED.

    #[test]
    fn shared_dataplane_from_coord_wires_every_field_to_the_intended_slot() {
        let coord = Coordinator::new();
        let bundle = WorkerSharedDataplane::from_coord(&coord);

        // The three swap-compatible session maps — the highest-value
        // fail-on-revert. A `synced`<->`nat` swap in `from_coord` fails
        // the first two of these.
        assert!(
            Arc::ptr_eq(&bundle.sessions.synced, &coord.sessions.synced),
            "synced must wire to coord.sessions.synced"
        );
        assert!(
            Arc::ptr_eq(&bundle.sessions.nat, &coord.sessions.nat),
            "nat must wire to coord.sessions.nat"
        );
        assert!(
            Arc::ptr_eq(
                &bundle.sessions.forward_wire,
                &coord.sessions.forward_wire
            ),
            "forward_wire must wire to coord.sessions.forward_wire"
        );
        // The three session maps are pairwise DISTINCT allocations, so a
        // swap cannot masquerade as correct by aliasing.
        assert!(!Arc::ptr_eq(&bundle.sessions.synced, &coord.sessions.nat));
        assert!(!Arc::ptr_eq(
            &bundle.sessions.nat,
            &coord.sessions.forward_wire
        ));

        // A representative sample of the remaining shared-dataplane
        // fields, including the nested neighbors sub-bundle.
        // #6592: one field, not two — validation and forwarding now travel in
        // the single `RuntimeView` ArcSwap.
        assert!(bundle.runtime.same_channel(&coord.ha.runtime_reader()));
        assert!(Arc::ptr_eq(&bundle.ha_state, &coord.ha.rg_runtime));
        assert!(Arc::ptr_eq(&bundle.fabrics, &coord.ha.fabrics));
        assert!(Arc::ptr_eq(&bundle.mirror_targets, &coord.mirror_targets));
        assert!(Arc::ptr_eq(&bundle.rg_epochs, &coord.rg_epochs));
        assert!(Arc::ptr_eq(
            &bundle.local_tunnel_deliveries,
            &coord.local_tunnel_deliveries
        ));
        assert!(Arc::ptr_eq(
            &bundle.neighbors.dynamic,
            &coord.neighbors.dynamic
        ));
        // #6471: the IKE exchange table wires to coord.ike_exchanges (not a
        // session map — a same-typed swap with one of the trio above would
        // fail their assertions first).
        assert!(Arc::ptr_eq(&bundle.ike_exchanges, &coord.ike_exchanges));
        // #7699: the PPTP control inbox. This test's NAME claims every field,
        // so a new field left unasserted makes the name false — and an inbox
        // wired to a fresh allocation instead of the coordinator's would leave
        // each worker filling a buffer nobody drains, with every other #7699
        // cell still green.
        assert!(Arc::ptr_eq(&bundle.pptp_control, &coord.pptp_control));
    }

    #[test]
    fn cos_state_from_coord_wires_every_field_to_the_intended_slot() {
        let coord = Coordinator::new();
        let bundle = WorkerCoSState::from_coord(&coord);

        assert!(Arc::ptr_eq(
            &bundle.cos_owner_worker_by_queue,
            &coord.cos.owner_worker_by_queue
        ));
        assert!(Arc::ptr_eq(
            &bundle.cos_owner_live_by_queue,
            &coord.cos.owner_live_by_queue
        ));
        assert!(Arc::ptr_eq(&bundle.cos_root_leases, &coord.cos.root_leases));
        assert!(Arc::ptr_eq(
            &bundle.cos_exact_backlogs,
            &coord.cos.exact_backlogs
        ));
        assert!(Arc::ptr_eq(
            &bundle.cos_queue_leases,
            &coord.cos.queue_leases
        ));
        assert!(Arc::ptr_eq(
            &bundle.cos_queue_vtime_floors,
            &coord.cos.queue_vtime_floors
        ));
    }

    #[test]
    fn control_channels_new_keeps_heartbeat_and_export_ack_distinct() {
        // The second silent-swap hazard: `heartbeat` and
        // `session_export_ack` are both `Arc<AtomicU64>`. Build the
        // bundle via the production `new` with two DISTINCT Arcs and
        // assert each landed in its intended slot — a swap in `new` fails
        // these ptr_eq checks.
        let heartbeat = Arc::new(AtomicU64::new(0xA));
        let session_export_ack = Arc::new(AtomicU64::new(0xB));
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let worker_commands_by_id = Arc::new(BTreeMap::new());
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, _rx) = std::sync::mpsc::channel::<WorkerStartupReport>();

        let bundle = WorkerControlChannels::new(
            commands.clone(),
            Vec::new(),
            worker_commands_by_id.clone(),
            stop.clone(),
            heartbeat.clone(),
            session_export_ack.clone(),
            Arc::new(crate::afxdp::binding_state::ExportBufferState::new()),
            None,
            tx,
        );

        assert!(
            Arc::ptr_eq(&bundle.heartbeat, &heartbeat),
            "heartbeat must wire to the heartbeat slot"
        );
        assert!(
            Arc::ptr_eq(&bundle.session_export_ack, &session_export_ack),
            "session_export_ack must wire to the export-ack slot"
        );
        // The two atomics are distinct allocations — a swap cannot alias.
        assert!(!Arc::ptr_eq(&bundle.heartbeat, &session_export_ack));
        assert!(Arc::ptr_eq(&bundle.commands, &commands));
        assert!(Arc::ptr_eq(
            &bundle.worker_commands_by_id,
            &worker_commands_by_id
        ));
        assert!(Arc::ptr_eq(&bundle.stop, &stop));
    }

    #[test]
    fn published_telemetry_new_wires_each_slot() {
        let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
        let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
        let last_resolution = Arc::new(Mutex::new(None));
        let cos_status = Arc::new(ArcSwap::from_pointee(Vec::new()));
        let runtime_atomics =
            Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new());
        let cold_path_atomics =
            Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new());

        let bundle = WorkerPublishedTelemetry::new(
            recent_exceptions.clone(),
            recent_session_deltas.clone(),
            last_resolution.clone(),
            cos_status.clone(),
            runtime_atomics.clone(),
            cold_path_atomics.clone(),
        );

        assert!(Arc::ptr_eq(&bundle.recent_exceptions, &recent_exceptions));
        assert!(Arc::ptr_eq(
            &bundle.recent_session_deltas,
            &recent_session_deltas
        ));
        assert!(Arc::ptr_eq(&bundle.last_resolution, &last_resolution));
        assert!(Arc::ptr_eq(&bundle.cos_status, &cos_status));
        assert!(Arc::ptr_eq(&bundle.runtime_atomics, &runtime_atomics));
        assert!(Arc::ptr_eq(&bundle.cold_path_atomics, &cold_path_atomics));
    }
}
