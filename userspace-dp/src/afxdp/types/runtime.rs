// Worker / runtime / per-binding plumbing types extracted from
// afxdp/types/mod.rs (Issue 68.4). Includes worker handles + commands,
// validation/disposition runtime state, debug poll counters, the
// per-call WorkerContext / TelemetryContext bundles, BindingPlan,
// XdpOptions, ResolutionDebug, LearnedNeighborKey, and the small HA
// runtime types that the worker needs to thread through the dispatch
// pipeline.
//
// Pure relocation. Original `pub(super)` widened to `pub(in crate::afxdp)`
// in this file; types/mod.rs re-exports via `pub(in crate::afxdp) use
// runtime::*;` so external call sites resolve unchanged.

use super::*;

#[repr(C)]
pub(in crate::afxdp) struct XdpOptions {
    pub(in crate::afxdp) flags: u32,
}

/// #7209: **every field is `Arc`-backed, and that is load-bearing.** The
/// worker's `JoinHandle` used to live here as an `Option<JoinHandle<()>>` and
/// was consumed with `join.take()`, which is the only thing that ever needed
/// `&mut` on a `WorkerRuntimeRecord`. It now lives in `WorkerManager::joins`
/// (lifecycle state, one producer in `reconcile/bringup.rs` and one consumer in
/// `WorkerManager::stop_and_clear`) so the record can be published behind an
/// `Arc` and read by the off-lock peer-synced import path.
///
/// Adding a non-`Arc` field back here re-imposes `&mut` on the record and
/// breaks that. If you need per-worker mutable state, put it behind its own
/// `Arc<Mutex<..>>` / atomic like the four slots above.
pub(in crate::afxdp) struct WorkerHandle {
    pub(in crate::afxdp) stop: Arc<AtomicBool>,
    pub(in crate::afxdp) heartbeat: Arc<AtomicU64>,
    pub(in crate::afxdp) commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    pub(in crate::afxdp) session_export_ack: Arc<AtomicU64>,
    pub(in crate::afxdp) cos_status: Arc<ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>>,
    // #869: per-worker busy/idle runtime telemetry publish slot.
    pub(in crate::afxdp) runtime_atomics: Arc<super::worker_runtime::WorkerRuntimeAtomics>,
    /// #1621: per-worker cold-path histogram publish slot. Separate
    /// from runtime_atomics per #1619 plan v3 Codex r1 finding 2 —
    /// the cold-path seqlock (cold_window_gen) is independent of the
    /// runtime seqlock (window_gen). Worker thread writes via
    /// publish_from_local() every ~1s tick; coordinator status path
    /// reads via snapshot() at each /metrics scrape (~1 Hz default).
    pub(in crate::afxdp) cold_path_atomics: Arc<super::cold_path_hist::WorkerColdPathAtomics>,
}

pub(in crate::afxdp) struct LocalTunnelSourceHandle {
    pub(in crate::afxdp) stop: Arc<AtomicBool>,
    /// #2412: the GRE local-origin thread blocks in poll(2) on this
    /// eventfd. After setting `stop`, the join paths signal it so the
    /// thread wakes immediately instead of waiting for the poll cap.
    /// `None` for the WG control thread (it polls its UDP socket with its
    /// own timeout cap and has no eventfd).
    pub(in crate::afxdp) wake: Option<Arc<TunnelWake>>,
    pub(in crate::afxdp) join: Option<JoinHandle<()>>,
}

impl LocalTunnelSourceHandle {
    /// #2412: request stop and wake the thread's poll(2). Set `stop`
    /// first so the woken thread observes it on its next stop-check, then
    /// signal the eventfd so a thread blocked in poll exits immediately
    /// rather than after the poll cap. The WG control thread has no
    /// eventfd (`wake == None`); it relies on its own poll cap as before.
    pub(in crate::afxdp) fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(wake) = &self.wake {
            wake.signal();
        }
    }
}

/// #1881: lifecycle entry for one GRE local-origin thread, keyed by
/// tunnel_endpoint_id in `Coordinator::tunnel_sources`. Mirrors
/// `WgControlEntry` minus the engine pointer — GRE has no engine, and
/// endpoint CONTENT changes (destination/source/key, routes, CoS)
/// flow to the live thread through the shared forwarding ArcSwap, so
/// only the TUN ATTACHMENT is spawn-baked identity.
///
/// `handle == None` is a TOMBSTONE (thread exited; backoff stamp +
/// attachment retained). Entries are removed ONLY by the apply-time
/// stale prune, the defer-branch snapshot prune, and `stop_inner` —
/// never by the finished sweep (#1866 D1 rule).
pub(crate) struct LocalTunnelSourceEntry {
    /// Live (or finished-but-unswept) thread handle. `None` = tombstone.
    pub(in crate::afxdp) handle: Option<LocalTunnelSourceHandle>,
    /// TUN attachment captured at spawn: logical ifindex + resolved
    /// tunnel name. Attachment drift is the ONLY restart condition.
    pub(in crate::afxdp) spawned_ifindex: i32,
    pub(in crate::afxdp) spawned_tunnel_name: String,
    /// Delivery endpoint for the CURRENT spawn attempt: the mpsc sender
    /// plus the eventfd that wakes the thread's poll(2) (#2412). A fresh
    /// channel + eventfd pair is created per spawn (the Receiver dies
    /// with the thread); a failed spawn leaves this `None`; publication
    /// into `local_tunnel_deliveries` is restricted to entries with a
    /// live handle (plan v3 SMR-2 / AGY r1 R2).
    pub(in crate::afxdp) delivery_tx: Option<LocalTunnelDelivery>,
    /// Stamped at EVERY spawn attempt (success or failure).
    pub(in crate::afxdp) last_spawn_attempt_ns: u64,
}

/// #1866: lifecycle entry for one WG control thread, keyed by
/// tunnel_endpoint_id in `Coordinator::wg_control_threads`.
///
/// An entry whose `handle` is `None` is a TOMBSTONE: the thread exited
/// (bind/TUN failure, panic, clean stop) but the entry is retained so
/// the respawn backoff (`last_spawn_attempt_ns`) and the recorded
/// identity/attachment survive until the endpoint actually leaves the
/// desired set. Entries are removed ONLY by the apply-time stale prune
/// (endpoint removed / engine identity changed / attachment changed),
/// the defer-branch snapshot prune, and `stop_inner` — never by the
/// finished sweep.
pub(crate) struct WgControlEntry {
    /// #7936: this tunnel's endpoint-resolver telemetry, owned HERE rather
    /// than by the resolver, which is a local of the control thread and dies
    /// with it. `None` on a tombstone created before any spawn.
    ///
    /// Held across restarts on purpose: a self-heal respawn reuses this Arc, so
    /// the counters do not reset at the moment an operator is most likely to be
    /// reading them.
    pub(in crate::afxdp) resolver_telemetry:
        Option<std::sync::Arc<crate::afxdp::wg::endpoint_resolver::WgEndpointResolverTelemetry>>,
    /// Live (or finished-but-unswept) thread handle. `None` = tombstone.
    pub(in crate::afxdp) handle: Option<LocalTunnelSourceHandle>,
    /// Address of the `Arc<WgEngine>` the thread was last spawned with.
    /// Kept outside `handle` so tombstones retain identity: the
    /// apply-time stale prune detects identity changes on tombstones
    /// too (removal deliberately resets the backoff — a fresh identity
    /// deserves an immediate attempt).
    pub(in crate::afxdp) engine_ptr: usize,
    /// TUN attachment captured at spawn (#1866 D5): logical ifindex +
    /// resolved tunnel name. Attachment drift is a stale condition —
    /// engine-Arc identity alone misses an interface rename with an
    /// unchanged WG crypto identity.
    pub(in crate::afxdp) spawned_ifindex: i32,
    pub(in crate::afxdp) spawned_tunnel_name: String,
    /// #2921: the resolved OUTER (underlay) MTU captured at spawn and
    /// handed by value into `wg_control_loop` (the TUN-origin egress
    /// MTU guard). The WG identity tuple (`wg_identity_unchanged`)
    /// ignores the transport table, the resolved egress ifindex, and
    /// the egress MTU, so a same-engine refresh after an underlay
    /// route/table/MTU change reuses the engine Arc and would otherwise
    /// keep this stale value forever — the transit/forwarded path
    /// re-resolves the underlay per-snapshot while the local TUN path
    /// kept the spawn-time capture. The apply-time stale prune compares
    /// this against a fresh `resolve_wg_outer_mtu` and restarts the
    /// thread when they diverge, so both packet origins enforce the
    /// SAME current outer MTU.
    pub(in crate::afxdp) spawned_outer_mtu: usize,
    /// #5291: the resolved OUTER (underlay) egress MTU captured at spawn
    /// PER PEER (keyed by peer public key), handed by value into
    /// `wg_control_loop` alongside `spawned_outer_mtu`. The TUN-origin
    /// egress guard selects the peer that owns the inner destination's
    /// AllowedIPs and must size that peer's encap against ITS OWN
    /// underlay MTU — the AF_XDP transit path already resolves per-peer
    /// (#2845/#3219). Only peers with a CONFIGURED endpoint (resolvable
    /// while `forwarding` is reachable) appear here; a peer absent from
    /// the map falls back to `spawned_outer_mtu`. The apply-time stale
    /// prune compares this against a fresh `resolve_wg_per_peer_outer_mtus`
    /// (alongside the scalar) and restarts the thread when they diverge,
    /// so a NON-first peer's underlay MTU change — which moves no
    /// scalar — still refreshes the TUN-origin guard.
    pub(in crate::afxdp) spawned_per_peer_outer_mtu: std::collections::HashMap<[u8; 32], usize>,
    /// Stamped at EVERY spawn attempt (success or failure), before the
    /// outcome is known. Tombstone-respawn backoff keys off this.
    pub(in crate::afxdp) last_spawn_attempt_ns: u64,
    /// #9521: whether this thread may write kernel-path transport plaintext to
    /// its wgN TUN, decided at spawn from the endpoint's listen port and the
    /// snapshot's steered port. The apply-time stale prune restarts the thread
    /// when a later snapshot changes the answer, so re-steering (adding or
    /// removing the tunnel that sorts first) takes effect without a restart.
    pub(in crate::afxdp) spawned_kernel_transport: WgKernelTransport,
}

/// #9521: may a WireGuard control thread write the plaintext of a TRANSPORT
/// record it received on its kernel socket to its wgN TUN?
///
/// The AF_XDP shim claims transport data for exactly one listen port
/// (`UserspaceCtrl.wg_listen_port`, programmed from
/// `ConfigSnapshot.wg_steered_listen_port`) and hands it to the worker, which
/// adjudicates the inner packet in the pipeline (#8274). For that port a record
/// reaches this socket only on a path the shim does not cover, and #8274
/// deliberately kept delivering it there (docs/log/8274.md, "The residual,
/// stated rather than closed"). A record for ANY OTHER port is never claimed:
/// it reaches the kernel on every path, and writing its plaintext to the TUN
/// gave an authenticated peer the kernel's forwarding path with no zone policy,
/// no session and no counters. That write is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WgKernelTransport {
    /// The steered port: deliver to the TUN, as before #9521.
    Deliver,
    /// Any other port: authenticate the record (so key confirmation, the replay
    /// window and endpoint roaming behave as for a keepalive), then drop it and
    /// count `rx_unsteered_transport_drops`.
    DropUnsteered,
}

impl WgKernelTransport {
    /// Fail closed: a snapshot that names no steered port (0) delivers for NO
    /// endpoint. The Go control plane stamps the port whenever a WireGuard
    /// tunnel is configured, and the protocol version refuses a daemon that
    /// would not.
    pub(crate) fn for_listen_port(listen_port: u16, steered_listen_port: u16) -> Self {
        if steered_listen_port != 0 && listen_port == steered_listen_port {
            Self::Deliver
        } else {
            Self::DropUnsteered
        }
    }
}

#[derive(Clone)]
pub(in crate::afxdp) struct BindingPlan {
    pub(in crate::afxdp) status: BindingStatus,
    pub(in crate::afxdp) live: Arc<BindingLiveState>,
    pub(in crate::afxdp) xsk_map_fd: c_int,
    pub(in crate::afxdp) heartbeat_map_fd: c_int,
    pub(in crate::afxdp) session_map_fd: c_int,
    pub(in crate::afxdp) conntrack_v4_fd: c_int,
    pub(in crate::afxdp) conntrack_v6_fd: c_int,
    pub(in crate::afxdp) ring_entries: u32,
    pub(in crate::afxdp) bind_strategy: AfXdpBindStrategy,
    pub(in crate::afxdp) poll_mode: crate::PollMode,
    pub(in crate::afxdp) shared_umem: SharedUmemBindingPlan,
}

/// #6245: the phase in which a per-slot binding setup TERMINALLY failed,
/// carried (as an owned, Copy discriminant) in [`BindingSetupFailure`]. The
/// shared-UMEM-group-attempt-then-recovered case is NOT a terminal failure —
/// it is reported separately as [`BindingRecoveredFallback`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum BindingSetupPhase {
    /// A private (non-shared-UMEM) XSK/UMEM bind failed for this slot.
    Private,
    /// A shared-UMEM group's bind failed AND this slot's private-UMEM
    /// fallback ALSO failed — the slot has no surviving binding. (A group
    /// whose fallback fully recovered is a [`BindingRecoveredFallback`], not
    /// a failure.)
    SharedFallback,
}

impl BindingSetupPhase {
    pub(in crate::afxdp) fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::SharedFallback => "shared-fallback",
        }
    }
}

/// #6245: an EXPLICIT per-slot binding-setup failure carried in
/// [`WorkerStartupReport`]. Pre-#6245 a failed binding was reported ONLY by
/// OMISSION — the slot was simply absent from `bound_slots`, discarding the
/// causal error, the phase, and the fallback path (`worker_loop_setup` merely
/// logged + mutated `BindingLiveState.last_error`). The readiness barrier could
/// prove incompleteness (bound != planned) but not say WHY. This makes the
/// cause explicit so the barrier's fail-closed diagnostic carries the slot,
/// phase, and owned error string. Owned strings only — this is the one-shot
/// cold setup path, never per-packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct BindingSetupFailure {
    pub(in crate::afxdp) slot: u32,
    /// #7497: the NIC coordinate the slot was for. A slot number is a position
    /// in the minted sequence with no external meaning, and since per-interface
    /// queue planning the slot -> (interface, queue) mapping shifts whenever any
    /// interface's queue count changes — so an operator reading a fail-closed
    /// bringup refusal could not tell WHICH queue failed.
    pub(in crate::afxdp) interface: String,
    pub(in crate::afxdp) queue_id: u32,
    pub(in crate::afxdp) phase: BindingSetupPhase,
    pub(in crate::afxdp) reason: String,
}

/// #7497: the NIC coordinate of a binding, captured from its plan's status
/// before the plan is moved into the bind call.
///
/// Exists so the capture is ONE named operation with a test behind it. The
/// three fields were previously read individually at each failure site, which
/// left the capture unguarded: emptying the interface there passed the entire
/// suite, because every cell that renders a failure constructs one directly
/// rather than going through a bind. Routing the capture through here does not
/// make the call sites' `of(&plan.status)` provable — that still needs a real
/// bind failure — but it reduces each site to one expression that cannot
/// silently read the wrong field, and puts the field-by-field copy under test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct BindingCoordinate {
    pub(in crate::afxdp) slot: u32,
    pub(in crate::afxdp) interface: String,
    pub(in crate::afxdp) queue_id: u32,
}

impl BindingCoordinate {
    pub(in crate::afxdp) fn of(status: &crate::protocol::BindingStatus) -> Self {
        Self {
            slot: status.slot,
            interface: status.interface.clone(),
            queue_id: status.queue_id,
        }
    }
}

impl BindingSetupFailure {
    /// Build a failure at a coordinate, so the three coordinate fields travel
    /// together rather than being re-listed at each site.
    pub(in crate::afxdp) fn at(
        coord: &BindingCoordinate,
        phase: BindingSetupPhase,
        reason: String,
    ) -> Self {
        Self {
            slot: coord.slot,
            interface: coord.interface.clone(),
            queue_id: coord.queue_id,
            phase,
            reason,
        }
    }
}

/// #6245: a shared-UMEM group whose group bind FAILED but which then RECOVERED
/// via a COMPLETE private-UMEM fallback (every member slot rebound privately).
/// This is a recorded DEGRADATION, not a terminal failure — the readiness
/// criterion is unaffected (all planned slots still bound), so a fully
/// recovered group must NOT fail the reconcile. Modeled separately from
/// [`BindingSetupFailure`] per the #6245 design amendment so a recovered
/// fallback is never conflated with a terminal per-slot failure. Purely
/// diagnostic: it makes the recovered path visible in the startup report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct BindingRecoveredFallback {
    pub(in crate::afxdp) group: String,
    pub(in crate::afxdp) reason: String,
}

/// #5143: a newly-started worker's one-shot STARTUP READINESS report,
/// sent once — after the worker finishes its in-thread XSK/UMEM binds in
/// `worker_loop_setup` and BEFORE it enters its steady poll loop — back to
/// `bring_up_workers` over the per-reconcile startup channel.
///
/// `bound_slots` is the set of planned binding slots whose XSK actually bound
/// (derived from the bindings the worker successfully constructed). A worker
/// whose in-thread bind failed for one or more planned bindings reports a set
/// SMALLER than its planned set. The `bring_up_workers` readiness barrier
/// compares this against the slot set it dispatched to the worker; any
/// shortfall (or a worker that never reports within the bounded deadline)
/// fails the reconcile closed. HEARTBEAT != READINESS: a live heartbeat alone
/// no longer satisfies the reconcile transaction — one READY binding must exist
/// per required plan.
///
/// #6245: `binding_failures` now carries the EXPLICIT per-slot terminal
/// failures (slot + phase + owned error) that produced any shortfall, instead
/// of leaving the barrier to infer the cause from the missing slots alone.
/// `recovered_fallbacks` records shared-UMEM groups that failed their group
/// bind but fully recovered via private fallback — a diagnostic degradation
/// that does NOT affect readiness (all slots still bound). Both are sorted
/// deterministically (failures by slot, fallbacks by group) so the surfaced
/// diagnostic is stable regardless of setup/channel ordering. The success path
/// is unchanged: a worker that bound its full planned set reports both vecs
/// empty.
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct WorkerStartupReport {
    pub(in crate::afxdp) worker_id: u32,
    pub(in crate::afxdp) bound_slots: Vec<u32>,
    pub(in crate::afxdp) binding_failures: Vec<BindingSetupFailure>,
    pub(in crate::afxdp) recovered_fallbacks: Vec<BindingRecoveredFallback>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) enum SharedUmemMode {
    #[default]
    Off,
    SameDeviceDebug,
    CrossNic,
}

impl SharedUmemMode {
    pub(in crate::afxdp) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::SameDeviceDebug => "same-device-debug",
            Self::CrossNic => "cross-nic",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) enum SharedUmemSocketRole {
    #[default]
    Private,
    Owner,
    Secondary,
}

impl SharedUmemSocketRole {
    pub(in crate::afxdp) fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Owner => "owner",
            Self::Secondary => "secondary",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct SharedUmemBindingPlan {
    pub(in crate::afxdp) mode: SharedUmemMode,
    pub(in crate::afxdp) group_key: String,
    pub(in crate::afxdp) socket_role: SharedUmemSocketRole,
    pub(in crate::afxdp) disabled_reason: String,
}

impl SharedUmemBindingPlan {
    pub(in crate::afxdp) fn private() -> Self {
        Self::default()
    }

    pub(in crate::afxdp) fn shared(
        mode: SharedUmemMode,
        group_key: String,
        socket_role: SharedUmemSocketRole,
    ) -> Self {
        Self {
            mode,
            group_key,
            socket_role,
            disabled_reason: String::new(),
        }
    }

    pub(in crate::afxdp) fn disabled(mode: SharedUmemMode, reason: String) -> Self {
        Self {
            mode,
            group_key: String::new(),
            socket_role: SharedUmemSocketRole::Private,
            disabled_reason: reason,
        }
    }

    pub(in crate::afxdp) fn is_shared(&self) -> bool {
        self.socket_role != SharedUmemSocketRole::Private && !self.group_key.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct ValidationState {
    pub(in crate::afxdp) snapshot_installed: bool,
    pub(in crate::afxdp) config_generation: u64,
    pub(in crate::afxdp) fib_generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(in crate::afxdp) enum HAForwardingLease {
    #[default]
    Inactive,
    ActiveUntil(u64),
}

impl HAForwardingLease {
    pub(in crate::afxdp) fn active(self, now_secs: u64) -> bool {
        matches!(self, Self::ActiveUntil(until) if until != 0 && now_secs <= until)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(in crate::afxdp) struct HAGroupRuntime {
    pub(in crate::afxdp) active: bool,
    pub(in crate::afxdp) watchdog_timestamp: u64,
    pub(in crate::afxdp) lease: HAForwardingLease,
}

impl HAGroupRuntime {
    pub(in crate::afxdp) fn active_lease_until(
        watchdog_timestamp: u64,
        now_secs: u64,
    ) -> HAForwardingLease {
        HAForwardingLease::ActiveUntil(
            watchdog_timestamp
                .max(now_secs)
                .saturating_add(super::HA_WATCHDOG_STALE_AFTER_SECS),
        )
    }

    pub(in crate::afxdp) fn is_forwarding_active(self, now_secs: u64) -> bool {
        self.active && self.lease.active(now_secs)
    }
}

#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ResolutionDebug {
    pub(in crate::afxdp) ingress_ifindex: i32,
    pub(in crate::afxdp) src_ip: Option<IpAddr>,
    pub(in crate::afxdp) dst_ip: Option<IpAddr>,
    pub(in crate::afxdp) src_port: u16,
    pub(in crate::afxdp) dst_port: u16,
    /// #919: stored as zone IDs; the slow-path `into_*` conversion
    /// looks up the name via `forwarding.zone_id_to_name`.
    pub(in crate::afxdp) from_zone: Option<u16>,
    pub(in crate::afxdp) to_zone: Option<u16>,
}

impl ResolutionDebug {
    pub(in crate::afxdp) fn from_flow(ingress_ifindex: i32, flow: &SessionFlow) -> Self {
        Self {
            ingress_ifindex,
            src_ip: Some(flow.src_ip),
            dst_ip: Some(flow.dst_ip),
            src_port: flow.forward_key.src_port,
            dst_port: flow.forward_key.dst_port,
            from_zone: None,
            to_zone: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct LearnedNeighborKey {
    pub(in crate::afxdp) ingress_ifindex: i32,
    pub(in crate::afxdp) ingress_vlan_id: u16,
    pub(in crate::afxdp) src_ip: IpAddr,
    pub(in crate::afxdp) src_mac: [u8; 6],
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) enum WorkerCommand {
    UpsertSynced(SyncedSessionEntry),
    UpsertLocal(SyncedSessionEntry),
    DeleteSynced(SessionKey),
    DemoteOwnerRGS {
        owner_rgs: Vec<i32>,
    },
    RefreshOwnerRGS {
        owner_rgs: Vec<i32>,
    },
    ExportOwnerRGSessions {
        sequence: u64,
        owner_rgs: Vec<i32>,
    },
    /// #7919: READ-ONLY diagnostic. Report what THIS worker's own session table
    /// holds for one 5-tuple, into the worker's `counter_query_*` reply slots.
    ///
    /// Broadcast to every worker, because the question is precisely "what does
    /// EACH worker's copy say": every worker holds a copy of every session
    /// (measured), but only the worker whose packets land accounts for one, so
    /// a per-flow answer needs all of them, not just the owner.
    ///
    /// It mutates nothing. The session table is read, never touched — a
    /// diagnostic that perturbs the state it reports would be worse than no
    /// diagnostic, and this one exists to adjudicate between two explanations
    /// that differ only in what the table holds.
    QuerySessionCounters {
        sequence: u64,
        key: SessionKey,
    },
    EnqueueShapedLocal(TxRequest),
    /// #941 Work item C: vacate ALL V_min slots owned by this worker
    /// across every binding's shared_exact queues. Enqueued by the
    /// coordinator on HA demotion (RG primary→secondary). The actual
    /// vacate runs on the worker thread (single-writer invariant) —
    /// this command sets a flag in `WorkerCommandResults`; the outer
    /// poll loop dispatches via `vacate_all_shared_exact_slots`.
    /// #7699: learn a PPTP call association on this worker.
    ///
    /// Broadcast to EVERY worker, not sent to one. The control channel
    /// (TCP/1723) and the GRE data channel are not reliably co-located — RSS
    /// hashes the flow tuple, so they share a worker only by chance — and the
    /// data packets must resolve on whichever worker they land on.
    InstallPptpCall {
        call: crate::session::pptp::PptpCall,
        /// The control channel that taught it — an association must not
        /// outlive the channel that set it up (#7699 stage 3).
        control: crate::session::pptp::ControlChannelId,
        /// When it was learned, carried rather than read from a clock in the
        /// drain so the idle bound is deterministic in tests and identical on
        /// every worker receiving this broadcast.
        learned_ns: u64,
    },
    /// #7699: forget a PPTP call association, by handle. Also broadcast.
    ///
    /// Teardown must reach every worker for the same reason the install does; a
    /// worker that keeps a stale association re-pairs a REUSED 16-bit call id
    /// onto a dead handle, which is a mis-attribution rather than a leak.
    ForgetPptpCall(u32),
    VacateAllSharedExactSlots,
}

#[derive(Default)]
pub(in crate::afxdp) struct DebugPollCounters {
    pub(in crate::afxdp) rx: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) tx: u64,
    pub(in crate::afxdp) forward: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) local: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) session_hit: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) session_miss: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) session_create: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) no_route: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) missing_neigh: u64,
    /// #5174: NAT64 MissingNeighbor fail-closed drops. Bumped when a PERMITTED
    /// NAT64 flow (IPv6 dst matching a Pref64) whose extracted-IPv4 next-hop is
    /// unresolved is dropped after firing the neighbor probe instead of seeding
    /// a plain-forward session + buffering the untranslated IPv6 frame (which the
    /// same-family cold-path replay cannot translate). The flow recovers via the
    /// ForwardCandidate path once the IPv4 neighbor resolves.
    #[allow(dead_code)]
    pub(in crate::afxdp) nat64_missing_neigh_drop: u64,
    /// #1651 B3: dead-host negative-cache fast-fail count. Bumped when a
    /// MissingNeighbor packet to a negatively-cached (un-expired,
    /// still-unresolved) dst is recycled without buffering.
    #[allow(dead_code)]
    pub(in crate::afxdp) neg_neigh_fast_fail: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) policy_deny: u64,
    /// #3610/M07: host-inbound-traffic admission denies, split out of
    /// `policy_deny` so a control-plane host-inbound drop is not conflated with a
    /// transit security-policy deny in the periodic debug report.
    #[allow(dead_code)]
    pub(in crate::afxdp) host_inbound_deny: u64,
    /// #7212: established sessions REVOKED by a static interface INPUT filter
    /// revalidation — the operator attached or tightened a purely static
    /// address/protocol/port filter and an already-established flow is now
    /// denied by it. Distinct from `policy_deny` (a security-policy verdict on a
    /// NEW flow) and from the per-packet #1430/#2362 re-eval drops, which drop a
    /// packet without revoking the session. Counted once per revoked session,
    /// not per dropped packet: the session is torn down on the first denied
    /// packet and every later packet of that 5-tuple takes the session-MISS path.
    #[allow(dead_code)]
    pub(in crate::afxdp) filter_revoked_sessions: u64,
    /// #8356: established sessions revoked because the live ZONE POLICY denies
    /// the flow — the policy sibling of `filter_revoked_sessions` above. A
    /// commit that narrows zone policy now tears down live flows it denies, the
    /// same way #5858/#7212 already does for a narrowed input filter.
    ///
    /// Distinct from `policy_deny`, which is a verdict on a NEW flow at the
    /// session-MISS path. This one counts a flow that was ALREADY established
    /// under an older generation and did not survive re-derivation under the
    /// current one. A non-zero value here right after a commit is the expected,
    /// intended signal — it is what the operator's narrowed policy did.
    ///
    /// Counted once per revoked session, not per dropped packet.
    #[allow(dead_code)]
    pub(in crate::afxdp) policy_revoked_sessions: u64,
    /// #9519: packets DROPPED because they hit an established session from a
    /// zone other than the one that admitted it, and their own zone's policy
    /// does not permit them. Per packet, not per session: nothing is revoked,
    /// because the session belongs to the zone that admitted it. Distinct from
    /// `policy_deny` (a NEW flow at the session-miss path) and from
    /// `policy_revoked_sessions` (an owner's session its own policy no longer
    /// admits).
    #[allow(dead_code)]
    pub(in crate::afxdp) foreign_authority_drops: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) ha_inactive: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) no_egress_binding: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) build_fail: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) tx_err: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) metadata_err: u64,
    pub(in crate::afxdp) disposition_other: u64,
    pub(in crate::afxdp) enqueue_ok: u64,
    pub(in crate::afxdp) enqueue_inplace: u64,
    pub(in crate::afxdp) enqueue_direct: u64,
    pub(in crate::afxdp) enqueue_copy: u64,
    pub(in crate::afxdp) rx_from_trust: u64,
    pub(in crate::afxdp) rx_from_wan: u64,
    pub(in crate::afxdp) fwd_trust_to_wan: u64,
    pub(in crate::afxdp) fwd_wan_to_trust: u64,
    pub(in crate::afxdp) nat_applied_snat: u64,
    pub(in crate::afxdp) nat_applied_dnat: u64,
    pub(in crate::afxdp) nat_applied_none: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) frame_build_none: u64,
    pub(in crate::afxdp) rx_tcp_rst: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) tx_tcp_rst: u64,
    pub(in crate::afxdp) rx_bytes_total: u64,
    pub(in crate::afxdp) tx_bytes_total: u64,
    /// #5190 (A1-b1-F7): count of RX descriptors longer than the FIXED
    /// 1514-byte Ethernet-II + 1500-MTU frame size. Named for the constant
    /// it actually tests, NOT `rx_oversized`: there is no per-interface MTU
    /// or jumbo awareness here (this runs before the shim metadata is even
    /// parsed, so the VLAN-tag presence is not yet known), so a perfectly
    /// valid in-band 802.1Q-tagged full-MTU frame (1518 bytes) and every
    /// jumbo frame land in this counter. Reading it as an anomaly/error
    /// signal is wrong — on the VLAN-trunked WAN path it counts ordinary
    /// traffic. Debug-build diagnostic only: the periodic report that prints
    /// it is `#[cfg(feature = "debug-log")]`.
    pub(in crate::afxdp) rx_over_1514: u64,
    pub(in crate::afxdp) rx_max_frame: u32,
    pub(in crate::afxdp) tx_max_frame: u32,
    pub(in crate::afxdp) seg_needed_but_none: u64,
    pub(in crate::afxdp) wan_return_hits: u64,
    #[allow(dead_code)]
    pub(in crate::afxdp) wan_return_misses: u64,
    pub(in crate::afxdp) rx_tcp_fin: u64,
    pub(in crate::afxdp) rx_tcp_synack: u64,
    pub(in crate::afxdp) rx_tcp_zero_window: u64,
    pub(in crate::afxdp) fwd_tcp_fin: u64,
    pub(in crate::afxdp) fwd_tcp_rst: u64,
    pub(in crate::afxdp) fwd_tcp_zero_window: u64,
}

/// #945: shared/passed-through context for `poll_binding_process_descriptor`.
///
/// The fields are shared (`&'a` or `&'a Arc<...>`) references that
/// the function reads from or that wrap interior-mutable state behind
/// `Mutex`/`Arc`. NOT read-only in the strict sense — several entries
/// like `dynamic_neighbors` are mutated through their inner `Mutex`
/// (e.g. `dynamic_neighbors.lock().insert(...)` at afxdp.rs ARP/NA
/// learn sites).
///
/// Constructed once per RX-batch call at the
/// `poll_binding_process_descriptor` call site. `'a` is covariant.
pub(in crate::afxdp) struct WorkerContext<'a> {
    pub(in crate::afxdp) ident: &'a BindingIdentity,
    pub(in crate::afxdp) binding_lookup: &'a WorkerBindingLookup,
    pub(in crate::afxdp) mirror_targets: &'a MirrorTargetMap,
    pub(in crate::afxdp) forwarding: &'a ForwardingState,
    pub(in crate::afxdp) ha_state: &'a BTreeMap<i32, HAGroupRuntime>,
    pub(in crate::afxdp) dynamic_neighbors: &'a Arc<super::sharded_neighbor::ShardedNeighborMap>,
    /// #7699: the PPTP control-segment inbox the data path copies a TCP/1723
    /// segment into.
    ///
    /// Carried here for the same reason as `dynamic_neighbors` directly above,
    /// and under the same constraint: a stage writes it through interior
    /// mutability, and the caller does not need visibility into what was
    /// learned for the SAME packet — an association learned from a control
    /// segment is needed by the GRE data packets that follow it, never by the
    /// segment itself. The alternative, threading `&mut SessionTable` into a
    /// hot-path stage, would widen that stage's contract permanently for one
    /// feature, and could not work anyway: no `&mut sessions` site in the
    /// worker loop has a packet frame.
    pub(in crate::afxdp) pptp_control: &'a Arc<crate::session::pptp_control::PptpControlInbox>,
    /// #1769: shared on-demand neighbor resolver. `Some` in production
    /// (spawned at coordinator bring-up); `None` in unit tests that do
    /// not exercise the resolver path. The `MissingNeighbor`
    /// negative-cache fast-fail enqueues the dst here so a single-key
    /// RTM_GETNEIGH/probe runs off the hot path.
    pub(in crate::afxdp) neighbor_resolver:
        Option<&'a Arc<super::neighbor_resolver::NeighborResolver>>,
    pub(in crate::afxdp) shared_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) shared_nat_sessions:
        &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) shared_forward_wire_sessions:
        &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) shared_owner_rg_indexes: &'a SharedSessionOwnerRgIndexes,
    /// #6471: the node-shared live-IKE-exchange table backing Stage 11's
    /// established-vs-forged discriminator on the IPsec secondary path
    /// (seeded on admitted NEW IKE initiations and on firewall-initiated
    /// outbound IKE via the GRE local-origin thread). Touched ONLY for
    /// IKE-to-self packets — never for ESP/AH or the general session path.
    pub(in crate::afxdp) ike_exchanges: &'a crate::afxdp::forwarding::SharedIkeExchangeTable,
    pub(in crate::afxdp) slow_path: Option<&'a Arc<SlowPathReinjector>>,
    pub(in crate::afxdp) event_stream: Option<&'a crate::event_stream::EventStreamWorkerHandle>,
    pub(in crate::afxdp) local_tunnel_deliveries:
        &'a Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    pub(in crate::afxdp) recent_exceptions: &'a Arc<Mutex<ExceptionEventRing>>,
    pub(in crate::afxdp) last_resolution: &'a Arc<Mutex<Option<ResolutionEvent>>>,
    pub(in crate::afxdp) peer_worker_commands: &'a [Arc<Mutex<VecDeque<WorkerCommand>>>],
    /// #8114 item 4: the SAME queues as `peer_worker_commands` plus this
    /// worker's own, but KEYED BY WORKER ID.
    ///
    /// It exists because a `DeleteSynced` refused by a full sibling queue
    /// leaves that sibling holding a NAT reservation it will now never release,
    /// and the repair — `release_source_nat_allocation_for_worker` — must name
    /// the worker whose holder bit to drop. `peer_worker_commands` cannot: the
    /// ids are dropped where the slice is built (`reconcile/bringup.rs` maps
    /// `.filter(|(id, _)| **id != worker_id).map(|(_, queue)| queue.clone())`).
    ///
    /// Releasing for a worker that WILL still process its delete is safe
    /// (idempotent); releasing for one that is still FORWARDING the flow is
    /// not — its port could be handed to another flow — so "release for every
    /// worker" is not a substitute for the id.
    pub(in crate::afxdp) worker_commands_by_id:
        &'a BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    pub(in crate::afxdp) dnat_fds: &'a DnatTableFds,
    pub(in crate::afxdp) rg_epochs: &'a [AtomicU32; MAX_RG_EPOCHS],
    /// #1620: cold-path latency histogram sample mask. Loaded once
    /// per poll cycle from `ForwardingState.cold_path_sample_mask`
    /// (via ArcSwap); can change across snapshot applies. `0xff`
    /// (1-in-256) by default; `0` (1-in-1) when operator explicitly
    /// enables 1-in-1 sampling for the bounded-cohort microbench.
    /// Read on every session-miss packet at the poll_descriptor
    /// pre-eval gate.
    pub(in crate::afxdp) cold_path_sample_mask: u64,
}

/// #8114 item 4: the empty `worker_commands_by_id` a `WorkerContext` fixture
/// uses when it is not exercising the dropped-delete repair.
///
/// Returned by reference from a `OnceLock` so a fixture can name it inline
/// without a local binding, and EMPTY on purpose: the repair resolves a refused
/// queue to its worker id by `Arc` identity against this map, so an empty one
/// means "no id resolved, no repair attempted" and every pre-#8114 fixture keeps
/// its exact behaviour. A cell that means to exercise the repair builds a real
/// map holding the same `Arc`s it puts in `peer_worker_commands`.
#[cfg(test)]
pub(in crate::afxdp) fn empty_worker_commands_by_id()
-> &'static BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> {
    static EMPTY: std::sync::OnceLock<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>> =
        std::sync::OnceLock::new();
    EMPTY.get_or_init(BTreeMap::new)
}

/// #945: mutable telemetry context for `poll_binding_process_descriptor`.
pub(in crate::afxdp) struct TelemetryContext<'a> {
    pub(in crate::afxdp) dbg: &'a mut DebugPollCounters,
    pub(in crate::afxdp) counters: &'a mut BatchCounters,
}

#[derive(Clone, Default)]
pub(crate) struct MirrorTargetMap {
    by_if_queue: FastMap<(i32, u32), Arc<BindingLiveState>>,
    by_if: FastMap<i32, MirrorTargetIfEntry>,
}

#[derive(Clone)]
struct MirrorTargetIfEntry {
    live: Arc<BindingLiveState>,
    count: usize,
}

impl MirrorTargetMap {
    pub(in crate::afxdp) fn insert(
        &mut self,
        ident: &BindingIdentity,
        live: Arc<BindingLiveState>,
    ) {
        self.by_if_queue
            .insert((ident.ifindex, ident.queue_id), live.clone());
        self.by_if
            .entry(ident.ifindex)
            .and_modify(|entry| entry.count = entry.count.saturating_add(1))
            .or_insert(MirrorTargetIfEntry { live, count: 1 });
    }

    pub(in crate::afxdp) fn target_live(
        &self,
        egress_ifindex: i32,
        ingress_queue_id: u32,
    ) -> Option<Arc<BindingLiveState>> {
        self.by_if_queue
            .get(&(egress_ifindex, ingress_queue_id))
            .cloned()
            .or_else(|| {
                self.by_if
                    .get(&egress_ifindex)
                    .filter(|entry| entry.count == 1)
                    .map(|entry| entry.live.clone())
            })
    }
}
