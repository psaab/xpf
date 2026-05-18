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

pub(in crate::afxdp) struct WorkerHandle {
    pub(in crate::afxdp) stop: Arc<AtomicBool>,
    pub(in crate::afxdp) heartbeat: Arc<AtomicU64>,
    pub(in crate::afxdp) commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    pub(in crate::afxdp) session_export_ack: Arc<AtomicU64>,
    pub(in crate::afxdp) cos_status: Arc<ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>>,
    // #869: per-worker busy/idle runtime telemetry publish slot.
    pub(in crate::afxdp) runtime_atomics: Arc<super::worker_runtime::WorkerRuntimeAtomics>,
    pub(in crate::afxdp) join: Option<JoinHandle<()>>,
}

pub(in crate::afxdp) struct LocalTunnelSourceHandle {
    pub(in crate::afxdp) stop: Arc<AtomicBool>,
    pub(in crate::afxdp) join: Option<JoinHandle<()>>,
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
    EnqueueShapedLocal(TxRequest),
    /// #941 Work item C: vacate ALL V_min slots owned by this worker
    /// across every binding's shared_exact queues. Enqueued by the
    /// coordinator on HA demotion (RG primary→secondary). The actual
    /// vacate runs on the worker thread (single-writer invariant) —
    /// this command sets a flag in `WorkerCommandResults`; the outer
    /// poll loop dispatches via `vacate_all_shared_exact_slots`.
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
    #[allow(dead_code)]
    pub(in crate::afxdp) policy_deny: u64,
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
    pub(in crate::afxdp) rx_oversized: u64,
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
/// All 16 fields are shared (`&'a` or `&'a Arc<...>`) references that
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
    pub(in crate::afxdp) shared_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) shared_nat_sessions:
        &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) shared_forward_wire_sessions:
        &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) shared_owner_rg_indexes: &'a SharedSessionOwnerRgIndexes,
    pub(in crate::afxdp) slow_path: Option<&'a Arc<SlowPathReinjector>>,
    pub(in crate::afxdp) event_stream: Option<&'a crate::event_stream::EventStreamWorkerHandle>,
    pub(in crate::afxdp) local_tunnel_deliveries:
        &'a Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    pub(in crate::afxdp) recent_exceptions: &'a Arc<Mutex<VecDeque<ExceptionStatus>>>,
    pub(in crate::afxdp) last_resolution: &'a Arc<Mutex<Option<PacketResolution>>>,
    pub(in crate::afxdp) peer_worker_commands: &'a [Arc<Mutex<VecDeque<WorkerCommand>>>],
    pub(in crate::afxdp) dnat_fds: &'a DnatTableFds,
    pub(in crate::afxdp) rg_epochs: &'a [AtomicU32; MAX_RG_EPOCHS],
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
