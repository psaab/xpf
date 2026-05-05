use super::*;
mod bpf_maps;
mod cos_state;
mod ha_state;
mod inject;
mod neighbor_manager;
mod session_manager;
mod status;
mod supervisor;
mod worker_manager;
use supervisor::{spawn_supervised_aux, spawn_supervised_worker};
pub(crate) use bpf_maps::BpfMaps;
pub(crate) use cos_state::SharedCoSState;
pub(in crate::afxdp) use ha_state::HaState;
pub(crate) use neighbor_manager::NeighborManager;
pub(in crate::afxdp) use session_manager::SessionManager;
pub(in crate::afxdp) use worker_manager::WorkerManager;

pub struct Coordinator {
    pub(crate) bpf_maps: BpfMaps,
    pub(crate) slow_path: Option<Arc<SlowPathReinjector>>,
    pub(crate) local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    pub(crate) tunnel_sources: BTreeMap<u16, LocalTunnelSourceHandle>,
    pub(crate) last_slow_path_status: SlowPathStatus,
    pub(in crate::afxdp) ha: HaState,
    pub(crate) cos: SharedCoSState,
    pub(crate) shared_validation: Arc<ArcSwap<ValidationState>>,
    pub(crate) neighbors: NeighborManager,
    pub(in crate::afxdp) sessions: SessionManager,
    pub(in crate::afxdp) workers: WorkerManager,
    pub(crate) forwarding: ForwardingState,
    pub(crate) recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    pub(crate) recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    pub(crate) last_resolution: Arc<Mutex<Option<PacketResolution>>>,
    pub(crate) validation: ValidationState,
    pub(crate) reconcile_calls: u64,
    pub(crate) last_reconcile_stage: String,
    pub(crate) poll_mode: crate::PollMode,
    pub(crate) event_stream: Option<crate::event_stream::EventStreamSender>,
    pub(crate) cos_owner_worker_by_queue: BTreeMap<(i32, u8), u32>,
    /// Monotonic timestamp (secs) of the last HA flow cache flush (#312).
    pub(crate) last_cache_flush_at: Arc<AtomicU64>,
    /// Per-RG epoch counters for O(1) flow cache invalidation on demotion.
    /// Shared with all worker threads; bumped atomically on demotion/activation.
    pub(crate) rg_epochs: Arc<[AtomicU32; MAX_RG_EPOCHS]>,
    /// #925 Phase 1: panic-payload slot per worker, keyed by `worker_id`.
    /// `BTreeMap` (not `Vec`) so non-contiguous or reused worker IDs map
    /// stably; written exactly once when the worker dies, read at most
    /// once per gRPC status poll (~1 Hz). Not on the packet hot path.
    pub(crate) worker_panics: BTreeMap<u32, Arc<Mutex<Option<String>>>>,
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            bpf_maps: BpfMaps::default(),
            slow_path: None,
            local_tunnel_deliveries: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            tunnel_sources: BTreeMap::new(),
            last_slow_path_status: SlowPathStatus::default(),
            ha: HaState::new(),
            cos: SharedCoSState::new(),
            shared_validation: Arc::new(ArcSwap::from_pointee(ValidationState::default())),
            neighbors: NeighborManager::new(),
            sessions: SessionManager::new(),
            workers: WorkerManager::new(),
            forwarding: ForwardingState::default(),
            recent_exceptions: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RECENT_EXCEPTIONS))),
            recent_session_deltas: Arc::new(Mutex::new(VecDeque::with_capacity(
                MAX_RECENT_SESSION_DELTAS,
            ))),
            last_resolution: Arc::new(Mutex::new(None)),
            validation: ValidationState::default(),
            reconcile_calls: 0,
            last_reconcile_stage: "idle".to_string(),
            poll_mode: crate::PollMode::BusyPoll,
            event_stream: None,
            cos_owner_worker_by_queue: BTreeMap::new(),
            last_cache_flush_at: Arc::new(AtomicU64::new(0)),
            rg_epochs: Arc::new(std::array::from_fn(|_| AtomicU32::new(0))),
            worker_panics: BTreeMap::new(),
        }
    }

    pub fn stop(&mut self) {
        self.stop_inner(true);
        // NOTE: Do NOT tear down event_stream here. The event stream must
        // survive across XSK bind/unbind cycles (e.g. when forwarding_armed
        // is temporarily false during startup). Use stop_with_event_stream()
        // for final process shutdown.
    }

    /// Full shutdown including the event stream. Called only on process exit.
    pub fn stop_with_event_stream(&mut self) {
        self.stop_inner(true);
        if let Some(mut es) = self.event_stream.take() {
            es.stop();
        }
    }

    /// Start the event stream sender. The I/O thread connects to the daemon
    /// listener at `socket_path` and pushes binary-framed session events.
    pub fn start_event_stream(&mut self, socket_path: &str) {
        self.event_stream = Some(crate::event_stream::EventStreamSender::new(socket_path));
    }

    /// Get a lightweight handle for worker threads to push events.
    pub fn event_stream_worker_handle(
        &self,
    ) -> Option<crate::event_stream::EventStreamWorkerHandle> {
        self.event_stream.as_ref().map(|es| es.worker_handle())
    }

    /// Event stream statistics for status reporting.
    pub fn event_stream_stats(&self) -> Option<crate::event_stream::EventStreamStats> {
        self.event_stream.as_ref().map(|es| es.stats())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn dynamic_neighbors_ref(&self) -> &Arc<ShardedNeighborMap> {
        &self.neighbors.dynamic
    }

    /// #919: zone name → ID lookup, used by main.rs's
    /// `build_synced_session_entry` to translate legacy
    /// `SessionSyncRequest.ingress_zone` strings to u16 IDs when
    /// older peers don't populate the new ID fields.
    pub fn zone_name_to_id_ref(&self) -> &FastMap<String, u16> {
        &self.forwarding.zone_name_to_id
    }

    pub fn apply_manager_neighbors(
        &mut self,
        replace: bool,
        neighbors: &[(i32, IpAddr, NeighborEntry)],
    ) {
        let old_manager_keys = if replace {
            self.neighbors.manager_keys
                .lock()
                .map(|manager_keys| manager_keys.iter().copied().collect::<Vec<_>>())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        if let Ok(mut manager_keys) = self.neighbors.manager_keys.lock() {
            if replace {
                manager_keys.clear();
            }
            for (ifindex, ip, _) in neighbors {
                manager_keys.insert((*ifindex, *ip));
            }
        }
        // #949: replace + insert under a single bulk acquisition so
        // readers see either the pre-replace or post-replace state,
        // never a half-replaced set. `with_all_shards` locks all 64
        // shards in shard-index order (deadlock-free invariant).
        self.neighbors.dynamic.with_all_shards(|bulk| {
            if replace {
                for key in &old_manager_keys {
                    bulk.remove(key);
                }
            }
            for (ifindex, ip, entry) in neighbors {
                bulk.insert((*ifindex, *ip), *entry);
            }
        });
        if replace {
            for key in &old_manager_keys {
                self.forwarding.neighbors.remove(key);
            }
        }
        for (ifindex, ip, entry) in neighbors {
            self.forwarding.neighbors.insert((*ifindex, *ip), *entry);
        }
        if replace || !neighbors.is_empty() {
            // Clone the full ForwardingState to publish neighbor changes.
            // This copies routes/policies too, but update_neighbors fires
            // infrequently (only when kernel ARP/NDP changes, gated by
            // neighborsEqual in the Go manager). The clone cost is
            // negligible vs packet processing.
            self.ha.forwarding
                .store(Arc::new(self.forwarding.clone()));
        }
        self.neighbors.generation.fetch_add(1, Ordering::Relaxed);
    }



    pub(crate) fn stop_inner(&mut self, clear_synced_state: bool) {
        if let Some(stop) = self.neighbors.monitor_stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        for handle in self.tunnel_sources.values_mut() {
            handle.stop.store(true, Ordering::Relaxed);
        }
        for (_, handle) in self.tunnel_sources.iter_mut() {
            if let Some(join) = handle.join.take() {
                let _ = join.join();
            }
        }
        self.tunnel_sources.clear();
        self.local_tunnel_deliveries
            .store(Arc::new(BTreeMap::new()));
        self.workers.stop_and_clear(
            self.bpf_maps.map_fd.as_ref(),
            self.bpf_maps.heartbeat_map_fd.as_ref(),
        );
        // #925 Phase 1: drop the per-worker panic slots alongside the
        // workers themselves so a long-running daemon that reconciles
        // through many worker-id sets doesn't accumulate stale slots.
        self.worker_panics.clear();
        self.cos_owner_worker_by_queue.clear();
        self.cos.owner_worker_by_queue
            .store(Arc::new(BTreeMap::new()));
        self.cos.owner_live_by_queue
            .store(Arc::new(BTreeMap::new()));
        self.cos.root_leases.store(Arc::new(BTreeMap::new()));
        self.cos.queue_leases
            .store(Arc::new(BTreeMap::new()));
        self.cos.queue_vtime_floors
            .store(Arc::new(BTreeMap::new()));
        self.last_slow_path_status = self
            .slow_path
            .as_ref()
            .map(|slow| slow.status())
            .unwrap_or_default();
        self.slow_path = None;
        self.bpf_maps.map_fd = None;
        self.bpf_maps.heartbeat_map_fd = None;
        self.bpf_maps.session_map_fd = None;
        self.bpf_maps.conntrack_v4_fd = None;
        self.bpf_maps.conntrack_v6_fd = None;
        self.bpf_maps.dnat_table_fd = None;
        self.bpf_maps.dnat_table_v6_fd = None;
        self.forwarding = ForwardingState::default();
        self.ha.forwarding
            .store(Arc::new(ForwardingState::default()));
        self.shared_validation
            .store(Arc::new(ValidationState::default()));
        self.ha.fabrics.store(Arc::new(Vec::new()));
        self.neighbors.generation.store(0, Ordering::Relaxed);
        // #949: clear all shards atomically vs readers.
        self.neighbors.dynamic.with_all_shards(|bulk| {
            for shard in bulk.each_shard_mut() {
                shard.clear();
            }
        });
        if let Ok(mut manager_keys) = self.neighbors.manager_keys.lock() {
            manager_keys.clear();
        }
        if clear_synced_state {
            if let Ok(mut sessions) = self.sessions.synced.lock() {
                sessions.clear();
            }
            if let Ok(mut nat_sessions) = self.sessions.nat.lock() {
                nat_sessions.clear();
            }
            if let Ok(mut forward_wire_sessions) = self.sessions.forward_wire.lock() {
                forward_wire_sessions.clear();
            }
            self.sessions.owner_rg_indexes.clear();
        }
        if let Ok(mut recent) = self.recent_exceptions.lock() {
            recent.clear();
        }
        if let Ok(mut recent) = self.recent_session_deltas.lock() {
            recent.clear();
        }
        if let Ok(mut last) = self.last_resolution.lock() {
            *last = None;
        }
        self.validation = ValidationState::default();
        self.workers.last_planned_workers = 0;
        self.workers.last_planned_bindings = 0;
        self.last_reconcile_stage = "stopped".to_string();
    }

    pub(crate) fn snapshot_shared_session_entries(&self) -> Vec<SyncedSessionEntry> {
        self.sessions.synced
            .lock()
            .map(|sessions| sessions.values().cloned().collect())
            .unwrap_or_default()
    }

    pub(crate) fn replay_synced_sessions(
        &self,
        entries: &[SyncedSessionEntry],
        worker_command_queues: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
        session_map_fd: c_int,
    ) -> usize {
        if entries.is_empty() {
            return 0;
        }
        let worker_queues = worker_command_queues.values().cloned().collect::<Vec<_>>();
        for entry in entries {
            let _ = publish_live_session_entry(
                session_map_fd,
                &entry.key,
                entry.decision.nat,
                entry.metadata.is_reverse,
            );
            replicate_session_upsert(&worker_queues, entry);
        }
        entries.len()
    }

    pub fn reconcile(
        &mut self,
        snapshot: Option<&ConfigSnapshot>,
        bindings: &mut [BindingStatus],
        ring_entries: usize,
    ) {
        self.reconcile_calls += 1;
        self.last_reconcile_stage = "start".to_string();
        let had_live_workers = !self.workers.handles.is_empty();
        let preserved_synced_sessions = self.snapshot_shared_session_entries();
        // Keep a healthy slow-path worker across back-to-back reconciles. The
        // userspace helper can receive multiple snapshot refreshes during HA
        // role changes; recreating the fixed-name TUN on every reconcile can
        // race with teardown and leave the new owner without xpf-usp0.
        let preserved_slow_path = self.slow_path.as_ref().and_then(|slow| {
            if slow.status().active {
                Some(slow.clone())
            } else {
                None
            }
        });
        self.stop_inner(false);
        if had_live_workers {
            // Zero-copy queue teardown is not synchronously reusable on mlx5.
            // A short quiesce avoids EBUSY when a later snapshot refresh
            // rebuilds the same queue set immediately after shutdown.
            thread::sleep(Duration::from_millis(500));
        }
        for binding in bindings.iter_mut() {
            binding.bound = false;
            binding.xsk_registered = false;
            binding.socket_fd = 0;
            binding.rx_packets = 0;
            binding.rx_bytes = 0;
            binding.rx_batches = 0;
            binding.rx_wakeups = 0;
            binding.metadata_packets = 0;
            binding.metadata_errors = 0;
            binding.validated_packets = 0;
            binding.validated_bytes = 0;
            binding.local_delivery_packets = 0;
            binding.forward_candidate_packets = 0;
            binding.route_miss_packets = 0;
            binding.neighbor_miss_packets = 0;
            binding.discard_route_packets = 0;
            binding.next_table_packets = 0;
            binding.exception_packets = 0;
            binding.config_gen_mismatches = 0;
            binding.fib_gen_mismatches = 0;
            binding.unsupported_packets = 0;
            binding.flow_cache_hits = 0;
            binding.flow_cache_misses = 0;
            binding.flow_cache_evictions = 0;
            binding.flow_cache_collision_evictions = 0;
            binding.v_min_throttle_hard_cap_overrides = 0;
            binding.v_min_throttles = 0;
            binding.session_hits = 0;
            binding.session_misses = 0;
            binding.session_creates = 0;
            binding.session_expires = 0;
            binding.session_delta_pending = 0;
            binding.session_delta_generated = 0;
            binding.session_delta_dropped = 0;
            binding.session_delta_drained = 0;
            binding.policy_denied_packets = 0;
            binding.snat_packets = 0;
            binding.dnat_packets = 0;
            binding.slow_path_packets = 0;
            binding.slow_path_bytes = 0;
            binding.slow_path_local_delivery_packets = 0;
            binding.slow_path_missing_neighbor_packets = 0;
            binding.slow_path_no_route_packets = 0;
            binding.slow_path_next_table_packets = 0;
            binding.slow_path_forward_build_packets = 0;
            binding.slow_path_drops = 0;
            binding.slow_path_rate_limited = 0;
            binding.kernel_rx_dropped = 0;
            binding.kernel_rx_invalid_descs = 0;
            binding.last_error.clear();
            binding.ready = false;
        }
        let Some(snapshot) = snapshot else {
            self.last_reconcile_stage = "no_snapshot".to_string();
            return;
        };
        self.validation = ValidationState {
            snapshot_installed: true,
            config_generation: snapshot.generation,
            fib_generation: snapshot.fib_generation,
        };
        self.forwarding = build_forwarding_state(snapshot);
        self.shared_validation.store(Arc::new(self.validation));
        self.ha.forwarding
            .store(Arc::new(self.forwarding.clone()));
        self.slow_path = if let Some(slow_path) = preserved_slow_path {
            self.last_slow_path_status = slow_path.status();
            Some(slow_path)
        } else {
            match SlowPathReinjector::new(DEFAULT_SLOW_PATH_TUN) {
                Ok(reinjector) => {
                    self.last_slow_path_status = reinjector.status();
                    Some(Arc::new(reinjector))
                }
                Err(err) => {
                    self.last_slow_path_status = SlowPathStatus {
                        last_error: err,
                        ..SlowPathStatus::default()
                    };
                    None
                }
            }
        };
        self.local_tunnel_deliveries
            .store(Arc::new(BTreeMap::new()));
        self.ha.fabrics
            .store(Arc::new(self.forwarding.fabrics.clone()));
        if snapshot.map_pins.xsk.is_empty() {
            self.last_reconcile_stage = "missing_xsk_pin".to_string();
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = "missing XSK map pin path".to_string();
                }
            }
            return;
        }
        if snapshot.map_pins.heartbeat.is_empty() {
            self.last_reconcile_stage = "missing_heartbeat_pin".to_string();
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = "missing heartbeat map pin path".to_string();
                }
            }
            return;
        }
        if snapshot.map_pins.sessions.is_empty() {
            self.last_reconcile_stage = "missing_session_pin".to_string();
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = "missing session map pin path".to_string();
                }
            }
            return;
        }
        let map_fd = match OwnedFd::open_bpf_map(&snapshot.map_pins.xsk) {
            Ok(fd) => fd,
            Err(err) => {
                self.last_reconcile_stage = format!("open_xsk_map_failed:{err}");
                for binding in bindings.iter_mut() {
                    if binding.registered {
                        binding.last_error = format!("open XSK map: {err}");
                    }
                }
                return;
            }
        };
        let heartbeat_map_fd = match OwnedFd::open_bpf_map(&snapshot.map_pins.heartbeat) {
            Ok(fd) => fd,
            Err(err) => {
                self.last_reconcile_stage = format!("open_heartbeat_map_failed:{err}");
                for binding in bindings.iter_mut() {
                    if binding.registered {
                        binding.last_error = format!("open heartbeat map: {err}");
                    }
                }
                return;
            }
        };
        let session_map_fd = match OwnedFd::open_bpf_map(&snapshot.map_pins.sessions) {
            Ok(fd) => fd,
            Err(err) => {
                self.last_reconcile_stage = format!("open_session_map_failed:{err}");
                for binding in bindings.iter_mut() {
                    if binding.registered {
                        binding.last_error = format!("open session map: {err}");
                    }
                }
                return;
            }
        };
        // Open BPF conntrack maps (sessions, sessions_v6) so the helper can
        // publish session entries that "show security flow session" reads.
        // Non-fatal: if the maps don't exist, session display will lack zone/interface info.
        let conntrack_v4_fd = if !snapshot.map_pins.conntrack_v4.is_empty() {
            OwnedFd::open_bpf_map(&snapshot.map_pins.conntrack_v4).ok()
        } else {
            None
        };
        let conntrack_v6_fd = if !snapshot.map_pins.conntrack_v6.is_empty() {
            OwnedFd::open_bpf_map(&snapshot.map_pins.conntrack_v6).ok()
        } else {
            None
        };
        // Open dnat_table BPF map for embedded ICMP NAT reversal support.
        // Non-fatal: if the map doesn't exist, embedded ICMP won't work
        // but normal forwarding is unaffected.
        let dnat_table_fd = if !snapshot.map_pins.dnat_table.is_empty() {
            OwnedFd::open_bpf_map(&snapshot.map_pins.dnat_table).ok()
        } else {
            None
        };
        let dnat_table_v6_fd = if !snapshot.map_pins.dnat_table_v6.is_empty() {
            OwnedFd::open_bpf_map(&snapshot.map_pins.dnat_table_v6).ok()
        } else {
            None
        };
        let dnat_fds = DnatTableFds {
            v4: dnat_table_fd.as_ref().map(|f| f.fd),
            v6: dnat_table_v6_fd.as_ref().map(|f| f.fd),
        };
        let ring_entries = ring_entries.max(64).min(u32::MAX as usize) as u32;
        let mut workers: BTreeMap<u32, Vec<BindingPlan>> = BTreeMap::new();
        for binding in bindings.iter_mut() {
            if !binding.registered || binding.ifindex <= 0 {
                binding.ready = false;
                continue;
            }
            let live = Arc::new(BindingLiveState::new());
            self.workers.live.insert(binding.slot, live.clone());
            let identity = BindingIdentity {
                slot: binding.slot,
                queue_id: binding.queue_id,
                worker_id: binding.worker_id,
                interface: Arc::<str>::from(binding.interface.as_str()),
                ifindex: binding.ifindex,
            };
            self.workers.identities.insert(binding.slot, identity);
            workers
                .entry(binding.worker_id)
                .or_default()
                .push(BindingPlan {
                    status: binding.clone(),
                    live,
                    xsk_map_fd: map_fd.fd,
                    heartbeat_map_fd: heartbeat_map_fd.fd,
                    session_map_fd: session_map_fd.fd,
                    conntrack_v4_fd: conntrack_v4_fd.as_ref().map(|f| f.fd).unwrap_or(-1),
                    conntrack_v6_fd: conntrack_v6_fd.as_ref().map(|f| f.fd).unwrap_or(-1),
                    ring_entries,
                    bind_strategy: preferred_bind_strategy(binding),
                    poll_mode: self.poll_mode,
                });
        }
        for plans in workers.values_mut() {
            plans.sort_by_key(|plan| (plan.status.queue_id, plan.status.ifindex, plan.status.slot));
        }
        let planned_bindings: usize = workers.values().map(|group| group.len()).sum();
        self.workers.last_planned_workers = workers.len();
        self.workers.last_planned_bindings = planned_bindings;
        self.last_reconcile_stage = format!(
            "planned:workers={}:bindings={}:live={}",
            self.workers.last_planned_workers(),
            self.workers.last_planned_bindings(),
            self.workers.live.len()
        );
        eprintln!(
            "xpf-userspace-dp: reconcile planned_workers={} planned_bindings={} live_slots={}",
            workers.len(),
            planned_bindings,
            self.workers.live.len()
        );
        let session_map_raw_fd = session_map_fd.fd;
        self.bpf_maps.map_fd = Some(map_fd);
        self.bpf_maps.heartbeat_map_fd = Some(heartbeat_map_fd);
        self.bpf_maps.session_map_fd = Some(session_map_fd);
        self.bpf_maps.conntrack_v4_fd = conntrack_v4_fd;
        self.bpf_maps.conntrack_v6_fd = conntrack_v6_fd;
        self.bpf_maps.dnat_table_fd = dnat_table_fd;
        self.bpf_maps.dnat_table_v6_fd = dnat_table_v6_fd;
        let worker_binding_ifindexes = workers
            .iter()
            .map(|(worker_id, binding_plans)| {
                (
                    *worker_id,
                    binding_plans
                        .iter()
                        .map(|plan| plan.status.ifindex)
                        .collect::<std::collections::BTreeSet<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let owner_map = build_cos_owner_worker_by_queue(&self.forwarding, &workers);
        let active_shards_by_egress_ifindex =
            build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes(
                &self.forwarding,
                &worker_binding_ifindexes,
                &worker_binding_ifindexes,
            );
        self.refresh_cos_runtime_maps(owner_map, active_shards_by_egress_ifindex);
        let worker_command_queues: Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>> =
            Arc::new(
                workers
                    .keys()
                    .copied()
                    .map(|worker_id| (worker_id, Arc::new(Mutex::new(VecDeque::new()))))
                    .collect(),
            );
        let replayed_synced_sessions = self.replay_synced_sessions(
            &preserved_synced_sessions,
            worker_command_queues.as_ref(),
            session_map_raw_fd,
        );
        if replayed_synced_sessions > 0 {
            self.last_reconcile_stage = format!(
                "replayed_synced:{}:workers={}",
                replayed_synced_sessions,
                worker_command_queues.len()
            );
        }
        for (worker_id, binding_plans) in workers {
            let plan_count = binding_plans.len();
            let stop = Arc::new(AtomicBool::new(false));
            let heartbeat = Arc::new(AtomicU64::new(monotonic_nanos()));
            let session_export_ack = Arc::new(AtomicU64::new(0));
            let cos_status = Arc::new(ArcSwap::from_pointee(Vec::new()));
            let commands = worker_command_queues
                .get(&worker_id)
                .cloned()
                .unwrap_or_else(|| Arc::new(Mutex::new(VecDeque::new())));
            let recent_exceptions = self.recent_exceptions.clone();
            let recent_session_deltas = self.recent_session_deltas.clone();
            let last_resolution = self.last_resolution.clone();
            let slow_path = self.slow_path.clone();
            let local_tunnel_deliveries = self.local_tunnel_deliveries.clone();
            let shared_forwarding = self.ha.forwarding.clone();
            let shared_validation = self.shared_validation.clone();
            let shared_sessions = self.sessions.synced.clone();
            let shared_nat_sessions = self.sessions.nat.clone();
            let shared_forward_wire_sessions = self.sessions.forward_wire.clone();
            let shared_owner_rg_indexes = self.sessions.owner_rg_indexes.clone();
            let stop_clone = stop.clone();
            let heartbeat_clone = heartbeat.clone();
            let session_export_ack_clone = session_export_ack.clone();
            let commands_clone = commands.clone();
            let peer_commands_clone = worker_command_queues
                .iter()
                .filter(|(id, _)| **id != worker_id)
                .map(|(_, queue)| queue.clone())
                .collect::<Vec<_>>();
            let worker_commands_by_id = worker_command_queues.clone();
            let ha_state = self.ha.rg_runtime.clone();
            let dynamic_neighbors = self.neighbors.dynamic.clone();
            let worker_poll_mode = self.poll_mode;
            let shared_fabrics = self.ha.fabrics.clone();
            let rg_epochs = self.rg_epochs.clone();
            let event_stream_handle = self.event_stream_worker_handle();
            let cos_status_clone = cos_status.clone();
            let shared_cos_owner_worker_by_queue = self.cos.owner_worker_by_queue.clone();
            let shared_cos_owner_live_by_queue = self.cos.owner_live_by_queue.clone();
            let shared_cos_root_leases = self.cos.root_leases.clone();
            let shared_cos_queue_leases = self.cos.queue_leases.clone();
            let shared_cos_queue_vtime_floors = self.cos.queue_vtime_floors.clone();
            let runtime_atomics =
                std::sync::Arc::new(super::worker_runtime::WorkerRuntimeAtomics::new());
            let runtime_atomics_clone = runtime_atomics.clone();
            // #925 Phase 1: per-worker panic slot, keyed by worker_id.
            let panic_slot = Arc::new(Mutex::new(None::<String>));
            self.worker_panics.insert(worker_id, panic_slot.clone());
            let join = spawn_supervised_worker(
                worker_id,
                runtime_atomics.clone(),
                panic_slot,
                move || {
                    worker_loop(
                        worker_id,
                        binding_plans,
                        shared_validation,
                        shared_forwarding,
                        ha_state,
                        dynamic_neighbors,
                        shared_sessions,
                        shared_nat_sessions,
                        shared_forward_wire_sessions,
                        shared_owner_rg_indexes,
                        slow_path,
                        local_tunnel_deliveries,
                        recent_exceptions,
                        recent_session_deltas,
                        last_resolution,
                        commands_clone,
                        peer_commands_clone,
                        worker_commands_by_id,
                        stop_clone,
                        heartbeat_clone,
                        session_export_ack_clone,
                        worker_poll_mode,
                        dnat_fds,
                        shared_fabrics,
                        event_stream_handle,
                        rg_epochs,
                        shared_cos_owner_worker_by_queue,
                        shared_cos_owner_live_by_queue,
                        shared_cos_root_leases,
                        shared_cos_queue_leases,
                        shared_cos_queue_vtime_floors,
                        cos_status_clone,
                        runtime_atomics_clone,
                    );
                },
            );
            match join {
                Ok(join) => {
                    eprintln!(
                        "xpf-userspace-dp: started worker thread worker_id={} planned_bindings={}",
                        worker_id, plan_count
                    );
                    self.workers.handles.insert(
                        worker_id,
                        WorkerHandle {
                            stop,
                            heartbeat,
                            commands,
                            session_export_ack,
                            cos_status,
                            runtime_atomics,
                            join: Some(join),
                        },
                    );
                }
                Err(err) => {
                    eprintln!(
                        "xpf-userspace-dp: failed to start worker thread worker_id={} err={}",
                        worker_id, err
                    );
                    self.last_reconcile_stage = format!("spawn_worker_failed:{worker_id}:{err}");
                    // #925 Phase 1: the panic slot was inserted before
                    // spawn; drop it now so a snapshot reader doesn't
                    // see a phantom slot for a worker that never ran.
                    self.worker_panics.remove(&worker_id);
                    if let Ok(mut recent) = self.recent_exceptions.lock() {
                        push_recent_exception(
                            &mut recent,
                            ExceptionStatus {
                                timestamp: Utc::now(),
                                reason: format!("spawn_worker_failed:{worker_id}:{err}"),
                                ..ExceptionStatus::default()
                            },
                        );
                    }
                }
            }
        }
        self.last_reconcile_stage = format!(
            "spawned:workers={}:identities={}:live={}",
            self.workers.handles.len(),
            self.workers.identities.len(),
            self.workers.live.len()
        );
        // Start the helper-owned neighbor sync path. It does an initial
        // RTM_GETNEIGH dump so startup sees the existing kernel table, then
        // subscribes to RTM_{NEW,DEL}NEIGH for incremental updates.
        if self.neighbors.monitor_stop.is_none() {
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = stop.clone();
            let dynamic_neighbors = self.neighbors.dynamic.clone();
            let neighbor_generation = self.neighbors.generation.clone();
            // #925-A: wrap aux thread in catch_unwind so a panic in the
            // netlink path doesn't kill the daemon. No respawn — see
            // spawn_supervised_aux doc for operator-visible degradation.
            spawn_supervised_aux("neigh-monitor", move || {
                neigh_monitor_thread(stop_clone, dynamic_neighbors, neighbor_generation)
            })
            .ok();
            self.neighbors.monitor_stop = Some(stop);
        }
        self.spawn_local_tunnel_sources();
        self.refresh_bindings(bindings);
    }

    fn spawn_local_tunnel_sources(&mut self) {
        let mut local_tunnel_deliveries = BTreeMap::new();
        for endpoint in self.forwarding.tunnel_endpoints.values() {
            if endpoint.mode != "gre" && endpoint.mode != "ip6gre" {
                continue;
            }
            let Some(tunnel_name) = self
                .forwarding
                .ifindex_to_name
                .get(&endpoint.logical_ifindex)
                .cloned()
            else {
                continue;
            };
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = stop.clone();
            let forwarding = self.forwarding.clone();
            let ha_state = self.ha.rg_runtime.clone();
            let dynamic_neighbors = self.neighbors.dynamic.clone();
            let live = self.workers.live.clone();
            let identities = self.workers.identities.clone();
            let shared_sessions = self.sessions.synced.clone();
            let shared_nat_sessions = self.sessions.nat.clone();
            let shared_forward_wire_sessions = self.sessions.forward_wire.clone();
            let shared_owner_rg_indexes = self.sessions.owner_rg_indexes.clone();
            let worker_commands = self
                .workers
                .handles
                .values()
                .map(|handle| handle.commands.clone())
                .collect::<Vec<_>>();
            let recent_exceptions = self.recent_exceptions.clone();
            let tunnel_endpoint_id = endpoint.id;
            let thread_tunnel_name = tunnel_name.clone();
            let logical_ifindex = endpoint.logical_ifindex;
            let (delivery_tx, delivery_rx) = mpsc::sync_channel(LOCAL_TUNNEL_DELIVERY_QUEUE_DEPTH);
            // #925-A: wrap aux tunnel-origin thread in catch_unwind.
            // A panic here would otherwise silently stop locally-
            // generated GRE traffic on this tunnel; transit packets
            // continue through worker_loop unaffected.
            let join = spawn_supervised_aux(
                format!("xpf-native-gre-origin-{}", tunnel_name),
                move || {
                    local_tunnel_source_loop(
                        thread_tunnel_name,
                        tunnel_endpoint_id,
                        forwarding,
                        ha_state,
                        dynamic_neighbors,
                        live,
                        identities,
                        shared_sessions,
                        shared_nat_sessions,
                        shared_forward_wire_sessions,
                        shared_owner_rg_indexes,
                        worker_commands,
                        delivery_rx,
                        recent_exceptions,
                        stop_clone,
                    );
                },
            );
            match join {
                Ok(join) => {
                    local_tunnel_deliveries.insert(logical_ifindex, delivery_tx);
                    self.tunnel_sources.insert(
                        tunnel_endpoint_id,
                        LocalTunnelSourceHandle {
                            stop,
                            join: Some(join),
                        },
                    );
                }
                Err(err) => {
                    if let Ok(mut recent) = self.recent_exceptions.lock() {
                        push_recent_exception(
                            &mut recent,
                            ExceptionStatus {
                                timestamp: Utc::now(),
                                interface: tunnel_name,
                                reason: format!(
                                    "spawn_local_tunnel_source_failed:{tunnel_endpoint_id}:{err}"
                                ),
                                ..ExceptionStatus::default()
                            },
                        );
                    }
                }
            }
        }
        self.local_tunnel_deliveries
            .store(Arc::new(local_tunnel_deliveries));
    }








    /// Refresh fabric link info from updated snapshots. Called when the
    /// Go daemon's refreshFabricFwd resolves a peer MAC that wasn't
    /// available at initial snapshot build time.
    ///
    /// This updates both the coordinator's local forwarding state and the
    /// shared Arc-backed state used by workers, so refreshed fabric links
    /// become visible to workers as soon as the new values are published.
    pub fn refresh_fabric_links(&mut self, snapshots: &[crate::FabricSnapshot]) {
        let new_fabrics = resolve_fabric_links_from_snapshots(
            snapshots,
            &self.forwarding.egress,
            &self.neighbors.dynamic,
        );
        if !new_fabrics.is_empty() {
            self.forwarding.fabrics = new_fabrics.clone();
            self.ha.fabrics.store(Arc::new(new_fabrics));
            // Also update shared_forwarding so workers see the new fabric
            // links for fabric redirect resolution. Without this, workers
            // use the snapshot's forwarding state which may have empty fabrics
            // if the peer MAC wasn't resolved at snapshot time.
            self.ha.forwarding
                .store(Arc::new(self.forwarding.clone()));
        }
    }

    pub fn refresh_runtime_snapshot(&mut self, snapshot: &crate::ConfigSnapshot) {
        let next_manager_keys = snapshot
            .neighbors
            .iter()
            .filter_map(|neigh| {
                if neigh.ifindex <= 0
                    || !neighbor_state_usable_str(&neigh.state)
                    || neigh.mac.is_empty()
                    || parse_mac_str(&neigh.mac).is_none()
                {
                    return None;
                }
                neigh
                    .ip
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| (neigh.ifindex, ip))
            })
            .collect::<FastSet<_>>();
        let old_manager_keys = if let Ok(mut manager_keys) = self.neighbors.manager_keys.lock() {
            let old = manager_keys.iter().copied().collect::<Vec<_>>();
            *manager_keys = next_manager_keys;
            old
        } else {
            Vec::new()
        };
        // #949: bulk-remove stale manager keys atomically vs readers.
        self.neighbors.dynamic.with_all_shards(|bulk| {
            for key in &old_manager_keys {
                bulk.remove(key);
            }
        });
        self.validation = ValidationState {
            snapshot_installed: true,
            config_generation: snapshot.generation,
            fib_generation: snapshot.fib_generation,
        };
        // Preserve existing fabric links — they are resolved separately
        // via refresh_fabric_links (SyncFabricState) and the snapshot
        // may not include them if the peer MAC wasn't resolved at
        // snapshot build time. Always keep the better-resolved set.
        let preserved_fabrics = self.forwarding.fabrics.clone();
        self.forwarding = build_forwarding_state(snapshot);
        if self.forwarding.fabrics.is_empty() && !preserved_fabrics.is_empty() {
            self.forwarding.fabrics = preserved_fabrics;
        } else if !preserved_fabrics.is_empty() {
            // Merge: for each preserved fabric, if the new snapshot
            // doesn't have a matching parent_ifindex, keep the old one.
            for old in &preserved_fabrics {
                if !self
                    .forwarding
                    .fabrics
                    .iter()
                    .any(|f| f.parent_ifindex == old.parent_ifindex)
                {
                    self.forwarding.fabrics.push(*old);
                }
            }
        }
        self.shared_validation.store(Arc::new(self.validation));
        self.ha.forwarding
            .store(Arc::new(self.forwarding.clone()));
        self.refresh_cos_owner_worker_map_from_identities();
        self.ha.fabrics
            .store(Arc::new(self.forwarding.fabrics.clone()));
    }

    fn refresh_cos_owner_worker_map_from_identities(&mut self) {
        let worker_binding_ifindexes =
            build_worker_binding_ifindexes_from_identities(&self.workers.identities);
        let owner_map = build_cos_owner_worker_by_queue_from_binding_ifindexes(
            &self.forwarding,
            &worker_binding_ifindexes,
        );
        let active_shards_by_egress_ifindex =
            build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes(
                &self.forwarding,
                &worker_binding_ifindexes,
                &worker_binding_ifindexes,
            );
        self.refresh_cos_runtime_maps(owner_map, active_shards_by_egress_ifindex);
    }

    fn refresh_cos_owner_worker_map_from_binding_statuses(&mut self, bindings: &[BindingStatus]) {
        let ready_worker_binding_ifindexes = bindings.iter().filter(|binding| binding.ready).fold(
            BTreeMap::<u32, std::collections::BTreeSet<i32>>::new(),
            |mut out, binding| {
                out.entry(binding.worker_id)
                    .or_default()
                    .insert(binding.ifindex);
                out
            },
        );
        let fallback_worker_binding_ifindexes =
            build_worker_binding_ifindexes_from_identities(&self.workers.identities);
        let owner_map = build_cos_owner_worker_by_queue_with_fallback_ifindexes(
            &self.forwarding,
            &ready_worker_binding_ifindexes,
            &fallback_worker_binding_ifindexes,
        );
        let active_shards_by_egress_ifindex =
            build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes(
                &self.forwarding,
                &ready_worker_binding_ifindexes,
                &fallback_worker_binding_ifindexes,
            );
        self.refresh_cos_runtime_maps(owner_map, active_shards_by_egress_ifindex);
    }

    fn refresh_cos_runtime_maps(
        &mut self,
        owner_map: BTreeMap<(i32, u8), u32>,
        active_shards_by_egress_ifindex: BTreeMap<i32, usize>,
    ) {
        let owner_changed = owner_map != self.cos_owner_worker_by_queue;
        let owner_map_for_runtime = if owner_changed {
            &owner_map
        } else {
            &self.cos_owner_worker_by_queue
        };
        let current_owner_live = self.cos.owner_live_by_queue.load();
        let next_owner_live = build_cos_owner_live_by_queue(
            &self.forwarding,
            owner_map_for_runtime,
            &self.workers.identities,
            &self.workers.live,
        );
        let current_leases = self.cos.root_leases.load();
        let next_leases = build_shared_cos_root_leases_reusing_existing(
            &self.forwarding,
            &active_shards_by_egress_ifindex,
            current_leases.as_ref(),
        );
        let current_queue_leases = self.cos.queue_leases.load();
        let next_queue_leases = build_shared_cos_queue_leases_reusing_existing(
            &self.forwarding,
            &active_shards_by_egress_ifindex,
            current_queue_leases.as_ref(),
        );
        // #917: V_min coordination Arcs sized by worker count.
        // workers.last_planned_workers is set in apply_planned_workers
        // before this reconcile fires; defaults to 0 at first
        // boot which produces zero-slot floors (the reconcile
        // re-fires once workers are planned).
        let current_queue_vtime_floors = self.cos.queue_vtime_floors.load();
        let num_workers = self.workers.last_planned_workers().max(1);
        let next_queue_vtime_floors = build_shared_cos_queue_vtime_floors_reusing_existing(
            &self.forwarding,
            num_workers,
            current_queue_vtime_floors.as_ref(),
        );
        if owner_changed {
            self.cos_owner_worker_by_queue = owner_map.clone();
            self.cos.owner_worker_by_queue
                .store(Arc::new(owner_map));
        }
        if !shared_cos_owner_live_by_queue_match(current_owner_live.as_ref(), &next_owner_live) {
            self.cos.owner_live_by_queue
                .store(Arc::new(next_owner_live));
        }
        if !shared_cos_root_leases_match(current_leases.as_ref(), &next_leases) {
            self.cos.root_leases.store(Arc::new(next_leases));
        }
        if !shared_cos_queue_leases_match(current_queue_leases.as_ref(), &next_queue_leases) {
            self.cos.queue_leases
                .store(Arc::new(next_queue_leases));
        }
        if !shared_cos_queue_vtime_floors_match(
            current_queue_vtime_floors.as_ref(),
            &next_queue_vtime_floors,
        ) {
            self.cos.queue_vtime_floors
                .store(Arc::new(next_queue_vtime_floors));
        }
    }

    /// Bump just the FIB generation counter without a full snapshot rebuild.
    /// Workers will invalidate flow cache entries with stale FIB generations.
    pub fn bump_fib_generation(&mut self, fib_generation: u32) {
        self.validation.fib_generation = fib_generation;
        self.shared_validation.store(Arc::new(self.validation));
    }









    pub fn refresh_bindings(&mut self, bindings: &mut [BindingStatus]) {
        for binding in bindings.iter_mut() {
            if let Some(live) = self.workers.live.get(&binding.slot) {
                let snap = live.snapshot();
                if snap.bound && !binding.bound {
                    eprintln!(
                        "refresh_bindings: slot={} transitioning bound=false->true fd={}",
                        binding.slot, snap.socket_fd
                    );
                }
                binding.bound = snap.bound;
                binding.xsk_registered = snap.xsk_registered;
                binding.xsk_bind_mode = snap.xsk_bind_mode;
                binding.zero_copy = snap.zero_copy;
                binding.socket_fd = snap.socket_fd;
                binding.socket_ifindex = snap.socket_ifindex;
                binding.socket_queue_id = snap.socket_queue_id;
                binding.socket_bind_flags = snap.socket_bind_flags;
                binding.rx_packets = snap.rx_packets;
                binding.rx_bytes = snap.rx_bytes;
                binding.rx_batches = snap.rx_batches;
                binding.rx_wakeups = snap.rx_wakeups;
                binding.metadata_packets = snap.metadata_packets;
                binding.metadata_errors = snap.metadata_errors;
                binding.validated_packets = snap.validated_packets;
                binding.validated_bytes = snap.validated_bytes;
                binding.local_delivery_packets = snap.local_delivery_packets;
                binding.forward_candidate_packets = snap.forward_candidate_packets;
                binding.route_miss_packets = snap.route_miss_packets;
                binding.neighbor_miss_packets = snap.neighbor_miss_packets;
                binding.discard_route_packets = snap.discard_route_packets;
                binding.next_table_packets = snap.next_table_packets;
                binding.exception_packets = snap.exception_packets;
                binding.config_gen_mismatches = snap.config_gen_mismatches;
                binding.fib_gen_mismatches = snap.fib_gen_mismatches;
                binding.unsupported_packets = snap.unsupported_packets;
                binding.flow_cache_hits = snap.flow_cache_hits;
                binding.flow_cache_misses = snap.flow_cache_misses;
                binding.flow_cache_evictions = snap.flow_cache_evictions;
                binding.flow_cache_collision_evictions = snap.flow_cache_collision_evictions;
                // #941 Work item D / #943: bridge V_min counters from
                // BindingLiveSnapshot through to BindingStatus so the
                // wire surface (BindingCountersSnapshot) sees them.
                binding.v_min_throttle_hard_cap_overrides = snap.v_min_throttle_hard_cap_overrides;
                binding.v_min_throttles = snap.v_min_throttles;
                binding.session_hits = snap.session_hits;
                binding.session_misses = snap.session_misses;
                binding.session_creates = snap.session_creates;
                binding.session_expires = snap.session_expires;
                binding.session_delta_pending = snap.session_delta_pending;
                binding.session_delta_generated = snap.session_delta_generated;
                binding.session_delta_dropped = snap.session_delta_dropped;
                binding.session_delta_drained = snap.session_delta_drained;
                binding.policy_denied_packets = snap.policy_denied_packets;
                binding.screen_drops = snap.screen_drops;
                binding.snat_packets = snap.snat_packets;
                binding.dnat_packets = snap.dnat_packets;
                binding.slow_path_packets = snap.slow_path_packets;
                binding.slow_path_bytes = snap.slow_path_bytes;
                binding.slow_path_local_delivery_packets = snap.slow_path_local_delivery_packets;
                binding.slow_path_missing_neighbor_packets =
                    snap.slow_path_missing_neighbor_packets;
                binding.slow_path_no_route_packets = snap.slow_path_no_route_packets;
                binding.slow_path_next_table_packets = snap.slow_path_next_table_packets;
                binding.slow_path_forward_build_packets = snap.slow_path_forward_build_packets;
                binding.slow_path_drops = snap.slow_path_drops;
                binding.slow_path_rate_limited = snap.slow_path_rate_limited;
                binding.kernel_rx_dropped = snap.kernel_rx_dropped;
                binding.kernel_rx_invalid_descs = snap.kernel_rx_invalid_descs;
                binding.tx_packets = snap.tx_packets;
                binding.tx_bytes = snap.tx_bytes;
                binding.tx_completions = snap.tx_completions;
                binding.tx_errors = snap.tx_errors;
                binding.redirect_inbox_overflow_drops = snap.redirect_inbox_overflow_drops;
                binding.pending_tx_local_overflow_drops = snap.pending_tx_local_overflow_drops;
                binding.tx_submit_error_drops = snap.tx_submit_error_drops;
                binding.post_drain_backup_bytes = snap.post_drain_backup_bytes;
                binding.drain_sent_bytes_shaped_unconditional =
                    snap.drain_sent_bytes_shaped_unconditional;
                binding.post_drain_backup_cos_drops = snap.post_drain_backup_cos_drops;
                binding.post_drain_backup_cos_drop_bytes = snap.post_drain_backup_cos_drop_bytes;
                // #710: `snap.no_owner_binding_drops` is not copied into
                // per-binding status — it is summed across all bindings
                // into `ProcessStatus::cos_no_owner_binding_drops_total`
                // at the refresh_status callsite, which is the correct
                // operator-facing scope for this counter.
                binding.direct_tx_packets = snap.direct_tx_packets;
                binding.copy_tx_packets = snap.copy_tx_packets;
                binding.in_place_tx_packets = snap.in_place_tx_packets;
                binding.direct_tx_no_frame_fallback_packets =
                    snap.direct_tx_no_frame_fallback_packets;
                binding.direct_tx_build_fallback_packets = snap.direct_tx_build_fallback_packets;
                binding.direct_tx_disallowed_fallback_packets =
                    snap.direct_tx_disallowed_fallback_packets;
                binding.debug_pending_fill_frames = snap.debug_pending_fill_frames;
                binding.debug_spare_fill_frames = 0;
                binding.debug_free_tx_frames = snap.debug_free_tx_frames;
                binding.debug_pending_tx_prepared = snap.debug_pending_tx_prepared;
                binding.debug_pending_tx_local = snap.debug_pending_tx_local;
                binding.debug_outstanding_tx = snap.debug_outstanding_tx;
                binding.debug_in_flight_recycles = snap.debug_in_flight_recycles;
                // #878: per-binding capacities + in-flight gauge flow
                // into BindingStatus so the daemon's fwdstatus
                // Buffer% can compute UMEM and TX-ring fill ratios.
                binding.umem_total_frames = snap.umem_total_frames;
                binding.tx_ring_capacity = snap.tx_ring_capacity;
                binding.umem_inflight_frames = snap.umem_inflight_frames;
                // #802: ring-pressure counters — atomic mirrors of
                // worker-local counters, published on the worker's
                // per-second debug tick. `outstanding_tx` aliases
                // `debug_outstanding_tx` for the operator-facing name.
                binding.dbg_tx_ring_full = snap.dbg_tx_ring_full;
                binding.dbg_sendto_enobufs = snap.dbg_sendto_enobufs;
                // #804: split counters — bound-pending FIFO vs CoS
                // queue admission. Pre-#804 a single `dbg_pending_overflow`
                // was published; the wire name was removed because
                // the semantics were ambiguous for operators.
                binding.dbg_bound_pending_overflow = snap.dbg_bound_pending_overflow;
                binding.dbg_cos_queue_overflow = snap.dbg_cos_queue_overflow;
                binding.rx_fill_ring_empty_descs = snap.rx_fill_ring_empty_descs;
                binding.outstanding_tx = snap.debug_outstanding_tx;
                // #812: per-queue TX submit→completion latency
                // telemetry. Materialize the fixed-cap snapshot
                // array into a freshly-owned Vec<u64> on the wire
                // boundary — reuses the buffer in-place to avoid
                // allocator churn when the BindingStatus entry is
                // refreshed on the ~1s poll cadence.
                binding
                    .tx_submit_latency_hist
                    .resize(snap.tx_submit_latency_hist.len(), 0);
                binding
                    .tx_submit_latency_hist
                    .copy_from_slice(&snap.tx_submit_latency_hist);
                binding.tx_submit_latency_count = snap.tx_submit_latency_count;
                binding.tx_submit_latency_sum_ns = snap.tx_submit_latency_sum_ns;
                // #825: per-kick `sendto` latency telemetry mirrors
                // the #812 submit-latency copy path above. Resize
                // the operator-facing Vec<u64> to match the
                // snapshot's fixed-cap array, then copy bucket
                // counts and scalars. `tx_kick_retry_count` is the
                // EAGAIN/EWOULDBLOCK tally (T1 ring-pushback).
                binding
                    .tx_kick_latency_hist
                    .resize(snap.tx_kick_latency_hist.len(), 0);
                binding
                    .tx_kick_latency_hist
                    .copy_from_slice(&snap.tx_kick_latency_hist);
                binding.tx_kick_latency_count = snap.tx_kick_latency_count;
                binding.tx_kick_latency_sum_ns = snap.tx_kick_latency_sum_ns;
                binding.tx_kick_retry_count = snap.tx_kick_retry_count;
                binding.last_heartbeat = snap.last_heartbeat;
                binding.last_error = snap.last_error;
                binding.ready = binding.registered
                    && binding.bound
                    && binding.xsk_registered
                    && heartbeat_fresh(snap.last_heartbeat);
            } else {
                binding.bound = false;
                binding.xsk_registered = false;
                binding.xsk_bind_mode.clear();
                binding.zero_copy = false;
                binding.socket_fd = 0;
                binding.socket_ifindex = 0;
                binding.socket_queue_id = 0;
                binding.socket_bind_flags = 0;
                binding.rx_packets = 0;
                binding.rx_bytes = 0;
                binding.rx_batches = 0;
                binding.rx_wakeups = 0;
                binding.metadata_packets = 0;
                binding.metadata_errors = 0;
                binding.validated_packets = 0;
                binding.validated_bytes = 0;
                binding.local_delivery_packets = 0;
                binding.forward_candidate_packets = 0;
                binding.route_miss_packets = 0;
                binding.neighbor_miss_packets = 0;
                binding.discard_route_packets = 0;
                binding.next_table_packets = 0;
                binding.exception_packets = 0;
                binding.config_gen_mismatches = 0;
                binding.fib_gen_mismatches = 0;
                binding.unsupported_packets = 0;
                binding.flow_cache_hits = 0;
                binding.flow_cache_misses = 0;
                binding.flow_cache_evictions = 0;
                binding.flow_cache_collision_evictions = 0;
                binding.v_min_throttle_hard_cap_overrides = 0;
                binding.v_min_throttles = 0;
                binding.session_hits = 0;
                binding.session_misses = 0;
                binding.session_creates = 0;
                binding.session_expires = 0;
                binding.session_delta_pending = 0;
                binding.session_delta_generated = 0;
                binding.session_delta_dropped = 0;
                binding.session_delta_drained = 0;
                binding.policy_denied_packets = 0;
                binding.snat_packets = 0;
                binding.dnat_packets = 0;
                binding.slow_path_packets = 0;
                binding.slow_path_bytes = 0;
                binding.slow_path_local_delivery_packets = 0;
                binding.slow_path_missing_neighbor_packets = 0;
                binding.slow_path_no_route_packets = 0;
                binding.slow_path_next_table_packets = 0;
                binding.slow_path_forward_build_packets = 0;
                binding.slow_path_drops = 0;
                binding.slow_path_rate_limited = 0;
                binding.kernel_rx_dropped = 0;
                binding.kernel_rx_invalid_descs = 0;
                binding.tx_packets = 0;
                binding.tx_bytes = 0;
                binding.tx_completions = 0;
                binding.tx_errors = 0;
                binding.post_drain_backup_bytes = 0;
                binding.drain_sent_bytes_shaped_unconditional = 0;
                binding.post_drain_backup_cos_drops = 0;
                binding.post_drain_backup_cos_drop_bytes = 0;
                binding.direct_tx_packets = 0;
                binding.copy_tx_packets = 0;
                binding.in_place_tx_packets = 0;
                binding.direct_tx_no_frame_fallback_packets = 0;
                binding.direct_tx_build_fallback_packets = 0;
                binding.direct_tx_disallowed_fallback_packets = 0;
                binding.debug_pending_fill_frames = 0;
                binding.debug_spare_fill_frames = 0;
                binding.debug_free_tx_frames = 0;
                binding.debug_pending_tx_prepared = 0;
                binding.debug_pending_tx_local = 0;
                binding.debug_outstanding_tx = 0;
                binding.debug_in_flight_recycles = 0;
                // #878: capacities + in-flight gauge zero when the
                // binding has no live state (slot unregistered). The
                // daemon treats zero umem_total_frames as "unknown"
                // and falls back to the legacy Buffer% display.
                binding.umem_total_frames = 0;
                binding.tx_ring_capacity = 0;
                binding.umem_inflight_frames = 0;
                // #802: ring-pressure counters — zero when the binding
                // has no live state (unregistered slot).
                binding.dbg_tx_ring_full = 0;
                binding.dbg_sendto_enobufs = 0;
                binding.dbg_bound_pending_overflow = 0;
                binding.dbg_cos_queue_overflow = 0;
                binding.rx_fill_ring_empty_descs = 0;
                binding.outstanding_tx = 0;
                // #812: zero the submit-latency histogram when the
                // binding has no live state (unregistered slot).
                binding.tx_submit_latency_hist.clear();
                binding.tx_submit_latency_count = 0;
                binding.tx_submit_latency_sum_ns = 0;
                // #825: zero the kick-latency histogram + retry
                // counter when the binding has no live state.
                binding.tx_kick_latency_hist.clear();
                binding.tx_kick_latency_count = 0;
                binding.tx_kick_latency_sum_ns = 0;
                binding.tx_kick_retry_count = 0;
                binding.last_heartbeat = None;
                binding.last_error.clear();
                binding.ready = false;
            }
        }
        self.refresh_cos_owner_worker_map_from_binding_statuses(bindings);
    }
}

// #710: pure-function extraction of the coordinator-level aggregation
// so it can be unit-tested without constructing a full `Coordinator`
// fixture. The live bug this PR closes escaped CI because this exact
// summation layer lacked a regression; the function form lets us pin
// it in isolation. `Coordinator::cos_statuses` reads per-worker
// snapshots from `worker.cos_status` (built by
// `build_worker_cos_statuses` on the worker side) and sums them here.
pub(super) fn aggregate_cos_statuses_across_workers(
    worker_snapshots: &[Vec<crate::protocol::CoSInterfaceStatus>],
    owner_by_queue: &BTreeMap<(i32, u8), u32>,
) -> Vec<crate::protocol::CoSInterfaceStatus> {
    let mut interfaces = BTreeMap::<i32, crate::protocol::CoSInterfaceStatus>::new();
    let mut queue_maps = BTreeMap::<i32, BTreeMap<u8, crate::protocol::CoSQueueStatus>>::new();
    for snapshot in worker_snapshots {
        for iface in snapshot.iter() {
            let entry = interfaces.entry(iface.ifindex).or_default();
            entry.ifindex = iface.ifindex;
            if entry.interface_name.is_empty() {
                entry.interface_name = iface.interface_name.clone();
            }
            entry.shaping_rate_bytes = entry.shaping_rate_bytes.max(iface.shaping_rate_bytes);
            entry.burst_bytes = entry.burst_bytes.max(iface.burst_bytes);
            entry.worker_instances = entry
                .worker_instances
                .saturating_add(iface.worker_instances);
            entry.timer_level0_sleepers = entry
                .timer_level0_sleepers
                .saturating_add(iface.timer_level0_sleepers);
            entry.timer_level1_sleepers = entry
                .timer_level1_sleepers
                .saturating_add(iface.timer_level1_sleepers);
            let queue_map = queue_maps.entry(iface.ifindex).or_default();
            for queue in &iface.queues {
                let q = queue_map.entry(queue.queue_id).or_default();
                q.queue_id = queue.queue_id;
                if q.owner_worker_id.is_none() {
                    q.owner_worker_id = owner_by_queue
                        .get(&(iface.ifindex, queue.queue_id))
                        .copied();
                }
                if q.forwarding_class.is_empty() {
                    q.forwarding_class = queue.forwarding_class.clone();
                }
                if q.worker_instances == 0 {
                    q.priority = queue.priority;
                } else {
                    q.priority = q.priority.min(queue.priority);
                }
                q.exact = queue.exact;
                // #784: flow_fair is per-worker-queue-runtime; OR
                // across workers so any worker with flow_fair=true
                // surfaces. active_flow_buckets_peak is already
                // max-aggregated by the worker snapshot; take max
                // here across workers too.
                if queue.flow_fair {
                    q.flow_fair = true;
                }
                if queue.active_flow_buckets_peak > q.active_flow_buckets_peak {
                    q.active_flow_buckets_peak = queue.active_flow_buckets_peak;
                }
                q.transmit_rate_bytes = q.transmit_rate_bytes.max(queue.transmit_rate_bytes);
                q.buffer_bytes = q.buffer_bytes.max(queue.buffer_bytes);
                q.worker_instances = q.worker_instances.saturating_add(queue.worker_instances);
                q.queued_packets = q.queued_packets.saturating_add(queue.queued_packets);
                q.queued_bytes = q.queued_bytes.saturating_add(queue.queued_bytes);
                q.runnable_instances = q
                    .runnable_instances
                    .saturating_add(queue.runnable_instances);
                q.parked_instances = q.parked_instances.saturating_add(queue.parked_instances);
                if q.next_wakeup_tick == 0
                    || (queue.next_wakeup_tick > 0 && queue.next_wakeup_tick < q.next_wakeup_tick)
                {
                    q.next_wakeup_tick = queue.next_wakeup_tick;
                }
                q.surplus_deficit_bytes = q
                    .surplus_deficit_bytes
                    .saturating_add(queue.surplus_deficit_bytes);
                // #710: aggregate drop-reason counters across per-worker
                // snapshots. The worker builder already summed across
                // queues within its local runtime; this layer sums
                // across workers for the final operator-facing view.
                q.admission_flow_share_drops = q
                    .admission_flow_share_drops
                    .saturating_add(queue.admission_flow_share_drops);
                q.admission_buffer_drops = q
                    .admission_buffer_drops
                    .saturating_add(queue.admission_buffer_drops);
                // #718: cross-worker aggregation for the ECN-marked
                // counter. Mirrors the other admission counters above.
                q.admission_ecn_marked = q
                    .admission_ecn_marked
                    .saturating_add(queue.admission_ecn_marked);
                q.root_token_starvation_parks = q
                    .root_token_starvation_parks
                    .saturating_add(queue.root_token_starvation_parks);
                q.queue_token_starvation_parks = q
                    .queue_token_starvation_parks
                    .saturating_add(queue.queue_token_starvation_parks);
                q.tx_ring_full_submit_stalls = q
                    .tx_ring_full_submit_stalls
                    .saturating_add(queue.tx_ring_full_submit_stalls);
                // #709: cross-worker aggregation for owner-profile
                // counters is sum, not max. Histograms and invocation
                // counters must stay coherent after aggregation;
                // per-bucket max can synthesize a profile no worker
                // observed while breaking `sum(hist) == invocations`.
                // See `merge_owner_profile_sum` /
                // `merge_cos_queue_owner_profile_sum`.
                super::worker::merge_cos_queue_owner_profile_sum(q, queue);
            }
        }
    }
    let mut out = Vec::with_capacity(interfaces.len());
    for (ifindex, mut iface) in interfaces {
        if let Some(queue_map) = queue_maps.remove(&ifindex) {
            iface.queues = queue_map.into_values().collect();
            iface.owner_worker_id = unique_interface_owner_worker_id(&iface.queues);
            iface.nonempty_queues = iface
                .queues
                .iter()
                .filter(|queue| queue.queued_packets > 0 || queue.queued_bytes > 0)
                .count();
            iface.runnable_queues = iface
                .queues
                .iter()
                .filter(|queue| queue.runnable_instances > 0)
                .count();
        }
        out.push(iface);
    }
    out.sort_by(|a, b| {
        a.interface_name
            .cmp(&b.interface_name)
            .then(a.ifindex.cmp(&b.ifindex))
    });
    out
}

fn unique_interface_owner_worker_id(queues: &[crate::protocol::CoSQueueStatus]) -> Option<u32> {
    let mut owner_worker_id = None;
    for queue in queues {
        let queue_owner = queue.owner_worker_id?;
        match owner_worker_id {
            None => owner_worker_id = Some(queue_owner),
            Some(existing) if existing == queue_owner => {}
            Some(_) => return None,
        }
    }
    owner_worker_id
}

fn build_cos_owner_worker_by_queue(
    forwarding: &ForwardingState,
    workers: &BTreeMap<u32, Vec<BindingPlan>>,
) -> BTreeMap<(i32, u8), u32> {
    let worker_binding_ifindexes = workers
        .iter()
        .map(|(worker_id, binding_plans)| {
            (
                *worker_id,
                binding_plans
                    .iter()
                    .map(|plan| plan.status.ifindex)
                    .collect::<std::collections::BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    build_cos_owner_worker_by_queue_from_binding_ifindexes(forwarding, &worker_binding_ifindexes)
}

fn build_worker_binding_ifindexes_from_identities(
    identities: &BTreeMap<u32, BindingIdentity>,
) -> BTreeMap<u32, std::collections::BTreeSet<i32>> {
    let mut out = BTreeMap::<u32, std::collections::BTreeSet<i32>>::new();
    for ident in identities.values() {
        out.entry(ident.worker_id)
            .or_default()
            .insert(ident.ifindex);
    }
    out
}

fn build_cos_owner_worker_by_queue_from_binding_ifindexes(
    forwarding: &ForwardingState,
    worker_binding_ifindexes: &BTreeMap<u32, std::collections::BTreeSet<i32>>,
) -> BTreeMap<(i32, u8), u32> {
    build_cos_owner_worker_by_queue_with_fallback_ifindexes(
        forwarding,
        worker_binding_ifindexes,
        worker_binding_ifindexes,
    )
}

fn build_cos_owner_worker_by_queue_with_fallback_ifindexes(
    forwarding: &ForwardingState,
    preferred_worker_binding_ifindexes: &BTreeMap<u32, std::collections::BTreeSet<i32>>,
    fallback_worker_binding_ifindexes: &BTreeMap<u32, std::collections::BTreeSet<i32>>,
) -> BTreeMap<(i32, u8), u32> {
    let mut owner_by_queue = BTreeMap::new();
    let mut next_owner_slot_by_tx_ifindex = BTreeMap::<i32, usize>::new();
    let mut egress_ifindexes = forwarding
        .cos
        .interfaces
        .keys()
        .copied()
        .collect::<Vec<_>>();
    egress_ifindexes.sort_unstable();
    for egress_ifindex in egress_ifindexes {
        let tx_ifindex = resolve_tx_binding_ifindex(forwarding, egress_ifindex);
        let preferred_workers = preferred_worker_binding_ifindexes
            .iter()
            .filter_map(|(worker_id, ifindexes)| {
                ifindexes.contains(&tx_ifindex).then_some(*worker_id)
            })
            .collect::<Vec<_>>();
        let eligible_workers = if preferred_workers.is_empty() {
            fallback_worker_binding_ifindexes
                .iter()
                .filter_map(|(worker_id, ifindexes)| {
                    ifindexes.contains(&tx_ifindex).then_some(*worker_id)
                })
                .collect::<Vec<_>>()
        } else {
            preferred_workers
        };
        if eligible_workers.is_empty() {
            continue;
        }
        let next_slot = next_owner_slot_by_tx_ifindex.entry(tx_ifindex).or_default();
        let Some(iface) = forwarding.cos.interfaces.get(&egress_ifindex) else {
            continue;
        };
        for queue in &iface.queues {
            let owner_worker_id = eligible_workers[*next_slot % eligible_workers.len()];
            *next_slot += 1;
            owner_by_queue.insert((egress_ifindex, queue.queue_id), owner_worker_id);
        }
    }
    owner_by_queue
}

fn build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes(
    forwarding: &ForwardingState,
    preferred_worker_binding_ifindexes: &BTreeMap<u32, std::collections::BTreeSet<i32>>,
    fallback_worker_binding_ifindexes: &BTreeMap<u32, std::collections::BTreeSet<i32>>,
) -> BTreeMap<i32, usize> {
    let mut out = BTreeMap::new();
    let mut egress_ifindexes = forwarding
        .cos
        .interfaces
        .keys()
        .copied()
        .collect::<Vec<_>>();
    egress_ifindexes.sort_unstable();
    for egress_ifindex in egress_ifindexes {
        let tx_ifindex = resolve_tx_binding_ifindex(forwarding, egress_ifindex);
        let preferred_count = preferred_worker_binding_ifindexes
            .values()
            .filter(|ifindexes| ifindexes.contains(&tx_ifindex))
            .count();
        let fallback_count = fallback_worker_binding_ifindexes
            .values()
            .filter(|ifindexes| ifindexes.contains(&tx_ifindex))
            .count();
        let active_shards = if preferred_count > 0 {
            preferred_count
        } else {
            fallback_count
        }
        .max(1);
        out.insert(egress_ifindex, active_shards);
    }
    out
}

fn build_shared_cos_root_leases(
    forwarding: &ForwardingState,
    active_shards_by_egress_ifindex: &BTreeMap<i32, usize>,
) -> BTreeMap<i32, Arc<SharedCoSRootLease>> {
    build_shared_cos_root_leases_reusing_existing(
        forwarding,
        active_shards_by_egress_ifindex,
        &BTreeMap::new(),
    )
}

fn build_cos_owner_live_by_queue(
    forwarding: &ForwardingState,
    owner_by_queue: &BTreeMap<(i32, u8), u32>,
    identities: &BTreeMap<u32, BindingIdentity>,
    live: &BTreeMap<u32, Arc<BindingLiveState>>,
) -> BTreeMap<(i32, u8), Arc<BindingLiveState>> {
    let mut live_by_worker_ifindex = BTreeMap::<(u32, i32), Arc<BindingLiveState>>::new();
    for (slot, ident) in identities {
        let Some(binding_live) = live.get(slot) else {
            continue;
        };
        live_by_worker_ifindex
            .entry((ident.worker_id, ident.ifindex))
            .or_insert_with(|| binding_live.clone());
    }

    let mut out = BTreeMap::new();
    for (&(egress_ifindex, queue_id), &worker_id) in owner_by_queue {
        let tx_ifindex = resolve_tx_binding_ifindex(forwarding, egress_ifindex);
        let Some(owner_live) = live_by_worker_ifindex.get(&(worker_id, tx_ifindex)) else {
            continue;
        };
        out.insert((egress_ifindex, queue_id), owner_live.clone());
    }
    out
}

fn build_shared_cos_root_leases_reusing_existing(
    forwarding: &ForwardingState,
    active_shards_by_egress_ifindex: &BTreeMap<i32, usize>,
    existing: &BTreeMap<i32, Arc<SharedCoSRootLease>>,
) -> BTreeMap<i32, Arc<SharedCoSRootLease>> {
    let mut out = BTreeMap::new();
    for (&ifindex, iface) in &forwarding.cos.interfaces {
        let active_shards = active_shards_by_egress_ifindex
            .get(&ifindex)
            .copied()
            .unwrap_or(1)
            .max(1);
        let burst_bytes = iface.burst_bytes.max(64 * 1500);
        if let Some(lease) = existing.get(&ifindex).filter(|lease| {
            lease.matches_config(iface.shaping_rate_bytes, burst_bytes, active_shards)
        }) {
            out.insert(ifindex, lease.clone());
            continue;
        }
        out.insert(
            ifindex,
            Arc::new(SharedCoSRootLease::new(
                iface.shaping_rate_bytes,
                burst_bytes,
                active_shards,
            )),
        );
    }
    out
}

fn build_shared_cos_queue_leases_reusing_existing(
    forwarding: &ForwardingState,
    active_shards_by_egress_ifindex: &BTreeMap<i32, usize>,
    existing: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
) -> BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>> {
    let mut out = BTreeMap::new();
    for (&ifindex, iface) in &forwarding.cos.interfaces {
        let active_shards = active_shards_by_egress_ifindex
            .get(&ifindex)
            .copied()
            .unwrap_or(1)
            .max(1);
        for queue in &iface.queues {
            if !queue.exact || queue.transmit_rate_bytes == 0 {
                continue;
            }
            let burst_bytes = queue.buffer_bytes.max(64 * 1500);
            let key = (ifindex, queue.queue_id);
            if let Some(lease) = existing.get(&key).filter(|lease| {
                lease.matches_config(queue.transmit_rate_bytes, burst_bytes, active_shards)
            }) {
                out.insert(key, lease.clone());
                continue;
            }
            out.insert(
                key,
                Arc::new(SharedCoSQueueLease::new(
                    queue.transmit_rate_bytes,
                    burst_bytes,
                    active_shards,
                )),
            );
        }
    }
    out
}

fn shared_cos_root_leases_match(
    current: &BTreeMap<i32, Arc<SharedCoSRootLease>>,
    next: &BTreeMap<i32, Arc<SharedCoSRootLease>>,
) -> bool {
    current.len() == next.len()
        && current.iter().all(|(ifindex, lease)| {
            next.get(ifindex)
                .is_some_and(|next| Arc::ptr_eq(lease, next))
        })
}

/// #917: build/reuse the per-shared_exact-queue V_min
/// coordination Arcs. Mirror of
/// `build_shared_cos_queue_leases_reusing_existing` — same
/// keying ((ifindex, queue_id)), same Arc-reuse discipline.
/// Each queue's `SharedCoSQueueVtimeFloor` is sized by the
/// configured worker count; if the worker count changes we
/// reallocate (slot count is fixed for the Arc's lifetime).
fn build_shared_cos_queue_vtime_floors_reusing_existing(
    forwarding: &ForwardingState,
    num_workers: usize,
    existing: &BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>,
) -> BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>> {
    let num_workers = num_workers.max(1);
    let mut out = BTreeMap::new();
    for (&ifindex, iface) in &forwarding.cos.interfaces {
        for queue in &iface.queues {
            // #917 Codex Q8: gate on shared_exact at allocation
            // time so owner-local-exact queues don't carry a
            // V_min floor. Owner-local queues have no peers
            // (single-owner by definition); a floor on those
            // would only consume memory and risk false
            // throttling if the read-path gate ever
            // regresses. The shared_exact promotion check
            // mirrors `queue_uses_shared_exact_service` in
            // worker.rs.
            if !queue.exact
                || queue.transmit_rate_bytes < super::worker::COS_SHARED_EXACT_MIN_RATE_BYTES
            {
                continue;
            }
            let key = (ifindex, queue.queue_id);
            if let Some(floor) = existing.get(&key).filter(|f| f.slots.len() == num_workers) {
                out.insert(key, floor.clone());
                continue;
            }
            out.insert(key, Arc::new(SharedCoSQueueVtimeFloor::new(num_workers)));
        }
    }
    out
}

fn shared_cos_queue_vtime_floors_match(
    current: &BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>,
    next: &BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>,
) -> bool {
    current.len() == next.len()
        && current.iter().all(|(key, floor)| {
            next.get(key)
                .is_some_and(|next| Arc::ptr_eq(floor, next))
        })
}

fn shared_cos_queue_leases_match(
    current: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
    next: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
) -> bool {
    current.len() == next.len()
        && current
            .iter()
            .all(|(key, lease)| next.get(key).is_some_and(|next| Arc::ptr_eq(lease, next)))
}

fn shared_cos_owner_live_by_queue_match(
    current: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
    next: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
) -> bool {
    current.len() == next.len()
        && current.iter().all(|(key, live)| {
            next.get(key)
                .is_some_and(|next_live| Arc::ptr_eq(live, next_live))
        })
}


#[cfg(test)]
#[path = "tests.rs"]
mod tests;
