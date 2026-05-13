use super::*;

// Issue 73 step 2: per-poll BindingWorker lifecycle (the central
// `poll_binding` orchestrator) lives in worker/lifecycle.rs.
mod lifecycle;
use lifecycle::poll_binding;

// #959 Phase 1: per-worker debug counters live in worker/telemetry.rs.
mod telemetry;
pub(crate) use telemetry::WorkerTelemetry;

// #959 Phase 2: per-binding reusable scratch buffers live in
// worker/scratch.rs.
mod scratch;
pub(crate) use scratch::WorkerScratch;

// #959 Phase 3: per-binding CoS scheduling state lives in
// worker/cos_state.rs (the `cos` module name is taken by
// worker/cos.rs which holds runtime helpers).
mod cos_state;
pub(crate) use cos_state::WorkerCos;

// #959 Phase 4: per-binding TX-disposition packet counters live in
// worker/tx_counters.rs.
mod tx_counters;
pub(crate) use tx_counters::WorkerTxCounters;

// #959 Phase 5: per-binding BPF map FDs live in worker/bpf_maps.rs.
mod bpf_maps;
pub(crate) use bpf_maps::WorkerBpfMaps;

// #959 Phase 6: per-binding timing / wake-pacing state lives in
// worker/timers.rs.
mod timers;
pub(crate) use timers::WorkerTimers;

// #959 Phase 7: per-binding TX pipeline state lives in
// worker/tx_pipeline.rs.
mod tx_pipeline;
pub(crate) use tx_pipeline::WorkerTxPipeline;

// #959 Phase 8: per-binding registration / identity metadata lives
// in worker/bind_meta.rs.
mod bind_meta;
pub(crate) use bind_meta::WorkerBindMeta;

// #959 Phase 9: per-binding flow-cache state lives in
// worker/flow_cache_state.rs (the `flow_cache` name is taken by
// the `FlowCache` data structure in src/afxdp/flow_cache.rs).
mod flow_cache_state;
pub(crate) use flow_cache_state::WorkerFlowCacheState;

// #959 Phase 11 — XSK kernel-ring handles in
// worker/xsk_rings.rs. Holds the three socket-ring objects
// `device`, `rx`, `tx` (was held back as highest-risk because
// of the `off.rx`/`off.tx` and `telemetry.dbg.rx`/`.tx`
// snapshot/diagnostic name collisions).
mod xsk_rings;
pub(crate) use xsk_rings::WorkerXskRings;

// #957 P1: worker-side CoS runtime helpers split out into a sibling
// submodule. Note this module is `worker::cos`, separate from the
// `afxdp::cos` directory module imported below as `super::cos`.
mod cos;
use cos::{
    build_worker_cos_fast_interfaces, build_worker_cos_owner_live_by_tx_ifindex,
    build_worker_cos_statuses, cos_runtime_config_changed, reset_binding_cos_runtime,
    reset_worker_cos_runtimes, vacate_all_shared_exact_slots_for_binding,
};
pub(crate) use cos::merge_cos_queue_owner_profile_sum;
pub(in crate::afxdp) use cos::COS_SHARED_EXACT_MIN_RATE_BYTES;
pub(in crate::afxdp) use cos::{
    OwnerProfileSnapshot, merge_binding_scoped_owner_profile, merge_owner_profile_sum,
    owner_profile_snapshot,
};

// #956 Phase 4-5: explicit imports for items that moved out of tx.rs into
// cos/token_bucket.rs (Phase 4) and cos/queue_ops.rs (Phase 5). Without
// this, neither the local `use super::*;` glob nor afxdp.rs's
// `use self::tx::*;` parent-module glob still reaches them — the items
// no longer originate from tx.rs after the moves.
use super::cos::{
    cos_queue_len, cos_queue_pop_front_no_snapshot, release_all_cos_queue_leases,
    release_all_cos_root_leases,
};

pub(crate) struct BindingWorker {
    pub(crate) slot: u32,
    pub(crate) queue_id: u32,
    pub(crate) worker_id: u32,
    pub(crate) interface: Arc<str>,
    pub(crate) ifindex: i32,
    pub(crate) live: Arc<BindingLiveState>,
    #[allow(dead_code)]
    pub(crate) user: User,
    /// #959 Phase 11: 3 XSK kernel-ring handles extracted into
    /// `WorkerXskRings`. Field semantics unchanged; access via
    /// `binding.xsk.device`, `binding.xsk.rx`, `binding.xsk.tx`.
    pub(crate) xsk: WorkerXskRings,
    /// Keep UMEM after the XSK handles in declaration order. Rust drops
    /// struct fields in declaration order, and libxdp sockets must be deleted
    /// before the backing UMEM can be deleted in shared mode.
    pub(crate) umem: WorkerUmem,
    /// #959 Phase 7 + Phase 10: 8 TX pipeline fields extracted into
    /// `WorkerTxPipeline` (Phase 7 brought 7; Phase 10 added
    /// `outstanding_tx` once the BindingStatus mirror collision was
    /// resolved by type-level disambiguation). Field semantics
    /// unchanged; access via `binding.tx_pipeline.X`.
    pub(crate) tx_pipeline: WorkerTxPipeline,
    /// #959 Phase 3: 5 `cos_*` per-binding CoS scheduling fields
    /// extracted into `WorkerCos`. Field semantics unchanged;
    /// access via `binding.cos.cos_X`.
    pub(crate) cos: WorkerCos,
    /// #959 Phase 2: 11 `scratch_*` reusable buffers extracted into
    /// `WorkerScratch`. Field semantics unchanged; access via
    /// `binding.scratch.scratch_X`.
    pub(crate) scratch: WorkerScratch,
    /// Packets waiting for neighbor resolution. The UMEM frame is held
    /// (not recycled) until the neighbor resolves or the entry times out.
    pub(crate) pending_neigh: VecDeque<PendingNeighPacket>,
    /// #959 Phase 5: 4 BPF map FDs extracted into `WorkerBpfMaps`.
    /// Field semantics unchanged; access via `binding.bpf_maps.X_fd`.
    pub(crate) bpf_maps: WorkerBpfMaps,
    /// #959 Phase 6: 6 timing / wake-pacing fields extracted into
    /// `WorkerTimers`. Field semantics unchanged; access via
    /// `binding.timers.last_X_ns` etc.
    pub(crate) timers: WorkerTimers,
    pub(crate) last_learned_neighbor: Option<LearnedNeighborKey>,
    /// #959 Phase 1: 23 `dbg_*` debug counters extracted into
    /// `WorkerTelemetry` to reduce BindingWorker's mutable surface
    /// area. Field semantics unchanged; access via `binding.telemetry.dbg_X`.
    pub(crate) telemetry: WorkerTelemetry,
    /// #959 Phase 4: 6 `pending_*_tx_*` packet counters extracted
    /// into `WorkerTxCounters`. Field semantics unchanged; access
    /// via `binding.tx_counters.pending_X`.
    pub(crate) tx_counters: WorkerTxCounters,
    /// #959 Phase 9: 2 flow-cache state fields extracted into
    /// `WorkerFlowCacheState`. Field semantics unchanged; access
    /// via `binding.flow.flow_cache` and `binding.flow.flow_cache_session_touch`.
    pub(crate) flow: WorkerFlowCacheState,
    /// #959 Phase 8: 3 binding registration / identity fields
    /// (bind_time_ns, bind_mode, xsk_rx_confirmed) extracted into
    /// `WorkerBindMeta`. Field semantics unchanged; access via
    /// `binding.bind_meta.X`.
    pub(crate) bind_meta: WorkerBindMeta,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum XskBindMode {
    Unknown,
    Copy,
    ZeroCopy,
}

impl XskBindMode {
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Copy => 1,
            Self::ZeroCopy => 2,
        }
    }

    pub(crate) fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Copy,
            2 => Self::ZeroCopy,
            _ => Self::Unknown,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "",
            Self::Copy => "copy",
            Self::ZeroCopy => "zerocopy",
        }
    }

    pub(crate) fn is_zerocopy(self) -> bool {
        matches!(self, Self::ZeroCopy)
    }
}

pub(crate) fn fabric_queue_hash(
    flow: Option<&SessionFlow>,
    expected_ports: Option<(u16, u16)>,
    meta: UserspaceDpMeta,
) -> u64 {
    fn mix(seed: &mut u64, value: u64) {
        *seed ^= value
            .wrapping_add(0x9e3779b97f4a7c15)
            .wrapping_add(*seed << 6)
            .wrapping_add(*seed >> 2);
    }

    let mut seed = meta.protocol as u64;
    if let Some(flow) = flow {
        match flow.src_ip {
            IpAddr::V4(ip) => mix(&mut seed, u32::from(ip) as u64),
            IpAddr::V6(ip) => {
                for chunk in ip.octets().chunks_exact(8) {
                    mix(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
                }
            }
        }
        match flow.dst_ip {
            IpAddr::V4(ip) => mix(&mut seed, u32::from(ip) as u64),
            IpAddr::V6(ip) => {
                for chunk in ip.octets().chunks_exact(8) {
                    mix(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
                }
            }
        }
        mix(&mut seed, flow.forward_key.src_port as u64);
        mix(&mut seed, flow.forward_key.dst_port as u64);
        return seed;
    }
    let (src_port, dst_port) = expected_ports.unwrap_or((meta.flow_src_port, meta.flow_dst_port));
    mix(&mut seed, src_port as u64);
    mix(&mut seed, dst_port as u64);
    seed
}

#[derive(Clone, Debug)]
pub(crate) struct SyncedSessionEntry {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
}

impl BindingWorker {
    fn create(
        binding: &BindingStatus,
        ring_entries: u32,
        xsk_map_fd: c_int,
        heartbeat_map_fd: c_int,
        session_map_fd: c_int,
        conntrack_v4_fd: c_int,
        conntrack_v6_fd: c_int,
        live: Arc<BindingLiveState>,
        bind_strategy: AfXdpBindStrategy,
        socket_role: XskSocketRole,
        poll_mode: crate::PollMode,
        mut worker_umem: WorkerUmem,
        frame_pool: &mut VecDeque<u64>,
        shared_umem: bool,
        register_xsk_now: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let driver_name = interface_driver_name(&binding.interface);
        let total_frames =
            binding_frame_count_for_driver(driver_name.as_deref(), ring_entries).max(1);
        let reserved_tx =
            reserved_tx_frames_for_driver(driver_name.as_deref(), ring_entries).min(total_frames);
        let mut reserved_tx_frames = VecDeque::with_capacity(reserved_tx as usize);
        for _ in 0..reserved_tx {
            let Some(offset) = frame_pool.pop_front() else {
                return Err(format!(
                    "insufficient shared UMEM frames for reserved TX on {} if{}q{}",
                    binding.interface, binding.ifindex, binding.queue_id
                )
                .into());
            };
            reserved_tx_frames.push_back(offset);
        }
        // Pre-populate fill ring with ALL remaining frames — no spare held back.
        // This maximizes the kernel's ability to place received packets and
        // prevents fill ring starvation under burst conditions (copy-mode fix).
        let mut initial_fill_frames = Vec::with_capacity((total_frames - reserved_tx) as usize);
        for _ in reserved_tx..total_frames {
            let Some(offset) = frame_pool.pop_front() else {
                return Err(format!(
                    "insufficient shared UMEM frames for fill ring on {} if{}q{}",
                    binding.interface, binding.ifindex, binding.queue_id
                )
                .into());
            };
            initial_fill_frames.push(offset);
        }
        let info = ifinfo_from_binding(binding)?;
        let (user, rx, tx, bind_mode, bind_flags, actual_bind_strategy, device) =
            open_binding_worker_rings(
                &mut worker_umem,
                &info,
                ring_entries,
                bind_strategy,
                socket_role,
                driver_name.as_deref(),
                poll_mode,
                Some(&initial_fill_frames),
            )
            .map_err(|err| format!("configure AF_XDP rings: {err}"))?;

        let user_fd = user.as_raw_fd();
        live.set_bound(user_fd);
        live.set_bind_mode(bind_mode);
        // getsockname() returns ENOTSUP on AF_XDP sockets (kernel doesn't
        // implement it for this family).  Use the binding plan's expected
        // ifindex/queue_id directly — umem.bind() already validated these.
        live.set_socket_binding(binding.ifindex, binding.queue_id, u32::from(bind_flags));
        // #878: publish per-binding capacities so the snapshot path can
        // expose them via the wire BindingStatus. These are write-once
        // (set here at worker construction) and read-many.
        live.umem_total_frames
            .store(total_frames, std::sync::atomic::Ordering::Relaxed);
        live.tx_ring_capacity
            .store(ring_entries, std::sync::atomic::Ordering::Relaxed);
        eprintln!(
            "xpf-userspace-dp: binding slot={} fd={} strategy={} role={} bound if{}q{} mode={:?} flags=0x{:04x} shared_umem={}",
            binding.slot,
            user_fd,
            actual_bind_strategy.describe(),
            socket_role.describe(),
            binding.ifindex,
            binding.queue_id,
            bind_mode,
            bind_flags,
            shared_umem,
        );
        let init_now = monotonic_nanos();
        let max_pending_tx = pending_tx_capacity(ring_entries);
        if let Err(err) = touch_heartbeat(heartbeat_map_fd, binding.slot, &live, init_now) {
            live.set_error(format!("update heartbeat slot: {err}"));
        }
        live.set_max_pending_tx(max_pending_tx);
        let mut binding = Self {
            slot: binding.slot,
            queue_id: binding.queue_id,
            worker_id: binding.worker_id,
            interface: Arc::<str>::from(binding.interface.as_str()),
            ifindex: binding.ifindex,
            umem: worker_umem,
            live,
            user,
            xsk: WorkerXskRings { device, rx, tx },
            tx_pipeline: WorkerTxPipeline {
                free_tx_frames: reserved_tx_frames,
                pending_tx_prepared: VecDeque::new(),
                pending_tx_local: VecDeque::new(),
                max_pending_tx,
                outstanding_tx: 0,
                pending_fill_frames: VecDeque::new(),
                in_flight_prepared_recycles: FastMap::default(),
                // #812: pre-allocate the submit-timestamp sidecar once,
                // sized to the binding's total UMEM frame count so every
                // legal `offset >> UMEM_FRAME_SHIFT` index lands inside
                // the vec. Initial contents are the unstamped sentinel so
                // any stray pre-existing offset in flight (cross-restart
                // completion) is skipped by the reap path (plan §5.4).
                // Allocation happens here — NEVER on the hot path.
                // Rust round-1 MED-1: Box<[u64]> — allocate-once, never
                // grow. `vec![...].into_boxed_slice()` produces an
                // exactly-sized heap allocation with no spare capacity.
                tx_submit_ns: vec![TX_SIDECAR_UNSTAMPED; total_frames as usize].into_boxed_slice(),
            },
            cos: WorkerCos {
                cos_fast_interfaces: FastMap::default(),
                cos_interfaces: FastMap::default(),
                cos_interface_order: Vec::new(),
                cos_interface_rr: 0,
                cos_nonempty_interfaces: 0,
                cos_queue_lease_acquire_v8_calls: 0,
                cos_queue_lease_acquire_v8_granted_bytes: 0,
            },
            scratch: WorkerScratch {
                scratch_recycle: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_forwards: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_fill: Vec::with_capacity(FILL_BATCH_SIZE),
                scratch_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_exact_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_exact_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
                scratch_completed_offsets: Vec::with_capacity(ring_entries as usize),
                scratch_post_recycles: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_cross_binding_tx: Vec::with_capacity(RX_BATCH_SIZE as usize),
                scratch_rst_teardowns: Vec::with_capacity(16),
            },
            // GEMINI-NEXT.md Section 3 cold start: lazy allocation. The
            // 4096-cap is enforced at admission (poll_descriptor.rs check
            // against MAX_PENDING_NEIGH), so pre-allocating that capacity
            // up front would burn ~576 KB per binding at startup even when
            // idle. Start at 0 capacity and let VecDeque grow on push as
            // packets actually queue up.
            pending_neigh: VecDeque::new(),
            bpf_maps: WorkerBpfMaps {
                heartbeat_map_fd,
                session_map_fd,
                conntrack_v4_fd,
                conntrack_v6_fd,
            },
            timers: WorkerTimers {
                last_heartbeat_update_ns: init_now,
                debug_state_counter: 0,
                last_idle_debug_publish_ns: init_now,
                last_rx_wake_ns: init_now,
                last_tx_wake_ns: init_now,
                empty_rx_polls: 0,
            },
            last_learned_neighbor: None,
            telemetry: WorkerTelemetry::default(),
            tx_counters: WorkerTxCounters {
                pending_direct_tx_packets: 0,
                pending_copy_tx_packets: 0,
                pending_in_place_tx_packets: 0,
                pending_direct_tx_no_frame_fallback_packets: 0,
                pending_direct_tx_build_fallback_packets: 0,
                pending_direct_tx_disallowed_fallback_packets: 0,
            },
            flow: WorkerFlowCacheState {
                flow_cache: FlowCache::new(),
                flow_cache_session_touch: 0,
            },
            bind_meta: WorkerBindMeta {
                bind_time_ns: {
                    let mut ts = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    };
                    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
                    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
                },
                bind_mode,
                xsk_rx_confirmed: false,
            },
        };
        if register_xsk_now {
            register_binding_xsk(&binding, xsk_map_fd)?;
        }
        update_binding_debug_state(&mut binding);
        Ok(binding)
    }

    pub(crate) fn identity(&self) -> BindingIdentity {
        BindingIdentity {
            slot: self.slot,
            queue_id: self.queue_id,
            worker_id: self.worker_id,
            interface: self.interface.clone(),
            ifindex: self.ifindex,
        }
    }
}

fn register_binding_xsk(
    binding: &BindingWorker,
    xsk_map_fd: c_int,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let user_fd = binding.user.as_raw_fd();
    if let Err(err) = register_xsk_slot(xsk_map_fd, binding.slot, user_fd) {
        eprintln!(
            "xpf-userspace-dp: ERROR register_xsk_slot slot={} fd={}: {}",
            binding.slot, user_fd, err,
        );
        binding.live.clear_socket_state();
        binding.live.set_error(format!("register XSK slot: {err}"));
        return Err(format!("register XSK slot {} fd {}: {err}", binding.slot, user_fd).into());
    }
    eprintln!(
        "xpf-userspace-dp: registered slot={} fd={} in XSKMAP",
        binding.slot, user_fd,
    );
    binding.live.set_xsk_registered(true);
    binding.live.clear_error();
    Ok(())
}

fn xsk_role_for_shared_plan(plan: &SharedUmemBindingPlan) -> XskSocketRole {
    match plan.socket_role {
        SharedUmemSocketRole::Private => XskSocketRole::Private,
        SharedUmemSocketRole::Owner => XskSocketRole::SharedOwner,
        SharedUmemSocketRole::Secondary => XskSocketRole::SharedSecondary,
    }
}

fn partition_binding_plans(
    binding_plans: Vec<BindingPlan>,
) -> (Vec<BindingPlan>, BTreeMap<String, Vec<BindingPlan>>) {
    let mut private = Vec::new();
    let mut shared = BTreeMap::new();
    for plan in binding_plans {
        if plan.shared_umem.is_shared() {
            shared
                .entry(plan.shared_umem.group_key.clone())
                .or_insert_with(Vec::new)
                .push(plan);
        } else {
            private.push(plan);
        }
    }
    (private, shared)
}

fn create_private_binding_from_plan(
    plan: BindingPlan,
) -> Result<BindingWorker, Box<dyn std::error::Error + Send + Sync>> {
    let driver_name = interface_driver_name(&plan.status.interface);
    let total_frames =
        binding_frame_count_for_driver(driver_name.as_deref(), plan.ring_entries).max(1);
    match WorkerUmemPool::new(total_frames).map_err(|err| format!("create binding umem: {err}")) {
        Ok(WorkerUmemPool {
            umem,
            mut free_frames,
        }) => BindingWorker::create(
            &plan.status,
            plan.ring_entries,
            plan.xsk_map_fd,
            plan.heartbeat_map_fd,
            plan.session_map_fd,
            plan.conntrack_v4_fd,
            plan.conntrack_v6_fd,
            plan.live.clone(),
            plan.bind_strategy,
            XskSocketRole::Private,
            plan.poll_mode,
            umem,
            &mut free_frames,
            false,
            true,
        ),
        Err(err) => Err(err.to_string().into()),
    }
}

fn create_shared_binding_group(
    group_key: &str,
    mut plans: Vec<BindingPlan>,
) -> Result<Vec<BindingWorker>, Box<dyn std::error::Error + Send + Sync>> {
    plans.sort_by_key(|plan| (plan.status.queue_id, plan.status.ifindex, plan.status.slot));
    let group_lives = plans
        .iter()
        .map(|plan| plan.live.clone())
        .collect::<Vec<_>>();
    let total_frames = plans.iter().fold(0u32, |acc, plan| {
        let driver_name = interface_driver_name(&plan.status.interface);
        acc.saturating_add(
            binding_frame_count_for_driver(driver_name.as_deref(), plan.ring_entries).max(1),
        )
    });
    let WorkerUmemPool {
        umem,
        mut free_frames,
    } = WorkerUmemPool::new(total_frames)
        .map_err(|err| format!("create shared UMEM group {group_key}: {err}"))?;

    let mut created: Vec<(BindingWorker, c_int)> = Vec::with_capacity(plans.len());
    for plan in plans {
        let planned_role = xsk_role_for_shared_plan(&plan.shared_umem);
        let socket_role = if created.is_empty() {
            XskSocketRole::SharedOwner
        } else {
            XskSocketRole::SharedSecondary
        };
        if socket_role != planned_role {
            eprintln!(
                "xpf-userspace-dp: shared UMEM group {group_key} corrected planned role for slot={} from {} to {}",
                plan.status.slot,
                planned_role.describe(),
                socket_role.describe(),
            );
        }
        match BindingWorker::create(
            &plan.status,
            plan.ring_entries,
            plan.xsk_map_fd,
            plan.heartbeat_map_fd,
            plan.session_map_fd,
            plan.conntrack_v4_fd,
            plan.conntrack_v6_fd,
            plan.live.clone(),
            plan.bind_strategy,
            socket_role,
            plan.poll_mode,
            umem.clone(),
            &mut free_frames,
            true,
            false,
        ) {
            Ok(binding) => created.push((binding, plan.xsk_map_fd)),
            Err(err) => {
                let msg = format!("shared UMEM group {group_key} bind failed: {err}");
                for live in &group_lives {
                    live.clear_socket_state();
                    live.set_error(msg.clone());
                }
                return Err(msg.into());
            }
        }
    }

    let mut registered = Vec::new();
    for (binding, xsk_map_fd) in &created {
        if let Err(err) = register_binding_xsk(binding, *xsk_map_fd) {
            let msg = format!("shared UMEM group {group_key} XSKMAP registration failed: {err}");
            for (map_fd, slot) in registered {
                let _ = delete_xsk_slot(map_fd, slot);
            }
            for live in &group_lives {
                live.clear_socket_state();
                live.set_error(msg.clone());
            }
            return Err(msg.into());
        }
        registered.push((*xsk_map_fd, binding.slot));
    }

    Ok(created.into_iter().map(|(binding, _)| binding).collect())
}

/// #1188: replace per-tick `.load_full() + Arc::ptr_eq` with `.load() +
/// Arc::ptr_eq` short-circuit. Returns `Some(new_arc)` when the
/// `ArcSwap` has been rotated since `cached` was observed; returns
/// `None` when the cached Arc is still current.
///
/// Steady state (no rotation): the `Arc::ptr_eq` short-circuit avoids
/// the unconditional Arc clone that `.load_full()` performs. At ~10K-
/// 100K worker ticks/sec × 8 workers, this eliminates ~12 atomic RMW
/// operations per tick (6 sites × 2 ops for clone + drop) on the
/// shared Arc control blocks — the bus-saturation issue the ticket
/// describes.
///
/// On actual change: `Guard::into_inner` consumes the observed Guard
/// and yields the exact Arc snapshot we just compared, avoiding a
/// second `.load_full()` (which could otherwise return a *newer* Arc
/// if the coordinator rotated between the `ptr_eq` check and the
/// second load — small TOCTOU window). Note: `load_full()` is itself
/// implemented as `Guard::into_inner(self.load())` (arc-swap 1.8.2
/// `src/lib.rs:414`), so the on-change branch may pay the same as
/// today. The win is the steady-state short-circuit, not the
/// on-change path.
#[inline]
fn load_arc_if_changed<T>(
    cached: &Arc<T>,
    shared: &ArcSwap<T>,
) -> Option<Arc<T>> {
    let guard = shared.load();
    if Arc::ptr_eq(cached, &*guard) {
        None
    } else {
        Some(arc_swap::Guard::into_inner(guard))
    }
}

#[inline]
fn refresh_worker_cos_queue_lease_runtime_counters(
    counters: &mut super::worker_runtime::WorkerRuntimeCounters,
    bindings: &[BindingWorker],
) {
    let mut calls = 0u64;
    let mut granted_bytes = 0u64;
    for binding in bindings {
        calls = calls.wrapping_add(binding.cos.cos_queue_lease_acquire_v8_calls);
        granted_bytes = granted_bytes
            .wrapping_add(binding.cos.cos_queue_lease_acquire_v8_granted_bytes);
    }
    counters.cos_queue_lease_acquire_v8_calls = calls;
    counters.cos_queue_lease_acquire_v8_granted_bytes = granted_bytes;
}

pub(crate) fn worker_loop(
    worker_id: u32,
    binding_plans: Vec<BindingPlan>,
    shared_validation: Arc<ArcSwap<ValidationState>>,
    shared_forwarding: Arc<ArcSwap<ForwardingState>>,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: SharedSessionOwnerRgIndexes,
    slow_path: Option<Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    last_resolution: Arc<Mutex<Option<PacketResolution>>>,
    commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    worker_commands_by_id: Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>>,
    stop: Arc<AtomicBool>,
    heartbeat: Arc<AtomicU64>,
    session_export_ack: Arc<AtomicU64>,
    poll_mode: crate::PollMode,
    dnat_fds: DnatTableFds,
    shared_fabrics: Arc<ArcSwap<Vec<FabricLink>>>,
    event_stream: Option<crate::event_stream::EventStreamWorkerHandle>,
    rg_epochs: Arc<[AtomicU32; MAX_RG_EPOCHS]>,
    shared_cos_owner_worker_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), u32>>>,
    shared_cos_owner_live_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<BindingLiveState>>>>,
    shared_cos_root_leases: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSRootLease>>>>,
    shared_cos_queue_leases: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>>,
    shared_cos_queue_vtime_floors: Arc<
        ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>,
    >,
    cos_status: Arc<ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>>,
    // #869: worker-runtime telemetry publish slot.  Worker writes its
    // local counters here on a ~1s cadence; coordinator reads for status.
    runtime_atomics: Arc<super::worker_runtime::WorkerRuntimeAtomics>,
) {
    pin_current_thread(worker_id);
    const COS_STATUS_INTERVAL_NS: u64 = 100_000_000;
    let ha_startup_grace_until_secs =
        (monotonic_nanos() / 1_000_000_000).saturating_add(TUNNEL_HA_STARTUP_GRACE_SECS);
    let mut validation = **shared_validation.load();
    let mut forwarding = shared_forwarding.load_full();
    let mut cos_owner_worker_by_queue = shared_cos_owner_worker_by_queue.load_full();
    let mut cos_owner_live_by_queue = shared_cos_owner_live_by_queue.load_full();
    let mut cos_shared_root_leases = shared_cos_root_leases.load_full();
    let mut cos_shared_queue_leases = shared_cos_queue_leases.load_full();
    let mut cos_shared_queue_vtime_floors = shared_cos_queue_vtime_floors.load_full();
    let mut sessions = SessionTable::new();
    let mut screen_state = ScreenState::new();
    screen_state.update_profiles(forwarding.screen_profiles.clone());
    sessions.set_timeouts(forwarding.session_timeouts);
    let mut bindings = Vec::with_capacity(binding_plans.len());
    let (private_plans, shared_groups) = partition_binding_plans(binding_plans);
    for plan in private_plans {
        let live = plan.live.clone();
        match create_private_binding_from_plan(plan) {
            Ok(binding) => bindings.push(binding),
            Err(err) => {
                eprintln!("xpf-userspace-dp: private binding creation failed: {err}");
                live.set_error(err.to_string());
            }
        }
    }
    for (group_key, plans) in shared_groups {
        let lives = plans
            .iter()
            .map(|plan| plan.live.clone())
            .collect::<Vec<_>>();
        match create_shared_binding_group(&group_key, plans) {
            Ok(mut group_bindings) => bindings.append(&mut group_bindings),
            Err(err) => {
                let msg = err.to_string();
                eprintln!("xpf-userspace-dp: {msg}");
                for live in lives {
                    live.set_error(msg.clone());
                }
            }
        }
    }
    bindings.sort_by_key(|binding| (binding.queue_id, binding.ifindex, binding.slot));
    let binding_lookup = WorkerBindingLookup::from_bindings(&bindings);
    let cos_owner_live_by_tx_ifindex = build_worker_cos_owner_live_by_tx_ifindex(
        bindings
            .iter()
            .map(|binding| (binding.ifindex, binding.live.clone())),
    );
    let cos_fast_interfaces = build_worker_cos_fast_interfaces(
        forwarding.as_ref(),
        worker_id,
        &cos_owner_live_by_tx_ifindex,
        cos_owner_worker_by_queue.as_ref(),
        cos_owner_live_by_queue.as_ref(),
        cos_shared_root_leases.as_ref(),
        cos_shared_queue_leases.as_ref(),
        cos_shared_queue_vtime_floors.as_ref(),
    );
    for binding in bindings.iter_mut() {
        binding.cos.cos_fast_interfaces = cos_fast_interfaces.clone();
    }
    let mut interrupt_poll_fds = if poll_mode == crate::PollMode::Interrupt {
        bindings
            .iter()
            .map(|binding| libc::pollfd {
                fd: binding.xsk.device.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut idle_iters = 0u32;
    let mut poll_start = 0usize;
    let mut shared_recycles = Vec::with_capacity((RX_BATCH_SIZE as usize).saturating_mul(2));
    // Debug: periodic summary counters
    let mut dbg_last_report_ns = monotonic_nanos();
    let mut dbg_rx_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_total = 0u64;
    let mut dbg_forward_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_local_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_session_hit = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_session_miss = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_session_create = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_no_route = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_missing_neigh = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_policy_deny = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_ha_inactive = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_no_egress_binding = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_build_fail = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_err = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_metadata_err = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_disposition_other = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_ok = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_inplace = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_direct = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_copy = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_from_trust = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_from_wan = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_trust_to_wan = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_wan_to_trust = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_nat_snat = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_nat_dnat = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_nat_none = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_frame_build_none = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_rst = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_tcp_rst = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_fin = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_synack = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_zero_window = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_tcp_fin = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_tcp_rst = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_tcp_zero_window = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_bytes_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_bytes_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_oversized = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_max_frame = 0u32;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_max_frame = 0u32;
    #[cfg(feature = "debug-log")]
    let mut dbg_seg_needed_but_none = 0u64;
    let mut prev_rx_total = 0u64;
    let mut prev_fwd_total = 0u64;
    let mut stall_prev_fwd = 0u64;
    let mut stall_reported = false;
    const DBG_REPORT_INTERVAL_NS: u64 = 1_000_000_000; // 1 second
    // Throttle for BPF conntrack last_seen refresh (~10s).
    // Keeps `show security flow session` idle times accurate without
    // per-second syscall overhead per session.  See issue #333.
    const CT_REFRESH_INTERVAL_NS: u64 = 10_000_000_000;
    // Cache BPF map FDs — they don't change during the worker's lifetime.
    let session_map_fd = bindings
        .first()
        .map(|binding| binding.bpf_maps.session_map_fd)
        .unwrap_or(-1);
    let conntrack_v4_fd = bindings
        .first()
        .map(|binding| binding.bpf_maps.conntrack_v4_fd)
        .unwrap_or(-1);
    let conntrack_v6_fd = bindings
        .first()
        .map(|binding| binding.bpf_maps.conntrack_v6_fd)
        .unwrap_or(-1);
    let mut last_ct_refresh_ns: u64 = 0;
    cos_status.store(Arc::new(build_worker_cos_statuses(
        &bindings,
        forwarding.as_ref(),
    )));
    let mut last_cos_status_ns = monotonic_nanos();
    // #869: worker-runtime telemetry.  Local counters, published to
    // `runtime_atomics` on the ~1s cadence below.
    use super::worker_runtime::{
        WorkerRuntimeCounters, WorkerRuntimeState, current_tid, sample_thread_cpu_ns,
    };
    let mut wr_counters = WorkerRuntimeCounters::default();
    let mut wr_state = WorkerRuntimeState::IdleBlock;
    let mut wr_last_loop_ns = monotonic_nanos();
    let mut wr_last_publish_ns = wr_last_loop_ns;
    const WR_PUBLISH_INTERVAL_NS: u64 = 1_000_000_000;
    runtime_atomics.set_tid(current_tid());
    while !stop.load(Ordering::Relaxed) {
        let loop_now_ns = monotonic_nanos();
        // #869: attribute elapsed delta to the previous loop's state.
        {
            let delta = loop_now_ns.saturating_sub(wr_last_loop_ns);
            wr_counters.wall_ns = wr_counters.wall_ns.wrapping_add(delta);
            match wr_state {
                WorkerRuntimeState::Active => {
                    wr_counters.active_ns = wr_counters.active_ns.wrapping_add(delta);
                }
                WorkerRuntimeState::IdleSpin => {
                    wr_counters.idle_spin_ns = wr_counters.idle_spin_ns.wrapping_add(delta);
                }
                WorkerRuntimeState::IdleBlock => {
                    wr_counters.idle_block_ns = wr_counters.idle_block_ns.wrapping_add(delta);
                }
            }
            wr_last_loop_ns = loop_now_ns;
            if loop_now_ns.saturating_sub(wr_last_publish_ns) >= WR_PUBLISH_INTERVAL_NS {
                // Skip on transient clock_gettime failure (sample == 0):
                // overwriting a previously-published nonzero value with 0
                // would make the Prometheus counter go backwards and
                // break `rate()` queries.
                let sampled_cpu_ns = sample_thread_cpu_ns();
                if sampled_cpu_ns != 0 {
                    wr_counters.thread_cpu_ns = sampled_cpu_ns;
                }
                refresh_worker_cos_queue_lease_runtime_counters(&mut wr_counters, &bindings);
                runtime_atomics.publish(&wr_counters);
                wr_last_publish_ns = loop_now_ns;
            }
        }
        let loop_now_secs = loop_now_ns / 1_000_000_000;
        let live_validation = shared_validation.load();
        if **live_validation != validation {
            validation = **live_validation;
        }
        let mut rebuild_cos_fast_interfaces = false;
        // #1188: per-tick Arc refresh — `.load() + Arc::ptr_eq`
        // short-circuits the unconditional `.load_full()` clone
        // when the coordinator hasn't rotated the Arc.
        if let Some(new_forwarding) =
            load_arc_if_changed(&forwarding, &shared_forwarding)
        {
            // Compare BEFORE assignment — needs both old and new.
            let cos_changed =
                cos_runtime_config_changed(forwarding.as_ref(), new_forwarding.as_ref());

            // Use NEW values for dependent state updates (forwarding-site
            // ordering — old `forwarding` is stale once rotated).
            screen_state.update_profiles(new_forwarding.screen_profiles.clone());
            sessions.set_timeouts(new_forwarding.session_timeouts);

            forwarding = new_forwarding;

            if cos_changed {
                reset_worker_cos_runtimes(&mut bindings);
                rebuild_cos_fast_interfaces = true;
            }
        }
        if let Some(new_x) =
            load_arc_if_changed(&cos_owner_worker_by_queue, &shared_cos_owner_worker_by_queue)
        {
            cos_owner_worker_by_queue = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) =
            load_arc_if_changed(&cos_owner_live_by_queue, &shared_cos_owner_live_by_queue)
        {
            cos_owner_live_by_queue = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) =
            load_arc_if_changed(&cos_shared_root_leases, &shared_cos_root_leases)
        {
            for binding in bindings.iter_mut() {
                release_all_cos_root_leases(binding);
                release_all_cos_queue_leases(binding);
            }
            cos_shared_root_leases = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) =
            load_arc_if_changed(&cos_shared_queue_leases, &shared_cos_queue_leases)
        {
            for binding in bindings.iter_mut() {
                release_all_cos_queue_leases(binding);
            }
            cos_shared_queue_leases = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) =
            load_arc_if_changed(&cos_shared_queue_vtime_floors, &shared_cos_queue_vtime_floors)
        {
            // #917: Arc-replacement of the V_min floors map.
            // Each shared_exact queue's per-worker slots default
            // to NOT_PARTICIPATING in the new Arc. Workers will
            // re-publish their committed vtime on the next
            // commit-boundary publish; until then peers reading
            // this slot see "not participating" and skip it in
            // V_min reduction (per plan §3.4 / §3.7 lifecycle
            // rules).
            cos_shared_queue_vtime_floors = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if rebuild_cos_fast_interfaces {
            let cos_owner_live_by_tx_ifindex = build_worker_cos_owner_live_by_tx_ifindex(
                bindings
                    .iter()
                    .map(|binding| (binding.ifindex, binding.live.clone())),
            );
            let cos_fast_interfaces = build_worker_cos_fast_interfaces(
                forwarding.as_ref(),
                worker_id,
                &cos_owner_live_by_tx_ifindex,
                cos_owner_worker_by_queue.as_ref(),
                cos_owner_live_by_queue.as_ref(),
                cos_shared_root_leases.as_ref(),
                cos_shared_queue_leases.as_ref(),
                cos_shared_queue_vtime_floors.as_ref(),
            );
            for binding in bindings.iter_mut() {
                binding.cos.cos_fast_interfaces = cos_fast_interfaces.clone();
            }
        }
        let ha_runtime = ha_state.load();
        // Only apply commands when pending — avoids lock overhead on
        // every loop iteration in the common (empty-queue) case.
        let has_commands = commands.try_lock().map(|q| !q.is_empty()).unwrap_or(false);
        let command_results = if has_commands {
            apply_worker_commands(
                &commands,
                &mut sessions,
                session_map_fd,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
            )
        } else {
            WorkerCommandResults {
                cancelled_keys: Vec::new(),
                exported_sequences: Vec::new(),
                shaped_tx_requests: Vec::new(),
                vacate_all_shared_exact_slots: false,
            }
        };
        let WorkerCommandResults {
            cancelled_keys,
            exported_sequences,
            shaped_tx_requests,
            vacate_all_shared_exact_slots,
        } = command_results;
        // #941 Work item C: HA-demotion vacate. The
        // VacateAllSharedExactSlots WorkerCommand cannot be processed
        // inside `apply_worker_commands` (no BindingWorker access);
        // it sets this flag and the dispatch happens here, where we
        // hold `&mut bindings`. Single-writer invariant: only this
        // worker writes its own slots.
        if vacate_all_shared_exact_slots {
            for binding in bindings.iter_mut() {
                vacate_all_shared_exact_slots_for_binding(binding);
            }
        }
        if !shaped_tx_requests.is_empty() {
            apply_worker_shaped_tx_requests(
                &mut bindings,
                forwarding.as_ref(),
                &binding_lookup,
                loop_now_ns,
                shaped_tx_requests,
            );
        }
        if !cancelled_keys.is_empty() {
            for key in &cancelled_keys {
                for binding in bindings.iter_mut() {
                    cancel_queued_flow_on_binding(binding, key, key);
                }
                if let Some((decision, metadata, origin)) = sessions.entry_with_origin(key) {
                    // Demotion keeps the session in the standby table, but the
                    // stale owner must stop advertising local XSK redirect
                    // aliases immediately or XDP will keep steering packets to
                    // the old node after RG handoff.
                    delete_session_map_redirect_for_session(
                        session_map_fd,
                        key,
                        decision,
                        &metadata,
                        origin,
                    );
                }
            }
        }
        heartbeat.store(loop_now_ns, Ordering::Relaxed);
        let expired_entries = sessions.expire_stale_entries(loop_now_ns);
        let expired = expired_entries.len() as u64;
        for expired_entry in expired_entries {
            delete_session_map_entry_for_removed_session_with_origin(
                session_map_fd,
                &expired_entry.key,
                expired_entry.decision,
                &expired_entry.metadata,
                expired_entry.origin,
                conntrack_v4_fd,
                conntrack_v6_fd,
            );
        }
        if expired > 0 {
            if let Some(binding) = bindings.first() {
                binding
                    .live
                    .session_expires
                    .fetch_add(expired, Ordering::Relaxed);
            }
        }
        // Periodically refresh last_seen in BPF conntrack entries so Go-side
        // callers of IterateSessions (CLI, gRPC, Prometheus) see accurate
        // session idle times.  Issue #333.
        if loop_now_ns.saturating_sub(last_ct_refresh_ns) >= CT_REFRESH_INTERVAL_NS {
            last_ct_refresh_ns = loop_now_ns;
            refresh_bpf_conntrack_last_seen(
                conntrack_v4_fd,
                conntrack_v6_fd,
                &sessions,
                loop_now_ns,
            );
        }
        // Check if fabric links were updated by the coordinator (e.g. after
        // RG failover when peer MAC was resolved). If so, rebuild the
        // forwarding Arc with the new fabric links so fabric redirect works.
        {
            let live_fabrics = shared_fabrics.load();
            if !live_fabrics.is_empty() && live_fabrics.as_ref() != &forwarding.fabrics {
                let mut updated = (*forwarding).clone();
                updated.fabrics = live_fabrics.as_ref().clone();
                forwarding = Arc::new(updated);
            }
        }
        let mut did_work = false;
        let mut dbg_poll = DebugPollCounters::default();
        for offset in 0..bindings.len() {
            let idx = if bindings.is_empty() {
                0
            } else {
                (poll_start + offset) % bindings.len()
            };
            if poll_binding(
                idx,
                &mut bindings,
                &binding_lookup,
                &mut sessions,
                &mut screen_state,
                validation,
                loop_now_ns,
                loop_now_secs,
                ha_startup_grace_until_secs,
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                slow_path.as_ref(),
                &local_tunnel_deliveries,
                &recent_exceptions,
                &recent_session_deltas,
                &last_resolution,
                &peer_worker_commands,
                worker_id,
                worker_commands_by_id.as_ref(),
                &mut shared_recycles,
                &dnat_fds,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &mut dbg_poll,
                &rg_epochs,
                cos_owner_worker_by_queue.as_ref(),
                cos_owner_live_by_queue.as_ref(),
            ) {
                did_work = true;
            }
        }
        crate::filter::flush_recorded_filter_counters();
        dbg_rx_total += dbg_poll.rx;
        #[cfg(feature = "debug-log")]
        {
            dbg_tx_total += dbg_poll.tx;
        }
        dbg_forward_total += dbg_poll.forward;
        #[cfg(feature = "debug-log")]
        {
            dbg_local_total += dbg_poll.local;
            dbg_session_hit += dbg_poll.session_hit;
            dbg_session_miss += dbg_poll.session_miss;
            dbg_session_create += dbg_poll.session_create;
            dbg_no_route += dbg_poll.no_route;
            dbg_missing_neigh += dbg_poll.missing_neigh;
            dbg_policy_deny += dbg_poll.policy_deny;
            dbg_ha_inactive += dbg_poll.ha_inactive;
            dbg_no_egress_binding += dbg_poll.no_egress_binding;
            dbg_build_fail += dbg_poll.build_fail;
            dbg_tx_err += dbg_poll.tx_err;
            dbg_metadata_err += dbg_poll.metadata_err;
        }
        #[cfg(feature = "debug-log")]
        {
            dbg_disposition_other += dbg_poll.disposition_other;
            dbg_enqueue_ok += dbg_poll.enqueue_ok;
            dbg_enqueue_inplace += dbg_poll.enqueue_inplace;
            dbg_enqueue_direct += dbg_poll.enqueue_direct;
            dbg_enqueue_copy += dbg_poll.enqueue_copy;
            dbg_rx_from_trust += dbg_poll.rx_from_trust;
            dbg_rx_from_wan += dbg_poll.rx_from_wan;
            dbg_fwd_trust_to_wan += dbg_poll.fwd_trust_to_wan;
            dbg_fwd_wan_to_trust += dbg_poll.fwd_wan_to_trust;
            dbg_nat_snat += dbg_poll.nat_applied_snat;
            dbg_nat_dnat += dbg_poll.nat_applied_dnat;
            dbg_nat_none += dbg_poll.nat_applied_none;
            dbg_frame_build_none += dbg_poll.frame_build_none;
        }
        #[cfg(feature = "debug-log")]
        {
            dbg_rx_tcp_rst += dbg_poll.rx_tcp_rst;
            dbg_rx_tcp_fin += dbg_poll.rx_tcp_fin;
            dbg_rx_tcp_synack += dbg_poll.rx_tcp_synack;
            dbg_rx_tcp_zero_window += dbg_poll.rx_tcp_zero_window;
            dbg_fwd_tcp_fin += dbg_poll.fwd_tcp_fin;
            dbg_fwd_tcp_rst += dbg_poll.fwd_tcp_rst;
            dbg_fwd_tcp_zero_window += dbg_poll.fwd_tcp_zero_window;
        }
        #[cfg(feature = "debug-log")]
        {
            dbg_rx_bytes_total += dbg_poll.rx_bytes_total;
            dbg_tx_bytes_total += dbg_poll.tx_bytes_total;
            dbg_rx_oversized += dbg_poll.rx_oversized;
            if dbg_poll.rx_max_frame > dbg_rx_max_frame {
                dbg_rx_max_frame = dbg_poll.rx_max_frame;
            }
            if dbg_poll.tx_max_frame > dbg_tx_max_frame {
                dbg_tx_max_frame = dbg_poll.tx_max_frame;
            }
            dbg_seg_needed_but_none += dbg_poll.seg_needed_but_none;
        }
        if !bindings.is_empty() {
            poll_start = (poll_start + 1) % bindings.len();
        }
        if loop_now_ns.saturating_sub(last_cos_status_ns) >= COS_STATUS_INTERVAL_NS {
            cos_status.store(Arc::new(build_worker_cos_statuses(
                &bindings,
                forwarding.as_ref(),
            )));
            last_cos_status_ns = loop_now_ns;
        }
        if !exported_sequences.is_empty() {
            while sessions.has_pending_deltas() {
                let deltas = sessions.drain_deltas(256);
                purge_queued_flows_for_closed_deltas(&mut bindings, &deltas);
                if let Some(binding) = bindings.first() {
                    let ident = binding.identity();
                    flush_session_deltas(
                        &ident,
                        &binding.live,
                        binding.bpf_maps.session_map_fd,
                        conntrack_v4_fd,
                        conntrack_v6_fd,
                        &deltas,
                        &shared_sessions,
                        &shared_nat_sessions,
                        &shared_forward_wire_sessions,
                        &shared_owner_rg_indexes,
                        &recent_session_deltas,
                        &peer_worker_commands,
                        &event_stream,
                        forwarding.as_ref(),
                    );
                }
            }
            if let Some(sequence) = exported_sequences.iter().copied().max() {
                session_export_ack.store(sequence, Ordering::Release);
            }
        } else if sessions.has_pending_deltas() {
            let deltas = sessions.drain_deltas(256);
            purge_queued_flows_for_closed_deltas(&mut bindings, &deltas);
            if let Some(binding) = bindings.first() {
                let ident = binding.identity();
                flush_session_deltas(
                    &ident,
                    &binding.live,
                    binding.bpf_maps.session_map_fd,
                    conntrack_v4_fd,
                    conntrack_v6_fd,
                    &deltas,
                    &shared_sessions,
                    &shared_nat_sessions,
                    &shared_forward_wire_sessions,
                    &shared_owner_rg_indexes,
                    &recent_session_deltas,
                    &peer_worker_commands,
                    &event_stream,
                    forwarding.as_ref(),
                );
            }
        }
        // Debug: periodic summary report
        {
            let elapsed = loop_now_ns.saturating_sub(dbg_last_report_ns);
            if elapsed >= DBG_REPORT_INTERVAL_NS {
                #[cfg(feature = "debug-log")]
                let secs = elapsed as f64 / 1_000_000_000.0;
                let session_count = sessions.len();
                let mut binding_summary = String::new();
                for (i, b) in bindings.iter().enumerate() {
                    use std::fmt::Write;
                    let fill_pending = b.xsk.device.pending();
                    let rx_avail = b.xsk.rx.available_relaxed();
                    let xsk_stats = b.xsk.device.statistics_v2().ok();
                    let inflight_recycles = b.tx_pipeline.in_flight_prepared_recycles.len() as u32;
                    let scratch_recycle_len = b.scratch.scratch_recycle.len() as u32;
                    let ptx_prepared = b.tx_pipeline.pending_tx_prepared.len() as u32;
                    let ptx_local = b.tx_pipeline.pending_tx_local.len() as u32;
                    let total_accounted = b.tx_pipeline.pending_fill_frames.len() as u32
                        + fill_pending
                        + rx_avail
                        + b.tx_pipeline.free_tx_frames.len() as u32
                        + b.tx_pipeline.outstanding_tx
                        + inflight_recycles
                        + scratch_recycle_len
                        + ptx_prepared; // prepared TX holds UMEM frames
                    let expected_total = b.umem.total_frames();
                    let _ = write!(
                        binding_summary,
                        " [{}:if{}q{} pfill={} fring={} rxring={} free_tx={} otx={} ifl={} scr={} ptxp={} ptxl={} total={}/{} fill_ok={} polls={} bp={} rx_empty={} wake={}",
                        i,
                        b.ifindex,
                        b.queue_id,
                        b.tx_pipeline.pending_fill_frames.len(),
                        fill_pending,
                        rx_avail,
                        b.tx_pipeline.free_tx_frames.len(),
                        b.tx_pipeline.outstanding_tx,
                        inflight_recycles,
                        scratch_recycle_len,
                        ptx_prepared,
                        ptx_local,
                        total_accounted,
                        expected_total,
                        b.telemetry.dbg_fill_submitted,
                        b.telemetry.dbg_poll_cycles,
                        b.telemetry.dbg_backpressure,
                        b.telemetry.dbg_rx_empty,
                        b.telemetry.dbg_rx_wakeups,
                    );
                    // TX pipeline debug counters
                    #[cfg(feature = "debug-log")]
                    {
                        dbg_tx_tcp_rst += b.telemetry.dbg_tx_tcp_rst;
                    }
                    let _ = write!(
                        binding_summary,
                        " TX:ring_sub={}/ring_full={}/compl={}/sendto={}/err={}/eagain={}/enobufs={}/bp_overflow={}/cos_overflow={}",
                        b.telemetry.dbg_tx_ring_submitted,
                        b.telemetry.dbg_tx_ring_full,
                        b.telemetry.dbg_completions_reaped,
                        b.telemetry.dbg_sendto_calls,
                        b.telemetry.dbg_sendto_err,
                        b.telemetry.dbg_sendto_eagain,
                        b.telemetry.dbg_sendto_enobufs,
                        b.telemetry.dbg_bound_pending_overflow,
                        b.telemetry.dbg_cos_queue_overflow,
                    );
                    #[cfg(feature = "debug-log")]
                    let _ = write!(binding_summary, "/rst={}", b.telemetry.dbg_tx_tcp_rst);
                    if let Some(s) = xsk_stats {
                        let _ = write!(
                            binding_summary,
                            " xsk:drop={}/inv={}/rfull={}/fempty={}/tinv={}/tempty={}",
                            s.rx_dropped,
                            s.rx_invalid_descs,
                            s.rx_ring_full,
                            s.rx_fill_ring_empty_descs,
                            s.tx_invalid_descs,
                            s.tx_ring_empty_descs,
                        );
                    }
                    // Socket error check (SO_ERROR) — detect kernel-side errors
                    {
                        let fd = b.xsk.rx.as_raw_fd();
                        let mut so_err: c_int = 0;
                        let mut so_err_len: libc::socklen_t = core::mem::size_of::<c_int>() as _;
                        let rc = unsafe {
                            libc::getsockopt(
                                fd,
                                libc::SOL_SOCKET,
                                libc::SO_ERROR,
                                &mut so_err as *mut c_int as *mut c_void,
                                &mut so_err_len,
                            )
                        };
                        if rc == 0 && so_err != 0 {
                            let _ = write!(binding_summary, " SO_ERR={so_err}");
                        }
                    }
                    // Ring diagnostics from xsk_ffi API
                    if cfg!(feature = "debug-log") {
                        let _ = write!(
                            binding_summary,
                            " RING:rx_nz={}/rx_max={}/fill_pend={}/dev_avail={} RX_WAKE:ok={}/err={}/errno={}",
                            b.telemetry.dbg_rx_avail_nonzero,
                            b.telemetry.dbg_rx_avail_max,
                            b.telemetry.dbg_fill_pending,
                            b.telemetry.dbg_device_avail,
                            b.telemetry.dbg_rx_wake_sendto_ok,
                            b.telemetry.dbg_rx_wake_sendto_err,
                            b.telemetry.dbg_rx_wake_sendto_errno,
                        );
                        // Direct mmap diagnosis: read raw ring producer/consumer
                        if let Some((rxp, rxc, frp, frc, txp, txc, crp, crc)) =
                            diagnose_raw_ring_state(b.xsk.rx.as_raw_fd())
                        {
                            let _ = write!(
                                binding_summary,
                                " RAW:rxP={rxp}/rxC={rxc}/frP={frp}/frC={frc}/txP={txp}/txC={txc}/crP={crp}/crC={crc}"
                            );
                        }
                    }
                    // Frame leak detection
                    if total_accounted != expected_total {
                        let _ = write!(
                            binding_summary,
                            " FRAME_LEAK:{}",
                            expected_total as i64 - total_accounted as i64,
                        );
                    }
                    binding_summary.push(']');
                }
                #[cfg(feature = "debug-log")]
                eprintln!(
                    "DBG w{}: {:.1}s rx={} tx={} fwd={} local={} sess_hit={} sess_miss={} sess_create={} \
                     no_route={} miss_neigh={} pol_deny={} ha_inact={} no_egress={} build_fail={} \
                     tx_err={} meta_err={} other={} enq_ok={} enq_ip={} enq_dir={} enq_cp={} sessions={} \
                     DIR:trust_rx={}/wan_rx={}/t2w={}/w2t={} NAT:snat={}/dnat={}/none={}/bld_none={} RST:rx={}/tx={} \
                     SIZE:rx_avg={}/rx_max={}/tx_avg={}/tx_max={}/rx_over={}/seg_miss={} \
                     TCP_RX:fin={}/synack={}/zwin={} TCP_FWD:fin={}/rst={}/zwin={} \
                     CSUM:verified={}/bad_ip={}/bad_l4={} \
                     SESS_BPF:verify_ok={}/verify_fail={}/bpf_entries={} bindings:{}",
                    worker_id,
                    secs,
                    dbg_rx_total,
                    dbg_tx_total,
                    dbg_forward_total,
                    dbg_local_total,
                    dbg_session_hit,
                    dbg_session_miss,
                    dbg_session_create,
                    dbg_no_route,
                    dbg_missing_neigh,
                    dbg_policy_deny,
                    dbg_ha_inactive,
                    dbg_no_egress_binding,
                    dbg_build_fail,
                    dbg_tx_err,
                    dbg_metadata_err,
                    dbg_disposition_other,
                    dbg_enqueue_ok,
                    dbg_enqueue_inplace,
                    dbg_enqueue_direct,
                    dbg_enqueue_copy,
                    session_count,
                    dbg_rx_from_trust,
                    dbg_rx_from_wan,
                    dbg_fwd_trust_to_wan,
                    dbg_fwd_wan_to_trust,
                    dbg_nat_snat,
                    dbg_nat_dnat,
                    dbg_nat_none,
                    dbg_frame_build_none,
                    dbg_rx_tcp_rst,
                    dbg_tx_tcp_rst,
                    if dbg_rx_total > 0 {
                        dbg_rx_bytes_total / dbg_rx_total
                    } else {
                        0
                    },
                    dbg_rx_max_frame,
                    if dbg_enqueue_ok > 0 {
                        dbg_tx_bytes_total / dbg_enqueue_ok
                    } else {
                        0
                    },
                    dbg_tx_max_frame,
                    dbg_rx_oversized,
                    dbg_seg_needed_but_none,
                    dbg_rx_tcp_fin,
                    dbg_rx_tcp_synack,
                    dbg_rx_tcp_zero_window,
                    dbg_fwd_tcp_fin,
                    dbg_fwd_tcp_rst,
                    dbg_fwd_tcp_zero_window,
                    CSUM_VERIFIED_TOTAL.swap(0, Ordering::Relaxed),
                    CSUM_BAD_IP_TOTAL.swap(0, Ordering::Relaxed),
                    CSUM_BAD_L4_TOTAL.swap(0, Ordering::Relaxed),
                    SESSION_PUBLISH_VERIFY_OK.swap(0, Ordering::Relaxed),
                    SESSION_PUBLISH_VERIFY_FAIL.swap(0, Ordering::Relaxed),
                    if let Some(b) = bindings.first() {
                        count_bpf_session_entries(b.bpf_maps.session_map_fd)
                    } else {
                        0
                    },
                    binding_summary,
                );
                // Non-debug builds: no per-second stats dump (use debug-log feature for verbose output).
                // Print XDP shim fallback stats — tells us WHY packets stop
                // being redirected to XSK.
                if cfg!(feature = "debug-log") {
                    if let Some(stats) = read_fallback_stats() {
                        if !stats.is_empty() {
                            let s: Vec<String> =
                                stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
                            eprintln!("DBG w{}: XDP_FALLBACK: {}", worker_id, s.join(" "));
                        }
                    }
                }
                // Save prev counters BEFORE reset for stall detection below
                if cfg!(feature = "debug-log") {
                    prev_rx_total = dbg_rx_total;
                    prev_fwd_total = dbg_forward_total;
                }
                dbg_last_report_ns = loop_now_ns;
                dbg_rx_total = 0;
                #[cfg(feature = "debug-log")]
                {
                    dbg_tx_total = 0;
                }
                dbg_forward_total = 0;
                #[cfg(feature = "debug-log")]
                {
                    dbg_local_total = 0;
                    dbg_session_hit = 0;
                    dbg_session_miss = 0;
                    dbg_session_create = 0;
                    dbg_no_route = 0;
                    dbg_missing_neigh = 0;
                    dbg_policy_deny = 0;
                    dbg_ha_inactive = 0;
                    dbg_no_egress_binding = 0;
                    dbg_build_fail = 0;
                    dbg_tx_err = 0;
                    dbg_metadata_err = 0;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_disposition_other = 0;
                    dbg_enqueue_ok = 0;
                    dbg_enqueue_inplace = 0;
                    dbg_enqueue_direct = 0;
                    dbg_enqueue_copy = 0;
                    dbg_rx_from_trust = 0;
                    dbg_rx_from_wan = 0;
                    dbg_fwd_trust_to_wan = 0;
                    dbg_fwd_wan_to_trust = 0;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_rx_bytes_total = 0;
                    dbg_tx_bytes_total = 0;
                    dbg_rx_oversized = 0;
                    dbg_rx_max_frame = 0;
                    dbg_tx_max_frame = 0;
                    dbg_seg_needed_but_none = 0;
                }
                // Stall detection: stall_prev_fwd is PREVIOUS interval's fwd count,
                // prev_fwd_total is THIS interval's fwd count (saved before reset).
                if cfg!(feature = "debug-log") {
                    if stall_prev_fwd > 10 && prev_fwd_total == 0 && !stall_reported {
                        stall_reported = true;
                        eprintln!(
                            "DBG STALL_DETECTED: w{} two_ago_fwd={} this_interval_fwd={} this_interval_rx={} sessions={}",
                            worker_id, stall_prev_fwd, prev_fwd_total, prev_rx_total, session_count
                        );
                        // Dump comprehensive per-binding state at stall moment
                        for (si, sb) in bindings.iter().enumerate() {
                            use std::fmt::Write;
                            let fill_p = sb.xsk.device.pending();
                            let rx_a = sb.xsk.rx.available_relaxed();
                            let ifl = sb.tx_pipeline.in_flight_prepared_recycles.len() as u32;
                            let ptxp = sb.tx_pipeline.pending_tx_prepared.len() as u32;
                            let ptxl = sb.tx_pipeline.pending_tx_local.len() as u32;
                            let total = sb.tx_pipeline.pending_fill_frames.len() as u32
                                + fill_p
                                + rx_a
                                + sb.tx_pipeline.free_tx_frames.len() as u32
                                + sb.tx_pipeline.outstanding_tx
                                + ifl
                                + sb.scratch.scratch_recycle.len() as u32
                                + ptxp;
                            let raw = diagnose_raw_ring_state(sb.xsk.rx.as_raw_fd());
                            let mut stall_line = format!(
                                "DBG STALL_BINDING[{}]: if={} q={} pfill={} fring={} rxring={} free_tx={} otx={} ifl={} ptxp={} ptxl={} total={}/{}",
                                si,
                                sb.ifindex,
                                sb.queue_id,
                                sb.tx_pipeline.pending_fill_frames.len(),
                                fill_p,
                                rx_a,
                                sb.tx_pipeline.free_tx_frames.len(),
                                sb.tx_pipeline.outstanding_tx,
                                ifl,
                                ptxp,
                                ptxl,
                                total,
                                sb.umem.total_frames(),
                            );
                            if let Some((rxp, rxc, frp, frc, txp, txc, crp, crc)) = raw {
                                let _ = write!(
                                    stall_line,
                                    " RAW:rxP={rxp}/rxC={rxc}/frP={frp}/frC={frc}/txP={txp}/txC={txc}/crP={crp}/crC={crc}"
                                );
                            }
                            if let Ok(Some(stats)) = sb.xsk.device.statistics_v2().map(Some) {
                                let _ = write!(
                                    stall_line,
                                    " xsk:drop={}/rfull={}/fempty={}/tempty={}",
                                    stats.rx_dropped,
                                    stats.rx_ring_full,
                                    stats.rx_fill_ring_empty_descs,
                                    stats.tx_ring_empty_descs
                                );
                            }
                            eprintln!("{stall_line}");
                        }
                        // Dump all session keys for this worker
                        let mut sess_dump = String::new();
                        let mut count = 0;
                        sessions.iter_with_origin(|key, decision, metadata, origin| {
                            if count < 20 {
                                use std::fmt::Write;
                                let _ = write!(
                                    sess_dump,
                                    "\n  SESS: {}:{} -> {}:{} proto={} nat=({:?},{:?}) is_rev={} origin={}",
                                    key.src_ip,
                                    key.src_port,
                                    key.dst_ip,
                                    key.dst_port,
                                    key.protocol,
                                    decision.nat.rewrite_src,
                                    decision.nat.rewrite_dst,
                                    metadata.is_reverse,
                                    origin.as_str(),
                                );
                                count += 1;
                            }
                        });
                        if !sess_dump.is_empty() {
                            eprintln!("DBG STALL_SESSIONS:{sess_dump}");
                        }
                        // Dump fallback stats at stall time
                        if let Some(stats) = read_fallback_stats() {
                            if !stats.is_empty() {
                                let s: Vec<String> =
                                    stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
                                eprintln!("DBG STALL_FALLBACK: {}", s.join(" "));
                            }
                        }
                        // Also dump BPF session count
                        if let Some(b) = bindings.first() {
                            eprintln!(
                                "DBG STALL_BPF_SESSIONS: entries={}",
                                count_bpf_session_entries(b.bpf_maps.session_map_fd)
                            );
                        }
                    } else if prev_fwd_total > 0 {
                        stall_reported = false;
                    }
                    stall_prev_fwd = prev_fwd_total;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_nat_snat = 0;
                    dbg_nat_dnat = 0;
                    dbg_nat_none = 0;
                    dbg_frame_build_none = 0;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_rx_tcp_rst = 0;
                    dbg_tx_tcp_rst = 0;
                    dbg_rx_tcp_fin = 0;
                    dbg_rx_tcp_synack = 0;
                    dbg_rx_tcp_zero_window = 0;
                    dbg_fwd_tcp_fin = 0;
                    dbg_fwd_tcp_rst = 0;
                    dbg_fwd_tcp_zero_window = 0;
                }
                for b in bindings.iter_mut() {
                    // #802: publish ring-pressure counters into BindingLiveState
                    // BEFORE resetting the worker-local window. The worker-local
                    // counters (b.telemetry.dbg_tx_ring_full, etc.) are accumulated by the
                    // hot path and reset each ~1s debug tick; without this
                    // publish they'd never be visible outside the worker thread.
                    // fetch_add is used because the atomic holds the cumulative
                    // total while the local counter holds only the current
                    // window. Relaxed is sufficient — diagnostic counters, no
                    // synchronization contract.
                    if b.telemetry.dbg_tx_ring_full != 0 {
                        b.live
                            .dbg_tx_ring_full
                            .fetch_add(b.telemetry.dbg_tx_ring_full, Ordering::Relaxed);
                    }
                    if b.telemetry.dbg_sendto_enobufs != 0 {
                        b.live
                            .dbg_sendto_enobufs
                            .fetch_add(b.telemetry.dbg_sendto_enobufs, Ordering::Relaxed);
                    }
                    if b.telemetry.dbg_bound_pending_overflow != 0 {
                        b.live
                            .dbg_bound_pending_overflow
                            .fetch_add(b.telemetry.dbg_bound_pending_overflow, Ordering::Relaxed);
                    }
                    if b.telemetry.dbg_cos_queue_overflow != 0 {
                        b.live
                            .dbg_cos_queue_overflow
                            .fetch_add(b.telemetry.dbg_cos_queue_overflow, Ordering::Relaxed);
                    }
                    // #802: kernel xdp_statistics.rx_fill_ring_empty_descs is
                    // already absolute (kernel-cumulative), so publish with
                    // store() not fetch_add. Sampling failures are silently
                    // ignored — the atomic simply retains its last good value.
                    if let Ok(stats) = b.xsk.device.statistics_v2() {
                        b.live
                            .rx_fill_ring_empty_descs
                            .store(stats.rx_fill_ring_empty_descs, Ordering::Relaxed);
                    }
                    // #802: outstanding_tx is a transient gauge on
                    // BindingWorker.tx_pipeline (current in-flight TX).
                    // Publish to the existing atomic mirror on
                    // BindingLiveState so the snapshot reader sees a
                    // recent value. store() because it's a gauge, not a
                    // counter. (#959 Phase 10 moved the field from
                    // BindingWorker to WorkerTxPipeline.)
                    b.live
                        .debug_outstanding_tx
                        .store(b.tx_pipeline.outstanding_tx, Ordering::Relaxed);
                    publish_tx_completion_ring_telemetry(&b.live, &mut b.telemetry);
                    // #878: publish UMEM in-flight gauge as a single atomic
                    // so the daemon's `show chassis forwarding` Buffer% can
                    // divide by `umem_total_frames` without torn-load risk.
                    // Computed in this thread from worker-local state, so
                    // the inputs are mutually consistent at sample time.
                    //
                    // "Idle" frames are: free_tx_frames (worker's TX-available
                    // pool), pending_fill_frames (worker's queue waiting to
                    // push to the kernel's fill ring), AND fill_pending (the
                    // kernel's fill ring itself, which holds frames the
                    // kernel can place RX data into — those are NOT in
                    // flight). Without subtracting fill_pending the gauge
                    // reads ~70-80% at idle because AF_XDP keeps the fill
                    // ring pre-populated by design.
                    let total = b.umem.total_frames();
                    let free_tx = b.tx_pipeline.free_tx_frames.len() as u32;
                    let pending_fill = b.tx_pipeline.pending_fill_frames.len() as u32;
                    let kernel_fill = b.xsk.device.pending();
                    let inflight = total
                        .saturating_sub(free_tx)
                        .saturating_sub(pending_fill)
                        .saturating_sub(kernel_fill);
                    b.live
                        .umem_inflight_frames
                        .store(inflight, Ordering::Relaxed);

                    b.telemetry.dbg_fill_submitted = 0;
                    b.telemetry.dbg_fill_failed = 0;
                    b.telemetry.dbg_poll_cycles = 0;
                    b.telemetry.dbg_backpressure = 0;
                    b.telemetry.dbg_rx_empty = 0;
                    b.telemetry.dbg_rx_wakeups = 0;
                    b.telemetry.dbg_tx_ring_submitted = 0;
                    b.telemetry.dbg_tx_ring_full = 0;
                    b.telemetry.dbg_completions_reaped = 0;
                    b.telemetry.dbg_sendto_calls = 0;
                    b.telemetry.dbg_sendto_err = 0;
                    b.telemetry.dbg_sendto_eagain = 0;
                    b.telemetry.dbg_sendto_enobufs = 0;
                    b.telemetry.dbg_bound_pending_overflow = 0;
                    b.telemetry.dbg_cos_queue_overflow = 0;
                    #[cfg(feature = "debug-log")]
                    {
                        b.telemetry.dbg_tx_tcp_rst = 0;
                    }
                    b.telemetry.dbg_rx_avail_nonzero = 0;
                    b.telemetry.dbg_rx_avail_max = 0;
                    b.telemetry.dbg_rx_wake_sendto_ok = 0;
                    b.telemetry.dbg_rx_wake_sendto_err = 0;
                    b.telemetry.dbg_rx_wake_sendto_errno = 0;
                }
            }
        }
        if did_work {
            idle_iters = 0;
            // #869: classify this iteration for next-loop-top accounting.
            wr_state = WorkerRuntimeState::Active;
            wr_counters.work_loops = wr_counters.work_loops.wrapping_add(1);
            continue;
        }
        idle_iters = idle_iters.saturating_add(1);
        wr_counters.idle_loops = wr_counters.idle_loops.wrapping_add(1);
        match poll_mode {
            crate::PollMode::BusyPoll => {
                if idle_iters <= IDLE_SPIN_ITERS {
                    wr_state = WorkerRuntimeState::IdleSpin;
                    std::hint::spin_loop();
                } else {
                    wr_state = WorkerRuntimeState::IdleBlock;
                    thread::sleep(Duration::from_micros(IDLE_SLEEP_US));
                }
            }
            crate::PollMode::Interrupt => {
                // Interrupt mode still needs a short local spin before blocking.
                // Firewall-local TCP flows are ACK-latency-sensitive; blocking
                // immediately on the first empty poll collapses cwnd badly.
                if idle_iters <= IDLE_SPIN_ITERS {
                    wr_state = WorkerRuntimeState::IdleSpin;
                    std::hint::spin_loop();
                } else if !interrupt_poll_fds.is_empty() {
                    wr_state = WorkerRuntimeState::IdleBlock;
                    for pfd in &mut interrupt_poll_fds {
                        pfd.revents = 0;
                    }
                    unsafe {
                        libc::poll(
                            interrupt_poll_fds.as_mut_ptr(),
                            interrupt_poll_fds.len() as libc::nfds_t,
                            INTERRUPT_POLL_TIMEOUT_MS,
                        );
                    }
                } else {
                    wr_state = WorkerRuntimeState::IdleBlock;
                    thread::sleep(Duration::from_millis(INTERRUPT_POLL_TIMEOUT_MS as u64));
                }
            }
        }
    }
    crate::filter::flush_recorded_filter_counters();
    for binding in bindings.iter_mut() {
        release_all_cos_root_leases(binding);
        release_all_cos_queue_leases(binding);
    }
    cos_status.store(Arc::new(build_worker_cos_statuses(
        &bindings,
        forwarding.as_ref(),
    )));
    heartbeat.store(monotonic_nanos(), Ordering::Relaxed);
}

fn apply_worker_shaped_tx_requests(
    bindings: &mut [BindingWorker],
    forwarding: &ForwardingState,
    binding_lookup: &WorkerBindingLookup,
    now_ns: u64,
    requests: Vec<TxRequest>,
) {
    for req in requests {
        let binding_index = bindings
            .first()
            .and_then(|binding| binding.cos.cos_fast_interfaces.get(&req.egress_ifindex))
            .and_then(|iface_fast| {
                binding_lookup
                    .first_by_if
                    .get(&iface_fast.tx_ifindex)
                    .copied()
            })
            .or_else(|| {
                let tx_ifindex = resolve_tx_binding_ifindex(forwarding, req.egress_ifindex);
                binding_lookup.first_by_if.get(&tx_ifindex).copied()
            });
        let Some(binding) = binding_index.and_then(|idx| bindings.get_mut(idx)) else {
            if let Some(binding) = bindings.first_mut() {
                binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                // #710: dedicated counter — a cross-worker shaped TX
                // request arrived for an egress this worker has no
                // binding to drain. Subset of tx_errors.
                binding
                    .live
                    .no_owner_binding_drops
                    .fetch_add(1, Ordering::Relaxed);
            }
            if cfg!(feature = "debug-log") {
                debug_log!(
                    "DBG COS_OWNER_MISSING_BINDING: egress_ifindex={}",
                    req.egress_ifindex,
                );
            }
            continue;
        };
        match enqueue_local_into_cos(binding, forwarding, req, now_ns) {
            Ok(()) => {}
            Err(req) => {
                binding.tx_pipeline.pending_tx_local.push_back(req);
                bound_pending_tx_local(binding);
            }
        }
    }
}

pub(crate) fn push_recent_exception(
    recent_exceptions: &mut VecDeque<ExceptionStatus>,
    exception: ExceptionStatus,
) {
    if recent_exceptions.len() >= MAX_RECENT_EXCEPTIONS {
        recent_exceptions.pop_front();
    }
    recent_exceptions.push_back(exception);
}

pub(crate) fn push_recent_session_delta(
    recent_session_deltas: &mut VecDeque<SessionDeltaInfo>,
    delta: SessionDeltaInfo,
) {
    if recent_session_deltas.len() >= MAX_RECENT_SESSION_DELTAS {
        recent_session_deltas.pop_front();
    }
    recent_session_deltas.push_back(delta);
}

fn publish_tx_completion_ring_telemetry(
    live: &BindingLiveState,
    telemetry: &mut WorkerTelemetry,
) {
    // #1241: publish owner-local AF_XDP TX completion-ring availability
    // samples on the same low-frequency debug cadence as the existing
    // ring-pressure gauges. These are gauges, not counters: current is
    // the last sampled CQ depth before a reap, max is the peak in this
    // debug window. Reset happens only after both stores so current and
    // max are published from the same telemetry window; a future reorder
    // must not clear either local sample before both live gauges are
    // updated.
    live.tx_completion_ring_available.store(
        telemetry.dbg_tx_completion_ring_available,
        Ordering::Relaxed,
    );
    live.tx_completion_ring_available_max.store(
        telemetry.dbg_tx_completion_ring_available_max,
        Ordering::Relaxed,
    );
    telemetry.dbg_tx_completion_ring_available = 0;
    telemetry.dbg_tx_completion_ring_available_max = 0;
}

pub(crate) struct BindingLiveSnapshot {
    pub(crate) bound: bool,
    pub(crate) xsk_registered: bool,
    pub(crate) xsk_bind_mode: String,
    pub(crate) zero_copy: bool,
    pub(crate) socket_fd: c_int,
    pub(crate) socket_ifindex: i32,
    pub(crate) socket_queue_id: u32,
    pub(crate) socket_bind_flags: u32,
    pub(crate) rx_packets: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) rx_batches: u64,
    pub(crate) rx_wakeups: u64,
    pub(crate) metadata_packets: u64,
    pub(crate) metadata_errors: u64,
    pub(crate) validated_packets: u64,
    pub(crate) validated_bytes: u64,
    pub(crate) local_delivery_packets: u64,
    pub(crate) forward_candidate_packets: u64,
    pub(crate) route_miss_packets: u64,
    pub(crate) neighbor_miss_packets: u64,
    pub(crate) discard_route_packets: u64,
    pub(crate) next_table_packets: u64,
    pub(crate) exception_packets: u64,
    pub(crate) config_gen_mismatches: u64,
    pub(crate) fib_gen_mismatches: u64,
    pub(crate) unsupported_packets: u64,
    pub(crate) flow_cache_hits: u64,
    pub(crate) flow_cache_misses: u64,
    pub(crate) flow_cache_evictions: u64,
    pub(crate) flow_cache_collision_evictions: u64,
    /// #1219: snapshot count of distinct active flows on this binding's
    /// flow_cache (refreshed at the ~65ms debug-state tick).
    pub(crate) active_flow_count: u32,
    /// #941 Work item D: count of V_min hard-cap activations on this
    /// binding (per `update_binding_debug_state` flush of each queue's
    /// scratch counter). Acceptance gate: under normal load, the
    /// override-rate (this / `drain_invocations` aggregated across
    /// queues) stays below 5 %.
    pub(crate) v_min_throttle_hard_cap_overrides: u64,
    /// #943: regular V_min throttle decisions on this binding (i.e.
    /// `cos_queue_v_min_continue` returned `false` and the drain
    /// loop early-broke). Counted distinctly from hard-cap overrides
    /// so operators can tell the fairness brake is engaged from the
    /// escape-hatch firing.
    pub(crate) v_min_throttles: u64,
    pub(crate) session_hits: u64,
    pub(crate) session_misses: u64,
    pub(crate) session_creates: u64,
    pub(crate) session_expires: u64,
    pub(crate) session_delta_pending: u64,
    pub(crate) session_delta_generated: u64,
    pub(crate) session_delta_dropped: u64,
    pub(crate) session_delta_drained: u64,
    pub(crate) policy_denied_packets: u64,
    pub(crate) screen_drops: u64,
    pub(crate) snat_packets: u64,
    pub(crate) dnat_packets: u64,
    pub(crate) slow_path_packets: u64,
    pub(crate) slow_path_bytes: u64,
    pub(crate) slow_path_local_delivery_packets: u64,
    pub(crate) slow_path_missing_neighbor_packets: u64,
    pub(crate) slow_path_no_route_packets: u64,
    pub(crate) slow_path_next_table_packets: u64,
    pub(crate) slow_path_forward_build_packets: u64,
    pub(crate) slow_path_drops: u64,
    pub(crate) slow_path_rate_limited: u64,
    pub(crate) kernel_rx_dropped: u64,
    pub(crate) kernel_rx_invalid_descs: u64,
    pub(crate) tx_packets: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) tx_completions: u64,
    pub(crate) tx_errors: u64,
    pub(crate) redirect_inbox_overflow_drops: u64,
    pub(crate) pending_tx_local_overflow_drops: u64,
    pub(crate) tx_submit_error_drops: u64,
    // #760 triage: surfaced on BindingStatus so operators can
    // compare binding-level vs per-queue drain accounting.
    pub(crate) post_drain_backup_bytes: u64,
    pub(crate) drain_sent_bytes_shaped_unconditional: u64,
    // #760 (PR #773): drop-filter counters for CoS-bound items
    // that reached the post-CoS backup paths. Non-zero indicates
    // a cross-worker routing failure the bounded ingest-drain
    // loop did not absorb.
    pub(crate) post_drain_backup_cos_drops: u64,
    pub(crate) post_drain_backup_cos_drop_bytes: u64,
    // #710: `no_owner_binding_drops` is intentionally NOT snapshotted
    // per-binding. The atomic on `BindingLiveState` accumulates drops
    // for mechanical accounting (the increment site can only write to
    // `bindings.first_mut()`), but the operator-facing aggregate lives
    // at `ProcessStatus::cos_no_owner_binding_drops_total`, summed
    // across every live state by
    // `Coordinator::cos_no_owner_binding_drops_total()`.
    pub(crate) direct_tx_packets: u64,
    pub(crate) copy_tx_packets: u64,
    pub(crate) in_place_tx_packets: u64,
    pub(crate) direct_tx_no_frame_fallback_packets: u64,
    pub(crate) direct_tx_build_fallback_packets: u64,
    pub(crate) direct_tx_disallowed_fallback_packets: u64,
    pub(crate) debug_pending_fill_frames: u32,
    #[allow(dead_code)]
    pub(crate) debug_spare_fill_frames: u32,
    pub(crate) debug_free_tx_frames: u32,
    pub(crate) debug_pending_tx_prepared: u32,
    pub(crate) debug_pending_tx_local: u32,
    pub(crate) debug_outstanding_tx: u32,
    /// #1241: last sampled AF_XDP TX completion-ring availability
    /// before the owner worker drained completions.
    pub(crate) tx_completion_ring_available: u32,
    /// #1241: maximum sampled completion-ring availability in the
    /// last debug window.
    pub(crate) tx_completion_ring_available_max: u32,
    pub(crate) debug_in_flight_recycles: u32,
    /// #878: per-binding UMEM total frames (set once at worker
    /// construction). Used as the denominator for the `show chassis
    /// forwarding` Buffer% display; numerator comes from
    /// `umem_inflight_frames` published once per second by the
    /// owning worker.
    pub(crate) umem_total_frames: u32,
    /// #878: configured TX-ring depth (set once at worker
    /// construction). `outstanding_tx / tx_ring_capacity` is the
    /// second pressure signal aggregated by Buffer%.
    pub(crate) tx_ring_capacity: u32,
    /// #878: UMEM in-flight gauge published in a single store from
    /// the worker's per-second debug tick — no torn-load risk on
    /// the read side.
    pub(crate) umem_inflight_frames: u32,
    // #802: ring-pressure snapshot fields. Mirrored from BindingLiveState
    // atomics that are published by the worker's per-second debug tick.
    pub(crate) dbg_tx_ring_full: u64,
    pub(crate) dbg_sendto_enobufs: u64,
    // #802/#804: split — see `BindingLiveState` for write-site semantics.
    pub(crate) dbg_bound_pending_overflow: u64,
    pub(crate) dbg_cos_queue_overflow: u64,
    pub(crate) rx_fill_ring_empty_descs: u64,
    pub(crate) last_heartbeat: Option<chrono::DateTime<Utc>>,
    pub(crate) last_error: String,
    // #709: owner-profile telemetry snapshot. Fixed-size arrays (no
    // `Vec`) to keep the snapshot allocation-free on the hot path;
    // readers that want a `Vec` for JSON can copy on demand.
    pub(crate) drain_latency_hist: [u64; DRAIN_HIST_BUCKETS],
    pub(crate) drain_invocations: u64,
    pub(crate) drain_noop_invocations: u64,
    pub(crate) redirect_acquire_hist: [u64; DRAIN_HIST_BUCKETS],
    pub(crate) owner_pps: u64,
    pub(crate) peer_pps: u64,
    /// #812: per-queue TX submit→completion latency histogram +
    /// count + sum-ns. Fixed-size array (same pattern as
    /// `drain_latency_hist`). The array is materialized into a
    /// `Vec<u64>` only at the JSON/protocol boundary; the snapshot
    /// itself stays allocation-free.
    pub(crate) tx_submit_latency_hist: [u64; TX_SUBMIT_LAT_BUCKETS],
    pub(crate) tx_submit_latency_count: u64,
    pub(crate) tx_submit_latency_sum_ns: u64,
    /// #825: per-kick `sendto` latency histogram + count +
    /// sum-ns + EAGAIN-retry count. Fixed-size array matches
    /// `tx_submit_latency_hist`; materialized into a `Vec<u64>`
    /// at the JSON/protocol boundary, the snapshot itself stays
    /// allocation-free.
    pub(crate) tx_kick_latency_hist: [u64; TX_SUBMIT_LAT_BUCKETS],
    pub(crate) tx_kick_latency_count: u64,
    pub(crate) tx_kick_latency_sum_ns: u64,
    pub(crate) tx_kick_retry_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_tx_completion_ring_telemetry_stores_before_reset() {
        let live = BindingLiveState::new();
        let mut telemetry = WorkerTelemetry {
            dbg_tx_completion_ring_available: 5,
            dbg_tx_completion_ring_available_max: 9,
            ..Default::default()
        };

        publish_tx_completion_ring_telemetry(&live, &mut telemetry);

        assert_eq!(
            live.tx_completion_ring_available.load(Ordering::Relaxed),
            5
        );
        assert_eq!(
            live.tx_completion_ring_available_max.load(Ordering::Relaxed),
            9
        );
        assert_eq!(telemetry.dbg_tx_completion_ring_available, 0);
        assert_eq!(telemetry.dbg_tx_completion_ring_available_max, 0);
    }
}
