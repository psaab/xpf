use super::*;

// #1782 Step-1: per-cause v8 queue-lease under-grant counter block,
// shared between WorkerCos (worker-local accumulation) and the
// per-worker runtime publish path.
use super::worker_runtime::CoSQueueLeaseUndergrantCounters;

// Issue 73 step 2: per-poll BindingWorker lifecycle (the central
// `poll_binding` orchestrator) lives in worker/lifecycle.rs.
mod lifecycle;
/// #8114 item 3: the derived size of the same-worker flow-cache revocation
/// window. Re-exported so the decision's figure is nameable from outside the
/// module that computes it.
pub(crate) use lifecycle::REVOCATION_FLOW_CACHE_WINDOW_DESCRIPTORS;
use lifecycle::poll_binding;
/// #8586: the flat (whole-`bindings`) flow-cache eviction the worker loop's
/// reconcile uses; the split-borrow sibling stays private to `poll_binding`.
pub(in crate::afxdp) use lifecycle::invalidate_flow_cache_slots_for_keys;

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
pub(in crate::afxdp) use cos::COS_SHARED_EXACT_MIN_RATE_BYTES;
pub(crate) use cos::merge_cos_queue_owner_profile_sum;
pub(in crate::afxdp) use cos::{
    OwnerProfileSnapshot, merge_binding_scoped_owner_profile, merge_owner_profile_sum,
    owner_profile_snapshot,
};
use cos::{
    build_worker_cos_fast_interfaces, build_worker_cos_owner_live_by_tx_ifindex,
    build_worker_cos_statuses, cos_runtime_config_changed, reset_binding_cos_runtime,
    reset_worker_cos_runtimes, vacate_all_shared_exact_slots_for_binding,
};

// #1326 Phase 1: `worker_loop` body extracted into worker/loop_body/.
// Re-exported here so external callers (`worker_runtime.rs`,
// `coordinator/mod.rs`, `afxdp/mod.rs`) keep working unchanged.
mod loop_body;
pub(crate) use loop_body::worker_loop;

// #9412: the synced session entry and its install mapping live in their own file.
mod synced_entry;
pub(crate) use synced_entry::SyncedSessionEntry;

// #6241: typed worker-launch bundles that replace the 38-parameter
// positional `worker_loop` protocol. Grouped named fields (constructed
// via `from_coord` / `new` builders) eliminate the positional
// silent-swap hazard; `worker_loop` destructures them back into the
// same locals at entry, so the hot loop body is unchanged.
mod launch;
pub(crate) use launch::{
    WorkerControlChannels, WorkerCoSState, WorkerLaunchPlan, WorkerNeighbors,
    WorkerPublishedTelemetry, WorkerSharedDataplane, WorkerSharedSessions,
};

// #956 Phase 4-5: explicit imports for items that moved out of tx.rs into
// cos/token_bucket.rs (Phase 4) and cos/queue_ops.rs (Phase 5). Without
// this, neither the local `use super::*;` glob nor afxdp.rs's
// `use self::tx::*;` parent-module glob still reaches them — the items
// no longer originate from tx.rs after the moves.
use super::cos::{
    clear_all_cos_exact_backlogs_for_binding, cos_queue_len, cos_queue_pop_front_no_snapshot,
    publish_cos_exact_backlog, release_all_cos_queue_leases, release_all_cos_root_leases,
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
    /// #8274 step 3: per-worker WireGuard decap output buffer.
    ///
    /// Separate from `WorkerScratch` and behind a `RefCell` on purpose. The
    /// decap stage runs at stage 6, alongside native-GRE decap, and takes only
    /// a SHARED borrow of the binding — a plain `Vec` here would need
    /// `&mut binding` at a point where the poll loop holds other borrows. The
    /// worker is single-threaded inside its own loop, so `RefCell` is
    /// sufficient and costs no `unsafe`; that is the reasoning
    /// `wg::scratch`'s own module comment gives, and this is the wiring it has
    /// been waiting for ("the integration PR will wire
    /// `WgWorkerScratch::new(UMEM_FRAME_SIZE as usize)` from the dispatch
    /// side").
    pub(crate) wg_scratch: crate::afxdp::wg::WgWorkerScratch,
    /// Packets waiting for neighbor resolution. The UMEM frame is held
    /// (not recycled) until the neighbor resolves or the entry times out.
    ///
    /// #1771 §2.2: keyed by `(egress_ifindex, next_hop)` — **one
    /// representative packet per unresolved next-hop**, not a FIFO of every
    /// admitted packet. Admission keeps the OLDEST packet for a key (it
    /// drives the probe/dwell clock) and drops+recycles duplicates, so a
    /// SYN flood to one dead host pins ≤1 UMEM frame for that host instead
    /// of up to `MAX_PENDING_NEIGH`. The cap now bounds distinct unresolved
    /// next-hops per worker (not total packets). Same key shape as
    /// `neg_neigh_cache` / `resolver_enqueue_throttle`. Worker-owned, no
    /// cross-core sync; lazy allocation.
    pub(crate) pending_neigh:
        super::types::FastMap<(i32, std::net::IpAddr), PendingNeighPacket>,
    /// #7156: deadline-ordered arming for `pending_neigh`. The map above stays
    /// authoritative for packet state; this only decides WHEN each key is next
    /// looked at, so a sweep with nothing due costs one heap peek instead of a
    /// walk of every unresolved key. Exactly one entry per live map key --
    /// see `neigh_schedule`'s header for why no tombstone can arise.
    pub(crate) pending_neigh_schedule: crate::afxdp::neigh_schedule::PendingNeighSchedule,
    /// #7156: last `ShardedNeighborMap::insert_generation` this worker acted on.
    /// When it still matches, no neighbour has been inserted since the last
    /// sweep, so no buffered key can have become resolvable and the sweep skips
    /// the walk over every pending key entirely.
    pub(crate) last_neigh_generation: (u64, usize),
    /// #7156: reused key scratch for the resolution walk, so the walk that does
    /// happen still allocates nothing steady-state (the old sweep built a fresh
    /// Vec of every key on EVERY sweep — ~98 KiB per sweep at the cap).
    pub(crate) pending_neigh_scan: Vec<(i32, std::net::IpAddr)>,
    /// #1651 B3: dead-host negative neighbor cache. Key
    /// `(egress_ifindex, next_hop)`; value = insertion `now_ns`. A dst is
    /// recorded when it times out in `pending_neigh` without resolving;
    /// while present + un-expired + still-unresolved, new `MissingNeighbor`
    /// packets to it fast-fail (recycle) instead of buffering for another
    /// `PENDING_NEIGH_TIMEOUT`. Per-binding (mirrors `pending_neigh`) —
    /// touched only by the owning worker thread, no cross-core sync. Lazy
    /// allocation (grows on first dead-host drop), like `pending_neigh`.
    pub(crate) neg_neigh_cache: super::neg_neigh::NegNeighCache,
    /// #1769: per-binding throttle for on-demand resolver enqueues. Keyed
    /// by `(egress_ifindex, next_hop)` → last-enqueue `now_ns`. On a
    /// negative-cache fast-fail the worker only clones the egress iface
    /// name and `try_send`s into the shared resolver if this key has not
    /// been enqueued within `RESOLVER_ENQUEUE_THROTTLE_NS`. Without it a
    /// dead-host SYN storm would `String::clone()` the iface name per
    /// fast-failed packet (Gemini hot-path-alloc finding) even though the
    /// resolver coalesces them anyway. Touched only by the owning worker
    /// thread — no cross-core sync, lazy allocation like `neg_neigh_cache`.
    pub(crate) resolver_enqueue_throttle: super::types::FastMap<(i32, std::net::IpAddr), u64>,
    /// #959 Phase 5: 4 BPF map FDs extracted into `WorkerBpfMaps`.
    /// Field semantics unchanged; access via `binding.bpf_maps.X_fd`.
    pub(crate) bpf_maps: WorkerBpfMaps,
    /// #959 Phase 6: 6 timing / wake-pacing fields extracted into
    /// `WorkerTimers`. Field semantics unchanged; access via
    /// `binding.timers.last_X_ns` etc.
    pub(crate) timers: WorkerTimers,
    pub(crate) last_learned_neighbor: Option<LearnedNeighborKey>,
    /// #5288: per-worker gate for the data-path ARP/NDP kernel-neighbor
    /// program. Bounds the netlink `socket()`/`sendto()`/`close()` +
    /// allocations `add_kernel_neighbor` performs so a repeat/flood of accepted
    /// adverts cannot starve this XSK worker. Touched only by the owning worker
    /// thread (the ARP/NDP learn in `stage_link_layer_classify`); no cross-core
    /// sync — neighbor programming is LOCAL, not HA/session-sync state.
    pub(crate) neigh_program_limiter: super::KernelNeighborProgramLimiter,
    /// #959 Phase 1: 23 `dbg_*` debug counters extracted into
    /// `WorkerTelemetry` to reduce BindingWorker's mutable surface
    /// area. Field semantics unchanged; access via `binding.telemetry.dbg_X`.
    pub(crate) telemetry: WorkerTelemetry,
    /// #959 Phase 4: 6 `pending_*_tx_*` packet counters extracted
    /// into `WorkerTxCounters`. Field semantics unchanged; access
    /// via `binding.tx_counters.pending_X`.
    pub(crate) tx_counters: WorkerTxCounters,
    /// #959 Phase 9: flow-cache state extracted into
    /// `WorkerFlowCacheState`. Field semantics unchanged; access via
    /// `binding.flow.flow_cache`. (#2220 dropped the binding-global
    /// modulo-64 `flow_cache_session_touch` keepalive counter in favour
    /// of `SessionTable::touch_if_stale`.)
    pub(crate) flow: WorkerFlowCacheState,
    /// #1620: cold-path latency histogram worker-local state.
    /// Co-located with `flow` because the policy-eval slow path
    /// already touches `binding.flow` — sharing cachelines avoids
    /// a compulsory L1 miss on `binding.cold_path.sample_phase`.
    /// Touched only by the owning worker thread. #1621 will add the
    /// sibling `WorkerColdPathAtomics` array and the ~1s tick publish
    /// hook in `worker_runtime.rs::publish`.
    pub(crate) cold_path: super::cold_path_hist::WorkerColdPathCounters,
    /// #1376: per-worker/per-binding mirror sampler. Reset on worker
    /// restart and intentionally not synchronized across workers.
    pub(crate) mirror_sample_counter: u64,
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
    non_first_fragment: bool,
) -> u64 {
    fabric_queue_hash_seeded(
        crate::hot_hash_seed::hot_path_hash_seed(),
        flow,
        expected_ports,
        meta,
        non_first_fragment,
    )
}

/// Seed-parameterized core of `fabric_queue_hash` (#2364).
///
/// The fabric queue hash maps an attacker-controllable 5-tuple (or, for a
/// non-first fragment, a 3-tuple) onto one of THIS node's local fabric
/// egress bindings (`BindingLookup::fabric_target_index` indexes
/// `all_by_if[..] % len`). With the previous fixed public mixing
/// (`seed = meta.protocol`) a flow generator could bias the selection and
/// pin attack flows onto a single fabric worker (queue skew → CPU/lock
/// amplification on that worker). Folding the per-boot process seed into
/// the initial state makes the mapping unknowable offline and reshuffled
/// per restart.
///
/// NODE-LOCAL CORRECTNESS: this hash is NOT a wire field and is NOT
/// HA-synced. Each node independently spreads its OWN fabric TX across its
/// OWN local fabric bindings; the peer does not need to agree on the
/// result, so a per-node seed is correct (it does not break fabric
/// forwarding). The ONLY intra-process invariant — every fragment of one
/// datagram must select the same fabric binding (no cross-chassis
/// reordering, #2357) — is preserved because the seed is constant for the
/// process lifetime, so the same input still maps to the same output.
pub(crate) fn fabric_queue_hash_seeded(
    seed_secret: u64,
    flow: Option<&SessionFlow>,
    expected_ports: Option<(u16, u16)>,
    meta: UserspaceDpMeta,
    non_first_fragment: bool,
) -> u64 {
    fn mix(seed: &mut u64, value: u64) {
        *seed ^= value
            .wrapping_add(0x9e3779b97f4a7c15)
            .wrapping_add(*seed << 6)
            .wrapping_add(*seed >> 2);
    }

    let mut seed = seed_secret ^ (meta.protocol as u64);
    // #2357: a non-first IP fragment has no L4 header — `meta.flow_*_port`
    // and `expected_ports` describe payload bytes, not real ports. Hash a
    // fragment-stable 3-tuple (protocol + L3 src/dst from metadata, which the
    // XDP shim copies from the IP header that IS present on every fragment)
    // and OMIT the ports, so every fragment of one datagram selects the same
    // fabric target binding (no cross-chassis reordering). `flow` is `None`
    // for a fragment (#2344), so the ported `flow`/`expected_ports` branches
    // below never run for it.
    if non_first_fragment {
        match meta.addr_family as i32 {
            libc::AF_INET => {
                mix(
                    &mut seed,
                    u32::from_be_bytes([
                        meta.flow_src_addr[0],
                        meta.flow_src_addr[1],
                        meta.flow_src_addr[2],
                        meta.flow_src_addr[3],
                    ]) as u64,
                );
                mix(
                    &mut seed,
                    u32::from_be_bytes([
                        meta.flow_dst_addr[0],
                        meta.flow_dst_addr[1],
                        meta.flow_dst_addr[2],
                        meta.flow_dst_addr[3],
                    ]) as u64,
                );
            }
            _ => {
                for chunk in meta.flow_src_addr.chunks_exact(8) {
                    mix(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
                }
                for chunk in meta.flow_dst_addr.chunks_exact(8) {
                    mix(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
                }
            }
        }
        return seed;
    }
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

impl BindingWorker {
    fn create(
        binding: &BindingStatus,
        ring_entries: u32,
        xsk_map_fd: c_int,
        heartbeat_map_fd: c_int,
        session_map: crate::afxdp::bpf_map::SteeringMapRef,
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
        // Safety: `BindingWorker` declares `xsk` before `umem`, so Rust drops
        // the socket/ring handles before the UMEM. That satisfies the UMEM
        // lifetime/drop-order contract enforced by `open_binding_worker_rings`.
        let (
            user,
            rx,
            tx,
            bind_mode,
            bind_flags,
            actual_bind_strategy,
            device,
            uninserted_fill_frames,
        ) = unsafe {
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
        }
        .map_err(|err| format!("configure AF_XDP rings: {err}"))?;
        // #2374: the bringup prime may not place every fill frame on a
        // transiently-full ring. The uninserted suffix is seeded into
        // `pending_fill_frames` below so the steady-state drain retries it —
        // those UMEM frames are accounted, never leaked.
        let pending_fill_frames: VecDeque<u64> = uninserted_fill_frames.into_iter().collect();

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
                backup_retry_scratch: std::collections::VecDeque::new(),
                max_pending_tx,
                outstanding_tx: 0,
                pending_fill_frames,
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
                cos_wheel_ticks_advanced_total: 0,
                cos_wheel_ticks_advanced_max: 0,
                cos_queue_lease_undergrants: CoSQueueLeaseUndergrantCounters::default(),
                released_queue_leases_scratch: Vec::new(),
                cos_local_batch_scratch: VecDeque::new(),
                cos_prepared_batch_scratch: VecDeque::new(),
            },
            scratch: WorkerScratch::pre_sized(ring_entries),
            wg_scratch: crate::afxdp::wg::WgWorkerScratch::new(UMEM_FRAME_SIZE as usize),
            // GEMINI-NEXT.md Section 3 cold start: lazy allocation. The
            // 4096-cap is enforced at admission (poll_descriptor.rs check
            // against MAX_PENDING_NEIGH), so pre-allocating that capacity
            // up front would burn ~576 KB per binding at startup even when
            // idle. Start at 0 capacity and let VecDeque grow on push as
            // packets actually queue up.
            pending_neigh: super::types::FastMap::default(),
            pending_neigh_schedule: Default::default(),
            last_neigh_generation: (0, 0),
            pending_neigh_scan: Vec::new(),
            // #1651 B3: lazy-grow (empty until first dead-host drop).
            neg_neigh_cache: super::neg_neigh::NegNeighCache::default(),
            resolver_enqueue_throttle: super::types::FastMap::default(),
            bpf_maps: WorkerBpfMaps {
                heartbeat_map_fd,
                session_map,
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
            neigh_program_limiter: super::KernelNeighborProgramLimiter::new(),
            telemetry: WorkerTelemetry::default(),
            tx_counters: WorkerTxCounters {
                pending_direct_tx_packets: 0,
                pending_copy_tx_packets: 0,
                neighbor_retry_cross_umem_copies: 0,
                pending_in_place_tx_packets: 0,
                pending_in_place_vlan_push_desc_packets: 0,
                pending_in_place_vlan_pop_desc_packets: 0,
                pending_in_place_vlan_push_no_headroom_packets: 0,
                pending_in_place_l2_memmove_fallback_packets: 0,
                pending_direct_tx_no_frame_fallback_packets: 0,
                pending_direct_tx_build_fallback_packets: 0,
                pending_direct_tx_disallowed_fallback_packets: 0,
            },
            flow: WorkerFlowCacheState {
                flow_cache: FlowCache::new(),
            },
            // #1620: cold-path histogram worker-local state; default
            // zero-initialized. ns_per_tsc_q32 / wrapper_ns_baseline /
            // clock_source are populated by the per-worker calibrate
            // in worker_loop entry (post-affinity).
            cold_path: super::cold_path_hist::WorkerColdPathCounters::default(),
            mirror_sample_counter: 0,
            bind_meta: WorkerBindMeta {
                bind_time_ns: {
                    let mut ts = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    };
                    // SAFETY: plain FFI call with a valid, live out-pointer
                    // to the stack-allocated `ts` above.
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

    #[cfg(test)]
    pub(in crate::afxdp) fn new_for_cos_drain_test(
        slot: u32,
        worker_id: u32,
        root_ifindex: i32,
        root: CoSInterfaceRuntime,
        fast_path: WorkerCoSInterfaceFastPath,
    ) -> Self {
        let ring_entries = 64;
        let total_frames = 64;
        let live = Arc::new(BindingLiveState::new());
        live.set_bound(-1);
        live.set_bind_mode(XskBindMode::Copy);
        live.set_socket_binding(root_ifindex, 0, 0);
        live.set_max_pending_tx(pending_tx_capacity(ring_entries));
        live.umem_total_frames
            .store(total_frames, std::sync::atomic::Ordering::Relaxed);
        live.tx_ring_capacity
            .store(ring_entries, std::sync::atomic::Ordering::Relaxed);

        let mut cos_interfaces = FastMap::default();
        let cos_nonempty_interfaces = usize::from(root.nonempty_queues > 0);
        cos_interfaces.insert(root_ifindex, root);
        let mut cos_fast_interfaces = FastMap::default();
        cos_fast_interfaces.insert(root_ifindex, fast_path);
        let init_now = monotonic_nanos();
        Self {
            slot,
            queue_id: 0,
            worker_id,
            interface: Arc::<str>::from("test0"),
            ifindex: root_ifindex,
            live,
            user: User::new_for_test(-1),
            xsk: WorkerXskRings {
                device: crate::xsk_ffi::DeviceQueue::new_for_test(-1, ring_entries),
                rx: crate::xsk_ffi::RingRx::new_for_test(-1, ring_entries),
                tx: crate::xsk_ffi::RingTx::new_for_test(-1, ring_entries),
            },
            umem: WorkerUmem::new_for_test(total_frames).expect("test worker umem"),
            tx_pipeline: WorkerTxPipeline {
                free_tx_frames: (0..total_frames)
                    .map(|idx| (idx as u64) << UMEM_FRAME_SHIFT)
                    .collect(),
                pending_tx_prepared: VecDeque::new(),
                pending_tx_local: VecDeque::new(),
                backup_retry_scratch: std::collections::VecDeque::new(),
                max_pending_tx: pending_tx_capacity(ring_entries),
                outstanding_tx: 0,
                pending_fill_frames: VecDeque::new(),
                in_flight_prepared_recycles: FastMap::default(),
                tx_submit_ns: vec![TX_SIDECAR_UNSTAMPED; total_frames as usize].into_boxed_slice(),
            },
            cos: WorkerCos {
                cos_fast_interfaces,
                cos_interfaces,
                cos_interface_order: vec![root_ifindex],
                cos_interface_rr: 0,
                cos_nonempty_interfaces,
                cos_queue_lease_acquire_v8_calls: 0,
                cos_queue_lease_acquire_v8_granted_bytes: 0,
                cos_wheel_ticks_advanced_total: 0,
                cos_wheel_ticks_advanced_max: 0,
                cos_queue_lease_undergrants: CoSQueueLeaseUndergrantCounters::default(),
                released_queue_leases_scratch: Vec::new(),
                cos_local_batch_scratch: VecDeque::new(),
                cos_prepared_batch_scratch: VecDeque::new(),
            },
            scratch: WorkerScratch::pre_sized(ring_entries),
            wg_scratch: crate::afxdp::wg::WgWorkerScratch::new(UMEM_FRAME_SIZE as usize),
            pending_neigh: super::types::FastMap::default(),
            pending_neigh_schedule: Default::default(),
            last_neigh_generation: (0, 0),
            pending_neigh_scan: Vec::new(),
            // #1651 B3: lazy-grow (empty until first dead-host drop).
            neg_neigh_cache: super::neg_neigh::NegNeighCache::default(),
            resolver_enqueue_throttle: super::types::FastMap::default(),
            bpf_maps: WorkerBpfMaps {
                heartbeat_map_fd: -1,
                session_map: crate::afxdp::bpf_map::SteeringMapRef::new(
                    -1,
                    std::sync::Arc::default(),
                ),
                conntrack_v4_fd: -1,
                conntrack_v6_fd: -1,
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
            neigh_program_limiter: super::KernelNeighborProgramLimiter::new(),
            telemetry: WorkerTelemetry::default(),
            tx_counters: WorkerTxCounters {
                pending_direct_tx_packets: 0,
                pending_copy_tx_packets: 0,
                neighbor_retry_cross_umem_copies: 0,
                pending_in_place_tx_packets: 0,
                pending_in_place_vlan_push_desc_packets: 0,
                pending_in_place_vlan_pop_desc_packets: 0,
                pending_in_place_vlan_push_no_headroom_packets: 0,
                pending_in_place_l2_memmove_fallback_packets: 0,
                pending_direct_tx_no_frame_fallback_packets: 0,
                pending_direct_tx_build_fallback_packets: 0,
                pending_direct_tx_disallowed_fallback_packets: 0,
            },
            flow: WorkerFlowCacheState {
                flow_cache: FlowCache::new(),
            },
            // #1620: cold-path histogram worker-local state; default
            // zero-initialized. ns_per_tsc_q32 / wrapper_ns_baseline /
            // clock_source are populated by the per-worker calibrate
            // in worker_loop entry (post-affinity).
            cold_path: super::cold_path_hist::WorkerColdPathCounters::default(),
            mirror_sample_counter: 0,
            bind_meta: WorkerBindMeta {
                bind_time_ns: init_now,
                bind_mode: XskBindMode::Copy,
                xsk_rx_confirmed: false,
            },
        }
    }

    #[cfg(test)]
    pub(in crate::afxdp) fn new_for_mirror_test(
        slot: u32,
        worker_id: u32,
        ifindex: i32,
        queue_id: u32,
    ) -> Self {
        let ring_entries = 128;
        let total_frames = 256;
        let live = Arc::new(BindingLiveState::new());
        live.set_bound(-1);
        live.set_bind_mode(XskBindMode::Copy);
        live.set_socket_binding(ifindex, queue_id, 0);
        live.set_max_pending_tx(pending_tx_capacity(ring_entries));
        live.umem_total_frames
            .store(total_frames, std::sync::atomic::Ordering::Relaxed);
        live.tx_ring_capacity
            .store(ring_entries, std::sync::atomic::Ordering::Relaxed);
        let init_now = monotonic_nanos();
        Self {
            slot,
            queue_id,
            worker_id,
            interface: Arc::<str>::from("mirror-test"),
            ifindex,
            live,
            user: User::new_for_test(-1),
            xsk: WorkerXskRings {
                device: crate::xsk_ffi::DeviceQueue::new_for_test(-1, ring_entries),
                rx: crate::xsk_ffi::RingRx::new_for_test(-1, ring_entries),
                tx: crate::xsk_ffi::RingTx::new_for_test(-1, ring_entries),
            },
            umem: WorkerUmem::new_for_test(total_frames).expect("test worker umem"),
            tx_pipeline: WorkerTxPipeline {
                free_tx_frames: (0..total_frames)
                    .map(|idx| (idx as u64) << UMEM_FRAME_SHIFT)
                    .collect(),
                pending_tx_prepared: VecDeque::new(),
                pending_tx_local: VecDeque::new(),
                backup_retry_scratch: std::collections::VecDeque::new(),
                max_pending_tx: pending_tx_capacity(ring_entries),
                outstanding_tx: 0,
                pending_fill_frames: VecDeque::new(),
                in_flight_prepared_recycles: FastMap::default(),
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
                cos_wheel_ticks_advanced_total: 0,
                cos_wheel_ticks_advanced_max: 0,
                cos_queue_lease_undergrants: CoSQueueLeaseUndergrantCounters::default(),
                released_queue_leases_scratch: Vec::new(),
                cos_local_batch_scratch: VecDeque::new(),
                cos_prepared_batch_scratch: VecDeque::new(),
            },
            scratch: WorkerScratch::pre_sized(ring_entries),
            wg_scratch: crate::afxdp::wg::WgWorkerScratch::new(UMEM_FRAME_SIZE as usize),
            pending_neigh: super::types::FastMap::default(),
            pending_neigh_schedule: Default::default(),
            last_neigh_generation: (0, 0),
            pending_neigh_scan: Vec::new(),
            // #1651 B3: lazy-grow (empty until first dead-host drop).
            neg_neigh_cache: super::neg_neigh::NegNeighCache::default(),
            resolver_enqueue_throttle: super::types::FastMap::default(),
            bpf_maps: WorkerBpfMaps {
                heartbeat_map_fd: -1,
                session_map: crate::afxdp::bpf_map::SteeringMapRef::new(
                    -1,
                    std::sync::Arc::default(),
                ),
                conntrack_v4_fd: -1,
                conntrack_v6_fd: -1,
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
            neigh_program_limiter: super::KernelNeighborProgramLimiter::new(),
            telemetry: WorkerTelemetry::default(),
            tx_counters: WorkerTxCounters {
                pending_direct_tx_packets: 0,
                pending_copy_tx_packets: 0,
                neighbor_retry_cross_umem_copies: 0,
                pending_in_place_tx_packets: 0,
                pending_in_place_vlan_push_desc_packets: 0,
                pending_in_place_vlan_pop_desc_packets: 0,
                pending_in_place_vlan_push_no_headroom_packets: 0,
                pending_in_place_l2_memmove_fallback_packets: 0,
                pending_direct_tx_no_frame_fallback_packets: 0,
                pending_direct_tx_build_fallback_packets: 0,
                pending_direct_tx_disallowed_fallback_packets: 0,
            },
            flow: WorkerFlowCacheState {
                flow_cache: FlowCache::new(),
            },
            // #1620: cold-path histogram worker-local state; default
            // zero-initialized. ns_per_tsc_q32 / wrapper_ns_baseline /
            // clock_source are populated by the per-worker calibrate
            // in worker_loop entry (post-affinity).
            cold_path: super::cold_path_hist::WorkerColdPathCounters::default(),
            mirror_sample_counter: 0,
            bind_meta: WorkerBindMeta {
                bind_time_ns: init_now,
                bind_mode: XskBindMode::Copy,
                xsk_rx_confirmed: false,
            },
        }
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

fn publish_plan_shared_umem_status(live: &BindingLiveState, status: &BindingStatus) {
    live.set_shared_umem_status(
        status.shared_umem_mode.clone(),
        status.shared_umem_group.clone(),
        status.shared_umem_socket_role.clone(),
        status.shared_umem_disabled_reason.clone(),
    );
}

fn shared_umem_socket_role_for_xsk_role(socket_role: XskSocketRole) -> SharedUmemSocketRole {
    match socket_role {
        XskSocketRole::Private => SharedUmemSocketRole::Private,
        XskSocketRole::SharedOwner => SharedUmemSocketRole::Owner,
        XskSocketRole::SharedSecondary => SharedUmemSocketRole::Secondary,
    }
}

fn prepare_shared_binding_plan_for_create(
    group_key: &str,
    mut plan: BindingPlan,
    socket_role: XskSocketRole,
) -> BindingPlan {
    let planned_role = xsk_role_for_shared_plan(&plan.shared_umem);
    let actual_role = shared_umem_socket_role_for_xsk_role(socket_role);
    if plan.shared_umem.socket_role != actual_role {
        eprintln!(
            "xpf-userspace-dp: shared UMEM group {group_key} corrected planned role for slot={} from {} to {}",
            plan.status.slot,
            planned_role.describe(),
            socket_role.describe(),
        );
        plan.shared_umem = SharedUmemBindingPlan::shared(
            plan.shared_umem.mode,
            plan.shared_umem.group_key.clone(),
            actual_role,
        );
        publish_shared_umem_plan_to_binding_status(&mut plan.status, &plan.shared_umem);
    }
    publish_plan_shared_umem_status(&plan.live, &plan.status);
    plan
}

fn create_private_binding_from_plan(
    plan: BindingPlan,
) -> Result<BindingWorker, Box<dyn std::error::Error + Send + Sync>> {
    publish_plan_shared_umem_status(&plan.live, &plan.status);
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
            plan.session_map.clone(),
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

struct SharedGroupBindError {
    group_key: String,
    plans: Vec<BindingPlan>,
    reason: String,
}

impl SharedGroupBindError {
    fn new(group_key: &str, plans: Vec<BindingPlan>, reason: String) -> Self {
        Self {
            group_key: group_key.to_string(),
            plans,
            reason,
        }
    }
}

impl std::fmt::Display for SharedGroupBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "shared UMEM group {} failed: {}",
            self.group_key, self.reason
        )
    }
}

impl std::fmt::Debug for SharedGroupBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedGroupBindError")
            .field("group_key", &self.group_key)
            .field("plan_count", &self.plans.len())
            .field("reason", &self.reason)
            .finish()
    }
}

impl std::error::Error for SharedGroupBindError {}

fn create_shared_binding_group(
    group_key: &str,
    mut plans: Vec<BindingPlan>,
) -> Result<Vec<BindingWorker>, SharedGroupBindError> {
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
    } = WorkerUmemPool::new(total_frames).map_err(|err| {
        SharedGroupBindError::new(group_key, plans.clone(), format!("create UMEM: {err}"))
    })?;

    let mut created: Vec<(BindingWorker, c_int)> = Vec::with_capacity(plans.len());
    for plan in plans.iter().cloned() {
        let socket_role = if created.is_empty() {
            XskSocketRole::SharedOwner
        } else {
            XskSocketRole::SharedSecondary
        };
        let plan = prepare_shared_binding_plan_for_create(group_key, plan, socket_role);
        match BindingWorker::create(
            &plan.status,
            plan.ring_entries,
            plan.xsk_map_fd,
            plan.heartbeat_map_fd,
            plan.session_map.clone(),
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
                return Err(SharedGroupBindError::new(group_key, plans, msg));
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
            return Err(SharedGroupBindError::new(group_key, plans, msg));
        }
        registered.push((*xsk_map_fd, binding.slot));
    }

    Ok(created.into_iter().map(|(binding, _)| binding).collect())
}

// #6245: `binding_failures` / `recovered_fallbacks` accumulate the EXPLICIT
// per-slot terminal failures and the recovered-degradation record so the
// WorkerStartupReport can carry the cause. A shared-group bind that FAILS but
// whose private fallback fully recovers is a `BindingRecoveredFallback` (all
// slots rebound, readiness unaffected); a slot whose private fallback ALSO
// fails is a terminal `BindingSetupFailure { phase: SharedFallback }`.
fn fallback_shared_group_to_private(
    err: SharedGroupBindError,
    bindings: &mut Vec<BindingWorker>,
    binding_failures: &mut Vec<BindingSetupFailure>,
    recovered_fallbacks: &mut Vec<BindingRecoveredFallback>,
) {
    let SharedGroupBindError {
        group_key,
        plans,
        reason,
    } = err;
    let fallback_reason =
        format!("shared UMEM group {group_key} failed; using private UMEM: {reason}");
    eprintln!("xpf-userspace-dp: {fallback_reason}");
    // #6245: track whether EVERY member slot recovered — only a fully recovered
    // group is a `BindingRecoveredFallback` (a partially-recovered group has its
    // failed slots recorded as terminal failures below, so it is not "recovered").
    let mut all_slots_recovered = true;
    for mut plan in plans {
        let live = plan.live.clone();
        let slot = plan.status.slot;
        // #7497: captured before `plan` is moved into the bind call, like slot.
        let coord = BindingCoordinate::of(&plan.status);
        let mode = plan.shared_umem.mode;
        plan.shared_umem = SharedUmemBindingPlan::disabled(mode, fallback_reason.clone());
        publish_shared_umem_plan_to_binding_status(&mut plan.status, &plan.shared_umem);
        match create_private_binding_from_plan(plan) {
            Ok(binding) => bindings.push(binding),
            Err(err) => {
                let msg = format!("private fallback after shared UMEM failure failed: {err}");
                eprintln!("xpf-userspace-dp: {msg}");
                live.set_error(msg.clone());
                binding_failures.push(BindingSetupFailure::at(
                    &coord,
                    BindingSetupPhase::SharedFallback,
                    msg,
                ));
                all_slots_recovered = false;
            }
        }
    }
    if all_slots_recovered {
        recovered_fallbacks.push(BindingRecoveredFallback {
            group: group_key,
            reason,
        });
    }
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
// #1881: pub(in crate::afxdp) so the GRE local-origin loop
// (afxdp/tunnel.rs) shares the same per-tick refresh helper.
pub(in crate::afxdp) fn load_arc_if_changed<T>(cached: &Arc<T>, shared: &ArcSwap<T>) -> Option<Arc<T>> {
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
    // #1782 Step-1: wheel catch-up sum/max + per-cause under-grant
    // attribution, summed (max'ed) across this worker's bindings on
    // the same ~1s publish cadence as the existing lease counters.
    let mut wheel_total = 0u64;
    let mut wheel_max = 0u64;
    let mut undergrant = CoSQueueLeaseUndergrantCounters::default();
    for binding in bindings {
        calls = calls.wrapping_add(binding.cos.cos_queue_lease_acquire_v8_calls);
        granted_bytes =
            granted_bytes.wrapping_add(binding.cos.cos_queue_lease_acquire_v8_granted_bytes);
        wheel_total = wheel_total.wrapping_add(binding.cos.cos_wheel_ticks_advanced_total);
        wheel_max = wheel_max.max(binding.cos.cos_wheel_ticks_advanced_max);
        undergrant.add_assign(&binding.cos.cos_queue_lease_undergrants);
    }
    counters.cos_queue_lease_acquire_v8_calls = calls;
    counters.cos_queue_lease_acquire_v8_granted_bytes = granted_bytes;
    counters.cos_wheel_ticks_advanced_total = wheel_total;
    counters.cos_wheel_ticks_advanced_max = wheel_max;
    counters.cos_queue_lease_undergrant = undergrant;
}

/// #4800: sum this worker's per-binding new-flow install counts onto its
/// runtime counters, on the same ~1s publish cadence as the CoS lease
/// counters above. A worker owns its bindings, so the sum is the worker's
/// share of the transit new-flow install path.
fn refresh_worker_new_flow_install_counters(
    counters: &mut super::worker_runtime::WorkerRuntimeCounters,
    bindings: &[BindingWorker],
) {
    counters.new_flow_installs = bindings
        .iter()
        .map(|binding| {
            binding
                .live
                .new_flow_installs
                .load(std::sync::atomic::Ordering::Relaxed)
        })
        .fold(0u64, |acc, v| acc.wrapping_add(v));
}

fn apply_worker_shaped_tx_requests(
    bindings: &mut [BindingWorker],
    forwarding: &ForwardingState,
    binding_lookup: &WorkerBindingLookup,
    now_ns: u64,
    requests: Vec<TxRequest>,
    shared_recycles: &mut Vec<(u32, u64)>,
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
        match enqueue_local_into_cos(
            binding,
            forwarding,
            req,
            now_ns,
            Some(&mut *shared_recycles),
        ) {
            Ok(()) => {}
            Err(req) => {
                binding.tx_pipeline.pending_tx_local.push_back(req);
                bound_pending_tx_local(binding);
            }
        }
    }
}

/// #5289: push an already-built POD event onto a ring, bypassing the
/// sampler. Used only by the rare control-thread manual-notice sites
/// (spawn / tunnel-setup failures) which are not attacker-floodable.
pub(crate) fn push_recent_exception(
    recent_exceptions: &mut ExceptionEventRing,
    exception: ExceptionEvent,
) {
    recent_exceptions.push(exception);
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

fn publish_tx_completion_ring_telemetry(live: &BindingLiveState, telemetry: &mut WorkerTelemetry) {
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
    pub(crate) shared_umem_mode: String,
    pub(crate) shared_umem_group: String,
    pub(crate) shared_umem_socket_role: String,
    pub(crate) shared_umem_disabled_reason: String,
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
    /// #4743: martian-dst NoRoute drops snapshotted from BindingLiveState (a
    /// sub-breakout of route_miss_packets).
    pub(crate) martian_dropped: u64,
    /// #4743: over-limit IPv6 ext-header fail-closed drops snapshotted from
    /// BindingLiveState.
    pub(crate) ipv6_ext_header_dropped: u64,
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
    /// Rust-owned per-binding flow-cache capacity.
    pub(crate) flow_cache_capacity: u32,
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
    /// #hb166 T-6(a): V_min suspended-batch count on this binding.
    pub(crate) v_min_suspended_batches: u64,
    pub(crate) session_hits: u64,
    pub(crate) session_misses: u64,
    pub(crate) session_creates: u64,
    pub(crate) session_expires: u64,
    pub(crate) session_delta_pending: u64,
    pub(crate) session_delta_generated: u64,
    pub(crate) session_delta_dropped: u64,
    /// #8108: greatest depth the RPC-fallback delta buffer has reached.
    pub(crate) session_delta_high_water: u64,
    pub(crate) session_delta_drained: u64,
    pub(crate) policy_denied_packets: u64,
    /// #3326: host-inbound admission denies on the LocalDelivery path.
    pub(crate) host_inbound_denied_packets: u64,
    pub(crate) screen_drops: u64,
    /// #3343: per-screen-reason DROP counters (ordinals per
    /// `screen::screen_reason_drop_index`), threaded from `BindingLiveState`
    /// to `BindingStatus` so the Go control plane can attribute screen drops.
    pub(crate) screen_reason_drops: [u64; crate::screen::SCREEN_REASON_DROP_COUNT],
    /// #1374: SYN-cookie challenge decisions selected by userspace screen
    /// runtime.
    pub(crate) syn_cookie_challenges: u64,
    pub(crate) syn_cookie_secret_unavailable: u64,
    pub(crate) syn_cookie_syn_ack_sent: u64,
    pub(crate) syn_cookie_ack_rst_sent: u64,
    pub(crate) syn_cookie_reply_budget_drops: u64,
    pub(crate) syn_cookie_ack_valid: u64,
    pub(crate) syn_cookie_ack_invalid: u64,
    pub(crate) syn_cookie_bypass: u64,
    /// #2089: policy-`reject` RST/ICMP-unreachable replies enqueued.
    pub(crate) policy_reject_sent: u64,
    /// #2521: firewall-filter `then reject` RST/ICMP-unreachable replies
    /// enqueued. Mirrors `policy_reject_sent`.
    pub(crate) filter_reject_sent: u64,
    /// #2089: POLICY-`reject` replies suppressed by TX-frame budget. #3615
    /// (L04): filter-source suppression is now counted separately in
    /// `filter_reject_reply_budget_drops` so this is policy-reject-only.
    pub(crate) policy_reject_reply_budget_drops: u64,
    /// #3615 (L04): FILTER-`reject` replies suppressed by TX-frame budget —
    /// the source-split sibling of `policy_reject_reply_budget_drops`.
    pub(crate) filter_reject_reply_budget_drops: u64,
    /// #3661: POLICY-`reject` replies dropped by the shared per-reason
    /// rate-limit bucket. Source split of the source-neutral aggregate
    /// `reject_rate_limited_total`.
    pub(crate) policy_reject_rate_limit_drops: u64,
    /// #3661: FILTER-`reject` replies dropped by the rate-limit bucket — the
    /// source-split sibling of `policy_reject_rate_limit_drops`.
    pub(crate) filter_reject_rate_limit_drops: u64,
    /// #2238: locally-generated replies dropped by an OUTPUT firewall filter
    /// (terminal discard/reject or three-color policer) on the egress
    /// interface, classified by the reply's OWN egress tuple. Per-leg.
    pub(crate) time_exceeded_output_filter_drops: u64,
    /// #2238/#3615 (L05): POLICY-`reject` replies dropped by an egress output
    /// filter. Filter-source suppression is now in
    /// `filter_reject_output_filter_drops` (policy-reject-only here).
    pub(crate) policy_reject_output_filter_drops: u64,
    /// #3615 (L05): FILTER-`reject` replies dropped by an egress output filter
    /// — the source-split sibling of `policy_reject_output_filter_drops`.
    pub(crate) filter_reject_output_filter_drops: u64,
    pub(crate) syn_cookie_output_filter_drops: u64,
    /// #2328: locally-generated egress-MTU PTB / Frag-Needed replies (the
    /// #2301 PMTUD path) dropped by an OUTPUT firewall filter terminal
    /// discard/reject (or three-color policer) on the egress interface,
    /// classified by the PTB's OWN egress tuple. Per-leg.
    pub(crate) ptb_output_filter_drops: u64,
    /// #2238: fail-closed drops — a generated reply's own bytes could not be
    /// re-parsed for output classification (§6.2; builder/parser logic bug).
    pub(crate) generated_reply_classify_parse_errors: u64,
    pub(crate) snat_packets: u64,
    pub(crate) dnat_packets: u64,
    /// #2161: cumulative NAT64 translations snapshotted from BindingLiveState.
    pub(crate) nat64_translations: u64,
    /// #2291: cumulative fail-closed NAT64 drops (prefix matched, no source
    /// pool available) snapshotted from BindingLiveState. #4520: config/empty
    /// pool case only; transient exhaustion is `nat64_pool_exhausted`.
    pub(crate) nat64_no_source_pool: u64,
    /// #4520: cumulative transient NAT64 pool-exhaustion drops snapshotted
    /// from BindingLiveState (prefix matched, pool full, no free port).
    pub(crate) nat64_pool_exhausted: u64,
    /// #2562: cumulative fail-closed NAT64 fragment drops snapshotted from
    /// BindingLiveState (a non-first fragment or a real ICMP/ICMPv6 fragment).
    pub(crate) nat64_frag_dropped: u64,
    /// #7054: first-fragment installs that evicted a still-LIVE association.
    pub(crate) nat64_frag_assoc_evicted: u64,
    /// #5623: cumulative fail-closed NAT64 source-ineligibility drops snapshotted
    /// from BindingLiveState (an incoming IPv6 packet whose source lies within a
    /// configured Pref64 — the RFC 6146 §3.5 mandatory hairpin/source drop).
    pub(crate) nat64_ineligible_source: u64,
    /// #6475: cumulative fail-closed NAT64 destination-ineligibility drops
    /// snapshotted from BindingLiveState (a NAT64-prefix-matched destination
    /// embedding a non-global IPv4 per RFC 6052 §3.1 — e.g.
    /// `64:ff9b::127.0.0.1`, which would otherwise LocalDeliver to the
    /// localhost-only control plane).
    pub(crate) nat64_ineligible_dest: u64,
    /// #5625: cumulative fail-closed NAT64 ext-header ineligibility drops
    /// snapshotted from BindingLiveState (a v6→v4 forward translation rejected
    /// because the IPv6 packet carried an Authentication Header, an active
    /// Routing header (Segments Left > 0), or a Mobility / HIP / Shim6 header —
    /// RFC 7915 §5.1 / §5.1.1).
    pub(crate) nat64_exthdr_ineligible: u64,
    /// #8890: fail-closed NAT64 tunnel-encapsulation drops (see
    /// `BindingLiveState::nat64_tunnel_encap_unsupported`).
    pub(crate) nat64_tunnel_encap_unsupported: u64,
    /// #8670: cumulative fail-closed NAT64 protocol-ineligibility drops
    /// snapshotted from BindingLiveState (a Pref64-addressed packet whose IP
    /// protocol stateful NAT64 does not translate — RFC 6146 covers TCP, UDP
    /// and ICMP only).
    pub(crate) nat64_ineligible_protocol: u64,
    /// #4477: cumulative source-NAT allocation failures snapshotted from
    /// BindingLiveState. Bridged into `GlobalCtrNATAllocFail` (Go side).
    pub(crate) nat_alloc_fail: u64,
    /// #6122: cumulative fail-closed drops of an ordinary same-family NAT'd
    /// non-first fragment that missed the fragment-association cache
    /// (SNAT / static-NAT / DNAT / NPTv6), snapshotted from BindingLiveState.
    /// The same-family sibling of `nat64_frag_dropped`.
    pub(crate) nat_frag_untranslated_dropped: u64,
    pub(crate) slow_path_packets: u64,
    pub(crate) slow_path_bytes: u64,
    pub(crate) slow_path_local_delivery_packets: u64,
    pub(crate) slow_path_missing_neighbor_packets: u64,
    pub(crate) slow_path_no_route_packets: u64,
    pub(crate) slow_path_next_table_packets: u64,
    pub(crate) slow_path_forward_build_packets: u64,
    pub(crate) slow_path_drops: u64,
    pub(crate) slow_path_rate_limited: u64,
    /// #1873 R-C/R-E tunnel-marked drop counter (see umem/mod.rs).
    pub(crate) tunnel_encap_unresolved_drops: u64,
    /// #1946 FabricRedirect-unsendable fail-closed drop counter (see
    /// umem/mod.rs).
    pub(crate) fabric_redirect_unsendable_drops: u64,
    /// #6664 NextTableUnsupported fail-closed drop counter.
    pub(crate) next_table_unsupported_drops: u64,
    pub(crate) kernel_rx_dropped: u64,
    pub(crate) kernel_rx_invalid_descs: u64,
    pub(crate) tx_packets: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) tx_completions: u64,
    pub(crate) tx_errors: u64,
    pub(crate) tx_shared_recycle_unknown_slot_drops: u64,
    pub(crate) redirect_inbox_overflow_drops: u64,
    pub(crate) pending_tx_local_overflow_drops: u64,
    pub(crate) tx_submit_error_drops: u64,
    pub(crate) mirrored_packets: u64,
    pub(crate) mirrored_bytes: u64,
    pub(crate) mirror_drops_no_frame: u64,
    pub(crate) mirror_drops_tx_frame_reserve: u64,
    pub(crate) mirror_drops_no_binding: u64,
    pub(crate) mirror_drops_queue_full: u64,
    pub(crate) mirror_drops_queue_full_same_worker: u64,
    pub(crate) mirror_drops_queue_full_cross_worker: u64,
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
    pub(crate) in_place_vlan_push_desc_packets: u64,
    pub(crate) in_place_vlan_pop_desc_packets: u64,
    pub(crate) in_place_vlan_push_no_headroom_packets: u64,
    pub(crate) in_place_l2_memmove_fallback_packets: u64,
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
    /// Monotonic-clock freshness verdict for `last_heartbeat`, computed at
    /// snapshot time in the CLOCK_MONOTONIC domain (see
    /// `bpf_map::heartbeat_fresh_mono`). The wall-clock `last_heartbeat`
    /// above is for operator display only; this bool is the load-bearing
    /// HA-liveness decision and is immune to clock steps (#2332, the Rust
    /// sibling of #1792).
    pub(crate) heartbeat_fresh: bool,
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
    fn shared_binding_plan_create_publishes_live_status() {
        let live = Arc::new(BindingLiveState::new());
        let group = "cross-nic:w0:ge-0-0-1,ge-0-0-2".to_string();
        let shared = SharedUmemBindingPlan::shared(
            SharedUmemMode::CrossNic,
            group.clone(),
            SharedUmemSocketRole::Secondary,
        );
        let mut status = BindingStatus {
            slot: 1,
            queue_id: 0,
            worker_id: 0,
            interface: "ge-0-0-2".to_string(),
            ifindex: 6,
            ..Default::default()
        };
        publish_shared_umem_plan_to_binding_status(&mut status, &shared);
        let plan = BindingPlan {
            status,
            live: live.clone(),
            xsk_map_fd: -1,
            heartbeat_map_fd: -1,
            session_map: crate::afxdp::bpf_map::SteeringMapRef::new(-1, std::sync::Arc::default()),
            conntrack_v4_fd: -1,
            conntrack_v6_fd: -1,
            ring_entries: 2048,
            bind_strategy: AfXdpBindStrategy::UmemOwnerSocket,
            poll_mode: crate::PollMode::Interrupt,
            shared_umem: shared,
        };

        let plan = prepare_shared_binding_plan_for_create(&group, plan, XskSocketRole::SharedOwner);
        let snap = live.snapshot();

        assert_eq!(plan.status.shared_umem_mode, "cross-nic");
        assert_eq!(plan.status.shared_umem_group, group);
        assert_eq!(plan.status.shared_umem_socket_role, "owner");
        assert_eq!(snap.shared_umem_mode, "cross-nic");
        assert_eq!(snap.shared_umem_group, plan.status.shared_umem_group);
        assert_eq!(snap.shared_umem_socket_role, "owner");
        assert_eq!(snap.shared_umem_disabled_reason, "");
    }

    #[test]
    fn publish_tx_completion_ring_telemetry_stores_before_reset() {
        let live = BindingLiveState::new();
        let mut telemetry = WorkerTelemetry {
            dbg_tx_completion_ring_available: 5,
            dbg_tx_completion_ring_available_max: 9,
            ..Default::default()
        };

        publish_tx_completion_ring_telemetry(&live, &mut telemetry);

        assert_eq!(live.tx_completion_ring_available.load(Ordering::Relaxed), 5);
        assert_eq!(
            live.tx_completion_ring_available_max
                .load(Ordering::Relaxed),
            9
        );
        assert_eq!(telemetry.dbg_tx_completion_ring_available, 0);
        assert_eq!(telemetry.dbg_tx_completion_ring_available_max, 0);
    }

    /// #4800: the worker-level `new_flow_installs` is the SUM over the
    /// worker's bindings, and the sum is what the whole series means — a
    /// worker owns several bindings (per NIC/queue), so a first-element or
    /// max read under-reports the worker's share and skews the very
    /// distribution the analyzer keys its cross-worker gates on
    /// (`active_workers < 3`, `max_worker_share > 0.60`).
    ///
    /// Three bindings with distinct primes, because two cannot separate the
    /// readings that matter: 7 / 11 / 101 sum to 119, while a first-element
    /// read gives 7, a last-element read 101, a max 101, and a count 3. Every
    /// degenerate reading lands on a different number.
    ///
    /// RED on revert: replacing the fold in
    /// `refresh_worker_new_flow_install_counters` with a first-element read
    /// (`.next()`/`[0]`), a `max`, or a constant fails the sum assertion on
    /// its message.
    #[test]
    fn refresh_worker_new_flow_install_counters_sums_across_bindings() {
        let bindings: Vec<BindingWorker> = [7u64, 11, 101]
            .iter()
            .enumerate()
            .map(|(slot, installs)| {
                let binding = BindingWorker::new_for_mirror_test(slot as u32, 0, 24, slot as u32);
                binding
                    .live
                    .new_flow_installs
                    .store(*installs, Ordering::Relaxed);
                binding
            })
            .collect();

        let mut counters = crate::afxdp::worker_runtime::WorkerRuntimeCounters::default();
        refresh_worker_new_flow_install_counters(&mut counters, &bindings);

        assert_eq!(
            counters.new_flow_installs, 119,
            "the worker counter must be the SUM over its bindings (7+11+101); \
             7 would be a first-element read, 101 a max or last-element read, \
             3 a count of bindings"
        );
    }

    /// #6971: the CoS lease / wheel refresh's own ARITHMETIC, which nothing
    /// covered — `refresh_worker_cos_queue_lease_runtime_counters` had zero
    /// references in the tree outside its definition and its one production
    /// call site. Its sibling `refresh_worker_new_flow_install_counters` had
    /// two direct tests; this one had none, so #6971's "the callees are bound"
    /// held for one of the two and not for this one.
    ///
    /// WHAT MAKES A MISTAKE VISIBLE HERE. The function folds SIX same-typed
    /// `u64` families off `binding.cos` onto `WorkerRuntimeCounters`, and one of
    /// them aggregates DIFFERENTLY from the other five:
    /// `cos_wheel_ticks_advanced_max` is a `.max()` while everything else is a
    /// `wrapping_add`. A fixture of equal or repeated values cannot separate
    /// `max` from `sum` from a first-element read, and cannot separate
    /// `counters.a = sum(binding.a)` from `counters.a = sum(binding.b)` — both
    /// assertions pass. So every seeded number is distinct, every EXPECTED
    /// number is distinct, and the wheel-max fixture is chosen so its `max`
    /// (97) and its `sum` (191) are different numbers.
    ///
    /// RED on revert: turning the `.max()` into a `wrapping_add` yields 191,
    /// turning any `wrapping_add` into a first-element read yields that
    /// binding's own value, and transposing any two of the six under-grant
    /// causes lands on another cause's expected total. Each fails on its own
    /// message.
    #[test]
    fn refresh_worker_cos_queue_lease_counters_sums_and_maxes_across_bindings_6971() {
        let seeds: [(u64, u64, u64, u64, [u64; 6]); 3] = [
            (7, 1_000_003, 13, 41, [101, 103, 107, 109, 113, 127]),
            (11, 2_000_003, 17, 97, [131, 137, 139, 149, 151, 157]),
            (101, 4_000_003, 19, 53, [163, 167, 173, 179, 181, 193]),
        ];
        let bindings: Vec<BindingWorker> = seeds
            .iter()
            .enumerate()
            .map(|(slot, (calls, granted, wheel_total, wheel_max, ug))| {
                let mut binding =
                    BindingWorker::new_for_mirror_test(slot as u32, 0, 24, slot as u32);
                binding.cos.cos_queue_lease_acquire_v8_calls = *calls;
                binding.cos.cos_queue_lease_acquire_v8_granted_bytes = *granted;
                binding.cos.cos_wheel_ticks_advanced_total = *wheel_total;
                binding.cos.cos_wheel_ticks_advanced_max = *wheel_max;
                binding.cos.cos_queue_lease_undergrants =
                    crate::afxdp::worker_runtime::CoSQueueLeaseUndergrantCounters {
                        seqlock_give_up: ug[0],
                        cap_zero: ug[1],
                        epoch_rotated: ug[2],
                        share_exhausted: ug[3],
                        class_cap: ug[4],
                        outstanding_cap: ug[5],
                    };
                binding
            })
            .collect();

        let mut counters = crate::afxdp::worker_runtime::WorkerRuntimeCounters::default();
        refresh_worker_cos_queue_lease_runtime_counters(&mut counters, &bindings);

        assert_eq!(
            counters.cos_queue_lease_acquire_v8_calls, 119,
            "lease acquire CALLS must be the SUM over this worker's bindings \
             (7+11+101); 7 would be a first-element read and 101 a max"
        );
        assert_eq!(
            counters.cos_queue_lease_acquire_v8_granted_bytes, 7_000_009,
            "lease GRANTED BYTES must be the SUM (1000003+2000003+4000003)"
        );
        assert_eq!(
            counters.cos_wheel_ticks_advanced_total, 49,
            "wheel ticks TOTAL must be the SUM (13+17+19)"
        );
        assert_eq!(
            counters.cos_wheel_ticks_advanced_max, 97,
            "wheel ticks MAX must be the MAXIMUM across bindings (max(41,97,53)), \
             not their sum — 191 here means the one field that aggregates \
             differently from its five neighbours was folded like them, and the \
             published per-worker catch-up depth becomes an invented number no \
             binding ever saw"
        );
        let ug = &counters.cos_queue_lease_undergrant;
        assert_eq!(ug.seqlock_give_up, 395, "under-grant seqlock_give_up sum");
        assert_eq!(ug.cap_zero, 407, "under-grant cap_zero sum");
        assert_eq!(ug.epoch_rotated, 419, "under-grant epoch_rotated sum");
        assert_eq!(ug.share_exhausted, 437, "under-grant share_exhausted sum");
        assert_eq!(ug.class_cap, 445, "under-grant class_cap sum");
        assert_eq!(
            ug.outstanding_cap, 477,
            "under-grant outstanding_cap sum. All six expected totals are \
             distinct (395/407/419/437/445/477), so transposing any two causes \
             lands on another cause's number and fails here rather than passing \
             with the attribution silently swapped"
        );
    }

    /// OVER-REACH GUARD for the CoS lease refresh, mirroring the one its
    /// sibling already has: it must leave the slots its neighbouring refreshers
    /// own alone. `new_flow_installs` is refreshed two lines below it on the
    /// same publish tick, so a CoS refresh that zeroed it would blank a counter
    /// that is about to be published — and #4800's two cross-worker analyzer
    /// gates key on exactly that series.
    ///
    /// Stays GREEN under every mutation the cell above catches: those change
    /// which number lands in the CoS slots, which this test does not read.
    #[test]
    fn refresh_worker_cos_queue_lease_counters_touches_no_other_slot_6971() {
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.cos.cos_queue_lease_acquire_v8_calls = 5;
        let bindings = vec![binding];

        let mut counters = crate::afxdp::worker_runtime::WorkerRuntimeCounters {
            new_flow_installs: 31,
            session_install_partial: 3,
            session_create_drops: 13,
            session_install_admission_refused: 17,
            ..Default::default()
        };
        refresh_worker_cos_queue_lease_runtime_counters(&mut counters, &bindings);

        assert_eq!(
            counters.new_flow_installs, 31,
            "the CoS lease refresh must not disturb new_flow_installs, which the \
             sibling refresher two lines below it owns"
        );
        assert_eq!(
            counters.session_install_partial, 3,
            "the CoS lease refresh must not disturb session_install_partial"
        );
        assert_eq!(
            counters.session_create_drops, 13,
            "the CoS lease refresh must not disturb session_create_drops"
        );
        assert_eq!(
            counters.session_install_admission_refused, 17,
            "the CoS lease refresh must not disturb session_install_admission_refused"
        );
    }

    /// OVER-REACH GUARD for the same refresh: it owns exactly ONE slot on
    /// `WorkerRuntimeCounters` and must leave every neighbouring slot alone.
    /// The neighbours are filled by sibling refreshers on the same ~1s
    /// cadence, so a refresh that reset or overwrote one of them would blank a
    /// counter that had just been published — the failure mode is silent, and
    /// the value it destroys (the #1861 install-refusal trio) is what tells an
    /// operator whether the new-flow rate is a ceiling or a refusal.
    ///
    /// Stays GREEN under the SUM->FIRST / SUM->MAX / constant mutations above:
    /// those change only which number lands in `new_flow_installs`, which this
    /// test does not read.
    #[test]
    fn refresh_worker_new_flow_install_counters_touches_no_other_slot() {
        let binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.live.new_flow_installs.store(5, Ordering::Relaxed);
        let bindings = vec![binding];

        let mut counters = crate::afxdp::worker_runtime::WorkerRuntimeCounters {
            session_install_partial: 3,
            session_create_drops: 13,
            session_install_admission_refused: 17,
            cos_queue_lease_acquire_v8_calls: 23,
            ..Default::default()
        };
        refresh_worker_new_flow_install_counters(&mut counters, &bindings);

        assert_eq!(
            counters.session_install_partial, 3,
            "the new-flow refresh must not disturb session_install_partial"
        );
        assert_eq!(
            counters.session_create_drops, 13,
            "the new-flow refresh must not disturb session_create_drops"
        );
        assert_eq!(
            counters.session_install_admission_refused, 17,
            "the new-flow refresh must not disturb session_install_admission_refused"
        );
        assert_eq!(
            counters.cos_queue_lease_acquire_v8_calls, 23,
            "the new-flow refresh must not disturb the CoS lease counters its \
             sibling refresher owns"
        );
    }
}
