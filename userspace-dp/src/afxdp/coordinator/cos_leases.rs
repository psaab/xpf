//! #1890: CoS runtime-map plumbing, split out of `coordinator/mod.rs`
//! (pure code motion). Owns the owner-worker map refresh methods
//! (`refresh_cos_owner_worker_map_from_{identities,binding_statuses}`
//! + `refresh_cos_runtime_maps`, which diff-and-store the SharedCoSState
//! Arcs) and the free-function builders/matchers they delegate to:
//! owner-by-queue assignment, active-shard counts, root/queue lease and
//! exact-backlog/vtime-floor construction with Arc-reuse discipline,
//! the Arc::ptr_eq match predicates, and the #710 cross-worker status
//! aggregation consumed by `status.rs`. `build_mirror_target_map` stays
//! in mod.rs — it is port-mirroring plumbing, not CoS. The
//! `SharedCoSState` container itself stays in `cos_state.rs`.
//!
//! Visibility (#1890): items with callers in sibling files of this
//! module — `reconcile/bringup.rs`, `refresh_bindings.rs`,
//! `snapshot_refresh.rs`, `status.rs`, `tests.rs` — are widened from
//! private-in-coordinator to `pub(super)` (same coordinator-subtree
//! audience; mod.rs re-imports the free functions so existing
//! coordinator-scope paths keep resolving). Builders and match
//! predicates called only from this file stay private.
use super::*;

impl super::Coordinator {
    pub(super) fn refresh_cos_owner_worker_map_from_identities(&mut self) {
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

    pub(super) fn refresh_cos_owner_worker_map_from_binding_statuses(
        &mut self,
        bindings: &[BindingStatus],
    ) {
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

    pub(super) fn refresh_cos_runtime_maps(
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
        let current_exact_backlogs = self.cos.exact_backlogs.load();
        // #917: V_min coordination Arcs sized so every planned worker
        // id is indexable. #1830 follow-up (Codex review on PR #1841):
        // this is last_planned_worker_slots (max planned worker id +
        // 1), NOT last_planned_workers (the COUNT) — worker ids can be
        // sparse after partial binding unregister, and a surviving
        // high-id worker must stay in range of the v8 lease per-worker
        // arrays (acquire_v8 out-of-range returns 0 + debug-panics)
        // and the V_min floor slots. Set in bring_up_workers before
        // this reconcile path fires; defaults to 0 at first boot which
        // produces zero-slot floors (the reconcile re-fires once
        // workers are planned).
        // #1229 Phase 6 v8: lease construction also needs this for
        // max_worker_id sizing of per-worker arrays. Hoisted ahead of
        // the queue_leases build site.
        let current_queue_vtime_floors = self.cos.queue_vtime_floors.load();
        let worker_slots = self.workers.last_planned_worker_slots().max(1);
        let current_queue_leases = self.cos.queue_leases.load();
        let max_binding_slot = self
            .workers
            .identities
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0) as usize;
        let next_exact_backlogs = build_shared_cos_exact_backlogs_reusing_existing(
            &self.forwarding,
            max_binding_slot,
            current_exact_backlogs.as_ref(),
        );
        let next_queue_leases = build_shared_cos_queue_leases_reusing_existing(
            &self.forwarding,
            &active_shards_by_egress_ifindex,
            worker_slots,
            current_queue_leases.as_ref(),
        );
        let next_queue_vtime_floors = build_shared_cos_queue_vtime_floors_reusing_existing(
            &self.forwarding,
            worker_slots,
            current_queue_vtime_floors.as_ref(),
        );
        if owner_changed {
            self.cos_owner_worker_by_queue = owner_map.clone();
            self.cos.owner_worker_by_queue.store(Arc::new(owner_map));
        }
        if !shared_cos_owner_live_by_queue_match(current_owner_live.as_ref(), &next_owner_live) {
            self.cos
                .owner_live_by_queue
                .store(Arc::new(next_owner_live));
        }
        if !shared_cos_root_leases_match(current_leases.as_ref(), &next_leases) {
            self.cos.root_leases.store(Arc::new(next_leases));
        }
        if !shared_cos_exact_backlogs_match(current_exact_backlogs.as_ref(), &next_exact_backlogs) {
            self.cos.exact_backlogs.store(Arc::new(next_exact_backlogs));
        }
        if !shared_cos_queue_leases_match(current_queue_leases.as_ref(), &next_queue_leases) {
            self.cos.queue_leases.store(Arc::new(next_queue_leases));
        }
        if !shared_cos_queue_vtime_floors_match(
            current_queue_vtime_floors.as_ref(),
            &next_queue_vtime_floors,
        ) {
            self.cos
                .queue_vtime_floors
                .store(Arc::new(next_queue_vtime_floors));
        }
    }
}

// #710: pure-function extraction of the coordinator-level aggregation
// so it can be unit-tested without constructing a full `Coordinator`
// fixture. The live bug this PR closes escaped CI because this exact
// summation layer lacked a regression; the function form lets us pin
// it in isolation. `Coordinator::cos_statuses` reads per-worker
// snapshots from `worker.cos_status` (built by
// `build_worker_cos_statuses` on the worker side) and sums them here.
pub(super) fn aggregate_cos_statuses_across_workers<S>(
    worker_snapshots: &[S],
    owner_by_queue: &BTreeMap<(i32, u8), u32>,
) -> Vec<crate::protocol::CoSInterfaceStatus>
where
    S: std::borrow::Borrow<Vec<crate::protocol::CoSInterfaceStatus>>,
{
    let mut interfaces = BTreeMap::<i32, crate::protocol::CoSInterfaceStatus>::new();
    let mut queue_maps = BTreeMap::<i32, BTreeMap<u8, crate::protocol::CoSQueueStatus>>::new();
    // #1628: tracks, per ifindex, whether the backlog-guarded
    // `waterfill_min_epochs_per_worker` MIN has been seeded by a first
    // active-exact-backlog worker yet. Cannot use `entry.worker_instances`
    // (counts idle workers too) nor `or_default()` (seeds 0, which would
    // pin a `.min()` to 0 forever — the r3 finding).
    let mut min_epochs_seeded = std::collections::HashSet::<i32>::new();
    for snapshot in worker_snapshots {
        for iface in snapshot.borrow().iter() {
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
            // #1628: per-interface waterfill counters. epochs +
            // phase1_budget_breaks SUM across workers (cluster event
            // counters, like timer_level*_sleepers).
            entry.waterfill_epochs =
                entry.waterfill_epochs.saturating_add(iface.waterfill_epochs);
            entry.waterfill_phase1_budget_breaks = entry
                .waterfill_phase1_budget_breaks
                .saturating_add(iface.waterfill_phase1_budget_breaks);
            // #1628 (code-review MAJOR): MIN-combine the PER-WORKER
            // `waterfill_min_epochs_per_worker` values, which the worker
            // side (interface_row.rs) already computed as the MIN over
            // each worker's OWN bindings-with-active-backlog — so a
            // healthy binding cannot mask a sibling locked binding within
            // one worker. A worker reports u64::MAX when it has NO
            // active-backlog binding (skip it); a backlogged binding that
            // completed 0 epochs reports 0 (the strongest lock-in signal,
            // which MUST be captured). Using the worker's per-binding MIN
            // (NOT iface.waterfill_epochs, the cross-binding SUM) is the
            // fix for the multi-binding masking the code review flagged.
            // Interfaces with at least one candidate are tracked in
            // `min_epochs_seeded`; interfaces with NO candidate are set to
            // u64::MAX after the loop (NOT 0) so an idle interface stays
            // distinguishable from a real 0-epoch lock-in.
            if iface.waterfill_min_epochs_per_worker != u64::MAX {
                if min_epochs_seeded.insert(iface.ifindex) {
                    entry.waterfill_min_epochs_per_worker =
                        iface.waterfill_min_epochs_per_worker;
                } else {
                    entry.waterfill_min_epochs_per_worker = entry
                        .waterfill_min_epochs_per_worker
                        .min(iface.waterfill_min_epochs_per_worker);
                }
            }
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
                q.guarantee_enabled = queue.guarantee_enabled;
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
                // #1830 (g): current occupied-bucket count SUMS across
                // workers (disjoint per-worker FlowFairState buckets),
                // matching the worker-side sum in queue_row.rs.
                q.flow_fair_buckets_occupied = q
                    .flow_fair_buckets_occupied
                    .saturating_add(queue.flow_fair_buckets_occupied);
                q.transmit_rate_bytes = q.transmit_rate_bytes.max(queue.transmit_rate_bytes);
                // #hb166 T-7: MAX, not SUM — `buffer_bytes` is a per-queue
                // CONFIG value identical across workers; summing reported N×
                // the configured buffer. Matches the worker-side fold in
                // queue_row.rs and the `transmit_rate_bytes` MAX above.
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
                // #1628: per-class waterfill trace counters, summed across
                // worker snapshots (same as the drop/park counters above).
                q.waterfill_phase1_admissions = q
                    .waterfill_phase1_admissions
                    .saturating_add(queue.waterfill_phase1_admissions);
                q.waterfill_phase2_admissions = q
                    .waterfill_phase2_admissions
                    .saturating_add(queue.waterfill_phase2_admissions);
                q.waterfill_eligible_visits = q
                    .waterfill_eligible_visits
                    .saturating_add(queue.waterfill_eligible_visits);
                // hb166 T-2: refunded zero-TX Phase-1 honored selections.
                q.waterfill_phase1_selected_no_progress = q
                    .waterfill_phase1_selected_no_progress
                    .saturating_add(queue.waterfill_phase1_selected_no_progress);
                // #1829 Phase 1: sojourn telemetry MAX-merges across
                // workers (worst instance), matching the worker-side
                // MAX in queue_row.rs — see the AGGREGATION contract
                // on `protocol::CoSQueueStatus`. Summing delays is
                // meaningless; the gate metric is "does ANY instance
                // sustain a standing queue".
                q.sojourn_ewma_ns = q.sojourn_ewma_ns.max(queue.sojourn_ewma_ns);
                q.sojourn_peak_ns = q.sojourn_peak_ns.max(queue.sojourn_peak_ns);
                q.sojourn_windowed_min_ns = q
                    .sojourn_windowed_min_ns
                    .max(queue.sojourn_windowed_min_ns);
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
        // #1628 (code-review r2, both reviewers): keep the u64::MAX
        // "no active-exact-backlog candidate" sentinel on the AGGREGATED
        // output too, rather than letting it collapse to the or_default()
        // 0. Otherwise an idle interface (0) and a hard 0-epoch lock-in
        // (0) collide and the metric is unalertable. With MAX preserved,
        // Prometheus suppresses the idle case (no series) and `0`
        // unambiguously means a backlogged binding that completed zero
        // epochs. An interface seeded by at least one active-backlog
        // worker keeps its real MIN (including a genuine 0).
        if !min_epochs_seeded.contains(&ifindex) {
            iface.waterfill_min_epochs_per_worker = u64::MAX;
        }
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

pub(super) fn unique_interface_owner_worker_id(
    queues: &[crate::protocol::CoSQueueStatus],
) -> Option<u32> {
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

pub(super) fn build_cos_owner_worker_by_queue(
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

pub(super) fn build_worker_binding_ifindexes_from_identities(
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

pub(super) fn build_cos_owner_worker_by_queue_from_binding_ifindexes(
    forwarding: &ForwardingState,
    worker_binding_ifindexes: &BTreeMap<u32, std::collections::BTreeSet<i32>>,
) -> BTreeMap<(i32, u8), u32> {
    build_cos_owner_worker_by_queue_with_fallback_ifindexes(
        forwarding,
        worker_binding_ifindexes,
        worker_binding_ifindexes,
    )
}

pub(super) fn build_cos_owner_worker_by_queue_with_fallback_ifindexes(
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

pub(super) fn build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes(
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

pub(super) fn build_shared_cos_root_leases(
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

pub(super) fn build_shared_cos_root_leases_reusing_existing(
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

fn build_shared_cos_exact_backlogs_reusing_existing(
    forwarding: &ForwardingState,
    max_binding_slot: usize,
    existing: &BTreeMap<i32, Arc<SharedCoSExactBacklog>>,
) -> BTreeMap<i32, Arc<SharedCoSExactBacklog>> {
    let mut out = BTreeMap::new();
    for (&ifindex, iface) in &forwarding.cos.interfaces {
        if !iface.queues.iter().any(|queue| queue.exact) {
            continue;
        }
        if let Some(backlog) = existing
            .get(&ifindex)
            .filter(|backlog| backlog.matches_config(max_binding_slot))
        {
            out.insert(ifindex, backlog.clone());
            continue;
        }
        out.insert(
            ifindex,
            Arc::new(SharedCoSExactBacklog::new(max_binding_slot)),
        );
    }
    out
}

pub(super) fn build_shared_cos_queue_leases_reusing_existing(
    forwarding: &ForwardingState,
    active_shards_by_egress_ifindex: &BTreeMap<i32, usize>,
    worker_slots: usize,
    existing: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
) -> BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>> {
    // #1229 Phase 6 v8 / #1830 follow-up (Codex review on PR #1841):
    // `worker_slots` is `max(planned worker_id) + 1` from
    // `planned_worker_slots` (reconcile/bringup.rs), NOT the worker
    // COUNT — worker ids can be sparse after partial binding
    // unregister, and the lease contract (`new_v8` doc) requires the
    // TRUE max id so per-worker arrays + rotation scratch cover every
    // live worker. `last_planned_worker_slots` is the same source the
    // V_min floors size against
    // (build_shared_cos_queue_vtime_floors_reusing_existing).
    let max_worker_id = worker_slots.saturating_sub(1);
    let mut out = BTreeMap::new();
    for (&ifindex, iface) in &forwarding.cos.interfaces {
        let active_shards = active_shards_by_egress_ifindex
            .get(&ifindex)
            .copied()
            .unwrap_or(1)
            .max(1);
        for queue in &iface.queues {
            if queue.transmit_rate_bytes == 0 {
                continue;
            }
            let burst_bytes = queue.buffer_bytes.max(64 * 1500);
            let key = (ifindex, queue.queue_id);
            if !queue.exact {
                // #4265 (R-2): a non-exact GUARANTEED queue that runs the
                // sharded `shared_exact` execution policy (its rate trips
                // `COS_SHARED_EXACT_MIN_RATE_BYTES`, so it drains locally on
                // EVERY worker rather than being funnelled to one owner) is
                // serviced through `select_nonexact_cos_guarantee_batch`,
                // which refilled a PRIVATE per-worker token bucket at the
                // FULL configured rate — admitting the guarantee at up to
                // N_workers x its rate. Attach a SHARED LEGACY lease
                // (`SharedCoSQueueLease::new`, v8=None: one greedy-aggregate
                // token bucket all workers draw from) so the class-wide
                // guarantee admission is metered to the configured rate
                // while staying work-conserving (a single busy worker can
                // drain the whole shared pool). Low-rate non-exact queues
                // stay single-owner (one worker services them; no
                // over-admission) and get no lease. The legacy lease has no
                // v8 epoch ledger, so it sidesteps the #4246 T-1 / R-5(a)
                // accounting hole. `active_shards` sizing means a worker
                // join/leave rebuilds the lease via `matches_config`, the
                // same discipline the exact v8 lease uses.
                // #5156: single source of truth for "non-exact queue is
                // lease-metered" — the runtime builder gates its 0-token
                // init on the SAME predicate, so the lease's init charge and
                // teardown give-back stay symmetric. `transmit_rate_bytes ==
                // 0` was already excluded by the guard above.
                if !queue.is_shared_lease_metered() {
                    continue;
                }
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
                continue;
            }
            let rate_mode = if queue.equal_flow_enforcement {
                V8RateMode::EqualFlowSuppress
            } else {
                V8RateMode::CstructDefault
            };
            // #1746: per-queue equal-flow target policy. forwarding_build
            // gates it on equal_flow_enforcement, so CstructDefault
            // queues always carry the default `Slowest` here and never
            // force a spurious lease rebuild.
            let equal_flow_target_policy = queue.equal_flow_target_policy;
            // #1229 Phase 6 v8: emit v8 leases for guarantee-phase
            // exact queues. Reuse existing lease only if v8 mode AND
            // max_worker_id/mode match (otherwise rebuild).
            if let Some(lease) = existing.get(&key).filter(|lease| {
                lease.matches_config_v8(
                    queue.transmit_rate_bytes,
                    burst_bytes,
                    active_shards,
                    max_worker_id,
                    rate_mode,
                    equal_flow_target_policy,
                )
            }) {
                out.insert(key, lease.clone());
                continue;
            }
            out.insert(
                key,
                Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
                    queue.transmit_rate_bytes,
                    burst_bytes,
                    active_shards,
                    max_worker_id,
                    rate_mode,
                    equal_flow_target_policy,
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

fn shared_cos_exact_backlogs_match(
    current: &BTreeMap<i32, Arc<SharedCoSExactBacklog>>,
    next: &BTreeMap<i32, Arc<SharedCoSExactBacklog>>,
) -> bool {
    current.len() == next.len()
        && current.iter().all(|(ifindex, backlog)| {
            next.get(ifindex)
                .is_some_and(|next| Arc::ptr_eq(backlog, next))
        })
}

/// #917: build/reuse the per-shared_exact-queue V_min
/// coordination Arcs. Mirror of
/// `build_shared_cos_queue_leases_reusing_existing` — same
/// keying ((ifindex, queue_id)), same Arc-reuse discipline.
/// Each queue's `SharedCoSQueueVtimeFloor` is sized by
/// `worker_slots` (#1830 follow-up: max planned worker id + 1, NOT
/// the worker count — slots are indexed by worker id and ids can be
/// sparse); if the slot requirement changes we reallocate (slot
/// count is fixed for the Arc's lifetime).
pub(super) fn build_shared_cos_queue_vtime_floors_reusing_existing(
    forwarding: &ForwardingState,
    worker_slots: usize,
    existing: &BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>,
) -> BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>> {
    let num_workers = worker_slots.max(1);
    let mut out = BTreeMap::new();
    for (&ifindex, iface) in &forwarding.cos.interfaces {
        for queue in &iface.queues {
            // #917 Codex Q8: gate on shared_exact at allocation
            // time so owner-local-exact queues don't carry a
            // V_min floor. Owner-local queues have no peers
            // (single-owner by definition); a floor on those
            // would only consume memory and risk false
            // throttling if the read-path gate ever
            // regresses.
            //
            // #1598: this filter is intentionally STRICTER than the
            // routing-side `queue_uses_shared_exact_service` gate in
            // `worker/cos/mod.rs`. The routing-side gate admits
            // high-rate non-exact queues (e.g. uncapped class with a
            // fallback rate equal to the interface shaping rate) to
            // sharded multi-worker drain. V_min coordination is an
            // exact-only concept (per-queue lease serves the
            // configured rate cap); allocating a floor for non-exact
            // queues would be useless work. So both gates keep their
            // own predicate: shared_exact-routing is broader,
            // V_min-floor is exact-only.
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
        && current
            .iter()
            .all(|(key, floor)| next.get(key).is_some_and(|next| Arc::ptr_eq(floor, next)))
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
