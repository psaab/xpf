use super::*;
// #5289: per-worker exception-ring reconstruction on the status thread.
use crate::afxdp::disposition::{
    EXCEPTION_RING_CAPACITY, ExceptionEvent, MonoWallAnchor, ResolutionEvent,
};

/// Operator-status surface split out of `coordinator/mod.rs` to keep
/// the gRPC / HTTP status methods in one place. Most are pure-read
/// snapshots (e.g. `cos_statuses` loads ArcSwap values and aggregates
/// them); the one exception is `drain_session_deltas`, which mutates
/// per-binding state by popping entries off `pending_session_deltas`
/// and bumping `session_delta_drained`. Coordinator lifecycle
/// (worker spawn / shutdown / reconcile) and HA reconciliation state
/// stay in mod.rs and ha.rs.
impl super::Coordinator {
    pub fn dynamic_neighbor_status(&self) -> (usize, u64) {
        let entries = self.neighbors.dynamic.len();
        let generation = self.neighbors.generation.load(Ordering::Relaxed);
        (entries, generation)
    }

    /// #6034: the highest authoritative manager-neighbor REPLACE generation
    /// applied so far (ACK'd back to the Go manager in `ProcessStatus`).
    /// Distinct from `dynamic_neighbor_status`'s resolver epoch — this only
    /// advances on an accepted versioned `update_neighbors` replace and lets
    /// the manager confirm a clear/replace landed (retaining retry debt on a
    /// non-advanced ACK).
    pub fn last_applied_manager_neighbor_generation(&self) -> u64 {
        self.neighbors
            .applied_manager_generation
            .load(Ordering::Relaxed)
    }

    /// #5673: cumulative data-path neighbor learns refused by the aggregate
    /// dynamic-neighbor map cap (`MAX_DYNAMIC_NEIGHBORS_PER_SHARD`). The
    /// counter is a single map-wide atomic (the map is shared across all
    /// workers via `Arc`), so this reads it directly rather than summing
    /// per-binding like the `pending_neigh_*` counters. Surfaced as
    /// `xpf_userspace_dynamic_neighbor_learn_cap_drops_total`.
    pub fn dynamic_neighbor_learn_cap_drops_total(&self) -> u64 {
        self.neighbors.dynamic.learn_cap_drops()
    }

    /// #3773 (M13): cumulative count of fabric links skipped for a MALFORMED
    /// value (invalid parent ifindex / unparseable peer address / a NON-EMPTY
    /// unparseable local|peer MAC). Surfaced as
    /// `xpf_userspace_fabric_link_skipped_malformed_total`.
    pub fn fabric_link_skipped_malformed_total(&self) -> u64 {
        crate::afxdp::forwarding::FABRIC_LINK_SKIPPED_MALFORMED.load(Ordering::Relaxed)
    }

    /// #3773 (M13): cumulative count of fabric links skipped for an UNRESOLVED
    /// peer/local MAC (an EMPTY MAC field awaiting neighbor/interface
    /// resolution — the expected late-resolution transient). Surfaced as
    /// `xpf_userspace_fabric_link_unresolved_peer_total`.
    pub fn fabric_link_unresolved_peer_total(&self) -> u64 {
        crate::afxdp::forwarding::FABRIC_LINK_UNRESOLVED_PEER.load(Ordering::Relaxed)
    }

    /// #710: sum of `no_owner_binding_drops` across every binding's
    /// `BindingLiveState`. The per-binding increment site lives in
    /// `apply_worker_shaped_tx_requests` and mechanically lands on
    /// `bindings.first_mut()` (there is no binding to attribute to —
    /// the whole point of the counter is that the request's egress
    /// has no binding on this worker). Summing across every binding's
    /// live state gives the cluster-wide total regardless of which
    /// worker's "first binding" the increments landed on. This is the
    /// only operator-facing surface for this counter.
    pub fn cos_no_owner_binding_drops_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.no_owner_binding_drops.load(Ordering::Relaxed))
            .sum()
    }

    /// #1782: sum of per-binding `neg_neigh_fast_fail` across every
    /// `BindingLiveState`. Mirrors `cos_no_owner_binding_drops_total`:
    /// the increment lands on whichever binding owns the worker that
    /// fast-failed, and summing across all live states gives the
    /// cluster-wide total. Surfaced as
    /// `xpf_userspace_neg_neigh_fast_fail_total`.
    pub fn neg_neigh_fast_fail_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.neg_neigh_fast_fail.load(Ordering::Relaxed))
            .sum()
    }

    /// #1782: sum of per-binding `pending_neigh_duplicate_drops` across
    /// every `BindingLiveState`. Counts ONLY the H5 sibling drops where
    /// the `(egress_ifindex, next_hop)` key was already pending — not
    /// the capacity-drop case. Surfaced as
    /// `xpf_userspace_pending_neigh_duplicate_drops_total`.
    pub fn pending_neigh_duplicate_drops_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.pending_neigh_duplicate_drops.load(Ordering::Relaxed))
            .sum()
    }

    /// #1902: sum of per-binding `pending_neigh_decap_drops` across
    /// every `BindingLiveState`. Counts GRE-decapped MissingNeighbor
    /// packets refused pending_neigh admission (the buffered desc/meta
    /// pairing would retry-TX a mis-rewritten outer frame). Surfaced as
    /// `xpf_userspace_pending_neigh_decap_drops_total`.
    pub fn pending_neigh_decap_drops_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.pending_neigh_decap_drops.load(Ordering::Relaxed))
            .sum()
    }

    /// #2375: sum of per-binding `pending_neigh_capacity_drops` across
    /// every `BindingLiveState`. Counts MissingNeighbor packets for a
    /// NEW distinct `(egress_ifindex, next_hop)` refused because
    /// `pending_neigh` is at `MAX_PENDING_NEIGH` distinct hops — the
    /// distinct-hop exhaustion / scan failure mode. Kept separate from
    /// `pending_neigh_duplicate_drops_total` (normal cold-start
    /// coalescing). Surfaced as
    /// `xpf_userspace_pending_neigh_capacity_drops_total`.
    pub fn pending_neigh_capacity_drops_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.pending_neigh_capacity_drops.load(Ordering::Relaxed))
            .sum()
    }

    /// #1771 §2.6: distinct unresolved `(egress_ifindex, next_hop)` keys
    /// currently buffered across every binding's `pending_neigh` map
    /// (gauge). Each per-binding value is a `len()` snapshot published
    /// by the owning worker at its ~65ms debug-state tick; the sum is
    /// the cluster-wide count of next-hops with a packet parked waiting
    /// for neighbor resolution. Surfaced as
    /// `xpf_userspace_neighbor_pending_keys`.
    pub fn neighbor_pending_keys_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.pending_neigh_keys.load(Ordering::Relaxed))
            .sum()
    }

    /// #1771 §2.6: keys currently held across every binding's negative
    /// neighbor cache (gauge; lazy-TTL upper bound — see the
    /// `BindingLiveState::neg_neigh_keys` doc). Surfaced as
    /// `xpf_userspace_neg_neigh_keys`.
    pub fn neg_neigh_keys_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.neg_neigh_keys.load(Ordering::Relaxed))
            .sum()
    }

    /// #1789: total failed USERSPACE_SESSIONS BPF-map publishes. Sum of
    /// the per-binding `session_publish_errors` atomics (worker poll
    /// sites, mirroring `neg_neigh_fast_fail_total`) plus the shared
    /// `SESSION_PUBLISH_ERRORS_SHARED` static (HA upsert, session-glue
    /// worker publish, post-reconcile replay, activation/reverse prewarm
    /// — sites with no binding context). A nonzero value is the
    /// cause-side signal for rising XDP-shim NO_SESSION degraded-path
    /// fallbacks (session map at capacity, stale/invalid fd after
    /// reconcile). Surfaced as
    /// `xpf_userspace_session_publish_errors_total`.
    pub fn session_publish_errors_total(&self) -> u64 {
        let per_binding: u64 = self
            .workers
            .live
            .values()
            .map(|live| live.session_publish_errors.load(Ordering::Relaxed))
            .sum();
        per_binding.saturating_add(SESSION_PUBLISH_ERRORS_SHARED.load(Ordering::Relaxed))
    }

    /// #4800 new-flow-install contention surface. Six process-global
    /// counters that, read as three (denominator, contended) pairs plus a
    /// depth high-water, say WHICH of the cross-worker synchronization
    /// points on the new-flow install path is saturating — the question a
    /// flat new-flows/sec plateau cannot answer on its own.
    ///
    /// `shared_session_publishes_total` is the publish-leg new-flow rate;
    /// `shared_session_publish_lock_{acquisitions,contended}_total` are the
    /// map-mutex pair scoped to `publish_shared_session` alone.
    /// `session_replication_{upserts,enqueued}_total` give the call rate
    /// and the N-way fan-out multiplier (`enqueued / upserts` = sibling
    /// worker count), `session_replication_lock_contended_total` is the
    /// blocked subset of those enqueues, and
    /// `session_replication_queue_depth_max` is the monotonic high-water
    /// sibling-queue depth — contention means producers collided, depth
    /// means the consumer is not keeping up, and the two have different
    /// remedies.
    ///
    /// Surfaced as `xpf_userspace_shared_session_publishes_total` and
    /// siblings. The NAT-allocator leg of the same question lives on the
    /// per-pool `SourceNatPoolStatus` (`live_lock_*`), because that mutex
    /// is per pool, not per process.
    pub fn shared_session_publishes_total(&self) -> u64 {
        crate::afxdp::shared_ops::SHARED_SESSION_PUBLISHES.load(Ordering::Relaxed)
    }

    pub fn shared_session_publish_lock_acquisitions_total(&self) -> u64 {
        crate::afxdp::shared_ops::SHARED_SESSION_PUBLISH_LOCK_ACQUISITIONS.load(Ordering::Relaxed)
    }

    pub fn shared_session_publish_lock_contended_total(&self) -> u64 {
        crate::afxdp::shared_ops::SHARED_SESSION_PUBLISH_LOCK_CONTENDED.load(Ordering::Relaxed)
    }

    /// #8486: owner-RG index filings declined because the peer-supplied
    /// `owner_rg_id` was outside the 0..15 range the Go strict validator
    /// enforces.
    ///
    /// Exposed rather than left as an internal counter, because an internal
    /// counter nothing reads is a claim written into inert code: it would
    /// record the decline and no operator would ever see one. Nonzero here
    /// means a peer is sending redundancy-group ids this cluster's own strict
    /// path would reject — a config skew worth investigating, and the only
    /// externally visible sign that the bound is doing anything.
    ///
    /// Counts ONLY out-of-range ids. The ordinary "no redundancy group" case
    /// (id 0, which every standalone session carries) is not a decline and is
    /// not counted; counting it would make this read as an attack on every
    /// non-clustered box and bury the signal.
    pub fn owner_rg_filings_declined_total(&self) -> u64 {
        crate::afxdp::shared_ops::OWNER_RG_FILINGS_DECLINED.load(Ordering::Relaxed)
    }

    pub fn session_replication_upserts_total(&self) -> u64 {
        crate::afxdp::session_glue::SESSION_REPLICATION_UPSERTS.load(Ordering::Relaxed)
    }

    pub fn session_replication_enqueued_total(&self) -> u64 {
        crate::afxdp::session_glue::SESSION_REPLICATION_ENQUEUED.load(Ordering::Relaxed)
    }

    pub fn session_replication_lock_contended_total(&self) -> u64 {
        crate::afxdp::session_glue::SESSION_REPLICATION_LOCK_CONTENDED.load(Ordering::Relaxed)
    }

    pub fn session_replication_queue_depth_sum(&self) -> u64 {
        crate::afxdp::session_glue::SESSION_REPLICATION_QUEUE_DEPTH_SUM.load(Ordering::Relaxed)
    }

    pub fn session_replication_queue_depth_max(&self) -> u64 {
        crate::afxdp::session_glue::SESSION_REPLICATION_QUEUE_DEPTH_MAX.load(Ordering::Relaxed)
    }

    /// #2244: total failed `dnat_table` reverse-SNAT BPF-map publishes.
    /// Sum of the per-binding `dnat_publish_errors` atomics bumped on the
    /// two worker poll-path `publish_dnat_table_entry` call sites whose
    /// `bpf_map_update_elem` return code was previously discarded, PLUS the
    /// shared `DNAT_PUBLISH_ERRORS_SHARED` static bumped on the coordinator's
    /// peer-synced install path (`upsert_synced_session`, #4393), which has no
    /// per-binding context. The `dnat_table` backs embedded-ICMP NAT reversal
    /// (PMTUD / traceroute inbound ICMP errors mapped back to the pre-NAT
    /// source); a failed publish silently drops the reverse record, so a
    /// nonzero value is the cause-side signal for `dnat_table` capacity
    /// pressure or kernel resource exhaustion. Surfaced as
    /// `xpf_userspace_dnat_publish_errors_total`.
    pub fn dnat_publish_errors_total(&self) -> u64 {
        let per_binding: u64 = self
            .workers
            .live
            .values()
            .map(|live| live.dnat_publish_errors.load(Ordering::Relaxed))
            .sum();
        per_binding.saturating_add(DNAT_PUBLISH_ERRORS_SHARED.load(Ordering::Relaxed))
    }

    /// #2170: total stale-generation installs refused by the helper's
    /// in-memory SyncedSessionEntry guard (the delayed-stale-install
    /// variant). The authoritative guard is in the Go cluster apply layer;
    /// this is the helper-side back-stop counter.
    pub fn session_install_stale_ignored_total(&self) -> u64 {
        self.sessions.install_stale_ignored.load(Ordering::Relaxed)
    }

    /// #7209: peer-synced imports whose zone pair did not resolve, so the
    /// source-NAT reservation skipped #6211's narrowing. See the field's doc on
    /// `session_manager.rs` for what an operator actually loses.
    pub fn synced_import_zone_unresolved_total(&self) -> u64 {
        self.sessions
            .synced_import_zone_unresolved
            .load(Ordering::Relaxed)
    }

    /// #7209: peer-synced imports that passed the local-replace guard but had
    /// no kernel session map to publish into. See the field's doc on
    /// `session_manager.rs` for why a nonzero value is expected today and what
    /// it is the instrument for.
    pub fn synced_import_unpublished_total(&self) -> u64 {
        self.sessions
            .synced_import_unpublished
            .load(Ordering::Relaxed)
    }

    /// #7209: reverse companions re-derived at reconcile replay because the
    /// stored one disagreed with what the live forwarding table resolves. See
    /// the field's doc on `session_manager.rs` for when a nonzero value is
    /// expected.
    pub fn synced_reverse_rederived_total(&self) -> u64 {
        self.sessions
            .synced_reverse_rederived
            .load(Ordering::Relaxed)
    }

    /// #2170: total stale-generation deletes refused by the helper's
    /// in-memory SyncedSessionEntry guard (belt-and-suspenders for any
    /// helper-side generation-aware delete).
    pub fn session_delete_stale_ignored_total(&self) -> u64 {
        self.sessions.delete_stale_ignored.load(Ordering::Relaxed)
    }

    /// #6979 F4: `DeleteSynced` commands dropped by a full worker command queue
    /// whose NAT reservation the coordinator released on the worker's behalf.
    pub fn session_delete_dropped_released_total(&self) -> u64 {
        self.sessions
            .delete_dropped_released
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// #8138: import-time `Untracked` reservations the tunnel-remap purge
    /// actually freed. See `tunnel_purge_reservations_released`.
    pub fn tunnel_purge_reservations_released_total(&self) -> u64 {
        self.sessions
            .tunnel_purge_reservations_released
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// #5674: total peer-synced session imports rejected by the coordinator's
    /// aggregate admission bound (`upsert_synced_session`). Locally-created
    /// sessions are capped per worker at `DEFAULT_MAX_SESSIONS`; peer-synced
    /// imports were previously uncapped and fanned out to every worker, so a
    /// peer under session-table pressure (or a compromised peer) could drive
    /// this node past its own aggregate session ceiling. A rising value means a
    /// peer exceeded this appliance's ceiling.
    ///
    /// #6413: state that ceiling in ENTRIES, matching `synced_import_cap` and
    /// `coordinator/session_manager.rs` — it is
    /// `2 * worker_count * DEFAULT_MAX_SESSIONS`,
    /// not the LOGICAL `worker_count * DEFAULT_MAX_SESSIONS`. Each admitted
    /// forward publishes TWO keys into `sessions.synced` (the forward and its
    /// synthesized reverse companion), so N logical sessions arrive as 2N
    /// entries and EXACTLY fit the 2N cap. A legitimate symmetric-pair failover
    /// therefore never trips it; firing semantics are unchanged by this wording.
    /// Surfaced as `xpf_userspace_synced_import_cap_drops_total`.
    pub fn synced_import_cap_drops_total(&self) -> u64 {
        self.sessions.import_cap_drops.load(Ordering::Relaxed)
    }

    /// #7160 (#2387): peer-synced imports refused because this node runs
    /// routing instances and the request named no ingress identity to resolve
    /// the session's routing domain from. See
    /// `SessionManager::import_unknown_routing_domain` for what a nonzero
    /// value means and why it cannot fire on a single-instance node.
    pub fn synced_import_unknown_routing_domain_total(&self) -> u64 {
        self.sessions
            .import_unknown_routing_domain
            .load(Ordering::Relaxed)
    }

    /// #6600: peer-synced imports refused because this node could not reserve
    /// the translated NAT port the session names. See
    /// `SessionManager::import_reserve_refused` for what a nonzero value means.
    pub fn synced_import_reserve_refused_total(&self) -> u64 {
        self.sessions.import_reserve_refused.load(Ordering::Relaxed)
    }

    /// #1760 W3': shared-map NAT reverse-key displacement events — a
    /// `publish_shared_session` insert into `shared_nat_sessions`
    /// displaced a DIFFERENT forward session's entry at the same reverse
    /// key. The shared map is the single choke point every transit
    /// forward NAT session passes through (including
    /// `MissingNeighborSeed` installs, which never replicate to sibling
    /// workers and are invisible to the per-worker
    /// `nat_reverse_key_collisions` counter), so this is the
    /// authoritative collision watch. Event count, not a pair census
    /// (docs/research/1760-reverse-key-v2/plan.md §2.3). Surfaced as
    /// `xpf_userspace_session_nat_reverse_key_shared_displacements_total`.
    pub fn nat_reverse_key_shared_displacements_total(&self) -> u64 {
        crate::afxdp::shared_ops::NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed)
    }

    /// #6751 PR 2/3: interface-mode SNAT identity-mint conflicts that took the
    /// PAT probe. A nonzero value is the two-flows-one-identity shape actually
    /// occurring; the LATER flow's wire source port moved so its replies stay
    /// distinguishable. Surfaced as
    /// `xpf_userspace_interface_snat_pat_collisions_total`.
    pub fn interface_snat_pat_collisions_total(&self) -> u64 {
        crate::nat::INTERFACE_SNAT_PAT_COLLISIONS.load(Ordering::Relaxed)
    }

    /// #7056 (#5798 required-fix #5): fragment-association misses where a
    /// same-datagram entry existed under a DIFFERENT ingress security domain.
    /// The fail-closed refusal itself is #6835's; this is the observability
    /// half, and it is the one miss cause that describes the TRAFFIC rather
    /// than cache pressure. Surfaced as
    /// `xpf_userspace_nat64_frag_cross_domain_misses_total`.
    pub fn nat64_frag_cross_domain_misses_total(&self) -> u64 {
        crate::fragment_assoc::NAT64_FRAG_CROSS_DOMAIN_MISSES.load(Ordering::Relaxed)
    }

    /// #7056: the sibling leg — same ingress domain, different upper-layer
    /// protocol, i.e. a TCP and a UDP datagram that collided on
    /// `(src, dst, ident)` and were separated by the #5798 `protocol` key
    /// field. Kept DISTINCT from the cross-domain counter because the two are
    /// different operator stories. Surfaced as
    /// `xpf_userspace_nat64_frag_protocol_alias_misses_total`.
    pub fn nat64_frag_protocol_alias_misses_total(&self) -> u64 {
        crate::fragment_assoc::NAT64_FRAG_PROTOCOL_ALIAS_MISSES.load(Ordering::Relaxed)
    }

    /// #6751 PR 2/3: interface-mode SNAT admissions that failed CLOSED with no
    /// free translated identity for their `(egress, remote)` pair, plus
    /// peer-synced imports refused for the same reason. Surfaced as
    /// `xpf_userspace_interface_snat_identity_exhaustion_total`.
    pub fn interface_snat_identity_exhaustion_total(&self) -> u64 {
        crate::nat::INTERFACE_SNAT_IDENTITY_EXHAUSTION.load(Ordering::Relaxed)
    }

    /// #6751 PR 2/3: peer-synced interface-SNAT imports dropped because a
    /// different live flow here already owns the translated identity the
    /// active assigned. Non-zero means individual synced flows will not
    /// survive a failover onto this node. Surfaced as
    /// `xpf_userspace_interface_snat_sync_identity_conflict_drops_total`.
    pub fn interface_snat_sync_identity_conflict_drops_total(&self) -> u64 {
        crate::nat::INTERFACE_SNAT_SYNC_IDENTITY_CONFLICT_DROPS.load(Ordering::Relaxed)
    }

    /// #6751 PR 2/3: interface-mode SNAT admissions that failed CLOSED because
    /// the registry could create no further state. Kept apart from identity
    /// exhaustion: this one says raise capacity, that one says the identity
    /// space for one remote is genuinely full. Surfaced as
    /// `xpf_userspace_interface_snat_registry_cap_exhaustion_total`.
    pub fn interface_snat_registry_cap_exhaustion_total(&self) -> u64 {
        crate::nat::INTERFACE_SNAT_REGISTRY_CAP_EXHAUSTION.load(Ordering::Relaxed)
    }

    /// #1807: total worker-command-queue poison recoveries across every
    /// producer/consumer site (worker poll peek + apply, HA enqueues,
    /// session replication, activation prewarm, tunnel install/drain-wait,
    /// cross-binding shaped-TX redirect). Each recovery means a thread
    /// panicked while holding a command-queue mutex and the committed
    /// queue was recovered + the poison cleared (worker_queue.rs policy,
    /// extends #1790). Surfaced as
    /// `xpf_userspace_worker_command_queue_poison_recoveries_total`; a
    /// nonzero value says a worker panic happened (see #925 supervisor)
    /// and the queues kept flowing.
    pub fn worker_command_queue_poison_recoveries_total(&self) -> u64 {
        crate::afxdp::worker_queue::WORKER_COMMAND_QUEUE_POISON_RECOVERIES.load(Ordering::Relaxed)
    }

    /// #6929: total worker commands refused because the target per-worker
    /// queue was already at `MAX_PENDING_WORKER_COMMANDS`.
    ///
    /// Deliberately NOT folded into the poison counter above: that one says
    /// a queue was recovered and nothing was lost, this one says a command
    /// was discarded, and the two have opposite remediations. Surfaced as
    /// `xpf_userspace_worker_command_queue_drops_total`. A nonzero value
    /// means a producer found a full queue, which — since the consumer
    /// takes the whole deque per poll — points at a worker that stopped
    /// draining rather than at a fast producer.
    pub fn worker_command_queue_drops_total(&self) -> u64 {
        crate::afxdp::worker_queue::WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed)
    }

    /// #8586: cross-worker `DeleteSynced` replicas a full sibling queue refused.
    /// Surfaced as `xpf_userspace_session_delete_replica_dropped_total`.
    ///
    /// Separate from `worker_command_queue_drops_total` because losing a DELETE
    /// and losing an UPSERT are not the same event: the upsert's content is
    /// still in the shared map, while a lost delete leaves a sibling serving a
    /// session that no longer exists AND holding its NAT reservation for the
    /// life of the allocator (#8576).
    pub fn session_delete_replica_dropped_total(&self) -> u64 {
        crate::afxdp::SESSION_DELETE_REPLICA_DROPPED.load(Ordering::Relaxed)
    }

    /// #8586: the subset of the above whose owning worker was identified, so
    /// #8576's NAT teardown ran on its behalf. The DIFFERENCE from the counter
    /// above is the unattributed remainder — a refused delete nothing repaired.
    pub fn session_delete_replica_drop_repaired_total(&self) -> u64 {
        crate::afxdp::SESSION_DELETE_REPLICA_DROP_REPAIRED.load(Ordering::Relaxed)
    }

    /// #9048: peer `DeleteSynced` commands REFUSED because the key named a
    /// live session this node created itself and is actively forwarding for.
    ///
    /// Non-zero means the cluster is, or recently was, DUAL-PRIMARY for some
    /// redundancy group. The delta emitter is gated on `IsPrimaryForRGFn`, so
    /// in normal operation exactly one node emits deletes and the receiver's
    /// entries at those keys carry a peer-synced origin — the guard is inert
    /// and this stays flat at zero. A climbing count is a split-brain
    /// indicator, and it is the ONLY surface that reports the condition: the
    /// refusal itself is silent by design, because the shape that produces it
    /// produces one per closing flow.
    pub fn peer_delete_refused_local_owned_total(&self) -> u64 {
        crate::afxdp::PEER_DELETE_REFUSED_LOCAL_OWNED.load(Ordering::Relaxed)
    }

    /// #2402/#6641: total shared-session mutex poison recoveries across
    /// every shared-session and owner-RG-index site (publish, remove,
    /// lookups, index maintenance, and the #5154 HA import
    /// generation-guard reads). Each recovery means a worker thread
    /// panicked while holding one of those mutexes and the committed map
    /// was recovered rather than lost — the #2402 policy, which exists
    /// because substituting an empty table silently dropped every active
    /// synced session at the moment of failover.
    ///
    /// Surfaced as
    /// `xpf_userspace_shared_session_poison_recoveries_total`. Nonzero
    /// means a worker panic happened (see #925 supervisor) and HA state
    /// survived it. The recovery is deliberately self-healing
    /// (`clear_poison` restores the fast path), so without this counter
    /// the only record was a sparse journald line — the twin of the
    /// #1807 counter directly above, which was already surfaced.
    pub fn shared_session_poison_recoveries_total(&self) -> u64 {
        crate::afxdp::shared_ops::SHARED_SESSION_POISON_RECOVERIES.load(Ordering::Relaxed)
    }

    /// #2315: GRE-decap frames dropped by the RFC 6040 §4.2 decap-side
    /// ECN combine because the outer header carried a CE mark over an
    /// inner packet that was Not-ECT (the illegal combination — a
    /// congested router CE-marked a packet whose endpoints never
    /// negotiated ECN). RFC 6040 mandates a drop here. Surfaced as
    /// `xpf_userspace_gre_decap_ecn_illegal_drops_total`; a nonzero
    /// value flags a misbehaving tunnel ingress (it copied ECT onto the
    /// outer for un-ECN-marked inner traffic) on a congested path.
    pub fn gre_decap_ecn_illegal_drops_total(&self) -> u64 {
        crate::afxdp::gre::GRE_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed)
    }

    /// #2317: WireGuard-decap inner packets dropped by the RFC 6040 §4.2
    /// decap-side ECN combine because the (recvmsg-captured) outer ECN
    /// was CE over a Not-ECT inner — the illegal combination. RFC 6040
    /// mandates a drop here. Surfaced as
    /// `xpf_userspace_wg_decap_ecn_illegal_drops_total`; a nonzero value
    /// flags a misbehaving WG ingress / congested path that CE-marked the
    /// outer of un-ECN inner traffic.
    pub fn wg_decap_ecn_illegal_drops_total(&self) -> u64 {
        crate::afxdp::gre::WG_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed)
    }

    /// #2331: native-GRE encap frames dropped because the fully built
    /// outer datagram exceeded the resolved transport/egress MTU while
    /// the IPv4 outer carries DF=1 (the only outer the native builder
    /// emits). A DF-set oversized outer cannot be fragmented downstream
    /// and would silently blackhole every inner flow over the tunnel
    /// with no PMTUD signal — so the builder refuses to emit it. Surfaced
    /// as `xpf_userspace_gre_encap_df_oversize_drops_total`; a nonzero
    /// value flags inner flows whose encapped size exceeds the tunnel
    /// path MTU (a missing/too-high inner MSS clamp, or a non-TCP inner
    /// with no segmentation lever). PMTUD/PTB signalling is deferred to
    /// #2330.
    pub fn gre_encap_df_oversize_drops_total(&self) -> u64 {
        crate::afxdp::gre::GRE_ENCAP_DF_OVERSIZE_DROPS.load(Ordering::Relaxed)
    }

    /// #2782: native-GRE decap frames dropped because the Checksum-Present
    /// (C) bit was set but the GRE checksum failed to verify (or the
    /// header was truncated past the 4-byte Checksum+Reserved1 field). The
    /// decap path now skips+validates the checksum (RFC 2784 §2.1 / RFC
    /// 2890) so a checksummed peer (e.g. a vSRX with GRE checksum enabled)
    /// forwards instead of being silently blackholed; a corrupt frame is
    /// dropped here with this specific counter. Surfaced as
    /// `xpf_userspace_gre_decap_checksum_invalid_drops_total`; a nonzero
    /// value flags a checksummed GRE peer delivering corrupt frames or a
    /// truncated GRE header.
    pub fn gre_decap_checksum_invalid_drops_total(&self) -> u64 {
        crate::afxdp::gre::GRE_DECAP_CHECKSUM_INVALID_DROPS.load(Ordering::Relaxed)
    }

    /// #6842: native-GRE frames REFUSED for decap because the GRE version
    /// field was non-zero (RFC 2637 / PPTP enhanced GRE is version 1)
    /// while the outer tuple named a configured GRE tunnel endpoint. RFC
    /// 2784/2890 GRE is version 0; a version-1 header re-purposes the
    /// 32-bit Key as `Payload Length (16) | Call ID (16)` and adds an
    /// Acknowledgment-Number field the RFC 2890 field order does not
    /// skip, so parsing it with version-0 rules would promote
    /// attacker-chosen bytes as the inner packet. This is a REFUSAL, not
    /// a drop — the frame continues on the ordinary transit/host-inbound
    /// path — and ordinary TRANSIT PPTP (no configured endpoint for the
    /// outer tuple) is deliberately NOT counted. Surfaced as
    /// `xpf_userspace_gre_decap_unsupported_version_refusals_total`; a
    /// nonzero value flags a peer offering PPTP to a GRE tunnel endpoint
    /// xpf has no ALG to terminate.
    pub fn gre_decap_unsupported_version_refusals_total(&self) -> u64 {
        self.forwarding.gre_decap_counters.unsupported_version_refusals()
    }

    /// #2472: locally-generated ICMP/ICMPv6 Time Exceeded replies dropped
    /// because the per-reason token bucket was empty. The TTL/hop-limit error
    /// generator is rate-limited (global-per-reason, Linux `icmp_msgs_per_sec`
    /// model, default 1000/s + 1000 burst) so a low-TTL flood / routing loop
    /// cannot drive unbounded generated-error emission. Surfaced as
    /// `xpf_userspace_time_exceeded_rate_limited_total`; a nonzero value flags
    /// an error-amplification attempt (or a real routing loop) being clamped.
    pub fn time_exceeded_rate_limited_total(&self) -> u64 {
        crate::afxdp::icmp_ratelimit::rate_limited_count(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::TimeExceeded,
        )
    }

    /// #2472: locally-generated PTB / Frag-Needed PMTUD replies dropped because
    /// the per-reason token bucket was empty. Surfaced as
    /// `xpf_userspace_packet_too_big_rate_limited_total`; a nonzero value flags
    /// an oversized-DF / IPv6 flood being clamped before it amplifies into
    /// unbounded PTB emission.
    pub fn packet_too_big_rate_limited_total(&self) -> u64 {
        crate::afxdp::icmp_ratelimit::rate_limited_count(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::PacketTooBig,
        )
    }

    /// #2472: locally-generated policy/filter `reject` replies (TCP RST or
    /// ICMP/ICMPv6 administratively-prohibited unreachable) dropped because the
    /// per-reason token bucket was empty. This is in ADDITION to the SYN-cookie
    /// TX-frame budget gate (`policy_reject_reply_budget_drops`), which is a
    /// queue-protection gate rather than a rate cap. Surfaced as
    /// `xpf_userspace_reject_rate_limited_total`; a nonzero value flags a
    /// rejected-flow flood being clamped before it amplifies into unbounded
    /// RST/ICMP backscatter.
    pub fn reject_rate_limited_total(&self) -> u64 {
        crate::afxdp::icmp_ratelimit::rate_limited_count(
            crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        )
    }

    /// #1782: debug dump of every key currently present in the userspace
    /// `dynamic_neighbors` mirror, as `(ifindex, ip)` pairs. The
    /// cold-start capture harness reads this at the pre-connect t0'
    /// sample to confirm whether the data-path next-hop is ABSENT from
    /// the mirror (the H2 fingerprint) while the kernel still shows it
    /// DELAY/STALE-usable. `NeighborEntry` carries only the MAC, not the
    /// kernel NUD state, so the harness pairs this membership check with
    /// `ip neigh` for the NUD state. Locks all shards once (same cost as
    /// `len()`); capped at `MAX` rows so a pathological table cannot bloat
    /// the status message. Debug/diagnostic surface only.
    pub fn dynamic_neighbor_keys(&self) -> Vec<(i32, std::net::IpAddr)> {
        const MAX: usize = 4096;
        self.neighbors.dynamic.with_all_shards(|bulk| {
            let mut out: Vec<(i32, std::net::IpAddr)> = Vec::new();
            for shard in bulk.each_shard_ref() {
                for (key, _entry) in shard.iter() {
                    if out.len() >= MAX {
                        return out;
                    }
                    out.push(*key);
                }
            }
            out
        })
    }

    /// #1636 option C: proactive-neighbor-warm telemetry. `warm_drops`
    /// is incremented when the bounded warmer queue is full (transient);
    /// `warm_disconnected` when the warmer worker died (fatal). Both are
    /// surfaced to the daemon's Prometheus collector.
    pub fn neighbor_warm_counters(&self) -> (u64, u64) {
        (
            self.neighbors.warm_drops.load(Ordering::Relaxed),
            self.neighbors.warm_disconnected.load(Ordering::Relaxed),
        )
    }

    /// #1769: on-demand neighbor-resolver telemetry. Returns the live
    /// queue-depth gauge (clamped to >= 0) plus the monotonic GET/probe/
    /// epoch counters. Exposes the previously-invisible stuck-state
    /// surface: pending depth, GET attempts/resolutions/failures,
    /// probe-on-stale rate, epoch-guard rejects, and enqueue
    /// drops/disconnects.
    pub fn neighbor_resolver_counters(&self) -> NeighborResolverCounters {
        let c = &self.neighbors.resolver_counters;
        NeighborResolverCounters {
            queue_depth: c.queue_depth.load(Ordering::Relaxed).max(0) as u64,
            enqueue_drops: c.enqueue_drops.load(Ordering::Relaxed),
            disconnected: c.disconnected.load(Ordering::Relaxed),
            get_attempts: c.get_attempts.load(Ordering::Relaxed),
            get_resolved: c.get_resolved.load(Ordering::Relaxed),
            probe_on_stale: c.probe_on_stale.load(Ordering::Relaxed),
            get_failures: c.get_failures.load(Ordering::Relaxed),
            epoch_rejects: c.epoch_rejects.load(Ordering::Relaxed),
            // #1771 §2.6: backoff-retry GETs + the monitor thread's
            // ENOBUFS / upsert-only re-dump telemetry (§2.5 mechanism).
            get_backoff_attempts: c.get_backoff_attempts.load(Ordering::Relaxed),
            netlink_enobufs: c.netlink_enobufs.load(Ordering::Relaxed),
            netlink_redumps: c.netlink_redumps.load(Ordering::Relaxed),
            netlink_redump_upserts: c.netlink_redump_upserts.load(Ordering::Relaxed),
        }
    }

    /// #1772: neighbor/ARP resolution LATENCY telemetry. Returns the
    /// pending-dwell + resolver GETNEIGH-RTT histogram snapshots plus the
    /// pending-neigh timeout-drop count and queue-depth high-water mark.
    /// Complements the #1769 count-only `neighbor_resolver_counters` with
    /// timing so the intermittent slow-new-connection symptom is visible.
    pub fn neighbor_latency_telemetry(&self) -> NeighborLatencyTelemetry {
        NeighborLatencyTelemetry {
            pending_dwell: self.neighbors.pending_dwell_hist.snapshot(),
            resolver_get_rtt: self.neighbors.resolver_get_rtt_hist.snapshot(),
            pending_timeout_drops: self.neighbors.pending_timeout_drops.load(Ordering::Relaxed),
            pending_max_depth: self.neighbors.pending_max_depth.load(Ordering::Relaxed),
        }
    }

    /// #5289: drain the control-thread ring + every per-worker ring, format
    /// each compact POD `ExceptionEvent` into an `ExceptionStatus` here (on
    /// the control/status thread — NOT the packet path), merge by monotonic
    /// timestamp and cap at the historical ring depth. The wall-clock and
    /// `String`/IP/zone formatting that the retired inline path did per
    /// terminal packet now runs once per status read.
    pub fn recent_exceptions(&self) -> Vec<ExceptionStatus> {
        let anchor = MonoWallAnchor::capture();
        let mut events: Vec<ExceptionEvent> = Vec::new();
        if let Ok(ring) = self.recent_exceptions.lock() {
            events.extend(ring.iter().cloned());
        }
        // #6242: drain each worker's exception ring off its runtime record
        // (was the standalone `worker_exception_rings` map).
        for rec in self.workers.records().values() {
            if let Ok(ring) = rec.exception_ring.lock() {
                events.extend(ring.iter().cloned());
            }
        }
        events.sort_by_key(|e| e.mono);
        let start = events.len().saturating_sub(EXCEPTION_RING_CAPACITY);
        events[start..]
            .iter()
            .map(|e| e.to_status(anchor, &self.forwarding))
            .collect()
    }

    pub fn recent_session_deltas(&self) -> Vec<SessionDeltaInfo> {
        self.recent_session_deltas
            .lock()
            .map(|recent| recent.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// #5289: the most-recent forwarding resolution across the control-thread
    /// slot and every per-worker slot (by monotonic timestamp), rebuilt into a
    /// `PacketResolution` on the control thread from its compact POD form.
    pub fn last_resolution(&self) -> Option<PacketResolution> {
        let mut newest: Option<ResolutionEvent> = None;
        let mut consider = |candidate: Option<ResolutionEvent>| {
            if let Some(ev) = candidate
                && newest.as_ref().is_none_or(|n| ev.mono >= n.mono)
            {
                newest = Some(ev);
            }
        };
        if let Ok(last) = self.last_resolution.lock() {
            consider(last.clone());
        }
        // #6242: pick the newest across each worker's last-resolution slot off
        // its runtime record (was the standalone `worker_last_resolution` map).
        for rec in self.workers.records().values() {
            if let Ok(last) = rec.last_resolution.lock() {
                consider(last.clone());
            }
        }
        newest.map(|ev| ev.to_resolution(&self.forwarding))
    }

    pub fn slow_path_status(&self) -> SlowPathStatus {
        self.slow_path
            .as_ref()
            .map(|slow| slow.status())
            .unwrap_or_else(|| self.last_slow_path_status.clone())
    }

    pub fn cos_statuses(&self) -> Vec<crate::protocol::CoSInterfaceStatus> {
        let snapshots: Vec<Vec<_>> = self
            .workers
            .records()
            .values()
            .map(|rec| rec.handle.cos_status.load().iter().cloned().collect())
            .collect();
        let mut statuses =
            aggregate_cos_statuses_across_workers(&snapshots, &self.cos_owner_worker_by_queue);
        let queue_leases = self.cos.queue_leases.load();
        overlay_shared_cos_queue_lease_statuses(&mut statuses, queue_leases.as_ref());
        // #1830 (g): overlay the flow-cache active-flow counts onto the
        // queue rows so each row carries BOTH halves of the
        // collision-vs-demand ratio (flow_fair_flows_active alongside
        // the worker-snapshot-summed flow_fair_buckets_occupied). Same
        // per-binding source as `cos_active_flow_counts`, re-keyed per
        // (ifindex, queue_id) by summing across workers.
        let mut flow_counts = BTreeMap::<(i32, u8), u64>::new();
        for live in self.workers.live.values() {
            for row in live.cos_active_flow_counts_snapshot() {
                let count = flow_counts.entry((row.ifindex, row.queue_id)).or_insert(0);
                *count = count.saturating_add(u64::from(row.active_flow_count));
            }
        }
        overlay_cos_flow_fair_flow_counts(&mut statuses, &flow_counts);
        statuses
    }

    pub fn filter_term_counters(&self) -> Vec<crate::protocol::FirewallFilterTermCounterStatus> {
        let mut filter_keys = self
            .forwarding
            .filter_state
            .filters
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        filter_keys.sort();
        let mut out = Vec::new();
        for key in filter_keys {
            let Some(filter) = self.forwarding.filter_state.filters.get(&key) else {
                continue;
            };
            for term in &filter.terms {
                out.push(crate::protocol::FirewallFilterTermCounterStatus {
                    family: filter.family.clone(),
                    filter_name: filter.name.clone(),
                    term_name: term.name.clone(),
                    packets: term.counter.packets.load(Ordering::Relaxed),
                    bytes: term.counter.bytes.load(Ordering::Relaxed),
                });
            }
        }
        out
    }

    pub fn three_color_policer_counters(&self) -> Vec<crate::protocol::ThreeColorPolicerStatus> {
        self.forwarding.filter_state.three_color_policer_statuses()
    }

    pub fn source_nat_pool_statuses(&self) -> Vec<crate::protocol::SourceNatPoolStatus> {
        crate::nat::source_nat_pool_statuses(&self.forwarding.source_nat_rules)
    }

    #[cfg(test)]
    pub(crate) fn test_match_source_nat_result_for_tuple(
        &self,
        from_zone: &str,
        to_zone: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
        egress_v4: Option<Ipv4Addr>,
        egress_v6: Option<Ipv6Addr>,
        now_ns: u64,
    ) -> crate::nat::SourceNatLookup {
        let mut counter = None;
        crate::nat::match_source_nat_result_for_tuple(
            &self.forwarding.iface_nat_allocators,
            &self.forwarding.source_nat_rules,
            &crate::nat::NatScopeCtx::default(),
            from_zone,
            to_zone,
            src_ip,
            dst_ip,
            // #5687: this test helper drives real-protocol tuples, so wrap in
            // `Some` (never the `None` tuple-unknown sentinel).
            Some(protocol),
            src_port,
            dst_port,
            egress_v4,
            egress_v6,
            now_ns,
            false,
            // #4088: this helper is exercised only with TCP/UDP tuples; ICMP
            // id==0 classification is covered by the nat/ unit tests.
            false,
            crate::nat::NatHolder::Untracked,
            &mut counter,
        )
    }

    #[cfg(test)]
    pub(crate) fn test_release_source_nat_allocation(
        &self,
        key: &crate::session::SessionKey,
        nat: crate::nat::NatDecision,
        now_ns: u64,
    ) {
        crate::nat::release_source_nat_allocation(
            &self.forwarding.iface_nat_allocators,
            &self.forwarding.source_nat_rules,
            key,
            nat,
            false,
            now_ns,
        );
    }

    pub fn flow_worker_map(&self) -> (Vec<crate::protocol::FlowWorkerStatus>, bool) {
        const FLOW_WORKER_MAP_MAX_ROWS: usize = 4096;
        let mut out = Vec::new();
        let mut truncated = false;
        for live in self.workers.live.values() {
            if out.len() >= FLOW_WORKER_MAP_MAX_ROWS {
                truncated = true;
                break;
            }
            let (rows, binding_truncated) = live.flow_worker_map_snapshot();
            truncated |= binding_truncated;
            for row in rows {
                if out.len() >= FLOW_WORKER_MAP_MAX_ROWS {
                    truncated = true;
                    break;
                }
                out.push(row);
            }
        }
        (out, truncated)
    }

    pub fn cos_active_flow_counts(&self) -> (Vec<crate::protocol::CoSActiveFlowCountStatus>, bool) {
        const COS_ACTIVE_FLOW_COUNT_MAX_ROWS: usize = 4096;
        let mut counts = std::collections::BTreeMap::<(i32, u8, u32), u32>::new();
        for live in self.workers.live.values() {
            for row in live.cos_active_flow_counts_snapshot() {
                let key = (row.ifindex, row.queue_id, row.worker_id);
                let count = counts.entry(key).or_insert(0);
                *count = count.saturating_add(row.active_flow_count);
            }
        }
        let truncated = counts.len() > COS_ACTIVE_FLOW_COUNT_MAX_ROWS;
        let out = counts
            .into_iter()
            .take(COS_ACTIVE_FLOW_COUNT_MAX_ROWS)
            .map(|((ifindex, queue_id, worker_id), active_flow_count)| {
                crate::protocol::CoSActiveFlowCountStatus {
                    ifindex,
                    queue_id,
                    worker_id,
                    active_flow_count,
                }
            })
            .collect();
        (out, truncated)
    }

    pub fn drain_session_deltas(&self, max: usize) -> Vec<SessionDeltaInfo> {
        // #5290: fair, rotating-cursor drain instead of whole-budget-first-slot.
        // The old drain handed the entire caller budget to each live binding in
        // slot order with an early break, so during the event-stream RPC
        // fallback a low-slot worker with many pending deltas consumed the whole
        // budget and starved higher-slot workers — HA state quality then
        // depended on worker-slot assignment.
        let bindings: Vec<&BindingLiveState> =
            self.workers.live.values().map(|b| b.as_ref()).collect();
        let start = self
            .workers
            .session_delta_drain_cursor
            .load(Ordering::Relaxed);
        let (out, next_cursor, overflow) =
            crate::afxdp::session_delta::drain_session_deltas_fair(&bindings, max, start);
        self.workers
            .session_delta_drain_cursor
            .store(next_cursor, Ordering::Relaxed);
        if overflow {
            // #5290: the caller-wide budget could not keep up — deltas remain
            // undrained in the per-binding fallback buffers. Arm loss-of-sync on
            // exactly the residual bindings so the owning worker's
            // `take_delta_loss` resync re-exports the full owner-RG snapshot
            // (table truth) and no delta is silently lost. Mirrors the
            // #2442/#2874 push_delta loss latch (deliver-or-resync).
            for b in self.workers.live.values() {
                if b.has_pending_session_deltas() {
                    b.set_delta_loss();
                }
            }
        }
        out
    }

    /// #5294 test seam: insert a live binding at `slot` pre-loaded with `count`
    /// pending RPC-fallback session deltas, so a server-level test can drive the
    /// `drain_session_deltas` control verb through the real `handle_stream`
    /// dispatcher with deltas actually queued. Compiled out of production builds.
    #[cfg(test)]
    pub(crate) fn seed_pending_session_deltas_for_test(&mut self, slot: u32, count: usize) {
        let live = std::sync::Arc::new(crate::afxdp::binding_state::BindingLiveState::new());
        for _ in 0..count {
            live.push_session_delta(crate::protocol::SessionDeltaInfo::default());
        }
        self.workers.live.insert(slot, live);
    }

    pub fn worker_heartbeats(&self) -> Vec<chrono::DateTime<Utc>> {
        let now_wall = Utc::now();
        let now_mono = monotonic_nanos();
        self.workers
            .records()
            .iter()
            .map(|(_, rec)| {
                monotonic_timestamp_to_datetime(
                    rec.handle.heartbeat.load(Ordering::Relaxed),
                    now_mono,
                    now_wall,
                )
                .unwrap_or(now_wall)
            })
            .collect()
    }

    pub fn worker_count(&self) -> usize {
        self.workers.records().len()
    }

    /// #869: snapshot per-worker busy/idle runtime counters.  Each row is
    /// the current `WorkerRuntimeAtomics` publish, most recently written
    /// on the worker's ~1s publish cadence.
    /// #925: also surfaces `dead` (one-shot AtomicBool set when the
    /// supervisor catches a worker_loop panic) and the rendered panic
    /// payload from the per-worker slot. #6242: the panic slot now lives on
    /// the worker's runtime record (`rec.panic`) alongside its handle — the
    /// former cross-map join (`handles.iter()` + `worker_panics.get(id)`)
    /// collapses into a single record read.
    /// #6979: reclaim the NAT holder bits of every worker that has died and not
    /// yet been retired. Returns the number of allocator records freed.
    ///
    /// THE LEAK. A holder bit is set on reserve and cleared only when that same
    /// worker runs its own release. `spawn_supervised_worker` catches a
    /// `worker_loop` panic, sets `dead`, and lets the thread exit; nothing
    /// respawns it, so its `SessionTable` dies with it and its reservations are
    /// stranded for the life of the allocator. There is no TTL and no reconcile
    /// that clears them, so those pool ports never come back and SNAT for new
    /// flows eventually fails `AllocatorExhausted`.
    ///
    /// `PortAllocator::retire_worker` (#7092) landed sound but unwired,
    /// explicitly deferring the call-site choice because retiring from this 1 Hz
    /// tick "would walk `live_by_flow` under the alloc mutex on every tick
    /// unless it also carries 'already retired' state". `holders_retired` is
    /// that state: a one-shot compare_exchange, so a dead worker is swept once
    /// and every later tick pays one relaxed load per record.
    ///
    /// SCOPE, stated rather than implied: this covers the PANIC route only. The
    /// REPLAN route -- a plan that shrinks the worker set retires ids that still
    /// hold bits, while `parse_source_nat_rules_with_previous` carries the
    /// allocator across the reload -- sets no flag at all, so there is nothing
    /// here to react to. It is not fixed by this change.
    /// #7092: reclaim the NAT holder bits of EVERY currently-registered worker,
    /// for the generation teardown that a replan performs. Returns records freed.
    ///
    /// The sibling of `retire_dead_worker_holders`, for the route that sets no
    /// flag. `dead` is written only by the panic supervisor, so a clean
    /// generation teardown — which is what a worker-count change does — never
    /// sets it, and a sweep keyed on `dead` cannot see this case at all. That
    /// gap is why #7092 stayed open after #8069 closed the panic route.
    ///
    /// The latch is shared with the dead-worker sweep on purpose: a worker that
    /// panicked and was already retired by the 1 Hz tick must not be swept a
    /// second time here, and one that is retired here must not be swept again if
    /// a status tick observes it before the records are dropped. One
    /// compare_exchange answers both.
    ///
    /// WHY ALL IDS, not just the ones a shrinking plan drops. An id reused by
    /// the next generation self-heals — the new worker takes the same bit and
    /// eventually releases it — so only the dropped ids leak, which is why
    /// #7092 frames this as shrinking. But "which ids does the NEXT plan mint"
    /// is not known at teardown, and deferring until it is means sweeping after
    /// the records naming the outgoing ids are already gone. Retiring all of
    /// them is correct for the same reason retiring one dead worker is: the bit
    /// records a claim by a worker that no longer exists. The next generation
    /// re-imports the synced sessions and re-reserves, and no forwarding happens
    /// in between, so the interval where a port is free while its session still
    /// exists has no packet path through it.
    /// #9367: release the worker's slots in every shared_exact CoS V_min
    /// floor.
    ///
    /// THE DEFECT. `PaddedVtimeSlot` has no TTL, generation or liveness input:
    /// `participating_v_min_snapshot` counts every non-sentinel peer slot and
    /// takes the MIN, and both production `vacate()` call sites are executed by
    /// the OWNING worker (its last flow bucket on the queue drained, or a
    /// binding reset / HA demotion). A worker that exits by PANIC executes
    /// neither, so its frozen `queue_vtime` pins the cross-worker V_min while
    /// the survivors' own vtimes keep advancing. `cos_queue_v_min_continue`
    /// then never passes, and because the window is restored to full only on a
    /// PASSING check the survivors decay 1000 -> 64 batches and settle into the
    /// minimum-window duty cycle: 8 throttled + 64 suspended, i.e. the fairness
    /// brake is off for 64/72 = 88.9% of drain opportunities. A standing ~11%
    /// drain-opportunity tax on one exact class, additive to the RX capacity
    /// the panic itself already cost.
    ///
    /// It is not "for the life of the process": a coordinator teardown discards
    /// the floors map, a worker-count change fails the
    /// `f.slots.len() == num_workers` reuse filter in `cos_leases.rs` and
    /// builds a fresh all-sentinel floor, and removing plus re-adding the exact
    /// queue drops the key. Under UNCHANGED operation none of those happen, so
    /// the poison can last indefinitely.
    ///
    /// #4254 (R-7) closed the REJOIN door — a worker whose runtime was rebuilt
    /// restarting `queue_vtime` at 0 — by seeding a rejoiner to the peer
    /// frontier. The dead / never-returning door reaches the identical state
    /// and is not closed by that fix.
    ///
    /// SINGLE-WRITER, still. `vacate()` is documented as owner-only because
    /// two writers racing on one slot could interleave a stale publish after a
    /// vacate. This call happens under the one-shot `holders_retired` CAS in
    /// [`Self::retire_worker_holders_where`], and there it is gated on
    /// `atomics.dead` rather than on that sweep's own predicate — a worker the
    /// supervisor has already recorded as `dead` has exited and nothing
    /// respawns it, so the owning writer is gone and this is the only writer
    /// left. The gate is load-bearing and not belt-and-braces:
    /// `retire_all_worker_holders` selects `|_| true` for the #7092 teardown
    /// reclaim and runs while those workers are still RUNNING, so an ungated
    /// vacate would race a live `publish()`. The Release store is unchanged, so
    /// a peer's Acquire read still pairs.
    ///
    /// Reads the floors map through `load_full()`, so a concurrent
    /// `queue_vtime_floors.store(..)` from a reconcile cannot be torn by this
    /// walk. A floor built AFTER this call starts all-sentinel, so the
    /// interleaving cannot leave a stale participating slot behind.
    ///
    /// Returns the number of slots that were actually participating and are
    /// now vacated, so the caller can say something happened rather than
    /// logging unconditionally.
    fn vacate_worker_v_min_slots(&self, worker_id: u32) -> usize {
        let floors = self.cos.queue_vtime_floors.load_full();
        let mut vacated = 0usize;
        for floor in floors.values() {
            let Some(slot) = floor.slots.get(worker_id as usize) else {
                continue;
            };
            if slot.read().is_none() {
                // Already NOT_PARTICIPATING — the worker had no flows on this
                // queue when it died, which is the case that was never poisoned
                // in the first place. Not counted, so the log line above means
                // "a pinned frontier was released" and not "the sweep ran".
                continue;
            }
            slot.vacate();
            vacated += 1;
        }
        vacated
    }

    pub(crate) fn retire_all_worker_holders(&self) -> usize {
        self.retire_worker_holders_where(|_| true)
    }

    pub(crate) fn retire_dead_worker_holders(&self) -> usize {
        self.retire_worker_holders_where(|atomics| atomics.dead.load(Ordering::Relaxed))
    }

    /// Shared body: retire every registered worker whose `select` says so,
    /// exactly once each.
    fn retire_worker_holders_where(
        &self,
        select: impl Fn(&crate::afxdp::worker_runtime::WorkerRuntimeAtomics) -> bool,
    ) -> usize {
        use std::sync::atomic::Ordering;
        let now_ns = crate::afxdp::wg::counters::monotonic_now_ns();
        let mut freed = 0;
        for (worker_id, rec) in self.workers.records().iter() {
            let atomics = &rec.handle.runtime_atomics;
            if !select(atomics) {
                continue;
            }
            // One-shot: the loser of a race does not sweep, so the walk happens
            // exactly once no matter how many tickers observe the death.
            if atomics
                .holders_retired
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            let id = *worker_id;
            freed += self.forwarding.iface_nat_allocators.retire_worker(id, now_ns);
            freed += crate::nat::retire_worker_from_pool_rules(
                &self.forwarding.source_nat_rules,
                id,
                now_ns,
            );
            freed += self.forwarding.nat64.retire_worker(id, now_ns);
            // #9560 round 3: retire that worker's STEERING claims too. NAT and CoS were
            // already reclaimed here; the steering registry was not, so a dead worker's
            // bit kept suppressing every later delete of the rows it held — an aliased
            // session's teardown found an owner that can never come back, and both the
            // registry holding and the fixed-size BPF row leaked for the life of the
            // process.
            let steering_retired = {
                let maps = self.bpf_maps.load();
                crate::afxdp::bpf_map::retire_worker_steering_rows(
                    crate::afxdp::bpf_map::SteeringMap {
                        fd: maps.session_map_fd.as_ref().map(|fd| fd.fd).unwrap_or(-1),
                        owners: &self.steering_owners,
                        holder: crate::afxdp::bpf_map::SteeringHolder::Coordinator,
                    },
                    id,
                )
            };
            if steering_retired > 0 {
                eprintln!(
                    "xpf-dp: retired {steering_retired} steering claim(s) stranded by dead \
                     worker {id}"
                );
            }
            // #9367: the V_min vacate is gated on the PANIC flag, not on this
            // sweep's own `select`. `retire_all_worker_holders` passes
            // `|_| true` — it retires every registered id, LIVE ones included,
            // because the #7092 teardown reclaim has to name them before
            // `stop_and_clear` drops the records. Those workers are still
            // RUNNING at that point, so vacating their slots there would make
            // the coordinator a SECOND writer to a slot whose contract is
            // single-writer, and it would buy nothing: the same teardown
            // discards `cos.queue_vtime_floors` outright a few statements
            // later (`coordinator/mod.rs`). Only a worker the supervisor has
            // already recorded as `dead` has no owning writer left, which is
            // exactly the case #9367 is about.
            let vacated = if atomics.dead.load(Ordering::Relaxed) {
                self.vacate_worker_v_min_slots(id)
            } else {
                0
            };
            if freed > 0 {
                eprintln!(
                    "xpf-dp: reclaimed {freed} NAT reservation(s) stranded by dead worker {id}"
                );
            }
            if vacated > 0 {
                eprintln!(
                    "xpf-dp: vacated {vacated} cross-worker CoS V_min slot(s) stranded by \
                     dead worker {id}"
                );
            }
        }
        freed
    }

    pub fn worker_runtime_snapshots(&self) -> Vec<crate::protocol::WorkerRuntimeStatus> {
        self.workers
            .records()
            .iter()
            .map(|(worker_id, rec)| {
                let handle = &rec.handle;
                let s = handle.runtime_atomics.snapshot();
                let w = handle.runtime_atomics.snapshot_window();
                let dead = handle
                    .runtime_atomics
                    .dead
                    .load(std::sync::atomic::Ordering::Relaxed);
                let panic_message = if dead {
                    match rec.panic.lock() {
                        Ok(g) => g.clone(),
                        Err(poisoned) => poisoned.into_inner().clone(),
                    }
                    .unwrap_or_default()
                } else {
                    String::new()
                };
                // #1621: snapshot the sibling cold_path_atomics under
                // its cold_window_gen seqlock. Copilot code-r1 C2+C5
                // catch: distinguishing snapshot=None from
                // snapshot=Some(default) is load-bearing for the wire
                // omitempty contract.
                //
                // Behavior:
                //   - snapshot() = None (retry exhausted): emit EMPTY
                //     Vec fields so Vec::is_empty omits them from the
                //     wire entirely; clock_source = ""; STILL stamp
                //     snapshot_failed (operator starvation signal).
                //   - snapshot() = Some(snap) but never-sampled
                //     (sample_phase == 0 AND all-zero samples/alias):
                //     also emit empty Vecs — there's no data to expose.
                //   - snapshot() = Some(snap) with data: populated Vecs.
                //
                // Result: a worker that has never sampled emits a
                // WorkerRuntimeStatus byte-identical to a pre-#1621
                // daemon's output, validating the wire-invariant
                // contract (and the protocol_wire_v1.json fixture).
                // ORDER MATTERS (Claude SMR code-r1 catch): call
                // snapshot() FIRST so any retry-exhaust fetch_add inside
                // snapshot() is visible to the snapshot_failed_count()
                // read below. Without this order, a failure on THIS
                // scrape would only show up on the NEXT scrape (1-tick
                // lag), making the operator's starvation-alert dashboard
                // one cycle late.
                let cold_opt = handle.cold_path_atomics.snapshot();
                let cold_snapshot_failed = handle.cold_path_atomics.snapshot_failed_count();
                let has_data = cold_opt
                    .as_ref()
                    .map(|c| {
                        c.sample_phase != 0
                            || c.samples.iter().any(|&v| v != 0)
                            || c.builder_collision.iter().any(|&v| v)
                    })
                    .unwrap_or(false);
                let cold = cold_opt.unwrap_or_default();
                // #1635: SPARSE wire encoding. Only slots with a live
                // zone-pair assignment AND samples > 0 ride the wire.
                // The slot→(from,to) mapping comes from the per-config
                // slot map's inverse table; the worker's local buckets
                // index by slot. A worker that never sampled emits zero
                // new wire bytes (Vec::is_empty omits the fields).
                let slot_map = &self.forwarding.cold_path_slot_map;
                let mut active_slot_ids: Vec<u32> = Vec::new();
                let mut active_zone_from: Vec<u32> = Vec::new();
                let mut active_zone_to: Vec<u32> = Vec::new();
                let mut active_samples: Vec<u64> = Vec::new();
                let mut active_sum_ns: Vec<u64> = Vec::new();
                let mut active_buckets: Vec<Vec<u64>> = Vec::new();
                let mut active_builder_collision: Vec<bool> = Vec::new();
                if has_data {
                    for slot in 0..crate::afxdp::cold_path_hist::POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
                        if cold.samples[slot] == 0 {
                            continue;
                        }
                        let Some((from, to)) = slot_map.inverse.get(slot).copied().flatten() else {
                            // Sampled into a slot with no live mapping
                            // (config rotated mid-window). Skip — the
                            // next publish after the worker's zero-out
                            // tick clears it.
                            continue;
                        };
                        // Codex code-r1 finding 3: the coordinator
                        // publishes the new slot-map BEFORE workers
                        // necessarily load it and zero reused slots, so
                        // for up to one publish tick the atomics can
                        // carry the PREVIOUS pair's counts under the
                        // NEW slot. Validate the recorded first_key
                        // against the live mapping; on mismatch the
                        // counts belong to the old pair — skip them
                        // rather than relabel stale samples as the new
                        // (from_zone, to_zone).
                        let expected_key =
                            crate::afxdp::cold_path_hist::zone_pair_packed_key(from, to);
                        if cold.first_key[slot] != 0 && cold.first_key[slot] != expected_key {
                            continue;
                        }
                        active_slot_ids.push(slot as u32);
                        active_zone_from.push(from as u32);
                        active_zone_to.push(to as u32);
                        active_samples.push(cold.samples[slot]);
                        active_sum_ns.push(cold.sum_ns[slot]);
                        active_buckets.push(cold.buckets[slot].to_vec());
                        active_builder_collision.push(cold.builder_collision[slot]);
                    }
                }
                crate::protocol::WorkerRuntimeStatus {
                    worker_id: *worker_id,
                    tid: handle.runtime_atomics.tid(),
                    wall_ns: s.wall_ns,
                    active_ns: s.active_ns,
                    idle_spin_ns: s.idle_spin_ns,
                    idle_block_ns: s.idle_block_ns,
                    thread_cpu_ns: s.thread_cpu_ns,
                    work_loops: s.work_loops,
                    session_volume_high_water: s.session_volume_high_water,
                    idle_loops: s.idle_loops,
                    cos_queue_lease_acquire_v8_calls: s.cos_queue_lease_acquire_v8_calls,
                    cos_queue_lease_acquire_v8_granted_bytes: s
                        .cos_queue_lease_acquire_v8_granted_bytes,
                    // #1782 Step-1: wheel catch-up + per-cause v8
                    // under-grant attribution.
                    cos_wheel_ticks_advanced_total: s.cos_wheel_ticks_advanced_total,
                    cos_wheel_ticks_advanced_max: s.cos_wheel_ticks_advanced_max,
                    cos_queue_lease_undergrant_seqlock_give_up: s
                        .cos_queue_lease_undergrant
                        .seqlock_give_up,
                    cos_queue_lease_undergrant_cap_zero: s.cos_queue_lease_undergrant.cap_zero,
                    cos_queue_lease_undergrant_epoch_rotated: s
                        .cos_queue_lease_undergrant
                        .epoch_rotated,
                    cos_queue_lease_undergrant_share_exhausted: s
                        .cos_queue_lease_undergrant
                        .share_exhausted,
                    cos_queue_lease_undergrant_class_cap: s.cos_queue_lease_undergrant.class_cap,
                    cos_queue_lease_undergrant_outstanding_cap: s
                        .cos_queue_lease_undergrant
                        .outstanding_cap,
                    session_table_entries: s.session_table_entries,
                    max_sessions: s.max_sessions,
                    nat_reverse_key_collisions: s.nat_reverse_key_collisions,
                    nat_reverse_key_collisions_distinct_src: s
                        .nat_reverse_key_collisions_distinct_src,
                    // #4800: per-worker transit new-flow installs.
                    new_flow_installs: s.new_flow_installs,
                    session_create_drops: s.session_create_drops,
                    // #7919
                    session_lookup_miss_no_handle: s.session_lookup_miss_no_handle,
                    session_lookup_miss_stale_handle: s.session_lookup_miss_stale_handle,
                    session_lookup_miss_key_mismatch: s.session_lookup_miss_key_mismatch,
                    session_install_admission_refused: s.session_install_admission_refused,
                    session_install_partial: s.session_install_partial,
                    dead,
                    panic_message,
                    thread_cpu_ns_60s: w.thread_cpu_ns,
                    wall_ns_60s: w.wall_ns,
                    active_ns_60s: w.active_ns,
                    window_ns: w.window_ns,
                    // #1635 cold-path histogram fields: SPARSE
                    // active-slot-only encoding (Vec::is_empty omits an
                    // empty worker's fields, preserving wire-compat with
                    // pre-#1635 Go readers per feedback_wire_protocol_both_sides).
                    // Stamp v3 when there is data OR when the slot map
                    // overflowed (Copilot code-r2: an overflow with no
                    // samples yet must still route the Go collector to
                    // the v3 emitter so the overflow gauge is visible —
                    // version 0 would route to the legacy v1 path and
                    // hide it).
                    cold_path_layout_version: if has_data || slot_map.overflow_active {
                        crate::afxdp::cold_path_hist::COLD_PATH_LAYOUT_VERSION
                    } else {
                        0
                    },
                    cold_path_active_slot_ids: active_slot_ids,
                    cold_path_active_zone_from: active_zone_from,
                    cold_path_active_zone_to: active_zone_to,
                    cold_path_active_samples: active_samples,
                    cold_path_active_sum_ns: active_sum_ns,
                    cold_path_active_buckets: active_buckets,
                    cold_path_active_builder_collision: active_builder_collision,
                    cold_path_overflow_active: slot_map.overflow_active,
                    // Scalars: u64_is_zero in serde skips them on
                    // the wire when 0; safe to write the raw value
                    // (clock_source.as_str() returns "" for Unset
                    // which String::is_empty skip will also omit).
                    cold_path_sample_phase: cold.sample_phase,
                    cold_path_wrapper_underflow_count: cold.wrapper_underflow_count,
                    cold_path_ns_per_tsc_q32: cold.ns_per_tsc_q32,
                    cold_path_wrapper_ns_baseline: cold.wrapper_ns_baseline,
                    cold_path_clock_source: cold.clock_source.as_str().to_string(),
                    cold_path_snapshot_failed: cold_snapshot_failed,
                }
            })
            .collect()
    }


    pub fn identity_count(&self) -> usize {
        self.workers.identities.len()
    }

    pub fn live_count(&self) -> usize {
        self.workers.live.len()
    }

    pub fn planned_counts(&self) -> (usize, usize) {
        (
            self.workers.last_planned_workers(),
            self.workers.last_planned_bindings(),
        )
    }

    /// #6244: render the typed reconcile stage to its legacy operator string
    /// for the `debug_reconcile_stage` wire field. This (and
    /// `ReconcileError`'s `Display`) are the ONLY places the string is
    /// produced; the strings are preserved byte-for-byte.
    pub fn reconcile_debug(&self) -> (u64, String) {
        (self.reconcile_calls, self.last_reconcile_stage.to_string())
    }
}

/// #1830 (g): write the per-(ifindex, queue) flow-cache active-flow sums
/// onto the aggregated queue status rows. A queue with no flow-cache
/// rows keeps the serde default 0 (idle / not flow-classified), so
/// older consumers and idle queues are indistinguishable from the
/// pre-#1830 wire — the field is purely additive.
fn overlay_cos_flow_fair_flow_counts(
    statuses: &mut [crate::protocol::CoSInterfaceStatus],
    flow_counts: &BTreeMap<(i32, u8), u64>,
) {
    for iface in statuses {
        for queue in &mut iface.queues {
            if let Some(count) = flow_counts.get(&(iface.ifindex, queue.queue_id)) {
                queue.flow_fair_flows_active = *count;
            }
        }
    }
}

fn overlay_shared_cos_queue_lease_statuses(
    statuses: &mut [crate::protocol::CoSInterfaceStatus],
    queue_leases: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
) {
    for iface in statuses {
        for queue in &mut iface.queues {
            let Some(lease) = queue_leases.get(&(iface.ifindex, queue.queue_id)) else {
                continue;
            };
            // #1863 Step-0: per-worker claim-flow counters for every v8
            // lease — BEFORE the equal-flow gate below (these are not
            // equal-flow state; they attribute the honored-realization
            // gap per docs/pr/1863-realization-gap/plan.md §5).
            if let Some((requested, granted)) = lease.v8_worker_claim_flow() {
                queue.lease_v8_worker_requested_bytes = requested;
                queue.lease_v8_worker_granted_bytes = granted;
            }
            if !lease.v8_equal_flow_active() {
                continue;
            }
            queue.equal_flow_enforcement = true;
            queue.equal_flow_enforced = lease.v8_equal_flow_enforced();
            queue.equal_flow_target_per_flow_bps = lease.v8_equal_flow_target_per_flow_bps();
            queue.equal_flow_max_worker_cap_bytes = lease.v8_equal_flow_worker_cap();
            queue.equal_flow_cap_hit_events = lease.v8_equal_flow_cap_hit_events();
            queue.equal_flow_suppressed_grant_bytes = lease.v8_equal_flow_suppressed_grant_bytes();
            queue.equal_flow_stale_or_tag_mismatch_events =
                lease.v8_equal_flow_stale_or_tag_mismatch_events();
            queue.equal_flow_fail_open_reason =
                lease.v8_equal_flow_fail_open_reason_label().to_string();
            // #1746: surface which target policy the lease enforces.
            queue.equal_flow_target_policy = lease.v8_equal_flow_target_policy_label().to_string();
        }
    }
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;

// #6961: the WorkerRuntimeStatus mapping hop — arg-swap binding plus the
// add-a-field ratchet. Its own file because it drives a live Coordinator.
#[cfg(test)]
#[path = "status_mapping_6961_tests.rs"]
mod status_mapping_6961_tests;
