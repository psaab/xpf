// Status projection helpers (#6234 split out of the former monolithic
// `server/helpers.rs`).
//
// `refresh_status` is the single cold-path orchestration that projects
// worker, neighbor, session, NAT, CoS, tunnel, HA, queue, exception, and
// debug state onto the mutable `ProcessStatus`. It runs on control
// responses and state snapshots, never per packet. Ordering + side-effect
// cadence are preserved exactly: the WG/GRE liveness self-heal stays gated
// on `should_run_afxdp`, the high-cardinality per-key dynamic-neighbor
// dump stays gated on `XPF_DEBUG_NEIGHBOR_KEYS`, bindings are refreshed
// before the queue/per-binding projections, and worker snapshots are read
// before the aggregates derived from them. No added coordinator
// traversal, status clone, or allocation. Bodies byte-for-byte identical
// to the pre-split source.

use super::summarize_queues;
use crate::afxdp;
use crate::protocol::{BindingCountersSnapshot, ProcessStatus, UserspaceCapabilities};
use crate::server::ServerState;
use chrono::Utc;

pub(crate) fn refresh_status(state: &mut ServerState) {
    state.afxdp.refresh_bindings(&mut state.status.bindings);
    // #1866 Change 2: WG control-thread self-heal. Tombstone-only +
    // snapshot-coherent (see Coordinator::reconcile_wg_control_liveness)
    // and gated on should_run_afxdp so a disarmed/stopped helper never
    // re-binds WG ports (the stop-gate — Claude SMR r1 F1). Runs on
    // every non-suppressed control response; the per-id 3s backoff and
    // the ≤1-spawn-per-invocation bound keep the cadence trivial.
    if should_run_afxdp(&state.status) {
        state
            .afxdp
            .reconcile_wg_control_liveness(state.snapshot.as_ref());
        // #1881: GRE local-origin self-heal — tombstone-only +
        // snapshot-coherent + worker-gated, ≤1 spawn per invocation;
        // republishes the delivery map when the set changed.
        state
            .afxdp
            .reconcile_local_tunnel_liveness(state.snapshot.as_ref());
    }
    let writer_status = state.state_writer.status();
    state.status.io_uring_active = writer_status.active;
    state.status.io_uring_mode = writer_status.mode;
    state.status.io_uring_last_error = writer_status.last_error;
    state.status.interface_addresses = state
        .snapshot
        .as_ref()
        .map(|s| s.interfaces.iter().map(|iface| iface.addresses.len()).sum())
        .unwrap_or(0);
    let (neighbor_entries, neighbor_generation) = state.afxdp.dynamic_neighbor_status();
    state.status.neighbor_entries = neighbor_entries;
    state.status.neighbor_generation = neighbor_generation;
    // #6034: ACK the highest applied authoritative manager-neighbor replace
    // generation so the Go manager can confirm a clear/replace landed.
    state.status.manager_neighbor_generation =
        state.afxdp.last_applied_manager_neighbor_generation();
    // #710: cluster-wide aggregate of cross-worker CoS no-owner-binding
    // drops. The per-binding increment site is mechanical; this is the
    // only operator-facing surface for the counter.
    state.status.cos_no_owner_binding_drops_total = state.afxdp.cos_no_owner_binding_drops_total();
    // #1636 option C: proactive-neighbor-warm telemetry surfaced to the
    // daemon's Prometheus collector.
    let (warm_drops, warm_disconnected) = state.afxdp.neighbor_warm_counters();
    state.status.neighbor_warm_drops_total = warm_drops;
    state.status.neighbor_warm_disconnected_total = warm_disconnected;
    // #1782 cold-start capture instrumentation: per-binding-summed
    // neg-neigh fast-fail (H1) and pending_neigh duplicate-drop (H5)
    // counters, plus a debug dump of the dynamic_neighbors key set so the
    // capture harness can confirm the t0' next-hop miss (H2).
    state.status.neg_neigh_fast_fail_total = state.afxdp.neg_neigh_fast_fail_total();
    state.status.pending_neigh_duplicate_drops_total =
        state.afxdp.pending_neigh_duplicate_drops_total();
    // #1902: decap-refusal gate at pending_neigh admission (the
    // outer-frame/inner-meta pairing must never reach the in-place
    // retry TX path).
    state.status.pending_neigh_decap_drops_total = state.afxdp.pending_neigh_decap_drops_total();
    // #7106: process-global, not per-binding — a registry that retains buffers
    // is being dropped, so the count has to outlive it.
    // #8447: process-global, like the io_uring counters below — the match path
    // has no per-pool object to hang them on.
    {
        let m = crate::nat::process_source_nat_match_counters().snapshot();
        state.status.source_nat_match_consulted_total = m.consulted;
        state.status.source_nat_match_matched_total = m.matched;
        state.status.source_nat_match_unavailable_total = m.unavailable;
        state.status.source_nat_match_no_match_total = m.no_match;
    }
    state.status.io_uring_retained_buffers_total =
        crate::io_uring_write::process_retained().buffers();
    state.status.io_uring_retained_bytes_total =
        crate::io_uring_write::process_retained().bytes();
    // #7944: capacity refusals, same process-global sink.
    state.status.io_uring_write_refused_total =
        crate::io_uring_write::process_retained().refused_writes();
    state.status.io_uring_write_refused_bytes_total =
        crate::io_uring_write::process_retained().refused_bytes();
    // #2375: distinct-hop capacity-drop gate at pending_neigh admission
    // (a NEW unresolved hop refused because the map is at
    // MAX_PENDING_NEIGH) — the scan/upstream-outage failure mode, kept
    // separate from the duplicate-drop counter.
    state.status.pending_neigh_capacity_drops_total =
        state.afxdp.pending_neigh_capacity_drops_total();
    // #5673: data-path neighbor learns refused by the aggregate
    // dynamic-neighbor map cap. A rising value means a spoofed-source
    // pre-policy flood (source learning runs on RX before screen/policy) is
    // being bounded rather than inflating the shared map.
    state.status.dynamic_neighbor_learn_cap_drops_total =
        state.afxdp.dynamic_neighbor_learn_cap_drops_total();
    // #1789: total failed USERSPACE_SESSIONS BPF-map publishes
    // (per-binding worker-poll sites + shared no-binding sites). The
    // cause-side signal for rising XDP-shim NO_SESSION fallbacks.
    state.status.session_publish_errors_total = state.afxdp.session_publish_errors_total();
    // #4800: new-flow-install contention surface — the publish and
    // replication legs. The NAT-allocator leg rides source_nat_pools.
    state.status.shared_session_publishes_total = state.afxdp.shared_session_publishes_total();
    state.status.owner_rg_filings_declined_total = state.afxdp.owner_rg_filings_declined_total();
    state.status.shared_session_publish_lock_acquisitions_total =
        state.afxdp.shared_session_publish_lock_acquisitions_total();
    state.status.shared_session_publish_lock_contended_total =
        state.afxdp.shared_session_publish_lock_contended_total();
    state.status.session_replication_upserts_total =
        state.afxdp.session_replication_upserts_total();
    state.status.session_replication_enqueued_total =
        state.afxdp.session_replication_enqueued_total();
    state.status.session_replication_lock_contended_total =
        state.afxdp.session_replication_lock_contended_total();
    state.status.session_replication_queue_depth_sum =
        state.afxdp.session_replication_queue_depth_sum();
    state.status.session_replication_queue_depth_max =
        state.afxdp.session_replication_queue_depth_max();
    // #2244: total failed dnat_table reverse-SNAT BPF-map publishes. The
    // cause-side signal for dnat_table capacity pressure that silently
    // breaks embedded-ICMP NAT reversal (PMTUD / traceroute).
    state.status.dnat_publish_errors_total = state.afxdp.dnat_publish_errors_total();
    // #5674: peer-synced session imports rejected by the coordinator's
    // aggregate admission bound — the availability/DoS ceiling that keeps a
    // peer under session-table pressure (or a compromised peer) from driving
    // this node past its own aggregate session ceiling and multiplying that
    // state across every worker.
    state.status.synced_import_cap_drops_total = state.afxdp.synced_import_cap_drops_total();
    // #1760 W3': shared-map NAT reverse-key displacement events — the
    // authoritative collision watch (covers MissingNeighborSeed installs
    // the per-worker counter cannot see).
    state.status.nat_reverse_key_shared_displacements_total =
        state.afxdp.nat_reverse_key_shared_displacements_total();
    // #6751 PR 2/3: the interface-mode SNAT identity registry's three
    // outcomes — the PAT'd collisions this fix creates, and the two distinct
    // fail-closed exhaustion modes it can hit.
    state.status.interface_snat_pat_collisions_total =
        state.afxdp.interface_snat_pat_collisions_total();
    // #7056: the two refused-alias legs, kept apart so an operator can tell a
    // cross-domain probe from a TCP/UDP ident collision.
    state.status.nat64_frag_cross_domain_misses_total =
        state.afxdp.nat64_frag_cross_domain_misses_total();
    state.status.nat64_frag_protocol_alias_misses_total =
        state.afxdp.nat64_frag_protocol_alias_misses_total();
    state.status.interface_snat_identity_exhaustion_total =
        state.afxdp.interface_snat_identity_exhaustion_total();
    state
        .status
        .interface_snat_sync_identity_conflict_drops_total = state
        .afxdp
        .interface_snat_sync_identity_conflict_drops_total();
    state.status.interface_snat_registry_cap_exhaustion_total =
        state.afxdp.interface_snat_registry_cap_exhaustion_total();
    // #1807: worker-command-queue poison recoveries (committed-prefix +
    // clear_poison policy in afxdp/worker_queue.rs). Nonzero = a worker
    // panic poisoned a command queue and it was recovered.
    state.status.worker_command_queue_poison_recoveries =
        state.afxdp.worker_command_queue_poison_recoveries_total();
    // #6929: worker commands dropped at the per-worker queue cap. Nonzero =
    // a producer found a full queue, which points at a worker that stopped
    // draining rather than at a fast producer.
    state.status.worker_command_queue_drops = state.afxdp.worker_command_queue_drops_total();
    // #8586: the DELETE-specific split of the aggregate above.
    state.status.session_delete_replica_dropped =
        state.afxdp.session_delete_replica_dropped_total();
    state.status.session_delete_replica_drop_repaired =
        state.afxdp.session_delete_replica_drop_repaired_total();
    // #9048: the split-brain indicator. Surfaced here rather than parked in
    // UNSURFACED for the reason that allowlist documents — a counter nothing
    // assigns reaches no operator through status, gRPC or Prometheus.
    state.status.peer_delete_refused_local_owned =
        state.afxdp.peer_delete_refused_local_owned_total();
    state.status.shared_session_poison_recoveries =
        state.afxdp.shared_session_poison_recoveries_total();
    // #7398: the three counters below were computed, unit-tested and never
    // assigned into ProcessStatus, so they reached no operator through status,
    // gRPC or Prometheus. They are the queue the UNSURFACED allowlist below
    // existed to hold; wiring them is what empties it.
    state.status.session_install_stale_ignored =
        state.afxdp.session_install_stale_ignored_total();
    state.status.session_delete_stale_ignored =
        state.afxdp.session_delete_stale_ignored_total();
    state.status.session_delete_dropped_released =
        state.afxdp.session_delete_dropped_released_total();
    state.status.tunnel_purge_reservations_released =
        state.afxdp.tunnel_purge_reservations_released_total();
    state.status.synced_import_reserve_refused =
        state.afxdp.synced_import_reserve_refused_total();
    // #7160 (#2387): imports refused for an unresolvable routing domain. Wired
    // here rather than parked in UNSURFACED because that allowlist is
    // deliberately EMPTY (#7398 emptied it), and because this counter is the
    // only signal that a VRF cluster is silently not taking over a subset of
    // its peer's sessions.
    state.status.synced_import_unknown_routing_domain =
        state.afxdp.synced_import_unknown_routing_domain_total();
    // #7209: peer-synced imports whose zone pair did not resolve, so the
    // source-NAT reservation skipped #6211's narrowing. Expected nonzero while
    // a config apply is in flight (sync_session reads the PUBLISHED forwarding
    // view by design) and on a standby's first sync; sustained growth on a
    // settled config means the nodes' zone config has drifted.
    state.status.synced_import_zone_unresolved = state.afxdp.synced_import_zone_unresolved_total();

    // #7209: imports admitted by the local-replace guard that found no kernel
    // session map. Expected nonzero on a standby taking bulk sync before its
    // first apply and across a stop/re-bringup; those are replayed by the next
    // reconcile's capture. It is the instrument for the window that opens if
    // sync_session is taken off the snapshot-wide mutex without a
    // deferred-and-replay path.
    state.status.synced_import_unpublished = state.afxdp.synced_import_unpublished_total();

    // #7209: reverse companions the reconcile replay had to REBUILD because the
    // stored one disagreed with what the live forwarding table resolves. Wired
    // rather than parked in UNSURFACED for the reason given above — that
    // allowlist is deliberately empty (#7398).
    //
    // Nonzero means an import was taken while the table could not answer, and
    // was repaired. Expected on a standby taking bulk sync before its first
    // apply. It is the instrument for the window scope item 2 opens: once a
    // reconcile releases the ServerState lock, imports land against a
    // torn-down table by design, and this is what shows the replay is
    // repairing them rather than the design being asserted from the lock graph.
    state.status.synced_reverse_rederived = state.afxdp.synced_reverse_rederived_total();

    // #2315: GRE-decap RFC 6040 §4.2 illegal-combination drops (outer CE
    // over a Not-ECT inner). Nonzero = a misbehaving tunnel ingress
    // ECT-marked the outer for un-ECN inner traffic on a congested path.
    state.status.gre_decap_ecn_illegal_drops_total =
        state.afxdp.gre_decap_ecn_illegal_drops_total();
    // #2317: WG-decap RFC 6040 §4.2 illegal-combination drops (outer CE,
    // captured via recvmsg IP_RECVTOS/IPV6_RECVTCLASS, over a Not-ECT
    // inner). Nonzero = a misbehaving WG ingress CE-marked the outer for
    // un-ECN inner traffic on a congested path.
    state.status.wg_decap_ecn_illegal_drops_total =
        state.afxdp.wg_decap_ecn_illegal_drops_total();
    // #2331: native-GRE encap DF-set oversized-outer drops. Nonzero =
    // inner flows whose encapped size exceeds the tunnel path MTU; the
    // builder refused to emit the un-fragmentable DF outer (blackhole)
    // rather than silently dropping it downstream.
    state.status.gre_encap_df_oversize_drops_total =
        state.afxdp.gre_encap_df_oversize_drops_total();
    // #2782: native-GRE decap checksum-invalid drops (C bit set but the
    // GRE checksum failed to verify, or the header was truncated past the
    // Checksum+Reserved1 field). Nonzero = a checksummed GRE peer
    // delivering corrupt frames / a truncated GRE header. A verified
    // checksummed frame forwards (RFC 2784 §2.1 / RFC 2890); only the
    // corrupt residue is counted here.
    state.status.gre_decap_checksum_invalid_drops_total =
        state.afxdp.gre_decap_checksum_invalid_drops_total();
    // #6842: native-GRE decap refusals for a non-zero GRE version (RFC
    // 2637 / PPTP is version 1) where the outer tuple named a configured
    // GRE endpoint. Nonzero = a peer offering PPTP/enhanced GRE to a
    // tunnel xpf cannot terminate (no PPTP ALG). Transit PPTP is not
    // counted.
    state.status.gre_decap_unsupported_version_refusals_total =
        state.afxdp.gre_decap_unsupported_version_refusals_total();
    // #2472: locally-generated error-reply per-reason token-bucket drops.
    // Nonzero = an error-amplification / reflection flood (or a routing loop)
    // being clamped before it emits unbounded generated ICMP/RST errors.
    state.status.time_exceeded_rate_limited_total =
        state.afxdp.time_exceeded_rate_limited_total();
    state.status.packet_too_big_rate_limited_total =
        state.afxdp.packet_too_big_rate_limited_total();
    state.status.reject_rate_limited_total = state.afxdp.reject_rate_limited_total();
    // The per-key dynamic_neighbors dump is a high-cardinality
    // (ifindex,ip)-labelled debug surface used only by the #1782 cold-start
    // capture. Gate it behind XPF_DEBUG_NEIGHBOR_KEYS so it is OFF by default:
    // unset -> empty field -> no Prometheus series AND no additional
    // dynamic_neighbor_keys() all-shard traversal here. (The scalar
    // neighbor_entries count above still takes the pre-existing len() shard
    // path regardless — this gate only removes the new per-key dump's
    // traversal + cardinality.) The operator launches the daemon with the env
    // set for the overnight capture only (review consensus: Codex + AGY +
    // Claude SMR all asked for this to be gated, not permanent on /metrics).
    state.status.dynamic_neighbor_keys = if std::env::var_os("XPF_DEBUG_NEIGHBOR_KEYS").is_some() {
        state
            .afxdp
            .dynamic_neighbor_keys()
            .into_iter()
            .map(|(ifindex, ip)| format!("{ifindex} {ip}"))
            .collect()
    } else {
        Vec::new()
    };
    // #1769: on-demand neighbor-resolver telemetry. Previously the only
    // neighbor metrics were the two warm counters; this surfaces the
    // stuck-state surface (pending depth, GET attempts/resolutions/
    // failures, probe-on-stale, epoch rejects, enqueue drops).
    let r = state.afxdp.neighbor_resolver_counters();
    state.status.neighbor_resolver_queue_depth = r.queue_depth;
    state.status.neighbor_resolver_enqueue_drops_total = r.enqueue_drops;
    state.status.neighbor_resolver_disconnected_total = r.disconnected;
    state.status.neighbor_resolver_get_attempts_total = r.get_attempts;
    state.status.neighbor_resolver_get_resolved_total = r.get_resolved;
    state.status.neighbor_resolver_probe_on_stale_total = r.probe_on_stale;
    state.status.neighbor_resolver_get_failures_total = r.get_failures;
    state.status.neighbor_resolver_epoch_rejects_total = r.epoch_rejects;
    // #1771 §2.6: backoff-retry GETs + the monitor thread's ENOBUFS /
    // upsert-only re-dump telemetry (§2.5 mechanism, previously blind).
    state.status.neighbor_resolver_get_backoff_attempts_total = r.get_backoff_attempts;
    state.status.neighbor_netlink_enobufs_total = r.netlink_enobufs;
    state.status.neighbor_netlink_redumps_total = r.netlink_redumps;
    state.status.neighbor_netlink_redump_upserts_total = r.netlink_redump_upserts;
    // #1771 §2.6: per-binding-summed gauges — distinct unresolved
    // next-hop keys in pending_neigh + keys in the negative caches.
    state.status.neighbor_pending_keys = state.afxdp.neighbor_pending_keys_total();
    state.status.neg_neigh_keys = state.afxdp.neg_neigh_keys_total();
    // #1772: neighbor/ARP resolution LATENCY telemetry (pending-dwell +
    // resolver GETNEIGH-RTT histograms + timeout-drop / max-depth).
    let lat = state.afxdp.neighbor_latency_telemetry();
    state.status.neighbor_pending_dwell_buckets = lat.pending_dwell.buckets.to_vec();
    state.status.neighbor_pending_dwell_sum_ns = lat.pending_dwell.sum_ns;
    state.status.neighbor_pending_dwell_count = lat.pending_dwell.count;
    state.status.neighbor_resolver_get_rtt_buckets = lat.resolver_get_rtt.buckets.to_vec();
    state.status.neighbor_resolver_get_rtt_sum_ns = lat.resolver_get_rtt.sum_ns;
    state.status.neighbor_resolver_get_rtt_count = lat.resolver_get_rtt.count;
    // #1865: per-WG-tunnel telemetry rows (empty — and omitted from
    // the wire — when no WG tunnel is configured).
    state.status.wg_tunnels = state.afxdp.wg_tunnel_statuses();
    state.status.neighbor_pending_timeout_drops_total = lat.pending_timeout_drops;
    state.status.neighbor_pending_max_depth = lat.pending_max_depth;
    state.status.route_entries = state.snapshot.as_ref().map(|s| s.routes.len()).unwrap_or(0);
    state.status.fabrics = state
        .snapshot
        .as_ref()
        .map(|s| s.fabrics.clone())
        .unwrap_or_default();
    state.status.worker_heartbeats = state.afxdp.worker_heartbeats();
    // #6979: reclaim any NAT holder bits stranded by a worker that panicked and
    // exited. Driven from this 1 Hz status path because it is the only place
    // that already observes `dead`, and it is one-shot per worker
    // (`holders_retired`), so a healthy node pays one relaxed atomic load per
    // worker per second and nothing else. Called BEFORE the snapshot below so a
    // reclaim and the status it is reported alongside cannot disagree by a tick.
    state.afxdp.retire_dead_worker_holders();
    // #869: per-worker busy/idle runtime telemetry.
    state.status.worker_runtime = state.afxdp.worker_runtime_snapshots();
    state.status.session_table_entries = state
        .status
        .worker_runtime
        .iter()
        .map(|w| w.session_table_entries as usize)
        .sum();
    // #1760: aggregate the per-worker NAT reverse-key displacement
    // counters into the top-level status for operator visibility.
    state.status.nat_reverse_key_collisions = state
        .status
        .worker_runtime
        .iter()
        .map(|w| w.nat_reverse_key_collisions)
        .sum();
    // #1861: aggregate the per-worker install-refusal trio.
    state.status.session_create_drops = state
        .status
        .worker_runtime
        .iter()
        .map(|w| w.session_create_drops)
        .sum();
    state.status.session_install_admission_refused = state
        .status
        .worker_runtime
        .iter()
        .map(|w| w.session_install_admission_refused)
        .sum();
    state.status.session_install_partial = state
        .status
        .worker_runtime
        .iter()
        .map(|w| w.session_install_partial)
        .sum();
    state.status.max_sessions = state
        .status
        .worker_runtime
        .iter()
        .map(|w| w.max_sessions as usize)
        .sum();
    if state.status.max_sessions == 0 {
        state.status.max_sessions = state
            .afxdp
            .worker_count()
            .saturating_mul(crate::session::default_max_sessions());
    }
    state.status.debug_worker_threads = state.afxdp.worker_count();
    state.status.debug_identity_slots = state.afxdp.identity_count();
    state.status.debug_live_slots = state.afxdp.live_count();
    let (planned_workers, planned_bindings) = state.afxdp.planned_counts();
    state.status.debug_planned_workers = planned_workers;
    state.status.debug_planned_bindings = planned_bindings;
    let (reconcile_calls, reconcile_stage) = state.afxdp.reconcile_debug();
    state.status.debug_reconcile_calls = reconcile_calls;
    state.status.debug_reconcile_stage = reconcile_stage;
    state.status.ha_groups = state.afxdp.ha_groups();
    // Report enabled when all bindings are registered+armed (XSKMAP slots
    // populated), NOT when every binding is `ready` (first RX packet
    // received). Requiring `ready` deadlocked bring-up: nothing is admitted
    // to the queue until ctrl is enabled, and ctrl was not enabled until a
    // packet had arrived, so the queue never became ready.
    //
    // A queue whose XSK RQ has not bootstrapped yet is covered by the fill
    // ring being primed BEFORE bind, so the driver's initial NAPI posts WQEs
    // immediately (see `maybe_touch_heartbeat`, which is why no
    // `xsk_rx_confirmed` gating is applied to the heartbeat any more).
    //
    // What such a queue does NOT get is pass-through: the shim drops transit
    // for a binding that is missing, not READY, or whose heartbeat slot is
    // absent or stale, and a slot that was zero-initialised and never stamped
    // reads as stale. Only proven local/control traffic passes while a queue
    // is not carrying (#7233).
    state.status.enabled = state.status.forwarding_armed
        && state.status.capabilities.forwarding_supported
        && !state.status.bindings.is_empty()
        && state
            .status
            .bindings
            .iter()
            .all(|b| b.registered && b.armed);
    state.status.queues = summarize_queues(&state.status.bindings);
    // #802: focused per-binding ring-pressure snapshot. Projected from
    // the freshly-refreshed BindingStatus entries so this field tracks
    // the same data source the richer `bindings[]` view exposes.
    state.status.per_binding = state
        .status
        .bindings
        .iter()
        .map(BindingCountersSnapshot::from)
        .collect();
    state.status.flow_cache_capacity = state
        .status
        .per_binding
        .iter()
        .map(|b| b.flow_cache_capacity as usize)
        .sum();
    // The dynamic neighbor cache is intentionally growable today. Keep
    // the field explicit and zero so Go renders it as a counter rather
    // than inventing a utilization denominator.
    state.status.neighbor_cache_capacity = 0;
    state.status.recent_session_deltas = state.afxdp.recent_session_deltas();
    state.status.recent_exceptions = state.afxdp.recent_exceptions();
    state.status.cos_interfaces = state.afxdp.cos_statuses();
    state.status.policy_rule_counters = state.afxdp.policy_rule_counters();
    state.status.nat_rule_counters = state.afxdp.nat_rule_counters();
    state.status.filter_term_counters = state.afxdp.filter_term_counters();
    // #3651: publish the pre-summed per-zone traffic block. Stamp the layout
    // version only when there is data (rows or overflow) so a helper with no
    // configured/active zones keeps the wire omitted (cold-path convention).
    state.status.zone_traffic_counters = state.afxdp.zone_traffic_counters();
    state.status.zone_counter_overflow_active = state.afxdp.zone_counter_overflow_active();
    state.status.zone_counter_layout_version = if state.status.zone_traffic_counters.is_empty()
        && !state.status.zone_counter_overflow_active
    {
        0
    } else {
        state.afxdp.zone_counter_layout_version()
    };
    // #3651: and the pre-summed per-zone FLOOD-event block, same convention.
    state.status.zone_flood_counters = state.afxdp.zone_flood_counters();
    state.status.flood_counter_overflow_active = state.afxdp.flood_counter_overflow_active();
    state.status.flood_counter_layout_version = if state.status.zone_flood_counters.is_empty()
        && !state.status.flood_counter_overflow_active
    {
        0
    } else {
        state.afxdp.flood_counter_layout_version()
    };
    state.status.three_color_policer_counters = state.afxdp.three_color_policer_counters();
    state.status.source_nat_pools = state.afxdp.source_nat_pool_statuses();
    let (flow_worker_map, flow_worker_map_truncated) = state.afxdp.flow_worker_map();
    state.status.flow_worker_map = flow_worker_map;
    state.status.flow_worker_map_truncated = flow_worker_map_truncated;
    let (cos_active_flow_counts, cos_active_flow_counts_truncated) =
        state.afxdp.cos_active_flow_counts();
    state.status.cos_active_flow_counts = cos_active_flow_counts;
    state.status.cos_active_flow_counts_truncated = cos_active_flow_counts_truncated;
    state.status.last_resolution = state.afxdp.last_resolution();
    state.status.slow_path = state.afxdp.slow_path_status().into();
    if let Some(es_stats) = state.afxdp.event_stream_stats() {
        state.status.event_stream_connected = es_stats.connected;
        state.status.event_stream_seq = es_stats.seq;
        state.status.event_stream_acked = es_stats.acked_seq;
        state.status.event_stream_sent = es_stats.sent;
        state.status.event_stream_dropped = es_stats.dropped;
        state.status.event_stream_write_stalls = es_stats.write_stalls;
        state.status.event_stream_replay_evictions = es_stats.replay_evictions;
        state.status.event_stream_invalid_acks = es_stats.invalid_acks;
        // #9169 / #4800 site 4: the producer-seq lock pair. Published
        // unconditionally and always as a COMPLETE pair — a denominator without
        // its contended half (or the reverse) is not interpretable, and the
        // #4800 analyzer refuses a ratio when the denominator is zero rather
        // than reporting 0.0.
        state.status.event_stream_producer_seq_lock_acquisitions_total =
            es_stats.producer_seq_lock_acquisitions;
        state.status.event_stream_producer_seq_lock_contended_total =
            es_stats.producer_seq_lock_contended;
        // #2512: surface the per-kind SESSION_CLOSE / SESSION_CREATE
        // producer-side sent/dropped counters so a rate-limited or
        // budget-shed close/create is observable in `show` / Prometheus.
        state.status.event_stream_session_close_sent = es_stats.dataplane_events.session_close.sent;
        state.status.event_stream_session_close_dropped =
            es_stats.dataplane_events.session_close.dropped;
        state.status.event_stream_session_create_sent =
            es_stats.dataplane_events.session_create.sent;
        state.status.event_stream_session_create_dropped =
            es_stats.dataplane_events.session_create.dropped;
    }
    state.status.last_cache_flush_at = state.afxdp.last_cache_flush_at();
    // #3773 (M13): surface the cumulative fabric-skip diagnostic atomics so an
    // operator (and Prometheus) sees a silently-unresolved HA cross-chassis
    // fabric link. Malformed = a config/environment fault; unresolved-peer =
    // the expected late-resolution transient (distinct counter).
    state.status.fabric_link_skipped_malformed_total =
        state.afxdp.fabric_link_skipped_malformed_total();
    state.status.fabric_link_unresolved_peer_total =
        state.afxdp.fabric_link_unresolved_peer_total();
    // #9654: capped NOW, from the published runtime view and only while a live
    // worker serves it. None (key omitted) when no worker is live.
    state.status.learned_route_import_capped = state.afxdp.learned_route_import_capped_now();
}

pub(crate) fn forwarding_unsupported_error(cap: &UserspaceCapabilities) -> String {
    if cap.unsupported_reasons.is_empty() {
        return "userspace live forwarding is not supported for the current configuration"
            .to_string();
    }
    format!(
        "userspace live forwarding is not supported: {}",
        cap.unsupported_reasons.join("; ")
    )
}

pub(crate) fn reconcile_status_bindings(
    state: &mut ServerState,
) -> Result<(), afxdp::ReconcileError> {
    if !should_run_afxdp(&state.status) {
        state.afxdp.stop();
        // #2794: route the disarmed-forwarding teardown through
        // `refresh_bindings` rather than hand-clearing a SUBSET of the
        // per-binding fields. `stop()` (above) emptied `workers.live` and
        // cleared the CoS owner maps, so `refresh_bindings` routes every
        // now-workerless slot through `zero_unbound_slot` — clearing the
        // FULL survivor set (`socket_ifindex`/`socket_queue_id`/
        // `socket_bind_flags`, `flow_cache_capacity`, `active_flow_count`,
        // every counter gauge, the latency histograms, and the
        // `bound`/`xsk_registered`/`xsk_bind_mode`/`zero_copy`/`socket_fd`/
        // `ready`/`last_error` fields the old hand-clear touched) AND
        // rebuilds the CoS owner->worker map empty. This is the same tail
        // the no_snapshot reconcile arm now runs (#2515): previously this
        // sibling path left `socket_ifindex`/`queue_id`/`bind_flags` +
        // `flow_cache_capacity`/`active_flow_count` stale, so status
        // commands reported a disarmed slot as if still bound on its old
        // queue.
        let mut bindings = std::mem::take(&mut state.status.bindings);
        state.afxdp.refresh_bindings(&mut bindings);
        state.status.bindings = bindings;
        // A disarmed reconcile is a stop/teardown — always successful.
        return Ok(());
    }
    let snapshot = state.snapshot.clone();
    let ring_entries = state.status.ring_entries;
    let mut bindings = std::mem::take(&mut state.status.bindings);
    // #3789: propagate the reconcile outcome. A pre-teardown abort
    // (integrity / mandatory-map failure) leaves the prior workers +
    // forwarding + generation live (#2440/#2484); the caller uses the
    // Err to fail closed instead of persisting a rejected snapshot.
    let result = state
        .afxdp
        .reconcile(snapshot.as_ref(), &mut bindings, ring_entries);
    state.status.bindings = bindings;
    result
}

pub(crate) fn should_run_afxdp(status: &ProcessStatus) -> bool {
    status.forwarding_armed && status.capabilities.forwarding_supported
}

/// #6750: the arm / registration bits a control handler is about to overwrite,
/// so a FAILED reconcile can put them back.
///
/// Three handlers — `set_forwarding_state`, `set_binding_state`,
/// `set_queue_state` — commit the REQUESTED state into `guard.status` and only
/// then call `reconcile_status_bindings`. #5621/#6135 made the failure honest to
/// the CALLER (ok=false plus the error, no persist), but the committed state
/// stayed committed: the helper went on reporting a posture its AF_XDP sockets
/// had never been reconciled to.
///
/// That retention is what suppresses recovery, and the second half is on the Go
/// side. `syncDesiredForwardingStateLocked` short-circuits on
/// `if m.lastStatus.ForwardingArmed == desired { return nil }`, and the 1 Hz
/// status poll feeds `m.lastStatus` straight from the helper
/// (`applyHelperStatusLocked` -> `recordHelperStatusLocked`). So the poll adopts
/// the retained "armed" the failed reconcile left behind, the equality then
/// holds, and the retry that would have fixed it is never sent. The box stays in
/// the un-reconciled state until something else moves the arm state.
///
/// Restoring makes the helper's report TRUE again, which is all automatic
/// recovery needs: the poll sees the real (still-disarmed) state, the equality
/// fails, and the next tick retries on its own. No new retry machinery, no
/// persisted debt.
pub(crate) struct BindingArmSnapshot {
    forwarding_armed: bool,
    /// (slot, registered, armed, last_change) — keyed by SLOT because that is
    /// how all three handlers address bindings.
    bindings: Vec<(u32, bool, bool, Option<chrono::DateTime<Utc>>)>,
}

/// Capture the bits `restore_binding_arm_state` can put back. Cheap: bounded by
/// the binding count, and only ever called on a control-socket request.
pub(crate) fn capture_binding_arm_state(status: &ProcessStatus) -> BindingArmSnapshot {
    BindingArmSnapshot {
        forwarding_armed: status.forwarding_armed,
        bindings: status
            .bindings
            .iter()
            .map(|b| (b.slot, b.registered, b.armed, b.last_change))
            .collect(),
    }
}

/// Put back exactly what `capture_binding_arm_state` recorded.
///
/// `last_change` is restored too, deliberately. Leaving it advanced would have
/// the helper advertise a transition that was rolled back — an operator reading
/// `show` would see a fresh timestamp on a binding whose state never moved, and
/// the staleness heuristics keyed on it would be reasoning about an event that
/// did not happen.
///
/// A slot that no longer exists is skipped rather than re-created: the
/// reconcile may have replanned, and resurrecting a slot the current plan does
/// not contain would be inventing state rather than restoring it.
pub(crate) fn restore_binding_arm_state(status: &mut ProcessStatus, prior: BindingArmSnapshot) {
    status.forwarding_armed = prior.forwarding_armed;
    for (slot, registered, armed, last_change) in prior.bindings {
        if let Some(binding) = status.bindings.iter_mut().find(|b| b.slot == slot) {
            binding.registered = registered;
            binding.armed = armed;
            binding.last_change = last_change;
        }
    }
}

pub(crate) fn set_bindings_forwarding_armed(status: &mut ProcessStatus, armed: bool) {
    for binding in &mut status.bindings {
        binding.armed = armed && binding.registered;
        binding.last_change = Some(Utc::now());
    }
}

#[cfg(test)]
mod status_wiring_tests {
    /// #6641: every Coordinator `*_total()` counter accessor must actually be
    /// ASSIGNED into `ProcessStatus` by the status refresh above.
    ///
    /// This exists because the populate line is the wiring, and nothing bound
    /// it. Deleting
    ///
    ///     state.status.shared_session_poison_recoveries =
    ///         state.afxdp.shared_session_poison_recoveries_total();
    ///
    /// left the ENTIRE suite green: the serde round-trip tests build a
    /// `ProcessStatus` literal, the Go decode tests parse a literal, and the
    /// Prometheus test feeds a literal — none of them observes whether the
    /// helper ever copies the live counter into the status it sends. Verified
    /// against the #1807 twin as well: deleting ITS populate line was also
    /// silent, so this was a gap in the pattern, not in one instance of it.
    ///
    /// The check is textual because it is a wiring property, not a value
    /// property: there is no cheap way to stand up a full coordinator here,
    /// and a behavioural test that did would still only cover the one counter
    /// it exercised.
    ///
    /// ALLOWLIST: counters that deliberately have no status field yet. Each is
    /// read only by tests today — the same state the #6641 counter was in
    /// before it was surfaced — so the list is a visible queue rather than a
    /// permission slip. Adding a counter here means deciding NOT to show it to
    /// an operator; prefer wiring it.
    // #7398 emptied this queue: all three former entries are now assigned into
    // `ProcessStatus` and exported as Prometheus counters. An EMPTY allowlist
    // is the intended steady state — the dead-entry rejection below means a
    // stale entry fails the gate, so leaving names here after wiring them
    // would break the build rather than rot silently.
    const UNSURFACED: &[&str] = &[];

    fn read(rel: &str) -> String {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
    }

    /// Strip comment lines before scanning.
    ///
    /// Load-bearing, and found the hard way: the doc comment on THIS test
    /// quotes the very assignment the scan looks for, so with comments
    /// included the gate stayed green after the real
    /// `state.status.shared_session_poison_recoveries = ...` line was deleted
    /// — the documentation satisfied the check on the code's behalf. Any
    /// source-scanning gate that can be quoted in prose has this failure mode.
    fn code_only(src: &str) -> String {
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// #6751: drop ALL whitespace before matching.
    ///
    /// The scan looks for `state.afxdp.<name>()` as a CONTIGUOUS substring,
    /// and rustfmt breaks that chain across lines as soon as the assignment's
    /// left-hand side gets long — which a descriptive counter name reaches
    /// easily. The gate then reports a correctly-wired counter as unwired, and
    /// the cheapest way to make that complaint go away is to rename the
    /// counter or add it to `UNSURFACED` — i.e. the false alarm pushes authors
    /// toward the two edits that would ALSO silence a genuine miss. Matching
    /// on the whitespace-free text makes the gate answer the question it means
    /// to ask, and can only be satisfied by the accessor actually being
    /// called. Not theoretical: the wrapped assignment for
    /// `interface_snat_sync_identity_conflict_drops_total` in the refresh
    /// above is what forced this, and deleting that line still reds the gate.
    fn squeeze(src: &str) -> String {
        src.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// Accessor names declared as `pub fn <name>_total(&self) -> u64`.
    fn accessors(src: &str) -> Vec<String> {
        let mut out = Vec::new();
        for line in src.lines() {
            let t = line.trim();
            let Some(rest) = t.strip_prefix("pub fn ") else {
                continue;
            };
            let Some(name) = rest.split('(').next() else {
                continue;
            };
            if name.ends_with("_total") && rest.contains("(&self) -> u64") {
                out.push(name.to_string());
            }
        }
        out.sort();
        out.dedup();
        out
    }

    #[test]
    fn every_counter_accessor_is_wired_into_process_status() {
        let coord = code_only(&read("src/afxdp/coordinator/status.rs"));
        let refresh = squeeze(&code_only(&read("src/server/helpers/status.rs")));

        let accs = accessors(&coord);
        assert!(
            accs.len() >= 20,
            "found only {} `*_total(&self) -> u64` accessors in coordinator/status.rs — the \
             scan pattern has rotted and this gate would pass vacuously",
            accs.len()
        );

        let mut missing = Vec::new();
        for a in &accs {
            if UNSURFACED.contains(&a.as_str()) {
                continue;
            }
            if !refresh.contains(&format!("state.afxdp.{}()", a)) {
                missing.push(a.clone());
            }
        }
        assert!(
            missing.is_empty(),
            "#6641: {} Coordinator counter(s) are never assigned into ProcessStatus by the \
             status refresh, so the helper computes them and an operator never sees them:\n  {}\n\
             Wire each as `state.status.<field> = state.afxdp.<name>();`, or — only if it is \
             deliberately not surfaced — add it to UNSURFACED with a reason.",
            missing.len(),
            missing.join("\n  ")
        );

        // The allowlist must not accumulate dead entries.
        for u in UNSURFACED {
            assert!(
                accs.iter().any(|a| a == u),
                "#6641: UNSURFACED lists {:?}, which is not a Coordinator `*_total()` accessor \
                 any more — a dead entry hides how many counters are really unsurfaced",
                u
            );
        }
    }
}
