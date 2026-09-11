//! #7160: `ProcessStatus` extracted from `protocol/control.rs`.
//!
//! Pure code motion. `control.rs` had grown to 1502 LOC and the touched-file
//! modularity gate reds a PR that pushes a file it touches past 1500. This
//! struct was 792 of those lines — over half the file — and it is a clean
//! seam rather than an arbitrary cut: everything else in `control.rs` is a
//! control-socket REQUEST or RESPONSE message, while this is the periodic
//! STATUS document the Go control plane polls and re-exports as Prometheus
//! series. Splitting it leaves `control.rs` at ~710 lines.
//!
//! Bodies are byte-for-byte identical to their prior location; nothing was
//! renamed and no visibility changed. The `protocol` module re-exports both
//! files with `pub(crate) use`, so every existing `crate::protocol::...` and
//! `crate::ProcessStatus` path resolves unchanged.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ProcessStatus {
    pub pid: i32,
    #[serde(rename = "config_snapshot_protocol_version", default)]
    pub config_snapshot_protocol_version: i32,
    #[serde(rename = "inject_packet_tuple_protocol_version", default)]
    pub inject_packet_tuple_protocol_version: i32,
    /// #9344: the version of the owner-RG session export PAGING contract this
    /// helper implements. 0 (or absent) means "no paging" — the Go caller then
    /// falls back to the pre-#9344 single-shot `max = 0` request rather than
    /// trying to page, because a helper that predates this field honours `max`
    /// and TRUNCATES: it would return exactly `max` deltas with no
    /// `session_export_more` bit, and a truncated window is precisely what
    /// #5085's authoritative receiver turns into deleted live sessions on the
    /// peer.
    ///
    /// An explicit version is used rather than probing because the ambiguous
    /// case is unresolvable by observation: an answer of exactly `max` deltas
    /// with `more` false is EITHER a new helper whose page consumed the window
    /// exactly OR an old helper that silently dropped the remainder, and the
    /// probe that would separate them (send a continuation) is itself unsafe on
    /// an old helper — serde ignores the unknown `continuation` field, so the
    /// old helper would run a second full phase-1 export and hand back a fresh
    /// set from a different instant.
    #[serde(rename = "session_export_paging_protocol_version", default)]
    pub session_export_paging_protocol_version: i32,
    /// #7194: DERIVED fingerprint of the session-open delta wire schema
    /// (protocol::session_delta_schema). Unlike the two version integers above
    /// it is not hand-maintained -- it is computed from the serialized shape of
    /// SessionDeltaInfo, so a field added to one transport and not the other
    /// changes it without anyone remembering to bump anything.
    ///
    /// 0 means "not advertised" (a helper predating this field). The Go gate
    /// treats 0 as unknown-and-deferred, never as a mismatch, so an older
    /// helper is fenced rather than bricked (#1960 no-brick doctrine).
    #[serde(rename = "session_delta_schema_fingerprint", default)]
    pub session_delta_schema_fingerprint: u64,
    /// #9726: the libraries build.rs recorded for this binary.
    /// `linked_libxdp_version` is the build host's libxdp (pkg-config), whose
    /// archive the build confirmed is the one linked. `linked_libbpf_version` is
    /// the full version of the vendored libbpf it linked. `build_host_libbpf_version`
    /// is the build host's libbpf (pkg-config); it is not linked, and it does not
    /// identify what libxdp was compiled against. Empty from a helper that
    /// predates the fields.
    #[serde(rename = "linked_libxdp_version", default)]
    pub linked_libxdp_version: String,
    #[serde(rename = "linked_libbpf_version", default)]
    pub linked_libbpf_version: String,
    #[serde(rename = "build_host_libbpf_version", default)]
    pub build_host_libbpf_version: String,
    #[serde(rename = "started_at")]
    pub started_at: DateTime<Utc>,
    #[serde(rename = "control_socket")]
    pub control_socket: String,
    #[serde(rename = "state_file")]
    pub state_file: String,
    pub workers: usize,
    #[serde(rename = "ring_entries")]
    pub ring_entries: usize,
    #[serde(rename = "helper_mode")]
    pub helper_mode: String,
    #[serde(rename = "io_uring_planned")]
    pub io_uring_planned: bool,
    #[serde(rename = "io_uring_active", default)]
    pub io_uring_active: bool,
    #[serde(rename = "io_uring_mode", default)]
    pub io_uring_mode: String,
    #[serde(rename = "io_uring_last_error", default)]
    pub io_uring_last_error: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(rename = "forwarding_armed", default)]
    pub forwarding_armed: bool,
    #[serde(default)]
    pub capabilities: UserspaceCapabilities,
    #[serde(rename = "last_snapshot_generation")]
    pub last_snapshot_generation: u64,
    #[serde(rename = "last_fib_generation", default)]
    pub last_fib_generation: u32,
    #[serde(rename = "last_snapshot_at", skip_serializing_if = "Option::is_none")]
    pub last_snapshot_at: Option<DateTime<Utc>>,
    #[serde(rename = "interface_addresses", default)]
    pub interface_addresses: usize,
    #[serde(rename = "neighbor_entries", default)]
    pub neighbor_entries: usize,
    /// Total entries installed in the Rust-owned worker session tables.
    /// Additive for mixed-version compatibility: older helpers omit it
    /// and Go treats zero max_sessions as "no denominator available".
    #[serde(rename = "session_table_entries", default)]
    pub session_table_entries: usize,
    /// Aggregate capacity of the Rust-owned worker session tables.
    #[serde(rename = "max_sessions", default)]
    pub max_sessions: usize,
    /// #1760: aggregate NAT reverse-key displacement events summed across
    /// the per-worker session tables — the latent 1:N collision (#1758)
    /// made observable. A near-precise upper bound on live collisions
    /// (counts displacement *events*, not distinct flow-pairs). Additive
    /// for mixed-version compatibility: older helpers omit it (defaults to
    /// 0). A nonzero value triggers the structural-fix research; this
    /// counter does NOT resolve #1760.
    #[serde(rename = "nat_reverse_key_collisions", default)]
    pub nat_reverse_key_collisions: u64,
    /// #6751: the DIFFERENT-SOURCE subset of the counter above. Additive and
    /// `default`ed, so an older helper that does not send it deserializes to 0
    /// rather than failing the status parse (#1961 additive-counter rule).
    #[serde(rename = "nat_reverse_key_collisions_distinct_src", default)]
    pub nat_reverse_key_collisions_distinct_src: u64,
    /// #6751 PR 2/3: interface-mode SNAT identity-mint conflicts that took the
    /// PAT probe — how often two flows actually contend for one translated
    /// reverse identity. Additive + `default`ed (#1961).
    #[serde(rename = "interface_snat_pat_collisions_total", default)]
    pub interface_snat_pat_collisions_total: u64,
    /// #7056 (#5798 required-fix #5): fragment-association misses caused by the
    /// key refusing a CROSS-DOMAIN alias — a same-datagram entry under a
    /// different ingress security domain. Previously indistinguishable from a
    /// reorder / TTL straddle / eviction on `nat64_frag_dropped`. Additive +
    /// `default`ed (#1961), so an older helper that does not emit it decodes 0.
    #[serde(rename = "nat64_frag_cross_domain_misses_total", default)]
    pub nat64_frag_cross_domain_misses_total: u64,
    /// #7056: the sibling leg — same domain, PROTOCOL alias (TCP vs UDP on one
    /// `(src, dst, ident)`). Distinct from the cross-domain counter on purpose.
    /// Additive + `default`ed (#1961).
    #[serde(rename = "nat64_frag_protocol_alias_misses_total", default)]
    pub nat64_frag_protocol_alias_misses_total: u64,
    /// #6751 PR 2/3: interface-mode SNAT admissions that failed CLOSED with no
    /// free translated identity — a completed full-cycle PAT probe, a port-less
    /// protocol whose single identity is owned, or a peer-synced import whose
    /// identity a local flow already holds. Additive + `default`ed (#1961).
    #[serde(rename = "interface_snat_identity_exhaustion_total", default)]
    pub interface_snat_identity_exhaustion_total: u64,
    /// #6751 PR 2/3: peer-synced interface-SNAT imports DROPPED because a
    /// different live flow on this node already owns the translated identity
    /// the active assigned. An HA-fidelity loss, not a data-path drop, so it
    /// is its own series. Additive + `default`ed (#1961).
    #[serde(rename = "interface_snat_sync_identity_conflict_drops_total", default)]
    pub interface_snat_sync_identity_conflict_drops_total: u64,
    /// #6751 PR 2/3: interface-mode SNAT admissions that failed CLOSED because
    /// no more REGISTRY state could be created (retained-allocator cap with
    /// nothing reclaimable, or the per-address tracked-flow cap). Distinct from
    /// identity exhaustion because the remedy differs. Additive + `default`ed.
    #[serde(rename = "interface_snat_registry_cap_exhaustion_total", default)]
    pub interface_snat_registry_cap_exhaustion_total: u64,
    /// #1861: aggregate at-cap install refusals summed across the
    /// per-worker session tables (`SessionTable::create_drops` — was
    /// write-only/invisible before #1861). Additive: older helpers omit
    /// it (defaults to 0).
    #[serde(rename = "session_create_drops", default)]
    pub session_create_drops: u64,
    /// #1861: aggregate pair-admission preflight refusals (one per
    /// refused flow) — the new-flow transaction boundary dropping a
    /// trigger packet at/near max_sessions. Additive.
    #[serde(rename = "session_install_admission_refused", default)]
    pub session_install_admission_refused: u64,
    /// #1861: aggregate post-preflight partial-install residuals.
    /// Expected 0 forever; nonzero means the preflight/install pairing
    /// has a bug. Additive.
    #[serde(rename = "session_install_partial", default)]
    pub session_install_partial: u64,
    /// Aggregate per-binding flow-cache capacity across helper-published
    /// binding status rows. Zero means unavailable, not full.
    #[serde(rename = "flow_cache_capacity", default)]
    pub flow_cache_capacity: usize,
    /// Hard capacity for the dynamic neighbor cache. The current
    /// sharded map is growable, so zero intentionally suppresses
    /// utilization rows until Rust owns a real bounded denominator.
    #[serde(rename = "neighbor_cache_capacity", default)]
    pub neighbor_cache_capacity: usize,
    #[serde(rename = "neighbor_generation", default)]
    pub neighbor_generation: u64,
    /// #6034: ACK of the highest authoritative manager-neighbor REPLACE
    /// generation the helper has applied. Distinct from
    /// `neighbor_generation` (the dynamic ARP/NDP resolver epoch): this
    /// echoes the `neighbor_generation` field the Go manager stamps on an
    /// `update_neighbors` replace so the manager can confirm the clear /
    /// replace landed and retain retry debt otherwise. Additive / defaulted:
    /// an older helper omits it (Go decodes 0 → treats as "no ACK support,
    /// assume applied", preserving pre-#6034 behavior).
    #[serde(rename = "manager_neighbor_generation", default)]
    pub manager_neighbor_generation: u64,
    #[serde(rename = "route_entries", default)]
    pub route_entries: usize,
    #[serde(rename = "worker_heartbeats", default)]
    pub worker_heartbeats: Vec<DateTime<Utc>>,
    /// #869: per-worker busy/idle runtime telemetry.  Empty on
    /// dataplanes that don't publish.  Additive / defaulted for
    /// backward compatibility with older daemon builds.
    #[serde(rename = "worker_runtime", default)]
    pub worker_runtime: Vec<WorkerRuntimeStatus>,
    // #710: cluster-wide aggregate of cross-worker CoS redirects that
    // could not locate a binding for their target egress on the landing
    // worker. Summed across all bindings in `refresh_status` — the
    // per-binding accounting is a mechanical choice (the increment
    // always lands on the landing worker's first binding), so the
    // per-binding view would be misleading as triage signal; the total
    // is the operator-facing number.
    #[serde(rename = "cos_no_owner_binding_drops_total", default)]
    pub cos_no_owner_binding_drops_total: u64,
    /// #1636 option C: proactive-neighbor-warm telemetry. `warm_drops`
    /// counts warm requests dropped because the bounded warmer queue was
    /// full (transient saturation under route churn); `warm_disconnected`
    /// counts requests dropped because the warmer worker thread died
    /// (fatal — warming disabled until restart). Both are the only
    /// operator-visible signal in production builds (debug-log off) and
    /// are surfaced as Prometheus counters by the Go collector. Additive
    /// / defaulted for backward compatibility with older daemons.
    #[serde(rename = "neighbor_warm_drops_total", default)]
    pub neighbor_warm_drops_total: u64,
    #[serde(rename = "neighbor_warm_disconnected_total", default)]
    pub neighbor_warm_disconnected_total: u64,
    /// #1782 cold-start capture instrumentation. Per-binding-summed
    /// count of neg-neigh-cache fast-fails (H1 amplifier signal) and of
    /// `pending_neigh` sibling drops where the `(egress_ifindex,
    /// next_hop)` key was already pending (H5 sibling-drop signal). Both
    /// are surfaced as Prometheus counters by the Go collector. Additive
    /// / defaulted for backward compatibility with older daemons.
    #[serde(rename = "neg_neigh_fast_fail_total", default)]
    pub neg_neigh_fast_fail_total: u64,
    #[serde(rename = "pending_neigh_duplicate_drops_total", default)]
    pub pending_neigh_duplicate_drops_total: u64,
    /// #1902: GRE-decapped MissingNeighbor packets refused
    /// `pending_neigh` admission (buffering the outer UMEM frame with
    /// the post-decap inner meta would retry-TX a mis-rewritten outer
    /// packet). Additive / defaulted for backward compatibility.
    #[serde(rename = "pending_neigh_decap_drops_total", default)]
    pub pending_neigh_decap_drops_total: u64,
    /// #7106: buffers this process RETAINED (leaked) at io_uring ring teardown
    /// because the bounded drain could not prove the kernel was done with them.
    ///
    /// Cumulative and normally 0. Non-zero means a ring was retired while
    /// writes it had submitted could not be proven terminal, so their buffers
    /// were deliberately not returned to the allocator. Without this the
    /// condition is silent by construction: the whole point is that nothing
    /// further is ever heard about those writes.
    /// #8447: source-NAT rule-match outcomes. `consulted` counts every packet
    /// that REACHED the match path, including the ones that matched nothing —
    /// which is what makes a zero in the other three readable. Without it,
    /// "nothing matched" and "nothing arrived" are the same number.
    #[serde(rename = "source_nat_match_consulted_total", default)]
    pub source_nat_match_consulted_total: u64,
    #[serde(rename = "source_nat_match_matched_total", default)]
    pub source_nat_match_matched_total: u64,
    #[serde(rename = "source_nat_match_unavailable_total", default)]
    pub source_nat_match_unavailable_total: u64,
    #[serde(rename = "source_nat_match_no_match_total", default)]
    pub source_nat_match_no_match_total: u64,
    #[serde(rename = "io_uring_retained_buffers_total", default)]
    pub io_uring_retained_buffers_total: u64,
    /// Bytes held by `io_uring_retained_buffers_total`.
    #[serde(rename = "io_uring_retained_bytes_total", default)]
    pub io_uring_retained_bytes_total: u64,
    /// #7944: writes REFUSED because the io_uring in-flight registry was at
    /// capacity. Distinct from the retained counters above: nothing was
    /// submitted and nothing is retained — the buffer went back to the caller,
    /// which wrote it synchronously. Non-zero means a ring is parking buffers
    /// faster than it reaps them (a sustained wait-retry storm), which without
    /// the cap was an unbounded memory vector.
    #[serde(rename = "io_uring_write_refused_total", default)]
    pub io_uring_write_refused_total: u64,
    /// Bytes belonging to `io_uring_write_refused_total`.
    #[serde(rename = "io_uring_write_refused_bytes_total", default)]
    pub io_uring_write_refused_bytes_total: u64,
    /// #2375: MissingNeighbor packets for a NEW distinct
    /// `(egress_ifindex, next_hop)` refused because `pending_neigh` is at
    /// `MAX_PENDING_NEIGH` distinct hops (distinct-hop neighbor
    /// exhaustion — the scan/upstream-outage failure mode). Kept distinct
    /// from `pending_neigh_duplicate_drops_total` (the key was already
    /// pending — normal cold-start coalescing). Additive / defaulted for
    /// backward compatibility with older daemons.
    #[serde(rename = "pending_neigh_capacity_drops_total", default)]
    pub pending_neigh_capacity_drops_total: u64,
    /// #5673: cumulative data-path neighbor LEARNS refused because the
    /// dynamic-neighbor map's target shard was at
    /// `MAX_DYNAMIC_NEIGHBORS_PER_SHARD`. Source-address learning runs on RX
    /// BEFORE screen/policy admission, so an attacker on an untrusted segment
    /// can otherwise inflate the shared map with one entry per spoofed source
    /// (a pre-policy CPU/memory DoS). A rising value is the always-on signal
    /// that the aggregate cap is bounding such a flood. Additive / defaulted
    /// for backward compatibility with older daemons.
    #[serde(rename = "dynamic_neighbor_learn_cap_drops_total", default)]
    pub dynamic_neighbor_learn_cap_drops_total: u64,
    /// #1789: total failed USERSPACE_SESSIONS BPF-map publishes
    /// (per-binding worker-poll sites summed with the shared no-binding
    /// sites: HA upsert, session-glue worker publish, post-reconcile
    /// replay, activation/reverse prewarm). Always-on cause-side signal
    /// for rising XDP-shim NO_SESSION degraded-path fallbacks (session
    /// map at capacity, stale fd after reconcile). Surfaced as the
    /// Prometheus counter `xpf_userspace_session_publish_errors_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "session_publish_errors_total", default)]
    pub session_publish_errors_total: u64,
    /// #4800: cross-worker contention accounting for the per-new-flow
    /// install path, so a connection-rate run can name the saturated
    /// synchronization point instead of inferring one from a flattened
    /// new-flows/sec curve.
    ///
    /// Read as pairs: `..._lock_contended_total / ..._lock_acquisitions_total`
    /// is the publish leg's blocked fraction, and
    /// `session_replication_lock_contended_total / session_replication_enqueued_total`
    /// the replication leg's. `session_replication_enqueued_total /
    /// session_replication_upserts_total` recovers the N-way sibling
    /// fan-out. `session_replication_queue_depth_max` is a monotonic
    /// high-water gauge, not a counter — do not `rate()` it.
    ///
    /// The NAT-allocator leg is per pool and rides `source_nat_pools`
    /// (`live_lock_acquisitions_total` / `live_lock_contended_total`)
    /// rather than these process-global fields. All additive / defaulted
    /// for backward compatibility.
    #[serde(rename = "shared_session_publishes_total", default)]
    pub shared_session_publishes_total: u64,

    /// #8486: owner-RG index filings declined because the peer-supplied
    /// `owner_rg_id` was outside the 0..15 range the Go strict validator
    /// enforces. Nonzero means a peer is sending redundancy-group ids this
    /// cluster's own strict path would reject. `default` so an older helper
    /// that does not send the field decodes as 0 rather than failing the
    /// whole status parse.
    #[serde(rename = "owner_rg_filings_declined_total", default)]
    pub owner_rg_filings_declined_total: u64,
    #[serde(rename = "shared_session_publish_lock_acquisitions_total", default)]
    pub shared_session_publish_lock_acquisitions_total: u64,
    #[serde(rename = "shared_session_publish_lock_contended_total", default)]
    pub shared_session_publish_lock_contended_total: u64,
    #[serde(rename = "session_replication_upserts_total", default)]
    pub session_replication_upserts_total: u64,
    #[serde(rename = "session_replication_enqueued_total", default)]
    pub session_replication_enqueued_total: u64,
    #[serde(rename = "session_replication_lock_contended_total", default)]
    pub session_replication_lock_contended_total: u64,
    /// #4800: sum of the per-call deepest sibling-queue depth. Divided by
    /// `session_replication_upserts_total` over the same window this is the
    /// MEAN worst-sibling depth per replicated flow — the differenceable
    /// backlog statistic. The `_max` below is a process-lifetime high-water
    /// that CANNOT be differenced (it never falls, so a zero delta is
    /// ambiguous and the absolute value stays elevated forever after one
    /// spike) and is therefore operator context only, never a verdict input.
    #[serde(rename = "session_replication_queue_depth_sum", default)]
    pub session_replication_queue_depth_sum: u64,
    #[serde(rename = "session_replication_queue_depth_max", default)]
    pub session_replication_queue_depth_max: u64,
    /// #2244: total failed `dnat_table` reverse-SNAT BPF-map publishes
    /// summed across worker bindings. The `dnat_table` is the reverse
    /// lookup the embedded-ICMP NAT path consults to map an inbound ICMP
    /// error (PMTUD Packet Too Big / Time Exceeded / traceroute) back to
    /// the original pre-NAT source; a failed publish silently omits the
    /// record so the error is dropped or mis-delivered. Always-on
    /// cause-side signal for `dnat_table` map-capacity pressure. Surfaced
    /// as the Prometheus counter `xpf_userspace_dnat_publish_errors_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "dnat_publish_errors_total", default)]
    pub dnat_publish_errors_total: u64,
    /// #5674: peer-synced session imports rejected by the coordinator's
    /// aggregate admission bound (`upsert_synced_session`). Locally-created
    /// sessions are capped per worker at `max_sessions`; peer-synced imports
    /// were previously uncapped and fanned out to every worker, so a peer under
    /// session-table pressure (or a compromised peer) could drive this node
    /// past its own aggregate session ceiling and multiply that state across
    /// all workers. A rising value means a peer exceeded this appliance's own
    /// ceiling — stated in ENTRIES as `2 * worker_count * max_sessions` (#6413),
    /// matching `synced_import_cap`, not the LOGICAL `worker_count *
    /// max_sessions`. Each admitted forward publishes TWO keys (the forward and
    /// its synthesized reverse companion), so N logical sessions arrive as 2N
    /// entries and EXACTLY fit the cap; it never trips on a legitimate
    /// symmetric-pair failover. Surfaced as the Prometheus counter
    /// `xpf_userspace_synced_import_cap_drops_total`. Additive / defaulted for
    /// backward compatibility.
    #[serde(rename = "synced_import_cap_drops_total", default)]
    pub synced_import_cap_drops_total: u64,
    /// #1760 W3': shared-map NAT reverse-key displacement events — a
    /// `publish_shared_session` insert into `shared_nat_sessions`
    /// displaced a DIFFERENT forward session's entry at the same reverse
    /// key (two live forward NAT sessions mapping onto one reply tuple —
    /// the #1758/#1760 latent 1:N collision). The shared map is the
    /// single choke point all transit forward NAT sessions pass through,
    /// including `MissingNeighborSeed` installs the per-worker
    /// `nat_reverse_key_collisions` counter cannot see. Event count, not
    /// a pair census. Surfaced as the Prometheus counter
    /// `xpf_userspace_session_nat_reverse_key_shared_displacements_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "nat_reverse_key_shared_displacements_total", default)]
    pub nat_reverse_key_shared_displacements_total: u64,
    /// #1807: total worker-command-queue poison recoveries (a thread
    /// panicked while holding a `Mutex<VecDeque<WorkerCommand>>`; the
    /// committed queue was recovered via into_inner and the poison
    /// cleared — uniform policy in afxdp/worker_queue.rs, extends
    /// #1790). Nonzero means a worker panic happened and the command
    /// queues kept flowing instead of going permanently deaf. Surfaced
    /// as the Prometheus counter
    /// `xpf_userspace_worker_command_queue_poison_recoveries_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "worker_command_queue_poison_recoveries", default)]
    pub worker_command_queue_poison_recoveries: u64,
    /// #6929: worker commands DROPPED because the target per-worker queue
    /// was already at `MAX_PENDING_WORKER_COMMANDS` (4096).
    ///
    /// Read alongside `worker_command_queue_poison_recoveries` and not in
    /// place of it: that counter means a queue was RECOVERED with its
    /// committed prefix intact and nothing was lost, this one means a
    /// command was DISCARDED.
    ///
    /// #8586: an earlier revision of this doc said "the expected steady-state
    /// value is 0, because the consumer drains the whole deque in one
    /// `core::mem::take` and so cannot be outrun by a sustained producer. A
    /// rising value therefore does not mean 'busy'; it means some worker has
    /// stopped draining." That reasoning was true when it was written and #7201
    /// hollowed it: the consumer now takes a BOUNDED front prefix of at most
    /// `WORKER_COMMAND_DRAIN_BUDGET` (256) per loop pass, precisely so the
    /// worker's AF_XDP rings are not left unserviced for the 3.85 ms a full
    /// 4096-command drain measured. A bounded consumer CAN be outrun.
    ///
    /// Measured on `loss:xpf-userspace-fw0` with every worker alive and no
    /// panic: 709,394 drops against 874,950 replication enqueues (81%) with
    /// `session_replication_queue_depth_max` pinned at the 4096 cap, under
    /// ordinary session establishment. So a rising value does NOT by itself
    /// mean a worker stopped draining, and an operator who reads it that way
    /// goes looking for a panic that is not there. Pair it with
    /// `worker_command_queue_poison_recoveries` and the per-worker liveness in
    /// `worker_runtime` before concluding a thread died. Surfaced as the
    /// Prometheus counter
    /// `xpf_userspace_worker_command_queue_drops_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "worker_command_queue_drops", default)]
    pub worker_command_queue_drops: u64,
    /// #8586: the subset of the drops above that were cross-worker
    /// `DeleteSynced` replicas, and the subset of THOSE whose owning worker was
    /// identified so its NAT teardown could be run on its behalf (#8576).
    ///
    /// Two fields, not one, and not folded into the counter above. The
    /// aggregate says a producer found a full queue; it cannot say whether what
    /// was lost was an `UpsertSynced` (a replica the shared map still holds) or
    /// a `DeleteSynced` (a session a sibling worker keeps serving, plus a NAT
    /// reservation held for the life of the allocator). Those have opposite
    /// severities, and #8586's whole question — how often the queue reaches the
    /// cap on the paths where a DELETE is what gets lost — cannot be read off
    /// the aggregate.
    ///
    /// `dropped - repaired` is the UNATTRIBUTED remainder: a refused delete
    /// whose queue could not be resolved to a worker id, so nothing ran on its
    /// behalf. A single number could not distinguish "no drops" from "drops
    /// nobody repaired".
    #[serde(rename = "session_delete_replica_dropped", default)]
    pub session_delete_replica_dropped: u64,
    #[serde(rename = "session_delete_replica_drop_repaired", default)]
    pub session_delete_replica_drop_repaired: u64,
    /// #9048: peer `DeleteSynced` commands REFUSED because the key named a
    /// LIVE LOCAL session this node is actively forwarding for — the
    /// delete-side mirror of the install-side clobber guard in
    /// `upsert_synced_with_origin`.
    ///
    /// Non-zero means the cluster is, or recently was, DUAL-PRIMARY for some
    /// redundancy group. The delta emitter is gated on `IsPrimaryForRGFn`, so
    /// in normal operation exactly one node emits deletes and the receiver's
    /// entries at those keys carry a peer-synced origin — the guard is inert
    /// and this stays flat at zero. It is the ONLY surface that reports the
    /// refusal, which is otherwise silent by design: the condition that
    /// produces it produces one per closing flow, so a log line would be a
    /// storm exactly when the cluster is already in trouble.
    #[serde(rename = "peer_delete_refused_local_owned", default)]
    pub peer_delete_refused_local_owned: u64,
    /// #2402/#6641: total shared-session mutex poison recoveries (a
    /// worker thread panicked while holding a shared-session or
    /// owner-RG-index mutex; the committed map was recovered and the
    /// poison cleared — afxdp/shared_ops.rs, mirroring the #1807
    /// worker-queue policy). Nonzero means a worker panic happened and
    /// the HA session state survived it instead of being silently
    /// emptied at failover (the #2402 bug). Surfaced as the Prometheus
    /// counter `xpf_userspace_shared_session_poison_recoveries_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "shared_session_poison_recoveries", default)]
    pub shared_session_poison_recoveries: u64,
    /// #2170/#7398: stale-generation session INSTALLS refused by the helper's
    /// in-memory `SyncedSessionEntry` guard (the delayed-stale-install
    /// variant). The authoritative guard is the Go cluster apply layer; this
    /// is the helper-side back-stop, so a nonzero value means a delayed peer
    /// install arrived after a newer generation had already been committed and
    /// the helper declined to regress it. Surfaced as
    /// `xpf_userspace_session_install_stale_ignored_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "session_install_stale_ignored", default)]
    pub session_install_stale_ignored: u64,
    /// #2170/#7398: stale-generation session DELETES refused by the same
    /// helper-side guard. Nonzero means a delete for a generation older than
    /// the committed entry arrived and was ignored rather than being allowed
    /// to remove a session a newer generation had installed. Surfaced as
    /// `xpf_userspace_session_delete_stale_ignored_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "session_delete_stale_ignored", default)]
    pub session_delete_stale_ignored: u64,
    /// #6979 F4: synced-session deletes whose `DeleteSynced` command was
    /// dropped by a full worker command queue, and whose NAT reservation the
    /// coordinator therefore released on that worker's behalf.
    ///
    /// Nonzero means a worker command queue hit its bound during a delete. The
    /// reservation is not leaked — that is what this counts — but the same
    /// dropped command also cost that worker its local session-table and BPF
    /// map teardown for the key, so a climbing value is real backpressure, not
    /// bookkeeping. Surfaced as
    /// `xpf_userspace_session_delete_dropped_released_total`.
    #[serde(rename = "session_delete_dropped_released", default)]
    pub session_delete_dropped_released: u64,
    /// #8138: import-time `Untracked` NAT reservations the tunnel-remap purge
    /// released. A purged session whose reservation no worker had adopted would
    /// otherwise strand its `(pool_addr, port)` for the life of the allocator.
    /// Counts ACTUAL frees only, never attempts.
    /// `xpf_userspace_tunnel_purge_reservations_released_total`.
    #[serde(rename = "tunnel_purge_reservations_released", default)]
    pub tunnel_purge_reservations_released: u64,
    /// #6600/#7398: peer-synced imports refused because this node could not
    /// reserve the translated NAT port the session names. Sustained growth
    /// means the standby cannot hold the primary's translations, so those
    /// flows will not survive a failover — the counter an operator needs
    /// BEFORE the failover rather than after. Surfaced as
    /// `xpf_userspace_synced_import_reserve_refused_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "synced_import_reserve_refused", default)]
    pub synced_import_reserve_refused: u64,
    /// #7160 (#2387): peer-synced imports refused because this node runs
    /// routing instances and the request named no ingress identity to resolve
    /// the session's routing DOMAIN from. Importing under domain 0 would file
    /// the session in the DEFAULT instance's identity space, where a reply
    /// that resolved its own domain reaches it — so it is refused instead.
    /// Sustained growth on a VRF cluster means those flows will NOT be taken
    /// over on failover; always 0 on a single-instance node. Surfaced as
    /// `xpf_userspace_synced_import_unknown_routing_domain_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "synced_import_unknown_routing_domain", default)]
    pub synced_import_unknown_routing_domain: u64,
    /// #7209: peer-synced imports whose zone pair did not resolve, so the
    /// source-NAT reservation skipped #6211's zone narrowing. Surfaced as
    /// `xpf_userspace_synced_import_zone_unresolved_total`.
    #[serde(default)]
    pub synced_import_zone_unresolved: u64,
    /// #7209: peer-synced imports the local-replace guard ADMITTED but which
    /// had no kernel session map to publish into. Surfaced as
    /// `xpf_userspace_synced_import_unpublished_total`.
    ///
    /// Additive / defaulted: decodes to 0 against a helper that predates this
    /// field, which reads as "never happened". Acceptable because the counter
    /// is diagnostic and, on a pre-#7209 helper, the window it reports is
    /// genuinely closed by the snapshot-wide mutex.
    #[serde(default)]
    pub synced_import_unpublished: u64,
    /// #7209: reverse companions RE-DERIVED at reconcile replay because the
    /// stored one disagreed with what the live forwarding table resolves.
    /// Surfaced as `xpf_userspace_synced_reverse_rederived_total`.
    ///
    /// Additive / defaulted, same reasoning as the field above: it decodes to 0
    /// against a helper that predates it, which reads as "never happened" — and
    /// on such a helper the replay genuinely never re-derived anything, so 0 is
    /// the truthful value rather than a silent gap.
    #[serde(default)]
    pub synced_reverse_rederived: u64,
    /// #2315: GRE-decap frames dropped by the RFC 6040 §4.2 decap-side
    /// ECN combine because the outer header carried a CE mark over an
    /// inner packet that was Not-ECT (the illegal combination — a
    /// congested router CE-marked a packet whose endpoints never
    /// negotiated ECN). RFC 6040 mandates a drop here rather than
    /// silently clearing the bogus CE. Surfaced as the Prometheus
    /// counter `xpf_userspace_gre_decap_ecn_illegal_drops_total`;
    /// nonzero flags a misbehaving tunnel ingress on a congested path.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "gre_decap_ecn_illegal_drops_total", default)]
    pub gre_decap_ecn_illegal_drops_total: u64,
    /// #2317: WireGuard-decap inner packets dropped by the SAME RFC 6040
    /// §4.2 decap-side ECN combine, for the WG path. The WG decap site
    /// captures the outer ECN out-of-band via `recvmsg` +
    /// `IP_RECVTOS`/`IPV6_RECVTCLASS` (the kernel UDP socket strips the
    /// outer IP header before userspace) and feeds it into the same
    /// combine. Surfaced as the Prometheus counter
    /// `xpf_userspace_wg_decap_ecn_illegal_drops_total`; nonzero flags a
    /// misbehaving WG ingress on a congested path. Additive / defaulted
    /// for backward compatibility.
    #[serde(rename = "wg_decap_ecn_illegal_drops_total", default)]
    pub wg_decap_ecn_illegal_drops_total: u64,
    /// #2331: native-GRE encap frames DROPPED because the fully built
    /// outer datagram (outer IP + GRE[+key] + inner) exceeded the
    /// resolved transport/egress MTU while the IPv4 outer carries DF=1
    /// (the only outer the native encap builder emits). A DF-set
    /// oversized outer cannot be fragmented downstream and would
    /// silently blackhole every inner flow with no PMTUD signal — so the
    /// builder refuses to emit it. Surfaced as the Prometheus counter
    /// `xpf_userspace_gre_encap_df_oversize_drops_total`; nonzero flags
    /// inner flows whose encapped size exceeds the tunnel path MTU.
    /// PMTUD/PTB signalling for this path LANDED in #2330 (TX dispatcher,
    /// tx/dispatch/mod.rs): where a PTB is owed the pre-build decision emits
    /// it and skips the encap, so it is not counted here. This counter is
    /// the no-PTB-owed residual, a non-DF IPv4 inner whose encapped outer
    /// still exceeds the DF-set transport MTU (#8942 — this line used to say
    /// "deferred to #2330", which read as outstanding after it shipped).
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "gre_encap_df_oversize_drops_total", default)]
    pub gre_encap_df_oversize_drops_total: u64,
    /// #2782: native-GRE decap frames DROPPED because the Checksum-Present
    /// (C) bit was set but the GRE checksum did not verify (or the header
    /// was truncated past the 4-byte Checksum+Reserved1 field). Per RFC
    /// 2784 §2.1 + RFC 2890 a checksummed peer (e.g. a vSRX with GRE
    /// checksum enabled) is now decapped after skipping+validating the
    /// checksum field instead of being silently blackholed; a frame the
    /// path corrupted is dropped HERE with this specific counter so the
    /// drop is observable. Surfaced as the Prometheus counter
    /// `xpf_userspace_gre_decap_checksum_invalid_drops_total`; nonzero
    /// flags a checksummed GRE peer delivering corrupt frames or a
    /// truncated GRE header. Additive / defaulted for backward
    /// compatibility.
    #[serde(rename = "gre_decap_checksum_invalid_drops_total", default)]
    pub gre_decap_checksum_invalid_drops_total: u64,
    /// #6842: native-GRE frames REFUSED for decap because the GRE version
    /// field was non-zero while the outer tuple named a configured GRE
    /// tunnel endpoint. RFC 2784/2890 GRE is version 0; RFC 2637 (PPTP)
    /// enhanced GRE is version 1 and re-purposes the 32-bit Key as
    /// `Payload Length (16) | Call ID (16)`, plus an
    /// Acknowledgment-Number field behind an `A` bit that the RFC 2890
    /// field order does not skip — so a version-blind parse would promote
    /// attacker-chosen bytes as the inner packet. Refused before any Key
    /// read or offset arithmetic. A REFUSAL, not a drop: the frame
    /// continues on the ordinary transit/host-inbound path. Ordinary
    /// TRANSIT PPTP is deliberately not counted. Surfaced as
    /// `xpf_userspace_gre_decap_unsupported_version_refusals_total`;
    /// nonzero flags a peer offering PPTP to a GRE endpoint xpf has no
    /// ALG to terminate. Additive / defaulted for backward compatibility.
    #[serde(rename = "gre_decap_unsupported_version_refusals_total", default)]
    pub gre_decap_unsupported_version_refusals_total: u64,
    /// #2472: locally-generated ICMP Time Exceeded / PTB / `reject` replies
    /// dropped because the per-reason token bucket was empty. Each reason has
    /// an independent global-per-reason bucket (Linux `icmp_msgs_per_sec`
    /// model, default 1000/s + 1000 burst) so an error-amplification /
    /// reflection flood (low-TTL stream, oversized-DF flood, rejected-flow
    /// flood, or a routing loop) cannot drive unbounded generated-error
    /// emission. Surfaced as the Prometheus counters
    /// `xpf_userspace_time_exceeded_rate_limited_total`,
    /// `xpf_userspace_packet_too_big_rate_limited_total`, and
    /// `xpf_userspace_reject_rate_limited_total`. Additive / defaulted for
    /// backward compatibility.
    #[serde(rename = "time_exceeded_rate_limited_total", default)]
    pub time_exceeded_rate_limited_total: u64,
    #[serde(rename = "packet_too_big_rate_limited_total", default)]
    pub packet_too_big_rate_limited_total: u64,
    #[serde(rename = "reject_rate_limited_total", default)]
    pub reject_rate_limited_total: u64,
    /// #1782 cold-start capture instrumentation. Debug dump of every key
    /// present in the userspace `dynamic_neighbors` mirror, rendered as
    /// `"ifindex ip"` strings. The capture harness greps this at the
    /// pre-connect t0' sample to confirm the data-path next-hop is ABSENT
    /// (the H2 fingerprint). Empty (and omitted) on dataplanes that don't
    /// publish, when the mirror is empty, OR — by default — because the dump
    /// is gated behind the `XPF_DEBUG_NEIGHBOR_KEYS` env var (off unless the
    /// helper is launched with it set for a capture). An empty field
    /// therefore does NOT imply the mirror is empty.
    #[serde(
        rename = "dynamic_neighbor_keys",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub dynamic_neighbor_keys: Vec<String>,
    /// #1769: on-demand neighbor-resolver telemetry. The resolver runs
    /// when a `MissingNeighbor` negative-cache fast-fail nudges a wedged
    /// dst: it issues a single-key RTM_GETNEIGH and either caches a
    /// confirmed lladdr (epoch-guarded) or probes to force kernel
    /// revalidation on a stale one. These are the operator-visible signal
    /// for the #1769 stuck-state (queue depth is a gauge; the rest are
    /// monotonic counters). Additive / defaulted for backward compat.
    #[serde(rename = "neighbor_resolver_queue_depth", default)]
    pub neighbor_resolver_queue_depth: u64,
    #[serde(rename = "neighbor_resolver_enqueue_drops_total", default)]
    pub neighbor_resolver_enqueue_drops_total: u64,
    #[serde(rename = "neighbor_resolver_disconnected_total", default)]
    pub neighbor_resolver_disconnected_total: u64,
    #[serde(rename = "neighbor_resolver_get_attempts_total", default)]
    pub neighbor_resolver_get_attempts_total: u64,
    #[serde(rename = "neighbor_resolver_get_resolved_total", default)]
    pub neighbor_resolver_get_resolved_total: u64,
    #[serde(rename = "neighbor_resolver_probe_on_stale_total", default)]
    pub neighbor_resolver_probe_on_stale_total: u64,
    #[serde(rename = "neighbor_resolver_get_failures_total", default)]
    pub neighbor_resolver_get_failures_total: u64,
    #[serde(rename = "neighbor_resolver_epoch_rejects_total", default)]
    pub neighbor_resolver_epoch_rejects_total: u64,
    /// #1772: neighbor/ARP resolution LATENCY telemetry. Complements the
    /// #1769 count-only resolver telemetry above with TIMING so the
    /// operator's intermittent slow-new-connection symptom is visible.
    /// Histogram buckets are NON-cumulative per-bucket sample counts on a
    /// 16-bucket pow2-ns ladder (bucket `i` upper bound `2^(16+i)` ns;
    /// bucket 15 = `+Inf`; the 3 s blackout class lands in bucket 15).
    /// Additive / defaulted for backward compat.
    /// pending_neigh dwell histogram (`now_ns - queued_ns` at resolve).
    #[serde(rename = "neighbor_pending_dwell_buckets", default)]
    pub neighbor_pending_dwell_buckets: Vec<u64>,
    #[serde(rename = "neighbor_pending_dwell_sum_ns", default)]
    pub neighbor_pending_dwell_sum_ns: u64,
    #[serde(rename = "neighbor_pending_dwell_count", default)]
    pub neighbor_pending_dwell_count: u64,
    /// Resolver single-key RTM_GETNEIGH round-trip-time histogram.
    #[serde(rename = "neighbor_resolver_get_rtt_buckets", default)]
    pub neighbor_resolver_get_rtt_buckets: Vec<u64>,
    #[serde(rename = "neighbor_resolver_get_rtt_sum_ns", default)]
    pub neighbor_resolver_get_rtt_sum_ns: u64,
    #[serde(rename = "neighbor_resolver_get_rtt_count", default)]
    pub neighbor_resolver_get_rtt_count: u64,
    /// pending_neigh timeout-drops + queue-depth high-water mark.
    #[serde(rename = "neighbor_pending_timeout_drops_total", default)]
    pub neighbor_pending_timeout_drops_total: u64,
    #[serde(rename = "neighbor_pending_max_depth", default)]
    pub neighbor_pending_max_depth: u64,
    /// #1771 §2.6: per-key resolver + §2.5 ENOBUFS-re-dump telemetry.
    /// `get_backoff_attempts` is the subset of resolver GET attempts
    /// that were backoff RETRIES (key re-admitted after the per-key
    /// rate-limit window). The `netlink_*` counters instrument the
    /// monitor thread's lost-notification self-heal: ENOBUFS receives,
    /// throttled upsert-only re-dumps issued, and dynamic-neighbor
    /// entries actually (re)added by re-dump replies. The two gauges are
    /// per-binding sums published at the ~65ms debug tick: distinct
    /// unresolved next-hop keys buffered in pending_neigh, and keys held
    /// in the negative caches (lazy-TTL upper bound). All additive /
    /// defaulted for backward compatibility.
    #[serde(rename = "neighbor_resolver_get_backoff_attempts_total", default)]
    pub neighbor_resolver_get_backoff_attempts_total: u64,
    #[serde(rename = "neighbor_netlink_enobufs_total", default)]
    pub neighbor_netlink_enobufs_total: u64,
    #[serde(rename = "neighbor_netlink_redumps_total", default)]
    pub neighbor_netlink_redumps_total: u64,
    #[serde(rename = "neighbor_netlink_redump_upserts_total", default)]
    pub neighbor_netlink_redump_upserts_total: u64,
    #[serde(rename = "neighbor_pending_keys", default)]
    pub neighbor_pending_keys: u64,
    #[serde(rename = "neg_neigh_keys", default)]
    pub neg_neigh_keys: u64,
    /// #802: focused per-binding ring-pressure view. Projected from the
    /// same `BindingLiveState` atomics that back `Self::bindings` — a
    /// compact snapshot of the counters an operator looks at first when
    /// triaging XSK ring saturation (TX full, sendto ENOBUFS, pending-
    /// overflow, fill-ring empty descs, outstanding-tx gauge). Keeping
    /// it as a parallel field (rather than only embedded in
    /// `bindings[].*`) lets the daemon pull just the triage counters on
    /// its poll path without deserializing every field on `BindingStatus`.
    /// #1865: per-WG-tunnel operator telemetry rows. Keyed by tunnel
    /// NAME (`tunnel`) — `tunnel_endpoint_id` is informational only
    /// because positional ids renumber across commits (#1873). Empty
    /// (and omitted — `skip_serializing_if`) when no WG tunnel is
    /// configured, so non-WG deployments stay wire-byte-identical to
    /// pre-#1865. Additive / defaulted for mixed-version compat.
    #[serde(rename = "wg_tunnels", default, skip_serializing_if = "Vec::is_empty")]
    pub wg_tunnels: Vec<WgTunnelStatus>,
    #[serde(rename = "per_binding", default, skip_serializing_if = "Vec::is_empty")]
    pub per_binding: Vec<BindingCountersSnapshot>,
    /// #1249: low-frequency debug snapshot mapping active flow-cache
    /// entries to the worker/RX queue that currently owns them. This
    /// is a diagnostic/status surface, not a scheduler input; workers
    /// publish bounded owned snapshots from their existing debug tick.
    #[serde(rename = "flow_worker_map", default)]
    pub flow_worker_map: Vec<FlowWorkerStatus>,
    #[serde(rename = "flow_worker_map_truncated", default)]
    pub flow_worker_map_truncated: bool,
    /// #1248: class-specific active-flow distribution for CoS
    /// fairness. Aggregated as `(ifindex, queue_id, worker_id) ->
    /// active distinct cached flows` from the same worker debug tick
    /// that publishes `active_flow_count`.
    #[serde(rename = "cos_active_flow_counts", default)]
    pub cos_active_flow_counts: Vec<CoSActiveFlowCountStatus>,
    #[serde(rename = "cos_active_flow_counts_truncated", default)]
    pub cos_active_flow_counts_truncated: bool,
    #[serde(rename = "ha_groups", default)]
    pub ha_groups: Vec<HAGroupStatus>,
    #[serde(default)]
    pub fabrics: Vec<FabricSnapshot>,
    #[serde(default)]
    pub queues: Vec<QueueStatus>,
    #[serde(default)]
    pub bindings: Vec<BindingStatus>,
    #[serde(rename = "recent_session_deltas", default)]
    pub recent_session_deltas: Vec<SessionDeltaInfo>,
    #[serde(rename = "recent_exceptions", default)]
    pub recent_exceptions: Vec<ExceptionStatus>,
    #[serde(rename = "cos_interfaces", default)]
    pub cos_interfaces: Vec<CoSInterfaceStatus>,
    #[serde(rename = "policy_rule_counters", default)]
    pub policy_rule_counters: Vec<PolicyRuleCounterStatus>,
    /// #2218: per-rule NAT translation hit counters (SNAT/DNAT/static),
    /// keyed by the compiler-assigned counter_id.
    #[serde(rename = "nat_rule_counters", default)]
    pub nat_rule_counters: Vec<NatRuleCounterStatus>,
    #[serde(rename = "filter_term_counters", default)]
    pub filter_term_counters: Vec<FirewallFilterTermCounterStatus>,
    /// #3651: per-zone ingress/egress traffic (packet + byte) volume, summed
    /// across every worker/binding by the helper (`ProcessStatus`-level
    /// pre-summed sparse block — one row per zone with nonzero traffic, keyed
    /// by the stable zone id). The Go control plane mirrors each row into the
    /// legacy `dataplane.Manager` zone-counter offset map via
    /// `ReplaceZoneCounterOffsets` (#6843: the whole map is replaced per poll,
    /// so a zone the helper stops publishing stops being reported rather than
    /// freezing at its last value), so `show security zones` (Traffic
    /// statistics),
    /// the REST `/security/zones` endpoint, and the Prometheus collector report
    /// live per-zone volume instead of `ErrCounterNotPopulated` ("not
    /// available"). `zone_counter_layout_version` selects the decode path
    /// (0/absent = pre-#3651 helper, no per-zone data); a nonzero
    /// `zone_counter_overflow_active` means the configured zone count exceeded
    /// the helper's dense hot-path slot capacity and some zones went uncounted.
    #[serde(
        rename = "zone_counter_layout_version",
        default,
        skip_serializing_if = "crate::protocol::u32_is_zero"
    )]
    pub zone_counter_layout_version: u32,
    #[serde(
        rename = "zone_counter_overflow_active",
        default,
        skip_serializing_if = "crate::protocol::bool_is_false"
    )]
    pub zone_counter_overflow_active: bool,
    // #6947: omit the block when empty, matching BOTH the Go mirror
    // (`json:"zone_traffic_counters,omitempty"`) and the sibling scalars in
    // this same struct, which already carry skip_serializing_if. Without
    // it the helper puts an empty array on the shared control socket on
    // every 1/s status poll, forever, on a firewall that never populated it.
    #[serde(
        rename = "zone_traffic_counters",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub zone_traffic_counters: Vec<ZoneTrafficCounterStatus>,
    /// #3651: per-zone SYN/ICMP/UDP flood-EVENT counts, summed across every
    /// worker by the helper (one `ProcessStatus`-level pre-summed sparse block,
    /// one row per zone with nonzero flood drops, keyed by the stable zone id).
    /// The Go control plane mirrors each row into the legacy
    /// `dataplane.Manager` flood-counter offset map via
    /// `ReplaceFloodCounterOffsets` (the whole map is replaced per poll, so a
    /// zone the helper stops publishing stops being reported rather than
    /// freezing at its last value), so `show security screen ids-option
    /// statistics` reports live per-zone flood counts instead of
    /// `ErrCounterNotPopulated` ("not available").
    /// `flood_counter_layout_version` selects the decode path (0/absent =
    /// helper with no per-zone flood accounting); a true
    /// `flood_counter_overflow_active` means the configured zone count exceeded
    /// the helper's dense slot capacity and some zones went uncounted.
    #[serde(
        rename = "flood_counter_layout_version",
        default,
        skip_serializing_if = "crate::protocol::u32_is_zero"
    )]
    pub flood_counter_layout_version: u32,
    #[serde(
        rename = "flood_counter_overflow_active",
        default,
        skip_serializing_if = "crate::protocol::bool_is_false"
    )]
    pub flood_counter_overflow_active: bool,
    // #6947: omit the block when empty, matching BOTH the Go mirror
    // (`json:"zone_flood_counters,omitempty"`) and the sibling scalars in
    // this same struct, which already carry skip_serializing_if. Without
    // it the helper puts an empty array on the shared control socket on
    // every 1/s status poll, forever, on a firewall that never populated it.
    #[serde(
        rename = "zone_flood_counters",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub zone_flood_counters: Vec<ZoneFloodCounterStatus>,
    #[serde(rename = "three_color_policer_counters", default)]
    pub three_color_policer_counters: Vec<ThreeColorPolicerStatus>,
    #[serde(rename = "source_nat_pools", default)]
    pub source_nat_pools: Vec<SourceNatPoolStatus>,
    #[serde(rename = "last_resolution", skip_serializing_if = "Option::is_none")]
    pub last_resolution: Option<PacketResolution>,
    #[serde(rename = "slow_path", default)]
    pub slow_path: SlowPathStatus,
    #[serde(rename = "debug_worker_threads", default)]
    pub debug_worker_threads: usize,
    #[serde(rename = "debug_identity_slots", default)]
    pub debug_identity_slots: usize,
    #[serde(rename = "debug_live_slots", default)]
    pub debug_live_slots: usize,
    #[serde(rename = "debug_planned_workers", default)]
    pub debug_planned_workers: usize,
    #[serde(rename = "debug_planned_bindings", default)]
    pub debug_planned_bindings: usize,
    #[serde(rename = "debug_reconcile_calls", default)]
    pub debug_reconcile_calls: u64,
    #[serde(rename = "debug_reconcile_stage", default)]
    pub debug_reconcile_stage: String,
    #[serde(rename = "event_stream_connected", default)]
    pub event_stream_connected: bool,
    #[serde(rename = "event_stream_seq", default)]
    pub event_stream_seq: u64,
    #[serde(rename = "event_stream_acked", default)]
    pub event_stream_acked: u64,
    #[serde(rename = "event_stream_sent", default)]
    pub event_stream_sent: u64,
    #[serde(rename = "event_stream_dropped", default)]
    pub event_stream_dropped: u64,
    /// I/O cycles in which the event-stream socket-write backlog hit its cap
    /// and the helper stopped draining the channel (stalled daemon reader,
    /// #2381). Growing → telemetry shed at the bounded channel; dataplane
    /// unaffected.
    #[serde(rename = "event_stream_write_stalls", default)]
    pub event_stream_write_stalls: u64,
    /// Accepted RT_FLOW / dataplane-telemetry frames evicted from the helper's
    /// replay buffer when it wrapped at capacity before the daemon ACKed them
    /// (#2382). These were counted in `event_stream_sent` at enqueue but are
    /// permanently lost after reconnect. A non-zero, growing value means
    /// telemetry was dropped via replay-buffer eviction (a disconnected or
    /// non-ACKing daemon let the window wrap). Distinct from ACK-trim, which
    /// is normal acknowledged-frame removal and is NOT counted here.
    #[serde(rename = "event_stream_replay_evictions", default)]
    pub event_stream_replay_evictions: u64,
    /// MSG_ACK control frames rejected because the daemon ACKed a sequence
    /// outside the valid `[acked_seq, next_seq]` window — a backward ACK
    /// (`seq < acked`) or a future ACK of a sequence never allocated
    /// (`seq > next`) (#2959). The helper fails closed and ignores such an
    /// ACK (watermark + replay buffer left intact). A non-zero, growing value
    /// means a buggy / mixed-version / corrupted daemon listener is emitting
    /// impossible ACK watermarks.
    #[serde(rename = "event_stream_invalid_acks", default)]
    pub event_stream_invalid_acks: u64,
    /// #9169 / #4800 SITE 4: acquisitions of the helper's process-global
    /// `producer_seq_lock` taken by a PRODUCER, and the blocked subset.
    ///
    /// Every session delta — Open as well as Close — allocates its wire
    /// sequence number and encodes its frame inside this mutex (#3878 F-152
    /// requires the allocation and the channel enqueue to be atomic together),
    /// so it is a cross-worker serialization point on the new-flow path. It was
    /// absent from `docs/userspace-newflow-ceiling.md`'s three-site model, so a
    /// run that saturated here reported a plateau with every named site cold.
    ///
    /// A pair, always emitted together: a contended count without its
    /// denominator is not interpretable, and "never taken" (zero acquisitions)
    /// is a different finding from "taken but never blocked".
    ///
    /// The I/O thread's replay-gap FullResync allocation takes the same mutex
    /// and is deliberately NOT counted — it is not a producer and fires once
    /// per reconnect, so folding it in would dilute the ratio with the
    /// observer. Its blocking effect is still visible as producer contention.
    ///
    /// `default` so an older helper that does not send these decodes 0. Read
    /// that as "this build does not report the site", which the analyzer
    /// distinguishes from a measured zero by requiring a non-zero denominator
    /// before it reports a ratio at all.
    #[serde(rename = "event_stream_producer_seq_lock_acquisitions_total", default)]
    pub event_stream_producer_seq_lock_acquisitions_total: u64,
    #[serde(rename = "event_stream_producer_seq_lock_contended_total", default)]
    pub event_stream_producer_seq_lock_contended_total: u64,
    /// #2512: per-kind producer-side accounting for the RT_FLOW SESSION_CLOSE
    /// (type 14) and SESSION_CREATE (type 15) frames. Before #2512 these used
    /// a bare `try_send` that did not pass through the per-kind rate limiter,
    /// queue budget, or sent/dropped counters, so a dropped close/create was
    /// invisible. `_sent` is frames accepted onto the event channel; `_dropped`
    /// sums rate-limited + queue-full + disconnected drops for that kind. A
    /// dropped SESSION_CLOSE loses only one flow-export/syslog record — the
    /// type-2 HA session-sync close delta rides a separate frame and is never
    /// rate-limited (`push_delta`), so the consumer session state self-heals
    /// via the 1s session sweep.
    #[serde(rename = "event_stream_session_close_sent", default)]
    pub event_stream_session_close_sent: u64,
    #[serde(rename = "event_stream_session_close_dropped", default)]
    pub event_stream_session_close_dropped: u64,
    #[serde(rename = "event_stream_session_create_sent", default)]
    pub event_stream_session_create_sent: u64,
    #[serde(rename = "event_stream_session_create_dropped", default)]
    pub event_stream_session_create_dropped: u64,
    /// Monotonic timestamp (secs) of the last HA flow cache flush (#312).
    #[serde(rename = "last_cache_flush_at", default)]
    pub last_cache_flush_at: u64,
    /// #3773 (M13): cumulative count of fabric links skipped during a
    /// forwarding build/refresh because a value was MALFORMED — an invalid
    /// parent ifindex, an unparseable peer address, or a NON-EMPTY local/peer
    /// MAC string that failed to parse. A non-zero (especially climbing) value
    /// is a fabric config/environment fault an operator must fix; the helper
    /// journal names which fabric and why. Additive / defaulted for
    /// mixed-version compat.
    #[serde(rename = "fabric_link_skipped_malformed_total", default)]
    pub fabric_link_skipped_malformed_total: u64,
    /// #3773 (M13): cumulative count of fabric links skipped because the peer
    /// or local MAC was UNRESOLVED — an EMPTY MAC field still awaiting
    /// neighbor/interface resolution (the expected late-resolution
    /// `SyncFabricState` transient). Briefly non-zero at startup is normal; a
    /// PERSISTENTLY climbing value means a fabric peer is not resolving. A
    /// distinct, non-malformed state per #3773.
    #[serde(rename = "fabric_link_unresolved_peer_total", default)]
    pub fabric_link_unresolved_peer_total: u64,
    /// #9654: whether the learned-route import is capped (#8355, #9054) in the
    /// forwarding state the live workers serve NOW, as projected by
    /// `Coordinator::learned_route_import_capped_now`.
    ///
    /// `None` omits the key, and absence means UNKNOWN: no worker is live, so
    /// nothing serves any published state. A helper that predates the field
    /// omits it too, while still enforcing capped forwarding. So the daemon
    /// must read absence as unknown, never as "not capped".
    #[serde(
        rename = "learned_route_import_capped",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub learned_route_import_capped: Option<bool>,
}
