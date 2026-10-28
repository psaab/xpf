//! CoS configuration and status DTOs. The configuration tree
//! (`ClassOfServiceSnapshot` plus its component snapshots) is leaf-pure
//! in protocol-internal terms — no cross-domain refs. The runtime status
//! types (`CoSInterfaceStatus`, `CoSQueueStatus`,
//! `CoSActiveFlowCountStatus`) are colocated because they vary alongside
//! the config types they describe.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ClassOfServiceSnapshot {
    #[serde(rename = "forwarding_classes", default)]
    pub forwarding_classes: Vec<CoSForwardingClassSnapshot>,
    #[serde(rename = "dscp_classifiers", default)]
    pub dscp_classifiers: Vec<CoSDSCPClassifierSnapshot>,
    #[serde(rename = "ieee8021_classifiers", default)]
    pub ieee8021_classifiers: Vec<CoSIEEE8021ClassifierSnapshot>,
    /// #6847: `class-of-service classifiers inet-precedence <name>`. Additive
    /// — an older helper ignores the key, and a newer helper reading an older
    /// snapshot gets the empty default (no inet-precedence binding is
    /// publishable by a control plane that does not emit this list, because
    /// the per-interface `cos_inet_precedence_classifier` is additive too).
    #[serde(rename = "inet_precedence_classifiers", default)]
    pub inet_precedence_classifiers: Vec<CoSINetPrecedenceClassifierSnapshot>,
    #[serde(rename = "dscp_rewrite_rules", default)]
    pub dscp_rewrite_rules: Vec<CoSDSCPRewriteRuleSnapshot>,
    #[serde(rename = "schedulers", default)]
    pub schedulers: Vec<CoSSchedulerSnapshot>,
    #[serde(rename = "scheduler_maps", default)]
    pub scheduler_maps: Vec<CoSSchedulerMapSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSForwardingClassSnapshot {
    pub name: String,
    #[serde(default)]
    pub queue: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSDSCPClassifierSnapshot {
    pub name: String,
    #[serde(default)]
    pub entries: Vec<CoSDSCPClassifierEntrySnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSDSCPClassifierEntrySnapshot {
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(rename = "loss_priority", default)]
    pub loss_priority: String,
    #[serde(rename = "dscp_values", default)]
    pub dscp_values: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSIEEE8021ClassifierSnapshot {
    pub name: String,
    #[serde(default)]
    pub entries: Vec<CoSIEEE8021ClassifierEntrySnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSIEEE8021ClassifierEntrySnapshot {
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(rename = "loss_priority", default)]
    pub loss_priority: String,
    #[serde(rename = "code_points", default)]
    pub code_points: Vec<u8>,
}

/// #6847: an IP-precedence behavior-aggregate classifier. IP precedence is the
/// top 3 bits of the SAME IPv4 TOS byte / IPv6 traffic-class field the DSCP
/// classifier reads, so a unit binds at most one of `dscp` and
/// `inet-precedence` (the Go commit gate `validateCoSUnitClassifierConflict`
/// rejects the combination; the tolerant load path downgrades to a warning and
/// DSCP wins on that boot, matching the resolution order in
/// `tx/cos_classify.rs`).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSINetPrecedenceClassifierSnapshot {
    pub name: String,
    #[serde(default)]
    pub entries: Vec<CoSINetPrecedenceClassifierEntrySnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSINetPrecedenceClassifierEntrySnapshot {
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(rename = "loss_priority", default)]
    pub loss_priority: String,
    /// IP-precedence code-points (0..=7). Out-of-range values fail the
    /// snapshot CLOSED at build time rather than being masked into a valid
    /// index — see `CosInetPrecedenceCodePointOutOfRange`.
    #[serde(rename = "precedences", default)]
    pub precedences: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSDSCPRewriteRuleSnapshot {
    pub name: String,
    #[serde(default)]
    pub entries: Vec<CoSDSCPRewriteRuleEntrySnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSDSCPRewriteRuleEntrySnapshot {
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(rename = "loss_priority", default)]
    pub loss_priority: String,
    #[serde(rename = "dscp_value", default)]
    pub dscp_value: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSSchedulerSnapshot {
    pub name: String,
    #[serde(rename = "transmit_rate_bytes", default)]
    pub transmit_rate_bytes: u64,
    /// #4228 Gap 2: the Junos `transmit-rate percent <n>` share (0,100].
    /// Legacy snapshots carry only `transmit_rate_bytes`; this defaults to
    /// 0.0. Resolved PER-INTERFACE in `forwarding_build::cos` against the
    /// bound interface's `cos_shaping_rate_bytes_per_sec` (a named scheduler
    /// can map onto interfaces of different shaping rates, so the absolute
    /// rate is materialized per interface, not stored on the shared
    /// scheduler). An absolute `transmit_rate_bytes` wins when both are
    /// present; the Go strict validator rejects that combination on commit,
    /// so a well-formed snapshot never sets both.
    #[serde(rename = "transmit_rate_percent", default)]
    pub transmit_rate_percent: f64,
    /// #6846: the Junos `transmit-rate remainder` form — "whatever the
    /// interface shaping rate has left after every sibling queue on the same
    /// scheduler-map resolves". Carried as a FLAG rather than a rate because
    /// it is a function of the sibling set, not of this scheduler, and the
    /// sibling set is only known per-interface in `forwarding_build::cos`.
    /// Legacy snapshots default to false and behave exactly as before.
    #[serde(rename = "transmit_rate_remainder", default)]
    pub transmit_rate_remainder: bool,
    #[serde(rename = "transmit_rate_exact", default)]
    pub transmit_rate_exact: bool,
    #[serde(default)]
    pub priority: String,
    #[serde(rename = "buffer_size_bytes", default)]
    pub buffer_size_bytes: u64,
    /// Additive #1336 field for Junos scheduler `buffer-size 10%`.
    /// Legacy snapshots carry only `buffer_size_bytes`; this defaults
    /// to 0.0 and is used by the runtime only when byte size is absent.
    #[serde(rename = "buffer_size_percent", default)]
    pub buffer_size_percent: f64,
    /// #6846: the Junos `buffer-size temporal <microseconds>` form — a queue
    /// depth expressed as DRAIN TIME. Converting it to bytes needs the
    /// queue's own resolved transmit-rate, so it is applied strictly after
    /// the rate resolves (including after `remainder`). Legacy snapshots
    /// default to 0 and keep the existing byte/percent sizing.
    #[serde(rename = "buffer_size_temporal_us", default)]
    pub buffer_size_temporal_us: u64,
    /// #915: opt an exact queue into surplus-phase participation
    /// so it can draw from root surplus tokens once its own bucket
    /// is empty. Only meaningful when transmit_rate_exact == true;
    /// the Go control plane warn-and-strips otherwise. `default` is
    /// required so older snapshots without the field decode safely.
    #[serde(rename = "surplus_sharing", default)]
    pub surplus_sharing: bool,
    /// Explicit opt-in for shared flow-aware enforcement on positive
    /// `transmit-rate exact` schedulers. Defaults false for older
    /// snapshots. The coordinator maps this onto shared v8 queue-lease
    /// equal-flow suppression.
    #[serde(rename = "equal_flow_enforcement", default)]
    pub equal_flow_enforcement: bool,
    /// #1746: equal-flow target policy ("slowest" | "mean" |
    /// "ideal-share"). Empty (the default for older snapshots and
    /// unset configs) decodes to the byte-unchanged `Slowest` math in
    /// forwarding_build. Only meaningful when `equal_flow_enforcement`
    /// is set. skip_serializing_if mirrors the Go omitempty so the
    /// unset-config wire stays byte-identical in BOTH directions
    /// (pinned by `wire_invariant_default_specimens`).
    #[serde(
        rename = "equal_flow_target_policy",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub equal_flow_target_policy: String,
    /// #1614 A3: per-queue CoDel target in nanoseconds. 0 disables
    /// CoDel for the queue (current default). WIRE SURFACE ONLY in
    /// PR #1618 — the dequeue-time sojourn check is deferred to a
    /// focused follow-up issue. Recommended >= 1.5x post-shaper
    /// RTT per AGY r2 finding #3 when the sojourn check ships.
    #[serde(rename = "codel_target_ns", default)]
    pub codel_target_ns: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSSchedulerMapSnapshot {
    pub name: String,
    #[serde(default)]
    pub entries: Vec<CoSSchedulerMapEntrySnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSSchedulerMapEntrySnapshot {
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(default)]
    pub scheduler: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSInterfaceStatus {
    #[serde(default)]
    pub ifindex: i32,
    #[serde(rename = "interface_name", default)]
    pub interface_name: String,
    #[serde(
        rename = "owner_worker_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_worker_id: Option<u32>,
    #[serde(rename = "shaping_rate_bytes", default)]
    pub shaping_rate_bytes: u64,
    #[serde(rename = "burst_bytes", default)]
    pub burst_bytes: u64,
    #[serde(rename = "worker_instances", default)]
    pub worker_instances: usize,
    #[serde(rename = "nonempty_queues", default)]
    pub nonempty_queues: usize,
    #[serde(rename = "runnable_queues", default)]
    pub runnable_queues: usize,
    #[serde(rename = "timer_level0_sleepers", default)]
    pub timer_level0_sleepers: usize,
    #[serde(rename = "timer_level1_sleepers", default)]
    pub timer_level1_sleepers: usize,
    // #1628: per-interface waterfill-selector trace counters. `epochs` and
    // `phase1_budget_breaks` are SUMMED across worker instances (cluster
    // event counters, like timer_level*_sleepers).
    // `min_epochs_per_worker` is the coordinator's MIN of the per-worker
    // per-binding MIN over bindings WITH active exact-guarantee backlog
    // (so a healthy binding/worker cannot mask a sibling locked in
    // Phase 2). A LOW value relative to `epochs` flags a single stalled
    // selector; `0` is a HARD lock-in (a backlogged binding that
    // completed zero epochs). `u64::MAX` is the "no active-backlog
    // candidate" sentinel (idle interface) and is preserved through
    // coordinator aggregation so the two cases never collide — Prometheus
    // suppresses the MAX gauge and the CLI renders it as "none", which
    // keeps `0` unambiguously meaning hard lock-in (alertable).
    #[serde(rename = "waterfill_epochs", default)]
    pub waterfill_epochs: u64,
    #[serde(rename = "waterfill_phase1_budget_breaks", default)]
    pub waterfill_phase1_budget_breaks: u64,
    #[serde(rename = "waterfill_min_epochs_per_worker", default)]
    pub waterfill_min_epochs_per_worker: u64,
    #[serde(default)]
    pub queues: Vec<CoSQueueStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSQueueStatus {
    #[serde(rename = "queue_id", default)]
    pub queue_id: u8,
    #[serde(
        rename = "owner_worker_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_worker_id: Option<u32>,
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(default)]
    pub priority: u8,
    #[serde(default)]
    pub exact: bool,
    #[serde(rename = "guarantee_enabled", default)]
    pub guarantee_enabled: bool,
    #[serde(rename = "transmit_rate_bytes", default)]
    pub transmit_rate_bytes: u64,
    /// Total queue capacity represented by this status row. Worker and
    /// coordinator aggregation sum this alongside `queued_bytes` so buffer
    /// fill percentages use matched numerator/denominator populations.
    #[serde(rename = "buffer_bytes", default)]
    pub buffer_bytes: u64,
    #[serde(rename = "worker_instances", default)]
    pub worker_instances: usize,
    #[serde(rename = "queued_packets", default)]
    pub queued_packets: u64,
    #[serde(rename = "queued_bytes", default)]
    pub queued_bytes: u64,
    #[serde(rename = "runnable_instances", default)]
    pub runnable_instances: usize,
    #[serde(rename = "parked_instances", default)]
    pub parked_instances: usize,
    #[serde(rename = "next_wakeup_tick", default)]
    pub next_wakeup_tick: u64,
    #[serde(rename = "surplus_deficit_bytes", default)]
    pub surplus_deficit_bytes: u64,
    /// #784 SFQ fairness diagnostic. Peak count of distinct
    /// active flow buckets observed on this queue since the last
    /// snapshot. Compare against iperf3 `-P N` count: if a flow-
    /// fair queue serving N flows shows peak < N, hash collisions
    /// are shrinking SFQ shares and forcing unfair rates.
    #[serde(rename = "active_flow_buckets_peak", default)]
    pub active_flow_buckets_peak: u64,
    /// #784: `flow_fair` flag from CoSQueueRuntime. For exact
    /// non-shared queues this should be true (SFQ scheduling
    /// active). If false on a queue that serves multiple TCP
    /// flows, each flow competes with no isolation and admission
    /// drops concentrate on whichever flow is unlucky.
    #[serde(rename = "flow_fair", default)]
    pub flow_fair: bool,
    // #710 drop-reason counters, aggregated across worker instances for
    // this (ifindex, queue_id). `parks` are not drops — the queue is
    // only deferred until its root/queue token bucket refills — but
    // tracking them alongside drops tells an operator which *scheduler*
    // decision is limiting the queue. See `types::CoSQueueDropCounters`
    // for per-reason semantics and refs to the issues driving each.
    #[serde(rename = "admission_flow_share_drops", default)]
    pub admission_flow_share_drops: u64,
    #[serde(rename = "admission_buffer_drops", default)]
    pub admission_buffer_drops: u64,
    /// #718: packets ECN CE-marked at admission (not dropped). A rising
    /// counter here indicates the admission-threshold signalling is
    /// steering ECN-negotiated TCP flows; operators should see
    /// per-queue retrans rates fall while this increments.
    #[serde(rename = "admission_ecn_marked", default)]
    pub admission_ecn_marked: u64,
    #[serde(rename = "root_token_starvation_parks", default)]
    pub root_token_starvation_parks: u64,
    #[serde(rename = "queue_token_starvation_parks", default)]
    pub queue_token_starvation_parks: u64,
    #[serde(rename = "tx_ring_full_submit_stalls", default)]
    pub tx_ring_full_submit_stalls: u64,
    /// #1304: true when the shared v8 queue lease for this exact queue
    /// was constructed in opt-in equal-flow suppression mode. This is
    /// config/mode state; `equal_flow_enforced` reports whether the
    /// current epoch is actually being capped rather than failed open.
    #[serde(rename = "equal_flow_enforcement", default)]
    pub equal_flow_enforcement: bool,
    #[serde(rename = "equal_flow_enforced", default)]
    pub equal_flow_enforced: bool,
    #[serde(rename = "equal_flow_target_per_flow_bps", default)]
    pub equal_flow_target_per_flow_bps: u64,
    #[serde(rename = "equal_flow_max_worker_cap_bytes", default)]
    pub equal_flow_max_worker_cap_bytes: u64,
    #[serde(rename = "equal_flow_cap_hit_events", default)]
    pub equal_flow_cap_hit_events: u64,
    #[serde(rename = "equal_flow_suppressed_grant_bytes", default)]
    pub equal_flow_suppressed_grant_bytes: u64,
    #[serde(rename = "equal_flow_stale_or_tag_mismatch_events", default)]
    pub equal_flow_stale_or_tag_mismatch_events: u64,
    #[serde(
        rename = "equal_flow_fail_open_reason",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub equal_flow_fail_open_reason: String,
    /// #1746: active equal-flow target policy label ("slowest" |
    /// "mean" | "ideal-share"). Populated only for EqualFlowSuppress
    /// leases (alongside `equal_flow_enforcement`); empty otherwise so
    /// the wire stays byte-identical for non-equal-flow queues.
    #[serde(
        rename = "equal_flow_target_policy",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub equal_flow_target_policy: String,
    /// #1863 Step-0: per-worker cumulative v8 queue-lease claim flow
    /// for this queue's shared lease — requested bytes (every
    /// `acquire_v8` ask, granted or not) and granted bytes, indexed by
    /// worker id. Populated by the coordinator status overlay from the
    /// lease registry; empty for legacy/non-v8 leases so the wire is
    /// byte-identical pre-#1863 for them. The Go mirror is
    /// `pkg/dataplane/userspace/protocol.go` (tags must match
    /// byte-for-byte).
    #[serde(
        rename = "lease_v8_worker_requested_bytes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub lease_v8_worker_requested_bytes: Vec<u64>,
    #[serde(
        rename = "lease_v8_worker_granted_bytes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub lease_v8_worker_granted_bytes: Vec<u64>,
    // #709 / #751: owner-profile telemetry for exact queues with an
    // unambiguous single owner-local binding snapshot. These fields are
    // populated only when exactly one owner-local exact queue can
    // inherit the binding's `BindingLiveState` profile truthfully; for
    // shared_exact, non-exact, and ambiguous multi-owner-local shapes
    // they are zero. The serde wire format is the cross-language
    // contract to Go (pkg/dataplane/userspace/protocol.go); rename
    // strings MUST match byte-for-byte. Histograms are `Vec<u64>` on
    // the wire so serde can serialise them without a schema for the
    // fixed-size array; the Rust side always fills them to
    // DRAIN_HIST_BUCKETS.
    #[serde(rename = "drain_latency_hist", default)]
    pub drain_latency_hist: Vec<u64>,
    #[serde(rename = "drain_invocations", default)]
    pub drain_invocations: u64,
    #[serde(rename = "drain_noop_invocations", default)]
    pub drain_noop_invocations: u64,
    #[serde(rename = "redirect_acquire_hist", default)]
    pub redirect_acquire_hist: Vec<u64>,
    #[serde(rename = "owner_pps", default)]
    pub owner_pps: u64,
    #[serde(rename = "peer_pps", default)]
    pub peer_pps: u64,
    // #760 overshoot-hunt instrumentation. Read at the same
    // cadence as the other owner-profile fields; zeroed for
    // queues without a single unambiguous owner-local binding.
    #[serde(rename = "drain_sent_bytes", default)]
    pub drain_sent_bytes: u64,
    // #1369 drain-phase telemetry. Populated for all queue types,
    // including non-exact and shared queues — not zeroed for queues
    // without a single owner-local binding. The steal counter
    // (`drain_nonexact_sent_bytes_while_exact_backlogged`) uses
    // interface-global exact-backlog visibility via
    // `SharedCoSExactBacklog` (per-binding cacheline-padded atomic
    // slots) rather than a worker-local scan.
    #[serde(rename = "drain_guarantee_sent_bytes", default)]
    pub drain_guarantee_sent_bytes: u64,
    #[serde(rename = "drain_surplus_sent_bytes", default)]
    pub drain_surplus_sent_bytes: u64,
    #[serde(rename = "drain_nonexact_sent_bytes_while_exact_backlogged", default)]
    pub drain_nonexact_sent_bytes_while_exact_backlogged: u64,
    #[serde(rename = "drain_park_root_tokens", default)]
    pub drain_park_root_tokens: u64,
    #[serde(rename = "drain_park_queue_tokens", default)]
    pub drain_park_queue_tokens: u64,
    // #760 binding-scoped: non-zero means the post-CoS backup
    // transmit path (drain_pending_tx) sent bytes without
    // going through any queue's token gate. Same value is
    // broadcast on every queue status belonging to the
    // binding — the Go renderer shows it once per interface.
    #[serde(rename = "post_drain_backup_bytes", default)]
    pub post_drain_backup_bytes: u64,
    /// #760 triage. Binding-scoped bytes observed at the three
    /// `apply_*` tx_bytes sites, written unconditionally. Compare
    /// against the sum of `drain_sent_bytes` across all queues —
    /// any gap attributes shaped traffic that bypassed the
    /// per-queue write via an `apply_*` early-return / queue miss.
    #[serde(rename = "drain_sent_bytes_shaped_unconditional", default)]
    pub drain_sent_bytes_shaped_unconditional: u64,
    // #1628: per-class waterfill-selector trace counters, aggregated
    // across worker instances for this (ifindex, queue_id). Zero on the
    // Proportional (legacy RR) selector path — non-zero means this
    // interface is in `guarantee-rate` mode. Diagnostic only; the
    // scheduler reads none of these. JSON tags MUST match the Go mirror
    // (pkg/dataplane/userspace/protocol.go) byte-for-byte. See
    // `types::CoSQueueWaterfillCounters` for the INTERPRETATION contract
    // (these are evidence to combine with queued_bytes + *_starvation_parks,
    // not standalone fingerprints).
    #[serde(rename = "waterfill_phase1_admissions", default)]
    pub waterfill_phase1_admissions: u64,
    #[serde(rename = "waterfill_phase2_admissions", default)]
    pub waterfill_phase2_admissions: u64,
    #[serde(rename = "waterfill_eligible_visits", default)]
    pub waterfill_eligible_visits: u64,
    // hb166 T-2: times a Phase-1 honored selection made ZERO TX progress
    // (ring full / no free frame / build Drop) and had its budget debit +
    // honored bit REFUNDED. Climbing here with flat waterfill_phase1_
    // admissions on a backlogged small class = TX-ring pressure eating the
    // guarantee pass. `default` keeps a pre-hb166 daemon's absent field at
    // 0 (rolling-upgrade safe).
    #[serde(rename = "waterfill_phase1_selected_no_progress", default)]
    pub waterfill_phase1_selected_no_progress: u64,
    // #1829 Phase 1: dequeue-time sojourn telemetry, sampled as
    // `now_ns - item.enqueue_ns` at the COMMITTED-PREFIX settle points
    // (after the TX insert accepts the item — Codex review on PR
    // #1846: rolled-back retry items keep their original stamp and
    // are sampled only on the attempt that ships them).
    // JSON tags MUST match the Go mirror
    // (pkg/dataplane/userspace/protocol.go) byte-for-byte.
    //
    // AGGREGATION contract: all three fields are MAX-merged — across
    // worker instances (worker/cos/queue_row.rs) and across workers
    // (coordinator/mod.rs). Each worker instance measures its OWN
    // queue runtime's delay; the row therefore reports the
    // worst-instance value, which is the right gate semantics (a
    // Phase-2 per-worker CoDel would act on exactly that instance).
    //
    // `sojourn_windowed_min_ns` is the #1829 GATE METRIC (plan §6.1d
    // via AGY r2 F2): the minimum sojourn over the last 1-2 100 ms
    // windows, i.e. CoDel's standing-queue estimator. A value
    // persistently above codel-target is standing-queue evidence;
    // EWMA/peak are supporting context only (both biased high by
    // transient scheduler service gaps). It reads 0 when the queue
    // has not popped for >= 2 windows at snapshot time, so a stale
    // reading cannot outlive the backlog that produced it.
    // `sojourn_peak_ns` is the lifetime maximum (same contract as
    // `active_flow_buckets_peak`); `sojourn_ewma_ns` is a shift-add
    // EWMA (alpha = 1/8) over pops.
    #[serde(rename = "sojourn_ewma_ns", default)]
    pub sojourn_ewma_ns: u64,
    #[serde(rename = "sojourn_peak_ns", default)]
    pub sojourn_peak_ns: u64,
    #[serde(rename = "sojourn_windowed_min_ns", default)]
    pub sojourn_windowed_min_ns: u64,
    // #1830 (g): bucket-vs-flow occupancy telemetry, distinguishing SFQ
    // hash-collision unfairness from demand unfairness on flow-fair
    // queues. JSON tags MUST match the Go mirror
    // (pkg/dataplane/userspace/protocol.go) byte-for-byte.
    //
    // `flow_fair_buckets_occupied` is the INSTANTANEOUS count of
    // occupied (backlogged) SFQ flow buckets, summed across worker
    // instances for this (ifindex, queue_id) — each worker's
    // FlowFairState owns disjoint buckets, so the sum never
    // double-counts. `flow_fair_flows_active` is the flow-cache
    // active-window (~650 ms) count of distinct flows mapped to this
    // queue, summed across workers (same source as
    // `cos_active_flow_counts`, re-keyed per queue).
    //
    // INTERPRETATION contract: the ratio flows_active /
    // buckets_occupied is meaningful only while the queue is
    // CONTINUOUSLY backlogged (e.g. sustained iperf3 -P N): then every
    // active flow keeps a bucket occupied, and a ratio persistently > 1
    // (or buckets_occupied < the known flow fan-in) indicates hash
    // collisions shrinking SFQ shares. On an idle or bursty queue,
    // flows_active naturally exceeds buckets_occupied (a window-active
    // flow with nothing queued right now occupies no bucket) — that is
    // demand variance, not collision evidence.
    #[serde(rename = "flow_fair_buckets_occupied", default)]
    pub flow_fair_buckets_occupied: u64,
    #[serde(rename = "flow_fair_flows_active", default)]
    pub flow_fair_flows_active: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct CoSActiveFlowCountStatus {
    /// Egress CoS interface ifindex.
    #[serde(default)]
    pub ifindex: i32,
    #[serde(rename = "queue_id", default)]
    pub queue_id: u8,
    #[serde(rename = "worker_id", default)]
    pub worker_id: u32,
    #[serde(rename = "active_flow_count", default)]
    pub active_flow_count: u32,
}

// #7689: the exhaustive-literal guard for this file's CoSSchedulerSnapshot.
#[cfg(test)]
#[path = "cos_literal_guard_7689.rs"]
mod cos_literal_guard_7689;
