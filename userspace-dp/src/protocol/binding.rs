//! Per-binding status (`BindingStatus`), its lean
//! `BindingCountersSnapshot` projection (plus the
//! `From<&BindingStatus>` conversion and the `'static + Send`
//! compile-time assertion), `WorkerRuntimeStatus`,
//! `HAGroupStatus`, `QueueStatus`, `ExceptionStatus`, and
//! `SessionDeltaInfo`. Also home to the `u64_is_zero`
//! `skip_serializing_if` helper consumed by
//! `HAGroupStatus.lease_until`; the helper is referenced via the
//! absolute path `crate::protocol::u64_is_zero` from the serde
//! attribute so future moves do not require touching the
//! attribute string.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// #869: per-worker busy/idle runtime telemetry, published on the
/// worker's ~1s cadence.  See `userspace-dp/src/afxdp/worker_runtime.rs`.
/// All fields default to 0 for backward compatibility with daemons that
/// predate this instrumentation.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WorkerRuntimeStatus {
    #[serde(rename = "worker_id", default)]
    pub worker_id: u32,
    #[serde(default)]
    pub tid: u64,
    #[serde(rename = "wall_ns", default)]
    pub wall_ns: u64,
    #[serde(rename = "active_ns", default)]
    pub active_ns: u64,
    #[serde(rename = "idle_spin_ns", default)]
    pub idle_spin_ns: u64,
    #[serde(rename = "idle_block_ns", default)]
    pub idle_block_ns: u64,
    #[serde(rename = "thread_cpu_ns", default)]
    pub thread_cpu_ns: u64,
    #[serde(rename = "work_loops", default)]
    pub work_loops: u64,
    /// #7919: monotonic high-water of per-session volume
    /// (`fwd_packets + rev_packets`) seen in THIS worker's session table on the
    /// conntrack-mirror refresh walk.
    ///
    /// ADDED, never a redefinition: in a rolling HA upgrade the two nodes run
    /// different binaries on one wire, so the new concept takes a new key. An
    /// OLD helper simply omits it, and the Go decoder models that as ABSENT
    /// (`*uint64` nil) rather than 0 — "this helper cannot answer" and "this
    /// worker has never held a session with traffic" are different facts, and
    /// conflating them would manufacture exactly the evidence this field exists
    /// to gather.
    ///
    /// `skip_serializing_if` keeps it off the wire while it is 0, so a helper
    /// that has genuinely observed nothing is indistinguishable from an old
    /// one — deliberate: both mean "no positive evidence of volume here", and
    /// neither may be read as a measured zero.
    #[serde(
        rename = "session_volume_high_water",
        default,
        skip_serializing_if = "is_zero_u64"
    )]
    pub session_volume_high_water: u64,
    #[serde(rename = "idle_loops", default)]
    pub idle_loops: u64,
    /// #1240: cumulative v8 per-worker queue-lease acquire calls
    /// observed by this worker across its bindings. Operators should
    /// compare `rate()` against per-worker TX rate to diagnose lease-
    /// request frequency imbalance.
    #[serde(rename = "cos_queue_lease_acquire_v8_calls", default)]
    pub cos_queue_lease_acquire_v8_calls: u64,
    /// #1240: cumulative bytes granted by v8 queue-lease acquire calls.
    #[serde(rename = "cos_queue_lease_acquire_v8_granted_bytes", default)]
    pub cos_queue_lease_acquire_v8_granted_bytes: u64,
    /// #1782 Step-1 (§5.2 mechanism (i)): cumulative CoS timer-wheel
    /// ticks advanced by `advance_cos_timer_wheel` across this
    /// worker's bindings. Pairs with `cos_wheel_ticks_advanced_max`,
    /// the largest single-call advance ever observed (a monotonic
    /// high-water mark) — one cold drain catching up a multi-minute
    /// per-worker idle lag appears as a single multi-million-tick max
    /// sample. `default` so an older daemon that predates the counter
    /// decodes as 0.
    #[serde(rename = "cos_wheel_ticks_advanced_total", default)]
    pub cos_wheel_ticks_advanced_total: u64,
    #[serde(rename = "cos_wheel_ticks_advanced_max", default)]
    pub cos_wheel_ticks_advanced_max: u64,
    /// #1782 Step-1 (§5.2 mechanism (ii)): per-cause v8 queue-lease
    /// under-grant attribution. Counted at the CoS exact-guarantee
    /// selector sites when the post-top-up `queue.hot.tokens <
    /// head_len` comparison shows the queue still cannot service its
    /// head, attributed to the `AcquireV8ShortfallCause` the lease
    /// reported. A v8-attributed subset of `drain_park_queue_tokens`.
    /// All `default` for mixed-version back-compat.
    #[serde(rename = "cos_queue_lease_undergrant_seqlock_give_up", default)]
    pub cos_queue_lease_undergrant_seqlock_give_up: u64,
    #[serde(rename = "cos_queue_lease_undergrant_cap_zero", default)]
    pub cos_queue_lease_undergrant_cap_zero: u64,
    #[serde(rename = "cos_queue_lease_undergrant_epoch_rotated", default)]
    pub cos_queue_lease_undergrant_epoch_rotated: u64,
    #[serde(rename = "cos_queue_lease_undergrant_share_exhausted", default)]
    pub cos_queue_lease_undergrant_share_exhausted: u64,
    #[serde(rename = "cos_queue_lease_undergrant_class_cap", default)]
    pub cos_queue_lease_undergrant_class_cap: u64,
    #[serde(rename = "cos_queue_lease_undergrant_outstanding_cap", default)]
    pub cos_queue_lease_undergrant_outstanding_cap: u64,
    /// Current entries in this worker's Rust-owned SessionTable.
    #[serde(rename = "session_table_entries", default)]
    pub session_table_entries: u64,
    /// Capacity of this worker's Rust-owned SessionTable.
    #[serde(rename = "max_sessions", default)]
    pub max_sessions: u64,
    /// #1760: cumulative NAT reverse-key displacement events on this
    /// worker's SessionTable nat_reverse_index — the latent 1:N collision
    /// (#1758) made observable. A near-precise upper bound on live
    /// collisions (counts displacement *events*, not distinct flow-pairs).
    /// `default` so an older daemon that predates this counter emits 0.
    #[serde(rename = "nat_reverse_key_collisions", default)]
    pub nat_reverse_key_collisions: u64,
    /// #6751: the DIFFERENT-SOURCE subset. Additive and `default`ed so an
    /// older helper deserializes to 0 instead of failing the status parse.
    #[serde(rename = "nat_reverse_key_collisions_distinct_src", default)]
    pub nat_reverse_key_collisions_distinct_src: u64,
    /// #1861: cumulative at-cap install refusals from this worker's
    /// SessionTable (`create_drops` — previously write-only). `default`
    /// for wire-additive compatibility with older daemons.
    #[serde(rename = "session_create_drops", default)]
    pub session_create_drops: u64,
    /// #7919: PER-WORKER by-key session-lookup misses, split by cause.
    ///
    /// Per-worker rather than only aggregated because the defect is
    /// per-session, not global: on the measured box one of three concurrent
    /// flows accounted perfectly while the other two froze, so any explanation
    /// predicting uniform behaviour is already wrong. A process-wide total
    /// cannot separate "one worker is missing everything" from "every worker
    /// misses occasionally", and those are different bugs.
    ///
    /// Additive (`default`), so an older peer decodes them as 0.
    #[serde(rename = "session_lookup_miss_no_handle", default)]
    pub session_lookup_miss_no_handle: u64,
    #[serde(rename = "session_lookup_miss_stale_handle", default)]
    pub session_lookup_miss_stale_handle: u64,
    #[serde(rename = "session_lookup_miss_key_mismatch", default)]
    pub session_lookup_miss_key_mismatch: u64,
    /// #1861: cumulative pair-admission preflight refusals (one per
    /// refused flow) on this worker's new-flow install path.
    #[serde(rename = "session_install_admission_refused", default)]
    pub session_install_admission_refused: u64,
    /// #1861: post-preflight partial-install residuals. Expected 0
    /// forever; nonzero means the preflight/install pairing has a bug.
    #[serde(rename = "session_install_partial", default)]
    pub session_install_partial: u64,
    /// #4800: cumulative locally-learned transit forward-flow installs on
    /// this worker — the per-worker share of the SNAT-allocate /
    /// `publish_shared_session` / `replicate_session_upsert` path. Divided
    /// by the run window this is the worker's new-flows/sec; compared
    /// across workers it shows whether a connection-rate ceiling is a
    /// genuine cross-worker lock bound or just one saturated RX queue.
    /// `default` so an older daemon that predates the counter emits 0.
    #[serde(rename = "new_flow_installs", default)]
    pub new_flow_installs: u64,
    /// #925: true if the worker_loop thread panicked and the supervisor
    /// caught it. Set once on first panic; never cleared in Phase 1.
    /// Operators see DEAD in `cli show chassis forwarding` and must
    /// restart the daemon for the dead worker's bindings to recover.
    #[serde(rename = "dead", default)]
    pub dead: bool,
    /// #925: panic payload string for operator diagnosis.
    /// Cases: `&str` payload → the argument; `String` payload → its
    /// content; non-string payload → literal "non-string panic payload";
    /// worker alive (no panic) → empty.
    #[serde(rename = "panic_message", default)]
    pub panic_message: String,
    /// Rolling last-window delta for `thread_cpu_ns`. Under the normal
    /// ~1 Hz worker publish cadence the rotated window is ~60–61s wide
    /// (one publish-tick of overshoot past `WR_WINDOW_INTERVAL_NS`); a
    /// stalled publisher can widen it further. `window_ns` carries the
    /// exact measured width so rate math is honest regardless of
    /// cadence. Both fields are zero until the first rotation has
    /// fired (~60s after worker start).
    #[serde(rename = "thread_cpu_ns_60s", default)]
    pub thread_cpu_ns_60s: u64,
    #[serde(rename = "wall_ns_60s", default)]
    pub wall_ns_60s: u64,
    #[serde(rename = "active_ns_60s", default)]
    pub active_ns_60s: u64,
    #[serde(rename = "window_ns", default)]
    pub window_ns: u64,

    // === #1621 cold-path histogram surface ===
    //
    // Mirrors WorkerColdPathCounters from #1619's cold_path_hist.rs.
    // The Vec fields use `skip_serializing_if = "Vec::is_empty"` so an
    // older Rust daemon that doesn't populate them emits no wire bytes
    // and an older Go reader sees nil. Scalar fields use
    // `serde(default)` so a missing field deserializes to 0 / empty
    // string. Per `feedback_wire_protocol_both_sides`.
    //
    // Aggregated PER WORKER (Claude SMR plan-r1 F1): when a worker owns
    // multiple bindings, the published values reflect the cross-binding
    // sum (buckets/sum_ns/samples/sample_phase/underflow_count) OR OR
    // (alias_seen) or first-non-zero (first_key) merge performed at
    // the publish tick. Per #1621 plan v1 §4.2.
    /// #1635 wire layout version. 0/absent = pre-#1635 (old dense v1
    /// fields, no longer emitted by this daemon); 3 = sparse
    /// active-slot encoding below. Go switches emission on this.
    #[serde(rename = "cold_path_layout_version", default,
            skip_serializing_if = "crate::protocol::u32_is_zero")]
    pub cold_path_layout_version: u32,
    /// #1635 SPARSE encoding — parallel arrays, one entry per ACTIVE
    /// zone-pair slot (samples > 0 AND a live slot-map assignment).
    /// Empty when the worker has never sampled, so its wire payload is
    /// byte-identical to a pre-#1635 daemon (forward-compat with old Go
    /// readers, per feedback_wire_protocol_both_sides).
    ///
    /// Slot index (for cross-reference / debugging).
    #[serde(rename = "cold_path_active_slot_ids", default,
            skip_serializing_if = "Vec::is_empty")]
    pub cold_path_active_slot_ids: Vec<u32>,
    /// Parallel: from_zone_id per active slot.
    #[serde(rename = "cold_path_active_zone_from", default,
            skip_serializing_if = "Vec::is_empty")]
    pub cold_path_active_zone_from: Vec<u32>,
    /// Parallel: to_zone_id per active slot.
    #[serde(rename = "cold_path_active_zone_to", default,
            skip_serializing_if = "Vec::is_empty")]
    pub cold_path_active_zone_to: Vec<u32>,
    /// Parallel: sample count per active slot.
    #[serde(rename = "cold_path_active_samples", default,
            skip_serializing_if = "Vec::is_empty")]
    pub cold_path_active_samples: Vec<u64>,
    /// Parallel: sum of sampled delta_ns per active slot.
    #[serde(rename = "cold_path_active_sum_ns", default,
            skip_serializing_if = "Vec::is_empty")]
    pub cold_path_active_sum_ns: Vec<u64>,
    /// Parallel: 48-bucket histogram per active slot.
    #[serde(rename = "cold_path_active_buckets", default,
            skip_serializing_if = "Vec::is_empty")]
    pub cold_path_active_buckets: Vec<Vec<u64>>,
    /// Parallel: builder-collision flag per active slot (should always
    /// be false with the direct slot map; true = builder bug).
    #[serde(rename = "cold_path_active_builder_collision", default,
            skip_serializing_if = "Vec::is_empty")]
    pub cold_path_active_builder_collision: Vec<bool>,
    /// True if some configured zone-pair could not be assigned a slot —
    /// either the 255-slot capacity was exhausted (slot 255 is the
    /// u8::MAX sentinel) OR the pair references a zone-id outside the
    /// 0..=64 direct-table range. Surfaced so operators see when a
    /// configured pair goes unmeasured.
    #[serde(rename = "cold_path_overflow_active", default,
            skip_serializing_if = "crate::protocol::bool_is_false")]
    pub cold_path_overflow_active: bool,
    /// Per-worker monotonic count of eligible cold-path sampling
    /// attempts (incremented on every session-miss pass). Used by the
    /// #1622 harness as the denominator for actual_sampling_rate =
    /// sum(samples[]) / sample_phase. `u64_is_zero` skip keeps an
    /// uncalibrated worker's wire payload identical to pre-#1621
    /// daemons (AGY r1 F1).
    #[serde(rename = "cold_path_sample_phase", default,
            skip_serializing_if = "crate::protocol::u64_is_zero")]
    pub cold_path_sample_phase: u64,
    /// Per-worker monotonic count of samples where raw_ns <
    /// wrapper_ns_baseline (frequency scaling / OoO jitter signal).
    #[serde(rename = "cold_path_wrapper_underflow_count", default,
            skip_serializing_if = "crate::protocol::u64_is_zero")]
    pub cold_path_wrapper_underflow_count: u64,
    /// Q32 fixed-point ns_per_tsc multiplier from worker startup
    /// calibration. 0 when TSC unavailable.
    #[serde(rename = "cold_path_ns_per_tsc_q32", default,
            skip_serializing_if = "crate::protocol::u64_is_zero")]
    pub cold_path_ns_per_tsc_q32: u64,
    /// Wrapper-pair baseline (cost of sample_tsc_start + sample_tsc_end
    /// itself) measured at worker startup. Subtracted from raw_ns on
    /// the hot path.
    #[serde(rename = "cold_path_wrapper_ns_baseline", default,
            skip_serializing_if = "crate::protocol::u64_is_zero")]
    pub cold_path_wrapper_ns_baseline: u64,
    /// "tsc" / "clock_gettime" / "" (empty = Unset). Harness gates
    /// Table A1/A2 publication on == "tsc" for every worker.
    #[serde(rename = "cold_path_clock_source", default,
            skip_serializing_if = "String::is_empty")]
    pub cold_path_clock_source: String,
    /// #1621 plan v2 (AGY r1 F3 + Codex r1 F5): monotonic count of
    /// snapshot() calls that exhausted their retry budget at the
    /// coordinator status path. Surfaced as
    /// `xpf_userspace_worker_cold_path_snapshot_failed_total` so
    /// operators can distinguish "no samples this window" from
    /// "transient publish-contention starvation".
    #[serde(rename = "cold_path_snapshot_failed", default,
            skip_serializing_if = "crate::protocol::u64_is_zero")]
    pub cold_path_snapshot_failed: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct HAGroupStatus {
    #[serde(rename = "rg_id", default)]
    pub rg_id: i32,
    #[serde(default)]
    pub active: bool,
    #[serde(rename = "watchdog_timestamp", default)]
    pub watchdog_timestamp: u64,
    #[serde(rename = "forwarding_active", default)]
    pub forwarding_active: bool,
    #[serde(
        rename = "lease_state",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub lease_state: String,
    #[serde(
        rename = "lease_until",
        default,
        skip_serializing_if = "crate::protocol::u64_is_zero"
    )]
    pub lease_until: u64,
}

pub(crate) fn u64_is_zero(value: &u64) -> bool {
    *value == 0
}

pub(crate) fn u32_is_zero(value: &u32) -> bool {
    *value == 0
}

pub(crate) fn u16_is_zero(value: &u16) -> bool {
    *value == 0
}

pub(crate) fn bool_is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct QueueStatus {
    #[serde(rename = "queue_id")]
    pub queue_id: u32,
    #[serde(rename = "worker_id")]
    pub worker_id: u32,
    #[serde(default)]
    pub interfaces: Vec<String>,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub armed: bool,
    #[serde(default)]
    pub ready: bool,
    #[serde(rename = "last_change", skip_serializing_if = "Option::is_none")]
    pub last_change: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct BindingStatus {
    pub slot: u32,
    #[serde(rename = "queue_id")]
    pub queue_id: u32,
    #[serde(rename = "worker_id")]
    pub worker_id: u32,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub ifindex: i32,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub armed: bool,
    #[serde(default)]
    pub ready: bool,
    #[serde(default)]
    pub bound: bool,
    #[serde(rename = "xsk_registered", default)]
    pub xsk_registered: bool,
    #[serde(rename = "xsk_bind_mode", default)]
    pub xsk_bind_mode: String,
    #[serde(rename = "zero_copy", default)]
    pub zero_copy: bool,
    #[serde(rename = "socket_fd", default)]
    pub socket_fd: i32,
    #[serde(rename = "rx_packets", default)]
    pub rx_packets: u64,
    #[serde(rename = "rx_bytes", default)]
    pub rx_bytes: u64,
    #[serde(rename = "rx_batches", default)]
    pub rx_batches: u64,
    #[serde(rename = "rx_wakeups", default)]
    pub rx_wakeups: u64,
    #[serde(rename = "metadata_packets", default)]
    pub metadata_packets: u64,
    #[serde(rename = "metadata_errors", default)]
    pub metadata_errors: u64,
    #[serde(rename = "validated_packets", default)]
    pub validated_packets: u64,
    #[serde(rename = "validated_bytes", default)]
    pub validated_bytes: u64,
    #[serde(rename = "local_delivery_packets", default)]
    pub local_delivery_packets: u64,
    #[serde(rename = "forward_candidate_packets", default)]
    pub forward_candidate_packets: u64,
    #[serde(rename = "route_miss_packets", default)]
    pub route_miss_packets: u64,
    /// #4743: NoRoute drops whose destination is a MARTIAN address (IPv4
    /// multicast/broadcast/unspecified/loopback, IPv6
    /// multicast/unspecified/loopback). A strict sub-breakout of
    /// `route_miss_packets` (a martian dst misses the FIB and drops as NoRoute,
    /// so it bumps both), letting an operator tell a martian-dst drop apart from
    /// an ordinary route miss. `default` keeps cross-version wire safety (an
    /// older helper omits it and Go/Rust read 0). Surfaced as the `Martian
    /// drops` status row.
    #[serde(rename = "martian_dropped", default)]
    pub martian_dropped: u64,
    /// #4743: fail-closed drops of an IPv6 packet whose extension-header chain
    /// is still on an extension header after `MAX_IPV6_EXT_HEADERS` (8)
    /// iterations (an over-limit, uninspectable chain). Distinct from a
    /// truncated chain (which stays flowless). `default` keeps cross-version
    /// wire safety. Surfaced as the `IPv6 ext-header drops` status row.
    #[serde(rename = "ipv6_ext_header_dropped", default)]
    pub ipv6_ext_header_dropped: u64,
    #[serde(rename = "neighbor_miss_packets", default)]
    pub neighbor_miss_packets: u64,
    #[serde(rename = "discard_route_packets", default)]
    pub discard_route_packets: u64,
    #[serde(rename = "next_table_packets", default)]
    pub next_table_packets: u64,
    #[serde(rename = "exception_packets", default)]
    pub exception_packets: u64,
    #[serde(rename = "config_gen_mismatches", default)]
    pub config_gen_mismatches: u64,
    #[serde(rename = "fib_gen_mismatches", default)]
    pub fib_gen_mismatches: u64,
    #[serde(rename = "unsupported_packets", default)]
    pub unsupported_packets: u64,
    #[serde(rename = "flow_cache_hits", default)]
    pub flow_cache_hits: u64,
    #[serde(rename = "flow_cache_misses", default)]
    pub flow_cache_misses: u64,
    #[serde(rename = "flow_cache_evictions", default)]
    pub flow_cache_evictions: u64,
    /// #918: collision-driven subset of `flow_cache_evictions`. An
    /// insert that displaced a different-key entry from the LRU way
    /// of a full set increments this; stale-on-lookup evictions do
    /// not. Acceptance gate watches `collision_evictions / hits`
    /// under load.
    #[serde(rename = "flow_cache_collision_evictions", default)]
    pub flow_cache_collision_evictions: u64,
    /// #1219: snapshot count of distinct active flows on this binding's
    /// flow_cache, refreshed at the ~65ms debug-state tick. Per
    /// `docs/fairness-regimes.md`, the harness reads this via
    /// Prometheus to compute `{a_i}` for the structural CoV gate.
    #[serde(rename = "active_flow_count", default)]
    pub active_flow_count: u32,
    /// Per-binding capacity of the Rust-owned flow cache. This is the
    /// denominator for operator buffer rendering when active_flow_count
    /// is shown as utilization.
    #[serde(rename = "flow_cache_capacity", default)]
    pub flow_cache_capacity: u32,
    /// #941 Work item D / #943: count of V_min hard-cap activations
    /// on this binding. Hard-cap is the escape hatch that fires
    /// after V_MIN_CONSECUTIVE_SKIP_HARD_CAP back-to-back throttle
    /// decisions, force-continuing the drain to recover throughput
    /// under persistent peer-vtime spread. Acceptance gate: under
    /// normal load, override-rate stays below 5 %.
    #[serde(rename = "v_min_throttle_hard_cap_overrides", default)]
    pub v_min_throttle_hard_cap_overrides: u64,
    /// #943: count of regular V_min throttle decisions
    /// (`cos_queue_v_min_continue` returned `false` and the drain
    /// loop early-broke) on this binding. Distinct from the hard-cap
    /// override path (which force-continues despite the throttle).
    /// Together: `v_min_throttles` is "fairness brake fired",
    /// `v_min_throttle_hard_cap_overrides` is "brake too tight, escape
    /// hatch rescued throughput". Ratio is the LAG_THRESHOLD diagnostic.
    #[serde(rename = "v_min_throttles", default)]
    pub v_min_throttles: u64,
    /// #hb166 T-6(a): count of V_min suspended drain batches (fairness
    /// brake OFF because a prior hard-cap armed suspension). Default keeps
    /// pre-fix consumers parseable.
    #[serde(rename = "v_min_suspended_batches", default)]
    pub v_min_suspended_batches: u64,
    #[serde(rename = "session_hits", default)]
    pub session_hits: u64,
    #[serde(rename = "session_misses", default)]
    pub session_misses: u64,
    #[serde(rename = "session_creates", default)]
    pub session_creates: u64,
    #[serde(rename = "session_expires", default)]
    pub session_expires: u64,
    #[serde(rename = "session_delta_pending", default)]
    pub session_delta_pending: u64,
    #[serde(rename = "session_delta_generated", default)]
    pub session_delta_generated: u64,
    #[serde(rename = "session_delta_dropped", default)]
    pub session_delta_dropped: u64,

    /// #8108: the greatest depth `pending_session_deltas` has reached on this
    /// binding. A HIGH-WATER mark, not a depth: the buffer drains, so a depth
    /// sampled at 1 Hz misses a revocation burst unless the sample lands inside
    /// it. `default` so an older helper decodes 0 rather than failing the parse.
    #[serde(rename = "session_delta_high_water", default)]
    pub session_delta_high_water: u64,
    #[serde(rename = "session_delta_drained", default)]
    pub session_delta_drained: u64,
    #[serde(rename = "policy_denied_packets", default)]
    pub policy_denied_packets: u64,
    // #3326: host-inbound admission denies on the LocalDelivery path. Mirrored
    // into the Go GlobalCtrHostInboundDeny counter (REST/Prometheus/show).
    #[serde(rename = "host_inbound_denied_packets", default)]
    pub host_inbound_denied_packets: u64,
    #[serde(rename = "screen_drops", default)]
    pub screen_drops: u64,
    /// #3343: per-screen-reason DROP counters. One u64 per published ordinal
    /// (see `screen::screen_reason_drop_index` / Go
    /// `pkg/dataplane.ScreenReasonCounters`). The Go control plane sums these
    /// across bindings and pushes each ordinal into its `GlobalCtrScreen*`
    /// global counter so `show security screen-statistics` / alarms / gRPC /
    /// REST / Prometheus attribute drops to a specific screen check instead of
    /// reading a permanent 0. Serialized unconditionally (no skip) so the wire
    /// key is stable.
    #[serde(rename = "screen_reason_drops", default)]
    pub screen_reason_drops: [u64; crate::screen::SCREEN_REASON_DROP_COUNT],
    #[serde(rename = "syn_cookie_challenges", default)]
    pub syn_cookie_challenges: u64,
    #[serde(rename = "syn_cookie_secret_unavailable", default)]
    pub syn_cookie_secret_unavailable: u64,
    #[serde(rename = "syn_cookie_syn_ack_sent", default)]
    pub syn_cookie_syn_ack_sent: u64,
    #[serde(rename = "syn_cookie_ack_rst_sent", default)]
    pub syn_cookie_ack_rst_sent: u64,
    #[serde(rename = "syn_cookie_reply_budget_drops", default)]
    pub syn_cookie_reply_budget_drops: u64,
    #[serde(rename = "syn_cookie_ack_valid", default)]
    pub syn_cookie_ack_valid: u64,
    #[serde(rename = "syn_cookie_ack_invalid", default)]
    pub syn_cookie_ack_invalid: u64,
    #[serde(rename = "syn_cookie_bypass", default)]
    pub syn_cookie_bypass: u64,
    #[serde(rename = "policy_reject_sent", default)]
    pub policy_reject_sent: u64,
    // #2521: firewall-filter `then reject` RST/ICMP-unreachable replies
    // enqueued (mirrors policy_reject_sent). `default` keeps cross-version
    // wire safety — an older helper omits the field and Go/Rust read 0
    // (#1961-class contract).
    #[serde(rename = "filter_reject_sent", default)]
    pub filter_reject_sent: u64,
    #[serde(rename = "policy_reject_reply_budget_drops", default)]
    pub policy_reject_reply_budget_drops: u64,
    // #3615 (L04): FILTER-`reject` reply TX-frame-budget suppression, split
    // from policy_reject_reply_budget_drops. `default` keeps cross-version
    // wire safety (an older helper omits it → 0).
    #[serde(rename = "filter_reject_reply_budget_drops", default)]
    pub filter_reject_reply_budget_drops: u64,
    // #3661: POLICY-`reject` replies dropped because the shared per-reason
    // rate-limit token bucket (REJECT_BUCKET) was empty — the source split of
    // the source-neutral aggregate ProcessStatus.reject_rate_limited_total.
    // `default` keeps cross-version wire safety (an older helper omits it → 0).
    #[serde(rename = "policy_reject_rate_limit_drops", default)]
    pub policy_reject_rate_limit_drops: u64,
    // #3661: FILTER-`reject` reply rate-limit drop, split from
    // policy_reject_rate_limit_drops. `default` keeps cross-version wire
    // safety (an older helper omits it → 0).
    #[serde(rename = "filter_reject_rate_limit_drops", default)]
    pub filter_reject_rate_limit_drops: u64,
    // #2238: locally-generated replies dropped by an output firewall filter
    // on the egress interface (now classified by the reply's OWN egress
    // tuple), and the fail-closed drops when the generated bytes could not be
    // re-parsed (§6.2). `default` keeps cross-version wire safety — an older
    // helper omits the field and Go/Rust read 0 (#1961-class contract).
    #[serde(rename = "time_exceeded_output_filter_drops", default)]
    pub time_exceeded_output_filter_drops: u64,
    #[serde(rename = "policy_reject_output_filter_drops", default)]
    pub policy_reject_output_filter_drops: u64,
    // #3615 (L05): FILTER-`reject` reply egress-output-filter suppression,
    // split from policy_reject_output_filter_drops. `default` keeps
    // cross-version wire safety (an older helper omits it → 0).
    #[serde(rename = "filter_reject_output_filter_drops", default)]
    pub filter_reject_output_filter_drops: u64,
    #[serde(rename = "syn_cookie_output_filter_drops", default)]
    pub syn_cookie_output_filter_drops: u64,
    // #2328: egress-MTU PTB / Frag-Needed replies dropped by an output
    // firewall filter, classified by the PTB's own egress tuple. `default`
    // keeps cross-version wire safety (an older helper omits it → 0).
    #[serde(rename = "ptb_output_filter_drops", default)]
    pub ptb_output_filter_drops: u64,
    #[serde(rename = "generated_reply_classify_parse_errors", default)]
    pub generated_reply_classify_parse_errors: u64,
    #[serde(rename = "snat_packets", default)]
    pub snat_packets: u64,
    #[serde(rename = "dnat_packets", default)]
    pub dnat_packets: u64,
    // #2161: `default` keeps cross-version wire safety — a peer/helper that
    // predates this field simply omits it and Go/Rust read 0 (the #1961-class
    // omitempty/serde-default contract).
    #[serde(rename = "nat64_translations", default)]
    pub nat64_translations: u64,
    // #2291: fail-closed NAT64 drops — a prefix matched but no IPv4 source
    // could be allocated (empty/exhausted pool), so the synthetic IPv6
    // destination was dropped rather than route-looked-up as IPv6. `default`
    // keeps the same cross-version wire safety as nat64_translations above.
    #[serde(rename = "nat64_no_source_pool", default)]
    pub nat64_no_source_pool: u64,
    /// #4520: transient NAT64 pool-exhaustion drops — a prefix matched and its
    /// pool was non-empty, but no free translated port could be allocated
    /// (`AllocatorExhausted`). The transient sibling of `nat64_no_source_pool`
    /// (config/empty). `default` keeps the same cross-version wire safety (an
    /// older helper omits it and Go/Rust read 0).
    #[serde(rename = "nat64_pool_exhausted", default)]
    pub nat64_pool_exhausted: u64,
    /// #2562: fail-closed NAT64 fragment drops — a datagram dropped because it
    /// is a fragment NAT64 cannot safely translate (a non-first fragment, or a
    /// real ICMP/ICMPv6 fragment whose checksum covers the whole datagram). The
    /// observable-drop half of #2562; the stateful frag-association cache
    /// (#3291 stage 4) that would let real fragments traverse is deferred.
    /// `default` keeps the same cross-version wire safety (an older helper omits
    /// it and Go/Rust read 0).
    #[serde(rename = "nat64_frag_dropped", default)]
    pub nat64_frag_dropped: u64,
    /// #7054: first-fragment installs that evicted a still-LIVE fragment
    /// association because the shard was at cap with nothing expired to
    /// reclaim. Additive + `default`, so an older reader simply does not see
    /// it and no interpretation of existing bytes changes.
    #[serde(rename = "nat64_frag_assoc_evicted", default)]
    pub nat64_frag_assoc_evicted: u64,
    /// #5623: fail-closed NAT64 SOURCE-ineligibility drops — an incoming IPv6
    /// packet whose SOURCE lies within a configured Pref64 (a looping/synthesized
    /// "already-translated" source, the RFC 6146 §5 hairpin construction — plus
    /// the lower/upper Pref64 boundary and any embedded non-global v4) dropped
    /// BEFORE route lookup, policy, or `allocate_source` per RFC 6146 §3.5.
    /// Distinct from the pool counters (config/capacity on an ELIGIBLE flow) —
    /// this is an input-validation reject. `default` keeps cross-version wire
    /// safety (an older helper omits it and Go/Rust read 0).
    #[serde(rename = "nat64_ineligible_source", default)]
    pub nat64_ineligible_source: u64,
    /// #6475: fail-closed NAT64 DESTINATION-ineligibility drops — an incoming
    /// IPv6 packet whose NAT64-prefix-matched destination embeds a non-global
    /// IPv4 per RFC 6052 §3.1 (0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
    /// 224.0.0.0/4, 240.0.0.0/4 — e.g. `64:ff9b::127.0.0.1`, which would
    /// otherwise resolve LocalDelivery to the localhost-only control plane once
    /// lo0 lands in `state.local_v4`) dropped BEFORE route lookup, policy, or
    /// `allocate_source`. Distinct from the source/pool counters — this is a
    /// destination input-validation reject. `default` keeps cross-version wire
    /// safety (an older helper omits it and Go/Rust read 0).
    #[serde(rename = "nat64_ineligible_dest", default)]
    pub nat64_ineligible_dest: u64,
    /// #5625: fail-closed NAT64 EXTENSION-HEADER ineligibility drops — a v6→v4
    /// forward translation rejected because the IPv6 packet carried an
    /// Authentication Header (51), an ACTIVE Routing header (43, Segments
    /// Left > 0), or a Mobility (135) / HIP (139) / Shim6 (140) header, none of
    /// which a stateless NAT64 translation can carry to IPv4 (RFC 7915 §5.1 /
    /// §5.1.1) — translating would strip the active extension semantics or break
    /// AH authentication. Distinct from the source/pool/fragment counters — this
    /// is an ext-header input reject. `default` keeps cross-version wire safety
    /// (an older helper omits it and Go/Rust read 0).
    #[serde(rename = "nat64_exthdr_ineligible", default)]
    pub nat64_exthdr_ineligible: u64,
    /// #8670: fail-closed NAT64 protocol-ineligibility drops (a Pref64-addressed
    /// packet carrying an IP protocol stateful NAT64 does not translate).
    #[serde(rename = "nat64_ineligible_protocol", default)]
    pub nat64_ineligible_protocol: u64,
    /// #4477: source-NAT allocation failures (rule matched, no translated
    /// mapping could be allocated → packet dropped). `default` keeps the same
    /// cross-version wire safety as the siblings above (an older helper omits it
    /// and Go/Rust read 0). The Go control plane bridges this into the
    /// `GlobalCtrNATAllocFail` global counter (`NAT allocation failures`) and,
    /// with the other enforcement drops, into `GlobalCtrDrops`.
    #[serde(rename = "nat_alloc_fail", default)]
    pub nat_alloc_fail: u64,
    /// #6122: fail-closed drops of an ordinary same-family NAT'd (SNAT /
    /// static-NAT / DNAT / NPTv6) NON-FIRST fragment that MISSED the
    /// fragment-association cache. Forwarding it untranslated would leak the
    /// internal source (SNAT / NPTv6) or the pre-NAT destination (DNAT), so the
    /// permitted-but-untranslatable fragment is dropped fail-closed instead of
    /// leaked. The same-family sibling of `nat64_frag_dropped`; a plain (no-NAT)
    /// fragment matches no rule and is NOT counted here. `default` keeps the same
    /// cross-version wire safety as the siblings above (an older helper omits it
    /// and Go/Rust read 0).
    #[serde(rename = "nat_frag_untranslated_dropped", default)]
    pub nat_frag_untranslated_dropped: u64,
    #[serde(rename = "slow_path_packets", default)]
    pub slow_path_packets: u64,
    #[serde(rename = "slow_path_bytes", default)]
    pub slow_path_bytes: u64,
    #[serde(rename = "slow_path_local_delivery_packets", default)]
    pub slow_path_local_delivery_packets: u64,
    #[serde(rename = "slow_path_missing_neighbor_packets", default)]
    pub slow_path_missing_neighbor_packets: u64,
    #[serde(rename = "slow_path_no_route_packets", default)]
    pub slow_path_no_route_packets: u64,
    #[serde(rename = "slow_path_next_table_packets", default)]
    pub slow_path_next_table_packets: u64,
    /// #6664: NextTableUnsupported frames dropped fail-closed by the
    /// slow-path allow-list. Since #6664 this is where the signal lives;
    /// `slow_path_next_table_packets` above stays on the wire for older
    /// readers but no longer advances.
    #[serde(rename = "next_table_unsupported_drops", default)]
    pub next_table_unsupported_drops: u64,
    #[serde(rename = "slow_path_forward_build_packets", default)]
    pub slow_path_forward_build_packets: u64,
    #[serde(rename = "slow_path_drops", default)]
    pub slow_path_drops: u64,
    #[serde(rename = "slow_path_rate_limited", default)]
    pub slow_path_rate_limited: u64,
    /// #1873 R-C/R-E: tunnel-marked inner packets dropped instead of
    /// plaintext kernel reinjection / in-place TX. Wire-additive
    /// (serde default; Go side omitempty).
    #[serde(rename = "tunnel_encap_unresolved_drops", default)]
    pub tunnel_encap_unresolved_drops: u64,
    /// #8890: NAT64-translated packets dropped because the route resolved
    /// through a GRE / WireGuard endpoint the NAT64 builder cannot
    /// encapsulate into — the fail-closed sibling of
    /// `tunnel_encap_unresolved_drops` on the RESOLVED route. Wire-additive
    /// (serde default; Go side omitempty): a counter absent from an older
    /// helper reads 0, which is honest — that build does not report it.
    #[serde(rename = "nat64_tunnel_encap_unsupported", default)]
    pub nat64_tunnel_encap_unsupported: u64,
    /// #1946: FabricRedirect frames dropped fail-closed because they
    /// could not be TX'd to the HA peer (no fabric XSK binding, or the
    /// forward-frame build/enqueue failed). Wire-additive (serde
    /// default; Go side omitempty).
    #[serde(rename = "fabric_redirect_unsendable_drops", default)]
    pub fabric_redirect_unsendable_drops: u64,
    #[serde(rename = "kernel_rx_dropped", default)]
    pub kernel_rx_dropped: u64,
    #[serde(rename = "kernel_rx_invalid_descs", default)]
    pub kernel_rx_invalid_descs: u64,
    #[serde(rename = "tx_packets", default)]
    pub tx_packets: u64,
    #[serde(rename = "tx_bytes", default)]
    pub tx_bytes: u64,
    #[serde(rename = "tx_errors", default)]
    pub tx_errors: u64,
    // #1307: shared-UMEM recycle requests dropped because their
    // recorded fill slot no longer maps to a live binding. Subset of
    // `tx_errors`.
    #[serde(rename = "tx_shared_recycle_unknown_slot_drops", default)]
    pub tx_shared_recycle_unknown_slot_drops: u64,
    // #710: per-binding subset of `tx_errors` attributed to the
    // redirect-inbox overflow path in `BindingLiveState::enqueue_tx` /
    // `enqueue_tx_owned`. Indicates the owner is not draining redirects
    // fast enough for the rate of incoming redirects from non-owner
    // workers. See #706 / #709.
    #[serde(rename = "redirect_inbox_overflow_drops", default)]
    pub redirect_inbox_overflow_drops: u64,
    // #710: per-binding `pending_tx_local`/`pending_tx_prepared` FIFO
    // overflow drops. Subset of `tx_errors`. Indicates the worker
    // cannot ingest redirected traffic into CoS as fast as it arrives
    // — often the load-bearing drop category on the owner worker
    // under multi-flow load.
    #[serde(rename = "pending_tx_local_overflow_drops", default)]
    pub pending_tx_local_overflow_drops: u64,
    // #710: catch-all counter for frame-level TX submit errors
    // (`TxError::Drop`, scratch-build slice/capacity failures). Subset
    // of `tx_errors`. Non-zero usually indicates a frame-builder bug
    // rather than a scheduler/shaper decision — separate category from
    // the flow-fair admission / redirect-inbox / pending-FIFO drops.
    #[serde(rename = "tx_submit_error_drops", default)]
    pub tx_submit_error_drops: u64,
    #[serde(rename = "mirrored_packets", default)]
    pub mirrored_packets: u64,
    #[serde(rename = "mirrored_bytes", default)]
    pub mirrored_bytes: u64,
    #[serde(rename = "mirror_drops_no_frame", default)]
    pub mirror_drops_no_frame: u64,
    #[serde(rename = "mirror_drops_tx_frame_reserve", default)]
    pub mirror_drops_tx_frame_reserve: u64,
    #[serde(rename = "mirror_drops_no_binding", default)]
    pub mirror_drops_no_binding: u64,
    #[serde(rename = "mirror_drops_queue_full", default)]
    pub mirror_drops_queue_full: u64,
    #[serde(rename = "mirror_drops_queue_full_same_worker", default)]
    pub mirror_drops_queue_full_same_worker: u64,
    #[serde(rename = "mirror_drops_queue_full_cross_worker", default)]
    pub mirror_drops_queue_full_cross_worker: u64,
    // #760 instrumentation: post-CoS backup transmit bytes
    // (drain_pending_tx fallbacks (tx/drain.rs::drain_pending_tx)) that bypass
    // any CoS queue's token gate.
    #[serde(rename = "post_drain_backup_bytes", default)]
    pub post_drain_backup_bytes: u64,
    // #760 instrumentation: binding-scoped bytes observed at the
    // three apply_* tx_bytes sites, written unconditionally. Gap
    // vs the sum of per-queue drain_sent_bytes attributes shaped
    // traffic that bypassed the per-queue write via an apply_*
    // early-return / queue miss.
    #[serde(rename = "drain_sent_bytes_shaped_unconditional", default)]
    pub drain_sent_bytes_shaped_unconditional: u64,
    // #760 (PR #773): CoS-bound items dropped at the post-drain
    // backup filter — cross-worker routing failures the bounded
    // ingest-drain loop didn't absorb. Non-zero is the primary
    // operator signal that the backup-path belt-and-suspenders
    // is catching real leakage.
    #[serde(rename = "post_drain_backup_cos_drops", default)]
    pub post_drain_backup_cos_drops: u64,
    #[serde(rename = "post_drain_backup_cos_drop_bytes", default)]
    pub post_drain_backup_cos_drop_bytes: u64,
    // #710 attribution note: cross-worker CoS "no-owner-binding" drops
    // are exposed at the `ProcessStatus::cos_no_owner_binding_drops_total`
    // top-level field, not per binding. The increment mechanically lands
    // on the landing worker's first binding (no ifindex is meaningful —
    // the drop fires specifically because no binding matched the
    // request's egress), so per-binding attribution would mislead
    // operators during triage.
    #[serde(rename = "direct_tx_packets", default)]
    pub direct_tx_packets: u64,
    #[serde(rename = "copy_tx_packets", default)]
    pub copy_tx_packets: u64,
    #[serde(rename = "in_place_tx_packets", default)]
    pub in_place_tx_packets: u64,
    #[serde(rename = "in_place_vlan_push_desc_packets", default)]
    pub in_place_vlan_push_desc_packets: u64,
    #[serde(rename = "in_place_vlan_pop_desc_packets", default)]
    pub in_place_vlan_pop_desc_packets: u64,
    #[serde(rename = "in_place_vlan_push_no_headroom_packets", default)]
    pub in_place_vlan_push_no_headroom_packets: u64,
    #[serde(rename = "in_place_l2_memmove_fallback_packets", default)]
    pub in_place_l2_memmove_fallback_packets: u64,
    #[serde(rename = "direct_tx_no_frame_fallback_packets", default)]
    pub direct_tx_no_frame_fallback_packets: u64,
    #[serde(rename = "direct_tx_build_fallback_packets", default)]
    pub direct_tx_build_fallback_packets: u64,
    #[serde(rename = "direct_tx_disallowed_fallback_packets", default)]
    pub direct_tx_disallowed_fallback_packets: u64,
    #[serde(rename = "last_heartbeat", skip_serializing_if = "Option::is_none")]
    pub last_heartbeat: Option<DateTime<Utc>>,
    #[serde(rename = "tx_completions", default)]
    pub tx_completions: u64,
    #[serde(rename = "socket_ifindex", default)]
    pub socket_ifindex: i32,
    #[serde(rename = "socket_queue_id", default)]
    pub socket_queue_id: u32,
    #[serde(rename = "socket_bind_flags", default)]
    pub socket_bind_flags: u32,
    /// Experimental shared-UMEM bind plan selected by the coordinator.
    /// Empty/default means the binding is using the normal private UMEM path.
    #[serde(rename = "shared_umem_mode", default)]
    pub shared_umem_mode: String,
    #[serde(rename = "shared_umem_group", default)]
    pub shared_umem_group: String,
    #[serde(rename = "shared_umem_socket_role", default)]
    pub shared_umem_socket_role: String,
    #[serde(rename = "shared_umem_disabled_reason", default)]
    pub shared_umem_disabled_reason: String,
    #[serde(rename = "debug_pending_fill_frames", default)]
    pub debug_pending_fill_frames: u32,
    #[serde(rename = "debug_spare_fill_frames", default)]
    pub debug_spare_fill_frames: u32,
    #[serde(rename = "debug_free_tx_frames", default)]
    pub debug_free_tx_frames: u32,
    #[serde(rename = "debug_pending_tx_prepared", default)]
    pub debug_pending_tx_prepared: u32,
    #[serde(rename = "debug_pending_tx_local", default)]
    pub debug_pending_tx_local: u32,
    #[serde(rename = "debug_outstanding_tx", default)]
    pub debug_outstanding_tx: u32,
    /// #1241: last sampled AF_XDP TX completion-ring availability
    /// before completion drain. This is a low-frequency status gauge
    /// published from owner-local worker telemetry; it is not read by
    /// the scheduler.
    #[serde(rename = "tx_completion_ring_available", default)]
    pub tx_completion_ring_available: u32,
    /// #1241: maximum sampled completion-ring availability in the last
    /// debug window.
    #[serde(rename = "tx_completion_ring_available_max", default)]
    pub tx_completion_ring_available_max: u32,
    #[serde(rename = "debug_in_flight_recycles", default)]
    pub debug_in_flight_recycles: u32,
    // #802: ring-pressure instrumentation. Operator-facing cumulative
    // counters for XSK ring saturation diagnosis. See the
    // `line-rate-investigation-plan.md` "DEFERRED-INSTRUMENTATION" rows
    // for semantics. `outstanding_tx` is a gauge (current value) that
    // serves as a proxy for `completion_reap_max_batch`; the real
    // completion-reap-batch histogram is accept-proxy per that plan.
    #[serde(rename = "dbg_tx_ring_full", default)]
    pub dbg_tx_ring_full: u64,
    #[serde(rename = "dbg_sendto_enobufs", default)]
    pub dbg_sendto_enobufs: u64,
    // #804: split from the old conflated `dbg_pending_overflow`. Two
    // distinct write-sites, two distinct wire keys. Pre-#804 snapshots
    // will deserialize both as 0 (`default`), which is the right
    // backward-compat behavior — the old field is no longer present on
    // the wire and consumers that want totals across either path should
    // sum the two explicitly.
    #[serde(rename = "dbg_bound_pending_overflow", default)]
    pub dbg_bound_pending_overflow: u64,
    #[serde(rename = "dbg_cos_queue_overflow", default)]
    pub dbg_cos_queue_overflow: u64,
    #[serde(rename = "rx_fill_ring_empty_descs", default)]
    pub rx_fill_ring_empty_descs: u64,
    #[serde(rename = "outstanding_tx", default)]
    pub outstanding_tx: u32,
    /// #878: per-binding UMEM total frames (set once at worker
    /// construction). Denominator for the daemon's `show chassis
    /// forwarding` Buffer%; numerator is `umem_inflight_frames`.
    /// `default` keeps the wire format additive — a pre-#878 helper
    /// that lacks this field deserializes as zero, which the daemon
    /// treats as "not yet published" and falls back to the legacy
    /// display.
    #[serde(rename = "umem_total_frames", default)]
    pub umem_total_frames: u32,
    /// #878: configured TX-ring depth.
    /// `outstanding_tx / tx_ring_capacity` is the second pressure
    /// signal aggregated by Buffer%.
    #[serde(rename = "tx_ring_capacity", default)]
    pub tx_ring_capacity: u32,
    /// #878: UMEM in-flight gauge, published in a single atomic
    /// store from the worker's per-second debug tick. `default`
    /// preserves wire compat — a pre-#878 helper sends 0 and the
    /// daemon treats `umem_total_frames == 0` (not this field) as
    /// the "not published" signal.
    #[serde(rename = "umem_inflight_frames", default)]
    pub umem_inflight_frames: u32,
    // #812: per-queue TX submit→completion latency telemetry. Emitted
    // in the rich BindingStatus shape; also projected onto the focused
    // `BindingCountersSnapshot` via the `From` impl so the
    // step1-capture consumer can reach it without a second join.
    // `drain_latency_hist` on ProcessStatus (see control.rs) is
    // the sibling wire contract this mirrors — histograms on the
    // wire are Vec<u64> so
    // serde needs no schema for the fixed-cap array. Default on all
    // three preserves backward-compat for pre-#812 helper payloads
    // (fields absent → zero-valued).
    #[serde(rename = "tx_submit_latency_hist", default)]
    pub tx_submit_latency_hist: Vec<u64>,
    #[serde(rename = "tx_submit_latency_count", default)]
    pub tx_submit_latency_count: u64,
    #[serde(rename = "tx_submit_latency_sum_ns", default)]
    pub tx_submit_latency_sum_ns: u64,
    // #825: per-kick `sendto` latency telemetry. Same wire shape
    // as `tx_submit_latency_*` — 16 log2 buckets via `Vec<u64>`,
    // plus count, sum-ns, and the EAGAIN/EWOULDBLOCK retry
    // tally (T1 ring-pushback signal per #819 §4.1). `default`
    // on each keeps the wire format additive: a pre-#825
    // helper that lacks these fields deserializes as empty/zero
    // rather than erroring.
    #[serde(rename = "tx_kick_latency_hist", default)]
    pub tx_kick_latency_hist: Vec<u64>,
    #[serde(rename = "tx_kick_latency_count", default)]
    pub tx_kick_latency_count: u64,
    #[serde(rename = "tx_kick_latency_sum_ns", default)]
    pub tx_kick_latency_sum_ns: u64,
    #[serde(rename = "tx_kick_retry_count", default)]
    pub tx_kick_retry_count: u64,
    #[serde(rename = "last_error", default)]
    pub last_error: String,
    #[serde(rename = "last_change", skip_serializing_if = "Option::is_none")]
    pub last_change: Option<DateTime<Utc>>,
}

/// #802: focused per-binding ring-pressure snapshot surfaced on
/// `ProcessStatus::per_binding`.
///
/// Fields (see `docs/line-rate-investigation-plan.md` lines 703-724 for
/// the full operator rationale):
/// - `dbg_tx_ring_full`: times the XSK TX ring producer returned 0 slots.
/// - `dbg_sendto_enobufs`: kernel-side TX drop — TX kick returned ENOBUFS.
/// - `dbg_bound_pending_overflow` (#804): drops from the per-binding
///   `bound_pending` FIFO (`pending_tx_local` / `pending_tx_prepared`)
///   overflowing its soft cap. **This does not include CoS admission
///   overflow** — those are counted separately below.
/// - `dbg_cos_queue_overflow` (#804): binding-lifetime CoS queue drops.
///   This includes class-of-service queue admission rejects
///   (`enqueue_cos_item`) and reset-time CoS queue drains. The wire key is
///   historical. Pre-#804 builds conflated this with `bound_pending`
///   overflow under the old `dbg_pending_overflow` wire key; the counter was
///   split so operators can disambiguate shaping pressure from bound-pending
///   pressure.
/// - `rx_fill_ring_empty_descs`: kernel `xdp_statistics_v2` counter of
///   RX fill-ring starvation events.
/// - `outstanding_tx`: accept-proxy for `completion_reap_max_batch` per
///   the investigation plan's disposition. Snapshot of the worker's
///   current in-flight TX gauge at the last publish tick.
/// - `tx_errors`, `tx_submit_error_drops`,
///   `pending_tx_local_overflow_drops`: operator-facing aggregate TX
///   drop attribution, re-surfaced here so the triage view does not
///   require a second join against `BindingStatus`.
///
/// ## Wire-compat
///
/// The split is not wire-compatible on the daemon→operator boundary —
/// we removed the old `dbg_pending_overflow` wire key rather than keep
/// it aliased, because the whole point of the split is to stop
/// operators reading a conflated number. On the helper→daemon boundary
/// both new fields carry `serde(default)` so a helper that pre-dates
/// this split (no fields present) deserializes as zero rather than

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct BindingCountersSnapshot {
    #[serde(rename = "worker_id")]
    pub worker_id: u32,
    // #804: explicit rename matches the other fields on this struct
    // (defensive — default serde field→key mapping is identity, but
    // making it explicit here prevents a rename of the Rust field name
    // from silently renaming the wire key and breaking the Go
    // consumer).
    #[serde(rename = "ifindex", default)]
    pub ifindex: i32,
    #[serde(rename = "queue_id")]
    pub queue_id: u32,
    #[serde(rename = "dbg_tx_ring_full", default)]
    pub dbg_tx_ring_full: u64,
    #[serde(rename = "dbg_sendto_enobufs", default)]
    pub dbg_sendto_enobufs: u64,
    // #804: split wire keys — `default` on both so a helper snapshot
    // that pre-dates the split (field absent on the wire) deserializes
    // as 0 rather than failing.
    #[serde(rename = "dbg_bound_pending_overflow", default)]
    pub dbg_bound_pending_overflow: u64,
    #[serde(rename = "dbg_cos_queue_overflow", default)]
    pub dbg_cos_queue_overflow: u64,
    #[serde(rename = "rx_fill_ring_empty_descs", default)]
    pub rx_fill_ring_empty_descs: u64,
    #[serde(rename = "outstanding_tx", default)]
    pub outstanding_tx: u32,
    /// #1241: last sampled AF_XDP TX completion-ring availability.
    #[serde(rename = "tx_completion_ring_available", default)]
    pub tx_completion_ring_available: u32,
    /// #1241: maximum sampled completion-ring availability in the last
    /// debug window.
    #[serde(rename = "tx_completion_ring_available_max", default)]
    pub tx_completion_ring_available_max: u32,
    /// #878: per-binding UMEM total frames. Mirror of BindingStatus.
    #[serde(rename = "umem_total_frames", default)]
    pub umem_total_frames: u32,
    /// #878: configured TX-ring depth. Mirror of BindingStatus.
    #[serde(rename = "tx_ring_capacity", default)]
    pub tx_ring_capacity: u32,
    /// #878: UMEM in-flight gauge. Mirror of BindingStatus.
    #[serde(rename = "umem_inflight_frames", default)]
    pub umem_inflight_frames: u32,
    #[serde(rename = "tx_errors", default)]
    pub tx_errors: u64,
    #[serde(rename = "tx_shared_recycle_unknown_slot_drops", default)]
    pub tx_shared_recycle_unknown_slot_drops: u64,
    #[serde(rename = "tx_submit_error_drops", default)]
    pub tx_submit_error_drops: u64,
    #[serde(rename = "pending_tx_local_overflow_drops", default)]
    pub pending_tx_local_overflow_drops: u64,
    #[serde(rename = "mirrored_packets", default)]
    pub mirrored_packets: u64,
    #[serde(rename = "mirrored_bytes", default)]
    pub mirrored_bytes: u64,
    #[serde(rename = "mirror_drops_no_frame", default)]
    pub mirror_drops_no_frame: u64,
    #[serde(rename = "mirror_drops_tx_frame_reserve", default)]
    pub mirror_drops_tx_frame_reserve: u64,
    #[serde(rename = "mirror_drops_no_binding", default)]
    pub mirror_drops_no_binding: u64,
    #[serde(rename = "mirror_drops_queue_full", default)]
    pub mirror_drops_queue_full: u64,
    #[serde(rename = "mirror_drops_queue_full_same_worker", default)]
    pub mirror_drops_queue_full_same_worker: u64,
    #[serde(rename = "mirror_drops_queue_full_cross_worker", default)]
    pub mirror_drops_queue_full_cross_worker: u64,
    // #812: TX submit→completion latency histogram, pulled through
    // from BindingStatus so step1-capture consumers can compute
    // per-queue latency distributions without a second join.
    // `default` keeps pre-#812 consumers parseable — the fields
    // simply deserialize as empty/zero.
    #[serde(rename = "tx_submit_latency_hist", default)]
    pub tx_submit_latency_hist: Vec<u64>,
    #[serde(rename = "tx_submit_latency_count", default)]
    pub tx_submit_latency_count: u64,
    #[serde(rename = "tx_submit_latency_sum_ns", default)]
    pub tx_submit_latency_sum_ns: u64,
    // #825: per-kick `sendto` latency telemetry, pulled through
    // from BindingStatus so step1-capture / P3 consumers can
    // compute per-queue kick-latency distributions without a
    // second join. `default` keeps pre-#825 helpers parseable —
    // the four fields simply deserialize as empty/zero.
    #[serde(rename = "tx_kick_latency_hist", default)]
    pub tx_kick_latency_hist: Vec<u64>,
    #[serde(rename = "tx_kick_latency_count", default)]
    pub tx_kick_latency_count: u64,
    #[serde(rename = "tx_kick_latency_sum_ns", default)]
    pub tx_kick_latency_sum_ns: u64,
    #[serde(rename = "tx_kick_retry_count", default)]
    pub tx_kick_retry_count: u64,
    /// #918: collision-driven subset of flow-cache evictions
    /// (full-set LRU displacement). Surfaces hot-set thrash so
    /// the post-merge acceptance gate (`collision_evictions /
    /// hits < 1 %` under 100E100M load) is observable from the
    /// standard binding-counter snapshot. `default` keeps pre-#918
    /// consumers parseable — the field simply deserializes as 0.
    #[serde(rename = "flow_cache_collision_evictions", default)]
    pub flow_cache_collision_evictions: u64,
    /// #1219: snapshot count of distinct active flows. See
    /// BindingStatus.active_flow_count for full doc.
    #[serde(rename = "active_flow_count", default)]
    pub active_flow_count: u32,
    /// Per-binding flow-cache capacity. Mirrors BindingStatus.
    #[serde(rename = "flow_cache_capacity", default)]
    pub flow_cache_capacity: u32,
    /// #941 Work item D / #943: V_min hard-cap activation count.
    /// Default keeps pre-#943 consumers parseable.
    #[serde(rename = "v_min_throttle_hard_cap_overrides", default)]
    pub v_min_throttle_hard_cap_overrides: u64,
    /// #943: regular V_min throttle decisions. Default keeps
    /// pre-#943 consumers parseable.
    #[serde(rename = "v_min_throttles", default)]
    pub v_min_throttles: u64,
    /// #hb166 T-6(a): V_min suspended-batch count. Default keeps
    /// pre-fix consumers parseable.
    #[serde(rename = "v_min_suspended_batches", default)]
    pub v_min_suspended_batches: u64,
}

// #812 (plan §3.5a / §6.1 test #8): compile-time assertion that
// `BindingCountersSnapshot` can cross the owner-worker →
// control-socket thread boundary without dragging a live borrow
// back into the per-worker sidecar. A `'static + Send` bound on a
// struct type with NO lifetime parameter is mechanically broken by
// any borrowed field added later (Rust's subtyping rule forces the
// struct to carry the reference's lifetime `'a`, and only `'a =
// 'static` satisfies the bound — which is not what a live
// per-worker snapshot would ever produce). `Send` additionally
// rejects `Rc<_>` / `Cell<_>` fields. The named const-item ties
// the failure message to this specific struct so a future
// `#[derive]` reshuffle that breaks Send/'static trips the build
// with a targeted error pointing HERE, not in some downstream
// generic.
//
// This is defense-in-depth on top of the JSON round-trip test
// (§6.1 test #4), which already mechanically requires
// DeserializeOwned.
const _ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND: () = {
    const fn require_static_send<T: 'static + Send>() {}
    require_static_send::<BindingCountersSnapshot>();
};

// #804: was `impl BindingCountersSnapshot { fn from_binding_status(...) }`.
// Switched to the idiomatic `From` impl so the projection composes with
// iterator adaptors (`.map(BindingCountersSnapshot::from)`) and any
// future `into()` callsites get the conversion for free.
impl From<&BindingStatus> for BindingCountersSnapshot {
    fn from(b: &BindingStatus) -> Self {
        Self {
            worker_id: b.worker_id,
            ifindex: b.ifindex,
            queue_id: b.queue_id,
            dbg_tx_ring_full: b.dbg_tx_ring_full,
            dbg_sendto_enobufs: b.dbg_sendto_enobufs,
            dbg_bound_pending_overflow: b.dbg_bound_pending_overflow,
            dbg_cos_queue_overflow: b.dbg_cos_queue_overflow,
            rx_fill_ring_empty_descs: b.rx_fill_ring_empty_descs,
            outstanding_tx: b.outstanding_tx,
            tx_completion_ring_available: b.tx_completion_ring_available,
            tx_completion_ring_available_max: b.tx_completion_ring_available_max,
            // #878: capacities + in-flight gauge flow into the
            // leaner snapshot so a step1-capture consumer reading
            // PerBinding (not the full BindingStatus) still sees
            // Buffer% inputs.
            umem_total_frames: b.umem_total_frames,
            tx_ring_capacity: b.tx_ring_capacity,
            umem_inflight_frames: b.umem_inflight_frames,
            tx_errors: b.tx_errors,
            tx_shared_recycle_unknown_slot_drops: b.tx_shared_recycle_unknown_slot_drops,
            tx_submit_error_drops: b.tx_submit_error_drops,
            pending_tx_local_overflow_drops: b.pending_tx_local_overflow_drops,
            mirrored_packets: b.mirrored_packets,
            mirrored_bytes: b.mirrored_bytes,
            mirror_drops_no_frame: b.mirror_drops_no_frame,
            mirror_drops_tx_frame_reserve: b.mirror_drops_tx_frame_reserve,
            mirror_drops_no_binding: b.mirror_drops_no_binding,
            mirror_drops_queue_full: b.mirror_drops_queue_full,
            mirror_drops_queue_full_same_worker: b.mirror_drops_queue_full_same_worker,
            mirror_drops_queue_full_cross_worker: b.mirror_drops_queue_full_cross_worker,
            // #812: clone the histogram Vec<u64> by value (owned
            // copy). Avoids any shared-reference aliasing against
            // the `BindingStatus` owner and satisfies the
            // `'static + Send` assert above.
            tx_submit_latency_hist: b.tx_submit_latency_hist.clone(),
            tx_submit_latency_count: b.tx_submit_latency_count,
            tx_submit_latency_sum_ns: b.tx_submit_latency_sum_ns,
            // #825: same discipline as #812 — owned clone of the
            // Vec<u64> and by-value scalars. The `'static + Send`
            // assert (_ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND
            // above this impl) covers these mechanically (no
            // borrowed fields; u64 and Vec<u64> are Send).
            tx_kick_latency_hist: b.tx_kick_latency_hist.clone(),
            tx_kick_latency_count: b.tx_kick_latency_count,
            tx_kick_latency_sum_ns: b.tx_kick_latency_sum_ns,
            tx_kick_retry_count: b.tx_kick_retry_count,
            // #918: flow under by-value u64; same Send/'static
            // discipline as the other counters.
            flow_cache_collision_evictions: b.flow_cache_collision_evictions,
            // #1219: active flow count snapshot. By-value u32.
            active_flow_count: b.active_flow_count,
            flow_cache_capacity: b.flow_cache_capacity,
            // #941 Work item D / #943: V_min counters propagate from
            // BindingDebugSnapshot through to the wire-visible
            // BindingCountersSnapshot. By-value u64, no Send concerns.
            v_min_throttle_hard_cap_overrides: b.v_min_throttle_hard_cap_overrides,
            v_min_throttles: b.v_min_throttles,
            v_min_suspended_batches: b.v_min_suspended_batches,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ExceptionStatus {
    pub timestamp: DateTime<Utc>,
    pub slot: u32,
    #[serde(rename = "queue_id")]
    pub queue_id: u32,
    #[serde(rename = "worker_id")]
    pub worker_id: u32,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub ifindex: i32,
    #[serde(rename = "ingress_ifindex", default)]
    pub ingress_ifindex: i32,
    pub reason: String,
    #[serde(rename = "packet_length", default)]
    pub packet_length: u32,
    #[serde(rename = "addr_family", default)]
    pub addr_family: u8,
    #[serde(default)]
    pub protocol: u8,
    #[serde(rename = "config_generation", default)]
    pub config_generation: u64,
    #[serde(rename = "fib_generation", default)]
    pub fib_generation: u32,
    #[serde(rename = "src_ip", default)]
    pub src_ip: String,
    #[serde(rename = "dst_ip", default)]
    pub dst_ip: String,
    #[serde(rename = "src_port", default)]
    pub src_port: u16,
    #[serde(rename = "dst_port", default)]
    pub dst_port: u16,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "to_zone", default)]
    pub to_zone: String,
    #[serde(rename = "rule_name", default)]
    pub rule_name: String,
    #[serde(rename = "pool_name", default)]
    pub pool_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionDeltaInfo {
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub slot: u32,
    #[serde(rename = "queue_id", default)]
    pub queue_id: u32,
    #[serde(rename = "worker_id", default)]
    pub worker_id: u32,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub ifindex: i32,
    #[serde(default)]
    pub event: String,
    #[serde(rename = "addr_family", default)]
    pub addr_family: u8,
    #[serde(default)]
    pub protocol: u8,
    #[serde(rename = "src_ip", default)]
    pub src_ip: String,
    #[serde(rename = "dst_ip", default)]
    pub dst_ip: String,
    #[serde(rename = "src_port", default)]
    pub src_port: u16,
    #[serde(rename = "dst_port", default)]
    pub dst_port: u16,
    #[serde(rename = "ingress_zone", default)]
    pub ingress_zone: String,
    #[serde(rename = "egress_zone", default)]
    pub egress_zone: String,
    /// #919/#922: u16 zone-id mirrors. New peers populate these from
    /// `SessionMetadata`; the legacy string fields hold the resolved
    /// zone NAME (or empty when unknown). Older daemons that don't
    /// know about the IDs ignore the new fields and use the names.
    #[serde(rename = "ingress_zone_id", default)]
    pub ingress_zone_id: u16,
    #[serde(rename = "egress_zone_id", default)]
    pub egress_zone_id: u16,
    #[serde(rename = "owner_rg_id", default)]
    pub owner_rg_id: i32,
    #[serde(default)]
    pub disposition: String,
    #[serde(default)]
    pub origin: String,
    #[serde(rename = "egress_ifindex", default)]
    pub egress_ifindex: i32,
    #[serde(rename = "tx_ifindex", default)]
    pub tx_ifindex: i32,
    #[serde(rename = "tunnel_endpoint_id", default)]
    pub tunnel_endpoint_id: u16,
    #[serde(rename = "tx_vlan_id", default)]
    pub tx_vlan_id: u16,
    #[serde(rename = "next_hop", default)]
    pub next_hop: String,
    #[serde(rename = "neighbor_mac", default)]
    pub neighbor_mac: String,
    #[serde(rename = "src_mac", default)]
    pub src_mac: String,
    #[serde(rename = "nat_src_ip", default)]
    pub nat_src_ip: String,
    #[serde(rename = "nat_dst_ip", default)]
    pub nat_dst_ip: String,
    #[serde(rename = "nat_src_port", default)]
    pub nat_src_port: u16,
    #[serde(rename = "nat_dst_port", default)]
    pub nat_dst_port: u16,
    #[serde(rename = "fabric_redirect", default)]
    pub fabric_redirect: bool,
    #[serde(rename = "fabric_ingress", default)]
    pub fabric_ingress: bool,
    /// #2785: the admitting policy's per-policy `then log` selection,
    /// mirrored from `SessionMetadata` onto the JSON RPC-fallback delta so
    /// the Go control plane can stamp the synced session's log flags. The
    /// primary HA path is the binary open frame (codec.rs flags bits
    /// 1<<3/1<<4); this keeps the JSON fallback at parity.
    #[serde(rename = "log_session_init", default)]
    pub log_session_init: bool,
    #[serde(rename = "log_session_close", default)]
    pub log_session_close: bool,
    /// #6312: the ORIGINATING node's STABLE RT_FLOW session id, mirrored from
    /// `SessionDelta.session_id` — the same value the binary open frame carries
    /// in its trailing u64 (#5212, `event_stream/codec/session_sync.rs`) — onto
    /// the JSON RPC-fallback delta. Without it a session recovered through the
    /// JSON leg (`drain_session_deltas` polling while the event stream is down,
    /// and the owner-RG resync export) imported id 0 and the peer minted a fresh
    /// local id, so its SESSION_CLOSE no longer correlated with the originating
    /// node's SESSION_CREATE.
    ///
    /// The Go consumer field already existed for the binary leg
    /// (`SessionDeltaInfo.RTFlowSessionID`, `json:"rt_flow_session_id"`); the
    /// rename below MUST match that tag. Additive and rolling-upgrade safe in
    /// both directions: an old helper omits the key and `default` decodes 0, an
    /// old daemon ignores a key it does not know, and 0 is the pre-existing
    /// "no id carried" sentinel that falls back to a fresh local id — i.e. the
    /// exact pre-#6312 behaviour of this leg.
    #[serde(rename = "rt_flow_session_id", default)]
    pub rt_flow_session_id: u64,
    /// #7239 (#7160/#2387): the session key's ROUTING DOMAIN, mirrored from the
    /// binary open frame's trailing u32 onto the JSON RPC-fallback delta so a
    /// session recovered through this leg carries the same identity.
    ///
    /// Both legs must carry it or the field means "not carried" on one of them,
    /// and 0 is a LEGAL value here (the default routing instance) rather than a
    /// sentinel — so a leg that silently omits it does not look absent, it
    /// looks like the default instance, which is a wrong answer rather than a
    /// missing one. That is the #6949 lesson on this exact struct, where the
    /// JSON leg carried none of the attribution fields the binary leg did.
    ///
    /// Additive and rolling-upgrade safe both ways: an old helper omits the key
    /// and `default` decodes 0; an old daemon ignores a key it does not know;
    /// and 0 is what every deployment with no routing-instance interface
    /// membership carries anyway.
    #[serde(rename = "routing_domain", default)]
    pub routing_domain: u32,
    /// #6949: the admitting policy's firewall metadata, at parity with the
    /// binary open frame's trailing #3301 fields. Derived with the frame's from
    /// the single-source `SessionSyncAttribution` (`session/sync_attribution.rs`).
    ///
    /// Until #6949 this struct carried NONE of the five fields below while the
    /// Go consumer (`pkg/dataplane/userspace/protocol_ha.go`, `SessionDeltaInfo`)
    /// read all of them unconditionally, so every session recovered through this
    /// leg — `drain_session_deltas` polling at 100 ms whenever the event stream
    /// is down and at 5 s while it is up, plus every helper-requested FullResync
    /// export — imported policy 0, counter 0, the global idle timeout and no
    /// NAT64 pool source. It rendered `unattributed` (a 0 id displays that way
    /// since #6851), was skipped by the commit-time deletion-clear and the #4234
    /// policy-rematch, and a later reconciliation copy could OVERWRITE an
    /// earlier, correct, event-derived copy on the peer.
    ///
    /// The renames below MUST match the Go struct tags; a mismatch is silent on
    /// both planes (the key is simply absent and serde/encoding-json leaves 0).
    /// `TestSessionDeltaPolicyAttributionWireKeysLockstepWithRust6949` pins
    /// each one against this file. Additive and rolling-upgrade safe in both
    /// directions: an old helper omits the keys and `default` decodes 0/""
    /// — precisely the pre-#6949 behaviour of this leg — and an old daemon
    /// ignores keys it does not know.
    #[serde(rename = "policy_id", default)]
    pub policy_id: u32,
    #[serde(rename = "policy_counter_idx", default)]
    pub policy_counter_idx: u32,
    /// #3227 per-application idle timeout in WHOLE SECONDS. The Go field is
    /// `AppTimeout`, so the key is `app_timeout` and NOT the
    /// `inactivity_timeout` spelling `SessionSyncRequest` uses for the same
    /// quantity on the install leg.
    #[serde(rename = "app_timeout", default)]
    pub app_timeout: u32,
    /// #4565 NAT64 cross-family marker + the translated pool SOURCE (dotted
    /// quad, "" when not NAT64). `nat64_snat_v4` is the one datum the standby
    /// cannot reconstruct from the synced forward v6 key, so without it a NAT64
    /// session promoted from this leg cannot rebuild its reverse v4->v6 BIB at
    /// all — a translation failure after failover, not a mis-attribution.
    #[serde(rename = "nat64", default)]
    pub nat64: bool,
    #[serde(rename = "nat64_snat_v4", default)]
    pub nat64_snat_v4: String,
    /// #7188: the session key's `TunnelDiscriminator`, encoded by
    /// `TunnelDiscriminator::to_wire` (`session/discriminator.rs`).
    ///
    /// GRE is protocol 47 and has no L4 ports, so two RFC 2890 tunnels between
    /// one pair of outer endpoints are one 5-tuple. The local session key
    /// separates them on this typed discriminator; without it on the wire the
    /// standby rebuilds BOTH sync records as the SAME key and the second
    /// install evicts the first (`session/install.rs` opens with an
    /// unconditional `remove_entry`) — one session for two tunnels, so after a
    /// failover they share one policy decision, one NAT state, one counter set
    /// and one timeout.
    ///
    /// `0` is RESERVED for "not carried" and is NOT the encoding of
    /// `TunnelDiscriminator::None`; see `WireDiscriminator`. That is what lets
    /// the receiver tell a peer that predates this field (withhold a protocol-47
    /// session rather than import it aliased, #7188 decision 2) from a new peer
    /// deliberately saying "this protocol has no discriminator". Additive and
    /// rolling-upgrade safe in both directions: an old helper omits the key and
    /// `default` decodes 0, an old daemon ignores a key it does not know.
    ///
    /// The rename MUST match the Go struct tag
    /// (`pkg/dataplane/userspace/protocol_ha.go`, `SessionDeltaInfo`).
    #[serde(rename = "tunnel_discriminator", default)]
    pub tunnel_discriminator: u64,
    /// #9412: the session's TCP close class (`0` = open or not carried,
    /// 1 = CLOSING, 2 = TIME_WAIT, 3 = RST). Set on open and close-state
    /// "update" deltas. Additive: an old daemon ignores the key.
    ///
    /// The rename MUST match the Go struct tag
    /// (`pkg/dataplane/userspace/protocol_ha.go`, `SessionDeltaInfo`).
    #[serde(rename = "tcp_close_class", default)]
    pub tcp_close_class: u8,
}


/// #7919: `skip_serializing_if` predicate — keeps a never-observed
/// high-water off the wire rather than emitting a 0 a reader could mistake for
/// a measurement.
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
