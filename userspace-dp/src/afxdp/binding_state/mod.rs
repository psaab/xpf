// Per-binding live runtime state: the `BindingLiveState` atomics
// cluster (ring state, forwarding/session/screen/NAT counters,
// owner/peer telemetry profiles, debug gauges, redirect TX inbox,
// HA session-delta fallback buffer). Extracted from `umem/mod.rs`
// (#6436) so `umem/` is just the memory region; see
// `binding_state/README.md` for the module contract.
//
// `BindingLiveState` is touched per-packet — this move is pure
// code-motion: no field reordering (drop order is load-bearing where
// documented), atomic orderings and `#[inline]` attributes move
// byte-identical, and the `const _: () = assert!` layout guards
// travel with their items.
//
// #1351: `WorkerTimers` is no longer referenced directly in this
// file (the debug-state cadence helpers that used it moved to
// `debug_state.rs`), but `binding_state/tests/debug_state.rs`
// references it via `use super::*;` in `debug_state_test_timers`.
// Gate the import on `cfg(test)` so production builds stay
// warning-free (per Copilot review on PR #1581).
#[cfg(test)]
use crate::afxdp::worker::WorkerTimers;

use super::*;

mod debug_state;
mod latency;
mod profile;
mod session_delta;
// #9856: dedicated per-worker owner-RG export buffer (page-sized, worker-keyed).
mod export_buffer;
pub(in crate::afxdp) use export_buffer::ExportBufferState;
// #8108: the delta-buffer high-water mark.
#[cfg(test)]
#[path = "delta_high_water_8108_tests.rs"]
mod delta_high_water_8108_tests;
// #9168: the kernel XDP-statistics publisher (`publish_kernel_xdp_statistics`).
mod kernel_stats;
#[cfg(test)]
#[path = "kernel_stats_9168_tests.rs"]
mod kernel_stats_9168_tests;
mod snapshot;
mod tx_inbox;

// #1351: telemetry-publishing free fns and the two cadence constants
// live in `debug_state.rs`. `binding_state/tests/debug_state.rs`
// references the constants (DEBUG_STATE_PUBLISH_MASK,
// IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS) and the two gate fns via
// `use super::*;`, and `crate::afxdp::binding_state::flush_v_min_scratches_into`
// is the absolute path it uses. Re-export everything at
// `pub(in crate::afxdp)` to match the existing `mmap::MmapArea` /
// `profile::Owner|Peer` precedent and to avoid E0364 (documented in
// `userspace-dp/src/afxdp/tx/mod.rs:38`).
pub(in crate::afxdp) use debug_state::{
    advance_debug_state_publish_counter, flush_v_min_scratches_into,
    idle_debug_state_publish_due, update_binding_debug_state,
    update_binding_idle_debug_state, DEBUG_STATE_PUBLISH_MASK,
    IDLE_DEBUG_STATE_PUBLISH_INTERVAL_NS,
};
pub(in crate::afxdp) use latency::{
    DRAIN_HIST_BUCKETS, TX_SIDECAR_UNSTAMPED, TX_SUBMIT_LAT_BUCKETS, bucket_index_for_ns,
};
// Only `binding_state/tests/latency_buckets.rs` consumes this
// re-export (via the `use super::*;` chain); gate on `cfg(test)` so
// production builds stay warning-free (same pattern as the
// `WorkerTimers` import at the top of this file).
#[cfg(test)]
pub(in crate::afxdp) use latency::REDIRECT_SAMPLE_MASK;
pub(in crate::afxdp) use profile::{OwnerProfileOwnerWrites, OwnerProfilePeerWrites};
pub(in crate::afxdp) use tx_inbox::{PENDING_TX_INBOX_HARD_CAP, PendingTxAdmission};
// #6304: the admission-attempt test instrument. Same `cfg(test)` treatment as
// `REDIRECT_SAMPLE_MASK` above — it has no production consumer, so gating the
// re-export keeps production builds warning-free. Consumed by
// `poll_descriptor/flow_cache_hit_tests.rs` through the absolute path
// `crate::afxdp::binding_state::pending_tx_admission_attempts`.
#[cfg(test)]
pub(in crate::afxdp) use tx_inbox::{
    pending_tx_admission_attempts, pending_tx_admission_attempts_reset,
};

/// Atomically published flow-worker diagnostic payload.
#[derive(Default)]
pub(super) struct FlowWorkerMapSnapshot {
    rows: Vec<crate::protocol::FlowWorkerStatus>,
    truncated: bool,
}

#[derive(Clone, Default)]
pub(super) struct SharedUmemLiveStatus {
    mode: String,
    group: String,
    socket_role: String,
    disabled_reason: String,
}

/// Raw ring state: (rxP, rxC, frP, frC, txP, txC, crP, crC)
pub(in crate::afxdp) struct BindingLiveState {
    pub(super) bound: AtomicBool,
    pub(super) xsk_registered: AtomicBool,
    pub(super) bind_mode: AtomicU8,
    pub(super) socket_fd: AtomicI32,
    pub(super) socket_ifindex: AtomicI32,
    pub(super) socket_queue_id: AtomicU32,
    pub(super) socket_bind_flags: AtomicU32,
    pub(super) shared_umem_status: Mutex<SharedUmemLiveStatus>,
    pub(super) rx_packets: AtomicU64,
    pub(super) rx_bytes: AtomicU64,
    pub(super) rx_batches: AtomicU64,
    pub(super) rx_wakeups: AtomicU64,
    pub(super) metadata_packets: AtomicU64,
    pub(super) metadata_errors: AtomicU64,
    pub(super) validated_packets: AtomicU64,
    pub(super) validated_bytes: AtomicU64,
    pub(super) local_delivery_packets: AtomicU64,
    pub(super) forward_candidate_packets: AtomicU64,
    /// #9956 F-051: cumulative flowless-forwarded packets/bytes (see
    /// `BatchCounters::flowless_forward_packets`). Surfaced as the `Flowless
    /// forwards` operator counter.
    pub(super) flowless_forward_packets: AtomicU64,
    pub(super) flowless_forward_bytes: AtomicU64,
    pub(super) route_miss_packets: AtomicU64,
    /// #4743: cumulative NoRoute drops whose destination is a MARTIAN address
    /// (IPv4 multicast/broadcast/unspecified/loopback, IPv6
    /// multicast/unspecified/loopback). A strict sub-breakout of
    /// `route_miss_packets` (a martian dst misses the FIB and drops as NoRoute,
    /// so it bumps BOTH) — mirrors how `screen_reason_drops` break out
    /// `screen_drops`. Lets an operator tell a martian-dst drop apart from an
    /// ordinary route miss and correlate it with the filter-`accept` log.
    /// Surfaced as the `Martian drops` operator counter.
    pub(super) martian_dropped: AtomicU64,
    /// #4743: cumulative fail-closed drops of an IPv6 packet whose
    /// extension-header chain is still on an extension header after
    /// `MAX_IPV6_EXT_HEADERS` (8) iterations (an over-limit, uninspectable
    /// chain). The #2292 walkers already fail closed (`None`) on this chain;
    /// before #4743 the flowless path forwarded it uninspectable
    /// (`l4_present = false`), an ext-header IDS-evasion. Now dropped explicitly
    /// and counted. Distinct from a TRUNCATED chain (which stays flowless).
    /// Surfaced as the `IPv6 ext-header drops` operator counter.
    pub(super) ipv6_ext_header_dropped: AtomicU64,
    pub(super) neighbor_miss_packets: AtomicU64,
    pub(super) discard_route_packets: AtomicU64,
    pub(super) next_table_packets: AtomicU64,
    pub(super) table_unavailable_packets: AtomicU64,
    pub(super) exception_packets: AtomicU64,
    pub(super) config_gen_mismatches: AtomicU64,
    pub(super) fib_gen_mismatches: AtomicU64,
    pub(super) unsupported_packets: AtomicU64,
    pub(super) flow_cache_hits: AtomicU64,
    pub(super) flow_cache_misses: AtomicU64,
    pub(super) flow_cache_evictions: AtomicU64,
    /// #918: subset of `flow_cache_evictions` driven by full-set LRU
    /// displacement (i.e. an insert kicked out a different-key entry
    /// from the LRU way). Surfaces hot-set thrash distinctly from
    /// stale-on-lookup evictions so the acceptance gate
    /// (`collision_evictions / hits < 1 %`) is observable at runtime.
    pub(super) flow_cache_collision_evictions: AtomicU64,
    /// #1219: snapshot of distinct active flows on this binding's
    /// flow_cache, refreshed at the existing ~65ms debug-state tick
    /// (`update_binding_debug_state`) by counting flow_cache entries
    /// hit within the last 10 epoch ticks (~650 ms window). Read
    /// from the helper-process status JSON; harness scrapes via
    /// Prometheus to compute `{a_i}` for the structural CoV gate
    /// per `docs/fairness-regimes.md`.
    pub(super) active_flow_count: AtomicU32,
    /// Per-binding flow-cache capacity. The value is Rust-owned and
    /// published so Go never has to duplicate FLOW_CACHE_SIZE.
    pub(super) flow_cache_capacity: AtomicU32,
    /// #1249: bounded active flow-cache rows published by the owning
    /// worker on the same debug cadence as `active_flow_count`. Stored
    /// as an owned ArcSwap snapshot so the control thread can aggregate
    /// tuple->worker mappings without taking a worker-local lock.
    pub(super) flow_worker_map: ArcSwap<FlowWorkerMapSnapshot>,
    /// #1248: bounded per-binding active-flow counts by egress CoS
    /// `(ifindex, queue_id)`, published by the owning worker on the
    /// debug cadence and later aggregated by coordinator status.
    pub(super) cos_active_flow_counts: ArcSwap<Vec<crate::protocol::CoSActiveFlowCountStatus>>,
    /// #941 Work item D: count of hard-cap activations. When V_min
    /// throttle would have fired for V_MIN_CONSECUTIVE_SKIP_HARD_CAP
    /// consecutive batches, hard-cap force-continues AND arms
    /// suspension. Each such activation increments this counter.
    /// Acceptance gate: under normal load (e.g. iperf-c P=12 saturating),
    /// per-binding hard-cap-override-rate = this / drain_invocations
    /// stays below 5 %. Counter is flushed from each queue's per-queue
    /// scratch field (`v_min_hard_cap_overrides_scratch`) in
    /// `update_binding_debug_state` (mirrors flow_cache_collision_evictions
    /// flush pattern).
    pub(super) v_min_throttle_hard_cap_overrides: AtomicU64,
    /// #943: count of V_min throttle decisions
    /// (`cos_queue_v_min_continue` returned `false` and the caller
    /// took the early-break path, exiting the drain loop). Distinct
    /// from `v_min_throttle_hard_cap_overrides` which only counts
    /// the hard-cap escape-hatch firings introduced by #941.
    /// Acceptance gate: `v_min_throttles` non-zero under load when
    /// V_min sync is active confirms the fairness brake is engaged;
    /// `v_min_throttle_hard_cap_overrides / v_min_throttles` ratio
    /// is the diagnostic for whether LAG_THRESHOLD is too tight.
    /// Flushed from each queue's `v_min_throttles_scratch` in
    /// `update_binding_debug_state` (mirrors flow_cache_collision_evictions).
    pub(super) v_min_throttles: AtomicU64,
    /// #hb166 T-6(a): count of V_min *suspended* drain batches — batches
    /// where the fairness brake was OFF because a prior hard-cap armed
    /// suspension. Flushed from each queue's
    /// `v_min_suspended_batches_scratch` in `update_binding_debug_state`.
    /// `v_min_suspended_batches / v_min_throttle_hard_cap_overrides` is
    /// the effective suspension-window-length diagnostic; a large ratio
    /// means the brake spends most of its time suppressed.
    pub(super) v_min_suspended_batches: AtomicU64,
    pub(super) session_hits: AtomicU64,
    pub(super) session_misses: AtomicU64,
    pub(super) session_creates: AtomicU64,
    pub(super) session_expires: AtomicU64,
    pub(super) session_delta_generated: AtomicU64,
    pub(super) session_delta_dropped: AtomicU64,
    /// #8108: the greatest depth `pending_session_deltas` has reached.
    ///
    /// Monotonic within a process, and a HIGH-WATER mark rather than a depth
    /// gauge because the buffer drains: a depth sampled at 1 Hz sees a
    /// revocation burst only if the sample lands inside it, and otherwise
    /// reports a comfortable number for exactly the event being measured.
    ///
    /// Paired with `session_delta_dropped` it separates three states the
    /// existing signals cannot: comfortable (high water well under the cap),
    /// surviving on luck (high water near the cap, dropped == 0), and lossy
    /// (dropped > 0). Before this only the third was observable, and only as
    /// a boolean.
    pub(super) session_delta_high_water: AtomicU64,
    pub(super) session_delta_drained: AtomicU64,
    pub(super) policy_denied_packets: AtomicU64,
    /// #3326: host-bound (LocalDelivery) packets dropped by the zone
    /// host-inbound admission gate (`host_inbound_admits` => false). These
    /// denies bypass the `policy_denied_packets` disposition path, so before
    /// #3326 a configured host-inbound restriction dropped traffic that no
    /// counter reflected. Mirrored into `GlobalCtrHostInboundDeny` (Go side).
    pub(super) host_inbound_denied_packets: AtomicU64,
    pub(super) screen_drops: AtomicU64,
    /// #3343: per-screen-reason DROP counters, indexed by
    /// `screen::screen_reason_drop_index`. Snapshotted into
    /// `BindingLiveSnapshot.screen_reason_drops` and surfaced on the wire as
    /// `BindingStatus.screen_reason_drops`, where the Go control plane pushes
    /// each ordinal into its `GlobalCtrScreen*` global counter so the
    /// per-reason screen-statistics rows stop reading a permanent 0.
    pub(super) screen_reason_drops: [AtomicU64; crate::screen::SCREEN_REASON_DROP_COUNT],
    /// #1374: SYN-cookie challenge decisions selected by the screen runtime.
    pub(super) syn_cookie_challenges: AtomicU64,
    /// #1374: SYN-cookie mode crossed the threshold but no HA-safe master key
    /// was published, so the runtime failed closed instead of minting a
    /// local-only cookie.
    pub(super) syn_cookie_secret_unavailable: AtomicU64,
    /// #1374: SYN-cookie SYN-ACK replies admitted to bounded userspace TX.
    pub(super) syn_cookie_syn_ack_sent: AtomicU64,
    /// #1374: RST replies emitted after a valid cookie ACK is consumed.
    pub(super) syn_cookie_ack_rst_sent: AtomicU64,
    /// #1374: SYN-cookie replies dropped to preserve the reserved TX budget.
    pub(super) syn_cookie_reply_budget_drops: AtomicU64,
    /// #1374: session-miss ACKs with a valid cookie accepted by the runtime.
    pub(super) syn_cookie_ack_valid: AtomicU64,
    /// #1374: session-miss ACKs rejected while SYN-cookie mode was active.
    pub(super) syn_cookie_ack_invalid: AtomicU64,
    /// #1374: retransmitted SYNs admitted by the single-use validated-client
    /// cache after a valid cookie ACK.
    pub(super) syn_cookie_bypass: AtomicU64,
    /// #2089: policy-`reject` RST/ICMP-unreachable replies enqueued.
    pub(super) policy_reject_sent: AtomicU64,
    /// #2521: firewall-filter `then reject` RST/ICMP-unreachable replies
    /// enqueued. Mirrors `policy_reject_sent`; the suppression legs
    /// (budget / output-filter / parse-error) are shared with policy reject.
    pub(super) filter_reject_sent: AtomicU64,
    /// #2089: POLICY-`reject` replies suppressed due to TX-frame budget
    /// exhaustion (the packet is still dropped — fail-closed). #3615 (L04):
    /// filter-source suppression is now `filter_reject_reply_budget_drops`.
    pub(super) policy_reject_reply_budget_drops: AtomicU64,
    /// #3615 (L04): FILTER-`reject` replies suppressed by TX-frame budget —
    /// the source-split sibling of `policy_reject_reply_budget_drops`.
    pub(super) filter_reject_reply_budget_drops: AtomicU64,
    /// #3661: POLICY-`reject` replies dropped because the shared per-reason
    /// REJECT_BUCKET rate-limit bucket was empty. Source-split of the
    /// source-neutral aggregate `reject_rate_limited_total`; filter-source
    /// drops are in `filter_reject_rate_limit_drops`.
    pub(super) policy_reject_rate_limit_drops: AtomicU64,
    /// #3661: FILTER-`reject` replies dropped by the rate-limit bucket — the
    /// source-split sibling of `policy_reject_rate_limit_drops`.
    pub(super) filter_reject_rate_limit_drops: AtomicU64,
    /// #2238: locally-generated replies dropped by an OUTPUT firewall filter
    /// terminal `discard`/`reject` (or three-color policer) on the egress
    /// interface, now that the reply is classified by its OWN egress tuple.
    /// Per-leg so an operator-installed output filter that suppresses a
    /// generated control frame is attributable.
    pub(super) time_exceeded_output_filter_drops: AtomicU64,
    /// #2238/#3615 (L05): POLICY-`reject` replies dropped by an egress output
    /// filter. Filter-source suppression is in
    /// `filter_reject_output_filter_drops`.
    pub(super) policy_reject_output_filter_drops: AtomicU64,
    /// #3615 (L05): FILTER-`reject` replies dropped by an egress output filter
    /// — the source-split sibling of `policy_reject_output_filter_drops`.
    pub(super) filter_reject_output_filter_drops: AtomicU64,
    pub(super) syn_cookie_output_filter_drops: AtomicU64,
    /// #2328: egress-MTU PTB / Frag-Needed (the #2301 PMTUD generator)
    /// dropped by an OUTPUT firewall filter terminal `discard`/`reject` (or
    /// three-color policer) on the egress interface, now that the PTB is
    /// classified by its OWN egress tuple. Per-leg, sibling of the three
    /// generator counters above.
    pub(super) ptb_output_filter_drops: AtomicU64,
    /// #2238: fail-CLOSED drops — a generated reply's own bytes could not be
    /// re-parsed for output classification (§6.2). A builder/parser logic
    /// bug; a non-zero value is never silent (the reply is dropped, not
    /// leaked past the egress filter).
    pub(super) generated_reply_classify_parse_errors: AtomicU64,
    pub(super) snat_packets: AtomicU64,
    pub(super) dnat_packets: AtomicU64,
    /// #2161: cumulative NAT64 (v6<->v4) translations on this binding,
    /// surfaced as the `NAT64 translations` operator counter.
    pub(super) nat64_translations: AtomicU64,
    /// #2291: cumulative fail-closed NAT64 drops — a NAT64 prefix matched but
    /// no IPv4 source could be allocated (empty/exhausted pool). Surfaced as
    /// the `NAT64 no-source-pool drops` operator counter; a non-zero value
    /// flags a misconfigured/exhausted source pool that would otherwise have
    /// leaked the synthetic IPv6 destination upstream (the pre-fix fail-open).
    /// #4520: now scoped to the config/empty/missing pool case only; transient
    /// port exhaustion is counted by `nat64_pool_exhausted`.
    pub(super) nat64_no_source_pool: AtomicU64,
    /// #4520: cumulative transient NAT64 pool-exhaustion drops — a prefix
    /// matched and its pool was non-empty, but no free translated port could
    /// be allocated (`AllocatorExhausted`). Surfaced as the `NAT64
    /// pool-exhausted drops` operator counter; a non-zero value flags a pool
    /// too small for the offered load (add capacity), distinct from the
    /// config/empty case in `nat64_no_source_pool` (fix config).
    pub(super) nat64_pool_exhausted: AtomicU64,
    /// #2562: cumulative fail-closed NAT64 fragment drops — a datagram dropped
    /// because it is a fragment NAT64 cannot safely translate (a non-first
    /// fragment, or a real ICMP/ICMPv6 fragment whose checksum covers the whole
    /// datagram). Surfaced as the `NAT64 fragment drops` operator counter. The
    /// stateful frag-association cache (#3291 stage 4) that would let real
    /// fragments traverse end-to-end is deferred, so this is the observable-drop
    /// half of #2562.
    pub(super) nat64_frag_dropped: AtomicU64,
    /// #7054: first-fragment installs that evicted a still-LIVE association.
    pub(super) nat64_frag_assoc_evicted: AtomicU64,
    /// #5623: cumulative fail-closed NAT64 SOURCE-ineligibility drops — an
    /// incoming IPv6 packet whose SOURCE lies within a configured Pref64 (a
    /// looping/synthesized "already-translated" source, the RFC 6146 §5 hairpin
    /// construction — plus the lower/upper Pref64 boundary and any embedded
    /// non-global v4) dropped BEFORE route lookup, policy, or `allocate_source`
    /// per RFC 6146 §3.5. Surfaced as the `NAT64 ineligible-source drops`
    /// operator counter; a non-zero value flags spoofed/looping v6 sources.
    /// Distinct from the pool counters (config/capacity on an ELIGIBLE flow) —
    /// this is an input-validation reject.
    pub(super) nat64_ineligible_source: AtomicU64,
    /// #6475: cumulative fail-closed NAT64 DESTINATION-ineligibility drops — an
    /// incoming IPv6 packet whose NAT64-prefix-matched destination embeds a
    /// non-global IPv4 per RFC 6052 §3.1 (0.0.0.0/8, 127.0.0.0/8,
    /// 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 — e.g. `64:ff9b::127.0.0.1`,
    /// which would otherwise resolve LocalDelivery to the localhost-only
    /// control plane once lo0 lands in `state.local_v4`) dropped BEFORE route
    /// lookup, policy, or `allocate_source`. Surfaced as the `NAT64
    /// ineligible-destination drops` operator counter; a non-zero value flags
    /// non-global-embedded destinations aimed at a NAT64 prefix. Distinct from
    /// the source/pool counters — this is a destination input-validation reject.
    pub(super) nat64_ineligible_dest: AtomicU64,
    /// #5625: cumulative fail-closed NAT64 EXTENSION-HEADER ineligibility drops
    /// — a v6→v4 forward translation rejected because the IPv6 packet carried an
    /// Authentication Header (51), an ACTIVE Routing header (43, Segments
    /// Left > 0), or a Mobility (135) / HIP (139) / Shim6 (140) header, none of
    /// which a stateless NAT64 translation can carry to IPv4 (RFC 7915 §5.1 /
    /// §5.1.1). Surfaced as the `NAT64 ext-header ineligible drops` operator
    /// counter; a non-zero value flags AH-protected or active-extension traffic
    /// aimed at a NAT64 prefix. Distinct from the source/pool/fragment counters.
    pub(super) nat64_exthdr_ineligible: AtomicU64,
    /// #8890: cumulative fail-closed NAT64 TUNNEL-ENCAPSULATION drops — a
    /// NAT64-translated packet whose route resolved through a GRE or
    /// WireGuard endpoint. `build_nat64_forwarded_frame` performs no
    /// encapsulation and the TX copy path selects it exclusively on
    /// `is_nat64`, so before #8890 the inner packet was emitted on the
    /// physical NIC as PLAINTEXT (measured byte-identical to the no-tunnel
    /// control). It is now dropped instead, matching the #1873 R-E posture
    /// for the unresolved-neighbour route. Surfaced as the `NAT64 tunnel
    /// encap unsupported drops` operator counter; a non-zero value means a
    /// NAT64 + tunnel route combination is configured and is NOT being
    /// forwarded — an unsupported-configuration signal, not a capacity one.
    ///
    /// Two caveats an operator reading this counter needs. It is an
    /// AVAILABILITY REGRESSION relative to pre-#8890 for a deployment whose
    /// underlay path to the IPv4 destination works regardless of the
    /// configured tunnel: that traffic was flowing (as plaintext) and now
    /// stops. And because the gate runs before the translator, a frame that is
    /// ALSO ext-header-ineligible (#5625) or an unassociated fragment (#2562)
    /// is counted here, so a drop on this counter is not a promise that tunnel
    /// support alone (#8896) would make the packet forwardable.
    pub(super) nat64_tunnel_encap_unsupported: AtomicU64,
    /// #8670: cumulative fail-closed NAT64 PROTOCOL-ineligibility drops — a
    /// packet addressed to a Pref64 destination whose IP protocol stateful
    /// NAT64 does not translate (RFC 6146 covers TCP, UDP and ICMP only), so it
    /// arrives flowless and is refused at the Pref64-destination gate.
    /// Surfaced as the `NAT64 ineligible-protocol drops` operator counter; a
    /// non-zero value flags tunnel traffic (ESP, GRE, IPIP) or a routing
    /// protocol aimed at a NAT64 prefix, which is an architectural mismatch
    /// rather than a fragmentation or capacity problem. Distinct from the
    /// fragment counter (a real fragment) and the ext-header counter.
    pub(super) nat64_ineligible_protocol: AtomicU64,
    /// #4477: cumulative source-NAT allocation failures (rule matched, no
    /// translated mapping could be allocated — missing/empty/invalid/exhausted
    /// pool, wrong family, or a non-first fragment on a port-translating rule).
    /// The packet is dropped. Bridged into `GlobalCtrNATAllocFail` (Go side) so
    /// the `NAT allocation failures` operator counter is no longer a dead 0.
    pub(super) nat_alloc_fail: AtomicU64,
    /// #6122: cumulative fail-closed drops of an ordinary same-family NAT'd
    /// (SNAT / static-NAT / DNAT / NPTv6) NON-FIRST fragment that MISSED the
    /// fragment-association cache. Forwarding it untranslated would leak the
    /// internal source (SNAT / NPTv6) or the pre-NAT destination (DNAT), so the
    /// permitted-but-untranslatable fragment is dropped fail-closed instead.
    /// Surfaced as the `NAT frag untranslated drops` operator counter; the
    /// same-family sibling of `nat64_frag_dropped`. A plain (no-NAT) fragment
    /// matches no rule and is NOT counted here — ordinary fragmented forwarding
    /// is preserved.
    pub(super) nat_frag_untranslated_dropped: AtomicU64,
    pub(super) slow_path_packets: AtomicU64,
    pub(super) slow_path_bytes: AtomicU64,
    pub(super) slow_path_local_delivery_packets: AtomicU64,
    pub(super) slow_path_missing_neighbor_packets: AtomicU64,
    pub(super) slow_path_no_route_packets: AtomicU64,
    pub(super) slow_path_next_table_packets: AtomicU64,
    pub(super) slow_path_forward_build_packets: AtomicU64,
    pub(super) slow_path_drops: AtomicU64,
    pub(super) slow_path_rate_limited: AtomicU64,
    /// #1873 R-C: tunnel-marked inner packets dropped at the slow-path
    /// chokepoint instead of being reinjected to the kernel TUN
    /// unencapsulated (the pre-#1873 plaintext-leak fallback). Also
    /// bumped by the R-E pending-neigh tunnel exclusion.
    pub(in crate::afxdp) tunnel_encap_unresolved_drops: AtomicU64,
    /// #1946: FabricRedirect frames dropped fail-closed because they
    /// could not be TX'd to the HA peer over the fabric link — either the
    /// fabric parent had no XSK binding (bind not ready / `bind()` failed)
    /// or the forward-frame build/enqueue failed. A FabricRedirect is a
    /// cross-chassis L2 redirect for the peer's pipeline, never a
    /// kernel-FIB-routable packet, so it is dropped rather than reinjected
    /// to the local kernel slow path (a wrong-path / conntrack-poison
    /// hazard; cf. the #1873 R-C `tunnel_encap_unresolved_drops` gate).
    pub(in crate::afxdp) fabric_redirect_unsendable_drops: AtomicU64,
    /// #6664: `NextTableUnsupported` frames refused by the slow-path
    /// allow-list and dropped fail-closed.
    ///
    /// This counter EXISTS BECAUSE the deny silences another one. Before
    /// #6664 the disposition was slow-path eligible, so every such packet
    /// bumped `slow_path_next_table_packets` on the accept path
    /// (`record_slow_path_accept`) and that counter is exported all the way
    /// to `xpf_userspace_binding_slow_path_next_table_packets_total`.
    /// Refusing the reinject without adding this would have driven that
    /// metric to a permanent zero -- indistinguishable, to an operator,
    /// from "no such packets ever arrived". The drop is counted here
    /// instead, so the signal moves rather than disappears.
    pub(in crate::afxdp) next_table_unsupported_drops: AtomicU64,
    /// #9752: `TableUnavailable` frames refused by the slow-path allow-list
    /// and dropped fail-closed (the #6664 shape: counted where refused).
    pub(in crate::afxdp) table_unavailable_drops: AtomicU64,
    pub(super) kernel_rx_dropped: AtomicU64,
    pub(super) kernel_rx_invalid_descs: AtomicU64,
    pub(super) tx_packets: AtomicU64,
    pub(super) tx_bytes: AtomicU64,
    pub(super) tx_completions: AtomicU64,
    pub(super) tx_errors: AtomicU64,
    /// #1307: subset of `tx_errors` for shared-UMEM recycle drops whose
    /// target slot no longer maps to a live binding.
    pub(super) tx_shared_recycle_unknown_slot_drops: AtomicU64,
    /// F-149 (#9904): subset of `tx_errors` for shared-UMEM recycles whose
    /// target slot is unknown but whose offset was preserved via the
    /// same-region backstop (single-region workers only) instead of lost.
    /// `tx_errors == drops + rescued` for unknown slots.
    pub(super) tx_shared_recycle_unknown_slot_rescued: AtomicU64,
    /// #710: counts packets that hit the redirect-inbox overflow path
    /// in `enqueue_tx` / `enqueue_tx_owned`. Multi-writer (every
    /// redirecting worker writes; the owner reads). Atomic because
    /// cross-thread. A non-zero value indicates the owner worker is
    /// not draining redirects fast enough — see #706 (mutex
    /// contention) and #709 (owner-worker hotspot).
    pub(super) redirect_inbox_overflow_drops: AtomicU64,
    /// #710: counts packets dropped from `pending_tx_local` /
    /// `pending_tx_prepared` when those bounded FIFOs overflow their
    /// `max_pending_tx` cap. Single-writer per binding (the worker
    /// that owns this binding), but exposed via atomic for cross-
    /// thread readers (status snapshotter). Indicates the worker is
    /// receiving redirected-in traffic faster than it can ingest into
    /// its CoS queues — upstream contributing cause is usually
    /// #706 / #709 (owner worker not keeping up) or #707 / #708
    /// (CoS enqueue throttled by buffer/admission caps).
    pub(super) pending_tx_local_overflow_drops: AtomicU64,
    /// #710: packets dropped at the TX submit path with a
    /// frame-level error (capacity exceeded, slice out of range, or
    /// other `TxError::Drop` from `transmit_batch` / transmit_prepared
    /// paths). Distinct from admission and redirect-inbox drops; a
    /// non-zero value usually indicates a frame-building bug upstream
    /// or a legitimate oversize packet. Subset of `tx_errors`.
    pub(super) tx_submit_error_drops: AtomicU64,
    /// #1376: ingress mirror clone packets successfully admitted to a
    /// mirror output binding. Written by the ingress binding's worker.
    pub(super) mirrored_packets: AtomicU64,
    /// #1376: full L2 bytes copied into admitted mirror clones.
    pub(super) mirrored_bytes: AtomicU64,
    /// #1376: mirror clone dropped for frame-unavailable outcomes:
    /// oversized packet (`len > tx_frame_capacity()`) or UMEM slice
    /// failure while cloning.
    pub(super) mirror_drops_no_frame: AtomicU64,
    /// #1376: mirror clone dropped specifically to preserve the
    /// output binding's owner-local TX-frame reserve. Split from
    /// `mirror_drops_no_frame` so operators can distinguish an
    /// oversize/slice failure from pressure that would starve normal TX.
    pub(super) mirror_drops_tx_frame_reserve: AtomicU64,
    /// #1376: mirror clone dropped because no live mirror target
    /// binding was available for the resolved output TX ifindex.
    pub(super) mirror_drops_no_binding: AtomicU64,
    /// #1376: mirror clone dropped because the output binding already
    /// had mirror/primary TX backlog. Mirrors are lossy under pressure.
    pub(super) mirror_drops_queue_full: AtomicU64,
    /// #1376: same-worker mirror queue-full drops. Split from
    /// cross-worker live-inbox drops so operators can localize mirror
    /// pressure to the ingress/owner worker boundary.
    pub(super) mirror_drops_queue_full_same_worker: AtomicU64,
    /// #1376: cross-worker mirror queue-full drops at the target live
    /// inbox/admission boundary.
    pub(super) mirror_drops_queue_full_cross_worker: AtomicU64,
    /// #710: packets dropped in `apply_worker_shaped_tx_requests`
    /// because the worker could not locate any binding for the
    /// request's egress_ifindex. Happens when a cross-worker CoS
    /// redirect lands on a worker whose bound interfaces do not
    /// include the target. Typically reveals a binding-registration
    /// race during config reload or helper restart. Subset of
    /// `tx_errors`.
    pub(super) no_owner_binding_drops: AtomicU64,
    /// #1782: per-binding count of neg-neigh-cache fast-fails. Promotes
    /// the debug-only `dbg.neg_neigh_fast_fail` counter into a real
    /// atomic surfaced via `Coordinator::neg_neigh_fast_fail_total()`
    /// (Prometheus `xpf_userspace_neg_neigh_fast_fail_total`). Capture
    /// instrumentation only: the increment is one Relaxed fetch_add on
    /// the existing fast-fail discard path, no new hot-path work. Lets
    /// the cold-start capture separate H1 (neg lockout) from H5 (sibling
    /// pending-drop) per worker.
    pub(super) neg_neigh_fast_fail: AtomicU64,
    /// #1782: per-binding count of `pending_neigh` sibling drops caused
    /// SPECIFICALLY by the key already being pending (`contains_key`
    /// true) — NOT the co-located `len >= MAX_PENDING_NEIGH` capacity
    /// drop. The first MissingNeighbor packet for a `(egress_ifindex,
    /// next_hop)` is buffered and drives the kernel probe; later
    /// same-key siblings in the same idle window are recycled here. This
    /// counter measures the H5 sibling-drop volume so it is separable
    /// from H1 and from RSS fan-out. Surfaced via
    /// `Coordinator::pending_neigh_duplicate_drops_total()` (Prometheus
    /// `xpf_userspace_pending_neigh_duplicate_drops_total`).
    pub(super) pending_neigh_duplicate_drops: AtomicU64,
    /// #1902: per-binding count of GRE-decapped MissingNeighbor packets
    /// REFUSED pending_neigh admission. A decapped packet's `desc`
    /// references the un-decapped OUTER UMEM frame while `meta`/decision
    /// describe the synthetic INNER frame, so the retry path's in-place
    /// rewrite+TX would transmit a mis-rewritten outer packet. Refused
    /// candidates are recycled; the trailing decap-aware slow-path
    /// chokepoint (#1901) still delivers the inner packet to the kernel.
    /// Counted only when the packet would otherwise have been an
    /// admission candidate (non-tunnel decision with a next_hop, seed
    /// not refused). Surfaced via
    /// `Coordinator::pending_neigh_decap_drops_total()` (Prometheus
    /// `xpf_userspace_pending_neigh_decap_drops_total`).
    pub(super) pending_neigh_decap_drops: AtomicU64,
    /// #7156: pending-neigh keys VISITED by the retry sweep, cumulative.
    ///
    /// The budget-exhaustion / backlog signal. The sweep used to visit every
    /// unresolved key on every poll, so this would have tracked
    /// `pending_neigh.len()` x polls; it now tracks actual serviced work, and
    /// the gap between it and the queue depth gauge is the backlog.
    ///
    /// Also the only way to observe that a sweep with nothing due did NO
    /// per-key work: that state is defined by the ABSENCE of side effects, so
    /// removals and recycles cannot distinguish "visited every key and found
    /// nothing to do" from "visited nothing".
    pub(super) pending_neigh_visits: AtomicU64,
    /// #2375: per-binding count of `pending_neigh` admissions REFUSED
    /// because the map already holds `MAX_PENDING_NEIGH` distinct
    /// unresolved `(egress_ifindex, next_hop)` hops — the capacity-drop
    /// case (a NEW distinct hop the worker cannot accept). Distinct from
    /// `pending_neigh_duplicate_drops` (the key was already pending —
    /// normal cold-start coalescing): a rising capacity counter means
    /// the worker is refusing NEW unresolved destinations (distinct-hop
    /// neighbor exhaustion / possible scan or upstream outage). The
    /// refused packet is recycled exactly like the duplicate case.
    /// Surfaced via `Coordinator::pending_neigh_capacity_drops_total()`
    /// (Prometheus `xpf_userspace_pending_neigh_capacity_drops_total`).
    pub(super) pending_neigh_capacity_drops: AtomicU64,
    /// #1771 §2.6: distinct unresolved `(egress_ifindex, next_hop)` keys
    /// currently buffered in this binding's `pending_neigh` map (gauge —
    /// post-#1779 §2.2 the map holds at most ONE representative packet
    /// per key, so `len()` == distinct pending next-hops). Published
    /// from the owning worker's ~65ms debug-state tick
    /// (`publish_binding_debug_state`), summed across bindings by
    /// `Coordinator::neighbor_pending_keys_total()` (Prometheus
    /// `xpf_userspace_neighbor_pending_keys`).
    pub(super) pending_neigh_keys: AtomicU64,
    /// #1771 §2.6: keys currently held in this binding's negative
    /// neighbor cache (gauge). Lazy-TTL caveat: `neg_neigh_active`
    /// evicts expired entries only on access, so an idle expired key
    /// stays counted until its next packet (or a cap-overflow clear) —
    /// the gauge is an upper bound on ACTIVE negative entries. Same
    /// publish cadence/path as `pending_neigh_keys`; summed by
    /// `Coordinator::neg_neigh_keys_total()` (Prometheus
    /// `xpf_userspace_neg_neigh_keys`).
    pub(super) neg_neigh_keys: AtomicU64,
    /// #1789: per-binding count of failed USERSPACE_SESSIONS BPF-map
    /// publishes (`publish_live_session_entry` /
    /// `publish_live_session_key` returning `Err`) on the worker poll
    /// paths that previously discarded the result with `let _ =`. A
    /// failed publish means the XDP shim never learns the session key
    /// and takes the NO_SESSION degraded path (drop in STRICT mode), so
    /// this is the cause-side signal for rising shim no-session
    /// fallbacks (map at capacity, stale fd after reconcile). One
    /// Relaxed fetch_add on the existing (rare) error branch — no new
    /// hot-path work. Call sites without a binding context (HA upsert,
    /// session-glue worker publish, replay, prewarm) bump the shared
    /// `SESSION_PUBLISH_ERRORS_SHARED` static instead; both are summed
    /// by `Coordinator::session_publish_errors_total()` (Prometheus
    /// `xpf_userspace_session_publish_errors_total`).
    pub(super) session_publish_errors: AtomicU64,
    /// #4800: per-binding count of LOCALLY-LEARNED transit forward flows
    /// installed on the worker poll path — the exact population that runs
    /// SNAT allocate -> `publish_shared_session` -> `replicate_session_upsert`.
    ///
    /// Summed per worker onto `WorkerRuntimeStatus.new_flow_installs`, so a
    /// connection-rate run can SEE a single-core bound as skew across the
    /// six mlx5 RX queues instead of inferring it. Counting reverse
    /// companions, peer-synced imports, promotes or local-delivery caches
    /// here would make the per-worker figures incomparable to the offered
    /// connection rate, so none of those bump it. One Relaxed fetch_add on
    /// a branch that already does a BPF map update and three mutex
    /// acquisitions.
    pub(super) new_flow_installs: AtomicU64,
    /// #2244: per-binding count of failed `dnat_table` BPF-map publishes
    /// (`publish_dnat_table_entry` `bpf_map_update_elem` returning < 0)
    /// on the worker poll paths that previously discarded the syscall
    /// result entirely. The `dnat_table` is the reverse-SNAT lookup the
    /// embedded-ICMP NAT path consults to reverse-NAT an inbound ICMP
    /// error (Time Exceeded / Packet Too Big for PMTUD, traceroute) back
    /// to the original pre-NAT source. A failed publish silently omits
    /// the reverse record, so the matching ICMP error is dropped or
    /// mis-delivered with no operator-visible signal. One Relaxed
    /// fetch_add on the existing (rare) error branch — no new hot-path
    /// work on success. Summed by `Coordinator::dnat_publish_errors_total()`
    /// (Prometheus `xpf_userspace_dnat_publish_errors_total`).
    pub(super) dnat_publish_errors: AtomicU64,
    /// #709 / #746: owner-written telemetry, cacheline-isolated.
    /// `drain_latency_hist` buckets sum to `drain_invocations` (pinned
    /// in unit tests); `drain_noop_invocations` is a subset counter
    /// (drains that returned `false`). `owner_pps` is the owner-local
    /// pps window.
    ///
    /// Written only by the owner worker (the sole caller of
    /// `drain_shaped_tx` on this binding); read by the snapshot path
    /// and by Prometheus scrape. Owner-only write + Relaxed load/store
    /// is sufficient: the snapshot reader tolerates monotonic counter
    /// tearing across a bucket array, and Prometheus semantics are
    /// "best effort at scrape time".
    pub(super) owner_profile_owner: OwnerProfileOwnerWrites,
    /// #709 / #746: peer-written telemetry, cacheline-isolated.
    /// `redirect_acquire_hist` is the redirect-acquire latency
    /// histogram, sampled 1-in-(`REDIRECT_SAMPLE_MASK`+1) on
    /// producers. `peer_pps` is the peer-redirect pps window.
    ///
    /// #5160: the sample SEQUENCE that decides which push is the 1-in-256
    /// sampled op is a producer-local thread-local (`REDIRECT_SAMPLE_SEQ`),
    /// NOT an atomic on this shared struct — so the many-producer redirect
    /// hot path pays no second contended RMW per enqueue. Only the sampled
    /// op writes `redirect_acquire_hist` here.
    ///
    /// Multi-writer: every worker that redirects a TX request into
    /// this binding's inbox increments a bucket on a sampled push.
    /// The owner reads via `snapshot()`.
    pub(super) owner_profile_peer: OwnerProfilePeerWrites,
    pub(super) direct_tx_packets: AtomicU64,
    pub(super) copy_tx_packets: AtomicU64,
    pub(super) in_place_tx_packets: AtomicU64,
    pub(super) in_place_vlan_push_desc_packets: AtomicU64,
    pub(super) in_place_vlan_pop_desc_packets: AtomicU64,
    pub(super) in_place_vlan_push_no_headroom_packets: AtomicU64,
    pub(super) in_place_l2_memmove_fallback_packets: AtomicU64,
    pub(super) direct_tx_no_frame_fallback_packets: AtomicU64,
    pub(super) direct_tx_build_fallback_packets: AtomicU64,
    pub(super) direct_tx_disallowed_fallback_packets: AtomicU64,
    pub(super) debug_pending_fill_frames: AtomicU32,
    pub(super) debug_spare_fill_frames: AtomicU32,
    pub(super) debug_free_tx_frames: AtomicU32,
    pub(super) debug_pending_tx_prepared: AtomicU32,
    pub(super) debug_pending_tx_local: AtomicU32,
    pub(super) debug_outstanding_tx: AtomicU32,
    /// #1241: last sampled AF_XDP TX completion-ring availability
    /// before the owner worker drained completions. Published on the
    /// existing debug tick from owner-local telemetry so the forwarding
    /// hot path does not introduce cross-worker cacheline traffic.
    pub(super) tx_completion_ring_available: AtomicU32,
    /// #1241: maximum sampled completion-ring availability during the
    /// last debug window. This catches short CQ buildup that a latest
    /// sample can miss when the owner drains quickly.
    pub(super) tx_completion_ring_available_max: AtomicU32,
    pub(super) debug_in_flight_recycles: AtomicU32,
    /// #878: total UMEM frames allocated to this binding. Set once
    /// at worker construction (after `binding_frame_count_for_driver`)
    /// and read by the snapshot path.
    pub(super) umem_total_frames: AtomicU32,
    /// #878: configured TX-ring depth for this binding. Set once at
    /// worker construction. `outstanding_tx / tx_ring_capacity` is
    /// the second pressure signal aggregated by the Buffer% display.
    pub(super) tx_ring_capacity: AtomicU32,
    /// #878: UMEM frames currently in flight (not idle in any pool).
    /// Computed in the worker's per-second debug tick as
    /// `total - free_tx_frames.len() - pending_fill_frames.len()
    ///        - device.pending()` — one publish, one read, so the
    /// `show chassis forwarding` Buffer% can divide by
    /// `umem_total_frames` without torn-load risk. Approximation by
    /// design: cross-field sampling on the publish side is acceptable
    /// because the per-second cadence bounds skew, and the CLI
    /// surface is rare-diagnostic, not a load-bearing invariant.
    /// Subtracting `device.pending()` (the kernel fill ring depth)
    /// is essential — without it an idle binding reads ~80% because
    /// AF_XDP keeps the fill ring pre-populated by design.
    pub(super) umem_inflight_frames: AtomicU32,
    /// #802: ring-pressure instrumentation. Cumulative monotonic counters
    /// mirrored from the worker-local `BindingWorker` fields of the same
    /// name. Worker increments `b.dbg_tx_ring_full += 1` (etc.) on the hot
    /// path; the published value here is updated via `fetch_add(delta)`
    /// at the existing ~1s debug-report tick, BEFORE the local counter is
    /// reset for the next window. The control-socket snapshot reads from
    /// these atomics. No hot-path code is touched — this is purely a new
    /// read-side publish sink.
    pub(super) dbg_tx_ring_full: AtomicU64,
    pub(super) dbg_sendto_enobufs: AtomicU64,
    /// #802/#804: per-binding `bound_pending` FIFO overflow counter —
    /// incremented when `bound_pending_tx_local`/`bound_pending_tx_prepared`
    /// evict an item because the FIFO is above `max_pending_tx`. This is
    /// strictly the bound-pending path; the class-of-service admission
    /// overflow has its own counter below. Pre-#804 builds published a
    /// single `dbg_pending_overflow` that conflated the two sites; that
    /// wire key was removed in #804 in favor of the split names.
    pub(super) dbg_bound_pending_overflow: AtomicU64,
    /// #804/#1315: binding-lifetime class-of-service queue drop counter.
    /// Incremented for admission rejects in `enqueue_cos_item()` (flow-share
    /// cap + buffer cap exhausted) and for reset-time CoS queue drains in
    /// `reset_binding_cos_runtime()`. Separate from
    /// `dbg_bound_pending_overflow` so operators can disambiguate
    /// bound-pending pressure from CoS shaping pressure at triage time. The
    /// wire key is historical.
    pub(super) dbg_cos_queue_overflow: AtomicU64,
    /// #802: kernel XDP statistics v2 `rx_fill_ring_empty_descs` — the
    /// kernel's native cumulative counter of RX fill-ring starvation
    /// events. Published via `store()` (not fetch_add) because the
    /// kernel-side value is already absolute. Sampled from
    /// `device.statistics_v2()` at the same ~1s debug-report tick as
    /// the local counters above.
    pub(super) rx_fill_ring_empty_descs: AtomicU64,
    pub(super) last_heartbeat: AtomicU64,
    pub(super) max_pending_tx: AtomicU32,
    /// Atomic admission count for `pending_tx`: queued requests plus
    /// producer-held reservations that have not committed yet. This is the
    /// linearizable capacity gate; `pending_tx.len()` remains observational.
    pub(super) pending_tx_admitted: AtomicUsize,
    pub(super) last_error: Mutex<String>,
    /// #4971: lock-free last expected-TX-backpressure retry reason.
    /// Stores a `crate::afxdp::tx::TxRetryReason` ordinal (0 = none).
    /// Written on the expected-congestion retry path via
    /// `set_tx_retry_status` INSTEAD of taking the `last_error` mutex —
    /// the TX drain path recurs every pass under ring pressure, so a
    /// mutex acquire there is a hot-path cost. Surfaced as the
    /// `last_error` FALLBACK in the status snapshot (read side, ~1s
    /// poll), so operator visibility of the backpressure reason is
    /// preserved without any lock on the send hot path.
    ///
    /// #6145 — precedence: this hint is surfaced ONLY when the
    /// `last_error` mutex string is empty. A non-empty `last_error`
    /// (an exceptional `TxError::Drop`, bind, or reconcile fault)
    /// OUTRANKS this hint and masks it until `clear_error()` (rebind)
    /// resets both. That stale-masking is deliberate — a Drop is rarer
    /// and more severe than expected backpressure. See `snapshot.rs`.
    pub(super) last_tx_retry_status: AtomicU8,
    /// Cross-worker redirect inbox (#706). N producer workers push
    /// redirected `TxRequest`s; the single owner worker drains. Bounded
    /// lock-free ring — replaces the pre-#706 `Mutex<VecDeque>` that
    /// serialised every producer against every other producer and
    /// against the owner's drain.
    pub(super) pending_tx: MpscInbox<TxRequest>,
    pub(super) pending_session_deltas: Mutex<VecDeque<SessionDeltaInfo>>,
    /// #5290: per-binding loss-of-sync latch for the RPC-fallback session-delta
    /// buffer (`pending_session_deltas`). Set when a delta is silently dropped
    /// because the buffer hit `MAX_PENDING_SESSION_DELTAS`, OR when the
    /// caller-wide fair drain (`drain_session_deltas_fair`) could not keep up
    /// and left deltas undrained (budget overflow). Consumed by the owning
    /// worker loop, which folds it into `SessionTable::set_delta_loss` so the
    /// existing #2442/#2874 `take_delta_loss` resync re-exports the full
    /// owner-RG snapshot (table truth) — the standby recovers the lost/undrained
    /// deltas instead of silently diverging. A single bool, so a burst raises
    /// exactly one resync (debounced by `take_delta_loss`). Cross-thread
    /// (control drain arms, worker consumes), so `AtomicBool` rather than the
    /// plain `bool` `SessionTable` can use under its `&mut self`.
    pub(super) delta_loss_pending: AtomicBool,
}

// #6304: FOUR PINNED LAYOUT VALUES, tripping if the `#[cfg(test)]`
// admission-attempt instrument (`pending_tx_admission_attempts`, `tx_inbox.rs`)
// moves any of them. Not a statement of whole-struct layout neutrality — see
// "WHAT THIS IS, exactly" below, which bounds the claim rather than qualifying
// it. This struct is the one whose
// cross-core cacheline behaviour #6114 exists to fix, so an instrument that
// moved anything in it would put a layout under test that production never has.
//
// These four asserts are deliberately NOT `#[cfg(test)]`. They are evaluated
// once in the PRODUCTION configuration (`cargo build` / `make
// build-userspace-dp`, instrument absent) and once in the TEST configuration
// (`cargo test` / `make test-rust`, instrument present), against the same
// literals — so an instrument that moved ANY OF THESE FOUR VALUES could satisfy
// at most one of the two builds. That is the cross-configuration comparison a
// `#[test]` alone cannot make; the runtime cell in
// `binding_state/tests/tx_inbox.rs` re-asserts these numbers and carries the
// reasoning.
//
// WHAT THIS IS, exactly. Four pinned values are a TRIPWIRE, not a layout
// fingerprint. Size, alignment and two field offsets do not determine the
// placement of the other ~90 fields, so a perturbation that moves only unpinned
// fields satisfies all four literals in both configurations and passes
// unnoticed. The guard is chosen for the specific hazard — a `#[cfg(test)]`
// member reaching this struct — and the two offsets are the two shapes that
// hazard takes (see the measured counterfactuals below); it is not a proof that
// the test-configuration struct is layout-EQUAL to the production one.
//
// It is also a toolchain-and-target tripwire, not a portable invariant.
// `BindingLiveState` is `repr(Rust)`, and this crate pins neither a
// `rust-version` nor a toolchain file, so field placement is whatever the
// compiler in use chooses. That direction of failure is safe — a changed value
// is a compile ERROR reporting the actual number, never a silent accept — but it
// does mean a toolchain upgrade or a different target can trip these literals
// without anything in this file having moved. Re-measure and update; do not
// widen the guard to make it stop failing.
//
// Measured, rustc 1.96.0, x86_64, both configurations:
//   size 2304, align 64, offset(pending_tx_admitted) 2152,
//   offset(delta_loss_pending) 2280.
//
// The two OFFSET asserts exist because size and align are NOT sufficient — both
// counterfactuals were measured rather than argued:
//   - a `#[cfg(test)]` `AtomicU64` FIELD declared ahead of `pending_tx_admitted`
//     (the instrument shape an earlier round considered and declined) leaves
//     size 2304 and align 64 UNCHANGED — it lands in existing tail slack — and
//     moves `pending_tx_admitted` to 2160.
//   - the same field declared LAST, after `delta_loss_pending`, leaves size,
//     align and `pending_tx_admitted` all unchanged, and moves
//     `delta_loss_pending` to 2288 (repr(Rust) reorders, so "declared last" is
//     not "placed last").
// A size-only guard would have called both of those harmless.
//
// If a legitimately new PRODUCTION field trips these, re-measure and update the
// literals — the compile error reports the actual value. If only the TEST build
// trips one, a test-only member has reached the struct and has moved one of
// these four values.
//
// WHAT PINS THESE FOUR LINES — nothing, deliberately, and the cost of that is
// measured rather than waved at. On this tree, deleting all four compiles the
// complete test binary and the mirrored runtime cell in
// `binding_state/tests/tx_inbox.rs` still PASSES; each line is individually
// deletable with the same result. Nothing in the tree observes their absence.
//
// They are given no guard of their own because the only shapes available for
// guarding a source construct are a match on its NAME or on its TEXT, and both
// are proxies — a differently-spelled equivalent satisfies them, and they red on
// a harmless rename while staying green on a semantic gutting. A guard that is
// itself a `const` is no better: it would be exactly as deletable as what it
// guards, and guarding IT is the same problem one level up. Every tripwire
// terminates somewhere; this one terminates at itself, and says so here rather
// than implying a completeness it does not have.
//
// Nor could a runtime witness exist even in principle. What these four lines
// assert is a statement about the PRODUCTION configuration, and a test binary is
// by construction the TEST configuration, so no `#[test]` can observe whether
// they are present in the build that matters.
//
// What their presence buys, measured with a `#[cfg(test)]` `AtomicU64` declared
// ahead of `pending_tx_admitted` — the hazard's own shape:
//   - asserts present, literals untouched: `cargo build` (production) SUCCEEDS,
//     because the field does not exist there, and the test build FAILS reporting
//     2152 -> 2160 AND 2280 -> 2288.
//   - asserts present, literals re-measured to 2160/2288 so the test build
//     passes: the test build then SUCCEEDS and `cargo build` FAILS, reporting
//     the same two values back the other way. That is the "at most one of the
//     two builds" property, and it is what makes this guard un-satisfiable by
//     re-measuring in whichever configuration happens to be in front of you.
//   - asserts DELETED and the runtime cell's own literals re-measured to
//     2160/2288: the production build and the test run BOTH pass, and the
//     test-only perturbation is accepted in silence.
// The last cell is exactly what deleting these four lines costs. It is also the
// difference between them and the runtime cell: the runtime cell can be
// re-measured green, and these cannot. Removing them is therefore a reviewable
// act, not cleanup.
//
// #6664 re-measured the two offset literals (2152 -> 2160, 2280 -> 2288) when
// `next_table_unsupported_drops` was added to the cold-counter run above. That
// is the legitimate case for this guard, and it is worth naming why: the hazard
// documented above is a `#[cfg(test)]` field, for which production and test
// builds DISAGREE and so at most one of them can be green at any one pair of
// literals. This field is unconditional, so both configurations shift by the
// same 8 bytes and re-measuring makes both green together -- which is the
// guard reporting a real layout change and being answered, not defeated.
// `size_of` is unchanged at 2304: the 8 bytes came out of existing tail
// padding, so the next field added here will move it and should expect to.
//
// #7054 re-measured the two offsets again (2160 -> 2168, 2288 -> 2296) when
// `nat64_frag_assoc_evicted` joined the cold-counter run. Same legitimate case
// as #6664: the field is UNCONDITIONAL, so the production and test builds shift
// by the same 8 bytes and re-measuring makes both green together — the guard
// reporting a real layout change and being answered, not defeated. (Contrast
// the `#[cfg(test)]` hazard above, where at most one of the two builds can be
// green at any one pair of literals, which is what makes that case
// un-satisfiable by re-measuring.)
//
// #8108 re-measured the same two offsets again (2176 -> 2184, 2304 -> 2312)
// when `session_delta_high_water` joined the cold-counter run. Same legitimate
// case as #6664 and #7054: the field is UNCONDITIONAL, so both builds shift by
// the same 8 bytes and re-measuring makes them green together. `size_of` did
// NOT move -- it is still 2368, so the tail padding absorbed this field too,
// exactly as it absorbed #7054's. That is now twice the #6664 note's
// "the next field will move size_of" has failed to hold, which is the reason
// that note says to check the OFFSETS rather than the size: an unchanged
// `size_of` is not evidence a field failed to land.
//
// The #6664 note's prediction that "the next field added here will move
// `size_of`" did NOT hold: it is still 2304, because the tail padding had room
// for a second u64. Recorded so the next reader does not treat an unchanged
// 2304 as evidence their field failed to land — check the OFFSETS, which did
// move.
// #7156 re-measured all three moving literals (size 2304 -> 2368, offsets
// 2168 -> 2176 and 2296 -> 2304) when `pending_neigh_visits` joined the
// cold-counter run. Same legitimate case as #6664 and #7054: the field is
// UNCONDITIONAL, so the production and test builds shift by the same 8 bytes
// and one pair of literals makes both green — the guard reporting a real layout
// change and being answered, not defeated. Verified by building BOTH
// configurations, since agreement between them is the whole discriminator
// against the `#[cfg(test)]` hazard above.
//
// This is the addition the #6664 note predicted and #7054 found had not yet
// happened: the tail padding is now full, so `size_of` moved a whole 64-byte
// alignment unit rather than absorbing the field. An unchanged 2304 would now
// be the surprising result.
const _: [(); 64] = [(); std::mem::align_of::<BindingLiveState>()];
//
// #8670 added `nat64_ineligible_protocol` and hit the INVERSE of the case
// above: `size_of` stayed 2368 (the 64-byte alignment unit #7156 opened still
// had room) while both offsets moved 2184 -> 2192 and 2312 -> 2320. That is
// exactly the reading the #6664 note warns about — an unchanged `size_of` is
// not evidence the field failed to land, and here it is the OFFSETS that
// carried the proof. Verified in both configurations per the note above.
//
// #8890 added `nat64_tunnel_encap_unsupported` and repeats #8670's case
// exactly: `size_of` stayed 2368 (the #7156 alignment unit still has room)
// while both offsets moved 2192 -> 2200 and 2320 -> 2328. The field is
// UNCONDITIONAL, so the discriminator the note above demands was applied:
// BOTH configurations were built and BOTH reported the same two shifts, by
// the same 8 bytes. That agreement is what distinguishes re-measuring a real
// layout change from defeating the guard — a `#[cfg(test)]` field would have
// moved the test build alone, and one pair of literals could not have made
// both green.
// F-149 (#9904) adds `tx_shared_recycle_unknown_slot_rescued` and repeats
// #8670/#8890's case exactly: `size_of` stays 2368 (the #7156 alignment
// unit still has room) while both offsets move 2200 -> 2208 and
// 2328 -> 2336. The field is UNCONDITIONAL, so both configurations (normal
// and test builds) must report the same two shifts — verified by building
// both.
// #9956 F-051 repeats it once more: `flowless_forward_packets/bytes` move
// both offsets 2208 -> 2224 and 2336 -> 2352 while `size_of` stays 2368.
// #9752 adds `table_unavailable_packets` and `table_unavailable_drops` (two
// unconditional u64s ahead of both sentinels): both offsets move 2224 -> 2240
// and 2352 -> 2368, and `size_of` grows 2368 -> 2432 — the #7156 alignment
// unit is finally full (the F-149 + F-051 + #9752 fields together exceed its
// slack), so the struct takes a new 64-byte unit. Same legitimate case as
// #6664: both builds shift identically and one triple of literals makes both
// green — verified by building BOTH the production (`cargo check`) and test
// (`--all-targets`) configurations.
const _: [(); 2432] = [(); std::mem::size_of::<BindingLiveState>()];
const _: [(); 2240] = [(); std::mem::offset_of!(BindingLiveState, pending_tx_admitted)];
const _: [(); 2368] = [(); std::mem::offset_of!(BindingLiveState, delta_loss_pending)];

impl BindingLiveState {
    pub(super) fn new() -> Self {
        Self {
            bound: AtomicBool::new(false),
            xsk_registered: AtomicBool::new(false),
            bind_mode: AtomicU8::new(XskBindMode::Unknown.as_u8()),
            socket_fd: AtomicI32::new(0),
            socket_ifindex: AtomicI32::new(0),
            socket_queue_id: AtomicU32::new(0),
            socket_bind_flags: AtomicU32::new(0),
            shared_umem_status: Mutex::new(SharedUmemLiveStatus::default()),
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            rx_batches: AtomicU64::new(0),
            rx_wakeups: AtomicU64::new(0),
            metadata_packets: AtomicU64::new(0),
            metadata_errors: AtomicU64::new(0),
            validated_packets: AtomicU64::new(0),
            validated_bytes: AtomicU64::new(0),
            local_delivery_packets: AtomicU64::new(0),
            forward_candidate_packets: AtomicU64::new(0),
            flowless_forward_packets: AtomicU64::new(0),
            flowless_forward_bytes: AtomicU64::new(0),
            route_miss_packets: AtomicU64::new(0),
            martian_dropped: AtomicU64::new(0),
            ipv6_ext_header_dropped: AtomicU64::new(0),
            neighbor_miss_packets: AtomicU64::new(0),
            discard_route_packets: AtomicU64::new(0),
            next_table_packets: AtomicU64::new(0),
            table_unavailable_packets: AtomicU64::new(0),
            exception_packets: AtomicU64::new(0),
            config_gen_mismatches: AtomicU64::new(0),
            fib_gen_mismatches: AtomicU64::new(0),
            unsupported_packets: AtomicU64::new(0),
            flow_cache_hits: AtomicU64::new(0),
            flow_cache_misses: AtomicU64::new(0),
            flow_cache_evictions: AtomicU64::new(0),
            flow_cache_collision_evictions: AtomicU64::new(0),
            active_flow_count: AtomicU32::new(0),
            flow_cache_capacity: AtomicU32::new(super::flow_cache::flow_cache_capacity() as u32),
            flow_worker_map: ArcSwap::from_pointee(FlowWorkerMapSnapshot::default()),
            cos_active_flow_counts: ArcSwap::from_pointee(Vec::new()),
            v_min_throttle_hard_cap_overrides: AtomicU64::new(0),
            v_min_throttles: AtomicU64::new(0),
            v_min_suspended_batches: AtomicU64::new(0),
            session_hits: AtomicU64::new(0),
            session_misses: AtomicU64::new(0),
            session_creates: AtomicU64::new(0),
            session_expires: AtomicU64::new(0),
            session_delta_generated: AtomicU64::new(0),
            session_delta_high_water: AtomicU64::new(0),
            session_delta_dropped: AtomicU64::new(0),
            session_delta_drained: AtomicU64::new(0),
            policy_denied_packets: AtomicU64::new(0),
            host_inbound_denied_packets: AtomicU64::new(0),
            screen_drops: AtomicU64::new(0),
            // #3343: one atomic per published screen-reason drop ordinal.
            screen_reason_drops: std::array::from_fn(|_| AtomicU64::new(0)),
            syn_cookie_challenges: AtomicU64::new(0),
            syn_cookie_secret_unavailable: AtomicU64::new(0),
            syn_cookie_syn_ack_sent: AtomicU64::new(0),
            syn_cookie_ack_rst_sent: AtomicU64::new(0),
            syn_cookie_reply_budget_drops: AtomicU64::new(0),
            syn_cookie_ack_valid: AtomicU64::new(0),
            syn_cookie_ack_invalid: AtomicU64::new(0),
            syn_cookie_bypass: AtomicU64::new(0),
            policy_reject_sent: AtomicU64::new(0),
            filter_reject_sent: AtomicU64::new(0),
            policy_reject_reply_budget_drops: AtomicU64::new(0),
            filter_reject_reply_budget_drops: AtomicU64::new(0),
            policy_reject_rate_limit_drops: AtomicU64::new(0),
            filter_reject_rate_limit_drops: AtomicU64::new(0),
            time_exceeded_output_filter_drops: AtomicU64::new(0),
            policy_reject_output_filter_drops: AtomicU64::new(0),
            filter_reject_output_filter_drops: AtomicU64::new(0),
            syn_cookie_output_filter_drops: AtomicU64::new(0),
            ptb_output_filter_drops: AtomicU64::new(0),
            generated_reply_classify_parse_errors: AtomicU64::new(0),
            snat_packets: AtomicU64::new(0),
            dnat_packets: AtomicU64::new(0),
            nat64_translations: AtomicU64::new(0),
            nat64_no_source_pool: AtomicU64::new(0),
            nat64_pool_exhausted: AtomicU64::new(0),
            nat64_frag_dropped: AtomicU64::new(0),
            nat64_frag_assoc_evicted: AtomicU64::new(0),
            nat64_ineligible_source: AtomicU64::new(0),
            nat64_ineligible_dest: AtomicU64::new(0),
            nat64_exthdr_ineligible: AtomicU64::new(0),
            nat64_tunnel_encap_unsupported: AtomicU64::new(0),
            nat64_ineligible_protocol: AtomicU64::new(0),
            nat_alloc_fail: AtomicU64::new(0),
            nat_frag_untranslated_dropped: AtomicU64::new(0),
            slow_path_packets: AtomicU64::new(0),
            slow_path_bytes: AtomicU64::new(0),
            slow_path_local_delivery_packets: AtomicU64::new(0),
            slow_path_missing_neighbor_packets: AtomicU64::new(0),
            slow_path_no_route_packets: AtomicU64::new(0),
            slow_path_next_table_packets: AtomicU64::new(0),
            slow_path_forward_build_packets: AtomicU64::new(0),
            slow_path_drops: AtomicU64::new(0),
            slow_path_rate_limited: AtomicU64::new(0),
            tunnel_encap_unresolved_drops: AtomicU64::new(0),
            fabric_redirect_unsendable_drops: AtomicU64::new(0),
            next_table_unsupported_drops: AtomicU64::new(0),
            table_unavailable_drops: AtomicU64::new(0),
            kernel_rx_dropped: AtomicU64::new(0),
            kernel_rx_invalid_descs: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            tx_completions: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            tx_shared_recycle_unknown_slot_drops: AtomicU64::new(0),
            tx_shared_recycle_unknown_slot_rescued: AtomicU64::new(0),
            redirect_inbox_overflow_drops: AtomicU64::new(0),
            pending_tx_local_overflow_drops: AtomicU64::new(0),
            tx_submit_error_drops: AtomicU64::new(0),
            mirrored_packets: AtomicU64::new(0),
            mirrored_bytes: AtomicU64::new(0),
            mirror_drops_no_frame: AtomicU64::new(0),
            mirror_drops_tx_frame_reserve: AtomicU64::new(0),
            mirror_drops_no_binding: AtomicU64::new(0),
            mirror_drops_queue_full: AtomicU64::new(0),
            mirror_drops_queue_full_same_worker: AtomicU64::new(0),
            mirror_drops_queue_full_cross_worker: AtomicU64::new(0),
            no_owner_binding_drops: AtomicU64::new(0),
            neg_neigh_fast_fail: AtomicU64::new(0),
            pending_neigh_duplicate_drops: AtomicU64::new(0),
            pending_neigh_decap_drops: AtomicU64::new(0),
            pending_neigh_visits: AtomicU64::new(0),
            pending_neigh_capacity_drops: AtomicU64::new(0),
            pending_neigh_keys: AtomicU64::new(0),
            neg_neigh_keys: AtomicU64::new(0),
            session_publish_errors: AtomicU64::new(0),
            new_flow_installs: AtomicU64::new(0),
            dnat_publish_errors: AtomicU64::new(0),
            // #709 / #746: owner-profile telemetry, split by writer
            // into two cacheline-isolated groups. Histograms are zero-
            // init fixed-cap arrays; sum of buckets == drain_invocations
            // invariant holds at `new()` (both 0). #5160: the redirect-sample
            // sequence is a producer-local thread-local (`REDIRECT_SAMPLE_SEQ`),
            // no longer a per-binding atomic, so there is nothing to seed here.
            // This drops the removed `new_seeded(worker_id)` phase-offset: each
            // worker thread's TLS starts at 0, so every worker's FIRST redirect
            // (v=0) is force-sampled. The "early-startup lockstep burst" that seed
            // mitigated is REINTRODUCED, but moved from per-destination to
            // per-thread — a one-time ~worker-count burst spread across all
            // destinations (a thread with v>0 does NOT force-sample its first op
            // to a new destination), not a chronic per-destination bias. Accepted,
            // not mitigated: `redirect_acquire_hist` is a latency-DISTRIBUTION
            // (percentile) histogram, so a bounded one-time startup sample burst
            // does not skew its quantiles; redirect rate/count use separate pps
            // counters.
            owner_profile_owner: OwnerProfileOwnerWrites::new(),
            owner_profile_peer: OwnerProfilePeerWrites::new(),
            direct_tx_packets: AtomicU64::new(0),
            copy_tx_packets: AtomicU64::new(0),
            in_place_tx_packets: AtomicU64::new(0),
            in_place_vlan_push_desc_packets: AtomicU64::new(0),
            in_place_vlan_pop_desc_packets: AtomicU64::new(0),
            in_place_vlan_push_no_headroom_packets: AtomicU64::new(0),
            in_place_l2_memmove_fallback_packets: AtomicU64::new(0),
            direct_tx_no_frame_fallback_packets: AtomicU64::new(0),
            direct_tx_build_fallback_packets: AtomicU64::new(0),
            direct_tx_disallowed_fallback_packets: AtomicU64::new(0),
            debug_pending_fill_frames: AtomicU32::new(0),
            debug_spare_fill_frames: AtomicU32::new(0),
            debug_free_tx_frames: AtomicU32::new(0),
            debug_pending_tx_prepared: AtomicU32::new(0),
            debug_pending_tx_local: AtomicU32::new(0),
            debug_outstanding_tx: AtomicU32::new(0),
            tx_completion_ring_available: AtomicU32::new(0),
            tx_completion_ring_available_max: AtomicU32::new(0),
            debug_in_flight_recycles: AtomicU32::new(0),
            // #878: capacities are stored once by the worker at
            // construction time (in worker.rs after
            // binding_frame_count_for_driver). umem_inflight_frames
            // is republished by the worker each per-second debug
            // tick. Zero here means "not yet published"; the
            // fwdstatus builder treats zero on umem_total_frames as
            // "unknown" and falls back to the legacy display.
            umem_total_frames: AtomicU32::new(0),
            tx_ring_capacity: AtomicU32::new(0),
            umem_inflight_frames: AtomicU32::new(0),
            // #802: ring-pressure instrumentation sinks. Zero-init;
            // published by the worker's per-second debug tick.
            dbg_tx_ring_full: AtomicU64::new(0),
            dbg_sendto_enobufs: AtomicU64::new(0),
            dbg_bound_pending_overflow: AtomicU64::new(0),
            dbg_cos_queue_overflow: AtomicU64::new(0),
            rx_fill_ring_empty_descs: AtomicU64::new(0),
            last_heartbeat: AtomicU64::new(0),
            max_pending_tx: AtomicU32::new(0),
            pending_tx_admitted: AtomicUsize::new(0),
            last_error: Mutex::new(String::new()),
            // #4971: 0 = no TX-retry backpressure reason recorded yet.
            last_tx_retry_status: AtomicU8::new(0),
            pending_tx: MpscInbox::new(PENDING_TX_INBOX_HARD_CAP),
            pending_session_deltas: Mutex::new(VecDeque::new()),
            delta_loss_pending: AtomicBool::new(false),
        }
    }


    pub(super) fn set_bound(&self, socket_fd: c_int) {
        self.bound.store(true, Ordering::Relaxed);
        self.socket_fd.store(socket_fd, Ordering::Relaxed);
    }

    pub(super) fn set_socket_binding(&self, ifindex: i32, queue_id: u32, flags: u32) {
        self.socket_ifindex.store(ifindex, Ordering::Relaxed);
        self.socket_queue_id.store(queue_id, Ordering::Relaxed);
        self.socket_bind_flags.store(flags, Ordering::Relaxed);
    }

    pub(super) fn set_shared_umem_status(
        &self,
        mode: String,
        group: String,
        socket_role: String,
        disabled_reason: String,
    ) {
        if let Ok(mut status) = self.shared_umem_status.lock() {
            *status = SharedUmemLiveStatus {
                mode,
                group,
                socket_role,
                disabled_reason,
            };
        }
    }

    pub(super) fn set_xsk_registered(&self, value: bool) {
        self.xsk_registered.store(value, Ordering::Relaxed);
    }

    pub(super) fn set_bind_mode(&self, mode: XskBindMode) {
        self.bind_mode.store(mode.as_u8(), Ordering::Relaxed);
    }

    pub(super) fn clear_socket_state(&self) {
        self.bound.store(false, Ordering::Relaxed);
        self.xsk_registered.store(false, Ordering::Relaxed);
        self.bind_mode
            .store(XskBindMode::Unknown.as_u8(), Ordering::Relaxed);
        self.socket_fd.store(0, Ordering::Relaxed);
        self.socket_ifindex.store(0, Ordering::Relaxed);
        self.socket_queue_id.store(0, Ordering::Relaxed);
        self.socket_bind_flags.store(0, Ordering::Relaxed);
    }

    pub(super) fn set_last_heartbeat_at(&self, now_ns: u64) {
        self.last_heartbeat.store(now_ns, Ordering::Relaxed);
    }

    pub(super) fn set_max_pending_tx(&self, max_pending: usize) {
        self.max_pending_tx
            .store(max_pending.min(u32::MAX as usize) as u32, Ordering::Relaxed);
    }

    pub(super) fn publish_flow_worker_map(
        &self,
        rows: Vec<crate::protocol::FlowWorkerStatus>,
        truncated: bool,
    ) {
        self.flow_worker_map
            .store(Arc::new(FlowWorkerMapSnapshot { rows, truncated }));
    }

    pub(in crate::afxdp) fn flow_worker_map_snapshot(
        &self,
    ) -> (Vec<crate::protocol::FlowWorkerStatus>, bool) {
        let snapshot = self.flow_worker_map.load();
        (snapshot.rows.clone(), snapshot.truncated)
    }

    /// Publish this binding's per-CoS active-flow counts.
    ///
    /// Unlike `flow_worker_map`, this per-binding snapshot has no local
    /// truncation bit; the coordinator reports truncation only when its
    /// aggregate status row cap is exceeded.
    pub(super) fn publish_cos_active_flow_counts(
        &self,
        rows: Vec<crate::protocol::CoSActiveFlowCountStatus>,
    ) {
        self.cos_active_flow_counts.store(Arc::new(rows));
    }

    pub(in crate::afxdp) fn cos_active_flow_counts_snapshot(
        &self,
    ) -> Vec<crate::protocol::CoSActiveFlowCountStatus> {
        self.cos_active_flow_counts.load().as_ref().clone()
    }

    pub(super) fn clear_error(&self) {
        if let Ok(mut err) = self.last_error.lock() {
            err.clear();
        }
        // #4971: also reset the lock-free retry status so a rebind /
        // successful reconcile clears the surfaced backpressure reason.
        self.last_tx_retry_status.store(0, Ordering::Relaxed);
    }

    pub(super) fn set_error(&self, msg: String) {
        if let Ok(mut err) = self.last_error.lock() {
            *err = msg;
        }
    }

    /// #4971: record an expected-TX-backpressure retry reason without
    /// touching the `last_error` mutex. A single `Relaxed` atomic store
    /// (single-writer owner worker) — cheap enough to sit on the send
    /// hot path, which recurs every drain pass under ring pressure. The
    /// reason is surfaced to operators as the `last_error` snapshot
    /// fallback (see `snapshot.rs`), so observability is preserved.
    pub(super) fn set_tx_retry_status(&self, reason: crate::afxdp::tx::TxRetryReason) {
        self.last_tx_retry_status
            .store(reason as u8, Ordering::Relaxed);
    }

    pub(super) fn record_slow_path_accept(
        &self,
        disposition: ForwardingDisposition,
        reason: &str,
        packet_len: u64,
    ) {
        self.slow_path_packets.fetch_add(1, Ordering::Relaxed);
        self.slow_path_bytes
            .fetch_add(packet_len, Ordering::Relaxed);
        if reason == "forward_build_slow_path" {
            self.slow_path_forward_build_packets
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        match disposition {
            ForwardingDisposition::LocalDelivery => {
                self.slow_path_local_delivery_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            ForwardingDisposition::MissingNeighbor => {
                self.slow_path_missing_neighbor_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            ForwardingDisposition::NoRoute => {
                self.slow_path_no_route_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            ForwardingDisposition::NextTableUnsupported => {
                self.slow_path_next_table_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// #6664: record a `NextTableUnsupported` frame refused by the slow-path
    /// allow-list and dropped fail-closed.
    ///
    /// Called from BOTH refusal sites -- the filtered wrapper
    /// `maybe_reinject_slow_path` and the trailing chokepoint in
    /// `poll_descriptor` -- because the two must never disagree about whether
    /// a refusal was counted. A divergence there is always a bug, never a
    /// policy difference, so it is one function rather than two agreeing
    /// increments.
    pub(in crate::afxdp) fn record_next_table_unsupported_drop(&self) {
        self.next_table_unsupported_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    /// #9752: record a `TableUnavailable` frame refused by the slow-path
    /// allow-list and dropped fail-closed. Called from BOTH refusal sites
    /// via `slow_path_admit`, like `record_next_table_unsupported_drop`.
    pub(in crate::afxdp) fn record_table_unavailable_drop(&self) {
        self.table_unavailable_drops
            .fetch_add(1, Ordering::Relaxed);
    }
}


#[cfg(test)]
mod tests;
#[cfg(test)]
mod torn_bindmode_6898_tests;
