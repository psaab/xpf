package userspace

import (
	"time"
)

type ForwardingControlRequest struct {
	Armed bool `json:"armed"`
}

type QueueControlRequest struct {
	QueueID    uint32 `json:"queue_id"`
	Registered bool   `json:"registered"`
	Armed      bool   `json:"armed"`
}

type BindingControlRequest struct {
	Slot       uint32 `json:"slot"`
	Registered bool   `json:"registered"`
	Armed      bool   `json:"armed"`
}

type QueueStatus struct {
	QueueID    uint32    `json:"queue_id"`
	WorkerID   uint32    `json:"worker_id"`
	Interfaces []string  `json:"interfaces,omitempty"`
	Registered bool      `json:"registered"`
	Armed      bool      `json:"armed"`
	Ready      bool      `json:"ready"`
	LastChange time.Time `json:"last_change,omitempty"`
}

type BindingStatus struct {
	Slot                     uint32 `json:"slot"`
	QueueID                  uint32 `json:"queue_id"`
	WorkerID                 uint32 `json:"worker_id"`
	Interface                string `json:"interface,omitempty"`
	Ifindex                  int    `json:"ifindex,omitempty"`
	Registered               bool   `json:"registered"`
	Armed                    bool   `json:"armed"`
	Ready                    bool   `json:"ready"`
	Bound                    bool   `json:"bound"`
	XSKRegistered            bool   `json:"xsk_registered"`
	XSKBindMode              string `json:"xsk_bind_mode,omitempty"`
	ZeroCopy                 bool   `json:"zero_copy,omitempty"`
	SocketFD                 int    `json:"socket_fd,omitempty"`
	SharedUMEMMode           string `json:"shared_umem_mode,omitempty"`
	SharedUMEMGroup          string `json:"shared_umem_group,omitempty"`
	SharedUMEMSocketRole     string `json:"shared_umem_socket_role,omitempty"`
	SharedUMEMDisabledReason string `json:"shared_umem_disabled_reason,omitempty"`
	RXPackets                uint64 `json:"rx_packets,omitempty"`
	RXBytes                  uint64 `json:"rx_bytes,omitempty"`
	RXBatches                uint64 `json:"rx_batches,omitempty"`
	RXWakeups                uint64 `json:"rx_wakeups,omitempty"`
	MetadataPackets          uint64 `json:"metadata_packets,omitempty"`
	MetadataErrors           uint64 `json:"metadata_errors,omitempty"`
	ValidatedPackets         uint64 `json:"validated_packets,omitempty"`
	ValidatedBytes           uint64 `json:"validated_bytes,omitempty"`
	LocalDeliveryPackets     uint64 `json:"local_delivery_packets,omitempty"`
	ForwardCandidatePkts     uint64 `json:"forward_candidate_packets,omitempty"`
	// #9956 F-051: flowless-forwarded packets/bytes — the session-uncharged
	// share of ForwardCandidatePkts (forwarded and counted globally + per
	// zone, but no flow exists to charge). Session + flowless reconciles
	// with the zone/global totals. omitempty + the Rust serde `default`
	// keep cross-version wire safety. Summed across bindings and rendered
	// as the "Flowless forwards" status row.
	FlowlessForwardPkts  uint64 `json:"flowless_forward_packets,omitempty"`
	FlowlessForwardBytes uint64 `json:"flowless_forward_bytes,omitempty"`
	RouteMissPackets     uint64 `json:"route_miss_packets,omitempty"`
	// #4743: NoRoute drops whose destination is a MARTIAN address (IPv4
	// multicast/broadcast/unspecified/loopback, IPv6
	// multicast/unspecified/loopback). A strict sub-breakout of RouteMissPackets
	// (a martian dst misses the FIB and drops as NoRoute, so it bumps both),
	// letting an operator tell a martian-dst drop apart from an ordinary route
	// miss and correlate it with the filter-accept log. omitempty + the Rust
	// serde `default` keep cross-version wire safety (an older helper omits it →
	// 0). Summed across bindings and rendered as the "Martian drops" status row.
	MartianDropped uint64 `json:"martian_dropped,omitempty"`
	// #4743: fail-closed drops of an IPv6 packet whose extension-header chain is
	// still on an extension header after MAX_IPV6_EXT_HEADERS (8) iterations (an
	// over-limit, uninspectable chain). Before #4743 such a packet was forwarded
	// flowless; it is now dropped explicitly and counted. Distinct from a
	// truncated chain (which stays flowless). omitempty + the Rust serde
	// `default` keep cross-version wire safety. Rendered as the "IPv6 ext-header
	// drops" status row.
	IPv6ExtHeaderDropped uint64 `json:"ipv6_ext_header_dropped,omitempty"`
	NeighborMissPackets  uint64 `json:"neighbor_miss_packets,omitempty"`
	DiscardRoutePackets  uint64 `json:"discard_route_packets,omitempty"`
	NextTablePackets     uint64 `json:"next_table_packets,omitempty"`
	ExceptionPackets     uint64 `json:"exception_packets,omitempty"`
	ConfigGenMismatches  uint64 `json:"config_gen_mismatches,omitempty"`
	FIBGenMismatches     uint64 `json:"fib_gen_mismatches,omitempty"`
	UnsupportedPackets   uint64 `json:"unsupported_packets,omitempty"`
	FlowCacheHits        uint64 `json:"flow_cache_hits,omitempty"`
	FlowCacheMisses      uint64 `json:"flow_cache_misses,omitempty"`
	FlowCacheEvictions   uint64 `json:"flow_cache_evictions,omitempty"`
	// #918: collision-driven subset of flow_cache_evictions (full-set
	// LRU displacement vs stale-on-lookup eviction). Acceptance gate
	// watches collision_evictions / hits under load.
	FlowCacheCollisionEvictions uint64 `json:"flow_cache_collision_evictions,omitempty"`
	// #1219: snapshot count of distinct active flows on this binding's
	// flow_cache, refreshed at the helper's ~65ms debug-state tick. The
	// fairness harness reads this via the xpf_userspace_binding_active_flow_count
	// Prometheus metric to compute {a_i} for the structural CoV gate
	// per docs/fairness-regimes.md.
	ActiveFlowCount uint32 `json:"active_flow_count,omitempty"`
	// FlowCacheCapacity is Rust-owned and helper-published; Go must not
	// duplicate the helper's private FLOW_CACHE_SIZE constant.
	FlowCacheCapacity uint32 `json:"flow_cache_capacity,omitempty"`
	// #941 Work item D / #943: V_min throttle counters. Hard-cap is
	// the escape-hatch firing when fairness brake (regular throttle)
	// has thrown V_MIN_CONSECUTIVE_SKIP_HARD_CAP back-to-back times.
	// Together: VMinThrottles = "fairness brake fired",
	// VMinThrottleHardCapOverrides = "brake too tight, escape hatch
	// rescued throughput". Ratio is the LAG_THRESHOLD diagnostic.
	VMinThrottleHardCapOverrides uint64 `json:"v_min_throttle_hard_cap_overrides,omitempty"`
	VMinThrottles                uint64 `json:"v_min_throttles,omitempty"`
	// #hb166 T-6(a): count of V_min suspended drain batches — batches
	// where the fairness brake was OFF because a prior hard-cap armed
	// suspension. VMinSuspendedBatches / VMinThrottleHardCapOverrides is
	// the effective suspension-window-length diagnostic.
	VMinSuspendedBatches  uint64 `json:"v_min_suspended_batches,omitempty"`
	SessionHits           uint64 `json:"session_hits,omitempty"`
	SessionMisses         uint64 `json:"session_misses,omitempty"`
	SessionCreates        uint64 `json:"session_creates,omitempty"`
	SessionExpires        uint64 `json:"session_expires,omitempty"`
	SessionDeltaPending   uint64 `json:"session_delta_pending,omitempty"`
	SessionDeltaGenerated uint64 `json:"session_delta_generated,omitempty"`
	SessionDeltaDropped   uint64 `json:"session_delta_dropped,omitempty"`
	// #8108: greatest depth the RPC-fallback delta buffer reached (high water).
	SessionDeltaHighWater uint64 `json:"session_delta_high_water,omitempty"`
	SessionDeltaDrained   uint64 `json:"session_delta_drained,omitempty"`
	PolicyDeniedPackets   uint64 `json:"policy_denied_packets,omitempty"`
	// #3326: host-bound packets dropped by the zone host-inbound admission
	// gate. Mirrored into dataplane.GlobalCtrHostInboundDeny by
	// syncBPFCountersLocked so REST (host_inbound_denies), Prometheus
	// (xpf_host_inbound_denies_total), and `show security flow statistics`
	// reflect the drop. Before #3326 these denies were never counted.
	HostInboundDeniedPackets uint64 `json:"host_inbound_denied_packets,omitempty"`
	ScreenDrops              uint64 `json:"screen_drops,omitempty"`
	// ScreenReasonDrops (#3343): per-screen-reason DROP counters, one element per
	// dataplane.ScreenReasonCounters ordinal (the userspace-dp wire array). The
	// manager sums these across bindings and pushes each ordinal's delta into its
	// dataplane.GlobalCtrScreen* index so the per-reason screen-statistics rows
	// (CLI alarms / show security screen / flow statistics, gRPC, REST,
	// Prometheus) stop reading a permanent 0. The Rust side always serializes the
	// fixed-length array, so the key is present even when all-zero.
	ScreenReasonDrops          []uint64 `json:"screen_reason_drops,omitempty"`
	SYNCookieChallenges        uint64   `json:"syn_cookie_challenges,omitempty"`
	SYNCookieSecretUnavailable uint64   `json:"syn_cookie_secret_unavailable,omitempty"`
	SYNCookieSynAckSent        uint64   `json:"syn_cookie_syn_ack_sent,omitempty"`
	SYNCookieAckRstSent        uint64   `json:"syn_cookie_ack_rst_sent,omitempty"`
	SYNCookieReplyBudgetDrops  uint64   `json:"syn_cookie_reply_budget_drops,omitempty"`
	SYNCookieAckValid          uint64   `json:"syn_cookie_ack_valid,omitempty"`
	SYNCookieAckInvalid        uint64   `json:"syn_cookie_ack_invalid,omitempty"`
	SYNCookieBypass            uint64   `json:"syn_cookie_bypass,omitempty"`
	// #2089: policy `reject` action — RST/ICMP-unreachable replies sent,
	// and replies suppressed due to TX-frame budget exhaustion.
	PolicyRejectSent uint64 `json:"policy_reject_sent,omitempty"`
	// #2521: firewall-filter `then reject` — RST/ICMP-unreachable replies
	// sent (mirrors PolicyRejectSent). #3615 (L04/L05): the budget and
	// output-filter suppression legs are now SPLIT by source
	// (FilterRejectReplyBudgetDrops / FilterRejectOutputFilterDrops) so a
	// filter-reject drop is not conflated with a policy-reject drop; the
	// parse-error leg stays source-neutral. omitempty + Rust serde `default`
	// keep cross-version wire safety.
	FilterRejectSent             uint64 `json:"filter_reject_sent,omitempty"`
	PolicyRejectReplyBudgetDrops uint64 `json:"policy_reject_reply_budget_drops,omitempty"`
	// #3615 (L04): FILTER-`reject` reply TX-frame-budget suppression, split
	// from PolicyRejectReplyBudgetDrops (which is now policy-reject-only).
	FilterRejectReplyBudgetDrops uint64 `json:"filter_reject_reply_budget_drops,omitempty"`
	// #3661: reject replies dropped because the shared per-reason rate-limit
	// token bucket (REJECT_BUCKET) was empty, split by source. The aggregate
	// ProcessStatus.RejectRateLimitedTotal stays source-neutral for
	// back-compat; policy+filter here sum to it exactly (the Reject bucket has
	// one consume site). omitempty + the Rust serde `default` keep
	// cross-version wire safety (an older helper omits them → 0).
	PolicyRejectRateLimitDrops uint64 `json:"policy_reject_rate_limit_drops,omitempty"`
	FilterRejectRateLimitDrops uint64 `json:"filter_reject_rate_limit_drops,omitempty"`
	// #2238: locally-generated replies (Time Exceeded, policy-reject
	// RST/ICMP-unreachable, SYN-cookie SYN-ACK/ACK-RST) are now classified by
	// their OWN egress 5-tuple + egress interface. An output firewall filter
	// terminal discard/reject (or three-color policer) on the egress
	// interface drops the reply; these per-leg counters make that
	// (operator-installed) drop attributable. GeneratedReplyClassifyParseErrors
	// counts fail-closed drops when the generated bytes could not be re-parsed
	// (§6.2). omitempty + Rust serde `default` keep cross-version wire safety.
	TimeExceededOutputFilterDrops uint64 `json:"time_exceeded_output_filter_drops,omitempty"`
	PolicyRejectOutputFilterDrops uint64 `json:"policy_reject_output_filter_drops,omitempty"`
	// #3615 (L05): FILTER-`reject` reply egress-output-filter suppression,
	// split from PolicyRejectOutputFilterDrops (now policy-reject-only).
	FilterRejectOutputFilterDrops uint64 `json:"filter_reject_output_filter_drops,omitempty"`
	SYNCookieOutputFilterDrops    uint64 `json:"syn_cookie_output_filter_drops,omitempty"`
	// #2328: egress-MTU PTB / Frag-Needed replies (#2301 PMTUD path) are now
	// classified by the PTB's OWN egress tuple like the three siblings above,
	// so an output firewall filter discard/reject drops the PTB. Per-leg.
	PTBOutputFilterDrops              uint64 `json:"ptb_output_filter_drops,omitempty"`
	GeneratedReplyClassifyParseErrors uint64 `json:"generated_reply_classify_parse_errors,omitempty"`
	SNATPackets                       uint64 `json:"snat_packets,omitempty"`
	DNATPackets                       uint64 `json:"dnat_packets,omitempty"`
	// #2161: NAT64 (v6<->v4) translations on this binding. omitempty +
	// the Rust serde `default` keep cross-version wire safety (#1961-class:
	// an older helper omits the field, Go reads 0 rather than failing decode).
	Nat64Translations uint64 `json:"nat64_translations,omitempty"`
	// #2291: fail-closed NAT64 drops — a prefix matched but no IPv4 source
	// could be allocated (empty/exhausted pool), so the synthetic IPv6
	// destination was dropped rather than route-looked-up as IPv6. omitempty +
	// Rust serde `default` keep the same cross-version wire safety.
	Nat64NoSourcePool uint64 `json:"nat64_no_source_pool,omitempty"`
	// #4520: transient NAT64 pool-exhaustion drops — a prefix matched and its
	// pool was non-empty, but no free translated port could be allocated
	// (AllocatorExhausted). The transient sibling of Nat64NoSourcePool
	// (config/empty): a full pool under load (add capacity) is now
	// distinguishable from a misconfigured/empty pool (fix config). omitempty +
	// the Rust serde `default` keep cross-version wire safety (an older helper
	// omits it → 0).
	Nat64PoolExhausted uint64 `json:"nat64_pool_exhausted,omitempty"`
	// #2562: fail-closed NAT64 fragment drops — a datagram dropped because it is
	// a fragment NAT64 cannot safely translate: a non-first fragment (no L4
	// header) or a real ICMP/ICMPv6 fragment (the ICMP checksum covers the whole
	// datagram and cannot be recomputed from a single fragment). The
	// observable-drop half of #2562; the stateful frag-association cache (#3291
	// stage 4) that would let real fragments traverse end-to-end is deferred.
	// omitempty + the Rust serde `default` keep cross-version wire safety (an
	// older helper omits it → 0).
	Nat64FragDropped uint64 `json:"nat64_frag_dropped,omitempty"`
	// #7054: first-fragment installs that evicted a still-LIVE fragment
	// association (shard at cap, nothing expired to reclaim). Separates capacity
	// pressure from ordinary reorder/orphan drops.
	Nat64FragAssocEvicted uint64 `json:"nat64_frag_assoc_evicted,omitempty"`
	// #5623: fail-closed NAT64 SOURCE-ineligibility drops — an incoming IPv6
	// packet whose SOURCE lies within a configured Pref64 (a looping/synthesized
	// "already-translated" source, the RFC 6146 §5 hairpin construction — plus
	// the lower/upper Pref64 boundary and any embedded non-global v4) dropped
	// BEFORE route lookup, policy, or allocate_source per RFC 6146 §3.5. Distinct
	// from the pool counters above (config/capacity on an ELIGIBLE flow); this is
	// an input-validation reject. omitempty + the Rust serde `default` keep
	// cross-version wire safety (an older helper omits it → 0).
	Nat64IneligibleSource uint64 `json:"nat64_ineligible_source,omitempty"`
	// #6475: fail-closed NAT64 DESTINATION-ineligibility drops — an incoming
	// IPv6 packet whose NAT64-prefix-matched destination embeds a non-global
	// IPv4 per RFC 6052 §3.1 (0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
	// 224.0.0.0/4, 240.0.0.0/4 — e.g. 64:ff9b::127.0.0.1, which would otherwise
	// resolve LocalDelivery to the localhost-only control plane once lo0 lands
	// in the helper's local_v4 set) dropped BEFORE route lookup, policy, or
	// allocate_source. Distinct from the source/pool counters; this is a
	// destination input-validation reject. omitempty + the Rust serde `default`
	// keep cross-version wire safety (an older helper omits it → 0).
	Nat64IneligibleDest uint64 `json:"nat64_ineligible_dest,omitempty"`
	// #5625: fail-closed NAT64 EXTENSION-HEADER ineligibility drops — a v6→v4
	// forward translation rejected because the IPv6 packet carried an
	// Authentication Header (51), an ACTIVE Routing header (43, Segments
	// Left > 0), or a Mobility (135) / HIP (139) / Shim6 (140) header, none of
	// which a stateless NAT64 translation can carry to IPv4 (RFC 7915 §5.1 /
	// §5.1.1) — translating would strip the active extension semantics or break
	// AH authentication. Distinct from the source/pool/fragment counters; this
	// is an ext-header input reject. omitempty + the Rust serde `default` keep
	// cross-version wire safety (an older helper omits it → 0).
	Nat64ExthdrIneligible uint64 `json:"nat64_exthdr_ineligible,omitempty"`
	// Nat64TunnelEncapUnsupported (#8890) counts fail-closed drops of a
	// NAT64-translated packet whose route resolved through a GRE or
	// WireGuard endpoint. build_nat64_forwarded_frame performs no
	// encapsulation and the TX copy path selects it exclusively on
	// is_nat64, so before #8890 the inner packet was emitted on the
	// physical NIC as plaintext. It is dropped instead, matching the
	// #1873 R-E posture for the unresolved-neighbour route. A non-zero
	// value means a NAT64 + tunnel route combination is configured and
	// is NOT being forwarded — an unsupported-configuration signal, not
	// a capacity one. omitempty + the Rust serde `default` keep
	// cross-version wire safety (an older helper omits it → 0).
	Nat64TunnelEncapUnsupported uint64 `json:"nat64_tunnel_encap_unsupported,omitempty"`
	// Nat64IneligibleProtocol (#8670) counts fail-closed drops of a packet
	// addressed to a Pref64 destination whose IP protocol stateful NAT64 does
	// not translate — RFC 6146 covers TCP, UDP and ICMP only, so GRE, ESP,
	// AH, OSPF, SCTP, IPIP and PIM arrive flowless and are refused. Split out
	// of Nat64FragDropped, which counted them despite their not being
	// fragments and reported a broken ESP/GRE tunnel as a fragmentation fault.
	Nat64IneligibleProtocol uint64 `json:"nat64_ineligible_protocol,omitempty"`
	// #4477: source-NAT allocation failures (a source-NAT rule matched but no
	// translated mapping could be allocated — missing/empty/invalid/exhausted
	// pool, wrong family, or a non-first fragment on a port-translating rule);
	// the packet is dropped. Summed across bindings and pushed into
	// dataplane.GlobalCtrNATAllocFail (and, with the other enforcement drops,
	// GlobalCtrDrops) by syncBPFCountersLocked so `show security flow
	// statistics` ("NAT allocation failures" / "Packets dropped"), REST
	// (nat_alloc_fails / drops), and Prometheus (xpf_nat_alloc_fails_total /
	// xpf_drops_total) stop reading a permanent 0. omitempty + the Rust serde
	// `default` keep cross-version wire safety (an older helper omits it → 0).
	NatAllocFail uint64 `json:"nat_alloc_fail,omitempty"`
	// #6122: fail-closed drops of an ordinary same-family NAT'd (SNAT /
	// static-NAT / DNAT / NPTv6) NON-FIRST fragment that MISSED the
	// fragment-association cache. Forwarding it untranslated would leak the
	// internal source (SNAT / NPTv6) or the pre-NAT destination (DNAT), so the
	// permitted-but-untranslatable fragment is dropped fail-closed. The
	// same-family sibling of Nat64FragDropped; a plain (no-NAT) fragment matches
	// no rule and is NOT counted here, so ordinary fragmented forwarding is
	// preserved. omitempty + the Rust serde `default` keep cross-version wire
	// safety (an older helper omits it → 0).
	NatFragUntranslatedDropped     uint64 `json:"nat_frag_untranslated_dropped,omitempty"`
	SlowPathPackets                uint64 `json:"slow_path_packets,omitempty"`
	SlowPathBytes                  uint64 `json:"slow_path_bytes,omitempty"`
	SlowPathLocalDeliveryPackets   uint64 `json:"slow_path_local_delivery_packets,omitempty"`
	SlowPathMissingNeighborPackets uint64 `json:"slow_path_missing_neighbor_packets,omitempty"`
	SlowPathNoRoutePackets         uint64 `json:"slow_path_no_route_packets,omitempty"`
	SlowPathNextTablePackets       uint64 `json:"slow_path_next_table_packets,omitempty"`
	// NextTableUnsupportedDrops counts NextTableUnsupported frames dropped
	// fail-closed by the slow-path allow-list (#6664). Since #6664 this is
	// where the signal lives; SlowPathNextTablePackets above stays on the wire
	// for older readers but no longer advances.
	NextTableUnsupportedDrops   uint64 `json:"next_table_unsupported_drops,omitempty"`
	SlowPathForwardBuildPackets uint64 `json:"slow_path_forward_build_packets,omitempty"`
	SlowPathDrops               uint64 `json:"slow_path_drops,omitempty"`
	SlowPathRateLimited         uint64 `json:"slow_path_rate_limited,omitempty"`
	// TunnelEncapUnresolvedDrops counts tunnel-marked inner packets
	// dropped at the slow-path chokepoint / pending-neigh exclusion
	// instead of plaintext kernel reinjection (#1873 R-C/R-E).
	// Wire-additive: older helpers omit it.
	TunnelEncapUnresolvedDrops uint64 `json:"tunnel_encap_unresolved_drops,omitempty"`
	// FabricRedirectUnsendableDrops counts FabricRedirect frames dropped
	// fail-closed because they could not be TX'd to the HA peer (no
	// fabric XSK binding, or the forward-frame build/enqueue failed)
	// instead of being reinjected to the local kernel FIB (#1946).
	// Wire-additive: older helpers omit it.
	FabricRedirectUnsendableDrops   uint64 `json:"fabric_redirect_unsendable_drops,omitempty"`
	KernelRXDropped                 uint64 `json:"kernel_rx_dropped,omitempty"`
	KernelRXInvalidDescs            uint64 `json:"kernel_rx_invalid_descs,omitempty"`
	TXPackets                       uint64 `json:"tx_packets,omitempty"`
	TXBytes                         uint64 `json:"tx_bytes,omitempty"`
	TXErrors                        uint64 `json:"tx_errors,omitempty"`
	TXSharedRecycleUnknownSlotDrops uint64 `json:"tx_shared_recycle_unknown_slot_drops,omitempty"`
	// F-149 (#9904): unknown-slot recycles preserved via the same-region
	// backstop. Subset of TXErrors; wire-additive, older helpers omit it.
	TXSharedRecycleUnknownSlotRescued uint64 `json:"tx_shared_recycle_unknown_slot_rescued,omitempty"`
	RedirectInboxOverflowDrops        uint64 `json:"redirect_inbox_overflow_drops,omitempty"`
	PendingTXLocalOverflowDrops       uint64 `json:"pending_tx_local_overflow_drops,omitempty"`
	TxSubmitErrorDrops                uint64 `json:"tx_submit_error_drops,omitempty"`
	TXCompletions                     uint64 `json:"tx_completions,omitempty"`
	MirroredPackets                   uint64 `json:"mirrored_packets,omitempty"`
	MirroredBytes                     uint64 `json:"mirrored_bytes,omitempty"`
	MirrorDropsNoFrame                uint64 `json:"mirror_drops_no_frame,omitempty"`
	MirrorDropsTXFrameReserve         uint64 `json:"mirror_drops_tx_frame_reserve,omitempty"`
	MirrorDropsNoBinding              uint64 `json:"mirror_drops_no_binding,omitempty"`
	MirrorDropsQueueFull              uint64 `json:"mirror_drops_queue_full,omitempty"`
	MirrorDropsQueueFullSameWorker    uint64 `json:"mirror_drops_queue_full_same_worker,omitempty"`
	MirrorDropsQueueFullCrossWorker   uint64 `json:"mirror_drops_queue_full_cross_worker,omitempty"`
	DirectTXPackets                   uint64 `json:"direct_tx_packets,omitempty"`
	CopyTXPackets                     uint64 `json:"copy_tx_packets,omitempty"`
	InPlaceTXPackets                  uint64 `json:"in_place_tx_packets,omitempty"`
	InPlaceVLANPushDescPackets        uint64 `json:"in_place_vlan_push_desc_packets,omitempty"`
	InPlaceVLANPopDescPackets         uint64 `json:"in_place_vlan_pop_desc_packets,omitempty"`
	InPlaceVLANPushNoHeadroomPackets  uint64 `json:"in_place_vlan_push_no_headroom_packets,omitempty"`
	InPlaceL2MemmoveFallbackPackets   uint64 `json:"in_place_l2_memmove_fallback_packets,omitempty"`
	DirectTXNoFrameFallbackPackets    uint64 `json:"direct_tx_no_frame_fallback_packets,omitempty"`
	DirectTXBuildFallbackPackets      uint64 `json:"direct_tx_build_fallback_packets,omitempty"`
	DirectTXDisallowedFallbackPackets uint64 `json:"direct_tx_disallowed_fallback_packets,omitempty"`
	DebugPendingFillFrames            uint32 `json:"debug_pending_fill_frames,omitempty"`
	DebugSpareFillFrames              uint32 `json:"debug_spare_fill_frames,omitempty"`
	DebugFreeTXFrames                 uint32 `json:"debug_free_tx_frames,omitempty"`
	DebugPendingTXPrepared            uint32 `json:"debug_pending_tx_prepared,omitempty"`
	DebugPendingTXLocal               uint32 `json:"debug_pending_tx_local,omitempty"`
	DebugOutstandingTX                uint32 `json:"debug_outstanding_tx,omitempty"`
	// #1241: low-frequency AF_XDP TX completion-ring availability
	// samples, published from owner-local worker telemetry. Current is
	// the last sampled CQ depth before a reap; Max is the peak in the
	// last debug window.
	TXCompletionRingAvailable    uint32 `json:"tx_completion_ring_available,omitempty"`
	TXCompletionRingAvailableMax uint32 `json:"tx_completion_ring_available_max,omitempty"`
	DebugInFlightRecycles        uint32 `json:"debug_in_flight_recycles,omitempty"`
	// #802/#804: ring-pressure instrumentation mirror fields. See the
	// Rust `BindingStatus` for semantics and write sites. The #804
	// split replaces the pre-#804 `dbg_pending_overflow` field with
	// two distinct wire keys — `dbg_bound_pending_overflow` for the
	// `bound_pending` FIFO evict sites in `tx.rs`, and
	// `dbg_cos_queue_overflow` for binding-lifetime CoS queue drops:
	// admission rejects in `enqueue_cos_item` plus reset-time CoS queue
	// drains. The wire key is historical. A snapshot from a pre-#804
	// helper deserializes both as 0 (standard Go json zero-value),
	// which is the right backward-compat behavior.
	DbgTxRingFull           uint64 `json:"dbg_tx_ring_full,omitempty"`
	DbgSendtoENOBUFS        uint64 `json:"dbg_sendto_enobufs,omitempty"`
	DbgBoundPendingOverflow uint64 `json:"dbg_bound_pending_overflow,omitempty"`
	DbgCoSQueueOverflow     uint64 `json:"dbg_cos_queue_overflow,omitempty"`
	RxFillRingEmptyDescs    uint64 `json:"rx_fill_ring_empty_descs,omitempty"`
	OutstandingTX           uint32 `json:"outstanding_tx,omitempty"`
	// #878: per-binding UMEM total frames and TX-ring depth (set
	// once at worker construction) plus in-flight gauge (republished
	// each ~1s by the worker as a single atomic store from local
	// state — no torn reads). fwdstatus Buffer% =
	//   max(UmemInflightFrames/UmemTotalFrames,
	//       OutstandingTX/TxRingCapacity)
	// aggregated as max across bindings. Zero on UmemTotalFrames
	// means "not yet published" — fwdstatus falls back to the legacy
	// "unknown" display.
	UmemTotalFrames    uint32 `json:"umem_total_frames,omitempty"`
	TxRingCapacity     uint32 `json:"tx_ring_capacity,omitempty"`
	UmemInflightFrames uint32 `json:"umem_inflight_frames,omitempty"`
	// #812: per-queue TX submit→completion latency telemetry. 16 log2-
	// spaced buckets (see Rust `DRAIN_HIST_BUCKETS` wire contract), plus
	// a total completion count and running sum-ns. Emitted on the rich
	// BindingStatus AND projected onto BindingCountersSnapshot so
	// step1-capture consumers can compute per-queue latency
	// distributions without a second join. omitempty keeps forward-
	// compat — a pre-#812 helper that lacks these fields decodes into
	// empty slice / zero u64.
	TxSubmitLatencyHist  []uint64 `json:"tx_submit_latency_hist,omitempty"`
	TxSubmitLatencyCount uint64   `json:"tx_submit_latency_count,omitempty"`
	TxSubmitLatencySumNs uint64   `json:"tx_submit_latency_sum_ns,omitempty"`
	// #825: per-kick `sendto` latency telemetry. 16 log2 buckets
	// (wire-compatible with `tx_submit_latency_hist` /
	// `drain_latency_hist`), plus count, sum-ns, and the
	// EAGAIN/EWOULDBLOCK retry tally (T1 ring-pushback signal per
	// #819 §4.1). omitempty keeps forward-compat — a pre-#825
	// helper that lacks these fields decodes into empty slice /
	// zero uint64.
	TxKickLatencyHist  []uint64 `json:"tx_kick_latency_hist,omitempty"`
	TxKickLatencyCount uint64   `json:"tx_kick_latency_count,omitempty"`
	TxKickLatencySumNs uint64   `json:"tx_kick_latency_sum_ns,omitempty"`
	TxKickRetryCount   uint64   `json:"tx_kick_retry_count,omitempty"`
	// #760 (#1642): the post-drain backup filter drop counters are
	// binding-scoped in the Rust helper (protocol/binding.rs), not
	// queue-scoped. They were previously declared on CoSQueueStatus, a
	// different JSON nesting level, so the Rust binding-level values were
	// silently dropped on unmarshal. JSON tags MUST match Rust serde
	// rename(...) exactly.
	PostDrainBackupCosDrops     uint64    `json:"post_drain_backup_cos_drops,omitempty"`
	PostDrainBackupCosDropBytes uint64    `json:"post_drain_backup_cos_drop_bytes,omitempty"`
	LastHeartbeat               time.Time `json:"last_heartbeat,omitempty"`
	LastError                   string    `json:"last_error,omitempty"`
	LastChange                  time.Time `json:"last_change,omitempty"`
}

// BindingCountersSnapshot is the focused per-binding ring-pressure view
// surfaced on ProcessStatus.PerBinding. It is a strict subset of
// BindingStatus, emitted by the Rust helper so the daemon's poll path
// can deserialize only the triage counters when that's all it needs.
// See the Rust `BindingCountersSnapshot` definition for semantics.
//
// #802.
type BindingCountersSnapshot struct {
	WorkerID         uint32 `json:"worker_id"`
	Ifindex          int    `json:"ifindex,omitempty"`
	QueueID          uint32 `json:"queue_id"`
	DbgTxRingFull    uint64 `json:"dbg_tx_ring_full,omitempty"`
	DbgSendtoENOBUFS uint64 `json:"dbg_sendto_enobufs,omitempty"`
	// #804: split from the pre-#804 `dbg_pending_overflow` field. Two
	// distinct increment sites (bound-pending FIFO evict in tx.rs vs
	// CoS queue admission in enqueue_cos_item) now publish two
	// distinct wire keys so operators can disambiguate. A snapshot
	// from a pre-#804 helper will leave both fields at the Go
	// zero-value — there is no silent re-attribution of the legacy
	// counter. Consumers that want a total across either path should
	// sum these two explicitly.
	DbgBoundPendingOverflow uint64 `json:"dbg_bound_pending_overflow,omitempty"`
	DbgCoSQueueOverflow     uint64 `json:"dbg_cos_queue_overflow,omitempty"`
	RxFillRingEmptyDescs    uint64 `json:"rx_fill_ring_empty_descs,omitempty"`
	OutstandingTX           uint32 `json:"outstanding_tx,omitempty"`
	// #1241: low-frequency AF_XDP TX completion-ring availability
	// gauges mirrored from BindingStatus for fast-poll consumers.
	TXCompletionRingAvailable    uint32 `json:"tx_completion_ring_available,omitempty"`
	TXCompletionRingAvailableMax uint32 `json:"tx_completion_ring_available_max,omitempty"`
	// #878: per-binding capacities pulled through to the leaner
	// snapshot so the daemon's fast poller can compute Buffer%
	// without joining the full BindingStatus. See BindingStatus
	// for full semantics.
	UmemTotalFrames                   uint32 `json:"umem_total_frames,omitempty"`
	TxRingCapacity                    uint32 `json:"tx_ring_capacity,omitempty"`
	UmemInflightFrames                uint32 `json:"umem_inflight_frames,omitempty"`
	TXErrors                          uint64 `json:"tx_errors,omitempty"`
	TXSharedRecycleUnknownSlotDrops   uint64 `json:"tx_shared_recycle_unknown_slot_drops,omitempty"`
	TXSharedRecycleUnknownSlotRescued uint64 `json:"tx_shared_recycle_unknown_slot_rescued,omitempty"`
	TxSubmitErrorDrops                uint64 `json:"tx_submit_error_drops,omitempty"`
	PendingTxLocalOverflowDrops       uint64 `json:"pending_tx_local_overflow_drops,omitempty"`
	MirroredPackets                   uint64 `json:"mirrored_packets,omitempty"`
	MirroredBytes                     uint64 `json:"mirrored_bytes,omitempty"`
	MirrorDropsNoFrame                uint64 `json:"mirror_drops_no_frame,omitempty"`
	MirrorDropsTXFrameReserve         uint64 `json:"mirror_drops_tx_frame_reserve,omitempty"`
	MirrorDropsNoBinding              uint64 `json:"mirror_drops_no_binding,omitempty"`
	MirrorDropsQueueFull              uint64 `json:"mirror_drops_queue_full,omitempty"`
	MirrorDropsQueueFullSameWorker    uint64 `json:"mirror_drops_queue_full_same_worker,omitempty"`
	MirrorDropsQueueFullCrossWorker   uint64 `json:"mirror_drops_queue_full_cross_worker,omitempty"`
	// #812: per-queue TX submit→completion latency histogram, pulled
	// through from BindingStatus so step1-capture consumers can
	// compute per-queue latency distributions without a second
	// query. Layout is 16 log2-spaced buckets (see the Rust
	// `DRAIN_HIST_BUCKETS` wire contract); omitempty on all three
	// preserves forward-compat — a pre-#812 helper that lacks these
	// fields decodes into empty slice / zero u64 without the daemon
	// erroring.
	TxSubmitLatencyHist  []uint64 `json:"tx_submit_latency_hist,omitempty"`
	TxSubmitLatencyCount uint64   `json:"tx_submit_latency_count,omitempty"`
	TxSubmitLatencySumNs uint64   `json:"tx_submit_latency_sum_ns,omitempty"`
	// #825: per-kick `sendto` latency telemetry, pulled through
	// from BindingStatus so step1-capture / P3 consumers can
	// compute per-queue kick-latency distributions without a
	// second query. omitempty on all four preserves forward-compat.
	TxKickLatencyHist  []uint64 `json:"tx_kick_latency_hist,omitempty"`
	TxKickLatencyCount uint64   `json:"tx_kick_latency_count,omitempty"`
	TxKickLatencySumNs uint64   `json:"tx_kick_latency_sum_ns,omitempty"`
	TxKickRetryCount   uint64   `json:"tx_kick_retry_count,omitempty"`
	// #918: per-set LRU collision-eviction counter, brought through
	// to the lean snapshot for fast-poll consumers that need the
	// flow-cache thrash signal. Default keeps pre-#918 helpers parseable.
	FlowCacheCollisionEvictions uint64 `json:"flow_cache_collision_evictions,omitempty"`
	// #1219: distinct active flow count snapshot for fairness harness.
	// See BindingStatus.ActiveFlowCount.
	ActiveFlowCount uint32 `json:"active_flow_count,omitempty"`
	// FlowCacheCapacity mirrors BindingStatus for fast-poll consumers.
	FlowCacheCapacity uint32 `json:"flow_cache_capacity,omitempty"`
	// #941 Work item D / #943: V_min throttle counters. The lean
	// per_binding view is what fast-poll consumers (mouse-latency
	// orchestrator, MQFQ diagnostics) read; without these here, V_min
	// observability stops at the rich BindingStatus and ProcessStatus.per_binding
	// projects zeros even when the atomics flushed real values.
	VMinThrottleHardCapOverrides uint64 `json:"v_min_throttle_hard_cap_overrides,omitempty"`
	VMinThrottles                uint64 `json:"v_min_throttles,omitempty"`
	// #hb166 T-6(a): V_min suspended-batch count (per_binding lean view).
	VMinSuspendedBatches uint64 `json:"v_min_suspended_batches,omitempty"`
}

type InjectPacketRequest struct {
	Slot                 uint32  `json:"slot"`
	PacketLength         uint32  `json:"packet_length,omitempty"`
	AddrFamily           uint8   `json:"addr_family,omitempty"`
	Protocol             uint8   `json:"protocol,omitempty"`
	ConfigGeneration     uint64  `json:"config_generation,omitempty"`
	FIBGeneration        uint32  `json:"fib_generation,omitempty"`
	MetadataValid        bool    `json:"metadata_valid"`
	DestinationIP        string  `json:"destination_ip,omitempty"`
	EmitOnWire           bool    `json:"emit_on_wire,omitempty"`
	TupleMetadataVersion int     `json:"tuple_metadata_version,omitempty"`
	SourceIP             string  `json:"source_ip,omitempty"`
	SourcePort           *uint16 `json:"source_port,omitempty"`
	DestinationPort      *uint16 `json:"destination_port,omitempty"`
}
