package userspace

type SourceNATPoolStatus struct {
	RuleName                         string `json:"rule_name,omitempty"`
	PoolName                         string `json:"pool_name,omitempty"`
	AddressCount                     int    `json:"address_count,omitempty"`
	PortLow                          uint16 `json:"port_low,omitempty"`
	PortHigh                         uint16 `json:"port_high,omitempty"`
	PersistentNAT                    bool   `json:"persistent_nat,omitempty"`
	PersistentNATPermitAnyRemoteHost bool   `json:"persistent_nat_permit_any_remote_host,omitempty"`
	// PersistentNATPermit carries the full three-way Junos `persistent-nat
	// permit` mode (#3193): "any-remote-host" / "target-host" /
	// "target-host-port". Empty from an older helper that only set the
	// binary PersistentNATPermitAnyRemoteHost flag.
	PersistentNATPermit            string `json:"persistent_nat_permit,omitempty"`
	PersistentNATInactivityTimeout int    `json:"persistent_nat_inactivity_timeout,omitempty"`
	LiveFlows                      uint64 `json:"live_flows,omitempty"`
	UsedPorts                      uint64 `json:"used_ports,omitempty"`
	PersistentLeases               uint64 `json:"persistent_leases,omitempty"`
	MaxTrackedFlows                uint64 `json:"max_tracked_flows,omitempty"`
	AllocationsTotal               uint64 `json:"allocations_total,omitempty"`
	ReusesTotal                    uint64 `json:"reuses_total,omitempty"`
	ExhaustionTotal                uint64 `json:"exhaustion_total,omitempty"`
	// #9902 F-026: the reporting allocator's instance id. Same id ⇒ same
	// counter instance (deltas comparable); changed id ⇒ the allocator was
	// rebuilt (rebaseline silently). 0 from a helper older than the field.
	// JSON tag MUST match the Rust serde rename(...) exactly
	// (protocol/nat.rs).
	AllocatorID uint64 `json:"allocator_id,omitempty"`
	// #8447: persistent-NAT admissions that produced a translation, and those
	// that returned a failure instead. Read as a PAIR for the same reason the
	// lock counters below are: a decline count of zero cannot tell "nothing
	// was declined" from "this path never ran", and only a non-zero admitted
	// count separates them. Zero from an older helper that predates the
	// counters. JSON tags MUST match the Rust serde names.
	PersistentAdmittedTotal uint64 `json:"persistent_admitted_total,omitempty"`
	PersistentDeclinedTotal uint64 `json:"persistent_declined_total,omitempty"`
	// #4800: acquisitions of this pool's residual live-state mutex on the
	// helper's production allocate/reserve/release/rollback/GC paths, and
	// the subset that found it already held by another worker. The
	// connection-rate harness reads the PAIR: a contended count without
	// its denominator cannot tell "the allocator mutex saturated" from
	// "the allocator ran hot but never blocked". Zero from an older helper
	// that predates the counters. JSON tags MUST match the Rust serde
	// rename(...) exactly (protocol/nat.rs).
	LiveLockAcquisitionsTotal uint64 `json:"live_lock_acquisitions_total,omitempty"`
	LiveLockContendedTotal    uint64 `json:"live_lock_contended_total,omitempty"`
	// #9392: the recycled-phase walk cost of the helper's port allocator,
	// summed over this pool's addresses -- tokens POPPED off the per-address
	// FIFO and the number of recycled-phase WALKS that popped them.
	//
	// Read as pops/walks. ~1 is healthy: a freed token was claimable at the
	// head. Materially above 1 means the #9327 cliff is REACHED on this pool --
	// K out-of-band-occupied tokens sit ahead of F free ones and retained
	// tokens are pushed to the BACK, so a full cycle costs (K+F)/F pops per
	// claim and degrades to K+1 as F -> 1, i.e. worst exactly as an address
	// approaches exhaustion. #9327 proved that mechanism on a fixture and could
	// not answer whether production reaches it, because the pop counter was
	// Rust-side `#[cfg(test)]`.
	//
	// ADDED, never redefined: the helper and the daemon roll independently.
	// Zero from an older helper that predates the counters -- and `show
	// security nat source pool` distinguishes that from a measured zero by
	// requiring a non-zero WALK count before printing a ratio. JSON tags MUST
	// match the Rust serde rename(...) exactly (protocol/nat.rs).
	RecycleScanPopsTotal  uint64 `json:"recycle_scan_pops_total,omitempty"`
	RecycleScanWalksTotal uint64 `json:"recycle_scan_walks_total,omitempty"`
}

type CoSInterfaceStatus struct {
	Ifindex             int     `json:"ifindex,omitempty"`
	InterfaceName       string  `json:"interface_name,omitempty"`
	OwnerWorkerID       *uint32 `json:"owner_worker_id,omitempty"`
	ShapingRateBytes    uint64  `json:"shaping_rate_bytes,omitempty"`
	BurstBytes          uint64  `json:"burst_bytes,omitempty"`
	WorkerInstances     int     `json:"worker_instances,omitempty"`
	NonemptyQueues      int     `json:"nonempty_queues,omitempty"`
	RunnableQueues      int     `json:"runnable_queues,omitempty"`
	TimerLevel0Sleepers int     `json:"timer_level0_sleepers,omitempty"`
	TimerLevel1Sleepers int     `json:"timer_level1_sleepers,omitempty"`
	// #1628: per-interface waterfill-selector trace counters. JSON tags
	// MUST match the Rust serde rename(...) byte-for-byte (protocol/cos.rs).
	// WaterfillEpochs / WaterfillPhase1BudgetBreaks are SUMMED across
	// workers. WaterfillMinEpochsPerWorker is the coordinator MIN of each
	// worker's per-binding MIN over bindings with active exact-guarantee
	// backlog; a LOW value vs Epochs flags a single stalled selector, and
	// 0 is a HARD lock-in (backlogged binding, zero epochs completed).
	// math.MaxUint64 is the "no active-backlog candidate" (idle) sentinel,
	// preserved through aggregation so it never collides with a real 0;
	// Prometheus suppresses the MAX gauge and the CLI renders it "none".
	WaterfillEpochs             uint64           `json:"waterfill_epochs,omitempty"`
	WaterfillPhase1BudgetBreaks uint64           `json:"waterfill_phase1_budget_breaks,omitempty"`
	WaterfillMinEpochsPerWorker uint64           `json:"waterfill_min_epochs_per_worker,omitempty"`
	Queues                      []CoSQueueStatus `json:"queues,omitempty"`
}

type ThreeColorPolicerStatus struct {
	ID            uint32 `json:"id,omitempty"`
	Name          string `json:"name,omitempty"`
	Mode          string `json:"mode,omitempty"`
	ColorBlind    bool   `json:"color_blind,omitempty"`
	GreenPackets  uint64 `json:"green_packets,omitempty"`
	GreenBytes    uint64 `json:"green_bytes,omitempty"`
	YellowPackets uint64 `json:"yellow_packets,omitempty"`
	YellowBytes   uint64 `json:"yellow_bytes,omitempty"`
	RedPackets    uint64 `json:"red_packets,omitempty"`
	RedBytes      uint64 `json:"red_bytes,omitempty"`
	DropPackets   uint64 `json:"drop_packets,omitempty"`
	DropBytes     uint64 `json:"drop_bytes,omitempty"`
}

type CoSQueueStatus struct {
	QueueID           int     `json:"queue_id,omitempty"`
	OwnerWorkerID     *uint32 `json:"owner_worker_id,omitempty"`
	ForwardingClass   string  `json:"forwarding_class,omitempty"`
	Priority          int     `json:"priority,omitempty"`
	Exact             bool    `json:"exact,omitempty"`
	GuaranteeEnabled  *bool   `json:"guarantee_enabled,omitempty"`
	TransmitRateBytes uint64  `json:"transmit_rate_bytes,omitempty"`
	// BufferBytes is total queue capacity for this status row. Rust status
	// aggregation sums it with QueuedBytes across worker/binding instances.
	BufferBytes         uint64 `json:"buffer_bytes,omitempty"`
	WorkerInstances     int    `json:"worker_instances,omitempty"`
	QueuedPackets       uint64 `json:"queued_packets,omitempty"`
	QueuedBytes         uint64 `json:"queued_bytes,omitempty"`
	RunnableInstances   int    `json:"runnable_instances,omitempty"`
	ParkedInstances     int    `json:"parked_instances,omitempty"`
	NextWakeupTick      uint64 `json:"next_wakeup_tick,omitempty"`
	SurplusDeficitBytes uint64 `json:"surplus_deficit_bytes,omitempty"`
	// #710/#718: per-queue admission-path counters aggregated across
	// worker instances by the Rust coordinator. JSON tags MUST match the
	// Rust serde rename(...) exactly — the wire format is the contract.
	AdmissionFlowShareDrops uint64 `json:"admission_flow_share_drops,omitempty"`
	AdmissionBufferDrops    uint64 `json:"admission_buffer_drops,omitempty"`
	AdmissionEcnMarked      uint64 `json:"admission_ecn_marked,omitempty"`
	// #1642: shaper starvation / TX-ring-pressure diagnostics the Rust
	// helper serializes on CoSQueueStatus (protocol/cos.rs). These are
	// distinct from the DrainPark* fields below (which count drain-loop
	// parks). JSON tags MUST match Rust serde rename(...) exactly.
	RootTokenStarvationParks  uint64 `json:"root_token_starvation_parks,omitempty"`
	QueueTokenStarvationParks uint64 `json:"queue_token_starvation_parks,omitempty"`
	TxRingFullSubmitStalls    uint64 `json:"tx_ring_full_submit_stalls,omitempty"`
	// #1304: Rust-owned equal-flow enforcement telemetry. The
	// measurement-only xpf_fairness_equal_flow_* gauges remain advisory;
	// these fields describe the opt-in shared v8 queue-lease suppressor.
	EqualFlowEnforcement              bool   `json:"equal_flow_enforcement,omitempty"`
	EqualFlowEnforced                 bool   `json:"equal_flow_enforced,omitempty"`
	EqualFlowTargetPerFlowBPS         uint64 `json:"equal_flow_target_per_flow_bps,omitempty"`
	EqualFlowMaxWorkerCapBytes        uint64 `json:"equal_flow_max_worker_cap_bytes,omitempty"`
	EqualFlowCapHitEvents             uint64 `json:"equal_flow_cap_hit_events,omitempty"`
	EqualFlowSuppressedGrantBytes     uint64 `json:"equal_flow_suppressed_grant_bytes,omitempty"`
	EqualFlowStaleOrTagMismatchEvents uint64 `json:"equal_flow_stale_or_tag_mismatch_events,omitempty"`
	EqualFlowFailOpenReason           string `json:"equal_flow_fail_open_reason,omitempty"`
	// EqualFlowTargetPolicy (#1746): active target-policy label
	// ("slowest" | "mean" | "ideal-share"); populated only for
	// equal-flow leases, empty otherwise.
	EqualFlowTargetPolicy string `json:"equal_flow_target_policy,omitempty"`
	// #1863 Step-0: per-worker cumulative v8 queue-lease claim flow —
	// requested bytes (every acquire_v8 ask, granted or not) and
	// granted bytes, indexed by worker id. Empty for legacy/non-v8
	// leases. JSON tags MUST match the Rust serde rename(...) in
	// protocol/cos.rs byte-for-byte.
	LeaseV8WorkerRequestedBytes []uint64 `json:"lease_v8_worker_requested_bytes,omitempty"`
	LeaseV8WorkerGrantedBytes   []uint64 `json:"lease_v8_worker_granted_bytes,omitempty"`
	// #709 / #751: owner-profile telemetry. Populated only when an
	// exact queue can inherit a binding-scoped owner profile
	// unambiguously; zero for shared_exact, non-exact, and ambiguous
	// multi-owner-local shapes. See docs/709-owner-hotspot-plan.md for
	// the decision tree these counters drive. JSON tags MUST match Rust
	// serde rename(...) byte-for-byte.
	//
	// DrainLatencyHist and RedirectAcquireHist are power-of-two ns
	// bucketed (see Rust `bucket_index_for_ns`): index 0 is < 1 µs,
	// index N >= 1 is [2^(N+9), 2^(N+10)) ns, index 15 saturates at
	// >= 2^24 ns (~16 ms).
	ActiveFlowBucketsPeak uint64 `json:"active_flow_buckets_peak,omitempty"`
	FlowFair              bool   `json:"flow_fair,omitempty"`
	// #1830 (g): bucket-vs-flow occupancy telemetry. JSON tags MUST
	// match the Rust serde rename(...) in protocol/cos.rs exactly.
	// FlowFairBucketsOccupied is the instantaneous occupied
	// (backlogged) SFQ bucket count summed across workers;
	// FlowFairFlowsActive is the flow-cache active-window (~650 ms)
	// distinct-flow count mapped to this queue, summed across workers.
	// The flows/buckets ratio distinguishes hash-collision unfairness
	// (ratio persistently > 1 while continuously backlogged) from
	// demand unfairness — see the INTERPRETATION contract on the Rust
	// CoSQueueStatus.
	FlowFairBucketsOccupied uint64   `json:"flow_fair_buckets_occupied,omitempty"`
	FlowFairFlowsActive     uint64   `json:"flow_fair_flows_active,omitempty"`
	DrainLatencyHist        []uint64 `json:"drain_latency_hist,omitempty"`
	DrainInvocations        uint64   `json:"drain_invocations,omitempty"`
	DrainNoopInvocations    uint64   `json:"drain_noop_invocations,omitempty"`
	RedirectAcquireHist     []uint64 `json:"redirect_acquire_hist,omitempty"`
	OwnerPPS                uint64   `json:"owner_pps,omitempty"`
	PeerPPS                 uint64   `json:"peer_pps,omitempty"`
	// #760 overshoot-hunt instrumentation. DrainSentBytes /
	// DrainParkRootTokens / DrainParkQueueTokens are queue-scoped.
	// PostDrainBackupBytes is binding-scoped (same row as
	// OwnerPPS/PeerPPS). See Rust `CoSQueueStatus` for field
	// semantics and write-site locations.
	DrainSentBytes          uint64 `json:"drain_sent_bytes,omitempty"`
	DrainGuaranteeSentBytes uint64 `json:"drain_guarantee_sent_bytes,omitempty"`
	DrainSurplusSentBytes   uint64 `json:"drain_surplus_sent_bytes,omitempty"`
	// #1369: non-exact bytes sent while exact queue demand existed on
	// the same shaped interface. A rising delta means best-effort or
	// uncapped service was competing with exact queues.
	DrainNonExactSentBytesWhileExactBacklogged uint64 `json:"drain_nonexact_sent_bytes_while_exact_backlogged,omitempty"`
	DrainParkRootTokens                        uint64 `json:"drain_park_root_tokens,omitempty"`
	DrainParkQueueTokens                       uint64 `json:"drain_park_queue_tokens,omitempty"`
	PostDrainBackupBytes                       uint64 `json:"post_drain_backup_bytes,omitempty"`
	DrainSentBytesShapedUnconditional          uint64 `json:"drain_sent_bytes_shaped_unconditional,omitempty"`
	// #1628: per-class waterfill-selector trace counters, aggregated across
	// worker instances. Zero on the Proportional (legacy RR) path. JSON
	// tags MUST match Rust serde rename(...) byte-for-byte. These are
	// EVIDENCE to combine with QueuedBytes + *StarvationParks, not
	// standalone fingerprints (see Rust CoSQueueWaterfillCounters).
	WaterfillPhase1Admissions uint64 `json:"waterfill_phase1_admissions,omitempty"`
	WaterfillPhase2Admissions uint64 `json:"waterfill_phase2_admissions,omitempty"`
	WaterfillEligibleVisits   uint64 `json:"waterfill_eligible_visits,omitempty"`
	// hb166 T-2: Phase-1 honored selections that made ZERO TX progress and
	// had their budget debit + honored bit refunded. Climbing here with
	// flat WaterfillPhase1Admissions = TX-ring pressure eating a small
	// class's guarantee pass. Additive field: a pre-hb166 daemon that omits
	// it decodes to 0 here regardless of omitempty (a missing JSON field
	// unmarshals to the zero value), so this is rolling-upgrade safe;
	// omitempty only suppresses emitting it on the wire when 0.
	WaterfillPhase1SelectedNoProgress uint64 `json:"waterfill_phase1_selected_no_progress,omitempty"`
	// #1829 Phase 1: dequeue-time sojourn telemetry. JSON tags MUST
	// match the Rust serde rename(...) in protocol/cos.rs exactly.
	// All three are MAX-merged across worker instances and across
	// workers (worst instance — see the AGGREGATION contract on the
	// Rust CoSQueueStatus). SojournWindowedMinNS is the #1829 gate
	// metric: the minimum sojourn over the last 1-2 100 ms windows
	// (CoDel's standing-queue estimator); it reads 0 when the queue
	// has not popped for >= 2 windows at snapshot time. SojournPeakNS
	// is the lifetime maximum; SojournEwmaNS is a shift-add EWMA
	// (alpha = 1/8) over pops — both supporting context only (biased
	// high by scheduler service gaps).
	SojournEwmaNS        uint64 `json:"sojourn_ewma_ns,omitempty"`
	SojournPeakNS        uint64 `json:"sojourn_peak_ns,omitempty"`
	SojournWindowedMinNS uint64 `json:"sojourn_windowed_min_ns,omitempty"`
	// #1642: post_drain_backup_cos_drops / _cos_drop_bytes were on this
	// struct, but the Rust helper serializes them on BindingStatus
	// (protocol/binding.rs), a different JSON nesting level. The Rust
	// binding-level values never decoded into CoSQueueStatus, so they were
	// silently dropped. They now live on BindingStatus to match the source.
	// (PostDrainBackupBytes above is correct here — Rust does serialize
	// post_drain_backup_bytes on CoSQueueStatus.)
}

type FirewallFilterTermCounterStatus struct {
	Family     string `json:"family,omitempty"`
	FilterName string `json:"filter_name,omitempty"`
	TermName   string `json:"term_name,omitempty"`
	Packets    uint64 `json:"packets,omitempty"`
	Bytes      uint64 `json:"bytes,omitempty"`
}

// PolicyRuleCounterStatus is one per-rule security-policy hit counter reported
// by the userspace dataplane, keyed by the stable RuleID string
// (`from->to/name`; the reserved "default-policy" id carries the implicit
// default-policy hits, #3363). Packets/Bytes are cumulative since helper start
// (or last `clear security policies hit-count`).
//
// #3451: Packets and Bytes are read from two independent relaxed atomics in the
// helper, so each total is exact but the PAIR is only eventually consistent — a
// single snapshot may pair a freshly bumped packet count with a byte count that
// has not yet absorbed that packet (skew bounded by one in-flight per-worker
// batch). Consumers that derive a bytes/packets ratio (CLI, REST, Prometheus)
// must treat it as approximate at sub-poll granularity; the fields reconcile
// over any poll interval. See the Rust `PolicyRuleCounter` type doc.
type PolicyRuleCounterStatus struct {
	RuleID  string `json:"rule_id,omitempty"`
	Packets uint64 `json:"packets,omitempty"`
	Bytes   uint64 `json:"bytes,omitempty"`
}

// NATRuleCounterStatus is one per-rule NAT translation hit counter reported
// by the userspace dataplane (#2218). CounterID is the compiler-assigned NAT
// rule counter ID (stable key-derived hash; matches CompileResult.NATCounterIDs
// and the CounterID stamped on the SNAT/DNAT/static rule snapshots, #2255).
// Packets/Bytes are cumulative since helper start (or last clear).
type NATRuleCounterStatus struct {
	CounterID uint32 `json:"counter_id,omitempty"`
	Packets   uint64 `json:"packets,omitempty"`
	Bytes     uint64 `json:"bytes,omitempty"`
}

// ZoneTrafficCounterStatus is one per-zone traffic-volume row reported by the
// userspace dataplane inside ProcessStatus.ZoneTrafficCounters (#3651). ZoneID
// is the stable name-hash zone id (StableZoneID / ZoneSnapshot.id); ingress
// totals count packets/bytes that entered the firewall through an interface in
// the zone, egress totals count packets/bytes that left through one. Totals are
// cumulative since helper start (or the last clear_zone_counters IPC). The Rust
// struct is ZoneTrafficCounterStatus (protocol/control.rs) with matching serde
// rename tags.
type ZoneTrafficCounterStatus struct {
	ZoneID         uint16 `json:"zone_id,omitempty"`
	IngressPackets uint64 `json:"ingress_packets,omitempty"`
	IngressBytes   uint64 `json:"ingress_bytes,omitempty"`
	EgressPackets  uint64 `json:"egress_packets,omitempty"`
	EgressBytes    uint64 `json:"egress_bytes,omitempty"`
}

// ZoneFloodCounterStatus is one per-zone flood-EVENT row reported by the
// userspace dataplane inside ProcessStatus.ZoneFloodCounters (#3651) -- the
// sibling of ZoneTrafficCounterStatus for the other per-zone counter family.
// ZoneID is the stable name-hash zone id (StableZoneID / ZoneSnapshot.id); the
// three counts are cumulative screen DROPS attributed to that zone for the
// syn-flood, icmp-flood, and udp-flood checks, since helper start (or the last
// clear_flood_counters IPC). syncBPFCountersLocked maps them onto
// dataplane.FloodState SynCount/ICMPCount/UDPCount. The Rust struct is
// ZoneFloodCounterStatus (protocol/control.rs) with matching serde rename tags.
type ZoneFloodCounterStatus struct {
	ZoneID          uint16 `json:"zone_id,omitempty"`
	SynFloodEvents  uint64 `json:"syn_flood_events,omitempty"`
	ICMPFloodEvents uint64 `json:"icmp_flood_events,omitempty"`
	UDPFloodEvents  uint64 `json:"udp_flood_events,omitempty"`
}

type CoSActiveFlowCountStatus struct {
	Ifindex         int    `json:"ifindex,omitempty"`
	QueueID         uint8  `json:"queue_id,omitempty"`
	WorkerID        uint32 `json:"worker_id,omitempty"`
	ActiveFlowCount uint32 `json:"active_flow_count,omitempty"`
}
