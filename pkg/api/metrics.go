package api

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// xpfCollector implements prometheus.Collector, reading BPF maps on each scrape.
type xpfCollector struct {
	srv *Server
	mu  sync.Mutex

	// Global counters
	packetsTotal         *prometheus.Desc
	dropsTotal           *prometheus.Desc
	sessionsCreatedTotal *prometheus.Desc
	sessionsClosedTotal  *prometheus.Desc
	screenDropsTotal     *prometheus.Desc
	policyDeniesTotal    *prometheus.Desc
	natAllocFailsTotal   *prometheus.Desc
	hostInboundDeny      *prometheus.Desc
	tcEgressPacketsTotal *prometheus.Desc
	syncookieTotal       *prometheus.Desc
	flowCacheTotal       *prometheus.Desc

	// Interface counters
	ifacePacketsTotal *prometheus.Desc
	ifaceBytesTotal   *prometheus.Desc

	// Zone counters
	zonePacketsTotal *prometheus.Desc
	zoneBytesTotal   *prometheus.Desc

	// Policy counters
	policyHitsTotal *prometheus.Desc

	// Filter counters
	filterHitsTotal *prometheus.Desc
	// Userspace three-color policer counters.
	threeColorPolicerPacketsTotal *prometheus.Desc
	threeColorPolicerBytesTotal   *prometheus.Desc
	threeColorPolicerDropsTotal   *prometheus.Desc
	threeColorPolicerDropBytes    *prometheus.Desc

	// Session gauges (from GC)
	sessionsActive      *prometheus.Desc
	sessionsEstablished *prometheus.Desc
	sessionsIPv4        *prometheus.Desc
	sessionsIPv6        *prometheus.Desc
	sessionsSNAT        *prometheus.Desc
	sessionsDNAT        *prometheus.Desc
	gcSweepDuration     *prometheus.Desc

	// NAT pool utilization
	natPoolUsedPorts         *prometheus.Desc
	natPoolTotalPorts        *prometheus.Desc
	natPoolDeterministicInfo *prometheus.Desc

	// DHCP lease gauge
	dhcpLeasesActive *prometheus.Desc

	// System metrics
	sysCPUUser   *prometheus.Desc
	sysCPUSystem *prometheus.Desc
	sysMemTotal  *prometheus.Desc
	sysMemAvail  *prometheus.Desc
	daemonUptime *prometheus.Desc
	daemonMemRSS *prometheus.Desc

	// #709: CoS owner-profile telemetry (userspace dataplane only).
	// Cardinality estimate per plan §5: num_queues (≤ 64) × num_interfaces
	// (≤ 8) × DRAIN_HIST_BUCKETS (16) = ≤ 8192 series for each of the
	// two histograms. The two gauges (owner_pps, peer_pps) add 512
	// more. Total ≤ 16896 series — within the envelope the plan
	// flagged.
	cosDrainLatencyBucket    *prometheus.Desc
	cosDrainInvocationsTotal *prometheus.Desc
	cosRedirectAcquireBucket *prometheus.Desc
	cosOwnerPPS              *prometheus.Desc
	cosPeerPPS               *prometheus.Desc
	// #1369: queue-scoped drain-phase counters. Unlike the owner
	// latency profile, these are meaningful for non-exact queues
	// too, because they expose whether best-effort/uncapped traffic
	// consumed service while exact queues still had backlog.
	cosDrainGuaranteeSentBytes                    *prometheus.Desc
	cosDrainSurplusSentBytes                      *prometheus.Desc
	cosDrainNonExactSentBytesWhileExactBacklogged *prometheus.Desc
	// #1304: Rust-owned opt-in equal-flow enforcement telemetry for
	// shared v8 CoS queue leases. Kept separate from the
	// measurement-only xpf_fairness_equal_flow_* estimator gauges.
	cosEqualFlowEnforcementEnabled       *prometheus.Desc
	cosEqualFlowEnforced                 *prometheus.Desc
	cosEqualFlowTargetPerFlowBPS         *prometheus.Desc
	cosEqualFlowMaxWorkerCapBytes        *prometheus.Desc
	cosEqualFlowCapHitEvents             *prometheus.Desc
	cosEqualFlowSuppressedGrantBytes     *prometheus.Desc
	cosEqualFlowStaleOrTagMismatchEvents *prometheus.Desc
	cosEqualFlowFailOpen                 *prometheus.Desc
	// #869: per-worker busy/idle runtime counters.
	workerWallSecs                           *prometheus.Desc
	workerActiveSecs                         *prometheus.Desc
	workerIdleSpinSecs                       *prometheus.Desc
	workerIdleBlockSecs                      *prometheus.Desc
	workerThreadCPUSecs                      *prometheus.Desc
	workerThreadCPUSecsLast60s               *prometheus.Desc
	workerThreadCPUWindowSecs                *prometheus.Desc
	workerWorkLoops                          *prometheus.Desc
	workerIdleLoops                          *prometheus.Desc
	workerCoSQueueLeaseAcquireV8Calls        *prometheus.Desc
	workerCoSQueueLeaseAcquireV8GrantedBytes *prometheus.Desc
	// #1379: daemon-side userspace event-stream transport counters.
	userspaceEventStreamFramesTotal          *prometheus.Desc
	userspaceEventStreamProducerFramesTotal  *prometheus.Desc
	userspaceEventStreamDecodeErrorsTotal    *prometheus.Desc
	userspaceEventStreamSequenceGapsTotal    *prometheus.Desc
	userspaceEventStreamDataplaneEventsTotal *prometheus.Desc
	userspaceEventStreamDataplaneDropsTotal  *prometheus.Desc
	userspaceEventStreamUnknownDropsTotal    *prometheus.Desc
	// #925 Phase 2: liveness gauge for the supervisor's catch_unwind
	// state. 1 = worker has panicked and the supervisor has caught it;
	// 0 = healthy. Set-only in Phase 1 (cleared by daemon restart).
	workerDead *prometheus.Desc
	// #1219: snapshot per-binding distinct active flow count for the
	// fairness harness (read by test/incus/fairness-harness.sh ->
	// fairness-eval to compute Cstruct + observed_CoV per
	// docs/fairness-regimes.md). Refreshed at the helper's ~65ms
	// debug-state tick.
	bindingActiveFlowCount *prometheus.Desc
	// #1241: per-binding AF_XDP TX completion service telemetry.
	// These signals let fairness measurements distinguish scheduler/RSS
	// skew from per-queue completion-ring service asymmetry.
	bindingTXCompletions                *prometheus.Desc
	bindingTXCompletionRingAvailable    *prometheus.Desc
	bindingTXCompletionRingAvailableMax *prometheus.Desc
	// #1248: class-specific active flow distribution by egress CoS
	// queue. This is the production/mixed-workload {a_i} source.
	cosActiveFlowCount *prometheus.Desc
	// #1247: production RSS/workload health gauges derived from the
	// same per-CoS {a_i} snapshot. These expose the structural ceiling
	// without adding packet-path state or global atomics.
	fairnessCstruct                           *prometheus.Desc
	fairnessActiveWorkers                     *prometheus.Desc
	fairnessActiveFlows                       *prometheus.Desc
	fairnessMaxWorkerFlowShare                *prometheus.Desc
	fairnessCoSCountsTruncated                *prometheus.Desc
	fairnessRSSExpectation                    *prometheus.Desc
	fairnessRSSExpectationValue               *prometheus.Desc
	fairnessRSSSkewViolation                  *prometheus.Desc
	fairnessSaturated                         *prometheus.Desc
	fairnessObservedCoV                       *prometheus.Desc
	fairnessStarvedFlows                      *prometheus.Desc
	fairnessEqualFlowEstimateValid            *prometheus.Desc
	fairnessEqualFlowSampledActiveWorkers     *prometheus.Desc
	fairnessEqualFlowUnsampledActiveWorkers   *prometheus.Desc
	fairnessEqualFlowTargetPerFlowBPS         *prometheus.Desc
	fairnessEqualFlowObservedBPS              *prometheus.Desc
	fairnessEqualFlowCappedBPS                *prometheus.Desc
	fairnessEqualFlowSuppressedBPS            *prometheus.Desc
	fairnessEqualFlowThroughputLossRatio      *prometheus.Desc
	fairnessEqualFlowWorkerObservedBPS        *prometheus.Desc
	fairnessEqualFlowWorkerObservedPerFlowBPS *prometheus.Desc
	fairnessEqualFlowWorkerCapBPS             *prometheus.Desc
	fairnessEqualFlowWorkerSuppressedBPS      *prometheus.Desc
	fairnessThroughputWindow                  *dpuserspace.FairnessThroughputWindow
}

func newCollector(srv *Server) *xpfCollector {
	return &xpfCollector{
		srv: srv,

		packetsTotal: prometheus.NewDesc(
			"xpf_packets_total",
			"Total packets processed.",
			[]string{"direction"}, nil,
		),
		dropsTotal: prometheus.NewDesc(
			"xpf_drops_total",
			"Total packets dropped.",
			nil, nil,
		),
		sessionsCreatedTotal: prometheus.NewDesc(
			"xpf_sessions_created_total",
			"Total sessions created.",
			nil, nil,
		),
		sessionsClosedTotal: prometheus.NewDesc(
			"xpf_sessions_closed_total",
			"Total sessions closed.",
			nil, nil,
		),
		screenDropsTotal: prometheus.NewDesc(
			"xpf_screen_drops_total",
			"Total packets dropped by screen/IDS checks.",
			nil, nil,
		),
		policyDeniesTotal: prometheus.NewDesc(
			"xpf_policy_denies_total",
			"Total packets denied by policy.",
			nil, nil,
		),
		natAllocFailsTotal: prometheus.NewDesc(
			"xpf_nat_alloc_failures_total",
			"Total NAT port allocation failures.",
			nil, nil,
		),
		hostInboundDeny: prometheus.NewDesc(
			"xpf_host_inbound_denies_total",
			"Total host-inbound traffic denials.",
			nil, nil,
		),
		tcEgressPacketsTotal: prometheus.NewDesc(
			"xpf_tc_egress_packets_total",
			"Total TC egress packets processed.",
			nil, nil,
		),
		syncookieTotal: prometheus.NewDesc(
			"xpf_screen_syncookie_total",
			"SYN cookie counters by type.",
			[]string{"type"}, nil,
		),
		flowCacheTotal: prometheus.NewDesc(
			"xpf_flow_cache_total",
			"Flow cache counters by type (IPv4 + IPv6).",
			[]string{"type"}, nil,
		),
		ifacePacketsTotal: prometheus.NewDesc(
			"xpf_interface_packets_total",
			"Total packets per interface.",
			[]string{"iface", "direction"}, nil,
		),
		ifaceBytesTotal: prometheus.NewDesc(
			"xpf_interface_bytes_total",
			"Total bytes per interface.",
			[]string{"iface", "direction"}, nil,
		),
		zonePacketsTotal: prometheus.NewDesc(
			"xpf_zone_packets_total",
			"Total packets per zone.",
			[]string{"zone", "direction"}, nil,
		),
		zoneBytesTotal: prometheus.NewDesc(
			"xpf_zone_bytes_total",
			"Total bytes per zone.",
			[]string{"zone", "direction"}, nil,
		),
		policyHitsTotal: prometheus.NewDesc(
			"xpf_policy_hits_total",
			"Total policy rule hits.",
			[]string{"from_zone", "to_zone", "rule"}, nil,
		),
		filterHitsTotal: prometheus.NewDesc(
			"xpf_filter_hits_total",
			"Total firewall filter term hits.",
			[]string{"filter", "family", "term"}, nil,
		),
		threeColorPolicerPacketsTotal: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_packets_total",
			"Userspace three-color policer packets by resulting color.",
			[]string{"policer", "color"}, nil,
		),
		threeColorPolicerBytesTotal: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_bytes_total",
			"Userspace three-color policer bytes by resulting color.",
			[]string{"policer", "color"}, nil,
		),
		threeColorPolicerDropsTotal: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_drops_total",
			"Userspace three-color policer packets dropped by policer treatment.",
			[]string{"policer"}, nil,
		),
		threeColorPolicerDropBytes: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_drop_bytes_total",
			"Userspace three-color policer bytes dropped by policer treatment.",
			[]string{"policer"}, nil,
		),
		sessionsActive: prometheus.NewDesc(
			"xpf_sessions_active",
			"Current number of active session entries.",
			nil, nil,
		),
		sessionsEstablished: prometheus.NewDesc(
			"xpf_sessions_established",
			"Current number of established sessions.",
			nil, nil,
		),
		sessionsIPv4: prometheus.NewDesc(
			"xpf_sessions_ipv4",
			"Current number of IPv4 sessions.",
			nil, nil,
		),
		sessionsIPv6: prometheus.NewDesc(
			"xpf_sessions_ipv6",
			"Current number of IPv6 sessions.",
			nil, nil,
		),
		sessionsSNAT: prometheus.NewDesc(
			"xpf_sessions_snat",
			"Current number of SNAT sessions.",
			nil, nil,
		),
		sessionsDNAT: prometheus.NewDesc(
			"xpf_sessions_dnat",
			"Current number of DNAT sessions.",
			nil, nil,
		),
		gcSweepDuration: prometheus.NewDesc(
			"xpf_gc_sweep_duration_seconds",
			"Duration of the last GC sweep in seconds.",
			nil, nil,
		),
		natPoolUsedPorts: prometheus.NewDesc(
			"xpf_nat_pool_used_ports",
			"Number of used ports in a NAT pool.",
			[]string{"pool"}, nil,
		),
		natPoolTotalPorts: prometheus.NewDesc(
			"xpf_nat_pool_total_ports",
			"Total available ports in a NAT pool.",
			[]string{"pool"}, nil,
		),
		natPoolDeterministicInfo: prometheus.NewDesc(
			"xpf_nat_pool_deterministic_info",
			"Deterministic NAT pool configuration (1 = enabled).",
			[]string{"pool", "block_size", "host_count"}, nil,
		),
		dhcpLeasesActive: prometheus.NewDesc(
			"xpf_dhcp_leases_active",
			"Number of active DHCP leases.",
			[]string{"family"}, nil,
		),

		sysCPUUser: prometheus.NewDesc(
			"xpf_system_cpu_user_percent",
			"User CPU utilization percentage.",
			nil, nil,
		),
		sysCPUSystem: prometheus.NewDesc(
			"xpf_system_cpu_system_percent",
			"System CPU utilization percentage.",
			nil, nil,
		),
		sysMemTotal: prometheus.NewDesc(
			"xpf_system_memory_total_bytes",
			"Total system memory in bytes.",
			nil, nil,
		),
		sysMemAvail: prometheus.NewDesc(
			"xpf_system_memory_available_bytes",
			"Available system memory in bytes.",
			nil, nil,
		),
		daemonUptime: prometheus.NewDesc(
			"xpf_daemon_uptime_seconds",
			"Daemon uptime in seconds.",
			nil, nil,
		),
		daemonMemRSS: prometheus.NewDesc(
			"xpf_daemon_memory_rss_bytes",
			"Daemon resident set size in bytes.",
			nil, nil,
		),

		// #709: owner-profile telemetry. Labels:
		//   ifindex:      interface ifindex as string
		//   queue_id:     CoS queue id 0-255
		//   bucket_hi_ns: upper bound of the histogram bucket (ns),
		//                 formatted as the power-of-two.
		// The histogram metrics are counters (monotonic bucket counts
		// in the Rust dataplane); owner/peer pps are gauges since the
		// Rust side re-uses them across the window.
		cosDrainLatencyBucket: prometheus.NewDesc(
			"xpf_cos_drain_latency_ns_bucket",
			"CoS owner-drain latency histogram — power-of-two ns buckets (#709).",
			[]string{"ifindex", "queue_id", "bucket_hi_ns"}, nil,
		),
		cosDrainInvocationsTotal: prometheus.NewDesc(
			"xpf_cos_drain_invocations_total",
			"Total CoS owner-drain invocations per (ifindex, queue_id) (#709).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosRedirectAcquireBucket: prometheus.NewDesc(
			"xpf_cos_redirect_acquire_ns_bucket",
			"CoS redirect-acquire latency histogram — power-of-two ns buckets, sampled 1-in-256 (#709).",
			[]string{"ifindex", "queue_id", "bucket_hi_ns"}, nil,
		),
		cosOwnerPPS: prometheus.NewDesc(
			"xpf_cos_owner_pps",
			"CoS owner-local pps (window accumulator, cleared by operator) (#709).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosPeerPPS: prometheus.NewDesc(
			"xpf_cos_peer_pps",
			"CoS peer-redirected pps (window accumulator, cleared by operator) (#709).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainGuaranteeSentBytes: prometheus.NewDesc(
			"xpf_userspace_cos_drain_guarantee_sent_bytes_total",
			"Bytes sent by this CoS queue during guarantee-phase service (#1369).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainSurplusSentBytes: prometheus.NewDesc(
			"xpf_userspace_cos_drain_surplus_sent_bytes_total",
			"Bytes sent by this CoS queue during surplus-phase service (#1369).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainNonExactSentBytesWhileExactBacklogged: prometheus.NewDesc(
			"xpf_userspace_cos_drain_nonexact_sent_bytes_while_exact_backlogged_total",
			"Non-exact CoS queue bytes sent while at least one exact queue on the same shaped interface still had backlog; non-zero deltas indicate best-effort/uncapped service competing with exact demand (#1369).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowEnforcementEnabled: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_enforcement_enabled",
			"1 when this exact CoS queue's shared v8 lease is configured for opt-in equal-flow suppression (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowEnforced: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_enforced",
			"1 when this exact CoS queue's current shared v8 lease epoch is actively applying equal-flow suppression; 0 when configured but failed open (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowTargetPerFlowBPS: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_target_per_flow_bps",
			"Current Rust-enforced equal-flow per-flow target in bits per second, derived from shared v8 lease grants rather than the measurement-only Go estimator (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowMaxWorkerCapBytes: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_max_worker_cap_bytes",
			"Maximum per-worker bytes-per-epoch cap currently published by the shared v8 equal-flow suppressor (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowCapHitEvents: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_cap_hit_events_total",
			"Acquire calls denied by the opt-in shared v8 equal-flow cap while class capacity remained (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowSuppressedGrantBytes: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_suppressed_grant_bytes_total",
			"Requested queue-lease bytes withheld by the opt-in shared v8 equal-flow suppressor while class capacity remained (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowStaleOrTagMismatchEvents: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_stale_or_tag_mismatch_events_total",
			"Acquire-side stale/tag-mismatch equal-flow cap reads that failed open without overwriting the rotation-published epoch reason (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowFailOpen: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_fail_open",
			"1 for the current bounded fail-open reason on an opt-in shared v8 equal-flow queue; absent for queues without equal-flow enforcement (#1304).",
			[]string{"ifindex", "queue_id", "reason"}, nil,
		),
		// #869: per-worker busy/idle runtime counters.
		workerWallSecs: prometheus.NewDesc(
			"xpf_userspace_worker_wall_seconds_total",
			"Monotonic wall seconds observed by the userspace-dp worker loop (#869).",
			[]string{"worker_id"}, nil,
		),
		workerActiveSecs: prometheus.NewDesc(
			"xpf_userspace_worker_active_seconds_total",
			"Seconds the userspace-dp worker spent processing packets (#869).",
			[]string{"worker_id"}, nil,
		),
		workerIdleSpinSecs: prometheus.NewDesc(
			"xpf_userspace_worker_idle_spin_seconds_total",
			"Seconds the userspace-dp worker spent idle-spinning on empty rings (#869).",
			[]string{"worker_id"}, nil,
		),
		workerIdleBlockSecs: prometheus.NewDesc(
			"xpf_userspace_worker_idle_block_seconds_total",
			"Seconds the userspace-dp worker spent blocked in poll()/sleep (#869).",
			[]string{"worker_id"}, nil,
		),
		workerThreadCPUSecs: prometheus.NewDesc(
			"xpf_userspace_worker_thread_cpu_seconds_total",
			"CLOCK_THREAD_CPUTIME_ID sample for the userspace-dp worker thread (#869).",
			[]string{"worker_id"}, nil,
		),
		workerThreadCPUSecsLast60s: prometheus.NewDesc(
			"xpf_userspace_worker_thread_cpu_seconds_last_60s",
			"CLOCK_THREAD_CPUTIME_ID consumed by the worker thread over the most recent rolling ~60s window (gauge, not counter; 0 until ~60s after worker start).",
			[]string{"worker_id"}, nil,
		),
		workerThreadCPUWindowSecs: prometheus.NewDesc(
			"xpf_userspace_worker_thread_cpu_window_seconds",
			"Wall-clock width of the rolling thread-CPU window matching xpf_userspace_worker_thread_cpu_seconds_last_60s; 0 until ~60s after worker start. Operators compute live CPU% as last_60s / this gauge.",
			[]string{"worker_id"}, nil,
		),
		workerWorkLoops: prometheus.NewDesc(
			"xpf_userspace_worker_work_loops_total",
			"Worker-loop iterations that did useful packet/ring work (#869).",
			[]string{"worker_id"}, nil,
		),
		workerIdleLoops: prometheus.NewDesc(
			"xpf_userspace_worker_idle_loops_total",
			"Worker-loop iterations with no useful work (#869).",
			[]string{"worker_id"}, nil,
		),
		workerCoSQueueLeaseAcquireV8Calls: prometheus.NewDesc(
			"xpf_userspace_worker_cos_queue_lease_acquire_v8_calls_total",
			"V8 CoS queue-lease acquire calls made by this worker (#1240).",
			[]string{"worker_id"}, nil,
		),
		workerCoSQueueLeaseAcquireV8GrantedBytes: prometheus.NewDesc(
			"xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total",
			"Bytes granted by v8 CoS queue-lease acquire calls for this worker (#1240).",
			[]string{"worker_id"}, nil,
		),
		userspaceEventStreamFramesTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_frames_total",
			"Daemon-side userspace event-stream frames by direction.",
			[]string{"direction"}, nil,
		),
		userspaceEventStreamProducerFramesTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_producer_frames_total",
			"Userspace helper event-stream producer counters by outcome.",
			[]string{"outcome"}, nil,
		),
		userspaceEventStreamDecodeErrorsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_decode_errors_total",
			"Daemon-side userspace event-stream decode errors.",
			nil, nil,
		),
		userspaceEventStreamSequenceGapsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_sequence_gaps_total",
			"Daemon-side userspace event-stream sequence gaps.",
			nil, nil,
		),
		userspaceEventStreamDataplaneEventsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_dataplane_events_total",
			"Decoded RT_FLOW dataplane events received over the userspace event stream.",
			[]string{"type"}, nil,
		),
		userspaceEventStreamDataplaneDropsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_dataplane_event_drops_total",
			"RT_FLOW dataplane events dropped by the userspace event-stream decoder.",
			[]string{"type"}, nil,
		),
		userspaceEventStreamUnknownDropsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_unknown_frame_drops_total",
			"Userspace event-stream frames dropped because their frame type is unknown.",
			nil, nil,
		),
		workerDead: prometheus.NewDesc(
			"xpf_userspace_worker_dead",
			"1 if the userspace-dp worker thread has panicked and been "+
				"caught by the supervisor; 0 otherwise. Cleared only by "+
				"daemon restart in Phase 1 (#925).",
			[]string{"worker_id"}, nil,
		),
		bindingActiveFlowCount: prometheus.NewDesc(
			"xpf_userspace_binding_active_flow_count",
			"Distinct active flows observed in this binding's flow_cache "+
				"in the last ~650ms (10 epoch ticks × ~65ms debug-state tick; "+
				"snapshot refreshed on each tick). Read by the fairness harness to "+
				"compute the structural CoV ceiling per docs/fairness-regimes.md (#1219).",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingTXCompletions: prometheus.NewDesc(
			"xpf_userspace_binding_tx_completions_total",
			"Cumulative AF_XDP TX completions reaped by this binding's owner worker (#1241).",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingTXCompletionRingAvailable: prometheus.NewDesc(
			"xpf_userspace_binding_tx_completion_ring_available",
			"Last sampled AF_XDP TX completion-ring descriptors available before the owner worker drained completions (#1241).",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingTXCompletionRingAvailableMax: prometheus.NewDesc(
			"xpf_userspace_binding_tx_completion_ring_available_max",
			"Maximum sampled AF_XDP TX completion-ring descriptors available in the last debug window (#1241).",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		cosActiveFlowCount: prometheus.NewDesc(
			"xpf_userspace_cos_active_flow_count",
			"Distinct active flows observed for this egress CoS queue on this worker "+
				"in the last ~650ms. This class-specific distribution is the preferred "+
				"fairness harness input for mixed workloads (#1248).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessCstruct: prometheus.NewDesc(
			"xpf_fairness_cstruct",
			"Structural per-flow CoV ceiling for this egress CoS queue, derived from "+
				"xpf_userspace_cos_active_flow_count and the fairness-regimes contract (#1247).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessActiveWorkers: prometheus.NewDesc(
			"xpf_fairness_active_workers",
			"Number of workers with at least one active flow for this egress CoS queue (#1247).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessActiveFlows: prometheus.NewDesc(
			"xpf_fairness_active_flows",
			"Total active flows observed for this egress CoS queue in the current userspace snapshot (#1247).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessMaxWorkerFlowShare: prometheus.NewDesc(
			"xpf_fairness_max_worker_flow_share",
			"Largest fraction of this egress CoS queue's active flows owned by one worker (#1247).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessCoSCountsTruncated: prometheus.NewDesc(
			"xpf_fairness_cos_active_flow_counts_truncated",
			"1 when the userspace CoS active-flow snapshot was truncated before fairness RSS gauges were derived; 0 otherwise (#1247).",
			nil, nil,
		),
		fairnessRSSExpectation: prometheus.NewDesc(
			"xpf_fairness_rss_expectation_configured",
			"1 for each configured opt-in RSS/workload expectation evaluated against this egress CoS queue (#1247).",
			[]string{"ifindex", "queue_id", "kind"}, nil,
		),
		fairnessRSSExpectationValue: prometheus.NewDesc(
			"xpf_fairness_rss_expectation_value",
			"Configured numeric value for RSS/workload expectation kinds that take one, such as active-worker count or threshold (#1265).",
			[]string{"ifindex", "queue_id", "kind"}, nil,
		),
		fairnessRSSSkewViolation: prometheus.NewDesc(
			"xpf_fairness_rss_skew_violation",
			"1 when the configured RSS/workload expectation fails for this egress CoS queue; 0 when it passes (#1247).",
			[]string{"ifindex", "queue_id", "kind"}, nil,
		),
		fairnessSaturated: prometheus.NewDesc(
			"xpf_fairness_saturated",
			"1 when the rolling per-flow byte window is at or above 95% of the configured egress CoS queue transmit rate (#1264).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessObservedCoV: prometheus.NewDesc(
			"xpf_fairness_observed_cov",
			"Rolling observed coefficient of variation across per-flow byte totals for this egress CoS queue (#1264).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessStarvedFlows: prometheus.NewDesc(
			"xpf_fairness_starved_flows",
			"Monotonic count of flows that enter below 1% of the rolling mean per-flow bytes for this egress CoS queue, de-duplicated while the flow remains in the rolling window (#1264).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowEstimateValid: prometheus.NewDesc(
			"xpf_fairness_equal_flow_estimate_valid",
			"1 when the measurement-only equal-flow suppression estimator has at least two currently-active-flow workers with rolling byte samples for this egress CoS queue (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowSampledActiveWorkers: prometheus.NewDesc(
			"xpf_fairness_equal_flow_sampled_active_workers",
			"Currently-active-flow workers with non-zero rolling byte samples in the measurement-only equal-flow suppression estimator (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowUnsampledActiveWorkers: prometheus.NewDesc(
			"xpf_fairness_equal_flow_unsampled_active_workers",
			"Currently-active-flow workers with no rolling byte samples in the measurement-only equal-flow suppression estimator (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowTargetPerFlowBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_target_per_flow_bps",
			"Slowest sampled currently-active worker's observed per-flow bit rate used as the measurement-only equal-flow suppression target for this egress CoS queue; low values may reflect source artifacts such as idle or receiver-limited flows, not only dataplane unfairness (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowObservedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_observed_bps",
			"Observed aggregate bits per second across currently-active-flow workers in the rolling estimator window before hypothetical equal-flow suppression (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowCappedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_capped_bps",
			"Estimated aggregate bits per second across currently-active-flow workers after applying the measurement-only equal-flow suppression cap; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowSuppressedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_suppressed_bps",
			"Estimated currently-active-flow worker bits per second that would be withheld by the measurement-only equal-flow suppression cap; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowThroughputLossRatio: prometheus.NewDesc(
			"xpf_fairness_equal_flow_throughput_loss_ratio",
			"Estimated suppressed_bps / observed_bps ratio for the measurement-only equal-flow suppression cap; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowWorkerObservedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_worker_observed_bps",
			"Observed bits per second for one currently-active-flow worker in the rolling equal-flow suppression estimator (#1304).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessEqualFlowWorkerObservedPerFlowBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_worker_observed_per_flow_bps",
			"Observed per-flow bits per second for one currently-active-flow worker in the rolling equal-flow suppression estimator (#1304).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessEqualFlowWorkerCapBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_worker_cap_bps",
			"Estimated bits-per-second cap for one currently-active-flow worker under measurement-only equal-flow suppression; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessEqualFlowWorkerSuppressedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_worker_suppressed_bps",
			"Estimated bits per second withheld from one currently-active-flow worker by measurement-only equal-flow suppression; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessThroughputWindow: dpuserspace.NewFairnessThroughputWindow(30 * time.Second),
	}
}

func (c *xpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packetsTotal
	ch <- c.dropsTotal
	ch <- c.sessionsCreatedTotal
	ch <- c.sessionsClosedTotal
	ch <- c.screenDropsTotal
	ch <- c.policyDeniesTotal
	ch <- c.natAllocFailsTotal
	ch <- c.hostInboundDeny
	ch <- c.tcEgressPacketsTotal
	ch <- c.syncookieTotal
	ch <- c.flowCacheTotal
	ch <- c.ifacePacketsTotal
	ch <- c.ifaceBytesTotal
	ch <- c.zonePacketsTotal
	ch <- c.zoneBytesTotal
	ch <- c.policyHitsTotal
	ch <- c.filterHitsTotal
	ch <- c.threeColorPolicerPacketsTotal
	ch <- c.threeColorPolicerBytesTotal
	ch <- c.threeColorPolicerDropsTotal
	ch <- c.threeColorPolicerDropBytes
	ch <- c.sessionsActive
	ch <- c.sessionsEstablished
	ch <- c.sessionsIPv4
	ch <- c.sessionsIPv6
	ch <- c.sessionsSNAT
	ch <- c.sessionsDNAT
	ch <- c.gcSweepDuration
	ch <- c.natPoolUsedPorts
	ch <- c.natPoolTotalPorts
	ch <- c.natPoolDeterministicInfo
	ch <- c.dhcpLeasesActive
	ch <- c.sysCPUUser
	ch <- c.sysCPUSystem
	ch <- c.sysMemTotal
	ch <- c.sysMemAvail
	ch <- c.daemonUptime
	ch <- c.daemonMemRSS
	ch <- c.cosDrainLatencyBucket
	ch <- c.cosDrainInvocationsTotal
	ch <- c.cosRedirectAcquireBucket
	ch <- c.cosOwnerPPS
	ch <- c.cosPeerPPS
	ch <- c.cosDrainGuaranteeSentBytes
	ch <- c.cosDrainSurplusSentBytes
	ch <- c.cosDrainNonExactSentBytesWhileExactBacklogged
	ch <- c.cosEqualFlowEnforcementEnabled
	ch <- c.cosEqualFlowEnforced
	ch <- c.cosEqualFlowTargetPerFlowBPS
	ch <- c.cosEqualFlowMaxWorkerCapBytes
	ch <- c.cosEqualFlowCapHitEvents
	ch <- c.cosEqualFlowSuppressedGrantBytes
	ch <- c.cosEqualFlowStaleOrTagMismatchEvents
	ch <- c.cosEqualFlowFailOpen
	ch <- c.workerWallSecs
	ch <- c.workerActiveSecs
	ch <- c.workerIdleSpinSecs
	ch <- c.workerIdleBlockSecs
	ch <- c.workerThreadCPUSecs
	ch <- c.workerThreadCPUSecsLast60s
	ch <- c.workerThreadCPUWindowSecs
	ch <- c.workerWorkLoops
	ch <- c.workerIdleLoops
	ch <- c.workerCoSQueueLeaseAcquireV8Calls
	ch <- c.workerCoSQueueLeaseAcquireV8GrantedBytes
	ch <- c.userspaceEventStreamFramesTotal
	ch <- c.userspaceEventStreamProducerFramesTotal
	ch <- c.userspaceEventStreamDecodeErrorsTotal
	ch <- c.userspaceEventStreamSequenceGapsTotal
	ch <- c.userspaceEventStreamDataplaneEventsTotal
	ch <- c.userspaceEventStreamDataplaneDropsTotal
	ch <- c.userspaceEventStreamUnknownDropsTotal
	ch <- c.workerDead
	ch <- c.bindingActiveFlowCount
	ch <- c.bindingTXCompletions
	ch <- c.bindingTXCompletionRingAvailable
	ch <- c.bindingTXCompletionRingAvailableMax
	ch <- c.cosActiveFlowCount
	ch <- c.fairnessCstruct
	ch <- c.fairnessActiveWorkers
	ch <- c.fairnessActiveFlows
	ch <- c.fairnessMaxWorkerFlowShare
	ch <- c.fairnessCoSCountsTruncated
	ch <- c.fairnessRSSExpectation
	ch <- c.fairnessRSSExpectationValue
	ch <- c.fairnessRSSSkewViolation
	ch <- c.fairnessSaturated
	ch <- c.fairnessObservedCoV
	ch <- c.fairnessStarvedFlows
	ch <- c.fairnessEqualFlowEstimateValid
	ch <- c.fairnessEqualFlowSampledActiveWorkers
	ch <- c.fairnessEqualFlowUnsampledActiveWorkers
	ch <- c.fairnessEqualFlowTargetPerFlowBPS
	ch <- c.fairnessEqualFlowObservedBPS
	ch <- c.fairnessEqualFlowCappedBPS
	ch <- c.fairnessEqualFlowSuppressedBPS
	ch <- c.fairnessEqualFlowThroughputLossRatio
	ch <- c.fairnessEqualFlowWorkerObservedBPS
	ch <- c.fairnessEqualFlowWorkerObservedPerFlowBPS
	ch <- c.fairnessEqualFlowWorkerCapBPS
	ch <- c.fairnessEqualFlowWorkerSuppressedBPS
}

func (c *xpfCollector) Collect(ch chan<- prometheus.Metric) {
	dp := c.srv.dp
	if dp == nil || !dp.IsLoaded() {
		return
	}

	c.collectGlobalCounters(ch, dp)
	c.collectInterfaceCounters(ch, dp)
	c.collectZoneCounters(ch, dp)
	c.collectPolicyCounters(ch, dp)
	c.collectFilterCounters(ch, dp)
	c.collectSessionGauges(ch, dp)
	c.collectNATPoolMetrics(ch, dp)
	c.collectDHCPMetrics(ch)
	c.collectSystemMetrics(ch)
	c.collectUserspaceStatus(ch, dp)
}

// #709 + #869: single Status() call per scrape, then dispatch to
// CoS owner profile + worker runtime collectors.  Both features need
// the same ProcessStatus; calling Status() twice per scrape is
// wasteful on the userspace-dp control socket.
func (c *xpfCollector) collectUserspaceStatus(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	provider, ok := dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return
	}
	status, err := provider.Status()
	if err != nil {
		return
	}
	c.emitCoSOwnerProfile(ch, status)
	c.emitCoSDrainPhaseTelemetry(ch, status)
	c.emitCoSEqualFlowEnforcement(ch, status)
	c.emitWorkerRuntime(ch, status)
	c.emitUserspaceEventStream(ch, status)
	c.emitBindingActiveFlowCount(ch, status)
	c.emitBindingTXCompletionTelemetry(ch, status)
	c.emitCoSActiveFlowCount(ch, status)
	c.emitThreeColorPolicerCounters(ch, status)
	c.emitFairnessRSSGauges(ch, status)
	c.emitFairnessThroughputGauges(ch, status)
}

func (c *xpfCollector) emitThreeColorPolicerCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, p := range status.ThreeColorPolicerCounters {
		emitColor := func(color string, packets, bytes uint64) {
			ch <- prometheus.MustNewConstMetric(
				c.threeColorPolicerPacketsTotal,
				prometheus.CounterValue,
				float64(packets),
				p.Name,
				color,
			)
			ch <- prometheus.MustNewConstMetric(
				c.threeColorPolicerBytesTotal,
				prometheus.CounterValue,
				float64(bytes),
				p.Name,
				color,
			)
		}
		emitColor("green", p.GreenPackets, p.GreenBytes)
		emitColor("yellow", p.YellowPackets, p.YellowBytes)
		emitColor("red", p.RedPackets, p.RedBytes)
		ch <- prometheus.MustNewConstMetric(
			c.threeColorPolicerDropsTotal,
			prometheus.CounterValue,
			float64(p.DropPackets),
			p.Name,
		)
		ch <- prometheus.MustNewConstMetric(
			c.threeColorPolicerDropBytes,
			prometheus.CounterValue,
			float64(p.DropBytes),
			p.Name,
		)
	}
}

// #1219: emit per-binding distinct active flow count for the fairness
// harness. Reads BindingStatus.ActiveFlowCount populated by the
// helper's ~65ms debug-state tick (see plan §3.2-3.3).
func (c *xpfCollector) emitBindingActiveFlowCount(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		ch <- prometheus.MustNewConstMetric(
			c.bindingActiveFlowCount,
			prometheus.GaugeValue,
			float64(b.ActiveFlowCount),
			strconv.FormatUint(uint64(b.Slot), 10),
			strconv.FormatUint(uint64(b.QueueID), 10),
			strconv.FormatUint(uint64(b.WorkerID), 10),
			b.Interface,
		)
	}
}

// #1241: emit per-binding AF_XDP TX completion service telemetry for
// flow-fairness qualification runs. `tx_completions_total` gives the
// per-queue completion rate via Prometheus `rate()`. The two gauges
// expose latest and peak completion-ring backlog observed by the owner
// worker before drain, without introducing a hot-path shared counter.
func (c *xpfCollector) emitBindingTXCompletionTelemetry(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		slot := strconv.FormatUint(uint64(b.Slot), 10)
		queueID := strconv.FormatUint(uint64(b.QueueID), 10)
		workerID := strconv.FormatUint(uint64(b.WorkerID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.bindingTXCompletions,
			prometheus.CounterValue,
			float64(b.TXCompletions),
			slot, queueID, workerID, b.Interface,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bindingTXCompletionRingAvailable,
			prometheus.GaugeValue,
			float64(b.TXCompletionRingAvailable),
			slot, queueID, workerID, b.Interface,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bindingTXCompletionRingAvailableMax,
			prometheus.GaugeValue,
			float64(b.TXCompletionRingAvailableMax),
			slot, queueID, workerID, b.Interface,
		)
	}
}

// #1248: emit class-specific active flow counts for each egress CoS
// `(ifindex, queue_id, worker_id)` tuple. This is intentionally a
// gauge snapshot from userspace-dp's debug cadence, not a line-rate
// packet counter.
func (c *xpfCollector) emitCoSActiveFlowCount(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, row := range status.CoSActiveFlowCounts {
		ch <- prometheus.MustNewConstMetric(
			c.cosActiveFlowCount,
			prometheus.GaugeValue,
			float64(row.ActiveFlowCount),
			strconv.Itoa(row.Ifindex),
			strconv.FormatUint(uint64(row.QueueID), 10),
			strconv.FormatUint(uint64(row.WorkerID), 10),
		)
	}
}

// #1247: expose production RSS/workload health gauges from the same
// per-CoS active-flow distribution used by the fairness harness. This
// remains a status-snapshot calculation; it does not feed scheduling and
// does not add packet-path shared state.
func (c *xpfCollector) emitFairnessRSSGauges(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	truncated := 0.0
	if status.CoSActiveFlowCountsTruncated {
		truncated = 1.0
	}
	ch <- prometheus.MustNewConstMetric(
		c.fairnessCoSCountsTruncated,
		prometheus.GaugeValue,
		truncated,
	)

	for _, row := range dpuserspace.CoSFairnessRSSSummaries(status) {
		ifindexLabel := strconv.Itoa(row.Ifindex)
		queueLabel := strconv.FormatUint(uint64(row.QueueID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessCstruct,
			prometheus.GaugeValue,
			row.Cstruct,
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessActiveWorkers,
			prometheus.GaugeValue,
			float64(row.ActiveWorkers),
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessActiveFlows,
			prometheus.GaugeValue,
			float64(row.ActiveFlows),
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessMaxWorkerFlowShare,
			prometheus.GaugeValue,
			row.MaxWorkerFlowShare,
			ifindexLabel,
			queueLabel,
		)
	}
	c.emitFairnessRSSExpectationGauges(ch, status, c.configuredFairnessRSSExpectations())
}

func (c *xpfCollector) configuredFairnessRSSExpectations() []dpuserspace.FairnessRSSExpectation {
	if c == nil || c.srv == nil || c.srv.store == nil {
		return nil
	}
	return dpuserspace.FairnessRSSExpectationsFromConfig(c.srv.store.ActiveConfig())
}

func (c *xpfCollector) emitFairnessRSSExpectationGauges(
	ch chan<- prometheus.Metric,
	status dpuserspace.ProcessStatus,
	expectations []dpuserspace.FairnessRSSExpectation,
) {
	for _, result := range dpuserspace.EvaluateFairnessRSSExpectations(status, expectations) {
		ifindexLabel := strconv.Itoa(result.Ifindex)
		queueLabel := strconv.FormatUint(uint64(result.QueueID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessRSSExpectation,
			prometheus.GaugeValue,
			1,
			ifindexLabel,
			queueLabel,
			result.ExpectationKind,
		)
		if result.HasExpectationValue {
			ch <- prometheus.MustNewConstMetric(
				c.fairnessRSSExpectationValue,
				prometheus.GaugeValue,
				result.ExpectationValue,
				ifindexLabel,
				queueLabel,
				result.ExpectationKind,
			)
		}
		violation := 1.0
		if result.Pass {
			violation = 0
		}
		ch <- prometheus.MustNewConstMetric(
			c.fairnessRSSSkewViolation,
			prometheus.GaugeValue,
			violation,
			ifindexLabel,
			queueLabel,
			result.ExpectationKind,
		)
	}
}

func (c *xpfCollector) emitFairnessThroughputGauges(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	c.mu.Lock()
	if c.fairnessThroughputWindow == nil {
		c.fairnessThroughputWindow = dpuserspace.NewFairnessThroughputWindow(30 * time.Second)
	}
	summaries := c.fairnessThroughputWindow.Update(time.Now(), status)
	c.mu.Unlock()

	for _, row := range summaries {
		if row.SourceTruncated || row.FlowCount == 0 || row.WindowSeconds <= 0 {
			continue
		}
		ifindexLabel := strconv.Itoa(row.Ifindex)
		queueLabel := strconv.FormatUint(uint64(row.QueueID), 10)
		saturated := 0.0
		if row.Saturated {
			saturated = 1
		}
		ch <- prometheus.MustNewConstMetric(
			c.fairnessSaturated,
			prometheus.GaugeValue,
			saturated,
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessObservedCoV,
			prometheus.GaugeValue,
			row.ObservedCoV,
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessStarvedFlows,
			prometheus.CounterValue,
			float64(row.StarvedFlowsTotal),
			ifindexLabel,
			queueLabel,
		)
		c.emitFairnessEqualFlowEstimateGauges(ch, row, ifindexLabel, queueLabel)
	}
}

func (c *xpfCollector) emitFairnessEqualFlowEstimateGauges(
	ch chan<- prometheus.Metric,
	row dpuserspace.FairnessThroughputSummary,
	ifindexLabel string,
	queueLabel string,
) {
	estimate := row.EqualFlowEstimate
	if estimate.ActiveWorkers == 0 {
		return
	}
	valid := 0.0
	if estimate.Valid {
		valid = 1
	}
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowEstimateValid,
		prometheus.GaugeValue,
		valid,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowSampledActiveWorkers,
		prometheus.GaugeValue,
		float64(estimate.SampledActiveWorkers),
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowUnsampledActiveWorkers,
		prometheus.GaugeValue,
		float64(estimate.UnsampledActiveWorkers),
		ifindexLabel,
		queueLabel,
	)
	if !estimate.Valid {
		return
	}
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowTargetPerFlowBPS,
		prometheus.GaugeValue,
		estimate.TargetPerFlowBPS,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowObservedBPS,
		prometheus.GaugeValue,
		estimate.ObservedBPS,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowCappedBPS,
		prometheus.GaugeValue,
		estimate.CappedBPS,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowSuppressedBPS,
		prometheus.GaugeValue,
		estimate.SuppressedBPS,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowThroughputLossRatio,
		prometheus.GaugeValue,
		estimate.ThroughputLossRatio,
		ifindexLabel,
		queueLabel,
	)
	for _, worker := range estimate.Workers {
		workerLabel := strconv.FormatUint(uint64(worker.WorkerID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessEqualFlowWorkerObservedBPS,
			prometheus.GaugeValue,
			worker.ObservedBPS,
			ifindexLabel,
			queueLabel,
			workerLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessEqualFlowWorkerObservedPerFlowBPS,
			prometheus.GaugeValue,
			worker.ObservedPerFlow,
			ifindexLabel,
			queueLabel,
			workerLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessEqualFlowWorkerCapBPS,
			prometheus.GaugeValue,
			worker.CapBPS,
			ifindexLabel,
			queueLabel,
			workerLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessEqualFlowWorkerSuppressedBPS,
			prometheus.GaugeValue,
			worker.SuppressedBPS,
			ifindexLabel,
			queueLabel,
			workerLabel,
		)
	}
}

// #869: emit per-worker busy/idle runtime counters from a cached
// ProcessStatus snapshot.
func (c *xpfCollector) emitWorkerRuntime(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, w := range status.WorkerRuntime {
		label := strconv.FormatUint(uint64(w.WorkerID), 10)
		toSecs := func(ns uint64) float64 { return float64(ns) / 1e9 }
		ch <- prometheus.MustNewConstMetric(c.workerWallSecs,
			prometheus.CounterValue, toSecs(w.WallNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerActiveSecs,
			prometheus.CounterValue, toSecs(w.ActiveNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerIdleSpinSecs,
			prometheus.CounterValue, toSecs(w.IdleSpinNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerIdleBlockSecs,
			prometheus.CounterValue, toSecs(w.IdleBlockNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerThreadCPUSecs,
			prometheus.CounterValue, toSecs(w.ThreadCPUNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerThreadCPUSecsLast60s,
			prometheus.GaugeValue, toSecs(w.ThreadCPUNS60s), label)
		ch <- prometheus.MustNewConstMetric(c.workerThreadCPUWindowSecs,
			prometheus.GaugeValue, toSecs(w.WindowNS), label)
		ch <- prometheus.MustNewConstMetric(c.workerWorkLoops,
			prometheus.CounterValue, float64(w.WorkLoops), label)
		ch <- prometheus.MustNewConstMetric(c.workerIdleLoops,
			prometheus.CounterValue, float64(w.IdleLoops), label)
		ch <- prometheus.MustNewConstMetric(c.workerCoSQueueLeaseAcquireV8Calls,
			prometheus.CounterValue, float64(w.CoSQueueLeaseAcquireV8Calls), label)
		ch <- prometheus.MustNewConstMetric(c.workerCoSQueueLeaseAcquireV8GrantedBytes,
			prometheus.CounterValue, float64(w.CoSQueueLeaseAcquireV8GrantedBytes), label)
		var deadValue float64
		if w.Dead {
			deadValue = 1
		}
		ch <- prometheus.MustNewConstMetric(c.workerDead,
			prometheus.GaugeValue, deadValue, label)
	}
}

func (c *xpfCollector) emitUserspaceEventStream(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	if status.EventStream == nil {
		return
	}
	es := status.EventStream
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamFramesTotal,
		prometheus.CounterValue, float64(es.FramesRead), "read")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamFramesTotal,
		prometheus.CounterValue, float64(es.FramesWritten), "written")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamSent), "sent")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamProducerFramesTotal,
		prometheus.CounterValue, float64(status.EventStreamDropped), "dropped")
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamDecodeErrorsTotal,
		prometheus.CounterValue, float64(es.DecodeErrors))
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamSequenceGapsTotal,
		prometheus.CounterValue, float64(es.SeqGaps))

	for _, item := range []struct {
		label string
		count uint64
	}{
		{"policy_deny", es.PolicyDenyEvents},
		{"screen_drop", es.ScreenDropEvents},
		{"filter_log", es.FilterLogEvents},
	} {
		ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamDataplaneEventsTotal,
			prometheus.CounterValue, float64(item.count), item.label)
	}
	for _, item := range []struct {
		label string
		count uint64
	}{
		{"policy_deny", es.PolicyDenyDrops},
		{"screen_drop", es.ScreenDropDrops},
		{"filter_log", es.FilterLogDrops},
	} {
		ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamDataplaneDropsTotal,
			prometheus.CounterValue, float64(item.count), item.label)
	}
	ch <- prometheus.MustNewConstMetric(c.userspaceEventStreamUnknownDropsTotal,
		prometheus.CounterValue, float64(es.UnknownFrameDrops))
}

// #709: export owner-profile telemetry when the dataplane is the
// userspace-dp helper. The eBPF-only build path doesn't have this
// shape (it has no CoS scheduler), so we type-assert on the optional
// `Status() (dpuserspace.ProcessStatus, error)` interface — if the
// assertion fails we skip silently (not an error).
func (c *xpfCollector) emitCoSOwnerProfile(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, iface := range status.CoSInterfaces {
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for _, queue := range iface.Queues {
			// Only exact queues with a named owner worker have
			// meaningful owner-profile telemetry. See cosfmt.go for
			// the same gating on the CLI side.
			if queue.OwnerWorkerID == nil {
				continue
			}
			queueLabel := strconv.Itoa(queue.QueueID)
			emitHistogram(ch, c.cosDrainLatencyBucket,
				queue.DrainLatencyHist, ifindexLabel, queueLabel)
			emitHistogram(ch, c.cosRedirectAcquireBucket,
				queue.RedirectAcquireHist, ifindexLabel, queueLabel)
			ch <- prometheus.MustNewConstMetric(c.cosDrainInvocationsTotal,
				prometheus.CounterValue, float64(queue.DrainInvocations),
				ifindexLabel, queueLabel)
			ch <- prometheus.MustNewConstMetric(c.cosOwnerPPS,
				prometheus.GaugeValue, float64(queue.OwnerPPS),
				ifindexLabel, queueLabel)
			ch <- prometheus.MustNewConstMetric(c.cosPeerPPS,
				prometheus.GaugeValue, float64(queue.PeerPPS),
				ifindexLabel, queueLabel)
		}
	}
}

// #1369: queue-scoped drain-phase bytes for exact-vs-best-effort
// contention diagnosis. These counters are intentionally not gated on
// OwnerWorkerID: non-exact queues are the critical source for
// `*_while_exact_backlogged`, and shared-exact queues still produce a
// truthful guarantee/surplus phase split.
func (c *xpfCollector) emitCoSDrainPhaseTelemetry(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, iface := range status.CoSInterfaces {
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for _, queue := range iface.Queues {
			queueLabel := strconv.Itoa(queue.QueueID)
			ch <- prometheus.MustNewConstMetric(
				c.cosDrainGuaranteeSentBytes,
				prometheus.CounterValue,
				float64(queue.DrainGuaranteeSentBytes),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosDrainSurplusSentBytes,
				prometheus.CounterValue,
				float64(queue.DrainSurplusSentBytes),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosDrainNonExactSentBytesWhileExactBacklogged,
				prometheus.CounterValue,
				float64(queue.DrainNonExactSentBytesWhileExactBacklogged),
				ifindexLabel, queueLabel,
			)
		}
	}
}

func (c *xpfCollector) emitCoSEqualFlowEnforcement(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, iface := range status.CoSInterfaces {
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for _, queue := range iface.Queues {
			if !queue.EqualFlowEnforcement {
				continue
			}
			queueLabel := strconv.Itoa(queue.QueueID)
			enforced := 0.0
			if queue.EqualFlowEnforced {
				enforced = 1.0
			}
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowEnforcementEnabled,
				prometheus.GaugeValue,
				1,
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowEnforced,
				prometheus.GaugeValue,
				enforced,
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowTargetPerFlowBPS,
				prometheus.GaugeValue,
				float64(queue.EqualFlowTargetPerFlowBPS),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowMaxWorkerCapBytes,
				prometheus.GaugeValue,
				float64(queue.EqualFlowMaxWorkerCapBytes),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowCapHitEvents,
				prometheus.CounterValue,
				float64(queue.EqualFlowCapHitEvents),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowSuppressedGrantBytes,
				prometheus.CounterValue,
				float64(queue.EqualFlowSuppressedGrantBytes),
				ifindexLabel, queueLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowStaleOrTagMismatchEvents,
				prometheus.CounterValue,
				float64(queue.EqualFlowStaleOrTagMismatchEvents),
				ifindexLabel, queueLabel,
			)
			reason := queue.EqualFlowFailOpenReason
			if reason == "" {
				reason = "none"
			}
			ch <- prometheus.MustNewConstMetric(
				c.cosEqualFlowFailOpen,
				prometheus.GaugeValue,
				1,
				ifindexLabel, queueLabel, reason,
			)
		}
	}
}

// #709: emit per-bucket counter samples. Bucket index maps to a
// power-of-two ns upper bound; see Rust `bucket_index_for_ns` and
// cosfmt.go `bucketLowerBoundMicros` for the shared layout. Label is
// the upper bound so Prometheus histogram consumers can plot a
// rate()-based le-histogram without needing the Rust-side layout
// inlined in promql.
func emitHistogram(ch chan<- prometheus.Metric, desc *prometheus.Desc, hist []uint64, ifindexLabel, queueLabel string) {
	for i, count := range hist {
		upperNs := bucketUpperBoundNs(i)
		ch <- prometheus.MustNewConstMetric(
			desc,
			prometheus.CounterValue,
			float64(count),
			ifindexLabel,
			queueLabel,
			strconv.FormatUint(upperNs, 10),
		)
	}
}

// #709: upper-bound ns for histogram bucket index `i`. Bucket 0 is
// [0, 1024 ns) — upper bound 1024. Bucket N (N >= 1) is
// [2^(N+9), 2^(N+10)) — upper bound 2^(N+10). Bucket 15 (top bucket)
// saturates at 2^24 and we report upper bound = math.MaxUint64-safe
// value (2^25) as the "+Inf" sentinel.
func bucketUpperBoundNs(i int) uint64 {
	if i <= 0 {
		return 1024
	}
	return uint64(1) << uint(i+10)
}

func (c *xpfCollector) collectGlobalCounters(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	readCounter := func(idx uint32) float64 {
		v, _ := dp.ReadGlobalCounter(idx)
		return float64(v)
	}

	ch <- prometheus.MustNewConstMetric(c.packetsTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrRxPackets), "rx")
	ch <- prometheus.MustNewConstMetric(c.packetsTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrTxPackets), "tx")
	ch <- prometheus.MustNewConstMetric(c.dropsTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrDrops))
	ch <- prometheus.MustNewConstMetric(c.sessionsCreatedTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrSessionsNew))
	ch <- prometheus.MustNewConstMetric(c.sessionsClosedTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrSessionsClosed))
	ch <- prometheus.MustNewConstMetric(c.screenDropsTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrScreenDrops))
	ch <- prometheus.MustNewConstMetric(c.policyDeniesTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrPolicyDeny))
	ch <- prometheus.MustNewConstMetric(c.natAllocFailsTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrNATAllocFail))
	ch <- prometheus.MustNewConstMetric(c.hostInboundDeny, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrHostInboundDeny))
	ch <- prometheus.MustNewConstMetric(c.tcEgressPacketsTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrTCEgressPackets))

	// SYN cookie counters
	ch <- prometheus.MustNewConstMetric(c.syncookieTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrSyncookieSent), "sent")
	ch <- prometheus.MustNewConstMetric(c.syncookieTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrSyncookieValid), "valid")
	ch <- prometheus.MustNewConstMetric(c.syncookieTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrSyncookieInvalid), "invalid")
	ch <- prometheus.MustNewConstMetric(c.syncookieTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrSyncookieBypass), "bypass")

	// Flow cache counters (IPv4 + IPv6)
	ch <- prometheus.MustNewConstMetric(c.flowCacheTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrFlowCacheHit), "hit")
	ch <- prometheus.MustNewConstMetric(c.flowCacheTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrFlowCacheMiss), "miss")
	ch <- prometheus.MustNewConstMetric(c.flowCacheTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrFlowCacheFlush), "flush")
	ch <- prometheus.MustNewConstMetric(c.flowCacheTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrFlowCacheInvalidate), "invalidate")
}

func (c *xpfCollector) collectInterfaceCounters(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}

	for ifName := range allInterfaceNames(cfg) {
		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			continue
		}
		ctrs, err := dp.ReadInterfaceCounters(iface.Index)
		if err != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.ifacePacketsTotal, prometheus.CounterValue,
			float64(ctrs.RxPackets), ifName, "rx")
		ch <- prometheus.MustNewConstMetric(c.ifacePacketsTotal, prometheus.CounterValue,
			float64(ctrs.TxPackets), ifName, "tx")
		ch <- prometheus.MustNewConstMetric(c.ifaceBytesTotal, prometheus.CounterValue,
			float64(ctrs.RxBytes), ifName, "rx")
		ch <- prometheus.MustNewConstMetric(c.ifaceBytesTotal, prometheus.CounterValue,
			float64(ctrs.TxBytes), ifName, "tx")
	}
}

func (c *xpfCollector) collectZoneCounters(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	cr := dp.LastCompileResult()
	if cr == nil {
		return
	}

	for zoneName, zoneID := range cr.ZoneIDs {
		ingress, err := dp.ReadZoneCounters(zoneID, 0)
		if err != nil {
			continue
		}
		egress, err := dp.ReadZoneCounters(zoneID, 1)
		if err != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.zonePacketsTotal, prometheus.CounterValue,
			float64(ingress.Packets), zoneName, "ingress")
		ch <- prometheus.MustNewConstMetric(c.zonePacketsTotal, prometheus.CounterValue,
			float64(egress.Packets), zoneName, "egress")
		ch <- prometheus.MustNewConstMetric(c.zoneBytesTotal, prometheus.CounterValue,
			float64(ingress.Bytes), zoneName, "ingress")
		ch <- prometheus.MustNewConstMetric(c.zoneBytesTotal, prometheus.CounterValue,
			float64(egress.Bytes), zoneName, "egress")
	}
}

func (c *xpfCollector) collectPolicyCounters(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}

	var policySetID uint32
	for _, zpp := range cfg.Security.Policies {
		fromZone := zpp.FromZone
		toZone := zpp.ToZone
		// Zone-pair compile output normalizes nil entries out of zpp.Policies.
		for i, rule := range zpp.Policies {
			policyID := policyCounterID(policySetID, i)
			ctrs, err := dp.ReadPolicyCounters(policyID)
			if err != nil {
				continue
			}
			ch <- prometheus.MustNewConstMetric(c.policyHitsTotal, prometheus.CounterValue,
				float64(ctrs.Packets), fromZone, toZone, rule.Name)
		}
		policySetID++
	}

	for i, rule := range cfg.Security.GlobalPolicies {
		if rule == nil {
			continue
		}
		policyID := policyCounterID(policySetID, i)
		ctrs, err := dp.ReadPolicyCounters(policyID)
		if err != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.policyHitsTotal, prometheus.CounterValue,
			float64(ctrs.Packets), "*", "*", rule.Name)
	}
}

func policyCounterID(policySetID uint32, ruleIndex int) uint32 {
	return policySetID*dataplane.MaxRulesPerPolicy + uint32(ruleIndex)
}

func (c *xpfCollector) collectFilterCounters(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	cr := dp.LastCompileResult()
	if cr == nil || cr.FilterIDs == nil {
		return
	}

	emitFilters := func(family string, filters map[string]*config.FirewallFilter) {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			fid, ok := cr.FilterIDs[family+":"+name]
			if !ok {
				continue
			}
			fcfg, err := dp.ReadFilterConfig(fid)
			if err != nil {
				continue
			}
			ruleOffset := fcfg.RuleStart
			for _, term := range filter.Terms {
				nSrc := len(term.SourceAddresses)
				if nSrc == 0 {
					nSrc = 1
				}
				nDst := len(term.DestAddresses)
				if nDst == 0 {
					nDst = 1
				}
				numRules := uint32(nSrc * nDst)
				var totalPkts uint64
				for i := uint32(0); i < numRules; i++ {
					if ctrs, err := dp.ReadFilterCounters(ruleOffset + i); err == nil {
						totalPkts += ctrs.Packets
					}
				}
				ch <- prometheus.MustNewConstMetric(c.filterHitsTotal, prometheus.CounterValue,
					float64(totalPkts), name, family, term.Name)
				ruleOffset += numRules
			}
		}
	}

	emitFilters("inet", cfg.Firewall.FiltersInet)
	emitFilters("inet6", cfg.Firewall.FiltersInet6)
}

func (c *xpfCollector) collectSessionGauges(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	if c.srv.gc == nil {
		return
	}
	stats := c.srv.gc.Stats()
	ch <- prometheus.MustNewConstMetric(c.sessionsActive, prometheus.GaugeValue,
		float64(stats.TotalEntries))
	ch <- prometheus.MustNewConstMetric(c.sessionsEstablished, prometheus.GaugeValue,
		float64(stats.EstablishedSessions))
	ch <- prometheus.MustNewConstMetric(c.gcSweepDuration, prometheus.GaugeValue,
		stats.LastSweepDuration.Seconds())

	// Session breakdowns by type
	var ipv4, ipv6, snat, dnat int
	_ = dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse == 0 {
			ipv4++
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				snat++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				dnat++
			}
		}
		return true
	})
	_ = dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse == 0 {
			ipv6++
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				snat++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				dnat++
			}
		}
		return true
	})
	ch <- prometheus.MustNewConstMetric(c.sessionsIPv4, prometheus.GaugeValue, float64(ipv4))
	ch <- prometheus.MustNewConstMetric(c.sessionsIPv6, prometheus.GaugeValue, float64(ipv6))
	ch <- prometheus.MustNewConstMetric(c.sessionsSNAT, prometheus.GaugeValue, float64(snat))
	ch <- prometheus.MustNewConstMetric(c.sessionsDNAT, prometheus.GaugeValue, float64(dnat))
}

func (c *xpfCollector) collectNATPoolMetrics(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	cr := dp.LastCompileResult()
	if cr == nil {
		return
	}

	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		totalPorts := (portHigh - portLow + 1) * len(pool.Addresses)
		ch <- prometheus.MustNewConstMetric(c.natPoolTotalPorts, prometheus.GaugeValue,
			float64(totalPorts), name)

		if id, ok := cr.PoolIDs[name]; ok {
			cnt, err := dp.ReadNATPortCounter(uint32(id))
			if err == nil {
				ch <- prometheus.MustNewConstMetric(c.natPoolUsedPorts, prometheus.GaugeValue,
					float64(cnt), name)
			}
		}

		if pool.Deterministic != nil {
			hostCount := 0
			if _, n, err := net.ParseCIDR(pool.Deterministic.HostAddress); err == nil {
				ones, bits := n.Mask.Size()
				hostCount = 1 << uint(bits-ones)
			}
			ch <- prometheus.MustNewConstMetric(c.natPoolDeterministicInfo, prometheus.GaugeValue,
				1.0, name,
				strconv.Itoa(pool.Deterministic.BlockSize),
				strconv.Itoa(hostCount))
		}
	}
}

func (c *xpfCollector) collectDHCPMetrics(ch chan<- prometheus.Metric) {
	if c.srv.dhcp == nil {
		return
	}
	leases := c.srv.dhcp.Leases()
	var inet, inet6 int
	for _, l := range leases {
		if l.Family == 6 {
			inet6++
		} else {
			inet++
		}
	}
	ch <- prometheus.MustNewConstMetric(c.dhcpLeasesActive, prometheus.GaugeValue,
		float64(inet), "inet")
	ch <- prometheus.MustNewConstMetric(c.dhcpLeasesActive, prometheus.GaugeValue,
		float64(inet6), "inet6")
}

func (c *xpfCollector) collectSystemMetrics(ch chan<- prometheus.Metric) {
	// Daemon uptime
	ch <- prometheus.MustNewConstMetric(c.daemonUptime, prometheus.GaugeValue,
		time.Since(c.srv.startTime).Seconds())

	// Daemon RSS from /proc/self/statm (field 1 = RSS in pages)
	if data, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 2 {
			if rssPages, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				ch <- prometheus.MustNewConstMetric(c.daemonMemRSS, prometheus.GaugeValue,
					float64(rssPages)*float64(os.Getpagesize()))
			}
		}
	}

	// System memory from /proc/meminfo
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				if v := parseMemInfoKB(line); v > 0 {
					ch <- prometheus.MustNewConstMetric(c.sysMemTotal, prometheus.GaugeValue, float64(v)*1024)
				}
			} else if strings.HasPrefix(line, "MemAvailable:") {
				if v := parseMemInfoKB(line); v > 0 {
					ch <- prometheus.MustNewConstMetric(c.sysMemAvail, prometheus.GaugeValue, float64(v)*1024)
				}
			}
		}
	}

	// CPU usage from /proc/stat (instantaneous snapshot)
	if f, err := os.Open("/proc/stat"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "cpu ") {
				fields := strings.Fields(line)
				// fields: cpu user nice system idle iowait irq softirq steal
				if len(fields) >= 5 {
					user, _ := strconv.ParseFloat(fields[1], 64)
					nice, _ := strconv.ParseFloat(fields[2], 64)
					system, _ := strconv.ParseFloat(fields[3], 64)
					idle, _ := strconv.ParseFloat(fields[4], 64)
					iowait := 0.0
					if len(fields) >= 6 {
						iowait, _ = strconv.ParseFloat(fields[5], 64)
					}
					total := user + nice + system + idle + iowait
					if len(fields) >= 9 {
						irq, _ := strconv.ParseFloat(fields[6], 64)
						softirq, _ := strconv.ParseFloat(fields[7], 64)
						steal, _ := strconv.ParseFloat(fields[8], 64)
						total += irq + softirq + steal
					}
					cpus := float64(runtime.NumCPU())
					if total > 0 && cpus > 0 {
						ch <- prometheus.MustNewConstMetric(c.sysCPUUser, prometheus.GaugeValue,
							(user+nice)/total*100*cpus)
						ch <- prometheus.MustNewConstMetric(c.sysCPUSystem, prometheus.GaugeValue,
							system/total*100*cpus)
					}
				}
			}
		}
	}
}

// parseMemInfoKB extracts the numeric kB value from a /proc/meminfo line.
func parseMemInfoKB(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[1], 10, 64)
	return v
}
