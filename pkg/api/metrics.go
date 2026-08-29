package api

import (
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/singleflight"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// xpfCollector implements prometheus.Collector, reading BPF maps on each scrape.
type xpfCollector struct {
	srv *Server
	mu  sync.Mutex

	// #4162: short-TTL, singleflight-coalesced cache for the seven scalar
	// session-aggregate gauges (active/established/ipv4/ipv6/snat/dnat +
	// scrape_ok). collectSessionGauges walks the shared v4+v6 conntrack BPF
	// hash maps (up to ~10M forward+reverse entries, 2 syscalls/entry each
	// taking a bucket lock) concurrently with the helper's conntrack-publish
	// path. Without this cache every /metrics scrape re-ran that O(sessions)
	// walk, so an unauthenticated (non-loopback web-management bind) or
	// tight-loop scraper could amplify the scan without bound. The export is
	// only seven scalar aggregates (no per-session cardinality), so the O(N)
	// walk yields O(1) output and is fully cacheable without losing a label.
	// A scrape inside sessionGaugeTTL serves the cached snapshot (O(1)); the
	// first scrape after it does exactly one refresh walk; sessionGaugeSF
	// coalesces concurrent stale-scrapes onto a single in-flight walk so N
	// parallel scrapes never fan out to N walks. The zero value is usable, so
	// literal-constructed test collectors get the default TTL and a working
	// cache. sessionGaugeTTLOverride is 0 in production (=> the default const);
	// tests set it to drive TTL boundaries deterministically.
	sessionGaugeMu          sync.Mutex
	sessionGaugeSF          singleflight.Group
	sessionGaugeSnap        sessionGaugeSnapshot
	sessionGaugeComputedAt  time.Time
	sessionGaugeValid       bool
	sessionGaugeTTLOverride time.Duration

	// Global counters
	packetsTotal         *prometheus.Desc
	dropsTotal           *prometheus.Desc
	sessionsCreatedTotal *prometheus.Desc
	sessionsClosedTotal  *prometheus.Desc
	screenDropsTotal     *prometheus.Desc
	// #3343: per-screen-reason drop counter, labeled by reason. The aggregate
	// xpf_screen_drops_total above cannot answer "which screen fired?"; this
	// labeled series can, now that the userspace bridge populates the per-reason
	// GlobalCtrScreen* counters.
	screenDropsByReasonTotal *prometheus.Desc
	// #5806: unresolved screen-profile references (see the descriptor).
	screenUnresolvedProfileZones *prometheus.Desc
	screenInertProfileZones      *prometheus.Desc
	policyDeniesTotal            *prometheus.Desc
	natAllocFailsTotal           *prometheus.Desc
	nat64XlateTotal              *prometheus.Desc
	hostInboundDeny              *prometheus.Desc
	hostInboundKernelDenies      *prometheus.Desc
	hostInboundJunosHostDenies   *prometheus.Desc
	hostInboundICMPNDAccept      *prometheus.Desc
	hostInboundAddresslessZones  *prometheus.Desc
	hostInboundAddresslessIface  *prometheus.Desc
	hostInboundAmbiguousAddrs    *prometheus.Desc
	lo0CounterHits               *prometheus.Desc
	pbrRulesInstalled            *prometheus.Desc
	pbrDegradedTerms             *prometheus.Desc
	tcEgressPacketsTotal         *prometheus.Desc
	syncookieTotal               *prometheus.Desc
	flowCacheTotal               *prometheus.Desc

	// #3345/#3408: monotonic count of counter reads that failed during a
	// scrape, across the global, per-zone, per-policy, and per-filter dataplane
	// collectors AND the kernel-nftables host-inbound collector (#3361). A
	// failed read SKIPS emitting that counter's sample (so a degraded counter
	// bridge does NOT report a misleading 0); this metric is the scrape-error
	// signal an operator alerts on. Persisted on the collector so it accumulates
	// across scrapes like a real counter. #3462/#5045: the SAMPLE is emitted via
	// a `defer c.emitCounterReadErrors(ch)` established at the TOP of Collect, so
	// it runs at function exit — after all collectors that can bump it — on
	// EVERY return path (the unloaded-dataplane early return AND normal
	// completion). A failure this scrape is reflected this scrape, and the
	// omit-plus-error contract is never violated by an early return.
	counterReadErrorsTotal *prometheus.Desc
	counterReadErrors      atomic.Uint64

	// Interface counters
	ifacePacketsTotal *prometheus.Desc
	ifaceBytesTotal   *prometheus.Desc
	// #3464: monotonic count of per-interface counter reads that failed during
	// a scrape. A failed read SKIPS that interface's xpf_interface_* samples
	// (so a degraded counter bridge does NOT report a misleading 0); this
	// metric is the scrape-error signal for interface counters. Kept SEPARATE
	// from counterReadErrorsTotal because interface counters are intentionally
	// out of the #3345 security-counter contract (README "Out of scope"), so
	// an operator can alert on a degraded interface-counter bridge without
	// conflating it with security-counter health. The SAMPLE is emitted last in
	// Collect (emitInterfaceCounterReadErrors), after collectInterfaceCounters,
	// so a failure this scrape is reflected this scrape.
	interfaceCounterReadErrorsTotal *prometheus.Desc
	interfaceCounterReadErrors      atomic.Uint64

	// Zone counters (#3651, restored after the #3643 HIDE). Sourced from the
	// Go-side SPARSE zone-counter offset map, never a dense array indexed by
	// zone id — see initZoneDescriptors for why that distinction is the whole
	// point. zoneCountersUnpopulatedZones is the explicit "not yet known"
	// signal that lets the per-zone samples be OMITTED rather than published
	// as an authoritative 0.
	zonePacketsTotal             *prometheus.Desc
	zoneBytesTotal               *prometheus.Desc
	zoneCountersUnpopulatedZones *prometheus.Desc
	// #6845: 0/1 — 1 while the helper's per-zone hot-path slot table has
	// OVERFLOWED, so some configured zones are not being counted at all.
	// Emitted only when a helper status was actually read, so its ABSENCE means
	// "no helper to ask" rather than "no overflow" — see the descriptor.
	zoneCountersOverflowActive *prometheus.Desc

	// Policy counters. policyCountersUnpublishedRules is the policy analogue of
	// zoneCountersUnpopulatedZones: the explicit "no counter published for this
	// rule" signal that lets the per-rule sample be OMITTED rather than
	// published as an authoritative 0 -- and, critically, WITHOUT bumping
	// counterReadErrors, because unpublished is not a failure (#7016).
	policyHitsTotal                *prometheus.Desc
	policyCountersUnpublishedRules *prometheus.Desc

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
	sessionScrapeOK     *prometheus.Desc
	gcSweepDuration     *prometheus.Desc

	// NAT pool utilization
	natPoolUsedPorts                  *prometheus.Desc
	natPoolTotalPorts                 *prometheus.Desc
	natPoolDeterministicInfo          *prometheus.Desc
	natPoolDetBlocksTotal             *prometheus.Desc
	natPoolDetBlocksAllocated         *prometheus.Desc
	userspaceSNATPoolLiveFlows        *prometheus.Desc
	userspaceSNATPoolUsedPorts        *prometheus.Desc
	userspaceSNATPoolPersistentLeases *prometheus.Desc
	userspaceSNATPoolAllocationsTotal *prometheus.Desc
	userspaceSNATPoolReusesTotal      *prometheus.Desc
	userspaceSNATPoolExhaustionsTotal *prometheus.Desc
	// #4800: the per-pool NAT-allocator leg of the new-flow-install
	// contention surface. Always emitted as a pair — a contention count
	// without its denominator is not interpretable.
	userspaceSNATPoolLiveLockAcquisitionsTotal *prometheus.Desc
	userspaceSNATPoolLiveLockContendedTotal    *prometheus.Desc

	// DHCP lease gauge
	dhcpLeasesActive *prometheus.Desc

	// DHCP dynamic-DNS metrics (#1387 inc-2)
	dhcpDDNSUpsertsTotal       *prometheus.Desc
	dhcpDDNSDeletesTotal       *prometheus.Desc
	dhcpDDNSReconcileRunsTotal *prometheus.Desc
	dhcpDDNSSkippedTotal       *prometheus.Desc
	dhcpDDNSOwnedRecords       *prometheus.Desc
	dhcpDDNSPTRPending         *prometheus.Desc
	dhcpDDNSDegraded           *prometheus.Desc
	dhcpDDNSLastReconcileTs    *prometheus.Desc
	dhcpDDNSLastReconcileN     *prometheus.Desc

	// Surface A (router/interface-address) DDNS metrics (#2691 P2).
	surfaceADDNSUpsertsTotal *prometheus.Desc
	surfaceADDNSDeletesTotal *prometheus.Desc
	surfaceADDNSSkippedTotal *prometheus.Desc
	surfaceADDNSScopes       *prometheus.Desc
	surfaceADDNSOrphaned     *prometheus.Desc
	surfaceADDNSDegraded     *prometheus.Desc

	// System metrics
	sysCPUUser   *prometheus.Desc
	sysCPUSystem *prometheus.Desc
	sysMemTotal  *prometheus.Desc
	sysMemAvail  *prometheus.Desc
	daemonUptime *prometheus.Desc
	daemonMemRSS *prometheus.Desc

	// #4707: previous /proc/stat aggregate-cpu tick sample, used to compute
	// the inter-scrape CPU-utilization delta. The pre-#4707 collector divided
	// cumulative-since-boot busy ticks by cumulative total ticks and exported
	// the ratio as a gauge — a lifetime average that barely moves as uptime
	// grows, so a real CPU spike at hour 100 was invisible and load alarms
	// silently never fired. We now persist the prior sample and report
	// (busyΔ/totalΔ) between consecutive scrapes (the idiomatic Prometheus
	// approach). Guarded by c.mu because Collect can run concurrently for
	// parallel scrapers. cpuSampleValid is false until the first scrape has
	// stored a predecessor, so no CPU gauge is emitted that first round.
	cpuSamplePrev  cpuSample
	cpuSampleValid bool

	// #1780: per-phase age of the Go periodic neighbor-maintenance loop.
	neighborPeriodicAge *prometheus.Desc
	frrReloadDegraded   *prometheus.Desc
	// #7640: gauge — NAT rules the tolerant path admitted despite the strict
	// terminal-action cardinality gate. Non-zero means the node is running a
	// rule a commit would have refused, on a path with no commit response to
	// report it.
	natRulesLenientTerminalAction *prometheus.Desc
	// #6807: gauge — how many route-maps the last rendered FRR managed
	// section replaced with the bounded explicit deny because their
	// expansion would overflow FRR's sequence ceiling. Non-zero is an
	// ongoing route withdrawal on every neighbor carrying one.
	frrRouteMapsQuarantined *prometheus.Desc
	// #4899: 0/1 gauge — 1 while the last DHCP-lease-change IPsec rebind
	// failed and swanctl local_addrs are still bound to a stale lease
	// address (the retry loop has not yet reconverged).
	ipsecRebindPending *prometheus.Desc

	// #6802: 0/1 gauge — 1 while a host-inbound kernel-conntrack revocation
	// has FAILED and not yet been re-driven. While set, direct-kernel
	// connections to a service the operator has REMOVED may still be riding
	// the host-inbound chain's leading `ct state established,related accept`,
	// i.e. the failure is fail-OPEN. hostInboundConntrackRevocationFailures is
	// the monotonic count of those failures.
	hostInboundConntrackRevocationPending  *prometheus.Desc
	hostInboundConntrackRevocationFailures *prometheus.Desc

	// #6800: the xpf-managed service configuration files (rsyslog drop-ins,
	// chrony sources/threshold) converge on disk and then gate a RUNTIME reload
	// on "did the on-disk set change". A reload that FAILS after the file
	// converged used to be erased by that gate, so the daemon kept serving the
	// previous ruleset with nothing to see. Labelled by `service` because the
	// legs fail independently and drive different commands.
	managedServiceReloadPending  *prometheus.Desc
	managedServiceReloadFailures *prometheus.Desc

	// #7615: the remaining debt-driven retry owners. Each is 1 while its loop
	// owes a repair, so a node re-driving a failing recovery stops looking
	// identical to a healthy one.
	raDeadSenderPending    *prometheus.Desc
	fabricOverlayMissing   *prometheus.Desc
	managementListenerDown *prometheus.Desc

	// #3780: 0/1 gauge — 1 while the most recent scheduler-driven policy
	// republish failed and has not yet converged (stale enforcement past
	// a schedule window: a permit still forwarding, or a scheduled block
	// that never engaged). schedulerRepublishStale is the age of that
	// failure streak in seconds (0 when healthy).
	schedulerRepublishFailed *prometheus.Desc
	schedulerRepublishStale  *prometheus.Desc
	// #5669: 0/1 gauge — 1 while the scheduler-republish failure streak has
	// persisted past the bounded age and the scheduler has escalated to
	// fail-closed (forcing scheduled policies inactive/deny), distinct from the
	// climbing stale-seconds age so an operator can alarm on the crisp
	// fail-closed crossing.
	schedulerRepublishFailClosed *prometheus.Desc

	// #1799: 0/1 gauge — 1 while the running active config failed to
	// persist to disk and the configstore's background retry has not
	// yet succeeded (restart would load a stale config).
	configPersistDegraded *prometheus.Desc

	// #3441: 0/1 gauge — 1 while the most recent commit failed to durably
	// write its text rollback-history files (the canonical rollback
	// history; loadRollbackHistory reads them at boot). The commit itself
	// still succeeded — the active config persisted via the #1799 path —
	// so this is an observability signal for a degraded recovery aid, not
	// a forwarding/durability emergency.
	rollbackHistoryDegraded *prometheus.Desc

	// #3261: 0/1 gauge — 1 while the most recently built userspace snapshot
	// carries unrepresentable policy content that the helper integrity
	// preflight rejects (previous-good retained / fresh-boot default-deny —
	// never fail-open). Nonzero means the running dataplane policy is NOT the
	// committed config; edit out the offending application/address and
	// re-commit. Surfaces the deliberate Go/Rust skew (ForwardingSupported=true
	// while the helper rejected the snapshot) so it is observable.
	userspacePolicyContentRejected *prometheus.Desc

	// #3719: 1 while the most recent userspace snapshot quarantined a security
	// zone whose StableZoneID collided with another zone's (lenient / HA-sync /
	// pre-#3075-persisted path). Zone isolation is degraded until one zone is
	// renamed.
	userspaceZoneIDCollision *prometheus.Desc

	// #1827: services ip-monitoring observability. #1844 adds the
	// unresolved interface-typed next-hop gauge (preferred routes of
	// FAILED policies skipped from the overlay for lack of a
	// DHCP-learned gateway).
	ipmonPolicyFailed       *prometheus.Desc
	ipmonPolicyTransitions  *prometheus.Desc
	ipmonRoutesApplied      *prometheus.Desc
	ipmonRoutesDesired      *prometheus.Desc
	ipmonUnresolvedNextHops *prometheus.Desc
	ipmonActuationFailures  *prometheus.Desc

	// #1895: count of RPM next-hop probe pins whose kernel fwmark
	// rule / pinned route failed to install (affected tests hold
	// state instead of probing the default path).
	rpmPinInstallFailures *prometheus.Desc

	// #2157: event-options remediation action observability. Makes the
	// previously-silent loss (drop on held config lock) visible.
	eventActionsCommitted         *prometheus.Desc
	eventActionsCommittedWithDebt *prometheus.Desc
	eventActionsRejected          *prometheus.Desc
	eventActionsRetried           *prometheus.Desc
	eventActionsDropped           *prometheus.Desc
	eventActionsSuperseded        *prometheus.Desc
	eventAttributesInvalid        *prometheus.Desc
	eventActionQueueDepth         *prometheus.Desc
	eventStreamSubscriberDropped  *prometheus.Desc

	// #2050: dynamic-address feed staleness. seconds-since-last-success
	// climbs while a feed cannot be refreshed (retain-forever default
	// keeps the last-good snapshot enforced indefinitely); the stale
	// gauge is 1 while a retained snapshot is being served as stale.
	feedSecondsSinceSuccess *prometheus.Desc
	feedStale               *prometheus.Desc

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
	// #1359: per-queue drain-loop / shaper park-reason counters. The
	// Rust helper already carries these on the CoS snapshot (protocol.go
	// RootTokenStarvationParks / QueueTokenStarvationParks /
	// DrainParkRootTokens / DrainParkQueueTokens) but they were never
	// exported. Surfacing them lets an operator attribute a surplus-
	// sharing mouse-latency tail to ROOT-surplus arbitration (a borrower
	// holds the shared root tokens — *_root_*) versus per-queue token
	// starvation (this queue's own bucket is empty — *_queue_*).
	cosRootTokenStarvationParks  *prometheus.Desc
	cosQueueTokenStarvationParks *prometheus.Desc
	cosDrainParkRootTokens       *prometheus.Desc
	cosDrainParkQueueTokens      *prometheus.Desc
	// #1628: per-class waterfill-selector trace counters. Per-queue
	// (admissions/visits/no-progress) plus per-interface
	// (epochs/breaks/min-epochs).
	cosWaterfillPhase1Admissions         *prometheus.Desc
	cosWaterfillPhase2Admissions         *prometheus.Desc
	cosWaterfillEligibleVisits           *prometheus.Desc
	cosWaterfillPhase1SelectedNoProgress *prometheus.Desc
	cosWaterfillEpochs                   *prometheus.Desc
	cosWaterfillPhase1BudgetBreaks       *prometheus.Desc
	cosWaterfillMinEpochsPerWorker       *prometheus.Desc
	// #1863 Step-0: per-(queue, worker) v8 lease claim-flow counters
	// (requested vs granted bytes) + per-queue admission-path drop
	// counters. The claim-flow pair attributes the honored-realization
	// gap between share/demand mismatch and claim-sampling loss per the
	// registered decision rule (docs/research/1863-realization-gap).
	cosLeaseV8RequestedBytes   *prometheus.Desc
	cosLeaseV8GrantedBytes     *prometheus.Desc
	cosAdmissionFlowShareDrops *prometheus.Desc
	cosAdmissionBufferDrops    *prometheus.Desc
	cosAdmissionEcnMarked      *prometheus.Desc
	// #1304: Rust-owned opt-in equal-flow enforcement telemetry for
	// shared v8 CoS queue leases. Kept separate from the
	// measurement-only xpf_fairness_equal_flow_* estimator gauges.
	cosEqualFlowEnforcementEnabled       *prometheus.Desc
	cosEqualFlowTargetPolicy             *prometheus.Desc
	cosEqualFlowEnforced                 *prometheus.Desc
	cosEqualFlowTargetPerFlowBPS         *prometheus.Desc
	cosEqualFlowMaxWorkerCapBytes        *prometheus.Desc
	cosEqualFlowCapHitEvents             *prometheus.Desc
	cosEqualFlowSuppressedGrantBytes     *prometheus.Desc
	cosEqualFlowStaleOrTagMismatchEvents *prometheus.Desc
	cosEqualFlowFailOpen                 *prometheus.Desc
	// #1829 Phase 1: dequeue-time sojourn gauges. The windowed-min
	// gauge is the Phase-2 gate metric (standing-queue estimator).
	cosSojournEwmaNS        *prometheus.Desc
	cosSojournPeakNS        *prometheus.Desc
	cosSojournWindowedMinNS *prometheus.Desc
	// #1830 (g): bucket-vs-flow occupancy gauges for flow-fair CoS
	// queues (collision-vs-demand unfairness diagnosis).
	cosFlowFairBucketsOccupied *prometheus.Desc
	cosFlowFairFlowsActive     *prometheus.Desc
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
	// #1782 Step-1 cold-start CoS instruments: per-worker timer-wheel
	// tick-advance sum + single-call high-water max (mechanism (i)) and
	// the per-cause v8 queue-lease under-grant family (mechanism (ii)).
	workerCoSWheelTicksAdvancedTotal         *prometheus.Desc
	workerCoSWheelTicksAdvancedMax           *prometheus.Desc
	workerCoSQueueLeaseUndergrant            *prometheus.Desc
	workerSessionTableEntries                *prometheus.Desc
	workerSessionTableCapacity               *prometheus.Desc
	workerNatReverseKeyCollisions            *prometheus.Desc
	workerNatReverseKeyCollisionsDistinctSrc *prometheus.Desc
	// #1861: install-refusal trio (per-worker + aggregate).
	workerSessionCreateDrops             *prometheus.Desc
	workerSessionInstallAdmissionRefused *prometheus.Desc
	workerSessionInstallPartial          *prometheus.Desc
	// #4800: per-worker transit new-flow installs, plus the six
	// process-global publish/replication contention counters.
	workerNewFlowInstalls                       *prometheus.Desc
	userspaceSharedSessionPublishes             *prometheus.Desc
	userspaceSharedSessionPublishLockAcquired   *prometheus.Desc
	userspaceSharedSessionPublishLockBlocked    *prometheus.Desc
	userspaceSessionReplicationUpserts          *prometheus.Desc
	userspaceSessionReplicationEnqueued         *prometheus.Desc
	userspaceSessionReplicationLockBlocked      *prometheus.Desc
	userspaceSessionReplicationQueueDepthSum    *prometheus.Desc
	userspaceSessionReplicationQueueDepthMax    *prometheus.Desc
	userspaceSessionCreateDrops                 *prometheus.Desc
	userspaceSessionInstallAdmissionRefused     *prometheus.Desc
	userspaceSessionInstallPartial              *prometheus.Desc
	userspaceSessionTableEntries                *prometheus.Desc
	userspaceSessionTableCapacity               *prometheus.Desc
	userspaceNatReverseKeyCollisions            *prometheus.Desc
	userspaceNatReverseKeyCollisionsDistinctSrc *prometheus.Desc
	// #1789: total failed USERSPACE_SESSIONS BPF-map publishes — the
	// cause-side signal for rising XDP-shim NO_SESSION fallbacks.
	userspaceSessionPublishErrors *prometheus.Desc

	// #2244: total failed dnat_table reverse-SNAT BPF-map publishes — the
	// cause-side signal for dnat_table map-capacity pressure that silently
	// breaks embedded-ICMP NAT reversal (PMTUD / traceroute).
	userspaceDnatPublishErrors *prometheus.Desc

	// #5674: peer-synced session imports rejected by the coordinator's
	// aggregate admission bound — the availability/DoS ceiling that keeps a
	// peer under session-table pressure (or a compromised peer) from driving
	// this node past its own aggregate session ceiling and multiplying that
	// state across every worker.
	userspaceSyncedImportCapDrops *prometheus.Desc

	// #1760 W3': shared-map NAT reverse-key displacement events (the
	// authoritative collision watch; covers seed installs the per-worker
	// counter cannot see).
	userspaceNatReverseKeySharedDisplacements *prometheus.Desc
	// #6751 PR 2/3: the interface-mode SNAT identity registry's three
	// outcomes — PAT'd collisions, identity exhaustion, registry-cap
	// exhaustion.
	userspaceInterfaceSNATPATCollisions      *prometheus.Desc
	userspaceInterfaceSNATIdentityExhaustion *prometheus.Desc
	userspaceInterfaceSNATSyncConflictDrops  *prometheus.Desc
	userspaceInterfaceSNATRegistryCap        *prometheus.Desc
	// #1807: worker-command-queue poison recoveries — nonzero means a
	// helper worker panic poisoned a command queue and it was recovered
	// (committed-prefix + clear_poison policy) instead of going deaf.
	userspaceWorkerCommandQueuePoisonRecoveries *prometheus.Desc
	// #6929: worker commands dropped at the per-worker queue cap —
	// nonzero means a producer found a full queue, which points at a
	// worker that stopped draining rather than at a fast producer.
	userspaceWorkerCommandQueueDrops       *prometheus.Desc
	userspaceSharedSessionPoisonRecoveries *prometheus.Desc
	// #2315: GRE-decap RFC 6040 §4.2 illegal-combination drops (outer CE
	// over a Not-ECT inner) — nonzero flags a misbehaving tunnel ingress
	// that ECT-marked the outer for un-ECN inner traffic on a congested
	// path.
	userspaceGreDecapEcnIllegalDrops *prometheus.Desc
	// #2317: WG-decap RFC 6040 §4.2 illegal-combination drops (outer CE,
	// captured via recvmsg IP_RECVTOS/IPV6_RECVTCLASS, over a Not-ECT
	// inner) — the WG sibling of the GRE counter above.
	userspaceWgDecapEcnIllegalDrops *prometheus.Desc
	// #2331: native-GRE encap frames dropped because the fully built outer
	// datagram exceeded the resolved transport/egress MTU while the IPv4
	// outer carries DF=1 (the only outer the native builder emits). A
	// DF-set oversized outer cannot be fragmented downstream and would
	// silently blackhole every inner flow with no PMTUD signal.
	userspaceGreEncapDfOversizeDrops *prometheus.Desc
	// #2782: native-GRE decap frames dropped because the Checksum-Present
	// (C) bit was set but the GRE checksum failed to verify (or the header
	// was truncated past the 4-byte Checksum+Reserved1 field). A
	// checksummed peer (e.g. vSRX) now decaps after skipping+validating
	// the checksum (RFC 2784 §2.1 / RFC 2890) instead of being silently
	// blackholed; only a corrupt frame is counted here.
	userspaceGreDecapChecksumInvalidDrops *prometheus.Desc
	// #6842: native-GRE frames refused for decap because the GRE version
	// field was non-zero (RFC 2637 / PPTP enhanced GRE is version 1) while
	// the outer tuple named a configured GRE tunnel endpoint. A refusal,
	// not a drop; transit PPTP is not counted.
	userspaceGreDecapUnsupportedVersionRefusals *prometheus.Desc
	// #2472: locally-generated ICMP/RST error replies dropped by the
	// per-reason token-bucket rate limiter (Time Exceeded / PTB / reject).
	userspaceTimeExceededRateLimited *prometheus.Desc
	userspacePacketTooBigRateLimited *prometheus.Desc
	userspaceRejectRateLimited       *prometheus.Desc
	// #3657 (H15/M02) / #3661: source-split reject reply telemetry. The
	// aggregate userspaceRejectRateLimited above stays for back-compat; these
	// expose the #3615 per-BindingStatus sent / TX-frame reply-budget /
	// egress output-filter drop legs plus the #3661 rate-limit drop leg,
	// labeled source=policy|filter, so alerting can attribute reject SUCCESS
	// vs SUPPRESSION to a security policy `then reject` or a firewall-filter
	// `then reject`. The rate-limit bucket is still a single global-per-reason
	// bucket in the helper; #3661 attributes each drop to the reply's source
	// at the consume site (policy+filter sum to the aggregate).
	userspaceRejectSent                *prometheus.Desc
	userspaceRejectReplyBudgetDrops    *prometheus.Desc
	userspaceRejectOutputFilterDrops   *prometheus.Desc
	userspaceRejectRateLimitedBySource *prometheus.Desc
	// #4768: per-binding drop-class counters (#4743) summed across bindings.
	userspaceMartianDropped       *prometheus.Desc
	userspaceIPv6ExtHeaderDropped *prometheus.Desc
	userspaceFlowCacheActiveFlows *prometheus.Desc
	userspaceFlowCacheCapacity    *prometheus.Desc
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
	// #1621: cold-path latency histogram surface (#1612 step-3).
	// Per worker / zone-pair-slot histogram of policy-eval slow path
	// latency. The 24-bucket power-of-two histogram lives on the
	// dataplane side; we expose it here as a Prometheus-native
	// `_bucket{le="..."}` counter family compatible with PromQL
	// histogram_quantile().
	workerColdPathBucket              *prometheus.Desc
	workerColdPathSamples             *prometheus.Desc
	workerColdPathSumNS               *prometheus.Desc
	workerColdPathAliasSeen           *prometheus.Desc
	workerColdPathSamplePhase         *prometheus.Desc
	workerColdPathWrapperUnderflow    *prometheus.Desc
	workerColdPathWrapperNSBaseline   *prometheus.Desc
	workerColdPathNSPerTSCQ32         *prometheus.Desc
	workerColdPathClockSource         *prometheus.Desc
	workerColdPathSnapshotFailedTotal *prometheus.Desc
	// #1635 sparse v3 per-zone-pair families (from_zone/to_zone labels).
	workerColdPathBucketV3           *prometheus.Desc
	workerColdPathSamplesV3          *prometheus.Desc
	workerColdPathSumNSV3            *prometheus.Desc
	workerColdPathBuilderCollisionV3 *prometheus.Desc
	workerColdPathOverflowActive     *prometheus.Desc
	workerColdPathLayoutVersion      *prometheus.Desc
	workerColdPathLayoutUnknownTotal *prometheus.Desc
	// #1219: snapshot per-binding distinct active flow count for the
	// fairness harness (read by test/incus/fairness-harness.sh ->
	// fairness-eval to compute Cstruct + observed_CoV per
	// docs/fairness-regimes.md). Refreshed at the helper's ~65ms
	// debug-state tick.
	bindingActiveFlowCount   *prometheus.Desc
	bindingFlowCacheCapacity *prometheus.Desc
	// #1241: per-binding AF_XDP TX completion service telemetry.
	// These signals let fairness measurements distinguish scheduler/RSS
	// skew from per-queue completion-ring service asymmetry.
	bindingTXCompletions                *prometheus.Desc
	bindingTXCompletionRingAvailable    *prometheus.Desc
	bindingTXCompletionRingAvailableMax *prometheus.Desc
	// #1831 (follow-up to #1766): per-binding V_min fairness-throttle
	// counters (#941 work item D / #943). Already on the wire in
	// BindingStatus; these export them to Prometheus. v_min_throttles
	// is "fairness brake fired"; hard-cap overrides is "brake too
	// tight, escape hatch rescued throughput" — the ratio is the
	// LAG_THRESHOLD diagnostic.
	bindingVMinThrottles                *prometheus.Desc
	bindingVMinThrottleHardCapOverrides *prometheus.Desc
	// #7409: per-binding slow-path reinject counters, split by the
	// disposition that sent the frame to the kernel. Already on the
	// BindingStatus wire since the counters were added; unexported until
	// now, which meant a rising reinject rate reached no alerting and was
	// visible only in `show`-style status output — the symptom of a policy
	// bypass was unobservable in production even once you knew to look.
	// no_route is the #7409 signal itself: every frame counted there was
	// forwarded by the kernel with no zone policy, session, NAT or screen.
	bindingSlowPathNoRoutePackets         *prometheus.Desc
	bindingSlowPathNextTablePackets       *prometheus.Desc
	bindingNextTableUnsupportedDrops      *prometheus.Desc
	bindingSlowPathLocalDeliveryPackets   *prometheus.Desc
	bindingSlowPathMissingNeighborPackets *prometheus.Desc
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
	// #1636 option C: proactive-neighbor-warm telemetry. The only
	// operator-visible signal for the warmer in production builds.
	neighborWarmDropsTotal        *prometheus.Desc
	neighborWarmDisconnectedTotal *prometheus.Desc
	// #1782 cold-start capture instrumentation. negNeighFastFailTotal is
	// the H1 amplifier signal; pendingNeighDuplicateDropsTotal is the H5
	// sibling-drop signal; dynamicNeighborPresent is a per-key presence
	// gauge dumped from the helper's dynamic_neighbors mirror so the
	// capture harness can grep the t0' next-hop membership (H2).
	negNeighFastFailTotal           *prometheus.Desc
	pendingNeighDuplicateDropsTotal *prometheus.Desc
	// #1902: decap-refusal gate at pending_neigh admission (frame/meta
	// pairing defect class — see also #1885/#1873).
	pendingNeighDecapDropsTotal *prometheus.Desc
	// #2375: distinct-hop capacity-drop gate at pending_neigh admission —
	// a NEW unresolved hop refused because the per-binding map is at
	// MAX_PENDING_NEIGH (the scan/upstream-outage failure mode). Kept
	// separate from pendingNeighDuplicateDropsTotal.
	pendingNeighCapacityDropsTotal *prometheus.Desc
	// #5673: data-path neighbor learns refused by the aggregate
	// dynamic-neighbor map cap (spoofed-source pre-policy flood bound).
	dynamicNeighborLearnCapDropsTotal *prometheus.Desc
	dynamicNeighborPresent            *prometheus.Desc
	// #1769: on-demand neighbor-resolver telemetry — the operator-visible
	// signal for the MissingNeighbor stuck-state.
	neighborResolverQueueDepth        *prometheus.Desc
	neighborResolverEnqueueDropsTotal *prometheus.Desc
	neighborResolverDisconnectedTotal *prometheus.Desc
	neighborResolverGetAttemptsTotal  *prometheus.Desc
	neighborResolverGetResolvedTotal  *prometheus.Desc
	neighborResolverProbeOnStaleTotal *prometheus.Desc
	neighborResolverGetFailuresTotal  *prometheus.Desc
	neighborResolverEpochRejectsTotal *prometheus.Desc
	// #1772: neighbor/ARP resolution LATENCY histograms + counters.
	neighborPendingDwellSeconds      *prometheus.Desc
	neighborResolverGetRttSeconds    *prometheus.Desc
	neighborPendingTimeoutDropsTotal *prometheus.Desc
	neighborPendingMaxDepth          *prometheus.Desc
	// #1771 §2.6: resolver backoff-retry counter, §2.5 ENOBUFS/re-dump
	// counters, and the pending-keys / negative-keys gauges.
	neighborResolverGetBackoffAttemptsTotal *prometheus.Desc
	neighborNetlinkEnobufsTotal             *prometheus.Desc
	neighborNetlinkRedumpsTotal             *prometheus.Desc
	neighborNetlinkRedumpUpsertsTotal       *prometheus.Desc
	neighborPendingKeys                     *prometheus.Desc
	negNeighKeys                            *prometheus.Desc
	// #3773 (M13): fabric-link skip diagnostics — malformed value vs
	// unresolved (empty) peer/local MAC.
	fabricLinkSkippedMalformedTotal *prometheus.Desc
	fabricLinkUnresolvedPeerTotal   *prometheus.Desc
	// #1865: operator-visible WireGuard telemetry — per-tunnel
	// handshake/encap/decap counters + drop reasons from the helper's
	// wg_tunnels status rows. Label sets: {tunnel} (+ role / direction
	// / reason / kind bounded enums). The tunnel label is the tunnel
	// NAME (stable across commits; #1873 ids are not).
	wgHandshakesCompletedTotal              *prometheus.Desc
	wgHandshakeInitiationsCreatedTotal      *prometheus.Desc
	wgHandshakeInitiationBuildFailuresTotal *prometheus.Desc
	wgHandshakeRxDropsTotal                 *prometheus.Desc
	wgHandshakeRequestsArmedTotal           *prometheus.Desc
	// #4094 PR-A responder cookie-reply / MAC2 under-load mechanism
	// "working" signals: event=sent (cookie challenges emitted),
	// event=mac2_ok (primed peers that completed a handshake under load).
	wgCookieRepliesTotal            *prometheus.Desc
	wgTransportPacketsTotal         *prometheus.Desc
	wgTransportBytesTotal           *prometheus.Desc
	wgKeepalivesReceivedTotal       *prometheus.Desc
	wgTransportDropsTotal           *prometheus.Desc
	wgSendErrorsTotal               *prometheus.Desc
	wgSessionConfirmed              *prometheus.Desc
	wgLastHandshakeTimeSeconds      *prometheus.Desc
	wgRekeysInitiatedTotal          *prometheus.Desc
	wgKeepalivesSentTotal           *prometheus.Desc
	wgSessionsExpiredTotal          *prometheus.Desc
	wgHandshakeAttemptsAbortedTotal *prometheus.Desc

	// #2464: per-collector NetFlow v9 / IPFIX write-health. A flow-export
	// collector that goes unreachable used to be invisible (every failed
	// UDP write was debug-logged and dropped while the exporter kept
	// counting "exported"). Labels: protocol {netflow-v9,ipfix} and the
	// collector address (bounded — one per configured flow-server).
	flowExportCollectorWriteAttemptsTotal *prometheus.Desc
	flowExportCollectorWriteFailuresTotal *prometheus.Desc
	flowExportCollectorWriteSkippedTotal  *prometheus.Desc
	flowExportCollectorHealthy            *prometheus.Desc
	flowExportCollectorLastSuccessSeconds *prometheus.Desc
	flowExportCollectorLastFailureSeconds *prometheus.Desc

	// #3747: per-exporter pending-batch queue depth / high-water / drop count.
	// The export batch was unbounded; a stalled or overrun drain grew memory
	// without bound and silently. These surface the backlog and any bounded
	// drops. Labels: protocol {netflow-v9,ipfix}, instance, template (bounded
	// — one series per configured flow-server group).
	flowExportBatchDepth        *prometheus.Desc
	flowExportBatchMaxDepth     *prometheus.Desc
	flowExportBatchDroppedTotal *prometheus.Desc
}

func (c *xpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packetsTotal
	ch <- c.dropsTotal
	ch <- c.sessionsCreatedTotal
	ch <- c.sessionsClosedTotal
	ch <- c.screenDropsTotal
	ch <- c.screenDropsByReasonTotal
	ch <- c.screenUnresolvedProfileZones
	ch <- c.screenInertProfileZones
	ch <- c.policyDeniesTotal
	ch <- c.natAllocFailsTotal
	ch <- c.nat64XlateTotal
	ch <- c.hostInboundDeny
	ch <- c.hostInboundKernelDenies
	ch <- c.hostInboundJunosHostDenies
	ch <- c.hostInboundICMPNDAccept
	ch <- c.hostInboundAddresslessZones
	ch <- c.hostInboundAddresslessIface
	ch <- c.hostInboundAmbiguousAddrs
	ch <- c.lo0CounterHits
	ch <- c.pbrRulesInstalled
	ch <- c.pbrDegradedTerms
	ch <- c.tcEgressPacketsTotal
	ch <- c.syncookieTotal
	ch <- c.flowCacheTotal
	ch <- c.counterReadErrorsTotal
	ch <- c.ifacePacketsTotal
	ch <- c.ifaceBytesTotal
	ch <- c.interfaceCounterReadErrorsTotal
	ch <- c.zonePacketsTotal
	ch <- c.zoneBytesTotal
	ch <- c.zoneCountersUnpopulatedZones
	ch <- c.zoneCountersOverflowActive
	ch <- c.policyHitsTotal
	ch <- c.policyCountersUnpublishedRules
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
	ch <- c.sessionScrapeOK
	ch <- c.gcSweepDuration
	ch <- c.natPoolUsedPorts
	ch <- c.natPoolTotalPorts
	ch <- c.natPoolDeterministicInfo
	ch <- c.natPoolDetBlocksTotal
	ch <- c.natPoolDetBlocksAllocated
	ch <- c.userspaceSNATPoolLiveFlows
	ch <- c.userspaceSNATPoolUsedPorts
	ch <- c.userspaceSNATPoolPersistentLeases
	ch <- c.userspaceSNATPoolAllocationsTotal
	ch <- c.userspaceSNATPoolReusesTotal
	ch <- c.userspaceSNATPoolExhaustionsTotal
	ch <- c.userspaceSNATPoolLiveLockAcquisitionsTotal
	ch <- c.userspaceSNATPoolLiveLockContendedTotal
	ch <- c.dhcpLeasesActive
	ch <- c.dhcpDDNSUpsertsTotal
	ch <- c.dhcpDDNSDeletesTotal
	ch <- c.dhcpDDNSReconcileRunsTotal
	ch <- c.dhcpDDNSSkippedTotal
	ch <- c.dhcpDDNSOwnedRecords
	ch <- c.dhcpDDNSPTRPending
	ch <- c.dhcpDDNSDegraded
	ch <- c.dhcpDDNSLastReconcileTs
	ch <- c.dhcpDDNSLastReconcileN
	ch <- c.surfaceADDNSUpsertsTotal
	ch <- c.surfaceADDNSDeletesTotal
	ch <- c.surfaceADDNSSkippedTotal
	ch <- c.surfaceADDNSScopes
	ch <- c.surfaceADDNSOrphaned
	ch <- c.surfaceADDNSDegraded
	ch <- c.sysCPUUser
	ch <- c.sysCPUSystem
	ch <- c.sysMemTotal
	ch <- c.sysMemAvail
	ch <- c.daemonUptime
	ch <- c.daemonMemRSS
	ch <- c.neighborPeriodicAge
	ch <- c.frrReloadDegraded
	ch <- c.frrRouteMapsQuarantined
	ch <- c.natRulesLenientTerminalAction
	ch <- c.ipsecRebindPending
	ch <- c.schedulerRepublishFailed
	ch <- c.schedulerRepublishStale
	ch <- c.schedulerRepublishFailClosed
	ch <- c.hostInboundConntrackRevocationPending
	ch <- c.hostInboundConntrackRevocationFailures
	ch <- c.managedServiceReloadPending
	ch <- c.managedServiceReloadFailures
	ch <- c.raDeadSenderPending
	ch <- c.fabricOverlayMissing
	ch <- c.managementListenerDown
	ch <- c.configPersistDegraded
	ch <- c.rollbackHistoryDegraded
	ch <- c.userspacePolicyContentRejected
	ch <- c.userspaceZoneIDCollision
	ch <- c.ipmonPolicyFailed
	ch <- c.ipmonPolicyTransitions
	ch <- c.ipmonRoutesApplied
	ch <- c.ipmonRoutesDesired
	ch <- c.ipmonUnresolvedNextHops
	ch <- c.ipmonActuationFailures
	ch <- c.rpmPinInstallFailures
	ch <- c.eventActionsCommitted
	ch <- c.eventActionsCommittedWithDebt
	ch <- c.eventActionsRejected
	ch <- c.eventActionsRetried
	ch <- c.eventActionsDropped
	ch <- c.eventActionsSuperseded
	ch <- c.eventAttributesInvalid
	ch <- c.eventActionQueueDepth
	ch <- c.eventStreamSubscriberDropped
	ch <- c.feedSecondsSinceSuccess
	ch <- c.feedStale
	ch <- c.cosDrainLatencyBucket
	ch <- c.cosDrainInvocationsTotal
	ch <- c.cosRedirectAcquireBucket
	ch <- c.cosOwnerPPS
	ch <- c.cosPeerPPS
	ch <- c.cosDrainGuaranteeSentBytes
	ch <- c.cosDrainSurplusSentBytes
	ch <- c.cosDrainNonExactSentBytesWhileExactBacklogged
	ch <- c.cosRootTokenStarvationParks
	ch <- c.cosQueueTokenStarvationParks
	ch <- c.cosDrainParkRootTokens
	ch <- c.cosDrainParkQueueTokens
	ch <- c.cosWaterfillPhase1Admissions
	ch <- c.cosWaterfillPhase2Admissions
	ch <- c.cosWaterfillEligibleVisits
	ch <- c.cosWaterfillPhase1SelectedNoProgress
	ch <- c.cosWaterfillEpochs
	ch <- c.cosWaterfillPhase1BudgetBreaks
	ch <- c.cosWaterfillMinEpochsPerWorker
	ch <- c.cosLeaseV8RequestedBytes
	ch <- c.cosLeaseV8GrantedBytes
	ch <- c.cosAdmissionFlowShareDrops
	ch <- c.cosAdmissionBufferDrops
	ch <- c.cosAdmissionEcnMarked
	ch <- c.cosEqualFlowEnforcementEnabled
	ch <- c.cosEqualFlowTargetPolicy
	ch <- c.cosEqualFlowEnforced
	ch <- c.cosEqualFlowTargetPerFlowBPS
	ch <- c.cosEqualFlowMaxWorkerCapBytes
	ch <- c.cosEqualFlowCapHitEvents
	ch <- c.cosEqualFlowSuppressedGrantBytes
	ch <- c.cosEqualFlowStaleOrTagMismatchEvents
	ch <- c.cosEqualFlowFailOpen
	ch <- c.cosSojournEwmaNS
	ch <- c.cosSojournPeakNS
	ch <- c.cosSojournWindowedMinNS
	ch <- c.cosFlowFairBucketsOccupied
	ch <- c.cosFlowFairFlowsActive
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
	ch <- c.workerCoSWheelTicksAdvancedTotal
	ch <- c.workerCoSWheelTicksAdvancedMax
	ch <- c.workerCoSQueueLeaseUndergrant
	ch <- c.workerSessionTableEntries
	ch <- c.workerSessionTableCapacity
	ch <- c.workerNatReverseKeyCollisions
	ch <- c.workerNatReverseKeyCollisionsDistinctSrc
	ch <- c.workerSessionCreateDrops
	ch <- c.workerSessionInstallAdmissionRefused
	ch <- c.workerSessionInstallPartial
	ch <- c.workerNewFlowInstalls
	ch <- c.userspaceSharedSessionPublishes
	ch <- c.userspaceSharedSessionPublishLockAcquired
	ch <- c.userspaceSharedSessionPublishLockBlocked
	ch <- c.userspaceSessionReplicationUpserts
	ch <- c.userspaceSessionReplicationEnqueued
	ch <- c.userspaceSessionReplicationLockBlocked
	ch <- c.userspaceSessionReplicationQueueDepthSum
	ch <- c.userspaceSessionReplicationQueueDepthMax
	ch <- c.userspaceSessionCreateDrops
	ch <- c.userspaceSessionInstallAdmissionRefused
	ch <- c.userspaceSessionInstallPartial
	ch <- c.userspaceSessionTableEntries
	ch <- c.userspaceSessionTableCapacity
	ch <- c.userspaceNatReverseKeyCollisions
	ch <- c.userspaceNatReverseKeyCollisionsDistinctSrc
	ch <- c.userspaceSessionPublishErrors
	ch <- c.userspaceDnatPublishErrors
	ch <- c.userspaceSyncedImportCapDrops
	ch <- c.userspaceNatReverseKeySharedDisplacements
	ch <- c.userspaceInterfaceSNATPATCollisions
	ch <- c.userspaceInterfaceSNATIdentityExhaustion
	ch <- c.userspaceInterfaceSNATSyncConflictDrops
	ch <- c.userspaceInterfaceSNATRegistryCap
	ch <- c.userspaceWorkerCommandQueuePoisonRecoveries
	ch <- c.userspaceWorkerCommandQueueDrops
	ch <- c.userspaceSharedSessionPoisonRecoveries
	ch <- c.userspaceGreDecapEcnIllegalDrops
	ch <- c.userspaceWgDecapEcnIllegalDrops
	ch <- c.userspaceGreEncapDfOversizeDrops
	ch <- c.userspaceGreDecapChecksumInvalidDrops
	ch <- c.userspaceGreDecapUnsupportedVersionRefusals
	ch <- c.userspaceTimeExceededRateLimited
	ch <- c.userspacePacketTooBigRateLimited
	ch <- c.userspaceRejectRateLimited
	ch <- c.userspaceRejectSent
	ch <- c.userspaceRejectReplyBudgetDrops
	ch <- c.userspaceRejectOutputFilterDrops
	ch <- c.userspaceRejectRateLimitedBySource
	ch <- c.userspaceMartianDropped
	ch <- c.userspaceIPv6ExtHeaderDropped
	ch <- c.userspaceFlowCacheActiveFlows
	ch <- c.userspaceFlowCacheCapacity
	ch <- c.userspaceEventStreamFramesTotal
	ch <- c.userspaceEventStreamProducerFramesTotal
	ch <- c.userspaceEventStreamDecodeErrorsTotal
	ch <- c.userspaceEventStreamSequenceGapsTotal
	ch <- c.userspaceEventStreamDataplaneEventsTotal
	ch <- c.userspaceEventStreamDataplaneDropsTotal
	ch <- c.userspaceEventStreamUnknownDropsTotal
	ch <- c.workerDead
	// #1635: cold-path histogram descriptors. xpfCollector is a CHECKED
	// collector — every Desc emitted by Collect() (via emitWorkerColdPath)
	// MUST be declared here, or promhttp logs a Gather error on every
	// scrape and a HTTPErrorOnError registry returns 500. The v1 +
	// scalar descs were never declared (a latent gap from #1619/#1621);
	// the v3 descs added in #1635 widened it. Declare the whole family.
	ch <- c.workerColdPathBucket
	ch <- c.workerColdPathSamples
	ch <- c.workerColdPathSumNS
	ch <- c.workerColdPathAliasSeen
	ch <- c.workerColdPathSamplePhase
	ch <- c.workerColdPathWrapperUnderflow
	ch <- c.workerColdPathWrapperNSBaseline
	ch <- c.workerColdPathNSPerTSCQ32
	ch <- c.workerColdPathClockSource
	ch <- c.workerColdPathSnapshotFailedTotal
	ch <- c.workerColdPathBucketV3
	ch <- c.workerColdPathSamplesV3
	ch <- c.workerColdPathSumNSV3
	ch <- c.workerColdPathBuilderCollisionV3
	ch <- c.workerColdPathOverflowActive
	ch <- c.workerColdPathLayoutVersion
	ch <- c.workerColdPathLayoutUnknownTotal
	ch <- c.bindingActiveFlowCount
	ch <- c.bindingFlowCacheCapacity
	ch <- c.bindingTXCompletions
	ch <- c.bindingTXCompletionRingAvailable
	ch <- c.bindingTXCompletionRingAvailableMax
	ch <- c.bindingVMinThrottles
	ch <- c.bindingVMinThrottleHardCapOverrides
	ch <- c.bindingSlowPathNoRoutePackets
	ch <- c.bindingSlowPathNextTablePackets
	ch <- c.bindingNextTableUnsupportedDrops
	ch <- c.bindingSlowPathLocalDeliveryPackets
	ch <- c.bindingSlowPathMissingNeighborPackets
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
	ch <- c.neighborWarmDropsTotal
	ch <- c.neighborWarmDisconnectedTotal
	ch <- c.negNeighFastFailTotal
	ch <- c.pendingNeighDuplicateDropsTotal
	ch <- c.pendingNeighDecapDropsTotal
	ch <- c.pendingNeighCapacityDropsTotal
	ch <- c.dynamicNeighborLearnCapDropsTotal
	ch <- c.dynamicNeighborPresent
	ch <- c.neighborResolverQueueDepth
	ch <- c.neighborResolverEnqueueDropsTotal
	ch <- c.neighborResolverDisconnectedTotal
	ch <- c.neighborResolverGetAttemptsTotal
	ch <- c.neighborResolverGetResolvedTotal
	ch <- c.neighborResolverProbeOnStaleTotal
	ch <- c.neighborResolverGetFailuresTotal
	ch <- c.neighborResolverEpochRejectsTotal
	ch <- c.neighborPendingDwellSeconds
	ch <- c.neighborResolverGetRttSeconds
	ch <- c.neighborPendingTimeoutDropsTotal
	ch <- c.neighborPendingMaxDepth
	ch <- c.neighborResolverGetBackoffAttemptsTotal
	ch <- c.neighborNetlinkEnobufsTotal
	ch <- c.neighborNetlinkRedumpsTotal
	ch <- c.neighborNetlinkRedumpUpsertsTotal
	ch <- c.neighborPendingKeys
	ch <- c.negNeighKeys
	ch <- c.fabricLinkSkippedMalformedTotal
	ch <- c.fabricLinkUnresolvedPeerTotal
	ch <- c.wgHandshakesCompletedTotal
	ch <- c.wgHandshakeInitiationsCreatedTotal
	ch <- c.wgHandshakeInitiationBuildFailuresTotal
	ch <- c.wgHandshakeRxDropsTotal
	ch <- c.wgHandshakeRequestsArmedTotal
	ch <- c.wgCookieRepliesTotal
	ch <- c.wgTransportPacketsTotal
	ch <- c.wgTransportBytesTotal
	ch <- c.wgKeepalivesReceivedTotal
	ch <- c.wgTransportDropsTotal
	ch <- c.wgSendErrorsTotal
	ch <- c.wgSessionConfirmed
	ch <- c.wgLastHandshakeTimeSeconds
	ch <- c.wgRekeysInitiatedTotal
	ch <- c.wgKeepalivesSentTotal
	ch <- c.wgSessionsExpiredTotal
	ch <- c.wgHandshakeAttemptsAbortedTotal
	ch <- c.flowExportCollectorWriteAttemptsTotal
	ch <- c.flowExportCollectorWriteFailuresTotal
	ch <- c.flowExportCollectorWriteSkippedTotal
	ch <- c.flowExportCollectorHealthy
	ch <- c.flowExportCollectorLastSuccessSeconds
	ch <- c.flowExportCollectorLastFailureSeconds
	ch <- c.flowExportBatchDepth
	ch <- c.flowExportBatchMaxDepth
	ch <- c.flowExportBatchDroppedTotal
}

func (c *xpfCollector) Collect(ch chan<- prometheus.Metric) {
	// #5045: emit the xpf_counter_read_errors_total scrape-error sample on
	// EVERY return path of Collect, so the #3345/#3462 omit-plus-error contract
	// (a series OMITTED because its read failed => the SAME scrape MUST carry
	// the error signal) holds even in a config-only / degraded boot. The
	// pre-gate host-inbound / lo0 collectors below
	// (collectHostInboundKernelDenies, collectHostInboundJunosHostDenies,
	// collectHostInboundICMPNDAccepts, collectLo0Counters) bump
	// counterReadErrors and SKIP their series on an nft read failure, then
	// Collect hits the `dp == nil || !dp.IsLoaded()` early return. Before this,
	// the only emit site sat AFTER that gate, so an unloaded-dataplane scrape
	// with a failing pre-gate read carried NEITHER the data series NOR the
	// error sample — a clean absence in exactly the degraded state those
	// pre-gate collectors exist to observe. A defer emits the total exactly
	// ONCE at function exit, after every collector that can bump it, on BOTH
	// the unloaded early return and normal completion. counterReadErrors is a
	// cumulative atomic.Uint64 (never reset per-scrape), so the deferred value
	// reflects THIS scrape's + prior errors — identical to the loaded-path
	// value before this change, since nothing after the former emit site
	// (collectSessionGauges..collectUserspaceStatus) bumps it.
	defer c.emitCounterReadErrors(ch)

	// #1799: config-persist health is a control-plane signal — emit it
	// BEFORE the dataplane gate below so the degraded state stays
	// visible even when the dataplane is not loaded.
	if c.srv.configPersistDegradedFn != nil {
		v := 0.0
		if c.srv.configPersistDegradedFn() {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.configPersistDegraded,
			prometheus.GaugeValue, v)
	}

	// #3441: rollback-history persistence is likewise a control-plane
	// signal — emit it before the dataplane gate so the degraded state
	// stays visible even when the dataplane is not loaded.
	if c.srv.rollbackHistoryDegradedFn != nil {
		v := 0.0
		if c.srv.rollbackHistoryDegradedFn() {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.rollbackHistoryDegraded,
			prometheus.GaugeValue, v)
	}

	// #1880: FRR reload-degraded is likewise a control-plane signal
	// (the daemon applies FRR even in config-only mode) — emit it
	// BEFORE the dataplane gate so it never disappears exactly when
	// the fallback path is active.
	if c.srv.frrReloadDegradedFn != nil {
		v := 0.0
		if c.srv.frrReloadDegradedFn() {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.frrReloadDegraded,
			prometheus.GaugeValue, v)
	}

	// #7640: NAT rules admitted by the tolerant path despite the strict
	// terminal-action gate. Reported UNCONDITIONALLY when the hook is wired —
	// an explicit 0 on a healthy node, so an alert on `> 0` can distinguish
	// "none admitted" from "the exporter stopped reporting this series". ABSENT
	// when unwired: a hardcoded 0 from a process that never consulted the
	// active config is a false all-clear.
	if c.srv.natLenientTerminalActionRulesFn != nil {
		ch <- prometheus.MustNewConstMetric(c.natRulesLenientTerminalAction,
			prometheus.GaugeValue, float64(len(c.srv.natLenientTerminalActionRulesFn())))
	}

	// #6807: quarantined route-maps. Reported UNCONDITIONALLY when the hook
	// is wired — a 0 must be published on a healthy box, or an alert on
	// `> 0` can never distinguish "no quarantine" from "the exporter stopped
	// reporting this series".
	if c.srv.frrQuarantinedRouteMapsFn != nil {
		ch <- prometheus.MustNewConstMetric(c.frrRouteMapsQuarantined,
			prometheus.GaugeValue, float64(len(c.srv.frrQuarantinedRouteMapsFn())))
	}

	// #4899: IPsec DHCP-lease-change rebind-pending is a control-plane
	// signal (the daemon re-renders swanctl even in config-only mode) —
	// emit it BEFORE the dataplane gate so a stale-local_addrs tunnel that
	// cannot re-establish stays visible even when the dataplane is not
	// loaded.
	if c.srv.ipsecRebindPendingFn != nil {
		v := 0.0
		if c.srv.ipsecRebindPendingFn() {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.ipsecRebindPending,
			prometheus.GaugeValue, v)
	}

	// #6802: host-inbound conntrack revocation is a control-plane signal (the
	// daemon rebuilds the kernel host-inbound table and reconciles conntrack
	// even in config-only mode) — emit it BEFORE the dataplane gate so a
	// now-denied host service that is still reachable over an established
	// kernel connection stays visible even when the dataplane is not loaded.
	if c.srv.hostInboundConntrackRevocationOwedFn != nil {
		v := 0.0
		if c.srv.hostInboundConntrackRevocationOwedFn() {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.hostInboundConntrackRevocationPending,
			prometheus.GaugeValue, v)
	}
	if c.srv.hostInboundConntrackFlushFailuresFn != nil {
		ch <- prometheus.MustNewConstMetric(c.hostInboundConntrackRevocationFailures,
			prometheus.CounterValue,
			float64(c.srv.hostInboundConntrackFlushFailuresFn()))
	}

	// #6800: managed-service reload debt. Emitted BEFORE the dataplane gate for
	// the same reason as the two series above — rsyslog forwarding and chrony
	// time sync are reconciled in config-only mode too, so a node whose
	// dataplane never loaded is exactly the node whose stale logging pipeline
	// most needs to be visible. Keys are sorted so the sample order is stable
	// across scrapes (Go map iteration is not).
	if c.srv.managedServiceReloadOwedFn != nil {
		owed := c.srv.managedServiceReloadOwedFn()
		for _, svc := range sortedKeys6800(owed) {
			v := 0.0
			if owed[svc] {
				v = 1
			}
			ch <- prometheus.MustNewConstMetric(c.managedServiceReloadPending,
				prometheus.GaugeValue, v, svc)
		}
	}
	if c.srv.managedServiceReloadFailuresFn != nil {
		failures := c.srv.managedServiceReloadFailuresFn()
		for _, svc := range sortedKeys6800(failures) {
			ch <- prometheus.MustNewConstMetric(c.managedServiceReloadFailures,
				prometheus.CounterValue, float64(failures[svc]), svc)
		}
	}

	// #7615: emitted BEFORE the dataplane gate for the same reason as their
	// siblings above — every one of these repairs runs in config-only mode too,
	// and a node whose dataplane never came up is exactly the node whose
	// unpaid retry debt most needs to be visible.
	for _, s := range []struct {
		fn   func() bool
		desc *prometheus.Desc
	}{
		{c.srv.raDeadSenderPendingFn, c.raDeadSenderPending},
		{c.srv.fabricOverlayMissingFn, c.fabricOverlayMissing},
		{c.srv.managementListenerDownFn, c.managementListenerDown},
	} {
		if s.fn == nil {
			continue
		}
		v := 0.0
		if s.fn() {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(s.desc, prometheus.GaugeValue, v)
	}

	// #3780: scheduler republish-failure is a control-plane signal (the
	// policy scheduler runs even in config-only mode) — emit it BEFORE
	// the dataplane gate so stale enforcement past a schedule window
	// stays visible even when the dataplane is not loaded.
	if c.srv.schedulerRepublishFailedFn != nil {
		v := 0.0
		if c.srv.schedulerRepublishFailedFn() {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.schedulerRepublishFailed,
			prometheus.GaugeValue, v)
	}
	if c.srv.schedulerRepublishStaleSecondsFn != nil {
		ch <- prometheus.MustNewConstMetric(c.schedulerRepublishStale,
			prometheus.GaugeValue, c.srv.schedulerRepublishStaleSecondsFn())
	}
	if c.srv.schedulerRepublishFailClosedFn != nil {
		v := 0.0
		if c.srv.schedulerRepublishFailClosedFn() {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.schedulerRepublishFailClosed,
			prometheus.GaugeValue, v)
	}

	// #2050: dynamic-address feed staleness is a control-plane signal (the
	// feed manager runs even in config-only mode) — emit it BEFORE the
	// dataplane gate so a frozen enforced address set stays visible when the
	// dataplane is not loaded.
	if c.srv.feedsFn != nil {
		now := time.Now()
		for name, info := range c.srv.feedsFn() {
			secs := -1.0
			if !info.LastSuccess.IsZero() {
				secs = now.Sub(info.LastSuccess).Seconds()
			}
			ch <- prometheus.MustNewConstMetric(c.feedSecondsSinceSuccess,
				prometheus.GaugeValue, secs, name)
			stale := 0.0
			if !info.StaleSince.IsZero() {
				stale = 1
			}
			ch <- prometheus.MustNewConstMetric(c.feedStale,
				prometheus.GaugeValue, stale, name)
		}
	}

	// #2464: per-collector flow-export write-health is a control-plane
	// signal — the exporters run independent of the dataplane — so emit it
	// BEFORE the dataplane gate. A collector that has gone unreachable must
	// stay visible even when the dataplane is not loaded.
	c.collectFlowExportMetrics(ch)

	// #3361: kernel nftables host-inbound DROP counters, per zone/family. The
	// `inet xpf_hostinbound` chain is installed by the daemon INDEPENDENT of
	// dataplane load state (applyConfig runs it even in a config-only / degraded
	// boot), and it actively DROPS host-bound control-plane traffic. So this is a
	// control-plane signal — emit it BEFORE the dataplane gate so the kernel-deny
	// series stays visible exactly in the degraded boot where the dataplane is
	// unloaded but the deny chain is still dropping (the blind spot this metric
	// exists to close). ReadHostInboundDenyCounters reads nft via netlink and has
	// no dataplane dependency.
	c.collectHostInboundKernelDenies(ch)

	// #4146: the fine `to-zone junos-host` DENY drop counters on the same kernel
	// `inet xpf_hostinbound` chain. Installed INDEPENDENT of dataplane load (they
	// enforce the direct host-bound path the kernel delivers), so — like the deny
	// counters above — emit BEFORE the dataplane gate so the series stays visible
	// in a config-only / degraded boot.
	c.collectHostInboundJunosHostDenies(ch)

	// #4759: the GLOBAL ICMP-error / ND ACCEPT counters on the same kernel
	// `inet xpf_hostinbound` chain. These control-message accepts are admitted
	// regardless of any per-zone host-inbound service set and are installed
	// INDEPENDENT of dataplane load, so — like the deny counters above — emit them
	// BEFORE the dataplane gate so the accept series stays visible in a
	// config-only / degraded boot. Aggregate (global rules, not per-zone).
	c.collectHostInboundICMPNDAccepts(ch)

	// #5806: zones whose configured screen profile does NOT resolve. The active
	// config claims a screen is attached while the dataplane enforces none of it
	// (tolerant load / HA config-sync / rolling upgrade can reach this state),
	// and until now the only DATAPLANE-RUNTIME signal was a rate-limited WARN —
	// the issue's acceptance criterion is explicitly that one warning must not be
	// the sole signal. (Other reporting exists: tolerant-load configuration
	// warnings and daemon logging. The precise claim is about the runtime WARN,
	// which #6860 shows cannot fire at all when NO profile resolves.)
	// Config-derived and independent of dataplane load, so emit it BEFORE
	// the dataplane gate: a config-only / degraded boot is exactly when an
	// unenforced security control must stay visible.
	c.collectScreenUnresolvedProfileZones(ch)
	c.collectScreenInertProfileZones(ch)

	// #3698: configured host-inbound-enforcing zones currently in the transient
	// fail-open admit window (a non-lifeline interface but no resolvable address
	// yet, so no kernel host-inbound deny is scoped to them). Config-derived and
	// independent of dataplane load, so emit it BEFORE the dataplane gate — the
	// window can be open in a config-only / degraded boot too, and that is exactly
	// when it must stay visible.
	//
	// KEEP THIS COMMENT ADJACENT TO ITS CALL (#6839 round 2): the #5806 call above
	// was inserted between this block and this line, so the #3698 rationale read
	// as the rationale for the #5806 emit and this call was left bare.
	c.collectHostInboundAddresslessZones(ch)

	// #3710: the per-interface/per-family refinement of the addressless-zone
	// signal above. A MIXED zone collapses to "scoped" at zone granularity the
	// moment ANY interface resolves ANY address, hiding a DHCP-pending unit beside
	// an addressed sibling, or the v6 side of a dual-stack edge whose v6 lease
	// lands after v4. Config-derived and independent of dataplane load, so emit it
	// BEFORE the dataplane gate like the zone-level signal.
	c.collectHostInboundAddresslessInterfaces(ch)

	// #3718 (Option B): firewall-local addresses reachable from multiple zones
	// with differing host-inbound service sets (order-dependent kernel verdict).
	// Config-derived and independent of dataplane load — and, unlike the
	// addressless window, NOT self-healing — so emit it BEFORE the dataplane gate
	// so it stays visible in a config-only / degraded boot too.
	c.collectHostInboundAmbiguousAddresses(ch)

	// #4422: kernel nftables lo0 loopback input-filter `then count` hits. The
	// `inet xpf_lo0` chain is installed by the daemon INDEPENDENT of dataplane
	// load state and keeps counting host-inbound loopback traffic in a
	// config-only / degraded boot, so emit it BEFORE the dataplane gate — the
	// counts are DISTINCT from the userspace fast-path xpf_filter_hits_total.
	c.collectLo0Counters(ch)

	// #4422: policy-based-routing (filter-based-forwarding) build health. Derived
	// from the active config (routing.PBRBuildStats, a pure function — no
	// netlink), so it is a control-plane signal emitted BEFORE the dataplane gate:
	// a degraded FBF mirror must stay visible in a config-only / degraded boot.
	c.collectPBRStatus(ch)

	// #6843 R1: per-zone traffic, emitted BEFORE the dataplane gate. The
	// xpf_zone_counters_unpopulated_zones gauge is documented as ALWAYS emitted
	// so `> 0` is alertable and its absence cannot be confused with a scrape
	// that failed to run — but below the gate that promise breaks exactly when
	// it matters most: on a degraded or config-only boot no sample is emitted at
	// all, so the alert silently stops evaluating precisely when per-zone volume
	// is most unavailable. The collector is config-derived (it counts every
	// configured zone as unpopulated when there is no apply result or no loaded
	// dataplane), so it degrades correctly above the gate, like collectPBRStatus
	// and the lo0/host-inbound families hoisted above for the same reason.
	// #3462 ordering, restated at the new position: a GENUINE per-zone read
	// failure bumps counterReadErrors, and the deferred emitCounterReadErrors at
	// the top of Collect runs at function exit — after this — so a failure this
	// scrape is reflected in THIS scrape's xpf_counter_read_errors_total rather
	// than lagging one behind. Moving the collector earlier preserves that: it
	// is still upstream of the deferred emit.
	c.collectZoneCounters(ch, c.srv.dp)

	dp := c.srv.dp
	if dp == nil || !dp.IsLoaded() {
		return
	}

	// #5317: fetch the userspace-dp helper status ONCE per scrape and share the
	// snapshot across collectFilterCounters (filter-term hit merge) and
	// collectUserspaceStatus (CoS / worker-runtime / fairness / neighbor / ...
	// families). Before this each of those collectors issued its own
	// control-socket Status() round trip, so a single scrape did two serialized
	// `status` RPCs — doubling contention with session installs during bulk sync
	// (CLAUDE.md "Control socket contention"). nil = no Status() surface or a
	// failed round trip; both collectors degrade exactly as they did on their
	// own failed/absent fetch.
	userspaceStatus := fetchUserspaceStatus(dp)

	c.collectGlobalCounters(ch, dp)
	c.collectInterfaceCounters(ch, dp)
	c.collectPolicyCounters(ch, dp)
	c.collectFilterCounters(ch, dp, userspaceStatus)
	// #3464: emit the per-interface scrape-error counter AFTER
	// collectInterfaceCounters has run, so a read failure this scrape is
	// reflected in THIS scrape's xpf_interface_counter_read_errors_total. Kept
	// separate from the security-counter total emitted just below.
	c.emitInterfaceCounterReadErrors(ch)
	// #5046: collect NAT pool metrics on the loaded path — a ReadNATPortCounter
	// failure bumps counterReadErrors. The deferred emitCounterReadErrors at the
	// top of Collect runs at function exit, AFTER this, so the bump is reflected
	// in THIS scrape's xpf_counter_read_errors_total rather than lagging a scrape
	// behind (the #3462 ordering the other counter collectors follow). #5045: the
	// scrape-error sample is no longer emitted from an explicit call here — the
	// deferred emit covers this normal-completion path AND the unloaded early
	// return above with exactly one emission per scrape.
	c.collectNATPoolMetrics(ch, dp)
	c.collectSessionGauges(ch, dp)
	c.collectDHCPMetrics(ch)
	c.collectDDNSMetrics(ch)
	c.collectSurfaceADDNSMetrics(ch)
	c.collectSystemMetrics(ch)
	c.collectUserspaceStatus(ch, userspaceStatus)
	// #6845: a top-level status-derived signal, emitted only when a status was
	// actually read — see emitZoneCounterOverflow for why its absence and its 0
	// mean different things.
	c.emitZoneCounterOverflow(ch, userspaceStatus)
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

func policyCounterID(policySetID uint32, ruleIndex int) uint32 {
	return policySetID*dataplane.MaxRulesPerPolicy + uint32(ruleIndex)
}

// sortedKeys6800 returns a map's keys in a stable order. Prometheus does not
// require a sample order, but an unstable one makes a golden scrape diff noise
// and makes a test that reads "the first sample" quietly nondeterministic.
func sortedKeys6800[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
