package api

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/logging"
)

// #1726: whole-collector Prometheus descriptor-coverage canary.
//
// xpfCollector is a CHECKED collector: every *prometheus.Desc emitted by
// Collect() MUST be declared in Describe(), or a scrape through a checked
// path errors (the #1635 bug — cold-path histogram descs were emitted but
// not declared, and the cluster smoke masked it). The existing
// TestColdPathDescriptorsAreDescribed guards ONLY the cold-path family by
// driving emitWorkerColdPath directly. This canary generalizes the guard
// to the ENTIRE collector by running the REAL Collect() through a
// prometheus.NewPedanticRegistry() and asserting Gather() returns no
// error.
//
// Why PEDANTIC: a plain prometheus.NewRegistry() does NOT validate that
// every collected metric's descriptor was declared by Describe()
// (client_golang only populates registeredDescIDs / runs the
// "unregistered descriptor" check under NewPedanticRegistry()). Production
// (server.go) uses a plain registry, so the desc-coverage error never
// surfaces via Gather there; #1635 surfaced through promhttp's
// checked-collector logging instead. The pedantic registry is the correct
// TEST instrument for asserting the Describe()⊇Collect() contract.

// descriptorCoverageDP is a fake apiRuntimeDataPlane that also implements
// the optional Status() surface used by collectUserspaceStatus. It embeds
// *dataplane.Manager for the methods we don't care about, and overrides
// the read paths that dataplane.New() answers with a map-missing ERROR
// (the per-family collectors `continue` on error, so without these
// overrides the zone/policy/filter/NAT descriptor families would never be
// exercised — they'd silently fall out of coverage).
type descriptorCoverageDP struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
	apply  *dataplane.ApplyResult
}

func (d *descriptorCoverageDP) IsLoaded() bool { return true }

// #3929: collectSessionGauges now derives xpf_sessions_active/established/
// breakdown from the session table iteration, omitting them on iterator error
// (the #2469 fail-loud contract). dataplane.New() answers IterateSessions with
// a map-missing error, which would drop the session-gauge family out of
// coverage — override both iterators to succeed (enumerate nothing) so the
// xpf_sessions_active sentinel stays exercised.
func (d *descriptorCoverageDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return nil
}

func (d *descriptorCoverageDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (d *descriptorCoverageDP) Status() (dpuserspace.ProcessStatus, error) {
	return d.status, nil
}

func (d *descriptorCoverageDP) LastApplyResult() *dataplane.ApplyResult {
	return d.apply
}

// #3345: collectGlobalCounters now SKIPS emitting a counter sample when the
// read fails (so a degraded bridge is not reported as a clean 0). dataplane.New()
// answers ReadGlobalCounter with a map-missing error, which would drop the
// global-counter descriptor families out of coverage — override it to succeed.
func (d *descriptorCoverageDP) ReadGlobalCounter(uint32) (uint64, error) {
	return 0, nil
}

func (d *descriptorCoverageDP) ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error) {
	return dataplane.InterfaceCounterValue{}, nil
}

func (d *descriptorCoverageDP) ReadZoneCounters(uint16, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (d *descriptorCoverageDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (d *descriptorCoverageDP) ReadFilterConfig(uint32) (dataplane.FilterConfig, error) {
	return dataplane.FilterConfig{RuleStart: 0}, nil
}

func (d *descriptorCoverageDP) ReadFilterCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (d *descriptorCoverageDP) ReadNATPortCounter(uint32) (uint64, error) {
	return 0, nil
}

// newDescriptorCoverageStore builds a real active config with interfaces,
// zones, zone-pair + global policies (with count), inet + inet6 firewall
// filters, and a source NAT pool — so every config-driven collect path
// (zone/policy/filter/NAT-pool) produces metrics.
func newDescriptorCoverageStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(strings.Join([]string{
		// Zones (zone IDs assigned by the compiler; the fake DP's
		// LastApplyResult supplies the ZoneIDs the collector reads).
		// Bind interface "lo" to the trust zone so
		// collectInterfaceCounters resolves ResolveKernelIfName("lo")=="lo"
		// and net.InterfaceByName("lo") succeeds (loopback always exists),
		// driving the xpf_interface_* descriptor family.
		"set interfaces lo unit 0 family inet",
		"set security zones security-zone trust interfaces lo.0",
		"set security zones security-zone untrust",
		// Enable policy-stats so collectPolicyCounters emits per-policy hit
		// counters (gated on this knob since #2008 M4).
		"set security policy-stats system-wide enable",
		// Zone-pair policy with count, plus a global policy with count.
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application any",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		"set security policies from-zone trust to-zone untrust policy allow then count",
		"set security policies global policy g1 match source-address any",
		"set security policies global policy g1 match destination-address any",
		"set security policies global policy g1 match application any",
		"set security policies global policy g1 then permit",
		"set security policies global policy g1 then count",
		// inet + inet6 firewall filters (one term each).
		"set firewall family inet filter fin term t1 from protocol tcp",
		"set firewall family inet filter fin term t1 then accept",
		"set firewall family inet6 filter fin6 term t1 from next-header tcp",
		"set firewall family inet6 filter fin6 term t1 then accept",
		// Source NAT pool with addresses so SourcePools is populated.
		"set security nat source pool p1 address 203.0.113.0/24",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r1 then source-nat pool p1",
	}, "\n")); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// populatedCoverageStatus returns a ProcessStatus that drives EVERY emit*
// path under collectUserspaceStatus to produce at least one metric, so the
// userspace descriptor families (CoS owner-profile, drain-phase,
// waterfill, equal-flow, worker runtime, cold-path v1/v3/scalars/unknown,
// event stream, binding active-flow + TX completion, CoS active-flow,
// three-color policer, source-NAT pool, fairness RSS, neighbor-warm) are
// all covered.
func populatedCoverageStatus() dpuserspace.ProcessStatus {
	ownerID := uint32(0)

	// One CoS interface with one exact, owner-attributed queue that has
	// equal-flow enforcement on and populated drain/waterfill histograms.
	drainHist := make([]uint64, 16)
	drainHist[2] = 5
	redirectHist := make([]uint64, 16)
	redirectHist[1] = 3
	cosIface := dpuserspace.CoSInterfaceStatus{
		Ifindex:                     80,
		InterfaceName:               "ge-0-0-2",
		WaterfillEpochs:             4,
		WaterfillPhase1BudgetBreaks: 1,
		WaterfillMinEpochsPerWorker: 2, // not MaxUint64 → gauge emits
		Queues: []dpuserspace.CoSQueueStatus{
			{
				QueueID:                 4,
				OwnerWorkerID:           &ownerID,
				Exact:                   true,
				DrainLatencyHist:        drainHist,
				DrainInvocations:        9,
				RedirectAcquireHist:     redirectHist,
				OwnerPPS:                100,
				PeerPPS:                 50,
				DrainGuaranteeSentBytes: 1000,
				DrainSurplusSentBytes:   200,
				DrainNonExactSentBytesWhileExactBacklogged: 10,
				WaterfillPhase1Admissions:                  3,
				WaterfillPhase2Admissions:                  2,
				WaterfillEligibleVisits:                    7,
				EqualFlowEnforcement:                       true,
				EqualFlowEnforced:                          true,
				EqualFlowTargetPerFlowBPS:                  3200,
				EqualFlowMaxWorkerCapBytes:                 9600,
				EqualFlowCapHitEvents:                      1,
				EqualFlowSuppressedGrantBytes:              64,
				EqualFlowStaleOrTagMismatchEvents:          0,
				EqualFlowFailOpenReason:                    "",
				// #1829 Phase 1: dequeue-time sojourn gauges.
				SojournEwmaNS:        2500000,
				SojournPeakNS:        9000000,
				SojournWindowedMinNS: 1750000,
				// #1830 (g): bucket-vs-flow occupancy gauges.
				FlowFairBucketsOccupied: 6,
				FlowFairFlowsActive:     8,
			},
		},
	}

	// Cold-path: one v3 worker (sparse populated + overflow), one
	// unknown-version worker, one v1 dense worker — mirrors the existing
	// cold-path test fixture so all cold-path desc families emit.
	v3Buckets := make([]uint64, 48)
	v3Buckets[6] = 3
	v1Hist := make([][]uint64, 16)
	for i := range v1Hist {
		v1Hist[i] = make([]uint64, 24)
	}
	v1Hist[3][5] = 1
	v1Samples := make([]uint64, 16)
	v1Samples[3] = 1
	v1SumNS := make([]uint64, 16)
	v1SumNS[3] = 100
	v1Alias := make([]bool, 16)
	v1Alias[3] = true

	capped9654 := true
	return dpuserspace.ProcessStatus{
		// #9654: a known flag, so the conditional gauge is emitted and covered.
		LearnedRouteImportCapped: &capped9654,
		SessionTableEntries:      12,
		MaxSessions:              1000,
		FlowCacheCapacity:        4096,
		CoSInterfaces:            []dpuserspace.CoSInterfaceStatus{cosIface},
		// #1865: one populated WG tunnel row so emitWireguardTelemetry's
		// whole descriptor family is exercised by the canary (the
		// zone/policy lesson at the top of this file: families that
		// need fixture data silently fall out of coverage without it).
		// LastHandshakeUnixSecs is nonzero so the gated gauge emits.
		WgTunnels: []dpuserspace.WgTunnelStatus{
			{
				Tunnel:           "wg0",
				TunnelEndpointID: 9,
				ListenPort:       51820,
				Peers: []dpuserspace.WgPeerStatus{{
					PeerPubkeyHex:    "ab",
					SessionConfirmed: true,
				}},
				LastHandshakeUnixSecs: 1_770_000_000,
				HsInitiationsCreated:  3,
				DecapPackets:          5,
				EncapPackets:          6,
				EncapMtuDrops:         1,
				HsSendErrors:          2,
			},
		},
		WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
			{
				WorkerID: 0,
				WallNS:   1e9,
				ActiveNS: 5e8,
				// #1782 Step-1 cold-start CoS instruments: drive both
				// wheel counters and one under-grant cause so the new
				// families emit through the pedantic-Gather canary.
				CoSWheelTicksAdvancedTotal:            12_000_000,
				CoSWheelTicksAdvancedMax:              11_000_000,
				CoSQueueLeaseUndergrantShareExhausted: 4,
				ColdPathLayoutVersion:                 3,
				ColdPathActiveSlotIDs:                 []uint32{0},
				ColdPathActiveZoneFrom:                []uint32{1},
				ColdPathActiveZoneTo:                  []uint32{2},
				ColdPathActiveSamples:                 []uint64{3},
				ColdPathActiveSumNS:                   []uint64{300},
				ColdPathActiveBuckets:                 [][]uint64{v3Buckets},
				ColdPathActiveBuilderCollision:        []bool{false},
				ColdPathOverflowActive:                true,
				ColdPathClockSource:                   "tsc",
			},
			{WorkerID: 1, ColdPathLayoutVersion: 99}, // unknown-version path
			{
				WorkerID:              2,
				ColdPathLayoutVersion: 1,
				ColdPathHist:          v1Hist,
				ColdPathSamples:       v1Samples,
				ColdPathSumNS:         v1SumNS,
				ColdPathAliasSeen:     v1Alias,
			},
		},
		Bindings: []dpuserspace.BindingStatus{
			{
				Slot:                         0,
				QueueID:                      4,
				WorkerID:                     0,
				Interface:                    "ge-0-0-2",
				ActiveFlowCount:              7,
				FlowCacheCapacity:            4096,
				TXCompletions:                123,
				TXCompletionRingAvailable:    10,
				TXCompletionRingAvailableMax: 20,
				// #1831: per-binding V_min throttle counters (always emit).
				VMinThrottles:                51,
				VMinThrottleHardCapOverrides: 2,
			},
		},
		CoSActiveFlowCounts: []dpuserspace.CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 7},
		},
		ThreeColorPolicerCounters: []dpuserspace.ThreeColorPolicerStatus{
			{
				Name:         "tcm1",
				GreenPackets: 10, GreenBytes: 1000,
				YellowPackets: 2, YellowBytes: 200,
				RedPackets: 1, RedBytes: 100,
				DropPackets: 1, DropBytes: 100,
			},
		},
		SourceNATPools: []dpuserspace.SourceNATPoolStatus{
			{
				PoolName: "p1", RuleName: "r1",
				LiveFlows: 5, UsedPorts: 50, PersistentLeases: 0,
				AllocationsTotal: 100, ReusesTotal: 10, ExhaustionTotal: 0,
			},
		},
		EventStream: &dpuserspace.EventStreamStatus{
			FramesRead: 11, FramesWritten: 7, DecodeErrors: 2, SeqGaps: 1,
			PolicyDenyEvents: 5, ScreenDropEvents: 6, FilterLogEvents: 8,
			PolicyDenyDrops: 1, ScreenDropDrops: 4, FilterLogDrops: 9,
			UnknownFrameDrops: 3,
		},
		EventStreamSent:    101,
		EventStreamDropped: 7,
		// #2382: replay-buffer eviction telemetry-loss counter — surfaced under
		// the producer-frames metric with the "replay_evicted" label.
		EventStreamReplayEvictions:    3,
		NeighborWarmDropsTotal:        2,
		NeighborWarmDisconnectedTotal: 0,
		// #1782 cold-start capture instrumentation: drive all three new
		// families (two counters always emit; the presence gauge emits
		// one series per dynamic_neighbors key).
		NegNeighFastFailTotal:           3,
		PendingNeighDuplicateDropsTotal: 4,
		// #1902: decap-refusal gate counter (always emits).
		PendingNeighDecapDropsTotal: 2,
		// #2375: distinct-hop capacity-drop counter (always emits).
		PendingNeighCapacityDropsTotal: 5,
		DynamicNeighborKeys:            []string{"7 10.0.61.1", "9 172.16.80.200"},
		// #1789: failed USERSPACE_SESSIONS publish counter (always emits).
		SessionPublishErrorsTotal: 5,
		// #2244: failed dnat_table reverse-NAT publish counter (always
		// emits).
		DnatPublishErrorsTotal: 6,
		// #1760 W3': shared-map reverse-key displacement counter (always
		// emits).
		NatReverseKeySharedDisplacementsTotal: 2,
		// #1807: worker-command-queue poison recoveries (always emits).
		WorkerCommandQueuePoisonRecoveries: 1,
		// #6929: per-worker command-queue capacity drops (always emits).
		WorkerCommandQueueDrops:           1,
		NeighborResolverQueueDepth:        3,
		NeighborResolverEnqueueDropsTotal: 1,
		NeighborResolverGetAttemptsTotal:  5,
		NeighborResolverGetResolvedTotal:  4,
		NeighborResolverProbeOnStaleTotal: 2,
		NeighborResolverGetFailuresTotal:  1,
		NeighborResolverEpochRejectsTotal: 0,
		NeighborResolverDisconnectedTotal: 0,
		// #1771 §2.6: resolver backoff + §2.5 ENOBUFS/re-dump counters
		// and the pending/negative key gauges (all always emit).
		NeighborResolverGetBackoffAttemptsTotal: 2,
		NeighborNetlinkEnobufsTotal:             1,
		NeighborNetlinkRedumpsTotal:             1,
		NeighborNetlinkRedumpUpsertsTotal:       6,
		NeighborPendingKeys:                     2,
		NegNeighKeys:                            1,
	}
}

func gatheredNames(mfs []*dto.MetricFamily) map[string]bool {
	out := make(map[string]bool, len(mfs))
	for _, mf := range mfs {
		out[mf.GetName()] = true
	}
	return out
}

// TestCollectorDescriptorCoverage is the #1726 whole-collector canary. It
// builds the REAL collector with a fully-wired fake runtime, registers it
// in a PEDANTIC registry, and asserts Gather() returns no error — the
// exact condition that fires when Collect() emits a metric whose
// descriptor is not declared in Describe() (the #1635 class). It also
// asserts representative families from every collect path are present, so
// silently dropping a whole family fails the canary too.
func TestCollectorDescriptorCoverage(t *testing.T) {
	store := newDescriptorCoverageStore(t)
	gc := conntrack.NewGC(nil, time.Minute)

	srv := &Server{
		store:     store,
		gc:        gc,
		startTime: time.Now(),
		// #1780: wire a non-nil neighbor-phase age source so the
		// neighbor_periodic_last_success_age_seconds family emits and the
		// canary covers its descriptor declaration.
		neighborPhaseAgeFn: func() map[string]float64 {
			return map[string]float64{
				"resolve":      1.0,
				"force_probe":  2.0,
				"clean_failed": 3.0,
				"warm":         4.0,
			}
		},
		// #1880: wire a non-nil FRR reload-degraded source so the
		// xpf_frr_reload_degraded gauge emits and the canary covers its
		// descriptor declaration.
		frrReloadDegradedFn: func() bool { return true },
		// #4899: wire a non-nil IPsec rebind-pending source so the
		// xpf_ipsec_rebind_pending gauge emits and the canary covers its
		// descriptor declaration.
		ipsecRebindPendingFn: func() bool { return true },
		// #9165: wire a non-nil syslog drop source so the
		// xpf_syslog_messages_dropped_total family emits and the canary
		// covers its descriptor declaration.
		syslogDropsFn: func() []logging.SyslogDropStat {
			return []logging.SyslogDropStat{
				{RemoteAddr: "10.0.0.9:514", Protocol: "udp", Writes: 2},
			}
		},
		// #1827: wire a non-nil ip-monitoring status source so the
		// xpf_ipmon_* family emits and the canary covers its
		// descriptor declarations.
		ipmonStatusFn: func() []ipmon.PolicyStatus {
			return []ipmon.PolicyStatus{{
				Name:        "wan-failover",
				Probe:       "WAN",
				Failed:      true,
				Transitions: 3,
				Routes: []config.RouteOverlayEntry{
					{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"},
				},
				// #3761 H8: an applied route so xpf_ipmon_routes_applied
				// emits a non-zero value distinct from routes_desired.
				AppliedRoutes: []config.RouteOverlayEntry{
					{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"},
				},
				// #1844: a skipped interface-typed route, so the
				// unresolved-next-hops gauge emits a non-zero value.
				UnresolvedRoutes: []ipmon.UnresolvedRoute{
					{Destination: "10.0.0.0/8", NextHopInterface: "ge-0-0-3.0", Reason: "no DHCP gateway"},
				},
			}}
		},
		// #1387 inc-2: wire a non-nil DDNS stats source so the
		// xpf_dhcp_ddns_* family emits and the canary covers its
		// descriptor declarations.
		ddnsStatsFn: func() *dhcpserver.DDNSStats {
			return &dhcpserver.DDNSStats{
				Enabled:           true,
				Backend:           "rfc2136",
				UpsertOK:          5,
				DeleteOK:          1,
				ReconcileOK:       3,
				SkippedPTRNotAuth: 1,
				OwnedRecords:      4,
				LastReconcile:     time.Now(),
				LastReconcileN:    4,
			}
		},
	}
	// dhcp.New opens a netlink handle, which a restricted sandbox may
	// refuse ("operation not permitted"). The DHCP family is one of many;
	// don't fail the whole descriptor canary on environment privilege.
	// When the manager is available we wire it (Leases() is empty) and
	// assert its sentinel; otherwise we skip just that family.
	dhcpWired := false
	if dhcpMgr, err := dhcp.New(t.TempDir(), nil, nil); err == nil {
		defer dhcpMgr.Close()
		srv.dhcp = dhcpMgr
		dhcpWired = true
	} else {
		t.Logf("dhcp.New unavailable in this environment (%v); skipping the "+
			"DHCP descriptor family only", err)
	}
	srv.dp = &descriptorCoverageDP{
		Manager: dataplane.New(),
		status:  populatedCoverageStatus(),
		apply: &dataplane.ApplyResult{
			ZoneIDs:   map[string]uint16{"trust": 1, "untrust": 2},
			FilterIDs: map[string]uint32{"inet:fin": 0, "inet6:fin6": 100},
			PoolIDs:   map[string]uint8{"p1": 0},
		},
	}

	// collectInterfaceCounters only emits when net.InterfaceByName succeeds
	// for the resolved kernel name. The config binds "lo" (resolves to the
	// loopback), which exists on any normal host — but a restricted sandbox
	// may deny the netlink lookup. Probe once and only assert the interface
	// sentinel where loopback is actually resolvable, so the family is
	// covered wherever the environment permits without a false failure on
	// netlink-denied runners (same posture as the optional DHCP family).
	_, loErr := net.InterfaceByName("lo")
	ifaceResolvable := loErr == nil
	if !ifaceResolvable {
		t.Logf("net.InterfaceByName(\"lo\") unavailable in this environment "+
			"(%v); skipping the interface descriptor family only", loErr)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(srv))

	mfs, err := reg.Gather()
	if err != nil {
		// The #1635 class manifests as "... with unregistered descriptor ...".
		t.Fatalf("pedantic Gather() returned an error — most likely a metric "+
			"was emitted by Collect() whose descriptor is not declared in "+
			"Describe() (the #1635 class). Add the missing ch <- c.<desc> "+
			"line to Describe(). Error: %v", err)
	}
	if len(mfs) == 0 {
		t.Fatal("collector emitted no metric families — fixture/dp not wired " +
			"(canary would be vacuous)")
	}

	// Positive sentinels: one representative family per collect path, so a
	// future change that drops an entire family (rather than mis-declaring
	// a single desc) also fails this canary.
	names := gatheredNames(mfs)
	want := []string{
		"xpf_packets_total",                                                // collectGlobalCounters
		"xpf_zone_packets_total",                                           // collectZoneCounters (#3651)
		"xpf_zone_bytes_total",                                             // collectZoneCounters (#3651)
		"xpf_zone_counters_unpopulated_zones",                              // collectZoneCounters (#3651)
		"xpf_policy_hits_total",                                            // collectPolicyCounters
		"xpf_filter_hits_total",                                            // collectFilterCounters
		"xpf_nat_pool_total_ports",                                         // collectNATPoolMetrics
		"xpf_sessions_active",                                              // collectSessionGauges
		"xpf_daemon_uptime_seconds",                                        // collectSystemMetrics
		"xpf_daemon_neighbor_periodic_last_success_age_seconds",            // #1780 neighbor watchdog
		"xpf_ipmon_policy_failed",                                          // #1827 ip-monitoring
		"xpf_frr_reload_degraded",                                          // #1880 FRR degraded reload
		"xpf_ipsec_rebind_pending",                                         // #4899 IPsec lease-change rebind health
		"xpf_pbr_rules_installed",                                          // #4422 PBR/FBF build health
		"xpf_pbr_degraded_terms",                                           // #4422 PBR/FBF degraded terms
		"xpf_userspace_worker_dead",                                        // emitWorkerRuntime
		"xpf_learned_route_import_capped",                                  // #9654 capped-now gauge (emitted only when known)
		"xpf_userspace_worker_cold_path_samples_v3_total",                  // cold-path v3
		"xpf_cos_drain_invocations_total",                                  // CoS owner profile
		"xpf_userspace_three_color_policer_drops_total",                    // three-color policer
		"xpf_userspace_source_nat_pool_live_flows",                         // userspace SNAT pool
		"xpf_userspace_neighbor_warm_drops_total",                          // neighbor-warm
		"xpf_userspace_neg_neigh_fast_fail_total",                          // #1782 cold-start H1
		"xpf_userspace_worker_cos_wheel_ticks_advanced_total",              // #1782 Step-1 (i) wheel sum
		"xpf_userspace_worker_cos_wheel_ticks_advanced_max",                // #1782 Step-1 (i) wheel max
		"xpf_userspace_worker_cos_queue_lease_undergrant_total",            // #1782 Step-1 (ii) per-cause
		"xpf_userspace_pending_neigh_duplicate_drops_total",                // #1782 cold-start H5
		"xpf_userspace_pending_neigh_decap_drops_total",                    // #1902 decap-refusal gate
		"xpf_userspace_pending_neigh_capacity_drops_total",                 // #2375 distinct-hop exhaustion
		"xpf_userspace_dynamic_neighbor_learn_cap_drops_total",             // #5673 neighbor-map cap (pre-policy flood bound)
		"xpf_userspace_dynamic_neighbor_present",                           // #1782 cold-start H2 dump
		"xpf_userspace_session_publish_errors_total",                       // #1789 publish failures
		"xpf_userspace_dnat_publish_errors_total",                          // #2244 dnat_table reverse-NAT publish failures
		"xpf_userspace_session_nat_reverse_key_shared_displacements_total", // #1760 W3' shared displacements
		"xpf_userspace_worker_command_queue_poison_recoveries_total",       // #1807 poison recoveries
		"xpf_userspace_worker_command_queue_drops_total",                   // #6929 per-worker command-queue capacity drops
		"xpf_userspace_shared_session_poison_recoveries_total",             // #2402/#6641 shared-session poison recoveries
		"xpf_userspace_gre_decap_ecn_illegal_drops_total",                  // #2315 RFC 6040 4.2 decap illegal-combo drops
		"xpf_userspace_wg_decap_ecn_illegal_drops_total",                   // #2317 WG RFC 6040 4.2 decap illegal-combo drops
		"xpf_userspace_gre_encap_df_oversize_drops_total",                  // #2331 GRE encap DF-set oversized-outer drops
		"xpf_userspace_gre_decap_checksum_invalid_drops_total",             // #2782 GRE decap checksum-present invalid drops
		"xpf_userspace_gre_decap_unsupported_version_refusals_total",       // #6842 GRE decap refused: non-zero GRE version (PPTP) at a configured endpoint
		// #1771 §2.6 resolver backoff + §2.5 ENOBUFS/re-dump + key gauges
		"xpf_userspace_neighbor_resolver_get_backoff_attempts_total",
		"xpf_userspace_neighbor_netlink_enobufs_total",
		"xpf_userspace_neighbor_netlink_redumps_total",
		"xpf_userspace_neighbor_netlink_redump_upserts_total",
		"xpf_userspace_neighbor_pending_keys",
		"xpf_userspace_neg_neigh_keys",
		// #1865 WireGuard telemetry family (emitWireguardTelemetry)
		"xpf_userspace_wg_handshakes_completed_total",
		"xpf_userspace_wg_handshake_rx_drops_total",
		"xpf_userspace_wg_transport_packets_total",
		"xpf_userspace_wg_transport_drops_total",
		"xpf_userspace_wg_send_errors_total",
		"xpf_userspace_wg_session_confirmed",
		"xpf_userspace_wg_last_handshake_time_seconds",
		// #1830 (g): bucket-vs-flow occupancy gauges
		"xpf_userspace_cos_flow_fair_buckets_occupied",
		"xpf_userspace_cos_flow_fair_flows_active",
		// #1831: per-binding V_min fairness-throttle counters (#941/#943)
		"xpf_userspace_binding_v_min_throttles_total",
		"xpf_userspace_binding_v_min_throttle_hard_cap_overrides_total",
		// #1829 Phase 1: dequeue-time sojourn gauges
		"xpf_userspace_cos_sojourn_ewma_ns",
		"xpf_userspace_cos_sojourn_peak_ns",
		"xpf_userspace_cos_sojourn_windowed_min_ns",
		// #9165: remote-syslog drop counters. The three SyslogClient drop
		// accessors had zero production readers before this family existed,
		// so the canary is what keeps the reader from being deleted back to
		// nothing without a test going red.
		"xpf_syslog_messages_dropped_total",
	}
	if ifaceResolvable {
		want = append(want, "xpf_interface_packets_total") // collectInterfaceCounters (lo)
	}
	if dhcpWired {
		want = append(want, "xpf_dhcp_leases_active") // collectDHCPMetrics
	}
	for _, name := range want {
		if !names[name] {
			t.Errorf("expected metric family %q in gathered output but it was "+
				"absent — its collect path did not emit (coverage gap)", name)
		}
	}
}

// TestFairnessThroughputDescriptorCoverage closes the coverage gap the
// single-Gather canary cannot reach deterministically: the
// fairness-throughput + equal-flow estimator descriptors emit only when
// the rolling FairnessThroughputWindow has a prior sample and a positive
// duration between updates (and FlowWorkerMap rows). Rather than depend on
// the window timing inside one Collect(), this test captures the
// Describe() descriptor set and drives the fairness emitters directly over
// two timed updates, asserting every emitted descriptor is declared — the
// same checked-collector contract, applied to the timing-gated families.
func TestFairnessThroughputDescriptorCoverage(t *testing.T) {
	store := newDescriptorCoverageStore(t)
	c := newCollector(&Server{store: store})

	declared := describedSet(c)

	queueID := uint8(4)
	fwk := dpuserspace.FlowTupleStatus{
		AddrFamily: 4, Protocol: 6,
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 80,
	}
	mkStatus := func(bytes uint64) dpuserspace.ProcessStatus {
		return dpuserspace.ProcessStatus{
			Workers: 2,
			CoSActiveFlowCounts: []dpuserspace.CoSActiveFlowCountStatus{
				{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 1},
			},
			FlowWorkerMap: []dpuserspace.FlowWorkerStatus{
				{
					EgressIfindex:  80,
					CoSQueueID:     &queueID,
					WorkerID:       0,
					ForwardWireKey: fwk,
					ObservedBytes:  bytes,
				},
			},
		}
	}

	// Two updates with a real positive duration so the window produces a
	// throughput summary (and, with a per-flow delta, the equal-flow
	// estimator). Drive emitFairnessThroughputGauges directly; it persists
	// the window on c across calls.
	collect := func(status dpuserspace.ProcessStatus) []prometheus.Metric {
		ch := make(chan prometheus.Metric)
		go func() {
			c.emitFairnessThroughputGauges(ch, status)
			close(ch)
		}()
		var got []prometheus.Metric
		for m := range ch {
			got = append(got, m)
		}
		return got
	}
	_ = collect(mkStatus(1_000_000)) // seed sample
	time.Sleep(2 * time.Millisecond) // positive window duration
	got := collect(mkStatus(9_000_000))

	// Also drive the equal-flow estimator emitter directly with a valid
	// estimate so its descriptor family is exercised regardless of window
	// state (mirrors TestEmitFairnessEqualFlowEstimateGauges shape).
	estRow := dpuserspace.FairnessThroughputSummary{
		EqualFlowEstimate: dpuserspace.FairnessEqualFlowEstimate{
			Valid:                true,
			TargetPerFlowBPS:     3200,
			ObservedBPS:          16000,
			CappedBPS:            12800,
			SuppressedBPS:        3200,
			ThroughputLossRatio:  0.2,
			ActiveWorkers:        2,
			SampledActiveWorkers: 2,
			Workers: []dpuserspace.FairnessEqualFlowWorkerEstimate{
				{WorkerID: 0, ObservedBPS: 9600, ObservedPerFlow: 3200, CapBPS: 9600},
				{WorkerID: 1, ObservedBPS: 6400, ObservedPerFlow: 6400, CapBPS: 3200, SuppressedBPS: 3200},
			},
		},
	}
	estCh := make(chan prometheus.Metric)
	go func() {
		c.emitFairnessEqualFlowEstimateGauges(estCh, estRow, "80", "4")
		close(estCh)
	}()
	for m := range estCh {
		got = append(got, m)
	}

	if len(got) == 0 {
		t.Fatal("fairness emitters produced no metrics — window/fixture not wired")
	}
	var undeclared []string
	sawThroughput, sawEqualFlow := false, false
	for _, m := range got {
		d := m.Desc()
		if _, ok := declared[d]; !ok {
			undeclared = append(undeclared, descName(d))
		}
		switch descName(d) {
		case "xpf_fairness_observed_cov":
			sawThroughput = true
		case "xpf_fairness_equal_flow_observed_bps":
			sawEqualFlow = true
		}
	}
	if len(undeclared) > 0 {
		t.Fatalf("fairness emitters produced %d descriptor(s) not declared in "+
			"Describe() (checked-collector contract violation — add them to "+
			"Describe()): %v", len(undeclared), undeclared)
	}
	if !sawThroughput {
		t.Error("fairness throughput summary did not emit xpf_fairness_observed_cov " +
			"— window timing fixture is not driving summaries")
	}
	if !sawEqualFlow {
		t.Error("equal-flow estimator did not emit xpf_fairness_equal_flow_observed_bps")
	}
}

// describedSet captures the full Describe() descriptor set of a collector.
func describedSet(c *xpfCollector) map[*prometheus.Desc]struct{} {
	// Buffer must hold the FULL Describe() set (sent synchronously before the
	// drain); size comfortably above the descriptor count so adding a
	// descriptor does not silently deadlock this capture.
	ch := make(chan *prometheus.Desc, 512)
	c.Describe(ch)
	close(ch)
	out := map[*prometheus.Desc]struct{}{}
	for d := range ch {
		out[d] = struct{}{}
	}
	return out
}
