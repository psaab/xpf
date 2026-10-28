package api

import (
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/eventengine"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/flowexport"
	"github.com/psaab/xpf/pkg/fwdstatus"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/sysservices"
)

// collectorDeps is the narrow seam (#16157) between xpfCollector and the
// rest of the API server. Previously the collector held a whole *Server, so
// every scrape helper reached through c.srv for exactly the state below and
// a unit test had to fabricate (or fabricate-and-mutate) a Server to drive
// one metric family. The collector now depends only on what it reads:
//
//   - live objects it snapshots per scrape (store, dp, fwdSampler,
//     dhcp, eventBuf) plus the server start time for uptime, and
//   - the optional daemon callback hooks, copied verbatim from the Server
//     fields of the same name (nil = family omitted, identical contract).
//
// collectorDepsFromServer snapshots the fields ONCE, at collector
// construction in NewServer — before the server serves, so no field read
// here races a later write. That snapshot discipline is itself part of the
// seam: Server.dp and friends are plain fields mutated by tests on
// not-yet-serving servers but never swapped on a live one, and the old
// c.srv reads inherited exactly the same lifetime. Copying the pointers
// (not the pointees) preserves the old visibility: a scrape sees live
// config through store.ActiveConfig, live gate counts through the
// connGate snapshot, and live sampler state through fwdSampler.
//
// The two restConn* closures capture the Server so the #16081 counts keep
// reading the atomically-loaded connGate (installed after the Server
// literal in NewServer); a bare Server yields the same 0 the nil-gate
// accessors returned before.
type collectorDeps struct {
	store      *configstore.Store
	dp         apiRuntimeDataPlane
	fwdSampler *fwdstatus.Sampler
	eventBuf   *logging.EventBuffer
	dhcp       *dhcp.Manager
	startTime  time.Time

	restConnRefusals func() uint64
	restConnActive   func() int64
	fabricConnStats  func() (uint64, int64)

	configPersistDegradedFn              func() bool
	rollbackHistoryDegradedFn            func() bool
	archiveDegradedFn                    func() bool
	archiveFailureCountFn                func() uint64
	earlyInputGuardSwapFailedFn          func() bool
	journalPermsDegradedFn               func() bool
	journalLegacyScrubDegradedFn         func() bool
	frrReloadDegradedFn                  func() bool
	natLenientTerminalActionRulesFn      func() []string
	frrQuarantinedRouteMapsFn            func() []string
	frrNarrowedPolicyChainsFn            func() []string
	frrNarrowedPolicyChainsDenySafeFn    func() []string
	frrNarrowedPolicyChainShapesFn       func() map[string]int
	ipsecRebindPendingFn                 func() bool
	ipsecCaptureWitnessFn                func() IpsecCaptureWitness
	interfaceLinkSnapshotPendingFn       func() bool
	hostInboundConntrackRevocationOwedFn func() bool
	hostInboundConntrackFlushFailuresFn  func() uint64
	hostInboundTCPlooseDisabledFn        func() bool
	hostInboundTCPloosePostureFailuresFn func() uint64
	snmpTrapStatsFn                      func() (enqueued, sent, dropped uint64)
	managedServiceReloadOwedFn           func() map[string]bool
	managedServiceReloadFailuresFn       func() map[string]uint64
	remoteArchiveStatusFn                func() (uint64, uint64)
	raDeadSenderPendingFn                func() bool
	proxyARPUnresolvedFn                 func() bool
	fabricOverlayMissingFn               func() bool
	managementListenerDownFn             func() bool
	managementListenersFn                func() sysservices.Listeners
	schedulerRepublishFailedFn           func() bool
	schedulerRepublishStaleSecondsFn     func() float64
	schedulerRepublishFailClosedFn       func() bool
	feedsFn                              func() map[string]feeds.FeedInfo
	helperCrashEpisodesFn                func() int
	forwardingSupportedFn                func() bool
	flowExportBuildStateFn               func() []flowexport.BuildState
	snmpServeBudgetStatsFn               func() (shed, evictions, trackedSources uint64)
	syslogDropsFn                        func() []logging.SyslogDropStat
	ddnsStatsFn                          func() *dhcpserver.DDNSStats
	surfaceAStatsFn                      func() *ddns.SurfaceAStats
	flowCollectorHealthFn                func() []flowexport.ExporterCollectorHealth
	flowExportBatchStatsFn               func() []flowexport.ExporterBatchStats
	flowExportSamplingStatsFn            func() []flowexport.SamplingStatsSnapshot
	flowExportLiveFeedMissesFn           func() uint64
	neighborPhaseAgeFn                   func() map[string]float64
	ipmonStatusFn                        func() []ipmon.PolicyStatus
	routeListenerMarksFn                 func() uint64
	routeListenerRepublishesFn           func() uint64
	ipmonActuationFailuresFn             func() uint64
	eventActionStatsFn                   func() eventengine.Stats
	rpmPinFailedFn                       func() float64
}

// activeConfig returns the store's active config, or nil when no store is
// wired (a bare test collector). It replaces the repeated
// `srv == nil || srv.store == nil` guards the c.srv reads needed: deps is a
// plain value on the collector, never nil itself, so only the store can be.
func (d collectorDeps) activeConfig() *config.Config {
	if d.store == nil {
		return nil
	}
	return d.store.ActiveConfig()
}

// collectorDepsFromServer snapshots the collector's dependencies from srv.
// A nil srv yields the zero deps (every family omitted), exactly the
// behaviour newCollector(nil) tests relied on through c.srv == nil guards
// and first-hook panics alike.
func collectorDepsFromServer(srv *Server) collectorDeps {
	if srv == nil {
		return collectorDeps{}
	}
	return collectorDeps{
		store:      srv.store,
		dp:         srv.dp,
		fwdSampler: srv.fwdSampler,
		eventBuf:   srv.eventBuf,
		dhcp:       srv.dhcp,
		startTime:  srv.startTime,

		restConnRefusals: srv.RestConnRefusals,
		restConnActive:   srv.RestConnActive,
		fabricConnStats:  srv.fabricConnStatsFn,

		configPersistDegradedFn:              srv.configPersistDegradedFn,
		rollbackHistoryDegradedFn:            srv.rollbackHistoryDegradedFn,
		archiveDegradedFn:                    srv.archiveDegradedFn,
		archiveFailureCountFn:                srv.archiveFailureCountFn,
		earlyInputGuardSwapFailedFn:          srv.earlyInputGuardSwapFailedFn,
		journalPermsDegradedFn:               srv.journalPermsDegradedFn,
		journalLegacyScrubDegradedFn:         srv.journalLegacyScrubDegradedFn,
		frrReloadDegradedFn:                  srv.frrReloadDegradedFn,
		natLenientTerminalActionRulesFn:      srv.natLenientTerminalActionRulesFn,
		frrQuarantinedRouteMapsFn:            srv.frrQuarantinedRouteMapsFn,
		frrNarrowedPolicyChainsFn:            srv.frrNarrowedPolicyChainsFn,
		frrNarrowedPolicyChainsDenySafeFn:    srv.frrNarrowedPolicyChainsDenySafeFn,
		frrNarrowedPolicyChainShapesFn:       srv.frrNarrowedPolicyChainShapesFn,
		ipsecRebindPendingFn:                 srv.ipsecRebindPendingFn,
		ipsecCaptureWitnessFn:                srv.ipsecCaptureWitnessFn,
		interfaceLinkSnapshotPendingFn:       srv.interfaceLinkSnapshotPendingFn,
		hostInboundConntrackRevocationOwedFn: srv.hostInboundConntrackRevocationOwedFn,
		hostInboundConntrackFlushFailuresFn:  srv.hostInboundConntrackFlushFailuresFn,
		hostInboundTCPlooseDisabledFn:        srv.hostInboundTCPlooseDisabledFn,
		hostInboundTCPloosePostureFailuresFn: srv.hostInboundTCPloosePostureFailuresFn,
		snmpTrapStatsFn:                      srv.snmpTrapStatsFn,
		managedServiceReloadOwedFn:           srv.managedServiceReloadOwedFn,
		managedServiceReloadFailuresFn:       srv.managedServiceReloadFailuresFn,
		remoteArchiveStatusFn:                srv.remoteArchiveStatusFn,
		raDeadSenderPendingFn:                srv.raDeadSenderPendingFn,
		proxyARPUnresolvedFn:                 srv.proxyARPUnresolvedFn,
		fabricOverlayMissingFn:               srv.fabricOverlayMissingFn,
		managementListenerDownFn:             srv.managementListenerDownFn,
		managementListenersFn:                srv.managementListenersFn,
		schedulerRepublishFailedFn:           srv.schedulerRepublishFailedFn,
		schedulerRepublishStaleSecondsFn:     srv.schedulerRepublishStaleSecondsFn,
		schedulerRepublishFailClosedFn:       srv.schedulerRepublishFailClosedFn,
		feedsFn:                              srv.feedsFn,
		helperCrashEpisodesFn:                srv.helperCrashEpisodesFn,
		forwardingSupportedFn:                srv.forwardingSupportedFn,
		flowExportBuildStateFn:               srv.flowExportBuildStateFn,
		snmpServeBudgetStatsFn:               srv.snmpServeBudgetStatsFn,
		syslogDropsFn:                        srv.syslogDropsFn,
		ddnsStatsFn:                          srv.ddnsStatsFn,
		surfaceAStatsFn:                      srv.surfaceAStatsFn,
		flowCollectorHealthFn:                srv.flowCollectorHealthFn,
		flowExportBatchStatsFn:               srv.flowExportBatchStatsFn,
		flowExportSamplingStatsFn:            srv.flowExportSamplingStatsFn,
		flowExportLiveFeedMissesFn:           srv.flowExportLiveFeedMissesFn,
		neighborPhaseAgeFn:                   srv.neighborPhaseAgeFn,
		ipmonStatusFn:                        srv.ipmonStatusFn,
		routeListenerMarksFn:                 srv.routeListenerMarksFn,
		routeListenerRepublishesFn:           srv.routeListenerRepublishesFn,
		ipmonActuationFailuresFn:             srv.ipmonActuationFailuresFn,
		eventActionStatsFn:                   srv.eventActionStatsFn,
		rpmPinFailedFn:                       srv.rpmPinFailedFn,
	}
}
