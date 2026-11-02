package api

import (
	"reflect"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
)

// #16202: per-family descriptor table driving both descriptor
// initialization (newCollector) and Describe. Each row binds one
// init*Descriptors function to the named xpfCollector *prometheus.Desc
// fields that function assigns, so the three surfaces that used to be
// handwritten separately — the init call list in newCollector, the
// ch <- c.<field> enumeration in Describe, and the struct fields
// themselves — share one registration source for Describe.
//
// The table is a package-level var initialized once at program
// startup: Describe iterates it directly and allocates nothing per
// call, and newCollector iterates it to run every family's init.
// Rows name struct fields; their indexes are resolved once at
// package init via reflection (xpfCollectorDescFieldIndex, which
// panics on a typo). The struct fields stay the assignment targets
// and the single storage, exactly as the narrowed #16202 form
// requires — no **prometheus.Desc is captured at table-construction
// time.
//
// Scope: Collect is deliberately NOT driven from this table. It
// still emits through its own emit* paths; the three-way
// registry/Describe/Collect agreement is checked explicitly by
// TestCollectorDescriptorTableAgreement16202 plus the #1726 pedantic
// canary, because a table alone cannot guarantee Describe covers
// Collect (see the issue's strongest-refutation note).
//
// Adding a metric: assign its Desc in the family's existing
// init*Descriptors (in metrics_descriptors_<family>.go or its
// metrics_* family file) and add the field name to that family's
// row below. TestCollectorDescriptorTableAgreement16202 fails if
// an assigned field is missing from its family row, if a row names
// a field its init does not assign, or if Describe and the struct
// disagree.
type collectorDescFamily struct {
	name string
	init func(*xpfCollector)
	// fields holds the struct field index (within xpfCollector) of
	// each descriptor in the family, in the order its init assigns
	// them. Storing indexes rather than bound **prometheus.Desc
	// keeps the table collector-independent, statically allocated,
	// and free of unsafe pointer arithmetic.
	fields []int
}

// collectorDescField returns the descriptor stored in the struct
// field at index fieldIdx, resolved via reflection so the static
// table needs no unsafe offset arithmetic.
func collectorDescField(c *xpfCollector, fieldIdx int) *prometheus.Desc {
	fv := reflect.ValueOf(c).Elem().Field(fieldIdx)
	if fv.IsNil() {
		return nil
	}
	// fv holds a *prometheus.Desc obtained from an unexported field,
	// so Interface() would panic; read the pointer via unsafe.
	return *(**prometheus.Desc)(unsafe.Pointer(fv.UnsafeAddr()))
}

// xpfCollectorDescFieldIndex returns the struct field index of the
// named *prometheus.Desc field, panicking at package init if the
// name does not resolve — a typo in the table below is a startup
// failure, never a silent Describe omission.
func xpfCollectorDescFieldIndex(name string) int {
	t := reflect.TypeOf(xpfCollector{})
	f, ok := t.FieldByName(name)
	if !ok {
		panic("api: collectorDescFamilies names unknown xpfCollector field " + name)
	}
	if f.Type != reflect.TypeOf((*prometheus.Desc)(nil)) {
		panic("api: collectorDescFamilies field " + name + " is not a *prometheus.Desc")
	}
	return f.Index[0]
}

var collectorDescFamilies = []collectorDescFamily{
	{name: "global", init: (*xpfCollector).initGlobalDescriptors, fields: collectorDescGlobal},
	{name: "hostinbound", init: (*xpfCollector).initHostInboundDescriptors, fields: collectorDescHostInbound},
	{name: "forwarding", init: (*xpfCollector).initForwardingDescriptors, fields: collectorDescForwarding},
	{name: "interface", init: (*xpfCollector).initInterfaceDescriptors, fields: collectorDescInterface},
	{name: "zone", init: (*xpfCollector).initZoneDescriptors, fields: collectorDescZone},
	{name: "policy", init: (*xpfCollector).initPolicyDescriptors, fields: collectorDescPolicy},
	{name: "session", init: (*xpfCollector).initSessionDescriptors, fields: collectorDescSession},
	{name: "nat", init: (*xpfCollector).initNATDescriptors, fields: collectorDescNAT},
	{name: "dhcp", init: (*xpfCollector).initDHCPDescriptors, fields: collectorDescDHCP},
	{name: "system", init: (*xpfCollector).initSystemDescriptors, fields: collectorDescSystem},
	{name: "controlplane", init: (*xpfCollector).initControlPlaneDescriptors, fields: collectorDescControlPlane},
	{name: "automation", init: (*xpfCollector).initAutomationDescriptors, fields: collectorDescAutomation},
	{name: "syslogdrop", init: (*xpfCollector).initSyslogDropDescriptors, fields: collectorDescSyslogDrop},
	{name: "flowexportbuild", init: (*xpfCollector).initFlowExportBuildDescriptors, fields: collectorDescFlowExportBuild},
	{name: "ipmonitoring", init: (*xpfCollector).initIPMonitoringDescriptors, fields: collectorDescIPMonitoring},
	{name: "cos", init: (*xpfCollector).initCoSDescriptors, fields: collectorDescCoS},
	{name: "worker", init: (*xpfCollector).initWorkerDescriptors, fields: collectorDescWorker},
	{name: "userspacesession", init: (*xpfCollector).initUserspaceSessionDescriptors, fields: collectorDescUserspaceSession},
	{name: "userspacestatus13280", init: (*xpfCollector).initUserspaceStatus13280Descriptors, fields: collectorDescUserspaceStatus13280},
	{name: "userspaceiouring13292", init: (*xpfCollector).initUserspaceIoUring13292Descriptors, fields: collectorDescUserspaceIoUring13292},
	{name: "userspacemapssync13300", init: (*xpfCollector).initUserspaceMapsSync13300Descriptors, fields: collectorDescUserspaceMapsSync13300},
	{name: "userspacedrops", init: (*xpfCollector).initUserspaceDropsDescriptors, fields: collectorDescUserspaceDrops},
	{name: "userspacenptv6", init: (*xpfCollector).initUserspaceNptv6Descriptors, fields: collectorDescUserspaceNptv6},
	{name: "slowpath", init: (*xpfCollector).initSlowPathDescriptors, fields: collectorDescSlowPath},
	{name: "userspacestream", init: (*xpfCollector).initUserspaceStreamDescriptors, fields: collectorDescUserspaceStream},
	{name: "coldpath", init: (*xpfCollector).initColdPathDescriptors, fields: collectorDescColdPath},
	{name: "binding", init: (*xpfCollector).initBindingDescriptors, fields: collectorDescBinding},
	{name: "fairness", init: (*xpfCollector).initFairnessDescriptors, fields: collectorDescFairness},
	{name: "neighbor", init: (*xpfCollector).initNeighborDescriptors, fields: collectorDescNeighbor},
	{name: "ipsecsa", init: (*xpfCollector).initIpsecSaDescriptors, fields: collectorDescIpsecSa},
	{name: "wireguard", init: (*xpfCollector).initWireGuardDescriptors, fields: collectorDescWireGuard},
	{name: "flowexport", init: (*xpfCollector).initFlowExportDescriptors, fields: collectorDescFlowExport},
	{name: "fwdstatus", init: (*xpfCollector).initFwdStatusDescriptors, fields: collectorDescFwdStatus},
	{name: "hatakeover", init: (*xpfCollector).initHATakeoverDescriptors13301, fields: collectorDescHATakeover},
	{name: "snmpservebudget", init: (*xpfCollector).initSNMPServeBudgetDescriptors, fields: collectorDescSNMPServeBudget},
	{name: "flowexportlivefeed", init: (*xpfCollector).initFlowExportLiveFeedDescriptors, fields: collectorDescFlowExportLiveFeed},
	{name: "restconn", init: (*xpfCollector).initRESTConnDescriptors, fields: collectorDescRESTConn},
	{name: "fabricconn", init: (*xpfCollector).initFabricConnDescriptors, fields: collectorDescFabricConn},
	{name: "dataplanesafety", init: (*xpfCollector).initDataplaneSafetyDescriptors, fields: collectorDescDataplaneSafety},
}

// initGlobalDescriptors (metrics_descriptors_global.go).
var collectorDescGlobal = []int{
	xpfCollectorDescFieldIndex("packetsTotal"),
	xpfCollectorDescFieldIndex("dropsTotal"),
	xpfCollectorDescFieldIndex("unknownVLANDropsTotal"),
	xpfCollectorDescFieldIndex("dstMACDropsTotal"),
	xpfCollectorDescFieldIndex("counterReadErrorsTotal"),
	xpfCollectorDescFieldIndex("admissionRefusalsTotal"),
	xpfCollectorDescFieldIndex("authzDenialsTotal"),
	xpfCollectorDescFieldIndex("napiProbeTargetSkipsTotal"),
	xpfCollectorDescFieldIndex("bindingWedgeGiveupsTotal"),
	xpfCollectorDescFieldIndex("statusPollDecodeErrorsTotal"),
	xpfCollectorDescFieldIndex("helperAnswerAgeSeconds"),
	xpfCollectorDescFieldIndex("helperElectionNotReady"),
	xpfCollectorDescFieldIndex("helperWedgeKillsTotal"),
	xpfCollectorDescFieldIndex("learnedRouteCapHitsTotal"),
	xpfCollectorDescFieldIndex("learnedRouteImportCapped"),
	xpfCollectorDescFieldIndex("degradedPathTotal"),
	xpfCollectorDescFieldIndex("managementTLSCertificateInvalidTotal"),
	xpfCollectorDescFieldIndex("sessionsCreatedTotal"),
	xpfCollectorDescFieldIndex("sessionsClosedTotal"),
	xpfCollectorDescFieldIndex("screenDropsTotal"),
	xpfCollectorDescFieldIndex("screenDropsByReasonTotal"),
	xpfCollectorDescFieldIndex("userspaceScreenSubstitutedDefaultDrops"),
	xpfCollectorDescFieldIndex("userspaceScreenSYNFloodDstDrops"),
	xpfCollectorDescFieldIndex("userspaceScreenSYNFloodSrcDrops"),
	xpfCollectorDescFieldIndex("userspaceScreenSYNFloodAlarmEvents"),
	xpfCollectorDescFieldIndex("userspaceScreenAlarmWithoutDropEvents"),
	xpfCollectorDescFieldIndex("userspaceScreenProfileWarns"),
	xpfCollectorDescFieldIndex("userspaceScreenTrackerPressureEvents"),
	xpfCollectorDescFieldIndex("screenUnresolvedProfileZones"),
	xpfCollectorDescFieldIndex("screenInertProfileZones"),
	xpfCollectorDescFieldIndex("policyDeniesTotal"),
	xpfCollectorDescFieldIndex("natAllocFailsTotal"),
	xpfCollectorDescFieldIndex("nat64XlateTotal"),
	xpfCollectorDescFieldIndex("invalidLabelValuesTotal"),
	xpfCollectorDescFieldIndex("collectorPanicsTotal"),
	xpfCollectorDescFieldIndex("gatherErrorsTotal"),
}

// initHostInboundDescriptors (metrics_descriptors_hostinbound.go).
var collectorDescHostInbound = []int{
	xpfCollectorDescFieldIndex("hostInboundDeny"),
	xpfCollectorDescFieldIndex("hostInboundKernelDenies"),
	xpfCollectorDescFieldIndex("hostInboundJunosHostDenies"),
	xpfCollectorDescFieldIndex("hostInboundICMPNDAccept"),
	xpfCollectorDescFieldIndex("hostInboundAddresslessZones"),
	xpfCollectorDescFieldIndex("hostInboundAddresslessIface"),
	xpfCollectorDescFieldIndex("hostInboundAmbiguousAddrs"),
	xpfCollectorDescFieldIndex("vrfOverlapPBRAdmitted"),
	xpfCollectorDescFieldIndex("riMemberDeviceConflicts"),
	xpfCollectorDescFieldIndex("lo0CounterHits"),
	xpfCollectorDescFieldIndex("lo0ImplicitDiscardHits"),
}

// initForwardingDescriptors (metrics_descriptors_forwarding.go).
var collectorDescForwarding = []int{
	xpfCollectorDescFieldIndex("pbrRulesInstalled"),
	xpfCollectorDescFieldIndex("pbrRulesDesired"),
	xpfCollectorDescFieldIndex("pbrRulesApplied"),
	xpfCollectorDescFieldIndex("pbrRulesMismatched"),
	xpfCollectorDescFieldIndex("pbrDegradedTerms"),
	xpfCollectorDescFieldIndex("tcEgressPacketsTotal"),
	xpfCollectorDescFieldIndex("syncookieTotal"),
	xpfCollectorDescFieldIndex("flowCacheTotal"),
	xpfCollectorDescFieldIndex("learnedRouteCapGroupShedsTotal"),
	xpfCollectorDescFieldIndex("learnedRouteCapGroupShedsByFamilyTotal"),
}

// initInterfaceDescriptors (metrics_descriptors_interface.go).
var collectorDescInterface = []int{
	xpfCollectorDescFieldIndex("ifacePacketsTotal"),
	xpfCollectorDescFieldIndex("ifaceBytesTotal"),
	xpfCollectorDescFieldIndex("interfaceCounterReadErrorsTotal"),
}

// initZoneDescriptors (metrics_descriptors_zone.go).
var collectorDescZone = []int{
	xpfCollectorDescFieldIndex("zonePacketsTotal"),
	xpfCollectorDescFieldIndex("zoneBytesTotal"),
	xpfCollectorDescFieldIndex("zoneCountersOverflowActive"),
	xpfCollectorDescFieldIndex("floodCounterOverflowActive"),
	xpfCollectorDescFieldIndex("zoneFloodDropsTotal"),
	xpfCollectorDescFieldIndex("zoneCountersUnpopulatedZones"),
}

// initPolicyDescriptors (metrics_descriptors_policy.go).
var collectorDescPolicy = []int{
	xpfCollectorDescFieldIndex("policyHitsTotal"),
	xpfCollectorDescFieldIndex("policyCountersUnpublishedRules"),
	xpfCollectorDescFieldIndex("filterHitsTotal"),
	xpfCollectorDescFieldIndex("threeColorPolicerPacketsTotal"),
	xpfCollectorDescFieldIndex("threeColorPolicerBytesTotal"),
	xpfCollectorDescFieldIndex("threeColorPolicerDropsTotal"),
	xpfCollectorDescFieldIndex("threeColorPolicerDropBytes"),
}

// initSessionDescriptors (metrics_descriptors_session.go).
var collectorDescSession = []int{
	xpfCollectorDescFieldIndex("sessionsActive"),
	xpfCollectorDescFieldIndex("sessionsEstablished"),
	xpfCollectorDescFieldIndex("sessionsIPv4"),
	xpfCollectorDescFieldIndex("sessionsIPv6"),
	xpfCollectorDescFieldIndex("sessionsSNAT"),
	xpfCollectorDescFieldIndex("sessionsDNAT"),
	xpfCollectorDescFieldIndex("sessionScrapeOK"),
}

// initNATDescriptors (metrics_descriptors_nat.go).
var collectorDescNAT = []int{
	xpfCollectorDescFieldIndex("natPoolUsedPorts"),
	xpfCollectorDescFieldIndex("natPoolTotalPorts"),
	xpfCollectorDescFieldIndex("natPoolDeterministicInfo"),
	xpfCollectorDescFieldIndex("natPoolDetBlocksTotal"),
	xpfCollectorDescFieldIndex("natPoolDetBlocksAllocated"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolLiveFlows"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolMaxTrackedFlows"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolUsedPorts"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolPersistentLeases"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolAllocationsTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolReusesTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolPersistentAdmittedTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolPersistentDeclinedTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolExhaustionsTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolIdleLeaseImportCapacityTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolFlowShardLockAcquisitionsTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolFlowShardLockContendedTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolLiveWriteLockAcquisitionsTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolLiveWriteLockContendedTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolLiveLockAcquisitionsTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolLiveLockContendedTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolRecycleScanPopsTotal"),
	xpfCollectorDescFieldIndex("userspaceSNATPoolRecycleScanWalksTotal"),
	xpfCollectorDescFieldIndex("ifaceSNATOverlapScansTotal"),
	xpfCollectorDescFieldIndex("ifaceSNATOverlapAddresses"),
	xpfCollectorDescFieldIndex("ifaceSNATOverlapQuarantined"),
}

// initDHCPDescriptors (metrics_descriptors_dhcp.go).
var collectorDescDHCP = []int{
	xpfCollectorDescFieldIndex("dhcpLeasesActive"),
	xpfCollectorDescFieldIndex("dhcpDDNSUpsertsTotal"),
	xpfCollectorDescFieldIndex("dhcpDDNSDeletesTotal"),
	xpfCollectorDescFieldIndex("dhcpDDNSReconcileRunsTotal"),
	xpfCollectorDescFieldIndex("dhcpDDNSSkippedTotal"),
	xpfCollectorDescFieldIndex("dhcpDDNSOwnedRecords"),
	xpfCollectorDescFieldIndex("dhcpDDNSPTRPending"),
	xpfCollectorDescFieldIndex("dhcpDDNSDegraded"),
	xpfCollectorDescFieldIndex("dhcpDDNSUnsignedActive"),
	xpfCollectorDescFieldIndex("dhcpDDNSLastReconcileTs"),
	xpfCollectorDescFieldIndex("dhcpDDNSLastReconcileN"),
	xpfCollectorDescFieldIndex("surfaceADDNSUpsertsTotal"),
	xpfCollectorDescFieldIndex("surfaceADDNSDeletesTotal"),
	xpfCollectorDescFieldIndex("surfaceADDNSSkippedTotal"),
	xpfCollectorDescFieldIndex("surfaceADDNSScopes"),
	xpfCollectorDescFieldIndex("surfaceADDNSOrphaned"),
	xpfCollectorDescFieldIndex("surfaceADDNSDegraded"),
	xpfCollectorDescFieldIndex("surfaceADDNSUnsignedActive"),
}

// initSystemDescriptors (metrics_descriptors_system.go).
var collectorDescSystem = []int{
	xpfCollectorDescFieldIndex("sysCPUUser"),
	xpfCollectorDescFieldIndex("sysCPUSystem"),
	xpfCollectorDescFieldIndex("sysMemTotal"),
	xpfCollectorDescFieldIndex("sysMemAvail"),
	xpfCollectorDescFieldIndex("daemonUptime"),
	xpfCollectorDescFieldIndex("daemonMemRSS"),
}

// initControlPlaneDescriptors (metrics_descriptors_controlplane.go).
var collectorDescControlPlane = []int{
	xpfCollectorDescFieldIndex("neighborPeriodicAge"),
	xpfCollectorDescFieldIndex("frrReloadDegraded"),
	xpfCollectorDescFieldIndex("frrPolicyChainsNarrowed"),
	xpfCollectorDescFieldIndex("frrPolicyChainsNarrowedDenySafe"),
	xpfCollectorDescFieldIndex("frrPolicyChainsNarrowedShape"),
	xpfCollectorDescFieldIndex("frrRouteMapsQuarantined"),
	xpfCollectorDescFieldIndex("natRulesLenientTerminalAction"),
	xpfCollectorDescFieldIndex("ipsecRebindPending"),
	xpfCollectorDescFieldIndex("interfaceLinkSnapshotPending"),
	xpfCollectorDescFieldIndex("hostInboundConntrackRevocationPending"),
	xpfCollectorDescFieldIndex("hostInboundConntrackRevocationFailures"),
	xpfCollectorDescFieldIndex("hostInboundTCPlooseDisabled"),
	xpfCollectorDescFieldIndex("hostInboundTCPloosePostureFailures"),
	xpfCollectorDescFieldIndex("snmpTrapsEnqueued"),
	xpfCollectorDescFieldIndex("snmpTrapsSent"),
	xpfCollectorDescFieldIndex("snmpTrapsDropped"),
	xpfCollectorDescFieldIndex("managedServiceReloadPending"),
	xpfCollectorDescFieldIndex("managedServiceReloadFailures"),
	xpfCollectorDescFieldIndex("remoteArchivePendingSites"),
	xpfCollectorDescFieldIndex("remoteArchiveFailures"),
	xpfCollectorDescFieldIndex("raDeadSenderPending"),
	xpfCollectorDescFieldIndex("proxyARPUnresolved"),
	xpfCollectorDescFieldIndex("fabricOverlayMissing"),
	xpfCollectorDescFieldIndex("managementListenerDown"),
	xpfCollectorDescFieldIndex("managementListenerState"),
	xpfCollectorDescFieldIndex("helperCrashEpisodesTotal"),
	xpfCollectorDescFieldIndex("forwardingSupported"),
	xpfCollectorDescFieldIndex("ipsecCaptureActorActive"),
	xpfCollectorDescFieldIndex("ipsecCapturePermitState"),
	xpfCollectorDescFieldIndex("ipsecCaptureConsumedTotal"),
	xpfCollectorDescFieldIndex("ipsecCaptureAdjudicatedTotal"),
	xpfCollectorDescFieldIndex("ipsecCaptureReinjectedTotal"),
	xpfCollectorDescFieldIndex("ipsecCaptureWrittenTotal"),
	xpfCollectorDescFieldIndex("ipsecCaptureUncertainTotal"),
	xpfCollectorDescFieldIndex("ipsecCaptureLateCompletionsTotal"),
	xpfCollectorDescFieldIndex("ipsecCaptureTimeoutsTotal"),
	xpfCollectorDescFieldIndex("ipsecCaptureStaleTotal"),
	xpfCollectorDescFieldIndex("ipsecCaptureCancelledTotal"),
	xpfCollectorDescFieldIndex("ipsecCaptureRefusedTotal"),
	xpfCollectorDescFieldIndex("ipsecCaptureD11SuppressedTotal"),
	xpfCollectorDescFieldIndex("ipsecCaptureD11Deny52Total"),
	xpfCollectorDescFieldIndex("ipsecCaptureDeliveredAvail"),
	xpfCollectorDescFieldIndex("ipsecCaptureDeliveredTotal"),
	xpfCollectorDescFieldIndex("schedulerRepublishFailed"),
	xpfCollectorDescFieldIndex("schedulerRepublishStale"),
	xpfCollectorDescFieldIndex("schedulerRepublishFailClosed"),
	xpfCollectorDescFieldIndex("schedulerRepublishFailOpenStale"),
	xpfCollectorDescFieldIndex("configPersistDegraded"),
	xpfCollectorDescFieldIndex("rollbackHistoryDegraded"),
	xpfCollectorDescFieldIndex("archiveDegraded"),
	xpfCollectorDescFieldIndex("archiveFailures"),
	xpfCollectorDescFieldIndex("earlyInputGuardSwapFailed"),
	xpfCollectorDescFieldIndex("journalPermsDegraded"),
	xpfCollectorDescFieldIndex("journalLegacyScrubDegraded"),
	xpfCollectorDescFieldIndex("userspacePolicyContentRejected"),
	xpfCollectorDescFieldIndex("userspaceZoneIDCollision"),
	xpfCollectorDescFieldIndex("userspaceSnapshotPolicyMismatch"),
	xpfCollectorDescFieldIndex("userspaceLastSnapshotPolicyCount"),
	xpfCollectorDescFieldIndex("rpmPinInstallFailures"),
}

// initAutomationDescriptors (metrics_descriptors_automation.go).
var collectorDescAutomation = []int{
	xpfCollectorDescFieldIndex("eventActionsCommitted"),
	xpfCollectorDescFieldIndex("eventActionsCommittedWithDebt"),
	xpfCollectorDescFieldIndex("eventActionsRejected"),
	xpfCollectorDescFieldIndex("eventActionsRetried"),
	xpfCollectorDescFieldIndex("eventActionsDropped"),
	xpfCollectorDescFieldIndex("eventActionsSuperseded"),
	xpfCollectorDescFieldIndex("eventActionsSkippedNoChange"),
	xpfCollectorDescFieldIndex("eventActionsDeferred"),
	xpfCollectorDescFieldIndex("eventCooldownSuppressed"),
	xpfCollectorDescFieldIndex("eventPendingDeferred"),
	xpfCollectorDescFieldIndex("eventAttributesInvalid"),
	xpfCollectorDescFieldIndex("eventPlantClassInvalid"),
	xpfCollectorDescFieldIndex("eventActionQueueDepth"),
	xpfCollectorDescFieldIndex("eventStreamSubscriberDropped"),
	xpfCollectorDescFieldIndex("eventStreamSubscriberRefusals"),
	xpfCollectorDescFieldIndex("eventStreamRingEvicted"),
	xpfCollectorDescFieldIndex("feedSecondsSinceSuccess"),
	xpfCollectorDescFieldIndex("feedStale"),
	xpfCollectorDescFieldIndex("feedPublicationDebt"),
	xpfCollectorDescFieldIndex("feedShrinkRefusalsTotal"),
	xpfCollectorDescFieldIndex("feedShrinkRefused"),
}

// initSyslogDropDescriptors (metrics_syslog_drops_9165.go).
var collectorDescSyslogDrop = []int{
	xpfCollectorDescFieldIndex("syslogMessagesDropped"),
}

// initFlowExportBuildDescriptors (metrics_flowexport_build_9166.go).
var collectorDescFlowExportBuild = []int{
	xpfCollectorDescFieldIndex("flowExportConfiguredGroups"),
	xpfCollectorDescFieldIndex("flowExportBuildFailed"),
	xpfCollectorDescFieldIndex("flowExportExcludedFlowServers"),
}

// initIPMonitoringDescriptors (metrics_descriptors_ipmonitoring.go).
var collectorDescIPMonitoring = []int{
	xpfCollectorDescFieldIndex("ipmonPolicyFailed"),
	xpfCollectorDescFieldIndex("ipmonPolicyTransitions"),
	xpfCollectorDescFieldIndex("ipmonRoutesApplied"),
	xpfCollectorDescFieldIndex("ipmonRoutesDesired"),
	xpfCollectorDescFieldIndex("ipmonUnresolvedNextHops"),
	xpfCollectorDescFieldIndex("routeListenerMarks"),
	xpfCollectorDescFieldIndex("routeListenerRepublishes"),
	xpfCollectorDescFieldIndex("ipmonActuationFailures"),
}

// initCoSDescriptors (metrics_descriptors_cos.go).
var collectorDescCoS = []int{
	xpfCollectorDescFieldIndex("cosDrainLatencyBucket"),
	xpfCollectorDescFieldIndex("cosDrainInvocationsTotal"),
	xpfCollectorDescFieldIndex("cosRedirectAcquireBucket"),
	xpfCollectorDescFieldIndex("cosOwnerPPS"),
	xpfCollectorDescFieldIndex("cosPeerPPS"),
	xpfCollectorDescFieldIndex("cosDrainGuaranteeSentBytes"),
	xpfCollectorDescFieldIndex("cosDrainSurplusSentBytes"),
	xpfCollectorDescFieldIndex("cosDrainNonExactSentBytesWhileExactBacklogged"),
	xpfCollectorDescFieldIndex("cosRootTokenStarvationParks"),
	xpfCollectorDescFieldIndex("cosQueueTokenStarvationParks"),
	xpfCollectorDescFieldIndex("cosDrainParkRootTokens"),
	xpfCollectorDescFieldIndex("cosDrainParkQueueTokens"),
	xpfCollectorDescFieldIndex("cosLeaseV8RequestedBytes"),
	xpfCollectorDescFieldIndex("cosLeaseV8GrantedBytes"),
	xpfCollectorDescFieldIndex("cosAdmissionFlowShareDrops"),
	xpfCollectorDescFieldIndex("cosAdmissionBufferDrops"),
	xpfCollectorDescFieldIndex("cosAdmissionEcnMarked"),
	xpfCollectorDescFieldIndex("cosWaterfillPhase1Admissions"),
	xpfCollectorDescFieldIndex("cosWaterfillPhase2Admissions"),
	xpfCollectorDescFieldIndex("cosWaterfillEligibleVisits"),
	xpfCollectorDescFieldIndex("cosWaterfillPhase1SelectedNoProgress"),
	xpfCollectorDescFieldIndex("cosWaterfillEpochs"),
	xpfCollectorDescFieldIndex("cosWaterfillPhase1BudgetBreaks"),
	xpfCollectorDescFieldIndex("cosWaterfillMinEpochsPerWorker"),
	xpfCollectorDescFieldIndex("cosEqualFlowEnforcementEnabled"),
	xpfCollectorDescFieldIndex("cosEqualFlowTargetPolicy"),
	xpfCollectorDescFieldIndex("cosEqualFlowEnforced"),
	xpfCollectorDescFieldIndex("cosEqualFlowTargetPerFlowBPS"),
	xpfCollectorDescFieldIndex("cosEqualFlowMaxWorkerCapBytes"),
	xpfCollectorDescFieldIndex("cosEqualFlowCapHitEvents"),
	xpfCollectorDescFieldIndex("cosEqualFlowSuppressedGrantBytes"),
	xpfCollectorDescFieldIndex("cosEqualFlowStaleOrTagMismatchEvents"),
	xpfCollectorDescFieldIndex("cosEqualFlowFailOpen"),
	xpfCollectorDescFieldIndex("cosSojournEwmaNS"),
	xpfCollectorDescFieldIndex("cosSojournPeakNS"),
	xpfCollectorDescFieldIndex("cosSojournWindowedMinNS"),
	xpfCollectorDescFieldIndex("cosFlowFairBucketsOccupied"),
	xpfCollectorDescFieldIndex("cosFlowFairFlowsActive"),
}

// initWorkerDescriptors (metrics_descriptors_worker.go).
var collectorDescWorker = []int{
	xpfCollectorDescFieldIndex("workerWallSecs"),
	xpfCollectorDescFieldIndex("workerActiveSecs"),
	xpfCollectorDescFieldIndex("workerIdleSpinSecs"),
	xpfCollectorDescFieldIndex("workerIdleBlockSecs"),
	xpfCollectorDescFieldIndex("workerThreadCPUSecs"),
	xpfCollectorDescFieldIndex("workerThreadCPUSecsLast60s"),
	xpfCollectorDescFieldIndex("workerThreadCPUWindowSecs"),
	xpfCollectorDescFieldIndex("workerWorkLoops"),
	xpfCollectorDescFieldIndex("workerIdleLoops"),
	xpfCollectorDescFieldIndex("workerSessionVolumeHighWater"),
	xpfCollectorDescFieldIndex("workerCoSQueueLeaseAcquireV8Calls"),
	xpfCollectorDescFieldIndex("workerCoSQueueLeaseAcquireV8GrantedBytes"),
	xpfCollectorDescFieldIndex("workerCoSWheelTicksAdvancedTotal"),
	xpfCollectorDescFieldIndex("workerCoSWheelTicksAdvancedMax"),
	xpfCollectorDescFieldIndex("workerCoSQueueLeaseUndergrant"),
	xpfCollectorDescFieldIndex("workerSessionTableEntries"),
	xpfCollectorDescFieldIndex("workerSessionTableCapacity"),
	xpfCollectorDescFieldIndex("workerNatReverseKeyCollisions"),
	xpfCollectorDescFieldIndex("workerNatReverseKeyCollisionsDistinctSrc"),
	xpfCollectorDescFieldIndex("workerSessionLookupMissNoHandle"),
	xpfCollectorDescFieldIndex("workerSessionLookupMissStaleHandle"),
	xpfCollectorDescFieldIndex("workerSessionLookupMissKeyMismatch"),
	xpfCollectorDescFieldIndex("workerSessionCreateDrops"),
	xpfCollectorDescFieldIndex("workerSessionInstallAdmissionRefused"),
	xpfCollectorDescFieldIndex("workerNewFlowInstalls"),
	xpfCollectorDescFieldIndex("workerSessionInstallPartial"),
}

// initUserspaceSessionDescriptors (metrics_descriptors_userspace_session.go).
var collectorDescUserspaceSession = []int{
	xpfCollectorDescFieldIndex("userspaceSessionTableEntries"),
	xpfCollectorDescFieldIndex("userspaceSessionTableCapacity"),
	xpfCollectorDescFieldIndex("userspaceNATParseErrorsTotal"),
	xpfCollectorDescFieldIndex("userspaceSourceNATMatchConsulted"),
	xpfCollectorDescFieldIndex("userspaceSourceNATMatchMatched"),
	xpfCollectorDescFieldIndex("userspaceSourceNATMatchUnavailable"),
	xpfCollectorDescFieldIndex("userspaceSourceNATMatchNoMatch"),
	xpfCollectorDescFieldIndex("userspaceNatReverseKeyCollisions"),
	xpfCollectorDescFieldIndex("userspaceNatReverseKeyCollisionsDistinctSrc"),
	xpfCollectorDescFieldIndex("userspaceNatReverseKeySharedDisplacements"),
	xpfCollectorDescFieldIndex("userspaceNAT64FragCrossDomainMisses"),
	xpfCollectorDescFieldIndex("userspaceNAT64OverBudgetTotal"),
	xpfCollectorDescFieldIndex("userspaceNAT64OverBudgetPrefixes"),
	xpfCollectorDescFieldIndex("userspaceNAT64DeterministicDowngrades"),
	xpfCollectorDescFieldIndex("userspaceIPv6AHFlowlessTotal"),
	xpfCollectorDescFieldIndex("userspaceNAT64FragProtocolAliasMisses"),
	xpfCollectorDescFieldIndex("userspaceFragMaxLifetimeEvictions"),
	xpfCollectorDescFieldIndex("userspaceFragQuotaRefusals"),
	xpfCollectorDescFieldIndex("userspaceEgressMTUUnknownForward"),
	xpfCollectorDescFieldIndex("userspacePTBUnbuildable"),
	xpfCollectorDescFieldIndex("userspaceInterfaceSNATPATCollisions"),
	xpfCollectorDescFieldIndex("userspaceInterfaceSNATIdentityExhaustion"),
	xpfCollectorDescFieldIndex("userspaceInterfaceSNATSyncConflictDrops"),
	xpfCollectorDescFieldIndex("userspaceInterfaceSNATRegistryCap"),
	xpfCollectorDescFieldIndex("userspaceSessionCreateDrops"),
	xpfCollectorDescFieldIndex("userspaceSessionInstallAdmissionRefused"),
	xpfCollectorDescFieldIndex("userspaceSessionInstallPartial"),
	xpfCollectorDescFieldIndex("userspaceSessionGCScanned"),
	xpfCollectorDescFieldIndex("userspaceSessionGCDroppedGone"),
	xpfCollectorDescFieldIndex("userspaceSessionGCDroppedStale"),
	xpfCollectorDescFieldIndex("userspaceSessionGCReBucketed"),
	xpfCollectorDescFieldIndex("userspaceSessionGCHeldStandby"),
	xpfCollectorDescFieldIndex("userspaceSessionGCReapedStaleSynced"),
	xpfCollectorDescFieldIndex("userspaceSessionGCHealedOnPromote"),
	xpfCollectorDescFieldIndex("userspaceSessionGCAgedOwnerRGZeroActiveNode"),
	xpfCollectorDescFieldIndex("userspaceSessionGCKeptAliveByCompanion"),
	xpfCollectorDescFieldIndex("userspaceSessionGCExpired"),
	xpfCollectorDescFieldIndex("userspacePptpUnassociatedPackets"),
	xpfCollectorDescFieldIndex("userspacePptpExpiredIdle"),
	xpfCollectorDescFieldIndex("userspacePptpHandleCollisions"),
	xpfCollectorDescFieldIndex("userspacePptpAllocatorCollisions"),
	xpfCollectorDescFieldIndex("userspaceSharedSessionPublishes"),
	xpfCollectorDescFieldIndex("userspaceEventStreamProducerSeqLockAcquired"),
	xpfCollectorDescFieldIndex("userspaceEventStreamProducerSeqLockBlocked"),
	xpfCollectorDescFieldIndex("userspaceSharedSessionPublishLockAcquired"),
	xpfCollectorDescFieldIndex("userspaceSharedSessionPublishLockBlocked"),
	xpfCollectorDescFieldIndex("userspaceSessionReplicationUpserts"),
	xpfCollectorDescFieldIndex("userspaceSessionReplicationEnqueued"),
	xpfCollectorDescFieldIndex("userspaceSessionReplicationLockBlocked"),
	xpfCollectorDescFieldIndex("userspaceSessionReplicationQueueDepthSum"),
	xpfCollectorDescFieldIndex("userspaceSessionReplicationQueueDepthMax"),
	xpfCollectorDescFieldIndex("userspaceSessionPublishErrors"),
	xpfCollectorDescFieldIndex("userspacePolicyRevokedSessions"),
	xpfCollectorDescFieldIndex("userspaceSnatRevokedSessions"),
	xpfCollectorDescFieldIndex("userspaceUnzonedIngressDenied"),
	xpfCollectorDescFieldIndex("userspaceUnzonedEgressDenied"),
	xpfCollectorDescFieldIndex("userspaceSyncedImportCapDrops"),
	xpfCollectorDescFieldIndex("userspaceWorkerCommandQueuePoisonRecoveries"),
	xpfCollectorDescFieldIndex("userspaceWorkerCommandQueueDrops"),
	xpfCollectorDescFieldIndex("userspaceSyncedImportUnpublished"),
	xpfCollectorDescFieldIndex("userspaceSyncedImportZoneUnresolved"),
	xpfCollectorDescFieldIndex("userspaceSessionInstallStaleIgnored"),
	xpfCollectorDescFieldIndex("userspaceSessionDeleteStaleIgnored"),
	xpfCollectorDescFieldIndex("userspaceSyncedImportReserveRefused"),
	xpfCollectorDescFieldIndex("userspaceSyncedImportMirrorRefused"),
	xpfCollectorDescFieldIndex("userspaceMirrorRestoreRepublished"),
	xpfCollectorDescFieldIndex("userspaceMirrorRestoreDeleted"),
	xpfCollectorDescFieldIndex("userspaceMirrorRestoreFailed"),
	xpfCollectorDescFieldIndex("userspacePolicyBatchCount"),
	xpfCollectorDescFieldIndex("userspacePolicyBatchHoldNs"),
	xpfCollectorDescFieldIndex("userspacePolicyBatchHoldMaxNs"),
	xpfCollectorDescFieldIndex("userspaceSyncedImportUnknownRoutingDomain"),
	xpfCollectorDescFieldIndex("userspaceSyncedImportIncompleteKey"),
	xpfCollectorDescFieldIndex("userspaceSharedSessionPoisonRecoveries"),
	xpfCollectorDescFieldIndex("userspaceTxCompletionSkew"),
	xpfCollectorDescFieldIndex("userspaceTxCompletionInvalid"),
	xpfCollectorDescFieldIndex("userspaceTxCompletionDuplicate"),
	xpfCollectorDescFieldIndex("userspaceFillInvalid"),
	xpfCollectorDescFieldIndex("userspaceWorkerCommandQueueShed"),
	xpfCollectorDescFieldIndex("userspaceServerStatePoisonRecoveries"),
	xpfCollectorDescFieldIndex("userspaceServerHandlerPanics"),
	xpfCollectorDescFieldIndex("userspaceReinjectHandlerPanics"),
}

// initUserspaceStatus13280Descriptors (metrics_descriptors_userspace_status_13280.go).
var collectorDescUserspaceStatus13280 = []int{
	xpfCollectorDescFieldIndex("userspaceCosNoOwnerBindingDrops"),
	xpfCollectorDescFieldIndex("userspaceIoUringWriteRefused"),
	xpfCollectorDescFieldIndex("userspaceIoUringWriteRefusedBytes"),
	xpfCollectorDescFieldIndex("userspaceRouteChangeUnrejudgedSessions"),
	xpfCollectorDescFieldIndex("userspaceOwnerRGFilingsDeclined"),
	xpfCollectorDescFieldIndex("userspaceSharedNatAmbiguityKeys"),
	xpfCollectorDescFieldIndex("userspaceSharedNatAmbiguitySaturated"),
	xpfCollectorDescFieldIndex("userspaceSharedWireAmbiguityKeys"),
	xpfCollectorDescFieldIndex("userspaceSharedWireAmbiguitySaturated"),
	xpfCollectorDescFieldIndex("userspaceSharedWireFallbackScans"),
	xpfCollectorDescFieldIndex("userspaceHATransitionDropped"),
	xpfCollectorDescFieldIndex("userspaceHATransitionStaleSkipped"),
	xpfCollectorDescFieldIndex("userspaceSessionDeleteRefusedIdentity"),
	xpfCollectorDescFieldIndex("userspaceSessionDeleteDroppedReleased"),
	xpfCollectorDescFieldIndex("userspaceTunnelPurgeReservationsReleased"),
	xpfCollectorDescFieldIndex("userspaceTunnelPurgeDeleteRefused"),
	xpfCollectorDescFieldIndex("userspaceSyncedReverseRederived"),
	xpfCollectorDescFieldIndex("userspacePeerDeleteRefusedLocalOwned"),
	xpfCollectorDescFieldIndex("userspaceSessionDeleteReplicaDropped"),
	xpfCollectorDescFieldIndex("userspaceSessionDeleteReplicaDropRepaired"),
	xpfCollectorDescFieldIndex("userspaceS5Reinject"),
	xpfCollectorDescFieldIndex("userspaceS5ReinjectCompletions"),
	xpfCollectorDescFieldIndex("userspaceWGUncoveredPacketsTotal"),
	xpfCollectorDescFieldIndex("userspaceWGUncoveredQueuePoison"),
	xpfCollectorDescFieldIndex("userspaceTupleGatePoison"),
}

// initUserspaceIoUring13292Descriptors (metrics_descriptors_userspace_io_uring_13292.go).
var collectorDescUserspaceIoUring13292 = []int{
	xpfCollectorDescFieldIndex("userspaceIoUringActive"),
	xpfCollectorDescFieldIndex("userspaceIoUringRetainedBuffers"),
	xpfCollectorDescFieldIndex("userspaceIoUringRetainedBytes"),
}

// initUserspaceMapsSync13300Descriptors (metrics_descriptors_userspace_maps_sync_13300.go).
var collectorDescUserspaceMapsSync13300 = []int{
	xpfCollectorDescFieldIndex("userspaceRSTSuppressionDegraded"),
	xpfCollectorDescFieldIndex("userspaceRSTSuppressionFailures"),
	xpfCollectorDescFieldIndex("userspaceBindingsWatchdogRepairs"),
	xpfCollectorDescFieldIndex("userspaceBindingsWatchdogErrors"),
	xpfCollectorDescFieldIndex("userspaceLocalAddrPruneSkipped"),
}

// initUserspaceDropsDescriptors (metrics_descriptors_userspace_drops.go).
var collectorDescUserspaceDrops = []int{
	xpfCollectorDescFieldIndex("userspaceGreDecapEcnIllegalDrops"),
	xpfCollectorDescFieldIndex("userspaceWgDecapEcnIllegalDrops"),
	xpfCollectorDescFieldIndex("userspaceGreEncapDfOversizeDrops"),
	xpfCollectorDescFieldIndex("userspaceGreDecapChecksumInvalidDrops"),
	xpfCollectorDescFieldIndex("userspaceGreDecapUnsupportedVersionRefusals"),
	xpfCollectorDescFieldIndex("userspaceGreDecapPtNibbleMismatchRefusals"),
	xpfCollectorDescFieldIndex("userspaceGreOuterFragDrops"),
	xpfCollectorDescFieldIndex("userspaceGreReassembledDecapRefusals"),
	xpfCollectorDescFieldIndex("userspaceGreDecapTransportEgressRefusals"),
	xpfCollectorDescFieldIndex("userspaceTimeExceededRateLimited"),
	xpfCollectorDescFieldIndex("userspacePacketTooBigRateLimited"),
	xpfCollectorDescFieldIndex("userspaceRejectRateLimited"),
	xpfCollectorDescFieldIndex("userspaceRejectSent"),
	xpfCollectorDescFieldIndex("userspaceRejectReplyBudgetDrops"),
	xpfCollectorDescFieldIndex("userspaceRejectOutputFilterDrops"),
	xpfCollectorDescFieldIndex("userspaceRejectRateLimitedBySource"),
	xpfCollectorDescFieldIndex("userspaceMartianDropped"),
	xpfCollectorDescFieldIndex("userspaceDNSIllegalReplyDropped"),
	xpfCollectorDescFieldIndex("userspaceIPv6ExtHeaderDropped"),
	xpfCollectorDescFieldIndex("userspaceV4MappedIPv6Dropped"),
	xpfCollectorDescFieldIndex("userspaceFabricInvalidStampDrops"),
	xpfCollectorDescFieldIndex("userspaceFabricUnstampedIngressDrops"),
	xpfCollectorDescFieldIndex("userspaceFabricAmbiguousZoneDrops"),
	xpfCollectorDescFieldIndex("userspaceUMEMSliceDropped"),
	xpfCollectorDescFieldIndex("userspaceUnknownVLANDropped"),
	xpfCollectorDescFieldIndex("userspaceDstMACDropped"),
	xpfCollectorDescFieldIndex("userspacePMechDecapHoldRefused"),
	xpfCollectorDescFieldIndex("userspaceTransitOutputFilterDrops"),
	xpfCollectorDescFieldIndex("userspaceTransitSourceMartianDrops"),
	xpfCollectorDescFieldIndex("userspaceTransitIPSecFenceDrops"),
	xpfCollectorDescFieldIndex("userspaceTransitL2GroupDrops"),
	xpfCollectorDescFieldIndex("userspaceForwardBuildFailures"),
	xpfCollectorDescFieldIndex("userspaceNoEgressBindingDrops"),
	xpfCollectorDescFieldIndex("userspaceEmbeddedQuoteSubminimalRefused"),
	xpfCollectorDescFieldIndex("userspaceEmbeddedErrorPerSessionSuppressed"),
	xpfCollectorDescFieldIndex("userspaceNATReverseAmbiguous"),
	xpfCollectorDescFieldIndex("userspaceZoneGateUnzoned"),
	xpfCollectorDescFieldIndex("userspaceZoneGateAmbiguous"),
	xpfCollectorDescFieldIndex("userspaceZoneGateStale"),
	xpfCollectorDescFieldIndex("userspaceZoneGateNoGeneration"),
	xpfCollectorDescFieldIndex("userspaceIpsecInnerParseDrops"),
	xpfCollectorDescFieldIndex("userspaceIpsecInnerEcnIllegalDrops"),
	xpfCollectorDescFieldIndex("userspaceIpsecInnerNoroute"),
	xpfCollectorDescFieldIndex("userspaceIpsecInnerWorkerQueueFull"),
	xpfCollectorDescFieldIndex("userspaceIpsecInnerVerdictQueueFull"),
	xpfCollectorDescFieldIndex("userspaceIpsecInnerVerdictQueueContended"),
	xpfCollectorDescFieldIndex("userspaceIpsecInnerSlabExhausted"),
	xpfCollectorDescFieldIndex("userspaceIpsecInnerWorkerRetired"),
	xpfCollectorDescFieldIndex("userspaceIpsecInnerWorkerOrphanReaped"),
	xpfCollectorDescFieldIndex("userspaceIpsecInnerOrphanProvisional"),
	xpfCollectorDescFieldIndex("userspaceIpsecInnerPermitForwardArmed"),
}

// initUserspaceNptv6Descriptors (metrics_descriptors_userspace_nptv6.go).
var collectorDescUserspaceNptv6 = []int{
	xpfCollectorDescFieldIndex("userspaceNptv6TranslationsTotal"),
	xpfCollectorDescFieldIndex("userspaceNptv6UntranslatableDrops"),
}

// initSlowPathDescriptors (metrics_descriptors_slowpath.go).
var collectorDescSlowPath = []int{
	xpfCollectorDescFieldIndex("userspaceSlowPathActive"),
	xpfCollectorDescFieldIndex("userspaceSlowPathDegraded"),
	xpfCollectorDescFieldIndex("userspaceSlowPathLiveMTU"),
	xpfCollectorDescFieldIndex("userspaceSlowPathQueuedPackets"),
	xpfCollectorDescFieldIndex("userspaceSlowPathInjectedPackets"),
	xpfCollectorDescFieldIndex("userspaceSlowPathInjectedBytes"),
	xpfCollectorDescFieldIndex("userspaceSlowPathDroppedPackets"),
	xpfCollectorDescFieldIndex("userspaceSlowPathDroppedBytes"),
	xpfCollectorDescFieldIndex("userspaceSlowPathRateLimited"),
	xpfCollectorDescFieldIndex("userspaceSlowPathQueueFull"),
	xpfCollectorDescFieldIndex("userspaceSlowPathWriteErrors"),
	xpfCollectorDescFieldIndex("userspaceSlowPathMTUDroppedPackets"),
}

// initUserspaceStreamDescriptors (metrics_descriptors_userspace_stream.go).
var collectorDescUserspaceStream = []int{
	xpfCollectorDescFieldIndex("userspaceFlowCacheActiveFlows"),
	xpfCollectorDescFieldIndex("userspaceFlowCacheCapacity"),
	xpfCollectorDescFieldIndex("userspaceEventStreamFramesTotal"),
	xpfCollectorDescFieldIndex("userspaceEventStreamProducerFramesTotal"),
	xpfCollectorDescFieldIndex("userspaceEventStreamDecodeErrorsTotal"),
	xpfCollectorDescFieldIndex("userspaceEventStreamSequenceGapsTotal"),
	xpfCollectorDescFieldIndex("userspaceEventStreamDataplaneEventsTotal"),
	xpfCollectorDescFieldIndex("userspaceEventStreamDataplaneDropsTotal"),
	xpfCollectorDescFieldIndex("userspaceEventStreamUnknownDropsTotal"),
	xpfCollectorDescFieldIndex("userspaceEventStreamResyncsTotal"),
	xpfCollectorDescFieldIndex("userspaceEventStreamDisconnectsTotal"),
	xpfCollectorDescFieldIndex("userspaceEventStreamResyncSuppressedTotal"),
	xpfCollectorDescFieldIndex("userspaceEventStreamPeerCredRejectionsTotal"),
	xpfCollectorDescFieldIndex("userspaceEventStreamState"),
}

// initColdPathDescriptors (metrics_descriptors_coldpath.go).
var collectorDescColdPath = []int{
	xpfCollectorDescFieldIndex("workerDead"),
	xpfCollectorDescFieldIndex("workerColdPathBucket"),
	xpfCollectorDescFieldIndex("workerColdPathSamples"),
	xpfCollectorDescFieldIndex("workerColdPathSumNS"),
	xpfCollectorDescFieldIndex("workerColdPathAliasSeen"),
	xpfCollectorDescFieldIndex("workerColdPathSamplePhase"),
	xpfCollectorDescFieldIndex("workerColdPathWrapperUnderflow"),
	xpfCollectorDescFieldIndex("workerColdPathWrapperNSBaseline"),
	xpfCollectorDescFieldIndex("workerColdPathNSPerTSCQ32"),
	xpfCollectorDescFieldIndex("workerColdPathClockSource"),
	xpfCollectorDescFieldIndex("workerColdPathSnapshotFailedTotal"),
	xpfCollectorDescFieldIndex("workerColdPathBucketV3"),
	xpfCollectorDescFieldIndex("workerColdPathSamplesV3"),
	xpfCollectorDescFieldIndex("workerColdPathSumNSV3"),
	xpfCollectorDescFieldIndex("workerColdPathBuilderCollisionV3"),
	xpfCollectorDescFieldIndex("workerColdPathOverflowActive"),
	xpfCollectorDescFieldIndex("workerColdPathLayoutVersion"),
	xpfCollectorDescFieldIndex("workerColdPathLayoutUnknownTotal"),
}

// initBindingDescriptors (metrics_descriptors_binding.go).
var collectorDescBinding = []int{
	xpfCollectorDescFieldIndex("bindingActiveFlowCount"),
	xpfCollectorDescFieldIndex("bindingFlowCacheCapacity"),
	xpfCollectorDescFieldIndex("bindingUMEMTotalFrames"),
	xpfCollectorDescFieldIndex("bindingUMEMInflightFrames"),
	xpfCollectorDescFieldIndex("bindingPendingFillFrames"),
	xpfCollectorDescFieldIndex("bindingPendingTXPreparedFrames"),
	xpfCollectorDescFieldIndex("bindingPendingTXLocalFrames"),
	xpfCollectorDescFieldIndex("bindingPendingRecycleFrames"),
	xpfCollectorDescFieldIndex("bindingTXCompletions"),
	xpfCollectorDescFieldIndex("bindingTXCompletionRingAvailable"),
	xpfCollectorDescFieldIndex("bindingTXCompletionRingAvailableMax"),
	xpfCollectorDescFieldIndex("bindingKernelRXRingFull"),
	xpfCollectorDescFieldIndex("bindingVMinThrottles"),
	xpfCollectorDescFieldIndex("bindingVMinThrottleHardCapOverrides"),
	xpfCollectorDescFieldIndex("bindingFragOverlapDropped"),
	xpfCollectorDescFieldIndex("bindingFragOverlapOverflowDropped"),
	xpfCollectorDescFieldIndex("bindingFragOverlapShardFullDropped"),
	xpfCollectorDescFieldIndex("bindingFragOverlapPostNATDropped"),
	xpfCollectorDescFieldIndex("bindingFragOverlapMaxLifetimeEvictions"),
	xpfCollectorDescFieldIndex("bindingSlowPathNoRoutePackets"),
	xpfCollectorDescFieldIndex("bindingSlowPathNextTablePackets"),
	xpfCollectorDescFieldIndex("bindingNextTableUnsupportedDrops"),
	xpfCollectorDescFieldIndex("bindingTableUnavailableDrops"),
	xpfCollectorDescFieldIndex("bindingTableUnavailablePackets"),
	xpfCollectorDescFieldIndex("bindingSlowPathLocalDeliveryPackets"),
	xpfCollectorDescFieldIndex("bindingSlowPathMissingNeighborPackets"),
	xpfCollectorDescFieldIndex("bindingFlowCacheEvictionsArm"),
}

// initFairnessDescriptors (metrics_descriptors_fairness.go).
var collectorDescFairness = []int{
	xpfCollectorDescFieldIndex("cosActiveFlowCount"),
	xpfCollectorDescFieldIndex("fairnessCstruct"),
	xpfCollectorDescFieldIndex("fairnessActiveWorkers"),
	xpfCollectorDescFieldIndex("fairnessActiveFlows"),
	xpfCollectorDescFieldIndex("fairnessMaxWorkerFlowShare"),
	xpfCollectorDescFieldIndex("fairnessCoSCountsTruncated"),
	xpfCollectorDescFieldIndex("fairnessRSSExpectation"),
	xpfCollectorDescFieldIndex("fairnessRSSExpectationValue"),
	xpfCollectorDescFieldIndex("fairnessRSSSkewViolation"),
	xpfCollectorDescFieldIndex("fairnessRSSIndeterminate"),
	xpfCollectorDescFieldIndex("fairnessSaturated"),
	xpfCollectorDescFieldIndex("fairnessObservedCoV"),
	xpfCollectorDescFieldIndex("fairnessStarvedFlows"),
	xpfCollectorDescFieldIndex("fairnessEqualFlowEstimateValid"),
	xpfCollectorDescFieldIndex("fairnessEqualFlowSampledActiveWorkers"),
	xpfCollectorDescFieldIndex("fairnessEqualFlowUnsampledActiveWorkers"),
	xpfCollectorDescFieldIndex("fairnessEqualFlowTargetPerFlowBPS"),
	xpfCollectorDescFieldIndex("fairnessEqualFlowObservedBPS"),
	xpfCollectorDescFieldIndex("fairnessEqualFlowCappedBPS"),
	xpfCollectorDescFieldIndex("fairnessEqualFlowSuppressedBPS"),
	xpfCollectorDescFieldIndex("fairnessEqualFlowThroughputLossRatio"),
	xpfCollectorDescFieldIndex("fairnessEqualFlowWorkerObservedBPS"),
	xpfCollectorDescFieldIndex("fairnessEqualFlowWorkerObservedPerFlowBPS"),
	xpfCollectorDescFieldIndex("fairnessEqualFlowWorkerCapBPS"),
	xpfCollectorDescFieldIndex("fairnessEqualFlowWorkerSuppressedBPS"),
}

// initNeighborDescriptors (metrics_descriptors_neighbor.go).
var collectorDescNeighbor = []int{
	xpfCollectorDescFieldIndex("neighborWarmDropsTotal"),
	xpfCollectorDescFieldIndex("neighborWarmDisconnectedTotal"),
	xpfCollectorDescFieldIndex("negNeighFastFailTotal"),
	xpfCollectorDescFieldIndex("pendingNeighDuplicateDropsTotal"),
	xpfCollectorDescFieldIndex("pendingNeighDecapDropsTotal"),
	xpfCollectorDescFieldIndex("pendingNeighCapacityDropsTotal"),
	xpfCollectorDescFieldIndex("dynamicNeighborLearnCapDropsTotal"),
	xpfCollectorDescFieldIndex("dynamicNeighborPresent"),
	xpfCollectorDescFieldIndex("ndpNaFragRefusedTotal"),
	xpfCollectorDescFieldIndex("ndpNaBadSourceRefusedTotal"),
	xpfCollectorDescFieldIndex("neighborResolverQueueDepth"),
	xpfCollectorDescFieldIndex("neighborResolverEnqueueDropsTotal"),
	xpfCollectorDescFieldIndex("neighborResolverDisconnectedTotal"),
	xpfCollectorDescFieldIndex("neighborResolverGetAttemptsTotal"),
	xpfCollectorDescFieldIndex("neighborResolverGetResolvedTotal"),
	xpfCollectorDescFieldIndex("neighborResolverProbeOnStaleTotal"),
	xpfCollectorDescFieldIndex("neighborResolverGetFailuresTotal"),
	xpfCollectorDescFieldIndex("neighborResolverEpochRejectsTotal"),
	xpfCollectorDescFieldIndex("neighborPendingDwellSeconds"),
	xpfCollectorDescFieldIndex("neighborResolverGetRttSeconds"),
	xpfCollectorDescFieldIndex("neighborPendingTimeoutDropsTotal"),
	xpfCollectorDescFieldIndex("neighborPendingMaxDepth"),
	xpfCollectorDescFieldIndex("neighborResolverGetBackoffAttemptsTotal"),
	xpfCollectorDescFieldIndex("neighborNetlinkEnobufsTotal"),
	xpfCollectorDescFieldIndex("neighborNetlinkRedumpsTotal"),
	xpfCollectorDescFieldIndex("neighborNetlinkRedumpUpsertsTotal"),
	xpfCollectorDescFieldIndex("neighborPendingKeys"),
	xpfCollectorDescFieldIndex("negNeighKeys"),
	xpfCollectorDescFieldIndex("fabricLinkSkippedMalformedTotal"),
	xpfCollectorDescFieldIndex("fabricLinkUnresolvedPeerTotal"),
	xpfCollectorDescFieldIndex("userspaceFabricAmbiguousZoneCount"),
}

// initIpsecSaDescriptors (metrics_descriptors_ipsec_sa.go).
var collectorDescIpsecSa = []int{
	xpfCollectorDescFieldIndex("ipsecSAMissDroppedPacketsTotal"),
	xpfCollectorDescFieldIndex("ipsecSAMissNoSATotal"),
	xpfCollectorDescFieldIndex("ipsecSAMissTruncatedTotal"),
	xpfCollectorDescFieldIndex("ipsecSAMissMalformedIKETotal"),
	xpfCollectorDescFieldIndex("ipsecSAMissKeepaliveTotal"),
	xpfCollectorDescFieldIndex("ipsecSASnapshotStaleDenyTotal"),
	xpfCollectorDescFieldIndex("ipsecSAInsertsTotal"),
	xpfCollectorDescFieldIndex("ipsecSARemovesTotal"),
	xpfCollectorDescFieldIndex("ipsecSAExpiryRemovesTotal"),
	xpfCollectorDescFieldIndex("ipsecSAEvictionsTotal"),
	xpfCollectorDescFieldIndex("ikeExchangeEvictionsTotal"),
	xpfCollectorDescFieldIndex("ikeExchangeEntries"),
	xpfCollectorDescFieldIndex("ipsecSAMultiSourceCollisionsTotal"),
	xpfCollectorDescFieldIndex("ipsecSANetlinkEnobufsTotal"),
	xpfCollectorDescFieldIndex("ipsecSANetlinkRedumpsTotal"),
	xpfCollectorDescFieldIndex("ipsecSANetlinkRedumpUpsertsTotal"),
}

// initWireGuardDescriptors (metrics_descriptors_wireguard.go).
var collectorDescWireGuard = []int{
	xpfCollectorDescFieldIndex("wgHandshakesCompletedTotal"),
	xpfCollectorDescFieldIndex("wgHandshakeInitiationsCreatedTotal"),
	xpfCollectorDescFieldIndex("wgHandshakeInitiationBuildFailuresTotal"),
	xpfCollectorDescFieldIndex("wgHandshakeRxDropsTotal"),
	xpfCollectorDescFieldIndex("wgCookieRepliesTotal"),
	xpfCollectorDescFieldIndex("wgHandshakeRequestsArmedTotal"),
	xpfCollectorDescFieldIndex("wgTransportPacketsTotal"),
	xpfCollectorDescFieldIndex("wgTransportBytesTotal"),
	xpfCollectorDescFieldIndex("wgKeepalivesReceivedTotal"),
	xpfCollectorDescFieldIndex("wgTransportDropsTotal"),
	xpfCollectorDescFieldIndex("wgSendErrorsTotal"),
	xpfCollectorDescFieldIndex("wgSessionConfirmed"),
	xpfCollectorDescFieldIndex("wgLastHandshakeTimeSeconds"),
	xpfCollectorDescFieldIndex("wgRekeysInitiatedTotal"),
	xpfCollectorDescFieldIndex("wgKeepalivesSentTotal"),
	xpfCollectorDescFieldIndex("wgSessionsExpiredTotal"),
	xpfCollectorDescFieldIndex("wgHandshakeAttemptsAbortedTotal"),
	xpfCollectorDescFieldIndex("wgEndpointResolutionsTotal"),
}

// initFlowExportDescriptors (metrics_descriptors_flowexport.go).
var collectorDescFlowExport = []int{
	xpfCollectorDescFieldIndex("flowExportCollectorWriteAttemptsTotal"),
	xpfCollectorDescFieldIndex("flowExportCollectorWriteFailuresTotal"),
	xpfCollectorDescFieldIndex("flowExportCollectorWriteSkippedTotal"),
	xpfCollectorDescFieldIndex("flowExportCollectorHealthy"),
	xpfCollectorDescFieldIndex("flowExportCollectorLastSuccessSeconds"),
	xpfCollectorDescFieldIndex("flowExportCollectorLastFailureSeconds"),
	xpfCollectorDescFieldIndex("flowExportBatchDepth"),
	xpfCollectorDescFieldIndex("flowExportBatchMaxDepth"),
	xpfCollectorDescFieldIndex("flowExportBatchDroppedTotal"),
	xpfCollectorDescFieldIndex("flowExportFlowsExportedTotal"),
	xpfCollectorDescFieldIndex("flowExportPacketsExportedTotal"),
	xpfCollectorDescFieldIndex("routeMaskCacheHits"),
	xpfCollectorDescFieldIndex("routeMaskCacheMisses"),
	xpfCollectorDescFieldIndex("routeMaskCacheFullClears"),
	xpfCollectorDescFieldIndex("routeMaskCacheInflightDrops"),
	xpfCollectorDescFieldIndex("routeMaskCacheLookupErrors"),
	xpfCollectorDescFieldIndex("routeMaskCacheEntries"),
	xpfCollectorDescFieldIndex("flowExportRouteMaskUnresolvedTotal"),
	xpfCollectorDescFieldIndex("flowExportMissingStartTimeTotal"),
	xpfCollectorDescFieldIndex("flowExportClockSkewClampedTotal"),
	xpfCollectorDescFieldIndex("flowExportSamplingEvaluatedTotal"),
	xpfCollectorDescFieldIndex("flowExportSamplingSelectedTotal"),
	xpfCollectorDescFieldIndex("flowExportZoneFilteredTotal"),
}

// initFwdStatusDescriptors (metrics_fwdstatus.go).
var collectorDescFwdStatus = []int{
	xpfCollectorDescFieldIndex("forwardingState"),
	xpfCollectorDescFieldIndex("forwardingHeapUtilization"),
	xpfCollectorDescFieldIndex("forwardingBufferUtilization"),
	xpfCollectorDescFieldIndex("forwardingDaemonCPU"),
	xpfCollectorDescFieldIndex("forwardingWorkerCPU"),
	xpfCollectorDescFieldIndex("forwardingCPUDataStale"),
	xpfCollectorDescFieldIndex("forwardingSamplerErrors"),
}

// initHATakeoverDescriptors13301 (metrics_descriptors_ha_takeover_13301.go).
var collectorDescHATakeover = []int{
	xpfCollectorDescFieldIndex("userspaceHATakeoverReady"),
	xpfCollectorDescFieldIndex("userspaceHATakeoverBlocker"),
	xpfCollectorDescFieldIndex("userspaceSessionSocketRequestsTotal"),
	xpfCollectorDescFieldIndex("userspaceSessionSocketErrorsTotal"),
	xpfCollectorDescFieldIndex("userspaceSessionSocketTimeoutsTotal"),
	xpfCollectorDescFieldIndex("userspaceSyncedImportRefusalsTotal"),
}

// initFlowExportLiveFeedDescriptors (metrics_flowexport_livefeed_16760.go).
var collectorDescFlowExportLiveFeed = []int{
	xpfCollectorDescFieldIndex("flowExportLiveFeedMissesTotal"),
}

// initSNMPServeBudgetDescriptors (metrics_snmp_serve_budget_13309.go).
var collectorDescSNMPServeBudget = []int{
	xpfCollectorDescFieldIndex("snmpRequestsShedTotal"),
	xpfCollectorDescFieldIndex("snmpSourceBucketEvictionsTotal"),
	xpfCollectorDescFieldIndex("snmpTrackedSources"),
}

// initRESTConnDescriptors (metrics_descriptors_rest_conn_16081.go).
var collectorDescRESTConn = []int{
	xpfCollectorDescFieldIndex("restConnRefusalsTotal"),
	xpfCollectorDescFieldIndex("restConnActive"),
}

// initFabricConnDescriptors (metrics_fabric_conn_16478.go).
var collectorDescFabricConn = []int{
	xpfCollectorDescFieldIndex("fabricConnRefusalsTotal"),
	xpfCollectorDescFieldIndex("fabricConnActive"),
}

// initDataplaneSafetyDescriptors (metrics_dataplane_safety_13302.go).
var collectorDescDataplaneSafety = []int{
	xpfCollectorDescFieldIndex("dataplaneObsoleteRegistryAccesses"),
	xpfCollectorDescFieldIndex("dataplaneXDPDetachDebtInterfaces"),
	xpfCollectorDescFieldIndex("dataplaneHostDivergenceMutations"),
	xpfCollectorDescFieldIndex("dataplaneArmUncoveredSurfaces"),
	xpfCollectorDescFieldIndex("dataplaneArmTotalSurfaces"),
	xpfCollectorDescFieldIndex("dataplaneXDPAttachModeSurfaces"),
}
