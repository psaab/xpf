package format

import (
	"fmt"
	"sort"
	"strings"
	"time"

	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// statusSummaryAggregates holds every counter FormatStatusSummary accumulates
// in its single pass over the status snapshot (queues, bindings, CoS queues)
// plus the two derived residuals. Separating the aggregation result from the
// rendering keeps the one-pass guarantee explicit: aggregateStatusSummary is
// the only place that walks status.Bindings, and the writeXxxSection helpers
// render from this struct without re-iterating.
type statusSummaryAggregates struct {
	// Queue tallies.
	readyQueues int
	armedQueues int

	// Binding tallies.
	readyBindings      int
	armedBindings      int
	boundBindings      int
	xskBindings        int
	zeroCopyBindings   int
	sharedUMEMBindings int

	// Per-binding packet/session/flow counters (summed).
	rxPackets         uint64
	validatedPackets  uint64
	forwardCandidates uint64
	// #9956 F-051: flowless-forwarded packets/bytes (the session-uncharged
	// share of forwardCandidates), summed across bindings.
	flowlessForwardPkts  uint64
	flowlessForwardBytes uint64
	routeMisses          uint64
	// #4743: martian-dst NoRoute drops (a sub-breakout of routeMisses) and
	// over-limit IPv6 ext-header fail-closed drops, summed across bindings.
	martianDropped        uint64
	ipv6ExtHeaderDropped  uint64
	neighborMisses        uint64
	exceptionPackets      uint64
	flowCacheHits         uint64
	flowCacheMisses       uint64
	flowCacheEvictions    uint64
	sessionHits           uint64
	sessionMisses         uint64
	sessionCreates        uint64
	sessionExpires        uint64
	sessionDeltaPending   uint64
	sessionDeltaGenerated uint64
	sessionDeltaDropped   uint64
	sessionDeltaDrained   uint64
	policyDeniedPackets   uint64
	screenDrops           uint64

	synCookieChallenges        uint64
	synCookieSecretUnavailable uint64
	synCookieSynAckSent        uint64
	synCookieAckRstSent        uint64
	synCookieReplyBudgetDrops  uint64
	synCookieAckValid          uint64
	synCookieAckInvalid        uint64
	synCookieBypass            uint64

	timeExceededOutputFilterDrops     uint64
	policyRejectOutputFilterDrops     uint64
	filterRejectOutputFilterDrops     uint64
	synCookieOutputFilterDrops        uint64
	ptbOutputFilterDrops              uint64
	generatedReplyClassifyParseErrors uint64
	policyRejectSent                  uint64
	filterRejectSent                  uint64
	policyRejectReplyBudgetDrops      uint64
	filterRejectReplyBudgetDrops      uint64
	policyRejectRateLimitDrops        uint64
	filterRejectRateLimitDrops        uint64

	snatPackets                 uint64
	dnatPackets                 uint64
	nat64Translations           uint64
	nat64NoSourcePool           uint64
	nat64PoolExhausted          uint64
	nat64FragDropped            uint64
	nat64IneligibleSource       uint64
	nat64IneligibleDest         uint64
	nat64ExthdrIneligible       uint64
	nat64TunnelEncapUnsupported uint64
	nat64IneligibleProtocol     uint64
	// #6122: fail-closed ordinary same-family NAT'd non-first-fragment miss
	// drops (SNAT / static-NAT / DNAT / NPTv6). Same-family sibling of
	// nat64FragDropped.
	natFragUntranslatedDropped uint64
	// #10131: binding-attributed fragment-overlap reasons.
	fragOverlapDropped              uint64
	fragOverlapOverflowDropped      uint64
	fragOverlapShardFullDropped     uint64
	fragOverlapPostNATDropped       uint64
	fragOverlapMaxLifetimeEvictions uint64

	txPackets                       uint64
	txBytes                         uint64
	txErrors                        uint64
	bindingLifetimeCoSQueueDrops    uint64
	txSharedRecycleUnknownSlotDrops uint64
	txCompletions                   uint64

	mirroredPackets                 uint64
	mirroredBytes                   uint64
	mirrorDropsNoFrame              uint64
	mirrorDropsTXFrameReserve       uint64
	mirrorDropsNoBinding            uint64
	mirrorDropsQueueFull            uint64
	mirrorDropsQueueFullSameWorker  uint64
	mirrorDropsQueueFullCrossWorker uint64

	kernelRXDropped                   uint64
	kernelRXInvalidDescs              uint64
	directTXPackets                   uint64
	copyTXPackets                     uint64
	inPlaceTXPackets                  uint64
	inPlaceVLANPushDescPackets        uint64
	inPlaceVLANPopDescPackets         uint64
	inPlaceVLANPushNoHeadroomPackets  uint64
	inPlaceL2MemmoveFallbackPackets   uint64
	directTXNoFrameFallbackPackets    uint64
	directTXBuildFallbackPackets      uint64
	directTXDisallowedFallbackPackets uint64

	debugPendingFillFrames uint64
	debugSpareFillFrames   uint64
	debugFreeTXFrames      uint64
	debugPendingTXPrepared uint64
	debugPendingTXLocal    uint64
	debugOutstandingTX     uint64
	debugInFlightRecycles  uint64

	slowPathPackets                uint64
	slowPathLocalDeliveryPackets   uint64
	slowPathMissingNeighborPackets uint64
	slowPathNoRoutePackets         uint64
	slowPathNextTablePackets       uint64
	slowPathForwardBuildPackets    uint64
	slowPathDrops                  uint64

	// CoS queue counters (summed over status.CoSInterfaces).
	currentRuntimeCoSFlowShareDrops uint64
	currentRuntimeCoSBufferDrops    uint64
	cosAdmissionEcnMarked           uint64

	// Derived residuals.
	currentRuntimeCoSAdmissionDrops uint64
	nonAdmissionTXErrors            uint64
}

// aggregateStatusSummary performs the single pass over the status snapshot that
// FormatStatusSummary renders from: one loop over Queues, one loop over
// Bindings, and one loop over CoSInterfaces, followed by the two derived
// residuals. It must not fetch additional status or iterate bindings more than
// once — the whole point of the aggregate/render split is that the render
// helpers never re-walk the snapshot.
func aggregateStatusSummary(status userspace.ProcessStatus) statusSummaryAggregates {
	var agg statusSummaryAggregates
	for _, q := range status.Queues {
		if q.Ready {
			agg.readyQueues++
		}
		if q.Armed {
			agg.armedQueues++
		}
	}
	for _, binding := range status.Bindings {
		if binding.Ready {
			agg.readyBindings++
		}
		if binding.Armed {
			agg.armedBindings++
		}
		if binding.Bound {
			agg.boundBindings++
		}
		if binding.XSKRegistered {
			agg.xskBindings++
		}
		if binding.ZeroCopy {
			agg.zeroCopyBindings++
		}
		if binding.SharedUMEMMode != "" && binding.SharedUMEMSocketRole != "" && binding.SharedUMEMDisabledReason == "" {
			agg.sharedUMEMBindings++
		}
		agg.rxPackets += binding.RXPackets
		agg.validatedPackets += binding.ValidatedPackets
		agg.forwardCandidates += binding.ForwardCandidatePkts
		agg.flowlessForwardPkts += binding.FlowlessForwardPkts
		agg.flowlessForwardBytes += binding.FlowlessForwardBytes
		agg.routeMisses += binding.RouteMissPackets
		agg.martianDropped += binding.MartianDropped
		agg.ipv6ExtHeaderDropped += binding.IPv6ExtHeaderDropped
		agg.neighborMisses += binding.NeighborMissPackets
		agg.exceptionPackets += binding.ExceptionPackets
		agg.flowCacheHits += binding.FlowCacheHits
		agg.flowCacheMisses += binding.FlowCacheMisses
		agg.flowCacheEvictions += binding.FlowCacheEvictions
		agg.sessionHits += binding.SessionHits
		agg.sessionMisses += binding.SessionMisses
		agg.sessionCreates += binding.SessionCreates
		agg.sessionExpires += binding.SessionExpires
		agg.sessionDeltaPending += binding.SessionDeltaPending
		agg.sessionDeltaGenerated += binding.SessionDeltaGenerated
		agg.sessionDeltaDropped += binding.SessionDeltaDropped
		agg.sessionDeltaDrained += binding.SessionDeltaDrained
		agg.policyDeniedPackets += binding.PolicyDeniedPackets
		agg.screenDrops += binding.ScreenDrops
		agg.synCookieChallenges += binding.SYNCookieChallenges
		agg.synCookieSecretUnavailable += binding.SYNCookieSecretUnavailable
		agg.synCookieSynAckSent += binding.SYNCookieSynAckSent
		agg.synCookieAckRstSent += binding.SYNCookieAckRstSent
		agg.synCookieReplyBudgetDrops += binding.SYNCookieReplyBudgetDrops
		agg.synCookieAckValid += binding.SYNCookieAckValid
		agg.synCookieAckInvalid += binding.SYNCookieAckInvalid
		agg.synCookieBypass += binding.SYNCookieBypass
		agg.timeExceededOutputFilterDrops += binding.TimeExceededOutputFilterDrops
		agg.policyRejectOutputFilterDrops += binding.PolicyRejectOutputFilterDrops
		agg.filterRejectOutputFilterDrops += binding.FilterRejectOutputFilterDrops
		agg.synCookieOutputFilterDrops += binding.SYNCookieOutputFilterDrops
		agg.ptbOutputFilterDrops += binding.PTBOutputFilterDrops
		agg.generatedReplyClassifyParseErrors += binding.GeneratedReplyClassifyParseErrors
		agg.policyRejectSent += binding.PolicyRejectSent
		agg.filterRejectSent += binding.FilterRejectSent
		agg.policyRejectReplyBudgetDrops += binding.PolicyRejectReplyBudgetDrops
		agg.filterRejectReplyBudgetDrops += binding.FilterRejectReplyBudgetDrops
		agg.policyRejectRateLimitDrops += binding.PolicyRejectRateLimitDrops
		agg.filterRejectRateLimitDrops += binding.FilterRejectRateLimitDrops
		agg.snatPackets += binding.SNATPackets
		agg.dnatPackets += binding.DNATPackets
		agg.nat64Translations += binding.Nat64Translations
		agg.nat64NoSourcePool += binding.Nat64NoSourcePool
		agg.nat64PoolExhausted += binding.Nat64PoolExhausted
		agg.nat64FragDropped += binding.Nat64FragDropped
		agg.fragOverlapDropped += binding.FragOverlapDropped
		agg.fragOverlapOverflowDropped += binding.FragOverlapOverflowDropped
		agg.fragOverlapShardFullDropped += binding.FragOverlapShardFullDropped
		agg.fragOverlapPostNATDropped += binding.FragOverlapPostNATDropped
		agg.fragOverlapMaxLifetimeEvictions += binding.FragOverlapMaxLifetimeEvictions
		agg.nat64IneligibleSource += binding.Nat64IneligibleSource
		agg.nat64IneligibleDest += binding.Nat64IneligibleDest
		agg.nat64ExthdrIneligible += binding.Nat64ExthdrIneligible
		agg.nat64TunnelEncapUnsupported += binding.Nat64TunnelEncapUnsupported
		agg.nat64IneligibleProtocol += binding.Nat64IneligibleProtocol
		agg.natFragUntranslatedDropped += binding.NatFragUntranslatedDropped
		agg.txPackets += binding.TXPackets
		agg.txBytes += binding.TXBytes
		agg.txErrors += binding.TXErrors
		agg.bindingLifetimeCoSQueueDrops = saturatingAddU64(agg.bindingLifetimeCoSQueueDrops, binding.DbgCoSQueueOverflow)
		agg.txSharedRecycleUnknownSlotDrops += binding.TXSharedRecycleUnknownSlotDrops
		agg.txCompletions += binding.TXCompletions
		agg.mirroredPackets += binding.MirroredPackets
		agg.mirroredBytes += binding.MirroredBytes
		agg.mirrorDropsNoFrame += binding.MirrorDropsNoFrame
		agg.mirrorDropsTXFrameReserve += binding.MirrorDropsTXFrameReserve
		agg.mirrorDropsNoBinding += binding.MirrorDropsNoBinding
		agg.mirrorDropsQueueFull += binding.MirrorDropsQueueFull
		agg.mirrorDropsQueueFullSameWorker += binding.MirrorDropsQueueFullSameWorker
		agg.mirrorDropsQueueFullCrossWorker += binding.MirrorDropsQueueFullCrossWorker
		agg.kernelRXDropped += binding.KernelRXDropped
		agg.kernelRXInvalidDescs += binding.KernelRXInvalidDescs
		agg.directTXPackets += binding.DirectTXPackets
		agg.copyTXPackets += binding.CopyTXPackets
		agg.inPlaceTXPackets += binding.InPlaceTXPackets
		agg.inPlaceVLANPushDescPackets += binding.InPlaceVLANPushDescPackets
		agg.inPlaceVLANPopDescPackets += binding.InPlaceVLANPopDescPackets
		agg.inPlaceVLANPushNoHeadroomPackets += binding.InPlaceVLANPushNoHeadroomPackets
		agg.inPlaceL2MemmoveFallbackPackets += binding.InPlaceL2MemmoveFallbackPackets
		agg.directTXNoFrameFallbackPackets += binding.DirectTXNoFrameFallbackPackets
		agg.directTXBuildFallbackPackets += binding.DirectTXBuildFallbackPackets
		agg.directTXDisallowedFallbackPackets += binding.DirectTXDisallowedFallbackPackets
		agg.debugPendingFillFrames += uint64(binding.DebugPendingFillFrames)
		agg.debugSpareFillFrames += uint64(binding.DebugSpareFillFrames)
		agg.debugFreeTXFrames += uint64(binding.DebugFreeTXFrames)
		agg.debugPendingTXPrepared += uint64(binding.DebugPendingTXPrepared)
		agg.debugPendingTXLocal += uint64(binding.DebugPendingTXLocal)
		agg.debugOutstandingTX += uint64(binding.DebugOutstandingTX)
		agg.debugInFlightRecycles += uint64(binding.DebugInFlightRecycles)
		agg.slowPathPackets += binding.SlowPathPackets
		agg.slowPathLocalDeliveryPackets += binding.SlowPathLocalDeliveryPackets
		agg.slowPathMissingNeighborPackets += binding.SlowPathMissingNeighborPackets
		agg.slowPathNoRoutePackets += binding.SlowPathNoRoutePackets
		agg.slowPathNextTablePackets += binding.SlowPathNextTablePackets
		agg.slowPathForwardBuildPackets += binding.SlowPathForwardBuildPackets
		agg.slowPathDrops += binding.SlowPathDrops
	}
	for _, iface := range status.CoSInterfaces {
		for _, queue := range iface.Queues {
			agg.currentRuntimeCoSFlowShareDrops = saturatingAddU64(agg.currentRuntimeCoSFlowShareDrops, queue.AdmissionFlowShareDrops)
			agg.currentRuntimeCoSBufferDrops = saturatingAddU64(agg.currentRuntimeCoSBufferDrops, queue.AdmissionBufferDrops)
			agg.cosAdmissionEcnMarked = saturatingAddU64(agg.cosAdmissionEcnMarked, queue.AdmissionEcnMarked)
		}
	}
	agg.currentRuntimeCoSAdmissionDrops = saturatingAddU64(agg.currentRuntimeCoSFlowShareDrops, agg.currentRuntimeCoSBufferDrops)
	// The residual must use the binding-lifetime CoS subset counter, not
	// current-runtime queue reason counters; CoS runtimes reset on config
	// changes while userspace.BindingStatus.TXErrors does not.
	agg.nonAdmissionTXErrors = saturatingSubU64(agg.txErrors, agg.bindingLifetimeCoSQueueDrops)
	return agg
}

// writeOverviewSection renders the helper header block: process identity,
// generations, table sizes, HA/fabric/degraded state, last resolution, the
// binding/queue tallies, and the per-binding packet/session/flow counters.
func writeOverviewSection(b *strings.Builder, status userspace.ProcessStatus, agg statusSummaryAggregates, now time.Time) {
	fmt.Fprintln(b, "Userspace dataplane helper:")
	fmt.Fprintf(b, "  PID:                       %d\n", status.PID)
	fmt.Fprintf(b, "  Helper mode:               %s\n", status.HelperMode)
	// #10203: expose the versions of the private static snapshots recorded by
	// the Rust helper. Conditional rendering preserves the old status surface
	// for helpers predating these fields.
	if status.LinkedLibelfVersion != "" || status.LinkedZlibVersion != "" || status.LinkedZstdVersion != "" {
		fmt.Fprintf(b, "  Linked libelf version:     %s\n", status.LinkedLibelfVersion)
		fmt.Fprintf(b, "  Linked zlib version:       %s\n", status.LinkedZlibVersion)
		fmt.Fprintf(b, "  Linked zstd version:       %s\n", status.LinkedZstdVersion)
	}
	fmt.Fprintf(b, "  io_uring active:           %t\n", status.IOUringActive)
	if status.IOUringMode != "" {
		fmt.Fprintf(b, "  io_uring mode:             %s\n", status.IOUringMode)
	}
	if status.IOUringLastError != "" {
		fmt.Fprintf(b, "  io_uring last error:       %s\n", status.IOUringLastError)
	}
	fmt.Fprintf(b, "  Enabled:                   %t\n", status.Enabled)
	fmt.Fprintf(b, "  Forwarding armed:          %t\n", status.ForwardingArmed)
	fmt.Fprintf(b, "  Forwarding supported:      %t\n", status.Capabilities.ForwardingSupported)
	if len(status.Capabilities.UnsupportedReasons) > 0 {
		fmt.Fprintf(b, "  Forwarding blocked by:     %s\n", strings.Join(status.Capabilities.UnsupportedReasons, "; "))
	}
	// #9642: report snapshot retry debt beside the backend classification.
	// This surface is shared by local CLI and gRPC; the mode/enabled lines
	// above keep describing the backend contract untouched.
	if status.SnapshotRetryDebt {
		fmt.Fprintf(b, "  Snapshot retry debt:      generation %d unpublished, ctrl held fail-closed\n", status.SnapshotRetryDebtGeneration)
	}
	fmt.Fprintf(b, "  Workers:                   %d\n", status.Workers)
	fmt.Fprintf(b, "  Ring entries:              %d\n", status.RingEntries)
	fmt.Fprintf(b, "  Last snapshot generation:  %d\n", status.LastSnapshotGeneration)
	fmt.Fprintf(b, "  Last FIB generation:       %d\n", status.LastFIBGeneration)
	if !status.LastSnapshotAt.IsZero() {
		fmt.Fprintf(b, "  Last snapshot age:         %s\n", formatStatusAge(now.Sub(status.LastSnapshotAt)))
	}
	fmt.Fprintf(b, "  Interface addresses:       %d\n", status.InterfaceAddresses)
	fmt.Fprintf(b, "  Neighbor entries:          %d\n", status.NeighborEntries)
	if status.NeighborCacheCapacity > 0 {
		fmt.Fprintf(b, "  Neighbor cache capacity:   %d\n", status.NeighborCacheCapacity)
	}
	if status.MaxSessions > 0 {
		fmt.Fprintf(b, "  Session table entries:     %d/%d\n", status.SessionTableEntries, status.MaxSessions)
	} else if status.SessionTableEntries > 0 {
		fmt.Fprintf(b, "  Session table entries:     %d\n", status.SessionTableEntries)
	}
	if status.FlowCacheCapacity > 0 {
		fmt.Fprintf(b, "  Flow cache capacity:       %d\n", status.FlowCacheCapacity)
	}
	fmt.Fprintf(b, "  Neighbor generation:       %d\n", status.NeighborGeneration)
	fmt.Fprintf(b, "  Route entries:             %d\n", status.RouteEntries)
	if len(status.HAGroups) > 0 {
		fmt.Fprintf(b, "  Local HA forwarding role:  %s\n", localHAForwardingRole(status))
		parts := make([]string, 0, len(status.HAGroups))
		for _, group := range status.HAGroups {
			parts = append(parts, fmt.Sprintf("rg%d active=%t watchdog=%d", group.RGID, group.Active, group.WatchdogTimestamp))
		}
		fmt.Fprintf(b, "  HA groups:                 %s\n", strings.Join(parts, "; "))
	}
	if len(status.Fabrics) > 0 {
		parts := make([]string, 0, len(status.Fabrics))
		for _, fabric := range status.Fabrics {
			part := fabric.Name
			if fabric.ParentLinuxName != "" {
				part += fmt.Sprintf(" parent=%s", fabric.ParentLinuxName)
			}
			if fabric.PeerAddress != "" {
				part += fmt.Sprintf(" peer=%s", fabric.PeerAddress)
			}
			parts = append(parts, part)
		}
		fmt.Fprintf(b, "  Fabric links:              %s\n", strings.Join(parts, "; "))
	}
	if len(status.DegradedPathCounters) > 0 {
		fmt.Fprintf(b, "  Degraded path counters:    %s\n", formatStatusCounterMap(status.DegradedPathCounters))
	}
	if status.LastResolution != nil {
		fmt.Fprintf(b, "  Last resolution:           %s", status.LastResolution.Disposition)
		if status.LastResolution.IngressIfindex > 0 {
			fmt.Fprintf(b, " ingress-ifindex=%d", status.LastResolution.IngressIfindex)
		}
		if status.LastResolution.LocalIfindex > 0 {
			fmt.Fprintf(b, " local-ifindex=%d", status.LastResolution.LocalIfindex)
		}
		if status.LastResolution.EgressIfindex > 0 {
			fmt.Fprintf(b, " egress-ifindex=%d", status.LastResolution.EgressIfindex)
		}
		if status.LastResolution.NextHop != "" {
			fmt.Fprintf(b, " next-hop=%s", status.LastResolution.NextHop)
		}
		if status.LastResolution.NeighborMAC != "" {
			fmt.Fprintf(b, " mac=%s", status.LastResolution.NeighborMAC)
		}
		if status.LastResolution.SrcIP != "" || status.LastResolution.DstIP != "" {
			fmt.Fprintf(b, " flow=%s:%d->%s:%d",
				status.LastResolution.SrcIP,
				status.LastResolution.SrcPort,
				status.LastResolution.DstIP,
				status.LastResolution.DstPort,
			)
		}
		if status.LastResolution.FromZone != "" || status.LastResolution.ToZone != "" {
			fmt.Fprintf(b, " zones=%s->%s", status.LastResolution.FromZone, status.LastResolution.ToZone)
		}
		fmt.Fprintln(b)
	}
	fmt.Fprintf(b, "  Bound bindings:            %d/%d\n", agg.boundBindings, len(status.Bindings))
	fmt.Fprintf(b, "  XSK-registered bindings:   %d/%d\n", agg.xskBindings, len(status.Bindings))
	fmt.Fprintf(b, "  Zerocopy bindings:         %d/%d\n", agg.zeroCopyBindings, len(status.Bindings))
	fmt.Fprintf(b, "  Shared UMEM bindings:      %d/%d\n", agg.sharedUMEMBindings, len(status.Bindings))
	fmt.Fprintf(b, "  Armed queues:              %d/%d\n", agg.armedQueues, len(status.Queues))
	fmt.Fprintf(b, "  Ready queues:              %d/%d\n", agg.readyQueues, len(status.Queues))
	fmt.Fprintf(b, "  Armed bindings:            %d/%d\n", agg.armedBindings, len(status.Bindings))
	fmt.Fprintf(b, "  Ready bindings:            %d/%d\n", agg.readyBindings, len(status.Bindings))
	fmt.Fprintf(b, "  RX packets:                %d\n", agg.rxPackets)
	fmt.Fprintf(b, "  Validated packets:         %d\n", agg.validatedPackets)
	fmt.Fprintf(b, "  Forward candidates:        %d\n", agg.forwardCandidates)
	fmt.Fprintf(b, "  Flowless forwards:         %d pkts / %d bytes\n", agg.flowlessForwardPkts, agg.flowlessForwardBytes)
	fmt.Fprintf(b, "  Route misses:              %d\n", agg.routeMisses)
	fmt.Fprintf(b, "  Martian drops:             %d\n", agg.martianDropped)
	fmt.Fprintf(b, "  IPv6 ext-header drops:     %d\n", agg.ipv6ExtHeaderDropped)
	fmt.Fprintf(b, "  Neighbor misses:           %d\n", agg.neighborMisses)
	fmt.Fprintf(b, "  Exception packets:         %d\n", agg.exceptionPackets)
	fmt.Fprintf(b, "  Flow cache hits:           %d\n", agg.flowCacheHits)
	fmt.Fprintf(b, "  Flow cache misses:         %d\n", agg.flowCacheMisses)
	fmt.Fprintf(b, "  Flow cache evictions:      %d\n", agg.flowCacheEvictions)
	fmt.Fprintf(b, "  Session hits:              %d\n", agg.sessionHits)
	fmt.Fprintf(b, "  Session misses:            %d\n", agg.sessionMisses)
	fmt.Fprintf(b, "  Session creates:           %d\n", agg.sessionCreates)
	fmt.Fprintf(b, "  Session expires:           %d\n", agg.sessionExpires)
	fmt.Fprintf(b, "  Session delta pending:     %d\n", agg.sessionDeltaPending)
	fmt.Fprintf(b, "  Session delta generated:   %d\n", agg.sessionDeltaGenerated)
	fmt.Fprintf(b, "  Session delta dropped:     %d\n", agg.sessionDeltaDropped)
	fmt.Fprintf(b, "  Session delta drained:     %d\n", agg.sessionDeltaDrained)
}

// writeEventStreamSection renders the RT_FLOW event-stream frame/producer/event
// counters, emitted only when the helper published an EventStream block.
func writeEventStreamSection(b *strings.Builder, status userspace.ProcessStatus) {
	if status.EventStream == nil {
		return
	}
	es := status.EventStream
	fmt.Fprintf(b, "  Event stream frames:       read=%d written=%d decode_errors=%d seq_gaps=%d\n",
		es.FramesRead, es.FramesWritten, es.DecodeErrors, es.SeqGaps)
	fmt.Fprintf(b, "  Event stream producer:     sent=%d dropped=%d write_stalls=%d replay_evictions=%d invalid_acks=%d\n",
		status.EventStreamSent, status.EventStreamDropped, status.EventStreamWriteStalls,
		status.EventStreamReplayEvictions, status.EventStreamInvalidAcks)
	// #2512: per-kind helper-side budget accounting for the RT_FLOW
	// SESSION_CLOSE / SESSION_CREATE frames (rate-limiter + queue budget).
	// Distinct from the consumer-side es.SessionClose* counters below
	// (which count what the daemon received): these report what the
	// producer accepted vs. shed under backpressure.
	fmt.Fprintf(b, "  Event stream rt_flow:      session_close[sent=%d dropped=%d] session_create[sent=%d dropped=%d]\n",
		status.EventStreamSessionCloseSent, status.EventStreamSessionCloseDropped,
		status.EventStreamSessionCreateSent, status.EventStreamSessionCreateDropped)
	fmt.Fprintf(b, "  Event stream events:       policy_deny=%d screen_drop=%d screen_alarm=%d filter_log=%d session_close=%d session_create=%d unknown_drops=%d\n",
		es.PolicyDenyEvents, es.ScreenDropEvents, es.ScreenAlarmEvents, es.FilterLogEvents, es.SessionCloseEvents, es.SessionCreateEvents, es.UnknownFrameDrops)
	fmt.Fprintf(b, "  Event stream drops:        policy_deny=%d screen_drop=%d filter_log=%d session_close=%d session_create=%d\n",
		es.PolicyDenyDrops, es.ScreenDropDrops, es.FilterLogDrops, es.SessionCloseDrops, es.SessionCreateDrops)
}

// writeSecurityCountersSection renders the policy/screen drop counters plus the
// SYN-cookie and generated-reply (drops/sent/budget/rate-limit) blocks, each of
// which is omitted when its counters are all zero.
func writeSecurityCountersSection(b *strings.Builder, agg statusSummaryAggregates) {
	fmt.Fprintf(b, "  Policy denied packets:     %d\n", agg.policyDeniedPackets)
	fmt.Fprintf(b, "  Screen drops:              %d\n", agg.screenDrops)
	if agg.synCookieChallenges != 0 || agg.synCookieSecretUnavailable != 0 ||
		agg.synCookieSynAckSent != 0 || agg.synCookieAckRstSent != 0 ||
		agg.synCookieReplyBudgetDrops != 0 || agg.synCookieAckValid != 0 ||
		agg.synCookieAckInvalid != 0 || agg.synCookieBypass != 0 {
		fmt.Fprintf(b, "  SYN-cookie counters:       challenges=%d unavailable=%d syn_ack_sent=%d ack_rst_sent=%d budget_drops=%d ack_valid=%d ack_invalid=%d bypass=%d\n",
			agg.synCookieChallenges, agg.synCookieSecretUnavailable, agg.synCookieSynAckSent,
			agg.synCookieAckRstSent, agg.synCookieReplyBudgetDrops, agg.synCookieAckValid,
			agg.synCookieAckInvalid, agg.synCookieBypass)
	}
	// #2238: locally-generated replies (Time Exceeded, policy-reject
	// RST/ICMP-unreachable, SYN-cookie SYN-ACK/ACK-RST) classified by their
	// own egress tuple — surface output-filter drops + fail-closed
	// parse-error drops when any are non-zero (operator-installed output
	// filters suppressing a generated control frame, RFC-1812 style).
	if agg.timeExceededOutputFilterDrops != 0 || agg.policyRejectOutputFilterDrops != 0 ||
		agg.filterRejectOutputFilterDrops != 0 ||
		agg.synCookieOutputFilterDrops != 0 || agg.ptbOutputFilterDrops != 0 ||
		agg.generatedReplyClassifyParseErrors != 0 {
		// #3615 (L05): policy_reject and filter_reject output-filter drops are
		// reported separately so a firewall-filter `then reject` suppressed by
		// an egress output filter is not conflated with a policy reject.
		fmt.Fprintf(b, "  Generated-reply drops:     time_exceeded=%d policy_reject=%d filter_reject=%d syn_cookie=%d ptb=%d classify_parse_errors=%d\n",
			agg.timeExceededOutputFilterDrops, agg.policyRejectOutputFilterDrops,
			agg.filterRejectOutputFilterDrops,
			agg.synCookieOutputFilterDrops, agg.ptbOutputFilterDrops, agg.generatedReplyClassifyParseErrors)
	}
	// #3657 (H13): active reject SUCCESS volume, split policy vs
	// firewall-filter `then reject` (#3615). As important as the
	// suppression counters for validating vSRX-style reject under load.
	if agg.policyRejectSent != 0 || agg.filterRejectSent != 0 {
		fmt.Fprintf(b, "  Generated-reply sent:      policy_reject=%d filter_reject=%d\n",
			agg.policyRejectSent, agg.filterRejectSent)
	}
	// #3657 (H14): TX-frame reply-budget suppression, split by source. The
	// docs (junos-cli-reference.md) promise budget pressure is counted per
	// source under the generated-reply status — a policy `then reject`
	// silently downgraded to `deny` because the per-tick TX-frame budget was
	// exhausted must be attributable, distinct from an egress output-filter
	// drop (the "Generated-reply drops" line above) and the global reject
	// rate-limit bucket (RejectRateLimitedTotal).
	if agg.policyRejectReplyBudgetDrops != 0 || agg.filterRejectReplyBudgetDrops != 0 {
		fmt.Fprintf(b, "  Generated-reply budget drops: policy_reject=%d filter_reject=%d\n",
			agg.policyRejectReplyBudgetDrops, agg.filterRejectReplyBudgetDrops)
	}
	// #3661 (M02): reject replies dropped because the shared per-reason
	// rate-limit token bucket was empty, split by source. This is distinct
	// from a TX-frame budget drop (the line above) and an egress output-filter
	// drop; the source split tells policy-reject starvation from filter-reject
	// starvation. The source-neutral aggregate is RejectRateLimitedTotal /
	// xpf_userspace_reject_rate_limited_total (Prometheus).
	if agg.policyRejectRateLimitDrops != 0 || agg.filterRejectRateLimitDrops != 0 {
		fmt.Fprintf(b, "  Generated-reply rate-limited: policy_reject=%d filter_reject=%d\n",
			agg.policyRejectRateLimitDrops, agg.filterRejectRateLimitDrops)
	}
}

// writeNATCountersSection renders the SNAT/DNAT/NAT64 summary counters.
func writeNATCountersSection(b *strings.Builder, agg statusSummaryAggregates) {
	fmt.Fprintf(b, "  SNAT packets:              %d\n", agg.snatPackets)
	fmt.Fprintf(b, "  DNAT packets:              %d\n", agg.dnatPackets)
	fmt.Fprintf(b, "  NAT64 translations:        %d\n", agg.nat64Translations)
	fmt.Fprintf(b, "  NAT64 no-source-pool drops:%d\n", agg.nat64NoSourcePool)
	fmt.Fprintf(b, "  NAT64 pool-exhausted drops:%d\n", agg.nat64PoolExhausted)
	fmt.Fprintf(b, "  NAT64 fragment drops:      %d\n", agg.nat64FragDropped)
	fmt.Fprintf(b, "  NAT64 ineligible-source drops:%d\n", agg.nat64IneligibleSource)
	fmt.Fprintf(b, "  NAT64 ineligible-destination drops:%d\n", agg.nat64IneligibleDest)
	fmt.Fprintf(b, "  NAT64 ext-header ineligible drops:%d\n", agg.nat64ExthdrIneligible)
	fmt.Fprintf(b, "  NAT64 tunnel encap unsupported drops:%d\n", agg.nat64TunnelEncapUnsupported)
	fmt.Fprintf(b, "  NAT64 ineligible-protocol drops:%d\n", agg.nat64IneligibleProtocol)
	fmt.Fprintf(b, "  NAT frag untranslated drops:%d\n", agg.natFragUntranslatedDropped)
	fmt.Fprintf(b, "  Fragment overlap drops:    %d\n", agg.fragOverlapDropped)
	fmt.Fprintf(b, "  Fragment overlap overflow drops:%d\n", agg.fragOverlapOverflowDropped)
	fmt.Fprintf(b, "  Fragment overlap shard-full drops:%d\n", agg.fragOverlapShardFullDropped)
	fmt.Fprintf(b, "  Fragment overlap post-NAT drops:%d\n", agg.fragOverlapPostNATDropped)
	fmt.Fprintf(b, "  Fragment overlap max-lifetime evictions:%d\n", agg.fragOverlapMaxLifetimeEvictions)
}

// writeSourceNATPoolsSection renders the per-pool source-NAT table, sorted by
// pool then rule, when any pools are present.
func writeSourceNATPoolsSection(b *strings.Builder, status userspace.ProcessStatus) {
	if len(status.SourceNATPools) == 0 {
		return
	}
	rows := append([]userspace.SourceNATPoolStatus(nil), status.SourceNATPools...)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].PoolName != rows[j].PoolName {
			return rows[i].PoolName < rows[j].PoolName
		}
		return rows[i].RuleName < rows[j].RuleName
	})
	fmt.Fprintln(b, "Source NAT pools:")
	fmt.Fprintf(b, "  %-20s %-20s %-6s %-16s %-11s %-11s %-10s %-10s %-10s %-10s %-10s\n",
		"Pool", "Rule", "Persist", "Permit", "LiveFlows", "MaxFlows", "UsedPorts", "Leases", "Alloc", "Reuse", "Exhaust")
	for _, row := range rows {
		fmt.Fprintf(b, "  %-20s %-20s %-6t %-16s %-11d %-11d %-10d %-10d %-10d %-10d %-10d\n",
			row.PoolName,
			row.RuleName,
			row.PersistentNAT,
			persistentNATPermitMode(row),
			row.LiveFlows,
			row.MaxTrackedFlows,
			row.UsedPorts,
			row.PersistentLeases,
			row.AllocationsTotal,
			row.ReusesTotal,
			row.ExhaustionTotal,
		)
	}
}

// writeTXCoSSummarySection renders the TX packet/byte/error totals and, when
// CoS interfaces are present, the CoS admission-drop attribution rows.
func writeTXCoSSummarySection(b *strings.Builder, status userspace.ProcessStatus, agg statusSummaryAggregates) {
	fmt.Fprintf(b, "  TX packets:                %d\n", agg.txPackets)
	fmt.Fprintf(b, "  TX bytes:                  %d\n", agg.txBytes)
	fmt.Fprintf(b, "  TX errors:                 %d\n", agg.txErrors)
	if len(status.CoSInterfaces) > 0 {
		fmt.Fprintf(b, "  TX errors non-admission:   %d\n", agg.nonAdmissionTXErrors)
		fmt.Fprintf(b, "  CoS queue drops lifetime:  %d\n", agg.bindingLifetimeCoSQueueDrops)
		fmt.Fprintf(b, "  CoS admission drops:       %d\n", agg.currentRuntimeCoSAdmissionDrops)
		fmt.Fprintf(b, "  CoS flow-share drops:      %d\n", agg.currentRuntimeCoSFlowShareDrops)
		fmt.Fprintf(b, "  CoS buffer drops:          %d\n", agg.currentRuntimeCoSBufferDrops)
		fmt.Fprintf(b, "  CoS ECN marked:            %d\n", agg.cosAdmissionEcnMarked)
	}
}

// writeThreeColorPolicersSection renders the three-color policer table, sorted
// by ID then name, when any policers are present.
func writeThreeColorPolicersSection(b *strings.Builder, status userspace.ProcessStatus) {
	if len(status.ThreeColorPolicerCounters) == 0 {
		return
	}
	rows := append([]userspace.ThreeColorPolicerStatus(nil), status.ThreeColorPolicerCounters...)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ID != rows[j].ID {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].Name < rows[j].Name
	})
	fmt.Fprintln(b, "Three-color policers:")
	fmt.Fprintf(b, "  %-5s %-16s %-11s %-6s %-9s %-9s %-9s %-9s %-10s %-10s %-10s %-10s\n",
		"ID", "Name", "Mode", "Blind", "GreenPkts", "YellowPkts", "RedPkts", "DropPkts", "GreenB", "YellowB", "RedB", "DropB")
	for _, row := range rows {
		fmt.Fprintf(b, "  %-5d %-16s %-11s %-6t %-9d %-9d %-9d %-9d %-10d %-10d %-10d %-10d\n",
			row.ID,
			row.Name,
			row.Mode,
			row.ColorBlind,
			row.GreenPackets,
			row.YellowPackets,
			row.RedPackets,
			row.DropPackets,
			row.GreenBytes,
			row.YellowBytes,
			row.RedBytes,
			row.DropBytes,
		)
	}
}

// writeTXPathCountersSection renders the TX-path detail counters: shared-recycle
// drops, completions, mirroring, kernel RX drops, and the direct/in-place/debug
// frame accounting.
func writeTXPathCountersSection(b *strings.Builder, agg statusSummaryAggregates) {
	fmt.Fprintf(b, "  TX shared recycle unk:     %d\n", agg.txSharedRecycleUnknownSlotDrops)
	fmt.Fprintf(b, "  TX completions:            %d\n", agg.txCompletions)
	fmt.Fprintf(b, "  Mirrored packets:          %d\n", agg.mirroredPackets)
	fmt.Fprintf(b, "  Mirrored bytes:            %d\n", agg.mirroredBytes)
	fmt.Fprintf(b, "  Mirror drops:              no-frame=%d tx-frame-reserve=%d no-binding=%d queue-full=%d same-worker=%d cross-worker=%d\n", agg.mirrorDropsNoFrame, agg.mirrorDropsTXFrameReserve, agg.mirrorDropsNoBinding, agg.mirrorDropsQueueFull, agg.mirrorDropsQueueFullSameWorker, agg.mirrorDropsQueueFullCrossWorker)
	fmt.Fprintf(b, "  Kernel RX dropped:         %d\n", agg.kernelRXDropped)
	fmt.Fprintf(b, "  Kernel RX invalid descs:   %d\n", agg.kernelRXInvalidDescs)
	fmt.Fprintf(b, "  Direct TX packets:         %d\n", agg.directTXPackets)
	fmt.Fprintf(b, "  Copy-path TX packets:      %d\n", agg.copyTXPackets)
	fmt.Fprintf(b, "  In-place TX packets:       %d\n", agg.inPlaceTXPackets)
	fmt.Fprintf(b, "  In-place VLAN push desc:   %d\n", agg.inPlaceVLANPushDescPackets)
	fmt.Fprintf(b, "  In-place VLAN pop desc:    %d\n", agg.inPlaceVLANPopDescPackets)
	fmt.Fprintf(b, "  In-place VLAN no-headroom: %d\n", agg.inPlaceVLANPushNoHeadroomPackets)
	fmt.Fprintf(b, "  In-place L2 memmove fb:    %d\n", agg.inPlaceL2MemmoveFallbackPackets)
	fmt.Fprintf(b, "  Direct TX no-frame fb:     %d\n", agg.directTXNoFrameFallbackPackets)
	fmt.Fprintf(b, "  Direct TX build-none fb:   %d\n", agg.directTXBuildFallbackPackets)
	fmt.Fprintf(b, "  Direct TX disallowed fb:   %d\n", agg.directTXDisallowedFallbackPackets)
	fmt.Fprintf(b, "  Pending fill frames:       %d\n", agg.debugPendingFillFrames)
	fmt.Fprintf(b, "  Spare fill frames:         %d\n", agg.debugSpareFillFrames)
	fmt.Fprintf(b, "  Free TX frames:            %d\n", agg.debugFreeTXFrames)
	fmt.Fprintf(b, "  Pending TX prepared:       %d\n", agg.debugPendingTXPrepared)
	fmt.Fprintf(b, "  Pending TX local:          %d\n", agg.debugPendingTXLocal)
	fmt.Fprintf(b, "  Outstanding TX:            %d\n", agg.debugOutstandingTX)
	fmt.Fprintf(b, "  In-flight recycles:        %d\n", agg.debugInFlightRecycles)
}

// writeSlowPathSection renders the slow-path (host reinjection) counters and
// state, mixing per-binding aggregates with the SlowPath snapshot fields.
func writeSlowPathSection(b *strings.Builder, status userspace.ProcessStatus, agg statusSummaryAggregates) {
	fmt.Fprintf(b, "  Slow path local-delivery:  %d\n", agg.slowPathLocalDeliveryPackets)
	fmt.Fprintf(b, "  Slow path missing-neigh:   %d\n", agg.slowPathMissingNeighborPackets)
	fmt.Fprintf(b, "  Slow path no-route:        %d\n", agg.slowPathNoRoutePackets)
	fmt.Fprintf(b, "  Slow path next-table:      %d\n", agg.slowPathNextTablePackets)
	fmt.Fprintf(b, "  Slow path forward-build:   %d\n", agg.slowPathForwardBuildPackets)
	fmt.Fprintf(b, "  Slow path active:          %t\n", status.SlowPath.Active)
	// #2471: surface the degraded MTU state so an operator is not misled by a
	// bare "active: true" while jumbo reinjection is being dropped.
	if status.SlowPath.Degraded {
		fmt.Fprintf(b, "  Slow path DEGRADED:        true (live MTU %d < configured; jumbo frames refused)\n", status.SlowPath.LiveMTU)
	}
	if status.SlowPath.LiveMTU != 0 {
		fmt.Fprintf(b, "  Slow path live MTU:        %d\n", status.SlowPath.LiveMTU)
	}
	if status.SlowPath.DeviceName != "" {
		fmt.Fprintf(b, "  Slow path device:          %s\n", status.SlowPath.DeviceName)
	}
	if status.SlowPath.Mode != "" {
		fmt.Fprintf(b, "  Slow path mode:            %s\n", status.SlowPath.Mode)
	}
	fmt.Fprintf(b, "  Slow path queued:          %d\n", status.SlowPath.QueuedPackets)
	fmt.Fprintf(b, "  Slow path injected:        %d pkts / %d bytes\n", status.SlowPath.InjectedPackets, status.SlowPath.InjectedBytes)
	fmt.Fprintf(b, "  Slow path dropped:         %d pkts / %d bytes\n", status.SlowPath.DroppedPackets, status.SlowPath.DroppedBytes)
	fmt.Fprintf(b, "  Slow path rate-limited:    %d\n", status.SlowPath.RateLimitedPackets)
	fmt.Fprintf(b, "  Slow path queue-full:      %d\n", status.SlowPath.QueueFullPackets)
	fmt.Fprintf(b, "  Slow path MTU-exceeded:    %d\n", status.SlowPath.MTUDroppedPackets)
	fmt.Fprintf(b, "  Slow path write errors:    %d\n", status.SlowPath.WriteErrors)
	if status.SlowPath.LastError != "" {
		fmt.Fprintf(b, "  Slow path last error:      %s\n", status.SlowPath.LastError)
	}
	fmt.Fprintf(b, "  Slow path per-binding:     %d pkts / %d drops\n", agg.slowPathPackets, agg.slowPathDrops)
	// #10069: expose the delegated outlet beside the trusted outlet. It has
	// independent MTU/degraded/counter state and must not be inferred from the
	// trusted outlet when the dual-outlet paths diverge.
	fmt.Fprintf(b, "  Slow path delegated active: %t\n", status.SlowPathDelegated.Active)
	if status.SlowPathDelegated.Degraded {
		fmt.Fprintf(b, "  Slow path delegated DEGRADED: true (live MTU %d < configured; jumbo frames refused)\n", status.SlowPathDelegated.LiveMTU)
	}
	if status.SlowPathDelegated.LiveMTU != 0 {
		fmt.Fprintf(b, "  Slow path delegated live MTU: %d\n", status.SlowPathDelegated.LiveMTU)
	}
	if status.SlowPathDelegated.DeviceName != "" {
		fmt.Fprintf(b, "  Slow path delegated device: %s\n", status.SlowPathDelegated.DeviceName)
	}
	if status.SlowPathDelegated.Mode != "" {
		fmt.Fprintf(b, "  Slow path delegated mode: %s\n", status.SlowPathDelegated.Mode)
	}
	fmt.Fprintf(b, "  Slow path delegated queued: %d\n", status.SlowPathDelegated.QueuedPackets)
	fmt.Fprintf(b, "  Slow path delegated injected: %d pkts / %d bytes\n", status.SlowPathDelegated.InjectedPackets, status.SlowPathDelegated.InjectedBytes)
	fmt.Fprintf(b, "  Slow path delegated dropped: %d pkts / %d bytes\n", status.SlowPathDelegated.DroppedPackets, status.SlowPathDelegated.DroppedBytes)
	fmt.Fprintf(b, "  Slow path delegated rate-limited: %d\n", status.SlowPathDelegated.RateLimitedPackets)
	fmt.Fprintf(b, "  Slow path delegated queue-full: %d\n", status.SlowPathDelegated.QueueFullPackets)
	fmt.Fprintf(b, "  Slow path delegated MTU-exceeded: %d\n", status.SlowPathDelegated.MTUDroppedPackets)
	fmt.Fprintf(b, "  Slow path delegated write errors: %d\n", status.SlowPathDelegated.WriteErrors)
	if status.SlowPathDelegated.LastError != "" {
		fmt.Fprintf(b, "  Slow path delegated last error: %s\n", status.SlowPathDelegated.LastError)
	}
}

// writeWorkerSection renders the recent-exception count, per-worker heartbeat
// ages, and the worker runtime table (#869).
func writeWorkerSection(b *strings.Builder, status userspace.ProcessStatus, now time.Time) {
	fmt.Fprintf(b, "  Recent exceptions:         %d\n", len(status.RecentExceptions))
	for i, hb := range status.WorkerHeartbeats {
		if hb.IsZero() {
			fmt.Fprintf(b, "  Worker %d heartbeat age:    unknown\n", i)
			continue
		}
		fmt.Fprintf(b, "  Worker %d heartbeat age:    %s\n", i, formatStatusAge(now.Sub(hb)))
	}
	// #869: worker runtime table. Cumulative columns are since worker
	// start; the trailing CPU%60s column is a rolling ~60s window
	// (under the normal ~1 Hz worker publish cadence the rotated
	// window is ~60-61s wide; a stalled publisher widens it, but the
	// % is divided by the exact WindowNS the worker measured so the
	// displayed rate stays honest) for live operator load visibility
	// — operators no longer have to mentally subtract two
	// cumulative-since-boot CPU samples to see "current load". The
	// matching Prometheus gauge is
	// xpf_userspace_worker_thread_cpu_seconds_last_60s.
	if len(status.WorkerRuntime) > 0 {
		fmt.Fprintln(b, "Worker runtime (cumulative since worker start; last column is rolling ~60s CPU window):")
		fmt.Fprintf(b, "  %-6s %-8s %-8s %-10s %-11s %-8s %-8s %-12s %-12s\n",
			"Worker", "TID", "Active%", "SpinIdle%", "BlockIdle%", "CPU%", "CPU%60s", "WorkLoops", "IdleLoops")
		for _, w := range status.WorkerRuntime {
			// #925 Phase 1: dead workers replace the runtime row with
			// a DEAD marker + the rendered panic payload. Operator
			// must restart the daemon to recover the worker's bindings.
			if w.Dead {
				fmt.Fprintf(b, "  %-6d %-8d   DEAD - panicked: %s\n",
					w.WorkerID, w.TID, w.PanicMessage)
				continue
			}
			wall := float64(w.WallNS)
			if wall <= 0 {
				fmt.Fprintf(b, "  %-6d %-8d    -        -          -        -        -    %-12d %-12d\n",
					w.WorkerID, w.TID, w.WorkLoops, w.IdleLoops)
				continue
			}
			activePct := 100.0 * float64(w.ActiveNS) / wall
			spinPct := 100.0 * float64(w.IdleSpinNS) / wall
			blockPct := 100.0 * float64(w.IdleBlockNS) / wall
			cpuPct := 100.0 * float64(w.ThreadCPUNS) / wall
			cpu60sStr := "-"
			if w.WindowNS > 0 {
				cpu60sStr = fmt.Sprintf("%.1f", 100.0*float64(w.ThreadCPUNS60s)/float64(w.WindowNS))
			}
			fmt.Fprintf(b, "  %-6d %-8d %-8.1f %-8.1f %-10.1f %-8.1f %-8s %-12d %-12d\n",
				w.WorkerID, w.TID, activePct, spinPct, blockPct, cpuPct, cpu60sStr,
				w.WorkLoops, w.IdleLoops)
		}
	}
}
