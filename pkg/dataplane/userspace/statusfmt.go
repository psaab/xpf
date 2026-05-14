package userspace

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultFlowWorkerMapLimit = 128
const flowWorkerMapAllLimit = -1

func localHAForwardingRole(status ProcessStatus) string {
	if len(status.HAGroups) == 0 {
		return ""
	}
	for _, group := range status.HAGroups {
		if group.Active {
			return "active"
		}
	}
	if status.ForwardingArmed {
		return "standby (armed for failover)"
	}
	return "standby"
}

func FormatStatusSummary(status ProcessStatus) string {
	var b strings.Builder
	now := time.Now()
	readyQueues := 0
	armedQueues := 0
	for _, q := range status.Queues {
		if q.Ready {
			readyQueues++
		}
		if q.Armed {
			armedQueues++
		}
	}
	readyBindings := 0
	armedBindings := 0
	boundBindings := 0
	xskBindings := 0
	zeroCopyBindings := 0
	sharedUMEMBindings := 0
	var rxPackets uint64
	var validatedPackets uint64
	var forwardCandidates uint64
	var routeMisses uint64
	var neighborMisses uint64
	var exceptionPackets uint64
	var flowCacheHits uint64
	var flowCacheMisses uint64
	var flowCacheEvictions uint64
	var sessionHits uint64
	var sessionMisses uint64
	var sessionCreates uint64
	var sessionExpires uint64
	var sessionDeltaPending uint64
	var sessionDeltaGenerated uint64
	var sessionDeltaDropped uint64
	var sessionDeltaDrained uint64
	var policyDeniedPackets uint64
	var snatPackets uint64
	var dnatPackets uint64
	var txPackets uint64
	var txBytes uint64
	var txErrors uint64
	var txCompletions uint64
	var kernelRXDropped uint64
	var kernelRXInvalidDescs uint64
	var directTXPackets uint64
	var copyTXPackets uint64
	var inPlaceTXPackets uint64
	var inPlaceVLANPushDescPackets uint64
	var inPlaceVLANPopDescPackets uint64
	var inPlaceVLANPushNoHeadroomPackets uint64
	var inPlaceL2MemmoveFallbackPackets uint64
	var directTXNoFrameFallbackPackets uint64
	var directTXBuildFallbackPackets uint64
	var directTXDisallowedFallbackPackets uint64
	var debugPendingFillFrames uint64
	var debugSpareFillFrames uint64
	var debugFreeTXFrames uint64
	var debugPendingTXPrepared uint64
	var debugPendingTXLocal uint64
	var debugOutstandingTX uint64
	var debugInFlightRecycles uint64
	var slowPathPackets uint64
	var slowPathLocalDeliveryPackets uint64
	var slowPathMissingNeighborPackets uint64
	var slowPathNoRoutePackets uint64
	var slowPathNextTablePackets uint64
	var slowPathForwardBuildPackets uint64
	var slowPathDrops uint64
	for _, binding := range status.Bindings {
		if binding.Ready {
			readyBindings++
		}
		if binding.Armed {
			armedBindings++
		}
		if binding.Bound {
			boundBindings++
		}
		if binding.XSKRegistered {
			xskBindings++
		}
		if binding.ZeroCopy {
			zeroCopyBindings++
		}
		if binding.SharedUMEMMode != "" && binding.SharedUMEMSocketRole != "" && binding.SharedUMEMDisabledReason == "" {
			sharedUMEMBindings++
		}
		rxPackets += binding.RXPackets
		validatedPackets += binding.ValidatedPackets
		forwardCandidates += binding.ForwardCandidatePkts
		routeMisses += binding.RouteMissPackets
		neighborMisses += binding.NeighborMissPackets
		exceptionPackets += binding.ExceptionPackets
		flowCacheHits += binding.FlowCacheHits
		flowCacheMisses += binding.FlowCacheMisses
		flowCacheEvictions += binding.FlowCacheEvictions
		sessionHits += binding.SessionHits
		sessionMisses += binding.SessionMisses
		sessionCreates += binding.SessionCreates
		sessionExpires += binding.SessionExpires
		sessionDeltaPending += binding.SessionDeltaPending
		sessionDeltaGenerated += binding.SessionDeltaGenerated
		sessionDeltaDropped += binding.SessionDeltaDropped
		sessionDeltaDrained += binding.SessionDeltaDrained
		policyDeniedPackets += binding.PolicyDeniedPackets
		snatPackets += binding.SNATPackets
		dnatPackets += binding.DNATPackets
		txPackets += binding.TXPackets
		txBytes += binding.TXBytes
		txErrors += binding.TXErrors
		txCompletions += binding.TXCompletions
		kernelRXDropped += binding.KernelRXDropped
		kernelRXInvalidDescs += binding.KernelRXInvalidDescs
		directTXPackets += binding.DirectTXPackets
		copyTXPackets += binding.CopyTXPackets
		inPlaceTXPackets += binding.InPlaceTXPackets
		inPlaceVLANPushDescPackets += binding.InPlaceVLANPushDescPackets
		inPlaceVLANPopDescPackets += binding.InPlaceVLANPopDescPackets
		inPlaceVLANPushNoHeadroomPackets += binding.InPlaceVLANPushNoHeadroomPackets
		inPlaceL2MemmoveFallbackPackets += binding.InPlaceL2MemmoveFallbackPackets
		directTXNoFrameFallbackPackets += binding.DirectTXNoFrameFallbackPackets
		directTXBuildFallbackPackets += binding.DirectTXBuildFallbackPackets
		directTXDisallowedFallbackPackets += binding.DirectTXDisallowedFallbackPackets
		debugPendingFillFrames += uint64(binding.DebugPendingFillFrames)
		debugSpareFillFrames += uint64(binding.DebugSpareFillFrames)
		debugFreeTXFrames += uint64(binding.DebugFreeTXFrames)
		debugPendingTXPrepared += uint64(binding.DebugPendingTXPrepared)
		debugPendingTXLocal += uint64(binding.DebugPendingTXLocal)
		debugOutstandingTX += uint64(binding.DebugOutstandingTX)
		debugInFlightRecycles += uint64(binding.DebugInFlightRecycles)
		slowPathPackets += binding.SlowPathPackets
		slowPathLocalDeliveryPackets += binding.SlowPathLocalDeliveryPackets
		slowPathMissingNeighborPackets += binding.SlowPathMissingNeighborPackets
		slowPathNoRoutePackets += binding.SlowPathNoRoutePackets
		slowPathNextTablePackets += binding.SlowPathNextTablePackets
		slowPathForwardBuildPackets += binding.SlowPathForwardBuildPackets
		slowPathDrops += binding.SlowPathDrops
	}

	fmt.Fprintln(&b, "Userspace dataplane helper:")
	fmt.Fprintf(&b, "  PID:                       %d\n", status.PID)
	fmt.Fprintf(&b, "  Helper mode:               %s\n", status.HelperMode)
	fmt.Fprintf(&b, "  io_uring active:           %t\n", status.IOUringActive)
	if status.IOUringMode != "" {
		fmt.Fprintf(&b, "  io_uring mode:             %s\n", status.IOUringMode)
	}
	if status.IOUringLastError != "" {
		fmt.Fprintf(&b, "  io_uring last error:       %s\n", status.IOUringLastError)
	}
	fmt.Fprintf(&b, "  Enabled:                   %t\n", status.Enabled)
	fmt.Fprintf(&b, "  Forwarding armed:          %t\n", status.ForwardingArmed)
	fmt.Fprintf(&b, "  Forwarding supported:      %t\n", status.Capabilities.ForwardingSupported)
	if len(status.Capabilities.UnsupportedReasons) > 0 {
		fmt.Fprintf(&b, "  Forwarding blocked by:     %s\n", strings.Join(status.Capabilities.UnsupportedReasons, "; "))
	}
	fmt.Fprintf(&b, "  Workers:                   %d\n", status.Workers)
	fmt.Fprintf(&b, "  Ring entries:              %d\n", status.RingEntries)
	fmt.Fprintf(&b, "  Last snapshot generation:  %d\n", status.LastSnapshotGeneration)
	fmt.Fprintf(&b, "  Last FIB generation:       %d\n", status.LastFIBGeneration)
	if !status.LastSnapshotAt.IsZero() {
		fmt.Fprintf(&b, "  Last snapshot age:         %s\n", formatStatusAge(now.Sub(status.LastSnapshotAt)))
	}
	fmt.Fprintf(&b, "  Interface addresses:       %d\n", status.InterfaceAddresses)
	fmt.Fprintf(&b, "  Neighbor entries:          %d\n", status.NeighborEntries)
	fmt.Fprintf(&b, "  Neighbor generation:       %d\n", status.NeighborGeneration)
	fmt.Fprintf(&b, "  Route entries:             %d\n", status.RouteEntries)
	if len(status.HAGroups) > 0 {
		fmt.Fprintf(&b, "  Local HA forwarding role:  %s\n", localHAForwardingRole(status))
		parts := make([]string, 0, len(status.HAGroups))
		for _, group := range status.HAGroups {
			parts = append(parts, fmt.Sprintf("rg%d active=%t watchdog=%d", group.RGID, group.Active, group.WatchdogTimestamp))
		}
		fmt.Fprintf(&b, "  HA groups:                 %s\n", strings.Join(parts, "; "))
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
		fmt.Fprintf(&b, "  Fabric links:              %s\n", strings.Join(parts, "; "))
	}
	if status.LastResolution != nil {
		fmt.Fprintf(&b, "  Last resolution:           %s", status.LastResolution.Disposition)
		if status.LastResolution.IngressIfindex > 0 {
			fmt.Fprintf(&b, " ingress-ifindex=%d", status.LastResolution.IngressIfindex)
		}
		if status.LastResolution.LocalIfindex > 0 {
			fmt.Fprintf(&b, " local-ifindex=%d", status.LastResolution.LocalIfindex)
		}
		if status.LastResolution.EgressIfindex > 0 {
			fmt.Fprintf(&b, " egress-ifindex=%d", status.LastResolution.EgressIfindex)
		}
		if status.LastResolution.NextHop != "" {
			fmt.Fprintf(&b, " next-hop=%s", status.LastResolution.NextHop)
		}
		if status.LastResolution.NeighborMAC != "" {
			fmt.Fprintf(&b, " mac=%s", status.LastResolution.NeighborMAC)
		}
		if status.LastResolution.SrcIP != "" || status.LastResolution.DstIP != "" {
			fmt.Fprintf(&b, " flow=%s:%d->%s:%d",
				status.LastResolution.SrcIP,
				status.LastResolution.SrcPort,
				status.LastResolution.DstIP,
				status.LastResolution.DstPort,
			)
		}
		if status.LastResolution.FromZone != "" || status.LastResolution.ToZone != "" {
			fmt.Fprintf(&b, " zones=%s->%s", status.LastResolution.FromZone, status.LastResolution.ToZone)
		}
		fmt.Fprintln(&b)
	}
	fmt.Fprintf(&b, "  Bound bindings:            %d/%d\n", boundBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  XSK-registered bindings:   %d/%d\n", xskBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  Zerocopy bindings:         %d/%d\n", zeroCopyBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  Shared UMEM bindings:      %d/%d\n", sharedUMEMBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  Armed queues:              %d/%d\n", armedQueues, len(status.Queues))
	fmt.Fprintf(&b, "  Ready queues:              %d/%d\n", readyQueues, len(status.Queues))
	fmt.Fprintf(&b, "  Armed bindings:            %d/%d\n", armedBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  Ready bindings:            %d/%d\n", readyBindings, len(status.Bindings))
	fmt.Fprintf(&b, "  RX packets:                %d\n", rxPackets)
	fmt.Fprintf(&b, "  Validated packets:         %d\n", validatedPackets)
	fmt.Fprintf(&b, "  Forward candidates:        %d\n", forwardCandidates)
	fmt.Fprintf(&b, "  Route misses:              %d\n", routeMisses)
	fmt.Fprintf(&b, "  Neighbor misses:           %d\n", neighborMisses)
	fmt.Fprintf(&b, "  Exception packets:         %d\n", exceptionPackets)
	fmt.Fprintf(&b, "  Flow cache hits:           %d\n", flowCacheHits)
	fmt.Fprintf(&b, "  Flow cache misses:         %d\n", flowCacheMisses)
	fmt.Fprintf(&b, "  Flow cache evictions:      %d\n", flowCacheEvictions)
	fmt.Fprintf(&b, "  Session hits:              %d\n", sessionHits)
	fmt.Fprintf(&b, "  Session misses:            %d\n", sessionMisses)
	fmt.Fprintf(&b, "  Session creates:           %d\n", sessionCreates)
	fmt.Fprintf(&b, "  Session expires:           %d\n", sessionExpires)
	fmt.Fprintf(&b, "  Session delta pending:     %d\n", sessionDeltaPending)
	fmt.Fprintf(&b, "  Session delta generated:   %d\n", sessionDeltaGenerated)
	fmt.Fprintf(&b, "  Session delta dropped:     %d\n", sessionDeltaDropped)
	fmt.Fprintf(&b, "  Session delta drained:     %d\n", sessionDeltaDrained)
	fmt.Fprintf(&b, "  Policy denied packets:     %d\n", policyDeniedPackets)
	fmt.Fprintf(&b, "  SNAT packets:              %d\n", snatPackets)
	fmt.Fprintf(&b, "  DNAT packets:              %d\n", dnatPackets)
	fmt.Fprintf(&b, "  TX packets:                %d\n", txPackets)
	fmt.Fprintf(&b, "  TX bytes:                  %d\n", txBytes)
	fmt.Fprintf(&b, "  TX errors:                 %d\n", txErrors)
	fmt.Fprintf(&b, "  TX completions:            %d\n", txCompletions)
	fmt.Fprintf(&b, "  Kernel RX dropped:         %d\n", kernelRXDropped)
	fmt.Fprintf(&b, "  Kernel RX invalid descs:   %d\n", kernelRXInvalidDescs)
	fmt.Fprintf(&b, "  Direct TX packets:         %d\n", directTXPackets)
	fmt.Fprintf(&b, "  Copy-path TX packets:      %d\n", copyTXPackets)
	fmt.Fprintf(&b, "  In-place TX packets:       %d\n", inPlaceTXPackets)
	fmt.Fprintf(&b, "  In-place VLAN push desc:   %d\n", inPlaceVLANPushDescPackets)
	fmt.Fprintf(&b, "  In-place VLAN pop desc:    %d\n", inPlaceVLANPopDescPackets)
	fmt.Fprintf(&b, "  In-place VLAN no-headroom: %d\n", inPlaceVLANPushNoHeadroomPackets)
	fmt.Fprintf(&b, "  In-place L2 memmove fb:    %d\n", inPlaceL2MemmoveFallbackPackets)
	fmt.Fprintf(&b, "  Direct TX no-frame fb:     %d\n", directTXNoFrameFallbackPackets)
	fmt.Fprintf(&b, "  Direct TX build-none fb:   %d\n", directTXBuildFallbackPackets)
	fmt.Fprintf(&b, "  Direct TX disallowed fb:   %d\n", directTXDisallowedFallbackPackets)
	fmt.Fprintf(&b, "  Pending fill frames:       %d\n", debugPendingFillFrames)
	fmt.Fprintf(&b, "  Spare fill frames:         %d\n", debugSpareFillFrames)
	fmt.Fprintf(&b, "  Free TX frames:            %d\n", debugFreeTXFrames)
	fmt.Fprintf(&b, "  Pending TX prepared:       %d\n", debugPendingTXPrepared)
	fmt.Fprintf(&b, "  Pending TX local:          %d\n", debugPendingTXLocal)
	fmt.Fprintf(&b, "  Outstanding TX:            %d\n", debugOutstandingTX)
	fmt.Fprintf(&b, "  In-flight recycles:        %d\n", debugInFlightRecycles)
	fmt.Fprintf(&b, "  Slow path local-delivery:  %d\n", slowPathLocalDeliveryPackets)
	fmt.Fprintf(&b, "  Slow path missing-neigh:   %d\n", slowPathMissingNeighborPackets)
	fmt.Fprintf(&b, "  Slow path no-route:        %d\n", slowPathNoRoutePackets)
	fmt.Fprintf(&b, "  Slow path next-table:      %d\n", slowPathNextTablePackets)
	fmt.Fprintf(&b, "  Slow path forward-build:   %d\n", slowPathForwardBuildPackets)
	fmt.Fprintf(&b, "  Slow path active:          %t\n", status.SlowPath.Active)
	if status.SlowPath.DeviceName != "" {
		fmt.Fprintf(&b, "  Slow path device:          %s\n", status.SlowPath.DeviceName)
	}
	if status.SlowPath.Mode != "" {
		fmt.Fprintf(&b, "  Slow path mode:            %s\n", status.SlowPath.Mode)
	}
	fmt.Fprintf(&b, "  Slow path queued:          %d\n", status.SlowPath.QueuedPackets)
	fmt.Fprintf(&b, "  Slow path injected:        %d pkts / %d bytes\n", status.SlowPath.InjectedPackets, status.SlowPath.InjectedBytes)
	fmt.Fprintf(&b, "  Slow path dropped:         %d pkts / %d bytes\n", status.SlowPath.DroppedPackets, status.SlowPath.DroppedBytes)
	fmt.Fprintf(&b, "  Slow path rate-limited:    %d\n", status.SlowPath.RateLimitedPackets)
	fmt.Fprintf(&b, "  Slow path queue-full:      %d\n", status.SlowPath.QueueFullPackets)
	fmt.Fprintf(&b, "  Slow path write errors:    %d\n", status.SlowPath.WriteErrors)
	if status.SlowPath.LastError != "" {
		fmt.Fprintf(&b, "  Slow path last error:      %s\n", status.SlowPath.LastError)
	}
	fmt.Fprintf(&b, "  Slow path per-binding:     %d pkts / %d drops\n", slowPathPackets, slowPathDrops)
	fmt.Fprintf(&b, "  Recent exceptions:         %d\n", len(status.RecentExceptions))
	for i, hb := range status.WorkerHeartbeats {
		if hb.IsZero() {
			fmt.Fprintf(&b, "  Worker %d heartbeat age:    unknown\n", i)
			continue
		}
		fmt.Fprintf(&b, "  Worker %d heartbeat age:    %s\n", i, formatStatusAge(now.Sub(hb)))
	}
	// #869: worker runtime table.  Percentages are cumulative since
	// process start — operators derive live rates with Prometheus
	// counters via rate().
	if len(status.WorkerRuntime) > 0 {
		fmt.Fprintln(&b, "Worker runtime (cumulative since worker start):")
		fmt.Fprintf(&b, "  %-6s %-8s %-8s %-10s %-11s %-8s %-12s %-12s\n",
			"Worker", "TID", "Active%", "SpinIdle%", "BlockIdle%", "CPU%", "WorkLoops", "IdleLoops")
		for _, w := range status.WorkerRuntime {
			// #925 Phase 1: dead workers replace the runtime row with
			// a DEAD marker + the rendered panic payload. Operator
			// must restart the daemon to recover the worker's bindings.
			if w.Dead {
				fmt.Fprintf(&b, "  %-6d %-8d   DEAD - panicked: %s\n",
					w.WorkerID, w.TID, w.PanicMessage)
				continue
			}
			wall := float64(w.WallNS)
			if wall <= 0 {
				fmt.Fprintf(&b, "  %-6d %-8d    -        -          -        -   %-12d %-12d\n",
					w.WorkerID, w.TID, w.WorkLoops, w.IdleLoops)
				continue
			}
			activePct := 100.0 * float64(w.ActiveNS) / wall
			spinPct := 100.0 * float64(w.IdleSpinNS) / wall
			blockPct := 100.0 * float64(w.IdleBlockNS) / wall
			cpuPct := 100.0 * float64(w.ThreadCPUNS) / wall
			fmt.Fprintf(&b, "  %-6d %-8d %-8.1f %-8.1f %-10.1f %-8.1f %-12d %-12d\n",
				w.WorkerID, w.TID, activePct, spinPct, blockPct, cpuPct,
				w.WorkLoops, w.IdleLoops)
		}
	}
	return b.String()
}

func FormatFairnessRSS(status ProcessStatus, expectations []FairnessRSSExpectation) string {
	var b strings.Builder
	rows := CoSFairnessRSSSummaries(status)
	fmt.Fprintln(&b, "Userspace fairness RSS structure:")
	if status.CoSActiveFlowCountsTruncated {
		fmt.Fprintln(&b, "  warning: CoS active-flow snapshot truncated; derived values are partial")
	}
	if len(rows) == 0 {
		fmt.Fprintln(&b, "  none")
	} else {
		fmt.Fprintf(&b, "  %-8s %-7s %-11s %-13s %-10s %-10s\n",
			"Ifindex", "Queue", "ActiveFlows", "ActiveWorkers", "Cstruct", "MaxShare")
		for _, row := range rows {
			maxShare := fmt.Sprintf("%.2f%%", 100.0*row.MaxWorkerFlowShare)
			fmt.Fprintf(&b, "  %-8d %-7d %-11d %-13d %-10.6f %-10s\n",
				row.Ifindex,
				row.QueueID,
				row.ActiveFlows,
				row.ActiveWorkers,
				row.Cstruct,
				maxShare,
			)
		}
	}
	if results := EvaluateFairnessRSSExpectations(status, expectations); len(results) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "RSS expectations:")
		fmt.Fprintf(&b, "  %-8s %-7s %-28s %-6s %-11s %-13s %-10s %s\n",
			"Ifindex", "Queue", "Expectation", "Pass", "ActiveFlows", "ActiveWorkers", "Cstruct", "Reason")
		for _, result := range results {
			fmt.Fprintf(&b, "  %-8d %-7d %-28s %-6t %-11d %-13d %-10.6f %s\n",
				result.Ifindex,
				result.QueueID,
				result.Expectation,
				result.Pass,
				result.ActiveFlows,
				result.ActiveWorkers,
				result.Cstruct,
				result.Reason,
			)
		}
	}
	return b.String()
}

func FormatFlowWorkerMap(status ProcessStatus, limit int) string {
	var b strings.Builder
	rows := append([]FlowWorkerStatus(nil), status.FlowWorkerMap...)
	sort.Slice(rows, func(i, j int) bool { return flowWorkerStatusLess(rows[i], rows[j]) })
	if limit == 0 {
		limit = defaultFlowWorkerMapLimit
	}

	fmt.Fprintln(&b, "Userspace flow-worker map:")
	if status.FlowWorkerMapTruncated {
		fmt.Fprintln(&b, "  warning: helper flow-worker snapshot truncated before daemon formatting")
	}
	if len(rows) == 0 {
		fmt.Fprintln(&b, "  none")
		return b.String()
	}
	if limit > 0 && len(rows) > limit {
		fmt.Fprintf(&b, "  showing first %d of %d rows\n", limit, len(rows))
		rows = rows[:limit]
	}
	fmt.Fprintf(&b, "  %-6s %-6s %-5s %-12s %-7s %-11s %-11s %-7s %-5s %s\n",
		"Worker", "Queue", "Slot", "Interface", "Ifidx", "Ingress", "Egress", "TxIf", "CoS", "Session")
	for _, row := range rows {
		fmt.Fprintf(&b, "  %-6d %-6d %-5d %-12s %-7d %-11d %-11d %-7d %-5s %s",
			row.WorkerID,
			row.QueueID,
			row.Slot,
			orDash(row.Interface),
			row.Ifindex,
			row.IngressIfindex,
			row.EgressIfindex,
			row.TxIfindex,
			formatOptionalUint8(row.CoSQueueID),
			formatFlowTuple(row.SessionKey),
		)
		if wire := formatFlowTuple(row.ForwardWireKey); wire != "-" {
			fmt.Fprintf(&b, " wire=%s", wire)
		}
		if rev := formatFlowTuple(row.ReverseCanonicalKey); rev != "-" {
			fmt.Fprintf(&b, " reverse=%s", rev)
		}
		if row.AgeEpochs > 0 {
			fmt.Fprintf(&b, " age-epochs=%d", row.AgeEpochs)
		}
		if row.DSCPRewrite != nil {
			fmt.Fprintf(&b, " dscp-rewrite=%d", *row.DSCPRewrite)
		}
		if row.ObservedBytes > 0 {
			fmt.Fprintf(&b, " observed-bytes=%d", row.ObservedBytes)
		}
		fmt.Fprintln(&b)
	}
	return b.String()
}

func ParseFlowWorkerMapLimitSpec(spec string) (int, error) {
	fields := strings.Fields(spec)
	switch len(fields) {
	case 0:
		return 0, nil
	case 1:
		field := strings.ToLower(fields[0])
		if field == "all" {
			return flowWorkerMapAllLimit, nil
		}
		if field == "limit" {
			return 0, fmt.Errorf("missing flow-worker map limit after limit")
		}
		if value, ok := strings.CutPrefix(field, "limit="); ok {
			return parsePositiveFlowWorkerMapLimit(value)
		}
		return parsePositiveFlowWorkerMapLimit(field)
	case 2:
		if strings.ToLower(fields[0]) != "limit" {
			return 0, fmt.Errorf("invalid flow-worker map selector %q: expected all or limit <rows>", spec)
		}
		return parsePositiveFlowWorkerMapLimit(fields[1])
	default:
		return 0, fmt.Errorf("invalid flow-worker map selector %q: expected all or limit <rows>", spec)
	}
}

func parsePositiveFlowWorkerMapLimit(value string) (int, error) {
	limit, err := strconv.Atoi(value)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("invalid flow-worker map limit %q: expected a positive integer", value)
	}
	return limit, nil
}

func flowWorkerStatusLess(a, b FlowWorkerStatus) bool {
	if a.WorkerID != b.WorkerID {
		return a.WorkerID < b.WorkerID
	}
	if a.QueueID != b.QueueID {
		return a.QueueID < b.QueueID
	}
	if a.Slot != b.Slot {
		return a.Slot < b.Slot
	}
	return flowTupleLess(a.SessionKey, b.SessionKey)
}

func flowTupleLess(a, b FlowTupleStatus) bool {
	if a.Protocol != b.Protocol {
		return a.Protocol < b.Protocol
	}
	if a.SrcIP != b.SrcIP {
		return a.SrcIP < b.SrcIP
	}
	if a.SrcPort != b.SrcPort {
		return a.SrcPort < b.SrcPort
	}
	if a.DstIP != b.DstIP {
		return a.DstIP < b.DstIP
	}
	return a.DstPort < b.DstPort
}

func FormatBindings(status ProcessStatus) string {
	var b strings.Builder

	fmt.Fprintln(&b, "Userspace queues:")
	if len(status.Queues) == 0 {
		fmt.Fprintln(&b, "  none")
	} else {
		fmt.Fprintf(&b, "  %-7s %-8s %-10s %-7s %-7s %s\n", "Queue", "Worker", "Registered", "Armed", "Ready", "Interfaces")
		for _, q := range status.Queues {
			fmt.Fprintf(&b, "  %-7d %-8d %-10t %-7t %-7t %s\n",
				q.QueueID, q.WorkerID, q.Registered, q.Armed, q.Ready, strings.Join(q.Interfaces, ","))
		}
	}
	fmt.Fprintln(&b)

	if len(status.Fabrics) > 0 {
		fmt.Fprintln(&b, "Userspace fabric links:")
		fmt.Fprintf(&b, "  %-8s %-16s %-8s %-16s %-8s %-7s %s\n", "Name", "Parent", "PIfidx", "Overlay", "OIfidx", "Queues", "Peer")
		for _, fabric := range status.Fabrics {
			fmt.Fprintf(&b, "  %-8s %-16s %-8d %-16s %-8d %-7d %s\n",
				fabric.Name,
				fabric.ParentLinuxName,
				fabric.ParentIfindex,
				fabric.OverlayLinux,
				fabric.OverlayIfindex,
				fabric.RXQueues,
				fabric.PeerAddress,
			)
		}
		fmt.Fprintln(&b)
	}

	fmt.Fprintln(&b, "Userspace bindings:")
	if len(status.Bindings) == 0 {
		fmt.Fprintln(&b, "  none")
		return b.String()
	}
	fmt.Fprintf(&b, "  %-6s %-7s %-8s %-10s %-7s %-7s %-7s %-5s %-8s %-8s %-9s %-9s %-8s %-8s %-8s %-9s %-9s %-9s %-9s %s\n", "Slot", "Queue", "Worker", "Registered", "Armed", "Ready", "Bound", "XSK", "Mode", "Ifindex", "RXPkts", "TXPkts", "DirTx", "CopyTx", "InPlTx", "SessHit", "SlowPkts", "ExcPkts", "RtMiss", "Interface")
	for _, binding := range status.Bindings {
		mode := binding.XSKBindMode
		if mode == "" {
			mode = "-"
		}
		fmt.Fprintf(&b, "  %-6d %-7d %-8d %-10t %-7t %-7t %-7t %-5t %-8s %-8d %-9d %-9d %-8d %-8d %-8d %-9d %-9d %-9d %-9d %s",
			binding.Slot, binding.QueueID, binding.WorkerID, binding.Registered, binding.Armed, binding.Ready, binding.Bound, binding.XSKRegistered, mode, binding.Ifindex, binding.RXPackets, binding.TXPackets, binding.DirectTXPackets, binding.CopyTXPackets, binding.InPlaceTXPackets, binding.SessionHits, binding.SlowPathPackets, binding.ExceptionPackets, binding.RouteMissPackets, binding.Interface)
		if binding.SharedUMEMMode != "" {
			fmt.Fprintf(&b, " shared=%s", binding.SharedUMEMMode)
		}
		if binding.SharedUMEMSocketRole != "" {
			fmt.Fprintf(&b, " role=%s", binding.SharedUMEMSocketRole)
		}
		if binding.SharedUMEMGroup != "" {
			fmt.Fprintf(&b, " group=%s", binding.SharedUMEMGroup)
		}
		if binding.SharedUMEMDisabledReason != "" {
			fmt.Fprintf(&b, " shared-disabled=%q", binding.SharedUMEMDisabledReason)
		}
		if binding.LastError != "" {
			fmt.Fprintf(&b, " (%s)", binding.LastError)
		}
		fmt.Fprintln(&b)
	}
	if len(status.RecentExceptions) == 0 && len(status.RecentSessionDeltas) == 0 {
		return b.String()
	}
	if len(status.RecentExceptions) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Recent userspace exceptions:")
		for _, exc := range status.RecentExceptions {
			fmt.Fprintf(&b, "  %s slot=%d queue=%d if=%s reason=%s len=%d af=%d proto=%d",
				exc.Timestamp.Format(time.RFC3339), exc.Slot, exc.QueueID, exc.Interface, exc.Reason, exc.PacketLength, exc.AddrFamily, exc.Protocol)
			if exc.IngressIfindex > 0 {
				fmt.Fprintf(&b, " ingress-ifindex=%d", exc.IngressIfindex)
			}
			if exc.SrcIP != "" || exc.DstIP != "" {
				fmt.Fprintf(&b, " flow=%s:%d->%s:%d", exc.SrcIP, exc.SrcPort, exc.DstIP, exc.DstPort)
			}
			if exc.FromZone != "" || exc.ToZone != "" {
				fmt.Fprintf(&b, " zones=%s->%s", exc.FromZone, exc.ToZone)
			}
			if exc.ConfigGeneration != 0 || exc.FIBGeneration != 0 {
				fmt.Fprintf(&b, " cfg=%d fib=%d", exc.ConfigGeneration, exc.FIBGeneration)
			}
			fmt.Fprintln(&b)
		}
	}
	if len(status.RecentSessionDeltas) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Recent userspace session deltas:")
		for _, delta := range status.RecentSessionDeltas {
			fmt.Fprintf(&b, "  %s slot=%d queue=%d if=%s event=%s af=%d proto=%d flow=%s:%d->%s:%d zones=%s->%s owner-rg=%d disposition=%s origin=%s egress-if=%d",
				delta.Timestamp.Format(time.RFC3339), delta.Slot, delta.QueueID, delta.Interface, delta.Event, delta.AddrFamily, delta.Protocol, delta.SrcIP, delta.SrcPort, delta.DstIP, delta.DstPort, delta.IngressZone, delta.EgressZone, delta.OwnerRGID, delta.Disposition, delta.Origin, delta.EgressIfindex)
			if delta.NextHop != "" {
				fmt.Fprintf(&b, " next-hop=%s", delta.NextHop)
			}
			if delta.NATSrcIP != "" || delta.NATDstIP != "" {
				fmt.Fprintf(&b, " nat=%s->%s", delta.NATSrcIP, delta.NATDstIP)
			}
			fmt.Fprintln(&b)
		}
	}
	return b.String()
}

func formatOptionalUint8(value *uint8) string {
	if value == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *value)
}

func formatFlowTuple(tuple FlowTupleStatus) string {
	if tuple.SrcIP == "" && tuple.DstIP == "" && tuple.SrcPort == 0 && tuple.DstPort == 0 && tuple.Protocol == 0 {
		return "-"
	}
	return fmt.Sprintf("%s %s->%s",
		protocolName(tuple.Protocol),
		formatTupleEndpoint(tuple.SrcIP, tuple.SrcPort),
		formatTupleEndpoint(tuple.DstIP, tuple.DstPort),
	)
}

func formatTupleEndpoint(ip string, port uint16) string {
	if ip == "" {
		ip = "?"
	}
	if port == 0 {
		return ip
	}
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func protocolName(protocol uint8) string {
	switch protocol {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmp6"
	default:
		if protocol == 0 {
			return "proto0"
		}
		return fmt.Sprintf("proto%d", protocol)
	}
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func formatStatusAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return d.Round(time.Second).String()
}
