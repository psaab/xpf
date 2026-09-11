package format

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

const defaultFlowWorkerMapLimit = 128
const flowWorkerMapAllLimit = -1

// SYNCookieCounters aggregates userspace per-binding SYN-cookie status counters.
type SYNCookieCounters struct {
	Challenges        uint64
	SecretUnavailable uint64
	SynAckSent        uint64
	AckRstSent        uint64
	ReplyBudgetDrops  uint64
	AckValid          uint64
	AckInvalid        uint64
	Bypass            uint64
}

// Any reports whether any SYN-cookie counter is non-zero.
func (c SYNCookieCounters) Any() bool {
	return c.Challenges != 0 ||
		c.SecretUnavailable != 0 ||
		c.SynAckSent != 0 ||
		c.AckRstSent != 0 ||
		c.ReplyBudgetDrops != 0 ||
		c.AckValid != 0 ||
		c.AckInvalid != 0 ||
		c.Bypass != 0
}

// SumSYNCookieCounters sums SYN-cookie counters across all bindings in status.
func SumSYNCookieCounters(status userspace.ProcessStatus) SYNCookieCounters {
	var counters SYNCookieCounters
	for _, binding := range status.Bindings {
		counters.Challenges += binding.SYNCookieChallenges
		counters.SecretUnavailable += binding.SYNCookieSecretUnavailable
		counters.SynAckSent += binding.SYNCookieSynAckSent
		counters.AckRstSent += binding.SYNCookieAckRstSent
		counters.ReplyBudgetDrops += binding.SYNCookieReplyBudgetDrops
		counters.AckValid += binding.SYNCookieAckValid
		counters.AckInvalid += binding.SYNCookieAckInvalid
		counters.Bypass += binding.SYNCookieBypass
	}
	return counters
}

// FormatSYNCookieCounterRows renders non-zero userspace SYN-cookie counters
// using the same Counter/Value table shape as show screen statistics.
func FormatSYNCookieCounterRows(counters SYNCookieCounters) string {
	if !counters.Any() {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  %-30s %s\n", "Userspace SYN-cookie scope", "all bindings")
	fmt.Fprintf(&b, "  %-30s %d\n", "SYN-cookie challenges", counters.Challenges)
	fmt.Fprintf(&b, "  %-30s %d\n", "SYN-cookie secret unavailable", counters.SecretUnavailable)
	fmt.Fprintf(&b, "  %-30s %d\n", "SYN-cookie SYN-ACK sent", counters.SynAckSent)
	fmt.Fprintf(&b, "  %-30s %d\n", "SYN-cookie ACK RST sent", counters.AckRstSent)
	fmt.Fprintf(&b, "  %-30s %d\n", "SYN-cookie budget drops", counters.ReplyBudgetDrops)
	fmt.Fprintf(&b, "  %-30s %d\n", "SYN-cookie ACK valid", counters.AckValid)
	fmt.Fprintf(&b, "  %-30s %d\n", "SYN-cookie ACK invalid", counters.AckInvalid)
	fmt.Fprintf(&b, "  %-30s %d\n", "SYN-cookie bypass", counters.Bypass)
	return b.String()
}

func localHAForwardingRole(status userspace.ProcessStatus) string {
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

func formatStatusCounterMap(counters map[string]uint64) string {
	keys := make([]string, 0, len(counters))
	for name := range counters {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, name := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", name, counters[name]))
	}
	return strings.Join(parts, " ")
}

func FormatStatusSummary(status userspace.ProcessStatus) string {
	var b strings.Builder
	now := time.Now()

	// Single pass over queues, bindings, and CoS interfaces; the render
	// helpers below never re-walk the snapshot (see aggregateStatusSummary and
	// the writeXxxSection helpers in status_sections.go).
	agg := aggregateStatusSummary(status)

	writeOverviewSection(&b, status, agg, now)
	writeEventStreamSection(&b, status)
	writeSecurityCountersSection(&b, agg)
	writeNATCountersSection(&b, agg)
	writeSourceNATPoolsSection(&b, status)
	writeTXCoSSummarySection(&b, status, agg)
	writeThreeColorPolicersSection(&b, status)
	writeTXPathCountersSection(&b, agg)
	writeSlowPathSection(&b, status, agg)
	writeWorkerSection(&b, status, now)

	return b.String()
}

func FormatFairnessRSS(status userspace.ProcessStatus, expectations []userspace.FairnessRSSExpectation) string {
	var b strings.Builder
	rows := userspace.CoSFairnessRSSSummaries(status)
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
	if results := userspace.EvaluateFairnessRSSExpectations(status, expectations); len(results) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "RSS expectations:")
		fmt.Fprintf(&b, "  %-12s %-7s %-28s %-13s %-11s %-13s %-10s %s\n",
			"Interface", "Queue", "Expectation", "Result", "ActiveFlows", "ActiveWorkers", "Cstruct", "Reason")
		for _, result := range results {
			// #9369: a tri-state verdict. INDETERMINATE must not read as FAIL (or PASS).
			verdict := "FAIL"
			switch {
			case result.Indeterminate:
				verdict = "INDETERMINATE"
			case result.Pass:
				verdict = "PASS"
			}
			fmt.Fprintf(&b, "  %-12s %-7d %-28s %-13s %-11d %-13d %-10.6f %s\n",
				result.Interface,
				result.QueueID,
				result.Expectation,
				verdict,
				result.ActiveFlows,
				result.ActiveWorkers,
				result.Cstruct,
				result.Reason,
			)
		}
	}
	return b.String()
}

func FormatFlowWorkerMap(status userspace.ProcessStatus, limit int) string {
	var b strings.Builder
	rows := append([]userspace.FlowWorkerStatus(nil), status.FlowWorkerMap...)
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

func flowWorkerStatusLess(a, b userspace.FlowWorkerStatus) bool {
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

func flowTupleLess(a, b userspace.FlowTupleStatus) bool {
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

func FormatBindings(status userspace.ProcessStatus) string {
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
			if exc.RuleName != "" {
				fmt.Fprintf(&b, " rule=%s", exc.RuleName)
			}
			if exc.PoolName != "" {
				fmt.Fprintf(&b, " pool=%s", exc.PoolName)
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

func formatFlowTuple(tuple userspace.FlowTupleStatus) string {
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

// persistentNATPermitMode renders the three-way persistent-NAT permit
// scope for the source-NAT pool status table (#3193). For non-persistent
// pools it returns "-". It prefers the explicit three-way wire mode and
// falls back to the legacy binary any-remote-host flag for an older helper
// that did not set persistent_nat_permit; an empty mode then resolves to
// the target-host-port default.
func persistentNATPermitMode(row userspace.SourceNATPoolStatus) string {
	if !row.PersistentNAT {
		return "-"
	}
	if row.PersistentNATPermit != "" {
		return row.PersistentNATPermit
	}
	if row.PersistentNATPermitAnyRemoteHost {
		return "any-remote-host"
	}
	return "target-host-port"
}
