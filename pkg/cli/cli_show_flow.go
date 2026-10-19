package cli

import (
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// topTalkerEntry holds a session's display info for sorting.
type topTalkerEntry struct {
	src, dst, proto, zone, state, app string
	fwdPkts, revPkts                  uint64
	fwdBytes, revBytes                uint64
	age                               uint64
}

type sessionBriefRow struct {
	ID          uint64
	Source      string
	Destination string
	Proto       string
	Zone        string
	NAT         string
	State       string
	Age         uint64
	FwdPackets  uint64
	RevPackets  uint64
}

func newSessionBriefRow(id uint64, srcAddr string, srcPort uint16, dstAddr string, dstPort uint16, proto, inZone, outZone, nat, state string, age, fwdPackets, revPackets uint64) sessionBriefRow {
	return sessionBriefRow{
		ID:          id,
		Source:      formatSessionBriefEndpoint(srcAddr, srcPort),
		Destination: formatSessionBriefEndpoint(dstAddr, dstPort),
		Proto:       proto,
		Zone:        inZone + "->" + outZone,
		NAT:         nat,
		State:       state,
		Age:         age,
		FwdPackets:  fwdPackets,
		RevPackets:  revPackets,
	}
}

// sessionBriefWriter streams fixed-width brief rows straight to the
// underlying writer. #14989 (D37-04): the previous text/tabwriter buffered
// the ENTIRE table until Flush, so `show security flow session brief` over
// a full session table heap-buffered every row before any byte reached the
// terminal/pager. A fixed layout (mirroring cmd/cli and showTopTalkers)
// needs no whole-table pass: header and each row are emitted as printed.
// Column widths match cmd/cli printSessionEntries; longer values overflow
// their field without truncation (Go %-Ns semantics), preserving the
// long-value guarantee TestSessionBriefWriterPreservesLongValues pins.
type sessionBriefWriter struct{ w io.Writer }

func newSessionBriefWriter(w io.Writer) *sessionBriefWriter {
	return &sessionBriefWriter{w: w}
}

func (s *sessionBriefWriter) Write(p []byte) (int, error) { return s.w.Write(p) }

// flushSessionBriefWriter is a no-op for the streaming writer (kept so call
// sites retain an explicit end-of-table point); rows are already emitted.
func flushSessionBriefWriter(w *sessionBriefWriter) {
	_ = w
}

func printSessionBriefHeader(w io.Writer) {
	fmt.Fprintf(w, "%-5s %-22s %-22s %-5s %-20s %-3s %-5s %5s %s\n",
		"ID", "Source", "Destination", "Proto", "Zone", "NAT", "State", "Age", "Pkts(f/r)")
}

func printSessionBriefRow(w io.Writer, row sessionBriefRow) {
	fmt.Fprintf(w, "%-5d %-22s %-22s %-5s %-20s %-3s %-5s %5d %d/%d\n",
		row.ID,
		row.Source,
		row.Destination,
		row.Proto,
		row.Zone,
		row.NAT,
		row.State,
		row.Age,
		row.FwdPackets,
		row.RevPackets)
}

func formatSessionBriefEndpoint(addr string, port uint16) string {
	if addr == "" {
		return "-"
	}
	ip := net.ParseIP(addr)
	if ip != nil && ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

// flowSessionDisplayID resolves the id shown for a `show security flow session`
// row. #5213: it renders the STABLE dataplane session id
// (dataplane.SessionValue.SessionID, which the userspace-dp conntrack mirror now
// stamps from SessionEntry.session_id, #4915) so the value is IDENTICAL to the
// id RT_FLOW emits (SESSION_CREATE/CLOSE) for the same session — an operator can
// correlate a flow across the two surfaces by id. It falls back to the per-row
// ordinal ONLY when the dataplane id is 0 (absent/unknown: an older helper that
// never stamped the id, or a synthesized row), preserving the legacy display and
// never showing a bare 0.
func flowSessionDisplayID(dpSessionID uint64, ordinalIdx int) uint64 {
	if dpSessionID != 0 {
		return dpSessionID
	}
	return uint64(ordinalIdx)
}

func (c *CLI) showStatistics(detail bool) error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Statistics: dataplane not loaded")
		return nil
	}

	// #3345: surface a counter-read failure rather than printing clean zeros
	// that hide a degraded counter bridge. This is the canonical operator
	// global-counter view (`show security flow statistics`).
	var readErr error
	readCounter := func(idx uint32) uint64 {
		v, err := c.dp.ReadGlobalCounter(idx)
		if err != nil && readErr == nil {
			readErr = err
		}
		return v
	}

	names := []struct {
		idx  uint32
		name string
	}{
		{dataplane.GlobalCtrRxPackets, "RX packets"},
		{dataplane.GlobalCtrTxPackets, "TX packets"},
		{dataplane.GlobalCtrDrops, "Drops"},
		{dataplane.GlobalCtrUnknownVLANDrops, "Unknown VLAN drops"},
		{dataplane.GlobalCtrDstMACDrops, "Destination MAC drops"},
		{dataplane.GlobalCtrSessionsNew, "Sessions created"},
		{dataplane.GlobalCtrSessionsClosed, "Sessions closed"},
		{dataplane.GlobalCtrScreenDrops, "Screen drops"},
		{dataplane.GlobalCtrPolicyDeny, "Policy denies"},
		{dataplane.GlobalCtrNATAllocFail, "NAT alloc failures"},
		{dataplane.GlobalCtrHostInboundDeny, "Host-inbound denies"},
		{dataplane.GlobalCtrHostInbound, "Host-inbound allowed"},
		{dataplane.GlobalCtrTCEgressPackets, "TC egress packets"},
		{dataplane.GlobalCtrNAT64Xlate, "NAT64 translations"},
	}

	fmt.Println("Global statistics:")
	for _, n := range names {
		fmt.Printf("  %-25s %d\n", n.name+":", readCounter(n.idx))
	}

	if !detail {
		// #3345: even in the non-detail path, surface a read failure (the
		// global loop above is the only read set here).
		if readErr != nil {
			fmt.Printf("warning: global counter read failed (statistics may be incomplete): %v\n", readErr)
		}
		return nil
	}

	// Active session counts
	v4, v6 := c.dp.SessionCount()
	fmt.Printf("\nActive sessions:\n")
	fmt.Printf("  %-25s %d\n", "IPv4 sessions:", v4)
	fmt.Printf("  %-25s %d\n", "IPv6 sessions:", v6)
	fmt.Printf("  %-25s %d\n", "Total:", v4+v6)

	// Screen drops breakdown
	screenDrops := readCounter(dataplane.GlobalCtrScreenDrops)
	if screenDrops > 0 {
		fmt.Printf("\nScreen drop details:\n")
		// #3343: shared screen-reason table — adds the previously-omitted
		// session-limit row and keeps every surface on the same reason set.
		for i := range dataplane.ScreenReasonCounters {
			rc := &dataplane.ScreenReasonCounters[i]
			v := readCounter(rc.Index)
			if v > 0 {
				fmt.Printf("  %-25s %d\n", rc.Label+":", v)
			}
		}
	}

	// Map utilization summary for key maps
	fmt.Printf("\nKey map utilization:\n")
	stats := c.dp.GetMapStats()
	for _, s := range stats {
		if s.MaxEntries > 0 && s.Type != "Array" && s.Type != "PerCPUArray" {
			pct := float64(s.UsedCount) / float64(s.MaxEntries) * 100
			flag := ""
			if pct >= 80 {
				flag = " !"
			}
			fmt.Printf("  %-24s %d/%d (%.1f%%)%s\n", s.Name+":", s.UsedCount, s.MaxEntries, pct, flag)
		}
	}

	// #3345: check AFTER all global-counter reads (incl. the detail screen
	// breakdown) so a failure on a late read is surfaced rather than printing
	// a stale 0.
	if readErr != nil {
		fmt.Printf("warning: global counter read failed (statistics may be incomplete): %v\n", readErr)
	}

	return nil
}

func (c *CLI) showFlowSession(args []string) error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Session table: dataplane not loaded")
		return nil
	}

	f := c.parseSessionFilter(args)
	if err := f.validate(); err != nil {
		return err
	}

	// Top-talkers mode: collect, sort, display top 20
	if f.sortBy == "bytes" || f.sortBy == "packets" {
		return c.showTopTalkers(f)
	}

	count := 0

	// In cluster mode, print node header before local sessions.
	clusterMode := c.cluster != nil
	// Cluster node IDs are 0 and 1; derive the peer label locally so it stays
	// valid when heartbeat liveness is down or flapping.
	peerNodeID := -1
	if clusterMode {
		peerNodeID = 1 - c.cluster.NodeID()
	}
	if clusterMode && !f.summary {
		fmt.Printf("node%d:\n", c.cluster.NodeID())
		fmt.Println("--------------------------------------------------------------------------")
	}

	// Summary counters for protocol/zone/NAT breakdown
	var byProto map[uint8]int
	var byZonePair map[string]int
	var v4Count, v6Count, natCount int
	if f.summary {
		byProto = make(map[uint8]int)
		byZonePair = make(map[string]int)
	}

	var briefWriter *sessionBriefWriter
	if f.brief {
		briefWriter = newSessionBriefWriter(os.Stdout)
		printSessionBriefHeader(briefWriter)
	}

	// Build reverse zone ID → name map, policy name map, and zone→interface map
	zoneNames := make(map[uint16]string)
	var policyNames map[uint32]string
	cr := c.applyResult()
	if cr != nil {
		zoneNames = config.SurvivorZoneNames(cr.ZoneIDs, f.cfg)
		policyNames = cr.PolicyNames
	}

	// Populate the interface maps used by BOTH the filter (matchesV4/V6) and
	// the `If:` columns below.
	//
	// #6987: display used to build its own `map[uint16]string` holding each
	// zone's FIRST interface, kept deliberately separate from the filter's
	// widened `map[uint16][]string`. That divergence is what let the column
	// name one interface on behalf of all of its siblings. There is now one
	// map and one rule; where the rule cannot defend a name, the column falls
	// back to the zone rather than picking a member arbitrarily.
	f.populateIfaceMaps(c)

	// #15236 (A52-03): HA state is per-session, derived from the owning
	// data RG of the session's interfaces/zones — not RG0. Unresolvable
	// ownership renders "unknown" instead of an inverted Active/Backup.
	sessionHAState := func(ingressIface, egressIface string, inZoneID, outZoneID uint16) string {
		if !clusterMode {
			return ""
		}
		cfg := f.cfg
		if cfg == nil && c.store != nil {
			cfg = c.store.ActiveConfig()
		}
		return config.SessionHAState(cfg, ingressIface, egressIface, inZoneID, outZoneID, zoneNames, func(rg int) (bool, bool) {
			return c.cluster.LocalGroupPrimary(rg)
		})
	}

	sessionEgressIf := func(fibIfindex uint32, fibVlanID uint16, zoneID uint16, zoneName string) string {
		if ifName := f.egressIfaceDisplay(fibIfindex, fibVlanID, zoneID); ifName != "" {
			return ifName
		}
		return zoneName
	}

	// #4983: resolve the "In: ... If:" column from the session's RECORDED
	// ingress binding, the same datum `sessionFilter.resolveIngressIfaces`
	// selects on. Without this the filter and the column disagree: `show
	// security flow session interface ge-0/0/2` would select the sessions that
	// arrived on ge-0/0/2 and then print `If: ge-0/0/0` for every one of them
	// (the zone's FIRST interface), which reads as a bug in the filter. Same
	// shape as sessionEgressIf above — precise when the identity is carried
	// and nameable, zone-derived otherwise — so the two columns of one row are
	// resolved by one rule.
	//
	// #6987: "zone-derived" is now the zone's SINGLE bound interface or
	// nothing, and a recorded identity the zone does not corroborate is not
	// printed at all. See sessionFilter.ingressIfaceDisplay for why a name the
	// row cannot support is worse here than in the filter.
	//
	// "the sessions that arrived on ge-0/0/2" describes the INGRESS ARM, not
	// the whole selection (#6928 review). `matchesV4`/`matchesV6` OR the two
	// arms — `!ifaceMatchesAny(inIfs) && !ifaceMatchesAny(outIfs)` in
	// session_filter.go — so `interface ge-0/0/2` ALSO selects a session that
	// arrived elsewhere and EGRESSES there. That is deliberate: an operator
	// naming an interface wants the flows crossing it in either direction. It
	// is also why this column can legitimately print a name other than the one
	// filtered on, without the filter and the column having disagreed about
	// the ingress identity.
	sessionIngressIf := func(ingressIfindex uint32, ingressVlanID uint16, zoneID uint16, zoneName string) string {
		if ifName := f.ingressIfaceDisplay(ingressIfindex, ingressVlanID, zoneID); ifName != "" {
			return ifName
		}
		return zoneName
	}

	now := monotonicSeconds()

	// printV4 prints a single IPv4 session entry inline during iteration.
	printV4 := func(idx int, key dataplane.SessionKey, val dataplane.SessionValue) {
		srcIP := net.IP(key.SrcIP[:])
		dstIP := net.IP(key.DstIP[:])
		srcPort := ntohs(key.SrcPort)
		dstPort := ntohs(key.DstPort)
		protoName := protoNameFromNum(key.Protocol)
		stateName := sessionStateName(val.State)

		inZone := zoneNames[val.IngressZone]
		outZone := zoneNames[val.EgressZone]
		if inZone == "" {
			inZone = fmt.Sprintf("%d", val.IngressZone)
		}
		if outZone == "" {
			outZone = fmt.Sprintf("%d", val.EgressZone)
		}

		inZone = f.zoneDisplay(val.IngressZone, inZone)
		outZone = f.zoneDisplay(val.EgressZone, outZone)
		sid := flowSessionDisplayID(val.SessionID, idx)

		if f.brief {
			natFlag := "-"
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				natFlag = "S"
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				natFlag = "D"
			}
			if val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == (dataplane.SessFlagSNAT | dataplane.SessFlagDNAT) {
				natFlag = "B"
			}
			var age uint64
			if now > val.Created {
				age = now - val.Created
			}
			printSessionBriefRow(briefWriter, newSessionBriefRow(
				sid,
				srcIP.String(), srcPort,
				dstIP.String(), dstPort,
				protoName, inZone, outZone, natFlag,
				stateName[:min(5, len(stateName))],
				age, val.FwdPackets, val.RevPackets,
			))
			return
		}

		// #4626: reserved ids (0 = no policy admitted this session,
		// DefaultPolicySentinelID = implicit default) must not be resolved
		// through the compiled map — id 0 IS the first configured policy there.
		polName := dataplane.SessionPolicyName(policyNames, val.PolicyID)
		if polName == "" {
			polName = fmt.Sprintf("%d", val.PolicyID)
		}
		haState := sessionHAState(sessionIngressIf(val.IngressIfindex, val.IngressVlanID, val.IngressZone, inZone), sessionEgressIf(val.FibIfindex, val.FibVlanID, val.EgressZone, outZone), val.IngressZone, val.EgressZone)
		if haState != "" {
			fmt.Printf("Session ID: %d, Policy name: %s/%d, HA State: %s, Timeout: %d, Session State: Unknown (validity not tracked)\n",
				sid, polName, val.PolicyID, haState, val.Timeout)
		} else {
			fmt.Printf("Session ID: %d, Policy name: %s/%d, Timeout: %d, Session State: Unknown (validity not tracked)\n",
				sid, polName, val.PolicyID, val.Timeout)
		}

		inIf := sessionIngressIf(val.IngressIfindex, val.IngressVlanID, val.IngressZone, inZone)
		fmt.Printf("  In: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Zone: %s, Pkts: %d, Bytes: %d,\n",
			srcIP, srcPort, dstIP, dstPort, protoName,
			inIf, inZone, val.FwdPackets, val.FwdBytes)

		outSrcIP := dstIP.String()
		outSrcPort := dstPort
		outDstIP := srcIP.String()
		outDstPort := srcPort
		if val.Flags&dataplane.SessFlagSNAT != 0 {
			natIP := uint32ToIP(val.NATSrcIP)
			natPort := ntohs(val.NATSrcPort)
			outDstIP = natIP.String()
			outDstPort = natPort
		}
		if val.Flags&dataplane.SessFlagDNAT != 0 {
			natIP := uint32ToIP(val.NATDstIP)
			natPort := ntohs(val.NATDstPort)
			outSrcIP = natIP.String()
			outSrcPort = natPort
		}
		outIf := sessionEgressIf(val.FibIfindex, val.FibVlanID, val.EgressZone, outZone)
		fmt.Printf("  Out: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Zone: %s, Pkts: %d, Bytes: %d,\n",
			outSrcIP, outSrcPort, outDstIP, outDstPort, protoName,
			outIf, outZone, val.RevPackets, val.RevBytes)
		if appName := appid.ResolveSessionNameWithIndex(f.appNames, f.cfg, f.appFallback, key.Protocol, srcPort, dstPort, val.AppID); appName != "" {
			fmt.Printf("  Application: %s\n", appName)
		}
		fmt.Println()
	}

	// IPv4 sessions — stream directly, no collect/sort.
	err := c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if f.hasFilter() && !f.matchesV4(key, val) {
			return true
		}
		count++

		if f.summary {
			v4Count++
			byProto[key.Protocol]++
			inZ := zoneNames[val.IngressZone]
			outZ := zoneNames[val.EgressZone]
			if inZ == "" {
				inZ = fmt.Sprintf("zone-%d", val.IngressZone)
			}
			if outZ == "" {
				outZ = fmt.Sprintf("zone-%d", val.EgressZone)
			}
			byZonePair[inZ+"->"+outZ]++
			if val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) != 0 {
				natCount++
			}
			return true
		}

		printV4(count, key, val)
		return true
	})
	if err != nil {
		return fmt.Errorf("iterate sessions: %w", err)
	}

	// printV6 prints a single IPv6 session entry inline during iteration.
	printV6 := func(idx int, key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
		srcIP := net.IP(key.SrcIP[:])
		dstIP := net.IP(key.DstIP[:])
		srcPort := ntohs(key.SrcPort)
		dstPort := ntohs(key.DstPort)
		protoName := protoNameFromNum(key.Protocol)
		stateName := sessionStateName(val.State)

		inZone := zoneNames[val.IngressZone]
		outZone := zoneNames[val.EgressZone]
		if inZone == "" {
			inZone = fmt.Sprintf("%d", val.IngressZone)
		}
		if outZone == "" {
			outZone = fmt.Sprintf("%d", val.EgressZone)
		}

		inZone = f.zoneDisplay(val.IngressZone, inZone)
		outZone = f.zoneDisplay(val.EgressZone, outZone)
		sid := flowSessionDisplayID(val.SessionID, idx)

		if f.brief {
			natFlag := "-"
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				natFlag = "S"
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				natFlag = "D"
			}
			if val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == (dataplane.SessFlagSNAT | dataplane.SessFlagDNAT) {
				natFlag = "B"
			}
			var age uint64
			if now > val.Created {
				age = now - val.Created
			}
			printSessionBriefRow(briefWriter, newSessionBriefRow(
				sid,
				srcIP.String(), srcPort,
				dstIP.String(), dstPort,
				protoName, inZone, outZone, natFlag,
				stateName[:min(5, len(stateName))],
				age, val.FwdPackets, val.RevPackets,
			))
			return
		}

		// #4626: reserved ids (0 = no policy admitted this session,
		// DefaultPolicySentinelID = implicit default) must not be resolved
		// through the compiled map — id 0 IS the first configured policy there.
		polName := dataplane.SessionPolicyName(policyNames, val.PolicyID)
		if polName == "" {
			polName = fmt.Sprintf("%d", val.PolicyID)
		}
		haState := sessionHAState(sessionIngressIf(val.IngressIfindex, val.IngressVlanID, val.IngressZone, inZone), sessionEgressIf(val.FibIfindex, val.FibVlanID, val.EgressZone, outZone), val.IngressZone, val.EgressZone)
		if haState != "" {
			fmt.Printf("Session ID: %d, Policy name: %s/%d, HA State: %s, Timeout: %d, Session State: Unknown (validity not tracked)\n",
				sid, polName, val.PolicyID, haState, val.Timeout)
		} else {
			fmt.Printf("Session ID: %d, Policy name: %s/%d, Timeout: %d, Session State: Unknown (validity not tracked)\n",
				sid, polName, val.PolicyID, val.Timeout)
		}

		inIf := sessionIngressIf(val.IngressIfindex, val.IngressVlanID, val.IngressZone, inZone)
		fmt.Printf("  In: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Zone: %s, Pkts: %d, Bytes: %d,\n",
			srcIP, srcPort, dstIP, dstPort, protoName,
			inIf, inZone, val.FwdPackets, val.FwdBytes)

		outSrcIP := dstIP.String()
		outSrcPort := dstPort
		outDstIP := srcIP.String()
		outDstPort := srcPort
		if val.Flags&dataplane.SessFlagSNAT != 0 {
			natIP := net.IP(val.NATSrcIP[:])
			natPort := ntohs(val.NATSrcPort)
			outDstIP = natIP.String()
			outDstPort = natPort
		}
		if val.Flags&dataplane.SessFlagDNAT != 0 {
			natIP := net.IP(val.NATDstIP[:])
			natPort := ntohs(val.NATDstPort)
			outSrcIP = natIP.String()
			outSrcPort = natPort
		}
		outIf := sessionEgressIf(val.FibIfindex, val.FibVlanID, val.EgressZone, outZone)
		fmt.Printf("  Out: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Zone: %s, Pkts: %d, Bytes: %d,\n",
			outSrcIP, outSrcPort, outDstIP, outDstPort, protoName,
			outIf, outZone, val.RevPackets, val.RevBytes)
		if appName := appid.ResolveSessionNameWithIndex(f.appNames, f.cfg, f.appFallback, key.Protocol, srcPort, dstPort, val.AppID); appName != "" {
			fmt.Printf("  Application: %s\n", appName)
		}
		fmt.Println()
	}

	// IPv6 sessions — stream directly, no collect/sort.
	err = c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if f.hasFilter() && !f.matchesV6(key, val) {
			return true
		}
		count++

		if f.summary {
			v6Count++
			byProto[key.Protocol]++
			inZ := zoneNames[val.IngressZone]
			outZ := zoneNames[val.EgressZone]
			if inZ == "" {
				inZ = fmt.Sprintf("zone-%d", val.IngressZone)
			}
			if outZ == "" {
				outZ = fmt.Sprintf("zone-%d", val.EgressZone)
			}
			byZonePair[inZ+"->"+outZ]++
			if val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) != 0 {
				natCount++
			}
			return true
		}

		printV6(count, key, val)
		return true
	})
	if err != nil {
		return fmt.Errorf("iterate sessions_v6: %w", err)
	}

	if briefWriter != nil {
		flushSessionBriefWriter(briefWriter)
	}

	var peerSummary *pb.GetSessionSummaryResponse
	var peerSummaryErr error
	if f.summary && clusterMode {
		peerSummary, peerSummaryErr = c.fetchPeerSessionSummary(f)
	}

	if f.summary {
		// In cluster mode, print dual-node Junos-style output.
		if clusterMode {
			fmt.Printf("node%d", c.cluster.NodeID())
			if peerSummaryErr != nil {
				fmt.Printf(" (LOCAL-ONLY)")
			}
			fmt.Println(":")
			fmt.Println("--------------------------------------------------------------------------")
		}
		// Junos-style session summary format
		fmt.Printf("Unicast-sessions: %d\n", count)
		fmt.Printf("Multicast-sessions: unknown\n")
		fmt.Printf("Services-offload-sessions: unknown\n")
		fmt.Printf("Failed-sessions: unknown\n")
		fmt.Printf("Sessions-in-drop-flow: unknown\n")
		fmt.Printf("Sessions-in-use: %d\n", count)
		fmt.Printf("  Valid sessions: unknown\n")
		fmt.Printf("  Pending sessions: unknown\n")
		fmt.Printf("  Invalidated sessions: unknown\n")
		fmt.Printf("  Sessions in other states: unknown\n")
		// #5323: render the dataplane's dynamic max (worker_count x per-worker
		// capacity) from the live helper status, not the old hardcoded
		// 10000000. If no userspace status is available (max 0), render
		// "unknown" instead of a fabricated authoritative bound.
		if st, err := c.userspaceDataplaneStatus(); err == nil && st.MaxSessions > 0 {
			fmt.Printf("Maximum-sessions: %d\n", st.MaxSessions)
		} else {
			fmt.Printf("Maximum-sessions: unknown\n")
		}

		if count > 0 {
			fmt.Printf("\nSession distribution:\n")
			fmt.Printf("  IPv4 sessions: %d\n", v4Count)
			fmt.Printf("  IPv6 sessions: %d\n", v6Count)
			fmt.Printf("  NAT sessions:  %d\n\n", natCount)

			fmt.Printf("  By protocol:\n")
			protoKeys := make([]uint8, 0, len(byProto))
			for k := range byProto {
				protoKeys = append(protoKeys, k)
			}
			sort.Slice(protoKeys, func(i, j int) bool { return protoKeys[i] < protoKeys[j] })
			for _, p := range protoKeys {
				fmt.Printf("    %-8s %d\n", protoNameFromNum(p), byProto[p])
			}

			fmt.Printf("\n  By zone pair:\n")
			zpKeys := make([]string, 0, len(byZonePair))
			for k := range byZonePair {
				zpKeys = append(zpKeys, k)
			}
			sort.Strings(zpKeys)
			for _, zp := range zpKeys {
				displayPair := zp
				if f.zoneName != "" && f.cfg != nil &&
					config.ZoneQuarantineExcludedReason(f.zoneName, f.cfg) != "" {
					survivor := zoneNames[f.zoneID]
					if survivor != "" {
						parts := strings.SplitN(zp, "->", 2)
						if len(parts) == 2 {
							if parts[0] == survivor {
								parts[0] = f.zoneDisplay(f.zoneID, parts[0])
							}
							if parts[1] == survivor {
								parts[1] = f.zoneDisplay(f.zoneID, parts[1])
							}
							displayPair = parts[0] + "->" + parts[1]
						}
					}
				}
				fmt.Printf("    %-30s %d\n", displayPair, byZonePair[zp])
			}
		}

		// A peer block is required in cluster mode even when heartbeat state
		// says the peer is down: heartbeat liveness does not guarantee that the
		// fabric RPC is reachable, and can flap independently of this fetch.
		if clusterMode {
			if peerSummaryErr != nil {
				printPeerSessionUnreachable(peerNodeID, peerSummaryErr)
			} else {
				fmt.Print(renderPeerSessionSummary(peerSummary))
			}
		}
		return nil
	}
	var peerResp *pb.GetSessionsResponse
	var peerErr error
	if clusterMode {
		peerResp, peerErr = c.fetchPeerSessions(f)
	}
	if peerErr != nil {
		fmt.Printf("Total sessions (LOCAL-ONLY): %d\n", count)
	} else {
		fmt.Printf("Total sessions: %d\n", count)
	}
	if clusterMode && peerErr != nil {
		printPeerSessionUnreachable(peerNodeID, peerErr)
	}

	// Fetch and display peer node sessions in cluster mode.
	if clusterMode {
		if peerResp != nil {
			// Sort peer sessions by SessionID for deterministic order.
			sort.Slice(peerResp.Sessions, func(i, j int) bool {
				return peerResp.Sessions[i].SessionId < peerResp.Sessions[j].SessionId
			})
			fmt.Println()
			fmt.Printf("node%d:\n", peerResp.NodeId)
			fmt.Println("--------------------------------------------------------------------------")
			if f.brief {
				peerBriefWriter := newSessionBriefWriter(os.Stdout)
				printSessionBriefHeader(peerBriefWriter)
				for i, se := range peerResp.Sessions {
					inZone := se.IngressZoneName
					if inZone == "" {
						inZone = fmt.Sprintf("%d", se.IngressZone)
					}
					outZone := se.EgressZoneName
					if outZone == "" {
						outZone = fmt.Sprintf("%d", se.EgressZone)
					}
					inZone = f.zoneDisplay(uint16(se.IngressZone), inZone)
					outZone = f.zoneDisplay(uint16(se.EgressZone), outZone)
					natFlag := peerSessionNATFlag(se.Nat)
					st := se.State
					if len(st) > 5 {
						st = st[:5]
					}
					peerSID := se.SessionId
					if peerSID == 0 {
						peerSID = uint64(i + 1)
					}
					age := uint64(0)
					if se.AgeSeconds > 0 {
						age = uint64(se.AgeSeconds)
					}
					printSessionBriefRow(peerBriefWriter, newSessionBriefRow(
						peerSID,
						se.SrcAddr, uint16(se.SrcPort),
						se.DstAddr, uint16(se.DstPort),
						se.Protocol, inZone, outZone, natFlag,
						st,
						age, se.FwdPackets, se.RevPackets,
					))
				}
				flushSessionBriefWriter(peerBriefWriter)
			} else {
				for i, se := range peerResp.Sessions {
					polDisplay := se.PolicyName
					if polDisplay == "" {
						polDisplay = fmt.Sprintf("%d", se.PolicyId)
					}
					peerFullSID := se.SessionId
					if peerFullSID == 0 {
						peerFullSID = uint64(i + 1)
					}
					peerHAState := "Backup"
					if se.HaActive {
						peerHAState = "Active"
					}
					fmt.Printf("Session ID: %d, Policy name: %s/%d, HA State: %s, Timeout: %d, Session State: Unknown (validity not tracked)\n",
						peerFullSID, polDisplay, se.PolicyId, peerHAState, se.TimeoutSeconds)
					inZone := se.IngressZoneName
					if inZone == "" {
						inZone = fmt.Sprintf("%d", se.IngressZone)
					}
					outZone := se.EgressZoneName
					if outZone == "" {
						outZone = fmt.Sprintf("%d", se.EgressZone)
					}
					inZone = f.zoneDisplay(uint16(se.IngressZone), inZone)
					outZone = f.zoneDisplay(uint16(se.EgressZone), outZone)
					inIf := se.IngressInterface
					if inIf == "" {
						inIf = inZone
					}
					outIf := se.EgressInterface
					if outIf == "" {
						outIf = outZone
					}
					fmt.Printf("  In: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Zone: %s, Pkts: %d, Bytes: %d,\n",
						se.SrcAddr, se.SrcPort, se.DstAddr, se.DstPort,
						se.Protocol, inIf, inZone, se.FwdPackets, se.FwdBytes)
					// Out line: reverse direction with NAT applied
					outSrcAddr := se.DstAddr
					outSrcPort := se.DstPort
					outDstAddr := se.SrcAddr
					outDstPort := se.SrcPort
					if se.NatSrcAddr != "" {
						outDstAddr = se.NatSrcAddr
						outDstPort = se.NatSrcPort
					}
					if se.NatDstAddr != "" {
						outSrcAddr = se.NatDstAddr
						outSrcPort = se.NatDstPort
					}
					fmt.Printf("  Out: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Zone: %s, Pkts: %d, Bytes: %d,\n",
						outSrcAddr, outSrcPort, outDstAddr, outDstPort,
						se.Protocol, outIf, outZone, se.RevPackets, se.RevBytes)
					if se.Application != "" {
						fmt.Printf("  Application: %s\n", se.Application)
					}
					fmt.Println()
				}
			}
			// #5034 (C175-HC-073): a current peer's GetSessions returns a REAL
			// filtered total in Total — an exact count-only scan of
			// filter-matching sessions, no longer the -1 sentinel — so it is
			// rendered directly (Total is the true count; len(Sessions)
			// undercounts once the peer's result is capped at limit 10000).
			// peerSessionsTotal retains the -1-sentinel->len fallback for a
			// pre-#5034 peer during a mixed-version ISSU window.
			fmt.Printf("Total sessions: %d\n", peerSessionsTotal(peerResp))
		}
	}
	return nil
}

// fetchPeerSessions dials the cluster peer's gRPC and returns its full session list.

func (c *CLI) showTopTalkers(f sessionFilter) error {
	zoneNames := make(map[uint16]string)
	if cr := c.applyResult(); cr != nil {
		zoneNames = config.SurvivorZoneNames(cr.ZoneIDs, f.cfg)
	}
	now := monotonicSeconds()
	collector := newTopTalkerCollector(topTalkerLimit)

	// #8597 (muse-004 K05): the scan does NOTHING per session but copy the
	// key/value into a fixed-size candidate. No net.IP conversion, no Sprintf,
	// no appid resolution, no closure — every one of those allocates, and an
	// allocation inside the callback is an allocation per SESSION, which is the
	// defect regardless of how few rows are eventually printed.
	//
	// This is not the first shape that was tried. Deferring the formatting
	// behind a closure per candidate looks bounded and is not: the closure
	// itself heap-allocates on every offer, and the zone/address work still
	// ran before it. The allocation-ratio cell caught that at 125x, which is
	// why it measures a ratio rather than asserting the design.

	// A backend iterator error (e.g. helper restart mid-scan) must fail
	// the command rather than printing a truncated top-talkers list as if
	// it were the full picture (#2469). The iteration runs before any
	// output, so an early return leaves no partial table on screen.
	if err := c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if f.hasFilter() && !f.matchesV4(key, val) {
			return true
		}
		collector.offerV4(topTalkerMetric(f.sortBy, val.FwdBytes, val.RevBytes, val.FwdPackets, val.RevPackets), key, val)
		return true
	}); err != nil {
		return fmt.Errorf("iterate sessions: %w", err)
	}

	if err := c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if f.hasFilter() && !f.matchesV6(key, val) {
			return true
		}
		collector.offerV6(topTalkerMetric(f.sortBy, val.FwdBytes, val.RevBytes, val.FwdPackets, val.RevPackets), key, val)
		return true
	}); err != nil {
		return fmt.Errorf("iterate sessions_v6: %w", err)
	}

	entries := collector.top(f, zoneNames, now)

	// The print cap stays explicit and independent of the collection cap.
	// Deriving it from len(entries) would make the two bounds one bound: a
	// change that widened collection would silently widen the printed table
	// too, and the mutation that removes the collection bound would then hang a
	// test on a full pipe instead of failing it. Two bounds, stated separately.
	limit := topTalkerLimit
	if limit > len(entries) {
		limit = len(entries)
	}

	if c.cluster != nil {
		fmt.Printf("Top %d sessions by %s on node%d (local only; of %d total):\n",
			limit, f.sortBy, c.cluster.NodeID(), collector.total)
	} else {
		fmt.Printf("Top %d sessions by %s (of %d total):\n", limit, f.sortBy, collector.total)
	}
	fmt.Printf("%-5s %-22s %-22s %-5s %-20s %12s %12s %5s %s\n",
		"#", "Source", "Destination", "Proto", "Zone", "Bytes(f/r)", "Pkts(f/r)", "Age", "App")
	for i := 0; i < limit; i++ {
		e := entries[i]
		fmt.Printf("%-5d %-22s %-22s %-5s %-20s %5d/%-6d %5d/%-6d %5d %s\n",
			i+1, e.src, e.dst, e.proto, e.zone,
			e.fwdBytes, e.revBytes, e.fwdPkts, e.revPkts, e.age, e.app)
	}
	return nil
}

func (c *CLI) showFlowTimeouts() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	// #15649 V11-04: single shared renderer (config.RenderFlowTimeouts) so
	// CLI/gRPC/REST cannot diverge on ICMP 60s, unset defaults, or GRE text.
	config.RenderFlowTimeouts(os.Stdout, cfg)
	return nil
}

// cliSessionCount reads table occupancy via the unwrapped backend,
// mirroring backendSessionCount, so a test double whose embedded manager
// is nil yields (0,0) rather than a promoted-method panic.
func cliSessionCount(dp cliRuntime) (v4, v6 int) {
	if dp == nil {
		return 0, 0
	}
	defer func() {
		if recover() != nil {
			v4, v6 = 0, 0
		}
	}()
	return dp.SessionCount()
}

// showFlowStatistics displays flow statistics from BPF global counters.

func (c *CLI) showFlowStatistics() error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Flow statistics: dataplane not loaded")
		return nil
	}

	// #3345: surface a counter-read failure rather than printing clean zeros
	// that hide a degraded counter bridge.
	var readErr error
	readCounter := func(idx uint32) uint64 {
		v, err := c.dp.ReadGlobalCounter(idx)
		if err != nil && readErr == nil {
			readErr = err
		}
		return v
	}

	rxPkts := readCounter(dataplane.GlobalCtrRxPackets)
	txPkts := readCounter(dataplane.GlobalCtrTxPackets)
	drops := readCounter(dataplane.GlobalCtrDrops)
	unknownVLANDrops := readCounter(dataplane.GlobalCtrUnknownVLANDrops)
	dstMACDrops := readCounter(dataplane.GlobalCtrDstMACDrops)
	sessNew := readCounter(dataplane.GlobalCtrSessionsNew)
	sessClosed := readCounter(dataplane.GlobalCtrSessionsClosed)
	screenDrops := readCounter(dataplane.GlobalCtrScreenDrops)
	policyDeny := readCounter(dataplane.GlobalCtrPolicyDeny)
	natFail := readCounter(dataplane.GlobalCtrNATAllocFail)
	hostDeny := readCounter(dataplane.GlobalCtrHostInboundDeny)
	hostAllow := readCounter(dataplane.GlobalCtrHostInbound)
	tcEgress := readCounter(dataplane.GlobalCtrTCEgressPackets)
	nat64 := readCounter(dataplane.GlobalCtrNAT64Xlate)
	fabricRedir := readCounter(dataplane.GlobalCtrFabricRedirect)
	cacheHit := readCounter(dataplane.GlobalCtrFlowCacheHit)
	cacheMiss := readCounter(dataplane.GlobalCtrFlowCacheMiss)
	cacheFlush := readCounter(dataplane.GlobalCtrFlowCacheFlush)
	cacheInval := readCounter(dataplane.GlobalCtrFlowCacheInvalidate)

	// #15236 (A52-05): "Current sessions" is table occupancy from
	// SessionCount(), not create-minus-expire of locally created sessions
	// (wrong after failover/clear for peer-synced sessions). The counter
	// delta is kept under its honest local-forwarding label.
	v4Cur, v6Cur := cliSessionCount(c.dp)
	fmt.Println("Flow statistics:")
	fmt.Printf("  %-30s %d\n", "Current sessions:", v4Cur+v6Cur)
	fmt.Printf("  %-30s %d\n", "Local forwarding sessions (created-closed):", dataplane.CurrentSessions(sessNew, sessClosed))
	fmt.Printf("  %-30s %d\n", "Sessions created:", sessNew)
	fmt.Printf("  %-30s %d\n", "Sessions closed:", sessClosed)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Packets received:", rxPkts)
	fmt.Printf("  %-30s %d\n", "Packets transmitted:", txPkts)
	fmt.Printf("  %-30s %d\n", "Packets dropped:", drops)
	fmt.Printf("  %-30s %d\n", "Unknown VLAN drops:", unknownVLANDrops)
	fmt.Printf("  %-30s %d\n", "Destination MAC drops:", dstMACDrops)
	fmt.Printf("  %-30s %d\n", "TC egress packets:", tcEgress)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Policy deny:", policyDeny)
	fmt.Printf("  %-30s %d\n", "NAT allocation failures:", natFail)
	fmt.Printf("  %-30s %d\n", "NAT64 translations:", nat64)
	fmt.Printf("  %-30s %d\n", "Fabric redirects:", fabricRedir)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Host-inbound allowed:", hostAllow)
	fmt.Printf("  %-30s %d\n", "Host-inbound denied:", hostDeny)

	// Flow cache (IPv4 + IPv6)
	if cacheHit > 0 || cacheMiss > 0 {
		fmt.Println()
		fmt.Printf("  %-30s %d\n", "Flow cache hits:", cacheHit)
		fmt.Printf("  %-30s %d\n", "Flow cache misses:", cacheMiss)
		fmt.Printf("  %-30s %d\n", "Flow cache flushes:", cacheFlush)
		fmt.Printf("  %-30s %d\n", "Flow cache invalidations:", cacheInval)
		if cacheHit+cacheMiss > 0 {
			hitRate := float64(cacheHit) / float64(cacheHit+cacheMiss) * 100
			fmt.Printf("  %-30s %.1f%%\n", "Flow cache hit rate:", hitRate)
		}
	}

	// Screen drops breakdown
	if screenDrops > 0 {
		fmt.Println()
		fmt.Printf("  %-30s %d\n", "Screen drops (total):", screenDrops)

		// #3343: shared screen-reason table — session-limit now appears in the
		// detailed breakdown alongside the rest.
		for i := range dataplane.ScreenReasonCounters {
			rc := &dataplane.ScreenReasonCounters[i]
			v := readCounter(rc.Index)
			if v > 0 {
				fmt.Printf("    %-28s %d\n", rc.Label+":", v)
			}
		}
	}

	// #3345: check AFTER all global-counter reads (incl. the screen breakdown
	// loop) so a failure on a late read is surfaced rather than printing a
	// stale 0.
	if readErr != nil {
		fmt.Printf("warning: global counter read failed (statistics may be incomplete): %v\n", readErr)
	}

	return nil
}

// showFlowTraceoptions displays flow traceoptions config.

func (c *CLI) showFlowTraceoptions() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	opts := cfg.Security.Flow.Traceoptions
	if opts == nil || opts.File == "" {
		fmt.Println("Flow traceoptions: not configured")
		return nil
	}

	fmt.Println("Flow traceoptions:")
	fmt.Printf("  File:           %s\n", opts.File)
	if opts.FileSize > 0 {
		fmt.Printf("  Max size:       %d bytes\n", opts.FileSize)
	}
	if opts.FileCount > 0 {
		fmt.Printf("  File count:     %d\n", opts.FileCount)
	}
	if len(opts.Flags) > 0 {
		fmt.Printf("  Flags:          %s\n", strings.Join(opts.Flags, ", "))
	}
	if len(opts.PacketFilters) > 0 {
		fmt.Println("  Packet filters:")
		for _, pf := range opts.PacketFilters {
			fmt.Printf("    %s:", pf.Name)
			if pf.SourcePrefix != "" {
				fmt.Printf(" src=%s", pf.SourcePrefix)
			}
			if pf.DestinationPrefix != "" {
				fmt.Printf(" dst=%s", pf.DestinationPrefix)
			}
			fmt.Println()
		}
	}

	return nil
}

func (c *CLI) showFlowMonitoring() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	// #15649 V17-04: shared SSOT for templates/IPFIX/bindings; CLI keeps its
	// richer sampling-instance section below.
	config.RenderFlowMonitoring(os.Stdout, cfg, flowServerNotInstalledSuffix)
	if cfg.ForwardingOptions.Sampling != nil {
		// sampling detail appended below by legacy block (hasConfig shim)
		_ = cfg
	}
	return c.showFlowMonitoringSampling(cfg)
}

func (c *CLI) showFlowMonitoringSampling(cfg *config.Config) error {
	hasConfig := config.HasFlowMonitoring(cfg)
	if cfg.ForwardingOptions.Sampling != nil && len(cfg.ForwardingOptions.Sampling.Instances) > 0 {
		hasConfig = true
	}
	if cfg.ForwardingOptions.Sampling != nil {
		for _, name := range sortedInstanceNames(cfg.ForwardingOptions.Sampling.Instances) {
			inst := cfg.ForwardingOptions.Sampling.Instances[name]
			hasConfig = true
			fmt.Printf("Sampling Instance: %s\n", name)
			if inst.InputRate > 0 {
				fmt.Printf("  Input rate: 1/%d\n", inst.InputRate)
			}
			showSamplingFamily := func(af string, fam *config.SamplingFamily) {
				if fam == nil {
					return
				}
				fmt.Printf("  Family %s:\n", af)
				if fam.InlineJflow {
					fmt.Printf("    Inline jflow: enabled\n")
				}
				if fam.SourceAddress != "" {
					fmt.Printf("    Source address: %s\n", fam.SourceAddress)
				}
				for _, fs := range fam.FlowServers {
					portStr := ""
					if fs.Port > 0 {
						portStr = fmt.Sprintf(":%d", fs.Port)
					}
					tmplStr := ""
					if fs.Version9Template != "" {
						tmplStr = fmt.Sprintf(" (v9 template: %s)", fs.Version9Template)
					} else if fs.VersionIPFIXTemplate != "" {
						tmplStr = fmt.Sprintf(" (ipfix template: %s)", fs.VersionIPFIXTemplate)
					}
					// Per-collector source-address override (#3745): the
					// effective bind is this value when set, else the
					// family output-level default shown above.
					srcStr := ""
					if fs.SourceAddress != "" {
						srcStr = fmt.Sprintf(" source %s", fs.SourceAddress)
					}
					// #6565 row 11 / #7422: a collector the snapshot builder
					// SKIPS (no port, or a port outside the u16 wire range)
					// used to render exactly like a healthy one — with port 0
					// the `:0` suffix is suppressed too, so `Collector:
					// 10.0.0.1` read as an active export target on the default
					// port. Ask the builder's own verdict.
					fmt.Printf("    Collector: %s%s%s%s%s\n", fs.Address, portStr,
						srcStr, tmplStr, flowServerNotInstalledSuffix(fs))
				}
			}
			showSamplingFamily("inet", inst.FamilyInet)
			showSamplingFamily("inet6", inst.FamilyInet6)
			fmt.Println()
		}
	}

	if !hasConfig {
		// RenderFlowMonitoring already printed "No flow monitoring
		// configured" when nothing exists; only sampling could add more.
		_ = hasConfig
	}

	return nil
}

// showFlowMonitoringStatistics renders live per-collector NetFlow v9 /
// IPFIX write-health (#2464): write attempt/failure counters, the current
// reachability, and the last success / failure timestamps for every
// running exporter collector. A collector going silently unreachable
// (every failed UDP write was debug-logged and dropped) was previously
// invisible while the exporter kept counting "exported" — a forensics /
// compliance loss with no operator warning.
func (c *CLI) showFlowMonitoringStatistics() error {
	if c.flowCollectorHealthFn == nil {
		fmt.Println("No flow export configured")
		return nil
	}
	health := c.flowCollectorHealthFn()
	if len(health) == 0 {
		fmt.Println("No flow export configured")
		return nil
	}
	fmt.Println("Flow export collector statistics:")
	for _, h := range health {
		state := "up"
		if !h.Healthy {
			state = "DOWN"
		}
		line := fmt.Sprintf("  Collector %s (%s)", h.Address, h.Protocol)
		if h.SourceAddress != "" {
			line += fmt.Sprintf(" source %s", h.SourceAddress)
		}
		if h.Instance != "" {
			line += fmt.Sprintf(" instance %s", h.Instance)
		}
		if h.Template != "" {
			line += fmt.Sprintf(" template %s", h.Template)
		}
		fmt.Println(line)
		fmt.Printf("    State:          %s\n", state)
		fmt.Printf("    Write attempts: %d\n", h.WriteAttempts)
		fmt.Printf("    Write failures: %d\n", h.WriteFailures)
		if h.WriteSkipped > 0 {
			fmt.Printf("    Write skipped:  %d (unhealthy backoff)\n", h.WriteSkipped)
		}
		if !h.LastSuccessTime.IsZero() {
			fmt.Printf("    Last success:   %s\n", h.LastSuccessTime.Format("2006-01-02 15:04:05"))
		}
		if !h.LastFailureTime.IsZero() {
			fmt.Printf("    Last failure:   %s\n", h.LastFailureTime.Format("2006-01-02 15:04:05"))
		}
		if h.LastError != "" {
			fmt.Printf("    Last error:     %s\n", h.LastError)
		}
	}
	return nil
}

// renderPeerSessionSummary renders the cluster-peer half of
// `show security flow session summary`.
//
// EXTRACTED so it can be tested (#6565 row 3 / #7422). Cluster mode attempts the
// peer RPC even when heartbeat state is down (#10836); keeping rendering
// independent lets tests pin the peer's own summary values without a live
// cluster connection.
func renderPeerSessionSummary(peerResp *pb.GetSessionSummaryResponse) string {
	var b strings.Builder
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "node%d:\n", peerResp.NodeId)
	fmt.Fprintln(&b, "--------------------------------------------------------------------------")
	fmt.Fprintf(&b, "Unicast-sessions: %d\n", peerResp.ForwardOnly)
	fmt.Fprintf(&b, "Multicast-sessions: unknown\n")
	fmt.Fprintf(&b, "Services-offload-sessions: unknown\n")
	fmt.Fprintf(&b, "Failed-sessions: unknown\n")
	fmt.Fprintf(&b, "Sessions-in-drop-flow: unknown\n")
	fmt.Fprintf(&b, "Sessions-in-use: %d\n", peerResp.ForwardOnly)
	fmt.Fprintf(&b, "  Valid sessions: unknown\n")
	fmt.Fprintf(&b, "  Pending sessions: unknown\n")
	fmt.Fprintf(&b, "  Invalidated sessions: unknown\n")
	fmt.Fprintf(&b, "  Sessions in other states: unknown\n")
	// The PEER's real capacity, not the hardcoded 10000000 #5323 was written to
	// delete. The LOCAL branch was fixed there; this one was missed, and
	// `peerResp.MaxSessions` has been on the wire the whole time
	// (`GetSessionSummaryResponse` field 12, set from the peer's own helper
	// status in `grpcapi/server_sessions.go`).
	//
	// Same `> 0 ? : "unknown"` shape as the local branch, and for the same
	// reason: a peer that returned no helper status has an UNKNOWN bound, and
	// "unknown" is the honest answer where a fabricated authoritative number is
	// not.
	if peerResp.MaxSessions > 0 {
		fmt.Fprintf(&b, "Maximum-sessions: %d\n", peerResp.MaxSessions)
	} else {
		fmt.Fprintf(&b, "Maximum-sessions: unknown\n")
	}
	return b.String()
}

func printPeerSessionUnreachable(peerNodeID int, err error) {
	fmt.Printf("\nnode%d: unreachable (%v)\n", peerNodeID, err)
}

// flowServerNotInstalledSuffix returns the `[NOT INSTALLED: <reason>]` suffix
// for a flow-server (collector) the userspace snapshot builder refuses to
// install, or "" when it installs.
//
// #6565 row 11 / #7422: the verdict is config.FlowServerExcludedReason — the
// SAME predicate buildFlowExportSnapshots consults — so the renderer and the
// builder cannot disagree about which collectors are live. Unlike most #6534
// families this state is reachable through a clean commit: nothing validates
// the flow-server port at commit time, so `flow-server 10.0.0.1` with no
// `port` lands in the active config, is skipped by the builder, and used to
// print as `Collector: 10.0.0.1` — the `:0` suffix suppressed, so it read as a
// healthy collector on the default port.
func flowServerNotInstalledSuffix(fs *config.FlowServer) string {
	reason := config.FlowServerExcludedReason(fs)
	if reason == "" {
		return ""
	}
	return "  [NOT INSTALLED: " + reason + "]"
}
func peerSessionNATFlag(nat string) string {
	hasSNAT := strings.Contains(nat, "SNAT")
	hasDNAT := strings.Contains(nat, "DNAT") || strings.HasPrefix(nat, "dst")
	switch {
	case hasSNAT && hasDNAT:
		return "B"
	case hasSNAT:
		return "S"
	case hasDNAT:
		return "D"
	default:
		return "-"
	}
}
