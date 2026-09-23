package cli

import (
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

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

func newSessionBriefWriter(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
}

func flushSessionBriefWriter(w *tabwriter.Writer) {
	if w != nil {
		_ = w.Flush()
	}
}

func printSessionBriefHeader(w io.Writer) {
	fmt.Fprintln(w, "ID\tSource\tDestination\tProto\tZone\tNAT\tState\tAge\tPkts(f/r)")
}

func printSessionBriefRow(w io.Writer, row sessionBriefRow) {
	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d/%d\n",
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
	if clusterMode && !f.summary {
		fmt.Printf("node%d:\n", c.cluster.NodeID())
		fmt.Println("--------------------------------------------------------------------------")
	}

	// Determine HA state string for session display.
	haState := ""
	if clusterMode {
		if c.cluster.IsLocalPrimary(0) {
			haState = "Active"
		} else {
			haState = "Backup"
		}
	}

	// Summary counters for protocol/zone/NAT breakdown
	var byProto map[uint8]int
	var byZonePair map[string]int
	var v4Count, v6Count, natCount int
	if f.summary {
		byProto = make(map[uint8]int)
		byZonePair = make(map[string]int)
	}

	var briefWriter *tabwriter.Writer
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
		if haState != "" {
			fmt.Printf("Session ID: %d, Policy name: %s/%d, HA State: %s, Timeout: %d, Session State: Valid\n",
				sid, polName, val.PolicyID, haState, val.Timeout)
		} else {
			fmt.Printf("Session ID: %d, Policy name: %s/%d, Timeout: %d, Session State: Valid\n",
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
		if appName := appid.ResolveSessionName(f.appNames, f.cfg, key.Protocol, srcPort, dstPort, val.AppID); appName != "" {
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
		if haState != "" {
			fmt.Printf("Session ID: %d, Policy name: %s/%d, HA State: %s, Timeout: %d, Session State: Valid\n",
				sid, polName, val.PolicyID, haState, val.Timeout)
		} else {
			fmt.Printf("Session ID: %d, Policy name: %s/%d, Timeout: %d, Session State: Valid\n",
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
		if appName := appid.ResolveSessionName(f.appNames, f.cfg, key.Protocol, srcPort, dstPort, val.AppID); appName != "" {
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

	if f.summary {
		// In cluster mode, print dual-node Junos-style output.
		if c.cluster != nil {
			fmt.Printf("node%d:\n", c.cluster.NodeID())
			fmt.Println("--------------------------------------------------------------------------")
		}
		// Junos-style session summary format
		fmt.Printf("Unicast-sessions: %d\n", count)
		fmt.Printf("Multicast-sessions: 0\n")
		fmt.Printf("Services-offload-sessions: 0\n")
		fmt.Printf("Failed-sessions: 0\n")
		fmt.Printf("Sessions-in-drop-flow: 0\n")
		fmt.Printf("Sessions-in-use: %d\n", count)
		fmt.Printf("  Valid sessions: %d\n", count)
		fmt.Printf("  Pending sessions: 0\n")
		fmt.Printf("  Invalidated sessions: 0\n")
		fmt.Printf("  Sessions in other states: 0\n")
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

		// Fetch and display peer node summary in cluster mode.
		if c.cluster != nil && c.cluster.PeerAlive() {
			if peerResp := c.fetchPeerSessionSummary(); peerResp != nil {
				fmt.Print(renderPeerSessionSummary(peerResp))
			}
		}
		return nil
	}
	fmt.Printf("Total sessions: %d\n", count)

	// Fetch and display peer node sessions in cluster mode.
	if clusterMode && c.cluster.PeerAlive() {
		if peerResp := c.fetchPeerSessions(f); peerResp != nil {
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
					natFlag := "-"
					if se.Nat != "" {
						if strings.Contains(se.Nat, "SNAT") {
							natFlag = "S"
						}
						if strings.Contains(se.Nat, "DNAT") || strings.HasPrefix(se.Nat, "dst") {
							natFlag = "D"
						}
					}
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
					fmt.Printf("Session ID: %d, Policy name: %s/%d, HA State: %s, Timeout: %d, Session State: Valid\n",
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

	fmt.Printf("Top %d sessions by %s (of %d total):\n", limit, f.sortBy, collector.total)
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

	flow := &cfg.Security.Flow

	fmt.Println("Flow session timeouts:")

	// TCP (#6539). Two claims on each of these rows are enforcement claims and
	// both used to be wrong:
	//
	//  1. Only established-timeout has a dataplane wire carrier. The other
	//     three are committed and stored but never leave the control plane, so
	//     they carry config.AnnotateTCPSessionTimeout's annotation — the same
	//     string the REST and gRPC surfaces and the commit advisory use.
	//  2. The "(default)" values were the Junos defaults (1800/30/30/120), not
	//     the windows this dataplane applies. Nothing in the Go path fills a
	//     default in, so an unset leaf reaches the helper as 0 and it falls
	//     back to its own constant. config.TCPSessionTimeoutDataplaneDefault is
	//     the authority for what those constants are; time-wait reports none,
	//     because the dataplane has no TIME_WAIT state to give a window to.
	printTimeout := func(name, leaf string, val int) {
		var cell string
		switch def, ok := config.TCPSessionTimeoutDataplaneDefault(leaf); {
		case val > 0:
			cell = fmt.Sprintf("%ds", val)
		case ok:
			cell = fmt.Sprintf("%ds (default)", def)
		default:
			cell = "not set"
		}
		fmt.Printf("  %-30s %s\n", name+":", config.AnnotateTCPSessionTimeout(leaf, cell))
	}
	tcp := flow.TCPSession
	if tcp == nil {
		// No tcp-session stanza: every leaf is unset, which is exactly the
		// val<=0 case above. Render through the same helper rather than
		// duplicating four literal lines that can drift out of agreement with
		// it (they had).
		tcp = &config.TCPSessionConfig{}
	}
	printTimeout("TCP established timeout", config.TCPSessionEstablishedTimeoutLeaf, tcp.EstablishedTimeout)
	printTimeout("TCP initial timeout", config.TCPSessionInitialTimeoutLeaf, tcp.InitialTimeout)
	printTimeout("TCP closing timeout", config.TCPSessionClosingTimeoutLeaf, tcp.ClosingTimeout)
	printTimeout("TCP time-wait timeout", config.TCPSessionTimeWaitTimeoutLeaf, tcp.TimeWaitTimeout)

	// UDP
	if flow.UDPSessionTimeout > 0 {
		fmt.Printf("  %-30s %ds\n", "UDP session timeout:", flow.UDPSessionTimeout)
	} else {
		fmt.Println("  UDP session timeout:           60s (default)")
	}

	// ICMP
	if flow.ICMPSessionTimeout > 0 {
		fmt.Printf("  %-30s %ds\n", "ICMP session timeout:", flow.ICMPSessionTimeout)
	} else {
		fmt.Println("  ICMP session timeout:          30s (default)")
	}

	// TCP MSS clamping
	if flow.TCPMSSAllTCP > 0 || flow.TCPMSSIPsecVPN > 0 || flow.TCPMSSGreIn > 0 || flow.TCPMSSGreOut > 0 {
		fmt.Println()
		fmt.Println("TCP MSS clamping:")
		if flow.TCPMSSAllTCP > 0 {
			fmt.Printf("  %-30s %d\n", "All TCP MSS:", flow.TCPMSSAllTCP)
		}
		if flow.TCPMSSIPsecVPN > 0 {
			fmt.Printf("  %-30s %d\n", "IPsec VPN MSS (not enforced):", flow.TCPMSSIPsecVPN)
		}
		if flow.TCPMSSGreIn > 0 {
			fmt.Printf("  %-30s %d\n", "GRE ingress MSS:", flow.TCPMSSGreIn)
		}
		if flow.TCPMSSGreOut > 0 {
			fmt.Printf("  %-30s %d\n", "GRE egress MSS:", flow.TCPMSSGreOut)
		}
	}

	// Flow options
	if flow.AllowDNSReply || flow.AllowEmbeddedICMP || flow.GREPerformanceAcceleration || flow.PowerModeDisable {
		fmt.Println()
		fmt.Println("Flow options:")
		if flow.AllowDNSReply {
			fmt.Println("  allow-dns-reply:               enabled")
		}
		if flow.AllowEmbeddedICMP {
			fmt.Println("  allow-embedded-icmp:           enabled")
		}
		if flow.GREPerformanceAcceleration {
			// #7188 cut 1: still do NOT render a plain "enabled", but the
			// reason changed. This used to say GRE sessions "remain 5-tuple
			// keyed", which stopped being true when transit GRE started
			// resolving a discriminator-keyed flow. It is now partially in
			// force: keyed locally, NOT keyed across HA sync, because
			// build_synced_session_key zeroes the discriminator on a
			// peer-synced key. An operator who reads "enabled" here and plans
			// per-tunnel separation through a failover gets aliasing on the
			// standby. Keep this in lockstep with the commit-time advisory in
			// validateSecurityFlowAcceptedOnly.
			fmt.Println("  gre-performance-acceleration:  configured (partial; transit GRE keyed on the RFC 2890 discriminator locally, NOT across HA sync — per-tunnel identity does not survive failover — #7188)")
		}
		if flow.PowerModeDisable {
			fmt.Println("  power-mode-disable:            yes")
		}
	}

	return nil
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

	fmt.Println("Flow statistics:")
	fmt.Printf("  %-30s %d\n", "Current sessions:", dataplane.CurrentSessions(sessNew, sessClosed))
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

	hasConfig := false

	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.Version9 != nil {
		v9 := cfg.Services.FlowMonitoring.Version9
		if len(v9.Templates) > 0 {
			hasConfig = true
			fmt.Println("Flow Monitoring Version 9 Templates:")
			for name, tmpl := range v9.Templates {
				activeTimeout := tmpl.FlowActiveTimeout
				if activeTimeout == 0 {
					activeTimeout = 60
				}
				inactiveTimeout := tmpl.FlowInactiveTimeout
				if inactiveTimeout == 0 {
					inactiveTimeout = 15
				}
				refreshRate := tmpl.TemplateRefreshRate
				if refreshRate == 0 {
					refreshRate = 60
				}
				fmt.Printf("  Template: %s\n", name)
				fmt.Printf("    Flow active timeout:   %d seconds\n", activeTimeout)
				fmt.Printf("    Flow inactive timeout: %d seconds\n", inactiveTimeout)
				fmt.Printf("    Template refresh rate: %d seconds\n", refreshRate)
				if len(tmpl.ExportExtensions) > 0 {
					fmt.Printf("    Export extensions:     %s\n", strings.Join(tmpl.ExportExtensions, ", "))
				}
			}
			fmt.Println()
		}
	}

	if cfg.Services.FlowMonitoring != nil && cfg.Services.FlowMonitoring.VersionIPFIX != nil {
		ipfix := cfg.Services.FlowMonitoring.VersionIPFIX
		if len(ipfix.Templates) > 0 {
			hasConfig = true
			fmt.Println("Flow Monitoring IPFIX Templates:")
			for name, tmpl := range ipfix.Templates {
				activeTimeout := tmpl.FlowActiveTimeout
				if activeTimeout == 0 {
					activeTimeout = 60
				}
				inactiveTimeout := tmpl.FlowInactiveTimeout
				if inactiveTimeout == 0 {
					inactiveTimeout = 15
				}
				refreshRate := tmpl.TemplateRefreshRate
				if refreshRate == 0 {
					refreshRate = 60
				}
				fmt.Printf("  Template: %s\n", name)
				fmt.Printf("    Flow active timeout:   %d seconds\n", activeTimeout)
				fmt.Printf("    Flow inactive timeout: %d seconds\n", inactiveTimeout)
				fmt.Printf("    Template refresh rate: %d seconds\n", refreshRate)
				if len(tmpl.ExportExtensions) > 0 {
					fmt.Printf("    Export extensions:     %s\n", strings.Join(tmpl.ExportExtensions, ", "))
				}
			}
			fmt.Println()
		}
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
		fmt.Println("No flow monitoring configured")
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
// EXTRACTED so it can be tested (#6565 row 3 / #7422). `c.cluster` is a
// concrete `*cluster.Manager` and the peer block is gated on
// `c.cluster != nil && c.cluster.PeerAlive()`, so a CLI-level fixture cannot
// reach it without a live cluster — which is exactly why the #5323 regression
// test could not catch this row. That test greps its output for "10000000",
// but its fixture leaves `cluster` nil, so the peer branch never runs and the
// assertion is physically unable to see the literal it was written to catch.
// A guard that cannot reach its subject is not a guard; pulling the render out
// is what makes the fail-on-revert cell real.
func renderPeerSessionSummary(peerResp *pb.GetSessionSummaryResponse) string {
	var b strings.Builder
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "node%d:\n", peerResp.NodeId)
	fmt.Fprintln(&b, "--------------------------------------------------------------------------")
	fmt.Fprintf(&b, "Unicast-sessions: %d\n", peerResp.ForwardOnly)
	fmt.Fprintf(&b, "Multicast-sessions: 0\n")
	fmt.Fprintf(&b, "Services-offload-sessions: 0\n")
	fmt.Fprintf(&b, "Failed-sessions: 0\n")
	fmt.Fprintf(&b, "Sessions-in-drop-flow: 0\n")
	fmt.Fprintf(&b, "Sessions-in-use: %d\n", peerResp.ForwardOnly)
	fmt.Fprintf(&b, "  Valid sessions: %d\n", peerResp.ForwardOnly)
	fmt.Fprintf(&b, "  Pending sessions: 0\n")
	fmt.Fprintf(&b, "  Invalidated sessions: 0\n")
	fmt.Fprintf(&b, "  Sessions in other states: 0\n")
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
