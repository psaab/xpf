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
)

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

func (c *CLI) showStatistics(detail bool) error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Statistics: dataplane not loaded")
		return nil
	}

	readCounter := func(idx uint32) uint64 {
		v, _ := c.dp.ReadGlobalCounter(idx)
		return v
	}

	names := []struct {
		idx  uint32
		name string
	}{
		{dataplane.GlobalCtrRxPackets, "RX packets"},
		{dataplane.GlobalCtrTxPackets, "TX packets"},
		{dataplane.GlobalCtrDrops, "Drops"},
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
		screenCounters := []struct {
			idx  uint32
			name string
		}{
			{dataplane.GlobalCtrScreenSynFlood, "SYN flood"},
			{dataplane.GlobalCtrScreenICMPFlood, "ICMP flood"},
			{dataplane.GlobalCtrScreenUDPFlood, "UDP flood"},
			{dataplane.GlobalCtrScreenPortScan, "Port scan"},
			{dataplane.GlobalCtrScreenIPSweep, "IP sweep"},
			{dataplane.GlobalCtrScreenLandAttack, "Land attack"},
			{dataplane.GlobalCtrScreenPingOfDeath, "Ping of death"},
			{dataplane.GlobalCtrScreenTearDrop, "Teardrop"},
			{dataplane.GlobalCtrScreenTCPSynFin, "TCP SYN+FIN"},
			{dataplane.GlobalCtrScreenTCPNoFlag, "TCP no flag"},
			{dataplane.GlobalCtrScreenTCPFinNoAck, "TCP FIN no ACK"},
			{dataplane.GlobalCtrScreenWinNuke, "WinNuke"},
			{dataplane.GlobalCtrScreenIPSrcRoute, "IP source route"},
			{dataplane.GlobalCtrScreenSynFrag, "SYN fragment"},
		}
		for _, sc := range screenCounters {
			v := readCounter(sc.idx)
			if v > 0 {
				fmt.Printf("  %-25s %d\n", sc.name+":", v)
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

	return nil
}

func (c *CLI) showFlowSession(args []string) error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("Session table: dataplane not loaded")
		return nil
	}

	f := c.parseSessionFilter(args)

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
	zoneIfaces := make(map[uint16]string) // zone ID → first interface name
	var policyNames map[uint32]string
	if cr := c.applyResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			zoneNames[id] = name
		}
		policyNames = cr.PolicyNames
	}
	if f.cfg != nil {
		for zoneName, zone := range f.cfg.Security.Zones {
			if cr := c.applyResult(); cr != nil {
				if zid, ok := cr.ZoneIDs[zoneName]; ok && len(zone.Interfaces) > 0 {
					zoneIfaces[zid] = zone.Interfaces[0]
				}
			}
		}
	}
	egressIfaces := buildSessionEgressIfaces(f.cfg)

	// Populate filter maps for interface-level matching in matchesV4/V6.
	f.zoneIfaces = zoneIfaces
	f.egressIfacesMap = egressIfaces

	sessionEgressIf := func(fibIfindex uint32, fibVlanID uint16, zoneID uint16, zoneName string) string {
		if fibIfindex != 0 {
			if ifName, ok := egressIfaces[sessionIfaceKey{ifindex: fibIfindex, vlanID: fibVlanID}]; ok && ifName != "" {
				return ifName
			}
		}
		if ifName := zoneIfaces[zoneID]; ifName != "" {
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

		sid := val.SessionID
		if sid == 0 {
			sid = uint64(idx)
		}

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

		polName := policyNames[val.PolicyID]
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

		inIf := zoneIfaces[val.IngressZone]
		if inIf == "" {
			inIf = inZone
		}
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
		if appName := appid.ResolveSessionName(f.appNames, f.cfg, key.Protocol, dstPort, val.AppID); appName != "" {
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

		sid := val.SessionID
		if sid == 0 {
			sid = uint64(idx)
		}

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

		polName := policyNames[val.PolicyID]
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

		inIf := zoneIfaces[val.IngressZone]
		if inIf == "" {
			inIf = inZone
		}
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
		if appName := appid.ResolveSessionName(f.appNames, f.cfg, key.Protocol, dstPort, val.AppID); appName != "" {
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
		fmt.Printf("Maximum-sessions: 10000000\n")

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
				fmt.Printf("    %-30s %d\n", zp, byZonePair[zp])
			}
		}

		// Fetch and display peer node summary in cluster mode.
		if c.cluster != nil && c.cluster.PeerAlive() {
			if peerResp := c.fetchPeerSessionSummary(); peerResp != nil {
				fmt.Println()
				fmt.Printf("node%d:\n", peerResp.NodeId)
				fmt.Println("--------------------------------------------------------------------------")
				fmt.Printf("Unicast-sessions: %d\n", peerResp.ForwardOnly)
				fmt.Printf("Multicast-sessions: 0\n")
				fmt.Printf("Services-offload-sessions: 0\n")
				fmt.Printf("Failed-sessions: 0\n")
				fmt.Printf("Sessions-in-drop-flow: 0\n")
				fmt.Printf("Sessions-in-use: %d\n", peerResp.ForwardOnly)
				fmt.Printf("  Valid sessions: %d\n", peerResp.ForwardOnly)
				fmt.Printf("  Pending sessions: 0\n")
				fmt.Printf("  Invalidated sessions: 0\n")
				fmt.Printf("  Sessions in other states: 0\n")
				fmt.Printf("Maximum-sessions: 10000000\n")
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
			fmt.Printf("Total sessions: %d\n", peerResp.Total)
		}
	}
	return nil
}

// fetchPeerSessions dials the cluster peer's gRPC and returns its full session list.

func (c *CLI) showTopTalkers(f sessionFilter) error {
	zoneNames := make(map[uint16]string)
	if cr := c.applyResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			zoneNames[id] = name
		}
	}
	now := monotonicSeconds()
	var entries []topTalkerEntry

	_ = c.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if f.hasFilter() && !f.matchesV4(key, val) {
			return true
		}
		srcIP := net.IP(key.SrcIP[:])
		dstIP := net.IP(key.DstIP[:])
		inZone := zoneNames[val.IngressZone]
		outZone := zoneNames[val.EgressZone]
		if inZone == "" {
			inZone = fmt.Sprintf("%d", val.IngressZone)
		}
		if outZone == "" {
			outZone = fmt.Sprintf("%d", val.EgressZone)
		}
		var age uint64
		if now > val.Created {
			age = now - val.Created
		}
		entries = append(entries, topTalkerEntry{
			src:      fmt.Sprintf("%s:%d", srcIP, ntohs(key.SrcPort)),
			dst:      fmt.Sprintf("%s:%d", dstIP, ntohs(key.DstPort)),
			proto:    protoNameFromNum(key.Protocol),
			zone:     inZone + "->" + outZone,
			state:    sessionStateName(val.State),
			app:      appid.ResolveSessionName(f.appNames, f.cfg, key.Protocol, ntohs(key.DstPort), val.AppID),
			fwdPkts:  val.FwdPackets,
			revPkts:  val.RevPackets,
			fwdBytes: val.FwdBytes,
			revBytes: val.RevBytes,
			age:      age,
		})
		return true
	})

	_ = c.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if f.hasFilter() && !f.matchesV6(key, val) {
			return true
		}
		srcIP := net.IP(key.SrcIP[:])
		dstIP := net.IP(key.DstIP[:])
		inZone := zoneNames[val.IngressZone]
		outZone := zoneNames[val.EgressZone]
		if inZone == "" {
			inZone = fmt.Sprintf("%d", val.IngressZone)
		}
		if outZone == "" {
			outZone = fmt.Sprintf("%d", val.EgressZone)
		}
		var age uint64
		if now > val.Created {
			age = now - val.Created
		}
		entries = append(entries, topTalkerEntry{
			src:      fmt.Sprintf("[%s]:%d", srcIP, ntohs(key.SrcPort)),
			dst:      fmt.Sprintf("[%s]:%d", dstIP, ntohs(key.DstPort)),
			proto:    protoNameFromNum(key.Protocol),
			zone:     inZone + "->" + outZone,
			state:    sessionStateName(val.State),
			app:      appid.ResolveSessionName(f.appNames, f.cfg, key.Protocol, ntohs(key.DstPort), val.AppID),
			fwdPkts:  val.FwdPackets,
			revPkts:  val.RevPackets,
			fwdBytes: val.FwdBytes,
			revBytes: val.RevBytes,
			age:      age,
		})
		return true
	})

	if f.sortBy == "bytes" {
		sort.Slice(entries, func(i, j int) bool {
			return (entries[i].fwdBytes + entries[i].revBytes) > (entries[j].fwdBytes + entries[j].revBytes)
		})
	} else {
		sort.Slice(entries, func(i, j int) bool {
			return (entries[i].fwdPkts + entries[i].revPkts) > (entries[j].fwdPkts + entries[j].revPkts)
		})
	}

	limit := 20
	if limit > len(entries) {
		limit = len(entries)
	}

	fmt.Printf("Top %d sessions by %s (of %d total):\n", limit, f.sortBy, len(entries))
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

	// TCP
	if flow.TCPSession != nil {
		tcp := flow.TCPSession
		printTimeout := func(name string, val, def int) {
			if val > 0 {
				fmt.Printf("  %-30s %ds\n", name+":", val)
			} else {
				fmt.Printf("  %-30s %ds (default)\n", name+":", def)
			}
		}
		printTimeout("TCP established timeout", tcp.EstablishedTimeout, 1800)
		printTimeout("TCP initial timeout", tcp.InitialTimeout, 30)
		printTimeout("TCP closing timeout", tcp.ClosingTimeout, 30)
		printTimeout("TCP time-wait timeout", tcp.TimeWaitTimeout, 120)
	} else {
		fmt.Println("  TCP established timeout:       1800s (default)")
		fmt.Println("  TCP initial timeout:           30s (default)")
		fmt.Println("  TCP closing timeout:           30s (default)")
		fmt.Println("  TCP time-wait timeout:         120s (default)")
	}

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
	if flow.TCPMSSIPsecVPN > 0 || flow.TCPMSSGreIn > 0 || flow.TCPMSSGreOut > 0 {
		fmt.Println()
		fmt.Println("TCP MSS clamping:")
		if flow.TCPMSSIPsecVPN > 0 {
			fmt.Printf("  %-30s %d\n", "IPsec VPN MSS:", flow.TCPMSSIPsecVPN)
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
			fmt.Println("  gre-performance-acceleration:  enabled")
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

	readCounter := func(idx uint32) uint64 {
		v, _ := c.dp.ReadGlobalCounter(idx)
		return v
	}

	rxPkts := readCounter(dataplane.GlobalCtrRxPackets)
	txPkts := readCounter(dataplane.GlobalCtrTxPackets)
	drops := readCounter(dataplane.GlobalCtrDrops)
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
	fmt.Printf("  %-30s %d\n", "Current sessions:", sessNew-sessClosed)
	fmt.Printf("  %-30s %d\n", "Sessions created:", sessNew)
	fmt.Printf("  %-30s %d\n", "Sessions closed:", sessClosed)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Packets received:", rxPkts)
	fmt.Printf("  %-30s %d\n", "Packets transmitted:", txPkts)
	fmt.Printf("  %-30s %d\n", "Packets dropped:", drops)
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

		screenCounters := []struct {
			idx  uint32
			name string
		}{
			{dataplane.GlobalCtrScreenSynFlood, "SYN flood"},
			{dataplane.GlobalCtrScreenICMPFlood, "ICMP flood"},
			{dataplane.GlobalCtrScreenUDPFlood, "UDP flood"},
			{dataplane.GlobalCtrScreenPortScan, "Port scan"},
			{dataplane.GlobalCtrScreenIPSweep, "IP sweep"},
			{dataplane.GlobalCtrScreenLandAttack, "Land attack"},
			{dataplane.GlobalCtrScreenPingOfDeath, "Ping of death"},
			{dataplane.GlobalCtrScreenTearDrop, "Tear drop"},
			{dataplane.GlobalCtrScreenTCPSynFin, "TCP SYN-FIN"},
			{dataplane.GlobalCtrScreenTCPNoFlag, "TCP no flag"},
			{dataplane.GlobalCtrScreenTCPFinNoAck, "TCP FIN no ACK"},
			{dataplane.GlobalCtrScreenWinNuke, "WinNuke"},
			{dataplane.GlobalCtrScreenIPSrcRoute, "IP source route"},
			{dataplane.GlobalCtrScreenSynFrag, "SYN fragment"},
		}
		for _, sc := range screenCounters {
			v := readCounter(sc.idx)
			if v > 0 {
				fmt.Printf("    %-28s %d\n", sc.name+":", v)
			}
		}
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
		for name, inst := range cfg.ForwardingOptions.Sampling.Instances {
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
						tmplStr = fmt.Sprintf(" (template: %s)", fs.Version9Template)
					}
					fmt.Printf("    Collector: %s%s%s\n", fs.Address, portStr, tmplStr)
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
