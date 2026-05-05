package main

import (
	"fmt"
	"strconv"
	"strings"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (c *ctl) handleShow(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show: specify what to show", "show")
		return nil
	}

	switch args[0] {
	case "chassis":
		if len(args) >= 2 {
			switch args[1] {
			case "cluster":
				if len(args) >= 3 {
					switch args[2] {
					case "status":
						return c.showText("chassis-cluster-status")
					case "interfaces":
						return c.showText("chassis-cluster-interfaces")
					case "information":
						return c.showText("chassis-cluster-information")
					case "statistics":
						return c.showText("chassis-cluster-statistics")
					case "control-plane":
						if len(args) >= 4 && args[3] == "statistics" {
							return c.showText("chassis-cluster-control-plane-statistics")
						}
						return c.showText("chassis-cluster-control-plane-statistics")
					case "data-plane":
						if len(args) >= 4 {
							switch args[3] {
							case "statistics":
								return c.showText("chassis-cluster-data-plane-statistics")
							case "interfaces":
								return c.showText("chassis-cluster-data-plane-interfaces")
							}
						}
						return c.showText("chassis-cluster-data-plane-statistics")
					case "ip-monitoring":
						if len(args) >= 4 && args[3] == "status" {
							return c.showText("chassis-cluster-ip-monitoring-status")
						}
						return c.showText("chassis-cluster-ip-monitoring-status")
					case "fabric":
						if len(args) >= 4 && args[3] == "statistics" {
							return c.showText("chassis-cluster-fabric-statistics")
						}
						return c.showText("chassis-cluster-fabric-statistics")
					}
				}
				return c.showText("chassis-cluster")
			case "environment":
				return c.showText("chassis-environment")
			case "forwarding":
				return c.showText("chassis-forwarding")
			case "hardware":
				return c.showText("chassis-hardware")
			}
		}
		return c.showText("chassis")

	case "configuration":
		format := pb.ConfigFormat_HIERARCHICAL
		rest := strings.Join(args[1:], " ")
		if strings.Contains(rest, "| display json") {
			format = pb.ConfigFormat_JSON
		} else if strings.Contains(rest, "| display set") {
			format = pb.ConfigFormat_SET
		} else if strings.Contains(rest, "| display xml") {
			format = pb.ConfigFormat_XML
		} else if strings.Contains(rest, "| display inheritance") {
			format = pb.ConfigFormat_INHERITANCE
		} else if idx := strings.Index(rest, "| "); idx >= 0 {
			pipeParts := strings.Fields(strings.TrimSpace(rest[idx+2:]))
			if len(pipeParts) >= 2 && pipeParts[0] == "display" {
				fmt.Printf("syntax error: unknown display option '%s'\n", pipeParts[1])
			} else if len(pipeParts) > 0 {
				fmt.Printf("syntax error: unknown pipe command '%s'\n", pipeParts[0])
			}
			return nil
		}
		var path []string
		for _, a := range args[1:] {
			if a == "|" {
				break
			}
			path = append(path, a)
		}
		resp, err := c.client.ShowConfig(c.ctx(), &pb.ShowConfigRequest{
			Format: format,
			Target: pb.ConfigTarget_ACTIVE,
			Path:   path,
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		if resp.Output == "" && len(path) > 0 {
			fmt.Printf("configuration path not found: %s\n", strings.Join(path, " "))
		} else {
			fmt.Print(resp.Output)
		}
		return nil

	case "class-of-service":
		if len(args) >= 2 && args[1] == "interface" {
			topic := "class-of-service"
			if len(args) >= 3 {
				topic += ":" + args[2]
			}
			return c.showText(topic)
		}
		printRemoteTreeHelp("show class-of-service:", "show", "class-of-service")
		return nil

	case "dhcp":
		if len(args) >= 2 {
			switch args[1] {
			case "leases":
				return c.showDHCPLeases()
			case "client-identifier":
				return c.showDHCPClientIdentifier()
			}
		}
		printRemoteTreeHelp("show dhcp:", "show", "dhcp")
		return nil

	case "route":
		if len(args) >= 2 && args[1] == "terse" {
			return c.showText("route-terse")
		}
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("route-detail")
		}
		if len(args) >= 2 && args[1] == "summary" {
			return c.showText("route-summary")
		}
		if len(args) >= 3 && args[1] == "instance" {
			return c.showTextFiltered("route-instance", args[2])
		}
		if len(args) >= 3 && args[1] == "table" {
			return c.showText("route-table:" + args[2])
		}
		if len(args) >= 3 && args[1] == "protocol" {
			return c.showText("route-protocol:" + args[2])
		}
		if len(args) >= 2 && (strings.Contains(args[1], "/") || strings.Contains(args[1], ".") || strings.Contains(args[1], ":")) {
			topic := "route-prefix:" + args[1]
			if len(args) >= 3 {
				switch args[2] {
				case "exact", "longer", "orlonger":
					topic += " " + args[2]
				}
			}
			return c.showText(topic)
		}
		return c.showRoutes()

	case "security":
		return c.handleShowSecurity(args[1:])

	case "interfaces":
		return c.showInterfaces(args[1:])

	case "protocols":
		return c.handleShowProtocols(args[1:])

	case "system":
		return c.handleShowSystem(args[1:])

	case "schedulers":
		return c.showText("schedulers")

	case "snmp":
		if len(args) >= 2 && args[1] == "v3" {
			return c.showText("snmp-v3")
		}
		return c.showText("snmp")

	case "lldp":
		if len(args) >= 2 && args[1] == "neighbors" {
			return c.showText("lldp-neighbors")
		}
		return c.showText("lldp")

	case "dhcp-relay":
		return c.showText("dhcp-relay")

	case "dhcp-server":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("dhcp-server-detail")
		}
		return c.showText("dhcp-server")

	case "firewall":
		if len(args) >= 3 && args[1] == "filter" {
			topic := "firewall-filter:" + args[2]
			if len(args) >= 5 && args[3] == "family" {
				topic += ":" + args[4]
			}
			return c.showText(topic)
		}
		return c.showText("firewall")

	case "flow-monitoring":
		return c.showText("flow-monitoring")

	case "log":
		if len(args) > 1 {
			return c.showText("log:" + strings.Join(args[1:], ":"))
		}
		return c.showText("log")

	case "services":
		return c.handleShowServices(args[1:])

	case "version":
		return c.showText("version")

	case "arp":
		return c.showSystemInfo("arp")

	case "ipv6":
		if len(args) >= 2 && args[1] == "neighbors" {
			return c.showSystemInfo("ipv6-neighbors")
		}
		if len(args) >= 2 && args[1] == "router-advertisement" {
			return c.showText("ipv6-router-advertisement")
		}
		printRemoteTreeHelp("show ipv6:", "show", "ipv6")
		return nil

	case "policy-options":
		return c.showText("policy-options")

	case "route-map":
		return c.showText("route-map")

	case "event-options":
		return c.showText("event-options")

	case "routing-options":
		return c.showText("routing-options")

	case "routing-instances":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("routing-instances-detail")
		}
		return c.showText("routing-instances")

	case "forwarding-options":
		if len(args) >= 2 && args[1] == "port-mirroring" {
			return c.showText("forwarding-options-port-mirroring")
		}
		return c.showText("forwarding-options")

	case "vlans":
		return c.showText("vlans")

	case "task":
		return c.showText("task")

	case "monitor":
		if len(args) >= 3 && args[1] == "security" && args[2] == "flow" {
			return c.showText("monitor-security-flow")
		}
		printRemoteTreeHelp("show monitor:", "show", "monitor")
		return nil

	default:
		return fmt.Errorf("unknown show target: %s", args[0])
	}
}

func (c *ctl) handleShowServices(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show services:", "show", "services")
		return nil
	}
	switch args[0] {
	case "rpm":
		return c.showText("rpm")
	case "application-identification":
		// #653: surface what xpf AppID actually does today. Per
		// cmdtree the only valid leaf is `application-identification
		// status`; reject anything else so typos surface as usage
		// errors instead of being silently swallowed.
		rest := args[1:]
		if len(rest) == 0 {
			printRemoteTreeHelp("show services application-identification:",
				"show", "services", "application-identification")
			return nil
		}
		if rest[0] != "status" {
			return fmt.Errorf("unknown application-identification target: %s "+
				"(expected `status`)", rest[0])
		}
		return c.showText("application-identification-status")
	default:
		return fmt.Errorf("unknown services target: %s", args[0])
	}
}

func (c *ctl) handleShowSecurity(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show security:", "show", "security")
		return nil
	}

	switch args[0] {
	case "zones":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("zones-detail")
		}
		return c.showZones()
	case "policies":
		if len(args) >= 2 && args[1] == "brief" {
			return c.showPoliciesBrief()
		}
		if len(args) >= 2 && args[1] == "detail" {
			var filterParts []string
			for i := 2; i+1 < len(args); i++ {
				if args[i] == "from-zone" || args[i] == "to-zone" {
					filterParts = append(filterParts, args[i], args[i+1])
					i++
				}
			}
			return c.showTextFiltered("policies-detail", strings.Join(filterParts, " "))
		}
		if len(args) >= 2 && args[1] == "hit-count" {
			var filterParts []string
			for i := 2; i+1 < len(args); i++ {
				if args[i] == "from-zone" || args[i] == "to-zone" {
					filterParts = append(filterParts, args[i], args[i+1])
					i++
				}
			}
			return c.showTextFiltered("policies-hit-count", strings.Join(filterParts, " "))
		}
		var fromZone, toZone string
		for i := 1; i+1 < len(args); i++ {
			switch args[i] {
			case "from-zone":
				i++
				fromZone = args[i]
			case "to-zone":
				i++
				toZone = args[i]
			}
		}
		return c.showPoliciesFiltered(fromZone, toZone)
	case "screen":
		if len(args) >= 2 && args[1] == "ids-option" && len(args) >= 3 {
			if len(args) >= 4 && args[3] == "detail" {
				return c.showText("screen-ids-option-detail:" + args[2])
			}
			return c.showText("screen-ids-option:" + args[2])
		}
		if len(args) >= 2 && args[1] == "statistics" {
			if len(args) >= 4 && args[2] == "zone" {
				return c.showText("screen-statistics:" + args[3])
			}
			return c.showText("screen-statistics-all")
		}
		return c.showScreen()
	case "flow":
		if len(args) >= 2 && args[1] == "session" {
			return c.showFlowSession(args[2:])
		}
		if len(args) >= 2 && args[1] == "traceoptions" {
			return c.showText("flow-traceoptions")
		}
		if len(args) >= 2 && args[1] == "statistics" {
			return c.showText("flow-statistics")
		}
		if len(args) == 1 {
			return c.showText("flow-timeouts")
		}
		return fmt.Errorf("usage: show security flow {session|statistics|traceoptions}")
	case "nat":
		return c.handleShowNAT(args[1:])
	case "log":
		return c.showEvents(args[1:])
	case "statistics":
		detail := len(args) >= 2 && args[1] == "detail"
		return c.showStatistics(detail)
	case "ipsec":
		return c.showIPsec(args[1:])
	case "ike":
		return c.showIKE(args[1:])
	case "match-policies":
		return c.showMatchPolicies(args[1:])
	case "vrrp":
		return c.showVRRP()
	case "alarms":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("security-alarms-detail")
		}
		return c.showText("security-alarms")
	case "alg":
		return c.showText("alg")
	case "dynamic-address":
		return c.showText("dynamic-address")
	case "address-book":
		return c.showText("address-book")
	case "applications":
		return c.showText("applications")
	default:
		return fmt.Errorf("unknown show security target: %s", args[0])
	}
}

func (c *ctl) showZones() error {
	resp, err := c.client.GetZones(c.ctx(), &pb.GetZonesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	polResp, _ := c.client.GetPolicies(c.ctx(), &pb.GetPoliciesRequest{})

	for _, z := range resp.Zones {
		if z.Id > 0 {
			fmt.Printf("Zone: %s (id: %d)\n", z.Name, z.Id)
		} else {
			fmt.Printf("Zone: %s\n", z.Name)
		}
		if z.Description != "" {
			fmt.Printf("  Description: %s\n", z.Description)
		}
		fmt.Printf("  Interfaces: %s\n", strings.Join(z.Interfaces, ", "))
		if z.TcpRst {
			fmt.Println("  TCP RST: enabled")
		}
		if z.ScreenProfile != "" {
			fmt.Printf("  Screen: %s\n", z.ScreenProfile)
		}
		if len(z.HostInboundServices) > 0 {
			fmt.Printf("  Host-inbound services: %s\n", strings.Join(z.HostInboundServices, ", "))
		}
		if z.IngressPackets > 0 || z.EgressPackets > 0 {
			fmt.Println("  Traffic statistics:")
			fmt.Printf("    Input:  %d packets, %d bytes\n", z.IngressPackets, z.IngressBytes)
			fmt.Printf("    Output: %d packets, %d bytes\n", z.EgressPackets, z.EgressBytes)
		}

		if polResp != nil {
			var refs []string
			for _, pi := range polResp.Policies {
				if pi.FromZone == z.Name || pi.ToZone == z.Name {
					dir := "from"
					peer := pi.ToZone
					if pi.ToZone == z.Name {
						dir = "to"
						peer = pi.FromZone
					}
					refs = append(refs, fmt.Sprintf("%s %s (%d rules)", dir, peer, len(pi.Rules)))
				}
			}
			if len(refs) > 0 {
				fmt.Printf("  Policies: %s\n", strings.Join(refs, ", "))
			}
		}

		fmt.Println()
	}
	return nil
}

func (c *ctl) showPoliciesFiltered(fromZone, toZone string) error {
	resp, err := c.client.GetPolicies(c.ctx(), &pb.GetPoliciesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for _, pi := range resp.Policies {
		if fromZone != "" && pi.FromZone != fromZone {
			continue
		}
		if toZone != "" && pi.ToZone != toZone {
			continue
		}
		fmt.Printf("From zone: %s, To zone: %s\n", pi.FromZone, pi.ToZone)
		for _, rule := range pi.Rules {
			fmt.Printf("  Rule: %s\n", rule.Name)
			if rule.Description != "" {
				fmt.Printf("    Description: %s\n", rule.Description)
			}
			fmt.Printf("    Match: src=%v dst=%v app=%v\n",
				rule.SrcAddresses, rule.DstAddresses, rule.Applications)
			fmt.Printf("    Action: %s\n", rule.Action)
			if rule.HitPackets > 0 || rule.HitBytes > 0 {
				fmt.Printf("    Hit count: %d packets, %d bytes\n", rule.HitPackets, rule.HitBytes)
			}
		}
		fmt.Println()
	}
	return nil
}

func (c *ctl) showScreen() error {
	return c.showText("screen")
}

func (c *ctl) showFlowSession(args []string) error {
	req := &pb.GetSessionsRequest{Limit: 100, IncludePeer: true}
	brief := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 < len(args) {
				i++
				if v, err := strconv.ParseUint(args[i], 10, 32); err == nil {
					req.Zone = uint32(v)
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				req.Protocol = strings.ToUpper(args[i])
			}
		case "source-prefix":
			if i+1 < len(args) {
				i++
				req.SourcePrefix = args[i]
			}
		case "destination-prefix":
			if i+1 < len(args) {
				i++
				req.DestinationPrefix = args[i]
			}
		case "source-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.ParseUint(args[i], 10, 32); err == nil {
					req.SourcePort = uint32(v)
				}
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.ParseUint(args[i], 10, 32); err == nil {
					req.DestinationPort = uint32(v)
				}
			}
		case "nat":
			req.NatOnly = true
		case "limit":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.Limit = int32(v)
				}
			}
		case "application":
			if i+1 < len(args) {
				i++
				req.Application = args[i]
			}
		case "summary":
			return c.showSessionSummary()
		case "brief":
			brief = true
		case "interface":
			if i+1 < len(args) {
				i++
			}
		case "sort-by":
			if i+1 < len(args) {
				i++
				return c.showText("sessions-top:" + args[i])
			}
		}
	}

	resp, err := c.client.GetSessions(c.ctx(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	hasPeer := resp.Peer != nil

	if hasPeer {
		printNodeSessionHeader(int(resp.NodeId))
	}
	printSessionEntries(resp, brief)

	if hasPeer {
		fmt.Println()
		printNodeSessionHeader(int(resp.Peer.NodeId))
		printSessionEntries(resp.Peer, brief)
	}
	return nil
}

func printNodeSessionHeader(nodeID int) {
	fmt.Printf("node%d:\n", nodeID)
	fmt.Println("--------------------------------------------------------------------------")
}

func printSessionEntries(resp *pb.GetSessionsResponse, brief bool) {
	if brief {
		fmt.Printf("%-5s %-22s %-22s %-5s %-20s %-3s %-5s %5s %s\n",
			"ID", "Source", "Destination", "Proto", "Zone", "NAT", "State", "Age", "Pkts(f/r)")
		for i, se := range resp.Sessions {
			inZone := se.IngressZoneName
			if inZone == "" {
				inZone = fmt.Sprintf("%d", se.IngressZone)
			}
			outZone := se.EgressZoneName
			if outZone == "" {
				outZone = fmt.Sprintf("%d", se.EgressZone)
			}
			natFlag := " "
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
			sid := se.SessionId
			if sid == 0 {
				sid = uint64(resp.Offset) + uint64(i) + 1
			}
			fmt.Printf("%-5d %-22s %-22s %-5s %-20s %-3s %-5s %5d %d/%d\n",
				sid,
				fmt.Sprintf("%s/%d", se.SrcAddr, se.SrcPort),
				fmt.Sprintf("%s/%d", se.DstAddr, se.DstPort),
				se.Protocol, inZone+"->"+outZone, natFlag,
				st, se.AgeSeconds,
				se.FwdPackets, se.RevPackets)
		}
		fmt.Printf("Total sessions: %d\n", resp.Total)
		return
	}

	for i, se := range resp.Sessions {
		polDisplay := se.PolicyName
		if polDisplay == "" {
			polDisplay = fmt.Sprintf("%d", se.PolicyId)
		}
		sid := se.SessionId
		if sid == 0 {
			sid = uint64(resp.Offset) + uint64(i) + 1
		}

		haStr := ""
		if se.HaActive {
			haStr = "Active"
		} else {
			haStr = "Backup"
		}
		fmt.Printf("Session ID: %d, Policy name: %s/%d, HA State: %s, Timeout: %d, Session State: Valid\n",
			sid, polDisplay, se.PolicyId, haStr, se.TimeoutSeconds)

		inIf := se.IngressInterface
		if inIf == "" {
			inIf = se.IngressZoneName
		}
		inZone := se.IngressZoneName
		if inZone == "" {
			inZone = fmt.Sprintf("%d", se.IngressZone)
		}
		fmt.Printf("  In: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Zone: %s, Pkts: %d, Bytes: %d,\n",
			se.SrcAddr, se.SrcPort, se.DstAddr, se.DstPort,
			se.Protocol, inIf, inZone, se.FwdPackets, se.FwdBytes)

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
		outIf := se.EgressInterface
		if outIf == "" {
			outIf = se.EgressZoneName
		}
		outZone := se.EgressZoneName
		if outZone == "" {
			outZone = fmt.Sprintf("%d", se.EgressZone)
		}
		fmt.Printf("  Out: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Zone: %s, Pkts: %d, Bytes: %d,\n",
			outSrcAddr, outSrcPort, outDstAddr, outDstPort,
			se.Protocol, outIf, outZone, se.RevPackets, se.RevBytes)
		fmt.Println()
	}
	fmt.Printf("Total sessions: %d\n", resp.Total)
}

func (c *ctl) showSessionSummary() error {
	resp, err := c.client.GetSessionSummary(c.ctx(), &pb.GetSessionSummaryRequest{IncludePeer: true})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	if resp.Peer != nil {
		printNodeSessionSummary(int(resp.NodeId), resp)
		fmt.Println()
		printNodeSessionSummary(int(resp.Peer.NodeId), resp.Peer)
	} else {
		printSessionSummaryBlock(resp)
	}
	return nil
}

func printNodeSessionSummary(nodeID int, resp *pb.GetSessionSummaryResponse) {
	fmt.Printf("node%d:\n", nodeID)
	fmt.Println("--------------------------------------------------------------------------")
	printSessionSummaryBlock(resp)
}

func printSessionSummaryBlock(resp *pb.GetSessionSummaryResponse) {
	unicast := resp.ForwardOnly
	fmt.Printf("Unicast-sessions: %d\n", unicast)
	fmt.Printf("Multicast-sessions: 0\n")
	fmt.Printf("Services-offload-sessions: 0\n")
	fmt.Printf("Failed-sessions: 0\n")
	fmt.Printf("Sessions-in-drop-flow: 0\n")
	fmt.Printf("Sessions-in-use: %d\n", unicast)
	fmt.Printf("  Valid sessions: %d\n", unicast)
	fmt.Printf("  Pending sessions: 0\n")
	fmt.Printf("  Invalidated sessions: 0\n")
	fmt.Printf("  Sessions in other states: 0\n")
	fmt.Printf("Maximum-sessions: 10000000\n")
}

func (c *ctl) handleShowNAT(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show security nat:", "show", "security", "nat")
		return nil
	}
	switch args[0] {
	case "static":
		return c.showText("nat-static")
	case "nptv6":
		return c.showText("nat-nptv6")
	case "source":
		if len(args) >= 2 && args[1] == "summary" {
			return c.showNATSourceSummary()
		}
		if len(args) >= 2 && args[1] == "pool" {
			return c.showNATPoolStats()
		}
		if len(args) >= 3 && args[1] == "persistent-nat-table" && args[2] == "detail" {
			return c.showText("persistent-nat-detail")
		}
		if len(args) >= 2 && args[1] == "persistent-nat-table" {
			return c.showText("persistent-nat")
		}
		if len(args) >= 3 && args[1] == "rule" && args[2] == "detail" {
			return c.showText("nat-source-rule-detail")
		}
		if len(args) >= 2 && args[1] == "rule" {
			return c.showNATRuleStats("")
		}
		if len(args) >= 3 && args[1] == "rule-set" {
			return c.showNATRuleStats(args[2])
		}
		if len(args) >= 2 && args[1] == "rule-set" {
			return c.showNATRuleStats("")
		}
		resp, err := c.client.GetNATSource(c.ctx(), &pb.GetNATSourceRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		for _, r := range resp.Rules {
			fmt.Printf("  %s -> %s: %s", r.FromZone, r.ToZone, r.Type)
			if r.Pool != "" {
				fmt.Printf(" (pool: %s)", r.Pool)
			}
			fmt.Println()
		}
		return nil
	case "destination":
		if len(args) >= 2 && args[1] == "summary" {
			return c.showNATDestinationSummary()
		}
		if len(args) >= 2 && args[1] == "pool" {
			return c.showNATDestinationPool()
		}
		if len(args) >= 3 && args[1] == "rule" && args[2] == "detail" {
			return c.showText("nat-dest-rule-detail")
		}
		if len(args) >= 2 && args[1] == "rule" {
			return c.showNATDNATRuleStats("")
		}
		if len(args) >= 3 && args[1] == "rule-set" {
			return c.showNATDNATRuleStats(args[2])
		}
		if len(args) >= 2 && args[1] == "rule-set" {
			return c.showNATDNATRuleStats("")
		}
		resp, err := c.client.GetNATDestination(c.ctx(), &pb.GetNATDestinationRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		for _, r := range resp.Rules {
			fmt.Printf("  Rule: %s  dst=%s", r.Name, r.DstAddr)
			if r.DstPort > 0 {
				fmt.Printf(":%d", r.DstPort)
			}
			fmt.Printf(" -> %s", r.TranslateIp)
			if r.TranslatePort > 0 {
				fmt.Printf(":%d", r.TranslatePort)
			}
			fmt.Println()
		}
		return nil
	case "nat64":
		return c.showText("nat64")
	default:
		return fmt.Errorf("unknown show security nat target: %s", args[0])
	}
}

func (c *ctl) showMatchPolicies(args []string) error {
	req := &pb.MatchPoliciesRequest{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "from-zone":
			if i+1 < len(args) {
				i++
				req.FromZone = args[i]
			}
		case "to-zone":
			if i+1 < len(args) {
				i++
				req.ToZone = args[i]
			}
		case "source-ip":
			if i+1 < len(args) {
				i++
				req.SourceIp = args[i]
			}
		case "destination-ip":
			if i+1 < len(args) {
				i++
				req.DestinationIp = args[i]
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil {
					req.DestinationPort = int32(v)
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				req.Protocol = args[i]
			}
		}
	}

	if req.FromZone == "" || req.ToZone == "" {
		fmt.Println("usage: show security match-policies from-zone <zone> to-zone <zone>")
		fmt.Println("       source-ip <ip> destination-ip <ip> destination-port <port> protocol <tcp|udp>")
		return nil
	}

	resp, err := c.client.MatchPolicies(c.ctx(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	if resp.Matched {
		fmt.Printf("Matching policy:\n")
		fmt.Printf("  From zone: %s, To zone: %s\n", req.FromZone, req.ToZone)
		fmt.Printf("  Policy: %s\n", resp.PolicyName)
		fmt.Printf("    Source addresses: %v\n", resp.SrcAddresses)
		fmt.Printf("    Destination addresses: %v\n", resp.DstAddresses)
		fmt.Printf("    Applications: %v\n", resp.Applications)
		fmt.Printf("    Action: %s\n", resp.Action)
	} else {
		fmt.Printf("No matching policy found for %s -> %s (default deny)\n", req.FromZone, req.ToZone)
	}
	return nil
}

func (c *ctl) showVRRP() error {
	resp, err := c.client.GetVRRPStatus(c.ctx(), &pb.GetVRRPStatusRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	if len(resp.Instances) == 0 {
		fmt.Println("No VRRP groups configured")
		return nil
	}

	if resp.ServiceStatus != "" {
		fmt.Println(resp.ServiceStatus)
	}

	fmt.Printf("%-14s %-6s %-8s %-10s %-16s %-8s\n",
		"Interface", "Group", "State", "Priority", "VIP", "Preempt")
	for _, inst := range resp.Instances {
		preempt := "no"
		if inst.Preempt {
			preempt = "yes"
		}
		vip := strings.Join(inst.VirtualAddresses, ",")
		fmt.Printf("%-14s %-6d %-8s %-10d %-16s %-8s\n",
			inst.Interface, inst.GroupId, inst.State, inst.Priority, vip, preempt)
	}
	return nil
}

func (c *ctl) showNATSourceSummary() error {
	resp, err := c.client.GetNATPoolStats(c.ctx(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Printf("Total active translations: %d\n", resp.TotalActiveTranslations)
	fmt.Printf("Total pools: %d\n", len(resp.Pools))
	fmt.Println()
	fmt.Printf("%-20s %-20s %-8s %-8s %-12s %-12s\n",
		"Pool", "Address", "Ports", "Used", "Available", "Utilization")
	for _, p := range resp.Pools {
		ports := "N/A"
		avail := "N/A"
		util := "N/A"
		if !p.IsInterface {
			ports = fmt.Sprintf("%d", p.TotalPorts)
			avail = fmt.Sprintf("%d", p.AvailablePorts)
			util = p.Utilization
		}
		fmt.Printf("%-20s %-20s %-8s %-8d %-12s %-12s\n",
			p.Name, p.Address, ports, p.UsedPorts, avail, util)
	}
	if len(resp.RuleSetSessions) > 0 {
		fmt.Println()
		fmt.Printf("%-30s %-12s\n", "Rule-set (from -> to)", "Sessions")
		for _, rs := range resp.RuleSetSessions {
			fmt.Printf("%-30s %-12d\n",
				fmt.Sprintf("%s -> %s", rs.FromZone, rs.ToZone), rs.Sessions)
		}
	}
	return nil
}

func (c *ctl) showNATPoolStats() error {
	resp, err := c.client.GetNATPoolStats(c.ctx(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	for _, p := range resp.Pools {
		fmt.Printf("Pool name: %s\n", p.Name)
		fmt.Printf("  Address: %s\n", p.Address)
		if !p.IsInterface {
			fmt.Printf("  Ports allocated: %d\n", p.UsedPorts)
			fmt.Printf("  Ports available: %d\n", p.AvailablePorts)
			fmt.Printf("  Utilization: %s\n", p.Utilization)
		} else {
			fmt.Printf("  Active sessions: %d\n", p.UsedPorts)
		}
		fmt.Println()
	}
	return nil
}

func (c *ctl) showNATRuleStats(ruleSet string) error {
	resp, err := c.client.GetNATRuleStats(c.ctx(), &pb.GetNATRuleStatsRequest{
		RuleSet: ruleSet,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Rules) == 0 {
		if ruleSet != "" {
			fmt.Printf("Rule-set %q not found\n", ruleSet)
		} else {
			fmt.Println("No source NAT rules configured")
		}
		return nil
	}

	curRS := ""
	for _, r := range resp.Rules {
		if r.RuleSet != curRS {
			if curRS != "" {
				fmt.Println()
			}
			curRS = r.RuleSet
			fmt.Printf("Rule-set: %s\n", r.RuleSet)
			fmt.Printf("  From zone: %s  To zone: %s\n", r.FromZone, r.ToZone)
		}
		fmt.Printf("  Rule: %s\n", r.RuleName)
		fmt.Printf("    Match: source %s destination %s\n", r.SourceMatch, r.DestinationMatch)
		fmt.Printf("    Action: %s\n", r.Action)
		fmt.Printf("    Translation hits: %d packets  %d bytes\n", r.HitPackets, r.HitBytes)
	}
	fmt.Println()
	return nil
}

func (c *ctl) showNATDestinationSummary() error {
	resp, err := c.client.GetNATDestination(c.ctx(), &pb.GetNATDestinationRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Rules) == 0 {
		fmt.Println("No destination NAT pools configured")
		return nil
	}

	type poolInfo struct {
		addr string
		port uint32
	}
	pools := make(map[string]poolInfo)
	for _, r := range resp.Rules {
		if _, ok := pools[r.TranslateIp]; !ok {
			pools[r.TranslateIp] = poolInfo{addr: r.TranslateIp, port: r.TranslatePort}
		}
	}

	statsResp, err := c.client.GetNATRuleStats(c.ctx(), &pb.GetNATRuleStatsRequest{
		NatType: "destination",
	})
	poolHits := make(map[string]uint64)
	if err == nil {
		for _, r := range statsResp.Rules {
			poolHits[r.Action] += r.HitPackets
		}
	}

	fmt.Printf("Total active translations: %d\n", resp.TotalActiveTranslations)
	fmt.Printf("Total pools: %d\n", len(pools))
	fmt.Println()
	fmt.Printf("%-20s %-20s %-8s %-12s\n", "Pool", "Address", "Port", "Hits")
	for addr, p := range pools {
		portStr := "-"
		if p.port > 0 {
			portStr = fmt.Sprintf("%d", p.port)
		}
		fmt.Printf("%-20s %-20s %-8s %-12d\n", addr, addr, portStr, poolHits["pool "+addr])
	}
	if len(resp.RuleSetSessions) > 0 {
		fmt.Println()
		fmt.Printf("%-30s %-12s\n", "Rule-set (from -> to)", "Sessions")
		for _, rs := range resp.RuleSetSessions {
			fmt.Printf("%-30s %-12d\n",
				fmt.Sprintf("%s -> %s", rs.FromZone, rs.ToZone), rs.Sessions)
		}
	}
	return nil
}

func (c *ctl) showNATDestinationPool() error {
	resp, err := c.client.GetNATDestination(c.ctx(), &pb.GetNATDestinationRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Rules) == 0 {
		fmt.Println("No destination NAT pools configured")
		return nil
	}
	for _, r := range resp.Rules {
		fmt.Printf("Pool: %s\n", r.TranslateIp)
		fmt.Printf("  Address: %s\n", r.TranslateIp)
		if r.TranslatePort > 0 {
			fmt.Printf("  Port: %d\n", r.TranslatePort)
		}
		fmt.Printf("  Rule: %s (dst %s", r.Name, r.DstAddr)
		if r.DstPort > 0 {
			fmt.Printf(":%d", r.DstPort)
		}
		fmt.Println(")")
		fmt.Println()
	}
	return nil
}

func (c *ctl) showNATDNATRuleStats(ruleSet string) error {
	resp, err := c.client.GetNATRuleStats(c.ctx(), &pb.GetNATRuleStatsRequest{
		RuleSet: ruleSet,
		NatType: "destination",
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Rules) == 0 {
		if ruleSet != "" {
			fmt.Printf("Rule-set %q not found\n", ruleSet)
		} else {
			fmt.Println("No destination NAT rules configured")
		}
		return nil
	}

	curRS := ""
	for _, r := range resp.Rules {
		if r.RuleSet != curRS {
			if curRS != "" {
				fmt.Println()
			}
			curRS = r.RuleSet
			fmt.Printf("Rule-set: %s\n", r.RuleSet)
			fmt.Printf("  From zone: %s  To zone: %s\n", r.FromZone, r.ToZone)
		}
		fmt.Printf("  Rule: %s\n", r.RuleName)
		fmt.Printf("    Match destination: %s\n", r.DestinationMatch)
		fmt.Printf("    Action: %s\n", r.Action)
		fmt.Printf("    Translation hits: %d packets  %d bytes\n", r.HitPackets, r.HitBytes)
	}
	fmt.Println()
	return nil
}

func (c *ctl) showEvents(args []string) error {
	filter := ""
	for _, a := range args {
		if _, err := strconv.Atoi(a); err == nil {
			filter = a
			break
		}
	}
	return c.showTextFiltered("security-log", filter)
}

func (c *ctl) showStatistics(detail bool) error {
	resp, err := c.client.GetGlobalStats(c.ctx(), &pb.GetGlobalStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println("Global statistics:")
	fmt.Printf("  %-25s %d\n", "RX packets:", resp.RxPackets)
	fmt.Printf("  %-25s %d\n", "TX packets:", resp.TxPackets)
	fmt.Printf("  %-25s %d\n", "Drops:", resp.Drops)
	fmt.Printf("  %-25s %d\n", "Sessions created:", resp.SessionsCreated)
	fmt.Printf("  %-25s %d\n", "Sessions closed:", resp.SessionsClosed)
	fmt.Printf("  %-25s %d\n", "Screen drops:", resp.ScreenDrops)
	fmt.Printf("  %-25s %d\n", "Policy denies:", resp.PolicyDenies)
	fmt.Printf("  %-25s %d\n", "NAT alloc failures:", resp.NatAllocFailures)
	fmt.Printf("  %-25s %d\n", "Host-inbound denies:", resp.HostInboundDenies)
	fmt.Printf("  %-25s %d\n", "Host-inbound allowed:", resp.HostInboundAllowed)
	fmt.Printf("  %-25s %d\n", "TC egress packets:", resp.TcEgressPackets)
	fmt.Printf("  %-25s %d\n", "NAT64 translations:", resp.Nat64Translations)

	if !detail {
		return nil
	}

	if resp.ScreenDrops > 0 {
		fmt.Printf("\nScreen drop details:\n")
		for name, count := range resp.ScreenDropDetails {
			fmt.Printf("  %-25s %d\n", name+":", count)
		}
	}

	text, err := c.client.ShowText(c.ctx(), &pb.ShowTextRequest{Topic: "buffers"})
	if err == nil && text.Output != "" {
		fmt.Printf("\n%s", text.Output)
	}
	return nil
}

func (c *ctl) showFlowStatistics() error {
	resp, err := c.client.GetGlobalStats(c.ctx(), &pb.GetGlobalStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	fmt.Println("Flow statistics:")
	fmt.Printf("  %-30s %d\n", "Current sessions:", resp.SessionsCreated-resp.SessionsClosed)
	fmt.Printf("  %-30s %d\n", "Sessions created:", resp.SessionsCreated)
	fmt.Printf("  %-30s %d\n", "Sessions closed:", resp.SessionsClosed)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Packets received:", resp.RxPackets)
	fmt.Printf("  %-30s %d\n", "Packets transmitted:", resp.TxPackets)
	fmt.Printf("  %-30s %d\n", "Packets dropped:", resp.Drops)
	fmt.Printf("  %-30s %d\n", "TC egress packets:", resp.TcEgressPackets)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Policy deny:", resp.PolicyDenies)
	fmt.Printf("  %-30s %d\n", "NAT allocation failures:", resp.NatAllocFailures)
	fmt.Printf("  %-30s %d\n", "NAT64 translations:", resp.Nat64Translations)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Host-inbound allowed:", resp.HostInboundAllowed)
	fmt.Printf("  %-30s %d\n", "Host-inbound denied:", resp.HostInboundDenies)

	if resp.ScreenDrops > 0 {
		fmt.Println()
		fmt.Printf("  %-30s %d\n", "Screen drops (total):", resp.ScreenDrops)
		for name, count := range resp.ScreenDropDetails {
			fmt.Printf("    %-28s %d\n", name+":", count)
		}
	}

	return nil
}

func (c *ctl) showIKE(args []string) error {
	if len(args) > 0 && args[0] == "security-associations" {
		resp, err := c.client.GetIPsecSA(c.ctx(), &pb.GetIPsecSARequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		if resp.Output == "" {
			fmt.Println("No IKE security associations")
		} else {
			fmt.Print(resp.Output)
		}
		return nil
	}
	return c.showText("ike")
}

func (c *ctl) showIPsec(args []string) error {
	if len(args) > 0 && args[0] == "security-associations" {
		resp, err := c.client.GetIPsecSA(c.ctx(), &pb.GetIPsecSARequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	}
	if len(args) > 0 && args[0] == "statistics" {
		return c.showText("ipsec-statistics")
	}
	printRemoteTreeHelp("show security ipsec:", "show", "security", "ipsec")
	return nil
}

func (c *ctl) showInterfaces(args []string) error {
	if len(args) > 0 && args[0] == "tunnel" {
		return c.showText("tunnels")
	}
	if len(args) > 0 && args[0] == "extensive" {
		return c.showText("interfaces-extensive")
	}
	if len(args) > 0 && args[0] == "statistics" {
		return c.showText("interfaces-statistics")
	}
	if len(args) > 0 && args[0] == "detail" {
		return c.showText("interfaces-detail")
	}
	if len(args) >= 2 && args[len(args)-1] == "detail" {
		return c.showTextFiltered("interfaces-detail", args[0])
	}
	req := &pb.ShowInterfacesDetailRequest{}
	for _, a := range args {
		if a == "terse" {
			req.Terse = true
		} else {
			req.Filter = a
		}
	}
	resp, err := c.client.ShowInterfacesDetail(c.ctx(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) showDHCPLeases() error {
	resp, err := c.client.GetDHCPLeases(c.ctx(), &pb.GetDHCPLeasesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Leases) == 0 {
		fmt.Println("No active DHCP leases")
		return nil
	}
	fmt.Println("DHCP leases:")
	for _, l := range resp.Leases {
		fmt.Printf("  Interface: %s, Family: %s\n", l.Interface, l.Family)
		fmt.Printf("    Address:   %s\n", l.Address)
		if l.Gateway != "" {
			fmt.Printf("    Gateway:   %s\n", l.Gateway)
		}
		if len(l.Dns) > 0 {
			fmt.Printf("    DNS:       %s\n", strings.Join(l.Dns, ", "))
		}
		fmt.Printf("    Lease:     %s\n", l.LeaseTime)
		fmt.Printf("    Obtained:  %s\n", l.Obtained)
		if len(l.DelegatedPrefixes) > 0 {
			fmt.Println("    Delegated prefixes:")
			for _, dp := range l.DelegatedPrefixes {
				fmt.Printf("      Prefix:    %s\n", dp.Prefix)
				fmt.Printf("      Preferred: %s\n", dp.PreferredLifetime)
				fmt.Printf("      Valid:     %s\n", dp.ValidLifetime)
			}
		}
		fmt.Println()
	}
	return nil
}

func (c *ctl) showDHCPClientIdentifier() error {
	resp, err := c.client.GetDHCPClientIdentifiers(c.ctx(), &pb.GetDHCPClientIdentifiersRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if len(resp.Identifiers) == 0 {
		fmt.Println("No DHCPv6 DUIDs configured")
		return nil
	}
	fmt.Println("DHCPv6 client identifiers:")
	for _, d := range resp.Identifiers {
		fmt.Printf("  Interface: %s\n", d.Interface)
		fmt.Printf("    Type:    %s\n", d.Type)
		fmt.Printf("    DUID:    %s\n", d.Display)
		fmt.Printf("    Hex:     %s\n", d.Hex)
		fmt.Println()
	}
	return nil
}

func (c *ctl) showRoutes() error {
	return c.showText("route-all")
}

func (c *ctl) handleShowProtocols(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show protocols:", "show", "protocols")
		return nil
	}
	switch args[0] {
	case "ospf":
		typ := "neighbor"
		if len(args) >= 2 {
			typ = args[1]
			if typ == "neighbor" && len(args) >= 3 && args[2] == "detail" {
				typ = "neighbor-detail"
			}
		}
		resp, err := c.client.GetOSPFStatus(c.ctx(), &pb.GetOSPFStatusRequest{Type: typ})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	case "bgp":
		typ := "summary"
		if len(args) >= 2 {
			typ = args[1]
			if typ == "neighbor" && len(args) >= 3 {
				ip := args[2]
				if len(args) >= 4 {
					switch args[3] {
					case "received-routes":
						typ = "received-routes:" + ip
					case "advertised-routes":
						typ = "advertised-routes:" + ip
					default:
						typ = "neighbor:" + ip
					}
				} else {
					typ = "neighbor:" + ip
				}
			}
		}
		resp, err := c.client.GetBGPStatus(c.ctx(), &pb.GetBGPStatusRequest{Type: typ})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	case "bfd":
		if len(args) >= 2 && args[1] == "peers" {
			return c.showText("bfd-peers")
		}
		printRemoteTreeHelp("show protocols bfd:", "show", "protocols", "bfd")
		return nil
	case "rip":
		resp, err := c.client.GetRIPStatus(c.ctx(), &pb.GetRIPStatusRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	case "isis":
		typ := "adjacency"
		if len(args) >= 2 {
			typ = args[1]
			if typ == "adjacency" && len(args) >= 3 && args[2] == "detail" {
				typ = "adjacency-detail"
			}
		}
		resp, err := c.client.GetISISStatus(c.ctx(), &pb.GetISISStatusRequest{Type: typ})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	default:
		return fmt.Errorf("unknown show protocols target: %s", args[0])
	}
}

func (c *ctl) handleShowSystem(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("show system:", "show", "system")
		return nil
	}

	switch args[0] {
	case "commit":
		if len(args) >= 2 && args[1] == "history" {
			return c.showText("commit-history")
		}
		printRemoteTreeHelp("show system commit:", "show", "system", "commit")
		return nil

	case "rollback":
		if len(args) >= 2 {
			if args[1] == "compare" && len(args) >= 3 {
				n, err := strconv.Atoi(args[2])
				if err != nil || n < 1 {
					return fmt.Errorf("usage: show system rollback compare <N>")
				}
				resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{
					RollbackN: int32(n),
				})
				if err != nil {
					return fmt.Errorf("%v", err)
				}
				if resp.Output == "" {
					fmt.Println("No differences found")
				} else {
					fmt.Print(resp.Output)
				}
				return nil
			}

			n, err := strconv.Atoi(args[1])
			if err != nil || n < 1 {
				return fmt.Errorf("usage: show system rollback <N>")
			}
			format := pb.ConfigFormat_HIERARCHICAL
			rest := strings.Join(args[2:], " ")
			if strings.Contains(rest, "| display set") {
				format = pb.ConfigFormat_SET
			} else if strings.Contains(rest, "| display xml") {
				format = pb.ConfigFormat_XML
			} else if strings.Contains(rest, "compare") {
				resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{
					RollbackN: int32(n),
				})
				if err != nil {
					return fmt.Errorf("%v", err)
				}
				if resp.Output == "" {
					fmt.Println("No differences found")
				} else {
					fmt.Print(resp.Output)
				}
				return nil
			}
			resp, err := c.client.ShowRollback(c.ctx(), &pb.ShowRollbackRequest{
				N:      int32(n),
				Format: format,
			})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Print(resp.Output)
			return nil
		}

		resp, err := c.client.ListHistory(c.ctx(), &pb.ListHistoryRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		if len(resp.Entries) == 0 {
			fmt.Println("No rollback history available")
			return nil
		}
		for _, e := range resp.Entries {
			fmt.Printf("  rollback %d: %s\n", e.Index, e.Timestamp)
		}
		return nil

	case "uptime":
		return c.showSystemInfo("uptime")
	case "memory":
		return c.showSystemInfo("memory")
	case "storage":
		return c.showText("storage")
	case "processes":
		return c.showSystemInfo("processes")
	case "alarms":
		return c.showText("alarms")
	case "users":
		return c.showSystemInfo("users")
	case "connections":
		return c.showSystemInfo("connections")
	case "license":
		fmt.Println("License: open-source (no license required)")
		return nil
	case "services":
		return c.showText("system-services")
	case "ntp":
		return c.showText("ntp")
	case "login":
		return c.showText("login")
	case "syslog":
		return c.showText("system-syslog")
	case "internet-options":
		return c.showText("internet-options")
	case "root-authentication":
		return c.showText("root-authentication")
	case "backup-router":
		return c.showText("backup-router")
	case "buffers":
		if len(args) >= 2 && args[1] == "detail" {
			return c.showText("buffers-detail")
		}
		return c.showText("buffers")
	case "boot-messages":
		return c.showSystemInfo("boot-messages")
	case "core-dumps":
		return c.showText("core-dumps")
	default:
		return fmt.Errorf("unknown show system target: %s", args[0])
	}
}

func (c *ctl) handleConfigShow(args []string) error {
	line := strings.Join(args, " ")

	if strings.Contains(line, "| compare") {
		if idx := strings.Index(line, "| compare rollback"); idx >= 0 {
			rest := strings.TrimSpace(line[idx+len("| compare rollback"):])
			n, err := strconv.Atoi(rest)
			if err != nil || n < 1 {
				return fmt.Errorf("usage: show | compare rollback <N>")
			}
			resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{RollbackN: int32(n)})
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			fmt.Print(resp.Output)
			return nil
		}
		resp, err := c.client.ShowCompare(c.ctx(), &pb.ShowCompareRequest{})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Print(resp.Output)
		return nil
	}

	format := pb.ConfigFormat_HIERARCHICAL
	if strings.Contains(line, "| display json") {
		format = pb.ConfigFormat_JSON
	} else if strings.Contains(line, "| display set") {
		format = pb.ConfigFormat_SET
	} else if strings.Contains(line, "| display xml") {
		format = pb.ConfigFormat_XML
	} else if strings.Contains(line, "| display inheritance") {
		format = pb.ConfigFormat_INHERITANCE
	} else if idx := strings.Index(line, "| "); idx >= 0 {
		pipeParts := strings.Fields(strings.TrimSpace(line[idx+2:]))
		if len(pipeParts) >= 2 && pipeParts[0] == "display" {
			fmt.Printf("syntax error: unknown display option '%s'\n", pipeParts[1])
		} else if len(pipeParts) > 0 {
			fmt.Printf("syntax error: unknown pipe command '%s'\n", pipeParts[0])
		}
		return nil
	}
	var path []string
	if len(c.editPath) > 0 {
		path = append(path, c.editPath...)
	}
	for _, a := range args {
		if a == "|" {
			break
		}
		path = append(path, a)
	}
	resp, err := c.client.ShowConfig(c.ctx(), &pb.ShowConfigRequest{
		Format: format,
		Target: pb.ConfigTarget_CANDIDATE,
		Path:   path,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

// --- Generic show helpers ---

func (c *ctl) showText(topic string) error {
	return c.showTextFiltered(topic, "")
}

func (c *ctl) showTextFiltered(topic, filter string) error {
	resp, err := c.client.ShowText(c.ctx(), &pb.ShowTextRequest{
		Topic:  topic,
		Filter: filter,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) showSystemInfo(typ string) error {
	resp, err := c.client.GetSystemInfo(c.ctx(), &pb.GetSystemInfoRequest{Type: typ})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Print(resp.Output)
	return nil
}

func (c *ctl) showPoliciesBrief() error {
	resp, err := c.client.GetPolicies(c.ctx(), &pb.GetPoliciesRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
		"From", "To", "Name", "Action", "Hits")
	for _, pi := range resp.Policies {
		for _, rule := range pi.Rules {
			hits := "-"
			if rule.HitPackets > 0 {
				hits = fmt.Sprintf("%d", rule.HitPackets)
			}
			fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
				pi.FromZone, pi.ToZone, rule.Name, rule.Action, hits)
		}
	}
	return nil
}
