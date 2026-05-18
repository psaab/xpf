package cli

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/logging"
)

func (c *CLI) showPoliciesHitCount(cfg *config.Config, fromZone, toZone string) error {
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("dataplane not loaded")
		return nil
	}

	fmt.Println("Logical system: root-logical-system")
	fmt.Printf("%-8s%-17s%-18s%-24s%-14s%s\n",
		"Index", "From zone", "To zone", "Name", "Policy count", "Action")

	index := uint32(1)
	policySetID := uint32(0)
	for _, zpp := range cfg.Security.Policies {
		if fromZone != "" && zpp.FromZone != fromZone {
			policySetID++
			continue
		}
		if toZone != "" && zpp.ToZone != toZone {
			policySetID++
			continue
		}
		for i, pol := range zpp.Policies {
			action := "Permit"
			switch pol.Action {
			case 1:
				action = "Deny"
			case 2:
				action = "Reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			var count uint64
			if counters, err := c.dp.ReadPolicyCounters(ruleID); err == nil {
				count = counters.Packets
			}
			fmt.Printf("%-8d%-17s%-18s%-24s%-14d%s\n",
				index, zpp.FromZone, zpp.ToZone, pol.Name, count, action)
			index++
		}
		policySetID++
	}
	// Global policies
	if len(cfg.Security.GlobalPolicies) > 0 && fromZone == "" && toZone == "" {
		for i, pol := range cfg.Security.GlobalPolicies {
			action := "Permit"
			switch pol.Action {
			case 1:
				action = "Deny"
			case 2:
				action = "Reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			var count uint64
			if counters, err := c.dp.ReadPolicyCounters(ruleID); err == nil {
				count = counters.Packets
			}
			fmt.Printf("%-8d%-17s%-18s%-24s%-14d%s\n",
				index, "junos-global", "junos-global", pol.Name, count, action)
			index++
		}
	}
	return nil
}

// showPoliciesDetail displays an expanded Junos-style detail view of security policies.

func (c *CLI) showPoliciesDetail(cfg *config.Config, fromZone, toZone string) error {
	policySetID := uint32(0)
	seqNum := 1
	for _, zpp := range cfg.Security.Policies {
		if fromZone != "" && zpp.FromZone != fromZone {
			policySetID++
			continue
		}
		if toZone != "" && zpp.ToZone != toZone {
			policySetID++
			continue
		}
		for i, pol := range zpp.Policies {
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			fmt.Printf("Policy: %s, action-type: %s, State: enabled, Index: %d, Scope Policy: 0\n",
				pol.Name, action, ruleID)
			fmt.Printf("  Policy Type: Configured\n")
			fmt.Printf("  Sequence number: %d\n", seqNum)
			fmt.Printf("  From zone: %s, To zone: %s\n", zpp.FromZone, zpp.ToZone)
			if pol.Description != "" {
				fmt.Printf("  Description: %s\n", pol.Description)
			}
			fmt.Printf("  Source addresses:\n")
			for _, addr := range pol.Match.SourceAddresses {
				if addr == "any" {
					fmt.Printf("    any-ipv4(global): 0.0.0.0/0\n")
					fmt.Printf("    any-ipv6(global): ::/0\n")
				} else {
					resolved := resolveAddressDetail(cfg, addr)
					fmt.Printf("    %s(global): %s\n", addr, resolved)
				}
			}
			fmt.Printf("  Destination addresses:\n")
			for _, addr := range pol.Match.DestinationAddresses {
				if addr == "any" {
					fmt.Printf("    any-ipv4(global): 0.0.0.0/0\n")
					fmt.Printf("    any-ipv6(global): ::/0\n")
				} else {
					resolved := resolveAddressDetail(cfg, addr)
					fmt.Printf("    %s(global): %s\n", addr, resolved)
				}
			}
			for _, app := range pol.Match.Applications {
				fmt.Printf("  Application: %s\n", app)
				c.printAppDetail(cfg, app)
			}
			if pol.Log != nil {
				parts := []string{}
				if pol.Log.SessionInit {
					parts = append(parts, "at-create")
				}
				if pol.Log.SessionClose {
					parts = append(parts, "at-close")
				}
				if len(parts) > 0 {
					fmt.Printf("  Session log: %s\n", strings.Join(parts, ", "))
				}
			}
			seqNum++

			_ = ruleID // available for future counter display
		}
		policySetID++
		fmt.Println()
	}

	// Global policies
	if len(cfg.Security.GlobalPolicies) > 0 && fromZone == "" && toZone == "" {
		for i, pol := range cfg.Security.GlobalPolicies {
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
			fmt.Printf("Policy: %s, action-type: %s, State: enabled, Index: %d, Scope Policy: 0\n",
				pol.Name, action, ruleID)
			fmt.Printf("  Policy Type: Configured\n")
			fmt.Printf("  Sequence number: %d\n", seqNum)
			fmt.Printf("  From zone: junos-global, To zone: junos-global\n")
			if pol.Description != "" {
				fmt.Printf("  Description: %s\n", pol.Description)
			}
			fmt.Printf("  Source addresses:\n")
			for _, addr := range pol.Match.SourceAddresses {
				if addr == "any" {
					fmt.Printf("    any-ipv4(global): 0.0.0.0/0\n")
					fmt.Printf("    any-ipv6(global): ::/0\n")
				} else {
					resolved := resolveAddressDetail(cfg, addr)
					fmt.Printf("    %s(global): %s\n", addr, resolved)
				}
			}
			fmt.Printf("  Destination addresses:\n")
			for _, addr := range pol.Match.DestinationAddresses {
				if addr == "any" {
					fmt.Printf("    any-ipv4(global): 0.0.0.0/0\n")
					fmt.Printf("    any-ipv6(global): ::/0\n")
				} else {
					resolved := resolveAddressDetail(cfg, addr)
					fmt.Printf("    %s(global): %s\n", addr, resolved)
				}
			}
			for _, app := range pol.Match.Applications {
				fmt.Printf("  Application: %s\n", app)
				c.printAppDetail(cfg, app)
			}
			if pol.Log != nil {
				parts := []string{}
				if pol.Log.SessionInit {
					parts = append(parts, "at-create")
				}
				if pol.Log.SessionClose {
					parts = append(parts, "at-close")
				}
				if len(parts) > 0 {
					fmt.Printf("  Session log: %s\n", strings.Join(parts, ", "))
				}
			}
			seqNum++

			_ = ruleID
		}
		fmt.Println()
	}
	return nil
}

// resolveAddressDetail returns the CIDR for an address name, or the name itself if not found.

func (c *CLI) showZonesDisplay(cfg *config.Config, detail bool, filterZone string) error {
	// Sort zone names for stable output
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	cr := c.applyResult()

	for _, name := range zoneNames {
		if filterZone != "" && name != filterZone {
			continue
		}
		zone := cfg.Security.Zones[name]

		// Resolve zone ID for counter lookup
		var zoneID uint16
		if cr != nil {
			zoneID = cr.ZoneIDs[name]
		}

		// Junos format: "Security zone: <name>"
		fmt.Printf("Security zone: %s\n", name)
		if zoneID > 0 {
			fmt.Printf("  Zone ID: %d\n", zoneID)
		}
		if zone.Description != "" {
			fmt.Printf("  Description: %s\n", zone.Description)
		}
		tcpRstStr := "Off"
		if zone.TCPRst {
			tcpRstStr = "On"
		}
		fmt.Printf("  Send reset for non-SYN session TCP packets: %s\n", tcpRstStr)
		fmt.Printf("  Policy configurable: Yes\n")
		if zone.ScreenProfile != "" {
			fmt.Printf("  Screen: %s\n", zone.ScreenProfile)
		}
		fmt.Printf("  Interfaces bound: %d\n", len(zone.Interfaces))
		fmt.Printf("  Interfaces:\n")
		for _, ifName := range zone.Interfaces {
			fmt.Printf("    %s\n", ifName)
		}
		if zone.HostInboundTraffic != nil {
			if len(zone.HostInboundTraffic.SystemServices) > 0 {
				fmt.Printf("  Allowed host-inbound traffic: %s\n",
					strings.Join(zone.HostInboundTraffic.SystemServices, " "))
			}
			if len(zone.HostInboundTraffic.Protocols) > 0 {
				fmt.Printf("  Allowed host-inbound protocols: %s\n",
					strings.Join(zone.HostInboundTraffic.Protocols, " "))
			}
		}

		// Per-zone traffic counters (xpf extension, not in Junos)
		if c.dp != nil && c.dp.IsLoaded() && zoneID > 0 {
			ingress, errIn := c.dp.ReadZoneCounters(zoneID, 0)
			egress, errOut := c.dp.ReadZoneCounters(zoneID, 1)
			if errIn == nil && errOut == nil {
				fmt.Println("  Traffic statistics:")
				fmt.Printf("    Input:  %d packets, %d bytes\n",
					ingress.Packets, ingress.Bytes)
				fmt.Printf("    Output: %d packets, %d bytes\n",
					egress.Packets, egress.Bytes)
			}
		}

		// Detail mode: per-interface breakdown, per-policy details, screen profile summary
		if detail {
			// Per-interface detail
			if len(zone.Interfaces) > 0 {
				fmt.Println("  Interface details:")
				for _, ifName := range zone.Interfaces {
					fmt.Printf("    %s:\n", ifName)
					if ifc, ok := cfg.Interfaces.Interfaces[ifName]; ok {
						for _, unit := range ifc.Units {
							for _, addr := range unit.Addresses {
								fmt.Printf("      Address: %s\n", addr)
							}
							if unit.DHCP {
								fmt.Printf("      DHCPv4: enabled\n")
							}
							if unit.DHCPv6 {
								fmt.Printf("      DHCPv6: enabled\n")
							}
						}
					}
				}
			}

			// Screen profile details
			if zone.ScreenProfile != "" {
				if profile, ok := cfg.Security.Screen[zone.ScreenProfile]; ok {
					fmt.Printf("  Screen profile details (%s):\n", zone.ScreenProfile)
					var checks []string
					if profile.TCP.Land {
						checks = append(checks, "land")
					}
					if profile.TCP.SynFin {
						checks = append(checks, "syn-fin")
					}
					if profile.TCP.NoFlag {
						checks = append(checks, "no-flag")
					}
					if profile.TCP.FinNoAck {
						checks = append(checks, "fin-no-ack")
					}
					if profile.TCP.WinNuke {
						checks = append(checks, "winnuke")
					}
					if profile.TCP.SynFrag {
						checks = append(checks, "syn-frag")
					}
					if profile.TCP.SynFlood != nil {
						checks = append(checks, fmt.Sprintf("syn-flood(threshold:%d)", profile.TCP.SynFlood.AttackThreshold))
					}
					if profile.ICMP.PingDeath {
						checks = append(checks, "ping-death")
					}
					if profile.ICMP.FloodThreshold > 0 {
						checks = append(checks, fmt.Sprintf("icmp-flood(threshold:%d)", profile.ICMP.FloodThreshold))
					}
					if profile.IP.SourceRouteOption {
						checks = append(checks, "source-route-option")
					}
					if profile.IP.TearDrop {
						checks = append(checks, "teardrop")
					}
					if profile.UDP.FloodThreshold > 0 {
						checks = append(checks, fmt.Sprintf("udp-flood(threshold:%d)", profile.UDP.FloodThreshold))
					}
					if len(checks) > 0 {
						fmt.Printf("    Enabled checks: %s\n", strings.Join(checks, ", "))
					} else {
						fmt.Printf("    Enabled checks: (none)\n")
					}
				}
			}

			// Policy detail breakdown
			fmt.Println("  Policy summary:")
			totalPolicies := 0
			for _, zpp := range cfg.Security.Policies {
				if zpp.FromZone == name || zpp.ToZone == name {
					for _, pol := range zpp.Policies {
						action := "permit"
						switch pol.Action {
						case 1:
							action = "deny"
						case 2:
							action = "reject"
						}
						fmt.Printf("    %s -> %s: %s (%s)\n",
							zpp.FromZone, zpp.ToZone, pol.Name, action)
						totalPolicies++
					}
				}
			}
			if totalPolicies == 0 {
				fmt.Println("    (no policies)")
			}
		}

		fmt.Println()
	}
	if filterZone != "" {
		if _, ok := cfg.Security.Zones[filterZone]; !ok {
			fmt.Printf("Zone '%s' not found\n", filterZone)
		}
	}
	return nil
}

func (c *CLI) showScreen() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	if len(cfg.Security.Screen) == 0 {
		fmt.Println("No screen profiles configured")
		return nil
	}

	// Build reverse map: profile name -> zones using it
	zonesByProfile := make(map[string][]string)
	for name, zone := range cfg.Security.Zones {
		if zone.ScreenProfile != "" {
			zonesByProfile[zone.ScreenProfile] = append(
				zonesByProfile[zone.ScreenProfile], name)
		}
	}

	for name, profile := range cfg.Security.Screen {
		fmt.Printf("Screen profile: %s\n", name)

		// TCP checks
		if profile.TCP.Land {
			fmt.Println("  TCP LAND attack detection: enabled")
		}
		if profile.TCP.SynFin {
			fmt.Println("  TCP SYN+FIN detection: enabled")
		}
		if profile.TCP.NoFlag {
			fmt.Println("  TCP no-flag detection: enabled")
		}
		if profile.TCP.FinNoAck {
			fmt.Println("  TCP FIN-no-ACK detection: enabled")
		}
		if profile.TCP.WinNuke {
			fmt.Println("  TCP WinNuke detection: enabled")
		}
		if profile.TCP.SynFrag {
			fmt.Println("  TCP SYN fragment detection: enabled")
		}
		if profile.TCP.SynFlood != nil {
			fmt.Printf("  TCP SYN flood protection: attack-threshold %d\n",
				profile.TCP.SynFlood.AttackThreshold)
		}

		// ICMP checks
		if profile.ICMP.PingDeath {
			fmt.Println("  ICMP ping-of-death detection: enabled")
		}
		if profile.ICMP.FloodThreshold > 0 {
			fmt.Printf("  ICMP flood protection: threshold %d\n",
				profile.ICMP.FloodThreshold)
		}

		// IP checks
		if profile.IP.SourceRouteOption {
			fmt.Println("  IP source-route option detection: enabled")
		}

		// UDP checks
		if profile.UDP.FloodThreshold > 0 {
			fmt.Printf("  UDP flood protection: threshold %d\n",
				profile.UDP.FloodThreshold)
		}

		// Zones using this profile
		if zones, ok := zonesByProfile[name]; ok {
			fmt.Printf("  Applied to zones: %s\n", strings.Join(zones, ", "))
		} else {
			fmt.Println("  Applied to zones: (none)")
		}

		fmt.Println()
	}

	// Show screen drop counters (total + per-type)
	if c.dp != nil && c.dp.IsLoaded() {
		readCtr := func(idx uint32) uint64 {
			v, _ := c.dp.ReadGlobalCounter(idx)
			return v
		}

		totalDrops := readCtr(dataplane.GlobalCtrScreenDrops)
		fmt.Printf("Total screen drops: %d\n", totalDrops)

		if totalDrops > 0 {
			screenCounters := []struct {
				idx  uint32
				name string
			}{
				{dataplane.GlobalCtrScreenSynFlood, "SYN flood"},
				{dataplane.GlobalCtrScreenICMPFlood, "ICMP flood"},
				{dataplane.GlobalCtrScreenUDPFlood, "UDP flood"},
				{dataplane.GlobalCtrScreenLandAttack, "LAND attack"},
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
				v := readCtr(sc.idx)
				if v > 0 {
					fmt.Printf("  %-25s %d\n", sc.name+":", v)
				}
			}
		}
	}

	return nil
}

func (c *CLI) showScreenIdsOption(name string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	profile, ok := cfg.Security.Screen[name]
	if !ok {
		fmt.Printf("Screen profile '%s' not found\n", name)
		return nil
	}

	fmt.Printf("Screen object status:\n\n")
	fmt.Printf("  %-45s %s\n", "Name", "Value")
	if profile.TCP.Land {
		fmt.Printf("  %-45s %s\n", "TCP land attack", "enabled")
	}
	if profile.TCP.SynFin {
		fmt.Printf("  %-45s %s\n", "TCP SYN+FIN", "enabled")
	}
	if profile.TCP.NoFlag {
		fmt.Printf("  %-45s %s\n", "TCP no-flag", "enabled")
	}
	if profile.TCP.FinNoAck {
		fmt.Printf("  %-45s %s\n", "TCP FIN-no-ACK", "enabled")
	}
	if profile.TCP.WinNuke {
		fmt.Printf("  %-45s %s\n", "TCP WinNuke", "enabled")
	}
	if profile.TCP.SynFrag {
		fmt.Printf("  %-45s %s\n", "TCP SYN fragment", "enabled")
	}
	if profile.TCP.SynFlood != nil {
		fmt.Printf("  %-45s %d\n", "TCP SYN flood attack threshold", profile.TCP.SynFlood.AttackThreshold)
		if profile.TCP.SynFlood.SourceThreshold > 0 {
			fmt.Printf("  %-45s %d\n", "TCP SYN flood source threshold", profile.TCP.SynFlood.SourceThreshold)
		}
		if profile.TCP.SynFlood.DestinationThreshold > 0 {
			fmt.Printf("  %-45s %d\n", "TCP SYN flood destination threshold", profile.TCP.SynFlood.DestinationThreshold)
		}
		if profile.TCP.SynFlood.Timeout > 0 {
			fmt.Printf("  %-45s %d\n", "TCP SYN flood timeout", profile.TCP.SynFlood.Timeout)
		}
	}
	if profile.ICMP.PingDeath {
		fmt.Printf("  %-45s %s\n", "ICMP ping of death", "enabled")
	}
	if profile.ICMP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %d\n", "ICMP flood threshold", profile.ICMP.FloodThreshold)
	}
	if profile.IP.SourceRouteOption {
		fmt.Printf("  %-45s %s\n", "IP source route option", "enabled")
	}
	if profile.UDP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %d\n", "UDP flood threshold", profile.UDP.FloodThreshold)
	}

	// Show zones using this profile
	var zones []string
	for zname, zone := range cfg.Security.Zones {
		if zone.ScreenProfile == name {
			zones = append(zones, zname)
		}
	}
	if len(zones) > 0 {
		sort.Strings(zones)
		fmt.Printf("\n  Bound to zones: %s\n", strings.Join(zones, ", "))
	}
	return nil
}

func (c *CLI) showScreenIdsOptionDetail(name string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	profile, ok := cfg.Security.Screen[name]
	if !ok {
		fmt.Printf("Screen profile '%s' not found\n", name)
		return nil
	}

	fmt.Printf("Screen object status (detail):\n\n")
	fmt.Printf("  %-45s %-12s %s\n", "Name", "Value", "Default")

	// TCP checks
	fmt.Printf("  %-45s %-12s %s\n", "TCP land attack",
		enabledStr(profile.TCP.Land), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP SYN+FIN",
		enabledStr(profile.TCP.SynFin), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP no-flag",
		enabledStr(profile.TCP.NoFlag), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP FIN-no-ACK",
		enabledStr(profile.TCP.FinNoAck), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP WinNuke",
		enabledStr(profile.TCP.WinNuke), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP SYN fragment",
		enabledStr(profile.TCP.SynFrag), "disabled")

	if profile.TCP.SynFlood != nil {
		fmt.Printf("  %-45s %-12s %s\n", "TCP SYN flood protection", "enabled", "disabled")
		fmt.Printf("  %-45s %-12d %s\n", "  Attack threshold",
			profile.TCP.SynFlood.AttackThreshold, "200")
		if profile.TCP.SynFlood.AlarmThreshold > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Alarm threshold",
				profile.TCP.SynFlood.AlarmThreshold, "512")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Alarm threshold", "(default)", "512")
		}
		if profile.TCP.SynFlood.SourceThreshold > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Source threshold",
				profile.TCP.SynFlood.SourceThreshold, "4000")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Source threshold", "(default)", "4000")
		}
		if profile.TCP.SynFlood.DestinationThreshold > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Destination threshold",
				profile.TCP.SynFlood.DestinationThreshold, "4000")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Destination threshold", "(default)", "4000")
		}
		if profile.TCP.SynFlood.Timeout > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Timeout (seconds)",
				profile.TCP.SynFlood.Timeout, "20")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Timeout (seconds)", "(default)", "20")
		}
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "TCP SYN flood protection", "disabled", "disabled")
	}

	// ICMP checks
	fmt.Printf("  %-45s %-12s %s\n", "ICMP ping of death",
		enabledStr(profile.ICMP.PingDeath), "disabled")
	if profile.ICMP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %-12d %s\n", "ICMP flood threshold",
			profile.ICMP.FloodThreshold, "1000")
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "ICMP flood threshold", "disabled", "disabled")
	}

	// IP checks
	fmt.Printf("  %-45s %-12s %s\n", "IP source route option",
		enabledStr(profile.IP.SourceRouteOption), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "IP teardrop",
		enabledStr(profile.IP.TearDrop), "disabled")

	// UDP checks
	if profile.UDP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %-12d %s\n", "UDP flood threshold",
			profile.UDP.FloodThreshold, "1000")
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "UDP flood threshold", "disabled", "disabled")
	}

	// Zones using this profile
	var zones []string
	for zname, zone := range cfg.Security.Zones {
		if zone.ScreenProfile == name {
			zones = append(zones, zname)
		}
	}
	if len(zones) > 0 {
		sort.Strings(zones)
		fmt.Printf("\n  Bound to zones: %s\n", strings.Join(zones, ", "))
	} else {
		fmt.Printf("\n  Bound to zones: (none)\n")
	}
	return nil
}

func (c *CLI) showScreenStatistics(zoneName string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("dataplane not loaded")
		return nil
	}
	cr := c.applyResult()
	if cr == nil {
		fmt.Println("no compile result available")
		return nil
	}
	zoneID, ok := cr.ZoneIDs[zoneName]
	if !ok {
		fmt.Printf("Zone '%s' not found\n", zoneName)
		return nil
	}
	fs, err := c.dp.ReadFloodCounters(zoneID)
	if err != nil {
		fmt.Printf("Error reading flood counters: %v\n", err)
		return nil
	}
	totalSyn, totalICMP, totalUDP := fs.SynCount, fs.ICMPCount, fs.UDPCount
	screenProfile := ""
	if z, ok := cfg.Security.Zones[zoneName]; ok {
		screenProfile = z.ScreenProfile
	}
	fmt.Printf("Screen statistics for zone '%s':\n", zoneName)
	if screenProfile != "" {
		fmt.Printf("  Screen profile: %s\n", screenProfile)
	}
	fmt.Printf("  %-30s %s\n", "Counter", "Value")
	fmt.Printf("  %-30s %d\n", "SYN flood events", totalSyn)
	fmt.Printf("  %-30s %d\n", "ICMP flood events", totalICMP)
	fmt.Printf("  %-30s %d\n", "UDP flood events", totalUDP)
	return nil
}

func (c *CLI) showScreenStatisticsAll() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("dataplane not loaded")
		return nil
	}
	cr := c.applyResult()
	if cr == nil {
		fmt.Println("no compile result available")
		return nil
	}
	// Collect zone names and sort for deterministic output
	var zones []string
	for name := range cr.ZoneIDs {
		zones = append(zones, name)
	}
	sort.Strings(zones)

	for _, zoneName := range zones {
		zoneID := cr.ZoneIDs[zoneName]
		fs, err := c.dp.ReadFloodCounters(zoneID)
		if err != nil {
			continue
		}
		screenProfile := ""
		if z, ok := cfg.Security.Zones[zoneName]; ok {
			screenProfile = z.ScreenProfile
		}
		fmt.Printf("Screen statistics for zone '%s':\n", zoneName)
		if screenProfile != "" {
			fmt.Printf("  Screen profile: %s\n", screenProfile)
		}
		fmt.Printf("  %-30s %s\n", "Counter", "Value")
		fmt.Printf("  %-30s %d\n", "SYN flood events", fs.SynCount)
		fmt.Printf("  %-30s %d\n", "ICMP flood events", fs.ICMPCount)
		fmt.Printf("  %-30s %d\n", "UDP flood events", fs.UDPCount)
		fmt.Println()
	}
	return nil
}

func (c *CLI) showAddressBook(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Security.AddressBook == nil {
		fmt.Println("No address book configured")
		return nil
	}
	ab := cfg.Security.AddressBook

	// Optional filter by name
	filterName := ""
	if len(args) > 0 {
		filterName = args[0]
	}

	if len(ab.Addresses) > 0 {
		if filterName == "" {
			fmt.Println("Addresses:")
		}
		for _, addr := range ab.Addresses {
			if filterName != "" && addr.Name != filterName {
				continue
			}
			fmt.Printf("  %-24s %s\n", addr.Name, addr.Value)
		}
	}

	if len(ab.AddressSets) > 0 {
		if filterName == "" {
			fmt.Println("Address sets:")
		}
		for _, as := range ab.AddressSets {
			if filterName != "" && as.Name != filterName {
				continue
			}
			var parts []string
			for _, a := range as.Addresses {
				parts = append(parts, a)
			}
			for _, s := range as.AddressSets {
				parts = append(parts, "set:"+s)
			}
			fmt.Printf("  %-24s members: %s\n", as.Name, strings.Join(parts, ", "))
			// If filtering by name, show member details
			if filterName != "" {
				for _, a := range as.Addresses {
					for _, addr := range ab.Addresses {
						if addr.Name == a {
							fmt.Printf("    %-22s %s\n", addr.Name, addr.Value)
						}
					}
				}
			}
		}
	}

	if filterName == "" && len(ab.Addresses) == 0 && len(ab.AddressSets) == 0 {
		fmt.Println("Address book is empty")
	}

	return nil
}

func (c *CLI) showApplications(args []string) error {
	cfg := c.store.ActiveConfig()

	// Parse sub-commands: detail, <name>
	detail := false
	filterName := ""
	for _, a := range args {
		switch a {
		case "detail":
			detail = true
		default:
			filterName = a
		}
	}

	// Helper to print application detail
	printApp := func(app *config.Application, indent string) {
		if detail || filterName != "" {
			fmt.Printf("%sApplication: %s\n", indent, app.Name)
			if app.Description != "" {
				fmt.Printf("%s  Description: %s\n", indent, app.Description)
			}
			if app.Protocol != "" {
				fmt.Printf("%s  IP protocol: %s\n", indent, app.Protocol)
			}
			if app.DestinationPort != "" {
				fmt.Printf("%s  Destination port: %s\n", indent, app.DestinationPort)
			}
			if app.SourcePort != "" {
				fmt.Printf("%s  Source port: %s\n", indent, app.SourcePort)
			}
			if app.InactivityTimeout > 0 {
				fmt.Printf("%s  Inactivity timeout: %ds\n", indent, app.InactivityTimeout)
			}
			if app.ALG != "" {
				fmt.Printf("%s  ALG: %s\n", indent, app.ALG)
			}
		} else {
			port := app.DestinationPort
			if port == "" {
				port = "-"
			}
			fmt.Printf("%s%-24s protocol: %-6s port: %s\n", indent, app.Name, app.Protocol, port)
		}
	}

	// User-defined applications
	if cfg != nil && len(cfg.Applications.Applications) > 0 {
		if filterName == "" {
			fmt.Println("User-defined applications:")
		}
		names := make([]string, 0, len(cfg.Applications.Applications))
		for name := range cfg.Applications.Applications {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			app := cfg.Applications.Applications[name]
			if filterName != "" && app.Name != filterName {
				continue
			}
			printApp(app, "  ")
		}
		if filterName == "" {
			fmt.Println()
		}
	}

	// User-defined application-sets
	if cfg != nil && len(cfg.Applications.ApplicationSets) > 0 {
		names := make([]string, 0, len(cfg.Applications.ApplicationSets))
		for name := range cfg.Applications.ApplicationSets {
			names = append(names, name)
		}
		sort.Strings(names)

		if filterName == "" {
			fmt.Println("Application sets:")
		}
		for _, name := range names {
			as := cfg.Applications.ApplicationSets[name]
			if filterName != "" && as.Name != filterName {
				continue
			}
			if detail || filterName != "" {
				fmt.Printf("  Application set: %s\n", as.Name)
				fmt.Printf("    Members:\n")
				for _, member := range as.Applications {
					fmt.Printf("      %s\n", member)
					// Show member details if filtering by set name
					if filterName != "" {
						if cfg != nil {
							if app, ok := cfg.Applications.Applications[member]; ok {
								printApp(app, "        ")
							}
						}
					}
				}
			} else {
				fmt.Printf("  %-24s members: %s\n", as.Name, strings.Join(as.Applications, ", "))
			}
		}
		if filterName == "" {
			fmt.Println()
		}
	}

	// Show matching predefined application if filtering by name
	if filterName != "" {
		for _, app := range config.PredefinedApplications {
			if app.Name == filterName {
				fmt.Println("Predefined application:")
				printApp(app, "  ")
				return nil
			}
		}
		return nil
	}

	// Predefined applications (only in list mode)
	fmt.Println("Predefined applications:")
	for _, app := range config.PredefinedApplications {
		printApp(app, "  ")
	}

	return nil
}

func (c *CLI) showIPsec(args []string) error {
	if c.ipsec == nil {
		fmt.Println("IPsec manager not available")
		return nil
	}

	if len(args) > 0 && args[0] == "security-associations" {
		detail := len(args) >= 2 && args[1] == "detail"
		sas, err := c.ipsec.GetSAStatus()
		if err != nil {
			return fmt.Errorf("IPsec SA status: %w", err)
		}
		if len(sas) == 0 {
			fmt.Println("No IPsec security associations")
			return nil
		}
		for _, sa := range sas {
			fmt.Printf("SA: %s\n", sa.Name)
			fmt.Printf("  State: %s\n", sa.State)
			if sa.LocalAddr != "" {
				fmt.Printf("  Local: %s\n", sa.LocalAddr)
			}
			if sa.RemoteAddr != "" {
				fmt.Printf("  Remote: %s\n", sa.RemoteAddr)
			}
			if sa.LocalTS != "" {
				fmt.Printf("  Local TS: %s\n", sa.LocalTS)
			}
			if sa.RemoteTS != "" {
				fmt.Printf("  Remote TS: %s\n", sa.RemoteTS)
			}
			if detail {
				inBytes := sa.InBytes
				if inBytes == "" {
					inBytes = "0"
				}
				outBytes := sa.OutBytes
				if outBytes == "" {
					outBytes = "0"
				}
				fmt.Printf("  Bytes transferred In/Out: %s/%s\n", inBytes, outBytes)
			}
			fmt.Println()
		}
		return nil
	}

	if len(args) > 0 && args[0] == "statistics" {
		return c.showIPsecStatistics()
	}

	// Default: show configured VPNs
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	if len(cfg.Security.IPsec.VPNs) == 0 {
		fmt.Println("No IPsec VPNs configured")
		return nil
	}

	for name, vpn := range cfg.Security.IPsec.VPNs {
		fmt.Printf("VPN: %s\n", name)
		fmt.Printf("  Gateway: %s\n", vpn.Gateway)
		if vpn.LocalAddr != "" {
			fmt.Printf("  Local address: %s\n", vpn.LocalAddr)
		}
		if vpn.IPsecPolicy != "" {
			fmt.Printf("  IPsec policy: %s\n", vpn.IPsecPolicy)
		}
		if vpn.BindInterface != "" {
			fmt.Printf("  Bind interface: %s\n", vpn.BindInterface)
		}
		if vpn.LocalID != "" {
			fmt.Printf("  Local identity: %s\n", vpn.LocalID)
		}
		if vpn.RemoteID != "" {
			fmt.Printf("  Remote identity: %s\n", vpn.RemoteID)
		}
		if len(vpn.TrafficSelectors) > 0 {
			names := make([]string, 0, len(vpn.TrafficSelectors))
			for tsName := range vpn.TrafficSelectors {
				names = append(names, tsName)
			}
			sort.Strings(names)
			for _, tsName := range names {
				ts := vpn.TrafficSelectors[tsName]
				fmt.Printf("  Traffic selector %s: %s -> %s\n", tsName, ts.LocalIP, ts.RemoteIP)
			}
		}
		fmt.Println()
	}
	return nil
}

func (c *CLI) showIPsecStatistics() error {
	if c.ipsec == nil {
		fmt.Println("IPsec manager not available")
		return nil
	}
	sas, err := c.ipsec.GetSAStatus()
	if err != nil {
		return fmt.Errorf("IPsec statistics: %w", err)
	}

	activeTunnels := 0
	for _, sa := range sas {
		if sa.State == "ESTABLISHED" || sa.State == "INSTALLED" {
			activeTunnels++
		}
	}

	fmt.Println("IPsec statistics:")
	fmt.Printf("  Active tunnels: %d\n", activeTunnels)
	fmt.Printf("  Total SAs:      %d\n", len(sas))
	fmt.Println()

	if len(sas) > 0 {
		fmt.Printf("  %-20s %-14s %-12s %-12s\n", "Name", "State", "Bytes In", "Bytes Out")
		for _, sa := range sas {
			inBytes := sa.InBytes
			if inBytes == "" {
				inBytes = "-"
			}
			outBytes := sa.OutBytes
			if outBytes == "" {
				outBytes = "-"
			}
			fmt.Printf("  %-20s %-14s %-12s %-12s\n", sa.Name, sa.State, inBytes, outBytes)
		}
	}

	// Show configured VPN count
	cfg := c.store.ActiveConfig()
	if cfg != nil && len(cfg.Security.IPsec.VPNs) > 0 {
		fmt.Printf("\n  Configured VPNs: %d\n", len(cfg.Security.IPsec.VPNs))
	}

	return nil
}

func (c *CLI) showIKE(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	if len(args) > 0 && args[0] == "security-associations" {
		// Show IKE SA status from strongSwan
		if c.ipsec != nil {
			sas, err := c.ipsec.GetSAStatus()
			if err != nil {
				return fmt.Errorf("IKE SA status: %w", err)
			}
			if len(sas) == 0 {
				fmt.Println("No IKE security associations")
				return nil
			}
			for _, sa := range sas {
				fmt.Printf("IKE SA: %s  State: %s\n", sa.Name, sa.State)
				if sa.LocalAddr != "" {
					fmt.Printf("  Local:  %s\n", sa.LocalAddr)
				}
				if sa.RemoteAddr != "" {
					fmt.Printf("  Remote: %s\n", sa.RemoteAddr)
				}
				fmt.Println()
			}
			return nil
		}
		fmt.Println("IPsec manager not available")
		return nil
	}

	// Show configured IKE gateways
	gateways := cfg.Security.IPsec.Gateways
	if len(gateways) == 0 {
		fmt.Println("No IKE gateways configured")
		return nil
	}

	names := make([]string, 0, len(gateways))
	for name := range gateways {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		gw := gateways[name]
		fmt.Printf("IKE gateway: %s\n", name)
		if gw.Address != "" {
			fmt.Printf("  Remote address:     %s\n", gw.Address)
		}
		if gw.DynamicHostname != "" {
			fmt.Printf("  Dynamic hostname:   %s\n", gw.DynamicHostname)
		}
		if gw.LocalAddress != "" {
			fmt.Printf("  Local address:      %s\n", gw.LocalAddress)
		}
		if gw.ExternalIface != "" {
			fmt.Printf("  External interface: %s\n", gw.ExternalIface)
		}
		if gw.LocalCertificate != "" {
			fmt.Printf("  Local certificate:  %s\n", gw.LocalCertificate)
		}
		if gw.IKEPolicy != "" {
			fmt.Printf("  IKE policy:         %s\n", gw.IKEPolicy)
			if pol, ok := cfg.Security.IPsec.IKEPolicies[gw.IKEPolicy]; ok {
				fmt.Printf("    Mode:     %s\n", pol.Mode)
				fmt.Printf("    Proposal: %s\n", pol.Proposals)
			}
		}
		ver := gw.Version
		if ver == "" {
			ver = "v1+v2"
		}
		fmt.Printf("  IKE version:        %s\n", ver)
		if gw.DeadPeerDetect != "" {
			fmt.Printf("  DPD:                %s\n", gw.DeadPeerDetect)
			if gw.DPDInterval > 0 {
				fmt.Printf("  DPD interval:       %ds\n", gw.DPDInterval)
			}
			if gw.DPDThreshold > 0 {
				fmt.Printf("  DPD threshold:      %d\n", gw.DPDThreshold)
			}
		}
		if gw.NoNATTraversal {
			fmt.Printf("  NAT-T:              disabled\n")
		} else if gw.NATTraversal == "force" {
			fmt.Printf("  NAT-T:              force\n")
		} else if gw.NATTraversal == "enable" {
			fmt.Printf("  NAT-T:              enabled\n")
		}
		if gw.LocalIDValue != "" {
			fmt.Printf("  Local identity:     %s %s\n", gw.LocalIDType, gw.LocalIDValue)
		}
		if gw.RemoteIDValue != "" {
			fmt.Printf("  Remote identity:    %s %s\n", gw.RemoteIDType, gw.RemoteIDValue)
		}
		fmt.Println()
	}

	// Show IKE proposals
	proposals := cfg.Security.IPsec.IKEProposals
	if len(proposals) > 0 {
		pNames := make([]string, 0, len(proposals))
		for name := range proposals {
			pNames = append(pNames, name)
		}
		sort.Strings(pNames)
		fmt.Println("IKE proposals:")
		for _, name := range pNames {
			p := proposals[name]
			fmt.Printf("  %s: auth=%s enc=%s dh=group%d", name, p.AuthMethod, p.EncryptionAlg, p.DHGroup)
			if p.LifetimeSeconds > 0 {
				fmt.Printf(" lifetime=%ds", p.LifetimeSeconds)
			}
			fmt.Println()
		}
	}
	return nil
}

func (c *CLI) showSecurityLog(args []string) error {
	if c.eventBuf == nil {
		fmt.Println("no events (event buffer not initialized)")
		return nil
	}

	n := 50
	var filter logging.EventFilter
	cr := c.applyResult()

	// Parse arguments: [N] [zone <name>] [protocol <proto>] [action <act>]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 < len(args) {
				i++
				zoneName := args[i]
				if cr != nil {
					if zid, ok := cr.ZoneIDs[zoneName]; ok {
						filter.Zone = zid
					} else {
						return fmt.Errorf("zone %q not found", zoneName)
					}
				}
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				filter.Protocol = args[i]
			}
		case "action":
			if i+1 < len(args) {
				i++
				filter.Action = args[i]
			}
		default:
			// Try parsing as count.
			if v, err := strconv.Atoi(args[i]); err == nil {
				n = v
			}
		}
	}

	var events []logging.EventRecord
	if !filter.IsEmpty() {
		events = c.eventBuf.LatestFiltered(n, filter)
	} else {
		events = c.eventBuf.Latest(n)
	}
	if len(events) == 0 {
		fmt.Println("no events recorded")
		return nil
	}

	// Build reverse zone ID → name map for event display
	evZoneNames := make(map[uint16]string)
	if cr != nil {
		for name, id := range cr.ZoneIDs {
			evZoneNames[id] = name
		}
	}
	zoneName := func(id uint16) string {
		if n, ok := evZoneNames[id]; ok {
			return n
		}
		return fmt.Sprintf("%d", id)
	}

	policyName := func(e logging.EventRecord) string {
		if e.PolicyName != "" {
			return e.PolicyName
		}
		return fmt.Sprintf("%d", e.PolicyID)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}

	for _, e := range events {
		ts := e.Time.Format("2006-01-02T15:04:05")

		// Parse source/destination address:port
		srcAddr, srcPort := splitAddrPort(e.SrcAddr)
		dstAddr, dstPort := splitAddrPort(e.DstAddr)
		natSrcAddr, natSrcPort := splitAddrPort(e.NATSrcAddr)
		natDstAddr, natDstPort := splitAddrPort(e.NATDstAddr)
		if natSrcAddr == "" {
			natSrcAddr = srcAddr
			natSrcPort = srcPort
		}
		if natDstAddr == "" {
			natDstAddr = dstAddr
			natDstPort = dstPort
		}

		inIface := e.IngressIface
		if inIface == "" {
			inIface = zoneName(e.InZone)
		}
		appName := e.AppName
		if appName == "" {
			appName = "UNKNOWN"
		}

		switch e.Type {
		case "SESSION_OPEN":
			fmt.Printf("%s %s RT_FLOW - RT_FLOW_SESSION_CREATE [source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" nat-source-address=\"%s\" nat-source-port=\"%s\" nat-destination-address=\"%s\" nat-destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" session-id-32=\"%d\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, srcAddr, srcPort, dstAddr, dstPort,
				natSrcAddr, natSrcPort, natDstAddr, natDstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZone), zoneName(e.OutZone),
				e.SessionID, appName, inIface)

		case "SESSION_CLOSE":
			reason := e.CloseReason
			if reason == "" {
				reason = "N/A"
			}
			fmt.Printf("%s %s RT_FLOW - RT_FLOW_SESSION_CLOSE [reason=\"%s\" source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" nat-source-address=\"%s\" nat-source-port=\"%s\" nat-destination-address=\"%s\" nat-destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" session-id-32=\"%d\" packets-from-client=\"%d\" bytes-from-client=\"%d\" packets-from-server=\"%d\" bytes-from-server=\"%d\" elapsed-time=\"%d\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, reason, srcAddr, srcPort, dstAddr, dstPort,
				natSrcAddr, natSrcPort, natDstAddr, natDstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZone), zoneName(e.OutZone),
				e.SessionID, e.SessionPkts, e.SessionBytes,
				e.RevSessionPkts, e.RevSessionBytes, e.ElapsedTime,
				appName, inIface)

		case "POLICY_DENY", "POLICY_REJECT":
			fmt.Printf("%s %s RT_FLOW - RT_FLOW_SESSION_DENY [source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, srcAddr, srcPort, dstAddr, dstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZone), zoneName(e.OutZone),
				appName, inIface)

		case "SCREEN_DROP":
			fmt.Printf("%s %s RT_IDS - RT_SCREEN_DROP [attack-name=\"%s\" source-address=\"%s\" destination-address=\"%s\" protocol-id=\"%s\" source-zone-name=\"%s\" action=\"%s\"]\n",
				ts, hostname, e.ScreenCheck, srcAddr, dstAddr,
				protoNameToID(e.Protocol), zoneName(e.InZone), e.Action)

		default:
			// Fallback for other event types
			fmt.Printf("%s %s RT_FLOW - %s [source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, e.Type, srcAddr, srcPort, dstAddr, dstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZone), zoneName(e.OutZone),
				appName, inIface)
		}
	}
	fmt.Printf("(%d events shown)\n", len(events))
	return nil
}

func (c *CLI) showFirewallFilters() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	if len(cfg.Firewall.FiltersInet) == 0 && len(cfg.Firewall.FiltersInet6) == 0 {
		fmt.Println("No firewall filters configured")
		return nil
	}

	// Look up filter IDs from compile result for counter display
	var filterIDs map[string]uint32
	if c.dp != nil && c.dp.IsLoaded() {
		if cr := c.applyResult(); cr != nil {
			filterIDs = cr.FilterIDs
		}
	}
	var userspaceStatus *dpuserspace.ProcessStatus
	if status, err := c.userspaceDataplaneStatus(); err == nil {
		userspaceStatus = &status
	}
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)

	showFilters := func(family string, filters map[string]*config.FirewallFilter, names []string) {
		for _, name := range names {
			f := filters[name]
			fmt.Printf("Filter: %s (family %s)\n", name, family)

			// Get filter config for counter lookup
			var ruleStart uint32
			var hasCounters bool
			if filterIDs != nil {
				if fid, ok := filterIDs[family+":"+name]; ok {
					if fcfg, err := c.dp.ReadFilterConfig(fid); err == nil {
						ruleStart = fcfg.RuleStart
						hasCounters = true
					}
				}
			}

			ruleOffset := ruleStart
			for _, term := range f.Terms {
				fmt.Printf("  Term: %s\n", term.Name)
				if term.DSCP != "" {
					fmt.Printf("    from dscp %s\n", term.DSCP)
				}
				if term.Protocol != "" {
					fmt.Printf("    from protocol %s\n", term.Protocol)
				}
				for _, addr := range term.SourceAddresses {
					fmt.Printf("    from source-address %s\n", addr)
				}
				for _, addr := range term.DestAddresses {
					fmt.Printf("    from destination-address %s\n", addr)
				}
				for _, port := range term.DestinationPorts {
					fmt.Printf("    from destination-port %s\n", port)
				}
				for _, port := range term.SourcePorts {
					fmt.Printf("    from source-port %s\n", port)
				}
				for _, ref := range term.SourcePrefixLists {
					mod := ""
					if ref.Except {
						mod = " except"
					}
					fmt.Printf("    from source-prefix-list %s%s\n", ref.Name, mod)
				}
				for _, ref := range term.DestPrefixLists {
					mod := ""
					if ref.Except {
						mod = " except"
					}
					fmt.Printf("    from destination-prefix-list %s%s\n", ref.Name, mod)
				}
				if term.ICMPType >= 0 {
					fmt.Printf("    from icmp-type %d\n", term.ICMPType)
				}
				if term.ICMPCode >= 0 {
					fmt.Printf("    from icmp-code %d\n", term.ICMPCode)
				}
				action := term.Action
				if action == "" {
					action = "accept"
				}
				if term.RoutingInstance != "" {
					fmt.Printf("    then routing-instance %s\n", term.RoutingInstance)
				}
				if term.ForwardingClass != "" {
					fmt.Printf("    then forwarding-class %s\n", term.ForwardingClass)
				}
				if term.LossPriority != "" {
					fmt.Printf("    then loss-priority %s\n", term.LossPriority)
				}
				if term.DSCPRewrite != "" {
					fmt.Printf("    then dscp %s\n", term.DSCPRewrite)
				}
				if term.Log {
					fmt.Printf("    then log\n")
				}
				if term.Count != "" {
					fmt.Printf("    then count %s\n", term.Count)
				}
				fmt.Printf("    then %s\n", action)

				// Sum counters across all expanded BPF rules for this term.
				// Must match the cross-product in expandFilterTerm:
				// nSrc * nDst * nDstPorts * nSrcPorts
				numRules := filterTermExpansionCount(cfg, term)
				var totalPkts, totalBytes uint64
				if hasCounters {
					for i := uint32(0); i < numRules; i++ {
						if ctrs, err := c.dp.ReadFilterCounters(ruleOffset + i); err == nil {
							totalPkts += ctrs.Packets
							totalBytes += ctrs.Bytes
						}
					}
					ruleOffset += numRules
				}
				userspaceCounter, userspaceOk := userspaceCounters[dpuserspace.FirewallFilterTermCounterKey{
					Family: family, FilterName: name, TermName: term.Name,
				}]
				if userspaceOk {
					totalPkts += userspaceCounter.Packets
					totalBytes += userspaceCounter.Bytes
				}
				if hasCounters || userspaceOk {
					fmt.Printf("    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
				}
			}
			fmt.Println()
		}
	}

	// Sort filter names for deterministic output (matches compiler order)
	inetNames := make([]string, 0, len(cfg.Firewall.FiltersInet))
	for name := range cfg.Firewall.FiltersInet {
		inetNames = append(inetNames, name)
	}
	sort.Strings(inetNames)

	inet6Names := make([]string, 0, len(cfg.Firewall.FiltersInet6))
	for name := range cfg.Firewall.FiltersInet6 {
		inet6Names = append(inet6Names, name)
	}
	sort.Strings(inet6Names)

	showFilters("inet", cfg.Firewall.FiltersInet, inetNames)
	showFilters("inet6", cfg.Firewall.FiltersInet6, inet6Names)
	return nil
}

func (c *CLI) showFirewallFilter(name, requestedFamily string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	requestedFamily = strings.TrimSpace(requestedFamily)
	if requestedFamily != "" && requestedFamily != "inet" && requestedFamily != "inet6" {
		fmt.Printf("invalid family: %s\n", requestedFamily)
		return nil
	}

	var filter *config.FirewallFilter
	var family string
	switch requestedFamily {
	case "inet":
		filter = cfg.Firewall.FiltersInet[name]
		family = "inet"
	case "inet6":
		filter = cfg.Firewall.FiltersInet6[name]
		family = "inet6"
	default:
		if f, ok := cfg.Firewall.FiltersInet[name]; ok {
			filter = f
			family = "inet"
		} else if f, ok := cfg.Firewall.FiltersInet6[name]; ok {
			filter = f
			family = "inet6"
		}
	}
	if filter == nil {
		if requestedFamily != "" {
			fmt.Printf("Filter not found: %s (family %s)\n", name, requestedFamily)
		} else {
			fmt.Printf("Filter not found: %s\n", name)
		}
		return nil
	}

	// Resolve filter IDs for counter display
	var ruleStart uint32
	var hasCounters bool
	if c.dp != nil && c.dp.IsLoaded() {
		if cr := c.applyResult(); cr != nil {
			if fid, ok := cr.FilterIDs[family+":"+name]; ok {
				if fcfg, err := c.dp.ReadFilterConfig(fid); err == nil {
					ruleStart = fcfg.RuleStart
					hasCounters = true
				}
			}
		}
	}
	var userspaceStatus *dpuserspace.ProcessStatus
	if status, err := c.userspaceDataplaneStatus(); err == nil {
		userspaceStatus = &status
	}
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)

	fmt.Printf("Filter: %s (family %s)\n", name, family)

	ruleOffset := ruleStart
	for _, term := range filter.Terms {
		fmt.Printf("\n  Term: %s\n", term.Name)
		if term.DSCP != "" {
			fmt.Printf("    from dscp %s\n", term.DSCP)
		}
		if term.Protocol != "" {
			fmt.Printf("    from protocol %s\n", term.Protocol)
		}
		for _, addr := range term.SourceAddresses {
			fmt.Printf("    from source-address %s\n", addr)
		}
		for _, ref := range term.SourcePrefixLists {
			mod := ""
			if ref.Except {
				mod = " except"
			}
			fmt.Printf("    from source-prefix-list %s%s\n", ref.Name, mod)
		}
		for _, addr := range term.DestAddresses {
			fmt.Printf("    from destination-address %s\n", addr)
		}
		for _, ref := range term.DestPrefixLists {
			mod := ""
			if ref.Except {
				mod = " except"
			}
			fmt.Printf("    from destination-prefix-list %s%s\n", ref.Name, mod)
		}
		if len(term.SourcePorts) > 0 {
			fmt.Printf("    from source-port %s\n", strings.Join(term.SourcePorts, ", "))
		}
		if len(term.DestinationPorts) > 0 {
			fmt.Printf("    from destination-port %s\n", strings.Join(term.DestinationPorts, ", "))
		}
		if term.ICMPType >= 0 {
			fmt.Printf("    from icmp-type %d\n", term.ICMPType)
		}
		if term.ICMPCode >= 0 {
			fmt.Printf("    from icmp-code %d\n", term.ICMPCode)
		}
		if term.RoutingInstance != "" {
			fmt.Printf("    then routing-instance %s\n", term.RoutingInstance)
		}
		if term.ForwardingClass != "" {
			fmt.Printf("    then forwarding-class %s\n", term.ForwardingClass)
		}
		if term.LossPriority != "" {
			fmt.Printf("    then loss-priority %s\n", term.LossPriority)
		}
		if term.DSCPRewrite != "" {
			fmt.Printf("    then dscp %s\n", term.DSCPRewrite)
		}
		if term.Log {
			fmt.Printf("    then log\n")
		}
		if term.Count != "" {
			fmt.Printf("    then count %s\n", term.Count)
		}
		action := term.Action
		if action == "" {
			action = "accept"
		}
		fmt.Printf("    then %s\n", action)

		// Sum counters across all expanded BPF rules for this term
		numRules := filterTermExpansionCount(cfg, term)
		var totalPkts, totalBytes uint64
		if hasCounters {
			for i := uint32(0); i < numRules; i++ {
				if ctrs, err := c.dp.ReadFilterCounters(ruleOffset + i); err == nil {
					totalPkts += ctrs.Packets
					totalBytes += ctrs.Bytes
				}
			}
			ruleOffset += numRules
		}
		userspaceCounter, userspaceOk := userspaceCounters[dpuserspace.FirewallFilterTermCounterKey{
			Family: family, FilterName: name, TermName: term.Name,
		}]
		if userspaceOk {
			totalPkts += userspaceCounter.Packets
			totalBytes += userspaceCounter.Bytes
		}
		if hasCounters || userspaceOk {
			fmt.Printf("    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
		}
	}
	fmt.Println()
	return nil
}

func filterTermExpansionCount(cfg *config.Config, term *config.FirewallFilterTerm) uint32 {
	nSrc := len(term.SourceAddresses)
	for _, ref := range term.SourcePrefixLists {
		if !ref.Except {
			if pl, ok := cfg.PolicyOptions.PrefixLists[ref.Name]; ok {
				nSrc += len(pl.Prefixes)
			}
		}
	}
	if nSrc == 0 {
		nSrc = 1
	}
	nDst := len(term.DestAddresses)
	for _, ref := range term.DestPrefixLists {
		if !ref.Except {
			if pl, ok := cfg.PolicyOptions.PrefixLists[ref.Name]; ok {
				nDst += len(pl.Prefixes)
			}
		}
	}
	if nDst == 0 {
		nDst = 1
	}
	nDstPorts := len(term.DestinationPorts)
	if nDstPorts == 0 {
		nDstPorts = 1
	}
	nSrcPorts := len(term.SourcePorts)
	if nSrcPorts == 0 {
		nSrcPorts = 1
	}
	return uint32(nSrc * nDst * nDstPorts * nSrcPorts)
}

func (c *CLI) showDynamicAddress() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	if len(cfg.Security.DynamicAddress.FeedServers) == 0 {
		fmt.Println("No dynamic address feeds configured")
		return nil
	}

	// Get runtime feed status if available.
	var runtimeFeeds map[string]feeds.FeedInfo
	if c.feedsFn != nil {
		runtimeFeeds = c.feedsFn()
	}

	fmt.Println("Dynamic Address Feed Servers:")
	for name, fs := range cfg.Security.DynamicAddress.FeedServers {
		updateInt := fs.UpdateInterval
		if updateInt == 0 {
			updateInt = 3600
		}
		holdInt := fs.HoldInterval
		if holdInt == 0 {
			holdInt = 7200
		}
		fmt.Printf("  Feed Server: %s\n", name)
		if fs.URL != "" {
			fmt.Printf("    URL: %s\n", fs.URL)
		}
		if fs.FeedName != "" {
			fmt.Printf("    Feed name: %s\n", fs.FeedName)
		}
		fmt.Printf("    Update interval: %d seconds\n", updateInt)
		fmt.Printf("    Hold interval:   %d seconds\n", holdInt)

		if fi, ok := runtimeFeeds[name]; ok {
			fmt.Printf("    Prefixes: %d\n", fi.Prefixes)
			if !fi.LastFetch.IsZero() {
				age := time.Since(fi.LastFetch).Truncate(time.Second)
				fmt.Printf("    Last fetch: %s (%s ago)\n", fi.LastFetch.Format("2006-01-02 15:04:05"), age)
			} else {
				fmt.Printf("    Last fetch: never\n")
			}
		}
	}

	return nil
}

func (c *CLI) showSecurityAlarms(args []string) error {
	detail := len(args) >= 1 && args[0] == "detail"

	cfg := c.store.ActiveConfig()
	var alarmCount int

	// Config validation warnings
	if cfg != nil {
		warnings := config.ValidateConfig(cfg)
		for _, w := range warnings {
			alarmCount++
			if detail {
				fmt.Printf("Alarm %d:\n  Class: Configuration\n  Severity: Warning\n  Description: %s\n\n", alarmCount, w)
			}
		}
	}

	// Screen drop alarms — any non-zero screen counter indicates detected attacks
	if c.dp != nil && c.dp.IsLoaded() {
		readCtr := func(idx uint32) uint64 {
			v, _ := c.dp.ReadGlobalCounter(idx)
			return v
		}
		screenNames := []struct {
			idx  uint32
			name string
		}{
			{dataplane.GlobalCtrScreenSynFlood, "SYN flood"},
			{dataplane.GlobalCtrScreenICMPFlood, "ICMP flood"},
			{dataplane.GlobalCtrScreenUDPFlood, "UDP flood"},
			{dataplane.GlobalCtrScreenLandAttack, "LAND attack"},
			{dataplane.GlobalCtrScreenPingOfDeath, "Ping of death"},
			{dataplane.GlobalCtrScreenTearDrop, "Tear-drop"},
			{dataplane.GlobalCtrScreenTCPSynFin, "TCP SYN+FIN"},
			{dataplane.GlobalCtrScreenTCPNoFlag, "TCP no-flag"},
			{dataplane.GlobalCtrScreenTCPFinNoAck, "TCP FIN-no-ACK"},
			{dataplane.GlobalCtrScreenWinNuke, "WinNuke"},
			{dataplane.GlobalCtrScreenIPSrcRoute, "IP source-route"},
			{dataplane.GlobalCtrScreenSynFrag, "SYN fragment"},
		}
		for _, s := range screenNames {
			val := readCtr(s.idx)
			if val > 0 {
				alarmCount++
				if detail {
					fmt.Printf("Alarm %d:\n  Class: IDS\n  Severity: Major\n  Description: %s attack detected (%d drops)\n\n", alarmCount, s.name, val)
				}
			}
		}
	}

	if alarmCount == 0 {
		fmt.Println("No security alarms currently active")
	} else if !detail {
		fmt.Printf("%d security alarm(s) currently active\n", alarmCount)
		fmt.Println("  run 'show security alarms detail' for details")
	}

	return nil
}

func (c *CLI) showALG() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	alg := &cfg.Security.ALG
	fmt.Println("ALG Status:")

	printALG := func(name string, disabled bool) {
		status := "Enabled"
		if disabled {
			status = "Disabled"
		}
		fmt.Printf("  %-9s: %s\n", name, status)
	}

	printALG("DNS", alg.DNSDisable)
	printALG("FTP", alg.FTPDisable)
	printALG("H323", false)
	printALG("MGCP", false)
	printALG("MSRPC", false)
	printALG("PPTP", false)
	printALG("RSH", true)
	printALG("RTSP", false)
	printALG("SCCP", false)
	printALG("SIP", alg.SIPDisable)
	printALG("SQL", true)
	printALG("SUNRPC", false)
	printALG("TALK", false)
	printALG("TFTP", alg.TFTPDisable)
	printALG("IKE-ESP", true)
	printALG("TWAMP", true)

	return nil
}

// showMatchPolicies performs a 5-tuple policy lookup and shows matching rules.

func (c *CLI) showMatchPolicies(cfg *config.Config, args []string) error {
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}

	// Parse arguments: from-zone <z> to-zone <z> source-ip <ip> destination-ip <ip>
	//                   destination-port <p> protocol <proto>
	var fromZone, toZone, srcIP, dstIP, proto string
	var dstPort int
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "from-zone":
			if i+1 < len(args) {
				i++
				fromZone = args[i]
			}
		case "to-zone":
			if i+1 < len(args) {
				i++
				toZone = args[i]
			}
		case "source-ip":
			if i+1 < len(args) {
				i++
				srcIP = args[i]
			}
		case "destination-ip":
			if i+1 < len(args) {
				i++
				dstIP = args[i]
			}
		case "destination-port":
			if i+1 < len(args) {
				i++
				dstPort, _ = strconv.Atoi(args[i])
			}
		case "protocol":
			if i+1 < len(args) {
				i++
				proto = args[i]
			}
		}
	}

	if fromZone == "" || toZone == "" {
		fmt.Println("usage: show security match-policies from-zone <zone> to-zone <zone>")
		fmt.Println("       source-ip <ip> destination-ip <ip> destination-port <port> protocol <tcp|udp>")
		return nil
	}

	parsedSrc := net.ParseIP(srcIP)
	parsedDst := net.ParseIP(dstIP)

	// Find the zone-pair policy
	for _, zpp := range cfg.Security.Policies {
		if zpp.FromZone != fromZone || zpp.ToZone != toZone {
			continue
		}

		for _, pol := range zpp.Policies {
			// Check source address match
			if !matchPolicyAddr(pol.Match.SourceAddresses, parsedSrc, cfg) {
				continue
			}
			// Check destination address match
			if !matchPolicyAddr(pol.Match.DestinationAddresses, parsedDst, cfg) {
				continue
			}
			// Check application match
			if !matchPolicyApp(pol.Match.Applications, proto, dstPort, cfg) {
				continue
			}

			// Found a match
			action := "permit"
			switch pol.Action {
			case 1:
				action = "deny"
			case 2:
				action = "reject"
			}
			fmt.Printf("Matching policy:\n")
			fmt.Printf("  From zone: %s, To zone: %s\n", fromZone, toZone)
			fmt.Printf("  Policy: %s\n", pol.Name)
			if pol.Description != "" {
				fmt.Printf("    Description: %s\n", pol.Description)
			}
			fmt.Printf("    Source addresses: %v\n", pol.Match.SourceAddresses)
			fmt.Printf("    Destination addresses: %v\n", pol.Match.DestinationAddresses)
			fmt.Printf("    Applications: %v\n", pol.Match.Applications)
			fmt.Printf("    Action: %s\n", action)
			return nil
		}
	}

	fmt.Printf("No matching policy found for %s -> %s (default deny)\n", fromZone, toZone)
	return nil
}
