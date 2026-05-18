// Phase 8 of #1043: extract the `zones-detail` ShowText case body
// into a dedicated method. Same methodology as Phases 1-7 (#1148,
// #1150, #1151, #1153, #1154, #1155, #1156): semantic relocation, no
// behavior change. The case body is moved verbatim apart from
// (a) `&buf` references becoming `buf` (passed-in `*strings.Builder`)
// and (b) the original `if cfg == nil { … } else { … long body }`
// flattened into early-return form. Output is unchanged.

package grpcapi

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// showZonesDetail renders per-zone configuration plus dataplane traffic
// counters, policy references, interface details, screen profile
// breakdown, and policy-rule summaries.
func (s *Server) showZonesDetail(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		buf.WriteString("No security zones configured\n")
		return
	}
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	cr := s.applyResult()
	for _, name := range zoneNames {
		zone := cfg.Security.Zones[name]
		var zoneID uint16
		if cr != nil {
			zoneID = cr.ZoneIDs[name]
		}
		if zoneID > 0 {
			fmt.Fprintf(buf, "Zone: %s (id: %d)\n", name, zoneID)
		} else {
			fmt.Fprintf(buf, "Zone: %s\n", name)
		}
		if zone.Description != "" {
			fmt.Fprintf(buf, "  Description: %s\n", zone.Description)
		}
		fmt.Fprintf(buf, "  Interfaces: %s\n", strings.Join(zone.Interfaces, ", "))
		if zone.TCPRst {
			buf.WriteString("  TCP RST: enabled\n")
		}
		if zone.ScreenProfile != "" {
			fmt.Fprintf(buf, "  Screen: %s\n", zone.ScreenProfile)
		}
		if zone.HostInboundTraffic != nil {
			if len(zone.HostInboundTraffic.SystemServices) > 0 {
				fmt.Fprintf(buf, "  Host-inbound system-services: %s\n",
					strings.Join(zone.HostInboundTraffic.SystemServices, ", "))
			}
			if len(zone.HostInboundTraffic.Protocols) > 0 {
				fmt.Fprintf(buf, "  Host-inbound protocols: %s\n",
					strings.Join(zone.HostInboundTraffic.Protocols, ", "))
			}
		}
		// Traffic counters
		if s.dp != nil && s.dp.IsLoaded() && zoneID > 0 {
			ingress, errIn := s.dp.ReadZoneCounters(zoneID, 0)
			egress, errOut := s.dp.ReadZoneCounters(zoneID, 1)
			if errIn == nil && errOut == nil {
				buf.WriteString("  Traffic statistics:\n")
				fmt.Fprintf(buf, "    Input:  %d packets, %d bytes\n", ingress.Packets, ingress.Bytes)
				fmt.Fprintf(buf, "    Output: %d packets, %d bytes\n", egress.Packets, egress.Bytes)
			}
		}
		// Policies referencing this zone
		var policyRefs []string
		for _, zpp := range cfg.Security.Policies {
			if zpp.FromZone == name || zpp.ToZone == name {
				dir := "from"
				peer := zpp.ToZone
				if zpp.ToZone == name {
					dir = "to"
					peer = zpp.FromZone
				}
				policyRefs = append(policyRefs, fmt.Sprintf("%s %s (%d rules)", dir, peer, len(zpp.Policies)))
			}
		}
		if len(policyRefs) > 0 {
			fmt.Fprintf(buf, "  Policies: %s\n", strings.Join(policyRefs, ", "))
		}
		// Detail: per-interface info
		if len(zone.Interfaces) > 0 {
			buf.WriteString("  Interface details:\n")
			for _, ifName := range zone.Interfaces {
				fmt.Fprintf(buf, "    %s:\n", ifName)
				if ifc, ok := cfg.Interfaces.Interfaces[ifName]; ok {
					for _, unit := range ifc.Units {
						for _, addr := range unit.Addresses {
							fmt.Fprintf(buf, "      Address: %s\n", addr)
						}
						if unit.DHCP {
							buf.WriteString("      DHCPv4: enabled\n")
						}
						if unit.DHCPv6 {
							buf.WriteString("      DHCPv6: enabled\n")
						}
					}
				}
			}
		}
		// Screen profile detail
		if zone.ScreenProfile != "" {
			if profile, ok := cfg.Security.Screen[zone.ScreenProfile]; ok {
				fmt.Fprintf(buf, "  Screen profile details (%s):\n", zone.ScreenProfile)
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
					fmt.Fprintf(buf, "    Enabled checks: %s\n", strings.Join(checks, ", "))
				}
			}
		}
		// Policy detail breakdown
		buf.WriteString("  Policy summary:\n")
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
					fmt.Fprintf(buf, "    %s -> %s: %s (%s)\n",
						zpp.FromZone, zpp.ToZone, pol.Name, action)
					totalPolicies++
				}
			}
		}
		if totalPolicies == 0 {
			buf.WriteString("    (no policies)\n")
		}
		buf.WriteString("\n")
	}
}
