package grpcapi

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/feeds"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func writeRPMConfig(buf *strings.Builder, cfg *config.Config) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
		return
	}
	if cfg.Services.RPM == nil || len(cfg.Services.RPM.Probes) == 0 {
		buf.WriteString("No RPM probes configured\n")
		return
	}

	buf.WriteString("RPM Probe Configuration:\n")
	for _, probeName := range rpm.SortedProbeNames(cfg.Services.RPM.Probes) {
		probe := cfg.Services.RPM.Probes[probeName]
		for _, testName := range rpm.SortedTestNames(probe.Tests) {
			rpm.WriteConfiguredTest(buf, probeName, testName, probe.Tests[testName])
			buf.WriteString("\n")
		}
	}
}

func firewallFilterTermExpansionCount(cfg *config.Config, term *config.FirewallFilterTerm) uint32 {
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

// --- Operational show RPCs ---

// --- GetSystemInfo RPC ---

// --- ShowText RPC ---

func (s *Server) ShowText(ctx context.Context, req *pb.ShowTextRequest) (*pb.ShowTextResponse, error) {
	cfg := s.store.ActiveConfig()
	var buf strings.Builder

	// Handle parameterized topics (prefix:value format)
	if strings.HasPrefix(req.Topic, "route-table:") {
		tableName := strings.TrimPrefix(req.Topic, "route-table:")
		if s.routing == nil {
			buf.WriteString("Routing manager not available\n")
		} else {
			entries, err := s.routing.GetTableRoutes(tableName)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "get table routes: %v", err)
			}
			if len(entries) == 0 {
				fmt.Fprintf(&buf, "No routes in table %s\n", tableName)
			} else {
				buf.WriteString(routing.FormatAllRoutes([]routing.TableRoutes{{Name: tableName, Entries: entries}}))
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if strings.HasPrefix(req.Topic, "route-protocol:") {
		proto := strings.ToLower(strings.TrimPrefix(req.Topic, "route-protocol:"))
		if s.routing == nil {
			buf.WriteString("Routing manager not available\n")
		} else {
			entries, err := s.routing.GetRoutes()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "get routes: %v", err)
			}
			fmt.Fprintf(&buf, "Routes matching protocol: %s\n", proto)
			fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %s\n", "Destination", "Next-hop", "Interface", "Proto", "Pref")
			count := 0
			for _, e := range entries {
				if strings.ToLower(e.Protocol) == proto {
					fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %d\n",
						e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
					count++
				}
			}
			if count == 0 {
				buf.WriteString("  (no routes)\n")
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if strings.HasPrefix(req.Topic, "route-prefix:") {
		prefixAndMod := strings.TrimPrefix(req.Topic, "route-prefix:")
		prefix := prefixAndMod
		modifier := ""
		if idx := strings.LastIndex(prefixAndMod, " "); idx != -1 {
			candidate := prefixAndMod[idx+1:]
			switch candidate {
			case "exact", "longer", "orlonger":
				prefix = prefixAndMod[:idx]
				modifier = candidate
			}
		}
		if s.routing == nil {
			buf.WriteString("Routing manager not available\n")
		} else {
			var instances []*config.RoutingInstanceConfig
			if cfg != nil {
				instances = cfg.RoutingInstances
			}
			allTables, err := s.routing.GetAllTableRoutes(instances)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "get routes: %v", err)
			}
			buf.WriteString(routing.FormatRouteDestination(allTables, prefix, modifier))
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if req.Topic == "class-of-service" || strings.HasPrefix(req.Topic, "class-of-service:") {
		selector := ""
		if strings.HasPrefix(req.Topic, "class-of-service:") {
			selector = strings.TrimPrefix(req.Topic, "class-of-service:")
		}
		var status *dpuserspace.ProcessStatus
		if userspaceStatus, err := s.userspaceDataplaneStatus(); err == nil {
			status = &userspaceStatus
		}
		buf.WriteString(dpuserspace.FormatCoSInterfaceSummary(cfg, status, selector))
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if strings.HasPrefix(req.Topic, "screen-ids-option:") {
		profileName := strings.TrimPrefix(req.Topic, "screen-ids-option:")
		if cfg == nil || len(cfg.Security.Screen) == 0 {
			buf.WriteString("No screen profiles configured\n")
		} else {
			profile, ok := cfg.Security.Screen[profileName]
			if !ok {
				fmt.Fprintf(&buf, "Screen profile '%s' not found\n", profileName)
			} else {
				fmt.Fprintf(&buf, "Screen object status:\n\n")
				fmt.Fprintf(&buf, "  Name                                        Value\n")
				if profile.TCP.Land {
					fmt.Fprintf(&buf, "  TCP land attack                             enabled\n")
				}
				if profile.TCP.SynFin {
					fmt.Fprintf(&buf, "  TCP SYN+FIN                                 enabled\n")
				}
				if profile.TCP.NoFlag {
					fmt.Fprintf(&buf, "  TCP no-flag                                 enabled\n")
				}
				if profile.TCP.FinNoAck {
					fmt.Fprintf(&buf, "  TCP FIN-no-ACK                              enabled\n")
				}
				if profile.TCP.WinNuke {
					fmt.Fprintf(&buf, "  TCP WinNuke                                 enabled\n")
				}
				if profile.TCP.SynFrag {
					fmt.Fprintf(&buf, "  TCP SYN fragment                            enabled\n")
				}
				if profile.TCP.SynFlood != nil {
					fmt.Fprintf(&buf, "  TCP SYN flood attack threshold              %d\n",
						profile.TCP.SynFlood.AttackThreshold)
					if profile.TCP.SynFlood.SourceThreshold > 0 {
						fmt.Fprintf(&buf, "  TCP SYN flood source threshold              %d\n",
							profile.TCP.SynFlood.SourceThreshold)
					}
					if profile.TCP.SynFlood.DestinationThreshold > 0 {
						fmt.Fprintf(&buf, "  TCP SYN flood destination threshold          %d\n",
							profile.TCP.SynFlood.DestinationThreshold)
					}
					if profile.TCP.SynFlood.Timeout > 0 {
						fmt.Fprintf(&buf, "  TCP SYN flood timeout                       %d\n",
							profile.TCP.SynFlood.Timeout)
					}
				}
				if profile.ICMP.PingDeath {
					fmt.Fprintf(&buf, "  ICMP ping of death                          enabled\n")
				}
				if profile.ICMP.FloodThreshold > 0 {
					fmt.Fprintf(&buf, "  ICMP flood threshold                        %d\n",
						profile.ICMP.FloodThreshold)
				}
				if profile.IP.SourceRouteOption {
					fmt.Fprintf(&buf, "  IP source route option                      enabled\n")
				}
				if profile.UDP.FloodThreshold > 0 {
					fmt.Fprintf(&buf, "  UDP flood threshold                         %d\n",
						profile.UDP.FloodThreshold)
				}
				// Show which zones use this profile
				var zones []string
				for name, zone := range cfg.Security.Zones {
					if zone.ScreenProfile == profileName {
						zones = append(zones, name)
					}
				}
				if len(zones) > 0 {
					sort.Strings(zones)
					fmt.Fprintf(&buf, "\n  Bound to zones: %s\n", strings.Join(zones, ", "))
				}
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if strings.HasPrefix(req.Topic, "screen-statistics:") {
		zoneName := strings.TrimPrefix(req.Topic, "screen-statistics:")
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else if s.dp == nil || !s.dp.IsLoaded() {
			buf.WriteString("Dataplane not loaded\n")
		} else {
			cr := s.dp.LastCompileResult()
			if cr == nil {
				buf.WriteString("No compile result available\n")
			} else {
				zoneID, ok := cr.ZoneIDs[zoneName]
				if !ok {
					fmt.Fprintf(&buf, "Zone '%s' not found\n", zoneName)
				} else {
					fs, err := s.dp.ReadFloodCounters(zoneID)
					if err != nil {
						fmt.Fprintf(&buf, "Error reading flood counters: %v\n", err)
					} else {
						screenProfile := ""
						if z, ok := cfg.Security.Zones[zoneName]; ok {
							screenProfile = z.ScreenProfile
						}
						fmt.Fprintf(&buf, "Screen statistics for zone '%s':\n", zoneName)
						if screenProfile != "" {
							fmt.Fprintf(&buf, "  Screen profile: %s\n", screenProfile)
						}
						fmt.Fprintf(&buf, "  %-30s %s\n", "Counter", "Value")
						fmt.Fprintf(&buf, "  %-30s %d\n", "SYN flood events", fs.SynCount)
						fmt.Fprintf(&buf, "  %-30s %d\n", "ICMP flood events", fs.ICMPCount)
						fmt.Fprintf(&buf, "  %-30s %d\n", "UDP flood events", fs.UDPCount)
					}
				}
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if req.Topic == "screen-statistics-all" {
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else if s.dp == nil || !s.dp.IsLoaded() {
			buf.WriteString("Dataplane not loaded\n")
		} else if cr := s.dp.LastCompileResult(); cr == nil {
			buf.WriteString("No compile result available\n")
		} else {
			var zones []string
			for name := range cr.ZoneIDs {
				zones = append(zones, name)
			}
			sort.Strings(zones)
			for _, zoneName := range zones {
				zoneID := cr.ZoneIDs[zoneName]
				fs, err := s.dp.ReadFloodCounters(zoneID)
				if err != nil {
					continue
				}
				screenProfile := ""
				if z, ok := cfg.Security.Zones[zoneName]; ok {
					screenProfile = z.ScreenProfile
				}
				fmt.Fprintf(&buf, "Screen statistics for zone '%s':\n", zoneName)
				if screenProfile != "" {
					fmt.Fprintf(&buf, "  Screen profile: %s\n", screenProfile)
				}
				fmt.Fprintf(&buf, "  %-30s %s\n", "Counter", "Value")
				fmt.Fprintf(&buf, "  %-30s %d\n", "SYN flood events", fs.SynCount)
				fmt.Fprintf(&buf, "  %-30s %d\n", "ICMP flood events", fs.ICMPCount)
				fmt.Fprintf(&buf, "  %-30s %d\n", "UDP flood events", fs.UDPCount)
				buf.WriteString("\n")
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if strings.HasPrefix(req.Topic, "screen-ids-option-detail:") {
		profileName := strings.TrimPrefix(req.Topic, "screen-ids-option-detail:")
		if cfg == nil || len(cfg.Security.Screen) == 0 {
			buf.WriteString("No screen profiles configured\n")
		} else {
			profile, ok := cfg.Security.Screen[profileName]
			if !ok {
				fmt.Fprintf(&buf, "Screen profile '%s' not found\n", profileName)
			} else {
				fmt.Fprintf(&buf, "Screen object status (detail):\n\n")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "Name", "Value", "Default")
				enabledS := func(v bool) string {
					if v {
						return "enabled"
					}
					return "disabled"
				}
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP land attack", enabledS(profile.TCP.Land), "disabled")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP SYN+FIN", enabledS(profile.TCP.SynFin), "disabled")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP no-flag", enabledS(profile.TCP.NoFlag), "disabled")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP FIN-no-ACK", enabledS(profile.TCP.FinNoAck), "disabled")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP WinNuke", enabledS(profile.TCP.WinNuke), "disabled")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP SYN fragment", enabledS(profile.TCP.SynFrag), "disabled")
				if profile.TCP.SynFlood != nil {
					fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP SYN flood protection", "enabled", "disabled")
					fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "  Attack threshold", profile.TCP.SynFlood.AttackThreshold, "200")
					if profile.TCP.SynFlood.AlarmThreshold > 0 {
						fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "  Alarm threshold", profile.TCP.SynFlood.AlarmThreshold, "512")
					} else {
						fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "  Alarm threshold", "(default)", "512")
					}
					if profile.TCP.SynFlood.SourceThreshold > 0 {
						fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "  Source threshold", profile.TCP.SynFlood.SourceThreshold, "4000")
					} else {
						fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "  Source threshold", "(default)", "4000")
					}
					if profile.TCP.SynFlood.DestinationThreshold > 0 {
						fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "  Destination threshold", profile.TCP.SynFlood.DestinationThreshold, "4000")
					} else {
						fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "  Destination threshold", "(default)", "4000")
					}
					if profile.TCP.SynFlood.Timeout > 0 {
						fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "  Timeout (seconds)", profile.TCP.SynFlood.Timeout, "20")
					} else {
						fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "  Timeout (seconds)", "(default)", "20")
					}
				} else {
					fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "TCP SYN flood protection", "disabled", "disabled")
				}
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "ICMP ping of death", enabledS(profile.ICMP.PingDeath), "disabled")
				if profile.ICMP.FloodThreshold > 0 {
					fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "ICMP flood threshold", profile.ICMP.FloodThreshold, "1000")
				} else {
					fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "ICMP flood threshold", "disabled", "disabled")
				}
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "IP source route option", enabledS(profile.IP.SourceRouteOption), "disabled")
				fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "IP teardrop", enabledS(profile.IP.TearDrop), "disabled")
				if profile.UDP.FloodThreshold > 0 {
					fmt.Fprintf(&buf, "  %-45s %-12d %s\n", "UDP flood threshold", profile.UDP.FloodThreshold, "1000")
				} else {
					fmt.Fprintf(&buf, "  %-45s %-12s %s\n", "UDP flood threshold", "disabled", "disabled")
				}
				var zones []string
				for name, zone := range cfg.Security.Zones {
					if zone.ScreenProfile == profileName {
						zones = append(zones, name)
					}
				}
				if len(zones) > 0 {
					sort.Strings(zones)
					fmt.Fprintf(&buf, "\n  Bound to zones: %s\n", strings.Join(zones, ", "))
				} else {
					fmt.Fprintf(&buf, "\n  Bound to zones: (none)\n")
				}
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	// test policy: "test-policy:from=X,to=Y,src=A,dst=B,port=P,proto=TCP"
	if strings.HasPrefix(req.Topic, "test-policy:") {
		params := strings.TrimPrefix(req.Topic, "test-policy:")
		var fromZone, toZone, srcIP, dstIP, proto string
		var dstPort int
		for _, kv := range strings.Split(params, ",") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				continue
			}
			switch parts[0] {
			case "from":
				fromZone = parts[1]
			case "to":
				toZone = parts[1]
			case "src":
				srcIP = parts[1]
			case "dst":
				dstIP = parts[1]
			case "port":
				dstPort, _ = strconv.Atoi(parts[1])
			case "proto":
				proto = parts[1]
			}
		}
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else if fromZone == "" || toZone == "" {
			buf.WriteString("Missing from/to zone parameters\n")
		} else {
			parsedSrc := net.ParseIP(srcIP)
			parsedDst := net.ParseIP(dstIP)
			found := false
			for _, zpp := range cfg.Security.Policies {
				if zpp.FromZone != fromZone || zpp.ToZone != toZone {
					continue
				}
				for _, pol := range zpp.Policies {
					if !matchShowPolicyAddr(pol.Match.SourceAddresses, parsedSrc, cfg) {
						continue
					}
					if !matchShowPolicyAddr(pol.Match.DestinationAddresses, parsedDst, cfg) {
						continue
					}
					if !matchShowPolicyApp(pol.Match.Applications, proto, dstPort, cfg) {
						continue
					}
					action := policyActionName(pol.Action)
					fmt.Fprintf(&buf, "Policy match:\n")
					fmt.Fprintf(&buf, "  From zone: %s\n  To zone:   %s\n", fromZone, toZone)
					fmt.Fprintf(&buf, "  Policy:    %s\n", pol.Name)
					fmt.Fprintf(&buf, "  Action:    %s\n", action)
					found = true
					break
				}
				if found {
					break
				}
			}
			if !found {
				// Check global policies
				for _, pol := range cfg.Security.GlobalPolicies {
					if !matchShowPolicyAddr(pol.Match.SourceAddresses, parsedSrc, cfg) {
						continue
					}
					if !matchShowPolicyAddr(pol.Match.DestinationAddresses, parsedDst, cfg) {
						continue
					}
					if !matchShowPolicyApp(pol.Match.Applications, proto, dstPort, cfg) {
						continue
					}
					action := policyActionName(pol.Action)
					fmt.Fprintf(&buf, "Policy match (global):\n")
					fmt.Fprintf(&buf, "  Policy:    %s\n", pol.Name)
					fmt.Fprintf(&buf, "  Action:    %s\n", action)
					found = true
					break
				}
			}
			if !found {
				fmt.Fprintf(&buf, "Default deny (no matching policy for %s -> %s)\n", fromZone, toZone)
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	// test routing: "test-routing:dest=10.0.0.0/24" or "test-routing:dest=10.0.0.0/24,instance=dmz-vr"
	if strings.HasPrefix(req.Topic, "test-routing:") {
		params := strings.TrimPrefix(req.Topic, "test-routing:")
		var dest, instance string
		for _, kv := range strings.Split(params, ",") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				continue
			}
			switch parts[0] {
			case "dest":
				dest = parts[1]
			case "instance":
				instance = parts[1]
			}
		}
		if s.routing == nil {
			buf.WriteString("Routing manager not available\n")
		} else if dest == "" {
			buf.WriteString("Missing dest parameter\n")
		} else {
			var entries []routing.RouteEntry
			var err error
			if instance != "" {
				entries, err = s.routing.GetVRFRoutes(instance)
			} else {
				entries, err = s.routing.GetRoutes()
			}
			if err != nil {
				return nil, status.Errorf(codes.Internal, "get routes: %v", err)
			}
			filterCIDR := dest
			if !strings.Contains(filterCIDR, "/") {
				if strings.Contains(filterCIDR, ":") {
					filterCIDR += "/128"
				} else {
					filterCIDR += "/32"
				}
			}
			filterIP, _, filterErr := net.ParseCIDR(filterCIDR)
			if filterErr != nil {
				filterIP = net.ParseIP(dest)
			}
			var best *routing.RouteEntry
			bestLen := -1
			for i := range entries {
				_, rNet, err := net.ParseCIDR(entries[i].Destination)
				if err != nil {
					continue
				}
				if filterIP != nil && rNet.Contains(filterIP) {
					ones, _ := rNet.Mask.Size()
					if ones > bestLen {
						bestLen = ones
						best = &entries[i]
					}
				}
			}
			if instance != "" {
				fmt.Fprintf(&buf, "Routing lookup in instance %s for %s:\n", instance, dest)
			} else {
				fmt.Fprintf(&buf, "Routing lookup for %s:\n", dest)
			}
			if best == nil {
				buf.WriteString("  No matching route found\n")
			} else {
				fmt.Fprintf(&buf, "  Destination: %s\n", best.Destination)
				fmt.Fprintf(&buf, "  Next-hop:    %s\n", best.NextHop)
				fmt.Fprintf(&buf, "  Interface:   %s\n", best.Interface)
				fmt.Fprintf(&buf, "  Protocol:    %s\n", best.Protocol)
				fmt.Fprintf(&buf, "  Preference:  %d\n", best.Preference)
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	// test security-zone: "test-zone:interface=trust0"
	if strings.HasPrefix(req.Topic, "test-zone:") {
		params := strings.TrimPrefix(req.Topic, "test-zone:")
		var ifName string
		for _, kv := range strings.Split(params, ",") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 && parts[0] == "interface" {
				ifName = parts[1]
			}
		}
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else if ifName == "" {
			buf.WriteString("Missing interface parameter\n")
		} else {
			found := false
			for zoneName, zone := range cfg.Security.Zones {
				for _, iface := range zone.Interfaces {
					if iface == ifName {
						fmt.Fprintf(&buf, "Interface %s belongs to zone: %s\n", ifName, zoneName)
						if zone.Description != "" {
							fmt.Fprintf(&buf, "  Description: %s\n", zone.Description)
						}
						if zone.ScreenProfile != "" {
							fmt.Fprintf(&buf, "  Screen:      %s\n", zone.ScreenProfile)
						}
						if zone.HostInboundTraffic != nil {
							if len(zone.HostInboundTraffic.SystemServices) > 0 {
								fmt.Fprintf(&buf, "  Host-inbound services: %s\n", strings.Join(zone.HostInboundTraffic.SystemServices, ", "))
							}
							if len(zone.HostInboundTraffic.Protocols) > 0 {
								fmt.Fprintf(&buf, "  Host-inbound protocols: %s\n", strings.Join(zone.HostInboundTraffic.Protocols, ", "))
							}
						}
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				fmt.Fprintf(&buf, "Interface %s is not assigned to any security zone\n", ifName)
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	if strings.HasPrefix(req.Topic, "firewall-filter:") {
		filterTopic := strings.TrimPrefix(req.Topic, "firewall-filter:")
		filterName := filterTopic
		requestedFamily := ""
		if idx := strings.LastIndex(filterTopic, ":"); idx > 0 {
			filterName = filterTopic[:idx]
			requestedFamily = filterTopic[idx+1:]
		}
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			var filter *config.FirewallFilter
			var family string
			switch requestedFamily {
			case "":
				if f, ok := cfg.Firewall.FiltersInet[filterName]; ok {
					filter = f
					family = "inet"
				} else if f, ok := cfg.Firewall.FiltersInet6[filterName]; ok {
					filter = f
					family = "inet6"
				}
			case "inet":
				filter = cfg.Firewall.FiltersInet[filterName]
				family = "inet"
			case "inet6":
				filter = cfg.Firewall.FiltersInet6[filterName]
				family = "inet6"
			default:
				fmt.Fprintf(&buf, "invalid family: %s\n", requestedFamily)
				return &pb.ShowTextResponse{Output: buf.String()}, nil
			}
			if filter == nil {
				if requestedFamily != "" {
					fmt.Fprintf(&buf, "Filter not found: %s (family %s)\n", filterName, requestedFamily)
				} else {
					fmt.Fprintf(&buf, "Filter not found: %s\n", filterName)
				}
			} else {
				var userspaceStatus *dpuserspace.ProcessStatus
				if status, err := s.userspaceDataplaneStatus(); err == nil {
					userspaceStatus = &status
				}
				userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)
				var filterIDs map[string]uint32
				if s.dp != nil && s.dp.IsLoaded() {
					if cr := s.dp.LastCompileResult(); cr != nil {
						filterIDs = cr.FilterIDs
					}
				}
				var ruleStart uint32
				var hasCounters bool
				if filterIDs != nil {
					if fid, ok := filterIDs[family+":"+filterName]; ok {
						if fcfg, err := s.dp.ReadFilterConfig(fid); err == nil {
							ruleStart = fcfg.RuleStart
							hasCounters = true
						}
					}
				}
				fmt.Fprintf(&buf, "Filter: %s (family %s)\n", filterName, family)
				ruleOffset := ruleStart
				for _, term := range filter.Terms {
					fmt.Fprintf(&buf, "\n  Term: %s\n", term.Name)
					if term.DSCP != "" {
						fmt.Fprintf(&buf, "    from dscp %s\n", term.DSCP)
					}
					if term.Protocol != "" {
						fmt.Fprintf(&buf, "    from protocol %s\n", term.Protocol)
					}
					for _, addr := range term.SourceAddresses {
						fmt.Fprintf(&buf, "    from source-address %s\n", addr)
					}
					for _, pl := range term.SourcePrefixLists {
						if pl.Except {
							fmt.Fprintf(&buf, "    from source-prefix-list %s except\n", pl.Name)
						} else {
							fmt.Fprintf(&buf, "    from source-prefix-list %s\n", pl.Name)
						}
					}
					for _, addr := range term.DestAddresses {
						fmt.Fprintf(&buf, "    from destination-address %s\n", addr)
					}
					for _, pl := range term.DestPrefixLists {
						if pl.Except {
							fmt.Fprintf(&buf, "    from destination-prefix-list %s except\n", pl.Name)
						} else {
							fmt.Fprintf(&buf, "    from destination-prefix-list %s\n", pl.Name)
						}
					}
					if len(term.SourcePorts) > 0 {
						fmt.Fprintf(&buf, "    from source-port %s\n", strings.Join(term.SourcePorts, ", "))
					}
					if len(term.DestinationPorts) > 0 {
						fmt.Fprintf(&buf, "    from destination-port %s\n", strings.Join(term.DestinationPorts, ", "))
					}
					if term.ICMPType >= 0 {
						fmt.Fprintf(&buf, "    from icmp-type %d\n", term.ICMPType)
					}
					if term.ICMPCode >= 0 {
						fmt.Fprintf(&buf, "    from icmp-code %d\n", term.ICMPCode)
					}
					if term.RoutingInstance != "" {
						fmt.Fprintf(&buf, "    then routing-instance %s\n", term.RoutingInstance)
					}
					if term.ForwardingClass != "" {
						fmt.Fprintf(&buf, "    then forwarding-class %s\n", term.ForwardingClass)
					}
					if term.LossPriority != "" {
						fmt.Fprintf(&buf, "    then loss-priority %s\n", term.LossPriority)
					}
					if term.Log {
						buf.WriteString("    then log\n")
					}
					if term.Count != "" {
						fmt.Fprintf(&buf, "    then count %s\n", term.Count)
					}
					action := term.Action
					if action == "" {
						action = "accept"
					}
					fmt.Fprintf(&buf, "    then %s\n", action)
					numRules := firewallFilterTermExpansionCount(cfg, term)
					var totalPkts, totalBytes uint64
					if hasCounters {
						for i := uint32(0); i < numRules; i++ {
							if ctrs, err := s.dp.ReadFilterCounters(ruleOffset + i); err == nil {
								totalPkts += ctrs.Packets
								totalBytes += ctrs.Bytes
							}
						}
						ruleOffset += numRules
					}
					userspaceCounter, userspaceOk := userspaceCounters[dpuserspace.FirewallFilterTermCounterKey{
						Family: family, FilterName: filterName, TermName: term.Name,
					}]
					if userspaceOk {
						totalPkts += userspaceCounter.Packets
						totalBytes += userspaceCounter.Bytes
					}
					if hasCounters || userspaceOk {
						fmt.Fprintf(&buf, "    Hit count: %d packets, %d bytes\n", totalPkts, totalBytes)
					}
				}
				buf.WriteString("\n")
			}
		}
		return &pb.ShowTextResponse{Output: buf.String()}, nil
	}

	switch req.Topic {
	case "zones-detail":
		// #1043 Phase 8: case body extracted to server_show_zones_text.go
		s.showZonesDetail(cfg, &buf)

	case "ipsec-statistics":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		if err := s.showIPsecStatistics(cfg, &buf); err != nil {
			return nil, err
		}

	case "schedulers":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		s.showSchedulers(cfg, &buf)

	case "snmp":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showSNMP(cfg, &buf)

	case "snmp-v3":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showSNMPv3(cfg, &buf)

	case "dhcp-server":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showDHCPServer(&buf)

	case "dhcp-server-detail":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showDHCPServerDetail(cfg, &buf)

	case "dhcp-relay":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showDHCPRelay(cfg, &buf)

	case "lldp":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showLLDP(cfg, &buf)

	case "lldp-neighbors":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showLLDPNeighbors(&buf)

	case "firewall":
		// #1043 Phase 1: case body extracted to server_show_firewall.go
		s.showFirewall(cfg, &buf)

	case "alg":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			alg := cfg.Security.ALG
			fmt.Fprintf(&buf, "SIP:  %s\n", boolStatus(!alg.SIPDisable))
			fmt.Fprintf(&buf, "FTP:  %s\n", boolStatus(!alg.FTPDisable))
			fmt.Fprintf(&buf, "TFTP: %s\n", boolStatus(!alg.TFTPDisable))
			fmt.Fprintf(&buf, "DNS:  %s\n", boolStatus(!alg.DNSDisable))
		}

	case "dynamic-address":
		if cfg == nil || len(cfg.Security.DynamicAddress.FeedServers) == 0 {
			buf.WriteString("No dynamic address feeds configured\n")
		} else {
			var runtimeFeeds map[string]feeds.FeedInfo
			if s.feedsFn != nil {
				runtimeFeeds = s.feedsFn()
			}
			for name, feed := range cfg.Security.DynamicAddress.FeedServers {
				fmt.Fprintf(&buf, "Feed server: %s\n", name)
				fmt.Fprintf(&buf, "  URL: %s\n", feed.URL)
				if feed.FeedName != "" {
					fmt.Fprintf(&buf, "  Feed name: %s\n", feed.FeedName)
				}
				if feed.UpdateInterval > 0 {
					fmt.Fprintf(&buf, "  Update interval: %ds\n", feed.UpdateInterval)
				}
				if feed.HoldInterval > 0 {
					fmt.Fprintf(&buf, "  Hold interval: %ds\n", feed.HoldInterval)
				}
				if fi, ok := runtimeFeeds[name]; ok {
					fmt.Fprintf(&buf, "  Prefixes: %d\n", fi.Prefixes)
					if !fi.LastFetch.IsZero() {
						age := time.Since(fi.LastFetch).Truncate(time.Second)
						fmt.Fprintf(&buf, "  Last fetch: %s (%s ago)\n", fi.LastFetch.Format("2006-01-02 15:04:05"), age)
					} else {
						fmt.Fprintf(&buf, "  Last fetch: never\n")
					}
				}
				buf.WriteString("\n")
			}
		}

	case "address-book":
		if cfg == nil || cfg.Security.AddressBook == nil {
			buf.WriteString("No address book configured\n")
		} else {
			ab := cfg.Security.AddressBook
			if len(ab.Addresses) > 0 {
				buf.WriteString("Addresses:\n")
				for name, addr := range ab.Addresses {
					fmt.Fprintf(&buf, "  %-20s %s\n", name, addr.Value)
				}
			}
			if len(ab.AddressSets) > 0 {
				buf.WriteString("Address sets:\n")
				for name, as := range ab.AddressSets {
					fmt.Fprintf(&buf, "  %-20s members: %s\n", name, strings.Join(as.Addresses, ", "))
				}
			}
		}

	case "applications":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		s.showApplications(cfg, &buf)

	case "flow-monitoring":
		// #1043 Phase 5: case body extracted to server_show_flow.go
		s.showFlowMonitoring(cfg, &buf)

	case "flow-timeouts":
		// #1043 Phase 5: case body extracted to server_show_flow.go
		s.showFlowTimeouts(cfg, &buf)

	case "flow-statistics":
		// #1043 Phase 5: case body extracted to server_show_flow.go
		s.showFlowStatistics(&buf)

	case "sessions-top:bytes", "sessions-top:packets":
		// #1043 Phase 5: case body extracted to server_show_flow.go
		s.showSessionsTop(cfg, req.Topic, &buf)

	case "flow-traceoptions":
		// #1043 Phase 5: case body extracted to server_show_flow.go
		s.showFlowTraceoptions(cfg, &buf)

	case "nat-static":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		s.showNATStatic(cfg, &buf)

	case "nat-nptv6":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		s.showNATNPTv6(cfg, &buf)

	case "persistent-nat":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		s.showPersistentNAT(&buf)

	case "nat-source-rule-detail":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		s.showNATSourceRuleDetail(cfg, &buf)

	case "nat-dest-rule-detail":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		s.showNATDestRuleDetail(cfg, &buf)

	case "persistent-nat-detail":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		s.showPersistentNATDetail(&buf)

	case "tunnels":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		s.showTunnels(&buf)

	case "rpm":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		s.showRPM(&buf)

	case "application-identification-status":
		// #653: surface what xpf AppID actually does today vs the
		// vSRX `services application-identification` feature.
		// Topic name carries `-status` so the showText topic stays
		// consistent with the cmdtree leaf
		// `application-identification status` (per Copilot review).
		s.showApplicationIdentificationStatus(cfg, &buf)

	case "version":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showVersion(&buf)

	case "security-log":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		s.showSecurityLog(req.Filter, &buf)

	case "chassis":
		// #1043 Phase 2: case body extracted to server_show_chassis.go
		s.showChassis(&buf)

	case "storage":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showStorage(&buf)

	case "commit-history":
		// #1043 Phase 7: case body extracted to server_show_system.go
		if err := s.showCommitHistory(&buf); err != nil {
			return nil, err
		}

	case "alarms":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showAlarms(&buf)

	case "security-alarms", "security-alarms-detail":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		s.showSecurityAlarms(cfg, req.Topic, &buf)

	case "route-all":
		// #1043 Phase 9: case body extracted to server_show_routes_text.go
		if err := s.showRouteAll(cfg, &buf); err != nil {
			return nil, err
		}

	case "route-summary":
		// #1043 Phase 9: case body extracted to server_show_routes_text.go
		if err := s.showRouteSummary(cfg, &buf); err != nil {
			return nil, err
		}

	case "route-terse":
		// #1043 Phase 9: case body extracted to server_show_routes_text.go
		if err := s.showRouteTerse(&buf); err != nil {
			return nil, err
		}

	case "route-detail":
		// #1043 Phase 9: case body extracted to server_show_routes_text.go
		if err := s.showRouteDetail(&buf); err != nil {
			return nil, err
		}

	case "interfaces-extensive":
		// #1043 Phase 6: case body extracted to server_show_interfaces_text.go
		if err := s.showInterfacesExtensive(cfg, &buf); err != nil {
			return nil, err
		}

	case "interfaces-detail":
		// #1043 Phase 6: case body extracted to server_show_interfaces_text.go
		if err := s.showInterfacesDetail(cfg, req.Filter, &buf); err != nil {
			return nil, err
		}

	case "interfaces-statistics":
		// #1043 Phase 6: case body extracted to server_show_interfaces_text.go
		if err := s.showInterfacesStatistics(&buf); err != nil {
			return nil, err
		}

	case "policies-hit-count":
		// #1043 Phase 10: case body extracted to server_show_policies_text.go
		s.showPoliciesHitCount(req.Filter, &buf)

	case "policies-detail":
		// #1043 Phase 10: case body extracted to server_show_policies_text.go
		s.showPoliciesDetail(req.Filter, &buf)

	case "chassis-hardware":
		// Alias: same output as "chassis" (CPU, memory, NICs).
		// Forward the caller's context so metadata like #879's
		// xpf-no-peer guard propagates correctly through the alias.
		return s.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis"})

	case "chassis-forwarding":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisForwarding(ctx, &buf)

	case "chassis-cluster", "chassis-cluster-status":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterStatus(&buf)

	case "chassis-cluster-interfaces":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterInterfaces(&buf)

	case "chassis-cluster-information":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterInformation(&buf)

	case "chassis-cluster-statistics":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterStatistics(&buf)

	case "chassis-cluster-control-plane-statistics":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterControlPlaneStatistics(&buf)

	case "chassis-cluster-data-plane-statistics":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterDataPlaneStatistics(&buf)

	case "chassis-cluster-data-plane-interfaces":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterDataPlaneInterfaces(&buf)

	case "chassis-cluster-ip-monitoring-status":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterIPMonitoringStatus(&buf)

	case "chassis-cluster-fabric-statistics":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterFabricStatistics(&buf)

	case "chassis-environment":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showChassisEnvironment(&buf)

	case "system-services":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showSystemServices(&buf)

	case "ntp":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showNTP(&buf)

	case "system-syslog":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showSystemSyslog(&buf)

	case "policy-options":
		// #1043 Phase 10: case body extracted to server_show_policies_text.go
		s.showPolicyOptions(cfg, &buf)

	case "backup-router":
		if cfg == nil || cfg.System.BackupRouter == "" {
			buf.WriteString("No backup router configured\n")
		} else {
			fmt.Fprintf(&buf, "Backup router: %s\n", cfg.System.BackupRouter)
			if cfg.System.BackupRouterDst != "" {
				fmt.Fprintf(&buf, "  Destination: %s\n", cfg.System.BackupRouterDst)
			} else {
				buf.WriteString("  Destination: 0.0.0.0/0 (default)\n")
			}
		}

	case "nat64":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		s.showNAT64(cfg, &buf)

	case "ike":
		if cfg == nil || len(cfg.Security.IPsec.Gateways) == 0 {
			buf.WriteString("No IKE gateways configured\n")
		} else {
			names := make([]string, 0, len(cfg.Security.IPsec.Gateways))
			for name := range cfg.Security.IPsec.Gateways {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				gw := cfg.Security.IPsec.Gateways[name]
				fmt.Fprintf(&buf, "IKE gateway: %s\n", name)
				if gw.Address != "" {
					fmt.Fprintf(&buf, "  Remote address:     %s\n", gw.Address)
				}
				if gw.DynamicHostname != "" {
					fmt.Fprintf(&buf, "  Dynamic hostname:   %s\n", gw.DynamicHostname)
				}
				if gw.LocalAddress != "" {
					fmt.Fprintf(&buf, "  Local address:      %s\n", gw.LocalAddress)
				}
				if gw.ExternalIface != "" {
					fmt.Fprintf(&buf, "  External interface: %s\n", gw.ExternalIface)
				}
				if gw.LocalCertificate != "" {
					fmt.Fprintf(&buf, "  Local certificate:  %s\n", gw.LocalCertificate)
				}
				if gw.IKEPolicy != "" {
					fmt.Fprintf(&buf, "  IKE policy:         %s\n", gw.IKEPolicy)
					if pol, ok := cfg.Security.IPsec.IKEPolicies[gw.IKEPolicy]; ok {
						fmt.Fprintf(&buf, "    Mode:     %s\n", pol.Mode)
						fmt.Fprintf(&buf, "    Proposal: %s\n", pol.Proposals)
					}
				}
				ver := gw.Version
				if ver == "" {
					ver = "v1+v2"
				}
				fmt.Fprintf(&buf, "  IKE version:        %s\n", ver)
				if gw.DeadPeerDetect != "" {
					fmt.Fprintf(&buf, "  DPD:                %s\n", gw.DeadPeerDetect)
					if gw.DPDInterval > 0 {
						fmt.Fprintf(&buf, "  DPD interval:       %ds\n", gw.DPDInterval)
					}
					if gw.DPDThreshold > 0 {
						fmt.Fprintf(&buf, "  DPD threshold:      %d\n", gw.DPDThreshold)
					}
				}
				if gw.NoNATTraversal {
					buf.WriteString("  NAT-T:              disabled\n")
				} else if gw.NATTraversal == "force" {
					buf.WriteString("  NAT-T:              force\n")
				} else if gw.NATTraversal == "enable" {
					buf.WriteString("  NAT-T:              enabled\n")
				}
				if gw.LocalIDValue != "" {
					fmt.Fprintf(&buf, "  Local identity:     %s %s\n", gw.LocalIDType, gw.LocalIDValue)
				}
				if gw.RemoteIDValue != "" {
					fmt.Fprintf(&buf, "  Remote identity:    %s %s\n", gw.RemoteIDType, gw.RemoteIDValue)
				}
				buf.WriteString("\n")
			}
			// IKE proposals
			if len(cfg.Security.IPsec.IKEProposals) > 0 {
				pNames := make([]string, 0, len(cfg.Security.IPsec.IKEProposals))
				for name := range cfg.Security.IPsec.IKEProposals {
					pNames = append(pNames, name)
				}
				sort.Strings(pNames)
				buf.WriteString("IKE proposals:\n")
				for _, name := range pNames {
					p := cfg.Security.IPsec.IKEProposals[name]
					fmt.Fprintf(&buf, "  %s: auth=%s enc=%s dh=group%d", name, p.AuthMethod, p.EncryptionAlg, p.DHGroup)
					if p.LifetimeSeconds > 0 {
						fmt.Fprintf(&buf, " lifetime=%ds", p.LifetimeSeconds)
					}
					buf.WriteString("\n")
				}
			}
		}

	case "event-options":
		if cfg == nil || len(cfg.EventOptions) == 0 {
			buf.WriteString("No event-options configured\n")
		} else {
			for _, ep := range cfg.EventOptions {
				fmt.Fprintf(&buf, "Policy: %s\n", ep.Name)
				if len(ep.Events) > 0 {
					fmt.Fprintf(&buf, "  Events: %s\n", strings.Join(ep.Events, ", "))
				}
				for _, w := range ep.WithinClauses {
					fmt.Fprintf(&buf, "  Within: %d seconds", w.Seconds)
					if w.TriggerOn > 0 {
						fmt.Fprintf(&buf, ", trigger on %d", w.TriggerOn)
					}
					if w.TriggerUntil > 0 {
						fmt.Fprintf(&buf, ", trigger until %d", w.TriggerUntil)
					}
					buf.WriteString("\n")
				}
				if len(ep.AttributesMatch) > 0 {
					buf.WriteString("  Attributes match:\n")
					for _, am := range ep.AttributesMatch {
						fmt.Fprintf(&buf, "    %s\n", am)
					}
				}
				if len(ep.ThenCommands) > 0 {
					buf.WriteString("  Then commands:\n")
					for _, cmd := range ep.ThenCommands {
						fmt.Fprintf(&buf, "    %s\n", cmd)
					}
				}
				buf.WriteString("\n")
			}
		}

	case "routing-options":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			ro := &cfg.RoutingOptions
			hasContent := false
			if ro.AutonomousSystem > 0 {
				fmt.Fprintf(&buf, "Autonomous system: %d\n\n", ro.AutonomousSystem)
				hasContent = true
			}
			if ro.ForwardingTableExport != "" {
				fmt.Fprintf(&buf, "Forwarding-table export: %s\n\n", ro.ForwardingTableExport)
				hasContent = true
			}
			if len(ro.StaticRoutes) > 0 {
				buf.WriteString("Static routes (inet.0):\n")
				fmt.Fprintf(&buf, "  %-24s %-20s %s\n", "Destination", "Next-Hop", "Pref")
				for _, sr := range ro.StaticRoutes {
					if sr.Discard {
						fmt.Fprintf(&buf, "  %-24s %-20s %s\n", sr.Destination, "discard", fmtPref(sr.Preference))
						continue
					}
					if sr.NextTable != "" {
						fmt.Fprintf(&buf, "  %-24s %-20s %s\n", sr.Destination, "next-table "+sr.NextTable, fmtPref(sr.Preference))
						continue
					}
					for i, nh := range sr.NextHops {
						dest := sr.Destination
						if i > 0 {
							dest = ""
						}
						nhStr := nh.Address
						if nh.Interface != "" {
							nhStr += " via " + nh.Interface
						}
						fmt.Fprintf(&buf, "  %-24s %-20s %s\n", dest, nhStr, fmtPref(sr.Preference))
					}
				}
				buf.WriteString("\n")
				hasContent = true
			}
			if len(ro.Inet6StaticRoutes) > 0 {
				buf.WriteString("Static routes (inet6.0):\n")
				fmt.Fprintf(&buf, "  %-40s %-30s %s\n", "Destination", "Next-Hop", "Pref")
				for _, sr := range ro.Inet6StaticRoutes {
					if sr.Discard {
						fmt.Fprintf(&buf, "  %-40s %-30s %s\n", sr.Destination, "discard", fmtPref(sr.Preference))
						continue
					}
					if sr.NextTable != "" {
						fmt.Fprintf(&buf, "  %-40s %-30s %s\n", sr.Destination, "next-table "+sr.NextTable, fmtPref(sr.Preference))
						continue
					}
					for i, nh := range sr.NextHops {
						dest := sr.Destination
						if i > 0 {
							dest = ""
						}
						nhStr := nh.Address
						if nh.Interface != "" {
							nhStr += " via " + nh.Interface
						}
						fmt.Fprintf(&buf, "  %-40s %-30s %s\n", dest, nhStr, fmtPref(sr.Preference))
					}
				}
				buf.WriteString("\n")
				hasContent = true
			}
			if len(ro.RibGroups) > 0 {
				buf.WriteString("RIB groups:\n")
				for name, rg := range ro.RibGroups {
					fmt.Fprintf(&buf, "  %-20s import-rib: %s\n", name, strings.Join(rg.ImportRibs, ", "))
				}
				buf.WriteString("\n")
				hasContent = true
			}
			if !hasContent {
				buf.WriteString("No routing-options configured\n")
			}
		}

	case "forwarding-options":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			fo := &cfg.ForwardingOptions
			hasContent := false
			if fo.FamilyInet6Mode != "" {
				fmt.Fprintf(&buf, "Family inet6 mode: %s\n", fo.FamilyInet6Mode)
				hasContent = true
			}
			if fo.Sampling != nil && len(fo.Sampling.Instances) > 0 {
				buf.WriteString("Sampling:\n")
				for name, inst := range fo.Sampling.Instances {
					fmt.Fprintf(&buf, "  Instance: %s\n", name)
					if inst.InputRate > 0 {
						fmt.Fprintf(&buf, "    Input rate: 1/%d\n", inst.InputRate)
					}
					for _, fam := range []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6} {
						if fam == nil {
							continue
						}
						for _, fs := range fam.FlowServers {
							fmt.Fprintf(&buf, "    Flow server: %s:%d\n", fs.Address, fs.Port)
							if fs.Version9Template != "" {
								fmt.Fprintf(&buf, "      Version 9 template: %s\n", fs.Version9Template)
							}
						}
						if fam.SourceAddress != "" {
							fmt.Fprintf(&buf, "    Source address: %s\n", fam.SourceAddress)
						}
						if fam.InlineJflow {
							buf.WriteString("    Inline jflow: enabled\n")
						}
						if fam.InlineJflowSourceAddress != "" {
							fmt.Fprintf(&buf, "    Inline jflow source: %s\n", fam.InlineJflowSourceAddress)
						}
					}
				}
				hasContent = true
			}
			if fo.DHCPRelay != nil {
				buf.WriteString("DHCP relay: (see 'show dhcp-relay' for details)\n")
				hasContent = true
			}
			if fo.PortMirroring != nil && len(fo.PortMirroring.Instances) > 0 {
				buf.WriteString("Port mirroring: (see 'show forwarding-options port-mirroring' for details)\n")
				hasContent = true
			}
			if !hasContent {
				buf.WriteString("No forwarding-options configured\n")
			}
		}

	case "forwarding-options-port-mirroring":
		if cfg == nil {
			buf.WriteString("No active configuration\n")
		} else {
			pm := cfg.ForwardingOptions.PortMirroring
			if pm == nil || len(pm.Instances) == 0 {
				buf.WriteString("No port-mirroring instances configured\n")
			} else {
				for name, inst := range pm.Instances {
					fmt.Fprintf(&buf, "Instance: %s\n", name)
					if inst.InputRate > 0 {
						fmt.Fprintf(&buf, "  Input rate: 1/%d\n", inst.InputRate)
					} else {
						buf.WriteString("  Input rate: all packets\n")
					}
					if len(inst.Input) > 0 {
						fmt.Fprintf(&buf, "  Input interfaces: %s\n", strings.Join(inst.Input, ", "))
					}
					if inst.Output != "" {
						fmt.Fprintf(&buf, "  Output interface: %s\n", inst.Output)
					}
					buf.WriteString("\n")
				}
			}
		}

	case "vlans":
		if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
			buf.WriteString("No VLANs configured\n")
		} else {
			ifZone := make(map[string]string)
			for zoneName, zone := range cfg.Security.Zones {
				for _, iface := range zone.Interfaces {
					ifZone[iface] = zoneName
				}
			}
			type vlanEntry struct {
				iface  string
				unit   int
				vlanID int
				zone   string
				trunk  bool
			}
			var entries []vlanEntry
			for _, ifc := range cfg.Interfaces.Interfaces {
				for unitNum, unit := range ifc.Units {
					if unit.VlanID > 0 || ifc.VlanTagging {
						entries = append(entries, vlanEntry{
							iface:  ifc.Name,
							unit:   unitNum,
							vlanID: unit.VlanID,
							zone:   ifZone[ifc.Name],
							trunk:  ifc.VlanTagging,
						})
					}
				}
			}
			if len(entries) == 0 {
				buf.WriteString("No VLANs configured\n")
			} else {
				sort.Slice(entries, func(i, j int) bool {
					if entries[i].iface != entries[j].iface {
						return entries[i].iface < entries[j].iface
					}
					return entries[i].unit < entries[j].unit
				})
				fmt.Fprintf(&buf, "%-16s %-6s %-8s %-12s %s\n", "Interface", "Unit", "VLAN ID", "Zone", "Mode")
				for _, e := range entries {
					mode := "access"
					if e.trunk {
						mode = "trunk"
					}
					vid := fmt.Sprintf("%d", e.vlanID)
					if e.vlanID == 0 {
						vid = "native"
					}
					fmt.Fprintf(&buf, "%-16s %-6d %-8s %-12s %s\n", e.iface, e.unit, vid, e.zone, mode)
				}
			}
		}

	case "routing-instances":
		if cfg == nil || len(cfg.RoutingInstances) == 0 {
			buf.WriteString("No routing instances configured\n")
		} else {
			fmt.Fprintf(&buf, "%-20s %-16s %-6s %s\n", "Instance", "Type", "Table", "Interfaces")
			for _, ri := range cfg.RoutingInstances {
				tableID := "-"
				if ri.TableID > 0 {
					tableID = fmt.Sprintf("%d", ri.TableID)
				}
				ifaces := "-"
				if len(ri.Interfaces) > 0 {
					ifaces = strings.Join(ri.Interfaces, ", ")
				}
				fmt.Fprintf(&buf, "%-20s %-16s %-6s %s\n", ri.Name, ri.InstanceType, tableID, ifaces)
				if ri.Description != "" {
					fmt.Fprintf(&buf, "  Description: %s\n", ri.Description)
				}
			}
		}

	case "routing-instances-detail":
		if cfg == nil || len(cfg.RoutingInstances) == 0 {
			buf.WriteString("No routing instances configured\n")
		} else {
			for _, ri := range cfg.RoutingInstances {
				fmt.Fprintf(&buf, "Instance: %s\n", ri.Name)
				if ri.Description != "" {
					fmt.Fprintf(&buf, "  Description: %s\n", ri.Description)
				}
				fmt.Fprintf(&buf, "  Type: %s\n", ri.InstanceType)
				if ri.TableID > 0 {
					fmt.Fprintf(&buf, "  Table ID: %d\n", ri.TableID)
				}
				if len(ri.Interfaces) > 0 {
					fmt.Fprintf(&buf, "  Interfaces: %s\n", strings.Join(ri.Interfaces, ", "))
				}
				if ri.TableID > 0 && s.routing != nil {
					if routes, err := s.routing.GetRoutesForTable(ri.TableID); err == nil {
						fmt.Fprintf(&buf, "  Route count: %d\n", len(routes))
					}
				}
				var protos []string
				if ri.OSPF != nil {
					protos = append(protos, "OSPF")
				}
				if ri.BGP != nil {
					protos = append(protos, "BGP")
				}
				if ri.RIP != nil {
					protos = append(protos, "RIP")
				}
				if ri.ISIS != nil {
					protos = append(protos, "IS-IS")
				}
				if len(protos) > 0 {
					fmt.Fprintf(&buf, "  Protocols: %s\n", strings.Join(protos, ", "))
				}
				if len(ri.StaticRoutes) > 0 {
					fmt.Fprintf(&buf, "  Static routes: %d\n", len(ri.StaticRoutes))
					for _, sr := range ri.StaticRoutes {
						if sr.Discard {
							fmt.Fprintf(&buf, "    %s -> discard\n", sr.Destination)
							continue
						}
						for _, nh := range sr.NextHops {
							nhStr := nh.Address
							if nh.Interface != "" {
								nhStr += " via " + nh.Interface
							}
							fmt.Fprintf(&buf, "    %s -> %s\n", sr.Destination, nhStr)
						}
					}
				}
				if ri.InterfaceRoutesRibGroup != "" {
					fmt.Fprintf(&buf, "  Interface routes rib-group: %s\n", ri.InterfaceRoutesRibGroup)
				}
				buf.WriteString("\n")
			}
		}

	case "route-instance":
		instanceName := req.Filter
		if instanceName == "" {
			buf.WriteString("Usage: show route instance <name>\n")
			break
		}
		if cfg == nil {
			buf.WriteString("No active configuration\n")
			break
		}
		var tableID int
		found := false
		for _, ri := range cfg.RoutingInstances {
			if ri.Name == instanceName {
				tableID = ri.TableID
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(&buf, "Routing instance %q not found\n", instanceName)
			break
		}
		if s.routing != nil {
			entries, err := s.routing.GetRoutesForTable(tableID)
			if err != nil {
				fmt.Fprintf(&buf, "Error: %v\n", err)
				break
			}
			fmt.Fprintf(&buf, "Routing table for instance %s (table %d):\n", instanceName, tableID)
			fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %s\n",
				"Destination", "Next-hop", "Interface", "Proto", "Pref")
			for _, e := range entries {
				fmt.Fprintf(&buf, "  %-24s %-20s %-14s %-12s %d\n",
					e.Destination, e.NextHop, e.Interface, e.Protocol, e.Preference)
			}
		} else {
			buf.WriteString("Routing manager not available\n")
		}

	case "login":
		if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
			buf.WriteString("No login users configured\n")
		} else {
			fmt.Fprintf(&buf, "%-16s %-6s %-14s %s\n", "User", "UID", "Class", "SSH Keys")
			for _, u := range cfg.System.Login.Users {
				uid := "-"
				if u.UID > 0 {
					uid = strconv.Itoa(u.UID)
				}
				class := u.Class
				if class == "" {
					class = "-"
				}
				keys := strconv.Itoa(len(u.SSHKeys))
				fmt.Fprintf(&buf, "%-16s %-6s %-14s %s\n", u.Name, uid, class, keys)
			}
		}

	case "screen":
		if cfg == nil || len(cfg.Security.Screen) == 0 {
			buf.WriteString("No screen profiles configured\n")
		} else {
			// Build reverse map: profile name -> zones
			zonesByProfile := make(map[string][]string)
			for name, zone := range cfg.Security.Zones {
				if zone.ScreenProfile != "" {
					zonesByProfile[zone.ScreenProfile] = append(zonesByProfile[zone.ScreenProfile], name)
				}
			}
			var names []string
			for name := range cfg.Security.Screen {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				profile := cfg.Security.Screen[name]
				fmt.Fprintf(&buf, "Screen profile: %s\n", name)
				if profile.TCP.Land {
					buf.WriteString("  TCP LAND attack detection: enabled\n")
				}
				if profile.TCP.SynFin {
					buf.WriteString("  TCP SYN+FIN detection: enabled\n")
				}
				if profile.TCP.NoFlag {
					buf.WriteString("  TCP no-flag detection: enabled\n")
				}
				if profile.TCP.FinNoAck {
					buf.WriteString("  TCP FIN-no-ACK detection: enabled\n")
				}
				if profile.TCP.WinNuke {
					buf.WriteString("  TCP WinNuke detection: enabled\n")
				}
				if profile.TCP.SynFrag {
					buf.WriteString("  TCP SYN fragment detection: enabled\n")
				}
				if profile.TCP.SynFlood != nil {
					fmt.Fprintf(&buf, "  TCP SYN flood protection: attack-threshold %d\n",
						profile.TCP.SynFlood.AttackThreshold)
				}
				if profile.ICMP.PingDeath {
					buf.WriteString("  ICMP ping-of-death detection: enabled\n")
				}
				if profile.ICMP.FloodThreshold > 0 {
					fmt.Fprintf(&buf, "  ICMP flood protection: threshold %d\n",
						profile.ICMP.FloodThreshold)
				}
				if profile.IP.SourceRouteOption {
					buf.WriteString("  IP source-route option detection: enabled\n")
				}
				if profile.UDP.FloodThreshold > 0 {
					fmt.Fprintf(&buf, "  UDP flood protection: threshold %d\n",
						profile.UDP.FloodThreshold)
				}
				if zones, ok := zonesByProfile[name]; ok {
					sort.Strings(zones)
					fmt.Fprintf(&buf, "  Applied to zones: %s\n", strings.Join(zones, ", "))
				}
				buf.WriteString("\n")
			}
			// Per-type drop counters
			if s.dp != nil && s.dp.IsLoaded() {
				readCtr := func(idx uint32) uint64 {
					v, _ := s.dp.ReadGlobalCounter(idx)
					return v
				}
				totalDrops := readCtr(dataplane.GlobalCtrScreenDrops)
				fmt.Fprintf(&buf, "Total screen drops: %d\n", totalDrops)
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
							fmt.Fprintf(&buf, "  %-25s %d\n", sc.name+":", v)
						}
					}
				}
			}
		}

	case "log":
		out, err := exec.Command("journalctl", "-u", "xpfd", "-n", "50", "--no-pager").CombinedOutput()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "journalctl: %v", err)
		}
		buf.Write(out)

	case "internet-options":
		if cfg == nil || cfg.System.InternetOptions == nil {
			buf.WriteString("No internet-options configured\n")
		} else {
			io := cfg.System.InternetOptions
			buf.WriteString("Internet options:\n")
			fmt.Fprintf(&buf, "  no-ipv6-reject-zero-hop-limit: %s\n", boolStatus(io.NoIPv6RejectZeroHopLimit))
		}

	case "root-authentication":
		if cfg == nil || cfg.System.RootAuthentication == nil {
			buf.WriteString("No root authentication configured\n")
		} else {
			ra := cfg.System.RootAuthentication
			if ra.EncryptedPassword != "" {
				buf.WriteString("Root password: configured (encrypted)\n")
			}
			if len(ra.SSHKeys) > 0 {
				fmt.Fprintf(&buf, "Root SSH keys: %d\n", len(ra.SSHKeys))
				for _, key := range ra.SSHKeys {
					// Show key type and fingerprint prefix
					parts := strings.Fields(key)
					if len(parts) >= 2 {
						comment := ""
						if len(parts) >= 3 {
							comment = " " + parts[2]
						}
						fmt.Fprintf(&buf, "  %s%s\n", parts[0], comment)
					}
				}
			}
		}

	case "buffers":
		if s.dp != nil {
			stats := s.dp.GetMapStats()
			if len(stats) == 0 {
				buf.WriteString("No BPF maps available\n")
			} else {
				fmt.Fprintf(&buf, "%-24s %-14s %10s %10s %8s %s\n", "Map", "Type", "Max", "Used", "Usage%", "Status")
				buf.WriteString(strings.Repeat("-", 78) + "\n")
				var warnings int
				for _, st := range stats {
					usage := "-"
					used := "-"
					sts := ""
					if st.Type != "Array" && st.Type != "PerCPUArray" {
						used = fmt.Sprintf("%d", st.UsedCount)
						if st.MaxEntries > 0 {
							pct := float64(st.UsedCount) / float64(st.MaxEntries) * 100
							usage = fmt.Sprintf("%.1f%%", pct)
							if pct >= 90 {
								sts = "CRITICAL"
								warnings++
							} else if pct >= 80 {
								sts = "WARNING"
								warnings++
							}
						}
					}
					fmt.Fprintf(&buf, "%-24s %-14s %10d %10s %8s %s\n", st.Name, st.Type, st.MaxEntries, used, usage, sts)
				}
				if warnings > 0 {
					fmt.Fprintf(&buf, "\n%d map(s) at high utilization — consider increasing max_entries\n", warnings)
				}
			}
			v4, v6 := s.dp.SessionCount()
			if v4 > 0 || v6 > 0 {
				fmt.Fprintf(&buf, "\nActive sessions: %d IPv4, %d IPv6, %d total\n", v4, v6, v4+v6)
			}
		} else {
			buf.WriteString("Dataplane not loaded\n")
		}

	case "buffers-detail":
		if s.dp != nil {
			stats := s.dp.GetMapStats()
			if len(stats) == 0 {
				buf.WriteString("No BPF maps available\n")
			} else {
				type mapDetail struct {
					name      string
					mapType   string
					max       uint32
					used      uint32
					keySize   uint32
					valueSize uint32
					pct       float64
				}
				var details []mapDetail
				for _, st := range stats {
					if st.Type == "Array" || st.Type == "PerCPUArray" {
						continue
					}
					pct := float64(0)
					if st.MaxEntries > 0 {
						pct = float64(st.UsedCount) / float64(st.MaxEntries) * 100
					}
					details = append(details, mapDetail{
						name: st.Name, mapType: st.Type, max: st.MaxEntries,
						used: st.UsedCount, keySize: st.KeySize, valueSize: st.ValueSize, pct: pct,
					})
				}
				sort.Slice(details, func(i, j int) bool {
					return details[i].pct > details[j].pct
				})
				buf.WriteString("BPF Map Details (sorted by utilization):\n\n")
				for _, d := range details {
					sts := "OK"
					if d.pct >= 90 {
						sts = "CRITICAL"
					} else if d.pct >= 80 {
						sts = "WARNING"
					}
					fmt.Fprintf(&buf, "Map: %s\n", d.name)
					fmt.Fprintf(&buf, "  Type: %s, Max: %d, Used: %d, Usage: %.1f%%\n", d.mapType, d.max, d.used, d.pct)
					fmt.Fprintf(&buf, "  Key size: %d bytes, Value size: %d bytes\n", d.keySize, d.valueSize)
					fmt.Fprintf(&buf, "  Status: %s\n\n", sts)
				}
			}
			v4, v6 := s.dp.SessionCount()
			if v4 > 0 || v6 > 0 {
				fmt.Fprintf(&buf, "Active sessions: %d IPv4, %d IPv6, %d total\n", v4, v6, v4+v6)
			}
		} else {
			buf.WriteString("Dataplane not loaded\n")
		}

	case "bfd-peers":
		if s.frr == nil {
			buf.WriteString("FRR not available\n")
		} else {
			output, err := s.frr.GetBFDPeers()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "BFD peers: %v", err)
			}
			if output == "" {
				buf.WriteString("No BFD peers\n")
			} else {
				buf.WriteString(output)
			}
		}

	case "route-map":
		if s.frr == nil {
			buf.WriteString("FRR not available\n")
		} else {
			output, err := s.frr.GetRouteMapList()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "route-map: %v", err)
			}
			if output == "" {
				buf.WriteString("No route-maps configured\n")
			} else {
				buf.WriteString(output)
			}
		}

	case "core-dumps":
		dirs := []string{"/var/crash", "/var/lib/systemd/coredump"}
		var found bool
		for _, dir := range dirs {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				info, err := e.Info()
				if err != nil {
					continue
				}
				if !found {
					fmt.Fprintf(&buf, "%-40s %-20s %10s\n", "Name", "Date", "Size")
					found = true
				}
				fmt.Fprintf(&buf, "%-40s %-20s %10d\n", e.Name(), info.ModTime().Format("2006-01-02 15:04:05"), info.Size())
			}
		}
		if !found {
			buf.WriteString("No core dumps found\n")
		}

	case "task":
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		uptime := time.Since(s.startTime).Truncate(time.Second)
		buf.WriteString("Task: xpfd daemon\n")
		fmt.Fprintf(&buf, "  Goroutines: %d\n", runtime.NumGoroutine())
		fmt.Fprintf(&buf, "  Memory allocated: %.1f MB\n", float64(m.Alloc)/1024/1024)
		fmt.Fprintf(&buf, "  System memory: %.1f MB\n", float64(m.Sys)/1024/1024)
		fmt.Fprintf(&buf, "  GC cycles: %d\n", m.NumGC)
		fmt.Fprintf(&buf, "  Uptime: %s\n", uptime)

	case "ipv6-router-advertisement":
		if s.raMgr == nil {
			fmt.Fprintln(&buf, "Router Advertisements: not available")
		} else {
			senders := s.raMgr.Status()
			if len(senders) == 0 {
				fmt.Fprintln(&buf, "Router Advertisements: no active senders")
			} else {
				fmt.Fprintf(&buf, "Router Advertisement: %d active sender(s)\n\n", len(senders))
				for _, info := range senders {
					fmt.Fprintf(&buf, "Interface: %s\n", info.Interface)
					fmt.Fprintf(&buf, "  Source address:     %s\n", info.SrcAddr)
					fmt.Fprintf(&buf, "  Router lifetime:    %ds\n", info.Lifetime)
					fmt.Fprintf(&buf, "  Preference:         %s\n", info.Preference)
					fmt.Fprintf(&buf, "  Max RA interval:    %ds\n", info.MaxInterval)
					fmt.Fprintf(&buf, "  Min RA interval:    %ds\n", info.MinInterval)
					if info.Managed {
						fmt.Fprintln(&buf, "  Managed flag:       on")
					}
					if info.Other {
						fmt.Fprintln(&buf, "  Other config flag:  on")
					}
					if info.LinkMTU > 0 {
						fmt.Fprintf(&buf, "  Link MTU:           %d\n", info.LinkMTU)
					}
					for _, pfx := range info.Prefixes {
						fmt.Fprintf(&buf, "  Prefix:             %s\n", pfx)
					}
					if len(info.DNSServers) > 0 {
						fmt.Fprintf(&buf, "  DNS servers:        %s\n", strings.Join(info.DNSServers, ", "))
					}
					if info.NAT64Prefix != "" {
						fmt.Fprintf(&buf, "  PREF64:             %s\n", info.NAT64Prefix)
					}
					fmt.Fprintf(&buf, "  Last RA sent:       %s\n", info.LastRA)
					fmt.Fprintln(&buf)
				}
			}
		}

	default:
		// Handle "log:<filename>[:<count>]" for syslog file destinations
		if req.Topic == "monitor-security-flow" {
			buf.WriteString("  Monitor security flow session status: Inactive\n")
			buf.WriteString("  Monitor security flow trace file: (not configured)\n")
			buf.WriteString("  Monitor security flow filters: 0\n")
			buf.WriteString("\n  Note: Flow monitor state is per-CLI-session.\n")
			buf.WriteString("  Use the local CLI on the firewall for flow tracing.\n")
		} else if strings.HasPrefix(req.Topic, "log:") {
			parts := strings.SplitN(req.Topic, ":", 3)
			filename := filepath.Base(parts[1]) // sanitize path
			n := "50"
			if len(parts) >= 3 {
				if _, err := strconv.Atoi(parts[2]); err == nil {
					n = parts[2]
				}
			}
			logPath := filepath.Join("/var/log", filename)
			out, err := exec.Command("tail", "-n", n, logPath).CombinedOutput()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "read %s: %v", logPath, err)
			}
			buf.Write(out)
		} else {
			return nil, status.Errorf(codes.InvalidArgument, "unknown topic: %s", req.Topic)
		}
	}

	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

// chassisForwardingSeparator is the dashed separator that frames each
// per-node block in cluster-mode `show chassis forwarding` output,
// matching the shape used by `show chassis cluster`.
const chassisForwardingSeparator = "--------------------------------------------------------------------------"

// buildLocalForwarding renders a single-node FWDD-status block for
// the local node. Used both for standalone-mode output and as the
// local half of cluster-mode composition.
// dialAndShowForwarding queries the cluster peer for its single-node
// FWDD-status block. Injects the `xpf-no-peer:1` outgoing metadata
// so the peer renders local-only and never recurses back. Returns
// the peer's formatted block or an error if the peer is unreachable.
//
// Timeout note: dialPeer() internally uses context.Background() for
// its 2s × N-fabric probes (server_diag.go) — that 4s worst-case
// dial budget is NOT bound by `ctx`. The 5s WithTimeout below only
// covers the post-dial ShowText RPC. Total worst case is therefore
// up to ~9s. On the peer side, buildLocalForwarding may block on
// userspace.Manager.mu during a failover — under that case the
// 5s outer can fire spuriously and the peer block renders
// "(peer unreachable)" even on a healthy-but-loaded peer. Future
// fix: thread ctx into dialPeer to bound the full path.
