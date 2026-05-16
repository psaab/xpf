package config

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
)

func compileProtocols(node *Node, proto *ProtocolsConfig) error {
	raNode := node.FindChild("router-advertisement")
	if raNode != nil {
		if err := compileRouterAdvertisement(raNode, proto); err != nil {
			return fmt.Errorf("router-advertisement: %w", err)
		}
	}

	lldpNode := node.FindChild("lldp")
	if lldpNode != nil {
		proto.LLDP = &LLDPConfig{}
		for _, child := range lldpNode.Children {
			switch child.Name() {
			case "interface":
				if v := nodeVal(child); v != "" {
					iface := LLDPInterface{Name: v}
					if child.FindChild("disable") != nil {
						iface.Disable = true
					}
					proto.LLDP.Interfaces = append(proto.LLDP.Interfaces, iface)
				}
			case "transmit-interval":
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						proto.LLDP.Interval = n
					}
				}
			case "hold-multiplier":
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						proto.LLDP.HoldMultiplier = n
					}
				}
			case "disable":
				proto.LLDP.Disable = true
			}
		}
	}

	ospfNode := node.FindChild("ospf")
	if ospfNode != nil {
		proto.OSPF = &OSPFConfig{}

		// Router ID, passive-default, and export policies at the ospf level
		for _, child := range ospfNode.Children {
			switch child.Name() {
			case "router-id":
				if len(child.Keys) >= 2 {
					proto.OSPF.RouterID = child.Keys[1]
				}
			case "reference-bandwidth":
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						proto.OSPF.ReferenceBandwidth = n
					}
				}
			case "passive":
				proto.OSPF.PassiveDefault = true
			case "export":
				if len(child.Keys) >= 2 {
					proto.OSPF.Export = append(proto.OSPF.Export, child.Keys[1])
				}
			}
		}

		for _, areaInst := range namedInstances(ospfNode.FindChildren("area")) {
			area := &OSPFArea{ID: areaInst.name}

			for _, ifInst := range namedInstances(areaInst.node.FindChildren("interface")) {
				iface := &OSPFInterface{Name: ifInst.name}
				for _, prop := range ifInst.node.Children {
					switch prop.Name() {
					case "passive":
						iface.Passive = true
					case "no-passive":
						iface.NoPassive = true
					case "interface-type":
						iface.NetworkType = nodeVal(prop)
					case "cost":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.Cost = n
							}
						}
					case "authentication":
						for _, authChild := range prop.Children {
							switch authChild.Name() {
							case "md5":
								iface.AuthType = "md5"
								if v := nodeVal(authChild); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										iface.AuthKeyID = n
									}
								}
								for _, kc := range authChild.Children {
									if kc.Name() == "key" {
										iface.AuthKey = nodeVal(kc)
									}
								}
							case "simple-password":
								iface.AuthType = "simple"
								iface.AuthKey = nodeVal(authChild)
							}
						}
					case "bfd-liveness-detection":
						iface.BFD = true
						for _, bc := range prop.Children {
							switch bc.Name() {
							case "minimum-interval":
								if v := nodeVal(bc); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										iface.BFDInterval = n
									}
								}
							case "multiplier":
								if v := nodeVal(bc); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										iface.BFDMultiplier = n
									}
								}
							}
						}
					}
				}
				area.Interfaces = append(area.Interfaces, iface)
			}

			// Parse area-type (stub/nssa)
			if atNode := areaInst.node.FindChild("area-type"); atNode != nil {
				for _, atChild := range atNode.Children {
					switch atChild.Name() {
					case "stub":
						area.AreaType = "stub"
						if atChild.FindChild("no-summaries") != nil {
							area.NoSummary = true
						}
					case "nssa":
						area.AreaType = "nssa"
						if atChild.FindChild("no-summaries") != nil {
							area.NoSummary = true
						}
					}
				}
			}

			// Parse virtual-link entries
			for _, vlInst := range namedInstances(areaInst.node.FindChildren("virtual-link")) {
				vl := &OSPFVirtualLink{
					NeighborID:  vlInst.name,
					TransitArea: area.ID,
				}
				// Allow explicit transit-area override
				if taNode := vlInst.node.FindChild("transit-area"); taNode != nil {
					if v := nodeVal(taNode); v != "" {
						vl.TransitArea = v
					}
				}
				area.VirtualLinks = append(area.VirtualLinks, vl)
			}

			proto.OSPF.Areas = append(proto.OSPF.Areas, area)
		}
	}

	bgpNode := node.FindChild("bgp")
	if bgpNode != nil {
		proto.BGP = &BGPConfig{}

		for _, child := range bgpNode.Children {
			switch child.Name() {
			case "local-as":
				if len(child.Keys) >= 2 {
					if v, err := strconv.Atoi(child.Keys[1]); err == nil {
						proto.BGP.LocalAS = uint32(v)
					}
				}
			case "router-id":
				if len(child.Keys) >= 2 {
					proto.BGP.RouterID = child.Keys[1]
				}
			case "cluster-id":
				if len(child.Keys) >= 2 {
					proto.BGP.ClusterID = child.Keys[1]
				}
			case "graceful-restart":
				proto.BGP.GracefulRestart = true
			case "log-updown":
				proto.BGP.LogNeighborChanges = true
			case "multipath":
				proto.BGP.Multipath = 64 // default to 64 when enabled
				for _, mc := range child.Children {
					if mc.Name() == "multiple-as" {
						proto.BGP.MultipathMultipleAS = true
					}
				}
			case "damping":
				proto.BGP.Dampening = true
				for _, dc := range child.Children {
					if v := nodeVal(dc); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							switch dc.Name() {
							case "half-life":
								proto.BGP.DampeningHalfLife = n
							case "reuse":
								proto.BGP.DampeningReuse = n
							case "suppress":
								proto.BGP.DampeningSuppress = n
							case "max-suppress":
								proto.BGP.DampeningMaxSuppress = n
							}
						}
					}
				}
				// Handle inline keys (flat set syntax)
				for i := 1; i < len(child.Keys)-1; i += 2 {
					if n, err := strconv.Atoi(child.Keys[i+1]); err == nil {
						switch child.Keys[i] {
						case "half-life":
							proto.BGP.DampeningHalfLife = n
						case "reuse":
							proto.BGP.DampeningReuse = n
						case "suppress":
							proto.BGP.DampeningSuppress = n
						case "max-suppress":
							proto.BGP.DampeningMaxSuppress = n
						}
					}
				}
			case "export":
				if len(child.Keys) >= 2 {
					proto.BGP.Export = append(proto.BGP.Export, child.Keys[1])
				}
			}
		}

		for _, groupInst := range namedInstances(bgpNode.FindChildren("group")) {
			var peerAS uint32
			var groupDesc string
			var groupMultihop int
			var groupExport []string
			var familyInet, familyInet6 bool
			var groupPrefixLimitInet, groupPrefixLimitInet6 int
			var groupAuthKey string
			var groupBFD bool
			var groupBFDInterval int
			var groupBFDMultiplier int
			var groupDefaultOriginate bool
			var groupAllowASIn int
			var groupRemovePrivateAS bool
			for _, child := range groupInst.node.Children {
				switch child.Name() {
				case "peer-as":
					if v := nodeVal(child); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							peerAS = uint32(n)
						}
					}
				case "description":
					groupDesc = nodeVal(child)
				case "multihop":
					if v := nodeVal(child); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							groupMultihop = n
						}
					}
				case "export":
					if v := nodeVal(child); v != "" {
						groupExport = append(groupExport, v)
					} else if len(child.Keys) >= 2 {
						groupExport = append(groupExport, child.Keys[1:]...)
					}
				case "family":
					// Hierarchical: family { inet { unicast; } inet6 { unicast; } }
					// Flat (via schema): family node with children inet/inet6
					if len(child.Keys) >= 2 {
						switch child.Keys[1] {
						case "inet":
							familyInet = true
							groupPrefixLimitInet = parsePrefixLimit(child)
						case "inet6":
							familyInet6 = true
							groupPrefixLimitInet6 = parsePrefixLimit(child)
						}
					} else {
						for _, fc := range child.Children {
							switch fc.Name() {
							case "inet":
								familyInet = true
								groupPrefixLimitInet = parsePrefixLimit(fc)
							case "inet6":
								familyInet6 = true
								groupPrefixLimitInet6 = parsePrefixLimit(fc)
							}
						}
					}
				case "default-originate":
					groupDefaultOriginate = true
				case "loops":
					if v := nodeVal(child); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							groupAllowASIn = n
						}
					}
				case "remove-private":
					groupRemovePrivateAS = true
				case "authentication-key":
					groupAuthKey = nodeVal(child)
				case "bfd-liveness-detection":
					groupBFD = true
					for _, bc := range child.Children {
						switch bc.Name() {
						case "minimum-interval":
							if v := nodeVal(bc); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									groupBFDInterval = n
								}
							}
						case "multiplier":
							if v := nodeVal(bc); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									groupBFDMultiplier = n
								}
							}
						}
					}
				case "neighbor":
					nAddr := nodeVal(child)
					if nAddr != "" {
						neighbor := &BGPNeighbor{
							Address:          nAddr,
							PeerAS:           peerAS,
							Description:      groupDesc,
							MultihopTTL:      groupMultihop,
							Export:           groupExport,
							FamilyInet:       familyInet,
							FamilyInet6:      familyInet6,
							GroupName:        groupInst.name,
							AuthPassword:     groupAuthKey,
							BFD:              groupBFD,
							BFDInterval:      groupBFDInterval,
							BFDMultiplier:    groupBFDMultiplier,
							DefaultOriginate: groupDefaultOriginate,
							AllowASIn:        groupAllowASIn,
							RemovePrivateAS:  groupRemovePrivateAS,
							PrefixLimitInet:  groupPrefixLimitInet,
							PrefixLimitInet6: groupPrefixLimitInet6,
						}
						// Per-neighbor overrides
						for _, prop := range child.Children {
							switch prop.Name() {
							case "description":
								neighbor.Description = nodeVal(prop)
							case "multihop":
								if v := nodeVal(prop); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										neighbor.MultihopTTL = n
									}
								}
							case "peer-as":
								if v := nodeVal(prop); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										neighbor.PeerAS = uint32(n)
									}
								}
							case "authentication-key":
								neighbor.AuthPassword = nodeVal(prop)
							case "route-reflector-client":
								neighbor.RouteReflectorClient = true
							case "default-originate":
								neighbor.DefaultOriginate = true
							case "bfd-liveness-detection":
								neighbor.BFD = true
								for _, bc := range prop.Children {
									switch bc.Name() {
									case "minimum-interval":
										if v := nodeVal(bc); v != "" {
											if n, err := strconv.Atoi(v); err == nil {
												neighbor.BFDInterval = n
											}
										}
									case "multiplier":
										if v := nodeVal(bc); v != "" {
											if n, err := strconv.Atoi(v); err == nil {
												neighbor.BFDMultiplier = n
											}
										}
									}
								}
							case "loops":
								if v := nodeVal(prop); v != "" {
									if n, err := strconv.Atoi(v); err == nil {
										neighbor.AllowASIn = n
									}
								}
							case "remove-private":
								neighbor.RemovePrivateAS = true
							case "family":
								if len(prop.Keys) >= 2 {
									switch prop.Keys[1] {
									case "inet":
										neighbor.FamilyInet = true
										if pl := parsePrefixLimit(prop); pl > 0 {
											neighbor.PrefixLimitInet = pl
										}
									case "inet6":
										neighbor.FamilyInet6 = true
										if pl := parsePrefixLimit(prop); pl > 0 {
											neighbor.PrefixLimitInet6 = pl
										}
									}
								} else {
									for _, fc := range prop.Children {
										switch fc.Name() {
										case "inet":
											neighbor.FamilyInet = true
											if pl := parsePrefixLimit(fc); pl > 0 {
												neighbor.PrefixLimitInet = pl
											}
										case "inet6":
											neighbor.FamilyInet6 = true
											if pl := parsePrefixLimit(fc); pl > 0 {
												neighbor.PrefixLimitInet6 = pl
											}
										}
									}
								}
							}
						}
						proto.BGP.Neighbors = append(proto.BGP.Neighbors, neighbor)
					}
				}
			}
		}
	}

	ospf3Node := node.FindChild("ospf3")
	if ospf3Node != nil {
		proto.OSPFv3 = &OSPFv3Config{}

		for _, child := range ospf3Node.Children {
			switch child.Name() {
			case "router-id":
				if len(child.Keys) >= 2 {
					proto.OSPFv3.RouterID = child.Keys[1]
				}
			case "export":
				if len(child.Keys) >= 2 {
					proto.OSPFv3.Export = append(proto.OSPFv3.Export, child.Keys[1])
				}
			}
		}

		for _, areaInst := range namedInstances(ospf3Node.FindChildren("area")) {
			area := &OSPFv3Area{ID: areaInst.name}

			for _, ifInst := range namedInstances(areaInst.node.FindChildren("interface")) {
				iface := &OSPFv3Interface{Name: ifInst.name}
				for _, prop := range ifInst.node.Children {
					switch prop.Name() {
					case "passive":
						iface.Passive = true
					case "cost":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.Cost = n
							}
						}
					}
				}
				area.Interfaces = append(area.Interfaces, iface)
			}

			proto.OSPFv3.Areas = append(proto.OSPFv3.Areas, area)
		}
	}

	ripNode := node.FindChild("rip")
	if ripNode != nil {
		proto.RIP = &RIPConfig{}
		for _, child := range ripNode.Children {
			switch child.Name() {
			case "group":
				for _, gc := range child.Children {
					switch gc.Name() {
					case "neighbor":
						if len(gc.Keys) >= 2 {
							proto.RIP.Interfaces = append(proto.RIP.Interfaces, gc.Keys[1])
						}
					case "export":
						if len(gc.Keys) >= 2 {
							proto.RIP.Redistribute = append(proto.RIP.Redistribute, gc.Keys[1])
						}
					}
				}
			case "neighbor":
				if len(child.Keys) >= 2 {
					proto.RIP.Interfaces = append(proto.RIP.Interfaces, child.Keys[1])
				}
			case "passive-interface":
				if len(child.Keys) >= 2 {
					proto.RIP.Passive = append(proto.RIP.Passive, child.Keys[1])
				}
			case "redistribute":
				if len(child.Keys) >= 2 {
					proto.RIP.Redistribute = append(proto.RIP.Redistribute, child.Keys[1])
				}
			case "authentication-key":
				if v := nodeVal(child); v != "" {
					proto.RIP.AuthKey = v
				}
			case "authentication-type":
				if v := nodeVal(child); v != "" {
					proto.RIP.AuthType = v
				}
			}
		}
	}

	isisNode := node.FindChild("isis")
	if isisNode != nil {
		proto.ISIS = &ISISConfig{Level: "level-2"}
		for _, child := range isisNode.Children {
			switch child.Name() {
			case "net":
				if len(child.Keys) >= 2 {
					proto.ISIS.NET = child.Keys[1]
				}
			case "level":
				if len(child.Keys) >= 2 {
					proto.ISIS.Level = child.Keys[1]
				}
			case "is-type":
				if len(child.Keys) >= 2 {
					proto.ISIS.Level = child.Keys[1]
				}
			case "export":
				if len(child.Keys) >= 2 {
					proto.ISIS.Export = append(proto.ISIS.Export, child.Keys[1])
				}
			case "authentication-key":
				if v := nodeVal(child); v != "" {
					proto.ISIS.AuthKey = v
				}
			case "authentication-type":
				if v := nodeVal(child); v != "" {
					proto.ISIS.AuthType = v
				}
			case "wide-metrics-only":
				proto.ISIS.WideMetricsOnly = true
			case "overload":
				proto.ISIS.Overload = true
			case "interface":
				if len(child.Keys) >= 2 {
					iface := &ISISInterface{Name: child.Keys[1]}
					for _, prop := range child.Children {
						switch prop.Name() {
						case "level":
							if len(prop.Keys) >= 2 {
								iface.Level = prop.Keys[1]
							}
						case "passive":
							iface.Passive = true
						case "metric":
							if len(prop.Keys) >= 2 {
								if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
									iface.Metric = v
								}
							}
						case "authentication-key":
							iface.AuthKey = nodeVal(prop)
						case "authentication-type":
							iface.AuthType = nodeVal(prop)
						case "bfd-liveness-detection":
							iface.BFD = true
							for _, bc := range prop.Children {
								switch bc.Name() {
								case "minimum-interval":
									if v := nodeVal(bc); v != "" {
										if n, err := strconv.Atoi(v); err == nil {
											iface.BFDInterval = n
										}
									}
								case "multiplier":
									if v := nodeVal(bc); v != "" {
										if n, err := strconv.Atoi(v); err == nil {
											iface.BFDMultiplier = n
										}
									}
								}
							}
						}
					}
					// Check keys for "level N" and "passive" shorthand
					for _, k := range child.Keys[2:] {
						switch k {
						case "passive":
							iface.Passive = true
						case "level":
							// next key is the level value, handled above
						}
					}
					proto.ISIS.Interfaces = append(proto.ISIS.Interfaces, iface)
				}
			}
		}
	}
	return nil
}

func compileRouterAdvertisement(node *Node, proto *ProtocolsConfig) error {
	for _, inst := range namedInstances(node.FindChildren("interface")) {
		ra := &RAInterfaceConfig{
			Interface: inst.name,
		}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "managed-configuration":
				ra.ManagedConfig = true
			case "other-stateful-configuration":
				ra.OtherStateful = true
			case "default-lifetime":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						ra.DefaultLifetime = n
					}
				}
			case "max-advertisement-interval":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						ra.MaxAdvInterval = n
					}
				}
			case "min-advertisement-interval":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						ra.MinAdvInterval = n
					}
				}
			case "link-mtu":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						ra.LinkMTU = n
					}
				}
			case "dns-server-address":
				if len(prop.Keys) >= 2 {
					ra.DNSServers = append(ra.DNSServers, nodeVal(prop))
				}
			case "preference":
				ra.Preference = nodeVal(prop)
			case "nat64prefix", "nat-prefix":
				ra.NAT64Prefix = nodeVal(prop)
				// Check for lifetime sub-property
				if ltNode := prop.FindChild("lifetime"); ltNode != nil {
					if v := nodeVal(ltNode); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							ra.NAT64PrefixLife = n
						}
					}
				}
			case "prefix":
				pfxName := nodeVal(prop)
				if pfxName != "" {
					pfx := &RAPrefix{
						Prefix:     pfxName,
						OnLink:     true, // defaults
						Autonomous: true,
					}
					// For flat set, prefix children may be under the named child
					pfxChildren := prop.Children
					if len(prop.Keys) < 2 && len(prop.Children) > 0 {
						pfxChildren = prop.Children[0].Children
					}
					for _, child := range pfxChildren {
						switch child.Name() {
						case "on-link":
							pfx.OnLink = true
						case "autonomous":
							pfx.Autonomous = true
						case "no-onlink":
							pfx.OnLink = false
						case "no-autonomous":
							pfx.Autonomous = false
						case "valid-lifetime":
							if v := nodeVal(child); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									pfx.ValidLifetime = n
								}
							}
						case "preferred-lifetime":
							if v := nodeVal(child); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									pfx.PreferredLife = n
								}
							}
						}
					}
					ra.Prefixes = append(ra.Prefixes, pfx)
				}
			}
		}

		proto.RouterAdvertisement = append(proto.RouterAdvertisement, ra)
	}
	return nil
}

// namedInstances handles the dual AST shape for named config objects.
// Hierarchical: Node Keys: ["type", "name"], Children are properties.
// Flat set:     Node Keys: ["type"], Children are named instance nodes.
// Returns (name, propertyNode) pairs for each instance.
func namedInstances(nodes []*Node) []struct {
	name string
	node *Node
} {
	var result []struct {
		name string
		node *Node
	}
	for _, child := range nodes {
		if len(child.Keys) >= 2 {
			result = append(result, struct {
				name string
				node *Node
			}{child.Keys[1], child})
		} else {
			for _, sub := range child.Children {
				result = append(result, struct {
					name string
					node *Node
				}{sub.Name(), sub})
			}
		}
	}
	return result
}

// nodeVal returns the value for a property node, handling both AST shapes.
// Hierarchical: Keys: ["prop", "value"] → returns "value"
// Flat set:     Keys: ["prop"], Children: [Node{Keys:["value"]}] → returns "value"
// parsePrefixLimit extracts the maximum prefix count from a family inet/inet6 node.
// Walks: inet -> unicast -> prefix-limit -> maximum -> value
func parsePrefixLimit(famNode *Node) int {
	unicast := famNode.FindChild("unicast")
	if unicast == nil {
		return 0
	}
	pl := unicast.FindChild("prefix-limit")
	if pl == nil {
		return 0
	}
	mx := pl.FindChild("maximum")
	if mx == nil {
		return 0
	}
	if v := nodeVal(mx); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

// parseExportExtensions extracts export-extension values from an ipv4-template or
// ipv6-template node. Handles both hierarchical (children) and flat set (Keys) AST shapes.
func parseExportExtensions(prop *Node) []string {
	var exts []string
	// Hierarchical: prop has children named "export-extension"
	for _, child := range prop.Children {
		if child.Name() == "export-extension" {
			if v := nodeVal(child); v != "" {
				exts = append(exts, v)
			}
		}
	}
	// Flat set: prop.Keys = ["ipv4-template", "export-extension", "<value>"]
	if len(exts) == 0 && len(prop.Keys) >= 3 && prop.Keys[1] == "export-extension" {
		exts = append(exts, prop.Keys[2])
	}
	return exts
}

// peerFromPointToPoint derives the peer IP address from a /30 or /31 CIDR.
// Returns "" if the CIDR is not a valid point-to-point subnet.
func peerFromPointToPoint(cidr string) string {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return ""
	}
	ipNum := binary.BigEndian.Uint32(ip4)
	switch ones {
	case 30:
		hostPart := ipNum & 0x3
		var peerNum uint32
		switch hostPart {
		case 1:
			peerNum = (ipNum &^ 0x3) | 2
		case 2:
			peerNum = (ipNum &^ 0x3) | 1
		default:
			return ""
		}
		peer := make(net.IP, 4)
		binary.BigEndian.PutUint32(peer, peerNum)
		return peer.String()
	case 31:
		peer := make(net.IP, 4)
		binary.BigEndian.PutUint32(peer, ipNum^1)
		return peer.String()
	}
	return ""
}

// parseBandwidthBps parses a Junos bandwidth value and returns bits per second.
// "1g" = 1,000,000,000; "100m" = 100,000,000; "500k" = 500,000; plain number = bps.
func parseBandwidthBps(s string) uint64 {
	return parseScaledDecimalUnit(s)
}

// parseBandwidthLimit parses a Junos bandwidth-limit value (in bits/sec) to bytes/sec.
// "1m" = 1,000,000 bps = 125,000 bytes/s; "10g" = 10 Gbps; "500k" = 500,000 bps; plain number = bps.
func parseBandwidthLimit(s string) uint64 {
	return parseScaledDecimalUnit(s) / 8
}

// parseBandwidthLimitStrict is the error-returning sibling of
// parseBandwidthLimit used by the #1319 SchemaValidate path.
//
// The legacy parseBandwidthLimit silently returns 0 on garbage input,
// which is fine when the compiler later treats 0 as "unset"; the
// schema validator however needs to fail loud so `commit check` can
// reject `transmit-rate asd` instead of writing 0 bps under the hood.
// We keep parseBandwidthLimit's zero-return contract unchanged on
// purpose — too many callers depend on it.
func parseBandwidthLimitStrict(s string) (uint64, error) {
	scaled, err := parseScaledDecimalUnitStrict(s)
	if err != nil {
		return 0, err
	}
	return scaled / 8, nil
}

// parseBurstSizeLimit parses a Junos burst-size-limit value (in bytes).
// "15k" = 15,000 bytes; "1m" = 1,000,000 bytes; plain number = bytes.
func parseBurstSizeLimit(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	multiplier := uint64(1)
	if strings.HasSuffix(s, "g") || strings.HasSuffix(s, "G") {
		multiplier = 1000000000
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "m") || strings.HasSuffix(s, "M") {
		multiplier = 1000000
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "k") || strings.HasSuffix(s, "K") {
		multiplier = 1000
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	// burst-size-limit is already in bytes
	return v * multiplier
}

func parseScaledDecimalUnit(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	multiplier := 1.0
	if strings.HasSuffix(s, "g") || strings.HasSuffix(s, "G") {
		multiplier = 1000000000
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "m") || strings.HasSuffix(s, "M") {
		multiplier = 1000000
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "k") || strings.HasSuffix(s, "K") {
		multiplier = 1000
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return 0
	}
	scaled := v * multiplier
	if math.IsNaN(scaled) || math.IsInf(scaled, 0) {
		return 0
	}
	rounded := math.Round(scaled)
	if rounded > float64(^uint64(0)) {
		return 0
	}
	return uint64(rounded)
}

// parseScaledDecimalUnitStrict is the error-returning sibling of
// parseScaledDecimalUnit used by the #1319 SchemaValidate path. Keeping
// the legacy zero-return parseScaledDecimalUnit untouched preserves the
// compiler's "unset = 0" contract; this strict variant is the one the
// schema validator uses to fail loud on `asd` / negative / NaN inputs.
func parseScaledDecimalUnitStrict(s string) (uint64, error) {
	orig := s
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty value")
	}
	multiplier := 1.0
	if strings.HasSuffix(s, "g") || strings.HasSuffix(s, "G") {
		multiplier = 1000000000
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "m") || strings.HasSuffix(s, "M") {
		multiplier = 1000000
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "k") || strings.HasSuffix(s, "K") {
		multiplier = 1000
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid scaled decimal %q: %w", orig, err)
	}
	if v < 0 {
		return 0, fmt.Errorf("invalid scaled decimal %q: negative not allowed", orig)
	}
	scaled := v * multiplier
	if math.IsNaN(scaled) || math.IsInf(scaled, 0) {
		return 0, fmt.Errorf("invalid scaled decimal %q: non-finite", orig)
	}
	rounded := math.Round(scaled)
	if rounded > float64(^uint64(0)) {
		return 0, fmt.Errorf("invalid scaled decimal %q: overflow", orig)
	}
	return uint64(rounded), nil
}

// parseBurstSizeLimitStrict is the error-returning sibling of
// parseBurstSizeLimit used by the #1319 SchemaValidate path.
func parseBurstSizeLimitStrict(s string) (uint64, error) {
	orig := s
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty value")
	}
	multiplier := uint64(1)
	if strings.HasSuffix(s, "g") || strings.HasSuffix(s, "G") {
		multiplier = 1000000000
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "m") || strings.HasSuffix(s, "M") {
		multiplier = 1000000
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "k") || strings.HasSuffix(s, "K") {
		multiplier = 1000
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte-size %q: %w", orig, err)
	}
	prod := v * multiplier
	if multiplier != 0 && prod/multiplier != v {
		return 0, fmt.Errorf("invalid byte-size %q: overflow", orig)
	}
	return prod, nil
}
