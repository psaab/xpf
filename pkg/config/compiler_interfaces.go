package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/rendersafe"
)

// vrrpGroupPropertyKeywords are the property keywords recognized inside
// a vrrp-group block. Used to delimit multi-value runs (virtual-address)
// when properties are packed into a single node's Keys (#1813).
var vrrpGroupPropertyKeywords = map[string]bool{
	"virtual-address":     true,
	"priority":            true,
	"preempt":             true,
	"accept-data":         true,
	"advertise-interval":  true,
	"authentication-type": true,
	"authentication-key":  true,
	"track-interface":     true,
	"track-priority-cost": true,
}

// parseInterfaceNumeric9899 parses a canonical unsigned decimal token in
// [min..max] for #9899 F030/F031 interface tunnel/VLAN leaves (key
// 0..4294967295, TTL 1..255, VLAN/inner 0..4094). Canonical form is a
// non-empty bare run of ASCII digits: signs, whitespace, and non-digits
// reject, matching ParseCanonicalUint but with a uint64 value domain so the
// u32 key ceiling holds on 32-bit builds too. Range failures report the
// [min..max] contract and the offending value.
func parseInterfaceNumeric9899(raw string, min, max uint64) (uint64, error) {
	if raw == "" {
		return 0, fmt.Errorf("missing value %q (expected integer)", raw)
	}
	for i := range len(raw) {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, fmt.Errorf("non-canonical numeric token %q: only unsigned decimal digits are allowed (no leading sign or whitespace)", raw)
		}
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("integer out of range [%d..%d] (got %q)", min, max, raw)
	}
	if v < min || v > max {
		return 0, fmt.Errorf("integer out of range [%d..%d] (got %d)", min, max, v)
	}
	return v, nil
}

// validateInterfaceNumeric9899 returns the schema LeafValidator for one #9899
// numeric leaf. It shares parseInterfaceNumeric9899 with the compiler so
// schema and compile can never drift on form or bounds; the missing-value
// check mirrors ValidateInteger.
func validateInterfaceNumeric9899(min, max uint64) LeafValidator {
	return func(raw string, _ *Config) error {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("missing value %q (expected integer)", raw)
		}
		_, err := parseInterfaceNumeric9899(raw, min, max)
		return err
	}
}

func compileInterfaces(node *Node, ifaces *InterfacesConfig, opts compileOpts, warnings *[]string) error {
	// #6782: reth interfaces whose redundancy-group token was present but
	// unusable. Only ever populated on the tolerant path — the strict compile
	// fails in runPreWalkGates before compileInterfaces runs.
	var invalidRethRG map[string]bool
	for _, child := range node.Children {
		if child.IsLeaf {
			continue
		}
		ifName := child.Name()
		ifLeaves := expandResolvingRun9792(child, interfaceSchema9792()) // #9792: expand a lenient-path packed run (#9235).
		ifc := &InterfaceConfig{
			Name:  ifName,
			Units: make(map[int]*InterfaceUnit),
			// #9899 P2: record unit authorship BEFORE the quarantine loop
			// below can skip every unit. An interface that authored units but
			// kept none is quarantined, not unitless — the emitter must not
			// fall back to the bare-name endpoint.
			AuthoredUnits: len(child.FindChildren("unit")) > 0,
		}

		// Check for description
		if descNode := ifLeaves.FindChild("description"); descNode != nil {
			ifc.Description = nodeVal(descNode)
		}

		// Interface-level MTU
		if mtuNode := child.FindChild("mtu"); mtuNode != nil {
			if v := nodeVal(mtuNode); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					ifc.MTU = n
				}
			}
		}

		// Speed and duplex (ether-options or gigether-options)
		if speedNode := child.FindChild("speed"); speedNode != nil {
			ifc.Speed = nodeVal(speedNode)
		}
		if duplexNode := child.FindChild("duplex"); duplexNode != nil {
			ifc.Duplex = nodeVal(duplexNode)
		}
		if child.FindChild("disable") != nil {
			ifc.Disable = true
		}

		// Interface bandwidth (bits per second)
		if bwNode := ifLeaves.FindChild("bandwidth"); bwNode != nil {
			if v := nodeVal(bwNode); v != "" {
				ifc.Bandwidth = parseBandwidthBps(v)
			}
		}

		// Check for vlan-tagging flag
		if child.FindChild("vlan-tagging") != nil {
			ifc.VlanTagging = true
		}

		// Check for flexible-vlan-tagging flag (QinQ)
		if child.FindChild("flexible-vlan-tagging") != nil {
			ifc.FlexibleVlanTagging = true
		}

		// #4308 (fable-review-167 I-3): accepted-only interface-level parity
		// knobs — typed + compiled so they stop silently vanishing, with a
		// commit-time advisory (validateInterfaceParityWarnings) noting they
		// are not enforced yet.
		if nvNode := child.FindChild("native-vlan-id"); nvNode != nil {
			if v := nodeVal(nvNode); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					ifc.NativeVlanID = n
				}
			}
		}
		if child.FindChild("gratuitous-arp-reply") != nil {
			ifc.GratuitousARPReply = true
		}
		if child.FindChild("no-gratuitous-arp-request") != nil {
			ifc.NoGratuitousARPRequest = true
		}

		// Check for encapsulation
		if encapNode := child.FindChild("encapsulation"); encapNode != nil {
			ifc.Encapsulation = nodeVal(encapNode)
		}

		// Check for gigether-options redundant-parent and 802.3ad LAG member
		if goNode := child.FindChild("gigether-options"); goNode != nil {
			goNode = expandResolvingRun9792(goNode, gigetherOptionsSchema9792()) // #9792: expand a lenient-path packed run (#9235).
			if rpNode := goNode.FindChild("redundant-parent"); rpNode != nil {
				ifc.RedundantParent = nodeVal(rpNode)
			}
			if adNode := goNode.FindChild("802.3ad"); adNode != nil {
				ifc.LAGParent = nodeVal(adNode)
			}
		}

		// Check for aggregated-ether-options (LAG/ae interface)
		if aeoNode := child.FindChild("aggregated-ether-options"); aeoNode != nil {
			aeoNode = expandResolvingRun9792(aeoNode, aggregatedEtherOptionsSchema9792()) // #9792: expand a lenient-path packed run (#9235).
			opts := &AggregatedEtherOptions{}
			if lacpNode := aeoNode.FindChild("lacp"); lacpNode != nil {
				if lacpNode.FindChild("active") != nil {
					opts.LACPActive = true
				}
				if lacpNode.FindChild("passive") != nil {
					opts.LACPPassive = true
				}
				if periodicNode := lacpNode.FindChild("periodic"); periodicNode != nil {
					opts.LACPPeriodic = nodeVal(periodicNode)
				}
			}
			if lsNode := aeoNode.FindChild("link-speed"); lsNode != nil {
				opts.LinkSpeed = nodeVal(lsNode)
			}
			if mlNode := aeoNode.FindChild("minimum-links"); mlNode != nil {
				if v := nodeVal(mlNode); v != "" {
					if n, ok := parseIntLeaf(warnings, "interfaces "+ifName+" aggregated-ether-options minimum-links", v); ok {
						opts.MinimumLinks = n
					}
				}
			}
			ifc.AggregatedEtherOpts = opts
		}

		// Check for redundant-ether-options redundancy-group
		if reoNode := child.FindChild("redundant-ether-options"); reoNode != nil {
			if rgNode := reoNode.FindChild("redundancy-group"); rgNode != nil {
				if v, err := strconv.Atoi(nodeVal(rgNode)); err == nil {
					ifc.RedundancyGroup = v
				}
				// #6782: the Atoi above deliberately keeps its
				// discard-the-error shape so the compiled value is bit-identical
				// to what every prior release produced. What changes is that an
				// unusable token is no longer SILENT. On the strict path
				// validateRethRedundancyGroupTokensAST has already hard-rejected
				// this configuration in runPreWalkGates, so reaching here with a
				// bad token means we are on the tolerant load / peer-sync path.
				// Record it: the post-pass below strips this reth's addresses so
				// the lenient boot cannot configure the reth's service address as
				// an ordinary static address on BOTH nodes, which is precisely the
				// duplicate-address condition the gate exists to prevent. Warning
				// on the way in and then doing the damage anyway would make the
				// tolerant path the bug.
				if _, bad := rethRGTokenProblem(nodeVal(rgNode)); bad {
					if invalidRethRG == nil {
						invalidRethRG = make(map[string]bool)
					}
					invalidRethRG[ifName] = true
				}
			}
		}

		// Check for fabric-options member-interfaces.
		//
		// #6694: read the member names out of EVERY AST shape, not just
		// miNode.Children. The `Children`-only descent compiled an EMPTY
		// member list for the two hierarchical spellings that carry the names
		// on the node's own Keys — the idiomatic bracket list
		// `member-interfaces [ ge-0/0/0 ge-0/0/1 ];` and the plain single
		// `member-interfaces ge-0/0/0;`. FindChildren, not FindChild, because
		// repeated hierarchical statements land as SIBLING nodes and only the
		// first was ever consulted.
		if foNode := child.FindChild("fabric-options"); foNode != nil {
			for _, miNode := range foNode.FindChildren("member-interfaces") {
				ifc.FabricMembers = append(ifc.FabricMembers, fabricMemberValues(miNode)...)
			}
			if len(ifc.FabricMembers) > 0 {
				ifc.BondMode = "active-backup"
			}
		}

		// Check for interface-level tunnel configuration
		tunnelNode := child.FindChild("tunnel")
		skipIface9899 := false
		if tunnelNode != nil {
			// Default mode based on interface name prefix: ip-X/X/X → ipip, gr-X/X/X → gre
			defaultMode := "gre"
			if strings.HasPrefix(ifName, "ip-") {
				defaultMode = "ipip"
			}
			tc := &TunnelConfig{
				Name: LinuxIfName(ifName),
				Mode: defaultMode,
			}
			// #9156: expand the flat-set run before reading it. An untyped head
			// (`keepalive-retry`, `routing-instance`) admits the whole run past
			// the strict gate and this loop would then read only the head.
			for _, prop := range tunnelRunChildren9156(tunnelNode) {
				switch prop.Name() {
				case "source":
					if len(prop.Keys) >= 2 {
						tc.Source = prop.Keys[1]
					}
				case "destination":
					if len(prop.Keys) >= 2 {
						tc.Destination = prop.Keys[1]
					}
				case "mode":
					if len(prop.Keys) >= 2 {
						tc.Mode = prop.Keys[1]
					}
				case "key":
					raw := nodeVal(prop)
					v, perr := parseInterfaceNumeric9899(raw, 0, 4294967295)
					if perr != nil {
						msg := fmt.Sprintf("interfaces %s: tunnel key %s", ifName, perr.Error())
						if opts.lenientInterfaceNumericBounds {
							if warnings != nil {
								*warnings = append(*warnings, msg+fmt.Sprintf("; quarantining interface %q", ifName))
							}
							skipIface9899 = true
							break
						}
						return fmt.Errorf("%s", msg)
					}
					tc.Key = uint32(v)
				case "ttl":
					raw := nodeVal(prop)
					v, perr := parseInterfaceNumeric9899(raw, 1, 255)
					if perr != nil {
						msg := fmt.Sprintf("interfaces %s: tunnel ttl %s", ifName, perr.Error())
						if opts.lenientInterfaceNumericBounds {
							if warnings != nil {
								*warnings = append(*warnings, msg+fmt.Sprintf("; quarantining interface %q", ifName))
							}
							skipIface9899 = true
							break
						}
						return fmt.Errorf("%s", msg)
					}
					tc.TTL = int(v)
				case "keepalive":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tc.Keepalive = n
						}
					}
				case "keepalive-retry":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tc.KeepaliveRetry = n
						}
					}
				case "routing-instance":
					// routing-instance { destination <name>; }
					if destNode := prop.FindChild("destination"); destNode != nil {
						tc.RoutingInstance = nodeVal(destNode)
					} else if v, packed := packedTunnelRoutingInstance8936(prop); packed {
						tc.RoutingInstance = v
					} else if v := nodeVal(prop); v != "" {
						tc.RoutingInstance = v
					}
				case "wireguard":
					parseTunnelWireguard(tc, prop)
				}
				if skipIface9899 {
					break
				}
			}
			if skipIface9899 {
				continue
			}
			ifc.Tunnel = tc
		}

		for _, unitInst := range namedInstances(child.FindChildren("unit")) {
			unitNum, err := strconv.Atoi(unitInst.name)
			if err != nil || unitNum < 0 || unitNum > MaxLogicalUnit {
				// #5829: a non-numeric / negative / overflow / out-of-range
				// logical-unit id is NOT a droppable no-op — every child
				// (addresses, firewall filters, sampling, DHCP/DDNS, tunnel)
				// carries security intent that would silently vanish (a
				// unit-level filter would commit with no enforcement:
				// fail-open). Fail CLOSED, mirroring the schema keyValidator
				// (ValidateLogicalUnit) range. Strict compile hard-errors
				// naming the interface + raw token; the tolerant load /
				// peer-sync path (lenientNonNumericUnit) instead warns and
				// QUARANTINES the unit — skipped here, its children never
				// reattached to another unit — so an already-persisted config
				// an older binary silently dropped still boots, now with a
				// deterministic diagnostic.
				msg := fmt.Sprintf("interfaces %s: logical unit %q must be an integer in 0..%d",
					ifName, unitInst.name, MaxLogicalUnit)
				if opts.lenientNonNumericUnit {
					if warnings != nil {
						*warnings = append(*warnings, msg)
					}
					continue
				}
				return fmt.Errorf("%s", msg)
			}
			unit := &InterfaceUnit{Number: unitNum}

			// Parse description on unit
			if descNode := unitInst.node.FindChild("description"); descNode != nil {
				unit.Description = nodeVal(descNode)
			}

			// Parse point-to-point flag
			if unitInst.node.FindChild("point-to-point") != nil {
				unit.PointToPoint = true
			}

			// Parse tunnel config at unit level (gr-0/0/0 unit N { tunnel { ... } })
			if tunnelNode := unitInst.node.FindChild("tunnel"); tunnelNode != nil {
				defaultMode := "gre"
				if strings.HasPrefix(ifName, "ip-") {
					defaultMode = "ipip"
				}
				// Per-unit tunnel: each unit with its own tunnel config gets
				// a separate Linux interface. Unit 0 uses the base name,
				// unit N>0 appends "uN".
				//
				// EXCEPT for a unit that stays on the interface's WireGuard
				// mode, which shares the interface device
				// (unitSharesInterfaceWireguardDevice, #6941).
				linuxName := LinuxIfName(ifName)
				if unitNum > 0 && !unitSharesInterfaceWireguardDevice(ifc, tunnelNode) {
					linuxName = linuxName + "u" + strconv.Itoa(unitNum)
				}
				tc := &TunnelConfig{Name: linuxName, Mode: defaultMode}
				// Inherit from interface-level tunnel if present. Deep-copy
				// so each per-unit tunnel owns independent backing arrays for
				// its slice fields (Addresses / WgPeers). A shallow
				// `*tc = *ifc.Tunnel` copies only the slice headers, so
				// sibling units would alias the parent's backing array and a
				// per-unit override on one unit would contaminate the others
				// (#3898 — duplicate IP on two tunnel netdevs).
				if ifc.Tunnel != nil {
					tc = ifc.Tunnel.cloneForUnit(linuxName)
				}
				// #9156: same expansion as the interface-level reader above.
				skipUnit9899 := false
				for _, prop := range tunnelRunChildren9156(tunnelNode) {
					switch prop.Name() {
					case "source":
						if v := nodeVal(prop); v != "" {
							tc.Source = v
						}
					case "destination":
						if v := nodeVal(prop); v != "" {
							tc.Destination = v
						}
					case "routing-instance":
						if destNode := prop.FindChild("destination"); destNode != nil {
							tc.RoutingInstance = nodeVal(destNode)
						} else if v, packed := packedTunnelRoutingInstance8936(prop); packed {
							tc.RoutingInstance = v
						} else if v := nodeVal(prop); v != "" {
							tc.RoutingInstance = v
						}
					case "mode":
						if v := nodeVal(prop); v != "" {
							tc.Mode = v
						}
					case "key":
						v := nodeVal(prop)
						n, perr := parseInterfaceNumeric9899(v, 0, 4294967295)
						if perr != nil {
							msg := fmt.Sprintf("interfaces %s unit %d: tunnel key %s", ifName, unitNum, perr.Error())
							if opts.lenientInterfaceNumericBounds {
								if warnings != nil {
									*warnings = append(*warnings, msg+fmt.Sprintf("; skipping unit %d", unitNum))
								}
								skipUnit9899 = true
								break
							}
							return fmt.Errorf("%s", msg)
						}
						tc.Key = uint32(n)
					case "ttl":
						v := nodeVal(prop)
						n, perr := parseInterfaceNumeric9899(v, 1, 255)
						if perr != nil {
							msg := fmt.Sprintf("interfaces %s unit %d: tunnel ttl %s", ifName, unitNum, perr.Error())
							if opts.lenientInterfaceNumericBounds {
								if warnings != nil {
									*warnings = append(*warnings, msg+fmt.Sprintf("; skipping unit %d", unitNum))
								}
								skipUnit9899 = true
								break
							}
							return fmt.Errorf("%s", msg)
						}
						tc.TTL = int(n)
					case "keepalive":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								tc.Keepalive = n
							}
						}
					case "keepalive-retry":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								tc.KeepaliveRetry = n
							}
						}
					case "wireguard":
						parseTunnelWireguard(tc, prop)
					}
					if skipUnit9899 {
						break
					}
				}
				if skipUnit9899 {
					continue
				}
				unit.Tunnel = tc
			}

			// Parse vlan-id on unit
			if vlanNode := unitInst.node.FindChild("vlan-id"); vlanNode != nil {
				v := nodeVal(vlanNode)
				n, perr := parseInterfaceNumeric9899(v, 0, 4094)
				if perr != nil {
					msg := fmt.Sprintf("interfaces %s unit %d: vlan-id %s", ifName, unitNum, perr.Error())
					if opts.lenientInterfaceNumericBounds {
						if warnings != nil {
							*warnings = append(*warnings, msg+fmt.Sprintf("; skipping unit %d", unitNum))
						}
						continue
					}
					return fmt.Errorf("%s", msg)
				}
				unit.VlanID = int(n)
			}

			// Parse inner-vlan-id on unit (QinQ inner tag)
			if ivNode := unitInst.node.FindChild("inner-vlan-id"); ivNode != nil {
				v := nodeVal(ivNode)
				n, perr := parseInterfaceNumeric9899(v, 0, 4094)
				if perr != nil {
					msg := fmt.Sprintf("interfaces %s unit %d: inner-vlan-id %s", ifName, unitNum, perr.Error())
					if opts.lenientInterfaceNumericBounds {
						if warnings != nil {
							*warnings = append(*warnings, msg+fmt.Sprintf("; skipping unit %d", unitNum))
						}
						continue
					}
					return fmt.Errorf("%s", msg)
				}
				unit.InnerVlanID = int(n)
			}

			// Handle two AST shapes:
			// - set commands:  family { inet { address ...; dhcp; } }
			//   Keys=["family"], child Keys=["inet"] with grandchildren
			// - hierarchical:  family inet { address ...; dhcp; }
			//   Keys=["family","inet"], children are address/dhcp directly
			for _, familyNode := range unitInst.node.FindChildren("family") {
				var afNodes []*Node
				if len(familyNode.Keys) >= 2 {
					afNodes = append(afNodes, familyNode)
				} else {
					afNodes = append(afNodes, familyNode.Children...)
				}
				for _, afNode := range afNodes {
					// #7522: Name() rather than Keys[0]. It returns "" for an
					// empty Keys slice, where Keys[0] panics with index out of
					// range. afNodes is either familyNode itself (len(Keys) >= 2
					// by the branch above, so safe) or familyNode.Children —
					// and a CHILD's Keys are not structurally guaranteed
					// non-empty once the tree can come from anywhere but the
					// parser.
					//
					// The live parser and SetPath paths do guarantee
					// len(Keys) >= 1, so this only bites a malformed persisted
					// AST — pkg/configstore/db.go's plain json.Unmarshal has no
					// Node validator — or a handcrafted tree. A bad persisted
					// state must ERROR on load, never panic (#1960
					// fail-closed-on-load). Same fix and same reasoning as
					// #4827 applied to the sibling firewall family walkers.
					//
					// An empty afName matches no address family below and the
					// unit is compiled without one, which is the same outcome as
					// an unrecognised family name — it does not silently adopt a
					// neighbour's family.
					afName := afNode.Name()
					if len(afNode.Keys) >= 2 {
						afName = afNode.Keys[1]
					}
					switch afName {
					case "inet":
						// #9424: a BRACKETED list packs every address past the
						// first onto this leaf's Keys (hierarchical) or into a
						// child chain (flat set), and namedInstances reads slot
						// 0 only — so `address [ a b ]` compiled to ONE address
						// with no error and no warning.
						inetAddrs, inetBad := unitAddressInstances(afNode, "inet")
						ifaces.MalformedAddresses = append(ifaces.MalformedAddresses, inetBad...)
						for _, addrInst := range inetAddrs {
							unit.Addresses = append(unit.Addresses, addrInst.name)
							// Check for primary/preferred flags
							if addrInst.node.FindChild("primary") != nil {
								unit.PrimaryAddress = addrInst.name
							}
							if addrInst.node.FindChild("preferred") != nil {
								unit.PreferredAddress = addrInst.name
							}
							parseVRRPGroups(unit, addrInst.name, addrInst.node)
						}
						// #9977: the `dhcp` node may carry its options as a PACKED
						// TAIL rather than as children. #9932 taught the fold to
						// put `dhcp` under `family inet` for the elided spelling,
						// but `family inet dhcp lease-time 3600;` leaves
						// `lease-time 3600` on the dhcp node's own Keys, where
						// FindChild and the Children range below cannot see it —
						// so the client came up with the DEFAULT lease time on a
						// commit that reported success and rendered the statement.
						//
						// A READER fix, not ten scope admissions: the ten
						// sub-option pairs each reach exactly one schema path and
						// each is empty-equivalent, so admitting them was viable,
						// but it is ten pairs owing rows in four registers to reach
						// what one packedBody call reaches here. Same shape as
						// #9620 H9.
						if dhcpNode := packedBody(afNode.FindChild("dhcp"),
							schemaForPath("interfaces", "x", "unit", "family", "inet", "dhcp")); dhcpNode != nil {
							unit.DHCP = true
							if len(dhcpNode.Children) > 0 {
								opts := &DHCPInetOptions{}
								for _, prop := range dhcpNode.Children {
									switch prop.Name() {
									case "lease-time":
										if v := nodeVal(prop); v != "" {
											if n, ok := parseIntLeaf(warnings, "interfaces "+ifName+" dhcp lease-time", v); ok {
												opts.LeaseTime = n
											}
										}
									case "retransmission-attempt":
										if v := nodeVal(prop); v != "" {
											if n, ok := parseIntLeaf(warnings, "interfaces "+ifName+" dhcp retransmission-attempt", v); ok {
												opts.RetransmissionAttempt = n
											}
										}
									case "retransmission-interval":
										if v := nodeVal(prop); v != "" {
											if n, ok := parseIntLeaf(warnings, "interfaces "+ifName+" dhcp retransmission-interval", v); ok {
												opts.RetransmissionInterval = n
											}
										}
									case "force-discover":
										opts.ForceDiscover = true
									}
								}
								unit.DHCPOptions = opts
							}
						}
						if mtuNode := afNode.FindChild("mtu"); mtuNode != nil {
							if v := nodeVal(mtuNode); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									unit.MTU = n
								}
							}
						}
						if sampNode := afNode.FindChild("sampling"); sampNode != nil {
							if sampNode.FindChild("input") != nil {
								unit.SamplingInput = true
							}
							if sampNode.FindChild("output") != nil {
								unit.SamplingOutput = true
							}
						}
						if filterNode := afNode.FindChild("filter"); filterNode != nil {
							if inputNode := filterNode.FindChild("input"); inputNode != nil {
								unit.FilterInputV4 = nodeVal(inputNode)
							}
							if outputNode := filterNode.FindChild("output"); outputNode != nil {
								unit.FilterOutputV4 = nodeVal(outputNode)
							}
						}
						// #4308 (fable-review-167 I-3): accepted-only family
						// inet parity knobs — typed + compiled so they stop
						// silently vanishing, with a commit-time advisory
						// (validateInterfaceParityWarnings) noting they are not
						// enforced yet.
						if unNode := afNode.FindChild("unnumbered-address"); unNode != nil {
							unit.UnnumberedInet = nodeVal(unNode)
						}
						if afNode.FindChild("targeted-broadcast") != nil {
							unit.TargetedBroadcast = true
						}
						// Surface A router/interface-address DDNS (#2691 P2): the
						// per-family `dynamic-dns` binding may appear as a child node
						// (hierarchical) OR be packed into afNode's Keys (flat-set), so
						// compileInterfaceDynamicDNS walks the whole inet subtree.
						if ddns := compileInterfaceDynamicDNS(afNode); ddns != nil {
							unit.DynamicDNSInet = ddns
						}
					case "inet6":
						// #9424, the inet6 arm of the same loss.
						inet6Addrs, inet6Bad := unitAddressInstances(afNode, "inet6")
						ifaces.MalformedAddresses = append(ifaces.MalformedAddresses, inet6Bad...)
						for _, addrInst := range inet6Addrs {
							unit.Addresses = append(unit.Addresses, addrInst.name)
							if addrInst.node.FindChild("primary") != nil && unit.PrimaryAddress == "" {
								unit.PrimaryAddress = addrInst.name
							}
							if addrInst.node.FindChild("preferred") != nil && unit.PreferredAddress == "" {
								unit.PreferredAddress = addrInst.name
							}
							// IPv6 VRRP groups (#2384): identical parse to the
							// inet arm; the VIPs are IPv6 and the engine
							// family-detects them at parse time.
							parseVRRPGroups(unit, addrInst.name, addrInst.node)
						}
						if afNode.FindChild("dhcpv6") != nil {
							unit.DHCPv6 = true
						}
						if afNode.FindChild("dad-disable") != nil {
							unit.DADDisable = true
						}
						if mtuNode := afNode.FindChild("mtu"); mtuNode != nil {
							if v := nodeVal(mtuNode); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									if n < unit.MTU || unit.MTU == 0 {
										unit.MTU = n
									}
								}
							}
						}
						if sampNode := afNode.FindChild("sampling"); sampNode != nil {
							if sampNode.FindChild("input") != nil {
								unit.SamplingInput = true
							}
							if sampNode.FindChild("output") != nil {
								unit.SamplingOutput = true
							}
						}
						if filterNode := afNode.FindChild("filter"); filterNode != nil {
							if inputNode := filterNode.FindChild("input"); inputNode != nil {
								unit.FilterInputV6 = nodeVal(inputNode)
							}
							if outputNode := filterNode.FindChild("output"); outputNode != nil {
								unit.FilterOutputV6 = nodeVal(outputNode)
							}
						}
						// Surface A router/interface-address DDNS (#2691 P2): the
						// per-family inet6 binding (independent of the inet binding).
						if ddns := compileInterfaceDynamicDNS(afNode); ddns != nil {
							unit.DynamicDNSInet6 = ddns
						}
						// #9977, the inet6 twin: `family inet6 dhcpv6-client
						// client-type stateful;` leaves the options on the
						// dhcpv6-client node's Keys.
						if dcNode := packedBody(afNode.FindChild("dhcpv6-client"),
							schemaForPath("interfaces", "x", "unit", "family", "inet6", "dhcpv6-client")); dcNode != nil {
							unit.DHCPv6 = true
							dc := &DHCPv6ClientConfig{}
							for _, prop := range dcNode.Children {
								switch prop.Name() {
								case "client-identifier":
									if dtNode := prop.FindChild("duid-type"); dtNode != nil {
										dc.DUIDType = nodeVal(dtNode)
									} else if nodeVal(prop) == "duid-type" && len(prop.Keys) >= 3 {
										// Inline: client-identifier duid-type duid-ll;
										dc.DUIDType = prop.Keys[2]
									}
								case "client-type":
									dc.ClientType = nodeVal(prop)
								case "client-ia-type":
									if v := nodeVal(prop); v != "" {
										dc.ClientIATypes = append(dc.ClientIATypes, v)
									}
								case "prefix-delegating":
									if plNode := prop.FindChild("preferred-prefix-length"); plNode != nil {
										if v := nodeVal(plNode); v != "" {
											if n, ok := parseIntLeaf(warnings, "interfaces "+ifName+" dhcpv6-client prefix-delegating preferred-prefix-length", v); ok {
												dc.PrefixDelegatingPrefixLen = n
											}
										}
									}
									if slNode := prop.FindChild("sub-prefix-length"); slNode != nil {
										if v := nodeVal(slNode); v != "" {
											if n, ok := parseIntLeaf(warnings, "interfaces "+ifName+" dhcpv6-client prefix-delegating sub-prefix-length", v); ok {
												dc.PrefixDelegatingSubPrefLen = n
											}
										}
									}
								case "req-option":
									if v := nodeVal(prop); v != "" {
										dc.ReqOptions = append(dc.ReqOptions, v)
									}
								case "update-router-advertisement":
									if ifNode := prop.FindChild("interface"); ifNode != nil {
										dc.UpdateRAInterface = nodeVal(ifNode)
									}
								}
							}
							unit.DHCPv6Client = dc
						}
					}
				}
			}

			ifc.Units[unitNum] = unit

			// Collect tunnel addresses from unit config
			if unit.Tunnel != nil {
				// Per-unit tunnel: addresses belong to this specific tunnel
				unit.Tunnel.Addresses = append(unit.Tunnel.Addresses, unit.Addresses...)
			} else if ifc.Tunnel != nil {
				// Interface-level tunnel: all unit addresses go to shared tunnel
				ifc.Tunnel.Addresses = append(ifc.Tunnel.Addresses, unit.Addresses...)
			}
		}

		ifaces.Interfaces[ifName] = ifc
	}
	suppressInvalidRethAddresses(ifaces, invalidRethRG)
	return nil
}

// suppressInvalidRethAddresses strips every configured address from a reth
// whose redundancy-group token was present but unusable (#6782), and from any
// interface that inherits from it as a redundant member.
//
// This runs on the tolerant load / peer-sync path only (the strict path
// hard-rejects in runPreWalkGates). The reth reads as NON-redundant everywhere
// downstream — pkg/dataplane compiler_iface.go decides both `isReth` and
// `isVRRPReth` with `redundancy-group > 0` — so leaving the addresses in place
// would make the lenient boot write the reth's service address onto the
// physical device as an ordinary static address, with `KeepAddresses:false`,
// on BOTH nodes of the cluster. Removing the addresses degrades the interface
// to no-service rather than to duplicate-service: the node still BOOTS as
// #1960 requires, the operator gets the warning the gate emitted, and no
// address is contended on the wire until the group is repaired.
//
// It clears the addresses rather than the group id because the group id is
// what the operator has to fix; rewriting it here would erase the evidence and
// make a later strict commit-check pass on a config that is still wrong.
func suppressInvalidRethAddresses(ifaces *InterfacesConfig, invalid map[string]bool) {
	if len(invalid) == 0 || ifaces == nil {
		return
	}
	clear := func(ifc *InterfaceConfig) {
		if ifc == nil {
			return
		}
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			unit.Addresses = nil
			unit.PrimaryAddress = ""
			unit.PreferredAddress = ""
		}
	}
	for name := range invalid {
		clear(ifaces.Interfaces[name])
	}
	// A physical member carries the reth's addresses through RedundantParent,
	// so an untouched member would reintroduce exactly what was just removed.
	for _, ifc := range ifaces.Interfaces {
		if ifc != nil && ifc.RedundantParent != "" && invalid[ifc.RedundantParent] {
			clear(ifc)
		}
	}
}

// parseTunnelWireguard fills the WireGuard fields on tc from a
// `wireguard { ... }` node under a tunnel stanza (#1432 S2a). The
// minimal generic grammar is:
//
//	tunnel {
//	    mode wireguard;
//	    wireguard {
//	        listen-port 51820;
//	        private-key <64-hex>;
//	        peer {
//	            public-key <64-hex>;
//	            allowed-ips <cidr>;   # repeatable
//	            endpoint <ip:port>;
//	            persistent-keepalive <secs>;
//	        }
//	    }
//	}
//
// This is intentionally narrower than the eventual Junos wireguard
// grammar (S6); it compiles to the TunnelEndpointSnapshot Wg* DTO
// fields without committing to that surface.
func parseTunnelWireguard(tc *TunnelConfig, wgNode *Node) {
	// listen-port / private-key are tunnel-level. The `peer` children
	// are named instances keyed by pubkey (#1434 multi-peer); collapse
	// both AST shapes via namedInstances and append one WgPeerConfig
	// per instance (preserving config order — the snapshot builder
	// sorts by pubkey for HA determinism).
	for _, prop := range expandResolvingRuns9792(wgNode.Children, tunnelWireguardSchema9792()) { // #9792: expand a lenient-path packed run (#9235).
		switch prop.Name() {
		case "listen-port":
			if v := nodeVal(prop); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
					tc.WgListenPort = uint16(n)
				}
			}
		case "private-key":
			if v := nodeVal(prop); v != "" {
				tc.WgLocalPrivkeyHex = Secret(v)
			}
		}
	}
	for _, inst := range namedInstances(wgNode.FindChildren("peer")) {
		if inst.name == "" {
			continue
		}
		tc.WgPeers = append(tc.WgPeers, parseTunnelWireguardPeer(inst.name, inst.node))
	}
}

// parseTunnelWireguardPeer parses ONE WG peer instance into a
// WgPeerConfig (#1434). The peer identity (pubkey) is the named-instance
// key; allowed-ips/endpoint/persistent-keepalive/preshared-key are the
// instance's children. Both AST shapes are already collapsed by the
// namedInstances caller, so `peerNode.Children` are the leaves.
//
// The pubkey is lowercased here so the canonical form drives EVERYTHING
// downstream at once: the dup-pubkey dedup in validateWireguardPeers
// (so `AA..` and `aa..` collide instead of both surviving and orphaning
// a peer in the engine's release-build reconcile, where the dup
// debug_assert is compiled out), the wire bytes the Rust hex decoder
// consumes, and the "64-char lowercase hex" contract the status row
// documents. A non-hex key (operator typo) survives unchanged and the
// commit-time hex validator rejects it.
func parseTunnelWireguardPeer(pubkey string, peerNode *Node) WgPeerConfig {
	peer := WgPeerConfig{PublicKeyHex: strings.ToLower(pubkey)}
	for _, prop := range expandResolvingRuns9792(peerNode.Children, tunnelWireguardPeerSchema9792()) { // #9792: expand a lenient-path packed run (#9235).
		switch prop.Name() {
		case "allowed-ips":
			// Multi-value (#2419): a bracketed list `allowed-ips [ a b ]`
			// collapses every prefix onto prop.Keys[1:] (and older trees may
			// split it into orphan leaf children). Reading only nodeVal here
			// kept the first prefix and dropped the rest. Accumulate both
			// shapes, mirroring firewallMatchValues.
			for _, k := range prop.Keys[1:] {
				if k != "" {
					peer.AllowedIPs = append(peer.AllowedIPs, k)
				}
			}
			for _, vn := range prop.Children {
				if vn.IsLeaf && len(vn.Keys) >= 1 && vn.Keys[0] != "" {
					peer.AllowedIPs = append(peer.AllowedIPs, vn.Keys[0])
				}
			}
		case "endpoint":
			if v := nodeVal(prop); v != "" {
				peer.Endpoint = v
			}
		case "persistent-keepalive":
			if v := nodeVal(prop); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 65535 {
					peer.KeepaliveSecs = uint16(n)
				}
			}
		case "preshared-key":
			if v := nodeVal(prop); v != "" {
				peer.PresharedKeyHex = Secret(v)
			}
		}
	}
	return peer
}

// selectMSSToken returns the raw MSS token the compiler would actually
// select for a tcp-mss kind node (ipsec-vpn / gre-in / gre-out / all-tcp),
// using the SAME precedence as parseMSSValue: the hierarchical `mss` child's
// Keys[1] FIRST (if present), else the node's own flat Keys[1]. The bool is
// false when neither position carries a token. #1979 Layer B shares this so
// the Tier-3 commit-time validator (validateTCPMSSRanges) can never diverge
// from what the compiler reads — it must range-check the SELECTED value, not
// "both positions" (a mixed shape like `gre-in 70000 { mss 1360; }` compiles
// the child 1360 and discards the flat 70000, so validating both would
// wrongly reject it).
func selectMSSToken(node *Node) (string, bool) {
	// Hierarchical: ipsec-vpn { mss 1360; } or gre-in { mss 1360; }.
	// Prefer the child ONLY when it parses — an unparseable child
	// (e.g. `gre-in 1360 { mss bogus; }`) must fall through to the flat
	// token so the value selected here matches what parseMSSValue/the
	// compiler actually use (the flat 1360), not the discarded child.
	// Returning the unparseable child unconditionally was a precedence
	// regression vs the original parseMSSValue (#1979).
	if mssChild := node.FindChild("mss"); mssChild != nil && len(mssChild.Keys) >= 2 {
		if _, err := strconv.Atoi(mssChild.Keys[1]); err == nil {
			return mssChild.Keys[1], true
		}
		// #8824: the child is present and UNPARSEABLE. Falling through is
		// correct only when a flat token exists to fall through TO — that is
		// the #1979 mixed-shape precedence above. With no flat token there is
		// nothing to select, and returning false here reported "no value
		// configured" for a config that plainly configures one:
		// `all-tcp { mss notanint; }` committed clean, clamped nothing, and
		// warned nobody, while the same bad token flat was rejected and an
		// out-of-range value in the SAME braced shape was rejected. Return the
		// unparseable token so the gates that already exist can refuse it.
		if len(node.Keys) < 2 {
			return mssChild.Keys[1], true
		}
	}
	// #8824: the flat-set spelling of the hierarchical child.
	// `set security flow tcp-mss all-tcp mss 1350` flattens the SAME hierarchy
	// the braced form writes, so it packs as Keys=["all-tcp","mss","1350"].
	//
	// This used to select the literal "mss" and reject the command, on #6564's
	// stated ground that "`mss` is the hierarchical keyword and is a typo when
	// inline". THE DISCONFIRMING ROW WAS ALWAYS IN THE SAME INSTRUMENT: the
	// braced `all-tcp { mss 1350; }` is ACCEPTED and compiles to 1350. If `mss`
	// were a typo the braced form would reject it too. It does not, so `mss` is
	// a real keyword in this grammar — and CLAUDE.md's contract is that the
	// compiler handles both AST shapes. A keyword legitimate in the hierarchy is
	// legitimate in its flattening, because that is what flat `set` IS.
	//
	// A genuine typo is still caught: `all-tcp msss 1350` selects "msss" and is
	// refused, and `all-tcp mss` with no value selects "mss" and is refused.
	// Only the exact keyword followed by a value token is consumed here.
	//
	// #8838 CORRECTS THAT SENTENCE. It was measured on the PACKED spelling and
	// generalised to the braced one, which did not hold: braced
	// `all-tcp { msss 1350; }` and `all-tcp { mss; }` were both ACCEPTED with
	// the clamp silently at 0. The final branch below closes that.
	if len(node.Keys) >= 3 && node.Keys[1] == "mss" {
		return node.Keys[2], true
	}
	// Flat: ipsec-vpn 1360; (set syntax)
	if len(node.Keys) >= 2 {
		return node.Keys[1], true
	}
	// #8838: a BRACED body that yields no usable token is malformed, not empty.
	//
	// `all-tcp { msss 1350; }` has a child that is not `mss`; `all-tcp { mss; }`
	// has the keyword with no value. Both reached here and returned "no token",
	// which every caller reads as "nothing configured" — so the clamp silently
	// sat at 0 while the packed spellings of the SAME mistakes were refused
	// loudly. That asymmetry is the defect: the identical typo was loud in one
	// spelling and silent in the other.
	//
	// Returning the offending keyword makes the braced form inherit the exact
	// refusal the packed form already gives, rather than adding a second gate
	// that could drift from it. An EMPTY body (`all-tcp { }`) still yields no
	// token and stays accepted-as-unconfigured, which is what it is: the
	// distinction is a body that says something unusable versus a body that
	// says nothing.
	if len(node.Children) > 0 {
		return node.Children[0].Name(), true
	}
	return "", false
}

// parseMSSValue extracts MSS value from either "node { mss VALUE; }" or "node VALUE;" syntax.
func parseMSSValue(node *Node) int {
	tok, ok := selectMSSToken(node)
	if !ok {
		return 0
	}
	if v, err := strconv.Atoi(tok); err == nil {
		return v
	}
	return 0
}

// parseVRRPGroups parses every `vrrp-group <id> { ... }` block under a
// family inet/inet6 address into unit.VRRPGroups. Shared by both family
// arms (#2384): the inet6 path carries IPv6 VIPs, and the native VRRP
// engine family-detects each VIP at parse (pkg/vrrp/instance.go
// ip.To4()==nil), so no runtime change was needed. Groups are keyed
// `<address-CIDR>_grp<id>`, so a dual-stack unit with the same group ID
// under both an inet AND an inet6 address yields TWO distinct map
// entries (the v4 and v6 address strings differ) — no collision.
// Handles both AST shapes (#1796): properties packed into the instance
// node's Keys[2:] (legacy flat-set leaves) AND properties as child
// nodes (hierarchical blocks + schema-structured flat-set).
func parseVRRPGroups(unit *InterfaceUnit, addrName string, addrNode *Node) {
	for _, vrrpInst := range namedInstances(addrNode.FindChildren("vrrp-group")) {
		groupID, err := strconv.Atoi(vrrpInst.name)
		if err != nil {
			continue
		}
		if unit.VRRPGroups == nil {
			unit.VRRPGroups = make(map[string]*VRRPGroup)
		}
		key := fmt.Sprintf("%s_grp%d", addrName, groupID)
		vg := unit.VRRPGroups[key]
		if vg == nil {
			vg = &VRRPGroup{
				ID:       groupID,
				Priority: 100, // default
			}
			unit.VRRPGroups[key] = vg
		}
		// Keys-encoded properties (flat-set leaf shape):
		// Keys = ["vrrp-group", "<id>", prop, value, ...].
		keys := vrrpInst.node.Keys
		for i := 2; i < len(keys); i++ {
			switch keys[i] {
			case "virtual-address":
				// Multi-value (#1813): consume every
				// following token up to the next
				// recognized property keyword —
				// `vrrp-group 1 virtual-address
				// [ a b ];` packs all addresses
				// inline.
				for i+1 < len(keys) && !vrrpGroupPropertyKeywords[keys[i+1]] {
					i++
					vg.VirtualAddresses = append(vg.VirtualAddresses, keys[i])
				}
			case "priority":
				if i+1 < len(keys) {
					i++
					// #4573: only overwrite on a clean parse. A swallowed
					// Atoi error (`_ =`) used to reset Priority to 0 — the
					// RFC 5798 resignation value — on the lenient / HA-sync
					// path; keep the constructor default (100) or the prior
					// value instead of silently resigning the group.
					if n, err := strconv.Atoi(keys[i]); err == nil {
						vg.Priority = n
					}
				}
			case "preempt":
				vg.Preempt = true
				// Junos `preempt hold-time <seconds>` packs the
				// nested leaf onto the Keys run in the flat-set
				// shape: ... preempt hold-time 30. Consume the
				// optional `hold-time <n>` pair when present.
				if i+2 < len(keys) && keys[i+1] == "hold-time" {
					// #4573: keep the prior value on a bad parse (`_ =`).
					if n, err := strconv.Atoi(keys[i+2]); err == nil {
						vg.PreemptHoldTime = n
					}
					i += 2
				}
			case "accept-data":
				vg.AcceptData = true
			case "advertise-interval":
				if i+1 < len(keys) {
					i++
					// #4573: keep the prior value on a bad parse (`_ =`).
					if n, err := strconv.Atoi(keys[i]); err == nil {
						vg.AdvertiseInterval = n
					}
				}
			case "authentication-type":
				if i+1 < len(keys) {
					i++
					vg.AuthType = keys[i]
				}
			case "authentication-key":
				if i+1 < len(keys) {
					i++
					vg.AuthKey = Secret(keys[i])
				}
			case "track-interface":
				if i+1 < len(keys) {
					i++
					// First-wins (#1814): duplicates in
					// the Keys-packed spelling are
					// rejected/warned by the AST
					// pre-walk; keep the first here so
					// lenient semantics are consistent
					// with the child-node prune.
					if vg.TrackInterface == "" {
						vg.TrackInterface = keys[i]
					}
				}
			case "track-priority-cost":
				if i+1 < len(keys) {
					i++
					vg.TrackPriorityDelta, _ = parseTrackCost(keys[i])
				}
			}
		}
		// Child-node properties (hierarchical blocks and
		// schema-structured flat-set containers).
		// Track-interface values are gathered and applied
		// AFTER the loop so the nested
		// `track-interface <if> { priority-cost <n>; }`
		// form wins over the legacy flat sibling
		// `track-priority-cost <n>` regardless of node
		// order (#1814 — the loop is source-order based).
		var (
			trackIface          string
			trackIfaceSet       bool
			nestedTrackCost     int
			nestedTrackCostSet  bool
			siblingTrackCost    int
			siblingTrackCostSet bool
		)
		for _, prop := range vrrpInst.node.Children {
			switch prop.Name() {
			case "virtual-address":
				// Multi-value spellings (#1813):
				// bracketed `virtual-address [ a b ];`
				// packs all addresses into Keys[1:]
				// (flat-set replay may carry trailing
				// values as children); braced block
				// `virtual-address { a; b; }` holds
				// one child per address. nodeVal kept
				// only the first of each.
				for _, k := range prop.Keys[1:] {
					vg.VirtualAddresses = append(vg.VirtualAddresses, k)
				}
				for _, child := range prop.Children {
					if v := child.Name(); v != "" {
						vg.VirtualAddresses = append(vg.VirtualAddresses, v)
					}
				}
			case "priority":
				if v := nodeVal(prop); v != "" {
					// #4573: only overwrite on a clean parse — see the
					// flat-set arm above (a swallowed Atoi would resign the
					// group at priority 0 on the lenient path).
					if n, err := strconv.Atoi(v); err == nil {
						vg.Priority = n
					}
				}
			case "preempt":
				vg.Preempt = true
				// Junos `preempt { hold-time <seconds>; }`. The
				// hierarchical / braced shape carries hold-time as a
				// child node; the structured flat-set replay may pack
				// it onto Keys[1:] (preempt, hold-time, <n>). Handle
				// both. Bare `preempt` leaves PreemptHoldTime 0
				// (immediate).
				if ht := prop.FindChild("hold-time"); ht != nil {
					if v := nodeVal(ht); v != "" {
						// #4573: keep the prior value on a bad parse (`_ =`).
						if n, err := strconv.Atoi(v); err == nil {
							vg.PreemptHoldTime = n
						}
					}
				} else if len(prop.Keys) >= 3 && prop.Keys[1] == "hold-time" {
					if n, err := strconv.Atoi(prop.Keys[2]); err == nil {
						vg.PreemptHoldTime = n
					}
				}
			case "accept-data":
				vg.AcceptData = true
			case "advertise-interval":
				if v := nodeVal(prop); v != "" {
					// #4573: keep the prior value on a bad parse (`_ =`).
					if n, err := strconv.Atoi(v); err == nil {
						vg.AdvertiseInterval = n
					}
				}
			case "authentication-type":
				vg.AuthType = nodeVal(prop)
			case "authentication-key":
				vg.AuthKey = Secret(nodeVal(prop))
			case "track-interface":
				// The interface name lives in Keys[1]
				// (NOT nodeVal — its Children[0]
				// fallback would misread the nested
				// priority-cost child as the name).
				if len(prop.Keys) >= 2 {
					trackIface = prop.Keys[1]
					trackIfaceSet = true
				}
				// Nested form (#1814): standard Junos
				// `track-interface <if> { priority-cost <n>; }`.
				if pc := prop.FindChild("priority-cost"); pc != nil {
					if v := nodeVal(pc); v != "" {
						if n, ok := parseTrackCost(v); ok {
							nestedTrackCost = n
							nestedTrackCostSet = true
						}
					}
				}
			case "track-priority-cost":
				if v := nodeVal(prop); v != "" {
					if n, ok := parseTrackCost(v); ok {
						siblingTrackCost = n
						siblingTrackCostSet = true
					}
				}
			}
		}
		if trackIfaceSet {
			vg.TrackInterface = trackIface
		}
		if siblingTrackCostSet {
			vg.TrackPriorityDelta = siblingTrackCost
		}
		if nestedTrackCostSet {
			// Nested wins over the legacy sibling,
			// independent of node order.
			vg.TrackPriorityDelta = nestedTrackCost
		}
	}
}

// validateVRRPTrackInterfaceAST walks the (group-expanded) AST and
// enforces the single-track-interface invariant per vrrp-group (#1814).
//
// Strict path (commit / commit-check, lenient=false): more than one
// track-interface statement inside a single vrrp-group is a hard
// compile error — single-interface tracking is what the runtime
// implements, and silently last-winsing the extras would hide it.
//
// Lenient path (load / peer-sync, lenient=true): the extra
// track-interface children are pruned IN PLACE (the tree is already a
// clone — same contract as sanitizeNodesControlChars) so the compiler
// deterministically sees only the FIRST, and a warning is returned.
//
// Shape-only warnings emitted on BOTH paths (the typed config cannot
// distinguish these post-compile):
//   - nested `priority-cost` AND legacy sibling `track-priority-cost`
//     both present (nested wins);
//   - an orphan `priority-cost` child directly under the vrrp-group
//     (only valid nested under track-interface).
func validateVRRPTrackInterfaceAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	for _, n := range nodes {
		nodePath := joinNodePath(prefix, n.Keys)
		if n.Name() == "vrrp-group" {
			// SECURITY (#5195, codex-177 A3-b2-F10): build the diagnostic path
			// from the group IDENTITY ONLY (`vrrp-group <id>`), never n.Keys — in
			// the Keys-packed spelling (`vrrp-group 1 authentication-key <secret>
			// track-interface X track-interface Y`) the node's Keys run carries
			// the authentication-key VALUE, so joinNodePath(prefix, n.Keys) would
			// ECHO the secret into the commit error / lenient warning (logs +
			// CLI). vrrpGroupIDKeys truncates to the value-free identity; `prefix`
			// is composed of ancestor container keys (interface/unit/family/
			// address) which carry no secret leaf value. Mirrors the identical
			// guard in validateVRRPAuthenticationAST.
			idPath := joinNodePath(prefix, vrrpGroupIDKeys(n))
			w, err := checkVRRPGroupTrackShape(n, idPath, lenient)
			warnings = append(warnings, w...)
			if err != nil {
				return nil, err
			}
		}
		w, err := validateVRRPTrackInterfaceAST(n.Children, nodePath, lenient)
		warnings = append(warnings, w...)
		if err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

// validateVRRPAuthenticationAST walks every vrrp-group node and rejects
// (strict) or drops-and-warns (lenient) a configured authentication-type /
// authentication-key. #4288: the native dataplane is RFC 5798 VRRPv3, which
// REMOVED authentication (VRRPv2 had it; v3 does not). The compiler parses the
// auth statements (nodeVal above), stores them on the VRRPGroup, and copies
// them into the VRRP instance (pkg/vrrp/vrrp.go), but the packet build/receive
// path never references them — the config is inert. Silently accepting it lets
// an operator believe adverts are authenticated when they are not: a rogue host
// on the segment can send higher-priority adverts and hijack mastership.
//
// Strict (commit / commit-check): REJECT the dead-security config so the
// operator is not misled into a false-security posture (#4288).
//
// Lenient (tolerant load / peer-sync, #5834): a WARN-BUT-STILL-ACTIVATE posture
// left a persisted or peer-synced auth group COMPILED — parseVRRPGroups below
// still built the VRRPGroup, pkg/vrrp instantiated it, and the group CLAIMED the
// VIP and exchanged UNAUTHENTICATED adverts even though the operator explicitly
// REQUIRED authentication. That is the exact false-security posture #4288 set
// out to close, only relocated to the load path. Fail-closed instead: DROP the
// auth-carrying vrrp-group node from the AST here (before parseVRRPGroups reads
// it) and warn loudly. The base interface address stays; only the VRRP VIP claim
// is dropped. The operator's intent (require auth) wins over availability (claim
// the VIP unauthenticated). This mirrors the CoS tolerant-path warn-and-drop for
// an unsupported-but-persisted entry (compiler_class_of_service.go) and honors
// #1960 no-brick (drop the one group, not the whole config). Mirrors
// validateVRRPTrackInterfaceAST's recursive vrrp-group walk; the AST mutation is
// seen by parseVRRPGroups because the pre-walk runs on the same tree before
// section compilation.
func validateVRRPAuthenticationAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	for _, n := range nodes {
		nodePath := joinNodePath(prefix, n.Keys)
		// Examine n's DIRECT vrrp-group children so a lenient prune can rebuild
		// n.Children (dropping the offending group). A vrrp-group is always a
		// child of a family inet/inet6 address node, so detecting it here (as a
		// child of n) covers every real config and gives us the parent handle
		// the prune needs.
		pruned := false
		kept := make([]*Node, 0, len(n.Children))
		for _, c := range n.Children {
			if c.Name() == "vrrp-group" {
				if leaf := vrrpAuthLeaf(c); leaf != "" {
					// SECURITY: build the message path from the group IDENTITY
					// ONLY (`vrrp-group <id>`), never c.Keys — in the Keys-packed
					// spelling (`vrrp-group 1 authentication-key <secret>;`) the
					// node's Keys run carries the authentication-key VALUE, so
					// joinNodePath(nodePath, c.Keys) would ECHO the secret into
					// the commit error / lenient warning (logs + CLI).
					// vrrpGroupIDKeys truncates to the value-free identity;
					// `nodePath` is composed of ancestor container keys
					// (interface/unit/family/address) which carry no secret leaf
					// value.
					idPath := joinNodePath(nodePath, vrrpGroupIDKeys(c))
					if !lenient {
						return nil, fmt.Errorf("%s: VRRP %s is configured but NOT enforced — "+
							"the dataplane is RFC 5798 VRRPv3, which removed authentication; "+
							"adverts are unauthenticated regardless, so a rogue host can hijack "+
							"mastership. Remove the authentication statement (#4288)",
							idPath, leaf)
					}
					warnings = append(warnings, fmt.Sprintf("%s: VRRP %s is configured but the "+
						"dataplane is RFC 5798 VRRPv3, which removed authentication; the group is "+
						"DROPPED (not activated) rather than claim the VIP with unauthenticated "+
						"adverts — the operator required authentication that the impl cannot honor. "+
						"Remove the authentication statement to activate the group (#4288/#5834)",
						idPath, leaf))
					pruned = true
					continue // drop this vrrp-group from the AST (fail-closed)
				}
			}
			kept = append(kept, c)
		}
		if pruned {
			n.Children = kept
		}
		w, err := validateVRRPAuthenticationAST(n.Children, nodePath, lenient)
		warnings = append(warnings, w...)
		if err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

// vrrpGroupIDKeys returns the value-free identity keys of a vrrp-group node —
// `["vrrp-group", "<id>"]` — dropping any trailing tokens that the Keys-packed
// spelling (`vrrp-group 1 authentication-key <secret>;`) folds onto the same
// Keys run. Used to build a diagnostic path that never echoes a leaf VALUE (the
// authentication-key is a secret; see validateVRRPAuthenticationAST). vrrp-group
// is `args: 1`, so the identity is exactly the first two keys.
func vrrpGroupIDKeys(n *Node) []string {
	if len(n.Keys) >= 2 {
		return n.Keys[:2]
	}
	return n.Keys
}

// vrrpAuthLeaf returns the first authentication leaf name
// ("authentication-type" or "authentication-key") present on a vrrp-group node,
// across BOTH the Keys-packed flat-set spelling (the token appears in the
// group node's Keys run) and the child-node / hierarchical spelling (a child
// node named authentication-type / authentication-key). Returns "" when no
// authentication statement is present.
func vrrpAuthLeaf(vg *Node) string {
	for _, k := range vg.Keys {
		if k == "authentication-type" || k == "authentication-key" {
			return k
		}
	}
	for _, c := range vg.Children {
		if name := c.Name(); name == "authentication-type" || name == "authentication-key" {
			return name
		}
	}
	return ""
}

// validateRenderUnsafeInterfaceNamesAST is the #9886 lenient-path gate on
// every interface-name position that reaches a systemd unit or a kernel
// rename: top-level `interfaces` and `bridge-domains` identity keys,
// `chassis device-map interface` logical names, and `fabric-options
// member-interfaces` references. It runs post-sanitize (#1798) and
// post-range-expansion (#4027) on the group-expanded tree, so the names it
// sees are exactly what section compilation would turn into device names —
// including apply-groups-inherited and range-expanded members.
//
// WHY DROP ON LENIENT, NOT HARD-ERROR. The strict commit path already rejects
// whitespace/control names at most of these positions (ValidateInterfaceName /
// ValidateBridgeDomainName / ValidateDeviceMapLogicalName via the schema
// walk), so this gate's strict arm is a backstop that fires only on a direct
// CompileConfig — except member-interfaces references, which the schema does
// not validate, where it IS the commit error. On the tolerant load / peer-sync
// path the name is USELESS but the rest of the config is not: a render-unsafe
// name can never have produced a correct unit (its intended device's kernel
// name contains no whitespace, so a multi-pattern [Match] Name= never matched
// it — it only ever claimed others). Hard-erroring the whole compile for one
// never-usable name would safe-state Load and alarm-loop SyncApply against a
// pre-gate primary (the loop store.go exists to forbid); dropping the name
// with a loud warning instead matches the #5834 VRRP-auth shape for a
// fail-closed security property on lenient, and the render belts (networkd
// Apply, linksetup .link guard) stay behind it for every route that does not
// compile (direct Apply callers).
//
// WHY THE RENDER CONTRACT, NOT FULL VALIDATION. The check is
// rendersafe.SafeInterfaceName — one match-list pattern plus control-free —
// not the full allowlist: lenient must not refuse to boot pre-gate values
// that still work (#6564/#1960), so UTF-8 single-pattern names pass and the
// glob and leading-dash classes stay in #10089's and #9885's lanes. Post-scrub
// keys are control-free, so this equals the one-pattern check on every
// reachable input; the uniform notion keeps compile and render from drifting
// about what "unsafe" means.
//
// WHY REFS ARE STRIPPED, NOT JUST DROPPED AT THE SOURCE. Pruning a poisoned
// member does not remove other members' references to it, and the dataplane
// emits fabric bond-member rows WITHOUT a kernel-existence check
// (buildFabricBondModels) — so a surviving `member-interfaces "ge 0"` would
// resurrect the dropped identity as a refused-but-partially-applied row. The
// gate strips render-unsafe references from surviving members (mirroring
// plainListValues' read pattern across all five member-interfaces spellings),
// which also covers references to never-defined poisoned names. Zone-member
// references are NOT stripped (they emit no rows — the #4515 existence gate
// downgrades them to a warning on lenient). Unexpanded interface-range stubs
// (the #8438 declined-expansion shape) never materialize members, so their
// `member` statements have no render path and are not inspected.
func validateRenderUnsafeInterfaceNamesAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	for _, n := range nodes {
		switch n.Name() {
		case "interfaces", "bridge-domains":
			w, err := pruneUnsafeIdentityMembers9886(n, lenient)
			warnings = append(warnings, w...)
			if err != nil {
				return nil, err
			}
		case "chassis":
			w, err := pruneUnsafeDeviceMapEntries9886(n, lenient)
			warnings = append(warnings, w...)
			if err != nil {
				return nil, err
			}
		}
	}
	// Fabric references are stripped AFTER member pruning, over the survivors:
	// a reference to a dropped member and a reference to a never-defined
	// poisoned name are the same sink, and stripping by predicate (not by
	// dropped-set) covers both without threading state between passes.
	for _, n := range nodes {
		if n.Name() != "interfaces" {
			continue
		}
		for _, c := range n.Children {
			w, err := stripUnsafeFabricMemberRefs9886(c, lenient)
			warnings = append(warnings, w...)
			if err != nil {
				return nil, err
			}
		}
	}
	return warnings, nil
}

// pruneUnsafeIdentityMembers9886 drops top-level `interfaces` / `bridge-domains`
// members whose identity key is not render-safe. Strict: hard error. Lenient:
// prune the member node + loud warning (#5834 shape).
func pruneUnsafeIdentityMembers9886(n *Node, lenient bool) ([]string, error) {
	kind := "interface"
	if n.Name() == "bridge-domains" {
		kind = "bridge-domain"
	}
	var warnings []string
	pruned := false
	kept := make([]*Node, 0, len(n.Children))
	for _, c := range n.Children {
		if len(c.Keys) == 0 || rendersafe.SafeInterfaceName(c.Keys[0]) {
			kept = append(kept, c)
			continue
		}
		name := c.Keys[0]
		sink := "[Match] Name="
		if kind == "bridge-domain" {
			sink = "[Match] Name= (via the br-" + name + " bridge device)"
		}
		if !lenient {
			return nil, fmt.Errorf("%s %q: %s name is not render-safe for %s — "+
				"systemd reads it as a whitespace-separated list of globs, so this name "+
				"would claim interfaces other than its own device. Rename the %s (#9886)",
				n.Name(), name, kind, sink, kind)
		}
		warnings = append(warnings, fmt.Sprintf("%s %q: %s name is not render-safe for %s — "+
			"systemd would read it as a whitespace-separated list claiming "+
			"other interfaces, so the member is DROPPED (not configured). The name may "+
			"have been rewritten by the lenient control-character sanitize (#1798); "+
			"rename the %s and commit to restore it (#9886)", n.Name(), name, kind, sink, kind))
		pruned = true
		continue // drop this member from the AST (fail-closed, #5834 shape)
	}
	if pruned {
		n.Children = kept
	}
	return warnings, nil
}

// pruneUnsafeDeviceMapEntries9886 drops `chassis device-map interface` entries
// whose logical name is not render-safe. The logical name becomes a .link
// [Link] Name=, a file name, and a kernel rename target, so a poisoned entry
// reaches the linksetup writer on the tolerant path (where the schema
// validator only warns). Instance shapes mirror bracketedGroupInstances8794 +
// namedInstances exactly: Keys[1:] fan-out with children, Keys[1] alone, or
// named children — so the gate prunes exactly what the compiler would read.
func pruneUnsafeDeviceMapEntries9886(chassis *Node, lenient bool) ([]string, error) {
	dmNode := chassis.FindChild("device-map")
	if dmNode == nil {
		return nil, nil
	}
	var warnings []string
	pruned := false
	kept := make([]*Node, 0, len(dmNode.Children))
	for _, c := range dmNode.Children {
		if c.Name() != "interface" {
			kept = append(kept, c)
			continue
		}
		switch {
		case len(c.Keys) >= 3 && len(c.Children) > 0:
			// Bracket fan-out: every Keys[1:] token is an instance.
			var names []string
			dropped := false
			for _, nm := range c.Keys[1:] {
				if rendersafe.SafeInterfaceName(nm) {
					names = append(names, nm)
					continue
				}
				if !lenient {
					return nil, fmt.Errorf("chassis device-map interface %q: logical name "+
						"is not render-safe for [Link] Name= — rename the entry (#9886)", nm)
				}
				warnings = append(warnings, deviceMapDropWarning9886(nm))
				dropped = true
			}
			if len(names) == 0 {
				pruned = true
				continue // all instances dropped: remove the node
			}
			if dropped {
				c.Keys = append([]string{c.Keys[0]}, names...)
				pruned = true
			}
			kept = append(kept, c)
		case len(c.Keys) >= 2:
			// Single instance: Keys[1] is the name (Keys[2:], if any, is
			// unread by the compiler and left alone, exactly like it).
			if rendersafe.SafeInterfaceName(c.Keys[1]) {
				kept = append(kept, c)
				continue
			}
			if !lenient {
				return nil, fmt.Errorf("chassis device-map interface %q: logical name "+
					"is not render-safe for [Link] Name= — rename the entry (#9886)", c.Keys[1])
			}
			warnings = append(warnings, deviceMapDropWarning9886(c.Keys[1]))
			pruned = true
			continue // drop this entry from the AST
		default:
			// Flat-set children shape: each child's Keys[0] is an instance.
			cpruned := false
			ckept := make([]*Node, 0, len(c.Children))
			for _, sub := range c.Children {
				if len(sub.Keys) == 0 || rendersafe.SafeInterfaceName(sub.Keys[0]) {
					ckept = append(ckept, sub)
					continue
				}
				if !lenient {
					return nil, fmt.Errorf("chassis device-map interface %q: logical name "+
						"is not render-safe for [Link] Name= — rename the entry (#9886)", sub.Keys[0])
				}
				warnings = append(warnings, deviceMapDropWarning9886(sub.Keys[0]))
				cpruned = true
			}
			if cpruned {
				c.Children = ckept
				pruned = true
			}
			kept = append(kept, c)
		}
	}
	if pruned {
		dmNode.Children = kept
	}
	return warnings, nil
}

// deviceMapDropWarning9886 is the loud lenient warning for a pruned device-map
// entry. The sink differs from the interfaces members (rename target + .link
// file, not a match list), so it gets its own message.
func deviceMapDropWarning9886(name string) string {
	return fmt.Sprintf("chassis device-map interface %q: logical name is not render-safe "+
		"for [Link] Name= — it would fail the kernel rename or poison the .link file, "+
		"so the entry is DROPPED (the NIC keeps its kernel name). The name may have "+
		"been rewritten by the lenient control-character sanitize (#1798); rename the "+
		"entry and commit to restore it (#9886)", name)
}

// stripUnsafeFabricMemberRefs9886 removes render-unsafe values from one
// surviving interfaces member's `fabric-options member-interfaces` statements.
// Values are read exactly where plainListValues reads them (node Keys[1:] plus
// every descendant's Keys, recursively), so the strip covers all five spellings
// the fabricMemberValues comment documents — including the grandchild quirk —
// and nothing the compiler would not read. Strict: hard error (this IS the
// commit error — the schema does not validate these values). Lenient: strip +
// loud warning.
func stripUnsafeFabricMemberRefs9886(member *Node, lenient bool) ([]string, error) {
	if len(member.Keys) == 0 {
		return nil, nil
	}
	foNode := member.FindChild("fabric-options")
	if foNode == nil {
		return nil, nil
	}
	var warnings []string
	for _, miNode := range foNode.FindChildren("member-interfaces") {
		stripped := filterUnsafeFabricMemberKeys9886(miNode, true)
		if len(stripped) == 0 {
			continue
		}
		quoted := make([]string, 0, len(stripped))
		for _, s := range stripped {
			quoted = append(quoted, fmt.Sprintf("%q", s))
		}
		if !lenient {
			return nil, fmt.Errorf("interfaces %q fabric-options member-interfaces: member "+
				"reference %s is not render-safe for [Match] Name= — the bond-member row it "+
				"would emit claims other interfaces. Rename the member (#9886)",
				member.Keys[0], strings.Join(quoted, ", "))
		}
		warnings = append(warnings, fmt.Sprintf("interfaces %q fabric-options member-interfaces: "+
			"member reference %s is not render-safe for [Match] Name= — the bond-member row "+
			"it would emit claims other interfaces, so the reference is STRIPPED (not "+
			"enslaved). Rename the member and commit to restore it (#9886)",
			member.Keys[0], strings.Join(quoted, ", ")))
	}
	return warnings, nil
}

// filterUnsafeFabricMemberKeys9886 removes render-unsafe tokens from n's Keys
// (skipping Keys[0] at the top node, which is the "member-interfaces" keyword
// itself) and recurses into every descendant exactly like plainListValues'
// walk. It returns the stripped values; Keys slices are rewritten only when
// something was stripped.
func filterUnsafeFabricMemberKeys9886(n *Node, top bool) []string {
	var stripped []string
	start := 0
	if top {
		start = 1
	}
	if len(n.Keys) > start {
		kept := make([]string, 0, len(n.Keys))
		kept = append(kept, n.Keys[:start]...)
		changed := false
		for _, k := range n.Keys[start:] {
			if k != "" && !rendersafe.SafeInterfaceName(k) {
				stripped = append(stripped, k)
				changed = true
				continue
			}
			kept = append(kept, k)
		}
		if changed {
			n.Keys = kept
		}
	}
	for _, c := range n.Children {
		stripped = append(stripped, filterUnsafeFabricMemberKeys9886(c, false)...)
	}
	return stripped
}

// parseTrackCost parses a priority-cost value, returning 0 (tracking
// has no effect) for anything outside the schema's 1..254 range — a
// negative cost would RAISE priority on link-down (Codex review on PR
// #1821). The AST pre-walk rejects out-of-range values on strict
// commits and warns on lenient loads; this keeps the lenient compile
// consistent with that warning.
func parseTrackCost(v string) (int, bool) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 254 {
		return 0, false
	}
	return n, true
}

// checkVRRPGroupTrackShape applies the #1814 track-interface shape
// checks to a single vrrp-group node. See validateVRRPTrackInterfaceAST.
func checkVRRPGroupTrackShape(vg *Node, nodePath string, lenient bool) ([]string, error) {
	var warnings []string
	// Keys-packed compact spelling (Codex review on PR #1821): a
	// hierarchical leaf like `vrrp-group 1 track-interface ge-0/0/1
	// track-interface ge-0/0/2;` packs duplicates into the node's own
	// Keys, bypassing the child-node count below. Count those too; the
	// compiler's keys walk is first-wins, so lenient semantics match.
	keysPacked := 0
	for _, k := range vg.Keys {
		if k == "track-interface" {
			keysPacked++
		}
	}
	tracks := vg.FindChildren("track-interface")
	if total := keysPacked + len(tracks); total > 1 {
		if !lenient {
			return nil, fmt.Errorf("%s: %d track-interface statements; only one tracked interface is supported per vrrp-group", nodePath, total)
		}
		if keysPacked > 0 {
			// Child-node duplicates are warned by the prune below; the
			// Keys-packed spelling needs its own warning (the compiler
			// keys walk is first-wins).
			warnings = append(warnings, fmt.Sprintf("%s: %d track-interface statements; keeping the first and ignoring the rest (#1814)", nodePath, total))
		}
	}
	if len(tracks) > 1 {
		if !lenient {
			return nil, fmt.Errorf("%s: %d track-interface statements; only one tracked interface is supported per vrrp-group", nodePath, len(tracks))
		}
		// First-wins: prune every track-interface child after the first.
		kept := false
		pruned := vg.Children[:0]
		for _, c := range vg.Children {
			if c.Name() == "track-interface" {
				if kept {
					continue
				}
				kept = true
			}
			pruned = append(pruned, c)
		}
		vg.Children = pruned
		warnings = append(warnings, fmt.Sprintf("%s: %d track-interface statements; keeping the first (%s) and ignoring the rest (#1814)", nodePath, len(tracks), nodeVal(tracks[0])))
		tracks = tracks[:1]
	}
	if len(tracks) == 1 && tracks[0].FindChild("priority-cost") != nil && vg.FindChild("track-priority-cost") != nil {
		warnings = append(warnings, fmt.Sprintf("%s: both nested track-interface priority-cost and legacy track-priority-cost are configured; the nested priority-cost wins", nodePath))
	}
	if vg.FindChild("priority-cost") != nil {
		warnings = append(warnings, fmt.Sprintf("%s: priority-cost is only valid nested under track-interface; this statement has no effect", nodePath))
	}
	// Range-validate every cost spelling (Codex review on PR #1821):
	// the schema advertises <1..254> but nothing enforced it, and a
	// negative cost would RAISE priority on link-down. Strict commit
	// rejects; lenient load warns (the compiler clamp keeps runtime
	// safe either way via getPriority's [1,254] clamp, but a raised
	// priority is a semantic inversion worth refusing).
	costCheck := func(val, spelling string) error {
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 || n > 254 {
			if !lenient {
				return fmt.Errorf("%s: %s %q out of range; must be 1..254", nodePath, spelling, val)
			}
			warnings = append(warnings, fmt.Sprintf("%s: %s %q out of range (1..254); ignoring tracking cost", nodePath, spelling, val))
		}
		return nil
	}
	// Validate EVERY occurrence, not just the first (Codex confirm
	// round on PR #1821): a duplicate invalid child after a valid one
	// must not bypass the strict reject.
	for _, tr := range tracks {
		for _, pc := range tr.FindChildren("priority-cost") {
			if len(pc.Keys) > 1 {
				if err := costCheck(pc.Keys[1], "priority-cost"); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, tpc := range vg.FindChildren("track-priority-cost") {
		if len(tpc.Keys) > 1 {
			if err := costCheck(tpc.Keys[1], "track-priority-cost"); err != nil {
				return nil, err
			}
		}
	}
	for i, k := range vg.Keys {
		if (k == "track-priority-cost" || k == "priority-cost") && i+1 < len(vg.Keys) {
			if err := costCheck(vg.Keys[i+1], k); err != nil {
				return nil, err
			}
		}
	}
	return warnings, nil
}

// vrrpTrackConfigWarnings derives operator-visible interface-tracking
// warnings from the compiled typed config (#1814). Emitted on both the
// strict and lenient paths so a tracking misconfiguration is never a
// silent no-op:
//   - track-interface without any priority-cost (nested or legacy
//     sibling) has no effect;
//   - track-priority-cost without track-interface has no effect;
//   - priority 255 marks the address owner — the runtime ignores
//     tracking there (an owner stepping down while still holding the
//     address invites duplicate-IP conflicts).
//
// Iteration is sorted at every level so warning order is deterministic.
func vrrpTrackConfigWarnings(cfg *Config) []string {
	var warnings []string
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			groupKeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				groupKeys = append(groupKeys, k)
			}
			sort.Strings(groupKeys)
			for _, gk := range groupKeys {
				vg := unit.VRRPGroups[gk]
				loc := fmt.Sprintf("interfaces %s unit %d vrrp-group %d", ifName, un, vg.ID)
				switch {
				case vg.TrackInterface != "" && vg.TrackPriorityDelta == 0:
					warnings = append(warnings, fmt.Sprintf("%s: track-interface %s without priority-cost has no effect", loc, vg.TrackInterface))
				case vg.TrackInterface == "" && vg.TrackPriorityDelta != 0:
					warnings = append(warnings, fmt.Sprintf("%s: track-priority-cost without track-interface has no effect", loc))
				case vg.TrackInterface != "" && vg.Priority == 255:
					warnings = append(warnings, fmt.Sprintf("%s: interface tracking is ignored for the address owner (priority 255)", loc))
				}
			}
		}
	}
	return warnings
}

// ifaceDDNSStringProps are the per-interface `dynamic-dns` leaves that carry a
// string value (everything except the integer `ttl`). Used by
// compileInterfaceDynamicDNS's walker to recognize a "<leaf> <value>" pair at
// any depth regardless of the AST shape (#2691 P2).
var ifaceDDNSStringProps = map[string]bool{
	"provider":       true,
	"hostname":       true,
	"address-source": true,
	"source-address": true,
}

// compileInterfaceDynamicDNS converts an interface family node's `dynamic-dns`
// subtree into a typed *InterfaceDynamicDNSConfig (Surface A, #2691 P2). The
// afNode passed in is the `family inet`/`family inet6` node; this finds the
// `dynamic-dns` block under it (as a child node in the hierarchical shape, or
// packed into the family node's Keys in the flat-set shape) and walks it. It
// handles BOTH AST shapes the same way compileDHCPDynamicDNS does. Returns nil
// when there is no dynamic-dns binding (so an interface with no Surface A
// config compiles to a nil field — byte-for-byte today's behaviour).
func compileInterfaceDynamicDNS(afNode *Node) *InterfaceDynamicDNSConfig {
	// Locate the subtree root. Hierarchical: a child node named dynamic-dns.
	// Flat-set: the token "dynamic-dns" appears inside afNode.Keys (the family
	// node), with the binding's leaves following it / nested as children.
	var root *Node
	if c := afNode.FindChild("dynamic-dns"); c != nil {
		root = c
	} else {
		for i, k := range afNode.Keys {
			if k == "dynamic-dns" {
				// Wrap the tail of the family node's Keys (from dynamic-dns on) so
				// the walker reads them; the family node's children are walked too.
				root = &Node{Keys: afNode.Keys[i:], Children: afNode.Children}
				break
			}
		}
	}
	if root == nil {
		return nil
	}

	props := map[string]string{}
	var walk func(n *Node, isRoot bool)
	walk = func(n *Node, isRoot bool) {
		start := 0
		if isRoot {
			start = 1 // skip the "dynamic-dns" identifier itself
		}
		for i := start; i < len(n.Keys); i++ {
			k := n.Keys[i]
			switch {
			case k == "ttl" && i+1 < len(n.Keys):
				if _, ok := props["ttl"]; !ok {
					props["ttl"] = n.Keys[i+1]
				}
				i++
			case ifaceDDNSStringProps[k] && i+1 < len(n.Keys):
				if _, ok := props[k]; !ok {
					props[k] = n.Keys[i+1]
				}
				i++
			}
		}
		for _, c := range n.Children {
			walk(c, false)
		}
	}
	walk(root, true)

	d := &InterfaceDynamicDNSConfig{
		Provider:      props["provider"],
		Hostname:      props["hostname"],
		AddressSource: props["address-source"],
		SourceAddress: props["source-address"],
	}
	if v := props["ttl"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			d.TTLSeconds = n
		}
	}
	// Empty block -> treat as absent (no Surface A binding).
	if d.Provider == "" && d.Hostname == "" && d.AddressSource == "" &&
		d.SourceAddress == "" && d.TTLSeconds == 0 {
		return nil
	}
	return d
}

// fabricMemberValues returns every member interface name carried by one
// `fabric-options member-interfaces` node.
//
// The names reach the compiler on the node's own Keys, on its children's Keys,
// or both, depending on how the config was authored (#6694 / the #2419
// multi-value-leaf class):
//
//   - hierarchical block      `member-interfaces { a; b; }`
//     → Keys=["member-interfaces"], one leaf child per name
//   - hierarchical bracket    `member-interfaces [ a b ];`
//     → Keys=["member-interfaces","a","b"], no children
//   - hierarchical single     `member-interfaces a;`
//     → Keys=["member-interfaces","a"], no children
//   - flat-set repeated       `set ... member-interfaces a` (x2)
//     → Keys=["member-interfaces"], one leaf child per name
//   - flat-set bracket        `set ... member-interfaces [ a b ]`
//     → Keys=["member-interfaces"], ONE child whose Keys hold every name
//
// The last shape is why firewallMatchValues is not enough here: it reads only
// Keys[0] of each child, so it would keep the first name of a flat-set bracket
// list and drop the rest. Descend the whole subtree and take every key.
//
// `member-interfaces` has no per-member option keywords in Junos, so unlike
// the NTP server list there is no trailing-token ambiguity to resolve — every
// non-empty token below the node is a member name.
//
// #7126: the mechanism is not specific to this leaf — `routing-options
// rib-groups <g> import-rib` and `event-options policy <p> events` are the same
// plain value list read the same way, and had the same flat-set-bracket drop.
// The implementation therefore lives in ast.go as plainListValues and is shared
// by all three; a divergence between them would always be a bug, so there is
// one body rather than three copies. This wrapper keeps the leaf-specific
// argument above attached to the leaf it argues about.
func fabricMemberValues(n *Node) []string {
	return plainListValues(n)
}

// packedTunnelRoutingInstance8936 reads the instance name out of a
// BRACE-ELIDED `tunnel { routing-instance destination <name>; }` and reports
// whether the node has that packed shape at all. For every other shape it
// returns ("", false), so the callers' existing branches are unchanged.
//
// The braced spelling gives `routing-instance` a CHILD named `destination`, and
// the callers read it with FindChild. The elided spelling packs the whole tail
// onto the node's own Keys -- ["routing-instance", "destination", "<name>"] --
// so there is no child, FindChild returns nil, and the fallback nodeVal(prop)
// returns Keys[1], which is the literal keyword "destination".
//
// That is not a dropped value, it is a WRONG one: the tunnel compiled with
// RoutingInstance="destination", binding it to a routing-instance that does not
// exist, while the operator's actual instance name was discarded. A missing
// value leaves the tunnel unbound and visible as unconfigured; this produced a
// plausible-looking binding that silently resolves to nothing (#8936).
//
// The site was classed `partial` in the #8690 register on the strength of
// "something consumed the tail". Something did -- and it was this defect, not a
// reader entitled to it. Fixing the consumer is what makes the two spellings
// agree; no scope admission is involved.
//
// #9172 (V044): the packed shape with NO name -- `routing-instance
// destination;` -- is still this shape, and the shape is what callers branch
// on. This used to require three keys, so the bare spelling fell through to the
// callers' nodeVal fallback, which returned Keys[1]: the literal keyword
// "destination" again, the exact wrong binding #8936 fixed for the named
// spelling. The braced `routing-instance { destination; }` compiles to no
// binding and is refused at commit; the packed bare spelling now compiles to no
// binding too, and the schema node's packedTail opt-in gives it the same
// commit-time refusal.
func packedTunnelRoutingInstance8936(prop *Node) (string, bool) {
	if prop == nil || len(prop.Keys) < 2 || prop.Keys[1] != "destination" {
		return "", false
	}
	if len(prop.Keys) < 3 {
		return "", true
	}
	return prop.Keys[2], true
}
