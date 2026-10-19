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
	"no-preempt":          true,
	"accept-data":         true,
	"advertise-interval":  true,
	"authentication-type": true,
	"authentication-key":  true,
	"track-interface":     true,
	"track":               true,
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

// vlanTagsOuterValue15035 extracts the raw value token(s) following the
// `outer` keyword of a `vlan-tags` node, across every AST shape:
// packed Keys (`vlan-tags outer 100`), hierarchical children
// (`vlan-tags { outer 100; }`), and the one-deeper form
// (`vlan-tags { outer { 100; } }`). Returns (nil, false) when the node
// carries no `outer` keyword at all. #15035 helper: compileInterfaces is
// the only consumer; the gates keep their own positive-tag predicates.
func vlanTagsOuterValue15035(n *Node) ([]string, bool) {
	for i, k := range n.Keys {
		if k == "outer" {
			return n.Keys[i+1:], true
		}
	}
	for _, c := range n.Children {
		if len(c.Keys) > 0 && c.Keys[0] == "outer" {
			if len(c.Keys) > 1 {
				return c.Keys[1:], true
			}
			// `outer { 100; }`: the value is the grandchild's key.
			var vals []string
			for _, g := range c.Children {
				vals = append(vals, g.Keys...)
			}
			return vals, true
		}
	}
	return nil, false
}

// parseVlanTagsOuter15035 parses a `vlan-tags outer` value into a VID.
// A TPID-prefixed value (`0x88a8.100`, the Junos TPID.VID form) names a
// tag protocol the single-tag dataplane cannot represent, so it is
// rejected rather than compiled to the bare VID. Otherwise the value
// shares the `vlan-id` canonical-digits 0..4094 contract (#9899).
func parseVlanTagsOuter15035(raw string) (uint64, error) {
	if strings.Contains(raw, ".") {
		return 0, fmt.Errorf("TPID-prefixed vlan-tags outer value %q is not supported: the dataplane enforces a single 802.1Q tag; configure `vlan-id` or a bare `vlan-tags outer <vid>` instead (#15035)", raw)
	}
	n, err := parseInterfaceNumeric9899(raw, 0, 4094)
	if err != nil {
		return 0, fmt.Errorf("vlan-tags outer %s", err.Error())
	}
	return n, nil
}

func compileInterfaces(node *Node, ifaces *InterfacesConfig, opts compileOpts, warnings *[]string) error {
	// #6782: reth interfaces whose redundancy-group token was present but
	// unusable. Only ever populated on the tolerant path — the strict compile
	// fails in runPreWalkGates before compileInterfaces runs.
	var invalidRethRG map[string]bool
	for _, child := range node.Children {
		interfaceSchema := interfaceSchema9792()
		ifLeaves := expandResolvingRun9792(child, interfaceSchema) // #9792: expand a lenient-path packed run (#9235).
		// #14442: the interface node's own packed tail (`ge-0/0/0
		// description "uplink" disable;`, or the same run nested under a
		// braced first leaf) carries every interface-level leaf on Keys
		// with no Children. packedBody expands that tail through the
		// schema so braced, packed and flat-set spellings compile
		// identically; reading raw child below dropped a non-first
		// `disable` (and every other non-first leaf) and, for a packed
		// interface with no bandwidth, skipped the interface entirely.
		// All interface-level reads go through ifBody; only authored-
		// unit detection and the IsLeaf guard consult the raw child,
		// and the guard now also honours a leaf exposed by expansion.
		ifBody := packedBody(ifLeaves, interfaceSchema)
		bandwidthNode := ifBody.FindChild("bandwidth")
		if child.IsLeaf && bandwidthNode == nil && len(ifBody.Children) == 0 {
			continue
		}
		// #14436 (DR17-H7): ifBody alone misses a unit packed onto the
		// RAW child's Keys when ifLeaves run-expansion rewrote Children
		// (packedBody then has no tail to synthesise from). Expand the
		// raw child too and merge statements it alone synthesises into
		// ifBody's view, keyed by full KeyPath so distinct units (unit 0
		// vs unit 1 in one run) merge while true duplicates do not.
		if ifRaw := packedBody(child, interfaceSchema); ifRaw != nil && ifRaw != child {
			have := make(map[string]bool, len(ifBody.Children))
			for _, c := range ifBody.Children {
				have[c.KeyPath()] = true
			}
			merged := append([]*Node(nil), ifBody.Children...)
			for _, c := range ifRaw.Children {
				if !have[c.KeyPath()] {
					merged = append(merged, c)
				}
			}
			if len(merged) != len(ifBody.Children) {
				clone := *ifBody
				clone.Children = merged
				ifBody = &clone
			}
		}
		ifName := child.Name()
		ifc := &InterfaceConfig{
			Name:  ifName,
			Units: make(map[int]*InterfaceUnit),
			// #9899 P2: record unit authorship BEFORE the quarantine loop
			// below can skip every unit. An interface that authored units but
			// kept none is quarantined, not unitless — the emitter must not
			// fall back to the bare-name endpoint.
			AuthoredUnits: len(ifBody.FindChildren("unit")) > 0,
		}

		// Check for description
		if descNode := ifBody.FindChild("description"); descNode != nil {
			ifc.Description = nodeVal(descNode)
		}
		// Interface-level MTU
		if mtuNode := ifBody.FindChild("mtu"); mtuNode != nil {
			if v := nodeVal(mtuNode); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					ifc.MTU = n
				}
			}
		}

		// Speed tokens are typed in the schema and rechecked here for callers
		// that compile directly. Tolerant loads discard an unsupported legacy
		// token with a warning so one bad value cannot block activation.
		if speedNode := ifBody.FindChild("speed"); speedNode != nil {
			raw := nodeVal(speedNode)
			speed := strings.ToLower(strings.TrimSpace(raw))
			if speed == "auto" {
				ifc.Speed = speed
			} else if _, ok := InterfaceSpeedMbps(speed); ok {
				ifc.Speed = speed
			} else {
				msg := fmt.Sprintf("interfaces %s speed %q: %v", ifName, raw, ValidateInterfaceSpeed(raw, nil))
				if !opts.lenientInterfaceSpeed {
					return fmt.Errorf("%s", msg)
				}
				if warnings != nil {
					*warnings = append(*warnings, msg+"; ignoring invalid speed")
				}
			}
		}
		if duplexNode := ifBody.FindChild("duplex"); duplexNode != nil {
			duplex := nodeVal(duplexNode)
			switch duplex {
			case "full", "half", "auto":
				ifc.Duplex = duplex
			default:
				msg := fmt.Sprintf("interfaces %s duplex %q: expected one of full, half, or auto", ifName, duplex)
				if !opts.lenientInterfaceDuplex {
					return fmt.Errorf("%s", msg)
				}
				if warnings != nil {
					*warnings = append(*warnings, msg+"; ignoring invalid value on tolerant load (#11824)")
				}
			}
		}
		if ifBody.FindChild("disable") != nil {
			ifc.Disable = true
		}

		// Interface bandwidth (bits per second). The interface node's own
		// packed tail is distinct from #9792's nested-run expansion; consume it
		// through the schema so braced and brace-elided bandwidth agree.
		if bwNode := bandwidthNode; bwNode != nil {
			v := nodeVal(bwNode)
			if bps, err := parseBandwidthBpsStrict(v); err != nil {
				path := "interfaces " + ifName + " bandwidth"
				if !opts.lenientInterfaceBandwidth {
					return fmt.Errorf("%s: %w", path, err)
				}
				if warnings != nil {
					*warnings = append(*warnings, fmt.Sprintf("%s: %v; ignoring invalid bandwidth", path, err))
				}
			} else {
				ifc.Bandwidth = bps
			}
		}

		// Check for vlan-tagging flag
		if ifBody.FindChild("vlan-tagging") != nil {
			ifc.VlanTagging = true
		}

		// Check for flexible-vlan-tagging flag (QinQ)
		if ifBody.FindChild("flexible-vlan-tagging") != nil {
			ifc.FlexibleVlanTagging = true
		}

		// #4308: typed interface settings. Native VLAN ingress uses a unique
		// vlan-id unit when present (#11434); otherwise the dataplane rejects
		// untagged traffic, so warn after compiling the units below (#12248).
		// The remaining ARP/addressing knobs retain their accepted-only advisory.
		if nvNode := ifBody.FindChild("native-vlan-id"); nvNode != nil {
			if v := nodeVal(nvNode); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					ifc.NativeVlanID = n
				}
			}
		}
		if ifBody.FindChild("gratuitous-arp-reply") != nil {
			ifc.GratuitousARPReply = true
		}
		if ifBody.FindChild("no-gratuitous-arp-request") != nil {
			ifc.NoGratuitousARPRequest = true
		}

		// Check for encapsulation
		if encapNode := ifBody.FindChild("encapsulation"); encapNode != nil {
			ifc.Encapsulation = nodeVal(encapNode)
		}

		// Check for gigether-options redundant-parent and 802.3ad LAG member
		if goNode := ifBody.FindChild("gigether-options"); goNode != nil {
			goNode = expandResolvingRun9792(goNode, gigetherOptionsSchema9792()) // #9792: expand a lenient-path packed run (#9235).
			if rpNode := goNode.FindChild("redundant-parent"); rpNode != nil {
				ifc.RedundantParent = nodeVal(rpNode)
			}
			if adNode := goNode.FindChild("802.3ad"); adNode != nil {
				ifc.LAGParent = nodeVal(adNode)
			}
		}

		// Check for aggregated-ether-options (LAG/ae interface)
		if aeoNode := ifBody.FindChild("aggregated-ether-options"); aeoNode != nil {
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
		// #14441: expand the elided spelling
		// `redundant-ether-options redundancy-group 1;`, whose tail sits on
		// the reo node's own Keys with no Children, exactly as the
		// gigether/aggregated siblings above do for their packed runs.
		// Without the expansion FindChild sees no child and the group stays
		// 0, so the reth reads as an ordinary interface on both nodes.
		if reoNode := ifBody.FindChild("redundant-ether-options"); reoNode != nil {
			reoNode = expandResolvingRun9792(reoNode, redundantEtherOptionsSchema9792())
			reoNode = packedBody(reoNode, redundantEtherOptionsSchema9792())
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
		if foNode := ifBody.FindChild("fabric-options"); foNode != nil {
			for _, miNode := range foNode.FindChildren("member-interfaces") {
				ifc.FabricMembers = append(ifc.FabricMembers, fabricMemberValues(miNode)...)
			}
			if len(ifc.FabricMembers) > 0 {
				ifc.BondMode = "active-backup"
			}
		}

		// Check for interface-level tunnel configuration.
		// #14450: iterate EVERY `tunnel` sibling, not FindChild first-only —
		// a second block's WireGuard config was dropped, installing
		// plaintext GRE. Scalars last-win across blocks; peers accumulate.
		tunnelNodes := ifBody.FindChildren("tunnel")
		skipIface9899 := false
		if len(tunnelNodes) > 0 {
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
			// #13215/#14440: retain values from braced scalar blocks before
			// tunnelRunChildren9156 flattens their body into sibling nodes.
			for _, tunnelNode := range tunnelNodes {
				applyTunnelBracedScalars14440(tc, tunnelNode)
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
					case "mode":
						if v := nodeVal(prop); v != "" {
							tc.Mode = v
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
					case "clear-dont-fragment-bit":
						tc.ClearDontFragmentBit = true
					}
					if skipIface9899 {
						break
					}
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

		for _, unitInst := range namedInstances(ifBody.FindChildren("unit")) {
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
			// #15035: lenient numeric quarantine flag, shared by the
			// tunnel reader and the vlan/vlan-tags readers below.
			skipUnit9899 := false

			// #14435 (DR17-H6): unpack the unit node's own Keys tail.
			// `unit 0 point-to-point family inet { ... }` (and the
			// `tunnel ...`-first form) is ONE node whose Children are the
			// family's contents, not a `family` child — FindChild /
			// FindChildren("family") below would see nothing and the whole
			// family subtree (addresses + filters) would be dropped while
			// the unit still gets a zoned snapshot row (fail-open).
			// packedBody returns the original node when there is no tail
			// (braced twin and bare `unit 0 point-to-point;` unchanged).
			unitNode := packedBody(unitInst.node,
				schemaForPath("interfaces", "x", "unit"))
			if unitNode == nil {
				unitNode = unitInst.node
			}

			// Parse description on unit
			if descNode := unitNode.FindChild("description"); descNode != nil {
				unit.Description = nodeVal(descNode)
			}

			// #14575: unit-level `disable` — the Junos per-logical-unit
			// admin-down. packedBody above has already expanded a packed
			// tail (`unit 0 disable family inet ...`), so braced, packed
			// and flat-set spellings all land here as a `disable` child.
			// Honoured end to end: the userspace snapshot marks the unit
			// AdminDisabled with no addresses, and the networkd/legacy
			// address planners skip it. Interface-level `disable`
			// (ifc.Disable) is unchanged and still disables every unit.
			if unitNode.FindChild("disable") != nil {
				unit.Disable = true
			}

			// Parse point-to-point flag
			if unitNode.FindChild("point-to-point") != nil {
				unit.PointToPoint = true
			}

			// Parse tunnel config at unit level (gr-0/0/0 unit N { tunnel { ... } })
			// #14450: merge EVERY unit `tunnel` sibling (see interface site).
			unitTunnelNodes := unitNode.FindChildren("tunnel")
			if len(unitTunnelNodes) > 0 {
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
				// #14450: the helper reads ONE node's mode; merged mode is
				// last-wins across blocks, so supply the latest block that
				// authors a mode (nil -> inherits, as the helper documents).
				modeNode14450 := lastModeTunnelNode14450(unitTunnelNodes)
				if unitNum > 0 && !unitSharesInterfaceWireguardDevice(ifc, modeNode14450) {
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
				for _, tunnelNode := range unitTunnelNodes {
					// #14440: same braced-scalar pre-pass as the interface-level
					// reader, applied after cloneForUnit so only leaves the unit
					// itself authored override the inherited interface values.
					// #14450: inside the merge loop, per block in order.
					applyTunnelBracedScalars14440(tc, tunnelNode)
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
						case "clear-dont-fragment-bit":
							tc.ClearDontFragmentBit = true
						case "wireguard":
							parseTunnelWireguard(tc, prop)
						}
						if skipUnit9899 {
							break
						}
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
			if vlanNode := unitNode.FindChild("vlan-id"); vlanNode != nil {
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

			// #15035: compile `vlan-tags outer N` (no inner tag — the
			// QinQ gate has already rejected any inner-bearing stack in
			// strict mode) into VlanID. The gates counted this spelling
			// as a positive tag (#5879 single S-tag, #14574 tagging
			// requirement) but no compiler consumer read it, so the unit
			// silently compiled untagged. Nodes carrying an `inner`
			// keyword are skipped here: strict compile never reaches
			// them, and the lenient path must keep its historical shape
			// (outer dropped, #5879 warning only). A `vlan-id` on the
			// same unit wins; vlanTagsSeen makes first-wins hold for a
			// bare `vlan-tags outer 0` too; skipUnit9899 (unit scope)
			// quarantines the whole unit on the lenient path.
			vlanTagsSeen := unitNode.FindChild("vlan-id") != nil
			for _, vtNode := range unitNode.FindChildren("vlan-tags") {
				if vlanTagsHasToken(vtNode, "inner") {
					continue
				}
				vals, hasOuter := vlanTagsOuterValue15035(vtNode)
				if !hasOuter {
					continue
				}
				raw := ""
				if len(vals) > 0 {
					raw = vals[0]
				}
				n, perr := parseVlanTagsOuter15035(raw)
				if perr != nil {
					msg := fmt.Sprintf("interfaces %s unit %d: %s", ifName, unitNum, perr.Error())
					if opts.lenientInterfaceNumericBounds {
						if warnings != nil {
							*warnings = append(*warnings, msg+fmt.Sprintf("; skipping unit %d", unitNum))
						}
						skipUnit9899 = true
						break
					}
					return fmt.Errorf("%s", msg)
				}
				if !vlanTagsSeen {
					unit.VlanID = int(n)
					vlanTagsSeen = true
				}
			}
			if skipUnit9899 {
				continue
			}

			// Parse inner-vlan-id on unit (QinQ inner tag)
			if ivNode := unitNode.FindChild("inner-vlan-id"); ivNode != nil {
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
			for _, familyNode := range unitNode.FindChildren("family") {
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
						unit.FamilyInet = true
						// #9424: a BRACKETED list packs every address past the
						// first onto this leaf's Keys (hierarchical) or into a
						// child chain (flat set), and namedInstances reads slot
						// 0 only — so `address [ a b ]` compiled to ONE address
						// with no error and no warning.
						inetAddrs, inetBad := unitAddressInstances(afNode, "inet")
						ifaces.MalformedAddresses = append(ifaces.MalformedAddresses, inetBad...)
						for _, addrInst := range inetAddrs {
							unit.Addresses = append(unit.Addresses, addrInst.name)
							// Check for primary/preferred flags. Preferred
							// is first-wins across families (#15222): the
							// inet6 arm already guards on empty, and a
							// last-wins overwrite here would silently
							// discard the first authored `preferred`.
							if addrInst.node.FindChild("primary") != nil {
								unit.PrimaryAddress = addrInst.name
							}
							if addrInst.node.FindChild("preferred") != nil && unit.PreferredAddress == "" {
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
						for _, rawDHCPNode := range afNode.FindChildren("dhcp") {
							if dhcpNode := packedBody(rawDHCPNode,
								schemaForPath("interfaces", "x", "unit", "family", "inet", "dhcp")); dhcpNode != nil {
								unit.DHCP = true
								if len(dhcpNode.Children) > 0 {
									opts := unit.DHCPOptions
									if opts == nil {
										opts = &DHCPInetOptions{}
									}
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
						}
						if mtuNode := afNode.FindChild("mtu"); mtuNode != nil {
							if v := nodeVal(mtuNode); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									// A unit's effective MTU is the minimum of
									// its family MTUs. Keep the fold
									// order-independent: family nodes are
									// visited in authored order, but unit.MTU
									// feeds both the #9837 gate and the
									// dataplane VLAN-child writer.
									if n < unit.MTU || unit.MTU == 0 {
										unit.MTU = n
									}
								}
							}
						}
						// #14608: sampling is per-family — `family inet
						// sampling` selects IPv4 flows only (see the inet6
						// arm for the other half). Union presence flags;
						// input/output accumulate across siblings.
						for _, sampNode := range afNode.FindChildren("sampling") {
							if sampNode.FindChild("input") != nil {
								unit.SamplingV4Input = true
							}
							if sampNode.FindChild("output") != nil {
								unit.SamplingV4Output = true
							}
						}
						for _, filterNode := range afNode.FindChildren("filter") {
							// Preserve flat-set replacement semantics for repeated
							// scalar filter leaves in hierarchical text.
							for _, inputNode := range filterNode.FindChildren("input") {
								unit.FilterInputV4 = nodeVal(inputNode)
							}
							for _, outputNode := range filterNode.FindChildren("output") {
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
						unit.FamilyInet6 = true
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
						// #14608: per-family — `family inet6 sampling`
						// selects IPv6 flows only (see the inet arm).
						for _, sampNode := range afNode.FindChildren("sampling") {
							if sampNode.FindChild("input") != nil {
								unit.SamplingV6Input = true
							}
							if sampNode.FindChild("output") != nil {
								unit.SamplingV6Output = true
							}
						}
						for _, filterNode := range afNode.FindChildren("filter") {
							for _, inputNode := range filterNode.FindChildren("input") {
								unit.FilterInputV6 = nodeVal(inputNode)
							}
							for _, outputNode := range filterNode.FindChildren("output") {
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
						for _, rawDCNode := range afNode.FindChildren("dhcpv6-client") {
							if dcNode := packedBody(rawDCNode,
								schemaForPath("interfaces", "x", "unit", "family", "inet6", "dhcpv6-client")); dcNode != nil {
								unit.DHCPv6 = true
								dc := unit.DHCPv6Client
								if dc == nil {
									dc = &DHCPv6ClientConfig{}
								}
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
										// #15063: multi leaf — accumulate every
										// value across Keys[1:] and child nodes
										// (bracket, block, flat and repeated
										// spellings), not just nodeVal's first.
										for _, v := range firewallMatchValues(prop) {
											dc.ClientIATypes = append(dc.ClientIATypes, v)
										}
									case "prefix-delegating":
										pdNode := packedBody(prop,
											schemaForPath("interfaces", "x", "unit", "family", "inet6", "dhcpv6-client", "prefix-delegating"))
										if plNode := pdNode.FindChild("preferred-prefix-length"); plNode != nil {
											if v := nodeVal(plNode); v != "" {
												if n, ok := parseIntLeaf(warnings, "interfaces "+ifName+" dhcpv6-client prefix-delegating preferred-prefix-length", v); ok {
													dc.PrefixDelegatingPrefixLen = n
												}
											}
										}
										if slNode := pdNode.FindChild("sub-prefix-length"); slNode != nil {
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
										uraNode := packedBody(prop,
											schemaForPath("interfaces", "x", "unit", "family", "inet6", "dhcpv6-client", "update-router-advertisement"))
										if ifNode := uraNode.FindChild("interface"); ifNode != nil {
											dc.UpdateRAInterface = nodeVal(ifNode)
										}
									}
								}
								unit.DHCPv6Client = dc
							}
						}
					}
				}
			}

			ifc.Units[unitNum] = unit

			// Collect tunnel addresses from unit config. A unit-disabled
			// unit (#14575) contributes none: its addresses must not be
			// installed on the tunnel device.
			if !unit.Disable {
				if unit.Tunnel != nil {
					// Per-unit tunnel: addresses belong to this specific tunnel
					unit.Tunnel.Addresses = append(unit.Tunnel.Addresses, unit.Addresses...)
				} else if ifc.Tunnel != nil {
					// Interface-level tunnel: all unit addresses go to shared tunnel
					ifc.Tunnel.Addresses = append(ifc.Tunnel.Addresses, unit.Addresses...)
				}
			}
		}
		if warnings != nil {
			if warning := nativeVLANBindingWarning(ifName, ifc); warning != "" {
				*warnings = append(*warnings, warning)
			}
		}

		ifaces.Interfaces[ifName] = ifc
	}
	suppressInvalidRethAddresses(ifaces, invalidRethRG)
	return nil
}
func nativeVLANBindingWarning(ifName string, ifc *InterfaceConfig) string {
	if ifc == nil || ifc.NativeVlanID <= 0 {
		return ""
	}
	matches := 0
	for _, unit := range ifc.Units {
		if unit != nil && unit.VlanID == ifc.NativeVlanID {
			matches++
			if matches > 1 {
				break
			}
		}
	}
	if matches == 1 {
		return ""
	}
	return fmt.Sprintf(
		"interfaces %s native-vlan-id %d has no unique matching unit with vlan-id %d; untagged ingress is rejected (#12248)",
		ifName, ifc.NativeVlanID, ifc.NativeVlanID,
	)
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
	expanded := expandResolvingRuns9792(wgNode.Children, tunnelWireguardSchema9792()) // #9792: expand a lenient-path packed run (#9235).
	for _, prop := range expanded {
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
	var peers []*Node
	for _, prop := range expanded {
		if prop.Name() == "peer" {
			peers = append(peers, prop)
		}
	}
	for _, inst := range namedInstances(peers) {
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
	peerBody := packedBody(peerNode, tunnelWireguardPeerSchema9792())
	for _, prop := range expandResolvingRuns9792(peerBody.Children, tunnelWireguardPeerSchema9792()) {
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

// selectMSSValueEnd returns the token the compiler selects (the
// selectMSSToken value) plus the end-exclusive index just past the
// consumed value grammar:
//
//   - parseable `mss` child: index 2 in that child (Keys[0]=="mss",
//     Keys[1]==value); the kind node's own Keys then carry no value —
//     a flat token beside a parseable child is the SELECTED value's
//     sibling in the #1979 mixed shape (`gre-in 70000 { mss 1360; }`
//     compiles 1360), not a tail.
//   - flat Keys[1]=="mss" with a value: index 3 in the kind node.
//   - any other flat token: index 2 in the kind node.
//   - unparseable child with a flat fallback: the value is Keys[1], so
//     index 2 in the kind node — tokens past it were never consumed
//     even though a child exists (`gre-in 1400 bogus { mss bogus; }`).
//   - unparseable/missing-value child with NO flat token, and any other
//     braced body (the #8838 branch): the offending keyword itself is
//     the selected token and the whole body is the (invalid) value
//     position, so there is no leftover to account.
//
// ok is false exactly when selectMSSToken reports no token; child != nil
// only for the parseable-child selection. #14576 uses the leftover past
// end (in child if set, else in the node) for token accounting: every
// token the statement carries must be the kind, the optional `mss`
// keyword, the selected value, or a #1979-discarded sibling — anything
// else packed into the same node was silently dropped before #14576.
func selectMSSValueEnd(node *Node) (tok string, child *Node, end int, ok bool) {
	if mssChild := node.FindChild("mss"); mssChild != nil && len(mssChild.Keys) >= 2 {
		if _, err := strconv.Atoi(mssChild.Keys[1]); err == nil {
			return mssChild.Keys[1], mssChild, 2, true
		}
		if len(node.Keys) < 2 {
			return mssChild.Keys[1], nil, 0, true
		}
		return node.Keys[1], nil, 2, true
	}
	if len(node.Keys) >= 3 && node.Keys[1] == "mss" {
		return node.Keys[2], nil, 3, true
	}
	if len(node.Keys) >= 2 {
		return node.Keys[1], nil, 2, true
	}
	if len(node.Children) > 0 {
		return node.Children[0].Name(), nil, 0, true
	}
	return "", nil, 0, false
}

// mssLeftoverTokens returns the tokens packed into a tcp-mss kind node
// past the compiler-selected value (#14576): a second kind
// (`gre-out mss 1300 all-tcp mss 1350`), trailing junk
// (`all-tcp mss 1350 bogus 7`), or an extra value
// (`all-tcp 1350 9999`). In the flat-set AST the tail nests on the
// `mss`/value child (`gre-out > [mss 1300 all-tcp ...]`, or
// `all-tcp > [1350 9999]` for the bare-value form); in the hierarchical
// packed AST it sits on the kind node itself; inside a braced `mss`
// child it follows the child's selected value. The first `mss` child is
// the value carrier the selection reads (or, when the flat token wins
// the #1979 fallback, the precedence's discard — only its tail past
// the value position is leftover). Any OTHER child contributed nothing
// the selection consumed, EXCEPT the child the precedence deliberately
// discards when a flat token exists (#1979/#8838: an unusable child
// beside a flat token is silent by design, and the flat token beside
// a parseable child likewise). A repeated `mss` child the FindChild
// selection never reads is leftover on the same terms.
func mssLeftoverTokens(node *Node) []string {
	_, child, end, ok := selectMSSValueEnd(node)
	if !ok {
		return nil
	}
	selected := child != nil || end > 0
	var leftover []string
	if child != nil {
		leftover = append(leftover, child.Keys[2:]...)
	} else if end > 0 {
		leftover = append(leftover, node.Keys[end:]...)
	}
	firstMSS := node.FindChild("mss")
	flatExists := len(node.Keys) >= 2
	for _, c := range node.Children {
		switch {
		case c == child:
			// The selected braced child; its tail is counted above.
		case c == firstMSS && flatExists && child == nil:
			// Flat fallback won (#1979): the child's value position
			// is the precedence's discard; tokens past it are
			// nobody's.
			leftover = append(leftover, c.Keys[2:]...)
		case c == firstMSS:
			// The value carrier when there is no flat token. Its tail
			// is handled once, after the loop, by the carrier check:
			// when the carrier IS the selection (packed keyword on
			// the kind node, or flat-set nesting) tokens past its
			// selected value count; when it merely holds the #8838
			// no-token keyword its rejection already covers the child.
		default:
			// Any other child — a repeated `mss`, a typo keyword,
			// junk. When a flat token exists the #1979/#8838
			// precedence discards an unusable child silently BY
			// DESIGN (`gre-in 1400 { msss 1; }` compiles 1400); when
			// there is no flat token and a value was selected (from
			// a braced child), a sibling child was never read at all.
			if !flatExists && selected {
				leftover = append(leftover, c.Keys...)
			}
		}
	}
	// Flat-set / SetPath nesting: an empty kind node whose single value
	// carrier child holds `[mss] value [tail...]` or `value [tail...]`.
	// selectMSSToken reads the carrier's token directly (it IS the
	// selection), so tokens past the carrier's selected value are
	// leftover even though selectMSSValueEnd reports end==0 on the
	// kind node. Only when the carrier was actually selected: a carrier
	// present beside a selected flat/braced value is the precedence
	// discard above, not this.
	if child == nil && end == 0 && len(node.Keys) < 2 {
		if carrier := valueCarrierChild(node); carrier != nil {
			if _, _, cend, cok := selectMSSValueEnd(carrierAsKind(carrier)); cok && cend > 0 {
				// cend indexes the adapted carrier (kind token
				// prepended), so the carrier's own leftover starts
				// one position earlier.
				leftover = append(leftover, carrier.Keys[cend-1:]...)
			}
		}
	}
	return leftover
}

// valueCarrierChild returns the single child of a leaf-less kind node
// that carries the MSS value in the flat-set AST (see
// mssLeftoverTokens), or nil when there is no such child. Repeated or
// multiple children are not a single carrier; the caller accounts them
// as leftover through the main loop instead.
func valueCarrierChild(node *Node) *Node {
	if len(node.Children) != 1 {
		return nil
	}
	c := node.Children[0]
	if len(c.Keys) == 0 {
		return nil
	}
	return c
}

// carrierAsKind adapts a flat-set value carrier (`[mss 1350 ...]` or
// `[1350 ...]`) to the kind-node shape selectMSSValueEnd expects (kind
// token first), so the carrier's consumed end index can be reused
// instead of duplicating the `mss`-keyword grammar.
func carrierAsKind(carrier *Node) *Node {
	keys := make([]string, 0, len(carrier.Keys)+1)
	keys = append(keys, "")
	keys = append(keys, carrier.Keys...)
	return &Node{Keys: keys}
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
				// Junos and RFC 5798 default Preempt_Mode to TRUE
				// (#15047): only an explicit `no-preempt` clears it.
				Preempt: true,
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
				vg.PreemptSet = true
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
			case "no-preempt":
				// Junos explicit opt-out (#15046): Preempt stays
				// false (last statement wins, mirroring the
				// child-node walk) and PreemptSet records the
				// authored statement so it round-trips.
				vg.Preempt = false
				vg.PreemptSet = true
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
			case "track":
				// Junos container packed onto the Keys run
				// (#15046): `track interface <if> priority-cost
				// <n>`. First-wins like track-interface above;
				// duplicates across spellings are gated by the
				// #1814/#15046 pre-walk.
				if i+2 < len(keys) && keys[i+1] == "interface" {
					if vg.TrackInterface == "" {
						vg.TrackInterface = keys[i+2]
					}
					i += 2
					if i+2 < len(keys) && keys[i+1] == "priority-cost" {
						if n, ok := parseTrackCost(keys[i+2]); ok && vg.TrackPriorityDelta == 0 {
							vg.TrackPriorityDelta = n
						}
						i += 2
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
		// A flat `set ... vrrp-group <id> priority <n> virtual-address <vip>`
		// run is represented as a chain of child nodes. Expand it against the
		// group schema before reading properties so every property is visible
		// to this loop, just as it is in the braced spelling.
		props := expandFlatRun(vrrpInst.node.Children, vrrpGroupSchemaNode(false))
		for _, prop := range props {
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
				vg.PreemptSet = true
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
			case "no-preempt":
				// Junos explicit opt-out (#15046). Last statement
				// wins against `preempt`, matching statement-order
				// semantics; PreemptSet records authorship.
				vg.Preempt = false
				vg.PreemptSet = true
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
			case "track":
				// Junos container (#15046):
				// `track { interface <if> { priority-cost <n>; } }`,
				// braced, or the flat-set chain
				// `track interface <if> priority-cost <n>` packed
				// onto Keys / nested as children. Feeds the same
				// single-track slot as track-interface.
				if iface, cost, ok := parseJunosTrackContainer15046(prop); ok {
					trackIface = iface
					trackIfaceSet = true
					if cost > 0 {
						nestedTrackCost = cost
						nestedTrackCostSet = true
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
		// The virtual-address list is a set: aliases of the same CIDR must not
		// survive collection as separate runtime VIPs.
		vg.VirtualAddresses = dedupeVRRPVIPs(vg.VirtualAddresses)
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
		// nodePath may embed a secret when n itself (or an ancestor-packed
		// node on the recursion path) carries a Keys-packed auth leaf
		// (#14403: e.g. `address 10.0.0.1/24 authentication-key <secret>;`).
		// Such nodes are reported via the misplaced arm below, which builds
		// its path from value-free segments (see safeVRRPPathKeys) and
		// returns before recursing, so a secret never reaches a deeper path.
		// A node that carries no auth token has no secret in its Keys.
		nodePath := joinNodePath(prefix, safeVRRPPathKeys(n))
		// #14403 (H1-e): auth nested UNDER a vrrp-group but not a direct
		// child (under virtual-address / track-interface) — recursive scan
		// when n itself is a group. Handled before the child loop so the
		// group's parent can prune it on the lenient path via the child
		// loop below; here we only need the strict reject when the group
		// is a top-level entry (defensive — real groups are children).
		// Examine n's DIRECT vrrp-group children so a lenient prune can rebuild
		// n.Children (dropping the offending group). A vrrp-group is always a
		// child of a family inet/inet6 address node, so detecting it here (as a
		// child of n) covers every real config and gives us the parent handle
		// the prune needs.
		pruned := false
		kept := make([]*Node, 0, len(n.Children))
		for _, c := range n.Children {
			if c.Name() == "vrrp-group" {
				if leaf := vrrpAuthLeafRecursive(c); leaf != "" {
					// SECURITY: build the message path from the group IDENTITY
					// ONLY (`vrrp-group <id>`), never c.Keys — in the Keys-packed
					// spelling (`vrrp-group 1 authentication-key <secret>;`) the
					// node's Keys run carries the authentication-key VALUE, so
					// joinNodePath(nodePath, c.Keys) would ECHO the secret into
					// the commit error / lenient warning (logs + CLI).
					// vrrpGroupIDKeys truncates to the value-free identity;
					// `nodePath` is composed of ancestor container keys
					// (interface/unit/family/address) which carry no secret leaf
					// value — except a Keys-packed misplaced leaf on an
					// ancestor, which safeVRRPPathKeys strips (#14403).
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
		// #14403 (H1-a..H1-d): auth leaf on a NON-group node (address /
		// family / unit / interface ancestor) whose subtree contains a
		// vrrp-group. Checked AFTER the direct-group prune so a group
		// already dropped for its own auth is not double-reported, and so
		// `groups` reflects only surviving groups. The message names the
		// misplaced keyword and the first affected group identity; paths
		// are built from value-free key segments only.
		if leaf, groups := vrrpMisplacedAuth(n); leaf != "" {
			idPath := joinNodePath(nodePath, vrrpGroupIDKeys(groups[0]))
			if !lenient {
				return nil, fmt.Errorf("%s: VRRP %s is configured but NOT enforced — "+
					"the dataplane is RFC 5798 VRRPv3, which removed authentication; "+
					"adverts are unauthenticated regardless, so a rogue host can hijack "+
					"mastership. Remove the authentication statement (#4288)",
					idPath, leaf)
			}
			for _, g := range groups {
				gidPath := joinNodePath(nodePath, vrrpGroupIDKeys(g))
				warnings = append(warnings, fmt.Sprintf("%s: VRRP %s is configured but the "+
					"dataplane is RFC 5798 VRRPv3, which removed authentication; the group is "+
					"DROPPED (not activated) rather than claim the VIP with unauthenticated "+
					"adverts — the operator required authentication that the impl cannot honor. "+
					"Remove the authentication statement to activate the group (#4288/#5834)",
					gidPath, leaf))
				stripVRRPGroup(n, g)
			}
			// Groups are now stripped, so recursion cannot re-report this
			// leaf (scope guard: no group in that child's subtree unless a
			// distinct placement remains). Recurse for sibling placements.
			w, err := validateVRRPAuthenticationAST(n.Children, nodePath, lenient)
			warnings = append(warnings, w...)
			if err != nil {
				return nil, err
			}
			continue
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

// safeVRRPPathKeys returns n.Keys truncated at the first auth token so a
// Keys-packed misplaced leaf (`address 10.0.0.1/24 authentication-key
// <secret>;` on an ancestor, #14403) never embeds the secret VALUE in a
// diagnostic path. Nodes without an auth token return Keys unchanged.
func safeVRRPPathKeys(n *Node) []string {
	for i := 1; i < len(n.Keys); i++ {
		if n.Keys[i] == "authentication-type" || n.Keys[i] == "authentication-key" {
			return n.Keys[:i]
		}
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

// vrrpAuthLeafRecursive is the #14403 descendant scan: like vrrpAuthLeaf but
// walks the group's WHOLE subtree, so an auth leaf nested under
// virtual-address / track-interface (not a direct child of the group) is
// caught. Keys of every descendant are scanned (a Keys-packed descendant may
// carry the leaf token); only the leaf NAME is returned, never a value.
func vrrpAuthLeafRecursive(vg *Node) string {
	if leaf := vrrpAuthLeaf(vg); leaf != "" {
		return leaf
	}
	for _, c := range vg.Children {
		if leaf := vrrpAuthLeafRecursive(c); leaf != "" {
			return leaf
		}
	}
	return ""
}

// vrrpDirectAuthLeaf returns the auth leaf carried DIRECTLY by a non-group
// node: a token in its own Keys run (Keys-packed spelling, e.g.
// `address 10.0.0.1/24 authentication-key <secret>;` — scan from index 1 so
// the node's own name at Keys[0] is not mistaken, though it never spells an
// auth leaf) or a direct child named authentication-type/key. Only the leaf
// NAME is returned, never a value.
func vrrpDirectAuthLeaf(n *Node) string {
	for i := 1; i < len(n.Keys); i++ {
		if n.Keys[i] == "authentication-type" || n.Keys[i] == "authentication-key" {
			return n.Keys[i]
		}
	}
	for _, c := range n.Children {
		if name := c.Name(); name == "authentication-type" || name == "authentication-key" {
			return name
		}
	}
	return ""
}

// collectVRRPGroups returns every vrrp-group node in n's subtree.
func collectVRRPGroups(n *Node) []*Node {
	var out []*Node
	if n.Name() == "vrrp-group" {
		out = append(out, n)
	}
	for _, c := range n.Children {
		out = append(out, collectVRRPGroups(c)...)
	}
	return out
}

// vrrpMisplacedAuth reports (leaf, groups) when node n — which is NOT itself
// a vrrp-group — directly carries an auth leaf AND its subtree contains at
// least one vrrp-group (#14403 cells H1-a..H1-d: address / family / unit /
// interface ancestors). Returns ("", nil) otherwise.
func vrrpMisplacedAuth(n *Node) (string, []*Node) {
	if n.Name() == "vrrp-group" {
		return "", nil
	}
	leaf := vrrpDirectAuthLeaf(n)
	if leaf == "" {
		return "", nil
	}
	groups := collectVRRPGroups(n)
	if len(groups) == 0 {
		return "", nil
	}
	return leaf, groups
}

// stripVRRPGroup removes target (by identity) from its parent's subtree,
// rebuilding Children slices in place. Returns true when removed. Used by
// the lenient #14403 arm where the misplaced leaf sits on an ancestor, so
// the affected group is not a direct child of the node being pruned.
func stripVRRPGroup(parent, target *Node) bool {
	for i, c := range parent.Children {
		if c == target {
			parent.Children = append(parent.Children[:i:i], parent.Children[i+1:]...)
			return true
		}
		if stripVRRPGroup(c, target) {
			return true
		}
	}
	return false
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
	// #13090: sibling `device-map` blocks are all live — compileChassis
	// folds every block — so pruning only the first FindChild hit would
	// leave the second block's poisoned names in the AST for the .link
	// writer (fail-open). Gate every block.
	var warnings []string
	for _, dmNode := range chassis.FindChildren("device-map") {
		w, err := pruneUnsafeDeviceMapBlockEntries9886(dmNode, lenient)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, w...)
	}
	return warnings, nil
}

// pruneUnsafeDeviceMapBlockEntries9886 is pruneUnsafeDeviceMapEntries9886 for
// ONE device-map block.
func pruneUnsafeDeviceMapBlockEntries9886(dmNode *Node, lenient bool) ([]string, error) {
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

// parseJunosTrackContainer15046 extracts (interface, priority-cost)
// from a Junos `track` container node (#15046) in every spelling:
// braced `track { interface <if> { priority-cost <n>; } }`, the
// flat-set chain packed onto Keys (`track interface <if>
// priority-cost <n>`), and a braced container whose interface child
// packs its cost onto its own Keys. Returns ok=false when no
// interface statement is present.
func parseJunosTrackContainer15046(track *Node) (string, int, bool) {
	// Keys-packed: Keys = [track, interface, <if>, ...].
	if len(track.Keys) >= 3 && track.Keys[1] == "interface" {
		cost := 0
		for i := 3; i+1 < len(track.Keys); i++ {
			if track.Keys[i] == "priority-cost" {
				if n, ok := parseTrackCost(track.Keys[i+1]); ok {
					cost = n
				}
			}
		}
		return track.Keys[2], cost, true
	}
	for _, iface := range track.FindChildren("interface") {
		name := ""
		if len(iface.Keys) >= 2 {
			name = iface.Keys[1]
		}
		if name == "" {
			continue
		}
		cost := 0
		if pc := iface.FindChild("priority-cost"); pc != nil {
			if v := nodeVal(pc); v != "" {
				if n, ok := parseTrackCost(v); ok {
					cost = n
				}
			}
		}
		// Flat-set chain: priority-cost nested as a child chain
		// under interface, or packed onto the interface Keys.
		if cost == 0 {
			for i := 2; i+1 < len(iface.Keys); i++ {
				if iface.Keys[i] == "priority-cost" {
					if n, ok := parseTrackCost(iface.Keys[i+1]); ok {
						cost = n
					}
				}
			}
		}
		return name, cost, true
	}
	return "", 0, false
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
	// Junos container spellings (#15046) feed the same single-track
	// slot: count `track` children and Keys-packed `track interface`
	// pairs alongside track-interface.
	junosTracks := vg.FindChildren("track")
	for _, k := range vg.Keys {
		if k == "track" {
			keysPacked++
		}
	}
	tracks := vg.FindChildren("track-interface")
	// Effective tracked-interface nodes for cost validation: the
	// interface child of each Junos track container.
	var junosIfaceNodes []*Node
	for _, tr := range junosTracks {
		for _, iface := range tr.FindChildren("interface") {
			junosIfaceNodes = append(junosIfaceNodes, iface)
		}
		// Keys-packed `track interface <if> priority-cost <n>;`
		if len(tr.Keys) >= 3 && tr.Keys[1] == "interface" {
			junosIfaceNodes = append(junosIfaceNodes, tr)
		}
	}
	totalTracks := keysPacked + len(tracks) + len(junosTracks)
	if totalTracks > 1 {
		if !lenient {
			return nil, fmt.Errorf("%s: %d track-interface statements; only one tracked interface is supported per vrrp-group", nodePath, totalTracks)
		}
		if keysPacked > 0 || len(junosTracks) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s: %d track-interface statements; keeping the first and ignoring the rest (#1814)", nodePath, totalTracks))
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
	// Lenient cross-spelling duplicate: prune Junos track containers
	// when a track-interface (or an earlier track) already won, so the
	// compiler's last-wins child walk cannot resurrect the loser.
	if lenient && totalTracks > 1 {
		seenTrack := len(tracks) > 0
		pruned := vg.Children[:0]
		changed := false
		for _, c := range vg.Children {
			if c.Name() == "track" {
				if seenTrack {
					changed = true
					continue
				}
				seenTrack = true
			}
			if c.Name() == "track-interface" && len(tracks) == 0 && totalTracks > 1 && seenTrack {
				// A Junos track kept above wins over a later
				// track-interface child.
				changed = true
				continue
			}
			pruned = append(pruned, c)
		}
		if changed {
			vg.Children = pruned
		}
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
	// Junos spelling costs (#15046): validate every priority-cost
	// under a track container's interface child, plus the Keys-packed
	// `track interface <if> priority-cost <n>` tail.
	for _, iface := range junosIfaceNodes {
		for _, pc := range iface.FindChildren("priority-cost") {
			if len(pc.Keys) > 1 {
				if err := costCheck(pc.Keys[1], "priority-cost"); err != nil {
					return nil, err
				}
			}
		}
		for i, k := range iface.Keys {
			if k == "priority-cost" && i+1 < len(iface.Keys) {
				if err := costCheck(iface.Keys[i+1], "priority-cost"); err != nil {
					return nil, err
				}
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
