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

		// #9408: expand a FLAT-SET CHAIN before reading the leaves, and read
		// the SAME expanded slice from both loops below (compiler_protocols_ospf_flat_run_9408.go).
		ospfChildren := expandFlatRun(ospfNode.Children, ospfSchema9408())
		ospfExpanded := &Node{Keys: ospfNode.Keys, Children: ospfChildren}

		// Router ID, passive-default, and export policies at the ospf level
		for _, child := range ospfChildren {
			switch child.Name() {
			case "router-id":
				if len(child.Keys) >= 2 {
					proto.OSPF.RouterID = child.Keys[1]
				}
			case "reference-bandwidth":
				applyOSPFReferenceBandwidth9408(proto.OSPF, child)
			case "passive":
				proto.OSPF.PassiveDefault = true
			case "export":
				// Multi-value leaf (#2587): `export [ p1 p2 ]` collapses onto
				// child.Keys[1:] (flat-set) or child.Children (hierarchical
				// block). Read ALL values via the firewallMatchValues SSOT;
				// reading only Keys[1] dropped every policy past the first.
				proto.OSPF.Export = append(proto.OSPF.Export, firewallMatchValues(child)...)
			}
		}

		for _, areaInst := range namedInstances(ospfExpanded.FindChildren("area")) {
			area := &OSPFArea{ID: areaInst.name}

			for _, ifInst := range bracketedGroupInstances8794(areaInst.node.FindChildren("interface")) {
				// #8436: FIND-OR-CREATE within the slice, keyed on the
				// interface NAME.
				//
				// `Interfaces` is a slice and this appended unconditionally, so
				// two `interface ge-0/0/0.0 { ... }` blocks under one area
				// produced TWO entries with the same name — whichever consumer
				// reads first wins and the other block's settings are
				// unreachable. Same shape as `system login class` (#8548),
				// where the slice made it look like a merge and it was not.
				//
				// THE DIFFERENT-NAMES CASE IS PRESERVED BY CONSTRUCTION, and
				// that is why this family was safe to fix after three batches
				// deferred it. Two blocks naming DIFFERENT interfaces do not
				// match here, so they still append and still produce two
				// entries — correct Junos authoring. Only two blocks naming the
				// SAME interface merge, which is the case the #8436 census
				// builds and the only one that was ever wrong.
				var iface *OSPFInterface
				for _, existing := range area.Interfaces {
					if existing != nil && existing.Name == ifInst.name {
						iface = existing
						break
					}
				}
				appendIface := iface == nil
				if appendIface {
					iface = &OSPFInterface{Name: ifInst.name}
				}
				// #7653: the body may be PACKED onto the instance line
				//   interface ge-0/0/0.0 authentication simple-password "s";
				// in which case Children is empty and every property below --
				// including the authentication that keeps the adjacency from
				// coming up unauthenticated -- is silently dropped. The
				// instance is still created, so the half-built object reaches
				// the FRR renderer, which emits interface activation
				// UNCONDITIONALLY while authentication is conditional on the
				// dropped AuthType. Expand the tail schema-driven, exactly as
				// the #6818/#6821 siblings do.
				for _, prop := range packedBodyChildren(ifInst.node,
					schemaForPath("protocols", "ospf", "area", "interface")) {
					switch prop.Name() {
					case "passive":
						iface.Passive = true
					case "no-passive":
						iface.NoPassive = true
					case "interface-type":
						// #8481: canonicalize through the SSOT the schema
						// validator uses, so the accepted set and the rendered
						// set cannot drift. On the tolerant load / peer-sync
						// path the value has NOT been through the validator,
						// so an unresolvable token is dropped rather than
						// passed to FRR — a config an older binary persisted
						// must not be able to break the managed-section
						// reload on a boot the operator did not initiate.
						if v := nodeVal(prop); v != "" {
							if canon, ok := CanonicalOSPFNetworkType(v); ok {
								iface.NetworkType = canon
							}
						}
					case "cost":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.Cost = n
							}
						}
					case "hello-interval":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.HelloInterval = n
							}
						}
					case "dead-interval":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.DeadInterval = n
							}
						}
					case "retransmit-interval":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.RetransmitInt = n
							}
						}
					case "priority":
						// OSPF priority 0 is valid ("never DR"), so mark
						// HasPriority to distinguish it from unset.
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.Priority = n
								iface.HasPriority = true
							}
						}
					case "authentication":
						// #6818: packedBodyChildren, not prop.Children. The
						// compact spelling `authentication simple-password
						// "secret";` puts the value on this stanza's own Keys,
						// so a Children-only loop ran zero times, AuthType and
						// AuthKey stayed empty, and the adjacency formed
						// UNAUTHENTICATED with no error and no warning.
						for _, authChild := range packedBodyChildren(prop,
							schemaForPath("protocols", "ospf", "area", "interface", "authentication")) {
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
										iface.AuthKey = Secret(nodeVal(kc))
									}
								}
							case "simple-password":
								iface.AuthType = "simple"
								iface.AuthKey = Secret(nodeVal(authChild))
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
				if appendIface {
					area.Interfaces = append(area.Interfaces, iface)
				}
			}

			// Parse area-type (stub/nssa).
			//
			// #9656 M26: this read `areaInst.node.FindChild("area-type")` and
			// then iterated ONLY that node's Children, which sees exactly one
			// of the three spellings an operator can write. Measured at
			// 766da5332, all three commit clean and two of them silently
			// rendered a stub or NSSA area as a NORMAL area:
			//
			//	area 0.0.0.1 area-type stub;          area.Keys=[area 0.0.0.1 area-type stub]
			//	                                      children=0        -> AreaType=""    WRONG
			//	area 0.0.0.1 { area-type stub; }      child Keys=[area-type stub]
			//	                                      nchild=0          -> AreaType=""    WRONG
			//	area 0.0.0.1 { area-type { stub; } }  child Keys=[area-type]
			//	                                      nchild=1          -> AreaType="stub"
			//
			// The consequence is silent and it is not cosmetic: a stub or NSSA
			// area rendered as a normal area floods the Type-5/7 LSAs the
			// operator asked to keep out.
			//
			// Both misses are the SAME defect — a packed tail that no reader
			// unpacks — so both are fixed by asking packedBodyChildren, the
			// schema-driven SSOT the sibling `interface` loop above already
			// uses, instead of reading Children directly. It is applied TWICE:
			// once to lift `area-type …` off the AREA node's own keys, and once
			// to lift `stub` / `nssa` off the `area-type` node's keys.
			areaSchema := schemaForPath("protocols", "ospf", "area")
			atSchema := schemaForPath("protocols", "ospf", "area", "area-type")
			for _, atNode := range packedBodyChildren(areaInst.node, areaSchema) {
				if atNode.Name() != "area-type" {
					continue
				}
				for _, atChild := range packedBodyChildren(atNode, atSchema) {
					switch atChild.Name() {
					case "stub":
						area.AreaType = "stub"
						if hasPackedChild9656(atChild, atSchema, "no-summaries") {
							area.NoSummary = true
						}
					case "nssa":
						area.AreaType = "nssa"
						if hasPackedChild9656(atChild, atSchema, "no-summaries") {
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
		// #9192: per-NEIGHBOR (not per-node) tracking of whether the neighbor
		// has already replaced its inherited group export/import list. Scoped
		// to this BGP instance, so a routing-instance's neighbors never share
		// state with the main instance's.
		ownExport9192 := map[*BGPNeighbor]bool{}
		ownImport9192 := map[*BGPNeighbor]bool{}

		// #8939, and the consequence here is not a lost setting -- it is the
		// whole protocol. `set protocols bgp graceful-restart cluster-id
		// 1.1.1.1 local-as 65001` nests each leaf under the previous one, so
		// this loop saw only the flag and LocalAS stayed 0. pkg/frr gates the
		// ENTIRE stanza on it (`if bgp != nil && bgp.LocalAS > 0`), so FRR
		// receives NO `router bgp` block at all: no sessions, no routes, and
		// `show configuration` renders exactly what the operator typed.
		for _, child := range expandFlatRun(bgpNode.Children, bgpLeafSchema8939()) {
			switch child.Name() {
			case "local-as":
				if len(child.Keys) >= 2 {
					// #4713: reject out-of-range/negative AS instead of the
					// silent uint32 wrap — leave LocalAS unset so a
					// leniently-loaded bad value is inert.
					if n, ok := parseASNumber(child.Keys[1]); ok {
						proto.BGP.LocalAS = n
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
				// #8939: split the packed run — see
				// bgp_multipath_schema_8939.go.
				for _, mc := range expandFlatRun(child.Children, bgpMultipathSchema8939()) {
					switch mc.Name() {
					case "multiple-as":
						proto.BGP.MultipathMultipleAS = true
					case "ibgp":
						// FRR `maximum-paths N` only enables eBGP multipath;
						// iBGP multipath needs the separate `maximum-paths
						// ibgp N` line. `multipath ibgp` selects it (#2978).
						proto.BGP.MultipathIBGP = true
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
				// Multi-value leaf (#2587): accumulate ALL policies across
				// both AST shapes via the firewallMatchValues SSOT.
				proto.BGP.Export = append(proto.BGP.Export, firewallMatchValues(child)...)
			case "import":
				proto.BGP.Import = append(proto.BGP.Import, firewallMatchValues(child)...)
			}
		}

		for _, groupInst := range namedInstances(bgpNode.FindChildren("group")) {
			var peerAS uint32
			var groupLocalAS uint32
			var groupLocalAddress string
			var groupHoldTime int
			var groupPassive bool
			var groupDesc string
			var groupMultihop int
			var groupExport []string
			var groupImport []string
			var familyInet, familyInet6 bool
			var groupPrefixLimitInet, groupPrefixLimitInet6 int
			var groupAuthKey string
			var groupBFD bool
			var groupBFDInterval int
			var groupBFDMultiplier int
			var groupDefaultOriginate bool
			var groupAllowASIn int
			var groupRemovePrivateAS bool
			// #5270: two-pass, order-INDEPENDENT group inheritance. A BGP
			// group's `neighbor` children and its group-level default
			// attributes (peer-as/local-as/local-address/hold-time/passive/
			// description/multihop/export/import/family+prefix-limit/
			// authentication-key/bfd/default-originate/loops/remove-private)
			// are semantically-unordered Junos siblings. The old single
			// stamp-as-you-go pass copied whatever group defaults had been
			// *seen so far* onto each neighbor as it was encountered, so a
			// `neighbor` authored BEFORE the group's `export` (or peer-as,
			// etc.) captured the empty/zero default — e.g. FRR then emitted
			// no outbound route-map and leaked routes (fail-open). Pass 0
			// processes every NON-neighbor child, fully collecting all group
			// defaults regardless of sibling order; pass 1 processes only the
			// `neighbor` children, stamping each from the completed defaults.
			// Per-neighbor explicit values still override the group default in
			// the neighbor block below (unchanged precedence). Works for both
			// the hierarchical and flat-set AST shapes; multi-value list leaves
			// (export/import, #2419/#2702) accumulate fully in pass 0.
			// #9181: expand ONCE, before the two-pass loop, so both passes see
			// the same segmentation. A packed run whose TAIL is a container
			// loses everything silently --
			//   `group G peer-as 65001 neighbor 10.0.0.1` -> neighbors=0, no
			// error -- because `neighbor` nests under `peer-as` and pass 1
			// never sees a child named `neighbor`. The group is then
			// configured with NOBODY IN IT, which reads as intentional.
			groupChildren := expandFlatRun(groupInst.node.Children, bgpGroupSchema9181())
			for pass := 0; pass < 2; pass++ {
				for _, child := range groupChildren {
					isNeighbor := child.Name() == "neighbor"
					if pass == 0 && isNeighbor {
						// Pass 0: collect group-level defaults only; defer
						// neighbor stamping until every default is known.
						continue
					}
					if pass == 1 && !isNeighbor {
						// Pass 1: stamp neighbors only; group defaults are
						// already fully collected.
						continue
					}
					switch child.Name() {
					case "peer-as":
						if v := nodeVal(child); v != "" {
							// #4713: no silent uint32 wrap — leave unset on a
							// negative/oversized AS (inert on lenient load).
							if n, ok := parseASNumber(v); ok {
								peerAS = n
							}
						}
					case "local-as":
						if v := nodeVal(child); v != "" {
							if n, ok := parseASNumber(v); ok {
								groupLocalAS = n
							}
						}
					case "local-address":
						groupLocalAddress = nodeVal(child)
					case "hold-time":
						if v := nodeVal(child); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								groupHoldTime = n
							}
						}
					case "passive":
						groupPassive = true
					case "description":
						groupDesc = nodeVal(child)
					case "multihop":
						if v := nodeVal(child); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								groupMultihop = n
							}
						}
					case "export":
						// Multi-value leaf (#2702): a bracket-list
						// `export [ p1 p2 ]` collapses every policy onto
						// child.Keys[1:] (flat-set, #2585) or onto child
						// nodes (hierarchical). The old nodeVal-first read
						// returned Keys[1] (non-empty) and appended ONLY the
						// first policy, masking the Keys[1:] fallback. Route
						// through the firewallMatchValues SSOT so all
						// policies survive in both AST shapes.
						groupExport = append(groupExport, firewallMatchValues(child)...)
					case "import":
						groupImport = append(groupImport, firewallMatchValues(child)...)
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
							// Gate group-level address-family flags by the
							// neighbor's own address version (#2454). A
							// dual-stack group (family inet AND inet6) must NOT
							// activate a bare IPv4 neighbor under
							// `address-family ipv6 unicast` (and vice versa):
							// without RFC 5549 extended-nexthop (which this
							// config model has no knob for) activating an IPv4
							// address for IPv6 unicast is invalid and breaks the
							// peer's AF activation. So an IPv4-addressed neighbor
							// inherits only the group's inet flag, an
							// IPv6-addressed neighbor only inet6.
							//
							// An address that does not parse (a hostname/peer-
							// group template or a malformed value) is left to
							// inherit BOTH group flags unchanged — preserving
							// pre-#2454 behavior for the non-literal-IP case
							// rather than silently dropping a family.
							inheritInet, inheritInet6 := familyInet, familyInet6
							if ip := net.ParseIP(nAddr); ip != nil {
								if ip.To4() != nil {
									inheritInet6 = false
								} else {
									inheritInet = false
								}
							}
							// #9192: FIND-OR-CREATE on (GroupName, Address),
							// instead of appending one *BGPNeighbor per AST
							// NODE. One authored neighbor can occupy several
							// nodes -- a bare declaration and a later sub-leaf
							// are siblings -- so ordinary flat-set authoring
							// produced two entries for one peer. Group defaults
							// are applied on CREATE only; re-applying them for a
							// later node would wipe what an earlier node set.
							// Rationale, the three boundaries and the
							// lenient-path decision:
							// compiler_bgp_neighbor_merge_9192.go.
							neighbor := findBGPNeighbor9192(proto.BGP.Neighbors, groupInst.name, nAddr)
							if neighbor == nil {
								neighbor = &BGPNeighbor{
									Address:          nAddr,
									PeerAS:           peerAS,
									LocalAS:          groupLocalAS,
									LocalAddress:     groupLocalAddress,
									HoldTime:         groupHoldTime,
									Passive:          groupPassive,
									Description:      groupDesc,
									MultihopTTL:      groupMultihop,
									Export:           groupExport,
									Import:           groupImport,
									FamilyInet:       inheritInet,
									FamilyInet6:      inheritInet6,
									GroupName:        groupInst.name,
									AuthPassword:     Secret(groupAuthKey),
									BFD:              groupBFD,
									BFDInterval:      groupBFDInterval,
									BFDMultiplier:    groupBFDMultiplier,
									DefaultOriginate: groupDefaultOriginate,
									AllowASIn:        groupAllowASIn,
									RemovePrivateAS:  groupRemovePrivateAS,
									PrefixLimitInet:  groupPrefixLimitInet,
									PrefixLimitInet6: groupPrefixLimitInet6,
								}
								proto.BGP.Neighbors = append(proto.BGP.Neighbors, neighbor)
							}
							// Per-neighbor overrides. neighborOwnExport /
							// neighborOwnImport track whether this neighbor set
							// its OWN export/import so the first own entry
							// REPLACES the inherited group list (Junos
							// most-specific-LEVEL-wins: a more-specific level's
							// export/import replaces — it does NOT merge with —
							// the inherited one, #5277). Subsequent same-level
							// entries (multiple set-lines or a bracket list)
							// accumulate into the neighbor's own ordered chain.
							//
							// #9192: keyed on the NEIGHBOR, not scoped to this
							// node -- see compiler_bgp_neighbor_merge_9192.go.
							neighborOwnExport := ownExport9192[neighbor]
							neighborOwnImport := ownImport9192[neighbor]
							applyBGPNeighborProps9192(neighbor, child, &neighborOwnExport, &neighborOwnImport)
							ownExport9192[neighbor] = neighborOwnExport
							ownImport9192[neighbor] = neighborOwnImport
						}
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
				// Multi-value leaf (#2587): accumulate ALL policies across
				// both AST shapes via the firewallMatchValues SSOT.
				proto.OSPFv3.Export = append(proto.OSPFv3.Export, firewallMatchValues(child)...)
			}
		}

		for _, areaInst := range namedInstances(ospf3Node.FindChildren("area")) {
			area := &OSPFv3Area{ID: areaInst.name}

			for _, ifInst := range bracketedGroupInstances8794(areaInst.node.FindChildren("interface")) {
				// #8436: FIND-OR-CREATE within the slice, keyed on the
				// interface NAME.
				//
				// `Interfaces` is a slice and this appended unconditionally, so
				// two `interface ge-0/0/0.0 { ... }` blocks under one area
				// produced TWO entries with the same name — whichever consumer
				// reads first wins and the other block's settings are
				// unreachable. Same shape as `system login class` (#8548),
				// where the slice made it look like a merge and it was not.
				//
				// THE DIFFERENT-NAMES CASE IS PRESERVED BY CONSTRUCTION, and
				// that is why this family was safe to fix after three batches
				// deferred it. Two blocks naming DIFFERENT interfaces do not
				// match here, so they still append and still produce two
				// entries — correct Junos authoring. Only two blocks naming the
				// SAME interface merge, which is the case the #8436 census
				// builds and the only one that was ever wrong.
				var iface *OSPFv3Interface
				for _, existing := range area.Interfaces {
					if existing != nil && existing.Name == ifInst.name {
						iface = existing
						break
					}
				}
				appendIface := iface == nil
				if appendIface {
					iface = &OSPFv3Interface{Name: ifInst.name}
				}
				// #7653: same packed-instance shape as the OSPFv2 loop above.
				for _, prop := range packedBodyChildren(ifInst.node,
					schemaForPath("protocols", "ospf3", "area", "interface")) {
					switch prop.Name() {
					case "passive":
						iface.Passive = true
					case "cost":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.Cost = n
							}
						}
					case "hello-interval":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.HelloInterval = n
							}
						}
					case "dead-interval":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.DeadInterval = n
							}
						}
					case "retransmit-interval":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.RetransmitInt = n
							}
						}
					case "priority":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								iface.Priority = n
								iface.HasPriority = true
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
				if appendIface {
					area.Interfaces = append(area.Interfaces, iface)
				}
			}

			proto.OSPFv3.Areas = append(proto.OSPFv3.Areas, area)
		}
	}

	ripNode := node.FindChild("rip")
	if ripNode != nil {
		proto.RIP = &RIPConfig{}
		// #8939: `set protocols rip authentication-key K authentication-type md5`
		// nests the TYPE under the KEY, so this loop saw only the key and
		// AuthType stayed "". AuthTypeIsMD5("") is false, so pkg/frr renders
		// `ip rip authentication mode text` and puts the operator's key on the
		// wire in CLEARTEXT -- and AuthTypeUnrecognized("") is ALSO false, so
		// #8443's downgrade warning does not fire either.
		for _, child := range expandFlatRun(ripNode.Children, ripLeafSchema8939()) {
			switch child.Name() {
			case "group":
				for _, gc := range child.Children {
					// Multi-value leaves (#3904): a bracket list collapses onto
					// Keys[1:] (opaque group) or child nodes; read EVERY value
					// via firewallMatchValues. The pre-#3904 Keys[1]-only read
					// truncated `export [ a b ]` / `neighbor [ i1 i2 ]` to the
					// first entry.
					switch gc.Name() {
					case "neighbor":
						proto.RIP.Interfaces = append(proto.RIP.Interfaces, firewallMatchValues(gc)...)
					case "export":
						proto.RIP.Redistribute = append(proto.RIP.Redistribute, firewallMatchValues(gc)...)
					}
				}
			case "neighbor":
				// Multi-value leaf (#3904): read EVERY neighbor via
				// firewallMatchValues (Keys[1:] + child nodes).
				proto.RIP.Interfaces = append(proto.RIP.Interfaces, firewallMatchValues(child)...)
			case "passive-interface":
				proto.RIP.Passive = append(proto.RIP.Passive, firewallMatchValues(child)...)
			case "redistribute":
				proto.RIP.Redistribute = append(proto.RIP.Redistribute, firewallMatchValues(child)...)
			case "authentication-key":
				if v := nodeVal(child); v != "" {
					proto.RIP.AuthKey = Secret(v)
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
		// #8939, and the same cleartext downgrade as `rip` above: a dropped
		// authentication-type renders `area-password clear` / `domain-password
		// clear` instead of `md5`.
		for _, child := range expandFlatRun(isisNode.Children, isisLeafSchema8939()) {
			switch child.Name() {
			case "net":
				if len(child.Keys) >= 2 {
					proto.ISIS.NET = child.Keys[1]
				}
			// #8446: `level` and `is-type` are two spellings of ONE
			// concept and both land on ISISConfig.Level, so authoring
			// both is last-write-wins. Store the CANONICAL form so
			// every consumer sees one spelling — `level-2-only` (what
			// the FRR renderer emits, and therefore what an operator
			// copying our own output writes) collapses onto `level-2`.
			// A value no spelling matches is kept verbatim rather than
			// dropped: the strict commit gate rejects it, and on the
			// tolerant Load / peer-sync path the renderer's own belt
			// turns it into the narrow default (#1960 no-brick).
			case "level", "is-type":
				if len(child.Keys) >= 2 {
					if c, ok := CanonicalISISLevel(child.Keys[1]); ok {
						proto.ISIS.Level = c
					} else {
						proto.ISIS.Level = child.Keys[1]
					}
				}
			case "export":
				// Multi-value leaf (#2587): accumulate ALL policies across
				// both AST shapes via the firewallMatchValues SSOT.
				proto.ISIS.Export = append(proto.ISIS.Export, firewallMatchValues(child)...)
			case "authentication-key":
				if v := nodeVal(child); v != "" {
					proto.ISIS.AuthKey = Secret(v)
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
					// #8436 find-or-create. ISIS.Interfaces is a SLICE, so a
					// second block naming the SAME interface used to APPEND a
					// second entry with that name rather than overwrite one —
					// it looks like a merge until the entries are counted, and
					// whichever consumer reads first wins while the other
					// block's settings are unreachable. Same shape as `system
					// login class` (#8548) and the #8594 OSPF/OSPF3/RA
					// interface batch.
					//
					// THE DIFFERENT-NAMES CASE IS PRESERVED BY CONSTRUCTION:
					// the lookup is keyed on the interface NAME, so two blocks
					// naming different interfaces do not match and still append
					// two entries — ordinary Junos authoring. Only two blocks
					// naming the SAME interface merge, which is the case the
					// #8436 census builds and the only one that was ever wrong.
					// TestDistinctISISInterfaceBlocksStillAppend8436 is the
					// control: an over-broad merge that matched any entry would
					// silently configure one interface where the operator wrote
					// two, and only that cell can see it.
					var iface *ISISInterface
					for _, existing := range proto.ISIS.Interfaces {
						if existing != nil && existing.Name == child.Keys[1] {
							iface = existing
							break
						}
					}
					appendISISIface := iface == nil
					if appendISISIface {
						iface = &ISISInterface{Name: child.Keys[1]}
					}
					// #8939: per-interface authentication has the same
					// cleartext-downgrade shape as the area-level pair above.
					for _, prop := range expandFlatRun(child.Children, isisInterfaceSchema8939()) {
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
							iface.AuthKey = Secret(nodeVal(prop))
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
					if appendISISIface {
						proto.ISIS.Interfaces = append(proto.ISIS.Interfaces, iface)
					}
				}
			}
		}
	}
	return nil
}

func compileRouterAdvertisement(node *Node, proto *ProtocolsConfig) error {
	for _, inst := range bracketedGroupInstances8794(node.FindChildren("interface")) {
		// #8436: FIND-OR-CREATE, keyed on the interface name — see the OSPF
		// loops above for why the different-names case is preserved. The store
		// here is `proto.RouterAdvertisement`, a slice, and the name lives on
		// the `Interface` field rather than `Name`.
		var ra *RAInterfaceConfig
		for _, existing := range proto.RouterAdvertisement {
			if existing != nil && existing.Interface == inst.name {
				ra = existing
				break
			}
		}
		appendRA := ra == nil
		if appendRA {
			ra = &RAInterfaceConfig{
				Interface: inst.name,
			}
		}

		// #8939: `set … interface ge-0/0/0 managed-configuration
		// default-lifetime 0` nests each leaf under the previous one, so this
		// loop saw only the flag. That RE-CREATES #4119 BY A DIFFERENT ROUTE:
		// DefaultLifetimeSet stays false, and pkg/ra/sender.go falls back to
		// defaultRouterLifetime (1800) -- so an EXPLICIT `default-lifetime 0`,
		// which RFC 4861 6.2.1 defines as "this router is NOT a default
		// router", is advertised as 1800 and the router hijacks host
		// default-route selection on a multi-router LAN. #4119 fixed the
		// `lifetime <= 0` coercion in the sender; the flat spelling reaches the
		// identical outcome by never setting the flag at all.
		for _, prop := range expandFlatRun(inst.node.Children, raInterfaceSchema8939()) {
			switch prop.Name() {
			case "managed-configuration":
				ra.ManagedConfig = true
			case "other-stateful-configuration":
				ra.OtherStateful = true
			case "default-lifetime":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						// #4119: record that default-lifetime was set
						// explicitly so the sender preserves an explicit 0
						// (RFC 4861 §6.2.1 "not a default router") instead of
						// re-defaulting it to 1800. An absent leaf leaves
						// DefaultLifetimeSet false → 1800 default.
						ra.DefaultLifetime = n
						ra.DefaultLifetimeSet = true
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
			case "reachable-time":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						ra.ReachableTime = n
					}
				}
			case "retransmit-timer":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						ra.RetransTimer = n
					}
				}
			case "dns-server-address":
				// #6695: `dns-server-address` is `multi: true`, so a bracketed
				// list (`dns-server-address [ 2001:db8::53 2001:db8::54 ]`)
				// collapses onto ONE node's Keys and the hierarchical BLOCK
				// spelling puts every address in Children. The pre-fix read
				// took Keys[1] alone — it kept the first bracket entry and
				// compiled NOTHING at all from the block spelling — so hosts
				// on the link learned one RDNSS server while `show
				// configuration` displayed both. The redundancy was invisible
				// until the primary resolver failed, which is exactly when the
				// fallback was supposed to matter.
				//
				// firewallMatchValues reads BOTH sides and skips empty tokens;
				// every value it returns is installed into a single RFC 8106
				// RecursiveDNSServer option by the sender (pkg/ra), so
				// "absent" is the right reading of an empty token. Widening is
				// safe on the validation axis because validateMultiValueLeaf
				// (schema_walk.go) runs the leaf's ValidateIPv6Address over
				// EVERY token of Keys[1:] and every block-child, not just the
				// first (#2497).
				ra.DNSServers = append(ra.DNSServers, firewallMatchValues(prop)...)
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
					// #9235: `prefix 2001:db8::/64 no-onlink no-autonomous` packs
					// the flags into a nested chain, so this loop read `no-onlink`
					// and left Autonomous at its `true` default -- the RA told hosts
					// to SLAAC-configure a prefix the operator had explicitly
					// marked no-autonomous. Lenient path only.
					for _, child := range expandRunChildren9235(pfxChildren, raPrefixSchema9235()) {
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

		if appendRA {
			proto.RouterAdvertisement = append(proto.RouterAdvertisement, ra)
		}
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

// instanceValueTail returns an instance node's trailing VALUE tokens — the
// keys that follow its NAME — for both node shapes namedInstances can hand
// back (#7568).
//
// namedInstances resolves an instance either from a node that carries its own
// name (Keys=["<keyword>", NAME, ...]) or, for the hierarchical block
// spelling, from a SUB-node whose keys begin with the name (Keys=[NAME, ...]).
// Anchoring on the name rather than on a fixed index is what makes a caller
// correct against both: a fixed Keys[2:] panics on the short shape, and a bare
// length guard silently drops a compact value that the block shape
// legitimately carries.
func instanceValueTail(node *Node, name string) []string {
	if node == nil {
		return nil
	}
	if len(node.Keys) >= 2 && node.Keys[1] == name {
		return node.Keys[2:]
	}
	if len(node.Keys) >= 1 && node.Keys[0] == name {
		return node.Keys[1:]
	}
	return nil
}

// parseASNumber parses a BGP AS-number string, returning the value and true
// ONLY when it is a valid 4-byte AS in [1, 4294967295]. A negative, oversized,
// non-numeric, or zero value returns ok=false so the caller leaves the field
// UNSET (zero value) rather than casting a silently-wrapped uint32 into the
// typed config (#4713).
//
// The pre-#4713 parse — `strconv.Atoi(v)` then `uint32(n)` — silently WRAPPED
// out-of-range input onto a different-but-valid ASN: `peer-as -1` became
// remote-as 4294967295, and `peer-as 5000000000` wrapped to 705032704, a
// small-looking ASN. The strict operator commit / commit-check path already
// hard-rejects these at the typed-leaf SchemaValidate gate (#4589,
// ValidateInteger(1, 4294967295) on every peer-as/local-as leaf), naming the
// field and value. This helper closes the LENIENT load / peer-sync path
// (compileTreeLenient), where SchemaValidate is downgraded to a warning so a
// persisted or peer-synced config still boots (#1960): leaving the AS unset
// keeps the FRR renderer's remote-as-0 skip / local-as-0 omit (#2963) in
// force, so a leniently-loaded bad AS is INERT rather than peering under a
// wrong-but-valid ASN. Mirrors the #2963/#2980 "leniently-loaded bad value is
// inert" defense-in-depth doctrine, applied at the parse layer.
//
// ParseUint with bitSize 32 rejects negatives and anything above uint32 max at
// parse; the explicit n == 0 check drops AS 0 (reserved, RFC 7607) so a stray
// `peer-as 0` / `local-as 0` never renders either.
func parseASNumber(v string) (uint32, bool) {
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
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
//
// It delegates to parseBurstSizeLimitStrict and keeps the legacy
// zero-return-on-garbage contract (empty / malformed input compiles as
// "unset"). Crucially, on an OVERFLOWING scaled product it now returns 0
// rather than the wrapped small nonzero value the old inline `v *
// multiplier` produced (#5299): a wrapped burst is a silently-wrong meter,
// whereas 0 is the unambiguous "unset" sentinel and is already rejected
// loud at commit by the ValidatePolicerBurstSize schema gate — only the
// tolerant Store.Load / SyncApply path ever reaches here with a value the
// strict gate downgraded to a warning.
func parseBurstSizeLimit(s string) uint64 {
	v, err := parseBurstSizeLimitStrict(s)
	if err != nil {
		return 0
	}
	return v
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
