Reading prompt from stdin...
OpenAI Codex v0.139.0
--------
workdir: /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
model: gpt-5.5
provider: openai
approval: never
sandbox: workspace-write [workdir, /tmp, $TMPDIR]
reasoning effort: xhigh
reasoning summaries: none
session id: 019ed59b-10b8-7190-874a-bb4e1897f533
--------
user
You are a HOSTILE plan reviewer doing a FOLLOW-UP round (r2) on issue #1914. You reviewed r1 and returned PLAN-NEEDS-REVISION with these findings: F1 (High) gate reusing CompileConfig*/buildTunnelEndpointSnapshots recurses + reads post-usedIDs-drop so Defect A still false-accepts; F2 (High) O1 crux view-1 narrowing under/over-registers; F3 (Medium) speculative node-view expansion error must not be fatal (node0-fallback compat at compiler.go:127-134, TestCompileConfigForNodeBackwardCompat); F4 (Medium) emitter must be config-pure not snapshot-identical.

The plan was revised to r2. Read the UPDATED doc: docs/research/1914-tunnel-endpoint-collision-gate/plan.md (repo /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision, branch research/1914-tunnel-endpoint-collision-gate). Focus on §3.5 (resolved questions), §4.1/4.2/4.3 (the reconciled approach), §5, §6.

Verify each r1 finding is now ADEQUATELY addressed:
1. Does §4.1/§4.2 truly avoid recursion? It proposes: gate clones → ExpandGroupsWithVars(nodeN) → compileInterfaces (compiler_interfaces.go:25, confirm this does NOT call validateTunnelEndpointIDCollisionAST) → EmitTunnelEndpointNames (a NEW config-pure pre-usedIDs emitter). Confirm compileInterfaces is gate-free by reading it. Confirm the emitter is pre-usedIDs so Defect A is caught.
2. Does §3.5-O1 + §4.2 keeping view 1 EXACTLY as-is + documenting Defect-B residual actually preserve all #1873 symmetry coverage AND fix Defect A? Any remaining false-accept?
3. Does §4.3 (per-node expansion error → empty set, not gate error) correctly preserve the node0-fallback and not introduce asymmetry? Confirm both nodes apply identical error-to-empty handling.
4. Is §4.1's emitter/builder boundary (config-pure emitter; builder intersects runtime ifaces + usedIDs) correct, with the mandated differential parity test?
5. Any NEW issue introduced by r2 (e.g., the emitter must mirror the WG-lowest-unit pick / leading-zero / overflow / last-wins logic that collectTunnelEndpointNamesAST and addEndpoint both currently encode — does centralizing into one emitter risk a behavior change vs either current site?).

Read pkg/config/tunnelid.go, pkg/config/compiler_interfaces.go (compileInterfaces), pkg/dataplane/userspace/tunnels.go, pkg/config/compiler.go:115-195. Output PLAN-READY only if all r1 findings are resolved AND no new fatal issue. Otherwise PLAN-NEEDS-REVISION / PLAN-KILL with quoted file:line counter-examples. This is /research — the plan must be sound but NOT include written production code.

codex
I’ll review the revised plan against the actual implementation points you named, with r1’s findings as the checklist. I’m going straight to the plan and the relevant source so any objection is grounded in concrete lines.
exec
/bin/bash -lc "nl -ba pkg/config/compiler_interfaces.go | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"sort"
     6		"strconv"
     7		"strings"
     8	)
     9	
    10	// vrrpGroupPropertyKeywords are the property keywords recognized inside
    11	// a vrrp-group block. Used to delimit multi-value runs (virtual-address)
    12	// when properties are packed into a single node's Keys (#1813).
    13	var vrrpGroupPropertyKeywords = map[string]bool{
    14		"virtual-address":     true,
    15		"priority":            true,
    16		"preempt":             true,
    17		"accept-data":         true,
    18		"advertise-interval":  true,
    19		"authentication-type": true,
    20		"authentication-key":  true,
    21		"track-interface":     true,
    22		"track-priority-cost": true,
    23	}
    24	
    25	func compileInterfaces(node *Node, ifaces *InterfacesConfig) error {
    26		for _, child := range node.Children {
    27			if child.IsLeaf {
    28				continue
    29			}
    30			ifName := child.Name()
    31			ifc := &InterfaceConfig{
    32				Name:  ifName,
    33				Units: make(map[int]*InterfaceUnit),
    34			}
    35	
    36			// Check for description
    37			if descNode := child.FindChild("description"); descNode != nil {
    38				ifc.Description = nodeVal(descNode)
    39			}
    40	
    41			// Interface-level MTU
    42			if mtuNode := child.FindChild("mtu"); mtuNode != nil {
    43				if v := nodeVal(mtuNode); v != "" {
    44					if n, err := strconv.Atoi(v); err == nil {
    45						ifc.MTU = n
    46					}
    47				}
    48			}
    49	
    50			// Speed and duplex (ether-options or gigether-options)
    51			if speedNode := child.FindChild("speed"); speedNode != nil {
    52				ifc.Speed = nodeVal(speedNode)
    53			}
    54			if duplexNode := child.FindChild("duplex"); duplexNode != nil {
    55				ifc.Duplex = nodeVal(duplexNode)
    56			}
    57			if child.FindChild("disable") != nil {
    58				ifc.Disable = true
    59			}
    60	
    61			// Interface bandwidth (bits per second)
    62			if bwNode := child.FindChild("bandwidth"); bwNode != nil {
    63				if v := nodeVal(bwNode); v != "" {
    64					ifc.Bandwidth = parseBandwidthBps(v)
    65				}
    66			}
    67	
    68			// Check for vlan-tagging flag
    69			if child.FindChild("vlan-tagging") != nil {
    70				ifc.VlanTagging = true
    71			}
    72	
    73			// Check for flexible-vlan-tagging flag (QinQ)
    74			if child.FindChild("flexible-vlan-tagging") != nil {
    75				ifc.FlexibleVlanTagging = true
    76			}
    77	
    78			// Check for encapsulation
    79			if encapNode := child.FindChild("encapsulation"); encapNode != nil {
    80				ifc.Encapsulation = nodeVal(encapNode)
    81			}
    82	
    83			// Check for gigether-options redundant-parent and 802.3ad LAG member
    84			if goNode := child.FindChild("gigether-options"); goNode != nil {
    85				if rpNode := goNode.FindChild("redundant-parent"); rpNode != nil {
    86					ifc.RedundantParent = nodeVal(rpNode)
    87				}
    88				if adNode := goNode.FindChild("802.3ad"); adNode != nil {
    89					ifc.LAGParent = nodeVal(adNode)
    90				}
    91			}
    92	
    93			// Check for aggregated-ether-options (LAG/ae interface)
    94			if aeoNode := child.FindChild("aggregated-ether-options"); aeoNode != nil {
    95				opts := &AggregatedEtherOptions{}
    96				if lacpNode := aeoNode.FindChild("lacp"); lacpNode != nil {
    97					if lacpNode.FindChild("active") != nil {
    98						opts.LACPActive = true
    99					}
   100					if lacpNode.FindChild("passive") != nil {
   101						opts.LACPPassive = true
   102					}
   103					if periodicNode := lacpNode.FindChild("periodic"); periodicNode != nil {
   104						opts.LACPPeriodic = nodeVal(periodicNode)
   105					}
   106				}
   107				if lsNode := aeoNode.FindChild("link-speed"); lsNode != nil {
   108					opts.LinkSpeed = nodeVal(lsNode)
   109				}
   110				if mlNode := aeoNode.FindChild("minimum-links"); mlNode != nil {
   111					if v := nodeVal(mlNode); v != "" {
   112						opts.MinimumLinks, _ = strconv.Atoi(v)
   113					}
   114				}
   115				ifc.AggregatedEtherOpts = opts
   116			}
   117	
   118			// Check for redundant-ether-options redundancy-group
   119			if reoNode := child.FindChild("redundant-ether-options"); reoNode != nil {
   120				if rgNode := reoNode.FindChild("redundancy-group"); rgNode != nil {
   121					if v, err := strconv.Atoi(nodeVal(rgNode)); err == nil {
   122						ifc.RedundancyGroup = v
   123					}
   124				}
   125			}
   126	
   127			// Check for fabric-options member-interfaces
   128			if foNode := child.FindChild("fabric-options"); foNode != nil {
   129				if miNode := foNode.FindChild("member-interfaces"); miNode != nil {
   130					for _, m := range miNode.Children {
   131						ifc.FabricMembers = append(ifc.FabricMembers, m.Name())
   132					}
   133				}
   134				if len(ifc.FabricMembers) > 0 {
   135					ifc.BondMode = "active-backup"
   136				}
   137			}
   138	
   139			// Check for interface-level tunnel configuration
   140			tunnelNode := child.FindChild("tunnel")
   141			if tunnelNode != nil {
   142				// Default mode based on interface name prefix: ip-X/X/X → ipip, gr-X/X/X → gre
   143				defaultMode := "gre"
   144				if strings.HasPrefix(ifName, "ip-") {
   145					defaultMode = "ipip"
   146				}
   147				tc := &TunnelConfig{
   148					Name: LinuxIfName(ifName),
   149					Mode: defaultMode,
   150				}
   151				for _, prop := range tunnelNode.Children {
   152					switch prop.Name() {
   153					case "source":
   154						if len(prop.Keys) >= 2 {
   155							tc.Source = prop.Keys[1]
   156						}
   157					case "destination":
   158						if len(prop.Keys) >= 2 {
   159							tc.Destination = prop.Keys[1]
   160						}
   161					case "mode":
   162						if len(prop.Keys) >= 2 {
   163							tc.Mode = prop.Keys[1]
   164						}
   165					case "key":
   166						if len(prop.Keys) >= 2 {
   167							if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
   168								tc.Key = uint32(v)
   169							}
   170						}
   171					case "ttl":
   172						if len(prop.Keys) >= 2 {
   173							if v, err := strconv.Atoi(prop.Keys[1]); err == nil {
   174								tc.TTL = v
   175							}
   176						}
   177					case "keepalive":
   178						if v := nodeVal(prop); v != "" {
   179							if n, err := strconv.Atoi(v); err == nil {
   180								tc.Keepalive = n
   181							}
   182						}
   183					case "keepalive-retry":
   184						if v := nodeVal(prop); v != "" {
   185							if n, err := strconv.Atoi(v); err == nil {
   186								tc.KeepaliveRetry = n
   187							}
   188						}
   189					case "routing-instance":
   190						// routing-instance { destination <name>; }
   191						if destNode := prop.FindChild("destination"); destNode != nil {
   192							tc.RoutingInstance = nodeVal(destNode)
   193						} else if v := nodeVal(prop); v != "" {
   194							tc.RoutingInstance = v
   195						}
   196					case "wireguard":
   197						parseTunnelWireguard(tc, prop)
   198					}
   199				}
   200				ifc.Tunnel = tc
   201			}
   202	
   203			for _, unitInst := range namedInstances(child.FindChildren("unit")) {
   204				unitNum, err := strconv.Atoi(unitInst.name)
   205				if err != nil {
   206					continue
   207				}
   208				unit := &InterfaceUnit{Number: unitNum}
   209	
   210				// Parse description on unit
   211				if descNode := unitInst.node.FindChild("description"); descNode != nil {
   212					unit.Description = nodeVal(descNode)
   213				}
   214	
   215				// Parse point-to-point flag
   216				if unitInst.node.FindChild("point-to-point") != nil {
   217					unit.PointToPoint = true
   218				}
   219	
   220				// Parse tunnel config at unit level (gr-0/0/0 unit N { tunnel { ... } })
   221				if tunnelNode := unitInst.node.FindChild("tunnel"); tunnelNode != nil {
   222					defaultMode := "gre"
   223					if strings.HasPrefix(ifName, "ip-") {
   224						defaultMode = "ipip"
   225					}
   226					// Per-unit tunnel: each unit with its own tunnel config gets
   227					// a separate Linux interface. Unit 0 uses the base name,
   228					// unit N>0 appends "uN".
   229					linuxName := LinuxIfName(ifName)
   230					if unitNum > 0 {
   231						linuxName = linuxName + "u" + strconv.Itoa(unitNum)
   232					}
   233					tc := &TunnelConfig{Name: linuxName, Mode: defaultMode}
   234					// Inherit from interface-level tunnel if present
   235					if ifc.Tunnel != nil {
   236						*tc = *ifc.Tunnel
   237						tc.Name = linuxName
   238					}
   239					for _, prop := range tunnelNode.Children {
   240						switch prop.Name() {
   241						case "source":
   242							if v := nodeVal(prop); v != "" {
   243								tc.Source = v
   244							}
   245						case "destination":
   246							if v := nodeVal(prop); v != "" {
   247								tc.Destination = v
   248							}
   249						case "routing-instance":
   250							if destNode := prop.FindChild("destination"); destNode != nil {
   251								tc.RoutingInstance = nodeVal(destNode)
   252							} else if v := nodeVal(prop); v != "" {
   253								tc.RoutingInstance = v
   254							}
   255						case "mode":
   256							if v := nodeVal(prop); v != "" {
   257								tc.Mode = v
   258							}
   259						case "key":
   260							if v := nodeVal(prop); v != "" {

exec
/bin/bash -lc "nl -ba pkg/config/tunnelid.go | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
exec
/bin/bash -lc "nl -ba docs/research/1914-tunnel-endpoint-collision-gate/plan.md | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"hash/fnv"
     6		"sort"
     7		"strconv"
     8	)
     9	
    10	// StableTunnelEndpointID maps a tunnel interface name (unit-qualified,
    11	// e.g. "wg0.0", "gr-0/0/0.0") to a stable nonzero u16 tunnel-endpoint
    12	// id: FNV-1a 64 xor-folded to 16 bits, mapped into [1, 0xFFFF].
    13	//
    14	// THE FOLD IS WIRE-ADJACENT AND MUST NEVER CHANGE (#1873): tunnel
    15	// endpoint ids cross the cluster as bare numbers (SessionValue.FibGen
    16	// in pkg/cluster/sync_protocol.go), and both HA nodes must compute
    17	// identical ids from identical config. The id is a pure function of
    18	// the interface NAME alone — never of runtime state, the rest of the
    19	// tunnel set, or allocation history — so adding or removing one
    20	// tunnel can never renumber another (the positional-id defect this
    21	// replaces), and both nodes agree by construction.
    22	//
    23	// 0 is never returned: id 0 means "not a tunnel" across the
    24	// dataplane.
    25	func StableTunnelEndpointID(name string) uint16 {
    26		h := fnv.New64a()
    27		_, _ = h.Write([]byte(name))
    28		s := h.Sum64()
    29		folded := uint16(s) ^ uint16(s>>16) ^ uint16(s>>32) ^ uint16(s>>48)
    30		return folded%0xFFFF + 1
    31	}
    32	
    33	// collectTunnelEndpointNamesAST appends the unit-qualified tunnel
    34	// endpoint names declared under one "interfaces" hierarchy node,
    35	// mirroring buildTunnelEndpointSnapshots naming exactly:
    36	//
    37	//   - interface-level tunnel, no COMPILABLE units -> "name"
    38	//   - interface-level WIREGUARD tunnel with units -> "name.N" of the
    39	//     lowest numeric unit only (one persistent TUN = one endpoint,
    40	//     #1910 r2/r3 Codex) — registering every unit would model ids the
    41	//     builder never publishes and could falsely reject a commit on a
    42	//     collision involving a never-emitted ref
    43	//   - interface-level non-WG tunnel with units    -> "name.N" per unit
    44	//   - unit-level tunnel                           -> "name.N"
    45	//
    46	// Every registered ref is the CANONICAL decimal form "%s.%d" of an
    47	// Atoi-parsed unit number, because that is all the builder can ever
    48	// emit: the typed compiler skips any unit whose name fails
    49	// strconv.Atoi (compiler_interfaces.go), so iface.Units holds ints
    50	// and the builder formats "%s.%d". Hashing a raw spelling diverges
    51	// both ways (#1910 r4/r5 Codex): `unit 01` must hash as "wg0.1" or
    52	// the gate misses a real collision on the emitted ref, and an
    53	// overflow-only spelling like `unit 999…9` must NOT register a raw
    54	// ref the builder cannot emit — with every unit unparseable,
    55	// iface.Units is empty and the builder emits the BARE interface ref,
    56	// so the gate registers the bare name in that case too.
    57	//
    58	// Handles both AST shapes (hierarchical merged keys and flat-set
    59	// single-key chains) via the same namedInstances helper the compiler
    60	// uses for unit nodes.
    61	func collectTunnelEndpointNamesAST(ifacesNode *Node, out map[string]struct{}) {
    62		if ifacesNode == nil {
    63			return
    64		}
    65		for _, iface := range ifacesNode.Children {
    66			if iface.IsLeaf {
    67				continue
    68			}
    69			name := iface.Name()
    70			if name == "" {
    71				continue
    72			}
    73			tunnelNode := iface.FindChild("tunnel")
    74			hasIfaceTunnel := tunnelNode != nil
    75			units := namedInstances(iface.FindChildren("unit"))
    76			// Mirror the typed compiler's unit admission: only
    77			// Atoi-parseable names become InterfaceUnit entries, and a
    78			// duplicate spelling of the same number (`unit 00` then
    79			// `unit 0`) OVERWRITES — the compiler does
    80			// `ifc.Units[unitNum] = unit` per instance, so the LAST
    81			// declared instance wins and only ITS tunnel node counts
    82			// (#1910 r6 Codex: sticky-OR here would falsely reject a
    83			// collision on a ref whose tunnel lives only on an
    84			// overwritten earlier instance).
    85			unitNums := make([]int, 0, len(units))
    86			unitTunnel := make(map[int]bool, len(units))
    87			for _, unit := range units {
    88				n, err := strconv.Atoi(unit.name)
    89				if err != nil {
    90					continue
    91				}
    92				if _, seen := unitTunnel[n]; !seen {
    93					unitNums = append(unitNums, n)
    94				}
    95				unitTunnel[n] = unit.node.FindChild("tunnel") != nil
    96			}
    97			if hasIfaceTunnel {
    98				if len(unitNums) == 0 {
    99					// No unit compiles (none declared, or none parses):
   100					// the builder sees len(iface.Units)==0 and emits the
   101					// bare interface ref.
   102					out[name] = struct{}{}
   103					continue
   104				}
   105				if astTunnelModeWireguard(tunnelNode) {
   106					lowest := unitNums[0]
   107					for _, n := range unitNums[1:] {
   108						if n < lowest {
   109							lowest = n
   110						}
   111					}
   112					out[fmt.Sprintf("%s.%d", name, lowest)] = struct{}{}
   113					continue
   114				}
   115				for _, n := range unitNums {
   116					out[fmt.Sprintf("%s.%d", name, n)] = struct{}{}
   117				}
   118				continue
   119			}
   120			for _, n := range unitNums {
   121				if unitTunnel[n] {
   122					out[fmt.Sprintf("%s.%d", name, n)] = struct{}{}
   123				}
   124			}
   125		}
   126	}
   127	
   128	// astTunnelModeWireguard reports whether a tunnel AST node carries an
   129	// explicit `mode wireguard` — the exact extraction the compiler uses
   130	// for TunnelConfig.Mode (prop Keys[1], compiler_interfaces.go), so the
   131	// collision gate's single-endpoint selection matches the compiled
   132	// outcome by construction. The compiler's prefix-derived default mode
   133	// is only ever gre/ipip, so wireguard is always explicit.
   134	func astTunnelModeWireguard(tunnelNode *Node) bool {
   135		if tunnelNode == nil {
   136			return false
   137		}
   138		for _, prop := range tunnelNode.Children {
   139			if prop.Name() == "mode" && len(prop.Keys) >= 2 && prop.Keys[1] == "wireguard" {
   140				return true
   141			}
   142		}
   143		return false
   144	}
   145	
   146	// validateTunnelEndpointIDCollisionAST checks the UNION of tunnel
   147	// endpoint names across the main "interfaces" hierarchy AND every
   148	// "groups" block for StableTunnelEndpointID collisions (#1873 R-B).
   149	//
   150	// The union (rather than the per-node effective config) keeps the
   151	// accept/reject decision identical on both chassis-cluster nodes: a
   152	// collision involving a `groups node0`-scoped tunnel must fail commit
   153	// on node1 too, or config-sync would split (originator accepts, peer
   154	// rejects). It runs on the PRE-expansion tree because ExpandGroups
   155	// removes the groups stanza.
   156	//
   157	// Strict (commit / commit-check) returns an error; lenient (load /
   158	// peer-sync of an already-active config) returns a warning so an
   159	// upgraded node still boots — the snapshot builder independently
   160	// drops the later-sorting collider (fail-closed belt-and-braces in
   161	// buildTunnelEndpointSnapshots).
   162	func validateTunnelEndpointIDCollisionAST(tree *ConfigTree, lenient bool) ([]string, error) {
   163		names := make(map[string]struct{})
   164		collectTunnelEndpointNamesAST(tree.FindChild("interfaces"), names)
   165		for _, child := range tree.Children {
   166			if child.Name() != "groups" {
   167				continue
   168			}
   169			for _, group := range child.Children {
   170				// Node{Keys:["groups","node0"]} merges the group name
   171				// into Keys[1]; the children are then the group body.
   172				if len(child.Keys) >= 2 {
   173					collectTunnelEndpointNamesAST(child.FindChild("interfaces"), names)
   174					break
   175				}
   176				collectTunnelEndpointNamesAST(group.FindChild("interfaces"), names)
   177			}
   178		}
   179		if len(names) < 2 {
   180			return nil, nil
   181		}
   182		sorted := make([]string, 0, len(names))
   183		for name := range names {
   184			sorted = append(sorted, name)
   185		}
   186		sort.Strings(sorted)
   187		byID := make(map[uint16]string, len(sorted))
   188		var warnings []string
   189		for _, name := range sorted {
   190			id := StableTunnelEndpointID(name)
   191			owner, taken := byID[id]
   192			if !taken {
   193				byID[id] = name
   194				continue
   195			}
   196			msg := fmt.Sprintf(
   197				"tunnel endpoint id collision between %q and %q (both fold to %d) — rename one interface (#1873)",
   198				owner, name, id)
   199			if !lenient {
   200				return nil, fmt.Errorf("interfaces: %s", msg)
   201			}
   202			warnings = append(warnings, msg+
   203				"; the later-sorting tunnel is NOT installed in the dataplane")
   204		}
   205		return warnings, nil
   206	}

 succeeded in 0ms:
     1	# Plan of Action — #1914: tunnel-endpoint collision gate, wildcard apply-groups false accept + src/dst-incomplete over-registration
     2	
     3	- **Issue:** #1914
     4	- **Mode:** `/research` — STOP at PLAN-READY. No PR, no production code.
     5	- **Revision:** r2 (incorporates Claude SMR + Codex + AGY r1 — three-way
     6	  PLAN-NEEDS-REVISION converged on recursion hazard, pre-`usedIDs`
     7	  enumeration, peer-group expansion-error handling, and the O1 crux)
     8	- **Branch:** `research/1914-tunnel-endpoint-collision-gate`
     9	- **Base:** `origin/master` @ `26e4a112d`
    10	- **Author:** Claude (research driver)
    11	
    12	---
    13	
    14	## 1. Problem statement
    15	
    16	`validateTunnelEndpointIDCollisionAST` (`pkg/config/tunnelid.go:162`) is the
    17	#1873 R-B commit-time gate that fails a commit when two tunnel-endpoint
    18	interface names fold to the same 16-bit `StableTunnelEndpointID`. It runs
    19	on the **pre-expansion** AST (before `ExpandGroups`) by design: it collects
    20	the **union** of tunnel names from `interfaces` and every `groups` block so
    21	both HA nodes accept/reject identically (pre-expansion union is a pure
    22	function of the candidate config, so node0 and node1 compute the same
    23	verdict regardless of which `${node}`-scoped group each would actually
    24	apply).
    25	
    26	Two defects, both **pre-existing since #1873 R-B landed** (PR #1882) and
    27	neither widened nor narrowed by PR #1910/#1904. Found by Codex r6 during
    28	PR #1910 review.
    29	
    30	### 1.1 Defect A — wildcard apply-groups false accept (High)
    31	
    32	`collectTunnelEndpointNamesAST` hashes the **literal** group-AST interface
    33	name. A wildcard group:
    34	
    35	```
    36	set groups wgtun interfaces <*> unit 0 tunnel mode wireguard
    37	set interfaces wg78   apply-groups wgtun
    38	set interfaces wg1408 unit 0 tunnel mode wireguard
    39	```
    40	
    41	registers the gate ref `<*>.0` (id **50477**), never the concrete
    42	post-expansion `wg78.0` (id **824**). The literal `wg1408.0` registers id
    43	**824**. The gate sees `{<*>.0=50477, wg1408.0=824}` — no collision —
    44	and **accepts the commit**. But `ExpandGroups`' wildcard merge
    45	(`mergeNodes`, `ast_groups.go:236`) splices the `unit 0 tunnel mode
    46	wireguard` body onto the **existing** `wg78` interface container, so the
    47	typed compiler emits `wg78.0` AND `wg1408.0`, **both fold to 824**. The
    48	snapshot builder's `usedIDs` belt (`tunnels.go:101`) then drops the
    49	later-sorting one with a loud `slog.Error` — a deterministic runtime drop
    50	instead of a commit rejection.
    51	
    52	**Confirmed empirically** (this research, throwaway test against master):
    53	the above three-line config compiles clean with zero warnings; both
    54	`wg78.unit0` and `wg1408.unit0` carry wireguard `TunnelConfig` in the typed
    55	`cfg.Interfaces.Interfaces` map. Folds verified live: `<*>.0`=50477,
    56	`wg78.0`=`wg1408.0`=824.
    57	
    58	**Severity rationale:** a real builder-emitted collision escapes the
    59	strict commit gate. The runtime belt keeps both nodes consistent (same
    60	deterministic drop), so it is not a split-brain / TCP-death class bug — it
    61	is a "loud silent" drop: one tunnel never installs and the operator only
    62	learns from `slog.Error`, not a commit error. Wildcard WG groups are rare;
    63	the per-pair fold-collision probability is 1/65535.
    64	
    65	### 1.2 Defect B — src/dst-incomplete non-WG tunnels over-registered (Medium)
    66	
    67	`collectTunnelEndpointNamesAST` registers a ref from **tunnel-node
    68	presence alone**. But the builder's `addEndpoint` (`tunnels.go:62`) drops
    69	any **non-WireGuard** tunnel whose `Source` or `Destination` is empty:
    70	
    71	```go
    72	if !isWireguard && (tunnel.Source == "" || tunnel.Destination == "") {
    73	    return
    74	}
    75	```
    76	
    77	So a half-configured GRE (`set interfaces gr-0/0/0 unit 0 tunnel mode
    78	gre`, no source/dest) registers a gate ref the builder will never emit.
    79	**Confirmed empirically:** the gate registers `gr-0/0/0.0` for exactly
    80	this shape. If that phantom ref collides (1/65535 per pair) with a *real*
    81	emitted ref, the commit is **falsely rejected** — the operator cannot
    82	commit a config the builder would have accepted.
    83	
    84	**Why it is conservative-by-design today:** AST-level src/dst presence
    85	cannot be judged reliably pre-expansion, because apply-groups can SUPPLY
    86	the source/destination later. A pre-expansion collector that modeled the
    87	src/dst gate would **under-register** (false ACCEPT — strictly worse than a
    88	false REJECT). So the current over-register is the safe direction given
    89	the pre-expansion constraint. Item B is only fully fixable if the collector
    90	sees an expanded view (couples to Defect A's fix).
    91	
    92	---
    93	
    94	## 2. Current behavior walk (code-grounded)
    95	
    96	| Layer | Function | File:line | Sees groups? | src/dst gate? | wildcard? |
    97	|-------|----------|-----------|--------------|---------------|-----------|
    98	| Commit gate | `validateTunnelEndpointIDCollisionAST` | `tunnelid.go:162` | union, **pre-expansion** | no | hashes `<*>` literally |
    99	| Gate collector | `collectTunnelEndpointNamesAST` | `tunnelid.go:61` | per-block | no (presence-only) | literal name |
   100	| Hash | `StableTunnelEndpointID` | `tunnelid.go:25` | — | — | — |
   101	| Expansion | `ExpandGroups` / `mergeNodes` | `ast_groups.go:13,225` | resolves | — | wildcard merges onto **existing** dst ifaces only |
   102	| Builder | `buildTunnelEndpointSnapshots` / `addEndpoint` | `tunnels.go:13,54` | **post-expansion typed cfg** | **yes** (drops incomplete non-WG) | n/a (concrete names) |
   103	| Runtime belt | `usedIDs` map | `tunnels.go:101` | — | — | deterministic later-sorting drop + `slog.Error` |
   104	
   105	**Key asymmetry:** the gate runs on pre-expansion union AST; the builder
   106	runs on the post-expansion **typed** `cfg.Interfaces.Interfaces`. The gate
   107	therefore cannot see (a) wildcard-expanded concrete names, nor (b)
   108	group-supplied source/destination. The builder sees both but only fails
   109	"loudly silent" via the belt.
   110	
   111	**Important wildcard semantics fact** (proven by reading `mergeNodes`,
   112	`ast_groups.go:236-245`): a wildcard apply-group merges its body onto
   113	interface containers **already present** in the dst tree — it does NOT
   114	synthesize new interfaces. So the post-expansion concrete name set is
   115	exactly `{ interfaces that (a) exist in the candidate AND (b) reference the
   116	wildcard group via apply-groups }`. This bounds the cardinality and makes
   117	post-expansion enumeration tractable.
   118	
   119	**HA-symmetry invariant (the thing #1873 chose pre-expansion to protect):**
   120	the accept/reject verdict must be a pure function of the candidate config
   121	(identical bytes on both nodes ⇒ identical verdict), so config-sync never
   122	splits (originator accepts, peer rejects). Any fix MUST preserve this. A
   123	naive "expand for *this* node then collect" breaks it, because `${node}`
   124	resolves differently on node0 vs node1.
   125	
   126	---
   127	
   128	## 3. Design space — Multiple Path Options
   129	
   130	This is a **design-decision** issue (the issue body says so). Four viable
   131	paths, with the HA-symmetry invariant as the hard constraint.
   132	
   133	### Path 1 — Union of {pre-expansion} ∪ {post-expansion node0} ∪ {post-expansion node1}, all computed from the same candidate tree (RECOMMENDED)
   134	
   135	Collect gate names from THREE views, all derived from the SAME candidate
   136	AST on both nodes:
   137	
   138	1. the existing pre-expansion union (unchanged — preserves the
   139	   group-scoped-collision coverage that
   140	   `TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric` pins), PLUS
   141	2. the concrete tunnel names the builder would emit after expanding for
   142	   node0, PLUS
   143	3. the concrete tunnel names the builder would emit after expanding for
   144	   node1.
   145	
   146	Because (2) and (3) are *both* computed on *both* nodes from the *same*
   147	candidate config, the union is still a pure function of config ⇒ still
   148	symmetric. node0 expanding "what would node1 see" is deterministic (it is
   149	just `ExpandGroupsWithVars(node1)` on the shared candidate). The gate
   150	rejects if ANY of the three views contains a fold collision.
   151	
   152	To make (2)/(3) faithful to the builder — including the src/dst gate
   153	(Defect B), the WG single-lowest-unit pick, the leading-zero/overflow unit
   154	canonicalization, and last-wins duplicate-unit — the cleanest realization
   155	is to **reuse the actual builder path**: for each node, clone → expand →
   156	`CompileConfig*` → `buildTunnelEndpointSnapshots` → read back the emitted
   157	endpoint names, OR factor the name-emission out of `addEndpoint` into a
   158	pure `config`-package helper the builder also calls (single source of
   159	truth). See §4 for the SSOT factoring.
   160	
   161	- **Defect A:** FIXED — post-expansion views contain `wg78.0`, collision
   162	  with `wg1408.0` detected → commit rejected.
   163	- **Defect B:** FIXED — views are built through the real src/dst gate, so
   164	  incomplete non-WG tunnels are not registered (and group-supplied src/dst
   165	  IS modeled, because expansion ran first). No phantom refs.
   166	- **HA-symmetry:** PRESERVED — all three views are pure functions of the
   167	  shared candidate config; both nodes compute the identical union.
   168	- **Complexity:** Medium-high. Needs the builder's name-emission logic
   169	  reachable from the gate (SSOT factoring) and two extra expand+compile
   170	  passes at commit time (cost: commit is not hot-path; acceptable).
   171	- **Risk:** the pre-expansion union (view 1) must STAY, or a collision
   172	  hidden entirely in an un-applied `groups node1` block (no apply-groups on
   173	  either node — see the existing symmetry test) would stop being caught.
   174	  Keep all three; the union is monotone (more refs ⇒ stricter), so adding
   175	  views can only ADD rejects, never remove the existing ones. That makes
   176	  Defect-B's de-registration the ONLY direction that could *relax* a
   177	  reject — and it only relaxes phantom (never-emitted) refs, which is
   178	  correct.
   179	
   180	  Subtle interaction: view 1 (pre-expansion, presence-only) STILL
   181	  over-registers incomplete GRE refs. So keeping view 1 unchanged does NOT
   182	  fix Defect B by itself — view 1 would still phantom-reject. **Resolution:**
   183	  view 1's role narrows to "catch group-scoped collisions invisible to any
   184	  single node's expansion"; to avoid re-introducing the Defect-B phantom,
   185	  view 1 must ALSO be built through a src/dst-aware collector — but
   186	  pre-expansion it cannot judge group-supplied src/dst. **This is the crux
   187	  the reviewers must rule on** (see §3.5 open question O1). The honest
   188	  framing: Path 1 fixes A cleanly; fixing B fully requires either dropping
   189	  view 1's incomplete-GRE refs (re-opening the theoretical group-supplied
   190	  under-register — but views 2/3 now cover the applied cases) or accepting
   191	  that view 1 still over-registers for the *un-applied-group* corner only.
   192	
   193	### Path 2 — Expand wildcards inside the collision pass only
   194	
   195	Keep the gate pre-expansion but teach `collectTunnelEndpointNamesAST` to
   196	resolve `<*>` group refs against the set of interfaces that apply that
   197	group, producing concrete names — a narrow, gate-local mini-expander.
   198	
   199	- **Defect A:** FIXED for the wildcard case.
   200	- **Defect B:** NOT fixed (still presence-only).
   201	- **HA-symmetry:** PRESERVED if the mini-expander is a pure function of the
   202	  candidate (it is).
   203	- **Complexity:** Medium, but introduces a SECOND expansion implementation
   204	  that must track `mergeNodes` wildcard semantics forever (drift risk —
   205	  exactly the class of bug #1910 r2-r6 kept finding when the gate's unit
   206	  logic drifted from the builder's). **Anti-pattern per the repo's own
   207	  history.** Rejected unless Path 1's cost is prohibitive.
   208	
   209	### Path 3 — Gate only complete src+dst tunnels (Defect B narrow fix)
   210	
   211	For non-WG tunnels, register a gate ref only when source AND destination
   212	are present in the AST (mirror the builder's gate).
   213	
   214	- **Defect A:** NOT fixed.
   215	- **Defect B:** PARTIALLY fixed — but pre-expansion it cannot see
   216	  group-supplied src/dst, so it would UNDER-register (false ACCEPT) when a
   217	  group supplies the missing endpoint. The issue body explicitly calls this
   218	  out as "worse than" the current over-register. Rejected as a standalone
   219	  fix.
   220	
   221	### Path 4 — Accept as documented limitation (do nothing structural)
   222	
   223	Document both gaps in `tunnelid.go` + an operator doc, lean on the runtime
   224	`usedIDs` belt + `slog.Error`, and add a metric/log so the silent drop is
   225	observable. Optionally add a `commit` warning that says "wildcard
   226	apply-groups tunnel refs are not collision-checked at commit; a collision
   227	will be dropped at runtime."
   228	
   229	- **Defect A:** UNFIXED, documented.
   230	- **Defect B:** UNFIXED, documented.
   231	- **HA-symmetry:** trivially preserved (no change).
   232	- **Complexity:** Trivial. Honest about the 1/65535 × rare-feature joint
   233	  probability.
   234	- **Risk:** leaves a real (if rare) false-accept. Acceptable ONLY if the
   235	  reviewers judge the joint probability (wildcard WG group × 16-bit fold
   236	  collision) negligible and the runtime belt sufficient.
   237	
   238	---
   239	
   240	## 3.5 Resolved design questions (after r1 three-way review)
   241	
   242	All four r1 reviewers (Claude SMR + Codex + AGY) converged on the answers
   243	below; they are now design decisions, not open questions.
   244	
   245	- **O1 (crux) — RESOLVED: view 1 stays byte-identical (presence-only
   246	  union).** Both the "narrow view 1 to complete-only" and "make view 1
   247	  src/dst-aware" ideas are provably unsound:
   248	  - Split-supply (Claude SMR, proven): `set interfaces gr-0/0/9 unit 0
   249	    tunnel mode gre` with src/dst supplied by an applied group → a
   250	    complete-only pre-expansion view 1 UNDER-registers (the literal AST has
   251	    no src/dst), missing a real emitted ref.
   252	  - Un-applied nested-apply-groups group (AGY F3 + Codex F2, proven shape):
   253	    `groups group-c interfaces gr-0/0/0 unit 0 {tunnel mode gre;
   254	    apply-groups my-group}` where `my-group` supplies src/dst, `group-c`
   255	    un-applied → a complete-only view 1 drops `gr-0/0/0.0`, views 2/3 never
   256	    expand the un-applied group, the ref is registered NOWHERE → **false
   257	    ACCEPT**, violating the #1873 group-symmetry invariant.
   258	
   259	  Therefore view 1 MUST remain the existing presence-only union. Its
   260	  Defect-B over-registration (phantom for an incomplete non-WG tunnel that

exec
/bin/bash -lc 'git status --short --branch' in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
## research/1914-tunnel-endpoint-collision-gate...origin/research/1914-tunnel-endpoint-collision-gate

codex
The branch matches the requested research branch. I’ve confirmed the current `compileInterfaces` entry point is plain typed-interface compilation, and I’m checking the rest of that file plus the runtime builder and compiler fallback path before judging the plan.
exec
/bin/bash -lc "nl -ba pkg/config/compiler_interfaces.go | sed -n '260,560p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
   260							if v := nodeVal(prop); v != "" {
   261								if n, err := strconv.Atoi(v); err == nil {
   262									tc.Key = uint32(n)
   263								}
   264							}
   265						case "ttl":
   266							if v := nodeVal(prop); v != "" {
   267								if n, err := strconv.Atoi(v); err == nil {
   268									tc.TTL = n
   269								}
   270							}
   271						case "keepalive":
   272							if v := nodeVal(prop); v != "" {
   273								if n, err := strconv.Atoi(v); err == nil {
   274									tc.Keepalive = n
   275								}
   276							}
   277						case "keepalive-retry":
   278							if v := nodeVal(prop); v != "" {
   279								if n, err := strconv.Atoi(v); err == nil {
   280									tc.KeepaliveRetry = n
   281								}
   282							}
   283						case "wireguard":
   284							parseTunnelWireguard(tc, prop)
   285						}
   286					}
   287					unit.Tunnel = tc
   288				}
   289	
   290				// Parse vlan-id on unit
   291				if vlanNode := unitInst.node.FindChild("vlan-id"); vlanNode != nil {
   292					if v := nodeVal(vlanNode); v != "" {
   293						if n, err := strconv.Atoi(v); err == nil {
   294							unit.VlanID = n
   295						}
   296					}
   297				}
   298	
   299				// Parse inner-vlan-id on unit (QinQ inner tag)
   300				if ivNode := unitInst.node.FindChild("inner-vlan-id"); ivNode != nil {
   301					if v := nodeVal(ivNode); v != "" {
   302						if n, err := strconv.Atoi(v); err == nil {
   303							unit.InnerVlanID = n
   304						}
   305					}
   306				}
   307	
   308				// Handle two AST shapes:
   309				// - set commands:  family { inet { address ...; dhcp; } }
   310				//   Keys=["family"], child Keys=["inet"] with grandchildren
   311				// - hierarchical:  family inet { address ...; dhcp; }
   312				//   Keys=["family","inet"], children are address/dhcp directly
   313				for _, familyNode := range unitInst.node.FindChildren("family") {
   314					var afNodes []*Node
   315					if len(familyNode.Keys) >= 2 {
   316						afNodes = append(afNodes, familyNode)
   317					} else {
   318						afNodes = append(afNodes, familyNode.Children...)
   319					}
   320					for _, afNode := range afNodes {
   321						afName := afNode.Keys[0]
   322						if len(afNode.Keys) >= 2 {
   323							afName = afNode.Keys[1]
   324						}
   325						switch afName {
   326						case "inet":
   327							for _, addrInst := range namedInstances(afNode.FindChildren("address")) {
   328								unit.Addresses = append(unit.Addresses, addrInst.name)
   329								// Check for primary/preferred flags
   330								if addrInst.node.FindChild("primary") != nil {
   331									unit.PrimaryAddress = addrInst.name
   332								}
   333								if addrInst.node.FindChild("preferred") != nil {
   334									unit.PreferredAddress = addrInst.name
   335								}
   336								// Parse VRRP groups under address. Handles both AST
   337								// shapes (#1796): properties as child nodes
   338								// (hierarchical blocks + schema-structured flat-set)
   339								// AND properties packed into the instance node's
   340								// Keys[2:] (legacy flat-set leaves, one leaf per
   341								// `set ... vrrp-group <id> <prop> <value>` line —
   342								// merged into one group instead of last-leaf-wins).
   343								for _, vrrpInst := range namedInstances(addrInst.node.FindChildren("vrrp-group")) {
   344									groupID, err := strconv.Atoi(vrrpInst.name)
   345									if err != nil {
   346										continue
   347									}
   348									if unit.VRRPGroups == nil {
   349										unit.VRRPGroups = make(map[string]*VRRPGroup)
   350									}
   351									key := fmt.Sprintf("%s_grp%d", addrInst.name, groupID)
   352									vg := unit.VRRPGroups[key]
   353									if vg == nil {
   354										vg = &VRRPGroup{
   355											ID:       groupID,
   356											Priority: 100, // default
   357										}
   358										unit.VRRPGroups[key] = vg
   359									}
   360									// Keys-encoded properties (flat-set leaf shape):
   361									// Keys = ["vrrp-group", "<id>", prop, value, ...].
   362									keys := vrrpInst.node.Keys
   363									for i := 2; i < len(keys); i++ {
   364										switch keys[i] {
   365										case "virtual-address":
   366											// Multi-value (#1813): consume every
   367											// following token up to the next
   368											// recognized property keyword —
   369											// `vrrp-group 1 virtual-address
   370											// [ a b ];` packs all addresses
   371											// inline.
   372											for i+1 < len(keys) && !vrrpGroupPropertyKeywords[keys[i+1]] {
   373												i++
   374												vg.VirtualAddresses = append(vg.VirtualAddresses, keys[i])
   375											}
   376										case "priority":
   377											if i+1 < len(keys) {
   378												i++
   379												vg.Priority, _ = strconv.Atoi(keys[i])
   380											}
   381										case "preempt":
   382											vg.Preempt = true
   383										case "accept-data":
   384											vg.AcceptData = true
   385										case "advertise-interval":
   386											if i+1 < len(keys) {
   387												i++
   388												vg.AdvertiseInterval, _ = strconv.Atoi(keys[i])
   389											}
   390										case "authentication-type":
   391											if i+1 < len(keys) {
   392												i++
   393												vg.AuthType = keys[i]
   394											}
   395										case "authentication-key":
   396											if i+1 < len(keys) {
   397												i++
   398												vg.AuthKey = keys[i]
   399											}
   400										case "track-interface":
   401											if i+1 < len(keys) {
   402												i++
   403												// First-wins (#1814): duplicates in
   404												// the Keys-packed spelling are
   405												// rejected/warned by the AST
   406												// pre-walk; keep the first here so
   407												// lenient semantics are consistent
   408												// with the child-node prune.
   409												if vg.TrackInterface == "" {
   410													vg.TrackInterface = keys[i]
   411												}
   412											}
   413										case "track-priority-cost":
   414											if i+1 < len(keys) {
   415												i++
   416												vg.TrackPriorityDelta, _ = parseTrackCost(keys[i])
   417											}
   418										}
   419									}
   420									// Child-node properties (hierarchical blocks and
   421									// schema-structured flat-set containers).
   422									// Track-interface values are gathered and applied
   423									// AFTER the loop so the nested
   424									// `track-interface <if> { priority-cost <n>; }`
   425									// form wins over the legacy flat sibling
   426									// `track-priority-cost <n>` regardless of node
   427									// order (#1814 — the loop is source-order based).
   428									var (
   429										trackIface          string
   430										trackIfaceSet       bool
   431										nestedTrackCost     int
   432										nestedTrackCostSet  bool
   433										siblingTrackCost    int
   434										siblingTrackCostSet bool
   435									)
   436									for _, prop := range vrrpInst.node.Children {
   437										switch prop.Name() {
   438										case "virtual-address":
   439											// Multi-value spellings (#1813):
   440											// bracketed `virtual-address [ a b ];`
   441											// packs all addresses into Keys[1:]
   442											// (flat-set replay may carry trailing
   443											// values as children); braced block
   444											// `virtual-address { a; b; }` holds
   445											// one child per address. nodeVal kept
   446											// only the first of each.
   447											for _, k := range prop.Keys[1:] {
   448												vg.VirtualAddresses = append(vg.VirtualAddresses, k)
   449											}
   450											for _, child := range prop.Children {
   451												if v := child.Name(); v != "" {
   452													vg.VirtualAddresses = append(vg.VirtualAddresses, v)
   453												}
   454											}
   455										case "priority":
   456											if v := nodeVal(prop); v != "" {
   457												vg.Priority, _ = strconv.Atoi(v)
   458											}
   459										case "preempt":
   460											vg.Preempt = true
   461										case "accept-data":
   462											vg.AcceptData = true
   463										case "advertise-interval":
   464											if v := nodeVal(prop); v != "" {
   465												vg.AdvertiseInterval, _ = strconv.Atoi(v)
   466											}
   467										case "authentication-type":
   468											vg.AuthType = nodeVal(prop)
   469										case "authentication-key":
   470											vg.AuthKey = nodeVal(prop)
   471										case "track-interface":
   472											// The interface name lives in Keys[1]
   473											// (NOT nodeVal — its Children[0]
   474											// fallback would misread the nested
   475											// priority-cost child as the name).
   476											if len(prop.Keys) >= 2 {
   477												trackIface = prop.Keys[1]
   478												trackIfaceSet = true
   479											}
   480											// Nested form (#1814): standard Junos
   481											// `track-interface <if> { priority-cost <n>; }`.
   482											if pc := prop.FindChild("priority-cost"); pc != nil {
   483												if v := nodeVal(pc); v != "" {
   484													if n, ok := parseTrackCost(v); ok {
   485														nestedTrackCost = n
   486														nestedTrackCostSet = true
   487													}
   488												}
   489											}
   490										case "track-priority-cost":
   491											if v := nodeVal(prop); v != "" {
   492												if n, ok := parseTrackCost(v); ok {
   493													siblingTrackCost = n
   494													siblingTrackCostSet = true
   495												}
   496											}
   497										}
   498									}
   499									if trackIfaceSet {
   500										vg.TrackInterface = trackIface
   501									}
   502									if siblingTrackCostSet {
   503										vg.TrackPriorityDelta = siblingTrackCost
   504									}
   505									if nestedTrackCostSet {
   506										// Nested wins over the legacy sibling,
   507										// independent of node order.
   508										vg.TrackPriorityDelta = nestedTrackCost
   509									}
   510								}
   511							}
   512							if dhcpNode := afNode.FindChild("dhcp"); dhcpNode != nil {
   513								unit.DHCP = true
   514								if len(dhcpNode.Children) > 0 {
   515									opts := &DHCPInetOptions{}
   516									for _, prop := range dhcpNode.Children {
   517										switch prop.Name() {
   518										case "lease-time":
   519											if v := nodeVal(prop); v != "" {
   520												opts.LeaseTime, _ = strconv.Atoi(v)
   521											}
   522										case "retransmission-attempt":
   523											if v := nodeVal(prop); v != "" {
   524												opts.RetransmissionAttempt, _ = strconv.Atoi(v)
   525											}
   526										case "retransmission-interval":
   527											if v := nodeVal(prop); v != "" {
   528												opts.RetransmissionInterval, _ = strconv.Atoi(v)
   529											}
   530										case "force-discover":
   531											opts.ForceDiscover = true
   532										}
   533									}
   534									unit.DHCPOptions = opts
   535								}
   536							}
   537							if mtuNode := afNode.FindChild("mtu"); mtuNode != nil {
   538								if v := nodeVal(mtuNode); v != "" {
   539									if n, err := strconv.Atoi(v); err == nil {
   540										unit.MTU = n
   541									}
   542								}
   543							}
   544							if sampNode := afNode.FindChild("sampling"); sampNode != nil {
   545								if sampNode.FindChild("input") != nil {
   546									unit.SamplingInput = true
   547								}
   548								if sampNode.FindChild("output") != nil {
   549									unit.SamplingOutput = true
   550								}
   551							}
   552							if filterNode := afNode.FindChild("filter"); filterNode != nil {
   553								if inputNode := filterNode.FindChild("input"); inputNode != nil {
   554									unit.FilterInputV4 = nodeVal(inputNode)
   555								}
   556								if outputNode := filterNode.FindChild("output"); outputNode != nil {
   557									unit.FilterOutputV4 = nodeVal(outputNode)
   558								}
   559							}
   560						case "inet6":

exec
/bin/bash -lc "nl -ba pkg/config/compiler.go | sed -n '1,240p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"errors"
     5		"fmt"
     6		"net"
     7		"strconv"
     8		"strings"
     9	)
    10	
    11	// ErrDPDKDataplaneRetired is the sentinel error returned at commit
    12	// time when a configuration sets `system dataplane-type dpdk`. External
    13	// API consumers (gRPC orchestration, REST wrappers, CLI tooling) can
    14	// match this with errors.Is rather than substring-searching the wrapped
    15	// error text. The wrapped form is preserved verbatim so the operator-
    16	// facing migration message remains stable; see #1525.
    17	//
    18	// Mirrors the runtime-side dataplane.ErrDPDKBackendRetired sentinel
    19	// introduced by #1527 so the config-time and runtime layers both expose
    20	// structured rejections.
    21	var ErrDPDKDataplaneRetired = errors.New(
    22		"the DPDK dataplane backend has been retired; " +
    23			"use 'set system dataplane-type userspace' " +
    24			"(see #1525)")
    25	
    26	// ErrEBPFDataplaneRetired is the sentinel error returned at commit
    27	// time when a configuration sets `system dataplane-type ebpf`. The
    28	// parse path still accepts the token as a legal value so that
    29	// `load merge` / `load override` of a pre-retirement configuration
    30	// does not syntax-error; this strict validator is what tells the
    31	// operator to migrate.
    32	//
    33	// Mirrors the runtime-side dataplane.ErrEBPFBackendRetired sentinel
    34	// introduced by #1476 so the config-time and runtime layers both
    35	// expose structured rejections. The verbatim message must remain
    36	// stable for downstream tooling that matches by text.
    37	var ErrEBPFDataplaneRetired = errors.New(
    38		"the legacy eBPF dataplane backend has been retired; " +
    39			"use 'set system dataplane-type userspace' " +
    40			"(see #1373)")
    41	
    42	// compileOpts carries per-call compilation policy. It is threaded into
    43	// compileExpanded so the strict commit path and the tolerant
    44	// load/peer-sync path can share the identical compile + group-expansion
    45	// pipeline while differing on a single, narrow validator's severity.
    46	type compileOpts struct {
    47		// #1830 (e): the former lenientEqualFlowWorkerCap flag (#1733) is
    48		// retired along with validateEqualFlowWorkerCapStrict — the
    49		// dataplane no longer caps equal-flow-enforcement at 32 workers, so
    50		// there is no severity to downgrade. The lenient compile entry
    51		// points remain for the flags below.
    52	
    53		// sanitizeFreeTextControlChars (#1798) downgrades the control-
    54		// character gate from a hard compile error to sanitize-in-place
    55		// plus a cfg.Warnings entry. The strict commit / commit-check path
    56		// rejects any value or annotation containing ASCII control
    57		// characters — the lexer maps "\n" inside a quoted string to a
    58		// real newline, which injects arbitrary directives into generated
    59		// networkd/FRR/strongSwan files. The tolerant load / peer-sync /
    60		// peer-display paths must instead scrub the value and keep going
    61		// so an already-persisted bad config cannot blackout-boot a node
    62		// or alarm-loop HA config sync. This check deliberately does NOT
    63		// live in SchemaValidate: the tolerant paths need the value scrubbed
    64		// in place, which the read-only schema walk cannot do (and since
    65		// #1319 PR 2 SchemaValidate violations are themselves downgraded to
    66		// warnings on the tolerant paths — see configstore.compileTreeLenient).
    67		// See freetext.go for the full three-layer design.
    68		sanitizeFreeTextControlChars bool
    69	
    70		// lenientVRRPTrackDuplicates (#1814) downgrades the duplicate
    71		// `track-interface` gate (more than one track-interface statement
    72		// inside a single vrrp-group) from a hard compile error to a
    73		// cfg.Warnings entry with deterministic first-wins pruning of the
    74		// extras. Set ONLY on the tolerant load / peer-sync paths
    75		// (CompileConfigLenient / CompileConfigForNodeLenient) so an
    76		// already-persisted or peer-synced config still boots; candidate
    77		// commit / commit-check stay strict and hard-reject new operator
    78		// edits. Like the other lenient gates, this check deliberately does
    79		// NOT live in SchemaValidate: pruning the duplicates is an AST-level
    80		// compile decision the read-only schema walk cannot make (and since
    81		// #1319 PR 2 SchemaValidate violations only warn on tolerant paths).
    82		lenientVRRPTrackDuplicates bool
    83	}
    84	
    85	// CompileConfig converts a parsed ConfigTree AST into a typed Config struct.
    86	// It clones the tree before expansion so the original tree is not mutated.
    87	func CompileConfig(tree *ConfigTree) (*Config, error) {
    88		return compileConfigWithOpts(tree, compileOpts{})
    89	}
    90	
    91	// CompileConfigLenient is CompileConfig with the tolerant-path
    92	// downgrades enabled (#1798 control-char sanitize-in-place, lenient
    93	// VRRP track duplicates). Use on TOLERANT paths that compile an
    94	// already-active / already-persisted config the operator did not just
    95	// author — e.g. Store.Load of a persisted config — so an upgraded node
    96	// boots through. MUST NOT be used on the candidate-commit path:
    97	// commit / commit-check use the strict CompileConfig so new operator
    98	// edits hard-reject. The node-aware sibling CompileConfigForNodeLenient
    99	// covers the cluster paths (Store.SyncApply, peer-interface display).
   100	// (The former #1733 equal-flow worker-cap downgrade was retired in
   101	// #1830 (e) — the dataplane no longer caps equal-flow at 32 workers.)
   102	func CompileConfigLenient(tree *ConfigTree) (*Config, error) {
   103		return compileConfigWithOpts(tree, compileOpts{
   104			sanitizeFreeTextControlChars: true,
   105			lenientVRRPTrackDuplicates:   true,
   106		})
   107	}
   108	
   109	func compileConfigWithOpts(tree *ConfigTree, opts compileOpts) (*Config, error) {
   110		// #1873 R-B: tunnel-endpoint id collision gate. Runs on the
   111		// PRE-expansion tree (ExpandGroups removes the groups stanza) so
   112		// the check covers the UNION of tunnel names across all groups —
   113		// both cluster nodes accept/reject identically. Strict paths
   114		// hard-reject; lenient paths warn (see tunnelid.go).
   115		tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
   116			tree, opts.sanitizeFreeTextControlChars)
   117		if tunnelIDErr != nil {
   118			return nil, tunnelIDErr
   119		}
   120	
   121		// Clone the tree before expanding groups — the caller's tree must retain
   122		// groups and apply-groups nodes for display (show configuration groups).
   123		tree = tree.Clone()
   124		usedNodeFallback := false
   125	
   126		// Expand groups before compilation — resolve all apply-groups references.
   127		if err := tree.ExpandGroups(); err != nil {
   128			if strings.Contains(err.Error(), `undefined group "${node}"`) {
   129				vars := map[string]string{"node": "node0"}
   130				if err2 := tree.ExpandGroupsWithVars(vars); err2 != nil {
   131					return nil, fmt.Errorf("apply-groups: %w", err2)
   132				}
   133				usedNodeFallback = true
   134			} else {
   135				return nil, fmt.Errorf("apply-groups: %w", err)
   136			}
   137		}
   138	
   139		cfg, err := compileExpanded(tree, opts)
   140		if err != nil {
   141			return nil, err
   142		}
   143		if usedNodeFallback {
   144			cfg.Warnings = append(cfg.Warnings, `apply-groups "${node}" resolved using default node0 context during generic compile`)
   145		}
   146		cfg.Warnings = append(cfg.Warnings, tunnelIDWarnings...)
   147		return cfg, nil
   148	}
   149	
   150	// CompileConfigForNode is like CompileConfig but resolves ${node} variables
   151	// in apply-groups names before lookup. nodeID selects which per-node group
   152	// to apply (e.g. nodeID=0 maps "node" -> "node0", so apply-groups "${node}"
   153	// resolves to group "node0"). This supports a single shared config for both
   154	// nodes in a chassis cluster.
   155	func CompileConfigForNode(tree *ConfigTree, nodeID int) (*Config, error) {
   156		return compileConfigForNodeWithOpts(tree, nodeID, compileOpts{})
   157	}
   158	
   159	// CompileConfigForNodeLenient is CompileConfigForNode with the
   160	// tolerant-path downgrades enabled (see CompileConfigLenient). Use on
   161	// node-aware TOLERANT paths that compile an already-active / peer-synced
   162	// config the local operator did not just author: Store.SyncApply (HA
   163	// peer-sync ingress) and the read-only peer-interface display re-compiles
   164	// (cli_show_interfaces.go, server_show_interfaces.go). MUST NOT be used on
   165	// the candidate-commit path — see CompileConfigLenient.
   166	func CompileConfigForNodeLenient(tree *ConfigTree, nodeID int) (*Config, error) {
   167		return compileConfigForNodeWithOpts(tree, nodeID, compileOpts{
   168			sanitizeFreeTextControlChars: true,
   169			lenientVRRPTrackDuplicates:   true,
   170		})
   171	}
   172	
   173	func compileConfigForNodeWithOpts(tree *ConfigTree, nodeID int, opts compileOpts) (*Config, error) {
   174		// #1873 R-B: union-of-groups tunnel id collision gate — see
   175		// compileConfigWithOpts. Pre-expansion on purpose.
   176		tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
   177			tree, opts.sanitizeFreeTextControlChars)
   178		if tunnelIDErr != nil {
   179			return nil, tunnelIDErr
   180		}
   181	
   182		tree = tree.Clone()
   183	
   184		vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
   185		if err := tree.ExpandGroupsWithVars(vars); err != nil {
   186			return nil, fmt.Errorf("apply-groups: %w", err)
   187		}
   188	
   189		cfg, err := compileExpanded(tree, opts)
   190		if err != nil {
   191			return nil, err
   192		}
   193		cfg.Warnings = append(cfg.Warnings, tunnelIDWarnings...)
   194		return cfg, nil
   195	}
   196	
   197	// compileExpanded compiles an already-expanded (groups resolved) ConfigTree
   198	// into a typed Config. Shared by CompileConfig and CompileConfigForNode.
   199	func compileExpanded(tree *ConfigTree, opts compileOpts) (*Config, error) {
   200		// #1798 free-text control-character gate. Strict (commit /
   201		// commit-check): hard-reject. Lenient (load / peer-sync / peer
   202		// display): scrub in place on this already-cloned tree and warn.
   203		// Runs on the group-expanded tree so values inherited via
   204		// apply-groups are covered, and BEFORE section compilation so the
   205		// lenient path's typed Config is built from the scrubbed values.
   206		var ctrlCharWarnings []string
   207		if opts.sanitizeFreeTextControlChars {
   208			for _, p := range sanitizeNodesControlChars(tree.Children, "") {
   209				ctrlCharWarnings = append(ctrlCharWarnings, fmt.Sprintf(
   210					"sanitized control characters in configuration value at %q (#1798)", p))
   211			}
   212		} else if err := validateNodesControlChars(tree.Children, ""); err != nil {
   213			return nil, err
   214		}
   215	
   216		// #1814 VRRP track-interface AST pre-walk. Runs on the group-expanded
   217		// tree (so apply-groups-inherited statements are covered) and BEFORE
   218		// section compilation so the lenient path's first-wins pruning is
   219		// what the compiler actually sees. Strict (commit / commit-check):
   220		// duplicate track-interface inside one vrrp-group hard-rejects.
   221		// Lenient (load / peer-sync): prune to the first + warn. Shape-only
   222		// warnings (nested+sibling both present, orphan priority-cost) come
   223		// from here too — the typed config cannot distinguish them
   224		// post-compile.
   225		trackWarnings, err := validateVRRPTrackInterfaceAST(tree.Children, "", opts.lenientVRRPTrackDuplicates)
   226		if err != nil {
   227			return nil, err
   228		}
   229	
   230		cfg := &Config{
   231			Security: SecurityConfig{
   232				Zones:  make(map[string]*ZoneConfig),
   233				Screen: make(map[string]*ScreenProfile),
   234			},
   235			Interfaces: InterfacesConfig{
   236				Interfaces: make(map[string]*InterfaceConfig),
   237			},
   238			Applications: ApplicationsConfig{
   239				Applications:    make(map[string]*Application),
   240				ApplicationSets: make(map[string]*ApplicationSet),

exec
/bin/bash -lc "nl -ba pkg/dataplane/userspace/tunnels.go | sed -n '1,220p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package userspace
     2	
     3	import (
     4		"fmt"
     5		"log/slog"
     6		"net"
     7		"sort"
     8		"strings"
     9	
    10		"github.com/psaab/xpf/pkg/config"
    11	)
    12	
    13	func buildTunnelEndpointSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) []TunnelEndpointSnapshot {
    14		if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
    15			return nil
    16		}
    17		ifaceByName := make(map[string]InterfaceSnapshot, len(interfaces))
    18		rgByAddress := make(map[string]int)
    19		for _, iface := range interfaces {
    20			if iface.Name == "" || iface.Ifindex <= 0 {
    21				continue
    22			}
    23			ifaceByName[iface.Name] = iface
    24			if iface.RedundancyGroup <= 0 {
    25				continue
    26			}
    27			for _, addr := range iface.Addresses {
    28				ip, _, err := net.ParseCIDR(addr.Address)
    29				if err != nil || ip == nil {
    30					continue
    31				}
    32				rgByAddress[ip.String()] = iface.RedundancyGroup
    33			}
    34		}
    35		if len(ifaceByName) == 0 {
    36			return nil
    37		}
    38		names := make([]string, 0, len(cfg.Interfaces.Interfaces))
    39		for name := range cfg.Interfaces.Interfaces {
    40			names = append(names, name)
    41		}
    42		sort.Strings(names)
    43		out := make([]TunnelEndpointSnapshot, 0)
    44		// #1873: ids are content-derived (config.StableTunnelEndpointID of
    45		// the unit-qualified interface name), NOT positional — adding or
    46		// removing one tunnel can never renumber another, and both HA
    47		// nodes compute identical ids from identical config. usedIDs is
    48		// the fail-closed belt-and-braces behind the commit-time collision
    49		// gate (validateTunnelEndpointIDCollisionAST): a snapshot must
    50		// never carry two rows with one id, so the later-sorting collider
    51		// is dropped loudly. Iteration is sorted (names + unit numbers),
    52		// so the drop is deterministic.
    53		usedIDs := make(map[uint16]string)
    54		addEndpoint := func(ifName string, tunnel *config.TunnelConfig) {
    55			if tunnel == nil {
    56				return
    57			}
    58			// WireGuard endpoints carry the peer in WgEndpoint and need no
    59			// Source/Destination (#1432 S2a); a WG endpoint configured with
    60			// only WgEndpoint must not be dropped by the GRE source/dest gate.
    61			isWireguard := tunnel.Mode == "wireguard"
    62			if !isWireguard && (tunnel.Source == "" || tunnel.Destination == "") {
    63				return
    64			}
    65			iface, ok := ifaceByName[ifName]
    66			if !ok {
    67				return
    68			}
    69			outerFamily := "inet"
    70			transportTable := "inet.0"
    71			if dst := net.ParseIP(tunnel.Destination); dst != nil && dst.To4() == nil {
    72				outerFamily = "inet6"
    73				transportTable = "inet6.0"
    74			} else if src := net.ParseIP(tunnel.Source); src != nil && src.To4() == nil {
    75				outerFamily = "inet6"
    76				transportTable = "inet6.0"
    77			}
    78			if tunnel.RoutingInstance != "" {
    79				if outerFamily == "inet6" {
    80					transportTable = tunnel.RoutingInstance + ".inet6.0"
    81				} else {
    82					transportTable = tunnel.RoutingInstance + ".inet.0"
    83				}
    84			}
    85			redundancyGroup := iface.RedundancyGroup
    86			if redundancyGroup <= 0 {
    87				if src := net.ParseIP(tunnel.Source); src != nil {
    88					redundancyGroup = rgByAddress[src.String()]
    89				}
    90			}
    91			// For WG the outer family follows the peer endpoint address
    92			// (the Source/Destination heuristic above sees empty strings).
    93			if isWireguard && tunnel.WgEndpoint != "" {
    94				if host, _, err := net.SplitHostPort(tunnel.WgEndpoint); err == nil {
    95					if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
    96						outerFamily = "inet6"
    97					}
    98				}
    99			}
   100			id := config.StableTunnelEndpointID(ifName)
   101			if owner, taken := usedIDs[id]; taken {
   102				slog.Error("tunnel endpoint id collision — dropping later-sorting tunnel (#1873)",
   103					"kept", owner, "dropped", ifName, "id", id)
   104				return
   105			}
   106			snap := TunnelEndpointSnapshot{
   107				ID:              id,
   108				Interface:       ifName,
   109				LinuxName:       iface.LinuxName,
   110				Ifindex:         iface.Ifindex,
   111				Zone:            iface.Zone,
   112				RedundancyGroup: redundancyGroup,
   113				MTU:             iface.MTU,
   114				Mode:            tunnel.Mode,
   115				OuterFamily:     outerFamily,
   116				Source:          tunnel.Source,
   117				Destination:     tunnel.Destination,
   118				Key:             tunnel.Key,
   119				TTL:             tunnel.TTL,
   120				TransportTable:  transportTable,
   121			}
   122			if isWireguard {
   123				snap.WgListenPort = tunnel.WgListenPort
   124				snap.WgLocalPrivkeyHex = tunnel.WgLocalPrivkeyHex
   125				snap.WgPeerPubkeyHex = tunnel.WgPeerPubkeyHex
   126				snap.WgAllowedIPs = tunnel.WgAllowedIPs
   127				snap.WgEndpoint = tunnel.WgEndpoint
   128				snap.WgKeepaliveSecs = tunnel.WgKeepaliveSecs
   129			}
   130			out = append(out, snap)
   131			usedIDs[id] = ifName
   132		}
   133		for _, name := range names {
   134			iface := cfg.Interfaces.Interfaces[name]
   135			if iface == nil {
   136				continue
   137			}
   138			if iface.Tunnel != nil {
   139				if len(iface.Units) == 0 {
   140					addEndpoint(name, iface.Tunnel)
   141					continue
   142				}
   143				unitNums := make([]int, 0, len(iface.Units))
   144				for unitNum := range iface.Units {
   145					unitNums = append(unitNums, unitNum)
   146				}
   147				sort.Ints(unitNums)
   148				if iface.Tunnel.Mode == "wireguard" {
   149					// Interface-level WireGuard is ONE persistent TUN with
   150					// ONE listen port shared by every unit (#1910 r2 Codex
   151					// High): now that TunnelNameMap resolves every unit ref
   152					// of an interface-level wg to the base device, per-unit
   153					// emission would produce N live endpoints with the SAME
   154					// ifindex + listen port — the Rust side overwrites
   155					// tunnel_endpoint_by_ifindex with the later id and the
   156					// second control thread tombstones on the duplicate UDP
   157					// bind, so routes can select an engine whose control
   158					// thread never came up. Emit exactly one endpoint,
   159					// keyed by the LOWEST CONFIGURED unit ref — a pure
   160					// function of config, never of runtime snapshot rows,
   161					// so both HA nodes compute the same endpoint id from
   162					// the same config (#1873) and the commit-time collision
   163					// gate (collectTunnelEndpointNamesAST) can mirror the
   164					// selection exactly. The common single-unit-0 shape
   165					// keeps its existing stable id. Rows for every unit of
   166					// an interface-level wg share one LinuxName/ifindex, so
   167					// row presence is all-or-nothing: if the device is
   168					// absent, addEndpoint drops the ref like it always did.
   169					addEndpoint(fmt.Sprintf("%s.%d", name, unitNums[0]), iface.Tunnel)
   170					continue
   171				}
   172				for _, unitNum := range unitNums {
   173					addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), iface.Tunnel)
   174				}
   175				continue
   176			}
   177			if len(iface.Units) == 0 {
   178				continue
   179			}
   180			unitNums := make([]int, 0, len(iface.Units))
   181			for unitNum := range iface.Units {
   182				unitNums = append(unitNums, unitNum)
   183			}
   184			sort.Ints(unitNums)
   185			for _, unitNum := range unitNums {
   186				unit := iface.Units[unitNum]
   187				if unit == nil || unit.Tunnel == nil {
   188					continue
   189				}
   190				addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), unit.Tunnel)
   191			}
   192		}
   193		return out
   194	}
   195	
   196	// wgEndpointSetSummary returns a canonical "id:iface:port@ifindex"
   197	// summary of the snapshot's WireGuard endpoint set (#1866 D3). Used by
   198	// logWgEndpointSetTransitionLocked to emit a publish-boundary log line
   199	// whenever the WG endpoint set the helper is being given changes —
   200	// paired with the Rust-side apply-boundary log, one journal capture
   201	// disambiguates "Go published a stale set" from "Rust skipped the
   202	// prune" if a teardown leak ever recurs.
   203	func wgEndpointSetSummary(snap *ConfigSnapshot) string {
   204		if snap == nil {
   205			return ""
   206		}
   207		parts := make([]string, 0, len(snap.TunnelEndpoints))
   208		for _, ep := range snap.TunnelEndpoints {
   209			if ep.Mode != "wireguard" {
   210				continue
   211			}
   212			parts = append(parts, fmt.Sprintf("%d:%s:%d@%d", ep.ID, ep.Interface, ep.WgListenPort, ep.Ifindex))
   213		}
   214		sort.Strings(parts)
   215		return strings.Join(parts, ",")
   216	}
   217	
   218	// logWgEndpointSetTransitionLocked logs (Info, state-transition-only)
   219	// when the WG endpoint set of an outgoing snapshot differs from the
   220	// previously published one, then records the new set. Call after a

exec
/bin/bash -lc "nl -ba docs/research/1914-tunnel-endpoint-collision-gate/plan.md | sed -n '240,620p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
   240	## 3.5 Resolved design questions (after r1 three-way review)
   241	
   242	All four r1 reviewers (Claude SMR + Codex + AGY) converged on the answers
   243	below; they are now design decisions, not open questions.
   244	
   245	- **O1 (crux) — RESOLVED: view 1 stays byte-identical (presence-only
   246	  union).** Both the "narrow view 1 to complete-only" and "make view 1
   247	  src/dst-aware" ideas are provably unsound:
   248	  - Split-supply (Claude SMR, proven): `set interfaces gr-0/0/9 unit 0
   249	    tunnel mode gre` with src/dst supplied by an applied group → a
   250	    complete-only pre-expansion view 1 UNDER-registers (the literal AST has
   251	    no src/dst), missing a real emitted ref.
   252	  - Un-applied nested-apply-groups group (AGY F3 + Codex F2, proven shape):
   253	    `groups group-c interfaces gr-0/0/0 unit 0 {tunnel mode gre;
   254	    apply-groups my-group}` where `my-group` supplies src/dst, `group-c`
   255	    un-applied → a complete-only view 1 drops `gr-0/0/0.0`, views 2/3 never
   256	    expand the un-applied group, the ref is registered NOWHERE → **false
   257	    ACCEPT**, violating the #1873 group-symmetry invariant.
   258	
   259	  Therefore view 1 MUST remain the existing presence-only union. Its
   260	  Defect-B over-registration (phantom for an incomplete non-WG tunnel that
   261	  is never emitted by any node) is the price of preserving cross-node
   262	  symmetry for un-applied groups, and is **accepted + documented (Path 4
   263	  for B's residual)**. Views 2/3 fix Defect B for every applied-group case
   264	  for free (they run the real src/dst gate post-expansion).
   265	- **O2 — RESOLVED: NO double-`CompileConfig`.** Reading back
   266	  `buildTunnelEndpointSnapshots` is WRONG for two independent reasons the
   267	  reviewers proved: (a) `CompileConfig*` call the gate FIRST
   268	  (`compiler.go:115-119`, `:176-180`) → calling them from the gate
   269	  **recurses to stack overflow** (AGY F2 Critical, Codex F1); (b) the
   270	  builder's `usedIDs` belt (`tunnels.go:100-105`) has ALREADY DROPPED one
   271	  of the colliding pair, so the gate would see only one ref and Defect A
   272	  would STILL false-accept (Codex F1 High). The gate must enumerate
   273	  candidate names BEFORE any `usedIDs` drop, via a recursion-free path
   274	  (§4).
   275	- **O3 — RESOLVED: yes, factor an SSOT emitter, config-pure.** The emitter
   276	  lives in `pkg/config` (no import cycle — `pkg/dataplane/userspace`
   277	  already imports `pkg/config`). It returns the **configured** candidate
   278	  endpoint-name set from a typed `*config.Config`; it does NOT see runtime
   279	  `InterfaceSnapshot` rows (those don't exist at commit). The builder
   280	  consumes the emitter and THEN intersects with runtime ifaces + applies
   281	  `usedIDs` (AGY F4, Codex F4). The emitter is the SSOT for NAME emission
   282	  only; runtime filtering stays in the builder. Mandatory: the builder is
   283	  refactored to call the emitter (not a parallel copy) + a differential
   284	  parity test guards drift (the #1910 r2-r6 drift class).
   285	- **O4 — RESOLVED: Defect B is fixed for applied-group cases by views 2/3,
   286	  and document-only for its un-applied-group residual.** The residual
   287	  phantom false-reject requires an incomplete non-WG tunnel that (a)
   288	  appears in view 1's presence union, (b) is emitted by no node, AND (c)
   289	  folds onto a real emitted ref — joint probability negligible (1/65535 ×
   290	  half-configured-and-never-applied). The runtime belt + the new doc
   291	  comment cover it.
   292	
   293	---
   294	
   295	## 4. Recommended approach (RECONCILED with r1 three-way review)
   296	
   297	**Path 1 for Defect A** (the High false accept) via a recursion-free,
   298	pre-`usedIDs` three-view union; **document-only for Defect B's
   299	un-applied-group residual** (views 2/3 fix the applied-group cases for
   300	free). Concrete, reviewer-corrected shape:
   301	
   302	### 4.1 SSOT name emitter (config-pure, pre-`usedIDs`)
   303	
   304	Add `pkg/config.EmitTunnelEndpointNames(cfg *config.Config) []string` (or a
   305	`map[string]struct{}`): given a typed, already-expanded `*config.Config`, it
   306	returns the exact set of unit-qualified endpoint names the builder would
   307	emit FROM CONFIG ALONE — same non-WG src/dst gate (drop if src or dst
   308	empty), same WG single-lowest-unit pick, same canonical decimal unit
   309	formatting, same last-wins duplicate-unit. It does **NOT** apply the
   310	`usedIDs` collision drop and does **NOT** consult runtime
   311	`InterfaceSnapshot` rows (AGY F4, Codex F4 — those don't exist at commit).
   312	
   313	`buildTunnelEndpointSnapshots` is refactored to call
   314	`EmitTunnelEndpointNames` for its name set, then intersect with runtime
   315	`ifaceByName`, then apply `usedIDs`. One name-emission truth; the runtime
   316	filtering + drop stay in the builder. A differential parity test
   317	(`tunnelid_test.go`) asserts the gate's emitter output == the builder's
   318	configured-name set over a tunnel-config corpus (kills the #1910 r2-r6
   319	drift class).
   320	
   321	### 4.2 Gate computes a recursion-free three-view union
   322	
   323	`validateTunnelEndpointIDCollisionAST` builds:
   324	
   325	- **View 1 — pre-expansion presence union (UNCHANGED).** Exactly today's
   326	  `collectTunnelEndpointNamesAST` over `interfaces` ∪ every `groups` block.
   327	  Preserves the #1873 un-applied cross-node symmetry guarantee
   328	  (`TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric`). Keeps its
   329	  Defect-B over-registration (accepted residual).
   330	- **View 2 — post-expansion node0 emitted names.** `tree.Clone()` →
   331	  `ExpandGroupsWithVars({node:node0})` → `compileInterfaces` (the
   332	  gate-free interfaces sub-compiler, `compiler_interfaces.go:25`, which does
   333	  NOT call the collision gate) into a throwaway `InterfacesConfig` →
   334	  `EmitTunnelEndpointNames`. **Never calls `CompileConfig*`** → no recursion
   335	  (AGY F2, Codex F1).
   336	- **View 3 — post-expansion node1 emitted names.** Same, with
   337	  `{node:node1}`.
   338	
   339	Union = V1 ∪ V2 ∪ V3. Reject (strict) / warn (lenient) on any fold
   340	collision in the union. The fold and severity split are unchanged.
   341	
   342	### 4.3 Per-node expansion errors are NON-FATAL (Claude SMR F2, Codex F3, AGY F1)
   343	
   344	If `ExpandGroupsWithVars({node:nodeN})` fails (e.g. config defines only
   345	`groups node0` and references `${node}`, so the node1 expansion hits
   346	`undefined group "node1"` — `ast_groups.go:163-167`), that node's view
   347	contributes the **empty set** to the union; it MUST NOT become the gate's
   348	verdict. Rationale: the existing generic `CompileConfig` already falls back
   349	to node0 for undefined `${node}` (`compiler.go:127-134`,
   350	`TestCompileConfigForNodeBackwardCompat`), and an undefined peer group is a
   351	separate, already-handled condition on the real per-node compile path —
   352	the collision gate must not turn it into a spurious commit failure for a
   353	config valid on the local node. View 1 still covers any collision in the
   354	un-expandable group (presence union), so dropping the failed node's view
   355	loses no real coverage.
   356	
   357	This keeps the verdict a pure function of the candidate config (both nodes
   358	compute identical V1∪V2∪V3 and apply identical error-to-empty-set
   359	handling), so HA symmetry holds (Codex Info F5: confirmed no node0/node1
   360	divergence under this construction).
   361	
   362	---
   363	
   364	## 5. Blast radius
   365	
   366	- `pkg/config/tunnelid.go` — gate gains views 2/3 (clone+expand+`compileInterfaces`+emitter
   367	  per node, non-fatal on expansion error) + the new `EmitTunnelEndpointNames`
   368	  SSOT emitter. View 1 collector UNCHANGED. ~120 LOC.
   369	- `pkg/dataplane/userspace/tunnels.go` — `buildTunnelEndpointSnapshots`
   370	  refactored to source its configured-name set from `EmitTunnelEndpointNames`,
   371	  then intersect runtime ifaces + apply `usedIDs` (no change to the emitted
   372	  snapshot rows — parity-tested).
   373	- `pkg/config/tunnelid_test.go` — existing 13 tests are the regression
   374	  contract (all stay green); ADD: wildcard-false-accept rejects (strict) /
   375	  warns (lenient) / symmetric across nodes; un-applied-`${node}`-group does
   376	  NOT spuriously fail (Finding-2 regression); emitter↔builder differential
   377	  parity. All existing folds (`824`, `14730`, `17799`, `50477`) stay frozen.
   378	- No wire/protocol change. No HA sync-protocol change (`StableTunnelEndpointID`
   379	  MUST stay byte-frozen, #1873).
   380	- Commit-path only (not hot-path). Two extra clone+expand+`compileInterfaces`
   381	  passes per commit/commit-check; `Clone()` is a deep copy
   382	  (`ast.go:113-140`, Codex F-cost) so the candidate is never mutated.
   383	
   384	---
   385	
   386	## 6. Test plan
   387	
   388	1. **Regression (must stay green):** all 13 existing `tunnelid_test.go`
   389	   tests, including the frozen-fold pins and the group-symmetry test.
   390	2. **Defect A:** the §1.1 three-line wildcard config must now FAIL strict
   391	   commit with a `wg78.0`/`wg1408.0` + `824` + `collision` + `rename`
   392	   error; must WARN (not error) on the lenient path.
   393	3. **Defect A symmetry:** the wildcard config must reject identically under
   394	   `CompileConfigForNode(tree, 0)` and `CompileConfigForNode(tree, 1)`.
   395	4. **Defect B:** a half-configured GRE (no src/dst) that folds onto a real
   396	   emitted ref must NOT falsely reject (phantom shed); a COMPLETE GRE that
   397	   genuinely collides must still reject.
   398	5. **No false positives:** the existing non-colliding multi-tunnel config
   399	   stays clean; a WG wildcard group applied to a single interface (no
   400	   second colliding ref) compiles clean.
   401	6. **SSOT parity:** a differential test asserting `EmitTunnelEndpointNames(cfg)`
   402	   equals the builder's configured-name set (before runtime-iface intersect
   403	   + `usedIDs`) for a corpus of tunnel configs (the anti-drift guard, O3).
   404	7. **No-recursion regression:** a test that the gate on a wildcard/multi-node
   405	   config returns in bounded time (guards against the Finding-2 recursion
   406	   if a future edit reintroduces a `CompileConfig*` call from the gate).
   407	8. **Non-fatal peer-group:** `groups node0 ... ; apply-groups "${node}"`
   408	   with NO `groups node1` must COMMIT cleanly (view 3 contributes empty,
   409	   not an error) — the Finding-2/Codex-F3/AGY-F1 regression.
   410	9. `make test` for `pkg/config` + `pkg/dataplane/userspace`.
   411	
   412	No cluster smoke needed at /research time. At /engineer time: a failover
   413	smoke is NOT required (commit-path-only change, no dataplane/VRRP/sync
   414	code), but a `make test` + a manual two-node commit-symmetry check on the
   415	loss cluster confirms the gate rejects identically.
   416	
   417	## 7. Rollback
   418	
   419	Pure revert — single PR, no migration, no persisted-state change. The id
   420	fold is untouched so no node renumbering on rollback.
   421	
   422	## 8. HA / cluster considerations
   423	
   424	The whole point of the design is HA symmetry. The recommended Path 1 keeps
   425	the verdict a pure function of the candidate config. `StableTunnelEndpointID`
   426	is byte-frozen and untouched — no `SessionValue.FibGen` wire change, no
   427	cross-node renumbering. The new logic adds expand-for-node0 + expand-for-node1
   428	passes that BOTH run on BOTH nodes, so the union is identical everywhere.
   429	
   430	## 9. Observability / docs
   431	
   432	- Keep the runtime `usedIDs` `slog.Error` belt (defense in depth even after
   433	  the gate closes A).
   434	- Update the doc comments on `validateTunnelEndpointIDCollisionAST` and
   435	  `collectTunnelEndpointNamesAST` to describe the three-view union.
   436	- If Path 4 is chosen for B, add an operator note that incomplete non-WG
   437	  tunnels are conservatively registered.
   438	
   439	## 10. Alternatives considered (summary)
   440	
   441	See §3. Path 2 (gate-local mini-expander) rejected for drift risk; Path 3
   442	(complete-only, standalone) rejected for under-register; Path 4 (document
   443	only) acceptable ONLY for Defect B's residual, not for the High Defect A.
   444	
   445	## 11. Reviewer convergence ledger
   446	
   447	See `reviewer-ids.md`. Target: 3-way PLAN-READY (Claude SMR + Codex + AGY)
   448	on the final rev. Round verdicts recorded per round below.
   449	
   450	| Round | Claude SMR | Codex | AGY |
   451	|-------|-----------|-------|-----|
   452	| r1 | PLAN-NEEDS-REVISION | PLAN-NEEDS-REVISION | PLAN-NEEDS-REVISION |
   453	| r2 | pending | pending | pending |
   454	
   455	### r1 convergence summary
   456	
   457	All three reviewers independently converged on the same core defects in r1
   458	(strong signal the diagnosis was right and the recommended fix was wrong):
   459	
   460	- **Recursion + pre-drop enumeration (Codex F1 High, AGY F2 Critical):**
   461	  the gate cannot reuse `CompileConfig*`/`buildTunnelEndpointSnapshots` —
   462	  recursion + the `usedIDs` belt already dropped one collider. r2 §4.1/4.2
   463	  fix: config-pure pre-`usedIDs` emitter + gate-free `compileInterfaces`.
   464	- **O1 crux (all three):** view 1 cannot be narrowed without re-opening a
   465	  false-accept (split-supply + un-applied nested-apply-groups, both with
   466	  proven shapes). r2 §3.5-O1 + §4.2 fix: view 1 stays presence-only;
   467	  Defect-B residual documented.
   468	- **Peer-group expansion error (SMR F2, Codex F3, AGY F1):** undefined
   469	  `${node}` group must not fail the gate. r2 §4.3 fix: error→empty-set.
   470	- **Emitter is config-pure, not snapshot-identical (Codex F4, AGY F4):**
   471	  builder intersects runtime ifaces after the emitter. r2 §4.1 states the
   472	  boundary.

codex
The revised O1 choice is deliberately conservative: view 1 remains the old presence-only group union, so the #1873 group-symmetry test shape is preserved. I’m now looking for contradictions in the r2 test plan and for any hidden behavior drift around name emission.
exec
/bin/bash -lc "nl -ba pkg/config/compiler_interfaces.go | sed -n '560,920p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
   560						case "inet6":
   561							for _, addrInst := range namedInstances(afNode.FindChildren("address")) {
   562								unit.Addresses = append(unit.Addresses, addrInst.name)
   563								if addrInst.node.FindChild("primary") != nil && unit.PrimaryAddress == "" {
   564									unit.PrimaryAddress = addrInst.name
   565								}
   566								if addrInst.node.FindChild("preferred") != nil && unit.PreferredAddress == "" {
   567									unit.PreferredAddress = addrInst.name
   568								}
   569							}
   570							if afNode.FindChild("dhcpv6") != nil {
   571								unit.DHCPv6 = true
   572							}
   573							if afNode.FindChild("dad-disable") != nil {
   574								unit.DADDisable = true
   575							}
   576							if mtuNode := afNode.FindChild("mtu"); mtuNode != nil {
   577								if v := nodeVal(mtuNode); v != "" {
   578									if n, err := strconv.Atoi(v); err == nil {
   579										if n < unit.MTU || unit.MTU == 0 {
   580											unit.MTU = n
   581										}
   582									}
   583								}
   584							}
   585							if sampNode := afNode.FindChild("sampling"); sampNode != nil {
   586								if sampNode.FindChild("input") != nil {
   587									unit.SamplingInput = true
   588								}
   589								if sampNode.FindChild("output") != nil {
   590									unit.SamplingOutput = true
   591								}
   592							}
   593							if filterNode := afNode.FindChild("filter"); filterNode != nil {
   594								if inputNode := filterNode.FindChild("input"); inputNode != nil {
   595									unit.FilterInputV6 = nodeVal(inputNode)
   596								}
   597								if outputNode := filterNode.FindChild("output"); outputNode != nil {
   598									unit.FilterOutputV6 = nodeVal(outputNode)
   599								}
   600							}
   601							if dcNode := afNode.FindChild("dhcpv6-client"); dcNode != nil {
   602								unit.DHCPv6 = true
   603								dc := &DHCPv6ClientConfig{}
   604								for _, prop := range dcNode.Children {
   605									switch prop.Name() {
   606									case "client-identifier":
   607										if dtNode := prop.FindChild("duid-type"); dtNode != nil {
   608											dc.DUIDType = nodeVal(dtNode)
   609										} else if nodeVal(prop) == "duid-type" && len(prop.Keys) >= 3 {
   610											// Inline: client-identifier duid-type duid-ll;
   611											dc.DUIDType = prop.Keys[2]
   612										}
   613									case "client-type":
   614										dc.ClientType = nodeVal(prop)
   615									case "client-ia-type":
   616										if v := nodeVal(prop); v != "" {
   617											dc.ClientIATypes = append(dc.ClientIATypes, v)
   618										}
   619									case "prefix-delegating":
   620										if plNode := prop.FindChild("preferred-prefix-length"); plNode != nil {
   621											if v := nodeVal(plNode); v != "" {
   622												dc.PrefixDelegatingPrefixLen, _ = strconv.Atoi(v)
   623											}
   624										}
   625										if slNode := prop.FindChild("sub-prefix-length"); slNode != nil {
   626											if v := nodeVal(slNode); v != "" {
   627												dc.PrefixDelegatingSubPrefLen, _ = strconv.Atoi(v)
   628											}
   629										}
   630									case "req-option":
   631										if v := nodeVal(prop); v != "" {
   632											dc.ReqOptions = append(dc.ReqOptions, v)
   633										}
   634									case "update-router-advertisement":
   635										if ifNode := prop.FindChild("interface"); ifNode != nil {
   636											dc.UpdateRAInterface = nodeVal(ifNode)
   637										}
   638									}
   639								}
   640								unit.DHCPv6Client = dc
   641							}
   642						}
   643					}
   644				}
   645	
   646				ifc.Units[unitNum] = unit
   647	
   648				// Collect tunnel addresses from unit config
   649				if unit.Tunnel != nil {
   650					// Per-unit tunnel: addresses belong to this specific tunnel
   651					unit.Tunnel.Addresses = append(unit.Tunnel.Addresses, unit.Addresses...)
   652				} else if ifc.Tunnel != nil {
   653					// Interface-level tunnel: all unit addresses go to shared tunnel
   654					ifc.Tunnel.Addresses = append(ifc.Tunnel.Addresses, unit.Addresses...)
   655				}
   656			}
   657	
   658			ifaces.Interfaces[ifName] = ifc
   659		}
   660		return nil
   661	}
   662	
   663	// parseTunnelWireguard fills the WireGuard fields on tc from a
   664	// `wireguard { ... }` node under a tunnel stanza (#1432 S2a). The
   665	// minimal generic grammar is:
   666	//
   667	//	tunnel {
   668	//	    mode wireguard;
   669	//	    wireguard {
   670	//	        listen-port 51820;
   671	//	        private-key <64-hex>;
   672	//	        peer {
   673	//	            public-key <64-hex>;
   674	//	            allowed-ips <cidr>;   # repeatable
   675	//	            endpoint <ip:port>;
   676	//	            persistent-keepalive <secs>;
   677	//	        }
   678	//	    }
   679	//	}
   680	//
   681	// This is intentionally narrower than the eventual Junos wireguard
   682	// grammar (S6); it compiles to the TunnelEndpointSnapshot Wg* DTO
   683	// fields without committing to that surface.
   684	func parseTunnelWireguard(tc *TunnelConfig, wgNode *Node) {
   685		for _, prop := range wgNode.Children {
   686			switch prop.Name() {
   687			case "listen-port":
   688				if v := nodeVal(prop); v != "" {
   689					if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
   690						tc.WgListenPort = uint16(n)
   691					}
   692				}
   693			case "private-key":
   694				if v := nodeVal(prop); v != "" {
   695					tc.WgLocalPrivkeyHex = v
   696				}
   697			case "peer":
   698				parseTunnelWireguardPeer(tc, prop)
   699			}
   700		}
   701	}
   702	
   703	func parseTunnelWireguardPeer(tc *TunnelConfig, peerNode *Node) {
   704		for _, prop := range peerNode.Children {
   705			switch prop.Name() {
   706			case "public-key":
   707				if v := nodeVal(prop); v != "" {
   708					tc.WgPeerPubkeyHex = v
   709				}
   710			case "allowed-ips":
   711				if v := nodeVal(prop); v != "" {
   712					tc.WgAllowedIPs = append(tc.WgAllowedIPs, v)
   713				}
   714			case "endpoint":
   715				if v := nodeVal(prop); v != "" {
   716					tc.WgEndpoint = v
   717				}
   718			case "persistent-keepalive":
   719				if v := nodeVal(prop); v != "" {
   720					if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 65535 {
   721						tc.WgKeepaliveSecs = uint16(n)
   722					}
   723				}
   724			}
   725		}
   726	}
   727	
   728	// parseMSSValue extracts MSS value from either "node { mss VALUE; }" or "node VALUE;" syntax.
   729	func parseMSSValue(node *Node) int {
   730		// Hierarchical: ipsec-vpn { mss 1360; } or gre-in { mss 1360; }
   731		mssChild := node.FindChild("mss")
   732		if mssChild != nil && len(mssChild.Keys) >= 2 {
   733			if v, err := strconv.Atoi(mssChild.Keys[1]); err == nil {
   734				return v
   735			}
   736		}
   737		// Flat: ipsec-vpn 1360; (set syntax)
   738		if len(node.Keys) >= 2 {
   739			if v, err := strconv.Atoi(node.Keys[1]); err == nil {
   740				return v
   741			}
   742		}
   743		return 0
   744	}
   745	
   746	// validateVRRPTrackInterfaceAST walks the (group-expanded) AST and
   747	// enforces the single-track-interface invariant per vrrp-group (#1814).
   748	//
   749	// Strict path (commit / commit-check, lenient=false): more than one
   750	// track-interface statement inside a single vrrp-group is a hard
   751	// compile error — single-interface tracking is what the runtime
   752	// implements, and silently last-winsing the extras would hide it.
   753	//
   754	// Lenient path (load / peer-sync, lenient=true): the extra
   755	// track-interface children are pruned IN PLACE (the tree is already a
   756	// clone — same contract as sanitizeNodesControlChars) so the compiler
   757	// deterministically sees only the FIRST, and a warning is returned.
   758	//
   759	// Shape-only warnings emitted on BOTH paths (the typed config cannot
   760	// distinguish these post-compile):
   761	//   - nested `priority-cost` AND legacy sibling `track-priority-cost`
   762	//     both present (nested wins);
   763	//   - an orphan `priority-cost` child directly under the vrrp-group
   764	//     (only valid nested under track-interface).
   765	func validateVRRPTrackInterfaceAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
   766		var warnings []string
   767		for _, n := range nodes {
   768			nodePath := joinNodePath(prefix, n.Keys)
   769			if n.Name() == "vrrp-group" {
   770				w, err := checkVRRPGroupTrackShape(n, nodePath, lenient)
   771				warnings = append(warnings, w...)
   772				if err != nil {
   773					return nil, err
   774				}
   775			}
   776			w, err := validateVRRPTrackInterfaceAST(n.Children, nodePath, lenient)
   777			warnings = append(warnings, w...)
   778			if err != nil {
   779				return nil, err
   780			}
   781		}
   782		return warnings, nil
   783	}
   784	
   785	// parseTrackCost parses a priority-cost value, returning 0 (tracking
   786	// has no effect) for anything outside the schema's 1..254 range — a
   787	// negative cost would RAISE priority on link-down (Codex review on PR
   788	// #1821). The AST pre-walk rejects out-of-range values on strict
   789	// commits and warns on lenient loads; this keeps the lenient compile
   790	// consistent with that warning.
   791	func parseTrackCost(v string) (int, bool) {
   792		n, err := strconv.Atoi(v)
   793		if err != nil || n < 1 || n > 254 {
   794			return 0, false
   795		}
   796		return n, true
   797	}
   798	
   799	// checkVRRPGroupTrackShape applies the #1814 track-interface shape
   800	// checks to a single vrrp-group node. See validateVRRPTrackInterfaceAST.
   801	func checkVRRPGroupTrackShape(vg *Node, nodePath string, lenient bool) ([]string, error) {
   802		var warnings []string
   803		// Keys-packed compact spelling (Codex review on PR #1821): a
   804		// hierarchical leaf like `vrrp-group 1 track-interface ge-0/0/1
   805		// track-interface ge-0/0/2;` packs duplicates into the node's own
   806		// Keys, bypassing the child-node count below. Count those too; the
   807		// compiler's keys walk is first-wins, so lenient semantics match.
   808		keysPacked := 0
   809		for _, k := range vg.Keys {
   810			if k == "track-interface" {
   811				keysPacked++
   812			}
   813		}
   814		tracks := vg.FindChildren("track-interface")
   815		if total := keysPacked + len(tracks); total > 1 {
   816			if !lenient {
   817				return nil, fmt.Errorf("%s: %d track-interface statements; only one tracked interface is supported per vrrp-group", nodePath, total)
   818			}
   819			if keysPacked > 0 {
   820				// Child-node duplicates are warned by the prune below; the
   821				// Keys-packed spelling needs its own warning (the compiler
   822				// keys walk is first-wins).
   823				warnings = append(warnings, fmt.Sprintf("%s: %d track-interface statements; keeping the first and ignoring the rest (#1814)", nodePath, total))
   824			}
   825		}
   826		if len(tracks) > 1 {
   827			if !lenient {
   828				return nil, fmt.Errorf("%s: %d track-interface statements; only one tracked interface is supported per vrrp-group", nodePath, len(tracks))
   829			}
   830			// First-wins: prune every track-interface child after the first.
   831			kept := false
   832			pruned := vg.Children[:0]
   833			for _, c := range vg.Children {
   834				if c.Name() == "track-interface" {
   835					if kept {
   836						continue
   837					}
   838					kept = true
   839				}
   840				pruned = append(pruned, c)
   841			}
   842			vg.Children = pruned
   843			warnings = append(warnings, fmt.Sprintf("%s: %d track-interface statements; keeping the first (%s) and ignoring the rest (#1814)", nodePath, len(tracks), nodeVal(tracks[0])))
   844			tracks = tracks[:1]
   845		}
   846		if len(tracks) == 1 && tracks[0].FindChild("priority-cost") != nil && vg.FindChild("track-priority-cost") != nil {
   847			warnings = append(warnings, fmt.Sprintf("%s: both nested track-interface priority-cost and legacy track-priority-cost are configured; the nested priority-cost wins", nodePath))
   848		}
   849		if vg.FindChild("priority-cost") != nil {
   850			warnings = append(warnings, fmt.Sprintf("%s: priority-cost is only valid nested under track-interface; this statement has no effect", nodePath))
   851		}
   852		// Range-validate every cost spelling (Codex review on PR #1821):
   853		// the schema advertises <1..254> but nothing enforced it, and a
   854		// negative cost would RAISE priority on link-down. Strict commit
   855		// rejects; lenient load warns (the compiler clamp keeps runtime
   856		// safe either way via getPriority's [1,254] clamp, but a raised
   857		// priority is a semantic inversion worth refusing).
   858		costCheck := func(val, spelling string) error {
   859			n, err := strconv.Atoi(val)
   860			if err != nil || n < 1 || n > 254 {
   861				if !lenient {
   862					return fmt.Errorf("%s: %s %q out of range; must be 1..254", nodePath, spelling, val)
   863				}
   864				warnings = append(warnings, fmt.Sprintf("%s: %s %q out of range (1..254); ignoring tracking cost", nodePath, spelling, val))
   865			}
   866			return nil
   867		}
   868		// Validate EVERY occurrence, not just the first (Codex confirm
   869		// round on PR #1821): a duplicate invalid child after a valid one
   870		// must not bypass the strict reject.
   871		for _, tr := range tracks {
   872			for _, pc := range tr.FindChildren("priority-cost") {
   873				if len(pc.Keys) > 1 {
   874					if err := costCheck(pc.Keys[1], "priority-cost"); err != nil {
   875						return nil, err
   876					}
   877				}
   878			}
   879		}
   880		for _, tpc := range vg.FindChildren("track-priority-cost") {
   881			if len(tpc.Keys) > 1 {
   882				if err := costCheck(tpc.Keys[1], "track-priority-cost"); err != nil {
   883					return nil, err
   884				}
   885			}
   886		}
   887		for i, k := range vg.Keys {
   888			if (k == "track-priority-cost" || k == "priority-cost") && i+1 < len(vg.Keys) {
   889				if err := costCheck(vg.Keys[i+1], k); err != nil {
   890					return nil, err
   891				}
   892			}
   893		}
   894		return warnings, nil
   895	}
   896	
   897	// vrrpTrackConfigWarnings derives operator-visible interface-tracking
   898	// warnings from the compiled typed config (#1814). Emitted on both the
   899	// strict and lenient paths so a tracking misconfiguration is never a
   900	// silent no-op:
   901	//   - track-interface without any priority-cost (nested or legacy
   902	//     sibling) has no effect;
   903	//   - track-priority-cost without track-interface has no effect;
   904	//   - priority 255 marks the address owner — the runtime ignores
   905	//     tracking there (an owner stepping down while still holding the
   906	//     address invites duplicate-IP conflicts).
   907	//
   908	// Iteration is sorted at every level so warning order is deterministic.
   909	func vrrpTrackConfigWarnings(cfg *Config) []string {
   910		var warnings []string
   911		ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
   912		for name := range cfg.Interfaces.Interfaces {
   913			ifNames = append(ifNames, name)
   914		}
   915		sort.Strings(ifNames)
   916		for _, ifName := range ifNames {
   917			ifc := cfg.Interfaces.Interfaces[ifName]
   918			unitNums := make([]int, 0, len(ifc.Units))
   919			for n := range ifc.Units {
   920				unitNums = append(unitNums, n)

exec
/bin/bash -lc 'rg -n "TestCompileConfigForNodeBackwardCompat|TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric|tunnel endpoint|collision" pkg/config/*test.go pkg/dataplane/userspace/*test.go' in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
pkg/config/parser_rpm_pin_test.go:161:		t.Fatalf("err = %v, want collision error", err)
pkg/config/tunnelid_test.go:18:		// fold to 824. Pinned so the collision-handling tests below
pkg/config/tunnelid_test.go:19:		// stay grounded in a REAL collision under the frozen fold.
pkg/config/tunnelid_test.go:51:	for _, want := range []string{"wg1408.0", "wg78.0", "collision", "rename"} {
pkg/config/tunnelid_test.go:53:			t.Fatalf("collision error %q does not mention %q", err.Error(), want)
pkg/config/tunnelid_test.go:58:// R-B lenient: an already-active config with a collision must still
pkg/config/tunnelid_test.go:72:		if strings.Contains(w, "collision") && strings.Contains(w, "wg1408.0") {
pkg/config/tunnelid_test.go:77:		t.Fatalf("lenient compile carried no collision warning: %v", cfg.Warnings)
pkg/config/tunnelid_test.go:81:// R-B union-of-groups symmetry (Claude SMR plan r2): a collision
pkg/config/tunnelid_test.go:86:func TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric(t *testing.T) {
pkg/config/tunnelid_test.go:94:		t.Fatalf("node0 compile accepted a collision hidden in groups node1")
pkg/config/tunnelid_test.go:97:		t.Fatalf("node1 compile accepted a collision hidden in groups node1")
pkg/config/tunnelid_test.go:101:// #1910 r3 Codex: the collision gate must not model endpoint ids the
pkg/config/tunnelid_test.go:104:// a collision involving a higher, never-emitted unit ref must not
pkg/config/tunnelid_test.go:105:// reject the commit. Real collision under the frozen fold:
pkg/config/tunnelid_test.go:120:		t.Fatalf("CompileConfig rejected a config whose only id collision is on a never-emitted WG unit ref: %v", err)
pkg/config/tunnelid_test.go:123:		if strings.Contains(w, "collision") {
pkg/config/tunnelid_test.go:124:			t.Fatalf("unexpected collision warning: %q", w)
pkg/config/tunnelid_test.go:132:// the frozen wg0.1/wg341 collision (14730) and the runtime usedIDs
pkg/config/tunnelid_test.go:142:		t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind a leading-zero unit spelling (wg0.01 -> emits wg0.1, collides with wg341)")
pkg/config/tunnelid_test.go:144:	for _, want := range []string{"wg0.1", "wg341", "collision"} {
pkg/config/tunnelid_test.go:146:			t.Fatalf("collision error %q does not mention %q", err.Error(), want)
pkg/config/tunnelid_test.go:155:// would let a real builder-emitted collision pass strict compile,
pkg/config/tunnelid_test.go:157:// Frozen collision: StableTunnelEndpointID("wg0") ==
pkg/config/tunnelid_test.go:169:		t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind an overflow-only unit spelling (wg0 emits bare ref, collides with wg34524.0)")
pkg/config/tunnelid_test.go:176:// too, or it misses the frozen wg0.1/wg341 collision (14730).
pkg/config/tunnelid_test.go:184:		t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind a unit-level leading-zero spelling (wg0.01 -> emits wg0.1, collides with wg341)")
pkg/config/tunnelid_test.go:186:	for _, want := range []string{"wg0.1", "wg341", "collision"} {
pkg/config/tunnelid_test.go:188:			t.Fatalf("collision error %q does not mention %q", err.Error(), want)
pkg/config/tunnelid_test.go:199:// reversed the tunnel-carrying instance wins and the collision is
pkg/config/tunnelid_test.go:203:	// so the wg1408.0/wg78.0 collision (both refs would collide if
pkg/config/tunnelid_test.go:211:		t.Fatalf("CompileConfig rejected a collision on a ref whose tunnel lives only on an overwritten duplicate unit instance: %v", err)
pkg/config/tunnelid_test.go:214:	// the builder emits wg1408.0, and the collision must reject.
pkg/config/tunnelid_test.go:221:		t.Fatalf("CompileConfig accepted a real collision whose tunnel lives on the last duplicate unit instance (wg1408.0 vs wg78.0)")
pkg/config/tunnelid_test.go:225:// And the inverse: a collision on the EMITTED lowest unit ref of an
pkg/config/tunnelid_test.go:235:		t.Fatalf("CompileConfig accepted a collision on the emitted lowest unit ref (wg1408.0 vs wg78.0)")
pkg/config/tunnelid_test.go:253:		if strings.Contains(w, "tunnel endpoint id collision") {
pkg/config/tunnelid_test.go:254:			t.Fatalf("unexpected collision warning: %q", w)
pkg/dataplane/userspace/tunnels_test.go:11:// snapshot WITHOUT the WG tunnel endpoint — the prune signal the Rust
pkg/dataplane/userspace/cold_path_status_test.go:43:		"cold_path_active_builder_collision",
pkg/dataplane/userspace/cold_path_status_test.go:198:		"cold_path_active_builder_collision": [false, true],
pkg/dataplane/userspace/cold_path_status_test.go:226:		t.Errorf("active_builder_collision decode mismatch: %v", got.ColdPathActiveBuilderCollision)
pkg/dataplane/userspace/cold_path_status_test.go:242:		"cold_path_active_buckets", "cold_path_active_builder_collision",
pkg/dataplane/userspace/manager_test.go:773:		t.Fatalf("tunnel endpoint id = %d, want 3", got)
pkg/dataplane/userspace/manager_test.go:776:		t.Fatalf("tunnel endpoint id for non-tunnel ifindex = %d, want 0", got)
pkg/dataplane/userspace/manager_test.go:882:		t.Fatalf("unexpected tunnel endpoint id: %d", req.TunnelEndpointID)
pkg/dataplane/userspace/manager_test.go:936:		t.Fatalf("unexpected tunnel endpoint id: %d", req.TunnelEndpointID)
pkg/config/parser_class_of_service_test.go:1441:// duplicate detection fires on the SECOND collision regardless of
pkg/dataplane/userspace/address_book_test.go:3:// content-dedup, collision recovery, the v3-shaped predicate, and
pkg/config/parser_ast_test.go:3160:		t.Fatalf("readSharedUMEMPhase0Artifact error = %v, want normalized-key collision", err)
pkg/config/parser_ast_test.go:3171:		t.Fatalf("readSharedUMEMPhase0Artifact error = %v, want normalized-array collision", err)
pkg/config/parser_ast_test.go:3953:func TestCompileConfigForNodeBackwardCompat(t *testing.T) {
pkg/dataplane/userspace/protocol_test.go:902:	for _, key := range []string{"flow_cache_collision_evictions", "v_min_throttle_hard_cap_overrides", "v_min_throttles"} {
pkg/dataplane/userspace/protocol_test.go:940:	for _, key := range []string{"flow_cache_collision_evictions", "v_min_throttle_hard_cap_overrides", "v_min_throttles"} {

exec
/bin/bash -lc 'rg -n "validateTunnelEndpointIDCollisionAST|CompileConfig|compileConfig|buildTunnelEndpointSnapshots|EmitTunnelEndpointNames|collectTunnelEndpointNamesAST|addEndpoint|usedIDs|CompileConfigForNodeBackwardCompat|TunnelEndpointIDCollisionAcrossGroupsIsSymmetric" pkg/config pkg/dataplane/userspace docs/research/1914-tunnel-endpoint-collision-gate/plan.md' in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:6:  PLAN-NEEDS-REVISION converged on recursion hazard, pre-`usedIDs`
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:16:`validateTunnelEndpointIDCollisionAST` (`pkg/config/tunnelid.go:162`) is the
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:32:`collectTunnelEndpointNamesAST` hashes the **literal** group-AST interface
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:48:snapshot builder's `usedIDs` belt (`tunnels.go:101`) then drops the
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:67:`collectTunnelEndpointNamesAST` registers a ref from **tunnel-node
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:68:presence alone**. But the builder's `addEndpoint` (`tunnels.go:62`) drops
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:98:| Commit gate | `validateTunnelEndpointIDCollisionAST` | `tunnelid.go:162` | union, **pre-expansion** | no | hashes `<*>` literally |
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:99:| Gate collector | `collectTunnelEndpointNamesAST` | `tunnelid.go:61` | per-block | no (presence-only) | literal name |
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:102:| Builder | `buildTunnelEndpointSnapshots` / `addEndpoint` | `tunnels.go:13,54` | **post-expansion typed cfg** | **yes** (drops incomplete non-WG) | n/a (concrete names) |
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:103:| Runtime belt | `usedIDs` map | `tunnels.go:101` | — | — | deterministic later-sorting drop + `slog.Error` |
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:140:   `TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric` pins), PLUS
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:156:`CompileConfig*` → `buildTunnelEndpointSnapshots` → read back the emitted
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:157:endpoint names, OR factor the name-emission out of `addEndpoint` into a
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:195:Keep the gate pre-expansion but teach `collectTunnelEndpointNamesAST` to
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:224:`usedIDs` belt + `slog.Error`, and add a metric/log so the silent drop is
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:265:- **O2 — RESOLVED: NO double-`CompileConfig`.** Reading back
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:266:  `buildTunnelEndpointSnapshots` is WRONG for two independent reasons the
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:267:  reviewers proved: (a) `CompileConfig*` call the gate FIRST
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:270:  builder's `usedIDs` belt (`tunnels.go:100-105`) has ALREADY DROPPED one
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:273:  candidate names BEFORE any `usedIDs` drop, via a recursion-free path
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:281:  `usedIDs` (AGY F4, Codex F4). The emitter is the SSOT for NAME emission
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:298:pre-`usedIDs` three-view union; **document-only for Defect B's
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:302:### 4.1 SSOT name emitter (config-pure, pre-`usedIDs`)
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:304:Add `pkg/config.EmitTunnelEndpointNames(cfg *config.Config) []string` (or a
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:310:`usedIDs` collision drop and does **NOT** consult runtime
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:313:`buildTunnelEndpointSnapshots` is refactored to call
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:314:`EmitTunnelEndpointNames` for its name set, then intersect with runtime
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:315:`ifaceByName`, then apply `usedIDs`. One name-emission truth; the runtime
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:323:`validateTunnelEndpointIDCollisionAST` builds:
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:326:  `collectTunnelEndpointNamesAST` over `interfaces` ∪ every `groups` block.
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:328:  (`TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric`). Keeps its
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:334:  `EmitTunnelEndpointNames`. **Never calls `CompileConfig*`** → no recursion
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:348:verdict. Rationale: the existing generic `CompileConfig` already falls back
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:350:`TestCompileConfigForNodeBackwardCompat`), and an undefined peer group is a
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:367:  per node, non-fatal on expansion error) + the new `EmitTunnelEndpointNames`
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:369:- `pkg/dataplane/userspace/tunnels.go` — `buildTunnelEndpointSnapshots`
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:370:  refactored to source its configured-name set from `EmitTunnelEndpointNames`,
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:371:  then intersect runtime ifaces + apply `usedIDs` (no change to the emitted
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:394:   `CompileConfigForNode(tree, 0)` and `CompileConfigForNode(tree, 1)`.
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:401:6. **SSOT parity:** a differential test asserting `EmitTunnelEndpointNames(cfg)`
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:403:   + `usedIDs`) for a corpus of tunnel configs (the anti-drift guard, O3).
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:406:   if a future edit reintroduces a `CompileConfig*` call from the gate).
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:432:- Keep the runtime `usedIDs` `slog.Error` belt (defense in depth even after
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:434:- Update the doc comments on `validateTunnelEndpointIDCollisionAST` and
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:435:  `collectTunnelEndpointNamesAST` to describe the three-view union.
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:461:  the gate cannot reuse `CompileConfig*`/`buildTunnelEndpointSnapshots` —
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:462:  recursion + the `usedIDs` belt already dropped one collider. r2 §4.1/4.2
docs/research/1914-tunnel-endpoint-collision-gate/plan.md:463:  fix: config-pure pre-`usedIDs` emitter + gate-free `compileInterfaces`.
pkg/dataplane/userspace/manager_test.go:2305:	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
pkg/dataplane/userspace/manager_test.go:2351:	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
pkg/dataplane/userspace/manager_test.go:2385:	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
pkg/dataplane/userspace/manager_test.go:5345:	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
pkg/dataplane/userspace/manager_test.go:5389:	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
pkg/dataplane/userspace/tunnels.go:13:func buildTunnelEndpointSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) []TunnelEndpointSnapshot {
pkg/dataplane/userspace/tunnels.go:47:	// nodes compute identical ids from identical config. usedIDs is
pkg/dataplane/userspace/tunnels.go:49:	// gate (validateTunnelEndpointIDCollisionAST): a snapshot must
pkg/dataplane/userspace/tunnels.go:53:	usedIDs := make(map[uint16]string)
pkg/dataplane/userspace/tunnels.go:54:	addEndpoint := func(ifName string, tunnel *config.TunnelConfig) {
pkg/dataplane/userspace/tunnels.go:101:		if owner, taken := usedIDs[id]; taken {
pkg/dataplane/userspace/tunnels.go:131:		usedIDs[id] = ifName
pkg/dataplane/userspace/tunnels.go:140:				addEndpoint(name, iface.Tunnel)
pkg/dataplane/userspace/tunnels.go:163:				// gate (collectTunnelEndpointNamesAST) can mirror the
pkg/dataplane/userspace/tunnels.go:168:				// absent, addEndpoint drops the ref like it always did.
pkg/dataplane/userspace/tunnels.go:169:				addEndpoint(fmt.Sprintf("%s.%d", name, unitNums[0]), iface.Tunnel)
pkg/dataplane/userspace/tunnels.go:173:				addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), iface.Tunnel)
pkg/dataplane/userspace/tunnels.go:190:			addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), unit.Tunnel)
pkg/dataplane/userspace/tunnels_test.go:31:	endpoints := buildTunnelEndpointSnapshots(withWg, interfaces)
pkg/dataplane/userspace/tunnels_test.go:43:	endpoints = buildTunnelEndpointSnapshots(removed, interfaces)
pkg/dataplane/userspace/tunnels_test.go:85:	endpoints := buildTunnelEndpointSnapshots(cfg, interfaces)
pkg/dataplane/userspace/tunnels_test.go:106:	endpoints = buildTunnelEndpointSnapshots(cfg, withoutUnit0)
pkg/dataplane/userspace/tunnels_test.go:195:	idsAll := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfgAll, ifAll))
pkg/dataplane/userspace/tunnels_test.go:203:	idsRm := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfgRm, ifRm))
pkg/dataplane/userspace/tunnels_test.go:212:	idsAdd := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfgAdd, ifAdd))
pkg/dataplane/userspace/tunnels_test.go:232:	idsAll := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfg, ifAll))
pkg/dataplane/userspace/tunnels_test.go:242:	idsFlap := endpointIDsByInterface(buildTunnelEndpointSnapshots(cfg, ifFlap))
pkg/dataplane/userspace/tunnels_test.go:259:	endpoints := buildTunnelEndpointSnapshots(cfg, ifAll)
pkg/dataplane/userspace/builder.go:42:		TunnelEndpoints:    buildTunnelEndpointSnapshots(cfg, interfaces),
pkg/config/login_password_test.go:78:	cfg, err := CompileConfig(tree)
pkg/config/login_password_test.go:114:	cfg, err := CompileConfig(tree)
pkg/config/login_password_test.go:116:		t.Fatalf("CompileConfig: %v", err)
pkg/config/freetext.go:16://   - The STRICT compile path (CompileConfig / CompileConfigForNode,
pkg/config/freetext.go:27://   - The LENIENT compile path (CompileConfigLenient /
pkg/config/freetext.go:28://     CompileConfigForNodeLenient — Store.Load, Store.SyncApply, and
pkg/config/sqm_cookbook_fixture_test.go:73:	cfg, err := CompileConfig(tree)
pkg/config/sqm_cookbook_fixture_test.go:75:		t.Fatalf("CompileConfig(sqm cookbook fixture): %v", err)
pkg/config/compiler_retired_dataplane_knobs_test.go:35:	cfg, err := CompileConfig(tree)
pkg/config/compiler_retired_dataplane_knobs_test.go:37:		t.Fatalf("CompileConfig with retired knobs must not error (back-compat): %v", err)
pkg/config/compiler_retired_dataplane_knobs_test.go:54:	cfg, err := CompileConfig(tree)
pkg/config/compiler_retired_dataplane_knobs_test.go:56:		t.Fatalf("CompileConfig: %v", err)
pkg/config/compiler_retired_dataplane_knobs_test.go:70:	cfg, err := CompileConfigLenient(tree)
pkg/config/compiler_retired_dataplane_knobs_test.go:72:		t.Fatalf("CompileConfigLenient: %v", err)
pkg/config/compiler_system.go:243:				// only from a direct CompileConfig call on a tree that still
pkg/config/parser_ast_test.go:75:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:176:func TestCompileConfig(t *testing.T) {
pkg/config/parser_ast_test.go:215:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:377:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:379:		t.Fatalf("CompileConfig failed: %v", err)
pkg/config/parser_ast_test.go:458:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_ast_test.go:552:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:554:		t.Fatalf("CompileConfig after deletions: %v", err)
pkg/config/parser_ast_test.go:639:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:641:		t.Fatalf("CompileConfig after inserts: %v", err)
pkg/config/parser_ast_test.go:738:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:774:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_ast_test.go:815:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:899:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:982:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_ast_test.go:1033:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1069:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_ast_test.go:1107:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1185:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1245:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1273:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1295:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_ast_test.go:1313:	cfg3, err := CompileConfig(tree3)
pkg/config/parser_ast_test.go:1358:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1360:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:1437:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1439:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:1487:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1489:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:1526:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1528:		t.Fatal("CompileConfig succeeded, want missing scheduler commit error")
pkg/config/parser_ast_test.go:1531:		t.Fatalf("CompileConfig error = %v, want missing scheduler commit error", err)
pkg/config/parser_ast_test.go:1553:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1555:		t.Fatal("CompileConfig succeeded, want missing global scheduler commit error")
pkg/config/parser_ast_test.go:1558:		t.Fatalf("CompileConfig error = %v, want missing global scheduler commit error", err)
pkg/config/parser_ast_test.go:1583:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1649:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1684:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1718:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1816:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1818:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:1838:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1840:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:1887:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1889:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:1945:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1947:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:1992:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:1994:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:2056:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2058:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:2114:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2181:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2222:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2277:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2350:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2399:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2434:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2588:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2610:	cfg2, err2 := CompileConfig(tree2)
pkg/config/parser_ast_test.go:2627:// Pre-#1526 this test ALSO asserted CompileConfig succeeded with
pkg/config/parser_ast_test.go:2629:// CompileConfig fails by design, so we split the parse coverage
pkg/config/parser_ast_test.go:2685:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2687:		t.Fatal("CompileConfig succeeded for dataplane-type dpdk; expected retirement rejection")
pkg/config/parser_ast_test.go:2694:		t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), dpdkRetirementSubstr)
pkg/config/parser_ast_test.go:2702:		t.Fatalf("CompileConfig error = %v, want errors.Is(err, ErrDPDKDataplaneRetired)", err)
pkg/config/parser_ast_test.go:2716:	_, err = CompileConfig(tree)
pkg/config/parser_ast_test.go:2718:		t.Fatal("CompileConfig succeeded for an unknown dataplane type")
pkg/config/parser_ast_test.go:2721:		t.Fatalf("CompileConfig error = %v", err)
pkg/config/parser_ast_test.go:2763:			_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2765:				t.Fatal("CompileConfig succeeded for duplicate hierarchical unknown dataplane type")
pkg/config/parser_ast_test.go:2768:				t.Fatalf("CompileConfig error = %v", err)
pkg/config/parser_ast_test.go:2777:// CompileConfig directly, Store.CommitCheck (raw), or Store.Commit
pkg/config/parser_ast_test.go:2799:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2801:		t.Fatal("CompileConfig succeeded for dataplane-type dpdk (flat-set form)")
pkg/config/parser_ast_test.go:2804:		t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), dpdkRetirementSubstr)
pkg/config/parser_ast_test.go:2822:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2824:		t.Fatal("CompileConfig succeeded for hierarchical dataplane-type dpdk")
pkg/config/parser_ast_test.go:2827:		t.Fatalf("CompileConfig error = %q, want substring %q", err.Error(), dpdkRetirementSubstr)
pkg/config/parser_ast_test.go:2875:	_, polErr := CompileConfig(tree1)
pkg/config/parser_ast_test.go:2905:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2907:		t.Fatal("CompileConfig succeeded for dpdk + malformed policer candidate")
pkg/config/parser_ast_test.go:2910:		t.Fatalf("CompileConfig error = %q, want DPDK retirement substring (policer error should not win): %q", err.Error(), dpdkRetirementSubstr)
pkg/config/parser_ast_test.go:2939:	_, err := CompileConfigForNode(tree, 0)
pkg/config/parser_ast_test.go:2941:		t.Fatal("CompileConfigForNode succeeded for apply-groups-injected dpdk")
pkg/config/parser_ast_test.go:2944:		t.Fatalf("CompileConfigForNode error = %q, want substring %q", err.Error(), dpdkRetirementSubstr)
pkg/config/parser_ast_test.go:2967:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2969:		t.Fatalf("CompileConfig for userspace: %v", err)
pkg/config/parser_ast_test.go:2995:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:2997:		t.Fatalf("CompileConfig with omitted dataplane-type: %v", err)
pkg/config/parser_ast_test.go:3016:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3072:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3129:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3131:		t.Fatalf("CompileConfig error = %v, want null artifact rejection", err)
pkg/config/parser_ast_test.go:3199:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3268:			cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3310:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3360:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3394:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3426:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3428:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:3454:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3456:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:3488:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3490:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:3553:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3555:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:3626:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3658:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3693:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3711:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3736:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3757:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3810:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3863:	_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3865:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_ast_test.go:3868:		t.Error("groups node stripped by CompileConfig")
pkg/config/parser_ast_test.go:3871:		t.Error("apply-groups node stripped by CompileConfig")
pkg/config/parser_ast_test.go:3913:func TestCompileConfigForNode(t *testing.T) {
pkg/config/parser_ast_test.go:3925:	cfg0, err := CompileConfigForNode(tree, 0)
pkg/config/parser_ast_test.go:3927:		t.Fatalf("CompileConfigForNode(0): %v", err)
pkg/config/parser_ast_test.go:3935:	cfg1, err := CompileConfigForNode(tree, 1)
pkg/config/parser_ast_test.go:3937:		t.Fatalf("CompileConfigForNode(1): %v", err)
pkg/config/parser_ast_test.go:3953:func TestCompileConfigForNodeBackwardCompat(t *testing.T) {
pkg/config/parser_ast_test.go:3965:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:3967:		t.Fatalf("CompileConfig() unexpected error: %v", err)
pkg/config/parser_ast_test.go:4060:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4180:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4267:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4350:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4419:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4447:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4475:	cfg, err := CompileConfigForNode(tree, 0)
pkg/config/parser_ast_test.go:4504:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4673:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4695:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4717:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4775:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4823:	cfg, cerr := CompileConfig(tree)
pkg/config/parser_ast_test.go:4880:	cfg, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4983:			_, err := CompileConfig(tree)
pkg/config/parser_ast_test.go:4985:				t.Fatalf("CompileConfig succeeded, want error containing %q", tt.wantErr)
pkg/config/parser_ast_test.go:4988:				t.Fatalf("CompileConfig error = %v, want substring %q", err, tt.wantErr)
pkg/config/parser_ast_test.go:5014:	_, compileErr := CompileConfig(tree)
pkg/config/parser_ast_test.go:5016:		t.Fatal("CompileConfig succeeded, want ambiguous color mode error")
pkg/config/parser_ast_test.go:5019:		t.Fatalf("CompileConfig error = %v", compileErr)
pkg/config/parser_ast_test.go:5040:	cfg, cerr := CompileConfig(tree)
pkg/config/tunnelid_test.go:47:	_, err := CompileConfig(tree)
pkg/config/tunnelid_test.go:49:		t.Fatalf("CompileConfig accepted a colliding tunnel pair")
pkg/config/tunnelid_test.go:66:	cfg, err := CompileConfigLenient(tree)
pkg/config/tunnelid_test.go:68:		t.Fatalf("CompileConfigLenient rejected a colliding pair: %v", err)
pkg/config/tunnelid_test.go:86:func TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric(t *testing.T) {
pkg/config/tunnelid_test.go:93:	if _, err := CompileConfigForNode(tree, 0); err == nil {
pkg/config/tunnelid_test.go:96:	if _, err := CompileConfigForNode(tree, 1); err == nil {
pkg/config/tunnelid_test.go:118:	cfg, err := CompileConfig(tree)
pkg/config/tunnelid_test.go:120:		t.Fatalf("CompileConfig rejected a config whose only id collision is on a never-emitted WG unit ref: %v", err)
pkg/config/tunnelid_test.go:132:// the frozen wg0.1/wg341 collision (14730) and the runtime usedIDs
pkg/config/tunnelid_test.go:140:	_, err := CompileConfig(tree)
pkg/config/tunnelid_test.go:142:		t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind a leading-zero unit spelling (wg0.01 -> emits wg0.1, collides with wg341)")
pkg/config/tunnelid_test.go:156:// landing on the runtime usedIDs drop instead of failing commit).
pkg/config/tunnelid_test.go:168:	if _, err := CompileConfig(tree); err == nil {
pkg/config/tunnelid_test.go:169:		t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind an overflow-only unit spelling (wg0 emits bare ref, collides with wg34524.0)")
pkg/config/tunnelid_test.go:182:	_, err := CompileConfig(tree)
pkg/config/tunnelid_test.go:184:		t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind a unit-level leading-zero spelling (wg0.01 -> emits wg0.1, collides with wg341)")
pkg/config/tunnelid_test.go:210:	if _, err := CompileConfig(tree); err != nil {
pkg/config/tunnelid_test.go:211:		t.Fatalf("CompileConfig rejected a collision on a ref whose tunnel lives only on an overwritten duplicate unit instance: %v", err)
pkg/config/tunnelid_test.go:220:	if _, err := CompileConfig(tree); err == nil {
pkg/config/tunnelid_test.go:221:		t.Fatalf("CompileConfig accepted a real collision whose tunnel lives on the last duplicate unit instance (wg1408.0 vs wg78.0)")
pkg/config/tunnelid_test.go:234:	if _, err := CompileConfig(tree); err == nil {
pkg/config/tunnelid_test.go:235:		t.Fatalf("CompileConfig accepted a collision on the emitted lowest unit ref (wg1408.0 vs wg78.0)")
pkg/config/tunnelid_test.go:248:	cfg, err := CompileConfig(tree)
pkg/config/tunnelid_test.go:250:		t.Fatalf("CompileConfig rejected a non-colliding config: %v", err)
pkg/config/compiler_equal_flow_worker_cap_test.go:66:		cfg, err := CompileConfig(tree)
pkg/config/compiler_equal_flow_worker_cap_test.go:68:			t.Fatalf("CompileConfig(workers %s + equal-flow) returned error "+
pkg/config/compiler_equal_flow_worker_cap_test.go:96:		cfg, err := CompileConfigForNode(tree, node)
pkg/config/compiler_equal_flow_worker_cap_test.go:104:		cfgL, err := CompileConfigForNodeLenient(tree, node)
pkg/config/freetext_test.go:51:func TestCompileConfigRejectsNewlineDescription(t *testing.T) {
pkg/config/freetext_test.go:53:	_, err := CompileConfig(tree)
pkg/config/freetext_test.go:55:		t.Fatal("strict CompileConfig must reject a description containing a newline")
pkg/config/freetext_test.go:65:func TestCompileConfigForNodeRejectsNewlineDescription(t *testing.T) {
pkg/config/freetext_test.go:67:	if _, err := CompileConfigForNode(tree, 0); err == nil {
pkg/config/freetext_test.go:68:		t.Fatal("strict CompileConfigForNode must reject a description containing a newline")
pkg/config/freetext_test.go:72:// TestCompileConfigRejectsHierarchicalQuotedNewline exercises the
pkg/config/freetext_test.go:75:func TestCompileConfigRejectsHierarchicalQuotedNewline(t *testing.T) {
pkg/config/freetext_test.go:85:	if _, err := CompileConfig(tree); err == nil {
pkg/config/freetext_test.go:86:		t.Fatal("strict CompileConfig must reject the hierarchical quoted-newline description")
pkg/config/freetext_test.go:90:func TestCompileConfigRejectsControlCharAnnotation(t *testing.T) {
pkg/config/freetext_test.go:100:	_, err = CompileConfig(tree)
pkg/config/freetext_test.go:102:		t.Fatal("strict CompileConfig must reject an annotation containing a newline")
pkg/config/freetext_test.go:109:func TestCompileConfigLenientSanitizesNewlineDescription(t *testing.T) {
pkg/config/freetext_test.go:111:	cfg, err := CompileConfigLenient(tree)
pkg/config/freetext_test.go:156:	if _, err := CompileConfig(tree); err != nil {
pkg/config/parser_ipmonitoring_test.go:32:	cfg, err := CompileConfig(tree)
pkg/config/parser_ipmonitoring_test.go:106:	cfg, err := CompileConfig(tree)
pkg/config/parser_ipmonitoring_test.go:190:			_, err := CompileConfig(tree)
pkg/config/parser_ipmonitoring_test.go:192:				t.Fatalf("CompileConfig succeeded, want error containing %q", tc.wantErr)
pkg/config/parser_ipmonitoring_test.go:228:	cfg, err := CompileConfig(tree)
pkg/config/parser_ipmonitoring_test.go:286:	cfg, err := CompileConfig(tree)
pkg/config/parser_ipmonitoring_test.go:316:			cfg, err := CompileConfig(buildTree(t, lines))
pkg/config/parser_ipmonitoring_test.go:405:			_, err := CompileConfig(buildTree(t, tc.lines))
pkg/config/parser_ipmonitoring_test.go:407:				t.Fatalf("CompileConfig succeeded, want error containing %q", tc.wantErr)
pkg/config/parser_ipmonitoring_test.go:425:	cfg, err := CompileConfig(buildTree(t, lines))
pkg/config/tunnelid.go:33:// collectTunnelEndpointNamesAST appends the unit-qualified tunnel
pkg/config/tunnelid.go:35:// mirroring buildTunnelEndpointSnapshots naming exactly:
pkg/config/tunnelid.go:61:func collectTunnelEndpointNamesAST(ifacesNode *Node, out map[string]struct{}) {
pkg/config/tunnelid.go:146:// validateTunnelEndpointIDCollisionAST checks the UNION of tunnel
pkg/config/tunnelid.go:161:// buildTunnelEndpointSnapshots).
pkg/config/tunnelid.go:162:func validateTunnelEndpointIDCollisionAST(tree *ConfigTree, lenient bool) ([]string, error) {
pkg/config/tunnelid.go:164:	collectTunnelEndpointNamesAST(tree.FindChild("interfaces"), names)
pkg/config/tunnelid.go:173:				collectTunnelEndpointNamesAST(child.FindChild("interfaces"), names)
pkg/config/tunnelid.go:176:			collectTunnelEndpointNamesAST(group.FindChild("interfaces"), names)
pkg/config/schema_validate_test.go:321:	cfg, err := config.CompileConfig(tree)
pkg/config/schema_validate_test.go:358:	cfg, err := config.CompileConfig(tree)
pkg/config/parser_security_test.go:20:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:22:		t.Fatalf("CompileConfig failed: %v", err)
pkg/config/parser_security_test.go:52:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:54:		t.Fatalf("CompileConfig hierarchical: %v", err)
pkg/config/parser_security_test.go:141:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:210:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:238:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:296:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:324:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:360:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:420:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:451:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:476:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:510:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:568:	cfg, cerr := CompileConfig(tree)
pkg/config/parser_security_test.go:620:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:682:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:730:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:794:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:862:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:944:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:1009:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1043:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:1077:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1114:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1150:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:1225:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1270:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1344:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1385:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1436:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1477:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1563:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1680:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1723:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1754:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1789:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1871:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1914:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1916:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:1950:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:1999:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2031:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_security_test.go:2064:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2104:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2161:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2193:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2247:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2283:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2285:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:2332:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2334:		t.Fatalf("CompileConfig failed: %v", err)
pkg/config/parser_security_test.go:2364:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2366:		t.Fatalf("CompileConfig failed: %v", err)
pkg/config/parser_security_test.go:2392:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2394:		t.Fatalf("CompileConfig failed: %v", err)
pkg/config/parser_security_test.go:2419:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2421:		t.Fatalf("CompileConfig failed: %v", err)
pkg/config/parser_security_test.go:2437:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2439:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:2472:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2474:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:2518:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2520:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:2560:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2562:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:2616:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2618:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:2652:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2654:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:2675:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2677:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:2728:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2730:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:2824:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2869:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2871:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:2925:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2962:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:2964:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:3012:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3058:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3060:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:3106:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3108:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:3145:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3147:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:3200:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3202:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:3237:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3239:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:3283:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3318:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3358:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3410:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3412:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_security_test.go:3491:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3526:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3571:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3602:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3639:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3676:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3712:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3749:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3800:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3862:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3916:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:3950:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4009:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4047:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4091:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4129:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4163:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4187:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4226:	cfg, cerr := CompileConfig(tree)
pkg/config/parser_security_test.go:4268:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4306:	cfg, err := CompileConfig(tree)
pkg/config/parser_security_test.go:4342:	cfg, err := CompileConfig(tree)
pkg/config/schema_validate_chassis_test.go:261:	cfg, err := config.CompileConfig(tree)
pkg/config/schema_validate_chassis_test.go:263:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_services_test.go:29:		cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:78:		cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:199:			_, err := CompileConfig(tree)
pkg/config/parser_services_test.go:204:				t.Fatalf("CompileConfig() error = %v, want substring %q", err, tc.wantErr)
pkg/config/parser_services_test.go:232:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:270:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:331:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:387:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:389:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_services_test.go:439:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:463:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:511:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:572:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:632:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:673:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:721:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:763:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:795:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:838:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:864:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:866:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_services_test.go:887:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:889:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_services_test.go:913:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:915:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_services_test.go:961:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:1028:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:1081:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:1127:	cfg, err := CompileConfig(tree)
pkg/config/parser_services_test.go:1165:	cfg, err := CompileConfig(tree)
pkg/config/parser_fbf_test.go:97:	cfg, err := CompileConfig(tree)
pkg/config/parser_fbf_test.go:168:	cfg, err := CompileConfig(tree)
pkg/config/compiler_test.go:11:// family in a single `CompileConfig` response — saving operator
pkg/config/compiler_test.go:54:	_, err := CompileConfig(tree)
pkg/config/compiler_test.go:56:		t.Fatal("CompileConfig succeeded; expected accumulated strict-validator errors")
pkg/config/compiler_test.go:92:// Exercises the PRODUCTION path through CompileConfig so the
pkg/config/compiler_test.go:122:	_, err := CompileConfig(tree)
pkg/config/compiler_test.go:124:		t.Fatal("CompileConfig succeeded; expected single CoS strict-validator error")
pkg/config/compiler_test.go:159:	// CompileConfig return through to ErrDPDKDataplaneRetired ==
pkg/config/compiler_test.go:214:	_, err := CompileConfig(tree)
pkg/config/compiler_test.go:216:		t.Fatal("CompileConfig succeeded; expected all three strict-validator families to error")
pkg/config/compiler_equal_flow_target_policy_test.go:27:	cfg, err := CompileConfig(tree)
pkg/config/compiler_equal_flow_target_policy_test.go:64:	cfg, err := CompileConfig(tree)
pkg/config/dual_ast_differential_test.go:25://  5. Compile BOTH trees with CompileConfig (the entry the existing
pkg/config/dual_ast_differential_test.go:862:	hierCfg, err := CompileConfig(hierTree)
pkg/config/dual_ast_differential_test.go:864:		t.Fatalf("fixture bug: hierarchical CompileConfig: %v", err)
pkg/config/dual_ast_differential_test.go:866:	flatCfg, err := CompileConfig(flatTree)
pkg/config/dual_ast_differential_test.go:869:			"CompileConfig while hierarchical compiled: %v", err)
pkg/config/parser_rpm_pin_test.go:33:	cfg, err := CompileConfig(tree)
pkg/config/parser_rpm_pin_test.go:63:	cfg, err := CompileConfig(tree)
pkg/config/parser_rpm_pin_test.go:122:			_, err := CompileConfig(tree)
pkg/config/parser_rpm_pin_test.go:124:				t.Fatalf("CompileConfig succeeded, want error containing %q", tc.wantErr)
pkg/config/parser_rpm_pin_test.go:143:	_, err := CompileConfig(tree)
pkg/config/parser_system_test.go:18:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:20:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:53:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:55:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:111:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:184:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:238:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_system_test.go:264:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:266:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:350:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:352:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:459:			cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:461:				t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:495:		cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:497:			t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:554:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:556:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:603:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:605:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:639:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:641:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:688:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:690:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:738:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:740:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:800:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:802:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:845:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:847:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:895:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:897:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:936:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:938:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:999:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1001:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:1056:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1082:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1105:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1134:		cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1171:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1206:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1234:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1261:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1300:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1302:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:1340:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1342:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:1379:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1381:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:1406:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1408:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:1429:	cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1431:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:1465:	_, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1467:		t.Fatal("CompileConfig succeeded; expected ErrEBPFDataplaneRetired")
pkg/config/parser_system_test.go:1470:		t.Fatalf("CompileConfig err = %v; want errors.Is(ErrEBPFDataplaneRetired)", err)
pkg/config/parser_system_test.go:1495:			cfg, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1497:				t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_system_test.go:1524:		_, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1526:			t.Fatalf("CompileConfig error = %v, want unknown dataplane-type rejection", err)
pkg/config/parser_system_test.go:1544:		_, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1546:			t.Fatalf("CompileConfig error = %v, want unknown dataplane-type rejection", err)
pkg/config/parser_system_test.go:1564:		_, err := CompileConfig(tree)
pkg/config/parser_system_test.go:1566:			t.Fatalf("CompileConfig error = %v, want unknown dataplane-type rejection", err)
pkg/config/schema_validate_interfaces_test.go:311:	cfg, err := config.CompileConfig(tree)
pkg/config/schema_validate_interfaces_test.go:313:		t.Fatalf("CompileConfig: %v", err)
pkg/config/README.md:27:- `CompileConfig(tree) (*Config, error)` — `compiler.go`. AST-to-typed-
pkg/config/vrrp_track_test.go:92:	cfg, err := CompileConfig(parseHier(t, trackNestedHier))
pkg/config/vrrp_track_test.go:94:		t.Fatalf("CompileConfig: %v", err)
pkg/config/vrrp_track_test.go:114:	cfg, err := CompileConfig(tree)
pkg/config/vrrp_track_test.go:116:		t.Fatalf("CompileConfig: %v", err)
pkg/config/vrrp_track_test.go:128:	cfg, err := CompileConfig(parseHier(t, `interfaces {
pkg/config/vrrp_track_test.go:145:		t.Fatalf("CompileConfig: %v", err)
pkg/config/vrrp_track_test.go:162:	cfg, err := CompileConfig(tree)
pkg/config/vrrp_track_test.go:164:		t.Fatalf("CompileConfig: %v", err)
pkg/config/vrrp_track_test.go:219:			cfg, err := CompileConfig(parseHier(t, text))
pkg/config/vrrp_track_test.go:221:				t.Fatalf("CompileConfig: %v", err)
pkg/config/vrrp_track_test.go:256:	_, err := CompileConfig(parseHier(t, trackDuplicateHier))
pkg/config/vrrp_track_test.go:266:	cfg, err := CompileConfigLenient(parseHier(t, trackDuplicateHier))
pkg/config/vrrp_track_test.go:268:		t.Fatalf("CompileConfigLenient: %v", err)
pkg/config/vrrp_track_test.go:283:	cfg, err := CompileConfig(parseHier(t, `interfaces {
pkg/config/vrrp_track_test.go:299:		t.Fatalf("CompileConfig: %v", err)
pkg/config/vrrp_track_test.go:311:	cfg, err := CompileConfig(parseHier(t, `interfaces {
pkg/config/vrrp_track_test.go:327:		t.Fatalf("CompileConfig: %v", err)
pkg/config/vrrp_track_test.go:335:	cfg, err := CompileConfig(parseHier(t, `interfaces {
pkg/config/vrrp_track_test.go:351:		t.Fatalf("CompileConfig: %v", err)
pkg/config/vrrp_track_test.go:359:	cfg, err := CompileConfig(parseHier(t, `interfaces {
pkg/config/vrrp_track_test.go:377:		t.Fatalf("CompileConfig: %v", err)
pkg/config/vrrp_track_test.go:400:	cfg, err := CompileConfig(flatTree)
pkg/config/vrrp_track_test.go:402:		t.Fatalf("CompileConfig(replayed): %v", err)
pkg/config/vrrp_track_test.go:428:	if _, err := CompileConfig(parseHier(t, text)); err == nil {
pkg/config/vrrp_track_test.go:431:	cfg, err := CompileConfigLenient(parseHier(t, text))
pkg/config/vrrp_track_test.go:467:		if _, err := CompileConfig(parseHier(t, text)); err == nil {
pkg/config/vrrp_track_test.go:470:		cfg, err := CompileConfigLenient(parseHier(t, text))
pkg/config/vrrp_track_test.go:507:	if _, err := CompileConfig(tree); err == nil {
pkg/config/compiler.go:75:	// (CompileConfigLenient / CompileConfigForNodeLenient) so an
pkg/config/compiler.go:85:// CompileConfig converts a parsed ConfigTree AST into a typed Config struct.
pkg/config/compiler.go:87:func CompileConfig(tree *ConfigTree) (*Config, error) {
pkg/config/compiler.go:88:	return compileConfigWithOpts(tree, compileOpts{})
pkg/config/compiler.go:91:// CompileConfigLenient is CompileConfig with the tolerant-path
pkg/config/compiler.go:97:// commit / commit-check use the strict CompileConfig so new operator
pkg/config/compiler.go:98:// edits hard-reject. The node-aware sibling CompileConfigForNodeLenient
pkg/config/compiler.go:102:func CompileConfigLenient(tree *ConfigTree) (*Config, error) {
pkg/config/compiler.go:103:	return compileConfigWithOpts(tree, compileOpts{
pkg/config/compiler.go:109:func compileConfigWithOpts(tree *ConfigTree, opts compileOpts) (*Config, error) {
pkg/config/compiler.go:115:	tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
pkg/config/compiler.go:150:// CompileConfigForNode is like CompileConfig but resolves ${node} variables
pkg/config/compiler.go:155:func CompileConfigForNode(tree *ConfigTree, nodeID int) (*Config, error) {
pkg/config/compiler.go:156:	return compileConfigForNodeWithOpts(tree, nodeID, compileOpts{})
pkg/config/compiler.go:159:// CompileConfigForNodeLenient is CompileConfigForNode with the
pkg/config/compiler.go:160:// tolerant-path downgrades enabled (see CompileConfigLenient). Use on
pkg/config/compiler.go:165:// the candidate-commit path — see CompileConfigLenient.
pkg/config/compiler.go:166:func CompileConfigForNodeLenient(tree *ConfigTree, nodeID int) (*Config, error) {
pkg/config/compiler.go:167:	return compileConfigForNodeWithOpts(tree, nodeID, compileOpts{
pkg/config/compiler.go:173:func compileConfigForNodeWithOpts(tree *ConfigTree, nodeID int, opts compileOpts) (*Config, error) {
pkg/config/compiler.go:175:	// compileConfigWithOpts. Pre-expansion on purpose.
pkg/config/compiler.go:176:	tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
pkg/config/compiler.go:198:// into a typed Config. Shared by CompileConfig and CompileConfigForNode.
pkg/config/compiler.go:534:// whether the error is observed via `CompileConfig` directly,
pkg/config/fbf_fixture_test.go:13:// the merged candidate must pass CompileConfig with the FBF composition
pkg/config/fbf_fixture_test.go:42:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:32:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:83:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:135:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:189:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:243:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:277:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:308:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:331:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:355:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:378:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:400:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:424:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:447:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:469:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:506:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:552:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:607:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:638:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:670:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:697:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:720:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:742:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:766:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:789:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:811:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:834:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:947:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:979:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1011:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1039:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1070:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1101:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1129:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1154:	cfg, err := CompileConfig(tree)
pkg/config/parser_cluster_test.go:1156:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_class_of_service_test.go:58:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:119:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:186:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:222:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:253:	if _, err := CompileConfig(tree); err != nil {
pkg/config/parser_class_of_service_test.go:254:		t.Fatalf("CompileConfig at 100%% aggregate: %v", err)
pkg/config/parser_class_of_service_test.go:297:			_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:299:				t.Fatal("CompileConfig succeeded, want equal-flow-enforcement validation error")
pkg/config/parser_class_of_service_test.go:302:				t.Fatalf("CompileConfig error = %v, want equal-flow-enforcement validation", err)
pkg/config/parser_class_of_service_test.go:325:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:327:		t.Fatal("CompileConfig succeeded, want equal-flow/surplus-sharing validation error")
pkg/config/parser_class_of_service_test.go:330:		t.Fatalf("CompileConfig error = %v, want equal-flow/surplus-sharing validation", err)
pkg/config/parser_class_of_service_test.go:356:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:358:		t.Fatal("CompileConfig succeeded, want percent overcommit validation error")
pkg/config/parser_class_of_service_test.go:361:		t.Fatalf("CompileConfig error = %v, want aggregate percent overcommit error", err)
pkg/config/parser_class_of_service_test.go:385:	if _, err := CompileConfig(tree); err != nil {
pkg/config/parser_class_of_service_test.go:386:		t.Fatalf("CompileConfig: unexpected error for 40%%+60%% = 100%%: %v", err)
pkg/config/parser_class_of_service_test.go:406:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:408:		t.Fatalf("CompileConfig: unexpected error for literal 100%%: %v", err)
pkg/config/parser_class_of_service_test.go:464:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:505:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:507:		t.Fatal("CompileConfig succeeded, want duplicate fairness expectation error")
pkg/config/parser_class_of_service_test.go:510:		t.Fatalf("CompileConfig error = %v, want multiple expectations configured", err)
pkg/config/parser_class_of_service_test.go:528:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:530:		t.Fatalf("CompileConfig error = %v", err)
pkg/config/parser_class_of_service_test.go:560:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:562:		t.Fatal("CompileConfig succeeded, want duplicate hierarchical fairness expectation error")
pkg/config/parser_class_of_service_test.go:565:		t.Fatalf("CompileConfig error = %v, want duplicate balanced expectation leaf", err)
pkg/config/parser_class_of_service_test.go:588:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:681:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:717:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:754:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:807:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:844:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:848:	// CompileConfig calls ValidateConfig internally and stores
pkg/config/parser_class_of_service_test.go:902:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:949:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1043:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1119:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1180:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1241:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1278:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1290:// same queue ID must cause `CompileConfig` to return an error, not a
pkg/config/parser_class_of_service_test.go:1326:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1329:			"expected CompileConfig to REJECT a config with two " +
pkg/config/parser_class_of_service_test.go:1372:	cfg, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1418:	_, err := CompileConfig(tree)
pkg/config/parser_class_of_service_test.go:1421:			"expected CompileConfig to REJECT a config that assigns " +
pkg/config/parser_class_of_service_test.go:1461:	_, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:22:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:24:		t.Fatalf("CompileConfig failed: %v", err)
pkg/config/parser_routing_test.go:144:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_routing_test.go:168:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:170:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:203:	hierCfg, err := CompileConfig(hierTree)
pkg/config/parser_routing_test.go:205:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:228:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:230:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:269:	hierCfg, err := CompileConfig(hierTree)
pkg/config/parser_routing_test.go:271:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:310:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:371:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_routing_test.go:416:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:418:		t.Fatalf("CompileConfig failed: %v", err)
pkg/config/parser_routing_test.go:493:	hierCfg, err := CompileConfig(hierTree)
pkg/config/parser_routing_test.go:530:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:577:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_routing_test.go:607:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:609:		t.Fatalf("CompileConfig failed: %v", err)
pkg/config/parser_routing_test.go:680:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:682:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:734:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:736:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:778:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:780:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:817:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:819:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:871:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:873:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:902:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:904:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:925:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:927:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:975:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:977:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1020:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1048:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1050:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1092:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1094:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1120:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1122:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1151:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1153:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1177:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1179:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1214:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1216:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1257:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1259:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1291:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1293:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1319:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1321:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1361:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1363:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1389:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1391:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1408:	cfg2, err := CompileConfig(tree2)
pkg/config/parser_routing_test.go:1410:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1429:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1431:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1477:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1479:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1515:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1517:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1540:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1542:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1568:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1570:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1596:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1598:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1624:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1626:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1649:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1651:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1677:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1679:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1705:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1707:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1733:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1735:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1761:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1763:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1819:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1821:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1860:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1862:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1897:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1899:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1935:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1937:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:1964:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:1966:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2000:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2002:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2033:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2035:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2069:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2071:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2103:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2105:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2138:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2176:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2178:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2211:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2254:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2285:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2287:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2323:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2325:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2352:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2354:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2381:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2383:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2420:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2456:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2492:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2535:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2574:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2616:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2651:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2696:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2748:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2806:	cfg, err := CompileConfig(tree2)
pkg/config/parser_routing_test.go:2837:	_, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2872:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2874:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2904:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2906:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2939:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2941:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:2973:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:2975:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:3017:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3019:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:3058:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3060:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:3095:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3097:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:3120:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3122:		t.Fatalf("CompileConfig: %v", err)
pkg/config/parser_routing_test.go:3148:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3188:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3220:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3273:	cfg, err := CompileConfig(tree)
pkg/config/parser_routing_test.go:3275:		t.Fatalf("CompileConfig: %v", err)

exec
/bin/bash -lc "nl -ba pkg/config/ast_groups.go | sed -n '1,300p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"fmt"
     5		"strings"
     6	)
     7	
     8	// ExpandGroups resolves all "apply-groups" references in the tree.
     9	// It collects group definitions from the "groups" stanza, then for each
    10	// "apply-groups <name>" node, clones the referenced group's children and
    11	// merges them into the parent. After expansion, both "groups" and
    12	// "apply-groups" nodes are removed from the tree.
    13	func (t *ConfigTree) ExpandGroups() error {
    14		return t.expandGroups(false, nil)
    15	}
    16	
    17	// ExpandGroupsTagged is like ExpandGroups but tags each inherited node
    18	// with InheritedFrom set to the group name, for "| display inheritance".
    19	func (t *ConfigTree) ExpandGroupsTagged() error {
    20		return t.expandGroups(true, nil)
    21	}
    22	
    23	// ExpandGroupsWithVars is like ExpandGroups but resolves ${var} references
    24	// in apply-groups names before lookup. This supports Junos-style per-node
    25	// group selection, e.g. apply-groups "${node}" with vars {"node": "node0"}.
    26	func (t *ConfigTree) ExpandGroupsWithVars(vars map[string]string) error {
    27		return t.expandGroups(false, vars)
    28	}
    29	
    30	// resolveVars replaces ${key} placeholders in s with values from vars.
    31	func resolveVars(s string, vars map[string]string) string {
    32		if vars == nil {
    33			return s
    34		}
    35		for k, v := range vars {
    36			s = strings.ReplaceAll(s, "${"+k+"}", v)
    37		}
    38		return s
    39	}
    40	
    41	func (t *ConfigTree) expandGroups(tagInherited bool, vars map[string]string) error {
    42		// Collect group definitions: groups { <name> { ... } }
    43		groups := make(map[string]*Node)
    44		for _, child := range t.Children {
    45			if child.Name() == "groups" {
    46				for _, g := range child.Children {
    47					if len(g.Keys) < 1 {
    48						continue
    49					}
    50					name := g.Keys[0]
    51					if len(g.Keys) > 1 {
    52						name = g.Keys[1]
    53					}
    54					groups[name] = g
    55				}
    56			}
    57		}
    58	
    59		// If no groups defined, just strip any stale apply-groups references.
    60		if len(groups) == 0 {
    61			return t.stripApplyGroups(vars)
    62		}
    63	
    64		// Recursively resolve apply-groups at all levels.
    65		// The nil ancestorPath means we're at the top level.
    66		if err := expandGroupsRecursive(&t.Children, groups, nil, nil, tagInherited, vars); err != nil {
    67			return err
    68		}
    69	
    70		// Remove the "groups" stanza itself.
    71		filtered := make([]*Node, 0, len(t.Children))
    72		for _, child := range t.Children {
    73			if child.Name() != "groups" {
    74				filtered = append(filtered, child)
    75			}
    76		}
    77		t.Children = filtered
    78	
    79		return nil
    80	}
    81	
    82	// tagNodesInherited recursively sets InheritedFrom on all nodes.
    83	func tagNodesInherited(nodes []*Node, groupName string) {
    84		for _, n := range nodes {
    85			n.InheritedFrom = groupName
    86			tagNodesInherited(n.Children, groupName)
    87		}
    88	}
    89	
    90	// stripApplyGroups walks the tree after group expansion and returns an error
    91	// if any apply-groups node still references an undefined group. vars is used
    92	// to resolve ${var} placeholders in group names for error messages.
    93	func (t *ConfigTree) stripApplyGroups(vars map[string]string) error {
    94		return stripApplyGroupsInNodes(t.Children, vars)
    95	}
    96	
    97	func stripApplyGroupsInNodes(nodes []*Node, vars map[string]string) error {
    98		for _, child := range nodes {
    99			if child.Name() == "apply-groups" {
   100				name := ""
   101				if len(child.Keys) > 1 {
   102					name = resolveVars(child.Keys[1], vars)
   103				}
   104				return fmt.Errorf("apply-groups references undefined group %q", name)
   105			}
   106			if !child.IsLeaf {
   107				if err := stripApplyGroupsInNodes(child.Children, vars); err != nil {
   108					return err
   109				}
   110			}
   111		}
   112		return nil
   113	}
   114	
   115	// walkGroupToContext walks a group definition's tree to match the ancestor
   116	// context path. Each element of ancestorPath is the Keys slice of a parent
   117	// node from root to the current level. Returns the children of the deepest
   118	// matching node, or nil if the group has no matching subtree.
   119	// Supports <*> wildcard matching in group keys.
   120	func walkGroupToContext(groupChildren []*Node, ancestorPath [][]string) []*Node {
   121		current := groupChildren
   122		for _, pathKeys := range ancestorPath {
   123			var next []*Node
   124			for _, child := range current {
   125				if child.IsLeaf {
   126					continue
   127				}
   128				// Exact match or wildcard match (group keys may contain <*>).
   129				if keysEqual(child.Keys, pathKeys) || keysMatchWildcard(pathKeys, child.Keys) {
   130					next = child.Children
   131					break
   132				}
   133			}
   134			if next == nil {
   135				return nil // group doesn't have matching subtree at this context
   136			}
   137			current = next
   138		}
   139		return current
   140	}
   141	
   142	// expandGroupsRecursive processes apply-groups nodes within a node list,
   143	// then recurses into all children to handle nested apply-groups.
   144	// ancestorPath tracks the key path from root to the current level, enabling
   145	// groups to be walked down to the matching context for nested apply-groups.
   146	// seen tracks group names being expanded to detect circular references.
   147	// If tagInherited is true, merged nodes get InheritedFrom set to the group name.
   148	// vars provides ${var} replacements for group names (may be nil).
   149	func expandGroupsRecursive(nodes *[]*Node, groups map[string]*Node, ancestorPath [][]string, seen map[string]bool, tagInherited bool, vars map[string]string) error {
   150		// First, collect apply-groups references at this level.
   151		// Support bracket-list syntax: apply-groups [ name1 name2 ] produces
   152		// Keys = ["apply-groups", "name1", "name2"].
   153		var applyNames []string
   154		for _, n := range *nodes {
   155			if n.Name() == "apply-groups" {
   156				for _, key := range n.Keys[1:] {
   157					applyNames = append(applyNames, resolveVars(key, vars))
   158				}
   159			}
   160		}
   161	
   162		// Expand each referenced group.
   163		for _, name := range applyNames {
   164			g, ok := groups[name]
   165			if !ok {
   166				return fmt.Errorf("apply-groups references undefined group %q", name)
   167			}
   168	
   169			if seen == nil {
   170				seen = make(map[string]bool)
   171			}
   172			if seen[name] {
   173				return fmt.Errorf("apply-groups circular reference: group %q", name)
   174			}
   175			seen[name] = true
   176	
   177			// Walk the group tree to match the current context path.
   178			var srcChildren []*Node
   179			if len(ancestorPath) == 0 {
   180				// Top-level: merge group's direct children.
   181				srcChildren = g.Children
   182			} else {
   183				srcChildren = walkGroupToContext(g.Children, ancestorPath)
   184			}
   185	
   186			if srcChildren != nil {
   187				cloned := cloneNodes(srcChildren)
   188				if tagInherited {
   189					tagNodesInherited(cloned, name)
   190				}
   191				mergeNodes(nodes, cloned)
   192			}
   193	
   194			delete(seen, name)
   195		}
   196	
   197		// Remove apply-groups nodes.
   198		filtered := make([]*Node, 0, len(*nodes))
   199		for _, n := range *nodes {
   200			if n.Name() != "apply-groups" {
   201				filtered = append(filtered, n)
   202			}
   203		}
   204		*nodes = filtered
   205	
   206		// Recurse into children to handle nested apply-groups.
   207		for _, n := range *nodes {
   208			if !n.IsLeaf && len(n.Children) > 0 {
   209				childPath := make([][]string, len(ancestorPath)+1)
   210				copy(childPath, ancestorPath)
   211				childPath[len(ancestorPath)] = n.Keys
   212				if err := expandGroupsRecursive(&n.Children, groups, childPath, seen, tagInherited, vars); err != nil {
   213					return err
   214				}
   215			}
   216		}
   217	
   218		return nil
   219	}
   220	
   221	// mergeNodes merges src nodes into dst. For container nodes with matching keys,
   222	// children are merged recursively. For leaf nodes or new containers, they are
   223	// appended (group values don't override existing explicit config — existing
   224	// config takes precedence via ordering, since the compiler uses first-match).
   225	func mergeNodes(dst *[]*Node, src []*Node) {
   226		for _, s := range src {
   227			if s.IsLeaf {
   228				// Only add leaf if no matching leaf exists.
   229				if !hasMatchingLeaf(*dst, s.Keys) {
   230					*dst = append(*dst, s)
   231				}
   232				continue
   233			}
   234	
   235			// Check if source keys contain wildcards (<*>).
   236			if keysContainWildcard(s.Keys) {
   237				// Wildcard merge: apply to all matching containers in dst.
   238				for _, d := range *dst {
   239					if !d.IsLeaf && keysMatchWildcard(d.Keys, s.Keys) {
   240						cloned := cloneNodes(s.Children)
   241						mergeNodes(&d.Children, cloned)
   242					}
   243				}
   244				continue
   245			}
   246	
   247			// Container node: find matching container in dst.
   248			found := false
   249			for _, d := range *dst {
   250				if !d.IsLeaf && keysEqual(d.Keys, s.Keys) {
   251					// Merge children recursively.
   252					mergeNodes(&d.Children, s.Children)
   253					found = true
   254					break
   255				}
   256			}
   257			if !found {
   258				*dst = append(*dst, s)
   259			}
   260		}
   261	}
   262	
   263	// keysContainWildcard returns true if any key is the Junos wildcard "<*>".
   264	func keysContainWildcard(keys []string) bool {
   265		for _, k := range keys {
   266			if k == "<*>" {
   267				return true
   268			}
   269		}
   270		return false
   271	}
   272	
   273	// keysMatchWildcard checks if dst keys match src keys where "<*>" matches
   274	// any value. Both slices must have the same length.
   275	func keysMatchWildcard(dst, src []string) bool {
   276		if len(dst) != len(src) {
   277			return false
   278		}
   279		for i := range src {
   280			if src[i] != "<*>" && src[i] != dst[i] {
   281				return false
   282			}
   283		}
   284		return true
   285	}
   286	
   287	// hasMatchingLeaf returns true if nodes contains a leaf whose first key
   288	// matches. This prevents group values from overriding explicit config
   289	// (e.g., if "host-name explicit" already exists, "host-name group" is skipped).
   290	func hasMatchingLeaf(nodes []*Node, keys []string) bool {
   291		if len(keys) == 0 {
   292			return false
   293		}
   294		for _, n := range nodes {
   295			if n.IsLeaf && len(n.Keys) > 0 && n.Keys[0] == keys[0] {
   296				return true
   297			}
   298		}
   299		return false
   300	}

exec
/bin/bash -lc "nl -ba pkg/config/tunnelid_test.go | sed -n '1,280p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
     1	package config
     2	
     3	import (
     4		"strings"
     5		"testing"
     6	)
     7	
     8	// Hash-freeze pins (#1873): StableTunnelEndpointID is wire-adjacent —
     9	// both HA nodes must compute identical ids from identical config, so
    10	// the fold may NEVER change. If this test fails, you changed the fold;
    11	// revert. (The literal values were computed once and frozen.)
    12	func TestStableTunnelEndpointIDHashFreeze(t *testing.T) {
    13		pins := map[string]uint16{
    14			// Ordinary names.
    15			"wg0.0":      16091,
    16			"gr-0/0/0.0": 44687,
    17			// The verified colliding pair (Codex plan-review r1): both
    18			// fold to 824. Pinned so the collision-handling tests below
    19			// stay grounded in a REAL collision under the frozen fold.
    20			"wg1408.0": 824,
    21			"wg78.0":   824,
    22		}
    23		for name, want := range pins {
    24			if got := StableTunnelEndpointID(name); got != want {
    25				t.Fatalf("StableTunnelEndpointID(%q) = %d, want %d — the fold is frozen (#1873)", name, got, want)
    26			}
    27		}
    28	}
    29	
    30	// id 0 means "not a tunnel" everywhere; the mapping must never emit it.
    31	func TestStableTunnelEndpointIDNeverZero(t *testing.T) {
    32		names := []string{"", "wg0", "wg0.0", "gr-0/0/0.0", "a", "zz.4094"}
    33		for _, name := range names {
    34			if got := StableTunnelEndpointID(name); got == 0 {
    35				t.Fatalf("StableTunnelEndpointID(%q) = 0", name)
    36			}
    37		}
    38	}
    39	
    40	// R-B: a config whose tunnel names fold to the same id must fail
    41	// commit compilation (strict path) with a two-name remediation error.
    42	func TestTunnelEndpointIDCollisionFailsCommit(t *testing.T) {
    43		tree := buildTree(t, []string{
    44			"set interfaces wg1408 unit 0 tunnel mode wireguard",
    45			"set interfaces wg78 unit 0 tunnel mode wireguard",
    46		})
    47		_, err := CompileConfig(tree)
    48		if err == nil {
    49			t.Fatalf("CompileConfig accepted a colliding tunnel pair")
    50		}
    51		for _, want := range []string{"wg1408.0", "wg78.0", "collision", "rename"} {
    52			if !strings.Contains(err.Error(), want) {
    53				t.Fatalf("collision error %q does not mention %q", err.Error(), want)
    54			}
    55		}
    56	}
    57	
    58	// R-B lenient: an already-active config with a collision must still
    59	// compile on the tolerant load/peer-sync paths (warn, not reject) so
    60	// an upgraded node boots.
    61	func TestTunnelEndpointIDCollisionLenientWarns(t *testing.T) {
    62		tree := buildTree(t, []string{
    63			"set interfaces wg1408 unit 0 tunnel mode wireguard",
    64			"set interfaces wg78 unit 0 tunnel mode wireguard",
    65		})
    66		cfg, err := CompileConfigLenient(tree)
    67		if err != nil {
    68			t.Fatalf("CompileConfigLenient rejected a colliding pair: %v", err)
    69		}
    70		found := false
    71		for _, w := range cfg.Warnings {
    72			if strings.Contains(w, "collision") && strings.Contains(w, "wg1408.0") {
    73				found = true
    74			}
    75		}
    76		if !found {
    77			t.Fatalf("lenient compile carried no collision warning: %v", cfg.Warnings)
    78		}
    79	}
    80	
    81	// R-B union-of-groups symmetry (Claude SMR plan r2): a collision
    82	// involving a `groups nodeN`-scoped tunnel must fail commit on BOTH
    83	// nodes — including the node whose effective config never applies the
    84	// group — or config-sync would split (originator accepts, peer
    85	// rejects).
    86	func TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric(t *testing.T) {
    87		tree := buildTree(t, []string{
    88			"set groups node1 interfaces wg1408 unit 0 tunnel mode wireguard",
    89			"set interfaces wg78 unit 0 tunnel mode wireguard",
    90			// No apply-groups: node0's EFFECTIVE config never contains
    91			// wg1408 — the union check must still reject.
    92		})
    93		if _, err := CompileConfigForNode(tree, 0); err == nil {
    94			t.Fatalf("node0 compile accepted a collision hidden in groups node1")
    95		}
    96		if _, err := CompileConfigForNode(tree, 1); err == nil {
    97			t.Fatalf("node1 compile accepted a collision hidden in groups node1")
    98		}
    99	}
   100	
   101	// #1910 r3 Codex: the collision gate must not model endpoint ids the
   102	// snapshot builder never publishes. An interface-level WireGuard
   103	// tunnel with units emits exactly ONE endpoint (lowest unit ref), so
   104	// a collision involving a higher, never-emitted unit ref must not
   105	// reject the commit. Real collision under the frozen fold:
   106	// StableTunnelEndpointID("wg0.1") == StableTunnelEndpointID("wg341")
   107	// == 14730, but only "wg0.0" (16091) and "wg341" are published.
   108	func TestTunnelEndpointIDNoFalsePositiveOnNonEmittedWGUnit(t *testing.T) {
   109		if a, b := StableTunnelEndpointID("wg0.1"), StableTunnelEndpointID("wg341"); a != b || a != 14730 {
   110			t.Fatalf("precondition: wg0.1=%d wg341=%d, want both 14730 (frozen fold)", a, b)
   111		}
   112		tree := buildTree(t, []string{
   113			"set interfaces wg0 tunnel mode wireguard",
   114			"set interfaces wg0 unit 0 family inet address 10.70.0.1/30",
   115			"set interfaces wg0 unit 1 family inet address 10.70.0.5/30",
   116			"set interfaces wg341 tunnel mode wireguard",
   117		})
   118		cfg, err := CompileConfig(tree)
   119		if err != nil {
   120			t.Fatalf("CompileConfig rejected a config whose only id collision is on a never-emitted WG unit ref: %v", err)
   121		}
   122		for _, w := range cfg.Warnings {
   123			if strings.Contains(w, "collision") {
   124				t.Fatalf("unexpected collision warning: %q", w)
   125			}
   126		}
   127	}
   128	
   129	// #1910 r4 Codex: a non-canonical numeric unit spelling (`unit 01`)
   130	// compiles to unit 1 and the builder emits/hashes the canonical
   131	// "wg0.1" — the gate must hash the SAME canonical ref, or it misses
   132	// the frozen wg0.1/wg341 collision (14730) and the runtime usedIDs
   133	// belt silently drops an endpoint instead of failing the commit.
   134	func TestTunnelEndpointIDLeadingZeroUnitStillCollides(t *testing.T) {
   135		tree := buildTree(t, []string{
   136			"set interfaces wg0 tunnel mode wireguard",
   137			"set interfaces wg0 unit 01 family inet address 10.70.0.1/30",
   138			"set interfaces wg341 tunnel mode wireguard",
   139		})
   140		_, err := CompileConfig(tree)
   141		if err == nil {
   142			t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind a leading-zero unit spelling (wg0.01 -> emits wg0.1, collides with wg341)")
   143		}
   144		for _, want := range []string{"wg0.1", "wg341", "collision"} {
   145			if !strings.Contains(err.Error(), want) {
   146				t.Fatalf("collision error %q does not mention %q", err.Error(), want)
   147			}
   148		}
   149	}
   150	
   151	// #1910 r5 Codex: an interface-level WG tunnel whose ONLY unit
   152	// spelling overflows strconv.Atoi compiles with iface.Units empty, so
   153	// the builder emits the BARE interface ref — the gate must hash that
   154	// bare ref, not the raw overflow spelling (which hashes elsewhere and
   155	// would let a real builder-emitted collision pass strict compile,
   156	// landing on the runtime usedIDs drop instead of failing commit).
   157	// Frozen collision: StableTunnelEndpointID("wg0") ==
   158	// StableTunnelEndpointID("wg34524.0") == 17799.
   159	func TestTunnelEndpointIDOverflowOnlyUnitHashesBareRef(t *testing.T) {
   160		if a, b := StableTunnelEndpointID("wg0"), StableTunnelEndpointID("wg34524.0"); a != b || a != 17799 {
   161			t.Fatalf("precondition: wg0=%d wg34524.0=%d, want both 17799 (frozen fold)", a, b)
   162		}
   163		tree := buildTree(t, []string{
   164			"set interfaces wg0 tunnel mode wireguard",
   165			"set interfaces wg0 unit 99999999999999999999999999999999999999 family inet address 10.70.2.1/30",
   166			"set interfaces wg34524 unit 0 tunnel mode wireguard",
   167		})
   168		if _, err := CompileConfig(tree); err == nil {
   169			t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind an overflow-only unit spelling (wg0 emits bare ref, collides with wg34524.0)")
   170		}
   171	}
   172	
   173	// The same canonicalization must hold on the per-unit branches: a
   174	// UNIT-LEVEL tunnel declared as `unit 01` compiles to unit 1 and the
   175	// builder emits "wg0.1" — the gate must hash the canonical ref there
   176	// too, or it misses the frozen wg0.1/wg341 collision (14730).
   177	func TestTunnelEndpointIDUnitLevelLeadingZeroStillCollides(t *testing.T) {
   178		tree := buildTree(t, []string{
   179			"set interfaces wg0 unit 01 tunnel mode wireguard",
   180			"set interfaces wg341 tunnel mode wireguard",
   181		})
   182		_, err := CompileConfig(tree)
   183		if err == nil {
   184			t.Fatalf("CompileConfig accepted a builder-emitted collision hidden behind a unit-level leading-zero spelling (wg0.01 -> emits wg0.1, collides with wg341)")
   185		}
   186		for _, want := range []string{"wg0.1", "wg341", "collision"} {
   187			if !strings.Contains(err.Error(), want) {
   188				t.Fatalf("collision error %q does not mention %q", err.Error(), want)
   189			}
   190		}
   191	}
   192	
   193	// #1910 r6 Codex: duplicate spellings of the same unit number must
   194	// follow the typed compiler's LAST-WINS overwrite
   195	// (ifc.Units[unitNum] = unit per instance). When `unit 00` carries
   196	// the tunnel but a later `unit 0` re-declares the unit without one,
   197	// the compiled unit has no tunnel and the builder emits nothing — the
   198	// gate must not register the ref (false reject). When the order is
   199	// reversed the tunnel-carrying instance wins and the collision is
   200	// real.
   201	func TestTunnelEndpointIDDuplicateUnitSpellingLastWins(t *testing.T) {
   202		// Tunnel on the OVERWRITTEN earlier instance: no endpoint emitted,
   203		// so the wg1408.0/wg78.0 collision (both refs would collide if
   204		// emitted) must NOT reject the commit.
   205		tree := buildTree(t, []string{
   206			"set interfaces wg1408 unit 00 tunnel mode wireguard",
   207			"set interfaces wg1408 unit 0 family inet address 10.70.3.1/30",
   208			"set interfaces wg78 unit 0 tunnel mode wireguard",
   209		})
   210		if _, err := CompileConfig(tree); err != nil {
   211			t.Fatalf("CompileConfig rejected a collision on a ref whose tunnel lives only on an overwritten duplicate unit instance: %v", err)
   212		}
   213		// Tunnel on the LAST instance: the unit compiles with the tunnel,
   214		// the builder emits wg1408.0, and the collision must reject.
   215		tree = buildTree(t, []string{
   216			"set interfaces wg1408 unit 00 family inet address 10.70.3.1/30",
   217			"set interfaces wg1408 unit 0 tunnel mode wireguard",
   218			"set interfaces wg78 unit 0 tunnel mode wireguard",
   219		})
   220		if _, err := CompileConfig(tree); err == nil {
   221			t.Fatalf("CompileConfig accepted a real collision whose tunnel lives on the last duplicate unit instance (wg1408.0 vs wg78.0)")
   222		}
   223	}
   224	
   225	// And the inverse: a collision on the EMITTED lowest unit ref of an
   226	// interface-level WG tunnel must still be rejected.
   227	func TestTunnelEndpointIDCollisionOnEmittedWGUnitStillRejected(t *testing.T) {
   228		tree := buildTree(t, []string{
   229			"set interfaces wg1408 tunnel mode wireguard",
   230			"set interfaces wg1408 unit 0 family inet address 10.70.1.1/30",
   231			"set interfaces wg1408 unit 1 family inet address 10.70.1.5/30",
   232			"set interfaces wg78 unit 0 tunnel mode wireguard",
   233		})
   234		if _, err := CompileConfig(tree); err == nil {
   235			t.Fatalf("CompileConfig accepted a collision on the emitted lowest unit ref (wg1408.0 vs wg78.0)")
   236		}
   237	}
   238	
   239	// Non-colliding multi-tunnel configs must compile clean (no false
   240	// positives from the gate).
   241	func TestTunnelEndpointIDNoFalsePositive(t *testing.T) {
   242		tree := buildTree(t, []string{
   243			"set interfaces wg0 unit 0 tunnel mode wireguard",
   244			"set groups node0 interfaces gr-0/0/0 unit 0 tunnel mode gre",
   245			"set groups node0 interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
   246			"set groups node0 interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2",
   247		})
   248		cfg, err := CompileConfig(tree)
   249		if err != nil {
   250			t.Fatalf("CompileConfig rejected a non-colliding config: %v", err)
   251		}
   252		for _, w := range cfg.Warnings {
   253			if strings.Contains(w, "tunnel endpoint id collision") {
   254				t.Fatalf("unexpected collision warning: %q", w)
   255			}
   256		}
   257	}

exec
/bin/bash -lc "nl -ba pkg/config/parser_ast_test.go | sed -n '3920,3995p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
  3920			}
  3921			if err := tree.SetPath(path); err != nil {
  3922				t.Fatalf("SetPath(%v): %v", path, err)
  3923			}
  3924		}
  3925		cfg0, err := CompileConfigForNode(tree, 0)
  3926		if err != nil {
  3927			t.Fatalf("CompileConfigForNode(0): %v", err)
  3928		}
  3929		if cfg0.System.HostName != "fw0" {
  3930			t.Errorf("node0 hostname = %q, want fw0", cfg0.System.HostName)
  3931		}
  3932		if cfg0.Chassis.Cluster == nil || cfg0.Chassis.Cluster.NodeID != 0 {
  3933			t.Errorf("node0 NodeID = %v, want 0", cfg0.Chassis.Cluster)
  3934		}
  3935		cfg1, err := CompileConfigForNode(tree, 1)
  3936		if err != nil {
  3937			t.Fatalf("CompileConfigForNode(1): %v", err)
  3938		}
  3939		if cfg1.System.HostName != "fw1" {
  3940			t.Errorf("node1 hostname = %q, want fw1", cfg1.System.HostName)
  3941		}
  3942		if cfg1.Chassis.Cluster == nil || cfg1.Chassis.Cluster.NodeID != 1 {
  3943			t.Errorf("node1 NodeID = %v, want 1", cfg1.Chassis.Cluster)
  3944		}
  3945		if tree.FindChild("groups") == nil {
  3946			t.Error("groups node stripped from original tree")
  3947		}
  3948		if tree.FindChild("apply-groups") == nil {
  3949			t.Error("apply-groups node stripped from original tree")
  3950		}
  3951	}
  3952	
  3953	func TestCompileConfigForNodeBackwardCompat(t *testing.T) {
  3954		tree := &ConfigTree{}
  3955		setCommands := []string{`set groups node0 system host-name fw0`, `set apply-groups "${node}"`}
  3956		for _, cmd := range setCommands {
  3957			path, err := ParseSetCommand(cmd)
  3958			if err != nil {
  3959				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
  3960			}
  3961			if err := tree.SetPath(path); err != nil {
  3962				t.Fatalf("SetPath(%q): %v", cmd, err)
  3963			}
  3964		}
  3965		cfg, err := CompileConfig(tree)
  3966		if err != nil {
  3967			t.Fatalf("CompileConfig() unexpected error: %v", err)
  3968		}
  3969		if cfg.System.HostName != "fw0" {
  3970			t.Fatalf("hostname = %q, want fw0", cfg.System.HostName)
  3971		}
  3972		found := false
  3973		for _, w := range cfg.Warnings {
  3974			if strings.Contains(w, `"${node}"`) && strings.Contains(w, "node0") {
  3975				found = true
  3976			}
  3977		}
  3978		if !found {
  3979			t.Fatalf("expected node placeholder warning, got %v", cfg.Warnings)
  3980		}
  3981	}
  3982	
  3983	func TestExpandGroupsWithVarsNilPreservesBackwardCompat(t *testing.T) {
  3984		tree := &ConfigTree{}
  3985		setCommands := []string{"set groups common system host-name test-fw", "set apply-groups common"}
  3986		for _, cmd := range setCommands {
  3987			path, err := ParseSetCommand(cmd)
  3988			if err != nil {
  3989				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
  3990			}
  3991			if err := tree.SetPath(path); err != nil {
  3992				t.Fatalf("SetPath(%q): %v", cmd, err)
  3993			}
  3994		}
  3995		if err := tree.ExpandGroupsWithVars(nil); err != nil {

exec
/bin/bash -lc "rg -n \"func compile(System|Security|Applications|Protocols|Routing|Policy|Zones|Services|Chassis|Class|Forwarding|Groups)|compileInterfaces\\(\" pkg/config/compiler.go pkg/config/compiler_*.go" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
pkg/config/compiler_system.go:14:func compileSystem(node *Node, sys *SystemConfig) error {
pkg/config/compiler_system.go:385:func compileSystemDataplaneType(node *Node) (string, error) {
pkg/config/compiler_system.go:879:func compileChassis(node *Node, ch *ChassisConfig) error {
pkg/config/compiler_class_of_service.go:11:func compileClassOfService(node *Node, cos *ClassOfServiceConfig) error {
pkg/config/compiler_services.go:241:func compileServices(node *Node, svc *ServicesConfig) error {
pkg/config/compiler_services.go:734:func compileForwardingOptions(node *Node, fo *ForwardingOptionsConfig) error {
pkg/config/compiler_security.go:8:func compileSecurity(node *Node, sec *SecurityConfig) error {
pkg/config/compiler_security.go:88:func compileZones(node *Node, sec *SecurityConfig) error {
pkg/config/compiler_security.go:197:func compilePolicy(polInst struct {
pkg/config/compiler_routing.go:9:func compileRoutingOptions(node *Node, ro *RoutingOptionsConfig) error {
pkg/config/compiler_routing.go:274:func compileRoutingInstances(node *Node, cfg *Config) error {
pkg/config/compiler_routing.go:346:func compilePolicyOptions(node *Node, po *PolicyOptionsConfig) error {
pkg/config/compiler_protocols.go:12:func compileProtocols(node *Node, proto *ProtocolsConfig) error {
pkg/config/compiler.go:261:			if err := compileInterfaces(node, &cfg.Interfaces); err != nil {
pkg/config/compiler.go:1483:func compileApplications(node *Node, apps *ApplicationsConfig) error {
pkg/config/compiler_interfaces.go:25:func compileInterfaces(node *Node, ifaces *InterfacesConfig) error {

codex
There is one material inconsistency now: the core design accepts a Defect-B residual by keeping the old view-1 collector, but the test plan still demands that the phantom be shed. I’m verifying whether that residual is limited to un-applied groups or whether it still applies to main/applied config as well.
exec
/bin/bash -lc "nl -ba docs/research/1914-tunnel-endpoint-collision-gate/plan.md | sed -n '255,335p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
   255	    un-applied → a complete-only view 1 drops `gr-0/0/0.0`, views 2/3 never
   256	    expand the un-applied group, the ref is registered NOWHERE → **false
   257	    ACCEPT**, violating the #1873 group-symmetry invariant.
   258	
   259	  Therefore view 1 MUST remain the existing presence-only union. Its
   260	  Defect-B over-registration (phantom for an incomplete non-WG tunnel that
   261	  is never emitted by any node) is the price of preserving cross-node
   262	  symmetry for un-applied groups, and is **accepted + documented (Path 4
   263	  for B's residual)**. Views 2/3 fix Defect B for every applied-group case
   264	  for free (they run the real src/dst gate post-expansion).
   265	- **O2 — RESOLVED: NO double-`CompileConfig`.** Reading back
   266	  `buildTunnelEndpointSnapshots` is WRONG for two independent reasons the
   267	  reviewers proved: (a) `CompileConfig*` call the gate FIRST
   268	  (`compiler.go:115-119`, `:176-180`) → calling them from the gate
   269	  **recurses to stack overflow** (AGY F2 Critical, Codex F1); (b) the
   270	  builder's `usedIDs` belt (`tunnels.go:100-105`) has ALREADY DROPPED one
   271	  of the colliding pair, so the gate would see only one ref and Defect A
   272	  would STILL false-accept (Codex F1 High). The gate must enumerate
   273	  candidate names BEFORE any `usedIDs` drop, via a recursion-free path
   274	  (§4).
   275	- **O3 — RESOLVED: yes, factor an SSOT emitter, config-pure.** The emitter
   276	  lives in `pkg/config` (no import cycle — `pkg/dataplane/userspace`
   277	  already imports `pkg/config`). It returns the **configured** candidate
   278	  endpoint-name set from a typed `*config.Config`; it does NOT see runtime
   279	  `InterfaceSnapshot` rows (those don't exist at commit). The builder
   280	  consumes the emitter and THEN intersects with runtime ifaces + applies
   281	  `usedIDs` (AGY F4, Codex F4). The emitter is the SSOT for NAME emission
   282	  only; runtime filtering stays in the builder. Mandatory: the builder is
   283	  refactored to call the emitter (not a parallel copy) + a differential
   284	  parity test guards drift (the #1910 r2-r6 drift class).
   285	- **O4 — RESOLVED: Defect B is fixed for applied-group cases by views 2/3,
   286	  and document-only for its un-applied-group residual.** The residual
   287	  phantom false-reject requires an incomplete non-WG tunnel that (a)
   288	  appears in view 1's presence union, (b) is emitted by no node, AND (c)
   289	  folds onto a real emitted ref — joint probability negligible (1/65535 ×
   290	  half-configured-and-never-applied). The runtime belt + the new doc
   291	  comment cover it.
   292	
   293	---
   294	
   295	## 4. Recommended approach (RECONCILED with r1 three-way review)
   296	
   297	**Path 1 for Defect A** (the High false accept) via a recursion-free,
   298	pre-`usedIDs` three-view union; **document-only for Defect B's
   299	un-applied-group residual** (views 2/3 fix the applied-group cases for
   300	free). Concrete, reviewer-corrected shape:
   301	
   302	### 4.1 SSOT name emitter (config-pure, pre-`usedIDs`)
   303	
   304	Add `pkg/config.EmitTunnelEndpointNames(cfg *config.Config) []string` (or a
   305	`map[string]struct{}`): given a typed, already-expanded `*config.Config`, it
   306	returns the exact set of unit-qualified endpoint names the builder would
   307	emit FROM CONFIG ALONE — same non-WG src/dst gate (drop if src or dst
   308	empty), same WG single-lowest-unit pick, same canonical decimal unit
   309	formatting, same last-wins duplicate-unit. It does **NOT** apply the
   310	`usedIDs` collision drop and does **NOT** consult runtime
   311	`InterfaceSnapshot` rows (AGY F4, Codex F4 — those don't exist at commit).
   312	
   313	`buildTunnelEndpointSnapshots` is refactored to call
   314	`EmitTunnelEndpointNames` for its name set, then intersect with runtime
   315	`ifaceByName`, then apply `usedIDs`. One name-emission truth; the runtime
   316	filtering + drop stay in the builder. A differential parity test
   317	(`tunnelid_test.go`) asserts the gate's emitter output == the builder's
   318	configured-name set over a tunnel-config corpus (kills the #1910 r2-r6
   319	drift class).
   320	
   321	### 4.2 Gate computes a recursion-free three-view union
   322	
   323	`validateTunnelEndpointIDCollisionAST` builds:
   324	
   325	- **View 1 — pre-expansion presence union (UNCHANGED).** Exactly today's
   326	  `collectTunnelEndpointNamesAST` over `interfaces` ∪ every `groups` block.
   327	  Preserves the #1873 un-applied cross-node symmetry guarantee
   328	  (`TestTunnelEndpointIDCollisionAcrossGroupsIsSymmetric`). Keeps its
   329	  Defect-B over-registration (accepted residual).
   330	- **View 2 — post-expansion node0 emitted names.** `tree.Clone()` →
   331	  `ExpandGroupsWithVars({node:node0})` → `compileInterfaces` (the
   332	  gate-free interfaces sub-compiler, `compiler_interfaces.go:25`, which does
   333	  NOT call the collision gate) into a throwaway `InterfacesConfig` →
   334	  `EmitTunnelEndpointNames`. **Never calls `CompileConfig*`** → no recursion
   335	  (AGY F2, Codex F1).

exec
/bin/bash -lc "nl -ba docs/research/1914-tunnel-endpoint-collision-gate/plan.md | sed -n '386,410p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
   386	## 6. Test plan
   387	
   388	1. **Regression (must stay green):** all 13 existing `tunnelid_test.go`
   389	   tests, including the frozen-fold pins and the group-symmetry test.
   390	2. **Defect A:** the §1.1 three-line wildcard config must now FAIL strict
   391	   commit with a `wg78.0`/`wg1408.0` + `824` + `collision` + `rename`
   392	   error; must WARN (not error) on the lenient path.
   393	3. **Defect A symmetry:** the wildcard config must reject identically under
   394	   `CompileConfigForNode(tree, 0)` and `CompileConfigForNode(tree, 1)`.
   395	4. **Defect B:** a half-configured GRE (no src/dst) that folds onto a real
   396	   emitted ref must NOT falsely reject (phantom shed); a COMPLETE GRE that
   397	   genuinely collides must still reject.
   398	5. **No false positives:** the existing non-colliding multi-tunnel config
   399	   stays clean; a WG wildcard group applied to a single interface (no
   400	   second colliding ref) compiles clean.
   401	6. **SSOT parity:** a differential test asserting `EmitTunnelEndpointNames(cfg)`
   402	   equals the builder's configured-name set (before runtime-iface intersect
   403	   + `usedIDs`) for a corpus of tunnel configs (the anti-drift guard, O3).
   404	7. **No-recursion regression:** a test that the gate on a wildcard/multi-node
   405	   config returns in bounded time (guards against the Finding-2 recursion
   406	   if a future edit reintroduces a `CompileConfig*` call from the gate).
   407	8. **Non-fatal peer-group:** `groups node0 ... ; apply-groups "${node}"`
   408	   with NO `groups node1` must COMMIT cleanly (view 3 contributes empty,
   409	   not an error) — the Finding-2/Codex-F3/AGY-F1 regression.
   410	9. `make test` for `pkg/config` + `pkg/dataplane/userspace`.

exec
/bin/bash -lc "nl -ba pkg/config/tunnelid.go | sed -n '61,124p;162,178p'" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
    61	func collectTunnelEndpointNamesAST(ifacesNode *Node, out map[string]struct{}) {
    62		if ifacesNode == nil {
    63			return
    64		}
    65		for _, iface := range ifacesNode.Children {
    66			if iface.IsLeaf {
    67				continue
    68			}
    69			name := iface.Name()
    70			if name == "" {
    71				continue
    72			}
    73			tunnelNode := iface.FindChild("tunnel")
    74			hasIfaceTunnel := tunnelNode != nil
    75			units := namedInstances(iface.FindChildren("unit"))
    76			// Mirror the typed compiler's unit admission: only
    77			// Atoi-parseable names become InterfaceUnit entries, and a
    78			// duplicate spelling of the same number (`unit 00` then
    79			// `unit 0`) OVERWRITES — the compiler does
    80			// `ifc.Units[unitNum] = unit` per instance, so the LAST
    81			// declared instance wins and only ITS tunnel node counts
    82			// (#1910 r6 Codex: sticky-OR here would falsely reject a
    83			// collision on a ref whose tunnel lives only on an
    84			// overwritten earlier instance).
    85			unitNums := make([]int, 0, len(units))
    86			unitTunnel := make(map[int]bool, len(units))
    87			for _, unit := range units {
    88				n, err := strconv.Atoi(unit.name)
    89				if err != nil {
    90					continue
    91				}
    92				if _, seen := unitTunnel[n]; !seen {
    93					unitNums = append(unitNums, n)
    94				}
    95				unitTunnel[n] = unit.node.FindChild("tunnel") != nil
    96			}
    97			if hasIfaceTunnel {
    98				if len(unitNums) == 0 {
    99					// No unit compiles (none declared, or none parses):
   100					// the builder sees len(iface.Units)==0 and emits the
   101					// bare interface ref.
   102					out[name] = struct{}{}
   103					continue
   104				}
   105				if astTunnelModeWireguard(tunnelNode) {
   106					lowest := unitNums[0]
   107					for _, n := range unitNums[1:] {
   108						if n < lowest {
   109							lowest = n
   110						}
   111					}
   112					out[fmt.Sprintf("%s.%d", name, lowest)] = struct{}{}
   113					continue
   114				}
   115				for _, n := range unitNums {
   116					out[fmt.Sprintf("%s.%d", name, n)] = struct{}{}
   117				}
   118				continue
   119			}
   120			for _, n := range unitNums {
   121				if unitTunnel[n] {
   122					out[fmt.Sprintf("%s.%d", name, n)] = struct{}{}
   123				}
   124			}
   162	func validateTunnelEndpointIDCollisionAST(tree *ConfigTree, lenient bool) ([]string, error) {
   163		names := make(map[string]struct{})
   164		collectTunnelEndpointNamesAST(tree.FindChild("interfaces"), names)
   165		for _, child := range tree.Children {
   166			if child.Name() != "groups" {
   167				continue
   168			}
   169			for _, group := range child.Children {
   170				// Node{Keys:["groups","node0"]} merges the group name
   171				// into Keys[1]; the children are then the group body.
   172				if len(child.Keys) >= 2 {
   173					collectTunnelEndpointNamesAST(child.FindChild("interfaces"), names)
   174					break
   175				}
   176				collectTunnelEndpointNamesAST(group.FindChild("interfaces"), names)
   177			}
   178		}

exec
/bin/bash -lc "python3 - <<'PY'
import sys

def fnv1a64(s):
    h=0xcbf29ce484222325
    for b in s.encode():
        h "'^= b
        h = (h * 0x100000001b3) & ((1<<64)-1)
    return h

def stable(s):
    x=fnv1a64(s)
    folded = (x & 0xffff) ''^ ((x>>16)&0xffff) ''^ ((x>>32)&0xffff) ''^ ((x>>48)&0xffff)
    return folded % 0xffff + 1

target=stable('"'gr-0/0/0.0')
print('gr-0/0/0.0', target)
for prefix in ['wg','gr-0/0/','ip-0/0/']:
    for i in range(200000):
        if prefix == 'gr-0/0/':
            name=f'gr-0/0/{i}.0'
        elif prefix == 'ip-0/0/':
            name=f'ip-0/0/{i}.0'
        else:
            name=f'{prefix}{i}.0'
        if name "'!= '"'gr-0/0/0.0' and stable(name)==target:
            print('collision', name, stable(name))
            sys.exit(0)
print('none')
PY" in /home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision
 succeeded in 0ms:
gr-0/0/0.0 44687
collision wg29715.0 44687

codex
PLAN-NEEDS-REVISION

**Finding 1 High: Defect-B residual is mis-scoped, and §6 contradicts §4.2.**

r2 says view 1 stays unchanged and keeps over-registration: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/docs/research/1914-tunnel-endpoint-collision-gate/plan.md:325). But it also claims “Defect B is fixed for applied-group cases” at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/docs/research/1914-tunnel-endpoint-collision-gate/plan.md:285), and §6 requires a half-configured GRE collision to “NOT falsely reject” at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/docs/research/1914-tunnel-endpoint-collision-gate/plan.md:395).

That cannot be true with unchanged view 1. Current view 1 registers tunnel presence without source/destination checks: [tunnelid.go](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/pkg/config/tunnelid.go:73), [tunnelid.go](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/pkg/config/tunnelid.go:120), and it includes all groups: [tunnelid.go](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/pkg/config/tunnelid.go:165). The builder drops incomplete non-WG tunnels: [tunnels.go](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/pkg/dataplane/userspace/tunnels.go:61).

Concrete applied-group counterexample:

```text
set groups g interfaces gr-0/0/0 unit 0 tunnel mode gre
set apply-groups g
set interfaces wg29715 unit 0 tunnel mode wireguard
```

Using the frozen fold logic, `gr-0/0/0.0` and `wg29715.0` both fold to `44687`. View 1 still registers the incomplete GRE phantom, views 2/3 drop it, and the union still rejects. So the residual is not just “un-applied-group”; it remains for main config and applied groups too.

**Finding 2 Medium: §4.1’s emitter API is underspecified for builder SSOT use.**

The boundary is right: config-pure emitter, builder applies runtime iface intersection and `usedIDs`. But §4.1 defines `EmitTunnelEndpointNames` as names only: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/docs/research/1914-tunnel-endpoint-collision-gate/plan.md:304). The builder needs the matching `*TunnelConfig` to populate snapshot fields: [tunnels.go](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/pkg/dataplane/userspace/tunnels.go:54), [tunnels.go](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/pkg/dataplane/userspace/tunnels.go:106). Revise the plan to return candidate entries such as `{Name, Tunnel}` or specify a helper that avoids re-deriving emission decisions in userspace.

r1 status: F1 recursion/pre-`usedIDs` is addressed; `compileInterfaces` is gate-free. F3 non-fatal per-node expansion error is addressed symmetrically. F4 boundary is conceptually addressed. F2/O1 is structurally addressed for preserving #1873 and fixing Defect A, but the Defect-B claims and tests are still wrong.
tokens used
79,993
PLAN-NEEDS-REVISION

**Finding 1 High: Defect-B residual is mis-scoped, and §6 contradicts §4.2.**

r2 says view 1 stays unchanged and keeps over-registration: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/docs/research/1914-tunnel-endpoint-collision-gate/plan.md:325). But it also claims “Defect B is fixed for applied-group cases” at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/docs/research/1914-tunnel-endpoint-collision-gate/plan.md:285), and §6 requires a half-configured GRE collision to “NOT falsely reject” at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/docs/research/1914-tunnel-endpoint-collision-gate/plan.md:395).

That cannot be true with unchanged view 1. Current view 1 registers tunnel presence without source/destination checks: [tunnelid.go](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/pkg/config/tunnelid.go:73), [tunnelid.go](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/pkg/config/tunnelid.go:120), and it includes all groups: [tunnelid.go](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/pkg/config/tunnelid.go:165). The builder drops incomplete non-WG tunnels: [tunnels.go](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/pkg/dataplane/userspace/tunnels.go:61).

Concrete applied-group counterexample:

```text
set groups g interfaces gr-0/0/0 unit 0 tunnel mode gre
set apply-groups g
set interfaces wg29715 unit 0 tunnel mode wireguard
```

Using the frozen fold logic, `gr-0/0/0.0` and `wg29715.0` both fold to `44687`. View 1 still registers the incomplete GRE phantom, views 2/3 drop it, and the union still rejects. So the residual is not just “un-applied-group”; it remains for main config and applied groups too.

**Finding 2 Medium: §4.1’s emitter API is underspecified for builder SSOT use.**

The boundary is right: config-pure emitter, builder applies runtime iface intersection and `usedIDs`. But §4.1 defines `EmitTunnelEndpointNames` as names only: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/docs/research/1914-tunnel-endpoint-collision-gate/plan.md:304). The builder needs the matching `*TunnelConfig` to populate snapshot fields: [tunnels.go](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/pkg/dataplane/userspace/tunnels.go:54), [tunnels.go](/home/ps/git/bpfrx/.claude/worktrees/1914-research-tunnel-collision/pkg/dataplane/userspace/tunnels.go:106). Revise the plan to return candidate entries such as `{Name, Tunnel}` or specify a helper that avoids re-deriving emission decisions in userspace.

r1 status: F1 recursion/pre-`usedIDs` is addressed; `compileInterfaces` is gate-free. F3 non-fatal per-node expansion error is addressed symmetrically. F4 boundary is conceptually addressed. F2/O1 is structurally addressed for preserving #1873 and fixing Defect A, but the Defect-B claims and tests are still wrong.
