package config

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
)

// StableTunnelEndpointID maps a tunnel interface name (unit-qualified,
// e.g. "wg0.0", "gr-0/0/0.0") to a stable nonzero u16 tunnel-endpoint
// id: FNV-1a 64 xor-folded to 16 bits, mapped into [1, 0xFFFF].
//
// THE FOLD IS WIRE-ADJACENT AND MUST NEVER CHANGE (#1873): tunnel
// endpoint ids cross the cluster as bare numbers (SessionValue.FibGen
// in pkg/cluster/sync_protocol.go), and both HA nodes must compute
// identical ids from identical config. The id is a pure function of
// the interface NAME alone — never of runtime state, the rest of the
// tunnel set, or allocation history — so adding or removing one
// tunnel can never renumber another (the positional-id defect this
// replaces), and both nodes agree by construction.
//
// 0 is never returned: id 0 means "not a tunnel" across the
// dataplane.
func StableTunnelEndpointID(name string) uint16 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	s := h.Sum64()
	folded := uint16(s) ^ uint16(s>>16) ^ uint16(s>>32) ^ uint16(s>>48)
	return folded%0xFFFF + 1
}

// collectTunnelEndpointNamesAST appends the unit-qualified tunnel
// endpoint names declared under one "interfaces" hierarchy node,
// mirroring buildTunnelEndpointSnapshots naming exactly:
//
//   - interface-level tunnel, no COMPILABLE units -> "name"
//   - interface-level WIREGUARD tunnel with units -> "name.N" of the
//     lowest numeric unit only (one persistent TUN = one endpoint,
//     #1910 r2/r3 Codex) — registering every unit would model ids the
//     builder never publishes and could falsely reject a commit on a
//     collision involving a never-emitted ref
//   - interface-level non-WG tunnel with units    -> "name.N" per unit
//   - unit-level tunnel                           -> "name.N"
//
// Every registered ref is the CANONICAL decimal form "%s.%d" of an
// Atoi-parsed unit number, because that is all the builder can ever
// emit: the typed compiler skips any unit whose name fails
// strconv.Atoi (compiler_interfaces.go), so iface.Units holds ints
// and the builder formats "%s.%d". Hashing a raw spelling diverges
// both ways (#1910 r4/r5 Codex): `unit 01` must hash as "wg0.1" or
// the gate misses a real collision on the emitted ref, and an
// overflow-only spelling like `unit 999…9` must NOT register a raw
// ref the builder cannot emit — with every unit unparseable,
// iface.Units is empty and the builder emits the BARE interface ref,
// so the gate registers the bare name in that case too.
//
// Handles both AST shapes (hierarchical merged keys and flat-set
// single-key chains) via the same namedInstances helper the compiler
// uses for unit nodes.
func collectTunnelEndpointNamesAST(ifacesNode *Node, out map[string]struct{}) {
	if ifacesNode == nil {
		return
	}
	for _, iface := range ifacesNode.Children {
		if iface.IsLeaf {
			continue
		}
		name := iface.Name()
		if name == "" {
			continue
		}
		// #14450: duplicate `tunnel` blocks merge (last-wins mode), so
		// presence and the WireGuard selection must consult every block,
		// not the first only.
		tunnelNodes := iface.FindChildren("tunnel")
		hasIfaceTunnel := len(tunnelNodes) > 0
		units := namedInstances(iface.FindChildren("unit"))
		// Mirror the typed compiler's unit admission: only
		// Atoi-parseable names become InterfaceUnit entries, and a
		// duplicate spelling of the same number (`unit 00` then
		// `unit 0`) OVERWRITES — the compiler does
		// `ifc.Units[unitNum] = unit` per instance, so the LAST
		// declared instance wins and only ITS tunnel node counts
		// (#1910 r6 Codex: sticky-OR here would falsely reject a
		// collision on a ref whose tunnel lives only on an
		// overwritten earlier instance).
		unitNums := make([]int, 0, len(units))
		unitTunnel := make(map[int]bool, len(units))
		for _, unit := range units {
			n, err := strconv.Atoi(unit.name)
			if err != nil {
				continue
			}
			if _, seen := unitTunnel[n]; !seen {
				unitNums = append(unitNums, n)
			}
			unitTunnel[n] = len(unit.node.FindChildren("tunnel")) > 0
		}
		if hasIfaceTunnel {
			if len(unitNums) == 0 {
				// No unit compiles (none declared, or none parses):
				// the builder sees len(iface.Units)==0 and emits the
				// bare interface ref.
				out[name] = struct{}{}
				continue
			}
			if astTunnelModeWireguardMerged14450(tunnelNodes) {
				lowest := unitNums[0]
				for _, n := range unitNums[1:] {
					if n < lowest {
						lowest = n
					}
				}
				out[fmt.Sprintf("%s.%d", name, lowest)] = struct{}{}
				continue
			}
			for _, n := range unitNums {
				out[fmt.Sprintf("%s.%d", name, n)] = struct{}{}
			}
			continue
		}
		for _, n := range unitNums {
			if unitTunnel[n] {
				out[fmt.Sprintf("%s.%d", name, n)] = struct{}{}
			}
		}
	}
}

// astTunnelModeWireguard reports whether a tunnel AST node carries an
// explicit `mode wireguard` — the exact extraction the compiler uses
// for TunnelConfig.Mode (nodeVal, compiler_interfaces.go), so the
// collision gate's single-endpoint selection matches the compiled
// outcome by construction. The compiler's prefix-derived default mode
// is only ever gre/ipip, so wireguard is always explicit. The braced
// form `mode { wireguard; }` (#14440) is honoured via nodeVal, which
// reads the braced child shape as well as Keys[1].

// astTunnelModeWireguardMerged14450 reports the merged (#14450)
// WireGuard selection over duplicate interface `tunnel` blocks: the
// last block's explicit mode wins (nodeVal, so the braced form counts
// too), exactly as the compiler's merged TunnelConfig.Mode. A later
// `mode gre` therefore un-selects the single-endpoint WireGuard
// naming an earlier block selected.
func astTunnelModeWireguardMerged14450(nodes []*Node) bool {
	wireguard := false
	for _, n := range nodes {
		// Braced `mode { wireguard; }` (#14440): the raw child's nodeVal
		// carries the value the run expansion flattens away, as in
		// astTunnelModeWireguard.
		for _, prop := range n.Children {
			if prop.Name() == "mode" && nodeVal(prop) != "" {
				wireguard = nodeVal(prop) == "wireguard"
			}
		}
		for _, prop := range tunnelRunChildren9156(n) {
			if prop.Name() == "mode" && nodeVal(prop) != "" {
				wireguard = nodeVal(prop) == "wireguard"
			}
		}
	}
	return wireguard
}

func astTunnelModeWireguard(tunnelNode *Node) bool {
	if tunnelNode == nil {
		return false
	}
	for _, prop := range tunnelNode.Children {
		if prop.Name() == "mode" && nodeVal(prop) == "wireguard" {
			return true
		}
	}
	return false
}

// emitNodeExpandedTunnelNames returns the concrete tunnel-endpoint names
// the snapshot builder would emit after expanding the candidate tree for
// chassis-cluster node nodeID. It is the #1914 post-expansion view (View 2
// for node0, View 3 for node1) used by validateTunnelEndpointIDCollisionAST.
//
// It is RECURSION-FREE by construction: it clones the candidate, expands
// groups for the node, runs the gate-free interfaces sub-compiler
// (compileInterfaces — which does NOT call this collision gate) into a
// throwaway InterfacesConfig, and feeds that typed config through the SSOT
// emitter EmitTunnelEndpointNames. It NEVER calls CompileConfig* (which
// would call the gate first and recurse) and NEVER consults the
// post-usedIDs snapshot (the builder's collision drop has not run, so both
// colliding refs are present).
//
// Per-node expansion or compile errors are NON-FATAL: the view contributes
// the EMPTY set. A config that defines only `groups node0` and references
// `${node}` legitimately has no `groups node1`, so expanding for node1
// hits `undefined group "node1"`; that is a separate, already-handled
// condition on the real per-node compile path (CompileConfig falls back to
// node0 for an undefined ${node}), and the collision gate must not turn it
// into a spurious commit failure. View 1's pre-expansion presence union
// still covers any collision inside the un-expandable group, so dropping
// the failed node's view loses no real coverage and keeps the verdict a
// pure function of the candidate config (both nodes compute identical
// error-to-empty-set handling).
func emitNodeExpandedTunnelNames(tree *ConfigTree, nodeID int, out map[string]struct{}) {
	clone := tree.Clone()
	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := clone.ExpandGroupsWithVars(vars); err != nil {
		return
	}
	// #5691: compile EVERY top-level `interfaces` root into one InterfacesConfig
	// (compileInterfaces merges into the shared map, exactly as compileSections
	// dispatches each root) so a tunnel split into a second stanza is emitted
	// here too. A per-root compile error contributes the empty set (non-fatal),
	// matching the pre-existing doctrine — View 1 above already covers the
	// pre-expansion union.
	ifacesNodes := clone.FindChildren("interfaces")
	if len(ifacesNodes) == 0 {
		return
	}
	ifaces := InterfacesConfig{Interfaces: make(map[string]*InterfaceConfig)}
	for _, ifacesNode := range ifacesNodes {
		// #5829: this is the best-effort tunnel-endpoint-name UNION used for
		// ID allocation, not a commit gate — compile leniently so a malformed
		// `unit <id>` is quarantined (dropped from the union, no hard error)
		// exactly as the pre-#5829 bare-continue did. The strict commit path
		// (compileSections) still hard-rejects the same config.
		if err := compileInterfaces(ifacesNode, &ifaces, compileOpts{lenientNonNumericUnit: true}, nil); err != nil {
			return
		}
	}
	cfg := &Config{Interfaces: ifaces}
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		out[ep.Name] = struct{}{}
	}
}

// validateTunnelEndpointIDCollisionAST checks the UNION of tunnel
// endpoint names across three views of the candidate config for
// StableTunnelEndpointID collisions (#1873 R-B, #1914):
//
//	View 1 — the PRE-expansion presence union across the main
//	  "interfaces" hierarchy AND every "groups" block (unchanged since
//	  #1873). It runs on the pre-expansion tree because ExpandGroups
//	  removes the groups stanza, and it keeps the accept/reject decision
//	  identical on both chassis-cluster nodes: a collision involving a
//	  `groups node0`-scoped tunnel must fail commit on node1 too, or
//	  config-sync would split (originator accepts, peer rejects).
//	View 2 — the concrete tunnel names the builder would emit after
//	  expanding the candidate for node0 (emitNodeExpandedTunnelNames).
//	View 3 — the same for node1.
//
// Views 2/3 (added in #1914) close Defect A: a wildcard apply-group
// (`groups g interfaces <*> unit 0 tunnel mode wireguard`) registers only
// the literal `<*>.0` in View 1, never the post-expansion concrete
// `wg78.0` / `wg1408.0` that fold to the same id — so View 1 alone falsely
// ACCEPTS a builder-emitted collision that the runtime usedIDs belt then
// drops with a loud slog.Error. Views 2/3 expand the wildcard onto the
// real applying interfaces, see both concrete refs, and reject at commit.
// Because all three views are pure functions of the SAME candidate config
// (View 2/3 both expand the shared candidate for a fixed node, computed on
// BOTH nodes), the union stays a pure function of config — HA symmetry is
// preserved. The union is monotone over View 1 (adding Views 2/3 only ADDS
// rejects), so every reject View 1 produced today is preserved.
//
// DOCUMENTED LIMITATION (Defect B, #1914): View 1 registers a ref from
// tunnel-node presence alone with NO source/destination check, while the
// builder drops a non-WireGuard tunnel whose Source or Destination is empty
// (tunnels.go addEndpoint). So a half-configured non-WG tunnel (e.g.
// `gr-0/0/0 unit 0 tunnel mode gre` with no source/dest) registers a
// phantom View-1 ref the builder never emits; if that phantom folds onto a
// real emitted ref (≈1/65535 per pair) the commit is FALSELY REJECTED. This
// is accepted, not fixed: View 1 MUST stay presence-only or the Defect-A
// fix re-opens a false ACCEPT (a group can SUPPLY src/dst later, and an
// un-applied nested-apply-groups group is never expanded by Views 2/3, so a
// complete-only View 1 would under-register and miss a real cross-node
// collision). Narrowing View 1 is mutually exclusive with the Defect-A fix;
// the runtime usedIDs slog.Error belt and the printed "rename one
// interface" remediation are the operator's recourse for the residual.
//
// Strict (commit / commit-check) returns an error; lenient (load /
// peer-sync of an already-active config) returns a warning so an
// upgraded node still boots — the snapshot builder independently
// drops the later-sorting collider (fail-closed belt-and-braces in
// buildTunnelEndpointSnapshots).
func validateTunnelEndpointIDCollisionAST(tree *ConfigTree, lenient bool) ([]string, error) {
	names := make(map[string]struct{})
	// View 1 — pre-expansion presence union (#1873). Union across EVERY
	// top-level `interfaces` root (#5691): a split config can declare tunnel
	// interfaces in a second `interfaces { }` stanza, and compileSections
	// compiles them all, so a first-root-only scan would miss a collision
	// spanning the roots.
	for _, ifaces := range tree.FindChildren("interfaces") {
		collectTunnelEndpointNamesAST(ifaces, names)
	}
	for _, child := range tree.Children {
		if child.Name() != "groups" {
			continue
		}
		for _, group := range child.Children {
			// Node{Keys:["groups","node0"]} merges the group name
			// into Keys[1]; the children are then the group body.
			if len(child.Keys) >= 2 {
				for _, ifaces := range child.FindChildren("interfaces") {
					collectTunnelEndpointNamesAST(ifaces, names)
				}
				break
			}
			for _, ifaces := range group.FindChildren("interfaces") {
				collectTunnelEndpointNamesAST(ifaces, names)
			}
		}
	}
	// Views 2/3 — post-expansion emitted names for node0 and node1
	// (#1914). Both computed on both nodes from the shared candidate, so
	// the union stays HA-symmetric; per-node expansion errors contribute
	// the empty set (non-fatal).
	emitNodeExpandedTunnelNames(tree, 0, names)
	emitNodeExpandedTunnelNames(tree, 1, names)
	if len(names) < 2 {
		return nil, nil
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	byID := make(map[uint16]string, len(sorted))
	var warnings []string
	for _, name := range sorted {
		id := StableTunnelEndpointID(name)
		owner, taken := byID[id]
		if !taken {
			byID[id] = name
			continue
		}
		msg := fmt.Sprintf(
			"tunnel endpoint id collision between %q and %q (both fold to %d) — rename one interface (#1873)",
			owner, name, id)
		if !lenient {
			return nil, fmt.Errorf("interfaces: %s", msg)
		}
		warnings = append(warnings, msg+
			"; the later-sorting tunnel is NOT installed in the dataplane")
	}
	return warnings, nil
}
