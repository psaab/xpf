package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_interface_unit_alias.go carries the #5631 (codex-review-181 M23)
// reject-at-commit gate for numeric interface-unit ALIASES — two distinct
// unit-number spellings under one interface that canonicalize to the SAME
// logical unit — PROMOTED in #5878 to a BOTH-NODE-EFFECTIVE union gate that
// runs PRE-expansion so a peer-only alias is caught at either node's commit.
//
// The compiler keys logical units by the numeric value: compileInterfaces
// (compiler_interfaces.go) iterates `namedInstances(child.FindChildren("unit"))`
// and canonicalizes each RAW spelling through `strconv.Atoi` — but only AFTER
// the AST has already split `unit 00` and `unit 0` into two SEPARATE named
// instances. The two instances then collide on the same `ifc.Units[unitNum]`
// key, and the two side effects disagree:
//
//   - `ifc.Units[unitNum] = unit` is LAST-WRITER-WINS: the later spelling's
//     unit (its filter, its addresses, its flags) completely REPLACES the
//     earlier one — so the interface's input/output firewall filter is decided
//     by config order.
//   - the interface-level tunnel address collection
//     (`ifc.Tunnel.Addresses = append(ifc.Tunnel.Addresses, unit.Addresses...)`)
//     is APPEND-ONLY: it accumulates the addresses of EVERY spelling, so a
//     stale address from the spelling that LOST the filter race still survives
//     on the tunnel.
//
// The observable result is order-dependent AND self-inconsistent: compiling
// `unit 00` then `unit 0` versus the reverse order yields a different final
// filter, a different unit address set, and a different tunnel-address set
// (see interface_unit_alias_5631_test.go). Because the winning filter flips
// with config order, an operator who reorders two otherwise-equivalent set
// lines can silently disarm the interface's firewall filter — a fail-open on
// a security hook — while the tunnel keeps forwarding on the stale address.
//
// Junos treats a logical unit as an integer identity: `unit 00` and `unit 0`
// are the SAME unit, and there is no meaningful configuration in which two
// numeric aliases of one unit carry DIFFERENT security state. Rather than pick
// an arbitrary winner (which spelling's filter survives is exactly the
// order-dependent ambiguity that makes this unsafe), this gate REJECTS the
// aliased config at commit so the operator authors a single canonical
// `unit <n>`. This matches how the rest of the compiler resolves unit
// identity (numeric) and the reject-at-commit / warn-on-load doctrine used by
// the sibling silent-inconsistency gates (validateApplicationNameCollisionsAST,
// validateFirewallFilterFamilyCollisionsAST, #1960 / #3261).
//
// # Both-node union (#5878)
//
// The #5631 gate originally ran INSIDE compileExpanded (runPreWalkGates) AFTER
// `tree.ExpandGroupsWithVars({node: nodeN})`, so it saw exactly the SUBMITTING
// node's post-`${node}` effective view. A `groups node1 { … unit 01 }` block
// applied through `apply-groups "${node}"` folds its aliasing spelling onto a
// base `unit 1` ONLY in the standby node's effective view — invisible at a
// node0 commit (Store.compileTree compiles s.nodeID only). The active node
// commits green; the standby's compiled config then diverges (a different
// firewall filter / address set) and a failover silently changes forwarding
// or security posture despite a "synchronized" commit (#5878).
//
// This gate is now the BOTH-NODE UNION, modeled EXACTLY on
// validateTunnelEndpointIDCollisionAST (tunnelid.go), and runs in the
// PRE-expansion gate block of compileTree node branch /
// compileTree (beside the tunnel/zone/table-id gates):
//
//	View 1 — the PRE-expansion presence union across every top-level
//	  "interfaces" root AND every "groups" block, grouping raw unit spellings
//	  under each interface by canonical unit. Catches a collision hidden inside
//	  an un-expandable / node-inverted group and keeps the verdict identical on
//	  both nodes (a `groups node0`-scoped alias must reject on node1 too, or
//	  config-sync would split — originator accepts, peer rejects).
//	View 2 — the concrete per-interface unit spellings after expanding the
//	  candidate for node0 (ExpandGroupsWithVars + expandInterfaceRanges).
//	View 3 — the same for node1.
//
// Views 2/3 close the wildcard / interface-range gap: an apply-group that
// carries the aliasing spelling onto interfaces named by a wildcard or range
// registers only the literal wildcard name in View 1 (which never matches the
// base interface), so only post-expansion do both concrete spellings land on
// the same interface. Per-node expansion errors are NON-FATAL and contribute
// the EMPTY set (mirrors emitNodeExpandedTunnelNames): a config with only
// `groups node0` legitimately fails node1 expansion, and View 1 still covers
// any collision inside the un-expandable group. Because all three views are
// pure functions of the SAME candidate config (Views 2/3 both computed on both
// nodes), the union — and therefore the accept/reject verdict — is IDENTICAL on
// node0 and node1, and it is MONOTONE over the old single-view gate (it only
// ADDS rejects). Same HA-symmetry / monotonicity safety argument tunnelid.go
// makes.
//
// Strict path (commit / commit-check, lenient=false): the lowest colliding
// canonical unit on the lowest-named interface is a hard compile error naming
// the interface, the colliding spellings, and the canonical unit number.
//
// Lenient path (load / peer-sync, lenient=true): every collision is returned as
// a warning and compilation continues, so an already-persisted or peer-synced
// config an older binary silently accepted still BOOTS (#1960 no-brick
// doctrine). The operator gets the warning as the signal to collapse the
// aliases.
//
// This is an AST pre-walk (not a SchemaValidate typed leaf) for the same
// reason as validateUnsupportedInterfaceStanzasAST: the colliding instances
// are merged away by last-writer-wins by the time the typed `ifc.Units` map
// exists — only the raw AST still carries every spelling. Inactive subtrees are
// pruned before the pre-expansion gate block runs (cloneForExpansion), so an
// `inactive:` unit is ignored for free.
//
// Detection is scoped to DISTINCT spellings that canonicalize to the same
// number: a single canonical `unit 0` (the overwhelming common case) never
// trips it, and flat-set `set` lines with the SAME spelling merge into one AST
// node upstream (they are the same unit, not an alias). A non-numeric or
// out-of-range unit token is skipped — the compiler `continue`s on the
// identical CanonicalLogicalUnit error, so it never reaches `ifc.Units` and
// cannot collide.

// collectInterfaceUnitSpellingsAST folds the distinct raw unit spellings under
// each interface of one "interfaces" hierarchy node into perIface, keyed by
// interface name then by CANONICAL logical unit (#5878). Two spellings that
// CanonicalLogicalUnit maps to the same int land in the same inner set — that
// is the collision the gate rejects. A malformed / out-of-range unit token is
// dropped (the compiler drops it too), mirroring the pre-#5878 strconv.Atoi
// skip so detection matches what compileInterfaces actually consumes.
func collectInterfaceUnitSpellingsAST(ifacesNode *Node, perIface map[string]map[int]map[string]int) {
	if ifacesNode == nil {
		return
	}
	for _, iface := range ifacesNode.Children {
		ifName := iface.Name()
		if ifName == "" {
			continue
		}
		for _, inst := range namedInstances(iface.FindChildren("unit")) {
			num, _, err := CanonicalLogicalUnit(inst.name)
			if err != nil {
				continue
			}
			if perIface[ifName] == nil {
				perIface[ifName] = make(map[int]map[string]int)
			}
			if perIface[ifName][num] == nil {
				perIface[ifName][num] = make(map[string]int)
			}
			// #8427: COUNT the instances, do not just record presence. Two
			// hierarchical `unit 0 { ... }` blocks are the SAME spelling, so a
			// presence set has size 1 and the #5631/#5878 alias gate — which
			// fires on two DISTINCT spellings — cannot see them. They are
			// nonetheless two AST instances that collide on one ifc.Units key,
			// with exactly the last-writer-wins / append-only split this gate
			// exists to reject. Counting is per-PASS; the caller folds views
			// with max, never sum, so the same unit seen by the pre-expansion
			// and both post-expansion views is not counted three times.
			perIface[ifName][num][inst.name]++
		}
	}
}

// collectNodeExpandedInterfaceUnitSpellings folds the per-interface unit
// spellings the compiler would see after expanding the candidate tree for
// chassis-cluster node nodeID into perIface (#5878 Views 2/3). It clones the
// candidate, resolves apply-groups "${node}" for the node, expands interface
// ranges (so a range/wildcard member's alias is seen exactly as the real
// runPreWalkGates path sees it), and collects every top-level "interfaces"
// root's units. Mirrors emitNodeExpandedTunnelNames: per-node expansion errors
// are NON-FATAL and contribute the empty set (View 1 still covers a collision
// inside an un-expandable group), so the verdict stays a pure function of the
// candidate config and is identical on both nodes.
func collectNodeExpandedInterfaceUnitSpellings(tree *ConfigTree, nodeID int, perIface map[string]map[int]map[string]int) {
	clone := tree.Clone()
	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := clone.ExpandGroupsWithVars(vars); err != nil {
		return
	}
	// expandInterfaceRanges mutates the clone in place; its warnings are
	// emitted on the real path (runPreWalkGates) and discarded here.
	// #8438: the clone paths only need the budget SKIP (the expansion is capped
	// inside); the rejection is surfaced once, by the prewalk caller.
	_, _ = expandInterfaceRanges(clone)
	for _, ifaces := range clone.FindChildren("interfaces") {
		collectInterfaceUnitSpellingsAST(ifaces, perIface)
	}
}

// foldMaxUnitCounts folds one VIEW's per-interface unit-spelling counts into the
// accumulator, taking the MAX per spelling rather than the sum (#8427).
//
// The three views deliberately overlap: View 1 collects pre-expansion and Views
// 2/3 collect the same tree expanded for node0 and node1, so a single authored
// `unit 0` appears in all three. Summing would count it three times and reject
// every config in the tree. Max keeps the union semantics the alias gate was
// built on while letting a count ABOVE ONE mean what it says — two AST
// instances of the same spelling under one interface, within a single view.
//
// Within View 1 the counts DO accumulate across sibling `interfaces { }` roots
// and groups, which is correct: #5744 established that a split config can
// declare one interface's units across two roots and compileSections compiles
// them all, so two `unit 0` declarations there collide on one ifc.Units key
// exactly as two blocks under one root do.
func foldMaxUnitCounts(dst, src map[string]map[int]map[string]int) {
	for ifName, byUnit := range src {
		if dst[ifName] == nil {
			dst[ifName] = make(map[int]map[string]int, len(byUnit))
		}
		for num, bySpelling := range byUnit {
			if dst[ifName][num] == nil {
				dst[ifName][num] = make(map[string]int, len(bySpelling))
			}
			for spelling, n := range bySpelling {
				if n > dst[ifName][num][spelling] {
					dst[ifName][num][spelling] = n
				}
			}
		}
	}
}

func validateInterfaceUnitAliasCollisionsAST(tree *ConfigTree, lenient bool) ([]string, error) {
	// perIface[ifName][canonicalUnit][rawSpelling] = occurrence count, folded
	// across views with MAX (#8427 — see foldMaxUnitCounts).
	perIface := make(map[string]map[int]map[string]int)

	// View 1 — pre-expansion presence union across every top-level `interfaces`
	// root (#5744: a split config can declare an interface's units across two
	// sibling `interfaces { }` stanzas, and compileSections compiles them all)
	// AND every `groups` block. Modeled on validateTunnelEndpointIDCollisionAST.
	// #8427: each `interfaces` root and each group body is its OWN collection
	// pass, folded with MAX. Counting ACROSS them would read the normal HA
	// pattern — `groups node0` and `groups node1` each declaring `em0 unit 0`
	// with that node's own address — as a duplicate. Measured: accumulating
	// across groups rejected all four shipped cluster configs
	// (docs/ha-cluster*.conf, examples/deploy/ha-pair.conf), which are correct.
	// Two `unit 0` blocks in two SIBLING `interfaces { }` roots are a different
	// shape and are already rejected by the duplicate-container gate.
	for _, ifaces := range tree.FindChildren("interfaces") {
		pass := make(map[string]map[int]map[string]int)
		collectInterfaceUnitSpellingsAST(ifaces, pass)
		foldMaxUnitCounts(perIface, pass)
	}
	for _, child := range tree.Children {
		if child.Name() != "groups" {
			continue
		}
		for _, group := range child.Children {
			// Node{Keys:["groups","node0"]} merges the group name into
			// Keys[1]; the children are then the group body directly.
			if len(child.Keys) >= 2 {
				for _, ifaces := range child.FindChildren("interfaces") {
					pass := make(map[string]map[int]map[string]int)
					collectInterfaceUnitSpellingsAST(ifaces, pass)
					foldMaxUnitCounts(perIface, pass)
				}
				break
			}
			for _, ifaces := range group.FindChildren("interfaces") {
				pass := make(map[string]map[int]map[string]int)
				collectInterfaceUnitSpellingsAST(ifaces, pass)
				foldMaxUnitCounts(perIface, pass)
			}
		}
	}

	// Views 2/3 — post-expansion per-interface unit spellings for node0 and
	// node1. Both computed on both nodes from the shared candidate, so the
	// union stays HA-symmetric; per-node expansion errors contribute the empty
	// set (non-fatal).
	view2 := make(map[string]map[int]map[string]int)
	view3 := make(map[string]map[int]map[string]int)
	collectNodeExpandedInterfaceUnitSpellings(tree, 0, view2)
	collectNodeExpandedInterfaceUnitSpellings(tree, 1, view3)
	foldMaxUnitCounts(perIface, view2)
	foldMaxUnitCounts(perIface, view3)

	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	// Deterministic, node-symmetric first error: lowest-named interface, then
	// lowest colliding canonical unit.
	ifNames := make([]string, 0, len(perIface))
	for ifName := range perIface {
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)

	for _, ifName := range ifNames {
		byUnit := perIface[ifName]
		// #5631/#5878: two or more DISTINCT spellings of one canonical unit.
		// #8427: OR one spelling declared more than once — two hierarchical
		// `unit 0 { ... }` blocks under one interface. Both reach the same
		// ifc.Units key with the same last-writer-wins / append-only split; the
		// only difference is the diagnostic, so they share this loop.
		nums := make([]int, 0, len(byUnit))
		dupSpelling := make(map[int]string, len(byUnit))
		for num := range byUnit {
			if len(byUnit[num]) >= 2 {
				nums = append(nums, num)
				continue
			}
			// Exactly one spelling: flag it when that spelling occurs more than
			// once in any single view. Sorted so the message is deterministic
			// even though the map has one entry (a later refactor could add
			// more).
			only := make([]string, 0, len(byUnit[num]))
			for sp := range byUnit[num] {
				only = append(only, sp)
			}
			sort.Strings(only)
			for _, sp := range only {
				if byUnit[num][sp] >= 2 {
					nums = append(nums, num)
					dupSpelling[num] = sp
					break
				}
			}
		}
		sort.Ints(nums)

		for _, num := range nums {
			if sp, isDup := dupSpelling[num]; isDup {
				if err := emit(
					"interfaces %s: `unit %s` is declared %d times — the later block "+
						"REPLACES the earlier one in ifc.Units[%d] (its firewall "+
						"filter, its addresses, its flags), while the interface-level "+
						"tunnel-address collection APPENDS from every block, so the "+
						"unit's security filter is decided by config order and its "+
						"addresses are not. The #5631/#5878 alias gate cannot see this "+
						"case: it fires on two DISTINCT spellings that canonicalize to "+
						"one unit, and these are the SAME spelling. Merge the blocks "+
						"into one `unit %s { ... }` (#8427)",
					ifName, sp, byUnit[num][sp], num, sp); err != nil {
					return nil, err
				}
				continue
			}
			spellings := make([]string, 0, len(byUnit[num]))
			for s := range byUnit[num] {
				spellings = append(spellings, s)
			}
			sort.Strings(spellings)
			quoted := make([]string, len(spellings))
			for i, s := range spellings {
				quoted[i] = "`unit " + s + "`"
			}
			if err := emit(
				"interfaces %s: %s all name the same logical unit %d — numeric "+
					"unit aliases collapse to one unit whose firewall-filter and "+
					"address ownership then depends on config order (the later "+
					"spelling wins the unit filter while tunnel-address side "+
					"effects accumulate from every spelling, a fail-open on the "+
					"security filter); the aliasing spelling may live in a "+
					"peer-only `groups node{0,1}`/`${node}` block that only "+
					"collides in the STANDBY node's effective view — use a single "+
					"canonical `unit %d` (#5631; both-node union #5878)",
				ifName, strings.Join(quoted, ", "), num, num); err != nil {
				return nil, err
			}
		}
	}
	return warnings, nil
}
