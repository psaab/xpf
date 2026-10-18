package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_interfaces_qinq.go carries the #5879 canonical per-physical-
// interface QinQ (stacked-VLAN) honesty gate (#14683: two-level unit form).
//
// Background (#2354): the AF_XDP shim's parse_l2 unwinds exactly ONE VLAN
// tag, so xpf cannot represent a double-tagged (802.1ad S-tag + 802.1Q
// C-tag) frame consistently. A committed inner / second tag is a silent
// functional lie: the frame keeps eth_proto=0x8100, the dispatch `_` arm
// XDP_PASSes it to the kernel forwarding path, and it is never firewalled.
// #2354 rejected the one obvious spelling — a per-unit `inner-vlan-id`
// leaf — at commit.
//
// #5879: that gate validated a LOCAL statement SHAPE (a literal
// `inner-vlan-id` leaf on the committing node's own expansion), not the
// AGGREGATE effective per-physical-interface VLAN stack. Two classes of
// unsupported QinQ therefore bypassed it:
//
//  1. A DIFFERENT inner-tag spelling. `vlan-tags outer <x> inner <y>` (the
//     modern Junos stacked-VLAN syntax) is not in setSchema and has no
//     compiler consumer, so it parse-accepts and is silently dropped — the
//     #2354 gate never looked at `vlan-tags`. The inner half can even be
//     SPLIT across two set statements (`vlan-tags outer 100` +
//     `vlan-tags inner 200`), so no single leaf is the recognizable
//     `inner-vlan-id` the old gate keyed on.
//  2. A PEER-ONLY node view. An `inner-vlan-id` (or `vlan-tags inner`)
//     living under `groups node1` + `apply-groups "${node}"` never
//     materializes when the candidate is compiled for node0, so a commit
//     ON node0 accepted a stack that renders unsupported QinQ on node1 — an
//     active/standby posture disagreement (the standby silently PASSes to
//     the kernel what the primary firewalls, a zone-policy bypass on one
//     node of the pair).
//
// This gate builds the canonical inner/outer tag stack per (interface,
// unit) from BOTH the `vlan-id`/`inner-vlan-id` and the `vlan-tags outer/
// inner` spellings (combined onto one statement OR split across several),
// and evaluates it against the effective view for EVERY cluster node — the
// node0 AND node1 `${node}`/apply-groups expansions — so a QinQ stack split
// across spellings, statements, or a peer-only group is caught on whichever
// node commits. Any INNER (second) tag is unsupported.
//
// #14683: the collector enumerates units with namedInstances (the same
// helper compileInterfaces uses), so the two-level hierarchical form
// `unit { 0 { ... } }` — Keys=[unit] with the numbered instance as a
// child — is seen, and unitVLANStack recurses so a vlan leaf nested
// under a packed-tail child (flat `unit 0 point-to-point inner-vlan-id`)
// is seen exactly as packedBody hoists it for the compiler.
//
// Doctrine mirrors #2354 / #1960: strict (commit / commit-check) hard-
// rejects, naming the interface, unit, and the contributing statement(s);
// lenient (tolerant load / peer-sync) downgrades to a warning so an
// already-persisted or peer-synced config an older binary silently accepted
// still boots. Because rejection is a compile error, the candidate is never
// promoted — no partial outer/inner state survives a reject.
//
// It runs PRE-expansion (like validateZoneIDCollisionAST) because it must
// expand the candidate once per node ITSELF; wiring it among the
// pre-expansion gates in BOTH compile entrypoints makes the verdict
// identical no matter which node commits. The single-node post-expansion
// #2008 gate (validateUnsupportedInterfaceStanzasAST) no longer checks
// QinQ — this gate subsumes and strengthens that coverage.

// qinqUnitStack is the canonical VLAN tag stack derived for one logical
// unit: the rendered outer- and inner-tag statements contributing to it,
// gathered across every spelling. An empty inner slice means a supported
// single-tag (or untagged) unit; a non-empty inner slice is unsupported
// stacked-VLAN.
type qinqUnitStack struct {
	outer []string // vlan-id / vlan-tags outer statements
	inner []string // inner-vlan-id / vlan-tags inner statements
}

// qinqFinding records one (interface, unit) whose canonical stack carries
// an unsupported inner tag, with the statements that contributed it.
type qinqFinding struct {
	iface string
	unit  string
	stack qinqUnitStack
}

// message renders the operator-facing reject / warn text, naming the
// interface, unit, and the contributing inner (and any outer) statements so
// a stack split across two statements or spellings is fully attributable.
func (f qinqFinding) message() string {
	var b strings.Builder
	fmt.Fprintf(&b, "interfaces %s unit %s: unsupported QinQ / stacked-VLAN stack — inner (second) tag `%s`",
		f.iface, f.unit, strings.Join(f.stack.inner, "`, `"))
	if len(f.stack.outer) > 0 {
		fmt.Fprintf(&b, " over outer tag `%s`", strings.Join(f.stack.outer, "`, `"))
	}
	b.WriteString(" is not enforced by the AF_XDP dataplane (parse_l2 unwinds a single " +
		"VLAN tag; a double-tagged 802.1ad S-tag + 802.1Q C-tag frame falls to the kernel " +
		"forwarding path and is never firewalled). Single 802.1Q tagging via `vlan-id` is " +
		"supported — remove the inner tag (#2354, #5879)")
	return b.String()
}

// vlanTagsHasToken reports whether a `vlan-tags` node carries the given
// keyword (`outer`/`inner`) in EITHER AST shape: the flat / one-line shape
// packs the keyword into the node's own Keys (`vlan-tags outer 100 inner
// 200` -> Keys=[vlan-tags outer 100 inner 200]), while a hierarchical
// `vlan-tags { outer 100; inner 200; }` nests them as child nodes.
func vlanTagsHasToken(n *Node, token string) bool {
	for _, k := range n.Keys[1:] {
		if k == token {
			return true
		}
	}
	for _, c := range n.Children {
		if len(c.Keys) > 0 && c.Keys[0] == token {
			return true
		}
	}
	return false
}

// renderVLANStmt renders a VLAN-tag statement back to readable text for the
// reject / warn message, folding any nested children (the hierarchical
// vlan-tags shape) onto one line.
func renderVLANStmt(n *Node) string {
	s := strings.Join(n.Keys, " ")
	for _, c := range n.Children {
		s += " " + strings.Join(c.Keys, " ")
	}
	return s
}

// unitVLANStack derives the canonical outer/inner tag stack of a logical-
// unit node, unioning the `vlan-id`/`inner-vlan-id` spelling and the
// `vlan-tags outer/inner` spelling (combined or split across statements).
// A `vlan-tags` node counts as inner if it carries an `inner` keyword
// (regardless of whether the same node also carries `outer`, i.e. the
// combined `vlan-tags outer X inner Y` form is inner-bearing); otherwise an
// `outer`-only `vlan-tags` is a single S-tag and contributes to outer.
//
// #14683: the scan is recursive. The flat `unit 0 point-to-point
// inner-vlan-id 200` form nests the inner leaf under the point-to-point
// child, and packedBody (as used by compileInterfaces) hoists it onto the
// unit, so the compiler compiles a tag this gate would miss with a
// direct-children-only scan. Recursing mirrors the compiler's effective
// view; the compound children still exclude family/filter/etc. subtrees
// because a vlan leaf there is a different statement (e.g. vlan-map args).
func unitVLANStack(unit *Node) qinqUnitStack {
	var st qinqUnitStack
	var walk func(n *Node, inVLANMap bool)
	walk = func(n *Node, inVLANMap bool) {
		for _, c := range n.Children {
			if len(c.Keys) == 0 {
				continue
			}
			childInVLANMap := inVLANMap || c.Keys[0] == "input-vlan-map" || c.Keys[0] == "output-vlan-map"
			switch c.Keys[0] {
			case "vlan-id":
				if !inVLANMap {
					st.outer = append(st.outer, renderVLANStmt(c))
				}
			case "inner-vlan-id":
				if !inVLANMap {
					st.inner = append(st.inner, renderVLANStmt(c))
				}
			case "vlan-tags":
				switch {
				case vlanTagsHasToken(c, "inner"):
					st.inner = append(st.inner, renderVLANStmt(c))
				case vlanTagsHasToken(c, "outer"):
					st.outer = append(st.outer, renderVLANStmt(c))
				}
			}
			walk(c, childInVLANMap)
		}
	}
	walk(unit, false)
	return st
}

// collectQinQFromInterfacesNode records every (interface, unit) under one
// "interfaces" hierarchy node whose canonical VLAN stack carries an
// unsupported inner tag into out, keyed by interface+unit so a finding
// present in more than one node view is reported once.
func collectQinQFromInterfacesNode(ifacesNode *Node, out map[string]qinqFinding) {
	if ifacesNode == nil {
		return
	}
	for _, iface := range ifacesNode.Children {
		ifName := iface.Name()
		if ifName == "" {
			continue
		}
		// #14436: expand a packed instance tail so a unit packed onto
		// the interface Keys (`ge-0/0/0 bandwidth 1g unit 0 vlan-id 10
		// inner-vlan-id 20 ...`) is checked like its braced twin.
		ifaceBody := packedBody(iface, interfaceSchema9792())
		if ifaceBody == nil {
			ifaceBody = iface
		}
		// #14683: enumerate units via namedInstances, mirroring
		// compileInterfaces. The two-level hierarchical form
		// `unit { 0 { ... } }` carries Keys=[unit] with the numbered
		// instance as a child; namedInstances descends into it, while a
		// direct-children scan saw only the child `0` and an empty stack.
		// Merging duplicate-unit statements matches the gate's prior
		// keyed-union behaviour (and validateVLANMapAST).
		for _, unitInst := range namedInstances(ifaceBody.FindChildren("unit")) {
			unit := unitInst.node
			// The packed unit form itself may carry vlan leaves on its
			// own Keys tail; expand those into children for the stack.
			if unitBody := packedBody(unit, schemaForPath("interfaces", "xpfname", "unit")); unitBody != nil {
				unit = unitBody
			}
			st := unitVLANStack(unit)
			if len(st.inner) == 0 {
				continue // supported single-tag / untagged unit
			}
			key := ifName + "\x00" + unitInst.name
			finding, seen := out[key]
			if !seen {
				out[key] = qinqFinding{iface: ifName, unit: unitInst.name, stack: st}
				continue
			}
			finding.stack.outer = append(finding.stack.outer, st.outer...)
			finding.stack.inner = append(finding.stack.inner, st.inner...)
			out[key] = finding
		}
	}
}

// collectQinQFindingsForNode expands the candidate tree for chassis-cluster
// node nodeID and records every (interface, unit) whose canonical stack
// carries an unsupported inner tag into out. This IS the "aggregate
// effective view for every cluster node" the #5879 invariant requires: the
// concrete VLAN stack the compiler would render on node nodeID after
// `${node}`/apply-groups expansion and interface-range expansion.
//
// It is RECURSION-FREE by construction (mirrors emitNodeExpandedZoneNames /
// collectNodeExpandedInterfaceUnitSpellings): it clones the candidate,
// expands groups for the node, expands interface ranges (so a range/wildcard
// member's inner tag is seen exactly as runPreWalkGates would), and reads
// the tag leaves straight off the expanded AST — it NEVER calls
// CompileConfig* (which would re-enter this gate). A per-node expansion
// error contributes NOTHING (non-fatal): a config that legitimately defines
// only `groups node1` and references `${node}` fails to expand for node0
// (`undefined group "node0"`), and the real per-node compile path already
// rejects that on the affected node — this gate must not turn it into a
// spurious commit failure, and the OTHER node's view still catches an inner
// tag hidden in the un-expandable group. Every `interfaces` root is unioned
// (#5744): a split hierarchical config can declare units under a second
// `interfaces {}` stanza that compileSections still compiles.
func collectQinQFindingsForNode(tree *ConfigTree, nodeID int, out map[string]qinqFinding) {
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
		collectQinQFromInterfacesNode(ifaces, out)
	}
}

// validateQinQVLANStackAST is the #5879 canonical per-physical-interface
// QinQ honesty gate. It builds the effective VLAN stack for EVERY cluster
// node (node0 AND node1 `${node}`/apply-groups expansions) and rejects any
// unit whose aggregate stack carries an inner / second tag — regardless of
// whether the inner tag was spelled `inner-vlan-id` or `vlan-tags inner`,
// combined onto one statement or split across several, or contributed by a
// peer-only group only the STANDBY node renders.
//
// Only the two per-node EFFECTIVE views are unioned (node0 + node1
// expansion) — deliberately NOT the pre-expansion all-groups "View 1" the
// sibling union gates (validateInterfaceUnitAliasCollisionsAST #5878,
// validateZoneIDCollisionAST) also fold in. Those gates need View 1 because
// their trigger is a COLLISION between two names/spellings, and View 1 keeps
// a collision hidden in an un-expandable group symmetric across nodes. QinQ
// trips on a SINGLE inner tag, so a View-1 union would additionally reject a
// QinQ stanza staged in a group that NO apply-groups references — inert dead
// config that never renders on any node — which is outside "the aggregate
// effective view." Both node views are computed on both nodes regardless of
// which node commits, so the verdict is already HA-symmetric without View 1,
// and a peer-only APPLIED group's inner tag is caught by the other node's
// view.
//
// Strict (lenient=false): the first offending unit (interface+unit sorted)
// is a hard compile error, so the candidate is never promoted (no partial
// outer/inner state survives). Lenient (lenient=true): every offending unit
// is returned as a warning and compilation continues (the #1960 no-brick
// tolerant-load / peer-sync contract).
func validateQinQVLANStackAST(tree *ConfigTree, lenient bool) ([]string, error) {
	findings := make(map[string]qinqFinding)
	// The aggregate effective view for every cluster node. Both are pure
	// functions of the same candidate, so the verdict is identical no matter
	// which node commits (HA symmetry).
	collectQinQFindingsForNode(tree, 0, findings)
	collectQinQFindingsForNode(tree, 1, findings)
	if len(findings) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(findings))
	for k := range findings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var warnings []string
	for _, k := range keys {
		msg := findings[k].message()
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
	}
	return warnings, nil
}
