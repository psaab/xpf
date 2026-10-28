package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_interfaces_qinq.go carries the #5879 canonical per-physical-
// interface QinQ (stacked-VLAN) honesty gate (#14683: two-level unit form;
// #16433: `vlan-tags` closed world).
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
// #16433: the `vlan-tags` statement's world is closed. Junos spells the
// second tag not only `inner <vid>` but also `inner-list <vids>` and
// `inner-range <lo>-<hi>` (and `inner-vlan-id-range`), none of which the
// exact-token `inner` predicate saw, and arbitrary trailing tokens
// (`outer 100 bogus 7`) were ignored by both this gate and the #15035
// reader, so the statement compiled as a plain single-tag VID. Now a
// `vlan-tags` node contributes to inner on any `inner`/`inner-*` token,
// to outer only on the exact `outer <vid>` form (see vlanTagsIsOuterOnly),
// and to invalid otherwise; validateQinQVLANStackAST rejects inner with
// the #5879 text and invalid with a #16433 text, and the #15035 reader
// refuses any node that is not outer-only. Lenient keeps the #1960
// warn-and-compile contract (a node carrying a closed-world defect is
// skipped by the reader, so its outer value never silently applies).
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
// stacked-VLAN. invalid holds a `vlan-tags` statement that is neither the
// supported `outer <vid>` form nor an inner spelling (#16433).
type qinqUnitStack struct {
	outer   []string // vlan-id / vlan-tags outer statements
	inner   []string // inner-vlan-id / vlan-tags inner statements
	invalid []string // #16433: malformed `vlan-tags` statements
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
	// #16433 precedence: an inner spelling is the QinQ defect even when
	// the same statement also carries a malformed token.
	if len(f.stack.inner) > 0 {
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
	return fmt.Sprintf("interfaces %s unit %s: unsupported `vlan-tags` statement `%s` — "+
		"only `vlan-tags outer <vid>` (a single 802.1Q tag) is supported; remove the extra token(s) "+
		"or configure `vlan-id <vid>` instead (#16433)",
		f.iface, f.unit, strings.Join(f.stack.invalid, "`, `"))
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

// vlanTagsIsInner reports whether a `vlan-tags` node spells an inner
// (second) tag in either AST shape: the `inner` keyword or any Junos
// `inner-*` spelling (#16433: `inner-list`, `inner-range`,
// `inner-vlan-id-range`). Packed Keys and hierarchical child heads are
// both consulted, so a TPID-qualified hierarchical `inner 0x8100.200`
// child (Keys=[inner 0x8100.200]) still matches.
func vlanTagsIsInner(n *Node) bool {
	if vlanTagsHasToken(n, "inner") {
		return true
	}
	for _, k := range n.Keys[1:] {
		if strings.HasPrefix(k, "inner-") {
			return true
		}
	}
	for _, c := range n.Children {
		if len(c.Keys) > 0 && strings.HasPrefix(c.Keys[0], "inner-") {
			return true
		}
	}
	return false
}

// vlanTagsIsOuterOnly reports whether a `vlan-tags` node is exactly the
// supported single-tag form (#16433 closed world): `outer <one value>`
// and nothing else, in any AST shape — packed Keys
// (`vlan-tags outer 100`), hierarchical children
// (`vlan-tags { outer 100; }`), or the one-deeper form
// (`vlan-tags { outer { 100; } }`). Numeric validity of the value is
// NOT judged here; the #15035 reader owns that (TPID prefix uses its
// own message). Bare `vlan-tags`, multiple children, extra tokens or
// children, and any non-`outer` child are not outer-only.
func vlanTagsIsOuterOnly(n *Node) bool {
	if len(n.Keys) >= 2 {
		// Packed flat / one-line shape. Inner spellings are handled by
		// the caller before this predicate; any remaining non-`outer`
		// form (no outer, or trailing tokens) is malformed.
		return len(n.Keys) == 3 && n.Keys[1] == "outer" && len(n.Children) == 0
	}
	if len(n.Children) != 1 {
		return false
	}
	c := n.Children[0]
	if len(c.Keys) == 0 || c.Keys[0] != "outer" {
		return false
	}
	if len(c.Keys) > 1 {
		return len(c.Keys) == 2 && len(c.Children) == 0
	}
	// `outer { 100; }`: exactly one grandchild carrying exactly one token.
	if len(c.Children) != 1 {
		return false
	}
	g := c.Children[0]
	return len(g.Keys) == 1 && len(g.Children) == 0
}

// renderVLANStmt renders a VLAN-tag statement back to readable text for the
// reject / warn message, folding any nested children (the hierarchical
// vlan-tags shape) onto one line.
func renderVLANStmt(n *Node) string {
	s := strings.Join(n.Keys, " ")
	for _, c := range n.Children {
		s += " " + renderVLANStmt(c)
	}
	return s
}

// unitVLANStack derives the canonical outer/inner tag stack of a logical-
// unit node, unioning the `vlan-id`/`inner-vlan-id` spelling and the
// `vlan-tags outer/inner` spelling (combined or split across statements).
// A `vlan-tags` node counts as inner if it carries an `inner`/`inner-*`
// keyword (regardless of whether the same node also carries `outer`, i.e.
// the combined `vlan-tags outer X inner Y` form is inner-bearing); an
// exact `outer <vid>` `vlan-tags` is a single S-tag and contributes to
// outer; any other `vlan-tags` shape contributes to invalid (#16433).
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
				case vlanTagsIsInner(c):
					st.inner = append(st.inner, renderVLANStmt(c))
				case vlanTagsIsOuterOnly(c):
					st.outer = append(st.outer, renderVLANStmt(c))
				default:
					// #16433: neither the supported outer-only form
					// nor an inner spelling — a token xpf does not
					// implement (or no token at all). Record it so
					// the gate rejects instead of silently
					// compiling the statement as a single tag.
					st.invalid = append(st.invalid, renderVLANStmt(c))
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
// unsupported inner tag — or a malformed `vlan-tags` statement (#16433) —
// into out, keyed by interface+unit so a finding present in more than one
// node view is reported once.
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
		// #14436/#14683: enumerate units via interfaceUnitsOf (#17222),
		// mirroring compileInterfaces: a packed instance tail on the
		// interface line and the two-level hierarchical form
		// `unit { 0 { ... } }` are both enumerated. Merging
		// duplicate-unit statements matches the gate's prior
		// keyed-union behaviour (and validateVLANMapAST).
		for _, unitInst := range interfaceUnitsOf(iface) {
			unit := unitInst.node
			// The packed unit form itself may carry vlan leaves on its
			// own Keys tail; expand those into children for the stack.
			if unitBody := packedBody(unit, refInterfaceUnit.resolve()); unitBody != nil {
				unit = unitBody
			}
			st := unitVLANStack(unit)
			if len(st.inner) == 0 && len(st.invalid) == 0 {
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
			finding.stack.invalid = append(finding.stack.invalid, st.invalid...)
			out[key] = finding
		}
	}
}

// collectQinQFindings records every (interface, unit) whose canonical
// stack carries an unsupported inner tag into out, across the aggregate
// effective view for every cluster node the #5879 invariant requires:
// the concrete VLAN stack the compiler would render after
// `${node}`/apply-groups expansion and interface-range expansion.
//
// The views come from effectiveNodeViews (#17222) with the generic
// fallback enabled: when neither per-node expansion succeeds — a group
// literally named "${node}" — the gate inspects the same tree the
// generic compile compiles (the #13146 raw-tree fallback vlan-map
// already had), instead of contributing nothing while the compiler
// compiles that tree. It is RECURSION-FREE by construction (the helper
// clones and expands; it never calls CompileConfig*, which would
// re-enter this gate). Every `interfaces` root is unioned (#5744): a
// split hierarchical config can declare units under a second
// `interfaces {}` stanza that compileSections still compiles.
func collectQinQFindings(tree *ConfigTree, out map[string]qinqFinding) {
	for _, view := range effectiveNodeViews(tree, gateNodeViewOpts{ExpandRanges: true, Fallback: true}) {
		for _, ifaces := range view.FindChildren("interfaces") {
			collectQinQFromInterfacesNode(ifaces, out)
		}
	}
}

// validateQinQVLANStackAST is the #5879 canonical per-physical-interface
// QinQ honesty gate, extended by #16433 to the closed `vlan-tags` world.
// It builds the effective VLAN stack for EVERY cluster
// node (node0 AND node1 `${node}`/apply-groups expansions) and rejects any
// unit whose aggregate stack carries an inner / second tag — regardless of
// whether the inner tag was spelled `inner-vlan-id` or `vlan-tags inner`,
// combined onto one statement or split across several, or contributed by a
// peer-only group only the STANDBY node renders — and (#16433) any unit
// whose `vlan-tags` statement is not exactly `outer <vid>`.
//
// Only the per-node EFFECTIVE views are unioned (node0 + node1
// expansion, plus the generic fallback view when neither expands) —
// deliberately NOT the pre-expansion all-groups "View 1" the
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
// view. The generic fallback view is not View 1 either: it is the tree the
// standalone compile actually compiles when neither node view expands
// (#13146/#17222), so a top-level offending stanza there is live config.
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
	collectQinQFindings(tree, findings)
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
