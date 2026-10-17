package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_interfaces_vlanmap.go carries the #6178 input-vlan-map /
// output-vlan-map (per-unit VLAN rewrite) unsupported-feature honesty gate.
//
// Background: Junos `input-vlan-map` / `output-vlan-map` under a logical
// unit request a VLAN-tag rewrite on ingress / egress — push a tag, pop a
// tag, or swap the tag id (`push`, `pop`, `swap`, `push-push`, `swap-swap`,
// and the tag arguments `vlan-id` / `tag-protocol-id` / `inner-vlan-id`).
// Neither spelling is in the unit `setSchema` and neither has a compiler
// consumer, so the stanza parse-accepts and is SILENTLY DROPPED: the
// AF_XDP dataplane performs no rewrite and forwards the frame with its tags
// unchanged.
//
// This is NOT a firewall bypass (#5879's QinQ receive-side case IS): a
// single-tagged frame still arrives single-tagged and IS firewalled — only
// the configured push/pop/swap never happens. But a strict commit ACCEPTS a
// rewrite the dataplane cannot perform, so the operator believes tags are
// being pushed / swapped when they are not — a config-honesty gap. This gate
// tells the operator at commit time rather than letting the rewrite silently
// vanish.
//
// Doctrine mirrors #5879 (validateQinQVLANStackAST) / #2354 / #1960 exactly:
// it runs PRE-expansion and evaluates the effective view for EVERY cluster
// node (node0 AND node1 `${node}`/apply-groups expansions) so a vlan-map
// staged under a peer-only `groups node1` is still surfaced on whichever
// node commits and the verdict is HA-symmetric. Strict (commit / commit-
// check) hard-rejects, naming the interface, unit, and contributing
// statement(s); lenient (tolerant load / peer-sync) downgrades to a warning
// so an already-persisted or peer-synced config an older binary silently
// accepted still boots (#1960 no-brick). Because a strict reject is a
// compile error, the candidate is never promoted.

// vlanMapFinding records one (interface, unit) that carries an unsupported
// input-vlan-map / output-vlan-map VLAN-rewrite stanza, with the rendered
// statements that contributed it.
type vlanMapFinding struct {
	iface string
	unit  string
	stmts []string // rendered input-vlan-map / output-vlan-map statements
}

// message renders the operator-facing reject / warn text, naming the
// interface, unit, and the contributing vlan-map statement(s).
func (f vlanMapFinding) message() string {
	return fmt.Sprintf("interfaces %s unit %s: unsupported VLAN rewrite — `%s` "+
		"is not enforced by the AF_XDP dataplane (input-vlan-map/output-vlan-map has no "+
		"compiler consumer; the configured VLAN tag push/pop/swap is silently dropped and "+
		"the frame is forwarded with its tags unchanged). Remove the vlan-map, or use a "+
		"single 802.1Q `vlan-id` on the unit (#6178)",
		f.iface, f.unit, strings.Join(f.stmts, "`, `"))
}

// unitVLANMapStmts returns the rendered input-vlan-map / output-vlan-map
// statements under a logical-unit node, across both AST shapes. The
// flat-set shape packs the direction + action onto the node's own Keys
// (`input-vlan-map push` -> Keys=[input-vlan-map push]); the hierarchical
// shape nests the action as child nodes (`input-vlan-map { push; }`).
// renderVLANStmt (compiler_interfaces_qinq.go) folds either onto one line.
// ANY such statement is an unsupported rewrite: xpf has no vlan-map
// consumer, so the operator's push/pop/swap never happens.
func unitVLANMapStmts(unit *Node) []string {
	var stmts []string
	for _, c := range unit.Children {
		if len(c.Keys) == 0 {
			continue
		}
		switch c.Keys[0] {
		case "input-vlan-map", "output-vlan-map":
			stmts = append(stmts, renderVLANStmt(c))
		}
	}
	return stmts
}

// collectVLANMapFromInterfacesNode records every (interface, unit) under one
// "interfaces" hierarchy node that carries an unsupported vlan-map stanza
// into out, keyed by interface+unit so a finding present in more than one
// node view is reported once.
func collectVLANMapFromInterfacesNode(ifacesNode *Node, out map[string]vlanMapFinding) {
	if ifacesNode == nil {
		return
	}
	for _, iface := range ifacesNode.Children {
		ifName := iface.Name()
		if ifName == "" {
			continue
		}
		// #14436: expand a packed instance tail so its unit is checked
		// like the braced spelling.
		ifaceBody := packedBody(iface, interfaceSchema9792())
		if ifaceBody == nil {
			ifaceBody = iface
		}
		for _, unitInst := range namedInstances(ifaceBody.FindChildren("unit")) {
			stmts := unitVLANMapStmts(unitInst.node)
			if len(stmts) == 0 {
				continue
			}
			key := ifName + "\x00" + unitInst.name
			finding, seen := out[key]
			if !seen {
				out[key] = vlanMapFinding{iface: ifName, unit: unitInst.name, stmts: stmts}
				continue
			}
			finding.stmts = append(finding.stmts, stmts...)
			out[key] = finding
		}
	}
}

// collectVLANMapFindingsForNode expands the candidate tree for chassis-
// cluster node nodeID and records every (interface, unit) that carries an
// unsupported vlan-map stanza into out. It returns whether group expansion
// succeeded, so callers can mirror CompileConfig's raw-tree fallback when
// neither node context can expand (for example a literal "${node}" group).
func collectVLANMapFindingsForNode(tree *ConfigTree, nodeID int, out map[string]vlanMapFinding) bool {
	clone := tree.Clone()
	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := clone.ExpandGroupsWithVars(vars); err != nil {
		return false
	}
	// expandInterfaceRanges mutates the clone in place; its warnings are
	// emitted on the real path (runPreWalkGates) and discarded here.
	// #8438: the clone paths only need the budget SKIP (the expansion is capped
	// inside); the rejection is surfaced once, by the prewalk caller.
	_, _ = expandInterfaceRanges(clone)
	for _, ifaces := range clone.FindChildren("interfaces") {
		collectVLANMapFromInterfacesNode(ifaces, out)
	}
	return true
}

// validateVLANMapAST is the #6178 input-vlan-map / output-vlan-map honesty
// gate. It builds the effective view for BOTH cluster nodes (node0 AND node1
// `${node}`/apply-groups expansions) and rejects any unit that carries an
// unsupported VLAN-rewrite stanza — regardless of whether the vlan-map lives
// in the committing node's own view or a peer-only group only the standby
// renders. Mirrors validateQinQVLANStackAST (#5879): both node views are
// computed on both nodes regardless of which commits, so the verdict is
// HA-symmetric.
//
// Strict (lenient=false): the first offending unit (interface+unit sorted)
// is a hard compile error, so the candidate is never promoted. Lenient
// (lenient=true): every offending unit is returned as a warning and
// compilation continues (the #1960 no-brick tolerant-load / peer-sync
// contract).
func validateVLANMapAST(tree *ConfigTree, lenient bool) ([]string, error) {
	findings := make(map[string]vlanMapFinding)
	expandedAny := collectVLANMapFindingsForNode(tree, 0, findings)
	expandedAny = collectVLANMapFindingsForNode(tree, 1, findings) || expandedAny
	if !expandedAny {
		// CompileConfig falls back to compiling the raw tree when neither
		// `${node}` expansion is available; inspect that same effective input
		// rather than silently bypassing the unsupported-feature gate.
		for _, ifaces := range tree.FindChildren("interfaces") {
			collectVLANMapFromInterfacesNode(ifaces, findings)
		}
	}
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
