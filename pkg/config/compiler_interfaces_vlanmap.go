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
		// #14436: enumerate units via interfaceUnitsOf (#17222) so a
		// packed instance tail is checked like the braced spelling.
		for _, unitInst := range interfaceUnitsOf(iface) {
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

// collectVLANMapFindings records every (interface, unit) that carries
// an unsupported vlan-map stanza into out, across the effective views
// from effectiveNodeViews (#17222) with the generic fallback enabled:
// when neither per-node expansion succeeds — a group literally named
// "${node}" — the gate inspects the same tree the generic compile
// compiles instead of silently returning no findings (#13146).
func collectVLANMapFindings(tree *ConfigTree, out map[string]vlanMapFinding) {
	for _, view := range effectiveNodeViews(tree, gateNodeViewOpts{ExpandRanges: true, Fallback: true}) {
		for _, ifaces := range view.FindChildren("interfaces") {
			collectVLANMapFromInterfacesNode(ifaces, out)
		}
	}
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
	collectVLANMapFindings(tree, findings)
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
