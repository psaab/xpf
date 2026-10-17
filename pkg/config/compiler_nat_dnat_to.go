package config

import "fmt"

// compiler_nat_dnat_to.go carries the #3444 reject-at-commit gate for a
// destination-NAT rule-set `to` scope.
//
// A Junos destination-NAT rule-set has only a `from` clause (zone |
// interface | routing-instance). DNAT translates the destination address on
// the inbound packet, so there is no egress / `to` context yet — only source
// NAT (which has both `from` and `to`) and the routed forward path can scope
// by an egress context. xpf's setSchema briefly advertised a `to` scope under
// `security nat destination rule-set`, and compileNATDestination
// Cartesian-expanded the collected `to` scopes onto each NATRuleSet
// (ToZone/ToInterface/ToRoutingInstance). But the userspace snapshot builder
// (pkg/dataplane/userspace/nat.go buildDestinationNATSnapshots) and the Rust
// DNAT runtime (userspace-dp/src/nat/destination.rs) model ONLY the `from`
// clause for DNAT — the DestinationNATRuleSnapshot wire struct intentionally
// has no `to_*`. So a configured `to zone|interface|routing-instance` was
// silently dropped: the translation applied regardless of the operator's
// declared destination context, and the operator got no error. Admitting a
// `to` scope that the running firewall does not enforce is a silent
// functional lie, so this gate hard-rejects it at commit / commit-check and
// warns (does not fail) on the tolerant load / peer-sync paths per the #1960
// fail-closed-on-load doctrine.
//
// This is an AST pre-walk (not a SchemaValidate typed leaf) because
// SchemaValidate is opt-in per known leaf and returns nil for unknown
// keywords by design (schema_walk.go) — it cannot REJECT a stanza, and the
// `to` keyword itself is legitimate elsewhere (source NAT rule-sets). The
// `to` subtree has also been removed from the DNAT rule-set setSchema so the
// CLI no longer offers it in completion; this gate covers the runtime
// reject + the already-persisted lenient-load path. Detection is scoped to
// `security nat destination rule-set` so the source-NAT `to` clause (a real
// feature) is never touched. The walk runs on the group-expanded,
// inactive-pruned tree (compileConfigWithOpts / compileConfigForNodeWithOpts
// strip inactive subtrees and expand groups before compileExpanded), so an
// apply-groups-inherited `to` is caught and an `inactive:` rule-set is
// ignored for free.

// natRuleSetHasToScope reports whether a destination-NAT rule-set node
// carries a `to` scope in EITHER spelling: a nested `to` child (flat-set and
// ordinary hierarchical form) or a `to` packed onto the rule-set header
// itself (`rule-set RD to zone trust { ... }`, R15-01), where the token
// rides on the rule-set node's own Keys tail and FindChild("to") never sees
// it. It is the single detection shared by the #3444 gate
// (validateDNATRuleSetToScopeAST) and the destination-NAT builder
// (compileNATDestination, #14391) so gate and builder cannot drift: a
// spelling the gate warns/rejects on is exactly the spelling the builder
// omits on the lenient path.
func natRuleSetHasToScope(rsNode *Node, name string) bool {
	if rsNode == nil {
		return false
	}
	for _, child := range natRuleSetChildren(rsNode, "destination") {
		if child.Name() == "to" {
			return true
		}
	}
	return false
}

// validateDNATRuleSetToScopeAST walks the `security nat destination
// rule-set` subtree of the group-expanded AST and rejects any rule-set
// carrying a `to` scope.
//
// Strict path (commit / commit-check, lenient=false): the first offending
// rule-set is a hard compile error, naming the exact rule-set.
//
// Lenient path (load / peer-sync, lenient=true): every offending rule-set is
// returned as a warning and compilation continues, but the rule-set is NOT
// installed scope-less — compileNATDestination omits it via the same
// natRuleSetHasToScope detection (#14391), so no translation applies
// regardless of the authored egress context. The warning is the operator
// signal; the omission is the fail-closed posture.
func validateDNATRuleSetToScopeAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	// Iterate ALL matching children at EVERY level the walk descends, not
	// the first match at any level. parseStatements APPENDS a repeated block
	// instead of merging it (parser.go), and the compiler iterates siblings
	// at each level it descends — compileExpanded processes every `security`
	// root, compileSecurity compiles every `nat` sibling. So a first-match-
	// only walk is bypassable at EVERY level (the multi-level duplicate-block
	// class, #3562): e.g. ONE `security` root with a benign first `nat {}` +
	// a second `nat { destination { rule-set RD { to zone trust; ... } } }`
	// would slip past a first-`nat` walk while the compiler still compiles
	// the second `nat`'s rule-set with the `to` silently dropped (the
	// original #3444 bug, reachable via a hierarchical LoadOverride input).
	// Using forEachChild at security/nat/destination guarantees a DNAT `to`
	// in ANY duplicate block at ANY level is caught. The inner rule-set
	// iteration + narrow direct-`to` check is unchanged — the scope
	// precision stays destination-only so the source-NAT `to` (#3096) is
	// untouched. (compileNAT itself reads only the first `destination` per
	// `nat`, so a duplicate `destination` WITHIN one `nat` is not currently
	// compiler-reachable for the silent drop; the walk rejects it anyway —
	// fail-closed and defensive against future compiler changes.)
	err := forEachChild(nodes, "security", func(sec *Node) error {
		return forEachChild(sec.Children, "nat", func(nat *Node) error {
			return forEachChild(nat.Children, "destination", func(dst *Node) error {
				for _, rs := range namedInstances(dst.FindChildren("rule-set")) {
					if !natRuleSetHasToScope(rs.node, rs.name) {
						continue
					}
					if err := emit(
						"security nat destination rule-set %q: a `to` scope is not "+
							"supported on a destination-NAT rule-set (Junos DNAT has only "+
							"a `from` clause — the destination is translated on inbound, so "+
							"there is no egress context; the `to` scope was silently ignored "+
							"and the translation applied regardless of it) — remove it (#3444)",
						rs.name); err != nil {
						return err
					}
				}
				return nil
			})
		})
	})
	if err != nil {
		return nil, err
	}
	return warnings, nil
}

// forEachChild invokes fn for every node in children whose Name() equals
// name, stopping and propagating the first error fn returns. It is the
// reference iterate-ALL-siblings primitive for the multi-level duplicate-
// block bypass class (#3562): the Junos parser APPENDS a repeated block as a
// sibling instead of merging it (parseStatements, parser.go) and the compiler
// iterates siblings at each level it descends, so a strict-reject AST walk
// that uses FindChild (first match) at ANY level it descends can be bypassed
// by placing the offending stanza in a duplicate block. Descending with
// forEachChild at every level closes that bypass. `children` is a `[]*Node`
// so the same primitive covers the top-level roots slice and every
// node.Children slice uniformly.
func forEachChild(children []*Node, name string, fn func(*Node) error) error {
	for _, c := range children {
		if c.Name() != name {
			continue
		}
		if err := fn(c); err != nil {
			return err
		}
	}
	return nil
}
