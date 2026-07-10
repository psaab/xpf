package config

import (
	"fmt"
	"sort"
	"strings"
)

// compiler_nat_mixed_scope.go carries the #4881 reject-at-commit gate for a NAT
// rule-set `from` / source-`to` / static-`from` clause that mixes scope KINDS.
//
// A Junos NAT rule-set `from` (and source-NAT `to`) clause scopes matched
// traffic by EXACTLY ONE kind: `zone`, `interface`, or `routing-instance`.
// Multiple VALUES of the chosen kind are a legitimate list (`from zone [ trust
// untrust ]` = match either zone — OR is correct there). But MIXING kinds in
// one clause is invalid Junos.
//
// xpf's setSchema declares zone / interface / routing-instance as independent
// `multi:true` children with no mutual-exclusion validator, and the #3096
// compiler Cartesian-expands the collected from-scopes × to-scopes into one
// typed NATRuleSet per (fromScope, toScope) pair (collectNATScopes /
// applyNATFromScope in compiler_nat.go). So `from zone trust` + `from interface
// ge-0/0/1.0` compiles into TWO rule-sets — FromZone=trust and
// FromInterface=ge-0/0/1.0 — with identical rules, matching traffic on EITHER
// scope. That is OR, i.e. WIDER than the operator's intent, and it directly
// contradicts the in-tree parseNATMatchScopes comment that claims a mixed-kind
// clause is "AND-ed fail-closed at match time" (it is not; the AND never
// happens). Reject the mixed-kind clause at commit so the ambiguous config
// fails CLOSED (operator error visible) instead of OPEN (silently widened).
//
// This is an AST pre-walk (not a SchemaValidate typed leaf) because
// SchemaValidate returns nil for structural shapes it does not own and cannot
// REJECT a stanza; the individual zone/interface/routing-instance leaves are
// each independently legal, so only a cross-leaf check catches the mix. The
// walk runs on the group-expanded, inactive-pruned tree (compileConfig*Opts
// strips inactive subtrees and expands groups before compileExpanded), so an
// apply-groups-inherited mixed clause is caught and an `inactive:` rule-set is
// ignored for free. Detection mirrors the compiler's own scope collection: it
// reuses parseNATMatchScopes on each `from` / `to` clause node and aggregates
// the DISTINCT kinds exactly as collectNATScopes feeds the Cartesian product,
// so what the gate rejects is precisely what the compiler would OR-expand.
//
// Strict path (commit / commit-check, lenient=false): the first offending
// clause is a hard compile error naming the NAT kind, rule-set, clause, and the
// mixed kinds. Lenient path (load / peer-sync, lenient=true): every offending
// clause is a warning and compilation continues — the config an older binary
// accepted still boots (#1960), now flagged. Mirrors
// validateDNATRuleSetToScopeAST (#3444). Destination NAT is checked on `from`
// only: its `to` clause is separately hard-rejected by
// validateDNATRuleSetToScopeAST, so a mixed-kind DNAT `to` never reaches here.

// natClauseScopeKinds returns the SET of distinct scope kinds (zone /
// interface / routing-instance), sorted for a deterministic message, present
// across every `clause` (`from` or `to`) child of a rule-set node. It
// aggregates across sibling clause nodes exactly as collectNATScopes does, so
// the kind count matches the compiler's Cartesian-expansion input. An empty
// clause contributes no kinds (the match-any default is injected later by
// collectNATScopes, never here).
func natClauseScopeKinds(rsNode *Node, clause string) []string {
	seen := make(map[string]bool)
	for _, child := range rsNode.Children {
		if child.Name() != clause {
			continue
		}
		for _, sc := range parseNATMatchScopes(child) {
			if sc.kind != "" {
				seen[sc.kind] = true
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	kinds := make([]string, 0, len(seen))
	for k := range seen {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}

// validateNATRuleSetMixedScopeAST walks the `security nat {source|destination|
// static}` rule-sets of the group-expanded AST and rejects any `from`
// clause (all three NAT kinds) or source-NAT `to` clause that carries more than
// one distinct scope kind.
func validateNATRuleSetMixedScopeAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(natKind, rsName, clause string, kinds []string) error {
		msg := fmt.Sprintf(
			"security nat %s rule-set %q: the `%s` clause mixes %d scope kinds "+
				"(%s) — a Junos NAT from/to clause scopes by exactly ONE kind "+
				"(zone | interface | routing-instance); mixing kinds OR-expands "+
				"into multiple rule-sets and WIDENS the match beyond the intended "+
				"ingress/egress boundary — use a single kind per clause (#4881)",
			natKind, rsName, clause, len(kinds), strings.Join(kinds, ", "))
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	checkClause := func(natKind, rsName string, rsNode *Node, clause string) error {
		kinds := natClauseScopeKinds(rsNode, clause)
		if len(kinds) <= 1 {
			return nil
		}
		return emit(natKind, rsName, clause, kinds)
	}

	// Iterate ALL matching children at EVERY level (forEachChild), not the
	// first match: parseStatements APPENDS a repeated block as a sibling and
	// the compiler compiles every one, so a first-match-only walk is bypassable
	// (the #3562 multi-level duplicate-block class), mirroring
	// validateDNATRuleSetToScopeAST.
	err := forEachChild(nodes, "security", func(sec *Node) error {
		return forEachChild(sec.Children, "nat", func(nat *Node) error {
			// Source NAT: `from` AND `to`.
			if err := forEachChild(nat.Children, "source", func(src *Node) error {
				for _, rs := range namedInstances(src.FindChildren("rule-set")) {
					if err := checkClause("source", rs.name, rs.node, "from"); err != nil {
						return err
					}
					if err := checkClause("source", rs.name, rs.node, "to"); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return err
			}
			// Destination NAT: `from` only (the `to` clause is rejected
			// wholesale by validateDNATRuleSetToScopeAST).
			if err := forEachChild(nat.Children, "destination", func(dst *Node) error {
				for _, rs := range namedInstances(dst.FindChildren("rule-set")) {
					if err := checkClause("destination", rs.name, rs.node, "from"); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return err
			}
			// Static NAT: `from` only.
			return forEachChild(nat.Children, "static", func(st *Node) error {
				for _, rs := range namedInstances(st.FindChildren("rule-set")) {
					if err := checkClause("static", rs.name, rs.node, "from"); err != nil {
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
