package config

import "fmt"

// validateNATRuleSetEmptyScopesAST rejects a present NAT from/to clause that
// has no non-empty scope values. Empty values are discarded by
// parseNATMatchScopes; treating the resulting empty set like an absent clause
// would widen the rule-set to match-any (#7525).
func validateNATRuleSetEmptyScopesAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(natKind, rsName, clause string) error {
		base := fmt.Sprintf(
			"security nat %s rule-set %q: the `%s` clause contains no non-empty scope",
			natKind, rsName, clause)
		if !lenient {
			return fmt.Errorf(
				"%s. The empty value is discarded and the resulting scope would become "+
					"match-any, so this rule-set would silently WIDEN (fail-open, #7525); "+
					"name the scope or remove the clause",
				base)
		}
		warnings = append(warnings, fmt.Sprintf(
			"%s; the rule-set is OMITTED from this tolerant load (its NAT rules do not "+
				"apply) because an empty scope must not widen to match-any (#7525)",
			base))
		return nil
	}
	checkClause := func(natKind, rsName string, rsNode *Node, clause string) error {
		present := false
		var scopes []natMatchScope
		for _, child := range rsNode.Children {
			if child.Name() != clause {
				continue
			}
			present = true
			scopes = append(scopes, parseNATMatchScopes(child)...)
		}
		if !present || len(scopes) != 0 {
			return nil
		}
		return emit(natKind, rsName, clause)
	}

	return warnings, forEachChild(nodes, "security", func(sec *Node) error {
		return forEachChild(sec.Children, "nat", func(nat *Node) error {
			if err := forEachChild(nat.Children, "source", func(src *Node) error {
				for _, rs := range namedInstances(src.FindChildren("rule-set")) {
					for _, clause := range []string{"from", "to"} {
						if err := checkClause("source", rs.name, rs.node, clause); err != nil {
							return err
						}
					}
				}
				return nil
			}); err != nil {
				return err
			}
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
}
