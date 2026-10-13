package config

import "fmt"

// defaultPolicyAction11821 reads the value exactly as compilePolicies does for
// the flat and hierarchical spellings. Ambiguous multi-value blocks remain the
// separate #11367 gate's responsibility.
func defaultPolicyAction11821(node *Node) string {
	if node == nil {
		return ""
	}
	if len(node.Keys) >= 2 {
		return node.Keys[1]
	}
	if len(node.Children) == 1 {
		return node.Children[0].Name()
	}
	return ""
}

// defaultPolicyActions12821 collects supported action tokens from every
// spelling inside one default-policy node. Junos parser nodes may put values
// in trailing Keys or in nested Children; looking at only the first loses
// contradictory values and can turn an authored deny/reject into permit.
func defaultPolicyActions12821(node *Node) []string {
	var actions []string
	var collect func(*Node)
	collect = func(n *Node) {
		if n == nil {
			return
		}
		add := func(action string) {
			switch action {
			case "permit-all", "deny-all", "reject-all":
				actions = append(actions, action)
			}
		}
		if len(n.Keys) > 0 {
			if n.Name() != "default-policy" {
				add(n.Name())
			}
			for _, key := range n.Keys[1:] {
				add(key)
			}
		}
		for _, child := range n.Children {
			collect(child)
		}
	}
	collect(node)
	return actions
}

// walkConflictingDefaultPolicyValues12821 reports distinct action values
// carried by one stanza. Equal repeated values remain legal; the separate
// #11367 gate continues to own multi-child choice cardinality.
func walkConflictingDefaultPolicyValues12821(nodes []*Node, visit func(first, current string) bool) {
	for _, security := range nodes {
		if security == nil || security.Name() != "security" {
			continue
		}
		for _, policies := range security.Children {
			if policies == nil || policies.Name() != "policies" {
				continue
			}
			for _, stanza := range policies.Children {
				if stanza == nil || stanza.Name() != "default-policy" {
					continue
				}
				actions := defaultPolicyActions12821(stanza)
				first := ""
				for _, action := range actions {
					if first == "" {
						first = action
						continue
					}
					if action != first && !visit(first, action) {
						return
					}
				}
			}
		}
	}
}

func validateDefaultPolicyValues12821(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	var strictErr error
	walkConflictingDefaultPolicyValues12821(nodes, func(first, current string) bool {
		diagnostic := fmt.Sprintf(
			"security policies default-policy: conflicting values within one stanza specify %q and %q (#12821)",
			first, current,
		)
		if !lenient {
			strictErr = fmt.Errorf("%s", diagnostic)
			return false
		}
		warnings = append(warnings, diagnostic+"; tolerant compilation uses deny-all")
		return true
	})
	return warnings, strictErr
}

func hasConflictingDefaultPolicyValues12821(nodes []*Node) bool {
	found := false
	walkConflictingDefaultPolicyValues12821(nodes, func(string, string) bool {
		found = true
		return false
	})
	return found
}

// walkConflictingDefaultPolicyStanzas11821 visits conflicting explicit values
// in author order across every security root and policies block. The callback
// returns false to stop after the first conflict.
func walkConflictingDefaultPolicyStanzas11821(nodes []*Node, visit func(first, current string) bool) {
	var first string
	for _, security := range nodes {
		if security == nil || security.Name() != "security" {
			continue
		}
		for _, policies := range security.Children {
			if policies == nil || policies.Name() != "policies" {
				continue
			}
			for _, stanza := range policies.Children {
				if stanza == nil || stanza.Name() != "default-policy" || len(stanza.Children) > 1 {
					continue
				}
				action := defaultPolicyAction11821(stanza)
				switch action {
				case "permit-all", "deny-all", "reject-all":
				default:
					continue
				}
				if first == "" {
					first = action
					continue
				}
				if action != first && !visit(first, action) {
					return
				}
			}
		}
	}
}

func validateDefaultPolicyConflicts11821(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	var strictErr error
	walkConflictingDefaultPolicyStanzas11821(nodes, func(first, current string) bool {
		diagnostic := fmt.Sprintf(
			"security policies default-policy: conflicting duplicate stanzas specify %q and %q (#11821)",
			first, current,
		)
		if !lenient {
			strictErr = fmt.Errorf("%s", diagnostic)
			return false
		}
		warnings = append(warnings, diagnostic+"; tolerant compilation uses deny-all")
		return true
	})
	return warnings, strictErr
}

func hasConflictingDefaultPolicyStanzas11821(nodes []*Node) bool {
	found := false
	walkConflictingDefaultPolicyStanzas11821(nodes, func(string, string) bool {
		found = true
		return false
	})
	return found
}
