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

// --- #15998: an invalid default-policy value beside a valid one -------------
//
// defaultPolicyActions12821 and walkConflictingDefaultPolicyStanzas11821 count
// only the three valid spellings, and compilePolicies' switch previously had
// no default arm — so `permit-all` followed by a garbage value (via duplicate
// roots or group restatement on Load/SyncApply) left the earlier permit
// standing. A single invalid value alone is safe (init is PolicyDeny); the
// fail-open needs a valid value anywhere plus an invalid value anywhere.
//
// The census below walks EVERY authored token of every default-policy
// stanza (trailing Keys, child names, child key tails, nested children) —
// not only the compiler's selected action — so a bracket list like
// `default-policy [ permit-all permit-al ]` or a packed tail like
// `default-policy { permit-all permit-al; }` is also caught.

// defaultPolicyTokens15998 returns every authored value token inside one
// default-policy node, mirroring defaultPolicyActions12821's traversal but
// keeping unsupported tokens instead of discarding them.
func defaultPolicyTokens15998(node *Node) []string {
	var tokens []string
	var collect func(n *Node, root bool)
	collect = func(n *Node, root bool) {
		if n == nil {
			return
		}
		if len(n.Keys) > 0 {
			// Only the stanza ROOT's identity is exempt. A DESCENDANT
			// node also named `default-policy` is an authored invalid
			// token in its own right (#15998 fold 3): exempting every
			// node with that name dropped
			// `default-policy { permit-all { default-policy; } }`
			// from the census and left permit-all standing tolerant.
			if root {
				// root name is the stanza keyword, not a value
			} else {
				tokens = append(tokens, n.Name())
			}
			tokens = append(tokens, n.Keys[1:]...)
		}
		for _, child := range n.Children {
			collect(child, false)
		}
	}
	collect(node, true)
	return tokens
}

// invalidDefaultPolicyTokens15998 collects every invalid authored token
// across all default-policy stanzas, in author order.
func invalidDefaultPolicyTokens15998(nodes []*Node) []string {
	var invalid []string
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
				toks := defaultPolicyTokens15998(stanza)
				if len(toks) == 0 {
					// Missing-value stanza (`default-policy;` with no
					// keys/children): an authored stanza carrying NO valid
					// action is invalid (#15998 fold 2), distinct from an
					// absent stanza (deny init).
					invalid = append(invalid, "")
					continue
				}
				for _, tok := range toks {
					// An empty token (quoted "") is INVALID, never
					// skipped (#15998 fold 2): skipping it left the
					// selected permit-all standing fail-open.
					switch tok {
					case "permit-all", "deny-all", "reject-all":
					default:
						invalid = append(invalid, tok)
					}
				}
			}
		}
	}
	return invalid
}

// hasInvalidDefaultPolicyValue15998 reports whether any default-policy stanza
// carries any authored token that is not a valid action.
func hasInvalidDefaultPolicyValue15998(nodes []*Node) bool {
	return len(invalidDefaultPolicyTokens15998(nodes)) > 0
}

func validateInvalidDefaultPolicy15998(nodes []*Node, lenient bool) ([]string, error) {
	invalid := invalidDefaultPolicyTokens15998(nodes)
	if len(invalid) == 0 {
		return nil, nil
	}
	diagnostic := fmt.Sprintf(
		"security policies default-policy: invalid value(s) %q are not permit-all, deny-all or reject-all (#15998)",
		invalid)
	if !lenient {
		return nil, fmt.Errorf("%s", diagnostic)
	}
	return []string{diagnostic + "; tolerant compilation uses deny-all"}, nil
}
