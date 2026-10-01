package config

import "fmt"

// walkAmbiguousDefaultPolicyBlocks11367 visits every `default-policy` block
// with multiple choice children. The callback returns false to stop early.
func walkAmbiguousDefaultPolicyBlocks11367(nodes []*Node, visit func(*Node) bool) {
	for _, security := range nodes {
		if security.Name() != "security" {
			continue
		}
		for _, policies := range security.Children {
			if policies.Name() != "policies" {
				continue
			}
			for _, policy := range policies.Children {
				if policy.Name() != "default-policy" || len(policy.Children) <= 1 {
					continue
				}
				if !visit(policy) {
					return
				}
			}
		}
	}
}

// validateDefaultPolicyBlockCardinality11367 rejects an ambiguous choice on
// strict compilation and warns on tolerant load/peer-sync compilation. The
// latter path continues with the default action forced to PolicyDeny.
func validateDefaultPolicyBlockCardinality11367(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	var strictErr error
	walkAmbiguousDefaultPolicyBlocks11367(nodes, func(policy *Node) bool {
		diagnostic := fmt.Sprintf(
			"security policies default-policy: "+defaultPolicyAmbiguousBlockDiagnostic,
			len(policy.Children),
		)
		if !lenient {
			strictErr = fmt.Errorf("%s", diagnostic)
			return false
		}
		warnings = append(warnings, diagnostic+"; tolerant compilation uses deny-all (#11367)")
		return true
	})
	return warnings, strictErr
}

func hasAmbiguousDefaultPolicyBlock11367(nodes []*Node) bool {
	found := false
	walkAmbiguousDefaultPolicyBlocks11367(nodes, func(*Node) bool {
		found = true
		return false
	})
	return found
}
