package config

import "fmt"

// recordMisnestedSecurityPolicyChild12629 records a skipped policy-shaped
// child through #12217's unknown-policy quarantine path. Strict schema walking
// rejects the same child; tolerant compilation must not let an omitted DENY
// fall through to a permit default.
func recordMisnestedSecurityPolicyChild12629(sec *SecurityConfig, context, keyword string) {
	if sec == nil || keyword == "" || isApplyStatementKeyword(keyword) {
		return
	}
	recordUnknownSecurityPoliciesChild12217(sec, fmt.Sprintf("%s %s", context, keyword))
}

func recordMisnestedPolicyChildren12629(sec *SecurityConfig, node *Node, expected, context string) {
	if node == nil {
		return
	}
	for _, child := range node.Children {
		if child.Name() != expected && hasPolicyIntent12629(child) {
			recordMisnestedSecurityPolicyChild12629(sec, context, child.Name())
		}
	}
}

// hasPolicyIntent12629 recognizes a rule node under an unsupported context
// spelling. The AST can either retain the `policy` node below the misspelling
// or put the rule's match/then body directly on a misspelled policy node.
// Ignore the pre-#2008 `inactive:` AST residue retained by upgrade-compat
// tests; it is not an active policy context.
func hasPolicyIntent12629(node *Node) bool {
	if node == nil || node.Name() == "inactive:" {
		return false
	}
	if node.Name() == "policy" {
		return true
	}
	for _, child := range node.Children {
		if child.Name() == "then" || hasPolicyIntent12629(child) {
			return true
		}
	}
	return false
}
