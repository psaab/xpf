package config

import (
	"fmt"
	"sort"
)

// policyNamelessTermErrors12521 collects malformed terms in stable policy and
// term order so strict diagnostics and tolerant warnings are deterministic.
func policyNamelessTermErrors12521(cfg *Config) []error {
	if cfg == nil || cfg.PolicyOptions.PolicyStatements == nil {
		return nil
	}

	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	var errs []error
	for _, name := range names {
		ps := cfg.PolicyOptions.PolicyStatements[name]
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term == nil || !term.nameless {
				continue
			}
			errs = append(errs, policyNamelessTermError12521(name, term.Name))
		}
	}
	return errs
}

func validatePolicyNamelessTermsStrict12521(cfg *Config) error {
	errs := policyNamelessTermErrors12521(cfg)
	if len(errs) == 0 {
		return nil
	}
	return errs[0]
}

func policyNestedTermWarnings12521(cfg *Config) []string {
	if cfg == nil || cfg.PolicyOptions.PolicyStatements == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	var warnings []string
	for _, name := range names {
		ps := cfg.PolicyOptions.PolicyStatements[name]
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term != nil && term.nestedContainer12521 {
				warnings = append(warnings, fmt.Sprintf(
					"policy-statement %q term %q is compiled from a one-key `term` container (#12521)",
					name, term.Name))
			}
		}
	}
	return warnings
}

// namedPolicyTermChild12521 recognizes the nested named-term spelling
// `term { NAME { ... } }`. The `from` and `then` containers are term-body
// statements, not names.
func namedPolicyTermChild12521(node *Node) bool {
	return node != nil && !node.IsLeaf && len(node.Keys) == 1 &&
		node.Name() != "from" && node.Name() != "then"
}

// policyNamelessTermBody12521 returns the body statements of an unnamed
// one-key term container. A truly empty container is also nameless.
func policyNamelessTermBody12521(term *Node) (body []*Node, first string, nameless bool) {
	if term == nil || len(term.Keys) >= 2 {
		return nil, "", false
	}
	for _, child := range term.Children {
		if !namedPolicyTermChild12521(child) {
			body = append(body, child)
		}
	}
	if len(body) > 0 {
		return body, body[0].Name(), true
	}
	if len(term.Children) == 0 {
		return nil, "", true
	}
	return nil, "", false
}

func policyNamelessTermError12521(policy, first string) error {
	return fmt.Errorf(
		"policy-statement %q contains a nameless `term` block starting with %q (#12521): "+
			"give every term an explicit name",
		policy, first)
}

// policyTermPathIndex12521 returns the term key's offset in the logical path
// whose AST shape may be split across parser nodes or packed in one key run.
func policyTermPathIndex12521(path []string) int {
	for i := 0; i+3 < len(path); i++ {
		if path[i] == "policy-options" &&
			path[i+1] == "policy-statement" &&
			path[i+3] == "term" {
			return i + 3
		}
	}
	return -1
}

// unpackPolicyScanNode12521 splits parser key runs into logical single-key
// chains on a cloned tree while preserving policy term names and body shapes.
func unpackPolicyScanNode12521(node *Node, ancestors []string) {
	if node == nil {
		return
	}
	path := make([]string, 0, len(ancestors)+len(node.Keys))
	path = append(path, ancestors...)
	path = append(path, node.Keys...)
	termPathIndex := policyTermPathIndex12521(path)
	if termPathIndex < 0 {
		for _, child := range node.Children {
			unpackPolicyScanNode12521(child, path)
		}
	}
	keys := node.Keys
	if len(keys) < 2 {
		return
	}
	splitEnd := len(keys)
	if termPathIndex >= 0 {
		splitEnd = termPathIndex - len(ancestors)
		if splitEnd <= 0 {
			return
		}
	}
	children := node.Children
	isLeaf := node.IsLeaf
	quoted := node.KeysQuoted
	bracketed := node.KeysBracketed
	var next *Node
	if splitEnd < len(keys) {
		segment := *node
		segment.Keys = keys[splitEnd:]
		if len(quoted) == len(keys) {
			segment.KeysQuoted = quoted[splitEnd:]
		} else {
			segment.KeysQuoted = nil
		}
		if len(bracketed) == len(keys) {
			segment.KeysBracketed = bracketed[splitEnd:]
		} else {
			segment.KeysBracketed = nil
		}
		segment.Children = children
		segment.IsLeaf = isLeaf
		next = &segment
	}
	for i := splitEnd - 1; i >= 1; i-- {
		segment := *node
		segment.Keys = keys[i : i+1]
		if len(quoted) == len(keys) {
			segment.KeysQuoted = quoted[i : i+1]
		} else {
			segment.KeysQuoted = nil
		}
		if len(bracketed) == len(keys) {
			segment.KeysBracketed = bracketed[i : i+1]
		} else {
			segment.KeysBracketed = nil
		}
		if next == nil {
			segment.Children = children
			segment.IsLeaf = isLeaf
		} else {
			segment.Children = []*Node{next}
			segment.IsLeaf = false
		}
		next = &segment
	}
	node.Keys = keys[:1]
	if len(quoted) == len(keys) {
		node.KeysQuoted = quoted[:1]
	} else {
		node.KeysQuoted = nil
	}
	if len(bracketed) == len(keys) {
		node.KeysBracketed = bracketed[:1]
	} else {
		node.KeysBracketed = nil
	}
	node.Children = []*Node{next}
	node.IsLeaf = false
}

// ValidatePolicyNamelessTermsAST12521 checks literal hierarchical input before
// lowering it to set paths. A clone is unpacked into logical paths outside term
// bodies so packed heads are visible without changing body-shape classification.
// Groups are deliberately not expanded: references may resolve against the
// candidate, and inactive/variable references remain deferred to normal loading.
func ValidatePolicyNamelessTermsAST12521(tree *ConfigTree) error {
	if tree == nil {
		return nil
	}
	logicalTree := tree.Clone()
	for _, root := range logicalTree.Children {
		unpackPolicyScanNode12521(root, nil)
	}
	type occurrence struct {
		policy string
		first  string
	}
	var occurrences []occurrence
	scanPolicyOptions := func(po *Node) {
		for _, ps := range namedInstances(po.FindChildren("policy-statement")) {
			if ps.node == nil {
				continue
			}
			for _, term := range ps.node.FindChildren("term") {
				if term.Inactive {
					continue
				}
				_, first, nameless := policyNamelessTermBody12521(term)
				if nameless {
					occurrences = append(occurrences, occurrence{policy: ps.name, first: first})
				}
			}
		}
	}
	for _, po := range logicalTree.FindChildren("policy-options") {
		scanPolicyOptions(po)
	}
	var visitGroupBody func(*Node)
	visitGroupBody = func(node *Node) {
		if node == nil {
			return
		}
		for _, child := range node.Children {
			if child.Name() == "policy-options" {
				scanPolicyOptions(child)
			}
			visitGroupBody(child)
		}
	}
	for _, groups := range logicalTree.FindChildren("groups") {
		for _, group := range groups.Children {
			visitGroupBody(group)
		}
	}
	sort.SliceStable(occurrences, func(i, j int) bool {
		return occurrences[i].policy < occurrences[j].policy
	})
	if len(occurrences) > 0 {
		return policyNamelessTermError12521(occurrences[0].policy, occurrences[0].first)
	}
	return nil
}

// neutralizePolicyNamelessTerms12521 keeps a typed placeholder so tolerant
// loads preserve the policy's term count without executing untrusted body
// matches or actions.
func neutralizePolicyNamelessTerms12521(cfg *Config) {
	if cfg == nil {
		return
	}
	for _, ps := range cfg.PolicyOptions.PolicyStatements {
		if ps == nil {
			continue
		}
		for i, term := range ps.Terms {
			if term != nil && term.nameless {
				ps.Terms[i] = &PolicyTerm{Name: term.Name, nameless: true}
			}
		}
	}
}
