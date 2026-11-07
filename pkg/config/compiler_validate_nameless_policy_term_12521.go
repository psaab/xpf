package config

import (
	"fmt"
	"sort"
	"strings"
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
	quoted := keyMask(node.KeysQuoted, len(keys))
	bracketed := keyMask(node.KeysBracketed, len(keys))
	var next *Node
	if splitEnd < len(keys) {
		segment := *node
		segment.replaceKeys(
			keys[splitEnd:],
			maskSlice(quoted, splitEnd, len(keys)),
			maskSlice(bracketed, splitEnd, len(keys)),
			node.BracketedClosed,
		)
		segment.Children = children
		segment.IsLeaf = isLeaf
		next = &segment
	}
	for i := splitEnd - 1; i >= 1; i-- {
		segment := *node
		segment.replaceKeys(
			keys[i:i+1],
			maskSlice(quoted, i, i+1),
			maskSlice(bracketed, i, i+1),
			node.BracketedClosed,
		)
		if next == nil {
			segment.Children = children
			segment.IsLeaf = isLeaf
		} else {
			segment.Children = []*Node{next}
			segment.IsLeaf = false
		}
		next = &segment
	}
	node.replaceKeys(
		keys[:1],
		maskSlice(quoted, 0, 1),
		maskSlice(bracketed, 0, 1),
		node.BracketedClosed,
	)
	node.Children = []*Node{next}
	node.IsLeaf = false
}

// policyNamelessSite17257 is one packed nameless policy term found by the AST
// scan. The packed compiler spelling can disappear before the typed policy
// compiler sees the term, so the site carries its authored ordinal forward.
type policyNamelessSite17257 struct {
	policy  string
	first   string
	ordinal int
}

func scanPolicyNamelessTerms12521(tree *ConfigTree) (all []policyNamelessSite17257, packed []policyNamelessSite17257) {
	if tree == nil {
		return nil, nil
	}
	logicalTree := tree.Clone()
	pre := make(map[*Node]struct{})
	var markPre func(*Node)
	markPre = func(n *Node) {
		if n == nil {
			return
		}
		pre[n] = struct{}{}
		for _, c := range n.Children {
			markPre(c)
		}
	}
	for _, root := range logicalTree.Children {
		markPre(root)
	}
	for _, root := range logicalTree.Children {
		unpackPolicyScanNode12521(root, nil)
	}
	scanPolicyOptions := func(po *Node) {
		for _, ps := range namedInstances(po.FindChildren("policy-statement")) {
			if ps.node == nil {
				continue
			}
			for ordinal, term := range ps.node.FindChildren("term") {
				if term.Inactive {
					continue
				}
				_, first, nameless := policyNamelessTermBody12521(term)
				if !nameless {
					continue
				}
				site := policyNamelessSite17257{policy: ps.name, first: first, ordinal: ordinal}
				all = append(all, site)
				if _, existedBeforeUnpack := pre[term]; !existedBeforeUnpack {
					packed = append(packed, site)
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
	sort.SliceStable(all, func(i, j int) bool {
		return all[i].policy < all[j].policy
	})
	sort.SliceStable(packed, func(i, j int) bool {
		return packed[i].policy < packed[j].policy
	})
	return all, packed
}

// ValidatePolicyNamelessTermsAST12521 checks literal hierarchical input before
// lowering it to set paths. A clone is unpacked into logical paths outside term
// bodies so packed heads are visible without changing body-shape classification.
// Groups are deliberately not expanded: references may resolve against the
// candidate, and inactive/variable references remain deferred to normal loading.
func ValidatePolicyNamelessTermsAST12521(tree *ConfigTree) error {
	_, _, err := validatePolicyNamelessTermsAST12521(tree, false)
	return err
}

// validatePolicyNamelessTermsAST12521 preserves the strict validator's
// historical error while also exposing packed sites to the tolerant compiler.
func validatePolicyNamelessTermsAST12521(tree *ConfigTree, lenient bool) ([]string, []policyNamelessSite17257, error) {
	all, packed := scanPolicyNamelessTerms12521(tree)
	if len(all) == 0 {
		return nil, nil, nil
	}
	if !lenient {
		return nil, nil, policyNamelessTermError12521(all[0].policy, all[0].first)
	}
	warnings := make([]string, 0, len(packed))
	for _, site := range packed {
		warnings = append(warnings, policyNamelessTermError12521(site.policy, site.first).Error())
	}
	return warnings, packed, nil
}

// ValidateInactiveNamelessPolicyTermReplay12598 refuses inactive terms whose
// nameless identity would alias an existing named term after set-path
// flattening. candidate is the pre-merge working tree, so this also catches
// collisions with the already-staged configuration.
func ValidateInactiveNamelessPolicyTermReplay12598(input, candidate *ConfigTree) error {
	type statement struct {
		terms []*Node
	}
	statements := make(map[string]statement)
	collect := func(tree *ConfigTree, visit func(string, *Node)) {
		if tree == nil {
			return
		}
		logical := tree.Clone()
		for _, root := range logical.Children {
			unpackPolicyScanNode12521(root, nil)
		}
		var scanPolicyOptions func(*Node, []string)
		scanPolicyOptions = func(po *Node, scope []string) {
			for _, ps := range namedInstances(po.FindChildren("policy-statement")) {
				if ps.node == nil {
					continue
				}
				path := append(append([]string(nil), scope...), "policy-options", "policy-statement", ps.name)
				visit(strings.Join(path, "\x00"), ps.node)
			}
		}
		for _, po := range logical.FindChildren("policy-options") {
			scanPolicyOptions(po, nil)
		}
		var walkGroup func(*Node, []string)
		walkGroup = func(node *Node, scope []string) {
			for _, child := range node.Children {
				if child.Name() == "policy-options" {
					scanPolicyOptions(child, scope)
					continue
				}
				next := append(append([]string(nil), scope...), child.Keys...)
				walkGroup(child, next)
			}
		}
		for _, groups := range logical.FindChildren("groups") {
			for _, group := range groups.Children {
				scope := append([]string{"groups"}, group.Keys...)
				walkGroup(group, scope)
			}
		}
	}
	collect(candidate, func(key string, ps *Node) {
		terms := statements[key].terms
		terms = append(terms, ps.FindChildren("term")...)
		statements[key] = statement{terms: terms}
	})
	var err error
	collect(input, func(key string, ps *Node) {
		if err != nil {
			return
		}
		terms := ps.FindChildren("term")
		candidateTerms := statements[key].terms
		for _, term := range terms {
			if term == nil || !term.Inactive || len(term.Keys) != 1 || term.Keys[0] != "term" {
				continue
			}
			names := make([]string, 0, len(term.Children))
			for _, child := range term.Children {
				if len(child.Keys) > 0 {
					names = append(names, child.Keys[0])
				}
			}
			if len(names) == 0 {
				names = append(names, "")
			}
			for _, name := range names {
				for _, sibling := range terms {
					if sibling == term || len(sibling.Keys) < 2 {
						continue
					}
					if name == "" || sibling.Keys[1] == name {
						err = fmt.Errorf("inactive nameless policy term would alias named term %q after LoadMerge flattening (#12598)", sibling.Keys[1])
						return
					}
				}
				for _, sibling := range candidateTerms {
					if sibling == nil || len(sibling.Keys) < 2 {
						continue
					}
					if name == "" || sibling.Keys[1] == name {
						err = fmt.Errorf("inactive nameless policy term would alias candidate term %q after LoadMerge flattening (#12598)", sibling.Keys[1])
						return
					}
				}
			}
		}
	})
	return err
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
