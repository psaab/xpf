package config

import (
	"fmt"
	"sort"
)

// firewallTermPathIndex12526 returns the term keyword offset in a logical AST
// path. It is used only to split packed heads before a term; the term body
// keeps its original key run so a value cannot be mistaken for a name.
func firewallTermPathIndex12526(path []string) int {
	for i := 0; i+5 < len(path); i++ {
		if path[i] == "firewall" && path[i+1] == "family" &&
			path[i+3] == "filter" && path[i+5] == "term" {
			return i + 5
		}
	}
	for i := 0; i+3 < len(path); i++ {
		if path[i] == "firewall" && path[i+1] == "filter" && path[i+3] == "term" {
			return i + 3
		}
	}
	return -1
}

// unpackFirewallScanNode12526 splits packed heads before firewall term nodes,
// preserving the complete term node and all of its authored body shape.
func unpackFirewallScanNode12526(node *Node, ancestors []string) {
	if node == nil {
		return
	}
	path := make([]string, 0, len(ancestors)+len(node.Keys))
	path = append(path, ancestors...)
	path = append(path, node.Keys...)
	termIndex := firewallTermPathIndex12526(path)
	if termIndex < 0 {
		for _, child := range node.Children {
			unpackFirewallScanNode12526(child, path)
		}
		return
	}
	splitEnd := termIndex - len(ancestors)
	if splitEnd <= 0 || splitEnd >= len(node.Keys) {
		return
	}
	keys := node.Keys
	quoted := keyMask(node.KeysQuoted, len(keys))
	bracketed := keyMask(node.KeysBracketed, len(keys))
	children, isLeaf := node.Children, node.IsLeaf
	var next *Node
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
	for i := splitEnd - 1; i >= 1; i-- {
		middle := *node
		middle.replaceKeys(
			keys[i:i+1],
			maskSlice(quoted, i, i+1),
			maskSlice(bracketed, i, i+1),
			node.BracketedClosed,
		)
		middle.Children = []*Node{next}
		middle.IsLeaf = false
		next = &middle
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

func firewallNamelessTermBody12526(term *Node) (first string, malformed bool) {
	if term == nil || len(term.Keys) != 1 {
		return "", false
	}
	for _, child := range term.Children {
		if child == nil {
			continue
		}
		if !child.IsLeaf && len(child.Keys) == 1 && child.Name() != "from" && child.Name() != "then" {
			continue
		}
		return child.Name(), true
	}
	return "", len(term.Children) == 0
}

// firewallNamelessSite17257 is one packed nameless firewall term found by
// the AST scan: the section compiler cannot see it (it never enters the
// compiled Config), so the tolerant path neutralizes it from this site.
type firewallNamelessSite17257 struct {
	family  string
	filter  string
	first   string
	ordinal int
	// expanded counts compiled terms authored BEFORE this site, expanding
	// one-key containers exactly as compileFirewall's namedInstances does.
	// ordinal counts AST term nodes; expanded is the only safe insert index
	// into the compiled term list (#17257 Sol MAJOR).
	expanded int
}

// expandedFirewallTermCount17257 counts compiled terms the authored terms
// before index authoredUpTo lower to: a >=2-key term yields one, a one-key
// container yields one per child block, and malformed terms yield zero
// (they never reach the compiled list; their placeholder takes the slot).
func expandedFirewallTermCount17257(terms []*Node, authoredUpTo int) int {
	count := 0
	for i, term := range terms {
		if i >= authoredUpTo {
			break
		}
		if _, malformed := firewallNamelessTermBody12526(term); malformed {
			continue
		}
		if len(term.Keys) >= 2 {
			count++
			continue
		}
		count += len(term.Children)
	}
	return count
}

// scanFirewallNamelessTerms12526 clones and unpacks the tree, then returns
// every nameless firewall term in stable (family, filter, source) order. A
// site is packed when its term node was synthesized by unpacking, or when an
// empty term has no typed term representation; visible sites stay with #10294.
func scanFirewallNamelessTerms12526(tree *ConfigTree) (all []firewallNamelessSite17257, packed []firewallNamelessSite17257) {
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
		unpackFirewallScanNode12526(root, nil)
	}
	record := func(family, filter string, node *Node) {
		terms := node.FindChildren("term")
		for i, term := range terms {
			first, malformed := firewallNamelessTermBody12526(term)
			if !malformed {
				continue
			}
			site := firewallNamelessSite17257{family: family, filter: filter, first: first, ordinal: i, expanded: expandedFirewallTermCount17257(terms, i)}
			all = append(all, site)
			_, existedBeforeUnpack := pre[term]
			if !existedBeforeUnpack || (len(term.Keys) == 1 && len(term.Children) == 0) {
				packed = append(packed, site)
			}
		}
	}
	var visit func(*Node)
	visit = func(node *Node) {
		if node == nil {
			return
		}
		if node.Name() == "firewall" {
			for _, child := range node.Children {
				if child.Name() == "family" {
					for _, member := range familyMembers(child) {
						for _, filter := range namedInstances(member.AfNode.FindChildren("filter")) {
							record(member.Af, filter.name, filter.node)
						}
					}
				} else if child.Name() == "filter" {
					for _, filter := range namedInstances([]*Node{child}) {
						record("", filter.name, filter.node)
					}
				}
				visit(child)
			}
			return
		}
		for _, child := range node.Children {
			visit(child)
		}
	}
	for _, root := range logicalTree.Children {
		visit(root)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].family != all[j].family {
			return all[i].family < all[j].family
		}
		return all[i].filter < all[j].filter
	})
	sort.SliceStable(packed, func(i, j int) bool {
		if packed[i].family != packed[j].family {
			return packed[i].family < packed[j].family
		}
		return packed[i].filter < packed[j].filter
	})
	return all, packed
}

func firewallNamelessError12526(s firewallNamelessSite17257) error {
	where := fmt.Sprintf("firewall filter %q", s.filter)
	if s.family != "" {
		where = fmt.Sprintf("firewall family %s filter %q", s.family, s.filter)
	}
	return fmt.Errorf("%s contains a nameless `term` block starting with %q (#10294/#12092/#12526): give every term an explicit name", where, s.first)
}

// ValidateFirewallNamelessTermsAST12526 checks literal hierarchical input
// before LoadMerge flattens term bodies into ordinary set paths. Only terms
// authored inside firewall filters are considered; flat set semantics and
// policy-group expansion retain their existing behavior.
func ValidateFirewallNamelessTermsAST12526(tree *ConfigTree) error {
	_, _, err := validateFirewallNamelessTermsAST12526(tree, false)
	return err
}

// validateFirewallNamelessTermsAST12526 preserves the strict validator's
// historical error while also exposing packed sites to the tolerant compiler.
func validateFirewallNamelessTermsAST12526(tree *ConfigTree, lenient bool) ([]string, []firewallNamelessSite17257, error) {
	all, packed := scanFirewallNamelessTerms12526(tree)
	if len(all) == 0 {
		return nil, nil, nil
	}
	if !lenient {
		return nil, nil, firewallNamelessError12526(all[0])
	}
	warnings := make([]string, 0, len(packed))
	for _, s := range packed {
		warnings = append(warnings, firewallNamelessError12526(s).Error())
	}
	return warnings, packed, nil
}
