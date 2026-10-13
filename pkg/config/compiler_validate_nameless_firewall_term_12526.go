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
	keys, quoted, bracketed := node.Keys, node.KeysQuoted, node.KeysBracketed
	children, isLeaf := node.Children, node.IsLeaf
	var next *Node
	segment := *node
	segment.Keys = keys[splitEnd:]
	segment.Children = children
	segment.IsLeaf = isLeaf
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
	next = &segment
	for i := splitEnd - 1; i >= 1; i-- {
		middle := *node
		middle.Keys = keys[i : i+1]
		middle.Children = []*Node{next}
		middle.IsLeaf = false
		if len(quoted) == len(keys) {
			middle.KeysQuoted = quoted[i : i+1]
		} else {
			middle.KeysQuoted = nil
		}
		if len(bracketed) == len(keys) {
			middle.KeysBracketed = bracketed[i : i+1]
		} else {
			middle.KeysBracketed = nil
		}
		next = &middle
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

// ValidateFirewallNamelessTermsAST12526 checks literal hierarchical input
// before LoadMerge flattens term bodies into ordinary set paths. Only terms
// authored inside firewall filters are considered; flat set semantics and
// policy-group expansion retain their existing behavior.
func ValidateFirewallNamelessTermsAST12526(tree *ConfigTree) error {
	if tree == nil {
		return nil
	}
	logicalTree := tree.Clone()
	for _, root := range logicalTree.Children {
		unpackFirewallScanNode12526(root, nil)
	}
	type occurrence struct{ family, filter, first string }
	var found []occurrence
	var visit func(*Node)
	visit = func(node *Node) {
		if node == nil {
			return
		}
		if node.Name() == "firewall" {
			for _, child := range node.Children {
				if child.Name() == "family" {
					for _, member := range firewallFamilyMembers9883(child) {
						for _, filter := range namedInstances(member.AfNode.FindChildren("filter")) {
							for _, term := range filter.node.FindChildren("term") {
								first, malformed := firewallNamelessTermBody12526(term)
								if malformed {
									found = append(found, occurrence{member.Af, filter.name, first})
								}
							}
						}
					}
				} else if child.Name() == "filter" {
					// The family-less `firewall filter F` spelling has no
					// family to report.
					for _, filter := range namedInstances([]*Node{child}) {
						for _, term := range filter.node.FindChildren("term") {
							first, malformed := firewallNamelessTermBody12526(term)
							if malformed {
								found = append(found, occurrence{"", filter.name, first})
							}
						}
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
	if len(found) == 0 {
		return nil
	}
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].family != found[j].family {
			return found[i].family < found[j].family
		}
		return found[i].filter < found[j].filter
	})
	bad := found[0]
	where := fmt.Sprintf("firewall filter %q", bad.filter)
	if bad.family != "" {
		where = fmt.Sprintf("firewall family %s filter %q", bad.family, bad.filter)
	}
	return fmt.Errorf("%s contains a nameless `term` block starting with %q (#10294/#12092/#12526): give every term an explicit name", where, bad.first)
}
