package config

import (
	"fmt"
	"strings"
)

// validateFirewallFusedThen12528 rejects tails following the two firewall
// `from` leaves whose compilers do not consume those tails. SetPath and the
// hierarchical parser preserve fused statements in different AST locations,
// so inspect both leaf Keys and their Children after expanding packed bodies.
func validateFirewallFusedThen12528(children []*Node) error {
	var walk func(*Node, string, string, string, bool) error
	walk = func(node *Node, family, filter, term string, inFlex bool) error {
		if node == nil || len(node.Keys) == 0 {
			return nil
		}
		name := node.Name()
		for i, key := range node.Keys {
			if key == "flexible-match-range" {
				inFlex = true
				for _, tail := range node.Keys[i+1:] {
					if tail == "then" {
						return fusedFirewallLeafError12528(family, filter, term, "flexible-match-range range", tail)
					}
				}
			}
			if key == "from" && i+1 < len(node.Keys) && node.Keys[i+1] == "is-fragment" && i+2 < len(node.Keys) {
				return fusedFirewallLeafError12528(family, filter, term, "is-fragment", node.Keys[i+2])
			}
			if key == "is-fragment" && i == 0 && i+1 < len(node.Keys) {
				return fusedFirewallLeafError12528(family, filter, term, "is-fragment", node.Keys[i+1])
			}
		}
		if inFlex {
			start := 1
			if name == "range" {
				start = 2 // range name is part of the identity
			}
			for i := start; i < len(node.Keys); i++ {
				if node.Keys[i] == "then" {
					return fusedFirewallLeafError12528(family, filter, term, "flexible-match-range range", node.Keys[i])
				}
			}
			if name == "then" {
				return fusedFirewallLeafError12528(family, filter, term, "flexible-match-range range", name)
			}
			for _, child := range node.Children {
				if child.Name() == "then" {
					return fusedFirewallLeafError12528(family, filter, term, "flexible-match-range range", child.Name())
				}
			}
		}
		if (name == "is-fragment" || node.Keys[len(node.Keys)-1] == "is-fragment") &&
			len(node.Children) > 0 {
			return fusedFirewallLeafError12528(family, filter, term, "is-fragment", node.Children[0].Name())
		}
		if name == "filter" && len(node.Keys) > 1 {
			filter = node.Keys[1]
		}
		if name == "term" && len(node.Keys) > 1 {
			term = node.Keys[1]
		}
		for _, child := range node.Children {
			if err := walk(child, family, filter, term, inFlex); err != nil {
				return err
			}
		}
		return nil
	}
	for _, fw := range children {
		if fw == nil || fw.Name() != "firewall" {
			continue
		}
		for _, child := range fw.Children {
			if child.Name() == "family" {
				for _, member := range firewallFamilyMembers9883(child) {
					if err := walk(member.AfNode, member.Af, "", "", false); err != nil {
						return err
					}
				}
			} else if child.Name() == "filter" {
				if err := walk(child, "", "", "", false); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func fusedFirewallLeafError12528(family, filter, term, leaf, token string) error {
	where := fmt.Sprintf("firewall filter %q term %q", filter, term)
	if family != "" {
		where = fmt.Sprintf("firewall family %s filter %q term %q", family, filter, term)
	}
	return fmt.Errorf("%s: token %q follows `%s` but is not consumed by the firewall compiler; the fused statement is silently dropped while configuration display still shows it. Add the missing semicolon (#8437/#12528)", where, strings.TrimSpace(token), leaf)
}
