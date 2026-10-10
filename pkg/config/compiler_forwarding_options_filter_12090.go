package config

import "fmt"

// validateUnsupportedForwardingOptionsFiltersAST rejects unsupported
// `filter`/`simple-filter` keyword heads under forwarding-options. DHCP relay
// server-group names are instances, not filter keywords. No forwarding-options
// filter hook has a compiler or dataplane consumer, and open-world schema
// walking otherwise accepts and drops these nodes (#12090).
func validateUnsupportedForwardingOptionsFiltersAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(label string) error {
		msg := fmt.Sprintf(
			"forwarding-options: `%s` is not supported (xpf has no consumer for this forwarding-options binding; remove it) (#12090)",
			label)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}

	var walk func(*Node, *schemaNode, []*Node) error
	walk = func(n *Node, parentSchema *schemaNode, ancestors []*Node) error {
		if n == nil {
			return nil
		}
		// Apply statements and their tails are values, not filter heads.
		if isApplyStatementKeyword(n.Name()) {
			return nil
		}
		instanceName := isDHCPRelayInstanceName12090(n, ancestors)
		if !instanceName && (n.Name() == "filter" || n.Name() == "simple-filter") {
			if err := emit(filterKeywordLabel12090(n)); err != nil {
				return err
			}
		}
		nodeSchema, identity := schemaNodeAndIdentity12090(parentSchema, n)
		if !instanceName && inspectPackedHead12090(n, nodeSchema, ancestors) {
			if head, rest, ok := packedHead12090(n, identity); ok &&
				(head == "filter" || head == "simple-filter") {
				if err := emit(packedFilterKeywordLabel12090(head, rest)); err != nil {
					return err
				}
			}
		}
		next := append(ancestors, n)
		for _, child := range n.Children {
			if err := walk(child, nodeSchema, next); err != nil {
				return err
			}
		}
		return nil
	}
	for _, node := range nodes {
		if node == nil || node.Name() != "forwarding-options" {
			continue
		}
		if err := walk(node, setSchema, nil); err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

func isDHCPRelayInstanceName12090(n *Node, ancestors []*Node) bool {
	if n == nil || (n.Name() != "filter" && n.Name() != "simple-filter") ||
		len(ancestors) < 3 {
		return false
	}
	parent := ancestors[len(ancestors)-1]
	if (parent.Name() != "server-group" && parent.Name() != "group") ||
		len(parent.Keys) != 1 {
		return false
	}
	for i := len(ancestors) - 2; i >= 0; i-- {
		if ancestors[i].Name() == "dhcp-relay" {
			return true
		}
	}
	return false
}
