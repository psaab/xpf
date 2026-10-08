package config

import "fmt"

// validateUnsupportedForwardingOptionsFiltersAST rejects every `filter` or
// `simple-filter` keyword under forwarding-options. No forwarding-options
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

	var walk func(*Node) error
	walk = func(n *Node) error {
		if n == nil {
			return nil
		}
		if n.Name() == "filter" || n.Name() == "simple-filter" {
			if err := emit(filterKeywordLabel12090(n)); err != nil {
				return err
			}
		}
		if n.Name() == "family" {
			// `family inet` is an open-world split shape: its AF child may
			// carry the remaining `filter input F` tail in Keys rather than
			// as child nodes. `family inet6` is compound-keyed, but persisted
			// trees can also carry a flattened tail on the family node itself.
			if len(n.Keys) >= 3 &&
				(n.Keys[1] == "inet" || n.Keys[1] == "inet6") &&
				(n.Keys[2] == "filter" || n.Keys[2] == "simple-filter") {
				if err := emit(forwardingPackedFilterLabel12090(n.Keys[2], n.Keys[3:])); err != nil {
					return err
				}
			}
			for _, af := range n.Children {
				if af == nil || len(af.Keys) < 2 ||
					(af.Keys[0] != "inet" && af.Keys[0] != "inet6") ||
					(af.Keys[1] != "filter" && af.Keys[1] != "simple-filter") {
					continue
				}
				if err := emit(forwardingPackedFilterLabel12090(af.Keys[1], af.Keys[2:])); err != nil {
					return err
				}
			}
		}
		for _, child := range n.Children {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	for _, node := range nodes {
		if node == nil || node.Name() != "forwarding-options" {
			continue
		}
		for _, child := range node.Children {
			if err := walk(child); err != nil {
				return nil, err
			}
		}
	}
	return warnings, nil
}
func forwardingPackedFilterLabel12090(keyword string, rest []string) string {
	if len(rest) > 0 && isFilterDirection12090(rest[0]) {
		return keyword + " " + rest[0]
	}
	return keyword
}
