package config

import "fmt"

// validateStaticRouteQNHTails12813 rejects incomplete qualified-next-hop tails
// left fused by the static-route compact normalizer. The normalizer extracts
// only complete, supported clauses; residual tokens otherwise pass through
// compilation as ordinary next-hop addresses.
func validateStaticRouteQNHTails12813(nodes []*Node) error {
	var walk func(nodes []*Node, parent, grandparent, greatGrandparent *Node, inStaticRoute, inStaticNextHop bool) error
	walk = func(nodes []*Node, parent, grandparent, greatGrandparent *Node, inStaticRoute, inStaticNextHop bool) error {
		for _, node := range nodes {
			if node == nil || len(node.Keys) == 0 {
				continue
			}
			name := node.Name()
			staticRoute := inStaticRoute || (name == "route" && isStaticRouteNode12648(parent, grandparent, greatGrandparent))
			staticNextHop := inStaticNextHop || (name == "next-hop" && staticRoute)
			if staticNextHop {
				for i := 1; i < len(node.Keys); i++ {
					if node.Keys[i] == "qualified-next-hop" {
						if node.KeyQuoted(i) {
							return fmt.Errorf("static route next-hop has a quoted qualified-next-hop tail (#12790)")
						}
						return fmt.Errorf("static route next-hop has a dangling qualified-next-hop tail or incomplete clause (#12790/#12813)")
					}
				}
			}
			if name == "qualified-next-hop" && inStaticRoute {
				if err := validateStaticRouteQNHKeys12813(node); err != nil {
					return err
				}
			}
			if err := walk(node.Children, node, parent, grandparent, staticRoute, staticNextHop); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(nodes, nil, nil, nil, false, false)
}

func validateStaticRouteQNHKeys12813(node *Node) error {
	if node == nil {
		return nil
	}
	for i := 2; i < len(node.Keys); {
		switch node.Keys[i] {
		case "interface", "preference", "metric":
			if i+1 >= len(node.Keys) {
				return fmt.Errorf("static route qualified-next-hop has an incomplete %q modifier (#12813)", node.Keys[i])
			}
			i += 2
		default:
			return fmt.Errorf("static route qualified-next-hop has unsupported trailing token %q (#12813)", node.Keys[i])
		}
	}
	return nil
}
