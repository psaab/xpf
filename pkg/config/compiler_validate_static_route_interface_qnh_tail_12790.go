package config

import "fmt"

// validateStaticRouteInterfaceQNHChild12790 rejects a qualified-next-hop
// keyword left fused onto a static next-hop interface child. The compact
// normalizer extracts only a complete, unquoted QNH clause; incomplete and
// quoted forms otherwise remain on the interface node and the route compiler
// silently ignores their tails.
func validateStaticRouteInterfaceQNHChild12790(nodes []*Node) error {
	var walk func(nodes []*Node, parent, grandparent, greatGrandparent *Node, inStaticRoute, inStaticNextHop bool) error
	walk = func(nodes []*Node, parent, grandparent, greatGrandparent *Node, inStaticRoute, inStaticNextHop bool) error {
		for _, node := range nodes {
			if node == nil || len(node.Keys) == 0 {
				continue
			}
			name := node.Name()
			staticRoute := inStaticRoute || (name == "route" && isStaticRouteNode12648(parent, grandparent, greatGrandparent))
			staticNextHop := inStaticNextHop || (name == "next-hop" && staticRoute)
			if name == "interface" && inStaticNextHop {
				for i := 2; i < len(node.Keys); i++ {
					if node.Keys[i] != "qualified-next-hop" {
						continue
					}
					if node.KeyQuoted(i) {
						return fmt.Errorf("static route next-hop interface has a quoted qualified-next-hop tail at token %q (#12790)", node.Keys[i])
					}
					return fmt.Errorf("static route next-hop interface has a dangling qualified-next-hop keyword (#12790)")
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
