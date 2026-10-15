package config

// hasPackedZoneInterfaces13108 detects an `interfaces` container embedded in
// a packed run under a sibling leaf. Such a run cannot be expanded safely: its
// following interface-body tokens may otherwise be hoisted to zone scope.
func hasPackedZoneInterfaces13108(children []*Node) bool {
	zoneSchema := securityZoneSchema9792()
	if zoneSchema == nil {
		return false
	}
	for _, n := range children {
		if n == nil || len(n.Children) != 0 || len(n.Keys) < 3 {
			continue
		}
		head := zoneSchema.children[n.Keys[0]]
		if head == nil || len(head.children) > 0 || head.wildcard != nil || head.multi {
			continue
		}
		for i := 1 + head.args; i < len(n.Keys); i++ {
			if n.Keys[i] == "interfaces" {
				return true
			}
			if child := zoneSchema.children[n.Keys[i]]; child != nil {
				i += child.args
			}
		}
	}
	return false
}
