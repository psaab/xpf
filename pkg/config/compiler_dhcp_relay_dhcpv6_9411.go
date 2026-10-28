package config

import "fmt"

// Junos places these Interface-ID modifiers under
// forwarding-options dhcp-relay dhcpv6 relay-agent-interface-id. xpf
// supports only a scalar byte value (or the valueless default), so every
// documented modifier remains in the scoped #9553 refusal boundary.
func isUnsupportedDHCPRelayV6InterfaceIDSubOption9553(value string) bool {
	switch value {
	case "use-option-82", "prefix", "host-name", "routing-instance-name",
		"logical-system-name", "use-interface-description",
		"include-irb-and-l2", "keep-incoming-interface-id",
		"no-vlan-interface-name", "use-vlan-id":
		return true
	default:
		return false
	}
}

// validateDHCPRelayDHCPv6AST now owns only the unsupported remainder of the
// Junos DHCPv6 relay grammar. The RFC 8415 subset implemented by #9553 is
// schema-declared and compiled by compileDHCPRelayV6; unknown direct children
// remain loud instead of being silently discarded by the open-world walker.
func validateDHCPRelayDHCPv6AST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	report := func(keyword string) error {
		msg := fmt.Sprintf("forwarding-options dhcp-relay dhcpv6: %q is not in xpf's implemented RFC 8415 relay subset (known: active-server-group, group, interface, relay-agent-interface-id, server-group) — it is not compiled (#9553)", keyword)
		if lenient {
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	checkScalar := func(node *Node) error {
		if node == nil {
			return nil
		}
		if len(node.Children) > 0 {
			return report(node.Children[0].Name())
		}
		// A normal scalar leaf is exactly one unbracketed value. Junos also
		// accepts valueless relay-agent-interface-id as an enable flag; the
		// compiler records an explicit group default so it suppresses inheritance.
		if node.Name() == "relay-agent-interface-id" && len(node.Keys) == 1 {
			return nil
		}
		if len(node.Keys) != 2 || node.KeyBracketed(1) {
			switch {
			case len(node.Keys) > 2:
				return report(node.Keys[2])
			case len(node.Keys) == 2:
				return report(node.Keys[1])
			default:
				return report(node.Name() + " requires a value")
			}
		}
		return nil
	}
	checkInterfaceID := func(node *Node) error {
		if node != nil && len(node.Keys) > 1 && isUnsupportedDHCPRelayV6InterfaceIDSubOption9553(node.Keys[1]) {
			return report(node.Keys[1])
		}
		return checkScalar(node)
	}
	checkInterface := func(node *Node) error {
		if node == nil {
			return nil
		}
		// `interface { ge-0/0/0.0; }` is a legitimate multi-value
		// container. A scalar followed by a braced child is not
		// (`interface ge-0/0/0.0 { disable; }`).
		if len(node.Children) > 0 && len(node.Keys) > 1 {
			return report(node.Children[0].Name())
		}
		// A braced member carrying its own children is a nested leaf
		// (`interface { ge-0/0/0.0 { disable; } }`), not a member list.
		for _, member := range node.Children {
			if member != nil && len(member.Children) > 0 {
				return report(member.Children[0].Name())
			}
		}
		// Packed remainder (the pre-#17205 gate's mechanism, #17205
		// fold B1): `interface ge-0/0/0.0 disable` packs a keyword tail
		// behind a logical-interface value. That tail is NOT a second
		// member even though `disable` alone is a legal bare name, so
		// it is refused BY POSITION: an unbracketed tail token behind
		// a unit-carrying first value that itself carries no unit is
		// the remainder. The flat/display-set list spelling
		// (`interface ge-0/0/1.0 ge-0/0/2.0`, replayed with no bracket
		// provenance) has unit-carrying tail tokens and is judged
		// member-by-member below, so it stays accepted; a bracketed
		// hierarchical list is bracketed at Keys[2] and never reaches
		// this arm.
		if len(node.Keys) > 2 && !node.KeyBracketed(2) {
			first := splitInterfaceRefWithDeclared(nil, node.Keys[1])
			if first.HasUnit {
				for _, member := range node.Keys[2:] {
					tail := splitInterfaceRefWithDeclared(nil, member)
					if !tail.HasUnit {
						return report(member)
					}
				}
			}
		}
		// The members are exactly what both compilers install, read
		// through the shared dhcpRelayGroupInterfaces (#17205). Every
		// member must be interface-shaped (ValidateInterfaceName plus
		// the logical-unit rules); digit-less bare names such as
		// `uplink`/`vrf-mgmt` are legal members.
		members := dhcpRelayGroupInterfaces(node)
		if len(members) == 0 {
			return report(node.Name() + " requires a value")
		}
		for _, member := range members {
			if !dhcpRelayInterfaceMemberValid(member) {
				return report(member)
			}
		}
		return nil
	}
	// checkGroupPacked judges the packed tail of a group instance
	// node exactly as compileDHCPRelayV6Group9553 consumes its
	// Keys[2:] run (#17205 fold B2): the gate previously iterated
	// only inst.node.Children, so a packed unsupported knob or a bad
	// interface member on that run strict-compiled clean while the
	// compiler installed it (`group { G6 unsupported-knob interface
	// badname; }` compiled with Interfaces=[badname]). The tail is
	// instanceValueTail anchored on the instance name, so both the
	// compact `group G6 …` node and a container instance child
	// (`G6 …` as one leaf) are judged. Tokens walk with the
	// compiler's own grammar: `interface` consumes following
	// non-keyword tokens as members, scalars consume one value, any
	// other token is an unsupported knob refused by name.
	checkGroupPacked := func(inst struct {
		name string
		node *Node
	}) error {
		tail := instanceValueTail(inst.node, inst.name)
		for i := 0; i < len(tail); {
			switch tail[i] {
			case "active-server-group":
				v := ""
				if i+1 < len(tail) {
					v = tail[i+1]
				}
				n := &Node{Keys: []string{"active-server-group"}, IsLeaf: true}
				if v != "" {
					n.Keys = []string{"active-server-group", v}
				}
				if err := checkScalar(n); err != nil {
					return err
				}
				if v == "" {
					i++
				} else {
					i += 2
				}
			case "relay-agent-interface-id":
				hasVal := i+1 < len(tail) && !dhcpRelayV6GroupKeyword9553(tail[i+1])
				n := &Node{Keys: []string{"relay-agent-interface-id"}, IsLeaf: true}
				if hasVal {
					n.Keys = []string{"relay-agent-interface-id", tail[i+1]}
				}
				if err := checkInterfaceID(n); err != nil {
					return err
				}
				if hasVal {
					i += 2
				} else {
					i++
				}
			case "interface":
				j := i + 1
				var members []string
				for j < len(tail) && !dhcpRelayV6GroupKeyword9553(tail[j]) {
					members = append(members, tail[j])
					j++
				}
				if len(members) == 0 {
					return report("interface requires a value")
				}
				if len(members) > 1 && splitInterfaceRefWithDeclared(nil, members[0]).HasUnit {
					for _, m := range members[1:] {
						if !splitInterfaceRefWithDeclared(nil, m).HasUnit {
							return report(m)
						}
					}
				}
				for _, m := range members {
					if !dhcpRelayInterfaceMemberValid(m) {
						return report(m)
					}
				}
				i = j
			default:
				return report(tail[i])
			}
		}
		return nil
	}
	for _, fo := range nodes {
		if fo == nil || fo.Name() != "forwarding-options" {
			continue
		}
		for _, family := range dhcpRelayV6Nodes9553(fo) {
			if family == nil {
				continue
			}
			for _, child := range family.Children {
				if child == nil {
					continue
				}
				if routingInstanceApplyMetaKeyword9323(child.Name()) {
					continue
				}
				switch child.Name() {
				case "active-server-group":
					if err := checkScalar(child); err != nil {
						return warnings, err
					}
				case "relay-agent-interface-id":
					if err := checkInterfaceID(child); err != nil {
						return warnings, err
					}
				case "group":
					// Judge exactly the instances the compiler compiles:
					// namedInstances normalises the compact
					// `group G6 { … }` and container `group { G6 { … } }`
					// shapes onto one instance node per group (#17205).
					// The packed tail of each instance node is judged
					// first (checkGroupPacked, fold B2): the compiler
					// consumes Keys[2:] of the same node, so a packed
					// unsupported knob/member there must refuse even
					// when the instance also carries braced children.
					for _, inst := range namedInstances([]*Node{child}) {
						if err := checkGroupPacked(inst); err != nil {
							return warnings, err
						}
						for _, groupChild := range inst.node.Children {
							if groupChild == nil {
								continue
							}
							if routingInstanceApplyMetaKeyword9323(groupChild.Name()) {
								continue
							}
							switch groupChild.Name() {
							case "active-server-group":
								if err := checkScalar(groupChild); err != nil {
									return warnings, err
								}
							case "interface":
								if err := checkInterface(groupChild); err != nil {
									return warnings, err
								}
							case "relay-agent-interface-id":
								if err := checkInterfaceID(groupChild); err != nil {
									return warnings, err
								}
							default:
								if err := report(groupChild.Name()); err != nil {
									return warnings, err
								}
							}
						}
					}
				case "server-group":
					// Named server-group values are validated by the
					// typed compiler; their child addresses are not
					// scalar statements. Iterate the same
					// namedInstances the compilers use so the canonical
					// Junos block `server-group { SG6 { addr; } }` is
					// judged as the SG6 instance it compiles to, not as
					// a member carrying a child address (#17205). A
					// member whose address itself carries a child is a
					// nested leaf and stays refused.
					for _, inst := range namedInstances([]*Node{child}) {
						for _, member := range inst.node.Children {
							if member != nil && len(member.Children) > 0 {
								if err := report(member.Children[0].Name()); err != nil {
									return warnings, err
								}
							}
						}
					}
				default:
					if err := report(child.Name()); err != nil {
						return warnings, err
					}
				}
			}
		}
	}
	return warnings, nil
}

// dhcpRelayV4Node9411 returns the first `dhcp-relay` node that is not the
// `dhcp-relay dhcpv6 { … }` spelling. DHCPv6 is compiled separately, but this
// guard remains necessary to prevent its identically-named `group` children
// from being installed as DHCPv4 relays (#9411, #9553).
func dhcpRelayV4Node9411(fo *Node) *Node {
	if fo == nil {
		return nil
	}
	for _, n := range fo.FindChildren("dhcp-relay") {
		if n == nil {
			continue
		}
		if len(n.Keys) >= 2 && n.Keys[1] == "dhcpv6" {
			continue
		}
		return n
	}
	return nil
}
