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
		// container. A scalar followed by a braced child is not.
		if len(node.Children) > 0 && len(node.Keys) > 1 {
			return report(node.Children[0].Name())
		}
		if len(node.Keys) == 1 && len(node.Children) == 0 {
			return report(node.Name() + " requires a value")
		}
		for _, member := range node.Children {
			if member != nil && len(member.Children) > 0 {
				return report(member.Children[0].Name())
			}
		}
		if len(node.Keys) > 2 && !node.KeyBracketed(2) {
			return report(node.Keys[2])
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
					for _, groupChild := range child.Children {
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
				case "server-group":
					for _, member := range child.Children {
						if member != nil && len(member.Children) > 0 {
							if err := report(member.Children[0].Name()); err != nil {
								return warnings, err
							}
						}
					}
					// Named server-group values are otherwise validated by
					// the typed compiler; their child addresses are not
					// scalar statements.
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
