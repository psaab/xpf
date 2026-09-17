package config

import (
	"fmt"
	"net"
)

// compileDHCPRelayV6 compiles the Junos DHCPv6 relay subtree into the shared
// DHCPRelayConfig. The v4 and v6 families deliberately have separate typed
// maps: both use the Junos names `server-group` and `group`, but their address
// families and runtime agents are different (#9553).
func compileDHCPRelayV6(node *Node, fo *ForwardingOptionsConfig, lenient bool, warnings *[]string) error {
	nodes := dhcpRelayV6Nodes9553(node)
	if len(nodes) == 0 {
		return nil
	}
	v6 := &DHCPRelayV6Config{
		ServerGroups: make(map[string]*DHCPRelayV6ServerGroup),
		Groups:       make(map[string]*DHCPRelayV6Group),
	}
	for _, family := range nodes {
		if family == nil {
			continue
		}
		compileDHCPRelayV6Family9553(family, v6)
	}
	if err := validateDHCPRelayV6Config9553(v6); err != nil {
		if lenient {
			// The tolerant path must not brick a persisted configuration. The
			// pre-walk catches token remainders; this records semantic remainders
			// that only the typed compiler can validate (#1960).
			if warnings != nil {
				*warnings = append(*warnings, err.Error())
			}
			return nil
		}
		return err
	}
	if fo.DHCPRelay == nil {
		fo.DHCPRelay = &DHCPRelayConfig{
			ServerGroups: make(map[string]*DHCPRelayServerGroup),
			Groups:       make(map[string]*DHCPRelayGroup),
		}
	}
	fo.DHCPRelay.V6 = v6
	return nil
}

// dhcpRelayV6Nodes9553 handles both parser forms produced for this subtree:
// `dhcp-relay { dhcpv6 { ... } }` and the brace-elided
// `dhcp-relay dhcpv6 { ... }`. A fully elided packed path is normalized here as
// a final defensive measure for persisted trees that predate the schema entry.
func dhcpRelayV6Nodes9553(fo *Node) []*Node {
	if fo == nil {
		return nil
	}
	var out []*Node
	if len(fo.Keys) >= 3 && fo.Keys[1] == "dhcp-relay" && fo.Keys[2] == "dhcpv6" {
		out = append(out, dhcpRelayV6PackedNode9553(fo.Keys[3:]))
	}
	for _, relay := range fo.FindChildren("dhcp-relay") {
		if relay == nil {
			continue
		}
		if len(relay.Keys) >= 2 && relay.Keys[1] == "dhcpv6" {
			family := &Node{Keys: []string{"dhcpv6"}, Children: relay.Children}
			if len(relay.Keys) > 2 {
				family = dhcpRelayV6PackedNode9553(relay.Keys[2:])
				family.Children = append(family.Children, relay.Children...)
			}
			out = append(out, family)
			continue
		}
		for _, child := range relay.Children {
			if child != nil && child.Name() == "dhcpv6" {
				family := child
				if len(child.Keys) > 1 {
					family = dhcpRelayV6PackedNode9553(child.Keys[1:])
					family.Children = append(family.Children, child.Children...)
				}
				out = append(out, family)
			}
		}
	}
	return out
}

// dhcpRelayV6PackedNode9553 turns a fully elided key tail into the same small
// Node shape used by the hierarchical compiler. Normal schema-walked input does
// not need this path, but retaining it prevents old persisted ASTs from being
// silently ignored after the schema gained the dhcpv6 family node.
func dhcpRelayV6PackedNode9553(keys []string) *Node {
	family := &Node{Keys: []string{"dhcpv6"}}
	for i := 0; i < len(keys); {
		tok := keys[i]
		switch tok {
		case "server-group":
			if i+1 >= len(keys) {
				family.Children = append(family.Children, &Node{Keys: []string{tok}, IsLeaf: true})
				i++
				continue
			}
			n := &Node{Keys: []string{"server-group", keys[i+1]}}
			i += 2
			for i < len(keys) && !dhcpRelayV6TopKeyword9553(keys[i]) {
				n.Children = append(n.Children, &Node{Keys: []string{keys[i]}, IsLeaf: true})
				i++
			}
			family.Children = append(family.Children, n)
		case "group":
			if i+1 >= len(keys) {
				family.Children = append(family.Children, &Node{Keys: []string{tok}, IsLeaf: true})
				i++
				continue
			}
			n := &Node{Keys: []string{"group", keys[i+1]}}
			i += 2
			for i < len(keys) && keys[i] != "server-group" && keys[i] != "group" {
				switch keys[i] {
				case "active-server-group", "relay-agent-interface-id":
					if i+1 < len(keys) && !dhcpRelayV6GroupKeyword9553(keys[i+1]) {
						n.Children = append(n.Children, &Node{Keys: []string{keys[i], keys[i+1]}, IsLeaf: true})
						i += 2
					} else {
						n.Children = append(n.Children, &Node{Keys: []string{keys[i]}, IsLeaf: true})
						i++
					}
				case "interface":
					n.Children = append(n.Children, &Node{Keys: []string{"interface"}, IsLeaf: true})
					i++
					if i < len(keys) && !dhcpRelayV6GroupKeyword9553(keys[i]) {
						n.Children[len(n.Children)-1].Keys = append(n.Children[len(n.Children)-1].Keys, keys[i])
						i++
					}
				default:
					// Keep unsupported packed group children visible to the
					// #9553 AST gate. Dropping them here would make the strict
					// compiler accept a remainder that the schema walk could
					// not represent.
					n.Children = append(n.Children, &Node{Keys: []string{keys[i]}, IsLeaf: true})
					i++
				}
			}
			family.Children = append(family.Children, n)
		case "active-server-group", "relay-agent-interface-id":
			if i+1 < len(keys) && !dhcpRelayV6TopKeyword9553(keys[i+1]) {
				family.Children = append(family.Children, &Node{Keys: []string{tok, keys[i+1]}, IsLeaf: true})
				i += 2
			} else {
				family.Children = append(family.Children, &Node{Keys: []string{tok}, IsLeaf: true})
				i++
			}
		default:
			// Unknown direct family tokens must survive packed-shape
			// normalization so validateDHCPRelayDHCPv6AST can report them.
			family.Children = append(family.Children, &Node{Keys: []string{tok}, IsLeaf: true})
			i++
		}
	}
	return family
}

func dhcpRelayV6TopKeyword9553(s string) bool {
	switch s {
	case "server-group", "group", "active-server-group", "relay-agent-interface-id":
		return true
	default:
		return false
	}
}

func dhcpRelayV6GroupKeyword9553(s string) bool {
	switch s {
	case "interface", "active-server-group", "relay-agent-interface-id", "server-group", "group":
		return true
	default:
		return false
	}
}

// dhcpRelayV6InterfaceIDValue9553 reads only a true scalar Interface-ID value.
// The #9553 tolerant gate warns instead of rejecting unsupported modifiers, so
// it must not let nodeVal's child-name fallback arm a modifier as Option 18.
func dhcpRelayV6InterfaceIDValue9553(node *Node) string {
	if node == nil || len(node.Children) != 0 || len(node.Keys) != 2 || node.KeyBracketed(1) {
		return ""
	}
	value := node.Keys[1]
	if isUnsupportedDHCPRelayV6InterfaceIDSubOption9553(value) {
		return ""
	}
	return value
}

func dhcpRelayV6InterfaceIDIsBare9553(node *Node) bool {
	return node != nil && len(node.Children) == 0 && len(node.Keys) == 1
}

func compileDHCPRelayV6Family9553(family *Node, v6 *DHCPRelayV6Config) {
	for _, prop := range family.Children {
		if prop == nil {
			continue
		}
		switch prop.Name() {
		case "server-group":
			instances := namedInstances([]*Node{prop})
			for _, inst := range instances {
				sg := v6.ServerGroups[inst.name]
				if sg == nil {
					sg = &DHCPRelayV6ServerGroup{Name: inst.name}
					v6.ServerGroups[inst.name] = sg
				}
				for i := 2; i < len(inst.node.Keys); i++ {
					sg.Servers = append(sg.Servers, inst.node.Keys[i])
				}
				for _, child := range inst.node.Children {
					if child != nil {
						sg.Servers = append(sg.Servers, child.Keys...)
					}
				}
			}
		case "group":
			instances := namedInstances([]*Node{prop})
			for _, inst := range instances {
				g := v6.Groups[inst.name]
				if g == nil {
					g = &DHCPRelayV6Group{Name: inst.name}
					v6.Groups[inst.name] = g
				}
				compileDHCPRelayV6Group9553(inst.node, g)
			}
		case "active-server-group":
			if v := nodeVal(prop); v != "" {
				v6.ActiveServerGroup = v
			}
		case "relay-agent-interface-id":
			if v := dhcpRelayV6InterfaceIDValue9553(prop); v != "" {
				v6.InterfaceIDOverride = v
			}
		}
	}
	// A packed family can carry its own properties in Keys after `dhcpv6`.
	for i := 1; i < len(family.Keys); i++ {
		if (family.Keys[i] == "active-server-group" || family.Keys[i] == "relay-agent-interface-id") && i+1 < len(family.Keys) {
			switch family.Keys[i] {
			case "active-server-group":
				v6.ActiveServerGroup = family.Keys[i+1]
			case "relay-agent-interface-id":
				if !isUnsupportedDHCPRelayV6InterfaceIDSubOption9553(family.Keys[i+1]) {
					v6.InterfaceIDOverride = family.Keys[i+1]
				}
			}
			i++
		}
	}
}

func compileDHCPRelayV6Group9553(node *Node, g *DHCPRelayV6Group) {
	for i := 2; i < len(node.Keys); i++ {
		switch node.Keys[i] {
		case "active-server-group":
			if i+1 < len(node.Keys) {
				g.ActiveServerGroup = node.Keys[i+1]
				i++
			}
		case "relay-agent-interface-id":
			if i+1 < len(node.Keys) && !dhcpRelayV6GroupKeyword9553(node.Keys[i+1]) {
				if !isUnsupportedDHCPRelayV6InterfaceIDSubOption9553(node.Keys[i+1]) {
					g.InterfaceIDOverride = node.Keys[i+1]
					g.InterfaceIDOverrideSet = true
				}
				i++
			} else {
				g.InterfaceIDOverride = ""
				g.InterfaceIDOverrideSet = true
			}
		case "interface":
			for i+1 < len(node.Keys) && !dhcpRelayV6GroupKeyword9553(node.Keys[i+1]) {
				i++
				g.Interfaces = append(g.Interfaces, node.Keys[i])
			}
		}
	}
	for _, prop := range node.Children {
		if prop == nil {
			continue
		}
		switch prop.Name() {
		case "interface":
			for _, value := range prop.Keys[1:] {
				if value != "" {
					g.Interfaces = append(g.Interfaces, value)
				}
			}
			for _, child := range prop.Children {
				if child != nil && child.Name() != "" {
					g.Interfaces = append(g.Interfaces, child.Name())
				}
			}
		case "active-server-group":
			g.ActiveServerGroup = nodeVal(prop)
		case "relay-agent-interface-id":
			if dhcpRelayV6InterfaceIDIsBare9553(prop) {
				g.InterfaceIDOverride = ""
				g.InterfaceIDOverrideSet = true
			} else if v := dhcpRelayV6InterfaceIDValue9553(prop); v != "" {
				g.InterfaceIDOverride = v
				g.InterfaceIDOverrideSet = true
			}
		}
	}
}

func validateDHCPRelayV6Config9553(v6 *DHCPRelayV6Config) error {
	if v6 == nil || len(v6.Groups) == 0 {
		return fmt.Errorf("forwarding-options dhcp-relay dhcpv6: at least one group is required (#9553)")
	}
	for name, sg := range v6.ServerGroups {
		if len(sg.Servers) == 0 {
			return fmt.Errorf("forwarding-options dhcp-relay dhcpv6 server-group %q: at least one IPv6 server is required (#9553)", name)
		}
		for _, raw := range sg.Servers {
			ip := net.ParseIP(raw)
			if ip == nil || ip.To4() != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				return fmt.Errorf("forwarding-options dhcp-relay dhcpv6 server-group %q: %q is not a usable global IPv6 server address (#9553)", name, raw)
			}
		}
	}
	for name, g := range v6.Groups {
		if len(g.Interfaces) == 0 {
			return fmt.Errorf("forwarding-options dhcp-relay dhcpv6 group %q: at least one interface is required (#9553)", name)
		}
		sgName := g.ActiveServerGroup
		if sgName == "" {
			sgName = v6.ActiveServerGroup
		}
		if sgName == "" {
			return fmt.Errorf("forwarding-options dhcp-relay dhcpv6 group %q: active-server-group is required (#9553)", name)
		}
		sg := v6.ServerGroups[sgName]
		if sg == nil || len(sg.Servers) == 0 {
			return fmt.Errorf("forwarding-options dhcp-relay dhcpv6 group %q: active server-group %q is undefined or empty (#9553)", name, sgName)
		}
	}
	return nil
}
