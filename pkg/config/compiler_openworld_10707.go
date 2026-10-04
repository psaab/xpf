package config

import (
	"fmt"
	"strings"
)

// routingKnobWarning11314 replaces generic open-world advisories with specific
// diagnostics for Junos routing knobs that the compiler accepts but does not
// apply.
func routingKnobWarning11314(path []string, keyword string) string {
	if keyword != bgpSAFIUnicast11815 && len(path) >= 2 &&
		path[len(path)-2] == "family" &&
		(path[len(path)-1] == "inet" || path[len(path)-1] == "inet6") {
		for i := 0; i+1 < len(path); i++ {
			if path[i] == "protocols" && path[i+1] == "bgp" {
				return fmt.Sprintf(
					"%s: BGP address-family SAFI %q is unsupported; only unicast is compiled, so this family is not activated (#11815)",
					strings.Join(path, " "), keyword)
			}
		}
	}
	if keyword == "rib-group" && len(path) >= 3 &&
		path[len(path)-3] == "static" && path[len(path)-2] == "route" {
		hasRoutingOptions := false
		for _, part := range path {
			if part == "routing-options" {
				hasRoutingOptions = true
				break
			}
		}
		if hasRoutingOptions {
			return fmt.Sprintf(
				"%s rib-group is ACCEPTED but NOT APPLIED: xpf only installs this static "+
					"route in its enclosing routing table; static-route rib-group route "+
					"sharing is not implemented (#11314)",
				strings.Join(path, " "))
		}
	}
	if len(path) == 3 && path[0] == "routing-instances" && path[2] == "routing-options" {
		switch keyword {
		case "rib-groups":
			return fmt.Sprintf(
				"routing-instance %q routing-options rib-groups is ACCEPTED but NOT APPLIED: "+
					"per-instance RIB-group definitions are retained in the compiled instance "+
					"but are not consumed by the route-sharing runtime; define route-sharing "+
					"groups globally under routing-options (#11314)",
				path[1])
		case "generate":
			return fmt.Sprintf(
				"routing-instance %q routing-options generate is ACCEPTED but NOT APPLIED: "+
					"per-instance generated routes are retained in the compiled instance but are "+
					"not applied to its forwarding configuration; configure generated routes "+
					"globally under routing-options (#11314)",
				path[1])
		case "forwarding-table":
			return fmt.Sprintf(
				"routing-instance %q routing-options forwarding-table is ACCEPTED but NOT APPLIED: "+
					"the export policy is retained in compiled instance state, but ECMP policy "+
					"selection reads only global routing-options forwarding-table export (#11782)",
				path[1])
		}
	}
	return ""
}

// warnUnknownRoutingLeaves10707 reports unmodeled child keywords in the
// protocols, policy-options, and routing-options grammars. Those schemas stay
// open-world because several have valid but not-yet-modeled Junos children;
// warning preserves those configurations while making possible silent drops
// visible on both strict commit and tolerant load/sync paths.
func warnUnknownRoutingLeaves10707(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	var warnings []string
	var seen map[string]struct{}
	appendWarning := func(message string) {
		if seen != nil {
			if _, ok := seen[message]; ok {
				return
			}
		} else {
			seen = make(map[string]struct{})
		}
		seen[message] = struct{}{}
		warnings = append(warnings, message)
	}
	warn := func(path []string, keyword string) {
		if message := routingKnobWarning11314(path, keyword); message != "" {
			appendWarning(message)
			return
		}
		appendWarning(fmt.Sprintf("%s: unmodeled configuration keyword %q is accepted by the open-world schema and may be silently ignored (#10707)",
			strings.Join(path, " "), keyword))
	}
	var walkChildren func(nodes []*Node, parent *schemaNode, path []string)
	var walkInstances func(nodes []*Node, container *schemaNode, remaining int, path []string)
	walkChildren = func(nodes []*Node, parent *schemaNode, path []string) {
		for _, node := range nodes {
			if node == nil || len(node.Keys) == 0 {
				continue
			}
			keyword := node.Keys[0]
			if message := routingKnobWarning11314(path, keyword); message != "" {
				appendWarning(message)
				continue
			}
			childSchema := resolveSchemaChild(parent, keyword)
			if childSchema == nil {
				warn(path, keyword)
				continue
			}
			// A leaf with no declared children or wildcard may carry a value
			// list or an opaque compiler-owned body. Its children are not
			// schema keywords.
			if (childSchema.children == nil && childSchema.wildcard == nil) || childSchema.closedWorldOpaque {
				continue
			}
			consumed, descend := consumeNodeKeys(node.Keys, childSchema)
			pathLen := len(path)
			path = append(path, node.Keys[:consumed]...)
			remaining := 1 + childSchema.args - consumed
			if remaining > 0 {
				walkInstances(node.Children, childSchema, remaining, path)
				path = path[:pathLen]
				continue
			}
			walkChildren(node.Children, descend, path)
			path = path[:pathLen]
		}
	}
	walkInstances = func(nodes []*Node, container *schemaNode, remaining int, path []string) {
		for _, node := range nodes {
			if node == nil || len(node.Keys) == 0 {
				continue
			}
			consumed := remaining
			if consumed > len(node.Keys) {
				consumed = len(node.Keys)
			}
			pathLen := len(path)
			path = append(path, node.Keys[:consumed]...)
			if stillMissing := remaining - consumed; stillMissing > 0 {
				walkInstances(node.Children, container, stillMissing, path)
				path = path[:pathLen]
				continue
			}
			walkChildren(node.Children, container, path)
			path = path[:pathLen]
		}
	}

	for _, node := range tree.Children {
		if node == nil || len(node.Keys) == 0 {
			continue
		}
		switch node.Keys[0] {
		case "protocols":
			walkChildren(node.Children, schemaProtocols, []string{"protocols"})
		case "policy-options":
			walkChildren(node.Children, schemaPolicyOptions, []string{"policy-options"})
		case "routing-options":
			walkChildren(node.Children, schemaRoutingOptions, []string{"routing-options"})
		case "routing-instances":
			for _, instance := range namedInstances([]*Node{node}) {
				instancePath := []string{"routing-instances", instance.name}
				for _, property := range routingInstancePropertyNodes9323(instance.node) {
					if property == nil {
						continue
					}
					pathLen := len(instancePath)
					instancePath = append(instancePath, property.Name())
					switch property.Name() {
					case "protocols":
						walkChildren(property.Children, schemaRoutingInstanceProtocols, instancePath)
					case "routing-options":
						instanceRO := schemaRoutingInstances.wildcard.children["routing-options"]
						walkChildren(property.Children, instanceRO, instancePath)
					}
					instancePath = instancePath[:pathLen]
				}
			}
		}
	}
	return warnings
}
