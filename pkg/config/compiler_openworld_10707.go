package config

import (
	"fmt"
	"strings"
)

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
	warn := func(path []string, keyword string) {
		message := fmt.Sprintf("%s: unmodeled configuration keyword %q is accepted by the open-world schema and may be silently ignored (#10707)",
			strings.Join(path, " "), keyword)
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
	var walkChildren func(nodes []*Node, parent *schemaNode, path []string)
	var walkInstances func(nodes []*Node, container *schemaNode, remaining int, path []string)
	walkChildren = func(nodes []*Node, parent *schemaNode, path []string) {
		for _, node := range nodes {
			if node == nil || len(node.Keys) == 0 {
				continue
			}
			keyword := node.Keys[0]
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
