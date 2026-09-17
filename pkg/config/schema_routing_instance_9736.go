package config

import (
	"fmt"
	"strings"
)

func routingInstanceRouteTargetValue9736(tok string) bool {
	return strings.HasPrefix(tok, "target:") && len(tok) > len("target:")
}

func routingInstanceFixedValueNestedType9814(node *Node, parent *schemaNode) bool {
	if parent == nil {
		return false
	}
	// #9792's ownership predicate defers only a fully declared nested RI leaf
	// run, so an undeclared sibling cannot hide a #9736 trailing token.
	return packedOrNestedLeafRun9792(node, parent)
}

func validateRoutingInstanceFixedValueNode9736(node *Node, parent *schemaNode, keyword string, args int) error {
	if node == nil {
		return nil
	}
	if routingInstanceFixedValueNestedType9814(node, parent) {
		// An authored block is compiler-owned nested structure. In particular,
		// `description x { instance-type ""; }` must reach the existing #9814
		// nested typed-leaf gate rather than being claimed by #9736.
		return nil
	}
	allowed := 1 + args
	if len(node.Keys) < allowed {
		return fmt.Errorf("`%s` declares a value and none was given (this leaf takes %d value token(s)); the compiler drops a valueless statement", keyword, args)
	}
	if len(node.Keys) > allowed {
		return fmt.Errorf("unexpected trailing token %q (this leaf takes %d value token(s); the extra token would be silently dropped)", node.Keys[allowed], args)
	}
	for _, child := range node.Children {
		if child == nil || len(child.Keys) == 0 {
			continue
		}
		return fmt.Errorf("unexpected trailing token %q (this leaf takes %d value token(s) and no sub-statement; the extra token would be silently dropped)", child.Keys[0], args)
	}
	return nil
}

func validateRoutingInstanceDescriptionNode9736(node *Node, parent *schemaNode) error {
	return validateRoutingInstanceFixedValueNode9736(node, parent, "description", 1)
}

func validateRoutingInstanceRouteDistinguisherNode9736(node *Node, parent *schemaNode) error {
	return validateRoutingInstanceFixedValueNode9736(node, parent, "route-distinguisher", 1)
}

func validateRoutingInstanceVRFTargetChild9736(node *Node) error {
	if node == nil || len(node.Keys) == 0 {
		return nil
	}
	if len(node.Children) > 0 {
		if len(node.Keys) != 1 || (node.Keys[0] != "export" && node.Keys[0] != "import") {
			return fmt.Errorf("unexpected VRF target block %q", node.Keys[0])
		}
		for _, child := range node.Children {
			if err := validateRoutingInstanceVRFTargetChild9736(child); err != nil {
				return err
			}
		}
		return nil
	}
	if node.Keys[0] == "export" || node.Keys[0] == "import" {
		tokens := node.Keys[1:]
		if node.KeyBracketed(1) {
			if len(tokens) == 0 {
				return fmt.Errorf("`%s` requires one or more route targets", node.Keys[0])
			}
			for _, tok := range tokens {
				if !routingInstanceRouteTargetValue9736(tok) {
					return fmt.Errorf("unexpected VRF target token %q in bracketed list", tok)
				}
			}
			return nil
		}
		if len(tokens) != 1 || !routingInstanceRouteTargetValue9736(tokens[0]) {
			return fmt.Errorf("`%s` requires one route target", node.Keys[0])
		}
		return nil
	}
	if len(node.Keys) != 1 || !routingInstanceRouteTargetValue9736(node.Keys[0]) {
		return fmt.Errorf("unexpected VRF target token %q", node.Keys[0])
	}
	return nil
}

// validateRoutingInstanceVRFTargetNode9736 models Junos' two ordinary forms:
// `vrf-target <target>` and `vrf-target export|import <target>`. A hierarchical
// body and an authored bracket list remain accepted because the existing
// compiler treats those as legitimate inert L3VPN statement shapes; their
// provenance is why this validator receives the AST node rather than a
// flattened token tail (#9736).
func validateRoutingInstanceVRFTargetNode9736(node *Node, _ *schemaNode) error {
	if node == nil {
		return nil
	}
	if len(node.Children) > 0 {
		if len(node.Keys) == 2 && (node.Keys[1] == "export" || node.Keys[1] == "import") {
			if len(node.Children) == 0 {
				return fmt.Errorf("`%s` requires one or more route targets", node.Keys[1])
			}
			for _, child := range node.Children {
				if child == nil || len(child.Keys) != 1 || !routingInstanceRouteTargetValue9736(child.Keys[0]) {
					return fmt.Errorf("`%s` requires one or more route targets", node.Keys[1])
				}
			}
			return nil
		}
		if len(node.Keys) != 1 {
			return fmt.Errorf("unexpected VRF target block header %v", node.Keys)
		}
		for _, child := range node.Children {
			if err := validateRoutingInstanceVRFTargetChild9736(child); err != nil {
				return err
			}
		}
		return nil
	}
	bracketed := false
	for i := 1; i < len(node.Keys); i++ {
		if node.KeyBracketed(i) {
			bracketed = true
			break
		}
	}
	if bracketed {
		tokens := node.Keys[1:]
		if len(tokens) == 0 {
			return fmt.Errorf("vrf-target bracket list requires one or more route targets")
		}
		offset := 0
		if tokens[0] == "export" || tokens[0] == "import" {
			offset = 1
		}
		if offset == len(tokens) {
			return fmt.Errorf("vrf-target direction requires one or more route targets")
		}
		for _, tok := range tokens[offset:] {
			if !routingInstanceRouteTargetValue9736(tok) {
				return fmt.Errorf("unexpected VRF target token %q in bracketed list", tok)
			}
		}
		return nil
	}
	tokens := node.Keys[1:]
	switch len(tokens) {
	case 0:
		return fmt.Errorf("missing route target")
	case 1:
		if !routingInstanceRouteTargetValue9736(tokens[0]) {
			return fmt.Errorf("unexpected route target %q", tokens[0])
		}
		return nil
	case 2:
		if tokens[0] != "export" && tokens[0] != "import" {
			return fmt.Errorf("expected `export` or `import` before the route target, got %q", tokens[0])
		}
		if !routingInstanceRouteTargetValue9736(tokens[1]) {
			return fmt.Errorf("unexpected route target %q", tokens[1])
		}
		return nil
	default:
		return fmt.Errorf("unexpected trailing token %q (vrf-target takes a target, optionally preceded by `export` or `import`)", tokens[2])
	}
}

// validateRoutingInstanceFlagNode9736 keeps the value-less
// `vrf-table-label` leaf from absorbing a packed token that the compiler
// ignores. Its ordinary flag spelling remains valid; malformed packed tails
// and arbitrary bodies are the #9736 silent-drop case.
func validateRoutingInstanceFlagNode9736(node *Node, _ *schemaNode) error {
	if node == nil {
		return nil
	}
	if len(node.Children) > 0 {
		return fmt.Errorf("unexpected block body (vrf-table-label takes no value or sub-statement)")
	}
	if len(node.Keys) <= 1 {
		return nil
	}
	for i := 1; i < len(node.Keys); i++ {
		if node.KeyBracketed(i) {
			return fmt.Errorf("unexpected bracketed value for vrf-table-label")
		}
	}
	return fmt.Errorf("unexpected trailing token %q (vrf-table-label takes no value)", node.Keys[1])
}
