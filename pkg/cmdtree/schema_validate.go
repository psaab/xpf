package cmdtree

// SchemaValidate is the #1319 typed-leaf gate that runs at commit-check
// time, BEFORE the existing pkg/config compiler.
//
// Why pre-compile? parseBandwidthLimit / parseBurstSizeLimit silently
// return 0 on garbage input, so `set class-of-service schedulers x
// transmit-rate asd` currently compiles to zero bps and commits
// silently. SchemaValidate walks the AST against the cmdtree's
// typed-leaf metadata (Node.ValueType + Node.Validator) and fails the
// commit with a human-readable error before the compiler ever sees the
// bad string.
//
// Scope this PR (#1319 Phase 1 + Phase 2 schedulers only):
//   - Walks `class-of-service schedulers <name> { ... }`.
//   - Every other subsystem is on ValueAny by default and skipped by
//     the walker — the gate is opt-in per leaf.
//
// Adding a new typed subtree is purely a matter of populating
// ValueType + Validator on the corresponding cmdtree Nodes and adding
// a walker entry below.

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// SchemaValidate walks the AST and, for every typed-leaf cmdtree Node
// that matches an AST node, invokes its Validator on the leaf's value.
// It returns the FIRST error encountered (matching how the existing
// compiler surfaces commit-check failures). cfg may be nil — none of
// the Phase-2 schedulers validators need it, but the signature reserves
// room for future cross-reference validators.
func SchemaValidate(tree *config.ConfigTree, cfg *config.Config) error {
	if tree == nil {
		return nil
	}
	// We only have a typed-leaf map for the `set class-of-service
	// schedulers ...` subtree in this PR. Walking the whole AST against
	// the (still-mostly-untyped) cmdtree ConfigTopLevel would be wasted
	// work; restrict the walk to the subtree we actually validate.
	cosNode := tree.FindChild("class-of-service")
	if cosNode == nil {
		return nil
	}
	schedRoot := ConfigClassOfServiceSchedulers
	if schedRoot == nil {
		return nil
	}
	for _, schedulersNode := range cosNode.FindChildren("schedulers") {
		if err := walkSchedulers(schedulersNode, schedRoot, cfg); err != nil {
			return err
		}
	}
	return nil
}

// walkSchedulers handles both AST shapes for the schedulers subtree:
//
//   - hierarchical: `schedulers { be-sched { transmit-rate 7g; ... } }`
//     ⇒ Node Keys=["schedulers"], child Keys=["be-sched"], grandchild
//     leaves like Keys=["transmit-rate","7g"].
//
//   - flat `set` form: `set class-of-service schedulers be-sched
//     transmit-rate 7g` ⇒ Keys=["schedulers","be-sched"] with a chain
//     of leaf Children Keys=["transmit-rate","7g"].
func walkSchedulers(node *config.Node, schemaSchedRoot *Node, cfg *config.Config) error {
	if node == nil || schemaSchedRoot == nil {
		return nil
	}
	// AST shape A: Keys = ["schedulers", "<name>"], children = leaves.
	if len(node.Keys) >= 2 && node.Keys[0] == "schedulers" {
		schedName := node.Keys[1]
		// Per-scheduler value tokens carried directly on this node
		// (uncommon but possible in flat set form).
		if len(node.Keys) > 2 {
			pseudoLeaf := &config.Node{Keys: node.Keys[2:]}
			if err := validateSchedulerLeaf(schedName, pseudoLeaf, schemaSchedRoot, cfg); err != nil {
				return err
			}
		}
		return walkSchedulerInstance(schedName, node.Children, schemaSchedRoot, cfg)
	}
	// AST shape B: Keys = ["schedulers"], children = instance nodes.
	for _, inst := range node.Children {
		if len(inst.Keys) == 0 {
			continue
		}
		schedName := inst.Keys[0]
		if len(inst.Keys) > 1 {
			pseudoLeaf := &config.Node{Keys: inst.Keys[1:]}
			if err := validateSchedulerLeaf(schedName, pseudoLeaf, schemaSchedRoot, cfg); err != nil {
				return err
			}
		}
		if err := walkSchedulerInstance(schedName, inst.Children, schemaSchedRoot, cfg); err != nil {
			return err
		}
	}
	return nil
}

func walkSchedulerInstance(schedName string, children []*config.Node, schemaSchedRoot *Node, cfg *config.Config) error {
	for _, leaf := range children {
		if err := validateSchedulerLeaf(schedName, leaf, schemaSchedRoot, cfg); err != nil {
			return err
		}
	}
	return nil
}

// validateSchedulerLeaf resolves the cmdtree node for this AST leaf and
// invokes its Validator on the leaf's value. The "value" lives either
// in Keys[N+] (flat set form: Keys=["transmit-rate","1g","exact"]) or
// in node.Children[0].Keys[0] (hierarchical: child node holds it).
func validateSchedulerLeaf(schedName string, leaf *config.Node, schemaSchedRoot *Node, cfg *config.Config) error {
	if len(leaf.Keys) == 0 {
		return nil
	}
	leafName := leaf.Keys[0]
	schemaNode, ok := schemaSchedRoot.Children[leafName]
	if !ok {
		// Unknown leaf — leave to existing parser/compiler; gate is opt-in.
		return nil
	}
	// Collect value tokens: trailing Keys[1:] plus any leaf child whose
	// Keys[0] is the value (hierarchical shape `transmit-rate 1g;` may
	// also appear as Keys=["transmit-rate"] with one child Keys=["1g"]).
	values := append([]string(nil), leaf.Keys[1:]...)
	for _, child := range leaf.Children {
		if len(child.Keys) > 0 {
			values = append(values, child.Keys[0])
		}
	}
	return validateValueTokens(schedName, leafName, schemaNode, values, cfg)
}

// validateValueTokens applies validators along a chain of value tokens.
// transmit-rate accepts <rate> followed optionally by `exact` — the
// chain is [<rate>, "exact"]. priority accepts a single enum value. We
// walk one token at a time; if the schemaNode is typed (ValueType !=
// ValueAny) and has a Validator, the first token is the value and the
// remainder are matched against children keywords (e.g. "exact").
func validateValueTokens(schedName, leafName string, schemaNode *Node, values []string, cfg *config.Config) error {
	cur := schemaNode
	consumedTypedValue := false
	typedLeaf := schemaNode != nil && schemaNode.IsTypedLeaf() && schemaNode.Validator != nil
	if typedLeaf && len(values) == 0 {
		return fmt.Errorf(
			"class-of-service schedulers %s %s: missing value",
			schedName, leafName)
	}
	for _, tok := range values {
		if cur == nil {
			if typedLeaf {
				return fmt.Errorf(
					"class-of-service schedulers %s %s: unknown modifier %q",
					schedName, leafName, tok)
			}
			return nil
		}
		if allowsModifierOnlyTypedLeaf(leafName, tok) && cur == schemaNode && !consumedTypedValue {
			if next, ok := cur.Children[tok]; ok {
				cur = next
				consumedTypedValue = false
				continue
			}
		}
		if cur.IsTypedLeaf() && cur.Validator != nil && !consumedTypedValue {
			if err := cur.Validator(tok, cfg); err != nil {
				return fmt.Errorf(
					"class-of-service schedulers %s %s: invalid value %q: %v",
					schedName, leafName, tok, err)
			}
			consumedTypedValue = true
			continue
		}
		// Not a typed value slot — token must be a child keyword.
		if cur.Children == nil {
			if typedLeaf {
				return fmt.Errorf(
					"class-of-service schedulers %s %s: unknown modifier %q",
					schedName, leafName, tok)
			}
			return nil
		}
		next, ok := cur.Children[tok]
		if !ok {
			if typedLeaf {
				return fmt.Errorf(
					"class-of-service schedulers %s %s: unknown modifier %q",
					schedName, leafName, tok)
			}
			// Token doesn't match a known modifier on an untyped leaf —
			// leave reporting to the existing compiler.
			return nil
		}
		cur = next
		consumedTypedValue = false
	}
	return nil
}

func allowsModifierOnlyTypedLeaf(leafName, tok string) bool {
	return leafName == "transmit-rate" && tok == "exact"
}
