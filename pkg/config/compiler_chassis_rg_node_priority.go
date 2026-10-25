package config

import (
	"fmt"
	"strconv"
	"strings"
)

// compiler_chassis_rg_node_priority.go carries the #16672 gate for a
// redundancy-group `node` statement that is not exactly
// `node <0|1> priority <1..254>`.
//
// A missing `;` fuses two statements into one node:
//
//	redundancy-group 1 { node 1 priority 100 node 0 priority 200; }
//
// The lexer has no terminator, so the second `node` and its tokens are
// absorbed onto the first node's Keys. The #8437 fused-statement gate
// exempts a same-keyword repeat (`tok == keyword { continue }`) and
// `priority` is a child of `node`, not a sibling, so neither token is
// flagged. compileRGNodePriority then took nodeID from the first
// `node` token and assigned EVERY `priority` value in the tail to it,
// last-wins: {1:200}, node 0 absent (clamped to 1 at runtime), so
// node 1 wins the RG although the operator wrote node 0 at 200. The
// reverse order keeps placement but silently changes the value.
//
// The same shape gate also refuses the V34-03 cohort cells on this
// statement: a missing priority, a missing/non-numeric priority value,
// a duplicate `priority`, and trailing tokens after the value. The
// compiled struct cannot distinguish any of these (a failed Atoi and
// an absent priority both leave no entry), and the schema walker
// consumes the packed tail as identity, so the check runs on the AST
// through redundancyGroupBody — the same splitter the compiler uses.
//
// Strictness follows the sibling chassis gates: hard-reject at commit /
// commit-check, downgrade to a cfg.Warnings entry on the tolerant load /
// peer-sync paths (#1960 no-brick). On the tolerant path the compiler
// keeps only the FIRST priority (see compileRGNodePriority), so the
// fused second statement no longer overwrites the first node's own
// priority.

// rgNodePriorityShape16672 inspects one `node` child of a redundancy
// group and returns a human-readable defect, or "" when the statement
// is exactly `node <id> priority <value>` in either spelling:
// inline Keys [node <id> priority <value>] or a `priority` child.
func rgNodePriorityShape16672(child *Node) string {
	if child == nil {
		return ""
	}
	keys := child.Keys
	// A second `node` token anywhere past the identity slot is a fused
	// statement: this node was one statement, the next opened with the
	// same keyword and the #8437 gate exempted it.
	for i := 2; i < len(keys); i++ {
		if keys[i] == "node" {
			return fmt.Sprintf("carries a second `node` statement fused onto it (%q) — "+
				"a missing `;` between two `node <n> priority <p>` statements; "+
				"split them with `;` so each node keeps its own priority", strings.Join(keys, " "))
		}
	}
	// Inline priorities: count `priority` tokens in the tail.
	priIdx := -1
	priCount := 0
	for i := 2; i < len(keys); i++ {
		if keys[i] == "priority" {
			priCount++
			if priIdx < 0 {
				priIdx = i
			}
		}
	}
	hasChildPri := child.FindChild("priority") != nil
	if priCount > 1 {
		return fmt.Sprintf("specifies `priority` %d times (%q) — specify exactly one priority", priCount, strings.Join(keys, " "))
	}
	if priCount == 1 && hasChildPri {
		return fmt.Sprintf("specifies `priority` both inline and as a block (%q) — specify exactly one priority", strings.Join(keys, " "))
	}
	if priCount == 0 && !hasChildPri {
		// No priority at all. A bare `node <id>;` / `node <id>` (Keys
		// exactly [node <id>], no children) carries no priority claim;
		// the identity gate and existing controls accept it, and a
		// missing per-node priority is already legal (the other node's
		// statement, or the runtime default, applies). Anything more
		// — extra keys or a non-priority child — is a malformed claim.
		if len(keys) <= 2 && len(child.Children) == 0 {
			return ""
		}
		return fmt.Sprintf("carries no `priority` (%q) — a redundancy-group node statement must be "+
			"`node <0|1> priority <1..254>`; add the priority or remove the statement", strings.Join(keys, " "))
	}
	if priCount == 1 {
		// Tokens before `priority` (past the identity) or after its
		// value are not part of this statement.
		if priIdx != 2 {
			return fmt.Sprintf("carries tokens before `priority` (%q) — a redundancy-group node statement must be "+
				"`node <0|1> priority <1..254>`", strings.Join(keys, " "))
		}
		if priIdx+1 >= len(keys) {
			return "carries `priority` with no value — specify `priority <1..254>`"
		}
		if _, err := strconv.Atoi(keys[priIdx+1]); err != nil {
			return fmt.Sprintf("priority %q is not an integer — specify `priority <1..254>`", keys[priIdx+1])
		}
		if len(keys) > priIdx+2 {
			return fmt.Sprintf("carries trailing tokens after the priority value (%q) — "+
				"a missing `;` may have fused the next statement; split statements with `;`", strings.Join(keys, " "))
		}
		return ""
	}
	// Block spelling only: `node <id> { priority <v>; }`. Extra inline
	// tokens past the identity are not part of the statement.
	if len(keys) > 2 {
		return fmt.Sprintf("carries tokens after the node id (%q) — a redundancy-group node statement must be "+
			"`node <0|1> priority <1..254>`", strings.Join(keys, " "))
	}
	if priNode := child.FindChild("priority"); priNode != nil {
		if v := nodeVal(priNode); v == "" {
			return "carries `priority` with no value — specify `priority <1..254>`"
		} else if _, err := strconv.Atoi(v); err != nil {
			return fmt.Sprintf("priority %q is not an integer — specify `priority <1..254>`", v)
		}
	}
	return ""
}

// rgNodeChainDefect16672 scans a `node` statement's CHILD chain for a
// fused second statement. The flat `set` path nests instead of packing:
// `... node 1 priority 100 node 0 priority 200` arrives as
// node(Keys=[node 1]) -> priority(100) -> node(Keys=[node 0 priority 200]).
// Only a descendant named `node` is fused: sibling node statements
// arrive as siblings, never in this chain, and a `priority` child
// chain (priority -> its own value node) is the normal flat shape.
func rgNodeChainDefect16672(child *Node) string {
	var walk func(ns []*Node) string
	walk = func(ns []*Node) string {
		for _, c := range ns {
			if c.Name() == "node" {
				return fmt.Sprintf("carries a second `node` statement fused beneath it (%q) — "+
					"a missing `;` between two `node <n> priority <p>` statements; "+
					"split them so each node keeps its own priority", strings.Join(c.Keys, " "))
			}
			if d := walk(c.Children); d != "" {
				return d
			}
		}
		return ""
	}
	return walk(child.Children)
}

// rgRawTailFused16672 reports a second `node` token in an RG instance's
// RAW packed tail. Split-based views hide it: clusterBodyStatements
// consumes `node` as an RG statement without reserving `priority`'s
// slots, and redundancyGroupBody then yields two clean `node` nodes,
// so the fused origin is invisible after either splitter runs. Scan
// Keys past the RG identity: exactly ONE `node <id> priority <v>`
// statement may pack there; a `node` past that statement's value
// slot is fused. The value slot is reserved so a value spelled
// `node` is not misread.
func rgRawTailFused16672(rgNode *Node) string {
	skip := 1
	if rgNode.Name() == "redundancy-group" {
		skip = 2
	}
	keys := rgNode.Keys
	if len(keys) <= skip {
		return ""
	}
	tail := keys[skip:]
	if tail[0] != "node" {
		return ""
	}
	// Statement grammar: node <id> priority <v> — `node` at index 4
	// or later (past the first statement's 4 tokens) is a second one.
	// Tokens before that are the first statement's own slots, even
	// when a slot value happens to spell `priority`.
	for i := 4; i < len(tail); i++ {
		if tail[i] == "node" {
			return fmt.Sprintf("carries a second `node` statement fused onto it (%q) — "+
				"a missing `;` between two `node <n> priority <p>` statements; "+
				"split them with `;` so each node keeps its own priority", strings.Join(keys, " "))
		}
	}
	return ""
}

// validateRGNodePriorityShapeAST walks the chassis cluster subtree and
// reports every redundancy-group `node` statement that is not exactly
// `node <id> priority <value>` (#16672). It reads statements through
// redundancyGroupBody, the same splitter compileChassis dispatches
// from, so packed and container spellings are judged identically.
//
// Returns (warnings, nil) when lenient, (nil, error) on the first
// offender when strict.
func validateRGNodePriorityShapeAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(rgName string, child *Node, defect string) error {
		msg := fmt.Sprintf("chassis cluster redundancy-group %s node: %s (#16672) — "+
			"the second priority would otherwise be written onto the first node, "+
			"inverting redundancy-group primary placement", rgName, defect)
		// child is unused beyond future location context; keep signature
		// explicit so call sites read as statement-scoped.
		_ = child
		if lenient {
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	// Walk via normalizedClusterNode so the `chassis cluster { }`
	// packed spellings the compiler accepts are judged too — mirroring
	// validateChassisClusterUnknownAST16456, whose walk already
	// resolves the cluster body the compiler's way. The identity and
	// monitor gates walk raw `chassis { cluster { } }` children and
	// miss that spelling; this gate must not.
	for _, n := range nodes {
		if n == nil || n.Name() != "chassis" {
			continue
		}
		cluster := normalizedClusterNode(n)
		if cluster == nil {
			continue
		}
		for _, stmt := range cluster.Children {
			if stmt == nil || stmt.Name() != "redundancy-group" {
				continue
			}
			for _, rgInst := range namedInstances([]*Node{stmt}) {
				if defect := rgRawTailFused16672(rgInst.node); defect != "" {
					if err := emit(rgInst.name, rgInst.node, defect); err != nil {
						return nil, err
					}
					continue
				}
				for _, child := range redundancyGroupBody(rgInst.node) {
					if child.Name() != "node" {
						continue
					}
					defect := rgNodePriorityShape16672(child)
					if defect == "" {
						defect = rgNodeChainDefect16672(child)
					}
					if defect != "" {
						if err := emit(rgInst.name, child, defect); err != nil {
							return nil, err
						}
					}
				}
			}
		}
	}
	return warnings, nil
}
