package config

import "fmt"

// security_policy_walk.go is the single shared enumeration of every
// security policy in the group-expanded AST, used by all eight strict
// policy gates (#17161, finding R4-Q50-06).
//
// Before #17161 each gate in compiler_policy_match.go,
// compiler_policy_missing_match.go and compiler_policy_then.go pasted its
// own copy of the security -> policies -> global / from-zone pair walk
// (a local `type zonePair struct` plus the pair enumeration). The #3562
// every-root iteration and the #12782 keyed-context arm
// (`len(tzNode.Keys) >= 2`) had to be patched into every copy in lockstep,
// and the #12782 regression test pinned the keyed arm for only four of the
// eight gates: deleting it in any other copy let a keyed
// `from-zone { A { to-zone B { ... } } }` policy carrying the gated
// construct commit silently while every test stayed green — a fail-open
// in gates that exist precisely to stop silently-dropped constructs.
//
// forEachSecurityPolicy carries that walk exactly once. The gates pass
// only their per-policy check; a future AST shape fix lands here and
// reaches every gate. The walk preserves the invariants the copies shared:
//
//   - #3562: EVERY top-level `security` node and EVERY `policies` sibling
//     is iterated (forEachChild), not the first match at any level —
//     parseStatements appends a repeated top-level block instead of
//     merging it, and compileExpanded compiles every `security` root, so a
//     first-only walk would let an offending policy in a duplicate block
//     bypass the gate while the compiler still compiled it.
//   - Both scopes: `global` policies (isGlobal=true, scope "global") and
//     zone-pair policies (isGlobal=false, scope
//     "from-zone <from> to-zone <to>").
//   - compilePolicies' two zone-pair AST shapes (compiler_security_policy.go):
//     the hierarchical combined spelling
//     (Keys=["from-zone","trust","to-zone","untrust"], policies are
//     children of the from-zone node itself) and the flat/nested spelling
//     (from-zone -> <name> -> to-zone -> ...), including the #12782 keyed
//     destination: a `to-zone` node with Keys >= 2 carries the pair body
//     itself and its key is the destination zone; only a keyless `to-zone`
//     node enumerates its children as destination-named containers. This
//     keeps gate pairs a superset of the pairs compilePolicies compiles.
//
// fn receives the human-readable scope the gates embed in their messages,
// the policy name, the policy node, and whether the policy is global. The
// first non-nil error from fn aborts the walk and is returned verbatim, so
// each gate's strict-first-error / lenient-collect doctrine stays with the
// gate, not the walker.
func forEachSecurityPolicy(nodes []*Node, fn func(scope, name string, pol *Node, isGlobal bool) error) error {
	return forEachChild(nodes, "security", func(security *Node) error {
		return forEachChild(security.Children, "policies", func(policies *Node) error {
			for _, child := range policies.Children {
				switch child.Name() {
				case "global":
					for _, polInst := range namedInstances(child.FindChildren("policy")) {
						if err := fn("global", polInst.name, polInst.node, true); err != nil {
							return err
						}
					}
				case "from-zone":
					// Mirror compilePolicies' two AST shapes.
					type zonePair struct {
						from, to   string
						policyNode *Node
					}
					var pairs []zonePair
					if len(child.Keys) >= 4 {
						// Hierarchical: Keys=["from-zone","trust","to-zone","untrust"]
						pairs = append(pairs, zonePair{child.Keys[1], child.Keys[3], child})
					} else {
						// Flat set: from-zone → <name> → to-zone → <name> → policy ...
						for _, fzSub := range child.Children {
							// Iterate every to-zone sibling so each compiled
							// pair is validated. The keyed destination
							// (#12782) carries the pair body itself; only a
							// keyless to-zone enumerates child containers.
							for _, tzNode := range fzSub.FindChildren("to-zone") {
								if len(tzNode.Keys) >= 2 {
									pairs = append(pairs, zonePair{fzSub.Name(), tzNode.Keys[1], tzNode})
									continue
								}
								for _, tzSub := range tzNode.Children {
									pairs = append(pairs, zonePair{fzSub.Name(), tzSub.Name(), tzSub})
								}
							}
						}
					}
					for _, zp := range pairs {
						scope := fmt.Sprintf("from-zone %s to-zone %s", zp.from, zp.to)
						for _, polInst := range namedInstances(zp.policyNode.FindChildren("policy")) {
							if err := fn(scope, polInst.name, polInst.node, false); err != nil {
								return err
							}
						}
					}
				}
			}
			return nil
		})
	})
}
