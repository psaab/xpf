package config

import (
	"fmt"
	"strconv"
)

// compiler_chassis_identity.go carries the #5694 (codex-182 M15) reject-at-
// commit gate for MALFORMED chassis-cluster REDUNDANCY-GROUP and per-RG NODE
// identities.
//
// compileChassis (compiler_system.go) parses each identity with strconv.Atoi
// and, on parse FAILURE, LEAVES the field at its zero default rather than
// erroring:
//
//   - `redundancy-group <name>`: `rgID := 0; if n, err := Atoi(name); err ==
//     nil { rgID = n }` — a non-numeric name (a typo like `redundancy-group
//     reth0`) skips the assignment and the group is built with ID 0, ALIASING a
//     valid redundancy-group 0.
//   - the RG-scoped `node <id> priority <v>`: same Atoi-then-default pattern,
//     so a malformed node token assigns the priority to node 0, overriding
//     node 0's real priority.
//
// A malformed identity therefore silently mis-assigns cluster OWNERSHIP /
// priority instead of being rejected. (A negative numeric token is the one
// exception to "defaults to 0": Atoi accepts it, so compileChassis keeps the
// negative id; see validID below and #9723.) This is DISTINCT from the sibling
// validateChassisClusterStrict (compiler_validate_strict_chassis.go), which
// gates the COMPILED int (RG count, RG id range 0..255, node-priority range) —
// by the time that runs the malformed token has already collapsed to 0, which
// passes its range check (0 is valid). Only the RAW AST still distinguishes a
// malformed token from a real 0, so this gate is an AST pre-walk (mirrors
// validateApplicationNameCollisionsAST and the other reject-at-commit AST
// gates in runPreWalkGates).
//
// SCOPE: only the two INSTANCE-NAME identity slots the schema explicitly leaves
// unvalidated (schema_chassis.go: "Instance-name slots (redundancy-group <id>,
// the RG-scoped node <id>) are NOT value slots ... typing them needs a new
// walker feature (deferred)"). The TOP-LEVEL `chassis cluster node <id>` is a
// typed value leaf (ValidateInteger(0, 1)) already rejected by SchemaValidate,
// so it is intentionally not re-checked here.
//
// Strict path (commit / commit-check, lenient=false): the first malformed
// identity is a hard compile error naming the offending token. Lenient path
// (load / peer-sync, lenient=true): every malformed identity is a warning and
// compilation continues with the existing zero-coercion, so an already-
// persisted or peer-synced config an older binary silently accepted still
// BOOTS (#1960 fail-closed-on-load doctrine). compileChassis is unchanged — the
// lenient path deliberately keeps producing the (arbitrary but stable) zero
// coercion it always did.

// validateChassisClusterIdentitiesAST walks the chassis cluster subtree and
// rejects (strict) or warns (lenient) a redundancy-group or per-RG node
// identity whose raw token is not a well-formed non-negative integer. See the
// file-level comment for the doctrine.
func validateChassisClusterIdentitiesAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(what, token string) error {
		msg := fmt.Sprintf(
			"chassis cluster %s %q is not a valid non-negative integer id; a "+
				"malformed identity silently defaults to 0 and aliases "+
				"redundancy-group / node 0, mis-assigning cluster ownership — use "+
				"a numeric id (#5694)", what, token)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}
	// validID accepts what compileChassis reads as a usable id: a token Atoi
	// parses to a non-negative integer. A non-numeric or empty token collapses
	// to the zero default and aliases id 0. A NEGATIVE numeric token does not
	// collapse: Atoi succeeds, so compileChassis keeps the negative value
	// (#9723). For a redundancy group that value saturates to heartbeat wire
	// byte 0 and aliases RG0 anyway, so the tolerant path drops it
	// (dropNegativeRedundancyGroups); a negative RG-scoped node token is kept as
	// a priority for a node that does not exist.
	validID := func(tok string) bool {
		n, err := strconv.Atoi(tok)
		return err == nil && n >= 0
	}
	walkErr := forEachChild(nodes, "chassis", func(chassis *Node) error {
		return forEachChild(chassis.Children, "cluster", func(cluster *Node) error {
			for _, rgInst := range namedInstances(cluster.FindChildren("redundancy-group")) {
				if !validID(rgInst.name) {
					if err := emit("redundancy-group", rgInst.name); err != nil {
						return err
					}
				}
				// The RG-scoped `node <id>` identity (nested `node { ... }` or
				// the packed one-liner `node 0 priority <v>`; compileChassis
				// reads both via nodeVal(child) on a `node` CHILD).
				// #6588: the body may be packed onto the RG instance's own Keys.
				for _, child := range redundancyGroupBody(rgInst.node) {
					if child.Name() != "node" {
						continue
					}
					if v := nodeVal(child); v != "" && !validID(v) {
						if err := emit("redundancy-group node", v); err != nil {
							return err
						}
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}
