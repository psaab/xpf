package config

import (
	"fmt"
	"strconv"
)

// compiler_chassis_identity.go carries the #5694 (codex-182 M15) reject-at-
// commit gate for MALFORMED chassis-cluster REDUNDANCY-GROUP and per-RG NODE
// identities.
//
// compileChassis (compiler_system.go) parses each identity with strconv.Atoi:
//
//   - `redundancy-group <name>`: a non-numeric or explicitly empty name (a typo
//     like `redundancy-group reth0`) is reported by this gate and DROPPED on
//     the tolerant path, rather than being assigned the old zero default and
//     ALIASING a valid redundancy-group 0.
//   - the RG-scoped `node <id> priority <v>`: a non-numeric or explicitly empty
//     node token is reported by this gate and contributes NO priority on the
//     tolerant path, rather than assigning that priority to node 0 and
//     overriding node 0's real priority.
//
// A malformed identity used to silently mis-assign cluster OWNERSHIP /
// priority instead of being rejected. (A negative numeric token is accepted by
// Atoi and remains negative; the tolerant path drops a negative RG through
// dropNegativeRedundancyGroups, while a negative node token remains a negative
// priority as before. This issue's drop covers Atoi failures, including
// explicitly empty tokens.) This is DISTINCT from the sibling
// validateChassisClusterStrict
// (compiler_validate_strict_chassis.go), which gates the COMPILED int (RG
// count, RG id range 0..255, node-priority range). Only the RAW AST
// distinguishes a malformed token from a real 0, so this gate is an AST
// pre-walk (mirrors validateApplicationNameCollisionsAST and the other
// reject-at-commit AST gates in runPreWalkGates).
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
// (load / peer-sync, lenient=true): malformed identities are warnings and
// compilation continues. A non-numeric or explicitly empty RG identity is
// dropped by compileChassis; a non-numeric or explicitly empty per-RG node
// identity is ignored by compileRGNodePriority before either can alias RG/node
// 0. Negative RG/node identities follow the existing handling described above.
// An already-persisted or peer-synced config an older binary silently accepted
// still BOOTS (#1960 fail-closed-on-load doctrine), while the invalid
// non-numeric/empty identity has no effect on valid records around it.
// validateChassisClusterIdentitiesAST walks the chassis cluster subtree and
// rejects (strict) or warns (lenient) a redundancy-group or per-RG node
// identity whose raw token is not a well-formed non-negative integer,
// including an explicitly quoted-empty token. See the file-level comment for
// the doctrine.
func validateChassisClusterIdentitiesAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(what, token string) error {
		msg := fmt.Sprintf(
			"chassis cluster %s %q is not a valid non-negative integer id; use "+
				"a numeric id (#5694)", what, token)
		if lenient {
			if _, err := strconv.Atoi(token); err != nil {
				action := "this malformed identity is ignored"
				switch what {
				case "redundancy-group":
					action = "this malformed redundancy-group instance is dropped"
				case "redundancy-group node":
					action = "this malformed redundancy-group node statement is ignored"
				}
				msg = fmt.Sprintf(
					"chassis cluster %s %q is not a valid non-negative integer id; on "+
						"the tolerant path %s instead of silently defaulting to 0 and "+
						"aliasing redundancy-group / node 0, mis-assigning cluster "+
						"ownership — use a numeric id (#5694)",
					what, token, action)
			}
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	// validID accepts what the identity readers can use as an id: a token Atoi
	// parses to a non-negative integer. A non-numeric or explicitly empty token
	// is reported here and dropped by compileChassis /
	// compileRGNodePriority instead of being allowed to alias id 0. A NEGATIVE
	// numeric token does not collapse: Atoi succeeds, so compileChassis keeps
	// the negative value (#9723). For a redundancy group that value saturates
	// to heartbeat wire byte 0 and aliases RG0 anyway, so the tolerant path
	// drops it (dropNegativeRedundancyGroups); a negative RG-scoped node token
	// is kept as a priority for a node that does not exist, as before.
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
					v := nodeVal(child)
					// A quoted-empty identity is a real second key whose
					// text is empty; do not confuse it with a node shape that
					// has no identity slot at all.
					if (v == "" && len(child.Keys) >= 2) ||
						(v != "" && !validID(v)) {
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
