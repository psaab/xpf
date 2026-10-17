package config

import (
	"fmt"
	"strings"
)

// compiler_validate_duplicate_scalar.go carries the #14448 (DR20-H2)
// duplicate-singleton-scalar gate for `system services web-management
// api-auth` class / expires leaves.
//
// Mechanism: the api-auth reader in compileSystem read `class` and
// `expires` with FindChild (first sibling wins) at six sites — default,
// per-user, and per-key. A config carrying
// `class super-user; class read-only;` therefore installed the
// permissive super-user class (PermAll via ResolveClassPermissions for
// every credential inheriting the default), and
// `expires 2099-01-01; expires 2020-01-01;` installed the far-future
// expiry, so a credential the config revokes stayed valid
// (daemon_run_servers.go addCredential checks now.Before(expires)).
// validateWebManagementAuthStrict reads only the COMPILED config and
// cannot see the dropped second value, so no compiled-config gate can
// catch this — the check must run on the AST.
//
// Doctrine (mirrors #5180 / #6455 duplicate gates): strict commit
// rejects a conflicting duplicate naming the scope, leaf, and both
// values; the tolerant load / peer-sync path warns and keeps the
// reader's (now Junos last-wins) result so an already-persisted config
// still boots (#1960 no-brick). Identical repeats are not conflicts.
//
// Scope is strictly class / expires: password / secret duplicates in
// the same block are a different (MEDIUM, rotation-failure) mechanism
// and the api-key multi-value accumulation is unchanged.
//
// The gate runs PRE-expansion on the inactive-pruned clone, walking
// every system -> services -> web-management -> api-auth node with
// forEachChild at each level (a duplicate split across two sibling
// api-auth / web-management / services / system blocks is therefore
// also caught, matching how compileSections pools repeated top-level
// stanzas). The reader applies no packed-run expansion, so the gate
// counts raw siblings only.
func validateAPIAuthDuplicateScalarAST(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	var conflicts []string
	add := func(scope, leaf string, values []string) {
		distinct := distinctNonEmptyAPIAuthValues(values)
		if len(distinct) < 2 {
			return
		}
		conflicts = append(conflicts, fmt.Sprintf(
			"system services web-management api-auth %s: conflicting duplicate %q values %q and %q — "+
				"a single-valued api-auth leaf may be set only once; the later value is the "+
				"restriction the config authors, so keeping the first silently installs the "+
				"permissive class / stale expiry (#14448)",
			scope, leaf, distinct[0], distinct[len(distinct)-1]))
	}

	_ = forEachChild(tree.Children, "system", func(systemNode *Node) error {
		return forEachChild(systemNode.Children, "services", func(svcNode *Node) error {
			return forEachChild(svcNode.Children, "web-management", func(wmNode *Node) error {
				return forEachChild(wmNode.Children, "api-auth", func(authNode *Node) error {
					add("default", "class", apiAuthLeafValues(authNode, "class"))
					add("default", "expires", apiAuthLeafValues(authNode, "expires"))
					for _, inst := range namedInstances(authNode.FindChildren("user")) {
						scope := fmt.Sprintf("user %q", inst.name)
						add(scope, "class", apiAuthLeafValues(inst.node, "class"))
						add(scope, "expires", apiAuthLeafValues(inst.node, "expires"))
					}
					for _, inst := range namedInstances(authNode.FindChildren("key")) {
						scope := fmt.Sprintf("key %q", inst.name)
						add(scope, "class", apiAuthLeafValues(inst.node, "class"))
						add(scope, "expires", apiAuthLeafValues(inst.node, "expires"))
					}
					return nil
				})
			})
		})
	})

	if len(conflicts) == 0 {
		return nil, nil
	}
	if !lenient {
		return nil, fmt.Errorf("%s", conflicts[0])
	}
	warnings := make([]string, 0, len(conflicts))
	for _, c := range conflicts {
		warnings = append(warnings, c+" (downgraded to warning on tolerant path; last value wins)")
	}
	return warnings, nil
}

// apiAuthLeafValues returns the authored values of every `leaf` sibling
// on node, in authored order. Empty class values are skipped, mirroring
// the reader's nodeVal(...) != "" guard (an empty class never installs).
func apiAuthLeafValues(node *Node, leaf string) []string {
	if node == nil {
		return nil
	}
	var values []string
	for _, ch := range node.FindChildren(leaf) {
		v := nodeVal(ch)
		if v == "" {
			continue
		}
		values = append(values, v)
	}
	return values
}

func distinctNonEmptyAPIAuthValues(values []string) []string {
	var distinct []string
	seen := map[string]bool{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		distinct = append(distinct, v)
	}
	return distinct
}

// lastAPIAuthClass returns the last non-empty `class` sibling value on
// node, or "" when no class sibling carries a value (the caller then
// keeps its inherited/default class). Junos last-wins counterpart of
// the pre-#14448 FindChild first-wins read.
func lastAPIAuthClass(node *Node) string {
	class := ""
	for _, ch := range node.FindChildren("class") {
		if v := nodeVal(ch); v != "" {
			class = v
		}
	}
	return class
}

// lastAPIAuthExpires returns the last `expires` sibling value on node
// parsed with ParseAPIAuthExpiry, reporting whether any expires sibling
// was present. The caller keeps its inherited/default expiry when no
// sibling is present. Parse errors keep the pre-#14448 behaviour
// (zero-value result of the ignored error is only installed when a
// sibling exists, exactly as the FindChild read did).
func lastAPIAuthExpires(node *Node) (string, bool) {
	raw, present := "", false
	for _, ch := range node.FindChildren("expires") {
		raw, present = nodeVal(ch), true
	}
	return raw, present
}
