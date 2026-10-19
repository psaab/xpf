package config

import (
	"fmt"
	"strings"
)

// #14981: `groups` / `apply-groups` inheritance bypassed deny-configuration
// in Set, Load, and Commit.
//
// The per-line gates adjudicated the literal spelling the caller typed:
// `set groups G system root-authentication …` was judged as a path under
// `groups`, and `set apply-groups G` as a path under `apply-groups`. Neither
// string is the configuration that takes effect; group expansion at compile
// time materializes the group's body at the apply site (including <*>
// wildcard fan-out, nested groups, and ${node} selection), so a class denied
// `system root-authentication` could plant that exact leaf inside a group,
// apply the group, and commit it on every surface. Load had the same hole in
// hierarchical and flat form, and Commit had it transitively: its
// long-standing justification ("every path in the candidate was adjudicated
// when it was written") was false for inherited paths, which were never
// written as adjudicated lines at all.
//
// The fix adjudicates the EFFECTIVE (group-expanded) paths in addition to
// the literal line. The helpers below are the one mechanism every surface
// shares, beside the existing AuthorizeConfigMutation decision:
//
//   - ExpandedMutationLines renders a candidate tree (or a load body parsed
//     into one) with groups expanded, as the flat set lines the compiler
//     will act on. Expansion failures fail closed: an unexpandable body
//     cannot be adjudicated, so it must not be allowed through as zero
//     mutations.
//   - AuthorizeExpandedTree adjudicates every expanded line for a class.
//   - AuthorizeConfigMutationExpanded / AuthorizeConfigLoad (existing) route
//     single lines and load bodies through it whenever the literal spelling
//     involves `groups` or `apply-groups`.
//
// Scoping the extra work to lines that mention groups/apply-groups keeps
// the common path byte-identical: a mutation that cannot create or trigger
// inheritance is adjudicated exactly as before.

// treeHasGroupStanzas14981 reports whether a tree carries any `groups` or
// `apply-groups` statement the expansion could act on. It scans key
// positions, not only statement heads, because a packed leaf
// (`set groups G system host-name x`) carries the keyword in its Keys.
func treeHasGroupStanzas14981(t *ConfigTree) bool {
	if t == nil {
		return false
	}
	var walk func(nodes []*Node) bool
	walk = func(nodes []*Node) bool {
		for _, n := range nodes {
			if n == nil {
				continue
			}
			for _, k := range n.Keys {
				if k == "groups" || k == "apply-groups" {
					return true
				}
			}
			if walk(n.Children) {
				return true
			}
		}
		return false
	}
	return walk(t.Children)
}

// ExpandedMutationLines returns the effective set lines a tree produces
// once groups are expanded (both ${node} views for cluster configs), or an
// error when expansion fails. Callers adjudicating for authorization MUST
// refuse on that error: adjudicating an unexpandable tree as zero mutations
// is a fail-open.
//
// The tree is cloned (with inactive subtrees stripped, mirroring the
// compiler) before expansion, so the caller's tree is never mutated.
func ExpandedMutationLines(t *ConfigTree) ([]string, error) {
	if t == nil || !treeHasGroupStanzas14981(t) {
		return nil, nil
	}
	var lines []string
	seen := make(map[string]bool)
	for _, vars := range []map[string]string{nil, {"node": "node0"}, {"node": "node1"}} {
		clone := t.cloneForExpansion()
		normalizeCompactStanzas(clone)
		var err error
		if vars == nil {
			err = clone.ExpandGroups()
		} else {
			err = clone.ExpandGroupsWithVars(vars)
		}
		if err != nil {
			// A ${node} view that references an undefined node group errors
			// exactly as the node-aware compile does; that view contributes
			// nothing on this node, but the other views still adjudicate.
			// Only a failure on the plain (no-vars) view is fatal: it means
			// the authored inheritance itself cannot be resolved.
			if vars == nil {
				return nil, err
			}
			continue
		}
		for _, line := range strings.Split(clone.FormatSet(), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || seen[line] {
				continue
			}
			seen[line] = true
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// denyConfigurationMatches14981 reports whether the class's deny pattern
// matches path (POSIX, unanchored — the matcher's own semantics), used to
// decide whether a `groups …` definition spelling is itself a denied
// mutation path. The deny rule here is the operator-authored pattern, not
// a substring guess.
func denyConfigurationMatches14981(cfg *Config, class, path string) bool {
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil || !ok {
		return false
	}
	return !rules.Evaluate(path).Allowed
}

// authorizeConfigLoadExpansion14981 adjudicates the group-expanded paths a
// load body produces. It re-parses the body exactly as LoadMutationLines
// rendered it (flat lines replayed into a tree, hierarchical text parsed
// directly), expands groups, and checks every effective line. Bodies
// without group stanzas return immediately.
func authorizeConfigLoadExpansion14981(cfg *Config, class, content string) error {
	flat, uncommented, err := ClassifyLoadContent(content)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
			"the load content cannot be classified for group adjudication: %w", class, err)
	}
	var tree *ConfigTree
	if flat {
		tree = &ConfigTree{}
		for _, raw := range strings.Split(uncommented, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !IsFlatLoadLine(line) {
				continue
			}
			// Replay through the same edit-line semantics the store uses:
			// a set/delete/deactivate/activate line mutates the tree the
			// expansion will read. Parse errors are the store's to report;
			// a line that cannot be replayed contributes nothing here and
			// the store refuses the load.
			verb, path, quoted, grouped, closed, perr := ParseSetVerbGroupedClosed(line)
			if perr != nil {
				continue
			}
			switch verb {
			case "delete":
				_ = tree.DeletePathGrouped(path, grouped)
			case "deactivate":
				_ = tree.DeactivatePathGrouped(path, grouped)
			case "activate":
				_ = tree.ActivatePathGrouped(path, grouped)
			default:
				_ = tree.SetPathQuotedGrouped(path, quoted, grouped, closed)
			}
		}
	} else {
		parsed, _ := NewParser(uncommented).Parse()
		if parsed == nil {
			return nil
		}
		tree = parsed
	}
	return AuthorizeExpandedTree(cfg, class, tree)
}

// AuthorizeExpandedTree adjudicates every group-expanded line of tree
// against class's *-configuration regexes. A tree without group stanzas is
// trivially permitted here; the literal lines that authored it are
// adjudicated by AuthorizeConfigMutation as before.
func AuthorizeExpandedTree(cfg *Config, class string, tree *ConfigTree) error {
	return authorizeExpandedTree14981(cfg, class, tree, nil)
}

// AuthorizeExpandedCandidate adjudicates a candidate's group-expanded
// lines for a commit by class, considering only lines that differ from
// the active tree (#14981). A commit promotes the difference between
// active and candidate; a line already active — most importantly the
// class's own deny-configuration definition, whose value names the
// denied subtree — is not a mutation this commit performs, and writing
// it was already adjudicated by the per-line gate. Without a usable
// active tree it behaves exactly like AuthorizeExpandedTree.
func AuthorizeExpandedCandidate(cfg *Config, class string, candidate, active *ConfigTree) error {
	return authorizeExpandedTree14981(cfg, class, candidate, active)
}

func authorizeExpandedTree14981(cfg *Config, class string, tree, active *ConfigTree) error {
	if class == "" || tree == nil {
		return nil
	}
	_, restricted, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !restricted {
		return nil
	}
	lines, err := ExpandedMutationLines(tree)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
			"the group expansion cannot be resolved for adjudication: %w", class, err)
	}
	var activeSet map[string]bool
	if active != nil {
		activeSet = make(map[string]bool)
		if activeLines, aerr := ExpandedMutationLines(active); aerr == nil {
			for _, l := range activeLines {
				activeSet[l] = true
			}
		}
		for _, l := range strings.Split(active.FormatSet(), "\n") {
			activeSet[strings.TrimSpace(l)] = true
		}
	}
	for _, line := range lines {
		if activeSet[line] {
			continue
		}
		// A `groups <name> …` line is a definition spelling, not an
		// effective path. Skip it UNLESS the class's rules deny the
		// definition path itself — e.g. an unanchored deny on
		// `system root-authentication` denies
		// `groups G system root-authentication …` exactly as the
		// per-line gate did when the definition was written. Evaluating
		// it through AuthorizeConfigMutation in that case preserves the
		// per-line verdict; skipping it otherwise keeps a merely-defined
		// (never applied) group from being treated as effective config.
		if expandedLineIsGroupDefinition14981(line) {
			if fields := strings.Fields(line); len(fields) >= 3 {
				if !denyConfigurationMatches14981(cfg, class, strings.Join(fields[3:], " ")) &&
					!denyConfigurationMatches14981(cfg, class, strings.Join(fields[1:], " ")) {
					continue
				}
			} else {
				continue
			}
		}
		if err := AuthorizeConfigMutation(cfg, class, nil, line); err != nil {
			return err
		}
	}
	return nil
}

// expandedLineIsGroupDefinition14981 reports whether an expanded set line
// is a `groups <name> …` definition spelling rather than an effective
// path. Expansion strips applied groups and materializes their bodies at
// the apply sites, so a surviving `groups …` line can only be an
// unapplied definition (or a node-view artifact), never effective config.
func expandedLineIsGroupDefinition14981(line string) bool {
	fields := strings.Fields(line)
	return len(fields) >= 2 && fields[1] == "groups"
}

// lineTouchesGroups14981 reports whether a config-mode line's mutation path
// involves `groups` or `apply-groups` — i.e. whether it can create a group
// body or trigger inheritance, so its effective expanded paths must also be
// adjudicated. It inspects the lexed mutation paths (edit-path resolved),
// so navigation and unrelated leaves that merely carry the word as data are
// not swept in.
func lineTouchesGroups14981(editPath []string, line string) bool {
	parts, quoted := lexConfigMutationLine9938(line)
	editPath, parts, quoted = normalizeEditPath14716(editPath, parts, quoted)
	paths, gated := configMutationPaths(editPath, parts, quoted)
	if !gated {
		return false
	}
	for _, p := range paths {
		for _, tok := range strings.Fields(p) {
			if tok == "groups" || tok == "apply-groups" {
				return true
			}
		}
	}
	return false
}

// LineTouchesGroups14981 is lineTouchesGroups14981 with no edit cursor, for
// cross-package gates that adjudicate an already-resolved line.
func LineTouchesGroups14981(line string) bool { return lineTouchesGroups14981(nil, line) }
