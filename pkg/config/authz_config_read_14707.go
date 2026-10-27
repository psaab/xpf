package config

import (
	"fmt"
	"strings"
)

// #14707: configuration READS were never adjudicated against the
// *-configuration regexes or the path/format-scoped *-commands regexes.
//
// ShowConfig / ShowCompare / ShowRollback (and their REST twins) rendered
// the full secret-redacted tree for any class the coarse permission bits
// admitted. deny-configuration "^security" denied `set security …` on
// every surface yet concealed nothing on read, and deny-commands
// "^show configuration security" or "display set" never fired because
// the gRPC gate flattened the RPC to the bare "show configuration".
// #14144 fixed Complete by reference to what "ShowConfig/Set conceal" —
// ShowConfig did not, in fact, conceal it. This file is the shared read
// decision so gRPC and REST cannot drift on it.
//
// Semantics, deliberately mirroring the surfaces operators already know:
//
//   - An explicit subtree path is adjudicated exactly as the CLI
//     adjudicates `show configuration <path>`: the configuration regexes
//     on the joined path (the same string checkConfigRegex /
//     AuthorizeConfigMutation evaluate, minus the verb) AND the
//     operational regexes on "show configuration <path>" with the bare
//     "show configuration" as an alternate form (EvaluateForms), so an
//     anchored `^show configuration$` still covers sub-paths and a
//     path-scoped `^show configuration security` fires.
//   - #15995: a subtree render discloses every descendant of the
//     requested path, so the path verdict alone is not the render's
//     price. AuthorizeConfigShowPathRendered (and the tree-aware
//     wrappers the surfaces call) additionally adjudicate every
//     rendered descendant path of the tree(s) that will actually be
//     rendered: a strict descendant the *-configuration pair denies —
//     or an allow-configuration allowlist does not cover — refuses the
//     ancestor read, exactly as the whole-tree refusal below refuses
//     what cannot be enumerated. The operational pair is NOT charged
//     per descendant: `show configuration security` is one command,
//     and a `^show configuration security ipsec$` deny is a command
//     spelling the operator never typed (mirroring whole-tree, where
//     a path-scoped operational deny does not refuse). A class with
//     no configuration regexes pays no tree walk.
//   - A whole-tree render, a candidate diff, and a rollback render have
//     no single path: like AuthorizeConfigLoad's override arm and
//     AuthorizeConfigRollback, they are REFUSED for a class with
//     configuration regexes, because the subtrees they would disclose
//     cannot be enumerated from the request. For the operational pair
//     the whole render is the bare `show configuration` command; a
//     path-scoped deny does not refuse it, a bare deny does.
//   - A class with no regexes in a family is untouched by that family.
//     An invalid regex denies (fail closed, as every sibling gate).
//   - Format is part of the operational command: `| display set` (and
//     json/xml/inheritance) reformats what a deny may withhold, exactly
//     as the CLI counts the pipe as part of the command (#7172). The
//     hierarchical form carries no suffix.

// AuthorizeConfigShowPath adjudicates an explicit `show configuration
// <path>` subtree read WITHOUT the rendered trees: only the requested
// path is priced. Prefer AuthorizeConfigShowPathRendered wherever the
// rendered tree is available — this form cannot see denied strict
// descendants below path (#15995) and remains only for callers that
// have already priced the descendants (AuthorizeConfigPathOnly's CLI
// arm, whose operational pair was charged on the full command line).
// displaySuffix is "display set" / "display json" / "display xml" /
// "display inheritance", or "" for the hierarchical form.
// #15994: group content is effective config. Group bodies are authored
// under the literal `groups <name> ...` definition spelling, so the
// joined-path evaluation alone never sees the `security ...` subtree
// the body materializes — and the scoped renders disclose it.
// readSpellings15994 returns every spelling the read gate prices:
// the authored (definition) path followed by the effective path it
// materializes, recursively unwrapping nested `groups <name>`
// containers. Ancestor spellings `groups` / `groups <name>` carry
// only the definition spelling here; the descendant walk admits
// those only when the class's rules admit every effective path the
// render actually contains (see authorizeConfigRenderedDescendants).
func readSpellings15994(path []string) [][]string {
	out := [][]string{append([]string(nil), path...)}
	if len(path) >= 2 && path[0] == "groups" {
		for _, sub := range readSpellings15994(path[2:]) {
			out = append(out, sub)
		}
	}
	return out
}

func AuthorizeConfigShowPath(cfg *Config, class string, path []string, displaySuffix string) error {
	if class == "" {
		return nil
	}
	for _, spelling := range readSpellings15994(path) {
		if len(spelling) == 0 {
			continue
		}
		joined := strings.Join(spelling, " ")
		if err := authorizeConfigReadPath(cfg, class, joined); err != nil {
			return err
		}
		if err := authorizeShowCommandReadSpelling(cfg, class, spelling, displaySuffix); err != nil {
			return err
		}
	}
	return nil
}

func authorizeShowCommandReadSpelling(cfg *Config, class string, spelling []string, displaySuffix string) error {
	if len(spelling) == 0 {
		return nil
	}
	return authorizeShowCommand(cfg, class, "show configuration "+strings.Join(spelling, " "), displaySuffix)
}

// AuthorizeConfigShowPathRendered adjudicates an explicit subtree read
// against every path the render will disclose: the requested path plus
// every descendant path present in trees (the tree(s) the handler will
// render — active/candidate for ShowConfig, both compare arms for a
// scoped compare, the rollback slot for a scoped rollback). A strict
// descendant denied by the *-configuration pair (deny match, or outside
// an allow-configuration allowlist) refuses the whole ancestor read;
// filtering the denied subtree out of the render instead would silently
// present a partial tree as the requested subtree. Nil trees are
// skipped (a missing candidate renders nothing). The operational pair
// is charged once, on the requested command, as in
// AuthorizeConfigShowPath.
//
// trees must be the EFFECTIVE trees the handler renders. For the
// `display inheritance` format that is the apply-groups-expanded tree
// (see AuthorizeExpandedConfigShowPathRendered / the store's
// *Expanded trees accessors): pricing the raw tree would miss denied
// descendants an applied group materializes at the requested path.
func AuthorizeConfigShowPathRendered(cfg *Config, class string, path []string, displaySuffix string, trees ...*ConfigTree) error {
	if class == "" {
		return nil
	}
	if err := AuthorizeConfigShowPath(cfg, class, path, displaySuffix); err != nil {
		return err
	}
	if err := authorizeRenderedDescendantsGroups(cfg, class, path, trees); err != nil {
		return err
	}
	return authorizeOpDescendantsGroups(cfg, class, path, displaySuffix, trees)
}

// AuthorizeExpandedConfigShowPathRendered is AuthorizeConfigShowPathRendered
// for a `display inheritance` read: each raw tree is first expanded
// exactly as the renderer expands it (expandForInheritance: inactive
// stripped, compact stanzas normalized, apply-groups resolved for
// nodeID), and the rendered descendants are priced on the expanded
// tree. An expansion failure refuses the read — the renderer would
// surface it as an error and render nothing, and adjudicating the
// unexpanded tree instead could admit what the expanded render would
// disclose on a retry with a fixed group. nodeID is the rendering
// store's cluster identity (negative = standalone/node0 view).
func AuthorizeExpandedConfigShowPathRendered(cfg *Config, class string, path []string, displaySuffix string, nodeID int, trees ...*ConfigTree) error {
	if class == "" {
		return nil
	}
	if err := AuthorizeConfigShowPath(cfg, class, path, displaySuffix); err != nil {
		return err
	}
	// Fold2-4: run BOTH walks regardless of which pair restricts —
	// the raw-tree groups walk (unwrapping + ancestors) AND the
	// expanded descendant walk AND the op-descendant walk. Skipping
	// the groups walk when config rules exist (the old shape) left
	// `groups G … | display inheritance` unpriced on the effective
	// spelling.
	if err := authorizeRenderedDescendantsGroups(cfg, class, path, trees); err != nil {
		return err
	}
	if err := authorizeOpDescendantsGroups(cfg, class, path, displaySuffix, trees); err != nil {
		return err
	}
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	expanded, err := expandRenderedTrees15995(class, path, nodeID, trees)
	if err != nil {
		return err
	}
	return authorizeConfigRenderedDescendantsWithRules(class, rules, path, expanded)
}

// expandRenderedTrees15995 expands each tree exactly as the inheritance
// renderer does (expandForInheritance for nodeID). A failure refuses:
// the expanded render cannot be adjudicated from the raw tree.
func expandRenderedTrees15995(class string, path []string, nodeID int, trees []*ConfigTree) ([]*ConfigTree, error) {
	expanded := make([]*ConfigTree, 0, len(trees))
	for _, tree := range trees {
		if tree == nil {
			continue
		}
		exp, err := tree.expandForInheritance(nodeID)
		if err != nil {
			return nil, fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
				"the inheritance expansion for %q cannot be resolved for adjudication: %w (#15995)",
				class, strings.Join(path, " "), err)
		}
		expanded = append(expanded, exp)
	}
	return expanded, nil
}

// AuthorizeConfigShowCompareAtPathRendered is
// AuthorizeConfigShowCompareAtPath priced over the rendered compare
// arms: a candidate (or rollback) descendant below path that the
// *-configuration pair denies refuses the scoped diff, because the
// diff lines disclose it (#15995). A nil/empty path is the global
// compare (AuthorizeConfigShowCompare).
func AuthorizeConfigShowCompareAtPathRendered(cfg *Config, class string, path []string, trees ...*ConfigTree) error {
	if class == "" || len(path) == 0 {
		return AuthorizeConfigShowCompare(cfg, class)
	}
	return AuthorizeConfigShowPathRendered(cfg, class, path, "", trees...)
}

// AuthorizeConfigShowCompareCommand adjudicates only the operational
// command pair for a candidate compare, without charging configuration
// paths or rendered descendants. It mirrors the command spellings used
// by AuthorizeConfigShowCompareAtPathRendered.
func AuthorizeConfigShowCompareCommand(cfg *Config, class string, path []string) error {
	if class == "" {
		return nil
	}
	if len(path) == 0 {
		return authorizeShowCommand(cfg, class, "show configuration", "")
	}
	for _, spelling := range readSpellings15994(path) {
		if err := authorizeShowCommandReadSpelling(cfg, class, spelling, ""); err != nil {
			return err
		}
	}
	return nil
}

// AuthorizeConfigShowRollbackCommand adjudicates only the operational
// command pair for a rollback render, without charging configuration
// paths or rendered descendants. It mirrors the command spellings used
// by the scoped and whole-tree rollback gates.
func AuthorizeConfigShowRollbackCommand(cfg *Config, class string, path []string, displaySuffix string) error {
	if class == "" {
		return nil
	}
	if len(path) == 0 {
		return authorizeShowCommand(cfg, class, "show configuration", displaySuffix)
	}
	for _, spelling := range readSpellings15994(path) {
		if err := authorizeShowCommandReadSpelling(cfg, class, spelling, displaySuffix); err != nil {
			return err
		}
	}
	return nil
}

// AuthorizeConfigShowRollbackAtPathRendered is
// AuthorizeConfigShowRollbackAtPath priced over the rendered rollback
// tree: a denied strict descendant below path refuses the scoped
// rollback render (#15995). A nil/empty path is the whole-tree
// rollback (AuthorizeConfigShowRollback).
func AuthorizeConfigShowRollbackAtPathRendered(cfg *Config, class string, path []string, displaySuffix string, trees ...*ConfigTree) error {
	if class == "" || len(path) == 0 {
		return AuthorizeConfigShowRollback(cfg, class, displaySuffix)
	}
	return AuthorizeConfigShowPathRendered(cfg, class, path, displaySuffix, trees...)
}

// AuthorizeExpandedConfigShowRollbackAtPathRendered is the scoped
// rollback twin of AuthorizeExpandedConfigShowPathRendered, for a
// `display inheritance` rollback render: the slot tree is expanded
// exactly as the renderer expands it before descendants are priced.
func AuthorizeExpandedConfigShowRollbackAtPathRendered(cfg *Config, class string, path []string, displaySuffix string, nodeID int, trees ...*ConfigTree) error {
	if class == "" || len(path) == 0 {
		return AuthorizeConfigShowRollback(cfg, class, displaySuffix)
	}
	return AuthorizeExpandedConfigShowPathRendered(cfg, class, path, displaySuffix, nodeID, trees...)
}

// authorizeConfigRenderedDescendants adjudicates every descendant path
// of path present in any of trees against the *-configuration pair.
// The requested path itself was already adjudicated by the caller;
// only strict descendants are priced here. A class with no
// configuration regexes returns before any tree is touched, so the
// common unrestricted read pays nothing.
func authorizeConfigRenderedDescendants(cfg *Config, class string, path []string, trees []*ConfigTree) error {
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	return authorizeConfigRenderedDescendantsWithRules(class, rules, path, trees)
}

// authorizeConfigRenderedDescendantsWithRules is the walk behind
// authorizeConfigRenderedDescendants with the rules already compiled.
//
// The requested path need not spell the matched node in full:
// navigatePath also matches a terminal PREFIX of a multi-key node
// (`security policies from-zone trust` selects the node keyed
// `from-zone trust to-zone untrust`), AND descends through an
// intermediate multi-key node on its first spelled pair alone
// (`… from-zone trust policy p1` selects the policy under the node
// keyed `from-zone trust to-zone untrust`). The renderer prints every
// matched node's complete keys, so pricing rebuilds each rendered
// path from the actual descent trail (navigateRenderedMatches):
// every intermediate node's full Keys, then the terminal node's full
// Keys.
//
// Fold 4 invariant: every complete path the renderer prints for
// this selector that the REQUEST did not itself spell must be
// priced — the trail ancestors carrying omitted keys, the terminal
// rendered path, and every descendant below it. Pricing only the
// terminal path left an anchored deny on an intermediate context
// (`^… from-zone trust to-zone untrust$`) unmatched by the longer
// terminal string, admitting a child read the direct context read
// refuses. Exact request prefixes are NOT re-priced (see the walk):
// they are the request the caller already adjudicated, and Junos
// longest-match semantics forbid re-judging an allowed request by
// its prefixes.
func authorizeConfigRenderedDescendantsWithRules(class string, rules CompiledLoginRegexes, path []string, trees []*ConfigTree) error {
	for _, tree := range trees {
		if tree == nil {
			continue
		}
		for _, m := range navigateRenderedMatches(tree.Children, path) {
			// Price the trail only where it EXTENDS the request:
			// an intermediate/terminal node whose complete keys
			// differ from the request's spelling of it (omitted
			// pairs). Strict ancestors spelled exactly as requested
			// must not be re-priced: Junos longest-match prices an
			// allowed named instance (^firewall filter f1 for
			// [firewall filter f1]) against the request, not each
			// prefix — re-pricing prefixes refuses every allowed
			// instance under an allowlist. The terminal rendered
			// path (ancestors' last element) is priced whenever it
			// differs from the requested spelling.
			for _, anc := range trailPathsBeyondRequest(path, m) {
				if err := authorizeRenderedPath(class, rules, path, anc); err != nil {
					return err
				}
			}
			// Fold 5: the terminal node itself may be a bracketed
			// group — price each member spelling of it, and price
			// its children under each member path (shared body
			// renders under every member selector).
			for _, mp := range renderedNodePaths(parentPathOf(m), m.node) {
				if err := authorizeRenderedPath(class, rules, path, mp); err != nil {
					return err
				}
				if strings.Join(mp, " ") != strings.Join(m.path, " ") {
					if err := authorizeRenderedNode(class, rules, mp, m.node); err != nil {
						return err
					}
				}
			}
			if err := authorizeRenderedNode(class, rules, m.path, m.node); err != nil {
				return err
			}
		}
	}
	return nil
}

// trailPathsBeyondRequest returns the complete trail paths carrying
// keys the request did not spell: ancestors that are not token-wise
// prefixes of the request, plus everything deeper once the trail
// extends past the request spelling. Exact request prefixes are
// excluded — the caller already priced the request itself.
func trailPathsBeyondRequest(requested []string, m renderedMatch) [][]string {
	var out [][]string
	beyond := false
	for _, anc := range m.ancestors {
		if !beyond {
			if isPathPrefix(anc, requested) {
				continue
			}
			beyond = true
		}
		out = append(out, anc)
	}
	return out
}

// isPathPrefix reports whether anc is a token-wise prefix of requested.
func isPathPrefix(anc, requested []string) bool {
	if len(anc) > len(requested) {
		return false
	}
	for i := range anc {
		if anc[i] != requested[i] {
			return false
		}
	}
	return true
}

// parentPathOf returns the complete path of m's parent: the
// second-to-last trail ancestor, or — for a top-level match — the
// terminal path minus the node's own Keys.
func parentPathOf(m renderedMatch) []string {
	if len(m.ancestors) >= 2 {
		return m.ancestors[len(m.ancestors)-2]
	}
	if len(m.path) >= len(m.node.Keys) {
		return m.path[:len(m.path)-len(m.node.Keys)]
	}
	return nil
}

// authorizeRenderedNode prices every descendant below n (already priced
// at prefix by the caller), recursively. The first denied descendant
// refuses the render, naming only the path root (configAuditRoot) as
//
// Bracketed groups (fold 5): a node authored `keyword [ m1 m2 ]`
// carries Keys [keyword m1 m2] with bracket provenance on the member
// keys. The renderer prints the whole group for ANY member selector,
// and FormatPathSet emits one line per member spelling — each member
// is therefore a rendered path of its own (`... keyword m1`,
// `... keyword m2`) in addition to the combined key path. An anchored
// deny naming one member must refuse a render of its sibling member
// (the group body is shared), so every bracketed member path is
// priced, and children are priced under EACH member path (the body
// renders under every member spelling).
func authorizeRenderedNode(class string, rules CompiledLoginRegexes, prefix []string, n *Node) error {
	for _, child := range n.Children {
		for _, childPath := range renderedNodePaths(prefix, child) {
			joined := strings.Join(childPath, " ")
			if decision := rules.Evaluate(joined); !decision.Allowed {
				return fmt.Errorf("permission denied: login class %q denies configuration under %q (%s); "+
					"the requested subtree %q renders that descendant, so the ancestor read is refused — "+
					"request an allowed subtree instead (#15995)",
					class, configAuditRoot(joined), decision.Reason, configAuditRoot(strings.Join(prefix, " ")))
			}
			if err := authorizeRenderedNode(class, rules, childPath, child); err != nil {
				return err
			}
		}
	}
	return nil
}

// renderedNodePaths returns every complete path at which node n (child
// of the node at parentPrefix) is rendered: the combined key path
// (parentPrefix + n.Keys), plus — for a bracketed group — one path per
// member (parentPrefix + [keyword, member]). Member detection uses
// bracket PROVENANCE (KeyBracketed), exactly as the renderer's
// bracketed-group handling does: unbracketed trailing keys are a
// packed body, never member names (#9799).
func renderedNodePaths(parentPrefix []string, n *Node) [][]string {
	combined := append(append([]string(nil), parentPrefix...), n.Keys...)
	out := [][]string{combined}
	if len(n.Keys) >= 2 && n.KeyBracketed(1) {
		for j := 1; j < len(n.Keys); j++ {
			if !n.KeyBracketed(j) {
				break // the bracketed group ended
			}
			member := append(append([]string(nil), parentPrefix...), n.Keys[0], n.Keys[j])
			out = append(out, member)
		}
	}
	return out
}

// authorizeRenderedPath prices one complete rendered path, skipping the
func authorizeRenderedPath(class string, rules CompiledLoginRegexes, requested, rendered []string) error {
	if len(rendered) == len(requested) {
		same := true
		for i := range rendered {
			if rendered[i] != requested[i] {
				same = false
				break
			}
		}
		if same {
			return nil
		}
	}
	joined := strings.Join(rendered, " ")
	if decision := rules.Evaluate(joined); !decision.Allowed {
		return fmt.Errorf("permission denied: login class %q denies configuration under %q (%s); "+
			"the requested subtree %q renders that descendant, so the ancestor read is refused — "+
			"request an allowed subtree instead (#15995)",
			class, configAuditRoot(joined), decision.Reason, configAuditRoot(strings.Join(requested, " ")))
	}
	return nil
}

// AuthorizeConfigShowWhole adjudicates a whole-tree configuration read
// (ShowConfig with no path, in any target/format). A class with
// configuration regexes is refused: the render includes subtrees the
// request cannot enumerate. The operational pair is evaluated against
// the bare command (plus format suffix).
func AuthorizeConfigShowWhole(cfg *Config, class string, displaySuffix string) error {
	if class == "" {
		return nil
	}
	if err := authorizeConfigWhole(cfg, class, "show configuration"); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, "show configuration", displaySuffix)
}

// --- #15994 whole-tree groups entries (op verdict always carried) ---

// authorizeWholeGroups checks whether a whole-render substitution
// is available for trees: every tree either carries group stanzas
// (priced by the contained+expanded walks) or is groupless (then
// the blanket refusal stands). Returns (substitute, error): when
// substitute is false the caller must return its base refusal.
func authorizeWholeGroups(cfg *Config, class string, trees []*ConfigTree) (bool, error) {
	anyGroups := false
	for _, tree := range trees {
		if tree == nil {
			continue
		}
		if treeHasGroupStanzas14981(tree) {
			anyGroups = true
		}
	}
	if !anyGroups {
		return false, nil
	}
	for _, tree := range trees {
		if tree == nil {
			continue
		}
		// Root scope: every root node + subtree, definitions and
		// unwrapped spellings included (fix for the nil-path
		// navigatePath no-match bug in the first fold).
		if err := authorizeRenderedDescendantsGroups(cfg, class, nil, []*ConfigTree{tree}); err != nil {
			return false, err
		}
		if err := authorizeConfigReadExpanded15994(cfg, class, tree); err != nil {
			return false, err
		}
	}
	return true, nil
}

// authorizeConfigReadExpanded15994 prices every effective (group-
// expanded) set line of tree, no wholeErr shortcut: any denied
// effective path refuses. Definition lines are NOT skipped — the
// render prints them, and a deny on `groups` must refuse (fold 3).
func authorizeConfigReadExpanded15994(cfg *Config, class string, tree *ConfigTree) error {
	if tree == nil {
		return nil
	}
	lines, err := ExpandedMutationLines(tree)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
			"the group expansion cannot be resolved for adjudication: %w", class, err)
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if err := authorizeConfigReadPath(cfg, class, strings.Join(fields[1:], " ")); err != nil {
			return err
		}
	}
	return nil
}

// AuthorizeConfigShowWholeAtTree adjudicates a whole-tree read whose
// render discloses trees: the config whole-refusal substitutes the
// contained+expanded pricing when the class admits every contained
// path; the operational bare command (with display suffix) is ALWAYS
// re-charged afterwards, so an op-only deny (e.g. `display set`)
// can never be substituted away (fold B1). A groupless tree keeps
// the blanket refusal.
func AuthorizeConfigShowWholeAtTree(cfg *Config, class string, displaySuffix string, trees ...*ConfigTree) error {
	if class == "" {
		return nil
	}
	base := AuthorizeConfigShowWhole(cfg, class, displaySuffix)
	if base == nil {
		// Fold3: whole renders serialize every path; when any
		// rendered tree carries `groups` stanzas, price the
		// effective op commands — the bare bare-command verdict
		// alone would wave through a path-scoped op deny
		// (`^show configuration security`) for content authored
		// as a group body. Only runs when groups present, so
		// groupless renders keep the pre-fold behavior exactly.
		var hasGroups bool
		for _, tree := range trees {
			if tree != nil && treeHasGroupStanzas14981(tree) {
				hasGroups = true
				break
			}
		}
		if hasGroups {
			if err := authorizeOpDescendantsGroups(cfg, class, nil, displaySuffix, trees); err != nil {
				return err
			}
			// Also price every effective path expanded (covers
			// applied bodies materialized outside `groups` nodes).
			if err := authorizeConfigReadExpanded15994(cfg, class, firstTree15994(trees)); err != nil {
				return err
			}
		}
		return nil
	}
	substitute, err := authorizeWholeGroups(cfg, class, trees)
	if err != nil || !substitute {
		return base
	}
	return authorizeShowCommand(cfg, class, "show configuration", displaySuffix)
}

// firstTree15994 returns the first non-nil tree, or nil.
func firstTree15994(trees []*ConfigTree) *ConfigTree {
	for _, t := range trees {
		if t != nil {
			return t
		}
	}
	return nil
}

// AuthorizeConfigShowCompareAtTree adjudicates an unscoped candidate
// diff over both arms, with the same fold-3 op pricing as WholeAtTree.
func AuthorizeConfigShowCompareAtTree(cfg *Config, class string, old, new *ConfigTree) error {
	if class == "" {
		return nil
	}
	trees := []*ConfigTree{old, new}
	var hasGroups bool
	for _, tree := range trees {
		if tree != nil && treeHasGroupStanzas14981(tree) {
			hasGroups = true
			break
		}
	}
	base := AuthorizeConfigShowCompare(cfg, class)
	if base == nil {
		if hasGroups {
			return authorizeOpDescendantsGroups(cfg, class, nil, "", trees)
		}
		return nil
	}
	substitute, err := authorizeWholeGroups(cfg, class, trees)
	if err != nil || !substitute {
		return base
	}
	return authorizeShowCommand(cfg, class, "show configuration", "")
}

// AuthorizeConfigShowRollbackAtTree adjudicates an unscoped rollback
// render over tree, with the same fold-3 op pricing as WholeAtTree.
func AuthorizeConfigShowRollbackAtTree(cfg *Config, class string, tree *ConfigTree, displaySuffix string) error {
	if class == "" {
		return nil
	}
	base := AuthorizeConfigShowRollback(cfg, class, displaySuffix)
	if base == nil {
		if tree != nil && treeHasGroupStanzas14981(tree) {
			return authorizeOpDescendantsGroups(cfg, class, nil, displaySuffix, []*ConfigTree{tree})
		}
		return nil
	}
	substitute, err := authorizeWholeGroups(cfg, class, []*ConfigTree{tree})
	if err != nil || !substitute {
		return base
	}
	return authorizeShowCommand(cfg, class, "show configuration", displaySuffix)
}

// AuthorizeConfigShowCompare adjudicates a candidate diff render
// (ShowCompare, both arms). The diff discloses candidate content under
// arbitrary paths, so a configuration-restricted class is refused, as
// with load override. Operationally it is the bare `show configuration`.
func AuthorizeConfigShowCompare(cfg *Config, class string) error {
	if class == "" {
		return nil
	}
	if err := authorizeConfigWhole(cfg, class, "show configuration"); err != nil {
		return err
	}
	return AuthorizeConfigShowCompareCommand(cfg, class, nil)
}

// AuthorizeConfigShowCompareAtPath adjudicates a candidate diff filtered
// to path (#15272 B24-03): the diff discloses only that subtree, so it is
// priced as a path read (AuthorizeConfigShowPath), not refused as a
// whole-tree render. A nil/empty path is the global compare.
func AuthorizeConfigShowCompareAtPath(cfg *Config, class string, path []string) error {
	if class == "" || len(path) == 0 {
		return AuthorizeConfigShowCompare(cfg, class)
	}
	return AuthorizeConfigShowPath(cfg, class, path, "")
}

// AuthorizeConfigShowRollback adjudicates a rollback-slot render
// (ShowRollback). Same whole-tree shape as AuthorizeConfigShowWhole.
func AuthorizeConfigShowRollback(cfg *Config, class string, displaySuffix string) error {
	if class == "" {
		return nil
	}
	if err := authorizeConfigWhole(cfg, class, "show system rollback"); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, "show configuration", displaySuffix)
}

// AuthorizeConfigShowRollbackAtPath adjudicates a rollback-slot render
// scoped to path (#15942 H2-04): the render discloses only that
// subtree, so it is priced as a path read (AuthorizeConfigShowPath),
// not refused as a whole-tree render and not waved through by a gate
// that never saw the path. A nil/empty path is the whole-tree rollback
// (AuthorizeConfigShowRollback).
func AuthorizeConfigShowRollbackAtPath(cfg *Config, class string, path []string, displaySuffix string) error {
	if class == "" || len(path) == 0 {
		return AuthorizeConfigShowRollback(cfg, class, displaySuffix)
	}
	return AuthorizeConfigShowPath(cfg, class, path, displaySuffix)
}

// AuthorizeConfigShowSystemPath adjudicates an operational
// `show system <subtree>` render of an explicit configuration path
// (login, root-authentication): *-configuration on the path,
// *-commands on the real command spelling `show system <name>` with
// the bare `show configuration` as alternate form (mirroring
// AuthorizeConfigShowRollback's alternate-form shape), so an anchored
// `^show configuration$` deny covers these renders and a path-scoped
// `show system login` deny fires. Added for #14987.
func AuthorizeConfigShowSystemPath(cfg *Config, class string, path []string, command string) error {
	if class == "" {
		return nil
	}
	for _, spelling := range readSpellings15994(path) {
		if len(spelling) == 0 {
			continue
		}
		joined := strings.Join(spelling, " ")
		if err := authorizeConfigReadPath(cfg, class, joined); err != nil {
			return err
		}
		if err := authorizeShowCommand(cfg, class, "show configuration "+joined, ""); err != nil {
			return err
		}
	}
	return authorizeShowCommand(cfg, class, command, "")
}

// AuthorizeConfigPathOnlyWithOp15994 is AuthorizeConfigPathOnly plus the
// operational (`*-commands`) pair on every effective spelling (#15994):
// the CLI operational `show configuration …` arm already charged the
// literal line through checkCommandRegex, but never the unwrapped
// effective command (`show configuration security` for
// `show configuration groups G security`). Charging it against the
// shorter string again is not double-charging: the literal verdict
// and the effective verdict judge different strings, and both must
// admit. displaySuffix is "set"/"json"/"xml"/"inheritance" or "".
func AuthorizeConfigPathOnlyWithOp15994(cfg *Config, class string, path []string, displaySuffix string) error {
	if err := AuthorizeConfigPathOnly(cfg, class, path); err != nil {
		return err
	}
	for _, spelling := range readSpellings15994(path) {
		if len(spelling) == 0 {
			continue
		}
		if err := authorizeShowCommand(cfg, class, "show configuration "+strings.Join(spelling, " "), displaySuffix); err != nil {
			return err
		}
	}
	return nil
}

// AuthorizeConfigPathOnlyRenderedWithOp15994 is
// AuthorizeConfigPathOnlyWithOp15994 plus the rendered-descendant
// price (#15995), for the CLI operational arm.
func AuthorizeConfigPathOnlyRenderedWithOp15994(cfg *Config, class string, path []string, displaySuffix string, trees ...*ConfigTree) error {
	if err := AuthorizeConfigPathOnlyWithOp15994(cfg, class, path, displaySuffix); err != nil {
		return err
	}
	if class == "" {
		return nil
	}
	if err := authorizeRenderedDescendantsGroups(cfg, class, path, trees); err != nil {
		return err
	}
	return authorizeOpDescendantsGroups(cfg, class, path, displaySuffix, trees)
}

// AuthorizeExpandedConfigPathOnlyRenderedWithOp15994 is the
// `| display inheritance` twin (expanded trees).
func AuthorizeExpandedConfigPathOnlyRenderedWithOp15994(cfg *Config, class string, path []string, displaySuffix string, nodeID int, trees ...*ConfigTree) error {
	if err := AuthorizeConfigPathOnlyWithOp15994(cfg, class, path, displaySuffix); err != nil {
		return err
	}
	if class == "" {
		return nil
	}
	// Fold2-4: both walks regardless of which pair restricts.
	if err := authorizeRenderedDescendantsGroups(cfg, class, path, trees); err != nil {
		return err
	}
	if err := authorizeOpDescendantsGroups(cfg, class, path, displaySuffix, trees); err != nil {
		return err
	}
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	expanded, err := expandRenderedTrees15995(class, path, nodeID, trees)
	if err != nil {
		return err
	}
	return authorizeConfigRenderedDescendantsWithRules(class, rules, path, expanded)
}

// --- #15994 helpers (groups pricing onto the #15995 Rendered gate) ---

// authorizeRenderedDescendantsGroups is authorizeConfigRenderedDescendants
// with the groups rewrite: every rendered complete path (trail,
// terminal, descendants — built by navigateRenderedMatches and the
// recursive authorizeRenderedNodeGroups walk) is also priced under
// its group-unwrapped spelling(s). Root scope (empty path) prices
// every root node and its whole subtree.
func authorizeRenderedDescendantsGroups(cfg *Config, class string, path []string, trees []*ConfigTree) error {
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	for _, tree := range trees {
		if tree == nil {
			continue
		}
		if len(path) == 0 {
			for _, root := range tree.Children {
				for _, mp := range renderedNodePaths(nil, root) {
					if err := authorizeRenderedPath(class, rules, path, mp); err != nil {
						return err
					}
					if err := authorizeRenderedNodeGroups(cfg, class, rules, mp, root); err != nil {
						return err
					}
				}
			}
			continue
		}
		matches := navigateRenderedMatches(tree.Children, path)
		if len(matches) == 0 && isAncestorGroupsScope(path) {
			// Restricted-only by construction (this helper is
			// config-restricted-gated): an unresolvable groups
			// scope on a restricted read cannot be priced.
			return fmt.Errorf("permission denied: login class %q denies configuration under \"groups\" "+
				"(scope %q cannot be resolved in the render for adjudication)", class, strings.Join(path, " "))
		}
		for _, m := range matches {
			for _, anc := range trailPathsBeyondRequest(path, m) {
				if err := authorizeRenderedPath(class, rules, path, anc); err != nil {
					return err
				}
				if err := authorizeConfigReadPathUnwrapped(cfg, class, anc); err != nil {
					return err
				}
			}
			for _, mp := range renderedNodePaths(parentPathOf(m), m.node) {
				if err := authorizeRenderedPath(class, rules, path, mp); err != nil {
					return err
				}
				if err := authorizeConfigReadPathUnwrapped(cfg, class, mp); err != nil {
					return err
				}
				if strings.Join(mp, " ") != strings.Join(m.path, " ") {
					if err := authorizeRenderedNodeGroups(cfg, class, rules, mp, m.node); err != nil {
						return err
					}
				}
			}
			if err := authorizeRenderedNodeGroups(cfg, class, rules, m.path, m.node); err != nil {
				return err
			}
		}
	}
	return nil
}

// authorizeRenderedNodeGroups prices every descendant below n,
// recursively, on the config pair — the #15995 recursive walk with
// group-unwrapped spellings added per rendered path.
func authorizeRenderedNodeGroups(cfg *Config, class string, rules CompiledLoginRegexes, prefix []string, n *Node) error {
	for _, child := range n.Children {
		for _, childPath := range renderedNodePaths(prefix, child) {
			joined := strings.Join(childPath, " ")
			if decision := rules.Evaluate(joined); !decision.Allowed {
				return fmt.Errorf("permission denied: login class %q denies configuration under %q (%s); "+
					"the requested subtree %q renders that descendant, so the ancestor read is refused — "+
					"request an allowed subtree instead (#15994)",
					class, configAuditRoot(joined), decision.Reason, configAuditRoot(strings.Join(prefix, " ")))
			}
			if err := authorizeConfigReadPathUnwrapped(cfg, class, childPath); err != nil {
				return err
			}
			if err := authorizeRenderedNodeGroups(cfg, class, rules, childPath, child); err != nil {
				return err
			}
		}
	}
	return nil
}

// authorizeConfigReadPathUnwrapped prices path under its group-
// unwrapped spellings (no-op when path has no `groups` prefix).
func authorizeConfigReadPathUnwrapped(cfg *Config, class string, path []string) error {
	for _, spelling := range readSpellings15994(path) {
		if len(spelling) == 0 {
			continue
		}
		joined := strings.Join(spelling, " ")
		if joined == strings.Join(path, " ") {
			continue
		}
		if err := authorizeConfigReadPath(cfg, class, joined); err != nil {
			return err
		}
	}
	return nil
}

// isAncestorGroupsScope reports whether path is `groups` or
// `groups <name>` — a scope whose value is the group bodies it holds.
func isAncestorGroupsScope(path []string) bool {
	return len(path) <= 2 && len(path) >= 1 && path[0] == "groups"
}

// authorizeOpDescendantsGroups charges the operational pair on the
// effective command for every rendered path under path that passes
// through a `groups` container (#15994 fold, ancestors op-arm).
// Literal paths were already charged by the caller's command
// verdict; only the group alias needs pricing here.
func authorizeOpDescendantsGroups(cfg *Config, class string, path []string, displaySuffix string, trees []*ConfigTree) error {
	_, ok, err := OperationalLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid command regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	for _, tree := range trees {
		if tree == nil {
			continue
		}
		if len(path) == 0 {
			for _, root := range tree.Children {
				for _, mp := range renderedNodePaths(nil, root) {
					if err := authorizeOpPath15994(cfg, class, mp, displaySuffix); err != nil {
						return err
					}
					if err := authorizeOpNode15994(cfg, class, mp, displaySuffix, root); err != nil {
						return err
					}
				}
			}
			continue
		}
		for _, m := range navigateRenderedMatches(tree.Children, path) {
			for _, mp := range renderedNodePaths(parentPathOf(m), m.node) {
				if err := authorizeOpPath15994(cfg, class, mp, displaySuffix); err != nil {
					return err
				}
				if err := authorizeOpNode15994(cfg, class, mp, displaySuffix, m.node); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// authorizeOpNode15994 prices every descendant of n (prefix =
// rendered path of n) on the operational pair via authorizeOpPath15994.
func authorizeOpNode15994(cfg *Config, class string, prefix []string, displaySuffix string, n *Node) error {
	for _, child := range n.Children {
		for _, childPath := range renderedNodePaths(prefix, child) {
			if err := authorizeOpPath15994(cfg, class, childPath, displaySuffix); err != nil {
				return err
			}
			if err := authorizeOpNode15994(cfg, class, childPath, displaySuffix, child); err != nil {
				return err
			}
		}
	}
	return nil
}

// authorizeOpPath15994 charges `show configuration <effective>` on
// the operational pair when path's group-unwrapped spelling differs
// from path itself — i.e. path passes through a `groups` container.
func authorizeOpPath15994(cfg *Config, class string, path []string, displaySuffix string) error {
	for _, spelling := range readSpellings15994(path) {
		if len(spelling) == 0 {
			continue
		}
		joined := strings.Join(spelling, " ")
		if joined == strings.Join(path, " ") {
			continue
		}
		if err := authorizeShowCommand(cfg, class, "show configuration "+joined, displaySuffix); err != nil {
			return err
		}
	}
	return nil
}

// priced over the rendered descendants of path in trees (#15995 fold):
// `show system login` and `show system root-authentication` print the
// whole subtree at path, so a denied strict descendant refuses the
// command exactly as a denied descendant refuses
// AuthorizeConfigShowPathRendered. The operational pair is charged
// once, on the real `show system <name>` spelling, as before.
func AuthorizeConfigShowSystemPathRendered(cfg *Config, class string, path []string, command string, trees ...*ConfigTree) error {
	if err := AuthorizeConfigShowSystemPath(cfg, class, path, command); err != nil {
		return err
	}
	if class == "" {
		return nil
	}
	return authorizeRenderedDescendantsGroups(cfg, class, path, trees)
}

// AuthorizeConfigShowRescue adjudicates `show system configuration
// rescue`: a whole-tree text render, refused for a *-configuration-
// restricted class like AuthorizeConfigShowWhole, and evaluated
// operationally on its real spelling with the bare form as alternate.
// Added for #14987.
func AuthorizeConfigShowRescue(cfg *Config, class string) error {
	if class == "" {
		return nil
	}
	if err := authorizeConfigWhole(cfg, class, "show system configuration rescue"); err != nil {
		return err
	}
	return authorizeShowCommand(cfg, class, "show system configuration rescue", "")
}

func authorizeConfigReadPath(cfg *Config, class, joined string) error {
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	if decision := rules.Evaluate(joined); !decision.Allowed {
		return fmt.Errorf("permission denied: login class %q denies configuration under %q (%s)",
			class, configAuditRoot(joined), decision.Reason)
	}
	return nil
}

func authorizeConfigWhole(cfg *Config, class, what string) error {
	_, restricted, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !restricted {
		return nil
	}
	return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
		"%s renders the whole configuration, so the subtrees it discloses cannot be "+
		"adjudicated one by one; request an allowed subtree instead (#14707)", class, what)
}

// AuthorizeConfigPathOnly adjudicates one config path against the
// *-configuration pair alone, WITHOUT the rendered trees. For surfaces
// that already charged the operational pair on the full command line
// (the on-box CLI's checkCommandRegex) and must not double-charge it
// against a shorter string. Prefer AuthorizeConfigPathOnlyRendered
// wherever the rendered tree is available (#15995).
func AuthorizeConfigPathOnly(cfg *Config, class string, path []string) error {
	if class == "" {
		return nil
	}
	for _, spelling := range readSpellings15994(path) {
		if len(spelling) == 0 {
			continue
		}
		if err := authorizeConfigReadPath(cfg, class, strings.Join(spelling, " ")); err != nil {
			return err
		}
	}
	return nil
}

// AuthorizeConfigPathOnlyRendered is AuthorizeConfigPathOnly plus the
// rendered-descendant price (#15995): every strict descendant of path
// present in trees is adjudicated against the *-configuration pair,
// and a denied one refuses the ancestor read.
func AuthorizeConfigPathOnlyRendered(cfg *Config, class string, path []string, trees ...*ConfigTree) error {
	if class == "" {
		return nil
	}
	if err := AuthorizeConfigPathOnly(cfg, class, path); err != nil {
		return err
	}
	return authorizeRenderedDescendantsGroups(cfg, class, path, trees)
}

// AuthorizeExpandedConfigPathOnlyRendered is AuthorizeConfigPathOnly
// plus the rendered-descendant price over apply-groups-expanded trees,
// for the CLI operational `show configuration … | display inheritance`
// arm whose operational pair was already charged on the full command
// line (#15995 fold).
func AuthorizeExpandedConfigPathOnlyRendered(cfg *Config, class string, path []string, nodeID int, trees ...*ConfigTree) error {
	if class == "" {
		return nil
	}
	if err := AuthorizeConfigPathOnly(cfg, class, path); err != nil {
		return err
	}
	// Fold2-4: groups walk regardless of which pair restricts (no
	// op walk — already charged on the full command line).
	if err := authorizeRenderedDescendantsGroups(cfg, class, path, trees); err != nil {
		return err
	}
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	expanded, err := expandRenderedTrees15995(class, path, nodeID, trees)
	if err != nil {
		return err
	}
	return authorizeConfigRenderedDescendantsWithRules(class, rules, path, expanded)
}

// authorizeShowCommand evaluates the operational pair against the
// canonical show command. The bare "show configuration" is measured as
// an alternate form so an anchored deny on it covers sub-paths
// (EvaluateForms max-per-side, #9022 shape), and the display suffix is
// part of the matched string so "display set" fires.
func authorizeShowCommand(cfg *Config, class, command, displaySuffix string) error {
	rules, ok, err := OperationalLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid command regex: %w", class, err)
	}
	if !ok {
		return nil
	}
	// #14987: callers pass the suffix in two spellings — the CLI's
	// displaySuffix14707 strips "display " to the bare format word
	// ("set"), while gRPC/REST pass ConfigShowDisplaySuffix output
	// ("display set"). The matched string must be the operator's
	// `| display set` in both cases; passing the bare word produced
	// `show configuration … | set`, which a `display set` deny never
	// matches. Normalize here, the one place the string is built.
	suffix := displaySuffix
	switch suffix {
	case "set", "json", "xml", "inheritance":
		suffix = "display " + suffix
	}
	full := command
	if suffix != "" {
		full = command + " | " + suffix
	}
	if decision := rules.EvaluateForms(full, "show configuration"); !decision.Allowed {
		return fmt.Errorf("permission denied: login class %q denies %q (%s)", class, command, decision.Reason)
	}
	return nil
}

// ConfigShowDisplaySuffix renders a display-format selector as the CLI
// pipe suffix operators write ("display set", …). format is the
// caller-surface spelling: "set", "json", "xml", "inheritance", or ""
// (hierarchical). Unknown spellings yield "" — the caller's own format
// validation rejects them; authorization must not invent a form.
func ConfigShowDisplaySuffix(format string) string {
	switch format {
	case "set", "json", "xml", "inheritance":
		return "display " + format
	}
	return ""
}
