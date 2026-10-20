package config

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"slices"
	"strings"
)

// expandForInheritance prepares the display clone (strip inactive, then
// normalize — see #2008 H1 / #9743 below) and expands its groups for the
// given node identity. nodeID >= 0 resolves apply-groups "${node}" to that
// node's group (node0/node1); nodeID < 0 is the standalone view and uses
// the generic node0 fallback (#15031), exactly as the generic compile does.
// An expansion failure is returned, never hidden: the old code fell back
// to the raw Format()/FormatPath() on error, so every ${node} HA config
// silently rendered unexpanded (no inherited leaves, no annotation) and a
// genuinely broken apply-groups looked like a plain config (#15197).
func (t *ConfigTree) expandForInheritance(nodeID int) (*ConfigTree, error) {
	clone := t.cloneForExpansion()
	// #9743: normalize the clone before expanding, because both compile cores
	// do (compiler.go, and schema_walk.go via normalizeCompactForValidation).
	// Since #9620 the #8662 normalizer rewrites a brace-elided routing instance
	// into its braced shape, and group expansion binds against that shape. A
	// display that expands the RAW tree therefore omits properties the commit
	// applies (the elided `routing-instances { blue instance-type forwarding
	// description inherited; } }` group body compiled with both properties
	// while the display showed neither). The clone is fresh
	// (cloneForExpansion never aliases t), so normalizing it in place cannot
	// reach the caller's tree.
	normalizeCompactStanzas(clone)
	if nodeID >= 0 {
		vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
		if err := clone.ExpandGroupsWithVarsTagged(vars); err != nil {
			return nil, fmt.Errorf("apply-groups: %w", err)
		}
		return clone, nil
	}
	if _, err := clone.ExpandGroupsNodeFallback15031(true); err != nil {
		return nil, fmt.Errorf("apply-groups: %w", err)
	}
	return clone, nil
}

// FormatInheritance returns the config with inherited groups expanded and
// annotated with "## 'X' was inherited from group 'Y'" comments, matching
// Junos "show configuration | display inheritance" output. It renders the
// standalone view (${node} resolved to node0, #15031); cluster callers
// that know their node identity use FormatInheritanceForNode. Expansion
// failures render as an explicit error line instead of silently falling
// back to the raw config (#15197).
func (t *ConfigTree) FormatInheritance() string {
	out, err := t.FormatInheritanceForNode(-1)
	if err != nil {
		return fmt.Sprintf("%% display inheritance failed: %v\n", err)
	}
	return out
}

// FormatInheritanceForNode is FormatInheritance for the given cluster node
// (nodeID >= 0), or the standalone view (nodeID < 0). It returns the
// expansion error instead of hiding it behind the raw tree (#15197).
func (t *ConfigTree) FormatInheritanceForNode(nodeID int) (string, error) {
	clone, err := t.expandForInheritance(nodeID)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	formatNodesInheritance(&b, clone.Children, 0)
	return b.String(), nil
}

// FormatPathInheritance is like FormatPath but with inheritance annotations.
// It renders the standalone view; see FormatInheritance.
func (t *ConfigTree) FormatPathInheritance(path []string) string {
	out, err := t.FormatPathInheritanceForNode(path, -1)
	if err != nil {
		return fmt.Sprintf("%% display inheritance failed: %v\n", err)
	}
	return out
}

// FormatPathInheritanceForNode is FormatPathInheritance for the given
// cluster node (nodeID >= 0), or the standalone view (nodeID < 0). It
// returns the expansion error instead of rendering the unexpanded subtree
// (#15197). An unmatched path returns "" with no error, as before.
func (t *ConfigTree) FormatPathInheritanceForNode(path []string, nodeID int) (string, error) {
	clone, err := t.expandForInheritance(nodeID)
	if err != nil {
		return "", err
	}
	if len(path) == 0 {
		var b strings.Builder
		formatNodesInheritance(&b, clone.Children, 0)
		return b.String(), nil
	}
	matches := navigatePath(clone.Children, path)
	if len(matches) == 0 {
		return "", nil
	}
	var b strings.Builder
	for _, n := range matches {
		if n.Annotation != "" {
			fmt.Fprintf(&b, "/* %s */\n", n.Annotation)
		}
		if n.IsLeaf {
			fmt.Fprintf(&b, "%s%s;\n", inactivePrefix(n), n.QuotedKeyPath())
		} else {
			fmt.Fprintf(&b, "%s%s {\n", inactivePrefix(n), n.QuotedKeyPath())
			formatNodesInheritance(&b, n.Children, 1)
			fmt.Fprintf(&b, "}\n")
		}
	}
	return b.String(), nil
}

func formatNodesInheritance(b *strings.Builder, nodes []*Node, indent int) {
	nodes = canonicalOrder(nodes)
	prefix := strings.Repeat("    ", indent)
	for _, n := range nodes {
		if n.Annotation != "" {
			fmt.Fprintf(b, "%s/* %s */\n", prefix, n.Annotation)
		}
		if n.InheritedFrom != "" {
			// Use the last key in the node's key path for inherited-node annotations
			// (for example, "## 'any' was inherited").
			displayKey := n.Keys[len(n.Keys)-1]
			fmt.Fprintf(b, "%s##\n%s## '%s' was inherited from group '%s'\n%s##\n",
				prefix, prefix, displayKey, n.InheritedFrom, prefix)
		}
		if n.IsLeaf {
			fmt.Fprintf(b, "%s%s%s;\n", prefix, inactivePrefix(n), n.QuotedKeyPath())
		} else {
			fmt.Fprintf(b, "%s%s%s {\n", prefix, inactivePrefix(n), n.QuotedKeyPath())
			formatNodesInheritance(b, n.Children, indent+1)
			fmt.Fprintf(b, "%s}\n", prefix)
		}
	}
}

// Format renders the tree as Junos hierarchical configuration text.
func (t *ConfigTree) Format() string {
	var b strings.Builder
	formatNodes(&b, t.Children, 0)
	return b.String()
}

// inactivePrefix returns the `inactive: ` text-form prefix for a
// deactivated node (#2008 H1), or "" for an active node. A single shared
// helper across every text serializer guarantees no display path silently
// drops the operator's deactivation from `show configuration`.
func inactivePrefix(n *Node) string {
	if n != nil && n.Inactive {
		return inactiveMarker + " "
	}
	return ""
}

// canonicalOrder reorders children so "match"/"from" comes before "then",
// matching Junos canonical display order for policies, NAT rules, and
// firewall filter terms.
func canonicalOrder(nodes []*Node) []*Node {
	matchIdx, thenIdx := -1, -1
	for i, n := range nodes {
		if len(n.Keys) > 0 {
			switch n.Keys[0] {
			case "match", "from":
				matchIdx = i
			case "then":
				thenIdx = i
			}
		}
	}
	if matchIdx < 0 || thenIdx < 0 || matchIdx < thenIdx {
		return nodes // already correct or doesn't apply
	}
	// match/from is after then — move it to just before then
	result := make([]*Node, 0, len(nodes))
	for i, n := range nodes {
		if i == matchIdx {
			continue
		}
		if i == thenIdx {
			result = append(result, nodes[matchIdx])
		}
		result = append(result, n)
	}
	return result
}

func formatNodes(b *strings.Builder, nodes []*Node, indent int) {
	nodes = canonicalOrder(nodes)
	prefix := strings.Repeat("    ", indent)
	for _, n := range nodes {
		if n.Annotation != "" {
			fmt.Fprintf(b, "%s/* %s */\n", prefix, n.Annotation)
		}
		if n.IsLeaf {
			fmt.Fprintf(b, "%s%s%s;\n", prefix, inactivePrefix(n), n.QuotedKeyPath())
		} else {
			fmt.Fprintf(b, "%s%s%s {\n", prefix, inactivePrefix(n), n.QuotedKeyPath())
			formatNodes(b, n.Children, indent+1)
			fmt.Fprintf(b, "%s}\n", prefix)
		}
	}
}

// FormatPath navigates to the given path and formats the subtree found there.
// Path components are matched against node keys. For example, FormatPath(["interfaces", "wan0"])
// navigates into the "interfaces" node, then into the child whose second key is "wan0",
// and formats that subtree. Returns "" if the path is not found.
func (t *ConfigTree) FormatPath(path []string) string {
	if len(path) == 0 {
		return t.Format()
	}
	matches := navigatePath(t.Children, path)
	if len(matches) == 0 {
		return ""
	}
	var b strings.Builder
	for _, n := range matches {
		if n.Annotation != "" {
			fmt.Fprintf(&b, "/* %s */\n", n.Annotation)
		}
		if n.IsLeaf {
			fmt.Fprintf(&b, "%s%s;\n", inactivePrefix(n), n.QuotedKeyPath())
		} else {
			fmt.Fprintf(&b, "%s%s {\n", inactivePrefix(n), n.QuotedKeyPath())
			formatNodes(&b, n.Children, 1)
			fmt.Fprintf(&b, "}\n")
		}
	}
	return b.String()
}

// FormatSet renders the tree as flat "set" commands.
func (t *ConfigTree) FormatSet() string {
	var b strings.Builder
	formatSetNodes(&b, t.Children, nil, nil, nil)
	return b.String()
}

// FormatSetForLoadMerge renders hierarchical input as replayable flat `set`
// commands for LoadMerge. It is deliberately separate from FormatSet:
// operator-visible `display set` output must keep the #6668 zero-churn rule
// that leaves never acquire bracket delimiters, while a merge replay must
// preserve leaf bracket provenance for provenance-based validation (#10084).
func (t *ConfigTree) FormatSetForLoadMerge() string {
	var b strings.Builder
	formatSetNodesMode(&b, t.Children, nil, nil, nil, true)
	return b.String()
}

// nodeKeyBracketMask returns the per-key BRACKET mask for one node's
// contribution to a flat `set` line (#6668): key i is emitted inside
// `[ ... ]` when the operator AUTHORED it inside a bracket list and the node
// is a CONTAINER.
//
// Provenance, not inference. The alternative — bracketing whenever a node
// carries more keys than its schema arity — also catches the PACKED-statement
// family (`scheduler-maps edge-map forwarding-class best-effort { ... }`,
// `unit 0 shaping-rate 10g { ... }`), which is a different defect class
// (#6588/#6665/#6672) whose flat replay already reconstructs an equivalent
// config. Bracketing those would churn `show | display set` for every deployed
// CoS config to say something the replay did not need to be told. Measured:
// that rule moved 4 lines of the class-of-service dual-AST fixture and 0 lines
// of the case this exists to fix.
//
// A LEAF is never bracketed: SetPath's trailing-value absorber already
// collapses a leaf's whole tail onto one node (the #2419 contract), so every
// bracketed VALUE list round-trips clean without a delimiter — and emitting one
// would rewrite every `source-address [ a b c ]` line in the tree.
func nodeKeyBracketMask(n *Node) []bool {
	if n == nil || n.IsLeaf || len(n.KeysBracketed) != len(n.Keys) {
		return nil
	}
	return n.KeysBracketed
}

// FormatPathSet renders a subtree as flat "set" commands.
// The full path prefix (including parent keys) is included in each set line.
func (t *ConfigTree) FormatPathSet(path []string) string {
	if len(path) == 0 {
		return t.FormatSet()
	}
	matches, width := navigatePathWidth(t.Children, path)
	if len(matches) == 0 {
		return ""
	}
	// Compute the parent prefix: the path elements BEFORE the matched terminal
	// node. navigatePath consumed exactly `width` trailing `path` tokens into the
	// terminal node's keys, so the prefix is the leading part of `path` with that
	// width stripped from the RIGHT. Using the TRUE consumed width — rather than
	// the node's first key from the LEFT (pre-#5717) or a suffix match of the
	// node's whole keys (the first #5717 cut) — is the only reconstruction that
	// stays correct when an ancestor value repeats the terminal node's keys: a
	// zone NAMED "interfaces" holding an `interfaces` stanza (single-key terminal,
	// width 1) and a filter NAMED `term` holding a term NAMED `term` (`... filter
	// term term term`, width 1) both broke the earlier heuristics
	// (codex-182 A3-b00-C001, #5717).
	parentPrefix := append([]string(nil), path[:len(path)-width]...)
	var b strings.Builder
	for _, n := range matches {
		// The ancestor prefix is reconstructed from the REQUESTED path, not
		// walked, so no node is available to source its quote provenance from;
		// only the matched node's own keys carry a mask (#6673).
		prefix, prefixQuote, prefixGroup := appendNodeKeysGrouped(parentPrefix, nil, nil, n)
		if n.IsLeaf {
			fmt.Fprintf(&b, "set %s\n", joinKeysProvGrouped(prefix, prefixQuote, prefixGroup))
		} else {
			if len(n.Children) == 0 {
				fmt.Fprintf(&b, "set %s\n", joinKeysProvGrouped(prefix, prefixQuote, prefixGroup))
			}
			formatSetNodes(&b, n.Children, prefix, prefixQuote, prefixGroup)
		}
		if n.Annotation != "" {
			fmt.Fprintf(&b, "annotate %s %s\n", joinKeysProvGrouped(prefix, prefixQuote, prefixGroup), EscapedAnnotation(n.Annotation))
		}
		if n.Inactive {
			fmt.Fprintf(&b, "deactivate %s\n", joinKeysProvGrouped(prefix, prefixQuote, prefixGroup))
		}
	}
	return b.String()
}

// formatSetNodes renders nodes as flat `set` commands. A deactivated node
// (#2008 H1) is emitted as its normal `set` line(s) followed by a
// `deactivate <path>` line — matching Junos `show | display set`, which
// models deactivation as the separate `deactivate` verb rather than an
// inline token. Loading such output replays the `set` then the
// `deactivate`, restoring the Inactive flag.
func formatSetNodes(b *strings.Builder, nodes []*Node, prefix []string, prefixQuote, prefixGroup []bool) {
	formatSetNodesMode(b, nodes, prefix, prefixQuote, prefixGroup, false)
}

func policyStatementTermPath12598(path []string) bool {
	for i := 0; i+3 < len(path); i++ {
		if path[i] == "policy-options" &&
			path[i+1] == "policy-statement" &&
			path[i+2] != "" &&
			path[i+3] == "term" {
			return true
		}
	}
	return false
}

func formatSetNodesMode(b *strings.Builder, nodes []*Node, prefix []string, prefixQuote, prefixGroup []bool, preserveLeafBrackets bool) {
	for _, n := range canonicalOrder(nodes) {
		path, pathQuote, pathGroup := appendNodeKeysGroupedMode(prefix, prefixQuote, prefixGroup, n, preserveLeafBrackets)
		pathText := joinKeysProvGrouped(path, pathQuote, pathGroup)
		if preserveLeafBrackets && n.IsLeaf {
			pathText = joinKeysProvGroupedFrom(path, pathQuote, pathGroup, len(path)-len(n.Keys))
		}
		switch {
		case n.IsLeaf:
			fmt.Fprintf(b, "set %s\n", pathText)
		case len(n.Children) == 0:
			// #9126: AN EMPTY CONTAINER MUST STILL EMIT ITS OWN `set` LINE.
			//
			// Recursing into no children emits nothing, so the container
			// vanished from `show | display set` and the round trip lost it.
			// When it was ALSO deactivated the output was actively broken: a
			// bare `deactivate <path>` with no preceding `set`, which
			// setInactiveAtPath rejects with `container %q does not exist`.
			// LoadSet and LoadMerge are atomic, so that one line aborts the
			// WHOLE restore -- it fails loudly and closed, but it costs the
			// transaction.
			//
			// Emitting the container is what Junos does and what makes the
			// deactivate replayable; there is no other line that could carry
			// it, because a container with no children has no leaf to hang it
			// off.
			fmt.Fprintf(b, "set %s\n", pathText)
		default:
			formatSetNodesMode(b, n.Children, path, pathQuote, pathGroup, preserveLeafBrackets)
		}
		if n.Annotation != "" {
			fmt.Fprintf(b, "annotate %s %s\n", pathText, EscapedAnnotation(n.Annotation))
		}
		if n.Inactive {
			// A one-key routing-policy term has no authored name. Flattening
			// its body makes each immediate body statement a replayed term
			// keyed by that statement's first token. A bare `deactivate ...
			// term` prefix-matches a named sibling instead.
			if preserveLeafBrackets && policyStatementTermPath12598(path) &&
				len(n.Keys) == 1 && n.Keys[0] == "term" && len(n.Children) > 0 {
				for _, child := range n.Children {
					if len(child.Keys) == 0 {
						continue
					}
					firstChildKey := *child
					firstChildKey.Keys = firstChildKey.Keys[:1]
					if len(firstChildKey.KeysQuoted) > 0 {
						firstChildKey.KeysQuoted = firstChildKey.KeysQuoted[:1]
					}
					if len(firstChildKey.KeysBracketed) > 0 {
						firstChildKey.KeysBracketed = firstChildKey.KeysBracketed[:1]
					}
					deactivatePath, deactivateQuote, deactivateGroup :=
						appendNodeKeysGroupedMode(path, pathQuote, pathGroup, &firstChildKey, preserveLeafBrackets)
					fmt.Fprintf(b, "deactivate %s\n",
						joinKeysProvGrouped(deactivatePath, deactivateQuote, deactivateGroup))
				}
			} else {
				fmt.Fprintf(b, "deactivate %s\n", pathText)
			}
		}
	}
}

// joinQuotedKeys joins keys with spaces, quoting any that contain special characters.
func joinQuotedKeys(keys []string) string {
	return joinQuotedKeysProv(keys, nil)
}

// joinQuotedKeysProv is joinQuotedKeys with per-key AUTHORED-quote provenance
// (#6673): where forceQuote[i] reports an AUTHORED quote, the key is emitted
// quoted even though its bare text would read back as the same key, because
// dropping the quotes would lose the value GROUPING. forceQuote may be nil or
// short — a missing entry means "quote only if quoteKey says so", which is
// exactly the pre-#6673 rendering.
//
// THE TERMINAL TEST IS AGAINST THIS LINE, not against the node a key came from,
// and that distinction is the #6673 r11 fail-open (B1). The hierarchical
// renderer may drop an authored quote on a node's LAST key, because there the
// key is followed by `{` and stays a container key on re-parse
// (keyNeedsAuthoredQuote). Flattening destroys that: a container's last key is
// concatenated with its child's keys, so it lands at the FRONT of the child's
// group, where it is exactly the token the grouping rule reads.
//
// Measured at the previous head on `commands "set" { "system host-name pwned"; }`
// — the hierarchical ingress compiles ["system host-name pwned"], which
// classifyPlan REJECTS for having no `set `/`delete ` prefix. FormatSet emitted
// the terminal `"set"` BARE, and replaying that line compiled
// ["set system host-name pwned"]: a valid command, APPLIED. Reject became
// apply, on the same authored bytes. origin/master does not have this — its
// reader compiles ["set"] on replay, which is rejected too, so both of its
// ingresses decline. The suppression added the hole.
//
// Quoting every authored-quoted key except the line's LAST restores that: the
// last token's quoting decides nothing (a one-token group is identical under
// both grouping rules), and every earlier token keeps the bit the next parse
// needs.
func joinQuotedKeysProv(keys []string, forceQuote []bool) string {
	parts := make([]string, len(keys))
	for i, k := range keys {
		if i < len(keys)-1 && i < len(forceQuote) && forceQuote[i] {
			parts[i] = `"` + keyEscaper.Replace(k) + `"`
			continue
		}
		parts[i] = quoteKey(k)
	}
	return strings.Join(parts, " ")
}

// appendNodeKeys extends a flat display-set path (and its parallel
// authored-quote mask) with one node's keys.
//
// It records the RAW authored bit — Node.KeyQuoted — and deliberately does NOT
// apply keyNeedsAuthoredQuote's per-node terminal rule (#6673 r11 B1). At this
// point it is not yet known whether a key is terminal: a container's last key
// is followed by its CHILDREN's keys in the flattened line. Pre-suppressing
// here dropped exactly the quote that decides the child group's boundary on
// re-parse, which is how a rejected remediation batch became an applied one.
// joinQuotedKeysProv owns the terminal test, against the finished line.
//
// forceQuote is normalized to len(path) first so a caller may pass nil (or a
// stale short mask) without silently shifting every subsequent key's flag.
func appendNodeKeys(path []string, forceQuote []bool, n *Node) ([]string, []bool) {
	p, q, _ := appendNodeKeysGrouped(path, forceQuote, nil, n)
	return p, q
}

// appendNodeKeysGrouped is appendNodeKeys plus the parallel BRACKET-GROUP mask
// (#6668), taken from the node's authored bracket provenance.
func appendNodeKeysGrouped(path []string, forceQuote, group []bool, n *Node) ([]string, []bool, []bool) {
	return appendNodeKeysGroupedMode(path, forceQuote, group, n, false)
}

func appendNodeKeysGroupedMode(path []string, forceQuote, group []bool, n *Node, preserveLeafBrackets bool) ([]string, []bool, []bool) {
	outPath := append(append([]string(nil), path...), n.Keys...)
	outQuote := make([]bool, len(path), len(outPath))
	copy(outQuote, forceQuote)
	outGroup := make([]bool, len(path), len(outPath))
	copy(outGroup, group)
	bracket := nodeKeyBracketMask(n)
	if preserveLeafBrackets && n.IsLeaf && len(n.KeysBracketed) == len(n.Keys) {
		bracket = n.KeysBracketed
	}
	for i := range n.Keys {
		outQuote = append(outQuote, n.KeyQuoted(i))
		outGroup = append(outGroup, i < len(bracket) && bracket[i])
	}
	return outPath, outQuote, outGroup
}

// joinKeysProvGrouped is joinQuotedKeysProv plus BRACKET GROUPS (#6668): a
// maximal run of group[i] spanning more than one key is wrapped in `[ ... ]`,
// which is the only way the flat-set language can say where a CONTAINER node's
// key list ends. A one-key run is emitted bare — a single token needs no
// delimiter and bracketing it would churn output for no information.
func joinKeysProvGrouped(keys []string, forceQuote, group []bool) string {
	return joinKeysProvGroupedFrom(keys, forceQuote, group, -1)
}

// joinKeysProvGroupedFrom is joinKeysProvGrouped with an optional starting
// index whose single-key bracket runs should remain delimited. The public
// FormatSet path passes -1 and therefore keeps the #6668 zero-churn rule.
// LoadMerge's private replay renderer passes the leaf's start index so a
// one-key leaf bracket is carried through ParseSetVerbGrouped (#10084).
func joinKeysProvGroupedFrom(keys []string, forceQuote, group []bool, singleBracketFrom int) string {
	if len(group) != len(keys) {
		return joinQuotedKeysProv(keys, forceQuote)
	}
	parts := make([]string, 0, len(keys)+4)
	for i := 0; i < len(keys); {
		if !group[i] {
			parts = append(parts, quoteKeyProv(keys, forceQuote, i))
			i++
			continue
		}
		run := 0
		for i+run < len(keys) && group[i+run] {
			run++
		}
		if run < 2 && (singleBracketFrom < 0 || i < singleBracketFrom) {
			parts = append(parts, quoteKeyProv(keys, forceQuote, i))
			i++
			continue
		}
		parts = append(parts, "[")
		for j := i; j < i+run; j++ {
			preserveQuote := singleBracketFrom >= 0 && j >= singleBracketFrom
			parts = append(parts, quoteKeyProvForLoadMerge(keys, forceQuote, j, preserveQuote))
		}
		parts = append(parts, "]")
		i += run
	}
	return strings.Join(parts, " ")
}

// quoteKeyProvForLoadMerge preserves an authored quote on the final key when
// that key is inside a replay-only bracket group. Public display-set output
// suppresses final-key quotes for ordinary values but retains terminal
// routing-policy inline keywords so they remain list values on replay. A
// bracketed leaf also needs final quotes for #9881's distinction between
// quoted bracket contents and an unquoted bracket that was lexer list sugar.
func quoteKeyProvForLoadMerge(keys []string, forceQuote []bool, i int, preserveFinalQuote bool) string {
	if (i < len(keys)-1 || preserveFinalQuote) && i < len(forceQuote) && forceQuote[i] {
		return `"` + keyEscaper.Replace(keys[i]) + `"`
	}
	return quoteKey(keys[i])
}

// quoteKeyProv renders keys[i] with the same authored-quote rule
// joinQuotedKeysProv applies, including terminal-key suppression for ordinary
// values (#6673 r11 B1). A terminal routing-policy inline keyword keeps its
// authored quote because it may be a `from` list value, not a clause boundary.
func quoteKeyProv(keys []string, forceQuote []bool, i int) string {
	if i < len(forceQuote) && forceQuote[i] &&
		(i < len(keys)-1 || policyTermInlineKeywords[keys[i]]) {
		return `"` + keyEscaper.Replace(keys[i]) + `"`
	}
	return quoteKey(keys[i])
}

// FormatCompare produces a Junos-style hierarchical diff between two trees.
// It shows [edit <path>] context headers and +/- prefixed lines for added/removed content.
// Unchanged sibling nodes within changed containers are shown collapsed as "name { ... }".
func FormatCompare(oldTree, newTree *ConfigTree) string {
	var b strings.Builder
	diffNodes(&b, oldTree.Children, newTree.Children, nil)
	return b.String()
}

// FormatCompareAtPath is FormatCompare filtered to the subtree at path
// (#15272 B24-03, #15758). Both trees are navigated to path; a side
// missing the path contributes no matches, so an added/deleted subtree
// renders as +/- under its parent [edit] header. A path present on
// neither side yields "". An empty path is the global compare.
//
// #15758: the matched nodes THEMSELVES are diffed (oldMatches vs
// newMatches) at the parent prefix — the same navigatePathWidth
// contract FormatPathSet / FormatPathJSON use — not just their
// children. Unwrapping children discarded everything that lives on
// the matched node itself: a leaf match was skipped outright, a
// container's own Inactive flag never reached the diff, and an empty
// container produced an empty child list indistinguishable from a
// missing path, so all three rendered "[no changes]". Diffing the
// node slice also keeps bare-keyword multi-matches (every sibling
// sharing the terminal keyword) as separate nodes for diffNodes'
// occurrence-aware pairing instead of flattening their children into
// one shared list where duplicate KeyPaths could pair across
// siblings.
func FormatCompareAtPath(oldTree, newTree *ConfigTree, path []string) string {
	if len(path) == 0 {
		return FormatCompare(oldTree, newTree)
	}
	var oldMatches []*Node
	oldWidth := 0
	if oldTree != nil {
		oldMatches, oldWidth = navigatePathWidth(oldTree.Children, path)
	}
	var newMatches []*Node
	newWidth := 0
	if newTree != nil {
		newMatches, newWidth = navigatePathWidth(newTree.Children, path)
	}
	if len(oldMatches) == 0 && len(newMatches) == 0 {
		return ""
	}
	// The parent prefix comes from the TRUE consumed width (see
	// FormatPathSet). When exactly one side matches, its width is the
	// only one available; when both match, navigatePathWidth consumes
	// the same tokens for the same path, so either side's width gives
	// the same prefix.
	width := oldWidth
	if len(oldMatches) == 0 {
		width = newWidth
	}
	parentPrefix := append([]string(nil), path[:len(path)-width]...)
	var b strings.Builder
	diffNodes(&b, oldMatches, newMatches, parentPrefix)
	return b.String()
}

// alignSiblings aligns two sibling lists as sequences (#15168, B24-01).
//
// Pairing is by KeyPath, but duplicates are content-aware: among siblings
// sharing a KeyPath, a content-equal old/new pair is matched first, so with
// repeated containers (two `from-zone trust to-zone untrust` blocks) removing
// a policy from one block reports that policy — not a same-KeyPath survivor
// from the other block — as removed. Leftover duplicates pair in occurrence
// order. A pair is a move when it falls off the longest increasing
// subsequence of new indices (pairs taken in old order): it renders as -/+
// at its old/new positions instead of as unchanged.
type siblingAlignment struct {
	pairs    [][2]int // (oldIdx, newIdx) for every KeyPath-matched pair
	movedOld map[int]bool
	movedNew map[int]bool
	oldOnly  []int
	newOnly  []int
}

func alignSiblings(oldNodes, newNodes []*Node) siblingAlignment {
	// Authored slice order is the sequence. canonicalOrder is deliberately
	// NOT applied: it only swaps match/from before then within one node,
	// which nodesEqual already normalizes, and applying it to sibling lists
	// would hide authored policy order.
	oldByKey := make(map[string][]int)
	for i, n := range oldNodes {
		k := n.KeyPath()
		oldByKey[k] = append(oldByKey[k], i)
	}
	newByKey := make(map[string][]int)
	for i, n := range newNodes {
		k := n.KeyPath()
		newByKey[k] = append(newByKey[k], i)
	}
	a := siblingAlignment{
		movedOld: make(map[int]bool),
		movedNew: make(map[int]bool),
	}
	matchedOld := make(map[int]bool)
	matchedNew := make(map[int]bool)
	for k, olds := range oldByKey {
		news := newByKey[k]
		usedNew := make(map[int]bool, len(news))
		paired := make(map[int]int, len(olds))
		// Content-equal duplicates pair first (shape 2 above).
		for _, oi := range olds {
			for _, ni := range news {
				if !usedNew[ni] && nodesEqual(oldNodes[oi], newNodes[ni]) {
					paired[oi] = ni
					usedNew[ni] = true
					break
				}
			}
		}
		var remNew []int
		for _, ni := range news {
			if !usedNew[ni] {
				remNew = append(remNew, ni)
			}
		}
		next := 0
		for _, oi := range olds {
			ni, ok := paired[oi]
			if !ok {
				if next >= len(remNew) {
					continue // old-only: removed duplicate occurrence
				}
				ni = remNew[next]
				next++
			}
			a.pairs = append(a.pairs, [2]int{oi, ni})
			matchedOld[oi] = true
			matchedNew[ni] = true
		}
	}
	markMovedPairs(&a)
	for i := range oldNodes {
		if !matchedOld[i] {
			a.oldOnly = append(a.oldOnly, i)
		}
	}
	for i := range newNodes {
		if !matchedNew[i] {
			a.newOnly = append(a.newOnly, i)
		}
	}
	return a
}

// markMovedPairs flags pairs off the longest increasing subsequence of new
// indices (pairs in old order) as moves. Anchored pairs keep their relative
// order; a moved pair is the minimal set whose removal restores monotonicity.
func markMovedPairs(a *siblingAlignment) {
	if len(a.pairs) == 0 {
		return
	}
	sorted := make([][2]int, len(a.pairs))
	copy(sorted, a.pairs)
	slices.SortFunc(sorted, func(x, y [2]int) int { return x[0] - y[0] })
	n := len(sorted)
	dpL := make([]int, n)
	prev := make([]int, n)
	best := 0
	for i := range n {
		dpL[i] = 1
		prev[i] = -1
		for j := range i {
			if sorted[j][1] < sorted[i][1] && dpL[j]+1 > dpL[i] {
				dpL[i] = dpL[j] + 1
				prev[i] = j
			}
		}
		if dpL[i] > dpL[best] {
			best = i
		}
	}
	onLIS := make(map[int]bool, n)
	for i := best; i >= 0; i = prev[i] {
		onLIS[sorted[i][0]] = true
		if prev[i] < 0 {
			break
		}
	}
	for _, p := range a.pairs {
		if !onLIS[p[0]] {
			a.movedOld[p[0]] = true
			a.movedNew[p[1]] = true
		}
	}
}

// siblingChanged reports whether the aligned old/new pair at this level
// differs, including order-only moves of the pair itself or of any descendant
// (descendant order is judged by nodesEqual, which is order-aware).
func siblingChanged(oldNode, newNode *Node, moved bool) bool {
	if moved {
		return true
	}
	return !nodesEqual(oldNode, newNode)
}

// diffNodes compares two sets of children at the same tree level.
// It recurses into modified containers to find the deepest [edit] context,
// only showing siblings at the level where actual leaf changes occur.
// Sibling lists are compared as sequences (#15168): duplicates pair by
// occurrence and a reordered sibling renders as -/+ at its old/new positions.
func diffNodes(b *strings.Builder, oldNodes, newNodes []*Node, editPath []string) {
	al := alignSiblings(oldNodes, newNodes)
	oldIdxOfNew := make(map[int]int, len(al.pairs))
	for _, p := range al.pairs {
		oldIdxOfNew[p[1]] = p[0]
	}

	type diffEntry struct {
		oldNode *Node
		newNode *Node
		moved   bool
	}

	// Collect changed entries: anchored pairs that differ, moved pairs,
	// removed-only and added-only siblings.
	var entries []diffEntry
	changed := false
	for _, p := range al.pairs {
		o, n := oldNodes[p[0]], newNodes[p[1]]
		mv := al.movedOld[p[0]]
		if siblingChanged(o, n, mv) {
			changed = true
			entries = append(entries, diffEntry{oldNode: o, newNode: n, moved: mv})
		}
	}
	if len(al.oldOnly) > 0 || len(al.newOnly) > 0 {
		changed = true
	}
	if !changed {
		return
	}
	// Pure reorders / pure add-remove at this level are shown here, not
	// recursed past: recursing into a moved container would hide the move.
	hasMoveOrUnpaired := len(al.oldOnly) > 0 || len(al.newOnly) > 0
	for _, e := range entries {
		if e.moved {
			hasMoveOrUnpaired = true
			break
		}
	}

	if !hasMoveOrUnpaired {
		// Check if all changes can be recursed into (both old and new are blocks).
		allRecursable := true
		for _, e := range entries {
			if e.oldNode.IsLeaf || e.newNode.IsLeaf {
				allRecursable = false
				break
			}
			if e.oldNode.Inactive != e.newNode.Inactive {
				allRecursable = false
				break
			}
			if e.oldNode.Annotation != e.newNode.Annotation {
				allRecursable = false
				break
			}
		}
		if allRecursable {
			for _, e := range entries {
				childPath := append(append([]string{}, editPath...), strings.Fields(e.oldNode.KeyPath())...)
				diffNodes(b, e.oldNode.Children, e.newNode.Children, childPath)
			}
			return
		}
	}

	// Collect this level's sections before writing anything: removals
	// first (old order, #15168), then the new-order list of additions,
	// moves-in, modified and unchanged siblings. Own lines render into
	// buffers; modified block pairs become recursion arms. The [edit]
	// header attribution depends on the interleaving: a recursed child
	// prints its own deeper header, so any of this level's own lines
	// that follow it must be preceded by this level's header again
	// (#15169). Rendering own lines lazily also keeps a header with no
	// lines under it from ever being printed.
	type section struct {
		own       string // rendered own lines; empty for a recursion
		oldNode   *Node  // recursion arm, set when own is empty
		newNode   *Node
		childPath []string
	}
	var sections []section
	hasOwn := false
	indent := "    "
	addOwn := func(render func(*strings.Builder)) {
		var sb strings.Builder
		render(&sb)
		if sb.Len() > 0 {
			hasOwn = true
			sections = append(sections, section{own: sb.String()})
		}
	}
	// Removals (deleted and moved-out) render in old order first, then the
	// new-order list renders additions, moves-in, modified and unchanged
	// siblings. A move therefore appears as - <node> ... + <node> within
	// the same [edit] block, naming the moved stanza on both arms.
	removedSet := make(map[int]bool)
	for _, oi := range al.oldOnly {
		removedSet[oi] = true
	}
	for oi := range al.movedOld {
		removedSet[oi] = true
	}
	// Old-order removals (moved-out and deleted) first.
	for oi, o := range oldNodes {
		if removedSet[oi] {
			addOwn(func(sb *strings.Builder) { formatPrefixed(sb, "-", indent, o) })
		}
	}
	// New-order list: additions, moves-in, modified and unchanged siblings.
	for ni, n := range newNodes {
		oi, paired := oldIdxOfNew[ni]
		switch {
		case !paired:
			addOwn(func(sb *strings.Builder) { formatPrefixed(sb, "+", indent, n) })
		case al.movedNew[ni]:
			addOwn(func(sb *strings.Builder) { formatPrefixed(sb, "+", indent, n) })
		default:
			o := oldNodes[oi]
			switch {
			case nodesEqual(o, n):
				addOwn(func(sb *strings.Builder) {
					if o.Annotation != "" {
						fmt.Fprintf(sb, " %s/* %s */\n", indent, o.Annotation)
					}
					if o.IsLeaf {
						fmt.Fprintf(sb, " %s%s%s;\n", indent, inactivePrefix(o), o.QuotedKeyPath())
					} else {
						fmt.Fprintf(sb, " %s%s%s { ... }\n", indent, inactivePrefix(o), o.QuotedKeyPath())
					}
				})
			case o.Annotation != n.Annotation && !o.IsLeaf && !n.IsLeaf && o.Inactive == n.Inactive:
				addOwn(func(sb *strings.Builder) { formatAnnotationChange(sb, indent, o, n) })
				childPath := append(append([]string{}, editPath...), strings.Fields(o.KeyPath())...)
				sections = append(sections, section{oldNode: o, newNode: n, childPath: childPath})
			case !o.IsLeaf && !n.IsLeaf && o.Inactive == n.Inactive:
			default:
				addOwn(func(sb *strings.Builder) {
					formatPrefixed(sb, "-", indent, o)
					formatPrefixed(sb, "+", indent, n)
				})
			}
		}
	}

	// This level's [edit <path>] header — at the root (empty editPath)
	// it is a bare [edit]. Printed lazily, immediately before each run
	// of this level's own lines (#15169).
	header := "[edit]\n"
	if len(editPath) > 0 {
		header = fmt.Sprintf("[edit %s]\n", strings.Join(editPath, " "))
	}
	headerPending := hasOwn
	for _, s := range sections {
		if s.own != "" {
			if headerPending {
				b.WriteString(header)
				headerPending = false
			}
			b.WriteString(s.own)
			continue
		}
		before := b.Len()
		diffNodes(b, s.oldNode.Children, s.newNode.Children, s.childPath)
		if b.Len() > before {
			// The child printed its own header(s); this level's header
			// must be re-emitted before any following own lines.
			headerPending = hasOwn
		}
	}
}

// nodesEqual returns true if two nodes have identical content (deep comparison).
// Children are compared as a sequence (#15168): same KeyPaths in a different
// order, or a different duplicate count, are NOT equal — sibling order is
// semantic for first-match constructs (policies, terms, rules).
func nodesEqual(a, b *Node) bool {
	if a.KeyPath() != b.KeyPath() {
		return false
	}
	if a.IsLeaf != b.IsLeaf {
		return false
	}
	// #2008 H1: a pure activate/deactivate (same content, flipped Inactive)
	// is a real change — Junos shows it in `show | compare`. Treat differing
	// Inactive as inequality so the diff surfaces it.
	if a.Inactive != b.Inactive {
		return false
	}
	if a.Annotation != b.Annotation {
		return false
	}
	if a.IsLeaf {
		return true
	}
	if len(a.Children) != len(b.Children) {
		return false
	}
	aOrd := canonicalOrder(a.Children)
	bOrd := canonicalOrder(b.Children)
	for i := range aOrd {
		if !nodesEqual(aOrd[i], bOrd[i]) {
			return false
		}
	}
	return true
}

// formatPrefixed writes a node with +/- prefix at the given indent.
func formatPrefixed(b *strings.Builder, prefix, indent string, n *Node) {
	if n.Annotation != "" {
		fmt.Fprintf(b, "%s%s/* %s */\n", prefix, indent, n.Annotation)
	}
	if n.IsLeaf {
		fmt.Fprintf(b, "%s%s%s%s;\n", prefix, indent, inactivePrefix(n), n.QuotedKeyPath())
	} else {
		fmt.Fprintf(b, "%s%s%s%s {\n", prefix, indent, inactivePrefix(n), n.QuotedKeyPath())
		formatPrefixedChildren(b, prefix, indent+"    ", n.Children)
		fmt.Fprintf(b, "%s%s}\n", prefix, indent)
	}
}

// formatAnnotationChange renders an annotation-only delta (#15718).
func formatAnnotationChange(b *strings.Builder, indent string, o, n *Node) {
	if o.Annotation != "" {
		fmt.Fprintf(b, "-%s/* %s */\n", indent, o.Annotation)
	}
	if n.Annotation != "" {
		fmt.Fprintf(b, "+%s/* %s */\n", indent, n.Annotation)
	}
}

// EscapedAnnotation renders annotation text as a quoted flat-load token (#15718).
func EscapedAnnotation(s string) string {
	return `"` + keyEscaper.Replace(s) + `"`
}

// formatPrefixedChildren writes all children with the same +/- prefix.
func formatPrefixedChildren(b *strings.Builder, prefix, indent string, nodes []*Node) {
	for _, n := range canonicalOrder(nodes) {
		formatPrefixed(b, prefix, indent, n)
	}
}

// FormatJSON renders the tree as a JSON object.
func (t *ConfigTree) FormatJSON() string {
	obj := nodesToJSON(t.Children)
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data) + "\n"
}

// FormatPathJSON renders a subtree as JSON.
func (t *ConfigTree) FormatPathJSON(path []string) string {
	if len(path) == 0 {
		return t.FormatJSON()
	}
	matches, consumed := navigatePathWidth(t.Children, path)
	if len(matches) == 0 {
		return ""
	}
	parentPath := strings.Join(path[:len(path)-consumed], " ")
	obj := nodesToJSONAt(matches, parentPath)
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data) + "\n"
}

// FormatXML renders the tree as Junos-style XML configuration.
func (t *ConfigTree) FormatXML() string {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<configuration>\n")
	formatXMLNodes(&b, t.Children, 1)
	b.WriteString("</configuration>\n")
	return b.String()
}

// FormatPathXML renders a subtree as Junos-style XML.
func (t *ConfigTree) FormatPathXML(path []string) string {
	if len(path) == 0 {
		return t.FormatXML()
	}
	matches := navigatePath(t.Children, path)
	if len(matches) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<configuration>\n")
	formatXMLNodes(&b, matches, 1)
	b.WriteString("</configuration>\n")
	return b.String()
}

func formatXMLNodes(b *strings.Builder, nodes []*Node, indent int) {
	prefix := strings.Repeat("    ", indent)
	for _, n := range nodes {
		if isXMLZonePair(n) {
			formatXMLZonePair(b, n, prefix, indent)
		} else if n.IsLeaf {
			formatXMLLeaf(b, n, prefix)
		} else {
			tag := xmlTag(n.Keys[0])
			if tag != n.Keys[0] {
				formatXMLNamedEntry(b, n, prefix, indent)
				continue
			}
			fmt.Fprintf(b, "%s<%s%s>\n", prefix, tag, xmlInactiveAttr(n))
			// Extra keys become <name> elements.
			for _, k := range n.Keys[1:] {
				fmt.Fprintf(b, "%s    <name>%s</name>\n", prefix, xmlEscape(k))
			}
			formatXMLNodes(b, n.Children, indent+1)
			fmt.Fprintf(b, "%s</%s>\n", prefix, tag)
		}
	}
}

func isXMLZonePair(n *Node) bool {
	return n != nil && len(n.Keys) == 4 &&
		n.Keys[0] == "from-zone" && n.Keys[2] == "to-zone"
}

func formatXMLZonePair(b *strings.Builder, n *Node, prefix string, indent int) {
	fmt.Fprintf(b, "%s<from-zone%s>\n", prefix, xmlInactiveAttr(n))
	fmt.Fprintf(b, "%s    <name>%s</name>\n", prefix, xmlEscape(n.Keys[1]))
	fmt.Fprintf(b, "%s    <to-zone>\n", prefix)
	fmt.Fprintf(b, "%s        <name>%s</name>\n", prefix, xmlEscape(n.Keys[3]))
	if !n.IsLeaf {
		formatXMLNodes(b, n.Children, indent+2)
	}
	fmt.Fprintf(b, "%s    </to-zone>\n", prefix)
	fmt.Fprintf(b, "%s</from-zone>\n", prefix)
}

func formatXMLNamedEntry(b *strings.Builder, n *Node, prefix string, indent int) {
	fmt.Fprintf(b, "%s<entry%s>\n", prefix, xmlInactiveAttr(n))
	for _, key := range n.Keys {
		fmt.Fprintf(b, "%s    <name>%s</name>\n", prefix, xmlEscape(key))
	}
	formatXMLNodes(b, n.Children, indent+1)
	fmt.Fprintf(b, "%s</entry>\n", prefix)
}

// xmlInactiveAttr returns the Junos ` inactive="inactive"` element
// attribute for a deactivated node (#2008 H1), or "" for an active node.
func xmlInactiveAttr(n *Node) string {
	if n != nil && n.Inactive {
		return ` inactive="inactive"`
	}
	return ""
}

func formatXMLLeaf(b *strings.Builder, n *Node, prefix string) {
	attr := xmlInactiveAttr(n)
	if len(n.Keys) == 1 {
		if tag := xmlTag(n.Keys[0]); tag != n.Keys[0] {
			fmt.Fprintf(b, "%s<name%s>%s</name>\n", prefix, attr, xmlEscape(n.Keys[0]))
		} else {
			// Boolean leaf: <keyword/>
			fmt.Fprintf(b, "%s<%s%s/>\n", prefix, tag, attr)
		}
		return
	}
	// Leaf with value: <keyword>value</keyword>
	// For multi-key leaves like "address 10.0.1.0/24", emit
	// <keyword><name>val1</name></keyword>
	tag := xmlTag(n.Keys[0])
	if tag != n.Keys[0] {
		fmt.Fprintf(b, "%s<entry%s>\n", prefix, attr)
		fmt.Fprintf(b, "%s    <name>%s</name>\n", prefix, xmlEscape(n.Keys[0]))
		for _, value := range n.Keys[1:] {
			fmt.Fprintf(b, "%s    <value>%s</value>\n", prefix, xmlEscape(value))
		}
		fmt.Fprintf(b, "%s</entry>\n", prefix)
	} else if len(n.Keys) == 2 {
		fmt.Fprintf(b, "%s<%s%s>%s</%s>\n", prefix, tag, attr, xmlEscape(n.Keys[1]), tag)
	} else {
		fmt.Fprintf(b, "%s<%s%s>\n", prefix, tag, attr)
		for _, k := range n.Keys[1:] {
			fmt.Fprintf(b, "%s    <name>%s</name>\n", prefix, xmlEscape(k))
		}
		fmt.Fprintf(b, "%s</%s>\n", prefix, tag)
	}
}

// xmlTag returns a namespace-neutral XML element name, or "entry" for a
// Junos value that cannot itself be represented as an element name.
func xmlTag(s string) string {
	if !xmlNameValid(s) {
		return "entry"
	}
	return s
}

func xmlNameValid(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !xmlNameStart(r) {
				return false
			}
		} else if !xmlNameStart(r) && r != '-' && r != '.' &&
			(r < '0' || r > '9') && r != 0xB7 &&
			(r < 0x300 || r > 0x36F) && (r < 0x203F || r > 0x2040) {
			return false
		}
	}
	return true
}

func xmlNameStart(r rune) bool {
	return r == '_' ||
		(r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
		(r >= 0xC0 && r <= 0xD6) || (r >= 0xD8 && r <= 0xF6) ||
		(r >= 0xF8 && r <= 0x2FF) || (r >= 0x370 && r <= 0x37D) ||
		(r >= 0x37F && r <= 0x1FFF) || (r >= 0x200C && r <= 0x200D) ||
		(r >= 0x2070 && r <= 0x218F) || (r >= 0x2C00 && r <= 0x2FEF) ||
		(r >= 0x3001 && r <= 0xD7FF) || (r >= 0xF900 && r <= 0xFDCF) ||
		(r >= 0xFDF0 && r <= 0xFFFD) || (r >= 0x10000 && r <= 0xEFFFF)
}

// xmlEscape escapes special XML characters in text content.
func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// nodesToJSON converts a list of AST nodes to a nested JSON structure. Security
// policy siblings are represented as ordered arrays rather than name-keyed maps,
// whose marshaled key order is sorted and loses Junos rule order.
//
// A deactivated node (#2008 H1) additionally emits a collision-safe marker
// entry `"<keypath> @inactive": "inactive"` alongside its normal entry. The
// `@` sigil is not a valid Junos identifier character (lexer.isIdentChar),
// so the marker key can never collide with a real configuration key.
func nodesToJSON(nodes []*Node) map[string]interface{} {
	return nodesToJSONAt(nodes, "")
}

func nodesToJSONAt(nodes []*Node, parentPath string) map[string]interface{} {
	result := make(map[string]interface{})

	for _, n := range nodes {
		if n.Inactive {
			result[n.KeyPath()+" @inactive"] = "inactive"
		}
		if n.IsLeaf {
			// Leaf node: a lone value is scalar; multiple values remain separate
			// JSON array elements so quoted tokens cannot be confused with joined
			// unquoted tokens.
			var val interface{}
			if len(n.Keys) == 1 {
				val = true
			} else if len(n.Keys) == 2 {
				val = n.Keys[1]
			} else {
				values := make([]interface{}, len(n.Keys)-1)
				for i, value := range n.Keys[1:] {
					values[i] = value
				}
				val = values
			}
			key := n.Keys[0]
			// #5194 A3-b2-F11: a REPEATED leaf statement (e.g. two `name-server`
			// lines) must not overwrite last-wins — Junos `display json` renders
			// repeats as an ordered array. Promote the second and later
			// occurrences of a key to a []interface{}, appending in document
			// order, so no configured value is silently dropped. A single
			// occurrence retains its scalar or multi-value shape. A prior
			// container map under the same key (a malformed mixed shape) is left
			// alone — the container branch owns that key.
			if existing, ok := result[key]; ok {
				if _, isMap := existing.(map[string]interface{}); !isMap {
					result[key] = mergeJSONValues(existing, val)
				}
			} else {
				result[key] = val
			}
		} else {
			name := n.Keys[0]
			qualifier := ""
			if len(n.Keys) > 1 {
				qualifier = strings.Join(n.Keys[1:], " ")
			}

			nodePath := n.KeyPath()
			if parentPath != "" {
				nodePath = parentPath + " " + nodePath
			}
			children := nodesToJSONAt(n.Children, nodePath)

			if qualifier != "" && name == "policy" && orderedSecurityPolicySiblings(parentPath) {
				entry := map[string]interface{}{qualifier: children}
				if existing, ok := result[name].([]interface{}); ok {
					result[name] = appendOrderedPolicyJSON(existing, entry)
				} else {
					result[name] = []interface{}{entry}
				}
				continue
			}

			if qualifier != "" {
				// Named instance: e.g. "interface trust0" → {"interface": {"trust0": {...}}}
				if existing, ok := result[name]; ok {
					if m, ok := existing.(map[string]interface{}); ok {
						if previous, ok := m[qualifier]; ok {
							if previous, ok := previous.(map[string]interface{}); ok {
								mergeJSONObjects(previous, children)
							} else {
								m[qualifier] = children
							}
						} else {
							m[qualifier] = children
						}
					}
				} else {
					result[name] = map[string]interface{}{qualifier: children}
				}
			} else if existing, ok := result[name]; ok {
				if previous, ok := existing.(map[string]interface{}); ok {
					mergeJSONObjects(previous, children)
				} else {
					result[name] = children
				}
			} else {
				result[name] = children
			}
		}
	}
	return result
}

func orderedSecurityPolicySiblings(parentPath string) bool {
	return parentPath == "security policies global" ||
		strings.HasPrefix(parentPath, "security policies from-zone ")
}

// mergeJSONObjects combines repeated containers using Junos' merge semantics.
// Nested containers merge recursively; duplicate leaves accumulate in document
// order just like the repeated-leaf projection above. Ordered policy arrays
// merge same-named policy blocks in place and append new siblings in source
// order. Container objects take precedence over leaf values on malformed mixed
// shapes, matching nodesToJSON's existing leaf/container collision behavior.
func mergeJSONObjects(dst, src map[string]interface{}) {
	for key, incoming := range src {
		existing, ok := dst[key]
		if !ok {
			dst[key] = incoming
			continue
		}
		if key == "policy" {
			existingPolicies, existingIsList := existing.([]interface{})
			incomingPolicies, incomingIsList := incoming.([]interface{})
			if existingIsList && incomingIsList {
				dst[key] = mergeOrderedPolicyJSON(existingPolicies, incomingPolicies)
				continue
			}
		}
		dst[key] = mergeJSONValues(existing, incoming)
	}
}

func appendOrderedPolicyJSON(policies []interface{}, incoming interface{}) []interface{} {
	incomingEntry, ok := incoming.(map[string]interface{})
	if !ok || len(incomingEntry) != 1 {
		return append(policies, incoming)
	}
	for name, incomingChildren := range incomingEntry {
		for _, existing := range policies {
			existingEntry, ok := existing.(map[string]interface{})
			if !ok {
				continue
			}
			existingChildren, ok := existingEntry[name]
			if !ok {
				continue
			}
			existingObject, existingIsObject := existingChildren.(map[string]interface{})
			incomingObject, incomingIsObject := incomingChildren.(map[string]interface{})
			if existingIsObject && incomingIsObject {
				mergeJSONObjects(existingObject, incomingObject)
			} else {
				existingEntry[name] = incomingChildren
			}
			return policies
		}
	}
	return append(policies, incoming)
}

func mergeOrderedPolicyJSON(existing, incoming []interface{}) []interface{} {
	for _, policy := range incoming {
		existing = appendOrderedPolicyJSON(existing, policy)
	}
	return existing
}

func mergeJSONValues(existing, incoming interface{}) interface{} {
	existingObject, existingIsObject := existing.(map[string]interface{})
	incomingObject, incomingIsObject := incoming.(map[string]interface{})
	if existingIsObject {
		if incomingIsObject {
			mergeJSONObjects(existingObject, incomingObject)
		}
		return existingObject
	}
	if incomingIsObject {
		return incomingObject
	}

	existingArray, existingIsArray := existing.([]interface{})
	incomingArray, incomingIsArray := incoming.([]interface{})
	switch {
	case existingIsArray && incomingIsArray:
		return append(existingArray, incomingArray...)
	case existingIsArray:
		return append(existingArray, incoming)
	case incomingIsArray:
		merged := make([]interface{}, 1, len(incomingArray)+1)
		merged[0] = existing
		return append(merged, incomingArray...)
	default:
		return []interface{}{existing, incoming}
	}
}
