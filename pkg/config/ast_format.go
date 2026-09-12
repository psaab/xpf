package config

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
)

// FormatInheritance returns the config with inherited groups expanded and
// annotated with "## 'X' was inherited from group 'Y'" comments, matching
// Junos "show configuration | display inheritance" output.
func (t *ConfigTree) FormatInheritance() string {
	// Strip inactive subtrees BEFORE group expansion so an `inactive:`
	// apply-groups is not shown as inherited and inactive nodes don't pull in
	// group content the compiler will never apply — mirrors the
	// strip-before-expand path the compiler/commit-check use (configstore
	// schemaValidateExpandedTreeForNode). #2008 H1. cloneForExpansion does a
	// single deep copy and never aliases t.
	clone := t.cloneForExpansion()
	// #9743: normalize the clone before expanding, because both compile cores
	// do (compiler.go, and schema_walk.go via normalizeCompactForValidation).
	// Since #9620 the #8662 normalizer rewrites a brace-elided routing instance
	// into its braced shape, and group expansion binds against that shape. A
	// display that expands the RAW tree therefore omits properties the commit
	// applies:
	//
	//	groups { G { routing-instances { blue instance-type forwarding description inherited; } } }
	//
	// compiled `blue` with InstanceType=forwarding and Description=inherited,
	// while `display inheritance` showed neither; the same group body written
	// braced showed both. `instance-type forwarding` is among the omitted
	// properties, and it decides whether the daemon creates a VRF at all -- so
	// the display was wrong exactly where an operator checks what a group
	// contributes.
	//
	// The clone is fresh (cloneForExpansion never aliases t), so normalizing it
	// in place cannot reach the caller's tree.
	normalizeCompactStanzas(clone)
	if err := clone.ExpandGroupsTagged(); err != nil {
		return t.Format() // fallback to plain format on error
	}
	var b strings.Builder
	formatNodesInheritance(&b, clone.Children, 0)
	return b.String()
}

// FormatPathInheritance is like FormatPath but with inheritance annotations.
func (t *ConfigTree) FormatPathInheritance(path []string) string {
	// Strip inactive before expansion (see FormatInheritance). #2008 H1.
	clone := t.cloneForExpansion()
	// #9743, same reason as FormatInheritance above.
	normalizeCompactStanzas(clone)
	if err := clone.ExpandGroupsTagged(); err != nil {
		return t.FormatPath(path)
	}
	if len(path) == 0 {
		return clone.FormatInheritance()
	}
	matches := navigatePath(clone.Children, path)
	if len(matches) == 0 {
		return ""
	}
	var b strings.Builder
	for _, n := range matches {
		if n.IsLeaf {
			fmt.Fprintf(&b, "%s%s;\n", inactivePrefix(n), n.QuotedKeyPath())
		} else {
			fmt.Fprintf(&b, "%s%s {\n", inactivePrefix(n), n.QuotedKeyPath())
			formatNodesInheritance(&b, n.Children, 1)
			fmt.Fprintf(&b, "}\n")
		}
	}
	return b.String()
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
			formatSetNodes(&b, n.Children, prefix, prefixQuote, prefixGroup)
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
	for _, n := range canonicalOrder(nodes) {
		path, pathQuote, pathGroup := appendNodeKeysGrouped(prefix, prefixQuote, prefixGroup, n)
		switch {
		case n.IsLeaf:
			fmt.Fprintf(b, "set %s\n", joinKeysProvGrouped(path, pathQuote, pathGroup))
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
			fmt.Fprintf(b, "set %s\n", joinKeysProvGrouped(path, pathQuote, pathGroup))
		default:
			formatSetNodes(b, n.Children, path, pathQuote, pathGroup)
		}
		if n.Inactive {
			fmt.Fprintf(b, "deactivate %s\n", joinKeysProvGrouped(path, pathQuote, pathGroup))
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
	outPath := append(append([]string(nil), path...), n.Keys...)
	outQuote := make([]bool, len(path), len(outPath))
	copy(outQuote, forceQuote)
	outGroup := make([]bool, len(path), len(outPath))
	copy(outGroup, group)
	bracket := nodeKeyBracketMask(n)
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
		if run < 2 {
			parts = append(parts, quoteKeyProv(keys, forceQuote, i))
			i++
			continue
		}
		parts = append(parts, "[")
		for j := i; j < i+run; j++ {
			parts = append(parts, quoteKeyProv(keys, forceQuote, j))
		}
		parts = append(parts, "]")
		i += run
	}
	return strings.Join(parts, " ")
}

// quoteKeyProv renders keys[i] with the same authored-quote rule
// joinQuotedKeysProv applies, including its terminal-key suppression (#6673
// r11 B1): the LAST token of a line decides no grouping, so its authored quote
// is dropped, while every earlier token keeps the bit the next parse needs.
func quoteKeyProv(keys []string, forceQuote []bool, i int) string {
	if i < len(keys)-1 && i < len(forceQuote) && forceQuote[i] {
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

// diffNodes compares two sets of children at the same tree level.
// It recurses into modified containers to find the deepest [edit] context,
// only showing siblings at the level where actual leaf changes occur.
func diffNodes(b *strings.Builder, oldNodes, newNodes []*Node, editPath []string) {
	oldByKey := make(map[string]*Node, len(oldNodes))
	for _, n := range oldNodes {
		oldByKey[n.KeyPath()] = n
	}
	newByKey := make(map[string]*Node, len(newNodes))
	for _, n := range newNodes {
		newByKey[n.KeyPath()] = n
	}

	// Collect changed entries at this level.
	type diffEntry struct {
		oldNode *Node
		newNode *Node
	}

	// Use canonical ordering from new tree, then appended removed-only entries.
	seen := make(map[string]bool)
	var entries []diffEntry
	for _, n := range canonicalOrder(newNodes) {
		kp := n.KeyPath()
		seen[kp] = true
		old := oldByKey[kp]
		if old == nil || !nodesEqual(old, n) {
			entries = append(entries, diffEntry{oldNode: old, newNode: n})
		}
	}
	for _, n := range canonicalOrder(oldNodes) {
		kp := n.KeyPath()
		if !seen[kp] {
			entries = append(entries, diffEntry{oldNode: n, newNode: nil})
		}
	}

	if len(entries) == 0 {
		return
	}

	// Check if all changes can be recursed into (both old and new are blocks).
	// If so, recurse without printing siblings at this level.
	allRecursable := true
	for _, e := range entries {
		if e.oldNode == nil || e.newNode == nil {
			allRecursable = false
			break
		}
		if e.oldNode.IsLeaf || e.newNode.IsLeaf {
			allRecursable = false
			break
		}
		// #2008 H1: a pure block-level activate/deactivate (identical
		// content, flipped Inactive) has NO child diff to recurse into —
		// it must be shown at this level as a removed/added pair, not
		// silently dropped by recursing into an unchanged subtree.
		if e.oldNode.Inactive != e.newNode.Inactive {
			allRecursable = false
			break
		}
	}

	if allRecursable {
		// All changes are in modified sub-containers — recurse deeper without showing this level.
		for _, e := range entries {
			childPath := append(append([]string{}, editPath...), strings.Fields(e.oldNode.KeyPath())...)
			diffNodes(b, e.oldNode.Children, e.newNode.Children, childPath)
		}
		return
	}

	// Print [edit <path>] header — this is the level where leaf changes exist.
	if len(editPath) > 0 {
		fmt.Fprintf(b, "[edit %s]\n", strings.Join(editPath, " "))
	}

	// Show all children at this level: unchanged as collapsed, added/removed with prefix.
	// Merge all nodes from both old and new in canonical order (new first, then old-only).
	seen2 := make(map[string]bool)
	var allEntries []diffEntry
	for _, n := range canonicalOrder(newNodes) {
		kp := n.KeyPath()
		seen2[kp] = true
		allEntries = append(allEntries, diffEntry{oldNode: oldByKey[kp], newNode: n})
	}
	for _, n := range canonicalOrder(oldNodes) {
		if !seen2[n.KeyPath()] {
			allEntries = append(allEntries, diffEntry{oldNode: n, newNode: nil})
		}
	}

	indent := "    "
	for _, e := range allEntries {
		switch {
		case e.oldNode == nil:
			// Added
			formatPrefixed(b, "+", indent, e.newNode)
		case e.newNode == nil:
			// Removed
			formatPrefixed(b, "-", indent, e.oldNode)
		case nodesEqual(e.oldNode, e.newNode):
			// Unchanged — show collapsed
			if e.oldNode.IsLeaf {
				fmt.Fprintf(b, " %s%s%s;\n", indent, inactivePrefix(e.oldNode), e.oldNode.QuotedKeyPath())
			} else {
				fmt.Fprintf(b, " %s%s%s { ... }\n", indent, inactivePrefix(e.oldNode), e.oldNode.QuotedKeyPath())
			}
		default:
			// Modified
			if !e.oldNode.IsLeaf && !e.newNode.IsLeaf &&
				e.oldNode.Inactive == e.newNode.Inactive {
				// Both are blocks with the same active/inactive state — show
				// [edit] context for the sub-container. A pure block-level
				// activate/deactivate (#2008 H1) falls through to the -/+
				// pair below so the change is visible.
				childPath := append(append([]string{}, editPath...), strings.Fields(e.oldNode.KeyPath())...)
				diffNodes(b, e.oldNode.Children, e.newNode.Children, childPath)
			} else {
				formatPrefixed(b, "-", indent, e.oldNode)
				formatPrefixed(b, "+", indent, e.newNode)
			}
		}
	}
}

// nodesEqual returns true if two nodes have identical content (deep comparison).
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
	if a.IsLeaf {
		return true
	}
	if len(a.Children) != len(b.Children) {
		return false
	}
	bByKey := make(map[string]*Node, len(b.Children))
	for _, n := range b.Children {
		bByKey[n.KeyPath()] = n
	}
	for _, ac := range a.Children {
		bc, ok := bByKey[ac.KeyPath()]
		if !ok {
			return false
		}
		if !nodesEqual(ac, bc) {
			return false
		}
	}
	return true
}

// formatPrefixed writes a node with +/- prefix at the given indent.
func formatPrefixed(b *strings.Builder, prefix, indent string, n *Node) {
	if n.IsLeaf {
		fmt.Fprintf(b, "%s%s%s%s;\n", prefix, indent, inactivePrefix(n), n.QuotedKeyPath())
	} else {
		fmt.Fprintf(b, "%s%s%s%s {\n", prefix, indent, inactivePrefix(n), n.QuotedKeyPath())
		formatPrefixedChildren(b, prefix, indent+"    ", n.Children)
		fmt.Fprintf(b, "%s%s}\n", prefix, indent)
	}
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

// FormatPathJSON renders a subtree as a JSON object.
func (t *ConfigTree) FormatPathJSON(path []string) string {
	if len(path) == 0 {
		return t.FormatJSON()
	}
	matches := navigatePath(t.Children, path)
	if len(matches) == 0 {
		return ""
	}
	obj := nodesToJSON(matches)
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
		if n.IsLeaf {
			formatXMLLeaf(b, n, prefix)
		} else {
			tag := xmlTag(n.Keys[0])
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
		// Boolean leaf: <keyword/>
		fmt.Fprintf(b, "%s<%s%s/>\n", prefix, xmlTag(n.Keys[0]), attr)
		return
	}
	// Leaf with value: <keyword>value</keyword>
	// For multi-key leaves like "address 10.0.1.0/24", emit
	// <keyword><name>val1</name></keyword>
	tag := xmlTag(n.Keys[0])
	if len(n.Keys) == 2 {
		fmt.Fprintf(b, "%s<%s%s>%s</%s>\n", prefix, tag, attr, xmlEscape(n.Keys[1]), tag)
	} else {
		fmt.Fprintf(b, "%s<%s%s>\n", prefix, tag, attr)
		for _, k := range n.Keys[1:] {
			fmt.Fprintf(b, "%s    <name>%s</name>\n", prefix, xmlEscape(k))
		}
		fmt.Fprintf(b, "%s</%s>\n", prefix, tag)
	}
}

// xmlTag sanitizes a Junos keyword into a valid XML element name.
func xmlTag(s string) string {
	// Junos keywords already use valid XML chars (letters, digits, hyphens).
	return s
}

// xmlEscape escapes special XML characters in text content.
func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// nodesToJSON converts a list of AST nodes to a nested map structure.
//
// A deactivated node (#2008 H1) additionally emits a collision-safe marker
// entry `"<keypath> @inactive": "inactive"` alongside its normal entry. The
// `@` sigil is not a valid Junos identifier character (lexer.isIdentChar),
// so the marker key can never collide with a real configuration key.
func nodesToJSON(nodes []*Node) map[string]interface{} {
	result := make(map[string]interface{})

	for _, n := range nodes {
		if n.Inactive {
			result[n.KeyPath()+" @inactive"] = "inactive"
		}
		if n.IsLeaf {
			// Leaf node: key is first key, value is remaining keys joined.
			var val interface{}
			if len(n.Keys) == 1 {
				val = true
			} else if len(n.Keys) == 2 {
				val = n.Keys[1]
			} else {
				val = strings.Join(n.Keys[1:], " ")
			}
			key := n.Keys[0]
			// #5194 A3-b2-F11: a REPEATED leaf statement (e.g. two `name-server`
			// lines) must not overwrite last-wins — Junos `display json` renders
			// repeats as an ordered array. Promote the second and later
			// occurrences of a key to a []interface{}, appending in document
			// order, so no configured value is silently dropped. A single
			// occurrence stays scalar (unchanged). A prior container map under
			// the same key (a malformed mixed leaf/container shape) is left
			// alone — the container branch owns that key.
			if existing, ok := result[key]; ok {
				if _, isMap := existing.(map[string]interface{}); !isMap {
					if arr, isArr := existing.([]interface{}); isArr {
						result[key] = append(arr, val)
					} else {
						result[key] = []interface{}{existing, val}
					}
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

			children := nodesToJSON(n.Children)

			if qualifier != "" {
				// Named instance: e.g. "interface trust0" → {"interface": {"trust0": {...}}}
				if existing, ok := result[name]; ok {
					if m, ok := existing.(map[string]interface{}); ok {
						m[qualifier] = children
					}
				} else {
					result[name] = map[string]interface{}{qualifier: children}
				}
			} else {
				result[name] = children
			}
		}
	}
	return result
}
