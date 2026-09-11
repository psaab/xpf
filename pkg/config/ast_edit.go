package config

import (
	"errors"
	"fmt"
	"strings"
)

// ErrPathNotFound is the sentinel every DeletePath "target does not exist"
// error wraps (#4423 M9). Callers that TOLERATE a missing delete — notably the
// event-options change-configuration batch, whose Junos semantics treat a
// delete of an absent path as a no-op rather than a failure — must test it with
// errors.Is(err, config.ErrPathNotFound) rather than substring-matching the
// message text, so a future reword of the human-readable detail cannot silently
// turn a tolerated missing-delete into a batch-aborting hard reject. The
// wrapped messages keep their original "path not found: ..." prefix, so any
// remaining string matchers continue to work during the transition.
var ErrPathNotFound = errors.New("path not found")

// CopyPath copies a subtree from src to dst, replacing the source node's keys
// with the destination's last N keys (N = len(sourceNode.Keys)).
//
// Both the source node and the destination PARENT are resolved by FULL identity
// via the longest-consumed-match navigator (findNodeWithParent / childrenAtPath) —
// the SAME resolver RenamePath uses — NOT the first-keyword-match insertNode the
// pre-#5822 implementation used. insertNode stopped at the FIRST child whose
// first keyword matched (matchNodeKeys returns a 1-key partial match when the
// keyword matches but later keys differ), so a copy whose destination parent was
// a NON-FIRST same-keyword sibling — e.g. `copy ... to policy Z` with siblings
// [policy A, policy B, policy Z] — descended into `policy A` and inserted the
// clone under the WRONG subtree (insertion-order dependent). This is the copy-side
// sibling of the #3982 rename-side fix; keeping two navigators with different
// ambiguity semantics WAS the bug, so insertNode is removed and both edit paths
// now share one resolver.
//
// Collision + atomicity: a copy whose new identity already exists under the
// destination parent is REJECTED (not silently merged or duplicated), mirroring
// RenamePath's collision guard. The destination parent is resolved and the
// collision checked BEFORE any mutation, and the source is cloned only after both
// pass, so a failed copy (missing destination parent OR collision) leaves the
// tree byte-for-byte unchanged. A missing destination parent wraps ErrPathNotFound
// so callers can classify it with errors.Is.
func (t *ConfigTree) CopyPath(src, dst []string) error {
	if len(src) == 0 || len(dst) == 0 {
		return fmt.Errorf("empty path")
	}
	srcNode, _, err := t.findNodeWithParent(src)
	if err != nil {
		return fmt.Errorf("%w: source %s", ErrPathNotFound, strings.Join(src, " "))
	}
	nk := len(srcNode.Keys)
	if len(dst) < nk {
		return fmt.Errorf("destination path too short")
	}
	newKeys := append([]string(nil), dst[len(dst)-nk:]...)
	dstParentPath := dst[:len(dst)-nk]

	// Resolve the destination parent via the longest-consumed-match navigator so a
	// non-first same-keyword sibling parent is reached by full identity (#5822).
	dstParent, err := t.childrenAtPath(dstParentPath)
	if err != nil {
		return fmt.Errorf("%w: destination parent %s", ErrPathNotFound, strings.Join(dstParentPath, " "))
	}
	// Collision guard: reject a copy onto an existing same-identity target rather
	// than silently duplicating it. Checked BEFORE any mutation.
	for _, n := range *dstParent {
		if keysEqual(n.Keys, newKeys) {
			return fmt.Errorf("copy target already exists: %s", strings.Join(dst, " "))
		}
	}
	// All checks passed — now (and only now) mutate: clone the source subtree,
	// stamp the destination keys, and append under the resolved parent.
	cloned := cloneNodes([]*Node{srcNode})[0]
	cloned.Keys = newKeys
	// The copy takes a NEW identity from the destination path, so the source's
	// per-key quote provenance no longer describes it (#6673). Dropping it is
	// the honest state — "unknown", never a false "these were bare".
	cloned.KeysQuoted = nil
	*dstParent = append(*dstParent, cloned)
	return nil
}

// RenamePath moves a subtree from src to dst path.
//
// The source node is resolved by its FULL identity (the named key, e.g.
// `policy <name>` / `term <name>`) via findNodeWithParent, which prefers the
// longest key match over the first keyword match. This is what lets a
// NON-FIRST same-keyword sibling be renamed: the earlier removeNode-based
// implementation broke on the first child whose FIRST key matched, so
// `rename policy B to B2` with siblings [A B C] resolved `policy A`, descended
// into it, and failed "source not found" (the #3982 read-all-siblings defect,
// the config-edit sibling of #3842/#2419/#3975/#3980).
//
// A rename that only changes the name (the common case: destination parent ==
// source parent) is performed IN PLACE so sibling order is preserved. A rename
// that moves the node under a different parent removes it from the source and
// appends it to the destination. Either way the renamed node keeps its
// children / sub-config. A rename whose new identity collides with an existing
// sibling under the destination parent is rejected rather than creating a
// duplicate.
func (t *ConfigTree) RenamePath(src, dst []string) error {
	if len(src) == 0 || len(dst) == 0 {
		return fmt.Errorf("empty path")
	}
	srcNode, srcParent, err := t.findNodeWithParent(src)
	if err != nil {
		return fmt.Errorf("source not found: %s", strings.Join(src, " "))
	}
	nk := len(srcNode.Keys)
	if len(dst) < nk {
		return fmt.Errorf("destination path too short")
	}
	newKeys := append([]string(nil), dst[len(dst)-nk:]...)
	dstParentPath := dst[:len(dst)-nk]
	dstParent, err := t.childrenAtPath(dstParentPath)
	if err != nil {
		return fmt.Errorf("destination parent not found: %s", strings.Join(dstParentPath, " "))
	}
	// Collision guard: reject a rename whose new identity duplicates an
	// existing sibling under the destination parent (excluding the node being
	// renamed, so renaming to the same name is a no-op rather than an error).
	for _, n := range *dstParent {
		if n != srcNode && keysEqual(n.Keys, newKeys) {
			return fmt.Errorf("rename target already exists: %s", strings.Join(dst, " "))
		}
	}
	if dstParent == srcParent {
		// Same parent: rename in place, preserving sibling order and children.
		srcNode.Keys = newKeys
		srcNode.KeysQuoted = nil // new identity — see CopyPath (#6673)
		return nil
	}
	// Different parent: detach from the source parent and append to the
	// destination parent, keeping the node's children/sub-config.
	for i, n := range *srcParent {
		if n == srcNode {
			*srcParent = append((*srcParent)[:i], (*srcParent)[i+1:]...)
			break
		}
	}
	srcNode.Keys = newKeys
	srcNode.KeysQuoted = nil // new identity — see CopyPath (#6673)
	*dstParent = append(*dstParent, srcNode)
	return nil
}

// childrenAtPath navigates to the node identified by path and returns a pointer
// to its children slice. An empty path returns the tree root's children. Like
// findNodeWithParent it prefers the longest key match at each level so a
// same-keyword sibling in the path is resolved by full identity.
func (t *ConfigTree) childrenAtPath(path []string) (*[]*Node, error) {
	children := &t.Children
	pos := 0
	for pos < len(path) {
		var bestChild *Node
		bestConsumed := 0
		for _, child := range *children {
			consumed := matchNodeKeys(child, path, pos)
			if consumed > bestConsumed {
				bestChild = child
				bestConsumed = consumed
			}
		}
		if bestChild == nil {
			return nil, fmt.Errorf("path element %q not found", path[pos])
		}
		children = &bestChild.Children
		pos += bestConsumed
	}
	return children, nil
}

// InsertBefore moves an existing element before another element in the same
// parent's children list. Both elements must exist under the same parent.
// elementPath is the full path to the element to move.
// refPath is the full path to the reference element.
func (t *ConfigTree) InsertBefore(elementPath, refPath []string) error {
	return t.insertRelative(elementPath, refPath, false)
}

// InsertAfter moves an existing element after another element in the same
// parent's children list.
func (t *ConfigTree) InsertAfter(elementPath, refPath []string) error {
	return t.insertRelative(elementPath, refPath, true)
}

func (t *ConfigTree) insertRelative(elementPath, refPath []string, after bool) error {
	if len(elementPath) == 0 || len(refPath) == 0 {
		return fmt.Errorf("empty path")
	}

	// Find the element and its parent children slice.
	elem, parentChildren, err := t.findNodeWithParent(elementPath)
	if err != nil {
		return fmt.Errorf("element not found: %s", strings.Join(elementPath, " "))
	}

	// Find the reference element — must be in the same parent.
	refNode, refParent, err := t.findNodeWithParent(refPath)
	if err != nil {
		return fmt.Errorf("reference not found: %s", strings.Join(refPath, " "))
	}

	// Both must share the same parent (same children slice).
	if parentChildren != refParent {
		return fmt.Errorf("elements must be siblings (same parent)")
	}

	if elem == refNode {
		return nil // already in position
	}

	// Find and remove the element from the children slice.
	elemIdx := -1
	for i, c := range *parentChildren {
		if c == elem {
			elemIdx = i
			break
		}
	}
	if elemIdx < 0 {
		return fmt.Errorf("element not found in parent")
	}
	*parentChildren = append((*parentChildren)[:elemIdx], (*parentChildren)[elemIdx+1:]...)

	// Find the reference's new index (may have shifted after removal).
	refIdx := -1
	for i, c := range *parentChildren {
		if c == refNode {
			refIdx = i
			break
		}
	}
	if refIdx < 0 {
		return fmt.Errorf("reference not found in parent")
	}

	// Insert before or after the reference.
	insertAt := refIdx
	if after {
		insertAt = refIdx + 1
	}

	// Grow and shift.
	*parentChildren = append(*parentChildren, nil)
	copy((*parentChildren)[insertAt+1:], (*parentChildren)[insertAt:])
	(*parentChildren)[insertAt] = elem
	return nil
}

// refreshDupKeysQuoted re-stamps an already-present duplicate leaf's authored
// quote provenance from the CURRENT set command (#6673 r11 B2).
//
// SetPath's dedup arms short-circuit on keysEqual, which compares the key TEXT
// and nothing else. Two set commands with identical text but different quoting
// are not the same statement — `commands "set" system` and `commands set
// "system"` produce the same Keys and opposite groupings — so returning early
// left the FIRST command's mask describing the SECOND command's tokens. The
// lengths still agree, so nothing downstream can notice; the node simply
// carries a mask that was never authored for it. Measured before this fix:
// re-issuing the path with mask [true,false] left [false,true] in place and the
// group joined where it should have split.
//
// The LATER command wins, which is what `set` means everywhere else here — the
// single-value arm a few lines up replaces the node outright for the same
// reason.
func refreshDupKeysQuoted(n *Node, quoted []bool) {
	if n == nil {
		return
	}
	n.setKeysQuoted(quoted)
}

// widenKeyCountToGroupEnd extends a node's key slice path[from:end) so that no
// authored bracket group is CUT IN HALF by it, and returns the new end (#6668).
//
// The flat-set walks split a path into nodes by consuming `1 + schema.args`
// tokens per level. That rule cannot express a container carrying more keys
// than its arity, which is exactly what a bracket list authored at a container
// position is — `interfaces [ ge-0/0/0 ge-0/0/1 ] { ... }` is ONE node with two
// keys. Replaying its flattened token run made the first token the container
// and demoted the rest to a LEAF, re-parenting the body under it; every token
// survived, so nothing downstream could notice.
//
// Overlap is the test, not "the group starts at from". A group need not begin
// where the node does: `security-zone [ trust dmz ]` puts the bracket on the
// node's SECOND and THIRD keys, and the arity rule would take
// ["security-zone","trust"] and leave `dmz` to open a node of its own, splitting
// one container into two.
//
// It only ever GROWS the slice, and THIS function is where that is decided —
// the call sites assign its result unconditionally rather than re-testing it,
// so the property has one owner and a change here is not silently masked by a
// second guard. A group shorter than the arity leaves the node exactly as the
// arity rule built it, so a malformed `[ x ]` at a two-token position cannot
// truncate a keyed container's identity and split one node into two. grouped
// may be nil, which is the pre-#6668 behaviour: nothing is widened.
func widenKeyCountToGroupEnd(grouped []bool, from, end int) int {
	if grouped == nil {
		return end
	}
	for k := from; k < end && k < len(grouped); k++ {
		if !grouped[k] {
			continue
		}
		j := k
		for j < len(grouped) && grouped[j] {
			j++
		}
		if j > end {
			end = j
		}
	}
	return end
}

// bracketGroupStartLen reports the length of an authored bracket group that
// begins exactly at from, or 0 when from is not a group's first token (#6668).
// Used only where no schema level is available to supply a starting arity, so
// the group itself has to say where the node's keys end.
func bracketGroupStartLen(grouped []bool, from int) int {
	if grouped == nil || from < 0 || from >= len(grouped) || !grouped[from] {
		return 0
	}
	if from > 0 && grouped[from-1] {
		return 0 // continuation of an earlier group, not its start
	}
	n := 0
	for from+n < len(grouped) && grouped[from+n] {
		n++
	}
	return n
}

// SetPath inserts a leaf node at the given path in the tree.
// Intermediate block nodes are created as needed. The schema determines
// which keywords are containers (and how many extra args they consume)
// versus leaves (all remaining tokens form the leaf's Keys).
func (t *ConfigTree) SetPath(path []string) error {
	return t.SetPathQuoted(path, nil)
}

// SetPathQuoted is SetPath carrying per-token QUOTE PROVENANCE (#6673):
// quoted[i] reports whether path[i] was authored as a quoted string. Every
// node this call creates records the provenance of the path tokens that became
// its keys, so a reader that must tell a bracketed LIST from one multi-word
// unquoted statement (eventMultiWordLeafValues) is not left guessing from the
// token text. Pass nil — as plain SetPath does — when the path was synthesized
// rather than authored; the created nodes then carry no provenance, which is
// exactly the pre-#6673 state and never a false "this was bare" claim.
//
// quoted must be nil or the same length as path; a mismatched length is
// treated as nil rather than silently misattributing quotes to the wrong
// tokens.
func (t *ConfigTree) SetPathQuoted(path []string, quoted []bool) error {
	return t.SetPathQuotedGrouped(path, quoted, nil)
}

// SetPathQuotedGrouped is SetPathQuoted carrying per-token BRACKET GROUPING
// (#6668): grouped[i] reports whether path[i] was authored inside a
// `[ ... ]` list.
//
// WHAT THE GROUPING DECIDES, and why arity cannot decide it. This walk splits a
// flat path into nodes by consuming `1 + schema.args` tokens per level. That
// rule can express a container whose key count IS its arity and nothing wider,
// so a container node carrying a bracket list —
//
//	interfaces { [ ge-0/0/0 ge-0/0/1 ] { host-inbound-traffic { ... } } }
//	  -> ONE node, Keys=["ge-0/0/0","ge-0/0/1"], with the body as its children
//
// — had no flat spelling at all. Replaying its flattened token run made
// `ge-0/0/0` the container and demoted `ge-0/0/1` to the FIRST KEY OF A LEAF,
// with the whole body re-parented under it. Every token survived, so the
// corruption is invisible to a token-count or an idempotency check: re-running
// FormatSet over the damaged tree reproduces the SAME line, a fixed point.
//
// A bracket only ever WIDENS a key group — `nodeKeyCount` is raised to the run
// length, never lowered below `1 + args`. A short group at a wide position
// (`[ x ]` where the schema takes two tokens) therefore behaves exactly as the
// bare tokens would, rather than truncating the node's identity.
//
// grouped may be nil (or a length that disagrees with path), which is the
// pre-#6668 behaviour: every group is one node's arity and nothing is widened.
// It is never a false "this was bare" claim — a nil mask asserts nothing.
func (t *ConfigTree) SetPathQuotedGrouped(path []string, quoted, grouped []bool) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}
	if len(quoted) != len(path) {
		quoted = nil
	}
	if len(grouped) != len(path) {
		grouped = nil
	}
	// quotedRange returns the provenance for path[from:to] — every node built
	// below takes its keys from exactly one CONTIGUOUS range of path (the
	// schema slice, plus any compound-key or trailing-value tokens, which are
	// consumed in order), so the mask is always this simple sub-slice.
	quotedRange := func(from, to int) []bool {
		if quoted == nil || from < 0 || to > len(quoted) || from > to {
			return nil
		}
		return quoted[from:to]
	}
	// groupedRange returns the bracket provenance for path[from:to], matching
	// quotedRange, so a node rebuilt from a flat line re-renders with the same
	// bracket the operator authored (#6668).
	groupedRange := func(from, to int) []bool {
		if grouped == nil || from < 0 || to > len(grouped) || from > to {
			return nil
		}
		return grouped[from:to]
	}
	current := &t.Children
	schema := setSchema
	// #8657: true when the walk has just descended into a `valueList` node, so
	// the tokens now being read are its MODIFIERS and must land as siblings of
	// each other rather than nesting.
	inValueListModifiers := false
	i := 0

	for i < len(path) {
		keyword := path[i]
		keyStart := i

		// Look up keyword in current schema level (#9685: an apply statement at
		// a wildcard slot is the statement, not an instance name).
		childSchema := schemaChildFor(schema, keyword)

		if childSchema == nil {
			// #6668: an unmodeled position still honours an authored bracket
			// group that does not reach the end of the path — those tokens are
			// ONE node's keys and what follows is its body, so the node must be
			// a CONTAINER. Without this the whole tail collapses into a single
			// leaf and the body is fused onto the group's keys.
			if run := bracketGroupStartLen(grouped, i); run > 0 && i+run < len(path) {
				nodeKeys := path[i : i+run]
				i += run
				found := false
				for _, n := range *current {
					if !n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
						current = &n.Children
						found = true
						break
					}
				}
				if !found {
					newNode := &Node{Keys: append([]string(nil), nodeKeys...)}
					newNode.setKeysQuoted(quotedRange(keyStart, i))
					newNode.setKeysBracketed(groupedRange(keyStart, i))
					*current = append(*current, newNode)
					current = &newNode.Children
				}
				schema = nil
				continue
			}
			// No schema match: all remaining tokens form a leaf node.
			// Skip if exact duplicate already exists.
			remaining := path[i:]
			for _, n := range *current {
				if n.IsLeaf && keysEqual(n.Keys, remaining) {
					refreshDupKeysQuoted(n, quotedRange(i, len(path)))
					return nil
				}
			}
			leaf := &Node{
				Keys:   append([]string(nil), remaining...),
				IsLeaf: true,
			}
			leaf.setKeysQuoted(quotedRange(i, len(path)))
			leaf.setKeysBracketed(groupedRange(i, len(path)))
			*current = append(*current, leaf)
			return nil
		}

		// Consume keyword + extra args as this node's keys.
		nodeKeyCount := 1 + childSchema.args
		// #6668: an authored bracket group carries the node's full key list,
		// which the arity rule cannot infer. widenKeyCountToGroupEnd owns the
		// widen-only rule; assign its result rather than re-testing it here.
		nodeKeyCount = widenKeyCountToGroupEnd(grouped, i, i+nodeKeyCount) - i
		if i+nodeKeyCount > len(path) {
			// Not enough tokens; treat remainder as leaf.
			leaf := &Node{
				Keys:   append([]string(nil), path[i:]...),
				IsLeaf: true,
			}
			leaf.setKeysQuoted(quotedRange(i, len(path)))
			leaf.setKeysBracketed(groupedRange(i, len(path)))
			*current = append(*current, leaf)
			return nil
		}

		nodeKeys := path[i : i+nodeKeyCount]
		i += nodeKeyCount

		// Compound key: children form part of the key rather than
		// separate hierarchy levels (e.g. "family inet6" is a single
		// node with Keys=["family","inet6"], not nested nodes).
		if childSchema.compoundKey && i < len(path) {
			if sub, ok := childSchema.children[path[i]]; ok {
				nodeKeys = append(append([]string(nil), nodeKeys...), path[i])
				i++
				childSchema = sub
			}
		}

		if i >= len(path) {
			// No more tokens after this node: it's a leaf.
			if childSchema.args > 0 && !childSchema.multi && childSchema.children == nil {
				// Single-value leaf with no sub-structure (e.g. host-name, description): replace existing.
				// Nodes with children are named containers that may appear as terminal leaves
				// with different values (e.g. "interface eth0", "interface eth1").
				// Replace the first match and remove all subsequent duplicates.
				replaced := false
				filtered := (*current)[:0] // reuse backing array
				for _, n := range *current {
					if n.IsLeaf && len(n.Keys) > 0 && n.Keys[0] == nodeKeys[0] {
						if !replaced {
							repl := &Node{
								Keys:   append([]string(nil), nodeKeys...),
								IsLeaf: true,
							}
							repl.setKeysQuoted(quotedRange(keyStart, i))
							repl.setKeysBracketed(groupedRange(keyStart, i))
							filtered = append(filtered, repl)
							replaced = true
						}
						// skip all duplicate entries
						continue
					}
					filtered = append(filtered, n)
				}
				if replaced {
					*current = filtered
					return nil
				}
			} else {
				// Flag leaf (args == 0) or multi-value leaf: skip if exact duplicate.
				for _, n := range *current {
					if n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
						refreshDupKeysQuoted(n, quotedRange(keyStart, i))
						return nil
					}
				}
			}
			leaf := &Node{
				Keys:   append([]string(nil), nodeKeys...),
				IsLeaf: true,
			}
			leaf.setKeysQuoted(quotedRange(keyStart, i))
			leaf.setKeysBracketed(groupedRange(keyStart, i))
			*current = append(*current, leaf)
			return nil
		}

		// More tokens follow. If the schema says this is a multi-value leaf
		// with no children, the remaining tokens are either sibling
		// statements at this level or trailing VALUE tokens belonging to
		// this leaf.
		//
		// (a) Next token is a known sibling keyword: emit this leaf and
		//     continue at the same level so remaining tokens become
		//     siblings (e.g. "match" children: destination-address any
		//     source-address any application any).
		//
		// (b) Next token is NOT a sibling: it is a trailing value for this
		//     same leaf. This is the flat-set bracket-list case (#2419):
		//     `set ... from protocol [ tcp udp icmp ]` arrives bracket-
		//     stripped as path [..., protocol, tcp, udp, icmp]. The
		//     hierarchical parser yields a SINGLE leaf
		//     Keys=[protocol tcp udp icmp]; the flat-set path must match
		//     that shape. Consume every following non-sibling token onto
		//     this node's keys and emit one leaf — never split the tail
		//     into an orphan child Keys=[udp icmp], which dropped all but
		//     the first list value at the compiler. A mid-key spelling like
		//     `destination-port 20000 to 20003` is handled the same way:
		//     none of "20000", "to", "20003" are siblings, so all land on
		//     the one leaf.
		// A multi leaf collapses a trailing value list onto ONE node. This
		// runs for a plain multi leaf (children == nil, the #2419 case) and,
		// via the valueList opt-in, for a multi leaf that ALSO declares
		// modifier children (the #3872 static `next-hop [ a b ]`, whose only
		// child is the `interface` modifier). A multi leaf WITH children that
		// does NOT opt in (every CoS named container) is untouched — the guard
		// keeps it on the container path below, exactly as before.
		if childSchema.multi && (childSchema.children == nil || childSchema.valueList) && i < len(path) {
			nextToken := path[i]
			_, nextIsSibling := schema.children[nextToken]
			// #9685: after an apply statement the remaining tokens are group
			// names, never an instance under this node's wildcard slot.
			if !nextIsSibling && schema.wildcard != nil && childSchema != applyStatementSchema {
				nextIsSibling = true
			}
			// When the next token names a known child of THIS node (only
			// possible for a valueList node — plain multi leaves have no
			// children, so indexing a nil map yields ok == false), the
			// occurrence is a CONTAINER: fall through to the container path so
			// the modifier attaches as a child rather than being absorbed as a
			// bogus extra value.
			if _, nextIsChild := childSchema.children[nextToken]; !nextIsChild {
				if !nextIsSibling {
					// Trailing values for this leaf: absorb every following
					// token that is neither a sibling keyword nor a known
					// child so the flat-set list collapses onto one node,
					// matching the hierarchical AST. (case (b) only runs when
					// schema.wildcard == nil — the wildcard check above forces
					// nextIsSibling=true otherwise.)
					nodeKeys = append([]string(nil), nodeKeys...)
					for i < len(path) {
						if _, sib := schema.children[path[i]]; sib {
							break
						}
						if _, ch := childSchema.children[path[i]]; ch {
							break
						}
						nodeKeys = append(nodeKeys, path[i])
						i++
					}
				}
				// Dedup: skip if exact leaf already exists.
				dup := false
				for _, n := range *current {
					if n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
						refreshDupKeysQuoted(n, quotedRange(keyStart, i))
						dup = true
						break
					}
				}
				if !dup {
					listLeaf := &Node{
						Keys:   append([]string(nil), nodeKeys...),
						IsLeaf: true,
					}
					listLeaf.setKeysQuoted(quotedRange(keyStart, i))
					listLeaf.setKeysBracketed(groupedRange(keyStart, i))
					*current = append(*current, listLeaf)
				}
				if i >= len(path) {
					return nil
				}
				// Don't descend — continue at same level for next sibling.
				continue
			}
			// nextIsChild: fall through to the container path so the modifier
			// child (e.g. `interface`) attaches under this node.
		}

		// #8657: a schema node that declares NO sub-structure cannot be a
		// container, so descending into it is always wrong. Emit it as a leaf
		// and continue at THIS level, making the next token a SIBLING.
		//
		// Without this, `set system ntp server 1.2.3.4 prefer version 4` built
		//
		//	[server 1.2.3.4]
		//	  [prefer]
		//	    [version 4]      <- a CHILD of prefer
		//
		// and the compiler, which scans SIBLINGS of the server node, saw only
		// the first modifier. Everything after it was unreachable, so exactly
		// one modifier survived and which one depended on authoring ORDER. The
		// hierarchical spelling of the same config produced siblings and kept
		// both, so one configuration compiled two ways — the dual-shape
		// divergence class CLAUDE.md warns about.
		//
		// SCOPED TO valueList MODIFIERS, and the scope was measured rather than
		// reasoned. The obvious wider rule — "any node declaring no
		// sub-structure cannot be a container" — is true in the abstract and
		// breaks 23 cells across `pkg/api`, `pkg/cli` and `pkg/config`: the
		// `applications` / `application-set` bodies rely on the existing
		// descent for repeated childless keywords, and flattening them turns
		// one definition with members into several duplicate definitions.
		//
		// So this fires only for a modifier of a `valueList` node — the leaf
		// shape that declares BOTH values and modifier children, which is the
		// only place successive modifiers are expected to be siblings. A
		// container, a wildcard node, a compound key and every non-valueList
		// parent are untouched. `args` are already consumed into nodeKeys
		// above, so the leaf carries its own value.
		if inValueListModifiers && childSchema.children == nil && childSchema.wildcard == nil {
			// Absorb this modifier's own trailing VALUE tokens before emitting
			// it. `schema` here is the valueList node, so its children are the
			// modifier keywords: a following token that names one is the NEXT
			// modifier (a sibling), and anything else is a value belonging to
			// THIS one.
			//
			// Without this the arm emits `1 + args` tokens and orphans the
			// rest as bogus siblings, which the #2419 differential gate caught
			// on `static route ... next-hop <gw> interface a b` — a site that
			// agreed across all six spellings before and would have started
			// disagreeing. The gate found it; it was not reasoned out.
			nodeKeys = append([]string(nil), nodeKeys...)
			for i < len(path) {
				if _, sib := schema.children[path[i]]; sib {
					break
				}
				nodeKeys = append(nodeKeys, path[i])
				i++
			}
			dup := false
			for _, n := range *current {
				if n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
					refreshDupKeysQuoted(n, quotedRange(keyStart, i))
					dup = true
					break
				}
			}
			if !dup {
				modLeaf := &Node{
					Keys:   append([]string(nil), nodeKeys...),
					IsLeaf: true,
				}
				modLeaf.setKeysQuoted(quotedRange(keyStart, i))
				modLeaf.setKeysBracketed(groupedRange(keyStart, i))
				*current = append(*current, modLeaf)
			}
			continue
		}

		// This is a container (or a leaf with trailing value tokens).
		// Find or create matching node.
		found := false
		for _, n := range *current {
			if !n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
				current = &n.Children
				found = true
				break
			}
		}
		if !found {
			newNode := &Node{
				Keys: append([]string(nil), nodeKeys...),
			}
			newNode.setKeysQuoted(quotedRange(keyStart, i))
			newNode.setKeysBracketed(groupedRange(keyStart, i))
			*current = append(*current, newNode)
			current = &newNode.Children
		}
		inValueListModifiers = childSchema.valueList
		schema = childSchema
	}

	return nil
}

// DeletePath removes a node at the given path from the tree.
// Uses the same schema-driven traversal as SetPath to navigate the tree,
// then removes the target node from its parent's Children slice.
func (t *ConfigTree) DeletePath(path []string) error {
	return t.DeletePathGrouped(path, nil)
}

// DeletePathGrouped is DeletePath carrying per-token BRACKET GROUPING (#6668),
// so a `delete` line replayed from `show | display set` navigates to the same
// node the matching `set` line built. Without it the walk re-splits a bracketed
// CONTAINER key group at the schema arity and reports the node missing.
func (t *ConfigTree) DeletePathGrouped(path []string, grouped []bool) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}
	if len(grouped) != len(path) {
		grouped = nil
	}

	return deletePath(&t.Children, path, grouped, setSchema, 0)
}

func deletePath(current *[]*Node, path []string, grouped []bool, schema *schemaNode, i int) error {
	if i >= len(path) {
		return ErrPathNotFound
	}

	// #8992: before anything else at the TOP level, a fully elided stanza --
	// `system master-password ascii-text "x";` -- is ONE node whose Keys carry
	// the whole path, so no descent by container name can find it. Handled
	// here rather than in the not-found branch because the elided node may sit
	// beside a BRACED container of the same name, in which case the descent
	// succeeds, fails deeper, and reports "no node matching <leaf>" while the
	// elided node is never examined at all. See elided_delete_8992.go for the
	// bound: only a node encoding exactly ONE statement is removed.
	// #8997: at EVERY level, not just the top. An elided node can sit at any
	// depth -- `chassis { cluster strict-session-auth; }` puts it one level
	// down -- and restricting this to i == 0 meant a partially elided stanza
	// was never examined. `schema` is the schema node for the CURRENT
	// container, so the bound below is evaluated in the right scope; where the
	// descent has dropped the schema (nil) the check is skipped, which is the
	// conservative direction for a delete.
	if schema != nil {
		if idx := findElidedNodeForPath(*current, path[i:], schema); idx >= 0 {
			*current = append((*current)[:idx], (*current)[idx+1:]...)
			return nil
		}
		// The stanza IS present, elided, but packed together with at least one
		// other statement on the same node. Removing the node would take the
		// others with it (#3846's fail-wide), and splitting it is
		// consumeNodeKeys work #8932 records as unfinished -- so refuse, and
		// say which.
		if keys := elidedPackedRunCarrying(*current, path[i:], schema); keys != nil {
			return fmt.Errorf("%w: %q is present in an ELIDED spelling packed together "+
				"with other statements on one line (%q), and deleting it would remove "+
				"them too. Re-author that line with braces around %q, then delete it "+
				"(#8992, #8932)",
				ErrPathNotFound, strings.Join(path, " "), strings.Join(keys, " "), path[len(path)-1])
		}
	}

	keyword := path[i]

	// Look up keyword in current schema level (#9685).
	childSchema := schemaChildFor(schema, keyword)

	if childSchema == nil {
		// #6668: an unmodeled position still honours an authored bracket group
		// that does not reach the end of the path — those tokens are ONE node's
		// keys and what follows is its body, so descend rather than treating
		// the whole tail as leaf keys.
		if run := bracketGroupStartLen(grouped, i); run > 0 && i+run < len(path) {
			nodeKeys := path[i : i+run]
			for _, n := range *current {
				if !n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
					return deletePath(&n.Children, path, grouped, nil, i+run)
				}
			}
			return fmt.Errorf("%w: container %q does not exist", ErrPathNotFound, strings.Join(nodeKeys, " "))
		}
		// No schema match: remaining tokens form leaf keys, remove matching node.
		leafKeys := path[i:]
		return removeMatchingNode(current, leafKeys)
	}

	// Value-list multi-leaf (a `multi: true` leaf with a single value slot and
	// no children): the bracket-list class fixed on the read side in #2419 —
	// `from protocol [ tcp udp icmp ]`, policy match
	// source-/destination-address/application, host-inbound-traffic
	// system-services/protocols, apply-groups, domain-search, and friends. The
	// leaf carries its members on Keys[1:] AND/OR one child node per member
	// (the dual AST shape). A `delete ... protocol tcp` names a MEMBER of the
	// list, not the whole node — remove ONLY that member and keep the rest,
	// mirroring firewallMatchValues on the read side. A bare `delete ...
	// protocol` (no trailing member) still clears the whole leaf. Without this
	// branch removeMatchingNode prefix-matches the leaf by its first key and
	// deletes the ENTIRE list (a config-integrity fail-wide, #3846), and a
	// non-first member is undeletable.
	//
	// Gate on args == 1 so keyed multi entries (address <name> <prefix>,
	// args == 2; named containers with children such as `interfaces <name>`)
	// keep whole-node delete semantics. The valueList opt-in (#3872 static
	// `next-hop`) extends member-delete to a multi leaf that ALSO carries
	// modifier children (its `interface`), mirroring the read/render-side gate
	// flip: without this, `delete ... next-hop <gw>` prefix-matched and deleted
	// the WHOLE next-hop leaf, so deleting one gateway of a `[ a b ]` ECMP list
	// silently blackholed the healthy other path (Null0), and a non-first
	// member was undeletable — the exact #3846 delete-side fail-wide.
	if childSchema.multi && (childSchema.children == nil || childSchema.valueList) && childSchema.args == 1 {
		return removeMultiLeafMembers(current, keyword, path[i+1:], childSchema.valueList)
	}

	// Consume keyword + extra args as this node's keys.
	nodeKeyCount := 1 + childSchema.args
	// #6668: widen to an authored bracket group's end, never narrower —
	// widenKeyCountToGroupEnd owns that rule.
	nodeKeyCount = widenKeyCountToGroupEnd(grouped, i, i+nodeKeyCount) - i
	if i+nodeKeyCount > len(path) {
		// Not enough tokens; treat remainder as leaf keys.
		leafKeys := path[i:]
		return removeMatchingNode(current, leafKeys)
	}

	nodeKeys := path[i : i+nodeKeyCount]
	i += nodeKeyCount

	// Compound key: consume child token as part of key.
	if childSchema.compoundKey && i < len(path) {
		if sub, ok := childSchema.children[path[i]]; ok {
			nodeKeys = append(append([]string(nil), nodeKeys...), path[i])
			i++
			childSchema = sub
		}
	}

	if i >= len(path) {
		// No more tokens: this container node itself is the target.
		return removeMatchingNode(current, nodeKeys)
	}

	// More tokens remain: find matching container and descend.
	for _, n := range *current {
		if !n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
			return deletePath(&n.Children, path, grouped, childSchema, i)
		}
	}

	// #4423 M9: wrap ErrPathNotFound here too. This return fires when an
	// INTERMEDIATE container in the delete path is absent (more tokens remain
	// past a schema-matched container that is not configured) — the most common
	// defensive-remediation shape, e.g. `delete system services ssh` when
	// `system services` is not configured. The message text still starts with
	// "path not found: ...", but the tolerated-missing-delete carve-out in the
	// event-options batch now matches with errors.Is, so this MUST wrap the
	// sentinel or the container-miss delete aborts the batch (the exact
	// regression M9 exists to prevent).
	return fmt.Errorf("%w: container %q does not exist", ErrPathNotFound, strings.Join(nodeKeys, " "))
}

// DeactivatePath marks the node at the given path inactive (#2008 H1),
// implementing the Junos `deactivate <path>` verb. The node keeps its
// identity and children — it is excluded from compilation/application until
// re-activated, exactly like an `inactive:` marker in hierarchical text.
// Navigation reuses the same schema-driven traversal as SetPath/DeletePath
// so the path tokenization matches `show | display set` output (which emits
// `deactivate <path>` for every inactive node), making that output
// round-trippable. The target node must already exist — `display set`
// always emits the node's `set` line(s) before its `deactivate` line, so on
// reload the node is present by the time this runs.
func (t *ConfigTree) DeactivatePath(path []string) error {
	return t.DeactivatePathGrouped(path, nil)
}

// DeactivatePathGrouped is DeactivatePath carrying per-token BRACKET GROUPING
// (#6668). `show | display set` emits a node's `set` line(s) and then its
// `deactivate` line over the SAME tokens, so the two must tokenize into the
// same nodes; without the grouping the deactivate line re-split a bracketed
// container key group at the schema arity and reported the node missing, which
// on the load paths aborts the whole replay.
func (t *ConfigTree) DeactivatePathGrouped(path []string, grouped []bool) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}
	if len(grouped) != len(path) {
		grouped = nil
	}
	return setInactiveAtPath(&t.Children, path, grouped, setSchema, 0, true)
}

// ActivatePath clears the inactive marker on the node at the given path
// (#2008 H1), implementing the Junos `activate <path>` verb. The target
// node must already exist.
func (t *ConfigTree) ActivatePath(path []string) error {
	return t.ActivatePathGrouped(path, nil)
}

// ActivatePathGrouped is ActivatePath carrying per-token BRACKET GROUPING
// (#6668). See DeactivatePathGrouped.
func (t *ConfigTree) ActivatePathGrouped(path []string, grouped []bool) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}
	if len(grouped) != len(path) {
		grouped = nil
	}
	return setInactiveAtPath(&t.Children, path, grouped, setSchema, 0, false)
}

// setInactiveAtPath navigates to the node identified by path (using the
// same schema-driven traversal as deletePath) and sets its Inactive flag to
// the requested value. It does NOT create missing nodes — deactivate /
// activate toggle an existing statement.
func setInactiveAtPath(current *[]*Node, path []string, grouped []bool, schema *schemaNode, i int, inactive bool) error {
	if i >= len(path) {
		return fmt.Errorf("path not found")
	}

	keyword := path[i]

	childSchema := schemaChildFor(schema, keyword) // #9685

	if childSchema == nil {
		// #6668: honour an authored bracket group at an unmodeled position —
		// see the matching branch in deletePath.
		if run := bracketGroupStartLen(grouped, i); run > 0 && i+run < len(path) {
			nodeKeys := path[i : i+run]
			for _, n := range *current {
				if !n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
					return setInactiveAtPath(&n.Children, path, grouped, nil, i+run, inactive)
				}
			}
			return fmt.Errorf("path not found: container %q does not exist", strings.Join(nodeKeys, " "))
		}
		// No schema match: remaining tokens form leaf keys.
		return markMatchingNodeInactive(current, path[i:], inactive)
	}

	// Value-list multi-leaf: the same bracket-list class deletePath intercepts
	// (see the deletePath comment). A `multi: true` leaf with a single value slot
	// and no children (or a valueList leaf with modifier children, #3872) carries
	// its members on Keys[1:] AND/OR one child node per member — the #2419 dual
	// AST shape. Without this branch the schema-driven consumption below eats the
	// first member as an extra key (nodeKeyCount == 2), then treats the remaining
	// members as container tokens and errors ("container \"protocol tcp\" does not
	// exist"): the display-set emit of an inactive bracket leaf is exactly
	// `deactivate ... from protocol tcp udp icmp`, so an inactive multi-value leaf
	// did NOT round-trip — it reloaded ACTIVE (#3975, the deactivate-side
	// counterpart of the #3846 delete-side fail). Route it through the member
	// matcher instead: a bare `deactivate ... protocol` toggles the whole leaf;
	// naming members toggles the whole leaf (flat/bracket — Inactive is a
	// node-level flag, a bracket list is one statement) or the named child nodes
	// (block shape). Gate on args == 1 so keyed multi entries (address <name>
	// <prefix>, args == 2) keep whole-node toggle semantics.
	if childSchema.multi && (childSchema.children == nil || childSchema.valueList) && childSchema.args == 1 {
		return markMultiLeafMembersInactive(current, keyword, path[i+1:], childSchema.valueList, inactive)
	}

	nodeKeyCount := 1 + childSchema.args
	// #6668: widen to an authored bracket group's end, never narrower —
	// widenKeyCountToGroupEnd owns that rule.
	nodeKeyCount = widenKeyCountToGroupEnd(grouped, i, i+nodeKeyCount) - i
	if i+nodeKeyCount > len(path) {
		return markMatchingNodeInactive(current, path[i:], inactive)
	}

	nodeKeys := path[i : i+nodeKeyCount]
	i += nodeKeyCount

	// Compound key: consume child token as part of key.
	if childSchema.compoundKey && i < len(path) {
		if sub, ok := childSchema.children[path[i]]; ok {
			nodeKeys = append(append([]string(nil), nodeKeys...), path[i])
			i++
			childSchema = sub
		}
	}

	if i >= len(path) {
		// No more tokens: this node itself is the target.
		return markMatchingNodeInactive(current, nodeKeys, inactive)
	}

	// More tokens remain: find matching container and descend.
	for _, n := range *current {
		if !n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
			return setInactiveAtPath(&n.Children, path, grouped, childSchema, i, inactive)
		}
	}

	return fmt.Errorf("path not found: container %q does not exist", strings.Join(nodeKeys, " "))
}

// markMatchingNodeInactive sets the Inactive flag on the first node whose
// keys match targetKeys (prefix matching, mirroring removeMatchingNode).
func markMatchingNodeInactive(nodes *[]*Node, targetKeys []string, inactive bool) error {
	for _, n := range *nodes {
		if keysMatch(n.Keys, targetKeys) {
			n.Inactive = inactive
			return nil
		}
	}
	return fmt.Errorf("path not found: no node matching %q", strings.Join(targetKeys, " "))
}

// removeMatchingNode removes the first node whose keys match targetKeys
// (using prefix matching) from the nodes slice.
func removeMatchingNode(nodes *[]*Node, targetKeys []string) error {
	for i, n := range *nodes {
		if keysMatch(n.Keys, targetKeys) {
			*nodes = append((*nodes)[:i], (*nodes)[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%w: no node matching %q", ErrPathNotFound, strings.Join(targetKeys, " "))
}

// removeMultiLeafMembers implements member-specific deletion for a value-list
// multi-leaf. keyword is the leaf's first key ("protocol", "next-hop"); members
// are the trailing tokens naming individual values to drop.
//
//   - members empty  → delete the whole leaf (mirrors removeMatchingNode's
//     prefix match), so `delete ... from protocol` still clears the list.
//   - members named  → drop ONLY those values from every node whose first key
//     is keyword, reading BOTH the flat Keys[1:] shape (bracket list / flat
//     set) AND, for a plain value-list leaf, the child-node shape (hierarchical
//     block) — the #2419 dual AST shape. A node left with no values is removed
//     entirely.
//
// modifierChildren distinguishes the two node classes:
//   - false — a plain value-list leaf (children == nil, e.g. `from protocol
//     [ tcp udp icmp ]`): child nodes ARE list members and are droppable.
//   - true  — a valueList leaf that ALSO declares MODIFIER children (#3872
//     static `next-hop <gw> { interface <if> }`): the children are modifiers
//     OF the value, never members, so they are never matched against the drop
//     set. When every value on Keys[1:] is dropped, the WHOLE entry — the
//     gateway AND its interface modifier — is removed, rather than left as a
//     gateway-less next-hop container that would render Null0/blackhole.
//
// Returns an error when no named member was found anywhere (mirroring
// removeMatchingNode's not-found contract), so deleting a member that is not
// present is reported rather than silently succeeding.
func removeMultiLeafMembers(nodes *[]*Node, keyword string, members []string, modifierChildren bool) error {
	if len(members) == 0 {
		return removeMatchingNode(nodes, []string{keyword})
	}
	drop := make(map[string]bool, len(members))
	for _, m := range members {
		drop[m] = true
	}
	removedAny := false
	out := (*nodes)[:0]
	for _, n := range *nodes {
		if len(n.Keys) == 0 || n.Keys[0] != keyword {
			out = append(out, n)
			continue
		}
		// Flat / bracket shape: members ride on Keys[1:].
		// #6673: the surviving keys keep their AUTHORED-quote provenance, which
		// means rebuilding the mask in lockstep — a stale-length KeysQuoted
		// would silently demote the node to "provenance unknown" and re-expose
		// the fused-member read that provenance exists to close.
		newKeys := append([]string(nil), n.Keys[:1]...)
		newQuoted := []bool{n.KeyQuoted(0)}
		for i, v := range n.Keys[1:] {
			if drop[v] {
				removedAny = true
				continue
			}
			newKeys = append(newKeys, v)
			newQuoted = append(newQuoted, n.KeyQuoted(i+1))
		}
		if modifierChildren {
			// valueList node: children are MODIFIERS of the value, not members.
			// Drop the whole entry (gateway + interface modifier) once every
			// gateway on Keys[1:] is gone — a next-hop with no gateway is
			// meaningless and would render Null0.
			if len(newKeys) == 1 {
				continue
			}
			n.Keys = newKeys
			n.setKeysQuoted(newQuoted)
			out = append(out, n)
			continue
		}
		// Block shape: one child node per member.
		newChildren := n.Children[:0]
		for _, c := range n.Children {
			if len(c.Keys) >= 1 && drop[c.Keys[0]] {
				removedAny = true
				continue
			}
			newChildren = append(newChildren, c)
		}
		// Leaf/container emptied of all members: drop it entirely.
		if len(newKeys) == 1 && len(newChildren) == 0 {
			continue
		}
		n.Keys = newKeys
		n.setKeysQuoted(newQuoted)
		n.Children = newChildren
		out = append(out, n)
	}
	*nodes = out
	if !removedAny {
		return fmt.Errorf("%w: no member %q of %q",
			ErrPathNotFound, strings.Join(members, " "), keyword)
	}
	return nil
}

// markMultiLeafMembersInactive is the deactivate/activate counterpart of
// removeMultiLeafMembers for a value-list multi-leaf (#3975). keyword is the
// leaf's first key ("protocol", "system-services", "next-hop"); members are the
// trailing tokens. Unlike delete, the Inactive marker is a NODE-level flag, so a
// bracket list — collapsed onto ONE node's Keys[1:] — can only be toggled whole,
// never per-value; block-shape members (one child node each) can be toggled
// individually.
//
//   - members empty  → toggle the whole leaf (mirrors markMatchingNodeInactive's
//     prefix match), so `deactivate ... protocol` toggles the list.
//   - members named  → for every node whose first key is keyword, toggle the
//     WHOLE node when any named member rides on Keys[1:] (the flat/bracket shape —
//     this is what display-set emits: `deactivate ... protocol tcp udp icmp`), and
//     for a plain value-list leaf ALSO toggle any child node the members name
//     (the hierarchical block shape). This restores round-trip of an inactive
//     bracket leaf, which errored before #3975.
//
// modifierChildren mirrors removeMultiLeafMembers: when true (a valueList leaf
// whose children are MODIFIERS of the value, e.g. static next-hop's interface),
// the children are never members, so only the Keys[1:] flat match applies.
//
// Returns an error when no named member was found anywhere, mirroring
// removeMultiLeafMembers' not-found contract.
func markMultiLeafMembersInactive(nodes *[]*Node, keyword string, members []string, modifierChildren, inactive bool) error {
	if len(members) == 0 {
		return markMatchingNodeInactive(nodes, []string{keyword}, inactive)
	}
	drop := make(map[string]bool, len(members))
	for _, m := range members {
		drop[m] = true
	}
	matched := false
	for _, n := range *nodes {
		if len(n.Keys) == 0 || n.Keys[0] != keyword {
			continue
		}
		// Flat / bracket shape: members ride on Keys[1:]. Inactive is node-level,
		// so any named member present toggles the whole statement.
		flatMatch := false
		for _, v := range n.Keys[1:] {
			if drop[v] {
				flatMatch = true
				break
			}
		}
		if flatMatch {
			n.Inactive = inactive
			matched = true
			continue
		}
		if modifierChildren {
			// valueList node: children are MODIFIERS, never members.
			continue
		}
		// Block shape: one child node per member — toggle only the named ones.
		for _, c := range n.Children {
			if len(c.Keys) >= 1 && drop[c.Keys[0]] {
				c.Inactive = inactive
				matched = true
			}
		}
	}
	if !matched {
		return fmt.Errorf("path not found: no member %q of %q",
			strings.Join(members, " "), keyword)
	}
	return nil
}

// keysMatch returns true if nodeKeys starts with all elements of targetKeys.
// This allows "delete ... address srv1" to match a leaf ["address", "srv1", "10.0.1.0/32"].
func keysMatch(nodeKeys, targetKeys []string) bool {
	if len(targetKeys) > len(nodeKeys) {
		return false
	}
	for i, tk := range targetKeys {
		if nodeKeys[i] != tk {
			return false
		}
	}
	return true
}
