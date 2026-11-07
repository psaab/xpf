package config

import "fmt"

// setKeysBracketed stores bracket provenance alongside keys, normalizing to
// nil unless the lengths agree and at least one key is bracketed. When closed
// is supplied, BracketedClosed is true only for a closed span with at least
// one bracketed key.
func (n *Node) setKeysBracketed(bracketed []bool, closed ...bool) {
	aligned := len(bracketed) == len(n.Keys)
	if len(closed) > 0 {
		n.BracketedClosed = false
		if closed[0] && aligned {
			for _, b := range bracketed {
				if b {
					n.BracketedClosed = true
					break
				}
			}
		}
	}
	if !aligned {
		n.KeysBracketed = nil
		return
	}
	for _, b := range bracketed {
		if b {
			n.KeysBracketed = append([]bool(nil), bracketed...)
			return
		}
	}
	n.KeysBracketed = nil
}

// setKeysQuoted stores quote provenance alongside keys, normalizing to nil
// unless the lengths agree and at least one key is quoted.
func (n *Node) setKeysQuoted(quoted []bool) {
	if len(quoted) != len(n.Keys) {
		n.KeysQuoted = nil
		return
	}
	for _, q := range quoted {
		if q {
			n.KeysQuoted = append([]bool(nil), quoted...)
			return
		}
	}
	n.KeysQuoted = nil
}

// appendKey adds one key and its per-key provenance without allocating mask
// storage for an all-bare sequence. An existing prefix is retained and a
// malformed short prefix is zero-padded; bits beyond the old key span are
// discarded. BracketedClosed is node-span provenance and is not changed here.
func (n *Node) appendKey(value string, quoted, bracketed bool) {
	if n == nil {
		return
	}
	oldLen := len(n.Keys)
	n.Keys = append(n.Keys, value)
	n.KeysQuoted = appendKeyMask(n.KeysQuoted, oldLen, quoted)
	n.KeysBracketed = appendKeyMask(n.KeysBracketed, oldLen, bracketed)
}

func appendKeyMask(mask []bool, oldLen int, bit bool) []bool {
	if len(mask) == oldLen {
		if !bit && (mask == nil || oldLen == 0) {
			return nil
		}
		// Setters normalize aligned masks, so the common path can extend them
		// in place without rescanning prior keys.
		return append(mask, bit)
	}
	if mask == nil && !bit {
		return nil
	}
	aligned := make([]bool, oldLen+1)
	copy(aligned, mask[:min(len(mask), oldLen)])
	aligned[oldLen] = bit
	if bit {
		return aligned
	}
	for _, marked := range aligned[:oldLen] {
		if marked {
			return aligned
		}
	}
	return nil
}
func hasBracketedKey(n *Node) bool {
	if n == nil {
		return false
	}
	for _, bracketed := range n.KeysBracketed {
		if bracketed {
			return true
		}
	}
	return false
}

// replaceKeys replaces a node's key span and all of its provenance. Keys and
// masks are copied; setters normalize absent, skewed, and all-false masks to
// nil so persisted JSON remains byte-identical for provenance-free nodes.
func (n *Node) replaceKeys(keys []string, quoted, bracketed []bool, closed bool) {
	if n == nil {
		return
	}
	n.Keys = cloneKeyStrings(keys)
	n.setKeysQuoted(quoted)
	n.setKeysBracketed(bracketed, closed)
}

// ReplaceKeys replaces a node's key span and quote/bracket provenance.
// It is exported for other packages that transform Node values; keys and
// masks are copied and misaligned masks are discarded.
func (n *Node) ReplaceKeys(keys []string, quoted, bracketed []bool, closed bool) {
	n.replaceKeys(keys, quoted, bracketed, closed)
}

func cloneKeyStrings(keys []string) []string {
	if keys == nil {
		return nil
	}
	out := make([]string, len(keys))
	copy(out, keys)
	return out
}

func cloneKeyMask(mask []bool) []bool {
	if mask == nil {
		return nil
	}
	out := make([]bool, len(mask))
	copy(out, mask)
	return out
}

// keySpan returns a fresh leaf containing n.Keys[from:to] and any aligned
// quote/bracket provenance for that span.
func (n *Node) keySpan(from, to int) *Node {
	if n == nil {
		return &Node{IsLeaf: true}
	}
	span := &Node{IsLeaf: true, InheritedFrom: n.InheritedFrom}
	var quoted, bracketed []bool
	if len(n.KeysQuoted) == len(n.Keys) {
		quoted = n.KeysQuoted[from:to]
	}
	if len(n.KeysBracketed) == len(n.Keys) {
		bracketed = n.KeysBracketed[from:to]
	}
	span.replaceKeys(n.Keys[from:to], quoted, bracketed, n.BracketedClosed)
	return span
}

// copyKeyProvenance copies both per-key masks and the node-level close bit
// verbatim. It is for structural clones, where even a legacy/skewed mask must
// not be silently repaired or its close bit discarded.
func (n *Node) copyKeyProvenance(src *Node) {
	if n == nil || src == nil {
		return
	}
	n.KeysQuoted = cloneKeyMask(src.KeysQuoted)
	n.KeysBracketed = cloneKeyMask(src.KeysBracketed)
	n.BracketedClosed = src.BracketedClosed
}

// keyMask returns m only when it is aligned with n keys.
func keyMask(mask []bool, keyCount int) []bool {
	if len(mask) != keyCount {
		return nil
	}
	return mask
}

// maskSlice returns a bounded mask span, or nil when the mask is absent or
// the requested range is invalid.
func maskSlice(mask []bool, from, to int) []bool {
	if mask == nil || from < 0 || from > to || to > len(mask) {
		return nil
	}
	return mask[from:to]
}

// checkNodeKeyInvariant reports path-qualified key-mask length violations.
// Nil trees have no violations.
func checkNodeKeyInvariant(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	var violations []string
	var walk func([]*Node, string)
	walk = func(nodes []*Node, parent string) {
		for i, n := range nodes {
			if n == nil {
				continue
			}
			path := fmt.Sprintf("%schildren[%d]", parent, i)
			if key := n.KeyPath(); key != "" {
				path += fmt.Sprintf(" (%s)", key)
			}
			if n.KeysQuoted != nil && len(n.KeysQuoted) != len(n.Keys) {
				violations = append(violations, fmt.Sprintf("%s: len(KeysQuoted)=%d, len(Keys)=%d", path, len(n.KeysQuoted), len(n.Keys)))
			}
			if n.KeysBracketed != nil && len(n.KeysBracketed) != len(n.Keys) {
				violations = append(violations, fmt.Sprintf("%s: len(KeysBracketed)=%d, len(Keys)=%d", path, len(n.KeysBracketed), len(n.Keys)))
			}
			walk(n.Children, path+"/")
		}
	}
	walk(tree.Children, "")
	return violations
}
