package config

import "strings"

// #14434 (DR17-H5): `applications application <name> term <term>` is an
// opaque schema leaf (args:1, children:nil — the term body rides on the
// packed leaf's Keys). The generic leaf merge could not treat one term
// as an instance: namedLeafPeer9859 requires children != nil, leafListPeer
// matched the inline term by keyword alone, term is not a leaf-list so no
// union fired, and the packed promotions require a children-bearing
// schema node. A group term leaf beside any inline term leaf therefore
// fell through to the inline-wins override and was dropped whole —
// a different group term (t2 beside t1) vanished, and a same-name group
// term lost its non-conflicting tail (e.g. `alg`).
//
// The helpers below give only this leaf, only under applications/
// application, the instance treatment the compiler already assumes:
// terms are additive under a parent (a policy matching the parent matches
// if ANY term matches), distinct names must both survive, and same-name
// bodies merge with per-leaf inline-wins, exactly as the braced
// container-container merge and parseApplicationTerms' duplicate gate
// expect. Adopt-beside shapes (group container vs inline leaf and vice
// versa) are untouched: they still twin-generate one name and the
// collision gate in compiler_applications_collision.go rejects them.
//
// Term-body keywords are the value-taking application leaves. That set is
// already pinned to the term/direct switches (valueTakingApplicationLeaves),
// so a future leaf admitted there merges here without a second list to
// drift. `protocol` is the one multi-valued exception: Junos repeats it
// to mint one application per protocol, and parseApplicationTerms dedups
// the run, so group protocol tokens that the inline term does not already
// carry are kept rather than treated as a scalar conflict.

// isApplicationTermLeaf14434 reports whether s is an applications
// `term` leaf: keyword term with a name token, standing at an
// application-children level. The schema check is primary (term resolves
// to the opaque args:1/children-nil leaf under application); the
// ancestor-shape fallback covers the same level reached through a path
// the schema walk cannot resolve.
func isApplicationTermLeaf14434(ancestorPath [][]string, s *Node) bool {
	if s == nil || len(s.Keys) < 2 || s.Keys[0] != "term" {
		return false
	}
	if parent := schemaAtAncestorPath(ancestorPath); parent != nil {
		if leaf := resolveSchemaChild(parent, "term"); leaf != nil {
			return leaf.children == nil && leaf.args == 1
		}
	}
	n := len(ancestorPath)
	if n < 1 {
		return false
	}
	last := ancestorPath[n-1]
	if len(last) >= 2 && last[0] == "applications" && last[1] == "application" {
		return true
	}
	if n >= 2 {
		return len(ancestorPath[n-2]) > 0 && ancestorPath[n-2][0] == "applications" &&
			len(ancestorPath[n-1]) > 0 && ancestorPath[n-1][0] == "application"
	}
	return false
}

// isApplicationTermChained14434 reports whether n is a flat-set chained
// term: Keys [term <name>] with a single leaf child carrying the body
// tokens (SetPath splits at the term keyword because term is opaque).
func isApplicationTermChained14434(n *Node) bool {
	return n != nil && !n.IsLeaf && len(n.Keys) == 2 && n.Keys[0] == "term" &&
		len(n.Children) == 1 && n.Children[0] != nil && n.Children[0].IsLeaf
}

// chainedLeafTokens14434 returns the body tokens of a node in either
// term shape: packed Keys[2:] for a leaf, or the chained child's Keys.
func chainedLeafTokens14434(n *Node) ([]string, bool) {
	if n == nil {
		return nil, false
	}
	if n.IsLeaf {
		if len(n.Keys) < 2 {
			return nil, false
		}
		return n.Keys[2:], true
	}
	if isApplicationTermChained14434(n) {
		return n.Children[0].Keys, true
	}
	return nil, false
}

// applicationTermFamilyNode14434 classifies a dst/src term-shaped node
// at an application level, including the flat-set chained shape whose
// ancestorPath does not resolve through the schema walk.
func applicationTermFamilyNode14434(ancestorPath [][]string, n *Node) bool {
	if n == nil || len(n.Keys) < 2 || n.Keys[0] != "term" {
		return false
	}
	if isApplicationTermLeaf14434(ancestorPath, n) {
		return true
	}
	if !isApplicationTermChained14434(n) {
		return false
	}
	m := len(ancestorPath)
	if m == 0 {
		return false
	}
	last := ancestorPath[m-1]
	// ancestorPath for children of application myapp is [..., [application myapp]]
	// after appendPath(peer.Keys) — the chained term's parent level.
	return len(last) > 0 && last[0] == "application"
}

func applicationTermName14434(n *Node) string {
	if n == nil || len(n.Keys) < 2 {
		return ""
	}
	return n.Keys[1]
}

// applicationTermPeer14434 finds a leaf peer for s whose body can be
// merged token-wise. A non-leaf (braced/container) term peer is not
// returned: that adopt-beside shape must keep twinning into the
// collision gate, not merge here.
func applicationTermPeer14434(dst []*Node, s *Node) *Node {
	name := applicationTermName14434(s)
	for _, d := range dst {
		if d == nil || !d.IsLeaf || len(d.Keys) < 2 || d.Keys[0] != "term" {
			continue
		}
		if d.Keys[1] == name {
			return d
		}
	}
	return nil
}

func applicationTermExists14434(dst []*Node, s *Node) bool {
	name := applicationTermName14434(s)
	for _, d := range dst {
		if d == nil || len(d.Keys) < 1 || d.Keys[0] != "term" {
			continue
		}
		if len(d.Keys) >= 2 && d.Keys[1] == name {
			return true
		}
	}
	return false
}

// mergeApplicationTermNodes14434 merges two term-shaped nodes (packed
// leaf or flat-set chained) into dst, preserving dst's shape.
func mergeApplicationTermNodes14434(dst, src *Node) bool {
	if dst == nil || src == nil || applicationTermName14434(dst) == "" ||
		applicationTermName14434(dst) != applicationTermName14434(src) {
		return false
	}
	dstToks, ok1 := chainedLeafTokens14434(dst)
	srcToks, ok2 := chainedLeafTokens14434(src)
	if !ok1 || !ok2 {
		return false
	}
	if dst.IsLeaf {
		return mergeApplicationTermLeaves14434(dst, src)
	}
	// Chained: reuse the leaf merger on synthetic leaves to keep the
	// scalar inline-wins logic single-sourced, then write the body
	// back onto dst's child. Body-token quote provenance is not
	// consumed by applicationTermKeys readers, so it is dropped.
	synthDst := &Node{Keys: append([]string{"term", dst.Keys[1]}, dstToks...), IsLeaf: true}
	synthSrc := &Node{Keys: append([]string{"term", src.Keys[1]}, srcToks...), IsLeaf: true}
	if !mergeApplicationTermLeaves14434(synthDst, synthSrc) {
		return false
	}
	child := dst.Children[0]
	child.Keys = append([]string(nil), synthDst.Keys[2:]...)
	child.setKeysQuoted(nil)
	child.setKeysBracketed(nil)
	return true
}

func findApplicationTermPeer14434(dst []*Node, s *Node) *Node {
	name := applicationTermName14434(s)
	for _, d := range dst {
		if d == nil || len(d.Keys) < 2 || d.Keys[0] != "term" || d.Keys[1] != name {
			continue
		}
		if _, ok := chainedLeafTokens14434(d); ok {
			return d
		}
	}
	return nil
}

// parseTermBody14434 splits a term tail (tokens after term <name>) into
// keyword/value pairs in order. Unknown tokens and dangling value-taking
// keywords are kept as value-less entries so strict gates that scan the
// merged Keys still see them; they are not silently discarded.
func parseTermBody14434(tokens []string) [][2]string {
	var out [][2]string
	for i := 0; i < len(tokens); {
		kw := tokens[i]
		if valueTakingApplicationLeaves[kw] && i+1 < len(tokens) {
			out = append(out, [2]string{kw, tokens[i+1]})
			i += 2
			continue
		}
		out = append(out, [2]string{kw, ""})
		i++
	}
	return out
}

func mergeApplicationTermLeaves14434(dst, src *Node) bool {
	if dst == nil || src == nil || len(dst.Keys) < 2 || len(src.Keys) < 2 || dst.Keys[1] != src.Keys[1] {
		return false
	}
	// Braced/containers carry bodies as Children (expanded synthesized
	// terms flatten Children into Keys via applicationTermKeys). Refuse
	// to merge those token-wise here; they keep their existing path.
	if len(dst.Children) > 0 || len(src.Children) > 0 {
		return false
	}
	dstPairs := parseTermBody14434(dst.Keys[2:])
	srcPairs := parseTermBody14434(src.Keys[2:])

	dstScalar := map[string]bool{}
	var dstProtos []string
	for _, p := range dstPairs {
		if p[0] == "protocol" {
			dstProtos = append(dstProtos, p[1])
		} else if p[1] != "" {
			dstScalar[p[0]] = true
		}
	}
	hasProto := func(v string) bool {
		for _, p := range dstProtos {
			if strings.EqualFold(p, v) {
				return true
			}
		}
		return false
	}

	merged := append([]string(nil), dst.Keys...)
	mergedQuoted := append([]bool(nil), dst.KeysQuoted...)
	mergedBracketed := append([]bool(nil), dst.KeysBracketed...)
	hasQ := len(dst.KeysQuoted) == len(dst.Keys)
	hasB := len(dst.KeysBracketed) == len(dst.Keys)

	appendTok := func(tok string, quoted, bracketed bool) {
		merged = append(merged, tok)
		if hasQ {
			mergedQuoted = append(mergedQuoted, quoted)
		}
		if hasB {
			mergedBracketed = append(mergedBracketed, bracketed)
		}
	}
	srcQ := len(src.KeysQuoted) == len(src.Keys)
	srcB := len(src.KeysBracketed) == len(src.Keys)
	// src token index: Keys[0]=term, Keys[1]=name, body starts at 2.
	srcIdx := 2
	for _, p := range srcPairs {
		kw, val := p[0], p[1]
		width := 1
		if val != "" {
			width = 2
		}
		q := func(off int) bool {
			if !srcQ || srcIdx+off >= len(src.KeysQuoted) {
				return false
			}
			return src.KeysQuoted[srcIdx+off]
		}
		b := func(off int) bool {
			if !srcB || srcIdx+off >= len(src.KeysBracketed) {
				return false
			}
			return src.KeysBracketed[srcIdx+off]
		}
		keep := false
		switch {
		case kw == "protocol":
			// Multi-protocol terms mint one application per protocol;
			// keep a group protocol the inline term lacks, skip dupes
			// (including alias dupes, which parseApplicationTerms dedups).
			if val != "" && !hasProto(val) {
				// normalize for alias comparison as parse does
				norm := normalizeProtocol(val)
				dup := false
				for _, dp := range dstProtos {
					if normalizeProtocol(dp) == norm {
						dup = true
						break
					}
				}
				keep = !dup
				if keep {
					dstProtos = append(dstProtos, val)
				}
			}
		case val == "":
			// Unknown or dangling token: preserve it so the strict
			// UnknownTermLeaves / IncompleteTermLeaves gates still
			// see group-authored junk instead of widening silently.
			// Skip an exact value-less repeat already inline.
			if !dstScalar[kw] {
				// check presence among dst value-less tokens
				present := false
				for _, dp := range dstPairs {
					if dp[0] == kw && dp[1] == "" {
						present = true
						break
					}
				}
				keep = !present
			}
		default:
			// Scalar leaf: inline wins. Adopt only if inline lacks it.
			keep = !dstScalar[kw]
			if keep {
				dstScalar[kw] = true
			}
		}
		if keep {
			appendTok(kw, q(0), b(0))
			if width == 2 {
				appendTok(val, q(1), b(1))
			}
		}
		srcIdx += width
	}
	dst.Keys = merged
	if hasQ {
		dst.setKeysQuoted(mergedQuoted)
	}
	if hasB {
		dst.setKeysBracketed(mergedBracketed)
	}
	return true
}
