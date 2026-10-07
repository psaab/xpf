package config

import "strings"

// malformedZonePairShape9246 reports zone-pair key shapes whose tail the
// policy compiler cannot represent, or "" when the shape is valid.
//
// There are two malformed AST forms:
//
//   - Grouped set input and hierarchical text preserve every zone token on the
//     context node. The compiler reads only Keys[1] and Keys[3], silently
//     dropping later to-zone tokens.
//   - The legacy ungrouped parser absorbs the rest of the statement into a
//     non-policy child, so the context has no attached rule.
//
// The first form is checked by key shape even when bracket provenance is
// absent; provenance only lets the diagnostic name an authored bracket list.
// The second uses the narrower absorbed-rule signature rather than rejecting
// every unexpected child.
//
// WHY NOT "any child that is not `policy`": that rejects supported
// `inactive: policy ...` statements and #2419's synthetic census placeholders.
// The legacy check exempts the inactive marker and requires `policy` later in
// the child's key list.
//
// SCOPE: `from-zone [ ... ]` shifts the keys so Keys[3] becomes "to-zone". It
// is already refused as an undefined zone; widening the detector to that shape
// would also catch #2419's synthetic census placeholders.
func malformedZonePairShape9246(n *Node) string {
	if n == nil || len(n.Keys) < 4 || n.Keys[2] != "to-zone" {
		return ""
	}
	if len(n.Keys) > 4 {
		bracketed := false
		for i := 3; i < len(n.Keys); i++ {
			if n.KeyBracketed(i) {
				bracketed = true
				break
			}
		}
		if bracketed {
			return "from-zone " + n.Keys[1] + " to-zone [ " + strings.Join(n.Keys[3:], " ") + " ]" +
				": a bracketed [ ... ] zone list is not valid on to-zone — a policy context is ONE " +
				"zone pair. The malformed context is not enforced on tolerant loads; write one " +
				"`from-zone <zone> to-zone <zone>` context per pair"
		}
		return "from-zone " + n.Keys[1] + " to-zone " + n.Keys[3] +
			": extra key tokens `" + strings.Join(n.Keys[4:], " ") + "` follow the single to-zone name " +
			"and have no policy-context meaning. A context is ONE zone pair; put each policy under " +
			"that context and write one context per pair"
	}
	for _, c := range n.Children {
		if len(c.Keys) < 2 || c.Keys[0] == "policy" {
			continue
		}
		// `inactive: policy p1 ...` is a supported Junos statement prefix
		// (#2008 H1), not an absorbed to-zone list.
		if c.Keys[0] == inactiveMarker {
			continue
		}
		carriesRule := false
		for _, k := range c.Keys[1:] {
			if k == "policy" {
				carriesRule = true
				break
			}
		}
		if !carriesRule {
			continue
		}
		return "from-zone " + n.Keys[1] + " to-zone [ " + n.Keys[3] + " " + c.Keys[0] + " ... ]" +
			": a bracketed [ ... ] zone list is not valid on to-zone — a policy context is ONE " +
			"zone pair, so `" + c.Keys[0] + "` and everything after it (" +
			strings.Join(c.Keys[1:], " ") + ") were absorbed as tokens and the policy was NOT " +
			"attached to any context on tolerant loads. Write one `from-zone <zone> to-zone <zone>` context per pair"
	}
	return ""
}
