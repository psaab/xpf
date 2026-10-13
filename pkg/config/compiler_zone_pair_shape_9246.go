package config

import (
	"slices"
	"strings"
)

// malformedZonePairShape9246 reports zone-pair key shapes whose tail the
// policy compiler cannot represent, or "" when the shape is valid.
//
// There are three malformed AST forms:
//
//   - Grouped set input and hierarchical text preserve every to-zone token on
//     the context node. The compiler reads only Keys[1] and Keys[3], silently
//     dropping later to-zone tokens.
//   - A bracketed from-zone list shifts the keys so "to-zone" moves to Keys[3]
//     or later. The pair builder then treats that keyword as the destination
//     zone and drops the actual destination and attached policy.
//   - The legacy ungrouped parser absorbs the rest of the statement into a
//     non-policy child, so the context has no attached rule.
//
// The first two forms are checked by key shape even when bracket provenance is
// absent; provenance only lets the diagnostic name an authored bracket list.
// The third uses the narrower absorbed-rule signature rather than rejecting
// every unexpected child.
//
// WHY NOT "any child that is not `policy`": that rejects supported
// `inactive: policy ...` statements and #2419's synthetic census placeholders.
// The legacy check exempts the inactive marker and requires `policy` later in
// the child's key list.
//
// SCOPE: #2419 synthesizes bare `from-zone xpfarg xpfarg xpfarg` census
// placeholders. The explicit helper excludes that exact placeholder prefix
// (with or without the schema's shifted `to-zone` token); bracket provenance
// keeps an authored list of those same values in scope.
func isSyntheticFromZoneCensusPlaceholder9246(n *Node) bool {
	if n == nil || len(n.Keys) < 4 || n.Keys[0] != "from-zone" ||
		n.KeyBracketed(1) || n.KeyBracketed(2) || n.KeyBracketed(3) {
		return false
	}
	return n.Keys[1] == "xpfarg" && n.Keys[2] == "xpfarg" &&
		(n.Keys[3] == "xpfarg" || n.Keys[3] == "to-zone")
}

func malformedZonePairShape9246(n *Node) string {
	if n == nil || len(n.Keys) < 4 {
		return ""
	}
	if n.Keys[0] == "from-zone" && n.Keys[2] != "to-zone" &&
		!isSyntheticFromZoneCensusPlaceholder9246(n) {
		for i := 3; i < len(n.Keys); i++ {
			if n.Keys[i] != "to-zone" {
				continue
			}
			toZone := ""
			if destination := fromListDestination9246(n, i); destination != "" {
				toZone = " " + destination
			}
			return "from-zone [ " + strings.Join(n.Keys[1:i], " ") + " ] to-zone" + toZone +
				": a bracketed [ ... ] zone list is not valid on from-zone — a policy context is ONE " +
				"zone pair. The malformed context is skipped on tolerant loads and the userspace " +
				"policy snapshot is refused; write one `from-zone <zone> to-zone <zone>` context per pair"
		}
	}
	if n.Keys[2] != "to-zone" {
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

// fromListDestination9246 renders the destination of a malformed from-list
// context whose `to-zone` keyword is n.Keys[toZone] (#12510). The producers
// place it differently:
//
//   - Hierarchical text keeps every token between `to-zone` and `{` on the
//     context node; its children are body statements.
//   - Grouped and legacy set input end the context node at `to-zone` and fold
//     each statement's destination into its body: a scalar leads a leaf
//     (`B policy p1 ...`), a bracketed list becomes a container whose
//     descendants carry the rest of the statement. Text formatted from such a
//     tree reparses to the same shape. Prefix-identical contexts share the
//     node, so every distinct destination is named, in child order.
//
// Either way the destination ends at the policy keyword, so a context that
// authored none (`to-zone [ ]`) names no zone rather than `policy` or its tail.
func fromListDestination9246(n *Node, toZone int) string {
	if toZone+1 < len(n.Keys) {
		destination, _ := zoneTokenRun9246(n, toZone+1, "")
		return destination
	}
	var destinations []string
	for _, c := range n.Children {
		destinations = appendBodyDestinations9246(destinations, c, "")
	}
	return strings.Join(destinations, ", ")
}

// appendBodyDestinations9246 appends the destination spelled along each
// statement path from n, continuing prefix, unless it is already listed.
func appendBodyDestinations9246(destinations []string, n *Node, prefix string) []string {
	destination, ended := zoneTokenRun9246(n, 0, prefix)
	if !ended && len(n.Children) > 0 {
		for _, c := range n.Children {
			destinations = appendBodyDestinations9246(destinations, c, destination)
		}
		return destinations
	}
	if destination == "" || slices.Contains(destinations, destination) {
		return destinations
	}
	return append(destinations, destination)
}

// zoneTokenRun9246 appends n.Keys[start:] up to the policy keyword (or the
// `inactive:` prefix of a policy statement) to prefix, spelling each authored
// [ ... ] run as a list. ended reports whether that keyword was reached.
func zoneTokenRun9246(n *Node, start int, prefix string) (run string, ended bool) {
	var b strings.Builder
	b.WriteString(prefix)
	inList := false
	for i := start; i < len(n.Keys); i++ {
		if n.Keys[i] == "policy" || n.Keys[i] == inactiveMarker {
			ended = true
			break
		}
		bracketed := n.KeyBracketed(i)
		if inList && !bracketed {
			b.WriteString(" ]")
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		if bracketed && !inList {
			b.WriteString("[ ")
		}
		inList = bracketed
		b.WriteString(n.Keys[i])
	}
	if inList {
		b.WriteString(" ]")
	}
	return b.String(), ended
}
