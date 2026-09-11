package config

// bracketedLaterMember9799 reports whether n is a statement whose key group
// was authored inside `[ ... ]` and names `name` as a LATER member: not the
// first key after the keyword, which the multi-key walks already match (#9799).
//
// `security-zone [ zga zgb ] { tcp-rst; }` is one node, Keys [security-zone zga
// zgb]. Every walk matched it by Keys[1], so `zga` reached the group and `zgb`
// reached nothing: `show ... security-zone zgb` printed nothing, and delete and
// deactivate said `no node matching "security-zone zgb"` about a zone the
// operator can see in `show configuration`.
//
// Bracket PROVENANCE is what makes the later keys member names rather than a
// packed body. `security-zone trust screen edge;` also carries keys past the
// name, but none was authored bracketed, so `edge` is never read as a zone. A
// node with no provenance at all (synthesized, or from a config DB written
// before #6668) answers false for every key, so it is never claimed either.
func bracketedLaterMember9799(n *Node, keyword, name string) bool {
	if n == nil || len(n.Keys) < 3 || n.Keys[0] != keyword || !n.KeyBracketed(1) {
		return false
	}
	for j := 2; j < len(n.Keys); j++ {
		if !n.KeyBracketed(j) {
			return false // the group ended before a later key named `name`
		}
		if n.Keys[j] == name {
			return true
		}
	}
	return false
}

// groupCarryingLaterMember9799 returns the Keys of the first node in nodes
// that is a bracketed group naming tail[1] as a later member of the tail[0]
// statement, or nil. A path that continues past the member (into the group's
// body) is included: that body is shared with every other member.
func groupCarryingLaterMember9799(nodes []*Node, tail []string) []string {
	if len(tail) < 2 {
		return nil
	}
	for _, n := range nodes {
		if bracketedLaterMember9799(n, tail[0], tail[1]) {
			return n.Keys
		}
	}
	return nil
}
