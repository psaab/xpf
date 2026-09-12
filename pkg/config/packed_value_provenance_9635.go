package config

// #9635: an AUTHORED quoted or bracketed value that happens to spell a sibling
// keyword was read as a statement head by two passes that never consulted how
// the operator wrote it.
//
//	security { ike { policy P1 { proposals [ P "proposal-set" ]; } } }
//
// `proposal-set` is a sibling of `proposals` under `ike policy`, so the packed
// splitter ended the multi-value statement there and produced
// `proposals P;` + `proposal-set;`, and SchemaValidate then refused the config
// with "proposal-set: missing value". The operator wrote a reference to a
// proposal that is merely NAMED like another keyword, quoted it, and put it in
// a bracketed list -- three marks saying "value" -- and none was read.
//
// The rule below is deliberately NOT "a quoted token is always a value". That
// was tried and it regressed a valid config, because Junos accepts a quoted
// statement HEAD by its decoded text:
//
//	security { ike { policy P1 { pre-shared-key ascii-text "s" "mode" aggressive; } } }
//
// `pre-shared-key` is fixed-arity (args: 2), so once `ascii-text` and the key
// are consumed it CANNOT own another value and the quoted `"mode"` really does
// begin the next statement. Master splits that correctly and must keep doing so.
//
// So the question is about the statement BEFORE the token, not the token alone:
// an authored value may stay a value only where the preceding leaf could accept
// another one. Both readers -- the packed splitter and the #8437 fusion gate --
// ask it through the two helpers here, because a config one accepted and the
// other refused is the exact failure #9635 records.

// leafOwnsMoreValues9635 reports whether a leaf can carry more values than its
// declared arg span: a `multi` leaf, or a `valueList` leaf (a multi leaf that
// also declares modifier children). A fixed-arity leaf is saturated at
// `1 + args` and anything past it is a different statement.
func leafOwnsMoreValues9635(s *schemaNode) bool {
	return s != nil && (s.multi || s.valueList)
}

// authoredValueMask9635 unions the quoted and bracketed per-key masks into one
// "the operator marked this token as a value" mask, or nil when the node
// carries no provenance at all.
//
// A node built by hand -- compiler synthesis, a config persisted before #6673 --
// legitimately has neither mask, and nil here means every caller falls back to
// the text-only behaviour that shipped before this change. That is the safe
// direction: no provenance recovers exactly master's split.
func authoredValueMask9635(quoted, bracketed []bool, n int) []bool {
	q := keyMask8921(quoted, n)
	b := keyMask8921(bracketed, n)
	if q == nil && b == nil {
		return nil
	}
	out := make([]bool, n)
	for i := range out {
		out[i] = (q != nil && q[i]) || (b != nil && b[i])
	}
	return out
}

// authoredValueRun9635 returns how many tokens past `from` were authored as
// values, given that the leaf at hand can own more of them. Zero when the leaf
// is saturated, when there is no provenance, or when the next token was written
// bare -- a bare sibling keyword still ends the statement, which is what every
// existing #8768 cell pins.
func authoredValueRun9635(leaf *schemaNode, mask []bool, from int) int {
	if !leafOwnsMoreValues9635(leaf) || mask == nil {
		return 0
	}
	n := 0
	for from+n < len(mask) && mask[from+n] {
		n++
	}
	return n
}
