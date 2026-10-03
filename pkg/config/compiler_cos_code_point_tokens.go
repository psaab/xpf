package config

import (
	"strconv"
	"strings"
)

// compiler_cos_code_point_tokens.go — CoS code-point token parsing.
//
// Extracted from compiler_class_of_service.go (#8436 batch), which crossed the
// 1500-LOC modularity WATCH floor. The split is along a real seam rather than at
// a line count: every function here turns the code-point TOKENS of a
// classifier/rewrite-rule statement into the numeric points the dataplane
// carries — `coSCodePointTokens` reads them off the node, the five
// `collectCoS*` functions validate and expand them per family (DSCP,
// inet-precedence, 802.1p, and the two rewrite variants), and
// `expandCoSCodePointToken` is the shared alias/range expander they all call.
// Nothing else in the CoS compiler parses code points, and none of these touch
// the container/instance structure the rest of that file builds.
//
// Pure relocation — no production logic changed.

// coSCodePointTokens returns every code-point token authored under `leaf`
// (`code-points`, or the scalar `code-point` a rewrite-rule entry uses) on a
// CoS loss-priority node, across ALL the spellings the Junos grammar admits:
//
//	code-points [ ef af11 ];    -> the leaf node's own tail, Keys[1:]
//	code-points ef;             -> ditto, once per repeated statement
//	code-points { ef; af11; }   -> the leaf node's CHILDREN, one token each
//	loss-priority low code-points ef;  -> the loss-priority node's own tail (#1809)
//
// #6697: NONE of the five CoS code-point readers read the leaf node's children,
// so the hierarchical BLOCK spelling compiled to nothing at all. That is not a
// truncated list — the compiler stores a classifier only when it has at least
// one entry, so the whole classifier went MISSING while `show class-of-service`
// rendered the authored config back intact. Two of the five readers (the
// rewrite-rule pair) additionally missed the inline `loss-priority low
// code-point ef;` tail, which is the spelling Junos itself emits.
//
// Because each caller's per-value domain check runs on what this returns, the
// unread shape was also a GATE ESCAPE and not merely a value drop:
// `code-points { totally-bogus; }` committed CLEAN where the identical token in
// `code-points [ totally-bogus ]` was REJECTED. Every caller MUST keep running
// its check over EVERY token this returns; see docs/config-schema.md, "A
// one-sided read is a GATE ESCAPE".
//
// Each child contributes ALL of its keys, not just Keys[0]: the flat-set
// bracket list lands on a child's Keys when the leaf is not `multi` in
// setSchema, which is the #7126 shape — reading Children is not the same as
// reading every KEY of each child.
func coSCodePointTokens(node *Node, leaf string) []string {
	var out []string
	for _, child := range node.FindChildren(leaf) {
		out = append(out, child.Keys[1:]...)
		for _, grandchild := range child.Children {
			out = append(out, grandchild.Keys...)
		}
	}
	// Inline leaf spelling (#1809): "loss-priority low code-points ef;" packs
	// the code points into the loss-priority node's own Keys after the leaf
	// token (bracketed lists arrive bracket-stripped).
	for i := 2; i < len(node.Keys); i++ {
		if node.Keys[i] == leaf {
			out = append(out, node.Keys[i+1:]...)
			break
		}
	}
	return out
}

func collectCoSDSCPCodePoints(node *Node) ([]uint8, error) {
	var values []uint8
	seen := make(map[uint8]struct{})
	add := func(raw string) error {
		expanded, err := expandCoSCodePointToken(raw)
		if err != nil {
			return err
		}
		for _, value := range expanded {
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
		return nil
	}
	// #6697: every authored spelling, INCLUDING the hierarchical block form,
	// runs through `add` — which is the only place a DSCP code point is
	// checked, so widening the read also closes the gate escape.
	for _, raw := range coSCodePointTokens(node, "code-points") {
		if err := add(raw); err != nil {
			return nil, err
		}
	}
	return values, nil
}

// collectCoSINetPrecedenceCodePoints collects the `code-points` values of an
// inet-precedence classifier entry (#6847). IP precedence is the top 3 bits of
// the IPv4 TOS byte, domain 0..7 — the same width as an 802.1p PCP but a
// different field, so it gets its own message wording rather than borrowing the
// 802.1p collector's. Out-of-range and non-numeric tokens are REJECTED at
// commit (warn-and-drop on the tolerant path via the shared downgradable-error
// classification) rather than silently skipped: a dropped code point installs a
// classifier that quietly does not cover the traffic the operator named.
func collectCoSINetPrecedenceCodePoints(node *Node) ([]uint8, error) {
	var values []uint8
	seen := make(map[uint8]struct{})
	add := func(raw string) error {
		raw = strings.TrimSpace(strings.ToLower(raw))
		if raw == "" {
			return nil
		}
		v, ok := coSINetPrecedenceCodePointValue(raw)
		if !ok {
			return newUnknownCodePointTokenError(
				"class-of-service inet-precedence classifier code-point %q is not a valid "+
					"0..7 value, 3-bit binary (000..111) or IP-precedence alias", raw)
		}
		if v < 0 || v > 7 {
			return newCodePointRangeError(
				"class-of-service inet-precedence classifier code-point %d is out of range (must be 0..7)",
				v)
		}
		value := uint8(v)
		if _, ok := seen[value]; ok {
			return nil
		}
		seen[value] = struct{}{}
		values = append(values, value)
		return nil
	}
	// #6697: every spelling, block form included, runs through `add`.
	for _, raw := range coSCodePointTokens(node, "code-points") {
		if err := add(raw); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func collectCoS8021CodePoints(node *Node) ([]uint8, error) {
	var values []uint8
	seen := make(map[uint8]struct{})
	// #2447: an 802.1p code-point is the 3-bit PCP field, domain 0..7. A
	// numeric token outside that range is REJECTED at commit rather than
	// silently dropped (pre-fix) or clamped to 7 by the dataplane builder —
	// a clamp would install the classifier for a DIFFERENT traffic class.
	add := func(raw string) error {
		raw = strings.TrimSpace(strings.ToLower(raw))
		if raw == "" {
			return nil
		}
		v, err := strconv.Atoi(raw)
		if err != nil {
			// #5194 A3-b2-F12: 802.1p has no symbolic aliases, so a non-numeric
			// token is always a typo. The pre-fix code silently skipped it in
			// both strict and tolerant paths; reject it at commit (warn-and-drop
			// on tolerant load) like the numeric out-of-range path below.
			return newUnknownCodePointTokenError(
				"class-of-service ieee-802.1 classifier code-point %q is not a valid 0..7 value", raw)
		}
		if v < 0 || v > 7 {
			return newCodePointRangeError(
				"class-of-service ieee-802.1 classifier code-point %d is out of range (must be 0..7)",
				v)
		}
		value := uint8(v)
		if _, ok := seen[value]; ok {
			return nil
		}
		seen[value] = struct{}{}
		values = append(values, value)
		return nil
	}
	// #6697: every spelling, block form included, runs through `add`.
	for _, raw := range coSCodePointTokens(node, "code-points") {
		if err := add(raw); err != nil {
			return nil, err
		}
	}
	return values, nil
}

// A rewrite-rule entry writes exactly ONE code point, so the first resolvable
// token wins — but EVERY token still passes the domain check on the way there
// (#6697), because skipping the check for the tokens after the first would
// re-open the gate escape on a different axis. `code-point` is the Junos leaf;
// `code-points` is accepted as an alias for it.
func collectCoSDSCPRewriteCodePoint(node *Node) (uint8, bool, error) {
	var first uint8
	found := false
	for _, leaf := range []string{"code-point", "code-points"} {
		for _, raw := range coSCodePointTokens(node, leaf) {
			values, err := expandCoSCodePointToken(raw)
			if err != nil {
				return 0, false, err
			}
			if len(values) > 0 && !found {
				first, found = values[0], true
			}
		}
	}
	return first, found, nil
}

// collectCoS8021RewriteCodePoint preserves the public family-specific
// diagnostic while sharing the 3-bit parser with inert inet-precedence and
// EXP rewrites.
func collectCoS8021RewriteCodePoint(node *Node) (uint8, bool, error) {
	return collectCoS3BitRewriteCodePoint(node, "ieee-802.1")
}

// collectCoS3BitRewriteCodePoint resolves a single numeric rewrite value in the
// 0..7 domain. Both `code-point` and its `code-points` alias are read; the first
// value wins, but every token is checked so an invalid later token cannot hide
// behind a valid first one.
func collectCoS3BitRewriteCodePoint(node *Node, family string) (uint8, bool, error) {
	parse := func(raw string) (uint8, bool, error) {
		raw = strings.TrimSpace(strings.ToLower(raw))
		if raw == "" {
			return 0, false, nil
		}
		v, err := strconv.Atoi(raw)
		if err != nil {
			return 0, false, newUnknownCodePointTokenError(
				"class-of-service %s rewrite-rule code-point %q is not a valid 0..7 value",
				family, raw)
		}
		if v < 0 || v > 7 {
			return 0, false, newCodePointRangeError(
				"class-of-service %s rewrite-rule code-point %d is out of range (must be 0..7)",
				family, v)
		}
		return uint8(v), true, nil
	}
	var first uint8
	found := false
	for _, leaf := range []string{"code-point", "code-points"} {
		for _, raw := range coSCodePointTokens(node, leaf) {
			value, ok, err := parse(raw)
			if err != nil {
				return 0, false, err
			}
			if ok && !found {
				first, found = value, true
			}
		}
	}
	return first, found, nil
}

// expandCoSCodePointToken resolves a DSCP code-point token (a symbolic
// alias such as `ef`/`af11`/`cs6` or a numeric value) to its 0..63 DSCP
// value(s).
//
// #2447: a NUMERIC token outside the 6-bit DSCP domain (0..63) is an
// out-of-range error, REJECTED at commit. The pre-fix code silently
// returned nil (dropping the entry), and the dataplane builder masked
// `dscp & 0x3f` — so a configured DSCP 110 silently installed a
// classifier for DSCP 46, a DIFFERENT traffic class, with no commit
// error. A non-numeric, non-alias token (a typo) is NOT an error here —
// it returns no values (the entry is skipped), preserving the pre-fix
// Junos-compatibility behavior for unknown symbolic spellings.
func expandCoSCodePointToken(raw string) ([]uint8, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return nil, nil
	}
	if value, ok := coSDSCPValues[raw]; ok {
		return []uint8{value}, nil
	}
	if v, err := strconv.Atoi(raw); err == nil {
		if v < 0 || v > 63 {
			return nil, newCodePointRangeError(
				"class-of-service dscp code-point %d is out of range (must be 0..63)",
				v)
		}
		return []uint8{uint8(v)}, nil
	}
	// #5194 A3-b2-F12: a non-numeric, non-alias token is a typo (e.g. `af99`).
	// The pre-fix code returned no values and no error, silently dropping the
	// classifier/rewrite entry in BOTH strict and tolerant paths. Reject it at
	// commit (warn-and-drop on tolerant load) like the numeric out-of-range
	// path so the operator sees the typo instead of a silently missing class.
	return nil, newUnknownCodePointTokenError(
		"class-of-service dscp code-point %q is not a valid DSCP alias or 0..63 value", raw)
}

var coSDSCPValues = map[string]uint8{
	"default": 0,
	"be":      0,
	"ef":      46,
	"af11":    10,
	"af12":    12,
	"af13":    14,
	"af21":    18,
	"af22":    20,
	"af23":    22,
	"af31":    26,
	"af32":    28,
	"af33":    30,
	"af41":    34,
	"af42":    36,
	"af43":    38,
	"cs0":     0,
	"cs1":     8,
	"cs2":     16,
	"cs3":     24,
	"cs4":     32,
	"cs5":     40,
	"cs6":     48,
	"cs7":     56,
}
