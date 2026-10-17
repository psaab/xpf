package config

import (
	"strings"
	"testing"
)

// #14347: compileFilterFrom read only named `range` instances under
// flexible-match-range and, inside a range, silently ignored unknown leaves,
// valueless leaves, trailing tokens and children-carried bodies. Each silently
// defaulted (Value 0, Mask 0xFFFFFFFF, BitLength 32) or dropped, so a strict
// commit accepted a materially different match. The fix records every such
// shape on UnknownFlexMatch; validateFilterFlexMatchStrict rejects strict and
// the tolerant path warns + poisons the term.
func TestFlexibleMatchRangeDirectAndMalformedRangeLeavesRejectedStrict(t *testing.T) {
	rows := []struct {
		name string
		from string
		want string // substring expected in UnknownFlexMatch / error
	}{
		{"direct leaves", `flexible-match-range { match-start layer-4; match-value 0x11; }`, "flexible-match-range"},
		{"direct single leaf", `flexible-match-range { byte-offset 9; }`, "flexible-match-range"},
		{"unknown child beside range", `flexible-match-range { range R { match-value 0x11; } typo-leaf 1; }`, "typo-leaf"},
		{"nameless range block", `flexible-match-range { range { match-value 0x11; } }`, "range"},
		{"bare range keyword", `flexible-match-range { range; }`, "range"},
		{"valueless match-value", `flexible-match-range { range R { match-value; byte-offset 9; } }`, "match-value"},
		{"valueless byte-offset", `flexible-match-range { range R { byte-offset; } }`, "byte-offset"},
		{"valueless match-start", `flexible-match-range { range R { match-start; } }`, "match-start"},
		{"unknown leaf in range", `flexible-match-range { range R { typo-match-value 0xdeadbeef; } }`, "typo-match-value"},
		{"trailing token", `flexible-match-range { range R { match-start layer-4 extra; match-value 0x11; } }`, "match-start"},
		{"trailing token match-value", `flexible-match-range { range R { match-value 0x11 extra; } }`, "match-value"},
		{"empty range", `flexible-match-range { range R { } }`, "range R"},
		{"children under leaf", `flexible-match-range { range R { byte-offset { 9; } } }`, "byte-offset"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			tree := fwTree8480(t, row.from)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("strict must reject %s (%s)", row.name, row.from)
			} else if !strings.Contains(err.Error(), "flexible-match-range") {
				t.Fatalf("strict error must name flexible-match-range, got: %v", err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient must not hard-fail: %v", err)
			}
			term := firstInetTerm(t, cfg, "F")
			joined := strings.Join(term.UnknownFlexMatch, ",")
			if !strings.Contains(joined, row.want) {
				t.Fatalf("UnknownFlexMatch=%v must contain %q", term.UnknownFlexMatch, row.want)
			}
			// Lenient must warn (operator-visible).
			var warned bool
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "flexible-match-range") {
					warned = true
				}
			}
			if !warned {
				t.Fatalf("lenient must warn about flexible-match-range, got %v", cfg.Warnings)
			}
		})
	}

	// Flat-set shapes reach the same compiler path.
	flatRows := []struct {
		name string
		cmds []string
		want string
	}{
		{"flat direct leaf", []string{
			"set firewall family inet filter F term T from flexible-match-range match-value 0x11",
			"set firewall family inet filter F term T then discard"}, "flexible-match-range"},
		{"flat valueless", []string{
			"set firewall family inet filter F term T from flexible-match-range range R match-value",
			"set firewall family inet filter F term T then discard"}, "match-value"},
		{"flat unknown leaf", []string{
			"set firewall family inet filter F term T from flexible-match-range range R typo-match-value 0xdeadbeef",
			"set firewall family inet filter F term T then discard"}, "typo-match-value"},
		{"flat extra token nested", []string{
			"set firewall family inet filter F term T from flexible-match-range range R match-start layer-4 extra",
			"set firewall family inet filter F term T then discard"}, "match-start"},
	}
	for _, row := range flatRows {
		t.Run(row.name, func(t *testing.T) {
			tree := buildFilterTree(t, row.cmds...)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("strict must reject flat %s", row.name)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient: %v", err)
			}
			term := firstInetTerm(t, cfg, "F")
			if !strings.Contains(strings.Join(term.UnknownFlexMatch, ","), row.want) {
				t.Fatalf("UnknownFlexMatch=%v must contain %q", term.UnknownFlexMatch, row.want)
			}
		})
	}

	// Controls: valid shapes must still commit clean and record nothing.
	controls := []string{
		`flexible-match-range { range R { match-start layer-4; byte-offset 9; bit-length 8; match-value 0x11; match-mask 0xFF; } }`,
		`flexible-match-range { range R { range 0x11/0xFF; } }`,
		`flexible-match-range { range R { byte-offset 9; match-value 0x11; } range R { bit-length 8; } }`,
	}
	for i, from := range controls {
		tree := fwTree8480(t, from)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("control %d must commit: %v", i, err)
		}
		term := firstInetTerm(t, cfg, "F")
		if len(term.UnknownFlexMatch) != 0 {
			t.Fatalf("control %d UnknownFlexMatch=%v", i, term.UnknownFlexMatch)
		}
		if term.FlexMatch == nil {
			t.Fatalf("control %d FlexMatch nil", i)
		}
	}
	// Empty flexible-match-range block: no range authored — existing control
	// in #8480/#9875 suites expects this to commit (nothing written).
	if _, err := CompileConfig(fwTree8480(t, `flexible-match-range { match-start layer-3; byte-offset 4; }`)); err == nil {
		t.Fatalf("direct-leaf control regression: direct leaves must now reject (see rows above)")
	}
}
