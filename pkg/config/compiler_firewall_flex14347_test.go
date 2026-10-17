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

// TestFlexibleMatchRangeSubByteCompilesFieldAligned14634 pins the #14634
// compiler contract: a sub-byte flexible-match-range term compiles clean
// (clean commit is NOT the bug — the evaluated bits were), records nothing
// on UnknownFlexMatch, and preserves the operator-authored field value/mask
// verbatim in FlexMatchConfig. The MSB-first alignment to the ceil-byte
// window happens at each matcher boundary (userspace snapshot builder, lo0
// nft renderers), NOT here, so this test guards against a fix that rewrites
// the stored config pair (which would double-shift through any boundary that
// also aligns, and corrupt `show` / forensic rendering of the authored
// value). Acceptance from the issue: `bit-length 4 byte-offset 0 range 4`
// (default mask, or explicit match-mask 0xf) must discard an IPv4 packet
// whose first byte is 0x45 — pinned end-to-end at the snapshot and Rust
// layers; this test pins the compiler half of that chain.
func TestFlexibleMatchRangeSubByteCompilesFieldAligned14634(t *testing.T) {
	for _, tc := range []struct {
		name      string
		from      string
		wantValue uint32
		wantMask  uint32
		wantBits  uint8
	}{
		{"range-form-default-mask", `flexible-match-range { range R { byte-offset 0; bit-length 4; range 0x4; } }`, 0x4, 0xF, 4},
		{"match-value-default-mask", `flexible-match-range { range R { byte-offset 0; bit-length 4; match-value 0x4; } }`, 0x4, 0xF, 4},
		{"explicit-junos-mask", `flexible-match-range { range R { byte-offset 0; bit-length 4; match-value 0x4; match-mask 0xf; } }`, 0x4, 0xF, 4},
		{"range-form-explicit-mask", `flexible-match-range { range R { byte-offset 0; bit-length 4; range 0x4/0xf; } }`, 0x4, 0xF, 4},
		{"sub-byte-12", `flexible-match-range { range R { byte-offset 0; bit-length 12; match-value 0xabc; } }`, 0xABC, 0xFFF, 12},
		{"byte-aligned-8-control", `flexible-match-range { range R { byte-offset 0; bit-length 8; match-value 0x45; } }`, 0x45, 0xFF, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(fwTree8480(t, tc.from))
			if err != nil {
				t.Fatalf("sub-byte flex term must commit clean: %v", err)
			}
			term := firstInetTerm(t, cfg, "F")
			if len(term.UnknownFlexMatch) != 0 {
				t.Fatalf("UnknownFlexMatch=%v, want empty", term.UnknownFlexMatch)
			}
			fm := term.FlexMatch
			if fm == nil {
				t.Fatal("FlexMatch nil")
			}
			if fm.Value != tc.wantValue || fm.Mask != tc.wantMask || fm.BitLength != tc.wantBits || fm.ByteOffset != 0 {
				t.Errorf("FlexMatch = {Value:0x%x Mask:0x%x BitLength:%d ByteOffset:%d}, "+
					"want field pair {Value:0x%x Mask:0x%x BitLength:%d ByteOffset:0} — "+
					"the compiler must preserve the authored field pair; MSB alignment "+
					"belongs to the matcher boundaries (#14634)",
					fm.Value, fm.Mask, fm.BitLength, fm.ByteOffset, tc.wantValue, tc.wantMask, tc.wantBits)
			}
		})
	}
}
