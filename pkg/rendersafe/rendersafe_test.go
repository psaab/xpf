package rendersafe

import (
	"strings"
	"testing"
)

// TestReplaceControlBytesReplacesTheWholeC0SetAndDEL is the primitive's own
// contract. It is exhaustive over the byte range rather than sampling, because
// the failure this guards is a future edit NARROWING the class -- "surely 0x0B
// is harmless" -- and a sampled test is exactly what such an edit slips past.
func TestReplaceControlBytesReplacesTheWholeC0SetAndDEL(t *testing.T) {
	for b := 0; b < 0x100; b++ {
		in := string([]byte{'a', byte(b), 'z'})
		got := ReplaceControlBytes(in, '_')
		ctl := b < 0x20 || b == 0x7f
		want := in
		if ctl {
			want = "a_z"
		}
		if got != want {
			t.Fatalf("byte %#02x: got %q, want %q (control=%v)", b, got, want, ctl)
		}
	}
}

// TestReplaceControlBytesLeavesCleanInputUnaltered pins the fast path's
// OBSERVABLE half. A version that always rebuilt the string would still be
// correct, so this asserts equality of contents rather than identity of the
// backing array -- the property a caller can actually depend on.
func TestReplaceControlBytesLeavesCleanInputUnaltered(t *testing.T) {
	for _, s := range []string{"", "plain", "with spaces", "non-ascii: \u00fc\u00f1", "tabs?no"} {
		if got := ReplaceControlBytes(s, '_'); got != s {
			t.Errorf("clean input %q was altered to %q", s, got)
		}
	}
}

// TestReplaceControlBytesNeverSplitsARune asserts the UTF-8 safety claim the doc
// comment makes, rather than leaving it as prose.
//
// It holds because C0 and DEL can never appear as a UTF-8 continuation byte, so
// a byte-wise scan cannot land inside a multi-byte rune. If someone widened the
// class to "any byte >= 0x7F", this reds -- and that widening is precisely the
// plausible-looking edit the package doc warns about.
func TestReplaceControlBytesNeverSplitsARune(t *testing.T) {
	in := "a\u00e9\u65e5b\u00e7"
	got := ReplaceControlBytes(in, ' ')
	for _, r := range []rune{'\u00e9', '\u65e5', '\u00e7'} {
		if !strings.ContainsRune(got, r) {
			t.Fatalf("multi-byte rune %q did not survive: %q -> %q", r, in, got)
		}
	}
}

// TestReplaceControlBytesHonoursTheCallersSubstitute pins that the substitute is
// the CALLER's choice.
//
// The whole point of #6833 is that the safe substitute is a per-consumer fact. A
// primitive that hardcoded a space would pull that decision back inside, which is
// the shape this package exists to undo.
func TestReplaceControlBytesHonoursTheCallersSubstitute(t *testing.T) {
	if got := ReplaceControlBytes("a\nb", '\t'); got != "a\tb" {
		t.Errorf("got %q, want a<tab>b", got)
	}
	if got := ReplaceControlBytes("a\nb", '?'); got != "a?b" {
		t.Errorf("got %q, want %q", got, "a?b")
	}
}

// TestRendersAsOnePatternRefusesExactlyASCIIWhitespace is exhaustive over the
// byte range, for the same reason the ReplaceControlBytes contract test is: the
// guarded failure is a future edit NARROWING the refused class ("surely \v is
// harmless") or WIDENING it to strings.Fields ("surely unicode spaces split
// too"). Both edits look like cleanups; a sampled test is what they slip past.
//
// Control bytes other than whitespace PASS here BY DESIGN: this predicate
// answers slot-count only ("ge\x010" IS one slot). Render refusal of controls
// is SafeInterfaceName's job, pinned exhaustively below — no render caller
// may use this predicate alone.
func TestRendersAsOnePatternRefusesExactlyASCIIWhitespace(t *testing.T) {
	for b := range 0x100 {
		in := "a" + string(rune(b)) + "z"
		got := RendersAsOnePattern(in)
		ws := b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r'
		if got == ws {
			t.Fatalf("byte %#02x: RendersAsOnePattern(%q) = %v, want %v (ascii-whitespace=%v)", b, in, got, !ws, ws)
		}
	}
}

// TestRendersAsOnePatternShape pins the non-obvious structural cases: empty is
// zero slots, not one; padding refuses even though the core is clean.
func TestRendersAsOnePatternShape(t *testing.T) {
	for _, bad := range []string{"", " ", " ge0", "ge0 ", "ge 0", "ge-0-0-0 eth0", "ge\t0", "ge\n0", "ge\r0", "ge\v0", "ge\f0"} {
		if RendersAsOnePattern(bad) {
			t.Errorf("RendersAsOnePattern(%q) = true, want false", bad)
		}
	}
	for _, ok := range []string{"ge-0/0/0", "ge-0-0-0", "reth0.50", "fab0", "em0", "br-bd0", "lo0", "a_b", "x.y", "z-", "g\u00e90"} {
		if !RendersAsOnePattern(ok) {
			t.Errorf("RendersAsOnePattern(%q) = false, want true", ok)
		}
	}
}

// TestRendersAsOnePatternPassesUnicodeSpaces pins the deliberate divergence
// from strings.Fields (#9886): NBSP, NEL and friends are kernel-legal and
// systemd-atomic, so a pre-gate config carrying one keeps booting. A future
// edit "simplifying" the predicate to Fields reds here.
func TestRendersAsOnePatternPassesUnicodeSpaces(t *testing.T) {
	for _, name := range []string{"ge\u00a00", "ge\u00850", "ge\u20280", "ge\u20030"} {
		if !RendersAsOnePattern(name) {
			t.Errorf("RendersAsOnePattern(%q) = false, want true — unicode spaces are atomic to systemd", name)
		}
	}
	if RendersAsOnePattern("") {
		t.Error("empty name must not render as one pattern")
	}
}

// TestRendersAsOnePatternPassesGlobsDeferredTo10089 pins the known-deferred
// pass-through: glob metacharacters are exactly one pattern, so they PASS this
// predicate. Render-side glob refusal is #10089; when it lands this test flips
// to refusal. Leading-dash names likewise pass here — one pattern, and the argv
// sink is #9885's belt, not this predicate's.
func TestRendersAsOnePatternPassesGlobsDeferredTo10089(t *testing.T) {
	for _, name := range []string{"ge*", "ge?", "ge[0-9]", "*", "--help", "-x"} {
		if !RendersAsOnePattern(name) {
			t.Errorf("RendersAsOnePattern(%q) = false, want true (glob/argv classes are not this predicate's — see #10089/#9885)", name)
		}
	}
}

// TestSafeInterfaceNameRefusesWhitespaceAndControls is the RENDER contract,
// exhaustive over the byte range: any ASCII whitespace or any C0/DEL byte
// refuses, everything else passes (including the unicode spaces NBSP/NEL,
// which the kernel allows and systemd treats atomically, and glob
// metacharacters, whose render refusal is #10089's, not this predicate's).
func TestSafeInterfaceNameRefusesWhitespaceAndControls(t *testing.T) {
	for b := range 0x100 {
		in := "a" + string(rune(b)) + "z"
		got := SafeInterfaceName(in)
		ws := b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r'
		ctl := b < 0x20 || b == 0x7f
		if got == (ws || ctl) {
			t.Fatalf("byte %#02x: SafeInterfaceName(%q) = %v, want %v (whitespace=%v control=%v)", b, in, got, !(ws || ctl), ws, ctl)
		}
	}
	if SafeInterfaceName("") {
		t.Fatal("SafeInterfaceName(\"\") = true, want false — empty is zero slots")
	}
	for _, ok := range []string{"ge-0/0/0", "ge-0-0-0", "fab0", "br-bd0", "g\u00e90", "ge\u00a00", "ge*", "--help"} {
		if !SafeInterfaceName(ok) {
			t.Errorf("SafeInterfaceName(%q) = false, want true", ok)
		}
	}
}
