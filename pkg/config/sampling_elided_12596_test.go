package config

import (
	"strings"
	"testing"
)

// #12596: elided/packed interface sampling spellings silently dropped on the
// strict commit path (CheckText -> CompileConfig -> normalizeCompactStanzas).
// The braced spelling compiles; every elided spelling compiled (F,F).

// samplingFlags12596 returns the inet sampling flags (the original
// #12596 contract); samplingFlagsPerFamily12596 returns all four
// per-family flags (#14608).
func samplingFlags12596(t *testing.T, text string) (bool, bool) {
	t.Helper()
	in4, out4, _, _ := samplingFlagsPerFamily12596(t, text)
	return in4, out4
}

func samplingFlagsPerFamily12596(t *testing.T, text string) (bool, bool, bool, bool) {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || len(ifc.Units) == 0 || ifc.Units[0] == nil {
		t.Fatalf("unit missing for %q", text)
	}
	u := ifc.Units[0]
	return u.SamplingV4Input, u.SamplingV4Output, u.SamplingV6Input, u.SamplingV6Output
}

func TestSamplingElidedSpellings12596(t *testing.T) {
	wrap := func(familyBody string) string {
		return "interfaces { ge-0/0/0 { unit 0 { " + familyBody + " } } }"
	}
	cases := []struct {
		name string
		text string
		in   bool
		out  bool
	}{
		{"braced control inet", wrap("family inet { sampling { input; output; } }"), true, true},
		{"family elided sampling braced inet", wrap("family inet sampling { input; }"), true, false},
		{"sampling packed inet", wrap("family inet { sampling input; }"), true, false},
		{"sampling packed output inet", wrap("family inet { sampling output; }"), false, true},
		{"mixed braced then packed inet", wrap("family inet { sampling { input; } sampling output; }"), true, true},
		{"mixed packed then braced inet", wrap("family inet { sampling output; sampling { input; } }"), true, true},
		{"family and sampling packed inet", wrap("family inet sampling input;"), true, false},
		{"family elided sampling braced inet6", "interfaces { ge-0/0/0 { unit 0 { family inet6 sampling { output; } } } }", false, true},
		{"sampling packed inet6", "interfaces { ge-0/0/0 { unit 0 { family inet6 { sampling input; } } } }", true, false},
		{"mixed inet6", "interfaces { ge-0/0/0 { unit 0 { family inet6 { sampling { output; } sampling input; } } } }", true, true},
		{"unit and family elided sampling", "interfaces { ge-0/0/0 { unit 0 family inet sampling { input; } } }", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in4, out4, in6, out6 := samplingFlagsPerFamily12596(t, tc.text)
			// #14608: inet6-spelled cases assert against the V6 flags and
			// must leave V4 unset (and vice versa); the original helper
			// compared every case against the single shared pair.
			in, out, otherIn, otherOut := in4, out4, in6, out6
			if strings.Contains(tc.name, "inet6") {
				in, out, otherIn, otherOut = in6, out6, in4, out4
			}
			if in != tc.in || out != tc.out {
				t.Errorf("sampling = (%v,%v), want (%v,%v) for %q", in, out, tc.in, tc.out, tc.text)
			}
			if otherIn || otherOut {
				t.Errorf("other-family sampling = (%v,%v), want (false,false) for %q", otherIn, otherOut, tc.text)
			}
		})
	}
}
