package ipsecname

import "testing"

// TestSectionNamePredicates9495 pins both predicates against the measured rows in
// docs/log/9495.md: SectionSafe is the commit allowlist, SectionBreaking the narrower render belt.
func TestSectionNamePredicates9495(t *testing.T) {
	for _, tc := range []struct {
		name           string
		safe, breaking bool
	}{
		{"plain", true, false},
		{"vpn-1_a", true, false},
		{"", false, true},
		{"evil } # {", false, true},
		{"x # y", false, true},
		{"a=b", false, true},
		{"a,b", false, true},
		{"a b", false, true},
		{`a"b`, false, true},
		{"a.b", false, true},
		{"a%b", false, true},
		{"a:b", false, true},
		{"vpné", false, true},
		{"x { children { p { mode = transport } } } y", false, true},
		{"a/b", false, false}, // loaded verbatim: refused at commit, still rendered if persisted
		{"a@b", false, false},
	} {
		if got := SectionSafe(tc.name); got != tc.safe {
			t.Errorf("SectionSafe(%q) = %v, want %v", tc.name, got, tc.safe)
		}
		if got := SectionBreaking(tc.name); got != tc.breaking {
			t.Errorf("SectionBreaking(%q) = %v, want %v", tc.name, got, tc.breaking)
		}
	}
}

// TestChildBaseMapsDot9495: a dotted selector name rendered child `sel-t.s`, which strongSwan
// cannot parse, so nothing in the file loaded. ChildBase now maps '.' like every other character.
func TestChildBaseMapsDot9495(t *testing.T) {
	if got := ChildBase("t.s"); got != "t-s" {
		t.Fatalf("ChildBase(%q) = %q, want %q", "t.s", got, "t-s")
	}
	if got := ChildBase("ts_1-a"); got != "ts_1-a" {
		t.Fatalf("ChildBase(%q) = %q, want it unchanged", "ts_1-a", got)
	}
}
