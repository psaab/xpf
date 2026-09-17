package ipsecname

import "testing"

// TestChildBaseAlphabet9999 pins the ChildBase alphabet pair (#9999): ASCII
// letters and digits plus '-' and '_' pass through, and every other rune —
// including '.', which the pre-#9999 docstring wrongly claimed was kept —
// becomes '-'.
func TestChildBaseAlphabet9999(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"abcXYZ019", "abcXYZ019"},
		{"a-b_c", "a-b_c"},
		{"-", "-"},
		{"_", "_"},
		{"a.b", "a-b"},
		{"...", "---"},
		{"t.s", "t-s"},
		{"a/b", "a-b"},
		{"a:b", "a-b"},
		{"a b", "a-b"},
		{"a@b+c", "a-b-c"},
		{"a\tb", "a-b"},
		{"vpné", "vpn-"},
		{"a.b_c-d e/f", "a-b_c-d-e-f"},
		{"", "traffic-selector"},
	} {
		if got := ChildBase(tc.in); got != tc.want {
			t.Errorf("ChildBase(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestChildBaseOutputStaysInAlphabet9999 sweeps a hostile input through
// ChildBase and requires every output rune to sit inside [A-Za-z0-9_-],
// so a future widening of the switch (e.g. preserving '.') fails loudly.
func TestChildBaseOutputStaysInAlphabet9999(t *testing.T) {
	got := ChildBase("Aa0-_.:/ \t@+%é.")
	for _, r := range got {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-' || r == '_':
		default:
			t.Fatalf("ChildBase output %q has rune %q outside [A-Za-z0-9_-]", got, r)
		}
	}
}
