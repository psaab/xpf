package config

import "testing"

// #15082: a top/up-prefixed mutation must be adjudicated as the
// inner command at the TARGET cursor. Bare top/up stay ungated
// (navigation), but `top delete <denied>` must not ride through
// ungated now that the dispatchers execute it.

func TestTopUpPrefixedMutationGatedAtTarget15082(t *testing.T) {
	deny := classWithConfigRegex9154(t, "", "^security policies")
	// Control: direct denied delete is refused.
	if err := AuthorizeConfigMutation(deny, "limited", nil, "delete security policies p1"); err == nil {
		t.Fatal("premise: direct denied delete was allowed")
	}
	deep := []string{"security", "policies", "from-zone", "trust"}
	// top: inner resolves at root.
	if err := AuthorizeConfigMutation(deny, "limited", deep, "top delete security policies p1"); err == nil {
		t.Error("top delete of denied path was ALLOWED (#15082)")
	}
	// up 1 from [security policies]: target [security]; inner `delete policies p1` -> security policies p1.
	if err := AuthorizeConfigMutation(deny, "limited", []string{"security", "policies"}, "up delete policies p1"); err == nil {
		t.Error("up delete of denied path was ALLOWED (#15082)")
	}
	// Allowed control stays allowed.
	if err := AuthorizeConfigMutation(deny, "limited", deep, "top delete system host-name x"); err != nil {
		t.Errorf("top delete of allowed path refused: %v", err)
	}
	// Bare navigation stays ungated even under a deny.
	for _, line := range []string{"top", "up", "up 2"} {
		if err := AuthorizeConfigMutation(deny, "limited", deep, line); err != nil {
			t.Errorf("bare %q gated as a mutation: %v", line, err)
		}
	}
}

func TestResolveTopUpPrefix15082(t *testing.T) {
	edit := []string{"a", "b", "c"}
	cases := []struct {
		line       string
		wantTarget string
		wantInner  string
		wantOK     bool
	}{
		{"top", "", "", true},
		{"top delete a b", "", "delete a b", true},
		{"up", "a b", "", true},
		{"up delete b c", "a b", "delete b c", true},
		{"up 1 delete b c", "a b", "delete b c", true},
		{"up 2 delete c", "a", "delete c", true},
		{"up 2", "a", "", true},
		{"up 99", "", "", true},           // bare: clamped to root
		{"up 99 delete c", "", "", false}, // prefixed: out of range, fail closed
		{"up 99999999999999999999 delete c", "", "", false},
	}
	for _, tc := range cases {
		parts, quoted := lexConfigMutationLine9938(tc.line)
		target, inner, _, ok := ResolveTopUpPrefix15082(edit, parts, quoted)
		if ok != tc.wantOK {
			t.Errorf("%q: ok=%v want %v", tc.line, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if got := join15082(target); got != tc.wantTarget {
			t.Errorf("%q: target=%q want %q", tc.line, got, tc.wantTarget)
		}
		if got := join15082(inner); got != tc.wantInner {
			t.Errorf("%q: inner=%q want %q", tc.line, got, tc.wantInner)
		}
	}
}

func join15082(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " "
		}
		out += p
	}
	return out
}
