package config

import "testing"

// #12069 follow-up (MEDIUM, Codex/Astra hostile review on PR #12322):
// standard-community tokenization may split only on bytes that survive the
// render gate as FRR separators. sanitizeFRRValue replaces ASCII controls with
// ASCII spaces but does not alter Unicode separators, so these values must be
// rejected rather than passed to bgpd as a single malformed community token.
func TestCommunityLiteralRejectsUnicodeSeparators12069(t *testing.T) {
	for _, tc := range []struct {
		name, separator string
	}{
		{"no-break space", "\u00a0"},
		{"em space", "\u2003"},
		{"line separator", "\u2028"},
		{"next line (NEL)", "\u0085"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := "65000:1" + tc.separator + "65000:2"
			if frrStandardCommunityLiteral(value) {
				t.Fatalf("frrStandardCommunityLiteral accepted U+%04X as a separator", []rune(tc.separator)[0])
			}
			if err := ValidCommunityMember(value); err == nil {
				t.Fatalf("ValidCommunityMember accepted U+%04X between communities", []rune(tc.separator)[0])
			}
			if _, ok := ResolveCommunityValue(nil, value); ok {
				t.Fatalf("ResolveCommunityValue accepted U+%04X between communities", []rune(tc.separator)[0])
			}
			tree := buildTreeFromSet(t, []string{
				"set policy-options policy-statement P term t1 then community add \"" + value + "\"",
				"set policy-options policy-statement P term t1 then accept",
			})
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("strict CompileConfig accepted U+%04X inside then community add", []rune(tc.separator)[0])
			}
		})
	}
}

func TestCommunityLiteralKeepsASCIITokenSeparators12069(t *testing.T) {
	for _, value := range []string{
		"65000:1 65000:2",
		"65000:1\t65000:2",
		"65000:1\n65000:2",
	} {
		if !frrStandardCommunityLiteral(value) {
			t.Errorf("frrStandardCommunityLiteral rejected ASCII-separated value %q", value)
		}
	}
}
