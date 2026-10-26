package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17853: an unanchored regex member used as the first conjunction
// factor was forced to a token start by communitySequencePattern16788,
// which only emitted the [^ ]* mid-token prefix for factors after the
// first. For members ["666:.*" "65000:1"] a route carrying
// "1666:5 65000:1" satisfies both members under the documented
// substring-within-token semantics, so neither permutation matched and
// a matching reject term was skipped. The term deliberately carries a
// sibling match dimension (`from protocol bgp`) to pin that a mixed
// chain keeps the protocol AND while matching each community member.

func TestFirstUnanchoredCommunityFactor17853(t *testing.T) {
	for _, members := range [][]string{
		{"666:.*", "65000:1"},
		{"65000:1", "666:.*"},
	} {
		po := communityPolicyPO(
			map[string]*config.CommunityDef{
				"X": {Name: "X", Members: members},
			},
			[]*config.PolicyTerm{
				{Name: "t-reject", FromCommunity: []string{"X"}, FromProtocols: []string{"bgp"}, Action: "reject"},
				{Name: "t-accept", Action: "accept"},
			}, "accept")
		got := New().generatePolicyOptions(po)
		if !strings.Contains(got, "route-map P permit 10\n") ||
			!strings.Contains(got, "route-map P deny 50\n") {
			t.Fatalf("members %v: mixed reject term did not render chain slots before its protocol body:\n%s", members, got)
		}
		for _, member := range members {
			if !strings.Contains(got, " match community "+communityChainListName16835("X", member)+"\n") {
				t.Fatalf("members %v: reject term omitted chain member %q:\n%s", members, member, got)
			}
		}
		if !strings.Contains(got, " match source-protocol bgp\n") ||
			strings.Contains(got, " match community X\n") {
			t.Fatalf("members %v: mixed chain did not retain source-protocol and replace the public list:\n%s", members, got)
		}
		if !strings.Contains(got, "on-match goto") {
			t.Fatalf("members %v: mixed term has no chain continuation:\n%s", members, got)
		}
		patterns := expandedPatterns16788(t, got, "X")
		if len(patterns) != 2 {
			t.Fatalf("members %v: want 2 permutation patterns, got %q:\n%s", members, patterns, got)
		}
		for _, tc := range []struct {
			joined string
			want   bool
		}{
			{"1666:5 65000:1", true},       // unanchored member mid-token, forward order
			{"65000:1 1666:5", true},       // unanchored member mid-token, reverse order
			{"100:1 1666:5 65000:1", true}, // intervening community before both
			{"666:5 65000:1", true},        // unanchored member at token start still matches
			{"1666:5", false},              // missing the literal member
			{"65000:1", false},             // missing the regex member
			{"65000:1 100:1", false},       // no token contains 666:
			{"66:5 65000:1", false},        // 666: spans no single token
			{"", false},
		} {
			if m := anyMatch16788(t, patterns, tc.joined); m != tc.want {
				t.Errorf("members %v: match(%q) = %v, want %v (patterns %q)", members, tc.joined, m, tc.want, patterns)
			}
		}
	}
}

// The fix must not de-anchor a genuinely anchored first factor: an
// anchored member still refuses a mid-token match.
func TestFirstAnchoredCommunityFactorStaysAnchored17853(t *testing.T) {
	got := renderCommunity16788(t, "X", "^666:.*$", "65000:1")
	patterns := expandedPatterns16788(t, got, "X")
	if len(patterns) != 2 {
		t.Fatalf("want 2 permutation patterns, got %q:\n%s", patterns, got)
	}
	for _, tc := range []struct {
		joined string
		want   bool
	}{
		{"666:5 65000:1", true},
		{"65000:1 666:5", true},
		{"1666:5 65000:1", false},
		{"65000:1 1666:5", false},
	} {
		if m := anyMatch16788(t, patterns, tc.joined); m != tc.want {
			t.Errorf("anchored conjunction: match(%q) = %v, want %v (patterns %q)", tc.joined, m, tc.want, patterns)
		}
	}
}
