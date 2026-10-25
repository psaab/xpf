package frr

import (
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16788 (R3-A11-05): Junos evaluates each community member regex
// against each community on the route, but the verbatim render let
// FRR match it against the whole space-joined community string, so
// ^666:.*$ missed any route whose 666 community did not sort first.
// The oracle is regexp.CompilePOSIX evaluated the way FRR's regexec
// evaluates community_str() (sorted values, single spaces).

func renderCommunity16788(t *testing.T, name string, members ...string) string {
	t.Helper()
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			name: {Name: name, Members: members},
		},
	}
	return New().generatePolicyOptions(po)
}

func expandedPatterns16788(t *testing.T, rendered, name string) []string {
	t.Helper()
	prefix := "bgp community-list expanded " + name + " permit "
	var patterns []string
	for _, line := range strings.Split(rendered, "\n") {
		if strings.HasPrefix(line, prefix) {
			patterns = append(patterns, strings.TrimPrefix(line, prefix))
		}
	}
	return patterns
}

func anyMatch16788(t *testing.T, patterns []string, joined string) bool {
	t.Helper()
	for _, p := range patterns {
		if strings.Contains(p, "| ") {
			t.Errorf("rendered pattern %q carries \"| \" (vty pipe hook, R3-A11-04)", p)
		}
		re, err := regexp.CompilePOSIX(p)
		if err != nil {
			t.Fatalf("rendered pattern %q fails POSIX compile: %v", p, err)
		}
		if re.MatchString(joined) {
			return true
		}
	}
	return false
}

// TestCommunityAnchoredMemberPerCommunity16788 is the issue
// acceptance: FROM-666 = ^666:.*$ matches 10.1, 10.2 and 10.3 and
// not 10.4. Pre-fix the single member rendered verbatim, so 10.2
// ("100:1 666:5") missed.
func TestCommunityAnchoredMemberPerCommunity16788(t *testing.T) {
	got := renderCommunity16788(t, "FROM-666", "^666:.*$")
	want := "bgp community-list expanded FROM-666 permit (^|[ ])666:[^ ]*([ ]|$)\n"
	if !strings.Contains(got, want) {
		t.Fatalf("want %q, got:\n%s", want, got)
	}
	patterns := expandedPatterns16788(t, got, "FROM-666")
	if len(patterns) != 1 {
		t.Fatalf("want 1 pattern, got %q", patterns)
	}
	for _, tc := range []struct {
		joined string
		want   bool
	}{
		{"666:5", true},         // 10.1
		{"100:1 666:5", true},   // 10.2 — the peer-controlled bypass
		{"666:5 100:1", true},   // 10.3
		{"100:1", false},        // 10.4
		{"100:1 1666:5", false}, // substring of a longer token
		{"", false},
	} {
		if m := anyMatch16788(t, patterns, tc.joined); m != tc.want {
			t.Errorf("FROM-666 vs %q = %v, want %v", tc.joined, m, tc.want)
		}
	}
}

func TestCommunityPerCommunityTranslation16788(t *testing.T) {
	t.Run("unanchored dot cannot span communities", func(t *testing.T) {
		got := renderCommunity16788(t, "X", "6.6:.*")
		patterns := expandedPatterns16788(t, got, "X")
		if len(patterns) != 1 || patterns[0] != "6[^ ]6:[^ ]*" {
			t.Fatalf("patterns = %q", patterns)
		}
		if anyMatch16788(t, patterns, "6 6:5") {
			t.Errorf("unanchored member matched across the separator")
		}
		if !anyMatch16788(t, patterns, "100:1 6x6:5") {
			t.Errorf("unanchored member must match inside one community")
		}
	})
	t.Run("anchored regex member in a conjunction", func(t *testing.T) {
		got := renderCommunity16788(t, "X", "^666:.*$", "65000:1")
		patterns := expandedPatterns16788(t, got, "X")
		if len(patterns) != 2 {
			t.Fatalf("want 2 permutation patterns, got %q:\n%s", patterns, got)
		}
		for _, tc := range []struct {
			joined string
			want   bool
		}{
			{"65000:1 666:5", true},
			{"666:5 65000:1", true},
			{"100:1 65000:1 666:5", true},
			{"65000:1 1666:5", false},
			{"666:5", false},
			{"65000:1", false},
		} {
			if m := anyMatch16788(t, patterns, tc.joined); m != tc.want {
				t.Errorf("conjunction %q vs %q = %v, want %v", patterns, tc.joined, m, tc.want)
			}
		}
	})
	t.Run("no rendered expanded line carries pipe-space", func(t *testing.T) {
		for _, members := range [][]string{
			{"^666:.*$"}, {"65000:100", "65001:.*"}, {"(65000|65001):100"},
		} {
			got := renderCommunity16788(t, "X", members...)
			for _, line := range strings.Split(got, "\n") {
				if strings.Contains(line, "community-list") && strings.Contains(line, "| ") {
					t.Errorf("members %v rendered a \"| \" line: %q", members, line)
				}
			}
		}
	})
}

// Untranslatable members: the strict predicate rejects them and the
// tolerant render omits the whole definition so referencing terms
// fail closed via communityListMissingAtRender.
func TestCommunityUntranslatableMemberFailsClosed16788(t *testing.T) {
	for _, member := range []string{"65000:[^0-9]+", `65000:\d+`, "^((56) | (78)):(.*)$", "65000:1^2"} {
		if err := config.ValidCommunityMember(member); err == nil {
			t.Errorf("ValidCommunityMember(%q) = nil, want rejection", member)
		}
		got := renderCommunity16788(t, "X", member)
		if strings.Contains(got, "community-list") {
			t.Errorf("untranslatable member %q rendered a list:\n%s", member, got)
		}
		po := &config.PolicyOptionsConfig{Communities: map[string]*config.CommunityDef{
			"X": {Name: "X", Members: []string{member}},
		}}
		if !communityListMissingAtRender(po, "X") {
			t.Errorf("member %q not reported missing; a referencing reject term would dangle fail-open", member)
		}
	}
	// One untranslatable member condemns the whole definition.
	got := renderCommunity16788(t, "X", "65000:100", "65000:[^0-9]+")
	if strings.Contains(got, "community-list") {
		t.Errorf("definition with one untranslatable member rendered:\n%s", got)
	}
}

// The delete backing carries the per-community translation for a
// regex member, not the raw whole-string member.
func TestCommunityDeleteBackingTranslated16788(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"X": {Name: "X", Members: []string{"^666:.*$", "65000:1"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "t", CommunityOp: "delete", CommunityDelete: []string{"X"}, Action: "accept"},
			}},
		},
	}
	got := New().generatePolicyOptions(po)
	backing := communityDeleteListName("X")
	want := "bgp community-list expanded " + backing + " permit (^|[ ])666:[^ ]*([ ]|$)\n"
	if !strings.Contains(got, want) {
		t.Errorf("delete backing lacks the translated regex entry %q:\n%s", want, got)
	}
	if strings.Contains(got, "permit ^666:.*$") {
		t.Errorf("raw whole-string member survived on a backing line:\n%s", got)
	}
	if !strings.Contains(got, " set comm-list "+backing+" delete\n") {
		t.Errorf("delete clause does not target the backing:\n%s", got)
	}
}
