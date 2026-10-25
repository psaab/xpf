package config

import (
	"regexp"
	"strings"
	"testing"
)

// #16788 (R3-A11-05): Junos evaluates each community member regex
// against each community on the route; FRR evaluates an expanded list
// against the whole space-joined sorted community string. The
// translator rewrites a member into a per-community pattern. The
// oracle below is Go's POSIX ERE — the dialect FRR compiles with
// regcomp(REG_EXTENDED) — evaluated against joined strings the way
// FRR's regexec evaluates community_str().

func TestTranslateCommunityMemberRegex16788Table(t *testing.T) {
	cases := []struct {
		junos string
		want  string
	}{
		{"^666:.*$", "(^|[ ])666:[^ ]*([ ]|$)"},
		{"^666:", "(^|[ ])666:"},
		{"666:.*", "666:[^ ]*"},
		{"65000:.*", "65000:[^ ]*"},
		{"65000:*", "65000:*"},
		{"65000:1{2,3}", "65000:1{2,3}"},
		{"(65000|65001):100", "(65000|65001):100"},
		{"65000:[0-9]+", "65000:[0-9]+"},
		{"65000:[^ ]+", "65000:[^ ]+"},
		{"65000:a.c", "65000:a[^ ]c"},
		{"65000:[.]", "65000:[.]"},
		{"^65000:[0-9]+$", "(^|[ ])65000:[0-9]+([ ]|$)"},
	}
	for _, tc := range cases {
		got, err := TranslateCommunityMemberRegex(tc.junos)
		if err != nil {
			t.Errorf("TranslateCommunityMemberRegex(%q): %v", tc.junos, err)
			continue
		}
		if got != tc.want {
			t.Errorf("TranslateCommunityMemberRegex(%q) = %q, want %q", tc.junos, got, tc.want)
		}
		if strings.Contains(got, "| ") {
			t.Errorf("translation %q of %q carries \"| \" (vty pipe hook, R3-A11-04)", got, tc.junos)
		}
		if _, err := regexp.CompilePOSIX(got); err != nil {
			t.Errorf("translation %q of %q fails POSIX compile: %v", got, tc.junos, err)
		}
	}
}

func TestTranslateCommunityMemberRegex16788PerCommunitySemantics(t *testing.T) {
	pattern, err := TranslateCommunityMemberRegex("^666:.*$")
	if err != nil {
		t.Fatal(err)
	}
	re, err := regexp.CompilePOSIX(pattern)
	if err != nil {
		t.Fatal(err)
	}
	// Numbered after the issue acceptance: FROM-666 matches 10.1,
	// 10.2 and 10.3 and not 10.4.
	for _, tc := range []struct {
		joined string
		want   bool
	}{
		{"666:5", true},         // 10.1 sole community
		{"100:1 666:5", true},   // 10.2 matching community not first
		{"666:5 100:1", true},   // 10.3 matching community first
		{"100:1", false},        // 10.4 no 666 community
		{"100:1 1666:5", false}, // token merely containing 666:
		{"100:1 6665:1", false}, // different AS number
		{"100:666:5", false},    // one token, not a 666 community
		{"100:1 666:", true},    // 666:.* admits the empty value part
		{"", false},
	} {
		if got := re.MatchString(tc.joined); got != tc.want {
			t.Errorf("pattern %q vs %q = %v, want %v", pattern, tc.joined, got, tc.want)
		}
	}

	// A "." must not span communities: ^6.6:.*$ against "6 6:5" would
	// match across the separator if "." stayed a wildcard.
	dot, err := TranslateCommunityMemberRegex("^6.6:.*$")
	if err != nil {
		t.Fatal(err)
	}
	dotRE, err := regexp.CompilePOSIX(dot)
	if err != nil {
		t.Fatal(err)
	}
	if dotRE.MatchString("6 6:5") {
		t.Errorf("confined pattern %q matched across the separator in %q", dot, "6 6:5")
	}
	if !dotRE.MatchString("100:1 6x6:5") {
		t.Errorf("confined pattern %q must match a single community 6x6:5", dot)
	}

	// Unanchored members keep Junos substring meaning within a token.
	sub, err := TranslateCommunityMemberRegex("666:")
	if err != nil {
		t.Fatal(err)
	}
	subRE, err := regexp.CompilePOSIX(sub)
	if err != nil {
		t.Fatal(err)
	}
	if !subRE.MatchString("100:1 1666:5") {
		t.Errorf("unanchored member translation %q lost substring match inside one community", sub)
	}
	if subRE.MatchString("100:1 66 6:5") {
		t.Errorf("unanchored member translation %q matched across the separator", sub)
	}
}

func TestTranslateCommunityMemberRegex16788Rejects(t *testing.T) {
	for _, in := range []string{
		"", "^$", "65000:1 65001:2", "65000:1^", "65000:$1", "65$000",
		`65000:\d+`, `65000:\s`, `65000:\w+`, "65000:(?=1)", "65000:[",
		"65000:[^0-9]+", "65000:[^:]+", "65000:[a-z ]",
		"65000:[[:alpha:]]+", "65000:[[:space:]]", "^((56) | (78)):(.*)$",
		"65000:.* ", " 65000:.*",
	} {
		if got, err := TranslateCommunityMemberRegex(in); err == nil {
			t.Errorf("TranslateCommunityMemberRegex(%q) = %q, want rejection", in, got)
		}
		if err := ValidCommunityMember(in); err == nil && CommunityMemberIsRegex(in) {
			t.Errorf("ValidCommunityMember(%q) accepts an untranslatable regex member", in)
		}
	}
}

// The strict gate must accept the canonical anchored idiom and the
// members that rendered before, and reject only the untranslatable.
func TestValidCommunityMember16788Gate(t *testing.T) {
	for _, ok := range []string{
		"^666:.*$", "^65000:", "65000:.*", "65000:*", "65000:1{2,3}",
		"(65000|65001):100", "65000:[0-9]+", "65000:[^ ]+",
	} {
		if err := ValidCommunityMember(ok); err != nil {
			t.Errorf("ValidCommunityMember(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"65000:[^0-9]+", `65000:\d+`, "^((56) | (78)):(.*)$", "65000:1^2"} {
		if err := ValidCommunityMember(bad); err == nil {
			t.Errorf("ValidCommunityMember(%q) = nil, want strict rejection (#16788)", bad)
		}
	}
}
