package config

import (
	"strings"
	"testing"
)

// #17977: a bracket class whose verbatim spelling carries "| " (e.g.
// `[^| ]`) sailed through the #16788 translator: the pipe refusal only
// inspected a "|" OUTSIDE brackets, while scanCommunityBracket returned
// the class text verbatim — so `bgp community-list expanded X permit
// 65000:[^| ]` rendered with a literal "| " that FRR's vty pipe hook
// (handle_pipe_action, raw strstr) refuses while frr-reload.py exits 0:
// the list silently never installed and a referencing reject term never
// matched. The bracket scan now refuses any class whose text spells
// "| ", so the member is strict-rejected, warned on tolerant load, and
// omitted at render like every other pipe-unsafe member. Classes that
// render no "| " (`[^ ]`, `[|]`, `[^ |]`, `[a|b]`) stay accepted.

func TestCommunityBracketPipeSpace17977(t *testing.T) {
	refused := []string{
		"65000:[^| ]",     // the issue's member: negated, space excluded via the "| " spelling
		"65000:[^x| ]",    // same, with another excluded literal
		"^65000:[^| ]$",   // anchored spelling
		"65000:[^| ]:9",   // class mid-member
		"65000:[^| ][^ ]", // only the first factor is pipe-unsafe
	}
	for _, m := range refused {
		if err := ValidCommunityMember(m); err == nil {
			t.Errorf("ValidCommunityMember(%q) = nil, want pipe refusal (#17977)", m)
		} else if !strings.Contains(err.Error(), "17977") {
			t.Errorf("ValidCommunityMember(%q) error %q does not cite #17977", m, err)
		}
		if _, err := TranslateCommunityMemberRegex(m); err == nil {
			t.Errorf("TranslateCommunityMemberRegex(%q) = nil error, want refusal", m)
		}
		if err := ValidCommunityMemberPipe16776(m); err == nil {
			t.Errorf("ValidCommunityMemberPipe16776(%q) = nil, want refusal", m)
		}
	}
	// Already refused since #16788 for the space axis; pins that the
	// #17977 change does not loosen it.
	if err := ValidCommunityMember("65000:[| ]"); err == nil {
		t.Errorf("ValidCommunityMember(%q) = nil, want the #16788 space-matching-class refusal", "65000:[| ]")
	}

	// Guard against over-rejection: a class whose rendered text carries
	// no "| " stays translatable. `[|]` and `[^ |]` confine to one token
	// and never match the separator; `[^ ]` is the translator's own
	// recommended space-excluding spelling; `[a|b]` alternates inside a
	// class; a bare alternation without the trailing space was always
	// pipe-safe.
	accepted := []string{"65000:[^ ]", "65000:[|]", "65000:[^ |]", "65000:[a|b]", "65000:1|666:.*"}
	for _, m := range accepted {
		if err := ValidCommunityMember(m); err != nil {
			t.Errorf("ValidCommunityMember(%q) = %v, want accepted (renders no \"| \")", m, err)
		}
		pattern, err := TranslateCommunityMemberRegex(m)
		if err != nil {
			t.Errorf("TranslateCommunityMemberRegex(%q) = %v, want pattern", m, err)
			continue
		}
		if strings.Contains(pattern, "| ") {
			t.Errorf("TranslateCommunityMemberRegex(%q) = %q, renders \"| \"", m, pattern)
		}
	}
}

func TestCommunityBracketPipeStrictLenient17977(t *testing.T) {
	lines := []string{
		`set policy-options community C17977 members "65000:[^| ]"`,
		"set policy-options policy-statement P term t-reject from community C17977",
		"set policy-options policy-statement P term t-reject then reject",
	}
	if _, err := CompileConfig(buildTree9007(t, lines...)); err == nil || !strings.Contains(err.Error(), "17977") {
		t.Fatalf("strict compile of negated-bracket pipe member = %v, want #17977 refusal", err)
	}
	cfg, err := CompileConfigLenient(buildTree9007(t, lines...))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	warned := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "17977") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("tolerant load did not warn about the pipe-unsafe bracket member; warnings=%v", cfg.Warnings)
	}
}
