package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func renderCommunity8449(t *testing.T, members ...string) string {
	t.Helper()
	m := &Manager{}
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"c1": {Name: "c1", Members: members},
			// A second, always-valid definition. It is the POSITIVE CONTROL:
			// the belt must omit only the condemned definition, not stop
			// rendering community-lists altogether.
			"cok": {Name: "cok", Members: []string{"65001:200"}},
		},
	}
	return m.generatePolicyOptions(po, nil)
}

// #8449: a member that forces the expanded list kind but does not compile as a
// POSIX ERE was rendered VERBATIM into frr.conf, where FRR's regcomp failure
// fails the ENTIRE frr-reload. The strict commit gate rejects it, but the
// tolerant Load / peer-sync path only warns (#1960), so the renderer needs its
// own belt — exactly as the #6686 as-path path does.
func TestCommunityRenderBeltOmitsUnrenderable_8449(t *testing.T) {
	for _, bad := range []string{"65000:[", "*65000", ""} {
		got := renderCommunity8449(t, bad)
		if strings.Contains(got, "community-list expanded c1") ||
			strings.Contains(got, "community-list standard c1") {
			t.Errorf("member %q was rendered into frr.conf — it poisons the whole reload:\n%s",
				bad, got)
		}
		// CONTROL: the sibling definition must still render, or this cell would
		// pass simply by rendering nothing at all.
		if !strings.Contains(got, "community-list standard cok permit 65001:200") {
			t.Errorf("member %q: the VALID sibling definition was also dropped — "+
				"the belt is omitting too much:\n%s", bad, got)
		}
	}
}

// The omission is per-DEFINITION. FRR does not allow one list name to be both
// standard and expanded, so a half-rendered list would change the kind decision
// itself. One bad member condemns every member of that definition.
func TestCommunityRenderBeltIsPerDefinition_8449(t *testing.T) {
	got := renderCommunity8449(t, "65000:100", "no-export", "65000:[")
	for _, sibling := range []string{"65000:100", "no-export"} {
		if strings.Contains(got, "permit "+sibling) {
			t.Errorf("valid sibling %q of a condemned definition was still rendered — "+
				"a half-rendered list changes the standard/expanded kind decision:\n%s",
				sibling, got)
		}
	}
	if !strings.Contains(got, "community-list standard cok permit 65001:200") {
		t.Errorf("the unrelated definition was dropped too:\n%s", got)
	}
}

// Every VALID member must still render exactly as before. A belt that narrows
// working configs is worse than the bug it fixes.
func TestCommunityRenderBeltDoesNotNarrowValidMembers_8449(t *testing.T) {
	cases := map[string]string{
		"65000:100":    "bgp community-list standard c1 permit 65000:100",
		"no-export":    "bgp community-list standard c1 permit no-export",
		"65000:.*":     "bgp community-list expanded c1 permit 65000:[^ ]*",
		"^65000:":      "bgp community-list expanded c1 permit (^|[ ])65000:",
		"65000:1{2,3}": "bgp community-list expanded c1 permit 65000:1{2,3}",
	}
	for member, want := range cases {
		got := renderCommunity8449(t, member)
		if !strings.Contains(got, want) {
			t.Errorf("valid member %q no longer renders %q:\n%s", member, want, got)
		}
	}
}

// #8449. `communityRegexChars` is an ALIAS of config.CommunityRegexChars, so
// today this assertion is true by construction — and that is precisely its job.
// It fires the moment someone turns the alias back into a second literal, which
// is a SURVIVING mutation against every other cell in this package: measured,
// drifting the copy to `*.+?^$()|\` (dropping the brackets and braces) left the
// whole pkg/frr suite green while the renderer and the commit gate disagreed
// about which members FRR compiles.
//
// The render side decides standard-vs-expanded; the commit gate decides what to
// reject. If they read different character sets, a member the gate waves through
// as "standard, not compiled" is rendered into an EXPANDED list and compiled
// after all — poisoning the reload the gate exists to prevent.
func TestCommunityRegexCharsIsTheSharedConstant_8449(t *testing.T) {
	if communityRegexChars != config.CommunityRegexChars {
		t.Fatalf("pkg/frr communityRegexChars = %q but config.CommunityRegexChars = %q; "+
			"the renderer's list-kind decision and the commit gate now disagree about "+
			"which members FRR runs through regcomp",
			communityRegexChars, config.CommunityRegexChars)
	}
}
