package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18055: communityListRenderable judged the RAW member via
// config.ValidCommunityMember while the pattern generators
// (communityExpandedConjunctionPatterns and the per-member branches
// in renderCommunityListDefinitions) judge sanitizeFRRValue(member).
// A directly-constructed (typed-config) member like "65000:[|\t]"
// passes the raw check (the tab is not yet a space), but sanitization
// renders it as "65000:[| ]" — a bracket expression that can match a
// space, which the translator refuses — so renderCommunityListDefinitions
// emitted nothing while communityListMissingAtRender reported the
// definition present. A referencing reject term therefore kept its
// `match community NEG` (+ the route-map deny sequence header) and
// dangled instead of lowering to deny-all: FRR resolves a dangling
// match to NO MATCH, so the reject never fired (fail-open).
//
// The fix judges the sanitized form in communityListRenderable,
// mirroring the #17839 description fix, so definition omission and
// missing-at-render cannot drift.
//
// Production-unreachable today: every FullConfig is built from a
// compiled config whose tree is control-char-scrubbed
// (pkg/config/compiler_prewalk.go sanitizeNodesControlChars; the
// lenient load scrubs [|\t] -> [| ] and the translator then refuses
// it). This pins the typed-PO path so a future caller that hands the
// renderer a typed value directly cannot reopen the dangle.
//
// FAIL-ON-REVERT: reverting communityListRenderable to judge the raw
// member makes communityListRenderable("65000:[|\t]") true again,
// communityListMissingAtRender false, and the render below keep
// `match community NEG` under `route-map P deny 10` instead of the
// bare deny-all — RED on every assertion below.
func TestCommunityTabMemberFailsClosed18055(t *testing.T) {
	member := "65000:[|\t]"

	// Fixture sanity: the raw and sanitized forms must straddle the
	// gate — raw passes, sanitized is refused. If either side stops
	// holding, this cell would pass vacuously.
	if err := config.ValidCommunityMember(member); err != nil {
		t.Fatalf("fixture broken: raw member %q unexpectedly refused: %v", member, err)
	}
	sanitized := sanitizeFRRValue(member)
	if sanitized != "65000:[| ]" {
		t.Fatalf("fixture broken: sanitizeFRRValue(%q) = %q, want %q", member, sanitized, "65000:[| ]")
	}
	if err := config.ValidCommunityMember(sanitized); err == nil {
		t.Fatalf("fixture broken: sanitized member %q unexpectedly passes ValidCommunityMember", sanitized)
	}
	if communityListRenderable([]string{member}) {
		t.Errorf("communityListRenderable(%q) = true; it must judge the sanitized form %q and report unrenderable", member, sanitized)
	}

	po := communityPolicyPO(
		map[string]*config.CommunityDef{"NEG": {Name: "NEG", Members: []string{member}}},
		[]*config.PolicyTerm{
			{Name: "t-reject", FromCommunity: []string{"NEG"}, Action: "reject"},
			{Name: "t-accept", Action: "accept"},
		}, "accept")

	if !communityListMissingAtRender(po, "NEG") {
		t.Errorf("tab-member definition not reported missing; the reject would dangle")
	}

	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "NEG permit") || strings.Contains(got, "community-list") {
		t.Fatalf("tab-member definition rendered instead of being omitted:\n%s", got)
	}
	if strings.Contains(got, "match community") {
		t.Fatalf("a dangling `match community` was emitted instead of lowering the reject to deny-all:\n%s", got)
	}
	if strings.Contains(got, "| ") || strings.Contains(got, "\t") {
		t.Fatalf("rendered config carries the pipe-space/tab payload:\n%s", got)
	}
	// deny-all 10 (the reject, fail-closed), bare permit 20
	// (t-accept), bare permit 30 (accept trailing default) — same
	// shape as the #10822/#17977 fail-closed cells.
	for _, want := range []string{
		"route-map P deny 10\nexit\n",
		"route-map P permit 20\nexit\n",
		"route-map P permit 30\nexit\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}

	// Multi-member conjunction: one tab member poisons the whole
	// definition (public list, delete backing, and #16835 chain
	// backings all share communityListRenderable), so nothing renders.
	gotMulti := renderCommunity15008(t, member, "65000:1")
	if strings.Contains(gotMulti, "community-list") {
		t.Fatalf("conjunction with the tab member rendered:\n%s", gotMulti)
	}
	poMulti := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"X": {Name: "X", Members: []string{member, "65000:1"}},
		},
	}
	if !communityListMissingAtRender(poMulti, "X") {
		t.Errorf("multi-member tab definition not reported missing")
	}
	if target := communityDeleteTarget(poMulti, "X"); target != frrName("X") {
		t.Errorf("communityDeleteTarget for unrenderable multi-member def = %q, want public name %q (no delete backing)", target, frrName("X"))
	}

	// Controls: members whose sanitized form is unchanged and valid
	// still render — a belt that narrows working configs is worse
	// than the bug. The bracket-pipe spelling without the tab
	// ("65000:[|]": '|' is a literal inside the class and cannot
	// match a space) keeps rendering, as does a plain literal.
	ok := renderCommunity15008(t, "65000:[|]")
	if !strings.Contains(ok, "community-list") || strings.Contains(ok, "| ") {
		t.Fatalf("pipe-free bracket member no longer renders:\n%s", ok)
	}
	okLit := renderCommunity15008(t, "65000:1")
	if !strings.Contains(okLit, "bgp community-list standard X permit 65000:1") {
		t.Fatalf("plain literal member no longer renders:\n%s", okLit)
	}
	poOK := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"X": {Name: "X", Members: []string{"65000:1"}},
		},
	}
	if communityListMissingAtRender(poOK, "X") {
		t.Errorf("valid literal definition reported missing")
	}
	if !communityListRenderable([]string{"65000:1"}) {
		t.Errorf("communityListRenderable rejected a valid literal member")
	}
}
