package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17977: `65000:[^| ]` passed the translator verbatim (the #16788
// pipe check only inspected a "|" outside brackets) and rendered
// `bgp community-list expanded NEG permit 65000:[^| ]`. FRR's vty pipe
// hook refuses any line containing "| " while frr-reload.py exits 0,
// so the list silently never installed and the referencing reject term
// never matched — communityListMissingAtRender stayed false because
// the belt thought the definition rendered. The translator now refuses
// the class, so the belt omits the whole definition and the reject
// term lowers fail-closed (#10822 posture), exactly like the other
// pipe-unsafe members.

func TestCommunityBracketPipeRender17977(t *testing.T) {
	member := "65000:[^| ]"
	po := communityPolicyPO(
		map[string]*config.CommunityDef{"NEG": {Name: "NEG", Members: []string{member}}},
		[]*config.PolicyTerm{
			{Name: "t-reject", FromCommunity: []string{"NEG"}, Action: "reject"},
			{Name: "t-accept", Action: "accept"},
		}, "accept")
	got := New().generatePolicyOptions(po)
	if strings.Contains(got, "| ") {
		t.Fatalf("rendered config contains \"| \" the vty pipe hook would refuse:\n%s", got)
	}
	if strings.Contains(got, "NEG permit") || strings.Contains(got, "match community") {
		t.Fatalf("negated-bracket pipe member rendered or dangled instead of failing closed:\n%s", got)
	}
	if !communityListMissingAtRender(po, "NEG") {
		t.Errorf("negated-bracket definition not reported missing; the reject would dangle")
	}
	if !strings.Contains(got, "route-map P deny 10\nexit\n") {
		t.Errorf("reject term did not lower to deny-all:\n%s", got)
	}

	// Multi-member conjunction: the untranslatable factor makes every
	// permutation pattern fail to build, so the whole definition (public
	// list and #16835 chain backings) is omitted.
	gotMulti := renderCommunity15008(t, member, "65000:1")
	if strings.Contains(gotMulti, "| ") || strings.Contains(gotMulti, "community-list") {
		t.Fatalf("conjunction with the pipe-unsafe factor rendered:\n%s", gotMulti)
	}

	// Control: the pipe-free spelling the refusal directs to still
	// renders (a community token never contains |, so [^ ] carries the
	// same per-community meaning).
	ok := renderCommunity15008(t, "65000:[^ ]")
	if !strings.Contains(ok, "community-list") || strings.Contains(ok, "| ") {
		t.Fatalf("pipe-free negated class no longer renders:\n%s", ok)
	}
}
