package daemon

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16001 (EX-4): a term marked UncoveredFamilyExcept16001 (sole-`except`
// prefix-list scope covering no address of the chain's family, tolerated
// on lenient load) must refuse the whole lo0 candidate on BOTH renderers:
// the text oracle emits the nft-invalid refusal bareword (atomic load
// rejected, prior generation retained) and the netlink DTO carries
// FromUnrepresentable. Without the refusal the v6 chain renders no
// predicate (empty except = match ALL) and installs the term's action
// for every host-bound v6 packet.
//
// FAIL-ON-REVERT: dropping either arm makes the corresponding assertion
// go RED while the other stays green.

func TestLo0UncoveredExceptRefusesCandidate16001(t *testing.T) {
	term := config.FirewallFilterTerm{
		Name:                       "accept-uncovered-except",
		Action:                     config.FilterActionAccept,
		SourcePrefixLists:          []config.PrefixListRef{{Name: "mgmt-v4", Except: true}},
		UncoveredFamilyExcept16001: true,
	}
	cfg := lo0Cfg9875(&term)
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
		"mgmt-v4": {Name: "mgmt-v4", Prefixes: []string{"10.0.0.0/8"}},
	}
	textRules := nftRulesFromTerm(&term, "ip6", cfg.PolicyOptions.PrefixLists)
	want := []string{nftRefuseUnrepresentableFrom}
	if !reflect.DeepEqual(textRules, want) {
		t.Fatalf("text oracle rules = %v, want refusal %v", textRules, want)
	}
	lowered := lowerLo0Term9875(t, cfg)
	if !lowered.FromUnrepresentable {
		t.Fatal("netlink DTO must carry FromUnrepresentable to refuse the candidate (#16001)")
	}
}

// Anti-over-fix control: the identical term without the marker renders
// its authored rule on the covered family and is not refused.
func TestLo0CoveredExceptDoesNotRefuse16001(t *testing.T) {
	term := config.FirewallFilterTerm{
		Name:              "accept-covered-except",
		Action:            config.FilterActionAccept,
		SourcePrefixLists: []config.PrefixListRef{{Name: "mgmt-v4", Except: true}},
	}
	cfg := lo0Cfg9875(&term)
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
		"mgmt-v4": {Name: "mgmt-v4", Prefixes: []string{"10.0.0.0/8"}},
	}
	rules := nftRulesFromTerm(&term, "ip", cfg.PolicyOptions.PrefixLists)
	if reflect.DeepEqual(rules, []string{nftRefuseUnrepresentableFrom}) {
		t.Fatalf("a covered except term must not refuse the candidate, got %v", rules)
	}
	if len(rules) == 0 {
		t.Fatal("a covered except term must still render its rule on the v4 chain")
	}
	if lowered := lowerLo0Term9875(t, cfg); lowered.FromUnrepresentable {
		t.Fatal("a covered except term must not set FromUnrepresentable (#16001)")
	}
}
