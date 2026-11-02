package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16001 (EX-4): a term marked UncoveredFamilyExcept16001 (a sole-`except`
// prefix-list scope covering no address of its pool's family, tolerated on
// lenient load) must refuse the whole userspace snapshot via
// FromUnrepresentable, so reconcile keeps prior-good state instead of
// installing an except+accept term that admits every packet of the
// uncovered family. The covered arm (unmarked) keeps installing.
//
// FAIL-ON-REVERT: dropping `term.UncoveredFamilyExcept16001` from the
// builder's marker condition makes the first assertion go RED.

func uncoveredCfg16001(markV6 bool) *config.Config {
	cfg := &config.Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
		"mgmt-v4": {Name: "mgmt-v4", Prefixes: []string{"10.0.0.0/8"}},
	}
	mkTerm := func(marked bool) *config.FirewallFilterTerm {
		return &config.FirewallFilterTerm{
			Name:                       "t",
			SourcePrefixLists:          []config.PrefixListRef{{Name: "mgmt-v4", Except: true}},
			Action:                     config.FilterActionAccept,
			UncoveredFamilyExcept16001: marked,
		}
	}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"permitMgmt": {Name: "permitMgmt", Terms: []*config.FirewallFilterTerm{mkTerm(false)}},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"permitMgmt": {Name: "permitMgmt", Terms: []*config.FirewallFilterTerm{mkTerm(markV6)}},
	}
	return cfg
}

func TestBuildFirewallFilterSnapshotsUncoveredExceptRefuses16001(t *testing.T) {
	snaps := authoredFilterSnapshots18728(t, BuildFirewallFilterSnapshots(uncoveredCfg16001(true)))
	byFamily := map[string]FirewallTermSnapshot{}
	for _, s := range snaps {
		if len(s.Terms) == 1 {
			byFamily[s.Family] = s.Terms[0]
		}
	}
	v6, ok := byFamily["inet6"]
	if !ok {
		t.Fatalf("snapshots = %+v, want an inet6 term", snaps)
	}
	if !v6.FromUnrepresentable {
		t.Fatal("the marked uncovered-family except term must refuse the candidate snapshot (#16001), not encode a match-all accept")
	}
	// The snapshot still encodes the authored except scope alongside the
	// refusal marker (the Rust side rejects on the marker, never on a
	// widened matcher).
	if !v6.SourceExcept || !v6.SourceConstrained {
		t.Fatalf("the authored except scope must ride the wire with the marker, got %+v", v6)
	}
	v4, ok := byFamily["inet"]
	if !ok {
		t.Fatalf("snapshots = %+v, want an inet term", snaps)
	}
	if v4.FromUnrepresentable {
		t.Fatal("the covered inet arm (unmarked) must NOT refuse — its authored except semantics install")
	}
}

// Anti-over-fix control: the identical config without the marker installs
// exactly as before (hand-built / older-peer terms keep today's behavior).
func TestBuildFirewallFilterSnapshotsUnmarkedExceptInstalls16001(t *testing.T) {
	snaps := authoredFilterSnapshots18728(t, BuildFirewallFilterSnapshots(uncoveredCfg16001(false)))
	for _, s := range snaps {
		for _, term := range s.Terms {
			if term.FromUnrepresentable {
				t.Fatalf("unmarked term must not refuse (%s): %+v", s.Family, term)
			}
		}
	}
}
