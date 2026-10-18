package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14700 (A): narrowedAliasEligible10821 must not bypass the non-suffix
// ghost refusal for fall-through/empty survivors. A ghost authored before
// (or between) survivors was ordered to preempt them; appending a trailing
// deny after all survivors cannot restore that ordering, so the collision
// belt must refuse the attachment instead of attaching the alias.

// TestNarrowedGhostBeforeFallThroughSurvivorRefused14700 is the decisive
// regression: [GHOST, ACCEPTER] where ACCEPTER is fall-through must be
// refused by narrowedAliasCollision10129, and the managed section must not
// attach the narrowed alias.
//
// FAIL-ON-REVERT: restoring narrowedAliasEligible10821's unconditional
// fall-through/empty eligibility makes the collision return nil and the
// alias attach — red here.
func TestNarrowedGhostBeforeFallThroughSurvivorRefused14700(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{{
				Address: "10.0.2.3", PeerAS: 65002, FamilyInet: true,
				Import: []string{"GHOST", "ACCEPTER"},
			}},
		},
	}
	sites := narrowedChainSites(fc.BGP, po)
	if len(sites) != 1 || sites[0].GhostsAreSuffix {
		t.Fatalf("want one non-suffix narrowed site, got %+v", sites)
	}
	if narrowedAliasEligible10821(sites[0], po) {
		t.Fatalf("non-suffix fall-through survivor must not be alias-eligible: %+v", sites[0])
	}
	if err := narrowedAliasCollision10129(fc); err == nil {
		t.Fatalf("ghost before fall-through survivor must be refused, got nil")
	} else if !strings.Contains(err.Error(), "non-suffix") {
		t.Fatalf("refusal must name non-suffix mechanism, got %v", err)
	}
	section := New().buildManagedSection(fc)
	alias := narrowedAliasName10129([]string{"ACCEPTER"})
	if strings.Contains(section, "route-map "+alias+" ") {
		t.Fatalf("refused chain must not attach/emit narrowed alias %q:\n%s", alias, section)
	}
}

// TestNarrowedGhostMiddleFallThroughSurvivorRefused14700 covers ghost-middle.
func TestNarrowedGhostMiddleFallThroughSurvivorRefused14700(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{{
				Address: "10.0.2.3", PeerAS: 65002, FamilyInet: true,
				Import: []string{"ACCEPTER", "GHOST", "B"},
			}},
		},
	}
	if err := narrowedAliasCollision10129(fc); err == nil {
		t.Fatalf("ghost-middle fall-through chain must be refused, got nil")
	}
}

// TestNarrowedSuffixFallThroughStillAlias14700 is the control: suffix ghosts
// keep the deny alias.
func TestNarrowedSuffixFallThroughStillAlias14700(t *testing.T) {
	po := policyOptions10129()
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{{
				Address: "10.0.2.3", PeerAS: 65002, FamilyInet: true,
				Import: []string{"ACCEPTER", "GHOST"},
			}},
		},
	}
	if err := narrowedAliasCollision10129(fc); err != nil {
		t.Fatalf("suffix fall-through must stay alias-eligible, got %v", err)
	}
	section := New().buildManagedSection(fc)
	alias := narrowedAliasName10129([]string{"ACCEPTER"})
	if !strings.Contains(section, "route-map "+alias+" ") {
		t.Fatalf("suffix chain must attach alias %q:\n%s", alias, section)
	}
}

// #14700 (B): a reject term over a mixed-family prefix-list with one
// all-malformed family must render a per-family deny-all for the dropped
// family, not silently drop that family's ref.

// TestRejectTermMixedFamilyPrefixListOneFamilyMalformedRendersDenyAll is
// the decisive regression named by the issue.
//
// FAIL-ON-REVERT: restoring the "any family renders => not dangling" rule
// emits only the v4 deny and lets v6 routes fall through — red here.
func TestRejectTermMixedFamilyPrefixListOneFamilyMalformedRendersDenyAll(t *testing.T) {
	defs := map[string]*config.PrefixList{
		"PARTIAL": {Name: "PARTIAL", Prefixes: []string{"10.0.0.0/8", "2001:db8::/999"}},
	}
	po := prefixListPolicyPO(defs, []*config.PolicyTerm{
		{Name: "t-reject", PrefixList: []string{"PARTIAL"}, Action: "reject"},
		{Name: "t-accept", Action: "accept"},
	}, "accept")
	got := New().generatePolicyOptions(po)
	// Fine v4 branch keeps its deny.
	if !strings.Contains(got, "route-map P deny 10\n match ip address prefix-list PARTIAL\nexit\n") {
		t.Fatalf("reject dropped the fine v4 branch:\n%s", got)
	}
	// Dropped v6 family must get a bare deny-all (no match line).
	if !strings.Contains(got, "route-map P deny 20\nexit\n") {
		t.Fatalf("reject must render bare deny-all for dropped v6 family (seq 20):\n%s", got)
	}
	if strings.Contains(got, "match ipv6 address prefix-list PARTIAL") {
		t.Fatalf("reject kept dangling v6 match:\n%s", got)
	}
	// Accept term and trailing permit must still follow.
	if !strings.Contains(got, "route-map P permit 30\n") {
		t.Fatalf("following accept term must remain at seq 30:\n%s", got)
	}
}

// TestAcceptTermMixedFamilyPrefixListOneFamilyMalformedKeepsFine14700:
// for accept, the dropped family contributes nothing (subset direction);
// no deny-all broadening, fine v4 branch kept.
func TestAcceptTermMixedFamilyPrefixListOneFamilyMalformedKeepsFine14700(t *testing.T) {
	defs := map[string]*config.PrefixList{
		"PARTIAL": {Name: "PARTIAL", Prefixes: []string{"10.0.0.0/8", "2001:db8::/999"}},
	}
	po := prefixListPolicyPO(defs, []*config.PolicyTerm{
		{Name: "t-accept", PrefixList: []string{"PARTIAL"}, Action: "accept"},
	}, "reject")
	got := New().generatePolicyOptions(po)
	if !strings.Contains(got, "match ip address prefix-list PARTIAL") {
		t.Fatalf("accept dropped fine v4 branch:\n%s", got)
	}
	if strings.Contains(got, "match ipv6 address prefix-list PARTIAL") {
		t.Fatalf("accept kept dangling v6 match:\n%s", got)
	}
	if n := strings.Count(got, "route-map P permit "); n != 1 {
		t.Fatalf("accept must emit only fine v4 permit, got %d:\n%s", n, got)
	}
	if n := strings.Count(got, "route-map P deny "); n != 1 {
		t.Fatalf("accept must not render per-family deny-all (only trailing deny), got %d:\n%s", n, got)
	}
}
