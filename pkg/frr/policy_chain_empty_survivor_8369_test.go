package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8369: the case a synthesized deny cannot be decided on without — a chain
// that IS suffix-narrowed (so the #8363 safety condition holds and a deny would
// be emitted) whose surviving member CARRIES NO TERMS.
//
// WHY THIS ONE. #8363's cells sweep ghost-last / ghosts-trailing / ghost-first /
// ghost-middle, all with a surviving member that matches something. None of them
// enters the state where a synthesized bound is AMBIGUOUS: with an empty
// survivor there is nothing for the permit sequence to match, so "append a
// trailing deny" and "make the whole chain deny" are the same render, and a
// fixture built only from populated survivors cannot tell them apart. That is
// the middle row a presence-based assertion is blind to.
//
// It is also reachable rather than contrived: `policy-statement P { }` with no
// terms is authorable, and the surviving member of a narrowed chain is by
// definition one the operator did NOT get to review at commit — the whole
// affected population arrives through the lenient load path, because strict
// commit rejects an undefined policy reference outright.
//
// These cells assert TODAY'S behaviour. #8369 is deferred rather than
// implemented (see the decision recorded in policy_chain_narrowing_warn_8363.go),
// so the value here is a measured baseline: whoever takes the deny later gets a
// green pin of what the chain does now, and any divergence is a diff against a
// fact rather than against an argument.
//
// #9947 CORRECTION to the "UNREACHABLE" inference below (not to the cells —
// they still pin today's render exactly). The inference assumed a trailing
// deny APPENDED after the survivor's permit-10 (deny-20 behind a match-all).
// The synthesis shape under discussion is a chain MEMBER with a terminating
// default, and EMPTY contributes zero sequences: [EMPTY,SYNTH-DENY] renders
// lone deny-10, reachable by every route (measured, not argued, in
// TestEmptySurvivorSynthesizedDenyIsReachable9947). The shape flips
// permit-all to deny-all — the maximum behavior change — so it belongs IN
// any deny-affected denominator; excluding it would hide an outage case.

func emptySurvivorPolicyOptions8369() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			// DEFINED, so it is not a ghost and the chain is NARROWED rather
			// than emptied — but it carries no terms and no default action.
			"EMPTY": {Name: "EMPTY"},
			// The populated control, so the two can be compared in one run.
			"ACCEPTER": {Name: "ACCEPTER", Terms: []*config.PolicyTerm{
				{Name: "t1", PrefixList: []string{"PL"}, Action: "accept"},
			}},
		},
		PrefixLists: map[string]*config.PrefixList{"PL": {Name: "PL", Prefixes: []string{"10.0.0.0/8"}}},
		Communities: map[string]*config.CommunityDef{},
		ASPaths:     map[string]*config.ASPathDef{},
	}
}

// TestEmptySurvivorStillClassifiesAsSuffixNarrowed8369 establishes that this
// shape reaches the decision at all.
//
// If an empty-but-defined survivor were classified as a ghost the chain would be
// EMPTIED, not narrowed, and #7625's bounded deny would already own it — the
// deny question would never arise. The classification is what puts this case
// inside #8369's remit, so it is asserted rather than assumed.
//
// MUTATION: make isDefinedPolicyStatement require a non-empty Terms slice and
// this reds (the site disappears — the chain classifies as emptied).
func TestEmptySurvivorStillClassifiesAsSuffixNarrowed8369(t *testing.T) {
	po := emptySurvivorPolicyOptions8369()
	bgp := &config.BGPConfig{
		LocalAS: 65001, RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"EMPTY", "GHOST"}},
		},
	}
	sites := narrowedChainSites(bgp, po)
	if len(sites) != 1 {
		t.Fatalf("want exactly one narrowed site for [EMPTY, GHOST], got %+v — an "+
			"empty-but-defined survivor must still count as a SURVIVOR, or this shape "+
			"is an emptied chain and #7625 owns it instead", sites)
	}
	if !sites[0].GhostsAreSuffix {
		t.Fatalf("[EMPTY, GHOST] must classify as suffix-narrowed (the ghost is last), " +
			"got GhostsAreSuffix=false — this case would then be excluded from the " +
			"deny decision for the wrong reason")
	}
	if got := sites[0].Kept; len(got) != 1 || got[0] != "EMPTY" {
		t.Errorf("Kept = %v, want [EMPTY]", got)
	}
}

// TestEmptySurvivorMakesASynthesizedDenyUNREACHABLE8369 pins today's render
// of the empty-survivor shape: ONE sequence, a match-all permit-10, with
// the ghost changing nothing.
//
//	route-map E-xpf-chain permit 10
//	exit
//
// (Name retained for history; the "UNREACHABLE" inference it was filed
// under is CORRECTED by #9947 — see the file header and
// TestEmptySurvivorSynthesizedDenyIsReachable9947. A deny synthesized as
// a chain member lands at deny-10 as the first and only sequence,
// reachable by every route: the shape flips permit-all to deny-all.
// The gauge therefore does NOT over-count here, and a sizing decision
// must keep this highest-impact member of the denominator.)
//
// MUTATION: give EMPTY a term (so it renders a match line) and the
// no-match-clause assertion reds — which is the populated case, and is exactly
// the substitution that hides this finding.
func TestEmptySurvivorMakesASynthesizedDenyUNREACHABLE8369(t *testing.T) {
	po := emptySurvivorPolicyOptions8369()
	m := New()

	empty := m.renderComposedRouteMap(po, "E-xpf-chain", []string{"EMPTY"})
	populated := m.renderComposedRouteMap(po, "P-xpf-chain", []string{"ACCEPTER"})

	// The control must carry a real match, or the comparison is between two
	// empty things and proves nothing.
	if !strings.Contains(populated, "match ip address prefix-list") {
		t.Fatalf("the POPULATED control renders no match line; the discriminator this "+
			"cell rests on is gone:\n%s", populated)
	}

	// The empty survivor's ONLY sequence, and it carries no match clause.
	seqs := strings.Count(empty, "route-map E-xpf-chain ")
	if seqs != 1 {
		t.Fatalf("empty-survivor chain rendered %d sequences, want exactly 1 — the "+
			"unreachability argument below depends on there being a single, "+
			"match-everything sequence:\n%s", seqs, empty)
	}
	if !strings.Contains(empty, "route-map E-xpf-chain permit 10") {
		t.Fatalf("the empty survivor's sequence is not a permit:\n%s", empty)
	}
	if strings.Contains(empty, "match ") {
		t.Errorf("the empty survivor rendered a match clause, which it has no terms to "+
			"produce. With a match clause the sequence is conditional and a trailing "+
			"deny WOULD be reachable, which inverts this cell's finding:\n%s", empty)
	}

	// Adding the ghost back changes nothing: the render is identical, so there
	// is no position for a deny to occupy that any route could reach.
	withGhost := m.renderComposedRouteMap(po, "E-xpf-chain", []string{"EMPTY", "GHOST"})
	if withGhost != empty {
		t.Errorf("the ghost changed the render, so the chain is not the shape this cell "+
			"measured:\n with ghost:\n%s\n without:\n%s", withGhost, empty)
	}
}

// TestNarrowedChainStillPermitsFallThroughToday8369 names the DIRECTION of the
// change #8369 proposes, as an assertion rather than as prose.
//
// A narrowed chain is carrying traffic right now with its fall-through
// PERMITTED (#2998, the Junos BGP default-accept). Synthesizing a deny converts
// that to denied. Because strict commit rejects an undefined policy reference in
// both directions, the entire affected population arrives via the LENIENT path —
// Store.Load / SyncApply — so the change would land on a reboot, a peer sync or
// a rollback: a routing change triggered by an unrelated event, on a config the
// operator did not just edit, with no commit to warn them at.
//
// On the first prefix it bites, the operator sees the route simply absent from
// the neighbour's adj-rib — no log line at the moment of the drop, because a
// route-map deny is silent — with the only breadcrumb being the narrowed-chain
// warning emitted at load time and the xpf_frr_policy_chains_narrowed gauge.
//
// MUTATION: emit a deny for a suffix-narrowed chain and this cell reds, which is
// the intended behaviour of that change — the assertion is here so it cannot
// happen silently.
func TestNarrowedChainStillPermitsFallThroughToday8369(t *testing.T) {
	po := emptySurvivorPolicyOptions8369()
	got := New().renderComposedRouteMap(po, "N-xpf-chain", []string{"ACCEPTER"})

	if strings.Contains(got, "route-map N-xpf-chain deny") {
		t.Errorf("a narrowed chain now renders a DENY sequence. That is #8369's proposed "+
			"change and it converts a chain that is currently carrying traffic with "+
			"fall-through PERMITTED into one that denies — at load time, via the lenient "+
			"path, with no commit to warn the operator at. If this is intended, the "+
			"deferral recorded in policy_chain_narrowing_warn_8363.go must be revisited "+
			"in the same change:\n%s", got)
	}
	if !strings.Contains(got, "route-map N-xpf-chain permit") {
		t.Fatalf("the chain renders no permit sequence at all; the fall-through this cell "+
			"is about does not exist and the assertion above is vacuous:\n%s", got)
	}
}
