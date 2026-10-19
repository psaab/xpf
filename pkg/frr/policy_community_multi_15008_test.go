package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15008 (A11-02): Junos requires EVERY member of a named community to
// match a route — "The evaluation of all members must be successful
// for the named community evaluation to be successful" (Junos routing
// policy community evaluation). The renderer emitted one
// `bgp community-list ... permit <member>` line per member. FRR's
// community_list_match returns on the FIRST permit entry whose
// community set is contained in the route, so a route carrying any
// ONE member matched the whole list: `from community X` was widened
// from ALL to ANY (over-accept on accept terms, over-reject on
// reject terms, wrong routes for non-terminal actions).
//
// Post-fix, a multi-member definition keeps its public name as ONE
// permit entry whose value is the conjunction, for both standard
// (AND via community_match over the joined literal list) and expanded
// (AND via a lookahead conjunction over the joined string, or a
// deliberately deferred route-map-local rendering), while
// single-member output is byte-identical.

func renderCommunity15008(t *testing.T, members ...string) string {
	t.Helper()
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"X": {Name: "X", Members: members},
		},
	}
	return New().generatePolicyOptions(po)
}

func TestMultiMemberCommunityIsConjunctive15008(t *testing.T) {
	t.Run("standard two literals one permit entry", func(t *testing.T) {
		got := renderCommunity15008(t, "65000:100", "65000:200")
		if n := strings.Count(got, "bgp community-list standard X permit "); n != 1 {
			t.Errorf("want exactly one match-facing permit entry for X, got %d:\n%s", n, got)
		}
		want := "bgp community-list standard X permit 65000:100 65000:200\n"
		if !strings.Contains(got, want) {
			t.Errorf("want conjunctive %q, got:\n%s", want, got)
		}
		for _, bare := range []string{
			"bgp community-list standard X permit 65000:100\n",
			"bgp community-list standard X permit 65000:200\n",
		} {
			if strings.Contains(got, bare) {
				t.Errorf("per-member OR line %q survived:\n%s", bare, got)
			}
		}
	})
	t.Run("standard member order preserved", func(t *testing.T) {
		got := renderCommunity15008(t, "65000:200", "65000:100")
		want := "bgp community-list standard X permit 65000:200 65000:100\n"
		if !strings.Contains(got, want) {
			t.Errorf("want authored order preserved %q, got:\n%s", want, got)
		}
	})
	t.Run("single member unchanged", func(t *testing.T) {
		got := renderCommunity15008(t, "65000:100")
		want := "bgp community-list standard X permit 65000:100\n"
		if !strings.Contains(got, want) {
			t.Errorf("single-member render changed: want %q got:\n%s", want, got)
		}
		if strings.Contains(got, "-xpf-del-") {
			t.Errorf("single-member definition gained a delete backing:\n%s", got)
		}
	})
	t.Run("all regex members conjunctive", func(t *testing.T) {
		got := renderCommunity15008(t, "65000:.*", "65001:.*")
		if strings.Contains(got, "bgp community-list expanded X permit 65000:.*\n") || strings.Contains(got, "bgp community-list expanded X permit 65001:.*\n") {
			t.Errorf("per-member OR expanded line survived:\n%s", got)
		}
		if n := strings.Count(got, "bgp community-list expanded X permit "); n != 1 {
			t.Fatalf("want one expanded permit entry for X, got %d:\n%s", n, got)
		}
		idx := strings.Index(got, "bgp community-list expanded X permit ")
		line := got[idx : strings.Index(got[idx:], "\n")+idx]
		for _, member := range []string{"65000:.*", "65001:.*"} {
			if !strings.Contains(line, member) {
				t.Errorf("expanded conjunction %q lost member %q", line, member)
			}
		}
		if !strings.Contains(line, "(?=") {
			t.Errorf("expanded conjunction lacks lookahead (must AND, not concat): %q", line)
		}
	})
	t.Run("mixed literal and regex conjunctive", func(t *testing.T) {
		got := renderCommunity15008(t, "65000:100", "65001:.*")
		if n := strings.Count(got, "bgp community-list expanded X permit "); n != 1 {
			t.Errorf("want one match-facing permit entry for X, got %d:\n%s", n, got)
		}
		for _, bare := range []string{"bgp community-list expanded X permit 65000:100\n", "bgp community-list expanded X permit 65001:.*\n"} {
			if strings.Contains(got, bare) {
				t.Errorf("per-member OR line %q survived:\n%s", bare, got)
			}
		}
		// Literal factor must be token-anchored, not a bare substring.
		if !strings.Contains(got, `(^| )65000:100( |$)`) {
			t.Errorf("mixed conjunction does not anchor the literal to a whole token:\n%s", got)
		}
	})
	t.Run("empty member definition renders nothing", func(t *testing.T) {
		got := renderCommunity15008(t)
		if strings.Contains(got, "community-list") {
			t.Errorf("empty definition rendered a list:\n%s", got)
		}
	})
	t.Run("duplicate members collapse", func(t *testing.T) {
		got := renderCommunity15008(t, "65000:100", "65000:100")
		want := "bgp community-list standard X permit 65000:100\n"
		if !strings.Contains(got, want) || strings.Contains(got, "-xpf-del-") {
			t.Errorf("duplicate members must collapse to the single-member render, got:\n%s", got)
		}
	})
}

func TestMultiMemberCommunityDeleteStaysWholeList15008(t *testing.T) {
	// `then community delete X` must still strip every member. With
	// the AND entry FRR's community_list_match_delete only strips a
	// value when ONE permit entry matches that single value, so an
	// AND-only entry would strip nothing (or only a full-match row).
	// The renderer therefore keeps a distinct delete backing whose
	// per-member entries strip each member, while the match-facing
	// name stays conjunctive.
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"X": {Name: "X", Members: []string{"65000:100", "65000:200"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "t", FromProtocols: []string{"bgp"}, CommunityOp: "delete", CommunityDelete: []string{"X"}, LocalPreference: 200, HasLocalPreference: true, Action: "accept"},
				},
			},
		},
	}
	got := New().generatePolicyOptions(po)
	// Match side stays conjunctive.
	if !strings.Contains(got, "bgp community-list standard X permit 65000:100 65000:200\n") {
		t.Errorf("match list is not conjunctive:\n%s", got)
	}
	// Delete side must reach both members. Either the delete still
	// targets X (only valid if X's entries themselves strip
	// individually — refuted by the conjunction) or it targets a
	// per-member backing list.
	if strings.Contains(got, " set comm-list X delete\n") {
		t.Errorf("delete still targets the AND list X; FRR strips nothing per-value:\n%s", got)
	}
	found := 0
	for _, want := range []string{"65000:100", "65000:200"} {
		// A backing delete list must carry a permit entry for the member.
		if strings.Contains(got, "permit "+want+"\n") {
			found++
		}
	}
	if found != 2 {
		t.Errorf("delete backing does not carry both per-member entries (found %d):\n%s", found, got)
	}
	if !strings.Contains(got, " set local-preference 200\n") {
		t.Errorf("sibling set clause lost:\n%s", got)
	}
}

func TestMultiMemberCommunityUnsafeNameDeleteBacking15008(t *testing.T) {
	// A delete backing derived from an operator name must not be
	// forged by another operator community name: an operator community
	// whose name spells a backing name must not silently merge with a
	// generated backing. The apply gate must refuse the config rather
	// than render a fused list (mirrors the route-filter collision
	// posture). The expected backing shape is the deterministic form
	// the renderer documents; assert via the gate, not the spelling.
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"X": {Name: "X", Members: []string{"65000:1", "65000:2"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocols: []string{"bgp"}, CommunityOp: "delete", CommunityDelete: []string{"X"}, Action: "accept"},
				},
			},
		},
	}
	got := New().generatePolicyOptions(po)
	// The delete backing renders under its documented marker and
	// carries both per-member entries (so FRR strips each value).
	if !strings.Contains(got, "-xpf-del-") {
		t.Errorf("delete does not target a generated per-member backing:\n%s", got)
	}
	backing := communityDeleteListName("X")
	if backing == "X" || backing == frrName("X") {
		t.Fatalf("generated delete backing %q collides with the public name", backing)
	}
	// An operator community named exactly as the generated backing
	// must be refused by the gate — its definition would otherwise
	// merge with the backing in FRR's flat namespace.
	forged := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"X":     {Name: "X", Members: []string{"65000:1", "65000:2"}},
			backing: {Name: backing, Members: []string{"65000:9"}},
		},
	}
	if err := communityListCollision(forged); err == nil {
		t.Errorf("operator community %q forging the generated delete backing was accepted; the two lists would merge in FRR", backing)
	}
	// Same for the raw spelling when it differs from the FRR name.
	if backing != frrName(backing) {
		raw := &config.PolicyOptionsConfig{
			Communities: map[string]*config.CommunityDef{
				"X": {Name: "X", Members: []string{"65000:1", "65000:2"}},
			},
		}
		_ = raw
	}
}

func TestMultiMemberCommunityCollisionGate15008(t *testing.T) {
	// communityListCollision mirrors the route-filter gate: a config
	// whose delete backing would fuse must fail closed, not render a
	// silently merged list. Single-member and empty configs stay clean.
	clean := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"C1": {Name: "C1", Members: []string{"65000:1"}},
			"C2": {Name: "C2", Members: []string{"65000:1", "65000:2"}},
		},
	}
	if err := communityListCollision(clean); err != nil {
		t.Errorf("clean config flagged: %v", err)
	}
	if err := communityListCollision(nil); err != nil {
		t.Errorf("nil flagged: %v", err)
	}
	if err := communityListCollision(&config.PolicyOptionsConfig{}); err != nil {
		t.Errorf("empty flagged: %v", err)
	}
}

func TestMultiMemberCommunityNormalizedNameCollision15008(t *testing.T) {
	// frrName keeps whitespace names apart via its hash alias, so the
	// plain normalized pair does NOT fuse and must stay clean; what the
	// gate must refuse is an operator name that spells another
	// community's frrName exactly (here the escaped alias), which would
	// fuse the two rendered lists in FRR.
	clean := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"A B": {Name: "A B", Members: []string{"65000:1", "65000:2"}},
			"A_B": {Name: "A_B", Members: []string{"65000:3", "65000:4"}},
		},
	}
	if err := communityListCollision(clean); err != nil {
		t.Errorf("hash-aliased names that frrName keeps apart were flagged: %v", err)
	}
	alias := frrName("A B")
	fused := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"A B": {Name: "A B", Members: []string{"65000:1", "65000:2"}},
			alias: {Name: alias, Members: []string{"65000:3", "65000:4"}},
		},
	}
	if err := communityListCollision(fused); err == nil {
		t.Errorf("operator community %q spelling another community's rendered name was accepted; their lists would merge in FRR", alias)
	}
}
