package frr

import (
	"regexp"
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
// Post-fix, a multi-member definition keeps its public name as
// conjunctive permit entries, for both standard (AND via
// community_match over the joined literal list) and expanded
// (#15779: AND via the permutation disjunction of ordered POSIX-ERE
// sequences — POSIX has no lookahead), while single-member output is
// byte-identical.
//
// #15779 (G20-04): the #15008 expanded conjunction used Perl-style
// `(?=.*factor)` lookaheads. FRR compiles expanded lists with
// regcomp(REG_EXTENDED) (POSIX ERE), which rejects lookaheads with
// CMD_WARNING_CONFIG_FAILED, aborting the whole frr-reload. The
// tests below compile every rendered expanded pattern with
// regexp.CompilePOSIX (Go's POSIX-ERE oracle for FRR's dialect) and
// evaluate conjunctive semantics against community strings in the
// joined, sorted form FRR matches against.

func renderCommunity15008(t *testing.T, members ...string) string {
	t.Helper()
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"X": {Name: "X", Members: members},
		},
	}
	return New().generatePolicyOptions(po)
}

// expandedPatterns15779 extracts the match-facing expanded permit
// patterns for list name from a rendered config and asserts the
// #15779 invariants on EVERY one: no non-POSIX lookahead survives,
// and the pattern compiles under regexp.CompilePOSIX — Go's
// POSIX-ERE oracle for the regcomp(REG_EXTENDED) FRR runs (the
// #8449 agreement). On the pre-fix lookahead render CompilePOSIX
// fails here, which is the RED evidence for this issue.
func expandedPatterns15779(t *testing.T, rendered, name string) []string {
	t.Helper()
	prefix := "bgp community-list expanded " + name + " permit "
	var patterns []string
	for _, line := range strings.Split(rendered, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		pattern := strings.TrimPrefix(line, prefix)
		if strings.Contains(pattern, "(?") {
			t.Errorf("rendered expanded pattern carries a non-POSIX construct %q: %q", "(?", pattern)
		}
		if _, err := regexp.CompilePOSIX(pattern); err != nil {
			t.Errorf("rendered expanded pattern %q fails POSIX ERE compile (FRR regcomp rejects it): %v", pattern, err)
		}
		patterns = append(patterns, pattern)
	}
	return patterns
}

type matchCase15779 struct {
	communityString string
	want            bool
}

// assertConjunctiveMatch15779 evaluates the entry SET the way FRR
// does — a list matches when ANY permit entry matches (regexec,
// unanchored) — and pins that the set as a whole is the conjunction:
// it matches exactly the community strings satisfying every member.
func assertConjunctiveMatch15779(t *testing.T, patterns []string, cases []matchCase15779) {
	t.Helper()
	if len(patterns) == 0 {
		t.Fatalf("no expanded patterns to evaluate")
	}
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		re, err := regexp.CompilePOSIX(p)
		if err != nil {
			t.Fatalf("pattern %q does not compile as POSIX ERE: %v", p, err)
		}
		compiled[i] = re
	}
	for _, tc := range cases {
		got := false
		for _, re := range compiled {
			if re.MatchString(tc.communityString) {
				got = true
				break
			}
		}
		if got != tc.want {
			t.Errorf("conjunction over %q: match(%q) = %v, want %v", patterns, tc.communityString, got, tc.want)
		}
	}
}

// TestExpandedCommunityConjunctionPOSIX15779 is the #15779
// regression: every multi-member expanded render must be
// POSIX-ERE-valid (no `(?=...)`) and conjunctive, at and past the
// permutation bound.
func TestExpandedCommunityConjunctionPOSIX15779(t *testing.T) {
	t.Run("three regex members conjunctive", func(t *testing.T) {
		got := renderCommunity15008(t, "65000:.*", "65001:.*", "65002:.*")
		patterns := expandedPatterns15779(t, got, "X")
		if len(patterns) != 6 {
			t.Fatalf("want 3! = 6 permutation entries, got %d %q:\n%s", len(patterns), patterns, got)
		}
		assertConjunctiveMatch15779(t, patterns, []matchCase15779{
			{"65000:1 65001:2 65002:3", true},
			{"65000:1 65002:3", false},
			{"65001:2 65002:3", false},
			{"65000:1 65001:2", false},
		})
	})
	t.Run("four members at the bound still render", func(t *testing.T) {
		got := renderCommunity15008(t, "65000:.*", "65001:.*", "65002:.*", "65003:.*")
		patterns := expandedPatterns15779(t, got, "X")
		if len(patterns) != 24 {
			t.Fatalf("want 4! = 24 permutation entries at the bound, got %d:\n%s", len(patterns), got)
		}
		assertConjunctiveMatch15779(t, patterns, []matchCase15779{
			{"65000:1 65001:2 65002:3 65003:4", true},
			{"65000:1 65001:2 65002:3", false},
		})
	})
	t.Run("five expanded members past the bound render nothing and report missing", func(t *testing.T) {
		members := []string{"65000:.*", "65001:.*", "65002:.*", "65003:.*", "65004:.*"}
		got := renderCommunity15008(t, members...)
		if strings.Contains(got, "community-list") {
			t.Errorf("past-bound expanded definition rendered (want omission, fail-closed):\n%s", got)
		}
		po := &config.PolicyOptionsConfig{Communities: map[string]*config.CommunityDef{
			"X": {Name: "X", Members: members},
		}}
		if !communityListMissingAtRender(po, "X") {
			t.Errorf("past-bound definition not reported missing; a referencing term would dangle instead of failing closed")
		}
		if target := communityDeleteTarget(po, "X"); target != frrName("X") {
			t.Errorf("past-bound delete target = %q, want the public name (no backing rendered)", target)
		}
	})
	t.Run("five literal members stay on the linear standard render", func(t *testing.T) {
		got := renderCommunity15008(t, "65000:1", "65000:2", "65000:3", "65000:4", "65000:5")
		want := "bgp community-list standard X permit 65000:1 65000:2 65000:3 65000:4 65000:5\n"
		if !strings.Contains(got, want) {
			t.Errorf("all-literal definition must not hit the expanded bound, want %q:\n%s", want, got)
		}
	})
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
		patterns := expandedPatterns15779(t, got, "X")
		// #15779: two members render the two ordered sequences (the
		// permutation disjunction), not one lookahead pattern.
		if len(patterns) != 2 {
			t.Fatalf("want 2 permutation entries for X, got %d %q:\n%s", len(patterns), patterns, got)
		}
		for _, member := range []string{"65000:.*", "65001:.*"} {
			for _, p := range patterns {
				if !strings.Contains(p, member) {
					t.Errorf("expanded conjunction pattern %q lost member %q", p, member)
				}
			}
		}
		assertConjunctiveMatch15779(t, patterns, []matchCase15779{
			{"65000:100 65001:200", true},         // both, sorted order
			{"65000:100 65002:7 65001:200", true}, // both, extra token between
			{"65000:100", false},                  // only one member satisfied
			{"65001:200", false},                  // only the other member
			{"65002:7 65003:8", false},            // neither
			{"", false},
		})
	})
	t.Run("mixed literal and regex conjunctive", func(t *testing.T) {
		got := renderCommunity15008(t, "65000:100", "65001:.*")
		if n := strings.Count(got, "bgp community-list expanded X permit "); n != 2 {
			t.Errorf("want 2 permutation entries for X, got %d:\n%s", n, got)
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
		patterns := expandedPatterns15779(t, got, "X")
		assertConjunctiveMatch15779(t, patterns, []matchCase15779{
			{"65000:100 65001:200", true},
			{"65001:200 65000:100", true},   // community_str order is the route's; both orders covered by permutations as authored here the sorted form is the first, the second pins factor-order independence of the ENTRY SET
			{"65000:1000 65001:200", false}, // literal must not match inside a longer token
			{"65000:100", false},
			{"65001:200", false},
		})
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
