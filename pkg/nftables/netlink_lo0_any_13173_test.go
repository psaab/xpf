package nftables

import "testing"

// #13173 (deep-review D5-04): a constrained address direction whose tokens
// include the match-any universe ("any", or the chain-family /0) matches
// EVERY address of that family. lo0AddrScope/filterFamilyAddrs used to strip
// "any" before the empty-set decision, so a lone positive "any" became
// "match NOTHING" (a discard/reject term silently vanished) and a lone
// "any" under except became "match ALL" (inverting the exclusion).

func TestLo0AddrScopeAnyUniverse13173(t *testing.T) {
	cases := []struct {
		name  string
		fam   nlFamily
		addrs []string
	}{
		{"v4 any", famV4, []string{"any"}},
		{"v6 any", famV6, []string{"any"}},
		{"v4 slash0", famV4, []string{"0.0.0.0/0"}},
		{"v6 slash0", famV6, []string{"::/0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/positive_is_match_all", func(t *testing.T) {
			out, skip, err := lo0AddrScope(tc.fam, tc.addrs, false, true)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if skip || out != nil {
				t.Fatalf("out=%v skip=%v, want nil,false (match-all universe)", out, skip)
			}
		})
		t.Run(tc.name+"/except_matches_nothing", func(t *testing.T) {
			out, skip, err := lo0AddrScope(tc.fam, tc.addrs, true, true)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if !skip {
				t.Fatalf("out=%v skip=%v, want skip=true (any-except matches nothing)", out, skip)
			}
		})
	}

	// Narrowing guard: "any" must not widen a mixed list in the OTHER
	// family, and wrong-family /0 stays a plain family literal drop.
	t.Run("any_plus_same_family_prefix_stays_match_all", func(t *testing.T) {
		out, skip, err := lo0AddrScope(famV4, []string{"any", "10.0.0.0/8"}, false, true)
		if err != nil || skip || out != nil {
			t.Fatalf("out=%v skip=%v err=%v, want nil,false,nil", out, skip, err)
		}
	})
	t.Run("wrong_family_only_still_matches_nothing", func(t *testing.T) {
		_, skip, err := lo0AddrScope(famV4, []string{"2001:db8::/32"}, false, true)
		if err != nil || !skip {
			t.Fatalf("skip=%v err=%v, want skip=true", skip, err)
		}
	})
	t.Run("unconstrained_unchanged", func(t *testing.T) {
		out, skip, err := lo0AddrScope(famV4, []string{"any"}, true, false)
		if err != nil || skip || out != nil {
			t.Fatalf("out=%v skip=%v err=%v", out, skip, err)
		}
	})
}

// Plan level: a discard term scoped only to "any" must still emit its drop
// rule, and "any except" must emit no rule.
func TestLo0AnyTermPlan13173(t *testing.T) {
	p := buildLo0Term6512(t, Lo0FilterTerm{
		Name: "any-discard", Action: "discard",
		SrcAddrs: []string{"any"}, SrcConstrained: true,
	})
	if p.err != nil {
		t.Fatalf("err = %v", p.err)
	}
	if len(p.rules) != 1 {
		t.Fatalf("positive any discard: want 1 rule, got %d:\n%s", len(p.rules), canonRules(p))
	}

	p2 := buildLo0Term6512(t, Lo0FilterTerm{
		Name: "any-except", Action: "discard",
		SrcAddrs: []string{"any"}, SrcExcept: true, SrcConstrained: true,
	})
	if p2.err != nil {
		t.Fatalf("err = %v", p2.err)
	}
	if len(p2.rules) != 0 {
		t.Fatalf("any-except discard: want 0 rules, got %d:\n%s", len(p2.rules), canonRules(p2))
	}
}
