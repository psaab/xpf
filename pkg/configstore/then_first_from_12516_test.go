package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12516: then-first term spellings (`term T then accept from ...`) are
// honoured by LoadOverride (packed term-node Keys via parsePolicyTermInlineKeys)
// but LoadMerge (FormatSetForLoadMerge -> SetPath), LoadSet, and direct
// `set` replay nested the `from` clause under the action before it, where the
// term compiler never reads it — committing a match-all permit.

// committedPolicyTerms12516 commits via load and returns the terms of P.
func committedPolicyTerms12516(t *testing.T, s *Store) []*config.PolicyTerm {
	t.Helper()
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("CommitCheck: %v", err)
	}
	cfg, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil {
		t.Fatalf("policy-statement P missing in %+v", cfg.PolicyOptions.PolicyStatements)
	}
	return ps.Terms
}

// committedPolicyTerm12516 commits via load and returns term T of P.
func committedPolicyTerm12516(t *testing.T, s *Store) *config.PolicyTerm {
	t.Helper()
	terms := committedPolicyTerms12516(t, s)
	if len(terms) != 1 {
		t.Fatalf("terms = %+v, want exactly one", terms)
	}
	if terms[0].Name != "T" {
		t.Fatalf("term name = %q, want T", terms[0].Name)
	}
	return terms[0]
}

func assertTerm12516(t *testing.T, term *config.PolicyTerm, wantAction string, wantFilters []config.RouteFilter, wantProtocols []string) {
	t.Helper()
	if term.Action != wantAction {
		t.Fatalf("action = %q, want %q", term.Action, wantAction)
	}
	if len(term.RouteFilters) != len(wantFilters) {
		t.Fatalf("route-filters = %+v, want %+v", term.RouteFilters, wantFilters)
	}
	for i, want := range wantFilters {
		got := term.RouteFilters[i]
		if got.Prefix != want.Prefix || got.MatchType != want.MatchType || got.UptoLen != want.UptoLen || got.UptoToken != want.UptoToken {
			t.Fatalf("route-filter[%d] = %+v, want %+v", i, got, want)
		}
	}
	if strings.Join(term.FromProtocols, ",") != strings.Join(wantProtocols, ",") {
		t.Fatalf("protocols = %v, want %v", term.FromProtocols, wantProtocols)
	}
}

var thenFirstForms12516 = []struct {
	name      string
	hier      string
	setLine   string
	filters   []config.RouteFilter
	protocols []string
}{
	{
		name:    "route-filter exact",
		hier:    `policy-options { policy-statement P { term T then accept from route-filter 10.0.0.0/8 exact; } }`,
		setLine: `set policy-options policy-statement P term T then accept from route-filter 10.0.0.0/8 exact`,
		filters: []config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}},
	},
	{
		name:    "bare upto",
		hier:    `policy-options { policy-statement P { term T then accept from route-filter 10.0.0.0/8 upto /24; } }`,
		setLine: `set policy-options policy-statement P term T then accept from route-filter 10.0.0.0/8 upto /24`,
		filters: []config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "upto", UptoLen: 24, UptoToken: "/24"}},
	},
	{
		name:      "bare protocol",
		hier:      `policy-options { policy-statement P { term T then accept from protocol static; } }`,
		setLine:   `set policy-options policy-statement P term T then accept from protocol static`,
		protocols: []string{"static"},
	},
	{
		name:      "multiple from conditions",
		hier:      `policy-options { policy-statement P { term T then accept from protocol static route-filter 10.0.0.0/8 exact; } }`,
		setLine:   `set policy-options policy-statement P term T then accept from protocol static route-filter 10.0.0.0/8 exact`,
		filters:   []config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}},
		protocols: []string{"static"},
	},
}

func TestThenFirstLoadMergePreservesFrom12516(t *testing.T) {
	for _, tc := range thenFirstForms12516 {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			enterCfg(t, s)
			if err := s.LoadMerge(tc.hier); err != nil {
				t.Fatalf("LoadMerge: %v", err)
			}
			assertTerm12516(t, committedPolicyTerm12516(t, s), "accept", tc.filters, tc.protocols)
		})
	}
}

func TestThenFirstFlatLoadMergePreservesFrom12516(t *testing.T) {
	for _, tc := range thenFirstForms12516 {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			enterCfg(t, s)
			if err := s.LoadMerge(tc.setLine); err != nil {
				t.Fatalf("LoadMerge(flat): %v", err)
			}
			assertTerm12516(t, committedPolicyTerm12516(t, s), "accept", tc.filters, tc.protocols)
		})
	}
}

func TestThenFirstLoadSetPreservesFrom12516(t *testing.T) {
	for _, tc := range thenFirstForms12516 {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			enterCfg(t, s)
			if _, err := s.LoadSet(tc.setLine); err != nil {
				t.Fatalf("LoadSet: %v", err)
			}
			assertTerm12516(t, committedPolicyTerm12516(t, s), "accept", tc.filters, tc.protocols)
		})
	}
}

func TestThenFirstDirectSetPreservesFrom12516(t *testing.T) {
	for _, tc := range thenFirstForms12516 {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			enterCfg(t, s)
			input := strings.TrimPrefix(tc.setLine, "set ")
			if err := s.SetFromInput(input); err != nil {
				t.Fatalf("SetFromInput: %v", err)
			}
			assertTerm12516(t, committedPolicyTerm12516(t, s), "accept", tc.filters, tc.protocols)
		})
	}
}

// Applied group paths carry the same policy term under a groups prefix; their
// SetPath replay must not re-nest from below the action (#12516). The reject
// cell pins the deny direction under a group, ahead of a match-all accept.
func TestThenFirstAppliedGroupPreservesFrom12516(t *testing.T) {
	want := []config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}
	for _, tc := range []struct {
		name, action, hier, flat string
	}{
		{
			name:   "accept",
			action: "accept",
			hier:   `groups { G { policy-options { policy-statement P { term T then accept from route-filter 10.0.0.0/8 exact; } } } } policy-options { apply-groups G; }`,
			flat:   "set groups G policy-options policy-statement P term T then accept from route-filter 10.0.0.0/8 exact\nset policy-options apply-groups G",
		},
		{
			name:   "reject before accept",
			action: "reject",
			hier:   `groups { G { policy-options { policy-statement P { term T then reject from route-filter 10.0.0.0/8 exact; term U then accept; } } } } policy-options { apply-groups G; }`,
			flat:   "set groups G policy-options policy-statement P term T then reject from route-filter 10.0.0.0/8 exact\nset groups G policy-options policy-statement P term U then accept\nset policy-options apply-groups G",
		},
	} {
		for _, replay := range replays12516(tc.hier, tc.flat) {
			t.Run(tc.name+"/"+replay.name, func(t *testing.T) {
				s := newTestStore(t)
				enterCfg(t, s)
				if err := replay.load(s); err != nil {
					t.Fatalf("%s: %v", replay.name, err)
				}
				terms := committedPolicyTerms12516(t, s)
				if len(terms) == 0 || terms[0].Name != "T" {
					t.Fatalf("terms = %+v, want T first", terms)
				}
				assertTerm12516(t, terms[0], tc.action, want, nil)
				if tc.action == "reject" {
					if len(terms) != 2 || terms[1].Name != "U" {
						t.Fatalf("terms = %+v, want T then U", terms)
					}
					assertTerm12516(t, terms[1], "accept", nil, nil)
				}
			})
		}
	}
}

// From-less then-first must stay a match-all accept (no invented filter).
func TestThenFirstWithoutFromUnchanged12516(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)
	if _, err := s.LoadSet(`set policy-options policy-statement P term T then accept`); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	term := committedPolicyTerm12516(t, s)
	if term.Action != "accept" || len(term.RouteFilters) != 0 || len(term.FromProtocols) != 0 {
		t.Fatalf("from-less term = %+v, want plain accept", term)
	}
}

// Bare/invalid from under then-first must refuse, never commit a permit.
func TestThenFirstMalformedFromRejected12516(t *testing.T) {
	cases := []struct{ name, hier, setLine, want string }{
		{
			name:    "bare route-filter",
			hier:    `policy-options { policy-statement P { term T then accept from route-filter; } }`,
			setLine: `set policy-options policy-statement P term T then accept from route-filter`,
			want:    "route-filter",
		},
		{
			name:    "upto missing length",
			hier:    `policy-options { policy-statement P { term T then accept from route-filter 10.0.0.0/8 upto; } }`,
			setLine: `set policy-options policy-statement P term T then accept from route-filter 10.0.0.0/8 upto`,
			want:    "upto",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/LoadMerge", func(t *testing.T) {
			s := newTestStore(t)
			enterCfg(t, s)
			if err := s.LoadMerge(tc.hier); err != nil {
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("LoadMerge error = %v, want naming %q", err, tc.want)
				}
				return
			}
			if _, err := s.CommitCheck(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CommitCheck error = %v, want rejection naming %q (must not commit match-all)", err, tc.want)
			}
			if _, err := s.Commit(); err == nil {
				t.Fatalf("Commit succeeded for malformed then-first from; must refuse")
			}
		})
		t.Run(tc.name+"/LoadSet", func(t *testing.T) {
			s := newTestStore(t)
			enterCfg(t, s)
			if _, err := s.LoadSet(tc.setLine); err != nil {
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("LoadSet error = %v, want naming %q", err, tc.want)
				}
				return
			}
			if _, err := s.CommitCheck(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CommitCheck error = %v, want rejection naming %q", err, tc.want)
			}
			if _, err := s.Commit(); err == nil {
				t.Fatalf("Commit succeeded for malformed then-first from; must refuse")
			}
		})
	}
}

// replay12516 is one of the flat-replay ingresses #12516 covers.
type replay12516 struct {
	name string
	load func(*Store) error
}

// replays12516 returns hierarchical LoadMerge (omitted when hier is empty),
// flat LoadMerge, LoadSet, and direct `set` of the same configuration; flat
// holds `set` lines.
func replays12516(hier, flat string) []replay12516 {
	var replays []replay12516
	if hier != "" {
		replays = append(replays, replay12516{"LoadMerge", func(s *Store) error { return s.LoadMerge(hier) }})
	}
	return append(replays,
		replay12516{"LoadMerge flat", func(s *Store) error { return s.LoadMerge(flat) }},
		replay12516{"LoadSet", func(s *Store) error { _, err := s.LoadSet(flat); return err }},
		replay12516{"set", func(s *Store) error {
			for _, line := range strings.Split(flat, "\n") {
				if err := s.SetFromInput(strings.TrimPrefix(line, "set ")); err != nil {
					return err
				}
			}
			return nil
		}},
	)
}

// Any then-action may precede the from clause, not only accept or reject. The
// clause used to land under the last action before it, so these committed
// as unconstrained terms (#12516 review B1). Each must keep its match and its
// actions on every replay path.
func TestThenFirstActionPrefixesKeepFrom12516(t *testing.T) {
	const c1 = "community C1 members 65000:1;"
	const setC1 = "set policy-options community C1 members 65000:1\n"
	static := []string{"static"}
	rf := []config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}
	for _, tc := range []struct {
		name, defs, setDefs, term string
		action                    string
		filters                   []config.RouteFilter
		protocols                 []string
		actions                   func(*config.PolicyTerm) bool
	}{
		{name: "metric", term: "then metric 10 accept from protocol static",
			action: "accept", protocols: static,
			actions: func(p *config.PolicyTerm) bool { return p.HasMetric && p.Metric == 10 }},
		{name: "local-preference", term: "then local-preference 200 accept from route-filter 10.0.0.0/8 exact",
			action: "accept", filters: rf,
			actions: func(p *config.PolicyTerm) bool { return p.HasLocalPreference && p.LocalPreference == 200 }},
		{name: "next-hop", term: "then next-hop self accept from protocol static",
			action: "accept", protocols: static,
			actions: func(p *config.PolicyTerm) bool { return p.NextHop == "self" }},
		{name: "community add", defs: c1, setDefs: setC1, term: "then community add C1 accept from protocol static",
			action: "accept", protocols: static,
			actions: func(p *config.PolicyTerm) bool { return p.CommunityAdd == "65000:1" }},
		{name: "quoted from", term: `then accept "from" route-filter 10.0.0.0/8 exact`,
			action: "accept", filters: rf},
		{name: "accept then local-preference", term: "then accept local-preference 200 from route-filter 10.0.0.0/8 exact",
			action: "accept", filters: rf,
			actions: func(p *config.PolicyTerm) bool { return p.HasLocalPreference && p.LocalPreference == 200 }},
		{name: "as-path-prepend", term: "then as-path-prepend 65001 accept from protocol static",
			action: "accept", protocols: static,
			actions: func(p *config.PolicyTerm) bool { return strings.Join(p.ASPathPrepend, " ") == "65001" }},
		{name: "next policy", term: "then next policy from route-filter 10.0.0.0/8 exact",
			filters: rf,
			actions: func(p *config.PolicyTerm) bool { return p.NextPolicy }},
		{name: "community value list", defs: c1, setDefs: setC1, term: "then community add C1 from protocol static",
			protocols: static,
			actions:   func(p *config.PolicyTerm) bool { return p.CommunityAdd == "65000:1" }},
	} {
		hier := "policy-options { " + tc.defs + " policy-statement P { term T " + tc.term + "; } }"
		flat := tc.setDefs + "set policy-options policy-statement P term T " + tc.term
		for _, replay := range replays12516(hier, flat) {
			t.Run(tc.name+"/"+replay.name, func(t *testing.T) {
				s := newTestStore(t)
				enterCfg(t, s)
				if err := replay.load(s); err != nil {
					t.Fatalf("%s: %v", replay.name, err)
				}
				term := committedPolicyTerm12516(t, s)
				assertTerm12516(t, term, tc.action, tc.filters, tc.protocols)
				if tc.actions != nil && !tc.actions(term) {
					t.Fatalf("compiled term = %+v, want the authored %s action", term, tc.name)
				}
			})
		}
	}
}

// The deny direction: a then-first reject keeps its match, so the match-all
// accept after it still governs every other route.
func TestThenFirstRejectKeepsMatch12516(t *testing.T) {
	const hier = `policy-options { policy-statement P { term T then reject from route-filter 10.0.0.0/8 exact; term U then accept; } }`
	const flat = "set policy-options policy-statement P term T then reject from route-filter 10.0.0.0/8 exact\n" +
		"set policy-options policy-statement P term U then accept"
	for _, replay := range replays12516(hier, flat) {
		t.Run(replay.name, func(t *testing.T) {
			s := newTestStore(t)
			enterCfg(t, s)
			if err := replay.load(s); err != nil {
				t.Fatalf("%s: %v", replay.name, err)
			}
			terms := committedPolicyTerms12516(t, s)
			if len(terms) != 2 || terms[0].Name != "T" || terms[1].Name != "U" {
				t.Fatalf("terms = %+v, want T then U", terms)
			}
			assertTerm12516(t, terms[0], "reject", []config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}, nil)
			assertTerm12516(t, terms[1], "accept", nil, nil)
		})
	}
}

// The from half keeps its bracket provenance: a closed list keeps every
// member, and an unclosed one is still refused (#11779) rather than committed.
// Hierarchical LoadMerge re-renders a list closed (FormatSetForLoadMerge), as
// it does for a from-first term, so only the flat ingresses carry an open one.
func TestThenFirstFromListProvenance12516(t *testing.T) {
	const term = "policy-options policy-statement P term T then metric 10 accept from protocol [ static bgp"
	for _, replay := range replays12516(
		`policy-options { policy-statement P { term T then metric 10 accept from protocol [ static bgp ]; } }`,
		"set "+term+" ]") {
		t.Run("closed/"+replay.name, func(t *testing.T) {
			s := newTestStore(t)
			enterCfg(t, s)
			if err := replay.load(s); err != nil {
				t.Fatalf("%s: %v", replay.name, err)
			}
			assertTerm12516(t, committedPolicyTerm12516(t, s), "accept", nil, []string{"static", "bgp"})
		})
	}
	for _, replay := range replays12516("", "set "+term) {
		t.Run("unclosed/"+replay.name, func(t *testing.T) {
			s := newTestStore(t)
			enterCfg(t, s)
			if err := replay.load(s); err != nil {
				t.Fatalf("%s: %v", replay.name, err)
			}
			if _, err := s.CommitCheck(); err == nil || !strings.Contains(err.Error(), "list did not close (#11779)") {
				t.Fatalf("CommitCheck err = %v, want the #11779 unclosed-list refusal", err)
			}
		})
	}
}

// A quoted from at a clause position is the clause (see the action-prefix
// cells). A quoted from filling another action's operand slot, and a bracketed
// one, could be either; each is refused before any mutation. A community named
// from stays the community value, quoted or not.
func TestThenFirstQuotedAndBracketedFrom12516(t *testing.T) {
	for _, tc := range []struct{ name, term, want string }{
		{"quoted from in an operand slot", `then metric "from" route-filter 10.0.0.0/8 exact accept`, `operand slot of "then metric"`},
		{"bracketed from", "then accept [ from route-filter 10.0.0.0/8 exact ]", "bracketed"},
	} {
		hier := "policy-options { policy-statement P { term T " + tc.term + "; } }"
		flat := "set policy-options policy-statement P term T " + tc.term
		for _, replay := range replays12516(hier, flat) {
			t.Run(tc.name+"/"+replay.name, func(t *testing.T) {
				s := newTestStore(t)
				enterCfg(t, s)
				err := replay.load(s)
				if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "#12516") {
					t.Fatalf("%s err = %v, want the #12516 refusal naming %q", replay.name, err, tc.want)
				}
				if view := s.ShowCandidateSet(); strings.Contains(view, "policy-statement P") {
					t.Fatalf("refused %s left the term behind:\n%s", replay.name, view)
				}
			})
		}
	}
	for _, tc := range []struct{ name, value string }{
		{"community named from", "from"},
		{"quoted community named from", `"from"`},
	} {
		hier := `policy-options { community from members 65000:1; policy-statement P { term T then community add ` + tc.value + ` accept; } }`
		flat := "set policy-options community from members 65000:1\n" +
			"set policy-options policy-statement P term T then community add " + tc.value + " accept"
		for _, replay := range replays12516(hier, flat) {
			t.Run(tc.name+"/"+replay.name, func(t *testing.T) {
				s := newTestStore(t)
				enterCfg(t, s)
				if err := replay.load(s); err != nil {
					t.Fatalf("%s: %v", replay.name, err)
				}
				term := committedPolicyTerm12516(t, s)
				assertTerm12516(t, term, "accept", nil, nil)
				if term.CommunityAdd != "65000:1" {
					t.Fatalf("community add = %q, want community from's 65000:1", term.CommunityAdd)
				}
			})
		}
	}
}

// delete, deactivate, and activate of a then-first line with a from clause
// are refused before any mutation (#12516 review F2): replay stores the line
// as separate from and then statements, and toggling a chained action reaches
// only its last link. The refusal is explicit on every ingress, including an
// inactive packed term merged from hierarchical text and the display-set
// output of one loaded by override.
func TestThenFirstFromLineVerbsRefused12516(t *testing.T) {
	const line = "policy-options policy-statement P term T then metric 10 accept from route-filter 10.0.0.0/8 exact"
	loaded := func(t *testing.T) *Store {
		t.Helper()
		s := newTestStore(t)
		enterCfg(t, s)
		if _, err := s.LoadSet("set " + line + "\nset policy-options policy-statement P term U then reject"); err != nil {
			t.Fatalf("LoadSet: %v", err)
		}
		return s
	}
	unchanged := func(t *testing.T, s *Store) {
		t.Helper()
		terms := committedPolicyTerms12516(t, s)
		if len(terms) != 2 {
			t.Fatalf("terms = %+v, want T and U", terms)
		}
		assertTerm12516(t, terms[0], "accept", []config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}, nil)
		if !terms[0].HasMetric || terms[0].Metric != 10 {
			t.Fatalf("term T = %+v, want metric 10 kept", terms[0])
		}
		assertTerm12516(t, terms[1], "reject", nil, nil)
	}
	for _, verb := range []string{"delete", "deactivate", "activate"} {
		t.Run(verb, func(t *testing.T) {
			s := loaded(t)
			_, err := s.LoadSet(verb + " " + line)
			if err == nil || !strings.Contains(err.Error(), verb+" "+line+": a then-first") || !strings.Contains(err.Error(), "#12516") {
				t.Fatalf("LoadSet(%s) err = %v, want the explicit #12516 refusal", verb, err)
			}
			unchanged(t, s)
		})
	}
	t.Run("interactive delete", func(t *testing.T) {
		s := loaded(t)
		if err := s.DeleteFromInput(line); err == nil || !strings.Contains(err.Error(), "#12516") {
			t.Fatalf("DeleteFromInput err = %v, want the explicit #12516 refusal", err)
		}
		unchanged(t, s)
	})
	t.Run("whole term", func(t *testing.T) {
		s := loaded(t)
		if _, err := s.LoadSet("deactivate policy-options policy-statement P term T"); err != nil {
			t.Fatalf("deactivate term: %v", err)
		}
		if terms := committedPolicyTerms12516(t, s); len(terms) != 1 || terms[0].Name != "U" {
			t.Fatalf("terms = %+v, want only U", terms)
		}
	})
	const inactive = `policy-options { policy-statement P { inactive: term T then accept from route-filter 10.0.0.0/8 exact; term U then reject; } }`
	t.Run("inactive packed term merge", func(t *testing.T) {
		s := newTestStore(t)
		enterCfg(t, s)
		if err := s.LoadMerge(inactive); err == nil || !strings.Contains(err.Error(), "deactivate") || !strings.Contains(err.Error(), "#12516") {
			t.Fatalf("LoadMerge err = %v, want the explicit #12516 deactivate refusal", err)
		}
	})
	t.Run("override display-set reload", func(t *testing.T) {
		src := newTestStore(t)
		enterCfg(t, src)
		if err := src.LoadOverride(inactive); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		var lines []string
		for _, l := range strings.Split(src.ShowCandidateSet(), "\n") {
			if strings.Contains(l, "policy-statement P") {
				lines = append(lines, l)
			}
		}
		dst := newTestStore(t)
		enterCfg(t, dst)
		if _, err := dst.LoadSet(strings.Join(lines, "\n")); err == nil || !strings.Contains(err.Error(), "deactivate") || !strings.Contains(err.Error(), "#12516") {
			t.Fatalf("LoadSet(display set) err = %v, want the explicit #12516 deactivate refusal", err)
		}
	})
}
