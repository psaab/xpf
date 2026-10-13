package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12516: then-first term spellings (`term T then accept from ...`) are
// honoured by LoadOverride (packed term-node Keys via parsePolicyTermInlineKeys)
// but LoadMerge (FormatSetForLoadMerge -> SetPath), LoadSet, and direct
// `set` replay nest the `from` clause under then/accept, where the term
// compiler never reads it — committing a match-all permit.

// committedPolicyTerm12516 commits via load and returns term T of P.
func committedPolicyTerm12516(t *testing.T, s *Store) *config.PolicyTerm {
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
	if len(ps.Terms) != 1 {
		t.Fatalf("terms = %+v, want exactly one", ps.Terms)
	}
	if ps.Terms[0].Name != "T" {
		t.Fatalf("term name = %q, want T", ps.Terms[0].Name)
	}
	return ps.Terms[0]
}

func assertTerm12516(t *testing.T, term *config.PolicyTerm, wantFilters []config.RouteFilter, wantProtocols []string) {
	t.Helper()
	if term.Action != "accept" {
		t.Fatalf("action = %q, want accept", term.Action)
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
			assertTerm12516(t, committedPolicyTerm12516(t, s), tc.filters, tc.protocols)
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
			assertTerm12516(t, committedPolicyTerm12516(t, s), tc.filters, tc.protocols)
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
			assertTerm12516(t, committedPolicyTerm12516(t, s), tc.filters, tc.protocols)
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
			assertTerm12516(t, committedPolicyTerm12516(t, s), tc.filters, tc.protocols)
		})
	}
}

// Applied group paths carry the same policy term under a groups prefix; their
// SetPath replay must not re-nest from below then/accept (#12516).
func TestThenFirstAppliedGroupPreservesFrom12516(t *testing.T) {
	const hierarchical = `groups { G { policy-options { policy-statement P { term T then accept from route-filter 10.0.0.0/8 exact; } } } } policy-options { apply-groups G; }`
	const flat = "set groups G policy-options policy-statement P term T then accept from route-filter 10.0.0.0/8 exact\nset policy-options apply-groups G"
	want := []config.RouteFilter{{Prefix: "10.0.0.0/8", MatchType: "exact"}}
	t.Run("LoadMerge", func(t *testing.T) {
		s := newTestStore(t)
		enterCfg(t, s)
		if err := s.LoadMerge(hierarchical); err != nil {
			t.Fatalf("LoadMerge: %v", err)
		}
		assertTerm12516(t, committedPolicyTerm12516(t, s), want, nil)
	})
	t.Run("LoadSet", func(t *testing.T) {
		s := newTestStore(t)
		enterCfg(t, s)
		if _, err := s.LoadSet(flat); err != nil {
			t.Fatalf("LoadSet: %v", err)
		}
		assertTerm12516(t, committedPolicyTerm12516(t, s), want, nil)
	})
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
