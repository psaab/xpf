package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12674: a policy-level (term-less) policy-statement such as
// `policy-statement P { then accept; from route-filter ...; }` became a
// default accept with its `from` dropped on every path, LoadOverride
// included, and a bare `from;` committed as accept-all.
//
// Junos (policy-statement syntax without terms) is `from ...; then ...;`
// with the match feeding the default action. xpf does not enforce a
// policy-level match (no PolicyStatement match fields, no FRR renderer
// for one), so the preserved behaviour is strict-reject / tolerant
// fail-closed through the existing #11779 marker — never a silent
// accept-all. Term-level bare `from;` is rejected the same way, while a
// term-less policy with only `then accept;` stays a valid default-accept.

const policyLevelRF12674 = "10.0.0.0/8"

func policyStatementP12674(t *testing.T, cfg *config.Config) *config.PolicyStatement {
	t.Helper()
	if cfg == nil {
		t.Fatal("nil config")
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil {
		t.Fatalf("policy-statement P missing in %+v", cfg.PolicyOptions.PolicyStatements)
	}
	return ps
}

// hier12674 wraps a policy-statement body (optionally with terms) in a
// hierarchical policy-options block.
func hier12674(body string) string {
	return "policy-options { policy-statement P { " + body + " } }"
}

var policyLevelIngress12674 = []struct {
	name string
	load func(t *testing.T, s *Store, hier, flat string) error
}{
	{"LoadOverride/hier", func(t *testing.T, s *Store, hier, flat string) error { return s.LoadOverride(hier) }},
	{"LoadOverride/flat", func(t *testing.T, s *Store, hier, flat string) error { return s.LoadOverride(flat) }},
	{"LoadMerge/hier", func(t *testing.T, s *Store, hier, flat string) error { return s.LoadMerge(hier) }},
	{"LoadMerge/flat", func(t *testing.T, s *Store, hier, flat string) error { return s.LoadMerge(flat) }},
	{"LoadSet/flat", func(t *testing.T, s *Store, hier, flat string) error { _, err := s.LoadSet(flat); return err }},
	{"direct-set", func(t *testing.T, s *Store, hier, flat string) error {
		for _, line := range strings.Split(flat, "\n") {
			path, err := config.ParseSetCommand(line)
			if err != nil {
				return err
			}
			if err := s.Set(path); err != nil {
				return err
			}
		}
		return nil
	}},
}

// assertRejected12674 requires the shape to fail at load, CommitCheck, or
// Commit (never to commit), with an error naming the policy-level /
// bare-from defect.
func assertRejected12674(t *testing.T, s *Store, loadErr error) {
	t.Helper()
	err := loadErr
	if err == nil {
		if _, cerr := s.CommitCheck(); cerr != nil {
			err = cerr
		} else if _, cerr := s.Commit(); cerr != nil {
			err = cerr
		}
	}
	if err == nil {
		cfg := s.ActiveConfig()
		var ps *config.PolicyStatement
		if cfg != nil {
			ps = cfg.PolicyOptions.PolicyStatements["P"]
		}
		t.Fatalf("shape committed as accept-all (ps=%+v); want strict rejection of the dropped/bare policy-level from", ps)
	}
	msg := err.Error()
	if !strings.Contains(msg, "policy-statement") && !strings.Contains(msg, "from") {
		t.Fatalf("rejection does not name the policy/from defect: %v", err)
	}
}

func TestPolicyLevelFromRejectedOnEveryPath12674(t *testing.T) {
	shapes := []struct {
		name string
		hier string
		flat string
	}{
		{
			name: "then-first route-filter",
			hier: hier12674("then accept; from route-filter " + policyLevelRF12674 + " exact;"),
			flat: "set policy-options policy-statement P then accept\nset policy-options policy-statement P from route-filter " + policyLevelRF12674 + " exact",
		},
		{
			name: "from-first route-filter (order control)",
			hier: hier12674("from route-filter " + policyLevelRF12674 + " exact; then accept;"),
			flat: "set policy-options policy-statement P from route-filter " + policyLevelRF12674 + " exact\nset policy-options policy-statement P then accept",
		},
		{
			name: "then-first from block",
			hier: hier12674("then { accept; } from { route-filter " + policyLevelRF12674 + " exact; }"),
			flat: "set policy-options policy-statement P then accept\nset policy-options policy-statement P from route-filter " + policyLevelRF12674 + " exact",
		},
		{
			name: "then-first protocol",
			hier: hier12674("then accept; from protocol static;"),
			flat: "set policy-options policy-statement P then accept\nset policy-options policy-statement P from protocol static",
		},
		{
			name: "packed then-first",
			hier: "policy-options { policy-statement P then accept from route-filter " + policyLevelRF12674 + " exact; }",
			flat: "set policy-options policy-statement P then accept from route-filter " + policyLevelRF12674 + " exact",
		},
		{
			name: "block-packed then-first",
			hier: "policy-options { policy-statement P { then accept from route-filter " + policyLevelRF12674 + " exact; } }",
			flat: "set policy-options policy-statement P then accept from route-filter " + policyLevelRF12674 + " exact",
		},
		{
			name: "grouped flat then-first",
			hier: hier12674("then accept from route-filter " + policyLevelRF12674 + " exact;"),
			flat: "set policy-options policy-statement [ P Q ] then accept from route-filter " + policyLevelRF12674 + " exact",
		},
		{
			name: "grouped hierarchical then-first",
			hier: "policy-options { policy-statement [ P Q ] { then accept from route-filter " + policyLevelRF12674 + " exact; } }",
			flat: "set policy-options policy-statement P then accept from route-filter " + policyLevelRF12674 + " exact",
		},
		{
			name: "policy-level from with term",
			hier: hier12674("term T { from protocol static; then accept; } then accept; from route-filter " + policyLevelRF12674 + " exact;"),
			flat: "set policy-options policy-statement P term T from protocol static\nset policy-options policy-statement P term T then accept\nset policy-options policy-statement P then accept\nset policy-options policy-statement P from route-filter " + policyLevelRF12674 + " exact",
		},
		{
			name: "unsupported neighbor (marker control)",
			hier: hier12674("from neighbor 10.0.0.1; then accept;"),
			flat: "set policy-options policy-statement P from neighbor 10.0.0.1\nset policy-options policy-statement P then accept",
		},
	}
	for _, sh := range shapes {
		for _, ing := range policyLevelIngress12674 {
			if sh.name == "grouped flat then-first" && ing.name == "direct-set" {
				continue // ParseSetCommand exposes no bracket-group provenance.
			}
			t.Run(sh.name+"/"+ing.name, func(t *testing.T) {
				s := newTestStore(t)
				enterCfg(t, s)
				assertRejected12674(t, s, ing.load(t, s, sh.hier, sh.flat))
			})
		}
	}
}

func TestPolicyLevelBareFromRejectedOnEveryPath12674(t *testing.T) {
	shapes := []struct {
		name string
		hier string
		flat string
	}{
		{
			name: "policy-level bare from",
			hier: hier12674("from; then accept;"),
			flat: "set policy-options policy-statement P from\nset policy-options policy-statement P then accept",
		},
		{
			name: "policy-level bare from then-first",
			hier: hier12674("then accept; from;"),
			flat: "set policy-options policy-statement P then accept\nset policy-options policy-statement P from",
		},
		{
			name: "policy-level empty from block",
			hier: hier12674("from { } then accept;"),
			flat: "set policy-options policy-statement P from\nset policy-options policy-statement P then accept",
		},
		{
			name: "term-level bare from",
			hier: hier12674("term T { from; then accept; }"),
			flat: "set policy-options policy-statement P term T from\nset policy-options policy-statement P term T then accept",
		},
		{
			name: "term-level bare from block",
			hier: hier12674("term T { from { } then accept; }"),
			flat: "set policy-options policy-statement P term T from\nset policy-options policy-statement P term T then accept",
		},
		{
			name: "term-packed bare from",
			hier: "policy-options { policy-statement P { term T from then accept; } }",
			flat: "set policy-options policy-statement P term T from\nset policy-options policy-statement P term T then accept",
		},
	}
	for _, sh := range shapes {
		for _, ing := range policyLevelIngress12674 {
			t.Run(sh.name+"/"+ing.name, func(t *testing.T) {
				s := newTestStore(t)
				enterCfg(t, s)
				assertRejected12674(t, s, ing.load(t, s, sh.hier, sh.flat))
			})
		}
	}
	// CheckText is the commit-check equivalent used by mgmt callers.
	if _, err := CheckText(hier12674("from; then accept;"), 0); err == nil {
		t.Fatal("CheckText accepted policy-level bare from; want rejection")
	}
	if _, err := CheckText(hier12674("term T { from; then accept; }"), 0); err == nil {
		t.Fatal("CheckText accepted term-level bare from; want rejection")
	}
}

// The valid controls must keep committing with exactly their authored
// meaning: a term-less default-accept policy, and a term-level
// route-filter term.
func TestPolicyLevelValidControlsUnchanged12674(t *testing.T) {
	for _, ing := range policyLevelIngress12674 {
		t.Run("default-accept/"+ing.name, func(t *testing.T) {
			s := newTestStore(t)
			enterCfg(t, s)
			if err := ing.load(t, s, hier12674("then accept;"),
				"set policy-options policy-statement P then accept"); err != nil {
				t.Fatalf("load: %v", err)
			}
			if _, err := s.CommitCheck(); err != nil {
				t.Fatalf("CommitCheck: %v", err)
			}
			cfg, err := s.Commit()
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}
			ps := policyStatementP12674(t, cfg)
			if ps.DefaultAction != "accept" || len(ps.Terms) != 0 || len(ps.UnknownFrom) != 0 {
				t.Fatalf("default-accept control changed: %+v", ps)
			}
		})
		t.Run("term route-filter/"+ing.name, func(t *testing.T) {
			s := newTestStore(t)
			enterCfg(t, s)
			hier := hier12674("term T { from route-filter " + policyLevelRF12674 + " exact; then accept; }")
			flat := "set policy-options policy-statement P term T from route-filter " + policyLevelRF12674 + " exact\nset policy-options policy-statement P term T then accept"
			if err := ing.load(t, s, hier, flat); err != nil {
				t.Fatalf("load: %v", err)
			}
			if _, err := s.CommitCheck(); err != nil {
				t.Fatalf("CommitCheck: %v", err)
			}
			cfg, err := s.Commit()
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}
			ps := policyStatementP12674(t, cfg)
			if len(ps.Terms) != 1 || len(ps.Terms[0].RouteFilters) != 1 ||
				ps.Terms[0].RouteFilters[0].Prefix != policyLevelRF12674 ||
				ps.Terms[0].Action != "accept" {
				t.Fatalf("term control changed: %+v", ps)
			}
		})
	}
	if _, err := CheckText(hier12674("then accept;"), 0); err != nil {
		t.Fatalf("CheckText rejected default-accept control: %v", err)
	}
	if _, err := CheckText("policy-options { policy-statement [ P Q ] { then accept; } }", 0); err != nil {
		t.Fatalf("CheckText rejected grouped default-accept control: %v", err)
	}
	// Every group member compiles, not just the first: Q must exist
	// with the shared default-accept body.
	qcfg, err := CheckText("policy-options { policy-statement [ P Q ] { then accept; } }", 0)
	if err != nil {
		t.Fatalf("CheckText grouped member control: %v", err)
	}
	q := qcfg.PolicyOptions.PolicyStatements["Q"]
	if q == nil || q.DefaultAction != "accept" {
		t.Fatalf("grouped member Q missing or wrong: %+v", qcfg.PolicyOptions.PolicyStatements)
	}
}

func TestPolicyLevelFromTolerantSyncFailsClosed12674(t *testing.T) {
	cases := []struct {
		name              string
		body              string
		policyLevelMarker bool
	}{
		{"block-packed", "then accept from route-filter 10.0.0.0/8 exact; term T { from protocol static; then accept; }", true},
		{"policy-level unsupported", "from route-filter 10.0.0.0/8 exact; then accept; term T { from protocol static; then accept; }", true},
		{"policy-level bare", "from; then accept; term T { from protocol static; then accept; }", true},
		{"term-level bare", "then accept; term T { from; then accept; }", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			cfg, err := s.SyncApply(hier12674(tc.body), nil)
			if err != nil {
				t.Fatalf("SyncApply: %v", err)
			}
			ps := policyStatementP12674(t, cfg)
			if tc.policyLevelMarker && (ps.DefaultAction != "reject" || len(ps.UnknownFrom) == 0) {
				t.Fatalf("tolerant policy-level from did not fail closed: %+v", ps)
			}
			if len(ps.Terms) != 1 || ps.Terms[0].Action != "reject" || ps.Terms[0].NextPolicy {
				t.Fatalf("tolerant from did not fail closed for terms: %+v", ps.Terms)
			}
			if len(cfg.Warnings) == 0 {
				t.Fatal("tolerant unsupported from load did not warn")
			}
		})
	}
	t.Run("grouped hierarchical", func(t *testing.T) {
		s := newTestStore(t)
		cfg, err := s.SyncApply("policy-options { policy-statement [ P Q ] { then accept from route-filter 10.0.0.0/8 exact; } }", nil)
		if err != nil {
			t.Fatalf("SyncApply: %v", err)
		}
		ps := policyStatementP12674(t, cfg)
		if ps.DefaultAction != "reject" || len(ps.UnknownFrom) == 0 {
			t.Fatalf("tolerant grouped policy-level from did not fail closed: %+v", ps)
		}
	})
}
