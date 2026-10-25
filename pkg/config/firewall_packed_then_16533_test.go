package config

import (
	"strings"
	"testing"
)

// #16533: a firewall-filter term packed on one line whose `then` tail carries
// an unmodelled token passed strict commit with zero warnings and installed a
// terminating ACCEPT (Rust maps Action "" to Accept).
//
// Mechanism: `term t1 from protocol tcp then dicsard;` packs the whole term
// body onto the term node's Keys with no Children. packedBodyChildren
// declines on `dicsard` (outside the modelled grammar at every open level)
// and returns node.Children — empty — so compileFirewall saw no `then` child,
// compileFilterThen never ran, UnknownActions stayed empty,
// validateFilterActionsStrict stayed silent, and failClosedUnknownFilterAction
// had nothing to fail closed on. The `from` half survived only via the #10071
// raw re-scan, which had no `then` counterpart.
//
// Fix: (1) model `next term` in the packed `then` grammar (schema), so the
// documented fall-through idiom expands instead of declining the whole tail;
// (2) when packedBody declines, re-scan the raw packed `then` segment(s) in
// compileFirewall (firewallPackedTermThenNodes) through compileFilterThen, so
// every unrecognised token lands in UnknownActions — strict rejects naming
// the token, tolerant warns and forces discard.
//
// FAIL ON REVERT: removing the re-scan call (or the helper) makes the typo /
// sample / inet6 rows compile strict-clean with Action "" again; removing the
// schema `next` declaration makes the count+next-term row decline and (with
// the re-scan) still work via the leaf arm, but removing BOTH makes it
// Action "" with NextTerm false.

func compilePacked16533(t *testing.T, src string) (*Config, error) {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", src, perrs)
	}
	return CompileConfig(tree)
}

func compilePackedLenient16533(t *testing.T, src string) *Config {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", src, perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile %q: %v", src, err)
	}
	return cfg
}

func term16533(t *testing.T, cfg *Config, family, filter string) *FirewallFilterTerm {
	t.Helper()
	var filters map[string]*FirewallFilter
	switch family {
	case "inet":
		filters = cfg.Firewall.FiltersInet
	case "inet6":
		filters = cfg.Firewall.FiltersInet6
	default:
		t.Fatalf("bad family %q", family)
	}
	f := filters[filter]
	if f == nil || len(f.Terms) != 1 {
		t.Fatalf("filter %q compiled %+v, want exactly one term", filter, f)
	}
	return f.Terms[0]
}

// The probe rows from #16533: packed typo, `sample`, and the inet6 spelling
// must be strict-rejected naming the token, and compile to discard (not the
// empty terminating-Accept action) on the tolerant path.
func TestPackedThenUnmodelledStrictRejects16533(t *testing.T) {
	cases := []struct {
		name, src, family, filter, token string
	}{
		{"typo after from", `firewall { family inet { filter f1 { term t1 from protocol tcp then dicsard; } } }`, "inet", "f1", "dicsard"},
		{"typo bare term", `firewall { family inet { filter f1 { term t1 then dicsard; } } }`, "inet", "f1", "dicsard"},
		{"sample", `firewall { family inet { filter f1 { term t1 then sample; } } }`, "inet", "f1", "sample"},
		{"inet6 typo", `firewall { family inet6 { filter f6 { term t1 then dicsard; } } }`, "inet6", "f6", "dicsard"},
		{"typo after known modifier", `firewall { family inet { filter f1 { term t1 from protocol tcp then count c1 dicsard; } } }`, "inet", "f1", "dicsard"},
		{"unknown before known terminal", `firewall { family inet { filter f1 { term t1 then frobnicate discard; } } }`, "inet", "f1", "frobnicate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compilePacked16533(t, tc.src)
			if err == nil {
				t.Fatalf("strict compile of %q must reject unknown then token %q, got clean commit", tc.src, tc.token)
			}
			if !strings.Contains(err.Error(), tc.token) {
				t.Fatalf("strict error %q must name the offending token %q", err.Error(), tc.token)
			}
			cfg := compilePackedLenient16533(t, tc.src)
			term := term16533(t, cfg, tc.family, tc.filter)
			if len(term.UnknownActions) == 0 || term.UnknownActions[0] != tc.token {
				// frobnicate-before-discard: first unknown is still the token.
				found := false
				for _, u := range term.UnknownActions {
					if u == tc.token {
						found = true
					}
				}
				if !found {
					t.Fatalf("lenient UnknownActions=%v, want to contain %q", term.UnknownActions, tc.token)
				}
			}
			if term.Action != FilterActionDiscard {
				t.Fatalf("lenient Action=%q, want discard (fail-closed, not empty terminating Accept)", term.Action)
			}
			warned := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, tc.token) {
					warned = true
				}
			}
			if !warned {
				t.Fatalf("lenient warnings %v must name %q", cfg.Warnings, tc.token)
			}
		})
	}
}

// `term t0 then count all next term;` — the documented lo0/transit idiom —
// must compile to next_term=true with the counter preserved, strict-clean.
func TestPackedThenCountNextTerm16533(t *testing.T) {
	for _, tc := range []struct{ name, src, family, filter string }{
		{"inet", `firewall { family inet { filter f1 { term t0 then count all next term; } } }`, "inet", "f1"},
		{"inet6", `firewall { family inet6 { filter f6 { term t0 then count all next term; } } }`, "inet6", "f6"},
		{"bare next term", `firewall { family inet { filter f1 { term t0 then next term; } } }`, "inet", "f1"},
		{"count log next term", `firewall { family inet { filter f1 { term t0 then count all log next term; } } }`, "inet", "f1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := compilePacked16533(t, tc.src)
			if err != nil {
				t.Fatalf("packed %q must commit strict-clean, got %v", tc.src, err)
			}
			term := term16533(t, cfg, tc.family, tc.filter)
			if !term.NextTerm {
				t.Fatalf("NextTerm=false, want true (authored `next term` fall-through); term=%+v", term)
			}
			if len(term.UnknownActions) != 0 {
				t.Fatalf("UnknownActions=%v, want empty for modelled `next term`", term.UnknownActions)
			}
			if strings.Contains(tc.src, "count all") && term.Count != "all" {
				t.Fatalf("Count=%q, want %q — the modifier before `next term` must survive", term.Count, "all")
			}
		})
	}
}

// Controls: the packed valid spellings and the braced controls are unchanged.
func TestPackedThenControlsUnchanged16533(t *testing.T) {
	// Packed discard still discards, strict-clean, no unknowns.
	cfg, err := compilePacked16533(t, `firewall { family inet { filter f1 { term t1 then discard; } } }`)
	if err != nil {
		t.Fatalf("packed discard must commit, got %v", err)
	}
	if term := term16533(t, cfg, "inet", "f1"); term.Action != FilterActionDiscard || len(term.UnknownActions) != 0 {
		t.Fatalf("packed discard term=%+v, want discard with no unknowns", term)
	}
	// Braced typo is still rejected (the pre-existing asymmetry's good side).
	if _, err := compilePacked16533(t, `firewall { family inet { filter f1 { term t1 { then { dicsard; } } } } }`); err == nil {
		t.Fatal("braced typo must still reject at strict commit")
	}
	// Braced next term still falls through.
	cfg, err = compilePacked16533(t, `firewall { family inet { filter f1 { term t0 { then { count all; next term; } } } } }`)
	if err != nil {
		t.Fatalf("braced count+next term must commit, got %v", err)
	}
	if term := term16533(t, cfg, "inet", "f1"); !term.NextTerm || term.Count != "all" {
		t.Fatalf("braced term=%+v, want NextTerm with count=all", term)
	}
	// Packed accept still accepts.
	cfg, err = compilePacked16533(t, `firewall { family inet { filter f1 { term t1 then accept; } } }`)
	if err != nil {
		t.Fatalf("packed accept must commit, got %v", err)
	}
	if term := term16533(t, cfg, "inet", "f1"); term.Action != FilterActionAccept {
		t.Fatalf("packed accept Action=%q, want accept", term.Action)
	}
}
