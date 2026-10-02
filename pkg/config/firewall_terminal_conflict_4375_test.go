package config

import (
	"strings"
	"testing"
)

// #4375 (avo-review-007 H3): a firewall-filter term that specifies more than one
// terminating action (accept / reject / discard) is contradictory — Junos treats
// the three as mutually exclusive (a term has exactly ONE terminating action).
// Before validateFilterTerminalConflictStrict, compileFilterThen wrote each
// keyword onto the single-valued term.Action field (last-write-wins) so a term
// with `then accept` AND `then reject` silently compiled to whichever appeared
// last — the operator's intent was ambiguous and the compiled behavior did not
// necessarily match what they wrote. The gate makes it an operator-visible
// commit error.
//
// FAIL-ON-REVERT: remove the validateFilterTerminalConflictStrict invocation (or
// the function's reject) and these strict-path tests go RED — CompileConfig
// accepts the contradictory term.

func TestFilterAcceptRejectConflict_4375(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t then accept",
		"set firewall family inet filter f term t then reject",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("term with both accept and reject must be rejected at commit " +
			"(#4375 — conflicting terminating actions resolve last-wins)")
	}
	if !strings.Contains(err.Error(), "accept") ||
		!strings.Contains(err.Error(), "reject") ||
		!strings.Contains(err.Error(), "terminating") {
		t.Fatalf("error %q must name both conflicting terminating actions", err)
	}
	if !strings.Contains(err.Error(), `filter "f"`) ||
		!strings.Contains(err.Error(), `term "t"`) {
		t.Fatalf("error %q must name the offending filter and term", err)
	}
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the accept/reject conflict: %v", lerr)
	}
}

func TestFilterAcceptDiscardConflict_4375(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t then accept",
		"set firewall family inet filter f term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("term with both accept and discard must be rejected at commit (#4375)")
	}
	if !strings.Contains(err.Error(), "accept") ||
		!strings.Contains(err.Error(), "discard") {
		t.Fatalf("error %q must name the accept/discard conflict", err)
	}
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must not hard-fail on the accept/discard conflict: %v", lerr)
	}
}

func TestFilterRejectDiscardConflict_4375(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t then reject",
		"set firewall family inet filter f term t then discard",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("term with both reject and discard must be rejected at commit (#4375)")
	}
}

// inet6 must be gated identically (the validator walks both families).
func TestFilterTerminalConflictV6_4375(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet6 filter f6 term t then accept",
		"set firewall family inet6 filter f6 term t then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("inet6 term with accept + discard must be rejected (#4375)")
	}
	if !strings.Contains(err.Error(), "inet6") {
		t.Fatalf("error %q must name the inet6 family", err)
	}
}

// A term with a non-terminating modifier (count) plus exactly ONE terminating
// action is valid Junos and must compile cleanly — count/log/forwarding-class/
// dscp/policer are NOT terminating actions and coexist with a terminal.
func TestFilterCountPlusTerminalAllowed_4375(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter ok term t then count c1",
		"set firewall family inet filter ok term t then log",
		"set firewall family inet filter ok term t then accept",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("count + log + accept (one terminal, non-terminal modifiers) must compile: %v", err)
	}
}

// A single terminating action is the ordinary case and must compile.
func TestFilterSingleTerminalAllowed_4375(t *testing.T) {
	for _, action := range []string{"accept", "reject", "discard"} {
		tree := buildFilterTree(t,
			"set firewall family inet filter ok term t then "+action,
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("single terminal %q must compile: %v", action, err)
		}
	}
}

// Repeating the SAME terminating action (e.g. two `then discard` blocks) is a
// redundancy, not a conflict — one distinct terminal — and must compile.
func TestFilterDuplicateSameTerminalAllowed_4375(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter ok term t then discard",
		"set firewall family inet filter ok term t then discard",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("two identical `then discard` blocks (one distinct terminal) must compile: %v", err)
	}
}

// A tolerant load or peer-sync must remain bootable while never installing a
// last-wins allow from contradictory terminals (#11507).
func TestFilterTerminalConflictPoisonsLenientAction11507(t *testing.T) {
	for _, tc := range []struct {
		name    string
		compile func(*ConfigTree) (*Config, error)
		actions []string
	}{
		{
			name:    "load last accept",
			compile: CompileConfigLenient,
			actions: []string{"discard", "accept"},
		},
		{
			name: "peer sync last accept",
			compile: func(tree *ConfigTree) (*Config, error) {
				return CompileConfigForNodeLenient(tree, 1)
			},
			actions: []string{"reject", "accept"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmds := make([]string, 0, len(tc.actions))
			for _, action := range tc.actions {
				cmds = append(cmds, "set firewall family inet filter f term t then "+action)
			}
			cfg, err := tc.compile(buildFilterTree(t, cmds...))
			if err != nil {
				t.Fatalf("tolerant compile must remain bootable (#1960 no-brick): %v", err)
			}
			term := cfg.Firewall.FiltersInet["f"].Terms[0]
			if term.Action != "discard" {
				t.Fatalf("conflicting terminals %v installed Action=%q; want fail-closed discard",
					term.TerminalActions, term.Action)
			}
			foundWarning := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "firewall filter terminal-action conflict") &&
					strings.Contains(warning, "conflicting terminating actions") {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("tolerant compile must warn about the conflict; warnings=%v", cfg.Warnings)
			}
		})
	}
}
