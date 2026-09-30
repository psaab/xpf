package config

import (
	"strings"
	"testing"
)

// #2399 finding 032-16: a firewall-filter `then` term with an UNKNOWN /
// misspelled action token was silently DROPPED by compileFilterThen, leaving
// the term's Action == "". Both the dataplane compiler
// (pkg/dataplane/compiler_filter.go) and the Rust filter
// (userspace-dp/src/filter/compiler.rs parse_term) map "" to ACCEPT, so a term
// the operator meant to DENY became a fail-open PERMIT, and commit reported
// SUCCESS. validateFilterActionsStrict now hard-rejects an unknown `then` token
// at the strict commit path (CompileConfig) while the tolerant load /
// peer-sync path (CompileConfigLenient) downgrades it to a warning (#1960
// no-brick).
//
// All trees are built from flat `set` commands via flatTreeFromSets (defined in
// compiler_interfaces_unsupported_test.go) — the only correct way to exercise
// the flat-set AST shape.

func filterWithThen(then string) []string {
	return []string{
		"set firewall family inet filter f1 term t1 from protocol tcp",
		"set firewall family inet filter f1 term t1 then " + then,
	}
}

// MUST FAIL if validateFilterActionsStrict (or the UnknownActions capture in
// compileFilterThen) is reverted: without the gate the term silently compiles
// to accept and CompileConfig returns no error.
func TestFilterAction_UnknownAction_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithThen("frobnicate")...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject firewall filter f1 term t1 with then frobnicate")
	}
	if !strings.Contains(err.Error(), "frobnicate") ||
		!strings.Contains(err.Error(), "f1") ||
		!strings.Contains(err.Error(), "t1") {
		t.Fatalf("error %q must name the family/filter/term and the offending action", err.Error())
	}
}

// A misspelled terminating action ("accpet") is the canonical real-world fat
// finger this gate exists to catch — it must be rejected, not coerced to a
// permit.
func TestFilterAction_MisspelledTerminatingAction_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithThen("accpet")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject firewall filter with then accpet (typo of accept)")
	}
}

func TestFilterAction_UnknownInet6_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set firewall family inet6 filter f6 term t1 from protocol tcp",
		"set firewall family inet6 filter f6 term t1 then permitt",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject inet6 firewall filter with then permitt")
	}
}

// Anti-over-reject: every legitimate terminating action and modifier (and their
// combinations, including a term that carries ONLY modifiers and falls through
// with no terminating action) must still commit cleanly.
func TestFilterAction_ValidActions_Commit(t *testing.T) {
	for _, then := range []string{
		"accept",
		"discard",
		"reject",
		"count c1",
		"log",
		"syslog",
		"forwarding-class be",
		"loss-priority high",
		"dscp ef",
		// A term with only modifiers and no terminating action is valid Junos
		// (fall-through); it must NOT be flagged as an unknown action.
		"count c1 log",
		// #2399 fold: standard Junos reject message-types and explicit
		// next-term fall-through. Master committed these; the over-reject
		// default arm must not reject them.
		"reject tcp-reset",
		"reject administratively-prohibited",
		"reject port-unreachable",
		"next term",
	} {
		t.Run(strings.ReplaceAll(then, " ", "_"), func(t *testing.T) {
			tree := flatTreeFromSets(t, filterWithThen(then)...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("valid filter then %q must commit, got %v", then, err)
			}
		})
	}

	// `then policer <name>` is valid only with a defined policer (a separate
	// existing reference gate); the action token itself must not be flagged as
	// unknown. Exercise it with the policer defined so the term commits.
	t.Run("policer", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set firewall policer p1 if-exceeding bandwidth-limit 1m",
			"set firewall policer p1 if-exceeding burst-size-limit 15k",
			"set firewall policer p1 then discard",
			"set firewall family inet filter f1 term t1 from protocol tcp",
			"set firewall family inet filter f1 term t1 then policer p1",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("valid filter then policer p1 must commit, got %v", err)
		}
	})
}

// No-brick (#1960 doctrine): a config persisted / peer-synced with a filter term
// carrying an unknown action must still LOAD on the tolerant path
// (CompileConfigLenient), downgraded to a warning — an upgraded or receiving
// node must not fail closed on boot. (The dataplane independently fails the
// unknown action closed; the leniently-loaded Go term keeps Action == "".)
func TestFilterAction_Unknown_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithThen("frobnicate")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of an unknown filter action must not fail: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "firewall filter action") && strings.Contains(w, "frobnicate") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected lenient path to record a firewall-filter-action downgrade warning, got %v", cfg.Warnings)
	}
}

// The unknown token must be captured onto the typed term (UnknownActions), not
// silently dropped — this is the seam the strict gate reads. MUST FAIL if the
// default arm of compileFilterThen is reverted.
func TestFilterAction_CompileCapturesUnknownToken(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithThen("frobnicate")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile failed: %v", err)
	}
	f := cfg.Firewall.FiltersInet["f1"]
	if f == nil || len(f.Terms) == 0 {
		t.Fatal("filter f1 term t1 not compiled")
	}
	term := f.Terms[0]
	if len(term.UnknownActions) == 0 || term.UnknownActions[0] != "frobnicate" {
		t.Fatalf("expected term.UnknownActions to capture %q, got %v", "frobnicate", term.UnknownActions)
	}
	// A captured-unknown term keeps Action == "" — which the dataplane maps to
	// accept. This is exactly why the commit gate (and the Rust fail-closed for
	// a non-empty unknown) are required.
	if term.Action != "" {
		t.Fatalf("expected Action to stay \"\" for an unknown token, got %q", term.Action)
	}
}

// #2399 fold: `then reject <message-type>` commits as a plain reject and
// captures the type for fidelity. MUST FAIL if the over-reject default-arm is
// restored (it would route tcp-reset to UnknownActions and reject the commit).
func TestFilterAction_RejectMessageType_CommitsAndCaptures(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithThen("reject tcp-reset")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("then reject tcp-reset must commit, got %v", err)
	}
	term := cfg.Firewall.FiltersInet["f1"].Terms[0]
	if term.Action != "reject" {
		t.Fatalf("expected Action reject, got %q", term.Action)
	}
	if term.RejectMessageType != "tcp-reset" {
		t.Fatalf("expected RejectMessageType tcp-reset, got %q", term.RejectMessageType)
	}
	if len(term.UnknownActions) != 0 {
		t.Fatalf("reject tcp-reset must not be flagged unknown, got %v", term.UnknownActions)
	}
}

// `then next term` (explicit fall-through) commits cleanly and marks NextTerm.
func TestFilterAction_NextTerm_CommitsAndMarks(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithThen("next term")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("then next term must commit, got %v", err)
	}
	term := cfg.Firewall.FiltersInet["f1"].Terms[0]
	if !term.NextTerm {
		t.Fatal("expected NextTerm to be set for then next term")
	}
	if len(term.UnknownActions) != 0 {
		t.Fatalf("next term must not be flagged unknown, got %v", term.UnknownActions)
	}
	// Fall-through keeps Action == "" (no terminating action).
	if term.Action != "" {
		t.Fatalf("next term must keep Action \"\", got %q", term.Action)
	}
}

// A genuine typo AFTER reject (an unrecognized message-type) must still be
// rejected at commit — the fidelity acceptance is gated to the KNOWN
// message-types only, so a fat-finger does not slip through.
func TestFilterAction_UnknownRejectMessageType_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithThen("reject blorp")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject `then reject blorp` (unknown message-type)")
	}
}

// #11355: SetPath can bury recognized actions beneath `next term` and
// `reject <message-type>`. Flat-set chains and packed lines must preserve the
// action fields; existing conflict gates or unknown-action validation then
// determine whether the resulting term is committable.
func TestFilterAction_TailsAreConsistentAcrossFlatAndPacked11355(t *testing.T) {
	for _, tc := range []struct {
		name                string
		then                string
		wantError           string
		wantWarning         string
		wantActionWarning   bool
		wantNextTerm        bool
		wantRejectMessage   string
		wantRoutingInstance string
		wantCount           string
	}{
		{
			name: "next term with routing-instance", then: "next term routing-instance ISP-B",
			wantError: "routing-instance", wantWarning: "routing-instance",
			wantNextTerm: true, wantRoutingInstance: "ISP-B",
		},
		{
			name: "reject type with routing-instance", then: "reject tcp-reset routing-instance ISP-B",
			wantError: "routing-instance", wantWarning: "routing-instance",
			wantRejectMessage: "tcp-reset", wantRoutingInstance: "ISP-B",
		},
		{
			name: "reject type with count", then: "reject tcp-reset count c1",
			wantRejectMessage: "tcp-reset", wantCount: "c1",
		},
		{
			name: "unknown action after next term", then: "next term frobnicate",
			wantError: "frobnicate", wantWarning: "frobnicate",
			wantActionWarning: true, wantNextTerm: true,
		},
		{
			name: "unknown action after reject type", then: "reject tcp-reset frobnicate",
			wantError: "frobnicate", wantWarning: "frobnicate",
			wantActionWarning: true, wantRejectMessage: "tcp-reset",
		},
	} {
		for _, form := range []struct {
			name  string
			build func(*testing.T, string) *ConfigTree
		}{
			{
				name: "flat-set",
				build: func(t *testing.T, then string) *ConfigTree {
					commands := []string{"set routing-instances ISP-B instance-type virtual-router"}
					commands = append(commands, filterWithThen(then)...)
					return flatTreeFromSets(t, commands...)
				},
			},
			{
				name: "packed-line",
				build: func(t *testing.T, then string) *ConfigTree {
					source := `routing-instances { ISP-B { instance-type virtual-router; } } ` +
						`firewall { family inet { filter f1 { term t1 { from { protocol tcp; } then ` +
						then + `; } } } }`
					return hierTree(t, source)
				},
			},
		} {
			t.Run(tc.name+"/"+form.name, func(t *testing.T) {
				_, strictErr := CompileConfig(form.build(t, tc.then))
				if tc.wantError == "" {
					if strictErr != nil {
						t.Fatalf("strict commit rejected then %q: %v", tc.then, strictErr)
					}
				} else {
					if strictErr == nil {
						t.Fatalf("strict commit accepted then %q", tc.then)
					}
					if !strings.Contains(strictErr.Error(), tc.wantError) {
						t.Fatalf("strict refusal %q does not name %q", strictErr, tc.wantError)
					}
				}

				cfg, err := CompileConfigLenient(form.build(t, tc.then))
				if err != nil {
					t.Fatalf("tolerant load rejected then %q: %v", tc.then, err)
				}
				term := cfg.Firewall.FiltersInet["f1"].Terms[0]
				if term.NextTerm != tc.wantNextTerm ||
					term.RejectMessageType != tc.wantRejectMessage ||
					term.RoutingInstance != tc.wantRoutingInstance ||
					term.Count != tc.wantCount {
					t.Fatalf("then %q compiled fields NextTerm=%v RejectMessageType=%q RoutingInstance=%q Count=%q",
						tc.then, term.NextTerm, term.RejectMessageType, term.RoutingInstance, term.Count)
				}
				if tc.wantWarning == "" {
					if len(cfg.Warnings) != 0 {
						t.Fatalf("valid then %q produced unexpected warnings: %v", tc.then, cfg.Warnings)
					}
					return
				}
				for _, warning := range cfg.Warnings {
					if strings.Contains(warning, tc.wantWarning) &&
						(!tc.wantActionWarning || strings.Contains(warning, "firewall filter action")) {
						return
					}
				}
				t.Fatalf("tolerant load did not warn about then %q: %v", tc.then, cfg.Warnings)
			})
		}
	}
}

// A hierarchical action body is another tree shape where the message-type
// owns the later action as a child rather than a direct sibling.
func TestFilterAction_HierarchicalNestedRejectTailPreservesCount11355(t *testing.T) {
	source := `firewall { family inet { filter f1 { term t1 { from { protocol tcp; } ` +
		`then { reject { tcp-reset { count c1; } } } } } } }`
	cfg, err := CompileConfig(hierTree(t, source))
	if err != nil {
		t.Fatalf("hierarchical reject/count action chain should compile: %v", err)
	}
	term := cfg.Firewall.FiltersInet["f1"].Terms[0]
	if term.Action != "reject" || term.RejectMessageType != "tcp-reset" || term.Count != "c1" {
		t.Fatalf("nested reject tail compiled as action=%q message=%q count=%q",
			term.Action, term.RejectMessageType, term.Count)
	}
}
