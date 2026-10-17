package config

import (
	"strings"
	"testing"
)

// Tests for #14660: event-options accepts events and actions the engine
// can never fire or execute, without a warning. The only producer wired
// to eventengine.HandleEvent fires ping_probe_failed / ping_test_failed
// / ping_test_completed (pkg/rpm), and the engine executes only
// `then change-configuration`. Before the gate, unknown event names
// (including case-typos like PING_TEST_FAILED), Junos `then` actions
// such as execute-commands / raise-trap / event-script, and undeclared
// event-options / policy children all committed with warnings=[].
//
// Strict (CompileConfig / CheckText via configstore): hard-reject
// naming the policy and token. Lenient (CompileConfigLenient): warn,
// still boots (#1960). The three RPM names with change-configuration
// stay warning-free on both paths.
//
// RED-on-revert: removing validateEventOptionsInertAST from
// runPreWalkGates (or its lenient flag) makes every Reject/Warn cell
// below accept silently.

func hierTree14660(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return tree
}

func hasWarningContaining14660(cfg *Config, subs ...string) bool {
	for _, w := range cfg.Warnings {
		ok := true
		for _, s := range subs {
			if !strings.Contains(w, s) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// TestEventOptionsInert14660StrictRejects is the decisive strict check:
// every never-fireable / never-executable shape must be a hard error
// naming the policy and the offending token, in both AST shapes.
func TestEventOptionsInert14660StrictRejects(t *testing.T) {
	cases := []struct {
		name string
		tree *ConfigTree
		want []string // substrings the error must contain
	}{
		{
			name: "unknown event hier",
			tree: hierTree14660(t, `event-options { policy p { events snmp_trap_link_down; then { change-configuration { commands "set system host-name x"; } } } }`),
			want: []string{"p", "snmp_trap_link_down", "ping_test_failed"},
		},
		{
			name: "unknown event flat",
			tree: setTree6659(t,
				`set event-options policy p events snmp_trap_link_down`,
				`set event-options policy p then change-configuration commands "set system host-name x"`),
			want: []string{"p", "snmp_trap_link_down"},
		},
		{
			name: "uppercase event hier (case-sensitive)",
			tree: hierTree14660(t, `event-options { policy p { events PING_TEST_FAILED; } }`),
			want: []string{"p", "PING_TEST_FAILED"},
		},
		{
			name: "uppercase event flat",
			tree: setTree6659(t, `set event-options policy p events PING_TEST_FAILED`),
			want: []string{"p", "PING_TEST_FAILED"},
		},
		{
			name: "mixed valid and unknown events hier bracket",
			tree: hierTree14660(t, `event-options { policy p { events [ ping_test_failed snmp_trap_link_down ]; } }`),
			want: []string{"snmp_trap_link_down"},
		},
		{
			name: "mixed valid and unknown events flat bracket",
			tree: setTree6659(t, `set event-options policy p events [ ping_test_failed snmp_trap_link_down ]`),
			want: []string{"snmp_trap_link_down"},
		},
		{
			name: "then execute-commands hier",
			tree: hierTree14660(t, `event-options { policy p { events ping_test_failed; then { execute-commands { commands "show version"; } } } }`),
			want: []string{"p", "execute-commands", "change-configuration"},
		},
		{
			name: "then execute-commands flat",
			tree: setTree6659(t,
				`set event-options policy p events ping_test_failed`,
				`set event-options policy p then execute-commands commands "show version"`),
			want: []string{"p", "execute-commands"},
		},
		{
			name: "then raise-trap hier",
			tree: hierTree14660(t, `event-options { policy p { events ping_test_failed; then { raise-trap; } } }`),
			want: []string{"raise-trap"},
		},
		{
			name: "then event-script flat",
			tree: setTree6659(t, `set event-options policy p then event-script foo.slax`),
			want: []string{"event-script"},
		},
		{
			name: "then ignore hier packed",
			tree: hierTree14660(t, `event-options { policy p { events ping_test_failed; then ignore; } }`),
			want: []string{"ignore"},
		},
		{
			name: "then generate-event flat",
			tree: setTree6659(t, `set event-options policy p then generate-event FOO time-of-day "2020-01-01"`),
			want: []string{"generate-event"},
		},
		{
			name: "event-options bogus child hier",
			tree: hierTree14660(t, `event-options { generate-event FOO { time-of-day "2020-01-01"; } policy p { events ping_test_failed; } }`),
			want: []string{"generate-event"},
		},
		{
			name: "event-options bogus child flat",
			tree: setTree6659(t, `set event-options bogus-child foo`),
			want: []string{"bogus-child"},
		},
		{
			name: "policy bogus child hier",
			tree: hierTree14660(t, `event-options { policy p { events ping_test_failed; generate-event FOO; } }`),
			want: []string{"p", "generate-event"},
		},
		{
			name: "policy bogus child flat",
			tree: setTree6659(t,
				`set event-options policy p events ping_test_failed`,
				`set event-options policy p destination foo`),
			want: []string{"p", "destination"},
		},
		{
			name: "second policy block unknown event (duplicate-block discipline)",
			tree: hierTree14660(t, `event-options { policy a { events ping_test_failed; } } event-options { policy b { events never_fired_event; } }`),
			want: []string{"b", "never_fired_event"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted inert event-options shape; want reject containing %v", tc.want)
			}
			for _, sub := range tc.want {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q missing %q", err.Error(), sub)
				}
			}
			if !strings.Contains(err.Error(), "#14660") {
				t.Errorf("error %q does not cite #14660", err.Error())
			}
		})
	}
}

// TestEventOptionsInert14660ValidControls proves the gate does not
// over-reject: the three RPM names with change-configuration (plus
// within / attributes-match / plant-class) stay clean on BOTH paths
// with no #14660 warning.
func TestEventOptionsInert14660ValidControls(t *testing.T) {
	trees := map[string]*ConfigTree{
		"hier all three events": hierTree14660(t, `event-options {
			policy p {
				events [ ping_probe_failed ping_test_failed ping_test_completed ];
				within 60 { trigger on 1; }
				attributes-match { ping_test_failed.test-owner matches WAN; }
				then { change-configuration { commands "set system host-name recovered"; } }
			}
		}`),
		"flat all three events": setTree6659(t,
			`set event-options policy p events ping_probe_failed`,
			`set event-options policy p events ping_test_failed`,
			`set event-options policy p events ping_test_completed`,
			`set event-options policy p then change-configuration commands "set system host-name recovered"`),
		"hier plant-class": hierTree14660(t, `event-options { policy p { events ping_test_failed; plant-class super-user; then { change-configuration { commands "set system host-name x"; } } } }`),
	}
	for name, tree := range trees {
		t.Run(name+"/strict", func(t *testing.T) {
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected valid control: %v", err)
			}
			if hasWarningContaining14660(cfg, "#14660") {
				t.Fatalf("strict valid control carried #14660 warning: %v", cfg.Warnings)
			}
		})
		t.Run(name+"/lenient", func(t *testing.T) {
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected valid control: %v", err)
			}
			if hasWarningContaining14660(cfg, "#14660") {
				t.Fatalf("lenient valid control carried #14660 warning: %v", cfg.Warnings)
			}
		})
	}
}

// TestEventOptionsInert14660LenientWarns proves the tolerant path
// downgrades every inert class to a named warning and still compiles
// (boots) — #1960 no-brick.
func TestEventOptionsInert14660LenientWarns(t *testing.T) {
	cases := []struct {
		name string
		tree *ConfigTree
		want []string
	}{
		{
			name: "unknown event",
			tree: setTree6659(t, `set event-options policy p events snmp_trap_link_down`),
			want: []string{"p", "snmp_trap_link_down", "#14660"},
		},
		{
			name: "then execute-commands",
			tree: hierTree14660(t, `event-options { policy p { events ping_test_failed; then { execute-commands { commands "show version"; } } } }`),
			want: []string{"execute-commands", "#14660"},
		},
		{
			name: "event-options bogus child",
			tree: setTree6659(t, `set event-options bogus-child foo`),
			want: []string{"bogus-child", "#14660"},
		},
		{
			name: "policy bogus child",
			tree: setTree6659(t, `set event-options policy p destination foo`),
			want: []string{"destination", "#14660"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tc.tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected inert shape on tolerant path: %v", err)
			}
			if cfg == nil {
				t.Fatal("lenient compile returned nil config")
			}
			if !hasWarningContaining14660(cfg, tc.want...) {
				t.Fatalf("lenient warnings %v contain no warning with %v", cfg.Warnings, tc.want)
			}
		})
	}
}

// TestEventOptionsInert14660DirectValidator exercises the AST gate
// directly (unit-level, independent of the full pipeline wiring).
func TestEventOptionsInert14660DirectValidator(t *testing.T) {
	tree := hierTree14660(t, `event-options { policy p { events ping_test_failed bogus_event; then { raise-trap; } } }`)
	// Strict: first error names the unknown event.
	if _, err := validateEventOptionsInertAST(tree.Children, false); err == nil ||
		!strings.Contains(err.Error(), "bogus_event") {
		t.Fatalf("strict direct gate = %v, want bogus_event reject", err)
	}
	// Lenient: warnings cover both the event and the action.
	warnings, err := validateEventOptionsInertAST(tree.Children, true)
	if err != nil {
		t.Fatalf("lenient direct gate error: %v", err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "bogus_event") || !strings.Contains(joined, "raise-trap") {
		t.Fatalf("lenient direct warnings %v missing bogus_event/raise-trap", warnings)
	}
	// Valid control: no error, no warnings either way.
	good := hierTree14660(t, `event-options { policy p { events ping_test_failed; then { change-configuration { commands "set system host-name x"; } } } }`)
	if w, err := validateEventOptionsInertAST(good.Children, false); err != nil || len(w) != 0 {
		t.Fatalf("strict direct valid = warnings %v err %v", w, err)
	}
	if w, err := validateEventOptionsInertAST(good.Children, true); err != nil || len(w) != 0 {
		t.Fatalf("lenient direct valid = warnings %v err %v", w, err)
	}
}
