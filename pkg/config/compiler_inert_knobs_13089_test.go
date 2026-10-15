package config

import (
	"strings"
	"testing"
)

// compileText13089 parses braced config text the way Store.Load does.
func compileText13089(t *testing.T, text string) *Config {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return c
}

// TestSNMPInertKnobAdvisoriesAcrossASTShapes is the RED-on-revert guard for
// #13089 (SNMP half): the security-relevant community advisories must fire
// identically no matter which AST spelling the operator used. compileSNMP
// accepts and compiles the flat-set CHAIN (`set snmp community <c>
// authorization ro view v` nests `view` under `authorization`, #8778) and the
// two-level container (`snmp { community { <name> { view v; } } }`), but
// snmpInertKnobWarnings only walked direct children, so those spellings
// committed with NO advisory — the view-scoped community silently kept full
// ifTable exposure. All cells were verified RED on pre-fix master.
func TestSNMPInertKnobAdvisoriesAcrossASTShapes(t *testing.T) {
	cases := []struct {
		name string
		// sets builds the tree via ParseSetCommand+SetPath (the CLI path);
		// text (when non-empty) is parsed as braced config instead.
		sets []string
		text string
		want []string
	}{
		{
			name: "flat-set chain nests view under authorization",
			sets: []string{
				"set snmp community SUPERSECRETCOMMUNITY authorization read-only view myview",
			},
			want: []string{"snmp community view"},
		},
		{
			name: "flat-set chain nests routing-instance under authorization",
			sets: []string{
				"set snmp community public authorization read-only routing-instance ri clients 10.0.0.0/8",
			},
			want: []string{"snmp community routing-instance"},
		},
		{
			name: "flat-set chain nests logical-system under authorization",
			sets: []string{
				"set snmp community public authorization read-only logical-system ls",
			},
			want: []string{"snmp community logical-system"},
		},
		{
			name: "two-level container with view in the name block",
			text: "snmp {\n community {\n  SUPERSECRETCOMMUNITY {\n   view myview;\n  }\n }\n}\n",
			want: []string{"snmp community view"},
		},
		{
			name: "two-level container with nested logical-system body",
			text: "snmp {\n community {\n  public {\n   logical-system ls {\n    clients 10.0.0.0/8;\n   }\n  }\n }\n}\n",
			want: []string{"snmp community logical-system"},
		},
		{
			// Regression guard for the spellings that already warned:
			// the direct child, and the tail packed on the community line.
			name: "direct child and packed tail still warn",
			sets: []string{
				"set snmp community SUPERSECRETCOMMUNITY view myview",
				"set snmp community packedtail authorization read-only view myview",
			},
			want: []string{"snmp community view"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c *Config
			if tc.text != "" {
				c = compileText13089(t, tc.text)
			} else {
				var err error
				tree := buildTree4303(t, tc.sets)
				c, err = CompileConfig(tree)
				if err != nil {
					t.Fatalf("compile: %v", err)
				}
			}
			all := strings.Join(c.Warnings, "\n")
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Errorf("missing advisory %q; warnings:\n%s", w, all)
				}
			}
			// The community string is a secret — never echoed, in any shape.
			if strings.Contains(all, "SUPERSECRETCOMMUNITY") {
				t.Errorf("advisory echoed the secret community string; warnings:\n%s", all)
			}
		})
	}
}

// TestSNMPInertKnobAdvisoriesQuietWhenAbsent is the negative control for the
// #13089 SNMP walk: a community carrying only modelled statements must not
// grow new advisories from the recursive search.
func TestSNMPInertKnobAdvisoriesQuietWhenAbsent(t *testing.T) {
	c, err := func() (*Config, error) {
		tree := buildTree4303(t, []string{
			"set snmp community public authorization read-only clients 10.0.0.0/8",
		})
		return CompileConfig(tree)
	}()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	all := strings.Join(c.Warnings, "\n")
	for _, unwanted := range []string{
		"snmp community view",
		"snmp community routing-instance",
		"snmp community logical-system",
	} {
		if strings.Contains(all, unwanted) {
			t.Errorf("unexpected advisory %q; warnings:\n%s", unwanted, all)
		}
	}
}

// TestSystemInertKnobAdvisoriesAcrossASTShapes is the RED-on-revert guard for
// #13089 (system half): the inert-knob advisories must fire on every AST
// spelling compileSystem accepts. Three shapes were blind: a SECOND sibling
// block (FindChild saw only the first), the flat-set chain (`set system
// services ssh root-login deny rate-limit 5` nests rate-limit under
// root-login, #8778), and the brace-elided body packed on the block's — or
// the whole `system` statement's — own Keys (#2419). All cells were verified
// RED on pre-fix master.
func TestSystemInertKnobAdvisoriesAcrossASTShapes(t *testing.T) {
	cases := []struct {
		name string
		sets []string
		text string
		want []string
	}{
		{
			name: "second login sibling block",
			text: "system {\n login {\n  message \"one\";\n }\n login {\n  retry-options tries-before-disconnect 3;\n }\n}\n",
			want: []string{"login message", "login retry-options"},
		},
		{
			name: "second ntp sibling block",
			text: "system {\n ntp {\n  boot-server 10.0.0.9;\n }\n ntp {\n  authentication-key 1 type md5 value NTPSECRETKEY;\n }\n}\n",
			want: []string{"ntp boot-server", "ntp authentication-key"},
		},
		{
			name: "second services sibling block",
			text: "system {\n services {\n  ssh {\n   protocol-version v2;\n  }\n }\n services {\n  ssh {\n   rate-limit 20;\n  }\n }\n}\n",
			want: []string{"ssh rate-limit"},
		},
		{
			name: "flat-set chain nests rate-limit under root-login",
			sets: []string{"set system services ssh root-login deny rate-limit 5"},
			want: []string{"ssh rate-limit"},
		},
		{
			name: "ssh body packed on the ssh line",
			text: "system {\n services {\n  ssh root-login deny rate-limit 5;\n }\n}\n",
			want: []string{"ssh rate-limit"},
		},
		{
			name: "ntp body packed on the ntp line",
			text: "system {\n ntp authentication-key 1 type md5 value NTPSECRETKEY;\n}\n",
			want: []string{"ntp authentication-key"},
		},
		{
			name: "whole body packed on the system line",
			text: "system services ssh rate-limit 5;\n",
			want: []string{"ssh rate-limit"},
		},
		{
			name: "internet-options chain nests an extra under the modelled leaf",
			sets: []string{"set system internet-options no-ipv6-reject-zero-hop-limit tcp-mss 1400"},
			want: []string{"internet-options [tcp-mss]"},
		},
		{
			// Regression guard: `system host-name fw1 { ... }` parses with
			// BOTH a packed tail and a braced body. The #13089 synthesis must
			// only run when Children is empty, or this shape would lose the
			// body's advisories.
			name: "packed tail and braced body coexist",
			text: "system host-name fw1 {\n services {\n  ssh {\n   rate-limit 5;\n  }\n }\n}\n",
			want: []string{"ssh rate-limit"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c *Config
			if tc.text != "" {
				c = compileText13089(t, tc.text)
			} else {
				var err error
				tree := buildTree4303(t, tc.sets)
				c, err = CompileConfig(tree)
				if err != nil {
					t.Fatalf("compile: %v", err)
				}
			}
			all := strings.Join(c.Warnings, "\n")
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Errorf("missing advisory %q; warnings:\n%s", w, all)
				}
			}
			// The NTP authentication-key VALUE is a secret — never echoed.
			if strings.Contains(all, "NTPSECRETKEY") {
				t.Errorf("advisory echoed the NTP authentication-key value; warnings:\n%s", all)
			}
		})
	}
}

// TestSystemInertKnobAdvisoriesQuietWhenAbsent is the negative control for
// the #13089 system walk: modelled statements only must not grow advisories.
func TestSystemInertKnobAdvisoriesQuietWhenAbsent(t *testing.T) {
	c := compileText13089(t, "system {\n internet-options {\n  no-ipv6-reject-zero-hop-limit;\n }\n services {\n  ssh {\n   root-login deny;\n  }\n }\n}\n")
	all := strings.Join(c.Warnings, "\n")
	for _, unwanted := range []string{
		"login message",
		"login announcement",
		"login retry-options",
		"ntp boot-server",
		"ntp authentication-key",
		"ntp source-address",
		"internet-options [",
		"ssh rate-limit",
	} {
		if strings.Contains(all, unwanted) {
			t.Errorf("unexpected advisory %q; warnings:\n%s", unwanted, all)
		}
	}
}
