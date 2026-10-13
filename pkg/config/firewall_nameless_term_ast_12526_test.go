package config

import (
	"strings"
	"testing"
)

func firewallNamelessASTTree12526(t *testing.T, body string) *ConfigTree {
	t.Helper()
	return hierTree(t, `firewall {
    family inet {
        filter F {
            `+body+`
        }
    }
}`)
}

func TestValidateFirewallNamelessTermsAST12526(t *testing.T) {
	rows := []struct{ name, body, first string }{
		{"bare foo", `term { foo; }`, "foo"},
		{"then discard leaf", `term { then discard; }`, "then"},
		{"empty container", `term { }`, ""},
		{"nested then discard", `term { T then discard { } }`, "T"},
		{"nested then accept", `term { T then accept { } }`, "T"},
		{"nested dest-port compact", `term { T from destination-port 22 { then { accept; } } }`, "T"},
		{"nested multi-key child", `term { T extra { then discard; } }`, "T"},
		{"is-fragment fused tail", `term { T from is-fragment { then { discard; } } }`, "T"},
		{"then discard block", `term { then discard { } }`, "then"},
		{"flat nested container", `term {
                foo;
            }`, "foo"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFirewallNamelessTermsAST12526(firewallNamelessASTTree12526(t, tc.body))
			if err == nil {
				t.Fatalf("pre-flatten AST accepted nameless term %q, want reject", tc.body)
			}
			for _, want := range []string{"firewall family inet", `filter "F"`, "nameless", "#10294", "#12092", "#12526", "give every term an explicit name"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %q, want substring %q", err, want)
				}
			}
			if tc.first != "" && !strings.Contains(err.Error(), `"`+tc.first+`"`) {
				t.Fatalf("error = %q, want first token %q", err, tc.first)
			}
		})
	}
}

func TestValidateFirewallNamelessTermsAST12526NamedControls(t *testing.T) {
	rows := []struct{ name, body string }{
		{"hier named", `term T { then discard; }`},
		{"packed named", `term T then discard;`},
		{"nested named", `term { T { then discard; } }`},
		{"flat explicit empty", `term last;`},
		{"flag only named", `term T { from is-fragment; then discard; }`},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateFirewallNamelessTermsAST12526(firewallNamelessASTTree12526(t, tc.body)); err != nil {
				t.Fatalf("named control rejected: %v", err)
			}
		})
	}
}

func TestValidateFirewallNamelessTermsAST12526FamiliesGroupsPacked(t *testing.T) {
	rows := []struct{ name, src, where string }{
		{"inet6", `firewall { family inet6 { filter F6 { term { foo; } } } }`, `firewall family inet6 filter "F6"`},
		{"filter-no-family", `firewall { filter F { term { foo; } } }`, `firewall filter "F"`},
		{"group body", `groups { g { firewall { family inet { filter F { term { foo; } } } } } }`, `firewall family inet filter "F"`},
		{"packed head", `firewall family inet filter F term { foo; }`, `firewall family inet filter "F"`},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFirewallNamelessTermsAST12526(hierTree(t, tc.src))
			if err == nil {
				t.Fatalf("accepted nameless term in %q", tc.src)
			}
			if !strings.Contains(err.Error(), "#12526") || !strings.HasPrefix(err.Error(), tc.where+" contains a nameless") {
				t.Fatalf("error = %q, want #12526 rejection at %s", err, tc.where)
			}
		})
	}
	t.Run("nil tree", func(t *testing.T) {
		if err := ValidateFirewallNamelessTermsAST12526(nil); err != nil {
			t.Fatalf("nil tree: %v", err)
		}
	})
}

// TestStrictCompileRejectsFirewallFilterNamelessTerms12777 is the #12777
// pre-walk regression: strict compilation must run the #12526 firewall AST
// validator from runPreWalkGates so nameless terms inside `firewall filter`
// (with or without a family wrapper) reject instead of silently compiling to
// a filter with zero terms. Covers the literal shapes from the issue plus
// packed/group-expanded variants the typed post-compile gate cannot see.
func TestStrictCompileRejectsFirewallFilterNamelessTerms12777(t *testing.T) {
	rows := []struct{ name, src, first string }{
		{"issue shape family-less discard", `firewall { filter { F term { then discard; } } }`, "then"},
		{"family inet discard", `firewall { family inet { filter F { term { then discard; } } } }`, "then"},
		{"family inet6 discard", `firewall { family inet6 { filter F6 { term { then discard; } } } }`, "then"},
		{"bare foo", `firewall { family inet { filter F { term { foo; } } } }`, "foo"},
		{"nested name discard", `firewall { family inet { filter F { term { T then discard { } } } } }`, "T"},
		{"packed head", `firewall family inet filter F term { foo; }`, "foo"},
		{"packed filter term", `firewall { family inet { filter F term { then discard; } } }`, "then"},
		{"apply-groups", "groups {\n  G {\n    firewall {\n      family inet {\n        filter F {\n          term { then discard; }\n        }\n      }\n    }\n  }\n}\nfirewall {\n  apply-groups G;\n}", "then"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(hierTree(t, tc.src))
			if err == nil {
				t.Fatalf("strict CompileConfig accepted nameless firewall term in %q (cfg=%+v), want #12777 reject", tc.src, cfg)
			}
			for _, want := range []string{"nameless", "#12526", "starting with " + `"` + tc.first + `"`} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %q, want substring %q", err, want)
				}
			}
		})
	}
}

// TestStrictCompileAcceptsNamedFirewallTerm12777 is the named control:
// wiring the strict gate must not reject correctly named terms.
func TestStrictCompileAcceptsNamedFirewallTerm12777(t *testing.T) {
	for _, src := range []string{
		`firewall { filter F { term deny { then discard; } } }`,
		`firewall { family inet { filter F { term deny { then discard; } } } }`,
		`firewall { family inet { filter F { term { deny { then discard; } } } } }`,
	} {
		cfg, err := CompileConfig(hierTree(t, src))
		if err != nil {
			t.Fatalf("named term %q rejected: %v", src, err)
		}
		if f := cfg.Firewall.FiltersInet["F"]; f == nil || len(f.Terms) != 1 || f.Terms[0].Name != "deny" {
			t.Fatalf("named term %q compiled to %+v, want one deny term", src, cfg.Firewall.FiltersInet)
		}
	}
}

// TestLenientCompileStillWarnsFirewallFilterNamelessTerm12777 pins the
// tolerant posture: the strict gate must stay off on CompileConfigLenient so
// persisted/peer-synced configs still boot with the #10294 warning.
func TestLenientCompileStillWarnsFirewallFilterNamelessTerm12777(t *testing.T) {
	cfg, err := CompileConfigLenient(hierTree(t, `firewall { filter F { term { then discard; } } }`))
	if err != nil {
		t.Fatalf("tolerant compile rejected nameless term: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"nameless", "#10294", "#12092", `"then"`} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("warnings = %q, want %q", warnings, want)
		}
	}
}
func TestCompileConfigLenientNamelessFirewallTermStillWarns12526(t *testing.T) {
	cfg, err := CompileConfigLenient(firewallNamelessASTTree12526(t, `term { T then discard { } }`))
	if err != nil {
		t.Fatalf("tolerant compile rejected nameless term: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"nameless", "#10294", "#12092", `"T"`} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("warnings = %q, want %q", warnings, want)
		}
	}
}

func TestCompileConfigLenientPackedNamelessFirewallTermWarns12526(t *testing.T) {
	// The packed-container issue shape on the tolerant path: the existing
	// lenient nameless warning fires and the term is neutralized (kept
	// inert), never silently enforced — the #1960 no-brick posture. The
	// strict/commit-check gate (#12777) owns refusal.
	cfg, err := CompileConfigLenient(hierTree(t, `firewall { filter F { term { then discard; } } }`))
	if err != nil {
		t.Fatalf("tolerant compile rejected nameless term: %v", err)
	}
	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "nameless") || !strings.Contains(warnings, "#10294") {
		t.Fatalf("tolerant packed nameless shape warnings = %q, want the nameless warning", cfg.Warnings)
	}
	f := cfg.Firewall.FiltersInet["F"]
	if f == nil || len(f.Terms) != 1 {
		t.Fatalf("tolerant packed nameless shape filter = %+v, want one neutralized term", f)
	}
}
