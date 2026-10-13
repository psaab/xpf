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
	rows := []struct{ name, src, family string }{
		{"inet6", `firewall { family inet6 { filter F6 { term { foo; } } } }`, "inet6"},
		{"filter-no-family", `firewall { filter F { term { foo; } } }`, ""},
		{"group body", `groups { g { firewall { family inet { filter F { term { foo; } } } } } }`, "inet"},
		{"packed head", `firewall family inet filter F term { foo; }`, "inet"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFirewallNamelessTermsAST12526(hierTree(t, tc.src))
			if err == nil {
				t.Fatalf("accepted nameless term in %q", tc.src)
			}
			if !strings.Contains(err.Error(), "#12526") || !strings.Contains(err.Error(), "family "+tc.family) {
				t.Fatalf("error = %q, want #12526 family %q", err, tc.family)
			}
		})
	}
	t.Run("nil tree", func(t *testing.T) {
		if err := ValidateFirewallNamelessTermsAST12526(nil); err != nil {
			t.Fatalf("nil tree: %v", err)
		}
	})
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
