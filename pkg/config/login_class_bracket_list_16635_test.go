package config

import (
	"strings"
	"testing"
)

// #16635: a bracketed deny-commands / deny-configuration value list, or an
// unquoted [...] character class, passed strict commit and only its first
// token was enforced. The four regex leaves now carry scalar:true +
// allowEmptyValue:true, so validateScalarValueLeaf rejects any token beyond
// Keys[1] at SchemaValidate (strict commit) while the quoted-empty deny-all
// spelling still commits.
//
// FAIL-ON-REVERT: drop scalar:true from any of the four leaves in
// schema_system.go and the corresponding bracket / char-class / multi-token
// cell below is silently accepted (SchemaValidate nil) and goes RED.

var loginRegexLeaves16635 = []string{
	"allow-commands", "deny-commands", "allow-configuration", "deny-configuration",
}

func hierLogin16635(leaf, value string) string {
	return "system { login { class ops { permissions view; " + leaf + " " + value + "; } } }"
}

// TestLoginRegexBracketListRejected16635 covers the bracketed list and the
// unquoted character-class shapes, hierarchical and flat, for all four leaves.
func TestLoginRegexBracketListRejected16635(t *testing.T) {
	for _, leaf := range loginRegexLeaves16635 {
		t.Run(leaf+"/hier bracket quoted", func(t *testing.T) {
			tree, err := parseHier(t, hierLogin16635(leaf, `[ "a" "b" ]`))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			assertTrailingRejected16635(t, SchemaValidate(tree), leaf, "b")
		})
		t.Run(leaf+"/hier bracket unquoted charclass", func(t *testing.T) {
			tree, err := parseHier(t, hierLogin16635(leaf, `[rR]equest.*`))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			assertTrailingRejected16635(t, SchemaValidate(tree), leaf, "equest.*")
		})
		t.Run(leaf+"/hier multi-token", func(t *testing.T) {
			tree, err := parseHier(t, hierLogin16635(leaf, `"a" "b"`))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			assertTrailingRejected16635(t, SchemaValidate(tree), leaf, "b")
		})
		t.Run(leaf+"/flat bracket quoted", func(t *testing.T) {
			tree := buildSetTree3332(t,
				"set system login class ops permissions view",
				"set system login class ops "+leaf+` [ "a" "b" ]`,
			)
			assertTrailingRejected16635(t, SchemaValidate(tree), leaf, "b")
		})
		t.Run(leaf+"/flat bracket unquoted charclass", func(t *testing.T) {
			tree := buildSetTree3332(t,
				"set system login class ops permissions view",
				"set system login class ops "+leaf+` [rR]equest.*`,
			)
			assertTrailingRejected16635(t, SchemaValidate(tree), leaf, "equest.*")
		})
		t.Run(leaf+"/flat multi-token", func(t *testing.T) {
			tree := buildSetTree3332(t,
				"set system login class ops permissions view",
				"set system login class ops "+leaf+` a b`,
			)
			assertTrailingRejected16635(t, SchemaValidate(tree), leaf, "b")
		})
	}
}

func parseHier(t *testing.T, text string) (*ConfigTree, error) {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) != 0 {
		return nil, perrs[0]
	}
	return tree, nil
}

func assertTrailingRejected16635(t *testing.T, err error, leaf, trailing string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: bracket/multi-token value accepted by SchemaValidate; trailing token %q would be silently dropped (only first token enforced)", leaf, trailing)
	}
	if !strings.Contains(err.Error(), leaf) {
		t.Errorf("%s: error should name the leaf, got %v", leaf, err)
	}
	if !strings.Contains(err.Error(), trailing) {
		t.Errorf("%s: error should name the trailing token %q, got %v", leaf, trailing, err)
	}
}

// TestLoginRegexSingleValueControls16635: single-value, alternation and
// quoted-empty controls still commit through strict CompileConfig.
func TestLoginRegexSingleValueControls16635(t *testing.T) {
	for _, leaf := range loginRegexLeaves16635 {
		for _, tc := range []struct{ name, value string }{
			{"single", `"request system reboot"`},
			{"alternation", `"request system (reboot|zeroize)"`},
			{"quoted empty deny-all", `""`},
			{"valueless presence", ``},
		} {
			t.Run(leaf+"/"+tc.name+"/hier", func(t *testing.T) {
				text := hierLogin16635(leaf, tc.value)
				if tc.value == "" {
					text = "system { login { class ops { permissions view; " + leaf + "; } } }"
				}
				cfg, err := compileLogin6662(t, text)
				if err != nil {
					t.Fatalf("control %s=%s rejected: %v", leaf, tc.value, err)
				}
				_ = cfg
			})
			t.Run(leaf+"/"+tc.name+"/flat", func(t *testing.T) {
				cmd := "set system login class ops " + leaf
				if tc.value != "" {
					cmd += " " + tc.value
				}
				cfg, err := compileLogin6662FlatSet(t,
					"set system login class ops permissions view",
					cmd,
				)
				if err != nil {
					t.Fatalf("flat control %s=%s rejected: %v", leaf, tc.value, err)
				}
				_ = cfg
			})
		}
	}
	// Quoted-empty deny still records presence (deny-all semantics preserved).
	cfg, err := compileLogin6662(t, hierLogin16635("deny-commands", `""`))
	if err != nil {
		t.Fatalf("empty deny: %v", err)
	}
	lc := cfg.System.Login.Classes[0]
	if len(lc.DenyLeavesPresent) != 1 || lc.DenyLeavesPresent[0] != "deny-commands" {
		t.Fatalf("empty deny presence lost: %v", lc.DenyLeavesPresent)
	}
	if lc.DenyCommands != "" {
		t.Fatalf("empty deny value = %q, want empty", lc.DenyCommands)
	}
}
