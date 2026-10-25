package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16635: bracketed / multi-token login-class regex values must be rejected
// by the real operator gates (CheckText and Store.Commit), not only by
// pkg/config SchemaValidate, and must warn (not brick) on tolerant load.

var loginLeaves16635 = []string{
	"allow-commands", "deny-commands", "allow-configuration", "deny-configuration",
}

func hierBracket16635(leaf string) string {
	return "system { login { class ops { permissions view; " + leaf + ` [ "a" "b" ]; } } }`
}

func TestCheckTextRejectsLoginRegexBracket16635(t *testing.T) {
	for _, leaf := range loginLeaves16635 {
		t.Run(leaf+"/bracket", func(t *testing.T) {
			_, err := CheckText(hierBracket16635(leaf), -1)
			if err == nil {
				t.Fatalf("CheckText accepted bracketed %s list; only first token would be enforced", leaf)
			}
			if !strings.Contains(err.Error(), leaf) || !strings.Contains(err.Error(), "b") {
				t.Errorf("CheckText error should name leaf and trailing token, got %v", err)
			}
		})
		t.Run(leaf+"/charclass", func(t *testing.T) {
			text := "system { login { class ops { permissions view; " + leaf + " [rR]equest.*; } } }"
			_, err := CheckText(text, -1)
			if err == nil {
				t.Fatalf("CheckText accepted unquoted char-class %s; only first token would be enforced", leaf)
			}
			if !strings.Contains(err.Error(), "equest.*") {
				t.Errorf("CheckText error should name trailing token, got %v", err)
			}
		})
	}
	// Controls still pass CheckText.
	for _, text := range []string{
		`system { login { class ops { permissions view; deny-commands "request system reboot"; } } }`,
		`system { login { class ops { permissions view; deny-commands "request system (reboot|zeroize)"; } } }`,
		`system { login { class ops { permissions view; deny-commands ""; } } }`,
		`system { login { class ops { permissions view; deny-commands; } } }`,
	} {
		if _, err := CheckText(text, -1); err != nil {
			t.Errorf("CheckText rejected control %q: %v", text, err)
		}
	}
}

func TestStoreCommitRejectsLoginRegexBracket16635(t *testing.T) {
	for _, leaf := range loginLeaves16635 {
		t.Run(leaf, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := s.SetFromInput("system login class ops permissions view"); err != nil {
				t.Fatalf("SetFromInput permissions: %v", err)
			}
			if err := s.SetFromInput(`system login class ops ` + leaf + ` [ "a" "b" ]`); err != nil {
				t.Fatalf("SetFromInput bracket: %v", err)
			}
			if _, err := s.CommitCheck(); err == nil {
				t.Fatalf("CommitCheck accepted bracketed %s list", leaf)
			} else if !strings.Contains(err.Error(), "b") {
				t.Errorf("CommitCheck error should name trailing token, got %v", err)
			}
			if _, err := s.Commit(); err == nil {
				t.Fatalf("Commit accepted bracketed %s list; only first token would be enforced", leaf)
			}
		})
	}
}

// TestTolerantLoadWarnsLoginRegexBracket16635: a persisted bracketed value
// boots on the tolerant path (#1960) with a warning naming the trailing token.
func TestTolerantLoadWarnsLoginRegexBracket16635(t *testing.T) {
	text := hierBracket16635("deny-commands")
	p := config.NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	buf := captureWarnLogs(t)
	s := newTestStore(t)
	cfg, err := s.compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load bricked on bracketed deny-commands (#1960): %v", err)
	}
	logs := buf.String()
	if !strings.Contains(logs, "deny-commands") || !strings.Contains(logs, "trailing token") {
		t.Fatalf("tolerant load should warn naming leaf and trailing token, logs=%q warnings=%v", logs, cfg.Warnings)
	}
	if cfg.System.Login.Classes[0].DenyCommands != "a" {
		t.Fatalf("tolerant deny=%q, want first token a retained", cfg.System.Login.Classes[0].DenyCommands)
	}
}
