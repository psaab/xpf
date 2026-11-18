package config

import (
	"strings"
	"testing"
)

// #6972 asked whether a content-free `system login` stanza should deny, permit,
// or be rejected at commit.
//
// The disposition is DENY, unchanged. An RBAC stanza that resolves to no
// authorization must not resolve to "everything", and the alternative is a
// fail-OPEN on the authorization surface reachable from a half-finished stanza
// or a `load merge` that lost a body.
//
// What was wrong is that the denial was invisible: all four content-free
// spellings commit clean with zero warnings, so an operator sees a successful
// commit and discovers at the next login that every non-root command is
// refused. That lockout is the defect, not the denial.
func TestContentFreeSystemLoginWarns_6972(t *testing.T) {
	for _, src := range []string{
		"system { login; }",
		"system login;",
		"system { login user; }",
		"system login user;",
	} {
		t.Run(src, func(t *testing.T) {
			cfg := compileHier6972(t, src)
			if !hasWarning6972(ValidateConfig(cfg), "names no user and no class") {
				t.Errorf("a content-free `system login` drew no warning; it denies every non-root "+
					"CLI command and commits clean (#6972). warnings=%v", ValidateConfig(cfg))
			}
		})
	}
}

// The other polarity, and the reason the warning cannot simply fire on the
// presence of the stanza: a login stanza that DOES grant something must stay
// silent, or the warning becomes noise on every correctly configured box and is
// filtered out before it is ever read.
func TestGrantingSystemLoginDoesNotWarn_6972(t *testing.T) {
	for _, src := range []string{
		// #15717 (8b8ed41b9c) rejects a user whose class is not defined, so
		// the granting user names a class the same stanza defines (#18847).
		"system { login { class ops { permissions view; } user alice { class ops; } } }",
		"system { login { class ops { permissions view; } } }",
	} {
		t.Run(src, func(t *testing.T) {
			cfg := compileHier6972(t, src)
			if hasWarning6972(ValidateConfig(cfg), "names no user and no class") {
				t.Errorf("a login stanza that grants access drew the content-free warning; "+
					"warnings=%v", ValidateConfig(cfg))
			}
		})
	}
}

// And a config with NO login stanza at all must stay silent — otherwise the
// warning fires on every box that has never configured RBAC, which is the
// majority, and says nothing about them.
func TestNoSystemLoginStanzaDoesNotWarn_6972(t *testing.T) {
	cfg := compileHier6972(t, "system { host-name fw; }")
	if hasWarning6972(ValidateConfig(cfg), "names no user and no class") {
		t.Errorf("a config with no `system login` stanza drew the content-free warning; "+
			"warnings=%v", ValidateConfig(cfg))
	}
}

// The disposition itself, pinned so a later change cannot quietly flip deny to
// permit while leaving the warning in place. #6972's whole question was which
// of the three outcomes is right; recording the answer as an assertion rather
// than as prose is what makes the decision durable.
//
// Both spellings reach the denial by DIFFERENT mechanisms — the nested one
// compiles a non-nil empty LoginConfig and ResolveLoginClass returns
// ClassUnidentified; the packed one compiles nil and denies via the
// LoginDroppedByPacking flag — so both are asserted rather than one standing in
// for the other.
func TestContentFreeSystemLoginStillDenies_6972(t *testing.T) {
	t.Run("nested: empty LoginConfig, flag irrelevant", func(t *testing.T) {
		cfg := compileHier6972(t, "system { login; }")
		if cfg.System.Login == nil {
			t.Fatal("fixture is wrong: the nested spelling must compile a non-nil LoginConfig, " +
				"or it is exercising the packed mechanism instead")
		}
		if len(cfg.System.Login.Users) != 0 || len(cfg.System.Login.Classes) != 0 {
			t.Fatalf("fixture is wrong: the stanza names somebody (users=%d classes=%d)",
				len(cfg.System.Login.Users), len(cfg.System.Login.Classes))
		}
	})
	t.Run("packed: nil Login, denial carried by the flag", func(t *testing.T) {
		cfg := compileHier6972(t, "system login;")
		if cfg.System.Login != nil {
			t.Fatal("fixture is wrong: the packed spelling must compile a nil Login, or it is " +
				"exercising the nested mechanism instead")
		}
		if !cfg.System.LoginDroppedByPacking {
			t.Error("the packed content-free stanza did not set LoginDroppedByPacking, so nothing " +
				"carries the denial and the CLI would run with an unset class (#6706 r11)")
		}
	})
}

func compileHier6972(t *testing.T, src string) *Config {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", src, errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig(%q): %v", src, err)
	}
	return cfg
}

func hasWarning6972(warnings []string, needle string) bool {
	for _, w := range warnings {
		if strings.Contains(w, needle) {
			return true
		}
	}
	return false
}
