package config_test

// Regression tests for #4895: `system login user <name>` was an untyped keyed
// instance with NO username validator. The daemon writes an
// /etc/sudoers.d/xpf-<name> NOPASSWD grant by formatting the raw config key
// directly into sudoers syntax, and the lexer decodes `\n` inside a quoted
// string into a literal newline — so a crafted username like
//
//	user "x\nnobody ALL=(ALL) NOPASSWD: ALL" class super-user
//
// injects a second, valid sudoers directive that passes visudo and is durably
// installed (unmodeled passwordless root).
//
// The fix adds a strict commit-check keyValidator (ValidateLoginUsername) on
// the login `user` container: a name must match a safe POSIX account shape
// (^[a-z_][a-z0-9_-]*$, <=32 chars). This test pins that gate.
//
// Fail-on-revert: strip keyValidator from the `user` node (or run against
// origin/master) and every "Rejects" case below stops erroring — that is the
// pre-fix silent-accept behaviour.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// --- ValidateLoginUsername unit table -----------------------------------

func TestValidateLoginUsername_Table(t *testing.T) {
	valid := []string{"admin", "netadmin", "user1", "read_only", "a", "_svc", "op-2", strings.Repeat("a", 32)}
	for _, name := range valid {
		if err := config.ValidateLoginUsername(name); err != nil {
			t.Errorf("ValidateLoginUsername(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{
		"",                                  // empty
		"x\nnobody ALL=(ALL) NOPASSWD: ALL", // #4895 embedded-newline injection
		"has space",                         // whitespace
		"has\ttab",                          // tab
		"-leadinghyphen",                    // leading hyphen (getopt hazard)
		"UPPER",                             // uppercase (outside the safe POSIX shape)
		"a/b",                               // slash (path/sudoers metachar)
		"a:b",                               // colon
		"a,b",                               // comma (sudoers list separator)
		"a=b",                               // equals (sudoers directive)
		"a b ALL=(ALL) NOPASSWD: ALL",       // space-injection
		"9leadingdigit",                     // must start with letter/underscore
		strings.Repeat("a", 33),             // over the length cap
	}
	for _, name := range invalid {
		if err := config.ValidateLoginUsername(name); err == nil {
			t.Errorf("ValidateLoginUsername(%q) = nil, want error", name)
		}
	}
}

// --- Commit-check gate: hierarchical (imported Junos) shape -------------

// The `\n` in the raw string below is literally backslash-n; the lexer decodes
// it to a newline, reproducing the injection key exactly.
func TestSchema4895_LoginUsername_RejectsNewlineInjection_Hierarchical(t *testing.T) {
	err := schemaCheck(t, `system {
    login {
        user "x\nnobody ALL=(ALL) NOPASSWD: ALL" {
            class super-user;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for login user name with embedded newline, got nil (sudoers injection would be accepted)")
	}
}

func TestSchema4895_LoginUsername_RejectsMetachar_Hierarchical(t *testing.T) {
	err := schemaCheck(t, `system {
    login {
        user "bad name" {
            class super-user;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for login user name with whitespace, got nil")
	}
}

// A normal username must still commit clean.
func TestSchema4895_LoginUsername_AcceptsNormal_Hierarchical(t *testing.T) {
	if err := schemaCheck(t, `system {
    login {
        user admin {
            class super-user;
        }
    }
}`); err != nil {
		t.Fatalf("normal login user name rejected: %v", err)
	}
}

// --- Commit-check gate: flat-set shape ----------------------------------

func TestSchema4895_LoginUsername_RejectsNewlineInjection_FlatSet(t *testing.T) {
	err := flatSchemaCheck(t,
		`set system login user "x\nnobody ALL=(ALL) NOPASSWD: ALL" class super-user`)
	if err == nil {
		t.Fatal("expected error for flat-set login user name with embedded newline, got nil")
	}
}

func TestSchema4895_LoginUsername_AcceptsNormal_FlatSet(t *testing.T) {
	if err := flatSchemaCheck(t,
		`set system login user admin class super-user`); err != nil {
		t.Fatalf("normal flat-set login user name rejected: %v", err)
	}
}
