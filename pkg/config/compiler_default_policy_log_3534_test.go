package config

import (
	"strings"
	"testing"
)

// buildDefaultPolicyLogTree parses flat set commands via the ParseSetCommand +
// SetPath loop the CLI uses (NewParser merges newline-separated set lines into
// one node and must not be used for set syntax — see CLAUDE.md "Testing flat
// set syntax").
func buildDefaultPolicyLogTree(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestDefaultPolicyLogCompiles is the #3534 fail-on-revert guard for the config
// compile path: `set security policies default-policy-log session-init/
// session-close` must set SecurityConfig.DefaultPolicyLogSessionInit/Close.
// Reverting the compilePolicies `default-policy-log` case drops the flags and
// this test goes RED.
func TestDefaultPolicyLogCompiles(t *testing.T) {
	cases := []struct {
		name      string
		cmds      []string
		wantInit  bool
		wantClose bool
	}{
		{
			name: "both",
			cmds: []string{
				"set security policies default-policy permit-all",
				"set security policies default-policy-log session-init",
				"set security policies default-policy-log session-close",
			},
			wantInit:  true,
			wantClose: true,
		},
		{
			name: "init-only",
			cmds: []string{
				"set security policies default-policy permit-all",
				"set security policies default-policy-log session-init",
			},
			wantInit:  true,
			wantClose: false,
		},
		{
			name: "close-only",
			cmds: []string{
				"set security policies default-policy permit-all",
				"set security policies default-policy-log session-close",
			},
			wantInit:  false,
			wantClose: true,
		},
		{
			name: "none",
			cmds: []string{
				"set security policies default-policy permit-all",
			},
			wantInit:  false,
			wantClose: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildDefaultPolicyLogTree(t, tc.cmds)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			if got := cfg.Security.DefaultPolicyLogSessionInit; got != tc.wantInit {
				t.Errorf("DefaultPolicyLogSessionInit = %v, want %v", got, tc.wantInit)
			}
			if got := cfg.Security.DefaultPolicyLogSessionClose; got != tc.wantClose {
				t.Errorf("DefaultPolicyLogSessionClose = %v, want %v", got, tc.wantClose)
			}
		})
	}
}

// TestDefaultPolicyLogSchemaValidates confirms the new sibling leaf is known to
// the config-mode schema (commit-check): a valid flag passes SchemaValidate,
// and a bogus sub-token is NOT silently grouped onto an enum value (the whole
// point of the sibling-leaf shape — the `default-policy` enum leaf is untouched
// and still rejects bogus values).
func TestDefaultPolicyLogSchemaValidates(t *testing.T) {
	for _, flag := range []string{"session-init", "session-close"} {
		tree := buildDefaultPolicyLogTree(t, []string{
			"set interfaces eth0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone trust interfaces eth0",
			"set security policies default-policy permit-all",
			"set security policies default-policy-log " + flag,
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig(%q): %v", flag, err)
		}
		if err := SchemaValidate(tree); err != nil {
			t.Errorf("SchemaValidate rejected valid default-policy-log %q: %v", flag, err)
		}
	}
	// The action enum leaf is unchanged: a bogus default-policy value is still
	// rejected (sibling-leaf shape preserves the #3065 enum guard).
	bogus := buildDefaultPolicyLogTree(t, []string{
		"set security policies default-policy allow-everything",
	})
	if err := SchemaValidate(bogus); err == nil {
		t.Errorf("SchemaValidate accepted bogus default-policy value (enum guard regressed)")
	}
}

// TestDefaultPolicyLogInertUnderDenyWarns proves the #3534 honesty warning: a
// default-policy-log selection with a default-DENY/REJECT verdict is inert (no
// session is installed for a session-init/close record to fire on), so commit
// emits a WARNING naming the configured modes. Fail-on-revert: deleting the
// validateDefaultPolicyLogWarnings call (or the append) removes the warning.
func TestDefaultPolicyLogInertUnderDenyWarns(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action string
	}{
		{"deny", "deny-all"},
		{"reject", "reject-all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildDefaultPolicyLogTree(t, []string{
				"set security policies default-policy " + tc.action,
				"set security policies default-policy-log session-init",
				"set security policies default-policy-log session-close",
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			var got string
			for _, w := range ValidateConfig(cfg) {
				if strings.Contains(w, "default-policy-log") && strings.Contains(w, "inert") {
					got = w
					break
				}
			}
			if got == "" {
				t.Fatalf("expected a default-policy-log inert warning under %s, got: %v",
					tc.action, ValidateConfig(cfg))
			}
			for _, want := range []string{"session-init", "session-close", "permit-all"} {
				if !strings.Contains(got, want) {
					t.Errorf("warning %q missing substring %q", got, want)
				}
			}
		})
	}
}

// TestDefaultPolicyLogPermitNoWarn confirms the warning is gated on the verdict:
// under default-policy permit-all the session-init/close records DO fire, so no
// inert warning is emitted.
func TestDefaultPolicyLogPermitNoWarn(t *testing.T) {
	tree := buildDefaultPolicyLogTree(t, []string{
		"set security policies default-policy permit-all",
		"set security policies default-policy-log session-init",
		"set security policies default-policy-log session-close",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "default-policy-log") {
			t.Fatalf("unexpected default-policy-log warning under permit-all: %q", w)
		}
	}
}
