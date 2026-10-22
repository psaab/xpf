package config

import (
	"strings"
	"testing"
)

// #7971. Before this file the four `*-regexps` login-class leaves were ACCEPTED
// and silently discarded, while `docs/system-login.md` told operators the
// opposite — that they are "rejected at commit as an unknown leaf rather than
// accepted and ignored — the safe posture for a control that is not
// implemented".
//
// The doc's inference is the part that was wrong. `closedWorld` is opt-in per
// subtree and `system login class` does not set it, so an unmodeled keyword is
// left to the compiler, which drops it. Absence of a schema leaf produces
// silent acceptance, not rejection.
//
// Measured on the real commit path before the fix, with the supported
// `deny-commands` as the accept-side control:
//
//	deny-commands-regexps "^set system"  -> SchemaValidate ACCEPT, nothing retained
//	deny-commands         "^set system"  -> SchemaValidate ACCEPT, DenyCommands retained
//
// Both committed clean; only one did anything. For an access control that is
// the fail-OPEN direction — the operator writes a restriction, sees success,
// and is not restricted.

func loginRegexpsTree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range cmds {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	return tree
}

// Every leaf in the family must be refused at strict commit.
//
// RED on revert: drop the four entries from `setSchema` (or set their
// `valueType` back to the ValueAny zero value, which leaves the validator
// uninvoked) and each case returns nil here — the exact silent-accept this
// change closes.
func TestRegexpsFamilyIsRejectedAtCommit_7971(t *testing.T) {
	for _, leaf := range []string{
		"allow-commands-regexps",
		"deny-commands-regexps",
		"allow-configuration-regexps",
		"deny-configuration-regexps",
	} {
		t.Run(leaf, func(t *testing.T) {
			tree := loginRegexpsTree(t,
				"set system login class limited permissions view",
				`set system login class limited `+leaf+` "^set system"`)
			err := SchemaValidate(tree)
			if err == nil {
				t.Fatalf("%s committed clean. An unimplemented ACCESS CONTROL that "+
					"accepts and discards is fail-open: the operator authors a "+
					"restriction, sees success, and is not restricted", leaf)
			}
			msg := err.Error()
			// The refusal has to be actionable, not merely present. An operator
			// hitting it is following Juniper's documentation and needs to know
			// which family this box implements.
			if !strings.Contains(msg, leaf) {
				t.Errorf("refusal does not name the leaf %q: %s", leaf, msg)
			}
			if !strings.Contains(msg, "#7971") {
				t.Errorf("refusal does not carry the issue reference: %s", msg)
			}
			if want := plainRegexpsCounterpart(leaf); !strings.Contains(msg, want) {
				t.Errorf("refusal does not name the supported alternative %q: %s", want, msg)
			}
		})
	}
}

// THE ACCEPT-SIDE CONTROL. A gate that rejects everything passes every
// rejection test, so the plain family must still commit — otherwise this change
// has broken the family xpf does implement rather than refusing the one it does
// not.
//
// It also pins the DISCRIMINATOR the fix rests on: the two families differ by a
// suffix, and the schema keys on the whole leaf name.
func TestPlainLoginRegexFamilyStillCommits_7971(t *testing.T) {
	for _, leaf := range []string{
		"allow-commands",
		"deny-commands",
		"allow-configuration",
		"deny-configuration",
	} {
		t.Run(leaf, func(t *testing.T) {
			tree := loginRegexpsTree(t,
				"set system login class limited permissions view",
				`set system login class limited `+leaf+` "^set system"`)
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("the SUPPORTED %s must still commit, got: %v", leaf, err)
			}
		})
	}
}

// And the value must still reach the compiler for the supported family — a
// schema that accepts but a compiler that drops would be the same fail-open in
// a different layer, which is precisely the shape this issue is about.
func TestPlainDenyCommandsStillReachesTheCompiler_7971(t *testing.T) {
	tree := loginRegexpsTree(t,
		"set system login class limited permissions view",
		`set system login class limited deny-commands "^set system"`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.Login == nil {
		t.Fatal("premise broken: no login config compiled")
	}
	for _, cl := range cfg.System.Login.Classes {
		if cl != nil && cl.Name == "limited" {
			if cl.DenyCommands != "^set system" {
				t.Errorf("DenyCommands = %q, want %q — the supported family must be "+
					"retained, not merely accepted", cl.DenyCommands, "^set system")
			}
			return
		}
	}
	t.Fatal("login class \"limited\" not found in the compiled config")
}
