package config

import (
	"strings"
	"testing"
)

// #8858: `system root-authentication` lost its whole stanza when the container
// brace was elided. The consequence is not a dropped field but a LOCKOUT:
// applyRootAuth (pkg/daemon/daemon_hostauth_apply.go) reads a nil stanza as
// "root-authentication not configured" and revokes the credentials xpf
// provisioned, D2-locking root (#5276). The operator authors a password, the
// commit succeeds, `show configuration` echoes it back, and root is locked.
//
// It fails CLOSED, so this is an availability hazard rather than a breach.
//
// TWO folds were needed, and admitting only one moves nothing:
//
//	system -> root-authentication          (the outer pair)
//	root-authentication -> <credential>    (the inner pairs)
//
// plus packedStatements on the container, because SSHKeys is a []string and a
// packed multi-key run otherwise folds into ONE key. The password-only fixture
// passes with that bug present, which is why the two-key arm below is not
// decoration.
//
// WHAT THIS DOES NOT FIX, so it is not rediscovered as a regression here:
// SchemaValidate walks the UN-NORMALIZED tree, so the packed spelling still
// reaches commit unvalidated -- `encrypted-password "hunter2"` is rejected
// braced and accepted packed. That gap is general to every admitted pair (the
// same asymmetry is measurable on `system name-server`, admitted long before
// this change) and is filed as issue 8867. Making the value COMPILE is what
// made the missing validation observable; before it there was nothing to
// validate.

const (
	rootAuthHash8858 = "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	rootAuthKey1     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfirst a@b"
	rootAuthKey2     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKsecond c@d"
)

// rootAuthSpellings8858 is the depth axis. d1 is the fully braced reference and
// the control that must keep working; d2 is what `show configuration system
// root-authentication` emits; d3 is the fully packed statement.
func rootAuthSpellings8858(body string) map[string]string {
	return map[string]string{
		"d1-braced":        "system {\n root-authentication {\n  " + body + "\n }\n}",
		"d2-stanza-elided": "system root-authentication {\n " + body + "\n}",
		// The packed spelling is ONE statement, so the body's internal
		// separators are dropped rather than kept: leaving them in produces a
		// second TOP-LEVEL statement, which parses and then measures nothing.
		"d3-fully-elided": "system root-authentication " +
			strings.TrimSuffix(strings.TrimSpace(strings.ReplaceAll(body, "; ", " ")), ";") + ";",
	}
}

func compileRootAuth8858(t *testing.T, text string) (*RootAuthConfig, *Config) {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse error for %q: %v", text, perrs[0])
	}
	// The tolerant path is the Store.Load / SyncApply ingress and the one the
	// lockout travels on.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile failed for %q: %v", text, err)
	}
	// The STRICT path must accept it too: a spelling that only survives the
	// tolerant path is still broken at commit.
	tree2, _ := NewParser(text).Parse()
	if _, serr := compileConfigWithOpts(tree2, compileOpts{}); serr != nil {
		t.Errorf("strict compile REJECTED %q: %v", text, serr)
	}
	return cfg.System.RootAuthentication, cfg
}

func TestRootAuthenticationSurvivesBraceElision8858(t *testing.T) {
	t.Run("encrypted-password", func(t *testing.T) {
		for name, text := range rootAuthSpellings8858(`encrypted-password "` + rootAuthHash8858 + `";`) {
			ra, _ := compileRootAuth8858(t, text)
			if ra == nil {
				t.Fatalf("%s: RootAuthentication is nil — applyRootAuth would REVOKE root's credentials", name)
			}
			if got := ra.EncryptedPassword.Reveal(); got != rootAuthHash8858 {
				t.Errorf("%s: EncryptedPassword = %q, want %q", name, got, rootAuthHash8858)
			}
		}
	})

	// SSHKeys is a []string. A fold that keeps only the first key satisfies
	// every single-key fixture, so the count is asserted as well as the values.
	t.Run("two ssh keys", func(t *testing.T) {
		body := `ssh-ed25519 "` + rootAuthKey1 + `"; ssh-ed25519 "` + rootAuthKey2 + `";`
		for name, text := range rootAuthSpellings8858(body) {
			ra, _ := compileRootAuth8858(t, text)
			if ra == nil {
				t.Fatalf("%s: RootAuthentication is nil", name)
			}
			if len(ra.SSHKeys) != 2 {
				t.Fatalf("%s: got %d SSH keys, want 2 (%v) — a packed run folding to one key locks out the second operator", name, len(ra.SSHKeys), ra.SSHKeys)
			}
			for i, want := range []string{rootAuthKey1, rootAuthKey2} {
				if ra.SSHKeys[i] != want {
					t.Errorf("%s: SSHKeys[%d] = %q, want %q", name, i, ra.SSHKeys[i], want)
				}
			}
		}
	})

	// LIVENESS. Both arms above compare against a constant, so they cannot pass
	// vacuously — but the braced reference is the thing the other two are held
	// to, and if IT ever stopped carrying a value the suite would still be
	// green while measuring nothing. Assert the reference is live.
	t.Run("braced reference is live", func(t *testing.T) {
		ra, _ := compileRootAuth8858(t, "system {\n root-authentication {\n  encrypted-password \""+rootAuthHash8858+"\";\n  ssh-ed25519 \""+rootAuthKey1+"\";\n }\n}")
		if ra == nil || ra.EncryptedPassword.Reveal() == "" || len(ra.SSHKeys) == 0 {
			t.Fatalf("braced reference carries nothing (%+v) — every comparison against it is vacuous", ra)
		}
	})
}

// The flat-set spelling is the other ingress and must agree. Per CLAUDE.md this
// uses ParseSetCommand + SetPath, never NewParser, which merges set lines.
//
// SCOPE: one key, not two. A second `set ... ssh-ed25519` REPLACES the first on
// this path -- measured on master before this change, so it is neither caused
// nor fixed here. That is a different mechanism (the leaf lacks `multi: true`;
// `name-server` has it and accumulates) and it is filed as issue 8863. Asserting
// two keys here would red this cell on an unrelated pre-existing defect.
func TestRootAuthenticationFlatSetAgrees8858(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		`set system root-authentication encrypted-password "` + rootAuthHash8858 + `"`,
		`set system root-authentication ssh-ed25519 "` + rootAuthKey1 + `"`,
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ra := cfg.System.RootAuthentication
	if ra == nil {
		t.Fatal("flat-set root-authentication compiled to nil")
	}
	if ra.EncryptedPassword.Reveal() != rootAuthHash8858 {
		t.Errorf("flat-set password = %q, want %q", ra.EncryptedPassword.Reveal(), rootAuthHash8858)
	}
	if len(ra.SSHKeys) != 1 || ra.SSHKeys[0] != rootAuthKey1 {
		t.Errorf("flat-set SSH keys = %v, want exactly [%q]", ra.SSHKeys, rootAuthKey1)
	}
}
