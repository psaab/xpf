package config

import (
	"strings"
	"testing"
)

// #5636 (codex-review-181 M28): a quoted-empty Basic secret (`password ""`) or
// empty api-key (`api-key ""`) parses as a real api-auth credential row. Before
// the fix the compiler stored it, the off-loopback #4047 gate counted it as a
// valid auth method (so the bind was accepted), daemon_run.go wired the empty
// secret, and the middleware authenticated a request presenting `username:`
// (empty password) or an empty Bearer/X-API-Key token — an authentication
// bypass on an off-loopback bind. An empty secret is never a valid credential,
// so the compiler must reject it at strict commit (and warn on the lenient
// load / peer-sync path).

// build5636Tree applies flat `set` commands via ParseSetCommand (the
// CLAUDE.md-mandated path — strings.Fields cannot tokenize a quoted-empty
// `""` value, whereas the lexer yields an empty-string value token).
func build5636Tree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	return tree
}

// RED-on-revert: an off-loopback HTTP bind whose ONLY api-auth credential is an
// empty Basic password must be REJECTED at strict commit. On revert of the
// #5636 fix this goes GREEN-with-nil-error — the empty-password user counts as
// a valid auth method, the config commits, and the daemon binds the API
// off-loopback while authenticating `admin:` with no password.
func TestAPIAuthEmptyBasicPasswordOffLoopbackRejected(t *testing.T) {
	tree := build5636Tree(t,
		"set system services web-management http interface fxp0.0",
		`set system services web-management api-auth user admin password ""`,
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of an off-loopback bind whose only credential is an empty Basic password, got nil")
	}
	// The precise empty-secret diagnosis (#5636) must win over the generic
	// #4047 "no api-auth" message.
	if !strings.Contains(err.Error(), "#5636") || !strings.Contains(err.Error(), "empty password") {
		t.Fatalf("expected an empty-password #5636 rejection, got: %v", err)
	}
}

// An empty Basic password is never a valid credential — reject it even on the
// safe loopback (default) bind, so it can never become an active credential.
func TestAPIAuthEmptyBasicPasswordLoopbackRejected(t *testing.T) {
	tree := build5636Tree(t,
		`set system services web-management http`,
		`set system services web-management api-auth user admin password ""`,
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of an empty Basic password on a loopback bind, got nil")
	}
	if !strings.Contains(err.Error(), "#5636") || !strings.Contains(err.Error(), "empty password") {
		t.Fatalf("expected an empty-password #5636 rejection, got: %v", err)
	}
}

// An empty api-key is likewise rejected.
func TestAPIAuthEmptyAPIKeyRejected(t *testing.T) {
	tree := build5636Tree(t,
		"set system services web-management http interface fxp0.0",
		`set system services web-management api-auth api-key ""`,
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of an empty api-key, got nil")
	}
	if !strings.Contains(err.Error(), "#5636") || !strings.Contains(err.Error(), "empty api-key") {
		t.Fatalf("expected an empty-api-key #5636 rejection, got: %v", err)
	}
}

// A compliant Basic password commits when API credentials are served only over HTTPS.
func TestAPIAuthNonEmptyBasicPasswordHTTPSCommits(t *testing.T) {
	tree := build5636Tree(t,
		"set system services web-management https system-generated-certificate",
		"set system services web-management https interface fxp0.0",
		"set system services web-management api-auth expires 2099-01-01",
		"set system services web-management api-auth user admin password correct-horse-battery",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig: HTTPS + compliant Basic password must commit, got: %v", err)
	}
}

// A mixed stanza — one empty and one usable credential — is still rejected at
// strict commit: the empty secret must never survive, even alongside a valid
// one.
func TestAPIAuthMixedEmptyAndUsableRejected(t *testing.T) {
	tree := build5636Tree(t,
		"set system services web-management http interface fxp0.0",
		"set system services web-management api-auth expires 2099-01-01",
		"set system services web-management api-auth user good password correct-horse-battery",
		`set system services web-management api-auth user bad password ""`,
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of a stanza containing an empty Basic password alongside a usable one, got nil")
	}
	if !strings.Contains(err.Error(), "#5636") {
		t.Fatalf("expected an empty-secret #5636 rejection, got: %v", err)
	}
}

// Lenient (load / peer-sync): an empty Basic password downgrades to a warning
// so an already-persisted config still boots (#1960). The runtime wiring and
// middleware independently neutralize the empty credential.
func TestAPIAuthEmptyBasicPasswordLenientWarns(t *testing.T) {
	tree := build5636Tree(t,
		"set system services web-management http interface fxp0.0",
		`set system services web-management api-auth user admin password ""`,
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: empty Basic password must downgrade to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "api-auth") && strings.Contains(w, "#5636") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #5636 empty-secret warning on the lenient path, got: %v", cfg.Warnings)
	}
}
