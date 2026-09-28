package config

import (
	"strings"
	"testing"
)

// #4047 (fable-161 F-155): the REST / config API (pkg/api) serves the mutating
// config endpoints (set / commit / rollback / system action) with NO auth
// middleware unless `system services web-management api-auth` is configured. The
// default bind is loopback (safe), but a `web-management http|https interface
// <mgmt-if>` stanza binds the API to a routable address — off-loopback WITHOUT
// api-auth exposes every mutating RPC to the network. validateWebManagementAuthStrict
// hard-rejects such a config at strict commit and warns on the tolerant load path.

// buildTreeFromSets applies flat `set` commands (the CLAUDE.md-mandated way to
// test set syntax — NewParser merges newline-separated set lines).
func buildTreeFromSets(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// RED-on-revert: an HTTP web-management bind to a non-loopback interface with no
// api-auth must be REJECTED at strict commit. On revert of the #4047 gate this
// goes RED — the config commits and the daemon binds the unauthenticated REST
// API off-loopback.
func TestWebManagementHTTPOffLoopbackNoAuthRejected(t *testing.T) {
	tree := buildTreeFromSets(t, "set system services web-management http interface fxp0.0")

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of an off-loopback HTTP bind with no api-auth, got nil")
	}
	if !strings.Contains(err.Error(), "web-management") || !strings.Contains(err.Error(), "api-auth") ||
		!strings.Contains(err.Error(), "#4047") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// HTTPS is covered too — transport encryption without authentication still lets
// any reachable client mutate config.
func TestWebManagementHTTPSOffLoopbackNoAuthRejected(t *testing.T) {
	tree := buildTreeFromSets(t,
		"set system services web-management https interface fxp0.0",
		"set system services web-management https system-generated-certificate")

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of an off-loopback HTTPS bind with no api-auth, got nil")
	}
	if !strings.Contains(err.Error(), "https interface") || !strings.Contains(err.Error(), "#4047") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// An off-loopback HTTPS bind WITH a scoped, expiring Basic identity commits.
func TestWebManagementOffLoopbackWithUserAuthCommits(t *testing.T) {
	tree := buildTreeFromSets(t,
		"set system services web-management https interface fxp0.0",
		"set system services web-management api-auth user admin password correct-horse-battery",
		"set system services web-management api-auth user admin class read-only",
		"set system services web-management api-auth user admin expires 2099-01-01")

	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig: off-loopback HTTPS + scoped auth must commit, got error: %v", err)
	}
}

// Legacy API keys inherit an explicit expiry and the read-only default class.
func TestWebManagementOffLoopbackWithAPIKeyCommits(t *testing.T) {
	tree := buildTreeFromSets(t,
		"set system services web-management https interface fxp0.0",
		"set system services web-management api-auth expires 2099-01-01",
		"set system services web-management api-auth api-key machine-generated-key-alpha")

	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig: off-loopback + expiring API key must commit, got error: %v", err)
	}
}

func TestWebManagementRejectsAPIAuthOnClearHTTP(t *testing.T) {
	tree := buildTreeFromSets(t,
		"set system services web-management http",
		"set system services web-management api-auth expires 2099-01-01",
		"set system services web-management api-auth api-key machine-generated-key-alpha")
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "cannot serve api-auth") {
		t.Fatalf("clear HTTP with api-auth error = %v, want explicit #10826 rejection", err)
	}
}

// A loopback bind (web-management http with NO interface) is safe without auth
// and must commit cleanly — the gate keys on an interface binding, not the mere
// presence of web-management.
func TestWebManagementLoopbackNoAuthCommits(t *testing.T) {
	tree := buildTreeFromSets(t, "set system services web-management http")

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: loopback web-management with no auth must commit, got error: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4047") {
			t.Fatalf("unexpected #4047 warning on a loopback config: %q", w)
		}
	}
}

// No web-management stanza at all: no gate fires.
func TestWebManagementAbsentCommits(t *testing.T) {
	tree := buildTreeFromSets(t, "set system host-name fw0")
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig: a config with no web-management must commit, got error: %v", err)
	}
}

// Lenient (load / peer-sync): the off-loopback no-auth config downgrades to a
// warning so an already-persisted or peer-synced config still boots (#1960); the
// daemon's part-B runtime clamp pulls the bind back to loopback.
func TestWebManagementOffLoopbackNoAuthLenientWarns(t *testing.T) {
	tree := buildTreeFromSets(t, "set system services web-management http interface fxp0.0")

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: off-loopback no-auth must downgrade to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "web-management auth") && strings.Contains(w, "#4047") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #4047 web-management-auth warning on the lenient path, got: %v", cfg.Warnings)
	}
}
