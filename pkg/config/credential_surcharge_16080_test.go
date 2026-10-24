package config

import (
	"strings"
	"testing"
)

// #16080 (MGMT-01): a PermConfig class without credential fencing could
// rewrite login / root / api-auth credentials silently — `configure`
// folded to PermConfig, Authorize was coarse-only, and the
// *-configuration regex leg no-opped when the class authored none
// (`if !ok { return nil }`). The fix prices credential paths above
// PermConfig in the shared AuthorizeConfigMutation decision (CLI +
// gRPC + REST all call it), so a non-PermAll class is denied by name on
// every surface, and the commit advisory names the fence.
//
// RED-on-revert: removing the fence check in
// authorizeConfigMutationDepth9939 (or moving it below the `if !ok`
// return) makes every denied cell below return nil again.

// cfg16080 compiles a custom class with the given Junos permission
// tokens and no *-configuration regexes — the limited configure class
// the issue names.
func cfg16080(t *testing.T, class, perms string) *Config {
	t.Helper()
	text := "system { login { class " + class + " { permissions [ " + perms + " ]; } } }"
	root, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(&ConfigTree{Children: root.Children})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func TestCredentialSurchargeDeniesLimitedConfigure16080(t *testing.T) {
	cfg := cfg16080(t, "limited", "configure view")
	// Premise: the class holds PermConfig but not PermAll.
	if !ClassHasPermission(cfg, "limited", PermConfig) {
		t.Fatal("premise: limited must hold PermConfig")
	}
	if ClassHasPermission(cfg, "limited", PermAll) {
		t.Fatal("premise: limited must not hold PermAll")
	}
	denied := []string{
		"set system root-authentication plain-text-password hunter2-16080",
		"set system root-authentication encrypted-password $6$abc$def",
		"set system login user eve class super-user",
		"set system login user eve authentication encrypted-password $6$abc$def",
		"set system login class limited permissions all",
		"set system services web-management api-auth user admin password correct-horse-16080",
		"set system services web-management api-auth api-key machine-key-16080",
		"set system services web-management api-auth key automation secret machine-key-16080",
		"set system services rest api-auth user admin password correct-horse-16080",
		"delete system root-authentication",
		"delete system login user eve",
		"deactivate system login",
		"activate system root-authentication",
		"copy system login user operator to user root",
		"rename system host-name to system root-authentication",
		// An event payload planting a credential write is data on an
		// allowed path; the recursive adjudication must fence it too.
		`set event-options policy p then change-configuration commands "set system root-authentication plain-text-password hunter2-16080"`,
	}
	for _, line := range denied {
		err := AuthorizeConfigMutation(cfg, "limited", nil, line)
		if err == nil {
			t.Errorf("%q ALLOWED for PermConfig class without PermAll; credential rewrite must be denied (#16080)", line)
			continue
		}
		if !strings.Contains(err.Error(), "16080") || !strings.Contains(err.Error(), "limited") {
			t.Errorf("%q denied but not by name with the credential reason: %v", line, err)
		}
		if strings.Contains(err.Error(), "hunter2-16080") || strings.Contains(err.Error(), "correct-horse-16080") {
			t.Errorf("%q denial leaked the credential secret: %v", line, err)
		}
	}
	// Edit-cursor spelling resolves to the same fenced path.
	if err := AuthorizeConfigMutation(cfg, "limited", []string{"system"}, "set root-authentication plain-text-password hunter2-16080"); err == nil {
		t.Error("edit-cursor credential set ALLOWED (#16080)")
	}
	if err := AuthorizeConfigMutation(cfg, "limited", []string{"system", "login"}, "set user eve class super-user"); err == nil {
		t.Error("edit-cursor login set ALLOWED (#16080)")
	}
}

func TestCredentialSurchargeControls16080(t *testing.T) {
	cfg := cfg16080(t, "limited", "configure view")
	allowed := []string{
		"set system host-name fw-16080",
		"set system services ssh root-login deny",
		"set interfaces ge-0/0/0 description uplink-16080",
		"delete system host-name",
		// Token-boundary control: api-authentication is not api-auth.
		"set system services web-management api-authentication description x",
		// A stanza merely named like a credential container.
		"set system services web-management https system-generated-certificate",
	}
	for _, line := range allowed {
		if err := AuthorizeConfigMutation(cfg, "limited", nil, line); err != nil {
			t.Errorf("%q refused for limited configure class, want allowed (over-denial): %v", line, err)
		}
	}
	// PermAll (authored `all`) and the built-in super-user keep credential access.
	allCfg := cfg16080(t, "full", "all")
	if err := AuthorizeConfigMutation(allCfg, "full", nil, "set system root-authentication plain-text-password hunter2-16080"); err != nil {
		t.Errorf("PermAll custom class refused credential set: %v", err)
	}
	if err := AuthorizeConfigMutation(cfg, "super-user", nil, "set system login user eve class super-user"); err != nil {
		t.Errorf("built-in super-user refused credential set: %v", err)
	}
	// Empty class = legacy no-RBAC mode, unchanged.
	if err := AuthorizeConfigMutation(cfg, "", nil, "set system root-authentication plain-text-password hunter2-16080"); err != nil {
		t.Errorf("empty class refused credential set, want legacy bypass: %v", err)
	}
	// Regexes cannot ALLOW a credential path past the fence, and an
	// explicitly allow-configuration-covered credential path stays denied.
	regexCfg := classWithConfigRegex9154(t, "^system", "")
	if err := AuthorizeConfigMutation(regexCfg, "limited", nil, "set system root-authentication plain-text-password hunter2-16080"); err == nil {
		t.Error("allow-configuration ^system admitted a credential set past the #16080 fence")
	}
	if err := AuthorizeConfigMutation(regexCfg, "limited", nil, "set system host-name fw-16080"); err != nil {
		t.Errorf("allow-configuration ^system refused a non-credential set: %v", err)
	}
}

func TestCredentialSurchargeLoadRollbackExpanded16080(t *testing.T) {
	cfg := cfg16080(t, "limited", "configure view")
	if err := AuthorizeConfigLoad(cfg, "limited", "merge", "set system root-authentication plain-text-password hunter2-16080"); err == nil {
		t.Error("load merge carrying a credential set ALLOWED (#16080)")
	}
	if err := AuthorizeConfigLoad(cfg, "limited", "merge", "set system host-name ok-16080"); err != nil {
		t.Errorf("load merge of a non-credential set refused: %v", err)
	}
	if err := AuthorizeConfigLoad(cfg, "limited", "override", "set system host-name ok-16080"); err == nil {
		t.Error("load override by a PermConfig class without PermAll ALLOWED (#16080)")
	}
	if err := PreflightConfigLoad(cfg, "limited", "override"); err == nil {
		t.Error("preflight load override by a PermConfig class without PermAll ALLOWED (#16080)")
	}
	if err := AuthorizeConfigRollback(cfg, "limited", 1); err == nil {
		t.Error("rollback 1 by a PermConfig class without PermAll ALLOWED (#16080)")
	}
	if err := AuthorizeConfigRollback(cfg, "limited", 0); err != nil {
		t.Errorf("rollback 0 refused, want available: %v", err)
	}
	// Group-planted credential leaf: expanded adjudication must fence it.
	tree := parseHierText(t, "groups { G { system { root-authentication { plain-text-password hunter2-16080; } } } } apply-groups G;")
	if err := AuthorizeExpandedTree(cfg, "limited", tree); err == nil {
		t.Error("group-expanded credential leaf ALLOWED (#16080)")
	}
	okTree := parseHierText(t, "groups { G { system { host-name ok-16080; } } } apply-groups G;")
	if err := AuthorizeExpandedTree(cfg, "limited", okTree); err != nil {
		t.Errorf("group-expanded non-credential leaf refused: %v", err)
	}
	// PermAll keeps whole-candidate operations.
	allCfg := cfg16080(t, "full", "all")
	if err := AuthorizeConfigLoad(allCfg, "full", "override", "set system host-name ok-16080"); err != nil {
		t.Errorf("PermAll load override refused: %v", err)
	}
	if err := AuthorizeConfigRollback(allCfg, "full", 1); err != nil {
		t.Errorf("PermAll rollback refused: %v", err)
	}
}

func TestCredentialAdvisoryNamesFence16080(t *testing.T) {
	cfg := cfg16080(t, "limited", "configure view")
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "limited") && strings.Contains(w, "cannot rewrite login/root/api credentials") && strings.Contains(w, "16080") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no commit advisory naming the credential fence for the limited configure class: %v", cfg.Warnings)
	}
	// A PermAll class needs no such advisory.
	allCfg := cfg16080(t, "full", "all")
	for _, w := range allCfg.Warnings {
		if strings.Contains(w, "cannot rewrite login/root/api credentials") {
			t.Fatalf("PermAll class got a spurious credential-fence advisory: %q", w)
		}
	}
}
