package config

import (
	"strings"
	"testing"
)

// TestCustomLoginClassCommitsWithAdvisory is the RED-on-revert guard for
// #4304 S-2. A real vSRX RBAC config that defines a custom `login class` and
// assigns a user to it must COMMIT (SchemaValidate accepts) — the pre-fix
// fixed enum hard-rejected `class noc-admin`, blocking the WHOLE config. The
// class must compile with the Junos permission set mapped to the coarse xpf
// model, and the compiler must emit the accept-with-advisory warning.
func TestCustomLoginClassCommitsWithAdvisory(t *testing.T) {
	tree := buildTree4303(t, []string{
		"set system login class noc-admin permissions all",
		"set system login class noc-admin idle-timeout 30",
		"set system login user bob class noc-admin",
		"set system login user bob uid 2001",
	})
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// RED-on-revert: the fixed enum rejected the custom class name here.
	if err := SchemaValidate(tree, c); err != nil {
		t.Fatalf("SchemaValidate hard-rejected a valid custom-RBAC config: %v", err)
	}
	if c.System.Login == nil || len(c.System.Login.Classes) != 1 {
		t.Fatalf("expected one custom login class, got %+v", c.System.Login)
	}
	lc := c.System.Login.Classes[0]
	if lc.Name != "noc-admin" {
		t.Fatalf("class name = %q, want noc-admin", lc.Name)
	}
	if len(lc.MappedPermissions) != 1 || lc.MappedPermissions[0] != PermAll {
		t.Fatalf("permissions all -> %v, want [PermAll]", lc.MappedPermissions)
	}
	// PermAll still governs command authorization; secret display uses class identity.
	if lc.IdleTimeout != 30 {
		t.Fatalf("idle-timeout = %d, want 30", lc.IdleTimeout)
	}
	// Accept-with-advisory: an advisory naming the class must be present.
	found := false
	for _, w := range c.Warnings {
		if strings.Contains(w, "noc-admin") && strings.Contains(w, "recognized") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an accept-with-advisory warning for noc-admin; warnings=%v", c.Warnings)
	}
}

// TestCustomLoginClassPermissionMapping checks the least-privilege folding:
// unambiguous whole-box tokens map precisely, and any other subsystem/-control
// token folds DOWN to a view-only floor (never silently grants config/control
// from a narrow token).
func TestCustomLoginClassPermissionMapping(t *testing.T) {
	tree := buildTree4303(t, []string{
		"set system login class ops permissions [ view clear network interface-control ]",
		"set system login user carol class ops",
	})
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := SchemaValidate(tree, c); err != nil {
		t.Fatalf("SchemaValidate rejected ops class: %v", err)
	}
	lc := c.System.Login.Classes[0]
	perms := map[LoginClassPermission]bool{}
	for _, p := range lc.MappedPermissions {
		perms[p] = true
	}
	if !perms[PermView] || !perms[PermClear] {
		t.Fatalf("expected view+clear in %v", lc.MappedPermissions)
	}
	// `network` and `interface-control` fold to view-only — they must NOT
	// silently grant config/control/maint.
	if perms[PermConfig] || perms[PermControl] || perms[PermMaint] || perms[PermAll] {
		t.Fatalf("subsystem tokens over-granted: %v", lc.MappedPermissions)
	}
}

// TestUndefinedLoginClassStillRejected proves the gate did not go fail-open:
// a user referencing a class that is neither built-in nor defined must still
// be rejected at commit.
func TestUndefinedLoginClassStillRejected(t *testing.T) {
	tree := buildTree4303(t, []string{
		"set system login user dave class ghost-class",
	})
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := SchemaValidate(tree, c); err == nil {
		t.Fatalf("SchemaValidate accepted an undefined login class (fail-open regression)")
	}
}

// TestCustomLoginClassNoPrivEsc pins the #4311-review privilege-escalation fix:
// the deceptive Junos tokens must NOT over-grant.
//   - `reset` (restart daemons) maps to PermControl, NOT PermMaint (the
//     destructive box verbs). RED on revert: reset->PermMaint lets a class
//     scoped to daemon restarts run `request system zeroize`.
//   - `rollback` (revert to a prior commit) maps to the PermView floor, NOT
//     PermConfig (arbitrary set/delete).
//   - only `maintenance` maps to PermMaint.
func TestCustomLoginClassNoPrivEsc(t *testing.T) {
	has := func(perms []LoginClassPermission, want LoginClassPermission) bool {
		for _, p := range perms {
			if p == want {
				return true
			}
		}
		return false
	}

	// `reset` -> PermControl, and crucially NOT PermMaint.
	resetPerms, _ := mapJunosPermissions([]string{"reset"})
	if !has(resetPerms, PermControl) {
		t.Errorf("permissions reset should map to PermControl; got %v", resetPerms)
	}
	if has(resetPerms, PermMaint) {
		t.Errorf("PRIV-ESC: permissions reset must NOT map to PermMaint (would grant reboot/zeroize); got %v", resetPerms)
	}
	if has(resetPerms, PermAll) {
		t.Errorf("permissions reset must NOT map to PermAll; got %v", resetPerms)
	}

	// `rollback` -> PermView floor, NOT PermConfig.
	rbPerms, _ := mapJunosPermissions([]string{"rollback"})
	if has(rbPerms, PermConfig) {
		t.Errorf("permissions rollback must NOT map to PermConfig; got %v", rbPerms)
	}
	if !has(rbPerms, PermView) {
		t.Errorf("permissions rollback should map to the PermView floor; got %v", rbPerms)
	}

	// `maintenance` is the ONLY token that legitimately maps to PermMaint.
	maintPerms, _ := mapJunosPermissions([]string{"maintenance"})
	if !has(maintPerms, PermMaint) {
		t.Errorf("permissions maintenance should map to PermMaint; got %v", maintPerms)
	}
}

// TestCustomLoginClassDenyCommandsIsEnforcedNotRejected traces the full arc of
// this statement's treatment, because the test that used to live here asserted
// the OPPOSITE and a reader needs to know that was correct at the time.
//
//   - #4304 accepted a deny-commands class and warned it was MORE PERMISSIVE
//     than the Junos config said.
//   - #5831/#6838 concluded that telling an operator their restriction is inert
//     is not good enough when we can simply refuse it, and hard-rejected it.
//     That was right while xpf could not enforce the regex.
//   - #7172 cut 6 implements the regex on every dispatch surface, so refusing
//     it became the opposite error. The class commits and the restriction is
//     real.
//
// The #4304 intent is unchanged throughout and is now met directly rather than
// by refusal: an operator must never silently get a class weaker OR stronger
// than they wrote.
func TestCustomLoginClassDenyCommandsIsEnforcedNotRejected(t *testing.T) {
	tree := buildTree4303(t, []string{
		"set system login class limited permissions all",
		`set system login class limited deny-commands "request system reboot"`,
		"set system login user carol class limited",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a deny-commands class must commit now that #7172 enforces it: %v", err)
	}
	lc := cfg.System.Login.Classes[0]
	if lc.DenyCommands != "request system reboot" {
		t.Errorf("the pattern must survive compilation verbatim; got %q", lc.DenyCommands)
	}
	// And it must be REACHABLE by the enforcement path, which reads presence
	// rather than value. A class whose pattern compiled but whose presence went
	// unrecorded would commit and restrict nothing — the #5831 fail-open
	// wearing the shape of a fix.
	rules, ok, err := OperationalLoginRegexesFor(cfg, "limited")
	if err != nil || !ok {
		t.Fatalf("the committed class must yield compiled rules (ok=%v err=%v)", ok, err)
	}
	if rules.Evaluate("request system reboot").Allowed {
		t.Error("the committed deny-commands does not deny its own pattern — the statement " +
			"is accepted and inert, which is exactly the #5831 defect")
	}
	if !rules.Evaluate("show version").Allowed {
		t.Error("a narrow deny must stay narrow; `show version` was denied")
	}
}
