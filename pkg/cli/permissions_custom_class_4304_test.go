package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestCustomLoginClassRuntimeRBAC is the runtime half of #4304 S-2: a user
// assigned to a custom `system login class <name>` must be enforced against
// the class's mapped permissions resolved from the active config — NOT locked
// out as an "unknown login class". Reverting resolveClassPerms back to a bare
// config.LoginClassPermissions lookup makes every subtest go RED (a custom
// class is unknown -> all commands denied).
func TestCustomLoginClassRuntimeRBAC(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	sets := []string{
		// noc-admin: permissions all -> PermAll for command authorization.
		"set system login class noc-admin permissions all",
		// viewer-plus: view + clear only.
		"set system login class viewer-plus permissions [ view clear ]",
		"set system login user alice class noc-admin",
		"set system login user bob class viewer-plus",
	}
	if _, err := store.LoadSet(strings.Join(sets, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}

	cases := []struct {
		class string
		parts []string
		allow bool
	}{
		{"noc-admin", []string{"configure"}, true},           // all -> PermAll
		{"noc-admin", []string{"clear", "security"}, true},   //
		{"viewer-plus", []string{"show", "version"}, true},   // view granted
		{"viewer-plus", []string{"clear", "security"}, true}, // clear granted
		{"viewer-plus", []string{"configure"}, false},        // no config perm
		{"viewer-plus", []string{"request", "system", "reboot"}, false},
	}
	for _, tc := range cases {
		c := &CLI{store: store, userClass: tc.class}
		err := c.checkPermission(tc.parts)
		cmd := strings.Join(tc.parts, " ")
		if tc.allow && err != nil {
			t.Errorf("%q for class %q denied: %v (want allowed)", cmd, tc.class, err)
		}
		if !tc.allow && err == nil {
			t.Errorf("%q for class %q ALLOWED (want denied)", cmd, tc.class)
		}
	}

	// `permissions all` still grants PermAll to command authorization, but only
	// the built-in super-user login class may read config secrets in cleartext.
	if !(&CLI{store: store, userClass: "noc-admin"}).showConfigRedacted() {
		t.Errorf("noc-admin (permissions all) should redact secret output")
	}
	if !(&CLI{store: store, userClass: "viewer-plus"}).showConfigRedacted() {
		t.Errorf("viewer-plus (view/clear only) SHOULD redact secrets")
	}
}

// TestCustomLoginClassResetCannotZeroize is the runtime half of the #4311
// priv-esc fix: a class with `permissions reset` (daemon restart) must be able
// to run benign control verbs but must NOT be able to run the destructive
// maintenance verbs (request system reboot/halt/power-off/zeroize + chassis
// cluster failover). Pre-fix reset->PermMaint let those through.
func TestCustomLoginClassResetCannotZeroize(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	sets := []string{
		"set system login class daemon-op permissions reset",
		"set system login user dan class daemon-op",
	}
	if _, err := store.LoadSet(strings.Join(sets, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}

	c := &CLI{store: store, userClass: "daemon-op"}

	// Destructive maintenance verbs MUST be denied (reset != maintenance).
	for _, parts := range [][]string{
		{"request", "system", "reboot"},
		{"request", "system", "zeroize"},
		{"request", "system", "halt"},
		{"request", "chassis", "cluster", "failover", "redundancy-group", "1", "node", "0"},
	} {
		if err := c.checkPermission(parts); err == nil {
			t.Errorf("PRIV-ESC: %q ALLOWED for `permissions reset` class (want denied — that is maintenance, not reset)",
				strings.Join(parts, " "))
		}
	}
	// A benign control verb IS allowed (reset -> PermControl).
	if err := c.checkPermission([]string{"request", "session"}); err != nil {
		t.Errorf("benign control verb denied for `permissions reset` class: %v", err)
	}
}
