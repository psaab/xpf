package config

import (
	"strings"
	"testing"
)

// #17121 (R4-Q47-07): LoginClassPermission had two diverged renderers —
// authz.PermissionName printed PermAll as "all" (default "permission(%d)")
// while config's private loginClassPermName printed PermAll as
// "super-user" (default "unknown"), so a class described at commit as
// holding {super-user} was later denied for lacking "the all permission".
// The fix single-sources the table in LoginClassPermission.String;
// loginClassPermName is deleted and authz.PermissionName delegates.
//
// RED-on-revert: restoring loginClassPermName's "super-user"/"unknown"
// arms (or rendering PermAll any other way here) turns every PermAll
// cell below RED.

// TestLoginClassPermissionString17121 pins every value of the enum,
// in-range and out-of-range, to the Junos permission vocabulary.
func TestLoginClassPermissionString17121(t *testing.T) {
	cases := []struct {
		perm LoginClassPermission
		want string
	}{
		{PermView, "view"},
		{PermClear, "clear"},
		{PermControl, "control"},
		{PermConfig, "configure"},
		{PermMaint, "maintenance"},
		{PermAll, "all"},
		{LoginClassPermission(99), "permission(99)"},
		{LoginClassPermission(-1), "permission(-1)"},
	}
	for _, tc := range cases {
		if got := tc.perm.String(); got != tc.want {
			t.Errorf("LoginClassPermission(%d).String() = %q, want %q", int(tc.perm), got, tc.want)
		}
	}
	// "super-user" is a predefined class NAME, never a permission word.
	for _, p := range []LoginClassPermission{PermView, PermClear, PermControl, PermConfig, PermMaint, PermAll} {
		if got := p.String(); got == "super-user" {
			t.Errorf("LoginClassPermission(%d).String() = %q — a class name, not a permission", int(p), got)
		}
	}
}

// TestLoginClassAdvisoryNamesPermAllAsAll17121 drives the REAL
// parser -> compiler path for a custom class whose authored tokens fold
// to PermAll, and pins the commit advisory (loginClassAdvisoryWarnings,
// appended to cfg.Warnings) to the same word the authorization denial
// uses: "all", never "super-user" inside the coarse-permission braces.
func TestLoginClassAdvisoryNamesPermAllAsAll17121(t *testing.T) {
	cfg, err := compileLogin6662(t, `system { login { class full { permissions [ all ]; } } }`)
	if err != nil {
		t.Fatalf("compile custom PermAll class: %v", err)
	}
	var advisory string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "mapped to xpf coarse permissions") {
			advisory = w
			break
		}
	}
	if advisory == "" {
		t.Fatalf("no login-class advisory in warnings %q — the custom class was not recognized", cfg.Warnings)
	}
	if !strings.Contains(advisory, "mapped to xpf coarse permissions {all}") {
		t.Errorf("advisory = %q, want it to name PermAll as {all} (the denial vocabulary)", advisory)
	}
	if strings.Contains(advisory, "{super-user}") {
		t.Errorf("advisory = %q renders PermAll as the class name super-user inside the permission set", advisory)
	}
	// The advisory surface and the enum rendering must agree exactly.
	if got := PermAll.String(); got != "all" {
		t.Errorf("PermAll.String() = %q, want %q to match the advisory", got, "all")
	}
}
