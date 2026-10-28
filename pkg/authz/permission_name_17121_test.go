package authz

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17121 (R4-Q47-07): the denial renderer (PermissionName) and the commit
// advisory renderer (the now-deleted loginClassPermName) disagreed on
// PermAll ("all" vs "super-user") and on unknown values
// ("permission(%d)" vs "unknown"). Both now consume the single table in
// config.LoginClassPermission.String.
//
// RED-on-revert: reintroducing an independent switch in PermissionName
// with either old divergent arm turns the corresponding cell RED.

// TestPermissionNameMatchesConfigString17121 asserts PermissionName is a
// pure delegation: identical output to LoginClassPermission.String for
// every defined value and for out-of-range values, and that PermAll —
// the value the two renderers disagreed on — is "all" on this surface.
func TestPermissionNameMatchesConfigString17121(t *testing.T) {
	perms := []config.LoginClassPermission{
		config.PermView, config.PermClear, config.PermControl,
		config.PermConfig, config.PermMaint, config.PermAll,
		config.LoginClassPermission(99), config.LoginClassPermission(-1),
	}
	for _, p := range perms {
		if got, want := PermissionName(p), p.String(); got != want {
			t.Errorf("PermissionName(%d) = %q, want %q (config String) — the denial and advisory renderers diverged", int(p), got, want)
		}
	}
	if got := PermissionName(config.PermAll); got != "all" {
		t.Errorf("PermissionName(PermAll) = %q, want %q — the commit advisory's old word was %q", got, "all", "super-user")
	}
}

// TestAuthorizeDenialNamesPermAllAsAll17121 drives the production
// Authorize decision: a read-only principal denied the PermAll tier must
// be told it lacks the "all" permission — the same word the commit
// advisory prints for a class holding PermAll — never "super-user".
func TestAuthorizeDenialNamesPermAllAsAll17121(t *testing.T) {
	cfg := testConfig()
	p := CredentialPrincipal("view-key", "read-only")
	err := Authorize(cfg, p, config.PermAll)
	if err == nil {
		t.Fatal("Authorize admitted a read-only principal for PermAll; want a denial")
	}
	if !strings.Contains(err.Error(), "lacks the all permission") {
		t.Errorf("denial = %q, want it to name the missing permission as %q", err.Error(), "all")
	}
	if strings.Contains(err.Error(), "super-user") {
		t.Errorf("denial = %q names a login CLASS (super-user) as the missing permission", err.Error())
	}
	// Cross-surface parity: the denial word is exactly PermissionName's.
	if !strings.Contains(err.Error(), PermissionName(config.PermAll)) {
		t.Errorf("denial = %q does not contain PermissionName(PermAll) = %q", err.Error(), PermissionName(config.PermAll))
	}
}
