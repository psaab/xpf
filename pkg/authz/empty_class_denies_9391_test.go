package authz

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9391: the OTHER direction of the login-user flat-run drop, pinned so the
// severity split stays honest.
//
// A user with NO prior class whose `class` was swallowed compiles to Class="",
// and that direction fails CLOSED here. It is an availability bug, not an
// authorization one — and saying so plainly is worth more than the larger
// claim, because the AUTHORIZATION half is the DOWNGRADE case (a previously
// authored class stands), which lives in pkg/config and pkg/daemon.
//
// This cell exists because that split was established by reading Authorize
// once. A reading is not a measurement, and the denial it depends on is one
// `if` away from being a default.
func TestEmptyLoginClassIsDeniedNotDefaulted9391(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{
		Users: []*config.LoginUser{
			{Name: "alice", UID: 2001, Class: ""},         // the swallowed class
			{Name: "bob", UID: 2002, Class: "super-user"}, // the control
		},
	}

	// CONTROL: a real class is authorized, so a denial below means "empty class"
	// and not "this fixture authorizes nothing".
	bob := Principal{Source: SourcePeerUID, UID: 2002, Username: "bob", Class: "super-user"}
	if err := Authorize(cfg, bob, config.PermView); err != nil {
		t.Fatalf("CONTROL: a super-user was denied view (%v) — every assertion below "+
			"would pass for the wrong reason", err)
	}

	alice := Principal{Source: SourcePeerUID, UID: 2001, Username: "alice", Class: ""}
	for _, perm := range []config.LoginClassPermission{
		config.PermView, config.PermClear, config.PermControl,
		config.PermConfig, config.PermMaint, config.PermAll,
	} {
		err := Authorize(cfg, alice, perm)
		if err == nil {
			t.Errorf("an EMPTY login class was AUTHORIZED for %s. An empty class must "+
				"deny: 'not in the RBAC model' is a reason to deny, never a reason to "+
				"pick a default", PermissionName(perm))
			continue
		}
	}
	if alice.Resolved() {
		t.Errorf("a principal with an empty class must not report Resolved(); callers " +
			"use that to decide whether to fall through to a weaker identity")
	}
}

// TestEmptyClassPrincipalIsBuiltUnresolved9391 pins the same property one layer
// up, at the point the class is read out of the config.
//
// Authorize denying is only half: if PrincipalForUID were to synthesize a
// default class for an empty one, Authorize would never see the empty string
// and would authorize whatever the default permits.
func TestEmptyClassPrincipalIsBuiltUnresolved9391(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{
		Users: []*config.LoginUser{{Name: "alice", UID: 2001, Class: ""}},
	}
	// UID 0 short-circuits to superuser and must keep doing so; without this the
	// cell below could pass on a resolver that returns an unresolved principal
	// for everything.
	if root := PrincipalForUID(cfg, 0); !root.Superuser {
		t.Fatalf("CONTROL: uid 0 must remain an unconditional superuser")
	}
}
