package config

import (
	"strings"
	"testing"
)

// #14387 (DR6-H3): a custom class shadowing a built-in is INERT at runtime
// because ResolveClassPermissions consults the built-in table first. On the
// strict path the definition is rejected; on the tolerant load / peer-sync
// path it used to warn-and-keep, so `class super-user { permissions view; }`
// + `user bob { class super-user; }` left bob holding built-in PermAll while
// the commit advisory reported the narrowing ("mapped to ... {view}") as
// applied. The fix neutralises the ASSIGNMENT on lenient load (bob resolves
// to "unauthorized", which denies) without inverting built-in-first
// precedence — inverting it would let `class read-only { permissions all; }`
// escalate the built-in.

func hasPerm14387(perms []LoginClassPermission, want LoginClassPermission) bool {
	for _, p := range perms {
		if p == want {
			return true
		}
	}
	return false
}

func TestLoginClassShadowBuiltinLenientNeutralisesAssignment14387(t *testing.T) {
	cfg, err := compileLogin6662Lenient(t, `system {
		login {
			class super-user { permissions view; }
			user bob { class super-user; }
			user alice { class operator; }
		}
	}`)
	if err != nil {
		t.Fatalf("tolerant path must NOT reject (#1960 no-brick): %v", err)
	}
	// User-scoped regression (the corrected DR6-H3 criterion):
	// ResolveClassPermissions(cfg, "super-user") itself must keep returning
	// PermAll — built-in-first precedence is deliberate. What must change is
	// the class bob resolves to.
	class, ok := LoginUserClass(cfg, "bob")
	if !ok {
		t.Fatal("LoginUserClass(bob) not found after lenient compile")
	}
	if class != "unauthorized" {
		t.Fatalf("LoginUserClass(bob) = %q, want %q (shadowed assignment neutralised)", class, "unauthorized")
	}
	perms, ok := ResolveClassPermissions(cfg, class)
	if !ok {
		t.Fatalf("ResolveClassPermissions(%q) unresolved — neutralised class must be a known deny class", class)
	}
	if hasPerm14387(perms, PermAll) || hasPerm14387(perms, PermMaint) || hasPerm14387(perms, PermView) {
		t.Fatalf("bob via neutralised class %q holds %v, want no permissions", class, perms)
	}
	if ClassHasPermission(cfg, class, PermView) {
		t.Fatalf("neutralised class %q holds PermView", class)
	}
	// The compiled user record itself must be neutralised, not just one
	// resolver: daemon consumers read User.Class directly (login shell,
	// sudoers reconciliation), so bob must not retain "super-user" there.
	for _, u := range cfg.System.Login.Users {
		if u != nil && u.Name == "bob" && u.Class != "unauthorized" {
			t.Fatalf("compiled bob.Class = %q, want unauthorized", u.Class)
		}
	}
	// A user assigned a built-in with NO shadowing definition is untouched.
	aclass, ok := LoginUserClass(cfg, "alice")
	if !ok || aclass != "operator" {
		t.Fatalf("LoginUserClass(alice) = %q,%v, want operator,true (unshadowed built-in preserved)", aclass, ok)
	}
	if perms, ok := ResolveClassPermissions(cfg, aclass); !ok || !hasPerm14387(perms, PermControl) {
		t.Fatalf("alice via %q = %v,%v, want operator permissions incl. control", aclass, perms, ok)
	}
	// Advisory must not report the narrowing as applied, and a warning must
	// state the assignment was neutralised.
	var neutralised bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, `system login class "super-user": recognized`) ||
			(strings.Contains(w, "super-user") && strings.Contains(w, "mapped to xpf coarse permissions {view}")) {
			t.Errorf("advisory reports the shadowed narrowing as applied: %q", w)
		}
		if strings.Contains(w, "bob") && strings.Contains(w, "unauthorized") {
			neutralised = true
		}
	}
	if !neutralised {
		t.Errorf("no warning states bob's assignment was neutralised to unauthorized; warnings: %v", cfg.Warnings)
	}
	// The shadowing definition itself stays authored (show-config fidelity)
	// and built-in-first resolution of the name itself is unchanged.
	if perms, ok := ResolveClassPermissions(cfg, "super-user"); !ok || !hasPerm14387(perms, PermAll) {
		t.Fatalf("ResolveClassPermissions(super-user) = %v,%v — built-in-first precedence must not change", perms, ok)
	}
}

func TestLoginClassShadowBuiltinLenientWideningShadowNeutralised14387(t *testing.T) {
	// Same mechanism in the widening direction: `class operator { permissions
	// all; }` is inert (built-in operator wins), so bob must end up denied,
	// never PermAll and never silently kept at a class whose authored
	// definition misdescribes his grant.
	cfg, err := compileLogin6662Lenient(t, `system {
		login {
			class operator { permissions all; }
			user bob { class operator; }
		}
	}`)
	if err != nil {
		t.Fatalf("tolerant path must NOT reject: %v", err)
	}
	class, ok := LoginUserClass(cfg, "bob")
	if !ok || class != "unauthorized" {
		t.Fatalf("LoginUserClass(bob) = %q,%v, want unauthorized,true", class, ok)
	}
	if ClassHasPermission(cfg, class, PermAll) || ClassHasPermission(cfg, class, PermMaint) {
		t.Fatalf("bob via %q holds PermAll/PermMaint after widening-shadow lenient load", class)
	}
}

func TestLoginClassShadowBuiltinNoDefinitionControl14387(t *testing.T) {
	// Control B: NO shadowing definition — a plain built-in assignment keeps
	// PermAll on both paths.
	for _, lenient := range []bool{true, false} {
		var cfg *Config
		var err error
		text := `system { login { user admin { class super-user; } } }`
		if lenient {
			cfg, err = compileLogin6662Lenient(t, text)
		} else {
			cfg, err = compileLogin6662(t, text)
		}
		if err != nil {
			t.Fatalf("lenient=%v: %v", lenient, err)
		}
		class, ok := LoginUserClass(cfg, "admin")
		if !ok || class != "super-user" {
			t.Fatalf("lenient=%v: LoginUserClass(admin) = %q,%v, want super-user,true", lenient, class, ok)
		}
		if perms, ok := ResolveClassPermissions(cfg, class); !ok || !hasPerm14387(perms, PermAll) {
			t.Fatalf("lenient=%v: admin perms = %v,%v, want PermAll preserved", lenient, perms, ok)
		}
	}
}

func TestLoginClassShadowBuiltinLenientForNode14387(t *testing.T) {
	// The per-node tolerant path (peer sync) must neutralise too.
	p := NewParser(`system {
		login {
			class super-user { permissions view; }
			user bob { class super-user; }
		}
	}`)
	tree, perrs := p.Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigForNodeLenient(tree, 0)
	if err != nil {
		t.Fatalf("CompileConfigForNodeLenient: %v", err)
	}
	class, ok := LoginUserClass(cfg, "bob")
	if !ok || class != "unauthorized" {
		t.Fatalf("per-node lenient: LoginUserClass(bob) = %q,%v, want unauthorized,true", class, ok)
	}
	if ClassHasPermission(cfg, class, PermMaint) {
		t.Fatalf("per-node lenient: bob holds PermMaint via %q", class)
	}
}

func TestLoginClassShadowBuiltinStrictStillRejects14387(t *testing.T) {
	_, err := compileLogin6662(t, `system {
		login {
			class super-user { permissions view; }
			user bob { class super-user; }
		}
	}`)
	mustReject(t, err, gate6701ShadowMarker, "strict shadowing definition")
}
