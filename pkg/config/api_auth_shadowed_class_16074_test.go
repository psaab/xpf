package config

import (
	"strings"
	"testing"
)

// #16074 (split from #15987 claim R1): the #14387 shadowed login-class
// neutralisation covered `system login user` assignments only. On the
// tolerant load / peer-sync path an api-auth credential referencing the
// shadowed built-in kept that name, and the daemon wired it into the REST
// auth middleware, which resolves classes through the same built-in-first
// table — so `class super-user { permissions view; }` left an api-auth
// user/key holding built-in PermAll while the authored narrowing never
// applied. The fix extends neutraliseShadowedLoginAssignments14387 to
// api-auth users, named keys, and the api-auth default class (which
// legacy `api-key` tokens and class-less credentials inherit).

const apiAuthShadow16074Hier = `system {
	login {
		class super-user { permissions view; }
		user bob { class super-user; }
	}
	services {
		web-management {
			https { system-generated-certificate; }
			api-auth {
				class super-user;
				expires 2099-01-01;
				user apiadmin { password "correct-horse-battery"; }
				user apiop { password "correct-horse-battery"; class operator; }
				key automation { secret "machine-generated-key-for-api-auth"; }
				key narrow { secret "machine-generated-key-for-api-auth"; class read-only; }
				api-key "legacy-token-for-api-auth";
			}
		}
	}
}`

func apiAuth16074(t *testing.T, cfg *Config) *APIAuthConfig {
	t.Helper()
	if cfg.System.Services == nil || cfg.System.Services.WebManagement == nil ||
		cfg.System.Services.WebManagement.APIAuth == nil {
		t.Fatal("api-auth missing after compile")
	}
	return cfg.System.Services.WebManagement.APIAuth
}

func apiUserClass16074(t *testing.T, auth *APIAuthConfig, name string) string {
	t.Helper()
	for _, u := range auth.Users {
		if u != nil && u.Username == name {
			if u.Class != "" {
				return u.Class
			}
			return auth.DefaultClass
		}
	}
	t.Fatalf("api-auth user %q not found in %+v", name, auth.Users)
	return ""
}

func apiKeyClass16074(t *testing.T, auth *APIAuthConfig, name string) string {
	t.Helper()
	for _, k := range auth.Keys {
		if k != nil && k.Name == name {
			if k.Class != "" {
				return k.Class
			}
			return auth.DefaultClass
		}
	}
	t.Fatalf("api-auth key %q not found in %+v", name, auth.Keys)
	return ""
}

func TestAPIAuthShadowedClassLenientNeutralised16074(t *testing.T) {
	cfg, err := compileLogin6662Lenient(t, apiAuthShadow16074Hier)
	if err != nil {
		t.Fatalf("tolerant path must NOT reject (#1960 no-brick): %v", err)
	}
	auth := apiAuth16074(t, cfg)

	// Decisive: every credential whose effective class is the shadowed
	// super-user is neutralised, and no permission survives through it.
	if auth.DefaultClass != "unauthorized" {
		t.Fatalf("DefaultClass = %q, want unauthorized (shadowed default neutralised)", auth.DefaultClass)
	}
	if got := apiUserClass16074(t, auth, "apiadmin"); got != "unauthorized" {
		t.Fatalf("api-auth user apiadmin class = %q, want unauthorized (inherited shadowed default)", got)
	}
	if got := apiKeyClass16074(t, auth, "automation"); got != "unauthorized" {
		t.Fatalf("api-auth key automation class = %q, want unauthorized (inherited shadowed default)", got)
	}
	if perms, ok := ResolveClassPermissions(cfg, auth.DefaultClass); !ok || len(perms) != 0 {
		t.Fatalf("neutralised default resolves to %v,%v, want empty known set", perms, ok)
	}
	if ClassHasPermission(cfg, auth.DefaultClass, PermView) {
		t.Fatal("neutralised default holds PermView")
	}
	// The pre-existing login-user neutralisation still fires alongside.
	if class, ok := LoginUserClass(cfg, "bob"); !ok || class != "unauthorized" {
		t.Fatalf("LoginUserClass(bob) = %q,%v, want unauthorized,true", class, ok)
	}

	// Controls: credentials on unshadowed classes are untouched.
	if got := apiUserClass16074(t, auth, "apiop"); got != "operator" {
		t.Fatalf("api-auth user apiop class = %q, want operator (unshadowed, preserved)", got)
	}
	if got := apiKeyClass16074(t, auth, "narrow"); got != "read-only" {
		t.Fatalf("api-auth key narrow class = %q, want read-only (unshadowed, preserved)", got)
	}

	// Legacy api-key rows survive as credentials; they inherit the
	// (now neutralised) default at daemon wiring time.
	if len(auth.APIKeys) != 1 {
		t.Fatalf("legacy APIKeys = %d, want 1 preserved", len(auth.APIKeys))
	}

	// One warning per neutralised site, naming the credential.
	for _, want := range []string{"api-auth: default class", "api-auth user apiadmin", "api-auth key automation"} {
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, want) && strings.Contains(w, "unauthorized") && strings.Contains(w, "#16074") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no neutralisation warning containing %q; warnings: %v", want, cfg.Warnings)
		}
	}
	// Built-in-first precedence itself is unchanged.
	if perms, ok := ResolveClassPermissions(cfg, "super-user"); !ok || !hasPerm14387(perms, PermAll) {
		t.Fatalf("ResolveClassPermissions(super-user) = %v,%v — built-in-first precedence must not change", perms, ok)
	}
}

func TestAPIAuthShadowedClassExplicitUserAndKey16074(t *testing.T) {
	// Explicit per-credential class naming the shadowed built-in, with a
	// harmless default: the explicit assignment is neutralised and the
	// default is left alone.
	cfg, err := compileLogin6662Lenient(t, `system {
		login {
			class super-user { permissions view; }
		}
		services {
			web-management {
				https { system-generated-certificate; }
				api-auth {
					class read-only;
					expires 2099-01-01;
					user apiadmin { password "correct-horse-battery"; class super-user; }
					key automation { secret "machine-generated-key-for-api-auth"; class super-user; }
				}
			}
		}
	}`)
	if err != nil {
		t.Fatalf("tolerant path must NOT reject: %v", err)
	}
	auth := apiAuth16074(t, cfg)
	if auth.DefaultClass != "read-only" {
		t.Fatalf("DefaultClass = %q, want read-only (unshadowed default preserved)", auth.DefaultClass)
	}
	if got := apiUserClass16074(t, auth, "apiadmin"); got != "unauthorized" {
		t.Fatalf("api-auth user apiadmin class = %q, want unauthorized", got)
	}
	if got := apiKeyClass16074(t, auth, "automation"); got != "unauthorized" {
		t.Fatalf("api-auth key automation class = %q, want unauthorized", got)
	}
}

func TestAPIAuthShadowedClassNoDefinitionControl16074(t *testing.T) {
	// Control: NO shadowing definition — a plain built-in api-auth class
	// keeps its grant on the tolerant path.
	cfg, err := compileLogin6662Lenient(t, `system {
		services {
			web-management {
				https { system-generated-certificate; }
				api-auth {
					class super-user;
					expires 2099-01-01;
					user apiadmin { password "correct-horse-battery"; }
					key automation { secret "machine-generated-key-for-api-auth"; }
				}
			}
		}
	}`)
	if err != nil {
		t.Fatalf("tolerant compile without shadow: %v", err)
	}
	auth := apiAuth16074(t, cfg)
	if auth.DefaultClass != "super-user" {
		t.Fatalf("DefaultClass = %q, want super-user preserved", auth.DefaultClass)
	}
	if got := apiUserClass16074(t, auth, "apiadmin"); got != "super-user" {
		t.Fatalf("api-auth user apiadmin class = %q, want super-user preserved", got)
	}
	if got := apiKeyClass16074(t, auth, "automation"); got != "super-user" {
		t.Fatalf("api-auth key automation class = %q, want super-user preserved", got)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16074") {
			t.Fatalf("unexpected #16074 neutralisation warning without a shadow: %q", w)
		}
	}
}

func TestAPIAuthShadowedClassStrictStillRejects16074(t *testing.T) {
	_, err := compileLogin6662(t, apiAuthShadow16074Hier)
	mustReject(t, err, gate6701ShadowMarker, "strict shadowing definition with api-auth")
}

func TestAPIAuthShadowedClassLenientForNode16074(t *testing.T) {
	// The per-node tolerant path (peer sync) must neutralise api-auth too.
	p := NewParser(apiAuthShadow16074Hier)
	tree, perrs := p.Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigForNodeLenient(tree, 0)
	if err != nil {
		t.Fatalf("CompileConfigForNodeLenient: %v", err)
	}
	auth := apiAuth16074(t, cfg)
	if auth.DefaultClass != "unauthorized" {
		t.Fatalf("per-node lenient: DefaultClass = %q, want unauthorized", auth.DefaultClass)
	}
	if got := apiUserClass16074(t, auth, "apiadmin"); got != "unauthorized" {
		t.Fatalf("per-node lenient: apiadmin class = %q, want unauthorized", got)
	}
	if got := apiKeyClass16074(t, auth, "automation"); got != "unauthorized" {
		t.Fatalf("per-node lenient: automation class = %q, want unauthorized", got)
	}
}
