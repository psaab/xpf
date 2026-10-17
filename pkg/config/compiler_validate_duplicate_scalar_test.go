package config

import (
	"strings"
	"testing"
)

// #14448 (DR20-H2): duplicate api-auth class / expires — the permissive
// class and the stale expiry win.
//
// Before the fix the api-auth reader in compileSystem used FindChild
// (first sibling wins) at six sites: default class/expires, per-user
// class/expires, per-key class/expires. A config carrying
// `class super-user; class read-only;` installed super-user (PermAll for
// every credential inheriting the default), and
// `expires 2099-01-01; expires 2020-01-01;` installed the far-future
// expiry, so a credential the config revokes stayed valid. Strict commit
// accepted both silently; validateWebManagementAuthStrict reads only the
// COMPILED config and cannot see the dropped second value.
//
// The fix: (1) the six reader sites keep the LAST sibling (Junos
// last-wins), and (2) validateAPIAuthDuplicateScalarAST rejects
// conflicting duplicates at strict commit and warns on the tolerant path.
//
// RED evidence: on the pre-fix tree every "strict rejects" case below
// compiles, and the lenient cases install the FIRST value
// (super-user / 2099-12-31+1d).

func apiAuthTree14448(t *testing.T, body string) *ConfigTree {
	t.Helper()
	return mustParse(t, "system {\n    services {\n        web-management {\n            api-auth {\n"+body+"\n            }\n        }\n    }\n}\n")
}

const apiAuthAlice14448 = `user alice { password "correct-horse-battery"; }`

func TestAPIAuthDuplicateScalar14448(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		leaf    string
		first   string
		last    string
		wantLen func(*Config) (string, bool)
	}{
		{
			name: "default class super-user then read-only",
			body: "class super-user;\nclass read-only;\n" + apiAuthAlice14448,
			leaf: "class", first: "super-user", last: "read-only",
			wantLen: func(c *Config) (string, bool) {
				return c.System.Services.WebManagement.APIAuth.DefaultClass, true
			},
		},
		{
			name: "default class read-only then super-user",
			body: "class read-only;\nclass super-user;\n" + apiAuthAlice14448,
			leaf: "class", first: "read-only", last: "super-user",
			wantLen: func(c *Config) (string, bool) {
				return c.System.Services.WebManagement.APIAuth.DefaultClass, true
			},
		},
		{
			name: "default expires far then past",
			body: "expires 2099-01-01;\nexpires 2020-01-01;\n" + apiAuthAlice14448,
			leaf: "expires", first: "2099-01-01", last: "2020-01-01",
			wantLen: func(c *Config) (string, bool) {
				return c.System.Services.WebManagement.APIAuth.DefaultExpiresAt.Format("2006-01-02"), true
			},
		},
		{
			name: "default expires past then far",
			body: "expires 2020-01-01;\nexpires 2099-01-01;\n" + apiAuthAlice14448,
			leaf: "expires", first: "2020-01-01", last: "2099-01-01",
			wantLen: func(c *Config) (string, bool) {
				return c.System.Services.WebManagement.APIAuth.DefaultExpiresAt.Format("2006-01-02"), true
			},
		},
		{
			name: "per-user class",
			body: `user bob { password "correct-horse-battery"; expires 2099-01-01; class super-user; class read-only; }`,
			leaf: "class", first: "super-user", last: "read-only",
			wantLen: func(c *Config) (string, bool) {
				for _, u := range c.System.Services.WebManagement.APIAuth.Users {
					if u.Username == "bob" {
						return u.Class, true
					}
				}
				return "", false
			},
		},
		{
			name: "per-user expires",
			body: `user bob { password "correct-horse-battery"; class read-only; expires 2099-01-01; expires 2020-01-01; }`,
			leaf: "expires", first: "2099-01-01", last: "2020-01-01",
			wantLen: func(c *Config) (string, bool) {
				for _, u := range c.System.Services.WebManagement.APIAuth.Users {
					if u.Username == "bob" {
						return u.ExpiresAt.Format("2006-01-02"), true
					}
				}
				return "", false
			},
		},
		{
			name: "per-key class",
			body: `key k1 { secret "machine-generated-key-for-api-auth"; expires 2099-01-01; class super-user; class read-only; }`,
			leaf: "class", first: "super-user", last: "read-only",
			wantLen: func(c *Config) (string, bool) {
				for _, k := range c.System.Services.WebManagement.APIAuth.Keys {
					if k.Name == "k1" {
						return k.Class, true
					}
				}
				return "", false
			},
		},
		{
			name: "per-key expires",
			body: `key k1 { secret "machine-generated-key-for-api-auth"; class read-only; expires 2099-01-01; expires 2020-01-01; }`,
			leaf: "expires", first: "2099-01-01", last: "2020-01-01",
			wantLen: func(c *Config) (string, bool) {
				for _, k := range c.System.Services.WebManagement.APIAuth.Keys {
					if k.Name == "k1" {
						return k.ExpiresAt.Format("2006-01-02"), true
					}
				}
				return "", false
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+" strict rejects", func(t *testing.T) {
			_, err := CompileConfig(apiAuthTree14448(t, tc.body))
			if err == nil {
				t.Fatalf("CompileConfig accepted conflicting duplicate %q (%q then %q)", tc.leaf, tc.first, tc.last)
			}
			for _, want := range []string{tc.leaf, tc.first, tc.last, "#14448"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not name %q", err.Error(), want)
				}
			}
		})
		t.Run(tc.name+" lenient warns and last wins", func(t *testing.T) {
			cfg, err := CompileConfigLenient(apiAuthTree14448(t, tc.body))
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected conflicting duplicate: %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, tc.leaf) && strings.Contains(w, tc.first) && strings.Contains(w, tc.last) && strings.Contains(w, "#14448") {
					found = true
				}
			}
			if !found {
				t.Fatalf("lenient warnings %v do not name conflicting duplicate %q %q/%q", cfg.Warnings, tc.leaf, tc.first, tc.last)
			}
			// ParseAPIAuthExpiry returns the day AFTER the named date
			// (exclusive expiry instant), so compare against last+1d via
			// the raw installed value rendered back.
			got, ok := tc.wantLen(cfg)
			if !ok {
				t.Fatalf("lenient compile did not install the credential for %s", tc.name)
			}
			want := tc.last
			if tc.leaf == "expires" {
				// installed = named date + 1 day
				switch tc.last {
				case "2020-01-01":
					want = "2020-01-02"
				case "2099-01-01":
					want = "2099-01-02"
				}
			}
			if got != want {
				t.Fatalf("lenient installed %q = %q, want last value %q (first-wins would give %q)", tc.leaf, got, want, tc.first)
			}
		})
		t.Run(tc.name+" node-aware strict rejects", func(t *testing.T) {
			if _, err := CompileConfigForNode(apiAuthTree14448(t, tc.body), 0); err == nil {
				t.Fatalf("CompileConfigForNode accepted conflicting duplicate %q", tc.leaf)
			}
		})
	}
}

func TestAPIAuthDuplicateScalarControls14448(t *testing.T) {
	t.Run("single values unchanged", func(t *testing.T) {
		cfg, err := CompileConfig(apiAuthTree14448(t, "class super-user;\nexpires 2099-01-01;\n"+`user bob { password "correct-horse-battery"; class read-only; expires 2030-06-15; }`+"\n"+`key k1 { secret "machine-generated-key-for-api-auth"; class super-user; expires 2031-01-01; }`))
		if err != nil {
			t.Fatalf("single-value api-auth rejected: %v", err)
		}
		auth := cfg.System.Services.WebManagement.APIAuth
		if auth.DefaultClass != "super-user" {
			t.Fatalf("DefaultClass = %q, want super-user", auth.DefaultClass)
		}
		if got := auth.DefaultExpiresAt.Format("2006-01-02"); got != "2099-01-02" {
			t.Fatalf("DefaultExpiresAt = %q, want 2099-01-02", got)
		}
		if len(auth.Users) != 1 || auth.Users[0].Class != "read-only" {
			t.Fatalf("users = %+v", auth.Users)
		}
		if len(auth.Keys) != 1 || auth.Keys[0].Class != "super-user" {
			t.Fatalf("keys = %+v", auth.Keys)
		}
	})

	t.Run("identical repeats compile", func(t *testing.T) {
		cfg, err := CompileConfig(apiAuthTree14448(t, "class read-only;\nclass read-only;\nexpires 2099-01-01;\nexpires 2099-01-01;\n"+apiAuthAlice14448))
		if err != nil {
			t.Fatalf("identical duplicate api-auth rejected: %v", err)
		}
		if got := cfg.System.Services.WebManagement.APIAuth.DefaultClass; got != "read-only" {
			t.Fatalf("DefaultClass = %q, want read-only", got)
		}
	})

	t.Run("no api-auth compiles", func(t *testing.T) {
		tree := mustParse(t, "system { host-name fw0; }")
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("config without api-auth rejected: %v", err)
		}
	})

	t.Run("gate unit: identical and single produce no conflict", func(t *testing.T) {
		for _, body := range []string{
			"class read-only;\n" + apiAuthAlice14448,
			"class read-only;\nclass read-only;\n" + apiAuthAlice14448,
			apiAuthAlice14448,
		} {
			warnings, err := validateAPIAuthDuplicateScalarAST(apiAuthTree14448(t, body), false)
			if err != nil || len(warnings) != 0 {
				t.Fatalf("body %q: warnings=%v err=%v, want none", body, warnings, err)
			}
		}
	})
}
