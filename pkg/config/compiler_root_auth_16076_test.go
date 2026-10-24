package config

import (
	"strings"
	"testing"
)

// #16076 (MGMT-14): `system login user root { authentication … }` compiled
// silently but was inert — the daemon skips root in applySystemLogin and
// the sudoers sweep, and nothing folds the stanza into RootAuthentication
// (root keys/password come only from `system root-authentication`).
// docs/system-login.md even called `user root authentication ssh-ed25519`
// "an ordinary way to give root a key", so an operator could believe root
// was key-locked when it was not.
//
// Fix: a commit warning naming `system root-authentication` whenever
// `user root` carries an `authentication` child, on both the strict and
// tolerant compile paths. The warning is keyed on the authored
// `authentication` child (authoredAuth in compileSystem), NOT on compiled
// credential values: the fold resets EncryptedPassword to "" before
// reading children, so a braced empty `authentication { }` would be
// indistinguishable from "never authored" by value — and Junos treats
// the authored container as the operator's credential intent either way.
//
// RED-on-revert: without the warning block in compileSystem every
// positive cell below fails (no warning names root-authentication);
// the negative controls (non-root user, root without authentication,
// root with only class) must stay quiet both before and after.

const rootAuthWarningMarker16076 = "system root-authentication"

func warningsContain16076(cfg *Config, marker string) bool {
	if cfg == nil {
		return false
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, marker) {
			return true
		}
	}
	return false
}

func rootWarnings16076(cfg *Config) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "user root") {
			out = append(out, w)
		}
	}
	return out
}

func TestRootUserAuthenticationWarns16076(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfirst root@host"
	hash := "$6$salt$hash"
	cases := []struct {
		name string
		text string
		sets []string
	}{
		{
			name: "braced ssh key",
			text: "system {\n login {\n  user root {\n   authentication {\n    ssh-ed25519 \"" + key + "\";\n   }\n  }\n }\n}\n",
		},
		{
			name: "braced encrypted-password",
			text: "system {\n login {\n  user root {\n   authentication {\n    encrypted-password \"" + hash + "\";\n   }\n  }\n }\n}\n",
		},
		{
			name: "braced empty authentication still authored",
			text: "system {\n login {\n  user root {\n   authentication {\n   }\n  }\n }\n}\n",
		},
		{
			name: "flat-set ssh key",
			sets: []string{`set system login user root authentication ssh-ed25519 "` + key + `"`},
		},
		{
			name: "flat-set encrypted-password",
			sets: []string{`set system login user root authentication encrypted-password "` + hash + `"`},
		},
		{
			name: "root auth beside class still warns for auth only",
			text: "system {\n login {\n  user root {\n   class super-user;\n   authentication {\n    ssh-rsa \"ssh-rsa AAAAB3NzaC1yc2E root@host\";\n   }\n  }\n }\n}\n",
		},
		{
			name: "two login sibling blocks, root auth in first warns",
			text: "system {\n login {\n  user root {\n   authentication {\n    ssh-ed25519 \"" + key + "\";\n   }\n  }\n }\n login {\n  user alice {\n   class super-user;\n   authentication {\n    ssh-ed25519 \"" + key + "\";\n   }\n  }\n }\n}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, lenient := range []bool{false, true} {
				var cfg *Config
				var err error
				if tc.text != "" {
					tree, perrs := NewParser(tc.text).Parse()
					if len(perrs) != 0 {
						t.Fatalf("parse: %v", perrs)
					}
					if lenient {
						cfg, err = CompileConfigLenient(tree)
					} else {
						cfg, err = CompileConfig(tree)
					}
				} else {
					tree := &ConfigTree{}
					for _, l := range tc.sets {
						path, perr := ParseSetCommand(l)
						if perr != nil {
							t.Fatalf("ParseSetCommand(%q): %v", l, perr)
						}
						if serr := tree.SetPath(path); serr != nil {
							t.Fatalf("SetPath(%q): %v", l, serr)
						}
					}
					if lenient {
						cfg, err = CompileConfigLenient(tree)
					} else {
						cfg, err = CompileConfig(tree)
					}
				}
				if err != nil {
					t.Fatalf("lenient=%v compile must succeed (warning, not rejection): %v", lenient, err)
				}
				if !warningsContain16076(cfg, rootAuthWarningMarker16076) {
					t.Errorf("lenient=%v: no warning names %q; warnings=%v (#16076)", lenient, rootAuthWarningMarker16076, cfg.Warnings)
				}
				if !warningsContain16076(cfg, "ignored") {
					t.Errorf("lenient=%v: warning must say the stanza is ignored; warnings=%v (#16076)", lenient, cfg.Warnings)
				}
				// The compiled root entry must NOT be folded into
				// RootAuthentication: the warning is the fix, not a
				// silent wiring of the inert stanza.
				if cfg.System.RootAuthentication != nil {
					t.Errorf("lenient=%v: user root authentication folded into RootAuthentication %+v; it must stay inert-but-warned (#16076)", lenient, cfg.System.RootAuthentication)
				}
			}
		})
	}
}

// Negative controls: shapes that must NOT warn. `user root class` is
// honoured (CLI class decision), a non-root user's authentication is
// applied, and root-authentication itself is the real stanza.
func TestRootUserAuthenticationQuietControls16076(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfirst user@host"
	hash := "$6$salt$hash"
	cases := []struct {
		name string
		text string
		sets []string
	}{
		{
			name: "root with only class",
			text: "system {\n login {\n  user root {\n   class super-user;\n  }\n }\n}\n",
		},
		{
			name: "root with only uid",
			sets: []string{"set system login user root uid 1000"},
		},
		{
			name: "root with no children",
			text: "system {\n login {\n  user root {\n  }\n }\n}\n",
		},
		{
			name: "non-root user with authentication",
			text: "system {\n login {\n  user alice {\n   class super-user;\n   authentication {\n    ssh-ed25519 \"" + key + "\";\n    encrypted-password \"" + hash + "\";\n   }\n  }\n }\n}\n",
		},
		{
			name: "real root-authentication stanza",
			text: "system {\n root-authentication {\n  ssh-ed25519 \"" + key + "\";\n }\n login {\n  user alice {\n   class super-user;\n   authentication {\n    ssh-ed25519 \"" + key + "\";\n   }\n  }\n }\n}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg *Config
			var err error
			if tc.text != "" {
				cfg, err = compileLogin6662(t, tc.text)
			} else {
				cfg, err = compileLogin6662FlatSet(t, tc.sets...)
			}
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got := rootWarnings16076(cfg); len(got) != 0 {
				t.Errorf("unexpected user-root warning for %q: %v (#16076)", tc.name, got)
			}
		})
	}
}
