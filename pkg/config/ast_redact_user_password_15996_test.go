package config

import (
	"strings"
	"testing"
)

// renders15996 renders tree through every PermView AST surface: full-tree
// formats plus the scoped (path) variants rooted at root, and compare.
func renders15996(t *testing.T, tree *ConfigTree, root string) map[string]string {
	t.Helper()
	red := tree.RedactedClone()
	path := []string{root}
	out := map[string]string{
		"Format":            red.Format(),
		"FormatSet":         red.FormatSet(),
		"FormatJSON":        red.FormatJSON(),
		"FormatXML":         red.FormatXML(),
		"Inheritance":       red.FormatInheritance(),
		"Compare":           FormatCompareRedacted(&ConfigTree{}, tree),
		"FormatPath":        red.FormatPathRedacted(path),
		"FormatPathSet":     red.FormatPathSetRedacted(path),
		"FormatPathJSON":    red.FormatPathJSONRedacted(path),
		"FormatPathXML":     red.FormatPathXMLRedacted(path),
		"FormatComparePath": FormatCompareRedactedAtPath(&ConfigTree{}, tree, path),
	}
	inh, err := tree.FormatPathInheritanceRedactedForNode(path, -1)
	if err != nil {
		t.Fatalf("FormatPathInheritanceRedactedForNode(%v): %v", path, err)
	}
	out["InheritanceScoped"] = inh
	return out
}

func assertMasked15996(t *testing.T, label string, tree *ConfigTree, root, secret, keep string) {
	t.Helper()
	for name, rendered := range renders15996(t, tree, root) {
		// The inheritance renderers legitimately render "" for a groups
		// scope (no inherited-from annotation); leak/placeholder checks
		// apply to every non-empty arm, emptiness only fails the others.
		if rendered == "" {
			if name == "Inheritance" || name == "InheritanceScoped" {
				continue
			}
			t.Errorf("%s/%s: render empty (test must not pass vacuously)", label, name)
			continue
		}
		if strings.Contains(rendered, secret) {
			t.Errorf("%s/%s leaked AD user-password in cleartext:\n%s", label, name, rendered)
		}
		if !strings.Contains(rendered, SecretDataPlaceholder) {
			t.Errorf("%s/%s did not render %s placeholder:\n%s", label, name, SecretDataPlaceholder, rendered)
		}
	}
	if keep != "" {
		red := tree.RedactedClone()
		if all := red.Format() + red.FormatSet(); !strings.Contains(all, keep) {
			t.Errorf("%s: non-secret %q masked in Format/FormatSet (over-redaction):\n%s", label, keep, all)
		}
		if strings.Contains(red.FormatSet(), secret) {
			t.Errorf("%s: secret leaked in FormatSet:\n%s", label, red.FormatSet())
		}
	}
}

// TestADUserPasswordRedacted15996 is the #15996 RED-on-revert net: the AD
// `user-password` leaf (pair: `user-name <bind-user>`) under
// active-directory-access was absent from every redaction list, so it rendered
// clear to PermView on every spelling/format. Removing "user-password" from
// secretIndices (ast_redact.go) makes every cell below leak.
func TestADUserPasswordRedacted15996(t *testing.T) {
	const secret = "LEAK-AD-USER-PASSWORD-15996"
	const user = "bind-svc-account"

	flat := []string{"active-directory-access", "user-name", user, "user-password", secret}

	shapes := []struct {
		name string
		root string
		tree *ConfigTree
		keep string
	}{
		{
			name: "flat services user-identification",
			root: "services",
			tree: buildRedactTree(t, []string{
				"set services user-identification " + strings.Join(flat, " "),
			}),
			keep: user,
		},
		{
			name: "flat security user-identification",
			root: "security",
			tree: buildRedactTree(t, []string{
				"set security user-identification " + strings.Join(flat, " "),
			}),
			keep: user,
		},
		{
			name: "flat security-root active-directory-access",
			root: "security",
			tree: buildRedactTree(t, []string{
				"set security " + strings.Join(flat, " "),
			}),
			keep: user,
		},
		{
			name: "flat services-root active-directory-access",
			root: "services",
			tree: buildRedactTree(t, []string{
				"set services " + strings.Join(flat, " "),
			}),
			keep: user,
		},
		{
			name: "hierarchical services user-identification",
			root: "services",
			tree: parseHierText(t, `services {
    user-identification {
        active-directory-access {
            user-name `+user+`;
            user-password `+secret+`;
        }
    }
}`),
			keep: user,
		},
		{
			name: "hierarchical security-root",
			root: "security",
			tree: parseHierText(t, `security {
    active-directory-access {
        user-name `+user+`;
        user-password `+secret+`;
    }
}`),
			keep: user,
		},
		{
			name: "flat services user-identification user-password only",
			root: "services",
			tree: buildRedactTree(t, []string{
				"set services user-identification active-directory-access user-password " + secret,
			}),
			keep: "",
		},
	}
	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			assertMasked15996(t, tc.name, tc.tree, tc.root, secret, tc.keep)
		})
	}

	// Embedded change-configuration command carrying the same leaf must mask
	// through the same secretIndices resolution.
	t.Run("embedded command", func(t *testing.T) {
		cmd := "set services user-identification active-directory-access user-name bind-svc-account user-password " + secret
		if got := RedactEmbeddedChangeConfigCommand(cmd); strings.Contains(got, secret) || !strings.Contains(got, SecretDataPlaceholder) {
			t.Errorf("embedded command leaked user-password: %q", got)
		}
	})

	// Ingest guard: a redacted export re-committed must be refused, not
	// silently stored with the placeholder as the literal credential. The
	// guard shares secretIndices, so this goes RED with the same revert.
	t.Run("placeholder ingest rejected", func(t *testing.T) {
		red := buildRedactTree(t, []string{
			"set services user-identification active-directory-access user-password " + secret,
		}).RedactedClone()
		if err := checkRedactionPlaceholder(red); err == nil {
			t.Fatalf("checkRedactionPlaceholder accepted redacted user-password export:\n%s", red.FormatSet())
		}
	})

	// Source tree keeps cleartext for HA sync / persistence (display-only).
	t.Run("source not mutated", func(t *testing.T) {
		tree := buildRedactTree(t, []string{
			"set services user-identification active-directory-access user-password " + secret,
		})
		_ = tree.RedactedClone()
		if !strings.Contains(tree.FormatSet(), secret) {
			t.Fatalf("source tree lost cleartext after RedactedClone:\n%s", tree.FormatSet())
		}
	})
}

// TestLoginUserNamedUserPasswordNotMasked15996 is the fold regression for the
// context gate: `user-password` is also a legal login USER NAME
// (`system login user user-password class … full-name …`), where the tokens
// after it are the account's class/full-name — an operator-visible identity,
// not a credential. The unqualified rule masked them; the gated rule must
// render the login stanza verbatim while the AD shapes above stay masked.
// Goes RED if the gate is dropped (class/full-name become placeholders).
func TestLoginUserNamedUserPasswordNotMasked15996(t *testing.T) {
	flat := buildRedactTree(t, []string{
		"set system login user user-password class super-user",
		`set system login user user-password full-name "AD Bind Helper"`,
	})
	for name, rendered := range map[string]string{
		"Format":    flat.RedactedClone().Format(),
		"FormatSet": flat.RedactedClone().FormatSet(),
	} {
		for _, want := range []string{"user-password", "super-user", "AD Bind Helper"} {
			if !strings.Contains(rendered, want) {
				t.Errorf("%s masked login identity token %q (over-redaction):\n%s", name, want, rendered)
			}
		}
		if strings.Contains(rendered, SecretDataPlaceholder) {
			t.Errorf("%s masked a login user named user-password:\n%s", name, rendered)
		}
	}
	hier := parseHierText(t, `system {
    login {
        user user-password {
            class super-user;
            full-name "AD Bind Helper";
        }
    }
}`)
	out := hier.RedactedClone().Format()
	for _, want := range []string{"user-password", "super-user", "AD Bind Helper"} {
		if !strings.Contains(out, want) {
			t.Errorf("hierarchical masked login identity token %q (over-redaction):\n%s", want, out)
		}
	}
	if strings.Contains(out, SecretDataPlaceholder) {
		t.Errorf("hierarchical masked a login user named user-password:\n%s", out)
	}
	// The placeholder-ingest guard must not refuse the login spelling either:
	// RedactedClone never masks it, so the literal is a real user name.
	if err := checkRedactionPlaceholder(flat); err != nil {
		t.Errorf("checkRedactionPlaceholder refused login user named user-password: %v", err)
	}
	// Control-char resolution agrees: class token after login user-password
	// is not a secret value.
	fp := []string{"system", "login", "user", "user-password", "class", "super-user"}
	if isSecretValueIndex(fp, 5) {
		t.Errorf("login class token wrongly marked secret: %v", fp)
	}
}

// TestGroupNamedIdentityDoesNotMaskLoginUser15996 is the fold-2 regression for
// the structural gate: a config GROUP named active-directory-access (or
// user-identification) puts those tokens earlier in the flattened path
// (`groups <name> system login user user-password class …`). The previous
// ancestor-scan gate masked the login user's class; the structural gate —
// (services|security) [user-identification] active-directory-access as the
// leaf's immediate parent chain at the root — must not. Goes RED if the gate
// regresses to containsAnyOf over ancestors.
func TestGroupNamedIdentityDoesNotMaskLoginUser15996(t *testing.T) {
	for _, group := range []string{"active-directory-access", "user-identification"} {
		t.Run(group, func(t *testing.T) {
			flat := buildRedactTree(t, []string{
				"set groups " + group + " system login user user-password class super-user",
				`set groups ` + group + ` system login user user-password full-name "AD Bind Helper"`,
			})
			hier := parseHierText(t, `groups {
    `+group+` {
        system {
            login {
                user user-password {
                    class super-user;
                }
            }
        }
    }
}`)
			for name, rendered := range map[string]string{
				"flat FormatSet": flat.RedactedClone().FormatSet(),
				"flat Format":    flat.RedactedClone().Format(),
				"hier Format":    hier.RedactedClone().Format(),
			} {
				for _, want := range []string{"user-password", "super-user"} {
					if !strings.Contains(rendered, want) {
						t.Errorf("%s masked login identity token %q under group %q (over-redaction):\n%s", name, want, group, rendered)
					}
				}
				if strings.Contains(rendered, SecretDataPlaceholder) {
					t.Errorf("%s masked a login user under group %q:\n%s", name, group, rendered)
				}
			}
			if got := flat.RedactedClone().FormatSet(); !strings.Contains(got, "AD Bind Helper") {
				t.Errorf("full-name masked under group %q:\n%s", group, got)
			}
			// Structural resolution agrees at the flattened-path level.
			fp := []string{"groups", group, "system", "login", "user", "user-password", "class", "super-user"}
			if isSecretValueIndex(fp, 7) {
				t.Errorf("group-named path wrongly marked secret: %v", fp)
			}
		})
	}
	// Positive structural controls: the exact leaf positions stay secret.
	for _, fp := range [][]string{
		{"services", "active-directory-access", "user-password", "x"},
		{"security", "active-directory-access", "user-password", "x"},
		{"services", "user-identification", "active-directory-access", "user-password", "x"},
		{"security", "user-identification", "active-directory-access", "user-password", "x"},
	} {
		if !isSecretValueIndex(fp, len(fp)-1) {
			t.Errorf("AD leaf position not marked secret: %v", fp)
		}
	}
	// Negative structural controls: same tokens, wrong position/root.
	for _, fp := range [][]string{
		{"groups", "active-directory-access", "system", "login", "user", "user-password", "class", "super-user"},
		{"system", "active-directory-access", "user-password", "x"},
		{"services", "foo", "active-directory-access", "user-password", "x"},
	} {
		if isSecretValueIndex(fp, len(fp)-1) {
			t.Errorf("non-AD position wrongly marked secret: %v", fp)
		}
	}
}

// TestGroupedADUserPasswordRedacted15996 is the fold-3 regression: the AD
// stanza DEFINED inside a config group (`groups g1 services
// user-identification …`, applied elsewhere via apply-groups) starts
// `groups <name>`, so the root-anchored structural gate missed it and the
// raw groups render leaked. The matcher now allows one leading
// `groups <name>` prefix; the login-user group shapes in
// TestGroupNamedIdentityDoesNotMaskLoginUser15996 (groups named after the
// identity stanzas, wrapping system login) stay unmasked because their
// chain after the prefix is system login, not services/security.
func TestGroupedADUserPasswordRedacted15996(t *testing.T) {
	const secret = "LEAK-AD-USER-PASSWORD-15996"
	const user = "bind-svc-account"

	shapes := []struct {
		name string
		tree *ConfigTree
	}{
		{
			name: "flat groups services user-identification",
			tree: buildRedactTree(t, []string{
				"set groups g1 services user-identification active-directory-access user-name " + user + " user-password " + secret,
				"set services apply-groups g1",
			}),
		},
		{
			name: "flat groups security-root",
			tree: buildRedactTree(t, []string{
				"set groups g1 security active-directory-access user-password " + secret,
			}),
		},
		{
			name: "hierarchical groups services user-identification",
			tree: parseHierText(t, `groups {
    g1 {
        services {
            user-identification {
                active-directory-access {
                    user-name `+user+`;
                    user-password `+secret+`;
                }
            }
        }
    }
}`),
		},
	}
	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			keep := user
			if tc.name == "flat groups security-root" {
				keep = ""
			}
			assertMasked15996(t, tc.name, tc.tree, "groups", secret, keep)
			// Raw group render + scoped/compare/inheritance arms, explicitly.
			red := tc.tree.RedactedClone()
			inh, err := tc.tree.FormatPathInheritanceRedactedForNode([]string{"groups"}, -1)
			if err != nil {
				t.Fatalf("inheritance render: %v", err)
			}
			for name, rendered := range map[string]string{
				"raw Format":        red.Format(),
				"raw FormatSet":     red.FormatSet(),
				"scoped FormatPath": red.FormatPathRedacted([]string{"groups"}),
				"compare":           FormatCompareRedacted(&ConfigTree{}, tc.tree),
				"compareAtPath":     FormatCompareRedactedAtPath(&ConfigTree{}, tc.tree, []string{"groups"}),
				"inheritanceScoped": inh,
			} {
				// The inheritance renderer legitimately renders "" for a
				// groups scope (groups carry no inherited-from annotation);
				// the leak check still applies whenever it renders, and the
				// placeholder is required only on the non-empty arms.
				if name == "inheritanceScoped" && rendered == "" {
					continue
				}
				if rendered == "" {
					t.Errorf("%s: render empty (must not pass vacuously)", name)
					continue
				}
				if strings.Contains(rendered, secret) {
					t.Errorf("%s leaked grouped AD user-password:\n%s", name, rendered)
				}
				if !strings.Contains(rendered, SecretDataPlaceholder) {
					t.Errorf("%s did not mask grouped AD user-password:\n%s", name, rendered)
				}
			}
		})
	}
	// Structural positives/negatives for the groups prefix.
	for _, fp := range [][]string{
		{"groups", "g1", "services", "user-identification", "active-directory-access", "user-password", "x"},
		{"groups", "g1", "security", "active-directory-access", "user-name", "u", "user-password", "x"},
		{"set", "groups", "g1", "services", "active-directory-access", "user-password", "x"},
	} {
		if !isSecretValueIndex(fp, len(fp)-1) {
			t.Errorf("grouped AD leaf not marked secret: %v", fp)
		}
	}
	for _, fp := range [][]string{
		{"groups", "active-directory-access", "system", "login", "user", "user-password", "class", "super-user"},
		{"groups", "g1", "system", "active-directory-access", "user-password", "x"},
	} {
		if isSecretValueIndex(fp, len(fp)-1) {
			t.Errorf("non-AD grouped position wrongly marked secret: %v", fp)
		}
	}
}

// TestADUserPasswordNotInSchemaPinnedSet15996 pins the filing constraint:
// user-password is unmodelled, so it MUST NOT enter the schema-pinned
// secretLeafKeywords set (TestSecretLeafKeywordsExistInSchema would fail);
// AST-side secretIndices is its only home. Control-char diagnostics still
// resolve it via secretIndices (secretValueIndicesFlat union).
func TestADUserPasswordNotInSchemaPinnedSet15996(t *testing.T) {
	if secretLeafKeywords["user-password"] {
		t.Fatal("user-password must not be added to schema-pinned secretLeafKeywords (#15996)")
	}
	if IsSecretLeafKeyword("user-password") {
		t.Fatal("IsSecretLeafKeyword must stay false for unmodelled user-password")
	}
	fp := []string{"services", "user-identification", "active-directory-access", "user-password", "LEAK-AD-USER-PASSWORD-15996"}
	if !isSecretValueIndex(fp, 4) {
		t.Fatalf("control-char/schema resolution does not mark user-password value secret: %v", fp)
	}
	// User-name sibling is NOT secret.
	fpUser := []string{"services", "user-identification", "active-directory-access", "user-name", "bind-svc-account"}
	if isSecretValueIndex(fpUser, 4) {
		t.Fatalf("user-name value wrongly marked secret: %v", fpUser)
	}
}
