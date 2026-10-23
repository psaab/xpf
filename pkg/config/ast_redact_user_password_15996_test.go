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
		if rendered == "" {
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
		cmd := "set services user-identification active-directory-access user-password " + secret
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
