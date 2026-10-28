package config

import (
	"strings"
	"testing"
)

// #17806: the #16731 credential-shape arm (secretIndices) applied its
// substring classifier (token contains "secret"/"password") to EVERY
// flattened token — identifiers and values included — and masked every
// trailing token. A schema-legal login user named `password-admin`
// (`system login user <name>`, schema_system.go: the name slot is a
// ValidateLoginUsername identifier, and `class read-only` is schema
// schema_system.go:416-419) therefore rendered as
// `user ##SECRET-DATA## ##SECRET-DATA## ##SECRET-DATA##`, hiding ordinary
// account/RBAC configuration from PermView readers.
//
// The positional fix: the substring classifier may fire only where the
// token occupies a KEYWORD position (it resolves as the schema child /
// statement keyword at that point in the walk, or the path has left the
// modelled grammar — the open world — where a credential-shaped token
// is not a value slot and stays fail-closed, #16731). Identifier/value
// tokens never trigger masking by substring. All nine #16731 credential
// rows must still mask: in those rows the credential token is a
// keyword-position leaf name.

var nonSecretIdentifierRows17806 = []struct {
	name  string
	lines []string
	keep  []string
}{
	{
		// The issue's headline row: identifier `password-admin` plus
		// descendants `class read-only` must all stay visible.
		name: "login user password-admin class read-only",
		lines: []string{
			"set system login user password-admin class read-only",
			"set system login user password-admin uid 1001",
		},
		keep: []string{"password-admin", "class", "read-only", "uid", "1001"},
	},
	{
		// Exact `password` as the username.
		name: "login user password class",
		lines: []string{
			"set system login user password class super-user",
		},
		keep: []string{"user", "password", "class", "super-user"},
	},
	{
		// Exact `password` in another schema-legal username slot. The
		// generic api-auth password gate must not reinterpret the name.
		name:  "web API user password class",
		lines: []string{"set system services web-management api-auth user password class read-only"},
		keep:  []string{"password", "class", "read-only"},
	},
	{
		// Exact `secret` as the username.
		name: "login user secret class",
		lines: []string{
			"set system login user secret class operator",
		},
		keep: []string{"user", "secret", "class", "operator"},
	},
	{
		// Schema-legal identifier containing a secret substring plus
		// visible descendants.
		name:  "login user secret-agent class",
		lines: []string{"set system login user secret-agent class operator"},
		keep:  []string{"secret-agent", "class", "operator"},
	},
	{
		// Value-position control, unmodelled region: first token after
		// `description` is a value, not a keyword.
		name: "description secret-rotation",
		lines: []string{
			"set system description secret-rotation",
			"set security zones security-zone trust description contains-password-word",
		},
		keep: []string{"secret-rotation", "contains-password-word"},
	},
}

// TestIdentifierSubstringNotMasked17806 is the RED-on-revert net for the
// positional fix: identifier/value tokens containing (or equal to)
// "password"/"secret" keep themselves and every descendant visible, on
// every render surface.
func TestIdentifierSubstringNotMasked17806(t *testing.T) {
	for _, row := range nonSecretIdentifierRows17806 {
		t.Run(row.name, func(t *testing.T) {
			tree := buildRedactTree(t, row.lines)
			red := tree.RedactedClone()
			renders := map[string]string{
				"Format":     red.Format(),
				"FormatSet":  red.FormatSet(),
				"FormatJSON": red.FormatJSON(),
				"FormatXML":  red.FormatXML(),
			}
			for name, out := range renders {
				for _, keep := range row.keep {
					if !strings.Contains(out, keep) {
						t.Errorf("%s: non-secret token %q masked (over-redaction):\n%s", name, keep, out)
					}
				}
			}
			if strings.Contains(red.FormatSet(), SecretDataPlaceholder) {
				t.Errorf("FormatSet emitted placeholder for non-secret identifiers:\n%s", red.FormatSet())
			}
			if row.name == "login user password-admin class read-only" {
				// Hierarchical (braced) spelling of the headline row must
				// behave identically (dual AST shape).
				hier := parseHierText(t, "system {\n login {\n  user password-admin {\n   class read-only;\n  }\n }\n}\n")
				hout := hier.RedactedClone().FormatSet()
				for _, keep := range []string{"password-admin", "class", "read-only"} {
					if !strings.Contains(hout, keep) {
						t.Errorf("hierarchical: non-secret token %q masked:\n%s", keep, hout)
					}
				}
				if strings.Contains(hout, SecretDataPlaceholder) {
					t.Errorf("hierarchical: placeholder emitted for non-secret identifiers:\n%s", hout)
				}
			}
		})
	}
}

// TestCredentialUnderSubstringIdentifierStillMasked17806: a real
// credential under a substring-bearing identifier stays masked — the fix
// is positional, not a blanket exemption for subtrees under such names.
func TestCredentialUnderSubstringIdentifierStillMasked17806(t *testing.T) {
	lines := []string{
		"set system login user password-admin authentication encrypted-password LEAK17806-CRYPT",
		"set system services web-management api-auth user secret-agent password LEAK17806-API",
	}
	out := buildRedactTree(t, lines).RedactedClone().FormatSet()
	for _, leak := range []string{"LEAK17806-CRYPT", "LEAK17806-API"} {
		if strings.Contains(out, leak) {
			t.Errorf("credential %q leaked under identifier subtree:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, SecretDataPlaceholder) {
		t.Errorf("expected placeholder for masked credentials:\n%s", out)
	}
	for _, identifier := range []string{"password-admin", "secret-agent"} {
		if !strings.Contains(out, identifier) {
			t.Errorf("identifier %q masked along with its credential descendant:\n%s", identifier, out)
		}
	}
}

// TestCredentialShapeKeywordPosition17806 pins secretIndices directly:
// the same token fires in keyword position and does not fire in
// identifier/value position, and the #16731 rows keep masking.
func TestCredentialShapeKeywordPosition17806(t *testing.T) {
	// Identifier position (schema-modelled paths): no masking at all.
	for _, fp := range [][]string{
		{"system", "login", "user", "password-admin", "class", "read-only"},
		{"system", "login", "user", "password", "class", "super-user"},
		{"system", "login", "user", "secret", "class", "operator"},
		{"system", "description", "secret-rotation"},
	} {
		if got := secretIndices(fp); len(got) != 0 {
			t.Errorf("secretIndices(%v) = %v, want none (identifier/value position)", fp, got)
		}
	}
	// Keyword position (each #16731 row's credential token): trailing
	// tokens mask.
	for _, fp := range [][]string{
		{"interfaces", "pp0", "unit", "0", "ppp-options", "chap", "default-chap-secret", "V17806"},
		{"snmp", "v3", "snmp-community", "idx1", "community-name", "V17806"},
		{"system", "services", "dhcp-local-server", "group", "g1", "authentication", "password", "V17806"},
	} {
		got := secretIndices(fp)
		if len(got) == 0 || got[len(got)-1] != len(fp)-1 {
			t.Errorf("secretIndices(%v) = %v, want trailing value masked", fp, got)
		}
	}
}

// TestOpenWorldCredentialShapeStaysFailClosed17806 pins the #18384
// review fold: a credential-shaped leaf outside the modelled grammar
// must mask (fail-closed, #16731), while an identifier-shaped token
// there keeps trailing tokens visible.
func TestOpenWorldCredentialShapeStaysFailClosed17806(t *testing.T) {
	for _, fp := range [][]string{
		{"unmodelled-thing", "new-password", "LEAK17806-OPEN"},
		{"unmodelled-thing", "wifi-password", "LEAK17806-OPEN"},
		{"unmodelled-thing", "nested", "bind-secret", "LEAK17806-OPEN"},
		{"interfaces", "pp0", "unit", "0", "ppp-options", "chap", "password", "LEAK17806-OPEN"},
		{"services", "foo", "authentication", "auth-token", "LEAK17806-OPEN"},
	} {
		got := secretIndices(fp)
		if len(got) == 0 || got[len(got)-1] != len(fp)-1 {
			t.Errorf("secretIndices(%v) = %v, want open-world credential value masked", fp, got)
		}
	}
	// A bare unmodelled root is fail-closed even for identifier-shaped
	// tokens: position alone cannot distinguish an instance name from a
	// credential keyword there, so #16731's substring masking applies
	// (this is the pre-#17806 open-world behavior, kept deliberately).
	for _, fp := range [][]string{
		{"unmodelled", "password-admin", "class", "read-only"},
		{"unmodelled", "password", "class", "read-only"},
		{"unmodelled", "secret-agent", "class", "operator"},
	} {
		got := secretIndices(fp)
		if len(got) == 0 || got[len(got)-1] != len(fp)-1 {
			t.Errorf("secretIndices(%v) = %v, want fail-closed masking (open-world bare root)", fp, got)
		}
	}
}
