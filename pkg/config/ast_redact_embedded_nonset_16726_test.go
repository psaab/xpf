package config

import (
	"errors"
	"strings"
	"testing"
)

// #16726 (R3-A20-02): the #14413 embedded-command redactor masked only a
// lexable lower-case `set` command. A stored command with any other shape —
// `delete … pre-shared-key ascii-text <v>`, mis-cased `Set …`, an unknown
// verb, or an unbalanced quote — committed clean and rendered the credential
// in cleartext on the PermView AST surfaces. The fix fails closed: every
// value token after a secret keyword is masked regardless of verb or case,
// and a command that does not lex cleanly is masked as a whole payload.

const secret16726 = "SECRET-16726-DISTINCTIVE"

func TestRedactEmbeddedNonSetVerbs16726(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		notContain string
		contain    string
	}{
		{"well-formed set control", "set security ike policy p1 pre-shared-key ascii-text " + secret16726, secret16726, "pre-shared-key ascii-text \"" + SecretDataPlaceholder + "\""},
		{"delete with PSK value", "delete security ike policy p1 pre-shared-key ascii-text " + secret16726, secret16726, SecretDataPlaceholder},
		{"mis-cased Set", "Set security ike policy p1 pre-shared-key ascii-text " + secret16726, secret16726, SecretDataPlaceholder},
		{"upper SET", "SET security ike policy p1 pre-shared-key ascii-text " + secret16726, secret16726, SecretDataPlaceholder},
		{"upper DELETE", "DELETE security ike policy p1 pre-shared-key ascii-text " + secret16726, secret16726, SecretDataPlaceholder},
		{"unknown verb", "frobnicate security ike policy p1 pre-shared-key ascii-text " + secret16726, secret16726, SecretDataPlaceholder},
		{"no verb", "security ike policy p1 pre-shared-key ascii-text " + secret16726, secret16726, SecretDataPlaceholder},
		{"bare secret keyword", "pre-shared-key ascii-text " + secret16726, secret16726, SecretDataPlaceholder},
		{"unbalanced quote set", `set security ike policy p1 pre-shared-key ascii-text "` + secret16726, secret16726, SecretDataPlaceholder},
		{"unbalanced quote delete", `delete security ike policy p1 pre-shared-key ascii-text "` + secret16726, secret16726, SecretDataPlaceholder},
		{"unbalanced quote unknown verb", `frobnicate security ike policy p1 pre-shared-key ascii-text "` + secret16726, secret16726, SecretDataPlaceholder},
		{"AD user-password via delete", "delete services user-identification active-directory-access user-name svc user-password " + secret16726, secret16726, SecretDataPlaceholder},
		{"AD user-password via Set", "Set services user-identification active-directory-access user-name svc user-password " + secret16726, secret16726, SecretDataPlaceholder},
		{"gated password via delete", "delete system archival configuration archive-sites https://example.com/dir password " + secret16726, secret16726, SecretDataPlaceholder},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactEmbeddedChangeConfigCommand(tc.in)
			if strings.Contains(got, tc.notContain) {
				t.Errorf("RedactEmbeddedChangeConfigCommand(%q) = %q, still contains the secret", tc.in, got)
			}
			if !strings.Contains(got, tc.contain) {
				t.Errorf("RedactEmbeddedChangeConfigCommand(%q) = %q, want substring %q", tc.in, got, tc.contain)
			}
		})
	}
}

func TestRedactEmbeddedNonSecretUnchanged16726(t *testing.T) {
	// No secret keyword, no URL credential: byte-identical, whatever the verb.
	for _, in := range []string{
		"delete security ike policy p1 pre-shared-key",
		"delete system host-name foo",
		"frobnicate system host-name foo",
		"Set system host-name foo",
		"set system host-name foo",
		"set interfaces gr-0-0-0 unit 0 tunnel key 12345",
		"delete interfaces gr-0-0-0 unit 0 tunnel key 12345",
		"",
	} {
		if got := RedactEmbeddedChangeConfigCommand(in); got != in {
			t.Errorf("RedactEmbeddedChangeConfigCommand(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestRedactEmbeddedUnlexableWholePayload16726(t *testing.T) {
	// The whole payload is replaced (not just the lexed prefix), so nothing
	// of the original — secret or not — survives, and a non-secret unlexable
	// command is masked too (it cannot be judged token-by-token).
	for _, in := range []string{
		`set system host-name "unterminated`,
		`delete system host-name "unterminated`,
		`frobnicate anything "unterminated`,
	} {
		got := RedactEmbeddedChangeConfigCommand(in)
		if got != SecretDataPlaceholder {
			t.Errorf("RedactEmbeddedChangeConfigCommand(%q) = %q, want whole-payload %q", in, got, SecretDataPlaceholder)
		}
	}
	// Whitespace-only does not lex-fail; it stays unchanged.
	if got := RedactEmbeddedChangeConfigCommand("   "); got != "   " {
		t.Errorf("whitespace command = %q, want unchanged", got)
	}
}

func TestRedactEmbeddedURLNonSet16726(t *testing.T) {
	// A bare URL truncates at `@` in the lenient lexer; the judged prefix
	// token (up to the credentials' `@`) is RedactURL-transformed and the
	// raw tail is never re-joined, so the password cannot render.
	const urlSecret = "URLPW-16726"
	in := "delete system archival configuration archive-sites https://user:" + urlSecret + "@host.example/dir"
	got := RedactEmbeddedChangeConfigCommand(in)
	if strings.Contains(got, urlSecret) || strings.Contains(got, "user:") {
		t.Errorf("delete URL command leaked credential: %q", got)
	}
	if !strings.Contains(got, SecretRedacted) {
		t.Errorf("delete URL command = %q, want RedactURL sentinel %q", got, SecretRedacted)
	}
	setIn := "set system archival configuration archive-sites https://user:" + urlSecret + "@host.example/dir password " + secret16726
	got = RedactEmbeddedChangeConfigCommand(setIn)
	if strings.Contains(got, urlSecret) || strings.Contains(got, secret16726) {
		t.Errorf("set URL+password command leaked: %q", got)
	}
}

// The AST surfaces: a hierarchical config carrying the four leaking shapes
// must mask on RedactedClone in every format and on FormatCompareRedacted,
// while the well-formed set control keeps its existing render.
func TestEmbeddedNonSetRedactedClone16726(t *testing.T) {
	text := `
event-options {
    policy p1 {
        events ping_test_failed;
        then {
            change-configuration {
                commands "delete security ike policy p1 pre-shared-key ascii-text ` + secret16726 + `";
                commands "Set security ike policy p1 pre-shared-key ascii-text ` + secret16726 + `";
                commands "frobnicate security ike policy p1 pre-shared-key ascii-text ` + secret16726 + `";
                commands "set security ike policy p1 pre-shared-key ascii-text ` + secret16726 + `";
                commands "set system host-name foo";
            }
        }
    }
}
`
	tree, errs := NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("NewParser: %v", errs)
	}
	redacted := tree.RedactedClone()
	for name, rendered := range map[string]string{
		"Format()":     redacted.Format(),
		"FormatSet()":  redacted.FormatSet(),
		"FormatJSON()": redacted.FormatJSON(),
		"FormatXML()":  redacted.FormatXML(),
	} {
		if strings.Contains(rendered, secret16726) {
			t.Errorf("%s leaked non-set embedded PSK:\n%s", name, rendered)
		}
		if !strings.Contains(rendered, SecretDataPlaceholder) {
			t.Errorf("%s did not render placeholder:\n%s", name, rendered)
		}
		if !strings.Contains(rendered, "set system host-name foo") {
			t.Errorf("%s dropped non-secret control:\n%s", name, rendered)
		}
	}
	// Live tree untouched.
	if !strings.Contains(tree.Format(), secret16726) {
		t.Errorf("source tree was mutated by RedactedClone:\n%s", tree.Format())
	}
	// Compare: changed non-set PSK diffs as changed, identical diffs clean,
	// neither renders a value.
	changed := strings.Replace(text, secret16726, "OTHER-16726", -1)
	changedTree, errs := NewParser(changed).Parse()
	if len(errs) != 0 {
		t.Fatalf("NewParser(changed): %v", errs)
	}
	diff := FormatCompareRedacted(tree, changedTree)
	if strings.Contains(diff, secret16726) || strings.Contains(diff, "OTHER-16726") {
		t.Errorf("FormatCompareRedacted leaked a PSK:\n%s", diff)
	}
	if !strings.Contains(diff, "secret fingerprint") {
		t.Errorf("FormatCompareRedacted (changed non-set PSK) lost fingerprint:\n%s", diff)
	}
	same := FormatCompareRedacted(tree, tree)
	if strings.Contains(same, secret16726) || strings.Contains(same, SecretDataPlaceholder) {
		t.Errorf("FormatCompareRedacted (identical) should render neither PSK nor placeholder:\n%s", same)
	}
}

// An unbalanced-quote command stored via the flat-set shape: the quoted
// payload token itself does not lex, so the whole token is masked.
func TestEmbeddedUnbalancedQuoteRedactedClone16726(t *testing.T) {
	// Build the node directly: the hierarchical parser would reject an
	// unterminated string, but a tolerant load / hand-built tree can carry
	// one, and RedactedClone must still fail closed on it.
	tree := &ConfigTree{Children: []*Node{{
		Keys: []string{"event-options", "policy", "p1", "then", "change-configuration", "commands",
			`set security ike policy p1 pre-shared-key ascii-text "` + secret16726},
		IsLeaf: true,
	}}}
	redacted := tree.RedactedClone()
	if strings.Contains(redacted.Format(), secret16726) {
		t.Errorf("RedactedClone leaked unbalanced-quote PSK:\n%s", redacted.Format())
	}
	if !strings.Contains(redacted.Format(), SecretDataPlaceholder) {
		t.Errorf("RedactedClone did not mask unbalanced-quote command:\n%s", redacted.Format())
	}
	if !strings.Contains(tree.Format(), secret16726) {
		t.Errorf("source tree mutated:\n%s", tree.Format())
	}
}

// Ingest symmetry (#16726 extends #15209): a redacted export of a non-set
// credential command must be refused, exactly as the set form is, while a
// value-less delete placeholder stays allowed (never produced by the
// redactor).
func TestEmbeddedNonSetPlaceholderIngestRefused16726(t *testing.T) {
	for name, cmd := range map[string]string{
		"delete with PSK placeholder":     "delete security ike policy p1 pre-shared-key ascii-text " + SecretDataPlaceholder,
		"Set with PSK placeholder":        "Set security ike policy p1 pre-shared-key ascii-text " + SecretDataPlaceholder,
		"frobnicate with PSK placeholder": "frobnicate security ike policy p1 pre-shared-key ascii-text " + SecretDataPlaceholder,
		"whole-payload placeholder":       SecretDataPlaceholder,
	} {
		t.Run(name, func(t *testing.T) {
			tree := embeddedIngest15209FlatTree(t,
				`set event-options policy p1 events ping_test_failed`,
				`set event-options policy p1 then change-configuration commands "`+cmd+`"`,
			)
			err := checkRedactionPlaceholder(tree)
			if err == nil {
				t.Fatalf("guard accepted %s:\n%s", name, tree.FormatSet())
			}
			if !errors.Is(err, errRedactionPlaceholderIngest) {
				t.Fatalf("err = %v, want errRedactionPlaceholderIngest", err)
			}
		})
	}
	// The redacted clone of a cleartext delete-PSK command is refused too:
	// build it through RedactedClone so the shape is proven to be one the
	// display path produces.
	cleartext := embeddedIngest15209FlatTree(t,
		`set event-options policy p1 events ping_test_failed`,
		`set event-options policy p1 then change-configuration commands "delete security ike policy p1 pre-shared-key ascii-text `+secret16726+`"`,
	)
	redacted := cleartext.RedactedClone()
	if !strings.Contains(redacted.FormatSet(), SecretDataPlaceholder) || strings.Contains(redacted.FormatSet(), secret16726) {
		t.Fatalf("RedactedClone precondition broken:\n%s", redacted.FormatSet())
	}
	if err := checkRedactionPlaceholder(redacted); !errors.Is(err, errRedactionPlaceholderIngest) {
		t.Fatalf("guard err = %v, want errRedactionPlaceholderIngest for redacted delete command", err)
	}
	// Cleartext delete-PSK ingests cleanly (only the placeholder is refused).
	if err := checkRedactionPlaceholder(cleartext); err != nil {
		t.Fatalf("guard rejected cleartext delete command: %v", err)
	}
}
