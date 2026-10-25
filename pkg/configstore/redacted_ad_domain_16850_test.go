package configstore

import (
	"path/filepath"
	"strings"
	"testing"
)

// #16850: the three domain-scoped AD spellings that leaked through the
// #15996 exact-parent-chain gate must commit through strict Commit and
// mask on every ShowActive{,Set,JSON,XML}Redacted PermView surface, while
// the #15996 login-user controls (a login user NAMED user-password) stay
// unmasked. Mirrors the executed probe in the issue:
// `ADA domain example.com user-password S`,
// `ADA domain-name example.com user-password S`, and
// `ADA domain example.com user-name bind user-password S` leaked on
// [text set json xml]; root ADA / ADA `user-name bind` / generic
// `password` controls were already masked.
func TestShowRedactedADDomainScope16850(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"services user-identification active-directory-access domain example.com user-password LEAK16850-DOMAIN",
		"services user-identification active-directory-access domain-name example.com user-password LEAK16850-DOMAINNAME",
		"services user-identification active-directory-access domain example.com user-name bind user-password LEAK16850-DOMAINUSER",
		// #15996 positive controls (already masked pre-fix).
		"security user-identification active-directory-access user-password LEAK16850-ROOT",
		"services user-identification active-directory-access domain other.example user bind password LEAK16850-GENERIC",
		// #15996 login-user controls: must stay unmasked.
		"system login user user-password class super-user",
	}
	secrets := []string{"LEAK16850-DOMAIN", "LEAK16850-DOMAINNAME", "LEAK16850-DOMAINUSER", "LEAK16850-ROOT", "LEAK16850-GENERIC"}
	for _, line := range lines {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit (premise: rows commit clean through strict commit): %v", err)
	}
	s.ExitConfigure()
	for name, rendered := range map[string]string{
		"text": s.ShowActiveRedacted(nil),
		"set":  s.ShowActiveSetRedacted(nil),
		"json": s.ShowActiveJSONRedacted(nil),
		"xml":  s.ShowActiveXMLRedacted(nil),
	} {
		if rendered == "" {
			t.Errorf("%s: render empty (must not pass vacuously)", name)
			continue
		}
		for _, sec := range secrets {
			if strings.Contains(rendered, sec) {
				t.Errorf("%s redacted leaked %q:\n%s", name, sec, rendered)
			}
		}
		if !strings.Contains(rendered, "##SECRET-DATA##") {
			t.Errorf("%s redacted missing placeholder:\n%s", name, rendered)
		}
		// Login-user control stays legible: the account named
		// user-password and its class are identity, not credential.
		if !strings.Contains(rendered, "user-password") || !strings.Contains(rendered, "super-user") {
			t.Errorf("%s redacted masked login user named user-password (over-redaction):\n%s", name, rendered)
		}
		// Non-secret AD interior stays legible.
		if !strings.Contains(rendered, "example.com") {
			t.Errorf("%s redacted masked non-secret domain token (over-redaction):\n%s", name, rendered)
		}
	}
}
