package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// #18997: the redaction-placeholder guard picks the SECRET index
// (archive-sites … password ##SECRET-DATA##), then redactedLocName renders
// the flattened path up to the password keyword — which includes the
// preceding URL-classified archive-sites token. redactSecretPath masked
// secretIndices only, so the URL credential `pw` in scp://user:pw@host/dir
// rode into the guard error verbatim. The fix must apply RedactURL to
// URL-classified indices in the kept prefix (and collect URL values in the
// schema exit scrub), without changing WHICH configs are rejected.
//
// RED assertions: error is rejected with the placeholder sentinel, keeps
// the ##SECRET-DATA## masking spelling, names the archive-sites/password
// location, and contains neither `pw@` nor `user:pw`.
//
// Public commit-ingest path = SchemaValidate (schema_walk_entry.go:
// checkRedactionPlaceholder -> scrubSchemaErrorSecrets), the same gate
// TestRedactionPlaceholderIngestRejected and
// TestPlaceholderGuardNeverEchoesPrecedingSecret16066 use.
func TestPlaceholderGuardNeverEchoesPrecedingURLCredential18997(t *testing.T) {
	tree := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "scp://user:pw@host/dir" password "##SECRET-DATA##"`,
	})

	guard := checkRedactionPlaceholder(tree)
	if guard == nil {
		t.Fatalf("premise: guard must reject the placeholder fixture:\n%s", tree.FormatSet())
	}
	if !errors.Is(guard, errRedactionPlaceholderIngest) {
		t.Fatalf("guard err lost placeholder sentinel: %v", guard)
	}
	if strings.Contains(guard.Error(), "pw@") || strings.Contains(guard.Error(), "user:pw") {
		t.Errorf("guard error echoed the preceding URL credential (#18997): %v", guard)
	}
	if !strings.Contains(guard.Error(), "archive-sites") || !strings.Contains(guard.Error(), "password") {
		t.Errorf("guard error lost its archive-sites/password location: %v", guard)
	}
	// The URL-classified value keeps its diagnostic path, but RedactURL
	// masks userinfo; the raw-AST placeholder remains named in the sentinel.
	if !strings.Contains(guard.Error(), SecretDataPlaceholder) ||
		!strings.Contains(guard.Error(), "scp://<redacted>@host/dir") {
		t.Errorf("guard error lost placeholder/URL masking: %v", guard)
	}

	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("SchemaValidate must reject the placeholder fixture")
	}
	if !IsRedactionPlaceholderIngestError(err) {
		t.Fatalf("SchemaValidate err lost placeholder classification: %v", err)
	}
	if strings.Contains(err.Error(), "pw@") || strings.Contains(err.Error(), "user:pw") {
		t.Errorf("SchemaValidate error echoed the preceding URL credential (#18997): %v", err)
	}
	if !strings.Contains(err.Error(), SecretDataPlaceholder) ||
		!strings.Contains(err.Error(), "scp://<redacted>@host/dir") {
		t.Errorf("SchemaValidate error lost placeholder/URL masking: %v", err)
	}

	// Control: cleartext credential URL + cleartext password ingests
	// cleanly (rejection set unchanged — only the message changed).
	clean := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "scp://user:pw@host/dir" password "s3cr3t"`,
	})
	if err := checkRedactionPlaceholder(clean); err != nil {
		t.Fatalf("guard rejected cleartext archive-sites password: %v", err)
	}
	if err := SchemaValidate(clean); err != nil {
		t.Fatalf("SchemaValidate rejected cleartext archive-sites password: %v", err)
	}
}

// #18997 schema-exit-scrub surface: collectSecretValues collected direct
// secretIndices only, so a URL-classified value in the tree was never a
// scrub needle. An error built OUTSIDE the schema choke point (here: a
// foreign error echoing the credential URL, the exact shape
// scrubSchemaErrorSecrets exists to catch) must have the URL credential
// scrubbed at the SchemaValidate exit. Reachable cell: scrubSchemaErrorSecrets
// is the exit scrub itself; this drives it exactly as schemaValidateImpl does.
func TestSchemaExitScrubNeverEchoesURLValue18997(t *testing.T) {
	tree := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "scp://user:pw@host/dir" password "s3cr3t"`,
	})
	foreign := fmt.Errorf("archive fetch failed for scp://user:pw@host/dir password s3cr3t")
	got := scrubSchemaErrorSecrets(tree, foreign)
	if got == nil {
		t.Fatal("scrub returned nil for non-nil error")
	}
	if strings.Contains(got.Error(), "pw@") || strings.Contains(got.Error(), "user:pw") {
		t.Errorf("schema exit scrub echoed the URL credential (#18997): %v", got)
	}
	if strings.Contains(got.Error(), "s3cr3t") {
		t.Errorf("schema exit scrub echoed the direct secret (control): %v", got)
	}
}

// #18997 overlapping-needle arm (Kimi delta at b141027483): "@" and
// ":p@" are both RedactURL-transformed URL tokens; if the shorter "@"
// needle fires first, ":p@" is rewritten to ":p<redacted>" and the
// inline password stands. collectURLValues returns traversal order, so
// scrubSecretValuesText must apply needles longest-first (as
// collectSecretValues itself already sorts). Tree order below puts
// the short needle first on purpose.
func TestSchemaExitScrubOverlappingURLNeedles18997(t *testing.T) {
	tree := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "@" password "s3cr3t"`,
		`set system archival configuration archive-sites ":p@" password "s3cr3t"`,
	})
	foreign := fmt.Errorf("archive fetch failed for :p@")
	got := scrubSchemaErrorSecrets(tree, foreign)
	if strings.Contains(got.Error(), ":p@") || strings.Contains(got.Error(), ":p<") {
		t.Errorf("shorter URL needle corrupted the longer credential needle (#18997): %v", got)
	}
	if !strings.Contains(got.Error(), SecretRedacted) {
		t.Errorf("overlapping URL credential was not scrubbed at all: %v", got)
	}
}

// #18997 short-URL arm (Kimi seat): a credential-bearing URL token can be
// shorter than beltSecretValues' 4-byte floor ("a@b" is 3 bytes, ":p@"
// carries an inline password) yet is still transformed by RedactURL.
// collectSecretValues adds such tokens, but the belt dropped them, so
// the scrub had no needle and returned the foreign error verbatim.
// URL-classified needles now bypass the belt via collectURLValues.
func TestSchemaExitScrubShortURLCredential18997(t *testing.T) {
	for _, raw := range []string{"a@b", ":p@"} {
		if RedactURL(raw) == raw {
			t.Fatalf("premise: RedactURL must transform %q", raw)
		}
		tree := buildRedactTree(t, []string{
			`set system archival configuration archive-sites "` + raw + `" password "s3cr3t"`,
		})
		foreign := fmt.Errorf("archive fetch failed for %s", raw)
		got := scrubSchemaErrorSecrets(tree, foreign)
		if strings.Contains(got.Error(), raw) {
			t.Errorf("schema exit scrub echoed short URL credential %q (#18997): %v", raw, got)
		}
	}
}

// #18997 variant matrix (Sol/Kimi seats): the committed cells must pin
// more than the single password-bearing fixture — empty-password and
// percent-encoded userinfo, multiple archive sites, and a
// credential-free URL that must pass the new collection unchanged
// (no needle for a no-op RedactURL token).
func TestPlaceholderGuardURLVariantMatrix18997(t *testing.T) {
	for _, u := range []string{
		`scp://user:@host/dir`,       // empty password
		`scp://user:p%40ss@host/dir`, // percent-encoded password
	} {
		tree := buildRedactTree(t, []string{
			`set system archival configuration archive-sites "` + u + `" password "##SECRET-DATA##"`,
		})
		err := SchemaValidate(tree)
		if err == nil {
			t.Fatalf("premise: placeholder fixture must be rejected (%q)", u)
		}
		if strings.Contains(err.Error(), ":@") || strings.Contains(err.Error(), "p%40ss@") ||
			strings.Contains(err.Error(), "user:") {
			t.Errorf("variant %q leaked through SchemaValidate: %v", u, err)
		}
	}
	// Multiple archive sites: neither site's credential may echo.
	multi := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "scp://u1:p1@h1/d" password "##SECRET-DATA##"`,
		`set system archival configuration archive-sites "scp://u2:p2@h2/d" password "s3cr3t"`,
	})
	err := SchemaValidate(multi)
	if err == nil {
		t.Fatal("premise: multi-site placeholder fixture must be rejected")
	}
	if strings.Contains(err.Error(), "p1@") || strings.Contains(err.Error(), "p2@") ||
		strings.Contains(err.Error(), "u1:p1") || strings.Contains(err.Error(), "u2:p2") {
		t.Errorf("multi-site credential leaked: %v", err)
	}
	// Credential-free URL: RedactURL is a no-op, so collectURLValues must
	// not return it, and a foreign error naming it stays intact.
	free := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "https://host/dir" password "s3cr3t"`,
	})
	if got := collectURLValues(free); len(got) != 0 {
		t.Errorf("credential-free URL became a scrub needle: %v", got)
	}
}
