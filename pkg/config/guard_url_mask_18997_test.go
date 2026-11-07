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
