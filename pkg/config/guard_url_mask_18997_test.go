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
// ":p@" are both RedactURL-transformed URL tokens; sequential
// replacement in traversal order rewrites ":p@" to ":p<redacted>" and
// the inline password stands. Occurrences now span-merge over the
// original text, so order no longer matters; tree order below still
// puts the short needle first on purpose.
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

// #18997 partial-overlap arm (Kimi delta at 72276114f0): two needles of
// equal length can overlap PARTIALLY — "user:pw@host" and "@host?SECRET"
// share "@host", so whichever fires first destroys the other's match
// and leaves the non-overlapped credential half standing ("?SECRET" or
// "user:pw"). Sequential ordering cannot fix this; occurrences
// span-merge over the original text so both needles' union is
// redacted in one pass. A needle that is a SUBSTRING of the sentinel
// ("redacted") is pre-existing cosmetic surface (it can rewrite an
// already-rendered "<redacted>" in construction-time text); a needle
// CONTAINING the sentinel is a real credential, pinned separately.
func TestSchemaExitScrubPartiallyOverlappingURLNeedles18997(t *testing.T) {
	for _, lines := range [][]string{
		{
			`set system archival configuration archive-sites "user:pw@host" password "redacted"`,
			`set system archival configuration archive-sites "@host?SECRET" password "s3cr3t"`,
		},
		{
			`set system archival configuration archive-sites "@host?SECRET" password "s3cr3t"`,
			`set system archival configuration archive-sites "user:pw@host" password "redacted"`,
		},
	} {
		tree := buildRedactTree(t, lines)
		foreign := fmt.Errorf("archive fetch failed for user:pw@host?SECRET")
		got := scrubSchemaErrorSecrets(tree, foreign).Error()
		if strings.Contains(got, "user:pw") || strings.Contains(got, "SECRET") {
			t.Errorf("partially overlapping needle left a credential half (#18997): %v", got)
		}
		if strings.Contains(got, "<<redacted>>") {
			t.Errorf("sentinel-containing needle corrupted the redaction sentinel: %v", got)
		}
	}
}


// Escaped arm of the same cell shape: a sentinel-containing credential
// with a newline renders under %q with escapes; raw-only spanning (the
// first sentinel fix) cannot match it. The unified span pass covers
// raw, Quote, and interior forms, so the %q text is scrubbed too.
// #18997 sentinel-cross-overlap arm (Sol fold at f33328217a): an ordinary
// credential partially overlapping a sentinel-containing one must
// merge with its span — a text pre-pass that replaces the sentinel
// value BEFORE spanning destroys the ordinary needle's match in the
// original text and leaves its non-overlapped half standing. Both
// needles below are whole archive-sites values; the foreign error
// carries their concatenation, quoted.
func TestSchemaExitScrubPivotCrossOverlap18997(t *testing.T) {
	tree := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "user:pw@host" password "s3cr3t"`,
		`set system archival configuration archive-sites "@host<redacted>" password "s3cr3t"`,
	})
	foreign := fmt.Errorf("archive fetch failed for %q", "user:pw@host<redacted>")
	got := scrubSchemaErrorSecrets(tree, foreign).Error()
	if strings.Contains(got, "user:pw") || strings.Contains(got, "@host") {
		t.Errorf("ordinary needle cross-destroyed by sentinel span (#18997): %v", got)
	}
	if strings.Contains(got, "xpf-redacted-pivot") {
		t.Errorf("removed pivot marker present in diagnostic: %v", got)
	}
}

func TestSchemaExitScrubSentinelContainingEscapedCredential18997(t *testing.T) {
	secret := "only<redacted>credential\nTAIL"
	tree := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "scp://u:p@h/d" password "` + secret + `"`,
	})
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("premise: escaped sentinel-containing password must validate: %v", err)
	}
	foreign := fmt.Errorf("archive fetch failed with password %q", secret)
	got := scrubSchemaErrorSecrets(tree, foreign).Error()
	if strings.Contains(got, "TAIL") || strings.Contains(got, "only<redacted>credential") {
		t.Errorf("escaped sentinel-containing credential echoed (#18997): %v", got)
	}
	if strings.Contains(got, "<<redacted>>") {
		t.Errorf("sentinel corrupted by scrub substitution: %v", got)
	}
}

// Sentinel-emission pin: a sentinel-containing span merges with
// ordinary spans and yields exactly one sentinel in raw and
// %q-rendered diagnostics (direct emission; matching reads the
// original text, so inserted sentinels are never re-matched).
func TestSchemaExitScrubPivotRewrittenOnce18997(t *testing.T) {
	tree := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "@host<redacted>" password "s3cr3t"`,
	})
	for _, foreign := range []error{
		fmt.Errorf("archive fetch failed for @host<redacted>"),
		fmt.Errorf("archive fetch failed for %q", "@host<redacted>"),
	} {
		got := scrubSchemaErrorSecrets(tree, foreign).Error()
		if strings.Contains(got, "xpf-redacted-pivot") || strings.Contains(got, "@host") {
			t.Errorf("sentinel span not emitted as one sentinel (#18997): %v", got)
		}
		if n := strings.Count(got, SecretRedacted); n != 1 {
			t.Errorf("merged sentinel span must yield exactly one sentinel, got %d: %v", n, got)
		}
	}
}

// #18997 nested-quote arm (Kimi close at a734ceba1c): a value rendered
// inside one %q string and embedded in a SECOND %q rendering appears
// with its interior doubly escaped; no raw/Quote/interior needle
// occurs. The doubly-escaped interior form is spanned.
func TestSchemaExitScrubNestedQuotedCredential18997(t *testing.T) {
	secret := "only<redacted>credential\nTAIL"
	tree := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "scp://u:p@h/d" password "` + secret + `"`,
	})
	foreign := fmt.Errorf("diag %q", fmt.Sprintf("prefix %q suffix", secret))
	got := scrubSchemaErrorSecrets(tree, foreign).Error()
	if strings.Contains(got, "TAIL") || strings.Contains(got, "credential") {
		t.Errorf("nested-quoted credential echoed (#18997): %v", got)
	}
}

// #18997 sentinel-containing credential arm (Kimi delta at 6f14ef160e):
// a password that merely CONTAINS the sentinel spelling
// ("only<redacted>credential") is a real credential — dropping its
// needle (the first span implementation) fails OPEN. Such values
// join the same span pass; because matching reads the original
// text, an inserted sentinel is never re-matched by a "redacted"
// needle within the call; all forms span-merge.
func TestSchemaExitScrubSentinelContainingCredential18997(t *testing.T) {
	tree := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "scp://u:p@h/d" password "only<redacted>credential"`,
	})
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("premise: sentinel-containing password must validate: %v", err)
	}
	foreign := fmt.Errorf("archive fetch failed with password only<redacted>credential")
	got := scrubSchemaErrorSecrets(tree, foreign).Error()
	if strings.Contains(got, "only<redacted>credential") {
		t.Errorf("sentinel-containing credential echoed (#18997): %v", got)
	}
	if strings.Contains(got, "<<redacted>>") {
		t.Errorf("sentinel corrupted by its own needle: %v", got)
	}
}

// #18997 quoted-overlap arm (Sol/Kimi deltas at 6f14ef160e): the span
// pass must cover the QUOTED and quoted-interior renderings too, not
// only raw occurrences. Values carrying a newline render under %q
// with \n escapes, so the diagnostic text contains neither raw value
// whole; their interior forms overlap partially ("user:pw\nw@host"
// and "w@host\n?SECRET" share "w@host\n"). Sequential interior
// replacement leaves a credential half standing in either order
// (parent probe); only span-merging the interior forms covers it.
// Drives the exit scrub SchemaValidate applies, with the foreign
// %q-error shape that surface exists to catch.
func TestSchemaValidateQuotedOverlapNeverEchoes18997(t *testing.T) {
	tree := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "user:pw\nw@host" password "s3cr3t"`,
		`set system archival configuration archive-sites "w@host\n?SECRET" password "s3cr3t"`,
	})
	foreign := fmt.Errorf("archive fetch failed for %q", "user:pw\nw@host\n?SECRET")
	got := scrubSchemaErrorSecrets(tree, foreign).Error()
	if strings.Contains(got, "user:pw") {
		t.Errorf("quoted partially-overlapping userinfo echoed (#18997): %v", got)
	}
	if strings.Contains(got, "SECRET") {
		t.Errorf("quoted partially-overlapping query credential echoed (#18997): %v", got)
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
