package config

import (
	"strings"
	"testing"
)

// compiler_warn_checkip_redaction_6545_test.go: the commit-time malformed
// checkip-url warning must not echo the operator's credential (#6545 review,
// security MINOR — same leak class as the runtime one in pkg/ddns).
//
// validateSurfaceADDNSWarnings interpolated p.CheckIPURL RAW while the sibling
// url-template warning three lines above it already went through RedactURL. A
// commit warning is printed to the operator's terminal AND logged, so a
// checkip-url carrying an API key in its query put that key in both.

// checkIPWarnCredential is planted where an operator's key goes.
const checkIPWarnCredential = "COMMITWARN-CHECKIP-KEY-MUST-NOT-LOG"

// TestCheckIPURLWarningRedactsCredential is the fail-on-revert gate: restore the
// raw p.CheckIPURL and this fails by assertion naming the leaked sentinel.
func TestCheckIPURLWarningRedactsCredential(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"key in query", "ftp://checkip.example/?apikey=" + checkIPWarnCredential},
		{"key in userinfo", "ftp://user:" + checkIPWarnCredential + "@checkip.example/"},
		// The missing-'@' typo: the value does NOT parse, and RedactURL is
		// authority-bounded and keys on '@', so it returns this string
		// unchanged. Redacting is therefore not enough here — the URL has to be
		// omitted from the warning entirely, matching the pkg/ddns runtime gate.
		{"key lands in the port (missing @)", "http://user:" + checkIPWarnCredential + ".example/"},
		// Credential inside a malformed IP-literal host.
		{"key in an IP-literal host", "http://user:pass@[" + checkIPWarnCredential + "]/"},
		// PARSE-SUCCESS shapes that RedactURL returns UNCHANGED: a
		// scheme-relative authority (no "://" for its scan to anchor on) and a
		// fragment (never redacted). Only omitting the URL closes these.
		{"scheme-relative authority (parses)", "//user:" + checkIPWarnCredential + "@checkip.example/"},
		{"key in the fragment (parses)", "ftp://checkip.example/#apikey=" + checkIPWarnCredential},
		{"key in the fragment, no host (parses)", "http:///path#" + checkIPWarnCredential},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set system services dynamic-dns provider bad backend dyndns2",
				"set system services dynamic-dns provider bad server dyn.example",
				// Quoted: the set-command lexer treats a bare '?' as the help
				// token and '@' as punctuation, exactly as an operator must
				// quote a credentialed URL at the CLI.
				`set system services dynamic-dns provider bad checkip-url "` + tc.url + `"`,
			})
			// Lenient: since #14372 the strict gate hard-rejects a non-https
			// checkip-url, so the warning layer is exercised on a lenient load.
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			joined := strings.Join(validateSurfaceADDNSWarnings(cfg), "\n") +
				"\n" + strings.Join(cfg.Warnings, "\n")

			// Not vacuous: the warning must have fired at all.
			if !strings.Contains(joined, `provider "bad" checkip-url`) {
				t.Fatalf("no malformed-checkip-url warning was emitted for %q; got:\n%s\n"+
					"the redaction assertion below would be vacuous", tc.url, joined)
			}
			if strings.Contains(joined, checkIPWarnCredential) {
				t.Fatalf("the commit-time checkip-url warning echoed the credential in "+
					"cleartext:\n%s\nit must contain %q nowhere — the warning is shown to the "+
					"operator and written to the log. The strict gate renders the value "+
					"through RedactURL and the warning pass omits it entirely.", joined, checkIPWarnCredential)
			}
		})
	}
}
