package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestLoadRescueConfigRedactedFailClosedOnParseError pins the #4099 Copilot
// follow-up: a malformed rescue.conf must fail CLOSED with a GENERIC,
// position-only error. It must NOT forward the raw config.ParseError text —
// ParseError.Error() embeds ParseError.Message, which the lexer/parser
// populates from the tampered file content (e.g. the offending character), and
// the whole point of the redacted rescue path is that a VIEW-only CLI caller
// never sees file-derived content it is not allowed to read.
//
// Before the fix the method returned fmt.Errorf("...: %v", perrs[0]), which
// rendered ParseError.Error() verbatim into the returned error. Reverting to
// that makes this test go RED (the raw parser detail — including the offending
// character from the file — reappears in the error).
func TestLoadRescueConfigRedactedFailClosedOnParseError(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	// A tampered/corrupt rescue.conf whose parse fails on an unexpected
	// character ('@', not a Junos identifier character) sitting immediately
	// after a secret-looking token. rescue.conf is written 0600 by the daemon
	// (#4056) and is normally always well-formed (SaveRescueConfig renders the
	// active tree); this simulates on-disk corruption / manual tampering.
	const secretSentinel = "PRESHAREDLEAKSENTINEL"
	malformed := "security {\n" +
		"    ike {\n" +
		"        policy p {\n" +
		"            pre-shared-key " + secretSentinel + "@ ;\n" +
		"        }\n" +
		"    }\n" +
		"}\n"
	rescuePath := filepath.Join(dir, "rescue.conf")
	if err := os.WriteFile(rescuePath, []byte(malformed), 0600); err != nil {
		t.Fatalf("write rescue.conf: %v", err)
	}

	// Independently derive the parser's detailed diagnostic, which the OLD code
	// forwarded (including its offending-character detail).
	_, perrs := config.NewParser(malformed).Parse()
	if len(perrs) == 0 {
		t.Fatalf("test setup: malformed rescue.conf parsed cleanly; adjust the fixture")
	}
	rawDetail := perrs[0].Message

	out, err := s.LoadRescueConfigRedacted()
	if err == nil {
		t.Fatalf("LoadRescueConfigRedacted() returned nil error on malformed rescue.conf; out=%q", out)
	}
	if out != "" {
		t.Errorf("LoadRescueConfigRedacted() returned non-empty output on parse failure: %q", out)
	}
	got := err.Error()

	// RED-on-revert: the raw parser detail (and the offending character it
	// carries) must not reach the VIEW-only CLI caller.
	if strings.Contains(got, rawDetail) {
		t.Errorf("error forwarded raw parser detail %q to the CLI caller:\n%s", rawDetail, got)
	}
	if strings.Contains(got, "unexpected character") {
		t.Errorf("error echoed the lexer's offending-character message:\n%s", got)
	}
	// The secret token body from the tampered file must never appear (guards
	// against a future parser message that embeds the offending token value).
	if strings.Contains(got, secretSentinel) {
		t.Errorf("error leaked secret token %q from the rescue file:\n%s", secretSentinel, got)
	}
	// Positive: the fix returns the generic, position-only fail-closed message.
	if !strings.Contains(got, "malformed") {
		t.Errorf("error is not the generic fail-closed message:\n%s", got)
	}
}
