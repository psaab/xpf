package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #15144 (B01-03): legacy journal lines written before the store-boundary
// rejection may carry control characters in Detail. The gRPC
// `show system commit history` renderer must termsafe-escape Detail so a
// legacy line renders as ONE escaped line, not forged rows / escapes.
//
// FAIL-ON-REVERT: print e.Detail raw in showCommitHistory and the raw
// newline/ESC assertions below fail.

func TestShowCommitHistoryEscapesLegacyDetail15144(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"v":2,"timestamp":"2026-01-02T03:04:05Z","action":"commit","detail":"ok\n  9  forged\u001b[31m","principal":"unknown"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".config.journal"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	srv := &Server{store: store}
	var buf strings.Builder
	if err := srv.showCommitHistory(&buf); err != nil {
		t.Fatalf("showCommitHistory: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("raw ESC survived in rendered history: %q", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("rendered history must be exactly one line, got %q", out)
	}
	if !strings.Contains(out, `\x0a`) || !strings.Contains(out, `\x1b`) {
		t.Fatalf("rendered history must contain visible escapes, got %q", out)
	}
	if !strings.Contains(out, "forged") {
		t.Fatalf("rendered history lost the detail text: %q", out)
	}

	// Control: a clean detail renders verbatim.
	dir2 := t.TempDir()
	clean := `{"v":2,"timestamp":"2026-01-02T03:04:05Z","action":"commit","detail":"rotated vpn psk","principal":"unknown"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir2, ".config.journal"), []byte(clean), 0o600); err != nil {
		t.Fatal(err)
	}
	srv2 := &Server{store: newConfigStore(t, filepath.Join(dir2, "xpf.conf"))}
	var buf2 strings.Builder
	if err := srv2.showCommitHistory(&buf2); err != nil {
		t.Fatalf("showCommitHistory(clean): %v", err)
	}
	if !strings.Contains(buf2.String(), "rotated vpn psk") || strings.Count(buf2.String(), "\n") != 1 {
		t.Fatalf("clean history rendered wrong: %q", buf2.String())
	}
}
