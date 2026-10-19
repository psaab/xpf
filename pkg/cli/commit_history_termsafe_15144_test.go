package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #15144 (B01-03): legacy journal lines may carry control characters in
// Detail. The in-process CLI `show system commit history` renderer must
// termsafe-escape Detail so a legacy line renders as ONE escaped line.
//
// FAIL-ON-REVERT: print e.Detail raw in handleShowSystem and the raw
// newline/ESC assertions below fail.

func TestShowSystemCommitHistoryEscapesLegacyDetail15144(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"v":2,"timestamp":"2026-01-02T03:04:05Z","action":"commit","detail":"ok\n  9  forged\u001b[31m","principal":"unknown"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".config.journal"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := configstore.New(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	c := &CLI{store: store}
	var runErr error
	out := captureStdout(t, func() {
		runErr = c.handleShowSystem([]string{"commit", "history"})
	})
	if runErr != nil {
		t.Fatalf("handleShowSystem(commit history): %v", runErr)
	}
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
}
