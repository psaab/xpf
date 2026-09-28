package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestMain points the reset handoff flag at a disposable directory for the
// whole package run. Every commit/sync path consults the flag, and most
// fixtures never set it: without this, tests would read the live
// /etc/xpf/.reset-handoff (absent on CI, and unreadable-as-non-root where
// /etc/xpf exists), failing closed for no reason related to the test.
// Per-test overrides (isolateHandoffFlag) save/restore around this value;
// no committing test in this package runs in parallel, so the shared path
// cannot race.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "daemon-reset-handoff")
	if err != nil {
		fmt.Fprintf(os.Stderr, "reset handoff test seam: %v\n", err)
		os.Exit(1)
	}
	configstore.ResetHandoffPath = filepath.Join(dir, ".reset-handoff")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
