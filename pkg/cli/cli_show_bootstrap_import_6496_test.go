package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/bootstrapshow"
)

// These drive the console path end-to-end and capture os.Stdout via the
// package-local captureStdout helper (cluster_failover_test.go).

// #6496: `show system bootstrap-import` on the in-process console CLI.
//
// The whole reason this command exists is that the day-0 operator is standing
// at the console with this prompt open. RED on revert: remove the dispatcher
// case and handleShowSystem returns "unknown show system target".
func TestHandleShowSystemDispatchesBootstrapImport(t *testing.T) {
	const detail = `day-0 config REJECTED: unknown statement "dataplane-type"`
	// Wired through SetBootstrapImportFn, NOT by assigning the private field:
	// the setter is the seam the daemon actually uses, and a test that writes
	// the field directly stays green with the setter's body emptied.
	c := &CLI{}
	c.SetBootstrapImportFn(func() bootstrapshow.Snapshot {
		return bootstrapshow.Snapshot{
			Status:  bootstrapshow.StatusFailed,
			Error:   detail,
			UnixSec: 1755792000,
			Failed:  true,
		}
	})
	var err error
	out := captureStdout(t, func() { err = c.handleShowSystem([]string{"bootstrap-import"}) })
	if err != nil {
		t.Fatalf("handleShowSystem(bootstrap-import) error = %v", err)
	}
	if !strings.Contains(out, "import-failed") {
		t.Errorf("wired status not rendered on the console path:\n%s", out)
	}
	if !strings.Contains(out, detail) {
		t.Errorf("the console path must render the failure REASON — it is the "+
			"question the operator is asking, and /health cannot carry it "+
			"(#5031):\n%s", out)
	}
}

// The console rendering must be BYTE-IDENTICAL to the shared renderer, which
// is also what the gRPC ShowText path emits. Two operators looking at the same
// box through the console and through the remote `cli` must not be told
// different things about one recorded fact.
func TestConsoleBootstrapImportMatchesTheSharedRenderer(t *testing.T) {
	for _, snap := range []bootstrapshow.Snapshot{
		{Status: bootstrapshow.StatusOK, UnixSec: 1755792000},
		{Status: bootstrapshow.StatusLoadedDB, UnixSec: 1755792000},
		{Status: bootstrapshow.StatusNoConfig, UnixSec: 1755792000},
		{Status: bootstrapshow.StatusPending, UnixSec: 1755792000},
		{Status: bootstrapshow.StatusCredentialFailed, Error: "credential failure", UnixSec: 1755792000, Failed: true},
		{Status: bootstrapshow.StatusFailed, Error: "boom", UnixSec: 1755792000, Failed: true},
		{},
	} {
		c := &CLI{}
		c.SetBootstrapImportFn(func() bootstrapshow.Snapshot { return snap })
		out := captureStdout(t, func() { _ = c.handleShowSystem([]string{"bootstrap-import"}) })
		var want bytes.Buffer
		bootstrapshow.Render(&want, snap)
		if out != want.String() {
			t.Errorf("status %q: console render diverges from bootstrapshow.Render\n"+
				"--- console ---\n%s\n--- shared ---\n%s", snap.Status, out, want.String())
		}
	}
}

// A `cli` spawned outside the daemon has no hook. It must still print an
// explicit unrecorded state rather than nothing, which an operator would read
// as "no problem here".
func TestConsoleBootstrapImportWithNoHookStillRenders(t *testing.T) {
	c := &CLI{}
	out := captureStdout(t, func() { _ = c.handleShowSystem([]string{"bootstrap-import"}) })
	if !strings.Contains(out, "not-recorded") {
		t.Errorf("nil hook must render an explicit not-recorded state:\n%s", out)
	}
}
