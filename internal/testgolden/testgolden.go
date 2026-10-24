// Package testgolden provides the shared compare-or-write tail shared by
// byte-exact golden tests (#16201).
//
// String compares got against the explicit golden file at path. The path is
// always caller-supplied — never derived from t.Name() — because callers such
// as the 4406 matrix harness key baselines by cell, not by test name, and
// locate them relative to the source file rather than the working directory.
//
// Regeneration reuses the existing -update flag: pass -update to the test
// binary (go test ./pkg/... -update) and String writes got verbatim instead
// of comparing. No header line is ever added — golden files are the exact
// compared bytes.
//
// String is suitable only from the test goroutine: on update failure,
// missing baseline, or mismatch it calls t.Fatalf.
package testgolden

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// update regenerates golden fixtures instead of comparing against them.
// This is the sole registration of the -update flag; importing testgolden
// into a test binary that also defines -update panics at flag registration.
var update = flag.Bool("update", false, "regenerate golden fixtures")

// String asserts got is byte-identical to the file at path, or, with
// -update, writes got to path (creating parent directories). It adds no
// trailing newline or header; got must contain the exact intended bytes.
func String(t testing.TB, path, got string) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("testgolden: mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("testgolden: write golden %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("testgolden: read golden %s (run with -update to generate): %v", path, err)
	}
	if got != string(want) {
		t.Fatalf("testgolden: output diverged from golden %s (run with -update to regenerate after a deliberate, reviewed change).\n--- got ---\n%s\n--- want ---\n%s", path, got, string(want))
	}
}

// UpdateRequested reports whether -update regeneration was requested. It
// lets callers whose update path cannot be expressed as a single String
// write — notably the 4406 harness, which must suppress its bespoke
// mismatch diagnostics (writing the .actual.json sidecar and diffing cases)
// while regenerating — share the same -update flag without duplicating its
// registration. Callers should write their bytes and return when it reports
// true; String already handles that case for plain string goldens.
func UpdateRequested() bool {
	return *update
}
