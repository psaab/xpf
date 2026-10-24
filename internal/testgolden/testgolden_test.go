package testgolden

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fatalTB records Fatalf instead of aborting the test goroutine, so the
// mismatch/missing-file paths of String — which are fatal by contract — can
// be asserted without failing this test.
type fatalTB struct {
	testing.TB
	fatal string
}

func (f *fatalTB) Helper() {}

func (f *fatalTB) Fatalf(format string, args ...any) {
	// String's callers see a real *testing.T, whose Fatalf never returns;
	// mimic that so String does not continue past the failure.
	f.fatal = strings.TrimSpace(fmt.Sprintf(format, args...))
	panic(fatalPanic{})
}

type fatalPanic struct{}

func callString(tb *fatalTB, path, got string) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(fatalPanic); ok {
				panicked = true
				return
			}
			panic(r)
		}
	}()
	String(tb, path, got)
	return false
}

func TestStringCompareEqual(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.golden")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	String(t, path, "hello\n")
}

func TestStringMismatchIsFatalAndNamesPathAndUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "x.golden")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("want-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &fatalTB{}
	if !callString(fake, path, "got-bytes") {
		t.Fatalf("mismatch did not Fatalf; fatal=%q", fake.fatal)
	}
	if !strings.Contains(fake.fatal, path) {
		t.Errorf("mismatch message does not name path %q: %q", path, fake.fatal)
	}
	if !strings.Contains(fake.fatal, "got-bytes") || !strings.Contains(fake.fatal, "want-bytes") {
		t.Errorf("mismatch message does not show got and want: %q", fake.fatal)
	}
	if !strings.Contains(fake.fatal, "-update") {
		t.Errorf("mismatch message does not name -update regenerate command: %q", fake.fatal)
	}
}

func TestStringMissingFileIsFatalAndNamesUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.golden")
	fake := &fatalTB{}
	if !callString(fake, path, "anything") {
		t.Fatalf("missing file did not Fatalf; fatal=%q", fake.fatal)
	}
	if !strings.Contains(fake.fatal, path) || !strings.Contains(fake.fatal, "-update") {
		t.Errorf("missing-file message must name path and -update: %q", fake.fatal)
	}
}

func TestStringWritesExactBytesWithUpdate(t *testing.T) {
	old := *update
	*update = true
	defer func() { *update = old }()

	// Nested path proves String creates parent directories, and the
	// headerless exact-bytes write is what makes forced-regen-clean
	// (git status clean after -update) possible.
	path := filepath.Join(t.TempDir(), "a", "b", "x.golden")
	const got = "exact bytes\nno header\n"
	String(t, path, got)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != got {
		t.Fatalf("update wrote %q, want exact %q", string(b), got)
	}
	if !UpdateRequested() {
		t.Error("UpdateRequested() = false while -update set")
	}
}

func TestUpdateRequestedDefaultsFalse(t *testing.T) {
	if *update {
		t.Skip("-update passed to this test binary; default check not applicable")
	}
	if UpdateRequested() {
		t.Error("UpdateRequested() = true without -update")
	}
}
