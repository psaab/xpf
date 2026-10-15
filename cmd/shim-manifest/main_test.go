package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestRunRejectsPositionalArguments_13203(t *testing.T) {
	root := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"unexpected", "-repo-root", root}, &stdout, &stderr); code != 2 {
		t.Fatalf("run with positional argument returned %d, want 2; stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("rejected invocation wrote output: %q", stdout.String())
	}
	if _, err := filepath.Glob(filepath.Join(root, "pkg", "dataplane", "userspace_xdp_manifest.json")); err != nil {
		t.Fatal(err)
	}
}
