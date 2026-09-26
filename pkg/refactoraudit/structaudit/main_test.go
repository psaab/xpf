package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingConfiguredRootsFailWithoutPartialOutput10901(t *testing.T) {
	goRoot := t.TempDir()
	rsRoot := t.TempDir()
	missingGoRoot := filepath.Join(t.TempDir(), "missing-go")
	missingRSRoot := filepath.Join(t.TempDir(), "missing-rs")
	if err := os.WriteFile(filepath.Join(goRoot, "fixture.go"), []byte("package fixture\ntype Example struct { Field int }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, missing := range []struct {
		language string
		path     string
		goRoots  string
		rsRoots  string
	}{
		{language: "Go", path: missingGoRoot, goRoots: missingGoRoot, rsRoots: rsRoot},
		{language: "Go after scanned root", path: missingGoRoot, goRoots: goRoot + " " + missingGoRoot, rsRoots: rsRoot},
		{language: "Rust", path: missingRSRoot, goRoots: goRoot, rsRoots: missingRSRoot},
	} {
		t.Run(missing.language, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			status := run([]string{
				"-skip", "x",
				"-go-roots", missing.goRoots,
				"-rs-roots", missing.rsRoots,
				"-all",
			}, &stdout, &stderr)
			if status != 1 {
				t.Fatalf("run status = %d, want 1; stderr: %s", status, stderr.String())
			}
			if !strings.Contains(stderr.String(), `configured root "`+missing.path+`" is unavailable`) {
				t.Errorf("stderr = %q, want missing root %q reported", stderr.String(), missing.path)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout contains partial audit output despite missing %s root: %q", missing.language, stdout.String())
			}
		})
	}
}
