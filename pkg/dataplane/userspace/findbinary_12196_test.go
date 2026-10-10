package userspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #12196: findBinary accepted an implicit cwd/build-tree/argv0-relative
// candidate on os.Stat success alone — including a directory or a 0644 stale
// artifact — ahead of a working PATH executable. cmd.Start then failed and the
// caller aborted bring-up rather than trying the valid candidate.
//
// These cells are intentionally NOT parallel: they chdir into a fixture cwd and
// rewrite PATH, both process-global. Sequential top-level tests run before any
// parallel ones, so the chdir cannot race the package's t.Parallel() cells.

const findBinaryName12196 = "xpf-userspace-dp"

// setupFindBinaryShadow12196 builds the shadowing fixture: a non-executable
// 0644 ./xpf-userspace-dp in the test's cwd plus an executable helper of the
// same name on PATH. Discovery must skip the stale artifact and return the
// PATH entry.
func setupFindBinaryShadow12196(t *testing.T) (wantPATH string) {
	t.Helper()
	cwd := t.TempDir()
	stale := filepath.Join(cwd, findBinaryName12196)
	if err := os.WriteFile(stale, []byte("# stale packaging residue\n"), 0o644); err != nil {
		t.Fatalf("write stale cwd artifact: %v", err)
	}
	bin := t.TempDir()
	helper := filepath.Join(bin, findBinaryName12196)
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write PATH helper: %v", err)
	}
	t.Chdir(cwd)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return helper
}

func TestFindBinarySkipsNonExecutableCwdArtifact12196(t *testing.T) {
	want := setupFindBinaryShadow12196(t)
	got, err := findBinary("")
	if err != nil {
		t.Fatalf("findBinary(\"\") = error %v, want %s", err, want)
	}
	if got != want {
		t.Fatalf("findBinary(\"\") = %q, want PATH candidate %q", got, want)
	}
}

func TestFindBinarySkipsDirectoryCwdCandidate12196(t *testing.T) {
	cwd := t.TempDir()
	if err := os.Mkdir(filepath.Join(cwd, findBinaryName12196), 0o755); err != nil {
		t.Fatalf("mkdir directory candidate: %v", err)
	}
	bin := t.TempDir()
	helper := filepath.Join(bin, findBinaryName12196)
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write PATH helper: %v", err)
	}
	t.Chdir(cwd)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	got, err := findBinary("")
	if err != nil {
		t.Fatalf("findBinary(\"\") = error %v, want %s", err, helper)
	}
	if got != helper {
		t.Fatalf("findBinary(\"\") = %q, want PATH candidate %q", got, helper)
	}
}

func TestFindBinaryExplicitNonExecutableIsInformativeError12196(t *testing.T) {
	fallback := setupFindBinaryShadow12196(t)
	stale := filepath.Join(t.TempDir(), findBinaryName12196)
	if err := os.WriteFile(stale, []byte("# stale packaging residue\n"), 0o644); err != nil {
		t.Fatalf("write explicit artifact: %v", err)
	}
	if got, err := findBinary(stale); err == nil {
		t.Fatalf("findBinary(%q) = %q, want informative not-executable error (must not fall back to %q)", stale, got, fallback)
	} else if !strings.Contains(err.Error(), stale) || !strings.Contains(err.Error(), "executable") {
		t.Fatalf("findBinary(%q) error %q must name the path and say it is not executable", stale, err)
	}
}

func TestFindBinaryExplicitMissingKeepsNotFoundError12196(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-helper")
	if _, err := findBinary(missing); err == nil {
		t.Fatalf("findBinary(%q) = success, want not-found error", missing)
	} else if !strings.Contains(err.Error(), "not found") || !strings.Contains(err.Error(), missing) {
		t.Fatalf("findBinary(%q) error %q must keep the not-found wording", missing, err)
	}
}
