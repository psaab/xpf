package userspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
func TestFindBinaryPrefersExecutableCwdOverPath12196(t *testing.T) {
	cwd := t.TempDir()
	cwdHelper := filepath.Join(cwd, findBinaryName12196)
	if err := os.WriteFile(cwdHelper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write executable cwd helper: %v", err)
	}
	bin := t.TempDir()
	pathHelper := filepath.Join(bin, findBinaryName12196)
	if err := os.WriteFile(pathHelper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write PATH helper: %v", err)
	}
	t.Chdir(cwd)
	t.Setenv("PATH", bin)

	got, err := findBinary("")
	if err != nil {
		t.Fatalf("findBinary(\"\") = error %v, want ./%s", err, findBinaryName12196)
	}
	want := cwdHelper
	if got != want {
		t.Fatalf("findBinary(\"\") = %q, want validated absolute cwd candidate %q (PATH helper %q)", got, want, pathHelper)
	}
}

func TestFindBinaryExplicitDirectoryIsInformativeError12196(t *testing.T) {
	dir := t.TempDir()
	if got, err := findBinary(dir); err == nil {
		t.Fatalf("findBinary(%q) = %q, want directory error", dir, got)
	} else if !strings.Contains(err.Error(), dir) || !strings.Contains(strings.ToLower(err.Error()), "is a directory") {
		t.Fatalf("findBinary(%q) error %q must name the path and say it is a directory", dir, err)
	}
}

func TestFindBinaryReportsSkippedCwdCandidate12196(t *testing.T) {
	tests := []struct {
		name   string
		mode   os.FileMode
		dir    bool
		reason string
	}{
		{name: "non-executable", mode: 0o644, reason: "not executable (mode"},
		{name: "directory", dir: true, reason: "is a directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cwd := t.TempDir()
			candidate := filepath.Join(cwd, findBinaryName12196)
			if tt.dir {
				if err := os.Mkdir(candidate, 0o755); err != nil {
					t.Fatalf("mkdir directory candidate: %v", err)
				}
			} else if err := os.WriteFile(candidate, []byte("# stale artifact\n"), tt.mode); err != nil {
				t.Fatalf("write non-executable candidate: %v", err)
			}
			t.Chdir(cwd)
			t.Setenv("PATH", t.TempDir())

			_, err := findBinary("")
			if err == nil {
				t.Fatal("findBinary(\"\") succeeded without an executable helper")
			}
			if !strings.Contains(err.Error(), findBinaryName12196) || !strings.Contains(err.Error(), tt.reason) {
				t.Fatalf("findBinary(\"\") error %q must name skipped candidate and reason %q", err, tt.reason)
			}
		})
	}
}

func TestFindBinaryDeduplicatesBareArgv0CwdCandidate12196(t *testing.T) {
	oldArg0 := os.Args[0]
	os.Args[0] = "xpfd"
	t.Cleanup(func() { os.Args[0] = oldArg0 })

	cwd := t.TempDir()
	candidate := filepath.Join(cwd, findBinaryName12196)
	if err := os.WriteFile(candidate, []byte("# stale artifact\n"), 0o644); err != nil {
		t.Fatalf("write non-executable candidate: %v", err)
	}
	t.Chdir(cwd)
	t.Setenv("PATH", "")

	_, err := findBinary("")
	if err == nil {
		t.Fatal("findBinary(\"\") succeeded without an executable helper")
	}
	count := strings.Count(err.Error(), findBinaryName12196+": ")
	if count != 1 {
		t.Fatalf("findBinary(\"\") error %q names skipped candidate %d times, want exactly once", err, count)
	}
}

func TestFindBinarySkipsNoexecCwdCandidate12196(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("noexec tmpfs regression requires Linux")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skipf("unshare unavailable: %v", err)
	}
	if _, err := exec.LookPath("mount"); err != nil {
		t.Skipf("mount unavailable: %v", err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	mountpoint := filepath.Join(t.TempDir(), "noexec")
	if err := os.Mkdir(mountpoint, 0o755); err != nil {
		t.Fatal(err)
	}
	// The sentinel is echoed inside the namespace after the mount succeeds and
	// before exec. A missing sentinel means the namespace never came up —
	// unshare, uid_map/setgroups, or mount denial (e.g. AppArmor-restricted
	// CI runners) — so skip; fail only when the sentinel is present.
	script := `mount -t tmpfs -o noexec,size=4m tmpfs "$1" || exit 77; echo NOEXEC_NS_READY; FIND_BINARY_NOEXEC_DIR="$1" exec "$2" -test.run=^TestFindBinaryNoexecNamespaceHelper12196$ -test.v`
	cmd := exec.Command(unshare, "-rm", "sh", "-c", script, "sh", mountpoint, binary)
	output, err := cmd.CombinedOutput()
	text := string(output)
	if !strings.Contains(text, "NOEXEC_NS_READY") {
		t.Skipf("noexec tmpfs namespace unavailable: err=%v output: %s", err, text)
	}
	if err != nil {
		t.Fatalf("noexec tmpfs child failed: %v\n%s", err, text)
	}
	// A renamed helper exits 0 with "no tests to run"; require the verbose
	// PASS line so a no-op child cannot silently pass this regression.
	if !strings.Contains(text, "--- PASS: TestFindBinaryNoexecNamespaceHelper12196") {
		t.Fatalf("noexec tmpfs child ran without the namespace helper passing:\n%s", text)
	}
}

func TestFindBinaryNoexecNamespaceHelper12196(t *testing.T) {
	mountpoint := os.Getenv("FIND_BINARY_NOEXEC_DIR")
	if mountpoint == "" {
		t.Skip("runs only inside the noexec tmpfs test namespace")
	}
	cwd := filepath.Join(mountpoint, "cwd")
	if err := os.Mkdir(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(cwd, findBinaryName12196)
	if err := os.WriteFile(candidate, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	_, lookPathErr := exec.LookPath("./" + findBinaryName12196)
	if lookPathErr == nil {
		t.Fatal("exec.LookPath accepted executable-bit helper on noexec tmpfs")
	}
	bin := t.TempDir()
	pathHelper := filepath.Join(bin, findBinaryName12196)
	if err := os.WriteFile(pathHelper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	got, err := findBinary("")
	if err != nil {
		t.Fatalf("findBinary(\"\") = error %v, want PATH helper %s", err, pathHelper)
	}
	if got != pathHelper {
		t.Fatalf("findBinary(\"\") = %q, want PATH helper %q", got, pathHelper)
	}
}
