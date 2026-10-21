package userspace

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #16054: findBinary's implicit candidate list starts with
// ./xpf-userspace-dp and admission checked only stat + exec-bit. A root
// xpfd hand-run from a low-privilege-writable CWD therefore executed a
// planted ./xpf-userspace-dp as root and then trusted its uid-0 peer
// credentials. Post-fix every resolved candidate (CWD, build-tree,
// argv[0]-dir and LookPath results, plus an explicit configured path)
// must be root-owned and not group/world-writable when the daemon runs
// as root, with a loud log for skipped implicit candidates.
//
// These cells are intentionally NOT parallel: they chdir, rewrite PATH,
// and swap the process-euid seam, all process-global. They use the seam
// so they exercise the root arm regardless of the test runner's euid;
// when the runner really is uid 1000, every fixture file below is
// genuinely user-owned, so the ownership arm is real kernel data, not
// mocked stat output.

func asRoot16054(t *testing.T) {
	t.Helper()
	old := helperProcessEuid
	helperProcessEuid = func() int { return 0 }
	t.Cleanup(func() { helperProcessEuid = old })
}

func writeHelper16054(t *testing.T, dir, mode string) string {
	t.Helper()
	p := filepath.Join(dir, "xpf-userspace-dp")
	var m os.FileMode = 0o755
	if mode == "writable" {
		m = 0o777
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), m); err != nil {
		t.Fatal(err)
	}
	return p
}

func captureSlog16054(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// Decisive check from the issue: executable user-owned plant in a
// writable CWD, default config, simulated root daemon. Pre-fix it won
// over PATH; post-fix it must be skipped with a loud log.
func TestFindBinaryRefusesUserOwnedCwdPlantAsRoot16054(t *testing.T) {
	asRoot16054(t)
	logs := captureSlog16054(t)
	cwd := t.TempDir()
	planted := writeHelper16054(t, cwd, "")
	t.Chdir(cwd)
	t.Setenv("PATH", t.TempDir())
	_, err := findBinary("")
	if err == nil {
		t.Fatalf("findBinary(\"\") accepted planted %q as root", planted)
	}
	if !strings.Contains(err.Error(), "not root") {
		t.Fatalf("findBinary error %q must explain the untrusted-owner refusal", err)
	}
	if !strings.Contains(logs.String(), "skipping dataplane helper candidate") {
		t.Fatalf("skipped CWD plant must be loudly logged, got log %q", logs.String())
	}
}

// The plant must be skipped, not fatal, when a trusted-resolution
// alternative would exist; here PATH also holds a user-owned helper, so
// as root the PATH result must be refused too and resolution must fail
// closed rather than return either untrusted binary.
func TestFindBinaryRefusesUserOwnedPathHelperAsRoot16054(t *testing.T) {
	asRoot16054(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	bin := t.TempDir()
	pathHelper := writeHelper16054(t, bin, "")
	t.Setenv("PATH", bin)

	got, err := findBinary("")
	if err == nil {
		t.Fatalf("findBinary(\"\") = %q as root, want refusal of user-owned PATH helper %q", got, pathHelper)
	}
	if !strings.Contains(err.Error(), "not root") {
		t.Fatalf("findBinary error %q must explain the untrusted-owner refusal", err)
	}
}

// Group/world-writable must be refused even apart from ownership
// (a non-root runner owns its fixtures, so under a simulated root
// daemon both arms fire; the reason must name writability or owner).
func TestFindBinaryRefusesWritableCwdHelperAsRoot16054(t *testing.T) {
	asRoot16054(t)
	cwd := t.TempDir()
	writeHelper16054(t, cwd, "writable")
	t.Chdir(cwd)
	t.Setenv("PATH", t.TempDir())

	_, err := findBinary("")
	if err == nil {
		t.Fatal("findBinary(\"\") accepted group/world-writable CWD helper as root")
	}
	if !strings.Contains(err.Error(), "writable") && !strings.Contains(err.Error(), "not root") {
		t.Fatalf("findBinary error %q must explain the trust refusal", err)
	}
}

func TestFindBinaryExplicitUntrustedAsRoot16054(t *testing.T) {
	asRoot16054(t)
	explicit := writeHelper16054(t, t.TempDir(), "")
	bin := t.TempDir()
	writeHelper16054(t, bin, "")
	t.Chdir(t.TempDir())
	t.Setenv("PATH", bin)

	got, err := findBinary(explicit)
	if err == nil {
		t.Fatalf("findBinary(%q) = %q as root, want hard not-trusted error (no PATH fallback)", explicit, got)
	}
	if !strings.Contains(err.Error(), "not trusted") || !strings.Contains(err.Error(), explicit) {
		t.Fatalf("findBinary(%q) error %q must name the path and say it is not trusted", explicit, err)
	}
}

// Control: a non-root daemon gains no privilege from its own helper,
// so the user-owned build-tree/CWD dev workflow (#12196 executable
// CWD-over-PATH preference) must keep working. Runs under the real
// euid; when the runner itself is root, ownership is genuinely root
// and the candidate is trusted for that reason instead.
func TestFindBinaryNonRootKeepsCwdPreference16054(t *testing.T) {
	cwd := t.TempDir()
	writeHelper16054(t, cwd, "")
	bin := t.TempDir()
	writeHelper16054(t, bin, "")
	t.Chdir(cwd)
	t.Setenv("PATH", bin)

	got, err := findBinary("")
	if err != nil {
		t.Fatalf("findBinary(\"\") = %v, want CWD helper for non-root/dev workflow", err)
	}
	if want := "./xpf-userspace-dp"; got != want {
		t.Fatalf("findBinary(\"\") = %q, want cwd candidate %q", got, want)
	}
}

// Control: trust check must admit a genuinely trusted helper — root-
// owned when the runner is root, the runner's own when it is not.
func TestFindBinaryExplicitTrustedAccepted16054(t *testing.T) {
	explicit := writeHelper16054(t, t.TempDir(), "")
	got, err := findBinary(explicit)
	if err != nil {
		t.Fatalf("findBinary(%q) = %v, want acceptance of trusted explicit helper", explicit, err)
	}
	if got != explicit {
		t.Fatalf("findBinary(%q) = %q", explicit, got)
	}
}
