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
// and swap the process-euid and file-owner seams, all process-global.
// The euid seam exercises the root arm regardless of the runner's euid;
// ownership is real kernel data except in the writability cell, where
// the owner seam presents the fixture as root-owned so only the
// &0o022 arm can refuse (a non-root runner cannot chown to root).

func asRoot16054(t *testing.T) {
	t.Helper()
	old := helperProcessEuid
	helperProcessEuid = func() int { return 0 }
	t.Cleanup(func() { helperProcessEuid = old })
}

// asRootOwned16054 presents every fixture file as root-owned via the
// owner seam, isolating the writability arm from the ownership arm:
// with ownership neutralized, only the &0o022 check can refuse.
func asRootOwned16054(t *testing.T) {
	t.Helper()
	old := helperFileOwnerUID
	helperFileOwnerUID = func(os.FileInfo) (uint32, bool) { return 0, true }
	t.Cleanup(func() { helperFileOwnerUID = old })
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

// Decisive writability cell: the fixture is presented as root-owned
// (owner seam) and chmodded 0777, so the ownership arm cannot fire —
// refusal can only come from the group/world-writable (&0o022) check,
// and the reason must name it specifically. Deleting the &0o022 check
// turns this cell RED (the root-owned writable helper is then accepted).
func TestFindBinaryRefusesWritableCwdHelperAsRoot16054(t *testing.T) {
	asRoot16054(t)
	asRootOwned16054(t)
	cwd := t.TempDir()
	writeHelper16054(t, cwd, "writable")
	t.Chdir(cwd)
	t.Setenv("PATH", t.TempDir())

	_, err := findBinary("")
	if err == nil {
		t.Fatal("findBinary(\"\") accepted root-owned but group/world-writable CWD helper as root")
	}
	if !strings.Contains(err.Error(), "group/world-writable") {
		t.Fatalf("findBinary error %q must specifically name group/world-writable, not the ownership arm", err)
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
	if want := filepath.Join(cwd, "xpf-userspace-dp"); got != want {
		t.Fatalf("findBinary(\"\") = %q, want validated absolute cwd candidate %q", got, want)
	}
}

// Bare-name witness (#16054 fold): a configured bare name stats the
// CWD file, but a bare return value would be re-resolved by
// exec.Command through PATH at Start time — validated file != executed
// file. findBinary must return the validated absolute path, so with a
// CWD plant and a different PATH helper the executed file is the CWD
// file that was actually checked (non-root arm, where the plant is
// admissible at all).
func TestFindBinaryBareNameReturnsValidatedAbsolute16054(t *testing.T) {
	cwd := t.TempDir()
	cwdHelper := writeHelper16054(t, cwd, "")
	bin := t.TempDir()
	pathHelper := writeHelper16054(t, bin, "")
	t.Chdir(cwd)
	t.Setenv("PATH", bin)

	got, err := findBinary("xpf-userspace-dp")
	if err != nil {
		t.Fatalf("findBinary(bare) = %v, want validated CWD helper", err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("findBinary(bare) = %q, want absolute path (bare name would be re-resolved through PATH %q)", got, pathHelper)
	}
	if got != cwdHelper {
		t.Fatalf("findBinary(bare) = %q, want validated CWD file %q, not PATH file %q", got, cwdHelper, pathHelper)
	}
}

// Bare-name witness, root arm: the CWD plant is user-owned, so under a
// simulated root daemon the bare name must be refused for the file it
// actually stats — it must never fall through to executing the PATH
// namesake instead.
func TestFindBinaryBareNamePlantRefusedAsRoot16054(t *testing.T) {
	asRoot16054(t)
	cwd := t.TempDir()
	planted := writeHelper16054(t, cwd, "")
	bin := t.TempDir()
	writeHelper16054(t, bin, "")
	t.Chdir(cwd)
	t.Setenv("PATH", bin)

	got, err := findBinary("xpf-userspace-dp")
	if err == nil {
		t.Fatalf("findBinary(bare) = %q as root, want refusal of planted %q (never the PATH namesake)", got, planted)
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("findBinary(bare) error %q must say the CWD file it stat'ed is not trusted", err)
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
