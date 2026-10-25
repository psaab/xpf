package userspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #16846: findBinary (#16054) validated the symlink-FOLLOWED target
// (os.Stat) but returned filepath.Abs of the unresolved name and never
// checked any containing directory. A planted
// ./xpf-userspace-dp -> /bin/true therefore passed as "root-owned" and
// could be flipped to attacker content between validation and exec.
//
// Post-fix findBinary returns the EvalSymlinks-resolved path and, for a
// root daemon, refuses any replaceable symlink or directory component
// on either spelling of the path. These cells are NOT parallel: they
// chdir, rewrite PATH, and swap the euid seam, all process-global (the
// same constraint as the #16054 cells).

// plantSymlink16846 links dir/xpf-userspace-dp -> target, asserting the
// fixture really is a symlink (the defect cell is meaningless otherwise).
func plantSymlink16846(t *testing.T, dir, target string) string {
	t.Helper()
	link := filepath.Join(dir, "xpf-userspace-dp")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("planted %s has mode %s, want a symlink", link, info.Mode())
	}
	return link
}

func trustedTarget16846(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/bin/true", "/usr/bin/true"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no /bin/true or /usr/bin/true fixture")
	return ""
}

// Defect cell, implicit CWD arm: a symlink in a user-writable CWD to a
// root-owned binary must be refused under a simulated root daemon. The
// owner seam presents the TARGET as root-owned, so pre-fix the target
// check passes and the unresolved CWD path is returned (RED); the
// refusal can only come from the new chain check. Controls 1/2 of the
// probe (attacker-owned file, symlink to it) are already refused by
// #16054 and are pinned unchanged by the existing #16054 cells.
func TestFindBinaryRefusesCwdSymlinkToTrustedTargetAsRoot16846(t *testing.T) {
	asRoot16054(t)
	asRootOwned16054(t)
	target := trustedTarget16846(t)
	cwd := t.TempDir()
	planted := plantSymlink16846(t, cwd, target)
	t.Chdir(cwd)
	t.Setenv("PATH", t.TempDir())

	got, err := findBinary("")
	if err == nil {
		t.Fatalf("findBinary(\"\") = %q as root, want refusal of planted symlink %q -> %q", got, planted, target)
	}
	if !strings.Contains(err.Error(), "not root") {
		t.Fatalf("findBinary(\"\") error %q must explain the untrusted chain refusal", err)
	}
}

// Defect cell, explicit arm: the same plant named by the operator must
// be a hard not-trusted error (no PATH fallback), naming the path.
func TestFindBinaryExplicitSymlinkToTrustedTargetRefusedAsRoot16846(t *testing.T) {
	asRoot16054(t)
	asRootOwned16054(t)
	target := trustedTarget16846(t)
	dir := t.TempDir()
	planted := plantSymlink16846(t, dir, target)
	t.Chdir(t.TempDir())
	t.Setenv("PATH", t.TempDir())

	got, err := findBinary(planted)
	if err == nil {
		t.Fatalf("findBinary(%q) = %q as root, want refusal of planted symlink -> %q", planted, got, target)
	}
	if !strings.Contains(err.Error(), "not trusted") || !strings.Contains(err.Error(), planted) {
		t.Fatalf("findBinary(%q) error %q must name the path and say it is not trusted", planted, err)
	}
}

// Directory-chain cell: an explicit REGULAR helper in a user-writable
// directory, presented as root-owned via the owner seam, must still be
// refused as root — its containing directory lets any local user
// replace it, which is exactly the unverified gap #16846 names. Only
// the new directory-component check can refuse (file mode is 0755).
func TestFindBinaryExplicitInUntrustedDirRefusedAsRoot16846(t *testing.T) {
	asRoot16054(t)
	asRootOwned16054(t)
	dir := t.TempDir()
	explicit := writeHelper16054(t, dir, "")
	t.Chdir(t.TempDir())
	t.Setenv("PATH", t.TempDir())

	got, err := findBinary(explicit)
	if err == nil {
		t.Fatalf("findBinary(%q) = %q as root, want refusal: containing directory %q is not root-owned", explicit, got, dir)
	}
	if !strings.Contains(err.Error(), "not trusted") || !strings.Contains(err.Error(), "not root") {
		t.Fatalf("findBinary(%q) error %q must say it is not trusted because a path component is not root-owned", explicit, err)
	}
}

// Resolution control (non-root): a developer's own symlink in their own
// directory must still resolve and be followed — the returned path is
// the resolved target, not the link. Pre-fix this returned the link
// itself, so this cell is also RED pre-fix (on the returned spelling).
func TestFindBinaryNonRootResolvesSymlink16846(t *testing.T) {
	target := writeHelper16054(t, t.TempDir(), "")
	dir := t.TempDir()
	planted := plantSymlink16846(t, dir, target)
	t.Chdir(t.TempDir())
	t.Setenv("PATH", t.TempDir())

	got, err := findBinary(planted)
	if err != nil {
		t.Fatalf("findBinary(%q) = %v, want resolved %q for the non-root dev workflow", planted, err, target)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("findBinary(%q) = %q, want symlink-resolved target %q", planted, got, want)
	}
}

// Control, unchanged: the packaged shape under a real root daemon — a
// root-owned regular helper in a root-owned trusted directory chain —
// is admitted and returned resolved. Runs only when the test binary
// itself is root (packaged CI), because only then is the fixture chain
// genuinely root-owned; otherwise this is the same shape as the
// directory-chain refusal cell above and would contradict it.
func TestFindBinaryExplicitTrustedAcceptedAsRoot16846(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("packaged root control requires a root test binary")
	}
	target := trustedTarget16846(t)
	explicit := target
	// /bin is a symlink to /usr/bin on merged-usr hosts; the accepted
	// answer must be the fully resolved spelling.
	want, err := filepath.EvalSymlinks(explicit)
	if err != nil {
		t.Fatal(err)
	}
	got, err := findBinary(explicit)
	if err != nil {
		t.Fatalf("findBinary(%q) = %v, want acceptance of the trusted packaged helper %q", explicit, err, want)
	}
	if got != want {
		t.Fatalf("findBinary(%q) = %q, want resolved %q", explicit, got, want)
	}
}
