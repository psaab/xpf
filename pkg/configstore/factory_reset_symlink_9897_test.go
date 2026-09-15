package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbidRoot9897 registers dir as a shared/system root for one test (the
// FactoryResetForbiddenRoots seam), restoring the denylist afterwards. The
// RESOLVED form is registered: the wipe compares resolved candidates, so an
// unresolved registration would miss under a symlinked TMPDIR (macOS /var ->
// /private/var). Best-effort — falls back to Clean when the path does not
// exist yet (callers create-then-register, and the canonical-identity check
// covers the rest).
func forbidRoot9897(t *testing.T, dir string) {
	t.Helper()
	if resolved, rerr := filepath.EvalSymlinks(dir); rerr == nil {
		dir = resolved
	}
	old := FactoryResetForbiddenRoots
	FactoryResetForbiddenRoots = append(append([]string(nil), old...), filepath.Clean(dir))
	t.Cleanup(func() { FactoryResetForbiddenRoots = old })
}

func mustWrite9897(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// #9897 F-040: ValidateFactoryResetRoot is lexical by its own doc ("it does not
// resolve symlinks"), while os.ReadDir follows intermediate links — so a
// config root that REACHES a forbidden directory through a symlink passes the
// guard and the wipe deletes xpf-named files under a tree xpf does not own,
// reporting success. The fix resolves configDir (EvalSymlinks) before BOTH
// validation and wipe.
func TestFactoryResetRefusesSymlinkToForbiddenRoot9897(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	victim := filepath.Join(real, "xpf.conf")
	mustWrite9897(t, victim, "live config text\n")
	// Create-then-register, and assert the RESOLVED target: the wipe names
	// resolved paths, which differ from these under a symlinked TMPDIR.
	forbidRoot9897(t, real)
	wantTarget, werr := filepath.EvalSymlinks(real)
	if werr != nil {
		t.Fatalf("EvalSymlinks(%q): %v", real, werr)
	}

	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	err := FactoryResetConfigDir(link, "xpf.conf")
	if err == nil {
		t.Fatalf("FactoryResetConfigDir wiped through a SYMLINKED root into a " +
			"FORBIDDEN directory and reported success -- the #9897 F-040 defect")
	}
	if !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), wantTarget) {
		t.Fatalf("error must name the link AND the resolved target, got: %v", err)
	}
	if _, serr := os.Stat(victim); serr != nil {
		t.Fatalf("file under the forbidden target was deleted: %v", serr)
	}
}

// Same bypass with the link in an INTERMEDIATE component: configDir itself is
// not a link, but one of its parents is.
func TestFactoryResetRefusesIntermediateLinkToForbidden9897(t *testing.T) {
	root := t.TempDir()
	resolved := filepath.Join(root, "real", "sub")
	victim := filepath.Join(resolved, "xpf.conf")
	mustWrite9897(t, victim, "live config text\n")
	// Create-then-register, and assert the RESOLVED target (see above).
	forbidRoot9897(t, resolved)
	wantTarget, werr := filepath.EvalSymlinks(resolved)
	if werr != nil {
		t.Fatalf("EvalSymlinks(%q): %v", resolved, werr)
	}

	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "l")); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(root, "l", "sub")

	err := FactoryResetConfigDir(configDir, "xpf.conf")
	if err == nil {
		t.Fatalf("FactoryResetConfigDir wiped through an INTERMEDIATE link into a " +
			"forbidden directory and reported success")
	}
	if !strings.Contains(err.Error(), configDir) || !strings.Contains(err.Error(), wantTarget) {
		t.Fatalf("error must name the link AND the resolved target, got: %v", err)
	}
	if _, serr := os.Stat(victim); serr != nil {
		t.Fatalf("file under the forbidden target was deleted: %v", serr)
	}
}

// A DANGLING-link root is a link, not an absence: reporting success would wipe
// nothing while telling the operator the box is clean (the #9013 shape), so it
// is refused with the link named.
func TestFactoryResetRefusesDanglingLinkRoot9897(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(root, "nowhere"), link); err != nil {
		t.Fatal(err)
	}
	err := FactoryResetConfigDir(link, "xpf.conf")
	if err == nil {
		t.Fatal("FactoryResetConfigDir on a DANGLING-link root reported success " +
			"while wiping nothing; want a refusal naming the link")
	}
	if !strings.Contains(err.Error(), link) {
		t.Fatalf("error must name the link, got: %v", err)
	}
}

// Resolve, don't refuse: a link to a DEDICATED (non-forbidden) root still wipes
// the resolved tree and reports nil. A guard that refused every link would pass
// the rows above while breaking legitimate symlinked-root layouts.
func TestFactoryResetFollowsLinkToDedicatedRoot9897(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	seeds := []string{
		filepath.Join(real, "xpf.conf"),
		filepath.Join(real, RescueConfigBase),
		filepath.Join(real, ".config.journal"),
		filepath.Join(real, ".configdb", "active.json"),
	}
	for _, s := range seeds {
		mustWrite9897(t, s, "secret\n")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	if err := FactoryResetConfigDir(link, "xpf.conf"); err != nil {
		t.Fatalf("wipe through a link to a DEDICATED root must succeed, got: %v", err)
	}
	for _, s := range seeds {
		if _, serr := os.Lstat(s); !os.IsNotExist(serr) {
			t.Fatalf("seed %q survived a wipe of its resolved root (err=%v)", s, serr)
		}
	}
}

// CONTROL: the ordinary wipe is byte-identical — everything owned erased, nil
// error — and an absent root stays a clean no-op (DeleteConfirm-style
// absent-file case: absence is the goal, not an error).
func TestFactoryResetOrdinaryPathsUnaffected9897(t *testing.T) {
	t.Run("ordinary-wipe-erases", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "xpf")
		seeds := []string{
			filepath.Join(dir, "xpf.conf"),
			filepath.Join(dir, RescueConfigBase),
			filepath.Join(dir, ".config.journal"),
			filepath.Join(dir, "xpf.conf.1"),
			filepath.Join(dir, ".configdb", "active.json"),
			filepath.Join(dir, ".configdb", "master.key"),
		}
		for _, s := range seeds {
			mustWrite9897(t, s, "secret\n")
		}
		if err := FactoryResetConfigDir(dir, "xpf.conf"); err != nil {
			t.Fatalf("ordinary wipe: %v", err)
		}
		for _, s := range seeds {
			if _, serr := os.Lstat(s); !os.IsNotExist(serr) {
				t.Fatalf("seed %q survived an ordinary wipe (err=%v)", s, serr)
			}
		}
	})

	t.Run("absent-root-is-clean-noop", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "absent")
		if err := FactoryResetConfigDir(dir, "xpf.conf"); err != nil {
			t.Fatalf("absent root must be a clean no-op, got: %v", err)
		}
	})
}
