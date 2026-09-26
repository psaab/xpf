package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/upgrade/stagedgen"
)

// seedEnv builds a populated staged tree and returns a Config wired to
// temp dirs. version "" means Seed reads it from the (fake) staged binary;
// tests pass an explicit version to avoid exec'ing a real binary.
func seedEnv(t *testing.T, ver string) Config {
	t.Helper()
	root := t.TempDir()
	staged := filepath.Join(root, "staged")
	for _, b := range managedBins {
		mkfile(t, filepath.Join(staged, b), "bin-"+b+"-"+ver)
	}
	return Config{
		StagedDir:    staged,
		VersionsDir:  filepath.Join(root, "versions"),
		StagedGenDir: filepath.Join(root, "staged-gen"),
		SbinDir:      filepath.Join(root, "sbin"),
		Logf:         func(format string, a ...any) { t.Logf("LOG "+format, a...) },
		version:      ver,
	}
}

func mkfile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

// assertSeeded verifies the full post-seed layout: versions/<ver>/<bin>
// exist with staged content, current -> <ver>, and each sbin link resolves
// through versions/current to the version dir's binary.
func assertSeeded(t *testing.T, cfg Config, ver string) {
	t.Helper()
	for _, b := range managedBins {
		p := filepath.Join(cfg.VersionsDir, ver, b)
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("missing version binary %s: %v", p, err)
		}
		if string(got) != "bin-"+b+"-"+ver {
			t.Errorf("version binary %s content = %q", p, got)
		}
	}
	cur, err := os.Readlink(filepath.Join(cfg.VersionsDir, currentLink))
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if filepath.Base(cur) != ver {
		t.Errorf("current -> %q, want %q", cur, ver)
	}
	for _, b := range managedBins {
		link := filepath.Join(cfg.SbinDir, b)
		// The link must resolve (through current) to a readable file with
		// the staged content — i.e. the daemon is launchable via sbin.
		got, err := os.ReadFile(link)
		if err != nil {
			t.Fatalf("sbin link %s does not resolve to a readable binary: %v", link, err)
		}
		if string(got) != "bin-"+b+"-"+ver {
			t.Errorf("sbin %s resolves to content %q", link, got)
		}
		// And the link target must route through versions/current.
		tgt, err := os.Readlink(link)
		if err != nil {
			t.Fatalf("readlink sbin %s: %v", link, err)
		}
		want := filepath.Join(cfg.VersionsDir, currentLink, b)
		if tgt != want {
			t.Errorf("sbin %s -> %q, want %q", link, tgt, want)
		}
	}
}

func TestSeed_FirstInstallLayout(t *testing.T) {
	cfg := seedEnv(t, "1.0.0")
	if err := Seed(cfg); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	assertSeeded(t, cfg, "1.0.0")
}

// TestSeed_PublishesInitialGeneration proves the #1981 Option B seed step: a
// first install publishes a resolvable staged generation containing the
// staged bytes, so a first manual `xpfd upgrade` has a pinned source.
func TestSeed_PublishesInitialGeneration(t *testing.T) {
	cfg := seedEnv(t, "1.0.0")
	if err := Seed(cfg); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	sg := stagedgen.Config{StagedDir: cfg.StagedDir, Dir: cfg.StagedGenDir}
	genid, err := sg.ResolveCurrent()
	if err != nil {
		t.Fatalf("ResolveCurrent after seed: %v", err)
	}
	if genid == "" {
		t.Fatal("seed did not publish an initial generation (current-gen absent)")
	}
	for _, b := range managedBins {
		data, rerr := os.ReadFile(filepath.Join(sg.GenDir(genid), b))
		if rerr != nil {
			t.Fatalf("published generation missing %s: %v", b, rerr)
		}
		if string(data) != "bin-"+b+"-1.0.0" {
			t.Errorf("published %s = %q, want seeded bytes", b, data)
		}
	}
}

// TestSeed_Idempotent re-runs Seed and asserts the layout is unchanged and
// no .partial residue is left.
func TestSeed_Idempotent(t *testing.T) {
	cfg := seedEnv(t, "1.0.0")
	if err := Seed(cfg); err != nil {
		t.Fatalf("Seed #1: %v", err)
	}
	if err := Seed(cfg); err != nil {
		t.Fatalf("Seed #2 (idempotent): %v", err)
	}
	assertSeeded(t, cfg, "1.0.0")
	// No leftover .partial.
	entries, _ := os.ReadDir(cfg.VersionsDir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".partial" {
			t.Errorf("leftover partial dir: %s", e.Name())
		}
	}
}

// TestSeed_ResumeAfterCopyCrash adopts a complete, byte-identical version dir
// left by a crash after the atomic rename, then completes current and sbin.
func TestSeed_ResumeAfterCopyCrash(t *testing.T) {
	cfg := seedEnv(t, "1.0.0")
	verDir := filepath.Join(cfg.VersionsDir, "1.0.0")
	for _, b := range managedBins {
		mkfile(t, filepath.Join(verDir, b), "bin-"+b+"-1.0.0")
	}
	if err := Seed(cfg); err != nil {
		t.Fatalf("Seed (resume): %v", err)
	}
	assertSeeded(t, cfg, "1.0.0")
}

func TestSeed_RefusesForeignOrIncompleteVersionDir(t *testing.T) {
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, verDir string)
	}{
		{
			name: "missing lockstep binary",
			damage: func(t *testing.T, verDir string) {
				t.Helper()
				if err := os.Remove(filepath.Join(verDir, "xpf-userspace-dp")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "different managed bytes",
			damage: func(t *testing.T, verDir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(verDir, "cli"), []byte("foreign cli"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := seedEnv(t, "1.0.0")
			verDir := filepath.Join(cfg.VersionsDir, "1.0.0")
			for _, b := range managedBins {
				mkfile(t, filepath.Join(verDir, b), "bin-"+b+"-1.0.0")
			}
			tc.damage(t, verDir)
			if err := Seed(cfg); err == nil {
				t.Fatal("Seed accepted a foreign or incomplete existing version dir")
			}
			if _, err := os.Lstat(filepath.Join(cfg.VersionsDir, currentLink)); !os.IsNotExist(err) {
				t.Fatalf("Seed changed current despite refusing the directory: err=%v", err)
			}
			if _, err := os.Stat(cfg.SbinDir); !os.IsNotExist(err) {
				t.Fatalf("Seed created sbin links despite refusing the directory: err=%v", err)
			}
			for _, b := range managedBins {
				got, err := os.ReadFile(filepath.Join(verDir, b))
				if err != nil {
					continue
				}
				if b == "cli" && tc.name == "different managed bytes" && string(got) != "foreign cli" {
					t.Fatalf("Seed replaced foreign %s bytes: %q", b, got)
				}
			}
		})
	}
}

// TestSeed_ResumeAfterCurrentCrash simulates a crash AFTER current was
// created but BEFORE sbin was repointed. A re-run must complete the sbin
// repoint (the critical crash-window the plan calls out: a daemon pointed at
// the old sbin path must end up resolving through versions/current).
func TestSeed_ResumeAfterCurrentCrash(t *testing.T) {
	cfg := seedEnv(t, "1.0.0")
	verDir := filepath.Join(cfg.VersionsDir, "1.0.0")
	for _, b := range managedBins {
		mkfile(t, filepath.Join(verDir, b), "bin-"+b+"-1.0.0")
	}
	// current exists, sbin does not.
	if err := os.Symlink("1.0.0", filepath.Join(cfg.VersionsDir, currentLink)); err != nil {
		t.Fatal(err)
	}
	if err := Seed(cfg); err != nil {
		t.Fatalf("Seed (resume after current): %v", err)
	}
	assertSeeded(t, cfg, "1.0.0")
}

// TestSeed_PreservesModes proves the seeded version dir preserves the
// SOURCE file/dir permissions (Copilot): a 0700 staged subdir and a 0644
// staged file must not be silently widened to 0755 in versions/<ver>/.
func TestSeed_PreservesModes(t *testing.T) {
	cfg := seedEnv(t, "1.0.0")
	// Add a non-0755 subdir + a non-0755 file under staged.
	subdir := filepath.Join(cfg.StagedDir, "data")
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(subdir, 0o700); err != nil { // MkdirAll applies umask
		t.Fatal(err)
	}
	rofile := filepath.Join(subdir, "ro.txt")
	if err := os.WriteFile(rofile, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rofile, 0o640); err != nil {
		t.Fatal(err)
	}
	// A setgid directory: the special bit must be preserved (Copilot r3).
	// NOTE: Go's os.FileMode does NOT map octal 0o2000 to setgid — the
	// setgid flag is os.ModeSetgid (a high bit), so chmod with that flag.
	sgiddir := filepath.Join(cfg.StagedDir, "shared")
	if err := os.MkdirAll(sgiddir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sgiddir, 0o775|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	// Skip the assertion if the staging filesystem dropped the setgid bit
	// (some tmpfs configs do); only assert preservation when the source
	// actually carries it.
	if sfi, _ := os.Stat(sgiddir); sfi.Mode()&os.ModeSetgid == 0 {
		t.Skip("staging filesystem does not preserve the setgid bit; cannot test preservation")
	}
	if err := Seed(cfg); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	gotDir, err := os.Stat(filepath.Join(cfg.VersionsDir, "1.0.0", "data"))
	if err != nil {
		t.Fatal(err)
	}
	if gotDir.Mode().Perm() != 0o700 {
		t.Errorf("seeded subdir mode = %o, want 0700", gotDir.Mode().Perm())
	}
	gotFile, err := os.Stat(filepath.Join(cfg.VersionsDir, "1.0.0", "data", "ro.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if gotFile.Mode().Perm() != 0o640 {
		t.Errorf("seeded file mode = %o, want 0640", gotFile.Mode().Perm())
	}
	// And the binaries stay executable (0755 staged).
	binInfo, err := os.Stat(filepath.Join(cfg.VersionsDir, "1.0.0", "xpfd"))
	if err != nil {
		t.Fatal(err)
	}
	if binInfo.Mode().Perm()&0o111 == 0 {
		t.Errorf("seeded xpfd not executable: mode %o", binInfo.Mode().Perm())
	}
	// The setgid special bit must survive (Copilot r3: chmod must not mask it).
	sgidInfo, err := os.Stat(filepath.Join(cfg.VersionsDir, "1.0.0", "shared"))
	if err != nil {
		t.Fatal(err)
	}
	if sgidInfo.Mode()&os.ModeSetgid == 0 {
		t.Errorf("seeded setgid dir lost its setgid bit: mode %o", sgidInfo.Mode())
	}
	if sgidInfo.Mode().Perm() != 0o775 {
		t.Errorf("seeded setgid dir perm = %o, want 0775", sgidInfo.Mode().Perm())
	}
}

// TestSeed_ToleratesStaleTempDir proves atomicSymlink uses RemoveAll, so a
// stale DIRECTORY at a symlink's temp path (manual intervention / a prior
// failed run) does not break seeding with EEXIST (Copilot r3).
func TestSeed_ToleratesStaleTempDir(t *testing.T) {
	cfg := seedEnv(t, "1.0.0")
	if err := os.MkdirAll(cfg.VersionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Plant a stale directory where the `current` symlink's temp goes
	// (versions/.current.tmp) and where an sbin link's temp goes
	// (sbin/.xpfd.tmp).
	if err := os.MkdirAll(filepath.Join(cfg.VersionsDir, "."+currentLink+".tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.SbinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.SbinDir, ".xpfd.tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Seed(cfg); err != nil {
		t.Fatalf("Seed with stale temp dirs: %v", err)
	}
	assertSeeded(t, cfg, "1.0.0")
}

// TestSeed_RejectsNonDirVersionPath proves Seed fails (rather than seeding
// through a broken layout) when versions/<ver> exists but is NOT a directory
// (corruption / manual edit) — so the postinst can fall back to legacy links
// instead of leaving current/sbin pointing at a non-launchable path (Copilot).
func TestSeed_RejectsNonDirVersionPath(t *testing.T) {
	cfg := seedEnv(t, "1.0.0")
	if err := os.MkdirAll(cfg.VersionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Plant a regular file where the version DIR should be.
	if err := os.WriteFile(filepath.Join(cfg.VersionsDir, "1.0.0"), []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Seed(cfg); err == nil {
		t.Fatal("Seed accepted a non-directory versions/<ver>")
	}
	// current must NOT have been repointed to the broken layout.
	if _, err := os.Lstat(filepath.Join(cfg.VersionsDir, currentLink)); err == nil {
		t.Error("Seed repointed current despite a non-directory version path")
	}
}

// TestSeed_RejectsUnsafeVersion proves a version that is not a safe path
// segment is rejected before any filesystem mutation.
func TestSeed_RejectsUnsafeVersion(t *testing.T) {
	for _, bad := range []string{"", "..", "../escape", "a/b", ".hidden", "ver with space", "tab\tver"} {
		cfg := seedEnv(t, bad)
		if err := Seed(cfg); err == nil {
			t.Errorf("Seed accepted unsafe version %q", bad)
		}
		// No version dir or current should have been created.
		if _, err := os.Stat(filepath.Join(cfg.VersionsDir, currentLink)); err == nil {
			t.Errorf("Seed created current for unsafe version %q", bad)
		}
	}
}

// TestStagedVersion_RejectsGarbageFormat proves stagedVersion (the seed-side
// reader) hard-fails an unrecognized `xpfd version` output instead of
// returning the raw trimmed string — #1967 C1 parity with
// realSystem.BinaryVersion, so a corrupt binary cannot seed versions/<token>
// by a wrong-shaped string.
func TestStagedVersion_RejectsGarbageFormat(t *testing.T) {
	mkStaged := func(out string) string {
		dir := t.TempDir()
		script := "#!/bin/sh\nprintf '%s' \"" + out + "\"\nexit 0\n"
		if err := os.WriteFile(filepath.Join(dir, "xpfd"), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	// Valid shape: token returned as-is.
	if got, err := stagedVersion(mkStaged("xpfd 1.2.3 (commit x)")); err != nil || got != "1.2.3" {
		t.Errorf("stagedVersion(valid) = %q, %v; want 1.2.3, nil", got, err)
	}

	// Garbage formats: hard-fail, never return the raw output.
	for _, out := range []string{
		"totally unexpected output",
		"xpfd", // only one field
		"some random text without the xpfd prefix",
		"",
	} {
		got, err := stagedVersion(mkStaged(out))
		if err == nil {
			t.Errorf("stagedVersion(%q) = %q, want error (unrecognized format)", out, got)
		}
		if got != "" {
			t.Errorf("stagedVersion(%q) leaked %q on error", out, got)
		}
	}
}
