// Package runtime owns the FIRST-INSTALL seeding of the versioned runtime
// layout (#1964 mechanism A). On the very first `.deb` install there is no
// versioned rollback target, so the first or legacy-migration upgrade had
// PreviousVersion=="" and the cut hard-refused (or, worse, stopped a daemon
// it could not roll back). Seeding a real, immutable rollback target at
// install time closes that gap.
//
// Layout contract (plan §4): versions/<ver>/ and the `current` symlink are
// runtime state OWNED BY MAINTAINER SCRIPTS, never in dpkg's file list, so
// dpkg never clobbers a versioned rollback target. dpkg only ever writes
// /usr/local/share/xpf/staged/. After seeding, /usr/local/sbin/* resolve
// THROUGH versions/current.
//
// Seed runs from the .deb postinst on FIRST install ($2 empty), AFTER unpack
// (so the new binaries are on disk and runnable) but BEFORE #DEBHELPER#
// starts the unit — there is NO cut/verify/stop at install. The legacy
// upgrade-migration of a pre-fix host is a DIFFERENT mechanism (B), and is
// self-contained shell in debian/xpf.preinst because preinst runs BEFORE
// unpack, when the new xpfd binary is not yet on disk.
//
// Crash-safety: Seed is idempotent. A copy uses a .partial dir + atomic
// rename; the `current` symlink and each sbin link are repointed atomically
// (temp symlink + rename). A crash at any point re-runs Seed (postinst is
// re-run by apt) and converges to the same fully-seeded state without
// snapshotting a different version.
package runtime

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/upgrade"
	"github.com/psaab/xpf/pkg/upgrade/manifest"
	"github.com/psaab/xpf/pkg/upgrade/stagedgen"
)

// Default layout, shared with pkg/upgrade. Overridable in Config for tests.
// Default layout paths are the SINGLE source of truth in pkg/upgrade; the
// runtime package references them (Copilot) so a future layout change updates
// both the cut machine and the first-install seed together.
const (
	defaultStagedDir    = upgrade.DefaultStagedDir
	defaultVersionsDir  = upgrade.DefaultVersionsDir
	defaultStagedGenDir = upgrade.DefaultStagedGenDir
	defaultSbinDir      = upgrade.DefaultSbinDir

	currentLink = "current"
)

// managedBins are the binaries copied into the version dir and linked from
// /usr/local/sbin. Derived from the single source of truth in
// pkg/upgrade/manifest (#1982): the cut machine (pkg/upgrade), this
// first-install seed, the maintainer scripts, and debian/rules all draw the
// managed-binary set from one place, and the manifest drift canary fails the
// suite if any shell site diverges. manifest.Names returns a fresh slice each
// call, so this package-level copy cannot mutate the SSOT.
var managedBins = manifest.Names()

// Config configures a Seed. Zero values fall back to the production layout.
type Config struct {
	StagedDir   string
	VersionsDir string
	// StagedGenDir is the staged-generation root (#1981 Option B). Seed
	// publishes an initial generation here so a first manual `xpfd upgrade`
	// has a pinned source.
	StagedGenDir string
	SbinDir      string

	// Logf is an optional progress sink (defaults to no-op).
	Logf func(format string, args ...any)

	// version, when non-empty, overrides the version read from
	// `staged/xpfd version` (tests). Production leaves it empty.
	version string
}

func (c *Config) withDefaults() {
	if c.StagedDir == "" {
		c.StagedDir = defaultStagedDir
	}
	if c.VersionsDir == "" {
		c.VersionsDir = defaultVersionsDir
	}
	if c.StagedGenDir == "" {
		c.StagedGenDir = defaultStagedGenDir
	}
	if c.SbinDir == "" {
		c.SbinDir = defaultSbinDir
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// Seed performs the first-install seeding (mechanism A). It is safe to call
// when the layout is already (partially or fully) seeded: it never
// snapshots a different version, never clobbers an existing version dir, and
// always (idempotently) ensures `current` and the sbin links resolve
// through versions/<ver>.
//
// Steps (each idempotent and crash-safe):
//  1. read the staged version (validated as a safe single path segment).
//  2. copy staged/* -> versions/<ver>/ via a .partial dir + atomic rename;
//     an existing directory is adopted only when every managed file is
//     complete and byte-identical to staged/.
//  3. repoint versions/current -> <ver> (atomic).
//  4. repoint /usr/local/sbin/<bin> -> versions/current/<bin> (atomic).
func Seed(cfg Config) (err error) {
	cfg.withDefaults()
	logf := cfg.Logf

	ver := cfg.version
	if ver == "" {
		ver, err = stagedVersion(cfg.StagedDir)
		if err != nil {
			return fmt.Errorf("seed: read staged version: %w", err)
		}
	}
	if verr := upgrade.ValidateVersionSegment(ver); verr != nil {
		return fmt.Errorf("seed: staged version is not a safe path segment: %w", verr)
	}

	if err := fsatomic.MkdirAllDurable(cfg.VersionsDir, 0o755); err != nil {
		return fmt.Errorf("seed: create versions dir: %w", err)
	}

	verDir := filepath.Join(cfg.VersionsDir, ver)
	if fi, statErr := os.Lstat(verDir); statErr == nil {
		// A pre-existing version dir may be a foreign or interrupted copy,
		// not a completed seed. Adopt it only when its lockstep binaries are
		// startable and every managed byte matches the fully-unpacked staged
		// payload. On failure the postinst keeps direct-staged links, rather
		// than switching current to a mixed or stale runtime.
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("seed: %s exists but is not a real directory "+
				"(corrupt runtime layout); refusing to seed through it", verDir)
		}
		if err := verifyVersionDirMatchesStaged(verDir, cfg.StagedDir); err != nil {
			return fmt.Errorf("seed: refusing to adopt existing version dir %s: %w", verDir, err)
		}
		logf("seed: version dir %s is complete and matches staged; resuming", verDir)
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("seed: stat version dir: %w", statErr)
	} else {
		if err := copyStagedToVersion(cfg.StagedDir, cfg.VersionsDir, verDir); err != nil {
			return err
		}
	}

	// 3. current -> <ver> (relative within VersionsDir). Always run: a crash
	//    after the copy but before the symlink must still complete on retry.
	if err := atomicRelSymlink(filepath.Join(cfg.VersionsDir, currentLink), ver); err != nil {
		return fmt.Errorf("seed: repoint current -> %s: %w", ver, err)
	}

	// 4. sbin/<bin> -> versions/current/<bin> (absolute). Always run for the
	//    same crash-safety reason. Pointing through `current` (not the
	//    concrete version dir) matches the cut-over flip layout so a later
	//    upgrade's flip is a no-op-shaped repoint of the same link.
	if err := fsatomic.MkdirAllDurable(cfg.SbinDir, 0o755); err != nil {
		return fmt.Errorf("seed: create sbin dir: %w", err)
	}
	for _, b := range managedBins {
		link := filepath.Join(cfg.SbinDir, b)
		target := filepath.Join(cfg.VersionsDir, currentLink, b)
		if err := atomicAbsSymlink(link, target); err != nil {
			return fmt.Errorf("seed: repoint sbin %s: %w", b, err)
		}
	}
	logf("seed: seeded versioned runtime %s (current + sbin resolve through versions/)", ver)

	// 5. Publish the FIRST staged generation (#1981 Option B) so a first manual
	//    `xpfd upgrade` has a pinned source even though first-install runs no
	//    cut. dpkg has finished unpacking staged/ before the postinst configure
	//    step runs, so this publishes a complete, single-generation source.
	//    Idempotent: a re-run publishes a fresh (distinct) generation and the
	//    GC keeps current + 1 prior. Best-effort idempotence aside, a publish
	//    FAILURE here is fatal to seeding (the caller falls back to legacy
	//    direct-staged links): a later cut then refuses safely with no source
	//    rather than reading torn staged/.
	sgCfg := stagedgen.Config{
		StagedDir: cfg.StagedDir,
		Dir:       cfg.StagedGenDir,
		Logf:      cfg.Logf,
	}
	if _, perr := sgCfg.Publish(); perr != nil {
		return fmt.Errorf("seed: publish initial staged generation: %w", perr)
	}
	// GC the staged-generation root (Copilot): a repeated seed (manual
	// `xpfd seed-runtime` or repeated postinst retries) publishes a fresh
	// generation each time, so without a GC they accumulate. Best-effort — a
	// GC failure does not fail the seed (the publish already succeeded). No
	// cut runs at first-install seed time, so no journal protection is needed.
	if gcErr := sgCfg.GC(nil); gcErr != nil {
		logf("seed: WARN staged-gen gc failed: %v", gcErr)
	}
	logf("seed: published the initial staged generation")
	return nil
}

// copyStagedToVersion copies staged/* into a .partial dir, fsyncs, and
// atomically renames to verDir. A leftover .partial from a prior crash is
// removed first.
func copyStagedToVersion(stagedDir, versionsDir, verDir string) error {
	partial := verDir + ".partial"
	_ = os.RemoveAll(partial)
	if err := copyTreeFsync(stagedDir, partial); err != nil {
		_ = os.RemoveAll(partial)
		return fmt.Errorf("seed: copy staged -> partial: %w", err)
	}
	if err := fsatomic.SyncDir(partial); err != nil {
		_ = os.RemoveAll(partial)
		return fmt.Errorf("seed: fsync partial: %w", err)
	}
	if err := os.Rename(partial, verDir); err != nil {
		_ = os.RemoveAll(partial)
		return fmt.Errorf("seed: atomic rename partial -> version dir: %w", err)
	}
	if err := fsatomic.SyncDir(versionsDir); err != nil {
		return fmt.Errorf("seed: fsync versions dir after rename: %w", err)
	}
	return nil
}

// verifyVersionDirMatchesStaged adopts an existing seed directory only when
// its lockstep executables are present and every managed file is byte-identical
// to the staged source. This handles a completed copy after a crash, while
// refusing foreign, partial, or same-version-different-content directories.
func verifyVersionDirMatchesStaged(verDir, stagedDir string) error {
	for _, name := range manifest.LockstepNames() {
		path := filepath.Join(verDir, name)
		fi, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("lockstep binary %s is missing: %w", name, err)
		}
		if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("lockstep binary %s is not a regular executable", name)
		}
	}
	for _, name := range managedBins {
		stagedPath := filepath.Join(stagedDir, name)
		versionPath := filepath.Join(verDir, name)
		stagedDigest, err := regularFileSHA256(stagedPath)
		if err != nil {
			return fmt.Errorf("inspect staged binary %s: %w", name, err)
		}
		versionDigest, err := regularFileSHA256(versionPath)
		if err != nil {
			return fmt.Errorf("inspect versioned binary %s: %w", name, err)
		}
		if stagedDigest != versionDigest {
			return fmt.Errorf("managed binary %s differs from staged source", name)
		}
	}
	return nil
}

func regularFileSHA256(path string) ([sha256.Size]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if !fi.Mode().IsRegular() {
		return [sha256.Size]byte{}, fmt.Errorf("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [sha256.Size]byte{}, err
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum, nil
}

// stagedVersion runs `<staged>/xpfd version` and returns the version token.
// Output shape: "xpfd <version> (commit <c>, built <t>)".
//
// It hard-fails an unrecognized output format instead of returning the raw
// trimmed output (#1967 C1 parity with realSystem.BinaryVersion): a corrupt
// binary or a benign `version`-format drift must NOT seed versions/<token>
// by a wrong-shaped string. The caller (Seed) additionally validates the
// returned token via upgrade.ValidateVersionSegment, so the two readers keep
// the same package-wide invariant.
func stagedVersion(stagedDir string) (string, error) {
	bin := filepath.Join(stagedDir, "xpfd")
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		return "", fmt.Errorf("%s version: %w", bin, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) >= 2 && fields[0] == "xpfd" {
		return fields[1], nil
	}
	return "", fmt.Errorf("%s version: unrecognized output format "+
		"(want \"xpfd <version> ...\"): %q", bin, strings.TrimSpace(string(out)))
}

// atomicRelSymlink atomically points link at a RELATIVE target (basename in
// the same dir, e.g. current -> <ver>) via temp+rename, then fsyncs the dir.
func atomicRelSymlink(link, relTarget string) error {
	return atomicSymlink(link, relTarget)
}

// atomicAbsSymlink atomically points link at an ABSOLUTE target.
func atomicAbsSymlink(link, absTarget string) error {
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return err
	}
	return atomicSymlink(link, absTarget)
}

func atomicSymlink(link, target string) error {
	dir := filepath.Dir(link)
	tmp := filepath.Join(dir, "."+filepath.Base(link)+".tmp")
	// RemoveAll, not Remove (Copilot): a stale DIRECTORY at the temp path
	// (manual intervention / a previous failed run) makes os.Remove fail and
	// the subsequent Symlink fail EEXIST, breaking the idempotent/crash-safe
	// seed and forcing an unnecessary legacy fallback. Matches the maintainer
	// scripts' `rm -rf "$link.tmp"`.
	_ = os.RemoveAll(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("create temp symlink: %w", err)
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("rename symlink into place: %w", err)
	}
	if err := fsatomic.SyncDir(dir); err != nil {
		return fmt.Errorf("fsync symlink dir: %w", err)
	}
	return nil
}

// copyTreeFsync recursively copies src into dst (which must not exist),
// preserving file modes and fsyncing each file. Mirrors upgrade.copyTree's
// durability without the checksum (Seed re-runs idempotently; there is no
// torn-source race at install — dpkg has finished unpacking staged/ before
// the postinst configure step runs).
func copyTreeFsync(src, dst string) error {
	type ent struct {
		rel  string
		info os.FileInfo
		path string
	}
	var ents []ent
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		ents = append(ents, ent{rel: rel, info: info, path: p})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].rel < ents[j].rel })

	var createdDirs []string
	for _, e := range ents {
		target := filepath.Join(dst, e.rel)
		switch {
		case e.info.IsDir():
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
			// Preserve the SOURCE dir's permissions (MkdirAll applies the
			// umask and won't chmod an existing dir, so set it explicitly) —
			// otherwise versions/<ver>/ could end up more permissive than
			// staged/ for a non-0755 staged subdir. preservedMode keeps the
			// setuid/setgid/sticky bits too (Copilot).
			if err := os.Chmod(target, preservedMode(e.info.Mode())); err != nil {
				return fmt.Errorf("chmod %s: %w", target, err)
			}
			createdDirs = append(createdDirs, target)
		case e.info.Mode().IsRegular():
			if err := copyFileFsync(e.path, target, e.info.Mode()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("copyTreeFsync: unsupported file type for %s", e.path)
		}
	}
	// Fsync created dirs deepest-first so a child's entries are durable
	// before the parent entry referencing it.
	sort.Slice(createdDirs, func(i, j int) bool {
		di := strings.Count(createdDirs[i], string(os.PathSeparator))
		dj := strings.Count(createdDirs[j], string(os.PathSeparator))
		if di != dj {
			return di > dj
		}
		return createdDirs[i] > createdDirs[j]
	})
	for _, d := range createdDirs {
		if err := fsatomic.SyncDir(d); err != nil {
			return fmt.Errorf("fsync copied dir %s: %w", d, err)
		}
	}
	return nil
}

// preservedMode returns the chmod-applicable mode bits of m: the rwx
// permission bits PLUS setuid/setgid/sticky. m.Perm() alone masks the
// special bits off (Copilot). Staged content is 0755 today, so this is
// forward-looking exactness rather than a current bug.
func preservedMode(m os.FileMode) os.FileMode {
	return m.Perm() | (m & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky))
}

func copyFileFsync(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	// OpenFile applies the umask to the create mode, so chmod to the exact
	// source mode — the staged binaries are 0755 and must stay executable
	// through versions/<ver>/ regardless of the installing process's umask.
	// preservedMode keeps any setuid/setgid/sticky bits too (Copilot).
	if err := out.Chmod(preservedMode(mode)); err != nil {
		out.Close()
		return fmt.Errorf("chmod %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return fmt.Errorf("fsync %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	return nil
}
