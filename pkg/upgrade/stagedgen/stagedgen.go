// Package stagedgen implements Option B of #1981 — immutable, versioned
// publication of the dpkg-staged binary set into generation-keyed source
// directories, so the in-place-upgrade cut reads a WHOLE, single-generation
// source that dpkg is NOT actively rewriting.
//
// # The race this closes
//
// dpkg unpacks the managed binaries into the dpkg-owned staging path one file
// at a time (write `<bin>.dpkg-new`, rename over `<bin>`). Across an `apt
// upgrade` unpack window the staging dir therefore holds a MIX of old and new
// binaries. The legacy cut (`copyStaged`, pkg/upgrade) copied directly from
// that live staging dir, so a cut landing inside the unpack window could
// publish a `versions/<ver>` mixing binaries from two dpkg generations — a
// torn set whose verify-dataplane gate (xpfd+shim only) cannot detect a
// mismatched `xpf-userspace-dp`. See #1981 / docs/in-place-upgrade.md.
//
// # The mechanism (Option B)
//
// After a COMPLETE unpack (Debian Policy §6.7: `postinst configure` runs after
// all files are unpacked and the dpkg frontend lock serializes transactions),
// the postinst PUBLISHES the staged tree into an immutable, generation-keyed
// source directory:
//
//	staged-gen/<genid>/        # one immutable copy of the staged set
//	staged-gen/current-gen     # atomic symlink naming the latest generation
//
// The publish is `.partial` + atomic-rename + dir-fsync, then an atomic
// (temp-symlink + rename) repoint of `current-gen`. A crash before the dir
// rename leaves a `.partial` (pre-swept on the next publish); a crash after
// the dir rename but before the `current-gen` repoint leaves a
// complete-but-unreferenced generation (the prior `current-gen` stays valid,
// and the next publish re-publishes idempotently). There is NEVER a torn
// published generation and NEVER an absent `current-gen`.
//
// The cut then resolves `current-gen` ONCE at INIT, records the genid in its
// journal, and copies from the resolved `staged-gen/<genid>/` DIRECTORY (never
// re-reading the symlink, never reading live staged/) — so a concurrent
// publish cannot redirect an in-flight cut, and the copy is internally a
// single generation by construction.
//
// # Lifecycle ownership
//
// staged-gen/ is maintainer-script-managed runtime state under /var/lib/xpf/
// (a sibling of versions/), NEVER a dpkg payload file — so dpkg never writes
// or removes it on unpack (it only touches its own recorded payload files).
// The postrm removes it on purge and on a downgrade to a pre-B package.
//
// # GC
//
// GC mirrors the versions/ GC shape but with a SMALLER retention (N=2:
// current + 1 prior). Unlike versions/ (which backs binary+DB rollback to N
// prior versions), staged-gen/ is only ever a CUT SOURCE: once superseded by a
// newer current-gen an older generation is never read again. GC protects
// current-gen AND any genid an active/resumable journal still references
// (the caller supplies the protected genid set), and sweeps .partial orphans.
package stagedgen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/upgrade/manifest"
)

const (
	// DirName is the staged-generation root, a sibling of versions/ under
	// /var/lib/xpf. The default absolute path is DefaultDir; tests override
	// via Config.Dir.
	DirName = "staged-gen"

	// DefaultDir is the production staged-generation root.
	DefaultDir = "/var/lib/xpf/" + DirName

	// CurrentGenLink is the atomic symlink naming the latest complete
	// generation, mirroring versions/current.
	CurrentGenLink = "current-gen"

	// SrcGenFile is the dotfile stamped INSIDE versions/<ver>/ recording the
	// source generation a version dir was cut from (B-P3b OPT1 identity
	// stamp). It lives inside the version dir so GC removes it with the dir.
	SrcGenFile = ".srcgen"

	// PackageVersionFile records the Debian package version carried by
	// this immutable generation. Binary cutover compares this version,
	// never the staged binary's git-describe self-report, against the
	// persisted anti-rollback high-water mark.
	PackageVersionFile = ".xpf-package-version"
	// RetainGenerations is N in the staged-gen retention policy: keep the
	// current generation + 1 prior. Smaller than versions/ N=3 because a
	// superseded generation is never read again (B-P5 / plan §4.B.5).
	RetainGenerations = 2

	partialSuffix = ".partial"
)

// Config configures publish / resolve / GC against a staged-generation root.
// Zero values fall back to the production layout.
type Config struct {
	// StagedDir is the dpkg-owned staging path to publish FROM (the source).
	StagedDir string
	// Dir is the staged-generation root to publish INTO. Defaults to
	// DefaultDir.
	Dir string
	// PackageVersion is the Debian version of the xpf package publishing
	// the generation. When present, Publish records it inside the
	// immutable generation so the cut can order this target against its
	// durable anti-rollback floor.
	PackageVersion string
	// Logf is an optional progress sink (defaults to no-op).
	Logf func(format string, args ...any)
}

func (c *Config) withDefaults() {
	if c.Dir == "" {
		c.Dir = DefaultDir
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// GenID returns a fresh generation identifier: a zero-padded wall-clock
// nanosecond timestamp (time.Now().UnixNano(), so lexicographic order USUALLY
// matches chronological order) joined with a random suffix. The timestamp is
// NOT strictly monotonic — an NTP step can move the wall clock backward — so
// it is only a generation key + a stable, mtime-independent GC ordering hint;
// correctness never depends on genid ordering (GC protects current-gen and
// journal-referenced generations explicitly). The random suffix makes a
// same-version reinstall (or two publishes in the same nanosecond) yield
// DISTINCT generations (plan B-P5). The result is a safe single path segment
// (lowercase hex + a single '-').
func GenID() string {
	var b [8]byte
	// crypto/rand never fails on Linux; if it ever did, fall back to a
	// time-only suffix so the genid is still unique-enough and a publish is
	// never blocked on entropy.
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%020d-%016x", time.Now().UnixNano(), time.Now().UnixNano())
	}
	return fmt.Sprintf("%020d-%s", time.Now().UnixNano(), hex.EncodeToString(b[:]))
}

// ValidGenID reports whether s is a syntactically valid generation id (the
// shape GenID produces): non-empty, not current-gen, no '.' prefix (so it can
// never collide with the current-gen temp file or a .partial), no path
// separators or "..", and only lowercase-hex + a single '-'. A resolved genid
// keys staged-gen/<genid>, so it MUST be a safe single path segment before any
// path use.
func ValidGenID(s string) bool {
	if s == "" || s == CurrentGenLink {
		return false
	}
	if strings.HasPrefix(s, ".") {
		return false
	}
	if strings.ContainsAny(s, "/\x00") {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	dashes := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r == '-':
			dashes++
		default:
			return false
		}
	}
	return dashes == 1
}

func (c Config) logf(format string, args ...any) { c.Logf(format, args...) }

// genDir returns the directory for a generation id.
func (c Config) genDir(genid string) string { return filepath.Join(c.Dir, genid) }

// currentGenPath returns the path of the current-gen symlink.
func (c Config) currentGenPath() string { return filepath.Join(c.Dir, CurrentGenLink) }

// Publish copies the staged set into a fresh, immutable staged-gen/<genid>/
// and atomically repoints current-gen at it. It returns the new genid.
//
// Steps (each crash-safe; plan B-P2):
//  1. pre-sweep stale staged-gen/*.partial (a crashed prior publish must not
//     accumulate half-copies that exhaust /var — B-P2b);
//  2. copy staged/* -> staged-gen/<genid>.partial (durable per-file fsync);
//  3. record package identity in the .partial, fsync it, atomic-rename to
//     staged-gen/<genid>, and fsync Dir;
//  4. repoint current-gen -> <genid> via temp-symlink + rename + dir-fsync.
//
// The caller is responsible for holding the host-wide upgrade lock (the
// postinst path serializes publish against an operator cut so GC cannot
// delete a generation a cut is reading). Publish does NOT take the lock
// itself so it composes with a caller that already holds it.
func (c Config) Publish() (genid string, err error) {
	c.withDefaults()
	if c.StagedDir == "" {
		return "", fmt.Errorf("stagedgen: StagedDir is required")
	}
	if err := fsatomic.MkdirAllDurable(c.Dir, 0o755); err != nil {
		return "", fmt.Errorf("stagedgen: create %s: %w", c.Dir, err)
	}

	// 1. Pre-sweep stale .partial dirs (B-P2b): a crashed prior publish leaves
	// a half-copy that would otherwise leak /var space until the next GC.
	c.sweepPartials()

	genid = GenID()
	// Defensive: GenID is internal, but a path is keyed by it, so validate.
	if !ValidGenID(genid) {
		return "", fmt.Errorf("stagedgen: generated an invalid genid %q (bug)", genid)
	}

	finalDir := c.genDir(genid)
	partial := finalDir + partialSuffix

	// 2. Copy staged/* -> <genid>.partial.
	_ = os.RemoveAll(partial)
	if err := fsatomic.CopyTreeDurable(c.StagedDir, partial, fsatomic.CopyTreeOptions{}); err != nil {
		_ = os.RemoveAll(partial)
		return "", fmt.Errorf("stagedgen: copy staged -> %s: %w", partial, err)
	}
	if c.PackageVersion != "" {
		if err := fsatomic.WriteFileDurable(filepath.Join(partial, PackageVersionFile),
			[]byte(c.PackageVersion+"\n"), 0o644); err != nil {
			_ = os.RemoveAll(partial)
			return "", fmt.Errorf("stagedgen: record package version %s: %w", c.PackageVersion, err)
		}
	}
	// 3. Make the .partial contents durable, then atomically rename it into place.
	if err := fsatomic.SyncDir(partial); err != nil {
		_ = os.RemoveAll(partial)
		return "", fmt.Errorf("stagedgen: fsync partial: %w", err)
	}
	if err := os.Rename(partial, finalDir); err != nil {
		_ = os.RemoveAll(partial)
		return "", fmt.Errorf("stagedgen: atomic rename %s -> %s: %w", partial, finalDir, err)
	}
	if err := fsatomic.SyncDir(c.Dir); err != nil {
		return "", fmt.Errorf("stagedgen: fsync %s after rename: %w", c.Dir, err)
	}

	// 4. Atomically repoint current-gen -> <genid>. A crash before this leaves
	// the prior current-gen valid (the new gen dir is complete but
	// unreferenced; a re-publish is idempotent, and the GC's protected set
	// keeps the dir from being prematurely reaped if a journal references it).
	if err := atomicRelSymlink(c.currentGenPath(), genid); err != nil {
		return "", fmt.Errorf("stagedgen: repoint current-gen -> %s: %w", genid, err)
	}
	c.logf("stagedgen: published generation %s (current-gen -> %s)", genid, genid)
	return genid, nil
}

// ResolveCurrent reads the current-gen symlink and returns the genid it names,
// validated as a safe single path segment. It returns ("", nil) when
// current-gen is absent (no generation published yet — the cut refuses with no
// source). A current-gen present but naming an unsafe / missing generation is
// an error (a corrupt layout must not key a path off it).
func (c Config) ResolveCurrent() (string, error) {
	c.withDefaults()
	target, err := os.Readlink(c.currentGenPath())
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("stagedgen: read current-gen: %w", err)
	}
	// current-gen MUST be a BARE in-tree generation name — a single path
	// segment with NO directory components (Copilot r4). A corrupt/hand-edited
	// symlink target like "../<genid>" or "/tmp/<genid>" would pass
	// ValidGenID(filepath.Base(target)) yet escape the staged-gen root, so we
	// require target == its own base (no separators) BEFORE deriving the genid.
	if target != filepath.Base(target) {
		return "", fmt.Errorf("stagedgen: current-gen target %q is not a bare in-tree "+
			"generation name (must have no path components)", target)
	}
	genid := target
	if !ValidGenID(genid) {
		return "", fmt.Errorf("stagedgen: current-gen names an unsafe generation %q", genid)
	}
	// The dir MUST exist — current-gen is only repointed AFTER the gen dir is
	// renamed into place, so a dangling current-gen is a corrupt layout.
	if fi, serr := os.Stat(c.genDir(genid)); serr != nil || !fi.IsDir() {
		return "", fmt.Errorf("stagedgen: current-gen -> %s but %s is missing or not a directory",
			genid, c.genDir(genid))
	}
	return genid, nil
}

// GenDir returns the absolute path of a published generation directory. The
// caller MUST have validated genid (via ValidGenID) before use; this is the
// directory the cut copies FROM.
func (c Config) GenDir(genid string) string {
	c.withDefaults()
	return c.genDir(genid)
}

// GC removes generation dirs beyond RetainGenerations, ordering by genid name
// (mtime-independent and deterministic — GenID's zero-padded wall-clock
// timestamp prefix makes lexicographic name order USUALLY chronological; an
// NTP step can reorder, but correctness never depends on it — see below). It
// NEVER removes the current-gen generation (resolved explicitly, protected
// additively) NOR any
// genid in protected (the generations an active/resumable journal still
// references — plan §4.B.5 / B-P3 GC-vs-resume protection), and it ignores
// (never counts toward retention, never deletes) any directory whose name is
// not a valid genid. It also sweeps .partial orphans. A missing staged-gen
// root is a no-op.
func (c Config) GC(protected map[string]bool) error {
	c.withDefaults()
	c.sweepPartials()

	entries, err := os.ReadDir(c.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stagedgen: read %s: %w", c.Dir, err)
	}

	// The caller's `protected` set (journal-referenced generations) PLUS the
	// current generation are kept ADDITIVELY — outside and on top of the
	// RetainGenerations window — so a journal-pinned OLD generation never
	// pushes an in-window generation out, and the active cut source is never
	// reaped even if directory mtimes are perturbed (Copilot). current-gen is
	// resolved EXPLICITLY rather than relying on it being the newest by mtime.
	extraProtected := map[string]bool{}
	for g := range protected {
		extraProtected[g] = true
	}
	// #6763: an UNRESOLVABLE current generation aborts the GC. This used to
	// read `if cur, rerr := c.ResolveCurrent(); rerr == nil && cur != ""`,
	// which DISCARDED rerr — so when current-gen could not be resolved the
	// live generation simply was not added to the protection set, and the
	// destructive loop below then deleted it as soon as it fell outside the
	// retention window.
	//
	// Every one of ResolveCurrent's error paths means "I cannot establish
	// which generation is live", and each is reachable: a readlink failure
	// (I/O, permissions), a hand-edited symlink with path components that
	// would escape the staged-gen root, a target that is not a valid genid,
	// and a DANGLING current-gen whose directory is missing. The last is the
	// sharpest — a corrupt layout is exactly when the live generation most
	// needs protecting, and it was exactly when protection silently vanished.
	//
	// ResolveCurrent already distinguishes the one benign case: NO current-gen
	// link at all returns ("", nil), not an error, so a fresh root that has
	// never published still GCs normally. Absence is determinate; failure is
	// not.
	//
	// Aborting is the established response, not a new policy: publish-
	// generation applies the same rule to the OTHER half of the protection set
	// (#4876) — "if the journal is present but unreadable or malformed, we
	// cannot see which generation a crashed cut pins, so GC is SKIPPED rather
	// than run with an empty protection set", and "skipping is safe — the
	// extra staged generations are harmless and the next publish reclaims
	// them". current-gen was the half that never got the rule. All three
	// callers already treat a GC error as a warning, never fatal, so this
	// degrades to "GC skipped" and cannot block a publish, a seed or a cut.
	//
	// sweepPartials above stays: a `.partial` directory is never a generation
	// (ValidGenID cannot match a name carrying partialSuffix, so current-gen
	// can never resolve to one), so removing them cannot destroy the live
	// generation and is not gated on identifying it.
	cur, rerr := c.ResolveCurrent()
	if rerr != nil {
		return fmt.Errorf("stagedgen: gc REFUSED, no generation deleted: the current "+
			"generation could not be resolved, so it cannot be protected from "+
			"deletion: %w", rerr)
	}
	if cur != "" {
		extraProtected[cur] = true
	}

	// Collect ONLY valid generation dirs (Copilot): a stray non-generation
	// directory must neither consume a retention slot nor be deleted. Order by
	// NAME, greatest first — GenID prefixes a zero-padded wall-clock nanosecond
	// timestamp, so lexicographic name order is mtime-INDEPENDENT and
	// deterministic (even when coarse-resolution mtimes tie), and USUALLY
	// chronological. A backward wall-clock step (NTP) can reorder, but
	// correctness never depends on it: current-gen and journal-referenced
	// generations are protected EXPLICITLY (below), so a misordering at most
	// changes which NON-protected, non-live generation is reaped first.
	var gens []string
	for _, e := range entries {
		n := e.Name()
		if n == CurrentGenLink || strings.HasPrefix(n, ".") {
			continue
		}
		if !e.IsDir() || !ValidGenID(n) {
			continue
		}
		gens = append(gens, n)
	}
	sort.Slice(gens, func(i, j int) bool { return gens[i] > gens[j] })

	kept := 0
	removedAny := false
	for _, g := range gens {
		// The RetainGenerations newest generations form the window.
		if kept < RetainGenerations {
			kept++
			continue
		}
		// Outside the window: keep ONLY if current-gen or journal-referenced
		// (additive protection — never reap the active source or a generation a
		// resumable cut still pins).
		if extraProtected[g] {
			continue
		}
		c.logf("stagedgen: gc removing old generation %s", g)
		if rerr := os.RemoveAll(c.genDir(g)); rerr != nil {
			c.logf("stagedgen: WARN gc remove %s: %v", g, rerr)
			continue
		}
		removedAny = true
	}
	if removedAny {
		if serr := fsatomic.SyncDir(c.Dir); serr != nil {
			c.logf("stagedgen: WARN fsync %s after gc: %v", c.Dir, serr)
		}
	}
	return nil
}

// RemoveAll removes the entire staged-generation root (postrm purge / pre-B
// downgrade cleanup, B-P6). Best-effort; a missing root is a no-op.
func (c Config) RemoveAll() error {
	c.withDefaults()
	if err := os.RemoveAll(c.Dir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stagedgen: remove %s: %w", c.Dir, err)
	}
	return nil
}

// sweepPartials removes any staged-gen/*.partial dirs (a crashed publish), and
// fsyncs Dir if it removed anything so the unlink cannot be resurrected.
func (c Config) sweepPartials() {
	entries, err := os.ReadDir(c.Dir)
	if err != nil {
		return
	}
	removedAny := false
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, partialSuffix) {
			_ = os.RemoveAll(filepath.Join(c.Dir, n))
			removedAny = true
		}
	}
	if removedAny {
		if serr := fsatomic.SyncDir(c.Dir); serr != nil {
			c.logf("stagedgen: WARN fsync %s after partial sweep: %v", c.Dir, serr)
		}
	}
}

// ManagedNames returns the managed-binary basenames a published generation
// contains. Exposed so the cut and tests share the SSOT list.
func ManagedNames() []string { return manifest.Names() }
