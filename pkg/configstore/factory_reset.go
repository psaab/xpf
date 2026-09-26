package configstore

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// DefaultArchiveDir is the xpf-owned DEFAULT local config-archive directory —
// the pkg/config archival compiler default (compiler_system.go) and the
// pkg/daemon runtime fallback (daemon_apply.go). writeArchive drops timestamped
// config-<ts>.<seq>.conf snapshots here, each a 0600 copy of the full committed
// config TEXT with cleartext secret leaves (IKE PSK, WireGuard private keys,
// SNMP communities, BGP MD5). It is the ONLY archive path a factory reset
// provably owns and is therefore allowed to erase (see FactoryResetArchiveDir's
// ownership guard).
//
// KEEP IN SYNC with the pkg/config archival compiler default: pkg/config cannot
// import pkg/configstore (configstore already imports config), so the literal
// is duplicated rather than shared. If the compiler default ever moves, this
// must move with it or a zeroize would skip the real archive.
//
// It is a var, not a const, so the zeroize tests can repoint the ownership
// guard at a throwaway tree (mirroring the grpcapi zeroize* path seams).
// Production code must never mutate it.
var DefaultArchiveDir = "/var/lib/xpf/archive"

// RescueConfigBase is the fixed base name of the xpf rescue configuration file
// the daemon writes alongside the live config (Store.rescuePath ->
// "<configDir>/rescue.conf"). It is the full active-config TEXT with cleartext
// secret leaves (IKE PSK, WireGuard keys, SNMP communities, #4056), so a factory
// reset must erase it. It is a named constant — rather than a bare "rescue.conf"
// literal scattered across the wipe primitives — so the config-state wipe's
// ownership-scoped top-level match (#5768) deletes EXACTLY this xpf-owned name
// instead of a broad `*.conf` glob that also caught unowned siblings. KEEP IN
// SYNC with Store.rescuePath; the grpcapi wipe mirror references this const.
const RescueConfigBase = "rescue.conf"

// Day0ConfigAppliedBase is the loader's successful-configuration stamp
// (scripts/image/xpf-day0-config and xpf-day0-config.service). A factory reset
// removes it so the loader can accept a new medium after reboot.
const Day0ConfigAppliedBase = ".day0-config-applied"

// FactoryResetArchiveDir erases the LOCAL configuration archive as part of a
// factory reset (#5186) — but ONLY when archiveDir is the xpf-owned default.
//
// WHY the wipe must erase it: zeroize must remove EVERY on-box generation of
// config secrets (the .configdb SSOT + master.key, the numbered text rollback
// slots, the audit journal, the rendered service configs, and the login
// accounts are all wiped by the sibling FactoryResetConfigDir /
// zeroizeRenderedConfigs / zeroizeLoginAccounts). The local config archive was
// the OMITTED generation: a pre-#5186 zeroize left /var/lib/xpf/archive
// untouched, so a device handed to the next tenant after a factory reset still
// carried 0600 full-config-text copies with the prior tenant's cleartext PSKs,
// keys, and communities.
//
// SymlinkedTarget names one path the factory reset was asked to ERASE that
// turned out to be a SYMLINK, together with what it pointed at.
type SymlinkedTarget struct {
	Path   string // the path the reset would have removed
	Target string // where the link pointed — where the secrets actually are
}

// FactoryResetSymlinkError reports that one or more paths the factory reset
// must erase were SYMLINKS, so they were left alone rather than unlinked
// (#9013).
//
// This is the UNDER-wipe direction, and it is silent by construction: os.Remove
// and os.RemoveAll operate on the LINK when the final path component is one.
// They unlink it, return nil, and the real bytes — archived config text,
// active.json, the live config, the rescue config, the audit journal, the
// numbered rollback slots — stay on the target volume. Each carries cleartext
// secret leaves (IKE PSKs, WireGuard private keys, SNMP communities, BGP MD5)
// unless a `system master-password` is configured, which is not the default.
// The operator was told "System zeroized. Configuration erased."
//
// The .configdb shape is the worst ordering, which is why that check runs
// BEFORE any removal: master.key is deleted THROUGH the link (a path inside a
// symlinked directory resolves normally), and only then does RemoveAll unlink
// the directory link — destroying the key while leaving the config body. On an
// unencrypted DB that body is the full cleartext config, so the key-first
// cryptographic-erasure guarantee buys nothing.
//
// Like ArchiveDirSkippedError this is a distinct type, not a plain error: the
// caller must tell "the secrets are still on disk" apart from "the erasure
// failed", and it is NOT a reason to abort the rest of the wipe. Use errors.As.
//
// Refusing rather than resolving-and-erasing is deliberate and matches
// ValidateFactoryResetRoot's stated doctrine: a link may point at a shared,
// remote or compliance volume that is not xpf's to destroy, so the reset fails
// CLOSED and hands the operator the exact paths instead of guessing.
type FactoryResetSymlinkError struct {
	Skipped []SymlinkedTarget
}

func (e *FactoryResetSymlinkError) Error() string {
	var b strings.Builder
	b.WriteString("factory reset did NOT erase ")
	if len(e.Skipped) == 1 {
		b.WriteString("1 path because it is a symlink")
	} else {
		fmt.Fprintf(&b, "%d paths because they are symlinks", len(e.Skipped))
	}
	b.WriteString(" (removing one would unlink the LINK and leave the real data): ")
	for i, sk := range e.Skipped {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(sk.Path + " -> " + sk.Target)
	}
	b.WriteString(". The configuration text and any secrets it contains remain on " +
		"the target volume; erase these manually to complete the zeroize")
	return b.String()
}

// HardlinkedPath names a managed regular file that has another directory entry
// for the same inode. The other names are intentionally not guessed: a
// pathname does not contain enough information to enumerate hardlink siblings.
// Dev and Ino are captured before the managed name is removed so remediation
// remains possible after the wipe.
type HardlinkedPath struct {
	Path  string
	Nlink uint64
	Dev   uint64
	Ino   uint64
}

// FactoryResetHardlinkError reports managed files whose contents can survive
// the wipe through another hardlink name. The managed name is still removed
// along with the other safe artifacts, but the reset is incomplete and must
// not be reported as successful.
//
// The operator must locate and remove every hardlink name by scanning the
// filesystem containing each captured device/inode pair (for example with
// `find <filesystem-root> -xdev -inum <inode>`), then rerun zeroize. Sibling
// names are not enumerable from the managed path alone, so this error names
// only attested paths and the metadata needed for that scan.
type FactoryResetHardlinkError struct {
	Paths []HardlinkedPath
}

func (e *FactoryResetHardlinkError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "factory reset incomplete: %d managed path", len(e.Paths))
	if len(e.Paths) != 1 {
		b.WriteString("s")
	}
	b.WriteString(" still has multiple hard-link names (the sibling names cannot be enumerated from the managed path): ")
	for i, p := range e.Paths {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s (dev=%d ino=%d nlink=%d; scan with `find <filesystem-root> -xdev -inum %d`)", p.Path, p.Dev, p.Ino, p.Nlink, p.Ino)
	}
	b.WriteString(". Remove every hard-link name found by those inode scans, then rerun zeroize")
	return b.String()
}

// SymlinkTarget reports whether path's FINAL component is a symlink, and where
// it points. Only the final component matters: when an INTERMEDIATE component
// is a link, os.RemoveAll resolves through it and does erase the real directory
// — measured, not assumed.
//
// A path that does not exist is not a symlink: the callers treat absence as
// "nothing to erase", matching RemoveAll's nil-on-absent contract.
//
// Exported because the zeroize erase logic exists TWICE — here and in
// pkg/grpcapi's zeroizeConfigDir, which is the one production actually runs
// (this file's FactoryResetConfigDir has no non-test caller). Sharing the
// predicate is the only thing keeping the #9013 guard from landing on one of
// the pair and silently missing the other, which is how the duplication bit
// the first time.
func SymlinkTarget(path string) (SymlinkedTarget, bool) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return SymlinkedTarget{}, false
	}
	target, rerr := os.Readlink(path)
	if rerr != nil {
		target = "<unreadable link target>"
	}
	return SymlinkedTarget{Path: path, Target: target}, true
}

// CollectInteriorSymlinks censuses every symlink UNDER root for the zeroize
// wipe (#10100 R-1). The #9013 guards check only the top paths (.configdb +
// master.key, tls/, .old/.restore.partial dir+key) then RemoveAll: a real dir
// holding a symlinked interior file has the link unlinked while the target
// bytes survive, nil returned. This pre-walk collects ANY interior symlink
// (flat, nested, symlink-to-dir, dangling, chain — WalkDir reports the link
// itself and does not descend into symlinked dirs, symmetric with RemoveAll
// unlinking without descending) so the caller can report them via
// FactoryResetSymlinkError while still erasing regulars.
//
// exclude, when non-empty, is ONE exact cleaned path to skip (the
// root-child master.key the caller's inverse-shape branch already owns).
// Comparison is by filepath.Clean equality, never basename: a nested
// subdir/master.key link MUST still be reported.
//
// Contract:
//   - absent root (Lstat ENOENT, incl. dangling INTERMEDIATE) → nil,nil;
//     absence is the goal, matching RemoveAll's nil-on-absent.
//   - root itself a symlink → [{root}],nil, no walk. The caller MUST treat
//     this as skip-whole-block (don't RemoveAll), mirroring the existing
//     .configdb whole-block skip; it closes a root-swap TOCTOU between the
//     caller's dir check and this census.
//   - file-not-dir root → nil,nil (WalkDir yields root only, skipped).
//   - non-ENOENT Lstat failure → nil,err; the caller fail()s it but still
//     attempts the erasure best-effort.
//   - per-entry walk error → (partial, wrapped census-incomplete err naming
//     root). The walk ABORTS (never skips a subtree); partial Skipped is
//     kept (a lower bound, never complete) and the error states coverage
//     is unknown.
//
// R-1 Skipped means link-unlinked-target-survives (RemoveAll still runs,
// like the master.key inverse-shape precedent), unlike R-2 leave-the-link.
// The recorded Target is Readlink as-is (possibly relative); resolve it
// against Dir(Path) (a known string even after unlink) like #9013.
//
// The census covers SYMLINKS and regular-file HARDLINKS. A same-filesystem
// hardlink (nlink>1) to interior content survives RemoveAll via its other name;
// CollectHardlinkedFiles attests that condition before removal and reports the
// managed path and count. The other names are not enumerable from that path,
// so the dedicated FactoryResetHardlinkError tells the operator to locate and
// remove every name before rerunning zeroize.
//
// Accepted residual: the validated census is a pathname walk, not a pinned
// handle — a concurrent plant DURING the wipe (dbDir/tls write while the
// walk + key fsync + RemoveAll run) could add a link after the census and
// report clean while it survives unlinked-but-unreported. Deterministic
// plants (link in place when zeroize runs — the modeled attack) ARE closed.
// Full closure needs descriptor-relative traversal (see
// ResolveFactoryResetRoot), excluded like every path-based guard.
func CollectInteriorSymlinks(root, exclude string) ([]SymlinkedTarget, error) {
	fi, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, rerr := os.Readlink(root)
		if rerr != nil {
			target = "<unreadable link target>"
		}
		return []SymlinkedTarget{{Path: root, Target: target}}, nil
	}
	if !fi.IsDir() {
		return nil, nil
	}
	var out []SymlinkedTarget
	cleanExclude := ""
	if exclude != "" {
		cleanExclude = filepath.Clean(exclude)
	}
	walkErr := filepath.WalkDir(root, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if p == root {
			return nil
		}
		_ = d
		if cleanExclude != "" && filepath.Clean(p) == cleanExclude {
			return nil
		}
		if sk, isLink := SymlinkTarget(p); isLink {
			out = append(out, sk)
		}
		return nil
	})
	if walkErr != nil {
		return out, fmt.Errorf("census interior symlinks under %s incomplete: %w", root, walkErr)
	}
	return out, nil
}

// CollectHardlinkedFiles attests the regular files under root before a wipe.
// It uses Lstat for every candidate so a symlink is never followed. A regular
// file with nlink>1 is returned as an attested managed path; sibling names are
// not inferable from that path and are intentionally not fabricated.
//
// Like CollectInteriorSymlinks, an absent root is a clean no-op and a walk
// failure returns the partial census plus an error. Callers continue their
// best-effort erase while surfacing that error.
func CollectHardlinkedFiles(root, exclude string) ([]HardlinkedPath, error) {
	cleanExclude := ""
	if exclude != "" {
		cleanExclude = filepath.Clean(exclude)
	}
	var out []HardlinkedPath
	inspect := func(path string) error {
		if cleanExclude != "" && filepath.Clean(path) == cleanExclude {
			return nil
		}
		fi, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return nil
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot attest hardlink count for %s: unsupported file metadata", path)
		}
		if st.Nlink > 1 {
			out = append(out, HardlinkedPath{
				Path:  path,
				Nlink: uint64(st.Nlink),
				Dev:   uint64(st.Dev),
				Ino:   uint64(st.Ino),
			})
		}
		return nil
	}

	fi, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if cleanExclude != "" && filepath.Clean(root) == cleanExclude {
		return nil, nil
	}
	if !fi.IsDir() {
		if err := inspect(root); err != nil {
			return nil, err
		}
		return out, nil
	}
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if cleanExclude != "" && filepath.Clean(path) == cleanExclude {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path == root {
			return nil
		}
		return inspect(path)
	})
	if walkErr != nil {
		return out, fmt.Errorf("census hardlinked files under %s incomplete: %w", root, walkErr)
	}
	return out, nil
}

// ArchiveDirSkippedError reports that the config archive was NOT erased because
// its directory could not be proven to be xpf-owned (#7173).
//
// It is deliberately a distinct type rather than a plain error: the caller must
// be able to tell "the archive still holds the prior tenant's secrets" apart
// from "the erasure failed", because they need different operator-facing words.
// It is also NOT a reason to abort the rest of the wipe — everything else must
// still be erased — so a caller that treats every non-nil error as fatal would
// make this change a regression. Use errors.As.
type ArchiveDirSkippedError struct {
	Dir string
}

func (e *ArchiveDirSkippedError) Error() string {
	return "config archive directory " + e.Dir + " was NOT erased: its ownership " +
		"could not be proven (not the xpf-owned default " + DefaultArchiveDir + "). " +
		"Archived configuration text and any secrets it contains remain on disk; " +
		"erase this directory manually to complete the zeroize"
}

// OWNERSHIP GUARD (#5186): erase the archive ONLY when archiveDir is the
// xpf-owned default (DefaultArchiveDir). An operator-configured CUSTOM archive
// directory may be a remote mount, an NFS export, or a compliance/audit
// retention store that is NOT xpf's to destroy — blindly deleting it could wipe
// records the operator is legally required to keep. Ownership cannot be proven
// for such a path, so it is SKIPPED with a warning rather than deleted (never
// fail-closed-delete). This mirrors how the config-state wipe proves ownership
// by its fixed default appliance path, and how zeroizeLoginAccounts refuses to
// touch a non-xpf-owned account.
//
// Discipline mirrors FactoryResetConfigDir: os.ErrNotExist is never an error
// (an already-absent archive is the goal); the whole archive tree is
// RemoveAll'd; the PARENT directory is then fsynced so the removal of the
// archive directory entry itself is durable before the completing reboot, and
// that fsync error is PROPAGATED — a fsync failure means the erasure may not be
// on stable storage, so it must not be reported as a clean zeroize. The
// durability barrier routes through the rbSyncDir seam so a dropped sync fails
// a test RED.
func FactoryResetArchiveDir(archiveDir string) error {
	// Ownership guard: only the xpf-owned default is provably safe to erase. A
	// custom/remote/compliance archive destination is skipped with a warning,
	// never blindly deleted.
	if filepath.Clean(archiveDir) != DefaultArchiveDir {
		slog.Warn("zeroize: skipping config archive directory with unproven "+
			"ownership (not the xpf-owned default); a custom, remote, or "+
			"compliance archive destination is the operator's to erase, not "+
			"the factory reset's",
			"dir", archiveDir, "default", DefaultArchiveDir)
		// #7173: the skip is a FIRST-CLASS RESULT, not a log line. This
		// function's own contract two paragraphs above says a merely
		// non-durable erasure "must not be reported as a clean zeroize"; a
		// skipped one did not happen AT ALL, which is strictly worse, and it
		// returned nil. An operator who ran zeroize on a box with a custom
		// archive-dir was told the reset completed while every archived config
		// snapshot — carrying cleartext IKE PSKs, WireGuard keys and SNMP
		// communities — was still on disk.
		//
		// The skip itself stays: erasing a directory whose ownership cannot be
		// proven could destroy compliance records that are not xpf's to delete.
		// What changes is that the caller can no longer mistake it for success.
		return &ArchiveDirSkippedError{Dir: archiveDir}
	}

	var firstErr error
	fail := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}

	// #9013: if the archive dir is itself a SYMLINK, RemoveAll unlinks the LINK
	// and returns nil — every config-<ts>.<seq>.conf snapshot survives on the
	// target volume while the operator is told the box was zeroized. Refuse and
	// report; the link may point at a volume xpf does not own.
	if sk, isLink := SymlinkTarget(archiveDir); isLink {
		slog.Warn("zeroize: config archive directory is a symlink; NOT erasing it — "+
			"removing it would unlink the link and leave the archived config text",
			"dir", sk.Path, "target", sk.Target)
		return &FactoryResetSymlinkError{Skipped: []SymlinkedTarget{sk}}
	}
	// #10100 GPT-3: a real archive dir holding a symlinked
	// config-<ts>.<seq>.conf snapshot has the link unlinked while the full
	// cleartext config survives on the target volume — the same R-1 shape as
	// tls/.configdb interior. Census ANY interior link (no exclusion: the
	// archive has no master.key shape), still RemoveAll regulars. A root-link
	// result here is a TOCTOU swap after the check above: refuse whole.
	var skipped []SymlinkedTarget
	var hardlinks []HardlinkedPath
	if interior, cerr := CollectInteriorSymlinks(archiveDir, ""); len(interior) == 1 && interior[0].Path == archiveDir {
		slog.Warn("zeroize: config archive directory is a symlink; NOT erasing it — "+
			"removing it would unlink the link and leave the archived config text",
			"dir", interior[0].Path, "target", interior[0].Target)
		return &FactoryResetSymlinkError{Skipped: interior}
	} else {
		for _, sk := range interior {
			slog.Warn("zeroize: config archive interior is a symlink; the link will be "+
				"unlinked but the target bytes survive — report, don't trust the wipe",
				"path", sk.Path, "target", sk.Target)
		}
		skipped = append(skipped, interior...)
		if cerr != nil {
			fail(cerr)
		}
	}
	found, herr := CollectHardlinkedFiles(archiveDir, "")
	hardlinks = append(hardlinks, found...)
	fail(herr)
	// Erase the whole archive tree — every config-<ts>.<seq>.conf snapshot of
	// the prior tenant's config text. RemoveAll is nil on an absent dir.
	fail(os.RemoveAll(archiveDir))

	// fsync the PARENT so the unlink of the archive directory entry itself is
	// durable before the reboot that completes the factory reset. A sync
	// failure is propagated — a silently non-durable erasure must never be
	// reported as a clean zeroize. ErrNotExist (parent absent → nothing was
	// removed) is excluded by fail().
	fail(rbSyncDir(filepath.Dir(archiveDir)))
	var result []error
	if len(skipped) > 0 {
		result = append(result, &FactoryResetSymlinkError{Skipped: skipped})
	}
	if len(hardlinks) > 0 {
		result = append(result, &FactoryResetHardlinkError{Paths: hardlinks})
	}
	if firstErr != nil {
		result = append(result, firstErr)
	}
	switch len(result) {
	case 0:
		return nil
	case 1:
		return result[0]
	default:
		return errors.Join(result...)
	}
}

// FactoryResetForbiddenRoots are directories a factory-reset config-state wipe
// must NEVER treat as an xpf-owned config root (#5684). FactoryResetConfigDir
// erases the xpf-owned config-state artifacts under configDir (the live config,
// rescue.conf, the audit journal, the numbered text rollback slots, fsatomic
// temps) and RemoveAll's <configDir>/.configdb. #5768 tightened the top-level
// match from a broad `*.conf` / `rollback*` glob to those EXACT xpf-owned names
// so an unowned sibling in the same directory is never deleted; this denylist
// remains as defense-in-depth against ever entering the wipe on a shared root at
// all. Every removal is bounded to configDir, but configDir itself is derived
// from filepath.Dir(store.ConfigPath()). A daemon started with a custom `-config`
// placed DIRECTLY in a shared directory (`-config /etc/xpf.conf` → configDir
// "/etc"; `-config /srv/site.conf` → "/srv") or pointed at a directory-shaped
// path (`-config /srv/firewall`, where filepath.Dir climbs to the PARENT
// "/srv") turns a factory reset into a broad deletion of files xpf does not own
// — the destructive-scope defect #5684 closes. ValidateFactoryResetRoot rejects
// these so the reset fails CLOSED (erases NOTHING, reports incomplete) instead
// of wiping the wrong tree. The default appliance root /etc/xpf and any
// dedicated subdirectory (/srv/xpf, /opt/xpf/data) are deliberately NOT on the
// list and pass. It is a var so a test can register a throwaway tree as a shared
// root (mirroring the DefaultArchiveDir seam); production code must never mutate
// it.
var FactoryResetForbiddenRoots = []string{
	"/",
	"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64",
	"/libx32", "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin",
	"/srv", "/sys", "/tmp", "/usr", "/usr/local", "/var", "/var/lib",
	"/var/tmp",
}

// ValidateFactoryResetRoot reports whether configDir is a plausible xpf-owned
// config root that a factory reset may erase, returning a descriptive error if
// it is not (#5684). configDir is filepath.Dir(store.ConfigPath()), so a
// custom/adversarial `-config` can resolve it to a directory xpf does not own;
// this is the guard that keeps `zeroize` from broad-deleting an enclosing
// directory. It rejects:
//
//   - a NON-ABSOLUTE path — an empty or relative `-config` resolves
//     filepath.Dir to "." (the daemon's working directory), never a config root;
//   - the filesystem root and the well-known shared/system directories in
//     FactoryResetForbiddenRoots — a `-config` placed directly in a shared
//     directory (or a directory-shaped `-config`, where filepath.Dir climbs to
//     the PARENT) would otherwise wipe *.conf / .configdb / tls siblings xpf
//     does not own.
//
// The comparison is lexical on filepath.Clean(configDir), so a trailing slash
// and `..` traversal (`/etc/xpf/..` → /etc) are normalized before the check.
// Callers surface the error so the reset erases NOTHING and reports incomplete
// rather than deleting the wrong tree. The default appliance root /etc/xpf and
// any dedicated subdirectory pass. This is a purely lexical guard (it does not
// resolve symlinks); a defense against config-path misconfiguration, not against
// an operator who symlinks the config root at a shared directory. Anything that
// ERASES must therefore resolve first (ResolveFactoryResetRoot), never call
// this on an unresolved path alone.
func ValidateFactoryResetRoot(configDir string) error {
	clean := filepath.Clean(configDir)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("zeroize: refusing to factory-reset non-absolute config root %q: a relative or empty -config path resolves to the daemon working directory, not an xpf config directory", configDir)
	}
	for _, forbidden := range FactoryResetForbiddenRoots {
		if clean == forbidden {
			return fmt.Errorf("zeroize: refusing to factory-reset shared/system directory %q as a config root: the -config path must live in a directory xpf owns (e.g. /etc/xpf), not directly in a shared directory whose siblings are not xpf's to erase", clean)
		}
	}
	return nil
}

// ResolveFactoryResetRoot resolves configDir to the directory a factory-reset
// wipe must actually validate and erase (#9897 F-040). ValidateFactoryResetRoot
// is lexical, while the wipe's ReadDir/RemoveAll follow links — so a root that
// REACHES a forbidden directory through a symlink passes the guard and the wipe
// deletes xpf-named files under a tree xpf does not own, reporting success.
// Resolving before BOTH validation and wipe closes the bypass; both wipe
// copies (FactoryResetConfigDir here and grpcapi.zeroizeConfigDir, the one
// production runs) and both early-gate resolvers share this one function so
// the pair cannot drift (#9013's lesson).
//
// BOTH the lexical path and the resolved target are validated, and either
// refusal wins: validating the resolved target alone would launder a
// lexically-forbidden root that is itself a link (e.g. /tmp -> /private/tmp)
// into a passing one, and validating the lexical path alone is the original
// defect. A link to a DEDICATED root still wipes (the resolved tree, which is
// where the daemon's live secrets are) — resolve, don't refuse — while a link
// to a forbidden root fails closed naming the link and the target.
//
// The denylist is ALSO matched by canonical identity: a forbidden root may be
// reachable by another pathname (merged-/usr /lib -> /usr/lib, a symlinked
// /tmp -> /private/tmp, or any test seam alias), and an alias of a forbidden
// directory is the same directory, not a dedicated root. Each EXISTING
// denylist entry is therefore canonicalized and the resolved candidate is
// compared against those identities too. This COMPLETES the denylist (same
// directories, all spellings) rather than extending it to new ones; absent
// entries are skipped, and the lexical rejections above are retained
// unchanged.
//
// An ABSENT root (Lstat ENOENT, including a dangling INTERMEDIATE link, which
// the kernel reports as ENOENT) validates lexically and returns the cleaned
// original: absence is the goal, and nothing is reachable to erase, so the
// wipe stays a clean no-op exactly as today. A DANGLING FINAL link (Lstat
// succeeds, EvalSymlinks fails) is a link, not an absence — reporting success
// would wipe nothing while telling the operator the box is clean, the #9013
// shape — so it is refused with the link named. Any other Lstat or resolution
// error fails closed.
//
// Accepted residual, stated accurately: the validated root is a PATHNAME, not
// a pinned handle — every wipe syscall below re-resolves it. A concurrent
// namespace mutation DURING the wipe (the root or an ancestor renamed/swapped
// to a link while the blocking dir fsyncs and recursive RemoveAll traversals
// run) could redirect the erasure at another tree or report clean while the
// validated tree's secrets survive. This is NOT a microsecond window: it spans
// the whole wipe. What it takes is write permission on the root's PARENT (or
// higher) during the wipe — parent-dir write, not root — plus, for
// destructive effect, exact-xpf-name collisions in the swapped-in tree (#5768
// scoping; #9013 final-component refusals still apply per artifact).
// Concurrent namespace mutation during a wipe is therefore EXCLUDED and
// documented here rather than timed away: the deterministic plant (a link
// already in place when zeroize runs — the modeled attack) IS closed above,
// and full closure would need descriptor-relative traversal (open the root
// once O_DIRECTORY|O_NOFOLLOW, then openat/unlinkat/fstat by dirfd; openat2
// with RESOLVE_NO_SYMLINKS is the direct form but not mandatory), which would
// rewrite both wipe copies' every destructive call site and seam. That
// exclusion matches every path-based guard in the repo (notably #9013's
// Lstat-then-act and the #5684 lexical gate itself).
func ResolveFactoryResetRoot(configDir string) (string, error) {
	clean := filepath.Clean(configDir)
	if err := ValidateFactoryResetRoot(clean); err != nil {
		return "", err
	}
	if _, lerr := os.Lstat(clean); lerr != nil {
		if os.IsNotExist(lerr) {
			return clean, nil
		}
		return "", fmt.Errorf("zeroize: cannot examine config root %q: %w "+
			"(refusing to factory-reset a root whose state cannot be determined)", clean, lerr)
	}
	resolved, rerr := filepath.EvalSymlinks(clean)
	if rerr != nil {
		if target, lerr := os.Readlink(clean); lerr == nil {
			return "", fmt.Errorf("zeroize: config root %q is a symlink to %q, which "+
				"cannot be resolved (%v) — refusing to factory-reset through it", clean, target, rerr)
		}
		return "", fmt.Errorf("zeroize: cannot resolve config root %q: %w "+
			"(refusing to factory-reset through an unresolvable root)", clean, rerr)
	}
	if resolved != clean {
		if verr := ValidateFactoryResetRoot(resolved); verr != nil {
			return "", fmt.Errorf("zeroize: config root %q resolves through a symlink "+
				"to %q: %w", clean, resolved, verr)
		}
	}
	// Canonical-identity denylist completion (see the doc above): refuse when
	// the resolved target IS a forbidden directory under another pathname.
	// This runs whether or not a link was involved — a direct alias spelling
	// (e.g. /private/tmp where /tmp is a link) has resolved == clean and
	// would otherwise pass both lexical checks.
	if alias := canonicalForbiddenAlias(resolved); alias != "" {
		if resolved != clean {
			return "", fmt.Errorf("zeroize: config root %q resolves through a symlink "+
				"to %q, which is the same directory as forbidden root %q: refusing to "+
				"factory-reset", clean, resolved, alias)
		}
		return "", fmt.Errorf("zeroize: config root %q is the same directory as "+
			"forbidden root %q (reached by another pathname): refusing to "+
			"factory-reset", resolved, alias)
	}
	return resolved, nil
}

// canonicalForbiddenAlias reports the denylist entry of which resolved is an
// alias — i.e. EvalSymlinks(entry) == resolved for an EXISTING entry — or ""
// when resolved is no forbidden directory under another pathname. Only
// existing entries can match: the resolved candidate always exists (its own
// EvalSymlinks succeeded), so an absent entry has no identity to compare.
func canonicalForbiddenAlias(resolved string) string {
	for _, forbidden := range FactoryResetForbiddenRoots {
		if forbidden == resolved {
			continue // lexical check already refused this spelling
		}
		canon, cerr := filepath.EvalSymlinks(forbidden)
		if cerr != nil {
			continue
		}
		if canon == resolved {
			return forbidden
		}
	}
	return ""
}

// FactoryResetConfigDir securely erases the on-disk configuration STATE under
// configDir as part of a factory reset (#4858). It is the single shared
// primitive behind `request system zeroize` so the on-box CLI and any RPC
// factory-reset path wipe exactly the same artifacts, and none of them can
// report success while the authoritative config DB + encryption key survive to
// re-activate on the next boot.
//
// configBase is the config file's base name (e.g. "xpf.conf"), used to
// recognize the numbered text rollback slots "<configBase>.<N>".
//
// The artifacts removed — state that could restore the prior tenant's config
// or prevent a factory-default appliance from provisioning:
//
//   - .configdb/master.key  — the AES-GCM key that decrypts an encrypted DB.
//     Removed FIRST (key-first) and that removal is fsynced (.configdb) BEFORE
//     the ciphertext body is touched (#5197): an interrupted wipe (crash /
//     power loss mid-RemoveAll) can then never leave the ciphertext together
//     with the key that decrypts it. Without the barrier both unlinks sit in
//     the page cache and the filesystem is free to persist the ciphertext
//     removal while losing the key removal, breaking the guarantee.
//   - .configdb/            — the SSOT: active.json, candidate.json,
//     rollback.N.json. Store.Load reloads active.json on the next boot, so the
//     whole tree must go or the "erased" config is restored.
//   - .config.journal[.N]   — the JSONL audit journal + rotated segments
//     (prior-tenant commit history; legacy fat lines may carry full config).
//   - <configBase>          — the LIVE config file, matched by EXACT name (#5768)
//     so a non-".conf" -config base (e.g. site.cfg) is erased too, and a broad
//     `*.conf` glob no longer catches unowned siblings.
//   - rescue.conf           — the rescue config (RescueConfigBase / rescuePath):
//     the full active-config TEXT with cleartext secret leaves (#4056).
//   - .day0-config-applied — the day-0 loader's successful-config stamp;
//     removing it permits provisioning from a new medium after factory reset
//     (#10740).
//   - <configBase>.<N>      — the canonical text rollback slots (full config
//     text with cleartext secret leaves; loadRollbackHistory reads them at
//     boot, so leaving them behind allows a rollback to the prior config).
//   - .<base>.tmp-*         — fsatomic crash-leaked write temps (#5475): a
//     daemon killed between fsatomic's CreateTemp and its rename leaves a
//     ".<base>.tmp-<rand>" file (pkg/fsatomic createTemp) still holding the FULL
//     cleartext config text it was mid-writing (xpf.conf / rescue.conf / a
//     numbered rollback slot) — IKE PSKs, WireGuard keys, SNMP communities.
//     fsatomic self-heals a leaked temp on the NEXT write to that base
//     (configstore NewDB sweeps the identical ".*.tmp-*" glob inside .configdb),
//     but a factory reset + reboot means there is no next write, so the temp —
//     and its secrets — would otherwise survive. Temps INSIDE .configdb are
//     already erased by the RemoveAll above; only TOP-LEVEL configDir temps
//     needed this sweep.
//
// Discipline: os.ErrNotExist is never an error (an already-absent artifact is
// the goal); removal is best-effort past a single stubborn file, but the FIRST
// real error is returned so a silently-incomplete wipe is never reported as a
// clean factory reset. The parent dir is fsynced at the end so the unlinks are
// durable across a power cut before the completing reboot, and that final
// directory-fsync error is now PROPAGATED (#5197) — a fsync failure means the
// erasure may not be on stable storage, so it must not be reported as a clean
// zeroize the way the discarded end-of-function d.Sync() previously was. The
// durability barriers route through the package fsync seam (rbSyncDir) so a
// dropped sync fails a test RED.
//
// Scope: this erases the config-DB SSOT + journal + rollback state under
// configDir. The RENDERED service configs xpfd writes OUTSIDE configDir
// (/etc/frr/frr.conf, /etc/swanctl/conf.d, /etc/kea) and provisioned OS login
// accounts are handled separately by the daemon's RPC factory-reset path; the
// local config archive (/var/lib/xpf/archive) — another OUTSIDE-configDir
// generation of config secrets — is erased by the sibling FactoryResetArchiveDir
// (#5186), which both the CLI and the gRPC wipe also call.
func FactoryResetConfigDir(configDir, configBase string) error {
	// #5684: refuse to wipe a shared/parent/system directory. configDir is
	// filepath.Dir(store.ConfigPath()); a custom -config placed in (or resolving
	// to) a shared directory must never let the reset RemoveAll <configDir>/.configdb
	// (a dedicated xpf subdir) on a tree xpf does not own. #5768 additionally
	// scopes the top-level file sweep below to EXACT xpf-owned names (no `*.conf` /
	// `rollback*` glob), but this guard stays as defense-in-depth: fail CLOSED —
	// surface the error and remove NOTHING — rather than enter the wipe at all.
	// #9897 F-040: resolve BEFORE validating and wiping — a lexically clean
	// path that REACHES a forbidden directory through a symlink must be
	// refused, and a link to a dedicated root is wiped AT THE RESOLVED
	// TARGET (where the daemon's live secrets are), so every path below
	// uses the resolved root. Shared with the grpcapi twin.
	resolved, rerr := ResolveFactoryResetRoot(configDir)
	if rerr != nil {
		return rerr
	}
	configDir = resolved

	var firstErr error
	fail := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}

	// #9013: paths that turned out to be symlinks and were therefore NOT erased.
	// Collected rather than returned early — a skipped path is no reason to
	// abandon the rest of the wipe, and the operator needs EVERY surviving path,
	// not just the first found.
	var skipped []SymlinkedTarget
	var hardlinks []HardlinkedPath

	dbDir := filepath.Join(configDir, ".configdb")
	// #9013: this check precedes EVERY removal in the DB block, and the ordering
	// is the whole point. If .configdb is a symlink, the key removal resolves
	// THROUGH it and destroys the real master.key, while the RemoveAll that
	// follows only unlinks the directory link — leaving active.json /
	// candidate.json / rollback.N.json behind. Checking afterwards, or merely
	// folding the error in later, would still have destroyed the key first.
	if sk, isLink := SymlinkTarget(dbDir); isLink {
		slog.Warn("zeroize: .configdb is a symlink; NOT erasing it — removing it "+
			"would destroy master.key through the link and leave the config body",
			"dir", sk.Path, "target", sk.Target)
		skipped = append(skipped, sk)
	} else {
		found, herr := CollectHardlinkedFiles(dbDir, "")
		hardlinks = append(hardlinks, found...)
		fail(herr)
		skipped = append(skipped, eraseConfigDB(dbDir, fail)...)
	}

	// Top-level artifacts in a single ReadDir pass. #5768: match ONLY names xpf
	// itself created/tracks — the live config file, the rescue config, the audit
	// journal (+ rotated segments), the numbered text rollback slots, and
	// fsatomic crash temps. The pre-#5768 code matched a broad `*.conf` suffix and
	// `rollback*` prefix, which — when a custom -config resolved configDir to a
	// shared or subdir location that slipped past ValidateFactoryResetRoot —
	// deleted UNOWNED siblings (a neighbor's foo.conf, xpf's own rendered
	// /etc/frr/frr.conf, an unrelated rollback-notes file). Ownership scoping,
	// not a bigger denylist, bounds the wipe to xpf's own artifacts. Note the
	// exact live-config match also erases a non-".conf" -config base (e.g.
	// site.cfg) the old suffix glob would have LEFT behind. configstore no longer
	// writes any top-level `rollback*` file: the canonical text rollback slots are
	// "<configBase>.<N>" (isTextRollbackSlot) and the DB slots live inside
	// .configdb (RemoveAll'd above), so dropping the legacy `rollback*` prefix
	// loses no owned artifact. isFsatomicTemp stays a shape match: under-scoping a
	// temp risks stranding an owned secret-bearing temp (#5475), the worse failure.
	entries, err := os.ReadDir(configDir)
	fail(err)
	for _, f := range entries {
		name := f.Name()
		if name == configBase || // the live config file (exact name, any extension)
			name == RescueConfigBase || // the rescue config (rescuePath)
			name == Day0ConfigAppliedBase || // allow day-0 configuration after reset (#10740)
			name == ".config.journal" ||
			strings.HasPrefix(name, ".config.journal.") ||
			isTextRollbackSlot(name, configBase) || // <configBase>.<N> text slots
			isFsatomicTemp(name) {
			full := filepath.Join(configDir, name)
			// #9013: os.Remove on a symlink unlinks the LINK and returns nil,
			// leaving the real file — the live config, the rescue config, the
			// audit journal and the numbered rollback slots each carry the full
			// config text with cleartext secret leaves. Record and skip.
			found, herr := CollectHardlinkedFiles(full, "")
			hardlinks = append(hardlinks, found...)
			fail(herr)
			if sk, isLink := SymlinkTarget(full); isLink {
				slog.Warn("zeroize: config artifact is a symlink; NOT erasing it — "+
					"removing it would unlink the link and leave the config text",
					"path", sk.Path, "target", sk.Target)
				skipped = append(skipped, sk)
				continue
			}
			fail(os.Remove(full))
		}
	}

	// fsync the parent directory so ALL the unlinks above are durable before
	// the reboot that completes the factory reset. Unlike the discarded
	// end-of-function d.Sync() this replaced, a sync failure here is PROPAGATED
	// (#5197): a failed fsync means the erasure may not be on stable storage,
	// so it must not be reported as a clean zeroize. ErrNotExist (configDir
	// itself absent → nothing to wipe) is excluded by fail().
	fail(rbSyncDir(configDir))
	var result []error
	if len(skipped) > 0 {
		result = append(result, &FactoryResetSymlinkError{Skipped: skipped})
	}
	if len(hardlinks) > 0 {
		result = append(result, &FactoryResetHardlinkError{Paths: hardlinks})
	}
	if firstErr != nil {
		result = append(result, firstErr)
	}
	switch len(result) {
	case 0:
		return nil
	case 1:
		return result[0]
	default:
		return errors.Join(result...)
	}
}

// eraseConfigDB erases the .configdb SSOT key-first. Split out of
// FactoryResetConfigDir (#9013) so the symlink refusal can skip the block
// WHOLE — key removal included — instead of interleaving a guard with it. The
// key-first ordering and its #5197 durability argument are unchanged.
func eraseConfigDB(dbDir string, fail func(error)) []SymlinkedTarget {
	var skipped []SymlinkedTarget
	keyPath := filepath.Join(dbDir, "master.key")
	// #10100 R-1: census ANY interior symlink BEFORE the master.key check,
	// excluding exactly the root-child master.key the inverse-shape branch
	// below owns (cleaned-path equality, never basename). Runs in BOTH the
	// master.key-link and key-first paths: the link branch still RemoveAlls
	// the body, so a master.key-link + active.json-link combo must report
	// both. Partial Skipped kept even when the census itself errors.
	if interior, cerr := CollectInteriorSymlinks(dbDir, keyPath); len(interior) == 1 && interior[0].Path == dbDir {
		slog.Warn("zeroize: .configdb is a symlink; NOT erasing it — removing it would "+
			"destroy master.key through the link and leave the config body",
			"dir", interior[0].Path, "target", interior[0].Target)
		return append(skipped, interior...)
	} else {
		for _, sk := range interior {
			slog.Warn("zeroize: .configdb interior is a symlink; the link will be unlinked "+
				"but the target bytes survive — report, don't trust the wipe",
				"path", sk.Path, "target", sk.Target)
		}
		skipped = append(skipped, interior...)
		if cerr != nil {
			fail(cerr)
		}
	}
	// #9013, the INVERSE shape: .configdb is a real directory but master.key
	// inside it is a symlink. rbRemove unlinks the LINK and returns nil, so the
	// real key survives on the target volume while the RemoveAll below erases
	// the ciphertext — the mirror image of the directory case, and equally
	// silent. It defeats cryptographic erasure in the other direction: against a
	// backup of the encrypted DB, a surviving key is the whole secret.
	//
	// The body erase still proceeds. The key cannot be destroyed (the link may
	// point at a volume xpf does not own), but removing the ciphertext leaves
	// nothing for the surviving key to decrypt ON THIS BOX, and the operator is
	// handed the key's real path. Skipping the body instead would leave BOTH.
	if sk, isLink := SymlinkTarget(keyPath); isLink {
		slog.Warn("zeroize: master.key is a symlink; NOT erasing it — removing it "+
			"would unlink the link and leave the real key material",
			"path", sk.Path, "target", sk.Target)
		skipped = append(skipped, sk)
		fail(os.RemoveAll(dbDir))
		return skipped
	}

	// KEY-FIRST: master.key before the encrypted DB body. Make the key unlink
	// DURABLE before the ciphertext is removed (#5197) — fsync .configdb so the
	// key removal is on stable storage before RemoveAll begins. Otherwise a
	// power cut could persist the ciphertext removal while losing the key
	// removal, defeating the key-first cryptographic-erasure guarantee.
	keyErr := rbRemove(keyPath)
	fail(keyErr)
	if keyErr == nil {
		// The key existed and was unlinked: make that unlink durable before the
		// ciphertext body removal. An absent .configdb yields ErrNotExist, which
		// fail() excludes (nothing was removed, so nothing to make durable).
		fail(rbSyncDir(dbDir))
	}
	// The config SSOT (active.json, candidate.json, rollback.N.json + any
	// residual key). RemoveAll erases the whole tree and is nil on absent.
	fail(os.RemoveAll(dbDir))
	return skipped
}

// isTextRollbackSlot reports whether name is a numbered text rollback slot for
// the config file configBase — "<configBase>.<N>" with N one-or-more decimal
// digits. These files carry the full prior config text including cleartext
// secret leaves, so a factory reset removes them. configBase itself ("xpf.conf")
// is caught by the .conf-suffix rule.
func isTextRollbackSlot(name, configBase string) bool {
	rest, ok := strings.CutPrefix(name, configBase+".")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isFsatomicTemp reports whether name is a crash-leaked fsatomic write temp —
// the ".<base>.tmp-<random>" shape pkg/fsatomic gives every temp it creates
// before the atomic rename (fsatomic.go createTemp: `"."+base+".tmp-"`). A
// daemon killed between CreateTemp and the rename leaves one behind still
// holding the FULL cleartext config text it was mid-writing (xpf.conf /
// rescue.conf / a numbered rollback slot with IKE PSKs, WireGuard keys, SNMP
// communities), and after a factory reset + reboot there is no next write to
// that base to self-heal it (#5475). The glob is the exact one the configstore
// NewDB sweep uses inside .configdb (db.go) — KEEP IN SYNC with fsatomic's temp
// naming. It is intentionally narrow: only a dotfile that contains ".tmp-"
// matches, so legitimate dotfiles (.config.journal, .config.journal.N) are left
// for their own rules. The pattern is a constant, so Match never errors.
func isFsatomicTemp(name string) bool {
	ok, _ := filepath.Match(".*.tmp-*", name)
	return ok
}
