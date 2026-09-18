package grpcapi

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/upgrade"
	"github.com/psaab/xpf/pkg/upgrade/lock"
)

// Upgrade DB snapshots are byte-for-byte COPIES of the live config DB, and a
// factory reset had no knowledge of them at all (#9236).
//
// `copyTree` (pkg/upgrade) is an unfiltered walk of ConfigDBDir, and master.key
// lives INSIDE that directory (pkg/configstore/README.md). So each snapshot at
// `/var/lib/xpf/versions/.<ver>.dbsnap` holds the AES-GCM body AND the key that
// opens it, in one directory — the project's own documented threat model:
// "copy master.key one directory over and decrypt".
//
// The residue is not an in-flight window. pkg/upgrade/flip.go's GC keeps a
// snapshot whenever its version dir survives, and `protected[]` covers
// current/target/previous — so after ONE successful upgrade the target IS
// current and its snapshot is retained on both counts. It is the steady state
// of any box that has ever been upgraded.
//
// Zeroize is the control people run at exactly one moment: before RMA, resale
// or re-tenanting. It returned "Configuration erased" while the prior tenant's
// IPsec PSKs, private keys, SNMP communities, API credentials and full policy
// sat in a self-decrypting copy one directory over. The 0700/0600 modes exclude
// ordinary users and do not exclude a successor administrator or a disk owner,
// which is the entire population this control is aimed at.
var (
	// The literal, not upgrade.DefaultVersionsDir by import, would drift; the
	// import is safe (nothing under pkg/upgrade depends on pkg/grpcapi) and a
	// guard cell pins the two together. A package var so the wipe primitive
	// stays fully hermetic under test, like every other path here.
	zeroizeVersionsDir = upgrade.DefaultVersionsDir

	// Seam for the host-wide upgrade lock. Production takes the real one.
	zeroizeAcquireUpgradeLock = func() (interface{ Release() error }, error) {
		return lock.Acquire("zeroize", "")
	}
)

// dbSnapshotSuffixes are the VersionsDir entry shapes that hold a config-DB
// copy: the snapshot taken in PREFLIGHT and its in-progress staging sibling
// (cutover.go: snapPartial = snapDir + partialSuffix).
//
// Deliberately NOT a `.` prefix glob. `.<ver>.partial` — a staged copy of a
// VERSION directory — is binaries, not config, and version dirs plus the
// `current` symlink are the running system. Widening this to every dotfile
// would erase the executable the box is about to boot. The scope is the name
// shape xpf itself gives a DB snapshot, which is also what makes it owned.
var dbSnapshotSuffixes = []string{".dbsnap", ".dbsnap.partial"}

func isDBSnapshotName(name string) bool {
	if !strings.HasPrefix(name, ".") {
		return false
	}
	for _, s := range dbSnapshotSuffixes {
		// `.dbsnap` alone has no version component and is not a name xpf
		// writes; require something between the dot and the suffix.
		if strings.HasSuffix(name, s) && len(name) > len(s)+1 {
			return true
		}
	}
	return false
}

// zeroizeDBCopyDir erases ONE directory that is a copy of the config DB, using
// the SAME key-first discipline as the live .configdb block: unlink master.key,
// make that unlink durable, and only then remove the ciphertext body. A power
// cut that persisted the body removal but lost the key removal would defeat the
// cryptographic-erasure guarantee, which is why the fsync sits between them
// (#5197) rather than at the end.
//
// The #9013 symlink doctrine applies unchanged, and for the same reason: os.Remove
// and os.RemoveAll act on the LINK when the final component is one, unlinking it
// and returning nil while the real bytes stay on the target volume — and the
// operator is told the configuration was erased. Both shapes are handled:
//
//   - the COPY DIRECTORY is a symlink: erasing it would destroy master.key
//     through the link and leave the body, so nothing is erased and it is
//     reported.
//   - master.key inside it is a symlink: the key cannot be destroyed (the link
//     may point at a volume xpf does not own), but the body erase still
//     proceeds — removing the ciphertext leaves nothing here to decrypt.
//
// Returns the symlinked targets it refused to erase; real I/O errors go to fail.
func zeroizeDBCopyDir(dir, what string, fail func(error)) []configstore.SymlinkedTarget {
	if sk, isLink := configstore.SymlinkTarget(dir); isLink {
		slog.Warn("zeroize: "+what+" is a symlink; NOT erasing it — removing it would "+
			"destroy master.key through the link and leave the config body",
			"dir", sk.Path, "target", sk.Target)
		return []configstore.SymlinkedTarget{sk}
	}
	// #10100 R-1: census ANY interior symlink BEFORE the master.key check
	// (same placement rule as the live .configdb blocks). The key-link
	// branch still RemoveAlls the body, so a combo must report both. A
	// root-link result is a TOCTOU swap: skip whole.
	keyPath := filepath.Join(dir, "master.key")
	interior, cerr := configstore.CollectInteriorSymlinks(dir, keyPath)
	if len(interior) == 1 && interior[0].Path == dir {
		slog.Warn("zeroize: "+what+" is a symlink; NOT erasing it — removing it would "+
			"destroy master.key through the link and leave the config body",
			"dir", interior[0].Path, "target", interior[0].Target)
		return interior
	}
	var skipped []configstore.SymlinkedTarget
	for _, sk := range interior {
		slog.Warn("zeroize: "+what+" interior is a symlink; the link will be unlinked "+
			"but the target bytes survive — report, don't trust the wipe",
			"path", sk.Path, "target", sk.Target)
	}
	skipped = append(skipped, interior...)
	if cerr != nil {
		fail(cerr)
	}
	if sk, isLink := configstore.SymlinkTarget(keyPath); isLink {
		slog.Warn("zeroize: "+what+"/master.key is a symlink; NOT erasing it — removing "+
			"it would unlink the link and leave the real key material",
			"path", sk.Path, "target", sk.Target)
		fail(os.RemoveAll(dir))
		return append(skipped, sk)
	}
	keyErr := os.Remove(keyPath)
	fail(keyErr)
	if keyErr == nil {
		fail(zeroizeSyncDir(dir))
	}
	fail(os.RemoveAll(dir))
	return skipped
}

// zeroizeUpgradeDBSnapshots erases every upgrade config-DB snapshot under
// versionsDir, key-first, and leaves the executable version directories and the
// `current` symlink alone — the target is the DB snapshots, not the binaries.
//
// The host-wide upgrade lock is taken FIRST and a busy lock is a FAILURE, not a
// skip. A reset running concurrently with a cut would otherwise race snapshot
// creation and half-erase: the cut writes `.dbsnap` after the sweep has passed
// it, and the box ends up factory-reset with a fresh copy of the DB it just
// erased. Failing busy tells the operator to stop the upgrade and re-run, which
// is recoverable; a silent half-erase reports success and is not.
//
// Every failure — busy lock, unlink, fsync — is surfaced so the caller reports
// an INCOMPLETE zeroize. A silent partial here is the same defect one layer
// down from the one this fixes.
func zeroizeUpgradeDBSnapshots(versionsDir string) error {
	if versionsDir == "" {
		return nil
	}
	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // never upgraded: nothing to erase
		}
		return fmt.Errorf("zeroize: read upgrade versions dir %s: %w", versionsDir, err)
	}
	// Nothing to erase — do not take the host-wide lock (and do not fail a
	// reset busy) for a box that has no snapshots.
	var snaps []string
	for _, e := range entries {
		if isDBSnapshotName(e.Name()) {
			snaps = append(snaps, e.Name())
		}
	}
	if len(snaps) == 0 {
		return nil
	}

	h, lerr := zeroizeAcquireUpgradeLock()
	if lerr != nil {
		return fmt.Errorf("zeroize: refusing to erase upgrade DB snapshots in %s "+
			"while an upgrade holds the host-wide lock — a reset racing a cut "+
			"would leave a fresh copy of the config DB behind. Stop the upgrade "+
			"and re-run the reset: %w", versionsDir, lerr)
	}
	defer func() { _ = h.Release() }()

	var firstErr error
	fail := func(e error) {
		if e != nil && !errors.Is(e, os.ErrNotExist) && firstErr == nil {
			firstErr = e
		}
	}
	var skipped []configstore.SymlinkedTarget
	var hardlinks []configstore.HardlinkedPath
	// Re-read under the lock: the pre-lock listing is only used to decide
	// whether locking is warranted, and a cut may have finished since.
	entries, err = os.ReadDir(versionsDir)
	if err != nil {
		return fmt.Errorf("zeroize: read upgrade versions dir %s: %w", versionsDir, err)
	}
	for _, e := range entries {
		if !isDBSnapshotName(e.Name()) {
			continue
		}
		dir := filepath.Join(versionsDir, e.Name())
		found, herr := configstore.CollectHardlinkedFiles(dir, "")
		hardlinks = append(hardlinks, found...)
		fail(herr)
		skipped = append(skipped,
			zeroizeDBCopyDir(dir, "upgrade DB snapshot "+e.Name(), fail)...)
	}
	// Make every unlink durable before the reboot that completes the reset.
	fail(zeroizeSyncDir(versionsDir))

	var result []error
	if len(skipped) > 0 {
		result = append(result, &configstore.FactoryResetSymlinkError{Skipped: skipped})
	}
	if len(hardlinks) > 0 {
		result = append(result, &configstore.FactoryResetHardlinkError{Paths: hardlinks})
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
