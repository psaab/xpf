package grpcapi

import (
	"context"
	"encoding/json"
	"errors"

	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/ipsec"
)

// zeroizeSyncDir is the directory-fsync seam for the factory-reset wipe
// (#5197). Production uses fsatomic.SyncDir; a test overrides it to record the
// durability barrier (so a dropped fsync fails RED) and to inject a sync
// failure. Mirrors the configstore rbSyncDir seam. Production code must never
// mutate it.
var zeroizeSyncDir = fsatomic.SyncDir

// defaultConfigDir / defaultConfigBase are the STANDARD-APPLIANCE config root
// (cmd/xpfd `-config /etc/xpf/xpf.conf`, pkg/daemon.New's default). They are the
// values the store's ConfigPath resolves to in the default deployment, NOT a
// hardcoded wipe target: performZeroizeWipe now takes the configured root
// (filepath.Dir/Base of configstore.Store.ConfigPath) so a daemon started with a
// non-default `-config` (e.g. /srv/xpf/site.conf) erases THAT root, not /etc/xpf
// (#5280). They remain as the documented default and the RED-on-revert reference
// (a reverted hardcoded wipe would target defaultConfigDir).
const (
	defaultConfigDir  = "/etc/xpf"
	defaultConfigBase = "xpf.conf"
)

// zeroizeConfigDir erases the xpf configuration STATE under configDir as part
// of a factory reset (#4576): the .configdb SSOT + master.key, the numbered
// text rollback slots, the top-level .conf files, and the audit journal — the
// artifacts that persist the prior tenant's committed policy, IKE PSKs,
// WireGuard private keys, and SNMP communities and would otherwise be reloaded
// on the next boot. It also removes the day-0 success stamp, which would prevent
// the loader from accepting a new medium after the configuration is erased
// (#10740).
//
// NOTE (scope): this erases the SSOT and rollback/journal state under
// configDir. The RENDERED service configs xpfd writes OUTSIDE configDir —
// /etc/frr/frr.conf (0644, BGP-MD5/OSPF/ISIS auth), /etc/swanctl/conf.d/xpf.conf
// (IKE PSKs), /etc/kea/kea-dhcp{4,6}.conf — are erased separately by
// zeroizeRenderedConfigs (#4585). Both run under performZeroizeWipe. Erasing
// the rendered configs in the wipe (rather than deferring to the reboot) is
// required because a post-zeroize boot has no committed config and SKIPS the
// reconcile that would otherwise clear them — see zeroizeRenderedConfigs.
//
// The artifacts removed (configBase is the config file's base name, e.g.
// "xpf.conf", used to recognize the numbered text rollback slots):
//   - .configdb/master.key      — the AES-GCM key that decrypts an encrypted DB
//   - .configdb/                — the SSOT: active.json, candidate.json,
//     rollback.N.json (Store.Load reloads active.json on next boot)
//   - <configBase>              — the LIVE config file, matched by EXACT name
//     (#5768) so a non-".conf" -config base (e.g. site.cfg) is erased too and a
//     broad `*.conf` glob no longer catches unowned siblings
//   - rescue.conf               — the rescue config (configstore.RescueConfigBase
//     / rescuePath): full active-config TEXT with cleartext secret leaves (#4056)
//   - .day0-config-applied      — the day-0 loader gate; a normal stamp is
//     removed after a reset, but a prefixed zeroize-pending record is held
//     through every wipe leg and removed only after the complete reset.
//   - <configBase>.<N>          — the CANONICAL text rollback slots
//     (saveRollbackFiles / loadRollbackHistory), full config TEXT with
//     cleartext secret leaves; loadRollbackHistory reloads them at boot, so
//     leaving them behind would let the prior tenant's config be rolled back
//     to — the exact leak #4576 closes
//   - .<base>.tmp-*             — fsatomic crash-leaked write temps (#5475): a
//     daemon killed between fsatomic's CreateTemp and its rename leaves a
//     ".<base>.tmp-<rand>" file (pkg/fsatomic createTemp) still holding the FULL
//     cleartext config text it was mid-writing (xpf.conf / rescue.conf / a
//     rollback slot). fsatomic self-heals a leaked temp on the NEXT write to
//     that base, but a factory reset + reboot means there is no next write, so
//     the temp — and its secrets — would otherwise survive. Temps inside
//     .configdb / tls are already erased by the RemoveAll calls above; only
//     TOP-LEVEL configDir temps needed this sweep.
//   - .config.journal[.N]       — the JSONL audit journal + rotated segments
//     (0644, prior-tenant commit history/comments; legacy v1 fat lines may
//     carry full config incl. secrets). This SUPERSEDES the #4108 "journal
//     survives a zeroize" belt-and-braces: the system_action record is still
//     fsynced BEFORE the wipe (so an interrupted wipe leaves a trail, and a
//     remote syslog collector keeps the durable cross-wipe record), but a
//     completed factory reset must not hand its audit log to the next owner.
//   - tls/                      — the self-signed REST-API TLS pair (#4599):
//     tls/key.pem (the device-generated localhost HTTPS private key, 0600) +
//     tls/cert.pem. xpf-generated, not tenant config; generateSelfSignedCertAt
//     (pkg/api) regenerates a fresh pair on absence at the next boot, so
//     removing them is safe and hands no prior-tenant key to the next owner.
//
// Removal is KEY-FIRST and DURABLY ordered (#4576/#5197): master.key is deleted
// before the encrypted DB body AND the key unlink is fsynced (.configdb) before
// RemoveAll begins, so an interrupted wipe (crash / power loss mid-RemoveAll)
// can never leave the ciphertext behind together with the key that decrypts it
// — once the key is gone any surviving ciphertext is unrecoverable. Without the
// fsync barrier both unlinks sit in the page cache and the filesystem is free
// to persist the ciphertext removal while losing the key removal.
//
// The parent directory is fsynced at the end so every unlink is durable before
// the completing reboot, and that final dir-fsync error is PROPAGATED (#5197):
// a failed fsync means the erasure may not be on stable storage, so it must not
// be reported as a clean zeroize.
//
// It is best-effort past a failure (a single stubborn file does not abort the
// rest of the erasure) but returns the FIRST real error so a
// silently-incomplete zeroize is never reported as a successful factory reset.
// os.ErrNotExist is not an error here (an already-absent artifact is the goal).
func zeroizeConfigDir(configDir, configBase string) error {
	// #5684 defense-in-depth: refuse a shared/parent/system config root before
	// any glob or RemoveAll. In production runZeroize already validates via
	// (*Server).zeroizeConfigRoot before performZeroizeWipe reaches here, but
	// this is the MORE destructive wipe primitive (it RemoveAll's <root>/tls and
	// <root>/.configdb), so it re-validates itself — the same defense-in-depth the
	// CLI's configstore.FactoryResetConfigDir applies. Fail CLOSED, removing
	// NOTHING, rather than trust the caller not to hand it an unowned root.
	// #9897 F-040: resolve BEFORE validating and wiping, through the SAME
	// shared helper as the configstore twin — a lexically clean path that
	// REACHES a forbidden directory through a symlink is refused, and a
	// link to a dedicated root is wiped AT THE RESOLVED TARGET. This
	// re-resolution (not the caller's string) is authoritative for the wipe.
	resolved, rerr := configstore.ResolveFactoryResetRoot(configDir)
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

	// #9013: paths that turned out to be SYMLINKS and were therefore NOT erased.
	// os.Remove / os.RemoveAll act on the LINK when the final component is one:
	// they unlink it, return nil, and the real bytes stay on the target volume
	// while the operator is told "System zeroized. Configuration erased." The
	// predicate is shared with configstore rather than re-spelled here — this
	// erase logic exists TWICE (configstore.FactoryResetConfigDir is the twin,
	// and has no non-test caller), which is exactly how a guard lands on one of
	// a pair and silently misses the reachable one.
	var skipped []configstore.SymlinkedTarget
	var hardlinks []configstore.HardlinkedPath

	dbDir := filepath.Join(configDir, ".configdb")
	// #9013: this precedes EVERY removal in the DB block, and the ordering is the
	// point. If .configdb is a symlink the key removal resolves THROUGH it and
	// destroys the real master.key, while the RemoveAll that follows only unlinks
	// the directory link — leaving active.json / candidate.json / rollback.N.json
	// behind. On a DB with no `system master-password` (the default, so encryption
	// is off — maybeEncryptTreeJSON returns the plaintext) that body is the full
	// cleartext config, and the key-first cryptographic-erasure guarantee buys
	// nothing at all.
	if sk, isLink := configstore.SymlinkTarget(dbDir); isLink {
		slog.Warn("zeroize: .configdb is a symlink; NOT erasing it — removing it would "+
			"destroy master.key through the link and leave the config body",
			"dir", sk.Path, "target", sk.Target)
		skipped = append(skipped, sk)
	} else {
		found, herr := configstore.CollectHardlinkedFiles(dbDir, "")
		hardlinks = append(hardlinks, found...)
		fail(herr)
		// #10100 R-1: census ANY interior symlink BEFORE the master.key
		// check, excluding exactly the root-child master.key the
		// inverse-shape branch owns. Runs in BOTH the link and key-first
		// paths (the link branch still RemoveAlls the body). A root-link
		// result here is a TOCTOU swap after the check above: skip the
		// whole DB block closed.
		dbKeyPath := filepath.Join(dbDir, "master.key")
		interior, cerr := configstore.CollectInteriorSymlinks(dbDir, dbKeyPath)
		if len(interior) == 1 && interior[0].Path == dbDir {
			slog.Warn("zeroize: .configdb is a symlink; NOT erasing it — removing it would "+
				"destroy master.key through the link and leave the config body",
				"dir", interior[0].Path, "target", interior[0].Target)
			skipped = append(skipped, interior...)
		} else {
			for _, sk := range interior {
				slog.Warn("zeroize: .configdb interior is a symlink; the link will be "+
					"unlinked but the target bytes survive — report, don't trust the wipe",
					"path", sk.Path, "target", sk.Target)
			}
			skipped = append(skipped, interior...)
			if cerr != nil {
				fail(cerr)
			}
			if sk, isLink := configstore.SymlinkTarget(dbKeyPath); isLink {
				// The INVERSE shape: a real .configdb holding a symlinked key. os.Remove
				// unlinks the LINK, so the real key survives while the body below is
				// erased — cryptographic erasure defeated in the other direction, since
				// against a backup of the encrypted DB a surviving key is the whole
				// secret. The body erase still proceeds: the key cannot be destroyed (the
				// link may point at a volume xpf does not own), but removing the
				// ciphertext leaves nothing on this box for it to decrypt.
				slog.Warn("zeroize: .configdb/master.key is a symlink; NOT erasing it — removing "+
					"it would unlink the link and leave the real key material",
					"path", sk.Path, "target", sk.Target)
				skipped = append(skipped, sk)
				fail(os.RemoveAll(dbDir))
			} else {
				// KEY-FIRST (#4576): master.key before the encrypted DB body. Make the key
				// unlink DURABLE before the ciphertext is removed (#5197) — fsync .configdb
				// so the key removal is on stable storage before RemoveAll begins.
				// Otherwise a power cut could persist the ciphertext removal while losing
				// the key removal, defeating the key-first cryptographic-erasure guarantee.
				keyErr := os.Remove(dbKeyPath)
				fail(keyErr)
				if keyErr == nil {
					// The key existed and was unlinked: make that unlink durable before the
					// ciphertext body removal. Absent .configdb → ErrNotExist, excluded by fail().
					fail(zeroizeSyncDir(dbDir))
				}
				// The config SSOT (active.json, candidate.json, rollback.N.json + any
				// residual key). RemoveAll erases the whole tree and is nil on absent.
				fail(os.RemoveAll(dbDir))
			}
		}
	}

	// #9236 (censused, not reported): the rollback path stages a full DB copy
	// as a SIBLING of .configdb — `.configdb.restore.partial` (the snapshot
	// being installed) and `.configdb.old` (the live DB moved aside). Both are
	// complete copies including master.key. The success path removes .old, but
	// a crash between the two renames is exactly the state the recovery branch
	// is designed to find, so both can be on disk indefinitely.
	//
	// These sit INSIDE the directory this function already enumerates, and the
	// #5768 owned-name loop below matches neither: not the live config, not the
	// rescue config, not a journal, not a numbered rollback slot, and
	// isFsatomicTemp requires ".tmp-". So they survived a reset that reported
	// success. Named exactly, never a `.configdb*` prefix match — that would
	// re-include .configdb itself and widen a RemoveAll over the symlink
	// handling above.
	for _, suffix := range []string{".restore.partial", ".old"} {
		copyDir := dbDir + suffix
		if _, statErr := os.Lstat(copyDir); statErr != nil {
			continue
		}
		found, herr := configstore.CollectHardlinkedFiles(copyDir, "")
		hardlinks = append(hardlinks, found...)
		fail(herr)
		skipped = append(skipped,
			zeroizeDBCopyDir(copyDir, ".configdb"+suffix, fail)...)
	}

	// The self-signed REST-API TLS material (#4599): tls/key.pem (the
	// device-generated localhost HTTPS private key) + tls/cert.pem. These are
	// xpf-generated, not tenant config — generateSelfSignedCertAt (pkg/api)
	// regenerates a fresh pair on absence at the next boot, so removing them is
	// safe. A subdir, so the top-level ReadDir loop's os.Remove never catches it;
	// erase the whole tree explicitly.
	// #9013: a symlinked tls/ leaves key.pem — the device HTTPS PRIVATE KEY — on
	// the target volume. Not a shape the issue named; found by censusing every
	// path this function erases rather than only the two reported.
	tlsDir := filepath.Join(configDir, "tls")
	if sk, isLink := configstore.SymlinkTarget(tlsDir); isLink {
		slog.Warn("zeroize: tls/ is a symlink; NOT erasing it — removing it would "+
			"unlink the link and leave the REST-API private key",
			"dir", sk.Path, "target", sk.Target)
		skipped = append(skipped, sk)
	} else {
		found, herr := configstore.CollectHardlinkedFiles(tlsDir, "")
		hardlinks = append(hardlinks, found...)
		fail(herr)
		// #10100 R-1: a real tls/ holding a symlinked key.pem/cert.pem has
		// the link unlinked while the private key survives. Census ANY
		// interior link (no exclusion: tls has no master.key shape), still
		// RemoveAll regulars. Root-link here is a TOCTOU swap: skip whole.
		if interior, cerr := configstore.CollectInteriorSymlinks(tlsDir, ""); len(interior) == 1 && interior[0].Path == tlsDir {
			slog.Warn("zeroize: tls/ is a symlink; NOT erasing it — removing it would "+
				"unlink the link and leave the REST-API private key",
				"dir", interior[0].Path, "target", interior[0].Target)
			skipped = append(skipped, interior...)
		} else {
			for _, sk := range interior {
				slog.Warn("zeroize: tls/ interior is a symlink; the link will be unlinked "+
					"but the target bytes survive — report, don't trust the wipe",
					"path", sk.Path, "target", sk.Target)
			}
			skipped = append(skipped, interior...)
			if cerr != nil {
				fail(cerr)
			}
			fail(os.RemoveAll(tlsDir))
		}
	}

	// Top-level artifacts in a single ReadDir pass. #5768: match ONLY names xpf
	// itself created/tracks — the live config file, the rescue config, the audit
	// journal (+ rotated segments), the numbered text rollback slots, and fsatomic
	// crash temps. The pre-#5768 code matched a broad `*.conf` suffix and
	// `rollback*` prefix; when a custom -config resolved configDir to a shared or
	// subdir location that slipped past ValidateFactoryResetRoot, those globs
	// deleted UNOWNED siblings (a neighbor's foo.conf, xpf's own rendered
	// /etc/frr/frr.conf, an unrelated rollback-notes file). Ownership scoping — not
	// a bigger denylist — bounds the wipe to xpf's artifacts. The exact live-config
	// match also erases a non-".conf" -config base the old suffix glob left behind.
	// configstore writes no top-level `rollback*` file (canonical text slots are
	// "<configBase>.<N>" via isTextRollbackFile; DB slots live inside .configdb,
	// RemoveAll'd above), so dropping the legacy `rollback*` prefix loses no owned
	// artifact. isFsatomicTemp stays a shape match: under-scoping a temp risks
	// stranding an owned secret-bearing temp (#5475), the worse failure.
	entries, err := os.ReadDir(configDir)
	pendingMarker, markerErr := configstore.IsFactoryResetPending(configDir)
	if markerErr != nil {
		fail(fmt.Errorf("zeroize: inspect config-root pending marker: %w", markerErr))
		pendingMarker = true // preserve the loader gate when marker state is unknown
	}
	fail(err)
	for _, f := range entries {
		name := f.Name()
		full := filepath.Join(configDir, name)
		if name == configstore.Day0ConfigAppliedBase && pendingMarker {
			continue
		}
		if name == configBase || // the live config file (exact name, any extension)
			name == configstore.RescueConfigBase || // the rescue config (configstore.RescueConfigBase / rescuePath)
			name == configstore.Day0ConfigAppliedBase || // allow day-0 configuration after reset (#10740)
			name == ".config.journal" ||
			strings.HasPrefix(name, ".config.journal.") ||
			isTextRollbackFile(name, configBase) || // <configBase>.<N> text slots
			isFsatomicTemp(name) {
			found, herr := configstore.CollectHardlinkedFiles(full, "")
			hardlinks = append(hardlinks, found...)
			fail(herr)
			// #9013: the live config, the rescue config, the audit journal and the
			// numbered rollback slots each carry the full config TEXT with
			// cleartext secret leaves. os.Remove on a symlink unlinks the link and
			// returns nil, so record and skip instead.
			if sk, isLink := configstore.SymlinkTarget(full); isLink {
				slog.Warn("zeroize: config artifact is a symlink; NOT erasing it — "+
					"removing it would unlink the link and leave the config text",
					"path", sk.Path, "target", sk.Target)
				skipped = append(skipped, sk)
				continue
			}
			fail(os.Remove(full))
		}
	}

	// fsync the parent directory so ALL the unlinks above (the .configdb tree,
	// tls/, and the enumerated top-level files) are durable before the reboot
	// that completes the factory reset (#5197). A sync failure means the
	// erasure may not be on stable storage, so it is PROPAGATED — never
	// reported as a clean zeroize. ErrNotExist (configDir absent) is excluded
	// by fail().
	fail(zeroizeSyncDir(configDir))
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

// isTextRollbackFile reports whether name is a numbered text rollback slot for
// the config file configBase — "<configBase>.<N>" with N one-or-more decimal
// digits (store_commit.go rollbackPath). These files carry the full prior
// config text including cleartext secret leaves, so a factory reset removes
// them. configBase itself ("xpf.conf") is caught by the .conf suffix rule.
func isTextRollbackFile(name, configBase string) bool {
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
// NewDB sweep uses inside .configdb (configstore/db.go) — KEEP IN SYNC with
// fsatomic's temp naming and the sibling configstore.FactoryResetConfigDir
// sweep. It is intentionally narrow: only a dotfile that contains ".tmp-"
// matches, so legitimate dotfiles (.config.journal, .config.journal.N) are left
// for their own rules. The pattern is a constant, so Match never errors.
func isFsatomicTemp(name string) bool {
	ok, _ := filepath.Match(".*.tmp-*", name)
	return ok
}

// zeroizeRenderedConfigs erases the RENDERED service configs xpfd writes
// OUTSIDE configDir — the artifacts that hold the prior tenant's secrets in
// cleartext but are not part of the .configdb SSOT wiped by zeroizeConfigDir
// (#4585, follow-up to #4576):
//
//   - frrConf (/etc/frr/frr.conf, mode 0644 WORLD-READABLE): the xpf-managed
//     section carries BGP MD5 / OSPF / IS-IS authentication keys. Only that
//     section is stripped (frr.StripManagedSectionFile) — operator content
//     outside the markers is preserved and a purely operator-managed frr.conf
//     is left untouched. No FRR reload: FRR restarts clean on the reboot.
//   - swanctlSnippet (/etc/swanctl/conf.d/xpf.conf): the IKE PSKs live in this
//     single xpf-owned snippet, so it is removed outright.
//   - kea4/kea6 (/etc/kea/kea-dhcp{4,6}.conf): xpf owns these whole files, so
//     they are removed outright.
//
// In ADDITION to the exact-path removals above, each rendered-config DIRECTORY
// is swept for crash-leaked fsatomic write temps (".<base>.tmp-<rand>",
// isFsatomicTemp), the rendered-config sibling of the #5475 configDir sweep
// (#5509). frr.conf (frr.WriteFileDurable), the swanctl PSK snippet
// (ipsec.WriteFileAtomic), and the Kea configs (dhcpserver.WriteFileAtomic) are
// ALL written via pkg/fsatomic, which drops a ".<base>.tmp-<rand>" temp holding
// the FULL cleartext render (BGP-MD5/OSPF/IS-IS routing-auth keys, IKE PSKs,
// Kea credentials) before its atomic rename. A daemon hard-killed mid-write
// leaves that temp behind; fsatomic self-heals a leaked temp on the NEXT write
// to that base, but a factory reset + reboot means there is no next write, so
// the temp — and its cleartext secrets — would otherwise SURVIVE the reset by
// EXACT PATH (StripManagedSectionFile / os.Remove never touch the temp name).
// The sweep covers ONLY the directories xpf writes these renders into
// (dir(frrConf), dir(swanctlSnippet), dir(kea4/kea6) — deduplicated), matches
// ONLY the narrow fsatomic temp shape, and treats an absent/unmanaged directory
// as a no-op — it never reaches into unrelated system directories.
//
// WHY the wipe must erase these DIRECTLY rather than lean on the completing
// reboot: a post-zeroize boot has NO committed config, so the daemon enters
// #1922 bootstrap mode (or, on an HA node, a normal boot with a nil active
// config) and SKIPS the boot-time applyConfig that would otherwise reconcile
// FRR/IPsec/Kea to empty (pkg/daemon/daemon_run.go: bootstrap suppresses the
// apply, and the normal-boot apply is gated on ActiveConfig() != nil). The
// rendered secrets are therefore a PERSISTENT residual across the reboot, not a
// transient one — a device handed to the next tenant would keep the prior
// tenant's routing-auth keys in a world-readable file. (See docs/system-login.md.)
//
// Discipline mirrors zeroizeConfigDir: os.ErrNotExist is not an error (an
// already-absent artifact is the goal), removal is best-effort past a single
// failure, but the FIRST real error is returned so a silently-incomplete wipe
// is never reported as a clean factory reset.
func zeroizeRenderedConfigs(frrConf, swanctlSnippet, kea4, kea6 string) error {
	var firstErr error
	fail := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	// #10100 R-2: rendered file legs that turned out to be SYMLINKS and were
	// therefore NOT erased (left, not unlinked — unlike R-1 report-and-unlink).
	// os.Remove on a link unlinks it and returns nil while the IKE/Kea/FRR
	// secrets survive on the target volume. Order pinned: frr, swanctl,
	// kea4, kea6, then per-dir temp sweeps in dedup slice order.
	var skipped []configstore.SymlinkedTarget
	var hardlinks []configstore.HardlinkedPath
	// FRR: strip only the xpf-managed section (the routing-auth secrets); the
	// file may carry operator content outside the markers. StripManagedSectionFile
	// already treats an absent file as a no-op (nil) and leaves an unmanaged
	// frr.conf untouched.
	found, herr := configstore.CollectHardlinkedFiles(frrConf, "")
	hardlinks = append(hardlinks, found...)
	fail(herr)
	if sk, isLink := configstore.SymlinkTarget(frrConf); isLink {
		slog.Warn("zeroize: frr.conf is a symlink; NOT stripping it — stripping would "+
			"modify the target through the link",
			"path", sk.Path, "target", sk.Target)
		skipped = append(skipped, sk)
	} else if serr := frr.StripManagedSectionFile(frrConf); serr != nil {
		// TOCTOU upgrade: clean at pre-check, link at Strip (or direct-Strip
		// race). Re-Lstat so the typed #9013 contract (Path+Target in
		// Skipped) holds even for the swap window; otherwise the plain
		// Strip error lands in firstErr (still fail-closed, just untyped).
		if sk, isLink := configstore.SymlinkTarget(frrConf); isLink {
			slog.Warn("zeroize: frr.conf became a symlink during strip; NOT stripping it",
				"path", sk.Path, "target", sk.Target)
			skipped = append(skipped, sk)
		} else {
			fail(serr)
		}
	}
	// swanctl snippet + Kea configs: xpf owns these whole files, remove them —
	// unless the final component is a link (refuse, leave the link).
	for _, leg := range []struct{ what, path string }{
		{"swanctl snippet", swanctlSnippet},
		{"kea4 config", kea4},
		{"kea6 config", kea6},
	} {
		found, herr := configstore.CollectHardlinkedFiles(leg.path, "")
		hardlinks = append(hardlinks, found...)
		fail(herr)
		if sk, isLink := configstore.SymlinkTarget(leg.path); isLink {
			slog.Warn("zeroize: rendered config is a symlink; NOT erasing it — removing "+
				"it would unlink the link and leave the rendered secrets",
				"what", leg.what, "path", sk.Path, "target", sk.Target)
			skipped = append(skipped, sk)
			continue
		}
		fail(os.Remove(leg.path))
	}
	// Sweep crash-leaked fsatomic write temps (#5509). The exact-path removals
	// above miss a ".<base>.tmp-<rand>" temp a hard-killed daemon left mid-write
	// — each temp still holds the full cleartext render. Sweep every directory
	// xpf writes these renders into (deduplicated: kea4/kea6 share /etc/kea).
	swept := make(map[string]bool)
	for _, dir := range []string{
		filepath.Dir(frrConf),
		filepath.Dir(swanctlSnippet),
		filepath.Dir(kea4),
		filepath.Dir(kea6),
	} {
		if swept[dir] {
			continue
		}
		swept[dir] = true
		sweepSkipped, sweepHardlinks := sweepFsatomicTemps(dir, fail)
		skipped = append(skipped, sweepSkipped...)
		hardlinks = append(hardlinks, sweepHardlinks...)
	}
	// #10100 R-2: a SKIPPED erase outranks a FAILED one (same doctrine as
	// zeroizeConfigDir #9013): an erasure that did not happen AT ALL is
	// strictly worse than one that failed. Joined so a real I/O failure is
	// not swallowed; errors.As finds either. performZeroizeWipe Join-aggregates
	// every leg's error, so this leg's Skipped set is never dropped when
	// another leg also fails.
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

// sweepFsatomicTemps removes crash-leaked fsatomic write temps
// (".<base>.tmp-<rand>", isFsatomicTemp) from a single rendered-config directory
// (#5509). It ReadDirs dir and os.Remove's only entries whose name matches the
// narrow fsatomic temp shape, so a legitimate config file or unrelated dotfile
// in the same directory is left untouched. An absent/unmanaged directory is a
// clean no-op: ReadDir yields os.ErrNotExist, which fail() excludes, so a
// directory the appliance does not run (no FRR / strongSwan / Kea installed)
// never errors the whole zeroize. A real ReadDir error IS surfaced via fail so
// a silently-incomplete sweep is not reported as a clean factory reset.
//
// #10100 R-2: a temp-shaped SYMLINK is refused (recorded in the returned
// Skipped, left not unlinked) rather than Removed — unlinking it returns nil
// while the cleartext render survives on the target volume. ReadDir failures
// stay on fail (never Skipped); per-entry ReadDir→Lstat→Remove keeps the
// classic swap-after-Lstat residual (accepted, like #9013 Lstat-then-act).
// A symlinked sweep DIR itself follows (intermediate doctrine, parent-write
// root-only) — out of scope per #10100 bounded R-2 file legs.
func sweepFsatomicTemps(dir string, fail func(error)) ([]configstore.SymlinkedTarget, []configstore.HardlinkedPath) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fail(err)
		return nil, nil
	}
	var skipped []configstore.SymlinkedTarget
	var hardlinks []configstore.HardlinkedPath
	for _, e := range entries {
		if name := e.Name(); isFsatomicTemp(name) {
			full := filepath.Join(dir, name)
			found, herr := configstore.CollectHardlinkedFiles(full, "")
			hardlinks = append(hardlinks, found...)
			fail(herr)
			if sk, isLink := configstore.SymlinkTarget(full); isLink {
				slog.Warn("zeroize: rendered temp is a symlink; NOT erasing it — removing "+
					"it would unlink the link and leave the cleartext render",
					"path", sk.Path, "target", sk.Target)
				skipped = append(skipped, sk)
				continue
			}
			fail(os.Remove(full))
		}
	}
	return skipped, hardlinks
}
func attestHardlinkPath(path string, hardlinks *[]configstore.HardlinkedPath, fail func(error)) {
	found, herr := configstore.CollectHardlinkedFiles(path, "")
	*hardlinks = append(*hardlinks, found...)
	fail(herr)
}

// zeroize login-account teardown paths (#4598). These mirror the production
// paths the daemon provisions OS login accounts under (pkg/daemon:
// provisionedUsersDir, sudoersDir/sudoersPrefix, passwdPath, /home/<user>).
// They cannot be imported — pkg/daemon imports pkg/grpcapi (daemon.go,
// daemon_run_servers.go), so a shared symbol would create an import cycle,
// the same reason the exec timeout helper is duplicated here. They are
// package vars only so a test can point the teardown at a throwaway tree
// instead of the real /etc + /home + /var/lib.
var (
	// zeroizeProvisionedUsersDir is the per-account provenance-marker directory
	// (pkg/daemon.provisionedUsersDir). Each file is named for an xpf-created
	// login account and CONTAINS that account's UID at provision time — the
	// UID-keyed ownership marker of #1944. It is the authoritative registry of
	// "which OS users did xpf provision", so the wipe walks it to know exactly
	// which accounts are safe to remove.
	zeroizeProvisionedUsersDir = "/var/lib/xpf/provisioned-users"
	// zeroizeSudoersDir + zeroizeSudoersPrefix mirror pkg/daemon.sudoersDir /
	// sudoersPrefix — the exclusive namespace of xpf-managed NOPASSWD sudo
	// drop-ins. Only files with the prefix are ever removed; operator-authored
	// drop-ins in the same directory are left untouched.
	zeroizeSudoersDir    = "/etc/sudoers.d"
	zeroizeSudoersPrefix = "xpf-"
	// zeroizePasswdPath is /etc/passwd, read to resolve an account's CURRENT
	// UID so a userdel only ever fires when the live UID still matches the
	// marker (never on an out-of-band recreate). Mirrors pkg/daemon.passwdPath.
	zeroizePasswdPath = "/etc/passwd"
	// zeroizeHomeBase is the home-directory root; authorized_keys lives at
	// <base>/<user>/.ssh/authorized_keys.
	zeroizeHomeBase = "/home"
	// zeroizeUserdel removes an OS account, its /etc/shadow + /etc/passwd
	// entries, and its home tree (-r). It is a seam so tests can record the
	// removal without touching real accounts. context.Background(): a client
	// disconnect must not abort a confirmed factory reset (mirrors runTimeout's
	// power-action rationale). NEVER call this for the root account / UID 0:
	// userdel -r root fails (you cannot delete the running superuser) and can
	// ABORT the whole reset — root is revoked in place instead (#5520,
	// zeroizeRootLoginAccount).
	zeroizeUserdel = func(name string) ([]byte, error) {
		return combinedOutputTimeoutUnlimited(context.Background(), "userdel", "-r", name)
	}
	// zeroizeRootSSHDir is the root account's .ssh directory. Root's home is
	// /root, NOT /home/root, so its authorized_keys lives at
	// /root/.ssh/authorized_keys — the generic /home/<name>/.ssh teardown MISSES
	// it entirely (#5520). Mirrors pkg/daemon.rootSSHDir (not importable — the
	// pkg/daemon → pkg/grpcapi import cycle, the same reason the other login
	// paths are duplicated here). Package var only so a test can point the root
	// revocation at a throwaway tree.
	zeroizeRootSSHDir = "/root/.ssh"
	// zeroizeLockRootPassword locks the root account password (passwd -l root
	// prefixes the shadow field with "!", disabling password/console root login)
	// as part of a factory reset. `passwd -l` is the same lock effect the #1944
	// day-2 reconciler applies via `chpasswd -e` with "<name>:!"; the request
	// path here has no stdin exec helper, so the equivalent argv-only `passwd -l`
	// is used. It is a seam so a test can record the lock without touching the
	// real root credential. context.Background(): a client disconnect must not
	// abort a confirmed factory reset (mirrors zeroizeUserdel).
	zeroizeLockRootPassword = func() ([]byte, error) {
		return combinedOutputTimeoutUnlimited(context.Background(), "passwd", "-l", "root")
	}
)

// zeroizeProvisionedPasswordsDir and zeroizeProvisionedKeysDir are the two
// RESOURCE-SPECIFIC ownership marker roots the #5841 split added alongside the
// account registry (pkg/daemon.provisionedPasswordsDir / provisionedKeysDir):
// provisioned-passwords records "xpf set this account's /etc/shadow password"
// and provisioned-keys records "xpf wrote this account's authorized_keys". Like
// their daemon counterparts they are computed as SIBLINGS of the account
// registry, so overriding the single zeroizeProvisionedUsersDir seam in a test
// relocates all three roots together. A factory reset must erase these two
// roots too: a surviving per-account UID marker is the #5869/#5871 residue
// class, and because reconcileAbsentLoginUsers unions all three roots, a
// re-tenant's reused-UID account colliding with a surviving marker would be
// deprovisioned (password locked / authorized_keys deleted) despite xpf never
// provisioning it — the exact overclaim #5841 exists to kill.
func zeroizeProvisionedPasswordsDir() string {
	return filepath.Join(filepath.Dir(zeroizeProvisionedUsersDir), "provisioned-passwords")
}

func zeroizeProvisionedKeysDir() string {
	return filepath.Join(filepath.Dir(zeroizeProvisionedUsersDir), "provisioned-keys")
}

// zeroizeRootAuthorizedKeysPath returns the xpf-managed ROOT authorized_keys
// file — /root/.ssh/authorized_keys, NOT /home/root/.ssh (#5520). applyRootAuth
// (pkg/daemon) writes root's SSH keys there wholesale, so the whole file is
// xpf-owned. Mirrors pkg/daemon.rootAuthorizedKeysPath.
func zeroizeRootAuthorizedKeysPath() string {
	return filepath.Join(zeroizeRootSSHDir, "authorized_keys")
}

// zeroizeRootLoginAccount revokes ROOT login as part of a factory reset,
// special-cased away from the generic /home/<name> + userdel-r teardown (#5520).
//
// On a MANAGED-ROOT appliance the daemon writes a genuine provenance marker for
// root (markProvisioned("root", 0), applyRootAuth in daemon_system.go), so root
// is enumerated by zeroizeLoginAccounts just like a provisioned non-root user.
// But the generic teardown is wrong for root two ways, and both defeat the
// factory reset:
//   - Root's authorized_keys is at /root/.ssh, NOT /home/root/.ssh, so the
//     generic keysFile (filepath.Join(zeroizeHomeBase, "root", ...)) points at a
//     path that does not exist and the prior tenant's ROOT SSH key SURVIVES a
//     "successful" reset — a decommissioned/RMA'd/resold appliance keeps prior-
//     operator root login, the worst re-tenant leak.
//   - `userdel -r root` deletes UID 0; it fails/is refused (you cannot delete
//     the running superuser) and — surfaced as the first error — can abort the
//     whole reset. Root is the appliance's own superuser, never a disposable
//     provisioned account, so it is revoked IN PLACE, never deleted.
//
// Root revocation removes /root/.ssh/authorized_keys and locks the password
// only when the separate provisioned-passwords marker proves xpf set it. A
// keys-only root-authentication must preserve the pre-existing console password.
// The SSH-key removal runs FIRST so that vector dies even if an owned password
// lock later fails (mirrors the generic path's keys-before-userdel ordering).
//
// Fail CLOSED (#5496/#5493 discipline): if key removal fails, an owned password
// lock fails, or password ownership cannot be read/resolved, surface the error
// (so performZeroizeWipe reports the reset INCOMPLETE) and RETAIN the provenance
// marker so a retried zeroize re-attempts. An absent password marker means xpf
// never provisioned that password; it is intentionally left untouched. An
// already-absent authorized_keys (os.ErrNotExist) is the goal, not a failure.
// The account marker is dropped only when key removal and all owned revocations
// succeed.
func zeroizeRootLoginAccount(fail func(error), attest func(string)) (removeMarker bool) {
	removeMarker = true
	// Kill the SSH-key vector first (survives a password-lock failure). An
	// already-absent file is the desired end state, not an error.
	keysFile := zeroizeRootAuthorizedKeysPath()
	attest(keysFile)
	if err := os.Remove(keysFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Error("zeroize: failed to remove root authorized_keys; retaining marker, reset incomplete",
			"file", keysFile, "err", err)
		fail(err)
		removeMarker = false
	}

	// The account-registry marker also covers keys-only root-authentication.
	// Do not infer password ownership from it: only the resource-specific
	// password marker proves xpf set root's password (#5841, #10741).
	passwordUID, err := readProvisionedMarkerUID(filepath.Join(zeroizeProvisionedPasswordsDir(), "root"))
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Keys-only root: preserve the factory/operator password.
		slog.Info("zeroize: left root password untouched (not xpf-managed)")
		return removeMarker
	case err != nil:
		slog.Error("zeroize: cannot resolve root password ownership; retaining marker, reset incomplete",
			"err", err)
		fail(err)
		return false
	case passwordUID != 0:
		err := fmt.Errorf("zeroize: root password marker UID %d != live UID 0; password left untouched", passwordUID)
		slog.Error("zeroize: root password ownership mismatch; retaining marker, reset incomplete",
			"markerUID", passwordUID)
		fail(err)
		return false
	}

	// Lock the root password only after its resource-specific marker proves
	// xpf provisioned it. If locking fails, keep the registry marker for retry.
	if out, err := zeroizeLockRootPassword(); err != nil {
		slog.Error("zeroize: failed to lock root password; retaining marker, reset incomplete",
			"err", err, "output", strings.TrimSpace(string(out)))
		fail(err)
		removeMarker = false
	} else {
		slog.Info("zeroize: revoked root login (authorized_keys removed, password locked)")
	}
	return removeMarker
}

// zeroizeLookupUIDErr resolves the CURRENT numeric UID for name by parsing
// zeroizePasswdPath directly (cgo-free, mirroring pkg/daemon.lookupUIDGIDErr,
// #5493). It distinguishes the THREE outcomes a fail-CLOSED factory reset must
// tell apart — the whole point of #5496:
//
//   - (uid, true,  nil): name found and its UID parsed — the live account.
//   - (0,   false, nil): passwd READ OK, name genuinely ABSENT — a real
//     out-of-band userdel. This is the ONLY outcome that proves the account is
//     gone and therefore safe to forget (drop the marker).
//   - (0,   false, err): passwd could NOT be read (transient mount / permission
//     / I/O error) OR its UID field FOR name is malformed. The identity
//     database is UNKNOWN, NOT proven absent.
//
// The err return is what lets zeroizeLoginAccounts fail CLOSED. The prior
// two-state helper collapsed "unreadable / malformed" into the same
// (0, false) as "genuinely absent", so an unreadable /etc/passwd or a garbled
// UID looked like proof the account was gone: the wipe then erased the only
// provenance marker and reported a clean reset while a live xpf-provisioned
// PASSWORD account (and its marker-less, no-longer-rediscoverable credential)
// survived — the #5496 fail-open. A malformed UID for the EXACT name is
// reported as an error (unknown), never as genuine absence. This mirrors the
// #5493/#5500 lookupUIDGIDErr split at the factory-reset locus.
func zeroizeLookupUIDErr(name string) (uid int, found bool, err error) {
	data, rerr := os.ReadFile(zeroizePasswdPath)
	if rerr != nil {
		return 0, false, rerr
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if fields[0] == name {
			u, aerr := strconv.Atoi(fields[2])
			if aerr != nil {
				return 0, false, fmt.Errorf("zeroize: unparseable uid for %q in %s", name, zeroizePasswdPath)
			}
			return u, true, nil
		}
	}
	return 0, false, nil
}

// zeroizeLoginAccounts tears down the OS LOGIN accounts xpf provisioned as part
// of a factory reset (#4598, follow-up to #4576/#4585). These are the biggest
// re-tenant leak of the three because they grant INTERACTIVE LOGIN + SUDO, not
// just a config-secret read:
//
//   - /etc/shadow password hashes (pkg/daemon.reconcileUserPassword)
//   - SSH authorized_keys under /home/<user>/.ssh (pkg/daemon.applySystemLogin)
//   - /etc/sudoers.d/xpf-<user> NOPASSWD grants (pkg/daemon.reconcileSudoers)
//
// All three live OUTSIDE /etc/xpf and SURVIVE the config wipe: applySystemLogin
// runs only inside the boot-time applyConfig, which a post-zeroize boot SKIPS
// (bootstrap mode / nil active config — the same boot-skip #4585 documents), and
// even a full reconcile early-returns on an empty config and never userdel's. So
// without this teardown a re-tenanted / RMA'd / resold device still carries the
// prior tenant's login accounts, SSH keys, and passwordless sudo.
//
// Ownership discipline — NEVER touch a non-xpf account (the core safety
// invariant, #1944 §5.4):
//   - Sudoers: only the xpf-<user> namespace is swept. Operator-authored
//     drop-ins (no xpf- prefix) are left untouched. The whole namespace is
//     removed unconditionally — at factory reset nothing is desired — so no
//     passwordless-root grant survives even if a marker is missing.
//   - Users: a userdel fires ONLY for an account that has a provenance marker
//     AND whose CURRENT /etc/passwd UID still equals the marker's recorded UID.
//     An operator's own account (no marker) is never iterated; a system account
//     (no marker) is never touched; an out-of-band userdel+recreate with a
//     different UID (marker mismatch) is left alone — exactly the #1944
//     leave-then-rejoin vs recreate distinction, so the wipe can never nuke the
//     wrong account or strand access.
//   - root: a MANAGED-ROOT appliance writes a real marker for root
//     (markProvisioned("root", 0), applyRootAuth), so root IS enumerated here —
//     but it is special-cased away from the userdel path (#5520): its keys live
//     at /root/.ssh (not /home/root) and userdel -r root fails on UID 0. It is
//     revoked IN PLACE (remove /root/.ssh/authorized_keys; lock the password
//     only when the provisioned-passwords marker proves xpf set it). A
//     keys-only root therefore keeps its existing password. See
//     zeroizeRootLoginAccount. A root with NO marker (unmanaged-root appliance)
//     is not enumerated and stays untouched.
//
// Ownership uncertainty FAILS CLOSED (#5496). Deciding "is this the account xpf
// provisioned?" needs TWO reads: the live UID (/etc/passwd, zeroizeLookupUIDErr)
// and the recorded UID (provenance marker, readProvisionedMarkerUID). If EITHER
// cannot be resolved — /etc/passwd unreadable, a malformed UID, or an
// unreadable/unparseable marker — the account's ownership is UNKNOWN, NOT proven
// absent. The teardown then makes NO destructive change, RETAINS the marker
// (durable evidence for a safe retry), and SURFACES the error so
// performZeroizeWipe reports the reset incomplete. The prior code conflated an
// unresolved read/parse with proof-of-absence (curOK=false → "already gone")
// or with a stale marker, erasing the marker and returning nil while a live
// PASSWORD account survived un-rediscoverable — the fail-open this closes. A
// proven UID-mismatch is likewise reported (unresolved) and its marker retained,
// absent an explicit durable stale-marker policy.
//
// authorized_keys is removed BEFORE userdel so the SSH-key login vector dies
// even if userdel later fails; the marker is retained on a userdel FAILURE so a
// retried zeroize re-attempts the removal (and the failure is surfaced, so the
// device is not reported safe to re-tenant while a live account remains).
//
// #5841 resource roots. The account-registry teardown above enumerates only
// provisioned-users, but the #5841 split records password/key ownership in two
// SIBLING roots (provisioned-passwords, provisioned-keys). A factory reset must
// erase those too — a surviving per-account UID marker is #5869/#5871-class
// residue, and because reconcileAbsentLoginUsers unions all three roots, a
// re-tenant's reused-UID account colliding with a surviving marker would be
// deprovisioned despite xpf never provisioning it. After the registry loop,
// zeroizeSweepResourceMarkerRoot (passwords) and zeroizeSweepProvisionedKeys
// (keys) erase every marker in the two resource roots (keeping only names
// retained for a fail-closed registry retry) and drop the roots, so no marker
// survives in ANY of the three roots. This mirrors the daemon's own
// forgetProvenance, which already drops all three per account.
//
// #6190 key-only accounts. The registry loop removes authorized_keys only for
// accounts in provisioned-users, so a KEY-ONLY account — a pre-existing
// operator/prior-tenant account xpf only added an SSH key to (a provisioned-keys
// marker, NO registry marker) — keeps its xpf-written authorized_keys after the
// reset, leaving the prior tenant SSH login (the #4598 leak class, asymmetric
// with the day-2 deprovisionLoginUser that enumerates the UNION and DOES remove
// that file). zeroizeSweepProvisionedKeys therefore removes the xpf-written
// /home/<name>/.ssh/authorized_keys FILE (UID-gated, fail-closed) alongside the
// keys marker — never an operator's own key file, and never a key file whose
// account's teardown was retained.
//
// Discipline mirrors zeroizeConfigDir / zeroizeRenderedConfigs: os.ErrNotExist
// is never an error (an already-absent artifact is the goal), removal is
// best-effort past a single failure, but the FIRST real error is returned so a
// silently-incomplete teardown is never reported as a clean factory reset.
func zeroizeLoginAccounts() error {
	var firstErr error
	fail := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	var hardlinks []configstore.HardlinkedPath
	attest := func(path string) {
		attestHardlinkPath(path, &hardlinks, fail)
	}

	// (A) Sweep the xpf sudoers namespace. Removing every xpf-<user> drop-in
	// guarantees no passwordless-root grant survives, independent of the marker
	// registry. Operator drop-ins without the prefix are never touched.
	if entries, err := os.ReadDir(zeroizeSudoersDir); err != nil {
		fail(err) // a real ReadDir error (absent dir is ErrNotExist → excluded)
	} else {
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasPrefix(name, zeroizeSudoersPrefix) {
				continue
			}
			full := filepath.Join(zeroizeSudoersDir, name)
			attest(full)
			fail(os.Remove(full))
		}
	}

	// (B) Tear down each xpf-provisioned OS user, gated on the UID-keyed marker.
	// retained collects the names whose account-registry teardown was KEPT for a
	// fail-closed retry (userdel failed, ownership unresolved, out-of-band
	// recreate); the resource-root sweep (C) leaves those names' password/key
	// markers in place too, so an account's three markers stay together for the
	// retry. Every other resource marker is erased. #5841.
	retained := make(map[string]struct{})
	entries, err := os.ReadDir(zeroizeProvisionedUsersDir)
	if err != nil {
		// Absent dir = xpf never provisioned an ACCOUNT-registry entry; a real
		// read error is surfaced. Either way, fall through to sweep the two
		// resource roots (C): a pre-existing account xpf only added an SSH key to
		// has a provisioned-keys marker but NO registry entry, so its marker must
		// still be erased even when the registry root is absent/unreadable.
		fail(err)
	} else {
		zeroizeTearDownProvisionedUsers(entries, retained, fail, attest)
	}
	// Drop the now-empty registry directory (best-effort; ENOTEMPTY after a
	// retained marker is fine and must not gate the factory reset).
	_ = os.Remove(zeroizeProvisionedUsersDir)

	// (C) #5841: erase the two resource-specific ownership roots
	// (provisioned-passwords, provisioned-keys) too, so a factory reset leaves NO
	// per-account marker in ANY of the three roots — no residue for a re-tenant's
	// reused-UID account to collide with. The KEYS root additionally removes the
	// xpf-written authorized_keys FILE itself, not just the marker (#6190): a
	// KEY-ONLY account (a pre-existing operator/prior-tenant account xpf only
	// added an SSH key to — a provisioned-keys marker but NO provisioned-users
	// registry entry) is never iterated by the registry loop above, so its
	// xpf-written key file would otherwise survive the reset and leave the prior
	// tenant SSH login — the #4598 credential-leak class, asymmetric with the
	// day-2 deprovisionLoginUser which enumerates the UNION and DOES remove that
	// file.
	zeroizeSweepResourceMarkerRoot(zeroizeProvisionedPasswordsDir(), retained, fail, attest)
	zeroizeSweepProvisionedKeys(zeroizeProvisionedKeysDir(), retained, fail, attest)
	if len(hardlinks) > 0 {
		hardErr := &configstore.FactoryResetHardlinkError{Paths: hardlinks}
		if firstErr != nil {
			return errors.Join(hardErr, firstErr)
		}
		return hardErr
	}
	return firstErr
}

// zeroizeTearDownProvisionedUsers runs the per-account registry teardown for
// each marker in the account-registry directory (#4598). It is split out of
// zeroizeLoginAccounts so the account loop and the #5841 resource-root sweep
// read as two distinct phases. Every account whose teardown is RETAINED for a
// fail-closed retry (userdel failure, ownership uncertainty, out-of-band
// recreate) is recorded in retained so the resource-root sweep keeps its
// password/key markers alongside the retained registry marker.
func zeroizeTearDownProvisionedUsers(entries []os.DirEntry, retained map[string]struct{}, fail func(error), attest func(string)) {
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name() // marker filename == account name (Base'd on write)
		markerFile := filepath.Join(zeroizeProvisionedUsersDir, name)

		if name == "root" {
			// Root is the appliance's own superuser, not a disposable
			// provisioned account. On a managed-root appliance it carries a real
			// marker (markProvisioned("root", 0)), so it reaches this loop — but
			// the generic /home/<name> + userdel-r path is wrong for it: root's
			// keys live at /root/.ssh (not /home/root) and userdel -r root fails
			// on UID 0 and can abort the reset (#5520). Revoke it IN PLACE
			// (remove /root/.ssh/authorized_keys; lock the password only when the
			// provisioned-passwords marker proves xpf set it); drop the account
			// marker only when its owned revocations fully succeeded (fail-closed).
			if zeroizeRootLoginAccount(fail, attest) {
				attest(markerFile)
				fail(os.Remove(markerFile))
			} else {
				// Revocation failed (fail-closed): retain root's registry marker
				// AND, via retained, its password/key markers so all three stay
				// together for a retry (#5841).
				retained[name] = struct{}{}
			}
			continue
		}

		recordedUID, markerErr := readProvisionedMarkerUID(markerFile)
		curUID, curFound, lookupErr := zeroizeLookupUIDErr(name)
		keysFile := filepath.Join(zeroizeHomeBase, name, ".ssh", "authorized_keys")

		removeMarker := true
		switch {
		case lookupErr != nil:
			// /etc/passwd is unreadable, OR its UID field for this account is
			// malformed: the identity database is UNKNOWN. We CANNOT prove the
			// account is gone or resolve its live UID, so this is ownership
			// uncertainty, not proof of absence. FAIL CLOSED (#5496): surface
			// the error (so performZeroizeWipe reports the reset INCOMPLETE),
			// make NO destructive change, and RETAIN the marker so a retry can
			// re-attempt once passwd is readable again. Conflating this with
			// genuine absence would erase the only provenance marker and leave a
			// live xpf credential un-rediscoverable — the fail-open this closes.
			slog.Error("zeroize: cannot resolve login account UID from passwd; retaining marker, reset incomplete",
				"user", name, "err", lookupErr)
			fail(lookupErr)
			removeMarker = false
		case markerErr != nil:
			// The provenance marker itself is unreadable/unparseable: we cannot
			// resolve OUR recorded UID, so we cannot decide whether the live
			// account is the one xpf provisioned. Same ownership uncertainty →
			// FAIL CLOSED (#5496): surface the error, no userdel, and RETAIN the
			// marker. Erasing it would destroy the only durable evidence needed
			// for a safe retry and could strand a live xpf credential unrecorded.
			slog.Error("zeroize: cannot read provenance marker; retaining marker, reset incomplete",
				"user", name, "err", markerErr)
			fail(markerErr)
			removeMarker = false
		case !curFound:
			// passwd READ OK and the account is genuinely ABSENT — a real
			// out-of-band userdel; it cannot authenticate. Best-effort clean up
			// any orphaned key residue; nothing to userdel; drop the stale marker.
			attest(keysFile)
			fail(os.Remove(keysFile))
		case curUID != recordedUID:
			// Proven UID-mismatch: the live account under this name has a
			// DIFFERENT UID than the one xpf provisioned — an out-of-band
			// userdel+recreate. The current account belongs to someone else, so
			// NEVER userdel it or touch its home (the #1944 leave-then-rejoin vs
			// recreate distinction). But absent an explicit, durable stale-marker
			// policy we also refuse to silently erase our marker and report a
			// clean reset: surface the UNRESOLVED condition and RETAIN the marker
			// so the anomaly is re-examined on a retry, not buried (#5496).
			slog.Warn("zeroize: provisioned marker UID mismatch (account recreated out of band); left untouched, reset incomplete",
				"user", name, "markerUID", recordedUID, "liveUID", curUID)
			fail(fmt.Errorf("zeroize: login account %q live UID %d != provenance marker UID %d (out-of-band recreate); left untouched", name, curUID, recordedUID))
			removeMarker = false
		default:
			// curUID == recordedUID → the exact account xpf provisioned. Kill
			// the SSH-key vector first (survives a userdel failure), then remove
			// the account (userdel -r drops /etc/shadow + /etc/passwd + home).
			attest(keysFile)
			fail(os.Remove(keysFile))
			if out, derr := zeroizeUserdel(name); derr != nil {
				slog.Error("zeroize: failed to remove xpf-provisioned login account",
					"user", name, "err", derr, "output", strings.TrimSpace(string(out)))
				fail(derr)
				removeMarker = false // keep the marker so a retry re-attempts
			} else {
				slog.Info("zeroize: removed xpf-provisioned login account", "user", name)
			}
		}
		if removeMarker {
			attest(markerFile)
			fail(os.Remove(markerFile))
		} else {
			// Fail-closed retry: keep the registry marker AND (via retained) this
			// account's password/key markers together for the next attempt (#5841).
			retained[name] = struct{}{}
		}
	}
}

// zeroizeSweepResourceMarkerRoot erases the resource-specific ownership markers
// (#5841) in dir — the provisioned-passwords root — as part of a factory reset,
// then drops the now-empty root. (The provisioned-keys root has its own sweep,
// zeroizeSweepProvisionedKeys, which additionally removes the xpf-written
// authorized_keys FILE — #6190.) Without this the resource root the #5841 split
// introduced SURVIVES a zeroize: each per-account UID marker is
// #5869/#5871-class residue, and because reconcileAbsentLoginUsers unions all
// three roots, a re-tenant's reused-UID account colliding with a surviving
// marker would be deprovisioned (its password locked) despite xpf never
// provisioning it — the exact overclaim #5841 exists to kill, resurrected on a
// "factory-reset" box.
//
// A marker whose name is in retained (its account-registry teardown was KEPT
// for a fail-closed retry) is LEFT so the account's three markers stay together
// for that retry; every other marker is removed. The root-dir removal is
// best-effort (ENOTEMPTY after a retained marker is fine, mirroring the
// registry root) and must not gate the factory reset. os.ErrNotExist is not an
// error (an already-absent root is the goal); a real ReadDir error IS surfaced
// via fail so a silently-incomplete sweep is not reported as a clean reset.
func zeroizeSweepResourceMarkerRoot(dir string, retained map[string]struct{}, fail func(error), attest func(string)) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fail(err) // absent root → ErrNotExist, excluded by fail()
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if _, keep := retained[name]; keep {
			continue // this account's registry teardown was retained (fail-closed)
		}
		full := filepath.Join(dir, name)
		attest(full)
		fail(os.Remove(full))
	}
	// Drop the now-(hopefully-)empty root; a retained marker leaves it non-empty,
	// which is fine and must not gate the factory reset.
	_ = os.Remove(dir)
}

// zeroizeSweepProvisionedKeys is the KEYS-root counterpart of
// zeroizeSweepResourceMarkerRoot (#6190). In ADDITION to erasing each
// provisioned-keys marker, it removes the xpf-written
// /home/<name>/.ssh/authorized_keys the marker proves xpf installed — the FILE
// itself, not just the ownership marker.
//
// Why a distinct sweep. The account-registry teardown
// (zeroizeTearDownProvisionedUsers) already removes authorized_keys for every
// account in the provisioned-users REGISTRY, but a KEY-ONLY account — a
// pre-existing operator/prior-tenant account xpf only added an SSH key to
// (`system login user <name> authentication ssh-*` with NO encrypted-password)
// — gets a provisioned-keys marker and NO registry marker (applySystemLogin
// writes markProvisioned only in the useradd branch; reconcileUserPassword only
// on a password apply). Such an account is never iterated by the registry loop,
// so before #6190 its xpf-written authorized_keys SURVIVED a factory reset and
// the prior tenant kept SSH login on that account — the #4598 credential-leak
// class, asymmetric with the day-2 path (reconcileAbsentLoginUsers enumerates
// the UNION provisionedNames() and deprovisionLoginUser DOES remove that key
// file, gated on keyProvisioned). This sweep closes the asymmetry: it enumerates
// the keys root (the union delta the registry loop misses) and removes the file,
// mirroring deprovisionLoginUser's keyProvisioned-gated
// os.Remove(managedAuthorizedKeysPath(name)).
//
// Ownership discipline — remove ONLY what xpf wrote, mirroring the registry
// teardown's UID-gated fail-closed rules (#5496):
//   - retained: an account whose registry teardown was KEPT for a fail-closed
//     retry keeps ALL its state consistent — its key marker AND key file are
//     left untouched (#6190 retained-set preservation). It is skipped entirely.
//   - root: root's authorized_keys is at /root/.ssh, NOT /home/root, and is
//     revoked by zeroizeRootLoginAccount in the registry phase (#5520); this
//     sweep NEVER touches a /home/root key file. The root keys marker itself is
//     still erased here (residue) when root's revocation succeeded (root not in
//     retained). Root is never a key-only account (applyRootAuth writes the
//     registry marker alongside the key marker), so it is always torn down by
//     the registry phase.
//   - UID gate: the key file is removed only when the live /etc/passwd UID for
//     name equals the keys marker's recorded UID — the account xpf actually
//     wrote the key for. A proven UID-MISMATCH is an out-of-band userdel+recreate
//     (the current authorized_keys belongs to SOMEONE ELSE), so it is left
//     intact, the anomaly surfaced, and the marker RETAINED — never delete an
//     operator's keys.
//   - Uncertainty (passwd unreadable / marker unparseable) FAILS CLOSED: surface
//     the error, retain the marker, remove nothing.
//   - Genuinely absent (passwd read OK, name gone out of band): remove any
//     orphaned xpf key residue (the marker proves xpf wrote it) and drop the
//     stale marker.
//
// In BOTH the proven-owned (default) and genuinely-absent (!curFound) branches
// the keys marker is dropped ONLY when the authorized_keys removal SUCCEEDED (or
// the file was already absent). On a REAL key-removal error the key SURVIVES, so
// the marker is RETAINED and the error surfaced so a retried reset re-enumerates
// the account — the retain-on-error contract lives in
// zeroizeRemoveKeyFileThenMarker (#6201, day-2 deprovisionLoginUser parity;
// unlike the account-registry teardown there is no userdel -r key-removal
// backstop, so dropping the marker on a surviving key would strand the prior
// tenant's SSH key with no retry evidence).
//
// os.ErrNotExist is never an error; removal is best-effort past a single failure
// but the FIRST real error is surfaced via fail so a silently-incomplete sweep
// is not reported as a clean reset. Discipline mirrors zeroizeConfigDir /
// zeroizeTearDownProvisionedUsers.
func zeroizeSweepProvisionedKeys(dir string, retained map[string]struct{}, fail func(error), attest func(string)) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fail(err) // absent root → ErrNotExist, excluded by fail()
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if _, keep := retained[name]; keep {
			// Registry teardown retained this account (fail-closed): keep ALL its
			// state consistent — leave its key marker AND its key file untouched
			// so a retried zeroize re-attempts with the account's markers intact.
			continue
		}
		markerFile := filepath.Join(dir, name)

		if name == "root" {
			// Root's key file lives at /root/.ssh and is revoked by
			// zeroizeRootLoginAccount in the registry phase (#5520), never at
			// /home/root. Only erase root's keys marker here (residue); never
			// touch a /home/root key file.
			attest(markerFile)
			fail(os.Remove(markerFile))
			continue
		}

		keysFile := filepath.Join(zeroizeHomeBase, name, ".ssh", "authorized_keys")
		recordedUID, markerErr := readProvisionedMarkerUID(markerFile)
		curUID, curFound, lookupErr := zeroizeLookupUIDErr(name)

		switch {
		case lookupErr != nil:
			// /etc/passwd unreadable, OR its UID field for this account is
			// malformed: the identity database is UNKNOWN. FAIL CLOSED (#5496) —
			// surface the error, remove nothing, and RETAIN the key marker so a
			// retry re-attempts once passwd is readable again.
			slog.Error("zeroize: cannot resolve key-only account UID from passwd; retaining key marker, reset incomplete",
				"user", name, "err", lookupErr)
			fail(lookupErr)
		case markerErr != nil:
			// The keys marker itself is unreadable/unparseable: we cannot resolve
			// OUR recorded UID, so we cannot prove the live authorized_keys is the
			// one xpf wrote. FAIL CLOSED — surface, retain the marker, remove nothing.
			slog.Error("zeroize: cannot read provisioned-keys marker; retaining key marker, reset incomplete",
				"user", name, "err", markerErr)
			fail(markerErr)
		case !curFound:
			// passwd READ OK and the account is genuinely ABSENT — an out-of-band
			// userdel. Remove any orphaned xpf-written key residue (the marker
			// proves xpf wrote it), then drop the stale marker — but ONLY when the
			// key removal SUCCEEDED (or the file was already absent). On a real
			// key-removal error the residue SURVIVES, so RETAIN the marker so a
			// retried reset re-enumerates this account instead of forgetting the
			// still-present key (zeroizeRemoveKeyFileThenMarker, #6201).
			zeroizeRemoveKeyFileThenMarker(name, keysFile, markerFile, fail, attest)
		case curUID != recordedUID:
			// Proven UID-mismatch: the live account under this name has a DIFFERENT
			// UID than the one xpf wrote the key for — an out-of-band
			// userdel+recreate. The current authorized_keys belongs to SOMEONE
			// ELSE, so NEVER remove it. Surface the unresolved condition and RETAIN
			// the marker (mirrors the registry teardown's mismatch branch, #5496).
			slog.Warn("zeroize: provisioned-keys marker UID mismatch (account recreated out of band); authorized_keys left untouched, reset incomplete",
				"user", name, "markerUID", recordedUID, "liveUID", curUID)
			fail(fmt.Errorf("zeroize: key-only account %q live UID %d != provisioned-keys marker UID %d (out-of-band recreate); left untouched", name, curUID, recordedUID))
		default:
			// curUID == recordedUID → the exact account xpf wrote the key for.
			// Remove the xpf-written authorized_keys, then drop the marker — but
			// ONLY when the key removal SUCCEEDED (or the file was already absent).
			// On a real key-removal error (an immutable file, an ENOTDIR/ENOTEMPTY
			// path shape, an I/O error) the key SURVIVES, so RETAIN the marker so a
			// retried reset re-enumerates and re-attempts the removal
			// (zeroizeRemoveKeyFileThenMarker, #6201).
			zeroizeRemoveKeyFileThenMarker(name, keysFile, markerFile, fail, attest)
		}
	}
	// Drop the now-(hopefully-)empty root; a retained marker leaves it non-empty,
	// which is fine and must not gate the factory reset.
	_ = os.Remove(dir)
}

// zeroizeRemoveKeyFileThenMarker removes an xpf-written authorized_keys file for
// a provisioned-keys account and drops its keys marker ONLY when that removal
// SUCCEEDED or the file was already absent (os.ErrNotExist). On a REAL
// key-removal error (an immutable `chattr +i` file, an ENOTDIR/ENOTEMPTY path
// shape, an I/O error) the key SURVIVES, so the marker is RETAINED and the error
// surfaced via fail — a retried factory reset then re-enumerates the account
// (the keys marker is what makes it discoverable) and re-attempts the removal
// (#6201).
//
// This mirrors the day-2 deprovisionLoginUser contract
// (pkg/daemon/login_password.go): on a real os.Remove(authorized_keys) error it
// KEEPS the provenance markers and returns to retry next apply, rather than
// forgetting the account with a live key on disk. Dropping the keys marker while
// the key file survives would strand the prior tenant's SSH key with no retry
// evidence. The account-registry teardown (zeroizeTearDownProvisionedUsers) can
// drop its marker unconditionally after a key-removal error only because its
// `userdel -r` backstops the removal by deleting the whole home tree; this
// key-only sweep has NO such backstop, so the retain-on-error gate is
// load-bearing.
//
// os.ErrNotExist is not an error (an already-absent key/marker is the goal) — it
// is excluded by fail() and, treated as success here, does not block the marker
// removal.
func zeroizeRemoveKeyFileThenMarker(name, keysFile, markerFile string, fail func(error), attest func(string)) {
	attest(keysFile)
	keyErr := os.Remove(keysFile)
	fail(keyErr)
	if keyErr == nil || errors.Is(keyErr, os.ErrNotExist) {
		attest(markerFile)
		fail(os.Remove(markerFile))
		return
	}
	// Real key-removal error: the key file SURVIVES. Retain the marker so a
	// retried reset re-enumerates this account (fail-closed, day-2 parity).
	slog.Error("zeroize: failed to remove key-only account authorized_keys; retaining key marker, reset incomplete",
		"user", name, "file", keysFile, "err", keyErr)
}

// readProvisionedMarkerUID reads a provenance marker file and returns the UID
// it records (pkg/daemon.markProvisioned writes the account's UID as decimal
// text). A read or parse error is OWNERSHIP UNCERTAINTY: zeroizeLoginAccounts
// FAILS CLOSED on it (#5496) — no userdel, the marker is retained, and the
// error is surfaced so the reset is reported incomplete. It is never treated as
// proof the marker is stale (which would silently erase it).
func readProvisionedMarkerUID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// performZeroizeWipe erases the on-disk config, rendered service-config
// secrets, provisioned login accounts, BPF pins, and managed networkd files
// (factory reset). It is a package var so a test can drive the `zeroize`
// SystemAction verb (to assert the #4108 F8 journal wiring) WITHOUT wiping a
// real config root on the developer/appliance box. It returns a non-nil error
// when a security-critical erasure did not fully complete (#4576/#4585/#4598).
//
// configDir/configBase are the CONFIGURED config root — the directory and base
// name of the store's `-config` path (configstore.Store.ConfigPath), threaded in
// by runZeroize (#5280). Erasing a hardcoded /etc/xpf while the daemon actually
// loads/persists config elsewhere (a non-default `-config`, e.g.
// /srv/xpf/site.conf) would leave the real .configdb SSOT + master.key, rollback
// slots and journal — the prior tenant's secrets — intact under the real root
// while reporting a clean factory reset. Only the config-root leg is
// parameterized: the rendered-config (frr/swanctl/kea), login-account,
// config-archive, BPF-pin and networkd legs live at fixed system paths
// independent of `-config` and stay as-is.
// Rendered service-config wipe targets. Package vars defaulting to the fixed
// system paths so the full-wipe primitive can be driven end-to-end against a
// throwaway tree in tests (#5890) instead of erasing the real /etc/frr,
// /etc/swanctl, /etc/kea — the config-root (parameter), login-account, and
// archive legs are already seamable, and these close the last real-/etc leg so
// PerformZeroizeWipe is fully hermetic under test. Production behavior is
// unchanged (defaults == the former inline constants).
var (
	zeroizeFRRConf        = frr.DefaultFRRConf
	zeroizeSwanctlSnippet = filepath.Join(ipsec.DefaultSwanctlDir, ipsec.BPFRXConfFile)
	zeroizeKea4Conf       = dhcpserver.DefaultKea4ConfPath
	zeroizeKea6Conf       = dhcpserver.DefaultKea6ConfPath
	// Non-secret best-effort legs — also package vars so the full-wipe primitive
	// is fully hermetic under test (never touches the real /sys/fs/bpf or
	// /etc/systemd/network). Production behavior unchanged.
	zeroizeBPFPinDir   = "/sys/fs/bpf/xpf"
	zeroizeNetworkdDir = "/etc/systemd/network"
)

// zeroizePendingRecord persists the pre-wipe inputs in both the configured
// config root and the day-0 loader's fixed stamp path. The prefixed atomic
// replacement gates media probing; the config-root copy keeps Store.Load
// fail-closed when xpfd uses a non-default config directory.
type zeroizePendingRecord struct {
	Version      int                 `json:"version"`
	ConfigDir    string              `json:"config_dir"`
	ConfigBase   string              `json:"config_base"`
	ArchiveDir   string              `json:"archive_dir"`
	LogInventory ZeroizeLogInventory `json:"log_inventory"`
}

func readZeroizePendingRecord(marker, configDir, configBase string) (zeroizePendingRecord, bool, error) {
	var empty zeroizePendingRecord
	info, err := os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		return empty, false, nil
	}
	if err != nil {
		return empty, false, fmt.Errorf("inspect marker %s: %w", marker, err)
	}
	if !info.Mode().IsRegular() {
		return empty, false, fmt.Errorf("pending marker %s is not a regular file", marker)
	}
	pending, err := configstore.IsFactoryResetPending(filepath.Dir(marker))
	if err != nil {
		return empty, false, fmt.Errorf("read pending marker %s: %w", marker, err)
	}
	if !pending {
		return empty, false, nil
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		return empty, false, fmt.Errorf("read pending marker %s: %w", marker, err)
	}
	body := strings.TrimPrefix(string(data), configstore.FactoryResetPendingPrefix)
	var record zeroizePendingRecord
	if err := json.Unmarshal([]byte(body), &record); err != nil {
		return empty, false, fmt.Errorf("parse pending marker %s: %w", marker, err)
	}
	if record.Version != 1 || filepath.Clean(record.ConfigDir) != configDir ||
		record.ConfigBase != configBase {
		return empty, false, fmt.Errorf("pending marker %s does not match the configured config root", marker)
	}
	return record, true, nil
}

func beginZeroize(configDir, configBase, archiveDir string, inv ZeroizeLogInventory) (zeroizePendingRecord, error) {
	resolved, err := configstore.ResolveFactoryResetRoot(configDir)
	if err != nil {
		return zeroizePendingRecord{}, err
	}
	configDir = resolved
	loaderMarker := configstore.FactoryResetPendingPath
	configMarker := filepath.Join(configDir, configstore.FactoryResetPendingBase)
	loaderRecord, loaderPending, err := readZeroizePendingRecord(loaderMarker, configDir, configBase)
	if err != nil {
		return zeroizePendingRecord{}, fmt.Errorf("zeroize: %w", err)
	}
	configRecord, configPending, err := readZeroizePendingRecord(configMarker, configDir, configBase)
	if err != nil {
		return zeroizePendingRecord{}, fmt.Errorf("zeroize: %w", err)
	}
	if loaderPending && configPending && !reflect.DeepEqual(loaderRecord, configRecord) {
		return zeroizePendingRecord{}, fmt.Errorf("zeroize: loader and config-root pending records differ")
	}

	record := zeroizePendingRecord{
		Version:      1,
		ConfigDir:    configDir,
		ConfigBase:   configBase,
		ArchiveDir:   archiveDir,
		LogInventory: inv,
	}
	if configPending {
		record = configRecord
	} else if loaderPending {
		record = loaderRecord
	}
	if err := fsatomic.MkdirAllDurable(configDir, 0o700); err != nil {
		return zeroizePendingRecord{}, fmt.Errorf("zeroize: create config root for pending marker: %w", err)
	}
	if err := fsatomic.MkdirAllDurable(filepath.Dir(loaderMarker), 0o700); err != nil {
		return zeroizePendingRecord{}, fmt.Errorf("zeroize: create loader root for pending marker: %w", err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return zeroizePendingRecord{}, fmt.Errorf("zeroize: encode pending marker: %w", err)
	}
	markerData := append([]byte(configstore.FactoryResetPendingPrefix), data...)
	if err := fsatomic.WriteFileDurable(loaderMarker, markerData, 0o600); err != nil {
		return zeroizePendingRecord{}, fmt.Errorf("zeroize: persist loader pending marker: %w", err)
	}
	if filepath.Clean(configMarker) != filepath.Clean(loaderMarker) {
		if err := fsatomic.WriteFileDurable(configMarker, markerData, 0o600); err != nil {
			return zeroizePendingRecord{}, fmt.Errorf("zeroize: persist config-root pending marker: %w", err)
		}
	}
	return record, nil
}

func completeZeroize(record zeroizePendingRecord) error {
	loaderMarker := configstore.FactoryResetPendingPath
	if err := os.Remove(loaderMarker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("zeroize: remove loader marker for %s: %w", record.ConfigDir, err)
	}
	if err := zeroizeSyncDir(filepath.Dir(loaderMarker)); err != nil {
		return fmt.Errorf("zeroize: sync loader-marker removal: %w", err)
	}
	configMarker := filepath.Join(record.ConfigDir, configstore.FactoryResetPendingBase)
	if filepath.Clean(configMarker) == filepath.Clean(loaderMarker) {
		return nil
	}
	if err := os.Remove(configMarker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("zeroize: remove config-root marker for %s: %w", record.ConfigDir, err)
	}
	if err := zeroizeSyncDir(record.ConfigDir); err != nil {
		return fmt.Errorf("zeroize: sync config-root marker removal: %w", err)
	}
	return nil
}

// PerformZeroizeWipe is the exported entry to the shared factory-reset wipe so
// the in-process interactive console (pkg/cli `request system zeroize`)
// DELEGATES to the SAME primitive the gRPC path uses (#5890). Both paths then
// erase an IDENTICAL, single-source-of-truth OWNED-artifact set — config state
// + tls/ + rendered service configs (frr/swanctl/kea) + provisioned login
// accounts + config archive + BPF pins + networkd + firewall logs — so they
// cannot diverge and leave secret residue on a re-tenanted device. Callers
// without a config store use the zero inventory for dynamic names; static
// xpf-owned log surfaces are still erased. Production gRPC/console callers use
// PerformZeroizeWipeWithLogInventory after snapshotting configured names.
// configDir/configBase are the CONFIGURED config root (see performZeroizeWipe);
// the caller resolves+validates them (cli.zeroizeConfigRoot /
// grpcapi.zeroizeConfigRoot) before delegating.
// #7173: archiveDir is the CONFIGURED archive directory, not the compiled-in
// default. Passing the default unconditionally meant the ownership guard inside
// FactoryResetArchiveDir could never fire — the caller handed it exactly the
// value the guard compares against — so a box with a custom
// `system archival archive-dir` had a path wiped that held nothing while the
// real archive, carrying cleartext IKE PSKs, WireGuard keys and SNMP
// communities, was never examined and the reset reported clean. Pass "" to mean
// "archival disabled, nothing to erase".
func PerformZeroizeWipe(configDir, configBase, archiveDir string) error {
	return performZeroizeWipeWithLogInventory(configDir, configBase, archiveDir, ZeroizeLogInventory{})
}

var performZeroizeWipe = func(configDir, configBase, archiveDir string) error {
	// Wipe every security-critical artifact outside the config root first. The
	// durable pending marker lets boot fail closed if any later leg is
	// interrupted; the config root is erased last by the shared wrapper.
	// Every leg error is retained and joined so later diagnostics are not lost.
	var legErrs []error

	// Rendered service configs (#4585): also security-critical — routing-auth
	// keys in a world-readable frr.conf, IKE PSKs, Kea configs. A post-zeroize
	// boot enters bootstrap / nil-active-config normal boot and SKIPS the
	// reconcile that would clear them, so the wipe must erase them itself. Its
	// error is appended to the surfaced result so a partial wipe is never
	// reported as a clean factory reset.
	if e := zeroizeRenderedConfigs(
		zeroizeFRRConf,
		zeroizeSwanctlSnippet,
		zeroizeKea4Conf,
		zeroizeKea6Conf,
	); e != nil {
		legErrs = append(legErrs, e)
	}

	// Provisioned login accounts (#4598): the OS users xpf created — their
	// /etc/shadow hashes, SSH authorized_keys, and /etc/sudoers.d/xpf-* grants —
	// live OUTSIDE /etc/xpf and SURVIVE the config wipe (applySystemLogin runs
	// only inside the boot-time applyConfig, which a post-zeroize boot SKIPS), so
	// a re-tenanted device would otherwise grant the prior tenant interactive
	// login + passwordless sudo. Marker-aware teardown (UID-keyed provenance
	// marker, #1944) so a non-xpf admin/system/operator account is NEVER touched.
	// Also security-critical, so its error is appended to the surfaced result.
	if e := zeroizeLoginAccounts(); e != nil {
		legErrs = append(legErrs, e)
	}

	// Local config archive (#5186): /var/lib/xpf/archive holds
	// config-<ts>.<seq>.conf snapshots — 0600 copies of the full committed
	// config TEXT WITH cleartext secret leaves (IKE PSK, WireGuard keys, SNMP
	// communities). It is the last on-box generation of config secrets and a
	// pre-#5186 zeroize LEFT it behind, so a re-tenanted device kept the prior
	// tenant's archived secrets. Ownership-guarded (FactoryResetArchiveDir):
	// erases ONLY the xpf-owned default path, never a custom/remote/compliance
	// archive destination. Also security-critical, so its error is appended to
	// the surfaced result.
	//
	// #7173: the CONFIGURED dir. A skip is reported as an
	// *configstore.ArchiveDirSkippedError and appended to the surfaced result
	// like any other secret-bearing failure — the reset genuinely is incomplete
	// and the operator has a directory to erase by hand. It is NOT a reason to
	// stop: everything else must still be wiped, which is why it is appended
	// rather than returned early.
	if archiveDir != "" {
		if e := configstore.FactoryResetArchiveDir(archiveDir); e != nil {
			legErrs = append(legErrs, e)
		}
	}

	// Upgrade config-DB snapshots (#9236): /var/lib/xpf/versions/.<ver>.dbsnap
	// is an unfiltered copy of the config DB — the AES-GCM body AND master.key
	// in one directory, which the project's own threat model calls "copy
	// master.key one directory over and decrypt". The GC retains it for as long
	// as its version dir survives, so it is the steady state of any upgraded
	// box, not an in-flight window. This primitive knew /var/lib/xpf/archive and
	// /var/lib/xpf/provisioned-users and had zero occurrences of "versions",
	// which is what made the omission an oversight rather than a decision.
	// Security-critical, so its error is appended to the surfaced result: a
	// busy upgrade lock or a failed unlink means the reset is INCOMPLETE and
	// must not be reported as a clean factory reset.
	if e := zeroizeUpgradeDBSnapshots(zeroizeVersionsDir); e != nil {
		legErrs = append(legErrs, e)
	}

	// BPF pins + managed networkd files carry no secret material, so their
	// removal stays best-effort (logged, never fatal — they do not gate the
	// success/failure of the factory reset).
	if e := os.RemoveAll(zeroizeBPFPinDir); e != nil {
		slog.Warn("zeroize: remove BPF pins failed", "err", e)
	}
	if ndFiles, e := os.ReadDir(zeroizeNetworkdDir); e == nil {
		for _, f := range ndFiles {
			if strings.HasPrefix(f.Name(), "10-xpf-") {
				if re := os.Remove(filepath.Join(zeroizeNetworkdDir, f.Name())); re != nil && !errors.Is(re, os.ErrNotExist) {
					slog.Warn("zeroize: remove networkd file failed", "file", f.Name(), "err", re)
				}
			}
		}
	}
	// Zero legs failed → clean wipe (nil, exactly as before). One leg failed
	// → its error unwrapped (identity preserved). Several failed → joined in
	// leg order; errors.As/Is find every leg's diagnostics.
	switch len(legErrs) {
	case 0:
		return nil
	case 1:
		return legErrs[0]
	default:
		return errors.Join(legErrs...)
	}
}
