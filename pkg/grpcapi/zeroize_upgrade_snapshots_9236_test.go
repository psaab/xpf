package grpcapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/upgrade"
	"github.com/psaab/xpf/pkg/upgrade/lock"
)

// Factory reset must not leave a self-decrypting copy of the config DB behind
// (#9236).
//
// `/var/lib/xpf/versions/.<ver>.dbsnap` is an unfiltered copy of the config DB
// taken in upgrade PREFLIGHT, so it holds the AES-GCM body AND master.key in
// one directory. pkg/upgrade's GC keeps it for as long as its version dir
// survives and `protected[]` covers current/target/previous, so after one
// successful upgrade it is the steady state, not an in-flight window.
// PerformZeroizeWipe had zero occurrences of "versions" while knowing about
// /var/lib/xpf/archive and /var/lib/xpf/provisioned-users — and returned
// "Configuration erased" regardless.
//
// The cells below drive PerformZeroizeWipe, the primitive BOTH the gRPC zeroize
// and the interactive CLI delegate to, so neither path can regress alone.

const snap9236Key = "MASTER-KEY-9236"
const snap9236Body = "IKE-PSK-AND-POLICY-9236"

// zeroize9236Env builds a throwaway config root + versions dir and points every
// wipe seam at it, so nothing real is touched.
type zeroize9236Env struct {
	root, configDir, configBase, versionsDir string
}

func newZeroize9236Env(t *testing.T) *zeroize9236Env {
	t.Helper()
	root := t.TempDir()
	e := &zeroize9236Env{
		root:        root,
		configDir:   filepath.Join(root, "etc-xpf"),
		configBase:  "xpf.conf",
		versionsDir: filepath.Join(root, "versions"),
	}
	mustWriteFile(t, filepath.Join(e.configDir, ".configdb", "master.key"), []byte(snap9236Key))
	mustWriteFile(t, filepath.Join(e.configDir, ".configdb", "active.json"), []byte(snap9236Body))
	mustWriteFile(t, filepath.Join(e.configDir, e.configBase), []byte("system { host-name fw; }\n"))

	// Point every OTHER leg at throwaway paths so this test never touches
	// /etc/frr, /sys/fs/bpf or /etc/systemd/network.
	origFRR, origSwan, origK4, origK6 := zeroizeFRRConf, zeroizeSwanctlSnippet, zeroizeKea4Conf, zeroizeKea6Conf
	origBPF, origND, origVer := zeroizeBPFPinDir, zeroizeNetworkdDir, zeroizeVersionsDir
	t.Cleanup(func() {
		zeroizeFRRConf, zeroizeSwanctlSnippet, zeroizeKea4Conf, zeroizeKea6Conf = origFRR, origSwan, origK4, origK6
		zeroizeBPFPinDir, zeroizeNetworkdDir, zeroizeVersionsDir = origBPF, origND, origVer
	})
	zeroizeFRRConf = filepath.Join(root, "frr", "frr.conf")
	zeroizeSwanctlSnippet = filepath.Join(root, "swanctl", "xpf.conf")
	zeroizeKea4Conf = filepath.Join(root, "kea", "kea4.conf")
	zeroizeKea6Conf = filepath.Join(root, "kea", "kea6.conf")
	zeroizeBPFPinDir = filepath.Join(root, "bpf")
	zeroizeNetworkdDir = filepath.Join(root, "networkd")
	zeroizeVersionsDir = e.versionsDir

	// The host-wide upgrade lock lives at /run/xpf in production. Point it at
	// the temp dir so the cells neither need /run nor collide with a real one.
	origLock := zeroizeAcquireUpgradeLock
	t.Cleanup(func() { zeroizeAcquireUpgradeLock = origLock })
	lockPath := filepath.Join(root, "upgrade.lock")
	zeroizeAcquireUpgradeLock = func() (interface{ Release() error }, error) {
		return lock.AcquireAt(lockPath, "zeroize", "")
	}
	return e
}

// snapshot writes a `.<ver>.dbsnap` — a complete DB copy, key included.
func (e *zeroize9236Env) snapshot(t *testing.T, name string) string {
	t.Helper()
	d := filepath.Join(e.versionsDir, name)
	mustWriteFile(t, filepath.Join(d, "master.key"), []byte(snap9236Key))
	mustWriteFile(t, filepath.Join(d, "active.json"), []byte(snap9236Body))
	return d
}

func (e *zeroize9236Env) wipe() error {
	return PerformZeroizeWipe(e.configDir, e.configBase, "")
}

// grepTree reports every file under dir whose bytes contain want.
func grepTree(t *testing.T, dir, want string) []string {
	t.Helper()
	var hits []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil //nolint:nilerr // a vanished file is the goal here
		}
		b, rerr := os.ReadFile(p)
		if rerr == nil && strings.Contains(string(b), want) {
			hits = append(hits, p)
		}
		return nil
	})
	return hits
}

// ── the defect ──

func TestZeroizeErasesUpgradeDBSnapshots9236(t *testing.T) {
	e := newZeroize9236Env(t)
	snap := e.snapshot(t, ".1.2.3.dbsnap")
	partial := e.snapshot(t, ".1.2.4.dbsnap.partial")

	if err := e.wipe(); err != nil {
		t.Fatalf("zeroize reported incomplete: %v", err)
	}
	for _, d := range []string{snap, partial} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("#9236: %s survived the factory reset. It is a complete copy "+
				"of the config DB INCLUDING master.key, so the next holder of this "+
				"box or this disk decrypts the prior tenant's IPsec PSKs, private "+
				"keys, SNMP communities and full policy — after being told the "+
				"configuration was erased", d)
		}
	}
	// The property that matters is the SECRET being gone, not a path being
	// absent: assert over bytes, across the whole tree.
	if hits := grepTree(t, e.root, snap9236Key); len(hits) > 0 {
		t.Errorf("#9236: master.key bytes still on disk after zeroize: %v", hits)
	}
	if hits := grepTree(t, e.root, snap9236Body); len(hits) > 0 {
		t.Errorf("#9236: config DB body still on disk after zeroize: %v", hits)
	}
}

// ── censused, not reported: the same copy one directory over ──

func TestZeroizeErasesConfigDBSiblingCopies9236(t *testing.T) {
	e := newZeroize9236Env(t)
	// The rollback path stages `.configdb.restore.partial` and moves the live DB
	// to `.configdb.old`. Both are full copies with master.key, both sit inside
	// the directory zeroize already enumerates, and the #5768 owned-name loop
	// matched neither.
	var copies []string
	for _, suffix := range []string{".restore.partial", ".old"} {
		d := filepath.Join(e.configDir, ".configdb"+suffix)
		mustWriteFile(t, filepath.Join(d, "master.key"), []byte(snap9236Key))
		mustWriteFile(t, filepath.Join(d, "active.json"), []byte(snap9236Body))
		copies = append(copies, d)
	}
	if err := e.wipe(); err != nil {
		t.Fatalf("zeroize reported incomplete: %v", err)
	}
	for _, d := range copies {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("#9236: %s survived — a full DB copy, key included, inside the "+
				"very directory the reset walks", d)
		}
	}
	if hits := grepTree(t, e.root, snap9236Key); len(hits) > 0 {
		t.Errorf("#9236: master.key bytes still on disk: %v", hits)
	}
}

// ── never widen a RemoveAll ──

func TestZeroizePreservesVersionDirsAndCurrent9236(t *testing.T) {
	e := newZeroize9236Env(t)
	e.snapshot(t, ".1.2.3.dbsnap")

	// The running system: version directories, the `current` bookkeeping
	// symlink, and `.<ver>.partial` — a staged copy of a VERSION dir, i.e.
	// binaries, not config. A dotfile-glob sweep would erase the executable the
	// box is about to boot.
	verBin := filepath.Join(e.versionsDir, "1.2.3", "xpfd")
	mustWriteFile(t, verBin, []byte("ELF"))
	partialBin := filepath.Join(e.versionsDir, ".1.2.5.partial", "xpfd")
	mustWriteFile(t, partialBin, []byte("ELF"))
	journal := filepath.Join(e.versionsDir, "upgrade.state")
	mustWriteFile(t, journal, []byte("{}"))
	cur := filepath.Join(e.versionsDir, "current")
	if err := os.Symlink("1.2.3", cur); err != nil {
		t.Fatal(err)
	}

	if err := e.wipe(); err != nil {
		t.Fatalf("zeroize reported incomplete: %v", err)
	}
	for _, p := range []string{verBin, partialBin, journal} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("#9236: the reset destroyed %s. The target is the DB "+
				"snapshots, not the binaries — erasing the version tree leaves the "+
				"box unable to boot the release it is running: %v", p, err)
		}
	}
	if _, err := os.Lstat(cur); err != nil {
		t.Errorf("#9236: the `current` symlink was removed: %v", err)
	}
}

// ── key-first ordering, observed rather than assumed ──

func TestZeroizeSnapshotKeyIsUnlinkedBeforeItsBody9236(t *testing.T) {
	e := newZeroize9236Env(t)
	snap := e.snapshot(t, ".1.2.3.dbsnap")

	// The fsync between the key unlink and the body removal is the whole point
	// of key-first (#5197): a power cut that persisted the body removal but lost
	// the key removal defeats cryptographic erasure. Observe the tree AT that
	// fsync — the key must already be gone and the body must still be there.
	orig := zeroizeSyncDir
	t.Cleanup(func() { zeroizeSyncDir = orig })
	var sawOrdering, sawSnapSync bool
	zeroizeSyncDir = func(dir string) error {
		if dir == snap {
			sawSnapSync = true
			_, keyErr := os.Stat(filepath.Join(snap, "master.key"))
			_, bodyErr := os.Stat(filepath.Join(snap, "active.json"))
			sawOrdering = os.IsNotExist(keyErr) && bodyErr == nil
		}
		return orig(dir)
	}
	if err := e.wipe(); err != nil {
		t.Fatalf("zeroize reported incomplete: %v", err)
	}
	if !sawSnapSync {
		t.Fatal("#9236: the snapshot dir was never fsynced between the key unlink " +
			"and the body removal, so the key-first erasure is not durable — a " +
			"power cut can persist the body removal and lose the key removal")
	}
	if !sawOrdering {
		t.Error("#9236: at the durability point the key was not already gone with " +
			"the body still present — the removal is not key-first")
	}
}

// ── a busy lock is a failure, not a skip ──

func TestZeroizeFailsBusyRatherThanRacingACut9236(t *testing.T) {
	e := newZeroize9236Env(t)
	snap := e.snapshot(t, ".1.2.3.dbsnap")

	zeroizeAcquireUpgradeLock = func() (interface{ Release() error }, error) {
		return nil, &lock.ErrBusy{Path: "/run/xpf/upgrade.lock"}
	}
	err := e.wipe()
	if err == nil {
		t.Fatal("#9236: a reset that could not take the upgrade lock reported " +
			"SUCCESS. A cut running concurrently writes a fresh .dbsnap after the " +
			"sweep passes it, so the box ends up factory-reset with a new copy of " +
			"the DB it just erased — reported as a clean erase")
	}
	if !lock.IsBusy(err) {
		t.Errorf("#9236: the busy lock must be identifiable in the surfaced error "+
			"so the operator knows to stop the upgrade and re-run; got %v", err)
	}
	if _, serr := os.Stat(snap); serr != nil {
		t.Error("#9236: the snapshot was erased anyway despite failing to take the " +
			"lock — half-erasing is the outcome the lock exists to prevent")
	}
}

// ── a symlinked snapshot is refused, not followed ──

func TestZeroizeSymlinkedSnapshotIsRefusedAndSurfaced9236(t *testing.T) {
	e := newZeroize9236Env(t)
	// The real snapshot lives on another volume; the versions dir holds a link.
	real := filepath.Join(e.root, "elsewhere", "snap")
	mustWriteFile(t, filepath.Join(real, "master.key"), []byte(snap9236Key))
	if err := os.MkdirAll(e.versionsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(e.versionsDir, ".1.2.3.dbsnap")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	err := e.wipe()
	if err == nil {
		t.Fatal("#9236: a symlinked snapshot was reported as a clean erase")
	}
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Errorf("#9236: expected a symlink-skip error the operator can act on, got %v", err)
	}
	if _, serr := os.Stat(filepath.Join(real, "master.key")); serr != nil {
		t.Error("#9236: the key on the LINK TARGET was destroyed through the link, " +
			"which unlinks the directory entry and leaves the body — the exact " +
			"inversion the #9013 doctrine exists to prevent")
	}
}

// ── an unlink/fsync failure is an INCOMPLETE zeroize ──

func TestZeroizeSnapshotFsyncFailureIsSurfaced9236(t *testing.T) {
	e := newZeroize9236Env(t)
	e.snapshot(t, ".1.2.3.dbsnap")

	orig := zeroizeSyncDir
	t.Cleanup(func() { zeroizeSyncDir = orig })
	boom := errors.New("simulated fsync failure")
	zeroizeSyncDir = func(dir string) error {
		if dir == e.versionsDir {
			return boom
		}
		return orig(dir)
	}
	if err := e.wipe(); !errors.Is(err, boom) {
		t.Errorf("#9236: an fsync failure on the versions dir means the erasure may "+
			"not be on stable storage, so it must be surfaced as an incomplete "+
			"zeroize rather than reported clean; got %v", err)
	}
}

// ── the seam must name the real production directory ──

func TestZeroizeVersionsDirIsTheUpgradeDefault9236(t *testing.T) {
	if zeroizeVersionsDir != upgrade.DefaultVersionsDir {
		t.Errorf("#9236: the reset sweeps %q but upgrade writes snapshots to %q — "+
			"a reset pointed at the wrong directory erases nothing and reports "+
			"success", zeroizeVersionsDir, upgrade.DefaultVersionsDir)
	}
}
