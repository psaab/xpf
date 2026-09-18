package grpcapi

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/upgrade/lock"
)

// R-1: interior symlinks under wiped trees survive silently (#10100).
//
// The #9013 guards check only the top paths (.configdb + master.key, tls/,
// .old/.restore.partial dir+key) then RemoveAll. A real dir containing a
// symlinked interior file has the link unlinked while the target bytes
// survive, nil returned. Each cell plants one interior link and requires the
// wipe to report the surviving target path via FactoryResetSymlinkError,
// never nil. Regulars must still be erased.
//
// Hermeticity (#10100 GPT-1): these cells drive zeroizeConfigDir — the bounded
// config-root primitive — NOT PerformZeroizeWipe, which would also visit the
// rendered, login-account, snapshot, BPF and networkd legs at real system
// paths on a privileged run. The full-wipe path is covered hermetically by
// TestZeroizeKeepsEveryLegSkipped10100 below.

const interiorSecret10100 = "SECRET-10100-INTERIOR-DO-NOT-SURVIVE-SILENTLY"

func TestZeroizeReportsInteriorTLSLink10100(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "xpf")
	real := filepath.Join(root, "elsewhere")
	for _, d := range []string{configDir, real} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Real tls/ holding a symlinked key.pem (HTTPS private key) + a regular cert.
	tlsDir := filepath.Join(configDir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(real, "key-real.pem")
	mustWrite(t, target, []byte("PRIVATE KEY "+interiorSecret10100))
	mustSymlink(t, target, filepath.Join(tlsDir, "key.pem"))
	mustWrite(t, filepath.Join(tlsDir, "cert.pem"), []byte("CERT "+interiorSecret10100))

	err := zeroizeConfigDir(configDir, "xpf.conf")
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("R-1 tls interior: expected FactoryResetSymlinkError, got %v; "+
			"the link was unlinked while the private key survives at %s", err, target)
	}
	if len(symErr.Skipped) == 0 {
		t.Fatal("R-1 tls interior: symlink error carries no paths")
	}
	found := false
	for _, sk := range symErr.Skipped {
		if strings.Contains(sk.Target, "key-real.pem") || sk.Target == target {
			found = true
		}
		if !bytes.Contains([]byte(symErr.Error()), []byte(sk.Target)) {
			t.Fatalf("R-1 tls interior: error text omits target %q: %v", sk.Target, symErr)
		}
	}
	if !found {
		t.Fatalf("R-1 tls interior: Skipped %v does not name the surviving %s", symErr.Skipped, target)
	}
	// The target bytes survive BY DESIGN (refuse, don't destroy a volume xpf
	// may not own) — the contract is the operator is TOLD.
	got, rerr := os.ReadFile(target)
	if rerr != nil || !bytes.Contains(got, []byte(interiorSecret10100)) {
		t.Fatalf("R-1 tls interior: surviving target lost or altered: %v %q", rerr, got)
	}
	// Regulars still erased: the real cert.pem must be gone (RemoveAll ran).
	if _, serr := os.Lstat(filepath.Join(tlsDir, "cert.pem")); !os.IsNotExist(serr) {
		t.Fatalf("R-1 tls interior: regular cert.pem was not erased (tlsDir still holds it)")
	}
}

func TestZeroizeReportsInteriorConfigDBLink10100(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "xpf")
	real := filepath.Join(root, "elsewhere")
	for _, d := range []string{configDir, real} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dbDir := filepath.Join(configDir, ".configdb")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dbDir, "master.key"), []byte("keymaterial"))
	mustWrite(t, filepath.Join(dbDir, "candidate.json"), []byte(`{"ok":true}`))
	target := filepath.Join(real, "active-real.json")
	mustWrite(t, target, []byte("config-text "+interiorSecret10100))
	mustSymlink(t, target, filepath.Join(dbDir, "active.json"))

	err := zeroizeConfigDir(configDir, "xpf.conf")
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("R-1 .configdb interior: expected FactoryResetSymlinkError, got %v; "+
			"active.json link unlinked while config text survives at %s", err, target)
	}
	found := false
	for _, sk := range symErr.Skipped {
		if sk.Target == target || strings.Contains(sk.Target, "active-real.json") {
			found = true
		}
	}
	if !found {
		t.Fatalf("R-1 .configdb interior: Skipped %v does not name %s", symErr.Skipped, target)
	}
	got, rerr := os.ReadFile(target)
	if rerr != nil || !bytes.Contains(got, []byte(interiorSecret10100)) {
		t.Fatalf("R-1 .configdb interior: surviving target lost: %v", rerr)
	}
	// Regulars still erased: candidate.json + master.key gone (RemoveAll ran).
	if _, serr := os.Lstat(filepath.Join(dbDir, "candidate.json")); !os.IsNotExist(serr) {
		t.Fatal("R-1 .configdb interior: regular candidate.json was not erased")
	}
	if _, serr := os.Lstat(filepath.Join(dbDir, "master.key")); !os.IsNotExist(serr) {
		t.Fatal("R-1 .configdb interior: regular master.key was not erased")
	}
}
func TestZeroizeReportsInteriorDBCopyLink10100(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "xpf")
	real := filepath.Join(root, "elsewhere")
	for _, d := range []string{configDir, real} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Minimal live DB so the wipe has something ordinary to do.
	mustWrite(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("keymaterial"))
	mustWrite(t, filepath.Join(configDir, ".configdb", "active.json"), []byte(`{"live":true}`))
	// The rollback copy sibling with an interior link.
	copyDir := filepath.Join(configDir, ".configdb.old")
	if err := os.MkdirAll(copyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(copyDir, "master.key"), []byte("keymaterial"))
	target := filepath.Join(real, "copy-active-real.json")
	mustWrite(t, target, []byte("copy-text "+interiorSecret10100))
	mustSymlink(t, target, filepath.Join(copyDir, "active.json"))

	err := zeroizeConfigDir(configDir, "xpf.conf")
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("R-1 .old interior: expected FactoryResetSymlinkError, got %v; "+
			"copy interior link unlinked while %s survives", err, target)
	}
	found := false
	for _, sk := range symErr.Skipped {
		if sk.Target == target || strings.Contains(sk.Target, "copy-active-real.json") {
			found = true
		}
	}
	if !found {
		t.Fatalf("R-1 .old interior: Skipped %v does not name %s", symErr.Skipped, target)
	}
	got, rerr := os.ReadFile(target)
	if rerr != nil || !bytes.Contains(got, []byte(interiorSecret10100)) {
		t.Fatalf("R-1 .old interior: surviving target lost: %v", rerr)
	}
	// Regulars still erased: copy master.key gone.
	if _, serr := os.Lstat(filepath.Join(copyDir, "master.key")); !os.IsNotExist(serr) {
		t.Fatal("R-1 .old interior: regular copy master.key was not erased")
	}
}

func TestZeroizeReportsInteriorRestorePartialLink10100(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "xpf")
	real := filepath.Join(root, "elsewhere")
	for _, d := range []string{configDir, real} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("keymaterial"))
	mustWrite(t, filepath.Join(configDir, ".configdb", "active.json"), []byte(`{"live":true}`))
	copyDir := filepath.Join(configDir, ".configdb.restore.partial")
	if err := os.MkdirAll(copyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(copyDir, "master.key"), []byte("keymaterial"))
	target := filepath.Join(real, "partial-active-real.json")
	mustWrite(t, target, []byte("partial-text "+interiorSecret10100))
	mustSymlink(t, target, filepath.Join(copyDir, "active.json"))
	err := zeroizeConfigDir(configDir, "xpf.conf")
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("R-1 .restore.partial interior: expected FactoryResetSymlinkError, got %v", err)
	}
	found := false
	for _, sk := range symErr.Skipped {
		if sk.Target == target || strings.Contains(sk.Target, "partial-active-real.json") {
			found = true
		}
	}
	if !found {
		t.Fatalf("R-1 .restore.partial interior: Skipped %v does not name %s", symErr.Skipped, target)
	}
}

func TestZeroizeReportsNestedInteriorLink10100(t *testing.T) {
	// Nested plant with the SAME basename as the excluded root-child master.key:
	// exclusion is exact-path only, so this MUST still be reported. Proves
	// recursion (WalkDir) + exact-path dedupe in one cell.
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "xpf")
	real := filepath.Join(root, "elsewhere")
	for _, d := range []string{configDir, real} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dbDir := filepath.Join(configDir, ".configdb")
	sub := filepath.Join(dbDir, "subdir")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dbDir, "master.key"), []byte("keymaterial"))
	mustWrite(t, filepath.Join(dbDir, "active.json"), []byte(`{"live":true}`))
	target := filepath.Join(real, "nested-key-real")
	mustWrite(t, target, []byte("nested-key "+interiorSecret10100))
	mustSymlink(t, target, filepath.Join(sub, "master.key"))
	err := zeroizeConfigDir(configDir, "xpf.conf")
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("R-1 nested interior: expected FactoryResetSymlinkError, got %v; "+
			"nested subdir/master.key link missed (basename exclusion bug?)", err)
	}
	found := false
	for _, sk := range symErr.Skipped {
		if sk.Target == target || strings.Contains(sk.Target, "nested-key-real") {
			found = true
		}
	}
	if !found {
		t.Fatalf("R-1 nested interior: Skipped %v does not name %s", symErr.Skipped, target)
	}
}

func TestZeroizeReportsMasterKeyPlusInteriorCombo10100(t *testing.T) {
	// Combo: symlinked root-child master.key + symlinked active.json. The
	// key-link branch still RemoveAlls the body, so BOTH must be reported
	// (master.key exactly once — exclusion dedupe, not double-append).
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "xpf")
	real := filepath.Join(root, "elsewhere")
	for _, d := range []string{configDir, real} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dbDir := filepath.Join(configDir, ".configdb")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyTarget := filepath.Join(real, "combo-key-real")
	mustWrite(t, keyTarget, []byte("combo-keymaterial"))
	mustSymlink(t, keyTarget, filepath.Join(dbDir, "master.key"))
	bodyTarget := filepath.Join(real, "combo-active-real.json")
	mustWrite(t, bodyTarget, []byte("combo-body "+interiorSecret10100))
	mustSymlink(t, bodyTarget, filepath.Join(dbDir, "active.json"))
	err := zeroizeConfigDir(configDir, "xpf.conf")
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("R-1 combo: expected FactoryResetSymlinkError, got %v", err)
	}
	var sawKey, sawBody int
	for _, sk := range symErr.Skipped {
		if sk.Target == keyTarget || strings.Contains(sk.Target, "combo-key-real") {
			sawKey++
		}
		if sk.Target == bodyTarget || strings.Contains(sk.Target, "combo-active-real.json") {
			sawBody++
		}
	}
	if sawKey != 1 || sawBody != 1 {
		t.Fatalf("R-1 combo: want master.key x1 + active.json x1, got key x%d body x%d in %v",
			sawKey, sawBody, symErr.Skipped)
	}
}

func TestZeroizeReportsDanglingInteriorLink10100(t *testing.T) {
	// A DANGLING interior link (Lstat succeeds, target absent) is still a
	// link, not an absence — "ANY interior symlink" is reported, mirroring
	// the #9897 dangling-final-link doctrine.
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "xpf")
	real := filepath.Join(root, "elsewhere")
	for _, d := range []string{configDir, real} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tlsDir := filepath.Join(configDir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, filepath.Join(real, "no-such-key.pem"), filepath.Join(tlsDir, "key.pem"))
	mustWrite(t, filepath.Join(tlsDir, "cert.pem"), []byte("CERT "+interiorSecret10100))
	err := zeroizeConfigDir(configDir, "xpf.conf")
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("R-1 dangling interior: expected FactoryResetSymlinkError, got %v", err)
	}
	found := false
	for _, sk := range symErr.Skipped {
		if strings.Contains(sk.Target, "no-such-key.pem") {
			found = true
		}
	}
	if !found {
		t.Fatalf("R-1 dangling interior: Skipped %v does not name the dangling link", symErr.Skipped)
	}
	if _, serr := os.Lstat(filepath.Join(tlsDir, "cert.pem")); !os.IsNotExist(serr) {
		t.Fatal("R-1 dangling interior: regular cert.pem was not erased")
	}
}

func TestZeroizeReportsInteriorDirLink10100(t *testing.T) {
	// A symlinked SUBDIRECTORY inside .configdb: WalkDir must report the link
	// WITHOUT descending (symmetric with RemoveAll unlinking without
	// descending), while the target tree's secrets survive and are named.
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "xpf")
	real := filepath.Join(root, "elsewhere")
	for _, d := range []string{configDir, real} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dbDir := filepath.Join(configDir, ".configdb")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dbDir, "master.key"), []byte("keymaterial"))
	mustWrite(t, filepath.Join(dbDir, "active.json"), []byte(`{"live":true}`))
	targetDir := filepath.Join(real, "shadow-tree")
	secretBody := "shadow-config-text " + interiorSecret10100
	mustWrite(t, filepath.Join(targetDir, "active.json"), []byte(secretBody))
	mustSymlink(t, targetDir, filepath.Join(dbDir, "shadow"))
	err := zeroizeConfigDir(configDir, "xpf.conf")
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("R-1 dir-link interior: expected FactoryResetSymlinkError, got %v; "+
			"dir link unlinked while %s survives silently", err, targetDir)
	}
	found := false
	for _, sk := range symErr.Skipped {
		if sk.Target == targetDir || strings.Contains(sk.Target, "shadow-tree") {
			found = true
		}
	}
	if !found {
		t.Fatalf("R-1 dir-link interior: Skipped %v does not name %s", symErr.Skipped, targetDir)
	}
	got, rerr := os.ReadFile(filepath.Join(targetDir, "active.json"))
	if rerr != nil || string(got) != secretBody {
		t.Fatalf("R-1 dir-link interior: surviving target lost or altered: %v", rerr)
	}
}

// hermeticWipe10100 points EVERY PerformZeroizeWipe leg at a throwaway tree so
// the full-wipe integration cell below never touches real system paths (#10100
// GPT-1): rendered configs, BPF pins, networkd, the versions dir + upgrade
// lock, and all login-account paths + destructive callbacks. The archive leg
// is disabled by passing "" (nothing to erase). Returns the versions dir for
// snapshot planting.
func hermeticWipe10100(t *testing.T, root string) (versionsDir string) {
	t.Helper()
	origFRR, origSwan, origK4, origK6 := zeroizeFRRConf, zeroizeSwanctlSnippet, zeroizeKea4Conf, zeroizeKea6Conf
	origBPF, origND, origVer := zeroizeBPFPinDir, zeroizeNetworkdDir, zeroizeVersionsDir
	t.Cleanup(func() {
		zeroizeFRRConf, zeroizeSwanctlSnippet, zeroizeKea4Conf, zeroizeKea6Conf = origFRR, origSwan, origK4, origK6
		zeroizeBPFPinDir, zeroizeNetworkdDir, zeroizeVersionsDir = origBPF, origND, origVer
	})
	zeroizeFRRConf = filepath.Join(root, "rendered", "frr", "frr.conf")
	zeroizeSwanctlSnippet = filepath.Join(root, "rendered", "swanctl", "xpf.conf")
	zeroizeKea4Conf = filepath.Join(root, "rendered", "kea", "kea-dhcp4.conf")
	zeroizeKea6Conf = filepath.Join(root, "rendered", "kea", "kea-dhcp6.conf")
	zeroizeBPFPinDir = filepath.Join(root, "bpf")
	zeroizeNetworkdDir = filepath.Join(root, "networkd")
	versionsDir = filepath.Join(root, "versions")
	zeroizeVersionsDir = versionsDir
	origLock := zeroizeAcquireUpgradeLock
	t.Cleanup(func() { zeroizeAcquireUpgradeLock = origLock })
	lockPath := filepath.Join(root, "upgrade.lock")
	zeroizeAcquireUpgradeLock = func() (interface{ Release() error }, error) {
		return lock.AcquireAt(lockPath, "zeroize", "")
	}
	login := filepath.Join(root, "login")
	setZeroizeLoginPaths(t, filepath.Join(login, "provisioned-users"),
		filepath.Join(login, "sudoers.d"), filepath.Join(login, "home"),
		filepath.Join(login, "passwd"))
	setZeroizeRootPaths(t, filepath.Join(login, "root-ssh"), nil)
	seamZeroizeFirewallLogPaths(t, root)
	return versionsDir
}

func TestZeroizeKeepsEveryLegSkipped10100(t *testing.T) {
	// GPT-2: the config-root leg AND the snapshot leg each plant an interior
	// link. BOTH Skipped sets must surface in the one returned error — a
	// first-wins fold would drop the snapshot set while its discovery link
	// is already unlinked, stranding the surviving target undiscoverable
	// (log-only) on re-run.
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "xpf")
	real := filepath.Join(root, "elsewhere")
	versionsDir := hermeticWipe10100(t, root)
	// Leg A: tls interior link under the config root.
	mustWrite(t, filepath.Join(real, "a-key-real.pem"), []byte("PRIVATE KEY "+interiorSecret10100))
	mustSymlink(t, filepath.Join(real, "a-key-real.pem"), filepath.Join(configDir, "tls", "key.pem"))
	mustWrite(t, filepath.Join(configDir, "tls", "cert.pem"), []byte("CERT "+interiorSecret10100))
	// Leg B: interior link inside an upgrade DB snapshot.
	snap := filepath.Join(versionsDir, ".9.9.9.dbsnap")
	mustWrite(t, filepath.Join(snap, "master.key"), []byte("keymaterial"))
	mustWrite(t, filepath.Join(real, "b-snap-real.json"), []byte("snap-body "+interiorSecret10100))
	mustSymlink(t, filepath.Join(real, "b-snap-real.json"), filepath.Join(snap, "active.json"))
	err := PerformZeroizeWipe(configDir, "xpf.conf", "")
	if err == nil {
		t.Fatal("GPT-2 multi-leg: expected a joined error naming both legs, got nil")
	}
	for _, want := range []string{"a-key-real.pem", "b-snap-real.json"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("GPT-2 multi-leg: joined error omits %s (a leg's Skipped set was dropped): %v", want, err)
		}
	}
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("GPT-2 multi-leg: expected FactoryResetSymlinkError in the join, got %T: %v", err, err)
	}
	if len(symErr.Skipped) == 0 {
		t.Fatal("GPT-2 multi-leg: joined symlink error carries no paths")
	}
}

// R-2: rendered-config wipe follows links (#10100).
//
// zeroizeRenderedConfigs os.Removes the swanctl snippet + kea4/kea6 with no
// SymlinkTarget check; sweepFsatomicTemps Removes temp-shaped names with no
// link check; frr.StripManagedSectionFile reads through a link and rewrites
// AT THE TARGET. Each cell requires Skipped (never nil) and no victim
// modification.

const renderedSecret10100 = "SECRET-10100-RENDERED-DO-NOT-SURVIVE"

func TestZeroizeRenderedRefusesSymlinkedSnippets10100(t *testing.T) {
	cases := []string{"swanctl", "kea4", "kea6"}
	for _, which := range cases {
		t.Run(which, func(t *testing.T) {
			root := t.TempDir()
			real := filepath.Join(root, "elsewhere")
			if err := os.MkdirAll(real, 0o700); err != nil {
				t.Fatal(err)
			}
			frrConf := filepath.Join(root, "frr", "frr.conf")
			swan := filepath.Join(root, "swanctl", "xpf.conf")
			kea4 := filepath.Join(root, "kea", "kea-dhcp4.conf")
			kea6 := filepath.Join(root, "kea", "kea-dhcp6.conf")
			// Ordinary regulars everywhere except the one planted link.
			mustWriteFile(t, frrConf, []byte("hostname r1\n"))
			mustWriteFile(t, swan, []byte("regular-swan"))
			mustWriteFile(t, kea4, []byte("regular-kea4"))
			mustWriteFile(t, kea6, []byte("regular-kea6"))
			var linkPath, target string
			switch which {
			case "swanctl":
				target = filepath.Join(real, "swan-real.conf")
				linkPath = swan
			case "kea4":
				target = filepath.Join(real, "kea4-real.conf")
				linkPath = kea4
			case "kea6":
				target = filepath.Join(real, "kea6-real.conf")
				linkPath = kea6
			}
			victimBody := "ike-secret " + renderedSecret10100 + "-" + which
			mustWrite(t, target, []byte(victimBody))
			if err := os.Remove(linkPath); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, target, linkPath)
			err := zeroizeRenderedConfigs(frrConf, swan, kea4, kea6)
			var symErr *configstore.FactoryResetSymlinkError
			if !errors.As(err, &symErr) {
				t.Fatalf("R-2 %s: expected FactoryResetSymlinkError, got %v; "+
					"link unlinked while %s survives silently", which, err, target)
			}
			found := false
			for _, sk := range symErr.Skipped {
				if sk.Target == target || strings.Contains(sk.Target, filepath.Base(target)) {
					found = true
				}
			}
			if !found {
				t.Fatalf("R-2 %s: Skipped %v does not name %s", which, symErr.Skipped, target)
			}
			// Refuse means the link is LEFT, not unlinked.
			fi, lerr := os.Lstat(linkPath)
			if lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("R-2 %s: symlinked snippet was unlinked (refuse must leave it): %v", which, lerr)
			}
			got, _ := os.ReadFile(target)
			if string(got) != victimBody {
				t.Fatalf("R-2 %s: victim not byte-identical:\n%s", which, got)
			}
			// Best-effort past the skip: sibling regulars still erased.
			for _, sib := range []struct{ what, path string }{
				{"swanctl", swan}, {"kea4", kea4}, {"kea6", kea6},
			} {
				if sib.path == linkPath {
					continue
				}
				if _, serr := os.Lstat(sib.path); !os.IsNotExist(serr) {
					t.Fatalf("R-2 %s: sibling regular %s was not erased", which, sib.what)
				}
			}
		})
	}
}

func TestZeroizeRenderedSweepRefusesTempSymlink10100(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "elsewhere")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	frrDir := filepath.Join(root, "frr")
	frrConf := filepath.Join(frrDir, "frr.conf")
	mustWriteFile(t, frrConf, []byte("hostname r1\n"))
	swan := filepath.Join(root, "swanctl", "xpf.conf")
	kea4 := filepath.Join(root, "kea", "kea-dhcp4.conf")
	kea6 := filepath.Join(root, "kea", "kea-dhcp6.conf")
	mustWriteFile(t, swan, []byte("regular-swan-temp-test"))
	mustWriteFile(t, kea4, []byte("regular-kea4-temp-test"))
	// Temp-shaped symlink inside the FRR rendered dir.
	target := filepath.Join(real, "temp-real")
	tempBody := "render-temp " + renderedSecret10100
	mustWrite(t, target, []byte(tempBody))
	linkPath := filepath.Join(frrDir, ".frr.conf.tmp-abc123")
	mustSymlink(t, target, linkPath)
	err := zeroizeRenderedConfigs(frrConf, swan, kea4, kea6)
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("R-2 temp-sweep: expected FactoryResetSymlinkError, got %v; "+
			"temp link unlinked while %s survives silently", err, target)
	}
	fi, lerr := os.Lstat(linkPath)
	if lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("R-2 temp-sweep: temp symlink was unlinked (refuse must leave it): %v", lerr)
	}
	got, _ := os.ReadFile(target)
	if string(got) != tempBody {
		t.Fatalf("R-2 temp-sweep: victim not byte-identical:\n%s", got)
	}
	// Exact-path removals still ran past the sweep skip.
	for _, sib := range []string{swan, kea4} {
		if _, serr := os.Lstat(sib); !os.IsNotExist(serr) {
			t.Fatalf("R-2 temp-sweep: sibling regular %s was not erased", sib)
		}
	}
}

func TestZeroizeRenderedRefusesSymlinkedFRR10100(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "elsewhere")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(real, "victim-frr.conf")
	victimBody := "hostname r1\n" +
		"! BEGIN BPFRX MANAGED CONFIG - do not edit this section\n" +
		" ip ospf message-digest-key 1 md5 " + renderedSecret10100 + "\n" +
		"! END BPFRX MANAGED CONFIG\n"
	mustWrite(t, victim, []byte(victimBody))
	frrConf := filepath.Join(root, "frr", "frr.conf")
	if err := os.MkdirAll(filepath.Dir(frrConf), 0o700); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, victim, frrConf)
	swan := filepath.Join(root, "swanctl", "xpf.conf")
	kea4 := filepath.Join(root, "kea", "kea-dhcp4.conf")
	kea6 := filepath.Join(root, "kea", "kea-dhcp6.conf")
	mustWriteFile(t, swan, []byte("regular-swan-frr-test"))
	mustWriteFile(t, kea4, []byte("regular-kea4-frr-test"))
	mustWriteFile(t, kea6, []byte("regular-kea6-frr-test"))
	err := zeroizeRenderedConfigs(frrConf, swan, kea4, kea6)
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("R-2 frr: expected FactoryResetSymlinkError, got %v; "+
			"symlinked frr.conf followed silently", err)
	}
	// The victim file must be byte-identical: no privileged modification.
	got, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != victimBody {
		t.Fatalf("R-2 frr: victim file was modified through the link:\n%s", got)
	}
	fi, lerr := os.Lstat(frrConf)
	if lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("R-2 frr: frr.conf link was replaced/unlinked: %v", lerr)
	}
	// Best-effort: sibling snippet regulars still erased past the frr skip.
	for _, sib := range []string{swan, kea4, kea6} {
		if _, serr := os.Lstat(sib); !os.IsNotExist(serr) {
			t.Fatalf("R-2 frr: sibling regular %s was not erased", sib)
		}
	}
}
