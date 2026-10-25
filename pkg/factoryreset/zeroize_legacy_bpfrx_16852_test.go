package factoryreset

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #16852: factory reset must erase the pre-rename conf.d/bpfrx.conf (and its
// editor backup) too. The exact-path leg removed only xpf.conf, so the
// legacy file's cleartext IKE PSKs survived zeroize; a post-zeroize boot
// skips the Manager reconcile that now removes it on Apply/Clear.
//
// RED on revert: drop the "legacy swanctl snippet" leg from
// wipeRenderedConfigs (and/or the bpfrx stem from
// wipeServiceBackupSweepTargets) and the assertions below fail.

func TestZeroizeRenderedRemovesLegacyBpfrx16852(t *testing.T) {
	dir := t.TempDir()
	origSwan := wipeSwanctlSnippet
	t.Cleanup(func() { wipeSwanctlSnippet = origSwan })

	frrConf := filepath.Join(dir, "frr", "frr.conf")
	swanctlSnippet := filepath.Join(dir, "swanctl", "xpf.conf")
	wipeSwanctlSnippet = swanctlSnippet // seal sweep derives its dir from this seam
	legacy := filepath.Join(dir, "swanctl", "bpfrx.conf")
	legacyBackup := filepath.Join(dir, "swanctl", "bpfrx.conf.bak")
	foreign := filepath.Join(dir, "swanctl", "operator.conf")
	kea4 := filepath.Join(dir, "kea", "kea-dhcp4.conf")
	kea6 := filepath.Join(dir, "kea", "kea-dhcp6.conf")
	mustWriteFile(t, frrConf, []byte("hostname r1\n"))
	mustWriteFile(t, swanctlSnippet, []byte("secrets { ike-x { secret = PSK-X } }\n"))
	mustWriteFile(t, legacy, []byte("secrets { ike-old { secret = PSK-LEGACY-16852 } }\n"))
	mustWriteFile(t, legacyBackup, []byte("secrets { ike-old { secret = PSK-LEGACY-16852 } }\n"))
	mustWriteFile(t, foreign, []byte("connections { operator { } }\n"))
	mustWriteFile(t, kea4, []byte("kea4"))
	mustWriteFile(t, kea6, []byte("kea6"))

	if err := wipeRenderedConfigs(frrConf, swanctlSnippet, kea4, kea6); err != nil {
		t.Fatalf("wipeRenderedConfigs: %v", err)
	}
	assertAbsent(t, swanctlSnippet)
	assertAbsent(t, legacy)
	// Foreign operator file in the same conf.d is never xpf's to erase.
	if _, err := os.Lstat(foreign); err != nil {
		t.Fatalf("foreign operator.conf must survive zeroize: %v", err)
	}

	// Editor backup of the legacy file carries the same PSK: the seal
	// backup sweep must own the bpfrx stem in this conf.d.
	found := false
	for _, tgt := range wipeServiceBackupSweepTargets() {
		if tgt.dir == filepath.Dir(swanctlSnippet) && tgt.owned("bpfrx.conf") {
			found = true
			if err := wipeSweepOwnedBackups(tgt.dir, tgt.owned); err != nil {
				t.Fatalf("backup sweep: %v", err)
			}
		}
	}
	if !found {
		t.Fatal("wipeServiceBackupSweepTargets does not own the bpfrx.conf stem in the swanctl conf.d")
	}
	assertAbsent(t, legacyBackup)
	if _, err := os.Lstat(foreign); err != nil {
		t.Fatalf("foreign operator.conf must survive the backup sweep: %v", err)
	}
}

// The legacy leg follows the #10100 R-2 symlink doctrine: a symlinked
// bpfrx.conf is refused (Skipped, link left, victim untouched) and the
// sibling regulars are still erased.
func TestZeroizeRenderedRefusesSymlinkedLegacyBpfrx16852(t *testing.T) {
	root := t.TempDir()
	origSwan := wipeSwanctlSnippet
	t.Cleanup(func() { wipeSwanctlSnippet = origSwan })

	real := filepath.Join(root, "elsewhere")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	frrConf := filepath.Join(root, "frr", "frr.conf")
	swan := filepath.Join(root, "swanctl", "xpf.conf")
	wipeSwanctlSnippet = swan
	legacy := filepath.Join(root, "swanctl", "bpfrx.conf")
	kea4 := filepath.Join(root, "kea", "kea-dhcp4.conf")
	kea6 := filepath.Join(root, "kea", "kea-dhcp6.conf")
	mustWriteFile(t, frrConf, []byte("hostname r1\n"))
	mustWriteFile(t, swan, []byte("regular-swan"))
	mustWriteFile(t, kea4, []byte("regular-kea4"))
	mustWriteFile(t, kea6, []byte("regular-kea6"))

	target := filepath.Join(real, "bpfrx-real.conf")
	victimBody := "ike-secret PSK-LEGACY-16852-symlink"
	mustWrite(t, target, []byte(victimBody))
	mustSymlink(t, target, legacy)

	err := wipeRenderedConfigs(frrConf, swan, kea4, kea6)
	var symErr *configstore.FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("expected FactoryResetSymlinkError for symlinked legacy snippet, got %v", err)
	}
	found := false
	for _, sk := range symErr.Skipped {
		if sk.Path == legacy {
			found = true
		}
	}
	if !found {
		t.Fatalf("Skipped %v does not name the legacy path %s", symErr.Skipped, legacy)
	}
	fi, lerr := os.Lstat(legacy)
	if lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlinked legacy snippet was unlinked (refuse must leave it): %v", lerr)
	}
	got, _ := os.ReadFile(target)
	if string(got) != victimBody {
		t.Fatalf("victim not byte-identical:\n%s", got)
	}
	assertAbsent(t, swan)
	assertAbsent(t, kea4)
	assertAbsent(t, kea6)
}
