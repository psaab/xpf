package configstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// #9013 archive half. FactoryResetArchiveDir is called by the production wipe,
// so this guards a reachable path alongside the shared FactoryResetConfigDir
// primitive's config-root checks.
//
// The archive holds config-<ts>.<seq>.conf snapshots: 0600 copies of the full
// committed config TEXT with cleartext IKE PSKs, WireGuard private keys, SNMP
// communities and BGP MD5 secrets.
func TestFactoryResetArchiveRefusesSymlink9013(t *testing.T) {
	const psk = "PSK-SUPERSECRET-DO-NOT-SURVIVE"
	body := []byte("security ike policy p1 pre-shared-key ascii-text \"" + psk + "\";\n")

	t.Run("symlinked-archive-is-refused", func(t *testing.T) {
		root := t.TempDir()
		real := filepath.Join(root, "bigvolume", "archive")
		link := filepath.Join(root, "xpf", "archive")
		if err := os.MkdirAll(real, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		victim := filepath.Join(real, "config-1757000000.1.conf")
		if err := os.WriteFile(victim, body, 0o600); err != nil {
			t.Fatal(err)
		}

		old := DefaultArchiveDir
		DefaultArchiveDir = link
		t.Cleanup(func() { DefaultArchiveDir = old })

		err := FactoryResetArchiveDir(link)
		var symErr *FactoryResetSymlinkError
		if !errors.As(err, &symErr) {
			t.Fatalf("zeroize reported %v for a SYMLINKED archive dir; RemoveAll unlinked "+
				"the link and every archived config snapshot survives on the target "+
				"while the operator is told the box is clean -- the #9013 defect", err)
		}
		// The archived secret is still there -- that is the POINT of refusing
		// (the link may point at a volume xpf does not own). What must not
		// happen is reporting success.
		got, rerr := os.ReadFile(victim)
		if rerr != nil {
			t.Fatalf("refusal should have left the target untouched: %v", rerr)
		}
		if !bytes.Contains(got, []byte(psk)) {
			t.Fatal("archived config lost its contents on a path that refused to erase")
		}
		if !bytes.Contains([]byte(symErr.Error()), []byte(real)) {
			t.Fatalf("error must name the TARGET so the operator can erase it: %v", symErr)
		}
	})

	// CONTROL: a real directory at the default still erases and reports nil. A
	// guard that refused everything would pass the row above while breaking
	// every ordinary zeroize.
	t.Run("CONTROL-real-dir-still-erased", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "archive")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		victim := filepath.Join(dir, "config-1757000000.1.conf")
		if err := os.WriteFile(victim, body, 0o600); err != nil {
			t.Fatal(err)
		}
		old := DefaultArchiveDir
		DefaultArchiveDir = dir
		t.Cleanup(func() { DefaultArchiveDir = old })

		if err := FactoryResetArchiveDir(dir); err != nil {
			t.Fatalf("ordinary archive erase must succeed: %v", err)
		}
		if _, err := os.Stat(victim); !os.IsNotExist(err) {
			t.Fatalf("ordinary archive erase left the snapshot behind (stat err=%v)", err)
		}
	})

	// The pre-existing #7173 skip must keep its own distinct type: a custom
	// archive dir is skipped for OWNERSHIP, not for being a link, and the two
	// need different operator-facing words.
	t.Run("7173-ownership-skip-unchanged", func(t *testing.T) {
		err := FactoryResetArchiveDir(filepath.Join(t.TempDir(), "custom"))
		var skip *ArchiveDirSkippedError
		if !errors.As(err, &skip) {
			t.Fatalf("a custom archive dir must still yield ArchiveDirSkippedError, got %v", err)
		}
		var symErr *FactoryResetSymlinkError
		if errors.As(err, &symErr) {
			t.Fatal("an ownership skip must not be reported as a symlink skip")
		}
	})
}
