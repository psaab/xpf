package configstore

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFactoryResetConfigDirZeroizeParity13220 pins #13220 (D4-02): the shared
// FactoryResetConfigDir primitive must erase the same config-root artifacts
// the production grpcapi zeroizeConfigDir erases (#9236 .configdb copies,
// #4599 tls/, #10769 DUIDs + editor backups), must preserve a factory-reset
// pending marker, and CollectInteriorSymlinks must skip excluded trees.
func TestFactoryResetConfigDirZeroizeParity13220(t *testing.T) {
	dir := t.TempDir()
	seed := func(rel string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		if err := os.WriteFile(p, []byte("SECRET-13220"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	for _, rel := range []string{
		".configdb.restore.partial/master.key",
		".configdb.restore.partial/active.json",
		".configdb.old/master.key",
		".configdb.old/active.json",
		"tls/key.pem",
		"tls/cert.pem",
		"dhcpv6-duid-ge-0-0-0",
		"xpf.conf.1",
		"xpf.conf~",
		"xpf.conf.bak",
		"rescue.conf.orig",
		".config.journal.save",
		"neighbor.conf",
		"neighbor.conf.bak",
		"README~",
	} {
		seed(rel)
	}
	// A normal day-0 stamp sharing FactoryResetPendingBase's path must
	// carry the pending prefix to survive.
	mustWriteFactoryResetPending13220(t, dir)

	if err := FactoryResetConfigDir(dir, "xpf.conf"); err != nil {
		t.Fatalf("FactoryResetConfigDir: %v", err)
	}
	for _, rel := range []string{
		".configdb.restore.partial",
		".configdb.old",
		"tls",
		"xpf.conf.1",
		"xpf.conf~",
		"xpf.conf.bak",
		"rescue.conf.orig",
		".config.journal.save",
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); !os.IsNotExist(err) {
			t.Errorf("owned zeroize artifact survived FactoryResetConfigDir: %s (stat err=%v)", rel, err)
		}
	}
	// Pending marker preserved so the loader/day-0 gate is not consumed.
	if pending, err := IsFactoryResetPending(dir); err != nil || !pending {
		t.Errorf("factory-reset pending marker after wipe: pending=%v err=%v, want preserved pending marker", pending, err)
	}
	// Unowned siblings survive (#5768 scoping preserved).
	for _, rel := range []string{"neighbor.conf", "neighbor.conf.bak", "README~"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Errorf("unowned sibling was deleted by FactoryResetConfigDir: %s (%v)", rel, err)
		}
	}
}

func mustWriteFactoryResetPending13220(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, FactoryResetPendingBase)
	if err := os.WriteFile(p, []byte(FactoryResetPendingPrefix+"record"), 0o600); err != nil {
		t.Fatalf("write pending marker: %v", err)
	}
}

// TestCollectInteriorSymlinksSkipsExcludedTree13220 pins #13220 (D4-02):
// an excluded directory, root == exclude, or excluded root symlink must not be
// descended into or reported.
func TestCollectInteriorSymlinksSkipsExcludedTree13220(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "archive")
	if err := os.MkdirAll(archive, 0o700); err != nil {
		t.Fatalf("mkdir archive: %v", err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(archive, "inner-link")); err != nil {
		t.Fatalf("symlink inner-link: %v", err)
	}
	kept := filepath.Join(root, "kept-link")
	if err := os.Symlink("/dev/null", kept); err != nil {
		t.Fatalf("symlink kept-link: %v", err)
	}
	got, err := CollectInteriorSymlinks(root, archive)
	if err != nil {
		t.Fatalf("CollectInteriorSymlinks: %v", err)
	}
	if len(got) != 1 || got[0].Path != kept {
		t.Fatalf("CollectInteriorSymlinks(root, excludedDir) = %v, want only %s", got, kept)
	}
	got, err = CollectInteriorSymlinks(root, root)
	if err != nil {
		t.Fatalf("CollectInteriorSymlinks(root, root): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("CollectInteriorSymlinks(root, root) = %v, want none", got)
	}
	// A symlinked excluded directory must not be reported or descended into.
	root2 := t.TempDir()
	real := filepath.Join(root2, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(real, "inner-link")); err != nil {
		t.Fatalf("symlink real/inner-link: %v", err)
	}
	link := filepath.Join(root2, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink link: %v", err)
	}
	got, err = CollectInteriorSymlinks(link, link)
	if err != nil {
		t.Fatalf("CollectInteriorSymlinks(link, link): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("CollectInteriorSymlinks(link, link) = %v, want none", got)
	}
	got, err = CollectInteriorSymlinks(root2, link)
	if err != nil {
		t.Fatalf("CollectInteriorSymlinks linked exclude: %v", err)
	}
	for _, item := range got {
		if item.Path == link || item.Path == filepath.Join(link, "inner-link") {
			t.Fatalf("CollectInteriorSymlinks reported excluded symlink tree: %v", got)
		}
	}
}
