package fsatomic

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCopyTreeFixture builds a nested source tree shared by the
// CopyTreeDurable cells.
func writeCopyTreeFixture(t *testing.T, src string) map[string]string {
	t.Helper()
	files := map[string]string{
		"top.txt":        "root file",
		"a/d.txt":        "mid file",
		"a/b/c.txt":      "deep file",
		"a/b/e/leaf.txt": "leaf file",
	}
	for rel, content := range files {
		full := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir src %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write src %s: %v", full, err)
		}
	}
	return files
}

func TestCopyTreeDurable_FsyncsEachDirDeepestFirst17176(t *testing.T) {
	src := t.TempDir()
	writeCopyTreeFixture(t, src)

	var synced []string
	orig := copyTreeSyncDir
	copyTreeSyncDir = func(d string) error { synced = append(synced, d); return nil }
	defer func() { copyTreeSyncDir = orig }()

	dst := filepath.Join(t.TempDir(), "copy")
	if err := CopyTreeDurable(src, dst, CopyTreeOptions{}); err != nil {
		t.Fatalf("CopyTreeDurable: %v", err)
	}

	// Every created directory must have been fsynced (root + a + a/b + a/b/e).
	wantDirs := []string{dst, filepath.Join(dst, "a"), filepath.Join(dst, "a/b"), filepath.Join(dst, "a/b/e")}
	syncedSet := map[string]bool{}
	for _, d := range synced {
		syncedSet[d] = true
	}
	for _, d := range wantDirs {
		if !syncedSet[d] {
			t.Errorf("copied dir %s was not fsynced (synced=%v)", d, synced)
		}
	}
	if len(synced) == 0 {
		t.Fatal("CopyTreeDurable fsynced no directories — the durability loop did not run")
	}

	// Depth (path-separator count) must be non-increasing across the order.
	prevDepth := strings.Count(synced[0], string(os.PathSeparator))
	for _, d := range synced[1:] {
		depth := strings.Count(d, string(os.PathSeparator))
		if depth > prevDepth {
			t.Errorf("fsync order not deepest-first: %s (depth %d) followed a shallower dir (depth %d): %v",
				d, depth, prevDepth, synced)
		}
		prevDepth = depth
	}
}

func TestCopyTreeDurable_FsyncDirErrorPropagates17176(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "a/b"), 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "a/b/c.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	orig := copyTreeSyncDir
	copyTreeSyncDir = func(d string) error { return fmt.Errorf("injected fsync failure") }
	defer func() { copyTreeSyncDir = orig }()

	dst := filepath.Join(t.TempDir(), "copy")
	if err := CopyTreeDurable(src, dst, CopyTreeOptions{}); err == nil {
		t.Fatal("CopyTreeDurable returned nil despite a directory-fsync failure")
	}
}

func TestCopyTreeDurable_HashMatchesChecksum17176(t *testing.T) {
	src := t.TempDir()
	files := writeCopyTreeFixture(t, src)

	h1 := sha256.New()
	dst1 := filepath.Join(t.TempDir(), "copy1")
	if err := CopyTreeDurable(src, dst1, CopyTreeOptions{Hash: h1}); err != nil {
		t.Fatalf("CopyTreeDurable: %v", err)
	}
	sum1 := hex.EncodeToString(h1.Sum(nil))
	if sum1 == "" {
		t.Fatal("CopyTreeDurable produced empty checksum")
	}

	// Every file (and thus every intermediate dir) must be present + intact.
	for rel, want := range files {
		got, rerr := os.ReadFile(filepath.Join(dst1, rel))
		if rerr != nil {
			t.Fatalf("nested entry %s not copied: %v", rel, rerr)
		}
		if string(got) != want {
			t.Errorf("nested entry %s = %q, want %q", rel, got, want)
		}
	}

	// Checksum is deterministic for the same source tree.
	h2 := sha256.New()
	dst2 := filepath.Join(t.TempDir(), "copy2")
	if err := CopyTreeDurable(src, dst2, CopyTreeOptions{Hash: h2}); err != nil {
		t.Fatalf("CopyTreeDurable second pass: %v", err)
	}
	if sum2 := hex.EncodeToString(h2.Sum(nil)); sum1 != sum2 {
		t.Errorf("CopyTreeDurable checksum non-deterministic: %s != %s", sum1, sum2)
	}
}
