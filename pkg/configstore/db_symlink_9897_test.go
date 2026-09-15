package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #9897 F-037: NewDB must refuse a symlinked db dir instead of MkdirAll/Chmod
// THROUGH it. The pre-fix code does fsatomic.MkdirAllDurable(dir, 0700) then
// os.Chmod(dir, 0700) with no Lstat/O_NOFOLLOW (db.go), so a symlinked
// .configdb has the TARGET's mode changed to 0700 — the one sibling the
// chmodOwnerOnly Lstat discipline (journal.go) did not reach.
//
// Every spelling of the link is refused, not just the bare path: a trailing
// separator ("link/", "link/.") makes Lstat traverse to the TARGET dir and
// makes the O_NOFOLLOW open succeed on it too, so without normalization the
// gate is dead for callers that forward an unnormalized spelling (cmd/xpfd
// upgrade.go forwards --configdb-dir verbatim). Each row reuses one fixture —
// refusal is side-effect-free, so the target mode assertion holds per row.
func TestNewDBRefusesSymlinkedDir9897(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, ".configdb")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	spellings := []struct {
		name string
		path string
	}{
		{"bare", link},
		{"trailing-slash", link + "/"},
		{"slash-dot", link + "/."},
		{"double-slash", link + "//"},
		// Raw concatenation, not filepath.Join: Join cleans, which would
		// collapse these rows back to the bare spelling under test.
		{"dot-segment", root + "/./.configdb"},
	}
	for _, sp := range spellings {
		t.Run(sp.name, func(t *testing.T) {
			_, err := NewDB(sp.path)
			if err == nil {
				t.Fatalf("NewDB(%q) = nil error for a SYMLINKED db dir; the "+
					"target's mode is chmod'd through the link -- the #9897 F-037 defect",
					sp.path)
			}
			if !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), real) {
				t.Fatalf("error must name the link AND its target so the operator can find "+
					"the misconfiguration, got: %v", err)
			}
			// The refusal must precede the chmod: the target keeps its mode.
			fi, statErr := os.Stat(real)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if got := fi.Mode().Perm(); got != 0o755 {
				t.Fatalf("symlink target mode = %o, want 0755 (refusal must precede Chmod)", got)
			}
		})
	}
}

// CONTROL: an ordinary db dir still opens (mode enforced to 0700), an absent
// one is still created, and an INTERMEDIATE link (a symlinked parent, the
// legitimate operator layout) still works — only the final component is gated.
func TestNewDBOrdinaryPathsUnaffected9897(t *testing.T) {
	root := t.TempDir()

	t.Run("existing-dir-enforced-0700", func(t *testing.T) {
		dir := filepath.Join(root, "a", ".configdb")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		db, err := NewDB(dir)
		if err != nil {
			t.Fatalf("NewDB on an ordinary dir: %v", err)
		}
		if db == nil {
			t.Fatal("NewDB returned nil DB with nil error")
		}
		fi, statErr := os.Stat(dir)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if got := fi.Mode().Perm(); got != 0o700 {
			t.Fatalf("ordinary dir mode = %o, want 0700", got)
		}
	})

	t.Run("absent-dir-created", func(t *testing.T) {
		dir := filepath.Join(root, "b", ".configdb")
		if _, err := NewDB(dir); err != nil {
			t.Fatalf("NewDB on an absent dir: %v", err)
		}
		fi, statErr := os.Stat(dir)
		if statErr != nil {
			t.Fatalf("absent dir was not created: %v", statErr)
		}
		if !fi.IsDir() {
			t.Fatal("created db path is not a directory")
		}
	})

	t.Run("intermediate-link-still-works", func(t *testing.T) {
		real := filepath.Join(root, "real")
		if err := os.MkdirAll(real, 0o755); err != nil {
			t.Fatal(err)
		}
		parent := filepath.Join(root, "parent")
		if err := os.Symlink(real, parent); err != nil {
			t.Fatal(err)
		}
		if _, err := NewDB(filepath.Join(parent, ".configdb")); err != nil {
			t.Fatalf("NewDB through a symlinked PARENT (legitimate layout): %v", err)
		}
	})
}
