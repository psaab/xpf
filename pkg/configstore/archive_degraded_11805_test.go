package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/fsatomic"
)

func restoreArchiveDegradedSeams(t *testing.T) {
	t.Helper()
	archiveRead := archiveDirReader
	rotateRead := archiveRotateDirReader
	atomicWrite := rbWriteFileAtomic
	t.Cleanup(func() {
		archiveDirReader = archiveRead
		archiveRotateDirReader = rotateRead
		rbWriteFileAtomic = atomicWrite
	})
}

func commitArchiveTestConfig(t *testing.T, s *Store, name string) {
	t.Helper()
	if err := s.SetFromInput("system host-name " + name); err != nil {
		t.Fatalf("SetFromInput(%q): %v", name, err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit(%q): %v", name, err)
	}
	s.archiveWG.Wait()
}

// TestArchiveDegradedFailureSurfaces11805 pins the three independent failure
// stages: the commit-time sequence scan, writing the archive, and rotating old
// files. Each failure keeps the config commit successful but records the
// degraded bit, monotonic failure counter, and journal event.
//
// RED on revert: removing the archive result tracking leaves the bit clear,
// count at zero, or archive_persist_error absent for the corresponding stage.
func TestArchiveDegradedFailureSurfaces11805(t *testing.T) {
	for _, stage := range []string{"scan", "write", "rotation"} {
		t.Run(stage, func(t *testing.T) {
			restoreArchiveDegradedSeams(t)
			injected := errors.New("injected " + stage + " failure")
			s := newTestStore(t)
			dir := filepath.Join(t.TempDir(), "archive")
			if stage == "scan" {
				archiveDirReader = func(string) ([]os.DirEntry, error) {
					return nil, injected
				}
			}
			s.SetArchiveConfig(dir, 1)
			if err := s.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			switch stage {
			case "write":
				atomicWrite := rbWriteFileAtomic
				rbWriteFileAtomic = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
					if strings.HasPrefix(filepath.Base(path), "config-") && strings.HasSuffix(path, ".conf") {
						return injected
					}
					return atomicWrite(path, data, perm, opts...)
				}
			case "rotation":
				archiveRotateDirReader = func(string) ([]os.DirEntry, error) {
					return nil, injected
				}
			}
			commitArchiveTestConfig(t, s, "archive-degraded-"+stage)
			if !s.ArchiveDegraded() {
				t.Fatal("ArchiveDegraded() = false after injected archive failure, want true")
			}
			if got := s.ArchiveFailureCount(); got != 1 {
				t.Fatalf("ArchiveFailureCount() = %d, want 1", got)
			}
			entries, err := s.journal.Tail(0)
			if err != nil {
				t.Fatalf("journal Tail: %v", err)
			}
			found := false
			for _, entry := range entries {
				if entry.Action == "archive_persist_error" {
					found = true
					break
				}
			}
			if !found {
				t.Fatal("journal has no archive_persist_error after injected archive failure")
			}
		})
	}
}

// TestArchiveDegradedClearsAfterSuccessfulSave11805 pins recovery: a fully
// successful later archive (write and rotation) clears the latch while
// preserving the cumulative failure count and journal history.
func TestArchiveDegradedClearsAfterSuccessfulSave11805(t *testing.T) {
	restoreArchiveDegradedSeams(t)
	s := newTestStore(t)
	dir := filepath.Join(t.TempDir(), "archive")
	s.SetArchiveConfig(dir, 2)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected archive write failure")
	atomicWrite := rbWriteFileAtomic
	rbWriteFileAtomic = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if strings.HasPrefix(filepath.Base(path), "config-") && strings.HasSuffix(path, ".conf") {
			return injected
		}
		return atomicWrite(path, data, perm, opts...)
	}
	commitArchiveTestConfig(t, s, "archive-degraded-before-clear")
	if !s.ArchiveDegraded() {
		t.Fatal("failed archive did not set ArchiveDegraded")
	}

	rbWriteFileAtomic = atomicWrite
	commitArchiveTestConfig(t, s, "archive-degraded-after-clear")
	if s.ArchiveDegraded() {
		t.Fatal("fully successful archive did not clear ArchiveDegraded")
	}
	if got := s.ArchiveFailureCount(); got != 1 {
		t.Fatalf("successful archive rewound failure count to %d, want 1", got)
	}
	entries, err := s.journal.Tail(0)
	if err != nil {
		t.Fatalf("journal Tail: %v", err)
	}
	for _, entry := range entries {
		if entry.Action == "archive_persist_error" {
			return
		}
	}
	t.Fatal("successful recovery erased archive failure journal history")
}
