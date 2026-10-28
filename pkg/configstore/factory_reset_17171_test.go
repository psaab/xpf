package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestEraseFileForResetTable17171 runs symlink/hardlink/regular/absent
// against the shared reset-erase primitive (#17171): the table every
// routed entry point — helper temp, ddns, ipsec, feeds, Kea, canonical
// helper state, and wipeRemovePath's regular-file arm — now exercises
// through EraseFileForReset, so a hardening landing here lands in all.
func TestEraseFileForResetTable17171(t *testing.T) {
	t.Run("symlink refused", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.txt")
		link := filepath.Join(dir, "link.txt")
		if err := os.WriteFile(target, []byte("bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		var symErr *FactoryResetSymlinkError
		if err := EraseFileForReset(link); !errors.As(err, &symErr) {
			t.Fatalf("expected FactoryResetSymlinkError, got %v", err)
		}
		if len(symErr.Skipped) != 1 || symErr.Skipped[0].Path != link || symErr.Skipped[0].Target != target {
			t.Fatalf("symlink error = %+v, want link %s -> %s", symErr.Skipped, link, target)
		}
		if _, err := os.Lstat(link); err != nil {
			t.Fatalf("refusal must retain the link: %v", err)
		}
		if _, err := os.Lstat(target); err != nil {
			t.Fatalf("target must survive refusal: %v", err)
		}
	})
	t.Run("hardlink refused", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "state.json")
		sibling := filepath.Join(dir, "sibling.json")
		if err := os.WriteFile(p, []byte("bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(p, sibling); err != nil {
			t.Fatalf("hardlink plant: %v", err)
		}
		var linkErr *FactoryResetHardlinkError
		if err := EraseFileForReset(p); !errors.As(err, &linkErr) {
			t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
		}
		if len(linkErr.Paths) != 1 || linkErr.Paths[0].Path != p {
			t.Fatalf("hardlink error = %+v, want path %s", linkErr.Paths, p)
		}
		for _, f := range []string{p, sibling} {
			if _, err := os.Lstat(f); err != nil {
				t.Fatalf("refusal must remove nothing, %s: %v", f, err)
			}
		}
	})
	t.Run("regular removed", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "state.json")
		if err := os.WriteFile(p, []byte("bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := EraseFileForReset(p); err != nil {
			t.Fatalf("regular erase: %v", err)
		}
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("regular file survived: %v", err)
		}
	})
	t.Run("non-regular FIFO refused", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "state.json")
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Skipf("mkfifo unsupported here: %v", err)
		}
		// The refusal text is the primitive's own wording; the
		// class contract is the ErrEraseNonRegular sentinel plus
		// the FIFO surviving untouched (an unlink would delete it).
		if err := EraseFileForReset(p); !errors.Is(err, ErrEraseNonRegular) {
			t.Fatalf("expected ErrEraseNonRegular, got %v", err)
		} else if !strings.Contains(err.Error(), "refusing to erase non-regular file "+p) {
			t.Fatalf("non-regular refusal = %q, want it to name %s", err, p)
		}
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("refusal must retain the FIFO: %v", err)
		}
	})
	t.Run("absent is clean", func(t *testing.T) {
		if err := EraseFileForReset(filepath.Join(t.TempDir(), "nope.json")); err != nil {
			t.Fatalf("absent erase must be nil, got %v", err)
		}
	})
}

// TestSweepCrashTemps17171 pins the shared list-then-erase loop: a
// symlinked member fails closed (link and target survive) while a
// regular member is erased and the joined error names the failure.
func TestSweepCrashTemps17171(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, ".state.json.tmp-1")
	target := filepath.Join(dir, "outside.txt")
	link := filepath.Join(dir, ".state.json.tmp-2")
	if err := os.WriteFile(regular, []byte("temp"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("tenant"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	list := func() ([]string, error) { return []string{link, regular}, nil }
	var symErr *FactoryResetSymlinkError
	if err := SweepCrashTemps(list); !errors.As(err, &symErr) {
		t.Fatalf("expected FactoryResetSymlinkError, got %v", err)
	}
	if _, err := os.Lstat(regular); !os.IsNotExist(err) {
		t.Fatalf("regular temp survived: %v", err)
	}
	for _, p := range []string{link, target} {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("refusal must remove nothing, %s: %v", p, err)
		}
	}
}

// TestSweepCrashTempsWithListError17171 pins the fold-F2 split: a list
// failure (which already embeds the caller's "<pkg>: " prefix) comes
// back as listErr and ONLY as listErr, so the caller can return it
// without stacking a second identical prefix; erase failures stay on
// the joined error channel with listErr nil.
func TestSweepCrashTempsWithListError17171(t *testing.T) {
	listBoom := errors.New("ddns: inspect ownership-state directory for /x: boom")
	listErr, err := SweepCrashTempsWithListError(func() ([]string, error) { return nil, listBoom })
	if !errors.Is(listErr, listBoom) || err != nil {
		t.Fatalf("list failure = (listErr=%v, err=%v), want (boom, nil)", listErr, err)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, ".state.json.tmp-1")
	target := filepath.Join(dir, "outside.txt")
	if err := os.WriteFile(target, []byte("tenant"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	var symErr *FactoryResetSymlinkError
	listErr, err = SweepCrashTempsWithListError(func() ([]string, error) { return []string{link}, nil })
	if listErr != nil || !errors.As(err, &symErr) {
		t.Fatalf("erase failure = (listErr=%v, err=%v), want (nil, FactoryResetSymlinkError)", listErr, err)
	}
}
