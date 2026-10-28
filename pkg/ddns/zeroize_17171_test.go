package ddns

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestEraseStateIfEmptyParity17171: the ddns erase entry point must behave
// like every other routed entry point — symlinked crash temp refused
// (link + target survive), regular store and temp erased, absent clean.
func TestEraseStateIfEmptyParity17171(t *testing.T) {
	t.Run("symlink refused", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "dhcp-ddns-state.json")
		if err := os.WriteFile(path, []byte(`{"version":1,"records":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, "outside.txt")
		link := filepath.Join(dir, ".dhcp-ddns-state.json.tmp-1")
		if err := os.WriteFile(target, []byte("tenant"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		var symErr *configstore.FactoryResetSymlinkError
		if err := EraseStateIfEmpty(path); !errors.As(err, &symErr) {
			t.Fatalf("expected FactoryResetSymlinkError, got %v", err)
		}
		for _, p := range []string{link, target} {
			if _, err := os.Lstat(p); err != nil {
				t.Fatalf("refusal must remove nothing, %s: %v", p, err)
			}
		}
	})
	t.Run("regular removed", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "dhcp-ddns-state.json")
		if err := os.WriteFile(path, []byte(`{"version":1,"records":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		temp := filepath.Join(dir, ".dhcp-ddns-state.json.tmp-1")
		if err := os.WriteFile(temp, []byte("temp"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := EraseStateIfEmpty(path); err != nil {
			t.Fatalf("regular erase: %v", err)
		}
		for _, p := range []string{path, temp} {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Fatalf("%s survived: %v", p, err)
			}
		}
	})
	t.Run("absent is clean", func(t *testing.T) {
		if err := EraseStateIfEmpty(filepath.Join(t.TempDir(), "nope.json")); err != nil {
			t.Fatalf("absent erase must be nil, got %v", err)
		}
	})
}

// TestEraseStateIfEmptyHistoricWording17171 pins the fold-F1/F2 message
// contract at the ddns entry point: a hardlinked crash temp keeps the
// verbatim historic ddns spelling (with the typed error), and a list
// failure (parent path is a regular file, so ReadDir fails) carries
// exactly ONE "ddns: " prefix.
func TestEraseStateIfEmptyHistoricWording17171(t *testing.T) {
	t.Run("hardlinked temp keeps historic wording", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "dhcp-ddns-state.json")
		if err := os.WriteFile(path, []byte(`{"version":1,"records":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		temp := filepath.Join(dir, ".dhcp-ddns-state.json.tmp-1")
		sibling := filepath.Join(dir, "sibling.json")
		if err := os.WriteFile(temp, []byte("temp"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(temp, sibling); err != nil {
			t.Fatalf("hardlink plant: %v", err)
		}
		err := EraseStateIfEmpty(path)
		var linkErr *configstore.FactoryResetHardlinkError
		if !errors.As(err, &linkErr) {
			t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
		}
		want := "ddns: refusing to erase hard-linked crash temp " + temp + ": "
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("hardlink refusal = %q, want verbatim historic %q", err, want)
		}
	})
	t.Run("list failure has a single ddns prefix", func(t *testing.T) {
		dir := t.TempDir()
		// Parent "directory" is a regular file: ReadDir fails, which
		// is the ListCrashTemps failure the fold-F2 wrap doubled.
		blocker := filepath.Join(dir, "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(blocker, "dhcp-ddns-state.json")
		if err := os.WriteFile(path, []byte(`{"version":1,"records":[]}`), 0o600); err == nil {
			t.Skip("cannot plant a state file under a regular-file parent on this fs")
		}
		// EraseStateIfEmpty gates on CheckStateEmpty first; exercise
		// the sweep directly for the list-failure wording.
		err := sweepCrashTemps(path)
		if err == nil || strings.Count(err.Error(), "ddns: ") != 1 || !strings.Contains(err.Error(), "ddns: inspect ownership-state directory for "+path+": ") {
			t.Fatalf("list failure = %q, want a single 'ddns: inspect ownership-state directory' prefix", err)
		}
	})
}
