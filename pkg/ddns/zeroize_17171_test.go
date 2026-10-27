package ddns

import (
	"errors"
	"os"
	"path/filepath"
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
