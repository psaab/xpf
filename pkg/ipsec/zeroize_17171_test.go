package ipsec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestEraseConnStateIfEmptyParity17171: the ipsec erase entry point must
// behave like every other routed entry point — symlinked crash temp
// refused (link + target survive), regular store and temp erased,
// absent clean.
func TestEraseConnStateIfEmptyParity17171(t *testing.T) {
	t.Run("symlink refused", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ipsec-conn-state.json")
		if err := os.WriteFile(path, []byte(`{"loaded":[],"pending_terminate":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, "outside.txt")
		link := filepath.Join(dir, ".ipsec-conn-state.json.tmp-1")
		if err := os.WriteFile(target, []byte("tenant"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		var symErr *configstore.FactoryResetSymlinkError
		if err := EraseConnStateIfEmpty(path); !errors.As(err, &symErr) {
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
		path := filepath.Join(dir, "ipsec-conn-state.json")
		if err := os.WriteFile(path, []byte(`{"loaded":[],"pending_terminate":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		temp := filepath.Join(dir, ".ipsec-conn-state.json.tmp-1")
		if err := os.WriteFile(temp, []byte("temp"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := EraseConnStateIfEmpty(path); err != nil {
			t.Fatalf("regular erase: %v", err)
		}
		for _, p := range []string{path, temp} {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Fatalf("%s survived: %v", p, err)
			}
		}
	})
	t.Run("absent is clean", func(t *testing.T) {
		if err := EraseConnStateIfEmpty(filepath.Join(t.TempDir(), "nope.json")); err != nil {
			t.Fatalf("absent erase must be nil, got %v", err)
		}
	})
}

// TestEraseConnStateIfEmptyHistoricWording17171 pins the fold-F1/F2
// message contract at the ipsec entry point: a hardlinked crash temp
// keeps the verbatim historic ipsec spelling (with the typed error),
// and a list failure carries exactly ONE "ipsec: " prefix.
func TestEraseConnStateIfEmptyHistoricWording17171(t *testing.T) {
	t.Run("hardlinked temp keeps historic wording", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ipsec-conn-state.json")
		if err := os.WriteFile(path, []byte(`{"loaded":[],"pending_terminate":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		temp := filepath.Join(dir, ".ipsec-conn-state.json.tmp-1")
		sibling := filepath.Join(dir, "sibling.json")
		if err := os.WriteFile(temp, []byte("temp"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(temp, sibling); err != nil {
			t.Fatalf("hardlink plant: %v", err)
		}
		err := EraseConnStateIfEmpty(path)
		var linkErr *configstore.FactoryResetHardlinkError
		if !errors.As(err, &linkErr) {
			t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
		}
		want := "ipsec: refusing to erase hard-linked crash temp " + temp + ": "
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("hardlink refusal = %q, want verbatim historic %q", err, want)
		}
	})
	t.Run("list failure has a single ipsec prefix", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(blocker, "ipsec-conn-state.json")
		err := sweepCrashTemps(path)
		if err == nil || strings.Count(err.Error(), "ipsec: ") != 1 || !strings.Contains(err.Error(), "ipsec: inspect connection-state directory for "+path+": ") {
			t.Fatalf("list failure = %q, want a single 'ipsec: inspect connection-state directory' prefix", err)
		}
	})
}
