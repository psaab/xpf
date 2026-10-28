package feeds

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func TestEraseShrinkHistoryCrashTempsRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed-shrink-history.json")
	temp := filepath.Join(dir, ".feed-shrink-history.json.tmp-1")
	target := filepath.Join(dir, "outside.json")
	if err := os.WriteFile(target, []byte("prior tenant"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, temp); err != nil {
		t.Fatal(err)
	}

	if err := EraseShrinkHistoryCrashTemps(path); err == nil {
		t.Fatal("symlinked crash temp must be refused")
	}
	if _, err := os.Lstat(temp); err != nil {
		t.Fatalf("refusal must retain symlink: %v", err)
	}
	if body, err := os.ReadFile(target); err != nil || string(body) != "prior tenant" {
		t.Fatalf("refusal must retain symlink target: body=%q err=%v", body, err)
	}
}

func TestEraseShrinkHistoryCrashTempsRefusesHardlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed-shrink-history.json")
	temp := filepath.Join(dir, ".feed-shrink-history.json.tmp-1")
	sibling := filepath.Join(dir, "sibling.json")
	if err := os.WriteFile(temp, []byte("prior tenant"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(temp, sibling); err != nil {
		t.Fatalf("hardlink plant: %v", err)
	}

	var hardlinkErr *configstore.FactoryResetHardlinkError
	if err := EraseShrinkHistoryCrashTemps(path); !errors.As(err, &hardlinkErr) {
		t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
	}
	if len(hardlinkErr.Paths) != 1 || hardlinkErr.Paths[0].Path != temp {
		t.Fatalf("hardlink error paths = %+v, want crash temp %s", hardlinkErr.Paths, temp)
	}
	for _, file := range []string{temp, sibling} {
		if _, err := os.Lstat(file); err != nil {
			t.Fatalf("refusal must retain hardlink %s: %v", file, err)
		}
	}
}

// TestEraseShrinkHistoryCrashTempsHistoricWording17171 pins the
// fold-F1/F2 message contract at the feeds entry point: symlinked and
// hardlinked temps keep their verbatim historic feeds spellings (the
// hardlink one with the typed error), and a list failure carries
// exactly ONE "feeds: " prefix.
func TestEraseShrinkHistoryCrashTempsHistoricWording17171(t *testing.T) {
	t.Run("symlinked temp keeps historic wording", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "feed-shrink-history.json")
		temp := filepath.Join(dir, ".feed-shrink-history.json.tmp-1")
		target := filepath.Join(dir, "outside.json")
		if err := os.WriteFile(target, []byte("prior tenant"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, temp); err != nil {
			t.Fatal(err)
		}
		err := EraseShrinkHistoryCrashTemps(path)
		want := "feeds: shrink-history crash temp " + temp + " is a symlink; NOT erasing it"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("symlink refusal = %v, want verbatim historic %q", err, want)
		}
	})
	t.Run("hardlinked temp keeps historic wording", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "feed-shrink-history.json")
		temp := filepath.Join(dir, ".feed-shrink-history.json.tmp-1")
		sibling := filepath.Join(dir, "sibling.json")
		if err := os.WriteFile(temp, []byte("prior tenant"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(temp, sibling); err != nil {
			t.Fatalf("hardlink plant: %v", err)
		}
		err := EraseShrinkHistoryCrashTemps(path)
		var linkErr *configstore.FactoryResetHardlinkError
		if !errors.As(err, &linkErr) {
			t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
		}
		want := "feeds: refusing to erase hard-linked shrink-history crash temp " + temp + ": "
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("hardlink refusal = %q, want verbatim historic %q", err, want)
		}
	})
	t.Run("list failure has a single feeds prefix", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(blocker, "feed-shrink-history.json")
		err := EraseShrinkHistoryCrashTemps(path)
		if err == nil || strings.Count(err.Error(), "feeds: ") != 1 || !strings.Contains(err.Error(), "feeds: inspect shrink-history directory for "+path+": ") {
			t.Fatalf("list failure = %q, want a single 'feeds: inspect shrink-history directory' prefix", err)
		}
	})
}
