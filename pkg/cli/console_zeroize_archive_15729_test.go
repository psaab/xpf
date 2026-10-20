package cli

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #15729 leg 1: console zeroize must surface a custom archive-dir skip.

func TestConsoleZeroizeSurfacesCustomArchiveDirSkip(t *testing.T) {
	c := consoleZeroizeStore(t)
	customDir := filepath.Join(t.TempDir(), "compliance-archive")
	c.store.SetArchiveConfig(customDir, 10)

	origWipe, origStop := zeroizeFullWipe, zeroizeStopDaemon
	t.Cleanup(func() { zeroizeFullWipe, zeroizeStopDaemon = origWipe, origStop })

	var gotArchive string
	// Faithful spy: run the SAME ownership-guarded eraser the real wipe
	// delegates to, so a hardcoded DefaultArchiveDir would erase cleanly
	// (nil) while the configured custom dir surfaces the typed skip.
	zeroizeFullWipe = func(_, _, archiveDir string, _ zeroizeLogInventory, _ string) error {
		gotArchive = archiveDir
		return configstore.FactoryResetArchiveDir(archiveDir)
	}
	stopped := false
	zeroizeStopDaemon = func() error { stopped = true; return nil }

	err := c.performConsoleZeroize()
	var skipped *configstore.ArchiveDirSkippedError
	if !errors.As(err, &skipped) {
		t.Fatalf("performConsoleZeroize = %v, want *configstore.ArchiveDirSkippedError for custom archive-dir", err)
	}
	if skipped.Dir != customDir {
		t.Errorf("skipped dir = %q, want configured %q", skipped.Dir, customDir)
	}
	if gotArchive != customDir {
		t.Errorf("wipe was handed archive dir %q, want configured %q", gotArchive, customDir)
	}
	if stopped {
		t.Fatal("zeroizeStopDaemon called despite incomplete (skipped-archive) reset")
	}
}
