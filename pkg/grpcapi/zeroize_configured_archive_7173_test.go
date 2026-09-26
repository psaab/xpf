package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #7173: runZeroize must hand the wipe the STORE'S CONFIGURED archive
// directory, not a hardcoded default.
//
// `system archival archive-dir` is operator-settable and IS honoured for
// WRITING archives, so a box can be archiving to a custom path. Zeroize called
// FactoryResetArchiveDir(configstore.DefaultArchiveDir) unconditionally, which
// meant it erased a path holding nothing and never examined the one holding
// config-<ts>.<seq>.conf snapshots — full committed config text with cleartext
// IKE PSKs, WireGuard keys and SNMP communities.
//
// It also made the ownership guard unreachable: that guard compares its
// argument against DefaultArchiveDir, and the caller handed it exactly that, so
// the warning it exists to emit could never fire from production. The operator
// saw a clean zeroize with no signal at all.
//
// WHY THIS CELL EXISTS SEPARATELY FROM THE CONTRACT TESTS. The pkg/configstore
// tests assert what FactoryResetArchiveDir RETURNS for a custom path. They pass
// whether or not anything ever passes it one. Measured: reverting runZeroize to
// hand the wipe "" — i.e. never erasing any archive — left the entire suite
// GREEN, 1340 collected, 0 failed. Binding the callee is not binding the
// wiring, and the wiring is where the production defect lived.
func TestZeroizePassesTheConfiguredArchiveDir7173(t *testing.T) {
	origWipe := performZeroizeWipeWithLogInventory
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipeWithLogInventory = origWipe
		scheduleStopDaemon = origStop
	})

	var gotArchive string
	var called bool
	performZeroizeWipeWithLogInventory = func(_, _, archiveDir string, _ ZeroizeLogInventory) error {
		called = true
		gotArchive = archiveDir
		return nil
	}
	scheduleStopDaemon = func() {}

	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "site.conf"))

	// The operator's custom archive destination — deliberately NOT the
	// compiled-in default, which is the whole point.
	customArchive := filepath.Join(dir, "compliance-archive")
	store.SetArchiveConfig(customArchive, 10)

	s := &Server{store: store}
	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"}); err != nil {
		t.Fatalf("SystemAction(zeroize): %v", err)
	}
	if !called {
		t.Fatal("zeroize never invoked performZeroizeWipe")
	}
	if gotArchive != customArchive {
		t.Fatalf("zeroize was handed archive dir %q, want the CONFIGURED %q. Handing it "+
			"anything else means the box archives its config — with cleartext PSKs — to one "+
			"directory and zeroizes another, reporting success (#7173)", gotArchive, customArchive)
	}
}

// An empty store archive dir does not prove that the default archive is empty:
// snapshots survive archival disable, and applyConfig may not have run yet.
// Exercise the real archive eraser through the gRPC zeroize path so this cell
// fails if the default path is skipped again.
func TestZeroizeErasesDefaultArchiveWhenArchiveDirUnset10739(t *testing.T) {
	origWipe := performZeroizeWipeWithLogInventory
	origStop := scheduleStopDaemon
	origArchive := configstore.DefaultArchiveDir
	t.Cleanup(func() {
		performZeroizeWipeWithLogInventory = origWipe
		scheduleStopDaemon = origStop
		configstore.DefaultArchiveDir = origArchive
	})

	// Keep this integration at the affected archive boundary: use the actual
	// ownership-guarded eraser while avoiding the unrelated system wipe legs.
	performZeroizeWipeWithLogInventory = func(_, _, archiveDir string, _ ZeroizeLogInventory) error {
		return configstore.FactoryResetArchiveDir(archiveDir)
	}
	scheduleStopDaemon = func() {}

	for _, tc := range []struct {
		name     string
		disabled bool
	}{
		{name: "apply not run"},
		{name: "archival disabled", disabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			archiveDir := filepath.Join(dir, "archive")
			configstore.DefaultArchiveDir = archiveDir

			store := newConfigStore(t, filepath.Join(dir, "site.conf"))
			if tc.disabled {
				store.SetArchiveConfig("", 0)
			}
			if got := store.ArchiveDir(); got != "" {
				t.Fatalf("test setup has archive dir %q, want empty", got)
			}

			snapshot := filepath.Join(archiveDir, "config-20260925.1.conf")
			if err := os.MkdirAll(archiveDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(snapshot, []byte("system { authentication-key SECRET; }\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			s := &Server{store: store}
			if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"}); err != nil {
				t.Fatalf("SystemAction(zeroize): %v", err)
			}
			if _, err := os.Stat(snapshot); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("default archive snapshot still exists after zeroize (stat err: %v)", err)
			}
		})
	}
}
