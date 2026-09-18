package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

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
	origWipe := performZeroizeWipe
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipe = origWipe
		scheduleStopDaemon = origStop
	})

	var gotArchive string
	var called bool
	performZeroizeWipe = func(_, _, archiveDir string) error {
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

// Control: with archival DISABLED the wipe must be handed "", not a stale or
// defaulted path. Without this, an implementation that always passed some
// non-empty directory would satisfy the cell above while erasing a path the
// operator never configured.
func TestZeroizePassesEmptyWhenArchivalDisabled7173(t *testing.T) {
	origWipe := performZeroizeWipe
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipe = origWipe
		scheduleStopDaemon = origStop
	})

	var gotArchive string
	performZeroizeWipe = func(_, _, archiveDir string) error {
		gotArchive = archiveDir
		return nil
	}
	scheduleStopDaemon = func() {}

	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "site.conf"))
	store.SetArchiveConfig("", 0) // archival off

	s := &Server{store: store}
	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"}); err != nil {
		t.Fatalf("SystemAction(zeroize): %v", err)
	}
	if gotArchive != "" {
		t.Errorf("with archival disabled the wipe must be handed \"\", got %q — erasing a "+
			"directory the operator did not configure is not this operation's business",
			gotArchive)
	}
}
