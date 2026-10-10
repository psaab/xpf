package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/frr"
	"golang.org/x/sync/semaphore"
)

// TestRecoveredFirstCommitBootCleanupRunsThroughDaemonRun12155 is the
// startup-chain regression for the #12155 boot cleanup: an expired FIRST
// teardown debt plus an abandoned managed networkd file are arranged, then
// the actual Daemon.Run startup phases must converge the filesystem teardown
// and clear the durable debt. Deleting BOTH daemon_run.go phase calls
// (durable-first-commit-teardown and durable-first-commit-dataplane-teardown)
// leaves the file and marker in place, so the filesystem and debt assertions
// below fail.
//
// Run exits through a preloaded fatal condition after startup completes: the
// fail-closed rollback boot has no active config, uses config-only mode, binds
// only an ephemeral loopback gRPC listener, and keeps host effects redirected
// into temp dirs.
func TestRecoveredFirstCommitBootCleanupRunsThroughDaemonRun12155(t *testing.T) {
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	root := t.TempDir()
	storePath := filepath.Join(root, "xpf.conf")
	store, err := configstore.New(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name FirstEver"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	store.ExitConfigure()
	store.CancelConfirmTimerForTesting()
	if err := expireConfirmWindow12155(t, storePath); err != nil {
		t.Fatal(err)
	}

	// Isolate the networkd directory and reload effect while seeding the
	// abandoned config file and authentic bootstrap lifeline snapshot that the
	// durable rollback teardown requires.
	networkDir := t.TempDir()
	oldLinkDir, oldCommand := linkDir, runCommandTimeout
	linkDir = networkDir
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() {
		linkDir = oldLinkDir
		runCommandTimeout = oldCommand
	})
	abandoned := filepath.Join(networkDir, "10-xpf-ge-0-0-1.network")
	if err := os.WriteFile(abandoned, []byte("[Match]\nName=ge-0-0-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lifeline := []byte(bootstrapLifelineNetworkMarker +
		" (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.1/24\n")
	if err := os.WriteFile(filepath.Join(networkDir, linkPrefix+"fxp0.network"), lifeline, 0o644); err != nil {
		t.Fatal(err)
	}
	freshStore, err := configstore.New(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := freshStore.Load(); err != nil {
		t.Fatal(err)
	}
	if !freshStore.FirstCommitTeardownOwed() {
		t.Fatal("expired FIRST fixture did not acquire durable teardown debt")
	}
	generation := freshStore.FirstCommitTeardownGeneration()
	if generation == "" {
		t.Fatal("expired FIRST fixture did not retain the abandoned generation")
	}
	snapshot, err := json.Marshal(bootstrapLifelineSnapshotRecord{
		Generation: generation,
		Network:    lifeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot = append(snapshot, '\n')
	if err := os.WriteFile(filepath.Join(networkDir, bootstrapLifelineSnapshotBase), snapshot, 0o600); err != nil {
		t.Fatal(err)
	}

	// Keep startup probes isolated too; no real host node-id, default-route,
	// forwarding sysctl, nftables, or reset-handoff state is consulted.
	isolateHandoffFlag(t)
	oldNodeIDCheck := hasNodeIDFileFn
	hasNodeIDFileFn = func() bool { return false }
	t.Cleanup(func() { hasNodeIDFileFn = oldNodeIDCheck })

	confPath, sentinel := seededFRRConf(t)
	recorder := &frr.RecordingExecutor{}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    freshStore,
		frr:      frr.NewForTest(confPath, recorder),
		opts: Options{
			ConfigFile:  storePath,
			NoDataplane: true,
			GRPCAddr:    "127.0.0.1:0",
		},
	}

	// Queue a real Run exit condition before startup. Run only consumes it
	// after every startup phase succeeds, so the call below proves the phases
	// completed without a sleep, signal race, or direct helper invocation.
	stopAfterStartup := errors.New("test stop after startup")
	d.fatalCh = make(chan error, 1)
	d.fatalCh <- stopAfterStartup
	if err := d.Run(context.Background()); !errors.Is(err, stopAfterStartup) {
		t.Fatalf("Daemon.Run returned %v, want its queued post-startup stop", err)
	}

	// Pre-dataplane stage: the abandoned managed file is actually gone from
	// the redirected networkd dir, not merely scheduled for removal.
	if _, err := os.Stat(abandoned); !os.IsNotExist(err) {
		t.Fatalf("Daemon.Run left the abandoned managed networkd file: %v", err)
	}
	if got := readConf(t, confPath); strings.Contains(got, sentinel) {
		t.Fatalf("Daemon.Run left FRR managed sentinel %q", sentinel)
	}

	// Post-dataplane stage: observe durable debt and its on-disk marker cleared
	// by Run after the no-dataplane setup phase completed.
	if freshStore.FirstCommitTeardownOwed() {
		t.Fatal("Daemon.Run left expired FIRST teardown debt owed after cleanup converged")
	}
	markerPath := filepath.Join(root, ".configdb", "first-commit-teardown.json")
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("durable teardown marker remains after Daemon.Run cleanup: %v", err)
	}
}
