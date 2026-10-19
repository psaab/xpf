package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/networkd"
)

// TestFirstCommitAbsentLifelineSurvivesRestart14993 is the D38-05 daemon
// leg: a first commit taken over when no 10-xpf-fxp0.network existed
// pre-takeover, expiring across a daemon restart, must remove the
// post-takeover file and converge the teardown debt. On pre-fix code the
// durable snapshot record never encoded the absent state, so the restart
// consumer had no provenance and stayed DEGRADED with debt retained.
func TestFirstCommitAbsentLifelineSurvivesRestart14993(t *testing.T) {
	dir := firstCommit12155FilesAndCommands(t)
	installFakeNetworkctl(t)
	path := filepath.Join(dir, linkPrefix+"fxp0.network")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("premise: pre-takeover lifeline file present: %v", err)
	}
	cfgPath := filepath.Join(t.TempDir(), "config.db")

	storeA, err := configstore.New(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.Load(); err != nil {
		t.Fatalf("fresh Load: %v", err)
	}
	dA := lifelineDaemon12154(t, storeA, dir,
		[]networkd.InterfaceConfig{{Name: "fxp0", Addresses: []string{"192.0.2.99/24"}}})
	dA.bootstrapMode.Store(true)
	commitConfirmedText12154(t, storeA,
		"interfaces { fxp0 { unit 0 { family inet { address 192.0.2.99/24; } } } }")
	if err := dA.applyConfigLocked(context.Background(), storeA.ActiveConfig()); err != nil {
		t.Fatalf("first-process apply: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("takeover did not write a post-takeover fxp0 network: %v", err)
	}
	storeA.CancelConfirmTimerForTesting()
	if err := expireConfirmWindow12155(t, cfgPath); err != nil {
		t.Fatal(err)
	}

	storeB := newConfigStore(t, cfgPath)
	dB0 := &Daemon{applySem: semaphore.NewWeighted(1), store: storeB, opts: Options{ConfigFile: cfgPath}}
	closed, err := dB0.loadAndBootstrapConfig()
	if err != nil || !closed {
		t.Fatalf("restart load closed=%v err=%v", closed, err)
	}
	if !storeB.FirstCommitTeardownOwed() {
		t.Fatal("restart did not re-arm FIRST teardown debt")
	}
	dB := &Daemon{applySem: semaphore.NewWeighted(1), store: storeB, opts: Options{ConfigFile: cfgPath}}
	filesystemDone := dB.teardownRecoveredFirstCommitBeforeDataplane()
	dB.setDataplane(&firstCommitTeardownRuntime12155{})
	dB.completeRecoveredFirstCommitTeardown(filesystemDone)
	if !filesystemDone {
		t.Fatal("absent pre-takeover lifeline made the restart teardown DEGRADED")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("post-takeover fxp0 network survived the restart rollback: %v", err)
	}
	if storeB.FirstCommitTeardownOwed() {
		t.Fatal("teardown debt remained after the absent-lifeline rollback converged")
	}
}
