package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/networkd"
)

// TestCrashBetweenPromoteAndTeardownRestoresFromDurableSnapshot12154 pins
// MINOR-3: a crash after PromoteRollback persisted committed=0 but before
// the daemon teardown ran must still restore the pre-takeover lifeline on
// restart — from the DURABLE snapshot, since the in-memory one is gone.
func TestCrashBetweenPromoteAndTeardownRestoresFromDurableSnapshot12154(t *testing.T) {
	dir := lifelineNetworkDir12154(t)
	path := filepath.Join(dir, linkPrefix+"fxp0.network")
	lifeline := []byte(bootstrapLifelineNetworkMarker +
		" (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.99/24\n")
	if err := os.WriteFile(path, lifeline, 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.db")
	storeA, err := configstore.New(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.Load(); err != nil {
		t.Fatalf("fresh Load: %v", err)
	}
	dA := lifelineDaemon12154(t, storeA, dir,
		[]networkd.InterfaceConfig{{Name: "fxp0", Addresses: []string{"192.0.2.99/24"}}})
	dA.bootstrapMode.Store(true)
	// Production captures at bootstrap exit (daemon_run_naming.go), BEFORE
	// the first commit is armed. Capture here for the same ordering: the
	// snapshot binds to the pre-takeover active generation.
	dA.captureBootstrapLifelineNetwork()
	commitConfirmedText12154(t, storeA,
		"interfaces { fxp0 { unit 0 { family inet { address 192.0.2.99/24; } } } }\n")
	if err := dA.applyConfigLocked(t.Context(), storeA.ActiveConfig()); err != nil {
		t.Fatalf("first process apply: %v", err)
	}
	// Simulate the crash: promote WITHOUT running the daemon teardown.
	// (InvokeRollbackTimerForTesting would run the registered executor =
	// the teardown; call PromoteRollback directly to model death before it.)
	if _, ok := storeA.PromoteRollback(storeA.ConfirmGenForTesting()); !ok {
		t.Fatal("premise: PromoteRollback did not promote")
	}
	// Fresh process: new store + daemon, no in-memory snapshot.
	storeB, err := configstore.New(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeB.Load(); err != nil {
		t.Fatalf("restart Load: %v", err)
	}
	dB := lifelineDaemon12154(t, storeB, dir,
		[]networkd.InterfaceConfig{{Name: "fxp0", Addresses: []string{"192.0.2.99/24"}}})
	dB.bootstrapLifelineMu.Lock()
	uncaptured := !dB.bootstrapLifelineCaptured && len(dB.bootstrapLifelineNetwork) == 0
	dB.bootstrapLifelineMu.Unlock()
	if !uncaptured {
		t.Fatal("premise: fresh daemon must have no in-memory snapshot")
	}
	restored, err := dB.restoreBootstrapLifelineNetwork()
	if err != nil {
		t.Fatalf("restore from durable snapshot: %v", err)
	}
	if !restored {
		t.Fatal("restore reported no-op; want durable-snapshot restore")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(lifeline) {
		t.Fatalf("restored lifeline = %q, err=%v; want original .99 bytes", got, err)
	}
}
