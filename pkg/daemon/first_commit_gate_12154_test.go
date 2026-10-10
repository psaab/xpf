package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/networkd"
)

// TestFirstCommitRollbackGateIgnoresNilNonFirstTarget12154 pins MINOR-1/M1:
// a nil-target rollback that is NOT first-commit (#6538 recovery shape) must
// enter the safe state WITHOUT first-commit cleanup. Observable: a running
// DHCP client must SURVIVE (the gate must not Reconcile(nil) it). Forcing
// the gate predicate true (M1) kills the client and fails this test.
func TestFirstCommitRollbackGateIgnoresNilNonFirstTarget12154(t *testing.T) {
	dir := lifelineNetworkDir12154(t)
	store, err := configstore.New(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("fresh Load: %v", err)
	}
	managed := []networkd.InterfaceConfig{{Name: "fxp0", DHCPv4: true}}
	d := lifelineDaemon12154(t, store, dir, managed)
	manager := dhcp.NewManagerForTesting(func(ctx context.Context, _ string, _ dhcp.AddressFamily) {
		<-ctx.Done()
	})
	defer manager.StopAll()
	d.dhcp = manager
	d.bootstrapMode.Store(true)
	// Commit a first config so the box is committed (non-first window).
	commitConfirmedText12154(t, store,
		"interfaces { fxp0 { unit 0 { family inet { dhcp; } } } }\n")
	if err := store.ConfirmCommit(); err != nil {
		t.Fatalf("confirm first: %v", err)
	}
	if !store.EverCommitted() {
		t.Fatal("premise: store not committed after confirm")
	}
	if err := d.applyConfigLocked(context.Background(), store.ActiveConfig()); err != nil {
		t.Fatalf("apply committed: %v", err)
	}
	d.opts.NoDataplane = false
	d.reconcileDHCPClients(store.ActiveConfig())
	d.opts.NoDataplane = true
	if _, ok := manager.RunningClientHandlesForTesting()["fxp0/4"]; !ok {
		t.Fatal("premise: committed DHCP fxp0 client did not start")
	}
	// Arm a NON-first confirmed window, then fire its rollback timer.
	commitConfirmedText12154(t, store,
		"interfaces { fxp0 { unit 0 { family inet { dhcp; } } } }\n system { host-name m1-gate-12154; }\n")
	gen := store.ConfirmGenForTesting()
	_, first, pending := store.PendingRollbackTarget(gen)
	if !pending || first {
		t.Fatalf("premise: pending=%v first=%v; want pending non-first window", pending, first)
	}
	store.InvokeRollbackTimerForTesting(gen)
	if store.IsConfirmPending() {
		t.Fatal("rollback timer did not resolve the window")
	}
	if _, ok := manager.RunningClientHandlesForTesting()["fxp0/4"]; !ok {
		t.Fatal("M1: non-first rollback killed the DHCP client (gate forced true)")
	}
}
