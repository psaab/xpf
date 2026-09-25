package daemon

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
)

func withApplianceMarker10733(t *testing.T, present bool) {
	t.Helper()
	old := applianceMarkerFile
	applianceMarkerFile = filepath.Join(t.TempDir(), "appliance")
	t.Cleanup(func() { applianceMarkerFile = old })
	if present {
		if err := os.WriteFile(applianceMarkerFile, []byte("appliance\n"), 0o644); err != nil {
			t.Fatalf("write appliance marker: %v", err)
		}
	}
}

func TestForeignNeverCommittedHostKeepsTransitForwarding10733(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, false)
	fence := withBarrierRecorder(t)
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if store.EverCommitted() {
		t.Fatal("fixture is not a fresh foreign host: store reports a committed config")
	}

	d := &Daemon{store: store}
	d.bootstrapMode.Store(true)
	d.applyBootTransitPolicy()
	d.closeTransitUntilAttached("foreign-host")
	d.markDataplaneNotArmed("test", "bootstrap")
	d.markDataplaneArmFailed("test", "foreign host", nil)
	d.markDataplaneArmed("foreign host")
	d.reassertTransitGate("xdp-link-tick")
	oldInterval := transitGateTickInterval
	transitGateTickInterval = 5 * time.Millisecond
	t.Cleanup(func() { transitGateTickInterval = oldInterval })
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	d.startTransitGateLoop(ctx, &wg)
	time.Sleep(25 * time.Millisecond)
	cancel()
	wg.Wait()

	assertTransitForwarding(t, v4, v6, "1", "after an uncommitted foreign-host boot and transit tick")
	if len(fence.barrierCalls) != 0 {
		t.Fatalf("uncommitted foreign host installed an nftables transit barrier: %v", fence.barrierCalls)
	}
}

func TestApplianceMarkerOwnsBootstrapTransitClosure10733(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, true)
	fence := withBarrierRecorder(t)
	d := &Daemon{}
	d.bootstrapMode.Store(true)

	d.applyBootTransitPolicy()

	assertTransitForwarding(t, v4, v6, "0", "after an appliance-marker bootstrap boot")
	if got := lastBarrierCall(fence); got != "install" {
		t.Fatalf("appliance bootstrap barrier call = %q, want install (calls: %v)", got, fence.barrierCalls)
	}
}

func TestCommittedForeignHostOwnsTransitGate10733(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, false)
	fence := withBarrierRecorder(t)
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name committed-host"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !store.EverCommitted() {
		t.Fatal("fixture did not commit its configuration")
	}

	d := &Daemon{store: store}
	d.bootstrapMode.Store(true)
	d.markDataplaneNotArmed("test", "committed host bootstrap")

	assertTransitForwarding(t, v4, v6, "0", "after a committed foreign host entered bootstrap")
	if got := lastBarrierCall(fence); got != "install" {
		t.Fatalf("committed-host bootstrap barrier call = %q, want install (calls: %v)", got, fence.barrierCalls)
	}
}

func TestFirstCommitRollbackRetainsTransitOwnership10733(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, false)
	oldLinkDir := linkDir
	linkDir = t.TempDir()
	t.Cleanup(func() { linkDir = oldLinkDir })
	fence := withBarrierRecorder(t)
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name first-commit"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	store.ExitConfigure()
	if !store.EverCommitted() {
		t.Fatal("first confirmed commit did not mark the store committed")
	}

	d := &Daemon{store: store}
	d.bootstrapMode.Store(false)
	d.setDataplane(&armedRecorderDP{})
	d.armBootDataplane(d.dataplane())
	assertTransitForwarding(t, v4, v6, "1", "after the first confirmed commit armed")

	if _, ok := store.PromoteRollback(store.ConfirmGenForTesting()); !ok {
		t.Fatal("PromoteRollback: ok=false, want first-commit rollback")
	}
	if store.EverCommitted() {
		t.Fatal("first-commit rollback did not clear EverCommitted")
	}
	if err := d.enterBootstrapMode(); err != nil {
		t.Fatalf("enterBootstrapMode: %v", err)
	}
	assertTransitForwarding(t, v4, v6, "0", "after rollback detached the armed dataplane")

	// A later tick still owns this host even though the first-commit rollback
	// made EverCommitted false before the detach.
	for _, path := range []string{v4, v6} {
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
			t.Fatalf("simulate operator forwarding write to %s: %v", path, err)
		}
	}
	d.reassertTransitGate("xdp-link-tick")
	assertTransitForwarding(t, v4, v6, "0", "after the first-commit rollback transit tick")
	if got := lastBarrierCall(fence); got != "install" {
		t.Fatalf("rollback transit barrier call = %q, want install (calls: %v)", got, fence.barrierCalls)
	}
}
