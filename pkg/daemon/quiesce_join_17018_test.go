package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/ipsec"

	"golang.org/x/sync/semaphore"
)

// #17018 (R4-Q31-02): a DHCP lease callback parked on an unbounded
// context.Background() applySem acquire deadlocks shutdown. The dhcp
// manager's Quiesce joins the in-flight callback (recompileWG), and
// runShutdownSequence calls Quiesce BEFORE the bounded apply drain and
// the #9035 fail-closed block. If the callback is parked behind a holder
// that keeps applySem past SIGTERM (a Background-bound rollback / boot /
// background apply, or a genuinely wedged holder), the parked callback
// never returns, Quiesce never returns, and systemd SIGKILLs the daemon
// at TimeoutStopSec before rg_active is cleared and Kea is stopped.
//
// The fix gives background appliers a daemon-lifetime context that
// fenceBackgroundApplies cancels: a parked waiter is rejected promptly,
// so the callback returns, the Quiesce join completes, and the bounded
// shutdown proceeds. These cells deliberately do NOT rely on a test-only
// cancellation hook: before the fix, fenceBackgroundApplies only latches
// the boolean and the permanently-held semaphore keeps each waiter parked.

func backgroundApplyContextForTest17018(d *Daemon) {
	d.backgroundApplyContext, d.backgroundApplyCancel = context.WithCancel(context.Background())
}

// holdApplySem17018 acquires the semaphore on behalf of a wedged holder
// and returns the release. The holder is NEVER released by the parked
// cells: the waiter must escape via fence cancellation, not via the
// holder finishing.
func holdApplySem17018(t *testing.T, d *Daemon) {
	t.Helper()
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("acquire holder: %v", err)
	}
	t.Cleanup(func() { d.applySem.Release(1) })
}

// awaitReturn17018 runs fn and requires it to return within 100ms of the
// fence being latched. The promptness clock starts at the fence (the
// acceptance bound in #17018); the parked wait must already be in flight.
func awaitReturn17018(t *testing.T, what string, fn func(), fence func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	// Let the waiter reach its blocking acquire.
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	fence()
	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("%s returned %s after the fence, want within 100ms (#17018)", what, elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("%s still parked 3s after fenceBackgroundApplies with applySem held: the "+
			"background acquire is unbounded (context.Background), so a DHCP lease callback "+
			"parked here is joined forever by dhcp.Manager.Quiesce and shutdown never reaches "+
			"the bounded drain or the #9035 fail-closed actions (#17018)", what)
	}
}

func parkedDaemon17018(t *testing.T) *Daemon {
	t.Helper()
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    newConfigStore(t, t.TempDir()+"/xpf.conf"),
	}
	backgroundApplyContextForTest17018(d)
	return d
}

func TestParkedApplyConfigAbortsOnFence17018(t *testing.T) {
	d, applies := fenceTestDaemon(t)
	backgroundApplyContextForTest17018(d)
	holdApplySem17018(t, d)
	awaitReturn17018(t, "applyConfig", func() { d.applyConfig(&config.Config{}) }, d.fenceBackgroundApplies)
	if got := applies.Load(); got != 0 {
		t.Fatalf("apply ran %d time(s) after the fence; a cancelled waiter must not apply (#17018)", got)
	}
}

func TestParkedApplyActiveConfigAbortsOnFence17018(t *testing.T) {
	d, _ := mgmtIPsecDaemon14976(t)
	backgroundApplyContextForTest17018(d)
	var applies atomic.Int32
	d.applyBodyForTest = func(*config.Config) { applies.Add(1) }
	holdApplySem17018(t, d)
	awaitReturn17018(t, "applyActiveConfig", d.applyActiveConfig, d.fenceBackgroundApplies)
	if got := applies.Load(); got != 0 {
		t.Fatalf("apply ran %d time(s) after the fence; a cancelled waiter must not apply (#17018)", got)
	}
}

func TestParkedManagementOnlyLeaseRefreshAbortsOnFence17018(t *testing.T) {
	d := parkedDaemon17018(t)
	var routeCalls atomic.Int32
	prevRoute := mgmtRouteRefreshFn
	t.Cleanup(func() { mgmtRouteRefreshFn = prevRoute })
	mgmtRouteRefreshFn = func(*Daemon) error { routeCalls.Add(1); return nil }
	d.reconcileDNSFn = func(*config.Config, bool) error { return nil }
	holdApplySem17018(t, d)
	awaitReturn17018(t, "managementOnlyLeaseRefresh", d.managementOnlyLeaseRefresh, d.fenceBackgroundApplies)
	if got := routeCalls.Load(); got != 0 {
		t.Fatalf("mgmt route refresh ran %d time(s) after the fence; the cancelled refresh must not reconcile (#17018)", got)
	}
}

func TestParkedReapplyIPsecAbortsOnFence17018(t *testing.T) {
	d := parkedDaemon17018(t)
	d.ipsec = ipsec.New()
	var applies atomic.Int32
	d.ipsecApply = func(*config.Config) error { applies.Add(1); return nil }
	holdApplySem17018(t, d)
	cfg := dhcpBoundIPsecConfig()
	awaitReturn17018(t, "reapplyIPsecForLeaseChange", func() { d.reapplyIPsecForLeaseChange(cfg) }, d.fenceBackgroundApplies)
	if got := applies.Load(); got != 0 {
		t.Fatalf("IPsec reapply ran %d time(s) after the fence; a cancelled waiter must not re-render swanctl (#17018)", got)
	}
}

func TestParkedRebindWebMgmtAbortsOnFence17018(t *testing.T) {
	d := parkedDaemon17018(t)
	d.mgmt.Store(&managementReconciler{})
	var calls atomic.Int32
	prevApply := webMgmtRebindApply
	t.Cleanup(func() { webMgmtRebindApply = prevApply })
	webMgmtRebindApply = func(*Daemon, *config.Config) error { calls.Add(1); return nil }
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true}}},
	}
	cfg.System.Services = &config.SystemServicesConfig{
		WebManagement: &config.WebManagementConfig{HTTPS: true, HTTPSInterface: "fxp0.0"},
	}
	holdApplySem17018(t, d)
	awaitReturn17018(t, "rebindWebMgmtForLeaseChange", func() { d.rebindWebMgmtForLeaseChange(cfg) }, d.fenceBackgroundApplies)
	if got := calls.Load(); got != 0 {
		t.Fatalf("web-management rebind ran %d time(s) after the fence; a cancelled waiter must not rebind (#17018)", got)
	}
}

func TestParkedReconcileDNSAbortsOnFence17018(t *testing.T) {
	d := parkedDaemon17018(t)
	d.reconcileDNSFn = func(*config.Config, bool) error { return nil }
	holdApplySem17018(t, d)
	awaitReturn17018(t, "reconcileDNSFromDHCP", d.reconcileDNSFromDHCP, d.fenceBackgroundApplies)
}

// TestDHCPCallbackReturnsWhenApplyWaitIsCancelled17018 exercises the
// callback body used by the lease-change debounce on its management-only
// branch. This covers both serialized acquisitions made by that callback
// (management refresh, then DNS): once shutdown fences, its first parked
// acquire must return instead of making the DHCP manager's Quiesce join
// unbounded. The test checks the externally observable state: no route
// refresh or IPsec/web-management rebind runs after the fence, and the
// callback returns within the required 100ms bound.
func TestDHCPCallbackReturnsWhenApplyWaitIsCancelled17018(t *testing.T) {
	d, _ := mgmtIPsecDaemon14976(t)
	backgroundApplyContextForTest17018(d)
	var routeCalls atomic.Int32
	prevRoute := mgmtRouteRefreshFn
	t.Cleanup(func() { mgmtRouteRefreshFn = prevRoute })
	mgmtRouteRefreshFn = func(*Daemon) error { routeCalls.Add(1); return nil }
	var ipsecCalls atomic.Int32
	d.ipsecApply = func(*config.Config) error { ipsecCalls.Add(1); return nil }

	holdApplySem17018(t, d)
	awaitReturn17018(t, "onDHCPAddressChange", d.onDHCPAddressChange, d.fenceBackgroundApplies)
	if got := routeCalls.Load(); got != 0 {
		t.Fatalf("mgmt route refresh ran %d time(s) after the fence, want 0", got)
	}
	if got := ipsecCalls.Load(); got != 0 {
		t.Fatalf("IPsec rebind ran %d time(s) after the fence, want 0", got)
	}
}

// TestShutdownCancelsBackgroundApplyAdmission17018 binds the lifecycle wiring:
// runShutdownSequence must cancel the same context used by background
// semaphore waiters before it reaches Quiesce and the drain.
func TestShutdownCancelsBackgroundApplyAdmission17018(t *testing.T) {
	d, _ := fenceTestDaemon(t)
	ctx, cancel := context.WithCancel(context.Background())
	d.backgroundApplyContext = ctx
	d.backgroundApplyCancel = cancel

	runShutdownFenceFor6788(t, d)

	select {
	case <-ctx.Done():
	default:
		t.Fatal("runShutdownSequence fenced applies without cancelling their parked admission waits (#17018)")
	}
}

// TestQuiesceJoinsParkedDHCPCallback17018 is the cross-package acceptance
// cell: a short debounce fires the real Manager callback, which reaches the
// daemon's full DHCP apply and parks on a held applySem. Shutdown fences and
// Quiesce must join that callback within the bound without applying or
// removing the committed lease.
func TestQuiesceJoinsParkedDHCPCallback17018(t *testing.T) {
	restoreDebounce := dhcp.SetRecompileDebounceForTesting(10 * time.Millisecond)
	defer restoreDebounce()

	store := newConfigStore(t, t.TempDir()+"/config.db")
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("set interfaces fxp0 unit 0 family inet dhcp\n"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	d := &Daemon{
		applySem:  semaphore.NewWeighted(1),
		store:     store,
		daemonCtx: context.Background(),
	}
	backgroundApplyContextForTest17018(d)
	var applies atomic.Int32
	d.applyBodyForTest = func(*config.Config) { applies.Add(1) }
	callbackStarted := make(chan struct{})
	d.preApplyHookForTest = func() { close(callbackStarted) }

	mgr, err := dhcp.New(t.TempDir(), d.onDHCPAddressChange, func() {})
	if err != nil {
		t.Fatalf("dhcp.New: %v", err)
	}
	defer mgr.Close()
	d.dhcp = mgr
	holdApplySem17018(t, d)
	if err := mgr.CommitLeaseForTesting("fxp0", dhcp.AFInet, &dhcp.Lease{}, nil); err != nil {
		t.Fatalf("CommitLeaseForTesting: %v", err)
	}

	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("short-debounce DHCP callback did not reach the apply handoff")
	}
	// The callback hook is immediately before applyActiveConfig's acquire;
	// let it enter the held semaphore before the shutdown fence.
	time.Sleep(25 * time.Millisecond)

	d.fenceBackgroundApplies()
	quiesced := make(chan struct{})
	go func() {
		mgr.Quiesce()
		close(quiesced)
	}()
	select {
	case <-quiesced:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Quiesce did not join the parked DHCP callback within 100ms of the fence (#17018)")
	}
	if !mgr.Quiesced() {
		t.Fatal("Quiesce did not latch")
	}
	if leases := mgr.Leases(); len(leases) != 1 {
		t.Fatalf("Quiesce must preserve the committed lease for graceful restart; got %d", len(leases))
	}
	if got := applies.Load(); got != 0 {
		t.Fatalf("parked callback applied %d time(s) after the fence, want 0", got)
	}
	if d.applySem.TryAcquire(1) {
		d.applySem.Release(1)
		t.Fatal("the callback acquired the semaphore while its holder remained parked")
	}
}
