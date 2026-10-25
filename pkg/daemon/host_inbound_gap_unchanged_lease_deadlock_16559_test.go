package daemon

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// TestUnchangedLeaseHookDoesNotWedgeApplySem16559 is the #16559 regression
// cell (va39 arms). Pre-fix, onDHCPUnchangedLease applied inline on the DHCP
// client goroutine: while gap debt was owed it parked uncancellably on
// applySem (context.Background). If the apply holding applySem then reached
// reconcileDHCPClients -> dhcp Reconcile and stopped/changed that client,
// Reconcile waited on the client's done channel forever, applySem never
// released, and every later commit/rollback/sync hung.
//
// Arm 1 (apply stops the caller): a real dhcp.Manager client whose
// runClientForTest does a content-identical commitLease (firing the real
// production hook) while the test holds applySem as the in-flight apply.
// The client goroutine must return from the hook (commitLease returns) so
// that cancelling it (what Reconcile does) closes done. Pre-fix the hook
// parks on applySem, commitLease never returns, done never closes, and
// Reconcile wedges — detected here by timeout, so wedged must be false.
//
// Arm 2 (hook's own apply stops its caller) is the same cycle with the
// roles collapsed: the hook itself would acquire applySem and its apply
// would stop the caller. It is covered by the same invariant — the hook
// must return without acquiring applySem — asserted directly: with
// applySem held by another party, onDHCPUnchangedLease must return
// promptly and must not itself perform an apply; the nudged retry loop
// (not running here, no loop started for this arm) owns the apply.
func TestUnchangedLeaseHookDoesNotWedgeApplySem16559(t *testing.T) {
	// Control: no debt owed -> hook is silent and returns promptly even
	// with applySem free, and performs no apply.
	t.Run("control_no_debt_no_apply", func(t *testing.T) {
		store, _ := newRollbackTestStore(t)
		d := &Daemon{applySem: semaphore.NewWeighted(1), store: store, hostInboundGapWakeCh: make(chan struct{}, 1)}
		applies := 0
		d.applyBodyForTest = func(*config.Config) { applies++ }
		done := make(chan struct{})
		go func() { defer close(done); d.onDHCPUnchangedLease() }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("hook wedged with no debt owed")
		}
		if applies != 0 {
			t.Fatalf("hook applied %d times with no debt, want 0", applies)
		}
		select {
		case <-d.hostInboundGapWakeCh:
			t.Fatal("hook nudged the retry loop with no debt owed")
		default:
		}
	})

	// Arm 2 collapsed: debt owed, applySem held by a concurrent apply.
	// The hook must return promptly, must not apply inline, and must
	// leave exactly one coalesced wake for the retry owner.
	t.Run("hook_returns_while_applySem_held", func(t *testing.T) {
		store, _ := newRollbackTestStore(t)
		d := &Daemon{applySem: semaphore.NewWeighted(1), store: store, hostInboundGapWakeCh: make(chan struct{}, 1)}
		applies := 0
		d.applyBodyForTest = func(*config.Config) { applies++ }
		d.noteHostInboundGapApplyResult(errors.New("real host-inbound and gap nft failures"))
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			t.Fatalf("acquire applySem: %v", err)
		}
		defer d.applySem.Release(1)
		done := make(chan struct{})
		go func() { defer close(done); d.onDHCPUnchangedLease() }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("wedged=true: unchanged-lease hook blocked while applySem held (inline apply on caller goroutine)")
		}
		if applies != 0 {
			t.Fatalf("hook applied inline %d times, want 0 (retry loop owns the apply)", applies)
		}
		// Burst coalesces: further nudges do not queue extra wakes.
		d.onDHCPUnchangedLease()
		d.onDHCPUnchangedLease()
		select {
		case <-d.hostInboundGapWakeCh:
		default:
			t.Fatal("hook did not nudge the retry loop while debt owed")
		}
		select {
		case <-d.hostInboundGapWakeCh:
			t.Fatal("burst produced more than one pending wake")
		default:
		}
	})

	// Arm 1: real client goroutine + real production hook + Reconcile stop.
	t.Run("reconcile_stop_of_renewing_client_converges", func(t *testing.T) {
		store, _ := newRollbackTestStore(t)
		d := &Daemon{applySem: semaphore.NewWeighted(1), store: store, hostInboundGapWakeCh: make(chan struct{}, 1)}
		var applies atomic.Int64
		d.applyBodyForTest = func(*config.Config) { applies.Add(1) }
		d.noteHostInboundGapApplyResult(errors.New("real host-inbound and gap nft failures"))

		hookReturned := make(chan struct{})
		var m *dhcp.Manager
		m = dhcp.NewManagerForTesting(func(ctx context.Context, iface string, af dhcp.AddressFamily) {
			mkLease := func() *dhcp.Lease {
				return &dhcp.Lease{
					Interface: iface, Family: af,
					Address:   netip.MustParsePrefix("10.0.0.5/24"),
					Gateway:   netip.MustParseAddr("10.0.0.1"),
					DNS:       []netip.Addr{netip.MustParseAddr("10.0.0.53")},
					LeaseTime: time.Hour, Obtained: time.Now(),
				}
			}
			// Initial acquisition (changed content: never the hook).
			prev := mkLease()
			if err := m.CommitLeaseForTesting(iface, af, prev, nil); err != nil {
				t.Errorf("initial commitLease: %v", err)
				return
			}
			// Content-identical renewal: fires the unchanged-lease hook
			// inline on THIS client goroutine (production path).
			renewed := mkLease()
			renewed.Obtained = prev.Obtained.Add(30 * time.Minute)
			if err := m.CommitLeaseForTesting(iface, af, renewed, prev); err != nil {
				t.Errorf("renewal commitLease: %v", err)
				return
			}
			close(hookReturned)
			<-ctx.Done() // long-running client until Reconcile stops it
		})
		// Wire the real production hook, as daemon_run_bringup does.
		m.SetUnchangedLeaseCallback(d.onDHCPUnchangedLease)
		d.dhcp = m

		// Start the retry loop: it receives the nudge and owns the apply.
		loopCtx, loopCancel := context.WithCancel(context.Background())
		loopDone := make(chan struct{})
		go func() { defer close(loopDone); d.hostInboundGapReassertLoop(loopCtx) }()
		defer func() { loopCancel(); <-loopDone }()

		// Hold applySem as the in-flight apply that will reconcile DHCP
		// clients. Pre-fix the renewing client parks here inside the hook.
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			t.Fatalf("acquire applySem: %v", err)
		}
		m.Reconcile([]dhcp.ClientSpec{{Iface: "ge-0-0-3", Family: dhcp.AFInet}})
		// Wait until the client has committed its renewal through the hook.
		select {
		case <-hookReturned:
		case <-time.After(5 * time.Second):
			d.applySem.Release(1)
			t.Fatal("wedged=true: client goroutine never returned from unchanged-lease hook while applySem held")
		}

		// Now, still holding applySem, stop the client the way an apply
		// whose config removes/changes its stanza does. Pre-fix this
		// blocks forever on the client's done channel.
		reconciled := make(chan struct{})
		go func() { defer close(reconciled); m.Reconcile(nil) }()
		select {
		case <-reconciled:
		case <-time.After(5 * time.Second):
			t.Fatal("wedged=true: Reconcile stop blocked on client done; applySem would never release")
		}
		d.applySem.Release(1)

		// The nudged retry owner converges the debt without any further
		// lease event, and applySem is free afterwards.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if owed, _, _ := d.HostInboundGapDebt(); !owed && applies.Load() >= 1 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if owed, _, _ := d.HostInboundGapDebt(); owed {
			t.Fatalf("gap debt still owed after nudged reassert (applies=%d)", applies.Load())
		}
		if applies.Load() < 1 {
			t.Fatal("nudged retry loop never applied the active config")
		}
		if !d.applySem.TryAcquire(1) {
			t.Fatal("applySem not free after convergence: the wedge persisted")
		}
		d.applySem.Release(1)
	})
}
