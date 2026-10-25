package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
)

// TestReconcileIpsecHostInputFenceSettledSafeSkipsApplySem16777 pins
// #16777: with a SAFE census, a CLOSING permit, an ACKed overlay authority
// and no committed divert, reconcileIpsecHostInputFence must return
// before acquiring applySem. The probe holds applySem externally; a
// reconcile that still tries to acquire would block for the full hold.
// Positive controls: the same reconcile with a divert active (must still
// acquire and open) and with a non-SAFE census (must still acquire and
// install) prove the early return is scoped to the settled state.
func TestReconcileIpsecHostInputFenceSettledSafeSkipsApplySem16777(t *testing.T) {
	origInstaller := nftInstaller
	origDelete := conntrackDeleteFilters
	origOverlayDelete := hostInputFenceConntrackDeleteFilters
	origCensus := hostInputFenceAllLocalAddrs
	t.Cleanup(func() {
		nftInstaller = origInstaller
		conntrackDeleteFilters = origDelete
		hostInputFenceConntrackDeleteFilters = origOverlayDelete
		hostInputFenceAllLocalAddrs = origCensus
	})
	hostInputFenceAllLocalAddrs = func() ([]string, error) { return nil, nil }
	conntrackDeleteFilters = func(netlink.InetFamily, ...netlink.CustomConntrackFilter) (uint, error) {
		return 0, nil
	}
	hostInputFenceConntrackDeleteFilters = func(netlink.InetFamily, ...netlink.CustomConntrackFilter) (uint, error) {
		return 0, nil
	}
	nftInstaller = &fakeNftInstaller{
		hostInbound:     func(xnft.HostInboundSpec) error { return nil },
		overlayReadback: func(xnft.HostInputFenceOverlay) error { return nil },
	}

	newDaemon := func(t *testing.T, key ipsecCloseRequestKey, withCapture bool) *Daemon {
		t.Helper()
		store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := store.LoadOverride("system { host-name fence-16777; }"); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		supervisor := newIpsecSupervisor()
		permit := testClosingRecord(8, 12, key, 4)
		supervisor.permit.Store(permit)
		supervisor.watch.Store(&TransitWatchSnapshot{Generation: 4, Ready: key.Ready, Tuples: key.Tuples})
		d := &Daemon{store: store, ipsecS4: supervisor, applySem: semaphore.NewWeighted(1)}
		desired, err := d.ipsecHostInputFenceOverlayForPermit(permit)
		if err != nil {
			t.Fatalf("derive overlay: %v", err)
		}
		d.ipsecOverlay.Store(desired)
		d.ipsecOverlayAcked.Store(desired)
		if withCapture {
			d.ipsecCaptureMu.Lock()
			d.ipsecCapture = &ipsecCaptureRuntime{supervisor: supervisor}
			d.ipsecCaptureMu.Unlock()
		}
		return d
	}

	runWhileApplySemHeld := func(t *testing.T, d *Daemon) time.Duration {
		t.Helper()
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			t.Fatalf("hold applySem: %v", err)
		}
		done := make(chan struct{})
		start := time.Now()
		go func() {
			defer close(done)
			d.reconcileIpsecHostInputFence(context.Background())
		}()
		var elapsed time.Duration
		select {
		case <-done:
			elapsed = time.Since(start)
		case <-time.After(150 * time.Millisecond):
			elapsed = 150 * time.Millisecond
		}
		d.applySem.Release(1)
		<-done
		return elapsed
	}

	xfrmi := ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 11, Name: "st0", Owner: "kernel"}

	t.Run("safe_no_divert_nonempty_overlay_returns_fast", func(t *testing.T) {
		d := newDaemon(t, testKey(ipsecReadySafe, 4, xfrmi), false)
		if elapsed := runWhileApplySemHeld(t, d); elapsed >= 150*time.Millisecond {
			t.Fatalf("settled SAFE reconcile blocked on held applySem for %v; want pre-semaphore return (#16777)", elapsed)
		}
		if got := d.ipsecS4.loadPermit(); got == nil || got.state != ipsecPermitClosing {
			t.Fatalf("settled reconcile changed permit: %+v, want still CLOSING", got)
		}
	})

	t.Run("safe_no_divert_empty_overlay_returns_fast", func(t *testing.T) {
		// No xfrmi tuples: census SAFE with empty desired overlay (the
		// no-route-based-VPN box from the issue).
		d := newDaemon(t, testKey(ipsecReadySafe, 4), false)
		if elapsed := runWhileApplySemHeld(t, d); elapsed >= 150*time.Millisecond {
			t.Fatalf("empty-overlay SAFE reconcile blocked on held applySem for %v; want pre-semaphore return (#16777)", elapsed)
		}
	})

	t.Run("safe_with_divert_still_acquires_and_opens", func(t *testing.T) {
		d := newDaemon(t, testKey(ipsecReadySafe, 4, xfrmi), true)
		if elapsed := runWhileApplySemHeld(t, d); elapsed < 150*time.Millisecond {
			t.Fatalf("divert-active reconcile returned in %v without applySem; early return is over-broad", elapsed)
		}
		if got := d.ipsecS4.loadPermit(); got == nil || got.state != ipsecPermitOpen {
			t.Fatalf("after held reconcile with divert, permit = %+v, want OPEN", got)
		}
	})
	t.Run("unsafe_no_divert_unacked_still_acquires", func(t *testing.T) {
		// UNSAFE + ACKed already returns via the pre-existing early
		// return; the semaphore-requiring UNSAFE case is the un-ACKed
		// one, which must install/read back a fence.
		d := newDaemon(t, testKey(ipsecReadyUnsafe, 4, xfrmi), false)
		d.ipsecOverlayAcked.Store(nil)
		if elapsed := runWhileApplySemHeld(t, d); elapsed < 150*time.Millisecond {
			t.Fatalf("UNSAFE un-ACKed reconcile returned in %v without applySem; settled fast path must not cover non-SAFE", elapsed)
		}
		if got := d.ipsecS4.loadPermit(); got == nil || got.state != ipsecPermitClosing {
			t.Fatalf("UNSAFE reconcile permit = %+v, want CLOSING", got)
		}
	})
	t.Run("safe_no_divert_unacked_still_acquires", func(t *testing.T) {
		d := newDaemon(t, testKey(ipsecReadySafe, 4, xfrmi), false)
		d.ipsecOverlayAcked.Store(nil)
		if elapsed := runWhileApplySemHeld(t, d); elapsed < 150*time.Millisecond {
			t.Fatalf("un-ACKed reconcile returned in %v without applySem; settled fast path requires ACKed authority", elapsed)
		}
	})
}
