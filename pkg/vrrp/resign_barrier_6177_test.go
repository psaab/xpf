package vrrp

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// #6177 item 1 — the RETH VIP-removal two-owner residual.
//
// #5640 withheld the remote-failover applied-ack until the local demotion was
// "actuated". On the RETH-VRRP path that meant ResignRG had RETURNED: the
// instance priority was driven to 0 under the instance lock and a NON-BLOCKING
// send was made on resignCh. The advert burst and the becomeBackup VIP removal
// still ran afterwards, on the instance's own goroutine — so the peer could be
// told "go ahead, promote" while this node's virtual addresses were still on
// the interface. These tests pin the barrier that closes that gap: ResignRG's
// return value must not complete until a VIP release has actually happened.

// resignBarrierInstance builds a RETH instance (Family == "" is what
// isRethInstance keys on) for redundancy group 1 — VRID 101 — whose VIP netlink
// removal is governed by delFn.
func resignBarrierInstance(t *testing.T, name string, delFn func(*netlink.Addr) error) (*Manager, *vrrpInstance) {
	t.Helper()
	m := NewManager()
	vi := newInstance(Instance{
		Interface:         name,
		GroupID:           101,
		Priority:          200,
		AdvertiseInterval: 1000,
		VirtualAddresses:  []string{"10.0.61.1/24"},
	}, &net.Interface{Name: name}, m.eventCh, nil)
	vi.linkByNameFn = func(n string) (netlink.Link, error) { return fiveZeroEightTwoLink(n), nil }
	vi.addrAddFn = func(netlink.Link, *netlink.Addr) error { return nil }
	vi.addrDelFn = func(_ netlink.Link, a *netlink.Addr) error { return delFn(a) }
	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{{iface: name, groupID: 101}: vi}
	m.mu.Unlock()
	t.Cleanup(func() {
		select {
		case <-vi.stopCh:
		default:
			close(vi.stopCh)
		}
	})
	return m, vi
}

func barrierDone(b *ResignBarrier) bool {
	select {
	case <-b.Done():
		return true
	default:
		return false
	}
}

func waitBarrier(t *testing.T, b *ResignBarrier, why string) {
	t.Helper()
	select {
	case <-b.Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("resign barrier never completed: %s", why)
	}
}

// TestResignRGBarrierNotCompleteUntilVIPRemoved_6177 is the fail-on-revert guard
// for the residual itself. The window under test is the one between ResignRG
// returning and the VRRP run loop reaching becomeBackup: in it, the resignation
// is SIGNALLED and the priority is 0, but the VIP is still on the interface.
//
// RED on revert: make ResignRG report completion at trigger time (the pre-fix
// posture — `return newResignBarrier(0)`, or arm the barrier and report to it
// inside the ResignRG loop instead of from becomeBackup) and the
// "barrier completed before the VIP was removed" assertion fires.
func TestResignRGBarrierNotCompleteUntilVIPRemoved_6177(t *testing.T) {
	release := make(chan struct{})
	removed := make(chan struct{}, 1)
	m, vi := resignBarrierInstance(t, "xpf-6177-a0", func(*netlink.Addr) error {
		<-release
		removed <- struct{}{}
		return nil
	})
	vi.setState(StateMaster)

	barrier := m.ResignRG(1)
	if barrier == nil {
		t.Fatal("ResignRG returned a nil barrier — a caller cannot fence on it")
	}

	// Positive controls: the production side effects of ResignRG really did
	// happen, so the assertion below is about ordering and not about a
	// no-op ResignRG.
	if len(vi.resignCh) != 1 {
		t.Fatalf("resignCh depth = %d, want 1 — ResignRG did not signal the instance", len(vi.resignCh))
	}
	// #15213 A25-06 supersedes the synchronous-write half of this
	// control: ResignRG now records a PENDING resignation (priority 0
	// stashed) instead of overwriting cfg.Priority, so routine adverts
	// keep the pre-resign priority until becomeBackup. The pending
	// marker — not cfg.Priority — is the synchronous side effect.
	if !vi.resignIsPending() {
		t.Fatal("ResignRG did not record a pending resignation synchronously")
	}
	if got := vi.getPriority(); got != 200 {
		t.Fatalf("routine priority after ResignRG = %d, want 200 (pre-resign, #15213 A25-06)", got)
	}

	// THE residual: at this instant the VIP delete has not been issued.
	if barrierDone(barrier) {
		t.Fatal("resign barrier completed before the VIP was removed — the peer would be " +
			"told to promote while this node still owns the virtual address (#6177 item 1)")
	}

	// Now let the run loop's hop happen: becomeBackup is what the MASTER arm of
	// the loop calls on a resignCh token.
	go vi.becomeBackup(time.NewTimer(time.Hour), time.NewTimer(time.Hour))
	// Still blocked inside the netlink delete.
	time.Sleep(20 * time.Millisecond)
	if barrierDone(barrier) {
		t.Fatal("resign barrier completed while the VIP delete was still in flight (#6177 item 1)")
	}

	close(release)
	waitBarrier(t, barrier, "becomeBackup finished removing the VIP")
	select {
	case <-removed:
	default:
		t.Fatal("the barrier completed but the netlink delete never ran")
	}
	if err := barrier.Err(); err != nil {
		t.Fatalf("barrier verdict = %v, want nil after a clean removal", err)
	}
}

// TestResignRGBarrierCarriesVIPRemoveFailure_6177 pins the verdict direction: a
// removal that FAILED leaves the address on the wire, so the barrier must not
// report a clean release. Reporting nil here would hand the peer the same
// two-owner promotion the barrier exists to prevent — the difference being that
// the stale VIP persists until the #5482 async reconcile clears it, not
// sub-millisecond.
//
// RED on revert: report `nil` instead of the removeVIPs outcome from
// becomeBackup and the Err assertion fires.
func TestResignRGBarrierCarriesVIPRemoveFailure_6177(t *testing.T) {
	injected := errors.New("injected netlink AddrDel failure")
	m, vi := resignBarrierInstance(t, "xpf-6177-b0", func(*netlink.Addr) error { return injected })
	vi.setState(StateMaster)
	vi.vipReconcileBackoff = time.Hour // keep the #5482 retry out of this test

	barrier := m.ResignRG(1)
	vi.becomeBackup(time.NewTimer(time.Hour), time.NewTimer(time.Hour))

	waitBarrier(t, barrier, "becomeBackup ran")
	err := barrier.Err()
	if err == nil {
		t.Fatal("barrier reported a clean release after the VIP removal FAILED — " +
			"a stale VIP is still answering ARP against the new master (#6177 item 1)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("barrier verdict = %v, want it to carry the netlink failure", err)
	}
}

// TestResignRGBarrierCompletesOnAlreadyBackupInstance_6177 covers the case the
// design has to get right or every clean failover turns into a hold: an
// instance that is ALREADY BACKUP when the resignation arrives. Nothing will
// call becomeBackup for it, so without a consumer the token sits in resignCh
// forever and the caller burns its whole timeout.
//
// RED on revert: delete the `case <-vi.resignCh` arm from stepBackup and this
// test fails on the barrier timeout.
func TestResignRGBarrierCompletesOnAlreadyBackupInstance_6177(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-6177-c0", func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)

	barrier := m.ResignRG(1)
	if barrierDone(barrier) {
		t.Fatal("barrier completed before the run loop consumed the resignation")
	}

	// One hop of the BACKUP arm of the run loop.
	go vi.stepBackup(time.NewTimer(time.Hour), time.NewTimer(time.Hour), time.NewTimer(time.Hour))

	waitBarrier(t, barrier, "an already-BACKUP instance must resolve the resignation, not stall it")
	if err := barrier.Err(); err != nil {
		t.Fatalf("barrier verdict = %v, want nil — an already-BACKUP instance holds no VIP tenure", err)
	}
	if len(vi.resignCh) != 0 {
		t.Fatalf("resignCh depth = %d, want 0 — the token must be consumed, not left pending", len(vi.resignCh))
	}
}

// TestResignRGBarrierAlreadyBackupWithStaleVIPFails_6177 is the honesty case of
// the one above: already BACKUP is only a clean release when no PREVIOUS
// removal failed. With #5482 divergence set the address may still be on the
// interface, so the resignation must report failure and the peer must hold.
func TestResignRGBarrierAlreadyBackupWithStaleVIPFails_6177(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-6177-d0", func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)
	vi.vipDiverged.Store(true)

	barrier := m.ResignRG(1)
	go vi.stepBackup(time.NewTimer(time.Hour), time.NewTimer(time.Hour), time.NewTimer(time.Hour))

	waitBarrier(t, barrier, "the resignation must resolve even when a stale VIP is flagged")
	if err := barrier.Err(); !errors.Is(err, ErrStaleVIPOnBackup) {
		t.Fatalf("barrier verdict = %v, want ErrStaleVIPOnBackup — a diverged VIP is not a clean release", err)
	}
}

// TestResignRGBarrierMultiInstanceWaitsForAll_6177 pins that the barrier is a
// conjunction: a RETH RG has one VRRP instance per member interface, and the
// fence is only satisfied when EVERY one of them has released. Completing on
// the first would leave the other member still answering for the VIP.
func TestResignRGBarrierMultiInstanceWaitsForAll_6177(t *testing.T) {
	m, vi1 := resignBarrierInstance(t, "xpf-6177-e0", func(*netlink.Addr) error { return nil })
	vi2 := newInstance(Instance{
		Interface:         "xpf-6177-e1",
		GroupID:           101,
		Priority:          200,
		AdvertiseInterval: 1000,
		VirtualAddresses:  []string{"10.0.61.1/24"},
	}, &net.Interface{Name: "xpf-6177-e1"}, m.eventCh, nil)
	vi2.linkByNameFn = func(n string) (netlink.Link, error) { return fiveZeroEightTwoLink(n), nil }
	vi2.addrDelFn = func(netlink.Link, *netlink.Addr) error { return nil }
	m.mu.Lock()
	m.instances[instanceKey{iface: "xpf-6177-e1", groupID: 101}] = vi2
	m.mu.Unlock()
	t.Cleanup(func() { close(vi2.stopCh) })
	vi1.setState(StateMaster)
	vi2.setState(StateMaster)

	barrier := m.ResignRG(1)
	vi1.becomeBackup(time.NewTimer(time.Hour), time.NewTimer(time.Hour))
	if barrierDone(barrier) {
		t.Fatal("barrier completed after ONE of two RETH member instances released its VIP (#6177 item 1)")
	}
	vi2.becomeBackup(time.NewTimer(time.Hour), time.NewTimer(time.Hour))
	waitBarrier(t, barrier, "both member instances released")
	if err := barrier.Err(); err != nil {
		t.Fatalf("barrier verdict = %v, want nil", err)
	}
}

// TestResignRGBarrierNoInstancesIsBornComplete_6177 pins the no-op contract: an
// RG with no RETH VRRP instances has no VIP tenure to release, so a caller must
// not be made to wait out a timeout for a fence that is already satisfied.
func TestResignRGBarrierNoInstancesIsBornComplete_6177(t *testing.T) {
	m, _ := resignBarrierInstance(t, "xpf-6177-f0", func(*netlink.Addr) error { return nil })
	barrier := m.ResignRG(7) // VRID 107 — no instance matches
	if !barrierDone(barrier) {
		t.Fatal("barrier for an RG with no RETH instances must be born complete")
	}
	if err := barrier.Err(); err != nil {
		t.Fatalf("barrier verdict = %v, want nil", err)
	}
}

// TestResignRGBarrierRetiredInstanceDoesNotStall_6177 covers the remaining way
// a release signal can fail to arrive: the instance is torn down (config
// change, shutdown) between the arm and the run loop's next hop. stop() drains
// the barrier so the caller gets a verdict instead of a hang.
func TestResignRGBarrierRetiredInstanceDoesNotStall_6177(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-6177-g0", func(*netlink.Addr) error { return nil })
	vi.setState(StateBackup)
	// The run loop is not running in this unit test, so close(stopped)
	// stands in for it having exited; stop() joins on it.
	close(vi.stopped)

	barrier := m.ResignRG(1)
	go vi.stop()

	waitBarrier(t, barrier, "a retired instance must resolve the resignation, not strand it")
}
