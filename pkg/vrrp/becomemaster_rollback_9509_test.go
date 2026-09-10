package vrrp

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #9509: becomeMaster's fail-closed arm rolls back the VIPs it added, but it
// DISCARDED the rollback's error. When the rollback delete also fails, the node
// publishes BACKUP while still holding a VIP, and nothing surfaces or sweeps it.
// Written before the fix; the acceptance and permanence cells are RED at base.

const (
	vip9509One = "10.0.61.1/24"
	vip9509Two = "10.0.61.2/24"
)

// fakeKernel9509 is the interface's address set behind the netlink seams. Adding
// vip9509Two fails. Deleting an absent address returns EADDRNOTAVAIL, as the
// kernel does, which removeVIPsLocked treats as benign.
type fakeKernel9509 struct {
	mu       sync.Mutex
	present  map[string]bool
	delFail  atomic.Bool
	addFail  atomic.Bool
	delCalls atomic.Int32
}

func (k *fakeKernel9509) has(vip string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.present[vip]
}

func newRollbackInstance9509(t *testing.T, name string, k *fakeKernel9509) (*vrrpInstance, chan VRRPEvent) {
	t.Helper()
	eventCh := make(chan VRRPEvent, 16)
	vi := newInstance(Instance{
		Interface:         name,
		GroupID:           1,
		Priority:          100,
		Family:            "inet",
		AdvertiseInterval: 1000,
		VirtualAddresses:  []string{vip9509One, vip9509Two},
	}, &net.Interface{Name: name}, eventCh, nil)
	vi.setState(StateBackup)
	vi.suppressGARP.Store(true)
	k.present = map[string]bool{}
	vi.linkByNameFn = func(n string) (netlink.Link, error) { return fiveZeroEightTwoLink(n), nil }
	vi.addrAddFn = func(_ netlink.Link, a *netlink.Addr) error {
		k.mu.Lock()
		defer k.mu.Unlock()
		if a.IPNet.String() == vip9509Two && k.addFail.Load() {
			return errors.New("injected netlink AddrAdd failure")
		}
		k.present[a.IPNet.String()] = true
		return nil
	}
	vi.addrDelFn = func(_ netlink.Link, a *netlink.Addr) error {
		k.delCalls.Add(1)
		k.mu.Lock()
		defer k.mu.Unlock()
		if !k.present[a.IPNet.String()] {
			return unix.EADDRNOTAVAIL
		}
		if k.delFail.Load() {
			return errors.New("injected netlink AddrDel failure")
		}
		delete(k.present, a.IPNet.String())
		return nil
	}
	t.Cleanup(func() {
		select {
		case <-vi.stopCh:
		default:
			close(vi.stopCh)
		}
	})
	return vi, eventCh
}

func sawBackup9509(eventCh chan VRRPEvent) bool {
	for {
		select {
		case ev := <-eventCh:
			if ev.State == StateBackup {
				return true
			}
		default:
			return false
		}
	}
}

// failPromotion9509 runs the compound fault: VIP 1 adds, VIP 2 fails, and the
// rollback delete of VIP 1 fails. It asserts the node's resulting state as FIXTURES.
func failPromotion9509(t *testing.T, vi *vrrpInstance, eventCh chan VRRPEvent, k *fakeKernel9509) {
	t.Helper()
	k.addFail.Store(true)
	k.delFail.Store(true)
	if vi.becomeMaster() {
		t.Fatal("FIXTURE: becomeMaster must refuse ownership when VIP 2 fails to actuate")
	}
	if got := vi.getState(); got != StateBackup {
		t.Fatalf("FIXTURE: state = %v, want StateBackup after the failed promotion", got)
	}
	if !sawBackup9509(eventCh) {
		t.Fatal("FIXTURE: the failed promotion must publish BACKUP")
	}
	if !k.has(vip9509One) {
		t.Fatal("FIXTURE: the failing rollback must leave VIP 1 on the interface; otherwise this cell has no stranded VIP to observe")
	}
}

// ACCEPTANCE: the stranded VIP is surfaced and then reconciled away.
func TestBecomeMasterRollbackFailureIsSurfacedAndReconciled_9509(t *testing.T) {
	k := &fakeKernel9509{}
	vi, eventCh := newRollbackInstance9509(t, "xpf-9509-a0", k)
	vi.vipReconcileBackoff = 5 * time.Millisecond
	failPromotion9509(t, vi, eventCh, k)

	if got := vi.vipRemoveFailures.Load(); got != 1 {
		t.Fatalf("#9509: becomeMaster discarded its rollback failure: vipRemoveFailures = %d, want 1. "+
			"The node published BACKUP while still holding %s", got, vip9509One)
	}
	if !vi.vipDiverged.Load() {
		t.Fatal("#9509: vipDiverged must be set when the rollback delete leaves a VIP on a BACKUP node")
	}

	k.delFail.Store(false) // the transient netlink fault clears
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && (k.has(vip9509One) || vi.vipDiverged.Load()) {
		time.Sleep(5 * time.Millisecond)
	}
	if k.has(vip9509One) {
		t.Fatalf("#9509: no reconcile removed the stranded %s from the BACKUP node", vip9509One)
	}
	if vi.vipDiverged.Load() {
		t.Fatal("#9509: the reconcile removed the VIP but left vipDiverged set")
	}
}

// PERMANENCE, measured rather than argued: once the promotion has failed, nothing
// ever attempts the delete again, even after the fault clears.
func TestStrandedVIPIsRetriedAfterAFailedPromotion_9509(t *testing.T) {
	k := &fakeKernel9509{}
	vi, eventCh := newRollbackInstance9509(t, "xpf-9509-b0", k)
	vi.vipReconcileBackoff = 5 * time.Millisecond
	failPromotion9509(t, vi, eventCh, k)
	callsAfterRollback := k.delCalls.Load()
	k.delFail.Store(false)
	time.Sleep(time.Duration(vipRemoveReconcileMax+2) * 5 * time.Millisecond * 4)
	if k.delCalls.Load() == callsAfterRollback {
		t.Fatalf("#9509: after the failed promotion no delete was ever attempted again (%d calls). "+
			"%s stays on the BACKUP node for the life of the process", callsAfterRollback, vip9509One)
	}
}

// CONTROL: a clean rollback removes VIP 1 at once and flags nothing.
func TestBecomeMasterCleanRollbackFlagsNothing_9509(t *testing.T) {
	k := &fakeKernel9509{}
	vi, eventCh := newRollbackInstance9509(t, "xpf-9509-c0", k)
	k.addFail.Store(true)
	if vi.becomeMaster() {
		t.Fatal("FIXTURE: becomeMaster must refuse ownership when VIP 2 fails")
	}
	if !sawBackup9509(eventCh) {
		t.Fatal("FIXTURE: the failed promotion must publish BACKUP")
	}
	if k.has(vip9509One) {
		t.Fatal("a clean rollback must remove VIP 1 synchronously")
	}
	if n := vi.vipRemoveFailures.Load(); n != 0 || vi.vipDiverged.Load() {
		t.Fatalf("a clean rollback must flag nothing: vipRemoveFailures=%d vipDiverged=%v", n, vi.vipDiverged.Load())
	}
}

// GUARD: a re-promotion during the retry backoff must keep its VIPs. The reconcile
// scheduled for the failed tenure must not delete a later tenure's addresses.
func TestRepromotionDuringReconcileKeepsItsVIPs_9509(t *testing.T) {
	k := &fakeKernel9509{}
	vi, eventCh := newRollbackInstance9509(t, "xpf-9509-d0", k)
	vi.vipReconcileBackoff = 40 * time.Millisecond
	failPromotion9509(t, vi, eventCh, k)

	k.addFail.Store(false)
	k.delFail.Store(false)
	if !vi.becomeMaster() {
		t.Fatal("FIXTURE: the re-promotion must succeed once both VIPs actuate")
	}
	callsAtRepromotion := k.delCalls.Load()
	time.Sleep(time.Duration(vipRemoveReconcileMax+2) * 40 * time.Millisecond)
	if !k.has(vip9509One) || !k.has(vip9509Two) {
		t.Fatalf("#9509: a reconcile scheduled for the failed tenure deleted the re-promoted MASTER's VIPs "+
			"(one=%v two=%v)", k.has(vip9509One), k.has(vip9509Two))
	}
	if got := k.delCalls.Load(); got != callsAtRepromotion {
		t.Fatalf("#9509: %d delete(s) ran after the re-promotion; the stale reconcile was not fenced",
			got-callsAtRepromotion)
	}
}

// ADJUDICATION of the second discard, in reconcileVIP's superseded arm. The only
// transition that can supersede a reconcile holding vipMu is becomeBackup, whose
// setState bumps ownerGen without vipMu. Every state write goes through setState,
// and becomeMaster's own state changes cannot interleave. becomeBackup then blocks
// on vipMu behind the rollback, removes ALL configured VIPs and surfaces that
// result. Driven with a real becomeBackup racing a real reconcileVIP, and every
// delete failing: the stranded VIPs must be surfaced and later reconciled. GREEN at
// base means that site needs no surfacing call of its own.
func TestSupersededReconcileRollbackIsCoveredByBecomeBackup_9509(t *testing.T) {
	k := &fakeKernel9509{}
	vi, _ := newRollbackInstance9509(t, "xpf-9509-e0", k)
	vi.vipReconcileBackoff = 5 * time.Millisecond
	vi.setState(StateMaster)
	k.delFail.Store(true)

	mdt := time.NewTimer(time.Hour)
	defer mdt.Stop()
	adv := time.NewTimer(time.Hour)
	defer adv.Stop()

	var demoted sync.WaitGroup
	var once sync.Once
	baseAdd := vi.addrAddFn
	vi.addrAddFn = func(l netlink.Link, a *netlink.Addr) error {
		err := baseAdd(l, a)
		once.Do(func() {
			demoted.Add(1)
			go func() { defer demoted.Done(); vi.becomeBackup(mdt, adv) }()
			deadline := time.Now().Add(time.Second)
			for vi.getState() != StateBackup && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
		})
		return err
	}
	vi.reconcileVIP()
	demoted.Wait()

	if got := vi.getState(); got != StateBackup {
		t.Fatalf("FIXTURE: the racing becomeBackup must leave the node BACKUP, got %v", got)
	}
	if !k.has(vip9509One) || !k.has(vip9509Two) {
		t.Fatal("FIXTURE: with every delete failing, the re-added VIPs must still be present")
	}
	if vi.vipRemoveFailures.Load() < 1 || !vi.vipDiverged.Load() {
		t.Fatalf("the superseded reconcile's failed rollback left VIPs on a BACKUP node UNSURFACED "+
			"(vipRemoveFailures=%d vipDiverged=%v): the second site needs its own call",
			vi.vipRemoveFailures.Load(), vi.vipDiverged.Load())
	}
	k.delFail.Store(false)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && (k.has(vip9509One) || k.has(vip9509Two)) {
		time.Sleep(5 * time.Millisecond)
	}
	if k.has(vip9509One) || k.has(vip9509Two) {
		t.Fatal("the surfaced divergence was never reconciled away")
	}
}

// A clean rollback clears a divergence flag left by an earlier failure whose
// reconcile this promotion attempt superseded. The rollback removed every present
// VIP (an existing address adds as EEXIST, counts as applied and is rolled back),
// so a flag left TRUE would cry wolf for the life of the process.
func TestCleanRollbackClearsAStaleDivergenceFlag_9509(t *testing.T) {
	k := &fakeKernel9509{}
	vi, eventCh := newRollbackInstance9509(t, "xpf-9509-f0", k)
	vi.vipDiverged.Store(true) // an earlier divergence whose reconcile was superseded
	k.addFail.Store(true)
	if vi.becomeMaster() {
		t.Fatal("FIXTURE: becomeMaster must refuse ownership when VIP 2 fails")
	}
	if !sawBackup9509(eventCh) || k.has(vip9509One) {
		t.Fatal("FIXTURE: the clean rollback must publish BACKUP and remove VIP 1")
	}
	if vi.vipDiverged.Load() {
		t.Fatal("#9509: a clean rollback that left no VIP on the BACKUP node must clear vipDiverged")
	}
}
