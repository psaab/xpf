package daemon

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #6177 item 1 — the remote-failover applied-ack must be fenced on the RETH
// VIPs actually LEAVING the interface, not on the resignation having been
// signalled.
//
// #5640 withheld the ack until the demotion was "actuated", but on the
// RETH-VRRP path ResignRG only writes priority-0 synchronously and then does a
// non-blocking send on resignCh: the advert burst and the becomeBackup VIP
// removal run afterwards, on the VRRP instance goroutine. The peer therefore
// received "applied" and promoted — adding VIPs, sending GARP — while this node
// still owned the virtual address. Sub-millisecond, but a genuine two-owner
// window, and the reason the issue carries the security label.
//
// Direct-VIP mode (`private-rg-election` / `no-reth-vrrp`) never had the gap and
// is covered unchanged by the #6371 tests, which run on that path.

// fakeVIPRelease is a caller-driven vipReleaseBarrier standing in for
// *vrrp.ResignBarrier, so this test drives the ORDERING without real VRRP
// instances or live netlink. pkg/vrrp owns the "the barrier tracks the real VIP
// removal" half (resign_barrier_6177_test.go); this file owns the "the daemon
// waits for it" half.
type fakeVIPRelease struct {
	done chan struct{}
	mu   sync.Mutex
	err  error
	once sync.Once
}

func newFakeVIPRelease() *fakeVIPRelease {
	return &fakeVIPRelease{done: make(chan struct{})}
}

func (f *fakeVIPRelease) Done() <-chan struct{} { return f.done }

func (f *fakeVIPRelease) Err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *fakeVIPRelease) release(err error) {
	f.once.Do(func() {
		f.mu.Lock()
		f.err = err
		f.mu.Unlock()
		close(f.done)
	})
}

// rethFenceClusterSet is fenceStartupClusterSet on the RETH-VRRP path:
// `no-private-rg-election` turns off the production default so isNoRethVRRP()
// is FALSE and handleClusterEvent takes the ResignRG branch under test.
const rethFenceClusterSet = fenceStartupClusterSet +
	"set chassis cluster no-private-rg-election\n"

// newRethFenceDaemon is newActuationDaemon on the RETH-VRRP path, with the
// resignation seam pointed at the caller's barrier.
func newRethFenceDaemon(t *testing.T, ha *actuationHA, barrier vipReleaseBarrier) *Daemon {
	t.Helper()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, NodePriorities: map[int]int{0: 200}},
			{ID: 1, NodePriorities: map[int]int{0: 200}},
		},
	})
	d := &Daemon{
		store:                      fenceTestStore(t, rethFenceClusterSet),
		cluster:                    cm,
		vrrpMgr:                    vrrp.NewManager(),
		rgStates:                   make(map[int]*rgStateMachine),
		failoverActuations:         failoverActuationRegistry{timeout: 2 * time.Second},
		rethVIPReleaseTimeout:      time.Second,
		userspaceDemotionPrepUntil: make(map[int]time.Time),
	}
	d.resignRethRGFn = func(int) vipReleaseBarrier { return barrier }
	d.setDataplane(&actuationDP{ha: ha})
	// Precondition: this daemon really is on the RETH-VRRP path. Without it
	// every assertion below would silently be testing the direct-VIP branch.
	if d.isNoRethVRRP() {
		t.Fatal("setup: isNoRethVRRP() is true — the RETH ResignRG branch is not reachable")
	}
	return d
}

// TestRethDemotionFenceWaitsForVIPRelease_6177 is the fail-on-revert guard. The
// applied-ack waiter must still be BLOCKED after handleClusterEvent has run the
// whole demotion — priority-0 written, rg_active cleared — and must release only
// once the VIP removal reports.
//
// RED on revert: restore the pre-#6177 `d.signalFailoverActuated(ev.GroupID)`
// as the unconditional else-branch (or drop the `case rethResign != nil` arm)
// and waitFailoverActuated returns nil at the first assertion, while the VIPs
// are demonstrably still on the interface.
func TestRethDemotionFenceWaitsForVIPRelease_6177(t *testing.T) {
	ha := &actuationHA{}
	barrier := newFakeVIPRelease()
	d := newRethFenceDaemon(t, ha, barrier)
	primeRG1Primary(t, d)

	d.armFailoverActuation(1, actuationReqID)

	waited := make(chan error, 1)
	go func() { waited <- d.waitFailoverActuated(1, actuationReqID) }()

	demoteRG1(t, d)

	// Positive control: the demotion really reached the rg_active clear, so a
	// still-blocked waiter is about the VIP fence and not about a demotion
	// that never ran.
	if got := ha.writeCount(); got != 1 {
		t.Fatalf("SetRGActive call count = %d, want 1 (the demotion must attempt the clear)", got)
	}
	if active, ok := ha.lastWrite(); !ok || active {
		t.Fatalf("SetRGActive wrote active=%v, want false", active)
	}

	// THE assertion: the VIPs have not been released, so the peer must not
	// have been told the transfer applied.
	select {
	case err := <-waited:
		t.Fatalf("applied-ack released with err=%v while the RETH virtual addresses were "+
			"still on the interface — the peer would promote into a two-owner window (#6177 item 1)", err)
	case <-time.After(100 * time.Millisecond):
	}

	barrier.release(nil)

	select {
	case err := <-waited:
		if err != nil {
			t.Fatalf("applied-ack verdict = %v, want nil after a clean VIP release", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("applied-ack never released after the VIP release reported — a clean failover " +
			"must not be downgraded to a hold")
	}
}

// TestRethDemotionFenceFailsOnVIPReleaseError_6177 pins the verdict direction
// when the release itself failed: a stale VIP is still answering ARP, so the
// ack must be downgraded and the peer must hold.
func TestRethDemotionFenceFailsOnVIPReleaseError_6177(t *testing.T) {
	injected := errors.New("netlink AddrDel refused")
	ha := &actuationHA{}
	barrier := newFakeVIPRelease()
	d := newRethFenceDaemon(t, ha, barrier)
	primeRG1Primary(t, d)

	d.armFailoverActuation(1, actuationReqID)
	barrier.release(injected)
	demoteRG1(t, d)

	err := d.waitFailoverActuated(1, actuationReqID)
	if err == nil {
		t.Fatal("applied-ack released after the RETH VIP removal FAILED (#6177 item 1)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("fence verdict = %v, want it to carry the VIP-removal failure", err)
	}
}

// TestRethDemotionFenceFailsWhenVIPReleaseStalls_6177 covers the wedged /
// retired run-loop case: no release signal can arrive. The bounded wait must
// produce a NAMED failure — so the operator sees which fence did not close —
// rather than hanging the peer's request or, worse, reporting success.
func TestRethDemotionFenceFailsWhenVIPReleaseStalls_6177(t *testing.T) {
	ha := &actuationHA{}
	barrier := newFakeVIPRelease() // never released
	d := newRethFenceDaemon(t, ha, barrier)
	d.rethVIPReleaseTimeout = 50 * time.Millisecond
	primeRG1Primary(t, d)

	d.armFailoverActuation(1, actuationReqID)
	demoteRG1(t, d)

	err := d.waitFailoverActuated(1, actuationReqID)
	if err == nil {
		t.Fatal("applied-ack released although the RETH VIP release never reported (#6177 item 1)")
	}
	if !strings.Contains(err.Error(), "virtual addresses") {
		t.Fatalf("fence verdict = %q, want it to name the un-released virtual addresses", err)
	}
	// The verdict must come from the VIP sub-wait, not from the outer
	// registry timeout — the latter is 2s here and would delay the peer.
	if strings.Contains(err.Error(), "timed out waiting for local fence actuation") {
		t.Fatalf("fence verdict = %q, want the VIP release timeout not the outer barrier timeout", err)
	}
}

// TestRethDemotionFenceNoVRRPInstancesAcksPromptly_6177 is the negative
// control: an RG with no RETH VIP tenure to release must not be made to wait.
// It drives the REAL vrrp.Manager (no seam), so it also pins that ResignRG's
// production return value is usable as a fence — a nil return there would make
// every RETH demotion take the immediate branch and silently reopen the window.
func TestRethDemotionFenceNoVRRPInstancesAcksPromptly_6177(t *testing.T) {
	ha := &actuationHA{}
	d := newRethFenceDaemon(t, ha, nil)
	d.resignRethRGFn = nil // real vrrp.Manager, zero instances
	primeRG1Primary(t, d)

	d.armFailoverActuation(1, actuationReqID)
	demoteRG1(t, d)

	start := time.Now()
	if err := d.waitFailoverActuated(1, actuationReqID); err != nil {
		t.Fatalf("waitFailoverActuated = %v, want nil for an RG with no RETH VIP tenure", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("applied-ack took %s for an RG with nothing to release — the fence must not "+
			"turn a clean failover into a stall", elapsed)
	}
}
