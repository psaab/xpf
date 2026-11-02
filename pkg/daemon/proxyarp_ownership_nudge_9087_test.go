// #9087, the second half: the reconcile was not driven by an RG OWNERSHIP
// CHANGE, only by a commit and a 30s ticker — and a failover is not a commit.
//
// So for up to proxyARPReassertInterval after a transition the new owner had
// not installed the proxy entry and the old owner had not swept it. Measured on
// the loss cluster right after a crash-failover plus manual failback:
// `fw0=0 fw1=1` — the only answerer being the node that no longer owns the
// address, which mis-steers pool-mode NAT return traffic for the window.
//
// These bind the WIRING, because the nudge helper on its own is not the fix:
// severing either call site restores the window while every unit test of the
// reconcile keeps passing. That is the shape that hid the first half of this
// issue for months.

package daemon

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

func drainNudge9087(t *testing.T, d *Daemon) bool {
	t.Helper()
	select {
	case <-d.proxyARPNudgeCh:
		return true
	case <-time.After(time.Second):
		return false
	}
}

// THE PROMOTE EDGE. applyRethServicesForRG is the per-RG VRRP MASTER
// transition; taking an RG means this node must start answering for its pool
// addresses.
func TestMasterEdgeNudgesProxyARP9087(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-9087",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	})
	d := &Daemon{store: store, proxyARPNudgeCh: make(chan struct{}, 1)}
	d.applyRethServicesForRG(1)
	if !drainNudge9087(t, d) {
		t.Fatal("#9087: taking an RG did not nudge the proxy-ARP reconcile, so the " +
			"new owner stays silent until the 30s ticker fires. For that window the " +
			"only node answering for the pool address is the one that no longer " +
			"owns it.")
	}
}

// THE DEMOTE EDGE, which is the half that leaves a WRONG answerer on the wire
// rather than merely a missing one.
func TestBackupEdgeNudgesProxyARP9087(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-9087",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	})
	d := &Daemon{store: store, proxyARPNudgeCh: make(chan struct{}, 1)}
	d.clearRethServicesForRG(1)
	if !drainNudge9087(t, d) {
		t.Fatal("#9087: losing an RG did not nudge the proxy-ARP reconcile, so the " +
			"demoted node keeps answering proxy-ARP for the pool address until the " +
			"30s ticker fires — the upstream sees one IP at two RETH virtual MACs")
	}
}

// The demote nudge must survive the early returns, because those are about
// RA/Kea state and say nothing about whether a sweep is owed. A node with no
// store still has stale kernel entries.
func TestBackupEdgeNudgesEvenWithNoConfig9087(t *testing.T) {
	d := &Daemon{proxyARPNudgeCh: make(chan struct{}, 1)} // no store at all
	d.clearRethServicesForRG(1)
	if !drainNudge9087(t, d) {
		t.Fatal("#9087: the demote nudge must precede the store/config early " +
			"returns — a node whose config is unreadable still holds the stale " +
			"kernel entry that has to be swept")
	}
}

// The nudge coalesces and never blocks: it runs on the VRRP event loop, where a
// blocking send would stall every later event behind a reconcile that itself
// waits on applySem.
func TestProxyARPNudgeCoalescesAndNeverBlocks9087(t *testing.T) {
	d := &Daemon{proxyARPNudgeCh: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			d.nudgeProxyARPReassert()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("nudgeProxyARPReassert blocked; on the VRRP event loop that stalls " +
			"every subsequent transition")
	}
	if !drainNudge9087(t, d) {
		t.Fatal("100 nudges produced no wakeup at all")
	}
	select {
	case <-d.proxyARPNudgeCh:
		t.Fatal("the nudge must COALESCE to depth 1, not queue a wakeup per call")
	default:
	}
	// A nil channel must be tolerated — a Daemon built without the loop.
	(&Daemon{}).nudgeProxyARPReassert()
}

// THE LAST LINK: nudge -> reconcile. Measured — with only the cells above,
// deleting the loop's `case <-d.proxyARPNudgeCh: d.reassertProxyARPOnce(ctx)`
// body SURVIVED: every cell checked that the channel received a wakeup and
// nothing checked that the wakeup did anything. The nudge would have been a
// well-tested no-op.
func TestNudgeDrivesAReconcile9087(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	})
	prevFn, prevInterval := proxyARPReconcileFn, proxyARPReassertInterval
	// Long enough that a tick cannot be mistaken for the nudge — otherwise the
	// cell would pass on the ticker alone and prove nothing about the nudge.
	proxyARPReassertInterval = time.Hour
	reconciled := make(chan struct{}, 8)
	proxyARPReconcileFn = func(*Daemon, *config.Config) { reconciled <- struct{}{} }
	t.Cleanup(func() { proxyARPReconcileFn, proxyARPReassertInterval = prevFn, prevInterval })

	d := &Daemon{
		store:           store,
		applySem:        semaphore.NewWeighted(1),
		proxyARPNudgeCh: make(chan struct{}, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.proxyARPReassertLoop(ctx)

	d.nudgeProxyARPReassert()
	select {
	case <-reconciled:
	case <-time.After(3 * time.Second):
		t.Fatal("#9087: a nudge did not drive a reconcile. The wakeup arrives and " +
			"nothing runs, so the ownership edge is a no-op and the failover window " +
			"is still the full re-assert interval.")
	}

	// CONTROL: no spurious reconcile without a nudge, or the assertion above
	// cannot distinguish "the nudge worked" from "the loop reconciles freely".
	select {
	case <-reconciled:
		t.Fatal("the loop reconciled without a nudge and with the ticker set to an " +
			"hour; the cell above would pass for the wrong reason")
	case <-time.After(300 * time.Millisecond):
	}
}
