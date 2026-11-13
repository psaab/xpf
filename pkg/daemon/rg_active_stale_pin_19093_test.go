package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #19093 daemon-side cells. The defect: a restarted xpfd's new helper was
// seeded Active=true from the rg_active pin a SIGKILLed predecessor left. The
// barrier for that lives where the pin is imported (pkg/dataplane/userspace,
// rg_active_inherited_pin_19093_test.go). These cells pin the daemon half of
// the hitless argument instead:
//
//	(D) during a fresh process's start, the daemon emits no rg_active=false for
//	    an RG before that RG's first true write.
//
// With the import barrier (the helper's first seed carries only this process's
// writes), (D) is what makes a restarted owner's helper see at most one edge,
// false->true, never true->false->true. (D) holds at master. The cells exist
// so that a fix which re-drives every RG on its first reconcile pass (the
// "applied starts UNKNOWN" alternative) cannot land: it writes false first.
//
// The RETH-VRRP held start is already pinned by
// TestSyncHoldReleaseOnlyReconcileRunsServices16692 and
// TestSyncHoldReleaseOnlyReconcileAlreadyMaster17821 (0 writes while held,
// exactly one true on release). These cover the private-RG default.

var stalePinClusterLines = []string{
	"set system dataplane-type userspace",
	"set chassis cluster cluster-id 1",
	"set chassis cluster control-interface em0",
	"set chassis cluster peer-address 10.99.0.2",
	"set chassis cluster node 0",
	"set chassis cluster reth-count 2",
	"set chassis cluster authentication-key test-cluster-psk-19093",
	"set chassis cluster redundancy-group 0 node 0 priority 200",
	"set chassis cluster redundancy-group 1 node 0 priority 200",
	"set chassis cluster redundancy-group 2 node 0 priority 200",
	"set interfaces reth1 redundant-ether-options redundancy-group 1",
	"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
	"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	"set interfaces reth2 redundant-ether-options redundancy-group 2",
	"set interfaces reth2 unit 0 family inet address 10.0.2.1/24",
	"set interfaces ge-0/0/1 gigether-options redundant-parent reth2",
}

// freshClusterDaemon19093 is a freshly started process: every RG state machine
// is new, the cluster has elected nothing (a complete control link makes the
// private-RG election wait for the peer, #16746, so every RG is secondary),
// and rg_active writes are recorded.
func freshClusterDaemon19093(t *testing.T) (*Daemon, *cluster.Manager, *rearmRecorderHA, *[]int) {
	t.Helper()
	store := testStoreWithSetConfig(t, stalePinClusterLines)
	cc := store.ActiveConfig().Chassis.Cluster
	if cc == nil {
		t.Fatal("fixture: the cluster config did not commit")
	}
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cc)
	rec := &rearmRecorderHA{}
	preps := &[]int{}
	d := &Daemon{
		rgStates: make(map[int]*rgStateMachine),
		cluster:  cm,
		store:    store,
		vrrpMgr:  vrrp.NewManager(),
	}
	d.tryPrepareDemotionFn = func(rgID int) { *preps = append(*preps, rgID) }
	d.setDataplane(&rearmRecorderDP{Manager: dataplane.New(), ha: rec})
	if !d.isNoRethVRRP() {
		t.Fatal("fixture: the default must be private-RG election (no RETH VRRP)")
	}
	for _, rg := range []int{0, 1, 2} {
		if cm.IsLocalPrimary(rg) {
			t.Fatalf("fixture: RG%d is primary on a fresh start; the cell needs it secondary", rg)
		}
	}
	return d, cm, rec, preps
}

// D1: a fresh process whose RGs are all secondary must cost nothing on its
// first reconcile pass — no rg_active write, no userspace demotion prep (a
// control-socket round trip bounded at 5 s plus a 10 s prep lease, each).
//
// GREEN at master. RED for a fix that re-drives every RG at birth.
func TestFreshStartSecondaryRGsCostNothing19093(t *testing.T) {
	d, _, rec, preps := freshClusterDaemon19093(t)

	d.reconcileRGState()

	if w := rec.take(); len(w) != 0 {
		t.Errorf("a fresh start with every RG secondary issued rg_active writes %v on its "+
			"first reconcile pass; nothing this process published says otherwise, so each "+
			"is a redundant demotion", w)
	}
	if len(*preps) != 0 {
		t.Errorf("a fresh start ran the userspace demotion prep for RGs %v", *preps)
	}
}

// D2: the private-RG held start of a node that becomes the owner. While the
// no-RETH startup hold is up and the RG is secondary, no rg_active write; once
// the hold releases and the node is promoted, exactly one write, true, and no
// false ever precedes it.
//
// GREEN at master. RED for a fix that writes the first-pass desired (false)
// for every RG — that is the true->false->true a restarted owner's helper
// would see.
func TestFreshStartOwnerWritesNoFalseBeforeFirstTrue19093(t *testing.T) {
	d, cm, rec, _ := freshClusterDaemon19093(t)
	d.armNoRethSyncHold(time.Hour)
	t.Cleanup(func() { d.releaseNoRethSyncHold("test-cleanup") })

	d.reconcileRGState() // held, secondary
	d.reconcileRGState()

	d.releaseNoRethSyncHold("test")
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.reconcileRGState() // promoted
	d.reconcileRGState() // steady

	var rg1 []bool
	for _, w := range rec.take() {
		if w.rgID == 1 {
			rg1 = append(rg1, w.active)
		}
	}
	if len(rg1) == 0 || !rg1[len(rg1)-1] {
		t.Fatalf("fixture: RG1 was never written active after the node became its owner "+
			"(RG1 writes %v); the cell cannot judge an edge it never drove to", rg1)
	}
	if rg1[0] != true {
		t.Errorf("the daemon wrote rg_active=false for RG1 before its first true write "+
			"(RG1 writes %v): a restarted owner's helper would see true->false->true", rg1)
	}
	if len(rg1) != 1 {
		t.Errorf("RG1 written %d times across the start (%v), want exactly one true write", len(rg1), rg1)
	}
}
