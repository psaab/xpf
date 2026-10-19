package daemon

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #15276 (C10-01): a live (no-cycle) RETH virtual-MAC change must still
// announce. programRethMAC used to report only linkCycled, so a MAC that
// changed without a link cycle reached step 2.6b as "nothing happened":
// reconcileAfterRethLinkCycle was gated on needLinkCycleRecovery alone, and
// the 2s direct-VIP reconcile does not announce either because the VIPs are
// already present (directAddVIPs only counts non-EEXIST adds). Neighbours
// kept the old MAC until their own ARP/ND ageing re-resolved it, black-holing
// inbound traffic to that RETH's VIPs in the meantime.
//
// The fix reports "MAC changed" separately from "link cycled"
// (programRethMAC -> programRethMACWithWorkerJoin -> programRethMemberMAC),
// threads the changed RG IDs from step 2.6 into step 2.6b, and announces for
// exactly those RGs: scheduleDirectAnnounce in direct mode, a forced
// RG-scoped GARP via vrrpMgr.ReconcileVIPsForRG in VRRP mode — cycled or not.
//
// RED-on-revert: make the live-set success path report macChanged=false
// again (or drop the macChangedRGs arm of reconcileAfterRethLinkCycle) and
// TestC10LiveMACChangeNoAnnounce fails at "no announce".

func c10DirectDaemon(t *testing.T) (*Daemon, chan int) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key test-15276-psk",
		"chassis cluster no-reth-vrrp",
		"chassis cluster redundancy-group 1 node 0 priority 200",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("set %q: %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit direct-mode cluster config: %v", err)
	}
	state := newRGStateMachine()
	state.SetCluster(true)
	announces := make(chan int, 4)
	d := &Daemon{
		store:                  store,
		cluster:                ipmonCluster(&config.RedundancyGroup{ID: 1, NodePriorities: map[int]int{0: 200}, Preempt: true}),
		rgStates:               map[int]*rgStateMachine{1: state},
		directAnnounceSchedule: []time.Duration{0},
		directSendGARPsFn: func(rgID int) {
			announces <- rgID
		},
	}
	if !d.cluster.IsLocalPrimary(1) {
		t.Fatal("setup: local node must be RG1 primary, or the direct announce leg is unreachable")
	}
	if !d.isNoRethVRRP() {
		t.Fatal("setup: daemon must be in direct (no-reth-vrrp) mode")
	}
	return d, announces
}

func c10Cfg() *config.Config {
	return &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
			},
		},
	}
}

func drainAnnounces(ch chan int) []int {
	var out []int
	for {
		select {
		case rg := <-ch:
			out = append(out, rg)
		default:
			return out
		}
	}
}

// TestC10LiveMACChangeNoAnnounce is the #15276 acceptance test: a RETH member
// whose virtual MAC changes via the live set (no link cycle) must produce at
// least one announce for its owning RG. The cycled control and the
// no-MAC-change apply (no announce) are unchanged.
func TestC10LiveMACChangeNoAnnounce(t *testing.T) {
	oldMAC := net.HardwareAddr{0x02, 0xbf, 0x72, 0x01, 0x01, 0x00}
	newMAC := net.HardwareAddr{0x02, 0xbf, 0x72, 0x01, 0x02, 0x00}

	t.Run("live MAC change announces for the owning RG", func(t *testing.T) {
		d, announces := c10DirectDaemon(t)
		var events []string
		withRethOps(t, newRecordingRethOps(t, &events, oldMAC, false /* live set works */))

		commitErr, needRecovery, _, macChanged := d.programRethMemberMAC(
			"ge-0-0-1", newMAC, nil, false, false)
		if commitErr != nil {
			t.Fatalf("live MAC program must not fail the commit; got %v", commitErr)
		}
		if needRecovery {
			t.Fatal("a live MAC set must not arm link-cycle recovery: the link never cycled")
		}
		if !macChanged {
			t.Fatal("the live MAC set changed the member MAC but reported macChanged=false — " +
				"step 2.6b will send no announce and neighbours keep the old MAC (#15276)")
		}

		changed := map[int]bool{}
		if macChanged {
			changed[1] = true
		}
		d.reconcileAfterRethLinkCycle(c10Cfg(), needRecovery, changed)

		got := drainAnnounces(announces)
		if len(got) != 1 || got[0] != 1 {
			t.Fatalf("announces = %v, want exactly one announce for RG 1 after a live MAC change (#15276)", got)
		}
	})

	t.Run("no MAC change sends no announce", func(t *testing.T) {
		d, announces := c10DirectDaemon(t)
		var events []string
		withRethOps(t, newRecordingRethOps(t, &events, newMAC, false /* live set works */))

		// The member already carries the target MAC: programRethMAC no-ops.
		_, needRecovery, _, macChanged := d.programRethMemberMAC(
			"ge-0-0-1", newMAC, nil, false, false)
		if macChanged {
			t.Fatal("a MAC-match no-op must not report a MAC change")
		}
		changed := map[int]bool{}
		if macChanged {
			changed[1] = true
		}
		d.reconcileAfterRethLinkCycle(c10Cfg(), needRecovery, changed)

		if got := drainAnnounces(announces); len(got) != 0 {
			t.Fatalf("announces = %v, want none for an apply that changed no MAC", got)
		}
	})

	t.Run("cycled MAC change announces exactly once", func(t *testing.T) {
		d, announces := c10DirectDaemon(t)
		var events []string
		withRethOps(t, newRecordingRethOps(t, &events, oldMAC, true /* force the cycle */))

		_, needRecovery, _, macChanged := d.programRethMemberMAC(
			"ge-0-0-1", newMAC, nil, false, false)
		if !needRecovery {
			t.Fatal("the cycled control must arm link-cycle recovery, as before")
		}
		if !macChanged {
			t.Fatal("the cycled control changed the MAC and must report it")
		}
		changed := map[int]bool{}
		if macChanged {
			changed[1] = true
		}
		d.reconcileAfterRethLinkCycle(c10Cfg(), needRecovery, changed)

		got := drainAnnounces(announces)
		if len(got) != 1 || got[0] != 1 {
			t.Fatalf("announces = %v, want exactly one link-cycle-recovery announce for RG 1 "+
				"(the MAC-change arm must not double-announce a cycled member)", got)
		}
	})

	t.Run("live MAC change in VRRP mode sends no direct announce", func(t *testing.T) {
		store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		for _, line := range []string{
			"chassis cluster cluster-id 1",
			"chassis cluster node 0",
			"chassis cluster authentication-key test-15276-psk",
			"chassis cluster no-private-rg-election",
			"chassis cluster redundancy-group 1 node 0 priority 200",
		} {
			if err := store.SetFromInput(line); err != nil {
				t.Fatalf("set %q: %v", line, err)
			}
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("commit VRRP-mode cluster config: %v", err)
		}
		announces := make(chan int, 4)
		d := &Daemon{
			store:                  store,
			vrrpMgr:                vrrp.NewManager(),
			directAnnounceSchedule: []time.Duration{0},
			directSendGARPsFn: func(rgID int) {
				announces <- rgID
			},
		}
		if d.isNoRethVRRP() {
			t.Fatal("setup: daemon must be in VRRP mode for this control")
		}
		var events []string
		withRethOps(t, newRecordingRethOps(t, &events, oldMAC, false /* live set works */))
		_, needRecovery, _, macChanged := d.programRethMemberMAC(
			"ge-0-0-1", newMAC, nil, false, false)
		if !macChanged {
			t.Fatal("the live MAC set changed the member MAC but reported macChanged=false (#15276)")
		}
		// The VRRP leg announces through vrrpMgr.ReconcileVIPsForRG (bound in
		// pkg/vrrp by TestReconcileVIPsForRGAnnouncesOnlyThatRG_15276, since a
		// daemon-level Manager with no instances has nothing to observe). Here
		// the control pins only the mode routing: no direct announce may fire.
		d.reconcileAfterRethLinkCycle(c10Cfg(), needRecovery, map[int]bool{1: true})
		if got := drainAnnounces(announces); len(got) != 0 {
			t.Fatalf("announces = %v, want no direct announce in VRRP mode", got)
		}
	})
}
