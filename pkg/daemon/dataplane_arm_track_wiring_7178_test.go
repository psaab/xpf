package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #7178/#9842: the dataplane-ready transitions must actually DRIVE the
// redundancy-group weight, not merely have a helper that could.
//
// WHY THIS IS SEPARATE FROM THE ARITHMETIC TESTS. pkg/cluster pins the cost's
// value — large enough to lose to a ready peer, small enough to leave the node
// eligible. Those pass whether or not anything ever applies it. Deleting the
// applyDataplaneReadyTrack call from the re-evaluation path leaves every one
// of these tests green, because they exercise rgWeightFromDebt directly. The
// defect being fixed lives in the WIRING — a node that failed to become ready
// went on holding RG mastership — so the wiring is what this file asserts.

func armTrackManager(t *testing.T) *cluster.Manager {
	t.Helper()
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{ID: 1, NodePriorities: map[int]int{0: 200}}},
	})
	return m
}

func armTrackDaemon(t *testing.T, m *cluster.Manager, attached int) (*Daemon, *gateRuntime9725) {
	t.Helper()
	rt := &gateRuntime9725{RuntimeDataPlane: &armedRecorderDP{}}
	rt.setCount(attached, false)
	d := &Daemon{cluster: m}
	d.setDataplane(rt)
	return d, rt
}

func rgWeight(t *testing.T, m *cluster.Manager, id int) int {
	t.Helper()
	for _, rg := range m.GroupStates() {
		if rg.GroupID == id {
			return rg.Weight
		}
	}
	t.Fatalf("redundancy group %d not found", id)
	return -1
}

func TestArmFailureDemotesRedundancyGroupWeight7178(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")

	m := armTrackManager(t)
	d, _ := armTrackDaemon(t, m, 1)
	d.markDataplaneArmed("test")

	// Precondition: an armed dataplane with a kernel-proven XDP link carries
	// the full weight. Without this the assertion below could pass on a group
	// that was never ready.
	full := rgWeight(t, m, 1)
	if full != 255 {
		t.Fatalf("precondition: attached dataplane weight = %d, want 255", full)
	}

	d.markDataplaneArmFailed("test", "test", errors.New("boom"))

	got := rgWeight(t, m, 1)
	if got >= full {
		t.Fatalf("after an arm FAILURE the RG weight is %d, unchanged from %d. The node "+
			"still outbids a peer that can forward, so it keeps taking the RETH VIPs and "+
			"attracting traffic it drops (#7178)", got, full)
	}
	if got == 0 {
		t.Errorf("the arm failure drove the weight to 0, which also demotes a STANDALONE " +
			"node — nothing takes its VIPs and the operator may lose the address they reach " +
			"it on. The cost is sub-total on purpose")
	}
}

// An arm-success signal alone is not enough: until the kernel proves an XDP
// link, the node remains at the losing floor (#9842).
func TestArmedButUnattachedKeepsRedundancyGroupWeightLow9842(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")

	m := armTrackManager(t)
	d, _ := armTrackDaemon(t, m, 0)
	d.markDataplaneArmed("test")

	if got := rgWeight(t, m, 1); got != 1 {
		t.Fatalf("armed-but-unattached RG weight = %d, want 1; Start must not restore "+
			"full weight before the first XDP attach (#9842)", got)
	}
}

// The gate must FOLLOW the full ready-to-serve predicate: a successful arm
// with an attached XDP link clears the debt, or a recovered node stays
// demoted forever and can never take back mastership.
func TestAttachedDataplaneRestoresFullRedundancyGroupWeight9842(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")

	m := armTrackManager(t)
	d, rt := armTrackDaemon(t, m, 0)
	d.markDataplaneArmed("test")
	if got := rgWeight(t, m, 1); got != 1 {
		t.Fatalf("precondition: armed-but-unattached RG weight = %d, want 1", got)
	}

	rt.setCount(1, false)
	d.reassertTransitGate("test-attach")

	if got := rgWeight(t, m, 1); got != 255 {
		t.Errorf("after the first proven attach the RG weight is %d, want full 255; "+
			"the node would remain permanently demoted after recovery", got)
	}
}

// A new RG created while the node is unattached starts at the same losing
// floor and is raised by the next ready re-evaluation.
func TestNewRGWhileUnattachedStartsLowThenRaisesOnAttach9842(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")

	m := armTrackManager(t)
	d, rt := armTrackDaemon(t, m, 0)
	d.markDataplaneArmed("test")
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 1, NodePriorities: map[int]int{0: 200}},
			{ID: 2, NodePriorities: map[int]int{0: 200}},
		},
	})

	if got := rgWeight(t, m, 2); got != 1 {
		t.Fatalf("new RG while unattached has weight %d, want losing floor 1", got)
	}
	rt.setCount(1, false)
	d.reassertTransitGate("test-attach")
	if got := rgWeight(t, m, 2); got != 255 {
		t.Fatalf("new RG after first attach has weight %d, want full 255", got)
	}
}

// The periodic kernel-truth census must refresh the RG bid too, including
// changes with no observer wake (the same completeness path as transit).
func TestDataplaneTickRefreshesRedundancyGroupWeight9842(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")
	withBarrierRecorder(t)
	oldInterval := transitGateTickInterval
	transitGateTickInterval = 5 * time.Millisecond
	t.Cleanup(func() { transitGateTickInterval = oldInterval })

	m := armTrackManager(t)
	d, rt := armTrackDaemon(t, m, 0)
	d.markDataplaneArmed("test")
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	d.startTransitGateLoop(ctx, &wg)
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	waitWeight := func(want int) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if got := rgWeight(t, m, 1); got == want {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("periodic RG weight = %d, want %d", rgWeight(t, m, 1), want)
	}

	rt.setCount(1, false)
	waitWeight(255)
	rt.setCount(0, false)
	waitWeight(1)
}

// A daemon with no cluster configured must not panic. This is the standalone
// non-cluster box, which is the common case.
func TestArmTrackIsSafeWithoutACluster7178(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")
	d := &Daemon{} // nil cluster
	d.markDataplaneArmFailed("test", "test", errors.New("boom"))
	d.markDataplaneArmed("test")
}
