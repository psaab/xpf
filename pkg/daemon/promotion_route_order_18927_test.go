package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
	"golang.org/x/sync/semaphore"
)

// promotionOrderLog18927 records the effects whose order protects a newly
// active RG from forwarding through a stale helper FIB.
type promotionOrderLog18927 struct {
	mu      sync.Mutex
	events  []string
	changed chan struct{}
}

func (l *promotionOrderLog18927) add(event string) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
	select {
	case l.changed <- struct{}{}:
	default:
	}
}

func (l *promotionOrderLog18927) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type promotionOrderHA18927 struct{ log *promotionOrderLog18927 }

func (h *promotionOrderHA18927) SetRGActive(_ context.Context, rgID int, active bool) error {
	h.log.add(fmt.Sprintf("rg_active[%d]=%t", rgID, active))
	return nil
}

func (h *promotionOrderHA18927) SetHAWatchdog(context.Context, int, uint64) error { return nil }
func (h *promotionOrderHA18927) SyncFabricState(context.Context) error            { return nil }

type promotionOrderDP18927 struct {
	dataplane.RuntimeDataPlane
	mu         sync.RWMutex
	log        *promotionOrderLog18927
	ha         *promotionOrderHA18927
	publishErr error
	bumpErr    error
}

func (d *promotionOrderDP18927) HA() dataplane.HAController { return d.ha }
func (d *promotionOrderDP18927) Mode() dpuserspace.DataplaneMode {
	return dpuserspace.ModeUserspaceStrict
}
func (d *promotionOrderDP18927) setErrors(publishErr, bumpErr error) {
	d.mu.Lock()
	d.publishErr = publishErr
	d.bumpErr = bumpErr
	d.mu.Unlock()
}
func (d *promotionOrderDP18927) PublishRouteOverlaySnapshotWithLatch(*config.Config, []config.RouteOverlayEntry, map[string]bool, bool) (bool, error) {
	d.log.add("publish")
	d.mu.RLock()
	err := d.publishErr
	d.mu.RUnlock()
	return true, err
}
func (d *promotionOrderDP18927) BumpFIBGeneration() (uint32, error) {
	d.log.add("bump")
	d.mu.RLock()
	err := d.bumpErr
	d.mu.RUnlock()
	return 1, err
}

func newPromotionOrderDaemon18927(t *testing.T) (*Daemon, *promotionOrderLog18927, *promotionOrderDP18927) {
	t.Helper()
	log := &promotionOrderLog18927{changed: make(chan struct{}, 32)}
	dp := &promotionOrderDP18927{log: log, ha: &promotionOrderHA18927{log: log}}
	d := newActuationDaemon(t, &actuationHA{})
	d.setDataplane(dp)
	d.applySem = semaphore.NewWeighted(1)
	return d, log, dp
}

func runPromotionPath18927(t *testing.T, d *Daemon, path string) {
	t.Helper()
	switch path {
	case "cluster-event":
		d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
		d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
		d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
			GroupID: 1, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
		}, nil)
	case "vrrp-master":
		d.handleVRRPEvent(context.Background(), vrrp.VRRPEvent{
			GroupID: rethVRIDBase + 1, Interface: "reth1", State: vrrp.StateMaster,
		}, rgTransition{})
	case "reconcile":
		d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
		d.reconcileRGState()
	default:
		t.Fatalf("unknown promotion path %q", path)
	}
}

func countPromotionEvent18927(events []string, event string) int {
	count := 0
	for _, got := range events {
		if got == event {
			count++
		}
	}
	return count
}

func waitPromotionRepublish18927(t *testing.T, log *promotionOrderLog18927, wantPublish, wantBump int) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		events := log.snapshot()
		if countPromotionEvent18927(events, "publish") >= wantPublish && countPromotionEvent18927(events, "bump") >= wantBump {
			return
		}
		select {
		case <-log.changed:
		case <-timer.C:
			t.Fatalf("timed out waiting for connected-RG republish (%d publish, %d bump); events=%v",
				wantPublish, wantBump, log.snapshot())
		}
	}
}

// TestPromotionRepublishesConnectedRGBeforeRGActive18927 pins all three
// activation producers. Before #18927 the reconcile arm wrote rg_active=true
// before its async republish, while the event arms ignored synchronous
// publish/bump errors. Reverting the reconcile republish makes the ordering
// assertion RED; reverting result propagation makes each failed-publish row
// RED.
func TestPromotionRepublishesConnectedRGBeforeRGActive18927(t *testing.T) {
	paths := []string{"cluster-event", "vrrp-master", "reconcile"}
	for _, path := range paths {
		t.Run(path+"/ordering", func(t *testing.T) {
			d, log, _ := newPromotionOrderDaemon18927(t)
			runPromotionPath18927(t, d, path)
			events := log.snapshot()
			active := slices.Index(events, "rg_active[1]=true")
			if active < 2 || events[active-2] != "publish" || events[active-1] != "bump" {
				t.Fatalf("RG1 activation order = %v; want publish -> bump -> rg_active[1]=true (#18927)", events)
			}
			if path != "vrrp-master" {
				waitPromotionRepublish18927(t, log, 2, 2)
			}
		})
	}

	for _, failure := range []string{"publisher-error", "bump-error"} {
		for _, path := range paths {
			t.Run(path+"/"+failure, func(t *testing.T) {
				d, log, dp := newPromotionOrderDaemon18927(t)
				if failure == "publisher-error" {
					dp.publishErr = errors.New("connected-route publish failed")
				} else {
					dp.bumpErr = errors.New("FIB generation bump failed")
				}
				runPromotionPath18927(t, d, path)
				if path != "vrrp-master" {
					wantPublish, wantBump := 1, 0
					if path == "cluster-event" {
						wantPublish = 2
					}
					if failure == "bump-error" {
						wantBump = 1
						if path == "cluster-event" {
							wantBump = 2
						}
					}
					waitPromotionRepublish18927(t, log, wantPublish, wantBump)
				}
				events := log.snapshot()
				if slices.Contains(events, "rg_active[1]=true") {
					t.Fatalf("RG1 activation proceeded despite %s on %s: events=%v", failure, path, events)
				}
				if !slices.Contains(events, "publish") {
					t.Fatalf("connected-RG publish was not attempted: events=%v", events)
				}
				if failure == "bump-error" && !slices.Contains(events, "bump") {
					t.Fatalf("FIB generation bump was not attempted: events=%v", events)
				}
				if !d.getOrCreateRGState(1).NeedsApply() {
					t.Fatalf("failed republish cleared retry debt on %s; events=%v", path, events)
				}
				if path == "vrrp-master" {
					s := d.getOrCreateRGState(1)
					if !d.cluster.IsLocalPrimary(1) || !s.AllVRRPMaster() {
						t.Fatalf("readiness control is vacuous: local-primary=%v all-master=%v",
							d.cluster.IsLocalPrimary(1), s.AllVRRPMaster())
					}
					if d.localFailoverCommitIsReady(1) {
						t.Fatalf("VRRP MASTER raised peer-commit readiness despite failed republish: events=%v", events)
					}
				}
			})
		}
	}
}

// A sync-hold release can make the merged transition active even on a
// Primary->Primary reaffirmation, where there is no cluster ownership edge.
func TestSyncHoldReleasePrimaryReaffirmRepublishes18927(t *testing.T) {
	d, log, _ := newPromotionOrderDaemon18927(t)
	d.store = testStoreWithSetConfig(t, []string{
		"set system dataplane-type userspace",
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster authentication-key test-cluster-psk-18927",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	})
	d.cluster.UpdateConfig(d.store.ActiveConfig().Chassis.Cluster)
	if d.isNoRethVRRP() {
		t.Fatal("fixture: RETH VRRP must be enabled")
	}
	d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.vrrpMgr.SetSyncHold(time.Hour)
	s := d.getOrCreateRGState(1)
	if !s.SyncHeld() {
		t.Fatal("fixture: RG1 must mirror the armed sync hold")
	}
	if tr := s.SetCluster(true); tr.Active || s.IsActive() {
		t.Fatalf("fixture: cluster-primary input must remain held inactive, got transition=%+v", tr)
	}
	d.vrrpMgr.ReleaseSyncHold()

	timer := d.dispatchClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StatePrimary, NewState: cluster.StatePrimary, DualActiveWin: true,
	}, nil)
	if timer != nil {
		timer.Stop()
	}
	events := log.snapshot()
	active := slices.Index(events, "rg_active[1]=true")
	if active < 2 || events[active-2] != "publish" || events[active-1] != "bump" {
		t.Fatalf("sync-hold release activation order = %v; want publish -> bump -> rg_active[1]=true (#18927)", events)
	}
	if s.NeedsApply() {
		t.Fatalf("successful hold-release activation left apply retry pending: events=%v", events)
	}
}

// A failed VRRP MASTER republish leaves peer-commit readiness low. The
// reconcile retry must restore readiness only after it republishes and
// records rg_active with the authoritative VRRP posture still MASTER.
func TestPromotionRepublishRetryRestoresVRRPCommitReadiness18927(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set system dataplane-type userspace",
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster authentication-key test-cluster-psk-18927",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	})
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	if !cm.IsLocalPrimary(1) {
		t.Fatal("fixture: RG1 must be local-primary")
	}
	vrrpMgr := vrrp.NewManager()
	instances := vrrp.CollectRethInstances(store.ActiveConfig(), cm.LocalPriorities())
	if len(instances) != 1 {
		t.Fatalf("fixture: expected one RETH VRRP instance, got %d", len(instances))
	}
	vrrpMgr.SeedInstanceForTesting(*instances[0], vrrp.StateMaster)
	log := &promotionOrderLog18927{changed: make(chan struct{}, 32)}
	dp := &promotionOrderDP18927{log: log, ha: &promotionOrderHA18927{log: log},
		publishErr: errors.New("connected-route publish failed")}
	d := &Daemon{
		store:                      store,
		cluster:                    cm,
		vrrpMgr:                    vrrpMgr,
		rgStates:                   make(map[int]*rgStateMachine),
		userspaceDemotionPrepUntil: make(map[int]time.Time),
		localFailoverCommitReady:   make(map[int]bool),
		rethServices:               make(map[int]rethServicesEdgeStatus),
		proxyARPNudgeCh:            make(chan struct{}, 8),
		applySem:                   semaphore.NewWeighted(1),
	}
	d.setDataplane(dp)

	d.reconcileRGState()
	s := d.getOrCreateRGState(1)
	if !s.AllVRRPMaster() {
		t.Fatal("fixture: reconcile did not preserve the authoritative MASTER posture")
	}
	if !s.NeedsApply() || d.localFailoverCommitIsReady(1) {
		t.Fatalf("failed republish must leave activation retry armed and readiness false; needsApply=%v ready=%v",
			s.NeedsApply(), d.localFailoverCommitIsReady(1))
	}

	dp.setErrors(nil, nil)
	d.reconcileRGState()
	if s.NeedsApply() || !d.localFailoverCommitIsReady(1) {
		t.Fatalf("successful reconcile retry must converge rg_active and restore readiness; needsApply=%v ready=%v",
			s.NeedsApply(), d.localFailoverCommitIsReady(1))
	}
}

// promotionModeInterleaveDP18927 invokes a competing event at a userspace
// mode check, providing a deterministic interleaving before a desired-state re-read.
type promotionModeInterleaveDP18927 struct {
	*promotionOrderDP18927
	onMode func()
}

func (p *promotionModeInterleaveDP18927) Mode() dpuserspace.DataplaneMode {
	fn := p.onMode
	p.onMode = nil
	if fn != nil {
		fn()
	}
	return dpuserspace.ModeUserspaceStrict
}

func TestVRRPBackupRecheckGatesInterleavedPromotion18927(t *testing.T) {
	d, log, dp := newPromotionOrderDaemon18927(t)
	d.store = testStoreWithSetConfig(t, []string{
		"set system dataplane-type userspace",
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster authentication-key test-cluster-psk-18927",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	})
	d.cluster.UpdateConfig(d.store.ActiveConfig().Chassis.Cluster)
	if d.isNoRethVRRP() {
		t.Fatal("fixture: RETH VRRP must be enabled")
	}
	instances := vrrp.CollectRethInstances(d.store.ActiveConfig(), d.cluster.LocalPriorities())
	if len(instances) != 1 {
		t.Fatalf("fixture: want one RETH VRRP instance, got %d", len(instances))
	}
	d.vrrpMgr.SeedInstanceForTesting(*instances[0], vrrp.StateMaster)
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)
	s := d.getOrCreateRGState(1)
	if tr := s.SetVRRP("reth1", true); !tr.Active {
		t.Fatal("fixture: initial MASTER must be active")
	}
	s.MarkApplied(true)
	dp.setErrors(errors.New("connected-route publication refused"), nil)
	p := &promotionModeInterleaveDP18927{promotionOrderDP18927: dp}
	p.onMode = func() {
		d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
		d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
			GroupID: 1, OldState: cluster.StateSecondary, NewState: cluster.StatePrimary,
		}, nil)
	}
	d.setDataplane(p)

	d.handleVRRPEvent(context.Background(), vrrp.VRRPEvent{
		GroupID: rethVRIDBase + 1, Interface: "reth1", State: vrrp.StateBackup,
	}, rgTransition{})
	events := log.snapshot()
	if !slices.Contains(events, "publish") {
		t.Fatalf("fixture did not exercise failed connected-route republish: %v", events)
	}
	if countPromotionEvent18927(events, "rg_active[1]=true") != 0 {
		t.Fatalf("BACKUP re-read wrote rg_active=true after failed concurrent PRIMARY republish: %v", events)
	}
	if !s.NeedsApply() {
		t.Fatalf("failed concurrent PRIMARY republish lost retry debt: %v", events)
	}
	if d.localFailoverCommitIsReady(1) {
		t.Fatal("failed concurrent PRIMARY republish opened peer-commit readiness")
	}

	dp.setErrors(nil, nil)
	d.reconcileRGState()
	if s.NeedsApply() || countPromotionEvent18927(log.snapshot(), "rg_active[1]=true") != 1 {
		t.Fatalf("reconcile did not converge the pending promotion exactly once; needsApply=%v events=%v",
			s.NeedsApply(), log.snapshot())
	}
	if !d.cluster.IsLocalPrimary(1) || !s.AllVRRPMaster() || !d.localFailoverCommitIsReady(1) {
		t.Fatalf("successful reconcile did not restore primary/Master readiness: primary=%v allMaster=%v ready=%v",
			d.cluster.IsLocalPrimary(1), s.AllVRRPMaster(), d.localFailoverCommitIsReady(1))
	}
}

func TestClusterDemotionRecheckGatesInterleavedPromotion18927(t *testing.T) {
	d, log, dp := newPromotionOrderDaemon18927(t)
	d.store = testStoreWithSetConfig(t, []string{
		"set system dataplane-type userspace",
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster authentication-key test-cluster-psk-18927",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	})
	d.cluster.UpdateConfig(d.store.ActiveConfig().Chassis.Cluster)
	if d.isNoRethVRRP() {
		t.Fatal("fixture: RETH VRRP must be enabled")
	}
	d.cluster.SetGroupStateForTesting(1, cluster.StatePrimary)
	s := d.getOrCreateRGState(1)
	if tr := s.SetCluster(true); !tr.Active {
		t.Fatal("fixture: initial cluster PRIMARY must be active")
	}
	s.MarkApplied(true)
	dp.setErrors(errors.New("connected-route publication refused"), nil)
	p := &promotionModeInterleaveDP18927{promotionOrderDP18927: dp}
	p.onMode = func() {
		d.handleVRRPEvent(context.Background(), vrrp.VRRPEvent{
			GroupID: rethVRIDBase + 1, Interface: "reth1", State: vrrp.StateMaster,
		}, rgTransition{})
	}
	d.setDataplane(p)
	d.cluster.SetGroupStateForTesting(1, cluster.StateSecondary)

	timer := d.dispatchClusterEvent(context.Background(), cluster.ClusterEvent{
		GroupID: 1, OldState: cluster.StatePrimary, NewState: cluster.StateSecondary,
	}, nil)
	if timer != nil {
		timer.Stop()
	}
	events := log.snapshot()
	if !slices.Contains(events, "publish") {
		t.Fatalf("fixture did not exercise the interleaved MASTER republish failure: %v", events)
	}
	if countPromotionEvent18927(events, "rg_active[1]=true") != 0 {
		t.Fatalf("cluster demotion re-read wrote rg_active=true after failed MASTER republish: %v", events)
	}
	if !s.NeedsApply() {
		t.Fatalf("failed MASTER republish lost retry debt in cluster demotion recheck: %v", events)
	}
}

func TestTransferPreActivationSkipsHelperPublishAfterConnectedRouteFailure18927(t *testing.T) {
	for _, failure := range []string{"publisher-error", "bump-error"} {
		t.Run(failure, func(t *testing.T) {
			d, dp := newPreActivateDaemon18559(t)
			if failure == "publisher-error" {
				dp.fakeOverlayDP.publishErr = errors.New("connected-route publish failed")
			} else {
				dp.fakeOverlayDP.bumpErr = errors.New("FIB generation bump failed")
			}
			if err := d.beginTransferPreActivation([]int{1}); err == nil {
				t.Fatal("transfer pre-activation reported success after connected-route republish failure")
			}
			calls := dp.callsSnapshot()
			if slices.Contains(calls, "ha-publish") {
				t.Fatalf("helper forwarding publish proceeded after connected-route failure: calls=%v", calls)
			}
			want := []string{"mark", "publish"}
			if failure == "bump-error" {
				want = append(want, "bump")
			}
			if !slices.Equal(calls, want) {
				t.Fatalf("calls=%v, want %v after %s", calls, want, failure)
			}
		})
	}
}
