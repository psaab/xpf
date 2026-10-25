package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
)

func ipmonGating16690Store(t *testing.T) *configstore.Store {
	t.Helper()
	// Build store via set lines so ActiveConfig returns the compiled cfg
	// (with PrivateRGElection default true => isNoRethVRRP true).
	return fenceTestStore(t, ""+
		"set chassis cluster cluster-id 1\n"+
		"set chassis cluster node 0\n"+
		"set chassis cluster reth-count 2\n"+
		"set chassis cluster redundancy-group 0 node 0 priority 100\n"+
		"set chassis cluster redundancy-group 0 node 1 priority 200\n"+
		"set chassis cluster redundancy-group 1 node 0 priority 100\n"+
		"set chassis cluster redundancy-group 1 node 1 priority 200\n"+
		"set chassis cluster authentication-key test-cluster-psk-16690\n"+
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0\n"+
		"set interfaces reth0 vlan-tagging\n"+
		"set interfaces reth0 redundant-ether-options redundancy-group 1\n"+
		"set interfaces reth0 unit 50 vlan-id 50\n"+
		"set interfaces reth0 unit 50 family inet address 10.0.0.1/24\n"+
		"set services rpm probe WAN test t probe-type tcp-ping\n"+
		"set services rpm probe WAN test t target address 127.0.0.1\n"+
		"set services rpm probe WAN test t destination-interface reth0.50\n"+
		"set services ip-monitoring policy wan-failover match rpm-probe WAN\n"+
		"set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 next-hop 192.0.2.1\n")
}

// waitIPMonGate polls until PublishEnabled == want or timeout.
func waitIPMonGate(t *testing.T, e *ipmon.Engine, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e.PublishEnabled() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("PublishEnabled = %v, want %v after event-delivered failover (#16690)", e.PublishEnabled(), want)
}

func waitRPMHas(t *testing.T, d *Daemon, probe string, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		d.rpmMu.Lock()
		eff := d.rpmEffective
		d.rpmMu.Unlock()
		has := eff != nil && eff.Probes[probe] != nil
		if has == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	d.rpmMu.Lock()
	eff := d.rpmEffective
	d.rpmMu.Unlock()
	t.Fatalf("rpmEffective has probe %q = %v, want %v (eff=%+v) (#16690)", probe, eff != nil && eff.Probes[probe] != nil, want, eff)
}

// TestIPMonGatingEventFailover16690 is the #16690 regression: an
// event-delivered cluster failover (handleClusterEvent consuming the
// rg-state edge before reconcile) must still re-gate ip-monitoring:
// publish gate follows IsLocalPrimaryAny and the gated RPM set swaps,
// with the takeover burst firing on the new owner. Pre-fix, the only
// caller was reconcileRGState gated on its own tr.Changed, which the
// event already consumed, so both assertions time out.
func TestIPMonGatingEventFailover16690(t *testing.T) {
	// Two nodes simulated sequentially on one harness shape: promotion
	// (secondary -> primary) and demotion (primary -> secondary).
	for _, tc := range []struct {
		name      string
		startPri  bool // RG1 primary at start?
		promote   bool
		wantGate  bool
		wantProbe bool
	}{
		{name: "promotion enables gate and gated probes", startPri: false, promote: true, wantGate: true, wantProbe: true},
		{name: "demotion disables gate and gated probes", startPri: true, promote: false, wantGate: false, wantProbe: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := ipmonGating16690Store(t)
			cfg := store.ActiveConfig()
			if cfg == nil {
				t.Fatal("ActiveConfig nil")
			}
			// Fix WAN port to a dead tcp target with long intervals so
			// only burst verdicts are fast; keep compiled cfg otherwise.
			// The compiled test uses default port handling; gating swap
			// is observed via rpmEffective, burst via transition below.

			cm := cluster.NewManager(0, 1)
			cm.UpdateConfig(cfg.Chassis.Cluster)
			for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
				cm.SetRGReady(rg.ID, true, nil)
			}
			// Force deterministic RG states: RG0 secondary always.
			cm.SetGroupStateForTesting(0, cluster.StateSecondary)
			if tc.startPri {
				cm.SetGroupStateForTesting(1, cluster.StatePrimary)
			} else {
				cm.SetGroupStateForTesting(1, cluster.StateSecondary)
			}
			// Drain election events.
			for drained := true; drained; {
				select {
				case <-cm.Events():
				default:
					drained = false
				}
			}
			if got := cm.IsLocalPrimary(1); got != tc.startPri {
				t.Fatalf("setup IsLocalPrimary(1)=%v want %v", got, tc.startPri)
			}

			engine := ipmon.New(nil)
			mgr := rpm.New()
			d := &Daemon{
				store:                      store,
				cluster:                    cm,
				vrrpMgr:                    vrrp.NewManager(),
				rgStates:                   make(map[int]*rgStateMachine),
				blackholeRoutes:            make(map[int][]netlink.Route),
				failoverActuations:         failoverActuationRegistry{timeout: 2 * time.Second},
				userspaceDemotionPrepUntil: make(map[int]time.Time),
				applySem:                   semaphore.NewWeighted(1),
				ipmon:                      engine,
				rpm:                        mgr,
				daemonCtx:                  context.Background(),
			}
			d.rpmFirstReconcileDone = true // avoid first-apply burst masking HA burst
			defer mgr.StopAll()
			transitions := make(chan rpm.Transition, 16)
			mgr.SetTransitionCallback(func(tr rpm.Transition) {
				// Forward to ipmon as production wiring does, and record.
				engine.HandleTransition(tr)
				select {
				case transitions <- tr:
				default:
				}
			})
			// Prime: apply gating for the START state synchronously
			// (as a commit/reconcile-observed edge would have).
			d.reconcileIPMonGating()
			if engine.PublishEnabled() != tc.startPri {
				// RG0 secondary, so predicate == RG1 primary == startPri.
				t.Fatalf("setup gate=%v want %v (predicate IsLocalPrimaryAny)", engine.PublishEnabled(), tc.startPri)
			}
			waitRPMHas(t, d, "WAN", tc.startPri)
			// Verify predicate helper agrees.
			if got := d.ipmonPublishAllowed(cfg); got != tc.startPri {
				t.Fatalf("setup predicate=%v want %v", got, tc.startPri)
			}

			// Deliver the failover event exactly as watchClusterEvents
			// would: flip cluster state first, then handleClusterEvent.
			var oldS, newS cluster.NodeState
			if tc.promote {
				oldS, newS = cluster.StateSecondary, cluster.StatePrimary
				cm.SetGroupStateForTesting(1, cluster.StatePrimary)
			} else {
				oldS, newS = cluster.StatePrimary, cluster.StateSecondary
				cm.SetGroupStateForTesting(1, cluster.StateSecondary)
			}
			// RG-state machine must reflect start state so the event is a real edge.
			// (handleClusterEvent calls SetCluster itself.)
			if timer := d.handleClusterEvent(context.Background(), cluster.ClusterEvent{
				GroupID: 1, OldState: oldS, NewState: newS,
			}, nil); timer != nil {
				timer.Stop()
			}
			// Two reconcile passes: pre-fix these see Changed=false and
			// must NOT be what saves us — but post-fix the scheduled
			// async gating may interleave; either way gate must match.
			d.reconcileRGState()
			d.reconcileRGState()

			waitIPMonGate(t, engine, tc.wantGate)
			if got := d.ipmonPublishAllowed(cfg); got != tc.wantGate {
				t.Fatalf("predicate=%v want %v", got, tc.wantGate)
			}
			waitRPMHas(t, d, "WAN", tc.wantProbe)

			if tc.promote {
				// #11414: the newly enabled gated probe must be selected
				// for the takeover burst. The live probe in this fixture
				// cannot run (no reth device in the test netns, so it
				// holds on setup error and emits no verdict), so pin the
				// selector — the same computation reconcileRPMMode uses
				// to build burstProbeNames for ApplyWithProbeBurst —
				// plus the rpmEffective swap already asserted above.
				// The burst execution itself is pinned by
				// pkg/rpm TestTakeoverProbeBurst*11414.
				d.rpmMu.Lock()
				prev := d.rpmEffective
				d.rpmMu.Unlock()
				// prev is now the promoted (WAN-present) set; recompute
				// from the secondary-era (WAN-absent) set.
				secondaryEra := &config.RPMConfig{Probes: map[string]*config.RPMProbe{}}
				if got := newlyEnabledIPMonProbeNames(cfg, secondaryEra, prev); len(got) != 1 {
					t.Fatalf("takeover burst selection = %v, want exactly {WAN} (#11414 via #16690)", got)
				} else if _, ok := got["WAN"]; !ok {
					t.Fatalf("takeover burst selection = %v, want WAN", got)
				}
			}
		})
	}
}

// TestIPMonGatingVRRPEvent16690 covers the legacy watchVRRPEvents arms:
// a VRRP MASTER/BACKUP edge that flips rg_active must schedule gating
// even when cluster primaryship alone would not be re-observed by
// reconcile. Directly drive the state machine + schedule contract via
// handleClusterEvent-independent path: simulate by calling the VRRP
// handler logic through a real vrrp manager is not injectable, so this
// test pins scheduleIPMonGating itself under applySem serialization.
func TestIPMonGatingVRRPSchedule16690(t *testing.T) {
	store := ipmonGating16690Store(t)
	cfg := store.ActiveConfig()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		cm.SetRGReady(rg.ID, true, nil)
	}
	cm.SetGroupStateForTesting(0, cluster.StateSecondary)
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	for drained := true; drained; {
		select {
		case <-cm.Events():
		default:
			drained = false
		}
	}
	engine := ipmon.New(nil)
	engine.SetPublishEnabled(true) // stale open gate on standby
	mgr := rpm.New()
	defer mgr.StopAll()
	d := &Daemon{
		store: store, cluster: cm, vrrpMgr: vrrp.NewManager(),
		rgStates: make(map[int]*rgStateMachine), blackholeRoutes: make(map[int][]netlink.Route),
		applySem: semaphore.NewWeighted(1),
		ipmon:    engine, rpm: mgr, daemonCtx: context.Background(),
	}
	d.rpmFirstReconcileDone = true
	// Promote cluster (predicate becomes true via RG1), then the VRRP
	// schedule entry point must close/open to predicate.
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.scheduleIPMonGating("vrrp-master")
	waitIPMonGate(t, engine, true)
	waitRPMHas(t, d, "WAN", true)
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	d.scheduleIPMonGating("vrrp-backup")
	waitIPMonGate(t, engine, false)
	waitRPMHas(t, d, "WAN", false)
}
