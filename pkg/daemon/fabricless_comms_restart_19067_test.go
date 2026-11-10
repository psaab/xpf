package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fabricsegment"
)

// #19067: step 20 (reconcileClusterTransportBinding) stops comms through
// stopClusterCommsAndClearFabricWatcher whenever the config has no fabric
// interface, and starts them again only if that stop reports success. The
// stop's finalizer guard compared d.sessionSync with the captured session AFTER
// the stop itself had cleared d.sessionSync. For a running epoch (a non-nil
// session) the guard was therefore always false: the stop returned false, the
// fabric watcher was not cleared, and comms were never restarted. A fabric-less
// cluster then sat with no heartbeat, no session sync and no fabric refresh
// until the process restarted.
//
// The 7072/7901 cells drive step 20 after an explicit stop, when no session is
// published, so they could not see this. These cells publish a live session
// first, which is the production shape: comms are up when a commit moves the
// transport.

// fabriclessEpoch19067 returns a daemon whose running comms epoch published the
// transport key `active` and a live session-sync object, plus a counter of
// step-20 restarts and an armed fabric watcher that step 20 must clear when the
// config carries no fabric.
func fabriclessEpoch19067(t *testing.T, active clusterTransportKey) (*Daemon, *int, *fabricsegment.Monitor) {
	t.Helper()
	mon := fabricsegment.NewMonitor(nil)
	prev := fabricsegment.SwapDefault(mon)
	t.Cleanup(func() {
		mon.Stop()
		fabricsegment.SwapDefault(prev)
	})
	mon.Update([]fabricsegment.Link{{
		Name: "fab0", Parent: "ge-0-0-0", ParentIfindex: 4,
		LocalMAC: []byte{0x10, 0x66, 0x6a, 0, 0, 1},
		PeerMAC:  []byte{0x10, 0x66, 0x6a, 0, 0, 2},
	}})
	if got := mon.Watched(); len(got) != 1 {
		t.Fatalf("premise: fixture watcher links = %v, want one armed fabric", got)
	}

	restarts := 0
	d := &Daemon{
		cluster:             cluster.NewManager(0, 1),
		daemonCtx:           context.Background(),
		startClusterCommsFn: func(context.Context) { restarts++ },
	}
	_, gen, _ := d.beginClusterCommsEpoch(context.Background())
	if active != (clusterTransportKey{}) && !d.setActiveTransportIfCurrent(gen, active) {
		t.Fatal("premise: could not publish the running epoch's transport")
	}
	ss := cluster.NewSessionSync(":0", "10.99.0.2:4785", nil)
	if !d.publishSessionSyncIfCurrent(gen, ss) {
		t.Fatal("premise: could not publish the running epoch's session")
	}
	if d.getSessionSync() != ss {
		t.Fatal("premise: the running epoch must hold a LIVE session; without one the stop's finalizer guard is trivially true and the defect is invisible")
	}
	t.Cleanup(func() { d.stopClusterComms() })
	return d, &restarts, mon
}

func fabriclessConfig19067(peer string) *config.Config {
	return &config.Config{Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{
		ControlInterface: "em0",
		PeerAddress:      peer,
	}}}
}

// TestFabriclessTransportChangeRestartsComms19067: a commit that moves the
// transport of a fabric-less cluster must replace the running epoch: stop it,
// clear the fabric watcher, and start comms again.
func TestFabriclessTransportChangeRestartsComms19067(t *testing.T) {
	d, restarts, mon := fabriclessEpoch19067(t, clusterTransportKey{ControlInterface: "em0", PeerAddress: "10.99.0.2"})
	cfg := fabriclessConfig19067("10.99.0.3")
	if got := d.clusterTransportForConfig(cfg); got == d.activeTransport() {
		t.Fatalf("premise: the commit must MOVE the transport key (active=%+v new=%+v)", d.activeTransport(), got)
	}

	d.reconcileClusterTransportBinding(cfg, false)

	if *restarts != 1 {
		t.Errorf("fabric-less transport change restarted comms %d times, want 1: the stop tore the epoch down and step 20 returned without starting it again, so the node keeps a valid cluster config with no heartbeat, session sync or fabric refresh until the process restarts (#19067)", *restarts)
	}
	if got := d.getSessionSync(); got != nil {
		t.Errorf("old session still published after the transport change: %p", got)
	}
	if got := mon.Watched(); len(got) != 0 {
		t.Errorf("fabric-less transport change left the fabric watcher armed: %v (the stop's finalizer did not run)", got)
	}
}

// TestFabriclessOwedRestartRunsWithLiveSession19067: the #7901 owed restart
// with an unchanged key takes the same stop-then-start path.
func TestFabriclessOwedRestartRunsWithLiveSession19067(t *testing.T) {
	active := clusterTransportKey{ControlInterface: "em0", PeerAddress: "10.99.0.2"}
	d, restarts, _ := fabriclessEpoch19067(t, active)
	cfg := fabriclessConfig19067("10.99.0.2")
	if got := d.clusterTransportForConfig(cfg); got != active {
		t.Fatalf("premise: the key must be UNCHANGED so only restartOwed drives the restart (active=%+v new=%+v)", active, got)
	}

	d.reconcileClusterTransportBinding(cfg, true)

	if *restarts != 1 {
		t.Errorf("owed restart on a fabric-less cluster with a live session ran %d times, want 1 (#19067)", *restarts)
	}
}

// TestFabriclessStartupEpochWithoutKeyRestartsComms19067: startup can publish
// an epoch (and its session) before its transport key. Step 20's zero-key
// branch joins that epoch and must start comms for the current config.
func TestFabriclessStartupEpochWithoutKeyRestartsComms19067(t *testing.T) {
	d, restarts, mon := fabriclessEpoch19067(t, clusterTransportKey{})
	if d.activeTransport() != (clusterTransportKey{}) {
		t.Fatal("premise: the startup epoch must not have published a transport key")
	}

	d.reconcileClusterTransportBinding(fabriclessConfig19067("10.99.0.2"), false)

	if *restarts != 1 {
		t.Errorf("fabric-less startup epoch without a key restarted comms %d times, want 1 (#19067)", *restarts)
	}
	if got := mon.Watched(); len(got) != 0 {
		t.Errorf("fabric-less startup epoch left the fabric watcher armed: %v", got)
	}
}

// TestFabricConfiguredTransportChangeRestartsComms19067 is the same-shape
// control: with a fabric configured, step 20 takes plain stopClusterComms and
// restarts. It passes with and without the #19067 fix, so a failure of the
// fabric-less cells above is attributable to the removing-fabric arm, not to
// the fixture.
func TestFabricConfiguredTransportChangeRestartsComms19067(t *testing.T) {
	d, restarts, _ := fabriclessEpoch19067(t, clusterTransportKey{ControlInterface: "em0", PeerAddress: "10.99.0.2", FabricInterface: "fab0"})
	cfg := fabriclessConfig19067("10.99.0.3")
	cfg.Chassis.Cluster.FabricInterface = "fab0"

	d.reconcileClusterTransportBinding(cfg, false)

	if *restarts != 1 {
		t.Errorf("control: fabric-configured transport change restarted comms %d times, want 1", *restarts)
	}
}
