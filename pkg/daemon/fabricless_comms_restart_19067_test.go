package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

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
// published, so they could not see this. These cells publish a session OBJECT
// first (the production shape is comms up when a commit moves the transport).
// What they assert is the published session object and the step-20 restart
// call count: the fixture never calls SessionSync.Start, opens no socket, and
// "restart" is a counting startClusterCommsFn hook (Codex F2).

// fabriclessEpoch19067 returns a daemon whose comms epoch published the
// transport key `active` and a (never started) session-sync object, plus a counter of
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
		t.Fatal("premise: could not publish the epoch's transport")
	}
	ss := cluster.NewSessionSync(":0", "10.99.0.2:4785", nil)
	if !d.publishSessionSyncIfCurrent(gen, ss) {
		t.Fatal("premise: could not publish the epoch's session object")
	}
	if d.getSessionSync() != ss {
		t.Fatal("premise: the epoch must hold a published session object; without one the stop's finalizer guard is trivially true and the defect is invisible")
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
	d, restarts, mon := fabriclessEpoch19067(t, active)
	cfg := fabriclessConfig19067("10.99.0.2")
	if got := d.clusterTransportForConfig(cfg); got != active {
		t.Fatalf("premise: the key must be UNCHANGED so only restartOwed drives the restart (active=%+v new=%+v)", active, got)
	}

	d.reconcileClusterTransportBinding(cfg, true)

	if *restarts != 1 {
		t.Errorf("owed restart on a fabric-less cluster with a live session ran %d times, want 1 (#19067)", *restarts)
	}
	if got := mon.Watched(); len(got) != 0 {
		t.Errorf("fabric-less owed restart left the fabric watcher armed: %v (the stop's finalizer did not run)", got)
	}
}

// TestStopWindowSerializesSuccessor19067 pins what the finalizer guard relies
// on, at the level that enforces it (cell shape from review seat R13 on
// #19067). The stop holds clusterCommsLifecycleMu from its re-capture through
// the guard and the finalizer; beginClusterCommsEpoch takes the same lock, so
// no successor epoch can begin inside that window, and the guard is therefore
// invariantly true when reached. The test parks the stop INSIDE the window
// (after its d.sessionSync clear, at stopSyncReadyTimer, by holding
// syncReadyTimerMu) and starts a successor that tries to begin an epoch:
//   - the successor signals just before it calls beginClusterCommsEpoch, and
//     the test waits for that signal while the stop is still parked; a cell
//     that never sees the signal FAILS ("did not exercise contention");
//   - while still parked, the comms generation must not advance: it is
//     watched for 2 s and sampled once more right before the park is
//     released, which narrows (does not close) the unsampled tail;
//   - after release, the stop reports success with exactly one finalizer run;
//     the successor can begin only after the stop releases
//     clusterCommsLifecycleMu (daemon_ha_sync.go:2527), which is the
//     exclusion boundary (it precedes the stop's return to its caller);
//   - had a successor begun inside the window, the stop must NOT report
//     success, or step 20 would start comms a second time.
//
// The kill of M5 (beginClusterCommsEpoch without clusterCommsLifecycleMu) is
// PROBABILISTIC, not deterministic (Codex, cycle 3): the signal proves the
// successor reached the signal, not the lock, so a successor descheduled
// between the two until after the park is released lets M5 pass. Observed:
// M5 killed 40/40 (lane H x20, R13 x10, R8 x10 at d8d6a3c9de), M3+M5 30/30.
// TestStopClusterCommsSerializesLateSuccessorStart17060 is the other M5
// witness and has the same shape (a pre-lock signal, then a single 25 ms
// sample, then teardown assertions), so its kill is not deterministic either.
func TestStopWindowSerializesSuccessor19067(t *testing.T) {
	d, _, _ := fabriclessEpoch19067(t, clusterTransportKey{ControlInterface: "em0", PeerAddress: "10.99.0.2"})
	gen := func() uint64 {
		d.clusterCommsMu.Lock()
		defer d.clusterCommsMu.Unlock()
		return d.clusterCommsGen
	}

	d.syncReadyTimerMu.Lock()
	parked := true
	defer func() {
		if parked {
			d.syncReadyTimerMu.Unlock()
		}
	}()

	var finalized atomic.Int32
	stopDone := make(chan bool, 1)
	go func() {
		stopDone <- d.stopClusterCommsWithFinalizer(func() { finalized.Add(1) })
	}()
	deadline := time.Now().Add(5 * time.Second)
	for d.getSessionSync() != nil {
		if time.Now().After(deadline) {
			t.Fatal("premise: the stop never reached its session clear")
		}
		time.Sleep(time.Millisecond)
	}
	stopGen := gen()

	attempting := make(chan struct{})
	successorBegan := make(chan context.CancelFunc, 1)
	go func() {
		close(attempting)
		_, _, cancel := d.beginClusterCommsEpoch(context.Background())
		successorBegan <- cancel
	}()
	select {
	case <-attempting:
	case <-time.After(5 * time.Second):
		t.Fatal("did not exercise contention: the successor never attempted beginClusterCommsEpoch while the stop was parked")
	}
	beganInWindow := false
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if gen() != stopGen {
			beganInWindow = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !beganInWindow && gen() != stopGen {
		// Final sample right before release (Codex cycle 3, scenario B: the
		// loop's last sleep was never sampled).
		beganInWindow = true
	}
	if beganInWindow {
		t.Errorf("a successor epoch began inside the stop's teardown window (generation %d -> %d while the stop was parked): beginClusterCommsEpoch must wait for clusterCommsLifecycleMu, which the stop holds through its guard and finalizer (#19067)", stopGen, gen())
	}

	d.syncReadyTimerMu.Unlock()
	parked = false
	var stopped bool
	select {
	case stopped = <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the parked stop did not finish after its window was released")
	}
	select {
	case cancel := <-successorBegan:
		defer cancel()
	case <-time.After(5 * time.Second):
		t.Fatal("the successor never began after the stop finished")
	}

	if beganInWindow {
		if stopped || finalized.Load() != 0 {
			t.Errorf("the stop reported success (stopped=%v, finalized=%d) although a successor epoch began inside its window: step 20 would start comms a second time", stopped, finalized.Load())
		}
		return
	}
	if !stopped || finalized.Load() != 1 {
		t.Errorf("a stop that still owned teardown returned stopped=%v finalized=%d, want true/1: step 20 would never restart comms (#19067)", stopped, finalized.Load())
	}
}

// TestBootstrapTeardownWithLiveSessionClearsWatcher19067: bootstrap rollback
// (relinquishClusterForBootstrap) uses the same finalizer path on EVERY
// cluster, fabric-configured or not. Before #18751 it cleared the fabric
// watcher unconditionally; #18751 moved the clear into the finalizer, and the
// `== ss` guard then skipped it whenever comms were live. The teardown must
// clear the watcher, leave comms stopped (it does not restart), and owe the
// #7901 restart.
func TestBootstrapTeardownWithLiveSessionClearsWatcher19067(t *testing.T) {
	d, restarts, mon := fabriclessEpoch19067(t, clusterTransportKey{
		ControlInterface: "em0", PeerAddress: "10.99.0.2", FabricInterface: "fab0",
	})

	if steps := d.relinquishClusterForBootstrap(); len(steps) != 0 {
		t.Fatalf("premise: no RG to resign, so the teardown must report no failed step, got %+v", steps)
	}

	if got := mon.Watched(); len(got) != 0 {
		t.Errorf("bootstrap teardown with a live session left the fabric watcher armed: %v (#18751 intent, #19067)", got)
	}
	if got := d.getSessionSync(); got != nil {
		t.Errorf("bootstrap teardown left the session published: %p", got)
	}
	if *restarts != 0 {
		t.Errorf("bootstrap teardown restarted comms %d times, want 0 (it is a stop-without-start)", *restarts)
	}
	if d.clusterCommsEpochActive() {
		t.Error("bootstrap teardown left a comms epoch active")
	}
	if !d.takeClusterCommsRestartNeeded() {
		t.Error("bootstrap teardown did not owe the #7901 restart")
	}
}

// TestFabriclessStartupEpochWithoutKeyRestartsComms19067 is SYNTHETIC
// coverage of step 20's zero-key branch (Codex F2): an epoch with a published
// session but no transport key. Production startClusterComms publishes the key
// (setActiveTransportIfCurrent, daemon_ha_sync.go:1781) BEFORE the constructor
// publishes the session (publishSessionSyncIfCurrent, :1940), so this cell does
// not reproduce a real startup ordering; it pins that the branch, if reached
// with a session, still joins the epoch and starts comms for the current config.
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
