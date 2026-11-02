package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fabricsegment"
)

// TestClusterFabricRemovalStopsWatcher18719 holds an old populate callback
// across transport teardown. The callback simulates its final SyncFabricState
// update after cancellation; removal must join it before clearing the watcher.
func TestClusterFabricRemovalStopsWatcher18719(t *testing.T) {
	mon := fabricsegment.NewMonitor(nil)
	prev := fabricsegment.SwapDefault(mon)
	t.Cleanup(func() {
		mon.Stop()
		fabricsegment.SwapDefault(prev)
	})
	link := fabricsegment.Link{
		Name: "fab0", Parent: "ge-0-0-0", ParentIfindex: 4,
		LocalMAC: []byte{0x10, 0x66, 0x6a, 0, 0, 1},
		PeerMAC:  []byte{0x10, 0x66, 0x6a, 0, 0, 2},
	}
	mon.Update([]fabricsegment.Link{link})
	if got := mon.Watched(); len(got) != 1 {
		t.Fatalf("fixture watcher links = %v, want one armed fabric", got)
	}

	d := &Daemon{
		cluster:             cluster.NewManager(0, 1),
		daemonCtx:           context.Background(),
		startClusterCommsFn: func(context.Context) {},
	}
	commsCtx, gen, _ := d.beginClusterCommsEpoch(context.Background())
	if !d.setActiveTransportIfCurrent(gen, clusterTransportKey{
		ControlInterface: "em0",
		PeerAddress:      "10.99.0.2",
		FabricInterface:  "fab0",
	}) {
		t.Fatal("could not publish running epoch transport")
	}
	d.clusterCommsMu.Lock()
	oldEpoch := d.clusterCommsEpoch
	if oldEpoch == nil {
		d.clusterCommsMu.Unlock()
		t.Fatal("running epoch was not published")
	}
	oldEpoch.fabricPopulateWG.Add(1)
	d.clusterCommsMu.Unlock()

	releasePopulate := make(chan struct{})
	populateEntered := make(chan struct{})
	go func() {
		defer oldEpoch.fabricPopulateWG.Done()
		d.clusterCommsLifecycleMu.Lock()
		close(populateEntered)
		<-releasePopulate
		// This late update is valid for the old epoch but must be followed by
		// the removal path's empty update after the epoch has been joined.
		mon.Update([]fabricsegment.Link{link})
		d.clusterCommsLifecycleMu.Unlock()
	}()
	<-populateEntered

	reconciled := make(chan struct{})
	go func() {
		d.reconcileClusterTransportBinding(&config.Config{}, false)
		close(reconciled)
	}()
	<-commsCtx.Done()
	close(releasePopulate)
	<-reconciled
	if got := mon.Watched(); len(got) != 0 {
		t.Fatalf("last-fabric removal left watcher armed after old populate callback: %v", got)
	}
}

// TestClusterFabricRemovalStopsWatcherWithoutActiveComms18719 exercises the
// real apply tail with no published transport or comms epoch. A removal must
// still retire the process-wide watcher when step 20 takes its zero-key path.
func TestClusterFabricRemovalStopsWatcherWithoutActiveComms18719(t *testing.T) {
	mon := fabricsegment.NewMonitor(nil)
	prev := fabricsegment.SwapDefault(mon)
	t.Cleanup(func() {
		mon.Stop()
		fabricsegment.SwapDefault(prev)
	})
	link := fabricsegment.Link{
		Name: "fab0", Parent: "ge-0-0-0", ParentIfindex: 4,
		LocalMAC: []byte{0x10, 0x66, 0x6a, 0, 0, 1},
		PeerMAC:  []byte{0x10, 0x66, 0x6a, 0, 0, 2},
	}
	mon.Update([]fabricsegment.Link{link})
	if got := mon.Watched(); len(got) != 1 {
		t.Fatalf("fixture watcher links = %v, want one armed fabric", got)
	}

	fixture := newCredentialTailFixture6790(t)
	fixture.d.cluster = cluster.NewManager(0, 1)
	fixture.d.daemonCtx = context.Background()
	fixture.d.startClusterCommsFn = func(context.Context) {}
	if fixture.d.clusterCommsEpochActive() || fixture.d.activeTransport() != (clusterTransportKey{}) {
		t.Fatal("premise: zero-key removal cell must start without an active comms epoch")
	}
	if err := fixture.d.applyTailReconciles(fixture.cfg, applyPhaseErrors{}); err != nil {
		t.Fatalf("applyTailReconciles after last-fabric removal: %v", err)
	}
	if got := mon.Watched(); len(got) != 0 {
		t.Fatalf("last-fabric removal left watcher armed without active comms: %v", got)
	}
}
