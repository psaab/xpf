package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fabricsegment"
)

// TestClusterFabricRemovalStopsWatcher18719 exercises the daemon's config
// reconcile path, not SyncFabricState: removing the last configured fabric
// must retire the process-wide watcher even when no peer resolution follows.
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

	ctx := context.Background()
	d := &Daemon{
		cluster:            cluster.NewManager(0, 1),
		daemonCtx:          ctx,
		startClusterCommsFn: func(context.Context) {},
	}
	_, gen, _ := d.beginClusterCommsEpoch(ctx)
	if !d.setActiveTransportIfCurrent(gen, clusterTransportKey{
		ControlInterface: "em0", PeerAddress: "10.99.0.2", FabricInterface: "fab0",
	}) {
		t.Fatal("fixture failed to publish the active cluster transport")
	}

	// This is the daemon's normal apply-tail transport reconciliation for the
	// newly committed config after the last fabric is removed.
	d.reconcileClusterTransportBinding(&config.Config{}, false)
	if got := mon.Watched(); len(got) != 0 {
		t.Fatalf("last-fabric removal left watcher armed: %v", got)
	}
}
