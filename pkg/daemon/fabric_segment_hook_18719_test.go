package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fabricsegment"
)

// TestConstructClusterManagerWiresTheFabricSegmentAlarms18719 (#18751
// review): cluster-manager construction installs the fabric-segment alarm
// source, and the installed source reads the CURRENT process-wide watcher,
// so its raised alarm reaches `show chassis cluster status`.
func TestConstructClusterManagerWiresTheFabricSegmentAlarms18719(t *testing.T) {
	trackers := make(chan *fabricsegment.Tracker, 1)
	mon := fabricsegment.NewMonitor(func(ctx context.Context, _ fabricsegment.Link, tr *fabricsegment.Tracker) error {
		trackers <- tr
		<-ctx.Done()
		return nil
	})
	d := &Daemon{}
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0, ClusterID: 1}
	if !d.constructClusterManager(cfg) {
		t.Fatal("constructClusterManager declined a cluster config")
	}
	if !d.cluster.InstalledHooks()[cluster.HookFabricSegmentAlarms] {
		t.Fatal("the fabric-segment alarm source is not installed at construction")
	}
	// Swapped AFTER construction: the installed source must read the
	// watcher at render time, not a monitor captured at boot.
	prev := fabricsegment.SwapDefault(mon)
	t.Cleanup(func() {
		mon.Stop()
		fabricsegment.SwapDefault(prev)
	})

	mon.Update([]fabricsegment.Link{{
		Name: "fab0", Parent: "ge-0-0-0", ParentIfindex: 4,
		LocalMAC: []byte{0x10, 0x66, 0x6a, 0, 0, 1}, PeerMAC: []byte{0x10, 0x66, 0x6a, 0, 0, 2},
	}})
	var tr *fabricsegment.Tracker
	select {
	case tr = <-trackers:
	case <-time.After(5 * time.Second):
		t.Fatal("the test watcher never started its sampler")
	}
	tr.Observe([]byte{0x18, 0xe8, 0x29, 0x2c, 0x13, 0x7a}, time.Now())

	got := d.cluster.FormatStatus()
	if !strings.Contains(got, "Warning: fabric link fab0 (ge-0-0-0) received") {
		t.Fatalf("the raised alarm of the current watcher is not rendered:\n%s", got)
	}
}
