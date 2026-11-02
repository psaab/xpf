package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fabricsegment"
)

// TestClusterFabricRemovalStopsWatcher18719 exercises the real daemon apply
// path: removing the last configured fabric must retire the process-wide
// watcher before any transport-reconcile early return or peer resolution.
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

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.applyBodyForTest = func(*config.Config) {}
	if err := d.applyConfigLocked(context.Background(), &config.Config{}); err != nil {
		t.Fatalf("applyConfigLocked after last-fabric removal: %v", err)
	}
	if got := mon.Watched(); len(got) != 0 {
		t.Fatalf("last-fabric removal left watcher armed: %v", got)
	}
}
