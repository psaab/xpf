package userspace

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fabricsegment"
)

// #18719: the watcher is fed the RESOLVED fabric identity, and a link whose
// peer MAC has not resolved yet is projected but not armable (every peer
// frame would otherwise read as foreign).
func TestFabricSegmentLinksProjectResolvedIdentity18719(t *testing.T) {
	links := fabricSegmentLinks([]FabricSnapshot{
		{Name: "fab0", ParentLinuxName: "ge-0-0-0", ParentIfindex: 4, LocalMAC: "10:66:6a:00:00:01", PeerMAC: "10:66:6a:00:00:02"},
		{Name: "fab1", ParentLinuxName: "ge-0-0-3", ParentIfindex: 7, LocalMAC: "10:66:6a:00:00:03", PeerMAC: ""},
	})
	if len(links) != 2 {
		t.Fatalf("links = %v, want 2", links)
	}
	got := links[0]
	if got.Name != "fab0" || got.Parent != "ge-0-0-0" || got.ParentIfindex != 4 ||
		got.LocalMAC.String() != "10:66:6a:00:00:01" || got.PeerMAC.String() != "10:66:6a:00:00:02" {
		t.Fatalf("fab0 projected as %+v", got)
	}
	if !fabricsegment.Armable(links[0]) {
		t.Fatal("a resolved fabric link must be armable")
	}
	if fabricsegment.Armable(links[1]) {
		t.Fatal("a fabric link with no resolved peer MAC must not be armable")
	}
}

// TestSyncFabricStateFeedsTheSegmentWatcher18719 (#18751 review): the
// refresh hands the process-wide watcher the exact resolved link (name,
// parent, ifindex, both MACs), and a refresh with no fabric empties it, so
// removing the fabric stops its tap.
func TestSyncFabricStateFeedsTheSegmentWatcher18719(t *testing.T) {
	mon := fabricsegment.NewMonitor(func(ctx context.Context, _ fabricsegment.Link, _ *fabricsegment.Tracker) error {
		<-ctx.Done()
		return nil
	})
	prev := fabricsegment.SwapDefault(mon)
	t.Cleanup(func() {
		mon.Stop()
		fabricsegment.SwapDefault(prev)
	})
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = "/nonexistent/xpf-18719-control.sock" // the helper send fails; the watcher is fed first
	m.lastSnapshot = &ConfigSnapshot{Version: ProtocolVersion, Generation: 1, Config: &config.Config{}}
	fabrics := []FabricSnapshot{{
		Name: "fab0", ParentInterface: "ge-0/0/0", ParentLinuxName: "ge-0-0-0", ParentIfindex: 4,
		LocalMAC: "10:66:6a:fe:d9:55", PeerMAC: "10:66:6a:3f:67:60", PeerAddress: "10.99.13.2", Up: true,
	}}
	m.fabricSnapshotBuilder = func(*config.Config) []FabricSnapshot { return fabrics }

	m.SyncFabricState()
	got := mon.Watched()
	if len(got) != 1 {
		t.Fatalf("watched links = %+v, want exactly fab0", got)
	}
	if l := got[0]; l.Name != "fab0" || l.Parent != "ge-0-0-0" || l.ParentIfindex != 4 ||
		l.LocalMAC.String() != "10:66:6a:fe:d9:55" || l.PeerMAC.String() != "10:66:6a:3f:67:60" {
		t.Fatalf("watched link = %+v", l)
	}

	fabrics = nil
	m.SyncFabricState()
	if got := mon.Watched(); len(got) != 0 {
		t.Fatalf("after the fabric was removed the watcher still watches %+v", got)
	}
}

// TestFabricPrivateLeafNeverReachesLinkAuthenticated18719 (#18751 review
// BLOCKING): the dataplane's per-link stamp-trust input is the #16023
// attestation alone. The #18719 private acknowledgement must never set it.
func TestFabricPrivateLeafNeverReachesLinkAuthenticated18719(t *testing.T) {
	build := func(private, authenticated bool) []FabricSnapshot {
		cfg := &config.Config{}
		cfg.Chassis.Cluster = &config.ClusterConfig{
			FabricInterface: "fab0", FabricPeerAddress: "10.99.13.2",
			Fabric1Interface: "fab1", Fabric1PeerAddress: "10.99.14.2",
			FabricLinkPrivate: private, Fabric1LinkPrivate: private,
			FabricLinkAuthenticated: authenticated, Fabric1LinkAuthenticated: authenticated,
		}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"fab0": {Name: "fab0", LocalFabricMember: "ge-0/0/0"},
			"fab1": {Name: "fab1", LocalFabricMember: "ge-0/0/3"},
		}
		return buildFabricSnapshotsFrom(cfg, nil)
	}
	private := build(true, false)
	if len(private) != 2 {
		t.Fatalf("snapshots = %+v, want fab0 and fab1", private)
	}
	for _, f := range private {
		if f.LinkAuthenticated {
			t.Fatalf("%s: the private acknowledgement reached LinkAuthenticated", f.Name)
		}
	}
	// Control: the real attestation does reach it, so the cell can fail.
	for _, f := range build(false, true) {
		if !f.LinkAuthenticated {
			t.Fatalf("%s: the #16023 attestation did not reach LinkAuthenticated (control)", f.Name)
		}
	}
}
