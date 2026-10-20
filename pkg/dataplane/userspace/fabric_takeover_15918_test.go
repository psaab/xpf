package userspace

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15918: takeover must not be ready when the only fabric row cannot install
// (empty PeerMAC) or when update_fabrics is unconverged.

func healthyFabricManager15918(t *testing.T, fabrics []FabricSnapshot) *Manager {
	t.Helper()
	return &Manager{
		proc:      &exec.Cmd{Process: &os.Process{Pid: 1}},
		clusterHA: true,
		lastStatus: ProcessStatus{
			Enabled:         true,
			ForwardingArmed: true,
			Capabilities:    UserspaceCapabilities{ForwardingSupported: true},
		},
		mode:              ModeUserspaceCompat,
		xskLivenessProven: true,
		eventStream:       boundEventStream(t),
		lastSnapshot:      &ConfigSnapshot{Fabrics: fabrics},
	}
}

func TestTakeoverReadyFabricInstallable15918(t *testing.T) {
	installableFab1 := FabricSnapshot{Name: "fab1", ParentIfindex: 21, PeerAddress: peerV4_15918, LocalMAC: localMAC_15918, PeerMAC: peerMAC_15918}
	t.Run("unresolved peer blocked", func(t *testing.T) {
		m := healthyFabricManager15918(t, []FabricSnapshot{{Name: "fab1", ParentIfindex: 21, PeerAddress: peerV4_15918, LocalMAC: localMAC_15918, PeerMAC: ""}})
		ready, reasons := m.TakeoverReady()
		if ready {
			t.Fatalf("ready=true with unresolved fabric peer, reasons=%v", reasons)
		}
		if !strings.Contains(strings.Join(reasons, ";"), "fabric peer unresolved") {
			t.Fatalf("reasons=%v, want fabric peer unresolved", reasons)
		}
		found := false
		for _, b := range m.HATakeoverReadiness().Blockers {
			if b == "fabric_peer_unresolved" {
				found = true
			}
		}
		if !found {
			t.Fatalf("blockers missing fabric_peer_unresolved")
		}
	})

	t.Run("resolved peer ready", func(t *testing.T) {
		m := healthyFabricManager15918(t, []FabricSnapshot{installableFab1})
		if ready, reasons := m.TakeoverReady(); !ready {
			t.Fatalf("ready=false with resolved fabric, reasons=%v", reasons)
		}
	})

	t.Run("missing local MAC blocked", func(t *testing.T) {
		row := installableFab1
		row.LocalMAC = ""
		m := healthyFabricManager15918(t, []FabricSnapshot{row})
		if ready, reasons := m.TakeoverReady(); ready {
			t.Fatalf("ready=true with empty LocalMAC (Rust UnresolvedLocalMac), reasons=%v", reasons)
		}
	})

	t.Run("malformed peer MAC blocked", func(t *testing.T) {
		row := installableFab1
		row.PeerMAC = "not-a-mac"
		m := healthyFabricManager15918(t, []FabricSnapshot{row})
		if ready, _ := m.TakeoverReady(); ready {
			t.Fatal("ready=true with malformed PeerMAC")
		}
	})

	t.Run("unparseable peer address blocked", func(t *testing.T) {
		row := installableFab1
		row.PeerAddress = "not-an-ip"
		m := healthyFabricManager15918(t, []FabricSnapshot{row})
		if ready, _ := m.TakeoverReady(); ready {
			t.Fatal("ready=true with unparseable PeerAddress")
		}
	})

	t.Run("one installable among two suffices", func(t *testing.T) {
		m := healthyFabricManager15918(t, []FabricSnapshot{
			{Name: "fab0", ParentIfindex: 11, PeerAddress: peerV4_15918, LocalMAC: localMAC_15918, PeerMAC: ""},
			installableFab1,
		})
		if ready, reasons := m.TakeoverReady(); !ready {
			t.Fatalf("ready=false with fab1 installable, reasons=%v", reasons)
		}
	})

	t.Run("partial fabrics debt blocked even if resolved", func(t *testing.T) {
		m := healthyFabricManager15918(t, []FabricSnapshot{installableFab1})
		m.partialOutcomeUnknown = partialFabrics
		ready, reasons := m.TakeoverReady()
		if ready {
			t.Fatalf("ready=true with partialFabrics debt, reasons=%v", reasons)
		}
		if !strings.Contains(strings.Join(reasons, ";"), "fabric state not converged") {
			t.Fatalf("reasons=%v, want fabric state not converged", reasons)
		}
	})

	t.Run("no fabric rows and no config unaffected", func(t *testing.T) {
		m := healthyFabricManager15918(t, nil)
		if ready, reasons := m.TakeoverReady(); !ready {
			t.Fatalf("ready=false with no fabrics, reasons=%v", reasons)
		}
	})

	t.Run("configured fabric with zero rows blocked", func(t *testing.T) {
		m := healthyFabricManager15918(t, nil)
		cfg := &config.Config{}
		cfg.Chassis.Cluster = &config.ClusterConfig{FabricInterface: "fab0", FabricPeerAddress: peerV4_15918}
		m.lastSnapshot.Config = cfg
		if ready, reasons := m.TakeoverReady(); ready {
			t.Fatalf("ready=true with configured fab0 but zero rows, reasons=%v", reasons)
		}
	})

	t.Run("config naming no fabric stays ready with zero rows", func(t *testing.T) {
		m := healthyFabricManager15918(t, nil)
		cfg := &config.Config{}
		cfg.Chassis.Cluster = &config.ClusterConfig{}
		m.lastSnapshot.Config = cfg
		if ready, reasons := m.TakeoverReady(); !ready {
			t.Fatalf("ready=false with cluster config naming no fabric, reasons=%v", reasons)
		}
	})

	t.Run("non-cluster unaffected unresolved", func(t *testing.T) {
		m := healthyFabricManager15918(t, []FabricSnapshot{{Name: "fab1", ParentIfindex: 21, PeerMAC: ""}})
		m.clusterHA = false
		if ready, reasons := m.TakeoverReady(); !ready {
			t.Fatalf("ready=false non-cluster, reasons=%v", reasons)
		}
	})
}
