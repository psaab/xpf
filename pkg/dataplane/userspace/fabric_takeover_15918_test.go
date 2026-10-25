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

// #16844: the #15918 fabric clause must not apply while the peer is down.
// A lone surviving node whose peer is confirmed absent has no fabric
// peer to resolve; pre-fix TakeoverReady (the only form) returned
// fabric_peer_unresolved and the daemon held every data RG secondary
// until the 2m degraded fallback. The peer-alive form must stay blocked.
func TestTakeoverReadyFabricPeerDown16844(t *testing.T) {
	unresolved := []FabricSnapshot{{Name: "fab1", ParentIfindex: 21, PeerAddress: peerV4_15918, LocalMAC: localMAC_15918, PeerMAC: ""}}
	installable := []FabricSnapshot{{Name: "fab1", ParentIfindex: 21, PeerAddress: peerV4_15918, LocalMAC: localMAC_15918, PeerMAC: peerMAC_15918}}

	t.Run("peer down unresolved fabric ready", func(t *testing.T) {
		m := healthyFabricManager15918(t, unresolved)
		if ready, reasons := m.TakeoverReadyForPeer(false); !ready {
			t.Fatalf("peer-down ready=false with unresolved fabric, reasons=%v (#16844)", reasons)
		}
		if _, reasons := m.TakeoverReadyForPeer(false); strings.Contains(strings.Join(reasons, ";"), "fabric") {
			t.Fatalf("peer-down reasons still name fabric: %v", reasons)
		}
	})

	t.Run("peer alive unresolved fabric still blocked (control)", func(t *testing.T) {
		m := healthyFabricManager15918(t, unresolved)
		ready, reasons := m.TakeoverReadyForPeer(true)
		if ready {
			t.Fatalf("peer-alive ready=true with unresolved fabric, reasons=%v (#15918 must stay)", reasons)
		}
		if !strings.Contains(strings.Join(reasons, ";"), "fabric peer unresolved") {
			t.Fatalf("peer-alive reasons=%v, want fabric peer unresolved", reasons)
		}
		// The no-arg form stays the peer-alive form.
		if ready, _ := m.TakeoverReady(); ready {
			t.Fatal("TakeoverReady() ready=true with unresolved fabric; want peer-alive default")
		}
	})

	t.Run("peer down installable fabric ready (control)", func(t *testing.T) {
		m := healthyFabricManager15918(t, installable)
		if ready, reasons := m.TakeoverReadyForPeer(false); !ready {
			t.Fatalf("peer-down ready=false with installable fabric, reasons=%v", reasons)
		}
	})

	t.Run("peer down configured fabric zero rows ready", func(t *testing.T) {
		m := healthyFabricManager15918(t, nil)
		cfg := &config.Config{}
		cfg.Chassis.Cluster = &config.ClusterConfig{FabricInterface: "fab0", FabricPeerAddress: peerV4_15918}
		m.lastSnapshot.Config = cfg
		if ready, reasons := m.TakeoverReadyForPeer(false); !ready {
			t.Fatalf("peer-down ready=false with configured fab0 but zero rows, reasons=%v (#16844)", reasons)
		}
	})

	t.Run("peer down partial fabrics debt ready", func(t *testing.T) {
		m := healthyFabricManager15918(t, installable)
		m.partialOutcomeUnknown = partialFabrics
		if ready, reasons := m.TakeoverReadyForPeer(false); !ready {
			t.Fatalf("peer-down ready=false with partialFabrics debt, reasons=%v (#16844)", reasons)
		}
		// Control: same debt still blocks while the peer is alive.
		if ready, reasons := m.TakeoverReadyForPeer(true); ready {
			t.Fatalf("peer-alive ready=true with partialFabrics debt, reasons=%v", reasons)
		}
	})

	t.Run("peer down local gates still block (control)", func(t *testing.T) {
		m := healthyFabricManager15918(t, unresolved)
		m.sessionMirrorFailed = true
		if ready, reasons := m.TakeoverReadyForPeer(false); ready {
			t.Fatalf("peer-down ready=true with session mirror failed, reasons=%v — only the fabric clause is peer-exempt", reasons)
		}
	})
}
