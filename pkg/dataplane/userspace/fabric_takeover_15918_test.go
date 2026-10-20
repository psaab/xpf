package userspace

import (
	"os"
	"os/exec"
	"strings"
	"testing"
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
	t.Run("unresolved peer blocked", func(t *testing.T) {
		m := healthyFabricManager15918(t, []FabricSnapshot{{Name: "fab1", ParentIfindex: 21, PeerMAC: ""}})
		ready, reasons := m.TakeoverReady()
		if ready {
			t.Fatalf("ready=true with unresolved fabric peer, reasons=%v", reasons)
		}
		if !strings.Contains(strings.Join(reasons, ";"), "fabric peer unresolved") {
			t.Fatalf("reasons=%v, want fabric peer unresolved", reasons)
		}
		if s := m.HATakeoverReadiness(); len(s.Blockers) == 0 || s.Blockers[len(s.Blockers)-1] != "fabric_peer_unresolved" {
			// blocker may not be last if other reasons; just check presence
			found := false
			for _, b := range s.Blockers {
				if b == "fabric_peer_unresolved" {
					found = true
				}
			}
			if !found {
				t.Fatalf("blockers=%v, want fabric_peer_unresolved", s.Blockers)
			}
		}
	})

	t.Run("resolved peer ready", func(t *testing.T) {
		m := healthyFabricManager15918(t, []FabricSnapshot{{Name: "fab1", ParentIfindex: 21, PeerMAC: peerMAC_15918}})
		ready, reasons := m.TakeoverReady()
		if !ready {
			t.Fatalf("ready=false with resolved fabric, reasons=%v", reasons)
		}
	})

	t.Run("one installable among two suffices", func(t *testing.T) {
		m := healthyFabricManager15918(t, []FabricSnapshot{
			{Name: "fab0", ParentIfindex: 11, PeerMAC: ""},
			{Name: "fab1", ParentIfindex: 21, PeerMAC: peerMAC_15918},
		})
		if ready, reasons := m.TakeoverReady(); !ready {
			t.Fatalf("ready=false with fab1 installable, reasons=%v", reasons)
		}
	})

	t.Run("partial fabrics debt blocked even if resolved", func(t *testing.T) {
		m := healthyFabricManager15918(t, []FabricSnapshot{{Name: "fab1", ParentIfindex: 21, PeerMAC: peerMAC_15918}})
		m.partialOutcomeUnknown = partialFabrics
		ready, reasons := m.TakeoverReady()
		if ready {
			t.Fatalf("ready=true with partialFabrics debt, reasons=%v", reasons)
		}
		if !strings.Contains(strings.Join(reasons, ";"), "fabric state not converged") {
			t.Fatalf("reasons=%v, want fabric state not converged", reasons)
		}
	})

	t.Run("no fabric rows unaffected", func(t *testing.T) {
		m := healthyFabricManager15918(t, nil)
		if ready, reasons := m.TakeoverReady(); !ready {
			t.Fatalf("ready=false with no fabrics, reasons=%v", reasons)
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
