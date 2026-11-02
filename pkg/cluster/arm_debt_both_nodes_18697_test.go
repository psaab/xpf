package cluster

import "testing"

// #18697/#18685: when BOTH nodes' helpers look suspect at once (both carry the
// dataplane-arm debt), the RG must stay where it is. Arm debt yields only to a
// peer with GREATER raw weight, so equal debt must never move ownership or
// ping-pong it frame to frame. And once only one node is suspect, ownership
// moves at most once, to the healthy node, and stays.
func TestBothNodesArmDebtDoesNotPingPong18697(t *testing.T) {
	type obs struct{ owner, peer bool }
	run := func(owner, peer *Manager, rounds int) (transitions, dual int, last obs) {
		last = obs{owner.IsLocalPrimary(1), peer.IsLocalPrimary(1)}
		for range rounds {
			owner.handlePeerHeartbeat(peer.buildHeartbeat())
			peer.handlePeerHeartbeat(owner.buildHeartbeat())
			now := obs{owner.IsLocalPrimary(1), peer.IsLocalPrimary(1)}
			if now != last {
				transitions++
			}
			if now.owner && now.peer {
				dual++
			}
			last = now
		}
		return
	}
	t.Run("simultaneous", func(t *testing.T) {
		owner, peer := armDebtPair12164(t)
		// The secondary's debt lands first, so the owner never sees a
		// healthier peer: both are suspect from the owner's first look.
		peer.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
		owner.handlePeerHeartbeat(peer.buildHeartbeat())
		owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
		tr, dual, last := run(owner, peer, 10)
		if tr != 0 || dual != 0 || !last.owner || last.peer {
			t.Fatalf("both suspect: transitions=%d dual=%d final=%+v; the RG must stay on the owner", tr, dual, last)
		}
	})
	t.Run("owner-then-peer", func(t *testing.T) {
		owner, peer := armDebtPair12164(t)
		// The owner goes suspect first: one move, to the healthy peer.
		owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
		tr, dual, last := run(owner, peer, 10)
		if tr != 1 || dual != 0 || last.owner || !last.peer {
			t.Fatalf("owner suspect: transitions=%d dual=%d final=%+v; want one move to the peer", tr, dual, last)
		}
		// Then the new owner goes suspect too while the old one still is:
		// equal debt, so the RG must stay on the peer, not bounce back.
		peer.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
		tr, dual, last = run(owner, peer, 10)
		if tr != 0 || dual != 0 || last.owner || !last.peer {
			t.Fatalf("both suspect after a move: transitions=%d dual=%d final=%+v; the RG must stay on the peer", tr, dual, last)
		}
	})
}
