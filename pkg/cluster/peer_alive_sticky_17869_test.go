package cluster

import "testing"

// #17869: PeerAlive must not report a peer alive when no heartbeat is
// running. handlePeerHeartbeat sets the sticky peerAlive flag, but in
// fabric-transport mode the daemon never launches a heartbeat
// (daemon_ha_sync.go gates StartHeartbeat on control-interface+peer-address),
// so no handlePeerTimeout ever clears it. A peer heartbeat-seen before a
// mode/config transition to fabric therefore kept PeerAlive()==true forever
// after the peer died, keeping the peer-alive fabric/readiness gates shut.
//
// Production sequence reproduced: HandlePeerHeartbeatForTesting (accepted
// heartbeat) -> StopHeartbeat (comms teardown) -> SetSyncTransport("fabric")
// (the value daemon wiring publishes for fabric mode).
func TestPeerAliveNotStickyWithoutHeartbeat17869(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200, 1: 100}))
	m.UpdateConfig(cfg)
	<-m.Events()

	m.HandlePeerHeartbeatForTesting(&HeartbeatPacket{
		NodeID:            1,
		ClusterID:         1,
		HAProtocolVersion: CurrentHAProtocolVersion,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
		},
	})
	if !m.PeerAlive() {
		t.Fatal("setup: peer should be alive after an accepted heartbeat")
	}

	m.StopHeartbeat()
	m.SetSyncTransport("fabric")

	if m.HeartbeatRunning() {
		t.Fatal("setup: heartbeat must not be running after StopHeartbeat")
	}
	if m.PeerAlive() {
		t.Fatal("#17869: PeerAlive() = true with no heartbeat running in fabric transport — sticky peerAlive survives into a mode with no heartbeat path")
	}

	// Control: a fresh fabric-mode Manager reports no live peer.
	fresh := NewManager(0, 1)
	fresh.SetSyncTransport("fabric")
	if fresh.PeerAlive() {
		t.Fatal("control: fresh fabric Manager must report PeerAlive() = false")
	}
}
