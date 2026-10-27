package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/ipsec"
)

// #17869 (Astra fold): a fabric epoch whose primary sync address never
// resolves returns at the address-debt arm before SetSyncTransport is ever
// published, so clearing liveness only in that setter leaves sticky
// heartbeat-derived peerAlive alive with no heartbeat running. Accepting the
// fabric comms epoch must invalidate it, independent of address resolution.
func TestFabricEpochUnresolvedPrimaryAddressClearsPeerAlive17869(t *testing.T) {
	exhaustSyncAddressPolls15687(t)
	// "xpf-nonexistent-15687" never resolves, so the primary poll exhausts.
	d := newVRFBindingRetryDaemon12168(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key 17869-test-cluster-psk",
		"set chassis cluster fabric-interface xpf-nonexistent-15687",
		"set chassis cluster fabric-peer-address 127.0.0.2",
		"set chassis cluster ipsec-session-synchronization",
	}, false)
	d.ipsec = ipsec.New()

	// Accepted heartbeat liveness from the prior control-link epoch.
	d.cluster.SetSyncTransport("control-link")
	d.cluster.HandlePeerHeartbeatForTesting(&cluster.HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []cluster.HeartbeatGroup{{
			GroupID:  0,
			Priority: 100,
			Weight:   255,
			State:    uint8(cluster.StateSecondary),
		}},
	})
	if !d.cluster.PeerAlive() {
		t.Fatal("precondition: accepted heartbeat must mark the peer alive")
	}

	d.startClusterComms(d.daemonCtx)
	waitVRFCommsConstructor12168(t, d)

	// Prove the unresolved-primary leg actually ran: no session sync was
	// published and the epoch carries address debt.
	if got := d.getSessionSync(); got != nil {
		t.Fatalf("session sync published despite unresolved primary address: %p", got)
	}
	if !d.activeTransport().BindingChanged {
		t.Fatal("premise: unresolved primary address must mark transport debt")
	}
	if d.cluster.HeartbeatRunning() {
		t.Fatal("premise: fabric epoch must not run a heartbeat")
	}
	if d.cluster.PeerAlive() {
		t.Fatal("#17869: PeerAlive() = true after an accepted fabric epoch with an unresolved primary address — sticky heartbeat liveness survived with no heartbeat running")
	}
}

func peerAliveManager17869(t *testing.T) *cluster.Manager {
	t.Helper()
	m := cluster.NewManager(0, 1)
	t.Cleanup(m.Stop)
	m.HandlePeerHeartbeatForTesting(&cluster.HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []cluster.HeartbeatGroup{{
			GroupID:  0,
			Priority: 100,
			Weight:   255,
			State:    uint8(cluster.StateSecondary),
		}},
	})
	if !m.PeerAlive() {
		t.Fatal("fixture: accepted heartbeat failed to mark peer alive")
	}
	return m
}

func TestStaleFabricAndCurrentControlLinkEpochKeepPeerAlive17869(t *testing.T) {
	m := peerAliveManager17869(t)
	d := &Daemon{cluster: m}

	_, staleGen, cancelStale := d.beginClusterCommsEpoch(context.Background())
	defer cancelStale()
	_, currentGen, cancelCurrent := d.beginClusterCommsEpoch(context.Background())
	defer cancelCurrent()

	fabric := clusterTransportKey{
		FabricInterface:   "fab0",
		FabricPeerAddress: "192.0.2.2",
	}
	if d.setActiveTransportIfCurrent(staleGen, fabric) {
		t.Fatal("superseded fabric epoch must not be accepted")
	}
	if !m.PeerAlive() {
		t.Fatal("superseded fabric epoch cleared current peer liveness")
	}

	control := clusterTransportKey{
		ControlInterface: "em0",
		PeerAddress:      "192.0.2.2",
	}
	if !d.setActiveTransportIfCurrent(currentGen, control) {
		t.Fatal("current control-link epoch was unexpectedly refused")
	}
	if !m.PeerAlive() {
		t.Fatal("control-link epoch must preserve liveness from accepted heartbeat")
	}
}
