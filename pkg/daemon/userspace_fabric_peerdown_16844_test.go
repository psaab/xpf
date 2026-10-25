package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #16844: the #15918 userspace fabric-installability term must not apply
// while the HA peer is down. On a cold boot where the peer is confirmed
// absent (never seen), PeerMAC="" held every data RG secondary until
// the cluster's 2m degraded fallback promoted it as DEGRADED. The twin
// with the peer alive must stay blocked with fabric_peer_unresolved.

// fabricPeerDP16844 is a userspace backend whose fabric peer never
// resolves (PeerMAC=""), mirroring TakeoverReadyForPeer via a stub so
// the daemon wiring — not the Manager predicate — is what varies here.
// The Manager predicate itself is pinned in
// TestTakeoverReadyFabricPeerDown16844 (pkg/dataplane/userspace).
type fabricPeerDP16844 struct{ *dataplane.Manager }

func newFabricPeerDP16844() *fabricPeerDP16844 {
	return &fabricPeerDP16844{Manager: dataplane.New()}
}

func (r *fabricPeerDP16844) Mode() dpuserspace.DataplaneMode {
	return dpuserspace.ModeUserspaceCompat
}

// TakeoverReady is the peer-alive form: unresolved fabric blocks.
func (r *fabricPeerDP16844) TakeoverReady() (bool, []string) {
	return false, []string{"userspace fabric peer unresolved (no installable fabric link)"}
}

// TakeoverReadyForPeer exempts the fabric clause when the peer is down.
func (r *fabricPeerDP16844) TakeoverReadyForPeer(peerAlive bool) (bool, []string) {
	if !peerAlive {
		return true, nil
	}
	return r.TakeoverReady()
}

func fabricPeerDaemon16844(t *testing.T) *Daemon {
	t.Helper()
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-16844",
		"set chassis cluster node 0",
		"set chassis cluster no-reth-vrrp",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
	})
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cm.Start(ctx)
	d := &Daemon{
		rgStates:       make(map[int]*rgStateMachine),
		cluster:        cm,
		store:          store,
		vrrpMgr:        vrrp.NewManager(),
		reconcileNowCh: make(chan struct{}, 1),
		linkByNameFn:   mockLinkByName(map[string]*testLink{"ge-0-0-0": newTestLink("ge-0-0-0", true)}),
	}
	d.setDataplane(newFabricPeerDP16844())
	return d
}

func TestUserspaceFabricPeerDownPromotes16844(t *testing.T) {
	d := fabricPeerDaemon16844(t)
	if d.cluster.PeerAlive() {
		t.Fatal("precondition: peer must never be seen in the cold-boot cell")
	}
	ready, reasons := rgReadiness(t, d)
	if !ready {
		t.Fatalf("peer never seen + unresolved fabric: RG must be ready, got reasons=%v (#16844)", reasons)
	}
	for _, r := range reasons {
		if strings.Contains(r, "fabric peer unresolved") {
			t.Fatalf("peer-down readiness still carries the fabric reason: %v", reasons)
		}
	}
}

func TestUserspaceFabricPeerAliveBlocked16844(t *testing.T) {
	d := fabricPeerDaemon16844(t)
	// Peer alive via the real heartbeat admission path (as in #15683).
	d.cluster.HandlePeerHeartbeatForTesting(&cluster.HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []cluster.HeartbeatGroup{{
			GroupID:  0,
			Priority: 100,
			Weight:   100,
			State:    uint8(cluster.StatePrimary),
		}},
	})
	if !d.cluster.PeerAlive() {
		t.Fatal("precondition: PeerAlive must be true for the control cell")
	}
	ready, reasons := rgReadiness(t, d)
	if ready {
		t.Fatalf("peer alive + unresolved fabric: RG must stay blocked (#15918), reasons=%v", reasons)
	}
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "fabric peer unresolved") {
			found = true
		}
	}
	if !found {
		t.Fatalf("peer-alive reasons=%v, want fabric peer unresolved", reasons)
	}
}

// Legacy backends implementing only TakeoverReady() keep the fail-closed
// peer-alive form even when the peer is down: the exemption must never
// be assumed for a backend that cannot express it.
type fabricLegacyDP16844 struct{ *dataplane.Manager }

func (r *fabricLegacyDP16844) Mode() dpuserspace.DataplaneMode {
	return dpuserspace.ModeUserspaceCompat
}
func (r *fabricLegacyDP16844) TakeoverReady() (bool, []string) {
	return false, []string{"userspace fabric peer unresolved (no installable fabric link)"}
}

func TestUserspaceFabricLegacyBackendStaysBlocked16844(t *testing.T) {
	d := fabricPeerDaemon16844(t)
	d.setDataplane(&fabricLegacyDP16844{Manager: dataplane.New()})
	if d.cluster.PeerAlive() {
		t.Fatal("precondition: peer must be down")
	}
	ready, _ := rgReadiness(t, d)
	if ready {
		t.Fatal("legacy TakeoverReady-only backend must stay blocked peer-down (fail-closed)")
	}
}
