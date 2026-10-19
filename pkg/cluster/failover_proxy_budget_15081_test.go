package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/clusterfailover"
)

// #15081: the failover proxy budget in pkg/clusterfailover duplicates
// this package's failoverAckTimeout (pkg/cluster cannot be imported
// from clusterfailover — cluster imports it for the grammar). Pin the
// copies together so a future change to the ACK cap cannot silently
// desize the proxy deadline.
func TestFailoverProxyBudgetMatchesAckTimeout15081(t *testing.T) {
	if clusterfailover.FailoverAckTimeout != failoverAckTimeout {
		t.Fatalf("clusterfailover.FailoverAckTimeout = %v, want failoverAckTimeout %v",
			clusterfailover.FailoverAckTimeout, failoverAckTimeout)
	}
	if want := 2*failoverAckTimeout + 2*clusterfailover.DefaultCommitSettle; clusterfailover.ProxyFailoverTimeout != want {
		t.Fatalf("ProxyFailoverTimeout = %v, want 2*ack + 2*settle = %v",
			clusterfailover.ProxyFailoverTimeout, want)
	}
	// The proxy budget must strictly cover one owner-side transfer-out
	// lease window (2*settle + 20s ACK cap at the defaults) — otherwise
	// a legitimate slow commit still trips the proxy deadline.
	if clusterfailover.ProxyFailoverTimeout <= DefaultRemoteTransferOutLease {
		t.Fatalf("ProxyFailoverTimeout = %v must exceed DefaultRemoteTransferOutLease %v",
			clusterfailover.ProxyFailoverTimeout, DefaultRemoteTransferOutLease)
	}
}

// #15081: PeerPrimaryRGs is the ownership oracle the proxy-timeout
// reconciliation reads. It must distinguish peer-unreachable (no
// verdict) from peer-reachable-and-not-primary, and exclude RG0.
func TestPeerPrimaryRGs15081(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, true, map[int]int{0: 100, 1: 90}),
		makeRG(1, true, map[int]int{0: 100, 1: 90}),
		makeRG(2, true, map[int]int{0: 100, 1: 90}),
	)
	m.UpdateConfig(cfg)

	// No heartbeat yet: unreachable, no verdict.
	if _, alive := m.PeerPrimaryRGs(); alive {
		t.Fatal("PeerPrimaryRGs peerAlive = true before any heartbeat, want false")
	}

	m.SetPeerGroupStateForTesting(1, StatePrimary)
	m.SetPeerGroupStateForTesting(2, StateSecondary)
	// RG0 peer-primary must be excluded (control plane, not a data RG).
	m.SetPeerGroupStateForTesting(0, StatePrimary)

	rgs, alive := m.PeerPrimaryRGs()
	if !alive {
		t.Fatal("PeerPrimaryRGs peerAlive = false with peer state set, want true")
	}
	if len(rgs) != 1 || rgs[0] != 1 {
		t.Fatalf("PeerPrimaryRGs = %v, want [1]", rgs)
	}
	if !m.IsPeerPrimary(1) || m.IsPeerPrimary(2) {
		t.Fatal("IsPeerPrimary inconsistent with PeerPrimaryRGs fixture")
	}
}
