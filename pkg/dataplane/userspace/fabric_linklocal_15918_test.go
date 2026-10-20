package userspace

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// #15918: the daemon's fab0/fab1 link-local fallback accepts a sole (or
// identity-matched) parent IPv6 link-local neighbour and latches
// fabricPopulated, but the LIVE userspace resolver buildFabricPeerMAC only
// looked up the configured peer IP. With an IPv4 peer (10.99.14.2) unresolved
// and only fe80::b present, it published PeerMAC="" — Rust then skips the
// fabric as UnresolvedPeerMac while the daemon claims fabric-ready.

const (
	peerV4_15918   = "10.99.14.2"
	localMAC_15918 = "02:00:00:00:00:0a"
	peerMAC_15918  = "02:00:00:00:00:0b"
	decoyMAC_15918 = "02:00:00:00:00:99"
)

func neigh15918(t *testing.T, ip, mac string) netlink.Neigh {
	t.Helper()
	m, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", mac, err)
	}
	return netlink.Neigh{IP: net.ParseIP(ip), HardwareAddr: m, State: netlink.NUD_REACHABLE}
}

func TestBuildFabricPeerMACLinkLocalFallback15918(t *testing.T) {
	local := mustMAC7443(t, localMAC_15918)

	t.Run("sole parent link-local resolves IPv4 peer", func(t *testing.T) {
		stubFabricNeighList(t, map[int][]netlink.Neigh{
			parentIfindex7443: {neigh15918(t, "fe80::b", peerMAC_15918)},
		}, nil)
		// Stub returns same table regardless of family; resolver must query
		// parent V6 after V4 address-match misses.
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_15918, local, nil); got != peerMAC_15918 {
			t.Fatalf("buildFabricPeerMAC = %q, want link-local peer %q (#15918)", got, peerMAC_15918)
		}
	})

	t.Run("known identity picks peer among decoys", func(t *testing.T) {
		stubFabricNeighList(t, map[int][]netlink.Neigh{
			parentIfindex7443: {
				neigh15918(t, "fe80::dec0", decoyMAC_15918),
				neigh15918(t, "fe80::b", peerMAC_15918),
			},
		}, nil)
		hint := mustMAC7443(t, peerMAC_15918)
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_15918, local, hint); got != peerMAC_15918 {
			t.Fatalf("buildFabricPeerMAC = %q, want identity-matched %q", got, peerMAC_15918)
		}
	})

	t.Run("ambiguous without identity refused", func(t *testing.T) {
		stubFabricNeighList(t, map[int][]netlink.Neigh{
			parentIfindex7443: {
				neigh15918(t, "fe80::dec0", decoyMAC_15918),
				neigh15918(t, "fe80::b", peerMAC_15918),
			},
		}, nil)
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_15918, local, nil); got != "" {
			t.Fatalf("buildFabricPeerMAC = %q, want \"\" on ambiguous segment", got)
		}
	})

	t.Run("lone decoy refused when identity known", func(t *testing.T) {
		stubFabricNeighList(t, map[int][]netlink.Neigh{
			parentIfindex7443: {neigh15918(t, "fe80::dec0", decoyMAC_15918)},
		}, nil)
		hint := mustMAC7443(t, peerMAC_15918)
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_15918, local, hint); got != "" {
			t.Fatalf("buildFabricPeerMAC = %q, want \"\" for lone decoy with known identity", got)
		}
	})

	t.Run("address matched still wins over link-local", func(t *testing.T) {
		stubFabricNeighList(t, map[int][]netlink.Neigh{
			overlayIfindex7443: {neigh15918(t, peerV4_15918, peerMAC_15918)},
			parentIfindex7443:  {neigh15918(t, "fe80::dec0", decoyMAC_15918)},
		}, nil)
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_15918, local, nil); got != peerMAC_15918 {
			t.Fatalf("buildFabricPeerMAC = %q, want address-matched %q", got, peerMAC_15918)
		}
	})

	t.Run("self link-local excluded sole other still resolves", func(t *testing.T) {
		stubFabricNeighList(t, map[int][]netlink.Neigh{
			parentIfindex7443: {
				neigh15918(t, "fe80::a", localMAC_15918),
				neigh15918(t, "fe80::b", peerMAC_15918),
			},
		}, nil)
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_15918, local, nil); got != peerMAC_15918 {
			t.Fatalf("buildFabricPeerMAC = %q, want %q (self excluded, sole peer remains)", got, peerMAC_15918)
		}
	})

	t.Run("IPv6 peer does not use link-local fallback for itself", func(t *testing.T) {
		// Peer is itself link-local: address match is the identity; ensure
		// normal path still works.
		stubFabricNeighList(t, map[int][]netlink.Neigh{
			parentIfindex7443: {neigh15918(t, "fe80::2", peerMAC_15918)},
		}, nil)
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, "fe80::2", local, nil); got != peerMAC_15918 {
			t.Fatalf("buildFabricPeerMAC = %q, want %q", got, peerMAC_15918)
		}
	})
}

func TestSelectFabricPeerLinkLocalMACShared15918(t *testing.T) {
	local := mustMAC7443(t, localMAC_15918)
	neighs := []netlink.Neigh{
		neigh15918(t, "fe80::dec0", decoyMAC_15918),
		neigh15918(t, "fe80::b", peerMAC_15918),
		neigh15918(t, "fe80::b2", peerMAC_15918), // same MAC, second LL addr: dedup
	}
	mac, _, n, reason := SelectFabricPeerLinkLocalMAC(neighs, local, mustMAC7443(t, peerMAC_15918))
	if mac == nil || mac.String() != peerMAC_15918 || reason != "" {
		t.Fatalf("SelectFabricPeerLinkLocalMAC known = %v n=%d reason=%q, want peer", mac, n, reason)
	}
	if n != 2 {
		t.Fatalf("candidates = %d, want 2 distinct MACs", n)
	}
	mac, _, _, reason = SelectFabricPeerLinkLocalMAC(neighs, local, nil)
	if mac != nil || reason == "" {
		t.Fatalf("ambiguous without identity = %v reason=%q, want refusal", mac, reason)
	}
	// Multicast MAC excluded.
	bad := neigh15918(t, "fe80::c", peerMAC_15918)
	bad.HardwareAddr = net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}
	mac, _, _, _ = SelectFabricPeerLinkLocalMAC([]netlink.Neigh{bad}, local, nil)
	if mac != nil {
		t.Fatalf("multicast MAC accepted: %v", mac)
	}
	_ = net.ParseIP
}
