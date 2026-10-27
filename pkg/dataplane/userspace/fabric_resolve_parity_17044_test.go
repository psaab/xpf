package userspace

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// #17044 parity: ResolveFabricPeer (the daemon readiness input) must agree
// with buildFabricPeerMAC (the helper's FabricSnapshot.PeerMAC source) on
// every table, because they are now the same resolver. Pre-fix the daemon
// resolved through its own copy in pkg/daemon and latched readiness on a
// fabric_fwd map write nobody read, while the helper resolved separately
// (#15918 was one divergence). These cells drive the divergent tables the
// issue names through BOTH entry points and assert agreement.
func neighRow(t *testing.T, ip, mac string) netlink.Neigh {
	t.Helper()
	return netlink.Neigh{IP: net.ParseIP(ip), HardwareAddr: mustMAC7443(t, mac), State: netlink.NUD_REACHABLE}
}

func TestResolveFabricPeerParity17044(t *testing.T) {
	local := mustMAC7443(t, "02:00:00:00:00:0a")
	peerMAC := "02:00:00:00:00:0b"
	decoyMAC := "02:00:00:00:00:99"

	t.Run("overlay list error falls through to parent", func(t *testing.T) {
		byIdx := map[int][]netlink.Neigh{
			parentIfindex7443: {neighRow(t, peerV4_7443, peerMAC)},
		}
		fail := map[int]bool{overlayIfindex7443: true}
		stubFabricNeighList(t, byIdx, fail)
		res := ResolveFabricPeer(overlayIfindex7443, parentIfindex7443, peerV4_7443, local)
		live := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_7443, local, nil)
		if res.PeerMAC.String() != peerMAC || live != peerMAC {
			t.Fatalf("overlay-error: ResolveFabricPeer=%v buildFabricPeerMAC=%q, want %s from parent", res.PeerMAC, live, peerMAC)
		}
	})

	t.Run("link-local peer uses address match not fallback", func(t *testing.T) {
		byIdx := map[int][]netlink.Neigh{
			overlayIfindex7443: {neighRow(t, "fe80::2", peerMAC)},
			parentIfindex7443:  {neighRow(t, "fe80::dec0", decoyMAC)},
		}
		stubFabricNeighList(t, byIdx, nil)
		res := ResolveFabricPeer(overlayIfindex7443, parentIfindex7443, "fe80::2", local)
		live := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, "fe80::2", local, nil)
		if res.PeerMAC.String() != peerMAC || live != peerMAC {
			t.Fatalf("link-local peer: ResolveFabricPeer=%v buildFabricPeerMAC=%q, want %s", res.PeerMAC, live, peerMAC)
		}
	})

	t.Run("missing overlay still resolves via parent", func(t *testing.T) {
		byIdx := map[int][]netlink.Neigh{
			parentIfindex7443: {neighRow(t, peerV4_7443, peerMAC)},
		}
		stubFabricNeighList(t, byIdx, nil)
		res := ResolveFabricPeer(0, parentIfindex7443, peerV4_7443, local)
		live := buildFabricPeerMAC(0, parentIfindex7443, peerV4_7443, local, nil)
		if res.PeerMAC.String() != peerMAC || live != peerMAC {
			t.Fatalf("missing overlay: ResolveFabricPeer=%v buildFabricPeerMAC=%q, want %s", res.PeerMAC, live, peerMAC)
		}
	})

	t.Run("ambiguous link-local segment unresolved in both", func(t *testing.T) {
		byIdx := map[int][]netlink.Neigh{
			parentIfindex7443: {neighRow(t, "fe80::dec0", decoyMAC), neighRow(t, "fe80::b", peerMAC)},
		}
		stubFabricNeighList(t, byIdx, nil)
		res := ResolveFabricPeer(overlayIfindex7443, parentIfindex7443, peerV4_7443, local)
		live := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_7443, local, nil)
		if len(res.PeerMAC) != 0 || res.Reason == "" || live != "" {
			t.Fatalf("ambiguous: ResolveFabricPeer=%v/%q buildFabricPeerMAC=%q, want both unresolved", res.PeerMAC, res.Reason, live)
		}
	})
}
