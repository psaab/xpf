package userspace

import (
	"errors"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// #7443: bind buildFabricPeerMAC ITSELF, not just the helper it calls.
//
// #6598 hardened the fabric peer-MAC selection and covered it with a table over
// selectFabricPeerMAC plus an AST scan of pkg/daemon. Neither executed
// buildFabricPeerMAC, so reverting that function's body to the pre-#6598 inline
// loop -- the exact shipped defect -- passed `go vet` and both full suites.
// selectFabricPeerMAC went dead under the revert, but Go does not error on an
// unused package-level func and this repo runs no unused/staticcheck gate, so
// nothing complained.
//
// These tests drive the real resolver through the fabricNeighListFn seam. The
// fail-on-revert case is "a NUD_FAILED entry retaining the peer's old lladdr":
// with the pre-#6598 body restored, buildFabricPeerMAC returns the stale MAC
// and staleFabricMAC7443 shows up where "" is required.

const (
	peerV4_7443        = "10.99.0.2"
	peerV6_7443        = "fe80::2"
	staleFabricMAC7443 = "02:bf:72:cc:00:01" // the MAC the peer used to own
	liveFabricMAC7443  = "02:bf:72:cc:00:02" // the MAC it owns now
	otherFabricMAC7443 = "02:bf:72:cc:00:03"

	overlayIfindex7443 = 11
	parentIfindex7443  = 12
)

func mustMAC7443(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return mac
}

// stubFabricNeighList installs a per-ifindex neighbour table and records, in
// order, which ifindexes the resolver actually asked about.
func stubFabricNeighList(t *testing.T, byIfindex map[int][]netlink.Neigh, failFor map[int]bool) *[]int {
	t.Helper()
	var queried []int
	orig := fabricNeighListFn
	t.Cleanup(func() { fabricNeighListFn = orig })
	fabricNeighListFn = func(ifindex, family int) ([]netlink.Neigh, error) {
		queried = append(queried, ifindex)
		if failFor[ifindex] {
			return nil, errors.New("synthetic netlink failure")
		}
		return byIfindex[ifindex], nil
	}
	return &queried
}

func TestBuildFabricPeerMACRejectsStaleNeighbour_7443(t *testing.T) {
	ip := net.ParseIP(peerV4_7443)
	stale := mustMAC7443(t, staleFabricMAC7443)
	live := mustMAC7443(t, liveFabricMAC7443)

	cases := []struct {
		name    string
		overlay []netlink.Neigh
		want    string
	}{{
		// THE fail-on-revert case. Restoring the pre-#6598 body makes this
		// return staleFabricMAC7443.
		name:    "NUD_FAILED retaining the peer's old lladdr is not the redirect MAC",
		overlay: []netlink.Neigh{{IP: ip, HardwareAddr: stale, State: netlink.NUD_FAILED}},
		want:    "",
	}, {
		name:    "NUD_INCOMPLETE is not the redirect MAC",
		overlay: []netlink.Neigh{{IP: ip, HardwareAddr: stale, State: netlink.NUD_INCOMPLETE}},
		want:    "",
	}, {
		name:    "NUD_NONE is not the redirect MAC",
		overlay: []netlink.Neigh{{IP: ip, HardwareAddr: stale, State: 0}},
		want:    "",
	}, {
		name:    "a non-6-byte lladdr is not the redirect MAC",
		overlay: []netlink.Neigh{{IP: ip, HardwareAddr: net.HardwareAddr{0x02, 0xbf, 0x72}, State: netlink.NUD_REACHABLE}},
		want:    "",
	}, {
		// Positive control: without this, a resolver that returned "" for
		// everything would satisfy every case above.
		name:    "a REACHABLE entry for the peer IS the redirect MAC",
		overlay: []netlink.Neigh{{IP: ip, HardwareAddr: live, State: netlink.NUD_REACHABLE}},
		want:    liveFabricMAC7443,
	}, {
		name: "a stale entry listed ahead of the live one does not win",
		overlay: []netlink.Neigh{
			{IP: ip, HardwareAddr: stale, State: netlink.NUD_FAILED},
			{IP: ip, HardwareAddr: live, State: netlink.NUD_REACHABLE},
		},
		want: liveFabricMAC7443,
	}, {
		name:    "an entry for a different address never answers for the peer",
		overlay: []netlink.Neigh{{IP: net.ParseIP("10.99.0.3"), HardwareAddr: live, State: netlink.NUD_REACHABLE}},
		want:    "",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubFabricNeighList(t, map[int][]netlink.Neigh{
				overlayIfindex7443: tc.overlay,
			}, nil)
			got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_7443, nil, nil)
			if got != tc.want {
				t.Errorf("buildFabricPeerMAC = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBuildFabricPeerMACOverlayThenParent_7443 pins the two-ifindex fallback.
// A usable entry may live on the parent while the overlay holds only an
// unusable one — that is precisely the RETH-reprogramming window this resolver
// has to survive — so rejecting the overlay entry must not end the search.
func TestBuildFabricPeerMACOverlayThenParent_7443(t *testing.T) {
	ip := net.ParseIP(peerV4_7443)
	stale := mustMAC7443(t, staleFabricMAC7443)
	live := mustMAC7443(t, liveFabricMAC7443)
	other := mustMAC7443(t, otherFabricMAC7443)

	t.Run("unusable on overlay falls through to a usable parent entry", func(t *testing.T) {
		queried := stubFabricNeighList(t, map[int][]netlink.Neigh{
			overlayIfindex7443: {{IP: ip, HardwareAddr: stale, State: netlink.NUD_FAILED}},
			parentIfindex7443:  {{IP: ip, HardwareAddr: live, State: netlink.NUD_STALE}},
		}, nil)
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_7443, nil, nil); got != liveFabricMAC7443 {
			t.Errorf("buildFabricPeerMAC = %q, want the parent's %q", got, liveFabricMAC7443)
		}
		if len(*queried) != 2 {
			t.Errorf("queried ifindexes %v, want both overlay and parent consulted", *queried)
		}
	})

	t.Run("a usable overlay entry wins and the parent is never consulted", func(t *testing.T) {
		queried := stubFabricNeighList(t, map[int][]netlink.Neigh{
			overlayIfindex7443: {{IP: ip, HardwareAddr: live, State: netlink.NUD_REACHABLE}},
			parentIfindex7443:  {{IP: ip, HardwareAddr: other, State: netlink.NUD_REACHABLE}},
		}, nil)
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_7443, nil, nil); got != liveFabricMAC7443 {
			t.Errorf("buildFabricPeerMAC = %q, want the overlay's %q", got, liveFabricMAC7443)
		}
		if len(*queried) != 1 || (*queried)[0] != overlayIfindex7443 {
			t.Errorf("queried ifindexes %v, want only the overlay (%d)", *queried, overlayIfindex7443)
		}
	})

	t.Run("a netlink failure on the overlay does not abandon the parent", func(t *testing.T) {
		stubFabricNeighList(t, map[int][]netlink.Neigh{
			parentIfindex7443: {{IP: ip, HardwareAddr: live, State: netlink.NUD_REACHABLE}},
		}, map[int]bool{overlayIfindex7443: true})
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_7443, nil, nil); got != liveFabricMAC7443 {
			t.Errorf("buildFabricPeerMAC = %q, want the parent's %q", got, liveFabricMAC7443)
		}
	})

	t.Run("a stale entry on BOTH ifindexes resolves to nothing", func(t *testing.T) {
		stubFabricNeighList(t, map[int][]netlink.Neigh{
			overlayIfindex7443: {{IP: ip, HardwareAddr: stale, State: netlink.NUD_FAILED}},
			parentIfindex7443:  {{IP: ip, HardwareAddr: stale, State: netlink.NUD_INCOMPLETE}},
		}, nil)
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV4_7443, nil, nil); got != "" {
			t.Errorf("buildFabricPeerMAC = %q, want \"\" — no usable entry exists", got)
		}
	})

	t.Run("a non-positive ifindex is skipped, not queried", func(t *testing.T) {
		queried := stubFabricNeighList(t, map[int][]netlink.Neigh{
			parentIfindex7443: {{IP: ip, HardwareAddr: live, State: netlink.NUD_REACHABLE}},
		}, nil)
		if got := buildFabricPeerMAC(0, parentIfindex7443, peerV4_7443, nil, nil); got != liveFabricMAC7443 {
			t.Errorf("buildFabricPeerMAC = %q, want the parent's %q", got, liveFabricMAC7443)
		}
		if len(*queried) != 1 || (*queried)[0] != parentIfindex7443 {
			t.Errorf("queried ifindexes %v, want only the parent (%d)", *queried, parentIfindex7443)
		}
	})
}

// TestBuildFabricPeerMACIPv6_7443 covers the v6 fabric peer: the family
// selection is part of this resolver, and an IPv6 peer address must reach the
// same NUD/length bar.
func TestBuildFabricPeerMACIPv6_7443(t *testing.T) {
	ip := net.ParseIP(peerV6_7443)
	stale := mustMAC7443(t, staleFabricMAC7443)
	live := mustMAC7443(t, liveFabricMAC7443)

	t.Run("family is resolved as V6 for a v6 peer", func(t *testing.T) {
		var families []int
		orig := fabricNeighListFn
		t.Cleanup(func() { fabricNeighListFn = orig })
		fabricNeighListFn = func(ifindex, family int) ([]netlink.Neigh, error) {
			families = append(families, family)
			return []netlink.Neigh{{IP: ip, HardwareAddr: live, State: netlink.NUD_REACHABLE}}, nil
		}
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV6_7443, nil, nil); got != liveFabricMAC7443 {
			t.Errorf("buildFabricPeerMAC = %q, want %q", got, liveFabricMAC7443)
		}
		if len(families) == 0 || families[0] != netlink.FAMILY_V6 {
			t.Errorf("queried families %v, want the first to be FAMILY_V6 (%d)", families, netlink.FAMILY_V6)
		}
	})

	t.Run("NUD_FAILED on a v6 peer is not the redirect MAC", func(t *testing.T) {
		stubFabricNeighList(t, map[int][]netlink.Neigh{
			overlayIfindex7443: {{IP: ip, HardwareAddr: stale, State: netlink.NUD_FAILED}},
		}, nil)
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, peerV6_7443, nil, nil); got != "" {
			t.Errorf("buildFabricPeerMAC = %q, want \"\"", got)
		}
	})

	t.Run("an unparseable peer address resolves to nothing without touching netlink", func(t *testing.T) {
		queried := stubFabricNeighList(t, nil, nil)
		if got := buildFabricPeerMAC(overlayIfindex7443, parentIfindex7443, "not-an-address", nil, nil); got != "" {
			t.Errorf("buildFabricPeerMAC = %q, want \"\"", got)
		}
		if len(*queried) != 0 {
			t.Errorf("queried ifindexes %v, want none — the address never parsed", *queried)
		}
	})
}
