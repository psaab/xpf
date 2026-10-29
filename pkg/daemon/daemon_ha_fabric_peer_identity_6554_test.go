package daemon

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #6554 — the fabric peer-MAC IPv6-NDP fallback must not accept an arbitrary
// link-local neighbour.
//
// probeFabricNeighbor deliberately seeds the fabric parent's NDP table by
// pinging ff02::1, so every IPv6-speaking host on the segment answers. The
// pre-fix fallback then took the FIRST non-self link-local entry it found. On a
// shared fabric segment that is an unrelated adjacent host: the refresh
// resolves a stranger's MAC as the cross-chassis peer, reports success, and
// latches the slot populated (which feeds the RG takeover-readiness gate).
//
// These tests drive the real refreshFabricFwdSlot end-to-end against a synthetic
// link + neighbour table and assert on the peer MAC the live resolver
// (pkg/dataplane/userspace.ResolveFabricPeer, #17044) returns for the slot
// — the value readiness latches on — not on an intermediate. The daemon
// neighbour table below is also the resolver's table: test daemons install
// a resolver that delegates to dpuserspace.ResolveFabricPeerWithNeighbours
// over the SAME synthetic dumps, so daemon readiness and helper PeerMAC
// agree by construction.

// fabricProgramRecorder captures every ResolveFabricPeer call so a test
// can assert on the peer MAC that was resolved.
type fabricProgramRecorder struct {
	mu      sync.Mutex
	writes  []dpuserspace.FabricPeerResolution
	ids     []int
	syncs   int
	neighFn func(ifindex, family int) ([]netlink.Neigh, error)
}

func (h *fabricProgramRecorder) SetRGActive(_ context.Context, _ int, _ bool) error { return nil }
func (h *fabricProgramRecorder) SetHAWatchdog(_ context.Context, _ int, _ uint64) error {
	return nil
}

// neighFn is installed by the test daemon factories; ResolveFabricPeer
// delegates to the live resolver over the same synthetic tables.
func (h *fabricProgramRecorder) ResolveFabricPeer(slot int, overlayIfindex, parentIfindex int, peer string, localMAC net.HardwareAddr) dpuserspace.FabricPeerResolution {
	res := dpuserspace.ResolveFabricPeerWithNeighbours(overlayIfindex, parentIfindex, peer, localMAC, h.neighFn)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ids = append(h.ids, slot)
	h.writes = append(h.writes, res)
	return res
}

func (h *fabricProgramRecorder) SyncFabricState(_ context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.syncs++
	return nil
}

// programmedPeerMACs returns the peer MACs of every resolved fabric
// resolution, in order. Unresolved resolutions carry no MAC.
func (h *fabricProgramRecorder) programmedPeerMACs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, w := range h.writes {
		if len(w.PeerMAC) == 0 {
			continue
		}
		out = append(out, w.PeerMAC.String())
	}
	return out
}

// programmedIDs returns the slots of every resolved fabric resolution, in order.
func (h *fabricProgramRecorder) programmedIDs() []int {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []int
	for i, w := range h.writes {
		if len(w.PeerMAC) == 0 {
			continue
		}
		out = append(out, h.ids[i])
	}
	return out
}

type fabricProgramDP struct {
	dataplane.RuntimeDataPlane
	ha *fabricProgramRecorder
}

func (d *fabricProgramDP) HA() dataplane.HAController { return d.ha }

func (d *fabricProgramDP) ResolveFabricPeer(slot int, overlayIfindex, parentIfindex int, peer string, localMAC net.HardwareAddr) dpuserspace.FabricPeerResolution {
	return d.ha.ResolveFabricPeer(slot, overlayIfindex, parentIfindex, peer, localMAC)
}

const (
	fabPeerTestLocalMAC = "02:00:00:00:00:0a" // this node's fabric parent MAC
	fabPeerTestPeerMAC  = "02:00:00:00:00:0b" // the real peer chassis
	fabPeerTestDecoyMAC = "02:00:00:00:00:99" // an unrelated host on the segment
)

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return mac
}

// fabPeerNeigh builds a valid (REACHABLE) neighbour entry.
func fabPeerNeigh(t *testing.T, ip, mac string) netlink.Neigh {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("ParseIP(%q) failed", ip)
	}
	return netlink.Neigh{
		IP:           parsed,
		HardwareAddr: mustMAC(t, mac),
		State:        netlink.NUD_REACHABLE,
	}
}

// fabPeerTestDaemon wires a Daemon whose fabric parent resolves to a synthetic
// link and whose neighbour dumps come from parentV6 (the fabric parent's IPv6
// NDP table, seeded by the ff02::1 probe). The overlay's own neighbour table is
// deliberately EMPTY and no parent IPv4 entry exists for the peer address, so
// resolution falls through to the link-local NDP fallback under test.
//
// TxQLen is pre-set at the 10000 threshold so refreshFabricFwdSlot never issues a
// real netlink LinkSetTxQLen against the fake link.
func fabPeerTestDaemon(t *testing.T, parentV6 []netlink.Neigh) (*Daemon, *fabricProgramRecorder) {
	t.Helper()
	dpuserspace.RegisterFabricPeerMACConstraint("10.99.13.2", nil)
	t.Cleanup(func() { dpuserspace.RegisterFabricPeerMACConstraint("10.99.13.2", nil) })
	const (
		parentIdx  = 11
		overlayIdx = 12
	)
	parent := &testLink{attrs: netlink.LinkAttrs{
		Name:         "ge-0-0-0",
		Index:        parentIdx,
		OperState:    netlink.OperUp,
		TxQLen:       10000,
		HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}
	overlay := &testLink{attrs: netlink.LinkAttrs{
		Name:         "fab0",
		Index:        overlayIdx,
		ParentIndex:  parentIdx,
		OperState:    netlink.OperUp,
		TxQLen:       10000,
		HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}

	rec := &fabricProgramRecorder{}
	neighFn := func(ifindex, family int) ([]netlink.Neigh, error) {
		if ifindex == parentIdx && family == netlink.FAMILY_V6 {
			return parentV6, nil
		}
		// Overlay ARP and parent IPv4 both miss — the state this
		// fallback exists to recover from.
		return nil, nil
	}
	rec.neighFn = neighFn
	d := &Daemon{
		fabricSlots: [2]fabricSlot{{name: "fabric", peerIP: net.ParseIP("10.99.13.2")}, {name: "fabric1"}},
		linkByNameFn: mockLinkByName(map[string]*testLink{
			"ge-0-0-0": parent,
			"fab0":     overlay,
		}),
		neighListFn: neighFn,
	}
	d.setDataplane(&fabricProgramDP{ha: rec}) // #2114: publish through the cell
	return d, rec
}

func fabPeerRefresh(t *testing.T, d *Daemon) bool {
	t.Helper()
	return d.refreshFabricFwdSlot(context.Background(), 0, "ge-0-0-0", "fab0",
		net.ParseIP("10.99.13.2"), false)
}

// TestFabricPeerNDPFallbackRejectsDecoyWithKnownPeerMAC is the primary
// fail-on-revert gate. A decoy link-local neighbour is listed FIRST, ahead of
// the real peer, and the peer's MAC is already known from an earlier
// address-matched resolution. The permissive pre-#6554 loop took the first
// non-self link-local entry and would program the decoy's MAC.
func TestFabricPeerNDPFallbackRejectsDecoyWithKnownPeerMAC(t *testing.T) {
	d, rec := fabPeerTestDaemon(t, []netlink.Neigh{
		// Decoy first — a permissive first-match selection picks this.
		fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
		fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
	})
	// An earlier address-matched resolution established the peer's identity.
	d.rememberFabricPeerMAC(0, mustMAC(t, fabPeerTestPeerMAC))

	if !fabPeerRefresh(t, d) {
		t.Fatal("refreshFabricFwdSlot returned false; expected the real peer to resolve")
	}

	got := rec.programmedPeerMACs()
	if len(got) != 1 {
		t.Fatalf("expected exactly one programmed fabric entry, got %d (%v)", len(got), got)
	}
	if got[0] == fabPeerTestDecoyMAC {
		// #15918 update: the live resolver now shares this selection, so a
		// decoy accepted here WOULD become the helper's PeerMAC as well.
		t.Fatalf("DECOY MAC %s was programmed as the fabric peer — the node would "+
			"latch slot populated, end the fast-retry probe loop early, and log an "+
			"unrelated host's MAC as the fabric peer during an HA incident (#6554)",
			fabPeerTestDecoyMAC)
	}
	if got[0] != fabPeerTestPeerMAC {
		t.Fatalf("programmed peer MAC = %s, want the real peer %s", got[0], fabPeerTestPeerMAC)
	}
}

// TestFabricPeerNDPFallbackRefusesAmbiguousSegment covers the cold-start case:
// a decoy is present alongside the real peer but NO address-matched resolution
// has ever identified the peer. With no identity to check against, the segment
// is ambiguous and the fallback must refuse rather than guess. The permissive
// form programmed the decoy.
func TestFabricPeerNDPFallbackRefusesAmbiguousSegment(t *testing.T) {
	d, rec := fabPeerTestDaemon(t, []netlink.Neigh{
		fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
		fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
	})
	// No rememberFabricPeerMAC — the peer address has never resolved.

	if fabPeerRefresh(t, d) {
		t.Fatal("refreshFabricFwdSlot reported success on an ambiguous fabric segment; " +
			"expected a fail-closed refusal (#6554)")
	}
	if got := rec.programmedPeerMACs(); len(got) != 0 {
		t.Fatalf("a peer MAC was programmed from an unidentifiable segment: %v "+
			"(decoy=%s, peer=%s) (#6554)", got, fabPeerTestDecoyMAC, fabPeerTestPeerMAC)
	}
	if d.fabricEntryPopulated(0) {
		t.Fatal("slot 0 populated latched on a refused resolution — the RG " +
			"takeover-readiness gate would read a fabric that never resolved")
	}
}

// TestFabricPeerNDPFallbackResolvesSolePeer is the over-reach guard: the normal
// point-to-point fabric — only the real peer on the segment, no cached identity
// — must still resolve, and to the peer's MAC. This test must stay GREEN when
// the fix is reverted.
func TestFabricPeerNDPFallbackResolvesSolePeer(t *testing.T) {
	d, rec := fabPeerTestDaemon(t, []netlink.Neigh{
		fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
	})

	if !fabPeerRefresh(t, d) {
		t.Fatal("refreshFabricFwdSlot returned false on a healthy point-to-point fabric")
	}
	got := rec.programmedPeerMACs()
	if len(got) != 1 || got[0] != fabPeerTestPeerMAC {
		t.Fatalf("programmed peer MACs = %v, want exactly [%s]", got, fabPeerTestPeerMAC)
	}
	if !d.fabricEntryPopulated(0) {
		t.Fatal("slot 0 populated not set after a successful sole-peer resolution")
	}
}

// TestFabricPeerNDPFallbackSolePeerMatchesKnownIdentity is the second half of
// the over-reach guard: a healthy fabric that HAS resolved before must keep
// resolving to the same MAC once the identity constraint is armed.
func TestFabricPeerNDPFallbackSolePeerMatchesKnownIdentity(t *testing.T) {
	d, rec := fabPeerTestDaemon(t, []netlink.Neigh{
		fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
	})
	d.rememberFabricPeerMAC(0, mustMAC(t, fabPeerTestPeerMAC))

	if !fabPeerRefresh(t, d) {
		t.Fatal("refreshFabricFwdSlot returned false for the known peer")
	}
	got := rec.programmedPeerMACs()
	if len(got) != 1 || got[0] != fabPeerTestPeerMAC {
		t.Fatalf("programmed peer MACs = %v, want exactly [%s]", got, fabPeerTestPeerMAC)
	}
}

// TestFabricPeerNDPFallbackRefusesLoneDecoyWhenPeerKnown covers the peer-down
// case on a shared segment: the real peer is gone, only the decoy answers. With
// the peer's identity known, the sole remaining neighbour must still be
// refused — "the only host left" is not "the peer".
func TestFabricPeerNDPFallbackRefusesLoneDecoyWhenPeerKnown(t *testing.T) {
	d, rec := fabPeerTestDaemon(t, []netlink.Neigh{
		fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
	})
	d.rememberFabricPeerMAC(0, mustMAC(t, fabPeerTestPeerMAC))

	if fabPeerRefresh(t, d) {
		t.Fatal("refreshFabricFwdSlot accepted a lone non-peer neighbour")
	}
	if got := rec.programmedPeerMACs(); len(got) != 0 {
		t.Fatalf("programmed peer MACs = %v, want none", got)
	}
}

// TestFabricPeerAddressMatchRecordsIdentity proves the identity the fallback
// checks against comes from an ADDRESS-MATCHED resolution — the MAC that
// actually answered for the configured fabric peer address — and that the
// fallback's own result never promotes itself into that identity.
func TestFabricPeerAddressMatchRecordsIdentity(t *testing.T) {
	t.Run("address match records", func(t *testing.T) {
		d, rec := fabPeerTestDaemon(t, nil)
		peerIP := net.ParseIP("10.99.13.2")
		d.neighListFn = func(ifindex, family int) ([]netlink.Neigh, error) {
			if ifindex == 12 && family == netlink.FAMILY_V4 {
				return []netlink.Neigh{
					fabPeerNeigh(t, peerIP.String(), fabPeerTestPeerMAC),
				}, nil
			}
			return nil, nil
		}
		rec.neighFn = d.neighListFn
		if !fabPeerRefresh(t, d) {
			t.Fatal("refreshFabricFwdSlot returned false on an address-matched resolution")
		}
		hint := d.fabricPeerMACHint(0)
		if hint.String() != fabPeerTestPeerMAC {
			t.Fatalf("peer identity hint = %v, want %s", hint, fabPeerTestPeerMAC)
		}
	})

	t.Run("fallback result is not promoted to identity", func(t *testing.T) {
		d, _ := fabPeerTestDaemon(t, []netlink.Neigh{
			fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
		})
		if !fabPeerRefresh(t, d) {
			t.Fatal("refreshFabricFwdSlot returned false on a sole-peer segment")
		}
		if hint := d.fabricPeerMACHint(0); hint != nil {
			t.Fatalf("link-local fallback promoted its own result to the peer "+
				"identity (%v); a single bad selection would then pin every "+
				"later refresh", hint)
		}
	})
}

// TestFabricPeerIdentityClearedOnPeerChange proves a re-pointed fabric drops
// the cached identity: the new peer chassis has a different MAC, and pinning
// the old one would refuse the new peer forever.
// populateFabricSlotStateOnly6554 lets a current epoch publish its slot state,
// then cancels at the first hermetic link lookup so no probes or retry sleeps
// occur.
func populateFabricSlotStateOnly6554(
	d *Daemon,
	epoch *clusterCommsEpoch,
	slot int,
	fabIface, overlay, peerAddr string,
) {
	ctx, cancel := context.WithCancel(context.Background())
	oldLinkByName := d.linkByNameFn
	d.linkByNameFn = func(string) (netlink.Link, error) {
		cancel()
		return nil, errors.New("hermetic slot-state test")
	}
	epoch.fabricPopulateWG.Add(1)
	d.populateFabricFwdSlot(ctx, epoch, slot, fabIface, overlay, peerAddr, nil)
	cancel()
	d.linkByNameFn = oldLinkByName
}

func TestFabricPeerIdentityClearedOnPeerChange(t *testing.T) {
	d := &Daemon{}
	// This cell must not touch real netlink: a live lookup of a physical
	// interface could otherwise probe it. The state-only helper cancels at
	// the first lookup, after the current epoch has published its config.
	d.linkByNameFn = func(string) (netlink.Link, error) {
		return nil, errors.New("hermetic test: netlink disabled")
	}
	d.neighListFn = func(int, int) ([]netlink.Neigh, error) {
		return nil, errors.New("hermetic test: netlink disabled")
	}
	d.fabricSlots[0].peerIP = net.ParseIP("10.99.13.2")
	d.rememberFabricPeerMAC(0, mustMAC(t, fabPeerTestPeerMAC))
	d.fabricSlots[1].peerIP = net.ParseIP("10.99.14.2")
	d.rememberFabricPeerMAC(1, mustMAC(t, fabPeerTestPeerMAC))

	epoch := &clusterCommsEpoch{generation: d.clusterCommsGen}
	// Same peer — identity survives.
	populateFabricSlotStateOnly6554(d, epoch, 0, "ge-0-0-0", "fab0", "10.99.13.2")
	if d.fabricPeerMACHint(0) == nil {
		t.Fatal("peer identity cleared even though the peer address is unchanged")
	}

	// Different peer — identity must be dropped.
	populateFabricSlotStateOnly6554(d, epoch, 0, "ge-0-0-0", "fab0", "10.99.13.3")
	if hint := d.fabricPeerMACHint(0); hint != nil {
		t.Fatalf("stale peer identity %v retained across a fabric peer change", hint)
	}

	populateFabricSlotStateOnly6554(d, epoch, 1, "ge-0-0-0", "fab1", "10.99.14.3")
	if hint := d.fabricPeerMACHint(1); hint != nil {
		t.Fatalf("stale fab1 identity %v retained across a peer change", hint)
	}
}

// TestPopulateFabricFwdHonoursCancelledContextBeforeFirstProbe pins the #6595
// cancellation guard. The retry loop used to check ctx.Done() only inside its
// `i > 0` sleep arm, so iteration 0 ran unconditionally: an already-cancelled
// caller still reached probeFabricNeighbor, which dumps the kernel neighbour
// table and — on a miss — transmits a raw ICMP probe plus an ff02::1
// solicitation on a live interface. A cancelled context must put nothing on the
// wire and read nothing from netlink.
//
// The assertion is a netlink-touch count rather than a packet capture: both
// populateFabricFwdSlot's probe and its refreshFabricFwdSlot call reach the kernel
// through fabricLinkByName, so ZERO calls is the only state in which neither
// can have run. Reverting the guard makes this count non-zero.
func TestPopulateFabricFwdHonoursCancelledContextBeforeFirstProbe(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(d *Daemon, ctx context.Context)
	}{
		{"fab0", func(d *Daemon, ctx context.Context) {
			epoch := &clusterCommsEpoch{}
			epoch.fabricPopulateWG.Add(1)
			d.populateFabricFwdSlot(ctx, epoch, 0, "ge-0-0-0", "fab0", "10.99.13.2", nil)
		}},
		{"fab1", func(d *Daemon, ctx context.Context) {
			epoch := &clusterCommsEpoch{}
			epoch.fabricPopulateWG.Add(1)
			d.populateFabricFwdSlot(ctx, epoch, 1, "ge-0-0-0", "fab1", "10.99.14.2", nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			netlinkTouches := 0
			d := &Daemon{}
			d.linkByNameFn = func(string) (netlink.Link, error) {
				mu.Lock()
				netlinkTouches++
				mu.Unlock()
				return nil, errors.New("hermetic test: netlink disabled")
			}
			d.neighListFn = func(int, int) ([]netlink.Neigh, error) {
				mu.Lock()
				netlinkTouches++
				mu.Unlock()
				return nil, errors.New("hermetic test: netlink disabled")
			}

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			tc.run(d, ctx)

			mu.Lock()
			got := netlinkTouches
			mu.Unlock()
			if got != 0 {
				t.Fatalf("cancelled context still performed %d netlink read(s) — "+
					"the pre-probe ctx.Err() guard is not holding, so a cancelled "+
					"caller can still transmit an ICMP/ff02::1 probe on a live NIC "+
					"(#6595)", got)
			}
		})
	}
}

// TestSelectFabricPeerLinkLocalMAC exercises the candidate filter directly:
// which neighbour entries are eligible at all, and how ambiguity is resolved.
func TestSelectFabricPeerLinkLocalMAC(t *testing.T) {
	local := mustMAC(t, fabPeerTestLocalMAC)
	peer := mustMAC(t, fabPeerTestPeerMAC)

	withState := func(n netlink.Neigh, state int) netlink.Neigh {
		n.State = state
		return n
	}

	tests := []struct {
		name     string
		neighs   []netlink.Neigh
		expected net.HardwareAddr
		want     string // "" means refusal
	}{
		{
			name:   "sole peer accepted",
			neighs: []netlink.Neigh{fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC)},
			want:   fabPeerTestPeerMAC,
		},
		{
			name: "self entry ignored",
			neighs: []netlink.Neigh{
				fabPeerNeigh(t, "fe80::a", fabPeerTestLocalMAC),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
			want: fabPeerTestPeerMAC,
		},
		{
			name: "global unicast ignored",
			neighs: []netlink.Neigh{
				fabPeerNeigh(t, "2001:db8::99", fabPeerTestDecoyMAC),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
			want: fabPeerTestPeerMAC,
		},
		{
			name: "unusable NUD state ignored",
			neighs: []netlink.Neigh{
				withState(fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC), netlink.NUD_FAILED),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
			want: fabPeerTestPeerMAC,
		},
		{
			name: "group-bit MAC ignored",
			neighs: []netlink.Neigh{
				fabPeerNeigh(t, "fe80::dec0", "33:33:00:00:00:01"),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
			want: fabPeerTestPeerMAC,
		},
		{
			name: "multiple link-locals on one peer NIC are one candidate",
			neighs: []netlink.Neigh{
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
				fabPeerNeigh(t, "fe80::bbbb", fabPeerTestPeerMAC),
			},
			want: fabPeerTestPeerMAC,
		},
		{
			name: "two distinct hosts refused without identity",
			neighs: []netlink.Neigh{
				fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
			want: "",
		},
		{
			name: "two distinct hosts resolved by identity",
			neighs: []netlink.Neigh{
				fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
			expected: peer,
			want:     fabPeerTestPeerMAC,
		},
		{
			name:     "lone decoy refused against identity",
			neighs:   []netlink.Neigh{fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC)},
			expected: peer,
			want:     "",
		},
		{
			name:   "empty table refused",
			neighs: nil,
			want:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mac, peerLL, n, reason := selectFabricPeerLinkLocalMAC(tc.neighs, local, tc.expected)
			if tc.want == "" {
				if mac != nil {
					t.Fatalf("selected %v (ll=%v), want refusal", mac, peerLL)
				}
				if reason == "" {
					t.Fatal("refusal carried no operator-facing reason")
				}
				return
			}
			if mac == nil {
				t.Fatalf("refused (%s, candidates=%d), want %s", reason, n, tc.want)
			}
			if mac.String() != tc.want {
				t.Fatalf("selected %s, want %s", mac, tc.want)
			}
			if reason != "" {
				t.Fatalf("success carried a refusal reason: %s", reason)
			}
			if peerLL == nil {
				t.Fatal("success carried no link-local address for logging")
			}
		})
	}
}

// #15683 — fab1 must get the same physical-parent ARP/NDP and IPv6 link-local
// fallbacks as fab0, and reconcileRGState must treat fab1-populated as
// fabric-ready.

// fab1PeerTestDaemon wires a Daemon whose secondary fabric parent resolves to
// a synthetic link. The fab1 overlay's own neighbour table is deliberately
// EMPTY, so resolution must fall through to the parent fallbacks under test.
// parentNeighs maps (ifindex, family) -> neighbours; unlisted keys miss.
func fab1PeerTestDaemon(t *testing.T, parentNeighs map[[2]int][]netlink.Neigh) (*Daemon, *fabricProgramRecorder) {
	t.Helper()
	dpuserspace.RegisterFabricPeerMACConstraint("10.99.14.2", nil)
	t.Cleanup(func() { dpuserspace.RegisterFabricPeerMACConstraint("10.99.14.2", nil) })
	const (
		parentIdx  = 21
		overlayIdx = 22
	)
	parent := &testLink{attrs: netlink.LinkAttrs{
		Name:         "ge-0-0-1",
		Index:        parentIdx,
		OperState:    netlink.OperUp,
		TxQLen:       10000,
		HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}
	overlay := &testLink{attrs: netlink.LinkAttrs{
		Name:         "fab1",
		Index:        overlayIdx,
		ParentIndex:  parentIdx,
		OperState:    netlink.OperUp,
		TxQLen:       10000,
		HardwareAddr: mustMAC(t, fabPeerTestLocalMAC),
	}}
	rec := &fabricProgramRecorder{}
	neighFn := func(ifindex, family int) ([]netlink.Neigh, error) {
		if got, ok := parentNeighs[[2]int{ifindex, family}]; ok {
			return got, nil
		}
		return nil, nil
	}
	rec.neighFn = neighFn
	d := &Daemon{
		fabricSlots: [2]fabricSlot{{name: "fabric"}, {name: "fabric1", peerIP: net.ParseIP("10.99.14.2")}},
		linkByNameFn: mockLinkByName(map[string]*testLink{
			"ge-0-0-1": parent,
			"fab1":     overlay,
		}),
		neighListFn: neighFn,
	}
	d.setDataplane(&fabricProgramDP{ha: rec})
	return d, rec
}

// TestRefreshFabricFwd1ParentARPAndLinkLocalFallback is the #15683 regression
// gate. The fab1 overlay table is empty; (a) an address-matched neighbour on
// the physical parent and (b) a sole fe80::/10 neighbour on the parent must
// each populate fab1. Pre-fix the fab1 copy had neither fallback leg and
// returned false in both cases.
func TestRefreshFabricFwd1ParentARPAndLinkLocalFallback(t *testing.T) {
	const parentIdx = 21
	peerIP := net.ParseIP("10.99.14.2")

	t.Run("parent ARP address-matched", func(t *testing.T) {
		d, rec := fab1PeerTestDaemon(t, map[[2]int][]netlink.Neigh{
			{parentIdx, netlink.FAMILY_V4}: {
				fabPeerNeigh(t, peerIP.String(), fabPeerTestPeerMAC),
			},
		})
		if !d.refreshFabricFwdSlot(context.Background(), 1, "ge-0-0-1", "fab1", peerIP, false) {
			t.Fatal("refreshFabricFwdSlot(1) returned false; expected parent ARP fallback to resolve the peer (#15683)")
		}
		if !d.fabricEntryPopulated(1) {
			t.Fatal("slot 1 populated not set after parent ARP fallback resolution")
		}
		if d.fabricSlots[1].populated != true {
			t.Fatal("fabricSlots[1].populated = false, want true")
		}
		ids := rec.programmedIDs()
		if len(ids) != 1 || ids[0] != 1 {
			t.Fatalf("resolved slots = %v, want exactly [1]", ids)
		}
		if got := rec.programmedPeerMACs(); len(got) != 1 || got[0] != fabPeerTestPeerMAC {
			t.Fatalf("programmed peer MACs = %v, want exactly [%s]", got, fabPeerTestPeerMAC)
		}
		if hint := d.fabricPeerMACHint(1); hint == nil || hint.String() != fabPeerTestPeerMAC {
			t.Fatalf("parent ARP hit must record slot-1 identity, hint = %v", hint)
		}
	})

	t.Run("parent IPv6 link-local sole peer", func(t *testing.T) {
		d, rec := fab1PeerTestDaemon(t, map[[2]int][]netlink.Neigh{
			{parentIdx, netlink.FAMILY_V6}: {
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
		})
		if !d.refreshFabricFwdSlot(context.Background(), 1, "ge-0-0-1", "fab1", peerIP, false) {
			t.Fatal("refreshFabricFwdSlot(1) returned false; expected parent IPv6 link-local fallback to resolve the sole peer (#15683)")
		}
		if !d.fabricEntryPopulated(1) {
			t.Fatal("slot 1 populated not set after link-local fallback resolution")
		}
		ids := rec.programmedIDs()
		if len(ids) != 1 || ids[0] != 1 {
			t.Fatalf("resolved slots = %v, want exactly [1]", ids)
		}
		if got := rec.programmedPeerMACs(); len(got) != 1 || got[0] != fabPeerTestPeerMAC {
			t.Fatalf("programmed peer MACs = %v, want exactly [%s]", got, fabPeerTestPeerMAC)
		}
		// Link-local fallback must not promote itself into identity (#6554).
		if hint := d.fabricPeerMACHint(1); hint != nil {
			t.Fatalf("link-local fallback promoted its own result to slot-1 identity (%v)", hint)
		}
	})

	t.Run("parent IPv6 ambiguous segment refused", func(t *testing.T) {
		d, rec := fab1PeerTestDaemon(t, map[[2]int][]netlink.Neigh{
			{parentIdx, netlink.FAMILY_V6}: {
				fabPeerNeigh(t, "fe80::dec0", fabPeerTestDecoyMAC),
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			},
		})
		if d.refreshFabricFwdSlot(context.Background(), 1, "ge-0-0-1", "fab1", peerIP, false) {
			t.Fatal("refreshFabricFwdSlot(1) reported success on an ambiguous segment; expected fail-closed refusal (#6554/#15683)")
		}
		if got := rec.programmedPeerMACs(); len(got) != 0 {
			t.Fatalf("a peer MAC was programmed from an unidentifiable segment: %v", got)
		}
		if d.fabricEntryPopulated(1) {
			t.Fatal("slot 1 populated latched on a refused resolution")
		}
	})
}

// TestReconcileRGStateFabricReadyWithFab1Only verifies that when fab0 is
// unpopulated but fab1 is populated and the peer is alive, reconcileRGState
// passes fabricReady=true to takeoverReadinessForRG (#15683). Without this,
// fab0-down/fab1-up blocks takeover even though fab1 could forward.
// fab1ReadyDaemon builds the noReth fixture with applySem installed: the
// reconcile pass schedules a connected-RG republish goroutine that acquires
// it, and the bare fixture's nil semaphore panics in that goroutine.
func fab1ReadyDaemon(t *testing.T) *Daemon {
	t.Helper()
	d := noRethHoldDaemon(t)
	d.applySem = semaphore.NewWeighted(1)
	return d
}

func TestReconcileRGStateFabricReadyWithFab1Only(t *testing.T) {
	d := fab1ReadyDaemon(t)

	// Peer alive via the real heartbeat admission path.
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
		t.Fatal("precondition: PeerAlive must be true for the fabric gate to be evaluated")
	}

	// fab1 only.
	d.fabricMu.Lock()
	d.fabricSlots[0].populated = false
	d.fabricSlots[1].populated = true
	d.fabricMu.Unlock()

	ready, reasons := rgReadiness(t, d)
	if !ready {
		t.Fatalf("RG must be takeover-ready with fab1-only populated: ready=false reasons=%v (#15683)", reasons)
	}
	for _, r := range reasons {
		if strings.Contains(r, "fabric forwarding path not ready") {
			t.Fatalf("fabric reason present despite fab1 populated: %v", reasons)
		}
	}

	// Control: neither fabric populated must stay not-ready, proving the
	// gate above was live and not vacuous.
	d.fabricMu.Lock()
	d.fabricSlots[1].populated = false
	d.fabricMu.Unlock()
	ready, reasons = rgReadiness(t, d)
	if ready {
		t.Fatal("control: RG must be not-ready when neither fabric is populated")
	}
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "fabric forwarding path not ready") {
			found = true
		}
	}
	if !found {
		t.Fatalf("control: expected fabric-not-ready reason, got %v", reasons)
	}

	// fab0-only also stays ready (no regression for single-fabric).
	d.fabricMu.Lock()
	d.fabricSlots[0].populated = true
	d.fabricMu.Unlock()
	if ready, reasons := rgReadiness(t, d); !ready {
		t.Fatalf("fab0-only must remain takeover-ready: %v", reasons)
	}
}

// TestRefreshFabricFwd1LinkLocalSyncsHelper15918 is the #15918 consumer gate:
// the fab1 link-local fallback must not only latch slot 1 populated and
// resolve, it must also push SyncFabricState so the userspace
// helper receives the resolved fabric (its buildFabricPeerMAC now resolves
// the same sole link-local neighbour). Pre-fix the fab1 copy never
// called SyncFabricState on its success path (fab0 did).
func TestRefreshFabricFwd1LinkLocalSyncsHelper15918(t *testing.T) {
	const parentIdx = 21
	peerIP := net.ParseIP("10.99.14.2")
	d, rec := fab1PeerTestDaemon(t, map[[2]int][]netlink.Neigh{
		{parentIdx, netlink.FAMILY_V6}: {
			fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
		},
	})
	if !d.refreshFabricFwdSlot(context.Background(), 1, "ge-0-0-1", "fab1", peerIP, false) {
		t.Fatal("refreshFabricFwdSlot(1) returned false on sole link-local peer")
	}
	rec.mu.Lock()
	syncs := rec.syncs
	rec.mu.Unlock()
	if syncs == 0 {
		t.Fatal("refreshFabricFwdSlot(1) link-local success did not call SyncFabricState — helper never learns fab1 PeerMAC (#15918)")
	}
	// fab0 sole-peer path already syncs; assert it stays (control).
	d0, rec0 := fabPeerTestDaemon(t, []netlink.Neigh{
		fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
	})
	if !fabPeerRefresh(t, d0) {
		t.Fatal("refreshFabricFwdSlot returned false on sole link-local peer")
	}
	rec0.mu.Lock()
	s0 := rec0.syncs
	rec0.mu.Unlock()
	if s0 == 0 {
		t.Fatal("refreshFabricFwdSlot lost its SyncFabricState call")
	}
}

// TestFabricSlotParity17040 is the #17040 parameterization gate: both slots
// must behave identically through the single populate/refresh/clear
// implementation, and one slot's state must never leak into the other.
// Before #17040 fab0/fab1 were hand-mirrored copies and fab1 drifted into
// the #15683/#15918 defects; a slot-specific regression in the shared path
// (e.g. re-branching on slot 1) fails the slot-1 subtests here while the
// slot-0 control stays green.
func TestFabricSlotParity17040(t *testing.T) {
	for _, tc := range []struct {
		slot int
		name string
	}{
		{slot: 0, name: "fabric"},
		{slot: 1, name: "fabric1"},
	} {
		slot := tc.slot
		t.Run(tc.name, func(t *testing.T) {
			peerAddr := "10.99.13.2"
			if slot == 1 {
				peerAddr = "10.99.14.2"
			}
			peerIP := net.ParseIP(peerAddr)
			dpuserspace.RegisterFabricPeerMACConstraint(peerAddr, nil)
			t.Cleanup(func() { dpuserspace.RegisterFabricPeerMACConstraint(peerAddr, nil) })

			d, rec := fabPeerTestDaemon(t, []netlink.Neigh{
				fabPeerNeigh(t, "fe80::b", fabPeerTestPeerMAC),
			})
			if got := d.fabricSlotLabel(slot); got != tc.name {
				t.Fatalf("slot %d label = %q, want stored name %q", slot, got, tc.name)
			}
			// fabPeerTestDaemon seeds slot 0's peer; re-point to this slot.
			d.fabricMu.Lock()
			d.fabricSlots[0].peerIP = nil
			d.fabricSlots[slot].peerIP = peerIP
			d.fabricMu.Unlock()
			if !d.refreshFabricFwdSlot(context.Background(), slot, "ge-0-0-0", "fab0", peerIP, false) {
				t.Fatalf("slot %d: refresh returned false on sole link-local peer", slot)
			}
			if !d.fabricEntryPopulated(slot) {
				t.Fatalf("slot %d: populated latch not set after resolution", slot)
			}
			if d.fabricEntryPopulated(1 - slot) {
				t.Fatalf("slot %d resolution leaked into slot %d populated latch", slot, 1-slot)
			}
			if ids := rec.programmedIDs(); len(ids) != 1 || ids[0] != slot {
				t.Fatalf("resolved slots = %v, want exactly [%d]", ids, slot)
			}
			rec.mu.Lock()
			syncs := rec.syncs
			rec.mu.Unlock()
			if syncs == 0 {
				t.Fatalf("slot %d: refresh success did not call SyncFabricState (#15918 parity)", slot)
			}
			// Link-local fallback must not promote itself into identity.
			if hint := d.fabricPeerMACHint(slot); hint != nil {
				t.Fatalf("slot %d: link-local fallback promoted itself to identity (%v)", slot, hint)
			}

			// Peer change through the shared populate path clears only
			// this slot's cached identity. The state-only helper lets an
			// active current epoch publish before cancelling its lookups.
			d.rememberFabricPeerMAC(slot, mustMAC(t, fabPeerTestPeerMAC))
			newAddr := "10.99.13.9"
			if slot == 1 {
				newAddr = "10.99.14.9"
			}
			epoch := &clusterCommsEpoch{generation: d.clusterCommsGen}
			populateFabricSlotStateOnly6554(d, epoch, slot, "ge-0-0-0", "fab0", newAddr)
			if hint := d.fabricPeerMACHint(slot); hint != nil {
				t.Fatalf("slot %d: stale identity %v retained across peer change", slot, hint)
			}

			// Clear through the shared path drops only this slot.
			d.fabricMu.Lock()
			d.fabricSlots[slot].populated = true
			d.fabricSlots[1-slot].populated = true
			d.fabricMu.Unlock()
			d.clearFabricFwdSlot(context.Background(), slot)
			if d.fabricEntryPopulated(slot) {
				t.Fatalf("slot %d: populated latch survived clearFabricFwdSlot", slot)
			}
			if !d.fabricEntryPopulated(1 - slot) {
				t.Fatalf("clearing slot %d also cleared slot %d", slot, 1-slot)
			}
		})
	}
}
