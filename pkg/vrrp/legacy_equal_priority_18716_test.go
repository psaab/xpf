package vrrp

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// #18716: the legacy VRRP mode demotion, as the two VRRP instances see it.
//
// On a cluster demotion the new primary forces MASTER at priority 200
// (ForceRGMaster), while the old primary is still MASTER at 200: its priority
// changes only through the resign or the debounced priority update after its
// demotion handler. Two MASTERs at equal priority fall to the RFC 5798 §6.4.3
// tie-break, which a v4-bearing RETH instance runs on IPv4 adverts only
// (resolveEqualPriorityMaster). There are three outcomes, and each cell below
// pins one with real run loops:
//
//  1. The new primary's IPv4 advert source is higher: the old master steps
//     down within an advert interval or two.
//  2. The old master's is higher: the NEW primary steps down, and the VIP
//     stays on the old (with #18716, possibly wedged) node.
//  3. Neither node has a non-VIP IPv4 on the RETH member, so no IPv4 advert
//     can be sent; the IPv6 adverts do not decide the tie-break, and both stay
//     MASTER holding the VIP.
//
// In every shape the old master's priority-0 resign ends it, which is why the
// daemon now sends that resign BEFORE any helper round trip when the helper is
// down (pkg/daemon/legacy_helper_down_18716_test.go). The handover the resign
// itself drives is break-before-make: no instant at which both nodes hold the
// VIP.

// The RETH instance carries one VIP per family. The holds track BOTH (review
// P3-3): VIPs are removed one at a time, so a check on one family alone
// cannot see a priority-0 advert sent between the two deletes.
var (
	vip4_18716 = net.ParseIP("10.0.61.1")
	vip6_18716 = net.ParseIP("2001:db8:61::1")
)

// held18716 records which of a node's VIPs are on its interface.
type held18716 struct{ v4, v6 atomic.Bool }

func (h *held18716) any() bool { return h.v4.Load() || h.v6.Load() }
func (h *held18716) all() bool { return h.v4.Load() && h.v6.Load() }

func (h *held18716) slot(ip net.IP) *atomic.Bool {
	switch {
	case ip.Equal(vip4_18716):
		return &h.v4
	case ip.Equal(vip6_18716):
		return &h.v6
	}
	return nil
}

type pair18716 struct {
	oldMgr, peerMgr   *Manager
	old, peer         *vrrpInstance
	oldHeld, peerHeld held18716
	// bothHeld latches when either node ADDS a VIP while the other holds any.
	bothHeld atomic.Bool
	// peerClaims counts the new primary's VIP adds; a forced MASTER claim can
	// be lost again within one advert interval, faster than a poll sees it.
	peerClaims atomic.Int32
	// prio0WhileHeld latches when the old master puts a priority-0 advert on
	// the wire while it still holds ANY VIP: the takeover signal must follow
	// the release, or the peer can claim before it.
	prio0WhileHeld atomic.Bool
	// firstPrio0 is when the old master's first priority-0 advert went on the
	// wire (UnixNano, 0 = never); peerClaimAfterPrio0 is the new primary's
	// first VIP add after it (later re-adds by the VIP reconcile don't move
	// it).
	firstPrio0, peerClaimAfterPrio0 atomic.Int64
}

func newPair18716(t *testing.T, oldV4, peerV4 net.IP) *pair18716 {
	t.Helper()
	vrid, ok := rethVRID(1)
	if !ok {
		t.Fatal("setup: no RETH VRID for RG1")
	}
	p := &pair18716{oldMgr: NewManager(), peerMgr: NewManager()}
	mk := func(mgr *Manager, held, other *held18716, claims *atomic.Int32, v4, ll net.IP) *vrrpInstance {
		vi := newInstance(Instance{
			Interface:         "reth18716",
			GroupID:           vrid,
			Priority:          200,
			AcceptData:        true,
			AdvertiseInterval: 30,
			VirtualAddresses:  []string{"10.0.61.1/24", "2001:db8:61::1/64"},
		}, &net.Interface{Name: "reth18716"}, mgr.eventCh, nil)
		vi.setLocalIP(v4)
		vi.setLocalIPv6(ll)
		vi.suppressGARP.Store(true)
		installFakeVIPNetlink(vi)
		vi.addrAddFn = func(_ netlink.Link, a *netlink.Addr) error {
			if slot := held.slot(a.IP); slot != nil {
				if other.any() {
					p.bothHeld.Store(true)
				}
				slot.Store(true)
				if claims != nil {
					claims.Add(1)
					if p.firstPrio0.Load() != 0 {
						p.peerClaimAfterPrio0.CompareAndSwap(0, time.Now().UnixNano())
					}
				}
			}
			return nil
		}
		vi.addrDelFn = func(_ netlink.Link, a *netlink.Addr) error {
			if slot := held.slot(a.IP); slot != nil {
				slot.Store(false)
			}
			return nil
		}
		mgr.mu.Lock()
		mgr.instances = map[instanceKey]*vrrpInstance{{iface: "reth18716", groupID: vrid}: vi}
		mgr.mu.Unlock()
		return vi
	}
	p.old = mk(p.oldMgr, &p.oldHeld, &p.peerHeld, nil, oldV4, net.ParseIP("fe80::a"))
	p.peer = mk(p.peerMgr, &p.peerHeld, &p.oldHeld, &p.peerClaims, peerV4, net.ParseIP("fe80::b"))

	// The wire: each advert reaches the other node with its sender's source
	// address for that family. Like sendPacket, an IPv4 advert without a
	// usable IPv4 source fails and is never sent.
	previous := sendPacketFn
	sendPacketFn = func(sender *vrrpInstance, pkt *VRRPPacket, isIPv6 bool) error {
		src := sender.getLocalIP()
		if isIPv6 {
			src = sender.getLocalIPv6()
		}
		if src == nil {
			return fmt.Errorf("no source address on %s", sender.cfg.Interface)
		}
		if sender == p.old && pkt.Priority == 0 {
			if p.oldHeld.any() {
				p.prio0WhileHeld.Store(true)
			}
			p.firstPrio0.CompareAndSwap(0, time.Now().UnixNano())
		}
		cp := *pkt
		cp.SrcIP = src
		to := p.peer
		if sender == p.peer {
			to = p.old
		}
		select {
		case to.rxCh <- &cp:
		default:
		}
		return nil
	}
	t.Cleanup(func() { sendPacketFn = previous })

	go p.old.run()
	go p.peer.run()
	t.Cleanup(func() { stopPrio0RunTestInstance(t, p.old) })
	t.Cleanup(func() { stopPrio0RunTestInstance(t, p.peer) })

	// The old primary holds the RG.
	p.oldMgr.ForceRGMaster(1)
	waitFor18716(t, "the old primary to become MASTER and hold the VIP", func() bool {
		return p.old.getState() == StateMaster && p.oldHeld.all()
	})
	// The election moves the RG: the new primary forces MASTER at 200 while
	// the old one is still MASTER at 200. ForceRGMaster only signals the run
	// loop, so wait for the claim itself.
	p.peerMgr.ForceRGMaster(1)
	waitFor18716(t, "the new primary to claim the VIP", func() bool { return p.peerClaims.Load() > 0 })
	return p
}

func waitFor18716(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// holdFor18716 asserts cond on every sample for d.
func holdFor18716(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !cond() {
			t.Fatalf("%s stopped holding", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// resignEndsIt18716: the old node's resign leaves exactly one holder, the new
// primary. When the old node is still MASTER (oldMaster), its priority-0
// adverts must exist and follow its release; a node that already lost the
// tie-break is BACKUP and correctly sends none. When the peer is BACKUP
// (peerBackup), the peer must take over ON that advert, within 50 ms of it,
// not on its ~100 ms master-down timer.
func resignEndsIt18716(t *testing.T, p *pair18716, oldMaster, peerBackup bool) {
	t.Helper()
	if got := p.old.getState() == StateMaster; got != oldMaster {
		t.Fatalf("setup: old node MASTER=%v at the resign, want %v", got, oldMaster)
	}
	p.oldMgr.ResignRG(1)
	waitFor18716(t, "the resign to hand the VIP to the new primary", func() bool {
		return !p.oldHeld.any() && p.old.getState() == StateBackup &&
			p.peerHeld.all() && p.peer.getState() == StateMaster
	})
	if p.prio0WhileHeld.Load() {
		t.Fatal("the old master sent its priority-0 resign while it still held the VIP")
	}
	first := p.firstPrio0.Load()
	if oldMaster && first == 0 {
		t.Fatal("the MASTER's resign put no priority-0 advert on the wire")
	}
	if peerBackup {
		claimed := p.peerClaimAfterPrio0.Load()
		if took := time.Duration(claimed - first); claimed == 0 || took > 50*time.Millisecond {
			t.Fatalf("the new primary claimed the VIP %s after the priority-0 advert, want within 50ms", took)
		}
	}
}

// TestLegacyEqualPriorityNewPrimaryHigherV4_18716 is outcome 1: no lasting
// window. The old master steps down on the new primary's advert.
func TestLegacyEqualPriorityNewPrimaryHigherV4_18716(t *testing.T) {
	p := newPair18716(t, net.ParseIP("10.0.61.2"), net.ParseIP("10.0.61.3"))
	waitFor18716(t, "the old master to lose the tie-break", func() bool {
		return !p.oldHeld.any() && p.old.getState() == StateBackup &&
			p.peerHeld.all() && p.peer.getState() == StateMaster
	})
	resignEndsIt18716(t, p, false, false)
}

// TestLegacyEqualPriorityOldMasterHigherV4_18716 is outcome 2: the NEW primary
// yields, so the VIP stays on the old node for as long as it does not resign.
// With the old order that was the 5 s prep (more with a stalled write) on a
// node whose helper is down: a single-owner blackhole, not a dual VIP. The
// resign then hands it over with no instant at which both hold it.
func TestLegacyEqualPriorityOldMasterHigherV4_18716(t *testing.T) {
	p := newPair18716(t, net.ParseIP("10.0.61.3"), net.ParseIP("10.0.61.2"))
	waitFor18716(t, "the new primary to lose the tie-break", func() bool {
		return p.peer.getState() == StateBackup && !p.peerHeld.any()
	})
	holdFor18716(t, 300*time.Millisecond, "the VIP staying on the old master", func() bool {
		return p.oldHeld.all() && !p.peerHeld.any()
	})
	p.bothHeld.Store(false) // the forced claim above is the tie-break's, not the resign's
	resignEndsIt18716(t, p, true, true)
	if p.bothHeld.Load() {
		t.Fatal("the resign handover added the VIP on the new primary while the old one still held it")
	}
}

// TestLegacyEqualPriorityNoIPv4SourceBothMaster_18716 is outcome 3, the dual-VIP
// shape: with no non-VIP IPv4 on the member there is no IPv4 advert, and both
// nodes stay MASTER holding the VIP until the old one resigns.
func TestLegacyEqualPriorityNoIPv4SourceBothMaster_18716(t *testing.T) {
	p := newPair18716(t, nil, nil)
	waitFor18716(t, "the new primary to become MASTER", func() bool {
		return p.peer.getState() == StateMaster && p.peerHeld.all()
	})
	holdFor18716(t, 500*time.Millisecond, "both nodes holding the VIP", func() bool {
		return p.oldHeld.all() && p.peerHeld.all() &&
			p.old.getState() == StateMaster && p.peer.getState() == StateMaster
	})
	resignEndsIt18716(t, p, true, false)
}
