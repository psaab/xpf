package vrrp

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// #18716 fold 2 (Codex P2): the daemon removes the stable router link-local
// when the resign barrier settles. That address sorts below the per-node
// link-locals, so resolveIPv6LinkLocal picks it as the IPv6 advert source and
// the peer learns it as the master source. The barrier must therefore settle
// only after the priority-0 burst is on the wire. Otherwise the burst goes out
// from a deleted address (the kernel rejects it), or, once the address watcher
// re-resolves, from a per-node source that the peer's #16018 gate drops as an
// unknown master. On an IPv6-only RETH the 1 ms handover then degrades to
// master-down expiry.

// addrList18716 is a mutable interface address list for addrsFn.
type addrList18716 struct {
	mu    sync.Mutex
	addrs []net.IP
}

func (l *addrList18716) get() ([]net.Addr, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]net.Addr, 0, len(l.addrs))
	for _, ip := range l.addrs {
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)})
	}
	return out, nil
}

func (l *addrList18716) has(ip net.IP) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, a := range l.addrs {
		if a.Equal(ip) {
			return true
		}
	}
	return false
}

func (l *addrList18716) remove(ip net.IP) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, a := range l.addrs {
		if a.Equal(ip) {
			l.addrs = append(l.addrs[:i], l.addrs[i+1:]...)
			return
		}
	}
}

func TestResignBurstKeepsTheLearnedLinkLocalSource18716(t *testing.T) {
	for _, ordering := range []string{"watcher-reresolves-at-once", "watcher-reresolves-later"} {
		t.Run(ordering, func(t *testing.T) {
			vrid, _ := rethVRID(1)
			stableLL := net.ParseIP("fe80::bf72:1:1") // config.StableRethLinkLocal(1, 1)
			oldEUI := net.ParseIP("fe80::5054:ff:fe00:1")
			peerEUI := net.ParseIP("fe80::5054:ff:fe00:2")
			vip := net.ParseIP("2001:db8:61::1")

			oldAddrs := &addrList18716{addrs: []net.IP{oldEUI, stableLL}}
			peerAddrs := &addrList18716{addrs: []net.IP{peerEUI}}
			oldMgr, peerMgr := NewManager(), NewManager()
			var peerClaimAt, firstPrio0At atomic.Int64
			mk := func(mgr *Manager, pri int, addrs *addrList18716, claimAt *atomic.Int64) *vrrpInstance {
				vi := newInstance(Instance{
					Interface:         "reth18716",
					GroupID:           vrid,
					Priority:          pri,
					AcceptData:        true,
					AdvertiseInterval: 30,
					VirtualAddresses:  []string{"2001:db8:61::1/64"}, // IPv6-only RETH
				}, &net.Interface{Name: "reth18716"}, mgr.eventCh, nil)
				vi.addrsFn = addrs.get
				vi.suppressGARP.Store(true)
				installFakeVIPNetlink(vi)
				vi.addrAddFn = func(_ netlink.Link, a *netlink.Addr) error {
					if claimAt != nil && a.IP.Equal(vip) && firstPrio0At.Load() != 0 {
						claimAt.CompareAndSwap(0, time.Now().UnixNano())
					}
					return nil
				}
				vi.reresolveLocalAddrs() // the real resolveIPv6LinkLocal
				mgr.mu.Lock()
				mgr.instances = map[instanceKey]*vrrpInstance{{iface: "reth18716", groupID: vrid}: vi}
				mgr.mu.Unlock()
				return vi
			}
			old := mk(oldMgr, 200, oldAddrs, nil)
			peer := mk(peerMgr, 100, peerAddrs, &peerClaimAt)
			if got := old.getLocalIPv6(); !got.Equal(stableLL) {
				t.Fatalf("setup: the old master's IPv6 advert source is %v, want the stable link-local %v (it sorts lowest)", got, stableLL)
			}

			// The "daemon" removes the stable link-local once the barrier
			// settles. The first priority-0 send waits briefly for that
			// removal, so a barrier that settles BEFORE the burst always lets
			// the removal win the race.
			removed := make(chan struct{})
			var gateOnce sync.Once
			var prio0Delivered atomic.Int32
			previous := sendPacketFn
			sendPacketFn = func(sender *vrrpInstance, pkt *VRRPPacket, isIPv6 bool) error {
				if !isIPv6 {
					return fmt.Errorf("no IPv4 on an IPv6-only RETH")
				}
				addrs, to := oldAddrs, peer
				if sender == peer {
					addrs, to = peerAddrs, old
				}
				if sender == old && pkt.Priority == 0 {
					gateOnce.Do(func() {
						select {
						case <-removed:
						case <-time.After(100 * time.Millisecond):
						}
					})
				}
				src := sender.getLocalIPv6()
				if src == nil || !addrs.has(src) {
					// IPV6_PKTINFO pins the source; the kernel rejects a
					// source that is no longer on the interface.
					return fmt.Errorf("source %v not on %s", src, sender.cfg.Interface)
				}
				if sender == old && pkt.Priority == 0 {
					firstPrio0At.CompareAndSwap(0, time.Now().UnixNano())
					prio0Delivered.Add(1)
				}
				cp := *pkt
				cp.SrcIP = src
				select {
				case to.rxCh <- &cp:
				default:
				}
				return nil
			}
			t.Cleanup(func() { sendPacketFn = previous })

			go old.run()
			go peer.run()
			t.Cleanup(func() { stopPrio0RunTestInstance(t, old) })
			t.Cleanup(func() { stopPrio0RunTestInstance(t, peer) })
			oldMgr.ForceRGMaster(1)
			waitPrio0TestMasterPriority(t, peer, 200) // the peer learned the master, from the stable LL
			if peer.getState() != StateBackup {
				t.Fatalf("setup: peer state %s, want BACKUP", peer.getState())
			}

			barrier := oldMgr.ResignRG(1)
			go func() {
				<-barrier.Done()
				oldAddrs.remove(stableLL)
				if ordering == "watcher-reresolves-later" {
					time.Sleep(30 * time.Millisecond)
				}
				old.reresolveLocalAddrs()
				close(removed)
			}()

			deadline := time.Now().Add(2 * time.Second)
			for peerClaimAt.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(2 * time.Millisecond)
			}
			if prio0Delivered.Load() == 0 {
				t.Fatal("no priority-0 advert reached the peer: the burst lost its source address")
			}
			claimed := peerClaimAt.Load()
			if took := time.Duration(claimed - firstPrio0At.Load()); claimed == 0 || took > 50*time.Millisecond {
				t.Fatalf("the peer claimed %v after the first priority-0 advert, want within 50ms: it did not admit the resign", took)
			}
		})
	}
}
