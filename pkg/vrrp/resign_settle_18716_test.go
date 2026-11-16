package vrrp

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// #18716 fold 2: a forced resign settles its barriers only after its
// priority-0 burst. These cells pin that it settles on EVERY exit, so a failed
// or panicking burst can never leave a daemon waiter (the failover fence, the
// stable link-local release) hanging.

func newSettleInstance18716(t *testing.T) (*vrrpInstance, *time.Timer, *time.Timer, *ResignBarrier) {
	t.Helper()
	vrid, _ := rethVRID(1)
	vi := newInstance(Instance{
		Interface:         "reth18716",
		GroupID:           vrid,
		Priority:          200,
		AdvertiseInterval: 30,
		VirtualAddresses:  []string{"10.0.61.1/24", "2001:db8:61::1/64"},
	}, &net.Interface{Name: "reth18716"}, make(chan VRRPEvent, 64), nil)
	vi.setLocalIP(net.ParseIP("10.0.61.2"))
	vi.setLocalIPv6(net.ParseIP("fe80::a"))
	vi.suppressGARP.Store(true)
	installFakeVIPNetlink(vi)
	vi.setState(StateMaster)
	masterDown, advert := time.NewTimer(time.Hour), time.NewTimer(time.Hour)
	t.Cleanup(func() { masterDown.Stop(); advert.Stop() })
	b := newResignBarrier(1)
	vi.armResignAck(b)
	return vi, masterDown, advert, b
}

func settled18716(t *testing.T, b *ResignBarrier) error {
	t.Helper()
	select {
	case <-b.Done():
		return b.Err()
	case <-time.After(time.Second):
		t.Fatal("the resign barrier never settled; a daemon waiter would hang")
		return nil
	}
}

func withSend18716(t *testing.T, fn func(*vrrpInstance, *VRRPPacket, bool) error) {
	t.Helper()
	previous := sendPacketFn
	sendPacketFn = fn
	t.Cleanup(func() { sendPacketFn = previous })
}

// The burst's sends all fail: the VIPs are off, so the barrier settles clean.
func TestForcedResignSettlesWhenTheBurstFailsToSend18716(t *testing.T) {
	vi, md, adv, b := newSettleInstance18716(t)
	var attempts atomic.Int32
	withSend18716(t, func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
		if pkt.Priority == 0 {
			attempts.Add(1)
		}
		return errors.New("socket closed")
	})
	vi.resignWithBurst(md, adv)
	if err := settled18716(t, b); err != nil {
		t.Fatalf("barrier verdict %v, want nil: the VIPs are off even though the burst failed", err)
	}
	if attempts.Load() == 0 {
		t.Fatal("setup: no priority-0 send was attempted")
	}
}

// The VIP removal fails: no burst, and the barrier settles WITH the error.
func TestForcedResignSettlesWithTheRemovalError18716(t *testing.T) {
	vi, md, adv, b := newSettleInstance18716(t)
	vi.addrDelFn = func(netlink.Link, *netlink.Addr) error { return errors.New("injected removal failure") }
	var prio0 atomic.Int32
	withSend18716(t, func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
		if pkt.Priority == 0 {
			prio0.Add(1)
		}
		return nil
	})
	vi.resignWithBurst(md, adv)
	if err := settled18716(t, b); err == nil {
		t.Fatal("barrier verdict nil, want the removal error: the VIPs may still be on the wire")
	}
	if prio0.Load() != 0 {
		t.Fatal("a failed removal sent priority zero")
	}
}

// A panic while sending (VIPs already off: nil) or while removing (nothing
// proves the VIPs are off: an error) still settles the barrier.
func TestForcedResignSettlesWhenItPanics18716(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inSend  bool
		wantErr bool
	}{
		{"panic-in-burst", true, false},
		{"panic-in-removal", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vi, md, adv, b := newSettleInstance18716(t)
			if tc.inSend {
				withSend18716(t, func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
					if pkt.Priority == 0 {
						panic("injected send panic")
					}
					return nil
				})
			} else {
				vi.addrDelFn = func(netlink.Link, *netlink.Addr) error { panic("injected removal panic") }
			}
			func() {
				defer func() { _ = recover() }()
				vi.resignWithBurst(md, adv)
			}()
			if err := settled18716(t, b); (err != nil) != tc.wantErr {
				t.Fatalf("barrier verdict %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
