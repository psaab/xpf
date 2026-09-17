package vrrp

import (
	"net"
	"testing"
	"time"
)

// #9914 F-042 fail-on-revert: the local timer and wire must agree after one
// normalization. Tolerant load / peer-sync may deliver non-positive or
// over-range intervals; neither may wrap through the wire field.
func TestF042_TimerWireAgreement_9914(t *testing.T) {
	cases := []struct {
		name string
		ms   int
	}{
		{"zero unset", 0},
		{"negative small", -10},
		{"negative large", -40950},
		{"inexact millisecond", 15},
		{"control 30ms", 30},
		{"control max encodable", 40950},
		{"first above max", 40960},
		{"large above max", 700000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vi := newInstance(Instance{
				Interface:         "xpf-9914-f042",
				GroupID:           42,
				Priority:          200,
				AdvertiseInterval: tc.ms,
				VirtualAddresses:  []string{"10.0.0.254/24"},
			}, &net.Interface{Name: "xpf-9914-f042"}, nil, nil)

			var pktVal uint16
			var saw bool
			prev := sendPacketFn
			sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
				pktVal, saw = pkt.MaxAdvertInt, true
				return nil
			}
			t.Cleanup(func() { sendPacketFn = prev })
			vi.sendAdvert(200)
			if !saw {
				t.Fatal("sendAdvert emitted no packet; fixture measures nothing")
			}
			// True wire after packet.go 0x0FFF mask, back to ms.
			wireMS := int(pktVal&0x0FFF) * 10
			timerMS := int(advertIntervalFromMS(tc.ms) / time.Millisecond)
			// Also observe the timer via the instance accessor.
			accessorMS := int(vi.advertInterval() / time.Millisecond)
			if timerMS != accessorMS {
				t.Fatalf("timer helper %dms != accessor %dms; fixture inconsistent", timerMS, accessorMS)
			}
			if pktVal&0x0FFF != pktVal {
				t.Errorf("ms=%d: pkt MaxAdvertInt %d needs the 0x0FFF mask (wraps to %d); sink must saturate",
					tc.ms, pktVal, pktVal&0x0FFF)
			}
			if timerMS != wireMS {
				t.Errorf("ms=%d: timer %dms != wire %dms (pkt %d); timer and wire must derive from one normalization",
					tc.ms, timerMS, wireMS, pktVal)
			}
		})
	}
}
