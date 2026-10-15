// rs_receive_validation_5095_test.go — #5095 / #13126.
//
// RFC 4861 §6.1.1 requires a router to silently discard a received Router
// Solicitation whose IP Hop Limit is not 255, whose source is off-link, or
// whose unspecified source carries a Source Link-Layer Address option.
package ra

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

func TestValidRSReceiveRFC4861(t *testing.T) {
	hop := func(n int) *ipv6.ControlMessage { return &ipv6.ControlMessage{HopLimit: n} }
	emptyRS := &ndp.RouterSolicitation{}
	slla := &ndp.LinkLayerAddress{Direction: ndp.Source, Addr: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}}
	tlla := &ndp.LinkLayerAddress{Direction: ndp.Target, Addr: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}}
	cases := []struct {
		name string
		cm   *ipv6.ControlMessage
		src  string
		rs   *ndp.RouterSolicitation
		want bool
	}{
		{"hop255 link-local", hop(255), "fe80::2", emptyRS, true},
		{"hop255 link-local with SLLA", hop(255), "fe80::2", &ndp.RouterSolicitation{Options: []ndp.Option{slla}}, true},
		{"hop255 unspecified no options", hop(255), "::", emptyRS, true},
		{"hop255 unspecified with SLLA", hop(255), "::", &ndp.RouterSolicitation{Options: []ndp.Option{slla}}, false},
		{"hop255 unspecified with TLLA", hop(255), "::", &ndp.RouterSolicitation{Options: []ndp.Option{tlla}}, true},
		{"hop255 global source", hop(255), "2001:db8::1", emptyRS, false},
		{"hop255 ULA source", hop(255), "fc00::1", emptyRS, false},
		{"hop255 multicast source", hop(255), "ff02::1", emptyRS, false},
		{"hop254 link-local (off-link)", hop(254), "fe80::2", emptyRS, false},
		{"hop64 link-local (forwarded)", hop(64), "fe80::2", emptyRS, false},
		{"nil control message", nil, "fe80::2", emptyRS, false},
		{"nil solicitation", hop(255), "fe80::2", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validRSReceive(tc.cm, netip.MustParseAddr(tc.src), tc.rs)
			if got != tc.want {
				t.Fatalf("validRSReceive(%v, %s, %v) = %v, want %v", tc.cm, tc.src, tc.rs, got, tc.want)
			}
		})
	}
}

// TestRSReceiveValidationEndToEnd drives the sender's real RS pipeline: an
// invalid RS (off-link hop limit) must NOT trigger an RA reply, while a valid RS
// (hop 255, link-local) does. fail-on-revert: reverting rsReceiver to skip
// validRSReceive makes the invalid RS reach the owner and trigger a reply within
// maxRSDelay, so the "no reply" assertion goes red.
func TestRSReceiveValidationEndToEnd(t *testing.T) {
	getConn, _ := installFakeListen(t)
	iface := &net.Interface{Name: "rs5095", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg("rs5095"), iface)
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.stop()

	fc := waitConn(t, getConn, "rs5095")
	waitWrites(t, fc, startupBurstCount)
	s.setLastRA(time.Now().Add(-2 * minRAMulticastDelay))
	fc.injectRSRaw(&ipv6.ControlMessage{HopLimit: 254}, netip.MustParseAddr("fe80::2"))
	time.Sleep(maxRSDelay + 300*time.Millisecond)
	if n := len(fc.snapshot()); n != startupBurstCount {
		t.Fatalf("off-link RS (hop-limit 254) triggered %d RA reply(ies); RFC 4861 §6.1.1 requires it be silently discarded (#5095)", n-startupBurstCount)
	}
	fc.injectRS(netip.MustParseAddr("fe80::2"))
	waitWrites(t, fc, startupBurstCount+1)
}
