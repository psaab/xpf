// rs_unspecified_slla_13126_test.go — #13126 (D10-09).
//
// RFC 4861 §6.1.1: "If the IP source address is the unspecified address,
// there is no source link-layer address option in the message." Before
// #13126 rsReceiver discarded the parsed *ndp.RouterSolicitation and
// validRSReceive checked only (HopLimit, src), so an RS from :: carrying a
// Source Link-Layer Address option passed and triggered a multicast RA.
package ra

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

// rsOptionsConn wraps fakeConn and returns a caller-supplied RS message.
type rsOptionsConn struct {
	*fakeConn
	msg ndp.Message
}

func (c *rsOptionsConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	msg, cm, src, err := c.fakeConn.ReadFrom()
	if err == nil {
		return c.msg, cm, src, nil
	}
	return msg, cm, src, err
}

// TestRSUnspecifiedSourceSLLAEndToEnd13126 drives the real sender pipeline:
// :: + SLLA must NOT trigger an RA.
func TestRSUnspecifiedSourceSLLAEndToEnd13126(t *testing.T) {
	rsWithSLLA := &ndp.RouterSolicitation{Options: []ndp.Option{
		&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}},
	}}
	// Exercise wire round-trip: ndp.ParseMessage sees only the payload, which
	// is exactly why rsReceiver must correlate src with rs.Options.
	raw, err := ndp.MarshalMessage(rsWithSLLA)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	parsed, err := ndp.ParseMessage(raw)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	getConn, _ := installFakeListen(t)
	origListen := listenFn
	t.Cleanup(func() { listenFn = origListen })
	listenFn = func(iface *net.Interface, addr ndp.Addr) (ndpConn, netip.Addr, error) {
		c, ip, err := origListen(iface, addr)
		if err != nil {
			return nil, ip, err
		}
		return &rsOptionsConn{fakeConn: c.(*fakeConn), msg: parsed}, ip, nil
	}

	iface := &net.Interface{Name: "rs13126", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg("rs13126"), iface)
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.stop()

	fc := waitConn(t, getConn, "rs13126")
	waitWrites(t, fc, startupBurstCount)
	s.setLastRA(time.Now().Add(-2 * minRAMulticastDelay))

	fc.injectRSRaw(&ipv6.ControlMessage{HopLimit: 255}, netip.MustParseAddr("::"))
	time.Sleep(maxRSDelay + 300*time.Millisecond)
	if n := len(fc.snapshot()); n != startupBurstCount {
		t.Fatalf("RS from :: with SLLA triggered %d RA reply(ies); RFC 4861 §6.1.1 requires 0 (#13126)", n-startupBurstCount)
	}
}
