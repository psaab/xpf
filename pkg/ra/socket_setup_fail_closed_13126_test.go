package ra

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

type setupFaultConn struct {
	ndpConn
	controlErr error
	joinErr    error
	filterErr  error
}

func (c *setupFaultConn) SetControlMessage(ipv6.ControlFlags, bool) error { return c.controlErr }
func (c *setupFaultConn) JoinGroup(netip.Addr) error                      { return c.joinErr }
func (c *setupFaultConn) SetICMPFilter(*ipv6.ICMPFilter) error            { return c.filterErr }

func TestOpenConnFailsClosedOnRouterSolicitationSetupError13126(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*setupFaultConn, error)
	}{
		{"enable hop-limit control message", func(c *setupFaultConn, err error) { c.controlErr = err }},
		{"join all-routers group", func(c *setupFaultConn, err error) { c.joinErr = err }},
		{"install RS-only ICMP filter", func(c *setupFaultConn, err error) { c.filterErr = err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			getConn, _ := installFakeListen(t)
			origListen := listenFn
			t.Cleanup(func() { listenFn = origListen })
			setupErr := errors.New("injected socket setup failure")
			listenFn = func(iface *net.Interface, addr ndp.Addr) (ndpConn, netip.Addr, error) {
				conn, src, err := origListen(iface, addr)
				if err != nil {
					return nil, src, err
				}
				fault := &setupFaultConn{ndpConn: conn}
				tc.setup(fault, setupErr)
				return fault, src, nil
			}

			s := newSender(testCfg("ra-setup-13126"), &net.Interface{Name: "ra-setup-13126"})
			if s.openConn() {
				t.Fatal("openConn succeeded despite Router Solicitation socket setup failure")
			}
			fc := getConn("ra-setup-13126")
			if fc == nil {
				t.Fatal("listen did not create test connection")
			}
			fc.mu.Lock()
			closed := fc.closed
			fc.mu.Unlock()
			if !closed {
				t.Fatal("partially configured NDP connection was not closed")
			}
			if s.conn != nil {
				t.Fatal("failed open retained partially configured connection")
			}
		})
	}
}
