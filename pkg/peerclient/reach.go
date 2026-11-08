package peerclient

import (
	"context"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ProbeFabricTCPTimeout bounds one fabric address's TCP reachability probe.
// It is the 2 s both dialers have always used.
const ProbeFabricTCPTimeout = 2 * time.Second

// ProbeFabricTCP reports, as a nil error, whether addr (host:port) accepts a
// TCP connection within timeout and the caller's ctx, optionally bound to
// vrfDevice (SO_BINDTODEVICE, the fabric VRF). The connection is closed at
// once; nothing is sent.
//
// It is the ONE "did the request reach the peer" test of the #18559
// untargeted-failover fallback, shared by pkg/cli's and pkg/grpcapi's dialers
// so the two frontends cannot disagree on it: a request counts as never
// reached only when NO fabric address accepted a TCP connection (transport
// absence: refused, unreachable, or no SYN-ACK in time). A peer that accepted
// a connection and then answered anything — an Unauthenticated or slow
// GetStatus probe, an RPC error — was reached, and its answer is returned to
// the operator instead of falling back to the local resign.
func ProbeFabricTCP(ctx context.Context, addr, vrfDevice string, timeout time.Duration) error {
	d := &net.Dialer{Timeout: timeout}
	if vrfDevice != "" {
		d.Control = func(network, address string, rc syscall.RawConn) error {
			var err error
			if cerr := rc.Control(func(fd uintptr) {
				err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, vrfDevice)
			}); cerr != nil {
				return cerr
			}
			return err
		}
	}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = c.Close()
	return nil
}
