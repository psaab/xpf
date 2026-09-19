// Cluster peer dialing for cluster-wide CLI queries. The CLI uses the
// fabric link to reach the other chassis node so that `show ...`
// commands can aggregate state across the pair without requiring the
// operator to log in to both nodes.
package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/grpcapi"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// fabricAuthKey resolves the #4107 control-link PSK the CLI attaches to peer
// fabric dials. It mirrors grpcapi Server.fabricAuthKey: a test seam wins, then
// the live cluster-manager key, else nil (unkeyed / standalone -> the dial is
// tokenless and the peer's dual-accept grace still admits it).
func (c *CLI) fabricAuthKey() []byte {
	if c.fabricAuthKeyFn != nil {
		return c.fabricAuthKeyFn()
	}
	if c.cluster != nil {
		return c.cluster.ControlLinkAuthKey()
	}
	return nil
}

// peerEndpoint builds the host:port gRPC/dial target for a peer fabric address.
// It uses net.JoinHostPort so an IPv6 fabric literal (e.g. 2001:db8::2) is
// bracketed to [2001:db8::2]:50051; the pre-#4909 fmt.Sprintf("%s:%d") produced
// the unbracketed 2001:db8::2:50051, which grpc.NewClient and the TCP
// reachability probe both parse as a bogus host:port so the IPv6 fabric dial
// silently fails.
func peerEndpoint(ip string, port int) string {
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

// peerPort returns the peer fabric gRPC port, defaulting to 50051.
func (c *CLI) peerPort() int {
	if c.fabricPeerPort != 0 {
		return c.fabricPeerPort
	}
	return 50051
}

// dialPeer establishes a gRPC connection to the cluster peer, trying fab0
// then fab1 if dual-fabric is configured. Returns nil if not in cluster mode.
func (c *CLI) dialPeer() *grpc.ClientConn {
	if c.fabricPeerAddrFn == nil {
		return nil
	}
	peerIPs := c.fabricPeerAddrFn()
	if len(peerIPs) == 0 {
		return nil
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// #5324: authenticate every RPC we dial on the peer's fabric listener
		// with the #4107 control-link PSK, mirroring the daemon-side dialer.
		// The client interceptors carry each full method to the credential so
		// captured tokens cannot be replayed across RPC methods.
		grpc.WithPerRPCCredentials(grpcapi.NewFabricAuthCreds(c.fabricAuthKey)),
		grpc.WithUnaryInterceptor(grpcapi.FabricAuthUnaryClientInterceptor),
		grpc.WithStreamInterceptor(grpcapi.FabricAuthStreamClientInterceptor),
	}
	if c.fabricVRFDevice != "" {
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Control: func(network, address string, rc syscall.RawConn) error {
					var err error
					rc.Control(func(fd uintptr) {
						err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.fabricVRFDevice)
					})
					return err
				},
			}
			return dialer.DialContext(ctx, "tcp", addr)
		}))
	}

	port := c.peerPort()
	for _, ip := range peerIPs {
		peerAddr := peerEndpoint(ip, port)
		conn, err := grpc.NewClient(peerAddr, dialOpts...)
		if err != nil {
			continue
		}
		// Quick TCP probe to verify the address is reachable.
		d := &net.Dialer{Timeout: 2 * time.Second}
		if c.fabricVRFDevice != "" {
			d.Control = func(network, address string, rc syscall.RawConn) error {
				var err error
				rc.Control(func(fd uintptr) {
					err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.fabricVRFDevice)
				})
				return err
			}
		}
		tc, err := d.DialContext(context.Background(), "tcp", peerAddr)
		if err != nil {
			conn.Close()
			slog.Debug("peer dial failed, trying next fabric address", "addr", peerAddr, "err", err)
			continue
		}
		tc.Close()
		return conn
	}
	slog.Warn("failed to dial peer on any fabric address")
	return nil
}

// requestPeerSystemAction asks the peer to perform a system-level action
// (reboot, shutdown, etc.) via the fabric gRPC link. When peerSystemActionFn
// is set, the request is satisfied locally without a fabric dial.
func (c *CLI) requestPeerSystemAction(ctx context.Context, action string) (string, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "x-peer-forwarded", "1")
	if c.peerSystemActionFn != nil {
		return c.peerSystemActionFn(ctx, action)
	}
	conn := c.dialPeer()
	if conn == nil {
		return "", fmt.Errorf("cluster peer not reachable")
	}
	defer conn.Close()

	peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := pb.NewBpfrxServiceClient(conn).SystemAction(peerCtx, &pb.SystemActionRequest{Action: action})
	if err != nil {
		return "", err
	}
	return resp.Message, nil
}
