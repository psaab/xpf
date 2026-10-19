// Cluster peer dialing for cluster-wide CLI queries. The CLI uses the
// fabric link to reach the other chassis node so that `show ...`
// commands can aggregate state across the pair without requiring the
// operator to log in to both nodes.
package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/clusterfailover"
	"github.com/psaab/xpf/pkg/grpcapi"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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

	vrfDevice := ""
	if c.fabricVRFDeviceFn != nil {
		vrfDevice = c.fabricVRFDeviceFn()
	}
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// #5324: authenticate every RPC we dial on the peer's fabric listener
		// with the #4107 control-link PSK, mirroring the daemon-side dialer.
		// The client interceptors carry the full method and, for unary RPCs,
		// the request digest to the credential: captured tokens cannot be replayed
		// across methods or changed unary arguments.
		grpc.WithPerRPCCredentials(grpcapi.NewFabricAuthCreds(c.fabricAuthKey)),
		grpc.WithUnaryInterceptor(grpcapi.FabricAuthUnaryClientInterceptor),
		grpc.WithStreamInterceptor(grpcapi.FabricAuthStreamClientInterceptor),
	}
	if vrfDevice != "" {
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Control: func(network, address string, rc syscall.RawConn) error {
					var err error
					rc.Control(func(fd uintptr) {
						err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, vrfDevice)
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
		if vrfDevice != "" {
			d.Control = func(network, address string, rc syscall.RawConn) error {
				var err error
				rc.Control(func(fd uintptr) {
					err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, vrfDevice)
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

// peerSystemActionTimeout sizes the deadline for a CLI-forwarded
// SystemAction. Ordinary actions keep the historical 5s budget; a
// forwarded node-targeted cluster failover (#15081) runs the peer's
// full RequestPeerFailover sequence (ACK + settle + commit, each
// bounded well above 5s), so it uses the cluster-budget sizing
// (clusterfailover.ProxyFailoverTimeout).
func peerSystemActionTimeout(action string) time.Duration {
	if clusterfailover.IsFailoverActionString(action) {
		return clusterfailover.ProxyFailoverTimeout
	}
	return 5 * time.Second
}

// failoverProxyTimeoutMessage reconciles a CLI-forwarded failover whose
// proxy leg hit a deadline against current RG ownership (#15081): the
// peer may have committed after the proxy gave up, so a bare
// DeadlineExceeded must never reach the operator for this path. It
// returns (message, true) for deadline outcomes on targeted failovers
// and ("", false) otherwise (the caller relays the original error).
func (c *CLI) failoverProxyTimeoutMessage(action string, err error) (string, bool) {
	if err == nil || c.cluster == nil {
		return "", false
	}
	if !isDeadlineErr(err) {
		return "", false
	}
	op, perr := clusterfailover.ParseAction(action)
	if perr != nil || !op.Targeted() {
		return "", false
	}
	switch op.Kind {
	case clusterfailover.KindRGFailoverNode:
		if c.cluster.IsPeerPrimary(op.RG) {
			return fmt.Sprintf("Manual failover completed for redundancy group %d (transfer committed on node %d; proxy response timed out after the peer committed)", op.RG, op.Node), true
		}
		if !c.cluster.PeerAlive() {
			return fmt.Sprintf("Cluster failover outcome unknown for redundancy group %d: forwarded request to node %d timed out and the peer is unreachable; verify redundancy group %d ownership before retrying", op.RG, op.Node, op.RG), true
		}
		return fmt.Sprintf("Cluster failover outcome unknown for redundancy group %d: forwarded request to node %d timed out; redundancy group %d is not primary on node %d — verify ownership before retrying", op.RG, op.Node, op.RG, op.Node), true
	case clusterfailover.KindDataFailover:
		peerRGs, peerAlive := c.cluster.PeerPrimaryRGs()
		if !peerAlive {
			return fmt.Sprintf("Data failover outcome unknown: forwarded request to node %d timed out and the peer is unreachable; verify redundancy group ownership before retrying", op.Node), true
		}
		if dataRGs := c.cluster.DataGroupIDs(); len(dataRGs) > 0 && len(peerRGs) == len(dataRGs) {
			committed := true
			for _, rgID := range dataRGs {
				found := false
				for _, prg := range peerRGs {
					if prg == rgID {
						found = true
						break
					}
				}
				if !found {
					committed = false
					break
				}
			}
			if committed {
				return fmt.Sprintf("Manual failover completed for data redundancy groups %v (transfer committed on node %d; proxy response timed out after the peer committed)", dataRGs, op.Node), true
			}
		}
		return fmt.Sprintf("Data failover outcome unknown: forwarded request to node %d timed out; data redundancy groups now primary on node %d: %v — verify ownership before retrying", op.Node, op.Node, peerRGs), true
	}
	return "", false
}

// isDeadlineErr reports whether err is a context/gRPC deadline outcome.
func isDeadlineErr(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return status.Code(err) == codes.DeadlineExceeded
}

// requestPeerSystemAction asks the peer to perform a system-level action
// (reboot, shutdown, etc.) via the fabric gRPC link. When peerSystemActionFn
// is set, the request is satisfied locally without a fabric dial.
func (c *CLI) requestPeerSystemAction(ctx context.Context, action string) (string, error) {
	return c.requestPeerSystemActionWithPersistentNatGeneration(ctx, action, "", 0)
}

// requestPeerSystemActionWithPersistentNatGeneration is
// requestPeerSystemAction plus the durable persistent-NAT clear
// generation fence (#11486): when origin is non-empty it carries
// persistent_nat_{origin,generation} inside the signed SystemActionRequest
// body so the peer records RemoteGenerations[origin]=generation and rejects
// pre-clear lease replays. #14580 moved these out of unsigned gRPC metadata
// (x-peer-persistent-nat-*) into the request body, where the #4107 fabric
// token's request-digest MAC binds them.
func (c *CLI) requestPeerSystemActionWithPersistentNatGeneration(ctx context.Context, action string, origin string, generation uint64) (string, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "x-peer-forwarded", "1")
	req := &pb.SystemActionRequest{Action: action, PersistentNatOrigin: origin, PersistentNatGeneration: generation}
	if c.peerSystemActionFn != nil {
		msg, err := c.peerSystemActionFn(ctx, req)
		if err != nil {
			if message, ok := c.failoverProxyTimeoutMessage(action, err); ok {
				return message, nil
			}
			return "", err
		}
		return msg, nil
	}
	conn := c.dialPeer()
	if conn == nil {
		return "", fmt.Errorf("cluster peer not reachable")
	}
	defer conn.Close()

	peerCtx, cancel := context.WithTimeout(ctx, peerSystemActionTimeout(action))
	defer cancel()
	resp, err := pb.NewBpfrxServiceClient(conn).SystemAction(peerCtx, req)
	if err != nil {
		if message, ok := c.failoverProxyTimeoutMessage(action, err); ok {
			return message, nil
		}
		return "", err
	}
	return resp.Message, nil
}
