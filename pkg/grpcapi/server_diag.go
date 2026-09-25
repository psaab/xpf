package grpcapi

import (
	"context"
	"log/slog"
	"net"
	"syscall"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// peerFabricGRPCPort is the port dialPeer probes on the peer's fabric listener.
// A package var ONLY so a test can point dialPeer at a real in-process gRPC
// server on an ephemeral port and drive the probe's error classification
// through the real function — a cell calling the classification helper directly
// would pass against a dialPeer that had stopped consulting it.
var peerFabricGRPCPort = "50051"

// dialPeer establishes a gRPC connection to the cluster peer via the fabric link.
// Tries fab0 first, then fab1 if dual-fabric is configured and fab0 fails.
// Returns the connection or an error if not in cluster mode / all addresses fail.
// The caller context bounds both connection establishment and each liveness probe.
func (s *Server) dialPeer(ctx context.Context) (*grpc.ClientConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	if s.fabricPeerAddrFn == nil {
		return nil, status.Error(codes.Unavailable, "not in cluster mode")
	}
	peerIPs := s.fabricPeerAddrFn()
	if len(peerIPs) == 0 {
		return nil, status.Error(codes.Unavailable, "cluster peer address not available")
	}
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}

	// #4107: authenticate every RPC we dial on the peer's fabric listener with
	// the control-link PSK. The client interceptors carry each full method and
	// unary request digest to the per-RPC credential, so a captured token cannot
	// cross methods or authorize changed unary arguments. GetRequestMetadata is
	// read per RPC, so tokens rotate with the auth window and a not-yet-keyed
	// node dials tokenless (dual-accept).
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(fabricAuthCreds{keyFn: s.fabricAuthKey}),
		grpc.WithUnaryInterceptor(FabricAuthUnaryClientInterceptor),
		grpc.WithStreamInterceptor(FabricAuthStreamClientInterceptor),
	}
	if s.fabricVRFDevice != "" {
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Control: func(network, address string, c syscall.RawConn) error {
					var err error
					c.Control(func(fd uintptr) {
						err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, s.fabricVRFDevice)
					})
					return err
				},
			}
			return dialer.DialContext(ctx, "tcp", addr)
		}))
	}

	// Try each fabric address; return first successful connection.
	var lastErr error
	for _, ip := range peerIPs {
		if err := ctx.Err(); err != nil {
			return nil, status.FromContextError(err).Err()
		}
		// #8597 (muse-004 K29): net.JoinHostPort, not "%s:port". An IPv6
		// fabric literal formatted the old way yields `2001:db8::2:50051`,
		// which grpc.NewClient parses as a bogus host:port — so an IPv6-only
		// fabric never dials its peer and the failure looks like the peer being
		// unreachable. #4909 fixed the identical shape in `pkg/cli/peer.go`,
		// whose comment documents this exact string; this site and the two
		// fabric LISTENER addresses in `daemon_ha_comms_wiring.go` were the
		// rest of that class.
		peerAddr := net.JoinHostPort(ip, peerFabricGRPCPort)
		conn, err := grpc.NewClient(peerAddr, dialOpts...)
		if err != nil {
			lastErr = err
			continue
		}
		// Verify the connection is usable with a short deadline derived from
		// the caller. The caller's earlier deadline wins, so cancellation
		// aborts the probe immediately rather than waiting for 2 seconds.
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		client := pb.NewBpfrxServiceClient(conn)
		_, err = client.GetStatus(probeCtx, &pb.GetStatusRequest{})
		cancel()
		if ctxErr := ctx.Err(); ctxErr != nil {
			conn.Close()
			return nil, status.FromContextError(ctxErr).Err()
		}
		// #8597 (muse-004 K28): a ResourceExhausted answer PROVES the peer is
		// alive and must not be read as a dead connection.
		//
		// `GetStatus` is used here purely as a liveness probe, but on the peer
		// it takes a `sessionWalkLimiter` slot and drives a full v4+v6
		// `SessionCount()` (#5782). A peer already at scan capacity therefore
		// answers ResourceExhausted, and treating that as a failed dial
		// reported a BUSY peer as an UNREACHABLE one — the diagnosis an
		// operator acts on is then "the fabric is down" when the fabric is
		// fine and the peer is loaded.
		//
		// A ResourceExhausted reply is strictly STRONGER evidence of liveness
		// than a success: the connection was accepted, the fabric PSK
		// authenticated, the #4122 allowlist admitted the method, and the
		// handler ran far enough to reach its own limiter. Nothing that far
		// down the path happens on a dead peer.
		//
		// NOT addressed here, deliberately: the probe still COSTS the peer a
		// scan slot when it is not saturated. Removing that means probing with
		// a cheaper RPC, and every cheaper candidate — GetConfigModeStatus
		// included — is absent from `fabricAllowedUnaryMethods`, so it would
		// mean widening a fail-closed security allowlist (#4122) to buy a
		// performance improvement. That trade wants its own decision, not a
		// side effect of this one.
		if err != nil && status.Code(err) == codes.ResourceExhausted {
			slog.Debug("peer is alive but at scan capacity; treating as reachable",
				"addr", peerAddr)
			return conn, nil
		}
		if err != nil {
			conn.Close()
			lastErr = err
			slog.Debug("peer dial failed, trying next fabric address", "addr", peerAddr, "err", err)
			continue
		}
		return conn, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	return nil, status.Errorf(codes.Unavailable, "cannot connect to peer on any fabric address: %v", lastErr)
}
