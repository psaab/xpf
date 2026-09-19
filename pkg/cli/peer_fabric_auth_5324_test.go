package cli

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/grpcapi"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// #5324: the CLI's peer fabric dialer (dialPeer) must attach the #4107
// control-link PSK per-RPC credential so its cross-node fabric RPCs are accepted
// once the peer's fabric auth guard arms. Before the fix dialPeer built
// insecure-only dialOpts with NO WithPerRPCCredentials, so a keyed cluster's
// fabric listener rejected every CLI peer RPC (sessions/clear/chassis-forwarding/
// target-failover) as Unauthenticated in the secure steady state — silently,
// because the pre-dial TCP probe still passed.
//
// These tests stand up a REAL loopback gRPC fabric server whose interceptor
// enforces the same token scheme the daemon uses (via the shared
// grpcapi.NewFabricAuthCreds oracle), then drive an RPC end-to-end through
// dialPeer. On revert to the insecure-only dialer the keyed case goes RED: the
// CLI sends no token and the armed server returns Unauthenticated.

// fabricAuthMetadataKeyTest mirrors the unexported grpcapi.fabricAuthMetadataKey.
// Pinned here (an external package cannot read the unexported constant); the
// grpcapi.NewFabricAuthCreds oracle below is the source of truth for the token
// value, so a scheme change surfaces as a mismatch, not a silent pass.
const fabricAuthMetadataKeyTest = "xpf-fabric-auth"

// fakeFabricServer is a minimal BpfrxService that answers GetStatus so a peer
// RPC dialed through dialPeer reaches a handler.
type fakeFabricServer struct {
	pb.UnimplementedBpfrxServiceServer
}

func (fakeFabricServer) GetStatus(context.Context, *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

// fabricEnforcingInterceptor mimics the ARMED fabric auth guard: it rejects any
// RPC whose xpf-fabric-auth header is absent or does not match the expected
// current-window token for serverKey. The expected token is computed with the
// production client-cred code (grpcapi.NewFabricAuthCreds) so the server side of
// the test cannot drift from the real scheme. On revert of dialPeer the header is
// absent -> Unauthenticated -> RED. When serverKey is empty the server is
// unkeyed and admits everything (dual-accept / no-regression path).
func fabricEnforcingInterceptor(serverKey []byte) grpc.UnaryServerInterceptor {
	oracle := grpcapi.NewFabricAuthCreds(func() []byte { return serverKey })
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if len(serverKey) == 0 {
			return handler(ctx, req) // unkeyed: cannot enforce, dual-accept
		}
		want, err := oracle.GetRequestMetadata(grpcapi.WithFabricAuthMethod(ctx, info.FullMethod))
		if err != nil {
			return nil, err
		}
		var got string
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if v := md.Get(fabricAuthMetadataKeyTest); len(v) > 0 {
				got = v[0]
			}
		}
		if got == "" || got != want[fabricAuthMetadataKeyTest] {
			return nil, status.Error(codes.Unauthenticated, "fabric RPC authentication failed")
		}
		return handler(ctx, req)
	}
}

// startFakeFabricServer launches a loopback gRPC fabric server with the given
// enforcing key and returns its port plus a stop func.
func startFakeFabricServer(t *testing.T, serverKey []byte) (port int, stop func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpc.UnaryInterceptor(fabricEnforcingInterceptor(serverKey)))
	pb.RegisterBpfrxServiceServer(srv, fakeFabricServer{})
	go func() { _ = srv.Serve(lis) }()
	return lis.Addr().(*net.TCPAddr).Port, srv.Stop
}

// callPeerStatus dials the peer through dialPeer and issues one GetStatus,
// returning the RPC error (nil on success).
func callPeerStatus(t *testing.T, c *CLI) error {
	t.Helper()
	conn := c.dialPeer()
	if conn == nil {
		t.Fatal("dialPeer returned nil (peer unreachable)")
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := pb.NewBpfrxServiceClient(conn).GetStatus(ctx, &pb.GetStatusRequest{})
	return err
}

// TestDialPeerKeyedAttachesCredentialAcceptedByArmedFabric: with a fabric PSK
// configured, dialPeer attaches the per-RPC credential and a peer RPC against an
// armed (keyed, enforcing) fabric server SUCCEEDS. RED on revert to the
// insecure-only dialer: the CLI sends no token and the server returns
// Unauthenticated.
func TestDialPeerKeyedAttachesCredentialAcceptedByArmedFabric(t *testing.T) {
	key := []byte("cli-fabric-control-link-psk")
	port, stop := startFakeFabricServer(t, key)
	defer stop()

	c := &CLI{
		fabricPeerAddrFn: func() []string { return []string{"127.0.0.1"} },
		fabricPeerPort:   port,
		fabricAuthKeyFn:  func() []byte { return key },
	}
	if err := callPeerStatus(t, c); err != nil {
		t.Fatalf("keyed peer RPC against armed fabric: expected success, got %v (status=%v)", err, status.Code(err))
	}
}

// TestDialPeerInsecureOnlyRejectedByArmedFabric documents the pre-fix behavior:
// a dialer that omits the credential (fabricAuthKeyFn returns nil so no token is
// sent, exactly like the reverted insecure-only dialer) is rejected
// Unauthenticated by the ARMED (keyed) fabric server. This is the failure mode
// #5324 fixes, and pins that the enforcing server truly rejects a tokenless dial.
func TestDialPeerInsecureOnlyRejectedByArmedFabric(t *testing.T) {
	key := []byte("cli-fabric-control-link-psk")
	port, stop := startFakeFabricServer(t, key)
	defer stop()

	// Build a dialer that mirrors the reverted (pre-#5324) code: transport creds
	// only, no WithPerRPCCredentials. Dial the same armed server directly.
	peerAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := grpc.NewClient(peerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := pb.NewBpfrxServiceClient(conn).GetStatus(ctx, &pb.GetStatusRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("tokenless dial against armed fabric: expected Unauthenticated, got %v", err)
	}
}

// TestDialPeerUnkeyedNoRegression: with NO fabric PSK (unkeyed cluster) dialPeer
// still works without a credential — the credential self-suppresses (empty key
// -> no token) and the unkeyed peer admits the tokenless call. No regression to
// today's unkeyed-cluster peer ops.
func TestDialPeerUnkeyedNoRegression(t *testing.T) {
	port, stop := startFakeFabricServer(t, nil) // unkeyed server: no enforcement
	defer stop()

	c := &CLI{
		fabricPeerAddrFn: func() []string { return []string{"127.0.0.1"} },
		fabricPeerPort:   port,
		// no fabricAuthKeyFn and no cluster -> fabricAuthKey() returns nil
	}
	if c.fabricAuthKey() != nil {
		t.Fatalf("unkeyed CLI: expected nil fabric key, got %q", c.fabricAuthKey())
	}
	if err := callPeerStatus(t, c); err != nil {
		t.Fatalf("unkeyed peer RPC: expected success (no credential), got %v", err)
	}
}

// TestDialPeerFabricCredMatchesDaemonScheme: the credential the CLI attaches
// (from its resolved fabric key) produces the SAME token header the daemon-side
// dialer (grpcapi.NewFabricAuthCreds over the identical key) produces — so the
// peer's fabricAuthInterceptor, which verifies against that scheme, accepts it.
func TestDialPeerFabricCredMatchesDaemonScheme(t *testing.T) {
	key := []byte("shared-control-link-psk")
	c := &CLI{fabricAuthKeyFn: func() []byte { return key }}

	if got := c.fabricAuthKey(); string(got) != string(key) {
		t.Fatalf("fabricAuthKey() = %q, want %q", got, key)
	}

	cliCreds := grpcapi.NewFabricAuthCreds(c.fabricAuthKey)
	daemonCreds := grpcapi.NewFabricAuthCreds(func() []byte { return key })
	method := pb.BpfrxService_GetStatus_FullMethodName

	cliMD, err := cliCreds.GetRequestMetadata(grpcapi.WithFabricAuthMethod(context.Background(), method))
	if err != nil {
		t.Fatalf("cli GetRequestMetadata: %v", err)
	}
	daemonMD, err := daemonCreds.GetRequestMetadata(grpcapi.WithFabricAuthMethod(context.Background(), method))
	if err != nil {
		t.Fatalf("daemon GetRequestMetadata: %v", err)
	}
	if cliMD[fabricAuthMetadataKeyTest] == "" {
		t.Fatal("keyed CLI attached no fabric token")
	}
	if cliMD[fabricAuthMetadataKeyTest] != daemonMD[fabricAuthMetadataKeyTest] {
		t.Fatalf("CLI token %q != daemon-scheme token %q",
			cliMD[fabricAuthMetadataKeyTest], daemonMD[fabricAuthMetadataKeyTest])
	}

	// Unkeyed -> no token header (the credential self-suppresses).
	empty := grpcapi.NewFabricAuthCreds(func() []byte { return nil })
	md, err := empty.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatalf("unkeyed GetRequestMetadata: %v", err)
	}
	if len(md) != 0 {
		t.Fatalf("unkeyed creds attached a token: %v", md)
	}
}
