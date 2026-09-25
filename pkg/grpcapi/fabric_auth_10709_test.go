package grpcapi

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// #10709: a captured method token must not authorize changed unary arguments.
// Mint the token through the production client interceptor + per-RPC credential,
// then drive it through the real server auth and allowlist interceptors. Reverting
// either side to method-only binding makes the changed-arguments cells RED.
func TestFabricAuth10709_UnaryArgumentsBound(t *testing.T) {
	cases := []struct {
		name   string
		method string
		first  interface{}
		other  interface{}
	}{
		{
			name:   "failover_rg",
			method: pb.BpfrxService_SystemAction_FullMethodName,
			first:  &pb.SystemActionRequest{Action: "cluster-failover:1:node1"},
			other:  &pb.SystemActionRequest{Action: "cluster-failover:2:node1"},
		},
		{
			name:   "clear_filter",
			method: pb.BpfrxService_ClearSessions_FullMethodName,
			first:  &pb.ClearSessionsRequest{SourcePrefix: "192.0.2.1/32"},
			other:  &pb.ClearSessionsRequest{SourcePrefix: "192.0.2.2/32"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var token string
			creds := fabricAuthCreds{keyFn: func() []byte { return []byte(fabricTestKey) }}
			invoker := func(ctx context.Context, method string, req, reply interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
				md, err := creds.GetRequestMetadata(ctx)
				if err != nil {
					return err
				}
				token = md[fabricAuthMetadataKey]
				return nil
			}
			if err := FabricAuthUnaryClientInterceptor(context.Background(), tc.method, tc.first, nil, nil, invoker); err != nil {
				t.Fatalf("client auth interceptor: %v", err)
			}
			if token == "" {
				t.Fatal("keyed client emitted no request token")
			}

			s := keyedServer(fabricTestKey)
			info := &grpc.UnaryServerInfo{FullMethod: tc.method}
			invoke := func(req interface{}, probe *unaryCallProbe) error {
				_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(token), req, info,
					func(ctx context.Context, req interface{}) (interface{}, error) {
						return s.fabricAllowlistUnaryInterceptor(ctx, req, info, probe.handler)
					})
				return err
			}

			// A correctly bound request remains admitted as a positive control.
			firstProbe := &unaryCallProbe{}
			if err := invoke(tc.first, firstProbe); err != nil {
				t.Fatalf("original request rejected: %v", err)
			}
			if !firstProbe.called {
				t.Fatal("original request did not reach the handler")
			}

			// The same captured method/window token cannot change failover RG or
			// ClearSessions filter. Auth rejects before the allowlist/handler.
			otherProbe := &unaryCallProbe{}
			err := invoke(tc.other, otherProbe)
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("captured token authorized changed arguments: err=%v status=%s", err, status.Code(err))
			}
			if otherProbe.called {
				t.Fatal("changed request arguments reached the handler")
			}
		})
	}
}

type fabricAuth10709Service struct {
	pb.UnimplementedBpfrxServiceServer
	calls atomic.Int32
}

func (s *fabricAuth10709Service) SystemAction(context.Context, *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
	s.calls.Add(1)
	return &pb.SystemActionResponse{}, nil
}

type fabricAuth10709RecordingCreds struct {
	key   []byte
	mu    sync.Mutex
	token string
}

func (c *fabricAuth10709RecordingCreds) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	md, err := (fabricAuthCreds{keyFn: func() []byte { return c.key }}).GetRequestMetadata(ctx)
	c.mu.Lock()
	c.token = md[fabricAuthMetadataKey]
	c.mu.Unlock()
	return md, err
}

func (c *fabricAuth10709RecordingCreds) capturedToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

func (*fabricAuth10709RecordingCreds) RequireTransportSecurity() bool { return false }

type fabricAuth10709CapturedCreds struct{ token string }

func (c fabricAuth10709CapturedCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{fabricAuthMetadataKey: c.token}, nil
}

func (fabricAuth10709CapturedCreds) RequireTransportSecurity() bool { return false }

// TestFabricAuth10709_RealGRPCReplay exercises the credentials callback,
// client interceptor, protobuf marshal/unmarshal, and server interceptor over
// an actual loopback gRPC transport. It captures the accepted failover-rg1
// token and replays it for rg2; only the original request reaches the handler.
func TestFabricAuth10709_RealGRPCReplay(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	authServer := keyedServer(fabricTestKey)
	service := &fabricAuth10709Service{}
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(
		authServer.fabricAuthUnaryInterceptor,
		authServer.fabricAllowlistUnaryInterceptor,
	))
	pb.RegisterBpfrxServiceServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	key := []byte(fabricTestKey)
	recordingCreds := &fabricAuth10709RecordingCreds{key: key}
	originalConn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(recordingCreds),
		grpc.WithUnaryInterceptor(FabricAuthUnaryClientInterceptor),
	)
	if err != nil {
		t.Fatalf("new original client: %v", err)
	}
	defer originalConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := pb.NewBpfrxServiceClient(originalConn)
	original := &pb.SystemActionRequest{Action: "cluster-failover:1:node1"}
	if _, err := client.SystemAction(ctx, original); err != nil {
		t.Fatalf("original rg1 request: %v", err)
	}
	if token := recordingCreds.capturedToken(); token == "" {
		t.Fatal("client credentials emitted no token")
	}
	if got := service.calls.Load(); got != 1 {
		t.Fatalf("handler calls after original request = %d, want 1", got)
	}

	replayConn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(fabricAuth10709CapturedCreds{token: recordingCreds.capturedToken()}),
		grpc.WithUnaryInterceptor(FabricAuthUnaryClientInterceptor),
	)
	if err != nil {
		t.Fatalf("new replay client: %v", err)
	}
	defer replayConn.Close()
	modified := &pb.SystemActionRequest{Action: "cluster-failover:2:node1"}
	_, err = pb.NewBpfrxServiceClient(replayConn).SystemAction(ctx, modified)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("captured rg1 token replayed for rg2: err=%v status=%s", err, status.Code(err))
	}
	if got := service.calls.Load(); got != 1 {
		t.Fatalf("changed request reached handler; calls=%d want 1", got)
	}
}
