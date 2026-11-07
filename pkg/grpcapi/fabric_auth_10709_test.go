package grpcapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// #10709: a captured method token must not authorize changed unary arguments.
// The changed request is cloned from the signed body, retains its nonce and
// token, and is tried against a fresh replay cache. A method+nonce-only digest
// mutant therefore accepts the forgery and makes this test fail.
func TestFabricAuth10709_UnaryArgumentsBound(t *testing.T) {
	cases := []struct {
		name   string
		method string
		first  proto.Message
		change func(proto.Message)
	}{
		{
			name:   "failover_rg",
			method: pb.BpfrxService_SystemAction_FullMethodName,
			first:  &pb.SystemActionRequest{Action: "cluster-failover:1:node1"},
			change: func(req proto.Message) { req.(*pb.SystemActionRequest).Action = "cluster-failover:2:node1" },
		},
		{
			name:   "clear_filter",
			method: pb.BpfrxService_ClearSessions_FullMethodName,
			first:  &pb.ClearSessionsRequest{SourcePrefix: "192.0.2.1/32"},
			change: func(req proto.Message) { req.(*pb.ClearSessionsRequest).SourcePrefix = "192.0.2.2/32" },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var token string
			var signedRequest proto.Message
			creds := fabricAuthCreds{keyFn: func() []byte { return []byte(fabricTestKey) }}
			invoker := func(ctx context.Context, method string, req, reply interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
				md, err := creds.GetRequestMetadata(ctx)
				if err != nil {
					return err
				}
				token = md[fabricAuthMetadataKey]
				signedRequest = proto.Clone(req.(proto.Message))
				return nil
			}
			if err := FabricAuthUnaryClientInterceptor(context.Background(), tc.method, tc.first, nil, nil, invoker); err != nil {
				t.Fatalf("client auth interceptor: %v", err)
			}
			if token == "" {
				t.Fatal("keyed client emitted no request token")
			}

			signedNonce := nonceForFabricNonce18999(signedRequest)
			if len(signedNonce) != sha256.Size {
				t.Fatalf("signed request nonce length = %d, want %d", len(signedNonce), sha256.Size)
			}
			forgedRequest := proto.Clone(signedRequest)
			tc.change(forgedRequest)
			if !bytes.Equal(signedNonce, nonceForFabricNonce18999(forgedRequest)) {
				t.Fatal("changed-argument clone did not retain the signed nonce")
			}

			// This fresh server has no consumed nonce: rejection must come from
			// request-argument authentication, not a replay-cache hit.
			s := keyedServer(fabricTestKey)
			info := &grpc.UnaryServerInfo{FullMethod: tc.method}
			invoke := func(req interface{}, probe *unaryCallProbe) error {
				_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(token), req, info,
					func(ctx context.Context, req interface{}) (interface{}, error) {
						return s.fabricAllowlistUnaryInterceptor(ctx, req, info, probe.handler)
					})
				return err
			}

			forgedProbe := &unaryCallProbe{}
			err := invoke(forgedRequest, forgedProbe)
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("same-nonce changed-argument request authorized: err=%v status=%s, want Unauthenticated", err, status.Code(err))
			}
			if forgedProbe.called {
				t.Fatal("same-nonce changed-argument request reached the handler")
			}

			// Authentication rejection must leave the signed original admissible.
			firstProbe := &unaryCallProbe{}
			if err := invoke(signedRequest, firstProbe); err != nil {
				t.Fatalf("original request rejected after forged attempt: %v", err)
			}
			if !firstProbe.called {
				t.Fatal("original request did not reach the handler")
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

type fabricAuth10709CapturedCreds struct{ token string }

func (c fabricAuth10709CapturedCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{fabricAuthMetadataKey: c.token}, nil
}

func (fabricAuth10709CapturedCreds) RequireTransportSecurity() bool { return false }

// TestFabricAuth10709_RealGRPCReplay sends a modified clone of a production-
// interceptor-signed request over a real loopback gRPC transport. The clone
// keeps the exact nonce and token and is sent first on a fresh server, so a
// method+nonce-only digest mutant reaches the handler and makes this test RED.
func TestFabricAuth10709_RealGRPCReplay(t *testing.T) {
	const method = pb.BpfrxService_SystemAction_FullMethodName
	original := &pb.SystemActionRequest{Action: "cluster-failover:1:node1"}
	creds := fabricAuthCreds{keyFn: func() []byte { return []byte(fabricTestKey) }}
	var token string
	var signedRequest *pb.SystemActionRequest
	invoker := func(ctx context.Context, _ string, req, _ interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		md, err := creds.GetRequestMetadata(ctx)
		if err != nil {
			return err
		}
		token = md[fabricAuthMetadataKey]
		signedRequest = proto.Clone(req.(*pb.SystemActionRequest)).(*pb.SystemActionRequest)
		return nil
	}
	if err := FabricAuthUnaryClientInterceptor(context.Background(), method, original, nil, nil, invoker); err != nil {
		t.Fatalf("client auth interceptor: %v", err)
	}
	if token == "" {
		t.Fatal("keyed client emitted no request token")
	}
	if len(signedRequest.GetFabricNonce()) != sha256.Size {
		t.Fatalf("signed request nonce length = %d, want %d", len(signedRequest.GetFabricNonce()), sha256.Size)
	}

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

	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(fabricAuth10709CapturedCreds{token: token}),
	)
	if err != nil {
		t.Fatalf("new replay client: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := pb.NewBpfrxServiceClient(conn)
	modified := proto.Clone(signedRequest).(*pb.SystemActionRequest)
	modified.Action = "cluster-failover:2:node1"
	if !bytes.Equal(signedRequest.GetFabricNonce(), modified.GetFabricNonce()) {
		t.Fatal("changed-action clone did not retain the signed nonce")
	}
	if _, err := client.SystemAction(ctx, modified); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("same-nonce changed-action request: err=%v status=%s, want Unauthenticated", err, status.Code(err))
	}
	if got := service.calls.Load(); got != 0 {
		t.Fatalf("changed request reached handler before original: calls=%d, want 0", got)
	}

	if _, err := client.SystemAction(ctx, signedRequest); err != nil {
		t.Fatalf("signed original after rejected forgery: %v", err)
	}
	if got := service.calls.Load(); got != 1 {
		t.Fatalf("handler calls after signed original = %d, want 1", got)
	}
}
