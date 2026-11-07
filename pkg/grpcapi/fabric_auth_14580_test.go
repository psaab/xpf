package grpcapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// #14580: a signed clear-persistent-nat request must not authorize a changed
// generation or origin. Each forged request is cloned from the authenticated
// body, retains its nonce and token, and is tried against a fresh replay cache.
// A method+nonce-only digest mutant would admit either forgery and make this
// test RED; the original request remains a positive control.
//
// Fail-on-revert: moving origin/generation outside the digest lets the forged
// request reach the handler before the durable peer-generation watermark.
func TestFabricAuth14580_PersistentNatGenerationForgedReplayRejected(t *testing.T) {
	const origin = "0123456789abcdef0123456789abcdef"
	method := pb.BpfrxService_SystemAction_FullMethodName
	genuine := &pb.SystemActionRequest{Action: "clear-persistent-nat", PersistentNatOrigin: origin, PersistentNatGeneration: 3}

	var token string
	var signedRequest *pb.SystemActionRequest
	creds := fabricAuthCreds{keyFn: func() []byte { return []byte(fabricTestKey) }}
	invoker := func(ctx context.Context, _ string, req, _ interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		md, err := creds.GetRequestMetadata(ctx)
		if err != nil {
			return err
		}
		token = md[fabricAuthMetadataKey]
		signedRequest = proto.Clone(req.(*pb.SystemActionRequest)).(*pb.SystemActionRequest)
		return nil
	}
	if err := FabricAuthUnaryClientInterceptor(context.Background(), method, genuine, nil, nil, invoker); err != nil {
		t.Fatalf("client auth interceptor: %v", err)
	}
	if token == "" {
		t.Fatal("keyed client emitted no request token")
	}
	if len(signedRequest.GetFabricNonce()) != sha256.Size {
		t.Fatalf("signed request nonce length = %d, want %d", len(signedRequest.GetFabricNonce()), sha256.Size)
	}

	info := &grpc.UnaryServerInfo{FullMethod: method}
	invoke := func(s *Server, req *pb.SystemActionRequest, probe *unaryCallProbe) error {
		_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(token), req, info,
			func(ctx context.Context, req interface{}) (interface{}, error) {
				return s.fabricAllowlistUnaryInterceptor(ctx, req, info, probe.handler)
			})
		return err
	}

	forgedServer := keyedServer(fabricTestKey)
	forged := proto.Clone(signedRequest).(*pb.SystemActionRequest)
	forged.PersistentNatGeneration = ^uint64(0)
	if !bytes.Equal(signedRequest.GetFabricNonce(), forged.GetFabricNonce()) {
		t.Fatal("changed-generation clone did not retain the signed nonce")
	}
	forgedProbe := &unaryCallProbe{}
	err := invoke(forgedServer, forged, forgedProbe)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("same-nonce forged generation authorized: err=%v status=%s, want Unauthenticated", err, status.Code(err))
	}
	if forgedProbe.called {
		t.Fatal("forged generation reached the handler: durable watermark would be poisoned")
	}

	genuineProbe := &unaryCallProbe{}
	if err := invoke(forgedServer, signedRequest, genuineProbe); err != nil {
		t.Fatalf("signed original after rejected forgery: %v", err)
	}
	if !genuineProbe.called {
		t.Fatal("signed original did not reach the handler")
	}

	// Control: origin is also bound. Use a fresh cache so its result cannot be
	// explained by a duplicate nonce claim from the positive control above.
	controlServer := keyedServer(fabricTestKey)
	control := proto.Clone(signedRequest).(*pb.SystemActionRequest)
	control.PersistentNatOrigin = "fedcba9876543210fedcba9876543210"
	if !bytes.Equal(signedRequest.GetFabricNonce(), control.GetFabricNonce()) {
		t.Fatal("changed-origin clone did not retain the signed nonce")
	}
	controlProbe := &unaryCallProbe{}
	if err := invoke(controlServer, control, controlProbe); status.Code(err) != codes.Unauthenticated || controlProbe.called {
		t.Fatalf("same-nonce changed-origin request: err=%v called=%v, want Unauthenticated/not called", err, controlProbe.called)
	}
}
