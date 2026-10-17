package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #14580 decisive check: a fabric SystemAction token minted for a genuine
// clear-persistent-nat (origin O, generation 3) must NOT authorize the same
// action replayed with a forged generation (MaxUint64) in the signed body.
// Before the fix, origin/generation rode unsigned metadata and the token
// bound only method+action, so the forged replay reached the handler and
// durably poisoned RemoteGenerations[O]=MaxUint64. Now the fields are inside
// SystemActionRequest, so the #10709 request-digest MAC rejects the forgery
// as Unauthenticated before the allowlist/handler. The genuine body remains
// admitted (positive control), and a body-change control (different action)
// is likewise rejected.
//
// Fail-on-revert: move origin/generation back to unsigned metadata (or drop
// them from the request digest) and the forged cell reaches the handler.
func TestFabricAuth14580_PersistentNatGenerationForgedReplayRejected(t *testing.T) {
	const origin = "0123456789abcdef0123456789abcdef"
	method := pb.BpfrxService_SystemAction_FullMethodName
	genuine := &pb.SystemActionRequest{Action: "clear-persistent-nat", PersistentNatOrigin: origin, PersistentNatGeneration: 3}
	forged := &pb.SystemActionRequest{Action: "clear-persistent-nat", PersistentNatOrigin: origin, PersistentNatGeneration: ^uint64(0)}

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
	if err := FabricAuthUnaryClientInterceptor(context.Background(), method, genuine, nil, nil, invoker); err != nil {
		t.Fatalf("client auth interceptor: %v", err)
	}
	if token == "" {
		t.Fatal("keyed client emitted no request token")
	}

	s := keyedServer(fabricTestKey)
	info := &grpc.UnaryServerInfo{FullMethod: method}
	invoke := func(req interface{}, probe *unaryCallProbe) error {
		_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(token), req, info,
			func(ctx context.Context, req interface{}) (interface{}, error) {
				return s.fabricAllowlistUnaryInterceptor(ctx, req, info, probe.handler)
			})
		return err
	}

	genuineProbe := &unaryCallProbe{}
	if err := invoke(genuine, genuineProbe); err != nil {
		t.Fatalf("genuine forwarded clear rejected: %v", err)
	}
	if !genuineProbe.called {
		t.Fatal("genuine forwarded clear did not reach the handler")
	}

	forgedProbe := &unaryCallProbe{}
	err := invoke(forged, forgedProbe)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("forged generation replay authorized: err=%v status=%s, want Unauthenticated", err, status.Code(err))
	}
	if forgedProbe.called {
		t.Fatal("forged generation replay reached the handler: durable watermark would be poisoned")
	}

	// Control: a different action under the same captured token is rejected
	// too, proving the rejection is the request-digest binding, not a
	// generation-specific special case.
	controlProbe := &unaryCallProbe{}
	control := &pb.SystemActionRequest{Action: "clear-persistent-nat", PersistentNatOrigin: "fedcba9876543210fedcba9876543210", PersistentNatGeneration: 3}
	if err := invoke(control, controlProbe); status.Code(err) != codes.Unauthenticated || controlProbe.called {
		t.Fatalf("changed-origin replay: err=%v called=%v, want Unauthenticated/not called", err, controlProbe.called)
	}
}
