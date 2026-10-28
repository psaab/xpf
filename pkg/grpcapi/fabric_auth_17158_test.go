package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestWithFabricAuthRequestBindsManualClient17158 proves #17158's fabric
// arm: the documented manual-client API (WithFabricAuthMethod +
// WithFabricAuthRequest, the stronger form the issue left to be tested)
// mints a credential token bound to BOTH the method and the request
// arguments, and the server accepts it only for that exact request.
// A token minted for different arguments — or the request-unbound token
// the deleted computeFabricAuthToken produced — is refused.
func TestWithFabricAuthRequestBindsManualClient17158(t *testing.T) {
	method := pb.BpfrxService_SystemAction_FullMethodName
	req := &pb.SystemActionRequest{Action: "cluster-failover:1:node1"}
	other := &pb.SystemActionRequest{Action: "cluster-failover:2:node1"}

	key := []byte(fabricTestKey)
	creds := fabricAuthCreds{keyFn: func() []byte { return key }}

	mint := func(r *pb.SystemActionRequest) string {
		t.Helper()
		ctx, err := WithFabricAuthRequest(WithFabricAuthMethod(context.Background(), method), r)
		if err != nil {
			t.Fatalf("WithFabricAuthRequest: %v", err)
		}
		md, err := creds.GetRequestMetadata(ctx)
		if err != nil {
			t.Fatalf("GetRequestMetadata: %v", err)
		}
		tok := md[fabricAuthMetadataKey]
		if tok == "" {
			t.Fatal("manual-client credential emitted no token")
		}
		return tok
	}

	s := keyedServer(fabricTestKey)
	info := &grpc.UnaryServerInfo{FullMethod: method}
	invoke := func(tok string, r interface{}, probe *unaryCallProbe) error {
		_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(tok), r, info, probe.handler)
		return err
	}

	// Exact method+request: admitted.
	probe := &unaryCallProbe{}
	if err := invoke(mint(req), req, probe); err != nil {
		t.Fatalf("manual-client token for the exact request rejected: %v", err)
	}
	if !probe.called {
		t.Fatal("manual-client token did not reach the handler")
	}

	// Same token, changed arguments: refused before the handler.
	probe2 := &unaryCallProbe{}
	if err := invoke(mint(req), other, probe2); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("manual-client token authorized changed arguments: err=%v", err)
	}
	if probe2.called {
		t.Fatal("changed-arguments request reached the handler")
	}

	// Request-unbound token (empty digest, the deleted weak form's shape,
	// expressed via the surviving empty-request helper): refused for a
	// non-empty request.
	probe3 := &unaryCallProbe{}
	unbound := fabricAuthTokenHex(key, time.Now(), method)
	if err := invoke(unbound, req, probe3); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("request-unbound token authorized a non-empty request: err=%v", err)
	}
	if probe3.called {
		t.Fatal("request-unbound token reached the handler")
	}

	// Non-protobuf request fails closed at composition time.
	if _, err := WithFabricAuthRequest(context.Background(), "not-a-proto"); err == nil {
		t.Fatal("WithFabricAuthRequest accepted a non-protobuf request (#17158)")
	}
}
