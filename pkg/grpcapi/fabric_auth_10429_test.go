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

// #10429: a fabric token must be scoped to the full RPC method. These cells
// drive the real server interceptor entry point so reverting the method input
// from the HMAC makes the cross-method replay cell RED.
func TestFabricAuth10429_CrossMethodReplayRejected(t *testing.T) {
	s := keyedServer(fabricTestKey)
	getMethod := pb.BpfrxService_GetSessions_FullMethodName
	clearMethod := pb.BpfrxService_ClearSessions_FullMethodName
	token := fabricAuthTokenHex([]byte(fabricTestKey), time.Now(), getMethod)

	getInfo := &grpc.UnaryServerInfo{FullMethod: getMethod}
	getProbe := &unaryCallProbe{}
	if _, err := s.fabricAuthUnaryInterceptor(ctxWithToken(token), nil, getInfo,
		func(ctx context.Context, req interface{}) (interface{}, error) {
			return s.fabricAllowlistUnaryInterceptor(ctx, req, getInfo, getProbe.handler)
		}); err != nil {
		t.Fatalf("same-method control call rejected: %v", err)
	}
	if !getProbe.called {
		t.Fatal("same-method control handler was not reached")
	}

	clearInfo := &grpc.UnaryServerInfo{FullMethod: clearMethod}
	clearProbe := &unaryCallProbe{}
	_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(token), nil, clearInfo,
		func(ctx context.Context, req interface{}) (interface{}, error) {
			return s.fabricAllowlistUnaryInterceptor(ctx, req, clearInfo, clearProbe.handler)
		})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("cross-method replay was accepted: err=%v", err)
	}
	if clearProbe.called {
		t.Fatal("cross-method replay reached the destructive handler")
	}

	// Hard cutover: the pre-10429 unbound form is not accepted even on the
	// method it was originally minted for; there is no legacy verification
	// fallback that could be stripped and replayed across methods.
	legacyProbe := &unaryCallProbe{}
	legacyToken := fabricAuthTokenHex([]byte(fabricTestKey), time.Now())
	_, err = s.fabricAuthUnaryInterceptor(ctxWithToken(legacyToken), nil, getInfo,
		legacyProbe.handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unbound legacy token was accepted: err=%v", err)
	}
	if legacyProbe.called {
		t.Fatal("unbound legacy token reached handler")
	}
}

func TestFabricAuth10429_SameMethodRetryAccepted(t *testing.T) {
	s := keyedServer(fabricTestKey)
	method := pb.BpfrxService_ClearSessions_FullMethodName
	info := &grpc.UnaryServerInfo{FullMethod: method}
	token := fabricAuthTokenHex([]byte(fabricTestKey), time.Now(), method)

	for attempt := 1; attempt <= 2; attempt++ {
		probe := &unaryCallProbe{}
		if _, err := s.fabricAuthUnaryInterceptor(ctxWithToken(token), nil, info, probe.handler); err != nil {
			t.Fatalf("same-method retry %d rejected: %v", attempt, err)
		}
		if !probe.called {
			t.Fatalf("same-method retry %d did not reach handler", attempt)
		}
	}
}

func TestFabricAuth10429_WindowExpiryEnforced(t *testing.T) {
	s := keyedServer(fabricTestKey)
	method := pb.BpfrxService_GetStatus_FullMethodName
	info := &grpc.UnaryServerInfo{FullMethod: method}
	// The verifier accepts only the current and adjacent windows. Three full
	// windows in the past is outside the replay horizon even for a boundary crossing.
	expired := fabricAuthTokenHex([]byte(fabricTestKey), time.Now().Add(-3*fabricAuthWindowSeconds*time.Second), method)
	probe := &unaryCallProbe{}
	_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(expired), nil, info, probe.handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expired token was accepted: err=%v", err)
	}
	if probe.called {
		t.Fatal("expired token reached handler")
	}
}
