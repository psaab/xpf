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

func TestFabricAuth11487_StateChangingCallsRequireArmedPeer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		req    interface{}
	}{
		{
			name:   "ClearSessions",
			method: pb.BpfrxService_ClearSessions_FullMethodName,
			req:    &pb.ClearSessionsRequest{},
		},
		{
			name:   "clear-persistent-nat",
			method: pb.BpfrxService_SystemAction_FullMethodName,
			req:    &pb.SystemActionRequest{Action: "clear-persistent-nat"},
		},
		{
			name:   "cluster-failover",
			method: pb.BpfrxService_SystemAction_FullMethodName,
			req:    &pb.SystemActionRequest{Action: "cluster-failover:1:node1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := keyedServer(fabricTestKey)
			info := &grpc.UnaryServerInfo{FullMethod: tc.method}
			probe := &unaryCallProbe{}
			_, err := s.fabricAuthUnaryInterceptor(context.Background(), tc.req, info,
				func(ctx context.Context, req interface{}) (interface{}, error) {
					return s.fabricAllowlistUnaryInterceptor(ctx, req, info, probe.handler)
				})
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("unarmed tokenless state change: got err=%v (%s), want Unauthenticated",
					err, status.Code(err))
			}
			if probe.called {
				t.Fatal("unarmed tokenless state change reached handler")
			}
		})
	}
}

func TestFabricAuth11487_ReadOnlyCallsKeepRolloutGrace(t *testing.T) {
	cases := []struct {
		name   string
		method string
		req    interface{}
	}{
		{
			name:   "GetStatus",
			method: pb.BpfrxService_GetStatus_FullMethodName,
			req:    &pb.GetStatusRequest{},
		},
		{
			name:   "GetSessions",
			method: pb.BpfrxService_GetSessions_FullMethodName,
			req:    &pb.GetSessionsRequest{},
		},
		{
			name:   "GetSessionSummary",
			method: pb.BpfrxService_GetSessionSummary_FullMethodName,
			req:    &pb.GetSessionSummaryRequest{},
		},
		{
			name:   "GetZonePairSummary",
			method: pb.BpfrxService_GetZonePairSummary_FullMethodName,
			req:    &pb.GetZonePairSummaryRequest{},
		},
		{
			name:   "ShowText",
			method: pb.BpfrxService_ShowText_FullMethodName,
			req:    &pb.ShowTextRequest{Topic: "chassis-forwarding"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := keyedServer(fabricTestKey)
			info := &grpc.UnaryServerInfo{FullMethod: tc.method}
			probe := &unaryCallProbe{}
			_, err := s.fabricAuthUnaryInterceptor(context.Background(), tc.req, info,
				func(ctx context.Context, req interface{}) (interface{}, error) {
					return s.fabricAllowlistUnaryInterceptor(ctx, req, info, probe.handler)
				})
			if err != nil {
				t.Fatalf("read-only tokenless call during rollout: %v", err)
			}
			if !probe.called {
				t.Fatal("read-only tokenless call did not reach handler")
			}
		})
	}
}
func TestFabricAuth11487_MonitorInterfaceKeepsRolloutGrace(t *testing.T) {
	s := keyedServer(fabricTestKey)
	handlerCalled := false
	err := s.fabricAuthStreamInterceptor(nil,
		fakeServerStream{ctx: context.Background()},
		&grpc.StreamServerInfo{FullMethod: pb.BpfrxService_MonitorInterface_FullMethodName},
		func(srv interface{}, ss grpc.ServerStream) error {
			handlerCalled = true
			return nil
		})
	if err != nil {
		t.Fatalf("read-only stream tokenless call during rollout: %v", err)
	}
	if !handlerCalled {
		t.Fatal("read-only stream tokenless call did not reach handler")
	}
}

func TestFabricAuth11487_ArmedStateChangeStillAcceptsValidToken(t *testing.T) {
	s := keyedServer(fabricTestKey)
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_SystemAction_FullMethodName}
	req := &pb.SystemActionRequest{Action: "clear-persistent-nat"}
	digest, err := fabricRequestDigest(req)
	if err != nil {
		t.Fatalf("request digest: %v", err)
	}
	token := fabricAuthTokenHexForDigest([]byte(fabricTestKey), time.Now(), info.FullMethod, digest)
	probe := &unaryCallProbe{}
	_, err = s.fabricAuthUnaryInterceptor(ctxWithToken(token), req, info,
		func(ctx context.Context, req interface{}) (interface{}, error) {
			return s.fabricAllowlistUnaryInterceptor(ctx, req, info, probe.handler)
		})
	if err != nil {
		t.Fatalf("valid-token state change: %v", err)
	}
	if !probe.called {
		t.Fatal("valid-token state change did not reach handler")
	}
}
