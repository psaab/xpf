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

// #16033: the tokenless rollout grace set included GetSessions — the full
// session table (complete 5-tuples, NAT bindings, counters). In a peer-down /
// replacement / rollout window the grace lasts up to five minutes per anchor
// event, so any on-segment host with no token could read the whole table.
// The decisive check from the issue: keyed node, peer down (never armed),
// tokenless GetSessions at anchor+1min must be rejected, while the
// non-sensitive summaries that share the grace remain admitted (so the fix
// is surgical, not a grace shutdown), and a valid-token GetSessions still
// works (so the peer's legitimate session proxy is not broken).

func fabricAuth16033Call(s *Server, method string, req interface{}) (*unaryCallProbe, error) {
	info := &grpc.UnaryServerInfo{FullMethod: method}
	probe := &unaryCallProbe{}
	_, err := s.fabricAuthUnaryInterceptor(context.Background(), req, info,
		func(ctx context.Context, req interface{}) (interface{}, error) {
			return s.fabricAllowlistUnaryInterceptor(ctx, req, info, probe.handler)
		})
	return probe, err
}

func TestFabricAuth16033_TokenlessGetSessionsRejectedDuringGrace(t *testing.T) {
	anchor := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	s := keyedServer(fabricTestKey)
	// First observation anchors the grace at `anchor`.
	s.fabricAuthNowFn = func() time.Time { return anchor }
	if _, err := fabricAuth16033Call(s, pb.BpfrxService_GetStatus_FullMethodName,
		&pb.GetStatusRequest{}); err != nil {
		t.Fatalf("anchor GetStatus during grace: %v", err)
	}

	// Issue's decisive instant: anchor+1min, peer still down / never armed.
	s.fabricAuthNowFn = func() time.Time { return anchor.Add(time.Minute) }
	probe, err := fabricAuth16033Call(s, pb.BpfrxService_GetSessions_FullMethodName,
		&pb.GetSessionsRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("tokenless GetSessions at anchor+1min during grace: err=%v (%s), want Unauthenticated",
			err, status.Code(err))
	}
	if probe.called {
		t.Fatal("tokenless GetSessions during grace reached the handler")
	}
}

func TestFabricAuth16033_TokenlessGetSessionsRejectedAtGraceStart(t *testing.T) {
	s := keyedServer(fabricTestKey)
	probe, err := fabricAuth16033Call(s, pb.BpfrxService_GetSessions_FullMethodName,
		&pb.GetSessionsRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("tokenless GetSessions at grace start: err=%v (%s), want Unauthenticated",
			err, status.Code(err))
	}
	if probe.called {
		t.Fatal("tokenless GetSessions at grace start reached the handler")
	}
	// Direct predicate: GetSessions must never be grace-eligible.
	if fabricAuthGraceAllowed(pb.BpfrxService_GetSessions_FullMethodName, &pb.GetSessionsRequest{}) {
		t.Fatal("fabricAuthGraceAllowed(GetSessions) = true, want false (#16033)")
	}
}

func TestFabricAuth16033_SummariesKeepGraceAndValidTokenGetSessionsWorks(t *testing.T) {
	// Non-sensitive summaries remain grace-eligible: removing GetSessions
	// must not shut the whole rollout grace down.
	for _, tc := range []struct {
		name   string
		method string
		req    interface{}
	}{
		{"GetStatus", pb.BpfrxService_GetStatus_FullMethodName, &pb.GetStatusRequest{}},
		{"GetSessionSummary", pb.BpfrxService_GetSessionSummary_FullMethodName, &pb.GetSessionSummaryRequest{}},
		{"GetZonePairSummary", pb.BpfrxService_GetZonePairSummary_FullMethodName, &pb.GetZonePairSummaryRequest{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := keyedServer(fabricTestKey)
			probe, err := fabricAuth16033Call(s, tc.method, tc.req)
			if err != nil || !probe.called {
				t.Fatalf("tokenless %s during grace: called=%t err=%v, want admitted", tc.name, probe.called, err)
			}
			if !fabricAuthGraceAllowed(tc.method, tc.req) {
				t.Fatalf("fabricAuthGraceAllowed(%s) = false, want true (grace must survive for summaries)", tc.name)
			}
		})
	}

	// A peer holding the key can still proxy GetSessions with a valid token.
	s := keyedServer(fabricTestKey)
	method := pb.BpfrxService_GetSessions_FullMethodName
	req := &pb.GetSessionsRequest{}
	digest, err := fabricRequestDigest(req)
	if err != nil {
		t.Fatalf("request digest: %v", err)
	}
	token := fabricAuthTokenHexForDigest([]byte(fabricTestKey), time.Now(), method, digest)
	info := &grpc.UnaryServerInfo{FullMethod: method}
	probe := &unaryCallProbe{}
	_, err = s.fabricAuthUnaryInterceptor(ctxWithToken(token), req, info,
		func(ctx context.Context, req interface{}) (interface{}, error) {
			return s.fabricAllowlistUnaryInterceptor(ctx, req, info, probe.handler)
		})
	if err != nil || !probe.called {
		t.Fatalf("valid-token GetSessions: called=%t err=%v, want admitted", probe.called, err)
	}
}
