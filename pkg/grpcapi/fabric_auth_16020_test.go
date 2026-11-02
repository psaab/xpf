package grpcapi

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/denyaudit"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func invokeFabricAuth16020(s *Server, method string, req interface{}, token string, handler grpc.UnaryHandler) error {
	_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(token), req,
		&grpc.UnaryServerInfo{FullMethod: method}, handler)
	return err
}

func tokenForFabricAuth16020(t *testing.T, method string, req interface{}) string {
	t.Helper()
	digest, err := fabricRequestDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	return fabricAuthTokenHexForDigest([]byte(fabricTestKey), time.Now(), method, digest)
}

func TestFabricAuth16020_ByteIdenticalMutatingReplayRejected(t *testing.T) {
	s := keyedServer(fabricTestKey)
	method := pb.BpfrxService_ClearSessions_FullMethodName
	req := &pb.ClearSessionsRequest{Protocol: "tcp"}
	token := tokenForFabricAuth16020(t, method, req)
	var calls atomic.Int32
	handler := func(context.Context, interface{}) (interface{}, error) {
		calls.Add(1)
		return "ok", nil
	}

	if err := invokeFabricAuth16020(s, method, req, token, handler); err != nil {
		t.Fatalf("first mutating request: %v", err)
	}
	auditBefore := denyaudit.Total(denyaudit.SurfaceFabricAuth)
	err := invokeFabricAuth16020(s, method, req, token, handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("byte-identical mutating replay status = %s, err=%v; want Unauthenticated", status.Code(err), err)
	}
	if got := denyaudit.Total(denyaudit.SurfaceFabricAuth); got <= auditBefore {
		t.Fatalf("mutating replay did not increment fabric-auth audit count: before=%d after=%d", auditBefore, got)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("mutating handler calls = %d, want 1", got)
	}
}

func TestFabricAuth16020_DistinctMutationTokensAccepted(t *testing.T) {
	s := keyedServer(fabricTestKey)
	method := pb.BpfrxService_ClearSessions_FullMethodName
	var calls atomic.Int32
	handler := func(context.Context, interface{}) (interface{}, error) {
		calls.Add(1)
		return "ok", nil
	}
	for _, req := range []*pb.ClearSessionsRequest{{Protocol: "tcp"}, {Protocol: "udp"}} {
		if err := invokeFabricAuth16020(s, method, req, tokenForFabricAuth16020(t, method, req), handler); err != nil {
			t.Fatalf("distinct mutation %q rejected: %v", req.GetProtocol(), err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("mutating handler calls = %d, want 2", got)
	}
}

func TestFabricAuth16020_ReadOnlyRepeatAccepted(t *testing.T) {
	s := keyedServer(fabricTestKey)
	method := pb.BpfrxService_GetStatus_FullMethodName
	req := &pb.GetStatusRequest{}
	token := tokenForFabricAuth16020(t, method, req)
	var calls atomic.Int32
	handler := func(context.Context, interface{}) (interface{}, error) {
		calls.Add(1)
		return "ok", nil
	}
	for i := 0; i < 2; i++ {
		if err := invokeFabricAuth16020(s, method, req, token, handler); err != nil {
			t.Fatalf("read-only call %d rejected: %v", i+1, err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("read-only handler calls = %d, want 2", got)
	}
}

func TestFabricAuth16020_HandlerErrorStillConsumesToken(t *testing.T) {
	s := keyedServer(fabricTestKey)
	method := pb.BpfrxService_SystemAction_FullMethodName
	req := &pb.SystemActionRequest{Action: "cluster-failover:1:node1"}
	token := tokenForFabricAuth16020(t, method, req)
	first := invokeFabricAuth16020(s, method, req, token, func(context.Context, interface{}) (interface{}, error) {
		return nil, status.Error(codes.Unavailable, "ambiguous partial action")
	})
	if status.Code(first) != codes.Unavailable {
		t.Fatalf("first handler error = %v, want Unavailable", first)
	}
	var calls atomic.Int32
	err := invokeFabricAuth16020(s, method, req, token, func(context.Context, interface{}) (interface{}, error) {
		calls.Add(1)
		return "ok", nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("retry after handler error status = %s, err=%v; want Unauthenticated", status.Code(err), err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("handler calls on consumed retry = %d, want 0", got)
	}
}

func TestFabricAuth16020_ConcurrentReplayHasSingleWinner(t *testing.T) {
	s := keyedServer(fabricTestKey)
	method := pb.BpfrxService_ClearSessions_FullMethodName
	req := &pb.ClearSessionsRequest{}
	token := tokenForFabricAuth16020(t, method, req)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- invokeFabricAuth16020(s, method, req, token, func(context.Context, interface{}) (interface{}, error) {
			calls.Add(1)
			close(entered)
			<-release
			return "ok", nil
		})
	}()
	<-entered

	const duplicates = 12
	var wg sync.WaitGroup
	statuses := make(chan codes.Code, duplicates)
	for range duplicates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := invokeFabricAuth16020(s, method, req, token, func(context.Context, interface{}) (interface{}, error) {
				calls.Add(1)
				return "duplicate", nil
			})
			statuses <- status.Code(err)
		}()
	}
	wg.Wait()
	close(statuses)
	for got := range statuses {
		if got != codes.Unauthenticated {
			t.Errorf("concurrent duplicate status = %s, want Unauthenticated", got)
		}
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("original request: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent mutating handler calls = %d, want 1", got)
	}
}

func TestFabricAuth16020_ProtectedMethodClassification(t *testing.T) {
	cases := []struct {
		name   string
		method string
		req    interface{}
		want   codes.Code
	}{
		{"clear-sessions", pb.BpfrxService_ClearSessions_FullMethodName, &pb.ClearSessionsRequest{}, codes.Unauthenticated},
		{"peer-failover", pb.BpfrxService_SystemAction_FullMethodName, &pb.SystemActionRequest{Action: "cluster-failover:2:node1"}, codes.Unauthenticated},
		{"persistent-nat-clear", pb.BpfrxService_SystemAction_FullMethodName, &pb.SystemActionRequest{Action: "clear-persistent-nat"}, codes.Unauthenticated},
		{"read-only-sessions", pb.BpfrxService_GetSessions_FullMethodName, &pb.GetSessionsRequest{}, codes.OK},
		{"unlisted-system-action", pb.BpfrxService_SystemAction_FullMethodName, &pb.SystemActionRequest{Action: "zeroize"}, codes.PermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := keyedServer(fabricTestKey)
			info := &grpc.UnaryServerInfo{FullMethod: tc.method}
			token := tokenForFabricAuth16020(t, tc.method, tc.req)
			var calls atomic.Int32
			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return s.fabricAllowlistUnaryInterceptor(ctx, req, info, func(context.Context, interface{}) (interface{}, error) {
					calls.Add(1)
					return "ok", nil
				})
			}
			firstErr := invokeFabricAuth16020(s, tc.method, tc.req, token, handler)
			wantFirst := codes.OK
			if tc.want == codes.PermissionDenied {
				wantFirst = codes.PermissionDenied
			}
			if got := status.Code(firstErr); got != wantFirst {
				t.Fatalf("first call status = %s, err=%v; want %s", got, firstErr, wantFirst)
			}
			err := invokeFabricAuth16020(s, tc.method, tc.req, token, handler)
			if got := status.Code(err); got != tc.want {
				t.Fatalf("second call status = %s, err=%v; want %s", got, err, tc.want)
			}
			wantCalls := int32(2)
			if tc.want == codes.Unauthenticated {
				wantCalls = 1
			} else if tc.want == codes.PermissionDenied {
				wantCalls = 0
			}
			if got := calls.Load(); got != wantCalls {
				t.Fatalf("handler calls = %d, want %d", got, wantCalls)
			}
		})
	}
}

// TestFabricAuth16020_AllowlistedMutationsAreReplayProtected is a census of
// the fabric unary allowlist's mutation surface. Clear-family methods are
// classified by their permission-table tier or name, so widening the allowlist
// to ClearCounters (or another clear RPC) must also add replay protection.
func TestFabricAuth16020_AllowlistedMutationsAreReplayProtected(t *testing.T) {
	for fullMethod := range fabricAllowedUnaryMethods {
		_, method, ok := splitFullMethod(fullMethod)
		if !ok {
			t.Fatalf("malformed fabric allowlist method %q", fullMethod)
		}
		// Tripwire: any non-view tier (or Clear-named method) counts as
		// mutating; an unlisted method reads PermView (iota-0) and must be
		// classified explicitly before it can widen the fabric surface.
		if methodPermissions[method] == config.PermView && !strings.HasPrefix(method, "Clear") {
			continue
		}
		if !fabricMutationReplayProtected(fullMethod, nil) {
			t.Errorf("fabric-allowlisted mutating RPC %s is not replay-protected", fullMethod)
		}
	}

	// SystemAction has a request-sensitive allowlist rather than a method-map
	// entry; keep every currently admitted mutating form in the replay census.
	for _, action := range []string{
		"cluster-failover-data:node0",
		"cluster-failover:2:node1",
		"clear-persistent-nat",
	} {
		req := &pb.SystemActionRequest{Action: action}
		if !isFabricSafeSystemAction(req) {
			t.Fatalf("test fixture action %q is not fabric-allowlisted", action)
		}
		if !fabricMutationReplayProtected(pb.BpfrxService_SystemAction_FullMethodName, req) {
			t.Errorf("fabric-allowlisted mutating SystemAction %q is not replay-protected", action)
		}
	}
}

func TestFabricAuth16020_HexCaseReplaySharesTokenIdentity(t *testing.T) {
	s := keyedServer(fabricTestKey)
	method := pb.BpfrxService_ClearSessions_FullMethodName
	req := &pb.ClearSessionsRequest{}
	token := tokenForFabricAuth16020(t, method, req)
	if token == strings.ToUpper(token) {
		t.Fatal("test token unexpectedly has no lowercase hex characters")
	}
	if err := invokeFabricAuth16020(s, method, req, strings.ToUpper(token), (&unaryCallProbe{}).handler); err != nil {
		t.Fatalf("uppercase-hex first presentation rejected: %v", err)
	}
	err := invokeFabricAuth16020(s, method, req, token, (&unaryCallProbe{}).handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("case-variant replay status = %s, err=%v; want Unauthenticated", status.Code(err), err)
	}
}

func TestFabricAuth16020_ReplayCacheExpiresEntries(t *testing.T) {
	var cache fabricMutationReplayCache
	var key [32]byte
	key[0] = 0x7f
	if got := cache.consumeAt(key, 100, 100); got != fabricReplayAccepted {
		t.Fatalf("first claim = %v, want accepted", got)
	}
	if got := cache.consumeAt(key, 100, 101); got != fabricReplayDuplicate {
		t.Fatalf("claim while token window remains accepted = %v, want duplicate", got)
	}
	var current [32]byte
	current[0] = 0x80
	if got := cache.consumeAt(current, 102, 102); got != fabricReplayAccepted {
		t.Fatalf("claim after token window expiry = %v, want accepted", got)
	}
	if got := cache.consumeAt(key, 100, 102); got != fabricReplayDuplicate {
		t.Fatalf("expired old-window token = %v, want permanently rejected", got)
	}
}

func TestFabricAuth16020_ReplayCacheCapFailsClosed(t *testing.T) {
	var cache fabricMutationReplayCache
	for i := range fabricMutationReplayCacheCapacity {
		var key [32]byte
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		if got := cache.consumeAt(key, 100, 100); got != fabricReplayAccepted {
			t.Fatalf("claim %d = %v, want accepted", i, got)
		}
	}
	var overflow [32]byte
	overflow[0] = 0xff
	overflow[1] = 0xff
	if got := cache.consumeAt(overflow, 100, 100); got != fabricReplayCacheFull {
		t.Fatalf("claim over cache cap = %v, want fail-closed cache-full", got)
	}
	if got := cache.consumeAt(overflow, 102, 102); got != fabricReplayAccepted {
		t.Fatalf("claim after cached windows expire = %v, want accepted", got)
	}
}

func TestFabricAuth16020_ReversedWindowOrderPrunesExpiredEntries(t *testing.T) {
	var cache fabricMutationReplayCache
	var laterExpiry [32]byte
	laterExpiry[0], laterExpiry[2] = 1, 1
	if got := cache.consumeAt(laterExpiry, 102, 101); got != fabricReplayAccepted {
		t.Fatalf("later-expiring claim = %v, want accepted", got)
	}
	var earlierExpiry [32]byte
	earlierExpiry[0], earlierExpiry[2] = 2, 2
	if got := cache.consumeAt(earlierExpiry, 101, 100); got != fabricReplayAccepted {
		t.Fatalf("out-of-order earlier-expiring claim = %v, want accepted", got)
	}
	for i := range fabricMutationReplayCacheCapacity - 2 {
		var key [32]byte
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		key[2] = 3
		if got := cache.consumeAt(key, 102, 101); got != fabricReplayAccepted {
			t.Fatalf("fill claim %d = %v, want accepted", i, got)
		}
	}
	var afterExpiry [32]byte
	afterExpiry[0], afterExpiry[1], afterExpiry[2] = 0xff, 0xff, 4
	if got := cache.consumeAt(afterExpiry, 103, 103); got != fabricReplayAccepted {
		t.Fatalf("claim after pruning earlier-expiring window = %v, want accepted", got)
	}
	if got := cache.consumeAt(earlierExpiry, 101, 103); got != fabricReplayDuplicate {
		t.Fatalf("replay from expired window = %v, want permanently rejected", got)
	}
	if got := cache.consumeAt(laterExpiry, 102, 103); got != fabricReplayDuplicate {
		t.Fatalf("replay from still-live window = %v, want duplicate", got)
	}
}

func TestFabricAuth16020_BackwardWallStepCannotReplayMutation(t *testing.T) {
	windowStart := time.Unix(1_800_000_000, 0).UTC()
	now := windowStart
	clock := func() time.Time { return now }
	s := keyedServer(fabricTestKey)
	s.fabricAuthNowFn = clock
	s.fabricMutationReplay.nowFn = clock
	method := pb.BpfrxService_ClearSessions_FullMethodName

	firstReq := &pb.ClearSessionsRequest{Protocol: "tcp"}
	firstDigest, err := fabricRequestDigest(firstReq)
	if err != nil {
		t.Fatalf("first request digest: %v", err)
	}
	firstToken := fabricAuthTokenHexForDigest([]byte(fabricTestKey),
		windowStart.Add(time.Duration(fabricAuthWindowSeconds)*time.Second), method, firstDigest)
	var originalCalls atomic.Int32
	originalHandler := func(context.Context, interface{}) (interface{}, error) {
		originalCalls.Add(1)
		return nil, nil
	}
	if err := invokeFabricAuth16020(s, method, firstReq, firstToken, originalHandler); err != nil {
		t.Fatalf("first mutation: %v", err)
	}

	// Move past the original token's 91-second maximum acceptance horizon so
	// a wall-time TTL cache would purge it, then consume a current-window token.
	now = windowStart.Add(91*time.Second + 500*time.Millisecond)
	currentReq := &pb.ClearSessionsRequest{Protocol: "udp"}
	currentDigest, err := fabricRequestDigest(currentReq)
	if err != nil {
		t.Fatalf("current request digest: %v", err)
	}
	currentToken := fabricAuthTokenHexForDigest([]byte(fabricTestKey), now, method, currentDigest)
	if err := invokeFabricAuth16020(s, method, currentReq, currentToken,
		func(context.Context, interface{}) (interface{}, error) { return nil, nil }); err != nil {
		t.Fatalf("current-window mutation: %v", err)
	}

	// Step back across the window edge by two seconds. The original token is
	// again inside the verifier's ±1 acceptance band, but its single-use claim
	// must remain effective after the cache has advanced and purged its entry.
	now = now.Add(-2 * time.Second)
	decoded, ok := decodeFabricAuthToken(firstToken)
	if !ok {
		t.Fatal("test token did not decode")
	}
	if _, valid := verifyFabricAuthTokenBytesForDigestAt([]byte(fabricTestKey), decoded,
		method, firstDigest, now); !valid {
		t.Fatal("original token is not valid at the rollback instant; test does not exercise replay-cache defense")
	}
	err = invokeFabricAuth16020(s, method, firstReq, firstToken, originalHandler)
	if status.Code(err) != codes.Unauthenticated || !strings.Contains(status.Convert(err).Message(), "already used") {
		t.Fatalf("backward-step replay status = %s, err=%v; want cached replay Unauthenticated", status.Code(err), err)
	}
	if got := originalCalls.Load(); got != 1 {
		t.Fatalf("original mutation handler calls = %d, want exactly 1", got)
	}
}
