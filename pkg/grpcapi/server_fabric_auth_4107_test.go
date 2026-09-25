package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// #4107 F1: the network-exposed cluster fabric gRPC listener must AUTHENTICATE
// its caller with the control-link PSK, not merely authorize a method allowlist
// (#4122). These tests drive the fabric auth interceptors directly. On revert
// (auth interceptors removed) the "invalid token" and "downgrade" cases go RED:
// an unauthenticated on-segment host regains access to the allowlisted
// read/monitor/ClearSessions/cross-node-failover RPCs.

const fabricTestKey = "control-link-secret-key"

func keyedServer(key string) *Server {
	return &Server{fabricAuthKeyFn: func() []byte {
		if key == "" {
			return nil
		}
		return []byte(key)
	}}
}

func ctxWithToken(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(fabricAuthMetadataKey, token))
}

// TestFabricAuthUnary_ValidTokenAllowed: with a key configured, an allowlisted
// read RPC carrying a valid current-window token reaches the handler, and the
// call flips the sticky peer-authenticated flag.
func TestFabricAuthUnary_ValidTokenAllowed(t *testing.T) {
	s := keyedServer(fabricTestKey)
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_GetSessions_FullMethodName}
	token := fabricAuthTokenHex([]byte(fabricTestKey), time.Now(), info.FullMethod)
	probe := &unaryCallProbe{}
	resp, err := s.fabricAuthUnaryInterceptor(ctxWithToken(token), nil, info, probe.handler)
	if err != nil {
		t.Fatalf("valid token: expected allow, got %v", err)
	}
	if !probe.called || resp != "ok" {
		t.Fatalf("valid token: handler not invoked / bad passthrough (called=%v resp=%v)", probe.called, resp)
	}
	if !s.fabricPeerAuthSeen.Load() {
		t.Error("valid token: expected fabricPeerAuthSeen to be set (sticky)")
	}
}

// TestFabricAuthUnary_InvalidTokenRejected: with a key configured, a present but
// wrong token is rejected Unauthenticated and the handler never runs. RED on
// revert (no auth): the handler runs.
func TestFabricAuthUnary_InvalidTokenRejected(t *testing.T) {
	s := keyedServer(fabricTestKey)
	// A token computed from a DIFFERENT key must not verify.
	badToken := fabricAuthTokenHex([]byte("attacker-guess"), time.Now(), pb.BpfrxService_ClearSessions_FullMethodName)
	probe := &unaryCallProbe{}
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_ClearSessions_FullMethodName}
	_, err := s.fabricAuthUnaryInterceptor(ctxWithToken(badToken), nil, info, probe.handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("invalid token: expected Unauthenticated, got %v", err)
	}
	if probe.called {
		t.Error("invalid token: handler was invoked")
	}
	// A syntactically broken token (non-hex) is likewise rejected.
	probe = &unaryCallProbe{}
	_, err = s.fabricAuthUnaryInterceptor(ctxWithToken("not-hex!!"), nil, info, probe.handler)
	if status.Code(err) != codes.Unauthenticated || probe.called {
		t.Errorf("malformed token: expected Unauthenticated with no handler call, got err=%v called=%v", err, probe.called)
	}
}

// TestFabricAuthUnary_TokenlessRejectedAfterPeerAuth: once the peer has proven
// it holds the key (sticky flag set), a tokenless call is a downgrade attack and
// is rejected. RED on revert: the tokenless call is admitted.
func TestFabricAuthUnary_TokenlessRejectedAfterPeerAuth(t *testing.T) {
	s := keyedServer(fabricTestKey)
	s.fabricPeerAuthSeen.Store(true) // peer authenticated earlier this process
	probe := &unaryCallProbe{}
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_GetStatus_FullMethodName}
	// No token metadata at all.
	_, err := s.fabricAuthUnaryInterceptor(context.Background(), nil, info, probe.handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("tokenless after peer-auth: expected Unauthenticated, got %v", err)
	}
	if probe.called {
		t.Error("tokenless after peer-auth: handler was invoked")
	}
}

// TestFabricAuthUnary_HeartbeatArmsDowngradeGuard: the post-restart-window fix.
// After a keyed node restarts, its fabric sticky flag is NOT armed (nothing has
// dialed the fabric listener on-demand yet), but its heartbeat receiver
// re-authenticates the peer within ~one interval. A tokenless fabric call must
// be REJECTED as soon as the heartbeat has armed enforcement — even though the
// fabric sticky flag is still false. RED on revert (arming only off the fabric
// sticky flag): the tokenless call is grace-accepted, re-opening the window in
// which any on-segment host can drive ClearSessions / cross-node failover.
func TestFabricAuthUnary_HeartbeatArmsDowngradeGuard(t *testing.T) {
	s := keyedServer(fabricTestKey)
	// Fabric sticky flag deliberately NOT armed (fresh after restart)...
	if s.fabricPeerAuthSeen.Load() {
		t.Fatal("precondition: fabric sticky flag should be unset")
	}
	// ...but the heartbeat has authenticated the peer.
	s.heartbeatAuthSeenFn = func() bool { return true }

	probe := &unaryCallProbe{}
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_ClearSessions_FullMethodName}
	// No token metadata at all.
	_, err := s.fabricAuthUnaryInterceptor(context.Background(), nil, info, probe.handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("heartbeat-armed tokenless: expected Unauthenticated, got %v", err)
	}
	if probe.called {
		t.Error("heartbeat-armed tokenless: handler was invoked (post-restart window still open)")
	}

	// Sanity: with the heartbeat NOT yet armed (peer not signing — e.g. rolling
	// upgrade / not-yet-keyed peer) the same tokenless call is grace-accepted,
	// preserving dual-accept.
	s.heartbeatAuthSeenFn = func() bool { return false }
	probe = &unaryCallProbe{}
	if _, err := s.fabricAuthUnaryInterceptor(context.Background(), nil, info, probe.handler); err != nil {
		t.Errorf("heartbeat-not-armed tokenless: expected grace allow, got %v", err)
	}
	if !probe.called {
		t.Error("heartbeat-not-armed tokenless: grace was not applied")
	}
}

// TestFabricAuthUnary_RollingUpgradeGrace: with a key configured but the peer not
// yet keyed (never authenticated), a tokenless call is admitted so the
// config-synced key can propagate without breaking cross-node proxy during the
// rollout. Documents the dual-accept grace (mirrors heartbeatAuthDecision).
func TestFabricAuthUnary_RollingUpgradeGrace(t *testing.T) {
	s := keyedServer(fabricTestKey) // peerAuthSeen defaults false
	probe := &unaryCallProbe{}
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_GetStatus_FullMethodName}
	resp, err := s.fabricAuthUnaryInterceptor(context.Background(), nil, info, probe.handler)
	if err != nil {
		t.Fatalf("rolling-upgrade grace: expected allow, got %v", err)
	}
	if !probe.called || resp != "ok" {
		t.Fatalf("rolling-upgrade grace: handler not invoked (called=%v)", probe.called)
	}
}

// TestFabricAuthUnary_NoKeyStatusOnly: GetStatus remains available as the
// fabric listener's unauthenticated health probe when no PSK is configured.
func TestFabricAuthUnary_NoKeyStatusOnly(t *testing.T) {
	s := keyedServer("") // no key
	probe := &unaryCallProbe{}
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_GetStatus_FullMethodName}
	_, err := s.fabricAuthUnaryInterceptor(context.Background(), nil, info,
		func(ctx context.Context, req interface{}) (interface{}, error) {
			return s.fabricAllowlistUnaryInterceptor(ctx, req, info, probe.handler)
		})
	if err != nil {
		t.Fatalf("unkeyed GetStatus health probe: expected allow, got %v", err)
	}
	if !probe.called {
		t.Fatal("unkeyed GetStatus health probe did not reach handler")
	}
}

// TestFabricAuthUnary_NoKeyRejectsClearSessionsAndFailover is the #10698
// fail-on-revert RED guard: without a configured PSK, destructive-within-peer-
// trust methods must stop at authentication before the allowlist or handler.
func TestFabricAuthUnary_NoKeyRejectsClearSessionsAndFailover(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		req    interface{}
	}{
		{
			name:   "GetSessions",
			method: pb.BpfrxService_GetSessions_FullMethodName,
			req:    &pb.GetSessionsRequest{},
		},
		{
			name:   "ClearSessions",
			method: pb.BpfrxService_ClearSessions_FullMethodName,
			req:    &pb.ClearSessionsRequest{},
		},
		{
			name:   "cluster-failover",
			method: pb.BpfrxService_SystemAction_FullMethodName,
			req:    &pb.SystemActionRequest{Action: "cluster-failover:1:node1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := keyedServer("") // no key
			probe := &unaryCallProbe{}
			info := &grpc.UnaryServerInfo{FullMethod: tc.method}
			_, err := s.fabricAuthUnaryInterceptor(context.Background(), tc.req, info,
				func(ctx context.Context, req interface{}) (interface{}, error) {
					return s.fabricAllowlistUnaryInterceptor(ctx, req, info, probe.handler)
				})
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("unkeyed %s: got err=%v (%s), want Unauthenticated",
					tc.name, err, status.Code(err))
			}
			if probe.called {
				t.Fatalf("unkeyed %s reached its handler", tc.name)
			}
		})
	}
}

// TestFabricAuthStream_NoKeyRejectsMonitorInterface enforces the same unkeyed
// GetStatus-only policy for the fabric listener's streaming surface.
func TestFabricAuthStream_NoKeyRejectsMonitorInterface(t *testing.T) {
	s := keyedServer("")
	handlerCalled := false
	err := s.fabricAuthStreamInterceptor(nil,
		fakeServerStream{ctx: context.Background()},
		&grpc.StreamServerInfo{FullMethod: pb.BpfrxService_MonitorInterface_FullMethodName},
		func(srv interface{}, ss grpc.ServerStream) error {
			handlerCalled = true
			return nil
		})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unkeyed MonitorInterface: got err=%v (%s), want Unauthenticated",
			err, status.Code(err))
	}
	if handlerCalled {
		t.Fatal("unkeyed MonitorInterface reached its handler")
	}
}

// TestFabricAuthStream_Enforced: the streaming interceptor enforces the same
// PSK auth (valid token allowed; invalid rejected before the handler runs).
func TestFabricAuthStream_Enforced(t *testing.T) {
	s := keyedServer(fabricTestKey)
	handlerCalled := false
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}
	info := &grpc.StreamServerInfo{FullMethod: pb.BpfrxService_MonitorInterface_FullMethodName}

	// Valid token: allowed.
	token := fabricAuthTokenHex([]byte(fabricTestKey), time.Now(), info.FullMethod)
	if err := s.fabricAuthStreamInterceptor(nil, fakeServerStream{ctx: ctxWithToken(token)}, info, handler); err != nil {
		t.Errorf("stream valid token: expected allow, got %v", err)
	}
	if !handlerCalled {
		t.Error("stream valid token: handler not invoked")
	}

	// Invalid token: rejected, handler not reached.
	handlerCalled = false
	bad := fabricAuthTokenHex([]byte("wrong"), time.Now(), info.FullMethod)
	err := s.fabricAuthStreamInterceptor(nil, fakeServerStream{ctx: ctxWithToken(bad)}, info, handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("stream invalid token: expected Unauthenticated, got %v", err)
	}
	if handlerCalled {
		t.Error("stream invalid token: handler was invoked")
	}
}

// fakeServerStream is a minimal grpc.ServerStream carrying a context for the
// stream interceptor auth check.
type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f fakeServerStream) Context() context.Context { return f.ctx }

// TestFabricAuthChainStopsDestructiveUnauth demonstrates the composed fabric
// pipeline: auth runs before the allowlist, so an unauthenticated SystemAction
// (which multiplexes zeroize) is stopped at the AUTH layer even before the
// allowlist's nested-action gate. RED on revert of either layer: a factory-reset
// wipe becomes reachable on the network-exposed fabric IP.
func TestFabricAuthChainStopsDestructiveUnauth(t *testing.T) {
	s := keyedServer(fabricTestKey)
	s.fabricPeerAuthSeen.Store(true) // both nodes keyed: enforce
	probe := &unaryCallProbe{}
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_SystemAction_FullMethodName}
	req := &pb.SystemActionRequest{Action: "zeroize"}

	// Compose the two interceptors in the SAME order RunFabricListener chains
	// them: auth first, then allowlist.
	chained := func(ctx context.Context, r interface{}, i *grpc.UnaryServerInfo, h grpc.UnaryHandler) (interface{}, error) {
		return s.fabricAuthUnaryInterceptor(ctx, r, i, func(c context.Context, rr interface{}) (interface{}, error) {
			return s.fabricAllowlistUnaryInterceptor(c, rr, i, h)
		})
	}
	// Unauthenticated (no token): auth layer rejects.
	_, err := chained(context.Background(), req, info, probe.handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("unauth zeroize: expected Unauthenticated from auth layer, got %v", err)
	}
	if probe.called {
		t.Error("unauth zeroize: handler reached")
	}
	// Authenticated but destructive: auth passes, allowlist rejects zeroize.
	probe = &unaryCallProbe{}
	token := fabricAuthTokenHex([]byte(fabricTestKey), time.Now(), info.FullMethod)
	_, err = chained(ctxWithToken(token), req, info, probe.handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("authed zeroize: expected PermissionDenied from allowlist, got %v", err)
	}
	if probe.called {
		t.Error("authed zeroize: handler reached")
	}
}

// TestFabricAuthTokenRoundTrip pins the token primitives: a current-window token
// verifies, a token from a different key does not, adjacent windows verify
// (clock-skew tolerance), and far windows / malformed input do not.
func TestFabricAuthTokenRoundTrip(t *testing.T) {
	key := []byte(fabricTestKey)
	now := time.Now()
	tok := fabricAuthTokenHex(key, now)
	if !verifyFabricAuthToken(key, tok) {
		t.Error("current-window token failed to verify")
	}
	if verifyFabricAuthToken([]byte("other-key"), tok) {
		t.Error("token verified under the wrong key")
	}
	if verifyFabricAuthToken(nil, tok) {
		t.Error("token verified with no key")
	}
	if verifyFabricAuthToken(key, "") {
		t.Error("empty token verified")
	}
	if verifyFabricAuthToken(key, "zz") {
		t.Error("malformed token verified")
	}
	// Adjacent windows (±1) verify; ±2 does not.
	prev := fabricAuthTokenHex(key, now.Add(-fabricAuthWindowSeconds*time.Second))
	next := fabricAuthTokenHex(key, now.Add(fabricAuthWindowSeconds*time.Second))
	if !verifyFabricAuthToken(key, prev) || !verifyFabricAuthToken(key, next) {
		t.Error("adjacent-window token failed to verify (skew tolerance)")
	}
	far := fabricAuthTokenHex(key, now.Add(3*fabricAuthWindowSeconds*time.Second))
	if verifyFabricAuthToken(key, far) {
		t.Error("far-window token verified (replay horizon too wide)")
	}
}

// TestFabricAuthCreds pins the client credential: it emits the token header when
// a key is configured, nothing when not, and never requires transport security
// (it must ride the fabric's insecure transport).
func TestFabricAuthCreds(t *testing.T) {
	creds := fabricAuthCreds{keyFn: func() []byte { return []byte(fabricTestKey) }}
	method := pb.BpfrxService_GetStatus_FullMethodName
	md, err := creds.GetRequestMetadata(withFabricAuthMethod(context.Background(), method))
	if err != nil {
		t.Fatalf("GetRequestMetadata: %v", err)
	}
	tok := md[fabricAuthMetadataKey]
	if tok == "" || !verifyFabricAuthToken([]byte(fabricTestKey), tok, method) {
		t.Errorf("creds emitted no/invalid method-bound token: %q", tok)
	}
	if creds.RequireTransportSecurity() {
		t.Error("fabric creds must not require transport security")
	}
	// Without the method-carrying interceptor no metadata is emitted rather
	// than falling back to a cross-method replayable token.
	unbound, err := creds.GetRequestMetadata(context.Background())
	if err != nil || len(unbound) != 0 {
		t.Errorf("missing-method creds: expected empty metadata, got %v (err %v)", unbound, err)
	}
	// No key => no metadata (tokenless dual-accept dial).
	empty := fabricAuthCreds{keyFn: func() []byte { return nil }}
	md, err = empty.GetRequestMetadata(withFabricAuthMethod(context.Background(), method))
	if err != nil || len(md) != 0 {
		t.Errorf("no-key creds: expected empty metadata, got %v (err %v)", md, err)
	}
}

// TestFabricAuthDecision pins the keyed dual-accept policy table (mirror of
// cluster.heartbeatAuthDecision). The method-aware unkeyed restriction is
// enforced by checkFabricAuth before this method-agnostic decision runs.
func TestFabricAuthDecision(t *testing.T) {
	type in struct{ keyConfigured, present, tokenOK, peerAuthSeen bool }
	cases := map[in]bool{
		{false, false, false, false}: true,  // no key: dual-accept
		{false, false, false, true}:  true,  // no key: dual-accept (flag irrelevant)
		{true, true, true, false}:    true,  // key + valid token
		{true, true, false, false}:   false, // key + invalid token
		{true, false, false, false}:  true,  // key + tokenless + never-authed: grace
		{true, false, false, true}:   false, // key + tokenless + peer-authed: downgrade
	}
	for c, want := range cases {
		got, reason := fabricAuthDecision(c.keyConfigured, c.present, c.tokenOK, c.peerAuthSeen)
		if got != want {
			t.Errorf("fabricAuthDecision(%+v) = %v (%q), want %v", c, got, reason, want)
		}
		if !got && reason == "" {
			t.Errorf("fabricAuthDecision(%+v) rejected without a reason", c)
		}
	}
}
