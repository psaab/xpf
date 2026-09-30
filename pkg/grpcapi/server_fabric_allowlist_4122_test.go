package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #4122: the cluster fabric gRPC listener is the only network-exposed gRPC
// surface (the loopback Run() listener binds 127.0.0.1). It must fail-close to
// the exact set of read/monitor RPCs the peer actually proxies; every other
// method — Commit/Delete/Rollback, the config-mode surface, and
// SystemAction{zeroize,reboot,halt,power-off} — must be rejected with
// PermissionDenied before the handler runs. These tests exercise the fabric
// interceptors directly; on revert (interceptors removed / SystemAction
// admitted / a destructive method added to the allowlist) they go RED because
// the full service — including zeroize — becomes reachable on the fabric IP.

// sentinelHandler records whether the unary handler was reached.
type unaryCallProbe struct{ called bool }

func (p *unaryCallProbe) handler(ctx context.Context, req interface{}) (interface{}, error) {
	p.called = true
	return "ok", nil
}

func TestFabricAllowlistUnary_AllowsProxiedReadMonitorRPCs(t *testing.T) {
	s := &Server{}
	allowed := []string{
		pb.BpfrxService_GetStatus_FullMethodName,
		pb.BpfrxService_GetSessions_FullMethodName,
		pb.BpfrxService_GetSessionSummary_FullMethodName,
		pb.BpfrxService_GetZonePairSummary_FullMethodName,
		pb.BpfrxService_ClearSessions_FullMethodName,
		// #9059 MOVED ShowText OUT of this list, and the move is the fix.
		//
		// This case passes a nil request and asserts admission BY NAME. That is
		// the right shape for a method that does one thing, and the wrong shape
		// for one that multiplexes ~127 topics: admitting the name admitted
		// route-all, security-log, commit-history, the nat-*-detail topics and
		// the test-policy: simulator, while the only topic either peer-proxy
		// call site sends is "chassis-forwarding".
		//
		// It is now gated by request TOPIC, exactly as SystemAction is gated by
		// request ACTION in TestFabricAllowlistUnary_SystemActionNestedGate
		// below — see TestFabricAllowlistUnary_ShowTextTopicGate_9059.
	}
	for _, method := range allowed {
		probe := &unaryCallProbe{}
		info := &grpc.UnaryServerInfo{FullMethod: method}
		resp, err := s.fabricAllowlistUnaryInterceptor(context.Background(), nil, info, probe.handler)
		if err != nil {
			t.Errorf("method %s: expected allow, got err %v", method, err)
		}
		if !probe.called {
			t.Errorf("method %s: handler was not invoked", method)
		}
		if resp != "ok" {
			t.Errorf("method %s: expected handler response passthrough, got %v", method, resp)
		}
	}
}

func TestFabricAllowlistUnary_DeniesDestructiveAndUnknownMethods(t *testing.T) {
	s := &Server{}
	denied := []string{
		pb.BpfrxService_Commit_FullMethodName,
		pb.BpfrxService_CommitConfirmed_FullMethodName,
		pb.BpfrxService_Delete_FullMethodName,
		pb.BpfrxService_Rollback_FullMethodName,
		pb.BpfrxService_Load_FullMethodName,
		pb.BpfrxService_Set_FullMethodName,
		pb.BpfrxService_EnterConfigure_FullMethodName,
		"/xpf.v1.BpfrxService/DoesNotExist", // unknown method
	}
	for _, method := range denied {
		probe := &unaryCallProbe{}
		info := &grpc.UnaryServerInfo{FullMethod: method}
		_, err := s.fabricAllowlistUnaryInterceptor(context.Background(), nil, info, probe.handler)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("method %s: expected PermissionDenied, got %v", method, err)
		}
		if probe.called {
			t.Errorf("method %s: handler was invoked on a denied method", method)
		}
	}
}

// TestFabricAllowlistUnary_SystemActionNestedGate verifies the nested-action
// decision: SystemAction is admitted on the fabric only for the two proxied
// cross-node failover forms and the exact persistent-NAT clear action;
// destructive / local-only actions and near-misses remain denied. On revert
// (the nested gate removed) the zeroize case goes RED — a factory-reset wipe
// becomes reachable unauth on the fabric IP.
func TestFabricAllowlistUnary_SystemActionNestedGate(t *testing.T) {
	s := &Server{}
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_SystemAction_FullMethodName}

	deniedActions := []string{
		"zeroize",
		"reboot",
		"halt",
		"power-off",
		"clear-config-lock",
		// Exact clear exception must not admit near-misses if a future edit
		// widens equality to a prefix/contains or normalizing predicate.
		"clear-persistent-nat:extra", // suffixed
		"xclear-persistent-nat",      // prefixed
		"Clear-persistent-nat",       // case variant
		" clear-persistent-nat",      // leading whitespace
		"clear-persistent-nat ",      // trailing whitespace
		"clear-arp",                  // sibling clear-* action
		"clear-nat-counters",         // sibling clear-* action
		"cluster-failover-reset:1",   // local-only, never proxied
		"cluster-failover:1",         // no node suffix -> local-only, never proxied
		// Malformed / out-of-range failover suffixes must be denied AT THE
		// INTERCEPTOR so they never reach the handler's outbound proxy-dial
		// path (an unauth fabric client could otherwise drive avoidable proxy
		// dials / connection churn to arbitrary node IDs). RED-on-revert: the
		// loose HasPrefix/Contains gate admitted all of these.
		"cluster-failover:1:node99",      // node out of supported range (0/1)
		"cluster-failover-data:node99",   // node out of supported range
		"cluster-failover:garbage:node1", // non-numeric rgID
		"cluster-failover:1:nodeX",       // non-numeric node
		"cluster-failover-data:nodeX",    // non-numeric node
		"cluster-failover:1:node1:node2", // trailing garbage suffix
		"cluster-failover:1:node",        // empty node
		"cluster-failover-data:node",     // empty node
	}
	for _, action := range deniedActions {
		probe := &unaryCallProbe{}
		req := &pb.SystemActionRequest{Action: action}
		_, err := s.fabricAllowlistUnaryInterceptor(context.Background(), req, info, probe.handler)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("SystemAction %q: expected PermissionDenied on fabric, got %v", action, err)
		}
		if probe.called {
			t.Errorf("SystemAction %q: handler was invoked on the fabric listener", action)
		}
	}

	allowedActions := []string{
		"cluster-failover-data:node0",
		"cluster-failover-data:node1",
		"cluster-failover:1:node0",
		"cluster-failover:2:node1",
		"clear-persistent-nat",
	}
	for _, action := range allowedActions {
		probe := &unaryCallProbe{}
		req := &pb.SystemActionRequest{Action: action}
		_, err := s.fabricAllowlistUnaryInterceptor(context.Background(), req, info, probe.handler)
		if err != nil {
			t.Errorf("SystemAction %q: expected allow (authorized peer-coordination action), got %v", action, err)
		}
		if !probe.called {
			t.Errorf("SystemAction %q: handler was not invoked", action)
		}
	}

	// A SystemAction with the wrong request type must not be admitted (defensive:
	// isFabricSafeSystemAction returns false rather than panicking).
	probe := &unaryCallProbe{}
	_, err := s.fabricAllowlistUnaryInterceptor(context.Background(), &pb.GetStatusRequest{}, info, probe.handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("SystemAction with wrong req type: expected PermissionDenied, got %v", err)
	}
	if probe.called {
		t.Error("SystemAction with wrong req type: handler was invoked")
	}
}

// TestParseProxiedFailoverAction pins the SSOT parse the fabric interceptor
// shares with the handler: only well-formed cross-node failover forms (valid
// numeric rgID + in-range node) parse ok; every malformed / out-of-range /
// non-failover action is fail-closed (ok=false).
func TestParseProxiedFailoverAction(t *testing.T) {
	type want struct {
		rgID, nodeID int
		ok           bool
	}
	cases := map[string]want{
		// Well-formed.
		"cluster-failover-data:node0": {-1, 0, true},
		"cluster-failover-data:node1": {-1, 1, true},
		"cluster-failover:1:node0":    {1, 0, true},
		"cluster-failover:2:node1":    {2, 1, true},
		"cluster-failover:0:node1":    {0, 1, true},
		// Malformed / out-of-range / non-failover -> fail-closed.
		"cluster-failover-data:node99":   {0, 0, false},
		"cluster-failover-data:nodeX":    {0, 0, false},
		"cluster-failover-data:node":     {0, 0, false},
		"cluster-failover:1:node99":      {0, 0, false},
		"cluster-failover:garbage:node1": {0, 0, false},
		"cluster-failover:1:nodeX":       {0, 0, false},
		"cluster-failover:1:node1:node2": {0, 0, false},
		"cluster-failover:1:node":        {0, 0, false},
		"cluster-failover:1":             {0, 0, false}, // no node -> local-only
		"cluster-failover-reset:1":       {0, 0, false},
		"zeroize":                        {0, 0, false},
		"reboot":                         {0, 0, false},
		"":                               {0, 0, false},
	}
	for action, w := range cases {
		rg, node, ok := parseProxiedFailoverAction(action)
		if ok != w.ok {
			t.Errorf("parseProxiedFailoverAction(%q): ok = %v, want %v", action, ok, w.ok)
			continue
		}
		if ok && (rg != w.rgID || node != w.nodeID) {
			t.Errorf("parseProxiedFailoverAction(%q): (rg=%d node=%d), want (rg=%d node=%d)", action, rg, node, w.rgID, w.nodeID)
		}
	}
}

func TestFabricAllowlistStream_AllowsOnlyMonitorInterface(t *testing.T) {
	s := &Server{}

	// MonitorInterface (the only proxied stream) is allowed.
	streamCalled := false
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		streamCalled = true
		return nil
	}
	info := &grpc.StreamServerInfo{FullMethod: pb.BpfrxService_MonitorInterface_FullMethodName}
	if err := s.fabricAllowlistStreamInterceptor(nil, nil, info, handler); err != nil {
		t.Errorf("MonitorInterface stream: expected allow, got %v", err)
	}
	if !streamCalled {
		t.Error("MonitorInterface stream: handler was not invoked")
	}

	// A non-allowlisted stream (MonitorPacketDrop) is denied.
	streamCalled = false
	info = &grpc.StreamServerInfo{FullMethod: pb.BpfrxService_MonitorPacketDrop_FullMethodName}
	err := s.fabricAllowlistStreamInterceptor(nil, nil, info, handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("MonitorPacketDrop stream: expected PermissionDenied, got %v", err)
	}
	if streamCalled {
		t.Error("MonitorPacketDrop stream: handler was invoked on a denied stream")
	}
}

// TestFabricAllowlistExcludesDestructiveMethods guards the allowlist SETS so a
// future edit cannot silently add a destructive / config-mutating method (or
// SystemAction, which multiplexes zeroize) to the fabric surface.
func TestFabricAllowlistExcludesDestructiveMethods(t *testing.T) {
	mustNotBeAllowed := []string{
		pb.BpfrxService_Commit_FullMethodName,
		pb.BpfrxService_CommitConfirmed_FullMethodName,
		pb.BpfrxService_ConfirmCommit_FullMethodName,
		pb.BpfrxService_Delete_FullMethodName,
		pb.BpfrxService_Rollback_FullMethodName,
		pb.BpfrxService_Load_FullMethodName,
		pb.BpfrxService_Set_FullMethodName,
		pb.BpfrxService_EnterConfigure_FullMethodName,
		pb.BpfrxService_SystemAction_FullMethodName, // gated by action, never blanket-allowed
	}
	for _, method := range mustNotBeAllowed {
		if fabricAllowedUnaryMethods[method] {
			t.Errorf("%s must NOT be in fabricAllowedUnaryMethods", method)
		}
		if fabricAllowedStreamMethods[method] {
			t.Errorf("%s must NOT be in fabricAllowedStreamMethods", method)
		}
	}
}

// TestLoopbackListenerUnaffected proves the loopback (Run) path applies NO
// method allowlist: unlike the fabric listener, it admits every method
// (including the destructive ones the fabric listener denies). The method
// restriction lives ONLY in fabricAllowlistUnaryInterceptor, which the fabric
// server chains and the loopback server does not — so the loopback admits these
// by construction. (Post-#5849 the loopback has no config-lock unary
// interceptor at all; the config-lock lifecycle moved to a connection-scoped
// stats.Handler that never inspects the method.) This is the #4122 invariant
// that the allowlist is applied to the fabric surface ONLY.
func TestLoopbackListenerUnaffected(t *testing.T) {
	s := &Server{}
	for _, method := range []string{
		pb.BpfrxService_Commit_FullMethodName,
		pb.BpfrxService_Delete_FullMethodName,
		pb.BpfrxService_Rollback_FullMethodName,
		pb.BpfrxService_SystemAction_FullMethodName,
	} {
		// The restricting interceptor is fabric-only: verify it DENIES these
		// destructive methods (so the loopback, which does not chain it, admits
		// them). The loopback has no equivalent gate.
		probe := &unaryCallProbe{}
		info := &grpc.UnaryServerInfo{FullMethod: method}
		if _, err := s.fabricAllowlistUnaryInterceptor(context.Background(), &pb.SystemActionRequest{Action: "zeroize"}, info, probe.handler); err == nil {
			t.Errorf("fabric allowlist admitted destructive method %s; the loopback (no allowlist) admits it, but the allowlist must be fabric-only (#4122)", method)
		}
		if probe.called {
			t.Errorf("fabric allowlist invoked the handler for denied method %s", method)
		}
	}
}

// TestFabricAllowlistUnary_ShowTextTopicGate_9059 is the ShowText twin of the
// SystemAction nested gate above, and it exists for the identical reason: a
// method that multiplexes cannot be adjudicated by its name.
//
// On revert (ShowText returned to the plain allowlist, or the topic gate
// removed) the denied rows go RED, because 126 of 127 topics become reachable on
// the fabric IP — a compartment the same interceptor already gates per-action
// for its sibling.
func TestFabricAllowlistUnary_ShowTextTopicGate_9059(t *testing.T) {
	s := &Server{}
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_ShowText_FullMethodName}

	// REFERENCE ARM: the one topic the local node actually proxies must still
	// be served, or peer-proxied `show chassis forwarding` breaks. Without this
	// row, every denial below is satisfied by refusing ShowText outright.
	probe := &unaryCallProbe{}
	req := &pb.ShowTextRequest{Topic: "chassis-forwarding"}
	if _, err := s.fabricAllowlistUnaryInterceptor(context.Background(), req, info, probe.handler); err != nil {
		t.Fatalf("chassis-forwarding must be served on the fabric: %v", err)
	}
	if !probe.called {
		t.Fatal("chassis-forwarding handler was not invoked")
	}

	// A sample across the tiers the loopback table prices differently: runtime
	// state, an audit surface, and the policy simulator the authz table calls
	// "policy reconnaissance ... exactly the tier confusion this file exists to
	// prevent".
	for _, topic := range []string{
		"route-all",
		"security-log",
		"commit-history",
		"nat-source-detail",
		"test-policy:from-zone trust to-zone untrust",
		"", // an empty topic must not fall through to the handler either
	} {
		p := &unaryCallProbe{}
		r := &pb.ShowTextRequest{Topic: topic}
		_, err := s.fabricAllowlistUnaryInterceptor(context.Background(), r, info, p.handler)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("ShowText topic %q: expected PermissionDenied on the fabric, got %v", topic, err)
		}
		if p.called {
			t.Errorf("ShowText topic %q: handler was invoked on the fabric listener", topic)
		}
	}

	// A malformed request (wrong type for this method) must fail CLOSED, like
	// its sibling: it cannot be type-asserted, so it cannot be shown safe.
	p := &unaryCallProbe{}
	if _, err := s.fabricAllowlistUnaryInterceptor(context.Background(), nil, info, p.handler); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a nil ShowText request must be denied, got %v", err)
	}
	if p.called {
		t.Error("a nil ShowText request reached the handler")
	}
}

// TestFabricShowTextAllowlistCoversEveryProxiedTopic_9059 keeps the topic
// allowlist and the peer-proxy call sites from drifting apart.
//
// The failure it prevents is the OPPOSITE of #9059's and just as quiet: someone
// adds a second peer-proxied ShowText topic, the fabric gate refuses it, and the
// new feature silently does not work across the cluster. The allowlist's whole
// justification is "a topic the local node actually proxies", and a claim of
// that form needs the enumeration to be checked rather than remembered.
//
// It reads the call sites' SOURCE rather than a hand-kept list, so adding a
// proxy and forgetting the allowlist cannot pass.
func TestFabricShowTextAllowlistCoversEveryProxiedTopic_9059(t *testing.T) {
	sources := []string{
		"server_show_forwarding.go",
		filepath.Join("..", "cli", "cli_show_chassis.go"),
	}
	re := regexp.MustCompile(`ShowTextRequest\{Topic:\s*"([^"]*)"`)

	found := 0
	for _, path := range sources {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			found++
			if !fabricAllowedShowTextTopics[m[1]] {
				t.Errorf("%s proxies ShowText topic %q to a peer, but the fabric "+
					"topic allowlist does not admit it — the fabric listener will "+
					"refuse it and the feature will silently not work across the "+
					"cluster", path, m[1])
			}
		}
	}
	// POSITIVE CONTROL: the pattern must actually match something. A regex that
	// found nothing would report a clean board for a check that ran over no
	// subjects — the failure mode this repository has hit repeatedly.
	if found == 0 {
		t.Fatal("the proxy-call-site scan matched no ShowText request literals; " +
			"the pattern or the paths are stale and this case is asserting nothing")
	}
	// And the allowlist must not have grown entries nothing proxies, or its
	// stated justification stops being true in the other direction.
	if len(fabricAllowedShowTextTopics) > found {
		t.Errorf("the allowlist holds %d topics but only %d are proxied; every entry "+
			"must be a topic the local node actually sends",
			len(fabricAllowedShowTextTopics), found)
	}
}
