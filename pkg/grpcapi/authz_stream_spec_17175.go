package grpcapi

import (
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #17175: which streaming RPCs need their decoded request to be priced.
//
// THE DEFECT. principalStreamInterceptor ran authorizeRPC with a nil
// request, and the #9051 re-auth tick did the same. Since #16067 the
// command gate names a request's arguments (rpcArgumentForms), so a nil
// request is unnameable: every class with any deny/allow-commands regex
// was refused Ping, Traceroute and MonitorInterface at stream open —
// including an allowlist that explicitly admits ^ping. The #16067 cells
// called authorizeRPCCommand directly with a decoded request, a shape
// production never takes for streams, so the regression was invisible.
//
// THE FIX SHAPE. A server-streaming handler's generated wrapper decodes
// the request with stream.RecvMsg BEFORE calling the handler
// (xpf_grpc.pb.go _BpfrxService_Ping_Handler etc.), and grpc-go then
// wraps that stream in GenericServerStream whose RecvMsg returns the
// already-decoded message. So the interceptor cannot see the request at
// open; it sees it when the handler's stream first receives. The
// interceptor therefore:
//
//   - at open, prices only what does not need the request
//     (methodPermission(fullMethod, nil) — the table floor for every
//     streaming method, all PermView today);
//   - wraps the stream in authzRecvStream, whose first RecvMsg runs the
//     full authorizeRPCContext with the decoded message and retains it;
//   - hands that retained message to the #9051 re-auth tick, so a
//     mid-stream revocation is judged on the same arguments, not nil.
//
// streamRequestSpec is the single declaration of which streaming
// methods are request-dependent. It is keyed by the generated
// BpfrxService_*_FullMethodName constants so a rename breaks the build
// here, not silently at runtime. needsRequest=false means the full
// decision (coarse price, config-target price, command gate, config
// gates) is request-independent for that method: every request-taking
// switch in authorizeRPCContext falls through to its charge/ignore arm
// for it. MonitorPacketDrop is that case today — rpcArgumentForms has
// no arm for it, so it is judged on the bare `monitor security
// packet-drop` charge, which needs no request.
//
// FAIL CLOSED ON DRIFT. A streaming method absent from this table is
// treated as request-dependent (deferred full authorization on first
// RecvMsg). TestStreamRequestSpecCoversEveryStream17175 enumerates
// BpfrxService_ServiceDesc.Streams and fails if a stream is missing
// from the table, if the table names a non-stream, or if any stream is
// client-streaming (ClientStreams: true) — a client-streaming RPC
// sends many messages and this first-message-only design must not be
// silently extended to it. The same census also guards the
// needsRequest=false claim above: for every such method it asserts
// the typed empty request, a populated request and nil name identical
// argument forms, canonical command and method permission, with no
// config-target, alias, config-read or commit arm — so adding a
// request-priced arm for a request-independent stream fails there
// instead of silently diverging open (typed empty) from first-message
// and tick (retained decoded message).
var streamRequestSpec17175 = map[string]bool{
	pb.BpfrxService_Ping_FullMethodName:              true,
	pb.BpfrxService_Traceroute_FullMethodName:        true,
	pb.BpfrxService_MonitorInterface_FullMethodName:  true,
	pb.BpfrxService_MonitorPacketDrop_FullMethodName: false,
}

// streamNeedsRequest reports whether fullMethod's authorization decision
// depends on its decoded request. Unknown methods default to true
// (defer; fail closed for a restricted class if the message cannot be
// named) — the census test keeps the table complete so this default is
// never the operative answer for a served stream.
func streamNeedsRequest17175(fullMethod string) bool {
	needs, ok := streamRequestSpec17175[fullMethod]
	if !ok {
		return true
	}
	return needs
}
