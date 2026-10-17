package grpcapi

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// #5883: the two internal hop-control metadata keys.
//
// `x-peer-forwarded` marks a request one node already forwarded to its cluster
// peer; `xpf-no-peer` is the same idea on the show/monitor proxies. Both exist
// to bound forwarding to ONE hop, and every handler that reads one uses it to
// SUPPRESS work: skip the peer clear, skip the peer fan-out, serve locally
// instead of proxying.
//
// They were read straight off incoming metadata by presence
// (`len(md.Get(...)) > 0`), which makes them caller-settable. Any client that
// can reach a listener could assert "I am a forwarded peer request" and have
// the node skip the peer half of a cluster-wide operation while still returning
// a normal success — a clear that says it cleared the cluster and did not.
//
// The fix is not to authenticate the header. It is to stop the header from
// being the carrier at all: trust is a property of WHICH LISTENER the call
// arrived on, and a listener decides it, not the caller.
//
//   - The FABRIC listener is the only one a cluster peer dials. Its interceptor
//     chain runs #4107 auth first, and only then promotes the header into an
//     in-process context value. A caller cannot set a context value.
//   - The LOOPBACK listener is never dialed by a peer, so an inbound marker
//     there is by definition forged (or confused). It is stripped, and nothing
//     is promoted.
//
// Both listeners STRIP the keys after the interceptor runs, so no handler can
// reach past the capability to the raw metadata even by mistake — the header
// does not exist below this layer.
//
// Deliberately NOT changed: the marker still rides an ordinary metadata header
// on the wire between nodes. It has to — that is the only channel there is. The
// change is that a header is now evidence only when the listener that received
// it is one a peer could have dialed.
const (
	peerForwardedMetadataKey = "x-peer-forwarded"
	peerNoPeerMetadataKey    = "xpf-no-peer"
)

// reservedPeerMetadataKeys is the complete set of caller-visible metadata keys
// that grant an internal capability. It is the single source of truth for BOTH
// the strip and the promote, so a key added to one cannot be forgotten by the
// other — the failure this whole file exists to prevent.
//
// TestReservedPeerMetadataKeysAreComplete pins it against the keys the handlers
// actually consume.
var reservedPeerMetadataKeys = []string{
	peerForwardedMetadataKey,
	peerNoPeerMetadataKey,
	// #14580: legacy unsigned persistent-NAT clear generation metadata.
	// Never honored (the signed request body is authoritative); stripped on
	// both listeners so no handler can read it even by mistake.
	"x-peer-persistent-nat-origin",
	"x-peer-persistent-nat-generation",
}

type peerMarkerCtxKeyType struct{}

// peerMarkerCtxKey is the in-process capability. A context value cannot be set
// by a gRPC caller — it has no channel to reach one — which is the entire
// security property.
var peerMarkerCtxKey peerMarkerCtxKeyType

// peerMarkers is the promoted, trusted form of the two hop markers.
type peerMarkers struct {
	forwarded bool
	noPeer    bool
}

// withPeerMarkers attaches the trusted capability. Only the fabric interceptor
// calls it, and only after authentication has already accepted the call.
func withPeerMarkers(ctx context.Context, m peerMarkers) context.Context {
	return context.WithValue(ctx, peerMarkerCtxKey, m)
}

// peerMarkersFromContext returns the trusted markers. A context with no
// capability yields the zero value — both false — which is the SAFE direction
// for both markers: false means "do the peer work", so a stripped or forged
// header can only cause MORE work to be attempted, never less.
func peerMarkersFromContext(ctx context.Context) peerMarkers {
	m, _ := ctx.Value(peerMarkerCtxKey).(peerMarkers)
	return m
}

// stripReservedPeerMetadata removes every reserved key from the incoming
// metadata, so a handler that reads raw metadata sees nothing to trust.
//
// It returns ctx unchanged when there is nothing to strip, so the common case
// allocates no copy.
func stripReservedPeerMetadata(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	present := false
	for _, k := range reservedPeerMetadataKeys {
		if len(md.Get(k)) > 0 {
			present = true
			break
		}
	}
	if !present {
		return ctx
	}
	// metadata.MD.Copy is required: the incoming MD may be shared, and mutating
	// it in place would reach other RPCs on the same connection.
	stripped := md.Copy()
	for _, k := range reservedPeerMetadataKeys {
		stripped.Delete(k)
	}
	return metadata.NewIncomingContext(ctx, stripped)
}

// readPeerMarkers reads the two markers off raw incoming metadata. It is called
// ONLY by the fabric interceptor, on a call #4107 auth has already accepted.
func readPeerMarkers(ctx context.Context) peerMarkers {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return peerMarkers{}
	}
	return peerMarkers{
		forwarded: len(md.Get(peerForwardedMetadataKey)) > 0,
		noPeer:    len(md.Get(peerNoPeerMetadataKey)) > 0,
	}
}

// peerMarkerCtx is the shared body of the four interceptors below. trust=false
// strips without promoting (loopback); trust=true promotes then strips
// (fabric, post-auth).
func peerMarkerCtx(ctx context.Context, trust bool) context.Context {
	if trust {
		ctx = withPeerMarkers(ctx, readPeerMarkers(ctx))
	}
	return stripReservedPeerMetadata(ctx)
}

// peerMarkerUnaryInterceptor returns the unary interceptor for one listener.
//
// On the fabric chain it MUST be chained AFTER fabricAuthUnaryInterceptor:
// grpc.ChainUnaryInterceptor runs interceptors in order, so auth rejects an
// unauthenticated call before anything is promoted.
func peerMarkerUnaryInterceptor(trust bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(peerMarkerCtx(ctx, trust), req)
	}
}

// peerMarkerServerStream re-parents a stream's context. grpc.ServerStream has
// no setter, so the standard shape is to embed and override Context().
type peerMarkerServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s peerMarkerServerStream) Context() context.Context { return s.ctx }

// peerMarkerStreamInterceptor is the streaming counterpart. It matters on its
// own: MonitorInterface is a streaming RPC and reads the no-peer marker to
// decide whether to proxy.
func peerMarkerStreamInterceptor(trust bool) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, peerMarkerServerStream{
			ServerStream: ss,
			ctx:          peerMarkerCtx(ss.Context(), trust),
		})
	}
}

// loopbackServerInterceptors is the interceptor chain the LOOPBACK gRPC server
// installs. It exists as a named function rather than an inline argument list
// so the wiring itself is testable: a test can run the returned chain and prove
// a forged marker is dropped, which an option slice passed straight into
// grpc.NewServer cannot support (server options are opaque once applied).
//
// Without this seam, deleting the interceptors from Run() would still compile
// and still pass every unit test that exercises the interceptor directly —
// the fix would be present in the package and absent from the listener.
func loopbackServerInterceptors() ([]grpc.UnaryServerInterceptor, []grpc.StreamServerInterceptor) {
	return []grpc.UnaryServerInterceptor{peerMarkerUnaryInterceptor(false)},
		[]grpc.StreamServerInterceptor{peerMarkerStreamInterceptor(false)}
}
