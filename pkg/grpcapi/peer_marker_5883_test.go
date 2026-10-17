package grpcapi

import (
	"context"
	"sort"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// fabricMarkerCtx runs the metadata md through the FABRIC listener's peer-marker
// interceptor and returns the context a handler would see. It is the production
// promotion path, so a test using it cannot pass by re-implementing the
// predicate — which the pre-#5883 chassis-forwarding test did, and which is why
// that test never noticed the header was forgeable.
func fabricMarkerCtx(t *testing.T, md metadata.MD) context.Context {
	t.Helper()
	var got context.Context
	_, err := peerMarkerUnaryInterceptor(true)(
		metadata.NewIncomingContext(context.Background(), md),
		nil, &grpc.UnaryServerInfo{FullMethod: "/test/M"},
		func(ctx context.Context, _ interface{}) (interface{}, error) {
			got = ctx
			return nil, nil
		})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	return got
}

// fabricMarkerCtxUntrusted is the same for the LOOPBACK listener, which
// promotes nothing. Named for the property under test (an UNTRUSTED ingress)
// rather than the listener, because the same interceptor guards any future
// listener that is not a peer-dialable one.
func fabricMarkerCtxUntrusted(t *testing.T, md metadata.MD) context.Context {
	t.Helper()
	var got context.Context
	_, err := peerMarkerUnaryInterceptor(false)(
		metadata.NewIncomingContext(context.Background(), md),
		nil, &grpc.UnaryServerInfo{FullMethod: "/test/M"},
		func(ctx context.Context, _ interface{}) (interface{}, error) {
			got = ctx
			return nil, nil
		})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	return got
}

// TestLoopbackListenerDoesNotHonorForgedPeerMarkers is the #5883 defect,
// directly. Before the fix, `peerForwardedFromContext` was
// `len(md.Get("x-peer-forwarded")) > 0` on raw incoming metadata, so ANY client
// that could reach the loopback listener could assert it was a forwarded peer
// request. ClearSessions then skipped the peer half of a cluster-wide clear and
// still reported success: sessions the operator was told were cleared survive
// on the peer and come back on failback.
//
// No cluster peer dials the loopback listener, so an inbound marker there is
// forged by definition.
//
// RED-on-revert: restore the raw-metadata read in peerForwardedFromContext (or
// drop the loopback interceptor) and both assertions fail.
func TestLoopbackListenerDoesNotHonorForgedPeerMarkers(t *testing.T) {
	ctx := fabricMarkerCtxUntrusted(t, metadata.MD{
		peerForwardedMetadataKey: []string{"1"},
		peerNoPeerMetadataKey:    []string{"1"},
	})

	if peerForwardedFromContext(ctx) {
		t.Error("a client-supplied x-peer-forwarded header on the loopback listener was honored: " +
			"a cluster-wide session clear can be suppressed to local-only while still reporting success")
	}
	if peerMarkersFromContext(ctx).noPeer {
		t.Error("a client-supplied xpf-no-peer header on the loopback listener was honored: " +
			"peer fan-out on the show/monitor proxies can be suppressed by the caller")
	}
}

// TestReservedMarkersAreStrippedFromMetadata proves the second half of the fix.
// Reading the capability is not enough on its own: a handler that reaches for
// the raw header must find nothing, or the next site added to this package
// re-opens the hole. `server_sessions.go` was exactly such a site — it read
// `md.Get("x-peer-forwarded")` directly instead of going through the helper.
//
// Both listeners strip, so this holds on the fabric side too: there the header
// has already been promoted to the capability and is redundant.
func TestReservedMarkersAreStrippedFromMetadata(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func() context.Context
	}{
		{"loopback", func() context.Context {
			return fabricMarkerCtxUntrusted(t, metadata.MD{
				peerForwardedMetadataKey: []string{"1"},
				peerNoPeerMetadataKey:    []string{"1"},
				"unrelated":              []string{"keep"},
			})
		}},
		{"fabric", func() context.Context {
			return fabricMarkerCtx(t, metadata.MD{
				peerForwardedMetadataKey: []string{"1"},
				peerNoPeerMetadataKey:    []string{"1"},
				"unrelated":              []string{"keep"},
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			md, ok := metadata.FromIncomingContext(tc.ctx())
			if !ok {
				t.Fatal("incoming metadata disappeared entirely")
			}
			for _, k := range reservedPeerMetadataKeys {
				if len(md.Get(k)) > 0 {
					t.Errorf("reserved key %q survived into the handler's metadata; a site that "+
						"reads it raw would trust a caller-supplied value", k)
				}
			}
			// Control: stripping must be surgical. Losing unrelated metadata
			// would break auth tokens, deadlines propagated as metadata, and
			// anything else riding the same MD.
			if got := md.Get("unrelated"); len(got) != 1 || got[0] != "keep" {
				t.Errorf("unrelated metadata was collateral damage: %#v", md)
			}
		})
	}
}

// TestFabricListenerPromotesPeerMarkers is the positive control, and it is what
// stops the fix from being "always return false". The fabric listener is the
// one a cluster peer dials, and the hop bound it enforces is real: without
// promotion, node A forwards a clear to node B, B does not recognise it as
// forwarded, and B forwards back to A — the A->B->A recursion the marker exists
// to stop.
func TestFabricListenerPromotesPeerMarkers(t *testing.T) {
	ctx := fabricMarkerCtx(t, metadata.MD{peerForwardedMetadataKey: []string{"1"}})
	if !peerForwardedFromContext(ctx) {
		t.Error("the fabric listener did not promote x-peer-forwarded: a peer-forwarded clear " +
			"will be forwarded back, recursing between the two nodes")
	}
	if peerMarkersFromContext(ctx).noPeer {
		t.Error("xpf-no-peer was promoted from a request that did not carry it")
	}

	ctx = fabricMarkerCtx(t, metadata.MD{peerNoPeerMetadataKey: []string{"1"}})
	if !peerMarkersFromContext(ctx).noPeer {
		t.Error("the fabric listener did not promote xpf-no-peer: the show/monitor proxies will re-proxy")
	}
	if peerForwardedFromContext(ctx) {
		t.Error("x-peer-forwarded was promoted from a request that did not carry it")
	}

	// A fabric call with neither marker is an ordinary first-hop request.
	ctx = fabricMarkerCtx(t, metadata.MD{"unrelated": []string{"1"}})
	if peerForwardedFromContext(ctx) || peerMarkersFromContext(ctx).noPeer {
		t.Error("markers appeared on a request that carried none")
	}
}

// TestPeerMarkerStreamInterceptorAppliesToStreams pins the streaming half.
// MonitorInterface is a server-streaming RPC and reads the no-peer marker to
// decide whether to proxy, so a unary-only fix would leave the streaming
// surface forgeable — the exact shape of gap #3908 was to #3082.
func TestPeerMarkerStreamInterceptorAppliesToStreams(t *testing.T) {
	run := func(trust bool) context.Context {
		var got context.Context
		base := metadata.NewIncomingContext(context.Background(),
			metadata.MD{peerNoPeerMetadataKey: []string{"1"}})
		err := peerMarkerStreamInterceptor(trust)(nil, fakeServerStream{ctx: base},
			&grpc.StreamServerInfo{FullMethod: "/test/S"},
			func(_ interface{}, ss grpc.ServerStream) error {
				got = ss.Context()
				return nil
			})
		if err != nil {
			t.Fatalf("stream interceptor: %v", err)
		}
		return got
	}

	if monitorRequestForwardedFromPeer(run(false)) {
		t.Error("a forged xpf-no-peer header was honored on a STREAMING RPC over the loopback listener")
	}
	if !monitorRequestForwardedFromPeer(run(true)) {
		t.Error("the fabric listener did not promote xpf-no-peer on a streaming RPC; " +
			"MonitorInterface will re-proxy and recurse")
	}
}

// TestReservedPeerMetadataKeysAreComplete binds the strip/promote key set to the
// keys the handlers actually consume. A new hop marker added to a handler
// without a row here would be readable raw and never stripped — which is how
// this defect existed in the first place, with two markers and one of them
// (`xpf-no-peer`) never named in the issue that found the other.
func TestReservedPeerMetadataKeysAreComplete(t *testing.T) {
	got := append([]string(nil), reservedPeerMetadataKeys...)
	sort.Strings(got)
	want := []string{"x-peer-forwarded", "x-peer-persistent-nat-generation", "x-peer-persistent-nat-origin", "xpf-no-peer"}
	if len(got) != len(want) {
		t.Fatalf("reserved key set = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reserved key set = %v, want %v", got, want)
		}
	}
	// The monitor path's own constant must be a member, not a parallel spelling.
	if monitorNoPeerMarker != peerNoPeerMetadataKey {
		t.Errorf("monitorNoPeerMarker = %q but the reserved key is %q: two spellings of one "+
			"marker, and only one of them is stripped", monitorNoPeerMarker, peerNoPeerMetadataKey)
	}
}

// TestLoopbackServerInstallsMarkerInterceptors binds the WIRING, not just the
// interceptor. Every other test in this file drives the interceptor directly,
// so all of them would still pass on a build where the loopback server simply
// never installs it — the fix present in the package, absent from the listener.
//
// It runs the chain the loopback server actually installs and asserts a forged
// marker does not survive it.
//
// RED-on-revert: remove the interceptors from Run()'s grpc.NewServer (i.e.
// return empty slices here) and both assertions fail.
func TestLoopbackServerInstallsMarkerInterceptors(t *testing.T) {
	unary, stream := loopbackServerInterceptors()
	if len(unary) == 0 || len(stream) == 0 {
		t.Fatal("the loopback gRPC server installs no peer-marker interceptor: a client-supplied " +
			"x-peer-forwarded header reaches the handlers and suppresses cluster-wide work")
	}

	forged := metadata.NewIncomingContext(context.Background(),
		metadata.MD{peerForwardedMetadataKey: []string{"1"}, peerNoPeerMetadataKey: []string{"1"}})

	var uctx context.Context
	if _, err := unary[0](forged, nil, &grpc.UnaryServerInfo{FullMethod: "/test/M"},
		func(ctx context.Context, _ interface{}) (interface{}, error) { uctx = ctx; return nil, nil }); err != nil {
		t.Fatalf("unary interceptor: %v", err)
	}
	if peerForwardedFromContext(uctx) || peerMarkersFromContext(uctx).noPeer {
		t.Error("the loopback unary chain honored a forged marker")
	}

	var sctx context.Context
	if err := stream[0](nil, fakeServerStream{ctx: forged}, &grpc.StreamServerInfo{FullMethod: "/test/S"},
		func(_ interface{}, ss grpc.ServerStream) error { sctx = ss.Context(); return nil }); err != nil {
		t.Fatalf("stream interceptor: %v", err)
	}
	if peerForwardedFromContext(sctx) || peerMarkersFromContext(sctx).noPeer {
		t.Error("the loopback stream chain honored a forged marker")
	}
}
