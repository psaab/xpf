package grpcapi

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// #16031: fabric streams have no continuous re-auth. Removing the PSK
// entirely while a fabric stream is open must end it within one re-auth
// tick; rotating to a new key that is still accepted must not.
//
// FAIL-ON-REVERT: without the reauthFabricStream watcher in
// fabricAuthStreamInterceptor, the key-removal cell hangs until the test
// timeout (the stream outlives decommission).

func shortenFabricStreamReauth16031(t *testing.T) {
	t.Helper()
	old := fabricStreamReauthInterval
	fabricStreamReauthInterval = 15 * time.Millisecond
	t.Cleanup(func() { fabricStreamReauthInterval = old })
}

func fabricStreamCtx16031(key []byte, method string) context.Context {
	md := metadata.Pairs(fabricAuthMetadataKey, fabricAuthTokenHex(key, time.Now(), method))
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestFabricStreamEndsWhenKeyRemoved16031(t *testing.T) {
	shortenFabricStreamReauth16031(t)
	const method = pb.BpfrxService_MonitorInterface_FullMethodName
	var key atomic.Value
	key.Store([]byte(fabricTestKey))
	s := &Server{fabricAuthKeyFn: func() []byte {
		if v := key.Load(); v != nil {
			if b, ok := v.([]byte); ok {
				return b
			}
		}
		return nil
	}}

	entered := make(chan struct{})
	handler := func(_ interface{}, ss grpc.ServerStream) error {
		close(entered)
		<-ss.Context().Done()
		return nil
	}
	errc := make(chan error, 1)
	go func() {
		errc <- s.fabricAuthStreamInterceptor(nil,
			fakeServerStream{ctx: fabricStreamCtx16031([]byte(fabricTestKey), method)},
			&grpc.StreamServerInfo{FullMethod: method}, handler)
	}()
	select {
	case <-entered:
	case err := <-errc:
		t.Fatalf("stream refused at open: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler never ran")
	}

	// Remove the PSK entirely (decommission, not rotation).
	key.Store([]byte{})

	select {
	case err := <-errc:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("key-removed fabric stream must end Unauthenticated, got %v (%v)", err, status.Code(err))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("fabric stream outlived PSK removal (#16031)")
	}
}

func TestFabricStreamSurvivesRotationToAcceptedKey16031(t *testing.T) {
	shortenFabricStreamReauth16031(t)
	const method = pb.BpfrxService_MonitorInterface_FullMethodName
	// Real rotation (#6630): start with the old key signing, then rotate so
	// the new key signs and the old remains accepted as the additional key.
	// A stream opened under the old key must survive — only REMOVAL (old
	// key no longer accepted) ends it.
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.NewSecret(fabricTestKey)})
	s := &Server{cluster: m}

	ctx, cancel := context.WithCancel(fabricStreamCtx16031([]byte(fabricTestKey), method))
	defer cancel()
	entered := make(chan struct{})
	handler := func(_ interface{}, ss grpc.ServerStream) error {
		close(entered)
		<-ss.Context().Done()
		return nil
	}
	errc := make(chan error, 1)
	go func() {
		errc <- s.fabricAuthStreamInterceptor(nil,
			fakeServerStream{ctx: ctx},
			&grpc.StreamServerInfo{FullMethod: method}, handler)
	}()
	select {
	case <-entered:
	case err := <-errc:
		t.Fatalf("stream refused at open: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler never ran")
	}

	m.UpdateConfig(&config.ClusterConfig{
		ControlLinkAuthKey:    config.NewSecret("rotated-control-key"),
		ControlLinkAuthKeyAlt: config.NewSecret(fabricTestKey),
	})

	// Several ticks across the rotation: must NOT terminate.
	select {
	case err := <-errc:
		t.Fatalf("fabric stream terminated by a rotation that still accepts its key: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end on client cancel")
	}
}

func TestFabricStreamRecheckUnit16031(t *testing.T) {
	const method = pb.BpfrxService_MonitorInterface_FullMethodName
	key := []byte(fabricTestKey)
	// Mint in a window far outside the current ±1 accept band: the token
	// is expired as a CURRENT-window credential, which is exactly the
	// state every healthy long-lived stream reaches within 30–90s.
	oldWindow := fabricAuthWindow(time.Now()) - 10
	tok := fabricAuthTokenHexForDigest(key, time.Unix(oldWindow*fabricAuthWindowSeconds, 0), method, fabricAuthEmptyRequestDigest[:])
	ctx := withFabricStreamMintWindow(
		metadata.NewIncomingContext(context.Background(), metadata.Pairs(fabricAuthMetadataKey, tok)),
		oldWindow)

	s := keyedServer(fabricTestKey)
	if err := s.fabricStreamRecheck(ctx, method); err != nil {
		t.Fatalf("expired-window token under an unchanged PSK must recheck clean (key-set membership, not current-window validity): %v", err)
	}
	if err := s.fabricStreamRecheck(
		metadata.NewIncomingContext(context.Background(), metadata.Pairs(fabricAuthMetadataKey, tok)), method,
	); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("without a captured mint window the expired token must fail the open-time check, got %v", err)
	}
	removed := keyedServer("")
	if err := removed.fabricStreamRecheck(ctx, method); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("recheck after key removal must be Unauthenticated, got %v", err)
	}
	stranger := keyedServer("some-other-key-entirely")
	if err := stranger.fabricStreamRecheck(ctx, method); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("recheck under a stranger key must be Unauthenticated, got %v", err)
	}
	// The capture helper finds the mint window inside the open-time band
	// and refuses tokens no accepted key verifies.
	liveTok := fabricAuthTokenHex(key, time.Now(), method)
	w, ok := captureFabricStreamMintWindow([][]byte{key}, liveTok, method)
	if !ok || w != fabricAuthWindow(time.Now()) {
		t.Fatalf("captureFabricStreamMintWindow = (%d, %v), want (%d, true)", w, ok, fabricAuthWindow(time.Now()))
	}
	if _, ok := captureFabricStreamMintWindow([][]byte{[]byte("some-other-key-entirely")}, liveTok, method); ok {
		t.Fatal("capture must fail when no accepted key verifies the token")
	}
	if _, ok := captureFabricStreamMintWindow([][]byte{key}, tok, method); ok {
		t.Fatal("capture must fail for a token minted outside the open-time band")
	}
}

// TestFabricStreamSurvivesTokenWindowExpiry16031 is the fold's defect
// cell end-to-end: a stream whose token window has left the accept band
// must NOT be terminated while the PSK is unchanged. A token minted ten
// windows ago would be refused at open by the production interceptor,
// so this drives the real reauthFabricStream watcher from the
// interceptor's post-open state (fabric marker + captured mint window,
// token already outside the band).
//
// FAIL-ON-REVERT: a recheck that re-verifies current-window validity
// terminates this stream on the first tick.
func TestFabricStreamSurvivesTokenWindowExpiry16031(t *testing.T) {
	shortenFabricStreamReauth16031(t)
	const method = pb.BpfrxService_MonitorInterface_FullMethodName
	key := []byte(fabricTestKey)
	oldWindow := fabricAuthWindow(time.Now()) - 10
	tok := fabricAuthTokenHexForDigest(key, time.Unix(oldWindow*fabricAuthWindowSeconds, 0), method, fabricAuthEmptyRequestDigest[:])
	ctx, cancel := context.WithCancel(withFabricStreamMintWindow(
		withFabricAuthStreamContext(metadata.NewIncomingContext(context.Background(), metadata.Pairs(fabricAuthMetadataKey, tok))),
		oldWindow))
	defer cancel()

	s := keyedServer(fabricTestKey)
	entered := make(chan struct{})
	handler := func(_ interface{}, ss grpc.ServerStream) error {
		close(entered)
		<-ss.Context().Done()
		return nil
	}
	errc := make(chan error, 1)
	go func() {
		errc <- s.reauthFabricStream(nil, fakeServerStream{ctx: ctx},
			&grpc.StreamServerInfo{FullMethod: method}, handler)
	}()
	select {
	case <-entered:
	case err := <-errc:
		t.Fatalf("stream refused: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler never ran")
	}
	select {
	case err := <-errc:
		t.Fatalf("stream with expired token window terminated under an unchanged PSK: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end on client cancel")
	}
}
