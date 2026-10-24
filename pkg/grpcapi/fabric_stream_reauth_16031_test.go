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
	s := keyedServer(fabricTestKey)
	ctx := fabricStreamCtx16031([]byte(fabricTestKey), method)
	if err := s.fabricStreamRecheck(ctx, method); err != nil {
		t.Fatalf("valid open stream must recheck clean: %v", err)
	}
	removed := keyedServer("")
	if err := removed.fabricStreamRecheck(ctx, method); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("recheck after key removal must be Unauthenticated, got %v", err)
	}
	stranger := keyedServer("some-other-key-entirely")
	if err := stranger.fabricStreamRecheck(ctx, method); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("recheck under a stranger key must be Unauthenticated, got %v", err)
	}
}
