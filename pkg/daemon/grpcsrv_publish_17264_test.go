package daemon

import (
	"context"
	"github.com/psaab/xpf/internal/testguard"
	"github.com/psaab/xpf/pkg/grpcapi"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const grpcFabricAddr17264 = "127.0.0.1:50051"

func newGRPCSrvPublishServer17264(t *testing.T) *grpcapi.Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config"))
	return grpcapi.NewServer("", grpcapi.Config{Store: store})
}

func waitGRPCFabricListener17264(t *testing.T, srv *grpcapi.Server) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if srv.FabricListenerUp(grpcFabricAddr17264) {
			conn, err := net.DialTimeout("tcp", grpcFabricAddr17264, time.Second)
			if err == nil {
				_ = conn.Close()
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("fabric gRPC listener %q did not become reachable", grpcFabricAddr17264)
}

func cancelGRPCFabricListener17264(t *testing.T, cancel context.CancelFunc, srv *grpcapi.Server) {
	t.Helper()
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !srv.FabricListenerUp(grpcFabricAddr17264) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("fabric gRPC listener %q stayed up after context cancellation", grpcFabricAddr17264)
}

// TestQ53GRPCSrvPollRace is class N (netns-kernel): it starts and dials a
// loopback listener in the testguard network namespace.
func TestQ53GRPCSrvPollRace(t *testing.T) {
	testguard.RequireDisposable(t)
	ensureLoopbackForSyncPair12210(t)
	d := &Daemon{}
	srv := newGRPCSrvPublishServer17264(t)
	commsCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancelGRPCFabricListener17264(t, cancel, srv) })

	d.startFabricGRPCListeners(commsCtx, "127.0.0.1", "", func() string { return "" })

	const readers = 8
	stopReaders := make(chan struct{})
	readersStarted := make(chan struct{}, readers)
	var readersWG sync.WaitGroup
	readersWG.Add(readers)
	defer func() {
		close(stopReaders)
		readersWG.Wait()
	}()
	for range readers {
		go func() {
			defer readersWG.Done()
			_ = d.loadGRPCSrv()
			readersStarted <- struct{}{}
			for {
				select {
				case <-stopReaders:
					return
				default:
					_ = d.loadGRPCSrv()
				}
			}
		}()
	}
	for range readers {
		<-readersStarted
	}

	publish := make(chan struct{})
	published := make(chan struct{})
	go func() {
		<-publish
		d.publishGRPCSrv(srv)
		close(published)
	}()
	close(publish)
	select {
	case <-published:
	case <-time.After(5 * time.Second):
		t.Fatal("gRPC server publication did not complete")
	}
	waitGRPCFabricListener17264(t, srv)
}

func TestGRPCSrvPublishWakesWaiter17264(t *testing.T) {
	d := &Daemon{}
	want := newGRPCSrvPublishServer17264(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		srv *grpcapi.Server
		ok  bool
	}
	got := make(chan result, 1)
	go func() {
		srv, ok := d.awaitGRPCSrv(ctx)
		got <- result{srv: srv, ok: ok}
	}()
	select {
	case r := <-got:
		t.Fatalf("waiter returned before publication: srv=%p ok=%v", r.srv, r.ok)
	case <-time.After(25 * time.Millisecond):
	}

	d.publishGRPCSrv(want)
	select {
	case r := <-got:
		if !r.ok || r.srv != want {
			t.Fatalf("awaitGRPCSrv() = (%p, %v), want (%p, true)", r.srv, r.ok, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not wake after gRPC server publication")
	}
}

func TestGRPCSrvCancelBeforeReadyExits17264(t *testing.T) {
	d := &Daemon{}
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan struct {
		srv *grpcapi.Server
		ok  bool
	}, 1)
	go func() {
		srv, ok := d.awaitGRPCSrv(ctx)
		got <- struct {
			srv *grpcapi.Server
			ok  bool
		}{srv: srv, ok: ok}
	}()
	cancel()
	select {
	case r := <-got:
		if r.srv != nil || r.ok {
			t.Fatalf("awaitGRPCSrv() after cancellation = (%p, %v), want (nil, false)", r.srv, r.ok)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("awaitGRPCSrv did not return after context cancellation")
	}
}

func TestGRPCSrvNilPublishDoesNotWake17264(t *testing.T) {
	d := &Daemon{}
	ready := d.grpcReadyChan()
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan struct {
		srv *grpcapi.Server
		ok  bool
	}, 1)
	waiterDone := make(chan struct{})
	go func() {
		defer close(waiterDone)
		srv, ok := d.awaitGRPCSrv(ctx)
		got <- struct {
			srv *grpcapi.Server
			ok  bool
		}{srv: srv, ok: ok}
	}()
	defer func() {
		cancel()
		select {
		case <-waiterDone:
		case <-time.After(2 * time.Second):
			t.Error("waiter did not exit during cleanup")
		}
	}()

	d.publishGRPCSrv(nil)
	if srv := d.loadGRPCSrv(); srv != nil {
		t.Fatalf("nil publication stored server %p", srv)
	}
	select {
	case <-ready:
		t.Fatal("nil publication closed the ready channel")
	case <-got:
		t.Fatal("nil publication woke the waiter")
	case <-time.After(25 * time.Millisecond):
	}
	cancel()
	select {
	case r := <-got:
		if r.srv != nil || r.ok {
			t.Fatalf("awaitGRPCSrv() after nil publication and cancellation = (%p, %v), want (nil, false)", r.srv, r.ok)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not return after cancellation following nil publication")
	}
}

// TestGRPCSrvDelayedReadyBeyond30sStartsListener17264 is class N
// (netns-kernel): it starts and dials a real loopback listener.
func TestGRPCSrvDelayedReadyBeyond30sStartsListener17264(t *testing.T) {
	testguard.RequireDisposable(t)
	ensureLoopbackForSyncPair12210(t)
	d := &Daemon{}
	srv := newGRPCSrvPublishServer17264(t)
	commsCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancelGRPCFabricListener17264(t, cancel, srv) })

	started := time.Now()
	d.startFabricGRPCListeners(commsCtx, "127.0.0.1", "", func() string { return "" })
	time.Sleep(35 * time.Second)
	if elapsed := time.Since(started); elapsed <= 30*time.Second {
		t.Fatalf("unpublished listener wait lasted %s, want more than 30s", elapsed)
	}
	if d.loadGRPCSrv() != nil {
		t.Fatal("gRPC server was published before the delayed-publication point")
	}
	if srv.FabricListenerUp(grpcFabricAddr17264) {
		t.Fatal("fabric listener started before gRPC server publication")
	}

	d.publishGRPCSrv(srv)
	waitGRPCFabricListener17264(t, srv)
}
