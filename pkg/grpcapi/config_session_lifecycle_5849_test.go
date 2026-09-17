package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/test/bufconn"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #5849: the config-lock / candidate session is a per-CONNECTION resource. It
// must be released only when the CONNECTION ends — never on a per-RPC
// cancellation — and keyed by an unguessable connection id, not the reusable
// peer address.

// newLifecycleTestServer spins a bufconn gRPC server mirroring the production
// loopback config-lock lifecycle (a configLockStatsHandler stats.Handler, no
// per-RPC interceptor). dial() opens a NEW client connection — a new connection
// id — on each call.
func newLifecycleTestServer(t *testing.T) (*Server, func(t *testing.T) (pb.BpfrxServiceClient, *grpc.ClientConn)) {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	s := &Server{
		store: store,
		addr:  "bufnet",
		peerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
			return authz.PeerIdentity{UID: 0, OK: true, Local: true}
		},
	}

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
		grpc.StatsHandler(&peerAuthStatsHandler{s: s}),
		grpc.StatsHandler(&configLockStatsHandler{s: s}),
	)
	pb.RegisterBpfrxServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	dial := func(t *testing.T) (pb.BpfrxServiceClient, *grpc.ClientConn) {
		t.Helper()
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			t.Fatalf("grpc.NewClient: %v", err)
		}
		return pb.NewBpfrxServiceClient(conn), conn
	}
	return s, dial
}

func waitCond5849(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// TestConfigLockStatsHandler_ReleasesExactlyOnceOnConnEnd_5849 pins the release
// contract of the lifecycle owner: a non-ConnEnd conn event and any per-RPC
// event do NOT release; ConnEnd releases EXACTLY once even if delivered twice
// (graceful drain + abrupt transport fault). [issue RED #3]
//
// FAIL-ON-REVERT: reverting to the per-RPC interceptor deletes
// configLockStatsHandler, so this test stops compiling.
func TestConfigLockStatsHandler_ReleasesExactlyOnceOnConnEnd_5849(t *testing.T) {
	var calls atomic.Int32
	h := &configLockStatsHandler{releaseFn: func(string) bool { calls.Add(1); return true }}
	ctx := h.TagConn(context.Background(), &stats.ConnTagInfo{})

	h.HandleConn(ctx, &stats.ConnBegin{})
	if got := calls.Load(); got != 0 {
		t.Fatalf("ConnBegin released the session; want 0 releases, got %d", got)
	}
	h.HandleRPC(ctx, &stats.End{})
	if got := calls.Load(); got != 0 {
		t.Fatalf("a per-RPC event released the session; want 0 releases, got %d", got)
	}
	h.HandleConn(ctx, &stats.ConnEnd{})
	h.HandleConn(ctx, &stats.ConnEnd{}) // duplicate ConnEnd must not double-release
	if got := calls.Load(); got != 1 {
		t.Fatalf("ConnEnd must release EXACTLY once (sync.Once guard); got %d", got)
	}
}

// TestConnSessionID_ConnScopedElseFallback_5849 pins the identity scheme: a
// tagged connection context returns an unguessable connection-scoped id, two
// connections get DISTINCT ids (a reused address cannot collide), and an
// untagged context falls back (empty here, no peer). [supports issue RED #4]
func TestConnSessionID_ConnScopedElseFallback_5849(t *testing.T) {
	h := &configLockStatsHandler{releaseFn: func(string) bool { return true }}

	ctx1 := h.TagConn(context.Background(), &stats.ConnTagInfo{})
	id1 := connSessionID(ctx1)
	if id1 == "" || !strings.HasPrefix(id1, "conn-") {
		t.Fatalf("connSessionID on a tagged connection = %q, want a non-empty conn- id", id1)
	}
	ctx2 := h.TagConn(context.Background(), &stats.ConnTagInfo{})
	if id2 := connSessionID(ctx2); id2 == id1 {
		t.Fatalf("two connections shared session id %q — a reused peer address must not collide (#5849)", id2)
	}
	if id := connSessionID(context.Background()); id != "" {
		t.Fatalf("untagged connSessionID = %q, want empty peer-fallback", id)
	}
}

// TestConfigSession_ReconnectSameAddrCannotInherit_5849 is the deterministic
// headline guard. Over bufconn EVERY connection shares one peer address, so
// address-keyed identity (the pre-#5849 scheme) would let a later connection
// INHERIT an earlier one's leaked config session. Connection 1 enters configure,
// stages an edit, then closes cleanly; connection 2 must see NO inherited
// session. [issue RED #4 + the headline #1 regression, via clean-close leak]
//
// FAIL-ON-REVERT: with the per-RPC interceptor + address keying, conn1's clean
// close (no in-flight RPC to cancel) leaves its session live under the shared
// address, so conn2 observes InConfigMode=true and the test fails.
func TestConfigSession_ReconnectSameAddrCannotInherit_5849(t *testing.T) {
	_, dial := newLifecycleTestServer(t)

	c1, conn1 := dial(t)
	if _, err := c1.EnterConfigure(context.Background(), &pb.EnterConfigureRequest{}); err != nil {
		t.Fatalf("conn1 EnterConfigure: %v", err)
	}
	if _, err := c1.Set(context.Background(), &pb.SetRequest{Input: "set system host-name conn1-edit"}); err != nil {
		t.Fatalf("conn1 Set: %v", err)
	}
	conn1.Close() // clean close → ConnEnd → releases conn1's session

	c2, conn2 := dial(t)
	defer conn2.Close()
	if !waitCond5849(3*time.Second, func() bool {
		st, err := c2.GetConfigModeStatus(context.Background(), &pb.GetConfigModeStatusRequest{})
		return err == nil && !st.InConfigMode && !st.Dirty
	}) {
		st, _ := c2.GetConfigModeStatus(context.Background(), &pb.GetConfigModeStatusRequest{})
		t.Fatalf("a reconnecting connection reusing the same peer address inherited the earlier "+
			"connection's config session (InConfigMode=%v Dirty=%v); #5849 keys the session by a "+
			"connection-scoped id and releases it on ConnEnd", st.GetInConfigMode(), st.GetDirty())
	}
}

// TestConfigSession_PerRPCCancelDoesNotTearDown_5849 pins the headline #5849
// regression: cancelling unrelated unary RPCs on a connection must NOT discard
// its staged candidate or release its lock — only ConnEnd does. [issue RED #1/#2]
//
// FAIL-ON-REVERT: the reverted per-RPC interceptor releases the session whenever
// a unary RPC returns with a cancelled context, so at least one of the cancelled
// probes below tears the session down and the surviving-edit assertion fails.
func TestConfigSession_PerRPCCancelDoesNotTearDown_5849(t *testing.T) {
	_, dial := newLifecycleTestServer(t)
	c, conn := dial(t)
	defer conn.Close()

	ctx := context.Background()
	if _, err := c.EnterConfigure(ctx, &pb.EnterConfigureRequest{}); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := c.Set(ctx, &pb.SetRequest{Input: "set system host-name conn-edit"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if st, err := c.GetConfigModeStatus(ctx, &pb.GetConfigModeStatusRequest{}); err != nil || !st.InConfigMode || !st.Dirty {
		t.Fatalf("precondition: InConfigMode/Dirty must be true, got %+v (err=%v)", st, err)
	}

	// Fire many unrelated unary RPCs whose per-RPC context is cancelled while in
	// flight. Under #5849 every one is a no-op for the session; under the
	// reverted interceptor at least one cancelled RPC releases the lock.
	for i := 0; i < 50; i++ {
		cctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(50 * time.Microsecond); cancel() }()
		_, _ = c.GetConfigModeStatus(cctx, &pb.GetConfigModeStatusRequest{})
		cancel()
	}

	st, err := c.GetConfigModeStatus(context.Background(), &pb.GetConfigModeStatusRequest{})
	if err != nil {
		t.Fatalf("GetConfigModeStatus after cancels: %v", err)
	}
	if !st.InConfigMode || !st.Dirty {
		t.Fatalf("per-RPC cancellation tore down the config session: InConfigMode=%v Dirty=%v, want both true (#5849)",
			st.InConfigMode, st.Dirty)
	}
}

// TestConfigSession_ExplicitExitImmediate_5849 confirms the explicit ExitConfigure
// backstop still releases the session immediately (keyed by the connection id).
// [issue RED #5]
func TestConfigSession_ExplicitExitImmediate_5849(t *testing.T) {
	_, dial := newLifecycleTestServer(t)
	c, conn := dial(t)
	defer conn.Close()

	ctx := context.Background()
	if _, err := c.EnterConfigure(ctx, &pb.EnterConfigureRequest{}); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := c.Set(ctx, &pb.SetRequest{Input: "set system host-name x"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := c.ExitConfigure(ctx, &pb.ExitConfigureRequest{}); err != nil {
		t.Fatalf("ExitConfigure: %v", err)
	}
	st, err := c.GetConfigModeStatus(ctx, &pb.GetConfigModeStatusRequest{})
	if err != nil {
		t.Fatalf("GetConfigModeStatus: %v", err)
	}
	if st.InConfigMode || st.Dirty {
		t.Fatalf("explicit ExitConfigure did not immediately release the session: InConfigMode=%v Dirty=%v",
			st.InConfigMode, st.Dirty)
	}
}
