package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// #9891: MonitorInterface was the one monitor stream with no subscriber budget
// and no send deadline — a 1s ticker, an unbounded for loop, and a blocking
// stream.Send with no admission gate. Sibling MonitorPacketDrop refuses past
// its EventBuffer cap and Ping/Traceroute refuse past diagLimiter; this one
// admitted without limit and a slow consumer parked its goroutine.

// capMonitorStream9891 is a MonitorInterface server stream that records frames
// and stays alive until its context is cancelled, holding its subscriber slot.
type capMonitorStream9891 struct {
	ctx    context.Context
	cancel context.CancelFunc
	frames atomic.Int64
}

func (m *capMonitorStream9891) Send(*pb.MonitorInterfaceResponse) error {
	m.frames.Add(1)
	return nil
}
func (m *capMonitorStream9891) Context() context.Context     { return m.ctx }
func (m *capMonitorStream9891) SetHeader(metadata.MD) error  { return nil }
func (m *capMonitorStream9891) SendHeader(metadata.MD) error { return nil }
func (m *capMonitorStream9891) SetTrailer(metadata.MD)       {}
func (m *capMonitorStream9891) SendMsg(any) error            { return nil }
func (m *capMonitorStream9891) RecvMsg(any) error            { return nil }

func monitorBudgetStore9891(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride("system { host-name fw; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Server{store: store, dp: &fanoutStatusDP{}}
}

func waitForFrames9891(t *testing.T, streams []*capMonitorStream9891, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok := true
		for _, st := range streams {
			if st.frames.Load() < want {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			counts := make([]int64, len(streams))
			for i, st := range streams {
				counts[i] = st.frames.Load()
			}
			t.Fatalf("streams did not reach %d frames within %v: %v", want, timeout, counts)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestMonitorInterfaceRejectsOverCap_9891 pins the #9891 admission cap: with a
// 3-slot budget, 4 concurrent subscribers admit 3 and refuse the 4th with
// ResourceExhausted (0 frames, no ticker, no goroutine held), while the
// admitted 3 keep receiving across a tick boundary.
//
// FAIL-ON-REVERT: removing the Acquire branch admits the 4th — it emits a
// frame instead of returning ResourceExhausted — so the refusal assertion
// fires RED.
func TestMonitorInterfaceRejectsOverCap_9891(t *testing.T) {
	orig := monitorInterfaceLimiter
	monitorInterfaceLimiter = diagcmd.NewLimiter(3)
	t.Cleanup(func() { monitorInterfaceLimiter = orig })

	s := monitorBudgetStore9891(t)

	const admitted, total = 3, 4
	streams := make([]*capMonitorStream9891, total)
	errc := make([]chan error, total)
	for i := range streams {
		ctx, cancel := context.WithCancel(context.Background())
		streams[i] = &capMonitorStream9891{ctx: ctx, cancel: cancel}
		errc[i] = make(chan error, 1)
		go func(idx int) {
			errc[idx] <- s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "lo"}, streams[idx])
		}(i)
	}
	refusedIdx := -1
	defer func() {
		for _, st := range streams {
			st.cancel()
		}
		for i := range errc {
			if i == refusedIdx {
				continue
			}
			select {
			case <-errc[i]:
			case <-time.After(5 * time.Second):
				t.Errorf("stream %d did not exit after cancel", i)
			}
		}
	}()

	// The 4th must be refused fail-fast. It returns ResourceExhausted without
	// emitting; the admitted 3 stay in the tick loop (no error yet).
	deadline := time.Now().Add(5 * time.Second)
	for refusedIdx < 0 && time.Now().Before(deadline) {
		for i := range errc {
			select {
			case err := <-errc[i]:
				if status.Code(err) != codes.ResourceExhausted {
					t.Fatalf("stream %d over-cap err = %v, want ResourceExhausted", i, err)
				}
				if got := streams[i].frames.Load(); got != 0 {
					t.Fatalf("refused stream %d emitted %d frames, want 0 (refusal must precede the ticker)", i, got)
				}
				refusedIdx = i
			default:
			}
		}
		if refusedIdx < 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if refusedIdx < 0 {
		t.Fatal("no stream was refused past the 3-slot cap (the N+1th was admitted → unbounded)")
	}

	// The admitted 3 keep receiving: first frame immediately, second past the
	// 1s tick.
	var live []*capMonitorStream9891
	for i, st := range streams {
		if i != refusedIdx {
			live = append(live, st)
		}
	}
	if len(live) != admitted {
		t.Fatalf("live streams = %d, want %d", len(live), admitted)
	}
	waitForFrames9891(t, live, 1, 5*time.Second)
	waitForFrames9891(t, live, 2, 5*time.Second)

	if got := monitorInterfaceLimiter.InFlight(); got != admitted {
		t.Fatalf("InFlight while held = %d, want %d", got, admitted)
	}
}

// TestMonitorInterfaceTeardownFreesSlot_9891 proves the `defer release()`
// returns the subscriber slot: an admitted stream holds the only slot (a probe
// acquire fails), and once its context is cancelled the probe succeeds.
func TestMonitorInterfaceTeardownFreesSlot_9891(t *testing.T) {
	orig := monitorInterfaceLimiter
	monitorInterfaceLimiter = diagcmd.NewLimiter(1)
	t.Cleanup(func() { monitorInterfaceLimiter = orig })

	s := monitorBudgetStore9891(t)
	ctx, cancel := context.WithCancel(context.Background())
	st := &capMonitorStream9891{ctx: ctx, cancel: cancel}
	errc := make(chan error, 1)
	go func() {
		errc <- s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "lo"}, st)
	}()

	waitForFrames9891(t, []*capMonitorStream9891{st}, 1, 5*time.Second)

	if _, err := monitorInterfaceLimiter.Acquire(); err == nil {
		t.Fatal("probe acquire succeeded while a stream holds the only slot (the stream is not holding admission)")
	}

	cancel()
	select {
	case err := <-errc:
		if err != context.Canceled {
			t.Fatalf("teardown err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not exit after cancel")
	}

	release, err := monitorInterfaceLimiter.Acquire()
	if err != nil {
		t.Fatalf("probe acquire after teardown failed: %v (the slot leaked)", err)
	}
	release()
	if got := monitorInterfaceLimiter.InFlight(); got != 0 {
		t.Fatalf("InFlight after drain = %d, want 0", got)
	}
}

// blockingMonitorStream9891 parks its writer exactly as a full socket buffer
// does: Send blocks until the stream context is done, or forever if the
// handler never returns. calls counts Send entries; exits counts Send returns,
// so a test can prove the Send worker exited (not just that the handler did).
type blockingMonitorStream9891 struct {
	ctx   context.Context
	calls atomic.Int64
	exits atomic.Int64
}

func (m *blockingMonitorStream9891) Send(*pb.MonitorInterfaceResponse) error {
	m.calls.Add(1)
	defer m.exits.Add(1)
	<-m.ctx.Done()
	return m.ctx.Err()
}
func (m *blockingMonitorStream9891) Context() context.Context     { return m.ctx }
func (m *blockingMonitorStream9891) SetHeader(metadata.MD) error  { return nil }
func (m *blockingMonitorStream9891) SendHeader(metadata.MD) error { return nil }
func (m *blockingMonitorStream9891) SetTrailer(metadata.MD)       {}
func (m *blockingMonitorStream9891) SendMsg(any) error            { return nil }
func (m *blockingMonitorStream9891) RecvMsg(any) error            { return nil }

// TestMonitorInterfaceSlowConsumerTimesOut_9891 pins the per-write send bound
// AND its slot transfer: a consumer whose Send never completes must not park
// the handler goroutine past the deadline, and the timed-out slot must move to
// the Send worker (retained, bounded) rather than freeing while the worker
// stays parked (retained, unbounded). With a compressed 200ms budget the RPC
// returns DeadlineExceeded promptly; at that point InFlight is still 1 (the
// worker holds the transferred slot, exits==0 proves it is still parked).
// Cancelling then unblocks Send, the worker exits and releases, and a probe
// acquire succeeds — error-path release EXECUTED (slot refills), not inspected.
//
// FAIL-ON-REVERT: sending via bare stream.Send blocks until ctx cancel — with
// no test cancel armed before the handler return the handler never returns and
// this cell times out RED. Dropping the transfer (immediate release on timeout)
// makes the InFlight==1 assertion fail RED (0 while the worker is still parked).
func TestMonitorInterfaceSlowConsumerTimesOut_9891(t *testing.T) {
	origTimeout := monitorInterfaceSendTimeout
	monitorInterfaceSendTimeout = 200 * time.Millisecond
	t.Cleanup(func() { monitorInterfaceSendTimeout = origTimeout })

	origLim := monitorInterfaceLimiter
	monitorInterfaceLimiter = diagcmd.NewLimiter(4)
	t.Cleanup(func() { monitorInterfaceLimiter = origLim })

	s := monitorBudgetStore9891(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &blockingMonitorStream9891{ctx: ctx}

	start := time.Now()
	err := s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "lo"}, st)
	elapsed := time.Since(start)

	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("slow-consumer err = %v, want DeadlineExceeded (err=%v)", status.Code(err), err)
	}
	if st.calls.Load() < 1 {
		t.Fatal("slow-consumer stream never reached Send, so this proves nothing about the send bound")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("slow-consumer Send parked the handler for %v (no send deadline)", elapsed)
	}
	t.Logf("slow consumer handler severed after %v (budget %v)", elapsed, monitorInterfaceSendTimeout)

	if got := st.exits.Load(); got != 0 {
		t.Fatalf("Send exits at handler return = %d, want 0 (the worker must still be parked in Send)", got)
	}
	if got := monitorInterfaceLimiter.InFlight(); got != 1 {
		t.Fatalf("InFlight at handler return = %d, want 1 (the timed-out slot transfers to the parked worker, not freed)", got)
	}

	cancel()
	waitForExits9891(t, st, 1, 5*time.Second)
	waitForInFlight9891(t, 0, 5*time.Second)
	release, err := monitorInterfaceLimiter.Acquire()
	if err != nil {
		t.Fatalf("probe acquire after worker exit failed: %v (the transferred slot leaked)", err)
	}
	release()
}

func waitForExits9891(t *testing.T, st *blockingMonitorStream9891, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for st.exits.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("Send exits = %d, want >= %d within %v (the worker never exited)", st.exits.Load(), want, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForInFlight9891(t *testing.T, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for monitorInterfaceLimiter.InFlight() != want {
		if time.Now().After(deadline) {
			t.Fatalf("InFlight = %d, want %d within %v", monitorInterfaceLimiter.InFlight(), want, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestMonitorInterfaceLimiterIsSharedInstance_9891 restates the premise the
// budget rests on: the gRPC alias points at the process-wide limiter, so the
// documented cap and the metrics registry observe the same instance.
func TestMonitorInterfaceLimiterIsSharedInstance_9891(t *testing.T) {
	if monitorInterfaceLimiter != diagcmd.MonitorInterfaceLimiter {
		t.Fatal("monitorInterfaceLimiter is not diagcmd.MonitorInterfaceLimiter; admission draws on an undocumented budget")
	}
	if diagcmd.MonitorInterfaceLimiter.Cap() != diagcmd.MaxConcurrentMonitorInterfaceStreams {
		t.Fatalf("MonitorInterfaceLimiter cap = %d, want MaxConcurrentMonitorInterfaceStreams = %d",
			diagcmd.MonitorInterfaceLimiter.Cap(), diagcmd.MaxConcurrentMonitorInterfaceStreams)
	}
	if diagcmd.MaxConcurrentMonitorInterfaceStreams != 64 {
		t.Fatalf("MaxConcurrentMonitorInterfaceStreams = %d, want 64 (the sibling EventBuffer streaming budget)", diagcmd.MaxConcurrentMonitorInterfaceStreams)
	}
	var found bool
	for _, nl := range diagcmd.AllLimiters() {
		if nl.Name == "monitor_interface" && nl.Limiter == diagcmd.MonitorInterfaceLimiter {
			found = true
		}
	}
	if !found {
		t.Fatal("monitor_interface missing from diagcmd.AllLimiters(); its refusals are unexported")
	}
}

// TestMonitorInterfaceValidationCostsNoSlot_9891 is the negative control: a
// NotFound validation failure must not consume admission. With the only slot
// held, a request for an unknown interface still returns NotFound rather than
// ResourceExhausted — the bound is taken after validation, not at the handler.
func TestMonitorInterfaceValidationCostsNoSlot_9891(t *testing.T) {
	orig := monitorInterfaceLimiter
	monitorInterfaceLimiter = diagcmd.NewLimiter(1)
	t.Cleanup(func() { monitorInterfaceLimiter = orig })

	release, err := monitorInterfaceLimiter.Acquire()
	if err != nil {
		t.Fatalf("pre-acquire: %v", err)
	}
	defer release()

	s := monitorBudgetStore9891(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &capMonitorStream9891{ctx: ctx, cancel: cancel}
	err = s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "ge-9/9/9-nonexistent"}, st)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown-interface with saturated limiter code = %v, want NotFound (validation must not take a slot); err=%v", status.Code(err), err)
	}
}

// stalledPeerStream9891 never produces a frame: Recv blocks until ctx done,
// exactly as a wedged peer does.
type stalledPeerStream9891 struct {
	ctx   context.Context
	calls atomic.Int64
	exits atomic.Int64
}

func (m *stalledPeerStream9891) Recv() (*pb.MonitorInterfaceResponse, error) {
	m.calls.Add(1)
	defer m.exits.Add(1)
	<-m.ctx.Done()
	return nil, m.ctx.Err()
}

// TestMonitorInterfacePeerStallTimesOut_9891 pins the proxy Recv bound: a peer
// that never sends must not park the proxy in Recv past the idle timeout.
// With a compressed 200ms budget the helper returns Unavailable promptly.
//
// FAIL-ON-REVERT: bare peerStream.Recv() blocks until ctx cancel — with no
// cancel armed the helper never returns and this cell times out RED.
func TestMonitorInterfacePeerStallTimesOut_9891(t *testing.T) {
	orig := monitorInterfacePeerIdleTimeout
	monitorInterfacePeerIdleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { monitorInterfacePeerIdleTimeout = orig })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer := &stalledPeerStream9891{ctx: ctx}

	start := time.Now()
	resp, err := recvMonitorInterfaceFrame(peer, ctx)
	elapsed := time.Since(start)

	if resp != nil {
		t.Fatalf("stalled Recv resp = %+v, want nil", resp)
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("stalled Recv code = %v, want Unavailable (err=%v)", status.Code(err), err)
	}
	if peer.calls.Load() < 1 {
		t.Fatal("stalled Recv never reached the peer, so this proves nothing about the idle bound")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("stalled Recv parked for %v (no peer-idle bound)", elapsed)
	}
	t.Logf("stalled peer severed after %v (budget %v)", elapsed, monitorInterfacePeerIdleTimeout)

	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for peer.exits.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if peer.exits.Load() < 1 {
		t.Fatal("Recv worker never exited after cancel (leaked)")
	}
}

// oneShotPeerStream9891 returns a single frame then stalls; it proves the Recv
// helper passes success through without tripping the idle bound.
type oneShotPeerStream9891 struct {
	frame string
	n     atomic.Int64
}

func (m *oneShotPeerStream9891) Recv() (*pb.MonitorInterfaceResponse, error) {
	if m.n.Add(1) == 1 {
		return &pb.MonitorInterfaceResponse{Frame: m.frame}, nil
	}
	select {}
}

func TestMonitorInterfacePeerRecvSuccessPassesThrough_9891(t *testing.T) {
	orig := monitorInterfacePeerIdleTimeout
	monitorInterfacePeerIdleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { monitorInterfacePeerIdleTimeout = orig })

	peer := &oneShotPeerStream9891{frame: "ok"}
	resp, err := recvMonitorInterfaceFrame(peer, context.Background())
	if err != nil {
		t.Fatalf("healthy Recv err = %v, want nil", err)
	}
	if resp.GetFrame() != "ok" {
		t.Fatalf("healthy Recv frame = %q, want ok", resp.GetFrame())
	}
}

func monitorProxyStore9891(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("set chassis cluster cluster-id 1\n" +
		"set chassis cluster authentication-key test-psk-9891-test-psk-9891\n" +
		"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
		"set chassis cluster redundancy-group 1 interface-monitor ge-7/0/1 weight 100\n" +
		"set system host-name fw\n"); err != nil {
		t.Fatalf("LoadSet cluster: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil || len(cfg.Chassis.Cluster.RedundancyGroups) != 1 {
		t.Fatalf("cluster config did not compile an RG: %+v", cfg)
	}
	return &Server{store: store, dp: &fanoutStatusDP{}}
}

// TestMonitorInterfaceProxyAdmissionPrecedesDial_9891 pins acquire-before-dial
// on the proxy path: a refused subscriber must not dial the peer, while an
// admitted one does. ge-7/0/1 exists in no local netdev but is named in the
// RG monitors, so decideMonitorProxy routes it to the peer; fabricPeerAddrFn
// counts dials and returns empty so dialPeer fails fast without a network dial.
//
// FAIL-ON-REVERT: moving the Acquire after the proxy dispatch (or dialling
// before acquiring) makes the refused call dial — dials==1 while refused —
// so the zero-dial assertion fires RED.
func TestMonitorInterfaceProxyAdmissionPrecedesDial_9891(t *testing.T) {
	orig := monitorInterfaceLimiter
	monitorInterfaceLimiter = diagcmd.NewLimiter(1)
	t.Cleanup(func() { monitorInterfaceLimiter = orig })

	s := monitorProxyStore9891(t)
	var dials atomic.Int64
	s.fabricPeerAddrFn = func() []string {
		dials.Add(1)
		return nil
	}

	hold, err := monitorInterfaceLimiter.Acquire()
	if err != nil {
		t.Fatalf("pre-acquire: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &capMonitorStream9891{ctx: ctx, cancel: cancel}
	err = s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "ge-7/0/1"}, st)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("saturated proxy code = %v, want ResourceExhausted (err=%v)", status.Code(err), err)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("refused proxy dialled %d times, want 0 (acquire must precede dial)", got)
	}
	if got := st.frames.Load(); got != 0 {
		t.Fatalf("refused proxy emitted %d frames, want 0", got)
	}
	hold()

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	st2 := &capMonitorStream9891{ctx: ctx2, cancel: cancel2}
	err = s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "ge-7/0/1"}, st2)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("admitted proxy code = %v, want Unavailable (empty peer addrs, dial attempted); err=%v", status.Code(err), err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("admitted proxy dials = %d, want 1 (the slot must admit the dial)", got)
	}
}

// TestMonitorInterfaceSlowDoesNotHeadOfLineHealthy_9891 pins contention
// behavior: while one subscriber sits in its timed-out Send (worker parked,
// slot transferred), a healthy subscriber on the same budget keeps receiving
// across the tick boundary. Slow severs with DeadlineExceeded; healthy reaches
// 2 frames before slow is cancelled.
func TestMonitorInterfaceSlowDoesNotHeadOfLineHealthy_9891(t *testing.T) {
	origTimeout := monitorInterfaceSendTimeout
	monitorInterfaceSendTimeout = 200 * time.Millisecond
	t.Cleanup(func() { monitorInterfaceSendTimeout = origTimeout })

	origLim := monitorInterfaceLimiter
	monitorInterfaceLimiter = diagcmd.NewLimiter(2)
	t.Cleanup(func() { monitorInterfaceLimiter = origLim })

	s := monitorBudgetStore9891(t)

	slowCtx, slowCancel := context.WithCancel(context.Background())
	defer slowCancel()
	slow := &blockingMonitorStream9891{ctx: slowCtx}
	slowErrc := make(chan error, 1)
	go func() {
		slowErrc <- s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "lo"}, slow)
	}()

	healthyCtx, healthyCancel := context.WithCancel(context.Background())
	defer healthyCancel()
	healthy := &capMonitorStream9891{ctx: healthyCtx, cancel: healthyCancel}
	healthyErrc := make(chan error, 1)
	go func() {
		healthyErrc <- s.MonitorInterface(&pb.MonitorInterfaceRequest{InterfaceName: "lo"}, healthy)
	}()

	select {
	case err := <-slowErrc:
		if status.Code(err) != codes.DeadlineExceeded {
			healthyCancel()
			<-healthyErrc
			t.Fatalf("slow err = %v, want DeadlineExceeded (err=%v)", status.Code(err), err)
		}
	case <-time.After(5 * time.Second):
		healthyCancel()
		<-healthyErrc
		t.Fatal("slow handler never severed (no send deadline under contention)")
	}
	if slow.calls.Load() < 1 {
		t.Fatal("slow stream never reached Send, so this proves nothing about contention")
	}
	if got := slow.exits.Load(); got != 0 {
		t.Fatalf("slow Send exits = %d, want 0 (worker still parked while healthy receives)", got)
	}
	if got := monitorInterfaceLimiter.InFlight(); got != 2 {
		t.Fatalf("InFlight under contention = %d, want 2 (slow worker transferred + healthy active)", got)
	}

	waitForFrames9891(t, []*capMonitorStream9891{healthy}, 2, 5*time.Second)

	slowCancel()
	waitForExits9891(t, slow, 1, 5*time.Second)
	waitForInFlight9891(t, 1, 5*time.Second)

	healthyCancel()
	select {
	case err := <-healthyErrc:
		if err != context.Canceled {
			t.Fatalf("healthy teardown err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("healthy stream did not exit after cancel")
	}
	waitForInFlight9891(t, 0, 5*time.Second)
}

// immediateMonitorStream9891 succeeds every Send without blocking: with a zero
// send budget the worker publishes success just as the timer fires, so each
// call races completion against the timeout and exercises the boundary.
type immediateMonitorStream9891 struct {
	ctx context.Context
}

func (m *immediateMonitorStream9891) Send(*pb.MonitorInterfaceResponse) error { return nil }
func (m *immediateMonitorStream9891) Context() context.Context                { return m.ctx }
func (m *immediateMonitorStream9891) SetHeader(metadata.MD) error             { return nil }
func (m *immediateMonitorStream9891) SendHeader(metadata.MD) error            { return nil }
func (m *immediateMonitorStream9891) SetTrailer(metadata.MD)                  {}
func (m *immediateMonitorStream9891) SendMsg(any) error                       { return nil }
func (m *immediateMonitorStream9891) RecvMsg(any) error                       { return nil }

// TestSendBoundaryContinuationHoldsAdmission_9891 pins the GPT-1 ownership
// invariant on both deterministic paths: a stream that CONTINUES (nil, false)
// always holds its slot (InFlight==1, probe fails), and a severed
// (transferred) stream always frees it (InFlight drains to 0, probe
// succeeds). Phase 1 uses a zero budget (timer always wins → all severed,
// 500 trials prove no leak at scale); phase 2 uses a long budget with an
// immediate Send (completion always wins → all continued, each holding
// admission). The exact timer-wins-with-done-ready interleaving is pinned
// deterministically by TestSendBoundarySeversOnConcurrentSuccess_9891 via the
// Store-to-drain seam; together they cover the handoff with no timing luck.
//
// FAIL-ON-REVERT: restoring `return err, false` on the timer-with-done path
// is caught by the seam test below (continued-without-slot fires RED there).
func TestSendBoundaryContinuationHoldsAdmission_9891(t *testing.T) {
	lim := diagcmd.NewLimiter(1)
	ctx := context.Background()
	st := &immediateMonitorStream9891{ctx: ctx}
	resp := &pb.MonitorInterfaceResponse{Frame: "x"}

	t.Run("severedFrees", func(t *testing.T) {
		origTimeout := monitorInterfaceSendTimeout
		monitorInterfaceSendTimeout = 0
		t.Cleanup(func() { monitorInterfaceSendTimeout = origTimeout })

		for i := range 500 {
			release, err := lim.Acquire()
			if err != nil {
				t.Fatalf("iter %d: acquire: %v (a leaked slot from a prior iter)", i, err)
			}
			sendErr, xfer := sendMonitorInterfaceFrame(st, resp, release)
			if sendErr == nil && !xfer {
				// Completion won despite the zero budget: continuation
				// must hold the slot.
				if got := lim.InFlight(); got != 1 {
					release()
					t.Fatalf("iter %d: continued stream InFlight = %d, want 1 (continuation without admission defeats the cap)", i, got)
				}
				release()
				continue
			}
			if !xfer {
				release()
				t.Fatalf("iter %d: unexpected (err=%v, xfer=false) with an always-succeeding Send", i, sendErr)
			}
			// Severed: transferred, so the caller must not release. The
			// worker frees it as the immediate Send completes — poll for
			// the drain (no timing assumption), then prove no leak.
			deadline := time.Now().Add(5 * time.Second)
			for lim.InFlight() != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := lim.InFlight(); got != 0 {
				t.Fatalf("iter %d: severed InFlight = %d, want 0 (slot leaked)", i, got)
			}
			if probe, perr := lim.Acquire(); perr != nil {
				t.Fatalf("iter %d: probe acquire after severed: %v (slot leaked)", i, perr)
			} else {
				probe()
			}
			if got := lim.InFlight(); got != 0 {
				t.Fatalf("iter %d: end-of-iter InFlight = %d, want 0", i, got)
			}
		}
	})

	t.Run("continuedHolds", func(t *testing.T) {
		origTimeout := monitorInterfaceSendTimeout
		monitorInterfaceSendTimeout = 30 * time.Second
		t.Cleanup(func() { monitorInterfaceSendTimeout = origTimeout })

		for i := range 100 {
			release, err := lim.Acquire()
			if err != nil {
				t.Fatalf("iter %d: acquire: %v", i, err)
			}
			sendErr, xfer := sendMonitorInterfaceFrame(st, resp, release)
			if sendErr != nil || xfer {
				if xfer {
					deadline := time.Now().Add(5 * time.Second)
					for lim.InFlight() != 0 && time.Now().Before(deadline) {
						time.Sleep(time.Millisecond)
					}
				} else {
					release()
				}
				t.Fatalf("iter %d: fast Send with a long budget returned (err=%v, xfer=%v), want (nil, false)", i, sendErr, xfer)
			}
			if got := lim.InFlight(); got != 1 {
				release()
				t.Fatalf("iter %d: continued stream InFlight = %d, want 1 (continuation must hold admission)", i, got)
			}
			if probe, perr := lim.Acquire(); perr == nil {
				probe()
				release()
				t.Fatalf("iter %d: continued stream's slot acquirable — it holds no admission", i)
			}
			release()
		}
	})
}

// delayedSuccessStream9891 succeeds its Send after delay: with the
// Store-to-drain seam widened past the delay, the completion lands inside the
// timer branch deterministically, pinning the exact boundary interleaving.
type delayedSuccessStream9891 struct {
	ctx   context.Context
	delay time.Duration
}

func (m *delayedSuccessStream9891) Send(*pb.MonitorInterfaceResponse) error {
	time.Sleep(m.delay)
	return nil
}
func (m *delayedSuccessStream9891) Context() context.Context     { return m.ctx }
func (m *delayedSuccessStream9891) SetHeader(metadata.MD) error  { return nil }
func (m *delayedSuccessStream9891) SendHeader(metadata.MD) error { return nil }
func (m *delayedSuccessStream9891) SetTrailer(metadata.MD)       {}
func (m *delayedSuccessStream9891) SendMsg(any) error            { return nil }
func (m *delayedSuccessStream9891) RecvMsg(any) error            { return nil }

// TestSendBoundarySeversOnConcurrentSuccess_9891 pins the GPT-1 boundary
// DETERMINISTICALLY: the timer wins (zero budget) while Send succeeds 10ms
// later, landing inside the 200ms Store-to-drain seam window — so the inner
// drain finds done ready with nil. The fixed handoff severs anyway
// (DeadlineExceeded, transferred): the worker owns the release via the flag,
// so continuing would run without admission. The test asserts sever + slot
// freed with no leak, and would assert continued-holds if the handoff ever
// continued — it must never continue here.
//
// FAIL-ON-REVERT: restoring `return err, false` on the timer-with-done path
// returns (nil, false) with InFlight==0 — the continued-without-slot
// assertion fires RED, deterministically, on every run.
func TestSendBoundarySeversOnConcurrentSuccess_9891(t *testing.T) {
	origTimeout := monitorInterfaceSendTimeout
	monitorInterfaceSendTimeout = 0
	t.Cleanup(func() { monitorInterfaceSendTimeout = origTimeout })

	origSeam := sendBoundaryDelay9891
	sendBoundaryDelay9891 = 200 * time.Millisecond
	t.Cleanup(func() { sendBoundaryDelay9891 = origSeam })

	lim := diagcmd.NewLimiter(1)
	ctx := context.Background()
	st := &delayedSuccessStream9891{ctx: ctx, delay: 10 * time.Millisecond}
	resp := &pb.MonitorInterfaceResponse{Frame: "x"}

	release, err := lim.Acquire()
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	sendErr, xfer := sendMonitorInterfaceFrame(st, resp, release)
	if sendErr == nil && !xfer {
		if got := lim.InFlight(); got != 1 {
			release()
			t.Fatalf("boundary continued with InFlight = %d, want 1 (continuation without admission defeats the cap)", got)
		}
		release()
		t.Fatal("boundary continued (nil, false) — timeout ownership must be terminal, sever even on concurrent success")
	}
	if !xfer {
		release()
		t.Fatalf("boundary returned (err=%v, xfer=false), want severed with transfer", sendErr)
	}
	if status.Code(sendErr) != codes.DeadlineExceeded {
		t.Fatalf("boundary err code = %v, want DeadlineExceeded (err=%v)", status.Code(sendErr), sendErr)
	}
	// Transferred: the boundary releases synchronously (Send completed), so
	// InFlight is already 0 — but poll briefly to tolerate the worker's own
	// release racing the handler's (idempotent either way).
	deadline := time.Now().Add(5 * time.Second)
	for lim.InFlight() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := lim.InFlight(); got != 0 {
		t.Fatalf("boundary InFlight = %d, want 0 (slot leaked)", got)
	}
	if probe, perr := lim.Acquire(); perr != nil {
		t.Fatalf("probe acquire after boundary: %v (slot leaked)", perr)
	} else {
		probe()
	}
}

// TestMonitorInterfacePeerEstablishmentBound_9891 pins the GPT-3 fix: a peer
// that never grants stream quota (wedged NewStream) must not pin the proxy's
// slot past the establishment budget, while a healthy establishment must not
// be lifetime-limited by it. Phase 1 drives a NewStream that blocks until ctx
// done (exactly as the http2_client quota wait does under
// SETTINGS_MAX_CONCURRENT_STREAMS=0): with a compressed 200ms budget the
// helper returns Unavailable promptly. Phase 2 drives an immediately
// succeeding NewStream, then waits past the budget and proves the established
// context is still alive (timer stopped on success) until the parent cancels.
//
// FAIL-ON-REVERT: calling newStream with the parent ctx directly (no
// establishment timer) parks phase 1 until the test timeout — RED.
func TestMonitorInterfacePeerEstablishmentBound_9891(t *testing.T) {
	orig := monitorInterfacePeerEstablishTimeout
	monitorInterfacePeerEstablishTimeout = 200 * time.Millisecond
	t.Cleanup(func() { monitorInterfacePeerEstablishTimeout = orig })

	t.Run("wedged", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		wedged := func(estCtx context.Context) (monitorInterfacePeerStream, error) {
			<-estCtx.Done()
			return nil, estCtx.Err()
		}
		start := time.Now()
		peer, estCtx, estCancel, err := establishMonitorInterfacePeerStream(ctx, wedged)
		elapsed := time.Since(start)
		if err == nil || status.Code(err) != codes.Unavailable {
			if estCancel != nil {
				estCancel()
			}
			t.Fatalf("wedged NewStream err code = %v, want Unavailable (err=%v)", status.Code(err), err)
		}
		if peer != nil || estCtx != nil || estCancel != nil {
			t.Fatal("wedged NewStream returned a stream context on failure — must be all nil")
		}
		if elapsed > 5*time.Second {
			t.Fatalf("wedged NewStream parked for %v (no establishment bound)", elapsed)
		}
		t.Logf("wedged peer establishment severed after %v (budget %v)", elapsed, monitorInterfacePeerEstablishTimeout)
	})

	t.Run("healthyNotLifetimeLimited", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		healthy := func(estCtx context.Context) (monitorInterfacePeerStream, error) {
			return &oneShotPeerStream9891{frame: "ok"}, nil
		}
		peer, estCtx, estCancel, err := establishMonitorInterfacePeerStream(ctx, healthy)
		if err != nil {
			t.Fatalf("healthy NewStream err = %v, want nil", err)
		}
		if peer == nil || estCtx == nil || estCancel == nil {
			t.Fatal("healthy NewStream returned nil stream/context/cancel on success")
		}
		defer estCancel()
		// Wait well past the establishment budget: the stream must still be
		// alive (the success path stops the timer rather than arming a
		// lifetime).
		select {
		case <-estCtx.Done():
			t.Fatalf("established stream context done after %v without parent cancel (budget lifetime-limits healthy monitoring)", monitorInterfacePeerEstablishTimeout)
		case <-time.After(600 * time.Millisecond):
		}
		// Parent cancel still propagates to the established stream.
		cancel()
		select {
		case <-estCtx.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("established stream context survived parent cancel")
		}
	})
}

// frameThenStallPeerStream9891 yields toYield frames and then stalls exactly
// as a wedged peer does (Recv blocks until ctx done). calls/exits prove the
// Recv workers ran and exited; forwarded counts yielded frames.
type frameThenStallPeerStream9891 struct {
	ctx       context.Context
	toYield   int
	calls     atomic.Int64
	exits     atomic.Int64
	forwarded atomic.Int64
}

func (m *frameThenStallPeerStream9891) Recv() (*pb.MonitorInterfaceResponse, error) {
	m.calls.Add(1)
	defer m.exits.Add(1)
	if int(m.forwarded.Add(1)) <= m.toYield {
		return &pb.MonitorInterfaceResponse{Frame: "peer-frame"}, nil
	}
	<-m.ctx.Done()
	return nil, m.ctx.Err()
}

// TestMonitorInterfaceProxyForwardingLoop_9891 pins the proxy forwarding loop
// (forwardMonitorInterfaceFrames): a peer that yields a frame and then stalls
// severs with Unavailable after forwarding what it yielded (no slot transfer
// — conn close unblocks Recv), while a slow local consumer severs with
// DeadlineExceeded and transfers its slot to the parked Send worker. The two
// phases share the loop's two sites (:Recv then :Send) with opposite stalls.
//
// FAIL-ON-REVERT: an unbounded proxy Recv parks phase 1 past the test
// timeout; a Send path without transfer reds the InFlight==1 assertion in
// phase 2 (0 while the worker is still parked).
func TestMonitorInterfaceProxyForwardingLoop_9891(t *testing.T) {
	t.Run("peerStall", func(t *testing.T) {
		origIdle := monitorInterfacePeerIdleTimeout
		monitorInterfacePeerIdleTimeout = 200 * time.Millisecond
		t.Cleanup(func() { monitorInterfacePeerIdleTimeout = origIdle })

		lim := diagcmd.NewLimiter(1)
		release, err := lim.Acquire()
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		defer release()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		peer := &frameThenStallPeerStream9891{ctx: ctx, toYield: 1}
		local := &capMonitorStream9891{ctx: ctx, cancel: cancel}

		start := time.Now()
		fwdErr, xfer := forwardMonitorInterfaceFrames(peer, local, ctx, release)
		elapsed := time.Since(start)

		if fwdErr == nil || status.Code(fwdErr) != codes.Unavailable {
			t.Fatalf("peer-stall forward code = %v, want Unavailable (err=%v)", status.Code(fwdErr), fwdErr)
		}
		if xfer {
			t.Fatal("peer-stall forward transferred the slot — Recv stalls must free, not transfer (conn close unblocks Recv)")
		}
		if got := local.frames.Load(); got != 1 {
			t.Fatalf("peer-stall local frames = %d, want 1 (the yielded frame must forward before the stall severs)", got)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("peer-stall forward parked for %v (no peer-idle bound in the loop)", elapsed)
		}
		if got := lim.InFlight(); got != 1 {
			t.Fatalf("peer-stall InFlight = %d, want 1 (no transfer: caller still holds the slot)", got)
		}
		t.Logf("peer stall severed after %v (budget %v) with 1 frame forwarded", elapsed, monitorInterfacePeerIdleTimeout)

		cancel()
		deadline := time.Now().Add(5 * time.Second)
		for peer.exits.Load() < peer.calls.Load() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if peer.exits.Load() < peer.calls.Load() {
			t.Fatalf("Recv workers exits = %d, calls = %d (a stalled Recv worker leaked)", peer.exits.Load(), peer.calls.Load())
		}
	})

	t.Run("slowConsumer", func(t *testing.T) {
		origSend := monitorInterfaceSendTimeout
		monitorInterfaceSendTimeout = 200 * time.Millisecond
		t.Cleanup(func() { monitorInterfaceSendTimeout = origSend })

		lim := diagcmd.NewLimiter(1)
		release, err := lim.Acquire()
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		transferred := false
		defer func() {
			if !transferred {
				release()
			}
		}()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		peer := &frameThenStallPeerStream9891{ctx: ctx, toYield: 1}
		slow := &blockingMonitorStream9891{ctx: ctx}

		start := time.Now()
		fwdErr, xfer := forwardMonitorInterfaceFrames(peer, slow, ctx, release)
		elapsed := time.Since(start)

		if fwdErr == nil || status.Code(fwdErr) != codes.DeadlineExceeded {
			t.Fatalf("slow-consumer forward code = %v, want DeadlineExceeded (err=%v)", status.Code(fwdErr), fwdErr)
		}
		if !xfer {
			t.Fatal("slow-consumer forward did not transfer the slot — the parked Send worker holds it")
		}
		transferred = true
		if slow.calls.Load() < 1 {
			t.Fatal("slow-consumer forward never reached Send, so this proves nothing about the send bound")
		}
		if elapsed > 5*time.Second {
			t.Fatalf("slow-consumer forward parked for %v (no send bound in the loop)", elapsed)
		}
		if got := slow.exits.Load(); got != 0 {
			t.Fatalf("slow Send exits at forward return = %d, want 0 (worker still parked)", got)
		}
		if got := lim.InFlight(); got != 1 {
			t.Fatalf("slow-consumer InFlight at forward return = %d, want 1 (slot transferred to the parked worker)", got)
		}
		t.Logf("slow consumer severed after %v (budget %v) with slot transferred", elapsed, monitorInterfaceSendTimeout)

		cancel()
		deadline := time.Now().Add(5 * time.Second)
		for slow.exits.Load() < 1 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if slow.exits.Load() < 1 {
			t.Fatal("Send worker never exited after cancel (leaked)")
		}
		deadline = time.Now().Add(5 * time.Second)
		for lim.InFlight() != 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if got := lim.InFlight(); got != 0 {
			t.Fatalf("InFlight after worker exit = %d, want 0 (transferred slot leaked)", got)
		}
		if probe, perr := lim.Acquire(); perr != nil {
			t.Fatalf("probe acquire after worker exit: %v (slot leaked)", perr)
		} else {
			probe()
		}
	})
}

// flowSvc9891 is a minimal server-streaming service whose handler drives the
// REAL grpc-go H2 transport through sendMonitorInterfaceFrame: large frames
// fill the 64KB stream quota while the client holds its window shut, so a
// later Send blocks on writeQuota.get exactly as a stalled MonitorInterface
// consumer blocks. done carries the handler outcome for the test's assertions.
type flowSvc9891Iface interface {
	Stream(grpc.ServerStream) error
}

type flowSvc9891 struct {
	lim  *diagcmd.Limiter
	done chan flowResult9891
}

type flowResult9891 struct {
	err           error
	xfer          bool
	succeeded     int
	inFlightAtRet int
}

type flowServerStream9891 struct {
	grpc.ServerStream
}

func (w *flowServerStream9891) Send(resp *pb.MonitorInterfaceResponse) error {
	return w.ServerStream.SendMsg(resp)
}

func (s *flowSvc9891) Stream(stream grpc.ServerStream) error {
	var req pb.MonitorInterfaceRequest
	_ = stream.RecvMsg(&req)
	w := &flowServerStream9891{ServerStream: stream}
	release, err := s.lim.Acquire()
	if err != nil {
		resErr := status.Error(codes.ResourceExhausted, "test budget exhausted")
		s.done <- flowResult9891{err: resErr, succeeded: 0, inFlightAtRet: s.lim.InFlight()}
		return resErr
	}
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
	large := &pb.MonitorInterfaceResponse{Frame: strings.Repeat("x", 200*1024)}
	succeeded := 0
	for range 10 {
		sendErr, xfer := sendMonitorInterfaceFrame(w, large, release)
		if sendErr != nil {
			if xfer {
				transferred = true
			}
			res := flowResult9891{err: sendErr, xfer: xfer, succeeded: succeeded, inFlightAtRet: s.lim.InFlight()}
			s.done <- res
			return sendErr
		}
		succeeded++
	}
	res := flowResult9891{succeeded: succeeded, inFlightAtRet: s.lim.InFlight()}
	s.done <- res
	return nil
}

// TestMonitorInterfaceRealFlowControlUnblocksOnReturn_9891 is the REAL H2
// counterpart to the blocking-Send fake: over bufconn with real grpc-go
// v1.78.0 transport, a client that never reads fills the server's stream
// quota, the handler's Send times out and severs, and then — with the client
// STILL CONNECTED and never cancelled — the Send worker exits on the
// handler-return stream cancel (server.go WriteStatus → http2_server
// finishStream s.cancel → flowcontrol writeQuota.get errStreamDone) and frees
// the transferred slot, while the queued DATA + trailer stay retained until
// the client drains (controlbuf.go queues the trailer behind pending DATA).
// The test proves both halves: InFlight drains to 0 with no test cancel (the
// fake would stay parked at 1), and the client's first read AFTER the drain
// still receives the queued DATA frame ahead of the DeadlineExceeded trailer.
//
// FAIL-ON-REVERT: without the send bound the handler parks in Send until the
// test timeout; without the transfer the InFlight==1 at-return assertion reds.
func TestMonitorInterfaceRealFlowControlUnblocksOnReturn_9891(t *testing.T) {
	origTimeout := monitorInterfaceSendTimeout
	monitorInterfaceSendTimeout = 300 * time.Millisecond
	t.Cleanup(func() { monitorInterfaceSendTimeout = origTimeout })

	lim := diagcmd.NewLimiter(1)
	svc := &flowSvc9891{lim: lim, done: make(chan flowResult9891, 1)}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "test9891.Monitor",
		HandlerType: (*flowSvc9891Iface)(nil),
		Streams: []grpc.StreamDesc{{
			StreamName:    "Stream",
			ServerStreams: true,
			Handler: func(srv any, stream grpc.ServerStream) error {
				return srv.(*flowSvc9891).Stream(stream)
			},
		}},
	}, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/test9891.Monitor/Stream")
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	if err := stream.SendMsg(&pb.MonitorInterfaceRequest{}); err != nil {
		t.Fatalf("SendMsg request: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	// Hold the window shut: no Recv until the server has severed AND the slot
	// has drained, proving the worker exited without any client read/cancel.
	var res flowResult9891
	select {
	case res = <-svc.done:
	case <-time.After(15 * time.Second):
		t.Fatal("server handler never returned (no send bound over real H2)")
	}
	if res.err == nil || status.Code(res.err) != codes.DeadlineExceeded {
		t.Fatalf("handler err code = %v, want DeadlineExceeded (err=%v, succeeded=%d)", status.Code(res.err), res.err, res.succeeded)
	}
	if !res.xfer {
		t.Fatal("handler did not transfer the slot on real-H2 timeout")
	}
	if res.succeeded < 1 {
		t.Fatalf("succeeded = %d, want >= 1 (no DATA queued, so flow control never engaged)", res.succeeded)
	}
	if res.inFlightAtRet != 1 {
		t.Fatalf("InFlight at handler return = %d, want 1 (slot transferred to the parked worker)", res.inFlightAtRet)
	}
	t.Logf("real-H2 handler severed after %d queued frames; InFlight==1 at return", res.succeeded)

	deadline := time.Now().Add(10 * time.Second)
	for lim.InFlight() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := lim.InFlight(); got != 0 {
		t.Fatalf("InFlight = %d after handler return with client still connected, want 0 (the worker must exit on the handler-return cancel, not linger until client cancel)", got)
	}
	t.Log("slot freed with client still connected — worker exited on handler-return cancel")

	// Transport still retained: the first read delivers the queued DATA frame
	// (written before the timeout), and only after the DATA drains does the
	// queued trailer surface as DeadlineExceeded.
	var first pb.MonitorInterfaceResponse
	if err := stream.RecvMsg(&first); err != nil {
		t.Fatalf("first RecvMsg err = %v, want the queued DATA frame (transport must retain DATA past slot release)", err)
	}
	if got := len(first.GetFrame()); got != 200*1024 {
		t.Fatalf("first RecvMsg frame len = %d, want %d (not the queued large frame)", got, 200*1024)
	}
	var second pb.MonitorInterfaceResponse
	recvErr := stream.RecvMsg(&second)
	if recvErr == nil || status.Code(recvErr) != codes.DeadlineExceeded {
		t.Fatalf("second RecvMsg code = %v, want DeadlineExceeded trailer behind DATA (err=%v)", status.Code(recvErr), recvErr)
	}
}
