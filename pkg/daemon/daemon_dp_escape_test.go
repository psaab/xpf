package daemon

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #2114 (Codex PR #6743 r4-F4): the escape guards.
//
// The atomic cell only fixes ACQUISITION. These tests bind the other
// half — that a GENUINE long-lived consumer, constructed through the
// PRODUCTION wiring (startGRPCServer, not a hand-built grpcapi.Config),
// stops dispatching into a backend the daemon has disowned.
//
// The consumer here is a real *grpcapi.Server driving its real
// SystemAction handler; the backend is a real *dataplane.Manager with
// two methods overridden to record. Nothing about the disown is faked:
// setDataplane(nil) is the exact writer the bootstrap-exit arm failure
// runs (daemon_run_bringup.go) and the retired-backend branch runs
// (daemon_run_naming.go).

// escapeRecorderDP is the published backend. It embeds a real
// *dataplane.Manager so it satisfies dataplane.RuntimeDataPlane and the
// full management surface without a hand-written stub, and overrides
// exactly the two methods the SystemAction("clear-policy-counters") arm
// touches. IsLoaded() reports true so the handler's
// `dp == nil || !dp.IsLoaded()` pre-check passes for a directly-held
// backend — that is what makes the retained-handle call reachable.
type escapeRecorderDP struct {
	*dataplane.Manager
	name         string
	clearCalls   atomic.Int64
	isLoadedSeen atomic.Int64
}

func newEscapeRecorderDP(name string) *escapeRecorderDP {
	return &escapeRecorderDP{Manager: dataplane.New(), name: name}
}

func (f *escapeRecorderDP) IsLoaded() bool {
	f.isLoadedSeen.Add(1)
	return true
}

func (f *escapeRecorderDP) ClearPolicyCounters() error {
	f.clearCalls.Add(1)
	return nil
}

// newEscapeTestDaemon builds a daemon with just enough wiring for
// startGRPCServer: a real store for its per-dial transport resolver and a
// loopback ephemeral bind.
func newEscapeTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	d := &Daemon{store: store}
	d.opts.GRPCAddr = "127.0.0.1:0"
	return d
}

// startEscapeTestGRPC runs the PRODUCTION server-startup path and returns
// the constructed server. The context is cancelled immediately so the
// serve loop exits without waiting; the server reference is published
// synchronously inside startGRPCServer, before the goroutine, so the
// handler is reachable regardless.
func startEscapeTestGRPC(t *testing.T, d *Daemon) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var wg sync.WaitGroup
	d.startGRPCServer(ctx, &wg, nil, nil)
	t.Cleanup(wg.Wait)
	if d.loadGRPCSrv() == nil {
		t.Fatal("startGRPCServer did not construct a server")
	}
}

func clearPolicyCountersViaGRPC(t *testing.T, d *Daemon) (*pb.SystemActionResponse, error) {
	t.Helper()
	return d.loadGRPCSrv().SystemAction(context.Background(),
		&pb.SystemActionRequest{Action: "clear-policy-counters"})
}

// TestGRPCServer_DisownedDataplaneIsNotReachable is the F4 binder: the
// gRPC server must not keep dispatching into a backend the daemon has
// cleared from the cell.
//
// Fail-on-revert: restore the capture-once wiring in
// daemon_run_servers.go's startGRPCServer —
//
//	var grpcDP grpcDataPlane
//	if rt := d.dataplane(); rt != nil {
//	        if probe, ok := rt.(grpcDataPlane); ok { grpcDP = probe }
//	}
//
// — and the server holds the backend directly, so the cleared cell is
// invisible to it and the clear lands on the disowned object.
func TestGRPCServer_DisownedDataplaneIsNotReachable(t *testing.T) {
	d := newEscapeTestDaemon(t)
	backend := newEscapeRecorderDP("A")
	d.setDataplane(backend)

	// ACQUIRE: the production wiring hands the server whatever it hands it.
	startEscapeTestGRPC(t, d)

	// DISOWN: the bootstrap-exit re-arm failure / retired-backend writer.
	d.setDataplane(nil)

	// CALL: a real operator RPC on the real handler.
	resp, err := clearPolicyCountersViaGRPC(t, d)

	if n := backend.clearCalls.Load(); n != 0 {
		t.Fatalf("gRPC cleared counters on the DISOWNED dataplane %d time(s) after setDataplane(nil); "+
			"the server is still holding the backend handle instead of re-reading the #2114 cell", n)
	}
	if err == nil {
		t.Fatalf("SystemAction(clear-policy-counters) succeeded with no published dataplane: %v", resp)
	}
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("SystemAction error code = %v (%v), want %v", got, err, codes.Unavailable)
	}
}

// TestGRPCServer_RepublishedDataplaneIsReachable is the second binder:
// the escape also matters when the cell is REPOINTED rather than
// cleared. A capture-once server keeps clearing counters on the old
// backend forever.
//
// Fail-on-revert: same hunk as above — under the capture, backend A
// takes the call and B takes none.
func TestGRPCServer_RepublishedDataplaneIsReachable(t *testing.T) {
	d := newEscapeTestDaemon(t)
	first := newEscapeRecorderDP("A")
	d.setDataplane(first)

	startEscapeTestGRPC(t, d)

	second := newEscapeRecorderDP("B")
	d.setDataplane(second)

	if _, err := clearPolicyCountersViaGRPC(t, d); err != nil {
		t.Fatalf("SystemAction(clear-policy-counters) after republication: %v", err)
	}
	if n := first.clearCalls.Load(); n != 0 {
		t.Fatalf("the SUPERSEDED backend took %d clear call(s); the server is pinned to the "+
			"startup snapshot instead of the currently published dataplane", n)
	}
	if n := second.clearCalls.Load(); n != 1 {
		t.Fatalf("the currently published backend took %d clear call(s), want 1", n)
	}
}

// TestGRPCServer_PublishedDataplaneStillReachable is the OVER-REACH
// guard. It asserts the behaviour this change must NOT alter: with a
// dataplane published, the operator RPC still reaches it and still
// succeeds. It stays GREEN under the revert above — a fix that simply
// severed gRPC from the dataplane would turn this one red.
func TestGRPCServer_PublishedDataplaneStillReachable(t *testing.T) {
	d := newEscapeTestDaemon(t)
	backend := newEscapeRecorderDP("A")
	d.setDataplane(backend)

	startEscapeTestGRPC(t, d)

	resp, err := clearPolicyCountersViaGRPC(t, d)
	if err != nil {
		t.Fatalf("SystemAction(clear-policy-counters) with a published dataplane: %v", err)
	}
	if resp == nil || resp.Message == "" {
		t.Fatalf("SystemAction returned %v, want the success message", resp)
	}
	if n := backend.clearCalls.Load(); n != 1 {
		t.Fatalf("published backend took %d clear call(s), want 1", n)
	}
	if n := backend.isLoadedSeen.Load(); n == 0 {
		t.Fatal("the handler's IsLoaded() pre-check never reached the published backend")
	}
}

// TestGRPCServer_NoDataplaneModeLeavesConfigNil is the second over-reach
// guard: --no-dataplane (config-only) must still hand gRPC a genuine nil
// interface, not a live indirection that reports "not published" on every
// call. Consumers branch on `s.dp == nil` in a dozen places
// (pkg/grpcapi/server_helpers.go, server_diag_monitor.go, ...) and this
// pins that those branches are still reachable. GREEN under the revert.
func TestGRPCServer_NoDataplaneModeLeavesConfigNil(t *testing.T) {
	d := newEscapeTestDaemon(t)
	d.opts.NoDataplane = true

	if _, ok := d.liveDataplane(); ok {
		t.Fatal("liveDataplane() offered an indirection in --no-dataplane mode")
	}

	startEscapeTestGRPC(t, d)

	// clear-persistent-nat is the arm that distinguishes a nil DP from a
	// live-but-unpublished one only via GetPersistentNAT; the
	// clear-policy-counters arm's `dp == nil` leg is the one under test.
	_, err := clearPolicyCountersViaGRPC(t, d)
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("SystemAction error code = %v (%v), want %v", got, err, codes.Unavailable)
	}
}

// TestLiveDataPlane_ResolvesPerCall pins the adapter contract directly:
// one value, three different answers as the cell changes underneath it.
// This is the unit-level statement of what the server-level binders above
// prove end to end.
func TestLiveDataPlane_ResolvesPerCall(t *testing.T) {
	d := &Daemon{}
	live, ok := d.liveDataplane()
	if !ok {
		t.Fatal("liveDataplane() not offered on a default daemon")
	}

	if live.IsLoaded() {
		t.Fatal("IsLoaded() true on an empty cell")
	}
	if err := live.ClearPolicyCounters(); err == nil {
		t.Fatal("ClearPolicyCounters() succeeded on an empty cell")
	}

	backend := newEscapeRecorderDP("A")
	d.setDataplane(backend)
	if !live.IsLoaded() {
		t.Fatal("IsLoaded() false after publication")
	}
	if err := live.ClearPolicyCounters(); err != nil {
		t.Fatalf("ClearPolicyCounters() after publication: %v", err)
	}
	if n := backend.clearCalls.Load(); n != 1 {
		t.Fatalf("backend clear calls = %d, want 1", n)
	}

	d.setDataplane(nil)
	if live.IsLoaded() {
		t.Fatal("IsLoaded() true after the cell was cleared")
	}
	if err := live.ClearPolicyCounters(); err == nil {
		t.Fatal("ClearPolicyCounters() succeeded after the cell was cleared")
	}
	if n := backend.clearCalls.Load(); n != 1 {
		t.Fatalf("backend clear calls = %d after the clear, want it to stay 1", n)
	}
}
