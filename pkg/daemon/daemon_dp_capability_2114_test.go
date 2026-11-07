package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #2114 (Codex PR #6743 r6-F1/F2/F3): the CAPABILITY guards.
//
// r4 stopped the published backend escaping into the management servers by
// giving them liveDataPlane, a hand-written adapter that re-resolves the
// cell per call. Go computes a method set statically, so that adapter's
// method set is EXACTLY its declared forwarders — every optional
// capability the consumers reach by asserting on `any` (LastApplyResult,
// Sessions, Telemetry, Status, AppliedNATView, the session cursor, the
// userspace controls) silently disappeared for a perfectly HEALTHY
// backend. The r4 compile-time assertions cannot see it: they pin the
// MANDATORY union, and erasure is precisely the absence of everything
// outside that union.
//
// The fix is dataplane.Unwrap: the probe resolves to the backend published
// AT THE MOMENT OF THE PROBE. These tests bind both halves of that — the
// capability must come back (below) and the disowned backend must stay
// gone (the separate body after it). They are deliberately SEPARATE
// functions: a preservation assertion sharing a body with the
// unreachability assertion would never run once the first one failed.

const (
	capabilityTestGeneration = 4242
	capabilityTestV4         = 7
	capabilityTestV6         = 11
)

// capabilitySessionStore is a SessionStore whose Count() is
// distinguishable from the null object dataplane.SessionStoreOf(nil)
// returns (0, 0). The embedded nil interface supplies the other methods;
// none of them is called here.
type capabilitySessionStore struct{ dataplane.SessionStore }

func (capabilitySessionStore) Count() (int, int) {
	return capabilityTestV4, capabilityTestV6
}

// Every fixture below embeds a real *dataplane.Manager so it satisfies
// liveDataPlaneSurface, exactly as both shipping backends do. That is
// load-bearing, not decoration: liveDataPlane.resolve() rejects a backend
// that does not implement the mandatory surface, so a stub-shaped fake
// makes IsLoaded() answer false and the handler takes its "dataplane not
// loaded" pre-check branch — the test would then pass without the
// forwarder, the probe, or the mapping under test ever running.

// capabilityBackendDP is the published backend. It carries TWO of the
// capabilities the adapter erases — the apply-result reader that
// pkg/api/metrics_nat.go's NAT-pool collector needs, and the session-store
// provider that pkg/grpcapi/server_helpers.go's NAT statistics need — so a
// single fixture covers both of the consumer shapes named in the finding.
type capabilityBackendDP struct {
	*dataplane.Manager
}

func newCapabilityBackendDP() *capabilityBackendDP {
	return &capabilityBackendDP{Manager: dataplane.New()}
}

func (d *capabilityBackendDP) LastApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{Generation: capabilityTestGeneration}
}

func (d *capabilityBackendDP) Sessions() dataplane.SessionStore {
	return capabilitySessionStore{}
}

// TestLiveDataPlane_PreservesOptionalCapabilities is F1(a).
//
// Fail-on-revert: delete the `provider = Unwrap(provider)` hunk from
// dataplane.LastApplyResultOf (or the `Unwrap(provider).(type)` switch
// head in SessionStoreOf) and the probe is made against liveDataPlane
// itself, whose method set has neither method — LastApplyResultOf returns
// nil and SessionStoreOf returns the null store, both asserted below.
func TestLiveDataPlane_PreservesOptionalCapabilities(t *testing.T) {
	d := &Daemon{}
	backend := newCapabilityBackendDP()
	d.setDataplane(backend)

	adapter, ok := d.liveDataplane()
	if !ok {
		t.Fatal("liveDataplane() reported not-wirable for a daemon with a published backend")
	}

	// CONTROL: the fixture really has the capabilities. Without this a RED
	// below could equally mean "the fake never implemented the method",
	// which would make the guard a statement about the fixture instead of
	// about the adapter.
	if got := dataplane.LastApplyResultOf(backend); got == nil || got.Generation != capabilityTestGeneration {
		t.Fatalf("control: LastApplyResultOf(backend) = %v, want generation %d", got, capabilityTestGeneration)
	}
	if v4, v6 := dataplane.SessionStoreOf(backend).Count(); v4 != capabilityTestV4 || v6 != capabilityTestV6 {
		t.Fatalf("control: SessionStoreOf(backend).Count() = (%d,%d), want (%d,%d)",
			v4, v6, capabilityTestV4, capabilityTestV6)
	}

	got := dataplane.LastApplyResultOf(adapter)
	if got == nil {
		t.Fatal("LastApplyResultOf(liveDataPlane) = nil for a HEALTHY published backend that " +
			"implements LastApplyResult: the adapter erased the capability, so " +
			"pkg/api/metrics_nat.go stops emitting every NAT-pool sample")
	}
	if got.Generation != capabilityTestGeneration {
		t.Fatalf("LastApplyResultOf(liveDataPlane).Generation = %d, want %d (the published backend's)",
			got.Generation, capabilityTestGeneration)
	}

	v4, v6 := dataplane.SessionStoreOf(adapter).Count()
	if v4 != capabilityTestV4 || v6 != capabilityTestV6 {
		t.Fatalf("SessionStoreOf(liveDataPlane).Count() = (%d,%d), want the published backend's "+
			"(%d,%d): the adapter erased Sessions(), so the NAT statistics domain is built "+
			"over a null store and reports healthy zeros", v4, v6, capabilityTestV4, capabilityTestV6)
	}
}

// TestLiveDataPlane_DisownedCapabilityIsUnreachable is F1(b): Unwrap must
// not become a back door that resurrects a backend the daemon has
// disowned. It is a SEPARATE function body from the preservation guard
// above on purpose — sharing one body would let a preservation failure
// skip this assertion entirely.
//
// Fail-on-revert: make liveDataPlane.Unwrap cache (return a value captured
// on an earlier call, or any non-live pointer) instead of re-reading the
// cell, and the post-disown probes below still find the backend.
func TestLiveDataPlane_DisownedCapabilityIsUnreachable(t *testing.T) {
	d := &Daemon{}
	backend := newCapabilityBackendDP()
	d.setDataplane(backend)

	adapter, ok := d.liveDataplane()
	if !ok {
		t.Fatal("liveDataplane() reported not-wirable for a daemon with a published backend")
	}

	// Precondition: reachable BEFORE the disown, and reached through the
	// adapter — otherwise a nil answer afterwards proves nothing.
	if got := dataplane.LastApplyResultOf(adapter); got == nil {
		t.Fatal("precondition: LastApplyResultOf(liveDataPlane) = nil before the disown")
	}
	if v4, _ := dataplane.SessionStoreOf(adapter).Count(); v4 != capabilityTestV4 {
		t.Fatalf("precondition: SessionStoreOf(liveDataPlane).Count() v4 = %d before the disown, want %d",
			v4, capabilityTestV4)
	}

	// DISOWN — the exact writer the bootstrap-exit arm failure
	// (daemon_run_bringup.go) and the retired-backend branch
	// (daemon_run_naming.go) run.
	d.setDataplane(nil)

	if got := dataplane.LastApplyResultOf(adapter); got != nil {
		t.Fatalf("LastApplyResultOf(liveDataPlane) = %+v after setDataplane(nil): Unwrap handed "+
			"back a DISOWNED backend, which is the escape #2114 exists to close", got)
	}
	if v4, v6 := dataplane.SessionStoreOf(adapter).Count(); v4 != 0 || v6 != 0 {
		t.Fatalf("SessionStoreOf(liveDataPlane).Count() = (%d,%d) after setDataplane(nil), want (0,0): "+
			"Unwrap resurrected the disowned backend's session store", v4, v6)
	}
}

// ---------------------------------------------------------------------------
// F1, end to end through a real probe site.
// ---------------------------------------------------------------------------

// statusProbeDP is a published backend that implements
// grpcapi's userspaceStatusProvider (Status()) — an OPTIONAL capability,
// absent from liveDataPlaneSurface. Status() fails with a distinctive
// message so the two `show system buffers` branches are trivially
// distinguishable in the rendered text.
type statusProbeDP struct {
	*dataplane.Manager
}

func newStatusProbeDP() *statusProbeDP {
	return &statusProbeDP{Manager: dataplane.New()}
}

const statusProbeErrText = "synthetic control-socket failure (#6743 F1 probe)"

func (d *statusProbeDP) IsLoaded() bool { return true }

func (d *statusProbeDP) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, errors.New(statusProbeErrText)
}

func showTextTopic(t *testing.T, d *Daemon, topic string) string {
	t.Helper()
	srv := d.loadGRPCSrv()
	if srv == nil {
		t.Fatal("gRPC server has not been published")
	}
	resp, err := srv.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
	if err != nil {
		t.Fatalf("ShowText(%q): %v", topic, err)
	}
	return resp.Output
}

// TestGRPCShowBuffers_OptionalStatusProbeSurvivesLiveIndirection binds the
// PROBE-SITE half of F1 through the production wiring: the gRPC server is
// built by startGRPCServer (so Server.dp really is the live indirection),
// and the published backend really does implement Status().
//
// Fail-on-revert: change server_show_system.go's probe back to
// `s.dp.(userspaceStatusProvider)` and the assertion on the userspace
// branch fails — the render silently takes the BPF-map branch and answers
// "No BPF maps available" about a running userspace helper.
func TestGRPCShowBuffers_OptionalStatusProbeSurvivesLiveIndirection(t *testing.T) {
	d := newEscapeTestDaemon(t)
	d.setDataplane(newStatusProbeDP())
	startEscapeTestGRPC(t, d)

	out := showTextTopic(t, d, "buffers")
	if !strings.Contains(out, statusProbeErrText) {
		t.Fatalf("show system buffers took the BPF-map branch for a backend that implements "+
			"Status(): the live indirection erased the userspace probe.\noutput: %q", out)
	}
	if strings.Contains(out, "No BPF maps available") {
		t.Fatalf("show system buffers reported %q for a userspace backend.\noutput: %q",
			"No BPF maps available", out)
	}
}

// ---------------------------------------------------------------------------
// F3(a): an EMPTY cell must read as "Dataplane not loaded".
// ---------------------------------------------------------------------------

// TestGRPCShowBuffers_UnpublishedReportsNotLoaded is F3(a). liveDataplane()
// wires a non-nil adapter whenever NoDataplane is false — including when
// startup Start() failed and cleared the cell — so a render keyed on
// `s.dp != nil` describes a backend that does not exist.
//
// Fail-on-revert: put `if s.dp != nil {` back at server_show_system.go's
// showBuffers and the empty cell falls into the backend arm, printing
// "No BPF maps available" (a claim about a loaded backend's maps) for a
// firewall with no dataplane at all.
func TestGRPCShowBuffers_UnpublishedReportsNotLoaded(t *testing.T) {
	d := newEscapeTestDaemon(t)
	// Publish, wire, then disown: the server must hold the live adapter,
	// which is precisely the r4 shape that made `dp != nil` meaningless.
	d.setDataplane(newStatusProbeDP())
	startEscapeTestGRPC(t, d)
	d.setDataplane(nil)

	out := showTextTopic(t, d, "buffers")
	if !strings.Contains(out, "Dataplane not loaded") {
		t.Fatalf("show system buffers with an EMPTY cell must report %q; got %q",
			"Dataplane not loaded", out)
	}
	if strings.Contains(out, "No BPF maps available") {
		t.Fatalf("show system buffers reported %q for a daemon with NO published dataplane: "+
			"the render mistook the permanently non-nil live adapter for a backend.\noutput: %q",
			"No BPF maps available", out)
	}
}

// ---------------------------------------------------------------------------
// F3(b): a clear that RACES the disown is Unavailable, not Internal.
// ---------------------------------------------------------------------------

// clearRaceDP reproduces the F3 race DETERMINISTICALLY through production
// code rather than by scheduling luck: its IsLoaded() disowns itself as a
// side effect and then answers true, so the handler's
// `dp == nil || !dp.IsLoaded()` pre-check passes and the very next call —
// the forwarder — resolves an EMPTY cell and returns
// dataplane.ErrNotPublished. That is exactly the interleaving a concurrent
// setDataplane(nil) produces; the fake only fixes WHEN it happens.
type clearRaceDP struct {
	*dataplane.Manager
	daemon *Daemon
}

func newClearRaceDP(d *Daemon) *clearRaceDP {
	return &clearRaceDP{Manager: dataplane.New(), daemon: d}
}

func (d *clearRaceDP) IsLoaded() bool {
	if d.daemon != nil {
		d.daemon.setDataplane(nil)
	}
	return true
}

// ClearPolicyCounters is never reached: the forwarder resolves the
// already-emptied cell first and returns dataplane.ErrNotPublished. It
// exists so a reader can see the backend itself would have SUCCEEDED —
// the error under test is purely the daemon's lifecycle state.
func (d *clearRaceDP) ClearPolicyCounters() error { return nil }

// plainClearErrDP is the NEGATIVE CONTROL for the mapping: a published,
// loaded backend whose clear fails for a genuine backend reason. It must
// still be codes.Internal, so the fix cannot be "call everything
// Unavailable".
type plainClearErrDP struct {
	*dataplane.Manager
}

func newPlainClearErrDP() *plainClearErrDP {
	return &plainClearErrDP{Manager: dataplane.New()}
}

func (d *plainClearErrDP) IsLoaded() bool { return true }

func (d *plainClearErrDP) ClearPolicyCounters() error {
	return errors.New("map update failed: EPERM")
}

// TestSystemAction_ClearRacingDisownIsUnavailable is F3(b).
//
// Fail-on-revert: restore `status.Errorf(codes.Internal, "%v", err)` at the
// clear-policy-counters arm (i.e. drop the dataplaneActionError mapping)
// and the daemon's own lifecycle state is reported to the operator as a
// server fault.
func TestSystemAction_ClearRacingDisownIsUnavailable(t *testing.T) {
	d := newEscapeTestDaemon(t)
	backend := newClearRaceDP(d)
	d.setDataplane(backend)
	startEscapeTestGRPC(t, d)

	_, err := clearPolicyCountersViaGRPC(t, d)
	if err == nil {
		t.Fatal("clear-policy-counters against a cell cleared mid-call returned success")
	}
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("clear-policy-counters raced by setDataplane(nil): code = %v, want %v (the same "+
			"code the dp==nil pre-check returns for the identical operator-visible condition); err = %v",
			got, codes.Unavailable, err)
	}
}

// TestSystemAction_ClearBackendFailureStaysInternal is the negative
// control for the mapping above, in its own body so a failure of one does
// not hide the other.
func TestSystemAction_ClearBackendFailureStaysInternal(t *testing.T) {
	d := newEscapeTestDaemon(t)
	d.setDataplane(newPlainClearErrDP())
	startEscapeTestGRPC(t, d)

	_, err := clearPolicyCountersViaGRPC(t, d)
	if err == nil {
		t.Fatal("clear-policy-counters with a failing backend returned success")
	}
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("a genuine backend clear failure: code = %v, want %v; err = %v",
			got, codes.Internal, err)
	}
}

// ---------------------------------------------------------------------------
// F2: GetPersistentNAT must be resolved ONCE per operation.
// ---------------------------------------------------------------------------

// persistentNATRaceDP hands back a real table on the FIRST
// GetPersistentNAT() and disowns itself as a side effect, so any SECOND
// call in the same operation resolves an empty cell and returns nil. A
// caller that check-then-uses across two calls nil-dereferences; a caller
// that resolved once does not notice.
type persistentNATRaceDP struct {
	*dataplane.Manager
	daemon *Daemon
	table  *dataplane.PersistentNATTable
	calls  int
}

func newPersistentNATRaceDP(d *Daemon, table *dataplane.PersistentNATTable) *persistentNATRaceDP {
	return &persistentNATRaceDP{Manager: dataplane.New(), daemon: d, table: table}
}

func (d *persistentNATRaceDP) IsLoaded() bool { return true }

func (d *persistentNATRaceDP) GetPersistentNAT() *dataplane.PersistentNATTable {
	d.calls++
	if d.daemon != nil {
		d.daemon.setDataplane(nil)
	}
	return d.table
}

// TestSystemAction_ClearPersistentNATResolvesOnce is F2.
//
// Fail-on-revert: restore the three-call shape
//
//	if s.dp == nil || s.dp.GetPersistentNAT() == nil { ... }
//	count := s.dp.GetPersistentNAT().Len()
//	s.dp.GetPersistentNAT().Clear()
//
// and the second call resolves the emptied cell, returning nil — .Len()
// then dereferences a nil *PersistentNATTable and the daemon panics
// serving an operator's `clear security nat source persistent-nat-table`.
func TestSystemAction_ClearPersistentNATResolvesOnce(t *testing.T) {
	d := newEscapeTestDaemon(t)
	table := dataplane.NewPersistentNATTable()
	backend := newPersistentNATRaceDP(d, table)
	d.setDataplane(backend)
	startEscapeTestGRPC(t, d)

	var (
		resp      *pb.SystemActionResponse
		err       error
		panicked  any
		panicSeen bool
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked, panicSeen = r, true
			}
		}()
		srv := d.loadGRPCSrv()
		if srv == nil {
			t.Fatal("gRPC server has not been published")
		}
		resp, err = srv.SystemAction(context.Background(),
			&pb.SystemActionRequest{Action: "clear-persistent-nat"})
	}()

	if panicSeen {
		t.Fatalf("clear-persistent-nat PANICKED (%v): the handler resolved GetPersistentNAT more "+
			"than once, so a cell cleared between the nil-check and the use returned nil to a "+
			"caller that had already proven non-nil. Resolutions observed: %d", panicked, backend.calls)
	}
	if err != nil {
		t.Fatalf("clear-persistent-nat: %v", err)
	}
	if backend.calls != 1 {
		t.Fatalf("GetPersistentNAT resolved %d times, want exactly 1: every extra call is a fresh "+
			"cell load that can return nil to a caller holding a proven-non-nil result", backend.calls)
	}
	if !strings.Contains(resp.Message, "Cleared") {
		t.Fatalf("clear-persistent-nat message = %q, want a Cleared-N report", resp.Message)
	}
}
