package upgrade

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestHAStatePresenceDistinguishesAbsentZeroMalformed17095 is the
// #17095 acceptance cell: for every gate input the typed channel
// distinguishes absent, zero and (unrepresentable) malformed. In the
// text world a present-but-garbled peer wire collapsed to 0 and
// PERMITTED (#14991); here a garbled value cannot be constructed, an
// absent peer HA fails closed, and a genuine 0 / unknown keeps its
// documented meaning.
func u32p(v uint32) *uint32 { return &v }

func TestHAStatePresenceDistinguishesAbsentZeroMalformed17095(t *testing.T) {
	t.Parallel()
	// Absent peer HA: not compatible, versions report not-present.
	absent := &pb.GetClusterHAStateResponse{LocalHaProtocol: u32p(1), SessionSyncWirePresent: true}
	if compat, _, _ := haProtocolVerdictFromState(absent); compat {
		t.Error("absent peer HA read as compatible")
	}
	if _, _, _, present, err := peerProtocolVersionsFromState(absent); present || err != nil {
		t.Errorf("absent peer HA: present=%v err=%v, want (false, nil)", present, err)
	}
	// Present and equal: compatible; mismatched: not.
	equal := &pb.GetClusterHAStateResponse{LocalHaProtocol: u32p(2), PeerHaProtocol: u32p(2)}
	if compat, l, p := haProtocolVerdictFromState(equal); !compat || l != 2 || p != 2 {
		t.Errorf("equal HA verdict = (%v,%d,%d), want (true,2,2)", compat, l, p)
	}
	skew := &pb.GetClusterHAStateResponse{LocalHaProtocol: u32p(2), PeerHaProtocol: u32p(3)}
	if compat, _, _ := haProtocolVerdictFromState(skew); compat {
		t.Error("mismatched HA read as compatible")
	}
	// Peer wire absent-field (line not carried): the check cannot run.
	noWireField := &pb.GetClusterHAStateResponse{PeerAlive: true}
	if ok, _, err := sessionSyncWireVerdictFromState(noWireField); ok || err == nil {
		t.Errorf("absent wire field: ok=%v err=%v, want refusal-as-error", ok, err)
	}
	// Field present, value absent = advertised-unknown (pre-#7990): permit.
	unknown := &pb.GetClusterHAStateResponse{PeerAlive: true, SessionSyncWirePresent: true}
	if ok, _, err := sessionSyncWireVerdictFromState(unknown); !ok || err != nil {
		t.Errorf("unknown peer wire: ok=%v err=%v, want permit", ok, err)
	}
	// Field present with the local version: permit; differing: refuse
	// without error (a real incompatibility, not an unreadable instrument).
	match := &pb.GetClusterHAStateResponse{PeerAlive: true, SessionSyncWirePresent: true, PeerSessionSyncWire: u32p(uint32(cluster.SessionSyncWireVersion))}
	if ok, _, err := sessionSyncWireVerdictFromState(match); !ok || err != nil {
		t.Errorf("matching peer wire: ok=%v err=%v, want permit", ok, err)
	}
	differ := &pb.GetClusterHAStateResponse{PeerAlive: true, SessionSyncWirePresent: true, PeerSessionSyncWire: u32p(4242)}
	if ok, _, err := sessionSyncWireVerdictFromState(differ); ok || err != nil {
		t.Errorf("differing peer wire: ok=%v err=%v, want refusal without error", ok, err)
	}
	// A genuine zero version is data, not absence: present with value 0.
	zeroWire := &pb.GetClusterHAStateResponse{PeerAlive: true, SessionSyncWirePresent: true, PeerSessionSyncWire: u32p(0)}
	if _, _, wire, present, err := peerProtocolVersionsFromState(&pb.GetClusterHAStateResponse{
		LocalHaProtocol: u32p(1), PeerHaProtocol: u32p(1), SessionSyncWirePresent: true, PeerSessionSyncWire: u32p(0),
	}); !present || wire != 0 || err != nil {
		t.Errorf("zero wire: wire=%d present=%v err=%v, want (0,true,nil)", wire, present, err)
	}
	_ = zeroWire
}

// TestDrainCompleteFromState17095 pins the typed strong drain predicate:
// every RG local-secondary + peer-primary, peer alive, sync up; any
// UNKNOWN peer row or empty RG set fails closed.
func TestDrainCompleteFromState17095(t *testing.T) {
	t.Parallel()
	rg := func(local, peer pb.RGNodeState) *pb.ClusterRGState {
		return &pb.ClusterRGState{Id: 0, LocalState: local, PeerState: peer}
	}
	drained := &pb.GetClusterHAStateResponse{PeerAlive: true, SyncEstablished: true,
		RedundancyGroups: []*pb.ClusterRGState{rg(pb.RGNodeState_RG_NODE_STATE_SECONDARY, pb.RGNodeState_RG_NODE_STATE_PRIMARY)}}
	if !drainCompleteFromState(drained) {
		t.Error("local secondary + peer primary should be drain-complete")
	}
	for name, st := range map[string]*pb.GetClusterHAStateResponse{
		"local primary":  {PeerAlive: true, SyncEstablished: true, RedundancyGroups: []*pb.ClusterRGState{rg(pb.RGNodeState_RG_NODE_STATE_PRIMARY, pb.RGNodeState_RG_NODE_STATE_PRIMARY)}},
		"both secondary": {PeerAlive: true, SyncEstablished: true, RedundancyGroups: []*pb.ClusterRGState{rg(pb.RGNodeState_RG_NODE_STATE_SECONDARY, pb.RGNodeState_RG_NODE_STATE_SECONDARY)}},
		"peer unknown":   {PeerAlive: true, SyncEstablished: true, RedundancyGroups: []*pb.ClusterRGState{rg(pb.RGNodeState_RG_NODE_STATE_SECONDARY, pb.RGNodeState_RG_NODE_STATE_UNKNOWN)}},
		"no groups":      {PeerAlive: true, SyncEstablished: true},
		"peer dead":      {PeerAlive: false, SyncEstablished: true, RedundancyGroups: drained.RedundancyGroups},
		"sync down":      {PeerAlive: true, SyncEstablished: false, RedundancyGroups: drained.RedundancyGroups},
		"second rg held": {PeerAlive: true, SyncEstablished: true, RedundancyGroups: []*pb.ClusterRGState{drained.RedundancyGroups[0], {Id: 1, LocalState: pb.RGNodeState_RG_NODE_STATE_SECONDARY, PeerState: pb.RGNodeState_RG_NODE_STATE_SECONDARY}}},
		"secondary-hold": {PeerAlive: true, SyncEstablished: true, RedundancyGroups: []*pb.ClusterRGState{rg(pb.RGNodeState_RG_NODE_STATE_SECONDARY_HOLD, pb.RGNodeState_RG_NODE_STATE_PRIMARY)}},
	} {
		if drainCompleteFromState(st) {
			t.Errorf("%s read as drain-complete, want fail-closed", name)
		}
	}
}

// TestRejoinAndTakeoverFromState17095 pins the typed rejoin (every RG
// weight > 0, empty set fails closed) and takeover-ready (any blocker
// RG or dead peer refuses) predicates.
func TestRejoinAndTakeoverFromState17095(t *testing.T) {
	t.Parallel()
	joined := &pb.GetClusterHAStateResponse{PeerAlive: true, RedundancyGroups: []*pb.ClusterRGState{
		{Id: 0, Weight: 255, TakeoverReady: true, TransferReady: true},
		{Id: 1, Weight: 100, TakeoverReady: true, TransferReady: true},
	}}
	if ok, err := localRejoinCompleteFromState(joined, nil); !ok || err != nil {
		t.Errorf("rejoined state: ok=%v err=%v, want (true,nil)", ok, err)
	}
	if !peerTakeoverReadyFromState(joined) {
		t.Error("all-ready state should be takeover-ready")
	}
	held := &pb.GetClusterHAStateResponse{PeerAlive: true, RedundancyGroups: []*pb.ClusterRGState{
		{Id: 0, Weight: 255, TakeoverReady: true, TransferReady: true},
		{Id: 1, Weight: 0, TakeoverReady: true, TransferReady: true},
	}}
	if ok, _ := localRejoinCompleteFromState(held, nil); ok {
		t.Error("RG at weight 0 (ForceSecondary drain) read as rejoined")
	}
	if ok, _ := localRejoinCompleteFromState(&pb.GetClusterHAStateResponse{}, nil); ok {
		t.Error("empty RG set read as rejoined, want fail-closed")
	}
	if _, err := localRejoinCompleteFromState(nil, errors.New("boom")); err == nil {
		t.Error("fetch error swallowed by rejoin predicate")
	}
	blocked := &pb.GetClusterHAStateResponse{PeerAlive: true, RedundancyGroups: []*pb.ClusterRGState{
		{Id: 0, Weight: 255, TakeoverReady: false, TakeoverReasons: []string{"interface down"}, TransferReady: true},
	}}
	if peerTakeoverReadyFromState(blocked) {
		t.Error("takeover-blocked RG read as takeover-ready")
	}
	monFail := &pb.GetClusterHAStateResponse{PeerAlive: true, RedundancyGroups: []*pb.ClusterRGState{
		{Id: 0, Weight: 255, TakeoverReady: true, TransferReady: true, MonitorFailures: []string{"IF"}},
	}}
	if peerTakeoverReadyFromState(monFail) {
		t.Error("monitor-failed RG read as takeover-ready")
	}
	if peerTakeoverReadyFromState(&pb.GetClusterHAStateResponse{PeerAlive: false, RedundancyGroups: joined.RedundancyGroups}) {
		t.Error("dead peer read as takeover-ready")
	}
	if ids, err := configuredRGsFromState(joined, nil); err != nil || len(ids) != 2 || ids[0] != 0 || ids[1] != 1 {
		t.Errorf("configuredRGsFromState = %v, %v; want [0 1]", ids, err)
	}
	if _, err := configuredRGsFromState(&pb.GetClusterHAStateResponse{}, nil); err == nil {
		t.Error("empty RG set enumerated without error, want fail-closed (#5044)")
	}
}

// fakeHAStateClient serves GetClusterHAState / ShowText for the
// fallback-selection cells.
type fakeHAStateClient struct {
	resp     *pb.GetClusterHAStateResponse
	err      error
	infoText string
	statText string
	textErr  error
}

func (f *fakeHAStateClient) GetClusterHAState(context.Context, *pb.GetClusterHAStateRequest, ...grpc.CallOption) (*pb.GetClusterHAStateResponse, error) {
	return f.resp, f.err
}

func (f *fakeHAStateClient) ShowText(_ context.Context, req *pb.ShowTextRequest, _ ...grpc.CallOption) (*pb.ShowTextResponse, error) {
	if f.textErr != nil {
		return nil, f.textErr
	}
	if strings.Contains(req.Topic, "information") {
		return &pb.ShowTextResponse{Output: f.infoText}, nil
	}
	return &pb.ShowTextResponse{Output: f.statText}, nil
}

func testCtxFn() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

// TestHAStateFallbackOnlyOnUnimplemented17095 binds the fallback
// selection: a typed response is used as-is, Unimplemented converts
// the text renders, and any other RPC error refuses (never masked by
// a text re-read).
func TestHAStateFallbackOnlyOnUnimplemented17095(t *testing.T) {
	t.Parallel()
	typed := &pb.GetClusterHAStateResponse{PeerAlive: true, SyncEstablished: true}
	got, err := haStateFromClient(&fakeHAStateClient{resp: typed}, testCtxFn)
	if err != nil || got != typed {
		t.Fatalf("typed response: got=%v err=%v, want the typed state", got, err)
	}

	info := "Remote node: healthy (node1)\nFabric link statistics:\n  Status: Up\n  Bulk sync primed: yes\n"
	stat := "Node name: node0\nHA protocol version: 1\nPeer HA protocol version: 1\n" +
		"Peer session-sync wire version: unknown\n" +
		"Redundancy group: 0 , Failover count: 2\nnode0   100      secondary      yes      no       None\nnode1   200      primary        yes      no       None\n"
	old := &fakeHAStateClient{
		err:      status.Error(codes.Unimplemented, "method GetClusterHAState not implemented"),
		infoText: info, statText: stat,
	}
	got, err = haStateFromClient(old, testCtxFn)
	if err != nil {
		t.Fatalf("Unimplemented fallback: %v", err)
	}
	if !got.GetPeerAlive() || !got.GetSyncEstablished() || !got.GetBulkPrimed() {
		t.Errorf("fallback state lost peer/sync/bulk facts: %+v", got)
	}
	if !drainCompleteFromState(got) {
		t.Errorf("fallback drained fixture not drain-complete: %+v", got.GetRedundancyGroups())
	}
	if got.PeerHaProtocol == nil || got.GetPeerHaProtocol() != 1 {
		t.Errorf("fallback peer HA = %v, want present 1", got.PeerHaProtocol)
	}
	if !got.GetSessionSyncWirePresent() || got.PeerSessionSyncWire != nil {
		t.Error("fallback unknown wire must be present-with-no-value (pre-#7990 permit shape)")
	}

	boom := &fakeHAStateClient{err: status.Error(codes.Unavailable, "connection refused"), infoText: info, statText: stat}
	if _, err := haStateFromClient(boom, testCtxFn); err == nil {
		t.Error("non-Unimplemented RPC error masked by text fallback, want refusal")
	}
}

// TestHAStateFallbackMalformedWireFailsClosed17095 is the #18118 B2
// cell: a pre-#17095 daemon whose status render carries a malformed
// peer session-sync wire value ("banana") must FAIL the fetch, not
// convert it into present+nil which sessionSyncWireVerdictFromState
// PERMITS as advertised-unknown (#14991 fail-open through the
// fallback). Driven through haStateFromClient — the production entry
// — so the strict error must survive haStateFromTextFallback and
// haStateFromText, not only the verdict helper that already checks
// it. A good wire and the unknown shape stay green as controls.
func TestHAStateFallbackMalformedWireFailsClosed17095(t *testing.T) {
	t.Parallel()
	info := "Remote node: healthy (node1)\nFabric link statistics:\n  Status: Up\n  Bulk sync primed: yes\n"
	mkStat := func(wire string) string {
		return "Node name: node0\nHA protocol version: 1\nPeer HA protocol version: 1\n" +
			"Peer session-sync wire version: " + wire + "\n" +
			"Redundancy group: 0 , Failover count: 2\nnode0   100      secondary      yes      no       None\nnode1   200      primary        yes      no       None\n"
	}
	unimpl := status.Error(codes.Unimplemented, "method GetClusterHAState not implemented")
	for _, wire := range []string{"banana", "-1", "70000", "2.5", ""} {
		cli := &fakeHAStateClient{err: unimpl, infoText: info, statText: mkStat(wire)}
		st, err := haStateFromClient(cli, testCtxFn)
		if err == nil {
			t.Errorf("malformed peer wire %q through haStateFromClient: st=%+v err=nil, want fail-closed error (#18118 B2)", wire, st)
			continue
		}
		if st != nil {
			t.Errorf("malformed peer wire %q: got non-nil state alongside error, want nil", wire)
		}
		// The downstream verdict must never see a permitting shape:
		// if a state had been returned, present+nil would permit.
		if st != nil {
			if ok, _, verr := sessionSyncWireVerdictFromState(st); ok && verr == nil {
				t.Errorf("malformed peer wire %q converted to a permitting typed state", wire)
			}
		}
	}
	// Controls: unknown (pre-#7990 permit shape) and a numeric wire
	// still convert without error through the same entry point.
	for _, wire := range []string{"unknown", "2"} {
		cli := &fakeHAStateClient{err: unimpl, infoText: info, statText: mkStat(wire)}
		st, err := haStateFromClient(cli, testCtxFn)
		if err != nil || st == nil {
			t.Errorf("wire %q control: st=%v err=%v, want converted state", wire, st, err)
		}
	}
}

// TestHAStateSkewAddedFieldStaysGreen17095 is the N-driver / N+1-state
// skew cell: a state carrying fields this driver does not know (a
// future RG/state extension, simulated by an unknown enum value and an
// extra group) must not crash or permit unsafely — unknown peer state
// fails the drain closed, known-good groups still pass.
func TestHAStateSkewAddedFieldStaysGreen17095(t *testing.T) {
	t.Parallel()
	future := &pb.GetClusterHAStateResponse{
		PeerAlive: true, SyncEstablished: true,
		LocalHaProtocol: u32p(1), PeerHaProtocol: u32p(1),
		SessionSyncWirePresent: true, PeerSessionSyncWire: u32p(uint32(cluster.SessionSyncWireVersion)),
		RedundancyGroups: []*pb.ClusterRGState{
			{Id: 0, LocalState: pb.RGNodeState_RG_NODE_STATE_SECONDARY, PeerState: pb.RGNodeState_RG_NODE_STATE_PRIMARY, Weight: 255, TakeoverReady: true, TransferReady: true},
			// A future state value this driver predates:
			{Id: 9, LocalState: pb.RGNodeState(99), PeerState: pb.RGNodeState(99), Weight: 255, TakeoverReady: true, TransferReady: true},
		},
	}
	if drainCompleteFromState(future) {
		t.Error("unknown future RG state read as drain-complete, want fail-closed")
	}
	// Without the unknown group the same state is drain-complete: the
	// added field did not break the known predicates.
	knownOnly := &pb.GetClusterHAStateResponse{
		PeerAlive: true, SyncEstablished: true,
		RedundancyGroups: future.RedundancyGroups[:1],
	}
	if !drainCompleteFromState(knownOnly) {
		t.Error("known-good groups no longer drain-complete under skew fixture")
	}
	if compat, _, _ := haProtocolVerdictFromState(future); !compat {
		t.Error("added RG field broke the HA verdict")
	}
}
