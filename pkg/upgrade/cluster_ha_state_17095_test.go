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

// TestHAStateFallbackLocalAbsentPeerPresentNoPanic17095 is the #18118
// F1 cell: the text fallback can leave LocalHaProtocol unset while the
// peer HA line and the peer wire line are present (peer line parses,
// local line missing or garbled). peerProtocolVersionsFromState must
// refuse as an ERROR — the same fail-closed shape checkTargetCompatible
// already gives a peerPresent=false or a transport error — never panic
// dereferencing the absent local, and never report peerPresent for a
// check that cannot run. Driven through peerProtocolVersionsFromStatus
// (haStateFromText + the typed verdict) so the cell exercises the
// fallback conversion, not only the typed helper.
func TestHAStateFallbackLocalAbsentPeerPresentNoPanic17095(t *testing.T) {
	t.Parallel()
	mkStat := func(localLine string) string {
		return "Node name: node0\n" + localLine +
			"Peer HA protocol version: 1\n" +
			"Peer session-sync wire version: 2\n" +
			"Redundancy group: 0 , Failover count: 2\nnode0   100      secondary      yes      no       None\nnode1   200      primary        yes      no       None\n"
	}
	for _, tc := range []struct {
		name      string
		localLine string
	}{
		{"local HA line missing", ""},
		{"local HA line garbled", "HA protocol version: banana\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := haStateFromText("", mkStat(tc.localLine))
			if err != nil {
				t.Fatalf("haStateFromText: %v (conversion must stay readable; the verdict refuses)", err)
			}
			if st.LocalHaProtocol != nil {
				t.Fatalf("local HA = %v, want absent for %q", st.LocalHaProtocol, tc.localLine)
			}
			if st.PeerHaProtocol == nil || !st.GetSessionSyncWirePresent() {
				t.Fatalf("fixture must carry peer HA + wire present: %+v", st)
			}
			// Must not panic (the pre-fold code dereferenced the absent
			// local unconditionally at this exact shape).
			_, _, _, present, err := peerProtocolVersionsFromState(st)
			if err == nil {
				t.Error("local-absent + peer-present: err = nil, want fail-closed error")
			}
			if present {
				t.Error("local-absent + peer-present: peerPresent = true, want false")
			}
			// Same refusal through the fallback-era entry the rolling
			// target gate used before #17095.
			if _, _, _, present, err := peerProtocolVersionsFromStatus(mkStat(tc.localLine)); err == nil || present {
				t.Errorf("peerProtocolVersionsFromStatus: present=%v err=%v, want (false, error)", present, err)
			}
			// The HA equality verdict on the same state stays fail-closed
			// without panicking either.
			if compat, _, _ := haProtocolVerdictFromState(st); compat {
				t.Error("local-absent state read as HA-compatible")
			}
		})
	}
	// Control: local HA present + peer present + wire present still
	// reports the versions, so the refusal above is the absent-local
	// shape and not a blanket refusal.
	if _, peerHA, wire, present, err := peerProtocolVersionsFromStatus(mkStat("HA protocol version: 3\n")); err != nil || !present || peerHA != 1 || wire != 2 {
		t.Errorf("control: peerHA=%d wire=%d present=%v err=%v, want (1, 2, true, nil)", peerHA, wire, present, err)
	}
}

// TestHAStateFallbackUnidentifiedLocalNodeFailsClosed17095 is the
// #18118 F2 cell: when the status render's "Node name:" line is missing
// or unparseable, the text fallback must not default the local node to
// node 0. On a node1 render that default inverts every RG row (the real
// local node1 primary row reads as the peer, the node0 secondary row as
// local), so drainCompleteFromState reported a NOT-drained cluster as
// drained and peerTakeoverReadyFromState reported ready. The old text
// parseDrainComplete failed closed when parseLocalNodeID failed; the
// fallback now leaves every RG's states UNKNOWN and every RG
// takeover-blocked, while the identity-free facts stay readable.
func TestHAStateFallbackUnidentifiedLocalNodeFailsClosed17095(t *testing.T) {
	t.Parallel()
	info := "Remote node: healthy (node0)\nFabric link statistics:\n  Status: Up\n  Bulk sync primed: yes\n" +
		"Redundancy group 0:\n  Takeover ready: yes\n  Transfer ready: yes\n  Monitor failures: none\n"
	// node1's view, NOT drained: local node1 is primary, peer node0 is
	// secondary. Read as local=node0 (the pre-fold default) this exact
	// fixture is "local secondary + peer primary" = drained.
	rows := "Redundancy group: 0 , Failover count: 2\n" +
		"node0   100      secondary      yes      no       None\n" +
		"node1   200      primary        yes      no       None\n"
	haLines := "HA protocol version: 1\nPeer HA protocol version: 1\n" +
		"Peer session-sync wire version: 2\n"
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"Node name line missing", ""},
		{"Node name line garbled", "Node name: banana\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := haStateFromText(info, tc.header+haLines+rows)
			if err != nil {
				t.Fatalf("haStateFromText: %v", err)
			}
			groups := st.GetRedundancyGroups()
			if len(groups) != 1 {
				t.Fatalf("groups = %v, want the one rendered RG", groups)
			}
			if got := groups[0].GetLocalState(); got != pb.RGNodeState_RG_NODE_STATE_UNKNOWN {
				t.Errorf("local state = %v, want UNKNOWN (never inverted)", got)
			}
			if got := groups[0].GetPeerState(); got != pb.RGNodeState_RG_NODE_STATE_UNKNOWN {
				t.Errorf("peer state = %v, want UNKNOWN (never inverted)", got)
			}
			if drainCompleteFromState(st) {
				t.Error("unidentified local node read as drain-complete on a not-drained render")
			}
			if peerTakeoverReadyFromState(st) {
				t.Error("unidentified local node read as takeover-ready")
			}
			// Identity-free facts stay readable: the fallback is a
			// partial instrument, not a blanket refusal.
			if !st.GetPeerAlive() || !st.GetSyncEstablished() {
				t.Errorf("identity-free facts lost: %+v", st)
			}
		})
	}
	// Control: the same render WITH its Node name line identifies
	// node1, reads local=primary / peer=secondary, and is honestly
	// not-drained — so the UNKNOWNs above are the missing identity,
	// not a blanket refusal.
	st, err := haStateFromText(info, "Node name: node1\n"+haLines+rows)
	if err != nil {
		t.Fatalf("control haStateFromText: %v", err)
	}
	groups := st.GetRedundancyGroups()
	if len(groups) != 1 || groups[0].GetLocalState() != pb.RGNodeState_RG_NODE_STATE_PRIMARY ||
		groups[0].GetPeerState() != pb.RGNodeState_RG_NODE_STATE_SECONDARY {
		t.Fatalf("control groups = %v, want local primary / peer secondary", groups)
	}
	if drainCompleteFromState(st) {
		t.Error("control (local primary) read as drain-complete")
	}
	if !peerTakeoverReadyFromState(st) {
		t.Error("control read as not takeover-ready, want ready (no blockers rendered)")
	}
}

// TestHAStateFallbackMalformedRGHeaderBlocksTakeover17095 is the
// #18118 F2 companion cell: a malformed "Redundancy group N:" header in
// the information render resets the blockers parser's cur to -1, so
// that RG's "Takeover ready: no" line is dropped and (pre-fold) every
// RG read takeover-ready. The fallback now marks every RG blocked when
// any RG header is unreadable, so peerTakeoverReadyFromState refuses.
func TestHAStateFallbackMalformedRGHeaderBlocksTakeover17095(t *testing.T) {
	t.Parallel()
	stat := "Node name: node0\nHA protocol version: 1\nPeer HA protocol version: 1\n" +
		"Peer session-sync wire version: 2\n" +
		"Redundancy group: 0 , Failover count: 2\nnode0   100      secondary      yes      no       None\nnode1   200      primary        yes      no       None\n"
	mkInfo := func(header string) string {
		return "Remote node: healthy (node1)\nFabric link statistics:\n  Status: Up\n  Bulk sync primed: yes\n" +
			header + "\n  Takeover ready: no\n  Transfer ready: yes\n  Monitor failures: none\n"
	}
	st, err := haStateFromText(mkInfo("Redundancy group banana:"), stat)
	if err != nil {
		t.Fatalf("haStateFromText: %v", err)
	}
	if peerTakeoverReadyFromState(st) {
		t.Error("malformed RG header read as takeover-ready: the blocked RG's 'Takeover ready: no' was dropped")
	}
	groups := st.GetRedundancyGroups()
	if len(groups) != 1 || groups[0].GetTakeoverReady() || groups[0].GetTransferReady() {
		t.Errorf("groups = %v, want RG0 takeover/transfer blocked on unreadable header", groups)
	}
	// Control: a well-formed header carrying the same blocker also
	// refuses (the blocker path itself), and a well-formed header with
	// no blocker stays ready — the refusal above is the unreadable
	// header, not a blanket refusal.
	st, err = haStateFromText(mkInfo("Redundancy group 0:"), stat)
	if err != nil {
		t.Fatalf("control haStateFromText: %v", err)
	}
	if peerTakeoverReadyFromState(st) {
		t.Error("control: rendered 'Takeover ready: no' read as ready")
	}
	readyInfo := "Remote node: healthy (node1)\nFabric link statistics:\n  Status: Up\n  Bulk sync primed: yes\n" +
		"Redundancy group 0:\n  Takeover ready: yes\n  Transfer ready: yes\n  Monitor failures: none\n"
	st, err = haStateFromText(readyInfo, stat)
	if err != nil {
		t.Fatalf("ready control haStateFromText: %v", err)
	}
	if !peerTakeoverReadyFromState(st) {
		t.Error("ready control read as not takeover-ready, want ready")
	}
}
