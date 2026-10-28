package upgrade

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"time"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/cluster"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// grpcCluster is the production RollingCluster backed by the xpfd gRPC API
// on the LOCAL node. It uses the NON-INTERACTIVE SystemAction RPC for
// mutations (the documented automation path — the interactive `cli -c
// "request ... in-service-upgrade"` hard-errors in non-TTY mode, #1563)
// and the typed GetClusterHAState RPC (#17095) for every drain-predicate
// read.
//
// Before #17095 the predicates scraped `show chassis cluster
// information|status` text (22 parse/verdict functions): a present-but-
// garbled value collapsed to 0 and permitted a drain (#14991), and any
// operator-facing rewording could abort or permit a roll. The typed RPC
// carries presence explicitly, so absent / zero / malformed are distinct
// by construction. The text parsers survive ONLY as a fallback for a
// peer daemon that does not implement GetClusterHAState yet
// (codes.Unimplemented — a pre-#17095 daemon during the one-release
// skew window); they are deleted with the fallback after that window.
// A typed response is never re-judged through the text parsers, and a
// non-Unimplemented RPC error is never masked by falling back.
type grpcCluster struct {
	addr        string
	dialTimeout time.Duration
}

// NewCLICluster returns a RollingCluster driving the SELECTED systemd unit's
// xpfd via gRPC. The name is retained for the cmd wiring; the implementation
// is the gRPC client (not the interactive `cli`).
//
// The cluster control RPCs (PeerAlive / SyncEstablished / DrainComplete /
// ForceSecondary / ResetFailover) target a single hard-coded local endpoint
// (127.0.0.1:50051). The systemd action side (stop/start/flip) honors the
// --unit selection, so a non-default --unit would cut one daemon while the
// drain predicate and ForceSecondary control ANOTHER — wrong-daemon control
// (#1983). Until a unit->endpoint mapping exists, only the default unit is
// supported; any other unit is REJECTED here at the single construction
// chokepoint so cluster RPCs can never silently target the wrong daemon
// while systemd actions hit a different one. Centralizing the guard in the
// constructor covers ALL callers (RunRolling + `xpfd upgrade kernel
// drain`/`rejoin`, which also pass --unit through) and any future caller
// automatically. --unit takes the BARE unit name (e.g. "xpfd"); the systemd
// layer appends ".service" itself (system_linux.go), so "xpfd.service" is a
// non-default spelling and is rejected.
func NewCLICluster(unit string) (RollingCluster, error) {
	if unit != "" && unit != DefaultUnit {
		return nil, fmt.Errorf("cluster control for systemd unit %q is "+
			"unsupported: the rolling/kernel upgrade control RPCs target the "+
			"default daemon at 127.0.0.1:50051, so a non-default --unit would "+
			"drive cluster failover against the WRONG daemon while systemd "+
			"actions hit %q (a per-unit control endpoint is not yet mapped; "+
			"use the default unit %q)", unit, unit, DefaultUnit)
	}
	return &grpcCluster{addr: "127.0.0.1:50051", dialTimeout: 5 * time.Second}, nil
}

func (g *grpcCluster) dial() (pb.BpfrxServiceClient, func(), error) {
	// #14581: this endpoint is the hard-coded loopback management port;
	// verify the server is privileged-owned at dial time (see authz).
	conn, err := grpc.NewClient(g.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(authz.DialContext))
	if err != nil {
		return nil, nil, fmt.Errorf("dial xpfd gRPC %s: %w", g.addr, err)
	}
	return pb.NewBpfrxServiceClient(conn), func() { _ = conn.Close() }, nil
}

const (
	rollingForceSecondaryBarrierTimeout = 60 * time.Second
	rollingForceSecondaryRetrySlack     = 5 * time.Second
	rollingForceSecondaryHandoffTimeout = 10 * time.Second
	rollingForceSecondaryDeadlineMargin = 15 * time.Second
)

// rollingForceSecondaryActionTimeoutForRGs covers ForceSecondary's sequential
// per-active-RG barrier waits, each RG's admission retry slack, and the
// observed peer-handoff wait. The production caller uses the maximum
// representable RG count: the daemon snapshots the active set only after the
// RPC begins, so a conservative bound here prevents a status read/ForceSecondary
// race from under-deadlining the action.
func rollingForceSecondaryActionTimeoutForRGs(activeRGCount int) time.Duration {
	if activeRGCount < 1 {
		activeRGCount = 1
	}
	return time.Duration(activeRGCount)*
		(rollingForceSecondaryBarrierTimeout+rollingForceSecondaryRetrySlack) +
		rollingForceSecondaryHandoffTimeout + rollingForceSecondaryDeadlineMargin
}

func (g *grpcCluster) actionCtx(action string, activeRGCount int) (context.Context, context.CancelFunc) {
	timeout := g.dialTimeout
	if action == "in-service-upgrade" {
		timeout = rollingForceSecondaryActionTimeoutForRGs(activeRGCount)
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (g *grpcCluster) systemAction(action string) error {
	cli, closeFn, err := g.dial()
	if err != nil {
		return err
	}
	defer closeFn()
	ctx, cancel := g.actionCtx(action, config.MaxRedundancyGroups)
	defer cancel()
	_, err = cli.SystemAction(ctx, &pb.SystemActionRequest{Action: action})
	return err
}

func (g *grpcCluster) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), g.dialTimeout)
}

// haStateClient is the slice of the gRPC client the HA-state reads use.
// It is a seam so the typed verdicts and the Unimplemented fallback are
// unit-tested without a live dial (#17095).
type haStateClient interface {
	GetClusterHAState(ctx context.Context, in *pb.GetClusterHAStateRequest, opts ...grpc.CallOption) (*pb.GetClusterHAStateResponse, error)
	ShowText(ctx context.Context, in *pb.ShowTextRequest, opts ...grpc.CallOption) (*pb.ShowTextResponse, error)
}

// haState fetches the typed HA state. Only codes.Unimplemented (a
// pre-#17095 daemon) falls back to the text parsers; every other error
// is returned so an unreadable instrument refuses rather than being
// re-judged through a second, text-shaped opinion.
func (g *grpcCluster) haState() (*pb.GetClusterHAStateResponse, error) {
	cli, closeFn, err := g.dial()
	if err != nil {
		return nil, err
	}
	defer closeFn()
	return haStateFromClient(cli, g.ctx)
}

func haStateFromClient(cli haStateClient, ctxFn func() (context.Context, context.CancelFunc)) (*pb.GetClusterHAStateResponse, error) {
	ctx, cancel := ctxFn()
	resp, err := cli.GetClusterHAState(ctx, &pb.GetClusterHAStateRequest{})
	cancel()
	if err == nil {
		return resp, nil
	}
	if status.Code(err) != codes.Unimplemented {
		return nil, fmt.Errorf("get cluster HA state: %w", err)
	}
	// Pre-#17095 daemon: one-release text fallback (#17095). Deleted
	// with the parsers in cluster_cli_text_fallback.go after the window.
	return haStateFromTextFallback(cli, ctxFn)
}

func (g *grpcCluster) PeerAlive() (bool, error) {
	st, err := g.haState()
	if err != nil {
		return false, err
	}
	return st.GetPeerAlive(), nil
}

func (g *grpcCluster) SyncEstablished() (bool, error) {
	st, err := g.haState()
	if err != nil {
		return false, err
	}
	return st.GetSyncEstablished(), nil
}

func (g *grpcCluster) SessionSyncBulkPrimed() (bool, error) {
	st, err := g.haState()
	if err != nil {
		return false, err
	}
	return st.GetBulkPrimed(), nil
}

func (g *grpcCluster) DrainComplete() (bool, error) {
	st, err := g.haState()
	if err != nil {
		return false, err
	}
	return drainCompleteFromState(st), nil
}

// drainCompleteFromState is the typed STRONG drain predicate (#17095):
// peer alive + sync established, and for EVERY redundancy group the
// local row is secondary AND the peer row is primary. An RG with no
// peer row (UNKNOWN) or an empty RG set fails closed — the same
// per-RG pairing the text parser enforced (Codex r3 High).
func drainCompleteFromState(st *pb.GetClusterHAStateResponse) bool {
	if st == nil || !st.GetPeerAlive() || !st.GetSyncEstablished() {
		return false
	}
	groups := st.GetRedundancyGroups()
	if len(groups) == 0 {
		return false
	}
	for _, rg := range groups {
		if rg.GetLocalState() != pb.RGNodeState_RG_NODE_STATE_SECONDARY ||
			rg.GetPeerState() != pb.RGNodeState_RG_NODE_STATE_PRIMARY {
			return false
		}
	}
	return true
}

func (g *grpcCluster) HAProtocolCompatible() (bool, error) {
	st, err := g.haState()
	if err != nil {
		return false, err
	}
	compat, _, _ := haProtocolVerdictFromState(st)
	return compat, nil
}

// haProtocolVerdictFromState is the typed decision half of
// HAProtocolCompatible: compatible iff both HA versions are PRESENT
// and equal. Absent (peer not alive / field not carried) fails closed
// with zero values for logging, mirroring the text verdict.
func haProtocolVerdictFromState(st *pb.GetClusterHAStateResponse) (bool, uint16, uint16) {
	if st == nil || st.LocalHaProtocol == nil || st.PeerHaProtocol == nil {
		return false, 0, 0
	}
	local, peer := uint16(*st.LocalHaProtocol), uint16(*st.PeerHaProtocol)
	return local == peer, local, peer
}

// PeerProtocolVersions returns the local/peer HA versions and the peer
// session-sync wire version from ONE typed fetch (#17095, ex-#14991).
// Absent peer values are reported via peerPresent=false (the caller
// decides — the rolling target gate refuses); malformed is
// unrepresentable in the typed channel, so there is no error case
// beyond transport.
func (g *grpcCluster) PeerProtocolVersions() (uint16, uint16, uint16, bool, error) {
	st, err := g.haState()
	if err != nil {
		return 0, 0, 0, false, err
	}
	return peerProtocolVersionsFromState(st)
}

func peerProtocolVersionsFromState(st *pb.GetClusterHAStateResponse) (uint16, uint16, uint16, bool, error) {
	if st != nil && st.LocalHaProtocol == nil && st.PeerHaProtocol != nil {
		// Absent local with a present peer is a garbled instrument, not
		// a zero local version: the typed server always carries the
		// local value (HAStateToProto), so this shape can only come
		// from the text fallback failing to parse the local HA line
		// while the peer line parsed. Refuse as an error — never
		// dereference the absent local, and never report peerPresent
		// for a check that cannot run (#18118 F1).
		return 0, 0, 0, false, fmt.Errorf("local HA protocol version not present in " +
			"cluster HA state while peer HA protocol is present — the compatibility " +
			"check cannot run, and an unreadable instrument is not evidence of compatibility")
	}
	if st == nil || st.PeerHaProtocol == nil || !st.GetSessionSyncWirePresent() {
		var local uint16
		if st != nil && st.LocalHaProtocol != nil {
			local = uint16(*st.LocalHaProtocol)
		}
		return local, 0, 0, false, nil
	}
	var wire uint16
	if st.PeerSessionSyncWire != nil {
		wire = uint16(*st.PeerSessionSyncWire)
	}
	return uint16(*st.LocalHaProtocol), uint16(*st.PeerHaProtocol), wire, true, nil
}

// SessionSyncWireCompatible reads the peer's advertised session-sync
// wire version from the typed state and asks pkg/cluster for the
// verdict (#7990). The verdict lives in pkg/cluster so there is ONE
// definition of "compatible" shared with the runtime side.
func (g *grpcCluster) SessionSyncWireCompatible() (bool, string, error) {
	st, err := g.haState()
	if err != nil {
		return false, "", err
	}
	return sessionSyncWireVerdictFromState(st)
}

// sessionSyncWireVerdictFromState is the typed decision half of
// SessionSyncWireCompatible (#17095). The absent-field case refuses as
// an ERROR (the instrument could not be read), exactly like the text
// verdict: the server renders the peer wire field whenever the peer is
// alive and PeerAlive gates first, so absence means the state could
// not be carried — never evidence of compatibility. A present field
func sessionSyncWireVerdictFromState(st *pb.GetClusterHAStateResponse) (bool, string, error) {
	if st == nil || !st.GetSessionSyncWirePresent() {
		return false, "", fmt.Errorf("peer session-sync wire version not present in " +
			"cluster HA state — the check cannot run, and an unreadable " +
			"instrument is not evidence of compatibility")
	}
	var peer uint16
	if st.PeerSessionSyncWire != nil {
		peer = uint16(*st.PeerSessionSyncWire)
	}
	okv, reason := cluster.SessionSyncWireCompatible(peer)
	return okv, reason, nil
}

func (g *grpcCluster) PeerTakeoverReady() (bool, error) {
	st, err := g.haState()
	if err != nil {
		return false, err
	}
	return peerTakeoverReadyFromState(st), nil
}

// peerTakeoverReadyFromState is the typed best-effort pre-demotion gate
// (#17095): peer alive, and no LOCAL RG carries a takeover blocker
// (takeover not ready incl. the hold window, transfer not ready, or a
// monitor failure). The AUTHORITATIVE guard remains DrainComplete,
// which after demotion confirms the peer actually holds primary for
// every RG (rolling.go).
func peerTakeoverReadyFromState(st *pb.GetClusterHAStateResponse) bool {
	if st == nil || !st.GetPeerAlive() {
		return false
	}
	for _, rg := range st.GetRedundancyGroups() {
		if !rg.GetTakeoverReady() || !rg.GetTransferReady() || len(rg.GetMonitorFailures()) > 0 {
			return false
		}
	}
	return true
}

func (g *grpcCluster) ForceSecondary() error {
	// Non-interactive demote via the documented automation path.
	return g.systemAction("in-service-upgrade")
}

func (g *grpcCluster) ResetFailover() error {
	// The orchestrator rejoin is a NODE rejoin, not a set of per-RG
	// resets: it must clear every configured RG's manual failover AND the
	// node-global kernel-upgrade election hold, synchronously (#15239,
	// A56-01). The single `cluster-rejoin` action does exactly that
	// (Manager.ResetAllFailover). Fail closed on the action error:
	// RejoinAndConfirm's per-RG readback (LocalRejoinComplete,
	// #5044/#5138) then refuses to confirm, so the roll stops instead of
	// advancing to drain the peer.
	return g.systemAction("cluster-rejoin")
}

// configuredRGs returns the redundancy-group IDs from the typed state.
// It FAILS CLOSED (#5044) rather than guessing a hardcoded set: a fetch
// error or an empty RG set is an error, never the pre-#5044 {0,1,2}
// guess that stranded RG>=3 (see configuredRGsFromState).
func (g *grpcCluster) configuredRGs() ([]int, error) {
	st, err := g.haState()
	return configuredRGsFromState(st, err)
}

func configuredRGsFromState(st *pb.GetClusterHAStateResponse, stateErr error) ([]int, error) {
	if stateErr != nil {
		return nil, fmt.Errorf("enumerate configured redundancy groups: %w", stateErr)
	}
	groups := st.GetRedundancyGroups()
	if len(groups) == 0 {
		return nil, fmt.Errorf("enumerate configured redundancy groups: " +
			"no redundancy groups found in cluster HA state")
	}
	out := make([]int, 0, len(groups))
	for _, rg := range groups {
		out = append(out, int(rg.GetId()))
	}
	return out, nil
}

// LocalRejoinComplete reports whether the local node has left the
// ForceSecondary drain for EVERY configured redundancy group (#5138):
// every RG in the typed state has weight > 0. ForceSecondary pins
// weight 0; ResetFailover restores it via re-election, so a configured
// RG still at weight 0 — or an empty RG set — is NOT yet rejoined.
func (g *grpcCluster) LocalRejoinComplete() (bool, error) {
	st, err := g.haState()
	return localRejoinCompleteFromState(st, err)
}

func localRejoinCompleteFromState(st *pb.GetClusterHAStateResponse, stateErr error) (bool, error) {
	if stateErr != nil {
		return false, fmt.Errorf("read cluster HA state for per-RG rejoin: %w", stateErr)
	}
	groups := st.GetRedundancyGroups()
	if len(groups) == 0 {
		return false, nil
	}
	for _, rg := range groups {
		if rg.GetWeight() <= 0 {
			return false, nil
		}
	}
	return true, nil
}

func (g *grpcCluster) LocalPrimary() (bool, error) {
	st, err := g.haState()
	if err != nil {
		return false, err
	}
	for _, rg := range st.GetRedundancyGroups() {
		if rg.GetLocalState() == pb.RGNodeState_RG_NODE_STATE_PRIMARY {
			return true, nil
		}
	}
	return false, nil
}
