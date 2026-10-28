package grpcapi

import (
	"context"

	"github.com/psaab/xpf/pkg/cluster"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetClusterHAState serves the typed HA state behind every rolling /
// kernel-drain safety predicate (#17095). Before #17095 the upgrade
// driver scraped `show chassis cluster information|status` text; the
// typed channel makes absent / zero / malformed distinguishable by
// construction (see proto/xpf/v1/xpf.proto and pkg/cluster.HAState).
//
// A standalone node (no cluster manager) is FailedPrecondition, not a
// fabricated empty state: the drain predicates must refuse, and an
// empty-but-OK response could be misread as "no RGs, nothing to drain".
func (s *Server) GetClusterHAState(_ context.Context, _ *pb.GetClusterHAStateRequest) (*pb.GetClusterHAStateResponse, error) {
	if s.cluster == nil {
		return nil, status.Error(codes.FailedPrecondition, "node is not in a cluster")
	}
	return HAStateToProto(s.cluster.HAState()), nil
}

// HAStateToProto converts the cluster typed state to the wire form.
// NodeState values map to RGNodeState with UNKNOWN for anything the
// wire does not know, so an unexpected local state fails closed in the
// consumer rather than aliasing to a real state.
func HAStateToProto(st cluster.HAState) *pb.GetClusterHAStateResponse {
	resp := &pb.GetClusterHAStateResponse{
		LocalNodeId:            int32(st.LocalNodeID),
		ClusterId:              int32(st.ClusterID),
		PeerAlive:              st.PeerAlive,
		PeerNodeId:             int32(st.PeerNodeID),
		SyncEstablished:        st.SyncEstablished,
		BulkPrimed:             st.BulkPrimed,
		SessionSyncWirePresent: st.PeerSessionSyncWirePresent,
		LocalSessionSyncWire:   uint32(st.LocalSessionSyncWire),
		RedundancyGroups:       make([]*pb.ClusterRGState, 0, len(st.Groups)),
	}
	local := uint32(st.LocalHAProtocol)
	resp.LocalHaProtocol = &local
	if st.PeerHAProtocol != nil {
		peer := uint32(*st.PeerHAProtocol)
		resp.PeerHaProtocol = &peer
	}
	if st.PeerSessionSyncWire != nil {
		wire := uint32(*st.PeerSessionSyncWire)
		resp.PeerSessionSyncWire = &wire
	}
	for _, g := range st.Groups {
		rg := &pb.ClusterRGState{
			Id:              int32(g.ID),
			LocalState:      nodeStateToProto(g.LocalState),
			PeerState:       pb.RGNodeState_RG_NODE_STATE_UNKNOWN,
			TakeoverReady:   g.TakeoverReady,
			TakeoverReasons: g.TakeoverReasons,
			TransferReady:   g.TransferReady,
			TransferReasons: g.TransferReasons,
			Weight:          int32(g.Weight),
			FailoverCount:   int32(g.FailoverCount),
			LocalPriority:   int32(g.LocalPriority),
			PeerPriority:    int32(g.PeerPriority),
			MonitorFailures: g.MonitorFailures,
		}
		if g.PeerStateKnown {
			rg.PeerState = nodeStateToProto(g.PeerState)
		}
		resp.RedundancyGroups = append(resp.RedundancyGroups, rg)
	}
	return resp
}

func nodeStateToProto(s cluster.NodeState) pb.RGNodeState {
	switch s {
	case cluster.StateSecondary:
		return pb.RGNodeState_RG_NODE_STATE_SECONDARY
	case cluster.StatePrimary:
		return pb.RGNodeState_RG_NODE_STATE_PRIMARY
	case cluster.StateSecondaryHold:
		return pb.RGNodeState_RG_NODE_STATE_SECONDARY_HOLD
	case cluster.StateLost:
		return pb.RGNodeState_RG_NODE_STATE_LOST
	case cluster.StateDisabled:
		return pb.RGNodeState_RG_NODE_STATE_DISABLED
	default:
		return pb.RGNodeState_RG_NODE_STATE_UNKNOWN
	}
}
