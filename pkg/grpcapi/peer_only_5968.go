package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #5968 — the REST include_peer double-WALK.
//
// A REST list / summary / zone-pair request with include_peer=1 walks the LOCAL
// session table in the REST handler, then delegates to the in-process gRPC
// service to obtain the PEER's table. That gRPC method walks the local table
// AGAIN to build its own local answer — and the REST caller discards it,
// keeping only `.Peer`.
//
// #5880 fixed the double-ACQUIRE on this path (the nested call re-acquired the
// shared limiter and self-rejected at capacity); the lease made the nested call
// reuse the parent's slot. The redundant WALK is a different defect and
// survived it: one slot, two full-table traversals, each contending with the
// live session-sync path for per-bucket map locks. On a large table that is a
// straight doubling of the most expensive thing these endpoints do.
//
// The peer-only entry points below fetch the peer table WITHOUT the local walk.
// They are in-process methods on the Go ClusterSessionService interface, not
// registered gRPC methods, so this costs no protobuf or wire change and no
// version negotiation — the REST bridge and the gRPC server are the same
// process by construction.
//
// ADMISSION IS ON THE REMOTE BUDGET (#7294 item 3). These paths drive no local
// walk, so charging them SessionWalkLimiter meant peer-directed work could
// refuse genuine local scans while the local table was untouched. They now take
// diagcmd.RemoteWalkLimiter — same capacity (4), same fail-fast semantics, same
// lease-aware AcquireCtx, but a budget of its own.
//
// This is not a loosening. An unleased peer call was bounded by 4 slots before
// and is bounded by 4 slots now; what changes is WHICH budget, and therefore
// that saturating one can no longer refuse the other. Independence is asserted
// in both directions, following the #8151 precedent that established this shape
// for SnapshotReadLimiter.
//
// #5880's lease-propagation property moves with the path rather than being
// retired: AcquireCtx is still the acquire, so nested in-process delegation
// within one request graph still reuses the ancestor's slot instead of
// self-rejecting — now on the limiter that actually governs this path. The
// guard for it (TestPeerOnlyReusesAnAncestorLease7294) was written against the
// session-walk limiter and is RESTATED, not relaxed: its control still requires
// an unleased call to be refused at capacity, on the budget that now bounds it.
//
// One consequence was fixed BEFORE this change rather than with it (#8306): a
// refused peer fetch on the REST list surface used to be discarded, returning
// 200 with the peer table silently absent. That path was unreachable while
// these methods reused the REST caller's session-walk lease; taking a real
// remote slot makes it reachable, so it had to stop being wrong first.
//
// PEER-STATUS CLASSIFICATION is shared with the full paths through the
// attachPeer* helpers rather than duplicated. A divergence between "how the
// full method classified this peer fetch" and "how the peer-only method
// classified the same fetch" would ALWAYS be a bug, so it is single-sourced
// rather than bound by a test.

// peerFetchErrorStatus classifies a peer-fetch ERROR (#8308).
//
// An admission refusal is NOT a partition. This node returns
// codes.ResourceExhausted when it declines to ask the peer (see the three
// sites below), which means the peer is reachable and the local budget said
// no. Reporting that as UNREACHABLE sends an operator debugging a fabric
// problem after a network fault that does not exist, and #8306 had already
// fixed the wording on the REST surface — so before this, REST said "busy"
// while gRPC said "unreachable" about the same event.
//
// Single-sourced for the same reason the attachPeer* helpers are: a divergence
// between how the full path and the peer-only path classify the same fetch
// would always be a bug.
func peerFetchErrorStatus(perr error) pb.PeerFetchStatus {
	if status.Code(perr) == codes.ResourceExhausted {
		return pb.PeerFetchStatus_PEER_FETCH_STATUS_BUSY
	}
	return pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE
}

// attachPeerSessionSummary classifies one peer summary fetch onto resp (#5320
// semantics, plus #8308): a fetch error is UNREACHABLE with the reason
// attached — or BUSY when it was this node refusing on admission — a result is
// OK, and (nil, nil) is either a standalone node (NOT_APPLICABLE) or a
// clustered node whose peer heartbeat is currently lost (UNREACHABLE — a
// partition, not standalone).
func (s *Server) attachPeerSessionSummary(resp, peerResp *pb.GetSessionSummaryResponse, perr error) {
	switch {
	case perr != nil:
		slog.Warn("failed to fetch peer session summary", "err", perr)
		resp.PeerStatus = peerFetchErrorStatus(perr)
		resp.PeerError = perr.Error()
	case peerResp != nil:
		resp.Peer = peerResp
		resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_OK
	default:
		resp.PeerStatus = s.peerAbsentStatus()
	}
}

// attachPeerZonePairSummary is the zone-pair counterpart (#3592/#5320).
func (s *Server) attachPeerZonePairSummary(resp, peerResp *pb.GetZonePairSummaryResponse, perr error) {
	switch {
	case perr != nil:
		slog.Warn("failed to fetch peer zone-pair summary", "err", perr)
		resp.PeerStatus = peerFetchErrorStatus(perr)
		resp.PeerError = perr.Error()
	case peerResp != nil:
		resp.Peer = peerResp
		resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_OK
	default:
		resp.PeerStatus = s.peerAbsentStatus()
	}
}

// PeerSessions returns ONLY the cluster peer's session list, with no local
// table walk. The returned response carries `Peer` and nothing else; the caller
// already has its own local view.
//
// The request's filters are forwarded so the peer applies the same predicate
// the local list did. IncludePeer is forced on because fetchPeerSessions gates
// on it, and PageToken is preserved because that function suppresses the peer
// fetch on a non-first page — dropping it here would re-attach the peer table
// to every page and over-count it (#3423).
func (s *Server) PeerSessions(ctx context.Context, req *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}
	release, _, err := remoteWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted,
			"peer session fetch concurrency limit reached; retry shortly")
	}
	defer release()
	// Field-by-field rather than a struct copy: a protobuf message embeds a
	// MessageState containing a mutex, so `*req` would copy a lock (go vet
	// catches it). fetchPeerSessions rebuilds its own outbound request from
	// these fields; PageToken is carried because that function suppresses the
	// peer fetch on a non-first page, and dropping it here would re-attach the
	// peer table to every page and over-count it (#3423).
	peerReq := &pb.GetSessionsRequest{IncludePeer: true}
	if req != nil {
		peerReq.Limit = req.Limit
		peerReq.Offset = req.Offset
		peerReq.Zone = req.Zone
		peerReq.Protocol = req.Protocol
		peerReq.SourcePrefix = req.SourcePrefix
		peerReq.DestinationPrefix = req.DestinationPrefix
		peerReq.SourcePort = req.SourcePort
		peerReq.DestinationPort = req.DestinationPort
		peerReq.NatOnly = req.NatOnly
		peerReq.Application = req.Application
		peerReq.InterfaceFilter = req.InterfaceFilter
		peerReq.SourceNatPool = req.SourceNatPool
		peerReq.PageSize = req.PageSize
		peerReq.PageToken = req.PageToken
		peerReq.NoEnrich = req.NoEnrich
	}

	resp := &pb.GetSessionsResponse{}
	s.fetchPeerSessions(ctx, peerReq, resp)
	return resp, nil
}

// PeerSessionSummary returns ONLY the cluster peer's session summary, with no
// local table walk, classified identically to the full GetSessionSummary path.
func (s *Server) PeerSessionSummary(ctx context.Context) (*pb.GetSessionSummaryResponse, error) {
	release, _, err := remoteWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted,
			"peer session fetch concurrency limit reached; retry shortly")
	}
	defer release()

	resp := &pb.GetSessionSummaryResponse{}
	peerResp, perr := s.proxyPeerSessionSummary(ctx, &pb.GetSessionSummaryRequest{})
	s.attachPeerSessionSummary(resp, peerResp, perr)
	return resp, nil
}

// PeerZonePairSummary returns ONLY the cluster peer's zone-pair breakdown, with
// no local table walk.
//
// The forwarded-request recursion guard is preserved: a request that is itself
// a peer-forwarded call must not fan out again. On the REST bridge that guard
// is always satisfied (a REST request carries no in-process peer marker), but
// checking it here keeps the peer-only path's behaviour identical to the full
// path's rather than relying on the caller to be the REST bridge.
func (s *Server) PeerZonePairSummary(ctx context.Context) (*pb.GetZonePairSummaryResponse, error) {
	release, _, err := remoteWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted,
			"peer session fetch concurrency limit reached; retry shortly")
	}
	defer release()

	resp := &pb.GetZonePairSummaryResponse{}
	if peerForwardedFromContext(ctx) {
		resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE
		return resp, nil
	}
	peerResp, perr := s.proxyPeerZonePairSummary(ctx, &pb.GetZonePairSummaryRequest{})
	s.attachPeerZonePairSummary(resp, peerResp, perr)
	return resp, nil
}
