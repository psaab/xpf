// #5320 + #5323 REST surface: the /security/sessions/summary endpoint now
// carries max_sessions (dynamic helper capacity) and peer_status/peer_error
// (include_peer completeness), so a peer partition is no longer served as a
// healthy-looking local-only 200.
package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
)

// statusSummaryDP is a one-session dataplane that also exposes a userspace
// ProcessStatus carrying max_sessions (#5323).
type statusSummaryDP struct {
	*dataplane.Manager
	maxSessions uint64
}

func (d *statusSummaryDP) IsLoaded() bool { return true }

func (d *statusSummaryDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	fn(dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{IsReverse: 0, IngressZone: 2, EgressZone: 3})
	return nil
}

func (d *statusSummaryDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (d *statusSummaryDP) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{MaxSessions: d.maxSessions}, nil
}

// TestRESTSessionSummaryMaxSessions asserts the REST summary surfaces the
// dataplane's dynamic max_sessions from the helper status (#5323).
//
// FAIL-ON-REVERT: dropping the fetchUserspaceStatus plumbing in
// sessionSummaryHandler leaves MaxSessions 0.
func TestRESTSessionSummaryMaxSessions(t *testing.T) {
	s := &Server{
		dp:       &statusSummaryDP{Manager: dataplane.New(), maxSessions: 234567},
		eventBuf: logging.NewEventBuffer(8),
	}
	rr := httptest.NewRecorder()
	s.sessionSummaryHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions/summary", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	sum := decodeSummary(t, rr.Body.Bytes())
	if sum.MaxSessions != 234567 {
		t.Fatalf("max_sessions = %d, want 234567 (dynamic per-table helper capacity)", sum.MaxSessions)
	}
	// Standalone summary makes no peer claim.
	if sum.PeerStatus != "not-applicable" {
		t.Fatalf("peer_status = %q, want not-applicable (standalone, no include_peer)", sum.PeerStatus)
	}
}

// TestRESTSessionSummaryPeerUnreachable asserts include_peer=true with a gRPC
// server reporting a swallowed peer fetch surfaces peer_status=unreachable and
// peer_error on the REST 200 (#5320) — so a peer partition is no longer served
// as a healthy local-only view.
//
// FAIL-ON-REVERT: dropping the pr.GetPeerStatus()/GetPeerError() plumbing
// leaves peer_status empty (or the pre-#5320 silent-nil path), flipping the
// assertion.
func TestRESTSessionSummaryPeerUnreachable(t *testing.T) {
	fake := &fakeClusterSessionService{
		summaryResp: &pb.GetSessionSummaryResponse{
			NodeId:     5,
			PeerStatus: pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE,
			PeerError:  "dial peer node 1: connection refused",
		},
	}
	s := &Server{
		dp:               &oneSessionDP{Manager: dataplane.New()},
		eventBuf:         logging.NewEventBuffer(8),
		nodeIDFn:         func() int { return 5 },
		clusterSessionFn: func() ClusterSessionService { return fake },
	}
	rr := httptest.NewRecorder()
	s.sessionSummaryHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions/summary?include_peer=true", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	sum := decodeSummary(t, rr.Body.Bytes())
	if sum.PeerStatus != "unreachable" {
		t.Fatalf("peer_status = %q, want unreachable (peer partition served as healthy standalone)", sum.PeerStatus)
	}
	if sum.PeerError == "" {
		t.Fatal("peer_error empty on an unreachable peer")
	}
	if sum.Peer != nil {
		t.Fatal("peer summary attached despite unreachable peer")
	}
}

// TestRESTSessionSummaryPeerOK asserts a healthy peer fetch surfaces
// peer_status=ok with the peer summary and its own max_sessions (#5320/#5323).
func TestRESTSessionSummaryPeerOK(t *testing.T) {
	fake := &fakeClusterSessionService{
		summaryResp: &pb.GetSessionSummaryResponse{
			NodeId:     5,
			PeerStatus: pb.PeerFetchStatus_PEER_FETCH_STATUS_OK,
			Peer: &pb.GetSessionSummaryResponse{
				NodeId:       6,
				TotalEntries: 3,
				MaxSessions:  262144,
			},
		},
	}
	s := &Server{
		dp:               &oneSessionDP{Manager: dataplane.New()},
		eventBuf:         logging.NewEventBuffer(8),
		nodeIDFn:         func() int { return 5 },
		clusterSessionFn: func() ClusterSessionService { return fake },
	}
	rr := httptest.NewRecorder()
	s.sessionSummaryHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions/summary?include_peer=true", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	sum := decodeSummary(t, rr.Body.Bytes())
	if sum.PeerStatus != "ok" {
		t.Fatalf("peer_status = %q, want ok", sum.PeerStatus)
	}
	if sum.Peer == nil || sum.Peer.NodeID != 6 || sum.Peer.MaxSessions != 262144 {
		t.Fatalf("peer summary = %+v, want node 6 max 262144", sum.Peer)
	}
}

// TestRESTZonePairsPeerUnreachable asserts the zone-pair endpoint mirrors the
// summary: an unreachable peer is surfaced instead of a silent local-only
// breakdown (#5320).
func TestRESTZonePairsPeerUnreachable(t *testing.T) {
	fake := &fakeClusterSessionService{
		zpResp: &pb.GetZonePairSummaryResponse{
			NodeId:     5,
			PeerStatus: pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE,
			PeerError:  "peer zone-pair: deadline exceeded",
		},
	}
	s := &Server{
		dp:               &oneSessionDP{Manager: dataplane.New()},
		eventBuf:         logging.NewEventBuffer(8),
		nodeIDFn:         func() int { return 5 },
		clusterSessionFn: func() ClusterSessionService { return fake },
	}
	rr := httptest.NewRecorder()
	s.sessionZonePairHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions/summary/zone-pairs?include_peer=true", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data ZonePairSummaryResponse `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rr.Body.String())
	}
	if resp.Data.PeerStatus != "unreachable" {
		t.Fatalf("zone-pair peer_status = %q, want unreachable", resp.Data.PeerStatus)
	}
	if resp.Data.PeerError == "" {
		t.Fatal("zone-pair peer_error empty on unreachable peer")
	}
}
