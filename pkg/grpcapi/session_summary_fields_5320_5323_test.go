// #5320 + #5323: the session-summary RPCs used to SWALLOW a peer-fetch failure
// (slog.Warn then return success with peer=nil, indistinguishable from a
// healthy standalone) and print a HARDCODED Maximum-sessions:10000000. These
// tests pin the additive completeness (peer_status/peer_error) and dynamic
// max_sessions fields.
//
// FAIL-ON-REVERT is called out per test.
package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// summaryFieldsDP is an empty-session dataplane that optionally exposes a
// userspace ProcessStatus carrying max_sessions (#5323). With hasStatus=false
// the Status() call errors, exercising the "no dynamic max" fallback.
type summaryFieldsDP struct {
	*dataplane.Manager
	hasStatus   bool
	maxSessions uint64
}

func (d *summaryFieldsDP) IsLoaded() bool { return true }

func (d *summaryFieldsDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return nil
}

func (d *summaryFieldsDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (d *summaryFieldsDP) Status() (dpuserspace.ProcessStatus, error) {
	if !d.hasStatus {
		return dpuserspace.ProcessStatus{}, errors.New("no userspace status")
	}
	return dpuserspace.ProcessStatus{MaxSessions: d.maxSessions}, nil
}

func newSummaryFieldsServer(t *testing.T, dp grpcRuntime) *Server {
	t.Helper()
	return &Server{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    dp,
	}
}

// TestGetSessionSummaryMaxSessionsFromHelper asserts the response carries the
// helper's dynamic per-table max_sessions from the live status — NOT the old
// hardcoded 10000000 (#5323).
//
// FAIL-ON-REVERT: dropping the resp.MaxSessions = st.MaxSessions plumbing
// leaves MaxSessions 0, flipping the assertion.
func TestGetSessionSummaryMaxSessionsFromHelper(t *testing.T) {
	s := newSummaryFieldsServer(t, &summaryFieldsDP{
		Manager:     dataplane.New(),
		hasStatus:   true,
		maxSessions: 234567,
	})

	resp, err := s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{})
	if err != nil {
		t.Fatalf("GetSessionSummary() error = %v", err)
	}
	if resp.GetMaxSessions() != 234567 {
		t.Fatalf("max_sessions = %d, want 234567 (dynamic per-table helper capacity)", resp.GetMaxSessions())
	}
	if resp.GetMaxSessions() == 10000000 {
		t.Fatal("max_sessions is the retired hardcoded 10000000")
	}
}

// TestGetSessionSummaryMaxSessionsUnknownFallback asserts a dataplane whose
// helper status is unavailable reports max_sessions 0 (rendered as "unknown"
// downstream) rather than a fabricated authoritative bound (#5323).
func TestGetSessionSummaryMaxSessionsUnknownFallback(t *testing.T) {
	s := newSummaryFieldsServer(t, &summaryFieldsDP{Manager: dataplane.New(), hasStatus: false})

	resp, err := s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{})
	if err != nil {
		t.Fatalf("GetSessionSummary() error = %v", err)
	}
	if resp.GetMaxSessions() != 0 {
		t.Fatalf("max_sessions = %d, want 0 (unknown fallback)", resp.GetMaxSessions())
	}
}

// TestGetSessionSummaryPeerStatusOK asserts a successful peer fetch stamps
// peer_status=OK and attaches the peer summary (#5320).
//
// FAIL-ON-REVERT: not setting PeerStatus on the success leg leaves it
// UNSPECIFIED, flipping the OK assertion.
func TestGetSessionSummaryPeerStatusOK(t *testing.T) {
	s := newSummaryFieldsServer(t, &summaryFieldsDP{Manager: dataplane.New()})
	s.peerSessionSummaryFn = func(context.Context) (*pb.GetSessionSummaryResponse, error) {
		return &pb.GetSessionSummaryResponse{NodeId: 1, TotalEntries: 7}, nil
	}

	resp, err := s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{IncludePeer: true})
	if err != nil {
		t.Fatalf("GetSessionSummary() error = %v", err)
	}
	if resp.GetPeerStatus() != pb.PeerFetchStatus_PEER_FETCH_STATUS_OK {
		t.Fatalf("peer_status = %v, want OK", resp.GetPeerStatus())
	}
	if resp.GetPeer() == nil || resp.GetPeer().GetNodeId() != 1 {
		t.Fatalf("peer summary not attached: %+v", resp.GetPeer())
	}
	if resp.GetPeerError() != "" {
		t.Fatalf("peer_error = %q, want empty on OK", resp.GetPeerError())
	}
}

// TestGetSessionSummaryPeerStatusUnreachable is the core #5320 regression: a
// FAILING peer fetch must be distinguishable from a healthy standalone. The
// RPC still succeeds with the local totals, but peer_status=UNREACHABLE and
// peer_error carries the detail.
//
// FAIL-ON-REVERT: restoring the slog.Warn-and-swallow leaves peer_status
// UNSPECIFIED (not UNREACHABLE) and peer_error empty — a peer partition again
// looks like a healthy standalone.
func TestGetSessionSummaryPeerStatusUnreachable(t *testing.T) {
	s := newSummaryFieldsServer(t, &summaryFieldsDP{Manager: dataplane.New()})
	s.peerSessionSummaryFn = func(context.Context) (*pb.GetSessionSummaryResponse, error) {
		return nil, errors.New("dial peer node 1: connection refused")
	}

	resp, err := s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{IncludePeer: true})
	if err != nil {
		t.Fatalf("GetSessionSummary() should still return the local totals, got error = %v", err)
	}
	if resp.GetPeerStatus() != pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE {
		t.Fatalf("peer_status = %v, want UNREACHABLE (peer-fetch failure swallowed)", resp.GetPeerStatus())
	}
	if resp.GetPeer() != nil {
		t.Fatal("peer must be nil on an unreachable fetch")
	}
	if resp.GetPeerError() == "" {
		t.Fatal("peer_error empty on UNREACHABLE — the failure detail was dropped")
	}
}

// TestGetSessionSummaryPeerStatusNotApplicable asserts a healthy standalone
// node (no cluster, include_peer requested but no peer to fetch) reports
// NOT_APPLICABLE — distinct from UNREACHABLE (#5320).
func TestGetSessionSummaryPeerStatusNotApplicable(t *testing.T) {
	s := newSummaryFieldsServer(t, &summaryFieldsDP{Manager: dataplane.New()})
	// No cluster, no seam: proxyPeerSessionSummary returns (nil, nil).
	resp, err := s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{IncludePeer: true})
	if err != nil {
		t.Fatalf("GetSessionSummary() error = %v", err)
	}
	if resp.GetPeerStatus() != pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE {
		t.Fatalf("peer_status = %v, want NOT_APPLICABLE for a standalone node", resp.GetPeerStatus())
	}

	// include_peer unset also reports NOT_APPLICABLE (no claim about a peer).
	resp, err = s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{})
	if err != nil {
		t.Fatalf("GetSessionSummary() error = %v", err)
	}
	if resp.GetPeerStatus() != pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE {
		t.Fatalf("peer_status = %v, want NOT_APPLICABLE without include_peer", resp.GetPeerStatus())
	}
}

// TestGetZonePairSummaryPeerStatusUnreachable asserts the zone-pair RPC also
// classifies a failed peer fetch as UNREACHABLE instead of swallowing it
// (#5320), mirroring GetSessionSummary.
//
// FAIL-ON-REVERT: reverting the switch to the old "else if peerResp != nil"
// swallow leaves peer_status UNSPECIFIED.
func TestGetZonePairSummaryPeerStatusUnreachable(t *testing.T) {
	s := newZonePairServer(t, &twoZonePairDP{Manager: dataplane.New()})
	s.peerZonePairSummaryFn = func(context.Context, *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error) {
		return nil, errors.New("peer zone-pair: deadline exceeded")
	}

	resp, err := s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{IncludePeer: true})
	if err != nil {
		t.Fatalf("GetZonePairSummary() error = %v", err)
	}
	if resp.GetPeerStatus() != pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE {
		t.Fatalf("peer_status = %v, want UNREACHABLE", resp.GetPeerStatus())
	}
	if resp.GetPeerError() == "" {
		t.Fatal("peer_error empty on UNREACHABLE zone-pair fetch")
	}
}

// TestGetZonePairSummaryPeerStatusOKAndNotApplicable asserts the OK (peer
// attached) and NOT_APPLICABLE (no include_peer) classifications for the
// zone-pair RPC (#5320).
func TestGetZonePairSummaryPeerStatusOKAndNotApplicable(t *testing.T) {
	s := newZonePairServer(t, &twoZonePairDP{Manager: dataplane.New()})
	s.peerZonePairSummaryFn = func(context.Context, *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error) {
		return &pb.GetZonePairSummaryResponse{NodeId: 1}, nil
	}
	resp, err := s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{IncludePeer: true})
	if err != nil {
		t.Fatalf("GetZonePairSummary() error = %v", err)
	}
	if resp.GetPeerStatus() != pb.PeerFetchStatus_PEER_FETCH_STATUS_OK {
		t.Fatalf("peer_status = %v, want OK", resp.GetPeerStatus())
	}

	// No include_peer -> NOT_APPLICABLE.
	resp, err = s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{})
	if err != nil {
		t.Fatalf("GetZonePairSummary() error = %v", err)
	}
	if resp.GetPeerStatus() != pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE {
		t.Fatalf("peer_status = %v, want NOT_APPLICABLE without include_peer", resp.GetPeerStatus())
	}
}
