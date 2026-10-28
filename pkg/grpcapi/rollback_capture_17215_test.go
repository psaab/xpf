package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #17215 (gRPC arm): ShowCompare/ShowRollback for a classed principal
// must surface the SAME error class as the ungated handler: the
// captured slot error verbatim (history out-of-range), and "not in
// configuration mode" for a resolved slot with no candidate — never a
// synthesized spelling or a success. The gate returns the slot error
// as InvalidArgument (grpcConfigReadSlotError at the authz boundary);
// direct handler calls with a captured snapshot exercise SlotErr.

func TestGRPCRollbackCapture17215(t *testing.T) {
	s := ancestor15995Server(t)
	s.store.ExitConfigure() // no candidate
	ctx := ctxWithPeerUID(uidOpen15995)

	// Missing slot, candidate-baseline compare: gate InvalidArgument
	// carrying the history error.
	_, err := s.authorizeRPCContext(ctx, show14707Method("ShowCompare"),
		&pb.ShowCompareRequest{RollbackN: 40})
	if st, _ := status.FromError(err); err == nil || st.Code() != codes.InvalidArgument || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("ShowCompare rollback=40 gate = %v, want InvalidArgument out-of-range", err)
	}
	// Missing slot, show-rollback.
	_, err = s.authorizeRPCContext(ctx, show14707Method("ShowRollback"),
		&pb.ShowRollbackRequest{N: 40})
	if st, _ := status.FromError(err); err == nil || st.Code() != codes.InvalidArgument || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("ShowRollback n=40 gate = %v, want InvalidArgument out-of-range", err)
	}

	// Resolved slot, no candidate: compare admitted at the gate, the
	// handler returns the mode error (TestShowCompareNoCandidateMode15995
	// covers the ancestor class; here the open class + handler arm).
	actx, err := s.authorizeRPCContext(ctx, show14707Method("ShowCompare"),
		&pb.ShowCompareRequest{RollbackN: 1})
	if err != nil {
		t.Fatalf("authorize slot-1 compare (open): %v", err)
	}
	if _, herr := s.ShowCompare(actx, &pb.ShowCompareRequest{RollbackN: 1}); herr == nil ||
		!strings.Contains(herr.Error(), "not in configuration mode") {
		t.Errorf("ShowCompare slot-1 no-candidate = %v, want mode error", herr)
	}
	// ShowRollback slot 1 renders without a candidate.
	rctx, err := s.authorizeRPCContext(ctx, show14707Method("ShowRollback"),
		&pb.ShowRollbackRequest{N: 1})
	if err != nil {
		t.Fatalf("authorize show-rollback 1 (open): %v", err)
	}
	resp, herr := s.ShowRollback(rctx, &pb.ShowRollbackRequest{N: 1})
	if herr != nil || !strings.Contains(resp.Output, "ancestor-15995") {
		t.Errorf("ShowRollback 1 = herr %v output %q, want slot content", herr, resp)
	}

	// Handler-level: a captured snapshot carrying SlotErr surfaces it
	// verbatim on both handlers (no second live-store read).
	bad := configReadSnapshots{Present: true, SlotErr: errors.New("history position 39 out of range [0, 1)")}
	hctx := context.WithValue(ctx, configReadSnapshotsKey{}, bad)
	if _, herr := s.ShowRollback(hctx, &pb.ShowRollbackRequest{N: 40}); herr == nil ||
		!strings.Contains(herr.Error(), "out of range") {
		t.Errorf("ShowRollback captured SlotErr = %v, want out-of-range", herr)
	}
	if _, herr := s.ShowCompare(hctx, &pb.ShowCompareRequest{RollbackN: 40}); herr == nil ||
		!strings.Contains(herr.Error(), "out of range") {
		t.Errorf("ShowCompare captured SlotErr = %v, want out-of-range", herr)
	}
	// #17215 fold: the handler's nil-Primary arm without a captured
	// slot error must NOT synthesize "rollback slot %d not found".
	// CaptureRollback invariants make Primary==nil imply Err!=nil for
	// slotted captures (rollbackTree(0) yields the — possibly nil —
	// active tree with no error, so RollbackN==0 with no active renders
	// empty; a nil store yields no capture), so this state is only
	// constructible by hand: pin that it falls through to the
	// renderer, not an error. Before the fold this returned the
	// synthesized spelling. ActiveBaseline gets past the mode arm.
	noErr := configReadSnapshots{Present: true}
	nctx := context.WithValue(ctx, configReadSnapshotsKey{}, noErr)
	// No path: the unscoped diff of a nil slot arm against the
	// active tree renders "" (FormatCompare would dereference a nil
	// arm, so scope the request the way a priced snapshot is consumed
	// — path-scoped rendering tolerates the absent arm exactly as
	// ShowRollback renders a nil Primary as "").
	// No-slot content at the scoped path renders "[no changes]" (the
	// absent arm contributes nothing against the active arm) — the
	// contract is only: no error, no synthesized slot text.
	resp2, herr := s.ShowCompare(nctx, &pb.ShowCompareRequest{RollbackN: 1, ActiveBaseline: true, Path: []string{"system"}})
	if herr != nil || resp2 == nil || strings.Contains(resp2.Output, "not found") {
		t.Errorf("ShowCompare nil Primary / nil SlotErr = resp %v err %v, want no error and no synthesized slot text", resp2, herr)
	}
}
