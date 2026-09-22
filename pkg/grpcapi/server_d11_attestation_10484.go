package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func d11LedgerPrincipalAllowed(principal authz.Principal, cfgs ...*config.Config) bool {
	var cfg *config.Config
	if len(cfgs) != 0 {
		cfg = cfgs[0]
	}
	return principal.Source == authz.SourcePeerUID &&
		(principal.UID == 0 ||
			principal.Superuser ||
			config.ClassHasPermission(cfg, principal.Class, config.PermMaint))
}

func (s *Server) d11AuthorizationConfig() *config.Config {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.ActiveConfig()
}

// GetD11AttestationLedger is restricted to local root or the configured
// super-user class. The ledger is intentionally a snapshot: callers cannot
// mutate admission state or request a second arm through this read surface.
func (s *Server) GetD11AttestationLedger(ctx context.Context, _ *xpfv1.GetD11AttestationLedgerRequest) (*xpfv1.GetD11AttestationLedgerResponse, error) {
	principal, ok := authorizedPrincipalFromContext(ctx)
	if !ok || !d11LedgerPrincipalAllowed(principal, s.d11AuthorizationConfig()) {
		return nil, status.Error(codes.PermissionDenied, "D11 attestation ledger requires uid 0 or the configured super-user class")
	}
	if s == nil || s.d11LedgerFn == nil {
		return nil, status.Error(codes.Unimplemented, "D11 attestation ledger is unavailable")
	}
	snapshot := s.d11LedgerFn()
	if snapshot == nil {
		return nil, status.Error(codes.Unavailable, "D11 attestation ledger is unavailable")
	}
	response := &xpfv1.GetD11AttestationLedgerResponse{
		NodeId:      snapshot.NodeID,
		RunId:       snapshot.RunID,
		PermitEpoch: snapshot.PermitEpoch,
		SnapshotSeq: snapshot.SnapshotSeq,
		Finalized:   snapshot.Finalized,
		Truncated:   snapshot.Truncated,
		Records:     make([]*xpfv1.D11LedgerRecord, 0, len(snapshot.Records)),
		Failures:    make([]*xpfv1.D11LedgerFailure, 0, len(snapshot.Failures)),
	}
	for _, record := range snapshot.Records {
		row := &xpfv1.D11LedgerRecord{
			NodeId:          record.Key.NodeID,
			RequestId:       record.Key.RequestID,
			PermitEpoch:     record.Key.PermitEpoch,
			QueueEpoch:      record.Key.QueueEpoch,
			QueueNumber:     uint32(record.Key.QueueNumber),
			Family:          string(record.Origin.Family),
			Hook:            string(record.Origin.Hook),
			Owner:           record.Origin.Owner,
			Stn:             record.Origin.STN,
			OwnedIfindex:    record.Origin.OwnedIfindex,
			FrameDigest:     append([]byte(nil), record.FrameDigest[:]...),
			AdmissionCode:   record.AdmissionCode,
			Completion:      string(record.Completion),
			ResolveCount:    record.ResolveCount,
			TerminalState:   record.TerminalState,
			LateAttempts:    record.LateAttempts,
			Duplicate:       record.Duplicate,
			ContractRefusal: record.ContractRefusal,
		}
		if completion := record.EarlyCompletion; completion != nil {
			row.EarlyOutcome = string(completion.Outcome)
			row.EarlyReason = completion.Reason
			row.EarlyBytesWritten = completion.BytesWritten
		}
		response.Records = append(response.Records, row)
	}
	for _, failure := range snapshot.Failures {
		response.Failures = append(response.Failures, &xpfv1.D11LedgerFailure{
			Family:       string(failure.Origin.Family),
			Hook:         string(failure.Origin.Hook),
			Owner:        failure.Origin.Owner,
			Stn:          failure.Origin.STN,
			OwnedIfindex: failure.Origin.OwnedIfindex,
			FrameDigest:  append([]byte(nil), failure.FrameDigest[:]...),
			Reason:       failure.Reason,
		})
	}
	return response, nil
}
