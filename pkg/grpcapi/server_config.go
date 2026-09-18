package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// configMutationStatus maps a store mutation/commit error to the right gRPC
// status code. A config-lock ownership violation (#5059,
// configstore.ErrConfigLockedByOther) is PermissionDenied; every other error
// (bad path, parse failure, read-only secondary, etc.) keeps the historical
// InvalidArgument mapping so existing clients see no behavior change.
func configMutationStatus(err error) error {
	if errors.Is(err, configstore.ErrConfigLockedByOther) {
		return status.Errorf(codes.PermissionDenied, "%v", err)
	}
	return status.Errorf(codes.InvalidArgument, "%v", err)
}

// journalPrincipalForContext consumes the principal captured by the
// authorization interceptor. A direct handler call without an admission
// context is intentionally unattributed.
func journalPrincipalForContext(_ *Server, ctx context.Context, sessionID string) string {
	p, ok := authorizedPrincipalFromContext(ctx)
	if !ok {
		return configstore.UnknownPrincipal
	}
	return configstore.FormatJournalPrincipal(p.Source.String(), p.UID, p.Username, p.Class, sessionID)
}

// commitApplyStatus maps a non-nil commit-callback error (commitFn /
// commitConfirmedFn) to the right gRPC status code (#5742). The daemon commit
// path (commitAndApply / commitConfirmedAndApply → applyAndSyncCommitted)
// already encodes the error CLASS in whether it returns the committed config
// alongside the error, so no error-text matching or new cross-package sentinel
// is needed — classify structurally on (compiled, err):
//
//   - context.Canceled / context.DeadlineExceeded (checked FIRST so a wrapped
//     context error can never be mis-mapped even if a caller also returns a
//     non-nil config): the commit was aborted by a daemon stop or a busy
//     apply-lock. Preserved as Canceled / DeadlineExceeded, unchanged.
//   - A NON-FATAL tail-reconcile / ordinary dataplane-apply error — networkd
//     write (#1778), Kea restart (#2987), IPsec reload (#4433), interface
//     reconcile (#5310), non-abort apply (#5679), #5578 deletion-clear:
//     applyAndSyncCommitted returns the committed config ALONGSIDE the error
//     (compiled != nil). The config is VALID and committed+active; only a
//     transient control-socket / subsystem step failed and self-heals on retry
//     (#5646). Map to codes.Unavailable (transient, retryable) so an operator /
//     automation client retries rather than editing a config that was never
//     rejected — the whole point of #5742.
//   - Everything else (compiled == nil): a real config-validation / compile
//     reject (the #5679 abort gate compileErrorMustAbortApply), a device-map
//     commit preflight reject, a bootstrap-mode refusal, or a pre-promotion
//     store persistence error — the config was NOT committed. Keep the
//     historical codes.InvalidArgument. This is the FAIL-SAFE default: an error
//     that cannot be positively identified as a tail-reconcile stays
//     InvalidArgument, so a client is never told to retry genuinely-bad config.
//
// Only the machine-readable code moves; the human-readable "%v" error text is
// byte-identical to the pre-#5742 mapping. Callers MUST pass a non-nil err.
func commitApplyStatus(compiled *config.Config, err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return status.Errorf(codes.Canceled, "commit busy: %v", err)
	case errors.Is(err, context.DeadlineExceeded):
		return status.Errorf(codes.DeadlineExceeded, "commit busy: %v", err)
	case compiled != nil:
		return status.Errorf(codes.Unavailable, "%v", err)
	default:
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
}

// --- Config lifecycle RPCs ---

func (s *Server) EnterConfigure(ctx context.Context, req *pb.EnterConfigureRequest) (*pb.EnterConfigureResponse, error) {
	// Block configure mode on secondary node — config changes must
	// be made on the primary (RG0 is config authority).
	if s.cluster != nil && !s.cluster.IsLocalPrimary(0) {
		return nil, status.Errorf(codes.FailedPrecondition, "node is not primary for RG0, configure on the primary node")
	}
	sessionID := connSessionID(ctx)
	var err error
	if req.Exclusive {
		err = s.store.EnterConfigureExclusive(sessionID)
	} else {
		err = s.store.EnterConfigureSession(sessionID)
	}
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return &pb.EnterConfigureResponse{}, nil
}

func (s *Server) ExitConfigure(ctx context.Context, _ *pb.ExitConfigureRequest) (*pb.ExitConfigureResponse, error) {
	sessionID := connSessionID(ctx)
	s.store.ExitConfigureSession(sessionID)
	return &pb.ExitConfigureResponse{}, nil
}

func (s *Server) GetConfigModeStatus(_ context.Context, _ *pb.GetConfigModeStatusRequest) (*pb.GetConfigModeStatusResponse, error) {
	return &pb.GetConfigModeStatusResponse{
		InConfigMode:   s.store.InConfigMode(),
		Dirty:          s.store.IsDirty(),
		ConfirmPending: s.store.IsConfirmPending(),
	}, nil
}

func (s *Server) mutationPlantClass(ctx context.Context) (string, error) {
	p := principalFromContext(ctx, s.activeConfig())
	if p.Superuser {
		return config.EventPlantClassSuperuser, nil
	}
	if p.Class == "" {
		return "", status.Error(codes.PermissionDenied, "authenticated principal has no login class")
	}
	return p.Class, nil
}

func (s *Server) Set(ctx context.Context, req *pb.SetRequest) (*pb.SetResponse, error) {
	sessionID := connSessionID(ctx)
	plantClass, err := s.mutationPlantClass(ctx)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "%v", err)
	}
	input := req.Input
	if strings.HasPrefix(input, "copy ") || strings.HasPrefix(input, "rename ") {
		return s.handleCopyRename(sessionID, plantClass, input)
	}
	if strings.HasPrefix(input, "insert ") {
		return s.handleInsert(sessionID, plantClass, input)
	}
	if fields := strings.Fields(input); len(fields) > 0 &&
		(fields[0] == "deactivate" || fields[0] == "activate") {
		verb := fields[0]
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(input), verb))
		if rest == "" {
			return nil, status.Errorf(codes.InvalidArgument,
				"%s requires a configuration path", verb)
		}
		var err error
		if verb == "deactivate" {
			err = s.store.DeactivateFromInputAsPlantClass(sessionID, plantClass, rest)
		} else {
			err = s.store.ActivateFromInputAsPlantClass(sessionID, plantClass, rest)
		}
		if err != nil {
			return nil, configMutationStatus(err)
		}
		return &pb.SetResponse{}, nil
	}
	if err := s.store.SetFromInputAsPlantClass(sessionID, plantClass, input); err != nil {
		return nil, configMutationStatus(err)
	}
	return &pb.SetResponse{}, nil
}

func (s *Server) handleCopyRename(sessionID, plantClass, input string) (*pb.SetResponse, error) {
	parts := strings.Fields(input)
	isRename := parts[0] == "rename"
	toIdx := -1
	for i, p := range parts {
		if p == "to" {
			toIdx = i
			break
		}
	}
	if toIdx < 2 || toIdx >= len(parts)-1 {
		return nil, status.Errorf(codes.InvalidArgument, "usage: %s <src> to <dst>", parts[0])
	}
	srcPath := parts[1:toIdx]
	dstPath := parts[toIdx+1:]
	var err error
	if isRename {
		err = s.store.RenameAsPlantClass(sessionID, plantClass, srcPath, dstPath)
	} else {
		err = s.store.CopyAsPlantClass(sessionID, plantClass, srcPath, dstPath)
	}
	if err != nil {
		return nil, configMutationStatus(err)
	}
	return &pb.SetResponse{}, nil
}

func (s *Server) handleInsert(sessionID, plantClass, input string) (*pb.SetResponse, error) {
	parts := strings.Fields(input)
	kwIdx := -1
	isBefore := false
	for i, p := range parts {
		if p == "before" {
			kwIdx = i
			isBefore = true
			break
		}
		if p == "after" {
			kwIdx = i
			break
		}
	}
	if kwIdx < 2 || kwIdx >= len(parts)-1 {
		return nil, status.Errorf(codes.InvalidArgument, "usage: insert <element-path> before|after <ref-identifier>")
	}
	elemPath := parts[1:kwIdx]
	refTokens := parts[kwIdx+1:]
	if len(refTokens) > len(elemPath) {
		return nil, status.Errorf(codes.InvalidArgument, "reference identifier is longer than element path")
	}
	parentPath := elemPath[:len(elemPath)-len(refTokens)]
	refPath := append(append([]string{}, parentPath...), refTokens...)
	if err := s.store.InsertAsPlantClass(sessionID, plantClass, elemPath, refPath, isBefore); err != nil {
		return nil, configMutationStatus(err)
	}
	return &pb.SetResponse{}, nil
}

func (s *Server) Delete(ctx context.Context, req *pb.DeleteRequest) (*pb.DeleteResponse, error) {
	plantClass, err := s.mutationPlantClass(ctx)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "%v", err)
	}
	if err := s.store.DeleteFromInputAsPlantClass(connSessionID(ctx), plantClass, req.Input); err != nil {
		return nil, configMutationStatus(err)
	}
	return &pb.DeleteResponse{}, nil
}


func (s *Server) Load(ctx context.Context, req *pb.LoadRequest) (*pb.LoadResponse, error) {
	sessionID := connSessionID(ctx)
	plantClass, err := s.mutationPlantClass(ctx)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "%v", err)
	}
	switch req.Mode {
	case "override":
		if err := s.store.LoadOverrideAsPlantClass(sessionID, plantClass, req.Content); err != nil {
			return nil, configMutationStatus(err)
		}
	case "merge", "":
		if err := s.store.LoadMergeAsPlantClass(sessionID, plantClass, req.Content); err != nil {
			return nil, configMutationStatus(err)
		}
	case "set":
		count, err := s.store.LoadSetAsPlantClass(sessionID, plantClass, req.Content)
		if err != nil {
			return nil, configMutationStatus(err)
		}
		slog.Info("load set applied", "commands", count)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown load mode: %s (use 'override', 'merge', or 'set')", req.Mode)
	}
	return &pb.LoadResponse{}, nil
}

func (s *Server) Commit(ctx context.Context, req *pb.CommitRequest) (*pb.CommitResponse, error) {
	// #5059: only the config-lock holder may commit the shared candidate. Reject
	// a commit from a non-holder session before it can confirm/apply another
	// session's pending work. Empty session (unit tests / internal) bypasses.
	sessionID := connSessionID(ctx)
	// #6808: mint the commit AUTHORITY under the same store-lock acquisition
	// that verifies the holder, and carry it into the callback, so a lock
	// turnover between this gate and promotion is detected instead of
	// substituting the new holder's candidate. On gRPC the turnover needs no
	// adversary: configLockStatsHandler.HandleConn auto-releases the lock on
	// ConnEnd from a separate goroutine with no coordination with an in-flight
	// commit, so an ordinary disconnect while this commit waits on the apply
	// semaphore is enough.
	authority, err := s.store.AuthorizeCommitAs(sessionID, journalPrincipalForContext(s, ctx, sessionID))
	if err != nil {
		return nil, configMutationStatus(err)
	}

	// Bare commit during a pending commit-confirmed window (#4000). Confirm
	// the pending config only when the candidate is UNCHANGED; new staged
	// edits fall through to the normal commit below, where the daemon commitFn
	// (CommitWithDescription, #3861) applies them AND clears the timer, so the
	// edits are committed rather than silently dropped.
	if s.store.IsConfirmPending() && !s.store.IsDirty() {
		if err := s.store.ConfirmCommitAs(sessionID); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.CommitResponse{}, nil
	}

	// Capture diff summary before commit (active will change)
	summary := s.store.CommitDiffSummary()

	if s.commitFn == nil {
		return nil, status.Errorf(codes.Internal, "commit handler not wired")
	}
	compiled, err := s.commitFn(ctx, authority, req.Comment)
	if err != nil {
		// #5742: classify structurally — a non-fatal tail-reconcile / ordinary
		// apply error (the daemon returns the committed config alongside it) is
		// transient/retryable (Unavailable), NOT a config reject (InvalidArgument).
		return nil, commitApplyStatus(compiled, err)
	}
	return &pb.CommitResponse{Summary: summary, Warnings: configWarnings(compiled)}, nil
}

func (s *Server) CommitCheck(_ context.Context, _ *pb.CommitCheckRequest) (*pb.CommitCheckResponse, error) {
	compiled, err := s.store.CommitCheck()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.CommitCheckResponse{Warnings: configWarnings(compiled)}, nil
}

func (s *Server) CommitConfirmed(ctx context.Context, req *pb.CommitConfirmedRequest) (*pb.CommitConfirmedResponse, error) {
	// #5059: only the config-lock holder may commit the shared candidate.
	// #6808: mint the commit AUTHORITY under the same store-lock acquisition
	// that verifies the holder, and carry it into the callback, so a lock
	// turnover between this gate and promotion is detected instead of
	// substituting the new holder's candidate. On gRPC the turnover needs no
	// adversary: configLockStatsHandler.HandleConn auto-releases the lock on
	// ConnEnd from a separate goroutine with no coordination with an in-flight
	// commit, so an ordinary disconnect while this commit waits on the apply
	// semaphore is enough.
	sessionID := connSessionID(ctx)
	authority, err := s.store.AuthorizeCommitAs(sessionID, journalPrincipalForContext(s, ctx, sessionID))
	if err != nil {
		return nil, configMutationStatus(err)
	}
	if s.commitConfirmedFn == nil {
		return nil, status.Errorf(codes.Internal, "commit-confirmed handler not wired")
	}
	compiled, err := s.commitConfirmedFn(ctx, authority, int(req.Minutes))
	if err != nil {
		// #5742: same structural classification as Commit — commitConfirmedAndApply
		// shares applyAndSyncCommitted, so a non-fatal tail error carries the
		// committed config (Unavailable/retryable) vs a nil-config config reject.
		return nil, commitApplyStatus(compiled, err)
	}
	return &pb.CommitConfirmedResponse{Warnings: configWarnings(compiled)}, nil
}

func (s *Server) ConfirmCommit(ctx context.Context, _ *pb.ConfirmCommitRequest) (*pb.ConfirmCommitResponse, error) {
	// #5059: only the config-lock holder may confirm (and cancel the auto-
	// rollback of) the pending commit-confirmed.
	if err := s.store.ConfirmCommitAs(connSessionID(ctx)); err != nil {
		if errors.Is(err, configstore.ErrConfigLockedByOther) {
			return nil, status.Errorf(codes.PermissionDenied, "%v", err)
		}
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return &pb.ConfirmCommitResponse{}, nil
}

func (s *Server) Rollback(ctx context.Context, req *pb.RollbackRequest) (*pb.RollbackResponse, error) {
	if req.N < 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid n %d: rollback index must be non-negative (0 = revert to active)", req.N)
	}
	plantClass, err := s.mutationPlantClass(ctx)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "%v", err)
	}
	if err := s.store.RollbackAsPlantClass(connSessionID(ctx), plantClass, int(req.N)); err != nil {
		return nil, configMutationStatus(err)
	}
	return &pb.RollbackResponse{}, nil
}
func configWarnings(cfg *config.Config) []string {
	if cfg == nil || len(cfg.Warnings) == 0 {
		return nil
	}
	return append([]string(nil), cfg.Warnings...)
}

func (s *Server) ShowConfig(_ context.Context, req *pb.ShowConfigRequest) (*pb.ShowConfigResponse, error) {
	// Secrets are masked on this raw-AST render RPC (#4051), matching the
	// #2053 typed-struct redaction. The redacted renderers take the path
	// directly (nil/empty selects the whole tree) and mirror the cleartext
	// siblings' nil-source defaults; the cleartext Show* SSOT still backs HA
	// config sync, the DR archive and persistence.
	var path []string
	if len(req.Path) > 0 {
		path = req.Path
	}
	var output string
	switch {
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_JSON:
		output = s.store.ShowActiveJSONRedacted(path)
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_SET:
		output = s.store.ShowActiveSetRedacted(path)
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_XML:
		output = s.store.ShowActiveXMLRedacted(path)
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_INHERITANCE:
		output = s.store.ShowActiveInheritanceRedacted(path)
	case req.Target == pb.ConfigTarget_ACTIVE:
		output = s.store.ShowActiveRedacted(path)
	case req.Format == pb.ConfigFormat_JSON:
		output = s.store.ShowCandidateJSONRedacted(path)
	case req.Format == pb.ConfigFormat_SET:
		output = s.store.ShowCandidateSetRedacted(path)
	case req.Format == pb.ConfigFormat_XML:
		output = s.store.ShowCandidateXMLRedacted(path)
	case req.Format == pb.ConfigFormat_INHERITANCE:
		output = s.store.ShowCandidateInheritanceRedacted(path)
	default:
		output = s.store.ShowCandidateRedacted(path)
	}
	return &pb.ShowConfigResponse{Output: output}, nil
}

func (s *Server) ShowCompare(_ context.Context, req *pb.ShowCompareRequest) (*pb.ShowCompareResponse, error) {
	// rollback_n is a change-control selector: 0 reserves candidate-vs-active,
	// positive values select a 1-based rollback slot. A negative value used to
	// fall through to the candidate-vs-active compare with a success response
	// (#3443 M6), silently comparing the wrong target. Reject it.
	if req.RollbackN < 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid rollback_n %d: must be non-negative (0 = candidate vs active)", req.RollbackN)
	}
	if req.RollbackN > 0 {
		diff, err := s.store.ShowCompareRollbackRedacted(int(req.RollbackN))
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return &pb.ShowCompareResponse{Output: diff}, nil
	}
	return &pb.ShowCompareResponse{Output: s.store.ShowCompareRedacted()}, nil
}

func (s *Server) ShowRollback(_ context.Context, req *pb.ShowRollbackRequest) (*pb.ShowRollbackResponse, error) {
	// #4556 M-01: n selects a 1-based rollback slot. A non-positive n
	// (0 or a negative wire value) maps to history.Get(n-1) =
	// history.Get(<0) → the opaque store error "history position -1 out
	// of range". Reject it up front with a clear positive-integer
	// message, mirroring the REST show-rollback leg and the ShowCompare
	// rollback_n guard (#3443 M6).
	if req.N <= 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid n %d: rollback index must be a positive integer", req.N)
	}
	var output string
	var err error
	if req.Format == pb.ConfigFormat_SET {
		output, err = s.store.ShowRollbackSetRedacted(int(req.N))
	} else {
		output, err = s.store.ShowRollbackRedacted(int(req.N))
	}
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.ShowRollbackResponse{Output: output}, nil
}

func (s *Server) ListHistory(_ context.Context, _ *pb.ListHistoryRequest) (*pb.ListHistoryResponse, error) {
	entries := s.store.ListHistory()
	resp := &pb.ListHistoryResponse{}
	for i, e := range entries {
		resp.Entries = append(resp.Entries, &pb.HistoryEntry{
			Index:     int32(i + 1),
			Timestamp: e.Timestamp.Format("2006-01-02 15:04:05"),
		})
	}
	return resp, nil
}
