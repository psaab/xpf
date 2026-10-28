package grpcapi

import (
	"context"
	"errors"
	"log/slog"

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
	if errors.Is(err, configstore.ErrCommitCheckBusy) {
		return status.Errorf(codes.ResourceExhausted, "%v", err)
	}
	if errors.Is(err, configstore.ErrRescueNotFound) {
		return status.Errorf(codes.FailedPrecondition, "%v", err)
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

// bindCommitGate attaches the #16611 priced-gate binding captured by
// the interceptor (authorizeRPCCommitGate16611) to authority. Absent
// a priced snapshot — a direct handler call, a superuser, or an
// unrestricted class whose commit gate priced nothing to bind — the
// authority is left unbound and promotion is unaffected.
func (s *Server) bindCommitGate(ctx context.Context, authority configstore.CommitAuthority) configstore.CommitAuthority {
	price, ok := commitGatePriceFrom(ctx)
	if !ok {
		return authority
	}
	return authority.WithCommitGate(price.cfg, price.class, price.candidateGen, price.active)
}

// commitApplyStatus maps a non-nil commit-callback error (commitFn /
// commitConfirmedFn) to the right gRPC status code (#5742). The
// structural classification is shared with REST via
// configstore.ClassifyCommitError (#16156); this function only maps
// the shared class onto gRPC codes:
//   - CommitErrCommittedNotApplied (#16828): the store promoted+
//     persisted the config but the apply aborted before publication
//     (required-protocol gate, policy READ authority refusal, daemon-
//     stop abort). The config was NOT rejected — it is active and
//     becomes live on a later apply or boot — so it must not be
//     InvalidArgument. It is also not live now, so it must not be the
//     tail class's plain retryable-live reading either. Map to
//     codes.FailedPrecondition: the box is in a committed-but-not-
//     applied state the operator must resolve (fix the gate cause or
//     restart), not a bad request and not a transient hiccup.
//   - context.Canceled / context.DeadlineExceeded (PRE-promotion only —
//     a post-promotion abort carries ErrCommittedNotApplied and is
//     classified above it): the commit never promoted. Preserved as
//     Canceled / DeadlineExceeded, unchanged.
//   - A NON-FATAL tail-reconcile / ordinary dataplane-apply error: the
//     daemon returns the committed config ALONGSIDE the error
//     (compiled != nil, no sentinel). The config is VALID, committed+
//     active and LIVE; only a transient control-socket / subsystem
//     step failed and self-heals on retry (#5646). Map to
//     codes.Unavailable (transient, retryable) so an operator /
//     automation client retries rather than editing a config that was
//     never rejected — the whole point of #5742.
//   - Everything else (compiled == nil, no sentinel): a real
//     config-validation / compile reject, a device-map commit
//     preflight reject, a bootstrap-mode refusal, or a pre-promotion
//     store persistence error — the config was NOT committed. Keep the
//     historical codes.InvalidArgument. This is the FAIL-SAFE default:
//     an error that cannot be positively identified as committed stays
//     InvalidArgument, so a client is never told to retry genuinely-
//     bad config.
//
// Only the machine-readable code moves; the human-readable "%v" error
// text is preserved (the committed-not-applied text additionally
// carries the ErrCommittedNotApplied marker). Callers MUST pass a
// non-nil err.
func commitApplyStatus(compiled *config.Config, err error) error {
	switch configstore.ClassifyCommitError(compiled, err) {
	case configstore.CommitErrCommittedNotApplied:
		return status.Errorf(codes.FailedPrecondition, "%v", err)
	case configstore.CommitErrCanceled:
		return status.Errorf(codes.Canceled, "commit busy: %v", err)
	case configstore.CommitErrDeadlineExceeded:
		return status.Errorf(codes.DeadlineExceeded, "commit busy: %v", err)
	case configstore.CommitErrCommittedTail:
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

// mutationPlantClass returns the login class the authorization interceptor
// admitted for this RPC (#11675). It consumes the admitted snapshot
// (authorizedPrincipalFromContext) — the same principal
// journalPrincipalForContext records — and MUST NOT re-resolve against the
// live active-config snapshot: a class redefinition or user reclass landing
// between admission and handling would otherwise stamp the NEW class while
// the journal records the ADMITTED one, and the deferred event-options
// change-configuration would later execute under a class whose authority was
// never evaluated. A direct handler call without an admission context has no
// admitted class and is denied, mirroring pkg/api's mutationPlantClass.
func (_ *Server) mutationPlantClass(ctx context.Context) (string, error) {
	p, ok := authorizedPrincipalFromContext(ctx)
	if !ok {
		return "", errors.New("authorized mutation principal is unavailable")
	}
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
	// #15760: route annotate on the lexed verb and split it with the
	// canonical #14717 parser (ParseAnnotateCommand): the comment is
	// the LAST token and only when authored quoted, so a quoted path
	// element stays in the path. The previous first-quote split
	// (cliterm.AnnotateCommentFromLine + strings.Fields) annotated a
	// shorter path than the authorization gate adjudicated, with the
	// rest of the line mangled into the comment.
	if verb, isMutation := config.ConfigMutationVerb(input); isMutation && verb == "annotate" {
		path, comment, ok := config.ParseAnnotateCommand(input)
		if !ok || len(path) == 0 {
			return nil, status.Error(codes.InvalidArgument, `usage: annotate <path> "comment"`)
		}
		if err := s.store.AnnotateAsPlantClass(sessionID, plantClass, path, comment); err != nil {
			return nil, configMutationStatus(err)
		}
		return &pb.SetResponse{}, nil
	}
	// #14147: route on the lexed verb, not a raw prefix/Fields split.
	// A tab after the verb, a comment, or a quoted keyword must route
	// (and split) exactly as the authorization gate adjudicated.
	if verb, isMutation := config.ConfigMutationVerb(input); isMutation {
		switch verb {
		case "copy", "rename":
			return s.handleCopyRename(sessionID, plantClass, input)
		case "insert":
			return s.handleInsert(sessionID, plantClass, input)
		case "deactivate", "activate":
			// #15166: split on the lexed remainder, not strings.Fields.
			// Fields is Unicode-aware, so "deactivate\u00a0system login"
			// reached DeactivatePath on a path the lexer-based gate never
			// lexed. ParseDeactivateActivateCommand requires the same
			// well-formed lexing the gate adjudicated; anything else is a
			// usage error, never a Fields-split execution.
			_, path, ok := config.ParseDeactivateActivateCommand(input)
			if !ok {
				return nil, status.Errorf(codes.InvalidArgument,
					"%s requires a configuration path", verb)
			}
			var err error
			if verb == "deactivate" {
				// #16790: re-join with JoinConfigPathTokens, not
				// strings.Join. The store re-lexes the input
				// (applyEditLine), so a whitespace-bearing element
				// (policy "allow web") must be re-quoted or it splits
				// into two tokens and the path is not found.
				err = s.store.DeactivateFromInputAsPlantClass(sessionID, plantClass, config.JoinConfigPathTokens(path))
			} else {
				err = s.store.ActivateFromInputAsPlantClass(sessionID, plantClass, config.JoinConfigPathTokens(path))
			}
			if err != nil {
				return nil, configMutationStatus(err)
			}
			return &pb.SetResponse{}, nil
		}
	}
	if err := s.store.SetFromInputAsPlantClass(sessionID, plantClass, input); err != nil {
		return nil, configMutationStatus(err)
	}
	return &pb.SetResponse{}, nil
}

func (s *Server) handleCopyRename(sessionID, plantClass, input string) (*pb.SetResponse, error) {
	// #14147: the canonical lexer split the gate adjudicated — only a
	// bare `to` separates, quoted strings are unquoted, comments are
	// stripped. strings.Fields here split at a different `to` than
	// the gate and acted on endpoints nobody authorized.
	verb, _ := config.ConfigMutationVerb(input)
	srcPath, dstPath, ok := config.ParseCopyRenameCommand(input)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "usage: %s <src> to <dst>", verb)
	}
	var err error
	if verb == "rename" {
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
	// #14147: canonical split, as in handleCopyRename. ParseInsertCommand
	// returns the full reference path (element parent + ref tokens) and
	// rejects a ref longer than the element, preserving the usage error.
	elemPath, refPath, isBefore, ok := config.ParseInsertCommand(input)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "usage: insert <element-path> before|after <ref-identifier>")
	}
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
	case "rescue":
		if req.Content != "" {
			return nil, status.Error(codes.InvalidArgument, "load rescue does not accept content")
		}
		if err := s.store.LoadRescueAsPlantClass(sessionID, plantClass); err != nil {
			return nil, configMutationStatus(err)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown load mode: %s (use 'rescue', 'override', 'merge', or 'set')", req.Mode)
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
	// #16611: bind the authority to the candidate generation the
	// interceptor priced for the admitted class, so a same-holder
	// copy/rename landing between the gate and promotion is refused
	// (or re-priced and refused) at promotion instead of being
	// adopted by the daemon's generation-retry loop.
	authority = s.bindCommitGate(ctx, authority)

	// Bare commit during a pending commit-confirmed window (#4000). Confirm
	// the pending config only when the candidate is UNCHANGED; new staged
	// edits fall through to the normal commit below, where the daemon commitFn
	// (CommitWithDescription, #3861) applies them AND clears the timer, so the
	// edits are committed rather than silently dropped.
	if s.store.ConfirmOnly() {
		if err := s.store.ConfirmCommitPrincipalAs(sessionID, journalPrincipalForContext(s, ctx, sessionID)); err != nil {
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
	return &pb.CommitResponse{Summary: summary, Warnings: configstore.WarningsOf(compiled)}, nil
}

func (s *Server) CommitCheck(ctx context.Context, _ *pb.CommitCheckRequest) (*pb.CommitCheckResponse, error) {
	// #16070: only the config-lock holder may check the shared candidate.
	// A non-holder must not obtain compile diagnostics about another
	// session's staged candidate, nor trigger a full compile of it at
	// will. CommitCheckAs enforces the holder under the store lock and
	// bounds concurrent compiles to a single slot; over-cap checks fail
	// fast with ErrCommitCheckBusy (ResourceExhausted). connSessionID
	// yields the holder's connection-scoped id (or the peer fallback on a
	// direct in-process call); ensureHolderLocked governs the no-holder
	// case exactly as it does for the sibling mutators.
	compiled, err := s.store.CommitCheckAs(connSessionID(ctx))
	if err != nil {
		return nil, configMutationStatus(err)
	}
	return &pb.CommitCheckResponse{Warnings: configstore.WarningsOf(compiled)}, nil
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
	if req.Minutes < 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"commit confirmed: timeout must be non-negative")
	}
	authority, err := s.store.AuthorizeCommitAs(sessionID, journalPrincipalForContext(s, ctx, sessionID))
	if err != nil {
		return nil, configMutationStatus(err)
	}
	authority = s.bindCommitGate(ctx, authority)
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
	return &pb.CommitConfirmedResponse{Warnings: configstore.WarningsOf(compiled)}, nil
}

func (s *Server) ConfirmCommit(ctx context.Context, _ *pb.ConfirmCommitRequest) (*pb.ConfirmCommitResponse, error) {
	// #5059: only the config-lock holder may confirm (and cancel the auto-
	// rollback of) the pending commit-confirmed.
	if err := s.store.ConfirmCommitPrincipalAs(connSessionID(ctx), journalPrincipalForContext(s, ctx, connSessionID(ctx))); err != nil {
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

func (s *Server) ShowConfig(ctx context.Context, req *pb.ShowConfigRequest) (*pb.ShowConfigResponse, error) {
	// Secrets are masked on this raw-AST render RPC (#4051), matching the
	// #2053 typed-struct redaction. This stays unconditional for every remote
	// caller, including one authorized by PermAll; unlike the in-process CLI,
	// this path has no built-in-super-user class identity exception. The redacted
	// renderers take the path directly (nil/empty selects the whole tree) and
	// mirror the cleartext siblings' nil-source defaults; the cleartext Show*
	// SSOT still backs HA config sync, the DR archive and persistence.
	//
	// #15995 fold: when the gate authorized this call it stashed the
	// priced snapshot in ctx — render THAT generation. Handlers reached
	// without the gate (direct/superuser calls) keep the store renderers.
	// Fold 3: a captured snapshot with nil Primary is a priced ABSENCE:
	// render empty (the candidate/slot did not exist at pricing), never
	// fall through to the live store.
	var path []string
	if len(req.Path) > 0 {
		path = req.Path
	}
	if snaps, ok := configReadSnapshotsFrom(ctx); ok && snaps.Present {
		resp, err := showConfigSnapshotResponse(snaps.Primary, snaps.NodeID, path, req.Format)
		return resp, rpcStatus(err)
	}
	var output string
	var inhErr error
	switch {
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_JSON:
		output = s.store.ShowActiveJSONRedacted(path)
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_SET:
		output = s.store.ShowActiveSetRedacted(path)
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_XML:
		output = s.store.ShowActiveXMLRedacted(path)
	case req.Target == pb.ConfigTarget_ACTIVE && req.Format == pb.ConfigFormat_INHERITANCE:
		output, inhErr = s.store.ShowActiveInheritanceRedacted(path)
	case req.Target == pb.ConfigTarget_ACTIVE:
		output = s.store.ShowActiveRedacted(path)
	case req.Format == pb.ConfigFormat_JSON:
		output = s.store.ShowCandidateJSONRedacted(path)
	case req.Format == pb.ConfigFormat_SET:
		output = s.store.ShowCandidateSetRedacted(path)
	case req.Format == pb.ConfigFormat_XML:
		output = s.store.ShowCandidateXMLRedacted(path)
	case req.Format == pb.ConfigFormat_INHERITANCE:
		output, inhErr = s.store.ShowCandidateInheritanceRedacted(path)
	default:
		output = s.store.ShowCandidateRedacted(path)
	}
	if inhErr != nil {
		return nil, rpcStatus(inhErr)
	}
	return &pb.ShowConfigResponse{Output: output}, nil
}

// showConfigSnapshotResponse renders path from one priced snapshot tree
// in the requested wire format (redacted, as ShowConfig always is).
func showConfigSnapshotResponse(tree *config.ConfigTree, nodeID int, path []string, format pb.ConfigFormat) (*pb.ShowConfigResponse, error) {
	switch format {
	case pb.ConfigFormat_JSON:
		return &pb.ShowConfigResponse{Output: configstore.RenderShowRedacted(tree, path, "json")}, nil
	case pb.ConfigFormat_SET:
		return &pb.ShowConfigResponse{Output: configstore.RenderShowRedacted(tree, path, "set")}, nil
	case pb.ConfigFormat_XML:
		return &pb.ShowConfigResponse{Output: configstore.RenderShowRedacted(tree, path, "xml")}, nil
	case pb.ConfigFormat_INHERITANCE:
		out, err := configstore.RenderShowInheritanceRedacted(tree, path, nodeID)
		if err != nil {
			return nil, err
		}
		return &pb.ShowConfigResponse{Output: out}, nil
	default:
		return &pb.ShowConfigResponse{Output: configstore.RenderShowRedacted(tree, path, "text")}, nil
	}
}

func (s *Server) ShowCompare(ctx context.Context, req *pb.ShowCompareRequest) (*pb.ShowCompareResponse, error) {
	// rollback_n is a change-control selector: 0 reserves candidate-vs-active,
	// positive values select a 1-based rollback slot. A negative value used to
	// fall through to the candidate-vs-active compare with a success response
	// (#3443 M6), silently comparing the wrong target. Reject it.
	if req.RollbackN < 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid rollback_n %d: must be non-negative (0 = candidate vs active)", req.RollbackN)
	}
	// #15995 fold: render the priced snapshot arms when the gate ran.
	// Fold 3: a captured absent candidate arm is the priced absence.
	// Candidate-baseline compares (RollbackN>=0, !ActiveBaseline)
	// require a candidate exactly as the live store helper does
	// ("not in configuration mode"); only the active-baseline arm
	// deliberately diffs without one.
	if snaps, ok := configReadSnapshotsFrom(ctx); ok && snaps.Present {
		// #17215: surface the captured slot error verbatim (the same
		// history error the ungated helper returns), not a synthesized
		// "slot not found" spelling.
		if snaps.SlotErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", snaps.SlotErr)
		}
		if !req.ActiveBaseline && snaps.Other == nil {
			return nil, status.Errorf(codes.InvalidArgument, "not in configuration mode")
		}
		if req.RollbackN > 0 && snaps.Primary == nil {
			return nil, status.Errorf(codes.InvalidArgument, "rollback slot %d not found", req.RollbackN)
		}
		hasCandidate := snaps.Other != nil || req.ActiveBaseline
		return &pb.ShowCompareResponse{Output: configstore.RenderCompareRedacted(snaps.Primary, snaps.Other, req.Path, hasCandidate)}, nil
	}
	// #15657 V45-03: the operational baseline diffs the rollback slot
	// (0 = active) against ACTIVE — no candidate read, no config mode.
	if req.ActiveBaseline {
		diff, err := s.store.ShowCompareRollbackActiveRedactedAtPath(int(req.RollbackN), req.Path)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return &pb.ShowCompareResponse{Output: diff}, nil
	}
	if req.RollbackN > 0 {
		diff, err := s.store.ShowCompareRollbackRedactedAtPath(int(req.RollbackN), req.Path)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return &pb.ShowCompareResponse{Output: diff}, nil
	}
	return &pb.ShowCompareResponse{Output: s.store.ShowCompareRedactedAtPath(req.Path)}, nil
}

func (s *Server) ShowRollback(ctx context.Context, req *pb.ShowRollbackRequest) (*pb.ShowRollbackResponse, error) {
	// #15657 V45-03/V48-02: n == 0 is the active configuration (Junos
	// rollback 0); only a negative wire value is invalid. Format and
	// Path are honoured for every format — previously only SET was
	// branched and xml/json/inheritance silently fell back to
	// hierarchical text, and there was no subtree selector at all.
	if req.N < 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid n %d: rollback index must be non-negative (0 = active configuration)", req.N)
	}
	var path []string
	if len(req.Path) > 0 {
		path = req.Path
	}
	// #15995 fold: render the priced slot snapshot when the gate ran.
	// Fold 3: captured nil Primary = slot absent at pricing — surface
	// the captured SlotErr (#17215), never render a later live slot.
	if snaps, ok := configReadSnapshotsFrom(ctx); ok && snaps.Present {
		if snaps.Primary == nil {
			if snaps.SlotErr != nil {
				return nil, status.Errorf(codes.InvalidArgument, "%v", snaps.SlotErr)
			}
			return &pb.ShowRollbackResponse{Output: ""}, nil
		}
		resp, err := showConfigSnapshotResponse(snaps.Primary, snaps.NodeID, path, req.Format)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return &pb.ShowRollbackResponse{Output: resp.Output}, nil
	}
	var output string
	var err error
	switch req.Format {
	case pb.ConfigFormat_SET:
		output, err = s.store.ShowRollbackSetRedactedPath(int(req.N), path)
	case pb.ConfigFormat_JSON:
		output, err = s.store.ShowRollbackJSONRedactedPath(int(req.N), path)
	case pb.ConfigFormat_XML:
		output, err = s.store.ShowRollbackXMLRedactedPath(int(req.N), path)
	case pb.ConfigFormat_INHERITANCE:
		output, err = s.store.ShowRollbackInheritanceRedactedPath(int(req.N), path)
	default:
		output, err = s.store.ShowRollbackRedactedPath(int(req.N), path)
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
