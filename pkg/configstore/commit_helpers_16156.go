package configstore

// Shared config-lifecycle helpers (#16156, W2.5 narrowed form).
//
// Only three small helpers are shared across the config-commit
// surfaces. There is deliberately NO configops.Service and NO
// three-surface CommitGate(store, session) -> authority: REST and
// gRPC mint a holder-epoch CommitAuthority (AuthorizeCommitAs)
// BEFORE the confirm gate, while the local CLI commits with no
// authority and can intentionally present an empty internal
// session (cliConfigSessionID). A gate that minted authority would
// change CLI commit-authority semantics, so authority minting stays
// per-surface. What is shared here never mints authority and never
// touches the CLI's authority-free path:
//
//   - ConfirmOnly (CommitGate-as-predicate in the research naming):
//     the pure confirm-only predicate, taken under ONE store lock
//     hold — IsConfirmPending() && !IsDirty(). The three call sites
//     previously read the two flags under two separate RLock holds,
//     so a concurrent edit landing between the reads could route a
//     dirty candidate into the confirm-only branch and silently
//     drop the staged edits (the #4000 hazard).
//   - ClassifyCommitError: the structural (compiled, err)
//     commit-error classification shared by REST and gRPC (#5742 /
//     #15281). Each surface maps the returned class onto its own
//     wire codes; the classification itself can no longer diverge.
//   - WarningsOf: the nil-safe defensive-copy extraction of
//     cfg.Warnings, previously open-coded in grpcapi (configWarnings)
//     and twice in pkg/api (writeCommitError, commitResponseFromConfig).

import (
	"context"
	"errors"

	"github.com/psaab/xpf/pkg/config"
)

// ConfirmOnly reports whether a bare commit on this store is a pure
// confirmation of a pending commit-confirmed window: a window is
// pending AND the candidate is unchanged since the confirmed commit.
// New staged edits (dirty candidate) must fall through to a normal
// commit, which applies them AND clears the timer (#4000 / #3861).
//
// Both flags are read under a single RLock hold, so the decision is
// atomic with respect to concurrent candidate edits and confirm-window
// changes. This is a pure predicate: it mints no commit authority and
// performs no mutation; each surface keeps its own authority and
// ConfirmCommitAs call.
func (s *Store) ConfirmOnly() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.confirmTimer != nil && !s.dirty
}

// CommitErrorClass is the structural class of a commit-callback error
// (#16156). The daemon commit path encodes the class in whether it
// returns the committed config alongside the error, so classification
// needs no error-text matching and no cross-package sentinel.
type CommitErrorClass uint8

const (
	// CommitErrCanceled: err wraps context.Canceled. Checked FIRST so
	// a wrapped context error can never be mis-classified even if the
	// callback also returns a non-nil config.
	CommitErrCanceled CommitErrorClass = iota
	// CommitErrDeadlineExceeded: err wraps context.DeadlineExceeded.
	// Checked FIRST, like CommitErrCanceled.
	CommitErrDeadlineExceeded
	// CommitErrCommittedTail: compiled != nil — the config was
	// committed, persisted and is live; only a non-fatal tail-reconcile
	// / peer-push step failed (transient, retryable).
	CommitErrCommittedTail
	// CommitErrRejected: compiled == nil — a real config-validation /
	// compile reject; nothing was committed. This is the FAIL-SAFE
	// default: an error that cannot be positively identified as a
	// tail-reconcile is never told to a client as committed/retryable.
	CommitErrRejected
)

// ClassifyCommitError classifies a non-nil commit-callback error
// (commitFn / commitConfirmedFn) structurally on (compiled, err),
// exactly as the gRPC commitApplyStatus (#5742) and the REST
// writeCommitError (#15281) mappings did before this helper existed.
// Callers MUST pass a non-nil err. Each surface maps the class onto
// its own wire representation (gRPC codes / REST HTTP status +
// envelope); only the machine-readable classification is shared —
// the human-readable "%v" error text is each caller's own and is
// byte-identical to the pre-#16156 mappings.
func ClassifyCommitError(compiled *config.Config, err error) CommitErrorClass {
	switch {
	case errors.Is(err, context.Canceled):
		return CommitErrCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return CommitErrDeadlineExceeded
	case compiled != nil:
		return CommitErrCommittedTail
	default:
		return CommitErrRejected
	}
}

// WarningsOf returns a defensive copy of cfg.Warnings, or nil when
// cfg is nil or carries no warnings. The copy keeps callers from
// mutating (or racing readers of) the compiled config the dataplane
// retains.
func WarningsOf(cfg *config.Config) []string {
	if cfg == nil || len(cfg.Warnings) == 0 {
		return nil
	}
	return append([]string(nil), cfg.Warnings...)
}
