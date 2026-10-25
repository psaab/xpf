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
// (#16156, #16828). The daemon commit path encodes the class in
// whether it returns the committed config alongside the error, so
// classification needs no error-text matching. Two committed classes
// exist: a tail error (the dataplane IS armed under the new config,
// only a best-effort subsystem step failed) and a committed-not-applied
// error (the store promoted+persisted the config but the apply aborted
// before publication — required-protocol gate #2138 or policy-session
// READ authority refusal). The committed classes are distinguished by
// the ErrCommittedNotApplied sentinel wrapping the latter's error.
type CommitErrorClass uint8

const (
	// CommitErrCanceled: err wraps context.Canceled. Reserved for an
	// error that occurred BEFORE promotion (applySem acquisition,
	// request-context abort); a post-promotion abort is never Canceled —
	// it is CommitErrCommittedNotApplied. See ClassifyCommitError.
	CommitErrCanceled CommitErrorClass = iota
	// CommitErrDeadlineExceeded: err wraps context.DeadlineExceeded;
	// same pre-promotion reservation as CommitErrCanceled.
	CommitErrDeadlineExceeded
	// CommitErrCommittedTail: compiled != nil — the config was
	// committed, persisted and is live; only a non-fatal tail-reconcile
	// / peer-push step failed (transient, retryable).
	CommitErrCommittedTail
	// CommitErrCommittedNotApplied: the store promoted+persisted the
	// config (it is the active config and becomes live on a later apply
	// or boot) but the apply aborted before publication
	// (applyAndSyncCommitted returns the promoted config with an
	// ErrCommittedNotApplied-wrapped error). Distinct from
	// CommitErrCommittedTail: the dataplane is NOT armed under the new
	// config, so the error must not be presented as transient/retryable-
	// live; distinctly from CommitErrRejected: the config was NOT
	// rejected, so the client must not be told to edit/abandon it.
	CommitErrCommittedNotApplied
	// CommitErrRejected: compiled == nil — a real config-validation /
	// compile reject; nothing was committed. This is the FAIL-SAFE
	// default: an error that cannot be positively identified as
	// committed is never told to a client as committed/retryable.
	CommitErrRejected
)

// ErrCommittedNotApplied marks a commit-callback error whose config
// was already promoted+persisted by the store before the apply aborted
// (the #16828 post-promotion abort class: required-protocol gate,
// policy-session READ authority refusal, daemon-stop abort). The daemon
// wraps the underlying apply error with this sentinel and returns the
// promoted config alongside it, so ClassifyCommitError can distinguish
// "committed, not applied" from both a true pre-promotion reject
// (compiled == nil) and a live-with-tail-error commit (compiled != nil,
// no sentinel). Defined here so both the daemon producer and the
// REST/gRPC classifiers can reference it without an import cycle
// (the underlying protocol/authority sentinels live in the dataplane
// package, which must not be imported by the classifier).
var ErrCommittedNotApplied = errors.New("configuration committed but not applied")

// ClassifyCommitError classifies a non-nil commit-callback error
// (commitFn / commitConfirmedFn). Callers MUST pass a non-nil err.
// Each surface maps the class onto its own wire representation (gRPC
// codes / REST HTTP status + envelope); only the machine-readable
// classification is shared — the human-readable "%v" error text is
// each caller's own.
//
// Precedence (first match wins):
//  1. ErrCommittedNotApplied — the committed-not-applied class. Checked
//     BEFORE the context arms: a post-promotion daemon-stop abort wraps
//     context.Canceled under this sentinel, and the config WAS
//     committed, so it must never be reported as a pre-promotion
//     "commit busy" rejection. Its compiled config may be nil (a
//     peer-sync caller that discards the promoted config), so this arm
//     keys on the sentinel, not the pointer.
//  2. context.Canceled / context.DeadlineExceeded — a PRE-promotion
//     abort (semaphore acquisition, request cancel); nothing was
//     committed. Beats the compiled!=nil arm so a wrapped context
//     error is never mis-mapped even if a caller also returns a
//     non-nil config.
//  3. compiled != nil — committed and live, only a tail/peer step
//     failed (CommitErrCommittedTail).
//  4. default — a true reject (CommitErrRejected), the fail-safe: an
//     error that cannot be positively identified as committed is never
//     told to a client as committed.
func ClassifyCommitError(compiled *config.Config, err error) CommitErrorClass {
	switch {
	case errors.Is(err, ErrCommittedNotApplied):
		return CommitErrCommittedNotApplied
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
