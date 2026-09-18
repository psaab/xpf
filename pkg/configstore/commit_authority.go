package configstore

import (
	"errors"
	"fmt"
	"strings"
)

// ErrCommitAuthorityMissing is returned by the authority-bound commit entry
// points when the caller passes a ZERO CommitAuthority (#6808).
//
// It exists so the zero value fails CLOSED. The obvious design — let the zero
// value mean "internal committer, skip the holder check" — would put the
// god-mode capability at the exact value a forgotten struct field, a
// zero-initialised slot, or a `CommitAuthority{}` written by someone who did
// not know better already produces. The explicit parameter would then catch
// OMISSION (it would not compile) while silently admitting a
// wrong-but-compiling zero, which reads as deliberate in review. Internal
// committers must say so with InternalCommitter().
var ErrCommitAuthorityMissing = errors.New(
	"commit authority missing: the caller did not state whose authority this commit runs under " +
		"(use configstore.InternalCommitter() for a system/daemon commit, or AuthorizeCommit for a session)")

// ErrConfigHolderTurnover is returned when a commit that was authorized for one
// config-lock holder reaches promotion after the lock has turned over — the
// holder released it (explicitly, by disconnect, or by idle-lease reclaim) and
// possibly another session acquired it and staged different work (#6808).
//
// It is a distinct sentinel from ErrCandidateGenerationConflict because the
// correct reaction is the OPPOSITE. A generation conflict means "the content
// moved, re-examine and retry" — commitWithGenBinding retries it deliberately.
// A holder turnover means "the authority that permitted this commit is gone";
// retrying would re-snapshot and promote the NEW holder's candidate under the
// OLD holder's authorization, which is the substitution this closes. So this
// sentinel must never be fed to that retry loop.
var ErrConfigHolderTurnover = errors.New(
	"config lock changed hands during commit preparation; the commit was not applied " +
		"(re-enter configuration mode and commit again)")

// commitAuthorityKind distinguishes the three states a CommitAuthority can be
// in. The zero value is deliberately the INVALID one — see
// ErrCommitAuthorityMissing.
type commitAuthorityKind uint8

const (
	// authorityUnset is the zero value: no authority was stated. Rejected.
	authorityUnset commitAuthorityKind = iota
	// authorityInternal is a system/daemon committer that legitimately carries
	// no config-lock session (HA sync, event engine, in-process CLI, tests).
	authorityInternal
	// authorityHolder is a transport session that passed the holder gate, bound
	// to the holder identity AND the epoch observed at that moment.
	authorityHolder
)

// CommitAuthority states whose authority a commit transaction runs under, and
// is verified again at promotion under the store lock (#6808).
//
// The defect it closes: the REST and gRPC commit paths verified the config-lock
// holder, then invoked a daemon callback carrying NO identity. Between the two,
// the lock could turn over — the holder exits, disconnects, or is reclaimed on
// its idle lease, and another session enters and stages different edits — and
// the in-flight commit would snapshot and promote the NEW holder's candidate
// under the ORIGINAL holder's authorization.
//
// The #5848 candidate-generation binding does not close it. That binding proves
// the candidate CONTENT did not move between the daemon's snapshot and the
// promotion; it says nothing about WHO holds the lock, takes no session id, and
// a turnover completing BEFORE the snapshot (i.e. while the commit waits on the
// apply semaphore, which is where a busy daemon actually waits) yields a
// perfectly consistent generation pair describing the new holder's candidate.
//
// It is passed as an explicit parameter rather than carried on a Context so a
// caller cannot omit it: an absent context value is indistinguishable from a
// deliberate one and would degrade silently to a bypass on an authorization
// path.
type CommitAuthority struct {
	kind      commitAuthorityKind
	sessionID string
	// journalPrincipal is a redacted, transport-derived actor label. It is
	// deliberately separate from sessionID: the latter is a bearer-like
	// lock token and must never be written to the audit journal verbatim.
	journalPrincipal string
	// epoch is the holder epoch observed when this authority was minted. It
	// distinguishes "the same session still holds the lock" from "the lock was
	// released and re-acquired", which the session id alone cannot: the same
	// session can legitimately re-enter, and a wall-clock stamp cannot tell
	// a held lock from a re-taken one.
	epoch uint64
}

// InternalCommitter returns an explicitly unattributed authority for a
// system/daemon commit that legitimately carries no config-lock session. The
// action-specific autonomous paths use InternalCommitterAs so they can name
// their known system source; direct/legacy callers remain "unknown".
func InternalCommitter() CommitAuthority {
	return InternalCommitterAs(UnknownPrincipal)
}

// InternalCommitterAs returns an internal authority with an explicit,
// non-secret journal actor/source label.
func InternalCommitterAs(principal string) CommitAuthority {
	return CommitAuthority{kind: authorityInternal, journalPrincipal: principal}
}

// IsInternal reports whether a is the system/daemon authority. Exported for the
// daemon's logging and for tests asserting which authority a path used.
func (a CommitAuthority) IsInternal() bool { return a.kind == authorityInternal }

// SessionID returns the config session this authority is bound to, or "" for an
// internal or unset authority.
func (a CommitAuthority) SessionID() string { return a.sessionID }

// JournalPrincipal returns the redacted principal to stamp on journal entries
// produced by this commit. Missing values stay explicitly unknown.
func (a CommitAuthority) JournalPrincipal() string {
	if strings.TrimSpace(a.journalPrincipal) == "" {
		return UnknownPrincipal
	}
	return a.journalPrincipal
}

// verifyCommitAuthorityLocked re-checks at promotion time that the authority a
// commit was granted still holds. Caller holds s.mu — the check and the
// promotion it guards MUST be atomic, or the turnover simply moves into the gap
// between them.
func (s *Store) verifyCommitAuthorityLocked(a CommitAuthority) error {
	switch a.kind {
	case authorityInternal:
		return nil
	case authorityHolder:
		holder := s.effectiveHolderLocked()
		if holder != a.sessionID || s.holderEpoch != a.epoch {
			return fmt.Errorf("%w (authorized for session %q at holder epoch %d; now %q at epoch %d)",
				ErrConfigHolderTurnover, a.sessionID, a.epoch, holder, s.holderEpoch)
		}
		return nil
	default:
		return ErrCommitAuthorityMissing
	}
}

// AuthorizeCommit verifies that sessionID may commit and mints the authority to
// be re-verified at promotion, both under a SINGLE acquisition of s.mu (#6808).
//
// Doing the check and the mint under one lock acquisition is the point: two
// calls would leave a window in which the lock turns over between "you are the
// holder" and "here is the epoch you hold it at", which is the same defect one
// level down.
//
// It is the authority-bearing replacement for EnsureConfigHolder on the
// commit-family paths. sessionID == "" yields InternalCommitter(), matching the
// documented internal/system bypass in ensureHolderLocked.
func (s *Store) AuthorizeCommit(sessionID string) (CommitAuthority, error) {
	return s.AuthorizeCommitAs(sessionID, UnknownPrincipal)
}

// AuthorizeCommitAs is AuthorizeCommit with the already-authorized transport
// principal attached for audit attribution. The principal is supplied by the
// REST/gRPC handler that already resolved it; this method never trusts a
// caller-controlled identity for authorization.
func (s *Store) AuthorizeCommitAs(sessionID, principal string) (CommitAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return CommitAuthority{}, err
	}
	if sessionID == "" {
		return InternalCommitterAs(principal), nil
	}
	// A session that passed ensureHolderLocked while NOT in config mode, or
	// against an unowned lock, holds nothing an epoch could bind — both are
	// documented bypasses of the holder check, not ownership. Treat them as
	// internal so behaviour is unchanged for those paths; the turnover this
	// closes requires a real recorded holder.
	if !s.configDir || s.effectiveHolderLocked() == "" {
		return InternalCommitterAs(principal), nil
	}
	return CommitAuthority{
		kind:             authorityHolder,
		sessionID:        sessionID,
		journalPrincipal: principal,
		epoch:            s.holderEpoch,
	}, nil
}

// HolderEpoch returns the current holder epoch. Exported for tests asserting
// that acquisition and release advance it.
func (s *Store) HolderEpoch() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.holderEpoch
}
