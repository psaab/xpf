package configstore

import (
	"fmt"
	"log/slog"
	"time"
)

// ensureWritableLocked returns ErrClusterReadOnly when the store is in
// cluster read-only mode (a non-RG0-primary / secondary node; config
// authority is the primary). Callers MUST hold s.mu.
//
// #3893: the read-only flag was previously checked ONLY at the
// EnterConfigure* gate. Once a config session was already open (entered
// before the node became secondary, or via a path that did not re-check),
// Set/Delete/Commit/Load/Rollback only verified candidate!=nil — so an open
// session could Set+Commit on the read-only secondary and diverge its active
// config from the primary (the local edit is one the primary never sees and
// the next config-sync overwrites, causing churn). Every user-session
// mutating op now calls this helper so the mutation is rejected regardless of
// when the session was opened. The internal HA-sync ingress (SyncApply) and
// the commit-confirmed timeout revert (PromoteRollback) do NOT go through the
// gated methods, so they correctly bypass this gate.
func (s *Store) ensureWritableLocked() error {
	if s.clusterReadOnly {
		return ErrClusterReadOnly
	}
	return nil
}

// ensureHolderLocked enforces config-lock ownership on a user-session mutation
// or commit (#5059). The candidate is singular and shared, so serialization
// under s.mu is not authorization: a session that never entered config mode
// could otherwise mutate/commit another session's candidate. It rejects a
// non-empty caller sessionID that differs from the recorded holder. Callers
// MUST hold s.mu.
//
// Two deliberate bypasses:
//   - sessionID == "" is the internal/system capability (daemon apply, HA sync, in-process CLI, tests). These
//     do not carry a peer session and must not be blocked.
//   - a lock with no recorded holder (effectiveHolderLocked() == "", i.e. the
//     internal/local EnterConfigure() path) is not owned by any session, so a
//     user session is not blocked from it — matching pre-#5059 behavior for the
//     local-CLI / internal acquire.
//
// A remote gRPC caller always carries a non-empty peerSessionID and records it
// as the holder on EnterConfigureSession, so a second remote session is gated
// against it — closing the exact cross-session mutation the issue describes.
func (s *Store) ensureHolderLocked(sessionID string) error {
	if sessionID == "" {
		return nil // internal/system caller: explicit bypass
	}
	if !s.configDir {
		return nil // not in config mode; candidate==nil is reported by the caller
	}
	holder := s.effectiveHolderLocked()
	if holder == "" {
		// #9632: the empty-holder pass (#5059) is for sessions that never held
		// this lock. A session whose lease was reclaimed would otherwise keep
		// writing, and committing, into the candidate that replaced its own.
		if _, reclaimed := s.reclaimedHolders[sessionID]; reclaimed {
			return fmt.Errorf("%w: this session's configuration lock was reclaimed after the %s idle lease; re-enter configure mode",
				ErrConfigLockedByOther, configLockLeaseTTL)
		}
		return nil
	}
	if holder == sessionID {
		return nil
	}
	return fmt.Errorf("%w", ErrConfigLockedByOther)
}

// reclaimedHoldersCap bounds reclaimedHolders. A reclaim fires only for a lock
// idle past the lease, so the set grows slowly; past the cap an arbitrary
// entry is dropped.
const reclaimedHoldersCap = 64

func (s *Store) markReclaimedHolderLocked(holder string) {
	if holder == "" {
		return
	}
	if s.reclaimedHolders == nil {
		s.reclaimedHolders = make(map[string]struct{})
	}
	if _, ok := s.reclaimedHolders[holder]; !ok && len(s.reclaimedHolders) >= reclaimedHoldersCap {
		for k := range s.reclaimedHolders {
			delete(s.reclaimedHolders, k)
			break
		}
	}
	s.reclaimedHolders[holder] = struct{}{}
}

// configLockLeaseTTL bounds how long a config lock may sit idle — with no edit
// activity — before a new entrant may reclaim it. #4476: the REST config-enter
// path (POST /api/v1/config/enter) is stateless and has NO disconnect hook,
// unlike the gRPC configLockInterceptor (pkg/grpcapi/server.go) which
// auto-releases the lock when a client's connection drops. A REST client that
// takes the lock and never calls /config/exit would otherwise wedge every
// CLI/gRPC/REST config edit until `clear system config-lock` or a daemon
// restart — a management-plane config-edit DoS. Every config mutation refreshes
// the lease (touchConfigLockLocked), so this TTL only ever reclaims a lock that
// has seen no edit for the full window; an actively-edited lock, including a
// long hand-composed change, is never stolen. Kept as a package var so tests
// can shrink it.
var configLockLeaseTTL = 10 * time.Minute

// touchConfigLockLocked refreshes the config-lock idle lease on a mutation
// (#4476). Both transports funnel config edits through the store's mutating
// methods (REST and gRPC both go via SetFromInput/DeleteFromInput/Commit/...),
// so refreshing here keeps an active holder's lease fresh regardless of which
// mode acquired it or whether a session identifier was recorded. Reads
// (show/status polls) deliberately do NOT refresh, so a lock held by a client
// that stops editing eventually becomes reclaimable. No-op when not in config
// mode. Callers MUST hold s.mu.
func (s *Store) touchConfigLockLocked() {
	if s.configDir {
		s.configLockAt = time.Now()
	}
}

// reclaimStaleLockLocked releases the current config lock IFF it has been idle
// (no edit activity) for longer than configLockLeaseTTL, and reports whether it
// did. It mirrors ForceExitConfigure's teardown but is gated on the idle lease,
// so an active holder is never disturbed. This is the check-on-acquire reaper
// for #4476: EnterConfigureSession / EnterConfigureExclusive call it before
// rejecting a would-be entrant with ErrConfigLocked, so a wedged REST lock is
// reclaimed exactly when another session needs it (the only moment a stuck lock
// causes harm). Callers MUST hold s.mu and MUST have already confirmed
// s.configDir.
func (s *Store) reclaimStaleLockLocked() bool {
	if time.Since(s.configLockAt) < configLockLeaseTTL {
		return false
	}
	slog.Warn("reclaiming stale config lock past idle lease",
		"holder", s.effectiveHolderLocked(),
		"idle_for", time.Since(s.configLockAt).Round(time.Second),
		"lease_ttl", configLockLeaseTTL)
	// #9632: remember whose lock this was before clearing it.
	s.markReclaimedHolderLocked(s.effectiveHolderLocked())
	s.candidate = nil
	s.bumpCandidateGenLocked() // #5848: candidate discarded — advance the generation
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.configHolder = ""
	// #6808: the config lock changed hands — advance the holder epoch so a
	// commit authorized under the previous holder cannot promote here.
	s.holderEpoch++
	s.editPath = nil
	return true
}

// EnterConfigure enters configuration mode by cloning the active config.
// Returns an error if another session is already in config mode.
func (s *Store) EnterConfigure() error {
	return s.EnterConfigureSession("")
}

// EnterConfigureSession enters configuration mode with a session identifier.
// If the same session already holds the lock, it's a no-op.
func (s *Store) EnterConfigureSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if s.configDir {
		// Allow re-entry by same session — and treat it as activity, so a
		// long-lived interactive session refreshes its idle lease (#4476)
		// rather than being reclaimed out from under itself.
		if sessionID != "" && s.configHolder == sessionID {
			s.configLockAt = time.Now()
			return nil
		}
		// #4476: reclaim a stale lease before rejecting. The current holder may
		// be a REST client that took the lock and never released it — the
		// stateless REST path has no disconnect hook like the gRPC
		// configLockInterceptor — which would otherwise wedge every config edit
		// forever. reclaimStaleLockLocked only fires on a lock idle past the
		// lease TTL; an actively-edited lock refreshes configLockAt on every
		// mutation and is never stolen.
		if !s.reclaimStaleLockLocked() {
			// #2157: return the ErrConfigLocked sentinel (wrapping the plain
			// message) so deferrable callers (the event-options action worker)
			// can errors.Is it and retry instead of string-matching.
			return fmt.Errorf("%w", ErrConfigLocked)
		}
	}
	s.candidate = s.active.Clone()
	s.bumpCandidateGenLocked() // #5848: entered config mode — advance the generation
	s.configDir = true
	s.dirty = false
	s.exclusiveHolder = ""
	s.configHolder = sessionID
	delete(s.reclaimedHolders, sessionID) // #9632: re-entered, so no longer refused
	// #6808: the config lock changed hands — advance the holder epoch so a
	// commit authorized under the previous holder cannot promote here.
	s.holderEpoch++
	s.configLockAt = time.Now()
	s.editPath = nil
	return nil
}

// EnterConfigureExclusive enters exclusive configuration mode.
func (s *Store) EnterConfigureExclusive(holder string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	if s.configDir {
		// #9119: allow re-entry by the SAME exclusive holder, and treat it as
		// activity, exactly as EnterConfigureSession has done since #4476.
		//
		// Without this arm the exclusive path was asymmetric with its shared
		// sibling in two ways, and the second is the damaging one. Measured:
		//
		//	fresh lease, same holder   -> ErrConfigLocked, staged edits kept
		//	stale lease, same holder   -> nil, and IsDirty() flips true -> FALSE
		//	shared-mode control        -> nil, staged edits kept
		//
		// So an automation client holding the exclusive lock could not
		// idempotently re-assert it, and if it re-asserted after a stall past
		// the idle lease it silently DESTROYED its own staged candidate --
		// reclaimStaleLockLocked discards the candidate for any entrant by
		// #4476's design, and here the entrant is the holder itself.
		//
		// MUST SIT BEFORE reclaimStaleLockLocked, or the stale-lease case
		// reclaims (and wipes) before the self-check can spare it. That
		// ordering is the whole fix for the second row above.
		//
		// AND IT MATCHES ON exclusiveHolder, NOT effectiveHolderLocked(). Using
		// the effective holder would make a SHARED-mode holder's call to this
		// function return nil while leaving the lock shared: the caller would
		// believe it had upgraded to exclusive and would not have. A silent
		// failure to acquire the stronger lock is worse than a refusal, so a
		// shared holder asking for exclusive falls through and is refused --
		// which is what it already did before this change.
		if holder != "" && s.exclusiveHolder == holder {
			s.configLockAt = time.Now()
			return nil
		}
		// #4476: reclaim a stale lease before rejecting, same idle-lease
		// contract as EnterConfigureSession.
		if !s.reclaimStaleLockLocked() {
			return fmt.Errorf("%w", ErrConfigLocked)
		}
	}
	s.candidate = s.active.Clone()
	s.bumpCandidateGenLocked() // #5848: entered config mode — advance the generation
	s.configDir = true
	s.dirty = false
	s.configHolder = ""
	s.exclusiveHolder = holder
	delete(s.reclaimedHolders, holder) // #9632: re-entered, so no longer refused
	// #6808: the config lock changed hands — advance the holder epoch so a
	// commit authorized under the previous holder cannot promote here.
	s.holderEpoch++
	s.configLockAt = time.Now()
	s.editPath = nil
	return nil
}

// effectiveHolderLocked returns the session ID that currently holds the config
// lock, regardless of mode. Exclusive mode records the holder in
// exclusiveHolder; shared/private mode records it in configHolder. Callers MUST
// hold s.mu. Returns "" when no session identifier was supplied at acquire time
// (the internal EnterConfigure()/daemon path) or when unlocked.
func (s *Store) effectiveHolderLocked() string {
	if s.exclusiveHolder != "" {
		return s.exclusiveHolder
	}
	return s.configHolder
}

// ExitConfigureSession exits configuration mode only if the given session holds
// the lock. Returns true if the lock was released.
//
// #3979: the release guard must match against whichever holder field the
// acquiring mode actually set. EnterConfigureExclusive records the holder in
// exclusiveHolder and leaves configHolder empty; the previous guard compared
// only configHolder, so an exclusive holder could NEVER release its own lock —
// the guard saw configHolder("") != sessionID and bailed out early. The lock
// then persisted with no live holder (the disconnect auto-release in
// configLockInterceptor routes through here too, so it silently failed), and
// every subsequent configure/configure exclusive/configure private was
// rejected until daemon restart — a single operator using `configure exclusive`
// then disconnecting bricked all future config edits. Comparing against the
// effective holder releases whichever lock THIS session holds and restores the
// stale-holder reclaim on disconnect.
func (s *Store) ExitConfigureSession(sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.configDir {
		return false
	}
	if sessionID != "" && s.effectiveHolderLocked() != sessionID {
		return false
	}
	s.candidate = nil
	s.bumpCandidateGenLocked() // #5848: candidate discarded — advance the generation
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.configHolder = ""
	// #6808: the config lock changed hands — advance the holder epoch so a
	// commit authorized under the previous holder cannot promote here.
	s.holderEpoch++
	s.editPath = nil
	return true
}

// ForceExitConfigure exits configuration mode regardless of who holds the lock.
// Used for stale lock cleanup.
func (s *Store) ForceExitConfigure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.configDir {
		return
	}
	slog.Warn("force-releasing stale config lock", "holder", s.configHolder,
		"held_for", time.Since(s.configLockAt).Round(time.Second))
	s.candidate = nil
	s.bumpCandidateGenLocked() // #5848: candidate discarded — advance the generation
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.configHolder = ""
	// #6808: the config lock changed hands — advance the holder epoch so a
	// commit authorized under the previous holder cannot promote here.
	s.holderEpoch++
	s.editPath = nil
}

// ConfigHolder returns the session ID of the current config lock holder
// and whether the lock is held. #3979: report the effective holder so an
// exclusive lock (tracked in exclusiveHolder, with configHolder empty) is
// attributed to its real holder in `clear system config-lock` / diagnostic
// output instead of an empty string.
func (s *Store) ConfigHolder() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.effectiveHolderLocked(), s.configDir
}

// IsExclusiveLocked returns true if exclusive mode is active.
func (s *Store) IsExclusiveLocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.exclusiveHolder != ""
}

// ExitConfigure exits configuration mode, discarding the candidate.
//
// #7635: this clears BOTH holder fields, matching ExitConfigureSession,
// ForceExitConfigure and reclaimStaleLockLocked. It previously cleared only
// exclusiveHolder, leaving a stale configHolder behind; that was safe solely
// because ensureHolderLocked short-circuits on !s.configDir and because every
// in-tree caller pairs it with the unsessioned EnterConfigure (sessionID ""),
// so the field was empty anyway. Neither is a property of this function, and
// the public ConfigHolder() accessor reported the stale string to any caller
// that did not first check the locked bool. Leaving config mode is a release,
// so the release is now complete here as it is on the other three paths.
//
// The #6808 holder-epoch bump below is independent of that and stays: it is
// what makes this path safe without depending on the field being clean, so a
// commit authorized before the exit fails verification afterwards.
func (s *Store) ExitConfigure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidate = nil
	s.bumpCandidateGenLocked() // #5848: candidate discarded — advance the generation
	s.configDir = false
	s.dirty = false
	s.exclusiveHolder = ""
	s.configHolder = ""
	// #6808: the config lock was released — advance the holder epoch.
	s.holderEpoch++
	s.editPath = nil
}

// SetEditPath sets the edit path for hierarchical navigation.
func (s *Store) SetEditPath(path []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.editPath = path
}

// GetEditPath returns a copy of the current edit path.
func (s *Store) GetEditPath() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.editPath...)
}

// NavigateUp moves the edit path up one level.
func (s *Store) NavigateUp() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.editPath) > 0 {
		s.editPath = s.editPath[:len(s.editPath)-1]
	}
}

// NavigateTop resets the edit path to the root.
func (s *Store) NavigateTop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.editPath = nil
}

// InConfigMode returns true if currently in configuration mode.
func (s *Store) InConfigMode() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configDir
}

// IsDirty returns true if the candidate differs from active.
func (s *Store) IsDirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dirty
}
