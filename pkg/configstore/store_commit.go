package configstore

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// isPostRenameDurabilityFailure reports whether err is fsatomic's
// post-rename directory-fsync failure (#5185). At that point the NEW
// content is already VISIBLE on disk (a daemon restart would load it),
// only its durability across power loss is unknown — categorically
// different from a pre-rename failure, which leaves the OLD content intact.
// The commit paths use it to converge to the new content on a post-rename
// failure instead of reporting a clean rejection while the new content is
// durable on disk (durable(C) != in-memory/applied(A)).
func isPostRenameDurabilityFailure(err error) bool {
	var e *fsatomic.PostRenameSyncError
	return errors.As(err, &e)
}

// Rollback/archive persistence seams (#3441, following the #1916
// pkg/api/tls_test.go pattern). Production code must never mutate these;
// tests override them to record durability calls (so a test fails RED if a
// WriteFileDurable is downgraded to atomic or a SyncDir is dropped) and to
// inject write failures. nil-free: each aliases the real fsatomic writer.
var (
	rbWriteFileDurable = fsatomic.WriteFileDurable
	rbWriteFileAtomic  = fsatomic.WriteFileAtomic
	rbSyncDir          = fsatomic.SyncDir
	rbRemove           = os.Remove
)

// archiveWriteBarrier is a test-only seam (#5869) invoked AFTER the archive
// fence check and BEFORE the actual write by BOTH archive writers: the async
// auto-archive goroutine and the synchronous Store.ArchiveConfig path (#6185).
// Production is a no-op. A test overrides it to hold a writer MID-FLIGHT —
// deliberately PAST the fence check, so the fence cannot mask it — to prove
// QuiesceArchival JOINS an in-flight writer (not merely fences future ones)
// before a factory reset erases the archive directory. Never mutated by
// production code.
var archiveWriteBarrier = func() {}

// maxCommitDescriptionBytes bounds the operator-supplied commit description
// (the `commit comment` text) that is recorded verbatim in the in-memory
// history entry and the durable JSONL audit journal.
//
// #4891: an unbounded description marshals into a single oversized JSONL line.
// The journal's bounded reverse-tail scanner (journal.maxTailLineBytes, 16 MiB)
// treats any line past its cap as a poisoned newline-free fragment and discards
// it — so an oversized-but-valid commit record would VANISH from bounded
// history / `show system commit` views after allocating memory and disk
// proportional to its size. 4 KiB is far above any human-authored commit
// comment while keeping every journal line orders of magnitude below the
// tail-scanner cap. Enforced strictly on the operator commit path (fail the
// commit with a clear error before anything is persisted — the #1960 strict-at-
// commit doctrine) and, as a structural belt at the journal boundary,
// defensively truncated in journalLog so no Detail from any caller can poison
// the tail scanner.
const maxCommitDescriptionBytes = 4 << 10

// CommitCheck validates the candidate configuration without applying it.
func (s *Store) CommitCheck() (*config.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := s.compileTree(s.candidate)
	if err != nil {
		return nil, err
	}

	return compiled, nil
}

// Commit validates, compiles, and applies the candidate configuration.
// Returns the compiled config for the caller to apply to the dataplane.
// Identical to CommitWithDescription with an empty description (the two
// were verbatim duplicates before #1799 unified them).
func (s *Store) Commit() (*config.Config, error) {
	return s.CommitWithDescription("")
}

// CommitWithDescription validates, compiles, and applies the candidate configuration
// with an optional comment/description attached to the history and journal entries.
//
// Persistence contract (#1799, Option A — persist-before-promote): the
// candidate tree is written to the on-disk active config BEFORE any
// in-memory promotion. WriteActive is temp-file + rename atomic
// (db.go), so a persist failure leaves the previous active config
// intact on disk; the commit then fails with the candidate left
// intact and NOTHING mutated — no active/candidate/compiled/dirty
// change, no history push, no journal entry, no rollback-file save.
// A commit that reports success can therefore never silently revert
// to the previous config on daemon restart.
func (s *Store) CommitWithDescription(description string) (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitWithDescriptionLocked(description)
}

// CommitWithDescriptionGen is CommitWithDescription bound to an expected
// candidate generation (#5848). It promotes the candidate ONLY if the current
// candidate generation still equals expectedGen — the token the caller captured
// (via CompileCandidateGen) before running its external device-map pre-flight.
// A concurrent set/delete/load/rollback/enter-exit between snapshot and promote
// bumps the generation, so this returns ErrCandidateGenerationConflict WITHOUT
// mutating any store state, and the caller re-runs the whole
// snapshot→pre-flight→commit against the new generation. This closes the
// examined-generation-vs-promoted-generation race: the compiled config the
// daemon pre-flighted against live hardware is exactly the one promoted, or the
// commit conflicts — never a silent substitution.
func (s *Store) CommitWithDescriptionGen(description string, expectedGen uint64) (*config.Config, error) {
	return s.CommitWithDescriptionGenAs(InternalCommitter(), description, expectedGen)
}

// CommitWithDescriptionGenAs is CommitWithDescriptionGen additionally bound to
// the AUTHORITY the commit was granted under (#6808).
//
// It verifies BOTH tokens under one acquisition of s.mu, immediately before
// promotion, because they answer different questions and neither implies the
// other:
//
//   - expectedGen answers "is the candidate CONTENT the one that was examined?"
//   - authority answers "is the SESSION that was authorized to commit still the
//     one holding the lock?"
//
// A holder turnover that completes before the caller's snapshot produces a
// perfectly consistent generation pair — describing the NEW holder's candidate.
// Only the authority check rejects that.
//
// On turnover it returns ErrConfigHolderTurnover, NOT
// ErrCandidateGenerationConflict, so it can never be swept into the caller's
// generation-conflict retry: retrying would re-snapshot the new holder's
// candidate and promote it under the old holder's authorization, which is
// precisely the substitution being closed.
func (s *Store) CommitWithDescriptionGenAs(
	authority CommitAuthority, description string, expectedGen uint64,
) (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.verifyCommitAuthorityLocked(authority); err != nil {
		return nil, err
	}
	if s.candidateGen != expectedGen {
		return nil, fmt.Errorf("%w (examined generation %d, current %d)",
			ErrCandidateGenerationConflict, expectedGen, s.candidateGen)
	}
	return s.commitWithDescriptionLocked(description)
}

// commitWithDescriptionLocked is the shared body of CommitWithDescription and
// the generation-bound CommitWithDescriptionGen. Caller holds s.mu.Lock.
func (s *Store) commitWithDescriptionLocked(description string) (*config.Config, error) {
	// #3893: reject a user-session commit on a read-only secondary. The
	// internal HA-sync ingress (SyncApply) and the commit-confirmed timeout
	// revert (PromoteRollback) promote the active config directly and never
	// reach here, so they are unaffected by this gate.
	if err := s.ensureWritableLocked(); err != nil {
		return nil, err
	}
	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	// #4891: reject an over-cap commit description BEFORE anything is
	// persisted or promoted. Fail-fast with a clear error (the #1960
	// strict-at-commit doctrine) so an oversized comment never bloats the
	// journal nor hides itself behind the tail scanner's corrupt-line defense.
	if len(description) > maxCommitDescriptionBytes {
		return nil, fmt.Errorf("commit description too long: %d bytes (max %d)",
			len(description), maxCommitDescriptionBytes)
	}

	compiled, err := s.compileTree(s.candidate)
	if err != nil {
		return nil, fmt.Errorf("commit check failed: %w", err)
	}

	// #1799 Option A: persist BEFORE promote. On a PRE-rename failure the
	// old active stays on disk and in memory; the operator sees the error
	// and the candidate is still there to retry.
	//
	// #5185: a POST-rename directory-fsync failure is categorically
	// different — the candidate (C) is already VISIBLE on disk (a restart
	// would load C), only its durability across power loss is unknown.
	// Returning a plain "commit failed" there would leave
	// durable(C) != in-memory/applied(A): the operator is told REJECTED
	// while a restart activates C — the reported-rejected-but-durable
	// divergence. So on a post-rename failure CONVERGE instead of rejecting:
	// promote C in memory and return the compiled config so the daemon
	// APPLIES it, restoring durable==memory==applied, and flag the
	// durability uncertainty through the Option-B degraded machinery
	// (health 503, gauge, journal ERROR, background re-fsync retry via
	// noteActivePersistFailureLocked). Converge-to-C is chosen over
	// durably-restoring-A because restoring A needs ANOTHER rename that can
	// itself fail post-rename — fsatomic cannot guarantee an atomic restore
	// — whereas C is already the durable content, so converging to it needs
	// no further write to hold the invariant.
	if err := s.writeActive(s.candidate); err != nil {
		if !isPostRenameDurabilityFailure(err) {
			return nil, fmt.Errorf("commit failed: persist active config: %w", err)
		}
		// Post-rename: converge memory+applied to C (fall through to the
		// promotion below), but keep the degraded signal. everCommitted /
		// persistMarkerCommitted are set BEFORE noteActivePersistFailureLocked
		// so the background retry re-writes committed=1 for C.
		s.everCommitted = true
		s.persistMarkerCommitted = true
		s.noteActivePersistFailureLocked("commit_postrename", err)
		// #5473: this commit's config C is VISIBLE on disk (post-rename: the
		// rename landed, only the dir-fsync is uncertain) and supersedes any
		// commit-confirmed window whose earlier resolution write failed. Finalize
		// the deferred (retained) confirm.json removal now — symmetric with the
		// success branch. Without this the stale flag persists into the degraded
		// retry, whose heal would then delete a LATER-armed window's fresh record
		// (or, for a plain commit, a stale PrevTree=A record lingers and a crash
		// reverts this just-committed C back to A). No-op unless a removal was
		// deferred.
		s.clearConfirmResolutionPendingLocked()
	} else {
		s.persistDegraded = false       // disk now holds the current config
		s.everCommitted = true          // #1922 step-0: a real commit has succeeded
		s.persistMarkerCommitted = true // #1922: degraded-retry writes committed=1
		// #5473: this commit's config is now durable and supersedes any
		// commit-confirmed window whose earlier resolution write failed. Drop
		// the deferred (retained) confirm.json so a reboot does not re-drive a
		// stale rollback that this commit has replaced. No-op unless a removal
		// was deferred.
		s.clearConfirmResolutionPendingLocked()
	}

	// Push current active to history with description
	s.history.Push(&HistoryEntry{
		Config:    s.active.Clone(),
		Timestamp: time.Now(),
		Comment:   description,
	})

	// Promote candidate to active
	s.active = s.candidate
	s.candidate = s.active.Clone()
	s.bumpCandidateGenLocked() // #5848: fresh candidate — advance the generation
	s.compiled = compiled
	s.dirty = false
	s.touchConfigLockLocked() // #4476: a commit is activity — refresh the lease

	// #3861: a PLAIN commit during a pending commit-confirmed window is
	// the confirmation (Junos semantics: any subsequent explicit commit
	// confirms a pending `commit confirmed`). The frontend `commit` path
	// intercepts a pending confirm and calls ConfirmCommit before it ever
	// reaches here, but NON-frontend callers (the eventengine remediation
	// commit, cli/gRPC/REST commit handlers) reach CommitWithDescription
	// directly. Without clearing the armed timer, its rollback target (the
	// pre-confirm T0 tree) stays live and reverts THIS just-promoted
	// config when it fires — silently discarding the background commit.
	// clearPendingConfirmLocked cancels the timer AND bumps confirmGen so a
	// callback that already fired and is blocked on s.mu no-ops instead of
	// reverting. Runs only AFTER the persist+promote succeeded, so a failed
	// commit leaves the pending confirm fully intact.
	// #5835: a plain commit is non-interactive here (the frontend confirm path
	// already returned an error to the operator when applicable); a durable
	// confirm.json-removal failure is retained as retry debt + degraded health
	// inside clearPendingConfirmLocked and converges autonomously.
	if cleared, _ := s.clearPendingConfirmLocked(); cleared {
		slog.Info("plain commit confirmed a pending commit-confirmed window")
	}

	// Log to journal with description
	s.journalLog(&JournalEntry{
		Action:     "commit",
		Detail:     description,
		ConfigHash: journalConfigHash(s.active),
	})

	s.saveRollbackFiles()

	// Auto-archive if configured (#3441 H4). Capture the JUST-COMMITTED
	// text, directory, max, and a nanosecond-resolution timestamp INSIDE
	// the commit critical section, then hand only those immutable values
	// to the async writer. The previous code passed nothing and let the
	// goroutine read s.active.Format() whenever it eventually ran: two
	// rapid commits raced so goroutine A could archive commit B's tree
	// (mislabeled archive), and the second-resolution filename meant two
	// same-second commits wrote the same path (later overwrote earlier).
	// The nanosecond timestamp makes the filename unique per commit (no
	// overwrite) and correctly labels the captured tree.
	//
	// #5869: skip launching a writer once the archive fence is set (a factory
	// reset is erasing the archive directory) and TRACK every writer we do
	// launch in s.archiveWG so QuiesceArchival can JOIN it before the wipe. The
	// launch guard and the Add(1) run under s.mu (held across
	// commitWithDescriptionLocked), and QuiesceArchival sets the fence under the
	// same lock before it Wait()s — so no Add can start after the fence, and the
	// WaitGroup counter never rises from zero concurrently with Wait.
	if s.archiveDir != "" && !s.archiveFenced.Load() {
		// #6404: re-attempt the archive-seq reseed if a prior SetArchiveConfig
		// scan of this dir failed (archiveSeedDir != archiveDir).
		// commitWithDescriptionLocked runs under s.mu.Lock (write), so
		// ensureArchiveSeededLocked may safely store archiveSeedDir. Edge 1: a
		// commit that lands in the window between a failed scan and the next
		// SetArchiveConfig retry re-scans here instead of capturing the still-low
		// seq. When the dir is already seeded the readiness check is a cheap
		// string compare — no per-commit ReadDir.
		if !s.ensureArchiveSeededLocked() {
			// Codex round-2 MAJOR: the commit-time rescan ALSO failed
			// (persistent scan error), so the on-disk max is unknown and the
			// counter is unconfirmed. Writing at the low counter would drop a
			// below-max archive that rotateArchives prunes as stale once the
			// scan recovers, LOSING this config version's archive. Skip this
			// commit's archive entirely — the next commit after the scan
			// recovers archives correctly. Skipping one archive during a
			// scan-failure window is strictly safer than writing a mis-seq'd one.
			slog.Warn("archive seq unconfirmed after scan failure; skipping this commit's archive, will archive on the next successful commit",
				"dir", s.archiveDir)
		} else {
			dir := s.archiveDir
			max := s.archiveMax
			if max <= 0 {
				max = 10
			}
			data := s.active.Format()
			ts := time.Now()
			seq := s.archiveSeq.Add(1)
			s.archiveWG.Add(1)
			go func() {
				defer s.archiveWG.Done()
				// #5869: re-check the fence inside the goroutine. A writer that
				// observes it (a factory reset began after this commit launched the
				// writer, before it reached the write) MUST NOT recreate the archive
				// directory the wipe is about to erase — that would resurrect the
				// prior tenant's config secrets on a re-tenanted device.
				if s.archiveFenced.Load() {
					return
				}
				archiveWriteBarrier()
				if err := writeArchive(dir, max, data, ts, seq); err != nil {
					slog.Warn("auto-archive failed", "err", err)
				}
			}()
		}
	}

	return compiled, nil
}

// SetRollbackExecutor registers the daemon's commit-confirmed timeout
// rollback transaction (#1922 Item 1a). The executor is invoked (on the
// timer's own goroutine, never under s.mu) with the confirm generation
// that armed the timer. It MUST acquire the daemon apply semaphore
// first, then call PromoteRollback(gen) + re-apply the returned config,
// so store promotion and dataplane re-apply are atomic under the same
// lock that serializes commits. Registering nil disables the executor
// and reverts to the self-contained performAutoRollback fallback.
func (s *Store) SetRollbackExecutor(fn func(gen uint64)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollbackExecutor = fn
}

// CommitConfirmed validates, compiles, and applies the candidate with an
// automatic rollback timer. If minutes is 0, defaults to 10.
// If a bare "commit" is not issued within the timeout, the config auto-reverts.
//
// Persistence contract (#1799, Option A + confirm-state ordering): the
// candidate is persisted BEFORE any in-memory promotion AND before any
// confirm state is touched. On persist failure nothing changes: no
// promotion, no timer armed, and an EXISTING pending confirm (its
// timer and rollback target) is left fully intact — the prior ordering
// cancelled the pending timer and overwrote the rollback target before
// the write, so a persist failure could strand a pending confirmed
// commit with no auto-rollback.
//
// Nested confirmed commits (a second CommitConfirmed while one is
// still pending) PRESERVE the existing confirmPrevTree/confirmPrevCfg:
// the rollback target must stay the last truly CONFIRMED config.
// Overwriting it with s.active (the unconfirmed commit-1 tree, as the
// code did before #1799) meant a commit-2 timeout "rolled back" to the
// equally-unconfirmed commit 1 and stayed there forever, because
// commit 1's own timer had been cancelled.
// MaxCommitConfirmedMinutes is the inclusive upper bound on a
// `commit confirmed <minutes>` auto-rollback window, matching the Junos
// range (1..65535 minutes). It bounds the timer so
// `time.Duration(minutes)*time.Minute` cannot overflow int64 nanoseconds
// (#4868). CLI parse sites enforce the same bound before the RPC.
const MaxCommitConfirmedMinutes = 65535

func (s *Store) CommitConfirmed(minutes int) (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitConfirmedLocked(minutes)
}

// CommitConfirmedGen is CommitConfirmed bound to an expected candidate
// generation (#5848), the commit-confirmed analogue of CommitWithDescriptionGen.
// It promotes+arms the auto-rollback timer ONLY if the candidate generation
// still equals expectedGen, else returns ErrCandidateGenerationConflict without
// mutating state. The rollback TARGET (the current active config the daemon
// pre-flighted) is stable across the transaction: the daemon holds its apply
// semaphore from pre-flight through this call, and every path that mutates the
// active config (commit, commit-confirmed, peer SyncApply, confirm-timeout
// rollback) runs under that same semaphore — so binding the (racy, semaphore-
// free) candidate generation is sufficient to keep both the promoted candidate
// and the stashed rollback target bound to what was examined.
func (s *Store) CommitConfirmedGen(minutes int, expectedGen uint64) (*config.Config, error) {
	return s.CommitConfirmedGenAs(InternalCommitter(), minutes, expectedGen)
}

// CommitConfirmedGenAs is CommitConfirmedGen additionally bound to the commit
// AUTHORITY (#6808) — the commit-confirmed analogue of
// CommitWithDescriptionGenAs, with the same both-tokens-under-one-lock
// discipline and the same distinct turnover sentinel.
//
// Commit-confirmed is the higher-consequence half: promoting another holder's
// candidate ALSO arms an auto-rollback timer against it, so a substituted
// commit-confirmed both applies work its author never approved and schedules a
// revert the authorized operator does not know is pending.
func (s *Store) CommitConfirmedGenAs(
	authority CommitAuthority, minutes int, expectedGen uint64,
) (*config.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.verifyCommitAuthorityLocked(authority); err != nil {
		return nil, err
	}
	if s.candidateGen != expectedGen {
		return nil, fmt.Errorf("%w (examined generation %d, current %d)",
			ErrCandidateGenerationConflict, expectedGen, s.candidateGen)
	}
	return s.commitConfirmedLocked(minutes)
}

// commitConfirmedLocked is the shared body of CommitConfirmed and the
// generation-bound CommitConfirmedGen. Caller holds s.mu.Lock.
func (s *Store) commitConfirmedLocked(minutes int) (*config.Config, error) {
	// #3893: reject a user-session commit-confirmed on a read-only secondary
	// (same gate as CommitWithDescription).
	if err := s.ensureWritableLocked(); err != nil {
		return nil, err
	}
	if s.candidate == nil {
		return nil, fmt.Errorf("not in configuration mode")
	}

	compiled, err := s.compileTree(s.candidate)
	if err != nil {
		return nil, fmt.Errorf("commit check failed: %w", err)
	}

	if minutes <= 0 {
		minutes = 10
	}
	// #4868: bound the confirm window. Without an upper bound a large value
	// overflows `time.Duration(minutes)*time.Minute` (int64 nanoseconds) below,
	// yielding a wrapped/negative deadline that fires an immediate or wrong
	// auto-rollback AFTER the candidate has already been promoted. Reject
	// out-of-range values here (defense in depth — the CLIs validate first, and
	// the gRPC handler maps this to InvalidArgument) rather than silently
	// wrapping. `minutes` never reaches the AfterFunc unclamped.
	if minutes > MaxCommitConfirmedMinutes {
		return nil, fmt.Errorf("commit confirmed: timeout %d exceeds maximum %d minutes",
			minutes, MaxCommitConfirmedMinutes)
	}

	// #7291: capture the DURABLE never-committed state before anything below
	// sets it. Both the post-rename-converge branch and the success branch set
	// s.everCommitted = true ahead of the arm site, so by the time the rollback
	// target is recorded the flag no longer says what it said on entry.
	everCommittedOnEntry := s.everCommitted

	// #1799 Option A: persist BEFORE promoting and BEFORE touching
	// any confirm state (see contract above).
	//
	// #5185: classify the failure exactly as CommitWithDescription does. A
	// PRE-rename failure is a clean rejection — old active intact, and (per
	// the #1799 ordering) no confirm state touched. A POST-rename dir-fsync
	// failure leaves the candidate (C) visible on disk, so converge to it
	// (promote, arm the timer, return compiled) and flag degraded
	// durability, rather than report REJECTED while a restart would activate
	// C. Rationale (converge-to-C over restore-A) is in CommitWithDescription.
	// #9617: preflight the commit-confirmed RECORD before anything is
	// promoted. confirm.json nests the rollback target one indentation level
	// deeper than active.json (MarshalIndent adds two bytes per line), so a
	// readable active DB does not bound its own confirm record, and the record
	// is only written after promotion (writeConfirmState below). Without this, a
	// record ReadConfirm will refuse is reported as an armed, crash-surviving
	// window, and a restart inside it keeps the unconfirmed config with no
	// timer. The record encoded here is the one writeConfirmState writes: the
	// same rollback target, the same deadline (hoisted for exactly this reason)
	// and the guarded hash of the tree about to become active; the encrypted
	// length is a function of the plaintext length.
	deadline := time.Now().Add(time.Duration(minutes) * time.Minute)
	if s.db != nil {
		prevTree, prevFirst := s.active, !everCommittedOnEntry
		if s.confirmTimer != nil {
			prevTree, prevFirst = s.confirmPrevTree, s.confirmPrevFirst
		}
		// Encode the TOMBSTONE form (Resolved: true). #8565 re-writes the record
		// with `resolved` before removing it, so that form is the larger of the
		// two this window will write, and a window that arms must also be
		// resolvable: a tombstone refused at the ceiling, followed by a failed
		// removal, would leave the unresolved record to re-arm a confirmed
		// window on reboot. Any encode failure rejects, with the candidate
		// intact: a window whose rollback record cannot be produced now has no
		// rollback to offer, and discovering that after promotion is the defect
		// this preflight exists to remove.
		if _, err := s.db.encodeConfirm(&confirmRecord{
			Deadline:    deadline,
			PrevTree:    prevTree,
			FirstCommit: prevFirst,
			GuardedHash: guardedConfigHash(s.candidate),
			Resolved:    true,
		}); err != nil {
			return nil, fmt.Errorf("commit confirmed failed: the rollback record would not survive a restart: %w", err)
		}
	}
	if err := s.writeActive(s.candidate); err != nil {
		if !isPostRenameDurabilityFailure(err) {
			return nil, fmt.Errorf("commit confirmed failed: persist active config: %w", err)
		}
		s.everCommitted = true
		s.persistMarkerCommitted = true
		s.noteActivePersistFailureLocked("commit_confirmed_postrename", err)
		// #5473: E's config is VISIBLE on disk (post-rename converge) and a fresh
		// window is about to be armed below (writeConfirmState). Finalize any
		// confirm.json removal deferred by an earlier failed resolution write
		// HERE — before the fresh window is written — so the stale flag does not
		// survive to make the degraded retry's heal delete E's OWN fresh record.
		// Symmetric with the success branch (removes STALE record; the fresh one
		// is written afterward by writeConfirmState). No-op unless a removal was
		// deferred.
		s.clearConfirmResolutionPendingLocked()
	} else {
		s.persistDegraded = false // disk now holds the current config
		// #1922 step-0: a commit confirmed persists the candidate as the
		// active config (committed=1 on disk via writeActive). The marker is
		// set here, NOT gated on confirmation — the on-disk DB is now a real
		// committed config; if the timer fires, the Item 1b first-commit
		// rollback path (prevCfg==nil) re-writes the never-committed marker.
		s.everCommitted = true
		s.persistMarkerCommitted = true
		// #5473: this commit's config is durable. Drop any confirm.json whose
		// removal was deferred by an earlier failed resolution write before the
		// fresh window below re-arms and re-writes it (clearConfirmResolution
		// removes the STALE record; writeConfirmState writes the NEW one). No-op
		// unless a removal was deferred.
		s.clearConfirmResolutionPendingLocked()
	}

	if s.confirmTimer != nil {
		// Nested confirmed commit: cancel the pending timer but keep
		// the original rollback target (last confirmed config).
		s.confirmTimer.Stop()
		s.confirmTimer = nil
	} else {
		// Save current active state for potential rollback.
		s.confirmPrevTree = s.active.Clone()
		s.confirmPrevCfg = s.compiled
		// #6538 records first-commit-ness HERE, where it is known, instead of
		// re-deriving it later from confirmPrevCfg==nil. #7291 corrects WHAT is
		// recorded: the durable never-committed marker, not the compiled
		// pointer.
		//
		// `s.compiled == nil` was an incidental proxy for "first commit" and it
		// is wrong in BOTH directions, because the two states are independent:
		//
		//   everCommitted=false, compiled != nil — after a #1922 Item 1b
		//   first-commit rollback the DB holds committed=0 with the EMPTY tree.
		//   The empty tree COMPILES, so the next Load leaves a never-committed
		//   store with a non-nil compiled config. The proxy said "not first",
		//   the rollback took the non-first branch, and it persisted
		//   committed=1 over a never-committed DB — the operator-committed-empty
		//   state, which computeBootClass resolves to NORMAL. The restart after
		//   that runs the positional claim-all interface rename on an empty
		//   config: precisely the #1922 Item 2 case-5 hazard the Item 1b marker
		//   exists to prevent.
		//
		//   everCommitted=true, compiled == nil — the #1960 broken-config load.
		//   The operator repairs the config and commits confirmed; the proxy
		//   said "first", so the rollback would write committed=0 over a box
		//   that HAS a committed config.
		//
		// everCommittedOnEntry is the durable marker as it stood before this
		// commit touched it, which is the authority the rollback branch needs.
		s.confirmPrevFirst = !everCommittedOnEntry
	}

	// Push current active to history
	s.history.Push(&HistoryEntry{
		Config:    s.active.Clone(),
		Timestamp: time.Now(),
	})

	// Promote candidate to active
	s.active = s.candidate
	s.candidate = s.active.Clone()
	s.bumpCandidateGenLocked() // #5848: fresh candidate — advance the generation
	s.compiled = compiled
	s.dirty = false
	s.touchConfigLockLocked() // #4476: a commit is activity — refresh the lease

	// Log to journal
	s.journalLog(&JournalEntry{
		Action:     "commit_confirmed",
		ConfigHash: journalConfigHash(s.active),
	})

	s.saveRollbackFiles()

	// Start auto-rollback timer. The closure captures the generation
	// at arm time; a stale callback from a superseded timer no-ops in
	// performAutoRollback.
	s.confirmGen++
	gen := s.confirmGen
	s.confirmTimer = time.AfterFunc(time.Duration(minutes)*time.Minute, func() {
		s.fireConfirmTimer(gen)
	})

	// #4577: persist the pending-confirm state so the auto-rollback deadline
	// survives a daemon crash/reboot inside the window. The in-memory timer
	// above is lost on restart; without confirm.json the just-promoted (and
	// still UNCONFIRMED) config would become permanent. Written AFTER the
	// successful writeActive+promote so a FAILED commit-confirmed never leaves
	// a confirm.json (persist-before-promote already returned above on
	// failure). PrevTree is confirmPrevTree — the ORIGINAL last-confirmed tree
	// for a nested re-arm; firstCommit is the recorded confirmPrevFirst, NOT a
	// re-derivation from confirmPrevCfg==nil (#6538: a nested arm preserves a
	// recovered rollback target, so that nil can mean "the target failed to
	// compile" and persisting it as firstCommit durably mislabels a real config
	// as the empty bootstrap tree). A residual crash window remains between the
	// writeActive syscall and this write (microseconds vs. the whole
	// multi-minute window before this fix).
	s.writeConfirmState(s.confirmPrevTree, deadline, s.confirmPrevFirst)

	slog.Info("commit confirmed started", "timeout_minutes", minutes)
	return compiled, nil
}

// writeConfirmState persists the pending commit-confirmed state (#4577) so the
// auto-rollback deadline + rollback target survive a daemon crash/reboot.
// Best-effort: a failure is logged, not fatal — the in-memory timer still
// covers the no-crash case (the #1799 degrade-not-fail doctrine). Caller holds
// s.mu.
func (s *Store) writeConfirmState(prevTree *config.ConfigTree, deadline time.Time, firstCommit bool) {
	if s.db == nil {
		return
	}
	rec := &confirmRecord{
		Deadline:    deadline,
		PrevTree:    prevTree,
		FirstCommit: firstCommit,
		// #5835: bind the record to the unconfirmed config it guards (s.active is
		// the just-promoted, still-unconfirmed tree at every arm/re-arm site). On
		// boot recovery a mismatch means a later commit/confirm advanced the
		// active config while this record's durable removal had failed — the
		// record is then stale and must not resurrect a rollback.
		GuardedHash: guardedConfigHash(s.active),
	}
	if err := s.db.WriteConfirm(rec); err != nil {
		s.noteConfirmArmFailureLocked(rec, err)
		return
	}
	// #8566: a readable record now exists again, so the "boot lost the window"
	// state is over. It clears on operator action rather than on its own
	// because nothing else can heal it — the lost window cannot be recovered.
	s.confirmRecoveryReadFailed = false
	// #9014: this write IS the debt. A successful arm — whether the first try
	// or a re-arm by a later `commit confirmed` — discharges any outstanding
	// arm-write debt, because the record on disk is now current.
	s.confirmArmDegraded = false
	s.confirmArmRec = nil
}

// noteConfirmArmFailureLocked records that the ARM write establishing a
// commit-confirmed window did not become durable, and starts the self-healing
// retry (#9014).
//
// THIS WAS THE ONE CONFIRM-DURABILITY LEG THAT RAISED NOTHING. It logged a
// single slog.Warn and returned; CommitConfirmed still reported success and
// /health stayed 200, so a crash or reboot inside the confirm window found no
// record, the unconfirmed configuration stood permanently, and nothing had
// alerted. Its two neighbours already did the opposite:
//
//	confirm READ at boot      confirmRecoveryReadFailed  journal  —      degraded
//	confirm REMOVAL           confirmRemoveDegraded      journal  retry  degraded
//	confirm ARM (this)        none                       none     none   200 OK
//
// The invariant it broke is written down in the same package, in #8566's own
// rationale: "Every OTHER way the store ends a boot unsafe raises degraded
// health; this one did not, so nothing alerted on it."
//
// The commit is NOT failed. That matches both neighbours and the #1960
// no-brick doctrine: the configuration is applied and correct, only its
// crash-recovery record is missing, and refusing the commit would turn a
// durability problem into an availability one. Health, the journal and the
// retry are what make it legible.
//
// Caller holds s.mu (write lock).
func (s *Store) noteConfirmArmFailureLocked(rec *confirmRecord, err error) {
	slog.Error("failed to persist commit-confirmed state; the auto-rollback will not "+
		"survive a crash within the confirm window, so a restart would leave the "+
		"UNCONFIRMED configuration standing permanently — configuration persistence "+
		"is degraded until the retry lands or the window is resolved",
		"err", err, "issue", "#9014")
	s.confirmArmDegraded = true
	s.confirmArmRec = rec
	// Pin the window this debt belongs to, so the retry cannot resurrect a
	// record for a window that has since been confirmed or rolled back.
	s.confirmArmGen = s.confirmGen
	s.journalLog(&JournalEntry{
		Action: "confirm_arm_error",
		Detail: fmt.Sprintf("durable write of the pending commit-confirmed record failed; auto-rollback would not survive a crash: %v", err),
	})
	s.ensurePersistRetryLoopLocked()
}

// removeConfirmState deletes the persisted pending commit-confirmed state
// (#4577/#5835). Called whenever a pending confirm is RESOLVED — confirmed
// (plain commit / HA sync / explicit confirm / demotion) or rolled back (timer
// fired). It now RETURNS the DeleteConfirm error (a durable-removal failure)
// instead of only logging it, so a caller that can act on it does — an explicit
// ConfirmCommit surfaces it to the operator; the non-returning resolution paths
// route it through resolveConfirmRemovalLocked to retain retry debt. A nil DB
// (embedder without persistence) is a clean no-op. Caller holds s.mu.
func (s *Store) removeConfirmState() error {
	if s.db == nil {
		return nil
	}
	if err := s.db.DeleteConfirm(); err != nil {
		slog.Warn("failed to remove persisted commit-confirmed state", "err", err, "issue", "#5835")
		return err
	}
	return nil
}

// resolveConfirmRemovalLocked durably removes confirm.json for a RESOLVED
// pending window and, on failure, RETAINS retry debt: it flips
// confirmRemoveDegraded (surfaced via ConfigPersistDegraded → /health) and
// starts the singleton persist-retry loop so the stale record is eventually
// deleted and health stays degraded until it is (#5835). On success it clears
// the flag. It returns the removal error so callers that ALSO propagate it (the
// explicit ConfirmCommit path) can — the non-returning resolution paths (plain
// commit, HA sync, demotion, timeout rollback, boot recovery) ignore the return
// and rely on the retained retry debt to converge. Caller holds s.mu.
func (s *Store) resolveConfirmRemovalLocked(action string) error {
	// #7675: capture WHICH record this removal is for BEFORE deleting it, so a
	// retained debt cannot later delete a DIFFERENT (newer) record. An empty id
	// means the record was already absent or unreadable — the debt is then only
	// the #4864 directory barrier, never a delete of a present file.
	rec := s.readConfirmRecordLocked()
	id := confirmRecordIdentity(rec)
	// #8565: TOMBSTONE BEFORE DELETE. If the delete does not become durable, the
	// record that survives must say it was already RESOLVED — otherwise recovery
	// cannot tell it from a live pending window and re-arms (or, past the
	// deadline, reverts) a config the operator confirmed. Best-effort: a failed
	// tombstone write degrades to exactly the pre-#8565 behaviour.
	s.markConfirmResolvedLocked(rec)
	if err := s.removeConfirmState(); err != nil {
		s.confirmRemoveDebtID = id
		s.noteConfirmRemoveFailureLocked(action, err)
		return err
	}
	s.confirmRemoveDegraded = false
	s.confirmRemoveDebtID = ""
	// #8566: an unreadable record that has now been removed is no longer
	// standing between the operator and a clean state.
	s.confirmRecoveryReadFailed = false
	return nil
}

// confirmRecordIdentity returns a stable identity for a persisted
// commit-confirmed record (#7675). Two records are the SAME arm iff they agree
// on the config they guard, the deadline they expire at, and whether the
// rollback target is the empty bootstrap tree. `writeConfirmState` is the sole
// production `WriteConfirm` caller and every arm / nested re-arm goes through
// it with a freshly computed deadline, so a later arm always yields a different
// identity. Returns "" for a nil record.
func confirmRecordIdentity(rec *confirmRecord) string {
	if rec == nil {
		return ""
	}
	return fmt.Sprintf("%s|%d|%t", rec.GuardedHash, rec.Deadline.UnixNano(), rec.FirstCommit)
}

// readConfirmRecordLocked reads the persisted record, or nil when there is
// none, the DB is absent, or it cannot be read. Caller holds s.mu.
func (s *Store) readConfirmRecordLocked() *confirmRecord {
	if s.db == nil {
		return nil
	}
	rec, err := s.db.ReadConfirm()
	if err != nil {
		return nil
	}
	return rec
}

// markConfirmResolvedLocked writes the #8565 resolution tombstone: the same
// record with Resolved set, persisted durably so a delete that does not land
// leaves behind a record recovery can recognise as already-resolved.
//
// Best-effort by design. A failed tombstone write leaves the unmarked record
// exactly as the pre-#8565 code did, so this can only shrink the window in
// which a resolved record is mistaken for a pending one, never widen it. Caller
// holds s.mu.
func (s *Store) markConfirmResolvedLocked(rec *confirmRecord) {
	if s.db == nil || rec == nil || rec.Resolved {
		return
	}
	tombstone := *rec
	tombstone.Resolved = true
	if err := s.db.WriteConfirm(&tombstone); err != nil {
		slog.Warn("failed to tombstone the resolved commit-confirmed record before removing it; "+
			"a restart before the removal lands may resurrect its rollback",
			"err", err, "issue", "#8565")
	}
}

// confirmRemovalSupersededLocked reports whether the record whose removal is
// owed has already been durably REPLACED by a newer arm (#7675), in which case
// the debt is satisfied by construction and re-driving the delete would destroy
// the NEW window's crash-recovery file.
//
// Absent or unreadable is deliberately NOT superseded: an absent record leaves
// the #4864 directory barrier owed, and an unreadable one cannot be a fresh arm
// (`writeConfirmState` always writes a record `ReadConfirm` accepts), so
// re-driving the delete is correct for both. Caller holds s.mu.
func (s *Store) confirmRemovalSupersededLocked() bool {
	if s.db == nil {
		return false
	}
	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		return false
	}
	return confirmRecordIdentity(rec) != s.confirmRemoveDebtID
}

// noteConfirmRemoveFailureLocked records that a resolved window's confirm.json
// removal failed to become durable and starts the self-healing retry (#5835).
// It sets confirmRemoveDegraded (the "removal not durable" operation state,
// surfaced to /health), journals an ERROR, and ensures the singleton retry loop
// is running so the removal is re-driven with backoff until it lands. Must be
// called with s.mu held.
func (s *Store) noteConfirmRemoveFailureLocked(action string, err error) {
	slog.Error("failed to durably remove the resolved commit-confirmed record; a restart "+
		"before the background retry heals could resurrect a stale rollback",
		"action", action, "err", err, "issue", "#5835")
	s.confirmRemoveDegraded = true
	s.journalLog(&JournalEntry{
		Action: "confirm_remove_error",
		Detail: fmt.Sprintf("%s: durable removal of pending commit-confirmed record failed: %v", action, err),
	})
	s.ensurePersistRetryLoopLocked()
}

// ensurePersistRetryLoopLocked starts the singleton background persist-retry
// goroutine if one is not already running (#1799/#5835). The loop re-drives
// both a degraded active-config write AND a degraded confirm.json removal until
// both are durable. Caller holds s.mu (write lock).
func (s *Store) ensurePersistRetryLoopLocked() {
	if s.persistRetryActive {
		return
	}
	s.persistRetryActive = true
	initial := s.persistRetryInitialBackoff
	if initial <= 0 {
		initial = time.Second
	}
	maxBackoff := s.persistRetryMaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 60 * time.Second
	}
	go s.persistRetryLoop(initial, maxBackoff)
}

// clearConfirmResolutionPendingLocked finalizes a #5473 DEFERRED confirm.json
// removal: it drops the crash-recovery record once the replacement config is
// durable on disk. A commit-confirmed window that was resolved in memory
// (timeout auto-rollback, boot recovery, or an HA config-sync supersede) but
// whose resolving active write FAILED keeps confirm.json (fail-closed) and
// marks the removal pending via confirmResolvePendingPersist. This is called
// from every path that lands a DURABLE active-config write — the persist-retry
// heal and every superseding commit/sync — so the retained record is dropped
// exactly when the replacement it was guarding becomes durable, never before.
// No-op unless a removal was deferred. Caller holds s.mu (write lock).
func (s *Store) clearConfirmResolutionPendingLocked() {
	if !s.confirmResolvePendingPersist {
		return
	}
	s.confirmResolvePendingPersist = false
	// #5835: the replacement config is durable, so remove the retained record.
	// A durable-removal failure here retains retry debt (degraded health +
	// background retry) rather than being swallowed — the loop re-drives it.
	s.resolveConfirmRemovalLocked("confirm_resolution_finalize")
}

// clearPendingConfirmLocked cancels an armed commit-confirmed rollback
// timer and discards its rollback target, treating whatever the caller is
// about to promote (a plain commit, an HA config-sync apply, or the
// operator's explicit confirmation) as the CONFIRMATION of the pending
// confirmed commit. This is Junos semantics: any subsequent explicit
// `commit` confirms a pending `commit confirmed`. It is a no-op when no
// timer is armed and returns true only when a pending timer was cleared.
// Must be called under s.mu.
//
// The confirmGen bump is load-bearing (#1817): time.Timer.Stop() cannot
// un-fire a callback that has already started and is blocked on s.mu.
// Bumping the generation makes that already-fired-but-blocked callback a
// no-op in PromoteRollback (gen mismatch), so it cannot revert the newer
// config the caller just promoted.
//
// A nested `commit confirmed` (CommitConfirmed while one is pending) does
// NOT go through here — it re-arms its own timer and PRESERVES the
// original rollback target — so this only fires on a PLAIN commit / sync /
// explicit confirm, never on a confirmed→confirmed re-arm.
// It returns (cleared, removeErr): cleared is true iff a pending timer was
// cancelled; removeErr is the durable confirm.json-removal failure, if any.
// The removal ALWAYS retains retry debt on failure (degraded health +
// background retry) regardless of caller, so the stale record converges to
// deletion; removeErr is returned in addition so an EXPLICIT ConfirmCommit can
// surface it to the operator (#5835). The non-returning callers (plain commit,
// demotion) ignore removeErr and rely on the retained retry debt.
func (s *Store) clearPendingConfirmLocked() (cleared bool, removeErr error) {
	if !s.cancelPendingConfirmTimerLocked() {
		return false, nil
	}
	// #4577: the pending confirm is now confirmed (plain commit / HA sync /
	// explicit confirm / demotion) — drop the persisted crash-recovery state
	// so a later restart does not resurrect a stale rollback window. A nested
	// confirmed re-arm does NOT pass through here (it re-writes confirm.json
	// with the extended deadline in CommitConfirmed), so this only fires on a
	// genuine confirmation.
	//
	// #5473: the callers that reach here have ALREADY made the confirming
	// config durable (CommitWithDescription/CommitConfirmed persist-before-
	// promote; ConfirmCommit/ConfirmPendingOnDemotion do not replace the active
	// config at all), so removing confirm.json now is the durable transition.
	// The degrade-not-fail sync path does NOT use this helper — it cancels the
	// timer with cancelPendingConfirmTimerLocked and orders confirm.json removal
	// AFTER its (possibly failing) write.
	//
	// #5835: a durable-removal failure is no longer swallowed — it retains retry
	// debt (degraded health + background retry) AND is returned so an explicit
	// ConfirmCommit surfaces it. Before this fix removeConfirmState was void, so
	// a confirmation reported success while confirm.json lingered and a restart
	// resurrected the stale rollback.
	return true, s.resolveConfirmRemovalLocked("confirm_resolve")
}

// cancelPendingConfirmTimerLocked cancels an armed commit-confirmed rollback
// timer and discards its in-memory rollback target WITHOUT touching the
// persisted confirm.json. Returns true iff a timer was armed. This is the
// timer-half of clearPendingConfirmLocked; a caller that resolves the window
// with a DEGRADE-NOT-FAIL active write (SyncApply) uses this so confirm.json
// removal can be ordered AFTER the replacement write is durable (#5473) rather
// than removed up front and lost if that write fails. Caller holds s.mu.
//
// The confirmGen bump is load-bearing (#1817): time.Timer.Stop() cannot un-fire
// a callback that has already started and is blocked on s.mu. Bumping the
// generation makes that already-fired-but-blocked callback a no-op in
// PromoteRollback (gen mismatch).
func (s *Store) cancelPendingConfirmTimerLocked() bool {
	if s.confirmTimer == nil {
		return false
	}
	s.confirmTimer.Stop()
	s.confirmGen++ // invalidate a callback that already fired and is blocked on s.mu
	s.confirmTimer = nil
	s.confirmPrevTree = nil
	s.confirmPrevCfg = nil
	s.confirmPrevFirst = false
	return true
}

// ConfirmCommit cancels the auto-rollback timer, confirming the config.
func (s *Store) ConfirmCommit() error { return s.ConfirmCommitAs("") }

// ConfirmCommitAs is ConfirmCommit scoped to a config-lock holder session
// (#5059): a non-holder session must not confirm (and thereby cancel the
// auto-rollback of) another session's pending commit-confirmed. sessionID == ""
// bypasses ownership (internal/system caller, e.g. the confirm-on-sync path).
func (s *Store) ConfirmCommitAs(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	cleared, removeErr := s.clearPendingConfirmLocked()
	if !cleared {
		return fmt.Errorf("no pending confirmed commit")
	}

	slog.Info("commit confirmed")
	// #5835: the timer is cancelled and the config is confirmed IN MEMORY, but
	// the durable removal of confirm.json failed. Surface it: a restart before
	// the retained background retry heals could resurrect the stale rollback.
	// The retry debt + degraded health were already retained inside
	// clearPendingConfirmLocked; returning the error lets the operator act.
	if removeErr != nil {
		return fmt.Errorf("commit confirmed in memory, but durably clearing the pending "+
			"commit-confirmed record failed (persistence degraded; a restart before the "+
			"background retry heals may roll back): %w", removeErr)
	}
	return nil
}

// ConfirmPendingOnDemotion confirms any pending `commit confirmed` window
// because this node is being DEMOTED from RG0 primary (#4378). It is the
// demotion-event analogue of #3861's confirm-on-plain-commit / confirm-on-sync:
// it cancels the armed rollback timer and bumps confirmGen (via
// clearPendingConfirmLocked) so an already-fired-but-blocked callback no-ops in
// PromoteRollback, and returns true iff a pending window was cleared. Unlike
// ConfirmCommit it does NOT return an error when nothing is pending — demotion
// fires on every clean weight-based failover and the common case is no pending
// commit-confirmed.
//
// CONFIRM (keep the committed config), not roll back: the committing node
// pushed the committed config to the peer via config-sync at commit-confirmed
// time (commitConfirmedAndApply -> applyAndSyncCommitted ->
// pushCommittedConfigToPeer). The peer — now RG0 primary — is therefore
// already running that committed config. Rolling THIS node's store back to the
// pre-confirm tree while the primary keeps the commit would diverge the two
// nodes (the #4378 bug, surfacing at the next failover). Confirming keeps both
// nodes converged on the committed config.
func (s *Store) ConfirmPendingOnDemotion() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleared, _ := s.clearPendingConfirmLocked()
	if !cleared {
		return false
	}

	// #5835: demotion is an event with no operator to return an error to; a
	// durable-removal failure is already retained as retry debt + degraded
	// health inside clearPendingConfirmLocked, so it converges autonomously.
	slog.Info("commit confirmed: confirmed on RG0 demotion (peer holds the synced config)")
	return true
}

// IsConfirmPending returns true if a commit confirmed is awaiting confirmation.
func (s *Store) IsConfirmPending() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.confirmTimer != nil
}

// fireConfirmTimer is the commit-confirmed auto-rollback timer's expiry
// dispatch (#1922 Item 1a). It runs on the timer's own goroutine.
//
// It prefers the daemon-owned rollback transaction (rollbackExecutor) so
// store promotion + dataplane re-apply run atomically under the daemon
// apply semaphore — and so SERVICE-mode (gRPC/REST/remote-cli) timeouts
// re-apply the dataplane at all, which the old interactive-only callback
// never did. The executor is read under s.mu but invoked WITHOUT holding
// s.mu (it acquires applySem then re-enters the store via PromoteRollback;
// holding s.mu across that would invert the applySem->s.mu lock order).
// When no executor is registered (tests / non-daemon embedders) it falls
// back to the self-contained performAutoRollback (store-state only).
func (s *Store) fireConfirmTimer(gen uint64) {
	s.mu.Lock()
	exec := s.rollbackExecutor
	s.mu.Unlock()
	if exec != nil {
		exec(gen)
	} else {
		s.performAutoRollback(gen)
	}
}

// PromoteRollback performs ONLY the store-state half of a commit-confirmed
// timeout rollback, atomically under s.mu, and returns the compiled
// pre-confirmed config so the caller can re-apply it to the dataplane
// (#1922 Item 1a, Path Option B). The store is the single owner of the
// promotion primitive; the daemon's rollback executor holds the apply
// semaphore around this call + its own re-apply so promotion and re-apply
// are one critical section relative to a concurrent commit.
//
// gen must be the confirmGen captured when the calling timer was armed.
// A mismatch means the callback was superseded (nested CommitConfirmed
// re-armed, or ConfirmCommit confirmed) after it fired but before it took
// s.mu; rolling back would revert a NEWER commit to an older tree (Codex
// review on PR #1817). On mismatch — or when there is no pending rollback
// target (confirmPrevTree==nil, e.g. a stale/double timer fire) — this
// returns (nil, false) and mutates nothing.
//
// IMPORTANT: ok=true means "store state was promoted", NOT "prevCfg is
// non-nil". On a FIRST commit confirmed (fresh store) the rollback target
// tree is the empty pre-config tree (confirmPrevTree != nil) but the
// compiled config recorded at arm time is nil (a fresh store has
// active=&ConfigTree{} but compiled=nil). PromoteRollback then promotes
// the store back to the empty tree exactly as the prior performAutoRollback
// did and returns (nil, true). The caller MUST nil-check prevCfg before
// applying it to the dataplane — exactly as the old code's
// `if fn != nil && prevCfg != nil` guard did. Re-applying that
// first-commit-to-bootstrap case to the dataplane (and not persisting an
// empty *committed* tree) is #1922 Item 1b, DEFERRED to PR-2; this PR
// leaves that path's behavior unchanged (store reverts, dataplane is not
// re-applied). The #1817 confirmGen guard and #1799 persist-failure
// semantics are preserved verbatim.
func (s *Store) PromoteRollback(gen uint64) (prevCfg *config.Config, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if gen != s.confirmGen {
		return nil, false
	}
	if s.confirmPrevTree == nil {
		return nil, false
	}

	s.active = s.confirmPrevTree
	s.compiled = s.confirmPrevCfg
	if s.candidate != nil {
		s.candidate = s.active.Clone()
		s.bumpCandidateGenLocked() // #5848: candidate reset on auto-rollback
	}
	s.dirty = false

	s.confirmTimer = nil
	s.confirmPrevTree = nil
	// #1922 Item 1b: first-commit rollback target. On a fresh-store FIRST
	// commit confirmed, confirmPrevCfg is nil here, so prevCfg below is nil
	// and ok is true — the store reverts to the empty tree. The caller
	// (the daemon executor) detects prevCfg==nil and rolls the dataplane
	// back via enterBootstrapMode rather than applying an empty config.
	prevCfg = s.confirmPrevCfg
	s.confirmPrevCfg = nil
	// #6538: the recorded flag, not `prevCfg == nil`. A nil prevCfg ALSO
	// happens when recoverPendingConfirmLocked could not compile the recovered
	// rollback target, and treating that as a first commit persists
	// committed=0 over a real config — which durably re-classifies the next
	// boot into bootstrap.
	firstCommitRollback := s.confirmPrevFirst
	s.confirmPrevFirst = false

	// Persist reverted config to disk. Option B (#1799): the rollback
	// ALWAYS proceeds in memory — reverting the running config is the
	// safety property — but a persist failure here used to leave the
	// UNCONFIRMED candidate on disk, so a reboot would load the config
	// the operator never confirmed. The degraded flag + singleton
	// retry make the failure visible (/health 503, gauge, journal
	// ERROR) and heal the disk in the background.
	//
	// #1922 Item 1b: on a first-commit rollback the reverted tree is the
	// empty bootstrap tree. It MUST be persisted with the never-committed
	// marker (committed=0), NOT as an operator-committed-empty config —
	// otherwise a subsequent restart would classify committed-empty =>
	// normal (Item 2 case 5) and take over interfaces on an empty config.
	// everCommitted is cleared so the in-memory predicate also reads
	// never-committed without a restart.
	var perr error
	if firstCommitRollback {
		// Record the never-committed marker for BOTH the immediate write
		// and the degraded-retry loop, so a failed-then-healed write still
		// persists committed=0 (Codex r1 release-blocker).
		s.persistMarkerCommitted = false
		s.everCommitted = false
		perr = s.writeActiveMarker(s.active, false)
	} else {
		s.persistMarkerCommitted = true
		perr = s.writeActive(s.active)
	}
	// #5473: model confirm.json removal as a DURABLE transition. The record is
	// the crash-recovery intent that re-drives this rollback to the target
	// (confirmPrevTree). It may be removed ONLY once that target is durable on
	// disk — i.e. only when the writeActive above SUCCEEDED.
	if perr != nil {
		// The rollback to the target is NOT durable (disk still holds the
		// pre-rollback config). Removing confirm.json here would delete the only
		// record that would re-drive the rollback on the next boot: a crash
		// before the degraded retry heals would then boot the pre-rollback
		// config with NO recovery record (the #5473 crash-window loss). Instead
		// keep confirm.json and defer its removal until the retry lands the
		// rollback target durably (clearConfirmResolutionPendingLocked).
		s.noteActivePersistFailureLocked("auto_rollback", perr)
		s.confirmResolvePendingPersist = true
	} else {
		// The rollback target is durable — drop the crash-recovery record now.
		// #4577: idempotent on the residual crash window between the successful
		// writeActive above and this remove (a Load recovery re-runs the
		// now-no-op rollback to the already-persisted target).
		s.persistDegraded = false
		s.confirmResolvePendingPersist = false
		// #5835: removal is durable-or-retry — a failed DeleteConfirm retains
		// retry debt + degraded health rather than being swallowed, so a crash
		// before the retry heals cannot leave a stale record that re-reverts.
		s.resolveConfirmRemovalLocked("auto_rollback_remove")
	}

	// Log to journal
	s.journalLog(&JournalEntry{
		Action:     "auto_rollback",
		ConfigHash: journalConfigHash(s.active),
	})

	return prevCfg, true
}

// performAutoRollback is the self-contained fallback rollback used when no
// daemon rollback executor is registered (tests / non-daemon embedders).
// It promotes store state via PromoteRollback (the single promotion
// primitive); it does NOT re-apply the dataplane — a non-daemon embedder
// has no dataplane to re-apply, and the daemon path goes through
// SetRollbackExecutor + executeConfirmedRollback instead (#1922 Item 1a).
// gen must be the confirmGen captured when the calling timer was armed.
func (s *Store) performAutoRollback(gen uint64) {
	if _, ok := s.PromoteRollback(gen); !ok {
		return
	}
	slog.Warn("commit confirmed timed out, configuration rolled back")
}

// Rollback reverts the candidate to a previous configuration.
// n=0 reverts to active; n>0 reverts to the nth previous commit.
func (s *Store) Rollback(n int) error { return s.RollbackAs("", n) }

// RollbackAs is Rollback scoped to a config-lock holder session (#5059).
// sessionID == "" bypasses ownership (internal/system caller).
func (s *Store) RollbackAs(sessionID string, n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// #3893: `rollback N` mutates the candidate; reject it on a read-only
	// secondary. This is the user-session verb, distinct from the internal
	// commit-confirmed timeout revert PromoteRollback (which promotes the
	// active config directly and is intentionally NOT gated).
	if err := s.ensureWritableLocked(); err != nil {
		return err
	}
	// #5059: reject a rollback issued by a session that is not the config-lock
	// holder — it mutates the shared candidate.
	if err := s.ensureHolderLocked(sessionID); err != nil {
		return err
	}
	if s.candidate == nil {
		return fmt.Errorf("not in configuration mode")
	}
	s.touchConfigLockLocked() // #4476: a rollback is activity — refresh the lease

	if n == 0 {
		s.candidate = s.active.Clone()
		s.bumpCandidateGenLocked() // #5848: candidate replaced by rollback 0
		s.dirty = false
		return nil
	}

	entry, err := s.rollbackEntry(n)
	if err != nil {
		return err
	}
	s.candidate = entry.Config.Clone()
	s.bumpCandidateGenLocked() // #5848: candidate replaced by rollback n
	s.dirty = true
	return nil
}

// rollbackEntry resolves rollback slot n (1-based) to its HistoryEntry.
// It returns a clear error both when n is out of range and when the slot
// was tombstoned at load time because its on-disk file could not be read
// or parsed (#4810) — the caller must never silently fall through to a
// DIFFERENT slot's config just because an intermediate slot was skipped.
// See loadRollbackHistory: a tombstone (HistoryEntry with a nil Config)
// occupies the slot's exact position so `rollback N` / `show ... rollback
// N` always resolve slot N, never slot N+1. Callers must hold s.mu (read
// or write — History reads are not independently synchronized).
func (s *Store) rollbackEntry(n int) (*HistoryEntry, error) {
	entry, err := s.history.Get(n - 1)
	if err != nil {
		return nil, err
	}
	if entry.Config == nil {
		return nil, fmt.Errorf("rollback slot %d is unreadable (failed to load at startup); see log for detail", n)
	}
	return entry, nil
}

// ListHistory returns all history entries, most recent first (goroutine-safe).
func (s *Store) ListHistory() []*HistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.history.List()
}

// ListCommitHistory returns recent commit journal entries (most recent
// last). The journal read is bounded by limit (#1896): the tail scan
// stops after limit entries, so cost is O(limit), not O(lifetime
// journal). Semantics preserved from v1: the last `limit` entries of
// ANY action are read first, THEN filtered to commit actions — fewer
// than `limit` commits can come back when other actions interleave.
// limit <= 0 reads everything (persist_failure_test relies on it).
// No Store.mu needed: the journal serializes Log/Tail internally.
func (s *Store) ListCommitHistory(limit int) ([]*JournalEntry, error) {
	entries, err := s.journal.Tail(limit)
	if err != nil {
		return nil, err
	}
	// Filter to commit/rollback actions only
	var commits []*JournalEntry
	for _, e := range entries {
		switch e.Action {
		case "commit", "commit_confirmed", "auto_rollback":
			commits = append(commits, e)
		}
	}
	return commits, nil
}

// LogSystemAction appends a `system_action` audit entry (action name +
// timestamp) to the commit journal and fsyncs it (#4108 F8). It is the
// tamper-evident record for the destructive maintenance verbs — reboot,
// halt, power-off, zeroize — which otherwise leave NO durable trail: the
// slog.Warn line goes to journald, which does not survive a zeroize, so
// post-incident attribution had nothing to read.
//
// The caller MUST invoke this BEFORE running the action, because the append
// is synchronous and fsynced (journal.Log), so the record is durable on disk
// before the box goes down or the config is wiped. For reboot/halt/power-off
// the on-disk record persists across the reboot. For `zeroize` the wipe now
// deliberately REMOVES `.config.journal` (#4576 — a completed factory reset
// must not hand its audit log to the next tenant), so the cross-wipe trail is
// the pre-execution fsync (an interrupted wipe still leaves it) plus remote
// syslog — this supersedes the earlier journal-survives-zeroize belt-and-braces.
//
// Journaling must never block a confirmed power/wipe action, so an append
// failure is warned (journalLog), not returned. Detail carries the action
// name; the local gRPC transport is unauthenticated (127.0.0.1, trusted) so
// no operator identity is available to attribute — action + timestamp is the
// best-effort record.
func (s *Store) LogSystemAction(action string) {
	s.journalLog(&JournalEntry{
		Action: "system_action",
		Detail: action,
	})
}

// CommitDiffSummary returns a human-readable summary of changes between
// the active and candidate configs. Must be called while in config mode.
func (s *Store) CommitDiffSummary() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.candidate == nil {
		return ""
	}

	activeSet := s.active.FormatSet()
	candidateSet := s.candidate.FormatSet()

	activeLines := splitLines(activeSet)
	candidateLines := splitLines(candidateSet)

	activeMap := make(map[string]bool, len(activeLines))
	for _, line := range activeLines {
		activeMap[line] = true
	}
	candidateMap := make(map[string]bool, len(candidateLines))
	for _, line := range candidateLines {
		candidateMap[line] = true
	}

	var added, removed int
	for _, line := range activeLines {
		if !candidateMap[line] {
			removed++
		}
	}
	for _, line := range candidateLines {
		if !activeMap[line] {
			added++
		}
	}

	total := added + removed
	if total == 0 {
		return ""
	}

	return fmt.Sprintf("%d statement(s) changed (%d added, %d removed)", total, added, removed)
}

// rollbackPath returns the file path for rollback slot n (1-based).
func (s *Store) rollbackPath(n int) string {
	return filepath.Join(filepath.Dir(s.filePath), fmt.Sprintf("%s.%d", filepath.Base(s.filePath), n))
}

// saveRollbackFiles writes rollback history entries to numbered files.
// Must be called under write lock.
//
// Durability split (#1894, adjudicated in the plan round): these files
// are the CANONICAL rollback history (loadRollbackHistory reads them at
// boot; the DB rollback slots have no production callers). Slot 1 — the
// immediate `rollback 1` target — is written durably; slots 2..N use
// the atomic writer (never missing, never torn, so loadRollbackHistory's
// break-on-first-missing stays sound; they may lag behind after a power
// cut). One trailing SyncDir then makes the whole shuffle AND the
// stale-slot unlinks durable for the cost of a single dir fsync,
// instead of ~50 file+dir fsync pairs under the store mutex.
func (s *Store) saveRollbackFiles() {
	if s.filePath == "" {
		return
	}

	entries := s.history.List() // most-recent-first
	degraded := false
	for i, entry := range entries {
		if entry.Config == nil {
			// #4810: a tombstoned slot (unreadable/corrupt at load, see
			// loadRollbackHistory) has no config text to persist, and removing
			// the file would let a NEXT boot's os.IsNotExist break() truncate
			// every slot after it. So the file must keep existing.
			//
			// #7176 (C179-056): it must NOT keep its OLD CONTENT. Leaving the
			// file untouched was the defect: history is most-recent-first and
			// shifts by one on every commit, so the bytes still sitting in slot
			// i+1 came from the PREVIOUS generation's slot i+1 — a different
			// entry. Next boot they parse cleanly and the slot presents as
			// healthy, so `rollback i+1` hands the operator a config from
			// another generation with nothing in the load path able to detect
			// it. A wrong answer to a recovery command is worse than a refused
			// one.
			//
			// Writing the marker preserves #4810's file-must-exist requirement
			// while guaranteeing the slot cannot masquerade as healthy config.
			path := s.rollbackPath(i + 1)
			if err := rbWriteFileAtomic(path, []byte(rollbackTombstoneMarker), 0600); err != nil {
				slog.Warn("failed to write rollback tombstone marker", "path", path, "err", err)
				degraded = true
			}
			continue
		}
		path := s.rollbackPath(i + 1)
		data := entry.Config.Format()
		var err error
		// Owner-only 0600 (#4056): the rollback slots (xpf.conf.N) hold the
		// full committed config TEXT, which always includes cleartext secret
		// leaves (IKE PSK, auth keys, SNMP community) — Format() does not
		// redact or encrypt. World-readable 0644 exposed every firewall
		// secret to any local user; 0600 keeps them owner-only. The daemon
		// owns the files, so loadRollbackHistory still reads them back.
		if i == 0 {
			err = rbWriteFileDurable(path, []byte(data), 0600)
		} else {
			err = rbWriteFileAtomic(path, []byte(data), 0600)
		}
		if err != nil {
			slog.Warn("failed to write rollback file", "path", path, "err", err)
			degraded = true
		}
	}
	s.cleanupRollbackFiles(len(entries) + 1)
	if len(entries) > 0 {
		if err := rbSyncDir(filepath.Dir(s.filePath)); err != nil {
			slog.Warn("failed to sync rollback directory", "err", err)
			degraded = true
		}
	}
	// #3441 L1: a rollback-slot write or dir-sync failure used to be
	// warning-only — the commit reported success and health stayed green
	// while xpf.conf.1 silently went missing/stale, so a restart loaded a
	// degraded text rollback history with no signal. Record the loss in a
	// degraded bit (surfaced via RollbackHistoryDegraded) and a journal
	// entry. The commit still succeeds: the canonical active config already
	// persisted durably via the #1799 persist-before-promote path; only the
	// best-effort text rollback copies are affected.
	if degraded && !s.rollbackPersistDegraded {
		s.journalLog(&JournalEntry{
			Action: "rollback_persist_error",
			Detail: "one or more rollback history files failed to persist; rollback history may be stale after restart",
		})
	}
	s.rollbackPersistDegraded = degraded
}

// cleanupRollbackFiles removes stale rollback files starting at startN.
//
// #3441 L3: stop only when a slot is genuinely absent (os.IsNotExist) — the
// contiguous-sequence invariant the loader assumes. A non-not-found remove
// error (e.g. EACCES, EBUSY) used to break the loop and leave higher slots
// behind, which then violated that invariant on the next boot; log and keep
// going so every reachable stale slot is cleared.
func (s *Store) cleanupRollbackFiles(startN int) {
	for i := startN; i <= s.history.MaxSize()+1; i++ {
		path := s.rollbackPath(i)
		if err := rbRemove(path); err != nil {
			if os.IsNotExist(err) {
				break // genuinely absent: contiguous sequence ends here
			}
			slog.Warn("failed to remove stale rollback file, continuing", "path", path, "err", err)
			continue
		}
	}
}

// loadRollbackHistory reads numbered rollback files and populates the history.
// Must be called under write lock.
func (s *Store) loadRollbackHistory() {
	if s.filePath == "" {
		return
	}

	var entries []*HistoryEntry
	for i := 1; i <= s.history.MaxSize(); i++ {
		path := s.rollbackPath(i)
		// #8597 (muse-004 K70): bounded, like every other authoritative read in
		// this package.
		data, err := ReadBoundedFile(path, MaxConfigSize)
		if err != nil {
			// #3441 L2: stop only at a genuinely missing slot (the
			// contiguous-sequence terminator). A transient/permission
			// error on an intermediate slot must NOT drop all the later
			// readable slots — log and continue so the rest of the
			// history still loads.
			if os.IsNotExist(err) {
				break
			}
			// #4810: continuing must NOT bare-skip this slot — appending
			// nothing here collapses every LATER slot's position in
			// `entries` down by one. Since position maps 1:1 onto the
			// user-facing `rollback N` index (History.Get(N-1)), that
			// silently redirected `rollback N` to slot N+1's config.
			// Push a tombstone (nil Config) so the position is preserved;
			// rollbackEntry() rejects a tombstone with a clear error
			// instead of ever returning the wrong generation.
			slog.Warn("error reading rollback file, continuing", "path", path, "err", err)
			entries = append(entries, &HistoryEntry{Timestamp: time.Now()})
			continue
		}
		// #5557: bound a rollback slot the same way every other parse
		// entry point is bounded (LoadOverride/LoadMerge/LoadSet/SyncApply
		// via checkConfigSize). loadRollbackHistory reads straight off disk
		// and would otherwise hand an unbounded payload to the parser at
		// boot — a local-root-planted or corrupt oversized slot could
		// exhaust memory before the daemon even finishes starting. Tombstone
		// the slot (preserving later slots' `rollback N` positions, per the
		// #4810 invariant above) rather than parse it.
		if len(data) > MaxConfigSize {
			slog.Warn("rollback file exceeds max config size, skipping",
				"path", path, "bytes", len(data), "max", MaxConfigSize)
			entries = append(entries, &HistoryEntry{Timestamp: time.Now()})
			continue
		}
		// #7176 (C179-056): an explicit tombstone written by saveRollbackFiles.
		//
		// THIS CHECK IS DIAGNOSTIC, NOT A CORRECTNESS GUARD, and the mutation
		// matrix is how I know: deleting it changes no outcome. The marker ends
		// in a stray "}", so a loader that falls through to the parser gets a
		// parse error and tombstones the slot via the corrupt-file branch below
		// — the same result. What this buys is the LOG: an operator seeing
		// "corrupt rollback file" on every boot cannot tell a recorded tombstone
		// from a slot that needs investigating.
		//
		// The safety property lives entirely in the marker's CONTENT, and it is
		// load-bearing there. A bare "# xpf-rollback-tombstone" comment parses
		// with ZERO errors into an EMPTY config (measured), so without the
		// trailing brace a reader predating this check would present the slot as
		// a healthy empty configuration and `rollback N` would WIPE the config
		// rather than return the wrong generation — the fix making the bug
		// worse. TestTombstoneMarkerFailsToParse_7176 binds that, and it is the
		// cell to keep if this check is ever removed.
		if bytes.HasPrefix(data, []byte(rollbackTombstoneMarkerPrefix)) {
			slog.Info("rollback slot is a recorded tombstone", "path", path)
			entries = append(entries, &HistoryEntry{Timestamp: time.Now()})
			continue
		}
		parser := config.NewParser(string(data))
		tree, errs := parser.Parse()
		if len(errs) > 0 {
			// Log POSITION only (#4690, mirroring the #4099 rescue-path
			// invariant): config.ParseError.Error() embeds ParseError.Message,
			// which the lexer/parser can populate with the OFFENDING TOKEN
			// VALUE (e.g. an unterminated `pre-shared-key "SECRET…`). Forwarding
			// errs[0] / the ParseError text would echo secret file content into
			// the log. Line/Column are ints and cannot hold a token.
			//
			// #4810: same positional-integrity reasoning as the read-error
			// branch above — a corrupt-but-readable slot also tombstones
			// rather than shifting later slots' indices.
			slog.Warn("skipping corrupt rollback file",
				"path", path, "line", errs[0].Line, "column", errs[0].Column)
			entries = append(entries, &HistoryEntry{Timestamp: time.Now()})
			continue
		}
		// Use file modification time as timestamp
		info, _ := os.Stat(path)
		ts := time.Now()
		if info != nil {
			ts = info.ModTime()
		}
		entries = append(entries, &HistoryEntry{
			Config:    tree,
			Timestamp: ts,
		})
	}

	// Push oldest-first so History ordering is correct
	for i := len(entries) - 1; i >= 0; i-- {
		s.history.Push(entries[i])
	}

	if len(entries) > 0 {
		slog.Info("loaded rollback history", "entries", len(entries))
	}
}

// Rollback-slot tombstone marker (#7176 C179-056).
//
// Written into a slot whose history entry is a tombstone, so the file keeps
// existing (the #4810 sequence-contiguity requirement) without keeping the
// PREVIOUS generation's config text, which would re-load as a healthy slot at a
// shifted index.
//
// The two lines do different jobs. The first is a human-readable comment naming
// the file, and is what loadRollbackHistory prefix-matches. The second is a
// stray closing brace that guarantees a PARSE ERROR — which is what makes the
// marker safe on a reader predating the prefix check, since that reader
// tombstones it through the corrupt-file branch. Without the brace the file is a
// comment-only config that parses cleanly into an EMPTY tree, and an old reader
// would offer it as a valid rollback target that wipes the configuration.
const (
	rollbackTombstoneMarkerPrefix = "# xpf-rollback-tombstone"
	rollbackTombstoneMarker       = rollbackTombstoneMarkerPrefix + "\n}\n"
)
