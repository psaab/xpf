package configstore

import (
	"errors"
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// ErrCandidateGenerationConflict is returned by the generation-bound commit
// entry points (CommitWithDescriptionGen / CommitConfirmedGen) when the
// candidate configuration changed between the caller's snapshot+pre-flight and
// the promotion attempt (#5848). It is a sentinel so callers can errors.Is it
// and RETRY the whole snapshot→pre-flight→commit against the new generation
// instead of promoting a candidate the external pre-flight never examined.
var ErrCandidateGenerationConflict = errors.New(
	"candidate configuration changed during commit preparation (generation conflict); re-validate and retry")

// bumpCandidateGenLocked advances the candidate generation token. It MUST be
// called under s.mu.Lock at EVERY site that changes the candidate tree's
// identity or content: the public candidate MUTATORS (set/delete/deactivate/
// activate/copy/rename/insert/annotate/load-override/load-merge/load-set,
// rollback), the config-mode transitions (enter/exit/reclaim/force-exit), the
// peer-sync + confirm-recovery + authoritative-load resets, and the post-commit
// candidate reset. Missing a site would let a candidate change slip past the
// generation guard.
//
// Test coverage is layered, not a single exhaustive table:
//   - TestCandidateGenerationBumps drives every PUBLIC candidate mutator and
//     asserts each advances the token;
//   - TestCandidateGenerationBumpsOnEnterExit covers the config-mode
//     transitions, and the commit/commit-confirmed/rollback tests exercise the
//     post-commit and rollback reset bumps;
//   - the remaining internal reset sites (peer-sync, confirm-recovery,
//     reclaim/force-exit) are guarded by the structural invariant that every
//     `s.candidate = …` reassignment is immediately followed by a bump —
//     verified by code audit — plus the generation-conflict tests that would
//     fail if a reset silently kept a stale token.
func (s *Store) bumpCandidateGenLocked() {
	s.candidateGen++
}

// activeSnapshot is one immutable publication of the active generation +
// compiled config (#9905). Readers load it with a single atomic read and
// therefore observe exactly one publication — never a new token with an old
// pointer or vice versa — which a separately-loaded generation + RLock-read
// pointer cannot guarantee (the pair can straddle a commit).
type activeSnapshot struct {
	gen uint64
	cfg *config.Config
}

// publishActiveLocked publishes the current active generation + compiled
// config. It MUST be called under s.mu.Lock immediately after EVERY
// `s.compiled = …` swap (commit, commit-confirmed, auto-rollback, peer sync,
// load, boot recovery): the structural invariant is that no compiled swap
// lacks a publication, verified by grepping `s\.compiled\s*=` against
// publish call sites. Missing a site would let a cached per-commit
// derivation (daemon zone-id map, #9905) go permanently stale. The
// swap-then-publish order is load-bearing: the snapshot captures the
// just-swapped pointer with a fresh generation, so no publication ever
// pairs an old pointer with a newer generation.
func (s *Store) publishActiveLocked() {
	s.activeSnap.Store(&activeSnapshot{gen: s.activeGen.Add(1), cfg: s.compiled})
}

// CandidateGeneration returns the current candidate generation token. Used by
// the daemon's commit transaction (paired with CompileCandidateGen) and by
// tests asserting that mutating ops advance the token.
func (s *Store) CandidateGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.candidateGen
}

// ActiveSnapshot returns the published active generation + compiled config
// (#9905): (0, nil) on a fresh store, advanced by every compiled-active
// swap. Lock-free (one atomic load of an immutable pair) — the warm-path
// probe that lets a caller reuse a cached per-commit derivation with zero
// store locks. An unchanged generation means the cached derivation is
// current; any change means rebuild from the returned config (no ActiveConfig
// call needed — the snapshot already carries the exact pointer published at
// that generation). A nil config means "no compiled config", matching
// ActiveConfig-nil semantics (bootstrap reset, failed recovery compile).
func (s *Store) ActiveSnapshot() (uint64, *config.Config) {
	if snap := s.activeSnap.Load(); snap != nil {
		return snap.gen, snap.cfg
	}
	return 0, nil
}

// CompileCandidateGen atomically compiles the current candidate AND reads the
// candidate generation token under a SINGLE read lock, so the returned compiled
// config and generation are a consistent pair describing the same candidate
// state (#5848). The daemon runs its external #1956 device-map hardware
// pre-flight on the returned compiled snapshot OUTSIDE the store lock, then
// commits with the returned generation via CommitWithDescriptionGen /
// CommitConfirmedGen so a concurrent candidate mutation between snapshot and
// promote is a CONFLICT, not a silent substitution.
//
// The generation is returned even when the candidate is absent or fails
// commit-check: the daemon still gen-binds the subsequent commit so that a
// candidate which a concurrent edit turns FROM non-compiling INTO a valid
// (e.g. management-stranding) config cannot be promoted without a fresh
// pre-flight. When compilation fails the returned *config.Config is nil and the
// caller skips the hardware pre-flight (there is nothing to examine); the
// generation-bound commit then recompiles under the lock and surfaces the SAME
// compile/mode error when the candidate is unchanged.
func (s *Store) CompileCandidateGen() (*config.Config, uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	gen := s.candidateGen
	if s.candidate == nil {
		return nil, gen, fmt.Errorf("not in configuration mode")
	}
	compiled, err := s.compileTree(s.candidate)
	if err != nil {
		return nil, gen, err
	}
	return compiled, gen, nil
}
