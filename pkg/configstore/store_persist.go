package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// Load builds the configuration from disk.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tree, committed, err := s.db.ReadActiveMeta()
	if err != nil {
		// A read/parse/decrypt/envelope failure on a PRESENT active.json is
		// the fail-closed case (#1917 increment B, D1): an unparseable or
		// too-new DB must NOT be silently overwritten by a blind bootstrap.
		// Tag it with ErrConfigDBUnreadable so the daemon can make it fatal
		// (daemon_run.go), distinct from a compile error (handled leniently
		// below) or an absent DB (handled above as start-fresh).
		return fmt.Errorf("read config: %w: %w", ErrConfigDBUnreadable, err)
	}
	if tree == nil {
		// Absent DB: start fresh. everCommitted stays false (a never-booted
		// store has never committed); the daemon's bootstrapFromFile may
		// import a preseeded xpf.conf, which resolves NOT-bootstrap on its
		// own (case 2). The #1922 step-0 marker only governs the DB-present
		// disambiguation.
		return nil
	}
	// #1922 step-0 marker: record whether the on-disk DB represents a
	// successfully-committed config. A legacy/older-build DB (no envelope
	// field) reads committed=true (migration rule C3), so an upgrade never
	// misclassifies an existing active config into bootstrap.
	s.everCommitted = committed
	// Seed the degraded-retry marker from the on-disk state too (Copilot
	// finding): if Load reads a never-committed DB (committed=0) and a later
	// persist failure triggers the #1799 retry loop BEFORE any commit/sync
	// resets the marker, the retry must re-write committed=0 — not the
	// New() default of true, which would silently heal the never-committed
	// marker into an operator-committed-empty DB and re-enable takeover.
	s.persistMarkerCommitted = committed

	// Rolling-upgrade tolerance (#1373 / #1525): a node may boot
	// with `system dataplane-type ebpf` or `... dpdk` persisted
	// from before the retirement-strict validator landed. Without
	// this rewrite, compileTree below returns
	// ErrEBPFDataplaneRetired / ErrDPDKDataplaneRetired, the daemon
	// gets nil active config, and bootstraps blind. Rewriting the
	// leaf to absent (defaults to userspace) lets the daemon come
	// up so the operator can fix the config from CLI.
	rewriteRetiredDataplaneType(tree, LoadCaller)

	// #1798 migration: a persisted free-text value carrying control
	// characters (e.g. a "lan\nDHCP=ipv4" description committed before
	// the strict commit-time gate landed) must neither fail boot now
	// nor make the operator's next unrelated commit fail mysteriously.
	// Scrub the tree in place with a warning — this tree becomes the
	// active config (and the candidate clones from it), so the next
	// strict commit sees only clean values.
	for _, p := range config.SanitizeTreeControlChars(tree) {
		slog.Warn("sanitized control characters in persisted config value",
			"path", p, "issue", "#1798")
	}

	// Tolerant compile: an already-persisted config must boot through
	// (see compileTreeLenient for the validator downgrades).
	compiled, err := s.compileTreeLenient(tree)
	if err != nil {
		// #1960 fail-closed: the bytes read+parsed fine (this is NOT
		// ErrConfigDBUnreadable) but a PRESENT, previously-committed config
		// no longer compiles. s.everCommitted was already set true above, so
		// the daemon could otherwise see ActiveConfig()==nil + everCommitted
		// and resolve to NORMAL boot — positional claim-all interface naming.
		// Tag the error with ErrConfigCompile so the daemon can detect this
		// edge with errors.Is and refuse takeover (enter the #1922
		// bootstrap/lifeline safe state) instead.
		//
		// s.compiled MUST stay nil — ActiveConfig() returns s.compiled, and
		// nil is precisely the signal that forces bootstrap (computeBootClass).
		// BUT retain the parsed-but-broken tree as s.active and load rollback
		// history, so the recovery the daemon advertises ("fix the config from
		// the CLI/gRPC and commit, or roll back") actually works (Codex #1991
		// r1): EnterConfigure clones s.active into the candidate, so `configure`
		// + `show | compare` surface the broken stanza for the operator to fix,
		// and Rollback(n) / `show | compare rollback n` reach the on-disk
		// history. Without this, s.active stayed the empty New() tree and the
		// history was never loaded — the operator saw an empty config and no
		// rollbacks, with no in-band way to recover. s.active is always non-nil
		// (New seeds an empty tree), so the (active non-nil, compiled nil) shape
		// here is the same one a fresh boot already has — no new invariant.
		s.active = tree
		s.loadRollbackHistory()
		return fmt.Errorf("compile config: %w: %w", ErrConfigCompile, err)
	}

	s.active = tree
	s.compiled = compiled
	s.loadRollbackHistory()
	// #6538: the recovery can leave the store with a nil compiled config (its
	// rollback target failed even the lenient compile). Load MUST NOT report
	// success in that state — see recoverPendingConfirmLocked.
	return s.recoverPendingConfirmLocked()
}

// recoverPendingConfirmLocked restores a commit-confirmed window that was
// still pending when the daemon last stopped (#4577). The in-memory
// time.AfterFunc rollback timer does not survive a process restart, so without
// this an UNCONFIRMED config that the operator armed with `commit confirmed`
// (relying on it to auto-revert) becomes PERMANENT after a crash/reboot inside
// the window — the safety hatch is silently lost and a management-stranding
// config can lock the operator out. Junos persists the pending confirm across
// a reboot and rolls back if it is not confirmed; this gives xpf the same
// property.
//
// Runs at the tail of a SUCCESSFUL Load (active.json read+compiled), under
// s.mu. Two outcomes:
//   - deadline already passed during downtime -> roll back to the persisted
//     prev tree NOW (the operator never confirmed) exactly as the in-memory
//     PromoteRollback would have, including the #1922 Item 1b first-commit
//     never-committed marker, then clear the state.
//   - deadline still in the future -> re-arm the timer for the REMAINING
//     duration so the original auto-rollback still fires; a clean restart
//     inside the window therefore also keeps the hatch.
//
// #6538: it returns an error so Load can FAIL CLOSED when the recovery leaves
// no compiled config. The rollback target here is a previously-committed
// config, and Load repairs the tree it reads from active.json
// (rewriteRetiredDataplaneType, SanitizeTreeControlChars) but never the
// PrevTree carried inside confirm.json — so a target committed on an older
// build can fail even the LENIENT compile. Warning and continuing assigned the
// nil into s.compiled while marking everCommitted, which the daemon resolves
// to a NORMAL boot with NO policy: positional claim-all interface naming on a
// box with no compiled configuration. The returned error is tagged
// ErrConfigCompile so classifyLoadError routes it to the same #1922
// bootstrap/lifeline safe state the #1960 main-path compile failure gets. The
// rollback itself still runs to completion first — reverting the unconfirmed
// config is the safety property, and the operator needs the reverted tree
// reachable to fix it from the CLI.
func (s *Store) recoverPendingConfirmLocked() error {
	if s.db == nil {
		return nil
	}
	rec, err := s.db.ReadConfirm()
	if err != nil {
		// #8566: this used to be a bare WARN + `return nil`, so `Load` reported
		// success and the box came up with the rollback window silently gone —
		// no timer, no debt, and `ConfigPersistDegraded()` false, so /health
		// returned 200. Every OTHER way the store ends a boot unsafe raises
		// degraded health; this one did not, so nothing alerted on it.
		//
		// `Load` still succeeds: refusing to boot on an unreadable TRANSIENT
		// recovery file would turn a corrupt 200-byte file into an outage,
		// which is the #1960 no-brick posture. The state is made VISIBLE
		// instead, and the record is left in place — a decrypt failure can be a
		// transient master-key problem and the window may be readable on a
		// later boot.
		//
		// Deliberately NOT added here: a bounded in-`Load` retry split by error
		// class. That is a startup-latency and taxonomy change with its own
		// design (the #7675 seed's TRANSIENT/PERMANENT split) and belongs in its
		// own review, not folded into making the state legible.
		slog.Error("failed to read persisted commit-confirmed state; the pending auto-rollback "+
			"window is LOST for this process and the unconfirmed config now stands with no "+
			"timer — configuration persistence is degraded until a commit or confirm clears it",
			"err", err, "issue", "#8566")
		s.confirmRecoveryReadFailed = true
		s.journalLog(&JournalEntry{
			Action: "confirm_recovery_read_error",
			Detail: fmt.Sprintf("pending commit-confirmed record unreadable on boot; auto-rollback window lost: %v", err),
		})
		return nil
	}
	if rec == nil {
		return nil
	}
	// #8565: a RESOLUTION TOMBSTONE. The window was confirmed, superseded or
	// rolled back and only the durable deletion was still owed, so there is
	// nothing to re-arm and nothing to revert to — finish the deletion and move
	// on. #5835's staleness check below cannot substitute for this: it fires
	// only when the resolution CHANGED the active config, and a confirmation
	// changes nothing (`ConfirmCommit` / `ConfirmPendingOnDemotion` replace no
	// tree), so the hash still matches and the record would be treated as live.
	// `ConfirmPendingOnDemotion` returns a bool and has no channel to warn
	// anyone on, so the operator's confirmation would be reverted here with no
	// diagnostic anywhere.
	if rec.Resolved {
		slog.Warn("ignoring a RESOLVED pending commit-confirmed record on boot: its window was "+
			"already confirmed or superseded and only the durable removal was owed; not "+
			"resurrecting its rollback", "issue", "#8565")
		s.resolveConfirmRemovalLocked("resolved_tombstone_recovery")
		return nil
	}
	// #5835: a stale record must not resurrect a rollback of an unrelated,
	// already-confirmed generation. GuardedHash binds the record to the
	// unconfirmed config it was armed for. The active config was already loaded
	// into s.active above; if it no longer matches, a later commit / confirm
	// advanced the active config while this record's durable removal had failed
	// — the pending window it describes is long resolved. Ignore it (do NOT
	// roll back or re-arm) and best-effort remove it, retaining retry debt so
	// the stale record still converges to deletion. A legacy record (empty
	// GuardedHash, written before #5835) skips this check and recovers exactly
	// as #4577 so the cross-upgrade auto-rollback hatch is preserved.
	// #8564: the CANONICAL basis, paired with the arm site. Note this end is
	// IDEMPOTENT today and a mutation of it alone escapes the suite: `s.active`
	// here was decoded from disk by `Load` immediately above, so it has already
	// been round-tripped and canonicalizing it again changes nothing. It is
	// written anyway so the two ends name the SAME function — swapping this back
	// to `journalConfigHash` encodes the unwritten assumption "the tree here is
	// always disk-derived", which a future recovery path that seeds `s.active`
	// from memory would silently falsify. The arm site is the one the #8564
	// cells bind; do not "simplify" this one away on the grounds that it is
	// provably a no-op.
	if rec.GuardedHash != "" && rec.GuardedHash != guardedConfigHash(s.active) {
		slog.Warn("ignoring a stale pending commit-confirmed record on boot: it guards a config "+
			"that is no longer active (a later commit/confirm superseded it); not resurrecting its "+
			"rollback", "issue", "#5835")
		s.resolveConfirmRemovalLocked("stale_confirm_recovery")
		return nil
	}
	prevTree := rec.PrevTree
	if prevTree == nil {
		prevTree = &config.ConfigTree{}
	}

	if time.Now().After(rec.Deadline) {
		// Expired during downtime: the operator never confirmed, so the
		// unconfirmed config on disk must NOT stand. Revert to the prev tree
		// with the same persistence semantics as PromoteRollback.
		s.active = prevTree
		var perr error
		// recoverErr is the #6538 fail-closed signal, returned at the end of
		// this branch so the rollback's persistence/journal/record-removal all
		// still run first.
		var recoverErr error
		if rec.FirstCommit {
			// #1922 Item 1b: the rollback target is the empty bootstrap tree;
			// persist committed=0 and clear everCommitted so a later restart
			// re-classifies into bootstrap, not operator-committed-empty.
			s.compiled = nil
			s.persistMarkerCommitted = false
			s.everCommitted = false
			perr = s.writeActiveMarker(prevTree, false)
		} else {
			compiled, cerr := s.compileTreeLenient(prevTree)
			if cerr != nil {
				// #6538: s.compiled is about to become nil while everCommitted
				// stays true — the exact (ActiveConfig()==nil, everCommitted)
				// shape #1960 fails closed on. Record it so Load returns an
				// ErrConfigCompile-tagged error at the end of this branch
				// instead of reporting success; the daemon then enters the
				// #1922 bootstrap/lifeline safe state rather than a NORMAL
				// boot with no policy. The rollback below still completes:
				// reverting the unconfirmed config is the safety property, and
				// the reverted tree must stay reachable so the operator can
				// fix it from the CLI.
				slog.Error("recovered commit-confirmed rollback target failed to compile; "+
					"reverting to it anyway and refusing config-driven takeover — fix the "+
					"configuration from the CLI or roll back",
					"err", cerr, "issue", "#6538")
				recoverErr = fmt.Errorf("compile commit-confirmed rollback target: %w: %w",
					ErrConfigCompile, cerr)
			}
			s.compiled = compiled
			s.persistMarkerCommitted = true
			s.everCommitted = true
			perr = s.writeActive(prevTree)
		}
		// #5473: confirm.json removal is a DURABLE transition. Remove the
		// crash-recovery record ONLY when the boot rollback to prevTree is
		// durable (writeActive above SUCCEEDED). On failure keep it — the
		// degrade-not-fail retry re-drives the rollback, and if the daemon
		// crashes again first, the NEXT boot re-reads confirm.json (deadline
		// still past) and reverts to prevTree again. Removing it here on a
		// failed write would boot the un-reverted config with no record.
		if perr != nil {
			s.noteActivePersistFailureLocked("confirm_recovery_rollback", perr)
			s.confirmResolvePendingPersist = true
		} else {
			s.persistDegraded = false
			s.confirmResolvePendingPersist = false
		}
		if s.candidate != nil {
			s.candidate = s.active.Clone()
			s.bumpCandidateGenLocked() // #5848: candidate reset by confirm-recovery rollback
		}
		if perr == nil {
			// #5835: durable-or-retry removal — a failed DeleteConfirm retains
			// retry debt + degraded health so a crash before the retry heals
			// re-reads the record (deadline still past) and re-reverts, rather
			// than silently swallowing the failure.
			s.resolveConfirmRemovalLocked("confirm_recovery_remove")
		}
		s.journalLog(&JournalEntry{
			Action:     "auto_rollback",
			Detail:     "commit-confirmed window expired during daemon downtime; reverted on boot (#4577)",
			ConfigHash: journalConfigHash(s.active),
		})
		slog.Warn("commit-confirmed window expired while the daemon was down; configuration "+
			"rolled back to the pre-confirm state on boot", "issue", "#4577")
		return recoverErr
	}

	// Still within the window: re-arm the timer for the remaining duration so
	// the original auto-rollback still fires. The active config loaded above
	// stays the unconfirmed tree; only confirmPrevTree/confirmPrevCfg (the
	// rollback target) are restored so a subsequent expiry / plain-commit /
	// sync resolves correctly. confirm.json is left in place until the window
	// is resolved.
	remaining := time.Until(rec.Deadline)
	s.confirmPrevTree = prevTree
	// #6538: first-commit-ness comes from the PERSISTED record, which is the
	// only authority on whether PrevTree is the empty bootstrap tree. It must
	// NOT be re-derived from confirmPrevCfg below, which goes nil on a compile
	// failure too.
	s.confirmPrevFirst = rec.FirstCommit
	if rec.FirstCommit {
		s.confirmPrevCfg = nil
	} else {
		compiled, cerr := s.compileTreeLenient(prevTree)
		if cerr != nil {
			// The window's rollback can still revert store state and the
			// on-disk tree, but there is no compiled config to re-apply, so
			// the daemon will fall back to the bootstrap/lifeline safe state
			// if the timer fires. confirmPrevFirst stays false, so the
			// rollback persists the target as COMMITTED (#6538) rather than
			// writing the never-committed marker over a real config.
			slog.Error("recovered commit-confirmed rollback target failed to compile; the "+
				"pending auto-rollback will revert store state and disk only, and the "+
				"daemon will drop to the bootstrap/lifeline safe state if it fires",
				"err", cerr, "issue", "#6538")
		}
		s.confirmPrevCfg = compiled
	}
	s.confirmGen++
	gen := s.confirmGen
	s.confirmTimer = time.AfterFunc(remaining, func() {
		s.fireConfirmTimer(gen)
	})
	// #9615: this window was armed by an earlier process (possibly an older
	// build), so its target was never pre-flighted here. The daemon checks it.
	s.confirmDeadline = rec.Deadline
	s.confirmRecovered = true
	s.confirmAlarm = ""
	slog.Info("restored pending commit-confirmed window after restart; auto-rollback re-armed",
		"remaining", remaining.String(), "issue", "#4577")
	return nil
}

// Save persists the active configuration to disk.
func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.writeActive(s.active)
}

// writeActive persists tree as the on-disk active configuration.
// Routes through the writeActiveFn test seam when set (#1799);
// otherwise uses the DB's durable temp + fsync + rename + dir-fsync
// write (#1894). Caller must hold s.mu (read or write lock).
func (s *Store) writeActive(tree *config.ConfigTree) error {
	if s.writeActiveFn != nil {
		return s.writeActiveFn(tree)
	}
	return s.db.WriteActive(tree)
}

// writeActiveMarker persists tree as the on-disk active config with an
// explicit #1922 step-0 committed marker. committed=false writes the
// never-committed marker (Item 1b first-commit rollback). Routes through
// the writeActiveMarkerFn test seam when set; otherwise the production
// DB.WriteActiveMarker. Caller must hold s.mu. When only the legacy
// writeActiveFn seam is set (older tests), the marker degrades to that seam
// (the committed bit is not observable through it, which is acceptable for
// those tests — the marker behavior has dedicated coverage via the DB seam).
func (s *Store) writeActiveMarker(tree *config.ConfigTree, committed bool) error {
	if s.writeActiveMarkerFn != nil {
		return s.writeActiveMarkerFn(tree, committed)
	}
	if s.writeActiveFn != nil {
		return s.writeActiveFn(tree)
	}
	return s.db.WriteActiveMarker(tree, committed)
}

// journalLog appends an audit entry; a failure is surfaced as a
// warning only — journaling must never fail a commit/sync/rollback,
// and the persist_error path must not recurse into journaling its own
// failure (#1896).
func (s *Store) journalLog(e *JournalEntry) {
	// #4891 boundary belt: never hand the journal a Detail larger than the
	// commit-description cap. An oversized JSONL line would be discarded by
	// the journal's bounded reverse-tail scanner (maxTailLineBytes), silently
	// dropping a real audit record. The operator commit path already rejects
	// an over-cap description with a clear error; this bounds every OTHER
	// Detail source (sync notes, error text) so the "no journal line poisons
	// the tail scanner" invariant holds structurally regardless of caller.
	if len(e.Detail) > maxCommitDescriptionBytes {
		e.Detail = truncateDetail(e.Detail, maxCommitDescriptionBytes)
	}
	if err := s.journal.Log(e); err != nil {
		slog.Warn("config journal append failed", "action", e.Action, "err", err)
	}
}

// truncateDetail bounds an audit Detail to at most max content bytes, backing
// off to a valid UTF-8 boundary, and appends an explicit marker so a reader
// sees the record was clipped rather than silently losing tail bytes (#4891).
func truncateDetail(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + fmt.Sprintf("…[truncated %d bytes]", len(s)-len(cut))
}

// journalConfigHash returns the sha256 hex of the tree's Format() text
// — the same text saveRollbackFiles writes to rollback slots, so a
// retained rollback file can be correlated to its journal entry with
// `sha256sum` (#1896). Best-effort correlation: slots shift on every
// commit and only history.MaxSize() of them are kept.
func journalConfigHash(tree *config.ConfigTree) string {
	if tree == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(tree.Format()))
	return hex.EncodeToString(sum[:])
}

// guardedConfigHash returns the hash used to bind a pending commit-confirmed
// record to the config it guards (`confirmRecord.GuardedHash`, #5835), over the
// tree's CANONICAL text: the text it has after ONE JSON round-trip (#8564).
//
// The two ends of that binding never saw the same tree. It is computed at ARM
// time over the IN-MEMORY promoted tree and re-computed at BOOT over the tree
// DECODED FROM DISK, so any value the JSON encoding normalizes makes the two
// hashes differ and recovery classifies a LIVE record as stale — dropping it,
// leaving the UNCONFIRMED config standing with no rollback timer, and logging
// that "a later commit/confirm superseded it" when nothing did.
//
// One such value is reachable from ordinary config: `hasControlChars` rejects
// only C0/DEL, so a raw invalid-UTF-8 byte in a free-text leaf commits cleanly,
// and `json.MarshalIndent` (the DB persistence format) coerces it to U+FFFD.
//
// Canonicalizing makes the two bases equal BY CONSTRUCTION rather than by the
// absence of any normalizing value: the round trip is idempotent, so the
// arm-time hash of the in-memory tree already equals the boot-time hash of the
// tree that comes back. For every config the encoding does NOT normalize —
// which is every config that works today — this is byte-identical to
// `journalConfigHash`, so records written by an older build still match and no
// #1917-style versioned basis is needed. The journal's own `ConfigHash` keeps
// the plain basis: it records what was committed, not what will be read back.
func guardedConfigHash(tree *config.ConfigTree) string {
	if tree == nil {
		return ""
	}
	return journalConfigHash(canonicalizeTree(tree))
}

// canonicalizeTree returns tree as it will be after a persist/load round trip:
// marshalled and decoded exactly as `writeTreeMarked`/`readTreeMeta` do. On a
// marshal/decode failure it returns tree unchanged, which degrades to the
// pre-#8564 basis rather than to an empty tree — a wrong-but-stable hash
// stale-drops one record, an empty tree would match every config.
func canonicalizeTree(tree *config.ConfigTree) *config.ConfigTree {
	data, err := json.Marshal(tree)
	if err != nil {
		return tree
	}
	var round config.ConfigTree
	if err := json.Unmarshal(data, &round); err != nil {
		return tree
	}
	return &round
}

// ConfigPersistDegraded reports whether the running active config
// failed to persist to disk on an Option-B path (SyncApply /
// performAutoRollback) and the background retry has not yet succeeded
// (#1799), OR a resolved commit-confirmed window's confirm.json removal is not
// yet durable (#5835), OR boot recovery could not READ confirm.json and the
// pending rollback window was lost (#8566), OR the ARM write that establishes a
// commit-confirmed window did not become durable (#9014). While true, a daemon
// restart would load a STALE config or resurrect a resolved rollback — or, for
// #8566, an UNCONFIRMED config is already standing with no rollback, and for
// #9014 a crash inside the window would leave one standing permanently because
// no record exists to recover; /health returns 503 and
// xpf_daemon_config_persist_degraded reads 1.
func (s *Store) ConfigPersistDegraded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.persistDegraded || s.confirmRemoveDegraded || s.confirmRecoveryReadFailed ||
		s.confirmArmDegraded
}

// ConfirmRecoveryReadFailed reports specifically whether boot recovery could not
// read confirm.json and therefore lost the pending commit-confirmed rollback
// window (#8566). A strict subset of ConfigPersistDegraded, exposed separately
// so a caller can distinguish "the window is gone" from a write-side debt that
// the background retry will heal on its own — this one will not: it clears only
// when a later arm or removal of a confirm record succeeds.
func (s *Store) ConfirmRecoveryReadFailed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.confirmRecoveryReadFailed
}

// ConfirmRemovalDegraded reports specifically whether a RESOLVED
// commit-confirmed window's confirm.json removal is not yet durable (#5835) —
// the stale crash-recovery record still lingers and the background retry has
// not yet deleted it. It is a strict subset of ConfigPersistDegraded, exposed
// separately so a caller (and the tests) can distinguish a confirm-removal
// debt from an active-config persist failure.
func (s *Store) ConfirmRemovalDegraded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.confirmRemoveDegraded
}

// noteActivePersistFailureLocked records a WriteActive failure on an
// Option-B path (#1799): the in-memory apply already happened (HA
// convergence / auto-rollback safety win over disk trouble), so the
// failure must become visible and self-healing instead of fatal.
// Flips the degraded flag, writes a journal ERROR entry, and starts
// the singleton retry goroutine. Must be called with s.mu held
// (write lock).
func (s *Store) noteActivePersistFailureLocked(action string, err error) {
	slog.Error("active config persist failed — running config is not durable; restart would load stale config",
		"action", action, "err", err, "issue", "#1799")
	s.persistDegraded = true
	// The retry loop re-writes s.active with the marker last requested by the
	// failing path. Callers that need the never-committed marker (Item 1b)
	// set s.persistMarkerCommitted=false BEFORE invoking this; all other
	// paths leave it at the default true.
	s.journalLog(&JournalEntry{
		Action: "persist_error",
		Detail: fmt.Sprintf("%s: write active config failed: %v", action, err),
	})
	s.ensurePersistRetryLoopLocked()
}

// persistRetryLoop retries persisting the CURRENT active config with
// doubling backoff until a write succeeds or the degraded flag is
// cleared by a successful write on another path (#1799). Each attempt
// re-reads s.active under s.mu and writes while holding the lock —
// never a stale captured tree — so rapid successive syncs cannot
// persist out-of-order state (the commit paths themselves write under
// s.mu, so lock-held writes are the existing serialization).
//
// Shutdown safety: the Store has no close signal, and none is needed.
// This is a plain goroutine outside any WaitGroup — it sleeps between
// attempts and holds s.mu only for the duration of one atomic
// temp-file write, so it cannot block daemon shutdown; process exit
// simply abandons it.
func (s *Store) persistRetryLoop(backoff, maxBackoff time.Duration) {
	for {
		time.Sleep(backoff)
		s.mu.Lock()
		if !s.persistDegraded && !s.confirmRemoveDegraded && !s.confirmArmDegraded {
			// A successful write on a commit/sync path already persisted the
			// current active config, no stale confirm.json removal is owed, and
			// no armed window is missing its durable record.
			s.persistRefusedTree = nil // #9617: a heal between ticks exits here
			s.persistRetryActive = false
			s.mu.Unlock()
			return
		}

		if s.confirmArmDegraded {
			switch {
			case s.confirmTimer == nil || s.confirmArmGen != s.confirmGen:
				// #9014: THE WINDOW THIS DEBT BELONGS TO IS GONE. It was
				// confirmed, superseded by a newer arm, or rolled back while the
				// write was still owed. Re-driving WriteConfirm here would write
				// a crash-recovery record for a window that no longer exists, so
				// a restart would resurrect a rollback the operator already
				// resolved — the mirror of #7675 on the removal side, where
				// re-driving a delete would have removed a LIVE window's record.
				s.confirmArmDegraded = false
				s.confirmArmRec = nil
				s.journalLog(&JournalEntry{
					Action: "confirm_arm_superseded",
					Detail: "pending commit-confirmed arm-write debt cleared: the window it was owed for was resolved or replaced",
				})
				slog.Info("pending commit-confirmed arm-write debt cleared: the window it was "+
					"owed for is no longer pending", "issue", "#9014")
			case s.confirmArmRec == nil:
				// Nothing to re-drive; do not hold health down on a debt that
				// cannot be paid.
				s.confirmArmDegraded = false
			default:
				if err := s.db.WriteConfirm(s.confirmArmRec); err == nil {
					s.confirmArmDegraded = false
					s.confirmArmRec = nil
					// A readable record exists again, so #8566's "boot lost the
					// window" state is over for the same reason writeConfirmState
					// clears it on a first-try success.
					s.confirmRecoveryReadFailed = false
					s.journalLog(&JournalEntry{
						Action: "confirm_arm_recovered",
						Detail: "commit-confirmed record persisted after an earlier arm-write failure",
					})
					slog.Info("commit-confirmed record persisted after an earlier arm-write "+
						"failure; the auto-rollback would now survive a crash", "issue", "#9014")
				} else {
					slog.Warn("commit-confirmed arm-write retry failed", "err", err,
						"retry_in", backoff*2, "issue", "#9014")
				}
			}
		}

		// #9617: the refused tree is only needed while it is still the active
		// one. Drop the reference as soon as a different tree is installed, so a
		// rejected multi-MiB AST is not kept alive by the skip that exists to
		// avoid re-serializing it. (The bottom exit needs no clear: the loop
		// holds s.mu from the top check to it, so a heal reaching it went
		// through this line first.)
		if s.persistRefusedTree != nil && s.persistRefusedTree != s.active {
			s.persistRefusedTree = nil
		}
		if s.persistDegraded && s.persistRefusedTree != s.active {
			// #1922: re-write with the marker the failing path requested
			// (committed=false only for a first-commit rollback). For every
			// other path persistMarkerCommitted is true, so this matches the
			// pre-#1922 committed=1 write exactly.
			if err := s.writeActiveMarker(s.active, s.persistMarkerCommitted); err == nil {
				s.persistDegraded = false
				// #5473: the active config is now durable. If a commit-confirmed
				// resolution (rollback / boot recovery / sync supersede) deferred
				// its confirm.json removal because the resolving write failed, that
				// replacement target is exactly what just landed durably — drop the
				// crash-recovery record now (via resolveConfirmRemovalLocked, which
				// re-arms retry debt if the delete itself fails). No-op unless a
				// removal was deferred.
				s.clearConfirmResolutionPendingLocked()
				s.journalLog(&JournalEntry{
					Action: "persist_recovered",
					Detail: "active config persisted after earlier write failure",
				})
				slog.Info("active config persisted after earlier write failure", "issue", "#1799")
			} else if errors.Is(err, ErrPersistExceedsReadCeiling) {
				// #9617: a size refusal is deterministic for this tree, so
				// retrying it only re-serializes a >16 MiB config every tick
				// and warns each time. Record the refused tree and stop
				// attempting it; persistence stays degraded until a DIFFERENT
				// active config is written. Every promotion installs a new tree
				// object, so the pointer compare resumes retries on its own.
				s.persistRefusedTree = s.active
				slog.Error("active config cannot be persisted: it serializes past the read ceiling, so no retry can succeed; persistence stays degraded until a smaller config is applied",
					"err", err, "issue", "#9617")
			} else {
				slog.Warn("active config persist retry failed", "err", err, "retry_in", backoff*2)
			}
		}

		if s.confirmRemoveDegraded && s.confirmRemovalSupersededLocked() {
			// #7675: a NEWER `commit confirmed` durably replaced the record this
			// debt was taken for. WriteConfirm is temp+fsync+rename+dir-fsync, so
			// the record we owed a removal for is already gone and the debt is
			// satisfied. Re-driving DeleteConfirm here would delete the LIVE
			// window's crash-recovery file — measured deterministic on master:
			// the in-memory timer stays armed so nothing looks wrong, and a
			// restart before the new deadline then leaves the UNCONFIRMED config
			// standing with no rollback (#4577).
			s.confirmRemoveDegraded = false
			s.confirmRemoveDebtID = ""
			s.journalLog(&JournalEntry{
				Action: "confirm_remove_superseded",
				Detail: "pending commit-confirmed removal debt cleared: a newer armed window durably replaced the record",
			})
			slog.Info("pending commit-confirmed removal debt cleared: a newer armed window "+
				"durably replaced the record it was owed for", "issue", "#7675")
		} else if s.confirmRemoveDegraded {
			// #5835: re-drive the stale confirm.json removal. DeleteConfirm
			// reaches the #4864 dir fsync even when the file is already absent,
			// so an "unlink succeeded, dir-sync owed" state converges here.
			if err := s.removeConfirmState(); err == nil {
				s.confirmRemoveDegraded = false
				s.confirmRemoveDebtID = ""
				s.journalLog(&JournalEntry{
					Action: "confirm_remove_recovered",
					Detail: "stale pending commit-confirmed record removed after earlier failure",
				})
				slog.Info("stale pending commit-confirmed record removed after earlier failure", "issue", "#5835")
			} else {
				slog.Warn("commit-confirmed record removal retry failed", "err", err, "retry_in", backoff*2)
			}
		}

		// #9625: the SAME debt set as the top check. This exit used to omit
		// confirmArmDegraded, so an arm-write retry that failed a second time,
		// with no other debt owed, returned here with the debt still standing:
		// the retry ran exactly once, and health stayed degraded for the rest of
		// the window with nothing left to heal it.
		if !s.persistDegraded && !s.confirmRemoveDegraded && !s.confirmArmDegraded {
			s.persistRetryActive = false
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// SetArchiveConfig configures automatic archival on commit.
//
// #5523 C179-060: it also SEEDS the monotonic archive sequence from the highest
// seq already present on disk, so config-<ts>.<seq>.conf filenames stay
// GLOBALLY monotonic across daemon restarts. archiveSeq is otherwise a fresh
// per-process counter that restarts at 0; because rotateArchives now prunes by
// seq (not lexical/ts order), a restart that reset seq to 0 would let a stale
// high-seq archive from the PRIOR process outrank — and evict — the fresh
// low-seq archives of the NEW process. Seeding to max(existing seq) keeps the
// newest commit's seq strictly highest so retention order is correct across
// restarts. The scan runs whenever the target dir differs from the one last
// successfully seeded (archiveSeedDir) — process start (archiveSeedDir=="") and
// a runtime dir switch both qualify (#6396: a switch to a previously-used dir
// must re-seed from that dir's existing max, else this process's lower counter
// would let the pre-existing archives outrank the new ones). A scan that fails
// to READ the dir does NOT mark the dir seeded — it leaves archiveSeedDir unset
// (#6404 clears it on a genuine error) so the next attempt rescans, rather than
// pinning the counter below the on-disk max (#6396 Codex MINOR 4); and while the
// counter is unconfirmed the readiness gate makes an archiving commit SKIP its
// archive rather than write a below-max seq (see ensureArchiveSeededLocked).
//
// #6404 edge 2: disabling archival (dir=="") INVALIDATES archiveSeedDir, so a
// later re-enable to the SAME dir re-scans it. Without the invalidation
// A→""→A left archiveSeedDir==A and the re-enable skipped the rescan; if the
// on-disk max in A advanced while archival was off (another process/tenant
// wrote there), the counter would stay low and every fresh archive would be
// pruned as stale. The seed retry the commit path performs (#6404 edge 1,
// ensureArchiveSeededLocked) rests on the same invariant: archiveSeedDir names
// a dir this process has actually scanned, never a stale disabled one.
// ArchiveDir returns the archive directory currently configured on this store,
// or "" when archival is disabled.
//
// #7173: zeroize needs the CONFIGURED directory, not the compiled-in default.
// It previously erased DefaultArchiveDir unconditionally, so on a box with a
// custom `system archival archive-dir` it wiped a path that held nothing and
// left the real archive — with its cleartext PSKs — untouched, reporting a
// clean reset.
func (s *Store) ArchiveDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.archiveDir
}

func (s *Store) SetArchiveConfig(dir string, max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.archiveDir = dir
	s.archiveMax = max
	if dir == "" {
		// #6404 edge 2: archival disabled. Clear archiveSeedDir so a later
		// re-enable to a previously-seeded dir re-scans it (the on-disk max may
		// have advanced while archival was off). A disabled store writes no
		// archives, so clearing the marker only forces the rescan the re-enable
		// must do — it never rewinds the monotonic counter itself.
		s.archiveSeedDir = ""
		return
	}
	// Seed the monotonic archive seq from the highest seq already on disk in
	// the target dir (see ensureArchiveSeededLocked for the full rationale).
	s.ensureArchiveSeededLocked()
}

// ensureArchiveSeededLocked seeds the monotonic archive counter (archiveSeq)
// from the highest seq present in the active archive dir, when that dir has not
// yet been SUCCESSFULLY scanned (archiveSeedDir != archiveDir). It returns
// whether the counter is CONFIRMED relative to the active dir — true when
// seeding is moot or succeeded, false only when a genuine scan failure leaves
// the on-disk max UNKNOWN. The caller MUST hold s.mu for WRITING — it may store
// archiveSeedDir.
//
// Switching to a previously-used directory whose existing archives carry HIGHER
// seqs than this process's counter would otherwise let those pre-existing
// archives outrank — and evict — the archives this process is about to write,
// the same across-restart hazard #5523 C179-060 closed but reached via a live
// dir switch (#6396). The seed is monotonic-up only (max of the current counter
// and the on-disk max), so switching to an empty or lower-seq dir never rewinds
// the counter.
//
// Readiness (#6404 Codex MAJOR round 2): the archiving commit path calls this
// BEFORE it captures a seq and SKIPS the archive when it returns false. A commit
// that lands in the window AFTER a failed SetArchiveConfig scan re-attempts the
// reseed here (edge 1); if that rescan ALSO fails the on-disk max is still
// unknown, so writing at the low counter would drop a below-max archive that
// rotateArchives prunes as stale — skipping this commit's archive (it archives
// on the next successful commit) is strictly safer than writing a mis-seq'd one.
//
// Result cases:
//   - dir=="" (archival off) or archiveSeedDir==dir (already confirmed): ready,
//     no scan (the common case is a cheap string compare — no per-commit ReadDir).
//   - dir does not exist yet (first use, os.ErrNotExist): CONFIRMED empty —
//     there are no pre-existing archives to outrank, so seq 0 is correct and the
//     write path's MkdirAll creates the dir. Recorded as seeded, ready.
//   - scan succeeds (including a readable empty dir → seed 0): seeded, ready.
//   - genuine READ error (mount/permission): UNCONFIRMED. archiveSeedDir is
//     CLEARED (#6404 adjacent) so we never retain confidence in a dir we have
//     navigated away from — A→failed-B→A then re-scans A — and a later call
//     retries. Returns false so the commit path skips this archive.
func (s *Store) ensureArchiveSeededLocked() bool {
	dir := s.archiveDir
	if dir == "" || s.archiveSeedDir == dir {
		return true
	}
	res, ok := s.awaitArchiveScanLocked(dir)
	if !ok {
		// #6776: the scan did not answer within archiveScanBudget. The archive
		// filesystem is unresponsive, so the on-disk max is UNKNOWN — the SAME
		// epistemic state a genuine read error leaves, and handled identically:
		// do NOT reseed to 0, clear archiveSeedDir so a later call retries, and
		// return false so the commit path SKIPS this commit's archive rather
		// than writing a below-max seq rotateArchives would prune as stale.
		//
		// This is the deliberate FAIL-OPEN choice for the boot path. Config
		// archival is a DR/compliance convenience; refusing to bring the
		// firewall up because a directory did not answer would convert a
		// degraded-storage event into a total outage. So bring-up proceeds and
		// archival — and only archival — is suspended until a scan lands.
		slog.Warn("archive seq reseed scan did not complete within budget; "+
			"counter unconfirmed, archival suspended until the scan lands",
			"dir", dir, "budget", archiveScanBudget)
		s.archiveSeedDir = ""
		return false
	}
	seed, err := res.seq, res.err
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// First use: the archive dir does not exist yet. This is NOT a scan
			// failure — a nonexistent dir holds no pre-existing archives, so seq
			// 0 is confirmed-correct and the write path's MkdirAll creates it.
			// Treat exactly like a readable empty dir: record as seeded, ready.
			s.archiveSeedDir = dir
			return true
		}
		// #6396 Codex MINOR 4 + #6404: a genuine scan failure (mount/permission)
		// must NOT reseed the counter to 0. The on-disk max is UNKNOWN, so the
		// counter is unconfirmed. Clear archiveSeedDir (#6404 adjacent) so a
		// stale marker for a previously-confirmed dir is not trusted after we
		// navigate to a new dir, and so the next call retries. Return false so
		// the commit path skips this archive rather than writing a below-max seq
		// that rotateArchives would prune as stale.
		slog.Warn("archive seq reseed scan failed; counter unconfirmed, will retry",
			"dir", dir, "err", err)
		s.archiveSeedDir = ""
		return false
	}
	if seed > s.archiveSeq.Load() {
		s.archiveSeq.Store(seed)
	}
	s.archiveSeedDir = dir
	return true
}

// parseArchiveSeq extracts the monotonic sequence number from an archive
// filename of the form config-<ts>.<seq>.conf. The ts itself embeds a dot
// (seconds.nanoseconds), so the seq is the LAST dot-delimited field before the
// .conf suffix. Returns (0, false) for any name that is not a well-formed
// archive filename (a legacy or foreign file) so callers can order it as oldest.
func parseArchiveSeq(name string) (uint64, bool) {
	if !strings.HasPrefix(name, "config-") || !strings.HasSuffix(name, ".conf") {
		return 0, false
	}
	core := strings.TrimSuffix(name, ".conf")
	dot := strings.LastIndexByte(core, '.')
	if dot < 0 {
		return 0, false
	}
	// #6396: a current-format archive is config-<ts>.<seq>.conf where <ts>
	// itself embeds a dot (seconds.nanoseconds), so core has TWO dots and the
	// portion before the seq dot still contains one. A legacy pre-#3441
	// config-<ts>.conf name has only the ts's single dot, whose trailing
	// nanoseconds ("20240101-120000.123456789") would otherwise be mis-read as
	// a huge sequence — corrupting the seq-ordered retention of a MIXED
	// legacy+current archive dir. Require the ts dot to be present so a legacy
	// name is treated as unparseable (oldest, pruned first, lexical-by-ts among
	// its peers), matching a config-<ts>.conf with no subsecond ts (which has
	// no dot in core and already returns false).
	if strings.IndexByte(core[:dot], '.') < 0 {
		return 0, false
	}
	seq, err := strconv.ParseUint(core[dot+1:], 10, 64)
	if err != nil {
		return 0, false
	}
	return seq, true
}

// archiveDirReader reads an archive directory. It is a package-level seam
// (defaulting to os.ReadDir) so a test can drive the reseed scan-failure path
// deterministically (#6396 Codex MINOR 4) — a live os.ReadDir cannot be
// reliably forced to fail from a unit test, least of all when tests run as root.
var archiveDirReader = os.ReadDir

// archiveScanBudget bounds how long the archive-seq reseed scan may hold the
// global store mutex waiting for the archive directory to answer (#6776).
//
// WHY A BUDGET AND NOT A CONTEXT. The scan is os.ReadDir — a readdir(2)
// syscall. A context cannot cancel it: a thread parked in an uninterruptible
// filesystem wait is not reachable from userspace, so "pass a ctx" would add a
// parameter that never fires. The only mechanism that actually bounds the wait
// is to run the syscall on a throwaway goroutine and stop waiting for it. That
// is what awaitArchiveScanLocked does.
//
// WHY 5s. The directory being scanned is the local config archive, which the
// retention policy caps at max-archives entries (default 10) — a readdir of it
// costs microseconds on any healthy storage. 5s is more than three orders of
// magnitude of headroom, so the budget cannot fire on a merely loaded disk; it
// fires only when the filesystem has genuinely stopped answering. It is also
// short relative to daemon bring-up: the boot apply runs before the gRPC/REST/
// CLI listeners start (daemon PHASE 4 precedes PHASE 5), so this is the most
// bring-up can be delayed by an unresponsive archive filesystem — once, not per
// commit (see archiveScanCh).
//
// Overridable for tests only.
var archiveScanBudget = 5 * time.Second

// archiveScanResult is one completed archive-directory scan: the highest
// on-disk sequence number, or the error that made it unknowable.
type archiveScanResult struct {
	seq uint64
	err error
}

// awaitArchiveScanLocked returns the result of an archive-directory scan of
// dir, waiting at most archiveScanBudget for it. ok is false when the budget
// expired with no result — the on-disk max is UNKNOWN, exactly as it is after a
// genuine read error, and callers must treat it that way.
//
// The caller MUST hold s.mu for WRITING: this reads and stores the pending-scan
// fields. It deliberately keeps the lock across the wait (bounded by the budget)
// rather than dropping and re-taking it — see #6403, which established that
// widening this critical section around the archive WRITE is the hazard, while
// the scan+claim belongs inside it: releasing s.mu here would let a concurrent
// SetArchiveConfig switch archiveDir out from under a seed the caller is about
// to store against the old dir.
//
// Two paths:
//
//   - No scan outstanding for dir: launch one on a throwaway goroutine and wait
//     up to the budget. The goroutine gets a buffered channel and the
//     already-sampled directory reader, so it never blocks on the send and never
//     touches Store state or a package var — it cannot race with anything, and
//     abandoning it is safe.
//   - A scan for dir is already outstanding (a previous call abandoned it at the
//     budget): poll it WITHOUT blocking. A caller must not pay a second full
//     budget for a filesystem already known to be unresponsive, so this returns
//     ok=false immediately when the earlier scan still has not landed. When it
//     HAS landed, its result is consumed here — that is the retry the reseed
//     contract promises, arriving on the first call after the filesystem
//     recovers rather than needing a fresh scan.
//
// The pending scan is keyed by dir: a call for a DIFFERENT dir drops the
// reference and launches its own scan (the abandoned goroutine still completes
// into its buffered channel and exits). A scan is therefore leaked at most once
// per distinct directory, never once per commit.
func (s *Store) awaitArchiveScanLocked(dir string) (archiveScanResult, bool) {
	if s.archiveScanCh != nil && s.archiveScanDir == dir {
		select {
		case res := <-s.archiveScanCh:
			s.archiveScanCh = nil
			s.archiveScanDir = ""
			return res, true
		default:
			return archiveScanResult{}, false
		}
	}

	// Sample the reader seam HERE, on the goroutine that holds the lock, and
	// hand it to the scan — see maxArchiveSeqWith.
	read := archiveDirReader
	ch := make(chan archiveScanResult, 1)
	s.archiveScanCh = ch
	s.archiveScanDir = dir
	go func() {
		seq, err := maxArchiveSeq(read, dir)
		ch <- archiveScanResult{seq: seq, err: err}
	}()

	timer := time.NewTimer(archiveScanBudget)
	defer timer.Stop()
	select {
	case res := <-ch:
		s.archiveScanCh = nil
		s.archiveScanDir = ""
		return res, true
	case <-timer.C:
		// Abandon the scan. The goroutine keeps ch (buffered, capacity 1), so it
		// completes and exits on its own whenever the filesystem answers, and the
		// reference retained in s.archiveScanCh lets the next call collect it.
		return archiveScanResult{}, false
	}
}

// maxArchiveSeq returns the highest config-<ts>.<seq>.conf sequence number
// present in dir. It returns a non-nil error when the directory is UNREADABLE,
// distinct from a readable directory that holds no well-formed archive (which
// returns 0, nil). The caller MUST NOT treat a scan error as an empty
// directory: seeding the monotonic counter to 0 on a transient failure would
// pin it below the on-disk max and prune every fresh archive as stale
// (#6396 Codex MINOR 4). Reached from SetArchiveConfig / the archiving commit
// path via awaitArchiveScanLocked, which seeds archiveSeq.
//
// #6776: the directory reader is passed in rather than read from the
// archiveDirReader package var, because this now runs on a throwaway scan
// goroutine. The seam must be sampled ONCE on the goroutine that holds s.mu and
// handed in — a test that restores the seam while an abandoned scan is still
// parked in readdir(2) would otherwise be a data race on the package var.
func maxArchiveSeq(read func(string) ([]os.DirEntry, error), dir string) (uint64, error) {
	entries, err := read(dir)
	if err != nil {
		return 0, err
	}
	var maxSeq uint64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if seq, ok := parseArchiveSeq(e.Name()); ok && seq > maxSeq {
			maxSeq = seq
		}
	}
	return maxSeq, nil
}

// QuiesceArchival fences and drains the async auto-archive writers so a
// factory-reset caller can guarantee the archive directory it is about to erase
// is not recreated by a resumed writer (#5869). Auto-archive launches a
// fire-and-forget writer goroutine per commit (commitWithDescriptionLocked);
// the #5281 terminal reset generation gates the daemon's config writers but NOT
// this configstore-owned goroutine, so a writer that resumes after
// FactoryResetArchiveDir removed /var/lib/xpf/archive would MkdirAll it again
// and drop a config-<ts>.<seq>.conf snapshot of the PRIOR tenant's full config
// text (cleartext IKE PSKs, WireGuard keys, SNMP communities) — zeroize secret
// residue on a re-tenanted device. QuiesceArchival closes that window in two
// steps:
//
//  1. Set the archive fence under s.mu, so no NEW writer is launched by a later
//     commit (the launch guard reads it under the same lock) and an
//     already-launched writer that has not yet written no-ops.
//  2. Wait for every in-flight writer that has already passed the fence check
//     (a mid-write writer executing writeArchive's MkdirAll + atomic write) to
//     finish, so none is still running when the caller erases the archive
//     directory. This JOIN is what defeats the write-after-wipe race the fence
//     alone cannot: a writer already past the fence check would otherwise
//     recreate the archive concurrently with, or after, the wipe.
//
// The Add/Wait ordering is race-free: every archiveWG.Add(1) runs under s.mu
// guarded by !archiveFenced, and this method sets archiveFenced under s.mu
// before Wait, so the WaitGroup counter can never rise from zero concurrently
// with Wait. It is idempotent and a no-op when no writer is outstanding. The
// daemon's factory-reset transaction (daemon.factoryReset) calls it AFTER
// entering the terminal reset generation (which blocks new commits) and BEFORE
// the wipe, so once it returns the archive directory can be erased with no
// writer left to recreate it.
func (s *Store) QuiesceArchival() {
	s.mu.Lock()
	s.archiveFenced.Store(true)
	s.mu.Unlock()
	s.archiveWG.Wait()
}

// ResumeArchival clears the archive fence set by QuiesceArchival (#5869). It is
// called ONLY on the fail-closed recoverable-wipe path: daemon.factoryReset
// exits the terminal reset generation on a wipe error so the box stays up and
// normal config work resumes, and without re-enabling archival a failed zeroize
// would permanently disable config archival on a still-running daemon. On a
// SUCCESSFUL wipe the daemon is stopped, so the fence is deliberately left
// latched and this is never called.
func (s *Store) ResumeArchival() {
	s.archiveFenced.Store(false)
}

// ArchiveConfig saves a timestamped copy of the active config. The active
// text and the timestamp are captured together under the lock so the
// written archive matches the config that was active at the call (#3441 H4),
// then the actual write happens off-lock via writeArchive.
//
// #6185: this SYNCHRONOUS archive path honors the #5869/#6182 archive fence
// exactly like the async auto-archive launch guard. It has zero production
// callers today, but if it is ever wired to an operator command (e.g.
// `request system configuration archive`) an unfenced call could run AFTER a
// factory reset (zeroize) has set the fence and erased the archive directory —
// writeArchive would MkdirAll it back and drop a config-<ts>.<seq>.conf
// snapshot of the PRIOR tenant's full config text (cleartext IKE PSKs,
// WireGuard keys, SNMP communities) on a re-tenanted device, reopening the
// exact residue #5869 closed for the async path. So it (1) no-ops when the
// fence is set and (2) registers itself in archiveWG when it is not, so a
// concurrent QuiesceArchival JOINs an in-flight synchronous write before the
// wipe — the fence alone cannot close the write-after-wipe window.
func (s *Store) ArchiveConfig(archiveDir string, maxArchives int) error {
	// Capture the fence check, the seed scan, the text, timestamp, the monotonic
	// seq AND the writer registration (archiveWG.Add) together under the store
	// WRITE lock. The seq/ts capture matches the commit path (#3441 H4, Codex
	// MAJOR): the previous code called time.Now() AFTER releasing the lock, an
	// ordering race that could mislabel the archive relative to a concurrent
	// commit.
	//
	// #6403: hold the WRITE lock (not RLock) across the seed scan + seq claim,
	// and seed the shared monotonic counter from THIS dir's on-disk max BEFORE
	// claiming a seq, so the archive we write always outranks every pre-existing
	// archive in the same dir. Two coupled hazards this closes:
	//
	//   1. Off-lock reseed overtakes the claimed seq. Under the old RLock the
	//      seq was claimed and the lock released, then the actual write ran
	//      off-lock. A concurrent SetArchiveConfig (write lock) that switched to
	//      a dir with a higher on-disk max reseeds archiveSeq UPWARD; because
	//      the shared counter is process-global, a subsequent writer to THIS dir
	//      would then claim a seq far above ours, and rotateArchives (#5523
	//      seq-ordered retention) prunes our fresh-but-low-seq archive as stale.
	//      Claiming under the write lock makes the seed+claim mutually exclusive
	//      with that reseed — the counter cannot be bumped between our seed and
	//      our claim, and two concurrent ArchiveConfig calls no longer race the
	//      Load→Store→Add seed as they could under a shared RLock.
	//   2. Stale shared counter vs THIS dir. archiveSeq tracks whatever dir
	//      SetArchiveConfig last seeded (possibly a different or empty dir), so
	//      it can sit BELOW the on-disk max of the dir passed here — which is a
	//      PARAMETER, decoupled from s.archiveDir. Writing at that low seq drops
	//      a below-max archive that rotateArchives immediately prunes as stale.
	//      Seeding from archiveDir here — monotonic-up, mirroring
	//      ensureArchiveSeededLocked / #6404 for the commit path — guarantees the
	//      claimed seq outranks the dir's existing contents.
	//
	// The seed scan is a bounded ReadDir under the lock, exactly what the commit
	// path already does via ensureArchiveSeededLocked; only the WRITE stays
	// off-lock (below), so a long archival I/O still never blocks
	// reconcile/QuiesceArchival (#6185) — the lock-widening #6403 warns against
	// is holding s.mu across the WRITE, not this scan+claim.
	//
	// #6185: the fence read and the Add(1) run under s.mu guarded by
	// !archiveFenced, exactly like the async launch guard, so the Add/Wait
	// ordering stays race-free: QuiesceArchival sets archiveFenced under s.mu
	// (write lock) before it Wait()s, and that write lock is mutually exclusive
	// with the lock we hold here — so a concurrent QuiesceArchival either
	// observes this writer in archiveWG and JOINs it (we Added before it took
	// the lock) or sets the fence first and we no-op (we read fenced=true and
	// never Add). The counter can never rise from zero concurrently with Wait.
	s.mu.Lock()
	if s.archiveFenced.Load() {
		// A factory reset is erasing the archive directory; do not recreate it.
		s.mu.Unlock()
		return nil
	}
	// #6403: seed the shared counter from THIS dir before claiming the seq.
	// #6776: bounded by archiveScanBudget — this is the "bounded ReadDir under
	// the lock" the comment above promises, which before #6776 it was not. A
	// budget expiry is reported to this SYNCHRONOUS caller as an error, the same
	// as a genuine read error below: both leave the on-disk max unknown, so the
	// caller must learn it could not safely archive.
	scan, ok := s.awaitArchiveScanLocked(archiveDir)
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("archive seq reseed scan of %s: did not complete within %s",
			archiveDir, archiveScanBudget)
	}
	if seed, err := scan.seq, scan.err; err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			// A genuine scan error (mount/permission) leaves the on-disk max
			// UNKNOWN, so a claimed seq cannot be guaranteed to outrank the
			// dir's contents; writing anyway could drop a below-max archive that
			// rotateArchives prunes as stale. Fail the SYNCHRONOUS call so the
			// caller learns it could not safely archive, and register NO writer
			// in archiveWG (none runs). A nonexistent dir is NOT an error — first
			// use holds no pre-existing archives, so seq 0 is correct and
			// writeArchive's MkdirAll creates the dir.
			s.mu.Unlock()
			return fmt.Errorf("archive seq reseed scan of %s: %w", archiveDir, err)
		}
	} else if seed > s.archiveSeq.Load() {
		s.archiveSeq.Store(seed)
	}
	data := s.active.Format()
	ts := time.Now()
	seq := s.archiveSeq.Add(1)
	s.archiveWG.Add(1)
	s.mu.Unlock()
	// The write happens off-lock (writeArchive never touches s.mu, so a
	// concurrent QuiesceArchival Wait()ing on archiveWG cannot deadlock on the
	// store lock), and Done fires only after it completes so the JOIN covers
	// the whole MkdirAll + atomic write.
	defer s.archiveWG.Done()
	// #6185: the same test-only seam the async writer uses, letting a test hold
	// this synchronous writer MID-FLIGHT (past the fence check) to prove
	// QuiesceArchival JOINS it before a wipe. Production is a no-op.
	archiveWriteBarrier()
	return writeArchive(archiveDir, maxArchives, data, ts, seq)
}

// writeArchive writes the captured config text to a uniquely-named archive
// file and rotates old archives. data, ts and seq are immutable values
// captured by the caller under the store lock; writeArchive never reads
// shared store state, so it is safe to call from the async auto-archive
// goroutine.
//
// #3441 H4: the filename is config-<ts>.<seq>.conf — a
// nanosecond-resolution timestamp PLUS a monotonic per-process sequence
// number (Codex MAJOR fix). The timestamp alone is not a unique key: two
// successive commits (serialized by the store mutex, so never concurrent)
// can still format the SAME wall-clock nanosecond under a coarse clock or
// an NTP step-back, and the later atomic write would overwrite the earlier
// archive. The seq always advances, so the filename is unique even on an
// identical timestamp. The ts is kept first so a human `ls` reads
// chronologically; retention order does NOT rely on that lexical order —
// rotateArchives prunes by the parsed seq (#5523 C179-060), which is robust
// to a backward wall-clock step that a ts-lexical sort would mis-order.
func writeArchive(archiveDir string, maxArchives int, data string, ts time.Time, seq uint64) error {
	// Owner-only 0700 (#4056): the archive directory holds only timestamped
	// copies of the full config text (each with cleartext secrets), so it
	// must not be world-traversable. MkdirAll does not chmod an existing
	// dir, so an upgrade keeps its old mode; the archive FILES are 0600
	// regardless, which is the load-bearing protection.
	if err := os.MkdirAll(archiveDir, 0700); err != nil {
		return fmt.Errorf("create archive dir: %w", err)
	}

	filename := fmt.Sprintf("config-%s.%020d.conf", ts.Format("20060102-150405.000000000"), seq)
	path := filepath.Join(archiveDir, filename)
	// AtomicGeneratedConfig (#1894): archives are best-effort history
	// copies — atomic so a crash never leaves a torn archive, but not
	// worth an fsync.
	//
	// Owner-only 0600 (#4056): an archive is the full committed config TEXT
	// with cleartext secret leaves (IKE PSK, auth keys); 0644 leaked them to
	// any local user.
	if err := rbWriteFileAtomic(path, []byte(data), 0600); err != nil {
		return fmt.Errorf("write archive: %w", err)
	}

	slog.Info("config archived", "path", path)

	// Rotate old archives
	if maxArchives > 0 {
		rotateArchives(archiveDir, maxArchives)
	}
	return nil
}

// RollbackHistoryDegraded reports whether the most recent commit failed to
// durably persist its text rollback history files (#3441 L1). The commit
// itself still succeeded — the canonical active config persisted via the
// #1799 path — but loadRollbackHistory would read a stale/lossy history
// after a restart. Surfaced so callers (status/health) can report the loss
// instead of it being warning-only.
func (s *Store) RollbackHistoryDegraded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rollbackPersistDegraded
}

// rotateArchives keeps only the most recent maxArchives files.
func rotateArchives(dir string, maxArchives int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var archives []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "config-") && strings.HasSuffix(e.Name(), ".conf") {
			archives = append(archives, e.Name())
		}
	}

	if len(archives) <= maxArchives {
		return
	}

	// Sort by the monotonic per-filename SEQ (#5523 C179-060), NOT lexically by
	// filename. The name is config-<ts>.<seq>.conf with the ts FIRST, so a
	// lexical sort is ts-dominated: a backward wall-clock step (an NTP
	// correction) makes the NEWEST commit format an EARLIER ts and sort first,
	// so the ts-lexical prune would evict that newest archive as if it were the
	// oldest. The seq always advances in commit order — and SetArchiveConfig
	// seeds it across restarts, so it is globally monotonic — hence seq order is
	// the true retention order. A filename with no parseable seq (legacy or
	// foreign) sorts as oldest (pruned first), with a lexical tiebreak among
	// such files and among equal seqs.
	sort.Slice(archives, func(i, j int) bool {
		si, oki := parseArchiveSeq(archives[i])
		sj, okj := parseArchiveSeq(archives[j])
		if oki != okj {
			// A parseable seq always outranks an unparseable name, so the
			// unparseable (legacy/foreign) one sorts first as oldest.
			return okj
		}
		if oki && okj && si != sj {
			return si < sj
		}
		return archives[i] < archives[j]
	})

	// Remove oldest.
	for i := 0; i < len(archives)-maxArchives; i++ {
		path := filepath.Join(dir, archives[i])
		if err := archiveRemoveErr(path); err != nil {
			slog.Warn("failed to remove old archive", "path", path, "err", err)
		}
	}
}

// archiveRemoveErr removes a single rotated archive file and returns the error
// that warrants a warning, or nil when the file was removed or was already
// gone.
//
// ENOENT-tolerant (#4689, mirroring the #3441 L3 cleanupRollbackFiles
// pattern): rotateArchives is spawned per commit and reads the archive
// directory without a per-store archive lock, so two rapid back-to-back
// commits can each pick the same oldest archive and race to remove it. The
// loser's os.Remove then fails with ENOENT — a benign already-gone, not a real
// cleanup failure — so it is suppressed. Any other error (e.g. EACCES) is
// still returned so the caller logs it.
func archiveRemoveErr(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// rescuePath returns the path for the rescue configuration file. The base name
// is RescueConfigBase (KEEP IN SYNC): the factory-reset wipe's ownership-scoped
// top-level match (#5768) deletes exactly this name.
func (s *Store) rescuePath() string {
	return filepath.Join(filepath.Dir(s.filePath), RescueConfigBase)
}

// SaveRescueConfig saves the active config as rescue configuration.
func (s *Store) SaveRescueConfig() error {
	s.mu.RLock()
	data := s.active.Format()
	s.mu.RUnlock()

	path := s.rescuePath()
	// DurableState (#1894): the rescue config is the operator's
	// explicitly-requested safety net — it must survive power loss.
	//
	// Owner-only 0600 (#4056): rescue.conf is the full active config TEXT
	// with cleartext secret leaves (IKE PSK, auth keys, SNMP community);
	// 0644 exposed them to any local user. The daemon owns the file, so
	// LoadRescueConfig still reads it back.
	if err := fsatomic.WriteFileDurable(path, []byte(data), 0600); err != nil {
		return fmt.Errorf("save rescue config: %w", err)
	}
	slog.Info("rescue configuration saved", "path", path)
	return nil
}

// DeleteRescueConfig removes the rescue configuration.
//
// The removal is a DURABLE transition (#5197 A4-b1-F10). SaveRescueConfig
// persists rescue.conf through fsatomic.WriteFileDurable (temp + fsync +
// rename + parent-dir fsync), so the delete must match that dir-sync
// discipline — mirroring DB.DeleteConfirm (#4864). A bare os.Remove is not
// durable: after a successful unlink the directory-entry removal lives only in
// the page cache, so a power loss in that window can replay the deleted
// rescue.conf on reboot. rescue.conf is the full active config TEXT with
// cleartext secret leaves (IKE PSK, SNMP community, auth-keys, #4056), so a
// resurrected copy re-exposes secrets the operator explicitly deleted. fsync
// the parent directory after the unlink so the removal survives power loss.
// The unlink and dir fsync route through the package durability seams
// (rbRemove/rbSyncDir) so a dropped dir sync fails a test RED.
func (s *Store) DeleteRescueConfig() error {
	path := s.rescuePath()
	if err := rbRemove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no rescue configuration exists")
		}
		return fmt.Errorf("delete rescue config: %w", err)
	}
	if err := rbSyncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync dir after delete rescue config: %w", err)
	}
	slog.Info("rescue configuration deleted", "path", path)
	return nil
}

// LoadRescueConfig returns the rescue configuration text, or "" if none.
func (s *Store) LoadRescueConfig() (string, error) {
	path := s.rescuePath()
	// #8597 (muse-004 K70): the rescue config is a configuration TEXT and gets
	// the same ceiling every other configuration ingress gets. Not named by the
	// finding, which listed two sites; a census of os.ReadFile in this package
	// found six.
	data, err := ReadBoundedFile(path, MaxConfigSize)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read rescue config: %w", err)
	}
	return string(data), nil
}

// LoadRescueConfigRedacted returns the rescue configuration text with secret
// leaves masked by config.SecretDataPlaceholder, for the on-box CLI display
// path (#4099). rescue.conf is the full active config TEXT with cleartext
// secret leaves (#4056), so `show system configuration rescue` — a PermView
// command — would otherwise leak IKE PSKs, SNMP communities and auth-keys to a
// read-only / config-viewer login class exactly as the raw-AST `show
// configuration` renderers did before they were routed through the #4051
// RedactedClone path. This reparses the saved text into an AST, redacts a
// clone, and re-renders it as hierarchical text. It fails CLOSED: an empty
// file returns "" (no rescue config), and a parse failure returns an error
// rather than falling back to the cleartext bytes, so a malformed rescue file
// can never leak a secret.
//
// The parse-failure error is deliberately GENERIC: config.ParseError.Error()
// embeds ParseError.Message, which the lexer/parser can populate with the
// OFFENDING TOKEN VALUE (e.g. an unterminated `pre-shared-key "SECRET…`). If
// that token were echoed back to the VIEW-only CLI caller it would defeat the
// whole "never leak a secret" guarantee, so the returned error carries only
// the position (Line/Column are ints and cannot hold a token) — never the
// ParseError itself, its .Message, or any token text (#4099 Copilot follow-up).
func (s *Store) LoadRescueConfigRedacted() (string, error) {
	text, err := s.LoadRescueConfig()
	if err != nil {
		return "", err
	}
	if text == "" {
		return "", nil
	}
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		return "", fmt.Errorf("rescue configuration is malformed and cannot be "+
			"safely displayed (parse failed at line %d, column %d)",
			perrs[0].Line, perrs[0].Column)
	}
	return tree.RedactedClone().Format(), nil
}
