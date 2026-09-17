// Package upgrade implements the xpf in-place upgrade cut-over mechanism
// (#1917 increment B, plan §6.1). It owns the crash-safe, idempotent
// state machine that copies the dpkg-staged binary set into a non-dpkg
// versioned runtime directory, runs the kernel verify-dataplane gate
// against the copied binary, and on PASS performs the STOP -> FLIP ->
// START cut-over with binary+DB-atomic rollback.
//
// The standalone single-node flow lives here; the HA rolling driver
// (pkg/upgrade/rolling.go) sequences a controlled per-node drain around
// this single-node flow so a cluster stays forwarding through an upgrade.
//
// Design invariants (plan §8):
//   - The ONLY live-state mutations are STOP and FLIP-then-START.
//     PREFLIGHT / COPY / VERIFY are pure and abortable: a failure there
//     leaves the running daemon and its config untouched.
//   - Every transition is journaled (temp+fsync+rename) so a crash is
//     recoverable and idempotent; re-running resumes from the journal.
//   - STOP-before-FLIP structurally closes the respawn-mismatch race (a
//     live old xpfd would otherwise re-resolve the flipped helper).
//   - The xpfd unit ExecStart is templated to the CONCRETE versioned
//     path so even a transient respawn resolves the matching-version
//     helper (systemd does not symlink-resolve argv[0]).
//   - Rollback is binary+DB atomic: restore the pre-upgrade config-DB
//     snapshot BEFORE re-flipping the binary, so the old daemon never
//     boots against a too-new (envelope) DB and fatal-rejects it.
package upgrade

// State is a phase of the cut-over state machine. Each value is the
// COMPLETED milestone — the journal records the last phase that finished,
// so a crash resumes by re-running the next phase. The order is total.
type State string

const (
	// StateInit is the implicit pre-start phase (no journal yet).
	StateInit State = ""

	// StateStaged: the staged version has been identified; nothing copied.
	StateStaged State = "STAGED"

	// StatePreflight: disk space checked (incl. rollback DB snapshot
	// size), GC of eligible old versions done if needed, and the
	// pre-upgrade config-DB snapshot has been taken (for rollback). No
	// live mutation yet.
	StatePreflight State = "PREFLIGHT"

	// StateCopied: staged/ has been copied to a .partial dir, fsynced,
	// checksummed, and atomically renamed to versions/<ver>/.
	StateCopied State = "COPIED"

	// StateVerified: versions/<ver>/xpfd --verify-dataplane passed against
	// the running kernel using throwaway socket/state paths.
	StateVerified State = "VERIFIED"

	// StateStopped: the old daemon has been stopped (systemctl stop). On
	// the HA path this node was already drained to the peer first.
	StateStopped State = "STOPPED"

	// StateFlipped: versions/current -> <ver> repointed, /usr/local/sbin
	// operator-tool links repointed, and the xpfd unit ExecStart templated
	// to the concrete <ver> path + daemon-reload done.
	StateFlipped State = "FLIPPED"

	// StateStarted: the new daemon started and reported healthy within the
	// deadline. (Auto-rollback, standalone only, fires if it does not.)
	StateStarted State = "STARTED"

	// StateCommitted: GC of versions beyond N=3 done. Terminal success.
	StateCommitted State = "COMMITTED"

	// StateRollingBack marks an in-progress auto-rollback (standalone). A
	// crash here resumes the rollback (re-flip to PreviousVersion + DB
	// restore), NOT the failed forward cut. On terminal rollback success
	// the journal is CLEARED. order() returns the sentinel -1 for it so
	// atLeast() never treats it as a forward milestone.
	StateRollingBack State = "ROLLINGBACK"
)

// order ranks states for resume comparisons.
func (s State) order() int {
	switch s {
	case StateInit:
		return 0
	case StateStaged:
		return 1
	case StatePreflight:
		return 2
	case StateCopied:
		return 3
	case StateVerified:
		return 4
	case StateStopped:
		return 5
	case StateFlipped:
		return 6
	case StateStarted:
		return 7
	case StateCommitted:
		return 8
	default:
		return -1
	}
}

// atLeast reports whether s has reached (completed) target.
func (s State) atLeast(target State) bool {
	return s.order() >= target.order()
}

// Journal is the crash-safe persisted state of an in-progress cut-over.
// It is written via temp+fsync+rename on every transition so a crash
// leaves a consistent record that a re-run resumes from. The journaled
// TargetVersion is authoritative: the FLIP substeps (current symlink,
// sbin links, unit template) are all DERIVED from it, so a crash between
// substeps re-runs idempotently to the same target.
type Journal struct {
	// TargetVersion is the version being cut to (the staged version).
	TargetVersion string `json:"target_version"`

	// PreviousVersion is the version that was live before this cut began
	// (the rollback target). Empty on the very first cut (the live path
	// still points at staged/).
	PreviousVersion string `json:"previous_version"`

	// State is the last COMPLETED phase.
	State State `json:"state"`

	// DBSnapshotPath is the absolute path to the pre-upgrade config-DB
	// snapshot taken in PREFLIGHT (for binary+DB-atomic rollback).
	DBSnapshotPath string `json:"db_snapshot_path,omitempty"`
	// RollbackDBRestored records the operator rollback's completed DB swap.
	// It closes the crash window where the snapshot is installed and .old
	// retained but the process dies before the binary flip: a retry must not
	// rotate the already-restored live DB into .old and destroy the original
	// failed-runtime copy. Forward-cut journals leave this false.
	RollbackDBRestored bool `json:"rollback_db_restored,omitempty"`
	// OperatorRollback distinguishes the CLI rollback journal from the legacy
	// automatic forward-cut failure journal. Runner.Run uses it to resume the
	// retained-.old DB path rather than the cleanup-oriented auto path.
	OperatorRollback bool `json:"operator_rollback,omitempty"`

	// AdvancedStateFloor records whether the new version raises the
	// config-DB state-format floor (envelope min-reader). When true,
	// auto-rollback MUST restore the DB snapshot before booting the old
	// binary (else the old daemon fatal-rejects the new envelope).
	AdvancedStateFloor bool `json:"advanced_state_floor"`

	// StartedAtUnixNano is when this cut-over began (diagnostics only).
	StartedAtUnixNano int64 `json:"started_at_unix_nano,omitempty"`

	// FirstCutSanctioned records that this cut was an explicitly sanctioned
	// no-rollback first cut (Options.AllowNoRollbackFirstCut) at INIT, when
	// PreviousVersion was empty (#1964 mechanism C). It is persisted so a
	// crash-resume PAST the STOP step — where the refuse-before-STOP guard no
	// longer re-runs — still treats the empty-previous cut as sanctioned
	// (recoverFromFlipFailure restarts the first-install binary), rather than
	// silently completing a cut whose sanction was never recorded. Without
	// this, a re-run without the flag would proceed past a STOPPED empty-prev
	// journal on the original run's sanction alone, which it could not prove.
	FirstCutSanctioned bool `json:"first_cut_sanctioned,omitempty"`

	// SourceGeneration is the staged-gen/<genid> the cut copies FROM (#1981
	// Option B). It is resolved ONCE at INIT (from staged-gen/current-gen) and
	// recorded so copyStaged reads the PINNED generation directory — never live
	// staged/ and never re-reading current-gen — closing the dpkg-unpack vs
	// operator-cut torn-read window by construction. A resume keys the SAME
	// genid, so the cut continues against its original source even if a
	// concurrent publish has advanced current-gen.
	//
	// Empty is the legacy back-compat case: a pre-#1981 journal resumed under a
	// B-aware runner has no SourceGeneration. The runner treats an empty
	// SourceGeneration in an already-copied journal (State >= COPIED) as valid
	// legacy state and copies from live staged/ only as the pre-B fallback —
	// it never blocks recovery of an in-flight pre-B cut (plan §10 AGY r4).
	SourceGeneration string `json:"source_generation,omitempty"`
}
