package upgrade

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// ── durable last-roll outcome (#6495) ────────────────────────────────
//
// The kernel channel deliberately forgets. `revert()` clears the journal by
// design — the next boot must be a clean ordinary boot — and the promotion
// marker is written only on PROMOTE. So after a candidate is rejected or
// firmware falls back before the candidate boots, `xpfd upgrade kernel status`
// prints `promoted=none` / `armed=none`: correct, and indistinguishable from a
// box that never tried. The reason for a rejection or known-good fallback
// otherwise survives only in journald, which on an appliance may not be
// persistent at all.
//
// That is the wrong thing to forget. Operators need to know WHAT was tried,
// WHY it failed, or that firmware discarded the trial by returning to
// known-good. So the outcome — and only the outcome, a few bytes, never the
// in-flight state — is recorded durably alongside the promotion marker.
//
// Deliberately NOT cleared at arm time, unlike the promotion marker. The marker
// is cleared on Arm because a stale "promoted" from a prior same-version roll
// would FALSE-SATISFY the HA orchestrator's post-reboot version check (r1 Codex
// High). This record answers no such check: it is history, it is overwritten by
// the next roll's outcome, and clearing it on arm would destroy the previous
// answer precisely when an operator re-arming after a failure wants it.

// KernelRollOutcome values.
const (
	// RollOutcomePromoted: the candidate passed the promotion gate and the
	// BootOrder was reordered candidate-first.
	RollOutcomePromoted = "promoted"
	// RollOutcomeReverted: the candidate did not pass; the box went back to
	// the known-good slot.
	RollOutcomeReverted = "reverted"
	// RollOutcomeDiscarded: the gate found the box already on the known-good
	// slot (the firmware fell back / ignored BootNext), so the candidate was
	// pruned in place with no reboot (#10772 x1-F6).
	RollOutcomeDiscarded = "discarded"
)

// KernelRollOutcome is the durable record of the LAST completed kernel roll.
// One roll, overwritten by the next.
type KernelRollOutcome struct {
	// Version is the candidate `uname -r` the roll was attempting.
	Version string `json:"version"`
	// KnownGood is the version the box was on before (and returned to, on a
	// revert or a known-good discard). Rendering the pair makes the result
	// legible: "tried X, still on Y".
	KnownGood string `json:"known_good,omitempty"`
	// Outcome is RollOutcomePromoted, RollOutcomeReverted, or
	// RollOutcomeDiscarded.
	Outcome string `json:"outcome"`
	// Reason explains a revert or known-good discard. Empty on a promote,
	// where "it passed every gate" is the whole story.
	Reason string `json:"reason,omitempty"`
	// UnixSec is when the outcome was recorded.
	UnixSec int64 `json:"unix_sec"`
}

// Reverted reports whether this record is a failed roll.
func (o KernelRollOutcome) Reverted() bool { return o.Outcome == RollOutcomeReverted }

// Recorded reports whether a roll outcome exists at all (a zero record means
// no roll has completed on this box).
func (o KernelRollOutcome) Recorded() bool { return o.Outcome != "" }

// lastRollPath records the outcome of the last completed kernel roll. Sits
// next to the promotion marker in the same durable dir; both survive the
// journal clear.
const lastRollPath = "/var/lib/xpf/kernel-last-roll"

func (s *realKernelSystem) WriteLastRoll(rec KernelRollOutcome) error {
	if err := fsatomic.MkdirAllDurable(filepath.Dir(lastRollPath), 0755); err != nil {
		return fmt.Errorf("create last-roll dir: %w", err)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal last-roll record: %w", err)
	}
	return fsatomic.WriteFileDurable(lastRollPath, append(data, '\n'), 0644)
}

func (s *realKernelSystem) ReadLastRoll() (KernelRollOutcome, error) {
	data, err := os.ReadFile(lastRollPath)
	if err != nil {
		if os.IsNotExist(err) {
			return KernelRollOutcome{}, nil
		}
		return KernelRollOutcome{}, fmt.Errorf("read last-roll record: %w", err)
	}
	var rec KernelRollOutcome
	if err := json.Unmarshal(data, &rec); err != nil {
		// A corrupt record must NOT fail the status surface: the point of this
		// file is to make a maintenance window less blind, and refusing to
		// render the rest of the channel state because a history byte rotted
		// would make it more blind. Report it as an unreadable record.
		return KernelRollOutcome{
			Outcome: RollOutcomeReverted,
			Reason: fmt.Sprintf("last-roll record at %s is unreadable (%v) — "+
				"the outcome of the previous roll is lost", lastRollPath, err),
			UnixSec: 0,
		}, nil
	}
	return rec, nil
}

// recordRollOutcome durably stores the outcome of a completed roll and returns
// the exact record attempted, even when the best-effort history write fails.
func (r *KernelRunner) recordRollOutcome(j *KernelJournal, outcome, reason string) KernelRollOutcome {
	rec := KernelRollOutcome{
		Outcome: outcome,
		UnixSec: time.Now().Unix(),
	}
	if j != nil {
		rec.Version = j.CandidateVersion
		rec.KnownGood = j.KnownGoodVersion
	}
	// Collapse the reason to one line: it is rendered in a status table, and a
	// multi-line error (a wrapped exec failure) would break the layout.
	rec.Reason = strings.Join(strings.Fields(reason), " ")
	if err := r.cfg.Sys.WriteLastRoll(rec); err != nil {
		r.logf("kernel-upgrade: WARNING record last-roll outcome (%s): %v", outcome, err)
	}
	return rec
}
