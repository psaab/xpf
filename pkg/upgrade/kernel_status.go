package upgrade

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// ── operator-facing kernel-channel status (#6495) ────────────────────
//
// Before this, the ONLY readout of the #1930 LANE-1 kernel channel was a root
// shell running `xpfd upgrade kernel status`, or journald. Nothing reached the
// surfaces an operator actually watches: `pkg/cmdtree`, `proto/xpf/v1` and
// `pkg/grpcapi` had zero kernel-upgrade references (the single cmdtree hit was
// `request system in-service-upgrade`, the ISSU verb).
//
// The asymmetry that made this matter: the xpf-deploy kernel-roll orchestrator
// polls `xpfd upgrade kernel status` over node_exec, so AUTOMATION had a path
// and the human did not — during exactly the maintenance window where the human
// is most anxious about node state.
//
// This renders the same durable state that verb reads, through the CLI and gRPC
// paths, from ONE implementation so the console, the remote `cli` and the shell
// verb cannot disagree about a node mid-roll.

// ChannelStatus is a read-only snapshot of the kernel channel for the operator
// status surfaces.
type ChannelStatus struct {
	// Armed is true only for a genuine in-flight trial (the VERIFIED ARMED
	// state — not ARMING, which is prepared intent whose firmware one-shot was
	// never read back; an ARMING boot is a genuine trial only with the
	// #16809 boot evidence, reported separately as UnconfirmedTrial).
	Armed bool
	// UnconfirmedTrial is true when the journal is ARMING but THIS boot is
	// positively the candidate (BootCurrent == the inactive slot's entry and
	// the running kernel == CandidateVersion): a one-shot was queued without
	// a verified ARMED record (#16809 — process death between SetBootNext
	// and the ARMED rename, or a landed-but-errored SetBootNext). It is
	// gated and held exactly like a verified trial. False with
	// TrialClassificationErr set means the classification could not be made.
	UnconfirmedTrial bool
	// TrialClassificationErr records a failure to classify an ARMING boot
	// (boot entries / BootCurrent / running kernel unreadable). It does NOT
	// set ReadErr: the durable channel state WAS read, and conflating the
	// two would hide which half is broken.
	TrialClassificationErr error
	// Journal is the persisted channel state. Its State is KernelStateInit
	// when no run is in progress.
	Journal KernelJournal
	// PromotedVersion is the durable promotion marker: the last `uname -r`
	// this node promoted, or "" if none.
	PromotedVersion string
	// LastRoll is the durable outcome of the last COMPLETED roll (#6495). Its
	// Recorded() is false when no roll has completed on this box.
	LastRoll KernelRollOutcome
	// RunningVersion is the currently booted `uname -r`, when the caller could
	// read it. Rendered next to the candidate so "am I on the new kernel" does
	// not require a second command.
	RunningVersion string
	// HoldReason, when non-empty, is why this node is being held SECONDARY by
	// the kernel-upgrade election hold. "" when not held or not clustered.
	//
	// Supplied by the CALLER rather than derived here, and the string itself
	// lives in pkg/cluster (cluster.KernelUpgradeHoldReason). pkg/cluster owns
	// the hold — the flag, the election gate, and the `show chassis cluster
	// status` annotation are all its state — and having this package reach for
	// it would be an inverted dependency: pkg/upgrade records what was ARMED,
	// pkg/cluster decides what that means for ELIGIBILITY. It would also be a
	// literal import cycle, since pkg/upgrade's tests already import
	// pkg/cluster.
	HoldReason string
	// Refusal is the boot gate's durable did-not-run record (#6622), when one
	// exists. The gate exits 0 on every path so `systemctl status` reads
	// SUCCESS even after a refusal; this is what makes the decline visible
	// somewhere an operator looks, and it survives journal rotation.
	//
	// It carries the resolution FACTS the gate decided on. It does NOT carry
	// which candidate was armed, and that is deliberate rather than a gap: the
	// gate is POSIX sh and the journal is JSON, so it reads that file for one
	// bit and never for a value. The candidate is joined in here instead, from
	// Journal.CandidateVersion, which this function has already parsed in Go —
	// and it is still accurate, because a refusal never transitions the
	// journal, so the record and the ARMED candidate it declined are read from
	// one consistent state.
	Refusal PromoteRefusal

	// ReadErr records a failure to read the durable state. The status still
	// renders — a channel whose state cannot be read is itself the finding, and
	// refusing to print anything would leave the operator with strictly less
	// than before.
	ReadErr error
}

// ReadChannelStatus reads the durable kernel-channel state. Read-only: it
// loads the journal, the promotion marker and the last-roll record, and
// mutates nothing. Safe to call from a status RPC at operator frequency.
func ReadChannelStatus(journalPath string, sys KernelSystem) ChannelStatus {
	st := ChannelStatus{}
	if journalPath == "" {
		journalPath = DefaultKernelJournalPath
	}
	// Reuse the runner's loader rather than a second parse of the same file:
	// two readers of one on-disk format is how they drift.
	r := &KernelRunner{cfg: KernelConfig{JournalPath: journalPath, Sys: sys}}
	j, err := r.loadKernelJournal()
	if err != nil {
		st.ReadErr = err
	} else if j != nil {
		st.Journal = *j
		st.Armed = j.State.atLeast(KernelStateArmed) &&
			j.State != KernelStatePromoted && j.State != KernelStateReverted
	}
	// The gate's did-not-run record (#6622). Read before the sys-backed
	// lookups because it needs no KernelSystem: a box whose sys is nil (or
	// whose probes fail) is exactly the box whose gate most likely declined,
	// and the refusal is the most useful thing on the screen there.
	if rec, rerr := ReadRefusalRecord(journalPath); rerr != nil {
		if st.ReadErr == nil {
			st.ReadErr = rerr
		}
	} else {
		st.Refusal = rec
	}
	// #16809: an ARMING journal is classified against THIS boot's evidence
	// (BootCurrent + running kernel), never asserted known-good from the
	// state alone. A nil sys cannot classify: the journal was still read, so
	// the renderer must say "could not determine", not "known-good".
	if st.Journal.State == KernelStateArming {
		if sys == nil {
			st.TrialClassificationErr = fmt.Errorf("no system surface to classify the ARMING boot")
		} else if trial, _, terr := r.UnconfirmedTrial(); terr != nil {
			st.TrialClassificationErr = terr
		} else {
			st.UnconfirmedTrial = trial
		}
	}
	if sys == nil {
		return st
	}
	if v, err := sys.ReadPromotionMarker(); err != nil {
		if st.ReadErr == nil {
			st.ReadErr = err
		}
	} else {
		st.PromotedVersion = v
	}
	if rec, err := sys.ReadLastRoll(); err != nil {
		if st.ReadErr == nil {
			st.ReadErr = err
		}
	} else {
		st.LastRoll = rec
	}
	// Best-effort: a box whose uname is unreadable still has a channel state
	// worth rendering, and the running version is context, not the subject.
	if v, err := sys.RunningKernel(); err == nil {
		st.RunningVersion = v
	}
	return st
}

func unixOrDash(sec int64) string {
	if sec == 0 {
		return "-"
	}
	return time.Unix(sec, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// RenderChannelStatus writes the Junos-style rendering of the kernel channel.
//
// Informational only: it describes state and never signals failure through its
// own return. A node mid-roll is doing exactly what it was told to do, and a
// status command must not be the thing that makes it look broken.
func RenderChannelStatus(w io.Writer, st ChannelStatus) {
	fmt.Fprintln(w, "Kernel upgrade channel (LANE 1, A/B slots):")

	if st.ReadErr != nil {
		// Reported, not fatal — see ChannelStatus.ReadErr.
		fmt.Fprintf(w, "  WARNING: could not fully read the channel state: %v\n", st.ReadErr)
	}
	if st.RunningVersion != "" {
		fmt.Fprintf(w, "  Running kernel:  %s\n", st.RunningVersion)
	}

	// ── armed candidate ──
	if st.TrialClassificationErr != nil {
		fmt.Fprintf(w, "  WARNING: could not classify the ARMING boot: %v\n", st.TrialClassificationErr)
	}
	if st.UnconfirmedTrial {
		// #16809: the journal never reached ARMED, but THIS boot IS the
		// candidate — a one-shot was queued without a verified record.
		// It is a trial in flight and must read as one, not as the
		// "next boot is known-good" intent an ordinary ARMING means.
		j := st.Journal
		fmt.Fprintln(w, "  Armed:           yes — an UNCONFIRMED candidate trial is IN FLIGHT (#16809)")
		fmt.Fprintf(w, "    Candidate:     %s\n", dashIfEmpty(j.CandidateVersion))
		fmt.Fprintf(w, "    Known-good:    %s\n", dashIfEmpty(j.KnownGoodVersion))
		fmt.Fprintf(w, "    Active slot:   %s\n", dashIfEmpty(j.ActiveSlot))
		fmt.Fprintf(w, "    Candidate slot:%s\n", " "+dashIfEmpty(j.InactiveSlot))
		fmt.Fprintf(w, "    State:         %s (one-shot queued but never read back; this boot IS the candidate)\n", dashIfEmpty(string(j.State)))
		if !j.StartedAt.IsZero() {
			fmt.Fprintf(w, "    Armed at:      %s\n", j.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
		if j.PromoteAttempts > 0 {
			fmt.Fprintf(w, "    Revert attempts: %d of %d\n", j.PromoteAttempts, maxPromoteAttempts)
		}
	} else if st.Armed {
		j := st.Journal
		fmt.Fprintln(w, "  Armed:           yes — a candidate trial is IN FLIGHT")
		fmt.Fprintf(w, "    Candidate:     %s\n", dashIfEmpty(j.CandidateVersion))
		fmt.Fprintf(w, "    Known-good:    %s\n", dashIfEmpty(j.KnownGoodVersion))
		fmt.Fprintf(w, "    Active slot:   %s\n", dashIfEmpty(j.ActiveSlot))
		fmt.Fprintf(w, "    Candidate slot:%s\n", " "+dashIfEmpty(j.InactiveSlot))
		fmt.Fprintf(w, "    State:         %s\n", dashIfEmpty(string(j.State)))
		if j.BootID != "" {
			// The one-shot BootNext that was positively read back (#5847) —
			// the provenance tying this boot to the arm.
			fmt.Fprintf(w, "    BootNext:      Boot%s (one-shot, cleared by the firmware on boot)\n", j.BootID)
		}
		if !j.StartedAt.IsZero() {
			fmt.Fprintf(w, "    Armed at:      %s\n", j.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
		if j.PromoteAttempts > 0 {
			fmt.Fprintf(w, "    Revert attempts: %d of %d\n", j.PromoteAttempts, maxPromoteAttempts)
		}
	} else if st.Journal.State != KernelStateInit && st.Journal.State != "" {
		// A run exists but is not a verified in-flight trial: INSTALLED (staged
		// but not armed) or ARMING (intent recorded, firmware one-shot never
		// confirmed). Naming the difference matters — the next boot does NOT
		// honor an ARMING candidate, so an operator who reads "armed" there
		// would expect a trial that will not happen.
		fmt.Fprintf(w, "  Armed:           no — a run is in progress at state %s\n", st.Journal.State)
		fmt.Fprintf(w, "    Candidate:     %s\n", dashIfEmpty(st.Journal.CandidateVersion))
		if st.Journal.State == KernelStateArming {
			if st.TrialClassificationErr != nil {
				fmt.Fprintln(w, "    NOTE: ARMING with unclassifiable boot evidence — the one-shot")
				fmt.Fprintln(w, "          may have been queued (#16809); this boot could NOT be")
				fmt.Fprintln(w, "          proven known-good, so do not assume it is.")
			} else {
				fmt.Fprintln(w, "    NOTE: ARMING is prepared intent only — the firmware one-shot was")
				fmt.Fprintln(w, "          never confirmed, and this boot is positively the KNOWN-GOOD")
				fmt.Fprintln(w, "          kernel (the candidate slot did not boot / is not running).")
			}
		}
	} else {
		fmt.Fprintln(w, "  Armed:           no — no candidate kernel is armed")
	}

	// ── durable promotion marker ──
	if st.PromotedVersion != "" {
		fmt.Fprintf(w, "  Promotion marker: %s\n", st.PromotedVersion)
	} else {
		fmt.Fprintln(w, "  Promotion marker: none")
	}

	// ── last completed roll (#6495) ──
	if st.LastRoll.Recorded() {
		fmt.Fprintf(w, "  Last roll:       %s\n", st.LastRoll.Outcome)
		fmt.Fprintf(w, "    Version:       %s\n", dashIfEmpty(st.LastRoll.Version))
		if st.LastRoll.KnownGood != "" {
			fmt.Fprintf(w, "    Known-good:    %s\n", st.LastRoll.KnownGood)
		}
		fmt.Fprintf(w, "    At:            %s\n", unixOrDash(st.LastRoll.UnixSec))
		if st.LastRoll.Reason != "" {
			fmt.Fprintf(w, "    Reason:        %s\n", st.LastRoll.Reason)
		}
	} else {
		fmt.Fprintln(w, "  Last roll:       none recorded")
	}

	// ── boot-gate refusal (#6622) ──
	//
	// Rendered AFTER the armed/marker/last-roll block so the candidate it
	// declined is already on screen above it: the record deliberately does not
	// duplicate the candidate version, and this ordering is what joins the two
	// for the reader.
	renderRefusal(w, st.Refusal)

	// ── cluster election hold ──
	if st.HoldReason != "" {
		fmt.Fprintln(w, "")
		fmt.Fprintf(w, "  Cluster: this node is HELD SECONDARY — %s\n", st.HoldReason)
	}
}

// summaryLine is a one-line form for embedding in a wider status render.
func (st ChannelStatus) summaryLine() string {
	switch {
	case st.UnconfirmedTrial:
		return strings.TrimSpace(fmt.Sprintf("unconfirmed trial candidate %s (known-good %s)",
			dashIfEmpty(st.Journal.CandidateVersion), dashIfEmpty(st.Journal.KnownGoodVersion)))
	case st.Armed:
		return strings.TrimSpace(fmt.Sprintf("armed candidate %s (known-good %s)",
			dashIfEmpty(st.Journal.CandidateVersion), dashIfEmpty(st.Journal.KnownGoodVersion)))
	case st.LastRoll.Recorded():
		return fmt.Sprintf("last roll %s (%s)", st.LastRoll.Outcome,
			dashIfEmpty(st.LastRoll.Version))
	default:
		return "idle"
	}
}
