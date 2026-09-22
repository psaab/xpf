// Package fwdstatus builds and formats the one-screen forwarding-daemon
// health view surfaced via `show chassis forwarding` (#877).  The
// package has no dependency on pkg/cli or pkg/grpcapi so both the
// local TTY and gRPC paths can consume it without circular imports.
package fwdstatus

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// State is the tri-state liveness of the forwarding path.
type State string

const (
	StateOnline   State = "Online"
	StateDegraded State = "Degraded"
	StateUnknown  State = "Unknown"
)

// CPUMode distinguishes whether the worker-threads CPU row has a
// meaningful value (userspace-dp) or reads as N/A (eBPF path).
type CPUMode int

const (
	// CPUModeWorkers is the userspace-dp path; WorkerCPUPercent is
	// the summed per-worker cumulative CPU%.
	CPUModeWorkers CPUMode = iota
	// CPUModeEBPFNoWorkers is the eBPF path; packet processing runs
	// in XDP/TC hooks, not user-space workers.  The row renders an
	// explicit N/A label instead of a bare "0 percent".
	CPUModeEBPFNoWorkers
)

// ForwardingStatus is the flat struct passed to Format.  All fields
// are computed by Build; Format does not read /proc or call into the
// dataplane.
type ForwardingStatus struct {
	State State

	// CPU windows (5s / 1m / 5m) — indexed by CPUWindow* constants.
	// DaemonCPUWindows is /proc/self/stat per-core % (can exceed
	// 100 on multi-core).  WorkerCPUWindows is per-worker-average
	// activity fraction in [0, 100] — time-weighted Σactive_ns /
	// Σwall_ns across all workers.  Parallel *Valid flags are
	// false when the ring doesn't have a sample ≥ W old yet
	// (short uptime); the formatter renders `-` for invalid cols.
	DaemonCPUWindows     [numCPUWindows]float64
	WorkerCPUWindows     [numCPUWindows]float64
	DaemonCPUWindowValid [numCPUWindows]bool
	WorkerCPUWindowValid [numCPUWindows]bool

	// WorkerCPUMode distinguishes the eBPF "no workers" path from
	// the userspace path — on eBPF the worker row prints the
	// explicit N/A label instead of window values, regardless of
	// WorkerCPUWindowValid.
	WorkerCPUMode CPUMode

	HeapPercent       float64
	HeapPercentValid  bool    // False when RSS or its memory limit cannot be measured.
	BufferPercent     float64 // Only valid if BufferKnown.
	BufferKnown       bool    // False on userspace-dp until UMEM telemetry lands.
	BufferFollowupRef int     // GitHub issue number printed in place of buffer %.
	Uptime            time.Duration

	// LastSnapshotRejectReasons is stamped by the userspace manager when the
	// latest snapshot contains policy content the matcher cannot represent.
	// The forwarding view receives it from the already-fetched ProcessStatus.
	LastSnapshotRejectReasons []string
	// --- Helper crash/restart state (#7250) ----------------------
	//
	// #5838's last acceptance bullet: "operational status exposes exit
	// code/signal, restart count, last exit/restart timestamps, backoff
	// deadline, and crash-loop reason". Before this, a crash-looping helper
	// rendered as `State  Unknown` and NOTHING else — every surface degraded
	// to a generic "unavailable" because `resetAfterHelperGoneLocked` clears
	// the cached status, so an operator could not tell "crashed and retrying"
	// from "never started" from "intentionally stopped".
	//
	// HelperCrashKnown gates every field below, and it is NOT redundant with
	// LastExitWasCrash. It is the same discipline BufferKnown applies above:
	// a zero HelperCrashRecord is byte-identical to a healthy one, and
	// `ExitCode: 0` satisfies the `ExitCode >= 0` discriminator, so a
	// renderer that keyed on the record alone would print "exit code 0" for a
	// helper that never crashed. False means "could not ask" (no manager, not
	// the userspace path); it is not a claim that the helper is well.
	HelperCrashKnown bool

	// LastExitWasCrash is the historical fact: the last helper exit was
	// unexpected. It deliberately SURVIVES an intentional stop, because the
	// supervisor's retry path reads it as debt.
	LastExitWasCrash bool

	// RestartPending reports whether a retry is actually ARMED. Distinct from
	// LastExitWasCrash on purpose: after an intentional stop the first is
	// true and this is false, and rendering the first as though it were the
	// second is the exact defect the #7250 data half fixed. Never render a
	// restart deadline without this.
	RestartPending bool

	// HelperCrashLooping is HelperCrashRecord.CrashLooping() — backoff at the
	// cap, not a restart count. Read as "this helper is not coming back".
	HelperCrashLooping bool

	// HelperExitCode is the child's exit status, or -1 when it was signalled.
	// Exactly one of HelperExitCode >= 0 and HelperSignal != "" is
	// meaningful, and HelperSignal is the discriminator.
	HelperExitCode int
	HelperSignal   string

	// HelperExitDetail is the reaped disposition as prose ("exit status
	// 101"). Display only — the split fields above are what a decision reads.
	HelperExitDetail string

	// HelperPID is the dead child, kept so an operator can correlate the row
	// with journald.
	HelperPID int

	// HelperLastExit is when the exit was observed; zero when none.
	HelperLastExit time.Time

	// HelperRestarts counts consecutive restart ATTEMPTS since the last
	// helper that reached readiness.
	HelperRestarts int

	// HelperLastRestartAttempt is when a restart was last attempted in this
	// crash episode; zero when none has been. Unlike HelperNextRestart this
	// needs no RestartPending guard — it is a fact about what already
	// happened, not a promise about what will (#7967).
	HelperLastRestartAttempt time.Time

	// HelperNextRestart is when the armed retry is due. Only meaningful when
	// RestartPending — after an intentional stop the underlying record
	// carries a time in the PAST with no timer behind it.
	HelperNextRestart time.Time

	// HelperCrashEpisodes is the #8397 count of crash episodes this daemon has
	// RECOVERED from, and HelperCrashEpisodesOldest the exit time of the oldest
	// one still retained.
	//
	// One summary row rather than a table, deliberately: this block is already
	// dense, and the question history answers is "is this recurring?" — which a
	// count and a window answer completely. The per-episode detail is reachable
	// through userspace.Manager.HelperCrashHistory() for a future verb.
	//
	// The count is NOT bounded by the retention ring. A daemon that recovered
	// from 40 crashes reports 40 while holding the last 8, because "8 crashes"
	// and "at least 8 crashes" are different answers to the question being
	// asked.
	HelperCrashEpisodes       int
	HelperCrashEpisodesOldest time.Time

	// (Cluster peer rendering moved to the gRPC handler in #879.
	// fwdstatus now produces pure single-block output; the handler
	// composes node0:/node1: blocks externally.)
}

// Format renders a ForwardingStatus in the Junos-style one-screen
// layout.  Labels, ordering, and spacing are the contract surface —
// do not rearrange without updating unit tests.
func Format(fs *ForwardingStatus) string {
	var b strings.Builder
	b.WriteString("FWDD status:\n")
	writeRow(&b, "State", string(fs.State))
	// CPU rows: three sliding windows (5s / 1m / 5m).  Daemon row
	// is /proc/self/stat per-core % (can exceed 100 on multi-core;
	// no upper clamp).  Worker row is Σ(thread_cpu_ns) / Σ(wall_ns)
	// from CLOCK_THREAD_CPUTIME_ID — OS thread CPU, not dataplane
	// activity (see #883/#884; activity-based signal was tried and
	// empirically found broken at 25 Gbps).  Columns with insufficient
	// history (uptime < window) render `-`.  On eBPF, the worker row
	// prints the N/A label.
	writeRow(&b, "Daemon CPU utilization",
		formatWindowRow(fs.DaemonCPUWindows, fs.DaemonCPUWindowValid))

	if fs.WorkerCPUMode == CPUModeEBPFNoWorkers {
		writeRow(&b, "Worker threads CPU utilization",
			"N/A — eBPF path has no worker threads")
	} else {
		writeRow(&b, "Worker threads CPU utilization",
			formatWindowRow(fs.WorkerCPUWindows, fs.WorkerCPUWindowValid))
	}

	if fs.HeapPercentValid {
		writeRow(&b, "Heap utilization",
			fmt.Sprintf("%.0f percent", clampPercent(fs.HeapPercent)))
	} else {
		writeRow(&b, "Heap utilization", "-")
	}

	if fs.BufferKnown {
		writeRow(&b, "Buffer utilization",
			fmt.Sprintf("%.0f percent", clampPercent(fs.BufferPercent)))
	} else if fs.BufferFollowupRef != 0 {
		writeRow(&b, "Buffer utilization",
			fmt.Sprintf("unknown (see #%d)", fs.BufferFollowupRef))
	} else {
		writeRow(&b, "Buffer utilization", "unknown")
	}

	writeRow(&b, "Uptime:", formatUptime(fs.Uptime))
	if len(fs.LastSnapshotRejectReasons) > 0 {
		writeRow(&b, "Last snapshot rejection", fs.LastSnapshotRejectReasons[0])
		for _, reason := range fs.LastSnapshotRejectReasons[1:] {
			fmt.Fprintf(&b, "%37s%s\n", "", reason)
		}
	}

	writeHelperCrash(&b, fs)

	// (#879: cluster framing — node0:/node1: headers, peer block —
	// is composed by the gRPC handler on top of this single-node
	// output. fwdstatus stays a pure single-block formatter.)
	return b.String()
}

// writeHelperCrash renders the helper crash/restart block (#7250).
//
// SILENT WHEN THERE IS NOTHING TO REPORT, by design. The record is cleared
// wholesale on a successful restart (`restartHelperAfterCrash` assigns a fresh
// HelperCrashRecord{}), so a healthy or recovered helper holds the zero value
// and there is no episode to describe. `State` already reports helper health;
// this block is an exception report, and printing "Helper last exit: none" on
// every healthy box would be the confusing empty record rather than a useful
// one. Same convention as writeEventStreamSection's early return and
// FormatSYNCookieCounterRows returning "" when no counter fired.
//
// It follows that this surface describes the CURRENT crash episode, not a
// history: once the helper recovers, the exit that preceded it is gone from the
// record and cannot be rendered. Correlate with journald via the PID row.
//
// #5838's "last restart timestamp" is NOT rendered and cannot be: the record is
// zeroed on a successful restart, so no such field could survive inside it.
// Tracked in #7967 rather than papered over.
func writeHelperCrash(b *strings.Builder, fs *ForwardingStatus) {
	// HelperCrashKnown first: a zero HelperCrashRecord is byte-identical to a
	// healthy one, so without this gate an unreachable manager and a
	// never-crashed helper are the same render.
	if !fs.HelperCrashKnown {
		return
	}

	// #8397: the RECURRENCE row, emitted ABOVE the recovered-helper early
	// return below, and that placement is the entire point.
	//
	// The guard that follows returns as soon as the helper is healthy — which
	// is correct for every CURRENT-episode row, and fatal for this one. History
	// exists precisely for the helper that crashed four times in the last hour
	// and is running now: `restartHelperAfterCrash` wipes the record on
	// success, so at that moment `LastExitWasCrash` is false, `RestartPending`
	// is false, and a row placed after the guard would render in every case
	// EXCEPT the one it was written for. That failure would be invisible —
	// a clean crash surface is exactly what a healthy helper is supposed to
	// look like.
	if fs.HelperCrashEpisodes > 0 {
		v := fmt.Sprintf("%d recovered in this daemon", fs.HelperCrashEpisodes)
		if !fs.HelperCrashEpisodesOldest.IsZero() {
			v += ", oldest retained " + fs.HelperCrashEpisodesOldest.Format(time.RFC3339)
		}
		writeRow(b, "Helper crash episodes", v)
	}

	if !fs.LastExitWasCrash && !fs.RestartPending {
		return
	}

	// FOUR NAMED STATES over (RestartPending x HelperCrashLooping), not a
	// crash-looping boolean with qualifiers.
	//
	// CrashLooping() stays true after an intentional stop — LastExitWasCrash
	// survives a stop because the retry path reads it as debt, and Restarts
	// survives with it — so the predicate keeps reporting "not coming back"
	// when the real reason is "stopped", not "backoff exhausted".
	//
	// RestartPending therefore picks the HEADLINE and the loop verdict only
	// refines it. An operator reads the first line and acts on it, so
	// "CRASH LOOPING" on a stopped helper sends them hunting a crash that is
	// not currently happening. "stopped, after a crash loop" is its own state
	// rather than a qualifier bolted onto the loop state, following
	// firewallEffectiveLiveness, whose third arm carries an explicit reason
	// instead of a flag.
	switch {
	case fs.RestartPending && fs.HelperCrashLooping:
		writeRow(b, "Helper", "CRASH LOOPING — retrying at the backoff maximum")
	case fs.RestartPending:
		writeRow(b, "Helper", "crashed — restart pending")
	case fs.HelperCrashLooping:
		writeRow(b, "Helper", "stopped — after a crash loop, no restart armed")
	default:
		writeRow(b, "Helper", "stopped — last exit was a crash, no restart armed")
	}

	// The crash-loop REASON, #5838's last-named field, rendered as a
	// DERIVATION rather than a stored string.
	//
	// CrashLooping() is `LastExitWasCrash && helperRestartDelay(Restarts) >=
	// helperRestartBackoffMax`, so the reason is fully determined by inputs
	// already on this struct: the restart count, and the fact that the
	// schedule reached its ceiling. Deriving it here cannot drift from the
	// predicate it explains, which a string captured at decision time can.
	if fs.HelperCrashLooping {
		writeRow(b, "Helper crash-loop reason",
			fmt.Sprintf("restart backoff reached its maximum after %d restarts",
				fs.HelperRestarts))
	}

	if !fs.HelperLastExit.IsZero() {
		writeRow(b, "Helper last exit", fs.HelperLastExit.Format(time.RFC3339))
	}

	// Signal is the discriminator: exactly one of the two is meaningful, and
	// ExitCode is -1 when the child was signalled. Rendering both would print
	// "exit code -1" beside a signal name.
	if fs.HelperSignal != "" {
		writeRow(b, "Helper exit signal", fs.HelperSignal)
	} else if fs.HelperExitCode >= 0 {
		writeRow(b, "Helper exit code", strconv.Itoa(fs.HelperExitCode))
	}
	if fs.HelperExitDetail != "" {
		writeRow(b, "Helper exit detail", fs.HelperExitDetail)
	}
	if fs.HelperPID != 0 {
		writeRow(b, "Helper last PID", strconv.Itoa(fs.HelperPID))
	}
	writeRow(b, "Helper restart attempts", strconv.Itoa(fs.HelperRestarts))

	// No RestartPending guard: a past attempt is a fact, not a promise. The
	// deadline below needs the guard because after an intentional stop the
	// record carries one with no timer behind it.
	if !fs.HelperLastRestartAttempt.IsZero() {
		writeRow(b, "Helper last restart attempt",
			fs.HelperLastRestartAttempt.Format(time.RFC3339))
	}

	// Only meaningful when a retry is armed. After an intentional stop the
	// record carries a deadline in the PAST with no timer behind it, so
	// printing it unconditionally would promise a restart that never comes.
	if fs.RestartPending && !fs.HelperNextRestart.IsZero() {
		writeRow(b, "Helper next restart", fs.HelperNextRestart.Format(time.RFC3339))
	}
}

// writeRow writes a `  <label>   <value>\n` line with a fixed
// label column (34 chars, matching the widest label "Worker threads
// CPU utilization").
func writeRow(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, "  %-34s %s\n", label, value)
}

// clampPercent clamps a percentage to [0, 100].  Used for Heap and
// Buffer (ratios that are bounded by construction — RSS/limit,
// used/max).  CPU rows use floorZero instead because multi-core
// daemons legitimately exceed 100%.
func clampPercent(p float64) float64 {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

// floorZero returns max(p, 0) with no upper bound.  Used for CPU
// rows where values > 100 are meaningful (per-core percent).
func floorZero(p float64) float64 {
	if p < 0 {
		return 0
	}
	return p
}

// formatWindowRow renders three windows as
// `NN% / NN% / NN%   (5s / 1m / 5m)`.  Invalid columns render `-`.
func formatWindowRow(pct [numCPUWindows]float64, valid [numCPUWindows]bool) string {
	cols := [numCPUWindows]string{}
	for i := 0; i < numCPUWindows; i++ {
		if valid[i] {
			cols[i] = fmt.Sprintf("%.0f%%", floorZero(pct[i]))
		} else {
			cols[i] = "-"
		}
	}
	return fmt.Sprintf("%-5s / %-5s / %-5s   (5s / 1m / 5m)", cols[0], cols[1], cols[2])
}

// formatUptime renders a duration as "N days, N hours, N minutes,
// N seconds" matching the Junos/vSRX layout in issue #877.
func formatUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int64(d / time.Second)
	days := total / 86400
	total -= days * 86400
	hours := total / 3600
	total -= hours * 3600
	minutes := total / 60
	seconds := total - minutes*60
	return fmt.Sprintf("%d days, %d hours, %d minutes, %d seconds",
		days, hours, minutes, seconds)
}
