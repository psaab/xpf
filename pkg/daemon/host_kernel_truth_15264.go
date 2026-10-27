package daemon

import (
	"context"
	"log/slog"
	"time"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #15264 (B06-02): low-rate kernel-truth recheck for the host-inbound / lo0
// applied-state latches.
//
// The latches (hostInboundEnforced / lo0Enforced) are process-local: they
// record that a table loaded at SOME generation, and nothing re-reads the
// kernel afterwards. A privileged out-of-band `nft flush ruleset` (an
// accepted operator action — scripts/image/xpf-input-closed.service:22-26
// says post-handoff a flush "also wipes the real tables ... re-apply to
// converge") therefore left HostInboundApplied() reporting Current while
// inet xpf_hostinbound (and xpf_lo0) no longer existed, until the next
// unrelated apply happened to re-install them.
//
// This recheck mirrors reassertTransitGate (transit_gate_tick_9725.go):
// periodically re-read kernel truth and, when an ESTABLISHED table is
// provably gone, mark the operator-facing state stale and Warn (once per
// drift episode) instead of claiming Current. It deliberately does NOT
// re-drive the apply: the service file documents re-apply as the operator
// convergence step, and an auto-reapply loop would fight an operator who
// flushed intentionally. The next successful apply clears the staleness via
// noteHostInboundApplySucceeded / applyLo0Filter as before.
//
// #16823 (R3-F09-02): marking stale alone was FAIL-OPEN on the documented
// recovery step. The host-inbound arm now also clears the day-2 retention
// state (hostInboundEnforced / hostInboundCoveredAddrs /
// hostInboundDHCPRetainedAddrs, plus the gap marker/spec when the gap
// table is also gone), mirroring the lo0 arm and the #5790 teardown: a
// re-apply whose real install then fails takes the cold-boot fence path
// instead of computing an empty uncovered set from the stale covered set
// and installing no fence at all. HostInboundApplied().Established keeps
// reporting the historical establishment via the separate sticky
// hostInboundEstablished15264 bit (also the probe gate above), while
// LastApplyFailed keeps the state Stale until a real install succeeds.
//
// #17861: the whole observe+clear pass runs under applySem. The retention
// state the drift arms clear (hostInboundEnforced, the covered /
// DHCP-retained sets, the gap + pre-activation fence pointers, lo0Enforced)
// is applySem-owned — every other reader and writer holds applySem — so the
// kernel reads and the clears must be ONE critical section relative to
// applies. An unlocked probe that had already observed a flushed table
// could be preempted between its reads and the clears while a concurrent
// apply installed and published a fresh real generation; resuming, the
// stale observation wiped the FRESH generation's retention state, so the
// next failed apply replaced the valid retained table and its service
// accepts with the cold-boot deny-only fence and lost the retained fence
// bookkeeping. Under applySem an apply either completes before the kernel
// reads (the probe then observes the fresh table and stays Current) or
// runs after the clears (its publication supersedes them).
//
// Probe choice:
//   - xpf_hostinbound: TableDropsInput. A real generation always carries a
//     DROP verdict on its base input chain except a junos-host program-only
//     generation, whose DROPs live in subchains and which therefore reads
//     false here (the documented TableDropsInput residual). To avoid
//     false-flagging that legitimate generation, a non-dropping read only
//     counts as drift when the table is also not TableEnforcing at all
//     (absent or an empty shell): a program-only table is enforcing by
//     shape, so it stays Current.
//   - xpf_lo0: TableEnforcing. A real lo0 filter governs via accept /
//     reject / discard terms and need not contain any DROP verdict at all,
//     so DROP presence is the wrong predicate; an input-hook chain with
//     rules is the enforcing shape. The lo0 cold-boot fence also reads
//     enforcing — correctly, since it does drop its snapshot's addresses.
//
// Read errors prove nothing (cf. runInputBarrierEnsure) and never mark
// stale. Nothing-established / nothing-configured surfaces are not probed
// at all, so a cold or no-enforcement daemon costs no netlink traffic and
// can never be marked stale for a table it never claimed.

var hostKernelTruthInterval15264 = 30 * time.Second

// The kernel readback seam is nftInstaller, like every other nft read in
// this package; tests script it via fakeNftInstaller.

// recheckHostKernelTruth15264 performs one kernel-truth pass. now is the
// observation time recorded as the failure time when host-inbound drift is
// found (lo0 has no timestamped failure latch; lo0LastFailed carries it).
//
// #17861: the pass holds applySem from before the first kernel read until
// after the last clear (see the file comment). A cancelled acquire means
// the daemon is stopping — skip the tick; the shutdown drain owns the
// semaphore from there, and the next tick of a still-running daemon
// re-probes.
func (d *Daemon) recheckHostKernelTruth15264(now time.Time) {
	if d == nil || nftInstaller == nil {
		return
	}
	if err := d.applySem.Acquire(d.applyCancelCtx(), 1); err != nil {
		return
	}
	defer d.applySem.Release(1)
	drift := false

	// Host-inbound: only an established surface can drift. The probe gate
	// is hostInboundEstablished15264, NOT hostInboundEnforced: on drift the
	// enforced latch is cleared (#16823, below), so a latch-gated probe
	// would go blind after the first drift episode and could never observe
	// a heal or a second flush. The established bit is sticky until a
	// successful real install or a daemon teardown clears it, so the
	// warn de-dupe and the never-established no-probe property both hold.
	if d.hostInboundEstablished15264.Load() {
		drops, err := nftInstaller.TableDropsInput(xnft.HostInboundTableName)
		switch {
		case err != nil:
			// Unreadable proves nothing; stay Current.
		case drops:
			// Table stands with DROP enforcement.
		default:
			// No DROP on the base chain: either the table is gone /
			// an empty shell (drift) or a program-only generation whose
			// DROPs live in subchains (legitimate). TableEnforcing
			// separates them: a program-only table still has rules.
			enforcing, enErr := nftInstaller.TableEnforcing(xnft.HostInboundTableName)
			if enErr == nil && !enforcing {
				d.noteHostInboundApplyFailed(now)
				// #16823 (R3-F09-02): the kernel-false premise must also
				// clear the day-2 retention state, mirroring the lo0 arm
				// below and the #5790 teardown. Leaving
				// hostInboundEnforced set made a re-apply whose real
				// install failed take the day-2 branch, compute an
				// empty uncovered set from the stale covered set, and
				// install NEITHER the cold-boot fence NOR a gap fence
				// for previously covered addresses — the documented
				// recovery step (re-apply after `nft flush ruleset`)
				// left every previously covered local address with no
				// kernel default-deny until a later apply succeeded.
				d.hostInboundEnforced.Store(false)
				d.hostInboundCoveredAddrs = nil
				d.hostInboundDHCPRetainedAddrs = nil
				// The gap/pre-activation fences share the flushed
				// ruleset. Probe the gap table before clearing its
				// marker/spec: a gap fence that somehow still stands
				// (partial flush) stays reported, and its spec stays
				// mergeable by the next gap install. The cold-boot
				// fence replaces the MAIN table, so it shares the main
				// table's fate and needs no separate probe.
				if d.hostInboundGapFenceActive.Load() {
					if gapEnforcing, gapErr := nftInstaller.TableEnforcing(xnft.HostInboundGapTableName); gapErr == nil && !gapEnforcing {
						d.hostInboundGapFenceActive.Store(false)
						d.hostInboundGapFenceSpec = nil
						d.hostInboundPreActivationFence = nil
					}
				}
				drift = true
			}
		}
	}

	// lo0: an established real filter (lo0Enforced) whose table vanished.
	// lo0 has no exported applied-state projection, so the drift is
	// recorded in lo0LastFailed (the host-inbound handoff already treats
	// it as "lo0 protection failed") and the lo0Enforced latch is
	// cleared: the premise "a real filter is loaded" is kernel-false,
	// so the next failed install must take the cold-boot fence path
	// rather than the day-2 retention branch (#6476/#5790 parity).
	// A standing fence (lo0Enforced false) is not probed: it is already
	// reported as not-a-real-filter.
	if d.lo0Enforced.Load() {
		enforcing, err := nftInstaller.TableEnforcing(xnft.Lo0TableName)
		if err == nil && !enforcing {
			d.lo0Enforced.Store(false)
			d.lo0LastFailed.Store(true)
			drift = true
		}
	}

	if drift {
		if !d.hostDriftNoticed15264.Swap(true) {
			slog.Warn("host nftables table missing from kernel while applied state claimed current; marking applied state stale — re-apply to converge (#15264)",
				"issue", "#15264",
				"host_inbound_current", d.HostInboundApplied().Current(),
				"lo0_enforced", d.lo0Enforced.Load())
		}
		return
	}
	// No drift observed: re-arm the one-shot Warn for the next episode.
	// A successful apply also clears staleness itself; this only resets
	// the log de-dupe so a healed-then-reflushed box warns again.
	if !d.HostInboundApplied().LastApplyFailed && d.hostDriftNoticed15264.Load() {
		d.hostDriftNoticed15264.Store(false)
	}
}

// hostKernelTruthLoop15264 is the always-on low-rate owner started from
// Run beside the other reassert loops. Idle cost is two atomic loads and
// one uncontended applySem round-trip per tick when nothing is established
// (#17861: the recheck serializes with applies for its whole pass).
func (d *Daemon) hostKernelTruthLoop15264(ctx context.Context) {
	interval := hostKernelTruthInterval15264
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			d.recheckHostKernelTruth15264(now)
		}
	}
}
