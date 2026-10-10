package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/upgrade"
)

// kernelSRCluster adapts *cluster.Manager to upgrade.SelfRecoveryCluster for the
// #1930 INC-2 kernel-channel bounded local self-recovery.
type kernelSRCluster struct{ m *cluster.Manager }

func (a kernelSRCluster) LocalDrained() (bool, error)       { return a.m.LocalDrained(), nil }
func (a kernelSRCluster) PeerHealthyPrimary() (bool, error) { return a.m.PeerHealthyPrimary(), nil }
func (a kernelSRCluster) ResetFailover() error              { return a.m.ResetAllFailover() }

// newKernelRunner builds the KernelRunner used to read the kernel-upgrade
// journal (IsArmed). Production path constructs it over the real /var/lib/xpf
// journal + system surface; tests inject kernelRunnerFn to point it at a temp
// journal (#5682 election-hold fail-closed coverage).
func (d *Daemon) newKernelRunner() (*upgrade.KernelRunner, error) {
	if d.kernelRunnerFn != nil {
		return d.kernelRunnerFn()
	}
	return upgrade.NewKernelRunner(upgrade.KernelConfig{Sys: daemonKernelSystem()})
}

// newKernelSystem builds the KernelSystem used by the hold-reconcile promotion
// check (RunningKernel / ReadPromotionMarker). Test seam: kernelSystemFn.
func (d *Daemon) newKernelSystem() upgrade.KernelSystem {
	if d.kernelSystemFn != nil {
		return d.kernelSystemFn()
	}
	return daemonKernelSystem()
}

// runningKernelMatchesCandidate is the discriminator between a candidate trial
// and a known-good fallback boot that still has an ARMED journal. If the running
// kernel cannot be established, callers fail closed and keep the election hold.
func (d *Daemon) runningKernelMatchesCandidate(candidate string) (bool, error) {
	if candidate == "" {
		return false, fmt.Errorf("armed kernel journal has empty candidate version")
	}
	running, err := d.newKernelSystem().RunningKernel()
	if err != nil {
		return false, fmt.Errorf("read running kernel: %w", err)
	}
	return running == candidate, nil
}

// holdSecondaryIfKernelCandidateArmed keeps a CANDIDATE-TRIAL boot SECONDARY
// until the promotion gate verifies the dataplane (r2 AGY Critical). The drain
// the orchestrator set is in-memory ManualFailover, lost across the reboot, so a
// candidate node boots election-eligible and — under preempt, OR via the
// isolated-node auto-promote path if it can't see the peer — could claim primary
// BEFORE xpf-kernel-promote.service runs verify-dataplane + the forward beacon.
// A verifier-rejected candidate claiming primary would blackhole cluster traffic.
//
// Set the unconditional kernelUpgradeHold before cluster.UpdateConfig (which
// itself runs the first election) so there is no election window. The hold
// cannot auto-clear for an isolated node. Reconciliation releases it only after
// the promotion marker verifies the running candidate; ResetAllFailover also
// clears it on rejoin. An ARMED journal on a running known-good fallback is not
// a candidate trial and must not acquire the hold, or the gate's discard path
// would leave a healthy node ineligible.
//
// No-op on an ordinary boot.
func (d *Daemon) holdSecondaryIfKernelCandidateArmed() {
	if d.cluster == nil {
		return
	}
	r, err := d.newKernelRunner()
	if err != nil {
		return
	}
	armed, j, err := r.IsArmed()
	if err != nil {
		// #5682 (codex-review-182 M24): the journal is UNREADABLE — an I/O error,
		// corruption, or parse failure. IsArmed/loadKernelJournal already fold a
		// clean ENOENT ("never armed") to not-armed with a nil error, so reaching
		// this branch means the journal EXISTS but cannot be read/parsed. That is
		// a failure mode which itself CORRELATES with a bad upgrade (a candidate
		// kernel that corrupted /var/lib/xpf, a half-written journal from a crash
		// mid-roll). Treating the unknown state as "not armed" and proceeding to a
		// normal election would let this node elect/promote as if no upgrade were
		// pending — bypassing the candidate-election hold and the promote/rollback
		// safety of the #1930 A/B kernel channel. Fail CLOSED: hold SECONDARY
		// exactly as a definitively-armed candidate would. reconcileKernelUpgradeHold
		// self-heals this hold on a later successful read (see below), so a
		// transient read error does not strand the node SECONDARY forever.
		// #6495: hold with the reason that is actually TRUE here. This node
		// does NOT know a candidate is armed — that is the whole point of the
		// fail-closed branch — so it must not tell the operator it is waiting
		// on a promotion marker that may never be written.
		d.cluster.SetKernelUpgradeHold(cluster.KernelUpgradeHoldUnreadableJournal)
		d.kernelUpgradeHoldFailClosed = true
		slog.Warn("kernel-upgrade journal unreadable, holding election fail-closed "+
			"(SECONDARY) until the state can be re-read", "err", err)
		return
	}
	if !armed {
		return
	}
	candidateRunning, err := d.runningKernelMatchesCandidate(j.CandidateVersion)
	if err != nil {
		// We cannot prove this is the known-good fallback, so fail closed and
		// preserve candidate-trial protection.
		d.cluster.SetKernelUpgradeHold(cluster.KernelUpgradeHoldCandidate)
		d.kernelUpgradeHoldFailClosed = false
		slog.Warn("kernel-upgrade journal is ARMED but running kernel is unknown; "+
			"holding SECONDARY fail-closed", "candidate", j.CandidateVersion, "err", err)
		return
	}
	if !candidateRunning {
		slog.Info("kernel-upgrade journal is ARMED but running kernel is not the candidate; "+
			"skipping candidate election hold", "candidate", j.CandidateVersion)
		return
	}
	d.cluster.SetKernelUpgradeHold(cluster.KernelUpgradeHoldCandidate)
	d.kernelUpgradeHoldFailClosed = false
	slog.Info("kernel-candidate boot: holding SECONDARY (election hold) until promotion "+
		"verifies the dataplane", "candidate", j.CandidateVersion)
}

// reconcileKernelUpgradeHold releases the election hold ONLY when the candidate
// has been affirmatively VERIFIED+PROMOTED. The promotion gate runs in a
// SEPARATE process (xpf-kernel-promote.service, After=xpfd) that clears only the
// on-disk journal, so the running daemon — which set the in-memory hold at boot
// — must notice the promotion and release the hold itself; otherwise a
// successfully promoted candidate would stay SECONDARY forever (a leaked hold).
//
// The release predicate is "the durable promotion marker names the CURRENTLY
// RUNNING kernel", NOT merely "no longer armed". A bare not-armed test is unsafe
// on the REVERT path: revert() clears the journal and THEN reboots, leaving a
// window where the journal is gone (not armed) but the broken candidate kernel
// is still running and shutting down. Clearing the hold there would let the
// unverified candidate transiently claim primary for the seconds before the
// reboot completes (r2 AGY Finding 2, HIGH). The marker is written only on
// PROMOTE (for the running kernel), so:
//   - promoted same-boot: marker == running -> release (correct).
//   - reverted: marker does NOT name the candidate -> keep holding; the node
//     reboots to known-good, where a fresh daemon never sets the hold (journal
//     cleared, IsArmed false) -> the hold is gone by construction.
//   - still verifying: marker not yet written -> keep holding.
//
// EXCEPTION (#5682): a FAIL-CLOSED hold — one set because the journal was
// UNREADABLE at boot rather than affirmatively ARMED — ALSO self-heals here. It
// has no promotion marker to wait on when the underlying cause was a transient
// I/O blip with no upgrade pending, so it would otherwise strand the node
// SECONDARY forever. On each tick it re-reads the journal: still unreadable ->
// keep holding; now armed -> convert to a normal armed hold (the marker gate
// governs); now cleanly not-armed -> release (the read error was transient). The
// strict marker-only release is preserved for a genuinely-armed hold so the
// revert window can't transiently promote an unverified candidate.
//
// No-op unless the hold is set.
func (d *Daemon) reconcileKernelUpgradeHold() {
	if d.cluster == nil || !d.cluster.KernelUpgradeHeld() {
		// The hold is gone (or never set), possibly cleared by another path
		// (rejoin / manual reset). Drop our local fail-closed bookkeeping so a
		// future hold starts clean.
		d.kernelUpgradeHoldFailClosed = false
		return
	}

	// #5682 self-heal for a FAIL-CLOSED hold (unreadable journal at boot). Unlike
	// a definitively-armed hold — which is released ONLY by the durable promotion
	// marker below, so the revert window can't transiently promote an unverified
	// candidate — a fail-closed hold was set from an AMBIGUOUS read, and the
	// promotion marker will never appear when the underlying cause was a transient
	// I/O blip with no upgrade in progress. Re-read the journal:
	//   - still unreadable        -> keep holding (nothing changed).
	//   - now readable & ARMED    -> check the running kernel; convert to an
	//                                ordinary armed hold only if it matches the
	//                                candidate, else release on known-good.
	//                                Keep fail-closed if the kernel is unreadable.
	//   - now readable & NOT armed-> the boot-time error was transient and there is
	//                                no upgrade pending: release the hold so the
	//                                node is not stranded SECONDARY forever.
	if d.kernelUpgradeHoldFailClosed {
		r, err := d.newKernelRunner()
		if err != nil {
			return // cannot construct a reader; keep holding fail-closed
		}
		armed, j, ierr := r.IsArmed()
		switch {
		case ierr != nil:
			return // journal still unreadable; keep holding fail-closed
		case armed:
			candidateRunning, err := d.runningKernelMatchesCandidate(j.CandidateVersion)
			if err != nil {
				return // cannot prove this is a known-good fallback; keep holding
			}
			if !candidateRunning {
				// The journal is readable and ARMED, but this is a known-good
				// fallback boot. The gate will discard the candidate; retaining
				// either hold would strand an otherwise healthy node.
				d.kernelUpgradeHoldFailClosed = false
				d.cluster.ClearKernelUpgradeHold()
				slog.Info("kernel-upgrade journal is ARMED but running kernel is not the candidate; "+
					"releasing fail-closed election hold", "candidate", j.CandidateVersion)
				return
			}
			// A genuine candidate is armed after all — this is now an ordinary
			// armed hold; the promotion-marker gate below governs its release.
			d.kernelUpgradeHoldFailClosed = false
			// #6495: the RENDERED reason must follow the state across this
			// transition. Without this the status keeps saying "journal
			// unreadable" on a node whose journal is now readable and whose
			// hold is now an ordinary candidate hold — sending the operator to
			// fix a filesystem that is fine. Re-setting is idempotent: the flag
			// is already true and no group is primary to demote.
			d.cluster.SetKernelUpgradeHold(cluster.KernelUpgradeHoldCandidate)
		default:
			// Definitively not armed on a clean read: the boot-time read failure
			// was transient and no kernel upgrade is pending. Release the hold.
			d.kernelUpgradeHoldFailClosed = false
			d.cluster.ClearKernelUpgradeHold()
			slog.Warn("kernel-upgrade journal now readable and NOT armed; releasing the " +
				"fail-closed SECONDARY election hold (transient read error self-healed)")
			return
		}
	}

	sys := d.newKernelSystem()
	running, err := sys.RunningKernel()
	if err != nil {
		return
	}
	promoted, err := sys.ReadPromotionMarker()
	if err != nil || promoted == "" || promoted != running {
		// Not yet a confirmed promotion of THIS running kernel — keep holding.
		// Covers: still verifying; reverted-pending-reboot; and the marker-write
		// failure on an OTHERWISE-successful promote. The last case leaves the
		// node SECONDARY on a GOOD kernel — accepted: a marker write failure
		// means /var/lib/xpf is unwritable (the same catastrophe that breaks the
		// journal), and the SAFE outcome there is the peer keeping primary while
		// the orchestrator (which also reads the marker and would see
		// promoted=none) stops the roll for operator recovery. Failing toward
		// "secondary, peer serves" beats releasing a possibly-unverified node.
		return
	}
	d.cluster.ClearKernelUpgradeHold()
	slog.Info("kernel-candidate PROMOTED (promotion marker matches running kernel); "+
		"releasing the SECONDARY election hold so the node takes its normal role",
		"kernel", running)
}

// startKernelSelfRecovery runs the bounded local self-recovery loop for the
// LANE-1 HA kernel channel (#1930 INC-2). If the external orchestrator crashes
// while this node is drained+rebooting for a kernel roll, the node would come
// back up drained with nothing to ResetFailover it. This loop notices that
// orphaned-drained state (no active roll lease naming us + a healthy primary
// peer) and auto-rejoins after a grace period. It is a no-op on a node that is
// not drained — i.e. virtually always.
//
// The loop is HA-only (started only when a cluster manager exists) and ticks
// slowly (it is a safety net, not a hot path).
func (d *Daemon) startKernelSelfRecovery(ctx context.Context) {
	if d.cluster == nil {
		return
	}
	sr := upgrade.NewKernelSelfRecovery(upgrade.SelfRecoveryConfig{
		NodeID: d.cluster.NodeID(),
		Logf:   func(f string, a ...any) { slog.Info("kernel-self-recovery", "msg", fmt.Sprintf(f, a...)) },
		// Refuse self-recovery while a candidate trial is still ARMED — even if
		// the orchestrator lease expired (r2 AGY long-hanging-roll TTL split-brain).
		Armed: func() (bool, error) {
			r, err := upgrade.NewKernelRunner(upgrade.KernelConfig{Sys: daemonKernelSystem()})
			if err != nil {
				return false, err
			}
			armed, _, err := r.IsArmed()
			return armed, err
		},
	}, kernelSRCluster{m: d.cluster})

	go func() {
		// Reconcile the in-memory election hold against the journal on a SHORT
		// cadence from the start: the promotion gate (a separate process) can
		// resolve within ~120s of boot, and we want the verified candidate to
		// drop its hold and resume its role promptly (fast failback), not wait
		// out the self-recovery settle. Cheap (a journal read; an election only
		// on the resolving tick).
		holdTick := time.NewTicker(5 * time.Second)
		defer holdTick.Stop()

		// Initial settle so a normal boot→election→rejoin completes before the
		// first self-recovery evaluation (the grace inside Tick adds further
		// hysteresis). The hold reconcile runs throughout this window.
		settle := time.NewTimer(30 * time.Second)
		defer settle.Stop()
		settled := false

		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-holdTick.C:
				d.reconcileKernelUpgradeHold()
			case <-settle.C:
				settled = true
			case <-tick.C:
				if !settled {
					continue // not past the initial settle yet
				}
				if did, err := sr.Tick(); err != nil {
					slog.Debug("kernel-self-recovery tick error", "err", err)
				} else if did {
					slog.Warn("kernel-self-recovery: auto-rejoined an orphaned-drained node " +
						"(external kernel-roll orchestrator appears to have crashed mid-roll)")
				}
			}
		}
	}()
}
