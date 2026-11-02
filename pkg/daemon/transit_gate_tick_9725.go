package daemon

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// transitGateTickInterval is the maximum time an unobserved kernel XDP-link
// change may leave the gate at its previous state. Event notifications wake an
// earlier recount, but the tick is the correctness source because kernel link
// state can change without any code in this process running (device unregister,
// driver reset, process exit, OOM, SIGKILL, or external cleanup).
var transitGateTickInterval = time.Second

// attachedLinksSource is an optional capability of the published runtime. The
// count is a fresh kernel-truth snapshot, never a writer-maintained claim.
type attachedLinksSource interface {
	AttachedXDPLinkCount() int
}

// attachedLinksNotifier is a wake-only capability. The callback carries no
// count or state; the daemon always calls attachedXDPLinkCount again.
type attachedLinksNotifier interface {
	SetAttachedLinksObserver(func())
}

// helperSupervisorStateSource is implemented by userspace runtimes that own a
// supervised helper. Non-userspace runtimes have no helper and are healthy by
// default.
type helperSupervisorStateSource interface {
	HelperSupervisorState() (running, crashLooping bool)
}

// helperSupervisorNotifier is a wake-only capability. Its callback carries no
// state; the daemon re-reads the supervisor snapshot in the gate loop.
type helperSupervisorNotifier interface {
	SetHelperSupervisorObserver(func())
}

// helperElectionReadinessSource reports that the helper must not hold the RGs
// at full weight: it exited unexpectedly and is not back, or is back but not
// yet armed and healthy (#18697), or is running but wedged (#18685). It must
// not block: the userspace Manager answers it from atomics and a leaf-locked
// tracker, never from m.mu.
type helperElectionReadinessSource interface {
	HelperElectionNotReady() bool
}

func (d *Daemon) ensureTransitGateWake() chan struct{} {
	d.transitGateWakeOnce.Do(func() {
		d.transitGateWake = make(chan struct{}, 1)
	})
	return d.transitGateWake
}

func (d *Daemon) attachedXDPLinks() int {
	if d == nil {
		return 0
	}
	src, ok := d.dataplane().(attachedLinksSource)
	if !ok || src == nil {
		return 0
	}
	count := src.AttachedXDPLinkCount()
	if count < 0 {
		// A malformed capability is uncertainty, not proof of attachment.
		return 0
	}
	return count
}

func (d *Daemon) helperSupervisorState() (running, crashLooping bool) {
	if d == nil {
		return true, false
	}
	src, ok := d.dataplane().(helperSupervisorStateSource)
	if !ok {
		return true, false
	}
	return src.HelperSupervisorState()
}

// helperElectionNotReady reports the #18697/#18685 verdict for the helper. A
// runtime without the method (legacy adapter, test fakes) is never not-ready.
func (d *Daemon) helperElectionNotReady() bool {
	if d == nil {
		return false
	}
	src, ok := d.dataplane().(helperElectionReadinessSource)
	return ok && src.HelperElectionNotReady()
}

func (d *Daemon) transitKernelReady() bool {
	return d != nil && d.dataplaneArmed.Load() && d.attachedXDPLinks() > 0
}

// writeTransitGateLocked drives both transit legs from the ready predicate
// computed by the caller. The caller holds transitGateMu and derives open from
// dataplaneArmed && AttachedXDPLinkCount > 0, additionally requiring a live
// supervisor when the runtime has one. Closing installs the appropriate
// forward fence before writing zero; opening installs the armed fence before
// raising the knobs. The production dataplane lease holds its XDP ownership
// lock across both operations, so a detach cannot invalidate the allowlist
// between them.
func (d *Daemon) writeTransitGateLocked(stage string, open bool) bool {
	if open {
		if err := d.openTransitGateLocked(); err != nil {
			// An armed fence may already be live from a previous reassert.
			// Restore the unconditional barrier before dropping the sysctls,
			// otherwise bridge forwarding could continue through stale rules.
			if barrierErr := d.applyTransitBarrier(false); barrierErr != nil {
				slog.Error("armed transit fence failed and unconditional barrier "+
					"restore also failed; keeping kernel transit forwarding disabled",
					"stage", stage, "err", err, "barrier_err", barrierErr)
			}
			writeTransitForwardSysctls(false)
			slog.Error("armed transit fence install failed; keeping kernel transit forwarding disabled",
				"stage", stage, "err", err)
			return false
		}
		slog.Debug("transit gate re-evaluated open", "stage", stage)
		return true
	}
	// Always install the unconditional barrier while the gate is closed.
	// ip_forward=0 does not govern bridge forwarding, and an armed XDP-link
	// count can change independently of the fence's name snapshot.
	_ = d.applyTransitBarrier(false)
	writeTransitForwardSysctls(false)
	slog.Debug("transit gate re-evaluated closed", "stage", stage)
	return false
}

// reassertTransitGate is the one authoritative actuation path for both the
// supervisor/link wake and periodic tick. Under transitGateMu it snapshots
// kernel attachment and helper state, closes transit unless both are healthy,
// preserves the separate kernel-arm debt, and applies full election debt only
// while a restart-pending helper has reached its crash-loop cap.
func (d *Daemon) reassertTransitGate(stage string) {
	if d == nil || !d.shouldManageTransitGate() {
		return
	}
	d.transitGateMu.Lock()
	defer d.transitGateMu.Unlock()
	kernelReady := d.transitKernelReady()
	helperRunning, crashLooping := d.helperSupervisorState()
	// #18697/#18685: a helper that died unexpectedly, is back but not yet
	// forwarding-ready and healthy, or is running but wedged forwards nothing.
	// It must not hold the RGs at full weight, so it counts as not ready for
	// ELECTION DEBT (arm debt yields the data RGs to a healthy peer, #12164; RG0
	// stays). The kernel transit gate itself is unchanged. Read after the lock-
	// free helperSupervisorState snapshot so the verdict is as fresh as possible.
	notReady := d.helperElectionNotReady()
	opened := d.writeTransitGateLocked(stage, kernelReady && helperRunning)
	// F2: a dead helper must not WIPE unrelated arm debt (a fence/kernel
	// failure predating the death must survive it: the old
	// `(!helperRunning || opened)` disjunct reported dataplaneReady=true
	// whenever the helper was down, flipping a fenced 1 → 255, fail-open).
	// F2 also used to say a dead helper must not INSTALL debt, on the premise
	// that "a short restart is not a kernel failure — weight stays 255". On
	// tcp (#18697) a single post-kill restart took 227 s with node0 primary
	// and transit dead, and even a fast one is seconds of dead transit while
	// the peer holds the synced sessions. So since #18697 an UNEXPECTED exit
	// installs arm debt, and it is held until the next helper is armed and
	// healthy; only an intentional stop or respawn keeps the pass-through.
	// Persistent loops carry their own full election debt via crashLooping.
	// F2, narrowed by #18697: only an INTENTIONAL stop or respawn (the helper
	// is down, not looping, and did not exit unexpectedly) leaves the arm bit
	// exactly as it is. An unexpected exit falls through and installs debt.
	if !helperRunning && !crashLooping && !notReady {
		d.applyTransitElectionDebtKeepArm(false, false, true)
	} else {
		// Helper running (or looping): dataplaneReady follows whether the
		// gate actually OPENED. A fence-install failure with the helper up
		// reports not-ready (arm debt at weight 1); only a live opened
		// gate reports ready.
		d.applyTransitElectionDebt(kernelReady && opened && !notReady, crashLooping)
	}
}

// closeTransitUntilAttached establishes the boot fence without changing the
// dataplane arm bit or redundancy-group arm tracking. A successful Start still
// leaves this fence in place until a fresh kernel count proves an XDP link.
func (d *Daemon) closeTransitUntilAttached(stage string) {
	if d == nil || !d.shouldManageTransitGate() {
		return
	}
	d.transitGateMu.Lock()
	defer d.transitGateMu.Unlock()
	_ = d.applyTransitBarrier(false)
	writeTransitForwardSysctls(false)
	slog.Info("transit gate closed until a live XDP link is proven", "stage", stage)
}

func (d *Daemon) registerAttachedLinksObserver() {
	if d == nil {
		return
	}
	if src, ok := d.dataplane().(attachedLinksNotifier); ok {
		src.SetAttachedLinksObserver(d.signalTransitGateWake)
	}
}

func (d *Daemon) clearAttachedLinksObserver() {
	if d == nil {
		return
	}
	if src, ok := d.dataplane().(attachedLinksNotifier); ok {
		src.SetAttachedLinksObserver(nil)
	}
}

func (d *Daemon) registerHelperSupervisorObserver() {
	if d == nil {
		return
	}
	if src, ok := d.dataplane().(helperSupervisorNotifier); ok {
		src.SetHelperSupervisorObserver(d.signalTransitGateWake)
	}
}

func (d *Daemon) clearHelperSupervisorObserver() {
	if d == nil {
		return
	}
	if src, ok := d.dataplane().(helperSupervisorNotifier); ok {
		src.SetHelperSupervisorObserver(nil)
	}
}

// signalTransitGateWake is deliberately non-blocking and state-free. A burst
// of writer notifications coalesces into one recount; the ticker handles every
// missed notification and therefore keeps correctness independent of writer
// enumeration.
func (d *Daemon) signalTransitGateWake() {
	if d == nil {
		return
	}
	wake := d.ensureTransitGateWake()
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (d *Daemon) startTransitGateLoop(ctx context.Context, wg *sync.WaitGroup) {
	if d == nil || ctx == nil || wg == nil {
		return
	}
	wake := d.ensureTransitGateWake()
	interval := transitGateTickInterval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer ticker.Stop()
		// Re-evaluate once immediately so a runtime that attached during startup
		// is not delayed behind a full interval.
		d.reassertTransitGate("tick-start")
		for {
			select {
			case <-ctx.Done():
				return
			case <-wake:
				d.reassertTransitGate("xdp-link-event")
			case <-ticker.C:
				d.reassertTransitGate("xdp-link-tick")
			}
		}
	}()
}
