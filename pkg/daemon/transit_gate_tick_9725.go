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

func (d *Daemon) transitOpen() bool {
	return d != nil && d.dataplaneArmed.Load() && d.attachedXDPLinks() > 0
}

// writeTransitGateLocked drives both transit legs from the single ready
// predicate computed by the caller. The caller holds transitGateMu and must
// derive open from dataplaneArmed && AttachedXDPLinkCount > 0. Closing
// installs the appropriate forward fence before writing zero; opening installs
// the armed fence before raising the knobs. The production dataplane lease
// holds its XDP ownership lock across both operations, so a detach cannot
// invalidate the allowlist between them.
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
// event wake and the periodic tick. It reads kernel truth once under
// transitGateMu, then drives the transit gate and RG weight from that same
// ready-to-serve verdict.
func (d *Daemon) reassertTransitGate(stage string) {
	if d == nil || !d.shouldManageTransitGate() {
		return
	}
	d.transitGateMu.Lock()
	defer d.transitGateMu.Unlock()
	ready := d.dataplaneArmed.Load() && d.attachedXDPLinks() > 0
	opened := d.writeTransitGateLocked(stage, ready)
	d.applyDataplaneReadyTrack(opened)
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
