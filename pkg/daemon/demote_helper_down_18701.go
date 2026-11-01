package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// helperDownDemotionBound caps how long a demotion waits for the helper-side
// rg_active=false write when this node's helper is not answering (#18701).
// The write is best-effort there: the VIPs are already released, and a
// wedged helper forwards nothing. One second is a third of the control
// deadline a silent round trip burns, and well above the healthy round trip
// measured under load (≤ 30 ms, #18685).
var helperDownDemotionBound = time.Second

// setRGActiveBounded runs SetRGActive but stops waiting after bound. The
// controller does not honour ctx past its entry check (UpdateRGActive holds
// m.mu across a control round trip), so the call runs on its own goroutine
// and is abandoned, not cancelled, on timeout. It finishes in the background
// and its outcome is dropped; the caller treats the timeout as a failed apply,
// which the reconcile loop retries. Abandoning it is safe because the write is
// idempotent and every later rg_active write serialises behind it on m.mu.
func setRGActiveBounded(ctx context.Context, ha dataplane.HAController, rgID int, active bool, bound time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- ha.SetRGActive(ctx, rgID, active) }()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return fmt.Errorf("rg_active=%v for redundancy group %d not acknowledged within %s by an unresponsive helper (#18701)", active, rgID, bound)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// releaseDirectVIPsHelperDown runs the direct-VIP reconcile for every RG of the
// cluster. Each reconcile keys on that RG's own local state
// (shouldOwnDirectVIPs), so it removes the VIPs, re-announce, and RA/DHCP
// services only of RGs this node no longer owns, and leaves an owned RG's
// VIPs in place. Used when the local helper is not answering, so that no RG's
// VIP release waits behind another RG's helper round trips (#18701).
func (d *Daemon) releaseDirectVIPsHelperDown(reason string) {
	if d.cluster == nil {
		return
	}
	for _, rg := range d.cluster.GroupStates() {
		d.reconcileDirectVIPOwnership(rg.GroupID, reason)
	}
}

// helperElectionReasonSource is the optional surface that explains the
// #18697/#18685 verdict, for the #18701 demotion log line.
type helperElectionReasonSource interface {
	HelperElectionReason() string
}

func (d *Daemon) helperElectionReason() string {
	if src, ok := d.dataplane().(helperElectionReasonSource); ok {
		return src.HelperElectionReason()
	}
	return ""
}

// helperControlSource reports that the helper's control socket is not
// answering: no helper running after an unexpected exit, or the silence
// verdict. A frozen worker with an answering control thread is NOT this.
type helperControlSource interface {
	HelperControlUnresponsive() bool
}

func (d *Daemon) helperControlUnresponsive() bool {
	if src, ok := d.dataplane().(helperControlSource); ok {
		return src.HelperControlUnresponsive()
	}
	return true // without the surface, keep the conservative skip
}
