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
