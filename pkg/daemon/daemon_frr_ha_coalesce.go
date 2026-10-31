package daemon

// FRR HA reconcile coalescing (#18561).
//
// Every RG ownership edge used to start its own goroutine that took applySem
// across a full frr-reload.py (300-600 ms). When the election promotes several
// RGs at once (a crash takeover), the cluster-event goroutine activates them
// one after another and each promotion first runs republishConnectedRGSync
// under the same applySem (#16270). On the loss cluster the LAN RG's
// activation queued behind two reloads and came 0.62 s after the WAN RG's.
//
// The reconcile is now coalesced. The first edge arms one timer; edges that
// arrive while it is armed join it; the timer runs ONE reconcile, which reads
// the active config and cluster state at run time, so it covers every joined
// edge. An edge that arrives after the timer fired (including while that
// reconcile runs) arms a new one, so no edge is lost. The helper FIB does not
// depend on FRR for transit forwarding (the connected-RG republish is
// synchronous on the activation path), so the delay only moves the kernel and
// routing-protocol view by the debounce.

import (
	"sync"
	"time"
)

// frrHAReconcileDebounce is how long the first edge of a burst waits for the
// rest. Longer than an election burst (three RG events land within ~10 ms)
// plus the per-RG activations (~50 ms each), short against routing-protocol
// timers.
const frrHAReconcileDebounce = 250 * time.Millisecond

type frrHACoalescer struct {
	mu      sync.Mutex
	pending bool
	// afterFunc is the timer seam; nil means time.AfterFunc.
	afterFunc func(time.Duration, func())
}

// schedule arms run after delay unless a run is already pending, in which
// case this edge joins it. It never blocks.
func (c *frrHACoalescer) schedule(delay time.Duration, run func()) {
	c.mu.Lock()
	if c.pending {
		c.mu.Unlock()
		return
	}
	c.pending = true
	after := c.afterFunc
	c.mu.Unlock()
	if after == nil {
		after = func(d time.Duration, f func()) { time.AfterFunc(d, f) }
	}
	after(delay, func() {
		// Clear BEFORE running: an edge that lands during the reconcile must
		// arm its own, because this run may already have read the config.
		c.mu.Lock()
		c.pending = false
		c.mu.Unlock()
		run()
	})
}
