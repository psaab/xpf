package daemon

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// hostInboundGapReassertInterval paces the retry owner for a double failure
// of the real host-inbound install and its additive gap fence (#11497).
var hostInboundGapReassertInterval = 30 * time.Second

// hostInboundGapReassertFn re-applies the active config. Tests replace it to
// drive the retry without waiting for the production interval or a kernel.
var hostInboundGapReassertFn = func(d *Daemon) error {
	return d.applyActiveConfigResult()
}

// hostInboundGapDebt records the one unresolved host-inbound exposure: both
// the real ruleset install and the additive gap-fence install failed during a
// day-2 apply. The zero value owes nothing.
type hostInboundGapDebt struct {
	mu       sync.Mutex
	owed     bool
	failures uint64
	lastErr  string
}

// noteHostInboundGapApplyResult latches only an actual double nft failure and
// discharges it after a successful full background apply or successful real
// host-inbound installation. Callers must not use this for unrelated errors.
func (d *Daemon) noteHostInboundGapApplyResult(err error) {
	d.hostInboundGapDebt.mu.Lock()
	defer d.hostInboundGapDebt.mu.Unlock()
	if err == nil {
		if d.hostInboundGapDebt.owed {
			slog.Info("host-inbound coverage gap converged; real ruleset covers the active address set",
				"issue", "#11497")
		}
		d.hostInboundGapDebt.owed = false
		d.hostInboundGapDebt.lastErr = ""
		return
	}
	if !d.hostInboundGapDebt.owed {
		slog.Error("host-inbound real install and coverage-gap fence both failed; retry owner will re-apply the active config",
			"err", err, "issue", "#11497")
	}
	d.hostInboundGapDebt.owed = true
	d.hostInboundGapDebt.failures++
	d.hostInboundGapDebt.lastErr = err.Error()
}

// HostInboundGapDebt reports whether the day-2 real+gap failure still needs
// convergence, the number of double failures observed, and the last error.
func (d *Daemon) HostInboundGapDebt() (owed bool, failures uint64, lastErr string) {
	d.hostInboundGapDebt.mu.Lock()
	defer d.hostInboundGapDebt.mu.Unlock()
	return d.hostInboundGapDebt.owed, d.hostInboundGapDebt.failures, d.hostInboundGapDebt.lastErr
}

func (d *Daemon) hostInboundGapOwed() bool {
	d.hostInboundGapDebt.mu.Lock()
	defer d.hostInboundGapDebt.mu.Unlock()
	return d.hostInboundGapDebt.owed
}

// hostInboundGapReassertLoop is the bounded wall-clock convergence owner for
// double failures. It does no work while no debt is owed and is joined by Run's
// daemon WaitGroup on shutdown.
func (d *Daemon) hostInboundGapReassertLoop(ctx context.Context) {
	t := time.NewTicker(hostInboundGapReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertHostInboundGapOnce(ctx)
		}
	}
}

// reassertHostInboundGapOnce re-reads and applies the active config only while
// debt is owed. applyActiveConfigResult takes applySem before reading ActiveConfig
// and honors the normal background-apply shutdown/bootstrap fences. Host-inbound
// apply success discharges the debt; a failure leaves it for the next 30s tick.
func (d *Daemon) reassertHostInboundGapOnce(ctx context.Context) {
	if ctx.Err() != nil || d.store == nil || !d.hostInboundGapOwed() {
		return
	}
	if err := hostInboundGapReassertFn(d); err != nil {
		slog.Warn("host-inbound gap re-assert failed; will retry", "err", err, "issue", "#11497")
	}
}
