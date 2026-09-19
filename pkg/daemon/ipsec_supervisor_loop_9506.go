package daemon

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// r6 §3.5/T12 bounds quarantine and terminal-reconciliation maintenance. The
// loop is joined through the caller's shutdown WaitGroup; no detached ticker can
// outlive the daemon or hold a queue generation after cancellation.
var ipsecSupervisorTickInterval = 5 * time.Millisecond

func (d *Daemon) startIpsecSupervisorLoop(ctx context.Context, wg *sync.WaitGroup) {
	if d == nil || ctx == nil || wg == nil {
		return
	}
	if d.ipsecS4 == nil {
		d.ipsecS4 = newIpsecSupervisor()
	}
	s := d.ipsecS4
	d.startIpsecTopologyLinkWatch(ctx, wg)
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(ipsecSupervisorTickInterval)
		defer t.Stop()
		census := time.NewTicker(ipsecTopologyPollInterval)
		defer census.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-census.C:
				d.pollIpsecTopology()
			case now := <-t.C:
				s.supervisorTickOnce(now)
				if err := d.reconcileIpsecCaptureAuthority(); err != nil {
					slog.Debug("ipsec capture authority announce deferred", "err", err)
				}
				d.reconcileIpsecHostInputFence(ctx)
			}
		}
	}()
}
