package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// syslogStreamRetryInterval paces the #14597 retry owner. 30s matches
// the sibling always-on re-assert loops (proxyARP, RA, fabric, mgmt).
var syslogStreamRetryInterval = 30 * time.Second

// syslogRetryOwed reports whether the last stream-mode syslog build
// skipped at least one stream. It is the cheap gate the retry loop
// reads without applySem.
func (d *Daemon) syslogRetryOwed() bool { return d.syslogRetryDebt.Load() }

func (d *Daemon) setSyslogRetryOwed(owed bool) { d.syslogRetryDebt.Store(owed) }

// syslogStreamRetryLoop is the always-on retry owner for a security-log
// stream skipped at build time (#14597).
//
// The canonical failure is cluster boot ordering: at the boot apply
// (daemon_run.go) the RETH VIP that a stream's source-address names is
// not yet present, DialUDP fails with "cannot assign requested
// address", and the stream is skipped. Before #14597 the #9326
// fingerprint had already latched, so no later apply — and nothing
// else — ever rebuilt it: the audit stream stayed dead until the
// stanza was edited or xpfd restarted. The latch now arms this debt
// instead, and this loop re-drives applySyslogConfig against the
// ACTIVE config until a build completes in full. It is free when
// nothing is owed (one atomic load per tick).
func (d *Daemon) syslogStreamRetryLoop(ctx context.Context) {
	t := time.NewTicker(syslogStreamRetryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertSyslogOnce(ctx)
		}
	}
}

// reassertSyslogOnce re-drives one syslog apply if a stream build is
// owed. It takes applySem before reading the active config (#4001:
// a read outside the semaphore could capture a pre-commit snapshot)
// and re-checks the debt inside, because the commit this tick queued
// behind may already have rebuilt the stream set in full.
func (d *Daemon) reassertSyslogOnce(ctx context.Context) {
	if !d.syslogRetryOwed() && !d.systemSyslogRetryOwed() {
		return
	}
	if d.applySem == nil || d.store == nil {
		return
	}
	if d.syslogRetryOwed() && d.eventReader == nil {
		// Stream debt needs the reader; system debt alone does not.
		if !d.systemSyslogRetryOwed() {
			return
		}
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return
	}
	defer d.applySem.Release(1)
	d.reassertSyslogLocked()
}

// reassertSyslogLocked is the inside-the-semaphore half of the retry
// tick: re-check the debt, then rebuild from the active config.
func (d *Daemon) reassertSyslogLocked() {
	if !d.syslogRetryOwed() && !d.systemSyslogRetryOwed() {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	d.rebuildSyslog(cfg)
}

// rebuildSyslog runs one apply against the daemon's live event reader.
func (d *Daemon) rebuildSyslog(cfg *config.Config) {
	if d.syslogRetryOwed() {
		slog.Debug("syslog stream build incomplete; retrying (#14597)")
		if d.eventReader != nil {
			d.applySyslogConfig(d.eventReader, cfg)
		}
		if !d.syslogRetryOwed() {
			slog.Info("syslog streams recovered; all configured streams now built (#14597)")
		}
	}
	if d.systemSyslogRetryOwed() {
		slog.Debug("system syslog build incomplete; retrying (#15231)")
		d.applySystemSyslog(cfg)
		if !d.systemSyslogRetryOwed() {
			slog.Info("system syslog hosts recovered (#15231)")
		}
	}
}

// reassertSyslogOnceForTest drives one retry against an explicit config
// and reader without needing a store or semaphore, so unit cells can
// exercise the owed → rebuild → discharged contract directly.
func (d *Daemon) reassertSyslogOnceForTest(cfg *config.Config) {
	if d.syslogRetryOwed() && d.eventReader != nil && cfg != nil {
		d.applySyslogConfig(d.eventReader, cfg)
	}
	if d.systemSyslogRetryOwed() && cfg != nil {
		d.applySystemSyslog(cfg)
	}
}
