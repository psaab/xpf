package daemon

import (
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// archiveTimerState groups the #4078 periodic configuration-archival timer
// supervision state, extracted from the Daemon god-struct as increment 3 of
// the #4407 decomposition (pure field grouping — no behavior/locking change).
// It is co-located with the reconcile/run/stop lifecycle that owns it and is
// reached as d.archiveTimer.<field>; naming the sub-field (rather than an
// embed) also avoids the prior collision between the old archiveTimerKey field
// and the package-level archiveTimerKey(interval, sites) helper.
type archiveTimerState struct {
	// mu guards key + stop.
	mu sync.Mutex
	// key is the (interval|sites) hash the running periodic-archival timer was
	// armed for; "" ⇒ no timer running. reconcileArchiveTimer compares against
	// it so an unrelated commit never bounces a healthy timer.
	key string
	// stop is closed to stop the running periodic-archival goroutine
	// (reschedule on a transfer-interval/site change, or shutdown). nil ⇒ none.
	stop chan struct{}
	// newTicker builds the periodic-archival tick channel + a stop func. nil ⇒
	// realArchiveTicker (a wall-clock time.Ticker). Overridable so tests drive
	// the periodic archive deterministically without a wall-clock wait and
	// assert it reuses the archiveToSites transport (#4078).
	newTicker func(d time.Duration) (<-chan time.Time, func())
}

// realArchiveTicker is the default archiveTimer.newTicker seam: a wall-clock
// time.Ticker firing every d. Tests override d.archiveTimer.newTicker to drive
// the periodic archive deterministically without a wall-clock wait (#4078).
func realArchiveTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// clampArchiveIntervalMinutes converts a config-derived `system archival
// transfer-interval` (minutes) into a POSITIVE, overflow-safe time.Duration
// for time.NewTicker. transfer-interval is bounded to 1..2880 at commit by the
// schema (ValidateInteger), so a normal commit never reaches the panic — but a
// crafted on-disk Store.Load / peer-sync config bypasses that strict bound
// (the #5723 lenient ingress). The raw-int `interval <= 0` guard in
// reconcileArchiveTimer inspects the MINUTES integer, not the
// `× time.Minute` product, so a value above config.MaxDurationMinutes
// (~1.5e8 min) overflows int64 nanoseconds to a non-positive Duration and
// time.NewTicker PANICS, crashing xpfd. Clamping the minutes to
// [1, MaxDurationMinutes] before the multiply keeps the product positive and
// bounded — defense-in-depth mirroring clampRPMIntervalSeconds (#5723) /
// clampKeepaliveIntervalSec (#5705), minutes-scoped (#5784). This is the
// straggler of the #5705/#5723 config-interval × time.Unit overflow class.
func clampArchiveIntervalMinutes(min int) time.Duration {
	if min < 1 {
		return time.Minute
	}
	if int64(min) > config.MaxDurationMinutes {
		return time.Duration(config.MaxDurationMinutes) * time.Minute
	}
	return time.Duration(min) * time.Minute
}

// archiveTimerKey collapses (interval, sites) into a stable string so
// reconcileArchiveTimer can hash-gate: an unrelated commit that leaves the
// periodic-archival config untouched must NOT bounce a healthy timer. An empty
// key means "no periodic archival" (interval <= 0 or no sites).
func archiveTimerKey(interval int, sites []string) string {
	if interval <= 0 || len(sites) == 0 {
		return ""
	}
	return strconv.Itoa(interval) + "|" + strings.Join(sites, "\x00")
}

// reconcileArchiveTimer starts, reschedules, or stops the periodic
// configuration-archival timer (#4078). Junos `system archival configuration
// transfer-interval <minutes>` archives the running config to the configured
// archive-sites every N minutes, independent of transfer-on-commit — a
// periodic off-box backup for a config that rarely changes but should still be
// backed up. Before this the leaf was parsed and compiled
// (config.ArchivalConfig.TransferInterval) but no runtime consumer existed, so
// the timed archive never fired.
//
// Lifecycle (mirrors reconcileRPM / reconcileFlowExporters): called from
// applyConfigLocked on every commit/boot apply. Hash-gated on (interval, sites)
// so an unrelated commit leaves a running timer alone; a change to the interval
// or the site set stops the old goroutine and starts a fresh one; removing the
// leaf (or dropping to 0 / no sites) stops it. Re-armed on daemon restart
// because the boot apply runs this same reconcile against the active config.
func (d *Daemon) reconcileArchiveTimer(cfg *config.Config) {
	interval := 0
	var sites []string
	if cfg != nil && cfg.System.Archival != nil {
		interval = cfg.System.Archival.TransferInterval
		sites = cfg.System.Archival.ArchiveSites
	}
	// Periodic archival needs a positive interval AND at least one site;
	// otherwise there is nothing to schedule.
	if interval <= 0 || len(sites) == 0 {
		interval, sites = 0, nil
	}
	key := archiveTimerKey(interval, sites)

	d.archiveTimer.mu.Lock()
	defer d.archiveTimer.mu.Unlock()
	if key == d.archiveTimer.key {
		return // unchanged — do not bounce a healthy timer
	}
	// Stop the currently-running timer (if any) before (re)scheduling.
	if d.archiveTimer.stop != nil {
		close(d.archiveTimer.stop)
		d.archiveTimer.stop = nil
	}
	d.archiveTimer.key = key
	if interval <= 0 {
		slog.Info("periodic config archival disabled")
		return
	}
	stop := make(chan struct{})
	d.archiveTimer.stop = stop
	sitesCopy := append([]string(nil), sites...)
	go d.runArchiveTimer(interval, sitesCopy, stop)
	slog.Info("periodic config archival scheduled",
		"interval_minutes", interval, "sites", len(sitesCopy))
}

// runArchiveTimer fires every `interval` minutes and archives the CURRENT
// active config to `sites` via the shared archiveToSites path (the same
// transport transfer-on-commit uses — the periodic archive always reflects the
// latest committed config, no daemon restart required). Exits when its
// per-generation stop channel is closed (reschedule/removal via
// reconcileArchiveTimer) or the daemon-stop context is cancelled. #4078.
func (d *Daemon) runArchiveTimer(interval int, sites []string, stop <-chan struct{}) {
	newTicker := d.archiveTimer.newTicker
	if newTicker == nil {
		newTicker = realArchiveTicker
	}
	tickC, tickStop := newTicker(clampArchiveIntervalMinutes(interval))
	defer tickStop()

	// Secondary shutdown guard: the daemon-stop context (nil at early boot, in
	// which case stopArchiveTimer in the teardown sequence is the authoritative
	// stop). A nil channel blocks forever in select — harmless.
	var ctxDone <-chan struct{}
	if d.applyCancelContext != nil {
		ctxDone = d.applyCancelContext.Done()
	}
	for {
		select {
		case <-stop:
			return
		case <-ctxDone:
			return
		case <-tickC:
			// Periodic attempts share archiveToSites with commit archiving;
			// each tick therefore retries pending current-config site debt and
			// clears only sites whose transfer completes successfully.
			d.archiveToSites(sites)
		}
	}
}

// stopArchiveTimer stops the periodic archival timer at daemon shutdown. Safe
// to call when no timer is running. #4078.
func (d *Daemon) stopArchiveTimer() {
	d.archiveTimer.mu.Lock()
	defer d.archiveTimer.mu.Unlock()
	if d.archiveTimer.stop != nil {
		close(d.archiveTimer.stop)
		d.archiveTimer.stop = nil
	}
	d.archiveTimer.key = ""
}
