package daemon

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// remoteArchiveDebt retains only the sites still owed a copy of the current
// config. Starting a newer attempt replaces the prior site's debt; results
// from older asynchronous uploads cannot discharge or re-arm the newer copy.
type remoteArchiveDebt struct {
	mu         sync.Mutex
	generation uint64
	pending    map[string]struct{}
	failures   uint64
}

func (d *remoteArchiveDebt) begin(sites []string) uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.generation++
	d.pending = make(map[string]struct{}, len(sites))
	for _, site := range sites {
		d.pending[site] = struct{}{}
	}
	return d.generation
}

func (d *remoteArchiveDebt) record(generation uint64, site string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.failures++
	}
	if generation != d.generation {
		return
	}
	if err == nil {
		delete(d.pending, site)
		return
	}
	d.pending[site] = struct{}{}
}

// retain drops debt for sites no longer configured while preserving outstanding
// obligations for sites that remain. Unchanged membership keeps the generation
// stable so an in-flight success can still discharge its debt.
func (d *remoteArchiveDebt) retain(sites []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.pending) == 0 {
		return
	}
	if len(sites) == 0 {
		d.pending = nil
		d.generation++
		return
	}
	keep := make(map[string]struct{}, len(sites))
	for _, site := range sites {
		keep[site] = struct{}{}
	}
	changed := false
	for site := range d.pending {
		if _, configured := keep[site]; !configured {
			delete(d.pending, site)
			changed = true
		}
	}
	if changed {
		d.generation++
	}
}

func (d *remoteArchiveDebt) sites() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.pending) == 0 {
		return nil
	}
	sites := make([]string, 0, len(d.pending))
	for site := range d.pending {
		sites = append(sites, site)
	}
	sort.Strings(sites)
	return sites
}

var remoteArchiveDebtReassertInterval = 30 * time.Second

// remoteArchiveDebtReassertLoop retries transfer-on-commit-only failures; the
// periodic timer remains an additional retry opportunity, not the debt owner.
func (d *Daemon) remoteArchiveDebtReassertLoop(ctx context.Context) {
	t := time.NewTicker(remoteArchiveDebtReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertRemoteArchiveDebtOnce(ctx)
		}
	}
}

// reassertRemoteArchiveDebtOnce runs in the archive FIFO so its active-config
// check cannot race a queued debt clear or superseding transfer attempt.
func (d *Daemon) reassertRemoteArchiveDebtOnce(ctx context.Context) {
	d.enqueueArchive(func() {
		if ctx.Err() != nil || d.store == nil {
			return
		}
		pending := d.archiveDebt.sites()
		if len(pending) == 0 {
			return
		}
		active := d.store.ActiveConfig()
		var configured []string
		if active != nil && active.System.Archival != nil {
			archival := active.System.Archival
			if archival.TransferOnCommit || archival.TransferInterval > 0 {
				configured = archival.ArchiveSites
			}
		}
		d.archiveDebt.retain(configured)
		pending = d.archiveDebt.sites()
		if len(pending) == 0 {
			return
		}
		slog.Info("retrying current-config remote archive debt",
			"sites", len(pending), "issue", "#11806")
		d.archiveToSitesNow(pending)
	})
}

func (d *remoteArchiveDebt) status() (pendingSites, failures uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return uint64(len(d.pending)), d.failures
}

// RemoteArchiveStatus returns the number of archive sites still owed a copy
// of the current config and the cumulative number of failed site attempts.
func (d *Daemon) RemoteArchiveStatus() (pendingSites, failures uint64) {
	return d.archiveDebt.status()
}
