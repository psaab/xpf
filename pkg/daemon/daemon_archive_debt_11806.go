package daemon

import "sync"

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

func (d *remoteArchiveDebt) clear() {
	d.mu.Lock()
	d.generation++
	d.pending = nil
	d.mu.Unlock()
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
