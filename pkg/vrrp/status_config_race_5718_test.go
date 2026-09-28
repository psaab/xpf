package vrrp

import (
	"net"
	"strings"
	"sync"
	"testing"
)

// #5718 (codex-182 C-HA C01c): Manager.Status() formatted vi.cfg.Priority,
// vi.cfg.Preempt, and vi.cfg.AdvertiseInterval while holding only m.mu.RLock.
// Those three cfg fields are mutated under vi.mu.Lock by updateConfig,
// UpdateRGPriority, and suppressPreempt/restorePreempt, so a `show`/status
// render concurrent with a failover priority update is an unsynchronized
// concurrent read/write — a diagnostic-only data race the Go memory model
// forbids and go test -race flags. The fix snapshots those fields under
// vi.mu.RLock before formatting, mirroring advertInterval/getPriority (#6230).
// vi.cfg.VirtualAddresses is also copied under that lock; VIP-set commits
// mutate the slice in place on an existing instance (#10780), so it is no
// longer merely a defensive copy.
//
// This is the fail-on-revert gate. A start barrier releases the writer and
// reader together, and the writer LOOPS mutating all three raced fields under
// vi.mu.Lock until the reader signals done, so the reader's Status() renders
// overlap a live concurrent writer for the whole window. That guaranteed
// overlap makes the race detector reliably observe the concurrent access under
// both the default GOMAXPROCS and GOMAXPROCS=1 — a fixed-count writer that can
// run to completion before the reader starts leaves no concurrent access and
// false-greens on revert. It is CLEAN with the snapshot fix and reliably
// reports WARNING: DATA RACE + FAIL if Status() reverts to reading any of
// vi.cfg.Priority/Preempt/AdvertiseInterval directly. Must be run with
// `go test -race`.
func TestStatusConfigNoRace5718(t *testing.T) {
	m := NewManager()
	reth := newInstance(
		Instance{Interface: "reth0", GroupID: 101, Priority: 100, AdvertiseInterval: 30, Preempt: true},
		&net.Interface{Name: "reth0", Index: 8}, m.eventCh, nil)
	m.instances[instanceKey{iface: "reth0", groupID: 101}] = reth

	const iters = 5000
	start := make(chan struct{})
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: a locked mutation of the three genuinely-raced snapshot fields
	// (Priority, Preempt, AdvertiseInterval), mirroring the vi.mu.Lock()
	// discipline every cfg writer (updateConfig, UpdateRGPriority,
	// suppressPreempt/restorePreempt) uses. It loops until the reader signals
	// done so a revert of ANY of the three snapshots — not just Priority — is
	// caught by the -race detector.
	go func() {
		defer wg.Done()
		<-start
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			reth.mu.Lock()
			if i%2 == 0 {
				reth.cfg.Priority = 100
				reth.cfg.Preempt = true
				reth.cfg.AdvertiseInterval = 30
			} else {
				reth.cfg.Priority = 1
				reth.cfg.Preempt = false
				reth.cfg.AdvertiseInterval = 100
			}
			reth.mu.Unlock()
		}
	}()

	// Reader: the real Status() render path, run for a bounded window while the
	// writer is guaranteed to be concurrently mutating the cfg snapshot fields.
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iters; i++ {
			if out := m.Status(); !strings.Contains(out, "reth0") {
				t.Errorf("Status() missing instance: %q", out)
				break
			}
		}
		close(done)
	}()

	close(start)
	wg.Wait()
}
