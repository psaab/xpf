package daemon

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

type archiveTransferObservation struct {
	site string
	data string
	err  error
}

func waitRemoteArchiveStatus11806(t *testing.T, d *Daemon, wantPending, wantFailures uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		pending, failures := d.RemoteArchiveStatus()
		if pending == wantPending && failures == wantFailures {
			return
		}
		time.Sleep(time.Millisecond)
	}
	pending, failures := d.RemoteArchiveStatus()
	t.Fatalf("remote archive status = pending %d / failures %d, want %d / %d",
		pending, failures, wantPending, wantFailures)
}

func remoteArchivePendingSites11806(d *Daemon) []string {
	d.archiveDebt.mu.Lock()
	defer d.archiveDebt.mu.Unlock()
	sites := make([]string, 0, len(d.archiveDebt.pending))
	for site := range d.archiveDebt.pending {
		sites = append(sites, site)
	}
	sort.Strings(sites)
	return sites
}

// TestRemoteArchiveDebtRetriesOnPeriodicTick11806 proves per-site debt is
// retained after a fake transfer failure and discharged by the existing timer
// owner when a later current-config upload succeeds.
func TestRemoteArchiveDebtRetriesOnPeriodicTick11806(t *testing.T) {
	d, _, tickCh, _ := storeWithHost(t, "remote-timer-debt")
	const siteA = "scp://user@site-a/archive/"
	const siteB = "scp://user@site-b/archive/"
	var failSiteB atomic.Bool
	failSiteB.Store(true)
	results := make(chan archiveTransferObservation, 8)
	d.archiveTransfer = func(_ context.Context, srcPath, site string) error {
		data, err := os.ReadFile(srcPath)
		if err == nil && site == siteB && failSiteB.Load() {
			err = errors.New("injected remote transfer failure")
		}
		results <- archiveTransferObservation{site: site, data: string(data), err: err}
		return err
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		d.runArchiveTimer(1, []string{siteA, siteB}, stop)
		close(done)
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})

	tickCh <- time.Now()
	first := []archiveTransferObservation{<-results, <-results}
	for _, result := range first {
		if result.err != nil && result.site != siteB {
			t.Fatalf("unexpected failure for %q: %v", result.site, result.err)
		}
		if !strings.Contains(result.data, "remote-timer-debt") {
			t.Errorf("timer uploaded wrong current config to %q: %q", result.site, result.data)
		}
	}
	waitRemoteArchiveStatus11806(t, d, 1, 1)
	if got := remoteArchivePendingSites11806(d); len(got) != 1 || got[0] != siteB {
		t.Fatalf("pending sites after partial transfer = %v, want [%s]", got, siteB)
	}

	failSiteB.Store(false)
	tickCh <- time.Now()
	second := []archiveTransferObservation{<-results, <-results}
	for _, result := range second {
		if result.err != nil {
			t.Fatalf("retry to %q failed: %v", result.site, result.err)
		}
	}
	waitRemoteArchiveStatus11806(t, d, 0, 1)
	if got := remoteArchivePendingSites11806(d); len(got) != 0 {
		t.Fatalf("pending sites after successful timer retry = %v, want none", got)
	}
}

// TestRemoteArchiveDebtRetriesCurrentCommit11806 proves the commit-triggered
// path replaces old current-config debt and uploads the new active text, rather
// than retaining or replaying a historical version.
func TestRemoteArchiveDebtRetriesCurrentCommit11806(t *testing.T) {
	d, _, _, _ := storeWithHost(t, "remote-commit-before")
	const site = "scp://user@archive-site/archive/"
	results := make(chan archiveTransferObservation, 4)
	var calls atomic.Uint32
	d.archiveTransfer = func(_ context.Context, srcPath, dest string) error {
		data, err := os.ReadFile(srcPath)
		if err == nil && calls.Add(1) == 1 {
			err = errors.New("injected first transfer failure")
		}
		results <- archiveTransferObservation{site: dest, data: string(data), err: err}
		return err
	}
	cfg := &config.Config{}
	cfg.System.Archival = &config.ArchivalConfig{
		TransferOnCommit: true,
		ArchiveSites:     []string{site},
	}

	d.archiveConfig(cfg)
	first := <-results
	if first.err == nil {
		t.Fatal("injected first remote transfer unexpectedly succeeded")
	}
	waitRemoteArchiveStatus11806(t, d, 1, 1)

	if err := d.store.SetFromInput("system host-name remote-commit-after"); err != nil {
		t.Fatalf("SetFromInput new current config: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("commit new current config: %v", err)
	}
	d.archiveConfig(cfg)
	second := <-results
	if second.err != nil {
		t.Fatalf("commit-triggered retry failed: %v", second.err)
	}
	if !strings.Contains(second.data, "remote-commit-after") || strings.Contains(second.data, "remote-commit-before") {
		t.Fatalf("retry uploaded non-current config: %q", second.data)
	}
	waitRemoteArchiveStatus11806(t, d, 0, 1)
}
