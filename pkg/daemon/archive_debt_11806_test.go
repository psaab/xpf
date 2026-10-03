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

// TestRemoteArchiveUploadsNeverFinishOutOfOrder11806 proves the remote-state
// hazard behind the bookkeeping-only generation guard: two back-to-back
// archiveToSites calls may run their transfers concurrently, and an older
// snapshot finishing last overwrites the newer remote copy while debt reports
// zero. A queued newer transfer must wait for the blocked old transfer, then
// leave the newest bytes as the last remote write.
func TestRemoteArchiveUploadsNeverFinishOutOfOrder11806(t *testing.T) {
	d, _, _, _ := storeWithHost(t, "remote-order-old")
	const site = "scp://user@archive-site/archive/"
	entered := make(chan string, 2)
	releaseOld := make(chan struct{})
	completions := make(chan string, 2)
	var calls atomic.Uint32
	d.archiveTransfer = func(_ context.Context, srcPath, _ string) error {
		data, err := os.ReadFile(srcPath)
		if err != nil {
			t.Errorf("read staged snapshot: %v", err)
			return err
		}
		entered <- string(data)
		if calls.Add(1) == 1 {
			<-releaseOld
		}
		completions <- string(data)
		return nil
	}

	d.archiveToSites([]string{site})
	firstEntered := <-entered
	if !strings.Contains(firstEntered, "remote-order-old") {
		t.Fatalf("first transfer staged %q, want the old current config", firstEntered)
	}

	if err := d.store.SetFromInput("system host-name remote-order-new"); err != nil {
		t.Fatalf("SetFromInput new current config: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("commit new current config: %v", err)
	}
	d.archiveToSites([]string{site})

	select {
	case data := <-entered:
		t.Fatalf("new transfer started before old transfer completed: %q", data)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseOld)
	if old := <-completions; !strings.Contains(old, "remote-order-old") {
		t.Fatalf("first completed transfer carried %q, want old config", old)
	}
	select {
	case latest := <-entered:
		if !strings.Contains(latest, "remote-order-new") || strings.Contains(latest, "remote-order-old") {
			t.Fatalf("queued transfer staged stale config: %q", latest)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued new current-config transfer did not start")
	}
	select {
	case latest := <-completions:
		if !strings.Contains(latest, "remote-order-new") || strings.Contains(latest, "remote-order-old") {
			t.Fatalf("last completed transfer was not the newest config: %q", latest)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("new current-config transfer did not complete")
	}
}

func waitArchiveQueue11806(t *testing.T, d *Daemon) {
	t.Helper()
	done := make(chan struct{})
	d.enqueueArchive(func() { close(done) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("archive queue did not drain")
	}
}

// TestRemoteArchiveDebtRetriesWithoutAnotherCommitOrTimer11806 proves the
// always-on owner retries transfer-on-commit-only debt and discharges it only
// after the transfer succeeds.
func TestRemoteArchiveDebtRetriesWithoutAnotherCommitOrTimer11806(t *testing.T) {
	d, _, _, _ := storeWithHost(t, "remote-retry-owner")
	const site = "scp://user@archive-site/archive/"
	if err := d.store.SetFromInput("system archival configuration transfer-on-commit"); err != nil {
		t.Fatalf("enable transfer-on-commit: %v", err)
	}
	if err := d.store.SetFromInput(`system archival configuration archive-sites "` + site + `"`); err != nil {
		t.Fatalf("configure archive site: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("commit archive config: %v", err)
	}
	var calls atomic.Uint32
	uploaded := make(chan string, 2)
	d.archiveTransfer = func(_ context.Context, srcPath, _ string) error {
		data, err := os.ReadFile(srcPath)
		if err != nil {
			return err
		}
		uploaded <- string(data)
		if calls.Add(1) == 1 {
			return errors.New("injected first transfer failure")
		}
		return nil
	}

	d.archiveToSites([]string{site})
	if got := <-uploaded; !strings.Contains(got, "remote-retry-owner") {
		t.Fatalf("first upload was not the current config: %q", got)
	}
	waitRemoteArchiveStatus11806(t, d, 1, 1)

	originalInterval := remoteArchiveDebtReassertInterval
	t.Cleanup(func() { remoteArchiveDebtReassertInterval = originalInterval })
	remoteArchiveDebtReassertInterval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.remoteArchiveDebtReassertLoop(ctx); close(done) }()
	waitRemoteArchiveStatus11806(t, d, 0, 1)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("remote archive debt owner did not stop on cancellation")
	}
	if got := <-uploaded; !strings.Contains(got, "remote-retry-owner") {
		t.Fatalf("retry uploaded non-current config: %q", got)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("archive transfer attempts = %d, want initial failure plus one retry", got)
	}
}

// TestRemoteArchiveDebtSurvivesUnrelatedPeriodicConfigCommit11806 prevents an
// unrelated commit from erasing a failed periodic copy that remains configured.
func TestRemoteArchiveDebtSurvivesUnrelatedPeriodicConfigCommit11806(t *testing.T) {
	d, _, _, _ := storeWithHost(t, "remote-periodic-before")
	const site = "scp://user@archive-site/archive/"
	if err := d.store.SetFromInput("system archival configuration transfer-interval 30"); err != nil {
		t.Fatalf("enable periodic archival: %v", err)
	}
	if err := d.store.SetFromInput(`system archival configuration archive-sites "` + site + `"`); err != nil {
		t.Fatalf("configure archive site: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("commit periodic archival config: %v", err)
	}
	generation := d.archiveDebt.begin([]string{site})
	d.archiveDebt.record(generation, site, errors.New("injected periodic failure"))
	waitRemoteArchiveStatus11806(t, d, 1, 1)

	if err := d.store.SetFromInput("system host-name remote-periodic-after"); err != nil {
		t.Fatalf("unrelated host-name edit: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("commit unrelated host-name edit: %v", err)
	}
	d.archiveConfig(d.store.ActiveConfig())
	waitArchiveQueue11806(t, d)
	waitRemoteArchiveStatus11806(t, d, 1, 1)
	if got := remoteArchivePendingSites11806(d); len(got) != 1 || got[0] != site {
		t.Fatalf("pending periodic archive sites after unrelated commit = %v, want [%s]", got, site)
	}
}
