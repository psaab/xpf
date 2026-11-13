package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcprelay"
	"github.com/psaab/xpf/pkg/ra"
)

// #16678: the first-commit `commit confirmed` rollback to bootstrap left the
// abandoned config's Router Advertisement senders running, the Kea DHCP
// server units running and the DHCP relay running, while it closed transit
// and logged "config-driven takeover removed". The abandoned config kept
// attracting the segment's IPv6 default route and new DHCP clients into a
// node that forwards nothing.
//
// These cells drive the real executeConfirmedRollback down the
// first-commit branch (prevCfg==nil / firstCommitRollback) with real
// service managers where the environment allows it, and a recording
// dhcpApplier for Kea (the Kea fake must record a stop on this path —
// there is no Kea binary in the test environment).

// rollbackDHCPRecorder16678 records every config that reaches the Kea
// applier, so the test can assert the rollback drove Apply(nil) — the stop.
type rollbackDHCPRecorder16678 struct {
	*recordingDHCPApplier9349
	applyNil    int
	applyNonNil int
	leaseSync   []bool
	shutdowns   int
}

func (r *rollbackDHCPRecorder16678) Apply(cfg *config.DHCPServerConfig) error {
	if cfg == nil {
		r.applyNil++
	} else {
		r.applyNonNil++
	}
	return r.recordingDHCPApplier9349.Apply(cfg)
}

func (r *rollbackDHCPRecorder16678) SetLeaseSyncEnabled(enabled bool) {
	r.leaseSync = append(r.leaseSync, enabled)
}

func (r *rollbackDHCPRecorder16678) Shutdown() error {
	r.shutdowns++
	return nil
}

// failingRollbackDHCP16678 fails Apply so the DEGRADED-reporting cell can
// prove a Kea stop failure is not swallowed into a clean rollback.
type failingRollbackDHCP16678 struct {
	*rollbackDHCPRecorder16678
	err error
}

func (f *failingRollbackDHCP16678) Apply(cfg *config.DHCPServerConfig) error {
	_ = f.rollbackDHCPRecorder16678.Apply(cfg)
	return f.err
}

// rollbackJoin16678 owns the commit-confirmed rollback executions of one
// fixture (#19089). The store's timer runs the executor on its own goroutine,
// outside the store's mutex, so stopping the timer does not wait for a
// rollback that already started: after PromoteRollback has cleared the
// pending window, cancellation returns at once while the rollback's service
// teardown (and its ERROR log) is still to come. The wrapper counts every
// admitted execution, refuses new ones once closed, and wait waits for the
// admitted ones to finish. Every rollback execution, including the daemon's
// retry, is dispatched through the store's registered executor, so this
// wrapper sees all of them (#19089 fold 2).
type rollbackJoin16678 struct {
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
	// afterRun, when set, runs after an admitted execution and before it
	// is counted done (a cell holds a promoted rollback here).
	afterRun func()
	// teardown is the exact closure the fixture registered with t.Cleanup,
	// so a cell can run the real cleanup rather than a copy of it.
	teardown func()
	// stateDir is the fixture's temp dir (the store's xpf.conf lives there).
	stateDir string
}

func (j *rollbackJoin16678) wrap(run func(gen uint64)) func(gen uint64) {
	return func(gen uint64) {
		j.mu.Lock()
		if j.closed {
			j.mu.Unlock()
			return
		}
		j.wg.Add(1)
		after := j.afterRun
		j.mu.Unlock()
		defer j.wg.Done()
		run(gen)
		if after != nil {
			after()
		}
	}
}

// close refuses every later execution (a timer that fires after the test,
// including one whose window a manual dispatch already resolved).
func (j *rollbackJoin16678) close() {
	j.mu.Lock()
	j.closed = true
	j.mu.Unlock()
}

// wait waits for every admitted execution to finish.
func (j *rollbackJoin16678) wait() {
	j.wg.Wait()
}

func (j *rollbackJoin16678) setAfterRun(fn func()) {
	j.mu.Lock()
	j.afterRun = fn
	j.mu.Unlock()
}

// holdAdmitted parks EVERY admitted execution after it runs, until release.
// ran is closed once, by the first execution to arrive (a real timer fire can
// overlap a manual dispatch, so a second arrival must not close it again);
// parked counts the executions waiting at the barrier. release is idempotent.
func (j *rollbackJoin16678) holdAdmitted() (ran <-chan struct{}, parked *atomic.Int32, release func()) {
	ranCh := make(chan struct{})
	rel := make(chan struct{})
	var ranOnce, relOnce sync.Once
	var n atomic.Int32
	j.setAfterRun(func() {
		ranOnce.Do(func() { close(ranCh) })
		n.Add(1)
		<-rel
	})
	return ranCh, &n, func() { relOnce.Do(func() { close(rel) }) }
}

func newFirstCommitRollbackDaemon16678(t *testing.T, dhcp *rollbackDHCPRecorder16678) (*Daemon, *configstore.Store) {
	t.Helper()
	d, s, _ := newFirstCommitRollbackDaemonJoined16678(t, dhcp)
	return d, s
}

func newFirstCommitRollbackDaemonJoined16678(t *testing.T, dhcp *rollbackDHCPRecorder16678) (*Daemon, *configstore.Store, *rollbackJoin16678) {
	t.Helper()
	isolateFirstCommitRollbackHostAuth12169(t)
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	// #19089: registered first, so it runs after every cleanup below. A
	// commit-confirmed window still armed here means its rollback timer fires
	// about a minute later, inside whatever test runs then: the DEGRADED cell
	// left one, and its rollback logged an ERROR (a persist into this test's
	// removed temp dir) into TestBootstrapLifelineRetainsMACFormLink12156.
	t.Cleanup(func() {
		if s.IsConfirmPending() {
			t.Errorf("#19089: a commit-confirmed window is still armed after the test; its rollback timer would fire inside a later test")
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := &Daemon{
		applySem:   semaphore.NewWeighted(1),
		store:      s,
		daemonCtx:  ctx,
		dhcpRelay:  dhcprelay.NewManager(),
		dhcpServer: dhcp,
	}
	// The dataplane apply must never run on this branch (same seam as
	// TestFirstCommitRollbackEntersBootstrap); bootstrap teardown is
	// stubbed by the same seam inside enterBootstrapMode.
	var applyCalls int
	d.applyBodyForTest = func(_ *config.Config) { applyCalls++ }
	t.Cleanup(func() {
		if applyCalls != 0 {
			t.Errorf("first-commit rollback applied a config %d times, want 0", applyCalls)
		}
	})
	t.Cleanup(d.dhcpRelay.Stop)
	// #19089: the join, run before the relay stops and before the temp dir
	// goes. It (1) closes admission, so a timer that fires later runs no
	// rollback; (2) stops a window the test left armed (the DEGRADED cell
	// drives enterBootstrapMode directly and never fires the timer); and
	// (3) waits for every rollback already admitted, including one that has
	// promoted (window cleared) but not yet torn services down. Stopping the
	// timer alone did only (2): it cannot wait for a callback that started.
	join := &rollbackJoin16678{stateDir: dir}
	join.teardown = func() {
		join.close()
		s.CancelConfirmTimerForTesting()
		join.wait()
	}
	t.Cleanup(join.teardown)
	s.SetRollbackExecutor(join.wrap(d.executeConfirmedRollback))
	return d, s, join
}

func armFirstCommitConfirmed16678(t *testing.T, s *configstore.Store) {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name box; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	s.ExitConfigure()
}

// TestFirstCommitRollbackWithdrawsServices16678 is the headline #16678
// cell: a first commit confirmed on a fresh store, timed out, must
// withdraw the RA senders, stop Kea (Apply(nil) recorded) and stop the
// DHCP relay before reporting the rollback complete.
//
// RED-on-revert: delete withdrawAbandonedServicesForBootstrap's call (or
// any one of its three legs) from enterBootstrapMode and the matching
// assertion below fails — the sender stays in Status(), no Apply(nil)
// is recorded, or the relay stays managed.
func TestFirstCommitRollbackWithdrawsServices16678(t *testing.T) {
	rec := &rollbackDHCPRecorder16678{recordingDHCPApplier9349: &recordingDHCPApplier9349{}}
	d, s := newFirstCommitRollbackDaemon16678(t, rec)

	// Seed the abandoned config's service claims exactly as the
	// bootstrap-exit apply would have left them: a real relay registered
	// through the daemon reconcile (socket-free on a nonexistent
	// interface) and the relay/Kea state a commit would have started.
	d.reconcileDHCPRelay(relayCfg("xpf-test-nonexistent16678"))
	if n := len(d.dhcpRelay.Stats()); n != 1 {
		t.Fatalf("premise: expected 1 managed relay after seed, got %d", n)
	}

	armFirstCommitConfirmed16678(t, s)
	gen := s.ConfirmGenForTesting()
	s.InvokeRollbackTimerForTesting(gen)

	if !d.inBootstrap() {
		t.Fatal("after first-commit rollback timeout, daemon must be in BOOTSTRAP mode")
	}
	// Kea: the rollback must have driven exactly one synchronous stop.
	if rec.applyNil != 1 {
		t.Fatalf("Kea stop: Apply(nil) recorded %d times, want 1 (applyNonNil=%d)", rec.applyNil, rec.applyNonNil)
	}
	if rec.shutdowns != 0 {
		t.Fatalf("Kea must be stopped via Apply(nil), not the latching Shutdown(); got %d Shutdown calls", rec.shutdowns)
	}
	// Relay: reconciled to nil, nothing managed.
	if n := len(d.dhcpRelay.Stats()); n != 0 {
		t.Fatalf("DHCP relay still managed after first-commit rollback: %d relays", n)
	}
}

// TestFirstCommitRollbackWithdrawsRA16678 pins the RA leg with a real
// ra.Manager. A sender that cannot open its conn (no such interface) is
// still tracked as wanted/dead by the manager; Withdraw must retire it
// so Status() reports no senders afterwards. On a live interface the
// same Withdraw emits the lifetime-0 goodbye (pkg/ra covers that); here
// the observable is senders=[] after rollback.
//
// Skipped where the RA manager cannot be exercised at all.
func TestFirstCommitRollbackWithdrawsRA16678(t *testing.T) {
	rec := &rollbackDHCPRecorder16678{recordingDHCPApplier9349: &recordingDHCPApplier9349{}}
	d, s := newFirstCommitRollbackDaemon16678(t, rec)
	d.ra = ra.New()
	t.Cleanup(func() { _ = d.ra.Clear() })

	// Apply an RA config for an interface that does not exist: the
	// manager records the sender as wanted/dead rather than dropping
	// the intent (see pkg/ra dead-sender handling). Withdraw must
	// still retire every trace of it.
	_ = d.ra.Apply([]*config.RAInterfaceConfig{{
		Interface: "xpf-test-nonexistent16678",
		Prefixes:  []*config.RAPrefix{{Prefix: "2001:db8:1::/64"}},
	}})

	armFirstCommitConfirmed16678(t, s)
	s.InvokeRollbackTimerForTesting(s.ConfirmGenForTesting())

	if !d.inBootstrap() {
		t.Fatal("after first-commit rollback timeout, daemon must be in BOOTSTRAP mode")
	}
	if got := d.ra.Status(); len(got) != 0 {
		t.Fatalf("RA senders after first-commit rollback = %+v, want []", got)
	}
}

// TestFirstCommitRollbackServiceFailureIsDegraded16678 proves the honest
// reporting leg: if the Kea stop fails, enterBootstrapMode must surface
// the failure (the rollback is DEGRADED) rather than logging
// "config-driven takeover removed" over a still-running Kea.
func TestFirstCommitRollbackServiceFailureIsDegraded16678(t *testing.T) {
	fail := &failingRollbackDHCP16678{
		rollbackDHCPRecorder16678: &rollbackDHCPRecorder16678{recordingDHCPApplier9349: &recordingDHCPApplier9349{}},
		err:                       errors.New("kea stop failed (injected)"),
	}
	d, s := newFirstCommitRollbackDaemon16678(t, fail.rollbackDHCPRecorder16678)
	d.dhcpServer = fail

	armFirstCommitConfirmed16678(t, s)

	// Drive enterBootstrapMode directly: executeConfirmedRollback logs
	// the DEGRADED outcome but does not return it, so the aggregation
	// contract is asserted at the owner that returns it.
	if err := d.enterBootstrapMode(); err == nil {
		t.Fatal("a failed Kea stop must make the bootstrap rollback DEGRADED, not clean")
	} else if !errors.Is(err, fail.err) && err.Error() == "" {
		t.Fatalf("DEGRADED error must name the failed step; got %v", err)
	}
	if fail.applyNil != 1 {
		t.Fatalf("the failing Kea stop must still have been attempted once; got %d", fail.applyNil)
	}
	if !d.inBootstrap() {
		t.Fatal("daemon must still enter bootstrap mode on a partial teardown")
	}
}

// TestEnterBootstrapModeWithoutServices16678 is the nil-safety cell: a
// daemon constructed with no RA/Kea/relay managers (unit-test harnesses,
// config-only boots) must enter bootstrap cleanly.
func TestEnterBootstrapModeWithoutServices16678(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.applyBodyForTest = func(_ *config.Config) {}
	if err := d.enterBootstrapMode(); err != nil {
		t.Fatalf("enterBootstrapMode with no service managers: %v", err)
	}
	if !d.inBootstrap() {
		t.Fatal("daemon must be in bootstrap mode")
	}
}

// TestBootstrapRelayStopFailureDegrades17693 proves the relay's bounded
// reconcile failure reaches bootstrap's shared DEGRADED aggregation instead
// of being discarded after the service-stop attempt.
func TestBootstrapRelayStopFailureDegrades17693(t *testing.T) {
	relayErr := errors.New("DHCP relay stop timed out")
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		dhcpRelayReconcileForTest: func(cfg *config.Config) error {
			if cfg == nil || cfg.ForwardingOptions.DHCPRelay != nil {
				t.Fatal("bootstrap must reconcile the relay with an empty config")
			}
			return relayErr
		},
	}
	d.applyBodyForTest = func(*config.Config) {}

	err := d.enterBootstrapMode()
	if !errors.Is(err, relayErr) {
		t.Fatalf("bootstrap error = %v, want joined DHCP relay stop failure", err)
	}
	if !strings.Contains(err.Error(), "stop DHCP relay") {
		t.Fatalf("bootstrap error %q does not identify the failed relay step", err)
	}
	if !d.inBootstrap() {
		t.Fatal("daemon must still enter bootstrap mode after a partial service stop")
	}
}

// TestRollbackJoinWaitsForAPromotedRollback19089 is the case stopping the
// timer could not cover (Codex review of 97b646d8fa). A rollback that has
// already been admitted and has PROMOTED (the pending window is cleared, so
// IsConfirmPending reads false) is held before it finishes, together with a
// second, overlapping dispatch of the same window (a real timer fire can
// overlap a manual one; Codex review of 04d3f69679). The fixture's REAL
// cleanup (the closure it registered with t.Cleanup) must not return until
// both finish, and once closed it admits nothing.
func TestRollbackJoinWaitsForAPromotedRollback19089(t *testing.T) {
	rec := &rollbackDHCPRecorder16678{recordingDHCPApplier9349: &recordingDHCPApplier9349{}}
	d, s, join := newFirstCommitRollbackDaemonJoined16678(t, rec)
	ran, parked, release := join.holdAdmitted()
	defer release()
	armFirstCommitConfirmed16678(t, s)
	gen := s.ConfirmGenForTesting()
	var fired sync.WaitGroup
	for i := 0; i < 2; i++ {
		fired.Add(1)
		go func() {
			defer fired.Done()
			s.InvokeRollbackTimerForTesting(gen)
		}()
	}
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		release()
		t.Fatal("FIXTURE: no admitted rollback ran")
	}
	deadline := time.Now().Add(10 * time.Second)
	for parked.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := parked.Load(); got != 2 {
		release()
		t.Fatalf("#19089: an admitted execution did not wait at the release barrier (parked %d of 2)", got)
	}
	if s.IsConfirmPending() || !d.inBootstrap() {
		release()
		t.Fatalf("FIXTURE: the held rollback must have promoted (pending=%v, bootstrap=%v)", s.IsConfirmPending(), d.inBootstrap())
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		join.teardown()
	}()
	select {
	case <-joined:
		release()
		t.Fatal("#19089: cleanup returned while an admitted rollback was still running")
	case <-time.After(200 * time.Millisecond):
	}
	release()
	select {
	case <-joined:
	case <-time.After(10 * time.Second):
		t.Fatal("cleanup never returned after the rollback finished")
	}
	fired.Wait()
	// The post-cleanup admission check has its own hook. The hold hook is
	// done with, so it is cleared first, and a late execution is recorded by
	// its own run function: the check is the only thing that can fire.
	join.setAfterRun(nil)
	lateAdmitted := false
	join.wrap(func(uint64) { lateAdmitted = true })(0)
	if lateAdmitted {
		t.Fatal("#19089: a rollback fired after cleanup was admitted")
	}
}

// TestRollbackJoinWaitsForAPromotedRetry19089 covers the rollback RETRY
// (Codex review of 04d3f69679, MAJOR). A first-commit rollback that cannot
// persist its host-auth closeout intent leaves the window pending and
// schedules a retry a second later. That retry used to call
// executeConfirmedRollback directly, so it was never admitted or joined by
// the fixture, and once it promoted nothing could see it. It now goes
// through the store's registered executor. Here the first attempt fails (a
// non-empty directory sits at the closeout record's path), the storage then
// recovers, and the retry must arrive through the wrapper, promote, and hold
// the fixture's real cleanup until it finishes.
func TestRollbackJoinWaitsForAPromotedRetry19089(t *testing.T) {
	rec := &rollbackDHCPRecorder16678{recordingDHCPApplier9349: &recordingDHCPApplier9349{}}
	d, s, join := newFirstCommitRollbackDaemonJoined16678(t, rec)
	armFirstCommitConfirmed16678(t, s)
	block := filepath.Join(join.stateDir, ".configdb", "first-commit-hostauth-closeout.json")
	if err := os.MkdirAll(filepath.Join(block, "keep"), 0o700); err != nil {
		t.Fatal(err)
	}
	var runs atomic.Int32
	var pendingAfterFirst atomic.Bool
	promoted := make(chan struct{})
	rel := make(chan struct{})
	var promotedOnce, relOnce sync.Once
	release := func() { relOnce.Do(func() { close(rel) }) }
	defer release()
	join.setAfterRun(func() {
		if runs.Add(1) == 1 {
			// The failed first attempt has scheduled its retry. The
			// storage recovers, so the retry can write its intent.
			pendingAfterFirst.Store(s.IsConfirmPending())
			_ = os.RemoveAll(block)
			return
		}
		promotedOnce.Do(func() { close(promoted) })
		<-rel
	})
	go s.InvokeRollbackTimerForTesting(s.ConfirmGenForTesting())
	select {
	case <-promoted:
	case <-time.After(10 * time.Second):
		release()
		if runs.Load() >= 1 && !pendingAfterFirst.Load() {
			t.Fatal("FIXTURE: the closeout fault did not fire; the first attempt promoted")
		}
		t.Fatalf("#19089: the rollback retry did not run through the registered executor (admitted %d executions, want 2; pending after the first: %v)",
			runs.Load(), pendingAfterFirst.Load())
	}
	if !pendingAfterFirst.Load() {
		release()
		t.Fatal("FIXTURE: the first attempt promoted; there was no retry to cover")
	}
	if s.IsConfirmPending() || !d.inBootstrap() {
		release()
		t.Fatalf("FIXTURE: the held retry must have promoted (pending=%v, bootstrap=%v)", s.IsConfirmPending(), d.inBootstrap())
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		join.teardown()
	}()
	select {
	case <-joined:
		release()
		t.Fatal("#19089: cleanup returned while an admitted retry was still running")
	case <-time.After(200 * time.Millisecond):
	}
	release()
	select {
	case <-joined:
	case <-time.After(10 * time.Second):
		t.Fatal("cleanup never returned after the retry finished")
	}
}
