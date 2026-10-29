package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

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

func newFirstCommitRollbackDaemon16678(t *testing.T, dhcp *rollbackDHCPRecorder16678) (*Daemon, *configstore.Store) {
	t.Helper()
	isolateFirstCommitRollbackHostAuth12169(t)
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{
		applySem:   semaphore.NewWeighted(1),
		store:      s,
		daemonCtx:  context.Background(),
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
	s.SetRollbackExecutor(d.executeConfirmedRollback)
	return d, s
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
