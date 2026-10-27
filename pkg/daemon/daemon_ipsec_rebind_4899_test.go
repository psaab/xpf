package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipsec"
)

// dhcpBoundIPsecConfig returns a config for which ipsec.HasDHCPBoundGateway is
// true: an IPsec gateway bound to an external-interface (no explicit
// local-address) whose unit is DHCP-managed — the exact shape that takes the
// #2884 management-only rebind path in onDHCPAddressChange.
func dhcpBoundIPsecConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {
			Name:  "ge-0/0/0",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true}},
		},
	}
	cfg.Security.IPsec.Gateways = map[string]*config.IPsecGateway{
		"gw1": {Name: "gw1", ExternalIface: "ge-0/0/0"},
	}
	return cfg
}

// newIPsecRebindDaemon builds a Daemon wired for the #4899 lease-change rebind
// path: a real (unused) IPsec manager so the nil guard passes, a fast retry
// cadence, and the config-source seam pointed at a DHCP-bound config so the
// retry loop has work. applyFn is the injected swanctl re-render+reload seam.
// The returned cancel stops the retry loop (call it via t.Cleanup).
func newIPsecRebindDaemon(t *testing.T, applyFn func(*config.Config) error) (*Daemon, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := dhcpBoundIPsecConfig()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("set interfaces ge-0/0/0 unit 0 family inet dhcp\n" +
		"set security ike gateway gw1 address 203.0.113.1\n" +
		"set security ike gateway gw1 external-interface ge-0/0/0.0\n"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	prevRoute := mgmtRouteRefreshFn
	t.Cleanup(func() { mgmtRouteRefreshFn = prevRoute })
	mgmtRouteRefreshFn = func(*Daemon) error { return nil }
	d := &Daemon{
		applySem:              semaphore.NewWeighted(1),
		store:                 store,
		daemonCtx:             ctx,
		ipsec:                 ipsec.New(),
		ipsecApply:            applyFn,
		ipsecRebindActiveCfg:  func() *config.Config { return cfg },
		ipsecRebindRetryEvery: 2 * time.Millisecond,
	}
	d.mgmt.Store(&managementReconciler{})
	d.reconcileDNSFn = func(*config.Config, bool) error { return nil }
	return d, cancel
}

// TestManagementOnlyLeaseRefresh_FailureArmsRetryAndSetsHealth is the #4899
// core regression. A swanctl reapply failure on the DHCP-lease-change path must
// (a) raise the ipsecRebindPending health signal and (b) arm the autonomous
// retry loop — NOT merely log a slog.Warn and forget. RED on revert: warn-only
// leaves ipsecRebindPending false and never re-invokes the apply, so both the
// health assertion and the retry-fired assertion fail.
func TestManagementOnlyLeaseRefresh_FailureArmsRetryAndSetsHealth(t *testing.T) {
	var calls atomic.Int32
	d, cancel := newIPsecRebindDaemon(t, func(*config.Config) error {
		calls.Add(1)
		return errors.New("swanctl --load-all: charon down")
	})
	t.Cleanup(cancel)

	d.managementOnlyLeaseRefresh()

	// (a) health signal is set immediately after the failing callback.
	if !d.IPsecRebindPending() {
		t.Fatal("ipsecRebindPending must be SET after a failed lease-change " +
			"rebind (regressed to warn-only: the swanctl reload error was dropped)")
	}
	// (a') the single-flight retry loop is armed.
	d.ipsecRebindMu.Lock()
	active := d.ipsecRebindRetryActive
	d.ipsecRebindMu.Unlock()
	if !active {
		t.Fatal("ipsecRebindRetryActive must be true after a failed rebind (no retry armed)")
	}

	// (b) the retry loop actually re-invokes the apply (>1 call proves the
	// autonomous retry, not just the one lease-callback attempt).
	waitFor(t, 3*time.Second, "retry loop to re-attempt the rebind (apply calls >= 2)",
		func() bool { return calls.Load() >= 2 })
}

// TestManagementOnlyLeaseRefresh_RecoveryClearsHealth proves the health signal
// CLEARS once a later reapply succeeds: the callback fails (arming the retry),
// then the injected apply starts succeeding, and the retry loop must converge
// and drop ipsecRebindPending + disarm itself. RED on revert: the pre-check
// asserts pending was SET after the first (failing) callback.
func TestManagementOnlyLeaseRefresh_RecoveryClearsHealth(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	var calls atomic.Int32
	d, cancel := newIPsecRebindDaemon(t, func(*config.Config) error {
		calls.Add(1)
		if fail.Load() {
			return errors.New("swanctl --load-all: charon down")
		}
		return nil
	})
	t.Cleanup(cancel)

	d.managementOnlyLeaseRefresh()
	if !d.IPsecRebindPending() {
		t.Fatal("ipsecRebindPending must be SET after the first failed rebind")
	}

	// Let the reload start succeeding; the retry loop must reconverge.
	fail.Store(false)
	waitFor(t, 3*time.Second, "ipsecRebindPending to clear after the reapply started succeeding",
		func() bool { return !d.IPsecRebindPending() })
	// The retry loop must disarm itself once converged (single-flight, not a
	// permanent background goroutine).
	waitFor(t, 1*time.Second, "ipsecRebindRetryActive to clear once the rebind reconverges",
		func() bool {
			d.ipsecRebindMu.Lock()
			defer d.ipsecRebindMu.Unlock()
			return !d.ipsecRebindRetryActive
		})
}

// TestManagementOnlyLeaseRefresh_NonFatalToLeaseProcessing proves the rebind
// failure does not block or fail lease processing: the callback returns
// promptly (no fatal error, no wedge) even when the reapply keeps failing, and
// a healthy (nil-error) reapply leaves no pending state and starts no loop.
func TestManagementOnlyLeaseRefresh_NonFatalToLeaseProcessing(t *testing.T) {
	// Failing reapply — must not block the lease callback.
	d, cancel := newIPsecRebindDaemon(t, func(*config.Config) error {
		return errors.New("swanctl --load-all: charon down")
	})
	t.Cleanup(cancel)

	done := make(chan struct{})
	go func() {
		d.managementOnlyLeaseRefresh()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("managementOnlyLeaseRefresh blocked on a failed rebind — it must " +
			"stay non-fatal to lease processing (retry + gauge ARE the recovery)")
	}

	// Healthy reapply — no pending state, no retry loop armed.
	d2, cancel2 := newIPsecRebindDaemon(t, func(*config.Config) error { return nil })
	t.Cleanup(cancel2)
	d2.managementOnlyLeaseRefresh()
	if d2.IPsecRebindPending() {
		t.Fatal("a successful rebind must leave ipsecRebindPending false")
	}
	d2.ipsecRebindMu.Lock()
	active := d2.ipsecRebindRetryActive
	d2.ipsecRebindMu.Unlock()
	if active {
		t.Fatal("a successful rebind must not arm the retry loop")
	}
}
